import Foundation
import os
import SwiftailBase
import SwiftailCrypto
import SwiftailHTTP2
import SwiftailIO
import SwiftailTKA

/// tailnet lock: 서버가 알린 상태에 맞춰 서명 권한 상태를 받아 검증하고, 그것으로 netmap을 걸러 낸다.
///
/// **거르지 않은 netmap은 이 actor 밖으로 나가지 않는다.** `MapSession`이 낸 netmap은 모두 `receivedLock`을 거쳐
/// `emitNetmap`에서만 사건이 된다. 닫힌 쪽이 기본이다: 서버가 lock이 켜졌다고 알리고 이 노드에 capability가 있는데
/// 검증한 상태가 없으면 피어를 하나도 내지 않는다(`.unverified`). 절차의 어떤 실패도 "거르지 않고 통과"가 되지 않는다.
/// 동기화가 실패하면 예전 상태로 계속 거르고, 꺼졌다는 말은 끄기 비밀이 검증될 때만 따른다.
///
/// 구조: 판정(`TailnetLockPlan`, `Authority`, `Netmap.filtered`)은 입출력 없는 값이고, 이 확장은 RPC와 파일과 차례만 맡는다.
/// - 맵 스트림(`receiveMap`)은 응답마다 `receivedLock`을 부른다. 할 일이 없으면 그 자리에서 걸러 내고, 있으면 netmap을
///   쥔 채 절차를 깨운다. 스트림 읽기는 멈추지 않고, 그사이 온 netmap은 가장 새것 하나만 쥔다.
/// - 절차(`runLockProcedures`)는 맵 스트림과 나란히 도는 연결의 자식 작업이다. 한 번에 하나만 돌고, 끝나면(성공이든
///   실패든) 쥔 netmap을 그때의 상태로 걸러 낸다. 상태 올리기의 물러나기에 막히지 않게 신호 처리와 따로 돈다.
/// - 서명 권한 상태는 연결이 끊겨도 메모리에 쥐고, 바뀔 때마다 `TailnetLockStore`에 적는다.
///
/// 계약 `docs/contracts/SwiftailTailnetLock.md` 동작 N·Y·P·O·T·K, 결정 L2·L3, 사용자의 답 U1.
/// `docs/protocol-notes/tailnet-lock.md` 3.10, 4.7~4.10 (출처: tailscale.com `ipn/ipnlocal/tailnet-lock.go`
/// `tkaSyncIfNeeded`·`tkaSyncLocked`·`tkaApplyDisablementLocked`·`tkaFetchBootstrap`·`tkaDoSyncOffer`·`tkaDoSyncSend`,
/// BSD-3-Clause).
extension ControlClient {
    /// 맵 세션 하나 동안의 lock 처리 상태. 연결을 새로 맺을 때 비운다.
    struct LockSession {
        /// 서버가 이 맵 세션에서 알린 상태.
        var server = ServerLockState()
        /// 이 세션의 가장 새 netmap(거르기 전). 절차가 도는 동안 내지 않고 쥐는 것도 이것이다.
        var netmap: Netmap?
        /// `netmap`을 아직 걸러 내지 않았다.
        var isNetmapPending = false
        /// 마지막으로 낸 netmap의 lock 모습. 절차 뒤에 달라졌으면 같은 netmap을 다시 걸러 낸다.
        var emitted: TailnetLockStatus?
        /// 절차가 돌고 있다. 그동안 온 netmap은 쥐었다가 절차가 끝날 때 낸다.
        var isProcedureRunning = false
        /// 절차를 돌 까닭이 생겼다(새 netmap이나 서버가 알린 상태의 변화에 할 일이 있다).
        var isWorkRequested = false
        /// 기다리는 절차를 깨우는 통로. 기다리는 중이 아니면 nil.
        var wakeup: AsyncStream<Void>.Continuation?
    }

    /// 절차가 서버의 응답에서 읽지 못한 것. 로그에 종류로만 남긴다.
    private enum LockResponseError: Error {
        /// 머리나 조상이 AUM 해시로 읽히지 않는다.
        case unreadableHash
    }

    static let lockLog = Logger(subsystem: "Swiftail", category: "tailnet-lock")
    /// 부트스트랩과 sync/send 응답 본문의 한도(Go의 Noise 응답 기본 한도).
    static let maximumTKAResponseSize = 1 << 20
    /// sync/offer 응답 본문의 한도. Go는 512MiB이고, 맵 프레임 한도와 같게 낮췄다(계약 동작 M, 결정 L16).
    static let maximumTKASyncOfferResponseSize = 8 << 20

    var lockStore: TailnetLockStore {
        TailnetLockStore(directory: identityStore.fileURL.deletingLastPathComponent())
    }

    /// 맵 요청의 `TKAHead`에 실을 로컬 머리. 상태가 없으면 빈 문자열이다.
    var lockHeadText: String { lockAuthority?.head.text ?? "" }

    /// 저장된 서명 권한 상태를 연다. `run()`이 첫 연결 전에 한 번 부른다(동작 N7·T3).
    ///
    /// 열지 못한 것은 "상태 없음"이 아니다: 그렇게 다루면 파일을 깨뜨리는 것만으로 신뢰가 새 부트스트랩으로 넘어간다.
    /// 파일을 고치거나 지우지 않고 `.unverified`에 머문다(동작 T4).
    func openLockStore() {
        do {
            lockAuthority = try lockStore.load()
        } catch {
            isLockStoreUnreadable = true
            // 저장소의 오류 문구는 종류만 담는다(경로·키·바이트가 없다).
            Self.lockLog.error("tailnet lock: 저장된 상태를 열지 못해 피어를 올리지 않는다: \(String(describing: error), privacy: .public)")
        }
    }

    // MARK: 맵 스트림 쪽

    /// 지금 할 일. 저장소를 열지 못한 뒤에는 없다(다시 시도해도 같다). 이 맵 세션의 첫 netmap 전에도 없다: 그 전의 응답
    /// (KeepAlive)에는 서버가 lock을 알릴 자리가 없었으므로 "처음부터 `TKAInfo`가 없다"는 첫 netmap에서 안다.
    var lockPlan: TailnetLockPlan {
        guard !isLockStoreUnreadable, let netmap = lockSession.netmap else { return .nothing }
        return TailnetLockPlan(
            localHead: lockAuthority?.head, hasCapability: netmap.selfNode.hasTailnetLockCapability, server: lockSession.server
        )
    }

    /// 맵 응답 하나를 적용한 결과를 받는다. 할 일이 없으면 netmap을 곧바로 걸러 내고, 있으면 쥔 채 절차를 깨운다(동작 N3).
    ///
    /// 새 netmap과 서버가 알린 상태의 변화가 계기다. 할 일이 남아 있으면(실패한 절차) 내용이 같은 맵 응답도 계기다:
    /// Go는 맵 응답마다 절차를 돈다(`ipn/ipnlocal/tailnet-lock.go`의 `tkaSyncIfNeeded`). 서버가 끄기 비밀만 바꾸고
    /// 같은 내용의 맵을 다시 보내면 그 맵에서 다시 시도해야 한다(관문 (가) 7에서 드러났다). KeepAlive는 계기가 아니다.
    func receivedLock(_ update: MapSession.Update) throws {
        if let netmap = update.netmap {
            lockSession.netmap = netmap
            lockSession.isNetmapPending = true
        }
        let serverChanged = update.serverLock != lockSession.server
        lockSession.server = update.serverLock
        guard update.netmap != nil || serverChanged || (update.isMapResponse && lockPlan != .nothing) else { return }
        if lockPlan != .nothing {
            lockSession.isWorkRequested = true
            lockSession.wakeup?.yield()
        } else if !lockSession.isProcedureRunning {
            try emitNetmap()
        }
    }

    /// 쥔 netmap을 지금의 lock 상태로 걸러 사건으로 낸다. netmap이 새로 온 것이 아니면 lock 모습이 달라졌을 때만 낸다.
    private func emitNetmap() throws {
        guard let raw = lockSession.netmap else { return }
        var netmap: Netmap
        if let lockAuthority {
            netmap = raw.filtered(by: lockAuthority, lockKey: identity.lockPublicKey)
            // 서버가 그 뒤 이 노드의 머리를 알리면 이어진 것이다(동기화를 기다리지 않는다).
            if isLockStateDiverged, lockAuthority.head != lockSession.server.head {
                netmap.tailnetLock.issue = .storedStateDiverged
            }
        } else if isLockStoreUnreadable {
            netmap = raw.withholdingPeers()
            netmap.tailnetLock.issue = .unreadableStoredState
        } else if lockPlan == .bootstrap {
            // 서버는 켜졌다고 하는데 검증한 상태가 아직 없다(부트스트랩 전이거나 실패했다).
            netmap = raw.withholdingPeers()
            netmap.tailnetLock.issue = .acquiringState
        } else {
            netmap = raw
        }
        let lock = netmap.tailnetLock
        guard lockSession.isNetmapPending || lock != lockSession.emitted else { return }
        if lock != lockSession.emitted {
            Self.lockLog.info("""
                tailnet lock: \(String(describing: lock.mode), privacy: .public), \
                거른 피어 \(lock.filteredPeerCount, privacy: .public)명, 자기 노드 잠김 \(lock.isLockedOut, privacy: .public)
                """)
        }
        lockSession.isNetmapPending = false
        lockSession.emitted = lock
        try accept(netmap)
    }

    // MARK: 절차

    /// tailnet lock의 절차를 한 번에 하나씩 돈다. 던지는 것으로만 끝난다(취소, 또는 낸 netmap의 키 만료).
    ///
    /// 부트스트랩이 실패한 채면(`.unverified`) 다음 netmap을 기다리지 않고 물러나며 다시 시도한다. 그동안 피어가 없기
    /// 때문이다(동작 N6). 동기화와 끄기의 실패는 예전 상태로 계속 거르므로 다음 계기를 기다린다.
    func runLockProcedures(over connection: ControlConnection) async throws {
        var bootstrapFailures = 0
        while true {
            let retry = bootstrapFailures > 0 && lockPlan == .bootstrap
                ? Self.lockRetryDelay(failures: bootstrapFailures, within: timeouts.lockRetry) : nil
            try await waitForLockWork(retryAfter: retry)
            lockSession.isWorkRequested = false
            let plan = lockPlan
            if plan != .nothing {
                lockSession.isProcedureRunning = true
                await performLock(plan, over: connection)
                lockSession.isProcedureRunning = false
                try Task.checkCancellation()
                bootstrapFailures = lockPlan == .bootstrap ? bootstrapFailures + 1 : 0
                announceLockHead()
            }
            try emitNetmap()
        }
    }

    /// `.unverified`에서 `failures`번 연달아 실패한 뒤 다시 시도하기까지의 간격: 하한에서 두 배씩, 상한까지.
    static func lockRetryDelay(failures: Int, within range: ClosedRange<Duration>) -> Duration {
        min(range.lowerBound * (1 << min(max(failures - 1, 0), 16)), range.upperBound)
    }

    /// 절차를 돌 까닭이 생기거나 `delay`가 지날 때까지 기다린다.
    private func waitForLockWork(retryAfter delay: Duration?) async throws {
        if !lockSession.isWorkRequested {
            // 깨움 통로는 기다릴 때마다 새로 만든다. 경쟁에서 진 쪽을 취소하면 그 흐름은 끝나기 때문이다.
            let (requests, continuation) = AsyncStream.makeStream(of: Void.self, bufferingPolicy: .bufferingNewest(1))
            lockSession.wakeup = continuation
            await withTaskGroup(of: Void.self) { group in
                group.addTask { for await _ in requests { return } }
                if let delay {
                    group.addTask { try? await Task.sleep(for: delay, clock: .continuous) }
                }
                await group.next()
                group.cancelAll()
            }
            lockSession.wakeup = nil
        }
        try Task.checkCancellation()
    }

    /// 절차 하나를 끝까지 돈다. 실패는 종류만 로그에 남기고 삼킨다: `run()`을 끝내지 않고, 상태는 실패하기 전 그대로다
    /// (동작 N5). 키, 해시, 서버 오류 본문은 로그에 남기지 않는다(동작 K5).
    private func performLock(_ plan: TailnetLockPlan, over connection: ControlConnection) async {
        do {
            switch plan {
            case .nothing:
                return
            case .bootstrap:
                try await bootstrapLock(over: connection)
                // 방금 켰으면 머리가 같아도 동기화를 부른다. 서버에 이 노드의 머리를 알리는 길이다(Go `didJustEnable`).
                try await synchronizeLock(over: connection)
            case .synchronize:
                try await synchronizeLock(over: connection)
            case .verifyDisablement:
                if try await disableLockIfVerified(over: connection) { return }
                // 비밀이 틀렸다: lock을 유지하고, 서버가 알린 머리와 다르면 동기화를 이어서 한다(동작 O4).
                if lockAuthority?.head != lockSession.server.head {
                    try await synchronizeLock(over: connection)
                }
            }
        } catch {
            let kind = switch error {
            case let error as TKAError: "검증(\(error))"
            case ControlError.http(let status): "HTTP \(status)"
            case is LockResponseError: "응답의 해시"
            default: "요청 또는 응답 본문"
            }
            Self.lockLog.error(
                "tailnet lock: \(String(describing: plan), privacy: .public) 실패, 종류 \(kind, privacy: .public)"
            )
        }
    }

    /// 서버가 준 체크포인트로 서명 권한 상태를 시작한다(동작 N2의 `bootstrap`, F5). 첫 신뢰는 그 체크포인트에 대한 TOFU다.
    private func bootstrapLock(over connection: ControlConnection) async throws {
        let response = try await tkaBootstrap(head: nil, over: connection)
        let authority = try Authority(bootstrappingWith: AUM(decoding: response.genesisAUM))
        lockAuthority = authority
        saveLock(authority)
        Self.lockLog.info("tailnet lock: 부트스트랩함")
    }

    /// 서버와 AUM을 주고받아 머리를 맞춘다(동작 Y, Go `tkaSyncLocked`).
    private func synchronizeLock(over connection: ControlConnection) async throws {
        guard var authority = lockAuthority else { return }
        let offer = authority.syncOffer()
        let response = try await tkaSyncOffer(offer, over: connection)
        let hashes = try ([response.head] + response.ancestors).map { text throws(LockResponseError) -> AUMHash in
            guard let hash = AUMHash(text: text) else { throw .unreadableHash }
            return hash
        }
        let serverOffer = SyncOffer(head: hashes[0], ancestors: Array(hashes.dropFirst()))
        guard serverOffer.head != offer.head else {
            isLockStateDiverged = false
            return
        }

        // 서버가 모르는 로컬 AUM을 먼저 계산한다. 이 계산이 실패하면 들이지도 보내지도 않는다(동작 Y4).
        // 공통 조상이 없다는 것(`noIntersection`)만 "이어지지 않음"으로 본다(5절 TL-11b 항목 4). 서버가 답한 사슬에 대한 로컬
        // 계산의 결과라 RPC 실패와 섞이지 않는다. 반복 한도(`iterationLimit`)는 사슬이 길다는 것일 뿐이라 넣지 않는다.
        let unknownToServer: [AUM]
        do {
            unknownToServer = try authority.missingAUMs(for: serverOffer)
            isLockStateDiverged = false
        } catch {
            if error == .noIntersection { isLockStateDiverged = true }
            throw error
        }
        if !response.missingAUMs.isEmpty {
            let updates = try response.missingAUMs.map { bytes throws(TKAError) in try AUM(decoding: bytes) }
            // 하나라도 통과하지 못하면 아무것도 들지 않고, 예전 상태로 계속 거른다.
            try authority.inform(updates)
            lockAuthority = authority
            saveLock(authority)
            // 쥔 수는 받은 수만큼 늘지 않을 수 있다: 이미 쥔 것은 다시 세지 않고, 활성 사슬 밖의 것은 한도에서 버린다.
            Self.lockLog.info(
                "tailnet lock: AUM \(updates.count, privacy: .public)개를 받아 들임(쥔 수 \(authority.aums.count, privacy: .public))")
        }
        let sent = try await tkaSyncSend(head: authority.head, missing: unknownToServer, over: connection)
        guard let serverHead = AUMHash(text: sent.head) else { throw LockResponseError.unreadableHash }
        if serverHead != authority.head {
            Self.lockLog.notice("tailnet lock: 동기화 뒤에도 서버와 머리가 다르다")
        }
    }

    /// 서버가 준 끄기 비밀이 맞으면 로컬 상태를 지운다(동작 O). 지웠으면 true.
    ///
    /// 서버의 "꺼졌다"만 믿고 지우지 않는다. 끄기 값은 신뢰 체크포인트에 서명되어 있으므로, 비밀 검증이 제어 서버가 lock을
    /// 끄지 못하게 지킨다.
    private func disableLockIfVerified(over connection: ControlConnection) async throws -> Bool {
        guard let authority = lockAuthority else { return true }
        let response = try await tkaBootstrap(head: authority.head, over: connection)
        guard isValidDisablement(response.disablementSecret, for: authority) else {
            Self.lockLog.notice("tailnet lock: 끄기 비밀이 맞지 않아 lock을 유지한다")
            return false
        }
        lockAuthority = nil
        isLockStateDiverged = false
        do {
            try lockStore.remove()
        } catch {
            // 메모리의 상태는 없앴다. 파일이 남으면 다음 시작에 다시 열려 lock이 유지된다(닫힌 쪽, 동작 T5).
            Self.lockLog.error("tailnet lock: 상태 파일을 지우지 못했다")
        }
        return true
    }

    /// 머리 하나에 대해 기억하는 거절한 끄기 비밀의 수(계약 5절 TL-11b 항목 2). 넘치면 오래된 것부터 잊는다.
    static let maximumRejectedDisablementCount = 8

    /// 끄기 비밀을 검증한다. 같은 상태에서 이미 거절한 비밀은 다시 계산하지 않는다(동작 O6, TL-11b 항목 2).
    ///
    /// 검증은 Argon2i로 16MiB를 쓴다. 서버가 `Disabled`를 되풀이해 보내도 netmap마다 돌지 않게, 거절한 비밀들의 BLAKE2s-256과
    /// 그때의 머리를 메모리에만 쥔다(끄기 값은 머리가 가리키는 상태의 것이므로 머리가 같으면 판정도 같다). 하나가 아니라
    /// 집합인 것은 서버가 틀린 비밀 여럿을 번갈아 보내도 비밀마다 한 번만 돌게 하려는 것이다.
    /// 계산은 이 actor 위에서 멈춤 없이 돈다: 그동안 맵 프레임의 해독이 겹치지 않아 메모리 최고치가 포개지지 않는다.
    private func isValidDisablement(_ secret: [UInt8], for authority: Authority) -> Bool {
        let digest = BLAKE2s.hash(secret)
        var rejected = rejectedDisablements?.head == authority.head ? rejectedDisablements?.secretDigests ?? [] : []
        if rejected.contains(where: { constantTimeEqual($0, digest) }) { return false }
        disablementDerivationCount += 1
        guard !authority.isValidDisablement(secret: secret) else {
            rejectedDisablements = nil
            return true
        }
        rejected.append(digest)
        rejectedDisablements = (authority.head, Array(rejected.suffix(Self.maximumRejectedDisablementCount)))
        return false
    }

    /// 상태를 파일에 적는다. 실패해도 판정은 바뀌지 않는다: 메모리의 상태로 계속 거르고 다음 변화 때 다시 쓴다(동작 T2).
    private func saveLock(_ authority: Authority) {
        do {
            try lockStore.save(authority)
        } catch {
            Self.lockLog.error("tailnet lock: 상태를 저장하지 못했다")
        }
    }

    /// 로컬 머리가 마지막으로 보낸 값과 달라졌으면 상태 올리기를 한 번 더 건다(동작 N4, Go `SetTKAHead`).
    ///
    /// 응답을 받은 값(`uploadedTKAHead`)이 아니라 보낸 값과 견준다. 올리는 응답을 기다리는 사이 머리가 바뀌어도(lock이 꺼져
    /// 빈 머리로 돌아가도) 그 응답 뒤에 지금 머리를 올린다. Go는 바뀔 때마다 세대를 올려 같은 일을 한다(`auto.go`
    /// `updateControl`·`updateRoutine`). 같은 머리를 거듭 올리지 않는 것은 `uploadStatus`가 맡는다.
    private func announceLockHead() {
        guard lockHeadText != sentTKAHead, !isStatusChangeQueued, let signals else { return }
        isStatusChangeQueued = true
        signals.yield(.statusChanged)
    }

    // MARK: RPC

    /// `GET /machine/tka/bootstrap`. lock을 켤 때는 머리 없이(체크포인트를 받는다), 끌 때는 로컬 머리를 실어(끄기 비밀을
    /// 받는다) 부른다.
    func tkaBootstrap(head: AUMHash?, over connection: ControlConnection) async throws(ControlError) -> TKABootstrapResponse {
        let request = TKABootstrapRequest(nodeKey: try registeredNodeKey(), head: head?.text ?? "")
        return try await tkaExchange("/machine/tka/bootstrap", request, limit: Self.maximumTKAResponseSize, over: connection)
    }

    /// `GET /machine/tka/sync/offer`. 로컬 머리와 조상을 알리고 서버의 것과 이 노드에 없는 AUM을 받는다.
    func tkaSyncOffer(_ offer: SyncOffer, over connection: ControlConnection) async throws(ControlError) -> TKASyncOfferResponse {
        let request = TKASyncOfferRequest(
            nodeKey: try registeredNodeKey(), head: offer.head.text, ancestors: offer.ancestors.map(\.text)
        )
        return try await tkaExchange(
            "/machine/tka/sync/offer", request, limit: Self.maximumTKASyncOfferResponseSize, over: connection
        )
    }

    /// `GET /machine/tka/sync/send`. 동기화 뒤의 로컬 머리와 서버가 모르는 로컬 AUM을 보낸다.
    func tkaSyncSend(
        head: AUMHash, missing: [AUM], over connection: ControlConnection
    ) async throws(ControlError) -> TKASyncSendResponse {
        let request = TKASyncSendRequest(
            nodeKey: try registeredNodeKey(), head: head.text, missingAUMs: missing.map { $0.serialized() }
        )
        return try await tkaExchange("/machine/tka/sync/send", request, limit: Self.maximumTKAResponseSize, over: connection)
    }

    private func registeredNodeKey() throws(ControlError) -> NodePublicKey {
        guard let nodeKey = nodePublicKey else { throw .connection("등록 전에는 TKA 요청을 보낼 수 없다") }
        return nodeKey
    }

    /// TKA RPC 하나: Noise 채널 위의 `GET`에 JSON 본문을 싣고 JSON 응답을 받는다(동작 Y7).
    ///
    /// `Content-Type`과 부하 분산 머리를 붙이지 않는다(Go `DoNoiseRequest`). 200이 아니면 본문을 읽지 않고 실패한다.
    /// 429·`Retry-After` 처리는 없다. 요청마다 `timeouts.tkaRequest`(60초) 안에 끝나야 한다.
    private func tkaExchange<Response: Decodable & Sendable>(
        _ path: String, _ body: some Encodable, limit: Int, over connection: ControlConnection
    ) async throws(ControlError) -> Response {
        let encoded: [UInt8]
        do {
            encoded = Array(try JSONEncoder().encode(body))
        } catch {
            throw .connection("TKA 요청을 JSON으로 만들지 못했다")
        }
        let request = HTTP2ClientConnection.Request(method: "GET", path: path, authority: connection.authority)
        let timeout = timeouts.tkaRequest
        let received: [UInt8]
        do {
            received = try await withTimeout(timeout) {
                var reader = try await connection.responseStream(to: request, body: encoded)
                // 읽개를 버리면 스트림이 취소된다(RST_STREAM). 거절의 본문은 읽지 않는다.
                guard reader.status == 200 else { throw ControlError.http(status: reader.status) }
                var collected: [UInt8] = []
                while let chunk = try await reader.nextChunk() {
                    guard collected.count + chunk.count <= limit else {
                        throw ControlError.connection("TKA 응답 본문이 한도(\(limit)바이트)를 넘는다")
                    }
                    collected += chunk
                }
                return collected
            }
        } catch let error as ControlError {
            throw error
        } catch is TimeoutError {
            throw .connection("TKA 요청이 \(timeout) 안에 끝나지 않았다")
        } catch {
            throw .connection("TKA 요청이 취소되었다")
        }
        do {
            return try JSONDecoder().decode(Response.self, from: Data(received))
        } catch {
            throw .connection("TKA 응답이 기대한 JSON이 아니다")
        }
    }
}
