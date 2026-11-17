import CoreGraphics
import Foundation
import Observation
import Swiftail
import SwiftailPairing

/// 여는 쪽: 제안을 열고, 들어오는 기기의 승인을 사용자에게 묻고, 짝 목록을 쥐고, 짝에게만 인사를 돌려준다.
///
/// `start(on:)`이 노드 위에 `PairingHost`를 만들고 `stop()`이 내린다. 그 사이의 일은 `serve`의 TaskGroup 하나에 있다:
///
/// ```
/// serve
///  ├ PairingHost.run()   짝 맺기 포트(4747). 끝나면 나머지를 취소한다
///  ├ greet               짝이 된 뒤의 연결 예(4748)
///  └ PairingHost.events  짝 목록이 바뀌면 다시 읽는다
/// ```
@MainActor @Observable
final class HostModel {
    /// 사용자의 답을 기다리는 승인 하나.
    struct Approval: Identifiable {
        let id: UUID
        let request: PairingRequest
        fileprivate let answer: CheckedContinuation<Bool, Never>
    }

    /// 화면에 낸 제안. 링크와 QR은 비밀이다.
    struct OpenOffer {
        let url: URL
        let qrCode: CGImage?
        let expires: Date
        let carriesAuthKey: Bool
    }

    static let pairingPort: UInt16 = 4747
    static let greetingPort: UInt16 = 4748
    /// 제안 링크의 앞부분. `Info.plist`의 URL 스킴과 같아야 들어오는 쪽 앱이 열린다.
    static let linkBase: URL = {
        guard let url = URL(string: "swiftail-demo://pair") else { preconditionFailure("고정된 링크 앞부분은 올바른 URL이다") }
        return url
    }()

    /// 여는 쪽이 돌고 있는가.
    var isRunning: Bool { host != nil }
    private(set) var offer: OpenOffer?
    /// 이 호스트에서 연 제안의 수와, 사건(`.opened`)으로 알려진 수. 같을 때의 상태 사건만 지금 제안의 것이다.
    @ObservationIgnored private var openedOffers = 0
    @ObservationIgnored private var announcedOffers = 0
    private(set) var approvals: [Approval] = []
    private(set) var peers: [PairedPeer] = []
    /// 저장된 OAuth 클라이언트의 ID. 없으면 nil.
    private(set) var oauthClientID = OAuthClientKeychain.load()?.id
    /// 마지막 실패의 안내.
    var message: String?

    private let log: EventLog
    private let automation: Automation?
    private var host: PairingHost?
    /// `host`가 묶인 노드.
    private var hostedNode: TailnetNode?
    private var serving: Task<Void, Never>?

    init(log: EventLog, automation: Automation?) {
        self.log = log
        self.automation = automation
    }

    // MARK: 수명

    /// `node` 위에서 여는 쪽을 돌린다. 이미 그 노드 위에서 돌고 있으면 아무 일도 하지 않는다. 다른 노드 위의 것은 먼저 내린다
    /// (`PairingHost`는 노드 하나에 묶여 있고, 같은 짝 목록 디렉터리를 둘이 쓸 수 없다).
    func start(on node: TailnetNode) async {
        guard hostedNode !== node else { return }
        await stop()
        do throws(PairingError) {
            let host = try await PairingHost(node: node, port: Self.pairingPort, storeDirectory: Storage.pairingStore) {
                [weak self] request in await self?.decide(request) ?? false
            }
            self.host = host
            hostedNode = node
            openedOffers = 0
            announcedOffers = 0
            peers = await host.pairedPeers
            log.record(.host, "started", "짝 \(peers.count)개")
            serving = Task { await self.serve(host, on: node) }
        } catch {
            fail("started", error)
        }
    }

    func stop() async {
        serving?.cancel()
        await serving?.value
    }

    /// `PairingHost.run()`이 끝날 때까지 돈다. 취소되거나 노드가 끝나면 돌아온다.
    private func serve(_ host: PairingHost, on node: TailnetNode) async {
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await self.greet(host, on: node) }
            group.addTask {
                for await event in host.events {
                    switch event {
                    case .pairedPeerAdded, .pairedPeerRemoved: await self.refreshPeers(from: host)
                    case .offerChanged(let state): await self.offerChanged(state)
                    }
                }
            }
            do throws(PairingError) {
                try await host.run()
            } catch {
                fail("run", error)
            }
            group.cancelAll()
        }
        self.host = nil
        hostedNode = nil
        serving = nil
        offer = nil
    }

    // MARK: 제안

    /// 제안의 사건을 화면에 맞춘다. 쓰였거나 만료됐거나 닫힌 제안의 QR과 링크는 더 보이지 않는다(비밀이 든 링크다).
    /// 사건은 차례대로 오므로, 받은 `.opened`의 수가 연 수와 같을 때의 상태 사건만 지금 화면의 제안의 것이다.
    private func offerChanged(_ state: PairingHost.OfferState) {
        switch state {
        case .opened: announcedOffers += 1
        case .used, .expired, .closed:
            if announcedOffers == openedOffers { offer = nil }
        }
    }

    func openOffer(lifetime: Duration, authKey: String?) async {
        guard let host else { return }
        message = nil
        do throws(PairingError) {
            let offer = try await host.openOffer(lifetime: lifetime, authKey: authKey)
            openedOffers += 1
            let url = offer.url(base: Self.linkBase)
            self.offer = OpenOffer(
                url: url, qrCode: offer.qrCode(base: Self.linkBase), expires: offer.expires, carriesAuthKey: authKey != nil)
            log.record(
                .host, "offer-opened", "수명 \(lifetime.components.seconds)초, 인증 키 \(authKey == nil ? "없음" : "있음")")
            if automation?.writesOfferLink == true {
                let written = (try? Data(url.absoluteString.utf8).write(to: Storage.offerLink, options: .atomic)) != nil
                log.record(.host, "offer-link-file", written ? "씀" : "쓰지 못함")
            }
        } catch {
            fail("offer-opened", error)
        }
    }

    /// 저장된 OAuth 클라이언트로 1회용 인증 키를 만들어 제안에 싣는다. 키의 수명은 제안과 같다.
    func openOfferWithIssuedKey(lifetime: Duration) async {
        guard let client = OAuthClientKeychain.load() else {
            message = "OAuth 클라이언트를 먼저 저장하세요."
            return
        }
        message = nil
        do throws(AuthKeyIssueError) {
            let issued = try await AuthKeyIssuer(client: client).issue(lifetime: lifetime)
            log.record(.host, "auth-key-issued", "성공")
            await openOffer(lifetime: lifetime, authKey: issued.key)
        } catch {
            message = error.guidance
            log.record(.host, "auth-key-issued", "실패: \(error)")
        }
    }

    func closeOffer() async {
        await host?.closeOffer()
        offer = nil
        log.record(.host, "offer-closed", "닫음")
    }

    // MARK: OAuth 클라이언트

    /// 모양을 검사하고 키체인에 둔다. 태그는 쉼표로 가른다.
    func saveOAuthClient(id: String, secret: String, tags: String) {
        let client = TailscaleOAuthClient(
            id: id.trimmingCharacters(in: .whitespaces), secret: secret.trimmingCharacters(in: .whitespaces),
            tags: tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) })
        do throws(AuthKeyIssueError) {
            _ = try AuthKeyIssuer(client: client)
        } catch {
            message = error.guidance
            return
        }
        guard OAuthClientKeychain.save(client) else {
            message = "키체인에 저장하지 못했습니다."
            return
        }
        message = nil
        oauthClientID = client.id
    }

    func removeOAuthClient() {
        OAuthClientKeychain.remove()
        oauthClientID = nil
    }

    // MARK: 승인

    /// `PairingHost`의 `decide`. 사용자의 답을 기다린다. 상대가 끊거나 120초가 지나면 이 Task가 취소되고, 그때는 승인
    /// 화면을 내리고 곧 돌아간다.
    private func decide(_ request: PairingRequest) async -> Bool {
        // 증명을 마친 제안은 이미 쓰였다(계약 P4). 화면의 QR을 내린다.
        offer = nil
        log.record(
            .host, "approval-requested",
            automation?.logsConfirmationCode == true ? "확인 숫자 \(request.confirmationCode)" : "사용자의 답을 기다림")
        if automation?.approvesAutomatically == true {
            log.record(.host, "approval", "자동 승인")
            return true
        }
        let id = UUID()
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                approvals.append(Approval(id: id, request: request, answer: continuation))
            }
        } onCancel: {
            Task { @MainActor in self.answer(id, approved: false, by: "취소됨(상대가 끊었거나 시간 초과)") }
        }
    }

    func approve(_ approval: Approval) { answer(approval.id, approved: true, by: "승인") }
    func deny(_ approval: Approval) { answer(approval.id, approved: false, by: "거절") }

    private func answer(_ id: UUID, approved: Bool, by result: String) {
        guard let index = approvals.firstIndex(where: { $0.id == id }) else { return }
        approvals.remove(at: index).answer.resume(returning: approved)
        log.record(.host, "approval", result)
    }

    // MARK: 짝 목록

    func remove(_ peer: PairedPeer) async {
        guard let host else { return }
        do throws(PairingError) {
            try await host.removePairedPeer(withStableID: peer.peer.stableID)
            log.record(.host, "peer-removed", "지움")
        } catch {
            fail("peer-removed", error)
        }
    }

    private func refreshPeers(from host: PairingHost) async {
        let latest = await host.pairedPeers
        guard latest != peers else { return }
        // 새로 짝이 됐거나 같은 노드가 다시 짝이 됐다(그때는 항목의 `pairedAt`이 바뀐다).
        if latest.contains(where: { !peers.contains($0) }) {
            log.record(.host, "paired", "짝 \(latest.count)개")
        }
        peers = latest
    }

    // MARK: 짝이 된 뒤의 연결

    /// 인사 포트에서 듣는다. 연결의 상대를 `whoIs`로 찾아 짝 목록에 있을 때만 한 줄을 돌려준다.
    private func greet(_ host: PairingHost, on node: TailnetNode) async {
        let listener: TailnetListener
        do throws(ConnectionError) {
            listener = try await node.listen(port: Self.greetingPort)
        } catch {
            log.record(.host, "greeting-listen", "실패: \(error)")
            return
        }
        await withDiscardingTaskGroup { group in
            for await connection in listener {
                group.addTask { await self.greet(connection, host: host, node: node) }
            }
        }
        await listener.close()
    }

    private func greet(_ connection: TailnetConnection, host: PairingHost, node: TailnetNode) async {
        guard let identity = await node.whoIs(connection.remoteEndpoint.address),
            let peer = await host.pairedPeer(withStableID: identity.stableID)
        else {
            await connection.abort()
            log.record(.host, "greeting", "거절: 짝이 아님")
            return
        }
        do throws(ConnectionError) {
            try await connection.write(Array("안녕하세요, \(peer.deviceName)\n".utf8))
            await connection.close()
            log.record(.host, "greeting", "보냄")
        } catch {
            await connection.abort()
            log.record(.host, "greeting", "실패: \(error)")
        }
    }

    private func fail(_ event: String, _ error: PairingError) {
        message = error.guidance
        log.record(.host, event, "실패: \(error)")
    }
}
