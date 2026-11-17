import Foundation
import Swiftail
import SwiftailBase
import os

/// 짝 맺기의 여는 쪽. 제안을 내고, tailnet 포트에서 들어오는 쪽을 받아 절차를 돌리고, 짝 목록을 쥔다.
///
/// 이 actor는 가장자리다. 절차의 판단은 입출력 없는 `PairingHostMachine`이 하고, 여기서는 그것을 노드의 리스너·연결,
/// 시계, 난수, 앱의 결정(`decide`), 짝 목록 파일과 잇는다. 동시성은 구조적이다: `run()`을 부른 Task를 취소하면 모두 멈춘다.
///
/// ```
/// run()
///  └ TaskGroup: 받은 연결마다 serve(connection)
///     └ TaskGroup: 연결 하나의 수명. 절차가 끝나면 나머지를 취소한다
///        ├ 읽기            받은 바이트·끊김 → 상태 기계
///        ├ 기한            증명 10초, 승인 120초
///        └ decide(request) 앱의 결정. 상대가 끊으면 취소된다
/// ```
///
/// ```swift
/// let host = try await PairingHost(node: node, port: 4747, storeDirectory: directory) { request in
///     await approvalScreen.ask(request)   // 확인 숫자를 보여 주고 사용자의 답을 기다린다
/// }
/// let running = Task { try await host.run() }
/// let offer = try await host.openOffer()
/// show(offer.qrCode(base: pairingBaseURL))   // 앱의 주소: myapp://pair, https://example.com/pair
/// ```
///
/// 짝이 된 뒤의 연결은 앱이 가린다: 연결의 신원을 `TailnetNode.whoIs(_:)`로 얻어 `pairedPeer(withStableID:)`에 묻는다.
///
/// 여는 쪽은 프로세스 안 노드(`.inProcess`)여야 한다. `listen`이 그 장치에서만 된다.
/// 계약 `docs/contracts/SwiftailPairing.md` 5·6절.
public actor PairingHost {
    /// 요약만 남긴다: 받음, 닫은 까닭, 결정. 비밀·증명·인증 키·확인 숫자·이름·주소는 남기지 않는다(계약 동작 P10).
    private static let log = Logger(subsystem: "Swiftail", category: "pairing")

    /// 연결 하나의 흐름에 들어오는 사건.
    private enum SessionEvent: Sendable {
        case received([UInt8])
        /// EOF나 오류로 읽기가 끝났다.
        case ended
        /// 기한이 됐을 수 있다. 판정은 상태 기계가 한다.
        case timer
        case decided(Bool)
    }

    private let node: TailnetNode
    private let port: UInt16
    private let decide: @Sendable (PairingRequest) async -> Bool
    private let file: PairedPeerFile
    /// 짝 목록 디렉터리를 쥔 열쇠. 버려질 때 푼다.
    private let claim: String
    private var peers: PairedPeerList
    private var machine = PairingHostMachine()
    private var nextSessionID: PairingHostMachine.SessionID = 0

    /// 짝 목록을 읽고 여는 쪽을 만든다. 듣기는 `run()`이 시작한다.
    ///
    /// - Parameters:
    ///   - node: 짝 맺기 연결을 받을 노드. 장치가 `.inProcess`여야 한다.
    ///   - port: 짝 맺기 연결을 받을 tailnet 포트. 제안의 링크에 실린다.
    ///   - storeDirectory: `paired-peers.json`을 둘 디렉터리. 없으면 첫 저장 때 만든다.
    ///   - decide: 승인을 묻는다. 상대가 끊거나 120초가 지나면 이 호출의 Task가 취소되니, 취소되면 곧 돌아와야 한다
    ///     (돌려준 값은 버린다).
    /// - Throws: 노드의 장치가 `.inProcess`가 아니거나 포트가 0이면 `invalidConfiguration`, 목록 파일을 읽지 못하면
    ///   `storeUnreadable`, 같은 디렉터리를 쓰는 호스트가 이 프로세스에 이미 있으면 `storeInUse`.
    public init(
        node: TailnetNode, port: UInt16, storeDirectory: URL,
        decide: @escaping @Sendable (PairingRequest) async -> Bool
    ) async throws(PairingError) {
        guard node.hasInProcessDevice else {
            throw .invalidConfiguration("여는 쪽은 .inProcess 장치의 노드여야 한다")
        }
        guard port != 0 else { throw .invalidConfiguration("포트는 0이 아니어야 한다") }
        guard storeDirectory.isFileURL else { throw .invalidConfiguration("짝 목록 디렉터리는 파일 URL이어야 한다") }
        guard let claim = StoreDirectoryClaims.shared.claim(storeDirectory) else { throw .storeInUse }
        let file = PairedPeerFile(directory: storeDirectory)
        do throws(PairingError) {
            peers = try file.load()
        } catch {
            StoreDirectoryClaims.shared.release(claim)
            throw error
        }
        self.node = node
        self.port = port
        self.decide = decide
        self.file = file
        self.claim = claim
    }

    deinit {
        StoreDirectoryClaims.shared.release(claim)
    }

    // MARK: 제안 (동작 P9)

    /// 새 제안을 연다. 앞의 제안은 그 자리에서 못 쓴다. 제안은 한 번만 쓰인다.
    ///
    /// `run()` 전에도 된다(연결은 `run()`이 듣기 시작해야 받는다). 돌려준 값의 링크와 QR은 비밀이다.
    ///
    /// - Parameters:
    ///   - lifetime: 제안의 수명. 초 단위로 버리고 1~3600초여야 한다. lock이 켜진 tailnet에서는 들어오는 노드가 서명될
    ///     때까지 걸리는 만큼 길게 연다.
    ///   - authKey: 들어오는 쪽이 tailnet에 들어올 때 쓸 1회용 인증 키. 링크에 싣는다.
    /// - Throws: 수명이 범위 밖이면 `invalidConfiguration`, 인증 키가 링크에 실을 수 없는 모양이면(감싼 키 포함)
    ///   `invalidAuthKey`, 노드에 자기 FQDN이 아직 없으면 `notRunning`.
    public func openOffer(
        lifetime: Duration = .seconds(300), authKey: String? = nil
    ) async throws(PairingError) -> PairingOffer {
        let seconds = lifetime.components.seconds
        guard (1...3600).contains(seconds) else { throw .invalidConfiguration("제안의 수명은 1~3600초여야 한다") }
        if let authKey {
            do throws(PairingOfferError) {
                _ = try OfferField.authKey(authKey.utf8)
            } catch {
                throw .invalidAuthKey
            }
        }
        // 낸 링크가 반드시 읽히도록 읽는 쪽과 같은 규칙으로 본다.
        guard let fqdn = await node.status.fqdn, let host = OfferField.host(fqdn.lowercased().utf8) else {
            throw .notRunning
        }
        let expires = Date(timeIntervalSince1970: Date().timeIntervalSince1970.rounded(.down) + Double(seconds))
        let offer = PairingOffer(
            host: host, port: port, expires: expires, authKey: authKey,
            secret: PairingRandom.bytes(PairingOffer.secretLength))
        machine.open(offer)
        Self.log.info("제안을 엶: 수명 \(seconds, privacy: .public)초")
        return offer
    }

    /// 열린 제안을 닫는다. 이미 증명을 마치고 승인을 기다리는 연결은 그대로 간다(동작 P6).
    public func closeOffer() {
        machine.closeOffer()
        Self.log.info("제안을 닫음")
    }

    // MARK: 짝 목록 (동작 S1~S4)

    /// 짝 목록. 짝이 된 차례대로다.
    public var pairedPeers: [PairedPeer] { peers.peers }

    /// 이 `StableID`의 짝. 없으면 nil. 연결의 상대가 짝인지 가릴 때 `whoIs(상대 주소)?.stableID`를 넘긴다.
    public func pairedPeer(withStableID stableID: String) -> PairedPeer? {
        peers.peer(withStableID: stableID)
    }

    /// 짝을 지우고 저장한다. 없는 짝이면 아무 일도 하지 않는다.
    ///
    /// - Throws: 저장하지 못하면 `storeWriteFailed`. 그때 목록은 그대로다.
    public func removePairedPeer(withStableID stableID: String) throws(PairingError) {
        var updated = peers
        guard updated.remove(stableID: stableID) else { return }
        try file.save(updated)
        peers = updated
    }

    /// 짝을 넣고 저장한다. 목록이 가득 찼거나 저장하지 못하면 넣지 않고 false.
    private func save(_ peer: PairedPeer) -> Bool {
        var updated = peers
        guard updated.insert(peer) else { return false }
        do throws(PairingError) {
            try file.save(updated)
        } catch {
            return false
        }
        peers = updated
        return true
    }

    // MARK: 절차

    /// 포트를 듣고 들어오는 연결마다 절차를 돌린다. 부른 Task가 취소될 때까지 돌아오지 않는다. 취소되면 절차 중인 연결을
    /// 닫고 돌아온다.
    ///
    /// - Throws: 포트를 이미 쓰고 있거나 리스너가 한도에 닿았으면 `invalidConfiguration`, 노드의 `run()`이 끝났으면
    ///   (듣는 중에 끝나도) `notRunning`.
    public func run() async throws(PairingError) {
        let listener: TailnetListener
        do throws(ConnectionError) {
            listener = try await node.listen(port: port)
        } catch {
            switch error {
            case .notRunning: throw .notRunning
            case .addressInUse: throw .invalidConfiguration("그 포트를 이미 듣고 있다")
            default: throw .invalidConfiguration("포트를 열지 못했다")
            }
        }
        Self.log.info("짝 맺기 연결을 듣기 시작")
        await withDiscardingTaskGroup { group in
            for await connection in listener {
                group.addTask { await self.serve(connection) }
            }
            group.cancelAll()
        }
        await listener.close()
        Self.log.info("짝 맺기 연결 듣기 끝")
        if !Task.isCancelled { throw .notRunning }
    }

    /// 연결 하나의 절차를 끝까지 돌리고 닫는다.
    private func serve(_ connection: TailnetConnection) async {
        let acceptedAt = ContinuousClock.now
        let id = nextSessionID
        nextSessionID += 1
        let endpoints = PairingEndpoints(joiner: connection.remoteEndpoint, host: connection.localEndpoint)
        // P1: 연결의 원격 주소는 WireGuard가 인증한 피어의 것이다. 그 신원을 모르면 읽지 않는다.
        let peer = await node.whoIs(endpoints.joiner.address)
        let (events, continuation) = AsyncStream.makeStream(of: SessionEvent.self)

        await withTaskGroup(of: Void.self) { group in
            let first = machine.accept(
                id, from: peer, endpoints: endpoints, nonce: PairingRandom.bytes(PairingMessage.nonceLength),
                at: acceptedAt)
            Self.log.info("짝 맺기 연결을 받음")
            if let deadline = machine.deadline(of: id) {
                group.addTask {
                    // 들어오는 쪽이 보낼 것은 hello와 proof뿐이다. 그보다 많이 왔으면 상태 기계가 이미 위반으로 끝냈으니
                    // 더 읽지 않는다. 처리를 기다리며 쌓이는 바이트가 이 상한을 크게 넘지 못한다.
                    var remaining = PairingMessage.maximumJoinerLength
                    while remaining >= 0, let bytes = try? await connection.read(upTo: 256) {
                        remaining -= bytes.count
                        continuation.yield(.received(bytes))
                    }
                    continuation.yield(.ended)
                }
                Self.addTimer(until: deadline, to: &group, continuation)
            }
            if await perform(first, for: id, on: connection, in: &group, continuation) {
                for await event in events {
                    let actions: [PairingHostMachine.Action]
                    switch event {
                    case .received(let bytes):
                        actions = machine.receive(bytes, on: id, wallClock: Date(), now: .now)
                    case .ended:
                        actions = machine.connectionEnded(id)
                    case .timer:
                        actions = machine.advance(id, to: .now)
                    case .decided(let approved):
                        // P7: 승인하는 그 순간의 신원을 다시 본다.
                        let currentPeer = await node.whoIs(endpoints.joiner.address)
                        let host = await node.whoIs(endpoints.host.address)
                        actions = machine.decided(
                            id, approved: approved, currentPeer: currentPeer, host: host, at: Date())
                    }
                    guard await perform(actions, for: id, on: connection, in: &group, continuation) else { break }
                }
            }
            // `run()`이 취소되어 나왔으면 자리가 남아 있다. 비운다.
            _ = machine.connectionEnded(id)
            group.cancelAll()
            // 보낸 것이 나간 뒤 FIN으로 닫는다. 결정 Task가 취소에 늦게 응해도 연결은 먼저 닫힌다.
            await connection.close()
        }
    }

    /// 상태 기계가 낸 할 일을 한다. 연결이 끝났으면(`finish`) false.
    private func perform(
        _ actions: [PairingHostMachine.Action], for id: PairingHostMachine.SessionID, on connection: TailnetConnection,
        in group: inout TaskGroup<Void>, _ continuation: AsyncStream<SessionEvent>.Continuation
    ) async -> Bool {
        var pending = actions[...]
        while let action = pending.popFirst() {
            switch action {
            case .send(let bytes):
                // 보내지 못했으면 연결이 끝난 것이고, 그 사실은 읽기가 알린다.
                try? await connection.write(bytes)
            case .requestDecision(let request):
                Self.log.info("증명이 맞음. 앱의 승인을 기다림")
                let decide = decide
                group.addTask { continuation.yield(.decided(await decide(request))) }
                if let deadline = machine.deadline(of: id) { Self.addTimer(until: deadline, to: &group, continuation) }
            case .save(let peer):
                pending.append(contentsOf: machine.saved(id, succeeded: save(peer)))
            case .finish(let ending):
                Self.log.info("짝 맺기 연결을 닫음: \(ending.rawValue, privacy: .public)")
                return false
            }
        }
        return true
    }

    private static func addTimer(
        until deadline: ContinuousClock.Instant, to group: inout TaskGroup<Void>,
        _ continuation: AsyncStream<SessionEvent>.Continuation
    ) {
        group.addTask {
            try? await Task.sleep(until: deadline, clock: .continuous)
            continuation.yield(.timer)
        }
    }
}

/// 시스템 난수. 상태 기계는 난수를 인자로 받고, 뽑는 곳은 가장자리뿐이다.
enum PairingRandom {
    static func bytes(_ count: Int) -> [UInt8] {
        var generator = SystemRandomNumberGenerator()
        return (0..<count).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
    }
}
