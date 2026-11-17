// 페어링 관문 (가)의 하네스(docs/contracts/SwiftailPairing.md 7절 9~11): `tailnet` 도구(testcontrol + DERP + STUN)와
// `.inProcess` Swift 노드들, 그리고 루프백 리스너에 물린 여는 쪽 상태 기계. 기존 관문처럼 도구와 노드를 시험마다 새로 띄우고
// 성공·실패·취소에서 모두 회수한다(상태 디렉터리는 TMPDIR 아래). Go 피어는 띄우지 않는다.

import Foundation
import Network
import Swiftail
import SwiftailBase
import Synchronization
import Testing

@testable import SwiftailPairing

/// 관문의 Swift 노드 하나.
final class PairingNode: Sendable {
    let node: TailnetNode
    private let run: Task<Void, any Error>

    init(directory: URL, hostname: String, controlURL: URL, authKey: String?) throws {
        let node = try TailnetNode(
            configuration: .init(stateDirectory: directory, hostname: hostname, controlURL: controlURL, authKey: authKey),
            device: .inProcess)
        run = Task { try await node.run() }
        self.node = node
    }

    /// `run()`을 끝내고 회수한다. 끝난 까닭이 취소가 아니면 그 설명을 돌려준다.
    @discardableResult
    func stop() async -> String? {
        run.cancel()
        if case .failure(let error) = await run.result, !(error is CancellationError) {
            return redacted(String(describing: error))
        }
        return nil
    }
}

/// 시험 하나의 페어링 관문.
struct PairingGate: Sendable {
    /// 띄운 노드들. 관문이 끝날 때 모두 멈춘다.
    final class Registry: Sendable {
        let nodes = Mutex<[PairingNode]>([])
    }

    let tool: GoTailnet
    let controlURL: URL
    let root: URL
    let registry: Registry

    func startNode(_ label: String, hostname: String, authKey: String? = nil) throws -> PairingNode {
        let node = try PairingNode(
            directory: root.appending(path: label), hostname: hostname, controlURL: controlURL, authKey: authKey)
        registry.nodes.withLock { $0.append(node) }
        return node
    }

    /// 두 노드가 `.running`이고 서로를 netmap에서 볼 때까지 기다린다.
    func waitUntilPeers(_ first: PairingNode, _ second: PairingNode) async throws {
        try await netstackWait("Swift 노드 둘의 상호 netmap 반영") {
            for (node, other) in [(first, second), (second, first)] {
                let status = await node.node.status
                guard status.state == .running, let address = await other.node.status.addresses.first,
                      await node.node.whoIs(address) != nil
                else { return false }
            }
            return true
        }
    }

    /// 여는 쪽을 만들고 `run()`을 돌린 채 `body`를 부른다. 끝나면 `run()`을 취소하고 회수한다.
    func withHost(
        _ node: PairingNode, port: UInt16 = 4_747, approver: Approver,
        _ body: (PairingHost) async throws -> Void
    ) async throws {
        let host = try await PairingHost(node: node.node, port: port, storeDirectory: root.appending(path: "store")) {
            await approver.decide($0)
        }
        let serving = Task { () async -> PairingError? in
            do throws(PairingError) {
                try await host.run()
                return nil
            } catch {
                return error
            }
        }
        do {
            try await body(host)
        } catch {
            serving.cancel()
            _ = await serving.value
            throw error
        }
        serving.cancel()
        let ending = await serving.value
        #expect(ending == nil, "취소된 run()은 던지지 않고 돌아온다")
    }
}

/// 페어링 관문 하나를 띄우고 회수한다. `authKey`를 주면 시험 제어 서버가 그 키로만 등록을 받는다.
func withPairingGate(authKey: String? = nil, _ body: (PairingGate) async throws -> Void) async throws {
    let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-m9-\(UUID().uuidString)")
    let tool = GoTailnet(temporaryDirectory: directory)
    let registry = PairingGate.Registry()
    defer {
        if FileManager.default.fileExists(atPath: directory.path) {
            do { try FileManager.default.removeItem(at: directory) }
            catch { Issue.record("페어링 관문 상태 디렉터리 정리 실패: \(redacted(String(describing: error)))") }
        }
    }
    func stopNodes() async -> [String] {
        var failures: [String] = []
        for node in registry.nodes.withLock({ $0 }) {
            if let failure = await node.stop() { failures.append(failure) }
        }
        return failures
    }
    do {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let ready = try await tool.start()
        if let authKey {
            _ = try await tool.command(.init(cmd: "setAuth", authKey: authKey), expecting: "auth")
        }
        let gate = PairingGate(tool: tool, controlURL: try #require(ready.controlURL), root: directory, registry: registry)
        try await body(gate)
        _ = await stopNodes()
        await tool.stop()
    } catch {
        let failures = await stopNodes()
        await tool.stop()
        var detail = redacted(String(describing: error))
        if !failures.isEmpty { detail += "\nTailnetNode.run: \(failures.joined(separator: "; "))" }
        throw GateFailure("\(detail)\n\(await tool.diagnostics())")
    }
}

/// 여는 쪽 앱의 승인 화면 노릇. 받은 요청을 적고 정해 둔 대로 답한다.
final class Approver: Sendable {
    enum Answer: Sendable {
        case approve, deny
        /// 답하지 않는다. 취소될 때까지 기다린다(상대가 끊으면 가장자리가 이 Task를 취소한다).
        case wait
    }

    private struct State {
        var answer = Answer.approve
        var requests: [PairingRequest] = []
        var cancelledCount = 0
    }

    private let state = Mutex(State())

    var requests: [PairingRequest] { state.withLock { $0.requests } }
    /// 답을 기다리다 취소된 결정의 수.
    var cancelledCount: Int { state.withLock { $0.cancelledCount } }

    func set(_ answer: Answer) {
        state.withLock { $0.answer = answer }
    }

    func decide(_ request: PairingRequest) async -> Bool {
        let answer = state.withLock { state in
            state.requests.append(request)
            return state.answer
        }
        switch answer {
        case .approve: return true
        case .deny: return false
        case .wait:
            while !Task.isCancelled { try? await Task.sleep(for: .seconds(1)) }
            state.withLock { $0.cancelledCount += 1 }
            return false
        }
    }
}

/// 들어오는 쪽이 `awaitingApproval`로 받은 확인 숫자를 모은다.
final class ConfirmationCodes: Sendable {
    private let codes = Mutex<[String]>([])
    private let arrivals: AsyncStream<Void>
    private let continuation: AsyncStream<Void>.Continuation

    init() {
        (arrivals, continuation) = AsyncStream.makeStream(of: Void.self)
    }

    var all: [String] { codes.withLock { $0 } }

    func record(_ code: String) {
        codes.withLock { $0.append(code) }
        continuation.yield()
    }

    /// 다음 확인 숫자가 올 때까지 기다린다.
    func next() async {
        for await _ in arrivals { return }
    }
}

/// `body`가 던진 `PairingError`. 던지지 않으면 nil. 다른 오류는 시험 실패다.
func pairingFailure<T>(_ body: () async throws -> T) async -> PairingError? {
    do {
        _ = try await body()
        return nil
    } catch let error as PairingError {
        return error
    } catch {
        Issue.record("PairingError가 아닌 오류: \(redacted(String(describing: error)))")
        return nil
    }
}

/// 루프백(`127.0.0.1`) 리스너에 여는 쪽 상태 기계를 물린 것(관문 11). tailnet도 노드도 없다.
///
/// 들어오는 쪽의 OS 소켓 길(`NWConnection`)이 실제 TCP 위에서 절차를 끝까지 도는지 본다. 두 끝이 루프백 주소이므로
/// 들어오는 쪽의 대역 검사는 시험만 쓰는 스위치로 끈다. 이름 풀이와 터널은 거치지 않는다.
actor LoopbackPairingHost {
    /// 연결 하나를 돌린 결과.
    struct Served: Sendable {
        var confirmationCode: String?
        var saved: PairedPeer?
        var ending: PairingHostMachine.Ending?
        /// 들어오는 쪽에게서 받은 바이트 수.
        var receivedByteCount = 0
    }

    static let joinerIdentity = PeerIdentity(
        stableID: "nEXAMPLEJOINER", name: "rd-phone-5e6f7a8b.tail0001.ts.net", computedName: "rd-phone-5e6f7a8b",
        loginName: "alice@example.com")
    static let hostIdentity = PeerIdentity(
        stableID: "nEXAMPLEHOST", name: "rd-mac-1a2b3c4d.tail0001.ts.net", computedName: "rd-mac-1a2b3c4d",
        loginName: "alice@example.com")

    nonisolated let port: UInt16
    private let listener: NWListener
    private let accepted: AsyncStream<NWConnection>
    private var machine = PairingHostMachine()
    private var nextID: PairingHostMachine.SessionID = 0

    private init(listener: NWListener, port: UInt16, accepted: AsyncStream<NWConnection>) {
        self.listener = listener
        self.port = port
        self.accepted = accepted
    }

    static func start() async throws -> LoopbackPairingHost {
        let parameters = NWParameters(tls: nil, tcp: NWProtocolTCP.Options())
        parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
        let listener = try NWListener(using: parameters)
        let (accepted, sink) = AsyncStream.makeStream(of: NWConnection.self)
        listener.newConnectionHandler = { sink.yield($0) }
        let (ports, ready) = AsyncStream.makeStream(of: UInt16?.self)
        listener.stateUpdateHandler = { state in
            switch state {
            case .ready: ready.yield(listener.port?.rawValue)
            case .failed, .cancelled: ready.yield(nil)
            default: break
            }
        }
        listener.start(queue: DispatchQueue(label: "test.pairing.listener"))
        var port: UInt16?
        for await value in ports {
            port = value
            break
        }
        guard let port else {
            listener.cancel()
            throw GateFailure("루프백 리스너를 열지 못했다")
        }
        return LoopbackPairingHost(listener: listener, port: port, accepted: accepted)
    }

    nonisolated func close() {
        listener.cancel()
    }

    /// 새 제안을 연다. 호스트 이름 자리에는 루프백 주소를 넣는다(양쪽이 같은 문자열을 T에 넣기만 하면 된다).
    func openOffer() -> PairingOffer {
        let offer = PairingOffer(
            host: "127.0.0.1", port: port, expires: Date().addingTimeInterval(300), authKey: nil,
            secret: PairingRandom.bytes(32))
        machine.open(offer)
        return offer
    }

    var hasOpenOffer: Bool { machine.hasOpenOffer }

    /// 다음 연결 하나를 받아 절차를 끝까지 돌린다.
    func serveNext(approving: Bool) async throws -> Served {
        var connection: NWConnection?
        for await next in accepted {
            connection = next
            break
        }
        guard let connection else { throw GateFailure("루프백 리스너가 닫혔다") }
        let transport = SocketPairingTransport(connection)
        guard await transport.open(), let ends = transport.endpoints else {
            throw GateFailure("받은 루프백 연결이 준비되지 않았다")
        }
        let id = nextID
        nextID += 1
        var served = Served()
        var actions = machine.accept(
            id, from: Self.joinerIdentity, endpoints: PairingEndpoints(joiner: ends.remote, host: ends.local),
            nonce: PairingRandom.bytes(32), at: .now)
        while true {
            while !actions.isEmpty {
                switch actions.removeFirst() {
                case .send(let bytes):
                    await transport.send(bytes)
                case .requestDecision(let request):
                    served.confirmationCode = request.confirmationCode
                    actions += machine.decided(
                        id, approved: approving, currentPeer: Self.joinerIdentity, host: Self.hostIdentity, at: Date())
                case .save(let peer):
                    served.saved = peer
                    actions += machine.saved(id, succeeded: true)
                case .finish(let ending):
                    served.ending = ending
                    await transport.close()
                    return served
                }
            }
            if let bytes = await transport.receive() {
                served.receivedByteCount += bytes.count
                actions = machine.receive(bytes, on: id, wallClock: Date(), now: .now)
            } else {
                actions = machine.connectionEnded(id)
            }
        }
    }
}
