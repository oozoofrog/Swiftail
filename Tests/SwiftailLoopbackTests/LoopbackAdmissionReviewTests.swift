import Foundation
import Network
import SwiftailBase
import Testing
@testable import Swiftail
@testable import SwiftailLoopback

/// 독립 검토(M7-9b)에서 짚은 경우의 재현. 실패하는 시험은 고칠 것이 남았다는 뜻이다(검토 보고 참고).
@Suite("루프백 다리: 검토 재현(M7-9b)", .timeLimit(.minutes(1)))
struct LoopbackAdmissionReviewTests {
    private typealias Support = BridgeTestSupport

    private static let origin = LoopbackBridge.Origin(
        remoteEndpoint: IPEndpoint(address: IPAddress("100.64.0.2")!, port: 41_641), peer: Support.selfIdentity)

    /// TLS 리스너에서 framer는 핸드셰이크 전에 허가를 적는다. 핸드셰이크가 끝나지 않으면 서버는 `.ready`를 보지 못해 계약대로
    /// 묻지 않고, 허가는 256개에 밀려날 때까지 남는다. 남은 열쇠로는 `expect`가 거절하므로, 다리가 같은 출발 포트를 다시 뽑은
    /// 다음 연결은 `loopbackUnavailable`로 끊긴다. tailnet의 상대가 잇자마자 끊기만 해도 하나씩 쌓인다.
    @Test("TLS 핸드셰이크 전에 끝난 다리 연결의 허가는 서버가 가져갈 수 없으므로 남지 않아야 한다")
    func admissionOfUnfinishedHandshakeIsNotLeft() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            let bridge = LoopbackBridge(node: node)
            let server = try await PlainLoopbackServer.start(
                admittingFor: bridge, tls: try SelfSignedIdentity.serverOptions(try SelfSignedIdentity.make()))
            defer { server.close() }
            var keys: [LoopbackAdmissionTable.Key] = []
            for round in 0..<3 {
                let pair = try await Support.connectedPair(node, port: 9_000 + UInt16(round))
                let forwarding = Support.forward(pair.server, with: bridge, toLoopbackPort: server.port)
                let accepted = try #require(await server.nextConnection())
                let outcome = Task { await PeerConnection.start(accepted) }
                try await Support.waitUntil("토큰이 소비됨") { bridge.admission.snapshot.admitted.count == round + 1 }
                // tailnet 쪽이 ClientHello를 보내지 않고 끊는다.
                await pair.client.abort()
                guard case .failed = await outcome.value else {
                    Issue.record("\(round)번째: 핸드셰이크 없이 준비되었다")
                    return
                }
                server.discard(accepted)
                #expect(await forwarding.value == nil)
                if case .hostPort(_, let port) = accepted.endpoint {
                    keys.append(.init(sourcePort: port.rawValue, listenerPort: server.port))
                }
            }
            let left = bridge.admission.snapshot.admitted
            #expect(left.isEmpty, "서버가 .ready를 보지 못한 연결의 허가 \(left.count)개가 남았다")
            for key in keys {
                #expect(bridge.admission.expect(LoopbackAdmissionTable.makeToken(), for: key, origin: Self.origin),
                        "출발 포트 \(key.sourcePort)를 다시 뽑은 다리 연결은 표에 적지 못해 끊긴다")
            }
        }
    }

    /// 위의 허가가 쌓이면 상한(256)이 가장 오래된 허가를 버린다. 핸드셰이크 중인 정당한 연결의 허가도 그 대상이다. tailnet의
    /// 상대 하나가 잇자마자 끊기를 되풀이하면, 다른 상대가 핸드셰이크를 끝내기 전에 그 허가를 밀어낸다.
    @Test("잇자마자 끊는 다리 연결이 쌓여도 핸드셰이크 중인 다른 연결의 허가가 밀려나지 않는다")
    func unfinishedHandshakesDoNotEvictPendingAdmission() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            let bridge = LoopbackBridge(node: node)
            let server = try await PlainLoopbackServer.start(
                admittingFor: bridge, tls: try SelfSignedIdentity.serverOptions(try SelfSignedIdentity.make()))
            defer { server.close() }

            // 정당한 연결: 다리가 토큰을 보내 허가가 적혔고, 상대는 아직 ClientHello를 보내지 않았다.
            let pending = try await Support.connectedPair(node, port: 9_000)
            let pendingForwarding = Support.forward(pending.server, with: bridge, toLoopbackPort: server.port)
            let pendingAccepted = try #require(await server.nextConnection())
            let pendingOutcome = Task { await PeerConnection.start(pendingAccepted) }
            try await Support.waitUntil("정당한 연결의 토큰이 소비됨") { bridge.admission.snapshot.admitted.count == 1 }
            guard case .hostPort(_, let pendingPort) = pendingAccepted.endpoint else {
                Issue.record("끝점이 없다")
                return
            }
            let pendingKey = LoopbackAdmissionTable.Key(sourcePort: pendingPort.rawValue, listenerPort: server.port)

            // 다른 상대가 잇자마자 끊기를 256번 한다.
            let flood = try await node.listen(port: 9_001)
            var floodConnections = flood.makeAsyncIterator()
            for round in 0..<LoopbackAdmissionTable.admittedLimit {
                let client = try await node.connect(to: "100.64.0.1", port: 9_001)
                let inbound = try #require(await floodConnections.next())
                let forwarding = Support.forward(inbound, with: bridge, toLoopbackPort: server.port)
                let accepted = try #require(await server.nextConnection())
                let outcome = Task { await PeerConnection.start(accepted) }
                try await Support.waitUntil("\(round)번째 토큰이 소비됨") { bridge.admission.snapshot.admitted.count >= min(round + 2, 256) }
                await client.abort()
                _ = await outcome.value
                server.discard(accepted)
                _ = await forwarding.value
            }
            #expect(bridge.admission.snapshot.admitted.contains(pendingKey), "핸드셰이크 중인 연결의 허가가 밀려났다")
            pendingOutcome.cancel()
            _ = await pendingOutcome.value
            await pending.client.abort()
            _ = await pendingForwarding.value
        }
    }

    @Test("토큰이 두 조각으로 나뉘어 와도 허가된다")
    func splitTokenIsAdmitted() async throws {
        let bridge = try Self.idleBridge()
        let server = try await PlainLoopbackServer.start(admittingFor: bridge)
        defer { server.close() }
        let socket = try RawLoopbackSocket(boundTo: 0, reuseAddress: false)
        let token = LoopbackAdmissionTable.makeToken()
        #expect(bridge.admission.expect(token, for: .init(sourcePort: socket.localPort, listenerPort: server.port), origin: Self.origin))
        try socket.connect(to: server.port)
        try socket.send(Array(token[..<10]))
        try await Task.sleep(for: .milliseconds(300))
        try socket.send(Array(token[10...]) + [7])
        socket.finishWriting()
        let peer = try await server.next()
        #expect(bridge.origin(of: peer.connection) == Self.origin)
        #expect(await peer.readToEnd() == .end([7]))
    }

    @Test("토큰 바로 뒤의 FIN이 서버에 끝으로 간다")
    func finRightAfterTokenReachesServer() async throws {
        let bridge = try Self.idleBridge()
        let server = try await PlainLoopbackServer.start(admittingFor: bridge)
        defer { server.close() }
        let socket = try RawLoopbackSocket(boundTo: 0, reuseAddress: false)
        let token = LoopbackAdmissionTable.makeToken()
        #expect(bridge.admission.expect(token, for: .init(sourcePort: socket.localPort, listenerPort: server.port), origin: Self.origin))
        try socket.connect(to: server.port)
        try socket.send(token)
        socket.finishWriting()
        let peer = try await server.next()
        #expect(bridge.origin(of: peer.connection) == Self.origin)
        #expect(await peer.read(within: .seconds(3)) == .end([]))
        peer.connection.cancel()
    }

    @Test("토큰보다 짧게 보내고 FIN한 연결은 기한(5초)을 기다리지 않고 끝난다")
    func shortThenFinFailsPromptly() async throws {
        let bridge = try Self.idleBridge()
        let server = try await PlainLoopbackServer.start(admittingFor: bridge)
        defer { server.close() }
        let socket = try RawLoopbackSocket(boundTo: 0, reuseAddress: false)
        try socket.connect(to: server.port)
        try socket.send([UInt8](repeating: 1, count: 10))
        socket.finishWriting()
        let started = ContinuousClock.now
        guard case .failed = await server.nextOutcome() else {
            Issue.record("준비되었다")
            return
        }
        let elapsed = ContinuousClock.now - started
        #expect(elapsed < .seconds(2), "\(elapsed)")
    }

    @Test("다리와 표의 dump·description에 토큰이 나오지 않는다")
    func tokenNotInReflection() throws {
        let bridge = try Self.idleBridge()
        let token = [UInt8](repeating: 0xA5, count: LoopbackAdmissionTable.tokenLength)
        #expect(bridge.admission.expect(token, for: .init(sourcePort: 50_000, listenerPort: 9), origin: Self.origin))
        var text = ""
        dump(bridge, to: &text)
        dump(bridge.admission, to: &text)
        text += String(describing: bridge) + String(reflecting: bridge.admission)
        #expect(!text.contains("165"), "\(text)")
        #expect(!text.lowercased().contains("token"), "\(text)")
    }

    private static func idleBridge() throws -> LoopbackBridge {
        let configuration = NodeConfiguration(
            stateDirectory: try #require(URL(string: "file:///var/empty/swiftail-test/")), hostname: "rd-mac-1a2b3c4d",
            controlURL: try #require(URL(string: "http://127.0.0.1:9")))
        return LoopbackBridge(node: try TailnetNode(configuration: configuration))
    }
}
