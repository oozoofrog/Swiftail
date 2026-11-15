import Foundation
import Network
import SwiftailBase
import Synchronization
import Testing
@testable import Swiftail
@testable import SwiftailLoopback

/// 독립 검토(M7-9b)에서 짚은 경우의 시험(계약 `docs/contracts/SwiftailHost.md` 동작 B "독립 검토에서 고친 것").
@Suite("루프백 다리: 검토 재현(M7-9b)", .timeLimit(.minutes(1)))
struct LoopbackAdmissionReviewTests {
    private typealias Support = BridgeTestSupport

    private static let origin = LoopbackBridge.Origin(
        remoteEndpoint: IPEndpoint(address: IPAddress("100.64.0.2")!, port: 41_641), peer: Support.selfIdentity)

    /// TLS 리스너에서 framer는 핸드셰이크 전에 허가를 적는다. 핸드셰이크가 끝나지 않으면 서버는 `.ready`를 보지 못해 계약대로
    /// 묻지 않고, 허가는 밀려날 때까지 남는다(지우면 늦게 온 조회가 같은 열쇠의 새 허가를 얻을 수 있어 지우지 않는다). 남은
    /// 열쇠로는 `expect`가 거절한다. 고치기 전에는 다리가 같은 출발 포트를 다시 뽑은 연결이 `loopbackUnavailable`로 끊겼다.
    @Test("TLS 핸드셰이크 전에 끝난 다리 연결의 허가는 끝났다는 표시와 함께 남고, 그 열쇠는 다시 적히지 않는다")
    func admissionOfUnfinishedHandshakeIsLeftAsEnded() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            let bridge = LoopbackBridge(node: node)
            let server = try await PlainLoopbackServer.start(
                admittingFor: bridge, tls: try SelfSignedIdentity.serverOptions(try SelfSignedIdentity.make()))
            defer { server.close() }
            let pair = try await Support.connectedPair(node)
            let forwarding = Support.forward(pair.server, with: bridge, toLoopbackPort: server.port)
            let accepted = try #require(await server.nextConnection())
            let outcome = Task { await PeerConnection.start(accepted) }
            try await Support.waitUntil("토큰이 소비됨") { bridge.admission.snapshot.admitted.count == 1 }
            // tailnet 쪽이 ClientHello를 보내지 않고 끊는다.
            await pair.client.abort()
            guard case .failed = await outcome.value else {
                Issue.record("핸드셰이크 없이 준비되었다")
                return
            }
            server.discard(accepted)
            #expect(await forwarding.value == nil)
            let key = try #require(bridge.admission.snapshot.admitted.first)
            #expect(!bridge.admission.expect(LoopbackAdmissionTable.makeToken(), for: key, origin: Self.origin))
        }
    }

    @Test("뽑힌 출발 포트의 열쇠에 허가가 남아 있으면 다리가 다른 포트로 다시 걸어 잇는다")
    func bridgeRedialsWhenKeyHasLeftoverAdmission() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            // 다리가 처음 뽑은 열쇠에, 앞선 연결이 남긴 것 같은 허가를 넣는다.
            let leftover = Mutex<LoopbackAdmissionTable.Key?>(nil)
            let bridge = LoopbackBridge(node: node, connectionLimit: 256, willExpect: { key, table in
                guard leftover.withLock({ $0 == nil }) else { return }
                let token = LoopbackAdmissionTable.makeToken()
                guard table.expect(token, for: key, origin: Self.origin), table.admit(token, for: key) else { return }
                leftover.withLock { $0 = key }
            })
            let server = try await PlainLoopbackServer.start(admittingFor: bridge)
            defer { server.close() }
            let pair = try await Support.connectedPair(node)
            let forwarding = Support.forward(pair.server, with: bridge, toLoopbackPort: server.port)
            try await pair.client.write(Array("ping".utf8))

            // 리스너는 연결 둘을 받는다: 다리가 토큰을 보내지 않고 끊은 것과 다시 건 것.
            var ready: PeerConnection?
            for _ in 0..<2 where ready == nil {
                if case .ready(let peer) = await server.nextOutcome() { ready = peer }
            }
            let peer = try #require(ready)
            let leftoverKey = try #require(leftover.withLock { $0 })
            #expect(peer.remotePort != leftoverKey.sourcePort)
            #expect(bridge.origin(of: peer.connection)?.peer == Support.selfIdentity)
            #expect(await peer.read() == .bytes(Array("ping".utf8)))
            #expect(bridge.admission.snapshot.admitted == [leftoverKey], "남아 있던 허가는 그대로다")

            await pair.client.abort()
            #expect(await forwarding.value == nil)
        }
    }

    @Test("허가가 남은 열쇠만 뽑히면 세 번 걸고 그만둔다")
    func bridgeGivesUpAfterThreeRefusedKeys() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            let refused = Mutex<[LoopbackAdmissionTable.Key]>([])
            let bridge = LoopbackBridge(node: node, connectionLimit: 256, willExpect: { key, table in
                let token = LoopbackAdmissionTable.makeToken()
                if table.expect(token, for: key, origin: Self.origin), table.admit(token, for: key) {
                    refused.withLock { $0.append(key) }
                }
            })
            let server = try await PlainLoopbackServer.start(admittingFor: bridge)
            defer { server.close() }
            let pair = try await Support.connectedPair(node)
            let forwarding = Support.forward(pair.server, with: bridge, toLoopbackPort: server.port)
            #expect(await forwarding.value == .loopbackUnavailable("토큰을 표에 적지 못했다"))
            let keys = refused.withLock { $0 }
            #expect(keys.count == 3)
            #expect(Set(keys.map(\.sourcePort)).count == 3, "쥐고 있는 동안에는 같은 출발 포트가 다시 뽑히지 않는다")
            // 다리가 건 셋은 토큰 없이 끊겨 준비되지 않는다.
            for _ in 0..<3 {
                if case .ready = await server.nextOutcome() { Issue.record("토큰 없이 준비되었다") }
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
