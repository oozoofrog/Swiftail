import Dispatch
import Foundation
import Network
import SwiftailBase
import Testing
@testable import Swiftail
@testable import SwiftailLoopback

/// 다리가 연 루프백 연결만 신원을 얻는다(계약 `docs/contracts/SwiftailHost.md` 동작 B6, M7-9b).
///
/// 같은 기기의 다른 프로세스가 할 수 있는 수를 POSIX 소켓(`RawLoopbackSocket`)으로 둔다: 원하는 출발 포트에 묶기
/// (`SO_REUSEADDR`), 루프백 리스너에 걸기, 아무 바이트나 보내기. 서버는 계약대로 `.ready`에서 묻는다.
@Suite("루프백 다리: 다리가 연 연결만 신원을 얻는다", .timeLimit(.minutes(1)))
struct LoopbackAdmissionTests {
    private typealias Support = BridgeTestSupport

    /// TLS 레코드처럼 시작하는 바이트(토큰 자리에 다른 것이 오는 경우).
    private static let stray = [UInt8](repeating: 0x16, count: 64)

    // MARK: 검토에서 재현된 것

    /// 검토 1: 표의 열쇠가 출발 포트뿐이면 둘째 리스너가 첫째 리스너로 잇는 연결의 신원을 얻었다.
    @Test("다리가 첫 리스너에 잇는 동안 같은 출발 포트로 둘째 리스너에 붙은 연결은 준비되지 않는다")
    func sameSourcePortOnSecondListener() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            let bridge = LoopbackBridge(node: node)
            let first = try await PlainLoopbackServer.start(admittingFor: bridge)
            defer { first.close() }
            let second = try await PlainLoopbackServer.start(admittingFor: bridge)
            defer { second.close() }
            let link = try await Support.bridge(node, bridge, to: first)

            let stranger = try RawLoopbackSocket(boundTo: link.peer.remotePort, reuseAddress: true)
            try stranger.connect(to: second.port)
            try stranger.send(Self.stray)
            await Self.expectRejected(second.nextOutcome(), bridge)

            #expect(bridge.origin(of: link.peer.connection)?.peer == Support.selfIdentity)
            await link.client.abort()
            _ = await link.finished()
        }
    }

    /// 검토 2: 서버가 응답하고 닫은 뒤 tailnet 쪽이 더 보내면 서버 커널이 RST를 내고, 다리가 알아채기 전에 출발 포트가 풀린다.
    /// 서버가 묻지 않은 허가가 그 4-튜플로 남아 있어도(그 연결이 실제로 나른 바이트의 상대다) 새 연결은 준비되지 않는다.
    @Test("서버가 닫은 뒤의 RST로 풀린 출발 포트로 같은 리스너에 붙은 연결은 남은 허가가 있어도 신원을 얻지 못한다")
    func portFreedByResetOnSameListener() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            let bridge = LoopbackBridge(node: node)
            let server = try await PlainLoopbackServer.start(admittingFor: bridge)
            defer { server.close() }
            let link = try await Support.bridge(node, bridge, to: server)
            let key = LoopbackAdmissionTable.Key(sourcePort: link.peer.remotePort, listenerPort: server.port)

            try await link.client.write(Array("request".utf8))
            #expect(await link.peer.read() == .bytes(Array("request".utf8)))
            try await link.peer.send(Array("response".utf8), final: true)
            link.peer.connection.cancel()
            #expect(try await Support.readToEnd(link.client) == Array("response".utf8))

            // 닫힌 서버 소켓으로 더 보내면 RST가 오고 다리의 루프백 소켓이 CLOSED가 된다. 그때 같은 4-튜플로 걸 수 있다.
            var stranger: RawLoopbackSocket?
            for _ in 0..<500 where stranger == nil {
                _ = try? await link.client.write([0xEE])
                stranger = Self.connectedStranger(from: key.sourcePort, to: server.port)
                if stranger == nil { try await Task.sleep(for: .milliseconds(10)) }
            }
            let socket = try #require(stranger, "출발 포트가 풀리지 않았다")
            #expect(bridge.admission.snapshot.admitted.contains(key))

            let accepted = try #require(await server.nextConnection())
            // 계약을 어기고 준비되기 전에 묻는 서버에게도 답하지 않는다.
            #expect(bridge.origin(of: accepted) == nil)
            try socket.send(Self.stray)
            await Self.expectRejected(PeerConnection.start(accepted), bridge)
            #expect(bridge.origin(of: accepted) == nil)
            // 다리는 루프백에서 더 받지 않으므로 다음에 쓸 때 RST를 안다. tailnet 쪽이 쓰지 않으면 그때까지 남는다.
            await link.client.abort()
            #expect(await link.finished() == nil)
        }
    }

    /// 검토 2의 둘째 경우: 다리가 받는 중에 서버가 RST로 끊으면, 포트가 풀린 때부터 다리가 알아채기까지 틈이 있었다.
    /// 다른 스레드가 그 포트로 걸기를 되풀이하다 풀리는 즉시 붙는다.
    @Test("받는 중에 서버가 RST로 끊은 직후 같은 출발 포트로 곧바로 붙은 연결은 준비되지 않는다", arguments: 0..<10)
    func probeRightAfterServerReset(round: Int) async throws {
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            let bridge = LoopbackBridge(node: node)
            let server = try await PlainLoopbackServer.start(admittingFor: bridge)
            defer { server.close() }
            let link = try await Support.bridge(node, bridge, to: server)
            #expect(bridge.origin(of: link.peer.connection) != nil)
            let sourcePort = link.peer.remotePort
            let serverPort = server.port
            let probe = Task {
                await withCheckedContinuation { (continuation: CheckedContinuation<RawLoopbackSocket?, Never>) in
                    DispatchQueue.global().async {
                        let deadline = ContinuousClock.now + .seconds(5)
                        while ContinuousClock.now < deadline {
                            if let socket = Self.connectedStranger(from: sourcePort, to: serverPort) {
                                try? socket.send(Self.stray)
                                continuation.resume(returning: socket)
                                return
                            }
                        }
                        continuation.resume(returning: nil)
                    }
                }
            }
            try await Task.sleep(for: .milliseconds(20))
            link.peer.connection.forceCancel()
            let stranger = await probe.value
            #expect(stranger != nil, "\(round)번째: 출발 포트가 풀리지 않았다")
            if stranger != nil { await Self.expectRejected(server.nextOutcome(), bridge) }
            #expect(await Support.error { try await Support.readToEnd(link.client) } == .reset)
            #expect(await link.finished() == nil)
        }
    }

    // MARK: 토큰

    @Test("토큰이 없거나 틀리거나, 토큰을 다 보내기 전에 끝낸 연결은 준비되지 않는다")
    func invalidTokensAreRejected() async throws {
        let bridge = try Self.idleBridge()
        let server = try await PlainLoopbackServer.start(admittingFor: bridge)
        defer { server.close() }
        let cases: [(String, [UInt8], Bool)] = [
            ("토큰 없이 HTTP", Array("GET / HTTP/1.1\r\nHost: rd-mac-1a2b3c4d\r\n\r\n".utf8), false),
            ("적지 않은 토큰", LoopbackAdmissionTable.makeToken() + [1], false),
            ("10바이트 뒤 FIN", [UInt8](repeating: 1, count: 10), true),
        ]
        for (what, bytes, finish) in cases {
            let stranger = try RawLoopbackSocket(boundTo: 0, reuseAddress: false)
            try stranger.connect(to: server.port)
            try stranger.send(bytes)
            if finish { stranger.finishWriting() }
            await Self.expectRejected(server.nextOutcome(), bridge, what)
        }
    }

    @Test("토큰을 다 보내지 않고 멈춘 연결은 5초 뒤 준비되지 않고 끝난다")
    func partialTokenTimesOut() async throws {
        let bridge = try Self.idleBridge()
        let server = try await PlainLoopbackServer.start(admittingFor: bridge)
        defer { server.close() }
        let stranger = try RawLoopbackSocket(boundTo: 0, reuseAddress: false)
        try stranger.connect(to: server.port)
        try stranger.send([UInt8](repeating: 1, count: 10))
        let started = ContinuousClock.now
        await Self.expectRejected(server.nextOutcome(), bridge)
        let elapsed = ContinuousClock.now - started
        #expect(elapsed >= .seconds(4) && elapsed < .seconds(10), "\(elapsed)")
    }

    @Test("토큰은 적힌 출발 포트와 리스너 포트의 연결에서 한 번만 통한다")
    func tokenIsBoundAndSingleUse() async throws {
        let bridge = try Self.idleBridge()
        let server = try await PlainLoopbackServer.start(admittingFor: bridge)
        defer { server.close() }
        let other = try await PlainLoopbackServer.start(admittingFor: bridge)
        defer { other.close() }
        let origin = LoopbackBridge.Origin(
            remoteEndpoint: IPEndpoint(address: try #require(IPAddress("100.64.0.2")), port: 41_641), peer: Support.selfIdentity)

        // 맞는 연결.
        let rightful = try RawLoopbackSocket(boundTo: 0, reuseAddress: false)
        let token = LoopbackAdmissionTable.makeToken()
        #expect(bridge.admission.expect(token, for: .init(sourcePort: rightful.localPort, listenerPort: server.port), origin: origin))
        try rightful.connect(to: server.port)
        // 토큰, 바이트, 끝(FIN)이 한꺼번에 온다. framer가 받아 둔 바이트와 끝이 위로 간다.
        try rightful.send(token + [7])
        rightful.finishWriting()
        let peer = try await server.next()
        #expect(bridge.origin(of: peer.connection) == origin)
        #expect(await peer.readToEnd() == .end([7]))

        // 같은 토큰을 다시 쓴다.
        let replay = try RawLoopbackSocket(boundTo: 0, reuseAddress: false)
        try replay.connect(to: server.port)
        try replay.send(token)
        await Self.expectRejected(server.nextOutcome(), bridge, "다시 쓴 토큰")

        // 다른 리스너에서 쓴다. 그 토큰은 소비되어 제 리스너에서도 더 통하지 않는다.
        let misdirected = try RawLoopbackSocket(boundTo: 0, reuseAddress: false)
        let stolen = LoopbackAdmissionTable.makeToken()
        let stolenKey = LoopbackAdmissionTable.Key(sourcePort: misdirected.localPort, listenerPort: server.port)
        #expect(bridge.admission.expect(stolen, for: stolenKey, origin: origin))
        try misdirected.connect(to: other.port)
        try misdirected.send(stolen)
        await Self.expectRejected(other.nextOutcome(), bridge, "다른 리스너의 토큰")
        let late = try RawLoopbackSocket(boundTo: stolenKey.sourcePort, reuseAddress: true)
        try late.connect(to: server.port)
        try late.send(stolen)
        await Self.expectRejected(server.nextOutcome(), bridge, "소비된 토큰")

        // 다른 출발 포트에서 쓴다.
        let elsewhere = try RawLoopbackSocket(boundTo: 0, reuseAddress: false)
        let reserved = LoopbackAdmissionTable.makeToken()
        #expect(bridge.admission.expect(reserved, for: .init(sourcePort: 1, listenerPort: server.port), origin: origin))
        try elsewhere.connect(to: server.port)
        try elsewhere.send(reserved)
        await Self.expectRejected(server.nextOutcome(), bridge, "다른 출발 포트의 토큰")
        #expect(bridge.admission.snapshot.expected.isEmpty)
    }

    @Test("기다리는 토큰과 가져가지 않은 허가는 256개까지다")
    func tableLimits() throws {
        let table = LoopbackAdmissionTable()
        let origin = LoopbackBridge.Origin(
            remoteEndpoint: IPEndpoint(address: try #require(IPAddress("100.64.0.2")), port: 41_641), peer: Support.selfIdentity)
        var tokens: [[UInt8]] = []
        for port in 1...UInt16(256) {
            let token = LoopbackAdmissionTable.makeToken()
            tokens.append(token)
            #expect(table.expect(token, for: .init(sourcePort: port, listenerPort: 9), origin: origin))
        }
        #expect(!table.expect(LoopbackAdmissionTable.makeToken(), for: .init(sourcePort: 999, listenerPort: 9), origin: origin))
        for (index, token) in tokens.enumerated() {
            #expect(table.admit(token, for: .init(sourcePort: UInt16(index + 1), listenerPort: 9)))
        }
        // 257번째 허가는 가장 오래된 것을 밀어낸다.
        let extra = LoopbackAdmissionTable.makeToken()
        #expect(table.expect(extra, for: .init(sourcePort: 999, listenerPort: 9), origin: origin))
        #expect(table.admit(extra, for: .init(sourcePort: 999, listenerPort: 9)))
        #expect(table.take(.init(sourcePort: 1, listenerPort: 9)) == nil)
        #expect(table.take(.init(sourcePort: 2, listenerPort: 9)) == origin)
        #expect(table.take(.init(sourcePort: 999, listenerPort: 9)) == origin)
        #expect(table.snapshot.admitted.count == 254)
    }

    // MARK: TLS 리스너

    /// TLS 클라이언트 → 시험의 입구 리스너 → tailnet 연결 → 다리 → 프로토콜을 넣은 TLS 리스너. 핸드셰이크가 다리를 지난다.
    @Test("TLS 리스너에서도 다리가 이은 연결은 핸드셰이크 뒤 신원을 얻고 바이트가 끝에서 끝으로 간다")
    func tlsEndToEnd() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            let bridge = LoopbackBridge(node: node)
            let server = try await PlainLoopbackServer.start(
                admittingFor: bridge, tls: try SelfSignedIdentity.serverOptions(try SelfSignedIdentity.make()))
            defer { server.close() }
            let entrance = try await PlainLoopbackServer.start()
            defer { entrance.close() }
            let pair = try await Support.connectedPair(node)
            let forwarding = Support.forward(pair.server, with: bridge, toLoopbackPort: server.port)

            let client = NWConnection(
                host: .ipv4(.loopback), port: try #require(NWEndpoint.Port(rawValue: entrance.port)),
                using: NWParameters(tls: SelfSignedIdentity.clientOptions(), tcp: NWProtocolTCP.Options()))
            defer { client.cancel() }
            let clientReady = Task { await PeerConnection.start(client) }
            let inbound = try await entrance.next()
            let upstream = Task {
                while case .bytes(let bytes) = await inbound.read() { try await pair.client.write(bytes) }
                try await pair.client.finishWriting()
            }
            let downstream = Task {
                while let bytes = try await pair.client.read() { try await inbound.send(bytes, final: false) }
            }
            defer {
                upstream.cancel()
                downstream.cancel()
            }

            let tlsPeer = try await server.next()
            #expect(bridge.origin(of: tlsPeer.connection)?.peer == Support.selfIdentity)
            guard case .ready(let tlsClient) = await clientReady.value else {
                Issue.record("TLS 클라이언트가 준비되지 않았다")
                return
            }
            try await tlsClient.send(Array("ping".utf8), final: false)
            #expect(await tlsPeer.read() == .bytes(Array("ping".utf8)))
            try await tlsPeer.send(Array("pong".utf8), final: false)
            #expect(await tlsClient.read() == .bytes(Array("pong".utf8)))

            await pair.client.abort()
            #expect(await forwarding.value == nil)
        }
    }

    @Test("TLS 리스너: 토큰 없이 건 TLS 클라이언트와 다리의 출발 포트를 다시 쓴 연결은 준비되지 않는다")
    func tlsRejections() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            let bridge = LoopbackBridge(node: node)
            let server = try await PlainLoopbackServer.start(
                admittingFor: bridge, tls: try SelfSignedIdentity.serverOptions(try SelfSignedIdentity.make()))
            defer { server.close() }
            let plain = try await PlainLoopbackServer.start(admittingFor: bridge)
            defer { plain.close() }

            let direct = NWConnection(
                host: .ipv4(.loopback), port: try #require(NWEndpoint.Port(rawValue: server.port)),
                using: NWParameters(tls: SelfSignedIdentity.clientOptions(), tcp: NWProtocolTCP.Options()))
            defer { direct.cancel() }
            direct.start(queue: DispatchQueue(label: "test.direct"))
            await Self.expectRejected(server.nextOutcome(), bridge, "토큰 없는 TLS 클라이언트")

            let link = try await Support.bridge(node, bridge, to: plain)
            let stranger = try RawLoopbackSocket(boundTo: link.peer.remotePort, reuseAddress: true)
            try stranger.connect(to: server.port)
            try stranger.send(Self.stray)
            await Self.expectRejected(server.nextOutcome(), bridge, "다리의 출발 포트")
            await link.client.abort()
            _ = await link.finished()
        }
    }

    // MARK: 도우미

    /// 노드를 돌리지 않는 다리. 표와 framer만 시험한다.
    private static func idleBridge() throws -> LoopbackBridge {
        let configuration = NodeConfiguration(
            stateDirectory: try #require(URL(string: "file:///var/empty/swiftail-test/")), hostname: "rd-mac-1a2b3c4d",
            controlURL: try #require(URL(string: "http://127.0.0.1:9")))
        return LoopbackBridge(node: try TailnetNode(configuration: configuration))
    }

    /// `127.0.0.1:<sourcePort>`에 묶어(`SO_REUSEADDR`) `127.0.0.1:<port>`에 건 소켓. 그 4-튜플이 쓰이는 중이면 nil이다.
    private static func connectedStranger(from sourcePort: UInt16, to port: UInt16) -> RawLoopbackSocket? {
        guard let socket = try? RawLoopbackSocket(boundTo: sourcePort, reuseAddress: true) else { return nil }
        do {
            try socket.connect(to: port)
            return socket
        } catch {
            return nil
        }
    }

    /// 연결이 준비되지 않고 끝났는지 본다. 준비되었다면 신원도 얻지 못해야 한다(둘 다 실패로 적는다).
    private static func expectRejected(
        _ outcome: PeerConnection.Outcome, _ bridge: LoopbackBridge, _ what: String = "",
        sourceLocation: SourceLocation = #_sourceLocation
    ) async {
        guard case .ready(let peer) = outcome else { return }
        let origin = bridge.origin(of: peer.connection)
        Issue.record("\(what): 준비되었다(신원 \(origin == nil ? "없음" : "있음"))", sourceLocation: sourceLocation)
        peer.connection.cancel()
    }
}
