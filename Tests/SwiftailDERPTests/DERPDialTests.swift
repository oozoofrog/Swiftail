import Network
import SwiftailBase
import Testing

@testable import SwiftailDERP

/// 서버 하나의 대상들을 함께 걸어 먼저 붙는 쪽을 쓰는가(Go `dialNode`). 루프백의 가짜 서버(평문)만 쓴다.
///
/// 닿지 않는 대상은 듣는 쪽이 없는 루프백 포트다(연결 거부). IPv4 리터럴만 거는 클라이언트는 IPv6만 닿는 서버에 붙지
/// 못한다(①). 실제 IPv6 전용 망(CLAT)에서 IPv4 리터럴이 어떻게 실패하는지는 여기서 재현하지 못한다.
@Suite("DERP 대상 동시 걸기")
struct DERPDialTests {
    private static let ipv4Loopback = IPAddress("127.0.0.1")!
    private static let ipv6Loopback = IPAddress("::1")!
    /// 두 체계의 루프백 리터럴. 엔진이 IPv4·IPv6 칸에 리터럴이 있는 노드에서 만드는 모양이다.
    private static let bothFamilies: [DERPServer.Target] = [.address(ipv4Loopback), .address(ipv6Loopback)]

    private static func client(_ servers: [DERPServer], interface: NWInterface? = nil) throws -> DERPClient {
        DERPClient(
            servers: servers, privateKey: try DERPFixtures.privateKey(seed: DERPFixtures.clientSeed), isPreferred: true,
            interface: interface, writeTimeout: .seconds(5), plaintextForTests: true
        )
    }

    private static func server(_ targets: [DERPServer.Target], port: UInt16) -> DERPServer {
        DERPServer(hostName: "localhost", targets: targets, port: port, verification: .noneForTests)
    }

    /// `127.0.0.1`에서 잠깐 들었다가 닫은 포트. 닫기가 끝난 뒤 돌려주므로 이제 그 포트로의 연결은 거부된다.
    private static func closedPort() async throws -> UInt16 {
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: .any)
        let listener = try NWListener(using: parameters)
        listener.newConnectionHandler = { $0.cancel() }
        let (states, state) = AsyncStream.makeStream(of: NWListener.State.self)
        listener.stateUpdateHandler = { state.yield($0) }
        listener.start(queue: .global())
        var port: UInt16?
        for await current in states {
            switch current {
            case .ready:
                port = listener.port?.rawValue
                listener.cancel()
            case .failed, .cancelled:
                return try #require(port, "듣지 못했다: \(current)")
            default:
                break
            }
        }
        return try #require(port)
    }

    /// 루프백이 아닌 인터페이스. 루프백 대상은 이것에 묶이지 않아야 붙는다.
    private static func nonLoopbackInterface() async throws -> NWInterface {
        let monitor = NWPathMonitor()
        defer { monitor.cancel() }
        var found: NWInterface?
        for await path in monitor {
            found = path.availableInterfaces.first { $0.type != .loopback }
            break
        }
        return try #require(found, "루프백이 아닌 인터페이스가 없다")
    }

    /// `client`를 돌리며 사건을 적고 `body`를 부른다. 끝나면 `run()`을 취소한다.
    private static func running(_ client: DERPClient, _ body: (EventLog) async throws -> Void) async throws {
        let log = EventLog()
        try await withThrowingTaskGroup(of: Void.self) { group in
            defer { group.cancelAll() }
            group.addTask { await client.run() }
            group.addTask { await log.record(client.events) }
            try await body(log)
        }
    }

    /// `condition`이 참이 될 때까지 기다린다. `duration`이 지나도 거짓이면 false.
    private static func eventually(within duration: Duration, _ condition: () -> Bool) async throws -> Bool {
        let deadline = ContinuousClock.now + duration
        while ContinuousClock.now < deadline {
            if condition() { return true }
            try await Task.sleep(for: .milliseconds(20))
        }
        return condition()
    }

    /// 고치기 전에는 IPv4 리터럴 하나로만 걸어, IPv4가 닿지 않는 경로(IPv6 전용 셀룰러)에서 한 번도 붙지 못했다.
    /// 인터페이스를 주어 `::1`이 루프백으로 판정되어 묶이지 않는 것도 함께 본다.
    @Test("IPv4 대상이 닿지 않고 IPv6(::1)만 닿으면 IPv6로 붙는다")
    func connectsOverIPv6WhenIPv4IsUnreachable() async throws {
        let ipv6 = try FakeDERPServer(.reading(keep: false), host: "::1")
        defer { ipv6.close() }
        let port = try await ipv6.port()
        let client = try Self.client([Self.server(Self.bothFamilies, port: port)], interface: try await Self.nonLoopbackInterface())
        try await Self.running(client) { log in
            try await log.wait(for: ["connected"], within: .seconds(10))
        }
        #expect(ipv6.acceptedCount >= 1)
    }

    @Test("IPv6 대상이 닿지 않고 IPv4만 닿으면 IPv4로 붙는다")
    func connectsOverIPv4WhenIPv6IsUnreachable() async throws {
        let ipv4 = try FakeDERPServer(.reading(keep: false), host: "127.0.0.1")
        defer { ipv4.close() }
        let port = try await ipv4.port()
        let client = try Self.client([Self.server(Self.bothFamilies, port: port)], interface: try await Self.nonLoopbackInterface())
        try await Self.running(client) { log in
            try await log.wait(for: ["connected"], within: .seconds(10))
        }
        #expect(ipv4.acceptedCount >= 1)
    }

    @Test("둘 다 닿으면 연결 하나만 쓰고 진 쪽은 닫는다(서버 쪽에 남은 연결이 하나다)")
    func losingConnectionIsClosed() async throws {
        let ipv4 = try FakeDERPServer(.reading(keep: false), host: "127.0.0.1")
        defer { ipv4.close() }
        let port = try await ipv4.port()
        let ipv6 = try FakeDERPServer(.reading(keep: false), host: "::1", port: try #require(NWEndpoint.Port(rawValue: port)))
        defer { ipv6.close() }
        #expect(try await ipv6.port() == port)
        let client = try Self.client([Self.server(Self.bothFamilies, port: port)])
        try await Self.running(client) { log in
            try await log.wait(for: ["connected"], within: .seconds(10))
            let settled = try await Self.eventually(within: .seconds(5)) { ipv4.openCount + ipv6.openCount == 1 }
            #expect(settled, "서버 쪽 열린 연결: IPv4 \(ipv4.openCount), IPv6 \(ipv6.openCount)")
            try await Task.sleep(for: .milliseconds(300))
            #expect(ipv4.openCount + ipv6.openCount == 1)
            #expect(log.all.filter { $0 == "connected" || $0 == "disconnected" } == ["connected"])
        }
    }

    @Test("마지막이 아닌 서버의 대상이 모두 닿지 않으면 다음 서버로 넘어가고, 실패 사건은 내지 않는다")
    func unreachableServerFallsThrough() async throws {
        let next = try FakeDERPServer(.reading(keep: false), host: "127.0.0.1")
        defer { next.close() }
        let unreachable = Self.server(Self.bothFamilies, port: try await Self.closedPort())
        let reachable = Self.server([.address(Self.ipv4Loopback)], port: try await next.port())
        let client = try Self.client([unreachable, reachable])
        try await Self.running(client) { log in
            try await log.wait(for: ["connected"], within: .seconds(10))
            #expect(!log.all.contains { $0.hasPrefix("attemptFailed") })
        }
        #expect(next.acceptedCount >= 1)
    }

    @Test("마지막 서버의 대상이 모두 닿지 않으면 시도마다 attemptFailed를 내고 연달아 실패한 수를 센다")
    func unreachableLastServerReportsEachAttempt() async throws {
        let client = try Self.client([Self.server(Self.bothFamilies, port: try await Self.closedPort())])
        try await Self.running(client) { log in
            try await log.wait(forEvent: "attemptFailed connectionFailed 2", within: .seconds(10))
            #expect(log.all.prefix(2) == ["attemptFailed connectionFailed 1", "attemptFailed connectionFailed 2"])
        }
    }

    /// 물러남의 실패 수는 프레임을 받은 연결 뒤 1로 돌아가므로, 그것을 그대로 쓰면 끊긴 뒤의 첫 실패가 2번째로 나온다.
    @Test("연결했다가 서버가 사라지면 그 뒤의 첫 실패는 1번째다")
    func attemptCountRestartsAfterConnection() async throws {
        let server = try FakeDERPServer(.reading(keep: false), host: "127.0.0.1")
        let client = try Self.client([Self.server([.address(Self.ipv4Loopback)], port: try await server.port())])
        try await Self.running(client) { log in
            try await log.wait(for: ["connected"], within: .seconds(10))
            server.close()
            try await log.wait(forEvent: "attemptFailed connectionFailed 2", within: .seconds(10))
            #expect(log.all.filter { $0.hasPrefix("attemptFailed") }.prefix(2)
                == ["attemptFailed connectionFailed 1", "attemptFailed connectionFailed 2"])
        }
    }

    @Test("연결을 여는 중에 취소하면 열던 연결이 모두 닫힌다")
    func cancellingWhileOpeningClosesConnections() async throws {
        let ipv4 = try FakeDERPServer(.unresponsive, host: "127.0.0.1")
        defer { ipv4.close() }
        let port = try await ipv4.port()
        let ipv6 = try FakeDERPServer(.unresponsive, host: "::1", port: try #require(NWEndpoint.Port(rawValue: port)))
        defer { ipv6.close() }
        #expect(try await ipv6.port() == port)
        let client = try Self.client([Self.server(Self.bothFamilies, port: port)])
        let log = EventLog()
        let running = Task { await client.run() }
        let recording = Task { await log.record(client.events) }
        // 서버가 핸드셰이크에 답하지 않으므로 클라이언트는 연결을 연 채 기다린다.
        let opened = try await Self.eventually(within: .seconds(5)) { ipv4.acceptedCount + ipv6.acceptedCount >= 1 }
        try #require(opened, "클라이언트가 서버에 닿지 않았다")
        running.cancel()
        await running.value
        await recording.value
        let closed = try await Self.eventually(within: .seconds(5)) { ipv4.openCount + ipv6.openCount == 0 }
        #expect(closed, "취소 뒤 서버 쪽 열린 연결: IPv4 \(ipv4.openCount), IPv6 \(ipv6.openCount)")
        #expect(log.all.isEmpty, "취소한 시도는 사건을 내지 않는다: \(log.all)")
    }
}
