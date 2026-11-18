import Network
import SwiftailBase
import Testing

@testable import SwiftailDERP

/// Tests whether dialing one server's targets concurrently uses the first connection to succeed (Go's `dialNode`). Uses only fake loopback servers (plaintext).
///
/// An unreachable target is a loopback port with no listener (connection refused). A client that dials only an IPv4 literal cannot
/// connect to a server reachable only over IPv6 (①). This does not reproduce how IPv4 literals fail on a real IPv6-only network (CLAT).
@Suite("Concurrent dialing of DERP targets")
struct DERPDialTests {
    private static let ipv4Loopback = IPAddress("127.0.0.1")!
    private static let ipv6Loopback = IPAddress("::1")!
    /// Loopback literals for both address families. This is what the engine builds for a node with literals in its IPv4 and IPv6 fields.
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

    /// A port briefly listened on at `127.0.0.1` and then closed. Returns after closure completes, so connections to the port are now refused.
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
                return try #require(port, "Could not listen: \(current)")
            default:
                break
            }
        }
        return try #require(port)
    }

    /// A non-loopback interface. A loopback target can only be reached if the connection is not bound to this interface.
    private static func nonLoopbackInterface() async throws -> NWInterface {
        let monitor = NWPathMonitor()
        defer { monitor.cancel() }
        var found: NWInterface?
        for await path in monitor {
            found = path.availableInterfaces.first { $0.type != .loopback }
            break
        }
        return try #require(found, "No non-loopback interface found")
    }

    /// Runs `client` while recording events and calls `body`. Cancels `run()` when finished.
    private static func running(_ client: DERPClient, _ body: (EventLog) async throws -> Void) async throws {
        let log = EventLog()
        try await withThrowingTaskGroup(of: Void.self) { group in
            defer { group.cancelAll() }
            group.addTask { await client.run() }
            group.addTask { await log.record(client.events) }
            try await body(log)
        }
    }

    /// Waits for `condition` to become true. Returns false if it is still false after `duration`.
    private static func eventually(within duration: Duration, _ condition: () -> Bool) async throws -> Bool {
        let deadline = ContinuousClock.now + duration
        while ContinuousClock.now < deadline {
            if condition() { return true }
            try await Task.sleep(for: .milliseconds(20))
        }
        return condition()
    }

    /// Before the fix, dialing used only one IPv4 literal, so it never connected on a path where IPv4 was unreachable (IPv6-only cellular).
    /// Also supplies an interface to verify that `::1` is recognized as loopback and the connection is not bound to the interface.
    @Test("Connects over IPv6 when the IPv4 target is unreachable and only IPv6 (::1) is reachable")
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

    @Test("Connects over IPv4 when the IPv6 target is unreachable and only IPv4 is reachable")
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

    @Test("When both targets are reachable, uses one connection and closes the losing one (one connection remains on the server side)")
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
            #expect(settled, "Open connections on the server side: IPv4 \(ipv4.openCount), IPv6 \(ipv6.openCount)")
            try await Task.sleep(for: .milliseconds(300))
            #expect(ipv4.openCount + ipv6.openCount == 1)
            #expect(log.all.filter { $0 == "connected" || $0 == "disconnected" } == ["connected"])
        }
    }

    @Test("If all targets of a server other than the last are unreachable, moves to the next server without emitting a failure event")
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

    @Test("If all targets of the last server are unreachable, emits attemptFailed on each attempt and counts consecutive failures")
    func unreachableLastServerReportsEachAttempt() async throws {
        let client = try Self.client([Self.server(Self.bothFamilies, port: try await Self.closedPort())])
        try await Self.running(client) { log in
            try await log.wait(forEvent: "attemptFailed connectionFailed 2", within: .seconds(10))
            #expect(log.all.prefix(2) == ["attemptFailed connectionFailed 1", "attemptFailed connectionFailed 2"])
        }
    }

    /// The backoff failure count resets to 1 after a connection receives a frame, so using it as-is would report the first failure after disconnect as the second.
    @Test("When the server disappears after connecting, the next failure is counted as the first")
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

    @Test("Canceling while opening connections closes all connections being opened")
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
        // The server does not answer the handshake, so the client waits with its connection open.
        let opened = try await Self.eventually(within: .seconds(5)) { ipv4.acceptedCount + ipv6.acceptedCount >= 1 }
        try #require(opened, "The client did not reach the server")
        running.cancel()
        await running.value
        await recording.value
        let closed = try await Self.eventually(within: .seconds(5)) { ipv4.openCount + ipv6.openCount == 0 }
        #expect(closed, "Open connections on the server side after cancellation: IPv4 \(ipv4.openCount), IPv6 \(ipv6.openCount)")
        #expect(log.all.isEmpty, "Canceled attempts emit no events: \(log.all)")
    }
}
