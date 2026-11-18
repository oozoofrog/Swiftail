import Foundation
import Network
import Synchronization
import Testing

@testable import SwiftailIO

@Suite("Socket cancellation")
struct NetworkSocketTests {
    /// Repeat the test because this path would occasionally (a few percent of the time) fail to finish, depending on the order of the cancellation handler and connection startup.
    @Test("Starting a connection from an already canceled Task fails immediately")
    func connectInCancelledTask() async throws {
        for _ in 0..<100 {
            let outcome = try await finishes(within: .seconds(2), inCancelledTask: true) {
                do {
                    // A port with no listener. The connection should end with a refusal even without cancellation.
                    let socket = try await NetworkSocket.connect(host: "127.0.0.1", port: 1, tls: .none)
                    socket.close()
                    return "connected"
                } catch {
                    return "failed"
                }
            }
            #expect(outcome == "failed")
            if outcome != "failed" { return }
        }
    }

    @Test("Starting a receive from an already canceled Task fails immediately")
    func receiveInCancelledTask() async throws {
        let listener = try LoopbackListener()
        defer { listener.close() }
        let socket = try await NetworkSocket.connect(host: "127.0.0.1", port: try await listener.port(), tls: .none)
        defer { socket.close() }
        let outcome = try await finishes(within: .seconds(3), inCancelledTask: true) {
            do {
                return try await socket.receive() == nil ? "closed" : "received"
            } catch {
                return "failed"
            }
        }
        #expect(outcome == "failed")
    }

    @Test("Starting a receive on a closed socket fails immediately")
    func receiveAfterClose() async throws {
        let listener = try LoopbackListener()
        defer { listener.close() }
        let socket = try await NetworkSocket.connect(host: "127.0.0.1", port: try await listener.port(), tls: .none)
        socket.close()
        let outcome = try await finishes(within: .seconds(3)) {
            do {
                return try await socket.receive() == nil ? "closed" : "received"
            } catch {
                return "failed"
            }
        }
        #expect(outcome != "received")
    }

    /// Before the fix, sends did not wait and the `NWConnection` buffer grew without bound (sending 256MiB brought RSS to hundreds of MB).
    @Test("write blocks against a peer that does not read, and the amount accepted before it blocks is bounded")
    func writeBlocksWhenPeerDoesNotRead() async throws {
        let listener = try LoopbackListener()
        defer { listener.close() }
        let socket = try await NetworkSocket.connect(host: "127.0.0.1", port: try await listener.port(), tls: .none)
        defer { socket.close() }
        let chunk = [UInt8](repeating: 0xA5, count: 64 << 10)
        let attemptLimit = 256 << 20
        var accepted = 0
        var blocked = false
        while accepted < attemptLimit {
            do {
                try await withTimeout(.milliseconds(500)) { await socket.write(chunk) }
                accepted += chunk.count
            } catch {
                blocked = true
                break
            }
        }
        #expect(blocked)
        // The loopback kernel buffers (sender and receiver) can fill. The amount stays under 32MiB, which is much greater.
        #expect(accepted < 32 << 20)
    }

    @Test("Dropping the socket closes the connection")
    func droppedSocketCloses() async throws {
        let listener = try LoopbackListener()
        defer { listener.close() }
        var socket: NetworkSocket? = try await NetworkSocket.connect(host: "127.0.0.1", port: try await listener.port(), tls: .none)
        #expect(socket != nil)
        let accepted = try await listener.firstConnection()
        socket = nil
        let outcome = try await finishes(within: .seconds(3)) {
            await Self.waitUntilClosed(accepted) ? "closed" : "received"
        }
        #expect(outcome == "closed")
    }

    // MARK: Interface binding

    @Test("Can connect to a loopback server while bound to the loopback interface")
    func connectBoundToLoopbackInterface() async throws {
        let listener = try LoopbackListener()
        defer { listener.close() }
        let loopback = try #require(await currentInterfaces(of: .loopback).first, "No loopback interface")
        let socket = try await NetworkSocket.connect(host: "127.0.0.1", port: try await listener.port(), tls: .none, interface: loopback)
        defer { socket.close() }
        _ = try await listener.firstConnection()
    }

    /// This shows the bound interface is actually used. Without the binding, the socket would connect to the loopback server.
    @Test("Binding to the wrong interface prevents connection to a loopback server")
    func connectBoundToWrongInterfaceFails() async throws {
        let listener = try LoopbackListener()
        defer { listener.close() }
        let other = try #require(await currentInterfaces(of: nil).first { $0.type != .loopback }, "No non-loopback interface")
        let port = try await listener.port()
        let outcome = try await finishes(within: .seconds(10)) {
            do {
                let socket = try await NetworkSocket.connect(host: "127.0.0.1", port: port, tls: .none, interface: other)
                socket.close()
                return "connected"
            } catch {
                return "failed"
            }
        }
        #expect(outcome == "failed")
    }

    @Test("Filters the interface binding for loopback destinations and keeps it for other destinations")
    func bindableInterfaceSkipsLoopbackDestinations() async throws {
        let interface = try #require(await currentInterfaces(of: .loopback).first, "No loopback interface")
        for host in ["127.0.0.1", "127.1.2.3", "::1", "localhost", "LOCALHOST", "localhost6", "ip6-loopback", "ip6-localhost"] {
            #expect(NetworkSocket.bindableInterface(interface, forHost: host) == nil, "\(host)")
        }
        for host in ["192.0.2.1", "128.0.0.1", "126.255.255.255", "127.0.0", "127.0.0.1.5", "2001:db8::1", "controlplane.example.test", ""] {
            #expect(NetworkSocket.bindableInterface(interface, forHost: host) == interface, "\(host)")
        }
        #expect(NetworkSocket.bindableInterface(nil, forHost: "192.0.2.1") == nil)
    }

    /// Reads until the peer closes. Returns true on closure or failure and false if bytes arrive.
    private static func waitUntilClosed(_ connection: NWConnection) async -> Bool {
        await withCheckedContinuation { (continuation: CheckedContinuation<Bool, Never>) in
            connection.receive(minimumIncompleteLength: 1, maximumLength: 1) { data, _, isComplete, error in
                continuation.resume(returning: (data?.isEmpty ?? true) && (isComplete || error != nil))
            }
        }
    }
}

/// Returns the current path's interface. Uses the default path if `type` is nil and the specified interface type otherwise.
private func currentInterfaces(of type: NWInterface.InterfaceType?) async -> [NWInterface] {
    let monitor = type.map { NWPathMonitor(requiredInterfaceType: $0) } ?? NWPathMonitor()
    defer { monitor.cancel() }
    for await path in monitor {
        return path.availableInterfaces
    }
    return []
}

/// Checks whether `operation` completes within `duration`. Throws a test failure if it does not complete.
/// Canceling a continuation that never completes does not resume it, so leave the Task without waiting for it (it goes away when the test process ends).
/// If `inCancelledTask` is set, cancels the Task before starting `operation`.
private func finishes(
    within duration: Duration,
    inCancelledTask: Bool = false,
    _ operation: @escaping @Sendable () async -> String
) async throws -> String {
    let (stream, continuation) = AsyncStream.makeStream(of: String?.self)
    let work = Task {
        if inCancelledTask {
            // Waits until canceled. The Task is still canceled when it wakes.
            try? await Task.sleep(for: .seconds(3_600))
        }
        continuation.yield(await operation())
    }
    if inCancelledTask { work.cancel() }
    let timer = Task {
        try? await Task.sleep(for: duration)
        continuation.yield(nil)
    }
    defer {
        work.cancel()
        timer.cancel()
    }
    for await result in stream {
        guard let result else {
            Issue.record("Did not complete within \(duration)")
            return "didNotComplete"
        }
        return result
    }
    return "didNotComplete"
}

/// A listener that accepts loopback connections and holds them open. Sends nothing.
private final class LoopbackListener: Sendable {
    private let listener: NWListener
    private let accepted = Accepted()

    private final class Accepted: Sendable {
        let connections = Mutex<[NWConnection]>([])
    }

    init() throws {
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: .any)
        listener = try NWListener(using: parameters)
        listener.newConnectionHandler = { [accepted] connection in
            connection.start(queue: .global())
            accepted.connections.withLock { $0.append(connection) }
        }
    }

    func port() async throws -> UInt16 {
        let listener = listener
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<UInt16, any Error>) in
            let once = Mutex<CheckedContinuation<UInt16, any Error>?>(continuation)
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    if let port = listener.port?.rawValue {
                        once.withLock { $0.take() }?.resume(returning: port)
                    }
                case .failed(let error):
                    once.withLock { $0.take() }?.resume(throwing: error)
                default:
                    break
                }
            }
            listener.start(queue: .global())
        }
    }

    /// Returns the first accepted connection. Waits for one if none has arrived yet.
    func firstConnection() async throws -> NWConnection {
        for _ in 0..<300 {
            if let first = accepted.connections.withLock({ $0.first }) { return first }
            try await Task.sleep(for: .milliseconds(10))
        }
        throw CancellationError()
    }

    func close() {
        listener.cancel()
        accepted.connections.withLock { connections in
            for connection in connections { connection.cancel() }
            connections = []
        }
    }
}
