import Foundation
import Network
import Synchronization
import Testing

@testable import SwiftailIO

/// Tests the socket operations used by the loopback bridge (contract `docs/contracts/SwiftailHost.md` §8, behaviors B4·B5·B6, first adopter review result 7).
///
/// The peer is a plaintext `NWListener` in the test. Check whether the peer sees a "clean EOF" (`isComplete` without an error) or an error.
@Suite("Socket loopback operations", .timeLimit(.minutes(1)))
struct NetworkSocketLoopbackTests {
    @Test("A ready socket's localPort is the source port seen by the listener")
    func localPortMatchesListenerView() async throws {
        let server = try await PlainLoopbackServer.start()
        defer { server.close() }
        for _ in 0..<5 {
            let socket = try await NetworkSocket.connectLoopback(port: server.port)
            defer { socket.close() }
            let accepted = try await server.next()
            let localPort = try #require(socket.localPort)
            #expect(localPort != 0)
            #expect(accepted.remotePort == localPort)
        }
    }

    @Test("After finishWriting, the peer sees a clean EOF and traffic continues in the opposite direction")
    func finishWritingHalfCloses() async throws {
        let server = try await PlainLoopbackServer.start()
        defer { server.close() }
        let socket = try await NetworkSocket.connectLoopback(port: server.port)
        defer { socket.close() }
        let accepted = try await server.next()

        #expect(await socket.writeAccepted(Array("request".utf8)))
        socket.finishWriting()
        #expect(await accepted.readToEnd() == .end(Array("request".utf8)))

        // The peer that received FIN sends a response.
        let response = [UInt8](repeating: 0x5A, count: 300_000)
        try await accepted.send(response, final: true)
        var received: [UInt8] = []
        while let chunk = try await socket.receive() { received += chunk }
        #expect(received == response)
    }

    /// `NWConnection` reports the last bytes together with EOF and ends the next receive with an `ENODATA` error. Before the fix,
    /// a normal close appeared as `readFailed`.
    @Test("receive returns nil on the next call even if EOF (FIN) comes with the last bytes")
    func endArrivingWithLastBytes() async throws {
        let server = try await PlainLoopbackServer.start()
        defer { server.close() }
        let socket = try await NetworkSocket.connectLoopback(port: server.port)
        defer { socket.close() }
        let peer = try await server.next()
        try await peer.send([1, 2, 3], final: true)
        // Receive after both the bytes and FIN have arrived.
        try await Task.sleep(for: .milliseconds(100))
        #expect(try await socket.receive() == [1, 2, 3])
        #expect(try await socket.receive() == nil)
        #expect(try await socket.receive() == nil)
    }

    /// Tests the test helper (`PeerConnection.read`). Before the fix it missed EOF arriving with the last bytes, so the next receive failed with `ENODATA`
    /// and the bridge test was flaky under load.
    @Test("Test server: readToEnd ends with a clean EOF even if EOF (FIN) arrives with the last bytes")
    func peerSeesEndArrivingWithLastBytes() async throws {
        let server = try await PlainLoopbackServer.start()
        defer { server.close() }
        let socket = try await NetworkSocket.connectLoopback(port: server.port)
        defer { socket.close() }
        let peer = try await server.next()
        #expect(await socket.writeAccepted([1, 2, 3]))
        socket.finishWriting()
        // Receive after both the bytes and FIN have arrived.
        try await Task.sleep(for: .milliseconds(100))
        #expect(await peer.readToEnd() == .end([1, 2, 3]))
    }

    @Test("The peer sees abort as an error (RST) and close as a clean EOF")
    func abortResetsAndCloseFinishes() async throws {
        let server = try await PlainLoopbackServer.start()
        defer { server.close() }

        let aborted = try await NetworkSocket.connectLoopback(port: server.port)
        let abortedPeer = try await server.next()
        #expect(await aborted.writeAccepted([1, 2, 3]))
        // Abort after the peer receives the earlier bytes (aborting before receipt can discard them).
        #expect(await abortedPeer.read() == .bytes([1, 2, 3]))
        aborted.abort()
        // forceCancel emits RST, so the peer's read ends with ECONNRESET (verified on macOS in 2026-11).
        guard case .failed(_, let error) = await abortedPeer.readToEnd() else {
            Issue.record("The peer's read did not end with an error after abort")
            return
        }
        #expect(error.contains("Connection reset"), "\(error)")

        let closed = try await NetworkSocket.connectLoopback(port: server.port)
        let closedPeer = try await server.next()
        #expect(await closed.writeAccepted([4, 5, 6]))
        closed.close()
        #expect(await closedPeer.readToEnd() == .end([4, 5, 6]))
    }

    @Test("Canceling the Task that is waiting on receive leaves the loopback socket open")
    func cancelledReceiveKeepsConnection() async throws {
        let server = try await PlainLoopbackServer.start()
        defer { server.close() }
        let socket = try await NetworkSocket.connectLoopback(port: server.port)
        defer { socket.abort() }
        let peer = try await server.next()
        let reader = Task { () -> String in
            do { return try await socket.receive() == nil ? "closed" : "received" } catch { return "failed" }
        }
        try await Task.sleep(for: .milliseconds(50))
        reader.cancel()
        #expect(await reader.value == "failed")
        // The peer does not see EOF, and writes still go through.
        #expect(await socket.writeAccepted([7]))
        #expect(await peer.read(within: .milliseconds(300)) == .bytes([7]))
        #expect(await peer.read(within: .milliseconds(200)) == nil)
    }

    @Test("Port 0 and a port with no listener yield connectFailed")
    func connectFailures() async throws {
        await #expect(throws: SocketError.connectFailed("Invalid port")) {
            _ = try await NetworkSocket.connectLoopback(port: 0)
        }
        let closedPort = try await PlainLoopbackServer.unusedPort()
        do {
            let socket = try await NetworkSocket.connectLoopback(port: closedPort)
            socket.close()
            Issue.record("Connected to a port with no listener")
        } catch {
            guard case .connectFailed = error else {
                Issue.record("Expected connectFailed, got \(error)")
                return
            }
        }
    }
}

// MARK: Test server

/// Provides a plaintext loopback listener within the test (`127.0.0.1`, with a system-assigned port). Yields accepted connections in order.
final class PlainLoopbackServer: Sendable {
    let port: UInt16
    private let listener: NWListener
    private let accepted: AsyncStream<NWConnection>
    private let all = Mutex<[NWConnection]>([])

    private init(listener: NWListener, port: UInt16, accepted: AsyncStream<NWConnection>) {
        self.listener = listener
        self.port = port
        self.accepted = accepted
    }

    static func start() async throws -> PlainLoopbackServer {
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
        let listener = try NWListener(using: parameters)
        let (accepted, sink) = AsyncStream.makeStream(of: NWConnection.self)
        listener.newConnectionHandler = { connection in sink.yield(connection) }
        let port = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<UInt16, any Error>) in
            let once = Mutex<CheckedContinuation<UInt16, any Error>?>(continuation)
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    if let port = listener.port?.rawValue { once.withLock { $0.take() }?.resume(returning: port) }
                case .failed(let error):
                    once.withLock { $0.take() }?.resume(throwing: error)
                default:
                    break
                }
            }
            listener.start(queue: DispatchQueue(label: "test.listener"))
        }
        return PlainLoopbackServer(listener: listener, port: port, accepted: accepted)
    }

    /// A port that was opened briefly and then closed. Nothing is listening unless something else takes it immediately.
    static func unusedPort() async throws -> UInt16 {
        let server = try await start()
        server.close()
        try await Task.sleep(for: .milliseconds(50))
        return server.port
    }

    /// Returns the next accepted connection. Waits until it is ready.
    func next() async throws -> PeerConnection {
        for await connection in accepted {
            all.withLock { $0.append(connection) }
            return try await PeerConnection.start(connection)
        }
        throw CancellationError()
    }

    func close() {
        listener.cancel()
        all.withLock { connections in
            for connection in connections { connection.cancel() }
            connections = []
        }
    }
}

/// Represents one connection accepted by the listener.
struct PeerConnection: Sendable {
    /// The result of one receive.
    enum Received: Equatable, Sendable {
        case bytes([UInt8])
        /// EOF without an error (FIN). Includes bytes received up to that point.
        case end([UInt8])
        /// EOF with an error (such as RST). Includes the number of bytes received up to that point.
        case failed(received: Int, error: String)
    }

    /// The peer's EOF (FIN) arrived with the last bytes. `NWConnection` reports EOF only once and ends the next receive with `ENODATA`,
    /// so `read()` uses this flag to return `.end` after returning those bytes.
    private final class EndSeen: Sendable {
        let value = Mutex(false)
    }

    let connection: NWConnection
    /// The peer's source port (the socket on the bridge side).
    let remotePort: UInt16
    private let endSeen = EndSeen()

    /// Starts the connection and waits until it is ready. If the waiting Task is canceled, closes the connection (the wait ends with an error).
    static func start(_ connection: NWConnection) async throws -> PeerConnection {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                let once = Mutex<CheckedContinuation<Void, any Error>?>(continuation)
                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready: once.withLock { $0.take() }?.resume()
                    case .failed(let error): once.withLock { $0.take() }?.resume(throwing: error)
                    case .cancelled: once.withLock { $0.take() }?.resume(throwing: CancellationError())
                    default: break
                    }
                }
                connection.start(queue: DispatchQueue(label: "test.peer"))
            }
        } onCancel: {
            connection.cancel()
        }
        guard case .hostPort(_, let port) = connection.endpoint else { throw CancellationError() }
        return PeerConnection(connection: connection, remotePort: port.rawValue)
    }

    /// Receives once. Returns `.end([])` at EOF. If the waiting Task is canceled, closes the connection (the receive ends with an error).
    func read() async -> Received {
        if endSeen.value.withLock({ $0 }) { return .end([]) }
        let endSeen = endSeen
        let connection = connection
        return await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<Received, Never>) in
                connection.receive(minimumIncompleteLength: 1, maximumLength: 1 << 20) { data, _, isComplete, error in
                    if let data, !data.isEmpty {
                        if isComplete { endSeen.value.withLock { $0 = true } }
                        continuation.resume(returning: .bytes([UInt8](data)))
                    } else if let error {
                        continuation.resume(returning: .failed(received: 0, error: "\(error)"))
                    } else if isComplete {
                        continuation.resume(returning: .end([]))
                    } else {
                        continuation.resume(returning: .bytes([]))
                    }
                }
            }
        } onCancel: {
            connection.cancel()
        }
    }

    /// Receives once within `duration`. Returns nil if nothing arrives in that time. Leaves the pending receive in place (it takes the next bytes).
    func read(within duration: Duration) async -> Received? {
        let (stream, sink) = AsyncStream.makeStream(of: Received?.self)
        // Leave the Task performing the receive running (canceling it closes the connection).
        Task { sink.yield(await read()) }
        let timer = Task {
            try? await Task.sleep(for: duration)
            sink.yield(nil)
        }
        defer { timer.cancel() }
        for await result in stream { return result }
        return nil
    }

    /// Receives until EOF.
    func readToEnd() async -> Received {
        var received: [UInt8] = []
        while true {
            switch await read() {
            case .bytes(let bytes): received += bytes
            case .end: return .end(received)
            case .failed(_, let error): return .failed(received: received.count, error: error)
            }
        }
    }

    /// Sends data and waits for the network stack to accept it. If `final` is set, closes the write direction (FIN).
    func send(_ bytes: [UInt8], final: Bool) async throws {
        let connection = connection
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                connection.send(
                    content: Data(bytes), contentContext: final ? .finalMessage : .defaultMessage, isComplete: true,
                    completion: .contentProcessed { error in
                        if let error { continuation.resume(throwing: error) } else { continuation.resume() }
                    })
            }
        } onCancel: {
            connection.cancel()
        }
    }
}
