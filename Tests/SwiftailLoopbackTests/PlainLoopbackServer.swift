// A loopback listener for tests. Extends the one in `Tests/SwiftailIOTests/NetworkSocketLoopbackTests.swift` to support the bridge's protocol and TLS
// (test targets cannot share code). Acts as the bridge's loopback peer.

import Foundation
import Network
import Synchronization
@testable import SwiftailLoopback

/// A loopback listener inside the test (`127.0.0.1`, with a system-assigned port). Yields accepted connections in order.
///
/// If given a `bridge`, installs its protocol at the bottom of the stack (below TLS). The first adopter's server does the same.
final class PlainLoopbackServer: Sendable {
    let port: UInt16
    private let listener: NWListener
    private let accepted: AsyncStream<NWConnection>
    private let all = Mutex<[NWConnection]>([])
    private let acceptCount: AcceptCount

    /// The number of connections accepted by the listener, including those not yet dequeued with `next()`.
    var acceptedCount: Int { acceptCount.value.withLock { $0 } }

    private final class AcceptCount: Sendable {
        let value = Mutex(0)
    }

    private init(listener: NWListener, port: UInt16, accepted: AsyncStream<NWConnection>, acceptCount: AcceptCount) {
        self.listener = listener
        self.port = port
        self.accepted = accepted
        self.acceptCount = acceptCount
    }

    static func start(admittingFor bridge: LoopbackBridge? = nil, tls: NWProtocolTLS.Options? = nil) async throws -> PlainLoopbackServer {
        let parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
        if let bridge {
            parameters.defaultProtocolStack.applicationProtocols.append(bridge.makeListenerProtocolOptions())
        }
        let listener = try NWListener(using: parameters)
        let (accepted, sink) = AsyncStream.makeStream(of: NWConnection.self)
        let acceptCount = AcceptCount()
        listener.newConnectionHandler = { connection in
            acceptCount.value.withLock { $0 += 1 }
            sink.yield(connection)
        }
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
        return PlainLoopbackServer(listener: listener, port: port, accepted: accepted, acceptCount: acceptCount)
    }

    /// A port that was opened briefly and then closed. Nothing is listening unless something else takes it immediately.
    static func unusedPort() async throws -> UInt16 {
        let server = try await start()
        server.close()
        try await Task.sleep(for: .milliseconds(50))
        return server.port
    }

    /// Returns the next accepted connection. Waits until it is ready. Throws if it ends without becoming ready.
    func next() async throws -> PeerConnection {
        switch await nextOutcome() {
        case .ready(let peer): return peer
        case .failed(let error): throw PeerConnection.NotReady(description: error)
        }
    }

    /// Reports whether the next accepted connection became ready or ended without becoming ready.
    func nextOutcome() async -> PeerConnection.Outcome {
        guard let connection = await nextConnection() else { return .failed("The listener closed") }
        return await PeerConnection.start(connection)
    }

    /// Returns the next accepted connection without starting it (as the server received it in `newConnectionHandler`).
    func nextConnection() async -> NWConnection? {
        for await connection in accepted {
            all.withLock { $0.append(connection) }
            return connection
        }
        return nil
    }

    /// Closes and releases an accepted connection. For connections that end before readiness, `cancel()` alone leaves the socket open until `NWConnection` is released.
    func discard(_ connection: NWConnection) {
        connection.cancel()
        all.withLock { $0.removeAll { $0 === connection } }
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

    /// The result of starting an accepted connection.
    enum Outcome: Sendable {
        case ready(PeerConnection)
        /// Ended before becoming ready. Includes the reason.
        case failed(String)
    }

    struct NotReady: Error, CustomStringConvertible {
        var description: String
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

    /// Starts the connection and waits until it is ready or has ended. If the waiting Task is canceled, closes the connection.
    static func start(_ connection: NWConnection) async -> Outcome {
        let (states, sink) = AsyncStream.makeStream(of: Outcome?.self)
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                guard case .hostPort(_, let port) = connection.endpoint else {
                    sink.yield(.failed("No endpoint"))
                    return
                }
                sink.yield(.ready(PeerConnection(connection: connection, remotePort: port.rawValue)))
            case .failed(let error): sink.yield(.failed("\(error)"))
            case .cancelled: sink.yield(.failed("Canceled"))
            default: break
            }
        }
        connection.start(queue: DispatchQueue(label: "test.peer"))
        return await withTaskCancellationHandler {
            for await outcome in states { if let outcome { return outcome } }
            return .failed("Canceled")
        } onCancel: {
            connection.cancel()
        }
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
