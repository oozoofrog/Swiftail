import Foundation
import Network
import Synchronization

/// Wraps one TCP (or TLS) connection as an async byte stream.
///
/// Used for control server (`SwiftailControl`) and DERP server (`SwiftailDERP`) connections. Failures are reported as
/// `SocketError`, which callers convert to their own error types.
///
/// The Network framework's `NWConnection` reports results through callbacks. This file is the only place that bridges
/// those callbacks to continuations. It guarantees the following.
///
/// - Resumes each continuation exactly once. Status callbacks can arrive more than once, so `ResumeOnce` delivers only the first result.
/// - On cancellation of a waiting Task, immediately resumes the continuation with an error and closes the connection,
///   except for loopback bridge sockets (`connectLoopback(port:)`). If called from an already canceled Task, the
///   cancellation handler runs before the continuation is installed. Store the result in `ResumeOnce` and deliver it as
///   soon as the continuation is installed. A canceled `NWConnection` callback may never arrive.
/// - Offers two ways to send. `send` returns without waiting. `write` waits until the network stack accepts the bytes.
///   `NWConnection` sends both in call order, preserving Noise record order (nonce order) and frame order. A send
///   failure puts the connection in the failed state, which the next `receive()` reports.
/// - Releasing the socket closes the connection (`deinit`). When a timeout races with connection completion and no
///   caller remains to receive the socket, it does not leave an open connection at the peer.
/// - With an interface specified, traffic uses only that interface (`connect(host:port:tls:interface:)`). This keeps
///   control and DERP connections in a packet tunnel from looping back into that tunnel.
///
/// Byte boundaries carry no meaning. Returns TCP fragments as received and lets higher layers assemble records and frames.
package final class NetworkSocket: Sendable {
    private static let maximumReadSize = 64 << 10

    let connection: NWConnection
    /// Whether to close the connection when a Task waiting on `receive` or `write` is canceled. Otherwise the socket's
    /// owner decides when to close.
    private let closesOnCancel: Bool
    /// The peer's end of stream (FIN) arrived with its final bytes. After returning those bytes, `receive()` returns
    /// nil. `NWConnection` reports the end only once and fails later reads with `ENODATA`.
    private let receivedEnd = Mutex(false)

    private init(connection: NWConnection, closesOnCancel: Bool) {
        self.connection = connection
        self.closesOnCancel = closesOnCancel
    }

    deinit {
        connection.cancel()
    }

    /// Waits until the connection is ready.
    ///
    /// - Parameter interface: If specified, the connection uses only that interface (`NWParameters.requiredInterface`).
    ///   If the destination is unreachable through that interface, the connection fails without switching routes. If
    ///   nil, the system chooses. A loopback destination is unreachable through the interface, so the caller filters it
    ///   with `bindableInterface(_:forHost:)`.
    package static func connect(
        host: String, port: UInt16, tls: TLS, interface: NWInterface? = nil
    ) async throws(SocketError) -> NetworkSocket {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            throw .connectFailed("Invalid port")
        }
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        tcp.connectionTimeout = 10
        // Leave ALPN empty. Negotiating HTTP/2 would prevent the HTTP/1.1 upgrade (control-transport notes §4.4).
        let parameters = NWParameters(tls: tls.options, tcp: tcp)
        parameters.requiredInterface = interface
        let connection = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: parameters)
        return try await open(connection, closesOnCancel: true)
    }

    /// Starts `connection` and waits until it is ready. Closes the connection and throws on failure or if the waiting Task is canceled.
    static func open(_ connection: NWConnection, closesOnCancel: Bool) async throws(SocketError) -> NetworkSocket {
        let socket = NetworkSocket(connection: connection, closesOnCancel: closesOnCancel)
        let once = ResumeOnce<Void>()
        do {
            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                    guard once.install(continuation) else { return }
                    connection.stateUpdateHandler = { state in
                        switch state {
                        case .ready:
                            once.resume(with: .success(()))
                        case .waiting(let error), .failed(let error):
                            // On failures such as connection refusal, NWConnection stays in waiting and retries. Treat
                            // waiting as failure here because the upper layer retries with backoff.
                            once.resume(with: .failure(SocketError.connectFailed("Could not connect: \(error)")))
                        case .cancelled:
                            once.resume(with: .failure(SocketError.connectFailed("Connection canceled")))
                        default:
                            break
                        }
                    }
                    connection.start(queue: DispatchQueue(label: "Swiftail.NetworkSocket"))
                }
            } onCancel: {
                once.resume(with: .failure(SocketError.connectFailed("Connection canceled")))
                connection.cancel()
            }
        } catch {
            connection.cancel()
            throw error as? SocketError ?? .connectFailed("Could not connect")
        }
        return socket
    }

    /// Sends bytes without waiting (see the type documentation).
    ///
    /// If the peer does not read or the uplink is slow, the `NWConnection` buffer grows without bound. Use `write` to cap pending bytes.
    package func send(_ bytes: [UInt8]) {
        guard !bytes.isEmpty else { return }
        connection.send(content: Data(bytes), completion: .contentProcessed { _ in })
    }

    /// Sends bytes and waits for the network stack to accept them.
    ///
    /// The call does not return while the peer is not reading or the uplink is slow. The caller therefore holds only
    /// one unsent chunk, the current write, and uses a deadline to detect a stall (`DERPClient` has one write watchdog
    /// per connection). This is simpler for the caller than reporting a byte count because it need not separately wait
    /// for the backlog to shrink.
    ///
    /// Does not throw on failure. As with `send`, failure puts the connection in the failed state and the next
    /// `receive()` reports it. If the waiting Task is canceled, closes the connection and returns. Loopback bridge
    /// sockets stay open.
    package func write(_ bytes: [UInt8]) async {
        await writeAccepted(bytes)
    }

    /// Writes as `write` does and returns the result.
    ///
    /// When the connection's read side has already ended, the next `receive()` does not report a failure. A caller with
    /// only writes left (the loopback bridge) uses this result to detect that the peer disconnected.
    ///
    /// - Returns: True if the network stack accepted the bytes, or false if sending failed or the Task was canceled.
    @discardableResult
    package func writeAccepted(_ bytes: [UInt8]) async -> Bool {
        guard !bytes.isEmpty else { return true }
        let connection = connection
        let closesOnCancel = closesOnCancel
        let once = ResumeOnce<Bool>()
        return await withTaskCancellationHandler {
            (try? await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Bool, any Error>) in
                guard once.install(continuation) else { return }
                connection.send(content: Data(bytes), completion: .contentProcessed { error in
                    once.resume(with: .success(error == nil))
                })
            }) ?? false
        } onCancel: {
            once.resume(with: .success(false))
            if closesOnCancel { connection.cancel() }
        }
    }

    /// Receives incoming bytes. Returns nil if the peer closed the connection.
    package func receive() async throws(SocketError) -> [UInt8]? {
        guard !receivedEnd.withLock({ $0 }) else { return nil }
        let connection = connection
        let closesOnCancel = closesOnCancel
        let once = ResumeOnce<[UInt8]?>()
        do {
            return try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<[UInt8]?, any Error>) in
                    guard once.install(continuation) else { return }
                    connection.receive(minimumIncompleteLength: 1, maximumLength: Self.maximumReadSize) { data, _, isComplete, error in
                        if let data, !data.isEmpty {
                            if isComplete { self.receivedEnd.withLock { $0 = true } }
                            once.resume(with: .success([UInt8](data)))
                        } else if let error {
                            once.resume(with: .failure(SocketError.readFailed("Read failed: \(error)")))
                        } else if isComplete {
                            once.resume(with: .success(nil))
                        } else {
                            once.resume(with: .success([]))
                        }
                    }
                }
            } onCancel: {
                once.resume(with: .failure(SocketError.readFailed("Read canceled")))
                if closesOnCancel { connection.cancel() }
            }
        } catch {
            throw error as? SocketError ?? .readFailed("Read failed")
        }
    }

    /// Closes the connection. Any pending `receive()` ends with an error. May be called multiple times.
    package func close() {
        connection.cancel()
    }
}

/// A container that resumes a continuation exactly once. Delivers only the first result even if several callbacks arrive.
///
/// A result can arrive before the continuation, as when the cancellation handler runs before the body of an already
/// canceled Task. In that case, the container holds the result until `install` delivers it.
private final class ResumeOnce<Value: Sendable>: Sendable {
    private enum State {
        case empty
        case waiting(CheckedContinuation<Value, any Error>)
        case early(Result<Value, any Error>)
        case resumed
    }

    private let state = Mutex(State.empty)

    /// Installs the continuation. Returns false if a result has already arrived and the continuation was resumed
    /// immediately. In that case, skip registering the callback.
    func install(_ continuation: CheckedContinuation<Value, any Error>) -> Bool {
        let early: Result<Value, any Error>? = state.withLock { state in
            switch state {
            case .early(let result):
                state = .resumed
                return result
            case .empty:
                state = .waiting(continuation)
                return nil
            case .waiting, .resumed:
                return nil
            }
        }
        guard let early else { return true }
        continuation.resume(with: early)
        return false
    }

    func resume(with result: Result<Value, any Error>) {
        let waiting: CheckedContinuation<Value, any Error>? = state.withLock { state in
            switch state {
            case .waiting(let continuation):
                state = .resumed
                return continuation
            case .empty:
                state = .early(result)
                return nil
            case .early, .resumed:
                return nil
            }
        }
        waiting?.resume(with: result)
    }
}
