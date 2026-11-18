import Network
import SwiftailIO

// Maps `SwiftailIO` errors to control client errors. Socket failures and timeouts are connection failures
// (`ControlError.connection`) that trigger backoff and retry.

extension ControlError {
    init(_ error: SocketError) {
        switch error {
        case .connectFailed(let message), .readFailed(let message), .bindFailed(let message), .sendFailed(let message),
             .invalidDevice(let message):
            self = .connection(message)
        }
    }
}

extension NetworkSocket {
    /// Connects to the control server. With TLS, verifies `host` using system certificate validation.
    /// If `interface` is present, connects only through that interface. Leaves loopback server connections unbound.
    static func connect(to endpoint: ControlEndpoint, interface: NWInterface?) async throws(ControlError) -> NetworkSocket {
        let tls: TLS = endpoint.usesTLS ? .system(serverName: endpoint.host) : .none
        do {
            return try await connect(
                host: endpoint.host, port: endpoint.port, tls: tls,
                interface: bindableInterface(interface, forHost: endpoint.host)
            )
        } catch {
            throw ControlError(error)
        }
    }

    /// Receives available bytes, or nil if the peer closed the connection.
    func receiveBytes() async throws(ControlError) -> [UInt8]? {
        do {
            return try await receive()
        } catch {
            throw ControlError(error)
        }
    }
}

/// Wraps `SwiftailIO.withTimeout` to throw `ControlError.connection` when the deadline expires.
func withControlTimeout<Result: Sendable>(
    _ duration: Duration,
    _ operation: @escaping @Sendable () async throws -> Result
) async throws -> Result {
    do {
        return try await withTimeout(duration, operation)
    } catch is TimeoutError {
        throw ControlError.connection("Did not finish within \(duration)")
    }
}
