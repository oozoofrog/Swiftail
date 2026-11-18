import Foundation
import Network

/// Support for the loopback bridge (`SwiftailLoopback.LoopbackBridge`). Contract `docs/contracts/SwiftailHost.md` behavior B and §8.
///
/// The bridge forwards tailnet connections to a `127.0.0.1` listener on the same device. This requires three additions.
/// The local port lets the listener's framer compare it with the source port of the accepted connection. A write
/// shutdown (FIN) propagates a half-close. An abort (RST) propagates errors in a way distinguishable from a normal
/// close.
extension NetworkSocket {
    /// Connects to `127.0.0.1:<port>` over plaintext TCP and waits until ready.
    ///
    /// The caller sets the deadline (`withTimeout`). If nothing is listening, the connection fails immediately. Like
    /// `connect`, it treats `waiting` as a failure. It uses only IPv4 loopback because the bridge looks up entries by
    /// (source port, listener port), so both ends must be `127.0.0.1`.
    ///
    /// This socket **keeps the connection open** if a Task waiting on `receive` or `write` is canceled. The bridge must
    /// withdraw the unconsumed token before closing (behavior B6) and choose FIN (`close()`) after normal completion or
    /// RST (`abort()`) after an error. The owner must therefore call `close()` or `abort()`. If released, `deinit`
    /// closes it like `close()`.
    ///
    /// - Throws: `connectFailed` if `port` is zero, the connection fails, or the waiting Task is canceled.
    package static func connectLoopback(port: UInt16) async throws(SocketError) -> NetworkSocket {
        guard port != 0, let nwPort = NWEndpoint.Port(rawValue: port) else {
            throw .connectFailed("Invalid port")
        }
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        let connection = NWConnection(host: .ipv4(.loopback), port: nwPort, using: NWParameters(tls: nil, tcp: tcp))
        return try await open(connection, closesOnCancel: false)
    }

    /// The local port of the ready connection. The loopback listener sees it as the peer's (this socket's) source port
    /// on the accepted connection. Returns nil before the connection is ready or if there is no path.
    package var localPort: UInt16? {
        guard case .hostPort(_, let port)? = connection.currentPath?.localEndpoint else { return nil }
        return port.rawValue
    }

    /// Closes only the write side (TCP FIN). Bytes from earlier calls to `send` or `write` go out first. Reads can continue.
    ///
    /// Signals completion with a `finalMessage` context and no content. Later `send` and `write` calls send nothing.
    package func finishWriting() {
        connection.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .idempotent)
    }

    /// Aborts the connection immediately. The peer sees an error (RST) distinct from a normal close (FIN). Drops unsent
    /// bytes. Any pending `receive()` ends with an error. May be called multiple times.
    ///
    /// Uses `NWConnection.forceCancel()`. The `cancel()` in `close()` closes with FIN, so the peer reads it as having
    /// received the complete stream.
    package func abort() {
        connection.forceCancel()
    }
}
