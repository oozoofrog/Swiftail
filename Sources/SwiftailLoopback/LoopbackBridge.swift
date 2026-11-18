import Network
import Swiftail
import SwiftailBase
import SwiftailIO
import Synchronization

/// Forwards TCP connections accepted from the tailnet to a TCP listener on this device's loopback address (`127.0.0.1`).
///
/// Apps use it to terminate TLS and HTTP with the OS stack (`NWListener`). The bridge forwards bytes without
/// interpreting them. The peer appears as `127.0.0.1` at the far end of the loopback connection, so the server installs
/// the bridge's protocol in the listener and calls `origin(of:)` with the accepted connection to identify the tailnet
/// peer.
///
/// The bridge sends a one-time token before any TLS bytes on each loopback connection. The listener's protocol passes
/// only connections with verified tokens up to TLS. Connections opened by other processes on the same device fail
/// before the server sees them as `.ready`. This holds when a source port is reused or the same source port is used
/// with a different listener (contract `docs/contracts/SwiftailHost.md` behavior B6).
///
/// Server requirements (behavior B7)
/// - Bind the listener only to `127.0.0.1` and let the system choose the port.
/// - Add `makeListenerProtocolOptions()` to the listener's `NWParameters` **at the end of `applicationProtocols`**
///   (below TLS, directly above TCP). Putting it first places it above TLS and breaks the handshake.
/// - On each accepted connection, call `origin(of:)` once **after it becomes `.ready` and before reading the request**.
///   Abort the connection if it returns nil. It answers only once and returns nil on the second call.
/// - Use `Origin.peer` for identity. It is verified when establishing the connection, so skip looking it up again with
///   `whoIs` on each request (behavior B2).
/// - Call `cancel()` on ended connections and release the reference to the `NWConnection`. On a connection that ended
///   before it was ready, as with a missing token, the socket closes only when the object is released. Calling
///   `cancel()` while retaining the connection leaves a file descriptor for each such connection.
///
/// The bridge works per connection, so existing connections forwarded to the old port continue if the server moves the
/// listener to a new port.
public final class LoopbackBridge: Sendable {
    /// The tailnet peer of one loopback connection.
    public struct Origin: Sendable, Equatable {
        /// The peer's tailnet address and port.
        public var remoteEndpoint: IPEndpoint
        /// The peer's identity, verified when forwarding starts. It stays fixed for the life of the connection.
        public var peer: PeerIdentity
    }

    /// How to end a loopback connection.
    private enum LoopbackEnding {
        /// A normal close (FIN).
        case close
        /// An abort due to an error (RST).
        case reset
    }

    /// The number of `forward` calls that have started and not yet returned. Checked against the limit.
    private let forwarding = Mutex(0)

    /// The bytes held in one direction at a time (contract limits table, 64KiB per direction).
    private static let chunkSize = 65_536
    /// The deadline for one attempt to establish a loopback connection (contract limits table).
    private static let connectTimeout = Duration.seconds(5)
    /// The number of loopback connection attempts. If an admission remains for the selected source port's key, retries
    /// with a different port (contract limits table).
    private static let connectAttempts = 3

    private let node: TailnetNode
    let connectionLimit: Int
    let admission = LoopbackAdmissionTable()
    /// Receives the connection key and a snapshot of the table immediately before closing a loopback connection. Used only in tests.
    private let willEndLoopback: (@Sendable (LoopbackAdmissionTable.Key, LoopbackAdmissionTable.Snapshot) -> Void)?
    /// Receives the key and table immediately before recording a loopback connection's key in the table. Tests use it
    /// to simulate a leftover admission on the selected source port.
    private let willExpect: (@Sendable (LoopbackAdmissionTable.Key, LoopbackAdmissionTable) -> Void)?

    /// Creates a bridge for connections accepted by `node`. Looks up identities with `node.whoIs(_:)`. Forwards at most
    /// 256 connections, equal to the node's connection limit.
    public convenience init(node: TailnetNode) {
        self.init(node: node, connectionLimit: 256)
    }

    /// Creates a bridge with a custom limit. Tests can reach the limit with a few connections because a single node's
    /// self-connections cannot give the bridge 256 connections. They also inspect the table at the moment a loopback
    /// connection closes.
    init(
        node: TailnetNode, connectionLimit: Int,
        willEndLoopback: (@Sendable (LoopbackAdmissionTable.Key, LoopbackAdmissionTable.Snapshot) -> Void)? = nil,
        willExpect: (@Sendable (LoopbackAdmissionTable.Key, LoopbackAdmissionTable) -> Void)? = nil
    ) {
        self.node = node
        self.connectionLimit = connectionLimit
        self.willEndLoopback = willEndLoopback
        self.willExpect = willExpect
    }

    /// Creates the protocol to install on the server's loopback listener. Only connections whose bridge token verifies are passed up.
    ///
    /// Add it **at the end of** `NWParameters.defaultProtocolStack.applicationProtocols` (`append`). This puts it below
    /// TLS, directly above TCP. The same applies to plaintext listeners. Use one bridge per listener because the
    /// protocol accepts only tokens from this bridge.
    public func makeListenerProtocolOptions() -> NWProtocolFramer.Options {
        let options = NWProtocolFramer.Options(definition: LoopbackAdmissionFramer.definition)
        options[LoopbackAdmissionFramer.tableOption] = admission
        return options
    }

    /// Forwards one connection to `127.0.0.1:<port>` and copies bytes until both directions end. Closes both connections before returning.
    ///
    /// Sequence (behavior B1). Checks the limit, verifies the peer's identity, and connects to loopback (5 seconds).
    /// Sends the new token **after** recording it under the connection's (source port, listener port), then starts
    /// copying. If the table rejects the key because an earlier admission remains, retries with another source port (up
    /// to 3 attempts). On completion, closes the loopback connection **after** withdrawing the unconsumed token.
    ///
    /// Copying (behaviors B3 and B4). Holds only one chunk per direction (up to 64KiB) and waits for the receiver to
    /// accept it before reading the next. When one side closes its write side (FIN), closes the other side's write side
    /// and continues copying in the opposite direction.
    ///
    /// Aborts (behavior B5). If either side ends with an error (`reset`, `timedOut`, `peerRemoved`, node stop, or
    /// loopback failure) or the calling Task is canceled, aborts both connections with RST. The loopback server sees an
    /// abort rather than a normal close (FIN), so it does not treat a partial read as complete. An abort after
    /// forwarding starts does not throw, except cancellation, which throws `cancelled`.
    ///
    /// - Throws: `limitReached` at the limit, `unknownPeer` if the identity is missing, `loopbackUnavailable` if
    ///   connecting to loopback or recording or sending the token fails, or `cancelled` if the calling Task is
    ///   canceled. Aborts `connection` with RST before throwing.
    public func forward(_ connection: TailnetConnection, toLoopbackPort port: UInt16) async throws(LoopbackBridgeError) {
        guard reserveSlot() else {
            await connection.abort()
            throw .limitReached
        }
        defer { releaseSlot() }

        guard let peer = await node.whoIs(connection.remoteEndpoint.address) else {
            await connection.abort()
            throw .unknownPeer
        }

        let token = LoopbackAdmissionTable.makeToken()
        let socket: NetworkSocket
        let key: LoopbackAdmissionTable.Key
        do {
            (socket, key) = try await openLoopback(
                port: port, token: token, origin: Origin(remoteEndpoint: connection.remoteEndpoint, peer: peer))
        } catch {
            await connection.abort()
            throw error
        }
        guard await socket.writeAccepted(token) else {
            endLoopback(socket, key, .reset)
            await connection.abort()
            if Task.isCancelled { throw .cancelled }
            throw .loopbackUnavailable("Could not send the token")
        }

        if await relay(connection, socket, key: key) {
            endLoopback(socket, key, .close)
            await connection.close()
        } else if Task.isCancelled {
            throw .cancelled
        }
    }

    /// Returns the tailnet peer of the loopback connection the server accepted. Does not wait. Answers once per
    /// connection and returns nil on the second call.
    ///
    /// Answers only if `connection` is `.ready` and the listener's `makeListenerProtocolOptions()` verified this
    /// bridge's token on that connection. The token arrives before TLS bytes, and the connection stays unready until
    /// verification, so querying after `.ready` always yields an answer for a connection forwarded by the bridge. A nil
    /// result means the bridge did not forward the connection or it has already been queried. The server aborts that
    /// connection.
    public func origin(of connection: NWConnection) -> Origin? {
        guard case .ready = connection.state,
              case .hostPort(.ipv4(let remoteHost), let remotePort) = connection.endpoint, remoteHost == .loopback,
              case .hostPort(_, let localPort)? = connection.currentPath?.localEndpoint
        else { return nil }
        return admission.take(LoopbackAdmissionTable.Key(sourcePort: remotePort.rawValue, listenerPort: localPort.rawValue))
    }

    // MARK: Loopback Connection

    /// Connects to `127.0.0.1:<port>` and records `token` under the connection's key. At this point, no bytes have been sent.
    ///
    /// The table rejects the selected source port's key if an admission remains. It belongs to an ended connection
    /// whose admission the server did not claim, as with a connection that ended before the TLS handshake. Retry while
    /// holding the socket so the kernel cannot assign the same port again. Abort held sockets with RST on return. The
    /// token was never sent, so the server sees them end before becoming ready.
    private func openLoopback(
        port: UInt16, token: [UInt8], origin: Origin
    ) async throws(LoopbackBridgeError) -> (NetworkSocket, LoopbackAdmissionTable.Key) {
        var refused: [NetworkSocket] = []
        defer { for socket in refused { socket.abort() } }
        for _ in 0..<Self.connectAttempts {
            let socket: NetworkSocket
            do {
                socket = try await withTimeout(Self.connectTimeout) { try await NetworkSocket.connectLoopback(port: port) }
            } catch {
                if Task.isCancelled { throw .cancelled }
                switch error {
                case SocketError.connectFailed(let message): throw .loopbackUnavailable(message)
                case is TimeoutError: throw .loopbackUnavailable("Could not connect within 5 seconds")
                default: throw .loopbackUnavailable("Could not connect")
                }
            }
            guard let sourcePort = socket.localPort else {
                socket.abort()
                throw .loopbackUnavailable("Could not read the source port")
            }
            let key = LoopbackAdmissionTable.Key(sourcePort: sourcePort, listenerPort: port)
            willExpect?(key, admission)
            if admission.expect(token, for: key, origin: origin) { return (socket, key) }
            refused.append(socket)
        }
        throw .loopbackUnavailable("Could not record the token in the table")
    }

    // MARK: Forwarding

    /// Copies in both directions. Returns true if both directions finish normally.
    ///
    /// If one direction fails, immediately aborts both connections with RST to unblock the other direction. If the
    /// calling Task is canceled, the waits in both directions fail and take the same path. Cancellation leaves the
    /// loopback socket open (`connectLoopback`), so closing always goes through `endLoopback`.
    private func relay(_ connection: TailnetConnection, _ socket: NetworkSocket, key: LoopbackAdmissionTable.Key) async -> Bool {
        await withTaskGroup(of: Bool.self) { group in
            group.addTask { await Self.copyToLoopback(from: connection, to: socket) }
            group.addTask { await Self.copyToTailnet(from: socket, to: connection) }
            var finishedCleanly = true
            for await finished in group where !finished && finishedCleanly {
                finishedCleanly = false
                endLoopback(socket, key, .reset)
                await connection.abort()
            }
            return finishedCleanly
        }
    }

    /// The only path for ending a loopback connection after recording a token. Withdraws any unconsumed token before closing.
    ///
    /// Keeps the admission (the peer the server has yet to claim) and only marks it ended (`withdraw`). The admission
    /// identifies the peer whose bytes this connection actually forwarded, and the server can still query the
    /// connection. Removing it could let a new bridge connection using the same 4-tuple take its place and return the
    /// wrong peer to a late query.
    private func endLoopback(_ socket: NetworkSocket, _ key: LoopbackAdmissionTable.Key, _ ending: LoopbackEnding) {
        admission.withdraw(key)
        willEndLoopback?(key, admission.snapshot)
        switch ending {
        case .close: socket.close()
        case .reset: socket.abort()
        }
    }

    /// Tailnet → loopback. When the peer closes its write side, sends FIN to loopback and returns true.
    private static func copyToLoopback(from connection: TailnetConnection, to socket: NetworkSocket) async -> Bool {
        while true {
            let chunk: [UInt8]?
            do {
                chunk = try await connection.read(upTo: chunkSize)
            } catch {
                return false
            }
            guard let chunk else {
                socket.finishWriting()
                return true
            }
            guard await socket.writeAccepted(chunk) else { return false }
        }
    }

    /// Loopback → tailnet. When loopback closes its write side, sends FIN to the tailnet and returns true.
    private static func copyToTailnet(from socket: NetworkSocket, to connection: TailnetConnection) async -> Bool {
        while true {
            let chunk: [UInt8]?
            do {
                chunk = try await socket.receive()
            } catch {
                return false
            }
            do {
                guard let chunk else {
                    try await connection.finishWriting()
                    return true
                }
                if !chunk.isEmpty { try await connection.write(chunk) }
            } catch {
                return false
            }
        }
    }

    // MARK: Limit

    private func reserveSlot() -> Bool {
        forwarding.withLock { forwarding in
            guard forwarding < connectionLimit else { return false }
            forwarding += 1
            return true
        }
    }

    private func releaseSlot() {
        forwarding.withLock { $0 -= 1 }
    }
}
