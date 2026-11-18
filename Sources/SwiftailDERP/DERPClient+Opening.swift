import CryptoKit
import Network
import SwiftailBase
import SwiftailIO

/// A connection after the handshake, including the socket, ready state machine, and events that arrived with readiness.
struct OpenedConnection: Sendable {
    let socket: NetworkSocket
    let connection: DERPConnection
    /// Events include packets the server sent in the same chunk as ServerKey, as well as `ready`.
    let events: [DERPConnection.Event]
}

extension DERPClient {
    /// Connects to the server, establishes TLS, and completes the upgrade and handshake through `ready`.
    ///
    /// Tries servers in list order over TCP (with `tcpTimeout` per server), then establishes TLS with the first one that connects. A TLS failure
    /// ends the attempt without advancing to the next server (notes §4.1, item 1). Within a server, `dial` tries the `targets` concurrently.
    static func open(
        servers: [DERPServer], privateKey: Curve25519.KeyAgreement.PrivateKey, isPreferred: Bool, plaintextForTests: Bool,
        interface: NWInterface?
    ) async throws -> OpenedConnection {
        let (socket, server) = try await connect(to: servers, plaintextForTests: plaintextForTests, interface: interface)
        do {
            var connection = try DERPConnection(
                privateKey: privateKey, host: hostHeader(for: server), isPreferred: isPreferred, clientInfoNonce: randomNonce()
            )
            socket.send(connection.takeOutboundBytes())
            while true {
                guard let bytes = try await socket.receive() else { throw Disconnection.closedByServer }
                let events = try connection.receive(bytes)
                socket.send(connection.takeOutboundBytes())
                if events.contains(.ready) { return OpenedConnection(socket: socket, connection: connection, events: events) }
            }
        } catch {
            socket.close()
            throw error
        }
    }

    /// Opens a TLS socket to the first reachable server in the list. With `plaintextForTests`, opens without TLS (for fake test servers).
    ///
    /// Either kind of failure on the last server fails the attempt, so establish TLS immediately. If `interface` is set, all connections go through
    /// that interface (loopback targets are unbound).
    // shortcut: `NetworkSocket.connect` establishes TCP and TLS together. To distinguish their failures, first probe nonfinal servers
    // with plaintext TCP (closing immediately), then reconnect with TLS to the first target that connected. This adds one TCP connection
    // per server. For the last server, start TCP and TLS together for each target and use the first to finish. Go adds TLS only to the first TCP connection,
    // so this approach can still use a different target if one target's TLS fails. Use a single connection once `SwiftailIO` can layer TLS
    // over an already established TCP connection.
    private static func connect(
        to servers: [DERPServer], plaintextForTests: Bool, interface: NWInterface?
    ) async throws -> (NetworkSocket, DERPServer) {
        for (index, server) in servers.enumerated() {
            try Task.checkCancellation()
            var targets = server.targets
            if index < servers.count - 1 {
                do {
                    let (probe, target) = try await withTimeout(tcpTimeout) { [targets] in
                        try await dial(targets, of: server, tls: .none, interface: interface)
                    }
                    probe.close()
                    targets = [target]
                } catch {
                    continue
                }
            }
            let security = plaintextForTests ? NetworkSocket.TLS.none : tls(for: server)
            return (try await dial(targets, of: server, tls: security, interface: interface).socket, server)
        }
        throw Disconnection.noServers
    }

    /// Races `targets` and returns the first successful connection and its target (Go `dialNode`). Closes the losing connections. If all fail,
    /// throws the first failure received. If there are no targets, throws `Disconnection.noServers`.
    ///
    /// Each connection is a TaskGroup child, so canceling the calling Task closes all connections still opening (`NetworkSocket.connect`).
    // shortcut: Go delays IPv4 by 200ms on networks that prefer IPv6 (`preferIPv6`). Swiftail has no address-family preference detection
    // and starts all attempts immediately. Add it if IPv4 winning the race causes problems on an IPv6-capable network.
    private static func dial(
        _ targets: [DERPServer.Target], of server: DERPServer, tls: NetworkSocket.TLS, interface: NWInterface?
    ) async throws -> (socket: NetworkSocket, target: DERPServer.Target) {
        try await withThrowingTaskGroup(of: (socket: NetworkSocket, target: DERPServer.Target).self) { group in
            for target in targets {
                let host = switch target {
                case .hostName: server.hostName
                case .address(let address): address.description
                }
                let bound = NetworkSocket.bindableInterface(interface, forHost: host)
                group.addTask {
                    (try await NetworkSocket.connect(host: host, port: server.port, tls: tls, interface: bound), target)
                }
            }
            var firstFailure: (any Error)?
            while let result = await group.nextResult() {
                switch result {
                case .success(let winner):
                    group.cancelAll()
                    // Close losing connections that succeeded before cancellation reached them.
                    while let late = await group.nextResult() {
                        if case .success(let loser) = late { loser.socket.close() }
                    }
                    return winner
                case .failure(let failure):
                    if firstFailure == nil { firstFailure = failure }
                }
            }
            throw firstFailure ?? Disconnection.noServers
        }
    }

    private static func tls(for server: DERPServer) -> NetworkSocket.TLS {
        switch server.verification {
        case .system: .system(serverName: server.hostName)
        case .named(let certificateName): .named(serverName: server.hostName, certificateName: certificateName)
        case .pinned(let sha256Hex): .pinned(serverName: server.hostName, sha256Hex: sha256Hex)
        case .noneForTests: .insecureForTests(serverName: server.hostName)
        }
    }

    /// The `Host` value. Includes the port if it differs from 443, as in Go.
    private static func hostHeader(for server: DERPServer) -> String {
        server.port == 443 ? server.hostName : "\(server.hostName):\(server.port)"
    }

    /// The nonce for sealing ClientInfo. Draws system randomness only here, outside the state machine.
    private static func randomNonce() -> [UInt8] {
        (0..<DERPHandshake.nonceSize).map { _ in UInt8.random(in: .min ... .max) }
    }
}
