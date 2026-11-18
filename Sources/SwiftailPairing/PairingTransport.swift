import Foundation
import Network
import Swiftail
import SwiftailBase

/// A connection the joiner uses to exchange pairing messages. It can be an in-process node connection or an OS socket.
///
/// Does not distinguish failure kinds. The protocol only cares that the connection ended, and the state machine interprets that based on its stage.
protocol PairingTransport: Sendable {
    /// The received bytes. Returns nil if the peer closed, the connection failed, or the waiting Task was canceled.
    func receive() async -> [UInt8]?
    /// Sends bytes. The next `receive()` reports failure.
    func send(_ bytes: [UInt8]) async
    /// Closes the connection. Queued data goes out first.
    func close() async
}

/// A tailnet connection through an in-process node.
struct TailnetPairingTransport: PairingTransport {
    let connection: TailnetConnection

    func receive() async -> [UInt8]? {
        try? await connection.read()
    }

    func send(_ bytes: [UInt8]) async {
        try? await connection.write(bytes)
    }

    func close() async {
        await connection.close()
    }
}

/// A TCP connection through an OS socket (`NWConnection`). Used by an app whose node is in a tunnel extension. The tunnel carries bytes to the tailnet.
///
/// `NWConnection` reports through callbacks. Converts each callback to a single-value stream and waits on it. Canceling the waiting Task ends the stream
/// and unblocks the wait. Late callback values are discarded (the canceled protocol closes the connection, so nothing is lost). Deallocation closes the connection.
final class SocketPairingTransport: PairingTransport {
    /// The amount read at a time. Every protocol message is smaller.
    private static let maximumReadLength = 4096

    private let connection: NWConnection

    init(_ connection: NWConnection) {
        self.connection = connection
    }

    /// A plaintext TCP connection dialed to `host:port`. The OS resolves names (MagicDNS when the tunnel is connected).
    ///
    /// - Parameters:
    ///   - isIPv4: The IP version to use. Dial only with the same version as this device's tailnet address so the local endpoint can be compared with it.
    ///   - tunnelOnly: Prevents the connection from using Wi-Fi, cellular, wired, or loopback interfaces. This leaves other interfaces
    ///     such as the tunnel (utun). No connection is established if the tunnel is off. Only loopback tests turn this off.
    convenience init(host: String, port: NWEndpoint.Port, isIPv4: Bool, tunnelOnly: Bool) {
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        let parameters = NWParameters(tls: nil, tcp: tcp)
        if let ip = parameters.defaultProtocolStack.internetProtocol as? NWProtocolIP.Options {
            ip.version = isIPv4 ? .v4 : .v6
        }
        if tunnelOnly {
            parameters.prohibitedInterfaceTypes = [.wifi, .cellular, .wiredEthernet, .loopback]
        }
        self.init(NWConnection(host: NWEndpoint.Host(host), port: port, using: parameters))
    }

    deinit {
        connection.cancel()
    }

    /// Starts the connection and waits for readiness. Returns true when ready.
    ///
    /// On refusal or name resolution failure, `NWConnection` stays in `waiting` and retries on its own. The caller handles redialing
    /// (contract behavior J1), so treat this as a failure here.
    func open() async -> Bool {
        let (states, continuation) = AsyncStream.makeStream(of: Bool.self)
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready: continuation.yield(true)
            case .waiting, .failed, .cancelled: continuation.yield(false)
            default: break
            }
        }
        connection.start(queue: DispatchQueue(label: "Swiftail.Pairing"))
        var isReady = false
        for await state in states {
            isReady = state
            break
        }
        connection.stateUpdateHandler = nil
        return isReady
    }

    /// The two endpoints of the ready connection (local, remote), or nil if they are not IP addresses.
    var endpoints: (local: IPEndpoint, remote: IPEndpoint)? {
        guard let path = connection.currentPath, let local = path.localEndpoint.flatMap(Self.endpoint),
              let remote = path.remoteEndpoint.flatMap(Self.endpoint)
        else { return nil }
        return (local, remote)
    }

    func receive() async -> [UInt8]? {
        let (chunks, continuation) = AsyncStream.makeStream(of: [UInt8].self)
        connection.receive(minimumIncompleteLength: 1, maximumLength: Self.maximumReadLength) {
            data, _, isComplete, error in
            if let data, !data.isEmpty {
                continuation.yield(Array(data))
            } else if error == nil, !isComplete {
                continuation.yield([])
            }
            continuation.finish()
        }
        for await chunk in chunks { return chunk }
        return nil
    }

    func send(_ bytes: [UInt8]) async {
        let (processed, continuation) = AsyncStream.makeStream(of: Void.self)
        connection.send(content: Data(bytes), completion: .contentProcessed { _ in continuation.finish() })
        for await _ in processed {}
    }

    func close() async {
        connection.cancel()
    }

    private static func endpoint(_ endpoint: NWEndpoint) -> IPEndpoint? {
        guard case .hostPort(let host, let port) = endpoint else { return nil }
        let address: SwiftailBase.IPAddress?
        switch host {
        case .ipv4(let ipv4): address = SwiftailBase.IPAddress(bytes: ipv4.rawValue)
        case .ipv6(let ipv6): address = SwiftailBase.IPAddress(bytes: ipv6.rawValue)
        default: address = nil
        }
        return address.map { IPEndpoint(address: $0, port: port.rawValue) }
    }
}
