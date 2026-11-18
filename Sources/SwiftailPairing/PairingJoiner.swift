import Foundation
import Network
import Swiftail
import SwiftailBase
import SwiftailIO

/// The pairing joiner. Dials the host in the received offer (`PairingOffer`), runs the protocol, and returns the paired host (`PairedHost`).
///
/// This is the edge. `PairingJoinerSession` makes protocol decisions without I/O. This type dials and redials when necessary, tracks deadlines,
/// and handles cancellation. There are no detached tasks. Canceling the calling Task closes the connection and returns `cancelled` (contract behavior J7).
///
/// A node that just joined the tailnet takes time to resolve names, get routes, and appear in the host's netmap. In the meantime, the
/// host closes connections from unknown peers without reading them. Retry every 1 second for up to 60 seconds until the first
/// `challenge` arrives (J1). Do not redial after receiving the challenge.
///
/// ```swift
/// let offer = try PairingOffer(link: scannedText)
/// let host = try await PairingJoiner.pair(with: offer, deviceName: "Living Room iPad", node: node) { code in
///     Task { @MainActor in screen.show(confirmationCode: code) }   // Compare with the SAS on the host's screen
/// }
/// ```
///
/// See contract `docs/contracts/SwiftailPairing.md` §5.
public enum PairingJoiner {
    /// The deadline for receiving the first `challenge` (J1).
    static let challengeWindow = Duration.seconds(60)
    /// The redial interval (J1).
    static let redialInterval = Duration.seconds(1)

    /// Joins using an in-process node.
    ///
    /// On approval, also checks that the `StableID` in `decision` matches `whoIs` for the connected peer (J6).
    ///
    /// - Parameters:
    ///   - offer: The offer read from a link or QR code.
    ///   - deviceName: This device's name as shown on the host's approval screen. Must be 1–64 bytes of displayable text
    ///     with no control characters and no format characters other than U+200C and U+200D.
    ///   - node: A running `.inProcess` node. If the offer included an auth key, this node was started with that key.
    ///   - awaitingApproval: Called once after the host has been verified. Display the supplied SAS on screen.
    /// - Throws: `PairingError`. `invalidConfiguration` for an invalid device name or node device, `unreachable` if the host cannot be reached within 60 seconds,
    ///   `rejected` if the offer is absent, expired, or already used, or the secret is wrong, `hostNotVerified` if the host could not be verified,
    ///   `denied` if approval was denied, `timedOut` if approval did not arrive within 130 seconds, `protocolViolation` for bytes outside the protocol,
    ///   or `cancelled` if the calling Task was canceled.
    public static func pair(
        with offer: PairingOffer, deviceName: String, node: TailnetNode,
        awaitingApproval: @escaping @Sendable (_ confirmationCode: String) -> Void = { _ in }
    ) async throws(PairingError) -> PairedHost {
        try await join(offer, deviceName: deviceName, awaitingApproval: awaitingApproval) {
            do throws(ConnectionError) {
                let connection = try await node.connect(to: offer.host, port: offer.port)
                return .connected(
                    TailnetPairingTransport(connection: connection),
                    PairingEndpoints(joiner: connection.localEndpoint, host: connection.remoteEndpoint))
            } catch {
                // Waiting can resolve a node that has not started or a host absent from the netmap. An invalid configuration persists.
                if case .invalidConfiguration = error {
                    return .failed(.invalidConfiguration("Could not dial through the node (requires an .inProcess device and a nonzero port)"))
                }
                return .unreachable
            }
        } verifyHost: { stableID, endpoints in
            await node.whoIs(endpoints.host.address)?.stableID == stableID
        }
    }

    /// Joins using an OS socket. An app whose node is in a tunnel extension calls this after the tunnel connects.
    ///
    /// The OS resolves the name (the tunnel's MagicDNS). The library cannot directly observe whether the connection used the tunnel, so it compares
    /// the local endpoint with the device's tailnet address supplied by the app. It dials only with the same IP version as that address. It does not
    /// restrict interface types, because Network.framework treats a path through the packet tunnel as also using the Wi-Fi or cellular interface
    /// beneath it. If the ready connection's local endpoint differs from that address or its remote endpoint falls outside the tailnet range,
    /// pairing ends with `notOnTailnet` before anything is sent (J2). Dial states are logged to subsystem `Swiftail`, category `pairing`.
    /// The library cannot identify the paired peer on subsequent connections through this path.
    ///
    /// - Parameter localAddress: This device's tailnet address (`100.64.0.1`). The tunnel extension must read it from the node's `status.addresses` and pass
    ///   it to the app. Converts IPv4-mapped IPv6 to IPv4. Guessing the value from the OS interface list defeats
    ///   this check.
    /// - Throws: The errors from `pair(with:deviceName:node:awaitingApproval:)`, plus `invalidConfiguration` if `localAddress` is outside the tailnet range,
    ///   or `notOnTailnet` if the connection did not traverse the tunnel.
    public static func pair(
        with offer: PairingOffer, deviceName: String, localAddress: SwiftailBase.IPAddress,
        awaitingApproval: @escaping @Sendable (_ confirmationCode: String) -> Void = { _ in }
    ) async throws(PairingError) -> PairedHost {
        try await pair(
            with: offer, deviceName: deviceName, localAddress: localAddress, requiringTunnel: true,
            awaitingApproval: awaitingApproval)
    }

    /// Joins using an OS socket. Only loopback tests turn off `requiringTunnel` (which is internal). Turning it off skips the range checks.
    /// The local endpoint must still match `localAddress`.
    static func pair(
        with offer: PairingOffer, deviceName: String, localAddress suppliedAddress: SwiftailBase.IPAddress,
        requiringTunnel: Bool,
        awaitingApproval: @escaping @Sendable (_ confirmationCode: String) -> Void
    ) async throws(PairingError) -> PairedHost {
        let localAddress = suppliedAddress.unmappedIPv4
        guard !requiringTunnel || localAddress.isTailscaleAddress else {
            throw .invalidConfiguration("localAddress must be this device's tailnet address")
        }
        return try await join(offer, deviceName: deviceName, awaitingApproval: awaitingApproval) {
            guard let port = NWEndpoint.Port(rawValue: offer.port), port.rawValue != 0 else {
                return .failed(.invalidConfiguration("The port must be nonzero"))
            }
            let transport = SocketPairingTransport(host: offer.host, port: port, isIPv4: localAddress.isIPv4)
            guard await transport.open(), let ends = transport.endpoints else {
                await transport.close()
                return .unreachable
            }
            let endpoints = PairingEndpoints(joiner: ends.local, host: ends.remote)
            // This check is what keeps pairing off other networks: `attempt` sends `hello` only after `.connected`.
            guard requiringTunnel ? endpoints.isOnTailnet(localAddress: localAddress) : endpoints.isLocal(localAddress)
            else {
                await transport.close()
                return .failed(.notOnTailnet)
            }
            return .connected(transport, endpoints)
        }
    }

    // MARK: Protocol

    /// The result of one dial attempt.
    enum Dialed: Sendable {
        case connected(any PairingTransport, PairingEndpoints)
        /// The peer was unreachable this time. Redial if time remains.
        case unreachable
        /// Redialing will not help.
        case failed(PairingError)
    }

    /// Dials the peer, redials before the deadline if unreachable, and runs the protocol to completion on the established connection.
    ///
    /// - Parameters:
    ///   - dial: Dials one connection.
    ///   - verifyHost: Checks whether the approved `StableID` belongs to the connected peer (J6).
    static func join(
        _ offer: PairingOffer, deviceName: String,
        awaitingApproval: @escaping @Sendable (String) -> Void,
        dial: @escaping @Sendable () async -> Dialed,
        verifyHost: @escaping @Sendable (_ stableID: String, PairingEndpoints) async -> Bool = { _, _ in true }
    ) async throws(PairingError) -> PairedHost {
        guard let deviceName = DeviceName(deviceName) else {
            throw .invalidConfiguration("The device name must be 1–64 UTF-8 bytes with no control or format characters except U+200C and U+200D")
        }
        let challengeDeadline = ContinuousClock.now + challengeWindow
        while true {
            do throws(PairingError) {
                let approval = try await attempt(
                    offer, deviceName: deviceName, challengeDeadline: challengeDeadline,
                    awaitingApproval: awaitingApproval, dial: dial, verifyHost: verifyHost)
                return PairedHost(host: offer.host, stableID: approval.stableID, name: approval.name, pairedAt: Date())
            } catch {
                guard error == .unreachable, ContinuousClock.now + redialInterval < challengeDeadline else {
                    throw error
                }
            }
            try? await Task.sleep(for: redialInterval)
            if Task.isCancelled { throw .cancelled }
        }
    }

    /// Attempts pairing over one connection. Returns `unreachable` if the connection ends before receiving `challenge`.
    private static func attempt(
        _ offer: PairingOffer, deviceName: DeviceName, challengeDeadline: ContinuousClock.Instant,
        awaitingApproval: @Sendable (String) -> Void,
        dial: @escaping @Sendable () async -> Dialed,
        verifyHost: @Sendable (String, PairingEndpoints) async -> Bool
    ) async throws(PairingError) -> PairingJoinerSession.Approval {
        // Dialing also waits only until the deadline (an unanswered SYN can take up to 247 seconds).
        let dialed = try? await withTimeout(ContinuousClock.now.duration(to: challengeDeadline), dial)
        guard case .connected(let transport, let endpoints) = dialed else {
            if Task.isCancelled { throw .cancelled }
            if case .failed(let error) = dialed { throw error }
            throw .unreachable
        }

        var session = PairingJoinerSession(
            offer: offer, deviceName: deviceName, nonce: PairingRandom.bytes(PairingMessage.nonceLength),
            endpoints: endpoints, challengeDeadline: challengeDeadline)
        var actions: [PairingJoinerSession.Action] = [.send(session.hello)]
        while true {
            for action in actions {
                switch action {
                case .send(let bytes):
                    await transport.send(bytes)
                case .awaitingApproval(let confirmationCode):
                    awaitingApproval(confirmationCode)
                case .finish(.success(let approval)):
                    let isVerified = await verifyHost(approval.stableID, endpoints)
                    await transport.close()
                    guard isVerified else { throw .hostNotVerified }
                    return approval
                case .finish(.failure(let error)):
                    await transport.close()
                    throw error
                }
            }
            // A protocol in progress always has a deadline.
            guard !Task.isCancelled, let deadline = session.deadline else {
                await transport.close()
                throw .cancelled
            }
            do {
                let received = try await withTimeout(ContinuousClock.now.duration(to: deadline)) {
                    await transport.receive()
                }
                // A read unblocked by cancellation does not indicate a disconnect. The next iteration ends the attempt with `cancelled`.
                actions = Task.isCancelled ? [] : received.map { session.receive($0, at: .now) }
                    ?? session.connectionEnded()
            } catch {
                actions = Task.isCancelled ? [] : session.advance(to: max(.now, deadline))
            }
        }
    }
}
