import CryptoKit
import SwiftailBase
import SwiftailCrypto

/// A state machine that discovers and maintains direct paths between peers. It has no socket, clock, or actor.
///
/// The node provides received UDP datagrams, packets received over DERP, WireGuard datagrams emitted by the engine, peer information from the netmap,
/// and the current time. `Magicsock` updates its state and returns "items to send over UDP or DERP," "items to pass to the WireGuard device,"
/// "items to publish to the control server," and "peers whose paths changed." All entry points are nonthrowing. Discards are reported as `.dropped`.
///
/// This type uses system randomness for disco nonces, TxIDs, and ReSTUN intervals (as does `WireGuardDevice`). The underlying
/// stages (`PeerPathState`, `Netcheck`, `DiscoPacket.seal`) take random values as arguments. Tests use fixed-seed randomness with the corresponding
/// internal overloads that take `using:`.
///
/// Pass a nondecreasing `now` across calls. The node calls `advance(to:)` at `nextDeadline`
/// and processes outputs from each entry point in list order.
///
/// This file contains state, outputs, and lookups. `+Peers` covers the peer table and disco keys (netmap and TSMP advertisements). `+Receiving` classifies incoming data and receives disco messages.
/// `+Sending` sends WireGuard and disco messages and handles CallMeMaybe. `+Timers` covers deadlines and STUN rounds. `+Rebind` covers
/// rebinding and rerunning STUN after network changes.
/// "Public API" and behaviors A~I in `docs/contracts/SwiftailMagicsock.md`, and `docs/protocol-notes/disco-magicsock.md` §4.
public struct Magicsock: Sendable {
    /// Actions emitted by the state machine.
    public enum Output: Sendable, Equatable {
        /// Sends through the UDP socket (WireGuard, disco, and STUN all share the same socket).
        case udp([UInt8], to: IPEndpoint)
        /// Sends to the peer over the connection for DERP region `region`. The node opens one if none exists for that region.
        case derp([UInt8], to: NodePublicKey, region: Int64)
        /// A datagram and its incoming path to pass to the WireGuard device (the engine's `receive`). The device's cookie reply
        /// for this datagram goes back over the same path, bypassing peer path selection.
        case wireGuard([UInt8], from: Source)
        /// The local endpoints to publish to the control server changed (order matters, notes 4.9 1).
        case endpointsChanged([Endpoint])
        /// The home DERP region changed. Publish it as `NetInfo.preferredDERP` and connect to that region.
        case homeRegionChanged(Int64)
        /// The peer's path changed. Nil means the peer was removed or is idle (behavior G3).
        case pathChanged(NodePublicKey, PeerPath?)
        /// A discard, for diagnostics and tests.
        case dropped(Drop)
    }

    /// The reason for a discard.
    public enum Drop: Sendable, Equatable {
        /// The sender disco key does not belong to a known peer.
        case unknownDiscoKey
        /// A disco message that could not be opened or parsed.
        case malformedDisco
        /// An unsupported disco type (peer relay 0x04–0x09) or a Geneve-encapsulated datagram.
        case unsupportedDisco
        /// A disco message that violated a path rule (CallMeMaybe over UDP, CallMeMaybe with a mismatched key, or an unknown DERP sender).
        case misroutedDisco
        /// A STUN response that is not from the active round or cannot be parsed.
        case unexpectedSTUN
        /// The DERP sender key does not identify a known peer.
        case unknownDERPSender
        /// There is no direct address or DERP region to send to.
        case noRouteToPeer
        /// An unsupported source (IPv6 or port 0).
        case unsupportedSource
    }

    /// The state of one peer.
    struct PeerEntry: Sendable {
        /// The netmap and TSMP keys. A key is stored only if the peer is in `discoPeers` for that key and the shared key exists (behaviors B1 and T4).
        var discoKeys = PeerDiscoKeys()
        var path: PeerPathState
        /// The last path reported via `.pathChanged`. Nil means no path has been reported yet or an idle path was reported.
        /// Suppresses consecutive reports of the same path (behavior G2).
        var reportedPath: PeerPath?
        /// The reason if the last reported path event was a downgrade (behavior G4), or nil otherwise.
        var reportedDowngrade: PathDowngrade?

        /// The active key used to seal outgoing disco messages to this peer. Nil means DERP only.
        var discoKey: DiscoPublicKey? { discoKeys.active }
    }

    /// The peers holding a disco key and the shared key for that key (behaviors B1 and B2, Go `peerMap.nodesOfDisco`).
    ///
    /// The shared key is computed once when the key first enters the table. `nodes` holds peers with this key as their netmap or TSMP key and
    /// is nonempty (the entry is removed when the last peer releases it). Insertion order makes output repeatable for the same input sequence.
    struct DiscoKeyHolders: Sendable {
        let sharedKey: DiscoSharedKey
        var nodes: [NodePublicKey]
    }

    /// This node's disco public key. The outgoing disco envelope carries it so the peer can select the shared key.
    public let discoPublicKey: DiscoPublicKey
    /// A secret hidden by `customMirror`.
    let discoPrivateKey: Curve25519.KeyAgreement.PrivateKey
    /// The local node key included in outgoing Pings (notes 4.6 1).
    let nodeKey: NodePublicKey

    /// The peer table, mapping keys to states.
    var peers: [NodePublicKey: PeerEntry] = [:]
    /// The order received by `setPeers`. It keeps output order repeatable for the same input sequence.
    var peerOrder: [NodePublicKey] = []
    /// Maps each disco key to its peers and shared key. Incoming disco sender keys are looked up only here (no X25519
    /// on each receive).
    var discoPeers: [DiscoPublicKey: DiscoKeyHolders] = [:]
    /// Local endpoints, the STUN round, and the home region.
    var netcheck: Netcheck
    /// Peers awaiting a CallMeMaybe after the round because endpoints are stale. One slot per peer (behavior F2).
    var pendingCallMeMaybe: [NodePublicKey] = []

    /// - Parameters:
    ///   - discoKey: This node's disco private key. Created at node startup and never persisted.
    ///   - nodeKey: This node's node public key. Included in outgoing Pings (notes 4.6 1).
    ///   - localPort: The port the UDP socket is bound to.
    ///   - localAddresses: Interface IPv4 addresses excluding loopback. Selected by `LocalInterfaceAddresses`.
    ///   - loopbackAddresses: Loopback IPv4 addresses. Used only when no other endpoints exist (notes 4.9 1.7).
    ///   - now: The current time. Accepted in the same form as the other state machines. There are no timers to arm until peers and regions arrive.
    public init(
        discoKey: Curve25519.KeyAgreement.PrivateKey,
        nodeKey: NodePublicKey,
        localPort: UInt16,
        localAddresses: [IPAddress],
        loopbackAddresses: [IPAddress],
        now: ContinuousClock.Instant
    ) {
        discoPrivateKey = discoKey
        discoPublicKey = DiscoPublicKey(discoKey.publicKey)
        self.nodeKey = nodeKey
        netcheck = Netcheck(localPort: localPort, localAddresses: localAddresses, loopbackAddresses: loopbackAddresses)
    }

    /// The peer's current path. Returns nil for a peer absent from the data plane or idle (behavior G3).
    public func path(to peer: NodePublicKey, at now: ContinuousClock.Instant) -> PeerPath? {
        peers[peer].flatMap { Self.path(of: $0, at: now) }
    }

    // MARK: Path events (behavior G)

    /// The current path for a peer. Returns nil for an idle peer, more than 45 seconds after its last WireGuard send or before its first send (behavior G3).
    ///
    /// Reporting an idle peer as `.relayed` would show "relayed" for a connection that will become direct once traffic starts. Report paths only
    /// during actual traffic. Idleness uses the same criterion as stopping heartbeats and periodic STUN (`sessionActiveTimeout`).
    static func path(of entry: PeerEntry, at now: ContinuousClock.Instant) -> PeerPath? {
        guard let lastSend = entry.path.lastSend, now - lastSend <= PeerPathState.sessionActiveTimeout else { return nil }
        return entry.path.path(at: now)
    }

    /// When a reported path becomes idle and turns nil. There is no deadline if nil was already reported, avoiding repeated past deadlines.
    static func idleDeadline(of entry: PeerEntry) -> ContinuousClock.Instant? {
        guard entry.reportedPath != nil, let lastSend = entry.path.lastSend else { return nil }
        return lastSend + PeerPathState.sessionActiveTimeout + .nanoseconds(1)
    }

    /// If a peer's current path differs from the last reported one, appends `.pathChanged` and records it. Also records the reason for any downgrade.
    mutating func reportPathChange(of key: NodePublicKey, at now: ContinuousClock.Instant, into outputs: inout [Output]) {
        guard let entry = peers[key] else { return }
        let current = Self.path(of: entry, at: now)
        guard entry.reportedPath != current else { return }
        peers[key]?.reportedPath = current
        peers[key]?.reportedDowngrade = Self.downgrade(of: entry, from: entry.reportedPath, to: current)
        outputs.append(.pathChanged(key, current))
    }

    /// The reason if the peer's last path event was a downgrade (behavior G4). The node queries it when logging `.pathChanged`.
    ///
    /// A peer absent from the table was removed (`.pathChanged(key, nil)` from `setPeers`). This diagnostic method is outside the public API.
    package func downgrade(of peer: NodePublicKey) -> PathDowngrade? {
        guard let entry = peers[peer] else { return .peerRemoved }
        return entry.reportedDowngrade
    }

    /// The reason if the change from `previous` to `current` was a downgrade.
    ///
    /// - Became nil: If send history was cleared, the disco key changed (`resetForNewDiscoKey`, stopped using disco). Otherwise the peer is idle.
    /// - Went from direct to relayed: If `bestAddr` remains, trust expired. If it was cleared, use the reason it was cleared.
    /// - Other changes (first send, becoming direct, or only an address or region change) are not downgrades.
    private static func downgrade(of entry: PeerEntry, from previous: PeerPath?, to current: PeerPath?) -> PathDowngrade? {
        switch (previous, current) {
        case (.some, nil):
            return entry.path.lastSend == nil ? .discoKeyChanged : .idle
        case (.direct, .relayed):
            guard entry.path.bestAddr == nil else { return .trustExpired }
            return entry.path.bestAddrLoss ?? .trustExpired
        default:
            return nil
        }
    }

    // MARK: Sealing disco messages

    /// Seals `message` with the shared key for disco key `discoKey`. Returns nil if disco is not used with that key.
    func seal(
        _ message: DiscoMessage,
        to discoKey: DiscoPublicKey,
        using generator: inout some RandomNumberGenerator
    ) -> [UInt8]? {
        guard let holders = discoPeers[discoKey] else { return nil }
        let nonce = (0..<NaClSecretBox.nonceByteCount).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
        return DiscoPacket.seal(message, sender: discoPublicKey, sharedKey: holders.sharedKey, nonce: nonce)
    }
}

extension Magicsock: CustomReflectable {
    /// Hides children and shows only public values to keep the disco private key and shared keys out of `dump` and debugger output (behavior I1).
    public var customMirror: Mirror {
        Mirror(
            self,
            children: ["discoPublicKey": discoPublicKey, "peerCount": peers.count, "homeRegion": netcheck.homeRegion],
            displayStyle: .struct
        )
    }
}
