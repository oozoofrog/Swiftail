import CryptoKit
import Foundation
import SwiftailBase
import SwiftailControl
import SwiftailWireGuard

/// A node's data plane, a state machine combining the netmap, WireGuard, and packet filter.
///
/// Has no I/O, socket, clock, or actor. Takes time as an argument and returns "WireGuard datagrams to send to peers" and
/// "IP packets to deliver up the stack." All entry points are nonthrowing. Discards are reported as `.dropped`.
///
/// The engine is unaware of paths. The caller (`Magicsock`) chooses whether to send a datagram by UDP or which DERP region to use,
/// and delivers only datagrams classified as WireGuard (the same principle as the WireGuard device being unaware of addresses).
/// Fails closed for unsupported packets and peers.
///
/// This file contains state, netmap application, and timers. Packet sending and receiving are in `TailnetEngine+Packets.swift`.
/// Local handling of packets to the service IP and local addresses is in `TailnetEngine+LocalDelivery.swift`.
/// `docs/protocol-notes/netmap-engine.md` 4.2 and 6.1, `docs/contracts/SwiftailEngine.md` behaviors 3 and 7 and "Changes in M4",
/// and `docs/contracts/SwiftailTunnel.md` behaviors D and L.
public struct TailnetEngine: Sendable {
    /// Actions emitted by the state machine.
    public enum Output: Sendable, Equatable {
        /// A WireGuard message to send to a peer. The caller (`Magicsock`) chooses the path.
        case datagram([UInt8], to: NodePublicKey)
        /// An IP packet allowed by the filter to deliver up the stack.
        case ipPacket([UInt8])
        /// A discarded packet, for diagnostics and tests.
        case dropped(Drop)
        /// A WireGuard cookie reply to send as is back to the source of the datagram just passed to `receive`. The sending peer is still unknown,
        /// so this bypasses peer path selection. Appears only in `receive` outputs.
        case cookieReply([UInt8])
        /// A peer announced its own disco key through the tunnel (a TSMP disco key advertisement, excluding keys of 0). Emitted only for packets
        /// authenticated by WireGuard that passed the source check. The caller passes it to `Magicsock`. Appears only in `receive` outputs.
        case discoKeyAdvertised(DiscoPublicKey, from: NodePublicKey)
    }

    /// The source of the received datagram. An opaque value the caller creates from the path (UDP address or DERP sender). The engine only passes it
    /// to the WireGuard device (for cookies and per-source rate limits under load).
    public typealias Source = WireGuardDevice.Source

    /// The reason for a discard.
    public enum Drop: Sendable, Equatable {
        /// The filter discarded a received packet.
        case inbound(PacketFilter.DropReason)
        /// Unable to parse as an IP packet.
        case malformedPacket
        /// A fragment or an IPv6 extension header.
        case unsupportedPacket
        /// TSMP. The engine consumes it without delivering it up the stack.
        case consumedControlPacket
        /// A packet to the service IP that the node does not answer (anything other than UDP 53, ICMP echo, or TCP, an RST that gets no reply, or malformed UDP).
        /// Sends neither a response nor an ICMP unreachable.
        case serviceIPPacket
        /// No peer owns the destination address.
        case noPeerForDestination
        /// WireGuard could not receive or send.
        case wireGuard(WireGuardError)
    }

    /// The maximum interval before rechecking key expiration. Prevents overflow when converting a far-future expiration to monotonic time.
    private static let maximumExpiryCheckInterval = Duration.seconds(24 * 60 * 60)

    /// Holds the node private key and WireGuard sessions. Hidden by `customMirror`.
    var device: WireGuardDevice
    /// This node's disco public key. Advertises it to the peer whenever a WireGuard session is established. A key of 0 is not advertised.
    let discoKey: DiscoPublicKey
    var filter = PacketFilter.allowNone
    /// Peers installed in the data plane, keyed by their keys.
    var peers: [NodePublicKey: EnginePeer] = [:]
    /// Maps data-plane addresses to their owner nodes (`EnginePeer.addressOwners`). Updated in the same computation whenever peers are recomputed
    /// (netmap application or key expiration). Sending, the node's `whoIs`, and connection owner verification use it to agree on the owner determined by AllowedIPs.
    package private(set) var addressOwners: [IPAddress: Node] = [:]
    /// The last netmap applied. Used to recompute peers when a key expires.
    private var netmap: Netmap?
    /// The next time a node key expires, whether for a peer or for this node.
    private var keyExpiryDeadline: ContinuousClock.Instant?
    /// A responder for UDP 53 queries to the service IP. Empty if there is no netmap or the local key expired (SERVFAIL for every name).
    var resolver = MagicDNSResolver(netmap: nil, localZones: [])
    /// Local tailnet addresses (single-address prefixes only). Packets to these addresses return to the device.
    var localAddresses: Set<IPAddress> = []
    /// The reference for converting monotonic to wall-clock time. The wall-clock time at `clockAnchor` is `wallClockAnchor`.
    private var clockAnchor: ContinuousClock.Instant
    private var wallClockAnchor: Date

    /// - Parameters:
    ///   - nodeKey: This node's node private key, the WireGuard static key.
    ///   - discoKey: This node's disco public key (`Magicsock.discoPublicKey`). Announces it via TSMP whenever a WireGuard session is established
    ///     with a peer (`SwiftailMagicsock` contract behaviors T1 and T2). A key of 0 is not announced (Go also sends nothing without a disco key).
    ///   - now: The current monotonic time.
    ///   - wallClock: The wall-clock time at `now`.
    public init(
        nodeKey: Curve25519.KeyAgreement.PrivateKey,
        discoKey: DiscoPublicKey,
        now: ContinuousClock.Instant,
        wallClock: Date
    ) {
        device = WireGuardDevice(privateKey: nodeKey, now: now, wallClock: wallClock)
        self.discoKey = discoKey
        clockAnchor = now
        wallClockAnchor = wallClock
    }

    /// Applies the netmap by adding and removing peers, replacing the filter, and rebuilding the MagicDNS responder from the new netmap.
    /// Returns any outbound items.
    ///
    /// Installs all eligible peers in WireGuard up front (without Go's lazy creation). Removes keys that have disappeared or are
    /// no longer eligible. Changing AllowedIPs for the same key preserves the session. The filter updates only rules and preserves UDP flow
    /// records. Adding and removing peers creates no messages, so currently this always returns an empty list.
    ///
    /// - Parameter wallClock: The wall-clock time at `now`. Used to check key expiration for peers and the local node.
    public mutating func apply(_ netmap: Netmap, at now: ContinuousClock.Instant, wallClock: Date) -> [Output] {
        clockAnchor = now
        wallClockAnchor = wallClock
        self.netmap = netmap
        let localAddresses = netmap.selfNode.addresses.filter(EnginePeer.isSingleAddress).map(\.address)
        self.localAddresses = Set(localAddresses)
        filter.replaceRules(netmap.packetFilter, localAddresses: localAddresses)
        applyKeyExpiry(at: now)
        return []
    }

    /// Processes timers due by now (WireGuard timers and key expiration for peers and the local node).
    ///
    /// Clears the responder when the local key expires, even if no new netmap arrives (SERVFAIL for every name). `nextDeadline` includes that time,
    /// so the caller must call `advance` then.
    public mutating func advance(to now: ContinuousClock.Instant) -> [Output] {
        if recomputesPeers(at: now) {
            applyKeyExpiry(at: now)
        }
        return route(device.advance(to: now))
    }

    /// Whether `advance(to: now)` will process key expiration and recompute peers and `addressOwners`. The node rereads the owner table then
    /// and closes connections for addresses whose owners changed.
    package func recomputesPeers(at now: ContinuousClock.Instant) -> Bool {
        keyExpiryDeadline.map { $0 <= now } ?? false
    }

    /// The next time to call advance. The node calls this on each processing step, so it does not allocate an array.
    public var nextDeadline: ContinuousClock.Instant? {
        guard let deviceDeadline = device.nextDeadline else { return keyExpiryDeadline }
        guard let keyExpiryDeadline else { return deviceDeadline }
        return min(deviceDeadline, keyExpiryDeadline)
    }

    // MARK: - Peer and responder synchronization

    /// Recomputes peers and the responder as of now from the last netmap and determines the next key expiration.
    private mutating func applyKeyExpiry(at now: ContinuousClock.Instant) {
        guard let netmap else { return }
        let wallNow = wallClock(at: now)
        configurePeers(in: netmap, wallNow: wallNow)
        installResolver(for: netmap, wallNow: wallNow)
        keyExpiryDeadline = nextExpiry(in: netmap, after: wallNow).map { now + $0 }
    }

    /// Rebuilds the responder from the netmap as of now. Uses an empty responder if the local key has expired (behavior D7, fail closed).
    private mutating func installResolver(for netmap: Netmap, wallNow: Date) {
        if TunnelNetworkSettings.isExpired(netmap.selfNode, at: wallNow) {
            resolver = MagicDNSResolver(netmap: nil, localZones: [])
        } else {
            resolver = MagicDNSResolver(netmap: netmap, localZones: TunnelNetworkSettings.localZones(in: netmap, at: wallNow))
        }
    }

    /// Computes peers from the netmap as of wallNow and synchronizes WireGuard and the send index.
    ///
    /// Also sets the TSMP disco key advertisement for each peer when a session is established. The source is a local address in the same family as the peer's first address,
    /// and the destination is that first address (Go `PriorityMessageForPeer`). Sends nothing if it cannot build the advertisement.
    private mutating func configurePeers(in netmap: Netmap, wallNow: Date) {
        var current: [NodePublicKey: EnginePeer] = [:]
        let eligible = EnginePeer.eligibleNodes(in: netmap, at: wallNow)
        for (_, peer) in eligible {
            current[peer.key] = peer
        }

        for key in peers.keys where current[key] == nil {
            device.removePeer(PublicKey(key))
        }
        for (node, peer) in eligible {
            device.addPeer(PublicKey(peer.key), allowedIPs: peer.allowedIPs)
            let advertisement = node.addresses.first.flatMap {
                TSMPDiscoKeyAdvertisement(selfAddresses: netmap.selfNode.addresses, destination: $0.address, key: discoKey)
            }
            // The peer was just installed and advertisements are 53 or 73 bytes, so this cannot fail.
            try? device.setPriorityMessage(advertisement?.bytes, for: PublicKey(peer.key))
        }
        peers = current
        addressOwners = EnginePeer.addressOwners(of: eligible)
    }

    /// Time until the earliest peer or local node key expiration after wallNow. If more than a day away, check again in a day.
    private func nextExpiry(in netmap: Netmap, after wallNow: Date) -> Duration? {
        let upcoming = (netmap.peers + [netmap.selfNode]).compactMap(\.keyExpiry).filter { $0 > wallNow }.min()
        return upcoming.map { min(.seconds($0.timeIntervalSince(wallNow)), Self.maximumExpiryCheckInterval) }
    }

    /// The wall-clock time corresponding to monotonic time now.
    func wallClock(at now: ContinuousClock.Instant) -> Date {
        let elapsed = (now - clockAnchor).components
        return wallClockAnchor.addingTimeInterval(Double(elapsed.seconds) + Double(elapsed.attoseconds) / 1e18)
    }
}

extension TailnetEngine: CustomReflectable {
    /// Hides children and shows only public values to keep the node private key and WireGuard session keys out of `dump` and debugger output.
    public var customMirror: Mirror {
        Mirror(
            self,
            children: ["publicKey": NodePublicKey(device.publicKey), "peerCount": peers.count],
            displayStyle: .struct
        )
    }
}
