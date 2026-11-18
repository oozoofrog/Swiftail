// Peer eligibility and AllowedIPs classification are ported from the Go implementation.
// Origin: tailscale.com v1.104.6 `net/routemanager/routemanager.go` (`peerPrefixes`, `isSelfPrefix`),
// `net/tsaddr/tsaddr.go` (`IsTailscaleIP`), `ipn/ipnlocal/expiry.go`.
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import Foundation
import SwiftailBase
import SwiftailControl

/// A netmap peer installed in the data plane.
///
/// M3 does not accept subnet routes or exit nodes (equivalent to Go's `RouteAll=false` and no exit node). A peer can therefore use only its own
/// addresses as sources. These are represented as single-address prefixes. Unsupported peers are excluded from the data plane (fail closed).
///
/// `docs/protocol-notes/netmap-engine.md` 4.1 and 4.3, and `docs/contracts/SwiftailEngine.md` behavior 2.
public struct EnginePeer: Sendable, Equatable {
    /// The peer's node key, which is its WireGuard public key.
    public var key: NodePublicKey
    /// The netmap `Name` verbatim (an FQDN with a trailing dot). May be empty. If multiple nodes claim the same key, this is the name
    /// of the particular node installed in the data plane.
    public var name: String
    /// Addresses this peer can use as sources. Become WireGuard AllowedIPs.
    public var allowedIPs: [IPPrefix]
    /// The DERP region to use when sending to this peer, or 0 if unknown.
    public var homeDERP: Int64
    /// The netmap's `DiscoKey`. A key of 0 disables disco with this peer (DERP only).
    public var discoKey: DiscoPublicKey
    /// The netmap's `Endpoints` verbatim. `Magicsock` filters addresses for candidate use.
    public var endpoints: [IPEndpoint]

    /// Selects peers to install in the data plane from the netmap, in ascending node ID order.
    ///
    /// Assigns each key and each prefix to only one peer. If multiple nodes claim the same key or prefix, the node with the lowest node ID gets it.
    /// Each prefix must have one owner so a source address identifies a single peer
    /// (wireguard-go AllowedIPs also have one owner per prefix). The local node's addresses are assigned to no peer.
    ///
    /// - Parameter now: The current time (local wall clock) for checking key expiration.
    public static func peers(in netmap: Netmap, at now: Date) -> [EnginePeer] {
        eligibleNodes(in: netmap, at: now).map(\.peer)
    }

    /// A peer to install and its node. The engine uses the node's addresses to build the outbound route index.
    static func eligibleNodes(in netmap: Netmap, at now: Date) -> [(node: Node, peer: EnginePeer)] {
        var claimedKeys: Set<NodePublicKey> = []
        // Reserve local addresses first. A peer claiming one still cannot send packets presenting this node as the source.
        var claimedPrefixes = Set(netmap.selfNode.addresses)
        var result: [(node: Node, peer: EnginePeer)] = []
        for node in netmap.peers.sorted(by: { $0.id < $1.id }) {
            guard var peer = EnginePeer(node: node, at: now), !claimedKeys.contains(peer.key) else { continue }
            peer.allowedIPs.removeAll { claimedPrefixes.contains($0) }
            guard !peer.allowedIPs.isEmpty else { continue }
            claimedKeys.insert(peer.key)
            claimedPrefixes.formUnion(peer.allowedIPs)
            result.append((node, peer))
        }
        return result
    }

    /// Returns `nil` if the node cannot be installed.
    private init?(node: Node, at now: Date) {
        guard node.id != 0, !node.key.isZero,
              !Self.isExpired(node, at: now),
              // A peer without a disco key or home DERP has no reachable path.
              !(node.discoKey.isZero && node.homeDERP == 0),
              Self.isSupported(node)
        else { return nil }

        // Keeps only the peer's own addresses from AllowedIPs, meaning single-address entries (/32 or /128) that are tailnet addresses or in `addresses`.
        // Subnet routes and /0 are excluded here. Presence in `addresses` alone does not add an entry.
        // Go (`peerViewOf`) treats prefixes in `addresses` as the peer's own addresses regardless of length. This implementation rejects broad prefixes because
        // WireGuard checks sources per peer, so a peer with a broad prefix could use another peer's address as its source.
        // Also rejects IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) because address-based identity lookup (`whoIs`) converts them to IPv4 before searching.
        // If a peer that does not own the IPv4 address uses its mapped form as the source, it would appear under another node's identity.
        // shortcut: Go excludes original prefixes that still have host bits set. This implementation cannot distinguish them (`IPPrefix` clears the bits during decoding).
        var allowedIPs: [IPPrefix] = []
        for prefix in node.allowedIPs
        where Self.isSingleAddress(prefix) && !Self.isIPv4Mapped(prefix.address) && !allowedIPs.contains(prefix) {
            if prefix.address.isTailscaleAddress || node.addresses.contains(prefix) {
                allowedIPs.append(prefix)
            }
        }
        guard !allowedIPs.isEmpty else { return nil }

        key = node.key
        name = node.name
        self.allowedIPs = allowedIPs
        homeDERP = node.homeDERP
        discoKey = node.discoKey
        endpoints = node.endpoints
    }

    /// An expiration flag is set or the key expiration time has passed (including the exact time).
    // shortcut: Uses the local clock. Go corrects a clock that differs from ControlTime by more than 1 minute.
    private static func isExpired(_ node: Node, at now: Date) -> Bool {
        if node.expired { return true }
        guard let expiry = node.keyExpiry else { return false }
        return expiry <= now
    }

    /// Peers unsupported in M3 include WireGuard-only peers, jailed peers, peers with masquerade addresses, and peers with no tailnet lock
    /// signature that can use only PeerAPI (`UnsignedPeerAPIOnly`). Go has a safeguard that clears all filter rules if the latter peers overlap
    /// with the filter's packet rules (notes 4.5 item 4). This implementation excludes them from the data plane entirely.
    private static func isSupported(_ node: Node) -> Bool {
        !node.isWireGuardOnly
            && !node.isJailed
            && !node.unsignedPeerAPIOnly
            && node.selfNodeV4MasqAddrForThisPeer == nil
            && node.selfNodeV6MasqAddrForThisPeer == nil
    }

    /// /32 or /128.
    static func isSingleAddress(_ prefix: IPPrefix) -> Bool {
        prefix.length == prefix.address.bytes.count * 8
    }

    /// An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`).
    static func isIPv4Mapped(_ address: IPAddress) -> Bool {
        address.bytes.count == 16 && address.bytes.starts(with: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF])
    }
}
