import Foundation
import SwiftailBase

/// A node in the tailnet. Go `tailcfg.Node`.
///
/// Arrives in `Node` (self), `Peers`, or `PeersChanged` in a map response. Each arrival replaces the entire object.
/// Missing fields stay missing regardless of previous values. A delta that changes only some fields uses `PeerChange`.
///
/// During decoding, upgrades old representations to current ones, like `upgradeNode` in the Go client (notes §4.3, item 2).
/// - If `homeDERP` is 0 and the legacy `DERP` string is `"127.3.3.40:N"`, uses N as the home DERP.
/// - A missing or `null` `AllowedIPs` matches `addresses`. An empty array is preserved as "no routes."
/// - Restricts the `allowedIPs` of an `unsignedPeerAPIOnly` node to its own addresses. This safeguard keeps the control server
///   from opening routes for a node without a tailnet lock signature.
///
/// Includes only fields used by the data plane, DNS, or WhoIs. Omits exit node DNS, audit log ID, and computed display name.
/// `docs/protocol-notes/control-map.md` §3.7 (origin: `Node` in tailscale.com `tailcfg/tailcfg.go`,
/// `control/controlclient/map.go` `upgradeNode`, BSD-3-Clause).
public struct Node: Decodable, Sendable, Equatable {
    /// The node ID used as the key in deltas.
    public internal(set) var id: Int64
    /// The opaque stable ID identifying the node.
    public internal(set) var stableID: String
    /// The MagicDNS name. Usually ends with a dot, though testcontrol sometimes omits it.
    public internal(set) var name: String
    /// The owner's user ID, a key in `Netmap.userProfiles`.
    public internal(set) var user: Int64
    /// The ID of the user who shared this node, or 0 if it was not shared.
    public internal(set) var sharer: Int64
    /// The WireGuard public key.
    public internal(set) var key: NodePublicKey
    /// The node key expiration time. `nil` means no expiration.
    public internal(set) var keyExpiry: Date?
    /// The tailnet lock signature for the node key, or an empty array if absent.
    public internal(set) var keySignature: [UInt8]
    /// The device's machine public key.
    public internal(set) var machine: MachinePublicKey
    /// The disco public key, used to encrypt path discovery messages.
    public internal(set) var discoKey: DiscoPublicKey
    /// The node's tailnet addresses (typically IPv4 /32 and IPv6 /128).
    public internal(set) var addresses: [IPPrefix]
    /// Destination prefixes routed to this node as WireGuard AllowedIPs.
    public internal(set) var allowedIPs: [IPPrefix]
    /// Candidate UDP addresses for direct connections.
    public internal(set) var endpoints: [IPEndpoint]
    /// The home DERP region that serves the node. 0 means none.
    public internal(set) var homeDERP: Int64
    /// Information the node reported about itself.
    public internal(set) var hostinfo: Hostinfo
    /// The node's capability version. 0 means unknown.
    public internal(set) var cap: Int
    /// ACL tags (`"tag:server"`). A tagged node has no user owner.
    public internal(set) var tags: [String]
    /// Subnet routes for which this node is currently the primary router.
    public internal(set) var primaryRoutes: [IPPrefix]
    /// The last time the node was online. `nil` means unknown or no permission to view it.
    public internal(set) var lastSeen: Date?
    /// Whether the node is connected to the control server. `nil` means unknown.
    public internal(set) var online: Bool?
    /// Whether the device is authorized. Meaningful for the self node.
    public internal(set) var machineAuthorized: Bool
    /// The legacy list of node capabilities. On the self node, merges into `capMap`.
    public internal(set) var capabilities: [String]
    /// Node capability → arguments. A capability with no arguments has an empty array.
    public internal(set) var capMap: [String: [JSONValue]]
    /// A node with no tailnet lock signature, permitted to use only peerAPI.
    public internal(set) var unsignedPeerAPIOnly: Bool
    /// Whether the node key has expired.
    public internal(set) var expired: Bool
    /// The IPv4 address this peer uses for the self node. Used to rewrite the source address of packets sent to that peer.
    public internal(set) var selfNodeV4MasqAddrForThisPeer: IPAddress?
    /// The IPv6 address this peer uses for the self node.
    public internal(set) var selfNodeV6MasqAddrForThisPeer: IPAddress?
    /// A WireGuard-only peer with no disco or DERP. Reachable only through `endpoints`.
    public internal(set) var isWireGuardOnly: Bool
    /// This node can accept connections but cannot initiate them.
    public internal(set) var isJailed: Bool

    private enum CodingKeys: String, CodingKey {
        case id = "ID"
        case stableID = "StableID"
        case name = "Name"
        case user = "User"
        case sharer = "Sharer"
        case key = "Key"
        case keyExpiry = "KeyExpiry"
        case keySignature = "KeySignature"
        case machine = "Machine"
        case discoKey = "DiscoKey"
        case addresses = "Addresses"
        case allowedIPs = "AllowedIPs"
        case endpoints = "Endpoints"
        case legacyDERP = "DERP"
        case homeDERP = "HomeDERP"
        case hostinfo = "Hostinfo"
        case cap = "Cap"
        case tags = "Tags"
        case primaryRoutes = "PrimaryRoutes"
        case lastSeen = "LastSeen"
        case online = "Online"
        case machineAuthorized = "MachineAuthorized"
        case capabilities = "Capabilities"
        case capMap = "CapMap"
        case unsignedPeerAPIOnly = "UnsignedPeerAPIOnly"
        case expired = "Expired"
        case selfNodeV4MasqAddrForThisPeer = "SelfNodeV4MasqAddrForThisPeer"
        case selfNodeV6MasqAddrForThisPeer = "SelfNodeV6MasqAddrForThisPeer"
        case isWireGuardOnly = "IsWireGuardOnly"
        case isJailed = "IsJailed"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decodeIfPresent(Int64.self, forKey: .id) ?? 0
        stableID = try container.decodeIfPresent(String.self, forKey: .stableID) ?? ""
        name = try container.decodeIfPresent(String.self, forKey: .name) ?? ""
        user = try container.decodeIfPresent(Int64.self, forKey: .user) ?? 0
        sharer = try container.decodeIfPresent(Int64.self, forKey: .sharer) ?? 0
        key = try container.decodeIfPresent(NodePublicKey.self, forKey: .key) ?? .zero
        keyExpiry = try container.decodeTimeIfPresent(forKey: .keyExpiry).flatMap(GoTime.nonZero)
        keySignature = try container.decodeBytesIfPresent(forKey: .keySignature) ?? []
        machine = try container.decodeIfPresent(MachinePublicKey.self, forKey: .machine) ?? .zero
        discoKey = try container.decodeIfPresent(DiscoPublicKey.self, forKey: .discoKey) ?? .zero
        addresses = try container.decodeIfPresent([IPPrefix].self, forKey: .addresses) ?? []
        allowedIPs = try container.decodeIfPresent([IPPrefix].self, forKey: .allowedIPs) ?? addresses
        endpoints = try container.decodeIfPresent([IPEndpoint].self, forKey: .endpoints) ?? []
        homeDERP = try container.decodeIfPresent(Int64.self, forKey: .homeDERP) ?? 0
        hostinfo = try container.decodeIfPresent(Hostinfo.self, forKey: .hostinfo) ?? Hostinfo()
        cap = try container.decodeIfPresent(Int.self, forKey: .cap) ?? 0
        tags = try container.decodeIfPresent([String].self, forKey: .tags) ?? []
        primaryRoutes = try container.decodeIfPresent([IPPrefix].self, forKey: .primaryRoutes) ?? []
        lastSeen = try container.decodeTimeIfPresent(forKey: .lastSeen)
        online = try container.decodeIfPresent(Bool.self, forKey: .online)
        machineAuthorized = try container.decodeIfPresent(Bool.self, forKey: .machineAuthorized) ?? false
        capabilities = try container.decodeIfPresent([String].self, forKey: .capabilities) ?? []
        capMap = try container.decodeCapMapIfPresent(forKey: .capMap) ?? [:]
        unsignedPeerAPIOnly = try container.decodeIfPresent(Bool.self, forKey: .unsignedPeerAPIOnly) ?? false
        expired = try container.decodeIfPresent(Bool.self, forKey: .expired) ?? false
        selfNodeV4MasqAddrForThisPeer = try container.decodeIfPresent(IPAddress.self, forKey: .selfNodeV4MasqAddrForThisPeer)
        selfNodeV6MasqAddrForThisPeer = try container.decodeIfPresent(IPAddress.self, forKey: .selfNodeV6MasqAddrForThisPeer)
        isWireGuardOnly = try container.decodeIfPresent(Bool.self, forKey: .isWireGuardOnly) ?? false
        isJailed = try container.decodeIfPresent(Bool.self, forKey: .isJailed) ?? false

        if homeDERP == 0, let legacy = try container.decodeIfPresent(String.self, forKey: .legacyDERP) {
            homeDERP = Self.regionID(fromLegacyDERP: legacy) ?? 0
        }
        if unsignedPeerAPIOnly {
            allowedIPs = addresses
        }
    }

    /// The N in the legacy `DERP` field `"127.3.3.40:N"`. Returns `nil` for any other format.
    private static func regionID(fromLegacyDERP text: String) -> Int64? {
        let magicPrefix = "127.3.3.40:"
        guard text.hasPrefix(magicPrefix) else { return nil }
        return Int64(text.dropFirst(magicPrefix.count))
    }
}
