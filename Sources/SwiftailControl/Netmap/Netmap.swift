import Foundation

/// The current view of the tailnet, produced by applying map stream responses in order (`MapSession`).
///
/// Data plane configuration (WireGuard peers, routes, packet filters), MagicDNS, and WhoIs read what they need from this value.
/// Corresponds to Go `netmap.NetworkMap`. `docs/protocol-notes/control-map.md` §4.3.
public struct Netmap: Sendable, Equatable {
    /// The self node. The legacy `Capabilities` list is merged into `capMap` as entries without arguments.
    public var selfNode: Node
    /// Peers in ascending Node ID order.
    public var peers: [Node]
    /// The DERP map, or `nil` if it has yet to arrive.
    public var derpMap: DERPMap?
    /// The DNS configuration, or `nil` if it has yet to arrive.
    public var dnsConfig: DNSConfig?
    /// Inbound packet filter rules. Concatenates named rule groups in name order. An empty list blocks everything.
    public var packetFilter: [FilterRule]
    /// User ID → profile. Contains only received profiles for owners and sharers of self and peers.
    public var userProfiles: [Int64: UserProfile]
    /// The tailnet name, or an empty string if it has yet to arrive.
    public var domain: String
    /// The last server time reported by the control server. Used to adjust for clock skew when calculating node key expiration.
    public var controlTime: Date?
    /// The tailnet lock view. `ControlClient` has already filtered the netmap's `peers` with it.
    /// A netmap directly from `MapSession` is unfiltered and has the default value here (`.disabled`).
    public var tailnetLock = TailnetLockStatus()
}
