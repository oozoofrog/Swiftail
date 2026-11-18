import SwiftailBase
import SwiftailControl
import SwiftailEngine

/// The node's current state. Read it through `TailnetNode.status` for display and diagnostics. It contains no keys.
public struct NodeStatus: Sendable, Equatable {
    public var state: NodeState
    /// Local tailnet addresses (single-address entries in the netmap's local node `Addresses`). Empty before a netmap.
    public var addresses: [IPAddress]
    /// The local MagicDNS name with its trailing dot removed (`rd-phone-1a2b3c4d.tail0001.ts.net`). Nil before a netmap
    /// or if the name is missing.
    public var fqdn: String?
    /// The local node's `StableID`. Nil before a netmap or if empty.
    public var stableID: String?
    /// Names eligible for ts.net certificates (netmap `DNSConfig.CertDomains`). The node exposes these names for display.
    public var certDomains: [String]
    /// The number of peers in the netmap.
    public var peerCount: Int
    /// The last settings published to `TailnetNode.networkSettings`. Nil until first publication.
    public var networkSettings: TunnelNetworkSettings?
    /// The tailnet lock state (netmap `tailnetLock`). `.disabled` before a netmap.
    ///
    /// A locked node's `state` still reaches `.running`, as in Go. Use this value to determine why communication is
    /// unavailable. It can be off (`.disabled`), on with this node signed (`.enforcing` and a nil `signingRequest`), on
    /// and awaiting a signature (`.enforcing` with a `signingRequest`), or unverified with peers not installed
    /// (`.unverified`). `docs/contracts/SwiftailTailnetLock.md` decision L4.
    public var tailnetLock: TailnetLockStatus

    /// Creates a status from supplied values. The node creates its status from the netmap and does not use this
    /// initializer. Use it to test consumers of this type without a node.
    public init(
        state: NodeState,
        addresses: [IPAddress] = [],
        fqdn: String? = nil,
        stableID: String? = nil,
        certDomains: [String] = [],
        peerCount: Int = 0,
        networkSettings: TunnelNetworkSettings? = nil,
        tailnetLock: TailnetLockStatus = TailnetLockStatus()
    ) {
        self.state = state
        self.addresses = addresses
        self.fqdn = fqdn
        self.stableID = stableID
        self.certDomains = certDomains
        self.peerCount = peerCount
        self.networkSettings = networkSettings
        self.tailnetLock = tailnetLock
    }

    /// Reads from the last netmap.
    init(state: NodeState, netmap: Netmap?, networkSettings: TunnelNetworkSettings?) {
        self.state = state
        addresses = netmap?.selfNode.addresses
            .filter { $0.length == $0.address.bytes.count * 8 }
            .map(\.address) ?? []
        let name = netmap?.selfNode.name ?? ""
        let trimmed = name.hasSuffix(".") ? String(name.dropLast()) : name
        fqdn = trimmed.isEmpty ? nil : trimmed
        stableID = netmap.flatMap { $0.selfNode.stableID.isEmpty ? nil : $0.selfNode.stableID }
        certDomains = netmap?.dnsConfig?.certDomains ?? []
        peerCount = netmap?.peers.count ?? 0
        self.networkSettings = networkSettings
        tailnetLock = netmap?.tailnetLock ?? TailnetLockStatus()
    }
}
