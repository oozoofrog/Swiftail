import Foundation

/// The response carried in a single map stream frame. Go `tailcfg.MapResponse`.
///
/// The first regular response in the stream contains full state. Later responses are deltas. `MapSession` applies them (notes §4.3).
/// A `nil` field means a missing key or `null`, equivalent in Go. For delta semantics, `nil` differs from an empty array or object.
/// - `peers`: Replaces the entire list only when nonempty. An empty array preserves existing peers.
/// - `packetFilter`: `nil` leaves rules unchanged, and an empty array clears the rules named `base`.
/// - `packetFilters`: Removes names with a `nil` (`null`) value. `"*": null` clears all names first.
///
/// Includes only fields Swiftail uses. Omits SSH policy, status messages (`Health`, `DisplayMessages`), control connection plans,
/// client version notifications, `Debug`, and session resumption fields (`MapSessionHandle`, `Seq`). Unknown keys are ignored.
/// `docs/protocol-notes/control-map.md` §3.5, §3.6 (origin: `MapResponse` in tailscale.com `tailcfg/tailcfg.go`).
public struct MapResponse: Decodable, Sendable, Equatable {
    /// Whether this is a keepalive response. It carries no map delta. Only `pingRequest` and `controlTime` also apply.
    public internal(set) var keepAlive: Bool
    /// A ping for which the server requested a reply. An event for this response alone.
    public internal(set) var pingRequest: PingRequest?
    /// The complete self node. `nil` preserves the current value. Required in the stream's first regular response.
    public internal(set) var node: Node?
    /// The DERP map. `nil` preserves it. See `DERPMap` for the rules for leaving subfields unchanged.
    public internal(set) var derpMap: DERPMap?
    /// The complete peer list. If nonempty, it replaces the peer store and other peer deltas in this response are discarded.
    public internal(set) var peers: [Node]?
    /// Peers to add or replace in full.
    public internal(set) var peersChanged: [Node]?
    /// IDs of peers to remove.
    public internal(set) var peersRemoved: [Int64]?
    /// Changes to individual fields of known peers.
    public internal(set) var peersChangedPatch: [PeerChange]?
    /// Peer ID → `true` means seen now, and `false` clears the last online time.
    public internal(set) var peerSeenChange: [Int64: Bool]?
    /// Peer ID → online status.
    public internal(set) var onlineChange: [Int64: Bool]?
    /// The entire DNS configuration. `nil` preserves it.
    public internal(set) var dnsConfig: DNSConfig?
    /// The tailnet name. An empty string preserves it.
    public internal(set) var domain: String
    /// Packet filter rules named `base`. `nil` preserves them.
    public internal(set) var packetFilter: [FilterRule]?
    /// A delta for named packet filter rules. Removes names with a `nil` value.
    public internal(set) var packetFilters: [String: [FilterRule]?]?
    /// User profiles to add or replace.
    public internal(set) var userProfiles: [UserProfile]?
    /// The server's current time. `nil` when absent or equal to Go's zero time.
    public internal(set) var controlTime: Date?
    /// Tailnet lock state. `nil` preserves it.
    public internal(set) var tkaInfo: TKAInfo?

    private enum CodingKeys: String, CodingKey {
        case keepAlive = "KeepAlive"
        case pingRequest = "PingRequest"
        case node = "Node"
        case derpMap = "DERPMap"
        case peers = "Peers"
        case peersChanged = "PeersChanged"
        case peersRemoved = "PeersRemoved"
        case peersChangedPatch = "PeersChangedPatch"
        case peerSeenChange = "PeerSeenChange"
        case onlineChange = "OnlineChange"
        case dnsConfig = "DNSConfig"
        case domain = "Domain"
        case packetFilter = "PacketFilter"
        case packetFilters = "PacketFilters"
        case userProfiles = "UserProfiles"
        case controlTime = "ControlTime"
        case tkaInfo = "TKAInfo"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        keepAlive = try container.decodeIfPresent(Bool.self, forKey: .keepAlive) ?? false
        pingRequest = try container.decodeIfPresent(PingRequest.self, forKey: .pingRequest)
        node = try container.decodeIfPresent(Node.self, forKey: .node)
        derpMap = try container.decodeIfPresent(DERPMap.self, forKey: .derpMap)
        peers = try container.decodeIfPresent([Node].self, forKey: .peers)
        peersChanged = try container.decodeIfPresent([Node].self, forKey: .peersChanged)
        peersRemoved = try container.decodeIfPresent([Int64].self, forKey: .peersRemoved)
        peersChangedPatch = try container.decodeIfPresent([PeerChange].self, forKey: .peersChangedPatch)
        peerSeenChange = try container.decodeIntegerKeyedIfPresent(Bool.self, forKey: .peerSeenChange)
        onlineChange = try container.decodeIntegerKeyedIfPresent(Bool.self, forKey: .onlineChange)
        dnsConfig = try container.decodeIfPresent(DNSConfig.self, forKey: .dnsConfig)
        domain = try container.decodeIfPresent(String.self, forKey: .domain) ?? ""
        packetFilter = try container.decodeIfPresent([FilterRule].self, forKey: .packetFilter)
        packetFilters = try container.decodeIfPresent([String: [FilterRule]?].self, forKey: .packetFilters)
        userProfiles = try container.decodeIfPresent([UserProfile].self, forKey: .userProfiles)
        controlTime = try container.decodeTimeIfPresent(forKey: .controlTime).flatMap(GoTime.nonZero)
        tkaInfo = try container.decodeIfPresent(TKAInfo.self, forKey: .tkaInfo)
    }
}
