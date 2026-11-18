import Foundation
import SwiftailBase

/// A delta that changes only some fields of a known peer. Go `tailcfg.PeerChange`. Arrives as `PeersChangedPatch` in a map response.
///
/// Each field has its own unchanged sentinel (notes §4.3, item 5).
/// - `derpRegion`, `cap`: 0 leaves the value unchanged.
/// - Other fields: `nil` (missing key or `null`) leaves the value unchanged. A present value replaces it. An empty `endpoints`
///   therefore clears all candidate addresses, an empty `capMap` clears all capabilities, and `online == false` means offline.
/// - Go's zero time (`0001-01-01T00:00:00Z`) in `keyExpiry` changes the field to no expiration. The field preserves
///   zero time as is because `nil` means unchanged.
/// - `nil` in `lastSeen` leaves it unchanged. Clearing it arrives as false in `PeerSeenChange` in a map response.
///
/// `docs/protocol-notes/control-map.md` §3.6, §4.3 (origin: `PeerChange` in tailscale.com `tailcfg/tailcfg.go`).
public struct PeerChange: Decodable, Sendable, Equatable {
    /// The ID of the peer to update. An unknown ID discards this delta.
    public internal(set) var nodeID: Int64
    /// The new home DERP region. 0 leaves it unchanged.
    public internal(set) var derpRegion: Int64
    /// The new capability version. 0 leaves it unchanged.
    public internal(set) var cap: Int
    /// The entire new set of node capabilities. `nil` leaves it unchanged.
    public internal(set) var capMap: [String: [JSONValue]]?
    /// The entire new set of candidate UDP addresses. `nil` leaves it unchanged.
    public internal(set) var endpoints: [IPEndpoint]?
    /// The new WireGuard public key. `nil` leaves it unchanged.
    public internal(set) var key: NodePublicKey?
    /// The new tailnet lock signature. `nil` leaves it unchanged.
    public internal(set) var keySignature: [UInt8]?
    /// The new disco public key. `nil` leaves it unchanged.
    public internal(set) var discoKey: DiscoPublicKey?
    /// The new online status. `nil` leaves it unchanged.
    public internal(set) var online: Bool?
    /// The new last-online timestamp. `nil` leaves it unchanged.
    public internal(set) var lastSeen: Date?
    /// The new key expiration time. `nil` leaves it unchanged, and Go's zero time means no expiration.
    public internal(set) var keyExpiry: Date?

    private enum CodingKeys: String, CodingKey {
        case nodeID = "NodeID"
        case derpRegion = "DERPRegion"
        case cap = "Cap"
        case capMap = "CapMap"
        case endpoints = "Endpoints"
        case key = "Key"
        case keySignature = "KeySignature"
        case discoKey = "DiscoKey"
        case online = "Online"
        case lastSeen = "LastSeen"
        case keyExpiry = "KeyExpiry"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        nodeID = try container.decodeIfPresent(Int64.self, forKey: .nodeID) ?? 0
        derpRegion = try container.decodeIfPresent(Int64.self, forKey: .derpRegion) ?? 0
        cap = try container.decodeIfPresent(Int.self, forKey: .cap) ?? 0
        capMap = try container.decodeCapMapIfPresent(forKey: .capMap)
        endpoints = try container.decodeIfPresent([IPEndpoint].self, forKey: .endpoints)
        key = try container.decodeIfPresent(NodePublicKey.self, forKey: .key)
        keySignature = try container.decodeBytesIfPresent(forKey: .keySignature)
        discoKey = try container.decodeIfPresent(DiscoPublicKey.self, forKey: .discoKey)
        online = try container.decodeIfPresent(Bool.self, forKey: .online)
        lastSeen = try container.decodeTimeIfPresent(forKey: .lastSeen)
        keyExpiry = try container.decodeTimeIfPresent(forKey: .keyExpiry)
    }
}
