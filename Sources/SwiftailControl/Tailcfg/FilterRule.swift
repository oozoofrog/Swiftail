import SwiftailBase

/// One inbound packet filter rule. Go `tailcfg.FilterRule`.
///
/// Arrives in `PacketFilter` or `PacketFilters` in a map response. The rules form a union of permissions, and packets that match no rule
/// are dropped. An empty list therefore blocks everything. The data plane (M5) interprets and enforces the rules.
/// This layer preserves the server's representations as sent (such as `"*"`, CIDR, ranges, and `"cap:"` in `srcIPs`).
///
/// `dstPorts` allows network access, and `capGrant` provides application capabilities returned by WhoIs. A rule never contains
/// both.
/// `docs/protocol-notes/control-map.md` §4.3 (origin: `FilterRule` in tailscale.com `tailcfg/tailcfg.go`).
public struct FilterRule: Decodable, Sendable, Equatable {
    /// Source expressions, each an IP, CIDR, `"a-b"` range, `"*"`, or `"cap:…"`.
    public internal(set) var srcIPs: [String]
    /// Legacy prefix lengths for the IPs at the corresponding positions in `srcIPs`.
    public internal(set) var srcBits: [Int]
    /// The allowed destinations and port ranges.
    public internal(set) var dstPorts: [NetPortRange]
    /// The allowed IP protocol numbers. An empty list means TCP, UDP, and ICMP (IPv4 and IPv6).
    public internal(set) var ipProto: [Int]
    /// The application capabilities granted to the source.
    public internal(set) var capGrant: [CapGrant]

    private enum CodingKeys: String, CodingKey {
        case srcIPs = "SrcIPs"
        case srcBits = "SrcBits"
        case dstPorts = "DstPorts"
        case ipProto = "IPProto"
        case capGrant = "CapGrant"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        srcIPs = try container.decodeIfPresent([String].self, forKey: .srcIPs) ?? []
        srcBits = try container.decodeIfPresent([Int].self, forKey: .srcBits) ?? []
        dstPorts = try container.decodeIfPresent([NetPortRange].self, forKey: .dstPorts) ?? []
        ipProto = try container.decodeIfPresent([Int].self, forKey: .ipProto) ?? []
        capGrant = try container.decodeIfPresent([CapGrant].self, forKey: .capGrant) ?? []
    }
}

/// A destination address expression and port range. Go `tailcfg.NetPortRange`.
public struct NetPortRange: Decodable, Sendable, Equatable {
    /// The destination expression, in the same format as `FilterRule.srcIPs`.
    public internal(set) var ip: String
    /// The legacy prefix length to apply to `ip`, or `nil` if absent.
    public internal(set) var bits: Int?
    /// The allowed port range.
    public internal(set) var ports: PortRange

    private enum CodingKeys: String, CodingKey {
        case ip = "IP"
        case bits = "Bits"
        case ports = "Ports"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        ip = try container.decodeIfPresent(String.self, forKey: .ip) ?? ""
        bits = try container.decodeIfPresent(Int.self, forKey: .bits)
        ports = try container.decodeIfPresent(PortRange.self, forKey: .ports) ?? PortRange(first: 0, last: 0)
    }
}

/// An inclusive port range. Go `tailcfg.PortRange`.
///
/// Go allows `first > last` (a range that matches no port), which is why this type avoids `ClosedRange<UInt16>`.
/// Preserves such a range as received to avoid rejecting an entire map response for a single rule.
public struct PortRange: Decodable, Sendable, Equatable {
    public internal(set) var first: UInt16
    public internal(set) var last: UInt16

    init(first: UInt16, last: UInt16) {
        self.first = first
        self.last = last
    }

    private enum CodingKeys: String, CodingKey {
        case first = "First"
        case last = "Last"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        first = try container.decodeIfPresent(UInt16.self, forKey: .first) ?? 0
        last = try container.decodeIfPresent(UInt16.self, forKey: .last) ?? 0
    }
}

/// Application capabilities granted to the source. Go `tailcfg.CapGrant`.
public struct CapGrant: Decodable, Sendable, Equatable {
    /// The destination prefixes to which the grant applies.
    public internal(set) var dsts: [IPPrefix]
    /// The legacy list of capability names.
    public internal(set) var caps: [String]
    /// Capability name → arguments.
    public internal(set) var capMap: [String: [JSONValue]]

    private enum CodingKeys: String, CodingKey {
        case dsts = "Dsts"
        case caps = "Caps"
        case capMap = "CapMap"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        dsts = try container.decodeIfPresent([IPPrefix].self, forKey: .dsts) ?? []
        caps = try container.decodeIfPresent([String].self, forKey: .caps) ?? []
        capMap = try container.decodeCapMapIfPresent(forKey: .capMap) ?? [:]
    }
}
