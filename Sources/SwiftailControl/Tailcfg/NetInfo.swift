/// Network state measured by the node. Go `tailcfg.NetInfo`.
///
/// Sent to the control server in `Hostinfo.NetInfo`. The server reports this node's home DERP to other nodes using
/// a nonzero `PreferredDERP`. Before DERP and STUN measurements (M4), `Hostinfo.netInfo` stays `nil`.
///
/// A `Bool?` field corresponds to Go `opt.Bool`. JSON `true` or `false` is the measurement result. A `nil` value (omitted or `null`)
/// means unmeasured. The string `"true"` is an error. All fields are `omitzero` or `omitempty`.
/// `docs/protocol-notes/control-map.md` §3.1, §3.3 (origin: `NetInfo` in tailscale.com `tailcfg/tailcfg.go`).
public struct NetInfo: Codable, Sendable, Equatable {
    /// Whether the NAT mapping varies with the destination IP (symmetric NAT).
    public var mappingVariesByDestIP: Bool?
    /// Whether IPv6 works over the Internet.
    public var workingIPv6: Bool?
    /// Whether the OS supports IPv6.
    public var osHasIPv6: Bool?
    /// Whether UDP works over the Internet.
    public var workingUDP: Bool?
    /// Whether ICMPv4 works over the Internet.
    public var workingICMPv4: Bool?
    /// Whether UPnP, NAT-PMP, or PCP port mapping is open.
    public var havePortMap: Bool
    /// Whether UPnP is present on the LAN.
    public var upnp: Bool?
    /// Whether NAT-PMP is present on the LAN.
    public var pmp: Bool?
    /// Whether PCP is present on the LAN.
    public var pcp: Bool?
    /// The home DERP region that serves this node. 0 means undecided.
    public var preferredDERP: Int64
    /// The connection type (`"wired"`, `"wifi"`, or `"mobile"`). An empty string means unknown.
    public var linkType: String
    /// `"<regionID>-v4"` and `"<regionID>-v6"` → recent minimum latency to that DERP region (seconds).
    public var derpLatency: [String: Double]

    public init(
        mappingVariesByDestIP: Bool? = nil,
        workingIPv6: Bool? = nil,
        osHasIPv6: Bool? = nil,
        workingUDP: Bool? = nil,
        workingICMPv4: Bool? = nil,
        havePortMap: Bool = false,
        upnp: Bool? = nil,
        pmp: Bool? = nil,
        pcp: Bool? = nil,
        preferredDERP: Int64 = 0,
        linkType: String = "",
        derpLatency: [String: Double] = [:]
    ) {
        self.mappingVariesByDestIP = mappingVariesByDestIP
        self.workingIPv6 = workingIPv6
        self.osHasIPv6 = osHasIPv6
        self.workingUDP = workingUDP
        self.workingICMPv4 = workingICMPv4
        self.havePortMap = havePortMap
        self.upnp = upnp
        self.pmp = pmp
        self.pcp = pcp
        self.preferredDERP = preferredDERP
        self.linkType = linkType
        self.derpLatency = derpLatency
    }

    private enum CodingKeys: String, CodingKey {
        case mappingVariesByDestIP = "MappingVariesByDestIP"
        case workingIPv6 = "WorkingIPv6"
        case osHasIPv6 = "OSHasIPv6"
        case workingUDP = "WorkingUDP"
        case workingICMPv4 = "WorkingICMPv4"
        case havePortMap = "HavePortMap"
        case upnp = "UPnP"
        case pmp = "PMP"
        case pcp = "PCP"
        case preferredDERP = "PreferredDERP"
        case linkType = "LinkType"
        case derpLatency = "DERPLatency"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        mappingVariesByDestIP = try container.decodeIfPresent(Bool.self, forKey: .mappingVariesByDestIP)
        workingIPv6 = try container.decodeIfPresent(Bool.self, forKey: .workingIPv6)
        osHasIPv6 = try container.decodeIfPresent(Bool.self, forKey: .osHasIPv6)
        workingUDP = try container.decodeIfPresent(Bool.self, forKey: .workingUDP)
        workingICMPv4 = try container.decodeIfPresent(Bool.self, forKey: .workingICMPv4)
        havePortMap = try container.decodeIfPresent(Bool.self, forKey: .havePortMap) ?? false
        upnp = try container.decodeIfPresent(Bool.self, forKey: .upnp)
        pmp = try container.decodeIfPresent(Bool.self, forKey: .pmp)
        pcp = try container.decodeIfPresent(Bool.self, forKey: .pcp)
        preferredDERP = try container.decodeIfPresent(Int64.self, forKey: .preferredDERP) ?? 0
        linkType = try container.decodeIfPresent(String.self, forKey: .linkType) ?? ""
        derpLatency = try container.decodeIfPresent([String: Double].self, forKey: .derpLatency) ?? [:]
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(mappingVariesByDestIP, forKey: .mappingVariesByDestIP)
        try container.encodeIfPresent(workingIPv6, forKey: .workingIPv6)
        try container.encodeIfPresent(osHasIPv6, forKey: .osHasIPv6)
        try container.encodeIfPresent(workingUDP, forKey: .workingUDP)
        try container.encodeIfPresent(workingICMPv4, forKey: .workingICMPv4)
        try container.encodeUnlessEmpty(havePortMap, forKey: .havePortMap)
        try container.encodeIfPresent(upnp, forKey: .upnp)
        try container.encodeIfPresent(pmp, forKey: .pmp)
        try container.encodeIfPresent(pcp, forKey: .pcp)
        try container.encodeUnlessEmpty(preferredDERP, forKey: .preferredDERP)
        try container.encodeUnlessEmpty(linkType, forKey: .linkType)
        try container.encodeUnlessEmpty(derpLatency, forKey: .derpLatency)
    }
}
