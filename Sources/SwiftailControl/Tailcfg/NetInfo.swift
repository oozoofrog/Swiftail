/// 노드가 측정한 네트워크 상태. Go `tailcfg.NetInfo`.
///
/// `Hostinfo.NetInfo`에 실려 제어 서버로 간다. 서버는 0이 아닌 `PreferredDERP`로 다른 노드에게
/// 이 노드의 홈 DERP를 알린다. DERP·STUN 측정(M4) 전에는 `Hostinfo.netInfo`를 `nil`로 둔다.
///
/// `Bool?` 필드는 Go `opt.Bool`이다: JSON의 `true`·`false`가 측정 결과이고, `nil`(생략·`null`)은
/// 측정하지 않음이다. 문자열 `"true"`는 오류다. 모든 필드가 `omitzero`·`omitempty`다.
/// `docs/protocol-notes/control-map.md` 3.1, 3.3 (출처: tailscale.com `tailcfg/tailcfg.go` `NetInfo`).
public struct NetInfo: Codable, Sendable, Equatable {
    /// 목적지 IP마다 NAT 매핑이 달라지는지(대칭 NAT).
    public var mappingVariesByDestIP: Bool?
    /// 인터넷으로 IPv6가 되는지.
    public var workingIPv6: Bool?
    /// 운영 체제가 IPv6를 지원하는지.
    public var osHasIPv6: Bool?
    /// 인터넷으로 UDP가 되는지.
    public var workingUDP: Bool?
    /// 인터넷으로 ICMPv4가 되는지.
    public var workingICMPv4: Bool?
    /// UPnP·NAT-PMP·PCP 포트 매핑이 열려 있는지.
    public var havePortMap: Bool
    /// LAN에 UPnP가 있는지.
    public var upnp: Bool?
    /// LAN에 NAT-PMP가 있는지.
    public var pmp: Bool?
    /// LAN에 PCP가 있는지.
    public var pcp: Bool?
    /// 이 노드가 받는 홈 DERP 지역. 0은 아직 정하지 않음.
    public var preferredDERP: Int64
    /// 연결 종류(`"wired"`, `"wifi"`, `"mobile"`). 모르면 빈 문자열.
    public var linkType: String
    /// `"<지역ID>-v4"`·`"<지역ID>-v6"` → 그 DERP 지역까지의 최근 최저 지연(초).
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
