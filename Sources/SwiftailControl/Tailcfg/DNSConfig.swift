import SwiftailBase

/// tailnet의 DNS 설정. Go `tailcfg.DNSConfig`. 맵 응답의 `DNSConfig`로 오고, 올 때마다 전체가 바뀐다.
///
/// MagicDNS 응답기와 iOS 터널의 DNS 설정(M5)이 쓴다. 출구 노드용 필드와 v14 이전의 `Nameservers`는 없다.
/// `docs/protocol-notes/control-map.md` 3.7 (출처: tailscale.com `tailcfg/tailcfg.go` `DNSConfig`).
public struct DNSConfig: Decodable, Sendable, Equatable {
    /// 기본 DNS 해석기. 앞의 것이 우선이다.
    public internal(set) var resolvers: [DNSResolver]
    /// 분할 DNS: 접미(앞 점 없음) → 그 이름을 맡을 해석기. 빈 배열은 내장 해석기가 맡는다는 뜻이다.
    public internal(set) var routes: [String: [DNSResolver]]
    /// 기본 해석기가 없을 때 분할 DNS 밖의 이름을 맡을 해석기.
    public internal(set) var fallbackResolvers: [DNSResolver]
    /// 검색 도메인(끝 점 없음).
    public internal(set) var domains: [String]
    /// MagicDNS가 켜져 있다(netmap의 노드 이름을 내장 해석기가 답한다).
    public internal(set) var proxied: Bool
    /// ts.net 인증서를 받을 수 있는 이름.
    public internal(set) var certDomains: [String]
    /// 내장 해석기가 답할 추가 레코드.
    public internal(set) var extraRecords: [DNSRecord]

    private enum CodingKeys: String, CodingKey {
        case resolvers = "Resolvers"
        case routes = "Routes"
        case fallbackResolvers = "FallbackResolvers"
        case domains = "Domains"
        case proxied = "Proxied"
        case certDomains = "CertDomains"
        case extraRecords = "ExtraRecords"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        resolvers = try container.decodeIfPresent([DNSResolver].self, forKey: .resolvers) ?? []
        // 값이 null이면 Go의 nil 슬라이스이고, 빈 배열과 같은 뜻이다.
        routes = try container.decodeIfPresent([String: [DNSResolver]?].self, forKey: .routes)?.mapValues { $0 ?? [] } ?? [:]
        fallbackResolvers = try container.decodeIfPresent([DNSResolver].self, forKey: .fallbackResolvers) ?? []
        domains = try container.decodeIfPresent([String].self, forKey: .domains) ?? []
        proxied = try container.decodeIfPresent(Bool.self, forKey: .proxied) ?? false
        certDomains = try container.decodeIfPresent([String].self, forKey: .certDomains) ?? []
        extraRecords = try container.decodeIfPresent([DNSRecord].self, forKey: .extraRecords) ?? []
    }
}

/// DNS 해석기 하나. Go `dnstype.Resolver`.
public struct DNSResolver: Decodable, Sendable, Equatable {
    /// 해석기 주소: IP(포트 53), 시험용 IP:포트, DoH URL, WireGuard 위 HTTP URL 가운데 하나.
    public internal(set) var addr: String
    /// `addr`가 이름일 때 그 이름의 주소. DNS 없이 해석기에 닿기 위해 쓴다.
    public internal(set) var bootstrapResolution: [IPAddress]

    private enum CodingKeys: String, CodingKey {
        case addr = "Addr"
        case bootstrapResolution = "BootstrapResolution"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        addr = try container.decodeIfPresent(String.self, forKey: .addr) ?? ""
        bootstrapResolution = try container.decodeIfPresent([IPAddress].self, forKey: .bootstrapResolution) ?? []
    }
}

/// 내장 해석기가 답할 레코드 하나. Go `tailcfg.DNSRecord`.
public struct DNSRecord: Decodable, Sendable, Equatable {
    /// 이름(FQDN, 끝 점은 있어도 없어도 된다).
    public internal(set) var name: String
    /// 레코드 종류. 빈 문자열이면 `value`의 주소 종류에 따라 A 또는 AAAA다. 다른 값은 Go도 무시한다.
    public internal(set) var type: String
    /// 레코드 값. A·AAAA에서는 IP 주소 문자열이다.
    public internal(set) var value: String

    private enum CodingKeys: String, CodingKey {
        case name = "Name"
        case type = "Type"
        case value = "Value"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        name = try container.decodeIfPresent(String.self, forKey: .name) ?? ""
        type = try container.decodeIfPresent(String.self, forKey: .type) ?? ""
        value = try container.decodeIfPresent(String.self, forKey: .value) ?? ""
    }
}
