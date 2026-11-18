import SwiftailBase

/// The tailnet DNS configuration. Go `tailcfg.DNSConfig`. Arrives as `DNSConfig` in map responses, replacing the entire configuration each time.
///
/// Used by the MagicDNS responder and iOS tunnel DNS configuration (M5). Omits exit node fields and pre-v14 `Nameservers`.
/// `docs/protocol-notes/control-map.md` §3.7 (origin: `DNSConfig` in tailscale.com `tailcfg/tailcfg.go`).
public struct DNSConfig: Decodable, Sendable, Equatable {
    /// The default DNS resolvers, in priority order.
    public internal(set) var resolvers: [DNSResolver]
    /// Split DNS: suffix (without a leading dot) → resolvers for that name. An empty array selects the built-in resolver.
    public internal(set) var routes: [String: [DNSResolver]]
    /// The resolvers for names outside split DNS when there is no default resolver.
    public internal(set) var fallbackResolvers: [DNSResolver]
    /// Search domains without trailing dots.
    public internal(set) var domains: [String]
    /// Whether MagicDNS is enabled (the built-in resolver answers for node names in the netmap).
    public internal(set) var proxied: Bool
    /// Names eligible for ts.net certificates.
    public internal(set) var certDomains: [String]
    /// Additional records the built-in resolver answers for.
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
        // A null value represents a Go nil slice and has the same meaning as an empty array.
        routes = try container.decodeIfPresent([String: [DNSResolver]?].self, forKey: .routes)?.mapValues { $0 ?? [] } ?? [:]
        fallbackResolvers = try container.decodeIfPresent([DNSResolver].self, forKey: .fallbackResolvers) ?? []
        domains = try container.decodeIfPresent([String].self, forKey: .domains) ?? []
        proxied = try container.decodeIfPresent(Bool.self, forKey: .proxied) ?? false
        certDomains = try container.decodeIfPresent([String].self, forKey: .certDomains) ?? []
        extraRecords = try container.decodeIfPresent([DNSRecord].self, forKey: .extraRecords) ?? []
    }
}

/// One DNS resolver. Go `dnstype.Resolver`.
public struct DNSResolver: Decodable, Sendable, Equatable {
    /// A resolver address, either an IP (port 53), a test IP:port, a DoH URL, or an HTTP URL over WireGuard.
    public internal(set) var addr: String
    /// The addresses of the name in `addr`, when it is a name. Used to reach the resolver without DNS.
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

/// A record the built-in resolver answers for. Go `tailcfg.DNSRecord`.
public struct DNSRecord: Decodable, Sendable, Equatable {
    /// The name (an FQDN with or without a trailing dot).
    public internal(set) var name: String
    /// The record type. An empty string means A or AAAA depending on the address family of `value`. Go also ignores records with a nonempty type.
    public internal(set) var type: String
    /// The record value. For A and AAAA, this is an IP address string.
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
