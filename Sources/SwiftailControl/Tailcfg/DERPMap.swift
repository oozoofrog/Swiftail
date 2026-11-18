/// A map of DERP relay servers. Go `tailcfg.DERPMap`. Arrives as `DERPMap` in a map response.
///
/// Deltas can leave each subfield unchanged (notes §4.3, item 8, applied by `MapSession`).
/// - `regions`: `nil` (missing key or `null`) keeps the previous region list and `omitDefaultRegions`.
///   An empty object means no regions. Decoding discards regions with `null` values, as the Go client does.
/// - `homeParams`: `nil` keeps the previous value.
///
/// `docs/protocol-notes/control-map.md` §3.7 (origin: tailscale.com `tailcfg/derpmap.go`).
public struct DERPMap: Decodable, Sendable, Equatable {
    /// Weights for choosing the home region. `nil` keeps the previous value.
    public internal(set) var homeParams: DERPHomeParams?
    /// Region ID → region. `nil` keeps the previous value.
    public internal(set) var regions: [Int64: DERPRegion]?
    /// The client must omit built-in default regions. Only meaningful when `regions` is present.
    public internal(set) var omitDefaultRegions: Bool

    private enum CodingKeys: String, CodingKey {
        case homeParams = "HomeParams"
        case regions = "Regions"
        case omitDefaultRegions = "omitDefaultRegions"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        homeParams = try container.decodeIfPresent(DERPHomeParams.self, forKey: .homeParams)
        regions = try container.decodeIntegerKeyedIfPresent(DERPRegion?.self, forKey: .regions)?.compactMapValues { $0 }
        omitDefaultRegions = try container.decodeIfPresent(Bool.self, forKey: .omitDefaultRegions) ?? false
    }
}

/// Weights for choosing a home DERP region. Go `tailcfg.DERPHomeParams`.
public struct DERPHomeParams: Decodable, Sendable, Equatable {
    /// Region ID → latency multiplier. Missing regions use 1.0. Values at or below 0 are ignored.
    /// `nil` keeps the previous scores. An empty object clears all scores.
    public internal(set) var regionScore: [Int64: Double]?

    private enum CodingKeys: String, CodingKey {
        case regionScore = "RegionScore"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        regionScore = try container.decodeIntegerKeyedIfPresent(Double.self, forKey: .regionScore)
    }
}

/// One DERP region. Servers in the same region share relay duties. Go `tailcfg.DERPRegion`.
public struct DERPRegion: Decodable, Sendable, Equatable {
    /// The region ID, matching the key in `DERPMap.regions`.
    public internal(set) var regionID: Int64
    /// A short region code (`"nyc"`).
    public internal(set) var regionCode: String
    /// The human-readable region name.
    public internal(set) var regionName: String
    /// Skips measurements and home selection for this region. Still connects if it is a peer's home region.
    public internal(set) var noMeasureNoHome: Bool
    /// Servers in the region, used in list order.
    public internal(set) var nodes: [DERPNode]

    private enum CodingKeys: String, CodingKey {
        case regionID = "RegionID"
        case regionCode = "RegionCode"
        case regionName = "RegionName"
        case noMeasureNoHome = "NoMeasureNoHome"
        case nodes = "Nodes"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        regionID = try container.decodeIfPresent(Int64.self, forKey: .regionID) ?? 0
        regionCode = try container.decodeIfPresent(String.self, forKey: .regionCode) ?? ""
        regionName = try container.decodeIfPresent(String.self, forKey: .regionName) ?? ""
        noMeasureNoHome = try container.decodeIfPresent(Bool.self, forKey: .noMeasureNoHome) ?? false
        nodes = try container.decodeIfPresent([DERPNode].self, forKey: .nodes) ?? []
    }
}

/// One DERP server (or STUN server). Go `tailcfg.DERPNode`.
public struct DERPNode: Decodable, Sendable, Equatable {
    /// The server name, unique within the region.
    public internal(set) var name: String
    /// The ID of the containing region.
    public internal(set) var regionID: Int64
    /// The hostname to connect to.
    public internal(set) var hostName: String
    /// The name to verify in the TLS certificate. Uses `hostName` if empty. A `"sha256-raw:"` prefix pins the certificate hash.
    public internal(set) var certName: String
    /// An overridden IPv4 address. An empty string uses DNS, and `"none"` disables IPv4.
    public internal(set) var ipv4: String
    /// An overridden IPv6 address. Follows the same rules as `ipv4`.
    public internal(set) var ipv6: String
    /// The STUN port. 0 means 3478, and −1 disables STUN.
    public internal(set) var stunPort: Int
    /// A STUN-only server (no DERP).
    public internal(set) var stunOnly: Bool
    /// The DERP HTTPS port. 0 means 443.
    public internal(set) var derpPort: Int
    /// For tests, skips TLS certificate validation.
    public internal(set) var insecureForTests: Bool
    /// A STUN address for tests.
    public internal(set) var stunTestIP: String
    /// Whether port 80 can be used to check for a captive portal.
    public internal(set) var canPort80: Bool

    private enum CodingKeys: String, CodingKey {
        case name = "Name"
        case regionID = "RegionID"
        case hostName = "HostName"
        case certName = "CertName"
        case ipv4 = "IPv4"
        case ipv6 = "IPv6"
        case stunPort = "STUNPort"
        case stunOnly = "STUNOnly"
        case derpPort = "DERPPort"
        case insecureForTests = "InsecureForTests"
        case stunTestIP = "STUNTestIP"
        case canPort80 = "CanPort80"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        name = try container.decodeIfPresent(String.self, forKey: .name) ?? ""
        regionID = try container.decodeIfPresent(Int64.self, forKey: .regionID) ?? 0
        hostName = try container.decodeIfPresent(String.self, forKey: .hostName) ?? ""
        certName = try container.decodeIfPresent(String.self, forKey: .certName) ?? ""
        ipv4 = try container.decodeIfPresent(String.self, forKey: .ipv4) ?? ""
        ipv6 = try container.decodeIfPresent(String.self, forKey: .ipv6) ?? ""
        stunPort = try container.decodeIfPresent(Int.self, forKey: .stunPort) ?? 0
        stunOnly = try container.decodeIfPresent(Bool.self, forKey: .stunOnly) ?? false
        derpPort = try container.decodeIfPresent(Int.self, forKey: .derpPort) ?? 0
        insecureForTests = try container.decodeIfPresent(Bool.self, forKey: .insecureForTests) ?? false
        stunTestIP = try container.decodeIfPresent(String.self, forKey: .stunTestIP) ?? ""
        canPort80 = try container.decodeIfPresent(Bool.self, forKey: .canPort80) ?? false
    }
}
