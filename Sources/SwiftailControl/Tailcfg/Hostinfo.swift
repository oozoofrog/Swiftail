/// Information a node reports about itself to the control server. Go `tailcfg.Hostinfo`.
///
/// Sent in registration and map requests. Information about other nodes arrives as `Node.Hostinfo` in map responses.
/// testcontrol uses `Hostname` for the node name. The Go client omits an empty `BackendLogID`.
/// The fields represented here use Go's `omitzero` semantics. Empty strings and absent optional values are omitted from JSON.
///
/// Includes only fields Swiftail uses. Omits fields for features outside scope, such as subnet routes, tag requests, and service advertisements.
/// `docs/protocol-notes/control-map.md` §3.3 (origin: `Hostinfo` in tailscale.com `tailcfg/tailcfg.go`).
public struct Hostinfo: Codable, Sendable, Equatable {
    /// The version string of the client implementation.
    public var ipnVersion: String
    /// The frontend (UI) log ID. An empty string means absent.
    public var frontendLogID: String
    /// The node's log ID. A nonsecret identifier that must be nonempty.
    public var backendLogID: String
    /// The OS name (such as `"iOS"` or `"macOS"`).
    public var os: String
    /// The OS version.
    public var osVersion: String
    /// The device name. testcontrol uses it to name the node.
    public var hostname: String
    /// A name identifying the app that embeds the node (such as a tsnet app).
    public var app: String
    /// Whether this runs with a userspace network stack. `nil` leaves it unreported.
    public var userspace: Bool?
    /// Whether the subnet router runs in userspace. `nil` leaves it unreported.
    public var userspaceRouter: Bool?
    /// Network state (UDP behavior, home DERP, and so on). `nil` if still unknown.
    public var netInfo: NetInfo?

    public init(
        ipnVersion: String = "",
        frontendLogID: String = "",
        backendLogID: String = "",
        os: String = "",
        osVersion: String = "",
        hostname: String = "",
        app: String = "",
        userspace: Bool? = nil,
        userspaceRouter: Bool? = nil,
        netInfo: NetInfo? = nil
    ) {
        self.ipnVersion = ipnVersion
        self.frontendLogID = frontendLogID
        self.backendLogID = backendLogID
        self.os = os
        self.osVersion = osVersion
        self.hostname = hostname
        self.app = app
        self.userspace = userspace
        self.userspaceRouter = userspaceRouter
        self.netInfo = netInfo
    }

    private enum CodingKeys: String, CodingKey {
        case ipnVersion = "IPNVersion"
        case frontendLogID = "FrontendLogID"
        case backendLogID = "BackendLogID"
        case os = "OS"
        case osVersion = "OSVersion"
        case hostname = "Hostname"
        case app = "App"
        case userspace = "Userspace"
        case userspaceRouter = "UserspaceRouter"
        case netInfo = "NetInfo"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        ipnVersion = try container.decodeIfPresent(String.self, forKey: .ipnVersion) ?? ""
        frontendLogID = try container.decodeIfPresent(String.self, forKey: .frontendLogID) ?? ""
        backendLogID = try container.decodeIfPresent(String.self, forKey: .backendLogID) ?? ""
        os = try container.decodeIfPresent(String.self, forKey: .os) ?? ""
        osVersion = try container.decodeIfPresent(String.self, forKey: .osVersion) ?? ""
        hostname = try container.decodeIfPresent(String.self, forKey: .hostname) ?? ""
        app = try container.decodeIfPresent(String.self, forKey: .app) ?? ""
        userspace = try container.decodeIfPresent(Bool.self, forKey: .userspace)
        userspaceRouter = try container.decodeIfPresent(Bool.self, forKey: .userspaceRouter)
        netInfo = try container.decodeIfPresent(NetInfo.self, forKey: .netInfo)
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeUnlessEmpty(ipnVersion, forKey: .ipnVersion)
        try container.encodeUnlessEmpty(frontendLogID, forKey: .frontendLogID)
        try container.encodeUnlessEmpty(backendLogID, forKey: .backendLogID)
        try container.encodeUnlessEmpty(os, forKey: .os)
        try container.encodeUnlessEmpty(osVersion, forKey: .osVersion)
        try container.encodeUnlessEmpty(hostname, forKey: .hostname)
        try container.encodeUnlessEmpty(app, forKey: .app)
        try container.encodeIfPresent(userspace, forKey: .userspace)
        try container.encodeIfPresent(userspaceRouter, forKey: .userspaceRouter)
        try container.encodeIfPresent(netInfo, forKey: .netInfo)
    }
}
