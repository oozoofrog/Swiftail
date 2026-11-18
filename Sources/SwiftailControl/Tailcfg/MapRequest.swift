import SwiftailBase

/// The body of `POST /machine/map`. Go `tailcfg.MapRequest`.
///
/// Has two uses (notes §4.2).
/// - Map stream: `stream = true`, `keepAlive = true`. The response is a sequence of map frames. When the request's capability version is 68 or later,
///   the server should treat the request as read-only and ignore state fields (`hostinfo`, `endpoints`, and others).
/// - State update (lite): `stream = false`, `omitPeers = true`. Reports `hostinfo`, `discoKey`, and `endpoints`
///   without closing the open stream.
///
/// Leaves `compress` empty to request uncompressed frames. See "Framing and Delta Application" in `docs/contracts/SwiftailControl.md` for the absence of a zstd decoder.
/// Map session resumption (`MapSessionHandle` and `MapSessionSeq`) is unused. The Go client also leaves it unused.
/// `docs/protocol-notes/control-map.md` §3.4, §3.5 (origin: `MapRequest` in tailscale.com `tailcfg/tailcfg.go`).
public struct MapRequest: Encodable, Sendable, Equatable {
    /// The level of protocol semantics the client understands (capability version).
    public var version: Int
    /// Response compression. An empty string means uncompressed.
    public var compress: String
    /// Requests periodic keepalive responses from the server.
    public var keepAlive: Bool
    /// The current registered node key.
    public var nodeKey: NodePublicKey
    /// The current disco key.
    public var discoKey: DiscoPublicKey
    /// Whether to finish after one response (`false`) or continue receiving a stream (`true`).
    public var stream: Bool
    /// Node information, or `null` if absent.
    public var hostinfo: Hostinfo?
    /// Candidate UDP addresses for receiving direct connections.
    public var endpoints: [IPEndpoint]
    /// How each address was discovered, in the same order as `endpoints`.
    public var endpointTypes: [EndpointType]
    /// Allows the response to omit the peer list. Used for state update requests.
    public var omitPeers: Bool
    /// The head of the local tailnet lock signing authority state (base32). When no state exists, it is an empty string and omitted from JSON
    /// (`docs/protocol-notes/tailnet-lock.md` §3.9).
    public var tkaHead: String

    public init(
        version: Int = 148,
        compress: String = "",
        keepAlive: Bool = false,
        nodeKey: NodePublicKey,
        discoKey: DiscoPublicKey,
        stream: Bool = false,
        hostinfo: Hostinfo?,
        endpoints: [IPEndpoint] = [],
        endpointTypes: [EndpointType] = [],
        omitPeers: Bool = false,
        tkaHead: String = ""
    ) {
        self.version = version
        self.compress = compress
        self.keepAlive = keepAlive
        self.nodeKey = nodeKey
        self.discoKey = discoKey
        self.stream = stream
        self.hostinfo = hostinfo
        self.endpoints = endpoints
        self.endpointTypes = endpointTypes
        self.omitPeers = omitPeers
        self.tkaHead = tkaHead
    }

    private enum CodingKeys: String, CodingKey {
        case version = "Version"
        case compress = "Compress"
        case keepAlive = "KeepAlive"
        case nodeKey = "NodeKey"
        case discoKey = "DiscoKey"
        case stream = "Stream"
        case hostinfo = "Hostinfo"
        case endpoints = "Endpoints"
        case endpointTypes = "EndpointTypes"
        case omitPeers = "OmitPeers"
        case tkaHead = "TKAHead"
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encodeUnlessEmpty(compress, forKey: .compress)
        try container.encodeUnlessEmpty(keepAlive, forKey: .keepAlive)
        try container.encode(nodeKey, forKey: .nodeKey)
        try container.encode(discoKey, forKey: .discoKey)
        try container.encodeUnlessEmpty(stream, forKey: .stream)
        try container.encode(hostinfo, forKey: .hostinfo)
        try container.encodeUnlessEmpty(endpoints, forKey: .endpoints)
        try container.encodeUnlessEmpty(endpointTypes, forKey: .endpointTypes)
        try container.encodeUnlessEmpty(omitPeers, forKey: .omitPeers)
        try container.encodeUnlessEmpty(tkaHead, forKey: .tkaHead)
    }
}

/// The origin of a candidate UDP address. Go `tailcfg.EndpointType`.
public enum EndpointType: Int, Encodable, Sendable {
    case unknown = 0
    /// The address of a local interface.
    case local = 1
    /// A public address discovered by STUN.
    case stun = 2
    /// An address opened by port mapping (such as UPnP).
    case portmapped = 3
    /// A guess combining the public IP discovered by STUN with the local port.
    case stun4LocalPort = 4
    /// An address specified in configuration.
    case explicitConfiguration = 5
}
