import SwiftailBase

/// `POST /machine/map`의 본문. Go `tailcfg.MapRequest`.
///
/// 두 가지로 쓴다(노트 4.2).
/// - 맵 스트림: `stream = true`, `keepAlive = true`. 응답은 맵 프레임의 연속이다. 버전 68 이상의 서버는
///   이 요청의 상태 필드(`hostinfo`, `endpoints` 등)를 무시한다.
/// - 상태 갱신(lite): `stream = false`, `omitPeers = true`. 열려 있는 스트림을 끊지 않고 `hostinfo`,
///   `discoKey`, `endpoints`를 올린다.
///
/// `compress`를 비워 비압축 프레임을 요청한다. zstd 해제기는 없다(계약 "프레이밍과 증분 적용").
/// 맵 세션 재개(`MapSessionHandle`·`MapSessionSeq`)는 쓰지 않는다. Go 클라이언트도 쓰지 않는다.
/// `docs/protocol-notes/control-map.md` 3.4, 3.5 (출처: tailscale.com `tailcfg/tailcfg.go` `MapRequest`).
public struct MapRequest: Encodable, Sendable, Equatable {
    /// 클라이언트가 이해하는 프로토콜 의미의 수준(capability version).
    public var version: Int
    /// 응답 압축. 빈 문자열은 비압축이다.
    public var compress: String
    /// 서버가 주기적으로 keepalive 응답을 보내기를 요청한다.
    public var keepAlive: Bool
    /// 등록된 지금의 노드 키.
    public var nodeKey: NodePublicKey
    /// 지금의 disco 키.
    public var discoKey: DiscoPublicKey
    /// 응답을 하나만 받고 끝낼지(`false`), 스트림으로 계속 받을지(`true`).
    public var stream: Bool
    /// 노드 정보. 없으면 `null`.
    public var hostinfo: Hostinfo?
    /// 직접 연결을 받을 UDP 후보 주소들.
    public var endpoints: [IPEndpoint]
    /// `endpoints`와 같은 순서로 각 주소를 어떻게 알았는지.
    public var endpointTypes: [EndpointType]
    /// 응답에 피어 목록이 없어도 된다. 상태 갱신 요청에 쓴다.
    public var omitPeers: Bool
    /// 로컬 tailnet lock 서명 권한 상태의 머리(base32). 상태가 없으면 빈 문자열이고 JSON에서 빠진다
    /// (`docs/protocol-notes/tailnet-lock.md` 3.9).
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

/// UDP 후보 주소의 출처. Go `tailcfg.EndpointType`.
public enum EndpointType: Int, Encodable, Sendable {
    case unknown = 0
    /// 로컬 인터페이스의 주소.
    case local = 1
    /// STUN으로 알아낸 공인 주소.
    case stun = 2
    /// 포트 매핑(UPnP 등)으로 연 주소.
    case portmapped = 3
    /// STUN으로 알아낸 공인 IP에 로컬 포트를 붙인 추측.
    case stun4LocalPort = 4
    /// 설정으로 지정한 주소.
    case explicitConfiguration = 5
}
