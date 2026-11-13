/// 노드가 제어 서버에 알리는 자기 정보. Go `tailcfg.Hostinfo`.
///
/// 등록 요청과 맵 요청에 실려 가고, 다른 노드의 것은 맵 응답의 `Node.Hostinfo`로 온다.
/// testcontrol은 `Hostname`을 노드 이름으로 쓰고, Go 클라이언트는 빈 `BackendLogID`를 보내지 않는다.
/// 모든 필드가 `omitzero`이므로 비어 있으면 JSON에서 빠진다.
///
/// Swiftail이 쓰는 필드만 둔다. 서브넷 경로, 태그 요청, 서비스 광고처럼 범위 밖 기능의 필드는 없다.
/// `docs/protocol-notes/control-map.md` 3.3 (출처: tailscale.com `tailcfg/tailcfg.go` `Hostinfo`).
public struct Hostinfo: Codable, Sendable, Equatable {
    /// 클라이언트 구현의 버전 문자열.
    public var ipnVersion: String
    /// 앞단(UI) 로그 ID. 없으면 빈 문자열.
    public var frontendLogID: String
    /// 노드의 로그 ID. 비밀이 아닌 식별자이고 비어 있으면 안 된다.
    public var backendLogID: String
    /// 운영 체제 이름(`"iOS"`, `"macOS"` 등).
    public var os: String
    /// 운영 체제 버전.
    public var osVersion: String
    /// 기기 이름. testcontrol은 이것으로 노드 이름을 짓는다.
    public var hostname: String
    /// 노드를 품은 앱의 구분 이름(tsnet 앱 등).
    public var app: String
    /// 사용자 공간 네트워크 스택으로 도는지. `nil`은 알리지 않음.
    public var userspace: Bool?
    /// 서브넷 라우터가 사용자 공간으로 도는지. `nil`은 알리지 않음.
    public var userspaceRouter: Bool?
    /// 네트워크 상태(UDP 동작, 홈 DERP 등). 아직 모르면 `nil`.
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
