import Foundation

/// 맵 스트림의 프레임 하나에 든 응답. Go `tailcfg.MapResponse`.
///
/// 스트림의 첫 일반 응답은 전체 상태이고, 그 뒤는 증분이다. 증분 적용은 `MapSession`이 한다(노트 4.3).
/// 필드의 `nil`은 "키 없음 또는 `null`"이고 Go에서도 둘은 같다. 증분의 뜻은 `nil`과 빈 배열·객체가 가른다.
/// - `peers`: 비어 있지 않을 때만 전체 교체다. 빈 배열로 기존 피어를 지우지 않는다.
/// - `packetFilter`: `nil`은 그대로, 빈 배열은 이름 `base`의 규칙을 비운다.
/// - `packetFilters`: 값이 `nil`(`null`)인 이름은 지운다. `"*": null`은 모든 이름을 먼저 지운다.
///
/// Swiftail이 쓰는 필드만 둔다. SSH 정책, 상태 메시지(`Health`, `DisplayMessages`), 제어 연결 계획,
/// 클라이언트 버전 알림, `Debug`, 세션 재개(`MapSessionHandle`, `Seq`) 필드는 없다(모르는 키로 무시된다).
/// `docs/protocol-notes/control-map.md` 3.5, 3.6 (출처: tailscale.com `tailcfg/tailcfg.go` `MapResponse`).
public struct MapResponse: Decodable, Sendable, Equatable {
    /// keepalive 응답. 상태를 바꾸지 않는다. `pingRequest`와 `controlTime`만 함께 유효하다.
    public internal(set) var keepAlive: Bool
    /// 서버가 답을 요구한 핑. 이 응답 한 번의 사건이다.
    public internal(set) var pingRequest: PingRequest?
    /// 자기 노드 전체. `nil`이면 그대로. 스트림의 첫 일반 응답에는 반드시 있다.
    public internal(set) var node: Node?
    /// DERP 지도. `nil`이면 그대로. 하위 필드의 "그대로"는 `DERPMap`을 본다.
    public internal(set) var derpMap: DERPMap?
    /// 피어 전체 목록. 비어 있지 않으면 피어 저장소를 이것으로 바꾸고 이 응답의 다른 피어 증분은 버린다.
    public internal(set) var peers: [Node]?
    /// 더하거나 통째로 바꿀 피어.
    public internal(set) var peersChanged: [Node]?
    /// 지울 피어 ID.
    public internal(set) var peersRemoved: [Int64]?
    /// 아는 피어의 일부 필드 변경.
    public internal(set) var peersChangedPatch: [PeerChange]?
    /// 피어 ID → `true`면 지금 보였음, `false`면 마지막 온라인 시각을 지움.
    public internal(set) var peerSeenChange: [Int64: Bool]?
    /// 피어 ID → 온라인 여부.
    public internal(set) var onlineChange: [Int64: Bool]?
    /// DNS 설정 전체. `nil`이면 그대로.
    public internal(set) var dnsConfig: DNSConfig?
    /// tailnet 이름. 빈 문자열이면 그대로.
    public internal(set) var domain: String
    /// 이름 `base`의 패킷 필터 규칙. `nil`이면 그대로.
    public internal(set) var packetFilter: [FilterRule]?
    /// 이름 붙은 패킷 필터 규칙의 증분. 값이 `nil`인 이름은 지운다.
    public internal(set) var packetFilters: [String: [FilterRule]?]?
    /// 더하거나 바꿀 사용자 프로필.
    public internal(set) var userProfiles: [UserProfile]?
    /// 서버의 지금 시각. 없거나 Go의 0 시각이면 `nil`.
    public internal(set) var controlTime: Date?
    /// tailnet lock 상태. `nil`이면 그대로.
    public internal(set) var tkaInfo: TKAInfo?

    private enum CodingKeys: String, CodingKey {
        case keepAlive = "KeepAlive"
        case pingRequest = "PingRequest"
        case node = "Node"
        case derpMap = "DERPMap"
        case peers = "Peers"
        case peersChanged = "PeersChanged"
        case peersRemoved = "PeersRemoved"
        case peersChangedPatch = "PeersChangedPatch"
        case peerSeenChange = "PeerSeenChange"
        case onlineChange = "OnlineChange"
        case dnsConfig = "DNSConfig"
        case domain = "Domain"
        case packetFilter = "PacketFilter"
        case packetFilters = "PacketFilters"
        case userProfiles = "UserProfiles"
        case controlTime = "ControlTime"
        case tkaInfo = "TKAInfo"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        keepAlive = try container.decodeIfPresent(Bool.self, forKey: .keepAlive) ?? false
        pingRequest = try container.decodeIfPresent(PingRequest.self, forKey: .pingRequest)
        node = try container.decodeIfPresent(Node.self, forKey: .node)
        derpMap = try container.decodeIfPresent(DERPMap.self, forKey: .derpMap)
        peers = try container.decodeIfPresent([Node].self, forKey: .peers)
        peersChanged = try container.decodeIfPresent([Node].self, forKey: .peersChanged)
        peersRemoved = try container.decodeIfPresent([Int64].self, forKey: .peersRemoved)
        peersChangedPatch = try container.decodeIfPresent([PeerChange].self, forKey: .peersChangedPatch)
        peerSeenChange = try container.decodeIntegerKeyedIfPresent(Bool.self, forKey: .peerSeenChange)
        onlineChange = try container.decodeIntegerKeyedIfPresent(Bool.self, forKey: .onlineChange)
        dnsConfig = try container.decodeIfPresent(DNSConfig.self, forKey: .dnsConfig)
        domain = try container.decodeIfPresent(String.self, forKey: .domain) ?? ""
        packetFilter = try container.decodeIfPresent([FilterRule].self, forKey: .packetFilter)
        packetFilters = try container.decodeIfPresent([String: [FilterRule]?].self, forKey: .packetFilters)
        userProfiles = try container.decodeIfPresent([UserProfile].self, forKey: .userProfiles)
        controlTime = try container.decodeTimeIfPresent(forKey: .controlTime).flatMap(GoTime.nonZero)
        tkaInfo = try container.decodeIfPresent(TKAInfo.self, forKey: .tkaInfo)
    }
}
