import Foundation
import SwiftailBase

/// 이미 아는 피어의 일부 필드만 바꾸는 증분. Go `tailcfg.PeerChange`. 맵 응답의 `PeersChangedPatch`로 온다.
///
/// 필드마다 "바꾸지 않음"이 따로 있다(노트 4.3의 5).
/// - `derpRegion`·`cap`: 0이면 그대로.
/// - 나머지: `nil`(키 없음·`null`)이면 그대로. 값이 있으면 그 값으로 바꾼다. 그래서 빈 `endpoints`는
///   "후보 주소를 모두 지움", 빈 `capMap`은 "속성을 모두 지움", `online == false`는 "오프라인"이다.
/// - `keyExpiry`에 Go의 0 시각(`0001-01-01T00:00:00Z`)이 오면 "만료 없음"으로 바꾼다. 그래서 이 필드는
///   0 시각을 `nil`로 줄이지 않고 그대로 담는다(`nil`은 "그대로"다).
/// - `lastSeen`의 `nil`은 지우기가 아니다. 지우기는 맵 응답의 `PeerSeenChange` false로 온다.
///
/// `docs/protocol-notes/control-map.md` 3.6, 4.3 (출처: tailscale.com `tailcfg/tailcfg.go` `PeerChange`).
public struct PeerChange: Decodable, Sendable, Equatable {
    /// 바꿀 피어의 ID. 모르는 ID면 이 증분은 버린다.
    public internal(set) var nodeID: Int64
    /// 새 홈 DERP 지역. 0이면 그대로.
    public internal(set) var derpRegion: Int64
    /// 새 capability version. 0이면 그대로.
    public internal(set) var cap: Int
    /// 새 노드 속성 전체. `nil`이면 그대로.
    public internal(set) var capMap: [String: [JSONValue]]?
    /// 새 UDP 후보 주소 전체. `nil`이면 그대로.
    public internal(set) var endpoints: [IPEndpoint]?
    /// 새 WireGuard 공개 키. `nil`이면 그대로.
    public internal(set) var key: NodePublicKey?
    /// 새 tailnet lock 서명. `nil`이면 그대로.
    public internal(set) var keySignature: [UInt8]?
    /// 새 disco 공개 키. `nil`이면 그대로.
    public internal(set) var discoKey: DiscoPublicKey?
    /// 새 온라인 상태. `nil`이면 그대로.
    public internal(set) var online: Bool?
    /// 새 마지막 온라인 시각. `nil`이면 그대로.
    public internal(set) var lastSeen: Date?
    /// 새 키 만료 시각. `nil`이면 그대로, Go의 0 시각이면 "만료 없음".
    public internal(set) var keyExpiry: Date?

    private enum CodingKeys: String, CodingKey {
        case nodeID = "NodeID"
        case derpRegion = "DERPRegion"
        case cap = "Cap"
        case capMap = "CapMap"
        case endpoints = "Endpoints"
        case key = "Key"
        case keySignature = "KeySignature"
        case discoKey = "DiscoKey"
        case online = "Online"
        case lastSeen = "LastSeen"
        case keyExpiry = "KeyExpiry"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        nodeID = try container.decodeIfPresent(Int64.self, forKey: .nodeID) ?? 0
        derpRegion = try container.decodeIfPresent(Int64.self, forKey: .derpRegion) ?? 0
        cap = try container.decodeIfPresent(Int.self, forKey: .cap) ?? 0
        capMap = try container.decodeCapMapIfPresent(forKey: .capMap)
        endpoints = try container.decodeIfPresent([IPEndpoint].self, forKey: .endpoints)
        key = try container.decodeIfPresent(NodePublicKey.self, forKey: .key)
        keySignature = try container.decodeBytesIfPresent(forKey: .keySignature)
        discoKey = try container.decodeIfPresent(DiscoPublicKey.self, forKey: .discoKey)
        online = try container.decodeIfPresent(Bool.self, forKey: .online)
        lastSeen = try container.decodeTimeIfPresent(forKey: .lastSeen)
        keyExpiry = try container.decodeTimeIfPresent(forKey: .keyExpiry)
    }
}
