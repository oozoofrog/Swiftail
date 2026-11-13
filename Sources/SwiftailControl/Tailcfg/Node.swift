import Foundation
import SwiftailBase

/// tailnet의 노드 하나. Go `tailcfg.Node`.
///
/// 맵 응답의 `Node`(자기 자신), `Peers`, `PeersChanged`로 온다. 올 때마다 객체 전체가 바뀐다.
/// 이전 값의 필드로 빈 필드를 메우지 않는다. 일부 필드만 바꾸는 증분은 `PeerChange`다.
///
/// 해독하면서 Go 클라이언트의 `upgradeNode`와 같이 옛 표현을 지금의 표현으로 바꾼다(노트 4.3의 2).
/// - `homeDERP`가 0이고 옛 `DERP` 문자열이 `"127.3.3.40:N"`이면 N을 홈 DERP로 쓴다.
/// - `AllowedIPs`가 없거나 `null`이면 `addresses`와 같다. 빈 배열은 "경로 없음"으로 그대로 둔다.
/// - `unsignedPeerAPIOnly` 노드의 `allowedIPs`는 자기 주소로 줄인다. tailnet lock 서명이 없는 노드에
///   제어 서버가 경로를 열어 주지 못하게 하는 안전장치다.
///
/// 데이터면·DNS·WhoIs에 쓰는 필드만 둔다. 출구 노드 DNS, 감사 로그 ID, 표시용 계산 이름은 없다.
/// `docs/protocol-notes/control-map.md` 3.7 (출처: tailscale.com `tailcfg/tailcfg.go` `Node`,
/// `control/controlclient/map.go` `upgradeNode`, BSD-3-Clause).
public struct Node: Decodable, Sendable, Equatable {
    /// 증분의 키가 되는 노드 ID.
    public internal(set) var id: Int64
    /// 노드를 가리키는 불투명한 안정 ID.
    public internal(set) var stableID: String
    /// MagicDNS 이름. 보통 끝에 점이 있지만 testcontrol은 없이 보내기도 한다.
    public internal(set) var name: String
    /// 소유자 사용자 ID. `Netmap.userProfiles`의 키다.
    public internal(set) var user: Int64
    /// 이 노드를 공유해 준 사용자 ID. 공유받은 노드가 아니면 0.
    public internal(set) var sharer: Int64
    /// WireGuard 공개 키.
    public internal(set) var key: NodePublicKey
    /// 노드 키 만료 시각. `nil`은 만료 없음.
    public internal(set) var keyExpiry: Date?
    /// 노드 키에 대한 tailnet lock 서명. 없으면 빈 배열.
    public internal(set) var keySignature: [UInt8]
    /// 기기의 machine 공개 키.
    public internal(set) var machine: MachinePublicKey
    /// disco 공개 키. 경로 탐색 메시지를 암호화한다.
    public internal(set) var discoKey: DiscoPublicKey
    /// 노드의 tailnet 주소(보통 IPv4 /32와 IPv6 /128).
    public internal(set) var addresses: [IPPrefix]
    /// 이 노드로 보낼 목적지 접두. WireGuard의 AllowedIPs가 된다.
    public internal(set) var allowedIPs: [IPPrefix]
    /// 직접 연결 UDP 후보 주소.
    public internal(set) var endpoints: [IPEndpoint]
    /// 노드가 받는 홈 DERP 지역. 0은 없음.
    public internal(set) var homeDERP: Int64
    /// 노드가 알린 자기 정보.
    public internal(set) var hostinfo: Hostinfo
    /// 노드의 capability version. 0은 모름.
    public internal(set) var cap: Int
    /// ACL 태그(`"tag:server"`). 태그가 있으면 사용자 소유가 아니다.
    public internal(set) var tags: [String]
    /// 이 노드가 지금 주 라우터인 서브넷 경로.
    public internal(set) var primaryRoutes: [IPPrefix]
    /// 마지막으로 온라인이었던 시각. `nil`은 모름 또는 볼 권한 없음.
    public internal(set) var lastSeen: Date?
    /// 제어 서버에 연결되어 있는지. `nil`은 모름.
    public internal(set) var online: Bool?
    /// 기기가 승인되었는지. self 노드에서 의미가 있다.
    public internal(set) var machineAuthorized: Bool
    /// 옛 형식의 노드 속성 목록. self 노드에서는 `capMap`에 합쳐진다.
    public internal(set) var capabilities: [String]
    /// 노드 속성 → 인자. 인자가 없는 속성은 빈 배열이다.
    public internal(set) var capMap: [String: [JSONValue]]
    /// tailnet lock 서명이 없어 peerAPI만 허용되는 노드.
    public internal(set) var unsignedPeerAPIOnly: Bool
    /// 노드 키가 만료되었다.
    public internal(set) var expired: Bool
    /// 이 피어가 self를 알아보는 IPv4 주소. 피어로 나가는 패킷의 출발 주소를 바꿀 때 쓴다.
    public internal(set) var selfNodeV4MasqAddrForThisPeer: IPAddress?
    /// 이 피어가 self를 알아보는 IPv6 주소.
    public internal(set) var selfNodeV6MasqAddrForThisPeer: IPAddress?
    /// disco·DERP 없이 WireGuard만 하는 피어. `endpoints`로만 닿는다.
    public internal(set) var isWireGuardOnly: Bool
    /// 이 노드는 연결을 시작할 수 없다. 이 노드로의 연결은 된다.
    public internal(set) var isJailed: Bool

    private enum CodingKeys: String, CodingKey {
        case id = "ID"
        case stableID = "StableID"
        case name = "Name"
        case user = "User"
        case sharer = "Sharer"
        case key = "Key"
        case keyExpiry = "KeyExpiry"
        case keySignature = "KeySignature"
        case machine = "Machine"
        case discoKey = "DiscoKey"
        case addresses = "Addresses"
        case allowedIPs = "AllowedIPs"
        case endpoints = "Endpoints"
        case legacyDERP = "DERP"
        case homeDERP = "HomeDERP"
        case hostinfo = "Hostinfo"
        case cap = "Cap"
        case tags = "Tags"
        case primaryRoutes = "PrimaryRoutes"
        case lastSeen = "LastSeen"
        case online = "Online"
        case machineAuthorized = "MachineAuthorized"
        case capabilities = "Capabilities"
        case capMap = "CapMap"
        case unsignedPeerAPIOnly = "UnsignedPeerAPIOnly"
        case expired = "Expired"
        case selfNodeV4MasqAddrForThisPeer = "SelfNodeV4MasqAddrForThisPeer"
        case selfNodeV6MasqAddrForThisPeer = "SelfNodeV6MasqAddrForThisPeer"
        case isWireGuardOnly = "IsWireGuardOnly"
        case isJailed = "IsJailed"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decodeIfPresent(Int64.self, forKey: .id) ?? 0
        stableID = try container.decodeIfPresent(String.self, forKey: .stableID) ?? ""
        name = try container.decodeIfPresent(String.self, forKey: .name) ?? ""
        user = try container.decodeIfPresent(Int64.self, forKey: .user) ?? 0
        sharer = try container.decodeIfPresent(Int64.self, forKey: .sharer) ?? 0
        key = try container.decodeIfPresent(NodePublicKey.self, forKey: .key) ?? .zero
        keyExpiry = try container.decodeTimeIfPresent(forKey: .keyExpiry).flatMap(GoTime.nonZero)
        keySignature = try container.decodeBytesIfPresent(forKey: .keySignature) ?? []
        machine = try container.decodeIfPresent(MachinePublicKey.self, forKey: .machine) ?? .zero
        discoKey = try container.decodeIfPresent(DiscoPublicKey.self, forKey: .discoKey) ?? .zero
        addresses = try container.decodeIfPresent([IPPrefix].self, forKey: .addresses) ?? []
        allowedIPs = try container.decodeIfPresent([IPPrefix].self, forKey: .allowedIPs) ?? addresses
        endpoints = try container.decodeIfPresent([IPEndpoint].self, forKey: .endpoints) ?? []
        homeDERP = try container.decodeIfPresent(Int64.self, forKey: .homeDERP) ?? 0
        hostinfo = try container.decodeIfPresent(Hostinfo.self, forKey: .hostinfo) ?? Hostinfo()
        cap = try container.decodeIfPresent(Int.self, forKey: .cap) ?? 0
        tags = try container.decodeIfPresent([String].self, forKey: .tags) ?? []
        primaryRoutes = try container.decodeIfPresent([IPPrefix].self, forKey: .primaryRoutes) ?? []
        lastSeen = try container.decodeTimeIfPresent(forKey: .lastSeen)
        online = try container.decodeIfPresent(Bool.self, forKey: .online)
        machineAuthorized = try container.decodeIfPresent(Bool.self, forKey: .machineAuthorized) ?? false
        capabilities = try container.decodeIfPresent([String].self, forKey: .capabilities) ?? []
        capMap = try container.decodeCapMapIfPresent(forKey: .capMap) ?? [:]
        unsignedPeerAPIOnly = try container.decodeIfPresent(Bool.self, forKey: .unsignedPeerAPIOnly) ?? false
        expired = try container.decodeIfPresent(Bool.self, forKey: .expired) ?? false
        selfNodeV4MasqAddrForThisPeer = try container.decodeIfPresent(IPAddress.self, forKey: .selfNodeV4MasqAddrForThisPeer)
        selfNodeV6MasqAddrForThisPeer = try container.decodeIfPresent(IPAddress.self, forKey: .selfNodeV6MasqAddrForThisPeer)
        isWireGuardOnly = try container.decodeIfPresent(Bool.self, forKey: .isWireGuardOnly) ?? false
        isJailed = try container.decodeIfPresent(Bool.self, forKey: .isJailed) ?? false

        if homeDERP == 0, let legacy = try container.decodeIfPresent(String.self, forKey: .legacyDERP) {
            homeDERP = Self.regionID(fromLegacyDERP: legacy) ?? 0
        }
        if unsignedPeerAPIOnly {
            allowedIPs = addresses
        }
    }

    /// 옛 `DERP` 필드 `"127.3.3.40:N"`의 N. 다른 형식이면 `nil`.
    private static func regionID(fromLegacyDERP text: String) -> Int64? {
        let magicPrefix = "127.3.3.40:"
        guard text.hasPrefix(magicPrefix) else { return nil }
        return Int64(text.dropFirst(magicPrefix.count))
    }
}
