import Foundation

/// 지금의 tailnet 모습. 맵 스트림의 응답을 차례로 적용한 결과다(`MapSession`).
///
/// 데이터면 설정(WireGuard 피어, 경로, 패킷 필터), MagicDNS, WhoIs가 이 값 하나에서 필요한 것을 읽는다.
/// Go `netmap.NetworkMap`에 대응한다. `docs/protocol-notes/control-map.md` 4.3.
public struct Netmap: Sendable, Equatable {
    /// 자기 노드. 옛 `Capabilities` 목록은 `capMap`에 인자 없는 항목으로 합쳐져 있다.
    public var selfNode: Node
    /// 피어. Node ID 오름차순이다.
    public var peers: [Node]
    /// DERP 지도. 아직 받지 못했으면 `nil`.
    public var derpMap: DERPMap?
    /// DNS 설정. 아직 받지 못했으면 `nil`.
    public var dnsConfig: DNSConfig?
    /// 수신 패킷 필터 규칙. 이름 붙은 규칙 묶음을 이름 순으로 이은 것이다. 비어 있으면 모두 차단이다.
    public var packetFilter: [FilterRule]
    /// 사용자 ID → 프로필. self와 피어의 소유자·공유자 가운데 프로필을 받은 사용자만 있다.
    public var userProfiles: [Int64: UserProfile]
    /// tailnet 이름. 아직 받지 못했으면 빈 문자열.
    public var domain: String
    /// tailnet lock이 켜져 있다. Swiftail은 lock을 구현하지 않으므로 켜져 있으면 통신을 시작하지 않는다.
    public var tailnetLockEnabled: Bool
    /// 제어 서버가 마지막으로 알린 서버 시각. 노드 키 만료를 계산할 때 시계 차이를 보정하는 데 쓴다.
    public var controlTime: Date?
}
