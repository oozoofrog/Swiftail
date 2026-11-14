import SwiftailEngine

/// 앱에 낼 터널 설정을 고르는 값 타입. 첫 사용처의 규칙을 그대로 따른다(`docs/contracts/SwiftailTunnel.md` 동작 E).
///
/// - 산출한 설정이 nil(자기 주소 없음)이면 내지 않는다. 로그인·승인을 기다리는 동안에도 빈 설정을 내지 않는다.
/// - 마지막으로 낸 값과 같으면(목록 순서 포함) 내지 않는다. 설정 적용 → utun 링크 변화 → 다시 적용으로 도는 고리를 막는다.
///   DNS만 바뀌어도 낸다.
///
/// 읽지 않은 설정을 새 것이 대신하는 것(동작 E 3)은 흐름의 버퍼(`.bufferingNewest(1)`)가 맡는다.
struct NetworkSettingsPublisher: Sendable, Equatable {
    /// 마지막으로 낸 설정. `NodeStatus.networkSettings`가 된다.
    private(set) var published: TunnelNetworkSettings?

    /// 새로 산출한 설정을 낼지 정한다. 낼 것이면 그 값을 돌려주고 기억한다.
    mutating func publish(_ settings: TunnelNetworkSettings?) -> TunnelNetworkSettings? {
        guard let settings, settings != published else { return nil }
        published = settings
        return settings
    }
}
