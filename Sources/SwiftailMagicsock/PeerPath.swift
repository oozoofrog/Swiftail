import SwiftailBase

/// 피어에게 가는 길. Go `ipnstate.PeerStatus`의 `CurAddr`와 같은 뜻이다(노트 6.3 마지막 줄, 7.1).
public enum PeerPath: Sendable, Equatable {
    /// 신뢰 기간 안의 직접 UDP 주소로만 보낸다.
    case direct(IPEndpoint)
    /// DERP를 거친다. 직접 주소로 함께 보내는 중(신뢰가 지난 `bestAddr`)이어도 여기에 든다.
    /// - Parameter derpRegion: 피어의 홈 DERP 지역. 0이면 모른다.
    case relayed(derpRegion: Int64)
}
