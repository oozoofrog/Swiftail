import Foundation
import SwiftailBase

/// `TailnetNode`가 알리는 상태 변화. `TailnetNode.events`로 받는다.
public enum NodeEvent: Sendable {
    /// 사용자가 이 URL에서 로그인해야 등록이 끝난다.
    case loginRequired(URL)
    /// 등록되고 netmap을 받았다. 자기 tailnet 주소다.
    ///
    /// 주소가 바뀌면 다시 나온다. `reconnecting` 뒤 끊겼던 연결이 모두 돌아와도 다시 나온다.
    case running(addresses: [IPAddress])
    /// 제어 서버나 DERP와의 연결이 끊겼다. 다시 잇는 중이다.
    case reconnecting
}
