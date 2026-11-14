import Foundation
import SwiftailBase
import SwiftailMagicsock

/// `TailnetNode`가 알리는 상태 변화. `TailnetNode.events`로 받는다.
public enum NodeEvent: Sendable {
    /// 사용자가 이 URL에서 로그인해야 등록이 끝난다.
    case loginRequired(URL)
    /// 등록되고 netmap을 받았다. 자기 tailnet 주소다.
    ///
    /// 주소가 바뀌면 다시 나온다. `reconnecting` 뒤 끊겼던 연결이 모두 돌아와도 다시 나온다.
    case running(addresses: [IPAddress])
    /// 제어 서버나 홈 DERP 지역과의 연결이 끊겼다. 다시 잇는 중이다.
    case reconnecting
    /// 피어의 경로가 바뀌었다. 뜻은 `TailnetNode.path(toPeerNamed:)`와 같다.
    ///
    /// nil은 그 피어가 데이터면에서 빠졌거나 45초 넘게 주고받은 것이 없다(유휴)는 뜻이다. 다시 주고받기 시작하면
    /// 그때의 경로로 다시 나온다. 이름이 빈 피어는 알리지 않는다.
    ///
    /// - Parameter fqdn: netmap의 노드 이름에서 끝의 점을 뗀 것(`rd-mac-1a2b3c4d.tail0001.ts.net`).
    case peerPathChanged(fqdn: String, path: PeerPath?)
}
