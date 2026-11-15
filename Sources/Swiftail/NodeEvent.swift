import SwiftailControl
import SwiftailMagicsock

/// `TailnetNode`가 알리는 변화. `TailnetNode.events`로 받는다.
///
/// 주소·이름 같은 지금의 모습은 사건에 싣지 않고 `TailnetNode.status`로 읽는다. 같은 사실을 두 길로 알리지 않는다
/// (`docs/contracts/SwiftailTunnel.md` 총괄 확인 T1).
public enum NodeEvent: Sendable, Equatable {
    /// 상태가 바뀌었다. 같은 상태는 다시 내지 않는다. 처음 상태는 `.starting`이고 그것은 내지 않는다.
    case stateChanged(NodeState)
    /// 피어의 경로가 바뀌었다. 뜻은 `TailnetNode.path(toPeerNamed:)`와 같다.
    ///
    /// nil은 그 피어가 데이터면에서 빠졌거나 45초 넘게 주고받은 것이 없다(유휴)는 뜻이다. 다시 주고받기 시작하면
    /// 그때의 경로로 다시 나온다. 이름이 빈 피어는 알리지 않는다.
    ///
    /// - Parameter fqdn: netmap의 노드 이름에서 끝의 점을 뗀 것(`rd-mac-1a2b3c4d.tail0001.ts.net`).
    case peerPathChanged(fqdn: String, path: PeerPath?)
    /// tailnet lock의 모습이 바뀌었다. 값은 그때의 `NodeStatus.tailnetLock`과 같다. 같은 값은 다시 내지 않는다. 처음 값은
    /// `.disabled`이고 그것은 내지 않는다.
    ///
    /// 한 netmap에서 나오는 사건 가운데 맨 앞이다. 그래서 잠긴 노드의 `stateChanged(.running)`보다 먼저 오고, 앱은 "연결됨"을
    /// 보이기 전에 서명 안내(`signingRequest`)를 안다. 서명 기기가 서명하면 다시 시작하지 않아도 다음 netmap에서
    /// `signingRequest`가 nil인 값으로 다시 나온다. `docs/contracts/SwiftailTailnetLock.md` 결정 L4, 첫 사용처 검토 F2.
    case tailnetLockChanged(TailnetLockStatus)
}
