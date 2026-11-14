import Foundation

/// 노드의 상태. Go `ipn.State`에서 앱이 쓰는 것만 남겼다(`docs/protocol-notes/dns-state-node.md` 4.5).
///
/// 정지와 실패는 상태가 아니다. 정지는 `TailnetNode.run()`이 돌아온 것이고, 실패는 `run()`이 던진 `NodeError`다.
public enum NodeState: Sendable, Equatable {
    /// 등록·netmap·첫 연결을 기다린다.
    case starting
    /// 사용자가 이 URL에서 로그인해야 한다. 노드가 등록을 시작하면 제어 서버가 늘 URL을 준다.
    ///
    /// URL은 그 자체로 로그인 권한이므로 로그에 남기지 않는다.
    case needsLogin(URL)
    /// tailnet 관리자가 이 기기를 승인해야 한다(netmap 자기 노드의 `MachineAuthorized`가 거짓).
    case needsMachineAuth
    /// netmap을 받았고, 홈 DERP 연결이 섰거나 피어 하나와 WireGuard 세션을 맺은 적이 있다. 그 뒤 연결이 끊겨도
    /// (다시 잇는 동안에도) 이 상태에 머문다.
    case running
}
