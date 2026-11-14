import Foundation

/// 노드 상태를 정하는 값 타입. 입력을 받을 때마다 아래 표를 위에서부터 보고, 상태가 바뀌었을 때만 새 상태를 돌려준다.
///
/// | # | 조건(위에서부터) | 결과 |
/// | --- | --- | --- |
/// | 1 | 제어가 `loginRequired(url)`를 냈고 그 뒤 `registered`가 오지 않았다 | `.needsLogin(url)` |
/// | 2 | netmap 없음 | `.starting` |
/// | 3 | 자기 노드가 `MachineAuthorized`가 아님 | `.needsMachineAuth` |
/// | 4 | 이전이 `.running` | `.running` |
/// | 5 | 홈 DERP 연결이 선 적이 있거나 세션을 맺은 피어가 있음 | `.running` |
/// | 6 | 그 밖 | `.starting` |
///
/// Go `nextStateLocked`(`ipn/ipnlocal/local.go`)의 표를 Swiftail의 입력으로 옮긴 것이다. 자기 키 만료는 제어 클라이언트가
/// 새 키로 다시 등록하며 `loginRequired`로 알리므로 1로 간다. `.running` 뒤 연결이 끊겨도 4로 `.running`이다.
/// `docs/contracts/SwiftailTunnel.md` 동작 B, `docs/protocol-notes/dns-state-node.md` 4.5.
struct NodeStateMachine: Sendable, Equatable {
    private(set) var state: NodeState = .starting
    /// 1의 URL. `registered`가 지운다(Go가 `Running` 진입 때 URL을 지우는 것과 같은 효과).
    private var loginURL: URL?
    /// 2. 받은 netmap이 하나라도 있었다.
    private var hasNetmap = false
    /// 3. 마지막 netmap의 자기 노드가 승인되었다.
    private var machineAuthorized = false
    /// 5. 홈 DERP 연결이 선 적이 있거나 피어와 세션을 맺은 적이 있다.
    private var hasConnected = false

    /// 제어 서버가 로그인 URL을 주었다.
    mutating func loginRequired(_ url: URL) -> NodeState? {
        loginURL = url
        return reevaluate()
    }

    /// 등록을 마쳤다.
    mutating func registered() -> NodeState? {
        loginURL = nil
        return reevaluate()
    }

    /// netmap을 받았다.
    mutating func receivedNetmap(machineAuthorized: Bool) -> NodeState? {
        hasNetmap = true
        self.machineAuthorized = machineAuthorized
        return reevaluate()
    }

    /// 홈 DERP 연결이 섰거나 피어와 WireGuard 세션을 맺었다.
    mutating func connected() -> NodeState? {
        hasConnected = true
        return reevaluate()
    }

    private mutating func reevaluate() -> NodeState? {
        let next: NodeState
        if let loginURL {
            next = .needsLogin(loginURL)
        } else if !hasNetmap {
            next = .starting
        } else if !machineAuthorized {
            next = .needsMachineAuth
        } else if state == .running || hasConnected {
            next = .running
        } else {
            next = .starting
        }
        guard next != state else { return nil }
        state = next
        return next
    }
}
