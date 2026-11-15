import SwiftailTKA

/// netmap을 받았을 때 tailnet lock에 대해 할 일(Go `tkaSyncIfNeeded`의 갈래). 입출력 없는 판정이다.
///
/// | 로컬 상태 | capability | 서버 | 할 일 |
/// | --- | --- | --- | --- |
/// | 없음 | 없음 | 무엇이든 | 없음(Go와 같이 거르지 않는다) |
/// | 없음 | 있음 | 꺼짐 | 없음 |
/// | 없음 | 있음 | 켜짐 | `bootstrap` |
/// | 있음 | 무관 | 켜짐, 머리 같음 | 없음 |
/// | 있음 | 무관 | 켜짐, 머리 다름 | `synchronize` |
/// | 있음 | 무관 | 꺼짐 | `verifyDisablement` |
///
/// 계약 `docs/contracts/SwiftailTailnetLock.md` 동작 N2, `docs/protocol-notes/tailnet-lock.md` 4.7·4.12
/// (출처: tailscale.com `ipn/ipnlocal/tailnet-lock.go` `tkaSyncIfNeeded`, BSD-3-Clause).
enum TailnetLockPlan: Equatable {
    case nothing
    /// 부트스트랩 RPC로 체크포인트를 받아 검증·저장하고 곧바로 동기화한다.
    case bootstrap
    /// 서버와 AUM을 주고받아 머리를 맞춘다.
    case synchronize
    /// 서버가 준 끄기 비밀을 검증한다. 맞을 때만 로컬 상태를 지운다.
    case verifyDisablement

    /// - Parameters:
    ///   - localHead: 로컬 서명 권한 상태의 머리. 상태가 없으면 nil.
    ///   - hasCapability: 자기 노드에 `tailnet-lock` capability가 있다.
    ///   - server: 서버가 이 맵 세션에서 알린 상태.
    init(localHead: AUMHash?, hasCapability: Bool, server: ServerLockState) {
        switch (localHead, server.isEnabled) {
        case (nil, true): self = hasCapability ? .bootstrap : .nothing
        case (nil, false): self = .nothing
        // 머리는 텍스트가 아니라 32바이트로 견준다(텍스트는 끝 글자가 달라도 같은 해시일 수 있다).
        case (let head?, true): self = head == server.head ? .nothing : .synchronize
        case (_?, false): self = .verifyDisablement
        }
    }
}

extension Node {
    /// 자기 노드에 tailnet lock을 켜는 node capability(`nodecap.TailnetLock`).
    static let tailnetLockCapability = "https://tailscale.com/cap/tailnet-lock"

    /// 이 노드에 `tailnet-lock` capability가 있다. 옛 `Capabilities` 목록과 `CapMap`의 키를 합쳐 본다
    /// (Go `mapSession.lastCapSet`, `control/controlclient/map.go`).
    var hasTailnetLockCapability: Bool {
        capMap[Self.tailnetLockCapability] != nil || capabilities.contains(Self.tailnetLockCapability)
    }
}
