import SwiftailTKA

/// 제어 서버가 이 맵 세션에서 알린 tailnet lock 상태(Go `netmap.TKAEnabled`·`TKAHead`).
///
/// 서버의 말일 뿐이다. 켜졌다는 말은 부트스트랩의 계기가 되고, 꺼졌다는 말은 끄기 비밀을 검증한 뒤에만 따른다
/// (`TailnetLockPlan`, 계약 `docs/contracts/SwiftailTailnetLock.md` 동작 N1·O1).
///
/// `docs/protocol-notes/tailnet-lock.md` 4.7·4.10 (출처: tailscale.com `control/controlclient/map.go`의 `netmap`,
/// BSD-3-Clause).
package struct ServerLockState: Sendable, Equatable {
    /// 서버가 lock이 켜졌다고 알렸다.
    package var isEnabled = false
    /// 서버가 알린 머리. 알리지 않았거나 읽히지 않으면 nil이다.
    package var head: AUMHash?

    package init(isEnabled: Bool = false, head: AUMHash? = nil) {
        self.isEnabled = isEnabled
        self.head = head
    }

    /// 이 맵 세션에서 받은 마지막 `TKAInfo`로 계산한다. 한 번도 받지 않았으면(nil) 꺼진 것이다.
    ///
    /// `Head`가 비지 않았는데 AUM 해시로 읽히지 않으면 꺼진 것으로 본다(Go와 같다). 머리는 `Disabled`와 무관하게 읽는다:
    /// 끄기 비밀이 틀려 lock을 유지할 때 Go는 이 머리와 로컬 머리를 견줘 동기화할지를 정한다.
    init(_ info: TKAInfo?) {
        guard let info else { return }
        isEnabled = !info.disabled
        guard !info.head.isEmpty else { return }
        head = AUMHash(text: info.head)
        if head == nil { isEnabled = false }
    }
}
