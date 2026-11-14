import SwiftailBase

/// 앱이 알린 기본 인터페이스와 그때 읽은 로컬 주소. 다시 묶을지(재결속) STUN만 다시 할지를 이것으로 정한다.
///
/// `NWInterface`는 시험에서 만들 수 없으므로 판정에 필요한 이름과 번호만 옮겨 담는다. 판정은 입출력 없는 함수다.
/// `docs/contracts/SwiftailTunnel.md` 동작 N 1·2, `docs/protocol-notes/dns-state-node.md` 4.6.2.
struct DefaultLink: Sendable, Equatable {
    /// 인터페이스 이름(`en0`, `pdp_ip0` 등).
    var name: String
    /// 인터페이스 번호(`NWInterface.index`). 소켓을 묶는 데 쓴다.
    var index: Int
    /// 그때 읽은 로컬 IPv4 주소(`LocalInterfaceAddresses.current()`의 일반 주소와 loopback 주소).
    var addresses: [IPAddress]
    var loopbackAddresses: [IPAddress]

    /// 통지 하나에 노드가 할 일.
    enum Change: Sendable, Equatable {
        /// 이 노드의 utun이다. 무시한다(Go `netns_darwin.go`가 Tailscale utun을 기본 인터페이스로 보지 않는 것과 같다).
        case ignore
        /// 같은 인터페이스·같은 주소다. STUN 회차만 다시 시작한다(Go: 링크 변경마다 `ReSTUN`).
        case restartSTUN
        /// 처음 받았거나 인터페이스나 주소가 바뀌었다. DERP·UDP·제어를 새 인터페이스로 다시 묶는다(Go `RebindLikelyRequired`).
        case rebind
    }

    /// `previous`(nil이면 아직 묶은 인터페이스가 없음)에서 `self`로 바뀌는 통지가 왔을 때 할 일.
    ///
    /// Go와 달리 가용 프로토콜·비용·PAC 변화는 보지 않는다. 앱이 알린 인터페이스와 그 주소만 본다.
    ///
    /// - Parameter tunnelName: 이 노드의 utun 이름. 메모리 장치면 nil.
    func change(from previous: DefaultLink?, tunnelName: String?) -> Change {
        if let tunnelName, name == tunnelName { return .ignore }
        return self == previous ? .restartSTUN : .rebind
    }
}
