import SwiftailBase

/// 서비스 IP: 노드가 MagicDNS를 직접 받는 두 주소(`100.100.100.100`, `fd7a:115c:a1e0::53`).
///
/// 응답기·설정 산출·응답 패킷·`TailnetEngine.send`의 로컬 처리가 같은 상수를 쓰도록 한 곳에 둔다.
/// 값은 Go의 `tsaddr.TailscaleServiceIP`·`TailscaleServiceIPv6`다(`docs/protocol-notes/dns-state-node.md` 5장).
enum ServiceIP {
    static let ipv4Text = "100.100.100.100"
    static let ipv6Text = "fd7a:115c:a1e0::53"

    // 리터럴이라 해석에 실패하지 않는다. 시험이 값을 확인한다.
    static let ipv4 = IPAddress(ipv4Text)
    static let ipv6 = IPAddress(ipv6Text)

    /// `address`가 두 서비스 IP 가운데 하나다.
    static func contains(_ address: IPAddress) -> Bool {
        address == ipv4 || address == ipv6
    }
}
