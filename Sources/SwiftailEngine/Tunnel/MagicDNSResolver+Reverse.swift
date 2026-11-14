// 역방향 이름 해석은 Tailscale의 `net/dns/resolver/tsdns.go` `rdnsNameToIPv4`·`rdnsNameToIPv6`과
// `net/tsaddr/tsaddr.go` `Tailscale6to4`(BSD-3-Clause, Copyright (c) Tailscale Inc & contributors)를 따른다.
// 규칙과 상수만 옮겼고 코드는 Swift로 새로 썼다.

import SwiftailBase

/// PTR 질의의 이름을 주소로 읽기: `in-addr.arpa`(RFC 1035 3.5)와 `ip6.arpa`(RFC 3596 2.5). 노트 4.2.2 5.
extension MagicDNSResolver {
    /// 4to6 범위 `fd7a:115c:a1e0:ab12:4843:cd96:6200::/104`의 앞 13바이트. 뒤 3바이트가 `100.x.y.z`의 x·y·z다(노트 5장).
    static let fourToSixPrefix: [UInt8] = [0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0xab, 0x12, 0x48, 0x43, 0xcd, 0x96, 0x62]

    /// 소문자 역방향 이름의 주소. 형식이 맞지 않으면 nil이고, 그 질의는 로컬 답이 없다.
    ///
    /// - `<d>.<c>.<b>.<a>.in-addr.arpa.`: 앞부분이 점 네 개 십진 IPv4(앞자리 0 없음)여야 하고, 뒤집어 `a.b.c.d`가 된다.
    /// - `<니블 32개>.ip6.arpa.`: 앞부분이 정확히 한 글자 16진 레이블 32개여야 하고, 첫 레이블이 가장 낮은 니블이다.
    static func address(fromReverseName name: DNSMessage.Name) -> IPAddress? {
        let labels = name.labels
        guard labels.count > 2 else { return nil }
        let zone = labels.suffix(2)
        let head = labels.dropLast(2)
        if zone.elementsEqual([Array("in-addr".utf8), Array("arpa".utf8)]) {
            let text = String(decoding: Array(head.joined(separator: [UInt8(ascii: ".")])), as: UTF8.self)
            guard let address = IPAddress(text), address.isIPv4 else { return nil }
            return IPAddress(bytes: address.bytes.reversed())
        }
        if zone.elementsEqual([Array("ip6".utf8), Array("arpa".utf8)]) {
            let nibbles = head.compactMap { $0.count == 1 ? hexValue($0[0]) : nil }
            guard head.count == 32, nibbles.count == 32 else { return nil }
            // 이름은 낮은 니블부터 온다. 뒤집으면 높은 니블부터 둘씩 한 바이트다.
            let ordered = Array(nibbles.reversed())
            return IPAddress(bytes: stride(from: 0, to: 32, by: 2).map { ordered[$0] << 4 | ordered[$0 + 1] })
        }
        return nil
    }

    /// 4to6 범위의 IPv6면 대응하는 `100.x.y.z`(Go `Tailscale6to4`).
    static func ipv4(from4to6 address: IPAddress) -> IPAddress? {
        guard !address.isIPv4, address.bytes.starts(with: fourToSixPrefix) else { return nil }
        return IPAddress(bytes: [100] + address.bytes.suffix(3))
    }

    private static func hexValue(_ byte: UInt8) -> UInt8? {
        switch byte {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): byte - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"): byte - UInt8(ascii: "a") + 10
        default: nil
        }
    }
}
