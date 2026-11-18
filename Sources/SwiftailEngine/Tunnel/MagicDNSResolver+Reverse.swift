// Reverse name parsing follows `rdnsNameToIPv4` and `rdnsNameToIPv6` in Tailscale's `net/dns/resolver/tsdns.go` and
// `Tailscale6to4` in `net/tsaddr/tsaddr.go` (BSD-3-Clause, Copyright (c) Tailscale Inc & contributors).
// Only the rules and constants were ported. The code was written from scratch in Swift.

import SwiftailBase

/// Parses PTR query names as addresses, using `in-addr.arpa` (RFC 1035 3.5) and `ip6.arpa` (RFC 3596 2.5). Notes 4.2.2 5.
extension MagicDNSResolver {
    /// The first 13 bytes of the 4to6 range `fd7a:115c:a1e0:ab12:4843:cd96:6200::/104`. The last 3 bytes are x, y, and z in `100.x.y.z` (notes §5).
    static let fourToSixPrefix: [UInt8] = [0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0xab, 0x12, 0x48, 0x43, 0xcd, 0x96, 0x62]

    /// The address of a lowercase reverse name. Returns nil for an invalid format, which leaves the query without a local answer.
    ///
    /// - `<d>.<c>.<b>.<a>.in-addr.arpa.`: The prefix must be IPv4 in four-part dotted decimal (no leading 0). Reverse it to get `a.b.c.d`.
    /// - `<32 nibbles>.ip6.arpa.`: The prefix must have exactly 32 single-character base-16 labels, with the least significant nibble first.
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
            // The name starts with the least significant nibble. Reverse the order and take two nibbles per byte, high nibble first.
            let ordered = Array(nibbles.reversed())
            return IPAddress(bytes: stride(from: 0, to: 32, by: 2).map { ordered[$0] << 4 | ordered[$0 + 1] })
        }
        return nil
    }

    /// The corresponding `100.x.y.z` address for IPv6 in the 4to6 range (Go `Tailscale6to4`).
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
