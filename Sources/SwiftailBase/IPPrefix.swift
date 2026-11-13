/// CIDR 접두(`100.64.0.0/10`, `fd7a:115c:a1e0::/48`).
///
/// 저장할 때 호스트 비트를 지운다. 그래서 `100.64.0.1/10`과 `100.64.0.0/10`은 같은 값이다.
/// WireGuard의 AllowedIPs, 경로 표에서 쓴다.
public struct IPPrefix: Hashable, Sendable, LosslessStringConvertible {
    /// 호스트 비트를 지운 망 주소.
    public let address: IPAddress
    /// 접두 길이. IPv4는 0...32, IPv6는 0...128이다.
    public let length: Int

    /// 주소와 길이로 만든다. 길이가 주소 종류의 범위 밖이면 `nil`.
    public init?(address: IPAddress, length: Int) {
        guard (0...address.bytes.count * 8).contains(length),
              let masked = IPAddress(bytes: Self.mask(address.bytes, length: length))
        else { return nil }
        self.address = masked
        self.length = length
    }

    /// `"100.64.0.1/32"` 같은 문자열을 해석한다.
    /// 길이는 앞자리 0이 없는 십진수만 받는다(`/032`, `/+8`은 거절).
    public init?(_ description: String) {
        let parts = description.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2,
              let address = IPAddress(String(parts[0])),
              let length = Self.parseLength(parts[1])
        else { return nil }
        self.init(address: address, length: length)
    }

    /// 주소가 이 접두에 속하는지. 주소 종류(IPv4·IPv6)가 다르면 `false`.
    public func contains(_ other: IPAddress) -> Bool {
        other.isIPv4 == address.isIPv4 && Self.mask(other.bytes, length: length) == address.bytes
    }

    /// 호스트 비트를 지운 CIDR 표기. 예: `"100.64.0.0/10"`.
    public var description: String { "\(address)/\(length)" }

    /// 앞 length비트만 남기고 나머지를 0으로 만든다.
    private static func mask(_ bytes: [UInt8], length: Int) -> [UInt8] {
        bytes.enumerated().map { index, byte in
            let keptBits = min(max(length - index * 8, 0), 8)
            // keptBits가 0이면 0xFF00 >> 0의 하위 바이트 0x00, 8이면 0xFF.
            return byte & UInt8(truncatingIfNeeded: 0xFF00 >> keptBits)
        }
    }

    private static func parseLength(_ text: Substring) -> Int? {
        guard (1...3).contains(text.count),
              text.allSatisfy({ ("0"..."9").contains($0) }),
              text == "0" || !text.hasPrefix("0")
        else { return nil }
        return Int(text)
    }
}
