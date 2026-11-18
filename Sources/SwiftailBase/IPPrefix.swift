/// A CIDR prefix (`100.64.0.0/10`, `fd7a:115c:a1e0::/48`).
///
/// Clears host bits on storage, so `100.64.0.1/10` and `100.64.0.0/10` are the same value.
/// Used in WireGuard AllowedIPs and routing tables.
public struct IPPrefix: Hashable, Sendable, LosslessStringConvertible {
    /// The network address with host bits cleared.
    public let address: IPAddress
    /// The prefix length. IPv4 uses 0...32 and IPv6 uses 0...128.
    public let length: Int

    /// Creates a prefix from an address and length. Returns `nil` for a length outside the address family's range.
    public init?(address: IPAddress, length: Int) {
        guard (0...address.bytes.count * 8).contains(length),
              let masked = IPAddress(bytes: Self.mask(address.bytes, length: length))
        else { return nil }
        self.address = masked
        self.length = length
    }

    /// Parses a string such as `"100.64.0.1/32"`.
    /// Accepts only decimal lengths without leading zeros (rejects `/032` and `/+8`).
    public init?(_ description: String) {
        let parts = description.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2,
              let address = IPAddress(String(parts[0])),
              let length = Self.parseLength(parts[1])
        else { return nil }
        self.init(address: address, length: length)
    }

    /// Returns whether the address belongs to this prefix. Returns `false` when the address families (IPv4 or IPv6) differ.
    public func contains(_ other: IPAddress) -> Bool {
        other.isIPv4 == address.isIPv4 && Self.mask(other.bytes, length: length) == address.bytes
    }

    /// The CIDR notation with host bits cleared, such as `"100.64.0.0/10"`.
    public var description: String { "\(address)/\(length)" }

    /// Preserves the first length bits and sets the rest to 0.
    private static func mask(_ bytes: [UInt8], length: Int) -> [UInt8] {
        bytes.enumerated().map { index, byte in
            let keptBits = min(max(length - index * 8, 0), 8)
            // When keptBits is 0, the low byte of 0xFF00 >> 0 is 0x00. When keptBits is 8, the low byte is 0xFF.
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
