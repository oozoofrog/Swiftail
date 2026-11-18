import Foundation
import Network

/// An IPv4 or IPv6 address.
///
/// Stores 4 or 16 bytes in network byte order. String parsing uses the Network framework's
/// `IPv4Address` and `IPv6Address` with three additional restrictions.
/// - Strings containing characters other than hexadecimal digits, `:`, or `.` are rejected. This includes zones (zone, `%en0`). Tailnet addresses have no zones.
///   Ignoring zones would make distinct addresses equal. This also rejects trailing text after a NUL, which Network ignores.
/// - IPv4 outside four-part dotted-decimal notation (`1.2.3`, `010.0.0.1`, `0x7f.0.0.1`) is rejected. Network accepts legacy inet_aton notation and
///   reads `1.2.3` as `1.2.0.3`. Accepting only standard notation keeps the same string from yielding different addresses across tools.
///   An IPv4 suffix in IPv6 (`::ffff:010.0.0.1`) follows the same rules.
/// - IPv6 groups longer than four hexadecimal digits (`00000::1`) are rejected. Network accepts them, while Go (`net.ParseIP` and `netip.ParseAddr`) rejects them.
public struct IPAddress: Hashable, Sendable, LosslessStringConvertible {
    /// The address in network byte order. IPv4 uses 4 bytes and IPv6 uses 16 bytes.
    public let bytes: [UInt8]

    /// Parses a string such as `"100.64.0.1"` or `"fd7a:115c:a1e0::1"`. Returns `nil` if the string is invalid.
    public init?(_ description: String) {
        // Network parses C strings and ignores everything after a NUL. Restricting input to valid address characters
        // rejects both zones (`%en0`) and trailing text after a NUL.
        guard description.utf8.allSatisfy({ $0 == UInt8(ascii: ":") || $0 == UInt8(ascii: ".") || Character(UnicodeScalar($0)).isHexDigit }) else {
            return nil
        }
        if let v4 = IPv4Address(description) {
            bytes = Array(v4.rawValue)
            guard Self.dottedDecimal(bytes) == description else { return nil }
        } else if let v6 = IPv6Address(description), Self.hasDottedDecimalTail(description),
                  description.split(separator: ":").allSatisfy({ $0.count <= 4 || $0.contains(".") }) {
            bytes = Array(v6.rawValue)
        } else {
            return nil
        }
    }

    /// Creates an address from 4 bytes (IPv4) or 16 bytes (IPv6) in network byte order. Returns `nil` for other lengths.
    public init?(bytes: some Collection<UInt8>) {
        let bytes = Array(bytes)
        guard bytes.count == 4 || bytes.count == 16 else { return nil }
        self.bytes = bytes
    }

    /// Whether the address is IPv4. IPv4-mapped IPv6 (`::ffff:a.b.c.d`) takes 16 bytes and returns `false`.
    public var isIPv4: Bool { bytes.count == 4 }

    /// The Tailscale address ranges used by the engine and pairing. Distinguishes the ChromeOS VM range within CGNAT.
    package var isTailscaleAddress: Bool {
        if isIPv4 {
            let inCGNAT = bytes[0] == 100 && bytes[1] & 0xC0 == 64
            let inChromeOSRange = bytes[0] == 100 && bytes[1] == 115 && bytes[2] & 0xFE == 92
            return inCGNAT && !inChromeOSRange
        }
        return bytes.starts(with: [0xFD, 0x7A, 0x11, 0x5C, 0xA1, 0xE0])
    }

    /// IPv4 uses four-part dotted decimal. IPv6 uses the Network framework's notation (RFC 5952 compression).
    public var description: String {
        if isIPv4 {
            return Self.dottedDecimal(bytes)
        }
        // Network accepts the 16-byte rawValue. Fall back to hexadecimal in case it fails.
        guard let v6 = IPv6Address(Data(bytes)) else { return bytes.hex }
        return "\(v6)"
    }

    /// Whether the IPv4 suffix of an IPv6 string, if present, uses four-part dotted decimal. Returns `true` if there is no suffix.
    private static func hasDottedDecimalTail(_ text: String) -> Bool {
        guard let tail = text.split(separator: ":").last, tail.contains(".") else { return true }
        return IPAddress(String(tail))?.isIPv4 == true
    }

    private static func dottedDecimal(_ bytes: [UInt8]) -> String {
        bytes.map(String.init).joined(separator: ".")
    }
}
