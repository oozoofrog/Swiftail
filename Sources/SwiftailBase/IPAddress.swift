import Foundation
import Network

/// IPv4 또는 IPv6 주소.
///
/// 네트워크 바이트 순서의 4바이트 또는 16바이트로 저장한다. 문자열 해석은 Network 프레임워크의
/// `IPv4Address`·`IPv6Address`에 맡기되 세 가지를 더 거절한다.
/// - 16진 숫자, `:`, `.` 밖의 문자가 든 문자열. 범위(zone, `%en0`)가 여기에 걸린다. tailnet 주소에는 범위가 없고,
///   범위를 무시하면 서로 다른 주소가 같은 값이 된다. Network가 무시하는 NUL 뒤의 꼬리도 여기서 걸린다.
/// - 점 네 개 십진이 아닌 IPv4(`1.2.3`, `010.0.0.1`, `0x7f.0.0.1`). Network는 inet_aton의 옛 표기를 받아
///   `1.2.3`을 `1.2.0.3`으로 읽는다. 같은 문자열이 도구마다 다른 주소가 되지 않게 표준 표기만 받는다.
///   IPv6 끝에 붙은 IPv4(`::ffff:010.0.0.1`)도 같은 규칙으로 본다.
/// - 16진 네 자리를 넘는 IPv6 묶음(`00000::1`). Network는 받지만 Go(`net.ParseIP`·`netip.ParseAddr`)는 받지 않는다.
public struct IPAddress: Hashable, Sendable, LosslessStringConvertible {
    /// 네트워크 바이트 순서의 주소. IPv4는 4바이트, IPv6는 16바이트다.
    public let bytes: [UInt8]

    /// `"100.64.0.1"`이나 `"fd7a:115c:a1e0::1"` 같은 문자열을 해석한다. 주소가 아니면 `nil`.
    public init?(_ description: String) {
        // Network는 C 문자열로 해석해 NUL 뒤를 무시한다. 주소에 올 수 있는 문자만 받으면
        // 범위(`%en0`)와 NUL 뒤의 꼬리를 함께 거른다.
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

    /// 네트워크 바이트 순서의 4바이트(IPv4) 또는 16바이트(IPv6)로 만든다. 길이가 다르면 `nil`.
    public init?(bytes: some Collection<UInt8>) {
        let bytes = Array(bytes)
        guard bytes.count == 4 || bytes.count == 16 else { return nil }
        self.bytes = bytes
    }

    /// IPv4 주소인지. IPv4-mapped IPv6(`::ffff:a.b.c.d`)는 16바이트이므로 `false`다.
    public var isIPv4: Bool { bytes.count == 4 }

    /// IPv4는 점 네 개 십진, IPv6는 Network 프레임워크의 표기(RFC 5952 축약)다.
    public var description: String {
        if isIPv4 {
            return Self.dottedDecimal(bytes)
        }
        // 16바이트 rawValue는 Network가 거절하지 않는다. 만에 하나를 위해 16진으로 물러선다.
        guard let v6 = IPv6Address(Data(bytes)) else { return bytes.hex }
        return "\(v6)"
    }

    /// IPv6 문자열이 IPv4 꼬리를 가지면 그 꼬리가 점 네 개 십진인지. 꼬리가 없으면 `true`.
    private static func hasDottedDecimalTail(_ text: String) -> Bool {
        guard let tail = text.split(separator: ":").last, tail.contains(".") else { return true }
        return IPAddress(String(tail))?.isIPv4 == true
    }

    private static func dottedDecimal(_ bytes: [UInt8]) -> String {
        bytes.map(String.init).joined(separator: ".")
    }
}
