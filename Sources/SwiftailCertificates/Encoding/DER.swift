/// An ASN.1 value to encode in DER (Distinguished Encoding Rules from ITU-T X.690).
///
/// Includes only types needed for a CSR (RFC 2986). Security decodes received X.509 data, so this implementation only encodes.
/// DER defines a single byte representation per value (X.690 §§10 and 11), so identical inputs produce the same bytes as Go
/// (notes chapter 7 item 2). The types prevent invalid values. Lengths are calculated from content, integers accept only nonnegative magnitudes,
/// OIDs are limited to this target's constants, and strings use types that validate their character sets.
indirect enum DERValue: Sendable, Equatable {
    /// `SEQUENCE` (tag 0x30). Concatenates elements in order.
    case sequence([DERValue])
    /// `SET OF` (tag 0x31). DER writes elements in ascending order of their encoded byte sequences (X.690 11.6).
    case setOf([DERValue])
    /// A nonnegative `INTEGER` (tag 0x02). The value is a big-endian magnitude. Drop leading zeros and prepend 0x00 for the sign
    /// if the first bit is 1 (X.690 8.3). An empty array represents 0.
    case integer(magnitude: [UInt8])
    /// `OBJECT IDENTIFIER` (tag 0x06, X.690 8.19).
    case objectIdentifier(ASN1ObjectIdentifier)
    /// `PrintableString` (tag 0x13).
    case printableString(PrintableString)
    /// `IA5String` (tag 0x16).
    case ia5String(IA5String)
    /// `BIT STRING` with no unused bits (tag 0x03). Prefix the contents with the unused bit count of 0 (X.690 8.6.2).
    case bitString([UInt8])
    /// `OCTET STRING` (tag 0x04).
    case octetString([UInt8])
    /// A value with a context-specific tag, `[number] IMPLICIT` (X.690 8.14.3). Replaces the inner tag with `number` in the context-specific class
    /// and retains the constructed bit and content. The CSR's `attributes [0]` and the SAN's `dNSName [2]` use this form.
    case implicitlyTagged(number: UInt8, DERValue)

    /// DER bytes (identifier ‖ length ‖ content).
    var encoded: [UInt8] {
        let content = contentOctets
        return identifierOctets + Self.lengthOctets(content.count) + content
    }

    // MARK: - Identifier (X.690 8.1.2)

    private var identifierOctets: [UInt8] {
        switch self {
        case .sequence: return [0x30]
        case .setOf: return [0x31]
        case .integer: return [0x02]
        case .objectIdentifier: return [0x06]
        case .printableString: return [0x13]
        case .ia5String: return [0x16]
        case .bitString: return [0x03]
        case .octetString: return [0x04]
        case .implicitlyTagged(let number, let value):
            // Class bits 10 (context-specific), with the inner value's constructed bit. Numbers 31 and higher use high-tag-number form (X.690 8.1.2.4).
            let leading: UInt8 = 0x80 | (value.isConstructed ? 0x20 : 0)
            return number < 31 ? [leading | number] : [leading | 0x1F] + base128(UInt64(number))
        }
    }

    private var isConstructed: Bool {
        switch self {
        case .sequence, .setOf: true
        case .implicitlyTagged(_, let value): value.isConstructed
        default: false
        }
    }

    // MARK: - Length (X.690 8.1.3, 10.1)

    /// Canonical length. Values up to 127 use one short-form byte. Larger values use `0x80 | n` followed by n big-endian bytes without leading zeros.
    private static func lengthOctets(_ length: Int) -> [UInt8] {
        guard length >= 0x80 else { return [UInt8(length)] }
        var bytes: [UInt8] = []
        var rest = length
        while rest > 0 {
            bytes.insert(UInt8(truncatingIfNeeded: rest), at: 0)
            rest >>= 8
        }
        return [0x80 | UInt8(bytes.count)] + bytes
    }

    // MARK: - Content

    private var contentOctets: [UInt8] {
        switch self {
        case .sequence(let elements):
            elements.flatMap(\.encoded)
        case .setOf(let elements):
            elements.map(\.encoded).sorted(by: Self.precedesInSetOf).flatMap { $0 }
        case .integer(let magnitude):
            Self.integerContent(magnitude)
        case .objectIdentifier(let identifier):
            identifier.contentOctets
        case .printableString(let string):
            Array(string.value.utf8)
        case .ia5String(let string):
            Array(string.value.utf8)
        case .bitString(let bytes):
            [0x00] + bytes
        case .octetString(let bytes):
            bytes
        case .implicitlyTagged(_, let value):
            value.contentOctets
        }
    }

    /// X.690 8.3: Use the minimum two's-complement bytes. The value is nonnegative, so prepend 0x00 if the first bit is 1.
    private static func integerContent(_ magnitude: [UInt8]) -> [UInt8] {
        let trimmed = magnitude.drop(while: { $0 == 0 })
        guard let first = trimmed.first else { return [0x00] }
        return first & 0x80 == 0 ? Array(trimmed) : [0x00] + trimmed
    }

    /// Ordering in X.690 11.6. Pad the shorter sequence with trailing zeros and compare the byte sequences.
    private static func precedesInSetOf(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
        for index in 0..<max(lhs.count, rhs.count) {
            let left = index < lhs.count ? lhs[index] : 0
            let right = index < rhs.count ? rhs[index] : 0
            if left != right { return left < right }
        }
        return false
    }
}

/// X.690 8.19.2: Encodes 7-bit groups in big-endian order and sets the first bit of every byte except the last. OID arcs and high tag numbers use this.
private func base128(_ value: UInt64) -> [UInt8] {
    var bytes = [UInt8(value & 0x7F)]
    var rest = value >> 7
    while rest > 0 {
        bytes.insert(UInt8(rest & 0x7F) | 0x80, at: 0)
        rest >>= 7
    }
    return bytes
}

/// An OBJECT IDENTIFIER used in a CSR. Only constants defined by this target exist. External construction is unavailable, so no value
/// can violate the first-two-arc rule in X.690 8.19.4.
struct ASN1ObjectIdentifier: Sendable, Equatable {
    /// The dotted arcs (`2.5.4.3` is `[2, 5, 4, 3]`).
    let arcs: [UInt64]
    /// DER content bytes. Encode the first two arcs as `40 × first + second` (X.690 8.19.4).
    let contentOctets: [UInt8]

    private init(_ first: UInt64, _ second: UInt64, _ rest: UInt64...) {
        arcs = [first, second] + rest
        contentOctets = base128(first * 40 + second) + rest.flatMap(base128)
    }

    /// `id-at-commonName` 2.5.4.3 (RFC 5280 Appendix A.1).
    static let commonName = Self(2, 5, 4, 3)
    /// `id-ce-subjectAltName` 2.5.29.17(RFC 5280 4.2.1.6).
    static let subjectAltName = Self(2, 5, 29, 17)
    /// `id-ecPublicKey` 1.2.840.10045.2.1(RFC 5480 2.1.1).
    static let ecPublicKey = Self(1, 2, 840, 10045, 2, 1)
    /// `secp256r1` 1.2.840.10045.3.1.7(RFC 5480 2.1.1.1).
    static let secp256r1 = Self(1, 2, 840, 10045, 3, 1, 7)
    /// `ecdsa-with-SHA256` 1.2.840.10045.4.3.2(RFC 5758 3.2).
    static let ecdsaWithSHA256 = Self(1, 2, 840, 10045, 4, 3, 2)
    /// `pkcs-9-at-extensionRequest` 1.2.840.113549.1.9.14(RFC 2985 5.4.2).
    static let extensionRequest = Self(1, 2, 840, 113549, 1, 9, 14)
}

/// A string limited to the `PrintableString` character set (English letters, digits, space, and `'()+,-./:=?`) (RFC 4517 3.2
/// `PrintableCharacter`, PrintableString in X.680).
struct PrintableString: Sendable, Equatable {
    let value: String

    /// Returns `nil` for characters outside the set. Accepts empty strings and leaves length limits to the caller.
    init?(_ value: String) {
        guard value.utf8.allSatisfy(Self.isPrintable) else { return nil }
        self.value = value
    }

    private static func isPrintable(_ byte: UInt8) -> Bool {
        switch byte {
        case UInt8(ascii: "A")...UInt8(ascii: "Z"), UInt8(ascii: "a")...UInt8(ascii: "z"),
             UInt8(ascii: "0")...UInt8(ascii: "9"):
            true
        default:
            punctuation.contains(byte)
        }
    }

    private static let punctuation = Array(" '()+,-./:=?".utf8)
}

/// An ASCII-only string (0x00–0x7F, RFC 4517 3.2 `IA5String`). The SAN's `dNSName` uses this type (RFC 5280 4.2.1.6).
struct IA5String: Sendable, Equatable {
    let value: String

    /// Returns `nil` for non-ASCII characters.
    init?(_ value: String) {
        guard value.utf8.allSatisfy({ $0 < 0x80 }) else { return nil }
        self.value = value
    }
}
