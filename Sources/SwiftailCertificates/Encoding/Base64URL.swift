/// Unpadded base64url (RFC 4648 §5, `BASE64URL` in RFC 7515 §2).
///
/// JOSE (the three JWS parts, JWK coordinates, and JWK thumbprint) and ACME (key authorization, DNS-01 TXT value, and finalize CSR)
/// use this format. The alphabet uses `-` and `_` in place of standard base64's `+` and `/` and omits trailing `=` (RFC 7515 §2).
///
/// Decoding rejects `=`, spaces and line breaks, the standard alphabet's `+` and `/`, and endings with nonzero unused bits
/// (noncanonical encoding under RFC 4648 3.5). This ensures that the same bytes cannot decode from two spellings.
enum Base64URL {
    /// Encodes bytes as base64url text.
    static func encode(_ bytes: some Sequence<UInt8>) -> String {
        var text: [UInt8] = []
        var buffer: UInt32 = 0
        var bitCount = 0
        for byte in bytes {
            buffer = buffer << 8 | UInt32(byte)
            bitCount += 8
            while bitCount >= 6 {
                bitCount -= 6
                text.append(alphabet[Int(buffer >> UInt32(bitCount) & 0x3F)])
            }
        }
        // Pad the remaining 1–5 bits on the right with zeros and encode them as one character (RFC 4648 §4 final quantum, without padding characters).
        if bitCount > 0 {
            text.append(alphabet[Int(buffer << UInt32(6 - bitCount) & 0x3F)])
        }
        return String(decoding: text, as: UTF8.self)
    }

    /// Decodes base64url text to bytes. Returns nil for characters outside the alphabet, padding, lengths with remainder 1 when divided by 4,
    /// or nonzero unused bits.
    static func decode(_ text: some StringProtocol) -> [UInt8]? {
        var bytes: [UInt8] = []
        var buffer: UInt32 = 0
        var bitCount = 0
        for character in text.utf8 {
            guard let value = sextet(character) else { return nil }
            buffer = buffer << 6 | UInt32(value)
            bitCount += 6
            if bitCount >= 8 {
                bitCount -= 8
                bytes.append(UInt8(truncatingIfNeeded: buffer >> UInt32(bitCount)))
            }
        }
        // Only 0 bits (4-character group), 4 bits (2 characters), or 2 bits (3 characters) may remain. 6 bits (1 character) indicate truncated text
        // that cannot form a byte. Nonzero unused bits are noncanonical (RFC 4648 3.5).
        guard bitCount != 6, buffer & (1 << UInt32(bitCount) - 1) == 0 else { return nil }
        return bytes
    }

    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".utf8)

    private static func sextet(_ character: UInt8) -> UInt8? {
        switch character {
        case UInt8(ascii: "A")...UInt8(ascii: "Z"): character - UInt8(ascii: "A")
        case UInt8(ascii: "a")...UInt8(ascii: "z"): character - UInt8(ascii: "a") + 26
        case UInt8(ascii: "0")...UInt8(ascii: "9"): character - UInt8(ascii: "0") + 52
        case UInt8(ascii: "-"): 62
        case UInt8(ascii: "_"): 63
        default: nil
        }
    }
}
