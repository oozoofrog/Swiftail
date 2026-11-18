// Ports the Go `encoding/json` string encoding rules (`appendString`, default `json.Marshal` with escapeHTML enabled).
// Origin: Go 1.27.3 `src/encoding/json/encode.go`. Copyright 2010 The Go Authors. BSD 3-Clause License.

/// Encodes a JSON string literal (RFC 8259 §7) to the same bytes as Go's `json.Marshal`.
///
/// This gives the JWS protected header (`alg`, `kid`, `nonce`, `url`) the same bytes as Go (notes chapter 7 item 1. Matching Go's member order and
/// serialization must produce identical header and signing input bytes). In addition to the escapes required by RFC 8259 (`"`, `\`,
/// and U+0000–U+001F), escape `<`, `>`, and `&` as Go does, using forms such as `\u003c`, and write U+2028 and U+2029 as `\u2028` and `\u2029`.
/// Leave other characters unchanged. Swift `String` is always valid UTF-8, so there is no Go-style `\ufffd` fallback.
enum JSONString {
    /// The JSON string including quotes.
    static func quoted(_ value: String) -> String {
        var text = "\""
        for scalar in value.unicodeScalars {
            switch scalar.value {
            case 0x22: text += "\\\""
            case 0x5C: text += "\\\\"
            case 0x08: text += "\\b"
            case 0x0C: text += "\\f"
            case 0x0A: text += "\\n"
            case 0x0D: text += "\\r"
            case 0x09: text += "\\t"
            case 0x00...0x1F, 0x3C, 0x3E, 0x26, 0x2028, 0x2029:  // Control characters, <, >, &, U+2028, U+2029
                text += "\\u" + hex4(scalar.value)
            default:
                text.unicodeScalars.append(scalar)
            }
        }
        return text + "\""
    }

    /// Four lowercase hexadecimal digits (same as Go's `hex` table).
    private static func hex4(_ value: UInt32) -> String {
        let digits = String(value, radix: 16)
        return String(repeating: "0", count: max(0, 4 - digits.count)) + digits
    }
}
