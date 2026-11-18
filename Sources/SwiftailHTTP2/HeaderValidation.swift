/// Validates regular header fields, excluding pseudo-headers. Centralizes the rules for sending requests, receiving response heads,
/// and receiving trailers.
///
/// - A name must be a nonempty lowercase token. The `:` character is outside the token set and is forbidden anywhere in a name,
///   including at the start (RFC 9113 §8.2.1, RFC 9110 §5.6.2).
/// - A value must be free of NUL, CR, and LF (§8.2.1).
/// - Connection-specific fields (`connection`, `keep-alive`, `proxy-connection`, `transfer-encoding`, `upgrade`) are
///   forbidden, and `te` is allowed only with the value `trailers` (§8.2.2).
///
/// A violation makes the message malformed (§8.1.1), yielding `invalidRequest` for a request or a stream error for a response.
enum HeaderValidation {
    /// Returns `true` if the regular header field conforms to the specification.
    static func isValid(_ field: HeaderField) -> Bool {
        isValidName(field.name) && isValidValue(field.value) && !isConnectionSpecific(field)
    }

    private static func isValidName(_ name: String) -> Bool {
        let bytes = name.utf8
        return !bytes.isEmpty && bytes.allSatisfy(isLowercaseTokenCharacter)
    }

    private static func isValidValue(_ value: String) -> Bool {
        !value.utf8.contains { $0 == 0x00 || $0 == 0x0a || $0 == 0x0d }
    }

    private static func isConnectionSpecific(_ field: HeaderField) -> Bool {
        switch field.name {
        case "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade":
            true
        case "te":
            field.value != "trailers"
        default:
            false
        }
    }

    /// RFC 9110 §5.6.2 tchar excluding uppercase letters (lowercase letters, digits, and ``!#$%&'*+-.^_`|~``).
    private static func isLowercaseTokenCharacter(_ byte: UInt8) -> Bool {
        switch byte {
        case UInt8(ascii: "a")...UInt8(ascii: "z"), UInt8(ascii: "0")...UInt8(ascii: "9"):
            true
        case UInt8(ascii: "!"), UInt8(ascii: "#"), UInt8(ascii: "$"), UInt8(ascii: "%"), UInt8(ascii: "&"),
            UInt8(ascii: "'"), UInt8(ascii: "*"), UInt8(ascii: "+"), UInt8(ascii: "-"), UInt8(ascii: "."),
            UInt8(ascii: "^"), UInt8(ascii: "_"), UInt8(ascii: "`"), UInt8(ascii: "|"), UInt8(ascii: "~"):
            true
        default:
            false
        }
    }
}
