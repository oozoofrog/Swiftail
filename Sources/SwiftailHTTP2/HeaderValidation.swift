/// 헤더 필드(의사 헤더가 아닌 일반 필드) 검증. 요청을 보낼 때, 응답 머리를 받을 때, 트레일러를 받을 때
/// 같은 규칙을 쓰도록 한 곳에 둔다.
///
/// - 이름은 비어 있지 않은 token 문자열이고 소문자여야 한다. `:`는 token 문자가 아니므로 이름의 맨 앞이든
///   중간이든 들어갈 수 없다(RFC 9113 §8.2.1, RFC 9110 §5.6.2).
/// - 값에는 NUL·CR·LF가 없어야 한다(§8.2.1).
/// - 연결 전용 필드(`connection`, `keep-alive`, `proxy-connection`, `transfer-encoding`, `upgrade`)는
///   없어야 하고, `te`는 값이 `trailers`일 때만 허용된다(§8.2.2).
///
/// 어긋나면 그 메시지는 잘못된 것이다(§8.1.1): 요청이면 `invalidRequest`, 응답이면 스트림 오류다.
enum HeaderValidation {
    /// 의사 헤더가 아닌 필드 하나가 규격에 맞으면 `true`.
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

    /// RFC 9110 §5.6.2의 tchar 중 대문자를 뺀 것: 소문자, 숫자, ``!#$%&'*+-.^_`|~``.
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
