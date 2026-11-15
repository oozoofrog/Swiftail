// Go `encoding/json`의 문자열 인코딩 규칙을 옮겼다(`appendString`, escapeHTML이 켜진 기본 `json.Marshal`).
// 출처: Go 1.27.3 `src/encoding/json/encode.go`. Copyright 2010 The Go Authors. BSD 3-Clause License.

/// JSON 문자열 리터럴(RFC 8259 7절)을 Go `json.Marshal`과 같은 바이트로 적는다.
///
/// JWS의 보호 머리(`alg`·`kid`·`nonce`·`url`)를 Go와 같은 바이트로 만들기 위해서다(노트 7장 1: 멤버 순서와
/// 직렬화를 Go와 같게 택하면 머리와 서명 입력의 바이트가 같아야 한다). RFC 8259가 요구하는 이스케이프(`"`, `\`,
/// U+0000~U+001F)에 더해 Go처럼 `<`·`>`·`&`를 `\u003c` 꼴로, U+2028·U+2029를 `\u2028`·`\u2029`로 적는다.
/// 그 밖의 문자는 그대로 둔다. Swift의 `String`은 늘 올바른 UTF-8이므로 Go의 `\ufffd` 대체 갈래는 없다.
enum JSONString {
    /// 따옴표까지 붙인 JSON 문자열.
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
            case 0x00...0x1F, 0x3C, 0x3E, 0x26, 0x2028, 0x2029:  // 제어 문자, `<`, `>`, `&`, U+2028, U+2029
                text += "\\u" + hex4(scalar.value)
            default:
                text.unicodeScalars.append(scalar)
            }
        }
        return text + "\""
    }

    /// 소문자 16진 네 자리(Go의 `hex` 표와 같다).
    private static func hex4(_ value: UInt32) -> String {
        let digits = String(value, radix: 16)
        return String(repeating: "0", count: max(0, 4 - digits.count)) + digits
    }
}
