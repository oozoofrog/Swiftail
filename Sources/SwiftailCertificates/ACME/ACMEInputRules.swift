import Foundation

/// ACME 서버의 응답에 거는 한도와 문자열 규칙(계약 동작 X1·X2, 한도 표).
///
/// 응답은 신뢰할 수 없는 입력이다. 주문 절차는 응답을 메시지 타입으로 바꾸는 경계에서 이 규칙으로 한 번 검사하고,
/// 그 뒤에는 검사를 통과한 문자열만 다룬다.
enum ACMEInputRules {
    /// JSON 응답 본문의 한도(64KiB).
    static let maximumJSONByteCount = 64 * 1024
    /// 인증서 사슬 응답 본문의 한도(256KiB). 전송의 본문 한도도 이 값이다(가장 큰 응답).
    static let maximumCertificateChainByteCount = 256 * 1024
    /// URL의 한도(2,048바이트).
    static let maximumURLByteCount = 2048
    /// 주문 하나의 authorization 수 상한(계약 동작 C5).
    static let maximumAuthorizationCount = 8
    /// `Replay-Nonce`와 challenge `token`의 길이 상한(512바이트).
    static let maximumTokenByteCount = 512

    /// 디렉터리·주문·authorization·challenge·finalize·인증서·계정의 URL로 쓸 수 있는가.
    ///
    /// `https` 스킴(대소문자 무시, RFC 3986 3.1), 호스트가 있음, 2,048바이트 이하. 호스트가 디렉터리와 같아야 한다는
    /// 제한은 두지 않는다(RFC 8555가 요구하지 않는다). 통과한 문자열은 다시 인코딩하지 않고 JWS `url`에 그대로 넣는다
    /// (RFC 8555 6.4).
    static func isAcceptableURL(_ text: String) -> Bool {
        guard text.utf8.count <= maximumURLByteCount,
              let components = URLComponents(string: text),
              components.scheme?.lowercased() == "https",
              let host = components.host, !host.isEmpty
        else { return false }
        return true
    }

    /// `Replay-Nonce`의 값으로 쓸 수 있는가: 채움 없는 base64url 문자만으로 된 1~512바이트(RFC 8555 6.5.1의 ABNF
    /// `1*base64url`). 길이 상한은 계약의 것이다. 어긋나는 값은 무시한다(RFC 8555 6.5.1 "MUST ignore").
    static func isAcceptableNonce(_ text: String) -> Bool {
        isBase64URLText(text)
    }

    /// challenge `token`으로 쓸 수 있는가: base64url 문자만, 채움 문자 없음(RFC 8555 8.4), 1~512바이트.
    static func isAcceptableToken(_ text: String) -> Bool {
        isBase64URLText(text)
    }

    private static func isBase64URLText(_ text: String) -> Bool {
        let bytes = text.utf8
        guard (1...maximumTokenByteCount).contains(bytes.count) else { return false }
        return bytes.allSatisfy { byte in
            switch byte {
            case UInt8(ascii: "A")...UInt8(ascii: "Z"), UInt8(ascii: "a")...UInt8(ascii: "z"),
                 UInt8(ascii: "0")...UInt8(ascii: "9"), UInt8(ascii: "-"), UInt8(ascii: "_"):
                true
            default:
                false
            }
        }
    }
}
