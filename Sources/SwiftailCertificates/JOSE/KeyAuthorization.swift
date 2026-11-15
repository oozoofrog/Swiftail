import CryptoKit

/// ACME challenge의 키 인가(RFC 8555 8.1)와 DNS-01 TXT 값(RFC 8555 8.4).
///
/// ```
/// keyAuthorization = token ‖ "." ‖ base64url(JWK 지문)
/// TXT 값           = base64url(SHA-256(keyAuthorization))
/// ```
///
/// 키 인가와 TXT 값은 로그에 남기지 않는다(계약 동작 K2).
struct KeyAuthorization: Sendable, Equatable {
    /// `token.thumbprint`.
    let value: String

    /// - Parameters:
    ///   - token: challenge의 `token`. base64url 알파벳만으로 된 1~512바이트인지는 응답을 읽는 쪽이 이미 검사했다
    ///     (계약 동작 X2, RFC 8555 8.4).
    ///   - accountKey: 계정 공개 키의 JWK.
    init(token: String, accountKey: JWK) {
        value = token + "." + accountKey.thumbprint
    }

    /// `_acme-challenge.<이름>`의 TXT 레코드에 올릴 값. SHA-256 32바이트의 base64url이므로 43 ASCII 바이트이고,
    /// DNS 표시용 따옴표는 붙이지 않는다(노트 3.5).
    var dns01TXTValue: String {
        Base64URL.encode(SHA256.hash(data: Array(value.utf8)))
    }
}
