import CryptoKit

/// P-256 공개 키의 JWK(RFC 7517, RFC 7518 6.2.1)와 그 지문(RFC 7638).
///
/// ACME에서 계정 키의 JWK는 newAccount 요청의 `jwk` 머리에 실리고(RFC 8555 6.2), 지문은 키 인가에 들어간다
/// (RFC 8555 8.1). 둘 다 같은 정규 JSON을 쓴다: 필수 멤버 `crv`·`kty`·`x`·`y`만, 이름의 사전 순, 공백 없이
/// (RFC 7638 3.2·3.3). Go `jwkEncode`도 이 문자열을 `jwk` 머리와 지문에 함께 쓴다(노트 3.4).
struct JWK: Sendable, Equatable {
    /// x 좌표. 앞자리가 0이어도 32바이트를 유지한다(RFC 7518 6.2.1.2).
    let x: [UInt8]
    /// y 좌표. 32바이트(RFC 7518 6.2.1.3).
    let y: [UInt8]

    init(_ publicKey: P256.Signing.PublicKey) {
        // X9.63 비압축 표현은 `04 ‖ X ‖ Y`이고 좌표마다 고정 32바이트다(SEC 1 2.3.3).
        let point = publicKey.x963Representation.dropFirst()
        x = Array(point.prefix(32))
        y = Array(point.dropFirst(32))
    }

    /// 정규 JSON: `{"crv":"P-256","kty":"EC","x":"<x>","y":"<y>"}`(RFC 7638 3.3). 값은 base64url 알파벳뿐이라
    /// 이스케이프할 문자가 없다.
    var canonicalJSON: String {
        #"{"crv":"P-256","kty":"EC","x":""# + Base64URL.encode(x) + #"","y":""# + Base64URL.encode(y) + #""}"#
    }

    /// JWK SHA-256 지문의 base64url(RFC 7638 3, RFC 8555 8.1이 SHA-256을 정한다).
    var thumbprint: String {
        Base64URL.encode(SHA256.hash(data: Array(canonicalJSON.utf8)))
    }
}
