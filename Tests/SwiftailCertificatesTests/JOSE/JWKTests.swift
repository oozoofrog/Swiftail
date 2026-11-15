// 계약 7절 시험 5: JWK와 지문, 키 인가와 DNS-01 TXT 값.

import CryptoKit
import Testing

@testable import SwiftailCertificates

@Suite("JWK와 지문")
struct JWKTests {
    @Test("RFC 7515 부록 A.3 키의 JWK 좌표와 정규 JSON (RFC 7638 3.3)")
    func rfc7515Key() throws {
        let jwk = JWK(try RFC7515Example.publicKey())
        #expect(Base64URL.encode(jwk.x) == RFC7515Example.x)
        #expect(Base64URL.encode(jwk.y) == RFC7515Example.y)
        #expect(jwk.canonicalJSON == #"{"crv":"P-256","kty":"EC","x":"\#(RFC7515Example.x)","y":"\#(RFC7515Example.y)"}"#)
        // 공개된 d로 만든 개인 키의 공개 키도 같은 JWK다(예시 키가 서로 맞는지).
        #expect(JWK(try RFC7515Example.privateKey().publicKey) == jwk)
    }

    /// 기대값은 위 정규 JSON을 `openssl dgst -sha256 -binary`에 넣고 base64url로 바꿔 따로 만들었다.
    @Test("P-256 지문: 정규 JSON의 SHA-256을 base64url로 (RFC 7638 3, RFC 8555 8.1)")
    func thumbprint() throws {
        #expect(JWK(try RFC7515Example.publicKey()).thumbprint == "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U")
    }

    /// RFC 7638 3.1의 예는 RSA 키라 JWK 타입으로 만들 수 없다. 정규 JSON → SHA-256 → base64url의 형식만 본다.
    @Test("RFC 7638 3.1의 지문 계산 형식(RSA 예)")
    func rfc7638Example() {
        let json = #"{"e":"AQAB","kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}"#
        #expect(Base64URL.encode(SHA256.hash(data: Array(json.utf8))) == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")
    }

    @Test("앞자리가 0인 좌표도 32바이트로 적는다 (RFC 7518 6.2.1.2·6.2.1.3)")
    func leadingZeroCoordinates() throws {
        var foundX = false, foundY = false
        for _ in 0..<20_000 where !(foundX && foundY) {
            let jwk = JWK(P256.Signing.PrivateKey().publicKey)
            #expect(jwk.x.count == 32 && jwk.y.count == 32)
            #expect(Base64URL.encode(jwk.x).utf8.count == 43 && Base64URL.encode(jwk.y).utf8.count == 43)
            foundX = foundX || jwk.x[0] == 0
            foundY = foundY || jwk.y[0] == 0
        }
        #expect(foundX && foundY)
    }

    /// RFC 8555 8.4 예의 token과 RFC 7515 A.3 키. 기대값은 openssl로 따로 만들었다.
    @Test("키 인가와 DNS-01 TXT 값 (RFC 8555 8.1·8.4)")
    func keyAuthorization() throws {
        let token = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA"
        let authorization = KeyAuthorization(token: token, accountKey: JWK(try RFC7515Example.publicKey()))
        #expect(authorization.value == token + ".oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U")
        #expect(authorization.dns01TXTValue == "ZaJgFtIV4WA0t2MzN7kbSk0sfRd2GZjaxRqaSTAK6lI")
        #expect(authorization.dns01TXTValue.utf8.count == 43)
    }
}
