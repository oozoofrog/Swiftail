// Contract §7 test 5: JWK and thumbprint, key authorization, and DNS-01 TXT value.

import CryptoKit
import Testing

@testable import SwiftailCertificates

@Suite("JWK and thumbprint")
struct JWKTests {
    @Test("JWK coordinates and canonical JSON for the RFC 7515 Appendix A.3 key (RFC 7638 3.3)")
    func rfc7515Key() throws {
        let jwk = JWK(try RFC7515Example.publicKey())
        #expect(Base64URL.encode(jwk.x) == RFC7515Example.x)
        #expect(Base64URL.encode(jwk.y) == RFC7515Example.y)
        #expect(jwk.canonicalJSON == #"{"crv":"P-256","kty":"EC","x":"\#(RFC7515Example.x)","y":"\#(RFC7515Example.y)"}"#)
        // The public key derived from the private key built using the published d yields the same JWK, confirming that the example keys match.
        #expect(JWK(try RFC7515Example.privateKey().publicKey) == jwk)
    }

    /// The expected value was generated separately by passing the canonical JSON above to `openssl dgst -sha256 -binary` and converting to base64url.
    @Test("P-256 thumbprint: base64url of the canonical JSON's SHA-256 (RFC 7638 3, RFC 8555 8.1)")
    func thumbprint() throws {
        #expect(JWK(try RFC7515Example.publicKey()).thumbprint == "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U")
    }

    /// The RFC 7638 3.1 example uses an RSA key, which cannot be represented by the JWK type. Check only the canonical JSON → SHA-256 → base64url format.
    @Test("RFC 7638 3.1 thumbprint calculation format (RSA example)")
    func rfc7638Example() {
        let json = #"{"e":"AQAB","kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}"#
        #expect(Base64URL.encode(SHA256.hash(data: Array(json.utf8))) == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")
    }

    @Test("Coordinates with leading zeros are also written as 32 bytes (RFC 7518 6.2.1.2 and 6.2.1.3)")
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

    /// Uses the token from RFC 8555 8.4 and the key from RFC 7515 A.3. The expected value was generated separately with openssl.
    @Test("Key authorization and DNS-01 TXT value (RFC 8555 8.1 and 8.4)")
    func keyAuthorization() throws {
        let token = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA"
        let authorization = KeyAuthorization(token: token, accountKey: JWK(try RFC7515Example.publicKey()))
        #expect(authorization.value == token + ".oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U")
        #expect(authorization.dns01TXTValue == "ZaJgFtIV4WA0t2MzN7kbSk0sfRd2GZjaxRqaSTAK6lI")
        #expect(authorization.dns01TXTValue.utf8.count == 43)
    }
}
