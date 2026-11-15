import CryptoKit
import Testing

@testable import SwiftailCertificates

/// RFC 7515 부록 A.3의 공개된 P-256 예시 키와 ES256 JWS. 고정 키가 필요한 시험이 쓴다(실제 키가 아니다).
enum RFC7515Example {
    static let x = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
    static let y = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
    static let d = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"

    /// A.3.1의 JWS Signing Input(`{"alg":"ES256"}`과 A.1의 본문).
    static let signingInput = "eyJhbGciOiJFUzI1NiJ9"
        + ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    /// A.3.1의 서명(R ‖ S)의 base64url.
    static let signature = "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"

    static func privateKey() throws -> P256.Signing.PrivateKey {
        try P256.Signing.PrivateKey(rawRepresentation: try #require(Base64URL.decode(d)))
    }

    static func publicKey() throws -> P256.Signing.PublicKey {
        let x = try #require(Base64URL.decode(x))
        let y = try #require(Base64URL.decode(y))
        return try P256.Signing.PublicKey(x963Representation: [0x04] + x + y)
    }
}
