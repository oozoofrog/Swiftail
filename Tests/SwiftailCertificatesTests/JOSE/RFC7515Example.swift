import CryptoKit
import Testing

@testable import SwiftailCertificates

/// The published P-256 example key and ES256 JWS from RFC 7515 Appendix A.3. Tests requiring a fixed key use it. It is not a real key.
enum RFC7515Example {
    static let x = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
    static let y = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
    static let d = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"

    /// The A.3.1 JWS Signing Input (`{"alg":"ES256"}` and the A.1 body).
    static let signingInput = "eyJhbGciOiJFUzI1NiJ9"
        + ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    /// The base64url encoding of the A.3.1 signature (R ‖ S).
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
