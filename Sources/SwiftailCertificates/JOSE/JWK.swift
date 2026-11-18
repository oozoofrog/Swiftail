import CryptoKit

/// The JWK (RFC 7517, RFC 7518 6.2.1) and thumbprint (RFC 7638) of a P-256 public key.
///
/// In ACME the account key's JWK goes in the newAccount request's `jwk` header (RFC 8555 6.2), and the thumbprint goes into the key authorization
/// (RFC 8555 8.1). Both use the same canonical JSON with only the required `crv`, `kty`, `x`, and `y` members, sorted lexicographically by name and without whitespace
/// (RFC 7638 3.2 and 3.3). Go's `jwkEncode` also uses this string for both the `jwk` header and the thumbprint (notes §3.4).
struct JWK: Sendable, Equatable {
    /// The x coordinate. Retains all 32 bytes even with leading zeros (RFC 7518 6.2.1.2).
    let x: [UInt8]
    /// The y coordinate (32 bytes, RFC 7518 6.2.1.3).
    let y: [UInt8]

    init(_ publicKey: P256.Signing.PublicKey) {
        // The uncompressed X9.63 representation is `04 ‖ X ‖ Y` with exactly 32 bytes per coordinate (SEC 1 2.3.3).
        let point = publicKey.x963Representation.dropFirst()
        x = Array(point.prefix(32))
        y = Array(point.dropFirst(32))
    }

    /// Canonical JSON: `{"crv":"P-256","kty":"EC","x":"<x>","y":"<y>"}` (RFC 7638 3.3). The values use only the base64url alphabet,
    /// so there are no characters to escape.
    var canonicalJSON: String {
        #"{"crv":"P-256","kty":"EC","x":""# + Base64URL.encode(x) + #"","y":""# + Base64URL.encode(y) + #""}"#
    }

    /// The base64url encoding of the JWK's SHA-256 thumbprint (RFC 7638 3, with SHA-256 specified by RFC 8555 8.1).
    var thumbprint: String {
        Base64URL.encode(SHA256.hash(data: Array(canonicalJSON.utf8)))
    }
}
