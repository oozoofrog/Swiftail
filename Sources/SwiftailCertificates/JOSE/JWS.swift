import CryptoKit

/// CryptoKit failed to create a signature. P-256 signing does not fail with valid keys, but CryptoKit's declaration
/// allows failure, so this exposes a failure kind. It omits the key and input (contract behavior K3).
struct SigningFailure: Error, Sendable, Equatable {}

/// A JWS ACME request body (RFC 7515) using Flattened JSON serialization (RFC 7515 7.2.2) and an ES256 signature.
///
/// The type enforces RFC 8555 6.2 by using a protected header only (no unprotected header), a single signature,
/// and **exactly one** of `jwk` and `kid` in the header alongside `alg`, `nonce`, and `url` (`KeyReference`).
/// It derives `jwk` from the signing key's public key, so it cannot include a different key.
///
/// The protected header JSON matches the bytes from Go's `jwsEncodeJSON`. Member order is `alg`, `kid` or `jwk`, `nonce`,
/// and `url`, with no whitespace and Go `json.Marshal` string escaping (`JSONString`). RFC 7515 5.1 leaves member order unspecified,
/// so this choice enables byte comparisons against Go reference values (notes chapter 7 item 1).
///
/// CryptoKit uses internal randomness for ECDSA signatures, so runs produce different signatures even for identical input. Tests verify signatures
/// with the public key instead of comparing bytes (contract behavior C introduction).
struct JWS: Sendable, Equatable {
    /// How the protected header references the signing key (RFC 8555 6.2).
    enum KeyReference: Sendable, Equatable {
        /// `jwk` carries the signing key's public key. Used only in newAccount requests.
        case publicKey
        /// `kid` is the account URL received in the newAccount response's `Location`. Used in every other request.
        case accountURL(String)
    }

    /// The base64url encoding of the protected header JSON.
    let protected: String
    /// The base64url encoding of the body. Empty for POST-as-GET (RFC 8555 6.3).
    let payload: String
    /// The base64url encoding of R ‖ S (64 bytes represented by 86 characters, RFC 7518 3.4).
    let signature: String

    /// Creates and signs the JWS for one request.
    ///
    /// - Parameters:
    ///   - payload: The JSON body bytes. **An empty array represents POST-as-GET.** Base64url encoding empty bytes produces an empty string,
    ///     so `payload` is `""` (RFC 8555 6.3). This differs from encoding `"{}"`.
    ///   - url: The URL to send this request to. Uses the server-supplied string unchanged without reencoding (RFC 8555 6.4, contract behavior X1).
    ///   - nonce: The value from the server's `Replay-Nonce` (RFC 8555 6.5). The response reader is responsible for validating its format (contract behavior X2).
    ///   - keyReference: `jwk` or `kid`.
    ///   - key: The account private key.
    init(
        payload: [UInt8],
        url: String,
        nonce: String,
        keyReference: KeyReference,
        signedWith key: P256.Signing.PrivateKey
    ) throws(SigningFailure) {
        protected = Base64URL.encode(Self.protectedHeader(url: url, nonce: nonce, keyReference: keyReference, publicKey: key.publicKey).utf8)
        self.payload = Base64URL.encode(payload)
        do {
            // RFC 7515 5.1: The signature input is ASCII(BASE64URL(header) ‖ "." ‖ BASE64URL(body)). CryptoKit applies SHA-256.
            let signingInput = Array((protected + "." + self.payload).utf8)
            signature = Base64URL.encode(try key.signature(for: signingInput).rawRepresentation)
        } catch {
            throw SigningFailure()
        }
    }

    /// The HTTP body is `{"protected":…,"payload":…,"signature":…}` (RFC 7515 7.2.2, same order as Go's `jsonWebSignature`).
    /// `Content-Type` is `application/jose+json` (RFC 8555 6.2). Write the three values directly because they contain only base64url characters.
    var flattenedJSON: [UInt8] {
        Array(#"{"protected":"\#(protected)","payload":"\#(payload)","signature":"\#(signature)"}"#.utf8)
    }

    /// The protected header JSON (same member order as `headers` in Go's `jwsEncodeJSON`).
    private static func protectedHeader(url: String, nonce: String, keyReference: KeyReference, publicKey: P256.Signing.PublicKey) -> String {
        let key = switch keyReference {
        case .publicKey: #""jwk":"# + JWK(publicKey).canonicalJSON
        case .accountURL(let accountURL): #""kid":"# + JSONString.quoted(accountURL)
        }
        return #"{"alg":"ES256","# + key + #","nonce":"# + JSONString.quoted(nonce) + #","url":"# + JSONString.quoted(url) + "}"
    }
}
