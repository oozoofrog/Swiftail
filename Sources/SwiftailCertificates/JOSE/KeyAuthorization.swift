import CryptoKit

/// The key authorization for an ACME challenge (RFC 8555 8.1) and its DNS-01 TXT value (RFC 8555 8.4).
///
/// ```
/// keyAuthorization = token ‖ "." ‖ base64url(JWK thumbprint)
/// TXT value        = base64url(SHA-256(keyAuthorization))
/// ```
///
/// Keep key authorization and TXT values out of logs (contract behavior K2).
struct KeyAuthorization: Sendable, Equatable {
    /// `token.thumbprint`.
    let value: String

    /// - Parameters:
    ///   - `token`: The challenge token. The response reader has already verified that it contains 1–512 bytes of base64url characters
    ///     (contract behavior X2, RFC 8555 8.4).
    ///   - accountKey: The account public key's JWK.
    init(token: String, accountKey: JWK) {
        value = token + "." + accountKey.thumbprint
    }

    /// The value to publish in the TXT record for `_acme-challenge.<name>`. Base64url encoding the 32 SHA-256 bytes produces 43 ASCII bytes.
    /// No DNS presentation quotes are added (notes §3.5).
    var dns01TXTValue: String {
        Base64URL.encode(SHA256.hash(data: Array(value.utf8)))
    }
}
