import Foundation

/// Limits and string rules for ACME server responses (contract behaviors X1 and X2, limits table).
///
/// Responses are untrusted input. The order flow checks these rules once at the boundary where it converts responses to message types.
/// It then handles only strings that passed validation.
enum ACMEInputRules {
    /// Maximum JSON response body size (64KiB).
    static let maximumJSONByteCount = 64 * 1024
    /// Maximum certificate chain response body size (256KiB). This is also the transport body limit because it is the largest response.
    static let maximumCertificateChainByteCount = 256 * 1024
    /// Maximum URL length (2,048 bytes).
    static let maximumURLByteCount = 2048
    /// Maximum number of authorizations per order (contract behavior C5).
    static let maximumAuthorizationCount = 8
    /// Maximum length of a `Replay-Nonce` or challenge `token` (512 bytes).
    static let maximumTokenByteCount = 512

    /// Checks whether a URL is suitable for a directory, order, authorization, challenge, finalize, certificate, or account.
    ///
    /// Requires the `https` scheme (case-insensitive, RFC 3986 3.1), a host, no userinfo, at most 2,048 bytes, and no change to the string
    /// when forming a URL. Validated strings go into the JWS `url` unchanged (RFC 8555 6.4). Reject spaces and malformed `%` escapes
    /// because `URL(string:)` would encode them and make the signed `url` differ from the actual request.
    static func isAcceptableURL(_ text: String) -> Bool {
        guard text.utf8.count <= maximumURLByteCount,
              let components = URLComponents(string: text),
              components.scheme?.lowercased() == "https",
              let host = components.host, !host.isEmpty,
              components.user == nil, components.password == nil,
              URL(string: text)?.absoluteString == text
        else { return false }
        return true
    }

    /// Checks whether two URLs have the same origin (scheme, host, and port). The order flow sends requests only to the directory origin.
    /// TLS has verified only the directory server, so the flow never follows a URL it provides to send account-key-signed requests to another host
    /// (including loopback). RFC 8555 does not require same-origin requests, but Let's Encrypt and pebble place all resources at the directory origin.
    static func hasSameOrigin(_ text: String, as other: String) -> Bool {
        guard let a = URLComponents(string: text), let b = URLComponents(string: other) else { return false }
        return a.scheme?.lowercased() == b.scheme?.lowercased() && a.host?.lowercased() == b.host?.lowercased() && a.port == b.port
    }

    /// Checks whether a value is usable as `Replay-Nonce`. It must contain 1–512 bytes of unpadded base64url characters (RFC 8555 6.5.1 ABNF
    /// `1*base64url`). The contract supplies the upper limit. Ignore invalid values (RFC 8555 6.5.1 "MUST ignore").
    static func isAcceptableNonce(_ text: String) -> Bool {
        isBase64URLText(text)
    }

    /// Checks whether a value is usable as a challenge `token`. It must contain 1–512 bytes of base64url characters without padding (RFC 8555 8.4).
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
