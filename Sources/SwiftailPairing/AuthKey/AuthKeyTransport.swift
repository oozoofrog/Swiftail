import Foundation

/// An HTTP round trip to the admin API. Implemented by the edge (`URLSessionAuthKeyTransport`) and tests (fake transport).
///
/// Returns 3xx responses unchanged without following redirects (contract `docs/contracts/SwiftailPairing.md` §4 K5).
/// Throws only `.network`, `.invalidResponse` (body limit exceeded), or `.cancelled`.
protocol AuthKeyTransport: Sendable {
    func send(_ request: AuthKeyHTTPRequest) async throws(AuthKeyIssueError) -> AuthKeyHTTPResponse
}

/// A `POST` request to the admin API. Both requests use POST.
///
/// `authorization` or `body` contains secrets (client credentials or tokens). Keep them out of logs.
struct AuthKeyHTTPRequest: Sendable, Equatable {
    var url: URL
    /// The full `Authorization` header value (`Basic …`, `Bearer …`). Omitted if nil (a token request with credentials in its body).
    var authorization: String?
    var contentType: String
    var body: [UInt8]
}

/// A response from the admin API. This flow reads only the status and body.
struct AuthKeyHTTPResponse: Sendable, Equatable {
    var status: Int
    /// The body up to the limit. The transport throws `.invalidResponse` if the limit is exceeded.
    var body: [UInt8]
}
