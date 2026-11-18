/// The reason an auth key could not be created (contract `docs/contracts/SwiftailPairing.md` §4 K4 and K6).
///
/// Associated values omit secrets, tokens, keys, and server bodies. The error can be logged as is.
public enum AuthKeyIssueError: Error, Sendable, Equatable {
    /// The OAuth client's `id` or `secret` violates the rules.
    case invalidClient
    /// Tags are missing or one fails the `tag:` rules.
    case invalidTags
    /// `lifetime` is shorter than 1 second (its value truncated to whole seconds is 0 or less).
    case invalidLifetime
    /// `baseURL` does not use `https` (except `http` on loopback) or contains a query, fragment, or userinfo.
    case invalidBaseURL
    /// The token request was rejected. A 400 or 401, or a 2xx with `error` or an empty `access_token`, indicates a bad client ID or secret
    /// or a deleted client.
    case clientRejected
    /// The key request was rejected with 401. The received token was not accepted.
    case unauthorized
    /// The key request was rejected with 403. The client lacks write access to `auth_keys` or cannot manage the tag.
    case forbidden
    /// Another HTTP status. Redirects (3xx) are reported here without being followed.
    case http(status: Int)
    /// The response could not be read. It was not JSON, a field was missing or malformed, or the body exceeded 64KiB.
    case invalidResponse
    /// The connection failed or dropped, or the per-request deadline (15 seconds) elapsed.
    case network
    /// The calling Task was canceled.
    case cancelled
}
