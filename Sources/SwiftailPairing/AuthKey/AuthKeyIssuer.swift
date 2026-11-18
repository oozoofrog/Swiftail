import Foundation

/// Creates single-use auth keys through the Tailscale admin API using an OAuth client (contract `docs/contracts/SwiftailPairing.md` §4).
///
/// Creates keys to include in pairing offers. The recipient uses the key to join the tailnet without logging in. Obtains a fresh token for each
/// call and does not retain it (K2). Issuance is infrequent, so caching is unnecessary, and a token that is never retained cannot leak from storage.
/// It also does not remember the credential method (header or body) and tries the header first on each call.
/// Does not delete created keys. Unused keys expire on their own after `lifetime` (K8).
///
/// ```swift
/// let issuer = try AuthKeyIssuer(client: TailscaleOAuthClient(
///     id: clientID, secret: clientSecret, tags: ["tag:example"]))
/// let issued = try await issuer.issue(lifetime: .seconds(600))
/// ```
public struct AuthKeyIssuer: Sendable {
    /// The Tailscale admin API.
    public static let defaultBaseURL: URL = {
        guard let url = URL(string: "https://api.tailscale.com") else {
            preconditionFailure("The fixed admin API URL is valid")
        }
        return url
    }()

    private let client: TailscaleOAuthClient
    private let baseURL: URL
    private let transport: any AuthKeyTransport

    /// Validates and stores the client and API address (K4). Sends nothing yet.
    ///
    /// - Parameters:
    ///   - client: The OAuth client and the tags to attach to the key.
    ///   - baseURL: The admin API address. Requires `https`, except that plaintext http is accepted on loopback hosts (`127.0.0.1`, `::1`,
    ///     `localhost`) for test servers.
    /// - Throws: `.invalidClient`, `.invalidTags`, `.invalidBaseURL`.
    public init(client: TailscaleOAuthClient, baseURL: URL = AuthKeyIssuer.defaultBaseURL) throws(AuthKeyIssueError) {
        try self.init(client: client, baseURL: baseURL, transport: URLSessionAuthKeyTransport())
    }

    /// Allows tests to inject fake transport.
    init(client: TailscaleOAuthClient, baseURL: URL, transport: any AuthKeyTransport) throws(AuthKeyIssueError) {
        try client.validate()
        guard Self.isAllowed(baseURL) else { throw .invalidBaseURL }
        self.client = client
        self.baseURL = baseURL
        self.transport = transport
    }

    /// Creates one single-use key (K1). Sends one or two token requests and a key request.
    ///
    /// The key is single-use, and the node joins without approval and stays in the tailnet (K3). These settings are fixed to the values pairing needs
    /// and are not parameters.
    ///
    /// - Parameter lifetime: The key lifetime, truncated to whole seconds. Keep it short and match the offer lifetime. The server rejects
    ///   excessive lifetimes (`.http(status:)`).
    /// - Throws: `AuthKeyIssueError`. A lifetime shorter than 1 second produces `.invalidLifetime` without sending anything. Errors contain
    ///   no secrets, tokens, or keys.
    public func issue(lifetime: Duration) async throws(AuthKeyIssueError) -> IssuedAuthKey {
        let expirySeconds = try AuthKeyExchange.expirySeconds(for: lifetime)
        let token = try await accessToken()
        let request = AuthKeyExchange.keyRequest(baseURL: baseURL, token: token, tags: client.tags, expirySeconds: expirySeconds)
        return try AuthKeyExchange.issuedKey(from: await transport.send(request))
    }

    /// Obtains a token. Like `x/oauth2` autodetection, any failure using the header method leads to one attempt with the body method, and that
    /// result determines the classification (`RetrieveToken` in `internal/token.go`). Cancellation is the only failure that skips the retry.
    private func accessToken() async throws(AuthKeyIssueError) -> String {
        do throws(AuthKeyIssueError) {
            let request = AuthKeyExchange.tokenRequest(baseURL: baseURL, client: client, style: .header)
            return try AuthKeyExchange.accessToken(from: await transport.send(request))
        } catch .cancelled {
            throw .cancelled
        } catch {
            let request = AuthKeyExchange.tokenRequest(baseURL: baseURL, client: client, style: .parameters)
            return try AuthKeyExchange.accessToken(from: await transport.send(request))
        }
    }

    /// Always allows `https` and allows plaintext `http` only on loopback hosts. Rejects userinfo, queries, and fragments because a path is appended to the base.
    private static func isAllowed(_ url: URL) -> Bool {
        guard let host = url.host(), !host.isEmpty, url.user() == nil, url.password() == nil,
              url.query() == nil, url.fragment() == nil
        else { return false }
        switch url.scheme?.lowercased() {
        case "https": return true
        case "http": return ["127.0.0.1", "::1", "localhost"].contains(host.lowercased())
        default: return false
        }
    }
}

extension AuthKeyIssuer: CustomStringConvertible, CustomReflectable {
    /// Redacts the client secret.
    public var description: String {
        "AuthKeyIssuer(client: \(client), baseURL: \(baseURL))"
    }

    /// `dump` also shows only the redacted client.
    public var customMirror: Mirror {
        Mirror(self, children: ["client": client, "baseURL": baseURL])
    }
}
