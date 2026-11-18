// Contract §7 test 6 in `docs/contracts/SwiftailPairing.md` uses a fake transport to test request shape (K1), response and error classification (K6), validation (K4),
// lifetime (K3), and redaction. The tests make no calls to the real management API.

import Foundation
import Testing

@testable import SwiftailPairing

@Suite("Auth key issuance")
struct AuthKeyIssuerTests {
    // MARK: K1 Request shape

    @Test("Token request using the header: POST /api/v2/oauth/token, Basic(QueryEscape(id):QueryEscape(secret)), and a form body")
    func tokenRequestHeaderStyle() throws {
        let request = AuthKeyExchange.tokenRequest(baseURL: try Example.baseURL(), client: Example.client, style: .header)
        #expect(request.url.absoluteString == "https://api.invalid/api/v2/oauth/token")
        #expect(request.contentType == "application/x-www-form-urlencoded")
        #expect(request.body == Array("grant_type=client_credentials".utf8))
        #expect(request.authorization == Example.basic)
    }

    @Test("Token request using the body sends client_id and client_secret in key order in the form without Authorization")
    func tokenRequestParameterStyle() throws {
        let request = AuthKeyExchange.tokenRequest(baseURL: try Example.baseURL(), client: Example.client, style: .parameters)
        #expect(request.url.absoluteString == "https://api.invalid/api/v2/oauth/token")
        #expect(request.authorization == nil)
        #expect(request.contentType == "application/x-www-form-urlencoded")
        #expect(String(decoding: request.body, as: UTF8.self) == Example.parametersForm)
    }

    @Test("queryEscape matches Go url.QueryEscape")
    func queryEscape() {
        #expect(AuthKeyExchange.queryEscape("aZ09-_.~") == "aZ09-_.~")
        #expect(AuthKeyExchange.queryEscape("a b") == "a+b")
        #expect(AuthKeyExchange.queryEscape(":/?#[]@!$&'()*+,;=%\"") == "%3A%2F%3F%23%5B%5D%40%21%24%26%27%28%29%2A%2B%2C%3B%3D%25%22")
    }

    @Test("Key request: POST /api/v2/tailnet/-/keys, Bearer, and a JSON body with fixed values")
    func keyRequestShape() throws {
        let request = AuthKeyExchange.keyRequest(
            baseURL: try Example.url("https://api.invalid/"), token: Example.token, tags: ["tag:example", "tag:b"], expirySeconds: 600
        )
        #expect(request.url.absoluteString == "https://api.invalid/api/v2/tailnet/-/keys")
        #expect(request.authorization == "Bearer tskey-api-EXAMPLE-token")
        #expect(request.contentType == "application/json")
        #expect(String(decoding: request.body, as: UTF8.self) ==
            #"{"capabilities":{"devices":{"create":{"ephemeral":false,"preauthorized":true,"reusable":false,"tags":["tag:example","tag:b"]}}},"expirySeconds":600}"#)
    }

    @Test("issue gets a token using the header and uses the token to create a key")
    func issueFlow() async throws {
        let transport = FakeAuthKeyTransport([Example.tokenOK, Example.keyOK])
        let issuer = try AuthKeyIssuer(client: Example.client, baseURL: try Example.baseURL(), transport: transport)
        let issued = try await issuer.issue(lifetime: .seconds(600))
        #expect(issued.key == Example.key)
        #expect(issued.expires == Date(timeIntervalSince1970: 1_767_226_200))

        let requests = transport.requests
        #expect(requests.map(\.url.path) == [Example.tokenPath, Example.keyPath])
        #expect(requests.first?.authorization == Example.basic)
        #expect(requests.last?.authorization == "Bearer " + Example.token)
        let body = try #require(requests.last.map { String(decoding: $0.body, as: UTF8.self) })
        #expect(body.contains(#""expirySeconds":600"#) && body.contains(#""tags":["tag:example"]"#))
    }

    @Test("If the header method fails, retry once using the body", arguments: [
        Example.response(401, #"{"error":"invalid_client"}"#),
        Example.response(400, "{}"),
        Example.response(500, ""),
        Example.response(200, #"{"error":"invalid_client"}"#),
        Example.response(200, "not json"),
        .failure(.network),
    ])
    func parameterFallback(first: Result<AuthKeyHTTPResponse, AuthKeyIssueError>) async throws {
        let transport = FakeAuthKeyTransport([first, Example.tokenOK, Example.keyOK])
        let issuer = try AuthKeyIssuer(client: Example.client, baseURL: try Example.baseURL(), transport: transport)
        let issued = try await issuer.issue(lifetime: .seconds(600))
        #expect(issued.key == Example.key)
        let requests = transport.requests
        #expect(requests.map(\.url.path) == [Example.tokenPath, Example.tokenPath, Example.keyPath])
        #expect(requests[0].authorization == Example.basic)
        #expect(requests[1].authorization == nil)
        #expect(String(decoding: requests[1].body, as: UTF8.self) == Example.parametersForm)
    }

    @Test("Cancellation prevents a retry")
    func noFallbackOnCancel() async throws {
        let transport = FakeAuthKeyTransport([.failure(.cancelled), Example.tokenOK, Example.keyOK])
        let issuer = try AuthKeyIssuer(client: Example.client, baseURL: try Example.baseURL(), transport: transport)
        await #expect(throws: AuthKeyIssueError.cancelled) { try await issuer.issue(lifetime: .seconds(60)) }
        #expect(transport.requests.count == 1)
    }

    @Test("Each call obtains a fresh token and chooses a credential method anew (K2)")
    func tokenPerCall() async throws {
        let rejected = Example.response(401, "{}")
        let transport = FakeAuthKeyTransport([rejected, Example.tokenOK, Example.keyOK, Example.tokenOK, Example.keyOK])
        let issuer = try AuthKeyIssuer(client: Example.client, baseURL: try Example.baseURL(), transport: transport)
        _ = try await issuer.issue(lifetime: .seconds(60))
        _ = try await issuer.issue(lifetime: .seconds(60))
        #expect(transport.requests.map(\.url.path) == [
            Example.tokenPath, Example.tokenPath, Example.keyPath, Example.tokenPath, Example.keyPath,
        ])
        #expect(transport.requests[3].authorization == Example.basic, "The second call also tries the header method first")
    }

    // MARK: K3 Lifetime

    @Test("The lifetime is rounded down to whole seconds", arguments: [
        (Duration.milliseconds(1900), Int64(1)), (.seconds(600), 600), (.seconds(7_776_001), 7_776_001), (.seconds(Int64.max), Int64.max),
    ])
    func lifetimeTruncation(lifetime: Duration, seconds: Int64) throws {
        #expect(try AuthKeyExchange.expirySeconds(for: lifetime) == seconds)
    }

    @Test("A lifetime shorter than 1 second returns invalidLifetime without sending anything", arguments: [
        Duration.zero, .milliseconds(999), .seconds(-5), .nanoseconds(-1),
    ])
    func invalidLifetime(lifetime: Duration) async throws {
        let transport = FakeAuthKeyTransport([Example.tokenOK, Example.keyOK])
        let issuer = try AuthKeyIssuer(client: Example.client, baseURL: try Example.baseURL(), transport: transport)
        await #expect(throws: AuthKeyIssueError.invalidLifetime) { try await issuer.issue(lifetime: lifetime) }
        #expect(transport.requests.isEmpty)
    }

    // MARK: K6 Classification

    @Test("If both methods fail, the last token response determines the classification", arguments: [
        (Example.response(400, #"{"error":"invalid_client"}"#), AuthKeyIssueError.clientRejected),
        (Example.response(401, "{}"), .clientRejected),
        (Example.response(200, #"{"error":"invalid_client","access_token":"tskey-api-EXAMPLE"}"#), .clientRejected),
        (Example.response(200, #"{"access_token":""}"#), .clientRejected),
        (Example.response(200, #"{"token_type":"Bearer"}"#), .clientRejected),
        (Example.response(403, "{}"), .http(status: 403)),
        (Example.response(500, "{}"), .http(status: 500)),
        (Example.response(302, ""), .http(status: 302)),
        (Example.response(200, "not json"), .invalidResponse),
        (Example.response(200, #"{"access_token":"a\r\nX-Injected: 1"}"#), .invalidResponse),
        (.failure(.network), .network),
        (.failure(.invalidResponse), .invalidResponse),
        (.failure(.cancelled), .cancelled),
    ])
    func tokenClassification(last: Result<AuthKeyHTTPResponse, AuthKeyIssueError>, expected: AuthKeyIssueError) async throws {
        let transport = FakeAuthKeyTransport([Example.response(401, "{}"), last])
        let issuer = try AuthKeyIssuer(client: Example.client, baseURL: try Example.baseURL(), transport: transport)
        await #expect(throws: expected) { try await issuer.issue(lifetime: .seconds(60)) }
        #expect(transport.requests.count == 2, "Without a token, no key is requested")
    }

    @Test("A 2xx token response succeeds without filtering on token_type", arguments: [
        Example.response(201, #"{"access_token":"tskey-api-EXAMPLE-token"}"#),
        Example.response(200, #"{"access_token":"tskey-api-EXAMPLE-token","token_type":"bearer"}"#),
        Example.response(200, #"{"access_token":"tskey-api-EXAMPLE-token","token_type":"mac"}"#),
        Example.response(200, #"{"access_token":"tskey-api-EXAMPLE-token","error":""}"#),
    ])
    func tokenAccepted(response: Result<AuthKeyHTTPResponse, AuthKeyIssueError>) async throws {
        let transport = FakeAuthKeyTransport([response, Example.keyOK])
        let issuer = try AuthKeyIssuer(client: Example.client, baseURL: try Example.baseURL(), transport: transport)
        _ = try await issuer.issue(lifetime: .seconds(60))
        #expect(transport.requests.count == 2)
        #expect(transport.requests.last?.authorization == "Bearer tskey-api-EXAMPLE-token")
    }

    @Test("Key response classification", arguments: [
        (Example.response(401, "{}"), AuthKeyIssueError.unauthorized),
        (Example.response(403, #"{"message":"tag not permitted"}"#), .forbidden),
        (Example.response(400, "{}"), .http(status: 400)),
        (Example.response(201, "{}"), .http(status: 201)),
        (Example.response(307, ""), .http(status: 307)),
        (Example.response(503, ""), .http(status: 503)),
        (Example.response(200, "[]"), .invalidResponse),
        (Example.response(200, #"{"expires":"2026-01-01T00:10:00Z"}"#), .invalidResponse),
        (Example.response(200, #"{"key":"tskey-api-EXAMPLE","expires":"2026-01-01T00:10:00Z"}"#), .invalidResponse),
        (Example.response(200, #"{"key":"tskey-auth-EXAMPLE","expires":"tomorrow"}"#), .invalidResponse),
        (Example.response(200, #"{"key":"tskey-auth-EXAMPLE"}"#), .invalidResponse),
        (Example.response(200, #"{"key":"tskey-auth-EX AMPLE","expires":"2026-01-01T00:10:00Z"}"#), .invalidResponse),
        (.failure(.network), .network),
    ])
    func keyClassification(response: Result<AuthKeyHTTPResponse, AuthKeyIssueError>, expected: AuthKeyIssueError) async throws {
        let transport = FakeAuthKeyTransport([Example.tokenOK, response])
        let issuer = try AuthKeyIssuer(client: Example.client, baseURL: try Example.baseURL(), transport: transport)
        await #expect(throws: expected) { try await issuer.issue(lifetime: .seconds(60)) }
        #expect(transport.requests.count == 2, "The key request is never retried")
    }

    @Test("The expiration time accepts fractional seconds")
    func fractionalExpiry() async throws {
        let key = Example.response(200, #"{"key":"tskey-auth-EXAMPLE","expires":"2026-01-01T00:10:00.5Z"}"#)
        let issuer = try AuthKeyIssuer(
            client: Example.client, baseURL: try Example.baseURL(), transport: FakeAuthKeyTransport([Example.tokenOK, key])
        )
        let issued = try await issuer.issue(lifetime: .seconds(600))
        #expect(issued.expires == Date(timeIntervalSince1970: 1_767_226_200.5))
    }

    // MARK: K4 Validation

    @Test("The client ID and secret accept only characters left unchanged by QueryEscape", arguments: [
        ("", Example.secret), ("id EXAMPLE", Example.secret), ("id:EXAMPLE", Example.secret), ("id+EXAMPLE", Example.secret),
        ("id\nEXAMPLE", Example.secret), ("아이디", Example.secret), (String(repeating: "a", count: 513), Example.secret),
        (Example.clientID, "EXAMPLE"), (Example.clientID, "tskey-auth-EXAMPLE"), (Example.clientID, "tskey-client-EX/AMPLE"),
        (Example.clientID, "tskey-client-EXAMPLE="), (Example.clientID, "tskey-client-" + String(repeating: "a", count: 500)),
    ])
    func invalidClient(id: String, secret: String) throws {
        let baseURL = try Example.baseURL()
        #expect(throws: AuthKeyIssueError.invalidClient) {
            try AuthKeyIssuer(client: TailscaleOAuthClient(id: id, secret: secret, tags: ["tag:example"]), baseURL: baseURL)
        }
    }

    @Test("A-Za-z0-9-_.~ is accepted up to 512 bytes")
    func validClientBoundary() throws {
        let client = TailscaleOAuthClient(
            id: String(repeating: "a", count: 512), secret: "tskey-client-AZaz09-_.~", tags: ["tag:example"]
        )
        _ = try AuthKeyIssuer(client: client, baseURL: try Example.baseURL())
    }

    @Test("Tags follow the Go tailcfg.CheckTag rules", arguments: [
        [], ["example"], ["tag:"], ["tag:1abc"], ["tag:-abc"], ["tag:a_b"], ["tag:a.b"], ["tag:a b"], ["tag:é"],
        ["TAG:example"], ["tag:example", "tag:"],
    ])
    func invalidTags(tags: [String]) throws {
        let baseURL = try Example.baseURL()
        #expect(throws: AuthKeyIssueError.invalidTags) {
            try AuthKeyIssuer(client: TailscaleOAuthClient(id: Example.clientID, secret: Example.secret, tags: tags), baseURL: baseURL)
        }
    }

    @Test("Valid tags have no length limit", arguments: [
        ["tag:a"], ["tag:Example-1"], ["tag:a-"], ["tag:" + String(repeating: "x", count: 1000)], ["tag:example", "tag:b"],
    ])
    func validTags(tags: [String]) throws {
        _ = try AuthKeyIssuer(client: TailscaleOAuthClient(id: Example.clientID, secret: Example.secret, tags: tags), baseURL: try Example.baseURL())
    }

    @Test("baseURL requires https or loopback http", arguments: [
        ("https://api.invalid", true), ("https://api.invalid/", true), ("https://api.invalid:8443/prefix", true),
        ("http://127.0.0.1:8080", true), ("http://localhost:8080", true), ("http://[::1]:8080", true),
        ("http://api.invalid", false), ("http://10.0.0.1", false), ("ftp://127.0.0.1", false),
        ("https://user:pw@api.invalid", false), ("https://api.invalid?x=1", false), ("https://api.invalid#x", false),
        ("file:///api", false),
    ])
    func baseURL(url: String, allowed: Bool) throws {
        let baseURL = try Example.url(url)
        let make = { () throws(AuthKeyIssueError) in
            _ = try AuthKeyIssuer(client: Example.client, baseURL: baseURL)
        }
        if allowed {
            try make()
        } else {
            #expect(throws: AuthKeyIssueError.invalidBaseURL) { try make() }
        }
    }

    @Test("If the base has a path, append to it")
    func baseURLWithPath() throws {
        let request = AuthKeyExchange.tokenRequest(baseURL: try Example.url("https://api.invalid/prefix/"), client: Example.client, style: .header)
        #expect(request.url.absoluteString == "https://api.invalid/prefix/api/v2/oauth/token")
    }

    // MARK: Redaction

    @Test("description and dump omit secrets and keys")
    func redaction() async throws {
        let issuer = try AuthKeyIssuer(
            client: Example.client, baseURL: try Example.baseURL(), transport: FakeAuthKeyTransport([Example.tokenOK, Example.keyOK])
        )
        let issued = try await issuer.issue(lifetime: .seconds(600))
        for value in [Example.client as Any, issuer, issued] {
            var dumped = ""
            dump(value, to: &dumped)
            for text in [String(describing: value), String(reflecting: value), dumped] {
                #expect(!text.contains("EXAMPLE-token") && !text.contains(Example.secret) && !text.contains(Example.key), "\(text)")
                #expect(text.contains("<redacted>"))
            }
        }
        #expect(String(describing: Example.client).contains(Example.clientID))
    }

    @Test("Error values omit secrets, tokens, and server bodies")
    func errorsCarryNoSecrets() async throws {
        let echo = Example.response(403, #"{"message":"tskey-api-EXAMPLE-token tskey-client-EXAMPLE"}"#)
        let issuer = try AuthKeyIssuer(
            client: Example.client, baseURL: try Example.baseURL(), transport: FakeAuthKeyTransport([Example.tokenOK, echo])
        )
        do {
            _ = try await issuer.issue(lifetime: .seconds(60))
            Issue.record("Unexpected success for a 403 response")
        } catch {
            var dumped = ""
            dump(error, to: &dumped)
            for text in [String(describing: error), String(reflecting: error), error.localizedDescription, dumped] {
                #expect(!text.contains("EXAMPLE"), "\(text)")
            }
        }
    }
}
