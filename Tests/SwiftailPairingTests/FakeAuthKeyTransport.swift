import Foundation
import Synchronization
import Testing

@testable import SwiftailPairing

/// Records requests and returns preset responses in order.
final class FakeAuthKeyTransport: AuthKeyTransport {
    private let state: Mutex<(requests: [AuthKeyHTTPRequest], responses: [Result<AuthKeyHTTPResponse, AuthKeyIssueError>])>

    init(_ responses: [Result<AuthKeyHTTPResponse, AuthKeyIssueError>]) {
        state = Mutex(([], responses))
    }

    var requests: [AuthKeyHTTPRequest] { state.withLock { $0.requests } }

    func send(_ request: AuthKeyHTTPRequest) async throws(AuthKeyIssueError) -> AuthKeyHTTPResponse {
        let next = state.withLock { state -> Result<AuthKeyHTTPResponse, AuthKeyIssueError>? in
            state.requests.append(request)
            return state.responses.isEmpty ? nil : state.responses.removeFirst()
        }
        guard let next else { throw .network }
        return try next.get()
    }
}

/// Test values that are obviously fake.
enum Example {
    static let clientID = "kEXAMPLE-client"
    static let secret = "tskey-client-EXAMPLE"
    static let token = "tskey-api-EXAMPLE-token"
    static let tokenPath = "/api/v2/oauth/token"
    static let keyPath = "/api/v2/tailnet/-/keys"
    static let key = "tskey-auth-EXAMPLE"
    static let client = TailscaleOAuthClient(id: clientID, secret: secret, tags: ["tag:example"])
    static func url(_ string: String) throws -> URL {
        try #require(URL(string: string))
    }

    static func baseURL() throws -> URL { try url("https://api.invalid") }

    static func response(_ status: Int, _ json: String) -> Result<AuthKeyHTTPResponse, AuthKeyIssueError> {
        .success(AuthKeyHTTPResponse(status: status, body: Array(json.utf8)))
    }

    static let tokenOK = response(200, #"{"access_token":"tskey-api-EXAMPLE-token","token_type":"Bearer","expires_in":3600}"#)
    static let keyOK = response(200, #"{"id":"kEXAMPLE","key":"tskey-auth-EXAMPLE","created":"2026-01-01T00:00:00Z","expires":"2026-01-01T00:10:00Z","capabilities":{}}"#)
    static let basic = "Basic " + Data("kEXAMPLE-client:tskey-client-EXAMPLE".utf8).base64EncodedString()
    static let parametersForm = "client_id=kEXAMPLE-client&client_secret=tskey-client-EXAMPLE&grant_type=client_credentials"
}
