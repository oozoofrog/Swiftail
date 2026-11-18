// `ControlClient.logOut()`: contract `docs/contracts/SwiftailHost.md`, "Logout," behavior O, "Unit" tests.
// Runs against a fake control server (`SetDNSFakeControlServer`) over a real connection (upgrade → Noise → HTTP/2). Does not call `run()`.

import CryptoKit
import Foundation
import Testing

import SwiftailBase
@testable import SwiftailControl

@Suite("Control client: Logout", .timeLimit(.minutes(1)))
struct LogoutTests {
    /// A fake auth key for tests. The logout request must omit it.
    static let authKey = "tskey-auth-fake0001"

    /// Creates a fake server and a client (using the stored identity if available), then runs `body`.
    private func withClient<T>(
        storedIdentity: NodeIdentity?,
        timeouts: ControlClient.Timeouts = ControlClient.Timeouts(),
        prepare: (SetDNSFakeControlServer) -> Void = { _ in },
        _ body: (ControlClient, SetDNSFakeControlServer, NodeIdentityStore) async throws -> T
    ) async throws -> T {
        let server = try SetDNSFakeControlServer()
        defer { server.close() }
        prepare(server)
        let url = try await server.start()
        let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-logout-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = NodeIdentityStore(directory: directory)
        if let storedIdentity { try store.save(storedIdentity) }
        let client = ControlClient(
            configuration: .init(serverURL: url, hostname: "rd-mac-1a2b3c4d", authKey: Self.authKey),
            identityStore: store,
            timeouts: timeouts
        )
        return try await body(client, server, store)
    }

    private func logOutError(_ client: ControlClient) async -> ControlError? {
        do throws(ControlError) {
            try await client.logOut()
            return nil
        } catch {
            return error
        }
    }

    private static func registeredIdentity() -> NodeIdentity {
        NodeIdentity(machineKey: .init(), nodeKey: .init())
    }

    // MARK: Requests

    @Test("Request preserves the stored node key, sets Expiry to 1970-01-01T00:02:03Z, omits the auth key, Followup, OldNodeKey, and signature, and preserves the identity file")
    func requestShape() async throws {
        let identity = Self.registeredIdentity()
        let nodeKey = try #require(identity.nodePublicKey)
        try await withClient(storedIdentity: identity) { client, server, store in
            try await client.logOut()

            #expect(server.keyRequests == 1)
            #expect(server.requests.count == 1, "Logout sends one request")
            let request = try #require(server.requests.first)
            #expect(request.method == "POST")
            #expect(request.path == "/machine/register")
            #expect(request.header("ts-lb") == nodeKey.description)

            let object = try #require(try JSONSerialization.jsonObject(with: Data(request.body)) as? [String: Any])
            #expect(Set(object.keys) == ["Version", "NodeKey", "OldNodeKey", "NLKey", "Expiry", "Followup", "Hostinfo", "NodeKeySignature"],
                    "Auth and Ephemeral must be absent")
            #expect(object["Version"] as? Int == 148)
            #expect(object["NodeKey"] as? String == nodeKey.description, "Does not create a new node key")
            #expect(object["OldNodeKey"] as? String == NodePublicKey.zero.description)
            #expect(object["NLKey"] as? String == identity.lockPublicKey.description)
            #expect(object["Expiry"] as? String == "1970-01-01T00:02:03Z", "JSON for Go time.Unix(123, 0)")
            #expect(object["Followup"] as? String == "")
            #expect(object["NodeKeySignature"] is NSNull)
            let hostinfo = try #require(object["Hostinfo"] as? [String: Any])
            #expect(hostinfo["Hostname"] as? String == "rd-mac-1a2b3c4d")
            #expect(!String(decoding: request.body, as: UTF8.self).contains(Self.authKey))

            let stored = try #require(try store.load())
            #expect(stored.nodePublicKey == nodeKey, "The node key in the identity file stays the same")
            #expect(stored.machinePublicKey == identity.machinePublicKey)
            #expect(stored.lockPublicKey == identity.lockPublicKey)
        }
    }

    @Test("If the identity file or node key is missing, sends nothing to the server and creates no file")
    func noIdentity() async throws {
        try await withClient(storedIdentity: nil) { client, server, store in
            try await client.logOut()
            #expect(server.keyRequests == 0)
            #expect(server.requests.isEmpty)
            #expect(try store.load() == nil, "Does not create an identity file")
        }
        try await withClient(storedIdentity: NodeIdentity()) { client, server, _ in
            try await client.logOut()
            #expect(server.keyRequests == 0)
            #expect(server.requests.isEmpty)
        }
    }

    // MARK: Responses

    @Test("Error in the response yields registrationRejected without retrying")
    func rejected() async throws {
        try await withClient(storedIdentity: Self.registeredIdentity(), prepare: {
            $0.enqueueRegisterReply(#"{"Error":"logout denied"}"#)
        }) { client, server, _ in
            guard case .registrationRejected(let message)? = await logOutError(client) else {
                Issue.record("Expected registrationRejected")
                return
            }
            #expect(message == "logout denied")
            #expect(server.requests.count == 1)
        }
    }

    @Test("Succeeds even if NodeKeyExpired, AuthURL, or NodeKeySignature arrives and takes no action on them (one request, same key)", arguments: [
        #"{"NodeKeyExpired":true}"#,
        #"{"AuthURL":"https://login.example.test/a/0001"}"#,
        #"{"NodeKeySignature":"AAEC"}"#,
        #"{}"#,
    ])
    func otherResponsesSucceed(_ reply: String) async throws {
        let identity = Self.registeredIdentity()
        try await withClient(storedIdentity: identity, prepare: { $0.enqueueRegisterReply(reply) }) { client, server, store in
            try await client.logOut()
            #expect(server.requests.count == 1)
            #expect(try store.load()?.nodePublicKey == identity.nodePublicKey)
        }
    }

    @Test("If the server does not reply, the deadline ends the operation with connection")
    func deadline() async throws {
        // The deadline includes key lookup and Noise connection setup. Use the production deadline to check waiting for a response after the request arrives.
        let limit = ControlClient.Timeouts().logout
        try await withClient(storedIdentity: Self.registeredIdentity(), prepare: {
            $0.setRegisterNeverAnswers(true)
        }) { client, server, _ in
            let start = ContinuousClock.now
            async let result = logOutError(client)
            try await server.wait("Logout request did not arrive", within: limit) {
                $0.requests.contains { $0.path == "/machine/register" }
            }
            guard case .connection(let message)? = await result else {
                Issue.record("Expected connection")
                return
            }
            #expect(message == "로그아웃이 \(limit) 안에 끝나지 않았다")
            #expect(start.duration(to: .now) >= limit)
            #expect(server.requests.map(\.path) == ["/machine/register"], "Does not resend the request")
        }
    }

    @Test("The default deadline is 10 seconds")
    func defaultDeadline() {
        #expect(ControlClient.Timeouts().logout == .seconds(10))
    }

    @Test("Fails without retrying if the server key cannot be obtained")
    func connectionFailureIsNotRetried() async throws {
        try await withClient(storedIdentity: Self.registeredIdentity(), prepare: { $0.setAcceptsConnections(false) }) { client, server, _ in
            let error = await logOutError(client)
            #expect(error != nil)
            #expect(server.keyRequests == 1)
            #expect(server.requests.isEmpty)
        }
    }
}
