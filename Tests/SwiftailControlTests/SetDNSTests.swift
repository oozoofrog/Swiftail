// `ControlClient.setDNS(name:value:)`: contract `docs/contracts/SwiftailHost.md`, behavior D, unit test 2.
// Runs against a fake control server (`SetDNSFakeControlServer`) over a real connection (upgrade → Noise → HTTP/2).

import CryptoKit
import Foundation
import Testing

import SwiftailBase
@testable import SwiftailControl

@Suite("Control client: set-dns", .timeLimit(.minutes(1)))
struct SetDNSTests {
    static let name = "_acme-challenge.rd-mac-1a2b3c4d.tail0001.ts.net"
    /// The shape of a DNS-01 TXT value (43 unquoted base64url characters). A fixed test value.
    static let value = "Zm9vYmFyLWFjbWUtY2hhbGxlbmdlLXZhbHVlLTEyMzQ"

    /// Starts a fake server and client and runs `body`. Cancels the client's `run()` afterward.
    private func withClient<T>(
        timeouts: ControlClient.Timeouts = ControlClient.Timeouts(),
        storedIdentity: NodeIdentity? = nil,
        prepare: (SetDNSFakeControlServer) -> Void = { _ in },
        _ body: (ControlClient, SetDNSFakeControlServer) async throws -> T
    ) async throws -> T {
        let server = try SetDNSFakeControlServer()
        defer { server.close() }
        prepare(server)
        let url = try await server.start()
        let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-setdns-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = NodeIdentityStore(directory: directory)
        if let storedIdentity { try store.save(storedIdentity) }
        let client = ControlClient(
            configuration: .init(serverURL: url, hostname: "rd-mac-1a2b3c4d"), identityStore: store, timeouts: timeouts
        )
        let running = Task { try await client.run() }
        defer { running.cancel() }
        return try await body(client, server)
    }

    /// Wait for the map stream to open, which happens after registration and state upload finish.
    private func waitForMapStream(_ server: SetDNSFakeControlServer) async throws {
        try await server.wait("The map stream did not open") { !$0.openMapStreams.isEmpty }
    }

    private func setDNSError(_ client: ControlClient, name: String = Self.name, value: String = Self.value) async -> ControlError? {
        do throws(ControlError) {
            try await client.setDNS(name: name, value: value)
            return nil
        } catch {
            return error
        }
    }

    // MARK: Requests

    @Test("Sends POST /machine/set-dns on a new stream over the connection carrying the map long poll, and leaves the map stream open")
    func requestOverOpenConnection() async throws {
        try await withClient { client, server in
            try await waitForMapStream(server)
            let mapStream = try #require(server.openMapStreams.first)
            try await client.setDNS(name: Self.name, value: Self.value)

            let request = try #require(server.setDNSRequests.first)
            #expect(server.setDNSRequests.count == 1)
            #expect(request.method == "POST")
            #expect(request.path == "/machine/set-dns")
            #expect(request.connection == Int(mapStream[0]), "Sent on a different connection than the map stream")
            #expect(request.stream != mapStream[1])
            #expect(server.openMapStreams.contains(mapStream), "set-dns closed the map stream")
            // Did not reconnect.
            #expect(server.keyRequests == 1)
        }
    }

    @Test("Request headers and body: Content-Type, Ts-Lb, Version 148, NodeKey, Name, Type TXT, and unquoted Value")
    func requestHeadersAndBody() async throws {
        try await withClient { client, server in
            try await waitForMapStream(server)
            try await client.setDNS(name: Self.name, value: Self.value)

            let request = try #require(server.setDNSRequests.first)
            let register = try #require(server.requests.first { $0.path == "/machine/register" })
            let registered = try #require(register.header("ts-lb"))
            #expect(request.header("content-type") == "application/json")
            #expect(request.header("ts-lb") == registered)

            let object = try #require(try JSONSerialization.jsonObject(with: Data(request.body)) as? [String: Any])
            #expect(Set(object.keys) == ["Version", "NodeKey", "Name", "Type", "Value"])
            #expect(object["Version"] as? Int == 148)
            #expect(object["NodeKey"] as? String == registered)
            #expect(object["Name"] as? String == Self.name)
            #expect(object["Type"] as? String == "TXT")
            #expect(object["Value"] as? String == Self.value)
            #expect(Self.value.utf8.count == 43)
        }
    }

    // MARK: Responses

    @Test("200 with a JSON object succeeds", arguments: ["{}", #"{"Unknown":1}"#, " { } "])
    func successfulObject(_ body: String) async throws {
        try await withClient(prepare: { $0.setSetDNSReply(.respond(status: 200, body: Array(body.utf8))) }) { client, server in
            try await waitForMapStream(server)
            try await client.setDNS(name: Self.name, value: Self.value)
        }
    }

    @Test("Even 200 fails if the body is not a JSON object (Go accepts null)", arguments: ["", "null", "[]", #""x""#, "1", "{", "{} {}"])
    func nonObjectBody(_ body: String) async throws {
        try await withClient(prepare: { $0.setSetDNSReply(.respond(status: 200, body: Array(body.utf8))) }) { client, server in
            try await waitForMapStream(server)
            guard case .connection? = await setDNSError(client) else {
                Issue.record("Accepted a non-object body \(body.debugDescription)")
                return
            }
        }
    }

    @Test("A status other than 200 carries the status code and omits the server body (which contains the name) from the error", arguments: [400, 403, 404, 429, 500, 503])
    func rejected(_ status: Int) async throws {
        let echoed = Array("record \(Self.name) = \(Self.value) refused".utf8)
        try await withClient(prepare: { $0.setSetDNSReply(.respond(status: status, body: echoed)) }) { client, server in
            try await waitForMapStream(server)
            let error = await setDNSError(client)
            guard case .http(status)? = error else {
                Issue.record("Status \(status) did not come back as http(status:): \(String(describing: error))")
                return
            }
            Self.expectNoSecrets(in: error)
        }
    }

    @Test("Accepts a 200 body up to 4KiB and fails beyond that")
    func responseLimit() async throws {
        // Pad `{"a":"…"}` to exactly 4,096 bytes.
        let exact = Array(#"{"a":""#.utf8) + [UInt8](repeating: UInt8(ascii: "x"), count: 4096 - 8) + Array(#""}"#.utf8)
        #expect(exact.count == ControlClient.maximumSetDNSResponseSize)
        try await withClient(prepare: { $0.setSetDNSReply(.respond(status: 200, body: exact)) }) { client, server in
            try await waitForMapStream(server)
            try await client.setDNS(name: Self.name, value: Self.value)
        }

        let over = Array(#"{"a":""#.utf8) + [UInt8](repeating: UInt8(ascii: "x"), count: 4096 - 7) + Array(#""}"#.utf8)
        try await withClient(prepare: { $0.setSetDNSReply(.respond(status: 200, body: over)) }) { client, server in
            try await waitForMapStream(server)
            guard case .connection? = await setDNSError(client) else {
                Issue.record("Accepted a body larger than 4KiB")
                return
            }
        }
    }

    // MARK: Deadline and connection

    @Test("If the server does not answer, the deadline ends the operation with connection, and the error omits the name and value")
    func noAnswer() async throws {
        var timeouts = ControlClient.Timeouts()
        timeouts.setDNS = .seconds(1)
        try await withClient(timeouts: timeouts, prepare: { $0.setSetDNSReply(.never) }) { client, server in
            try await waitForMapStream(server)
            let start = ContinuousClock.now
            let error = await setDNSError(client)
            let elapsed = ContinuousClock.now - start
            guard case .connection? = error else {
                Issue.record("An unresponsive server did not yield connection: \(String(describing: error))")
                return
            }
            #expect(elapsed >= .milliseconds(900) && elapsed < .seconds(5), "Unexpected deadline: \(elapsed)")
            #expect(server.setDNSRequests.count == 1)
            Self.expectNoSecrets(in: error)
        }
    }

    @Test("With a registered identity and no connection yet, waits for the connection before sending")
    func waitsForConnection() async throws {
        let identity = NodeIdentity(machineKey: .init(), nodeKey: .init())
        try await withClient(storedIdentity: identity, prepare: { $0.setAcceptsConnections(false) }) { client, server in
            // Once the first /key attempt arrives, run() has loaded the stored identity.
            try await server.wait("No connection attempt arrived") { $0.keyRequests >= 1 }
            async let sent: ControlError? = setDNSError(client)
            try await Task.sleep(for: .milliseconds(300))
            #expect(server.setDNSRequests.isEmpty)
            server.setAcceptsConnections(true)
            let error = await sent
            #expect(error == nil, "Failed even after the connection was established: \(String(describing: error))")
            let request = try #require(server.setDNSRequests.first)
            let object = try #require(try JSONSerialization.jsonObject(with: Data(request.body)) as? [String: Any])
            #expect(object["NodeKey"] as? String == identity.nodePublicKey?.description)
        }
    }

    @Test("If a connection is not established by the deadline, ends with connection and sends no request")
    func connectionNeverComes() async throws {
        var timeouts = ControlClient.Timeouts()
        timeouts.setDNS = .seconds(1)
        let identity = NodeIdentity(machineKey: .init(), nodeKey: .init())
        try await withClient(timeouts: timeouts, storedIdentity: identity, prepare: { $0.setAcceptsConnections(false) }) { client, server in
            try await server.wait("No connection attempt arrived") { $0.keyRequests >= 1 }
            let start = ContinuousClock.now
            let error = await setDNSError(client)
            let elapsed = ContinuousClock.now - start
            guard case .connection? = error else {
                Issue.record("The deadline without a connection did not yield connection")
                return
            }
            #expect(elapsed >= .milliseconds(900) && elapsed < .seconds(5), "Unexpected deadline: \(elapsed)")
            #expect(server.setDNSRequests.isEmpty)
        }
    }

    @Test("Before registration (no node key), fails immediately without waiting")
    func beforeRegistration() async throws {
        try await withClient(prepare: { $0.setAcceptsConnections(false) }) { client, server in
            try await server.wait("No connection attempt arrived") { $0.keyRequests >= 1 }
            let start = ContinuousClock.now
            guard case .connection? = await setDNSError(client) else {
                Issue.record("set-dns before registration did not end with connection")
                return
            }
            #expect(ContinuousClock.now - start < .seconds(1), "Waited before registration")
            #expect(server.setDNSRequests.isEmpty)
        }
    }

    @Test("An empty name or value yields invalidConfiguration and sends no request", arguments: [("", "v"), ("n", "")])
    func emptyArguments(_ arguments: (String, String)) async throws {
        try await withClient { client, server in
            try await waitForMapStream(server)
            guard case .invalidConfiguration? = await setDNSError(client, name: arguments.0, value: arguments.1) else {
                Issue.record("Accepted an empty argument")
                return
            }
            #expect(server.setDNSRequests.isEmpty)
        }
    }

    /// The error string (including associated values) omits the record name, domain, and value (contract behaviors K2 and K3).
    private static func expectNoSecrets(in error: ControlError?, sourceLocation: SourceLocation = #_sourceLocation) {
        let text = String(describing: error) + String(reflecting: error)
        for secret in [name, "tail0001", value] {
            #expect(!text.contains(secret), "\(secret) remained in the error string: \(text)", sourceLocation: sourceLocation)
        }
    }
}
