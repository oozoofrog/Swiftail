// Tests added by the independent review of `ControlClient.logOut()`. Contract `docs/contracts/SwiftailHost.md`, "Logout," behavior O.
// Covers cases outside `LogoutTests`: deadline when the server stalls before the response (`/key` or upgrade), cancellation in flight, a corrupt identity file,
// byte-for-byte preservation of the identity file, auth key redaction in rejection messages, large responses, and calling `run()` again with a logged-out key
// in the flow likely to occur on the production server (expiration → login required to register a new key).

import CryptoKit
import Foundation
import Network
import Synchronization
import Testing

import SwiftailBase
@testable import SwiftailControl

/// A server that receives requests without answering. If `answersKey` is set, it answers `GET /key` and stalls at the next step (upgrade).
private final class StallingServer: Sendable {
    private struct State {
        var connections: [NWConnection] = []
        var opened = 0
        /// The number of connections that the peer closed or that dropped.
        var closed = 0
    }

    private let listener: NWListener
    private let state = Mutex(State())
    private let answersKey: Bool

    init(answersKey: Bool) throws {
        self.answersKey = answersKey
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: .any)
        listener = try NWListener(using: parameters)
        listener.newConnectionHandler = { [weak self] connection in
            guard let self else { connection.cancel(); return }
            self.state.withLock {
                $0.connections.append(connection)
                $0.opened += 1
            }
            connection.start(queue: .global())
            self.read(connection, received: [])
        }
    }

    var opened: Int { state.withLock { $0.opened } }
    var closed: Int { state.withLock { $0.closed } }

    private func read(_ connection: NWConnection, received: [UInt8]) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if isComplete || error != nil {
                self.state.withLock { $0.closed += 1 }
                connection.cancel()
                return
            }
            let received = received + [UInt8](data ?? Data())
            if self.answersKey, String(decoding: received, as: UTF8.self).hasPrefix("GET /key"),
               String(decoding: received, as: UTF8.self).contains("\r\n\r\n") {
                let key = MachinePublicKey(Curve25519.KeyAgreement.PrivateKey().publicKey)
                let body = #"{"publicKey":"\#(key)"}"#
                let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)"
                connection.send(content: Data(response.utf8), completion: .contentProcessed { _ in connection.cancel() })
                self.state.withLock { $0.closed += 1 }
                return
            }
            self.read(connection, received: received)
        }
    }

    func start() async throws -> URL {
        let listener = listener
        let port = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<UInt16, any Error>) in
            let once = Mutex<CheckedContinuation<UInt16, any Error>?>(continuation)
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    if let port = listener.port?.rawValue { once.withLock { $0.take() }?.resume(returning: port) }
                case .failed(let error):
                    once.withLock { $0.take() }?.resume(throwing: error)
                default:
                    break
                }
            }
            listener.start(queue: .global())
        }
        return try #require(URL(string: "http://127.0.0.1:\(port)"))
    }

    func close() {
        listener.cancel()
        for connection in state.withLock({ $0.connections }) { connection.cancel() }
    }
}

@Suite("Control client: Logout (review)", .timeLimit(.minutes(1)))
struct LogoutReviewTests {
    static let authKey = "tskey-auth-fake0001"

    private static func temporaryStore() -> (NodeIdentityStore, URL) {
        let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-logout-review-\(UUID().uuidString)")
        return (NodeIdentityStore(directory: directory), directory)
    }

    private static func registeredIdentity() -> NodeIdentity {
        NodeIdentity(machineKey: .init(), nodeKey: .init())
    }

    private func logOutError(_ client: ControlClient) async -> ControlError? {
        do throws(ControlError) {
            try await client.logOut()
            return nil
        } catch {
            return error
        }
    }

    private func waitUntil(_ what: String, within duration: Duration = .seconds(5), _ condition: () -> Bool) async {
        let deadline = ContinuousClock.now + duration
        while !condition() {
            guard ContinuousClock.now < deadline else {
                Issue.record("\(what) within \(duration)")
                return
            }
            try? await Task.sleep(for: .milliseconds(10))
        }
    }

    // MARK: Deadline (behavior O5)

    @Test("Even if the server stalls at /key or upgrade, the deadline ends the operation with connection and leaves no open connection", arguments: [false, true])
    func deadlineBeforeRegister(answersKey: Bool) async throws {
        let server = try StallingServer(answersKey: answersKey)
        defer { server.close() }
        let url = try await server.start()
        let (store, directory) = Self.temporaryStore()
        defer { try? FileManager.default.removeItem(at: directory) }
        try store.save(Self.registeredIdentity())
        var timeouts = ControlClient.Timeouts()
        timeouts.logout = .milliseconds(500)
        let client = ControlClient(
            configuration: .init(serverURL: url, hostname: "rd-mac-1a2b3c4d", authKey: nil), identityStore: store, timeouts: timeouts
        )

        let start = ContinuousClock.now
        guard case .connection? = await logOutError(client) else {
            Issue.record("Expected connection")
            return
        }
        let elapsed = ContinuousClock.now - start
        #expect(elapsed >= .milliseconds(500) && elapsed < .seconds(3), "Must finish by the deadline: \(elapsed)")
        let expected = answersKey ? 2 : 1
        #expect(server.opened == expected)
        await waitUntil("The client closes the connection") { server.closed == server.opened }
    }

    @Test("Canceling in flight ends promptly with connection and preserves the identity file")
    func cancellation() async throws {
        let server = try SetDNSFakeControlServer()
        defer { server.close() }
        server.setRegisterNeverAnswers(true)
        let url = try await server.start()
        let (store, directory) = Self.temporaryStore()
        defer { try? FileManager.default.removeItem(at: directory) }
        try store.save(Self.registeredIdentity())
        let before = try Data(contentsOf: store.fileURL)
        let client = ControlClient(configuration: .init(serverURL: url, hostname: "rd-mac-1a2b3c4d", authKey: nil), identityStore: store)

        let task = Task { await logOutError(client) }
        try await server.wait("Logout request arrives") { $0.requests.count == 1 }
        let start = ContinuousClock.now
        task.cancel()
        guard case .connection? = await task.value else {
            Issue.record("Expected connection")
            return
        }
        #expect(ContinuousClock.now - start < .seconds(3), "Does not wait for the default deadline (10 seconds)")
        #expect(try Data(contentsOf: store.fileURL) == before)
    }

    // MARK: Local file (behavior O6)

    @Test("Successful logout preserves the identity file byte for byte and creates no other file in the directory")
    func identityFileUntouched() async throws {
        let server = try SetDNSFakeControlServer()
        defer { server.close() }
        let url = try await server.start()
        let (store, directory) = Self.temporaryStore()
        defer { try? FileManager.default.removeItem(at: directory) }
        try store.save(Self.registeredIdentity())
        let before = try Data(contentsOf: store.fileURL)
        let modified = try FileManager.default.attributesOfItem(atPath: store.fileURL.path)[.modificationDate] as? Date
        let client = ControlClient(configuration: .init(serverURL: url, hostname: "rd-mac-1a2b3c4d", authKey: nil), identityStore: store)

        try await client.logOut()

        #expect(server.requests.count == 1)
        #expect(try Data(contentsOf: store.fileURL) == before)
        #expect(try FileManager.default.attributesOfItem(atPath: store.fileURL.path)[.modificationDate] as? Date == modified)
        #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path) == [store.fileURL.lastPathComponent])
    }

    @Test("An old identity file without an NL key sends the request (with NLKey other than 0) and leaves the file without an NL key")
    func oldIdentityFileWithoutLockKey() async throws {
        let server = try SetDNSFakeControlServer()
        defer { server.close() }
        let url = try await server.start()
        let (store, directory) = Self.temporaryStore()
        defer { try? FileManager.default.removeItem(at: directory) }
        try store.save(Self.registeredIdentity())
        // Remove only NLKey from the stored file.
        var object = try #require(try JSONSerialization.jsonObject(with: Data(contentsOf: store.fileURL)) as? [String: Any])
        #expect(object.removeValue(forKey: "NLKey") != nil)
        let old = try JSONSerialization.data(withJSONObject: object)
        try old.write(to: store.fileURL)
        let client = ControlClient(configuration: .init(serverURL: url, hostname: "rd-mac-1a2b3c4d", authKey: nil), identityStore: store)

        try await client.logOut()

        let request = try #require(server.requests.first)
        let body = try #require(try JSONSerialization.jsonObject(with: Data(request.body)) as? [String: Any])
        #expect(body["NLKey"] as? String != NLPublicKey.zero.description)
        #expect(try Data(contentsOf: store.fileURL) == old)
    }

    @Test("A corrupt identity file yields storage, sends nothing to the server, and leaves the file intact")
    func corruptedIdentity() async throws {
        let server = try SetDNSFakeControlServer()
        defer { server.close() }
        let url = try await server.start()
        let (store, directory) = Self.temporaryStore()
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let garbage = Data("{not json".utf8)
        try garbage.write(to: store.fileURL)
        let client = ControlClient(configuration: .init(serverURL: url, hostname: "rd-mac-1a2b3c4d", authKey: nil), identityStore: store)

        guard case .storage? = await logOutError(client) else {
            Issue.record("Expected storage")
            return
        }
        #expect(server.keyRequests == 0)
        #expect(server.requests.isEmpty)
        #expect(try Data(contentsOf: store.fileURL) == garbage)
    }

    // MARK: Errors (behaviors O4 and O7)

    @Test("A /key response other than 200 yields http(status:)")
    func keyStatus() async throws {
        let server = try SetDNSFakeControlServer()
        defer { server.close() }
        server.setAcceptsConnections(false)
        let url = try await server.start()
        let (store, directory) = Self.temporaryStore()
        defer { try? FileManager.default.removeItem(at: directory) }
        try store.save(Self.registeredIdentity())
        let client = ControlClient(configuration: .init(serverURL: url, hostname: "rd-mac-1a2b3c4d", authKey: nil), identityStore: store)
        guard case .http(status: 500)? = await logOutError(client) else {
            Issue.record("Expected http(500)")
            return
        }
    }

    @Test("Redacts the auth key (the original and the part before --TL) in the rejection message and truncates it to 200 characters. The error string contains no key")
    func rejectionHidesSecrets() async throws {
        let wrapped = Self.authKey + "--TL0001-fakefakefake"
        let identity = Self.registeredIdentity()
        let server = try SetDNSFakeControlServer()
        defer { server.close() }
        server.enqueueRegisterReply(#"{"Error":"bad key \#(wrapped) and \#(Self.authKey) \#(String(repeating: "x", count: 400))"}"#)
        let url = try await server.start()
        let (store, directory) = Self.temporaryStore()
        defer { try? FileManager.default.removeItem(at: directory) }
        try store.save(identity)
        let client = ControlClient(configuration: .init(serverURL: url, hostname: "rd-mac-1a2b3c4d", authKey: wrapped), identityStore: store)

        let error = try #require(await logOutError(client))
        guard case .registrationRejected(let message) = error else {
            Issue.record("Expected registrationRejected, got \(error)")
            return
        }
        #expect(message.count <= ControlClient.maximumRejectionLength + 1)
        let text = String(describing: error) + String(reflecting: error)
        #expect(!text.contains(Self.authKey))
        #expect(!text.contains("--TL"))
        #expect(!text.contains(try #require(identity.nodePublicKey).description))
        // The request contains no auth key either, even if the key is wrapped.
        let body = String(decoding: try #require(server.requests.first).body, as: UTF8.self)
        #expect(!body.contains("tskey-") && !body.contains("--TL"))
    }

    @Test("A response larger than 1MiB ends with connection")
    func oversizedResponse() async throws {
        let server = try SetDNSFakeControlServer()
        defer { server.close() }
        server.enqueueRegisterReply(#"{"Error":"\#(String(repeating: "x", count: (1 << 20) + 16))"}"#)
        let url = try await server.start()
        let (store, directory) = Self.temporaryStore()
        defer { try? FileManager.default.removeItem(at: directory) }
        try store.save(Self.registeredIdentity())
        let client = ControlClient(configuration: .init(serverURL: url, hostname: "rd-mac-1a2b3c4d", authKey: nil), identityStore: store)
        guard case .connection? = await logOutError(client) else {
            Issue.record("Expected connection")
            return
        }
        #expect(server.requests.count == 1)
    }

    // MARK: Calling run() again with a logged-out key (expected production server behavior from the contract's "Tests and gates")

    /// Likely production server flow: `NodeKeyExpired` for registration with the stored (logged-out) key, `AuthURL` (login required) for registration with a new key,
    /// and success on Followup after login. Unlike the testcontrol copy, this server does not carry the expiry time over to the new key.
    @Test("Runs run() again with a logged-out key: expiration → registration with a new key (OldNodeKey = old key) → loginRequired → Followup → new key stored", arguments: [nil, authKey])
    func runAfterLogout(authKey: String?) async throws {
        let server = try SetDNSFakeControlServer()
        defer { server.close() }
        let authURL = "https://login.example.test/a/0001"
        server.enqueueRegisterReply(#"{"NodeKeyExpired":true}"#)
        server.enqueueRegisterReply(#"{"AuthURL":"\#(authURL)"}"#)
        server.enqueueRegisterReply(#"{"MachineAuthorized":true}"#)
        let url = try await server.start()
        let (store, directory) = Self.temporaryStore()
        defer { try? FileManager.default.removeItem(at: directory) }
        let identity = Self.registeredIdentity()
        let oldKey = try #require(identity.nodePublicKey)
        try store.save(identity)
        let client = ControlClient(configuration: .init(serverURL: url, hostname: "rd-mac-1a2b3c4d", authKey: authKey), identityStore: store)

        let run = Task { () -> ControlError? in
            do throws(ControlError) {
                try await client.run()
                return nil
            } catch {
                return error
            }
        }
        defer { run.cancel() }
        var loginURL: URL?
        var registered: NodePublicKey?
        for await event in client.events {
            if case .loginRequired(let url) = event { loginURL = url }
            if case .registered(let key) = event {
                registered = key
                break
            }
        }

        let registers = server.requests.filter { $0.path == "/machine/register" }
        let bodies = try registers.map { try #require(try JSONSerialization.jsonObject(with: Data($0.body)) as? [String: Any]) }
        try #require(bodies.count == 3)
        #expect(bodies[0]["NodeKey"] as? String == oldKey.description)
        #expect(bodies[0]["Auth"] == nil, "Registration with the stored key omits the auth key")
        let newKey = try #require(bodies[1]["NodeKey"] as? String)
        #expect(newKey != oldKey.description)
        #expect(bodies[1]["OldNodeKey"] as? String == oldKey.description)
        #expect((bodies[1]["Auth"] != nil) == (authKey != nil))
        #expect(bodies[1]["Followup"] as? String == "")
        #expect(bodies[2]["NodeKey"] as? String == newKey)
        #expect(bodies[2]["Followup"] as? String == authURL)
        #expect(bodies.allSatisfy { $0["Expiry"] as? String == "0001-01-01T00:00:00Z" }, "Registration has no Expiry")
        #expect(loginURL?.absoluteString == authURL)
        #expect(registered?.description == newKey)
        #expect(try store.load()?.nodePublicKey?.description == newKey)

        run.cancel()
        #expect(await run.value == nil, "run() does not end with nodeKeyExpired")
    }
}
