// Tailnet lock fields in registration requests: contract `docs/contracts/SwiftailTailnetLock.md`, behaviors R and K, unit tests 15 and 16.
// Runs against a fake control server (`SetDNSFakeControlServer`) over a real connection (upgrade → Noise → HTTP/2). Inspects the bytes of the requests received by the server.
//
// The test generates all keys on the spot. Checks signatures using `SwiftailTKA`'s `authorize`, which was checked against Go's decisions.

import CryptoKit
import Foundation
import Testing

import SwiftailBase
@testable import SwiftailControl
@testable import SwiftailTKA

@Suite("Control client: NL key and signature at registration", .timeLimit(.minutes(1)))
struct RegistrationSigningTests {
    /// Tailnet lock for the test: one trusted key and a signed auth key made with a wrapped key that the trusted key delegated.
    struct Lock {
        let trustedKey = Curve25519.Signing.PrivateKey()
        let wrappingKey = Curve25519.Signing.PrivateKey()

        var state: AuthorityState {
            AuthorityState(keys: [TrustedKey(kind: 1, votes: 1, publicKey: Array(trustedKey.publicKey.rawRepresentation))])
        }

        /// Wrapped private key (B): 64 bytes of seed ‖ public key.
        var wrappedPrivateKey: [UInt8] {
            Array(wrappingKey.rawRepresentation) + Array(wrappingKey.publicKey.rawRepresentation)
        }

        /// `tskey-auth-fake--TL<credential>-<B>` (notes §3.8).
        func authKey(privateKey: [UInt8]? = nil) throws -> String {
            var credential = NodeKeySignature(
                kind: 3,
                keyID: Array(trustedKey.publicKey.rawRepresentation),
                wrappingPublicKey: Array(wrappingKey.publicKey.rawRepresentation)
            )
            try credential.sign(with: trustedKey)
            return "tskey-auth-fake--TL" + rawBase64(credential.serialized()) + "-" + rawBase64(privateKey ?? wrappedPrivateKey)
        }

        /// A direct signature signed by the trusted key. If `wrappingKey` is present, it can sign this signature again as a rotation.
        func directSignature(for nodeKey: NodePublicKey, wrappingKey: NLPublicKey?) throws -> [UInt8] {
            var signature = NodeKeySignature(
                kind: 1,
                publicKey: nodeKey.binaryForm,
                keyID: Array(trustedKey.publicKey.rawRepresentation),
                wrappingPublicKey: wrappingKey?.rawValue ?? []
            )
            try signature.sign(with: trustedKey)
            return signature.serialized()
        }
    }

    static func rawBase64(_ bytes: [UInt8]) -> String {
        Data(bytes).base64EncodedString().replacingOccurrences(of: "=", with: "")
    }

    /// Starts a fake server and client and runs `body`. Cancels the client's `run()` afterward.
    private func withClient<T>(
        authKey: String? = nil,
        prepare: (SetDNSFakeControlServer, NodeIdentityStore, URL) throws -> Void = { _, _, _ in },
        _ body: (SetDNSFakeControlServer, NodeIdentityStore) async throws -> T
    ) async throws -> T {
        let server = try SetDNSFakeControlServer()
        defer { server.close() }
        let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-register-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = NodeIdentityStore(directory: directory)
        try prepare(server, store, directory)
        let url = try await server.start()
        let client = ControlClient(
            configuration: .init(serverURL: url, hostname: "rd-mac-1a2b3c4d", authKey: authKey), identityStore: store
        )
        let running = Task { try await client.run() }
        defer { running.cancel() }
        return try await body(server, store)
    }

    private func registerRequests(_ server: SetDNSFakeControlServer) -> [SetDNSFakeControlServer.Request] {
        server.requests.filter { $0.path == "/machine/register" }
    }

    private func object(_ request: SetDNSFakeControlServer.Request) throws -> [String: Any] {
        try #require(try JSONSerialization.jsonObject(with: Data(request.body)) as? [String: Any])
    }

    private func nodeKey(_ object: [String: Any], _ field: String = "NodeKey") throws -> NodePublicKey {
        let text = try #require(object[field] as? String)
        return try #require(NodePublicKey(text))
    }

    private func signature(_ object: [String: Any]) throws -> [UInt8] {
        let text = try #require(object["NodeKeySignature"] as? String, "Missing signature")
        return [UInt8](try #require(Data(base64Encoded: text)))
    }

    // MARK: Ordinary auth key

    @Test("With an ordinary auth key, NLKey is the stored local NL public key and the signature is null")
    func plainAuthKey() async throws {
        try await withClient(authKey: "tskey-auth-fake") { server, store in
            try await server.wait("The map stream did not open") { !$0.openMapStreams.isEmpty }
            let request = try object(try #require(registerRequests(server).first))
            let stored = try #require(try store.load())
            #expect(request["NLKey"] as? String == stored.lockPublicKey.description)
            #expect(stored.lockPublicKey != .zero)
            #expect(request["NodeKeySignature"] is NSNull)
            #expect((request["Auth"] as? [String: Any])?["AuthKey"] as? String == "tskey-auth-fake")
        }
    }

    @Test("An old identity file without an NL key stores a new NL key before the first request and includes that key (behavior R1)")
    func oldIdentityFile() async throws {
        let old = NodeIdentity(machineKey: .init(), nodeKey: .init())
        try await withClient(prepare: { _, store, directory in
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let object = [
                "MachineKey": "privkey:" + [UInt8](old.machineKey.rawRepresentation).hex,
                "NodeKey": "privkey:" + [UInt8](try #require(old.nodeKey).rawRepresentation).hex,
            ]
            try JSONSerialization.data(withJSONObject: object).write(to: store.fileURL)
        }) { server, store in
            try await server.wait("The registration request did not arrive") { !registerRequests($0).isEmpty }
            let request = try object(try #require(registerRequests(server).first))
            let stored = try #require(try store.load())
            // Starts as the same node by reconnecting with the stored node key.
            #expect(try nodeKey(request) == old.nodePublicKey)
            #expect(stored.machinePublicKey == old.machinePublicKey)
            #expect(request["NLKey"] as? String == stored.lockPublicKey.description)
            #expect(request["NodeKeySignature"] is NSNull)
            #expect(request["Auth"] == nil)
        }
    }

    // MARK: Signed auth key

    @Test("With a signed auth key, the server receives the part before --TL and the signature authorizes the node key")
    func signedAuthKey() async throws {
        let lock = Lock()
        let authKey = try lock.authKey()
        try await withClient(authKey: authKey) { server, store in
            try await server.wait("The map stream did not open") { !$0.openMapStreams.isEmpty }
            let requests = registerRequests(server)
            #expect(requests.count == 1)
            let request = try object(try #require(requests.first))
            #expect((request["Auth"] as? [String: Any])?["AuthKey"] as? String == "tskey-auth-fake")
            let registered = try nodeKey(request)
            #expect(registered == (try #require(try store.load())).nodePublicKey)

            let details = try lock.state.authorize(registered, keySignature: try signature(request))
            #expect(details?.previousNodeKeys == [])
            #expect(details?.initialSignature.kind == 3)
            #expect(throws: TKAError.unauthorized) {
                try lock.state.authorize(NodePublicKey(Curve25519.KeyAgreement.PrivateKey().publicKey), keySignature: try signature(request))
            }
        }
    }

    @Test("No request to the server contains the part after --TL or the wrapped private key (base64, base-16, or bytes) (behaviors R4 and K3)")
    func noWrappedKeyOnTheWire() async throws {
        let lock = Lock()
        let authKey = try lock.authKey()
        try await withClient(authKey: authKey) { server, _ in
            try await server.wait("The map stream did not open") { !$0.openMapStreams.isEmpty }
            let seed = Array(lock.wrappingKey.rawRepresentation)
            let secrets: [[UInt8]] = [
                Array(authKey.utf8),
                Array(authKey[try #require(authKey.range(of: "--TL")).lowerBound...].utf8),
                Array(Self.rawBase64(lock.wrappedPrivateKey).utf8),
                Array(Data(lock.wrappedPrivateKey).base64EncodedString().utf8),
                Array(Self.rawBase64(seed).utf8),
                Array(Data(seed).base64EncodedString().utf8),
                Array(lock.wrappedPrivateKey.hex.utf8),
                Array(seed.hex.utf8),
                Array(seed.hex.uppercased().utf8),
                seed,
            ]
            #expect(!server.requests.isEmpty)
            for request in server.requests {
                let wire = request.body + request.headers.flatMap { Array($0.name.utf8) + Array($0.value.utf8) } + Array(request.path.utf8)
                for secret in secrets {
                    #expect(wire.firstRange(of: secret) == nil, "A secret was included in \(request.path)")
                }
                #expect(wire.firstRange(of: Array("--TL".utf8)) == nil)
            }
        }
    }

    @Test("An undecodable --TL yields invalidConfiguration and sends no request (decisions L12 and L13)", arguments: [
        "missing-dash", "padded-credential", "short-key", "long-key", "wrong-public-half", "other-wrapping-key", "not-credential",
    ])
    func invalidWrappedAuthKey(_ variant: String) async throws {
        let lock = Lock()
        let valid = try lock.authKey()
        let suffix = String(valid[try #require(valid.range(of: "--TL")).upperBound...])
        let parts = suffix.split(separator: "-", maxSplits: 1).map(String.init)
        let authKey: String
        switch variant {
        case "missing-dash": authKey = "tskey-auth-fake--TL" + parts[0] + parts[1]
        case "padded-credential": authKey = "tskey-auth-fake--TL" + parts[0] + "=-" + parts[1]
        case "short-key": authKey = try lock.authKey(privateKey: Array(lock.wrappedPrivateKey.prefix(63)))
        case "long-key": authKey = try lock.authKey(privateKey: lock.wrappedPrivateKey + [0])
        case "wrong-public-half": authKey = try lock.authKey(privateKey: Array(lock.wrappedPrivateKey.prefix(32)) + Array(repeating: 1, count: 32))
        case "other-wrapping-key":
            let other = Curve25519.Signing.PrivateKey()
            authKey = try lock.authKey(privateKey: Array(other.rawRepresentation) + Array(other.publicKey.rawRepresentation))
        default:
            authKey = "tskey-auth-fake--TL" + Self.rawBase64(try lock.directSignature(for: .zero, wrappingKey: nil)) + "-" + parts[1]
        }

        let server = try SetDNSFakeControlServer()
        defer { server.close() }
        let url = try await server.start()
        let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-register-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let client = ControlClient(
            configuration: .init(serverURL: url, hostname: "rd-mac-1a2b3c4d", authKey: authKey),
            identityStore: NodeIdentityStore(directory: directory)
        )
        let running = Task<ControlError?, Never> {
            do throws(ControlError) { try await client.run(); return nil } catch { return error }
        }
        let timer = Task {
            try await Task.sleep(for: .seconds(5))
            running.cancel()
        }
        defer { timer.cancel() }
        guard case .invalidConfiguration(let message)? = await running.value else {
            Issue.record("run() did not immediately end with invalidConfiguration")
            return
        }
        #expect(server.keyRequests == 0)
        #expect(server.requests.isEmpty)
        #expect(!message.contains(suffix) && !message.contains(parts[1]) && !message.contains("tskey"))
    }

    // MARK: Re-signing requests

    @Test("A re-signing request creates a new node key, extends the received signature chain with the NL key, and registers again (behaviors R6 and R7)")
    func resignRequest() async throws {
        let lock = Lock()
        let identity = NodeIdentity(machineKey: .init(), nodeKey: .init())
        let oldKey = try #require(identity.nodePublicKey)
        let oldSignature = try lock.directSignature(for: oldKey, wrappingKey: identity.lockPublicKey)
        try await withClient(prepare: { server, store, _ in
            try store.save(identity)
            server.enqueueRegisterReply(#"{"NodeKeySignature":"\#(Data(oldSignature).base64EncodedString())"}"#)
        }) { server, store in
            try await server.wait("The map stream did not open") { !$0.openMapStreams.isEmpty }
            let requests = try registerRequests(server).map(object)
            #expect(requests.count == 2)
            let first = try #require(requests.first), second = try #require(requests.last)
            #expect(try nodeKey(first) == oldKey)
            #expect(try nodeKey(first, "OldNodeKey") == .zero)
            #expect(first["NodeKeySignature"] is NSNull)

            let newKey = try nodeKey(second)
            #expect(newKey != oldKey)
            #expect(try nodeKey(second, "OldNodeKey") == oldKey)
            #expect(second["NLKey"] as? String == identity.lockPublicKey.description)
            let details = try lock.state.authorize(newKey, keySignature: try signature(second))
            #expect(details?.previousNodeKeys == [oldKey])
            #expect(try #require(try store.load()).nodePublicKey == newKey)
        }
    }

    @Test("If the old signature cannot be re-signed, registers with a new key and no signature (behavior R5 ①)")
    func unreadableResignInput() async throws {
        let identity = NodeIdentity(machineKey: .init(), nodeKey: .init())
        let oldKey = try #require(identity.nodePublicKey)
        try await withClient(prepare: { server, store, _ in
            try store.save(identity)
            server.enqueueRegisterReply(#"{"NodeKeySignature":"\#(Data([0xff, 0x00]).base64EncodedString())"}"#)
        }) { server, store in
            try await server.wait("The map stream did not open") { !$0.openMapStreams.isEmpty }
            let second = try object(try #require(registerRequests(server).last))
            #expect(registerRequests(server).count == 2)
            #expect(try nodeKey(second) != oldKey)
            #expect(try nodeKey(second, "OldNodeKey") == oldKey)
            #expect(second["NodeKeySignature"] is NSNull)
            #expect(try #require(try store.load()).nodePublicKey == (try nodeKey(second)))
        }
    }

    /// Contract §5, TL-11b item 1: Re-sign only chains signed by this node with its NL key. A node registered with a signed auth key
    /// has a rotation signature signed by the wrapped key, so it falls under this rule (Go produces a signature that the recipient cannot verify).
    @Test("A re-signing request for a node registered with a signed auth key registers with a new key and no signature (TL-11b item 1)")
    func resignRequestForCredentialChain() async throws {
        let lock = Lock()
        let identity = NodeIdentity(machineKey: .init(), nodeKey: .init())
        let oldKey = try #require(identity.nodePublicKey)
        var credential = NodeKeySignature(
            kind: NodeKeySignature.Kind.credential, keyID: Array(lock.trustedKey.publicKey.rawRepresentation),
            wrappingPublicKey: Array(lock.wrappingKey.publicKey.rawRepresentation)
        )
        try credential.sign(with: lock.trustedKey)
        var registered = NodeKeySignature(kind: NodeKeySignature.Kind.rotation, publicKey: oldKey.binaryForm, nested: credential)
        try registered.sign(with: lock.wrappingKey)
        #expect(try lock.state.authorize(oldKey, keySignature: registered.serialized()) != nil)
        try await withClient(prepare: { server, store, _ in
            try store.save(identity)
            server.enqueueRegisterReply(#"{"NodeKeySignature":"\#(Data(registered.serialized()).base64EncodedString())"}"#)
        }) { server, store in
            try await server.wait("The map stream did not open") { !$0.openMapStreams.isEmpty }
            let requests = try registerRequests(server).map(object)
            #expect(requests.count == 2)
            let second = try #require(requests.last)
            #expect(try nodeKey(second) != oldKey)
            #expect(try nodeKey(second, "OldNodeKey") == oldKey)
            #expect(second["NodeKeySignature"] is NSNull)
            #expect(try #require(try store.load()).nodePublicKey == (try nodeKey(second)))
        }
    }

    @Test("Repeated re-signing requests abandon the registration and reconnect to register with the stored key")
    func repeatedResignRequest() async throws {
        let lock = Lock()
        let identity = NodeIdentity(machineKey: .init(), nodeKey: .init())
        let oldKey = try #require(identity.nodePublicKey)
        let reply = #"{"NodeKeySignature":"\#(Data(try lock.directSignature(for: oldKey, wrappingKey: identity.lockPublicKey)).base64EncodedString())"}"#
        try await withClient(prepare: { server, store, _ in
            try store.save(identity)
            server.enqueueRegisterReply(reply)
            server.enqueueRegisterReply(reply)
        }) { server, store in
            try await server.wait("The map stream did not open") { !$0.openMapStreams.isEmpty }
            let requests = try registerRequests(server).map(object)
            #expect(requests.count == 3)
            #expect(server.keyRequests == 2, "Did not reconnect")
            #expect(try nodeKey(requests[2]) == oldKey)
            #expect(try #require(try store.load()).nodePublicKey == oldKey)
        }
    }

    // MARK: Secrets

    @Test("Configuration and errors holding a signed auth key do not expose the wrapped key (behavior K2)")
    func secretsInRenderings() throws {
        let lock = Lock()
        let authKey = try lock.authKey()
        let configuration = ControlClient.Configuration(
            serverURL: try #require(URL(string: "http://127.0.0.1:9911")), hostname: "rd-mac-1a2b3c4d", authKey: authKey
        )
        let wrapped = try #require(try AuthKey.wrapped(in: authKey))
        var dumped = ""
        dump(configuration, to: &dumped)
        dump(wrapped, to: &dumped)
        let rendered = [String(describing: configuration), String(reflecting: configuration), String(describing: wrapped), String(reflecting: wrapped), dumped]
        let seed = Array(lock.wrappingKey.rawRepresentation)
        for text in rendered {
            for secret in ["tskey-auth-fake", "--TL", Self.rawBase64(lock.wrappedPrivateKey), Self.rawBase64(seed), seed.hex] {
                #expect(!text.contains(secret))
            }
        }
        do throws(ControlError) {
            _ = try AuthKey.wrapped(in: authKey + "x")
            Issue.record("Accepted a malformed auth key")
        } catch {
            #expect(!String(describing: error).contains("tskey") && !String(describing: error).contains(Self.rawBase64(seed)))
        }
    }
}
