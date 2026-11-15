// 등록 요청의 tailnet lock 필드: 계약 `docs/contracts/SwiftailTailnetLock.md` 동작 R·K, 단위 시험 15·16.
// 가짜 제어 서버(`SetDNSFakeControlServer`)와 실제 연결(업그레이드 → Noise → HTTP/2)로 돈다. 서버가 받은 요청의 바이트를 본다.
//
// 키는 모두 시험이 그 자리에서 만든다. 서명이 맞는지는 `SwiftailTKA`의 `authorize`(Go 판정과 대조된 것)로 본다.

import CryptoKit
import Foundation
import Testing

import SwiftailBase
@testable import SwiftailControl
@testable import SwiftailTKA

@Suite("제어 클라이언트: 등록의 NL 키와 서명", .timeLimit(.minutes(1)))
struct RegistrationSigningTests {
    /// 시험의 tailnet lock: 신뢰 키 하나와, 그 키가 위임한 감싼 키로 만든 서명된 인증 키.
    struct Lock {
        let trustedKey = Curve25519.Signing.PrivateKey()
        let wrappingKey = Curve25519.Signing.PrivateKey()

        var state: AuthorityState {
            AuthorityState(keys: [TrustedKey(kind: 1, votes: 1, publicKey: Array(trustedKey.publicKey.rawRepresentation))])
        }

        /// 감싼 개인 키(B): 시드 ‖ 공개 키 64바이트.
        var wrappedPrivateKey: [UInt8] {
            Array(wrappingKey.rawRepresentation) + Array(wrappingKey.publicKey.rawRepresentation)
        }

        /// `tskey-auth-fake--TL<credential>-<B>`(노트 3.8).
        func authKey(privateKey: [UInt8]? = nil) throws -> String {
            var credential = NodeKeySignature(
                kind: 3,
                keyID: Array(trustedKey.publicKey.rawRepresentation),
                wrappingPublicKey: Array(wrappingKey.publicKey.rawRepresentation)
            )
            try credential.sign(with: trustedKey)
            return "tskey-auth-fake--TL" + rawBase64(credential.serialized()) + "-" + rawBase64(privateKey ?? wrappedPrivateKey)
        }

        /// 신뢰 키로 서명한 direct 서명. `wrappingKey`면 그 키가 이 서명 위에 rotation으로 다시 서명할 수 있다.
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

    /// 가짜 서버와 클라이언트를 띄우고 `body`를 돌린다. 클라이언트의 `run()`은 끝나면 취소한다.
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
        let text = try #require(object["NodeKeySignature"] as? String, "서명이 없다")
        return [UInt8](try #require(Data(base64Encoded: text)))
    }

    // MARK: 평범한 인증 키

    @Test("평범한 인증 키: NLKey는 저장된 자기 NL 공개 키이고 서명은 null이다")
    func plainAuthKey() async throws {
        try await withClient(authKey: "tskey-auth-fake") { server, store in
            try await server.wait("맵 스트림이 열리지 않았다") { !$0.openMapStreams.isEmpty }
            let request = try object(try #require(registerRequests(server).first))
            let stored = try #require(try store.load())
            #expect(request["NLKey"] as? String == stored.lockPublicKey.description)
            #expect(stored.lockPublicKey != .zero)
            #expect(request["NodeKeySignature"] is NSNull)
            #expect((request["Auth"] as? [String: Any])?["AuthKey"] as? String == "tskey-auth-fake")
        }
    }

    @Test("NL 키가 없는 옛 신원 파일: 첫 요청 전에 새 NL 키를 저장하고 그 키를 싣는다(동작 R1)")
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
            try await server.wait("등록 요청이 오지 않았다") { !registerRequests($0).isEmpty }
            let request = try object(try #require(registerRequests(server).first))
            let stored = try #require(try store.load())
            // 같은 노드로 뜬다: 저장된 node 키로 다시 붙는다.
            #expect(try nodeKey(request) == old.nodePublicKey)
            #expect(stored.machinePublicKey == old.machinePublicKey)
            #expect(request["NLKey"] as? String == stored.lockPublicKey.description)
            #expect(request["NodeKeySignature"] is NSNull)
            #expect(request["Auth"] == nil)
        }
    }

    // MARK: 서명된 인증 키

    @Test("서명된 인증 키: 서버로 간 인증 키는 --TL 앞부분이고, 서명은 그 node 키를 인가한다")
    func signedAuthKey() async throws {
        let lock = Lock()
        let authKey = try lock.authKey()
        try await withClient(authKey: authKey) { server, store in
            try await server.wait("맵 스트림이 열리지 않았다") { !$0.openMapStreams.isEmpty }
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

    @Test("서버로 간 어떤 요청에도 --TL 뒤와 감싼 개인 키(base64·16진·바이트)가 없다(동작 R4·K3)")
    func noWrappedKeyOnTheWire() async throws {
        let lock = Lock()
        let authKey = try lock.authKey()
        try await withClient(authKey: authKey) { server, _ in
            try await server.wait("맵 스트림이 열리지 않았다") { !$0.openMapStreams.isEmpty }
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
                    #expect(wire.firstRange(of: secret) == nil, "\(request.path)에 비밀이 실렸다")
                }
                #expect(wire.firstRange(of: Array("--TL".utf8)) == nil)
            }
        }
    }

    @Test("해석되지 않는 --TL: 요청이 하나도 나가지 않고 invalidConfiguration이다(결정 L12·L13)", arguments: [
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
            Issue.record("run()이 invalidConfiguration으로 곧바로 끝나지 않았다")
            return
        }
        #expect(server.keyRequests == 0)
        #expect(server.requests.isEmpty)
        #expect(!message.contains(suffix) && !message.contains(parts[1]) && !message.contains("tskey"))
    }

    // MARK: 재서명 요청

    @Test("재서명 요청: 새 node 키를 만들고, 받은 서명을 NL 키로 이어 서명해 다시 등록한다(동작 R6·R7)")
    func resignRequest() async throws {
        let lock = Lock()
        let identity = NodeIdentity(machineKey: .init(), nodeKey: .init())
        let oldKey = try #require(identity.nodePublicKey)
        let oldSignature = try lock.directSignature(for: oldKey, wrappingKey: identity.lockPublicKey)
        try await withClient(prepare: { server, store, _ in
            try store.save(identity)
            server.enqueueRegisterReply(#"{"NodeKeySignature":"\#(Data(oldSignature).base64EncodedString())"}"#)
        }) { server, store in
            try await server.wait("맵 스트림이 열리지 않았다") { !$0.openMapStreams.isEmpty }
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

    @Test("재서명하지 못하는 옛 서명이면 서명 없이 새 키로 등록한다(동작 R5 ①)")
    func unreadableResignInput() async throws {
        let identity = NodeIdentity(machineKey: .init(), nodeKey: .init())
        let oldKey = try #require(identity.nodePublicKey)
        try await withClient(prepare: { server, store, _ in
            try store.save(identity)
            server.enqueueRegisterReply(#"{"NodeKeySignature":"\#(Data([0xff, 0x00]).base64EncodedString())"}"#)
        }) { server, store in
            try await server.wait("맵 스트림이 열리지 않았다") { !$0.openMapStreams.isEmpty }
            let second = try object(try #require(registerRequests(server).last))
            #expect(registerRequests(server).count == 2)
            #expect(try nodeKey(second) != oldKey)
            #expect(try nodeKey(second, "OldNodeKey") == oldKey)
            #expect(second["NodeKeySignature"] is NSNull)
            #expect(try #require(try store.load()).nodePublicKey == (try nodeKey(second)))
        }
    }

    @Test("재서명 요청이 거듭 오면 그 등록을 그만두고 다시 이어 저장된 키로 등록한다")
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
            try await server.wait("맵 스트림이 열리지 않았다") { !$0.openMapStreams.isEmpty }
            let requests = try registerRequests(server).map(object)
            #expect(requests.count == 3)
            #expect(server.keyRequests == 2, "다시 잇지 않았다")
            #expect(try nodeKey(requests[2]) == oldKey)
            #expect(try #require(try store.load()).nodePublicKey == oldKey)
        }
    }

    // MARK: 비밀

    @Test("서명된 인증 키를 쥔 설정과 오류에 감싼 키가 나오지 않는다(동작 K2)")
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
            Issue.record("깨진 인증 키를 받아들였다")
        } catch {
            #expect(!String(describing: error).contains("tskey") && !String(describing: error).contains(Self.rawBase64(seed)))
        }
    }
}
