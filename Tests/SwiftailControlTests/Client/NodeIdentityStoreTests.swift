import CryptoKit
import Foundation
import Testing

@testable import SwiftailControl

@Suite("신원 저장")
struct NodeIdentityStoreTests {
    /// 시험마다 새 디렉터리를 만들고 끝나면 지운다.
    private func withDirectory(_ body: (URL) throws -> Void) throws {
        let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-identity-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        try body(directory)
    }

    @Test("파일이 없으면 nil")
    func missing() throws {
        try withDirectory { directory in
            let loaded = try NodeIdentityStore(directory: directory).load()
            #expect(loaded == nil)
        }
    }

    @Test("저장한 신원을 그대로 읽는다(node 키 있음·없음)")
    func roundTrip() throws {
        try withDirectory { directory in
            let store = NodeIdentityStore(directory: directory)
            var identity = NodeIdentity()
            try store.save(identity)
            var loaded = try #require(try store.load())
            #expect(loaded.machineKey.rawRepresentation == identity.machineKey.rawRepresentation)
            #expect(loaded.nodeKey == nil)
            #expect(loaded.lockKey.rawRepresentation == identity.lockKey.rawRepresentation)

            identity.nodeKey = Curve25519.KeyAgreement.PrivateKey()
            try store.save(identity)
            loaded = try #require(try store.load())
            #expect(loaded.machinePublicKey == identity.machinePublicKey)
            #expect(loaded.nodeKey?.rawRepresentation == identity.nodeKey?.rawRepresentation)
            #expect(loaded.nodePublicKey == identity.nodePublicKey)
            #expect(loaded.lockPublicKey == identity.lockPublicKey)
        }
    }

    /// NL 키가 없는 옛 형식(tailnet lock 전)의 파일을 쓴다.
    private func writeOldFormat(_ identity: NodeIdentity, to store: NodeIdentityStore, directory: URL) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        var object = ["MachineKey": "privkey:" + hex(identity.machineKey.rawRepresentation)]
        if let nodeKey = identity.nodeKey { object["NodeKey"] = "privkey:" + hex(nodeKey.rawRepresentation) }
        try JSONSerialization.data(withJSONObject: object).write(to: store.fileURL)
    }

    @Test("NL 키가 없는 옛 파일: 같은 machine 키·node 키로 뜨고, 새 NL 키를 저장한 뒤 다시 읽어도 같다(동작 R1)", arguments: [false, true])
    func migratesOldFile(withNodeKey: Bool) throws {
        try withDirectory { directory in
            let store = NodeIdentityStore(directory: directory)
            var old = NodeIdentity()
            if withNodeKey { old.nodeKey = Curve25519.KeyAgreement.PrivateKey() }
            try writeOldFormat(old, to: store, directory: directory)

            // `load()`는 저장하지 않는다.
            let unsaved = try #require(try store.load())
            #expect(unsaved.machinePublicKey == old.machinePublicKey)
            #expect(try fileObject(store)["NLKey"] == nil)

            let migrated = try store.loadOrCreate()
            #expect(migrated.machinePublicKey == old.machinePublicKey)
            #expect(migrated.nodePublicKey == old.nodePublicKey)
            #expect(try fileObject(store)["NLKey"] == NodeIdentityStore.text(migrated.lockKey))

            let again = try store.loadOrCreate()
            #expect(again.lockKey.rawRepresentation == migrated.lockKey.rawRepresentation)
            #expect(try #require(try store.load()).lockPublicKey == migrated.lockPublicKey)

            let attributes = try FileManager.default.attributesOfItem(atPath: store.fileURL.path)
            #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
            #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path) == [NodeIdentityStore.fileName])
        }
    }

    @Test("파일이 없으면 loadOrCreate가 새 신원을 저장한다")
    func createsIdentity() throws {
        try withDirectory { directory in
            let store = NodeIdentityStore(directory: directory)
            let created = try store.loadOrCreate()
            let loaded = try #require(try store.load())
            #expect(loaded.machinePublicKey == created.machinePublicKey)
            #expect(loaded.lockPublicKey == created.lockPublicKey)
            #expect(loaded.nodeKey == nil)
        }
    }

    private func fileObject(_ store: NodeIdentityStore) throws -> [String: String] {
        try #require(try JSONSerialization.jsonObject(with: Data(contentsOf: store.fileURL)) as? [String: String])
    }

    private func hex(_ bytes: some DataProtocol) -> String { bytes.map { String(format: "%02x", $0) }.joined() }

    @Test("파일은 소유자만 읽고, 임시 파일을 남기지 않는다")
    func permissions() throws {
        try withDirectory { directory in
            let store = NodeIdentityStore(directory: directory)
            try store.save(NodeIdentity())
            try store.save(NodeIdentity())
            let attributes = try FileManager.default.attributesOfItem(atPath: store.fileURL.path)
            #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
            #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path) == [NodeIdentityStore.fileName])
        }
    }

    @Test("파일 형식: privkey: + 16진 64자리", arguments: [false, true])
    func fileFormat(withNodeKey: Bool) throws {
        try withDirectory { directory in
            let store = NodeIdentityStore(directory: directory)
            var identity = NodeIdentity()
            if withNodeKey { identity.nodeKey = Curve25519.KeyAgreement.PrivateKey() }
            try store.save(identity)
            let object = try #require(try JSONSerialization.jsonObject(with: Data(contentsOf: store.fileURL)) as? [String: String])
            #expect(object["MachineKey"] == "privkey:" + identity.machineKey.rawRepresentation.map { String(format: "%02x", $0) }.joined())
            #expect((object["NodeKey"] != nil) == withNodeKey)
            // nlpriv: + 시드 ‖ 공개 키.
            let seed = hex(identity.lockKey.rawRepresentation), lockPublic = hex(identity.lockKey.publicKey.rawRepresentation)
            #expect(object["NLKey"] == "nlpriv:" + seed + lockPublic)
        }
    }

    @Test("손상된 파일은 storage 오류이고 키를 드러내지 않는다", arguments: [
        "",
        "not json",
        #"{}"#,
        #"{"MachineKey":"privkey:abcd"}"#,
        #"{"MachineKey":"mkey:\#(String(repeating: "ab", count: 32))"}"#,
        #"{"MachineKey":"privkey:\#(String(repeating: "zz", count: 32))"}"#,
        #"{"MachineKey":"privkey:\#(String(repeating: "ab", count: 32))","NodeKey":"privkey:12"}"#,
        // 깨진 NL 키: 빈 값, 접두사, 시드만, 길이, 16진이 아님, 뒤 32바이트가 시드의 공개 키가 아님(동작 R1).
        Self.withLockKey(""),
        Self.withLockKey("privkey:" + String(repeating: "ab", count: 64)),
        Self.withLockKey("nlpub:" + Self.validLockKeyHex),
        Self.withLockKey("nlpriv:" + String(Self.validLockKeyHex.prefix(64))),
        Self.withLockKey("nlpriv:" + Self.validLockKeyHex + "00"),
        Self.withLockKey("nlpriv:" + String(repeating: "zz", count: 64)),
        Self.withLockKey("nlpriv:" + String(Self.validLockKeyHex.prefix(64)) + String(repeating: "ab", count: 32)),
        #"{"MachineKey":"privkey:\#(String(repeating: "ab", count: 32))","NLKey":7}"#,
    ])
    func corrupted(contents: String) throws {
        try withDirectory { directory in
            let store = NodeIdentityStore(directory: directory)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            try Data(contents.utf8).write(to: store.fileURL)
            do throws(ControlError) {
                _ = try store.load()
                Issue.record("손상된 파일을 받아들였다")
            } catch {
                guard case .storage(let message) = error else {
                    Issue.record("storage 오류가 아니다: \(error)")
                    return
                }
                #expect(!message.contains("ab"))
            }
        }
    }

    /// Go 기준값의 NL 개인 키(`tka-fixtures.json`의 `nlpriv-decode`. 시험 전용 공개 값).
    static let validLockKeyHex = "d132274d5c925219b42ed925e1b1c8aed8b70c35cd1ba669de00a9f56c9dd5caeea291d210cd96c16600e331c931c130d142e0b0fd9ddcfa1fcfb756e6a00438"

    static func withLockKey(_ text: String) -> String {
        #"{"MachineKey":"privkey:\#(String(repeating: "ab", count: 32))","NLKey":"\#(text)"}"#
    }

    @Test("Go 기준값의 NL 키를 담은 파일을 읽는다")
    func readsLockKey() throws {
        try withDirectory { directory in
            let store = NodeIdentityStore(directory: directory)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            try Data(Self.withLockKey("nlpriv:" + Self.validLockKeyHex.uppercased()).utf8).write(to: store.fileURL)
            let loaded = try store.loadOrCreate()
            #expect(loaded.lockPublicKey.rawValue.hex == String(Self.validLockKeyHex.suffix(64)))
            // NL 키가 있던 파일은 다시 쓰지 않는다.
            #expect(try fileObject(store)["NLKey"] == "nlpriv:" + Self.validLockKeyHex.uppercased())
        }
    }

    @Test("description과 dump에 개인 키가 나오지 않는다")
    func hidesPrivateKeys() {
        var identity = NodeIdentity()
        identity.nodeKey = Curve25519.KeyAgreement.PrivateKey()
        var dumped = ""
        dump(identity, to: &dumped)
        let privateKeys = [identity.machineKey, identity.nodeKey].compactMap { $0?.rawRepresentation } + [identity.lockKey.rawRepresentation]
        for key in privateKeys {
            let hex = key.map { String(format: "%02x", $0) }.joined()
            #expect(!String(describing: identity).contains(hex))
            #expect(!String(reflecting: identity).contains(hex))
            #expect(!dumped.contains(hex))
        }
        #expect(String(describing: identity).contains(identity.machinePublicKey.description))
        #expect(String(describing: identity).contains(identity.lockPublicKey.description))
    }
}
