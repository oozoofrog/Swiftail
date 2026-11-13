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

            identity.nodeKey = Curve25519.KeyAgreement.PrivateKey()
            try store.save(identity)
            loaded = try #require(try store.load())
            #expect(loaded.machinePublicKey == identity.machinePublicKey)
            #expect(loaded.nodeKey?.rawRepresentation == identity.nodeKey?.rawRepresentation)
            #expect(loaded.nodePublicKey == identity.nodePublicKey)
        }
    }

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

    @Test("description과 dump에 개인 키가 나오지 않는다")
    func hidesPrivateKeys() {
        var identity = NodeIdentity()
        identity.nodeKey = Curve25519.KeyAgreement.PrivateKey()
        var dumped = ""
        dump(identity, to: &dumped)
        for key in [identity.machineKey, identity.nodeKey].compactMap({ $0 }) {
            let hex = key.rawRepresentation.map { String(format: "%02x", $0) }.joined()
            #expect(!String(describing: identity).contains(hex))
            #expect(!String(reflecting: identity).contains(hex))
            #expect(!dumped.contains(hex))
        }
        #expect(String(describing: identity).contains(identity.machinePublicKey.description))
    }
}
