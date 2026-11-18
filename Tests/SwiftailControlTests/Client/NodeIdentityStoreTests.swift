import CryptoKit
import Foundation
import Testing

@testable import SwiftailControl

@Suite("Identity storage")
struct NodeIdentityStoreTests {
    /// Creates a fresh directory for each test and removes it afterward.
    private func withDirectory(_ body: (URL) throws -> Void) throws {
        let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-identity-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        try body(directory)
    }

    @Test("Returns nil if the file is missing")
    func missing() throws {
        try withDirectory { directory in
            let loaded = try NodeIdentityStore(directory: directory).load()
            #expect(loaded == nil)
        }
    }

    @Test("Loads the stored identity unchanged, with or without a node key")
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

    /// Writes a file in the old format (before tailnet lock), without an NL key.
    private func writeOldFormat(_ identity: NodeIdentity, to store: NodeIdentityStore, directory: URL) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        var object = ["MachineKey": "privkey:" + hex(identity.machineKey.rawRepresentation)]
        if let nodeKey = identity.nodeKey { object["NodeKey"] = "privkey:" + hex(nodeKey.rawRepresentation) }
        try JSONSerialization.data(withJSONObject: object).write(to: store.fileURL)
    }

    @Test("An old file without an NL key starts with the same machine and node keys, and they stay the same after storing a new NL key and reloading (behavior R1)", arguments: [false, true])
    func migratesOldFile(withNodeKey: Bool) throws {
        try withDirectory { directory in
            let store = NodeIdentityStore(directory: directory)
            var old = NodeIdentity()
            if withNodeKey { old.nodeKey = Curve25519.KeyAgreement.PrivateKey() }
            try writeOldFormat(old, to: store, directory: directory)

            // `load()` does not save.
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

    @Test("If the file is missing, loadOrCreate stores a new identity")
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

    @Test("Only the owner can read the file, and no temporary file remains")
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

    @Test("File format: privkey: + 64 base-16 digits", arguments: [false, true])
    func fileFormat(withNodeKey: Bool) throws {
        try withDirectory { directory in
            let store = NodeIdentityStore(directory: directory)
            var identity = NodeIdentity()
            if withNodeKey { identity.nodeKey = Curve25519.KeyAgreement.PrivateKey() }
            try store.save(identity)
            let object = try #require(try JSONSerialization.jsonObject(with: Data(contentsOf: store.fileURL)) as? [String: String])
            #expect(object["MachineKey"] == "privkey:" + identity.machineKey.rawRepresentation.map { String(format: "%02x", $0) }.joined())
            #expect((object["NodeKey"] != nil) == withNodeKey)
            // nlpriv: + seed ‖ public key.
            let seed = hex(identity.lockKey.rawRepresentation), lockPublic = hex(identity.lockKey.publicKey.rawRepresentation)
            #expect(object["NLKey"] == "nlpriv:" + seed + lockPublic)
        }
    }

    @Test("A corrupt file yields a storage error and does not expose the key", arguments: [
        "",
        "not json",
        #"{}"#,
        #"{"MachineKey":"privkey:abcd"}"#,
        #"{"MachineKey":"mkey:\#(String(repeating: "ab", count: 32))"}"#,
        #"{"MachineKey":"privkey:\#(String(repeating: "zz", count: 32))"}"#,
        #"{"MachineKey":"privkey:\#(String(repeating: "ab", count: 32))","NodeKey":"privkey:12"}"#,
        // Invalid NL keys: empty value, prefix, seed alone, length, non-base-16 text, and last 32 bytes that differ from the seed's public key (behavior R1).
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
                Issue.record("Accepted a corrupt file")
            } catch {
                guard case .storage(let message) = error else {
                    Issue.record("Expected a storage error, got \(error)")
                    return
                }
                #expect(!message.contains("ab"))
            }
        }
    }

    /// Checks whether `load()` ends with a storage error.
    private func expectStorageError(_ store: NodeIdentityStore, sourceLocation: SourceLocation = #_sourceLocation) {
        do throws(ControlError) {
            _ = try store.load()
            Issue.record("Accepted a file that must not be read", sourceLocation: sourceLocation)
        } catch {
            guard case .storage = error else {
                Issue.record("Expected a storage error, got \(error)", sourceLocation: sourceLocation)
                return
            }
        }
    }

    @Test("Does not follow a symlink at the identity file path")
    func refusesSymbolicLink() throws {
        try withDirectory { directory in
            // A valid identity file is located elsewhere, and `identity.json` in the state directory is a link to it.
            let elsewhere = NodeIdentityStore(directory: directory.appending(path: "elsewhere"))
            try elsewhere.save(NodeIdentity())
            let store = NodeIdentityStore(directory: directory.appending(path: "state"))
            try FileManager.default.createDirectory(at: directory.appending(path: "state"), withIntermediateDirectories: true)
            try FileManager.default.createSymbolicLink(at: store.fileURL, withDestinationURL: elsewhere.fileURL)
            expectStorageError(store)
        }
    }

    @Test("Reads identity files only up to 64KiB")
    func limitsFileSize() throws {
        try withDirectory { directory in
            let store = NodeIdentityStore(directory: directory)
            try store.save(NodeIdentity())
            let contents = try Data(contentsOf: store.fileURL)
            // Padding the end with spaces still yields valid JSON. Reads up to the limit and refuses one byte more.
            try (contents + Data(repeating: 0x20, count: 65_536 - contents.count)).write(to: store.fileURL)
            #expect(try store.load() != nil)
            try (contents + Data(repeating: 0x20, count: 65_537 - contents.count)).write(to: store.fileURL)
            expectStorageError(store)
        }
    }

    @Test("Does not read a non-regular file at the identity file path")
    func refusesNonRegularFile() throws {
        try withDirectory { directory in
            let store = NodeIdentityStore(directory: directory)
            try FileManager.default.createDirectory(at: store.fileURL, withIntermediateDirectories: true)
            expectStorageError(store)
        }
    }

    /// NL private key from the Go reference values (`nlpriv-decode` in `tka-fixtures.json`, a public test-only value).
    static let validLockKeyHex = "d132274d5c925219b42ed925e1b1c8aed8b70c35cd1ba669de00a9f56c9dd5caeea291d210cd96c16600e331c931c130d142e0b0fd9ddcfa1fcfb756e6a00438"

    static func withLockKey(_ text: String) -> String {
        #"{"MachineKey":"privkey:\#(String(repeating: "ab", count: 32))","NLKey":"\#(text)"}"#
    }

    @Test("Reads a file containing an NL key from the Go reference values")
    func readsLockKey() throws {
        try withDirectory { directory in
            let store = NodeIdentityStore(directory: directory)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            try Data(Self.withLockKey("nlpriv:" + Self.validLockKeyHex.uppercased()).utf8).write(to: store.fileURL)
            let loaded = try store.loadOrCreate()
            #expect(loaded.lockPublicKey.rawValue.hex == String(Self.validLockKeyHex.suffix(64)))
            // Does not rewrite a file that already contained an NL key.
            #expect(try fileObject(store)["NLKey"] == "nlpriv:" + Self.validLockKeyHex.uppercased())
        }
    }

    @Test("The private key is absent from description and dump output")
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
