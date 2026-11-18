// Contract §7 unit test 11 (storage): behaviors S1–S3 and S6, C4, and H7, H16, and H20. Name validation cases (behavior C2) are
// covered by `CSR/CertificateDomainTests.swift`. The store accepts only `CertificateDomain` values that passed that validation.
//
// Creates files only under the directory specified by `SWIFTAIL_TEST_SCRATCH`. If it is missing, skips this test group.

import CryptoKit
import Foundation
import Security
import Testing

@testable import SwiftailCertificates

/// A state directory for one test. Creates it under `SWIFTAIL_TEST_SCRATCH` and removes it when done.
private struct ScratchState {
    static let root = ProcessInfo.processInfo.environment["SWIFTAIL_TEST_SCRATCH"]

    let url: URL
    var certs: URL { url.appending(path: "certs", directoryHint: .isDirectory) }

    init() throws {
        let root = URL(fileURLWithPath: try #require(Self.root), isDirectory: true)
        url = root.appending(path: "store-\(UUID().uuidString)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    }

    func remove() {
        try? FileManager.default.removeItem(at: url)
    }

    func file(_ name: String) -> URL { certs.appending(path: name, directoryHint: .notDirectory) }

    func mode(_ url: URL) throws -> Int {
        try #require(try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? Int)
    }

    func setMode(_ mode: Int, _ url: URL) throws {
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: url.path)
    }

    /// Writes directly to simulate files left by Go, interrupted writes, and corrupt files.
    func put(_ bytes: [UInt8], _ name: String, mode: Int = 0o600) throws {
        try FileManager.default.createDirectory(at: certs, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try Data(bytes).write(to: file(name))
        try setMode(mode, file(name))
    }

    func contents(_ name: String) throws -> [UInt8] { Array(try Data(contentsOf: file(name))) }
}

@Suite("Certificate storage", .enabled(if: ScratchState.root != nil, "SWIFTAIL_TEST_SCRATCH is missing"))
struct CertificateStoreTests {
    let pki: TestPKI

    init() throws {
        pki = try TestPKI()
    }

    private func verified(_ chain: [[UInt8]]? = nil, key: P256.Signing.PrivateKey? = nil) throws -> VerifiedCertificate {
        let key = key ?? pki.key
        return try pki.verify(pemChain(chain ?? [pki.leaf(key: key.publicKey), pki.intermediate.certificate]), key: key)
    }

    private func load(_ store: CertificateStore, at now: Date = TestPKI.now) throws -> VerifiedCertificate? {
        try store.certificate(for: pki.domain, at: now, anchors: pki.anchors)
    }

    private var crt: String { TestPKI.domainName + ".crt" }
    private var key: String { TestPKI.domainName + ".key" }

    // MARK: - Reading, writing, and permissions

    @Test("Read and write: same location and names as Go, mode 0700 for new certs/, and 0600 for all new files, including certificates")
    func roundTrip() throws {
        let state = try ScratchState()
        defer { state.remove() }
        let store = CertificateStore(stateDirectory: state.url)
        #expect(try load(store) == nil)

        let certificate = try verified()
        try store.save(certificate)
        let accountKey = P256.Signing.PrivateKey()
        try store.saveAccountKey(accountKey)

        #expect(try state.mode(state.certs) == 0o700)
        for name in [crt, key, "acme-account.key.pem"] {
            #expect(try state.mode(state.file(name)) == 0o600, "\(name)")
        }
        let names = try FileManager.default.contentsOfDirectory(atPath: state.certs.path).sorted()
        #expect(names == ["acme-account.key.pem", crt, key].sorted())  // No temporary files remain

        let read = try #require(try load(store))
        #expect(read.chain == certificate.chain)
        #expect(read.lifetime == certificate.lifetime)
        #expect(read.privateKey.rawRepresentation == pki.key.rawRepresentation)
        #expect(try store.accountKey()?.rawRepresentation == accountKey.rawRepresentation)
        // PKCS#8 PEM for the key and CERTIFICATE PEM for the chain, starting with the leaf.
        #expect(String(decoding: try state.contents(key), as: UTF8.self).hasPrefix("-----BEGIN PRIVATE KEY-----\n"))
        #expect(try PEM.certificateChain(from: state.contents(crt), maximumByteCount: 1 << 16) == certificate.receivedChain)
    }

    @Test("A root included in the received chain stays in the file and is omitted from the loaded chain (behavior S6)")
    func rootKeptInFile() throws {
        let state = try ScratchState()
        defer { state.remove() }
        let store = CertificateStore(stateDirectory: state.url)
        let received = [pki.leaf(), pki.intermediate.certificate, pki.root.certificate]
        try store.save(try verified(received))
        #expect(try PEM.certificateChain(from: state.contents(crt), maximumByteCount: 1 << 16) == received)
        #expect(try load(store)?.chain == Array(received.prefix(2)))
    }

    @Test("Rewriting replaces the contents (certificate renewal)")
    func overwrite() throws {
        let state = try ScratchState()
        defer { state.remove() }
        let store = CertificateStore(stateDirectory: state.url)
        try store.save(try verified())
        let newKey = P256.Signing.PrivateKey()
        try store.save(try verified(key: newKey))
        #expect(try load(store)?.privateKey.rawRepresentation == newKey.rawRepresentation)
    }

    @Test("Existing certs/ permissions stay as they are", arguments: [0o750, 0o755, 0o711])
    func keepsExistingMode(mode: Int) throws {
        let state = try ScratchState()
        defer { state.remove() }
        try FileManager.default.createDirectory(at: state.certs, withIntermediateDirectories: false)
        try state.setMode(mode, state.certs)
        let store = CertificateStore(stateDirectory: state.url)
        try store.save(try verified())
        #expect(try load(store) != nil)
        #expect(try state.mode(state.certs) == mode)
    }

    @Test("An existing certs/ writable by the group or others returns storage for reads and writes (H20)", arguments: [0o770, 0o702, 0o777])
    func writableByOthers(mode: Int) throws {
        let state = try ScratchState()
        defer { state.remove() }
        let store = CertificateStore(stateDirectory: state.url)
        let certificate = try verified()
        try store.save(certificate)
        try store.saveAccountKey(P256.Signing.PrivateKey())
        let before = try [crt, key, "acme-account.key.pem"].map(state.contents)
        try state.setMode(mode, state.certs)

        #expect(throws: CertificateStoreError.self) { try load(store) }
        #expect(throws: CertificateStoreError.self) { try store.accountKey() }
        #expect(throws: CertificateStoreError.self) { try store.save(try verified(key: P256.Signing.PrivateKey())) }
        #expect(throws: CertificateStoreError.self) { try store.saveAccountKey(P256.Signing.PrivateKey()) }
        #expect(try [crt, key, "acme-account.key.pem"].map(state.contents) == before)
        #expect(try state.mode(state.certs) == mode)
        do throws(CertificateStoreError) {
            _ = try store.certificate(for: pki.domain, at: TestPKI.now, anchors: pki.anchors)
        } catch {
            // The message omits the path and name (behavior K3).
            guard case .storage(let message) = error else { Issue.record("\(error)"); return }
            #expect(!message.contains(state.url.path) && !message.contains(TestPKI.domainName))
        }
    }

    @Test("Permission checks: non-directory, another owner, and write access for group or others")
    func directoryProblem() {
        let user = geteuid()
        #expect(CertificateStore.directoryProblem(mode: S_IFDIR | 0o700, owner: user, currentUser: user) == nil)
        #expect(CertificateStore.directoryProblem(mode: S_IFDIR | 0o755, owner: user, currentUser: user) == nil)
        #expect(CertificateStore.directoryProblem(mode: S_IFDIR | 0o720, owner: user, currentUser: user) != nil)
        #expect(CertificateStore.directoryProblem(mode: S_IFDIR | 0o702, owner: user, currentUser: user) != nil)
        #expect(CertificateStore.directoryProblem(mode: S_IFDIR | 0o700, owner: user &+ 1, currentUser: user) != nil)
        #expect(CertificateStore.directoryProblem(mode: S_IFLNK | 0o700, owner: user, currentUser: user) != nil)
        #expect(CertificateStore.directoryProblem(mode: S_IFREG | 0o700, owner: user, currentUser: user) != nil)
    }

    // MARK: - Symbolic links

    @Test("A certs/ symbolic link is never followed")
    func symlinkedDirectory() throws {
        let state = try ScratchState()
        defer { state.remove() }
        let elsewhere = state.url.appending(path: "elsewhere", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: elsewhere, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        try FileManager.default.createSymbolicLink(at: state.certs, withDestinationURL: elsewhere)
        let store = CertificateStore(stateDirectory: state.url)
        #expect(throws: CertificateStoreError.self) { try load(store) }
        #expect(throws: CertificateStoreError.self) { try store.save(try verified()) }
        #expect(throws: CertificateStoreError.self) { try store.accountKey() }
        #expect(try FileManager.default.contentsOfDirectory(atPath: elsewhere.path).isEmpty)
    }

    @Test("A symbolic link is never read. Writing replaces the link itself and preserves its target")
    func symlinkedFile() throws {
        let state = try ScratchState()
        defer { state.remove() }
        let store = CertificateStore(stateDirectory: state.url)
        try store.save(try verified())
        let outside = state.url.appending(path: "outside.key", directoryHint: .notDirectory)
        let outsideBytes = Array(P256.Signing.PrivateKey().pemRepresentation.utf8)
        try Data(outsideBytes).write(to: outside)
        try FileManager.default.removeItem(at: state.file(key))
        try FileManager.default.createSymbolicLink(at: state.file(key), withDestinationURL: outside)

        #expect(throws: CertificateStoreError.self) { try load(store) }
        try store.save(try verified())
        #expect(Array(try Data(contentsOf: outside)) == outsideBytes)
        let type = try FileManager.default.attributesOfItem(atPath: state.file(key).path)[.type] as? FileAttributeType
        #expect(type == .typeRegular)
        #expect(try load(store) != nil)
    }

    @Test("A symbolic link for the account key returns storage and stays as it is")
    func symlinkedAccountKey() throws {
        let state = try ScratchState()
        defer { state.remove() }
        let outside = state.url.appending(path: "outside.pem", directoryHint: .notDirectory)
        try Data(P256.Signing.PrivateKey().pemRepresentation.utf8).write(to: outside)
        try state.put([], "placeholder")
        try FileManager.default.createSymbolicLink(at: state.file("acme-account.key.pem"), withDestinationURL: outside)
        let store = CertificateStore(stateDirectory: state.url)
        #expect(throws: CertificateStoreError.self) { try store.accountKey() }
        #expect(throws: CertificateStoreError.self) { try store.saveAccountKey(P256.Signing.PrivateKey()) }
        #expect(try FileManager.default.destinationOfSymbolicLink(atPath: state.file("acme-account.key.pem").path) == outside.path)
    }

    // MARK: - Read decisions (behavior S3)

    @Test("An interrupted write that leaves only the new key is treated as absent because the pair does not match (behavior S3 ④)")
    func keyWrittenWithoutCertificate() throws {
        let state = try ScratchState()
        defer { state.remove() }
        let store = CertificateStore(stateDirectory: state.url)
        try store.save(try verified())
        // The new issuance stopped after writing only the key file.
        try state.put(Array(P256.Signing.PrivateKey().pemRepresentation.utf8), key)
        #expect(try load(store) == nil)
    }

    @Test("Only one file is present")
    func onlyOneFile() throws {
        let state = try ScratchState()
        defer { state.remove() }
        let store = CertificateStore(stateDirectory: state.url)
        try store.save(try verified())
        try FileManager.default.removeItem(at: state.file(crt))
        #expect(try load(store) == nil)
    }

    @Test("A Go-written SEC1 key file and a mode 0644 certificate file (fixture test key)")
    func goWrittenFiles() throws {
        let fixture = try GoKeyFixture.load()
        let goKey = try P256.Signing.PrivateKey(pemRepresentation: fixture.sec1PEM)
        let state = try ScratchState()
        defer { state.remove() }
        try state.put(Array(fixture.sec1PEM.utf8), key, mode: 0o600)
        try state.put(pemChain([pki.leaf(key: goKey.publicKey), pki.intermediate.certificate]), crt, mode: 0o644)
        try state.put(Array(fixture.pkcs8PEM.utf8), "acme-account.key.pem", mode: 0o600)
        let store = CertificateStore(stateDirectory: state.url)
        let read = try #require(try load(store))
        #expect(read.privateKey.rawRepresentation == goKey.rawRepresentation)
        #expect(try store.accountKey()?.rawRepresentation == goKey.rawRepresentation)
        #expect(try state.mode(state.file(crt)) == 0o644)  // Reading does not change permissions
    }

    @Test("A stored certificate that has expired or has different anchors is treated as absent and is retained")
    func storedButInvalid() throws {
        let state = try ScratchState()
        defer { state.remove() }
        let store = CertificateStore(stateDirectory: state.url)
        try store.save(try verified())
        #expect(try load(store, at: TestPKI.leafEnd + 1) == nil)
        let stranger = TestCertificateAuthority.root("Stranger Root", from: TestPKI.now - TestPKI.day, to: TestPKI.now + TestPKI.day)
        #expect(try store.certificate(for: pki.domain, at: TestPKI.now, anchors: .only([stranger.certificate])) == nil)
        #expect(FileManager.default.fileExists(atPath: state.file(crt).path))
    }

    @Test("Files over 64KiB are treated as absent. Files up to 64KiB are read")
    func sizeLimit() throws {
        let state = try ScratchState()
        defer { state.remove() }
        let store = CertificateStore(stateDirectory: state.url)
        try store.save(try verified())
        let chain = try state.contents(crt)
        let padded = chain + Array(repeating: UInt8(ascii: "\n"), count: CertificateStore.maximumFileByteCount - chain.count)
        try state.put(padded, crt)
        #expect(try load(store) != nil)
        try state.put(padded + [UInt8(ascii: "\n")], crt)
        #expect(try load(store) == nil)
    }

    @Test("A directory at the name's path under certs/ returns storage")
    func notRegularFile() throws {
        let state = try ScratchState()
        defer { state.remove() }
        try FileManager.default.createDirectory(at: state.file(crt), withIntermediateDirectories: true)
        try state.setMode(0o700, state.certs)
        #expect(throws: CertificateStoreError.self) { try load(CertificateStore(stateDirectory: state.url)) }
    }

    @Test("A missing state directory yields absence on reads and storage on writes")
    func missingStateDirectory() throws {
        let state = try ScratchState()
        defer { state.remove() }
        let store = CertificateStore(stateDirectory: state.url.appending(path: "missing", directoryHint: .isDirectory))
        #expect(try load(store) == nil)
        #expect(try store.accountKey() == nil)
        #expect(throws: CertificateStoreError.self) { try store.save(try verified()) }
    }

    // MARK: - Account key (behavior C4, H16)

    @Test("An absent account key returns nil, and an existing key is never overwritten")
    func accountKeyNoOverwrite() throws {
        let state = try ScratchState()
        defer { state.remove() }
        let store = CertificateStore(stateDirectory: state.url)
        #expect(try store.accountKey() == nil)
        let first = P256.Signing.PrivateKey()
        try store.saveAccountKey(first)
        #expect(throws: CertificateStoreError.self) { try store.saveAccountKey(P256.Signing.PrivateKey()) }
        #expect(try store.accountKey()?.rawRepresentation == first.rawRepresentation)
        #expect(try FileManager.default.contentsOfDirectory(atPath: state.certs.path) == ["acme-account.key.pem"])
    }

    @Test("An unreadable account key returns accountKeyUnreadable and preserves the file", arguments: AccountKeyCase.allCases)
    func unreadableAccountKey(_ testCase: AccountKeyCase) throws {
        let state = try ScratchState()
        defer { state.remove() }
        let bytes = try testCase.bytes()
        try state.put(bytes, "acme-account.key.pem")
        let store = CertificateStore(stateDirectory: state.url)
        #expect(throws: CertificateStoreError.accountKeyUnreadable) { try store.accountKey() }
        #expect(throws: CertificateStoreError.self) { try store.saveAccountKey(P256.Signing.PrivateKey()) }
        #expect(try state.contents("acme-account.key.pem") == bytes)
    }

    enum AccountKeyCase: CaseIterable, Sendable {
        /// Go's old RSA account key (PKCS#1 `RSA PRIVATE KEY`).
        case rsa
        case garbage
        case empty
        /// A file with more than 64KiB appended after a P-256 key.
        case tooLarge
        /// Two blocks.
        case twoKeys

        func bytes() throws -> [UInt8] {
            switch self {
            case .rsa:
                let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048]
                let key = try #require(SecKeyCreateRandomKey(attributes as CFDictionary, nil))
                let pkcs1 = try #require(SecKeyCopyExternalRepresentation(key, nil) as Data?)
                let body = pkcs1.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
                return Array("-----BEGIN RSA PRIVATE KEY-----\n\(body)\n-----END RSA PRIVATE KEY-----\n".utf8)
            case .garbage:
                return Array("not a key\n".utf8)
            case .empty:
                return []
            case .tooLarge:
                return Array(P256.Signing.PrivateKey().pemRepresentation.utf8) + Array(repeating: UInt8(ascii: "\n"), count: 64 * 1024)
            case .twoKeys:
                return Array((P256.Signing.PrivateKey().pemRepresentation + P256.Signing.PrivateKey().pemRepresentation).utf8)
            }
        }
    }

    @Test("The value function for decoding an account key")
    func decodeAccountKey() throws {
        #expect(try CertificateStore.decodeAccountKey(.missing) == nil)
        #expect(throws: CertificateStoreError.accountKeyUnreadable) { try CertificateStore.decodeAccountKey(.tooLarge) }
        let key = P256.Signing.PrivateKey()
        #expect(try CertificateStore.decodeAccountKey(.contents(Array(key.pemRepresentation.utf8)))?.rawRepresentation == key.rawRepresentation)
    }
}

/// `keys[0]` in `Fixtures/acme-fixtures.json` (SEC1 and PKCS#8 PEM for a test-only key written by Go).
private struct GoKeyFixture: Decodable {
    var sec1PEM: String
    var pkcs8PEM: String

    private struct File: Decodable { var keys: [GoKeyFixture] }

    static func load() throws -> GoKeyFixture {
        let url = try #require(Bundle.module.url(forResource: "acme-fixtures", withExtension: "json", subdirectory: "Fixtures"))
        let file = try JSONDecoder().decode(File.self, from: Data(contentsOf: url))
        return try #require(file.keys.first)
    }
}
