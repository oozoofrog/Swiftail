// 계약 7절 단위 시험 11(저장): 동작 S1~S3·S6, C4, H7·H16·H20. 이름 검사(동작 C2)의 사례는
// `CSR/CertificateDomainTests.swift`가 다룬다(저장소는 그 검사를 통과한 `CertificateDomain`만 받는다).
//
// 파일은 `SWIFTAIL_TEST_SCRATCH`가 가리키는 디렉터리 아래에만 만든다. 없으면 이 묶음을 건너뛴다.

import CryptoKit
import Foundation
import Security
import Testing

@testable import SwiftailCertificates

/// 시험마다 하나씩 쓰는 상태 디렉터리. `SWIFTAIL_TEST_SCRATCH` 아래에 만들고 끝나면 지운다.
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

    /// 저장소를 거치지 않고 파일을 쓴다(Go가 남긴 파일, 멈춘 쓰기, 망가진 파일을 흉내 낸다).
    func put(_ bytes: [UInt8], _ name: String, mode: Int = 0o600) throws {
        try FileManager.default.createDirectory(at: certs, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try Data(bytes).write(to: file(name))
        try setMode(mode, file(name))
    }

    func contents(_ name: String) throws -> [UInt8] { Array(try Data(contentsOf: file(name))) }
}

@Suite("인증서 저장", .enabled(if: ScratchState.root != nil, "SWIFTAIL_TEST_SCRATCH가 없다"))
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

    // MARK: - 쓰고 읽기, 권한

    @Test("쓰고 읽기: Go와 같은 자리·이름, 새 certs/는 0700, 새 파일은 모두 0600(인증서 포함)")
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
        #expect(names == ["acme-account.key.pem", crt, key].sorted())  // 임시 파일이 남지 않는다

        let read = try #require(try load(store))
        #expect(read.chain == certificate.chain)
        #expect(read.lifetime == certificate.lifetime)
        #expect(read.privateKey.rawRepresentation == pki.key.rawRepresentation)
        #expect(try store.accountKey()?.rawRepresentation == accountKey.rawRepresentation)
        // 키는 PKCS#8 PEM, 사슬은 CERTIFICATE PEM을 leaf부터.
        #expect(String(decoding: try state.contents(key), as: UTF8.self).hasPrefix("-----BEGIN PRIVATE KEY-----\n"))
        #expect(try PEM.certificateChain(from: state.contents(crt), maximumByteCount: 1 << 16) == certificate.receivedChain)
    }

    @Test("루트를 함께 받은 사슬: 파일에는 남고 읽은 chain에서는 빠진다(동작 S6)")
    func rootKeptInFile() throws {
        let state = try ScratchState()
        defer { state.remove() }
        let store = CertificateStore(stateDirectory: state.url)
        let received = [pki.leaf(), pki.intermediate.certificate, pki.root.certificate]
        try store.save(try verified(received))
        #expect(try PEM.certificateChain(from: state.contents(crt), maximumByteCount: 1 << 16) == received)
        #expect(try load(store)?.chain == Array(received.prefix(2)))
    }

    @Test("다시 쓰면 바뀐다(인증서 갱신)")
    func overwrite() throws {
        let state = try ScratchState()
        defer { state.remove() }
        let store = CertificateStore(stateDirectory: state.url)
        try store.save(try verified())
        let newKey = P256.Signing.PrivateKey()
        try store.save(try verified(key: newKey))
        #expect(try load(store)?.privateKey.rawRepresentation == newKey.rawRepresentation)
    }

    @Test("이미 있는 certs/의 권한은 고치지 않는다", arguments: [0o750, 0o755, 0o711])
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

    @Test("그룹·기타가 쓸 수 있는 기존 certs/: 읽지도 쓰지도 않고 storage(H20)", arguments: [0o770, 0o702, 0o777])
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
            // 메시지에 경로·이름이 없다(동작 K3).
            guard case .storage(let message) = error else { Issue.record("\(error)"); return }
            #expect(!message.contains(state.url.path) && !message.contains(TestPKI.domainName))
        }
    }

    @Test("권한 판단: 디렉터리가 아님, 다른 사용자, 그룹·기타 쓰기")
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

    // MARK: - 심볼릭 링크

    @Test("certs/가 심볼릭 링크면 따라가지 않는다")
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

    @Test("파일이 심볼릭 링크면 읽지 않고, 쓰기는 링크 자체를 바꾼다(가리키던 곳은 그대로)")
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

    @Test("계정 키 파일이 심볼릭 링크면 storage이고 그대로 둔다")
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

    // MARK: - 읽기의 판단(동작 S3)

    @Test("키만 쓰이고 멈춘 상태: 짝이 맞지 않아 없는 것으로 본다(동작 S3 ④)")
    func keyWrittenWithoutCertificate() throws {
        let state = try ScratchState()
        defer { state.remove() }
        let store = CertificateStore(stateDirectory: state.url)
        try store.save(try verified())
        // 새 발급이 키 파일만 쓰고 멈췄다.
        try state.put(Array(P256.Signing.PrivateKey().pemRepresentation.utf8), key)
        #expect(try load(store) == nil)
    }

    @Test("한쪽 파일만 있음")
    func onlyOneFile() throws {
        let state = try ScratchState()
        defer { state.remove() }
        let store = CertificateStore(stateDirectory: state.url)
        try store.save(try verified())
        try FileManager.default.removeItem(at: state.file(crt))
        #expect(try load(store) == nil)
    }

    @Test("Go가 쓴 SEC1 키 파일과 0644 인증서 파일(자료의 시험 전용 키)")
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
        #expect(try state.mode(state.file(crt)) == 0o644)  // 읽기는 권한을 고치지 않는다
    }

    @Test("저장된 인증서가 만료되었거나 앵커가 다르면 없는 것으로 본다(지우지 않는다)")
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

    @Test("64KiB를 넘는 파일은 없는 것으로 본다, 64KiB까지는 읽는다")
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

    @Test("certs/의 이름 자리가 디렉터리면 storage")
    func notRegularFile() throws {
        let state = try ScratchState()
        defer { state.remove() }
        try FileManager.default.createDirectory(at: state.file(crt), withIntermediateDirectories: true)
        try state.setMode(0o700, state.certs)
        #expect(throws: CertificateStoreError.self) { try load(CertificateStore(stateDirectory: state.url)) }
    }

    @Test("상태 디렉터리가 없으면 읽기는 없음, 쓰기는 storage")
    func missingStateDirectory() throws {
        let state = try ScratchState()
        defer { state.remove() }
        let store = CertificateStore(stateDirectory: state.url.appending(path: "missing", directoryHint: .isDirectory))
        #expect(try load(store) == nil)
        #expect(try store.accountKey() == nil)
        #expect(throws: CertificateStoreError.self) { try store.save(try verified()) }
    }

    // MARK: - 계정 키(동작 C4, H16)

    @Test("계정 키: 없음은 nil, 있으면 덮어쓰지 않는다")
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

    @Test("읽지 못하는 계정 키: accountKeyUnreadable이고 파일은 그대로", arguments: AccountKeyCase.allCases)
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
        /// Go의 옛 RSA 계정 키(PKCS#1 `RSA PRIVATE KEY`).
        case rsa
        case garbage
        case empty
        /// P-256 키 뒤에 64KiB를 넘게 덧붙인 파일.
        case tooLarge
        /// 블록 둘.
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

    @Test("계정 키 해석의 값 함수")
    func decodeAccountKey() throws {
        #expect(try CertificateStore.decodeAccountKey(.missing) == nil)
        #expect(throws: CertificateStoreError.accountKeyUnreadable) { try CertificateStore.decodeAccountKey(.tooLarge) }
        let key = P256.Signing.PrivateKey()
        #expect(try CertificateStore.decodeAccountKey(.contents(Array(key.pemRepresentation.utf8)))?.rawRepresentation == key.rawRepresentation)
    }
}

/// `Fixtures/acme-fixtures.json`의 `keys[0]`(Go가 쓴 시험 전용 키의 SEC1·PKCS#8 PEM).
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
