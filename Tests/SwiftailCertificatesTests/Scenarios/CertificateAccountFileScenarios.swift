import Foundation
import Security
import Testing

@testable import SwiftailCertificates

@Suite("독립 ACME 계정 파일 경계")
struct CertificateAccountFileScenarios {
    enum AccountFileCase: String, Sendable, CaseIterable { case rsa, corrupted }

    @Test(.enabled(if: ProcessInfo.processInfo.environment["SWIFTAIL_TEST_SCRATCH"] != nil), arguments: AccountFileCase.allCases)
    func unreadableAccountIsPreserved(_ kind: AccountFileCase) throws {
        let scratch = try #require(ProcessInfo.processInfo.environment["SWIFTAIL_TEST_SCRATCH"])
        let directory = URL(fileURLWithPath: scratch, isDirectory: true).appendingPathComponent(UUID().uuidString, isDirectory: true)
        let certificates = directory.appendingPathComponent("certs", isDirectory: true)
        try FileManager.default.createDirectory(at: certificates, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let accountFile = certificates.appendingPathComponent("acme-account.key.pem")
        let bytes: Data
        switch kind {
        case .corrupted: bytes = Data("not a private key".utf8)
        case .rsa:
            // 키는 영구 키체인에 저장하지 않고 시험 중에만 만든다.
            let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048]
            let key = try #require(SecKeyCreateRandomKey(attributes as CFDictionary, nil))
            let representation = try #require(SecKeyCopyExternalRepresentation(key, nil)) as Data
            bytes = Data(("-----BEGIN RSA PRIVATE KEY-----\n" + representation.base64EncodedString()
                + "\n-----END RSA PRIVATE KEY-----\n").utf8)
        }
        try bytes.write(to: accountFile)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: accountFile.path)
        let store = CertificateStore(stateDirectory: directory)
        do { _ = try store.accountKey(); Issue.record("읽지 못하는 계정 키가 통과했다") }
        catch { #expect(error == .accountKeyUnreadable) }
        // 비교 결과만 진단에 넘긴다. 실패해도 파일의 키 바이트가 로그에 나오지 않는다.
        let reread = Array(try Data(contentsOf: accountFile))
        let original = Array(bytes)
        var difference = reread.count ^ original.count
        for index in 0..<min(reread.count, original.count) { difference |= Int(reread[index] ^ original[index]) }
        let unchanged = difference == 0
        #expect(unchanged)
    }
}
