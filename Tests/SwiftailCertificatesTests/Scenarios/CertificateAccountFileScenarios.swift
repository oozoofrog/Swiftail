import Foundation
import Security
import Testing

@testable import SwiftailCertificates

@Suite("Independent ACME account file boundary")
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
            // Creates keys only during tests and does not store them in the persistent keychain.
            let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048]
            let key = try #require(SecKeyCreateRandomKey(attributes as CFDictionary, nil))
            let representation = try #require(SecKeyCopyExternalRepresentation(key, nil)) as Data
            bytes = Data(("-----BEGIN RSA PRIVATE KEY-----\n" + representation.base64EncodedString()
                + "\n-----END RSA PRIVATE KEY-----\n").utf8)
        }
        try bytes.write(to: accountFile)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: accountFile.path)
        let store = CertificateStore(stateDirectory: directory)
        do { _ = try store.accountKey(); Issue.record("An unreadable account key passed") }
        catch { #expect(error == .accountKeyUnreadable) }
        // Pass only the comparison result to diagnostics. Even on failure, the file's key bytes stay out of the log.
        let reread = Array(try Data(contentsOf: accountFile))
        let original = Array(bytes)
        var difference = reread.count ^ original.count
        for index in 0..<min(reread.count, original.count) { difference |= Int(reread[index] ^ original[index]) }
        let unchanged = difference == 0
        #expect(unchanged)
    }
}
