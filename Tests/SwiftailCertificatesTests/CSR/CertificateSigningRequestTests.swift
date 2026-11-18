// Contract §7 test 7: CSR. Subject, SAN, and algorithm structure (fixed key), `certificationRequestInfo` bytes, CN encoded as
// `PrintableString` (0x13), and signature verification with CryptoKit and system openssl.

import CryptoKit
import Foundation
import SwiftailBase
import Testing

@testable import SwiftailCertificates

@Suite("CSR")
struct CertificateSigningRequestTests {
    private static let name = "rd-mac-1a2b3c4d.tail0001.ts.net"

    private static func domain() throws -> CertificateDomain {
        try #require(CertificateDomain(name))
    }

    /// Hand-encoded `certificationRequestInfo` using the RFC 7515 A.3 key and `rd-mac-1a2b3c4d.tail0001.ts.net` (31 characters = 0x1f).
    /// The coordinates are the RFC 7515 A.3 x and y values decoded to hex.
    private static var expectedInfo: String {
        let n = Array(name.utf8).hex
        let x = "7fcdce2770f6c45d4183cbee6fdb4b7b580733357be9ef13bacf6e3c7bd15445"
        let y = "c7f144cd1bbd9b7e872cdfedb9eeb9f4b3695d6ea90b24ad8a4623288588e5ad"
        return "3081c9"                                             // SEQUENCE, 201 bytes (long form)
            + "020100"                                              // version 0
            + "302a" + "3128" + "3026"                              // Name → RDN SET → AttributeTypeAndValue
            + "0603550403" + "131f" + n                             // commonName, PrintableString
            + "3059" + "3013"                                       // SubjectPublicKeyInfo → AlgorithmIdentifier
            + "06072a8648ce3d0201" + "06082a8648ce3d030107"         // id-ecPublicKey, secp256r1
            + "0342" + "00" + "04" + x + y                          // BIT STRING (0 unused bits), uncompressed point
            + "a03d" + "303b"                                       // attributes [0] → Attribute
            + "06092a864886f70d01090e" + "312e"                     // extensionRequest, SET
            + "302c" + "302a" + "0603551d11"                        // Extensions → Extension, subjectAltName
            + "0423" + "3021" + "821f" + n                          // OCTET STRING → GeneralNames → [2] dNSName
    }

    @Test("certificationRequestInfo bytes match the hand-calculated value (fixed key)")
    func certificationRequestInfoBytes() throws {
        let publicKey = try RFC7515Example.publicKey()
        #expect(CertificateSigningRequest.certificationRequestInfo(domain: try Self.domain(), publicKey: publicKey).encoded.hex == Self.expectedInfo)
        let csr = try CertificateSigningRequest(domain: try Self.domain(), signedWith: try RFC7515Example.privateKey())
        #expect(csr.certificationRequestInfo.hex == Self.expectedInfo)
    }

    @Test("SubjectPublicKeyInfo matches CryptoKit derRepresentation (RFC 5480 §2)")
    func subjectPublicKeyInfoMatchesCryptoKit() throws {
        for _ in 0..<50 {
            let key = P256.Signing.PrivateKey().publicKey
            let info = CertificateSigningRequest.certificationRequestInfo(domain: try Self.domain(), publicKey: key).encoded.hex
            #expect(info.contains(Array(key.derRepresentation).hex))
        }
        #expect(Self.expectedInfo.contains(Array(try RFC7515Example.publicKey().derRepresentation).hex))
    }

    @Test("CryptoKit verifies the full CSR structure and ECDSA-SHA256 signature")
    func structureAndSignature() throws {
        let key = P256.Signing.PrivateKey()
        let csr = try CertificateSigningRequest(domain: try Self.domain(), signedWith: key)
        var reader = TLVReader(csr.der)
        let outer = try reader.read()
        #expect(outer.tag == 0x30 && reader.isAtEnd)
        var elements = TLVReader(outer.content)
        let info = try elements.read()
        let algorithm = try elements.read()
        let signature = try elements.read()
        #expect(elements.isAtEnd)
        #expect(info.whole == csr.certificationRequestInfo)
        #expect(algorithm.whole.hex == "300a06082a8648ce3d040302")  // ecdsa-with-SHA256, no parameters (RFC 5758 3.2)
        #expect(signature.tag == 0x03 && signature.content.first == 0x00)
        let der = Array(signature.content.dropFirst())
        let ecdsa = try P256.Signing.ECDSASignature(derRepresentation: der)
        #expect(key.publicKey.isValidSignature(ecdsa, for: csr.certificationRequestInfo))
        #expect(!P256.Signing.PrivateKey().publicKey.isValidSignature(ecdsa, for: csr.certificationRequestInfo))
    }

    #if os(macOS)
    /// Runs only when `SWIFTAIL_TEST_SCRATCH` (a temporary location under the build directory) and `/usr/bin/openssl` are available.
    private static let scratch = ProcessInfo.processInfo.environment["SWIFTAIL_TEST_SCRATCH"]
    private static let openssl = "/usr/bin/openssl"

    @Test(
        "System openssl accepts the CSR signature and name",
        .enabled(if: scratch != nil && FileManager.default.isExecutableFile(atPath: openssl), "SWIFTAIL_TEST_SCRATCH or /usr/bin/openssl is missing")
    )
    func opensslVerifies() throws {
        let directory = URL(fileURLWithPath: try #require(Self.scratch), isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let file = directory.appendingPathComponent("csr-\(UUID().uuidString).der")
        defer { try? FileManager.default.removeItem(at: file) }
        let csr = try CertificateSigningRequest(domain: try Self.domain(), signedWith: P256.Signing.PrivateKey())
        try Data(csr.der).write(to: file)

        let verify = try Self.run(["req", "-verify", "-noout", "-in", file.path, "-inform", "DER"])
        #expect(verify.status == 0, "\(verify.output)")
        #expect(verify.output.contains("verify OK") || verify.output.contains("Certificate request self-signature verify OK"))

        let text = try Self.run(["req", "-noout", "-text", "-in", file.path, "-inform", "DER"])
        #expect(text.status == 0, "\(text.output)")
        #expect(text.output.contains("CN=\(Self.name)") || text.output.contains("CN = \(Self.name)"))
        #expect(text.output.contains("DNS:\(Self.name)"))
        #expect(text.output.contains("ecdsa-with-SHA256"))
    }

    private static func run(_ arguments: [String]) throws -> (status: Int32, output: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: openssl)
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        try process.run()
        let output = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, String(decoding: output, as: UTF8.self))
    }
    #endif
}

/// Minimal DER reader for inspecting the CSR in tests (single-byte tags and canonical lengths only). The library has no DER reader.
private struct TLVReader {
    struct Element {
        var tag: UInt8
        var content: [UInt8]
        var whole: [UInt8]
    }

    struct Malformed: Error {}

    private let bytes: [UInt8]
    private var index = 0

    init(_ bytes: [UInt8]) { self.bytes = bytes }

    var isAtEnd: Bool { index == bytes.count }

    mutating func read() throws -> Element {
        let start = index
        let tag = try byte()
        var length = Int(try byte())
        if length & 0x80 != 0 {
            let count = length & 0x7F
            guard (1...3).contains(count) else { throw Malformed() }
            length = 0
            for _ in 0..<count { length = length << 8 | Int(try byte()) }
        }
        guard length <= bytes.count - index else { throw Malformed() }
        let content = Array(bytes[index..<index + length])
        index += length
        return Element(tag: tag, content: content, whole: Array(bytes[start..<index]))
    }

    private mutating func byte() throws -> UInt8 {
        guard index < bytes.count else { throw Malformed() }
        defer { index += 1 }
        return bytes[index]
    }
}
