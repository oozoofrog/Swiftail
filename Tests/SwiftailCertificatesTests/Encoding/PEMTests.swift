// Contract §7 test 4 (PEM: multiple blocks, line lengths, and unknown types) and behaviors X3 ① (full input validation), S3 ②.

import Foundation
import Testing

@testable import SwiftailCertificates

@Suite("PEM")
struct PEMTests {
    private static let limit = 64 * 1024

    private static func block(_ label: PEMLabel, count: Int, seed: UInt64) -> PEMBlock {
        var random = SplitMix64(seed: seed)
        return PEMBlock(label: label, der: random.bytes(count))
    }

    private static func decode(_ text: String) throws(PEMError) -> [PEMBlock] {
        try PEM.decode(Array(text.utf8), maximumByteCount: limit)
    }

    @Test("Writing: 64 columns, LF, and matching BEGIN and END labels (RFC 7468 §2)")
    func encodeWrapsAt64Columns() {
        let block = Self.block(.certificate, count: 100, seed: 1)
        let lines = PEM.encode(block).split(separator: "\n", omittingEmptySubsequences: false)
        #expect(lines.first == "-----BEGIN CERTIFICATE-----")
        #expect(lines.dropFirst().dropLast(2).map(\.count) == [64, 64, 8])  // 100 bytes = 136 base64 characters
        #expect(lines.suffix(2) == ["-----END CERTIFICATE-----", ""])
        #expect(PEM.encode(PEMBlock(label: .ecPrivateKey, der: [1, 2, 3])) == "-----BEGIN EC PRIVATE KEY-----\nAQID\n-----END EC PRIVATE KEY-----\n")
    }

    @Test("Round trips: three labels, 48 bytes (exactly 64 columns), and several sizes")
    func roundTrip() throws {
        for (index, label) in PEMLabel.allCases.enumerated() {
            for count in [1, 2, 3, 47, 48, 49, 1_000] {
                let block = Self.block(label, count: count, seed: UInt64(index * 10_000 + count))
                #expect(try Self.decode(PEM.encode(block)) == [block])
            }
        }
    }

    @Test("Multiple blocks with whitespace between them, CRLF, trailing whitespace, and different line lengths")
    func multipleBlocks() throws {
        let first = Self.block(.certificate, count: 70, seed: 2)
        let second = Self.block(.certificate, count: 30, seed: 3)
        let crlf = PEM.encode(first).replacingOccurrences(of: "\n", with: "\r\n")
        let body = Data(second.der).base64EncodedString()
        let unwrapped = "-----BEGIN CERTIFICATE-----  \n\n\(body)\t\n-----END CERTIFICATE----- \n"
        #expect(try Self.decode("\n \t\r\n" + crlf + "\n\n" + unwrapped + "\n  \n") == [first, second])
        #expect(try Self.decode("") == [])
        #expect(try Self.decode(" \n\r\n\t") == [])
    }

    @Test("Non-whitespace bytes outside blocks cause rejection of the entire input", arguments: [
        "Leading text\n%@",
        "%@trailing junk",
        "%@x\n%@",
        "%@\u{0}",
        " %@",          // A boundary starts at the beginning of a line
    ])
    func bytesOutsideBlocks(_ template: String) {
        let pem = PEM.encode(Self.block(.certificate, count: 40, seed: 4))
        #expect(throws: PEMError.malformed) { try Self.decode(template.replacingOccurrences(of: "%@", with: pem)) }
    }

    @Test("Unknown label", arguments: ["RSA PRIVATE KEY", "PUBLIC KEY", "CERTIFICATE REQUEST", "certificate", "X509 CRL"])
    func unknownLabel(_ label: String) {
        let text = "-----BEGIN \(label)-----\nAQID\n-----END \(label)-----\n"
        #expect(throws: PEMError.unexpectedLabel) { try Self.decode(text) }
    }

    @Test("Truncated blocks and malformed boundaries or bodies", arguments: [
        "-----BEGIN CERTIFICATE-----\nAQID\n",                                   // Missing END
        "-----BEGIN CERTIFICATE-----\nAQID",                                     // Ends midline
        "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE",               // Truncated END
        "-----BEGIN CERTIFICATE-----\nAQID\n-----END PRIVATE KEY-----\n",        // Mismatched labels
        "-----BEGIN CERTIFICATE----\nAQID\n-----END CERTIFICATE-----\n",         // Four dashes
        "-----BEGIN -----\nAQID\n-----END -----\n",                              // Empty label
        "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n",              // Empty body
        "-----BEGIN CERTIFICATE-----\nAQ\n-----END CERTIFICATE-----\n",          // Missing padding
        "-----BEGIN CERTIFICATE-----\nAQ==AQ==\n-----END CERTIFICATE-----\n",    // Interior =
        "-----BEGIN CERTIFICATE-----\nAQ-_\n-----END CERTIFICATE-----\n",        // base64url alphabet
        "-----BEGIN CERTIFICATE-----\nAQ ID\n-----END CERTIFICATE-----\n",       // Whitespace within a line
        "-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\nAQID\n-----END CERTIFICATE-----\n",  // Headers (RFC 7468 §2)
        "-----BEGIN CERTIFICATE-----\nAQID\n-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n",  // Duplicate BEGIN
        "-----END CERTIFICATE-----\n",                                            // END without BEGIN
    ])
    func malformed(_ text: String) {
        #expect(throws: PEMError.malformed) { try Self.decode(text) }
    }

    @Test("Checks the size limit before parsing")
    func sizeLimit() throws {
        let text = Array(PEM.encode(Self.block(.certificate, count: 300, seed: 5)).utf8)
        #expect(try PEM.decode(text, maximumByteCount: text.count).count == 1)
        #expect(throws: PEMError.tooLarge) { try PEM.decode(text, maximumByteCount: text.count - 1) }
        #expect(throws: PEMError.tooLarge) { try PEM.decode(text + [0x20], maximumByteCount: text.count) }
    }

    @Test("Certificate chain: preserves order and accepts only 1–5 certificates")
    func certificateChain() throws {
        let blocks = (0..<6).map { Self.block(.certificate, count: 50 + $0, seed: 10 + UInt64($0)) }
        for count in 1...5 {
            let text = Array(blocks.prefix(count).map(PEM.encode).joined().utf8)
            #expect(try PEM.certificateChain(from: text, maximumByteCount: Self.limit) == blocks.prefix(count).map(\.der))
        }
        #expect(throws: PEMError.wrongBlockCount) {
            try PEM.certificateChain(from: Array(blocks.map(PEM.encode).joined().utf8), maximumByteCount: Self.limit)
        }
        #expect(throws: PEMError.wrongBlockCount) { try PEM.certificateChain(from: Array(" \n".utf8), maximumByteCount: Self.limit) }
    }

    @Test("A PRIVATE KEY block in the chain causes rejection of the entire chain (RFC 8555 11.4)", arguments: [PEMLabel.privateKey, .ecPrivateKey])
    func keyBlockInsideChain(_ label: PEMLabel) {
        let text = PEM.encode(Self.block(.certificate, count: 50, seed: 20))
            + PEM.encode(Self.block(label, count: 50, seed: 21))
            + PEM.encode(Self.block(.certificate, count: 50, seed: 22))
        #expect(throws: PEMError.unexpectedLabel) { try PEM.certificateChain(from: Array(text.utf8), maximumByteCount: Self.limit) }
    }

    @Test("Arbitrary bytes and corrupted PEM do not cause a crash")
    func randomInput() {
        var random = SplitMix64(seed: 0x7065_6d)
        let valid = Array((PEM.encode(Self.block(.certificate, count: 120, seed: 30))
            + PEM.encode(Self.block(.privateKey, count: 40, seed: 31))).utf8)
        for _ in 0..<3_000 {
            _ = try? PEM.decode(random.bytes(Int.random(in: 0...300, using: &random)), maximumByteCount: Self.limit)
            var mutated = valid
            for _ in 0..<Int.random(in: 1...4, using: &random) {
                let index = Int.random(in: 0..<mutated.count, using: &random)
                switch Int.random(in: 0..<3, using: &random) {
                case 0: mutated[index] = UInt8.random(in: .min ... .max, using: &random)
                case 1: mutated.remove(at: index)
                default: mutated.insert(UInt8.random(in: .min ... .max, using: &random), at: index)
                }
            }
            _ = try? PEM.decode(mutated, maximumByteCount: Self.limit)
            _ = try? PEM.certificateChain(from: mutated, maximumByteCount: Self.limit)
        }
        // No truncated prefix causes a crash.
        for end in 0..<valid.count {
            _ = try? PEM.decode(Array(valid[..<end]), maximumByteCount: Self.limit)
        }
    }
}
