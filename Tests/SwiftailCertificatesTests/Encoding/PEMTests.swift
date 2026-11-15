// 계약 7절 시험 4(PEM: 여러 블록, 줄 길이, 모르는 종류)와 동작 X3 ①(입력 전체 검사), S3 ②.

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

    @Test("쓰기: 64열, LF, 같은 라벨의 BEGIN·END (RFC 7468 2절)")
    func encodeWrapsAt64Columns() {
        let block = Self.block(.certificate, count: 100, seed: 1)
        let lines = PEM.encode(block).split(separator: "\n", omittingEmptySubsequences: false)
        #expect(lines.first == "-----BEGIN CERTIFICATE-----")
        #expect(lines.dropFirst().dropLast(2).map(\.count) == [64, 64, 8])  // 100바이트 = base64 136자
        #expect(lines.suffix(2) == ["-----END CERTIFICATE-----", ""])
        #expect(PEM.encode(PEMBlock(label: .ecPrivateKey, der: [1, 2, 3])) == "-----BEGIN EC PRIVATE KEY-----\nAQID\n-----END EC PRIVATE KEY-----\n")
    }

    @Test("왕복: 세 라벨, 48바이트(64열에 꼭 맞음)와 여러 크기")
    func roundTrip() throws {
        for (index, label) in PEMLabel.allCases.enumerated() {
            for count in [1, 2, 3, 47, 48, 49, 1_000] {
                let block = Self.block(label, count: count, seed: UInt64(index * 10_000 + count))
                #expect(try Self.decode(PEM.encode(block)) == [block])
            }
        }
    }

    @Test("여러 블록과 블록 사이의 공백, CRLF, 줄 끝 공백, 다른 줄 길이")
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

    @Test("블록 밖의 공백이 아닌 바이트는 전체를 버린다", arguments: [
        "앞의 설명\n%@",
        "%@뒤의 쓰레기",
        "%@x\n%@",
        "%@\u{0}",
        " %@",          // 경계선은 줄의 처음에서 시작한다
    ])
    func bytesOutsideBlocks(_ template: String) {
        let pem = PEM.encode(Self.block(.certificate, count: 40, seed: 4))
        #expect(throws: PEMError.malformed) { try Self.decode(template.replacingOccurrences(of: "%@", with: pem)) }
    }

    @Test("모르는 라벨", arguments: ["RSA PRIVATE KEY", "PUBLIC KEY", "CERTIFICATE REQUEST", "certificate", "X509 CRL"])
    func unknownLabel(_ label: String) {
        let text = "-----BEGIN \(label)-----\nAQID\n-----END \(label)-----\n"
        #expect(throws: PEMError.unexpectedLabel) { try Self.decode(text) }
    }

    @Test("잘린 블록과 틀린 경계선·본문", arguments: [
        "-----BEGIN CERTIFICATE-----\nAQID\n",                                   // END 없음
        "-----BEGIN CERTIFICATE-----\nAQID",                                     // 줄 중간에서 끝남
        "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE",               // 잘린 END
        "-----BEGIN CERTIFICATE-----\nAQID\n-----END PRIVATE KEY-----\n",        // 라벨이 다름
        "-----BEGIN CERTIFICATE----\nAQID\n-----END CERTIFICATE-----\n",         // 대시 넷
        "-----BEGIN -----\nAQID\n-----END -----\n",                              // 빈 라벨
        "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n",              // 빈 본문
        "-----BEGIN CERTIFICATE-----\nAQ\n-----END CERTIFICATE-----\n",          // 채움 없음
        "-----BEGIN CERTIFICATE-----\nAQ==AQ==\n-----END CERTIFICATE-----\n",    // 가운데의 =
        "-----BEGIN CERTIFICATE-----\nAQ-_\n-----END CERTIFICATE-----\n",        // base64url 알파벳
        "-----BEGIN CERTIFICATE-----\nAQ ID\n-----END CERTIFICATE-----\n",       // 줄 안의 공백
        "-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\nAQID\n-----END CERTIFICATE-----\n",  // 머리(RFC 7468 2절)
        "-----BEGIN CERTIFICATE-----\nAQID\n-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n",  // 겹친 BEGIN
        "-----END CERTIFICATE-----\n",                                            // BEGIN 없는 END
    ])
    func malformed(_ text: String) {
        #expect(throws: PEMError.malformed) { try Self.decode(text) }
    }

    @Test("크기 한도는 읽기 전에 본다")
    func sizeLimit() throws {
        let text = Array(PEM.encode(Self.block(.certificate, count: 300, seed: 5)).utf8)
        #expect(try PEM.decode(text, maximumByteCount: text.count).count == 1)
        #expect(throws: PEMError.tooLarge) { try PEM.decode(text, maximumByteCount: text.count - 1) }
        #expect(throws: PEMError.tooLarge) { try PEM.decode(text + [0x20], maximumByteCount: text.count) }
    }

    @Test("인증서 사슬: 순서를 지키고 1~5장만")
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

    @Test("사슬에 낀 PRIVATE KEY 블록은 전체를 버린다 (RFC 8555 11.4)", arguments: [PEMLabel.privateKey, .ecPrivateKey])
    func keyBlockInsideChain(_ label: PEMLabel) {
        let text = PEM.encode(Self.block(.certificate, count: 50, seed: 20))
            + PEM.encode(Self.block(label, count: 50, seed: 21))
            + PEM.encode(Self.block(.certificate, count: 50, seed: 22))
        #expect(throws: PEMError.unexpectedLabel) { try PEM.certificateChain(from: Array(text.utf8), maximumByteCount: Self.limit) }
    }

    @Test("임의 바이트와 망가뜨린 PEM으로 죽지 않는다")
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
        // 잘라 낸 모든 앞부분으로도 죽지 않는다.
        for end in 0..<valid.count {
            _ = try? PEM.decode(Array(valid[..<end]), maximumByteCount: Self.limit)
        }
    }
}
