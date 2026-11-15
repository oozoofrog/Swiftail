// 독립 검토에서 더한 Go 대조와 경계 입력 시험.
//
// `Vectors/crypto-review-go.json`은 기존 기준값(`ed25519-verify.json`, `argon2i-go.json`, `blake2b-kat.json`)에 없던
// 종류의 입력에 대한 Go의 출력이다(만든 방법은 `Vectors/README.md`).
// - `scalarReduction`: `edwards25519.Scalar.SetUniformBytes`. kL·kL±1(k ≤ 20), 2^n·2^n±1·2^n±L, 2^512−1 같은 경계와 무작위.
// - `field`: `field.Element`의 곱·제곱·합·차·부호 반전·역원·`SqrtRatio`와 긴 연산 사슬. 0…39, p±0…39, 2^51·2^102 등
//   림 경계, 맨 위 비트가 선 표현을 서로 짝지었다.
// - `pointDecoding`: `Point.SetBytes`·`Bytes`·`MultByCofactor`. y = 0…59, p…2^255−1, p−59…p에 부호 비트 0·1.
// - `verify`: 두 검증 규칙. 작은 위수 A(비정준 인코딩 포함) × R = [S]B + T × 경계 S(1, L−1, 2^252, 2^252−1),
//   비정준 S(L, L+1, 2L−1, 2^253−1, …), 실제 키의 A와 R 양쪽에 작은 위수 성분, 0바이트~1 MiB 메시지.
//   `messageLength`가 0보다 크면 메시지는 i번째 바이트가 (31·i + 7) mod 256인 바이트열이다.
// - `blake2b`: `golang.org/x/crypto/blake2b.New(outputLength, key)`. 키는 i번째 바이트가 (13·i + 1) mod 256,
//   입력은 (7·i + keyLength + outputLength) mod 256. 키 길이 0…64 전부.
// - `argon2i`: `argon2.Key`. 병렬도 3·5·7·16·255, 메모리 8p·8p+1·8p+3·12p−1, 패스 10, 출력 5~4096바이트, 빈 비밀·솔트,
//   조각 길이가 128의 배수가 아닌 메모리. `goOnly`는 Go만 받는 인자(출력 4바이트 미만, 메모리 8p 미만)다.

import Foundation
import Testing

@testable import SwiftailCrypto

private struct ReviewVectors: Decodable {
    struct ScalarCase: Decodable { let input, output: String }
    struct FieldCase: Decodable {
        let a, b, aBytes, product, square, sum, difference, negation, inverse, squareRoot, chain: String
        let wasSquare: Bool
    }
    struct PointCase: Decodable { let encoding: String; let decodes: Bool; let canonical, timesCofactor: String }
    struct VerifyCase: Decodable {
        let kind, publicKey, signature, message: String
        let messageLength: Int
        let zip215, standard: Bool
    }
    struct BLAKE2bCase: Decodable { let keyLength, outputLength, inputLength: Int; let output: String }
    struct Argon2iCase: Decodable {
        let password, salt: String
        let iterations, memoryKiB: UInt32
        let parallelism: UInt8
        let outputLength: Int
        let output: String
        let goOnly: Bool
    }

    let scalarReduction: [ScalarCase]
    let field: [FieldCase]
    let pointDecoding: [PointCase]
    let verify: [VerifyCase]
    let blake2b: [BLAKE2bCase]
    let argon2i: [Argon2iCase]
}

private func loadReviewVectors() throws -> ReviewVectors {
    let url = try #require(Bundle.module.url(forResource: "crypto-review-go", withExtension: "json", subdirectory: "Vectors"))
    return try JSONDecoder().decode(ReviewVectors.self, from: Data(contentsOf: url))
}

private func hex(_ bytes: [UInt8]) -> String { bytes.map { String(format: "%02x", $0) }.joined() }

private func pattern(_ count: Int, multiplier: Int, offset: Int) -> [UInt8] {
    (0..<count).map { UInt8(truncatingIfNeeded: $0 * multiplier + offset) }
}

/// `Scalar`에는 바이트 접근자가 없어 비트로 되돌린다.
private func littleEndianBytes(_ s: Scalar) -> [UInt8] {
    (0..<32).map { byte in (0..<8).reduce(UInt8(0)) { $0 | (s.bit(8 * byte + $1) ? 1 << $1 : 0) } }
}

@Suite("검토: Go 대조와 경계 입력")
struct CryptoReviewTests {
    @Test("64바이트 환원이 Go SetUniformBytes와 같다(kL 경계, 2^n 경계, 무작위)")
    func scalarReduction() throws {
        let cases = try loadReviewVectors().scalarReduction
        #expect(cases.count == 331)
        let mismatches = cases.filter { hex(littleEndianBytes(Scalar(reducing: bytes($0.input)))) != $0.output }.map(\.input)
        #expect(mismatches.isEmpty, "\(mismatches.prefix(5))")
    }

    @Test("필드 연산이 Go field.Element와 같다(p 근처, 림 경계, 맨 위 비트, 긴 사슬)")
    func fieldArithmetic() throws {
        let cases = try loadReviewVectors().field
        #expect(cases.count == 403)
        for c in cases {
            let a = FieldElement(bytes: bytes(c.a)), b = FieldElement(bytes: bytes(c.b))
            // Go 생성기와 같은 순서의 사슬: 림이 커진 중간값을 오래 이어 간다.
            var x = a
            for _ in 0..<16 {
                x = x * b; x = x - a; x = x.squared(); x = x + b; x = -x; x = x + x; x = x - b
            }
            let root = FieldElement.squareRootOfRatio(a, b)
            let label = "a=\(c.a) b=\(c.b)"
            #expect(hex(a.bytes) == c.aBytes, "\(label)")
            #expect(hex((a * b).bytes) == c.product, "\(label)")
            #expect(hex(a.squared().bytes) == c.square, "\(label)")
            #expect(hex((a + b).bytes) == c.sum, "\(label)")
            #expect(hex((a - b).bytes) == c.difference, "\(label)")
            #expect(hex((-a).bytes) == c.negation, "\(label)")
            #expect(hex(a.inverted().bytes) == c.inverse, "\(label)")
            #expect(hex(x.bytes) == c.chain, "\(label)")
            #expect((root != nil) == c.wasSquare, "\(label)")
            if let root { #expect(hex(root.bytes) == c.squareRoot, "\(label)") }
        }
    }

    @Test("y ≥ p, y 근처 0, 부호 비트가 선 인코딩의 해독이 Go Point.SetBytes와 같다")
    func pointDecoding() throws {
        let cases = try loadReviewVectors().pointDecoding
        #expect(cases.count == 292)
        for c in cases {
            let point = EdwardsPoint(encoding: bytes(c.encoding))
            #expect((point != nil) == c.decodes, "\(c.encoding)")
            if let point {
                #expect(hex(point.encoding) == c.canonical, "\(c.encoding)")
                #expect(hex(point.multipliedByCofactor().encoding) == c.timesCofactor, "\(c.encoding)")
            }
        }
    }

    @Test("작은 위수·경계 S·비정준 S·긴 메시지에서 두 규칙의 판정이 Go와 같다")
    func verification() throws {
        let cases = try loadReviewVectors().verify
        #expect(cases.count == 697)
        var mismatches: [String] = []
        for c in cases {
            let message = c.messageLength > 0 ? pattern(c.messageLength, multiplier: 31, offset: 7) : bytes(c.message)
            let signature = bytes(c.signature), publicKey = bytes(c.publicKey)
            if Ed25519Verification.isValidZIP215(signature: signature, message: message, publicKey: publicKey) != c.zip215 {
                mismatches.append("\(c.kind) zip215(Go \(c.zip215)) A=\(c.publicKey) sig=\(c.signature)")
            }
            if Ed25519Verification.isValidStandard(signature: signature, message: message, publicKey: publicKey) != c.standard {
                mismatches.append("\(c.kind) standard(Go \(c.standard)) A=\(c.publicKey) sig=\(c.signature)")
            }
        }
        #expect(mismatches.isEmpty, "Go와 다른 판정 \(mismatches.count)개: \(mismatches.prefix(5))")
        // 두 규칙이 갈리는 사례가 실제로 들어 있다(ZIP-215만 참인 사례가 있어야 대조가 의미 있다).
        #expect(cases.contains { $0.zip215 && !$0.standard })
        #expect(cases.contains { $0.zip215 && $0.standard })
    }

    @Test("BLAKE2b 키 길이 0…64 × 출력 길이가 Go와 같다. 나누어 넣어도 같다")
    func blake2b() throws {
        let cases = try loadReviewVectors().blake2b
        #expect(cases.count == 520)
        for (i, c) in cases.enumerated() {
            let key = pattern(c.keyLength, multiplier: 13, offset: 1)
            let input = pattern(c.inputLength, multiplier: 7, offset: c.keyLength + c.outputLength)
            let label = "key=\(c.keyLength) out=\(c.outputLength) in=\(c.inputLength)"
            #expect(hex(BLAKE2b.hash(input, outputByteCount: c.outputLength, key: key)) == c.output, "\(label)")
            var hasher = BLAKE2b(outputByteCount: c.outputLength, key: key)
            var offset = 0, step = i % 130 + 1
            while offset < input.count {
                let end = min(input.count, offset + step)
                hasher.update(input[offset..<end])
                hasher.update([UInt8]())
                offset = end
                step = (step * 7 + 3) % 131
            }
            #expect(hex(hasher.finalize()) == c.output, "나누어 넣음 \(label)")
        }
    }

    @Test("Argon2i가 Go argon2.Key와 같다(병렬도 3~255, 8p 경계, 긴 출력). Go만 받는 인자는 거절한다")
    func argon2i() throws {
        let cases = try loadReviewVectors().argon2i
        #expect(cases.count == 107)
        #expect(cases.filter(\.goOnly).count == 5)
        for c in cases {
            let label = "t=\(c.iterations) m=\(c.memoryKiB) p=\(c.parallelism) T=\(c.outputLength)"
            let derive = {
                try Argon2i.derive(
                    password: bytes(c.password), salt: bytes(c.salt), iterations: c.iterations,
                    memoryKiB: c.memoryKiB, parallelism: c.parallelism, outputByteCount: c.outputLength)
            }
            if c.goOnly {
                #expect(throws: CryptoError.invalidLength, "\(label)") { try derive() }
            } else {
                #expect(hex(try derive()) == c.output, "\(label)")
            }
        }
    }

    @Test("Ed25519 검증은 어떤 길이·값에서도 트랩하지 않고 거짓을 돌려준다")
    func ed25519ArbitraryInputs() {
        var generator = SystemRandomNumberGenerator()
        for signatureLength in [0, 1, 32, 63, 64, 65, 128] {
            for publicKeyLength in [0, 1, 31, 32, 33, 64] {
                for fill in [UInt8(0x00), 0xff, 0x7f, 0x80] {
                    let signature = [UInt8](repeating: fill, count: signatureLength)
                    let publicKey = [UInt8](repeating: fill, count: publicKeyLength)
                    let zip215 = Ed25519Verification.isValidZIP215(signature: signature, message: [fill], publicKey: publicKey)
                    let standard = Ed25519Verification.isValidStandard(signature: signature, message: [fill], publicKey: publicKey)
                    if signatureLength == 64, publicKeyLength == 32, fill == 0 {
                        // A = R = (y = 0인 위수 4의 점), S = 0: [8](−[k]A − R) = 0이라 ZIP-215는 어떤 메시지든 참이다
                        // (ed25519consensus zip215_test.go의 같은 꼴 벡터와 같다). 표준은 k mod 4에 달려 있어 보지 않는다.
                        #expect(zip215)
                        _ = standard
                    } else {
                        #expect(!zip215 && !standard, "sig \(signatureLength)×\(fill) A \(publicKeyLength)")
                    }
                }
            }
        }
        // 무작위 64·32바이트(곡선 밖, S ≥ L, sig[63]의 위 비트가 섞인다). 참이 나올 확률은 무시할 만하다.
        for _ in 0..<500 {
            let signature = (0..<64).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
            let publicKey = (0..<32).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
            #expect(!Ed25519Verification.isValidZIP215(signature: signature, message: [], publicKey: publicKey))
            #expect(!Ed25519Verification.isValidStandard(signature: signature, message: [], publicKey: publicKey))
        }
    }

    @Test("Argon2i의 범위 밖 인자는 트랩 없이 invalidLength", arguments: [
        (UInt32(1), UInt32(8), UInt8(0), 32),       // 병렬도 0
        (UInt32(0), UInt32(8), UInt8(1), 32),       // 패스 0
        (UInt32(1), UInt32(0), UInt8(1), 32),       // 메모리 0
        (UInt32(1), UInt32(7), UInt8(1), 32),       // 메모리 8p − 1
        (UInt32(1), UInt32(2039), UInt8(255), 32),  // 메모리 8·255 − 1
        (UInt32(1), UInt32(8), UInt8(1), 3),        // 출력 3
        (UInt32(1), UInt32(8), UInt8(1), 0),
        (UInt32(1), UInt32(8), UInt8(1), -1),
        (UInt32(1), UInt32(8), UInt8(1), Int.min),
        (UInt32(1), UInt32(8), UInt8(1), Int(UInt32.max) + 1),
        (UInt32(1), UInt32(8), UInt8(1), Int.max),
    ])
    func argon2iRejectsOutOfRange(iterations: UInt32, memoryKiB: UInt32, parallelism: UInt8, outputByteCount: Int) {
        #expect(throws: CryptoError.invalidLength) {
            try Argon2i.derive(
                password: [1], salt: [2], iterations: iterations, memoryKiB: memoryKiB,
                parallelism: parallelism, outputByteCount: outputByteCount)
        }
    }
}
