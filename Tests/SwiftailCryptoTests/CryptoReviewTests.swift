// Go comparisons and boundary input tests added in the independent review.
//
// `Vectors/crypto-review-go.json` contains Go outputs for input categories absent from the existing reference values (`ed25519-verify.json`, `argon2i-go.json`, `blake2b-kat.json`).
// See `Vectors/README.md` for how it was generated.
// - `scalarReduction` uses `edwards25519.Scalar.SetUniformBytes`. Inputs include boundaries such as kL and kL±1 (k ≤ 20), 2^n, 2^n±1, 2^n±L, and 2^512−1, plus random values.
// - `field` covers `field.Element` multiplication, squaring, addition, subtraction, negation, inversion, `SqrtRatio`, and long operation chains. Inputs pair 0…39, p±0…39, 2^51 and 2^102 and other
//   limb boundaries, and representations with the top bit set.
// - `pointDecoding` uses `Point.SetBytes`, `Bytes`, and `MultByCofactor`. y = 0…59, p…2^255−1, and p−59…p with both sign bits 0 and 1.
// - `verify` covers both verification rules. Small-order A (including noncanonical encodings) × R = [S]B + T × boundary S (1, L−1, 2^252, 2^252−1),
//   noncanonical S (L, L+1, 2L−1, 2^253−1, …), small-order components in both A and R of real keys, and messages from 0 bytes to 1 MiB.
//   If `messageLength` is greater than 0, the message is a byte sequence with byte i equal to (31·i + 7) mod 256.
// - `blake2b` uses `golang.org/x/crypto/blake2b.New(outputLength, key)`. Key byte i is (13·i + 1) mod 256,
//   and input byte i is (7·i + keyLength + outputLength) mod 256. Covers all key lengths 0…64.
// - `argon2i` uses `argon2.Key`. Parallelism 3, 5, 7, 16, 255, memory 8p, 8p+1, 8p+3, 12p−1, 10 passes, 5–4096 output bytes, empty secrets and salts,
//   and memory with a segment length that is not a multiple of 128. `goOnly` marks parameters only Go accepts (output under 4 bytes and memory under 8p).

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

/// Recovers the bytes from bits because `Scalar` has no byte accessor.
private func littleEndianBytes(_ s: Scalar) -> [UInt8] {
    (0..<32).map { byte in (0..<8).reduce(UInt8(0)) { $0 | (s.bit(8 * byte + $1) ? 1 << $1 : 0) } }
}

@Suite("Review of Go comparisons and boundary inputs")
struct CryptoReviewTests {
    @Test("64-byte reduction matches Go SetUniformBytes at kL and 2^n boundaries and for random inputs")
    func scalarReduction() throws {
        let cases = try loadReviewVectors().scalarReduction
        #expect(cases.count == 331)
        let mismatches = cases.filter { hex(littleEndianBytes(Scalar(reducing: bytes($0.input)))) != $0.output }.map(\.input)
        #expect(mismatches.isEmpty, "\(mismatches.prefix(5))")
    }

    @Test("Field operations match Go field.Element near p, at limb boundaries, with the top bit set, and in long chains")
    func fieldArithmetic() throws {
        let cases = try loadReviewVectors().field
        #expect(cases.count == 403)
        for c in cases {
            let a = FieldElement(bytes: bytes(c.a)), b = FieldElement(bytes: bytes(c.b))
            // The chain follows the Go generator's order and carries intermediate values with grown limbs through many operations.
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

    @Test("Decoding matches Go Point.SetBytes for y ≥ p, y near 0, and encodings with the sign bit set")
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

    @Test("Both rules match Go for small orders, boundary S, noncanonical S, and long messages")
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
        #expect(mismatches.isEmpty, "\(mismatches.count) verdicts differ from Go: \(mismatches.prefix(5))")
        // The two rules do differ on some cases in the set (the comparison is meaningful only if ZIP-215 alone accepts some cases).
        #expect(cases.contains { $0.zip215 && !$0.standard })
        #expect(cases.contains { $0.zip215 && $0.standard })
    }

    @Test("BLAKE2b matches Go for key lengths 0…64 × output lengths, including chunked input")
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
            #expect(hex(hasher.finalize()) == c.output, "Chunked input \(label)")
        }
    }

    @Test("Argon2i matches Go argon2.Key (parallelism 3–255, 8p boundary, long output) and rejects parameters only Go accepts")
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

    @Test("Ed25519 verification returns false without trapping for any length or value")
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
                        // A = R = (the point of order 4 with y = 0), S = 0. Since [8](−[k]A − R) = 0, ZIP-215 accepts any message
                        // (as in the vector of the same form in ed25519consensus zip215_test.go). The standard rule depends on k mod 4, so this test omits it.
                        #expect(zip215)
                        _ = standard
                    } else {
                        #expect(!zip215 && !standard, "sig \(signatureLength)×\(fill) A \(publicKeyLength)")
                    }
                }
            }
        }
        // Random 64-byte and 32-byte inputs mix off-curve points, S ≥ L, and high bits of sig[63]. The probability of a true result is negligible.
        for _ in 0..<500 {
            let signature = (0..<64).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
            let publicKey = (0..<32).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
            #expect(!Ed25519Verification.isValidZIP215(signature: signature, message: [], publicKey: publicKey))
            #expect(!Ed25519Verification.isValidStandard(signature: signature, message: [], publicKey: publicKey))
        }
    }

    @Test("Out-of-range Argon2i parameters yield invalidLength without trapping", arguments: [
        (UInt32(1), UInt32(8), UInt8(0), 32),       // Parallelism 0
        (UInt32(0), UInt32(8), UInt8(1), 32),       // Passes 0
        (UInt32(1), UInt32(0), UInt8(1), 32),       // Memory 0
        (UInt32(1), UInt32(7), UInt8(1), 32),       // Memory 8p − 1
        (UInt32(1), UInt32(2039), UInt8(255), 32),  // Memory 8·255 − 1
        (UInt32(1), UInt32(8), UInt8(1), 3),        // Output 3
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
