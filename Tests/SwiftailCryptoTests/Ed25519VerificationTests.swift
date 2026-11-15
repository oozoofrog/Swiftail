// Ed25519 검증의 두 규칙을 규격 벡터와 Go 기준값으로 확인한다.
//
// - `rfc8032-ed25519.json`: RFC 8032 7.1(Ed25519 순수 변형) 벡터 5개.
// - `ed25519-verify.json`: `Tools/interop/cmd/ed25519fixtures`가 뽑은 Go 두 구현
//   (`ed25519consensus.Verify`, `crypto/ed25519.Verify`)의 판정. ZIP-215 벡터 196개가 앞에 있다.
// - 필드·스칼라 경계의 기대값은 Python 정수 연산으로 교차 계산했다.

import CryptoKit
import Foundation
import Testing

@testable import SwiftailCrypto

private struct RFC8032Vector: Decodable {
    let name: String
    let publicKey: String
    let message: String
    let signature: String
}

private struct GoVerdicts: Decodable {
    let go: String
    let ed25519consensus: String
    let caseCount: Int
    let cases: [GoCase]
}

private struct GoCase: Decodable {
    let kind: String
    let index: Int
    let publicKey: String
    let signature: String
    let message: String
    let zip215: Bool
    let standard: Bool
}

private func loadJSON<T: Decodable>(_ name: String, as type: T.Type) throws -> T {
    let url = try #require(Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Vectors"))
    return try JSONDecoder().decode(type, from: Data(contentsOf: url))
}

private func hexString(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

/// Go와 판정이 다른 사례를 "종류#번호: 규칙"으로 모은다.
private func disagreements(_ cases: [GoCase]) -> [String] {
    cases.flatMap { c -> [String] in
        let signature = bytes(c.signature), message = bytes(c.message), publicKey = bytes(c.publicKey)
        var found: [String] = []
        if Ed25519Verification.isValidZIP215(signature: signature, message: message, publicKey: publicKey) != c.zip215 {
            found.append("\(c.kind)#\(c.index): zip215(Go \(c.zip215))")
        }
        if Ed25519Verification.isValidStandard(signature: signature, message: message, publicKey: publicKey) != c.standard {
            found.append("\(c.kind)#\(c.index): standard(Go \(c.standard))")
        }
        return found
    }
}

/// 환경 변수 `SWIFTAIL_ED25519FIXTURES`가 가리키는 `ed25519fixtures` 실행 파일. 없으면 Go 대조 시험을 건너뛴다.
/// 만드는 법: `sh Scripts/build-interop-tools.sh ed25519fixtures`.
private let fixtureTool = ProcessInfo.processInfo.environment["SWIFTAIL_ED25519FIXTURES"].flatMap { $0.isEmpty ? nil : $0 }

@Suite("Ed25519 검증")
struct Ed25519VerificationTests {
    @Test("RFC 8032 7.1 벡터: 두 규칙 모두 참, 한 비트 바꾸면 거짓")
    func rfc8032() throws {
        let vectors = try loadJSON("rfc8032-ed25519", as: [RFC8032Vector].self)
        #expect(vectors.count == 5)
        for v in vectors {
            let signature = bytes(v.signature), message = bytes(v.message), publicKey = bytes(v.publicKey)
            #expect(Ed25519Verification.isValidZIP215(signature: signature, message: message, publicKey: publicKey), "TEST \(v.name)")
            #expect(Ed25519Verification.isValidStandard(signature: signature, message: message, publicKey: publicKey), "TEST \(v.name)")
            var tampered = signature
            tampered[0] ^= 1
            #expect(!Ed25519Verification.isValidZIP215(signature: tampered, message: message, publicKey: publicKey))
            #expect(!Ed25519Verification.isValidStandard(signature: tampered, message: message, publicKey: publicKey))
        }
    }

    @Test("Go 기준값: 모든 사례에서 두 규칙의 판정이 Go와 같다")
    func goVerdicts() throws {
        let verdicts = try loadJSON("ed25519-verify", as: GoVerdicts.self)
        #expect(verdicts.cases.count == verdicts.caseCount)
        let found = disagreements(verdicts.cases)
        #expect(found.isEmpty, "Go와 다른 판정 \(found.count)개: \(found.prefix(20))")
    }

    @Test("ZIP-215 벡터 196개: ZIP-215는 모두 참, 표준이 받는 집합은 Go 표준과 같다")
    func zip215Vectors() throws {
        let zip215 = try loadJSON("ed25519-verify", as: GoVerdicts.self).cases.filter { $0.kind == "zip215" }
        #expect(zip215.count == 196)
        var acceptedByStandard: [Int] = []
        for c in zip215 {
            let signature = bytes(c.signature), message = bytes(c.message), publicKey = bytes(c.publicKey)
            #expect(message == Array("Zcash".utf8))
            #expect(Ed25519Verification.isValidZIP215(signature: signature, message: message, publicKey: publicKey), "ZIP-215 #\(c.index)")
            if Ed25519Verification.isValidStandard(signature: signature, message: message, publicKey: publicKey) {
                acceptedByStandard.append(c.index)
            }
        }
        #expect(acceptedByStandard == zip215.filter(\.standard).map(\.index))
    }

    @Test("CryptoKit으로 만든 서명은 두 규칙 모두 참")
    func cryptoKitSignatures() throws {
        for length in [0, 1, 31, 32, 33, 64, 127, 128, 129, 1000] {
            let key = Curve25519.Signing.PrivateKey()
            let message = (0..<length).map { UInt8(truncatingIfNeeded: $0 &* 7 &+ length) }
            let signature = Array(try key.signature(for: message))
            let publicKey = Array(key.publicKey.rawRepresentation)
            #expect(Ed25519Verification.isValidZIP215(signature: signature, message: message, publicKey: publicKey))
            #expect(Ed25519Verification.isValidStandard(signature: signature, message: message, publicKey: publicKey))
            let other = Array(Curve25519.Signing.PrivateKey().publicKey.rawRepresentation)
            #expect(!Ed25519Verification.isValidZIP215(signature: signature, message: message, publicKey: other))
            #expect(!Ed25519Verification.isValidStandard(signature: signature, message: message, publicKey: other))
        }
    }

    @Test("길이가 틀린 입력은 거짓이다(트랩하지 않는다)")
    func wrongLengths() throws {
        let v = try #require(try loadJSON("rfc8032-ed25519", as: [RFC8032Vector].self).first)
        let signature = bytes(v.signature), publicKey = bytes(v.publicKey)
        for n in [0, 1, 32, 63, 65, 128] {
            let s = Array((signature + signature).prefix(n))
            #expect(!Ed25519Verification.isValidZIP215(signature: s, message: [], publicKey: publicKey))
            #expect(!Ed25519Verification.isValidStandard(signature: s, message: [], publicKey: publicKey))
        }
        for n in [0, 1, 31, 33, 64] {
            let k = Array((publicKey + publicKey).prefix(n))
            #expect(!Ed25519Verification.isValidZIP215(signature: signature, message: [], publicKey: k))
            #expect(!Ed25519Verification.isValidStandard(signature: signature, message: [], publicKey: k))
        }
    }

    @Test("Go 도구로 새로 뽑은 기준값과 같다", .enabled(if: fixtureTool != nil))
    func freshGoVerdicts() throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: try #require(fixtureTool))
        let output = Pipe()
        process.standardOutput = output
        try process.run()
        let data = try output.fileHandleForReading.readToEnd() ?? Data()
        process.waitUntilExit()
        #expect(process.terminationStatus == 0)
        let verdicts = try JSONDecoder().decode(GoVerdicts.self, from: data)
        #expect(verdicts.cases.count == verdicts.caseCount && verdicts.caseCount > 0)
        let found = disagreements(verdicts.cases)
        #expect(found.isEmpty, "Go(\(verdicts.go), ed25519consensus \(verdicts.ed25519consensus))와 다른 판정 \(found.count)개: \(found.prefix(20))")
    }

    @Test("검증 속도(서명 하나의 평균 시간을 출력한다)")
    func speed() throws {
        let v = try #require(try loadJSON("rfc8032-ed25519", as: [RFC8032Vector].self).last)
        let signature = bytes(v.signature), message = bytes(v.message), publicKey = bytes(v.publicKey)
        let rounds = 200
        let clock = ContinuousClock()
        var accepted = 0
        let zip215 = clock.measure {
            for _ in 0..<rounds where Ed25519Verification.isValidZIP215(signature: signature, message: message, publicKey: publicKey) { accepted += 1 }
        }
        let standard = clock.measure {
            for _ in 0..<rounds where Ed25519Verification.isValidStandard(signature: signature, message: message, publicKey: publicKey) { accepted += 1 }
        }
        #expect(accepted == 2 * rounds)
        print("Ed25519 검증 평균: ZIP-215 \(zip215 / rounds), 표준 \(standard / rounds)")
    }
}

@Suite("edwards25519 부품")
struct Edwards25519PartsTests {
    /// p = 2^255 − 19의 바이트에 작은 수를 더한 리틀 엔디언 32바이트(맨 위 비트 0).
    private static func pPlus(_ n: UInt8) -> [UInt8] {
        var b = [UInt8](repeating: 0xff, count: 32)
        b[0] = 0xed + n
        b[31] = 0x7f
        return b
    }

    private static func small(_ n: UInt8) -> [UInt8] { [n] + [UInt8](repeating: 0, count: 31) }

    @Test("필드 원소 해독의 경계: 0, 1, p−1, p, p+1, 2^255−1, 맨 위 비트")
    func fieldBoundaries() {
        let pMinusOne = [0xec] + [UInt8](repeating: 0xff, count: 30) + [0x7f]
        #expect(FieldElement(bytes: Self.small(0)).bytes == Self.small(0))
        #expect(FieldElement(bytes: Self.small(1)).bytes == Self.small(1))
        #expect(FieldElement(bytes: pMinusOne).bytes == pMinusOne)
        #expect(FieldElement(bytes: Self.pPlus(0)).bytes == Self.small(0))
        #expect(FieldElement(bytes: Self.pPlus(1)).bytes == Self.small(1))
        #expect(FieldElement(bytes: Self.pPlus(18)).bytes == Self.small(18))  // 2^255 − 1
        var topBit = Self.small(5)
        topBit[31] = 0x80
        #expect(FieldElement(bytes: topBit) == FieldElement(bytes: Self.small(5)))
    }

    @Test("필드 산술: 넘침, 역원, 제곱근")
    func fieldArithmetic() {
        let pMinusOne = FieldElement(bytes: [0xec] + [UInt8](repeating: 0xff, count: 30) + [0x7f])
        #expect(pMinusOne + .one == .zero)
        #expect(FieldElement.zero - .one == pMinusOne)
        #expect(-FieldElement.one == pMinusOne)
        #expect(pMinusOne * pMinusOne == .one)
        #expect(pMinusOne.squared() == .one)
        #expect(FieldElement.zero.inverted() == .zero)
        let x = FieldElement(bytes: (0..<32).map { UInt8(truncatingIfNeeded: $0 &* 37 &+ 11) & ($0 == 31 ? 0x7f : 0xff) })
        #expect(x * x.inverted() == .one)
        #expect(FieldElement.sqrtMinusOne.squared() == pMinusOne)
        // √(−1/1)은 ±√−1 가운데 음수가 아닌 쪽이다.
        let root = FieldElement.squareRootOfRatio(pMinusOne, .one)
        #expect(root?.squared() == pMinusOne && root?.isNegative == false)
        // p ≡ 5 (mod 8)이라 2는 제곱수가 아니다.
        #expect(FieldElement.squareRootOfRatio(FieldElement(bytes: Self.small(2)), .one) == nil)
        #expect(FieldElement.squareRootOfRatio(.zero, .zero) == .zero)
        #expect(FieldElement.squareRootOfRatio(.one, .zero) == nil)
        let four = FieldElement(bytes: Self.small(4))
        #expect(FieldElement.squareRootOfRatio(four, .one) == FieldElement(bytes: Self.small(2)))
    }

    @Test("스칼라의 정준 검사: L−1은 받고 L, L+1, 2^256−1은 거절한다")
    func scalarCanonical() {
        let order = bytes("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
        var orderMinusOne = order
        orderMinusOne[0] -= 1
        var orderPlusOne = order
        orderPlusOne[0] += 1
        #expect(Scalar(canonicalBytes: Self.small(0)) == .zero)
        #expect(Scalar(canonicalBytes: orderMinusOne) != nil)
        #expect(Scalar(canonicalBytes: order) == nil)
        #expect(Scalar(canonicalBytes: orderPlusOne) == nil)
        #expect(Scalar(canonicalBytes: [UInt8](repeating: 0xff, count: 32)) == nil)
        #expect(Scalar(canonicalBytes: Self.small(0) + [0]) == nil)
    }

    @Test("64바이트 스칼라 환원: L, L+1, 2^256, 2^512−1")
    func scalarReduction() throws {
        let order = bytes("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
        let zeros = [UInt8](repeating: 0, count: 32)
        #expect(Scalar(reducing: order + zeros) == .zero)
        var orderPlusOne = order
        orderPlusOne[0] += 1
        #expect(Scalar(reducing: orderPlusOne + zeros) == Scalar(canonicalBytes: Self.small(1)))
        // 기대값은 Python으로 계산했다.
        let twoTo256 = try #require(Scalar(canonicalBytes: bytes("1d95988d7431ecd670cf7d73f45befc6feffffffffffffffffffffffffffff0f")))
        #expect(Scalar(reducing: zeros + Self.small(1)) == twoTo256)
        let allOnes = try #require(Scalar(canonicalBytes: bytes("000f9c44e31106a447938568a71b0ed065bef517d273ecce3d9a307c1b419903")))
        #expect(Scalar(reducing: [UInt8](repeating: 0xff, count: 64)) == allOnes)
    }

    @Test("기준점: 인코딩 왕복과 [L−1]B + B = 항등원")
    func basepoint() throws {
        let encoding = [0x58] + [UInt8](repeating: 0x66, count: 31)
        #expect(EdwardsPoint.basepoint.encoding == encoding)
        #expect(EdwardsPoint(encoding: encoding)?.encoding == encoding)
        var orderMinusOne = bytes("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
        orderMinusOne[0] -= 1
        let scalar = try #require(Scalar(canonicalBytes: orderMinusOne))
        let point = EdwardsPoint.varTimeDoubleScalarBaseMultiply(.zero, .identity, scalar)
        #expect(point.encoding == (-EdwardsPoint.basepoint).encoding)
        #expect((point + .basepoint).isIdentity)
        #expect(!EdwardsPoint.basepoint.isIdentity)
        #expect((EdwardsPoint.basepoint - .basepoint).isIdentity)
        #expect(EdwardsPoint.basepoint.doubled().encoding == (EdwardsPoint.basepoint + .basepoint).encoding)
    }

    @Test("점 해독: 비정준 인코딩은 받고 곡선 밖과 길이 오류는 거절한다")
    func pointDecoding() throws {
        // y = 1(항등원)의 세 표현: 정준, x = 0에 부호 비트, y = p + 1.
        var signedIdentity = Self.small(1)
        signedIdentity[31] = 0x80
        for e in [Self.small(1), signedIdentity, Self.pPlus(1)] {
            let point = try #require(EdwardsPoint(encoding: e))
            #expect(point.isIdentity)
            #expect(point.encoding == Self.small(1))
        }
        // y = 0(위수 4)의 비정준 표현 y = p.
        #expect(EdwardsPoint(encoding: Self.pPlus(0))?.encoding == Self.small(0))
        #expect(EdwardsPoint(encoding: Self.pPlus(0))?.multipliedByCofactor().isIdentity == true)
        // y = 2는 곡선 위가 아니다(Python으로 확인). y = p + 2도 같다.
        #expect(EdwardsPoint(encoding: Self.small(2)) == nil)
        #expect(EdwardsPoint(encoding: Self.pPlus(2)) == nil)
        #expect(EdwardsPoint(encoding: Self.small(1) + [0]) == nil)
        #expect(EdwardsPoint(encoding: Array(Self.small(1).prefix(31))) == nil)
    }
}
