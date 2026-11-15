// Argon2i(RFC 9106) 시험.
//
// 출처:
// - RFC 9106 5.2: Argon2i 시험 벡터(t=3, m=32 KiB, p=4, T=32, 비밀 키·연관 자료 있음)와 H0(Pre-hashing digest)
// - `Vectors/argon2i-go.json`: golang.org/x/crypto v0.58.0 `argon2.Key`의 출력. `Tools/interop/cmd/argon2fixtures`가 만든다.
//   마지막 항목은 Tailnet Lock 끄기 비밀의 인자 그대로이고 도구가 `tka.DisablementKDF`와도 견준다.

import Foundation
import Testing

@testable import SwiftailCrypto

private struct GoArgon2Vectors: Decodable {
    struct Vector: Decodable {
        let password: String
        let salt: String
        let iterations: UInt32
        let memoryKiB: UInt32
        let parallelism: UInt8
        let output: String
    }

    let reference: String
    let vectors: [Vector]
}

private func loadGoVectors() throws -> GoArgon2Vectors {
    let url = try #require(Bundle.module.url(forResource: "argon2i-go", withExtension: "json", subdirectory: "Vectors"))
    return try JSONDecoder().decode(GoArgon2Vectors.self, from: Data(contentsOf: url))
}

private func derive(_ v: GoArgon2Vectors.Vector) throws -> [UInt8] {
    try Argon2i.derive(
        password: bytes(v.password), salt: bytes(v.salt), iterations: v.iterations,
        memoryKiB: v.memoryKiB, parallelism: v.parallelism, outputByteCount: v.output.count / 2
    )
}

private func describe(_ v: GoArgon2Vectors.Vector) -> String {
    "t=\(v.iterations) m=\(v.memoryKiB) p=\(v.parallelism) T=\(v.output.count / 2) |P|=\(v.password.count / 2) |S|=\(v.salt.count / 2)"
}

/// Tailnet Lock 끄기 비밀의 인자(tailscale.com/tka/state.go `DisablementKDF`)는 메모리 16 MiB를 채운다.
private let tkaMemoryKiB: UInt32 = 16 * 1024

/// 새로 뽑아 견줄 Go 도구. `sh Scripts/build-interop-tools.sh argon2fixtures`가 출력한 경로를 준다.
private let argon2FixturesBinary = ProcessInfo.processInfo.environment["SWIFTAIL_ARGON2FIXTURES"].flatMap { $0.isEmpty ? nil : $0 }

@Suite("Argon2i")
struct Argon2iTests {
    @Test("RFC 9106 5.2: Argon2i 벡터와 H0")
    func rfcVector() throws {
        let password = [UInt8](repeating: 0x01, count: 32)
        let salt = [UInt8](repeating: 0x02, count: 16)
        let secret = [UInt8](repeating: 0x03, count: 8)
        let associatedData = [UInt8](repeating: 0x04, count: 12)
        let h0 = Argon2i.initialHash(
            password: password, salt: salt, secret: secret, associatedData: associatedData,
            iterations: 3, memoryKiB: 32, parallelism: 4, outputByteCount: 32
        )
        #expect(h0 == bytes(
            "c46065815276a0b3e731731c902f1fd80cf776907fbb7b6a5ca72e7b56011fee"
                + "ca446c86dd75b9469a5e6879dec4b72d0863fb939b982e5f397cc7d164fddaa9"
        ))
        let tag = try Argon2i.derive(
            password: password, salt: salt, secret: secret, associatedData: associatedData,
            iterations: 3, memoryKiB: 32, parallelism: 4, outputByteCount: 32
        )
        #expect(tag == bytes("c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8"))
    }

    @Test("Go argon2.Key 기준값: 패스·메모리·병렬도·출력 길이(H'의 긴 경로)·비밀·솔트 길이")
    func goVectors() throws {
        let fixtures = try loadGoVectors()
        let vectors = fixtures.vectors.filter { $0.memoryKiB < tkaMemoryKiB }
        #expect(vectors.count == 74)
        for v in vectors {
            #expect(try derive(v) == bytes(v.output), "\(describe(v))")
        }
    }

    @Test("TKA 인자(t=4, m=16 MiB, p=4, T=32): DisablementKDF(0xa5 × 32)", .timeLimit(.minutes(1)))
    func tkaParameters() throws {
        let fixtures = try loadGoVectors()
        let v = try #require(fixtures.vectors.last)
        let salt = Array("tailscale network-lock disablement salt".utf8)
        #expect(bytes(v.salt) == salt)
        #expect(v.iterations == 4 && v.memoryKiB == tkaMemoryKiB && v.parallelism == 4)
        let clock = ContinuousClock()
        let start = clock.now
        let output = try Argon2i.derive(
            password: [UInt8](repeating: 0xA5, count: 32), salt: salt,
            iterations: 4, memoryKiB: tkaMemoryKiB, parallelism: 4, outputByteCount: 32
        )
        let elapsed = clock.now - start
        print("Argon2i TKA 인자 1회: \(elapsed)")
        #expect(output == bytes("c3fea8a0d70ede2555990ca60d70a8a03cbe627d2c9f3cb0e2ba7093d0884e2f"))
        #expect(output == bytes(v.output))
    }

    @Test(
        "Go 도구로 새로 뽑은 값과 견준다(SWIFTAIL_ARGON2FIXTURES가 없으면 건너뜀)",
        .enabled(if: argon2FixturesBinary != nil), .timeLimit(.minutes(2))
    )
    func freshGoVectors() throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: try #require(argon2FixturesBinary))
        let pipe = Pipe()
        process.standardOutput = pipe
        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        #expect(process.terminationStatus == 0)
        let fresh = try JSONDecoder().decode(GoArgon2Vectors.self, from: data)
        let stored = try loadGoVectors()
        #expect(fresh.vectors.map(\.output) == stored.vectors.map(\.output), "저장된 argon2i-go.json이 도구 출력과 다르다")
        for v in fresh.vectors {
            #expect(try derive(v) == bytes(v.output), "\(describe(v))")
        }
    }

    @Test("RFC 9106 3.1 범위 밖의 인자는 invalidLength, 경계값은 받는다")
    func invalidParameters() {
        let salt = [UInt8](repeating: 0x02, count: 16)
        func derive(t: UInt32 = 1, m: UInt32 = 32, p: UInt8 = 4, length: Int = 32) throws(CryptoError) -> [UInt8] {
            try Argon2i.derive(password: [1, 2, 3], salt: salt, iterations: t, memoryKiB: m, parallelism: p, outputByteCount: length)
        }
        #expect(throws: CryptoError.invalidLength) { try derive(p: 0) }
        #expect(throws: CryptoError.invalidLength) { try derive(t: 0) }
        #expect(throws: CryptoError.invalidLength) { try derive(m: 31, p: 4) }
        #expect(throws: CryptoError.invalidLength) { try derive(m: 7, p: 1) }
        #expect(throws: CryptoError.invalidLength) { try derive(m: 0, p: 1) }
        #expect(throws: CryptoError.invalidLength) { try derive(m: 2039, p: 255) }
        #expect(throws: CryptoError.invalidLength) { try derive(length: 3) }
        #expect(throws: CryptoError.invalidLength) { try derive(length: 0) }
        #expect(throws: CryptoError.invalidLength) { try derive(length: -1) }
        // 경계값은 받는다.
        #expect((try? derive(m: 32, p: 4))?.count == 32)
        #expect((try? derive(m: 8, p: 1, length: 4))?.count == 4)
        #expect((try? Argon2i.derive(password: [], salt: [], iterations: 1, memoryKiB: 8, parallelism: 1, outputByteCount: 4))?.count == 4)
    }
}
