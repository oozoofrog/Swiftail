import Foundation

/// RFC 7693 BLAKE2b. 순차 모드만.
///
/// Argon2(RFC 9106 3.2)의 내부 해시 H^x로 쓴다. 규칙은 `BLAKE2s`와 같고 다른 것은 단어 크기(64비트),
/// 블록(128바이트), 라운드 수(12), G의 회전 상수(32, 24, 16, 63)다(RFC 7693 2.1).
public struct BLAKE2b: Sendable {
    // RFC 7693 2.6, 부록 C. SHA-512의 IV와 같다.
    private static let iv: [UInt64] = [
        0x6A09_E667_F3BC_C908, 0xBB67_AE85_84CA_A73B, 0x3C6E_F372_FE94_F82B, 0xA54F_F53A_5F1D_36F1,
        0x510E_527F_ADE6_82D1, 0x9B05_688C_2B3E_6C1F, 0x1F83_D9AB_FB41_BD6B, 0x5BE0_CD19_137E_2179,
    ]

    // RFC 7693 2.7의 SIGMA. 12라운드 가운데 10·11라운드는 0·1행을 다시 쓴다(`round % 10`).
    private static let sigma: [[Int]] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    ]

    private var h: [UInt64]
    /// 아직 압축하지 않은 입력. 마지막 블록을 표시해야 하므로 가득 차도 다음 입력이 올 때까지 둔다.
    private var buffer: [UInt8] = []
    /// 압축을 마친 바이트 수. 규격의 카운터는 128비트지만 2^64바이트를 넘는 입력은 없으므로 위 64비트는 늘 0이다.
    private var compressed: UInt64 = 0
    private let outputByteCount: Int

    /// outputByteCount는 1...64, key는 0...64바이트(RFC 7693 2.1). 범위 밖은 프로그래머 오류로 멈춘다.
    public init(outputByteCount: Int = 64, key: [UInt8] = []) {
        precondition((1...64).contains(outputByteCount), "BLAKE2b 출력 길이는 1...64")
        precondition(key.count <= 64, "BLAKE2b 키는 최대 64바이트")
        self.outputByteCount = outputByteCount
        h = Self.iv
        // 매개변수 블록 p[0](RFC 7693 3.3): 깊이 1, 팬아웃 1, 키 길이, 출력 길이.
        h[0] ^= 0x0101_0000 ^ (UInt64(key.count) << 8) ^ UInt64(outputByteCount)
        if !key.isEmpty {
            buffer = key + [UInt8](repeating: 0, count: 128 - key.count)
        }
    }

    /// 입력을 더한다. 여러 번 나누어 불러도 한 번에 넣은 것과 결과가 같다.
    public mutating func update(_ data: some DataProtocol) {
        for byte in data {
            if buffer.count == 128 {
                compressed += 128
                Self.compress(&h, block: buffer, counter: compressed, isLast: false)
                buffer.removeAll(keepingCapacity: true)
            }
            buffer.append(byte)
        }
    }

    /// 지금까지의 입력에 대한 해시. 상태를 바꾸지 않으므로 이어서 update할 수 있다.
    public func finalize() -> [UInt8] {
        var state = h
        let total = compressed + UInt64(buffer.count)
        let block = buffer + [UInt8](repeating: 0, count: 128 - buffer.count)
        Self.compress(&state, block: block, counter: total, isLast: true)
        var out: [UInt8] = []
        out.reserveCapacity(64)
        for word in state {
            for shift in stride(from: 0, to: 64, by: 8) {
                out.append(UInt8(truncatingIfNeeded: word >> UInt64(shift)))
            }
        }
        return Array(out[0..<outputByteCount])
    }

    /// 한 번에 해시한다. 인자 범위는 `init(outputByteCount:key:)`와 같다.
    public static func hash(_ data: some DataProtocol, outputByteCount: Int = 64, key: [UInt8] = []) -> [UInt8] {
        var hasher = BLAKE2b(outputByteCount: outputByteCount, key: key)
        hasher.update(data)
        return hasher.finalize()
    }

    /// 압축 함수 F(RFC 7693 3.2).
    private static func compress(_ h: inout [UInt64], block: [UInt8], counter: UInt64, isLast: Bool) {
        var m = [UInt64](repeating: 0, count: 16)
        for i in 0..<16 {
            for j in 0..<8 {
                m[i] |= UInt64(block[8 * i + j]) << UInt64(8 * j)
            }
        }
        var v = h + iv
        v[12] ^= counter
        // v[13] ^= 카운터의 위 64비트(늘 0).
        if isLast { v[14] = ~v[14] }

        func g(_ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt64, _ y: UInt64) {
            v[a] = v[a] &+ v[b] &+ x
            v[d] = rotateRight(v[d] ^ v[a], 32)
            v[c] = v[c] &+ v[d]
            v[b] = rotateRight(v[b] ^ v[c], 24)
            v[a] = v[a] &+ v[b] &+ y
            v[d] = rotateRight(v[d] ^ v[a], 16)
            v[c] = v[c] &+ v[d]
            v[b] = rotateRight(v[b] ^ v[c], 63)
        }

        for round in 0..<12 {
            let s = sigma[round % 10]
            g(0, 4, 8, 12, m[s[0]], m[s[1]])
            g(1, 5, 9, 13, m[s[2]], m[s[3]])
            g(2, 6, 10, 14, m[s[4]], m[s[5]])
            g(3, 7, 11, 15, m[s[6]], m[s[7]])
            g(0, 5, 10, 15, m[s[8]], m[s[9]])
            g(1, 6, 11, 12, m[s[10]], m[s[11]])
            g(2, 7, 8, 13, m[s[12]], m[s[13]])
            g(3, 4, 9, 14, m[s[14]], m[s[15]])
        }
        for i in 0..<8 {
            h[i] ^= v[i] ^ v[i + 8]
        }
    }

    private static func rotateRight(_ x: UInt64, _ n: UInt64) -> UInt64 {
        (x >> n) | (x << (64 - n))
    }
}
