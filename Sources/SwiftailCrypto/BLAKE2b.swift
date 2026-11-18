import Foundation

/// RFC 7693 BLAKE2b in sequential mode only.
///
/// Used as the internal hash H^x in Argon2 (RFC 9106 §3.2). It follows the same rules as `BLAKE2s` with a different word size (64 bits),
/// block size (128 bytes), round count (12), and G rotation constants (32, 24, 16, 63) (RFC 7693 §2.1).
public struct BLAKE2b: Sendable {
    // RFC 7693 §2.6 and Appendix C. This is the same as the SHA-512 IV.
    private static let iv: [UInt64] = [
        0x6A09_E667_F3BC_C908, 0xBB67_AE85_84CA_A73B, 0x3C6E_F372_FE94_F82B, 0xA54F_F53A_5F1D_36F1,
        0x510E_527F_ADE6_82D1, 0x9B05_688C_2B3E_6C1F, 0x1F83_D9AB_FB41_BD6B, 0x5BE0_CD19_137E_2179,
    ]

    // SIGMA from RFC 7693 §2.7. Of the 12 rounds, rounds 10 and 11 reuse rows 0 and 1 (`round % 10`).
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
    /// Input awaiting compression. The last block must be marked, so keep a full block until more input arrives.
    private var buffer: [UInt8] = []
    /// The number of bytes already compressed. The specification uses a 128-bit counter. This implementation stores only the low 64 bits and requires the total, including any padded key block, to stay below 2^64 bytes.
    private var compressed: UInt64 = 0
    private let outputByteCount: Int

    /// Creates a BLAKE2b hasher. `outputByteCount` is 1...64 and `key` is 0...64 bytes (RFC 7693 §2.1). Out-of-range values trap as programmer errors.
    public init(outputByteCount: Int = 64, key: [UInt8] = []) {
        precondition((1...64).contains(outputByteCount), "BLAKE2b output length must be in 1...64")
        precondition(key.count <= 64, "BLAKE2b keys can be at most 64 bytes")
        self.outputByteCount = outputByteCount
        h = Self.iv
        // Parameter block p[0] (RFC 7693 §3.3), with depth 1, fanout 1, key length, and output length.
        h[0] ^= 0x0101_0000 ^ (UInt64(key.count) << 8) ^ UInt64(outputByteCount)
        if !key.isEmpty {
            buffer = key + [UInt8](repeating: 0, count: 128 - key.count)
        }
    }

    /// Adds input. Splitting the input across calls produces the same result as adding it in a single call.
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

    /// Returns the hash of the input so far. Leaves the state intact so update can continue.
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

    /// Hashes the input in one call. Uses the same argument ranges as `init(outputByteCount:key:)`.
    public static func hash(_ data: some DataProtocol, outputByteCount: Int = 64, key: [UInt8] = []) -> [UInt8] {
        var hasher = BLAKE2b(outputByteCount: outputByteCount, key: key)
        hasher.update(data)
        return hasher.finalize()
    }

    /// The compression function F (RFC 7693 §3.2).
    private static func compress(_ h: inout [UInt64], block: [UInt8], counter: UInt64, isLast: Bool) {
        var m = [UInt64](repeating: 0, count: 16)
        for i in 0..<16 {
            for j in 0..<8 {
                m[i] |= UInt64(block[8 * i + j]) << UInt64(8 * j)
            }
        }
        var v = h + iv
        v[12] ^= counter
        // v[13] ^= the counter's high 64 bits (always 0).
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
