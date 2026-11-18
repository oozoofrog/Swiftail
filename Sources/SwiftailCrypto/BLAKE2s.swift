import Foundation

/// RFC 7693 BLAKE2s in sequential mode only.
public struct BLAKE2s: Sendable {
    private static let iv: [UInt32] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ]

    // SIGMA from RFC 7693 §2.7. BLAKE2s uses 10 rows for its 10 rounds.
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

    private var h: [UInt32]
    /// Input awaiting compression. The last block must be marked, so keep a full block until more input arrives.
    private var buffer: [UInt8] = []
    /// The number of bytes already compressed.
    private var compressed: UInt64 = 0
    private let outputByteCount: Int

    /// Creates a BLAKE2s hasher. `outputByteCount` is 1...32 and `key` is 0...32 bytes.
    public init(outputByteCount: Int = 32, key: [UInt8] = []) {
        precondition((1...32).contains(outputByteCount), "BLAKE2s output length must be in 1...32")
        precondition(key.count <= 32, "BLAKE2s keys can be at most 32 bytes")
        self.outputByteCount = outputByteCount
        h = Self.iv
        h[0] ^= 0x0101_0000 ^ (UInt32(key.count) << 8) ^ UInt32(outputByteCount)
        if !key.isEmpty {
            buffer = key + [UInt8](repeating: 0, count: 64 - key.count)
        }
    }

    public mutating func update(_ data: some DataProtocol) {
        for byte in data {
            if buffer.count == 64 {
                compressed += 64
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
        let block = buffer + [UInt8](repeating: 0, count: 64 - buffer.count)
        Self.compress(&state, block: block, counter: total, isLast: true)
        var out: [UInt8] = []
        out.reserveCapacity(32)
        for word in state {
            for shift in stride(from: 0, to: 32, by: 8) {
                out.append(UInt8(truncatingIfNeeded: word >> UInt32(shift)))
            }
        }
        return Array(out[0..<outputByteCount])
    }

    public static func hash(_ data: some DataProtocol, outputByteCount: Int = 32, key: [UInt8] = []) -> [UInt8] {
        var hasher = BLAKE2s(outputByteCount: outputByteCount, key: key)
        hasher.update(data)
        return hasher.finalize()
    }

    private static func compress(_ h: inout [UInt32], block: [UInt8], counter: UInt64, isLast: Bool) {
        var m = [UInt32](repeating: 0, count: 16)
        for i in 0..<16 {
            m[i] = UInt32(block[4 * i])
                | UInt32(block[4 * i + 1]) << 8
                | UInt32(block[4 * i + 2]) << 16
                | UInt32(block[4 * i + 3]) << 24
        }
        var v = h + iv
        v[12] ^= UInt32(truncatingIfNeeded: counter)
        v[13] ^= UInt32(truncatingIfNeeded: counter >> 32)
        if isLast { v[14] = ~v[14] }

        func g(_ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt32, _ y: UInt32) {
            v[a] = v[a] &+ v[b] &+ x
            v[d] = rotateRight(v[d] ^ v[a], 16)
            v[c] = v[c] &+ v[d]
            v[b] = rotateRight(v[b] ^ v[c], 12)
            v[a] = v[a] &+ v[b] &+ y
            v[d] = rotateRight(v[d] ^ v[a], 8)
            v[c] = v[c] &+ v[d]
            v[b] = rotateRight(v[b] ^ v[c], 7)
        }

        for round in 0..<10 {
            let s = sigma[round]
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

    private static func rotateRight(_ x: UInt32, _ n: UInt32) -> UInt32 {
        (x >> n) | (x << (32 - n))
    }
}

/// RFC 2104 HMAC with BLAKE2s-256 (64-byte blocks) and 32-byte output.
public enum HMACBLAKE2s {
    public static func authenticationCode(for data: some DataProtocol, key: [UInt8]) -> [UInt8] {
        var block = key.count > 64 ? BLAKE2s.hash(key) : key
        block += [UInt8](repeating: 0, count: 64 - block.count)

        var inner = BLAKE2s()
        inner.update(block.map { $0 ^ 0x36 })
        inner.update(data)

        var outer = BLAKE2s()
        outer.update(block.map { $0 ^ 0x5c })
        outer.update(inner.finalize())
        return outer.finalize()
    }
}

/// KDFn for Noise and WireGuard.
/// PRK = HMAC(chainingKey, input), T1 = HMAC(PRK, 0x01), T2 = HMAC(PRK, T1 ‖ 0x02), T3 = HMAC(PRK, T2 ‖ 0x03).
public enum HKDFBLAKE2s {
    /// Derives `outputCount` outputs (1...3), each 32 bytes long.
    public static func derive(chainingKey: [UInt8], input: some DataProtocol, outputCount: Int) -> [[UInt8]] {
        precondition((1...3).contains(outputCount), "HKDF output count must be in 1...3")
        let prk = HMACBLAKE2s.authenticationCode(for: input, key: chainingKey)
        var outputs: [[UInt8]] = []
        var previous: [UInt8] = []
        for counter in 1...outputCount {
            previous = HMACBLAKE2s.authenticationCode(for: previous + [UInt8(counter)], key: prk)
            outputs.append(previous)
        }
        return outputs
    }
}
