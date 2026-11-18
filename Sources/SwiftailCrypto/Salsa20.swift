/// Salsa20-family primitives (20 rounds). Uses only 32-bit addition, rotation, and XOR, with no secret-dependent branching or table lookups.
enum Salsa20 {
    /// "expand 32-byte k"
    private static let sigma: [UInt32] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]

    /// One line of the Salsa20 quarter-round.
    private static func quarterRound(_ x: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
        x[b] ^= rotateLeft(x[a] &+ x[d], 7)
        x[c] ^= rotateLeft(x[b] &+ x[a], 9)
        x[d] ^= rotateLeft(x[c] &+ x[b], 13)
        x[a] ^= rotateLeft(x[d] &+ x[c], 18)
    }

    /// Runs 20 rounds, alternating columns and rows 10 times each, without the final addition of the input.
    private static func rounds(_ input: [UInt32]) -> [UInt32] {
        var x = input
        for _ in 0..<10 {
            quarterRound(&x, 0, 4, 8, 12)
            quarterRound(&x, 5, 9, 13, 1)
            quarterRound(&x, 10, 14, 2, 6)
            quarterRound(&x, 15, 3, 7, 11)
            quarterRound(&x, 0, 1, 2, 3)
            quarterRound(&x, 5, 6, 7, 4)
            quarterRound(&x, 10, 11, 8, 9)
            quarterRound(&x, 15, 12, 13, 14)
        }
        return x
    }

    /// Runs the Salsa20 core, adding the input after 20 rounds to produce a 64-byte block.
    static func core(_ input: [UInt32]) -> [UInt8] {
        precondition(input.count == 16)
        let x = rounds(input)
        var out: [UInt8] = []
        out.reserveCapacity(64)
        for i in 0..<16 { out += littleEndianBytes(x[i] &+ input[i]) }
        return out
    }

    /// Runs HSalsa20 with a 32-byte key and 16-byte input to produce 32 bytes. Returns words 0, 5, 10, 15, 6, 7, 8, and 9 without adding the input.
    static func hsalsa20(key: [UInt8], input: [UInt8]) -> [UInt8] {
        precondition(key.count == 32 && input.count == 16)
        var state = [UInt32](repeating: 0, count: 16)
        state[0] = sigma[0]; state[5] = sigma[1]; state[10] = sigma[2]; state[15] = sigma[3]
        for i in 0..<4 {
            state[1 + i] = loadLE(key, 4 * i)
            state[11 + i] = loadLE(key, 16 + 4 * i)
            state[6 + i] = loadLE(input, 4 * i)
        }
        let x = rounds(state)
        var out: [UInt8] = []
        for i in [0, 5, 10, 15, 6, 7, 8, 9] { out += littleEndianBytes(x[i]) }
        return out
    }

    /// Returns count bytes of the Salsa20 keystream with a 32-byte key, 8-byte nonce, and block counter starting at 0.
    static func keystream(key: [UInt8], nonce: [UInt8], count: Int) -> [UInt8] {
        precondition(key.count == 32 && nonce.count == 8)
        var state = [UInt32](repeating: 0, count: 16)
        state[0] = sigma[0]; state[5] = sigma[1]; state[10] = sigma[2]; state[15] = sigma[3]
        for i in 0..<4 { state[1 + i] = loadLE(key, 4 * i); state[11 + i] = loadLE(key, 16 + 4 * i) }
        state[6] = loadLE(nonce, 0)
        state[7] = loadLE(nonce, 4)
        var out: [UInt8] = []
        out.reserveCapacity(count + 64)
        var counter: UInt64 = 0
        while out.count < count {
            state[8] = UInt32(truncatingIfNeeded: counter)
            state[9] = UInt32(truncatingIfNeeded: counter >> 32)
            out += core(state)
            counter += 1
        }
        return Array(out[0..<count])
    }

    /// Produces the XSalsa20 keystream with a 32-byte key and 24-byte nonce.
    /// Uses HSalsa20(key, nonce[0..<16]) as the subkey and runs Salsa20(nonce[16..<24]).
    static func xsalsa20Keystream(key: [UInt8], nonce: [UInt8], count: Int) -> [UInt8] {
        precondition(key.count == 32 && nonce.count == 24)
        let subkey = hsalsa20(key: key, input: Array(nonce[0..<16]))
        return keystream(key: subkey, nonce: Array(nonce[16..<24]), count: count)
    }
}

/// HChaCha20 (draft-irtf-cfrg-xchacha-03 §2.2), with a 32-byte key and 16-byte input producing 32 bytes.
func hchacha20(key: [UInt8], input: [UInt8]) -> [UInt8] {
    precondition(key.count == 32 && input.count == 16)
    var x = [UInt32](repeating: 0, count: 16)
    x[0] = 0x6170_7865; x[1] = 0x3320_646e; x[2] = 0x7962_2d32; x[3] = 0x6b20_6574
    for i in 0..<8 { x[4 + i] = loadLE(key, 4 * i) }
    for i in 0..<4 { x[12 + i] = loadLE(input, 4 * i) }

    func quarterRound(_ a: Int, _ b: Int, _ c: Int, _ d: Int) {
        x[a] = x[a] &+ x[b]; x[d] = rotateLeft(x[d] ^ x[a], 16)
        x[c] = x[c] &+ x[d]; x[b] = rotateLeft(x[b] ^ x[c], 12)
        x[a] = x[a] &+ x[b]; x[d] = rotateLeft(x[d] ^ x[a], 8)
        x[c] = x[c] &+ x[d]; x[b] = rotateLeft(x[b] ^ x[c], 7)
    }
    for _ in 0..<10 {
        quarterRound(0, 4, 8, 12)
        quarterRound(1, 5, 9, 13)
        quarterRound(2, 6, 10, 14)
        quarterRound(3, 7, 11, 15)
        quarterRound(0, 5, 10, 15)
        quarterRound(1, 6, 11, 12)
        quarterRound(2, 7, 8, 13)
        quarterRound(3, 4, 9, 14)
    }
    var out: [UInt8] = []
    for i in [0, 1, 2, 3, 12, 13, 14, 15] { out += littleEndianBytes(x[i]) }
    return out
}

private func rotateLeft(_ x: UInt32, _ n: UInt32) -> UInt32 {
    (x << n) | (x >> (32 - n))
}

private func loadLE(_ bytes: [UInt8], _ i: Int) -> UInt32 {
    UInt32(bytes[i]) | UInt32(bytes[i + 1]) << 8 | UInt32(bytes[i + 2]) << 16 | UInt32(bytes[i + 3]) << 24
}

private func littleEndianBytes(_ x: UInt32) -> [UInt8] {
    [UInt8(truncatingIfNeeded: x), UInt8(truncatingIfNeeded: x >> 8), UInt8(truncatingIfNeeded: x >> 16), UInt8(truncatingIfNeeded: x >> 24)]
}
