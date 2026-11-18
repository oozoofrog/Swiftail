/// A one-time Poly1305 authenticator (RFC 8439 §2.5). Performs arithmetic modulo 2^130-5 in five 26-bit limbs.
/// Use the key for only one message.
enum Poly1305 {
    static let keyByteCount = 32
    static let tagByteCount = 16

    /// Returns a 16-byte tag. The key is 32 bytes (r ‖ s).
    static func authenticate(_ message: [UInt8], key: [UInt8]) -> [UInt8] {
        precondition(key.count == keyByteCount)
        let mask: UInt64 = 0x3ff_ffff

        // Clamp r while splitting it into 26-bit limbs.
        let r0 = load32(key, 0) & 0x3ff_ffff
        let r1 = (load32(key, 3) >> 2) & 0x3ff_ff03
        let r2 = (load32(key, 6) >> 4) & 0x3ff_c0ff
        let r3 = (load32(key, 9) >> 6) & 0x3f0_3fff
        let r4 = (load32(key, 12) >> 8) & 0x00f_ffff
        let s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5

        var h0: UInt64 = 0, h1: UInt64 = 0, h2: UInt64 = 0, h3: UInt64 = 0, h4: UInt64 = 0

        var offset = 0
        while offset < message.count {
            // Process 16-byte blocks. Append 0x01 to a short final block and zero-pad it without setting the high bit.
            let take = min(16, message.count - offset)
            var block = [UInt8](repeating: 0, count: 16)
            for i in 0..<take { block[i] = message[offset + i] }
            var hibit: UInt64 = 1 << 24
            if take < 16 {
                block[take] = 1
                hibit = 0
            }
            offset += take

            h0 += load32(block, 0) & mask
            h1 += (load32(block, 3) >> 2) & mask
            h2 += (load32(block, 6) >> 4) & mask
            h3 += (load32(block, 9) >> 6) & mask
            h4 += (load32(block, 12) >> 8) | hibit

            // h = h * r mod 2^130-5 (since 2^130 ≡ 5, multiply overflow limbs by 5).
            let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1
            var d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2
            var d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3
            var d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4
            var d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0

            var c = d0 >> 26
            h0 = d0 & mask
            d1 += c; c = d1 >> 26; h1 = d1 & mask
            d2 += c; c = d2 >> 26; h2 = d2 & mask
            d3 += c; c = d3 >> 26; h3 = d3 & mask
            d4 += c; c = d4 >> 26; h4 = d4 & mask
            h0 += c * 5
            c = h0 >> 26; h0 &= mask
            h1 += c
        }

        // Fully reduce by propagating carries through all limbs.
        var c = h1 >> 26; h1 &= mask
        h2 += c; c = h2 >> 26; h2 &= mask
        h3 += c; c = h3 >> 26; h3 &= mask
        h4 += c; c = h4 >> 26; h4 &= mask
        h0 += c * 5; c = h0 >> 26; h0 &= mask
        h1 += c

        // g = h + 5 - 2^130. If g is nonnegative, h ≥ 2^130-5, so use g. Select with a mask.
        var g0 = h0 &+ 5; c = g0 >> 26; g0 &= mask
        var g1 = h1 &+ c; c = g1 >> 26; g1 &= mask
        var g2 = h2 &+ c; c = g2 >> 26; g2 &= mask
        var g3 = h3 &+ c; c = g3 >> 26; g3 &= mask
        let g4 = h4 &+ c &- (1 << 26)
        let select = (g4 >> 63) &- 1  // All ones if g4 ≥ 0 and zero if negative.
        let keep = ~select
        h0 = (h0 & keep) | (g0 & select)
        h1 = (h1 & keep) | (g1 & select)
        h2 = (h2 & keep) | (g2 & select)
        h3 = (h3 & keep) | (g3 & select)
        h4 = (h4 & keep) | ((g4 & mask) & select)

        // Combine into 128 bits and add s (modulo 2^128).
        let w0 = (h0 | h1 << 26) & 0xffff_ffff
        let w1 = (h1 >> 6 | h2 << 20) & 0xffff_ffff
        let w2 = (h2 >> 12 | h3 << 14) & 0xffff_ffff
        let w3 = (h3 >> 18 | h4 << 8) & 0xffff_ffff

        var f = w0 + load32(key, 16)
        var tag = [UInt8](repeating: 0, count: 16)
        store32(&tag, 0, f)
        f = w1 + load32(key, 20) + (f >> 32)
        store32(&tag, 4, f)
        f = w2 + load32(key, 24) + (f >> 32)
        store32(&tag, 8, f)
        f = w3 + load32(key, 28) + (f >> 32)
        store32(&tag, 12, f)
        return tag
    }

    private static func load32(_ bytes: [UInt8], _ i: Int) -> UInt64 {
        UInt64(bytes[i]) | UInt64(bytes[i + 1]) << 8 | UInt64(bytes[i + 2]) << 16 | UInt64(bytes[i + 3]) << 24
    }

    private static func store32(_ bytes: inout [UInt8], _ i: Int, _ value: UInt64) {
        for k in 0..<4 { bytes[i + k] = UInt8(truncatingIfNeeded: value >> UInt64(8 * k)) }
    }
}
