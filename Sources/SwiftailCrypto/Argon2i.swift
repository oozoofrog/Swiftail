// Argon2i (RFC 9106). The algorithm follows RFC 9106 §3. The reference block index calculation (`referenceIndex`) and
// the timing of address block generation were matched to the Go implementation.
// Origin: golang.org/x/crypto v0.58.0 `argon2/argon2.go` (`processBlocks`, `indexAlpha`, `phi`),
// `argon2/blake2b.go` (`blake2bHash`).
// Copyright 2017 The Go Authors. BSD-3-Clause (full text at the top of `Edwards25519/FieldElement.swift`. The clauses match the
// golang.org/x/crypto LICENSE).

/// Argon2i (RFC 9106, version 0x13). Secret keys and associated data are unsupported because no caller uses them.
///
/// Used to verify the Tailnet Lock disablement secret. Produces the same value as Go `argon2.Key(password, salt, time, memory, threads, keyLen)`
/// (`time` = `iterations`, `memory` = `memoryKiB`, `threads` = `parallelism`,
/// `keyLen` = `outputByteCount`).
///
/// Selects reference blocks solely from address blocks made from (pass, lane, slice, block count, pass count, type, counter), independent of the secret
/// (RFC 9106 §3.4.1.2). This makes memory access order independent of `password`.
public enum Argon2i {
    /// One block is 1024 bytes = 128 64-bit words.
    private static let wordsPerBlock = 128
    /// The number of slices SL (RFC 9106 §3.4).
    private static let syncPoints = 4
    private static let version: UInt32 = 0x13
    /// The type y. Argon2d = 0, Argon2i = 1, Argon2id = 2 (RFC 9106 §3.1).
    private static let type: UInt32 = 1

    /// Derives a tag of `outputByteCount` bytes from the secret.
    ///
    /// Allocates `memoryKiB` KiB of memory at once. Parallelism is only a parameter that determines the result, and computation runs on a single thread.
    ///
    /// - Parameters:
    ///   - password: The secret P. Never logged.
    ///   - salt: The salt S. RFC 9106 §3.1 sets no minimum length (16 bytes recommended).
    ///   - iterations: The number of passes t over memory. At least 1.
    ///   - memoryKiB: The memory size m, **in KiB** (same as `memory` in Go `argon2.Key`). At least `8 × parallelism`.
    ///     The actual block count is rounded down to a multiple of `4 × parallelism`. H0 uses the supplied value unchanged (RFC 9106 §3.2).
    ///   - parallelism: The number of lanes p. At least 1.
    ///   - outputByteCount: The tag length T in bytes. At least 4.
    /// - Throws: `CryptoError.invalidLength` when any argument is outside RFC 9106 §3.1's range (parallelism, iterations, memory, output length, or input length).
    ///   Go silently raises memory below `8 × p` and skips output length checks. This implementation rejects out-of-range values as specified.
    public static func derive(
        password: [UInt8], salt: [UInt8], iterations: UInt32, memoryKiB: UInt32, parallelism: UInt8, outputByteCount: Int
    ) throws(CryptoError) -> [UInt8] {
        try derive(
            password: password, salt: salt, secret: [], associatedData: [],
            iterations: iterations, memoryKiB: memoryKiB, parallelism: parallelism, outputByteCount: outputByteCount
        )
    }

    /// Derives a tag with the full parameter set, including secret key K and associated data X. Used only by tests checking the RFC 9106 §5.2 vectors.
    static func derive(
        password: [UInt8], salt: [UInt8], secret: [UInt8], associatedData: [UInt8],
        iterations: UInt32, memoryKiB: UInt32, parallelism: UInt8, outputByteCount: Int
    ) throws(CryptoError) -> [UInt8] {
        // Ranges from RFC 9106 §3.1. CryptoError has no separate case for cost parameters, so report a length error.
        let maxLength = Int(UInt32.max)
        guard parallelism >= 1, iterations >= 1, memoryKiB >= 8 * UInt32(parallelism),
              (4...maxLength).contains(outputByteCount),
              [password, salt, secret, associatedData].allSatisfy({ $0.count <= maxLength })
        else {
            throw .invalidLength
        }

        let lanes = Int(parallelism)
        let initial = initialHash(
            password: password, salt: salt, secret: secret, associatedData: associatedData,
            iterations: iterations, memoryKiB: memoryKiB, parallelism: parallelism, outputByteCount: outputByteCount
        )
        var memory = Memory(memoryKiB: Int(memoryKiB), lanes: lanes)

        // The first two blocks of each lane (RFC 9106 §3.2, steps 3 and 4).
        for lane in 0..<lanes {
            for column in 0..<2 {
                let seed = initial + littleEndian32(UInt32(column)) + littleEndian32(UInt32(lane))
                memory.store(variableLengthHash(seed, outputByteCount: 1024), atBlock: lane * memory.laneLength + column)
            }
        }

        // RFC 9106 §3.2, steps 5 and 6. Fill slices in order. A segment never references another lane's segment within the same slice, so
        // (§3.4 "Segments of the same slice can be computed in parallel and do not reference blocks from each other")
        // filling the segments of a slice one at a time produces the same result as filling them in parallel.
        for pass in 0..<Int(iterations) {
            for slice in 0..<syncPoints {
                for lane in 0..<lanes {
                    fillSegment(&memory, pass: pass, slice: slice, lane: lane, iterations: Int(iterations))
                }
            }
        }

        // Use H' to turn the XOR of the last column (§3.2, step 7) into the tag (step 8).
        var final = [UInt64](repeating: 0, count: wordsPerBlock)
        for lane in 0..<lanes {
            let base = (lane * memory.laneLength + memory.laneLength - 1) * wordsPerBlock
            for i in 0..<wordsPerBlock {
                final[i] ^= memory.words[base + i]
            }
        }
        return variableLengthHash(bytes(of: final), outputByteCount: outputByteCount)
    }

    /// Computes the 64-byte H0 (RFC 9106 §3.2, step 1, Figure 1).
    static func initialHash(
        password: [UInt8], salt: [UInt8], secret: [UInt8], associatedData: [UInt8],
        iterations: UInt32, memoryKiB: UInt32, parallelism: UInt8, outputByteCount: Int
    ) -> [UInt8] {
        var hasher = BLAKE2b(outputByteCount: 64)
        for field in [UInt32(parallelism), UInt32(outputByteCount), memoryKiB, iterations, version, type] {
            hasher.update(littleEndian32(field))
        }
        for field in [password, salt, secret, associatedData] {
            hasher.update(littleEndian32(UInt32(field.count)))
            hasher.update(field)
        }
        return hasher.finalize()
    }

    /// The variable-length hash H'^T (RFC 9106 §3.3, Figure 8).
    static func variableLengthHash(_ input: [UInt8], outputByteCount: Int) -> [UInt8] {
        let prefixed = littleEndian32(UInt32(outputByteCount)) + input
        guard outputByteCount > 64 else {
            return BLAKE2b.hash(prefixed, outputByteCount: outputByteCount)
        }
        // V_1..V_r are 64 bytes each. Use only the first 32 bytes (W_i) of each. The final V_{r+1} supplies the entire remaining length.
        let r = (outputByteCount + 31) / 32 - 2
        var v = BLAKE2b.hash(prefixed)
        var out = Array(v[0..<32])
        out.reserveCapacity(outputByteCount)
        for _ in 1..<r {
            v = BLAKE2b.hash(v)
            out += v[0..<32]
        }
        out += BLAKE2b.hash(v, outputByteCount: outputByteCount - 32 * r)
        return out
    }

    // MARK: Filling memory

    /// A block matrix B[i][j] with p lanes × q columns (RFC 9106 §3.2, step 2). Column j of lane i is block `i·q + j`.
    private struct Memory {
        /// The number of lanes p.
        let lanes: Int
        /// The number of blocks in a lane, q = m' / p.
        let laneLength: Int
        /// The number of blocks in a segment, q / SL.
        let segmentLength: Int
        /// The total block count m' = 4p·⌊m / 4p⌋.
        let blockCount: Int
        var words: [UInt64]

        init(memoryKiB: Int, lanes: Int) {
            self.lanes = lanes
            blockCount = memoryKiB / (syncPoints * lanes) * (syncPoints * lanes)
            laneLength = blockCount / lanes
            segmentLength = laneLength / syncPoints
            words = [UInt64](repeating: 0, count: blockCount * wordsPerBlock)
        }

        mutating func store(_ block: [UInt8], atBlock index: Int) {
            let base = index * wordsPerBlock
            for i in 0..<wordsPerBlock {
                var word: UInt64 = 0
                for j in 0..<8 {
                    word |= UInt64(block[8 * i + j]) << UInt64(8 * j)
                }
                words[base + i] = word
            }
        }
    }

    /// Fills one segment. Selects the reference block's position solely from the address block (§3.4.1.2).
    private static func fillSegment(_ memory: inout Memory, pass: Int, slice: Int, lane: Int, iterations: Int) {
        // Z = (r, l, sl, m', t, y) and counter i (§3.4.1.2, Figure 11). The remaining 968 bytes are 0.
        var input = [UInt64](repeating: 0, count: wordsPerBlock)
        input[0] = UInt64(pass)
        input[1] = UInt64(lane)
        input[2] = UInt64(slice)
        input[3] = UInt64(memory.blockCount)
        input[4] = UInt64(iterations)
        input[5] = UInt64(type)
        var addresses: [UInt64] = []
        var scratch = [UInt64](repeating: 0, count: wordsPerBlock)

        // The first two blocks are already filled in the first segment of the first pass.
        let start = pass == 0 && slice == 0 ? 2 : 0
        for index in start..<memory.segmentLength {
            // One address block provides reference positions for 128 blocks. The first segment still starts at counter 1 when it skips its two prefilled blocks.
            if index == start || index % wordsPerBlock == 0 {
                input[6] += 1
                addresses = addressBlock(input)
            }
            let column = slice * memory.segmentLength + index
            let current = lane * memory.laneLength + column
            // The block preceding the first column is the last block in the same lane (§3.2, step 6).
            let previous = column == 0 ? current + memory.laneLength - 1 : current - 1
            let reference = referenceIndex(
                pseudoRandom: addresses[index % wordsPerBlock], memory: memory,
                pass: pass, slice: slice, lane: lane, index: index
            )
            mix(&memory.words, current: current, previous: previous, reference: reference, scratch: &scratch)
        }
    }

    /// The index of reference block B[l][z] (RFC 9106 §3.4.2). J_1 is the low 32 bits and J_2 the high 32 bits.
    private static func referenceIndex(
        pseudoRandom: UInt64, memory: Memory, pass: Int, slice: Int, lane: Int, index: Int
    ) -> Int {
        let j1 = pseudoRandom & 0xFFFF_FFFF
        let j2 = pseudoRandom >> 32
        // The first segment of the first pass selects from its own lane because the other lanes have nothing yet.
        let referenceLane = pass == 0 && slice == 0 ? lane : Int(j2 % UInt64(memory.lanes))
        let sameLane = referenceLane == lane

        // W consists of completed segments (the segments so far in the first pass, the latest 3 in later passes).
        // For the same lane, add the already filled blocks of the current segment (excluding the immediately preceding block B[i][j-1]).
        // For another lane, when processing the segment's first block, exclude W's last block (which can be computed at the same time as B[i][j-1]).
        let finishedSegments = pass == 0 ? slice : syncPoints - 1
        var areaSize = finishedSegments * memory.segmentLength
        if sameLane {
            areaSize += index - 1
        } else if index == 0 {
            areaSize -= 1
        }
        // The first block of W. In the first pass it is the first block of the lane. Later it is the first block of the segment immediately following the current one.
        let areaStart = pass == 0 ? 0 : (slice + 1) % syncPoints * memory.segmentLength

        // Figure 13 gives x = J_1² / 2^32, y = |W|·x / 2^32, zz = |W| - 1 - y.
        let x = (j1 * j1) >> 32
        let y = (UInt64(areaSize) * x) >> 32
        let zz = areaSize - 1 - Int(y)
        return referenceLane * memory.laneLength + (areaStart + zz) % memory.laneLength
    }

    /// The address block G(0, G(0, Z ‖ i ‖ 0…)) (RFC 9106 §3.4.1.2). G(0, X) = P(X) ⊕ X.
    private static func addressBlock(_ input: [UInt64]) -> [UInt64] {
        var block = input
        for _ in 0..<2 {
            let before = block
            permute(&block)
            for i in 0..<wordsPerBlock {
                block[i] ^= before[i]
            }
        }
        return block
    }

    /// Computes B[current] ⊕= G(B[previous], B[reference]) (RFC 9106 §3.2, steps 5 and 6, and §3.5).
    ///
    /// G(X, Y) = P(R) ⊕ R, R = X ⊕ Y. Version 0x13 XORs with the previous value from the second pass onward. First-pass blocks are zero,
    /// so XOR on every pass is equivalent to assignment on the first pass.
    private static func mix(_ words: inout [UInt64], current: Int, previous: Int, reference: Int, scratch r: inout [UInt64]) {
        let out = current * wordsPerBlock
        let x = previous * wordsPerBlock
        let y = reference * wordsPerBlock
        for i in 0..<wordsPerBlock {
            let value = words[x + i] ^ words[y + i]
            r[i] = value
            words[out + i] ^= value
        }
        permute(&r)
        for i in 0..<wordsPerBlock {
            words[out + i] ^= r[i]
        }
    }

    /// Applies P to each row of the block, then to each column (RFC 9106 §3.5, Figure 15).
    ///
    /// A block is an 8×8 matrix of 16-byte registers. Row k is words 16k..16k+15, and column k is words (2k, 2k+1), (2k+16, 2k+17), …,
    /// (2k+112, 2k+113). Register S_i = (v_{2i+1} ‖ v_{2i}), so v_{2i} is the first word in memory (§3.6).
    private static func permute(_ block: inout [UInt64]) {
        for row in 0..<8 {
            round(&block, base: 16 * row, pairStride: 2)
        }
        for column in 0..<8 {
            round(&block, base: 2 * column, pairStride: 16)
        }
    }

    /// The permutation P (RFC 9106 §3.6). Word v_k is at `base + (k / 2)·pairStride + k % 2`.
    private static func round(_ block: inout [UInt64], base: Int, pairStride: Int) {
        let i0 = base, i1 = base + pairStride, i2 = base + 2 * pairStride, i3 = base + 3 * pairStride
        let i4 = base + 4 * pairStride, i5 = base + 5 * pairStride, i6 = base + 6 * pairStride, i7 = base + 7 * pairStride
        var v0 = block[i0], v1 = block[i0 + 1], v2 = block[i1], v3 = block[i1 + 1]
        var v4 = block[i2], v5 = block[i2 + 1], v6 = block[i3], v7 = block[i3 + 1]
        var v8 = block[i4], v9 = block[i4 + 1], v10 = block[i5], v11 = block[i5 + 1]
        var v12 = block[i6], v13 = block[i6 + 1], v14 = block[i7], v15 = block[i7 + 1]

        mixColumn(&v0, &v4, &v8, &v12)
        mixColumn(&v1, &v5, &v9, &v13)
        mixColumn(&v2, &v6, &v10, &v14)
        mixColumn(&v3, &v7, &v11, &v15)
        mixColumn(&v0, &v5, &v10, &v15)
        mixColumn(&v1, &v6, &v11, &v12)
        mixColumn(&v2, &v7, &v8, &v13)
        mixColumn(&v3, &v4, &v9, &v14)

        block[i0] = v0; block[i0 + 1] = v1; block[i1] = v2; block[i1 + 1] = v3
        block[i2] = v4; block[i2 + 1] = v5; block[i3] = v6; block[i3 + 1] = v7
        block[i4] = v8; block[i4 + 1] = v9; block[i5] = v10; block[i5 + 1] = v11
        block[i6] = v12; block[i6 + 1] = v13; block[i7] = v14; block[i7 + 1] = v15
    }

    /// GB(a, b, c, d) (RFC 9106 §3.6, Figure 19). Adds 2·trunc(a)·trunc(b) to every addition in BLAKE2b's G.
    @inline(__always)
    private static func mixColumn(_ a: inout UInt64, _ b: inout UInt64, _ c: inout UInt64, _ d: inout UInt64) {
        a = multiplyAdd(a, b); d = rotateRight(d ^ a, 32)
        c = multiplyAdd(c, d); b = rotateRight(b ^ c, 24)
        a = multiplyAdd(a, b); d = rotateRight(d ^ a, 16)
        c = multiplyAdd(c, d); b = rotateRight(b ^ c, 63)
    }

    @inline(__always)
    private static func multiplyAdd(_ x: UInt64, _ y: UInt64) -> UInt64 {
        x &+ y &+ 2 &* (x & 0xFFFF_FFFF) &* (y & 0xFFFF_FFFF)
    }

    @inline(__always)
    private static func rotateRight(_ x: UInt64, _ n: UInt64) -> UInt64 {
        (x >> n) | (x << (64 - n))
    }

    // MARK: Byte conversion

    private static func littleEndian32(_ value: UInt32) -> [UInt8] {
        (0..<4).map { UInt8(truncatingIfNeeded: value >> UInt32(8 * $0)) }
    }

    private static func bytes(of words: [UInt64]) -> [UInt8] {
        words.flatMap { word in (0..<8).map { UInt8(truncatingIfNeeded: word >> UInt64(8 * $0)) } }
    }
}
