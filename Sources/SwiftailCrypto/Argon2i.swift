// Argon2i(RFC 9106). 알고리즘은 RFC 9106 3절을 따라 썼고, 참조 블록 색인 계산(`referenceIndex`)과
// 주소 블록을 만드는 시점은 Go 구현과 견주어 맞췄다.
// 출처: golang.org/x/crypto v0.58.0 `argon2/argon2.go` (`processBlocks`, `indexAlpha`, `phi`),
// `argon2/blake2b.go` (`blake2bHash`).
// Copyright 2017 The Go Authors. BSD-3-Clause.

/// Argon2i(RFC 9106, 버전 0x13). 비밀 키와 연관 자료는 받지 않는다(쓰는 곳이 없다).
///
/// Tailnet Lock의 끄기 비밀 검증이 쓴다. Go `argon2.Key(password, salt, time, memory, threads, keyLen)`와
/// 같은 값을 낸다(`time` = `iterations`, `memory` = `memoryKiB`, `threads` = `parallelism`,
/// `keyLen` = `outputByteCount`).
///
/// 참조 블록은 비밀이 아니라 (패스, 차선, 조각, 블록 수, 패스 수, 형식, 카운터)로 만든 주소 블록에서만 고른다
/// (RFC 9106 3.4.1.2). 그래서 메모리 접근 순서가 `password`에 따라 달라지지 않는다.
public enum Argon2i {
    /// 블록 하나는 1024바이트 = 64비트 단어 128개.
    private static let wordsPerBlock = 128
    /// 조각(slice) 수 SL(RFC 9106 3.4).
    private static let syncPoints = 4
    private static let version: UInt32 = 0x13
    /// 형식 y. Argon2d = 0, Argon2i = 1, Argon2id = 2(RFC 9106 3.1).
    private static let type: UInt32 = 1

    /// 비밀에서 `outputByteCount`바이트의 태그를 유도한다.
    ///
    /// 메모리 `memoryKiB` KiB를 한 번에 잡는다. 병렬도는 결과를 정하는 인자일 뿐이고 계산은 한 스레드에서 한다.
    ///
    /// - Parameters:
    ///   - password: 비밀 P. 로그에 남기지 않는다.
    ///   - salt: 솔트 S. RFC 9106 3.1은 길이의 하한을 두지 않는다(16바이트 권장).
    ///   - iterations: 메모리를 훑는 패스 수 t. 1 이상.
    ///   - memoryKiB: 메모리 크기 m, **KiB 단위**(Go `argon2.Key`의 `memory`와 같다). `8 × parallelism` 이상.
    ///     실제 블록 수는 `4 × parallelism`의 배수로 내림한 값이고, H0에는 준 값이 그대로 들어간다(RFC 9106 3.2).
    ///   - parallelism: 차선(lane) 수 p. 1 이상.
    ///   - outputByteCount: 태그 길이 T, 바이트. 4 이상.
    /// - Throws: 인자가 RFC 9106 3.1의 범위 밖이면 `CryptoError.invalidLength`(병렬도·반복·메모리·출력 길이·입력 길이 모두).
    ///   Go는 메모리가 `8 × p`보다 작으면 조용히 올리고 출력 길이를 검사하지 않지만, 여기서는 규격대로 거절한다.
    public static func derive(
        password: [UInt8], salt: [UInt8], iterations: UInt32, memoryKiB: UInt32, parallelism: UInt8, outputByteCount: Int
    ) throws(CryptoError) -> [UInt8] {
        try derive(
            password: password, salt: salt, secret: [], associatedData: [],
            iterations: iterations, memoryKiB: memoryKiB, parallelism: parallelism, outputByteCount: outputByteCount
        )
    }

    /// 비밀 키 K와 연관 자료 X까지 받는 전체 형태. RFC 9106 5.2 벡터를 확인하는 시험만 쓴다.
    static func derive(
        password: [UInt8], salt: [UInt8], secret: [UInt8], associatedData: [UInt8],
        iterations: UInt32, memoryKiB: UInt32, parallelism: UInt8, outputByteCount: Int
    ) throws(CryptoError) -> [UInt8] {
        // RFC 9106 3.1의 범위. CryptoError에는 비용 인자용 경우가 따로 없어 길이 오류로 알린다.
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

        // 각 차선의 첫 두 블록(RFC 9106 3.2 3·4단계).
        for lane in 0..<lanes {
            for column in 0..<2 {
                let seed = initial + littleEndian32(UInt32(column)) + littleEndian32(UInt32(lane))
                memory.store(variableLengthHash(seed, outputByteCount: 1024), atBlock: lane * memory.laneLength + column)
            }
        }

        // RFC 9106 3.2 5·6단계. 조각은 반드시 차례로 채우지만 같은 조각의 차선끼리는 서로 참조하지 않으므로
        // (3.4 "Segments of the same slice can be computed in parallel and do not reference blocks from each other")
        // 차선을 하나씩 채워도 병렬로 채운 것과 결과가 같다.
        for pass in 0..<Int(iterations) {
            for slice in 0..<syncPoints {
                for lane in 0..<lanes {
                    fillSegment(&memory, pass: pass, slice: slice, lane: lane, iterations: Int(iterations))
                }
            }
        }

        // 마지막 열의 XOR(3.2 7단계)을 H'로 태그로 만든다(8단계).
        var final = [UInt64](repeating: 0, count: wordsPerBlock)
        for lane in 0..<lanes {
            let base = (lane * memory.laneLength + memory.laneLength - 1) * wordsPerBlock
            for i in 0..<wordsPerBlock {
                final[i] ^= memory.words[base + i]
            }
        }
        return variableLengthHash(bytes(of: final), outputByteCount: outputByteCount)
    }

    /// H0(RFC 9106 3.2 1단계, 그림 1). 64바이트.
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

    /// 가변 길이 해시 H'^T(RFC 9106 3.3, 그림 8).
    static func variableLengthHash(_ input: [UInt8], outputByteCount: Int) -> [UInt8] {
        let prefixed = littleEndian32(UInt32(outputByteCount)) + input
        guard outputByteCount > 64 else {
            return BLAKE2b.hash(prefixed, outputByteCount: outputByteCount)
        }
        // V_1..V_r은 64바이트이고 앞 32바이트(W_i)만 쓴다. 마지막 V_{r+1}은 남은 길이 전부다.
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

    // MARK: 메모리 채우기

    /// p개 차선 × q열의 블록 행렬 B[i][j](RFC 9106 3.2 2단계). 차선 i의 j열은 `i·q + j`번 블록이다.
    private struct Memory {
        /// 차선 수 p.
        let lanes: Int
        /// 차선 하나의 블록 수 q = m' / p.
        let laneLength: Int
        /// 조각 하나(segment)의 블록 수 q / SL.
        let segmentLength: Int
        /// 전체 블록 수 m' = 4p·⌊m / 4p⌋.
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

    /// 조각 하나를 채운다. 참조 블록의 위치는 주소 블록(3.4.1.2)에서만 정한다.
    private static func fillSegment(_ memory: inout Memory, pass: Int, slice: Int, lane: Int, iterations: Int) {
        // Z = (r, l, sl, m', t, y)와 카운터 i(3.4.1.2 그림 11). 나머지 968바이트는 0이다.
        var input = [UInt64](repeating: 0, count: wordsPerBlock)
        input[0] = UInt64(pass)
        input[1] = UInt64(lane)
        input[2] = UInt64(slice)
        input[3] = UInt64(memory.blockCount)
        input[4] = UInt64(iterations)
        input[5] = UInt64(type)
        var addresses: [UInt64] = []
        var scratch = [UInt64](repeating: 0, count: wordsPerBlock)

        // 첫 패스의 첫 조각은 처음 두 블록이 이미 차 있다.
        let start = pass == 0 && slice == 0 ? 2 : 0
        for index in start..<memory.segmentLength {
            // 주소 블록 하나가 블록 128개의 참조 위치를 준다. 첫 블록을 건너뛴 조각도 카운터 1부터 쓴다.
            if index == start || index % wordsPerBlock == 0 {
                input[6] += 1
                addresses = addressBlock(input)
            }
            let column = slice * memory.segmentLength + index
            let current = lane * memory.laneLength + column
            // 첫 열의 앞 블록은 같은 차선의 마지막 블록이다(3.2 6단계).
            let previous = column == 0 ? current + memory.laneLength - 1 : current - 1
            let reference = referenceIndex(
                pseudoRandom: addresses[index % wordsPerBlock], memory: memory,
                pass: pass, slice: slice, lane: lane, index: index
            )
            mix(&memory.words, current: current, previous: previous, reference: reference, scratch: &scratch)
        }
    }

    /// 참조 블록 B[l][z]의 번호(RFC 9106 3.4.2). J_1은 아래 32비트, J_2는 위 32비트다.
    private static func referenceIndex(
        pseudoRandom: UInt64, memory: Memory, pass: Int, slice: Int, lane: Int, index: Int
    ) -> Int {
        let j1 = pseudoRandom & 0xFFFF_FFFF
        let j2 = pseudoRandom >> 32
        // 첫 패스의 첫 조각은 다른 차선에 아직 아무것도 없으므로 자기 차선에서 고른다.
        let referenceLane = pass == 0 && slice == 0 ? lane : Int(j2 % UInt64(memory.lanes))
        let sameLane = referenceLane == lane

        // W는 끝난 조각들(첫 패스에서는 지금까지의 조각, 이후에는 최근 3개)이고,
        // 같은 차선이면 지금 조각에서 이미 채운 블록(바로 앞 블록 B[i][j-1] 제외)을 더하고,
        // 다른 차선이면 조각의 첫 블록일 때 W의 마지막 블록(B[i][j-1]과 동시에 계산될 수 있는 블록)을 뺀다.
        let finishedSegments = pass == 0 ? slice : syncPoints - 1
        var areaSize = finishedSegments * memory.segmentLength
        if sameLane {
            areaSize += index - 1
        } else if index == 0 {
            areaSize -= 1
        }
        // W의 첫 블록. 첫 패스는 차선의 맨 앞, 이후는 지금 조각 바로 다음 조각의 맨 앞이다.
        let areaStart = pass == 0 ? 0 : (slice + 1) % syncPoints * memory.segmentLength

        // 그림 13: x = J_1² / 2^32, y = |W|·x / 2^32, zz = |W| - 1 - y.
        let x = (j1 * j1) >> 32
        let y = (UInt64(areaSize) * x) >> 32
        let zz = areaSize - 1 - Int(y)
        return referenceLane * memory.laneLength + (areaStart + zz) % memory.laneLength
    }

    /// 주소 블록 G(0, G(0, Z ‖ i ‖ 0…))(RFC 9106 3.4.1.2). G(0, X) = P(X) ⊕ X.
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

    /// B[current] ⊕= G(B[previous], B[reference])(RFC 9106 3.2 5·6단계, 3.5).
    ///
    /// G(X, Y) = P(R) ⊕ R, R = X ⊕ Y. 버전 0x13은 둘째 패스부터 옛 값에 XOR한다. 첫 패스의 블록은 아직 0이므로
    /// 패스와 상관없이 XOR하면 첫 패스는 대입과 같다.
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

    /// 블록에 P를 행마다, 그다음 열마다 적용한다(RFC 9106 3.5 그림 15).
    ///
    /// 블록은 16바이트 레지스터 8×8 행렬이다. 행 k는 단어 16k..16k+15, 열 k는 단어 (2k, 2k+1), (2k+16, 2k+17), …,
    /// (2k+112, 2k+113)이다. 레지스터 S_i = (v_{2i+1} ‖ v_{2i})이므로 v_{2i}가 메모리에서 앞 단어다(3.6).
    private static func permute(_ block: inout [UInt64]) {
        for row in 0..<8 {
            round(&block, base: 16 * row, pairStride: 2)
        }
        for column in 0..<8 {
            round(&block, base: 2 * column, pairStride: 16)
        }
    }

    /// 순열 P(RFC 9106 3.6). 단어 v_k는 `base + (k / 2)·pairStride + k % 2`에 있다.
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

    /// GB(a, b, c, d)(RFC 9106 3.6 그림 19). BLAKE2b의 G에서 덧셈마다 2·trunc(a)·trunc(b)를 더한다.
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

    // MARK: 바이트 변환

    private static func littleEndian32(_ value: UInt32) -> [UInt8] {
        (0..<4).map { UInt8(truncatingIfNeeded: value >> UInt32(8 * $0)) }
    }

    private static func bytes(of words: [UInt64]) -> [UInt8] {
        words.flatMap { word in (0..<8).map { UInt8(truncatingIfNeeded: word >> UInt64(8 * $0)) } }
    }
}
