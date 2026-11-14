/// 버퍼 시험이 함께 쓰는 고정 씨앗 난수와 바이트 열. 시험 타깃 안에서만 쓴다.

/// 씨앗에서 같은 열을 만드는 SplitMix64. 실패하면 씨앗으로 같은 경우를 다시 만들 수 있다.
struct BufferTestGenerator: RandomNumberGenerator {
    private var state: UInt64

    init(seed: UInt64) {
        state = seed
    }

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

/// 위치마다 값이 다른 결정적 바이트. 0부터 `count`개.
func patternBytes(_ range: Range<Int>) -> [UInt8] {
    range.map { patternByte(at: $0) }
}

func patternByte(at index: Int) -> UInt8 {
    UInt8(truncatingIfNeeded: index &* 31 &+ (index >> 8) &* 7 &+ 1)
}
