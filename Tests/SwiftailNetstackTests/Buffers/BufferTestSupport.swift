/// Fixed-seed random numbers and byte sequences shared by the buffer tests. Used only inside the test target.

/// SplitMix64 generates the same sequence from the same seed. If a test fails, the seed reproduces the case.
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

/// Deterministic bytes whose values vary by position. Returns `count` bytes starting at 0.
func patternBytes(_ range: Range<Int>) -> [UInt8] {
    range.map { patternByte(at: $0) }
}

func patternByte(at index: Int) -> UInt8 {
    UInt8(truncatingIfNeeded: index &* 31 &+ (index >> 8) &* 7 &+ 1)
}
