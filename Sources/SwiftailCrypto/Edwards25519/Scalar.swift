/// edwards25519 기준점 위수 L = 2^252 + 27742317777372353535851937790883648493을 법으로 하는 스칼라
/// (RFC 8032 5.1). 값은 언제나 0 ≤ 값 < L이다.
///
/// 서명 검증의 공개 값만 다루므로 가변 시간 연산을 쓴다.
struct Scalar: Equatable {
    /// 64비트 리틀 엔디언 단어 넷.
    private var words: [UInt64]

    /// L의 64비트 리틀 엔디언 단어.
    private static let order: [UInt64] = [0x5812_631A_5CF5_D3ED, 0x14DE_F9DE_A2F7_9CD6, 0, 0x1000_0000_0000_0000]

    static let zero = Scalar(words: [0, 0, 0, 0])

    private init(words: [UInt64]) { self.words = words }

    /// 32바이트 리틀 엔디언 정수가 L보다 작을 때만 만든다(RFC 8032 5.1.7의 S 검사, Go
    /// `Scalar.SetCanonicalBytes`). 길이가 32가 아니면 `nil`이다.
    init?(canonicalBytes bytes: [UInt8]) {
        guard bytes.count == 32 else { return nil }
        let words = (0..<4).map { w in (0..<8).reduce(UInt64(0)) { $0 | UInt64(bytes[8 * w + $1]) << (8 * $1) } }
        guard Self.isLess(words, Self.order) else { return nil }
        self.init(words: words)
    }

    /// 64바이트 리틀 엔디언 정수를 L로 나눈 나머지(Go `Scalar.SetUniformBytes`). SHA-512 출력에서
    /// k를 만든다.
    ///
    /// 가장 높은 비트부터 r ← 2r + 비트를 하고 r ≥ L이면 L을 뺀다. r < L이면 2r + 1 < 2L이므로
    /// 한 번 빼는 것으로 충분하고, 2L < 2^254라 네 단어에 들어간다.
    ///
    /// - Precondition: `bytes.count == 64`.
    init(reducing bytes: [UInt8]) {
        precondition(bytes.count == 64, "환원할 입력은 64바이트")
        var r: [UInt64] = [0, 0, 0, 0]
        for bitIndex in (0..<512).reversed() {
            let bit = UInt64(bytes[bitIndex / 8] >> (bitIndex % 8) & 1)
            r = [r[0] << 1 | bit, r[1] << 1 | r[0] >> 63, r[2] << 1 | r[1] >> 63, r[3] << 1 | r[2] >> 63]
            if !Self.isLess(r, Self.order) { r = Self.subtract(r, Self.order) }
        }
        self.init(words: r)
    }

    /// i번째 비트(0이 가장 낮다). i는 0..<256.
    func bit(_ i: Int) -> Bool { words[i / 64] >> (i % 64) & 1 == 1 }

    /// a < b (네 단어 리틀 엔디언).
    private static func isLess(_ a: [UInt64], _ b: [UInt64]) -> Bool {
        for i in (0..<4).reversed() where a[i] != b[i] { return a[i] < b[i] }
        return false
    }

    /// a − b. a ≥ b.
    private static func subtract(_ a: [UInt64], _ b: [UInt64]) -> [UInt64] {
        var result: [UInt64] = []
        var borrow = false
        for i in 0..<4 {
            let (d1, o1) = a[i].subtractingReportingOverflow(b[i])
            let (d2, o2) = d1.subtractingReportingOverflow(borrow ? 1 : 0)
            result.append(d2)
            borrow = o1 || o2
        }
        return result
    }
}
