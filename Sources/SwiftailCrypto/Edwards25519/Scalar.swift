/// A scalar modulo the edwards25519 base point order L = 2^252 + 27742317777372353535851937790883648493
/// (RFC 8032 §5.1). The value always satisfies 0 ≤ value < L.
///
/// Uses variable-time operations because it handles only public values in signature verification.
struct Scalar: Equatable {
    /// Four 64-bit little-endian words.
    private var words: [UInt64]

    /// The 64-bit little-endian words of L.
    private static let order: [UInt64] = [0x5812_631A_5CF5_D3ED, 0x14DE_F9DE_A2F7_9CD6, 0, 0x1000_0000_0000_0000]

    static let zero = Scalar(words: [0, 0, 0, 0])

    private init(words: [UInt64]) { self.words = words }

    /// Creates a scalar only when the 32-byte little-endian integer is smaller than L (the S check in RFC 8032 §5.1.7, Go
    /// `Scalar.SetCanonicalBytes`). Returns `nil` for a length other than 32.
    init?(canonicalBytes bytes: [UInt8]) {
        guard bytes.count == 32 else { return nil }
        let words = (0..<4).map { w in (0..<8).reduce(UInt64(0)) { $0 | UInt64(bytes[8 * w + $1]) << (8 * $1) } }
        guard Self.isLess(words, Self.order) else { return nil }
        self.init(words: words)
    }

    /// The remainder of a 64-byte little-endian integer modulo L (Go `Scalar.SetUniformBytes`). Derives
    /// k from the SHA-512 output.
    ///
    /// Starting from the highest bit, update r ← 2r + bit, then subtract L if r ≥ L. When r < L, 2r + 1 < 2L, so
    /// one subtraction suffices. Since 2L < 2^254, it fits in four words.
    ///
    /// - Precondition: `bytes.count == 64`.
    init(reducing bytes: [UInt8]) {
        precondition(bytes.count == 64, "Input to reduce must be 64 bytes")
        var r: [UInt64] = [0, 0, 0, 0]
        for bitIndex in (0..<512).reversed() {
            let bit = UInt64(bytes[bitIndex / 8] >> (bitIndex % 8) & 1)
            r = [r[0] << 1 | bit, r[1] << 1 | r[0] >> 63, r[2] << 1 | r[1] >> 63, r[3] << 1 | r[2] >> 63]
            if !Self.isLess(r, Self.order) { r = Self.subtract(r, Self.order) }
        }
        self.init(words: r)
    }

    /// The bit at index i (0 is the lowest). i is in 0..<256.
    func bit(_ i: Int) -> Bool { words[i / 64] >> (i % 64) & 1 == 1 }

    /// Whether a < b (four little-endian words).
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
