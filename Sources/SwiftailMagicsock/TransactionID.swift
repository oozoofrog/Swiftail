/// The 12-byte transaction ID shared by disco Ping and Pong and STUN binding requests.
///
/// The caller supplies randomness. Tests can pass a fixed random number generator.
struct TransactionID: Hashable, Sendable {
    static let byteCount = 12

    let bytes: [UInt8]

    /// Returns `nil` unless the input is exactly 12 bytes.
    init?(_ bytes: some Collection<UInt8>) {
        guard bytes.count == Self.byteCount else { return nil }
        self.bytes = Array(bytes)
    }

    /// Draws 12 bytes using `generator`.
    static func random(using generator: inout some RandomNumberGenerator) -> TransactionID {
        let bytes = (0..<byteCount).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
        return TransactionID(storage: bytes)
    }

    private init(storage: [UInt8]) {
        bytes = storage
    }
}
