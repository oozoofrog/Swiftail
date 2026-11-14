/// disco Ping·Pong과 STUN 바인딩 요청이 함께 쓰는 12바이트 트랜잭션 ID.
///
/// 난수는 호출한 쪽이 넘긴다. 시험은 고정 난수 생성기를 넘길 수 있다.
struct TransactionID: Hashable, Sendable {
    static let byteCount = 12

    let bytes: [UInt8]

    /// 정확히 12바이트가 아니면 `nil`.
    init?(_ bytes: some Collection<UInt8>) {
        guard bytes.count == Self.byteCount else { return nil }
        self.bytes = Array(bytes)
    }

    /// `generator`로 12바이트를 뽑는다.
    static func random(using generator: inout some RandomNumberGenerator) -> TransactionID {
        let bytes = (0..<byteCount).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
        return TransactionID(storage: bytes)
    }

    private init(storage: [UInt8]) {
        bytes = storage
    }
}
