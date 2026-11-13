/// TAI64N timestamp 12바이트.
///
/// 초기자는 initiation마다 현재 시각을 암호화해 넣고, 응답자는 피어별로 마지막에 받아들인 값보다
/// 엄격히 큰 것만 받는다. 같은 initiation을 다시 보내는 재전송 공격을 막는 장치다.
/// 하위 24비트 나노초를 지워(약 16.8ms 해상도) 시각으로 부채널 정보가 새지 않게 한다.
///
/// 백서 §5.1·§5.4.2, `docs/protocol-notes/wireguard.md` "TAI64N"
/// (출처: wireguard-go `tai64n/tai64n.go`).
struct TAI64N: Comparable {
    static let size = 12
    private static let base: UInt64 = 0x4000_0000_0000_000a
    private static let whitenerMask: UInt32 = 0x0100_0000 - 1

    /// big-endian 초(base + Unix 초) 8바이트 ‖ big-endian 나노초 4바이트.
    let bytes: [UInt8]

    /// Unix 기원부터의 경과 시간으로 만든다. 1970년 이전은 0초로 본다.
    init(sinceUnixEpoch elapsed: Duration) {
        let (seconds, attoseconds) = elapsed.components
        let tai = Self.base + UInt64(clamping: seconds)
        let nanoseconds = UInt32(clamping: attoseconds / 1_000_000_000) & ~Self.whitenerMask
        bytes = Array(tai.littleEndianBytes.reversed()) + Array(nanoseconds.littleEndianBytes.reversed())
    }

    /// 복호화한 12바이트로 만든다. 길이가 다르면 `nil`.
    init?(bytes: [UInt8]) {
        guard bytes.count == Self.size else { return nil }
        self.bytes = bytes
    }

    /// 12바이트 사전식 비교(`bytes.Compare`).
    static func < (lhs: TAI64N, rhs: TAI64N) -> Bool {
        lhs.bytes.lexicographicallyPrecedes(rhs.bytes)
    }
}
