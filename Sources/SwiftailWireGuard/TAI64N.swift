/// A 12-byte TAI64N timestamp.
///
/// The initiator encrypts the current time into every initiation. For each peer the responder accepts only values
/// strictly greater than the last one accepted. This prevents replay attacks that resend the same initiation.
/// Clears the low 24 bits of the nanoseconds (about 16.8ms resolution) to prevent time-based side-channel leaks.
///
/// Whitepaper §5.1 and §5.4.2, `docs/protocol-notes/wireguard.md` "TAI64N"
/// (origin: wireguard-go `tai64n/tai64n.go`).
struct TAI64N: Comparable {
    static let size = 12
    private static let base: UInt64 = 0x4000_0000_0000_000a
    private static let whitenerMask: UInt32 = 0x0100_0000 - 1

    /// 8 bytes of big-endian seconds (base + Unix seconds) ‖ 4 bytes of big-endian nanoseconds.
    let bytes: [UInt8]

    /// Creates a timestamp from elapsed time since the Unix epoch. Times before 1970 are treated as 0 seconds.
    init(sinceUnixEpoch elapsed: Duration) {
        let (seconds, attoseconds) = elapsed.components
        let tai = Self.base + UInt64(clamping: seconds)
        let nanoseconds = UInt32(clamping: attoseconds / 1_000_000_000) & ~Self.whitenerMask
        bytes = Array(tai.littleEndianBytes.reversed()) + Array(nanoseconds.littleEndianBytes.reversed())
    }

    /// Creates a timestamp from 12 decrypted bytes. Returns `nil` for any other length.
    init?(bytes: [UInt8]) {
        guard bytes.count == Self.size else { return nil }
        self.bytes = bytes
    }

    /// Lexicographic comparison of 12 bytes (`bytes.Compare`).
    static func < (lhs: TAI64N, rhs: TAI64N) -> Bool {
        lhs.bytes.lexicographicallyPrecedes(rhs.bytes)
    }
}
