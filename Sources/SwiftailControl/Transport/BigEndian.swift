/// All fixed-width integers in the control transport layer are big-endian, including the message length (uint16), record nonce
/// counter (uint64), and early payload length (uint32).
///
/// `docs/protocol-notes/control-transport.md` Chapter 3 introduction.
extension FixedWidthInteger {
    /// The big-endian byte sequence. Its length is `bitWidth / 8`.
    var bigEndianBytes: [UInt8] {
        (0..<(Self.bitWidth / 8)).reversed().map { UInt8(truncatingIfNeeded: self >> ($0 * 8)) }
    }

    /// Reads a big-endian byte sequence. The caller provides exactly `bitWidth / 8` bytes.
    init(bigEndianBytes bytes: some Collection<UInt8>) {
        self = bytes.reduce(0) { $0 << 8 | Self($1) }
    }
}
