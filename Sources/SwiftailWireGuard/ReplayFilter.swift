/// A replay protection window for transport counters (RFC 6479).
///
/// UDP does not preserve order, so counters cannot be expected to always increase. The window accepts out-of-order packets up to
/// 8128 counters behind the highest counter, and accepts each counter only once.
/// It uses a ring of 128 64-bit blocks and clears only the blocks it passes as the window advances.
///
/// Apply this only to AEAD-authenticated packets so forged counters cannot advance the window and block legitimate packets.
///
/// Whitepaper §5.4.6, `docs/protocol-notes/wireguard.md` "Transport data: receiving" 4
/// (origin: wireguard-go `replay/replay.go`, MIT license, Copyright (C) 2017-2023 WireGuard LLC).
struct ReplayFilter {
    private static let blockBitLog: UInt64 = 6
    private static let blockBits: UInt64 = 1 << blockBitLog
    private static let ringBlocks: UInt64 = 1 << 7
    /// The maximum accepted lag. (128 − 1) × 64 = 8128.
    static let windowSize: UInt64 = (ringBlocks - 1) * blockBits

    private var last: UInt64 = 0
    private var ring = [UInt64](repeating: 0, count: Int(ringBlocks))

    /// Determines whether to accept the counter and records it if accepted. Always rejects counters at or above the limit.
    /// Rejecting a counter leaves the state unchanged.
    mutating func accept(_ counter: UInt64, limit: UInt64 = Constants.rejectAfterMessages) -> Bool {
        guard counter < limit else { return false }
        let block = counter >> Self.blockBitLog
        if counter > last {
            // Advance the window. Clear the blocks it passes, at most one full turn of the ring.
            let current = last >> Self.blockBitLog
            let advance = min(block - current, Self.ringBlocks)
            for offset in stride(from: 1, through: advance, by: 1) {
                ring[Self.ringIndex(current &+ offset)] = 0
            }
            last = counter
        } else if last - counter > Self.windowSize {
            return false
        }
        let index = Self.ringIndex(block)
        let bit: UInt64 = 1 << (counter & (Self.blockBits - 1))
        guard ring[index] & bit == 0 else { return false }
        ring[index] |= bit
        return true
    }

    private static func ringIndex(_ block: UInt64) -> Int {
        Int(block & (ringBlocks - 1))
    }
}
