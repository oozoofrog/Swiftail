/// The send buffer for one connection (contract `docs/contracts/SwiftailNetstack.md` behavior F6).
///
/// Holds unacknowledged bytes (sent from `SND.UNA` onward) and unsent bytes in order. `append` adds app writes to the
/// back. When an ACK arrives, `acknowledge` discards from the front. Retransmissions copy a range at an offset from
/// `SND.UNA`. The connection reuses circular storage throughout its life, so sending and acknowledging do not allocate
/// new storage.
///
/// SYN and FIN consume one sequence number each but carry no data, so they are absent from this buffer. `startSequence`
/// is the **data** `SND.UNA`. It is the first data sequence number (`ISS + 1`) before SYN is acknowledged and the FIN
/// number after all data is acknowledged. The connection handles the FIN ACK (`endSequence + 1`) directly.
package struct SendBuffer: Sendable {
    /// Contract behavior F6 specifies 256KiB per connection.
    package static let defaultCapacity = 256 * 1024

    private var ring: ByteRing

    /// The sequence number of the oldest unacknowledged byte (data `SND.UNA`).
    package private(set) var startSequence: SequenceNumber
    /// The number of buffered bytes (unacknowledged + unsent).
    package private(set) var count = 0

    /// Creates an empty buffer with the first byte numbered `firstSequence` and capacity `capacity`. Capacity must be at most 2³⁰.
    package init(firstSequence: SequenceNumber, capacity: Int = SendBuffer.defaultCapacity) {
        precondition(capacity <= 1 << 30, "Capacity exceeds the sequence number comparison range")
        ring = ByteRing(capacity: capacity)
        startSequence = firstSequence
    }

    /// Storage capacity in bytes. Buffered bytes cannot exceed it.
    package var capacity: Int { ring.capacity }

    /// The number of additional bytes the buffer can accept.
    package var freeSpace: Int { capacity - count }

    /// The sequence number immediately after the buffered bytes. The next appended byte gets this number.
    package var endSequence: SequenceNumber { startSequence.advanced(by: UInt32(count)) }

    /// The number of bytes actually allocated for storage (for tests and measurement). Never exceeds capacity.
    package var allocatedByteCount: Int { ring.allocatedByteCount }

    /// Appends as many bytes as fit and returns the number accepted. The caller retains any remaining bytes.
    package mutating func append(_ bytes: ArraySlice<UInt8>) -> Int {
        let accepted = min(bytes.count, freeSpace)
        guard accepted > 0 else { return 0 }
        ring.write(bytes.prefix(accepted), at: count)
        count += accepted
        return accepted
    }

    /// Copies up to `maximumLength` bytes beginning at `offset` from `startSequence`. Both outgoing segments
    /// (`offset = SND.NXT − SND.UNA`) and retransmissions (`offset = 0`) use this. Copies only buffered bytes.
    /// Returns an empty array if `offset` is out of range or `maximumLength` is 0 or less.
    ///
    /// shortcut: Copies into a new array per call. The segment payload is `[UInt8]`, so one copy is needed anyway.
    /// Lending the storage would require an unsafe pointer or `Span`, which is unavailable at the minimum platform
    /// version.
    package func bytes(from offset: Int, upTo maximumLength: Int) -> [UInt8] {
        guard offset >= 0, offset < count, maximumLength > 0 else { return [] }
        return ring.copy(from: offset, count: min(maximumLength, count - offset))
    }

    /// Discards bytes acknowledged by cumulative ACK `ack` from the front and returns the number discarded.
    ///
    /// Returns 0 without changing the buffer if `ack` is at or before `startSequence` (a stale or duplicate ACK)
    /// or past `endSequence`. The connection validates ACKs against `SND.NXT` and answers with an ACK before
    /// dropping an ACK of unsent data (behavior X3).
    package mutating func acknowledge(upTo ack: SequenceNumber) -> Int {
        let released = Int(ack.distance(from: startSequence))
        guard released > 0, released <= count else { return 0 }
        ring.discard(released)
        count -= released
        startSequence = ack
        if count == 0 {
            ring.rewind()
        }
        return released
    }
}
