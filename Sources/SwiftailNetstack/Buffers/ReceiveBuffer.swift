/// The receive buffer for one connection (contract `docs/contracts/SwiftailNetstack.md` behaviors F1 and F4, behavior X6).
///
/// Holds contiguous readable bytes immediately before `RCV.NXT` and out-of-order ranges within the receive window
/// in a single fixed-capacity circular store. Out-of-order data goes straight into place at its distance from `RCV.NXT`,
/// so segments need not be retained separately or copied later. Even when 1-byte segments arrive with gaps, memory is
/// limited to the capacity (256KiB) and the range table (32 entries).
///
/// The receive window extends `windowSize` bytes from `RCV.NXT`. Unread bytes occupy space and out-of-order bytes sit
/// within the window. As a result, the right edge (`windowEnd`) stays put when data arrives and advances only when the
/// app reads. Keeping the edge from moving left follows SHLD-14 (RFC 9293 §3.8.6).
///
/// FIN consumes one sequence number but carries no data. This buffer's `nextSequence` is the end of **data**, and the
/// connection tracks `RCV.NXT` (= `nextSequence + 1`) after consuming FIN.
package struct ReceiveBuffer: Sendable {
    /// Contract behavior F1 specifies 256KiB per connection.
    package static let defaultCapacity = 256 * 1024
    /// Contract behavior F4 allows up to 32 out-of-order ranges.
    package static let maximumOutOfOrderRanges = 32

    /// An out-of-order range `[start, end)` expressed as distances from `RCV.NXT`. The list is ordered by `start`.
    /// Ranges neither overlap nor touch and have `start >= 1`. A range that reaches `RCV.NXT` becomes readable bytes.
    private struct Extent: Sendable {
        var start: Int
        var end: Int
        /// The order number of the last `insert` whose segment touched this range. Used to select SACK blocks in
        /// recency order (`sackBlocks(limit:)`).
        var lastInsertion: UInt64
    }

    /// The result of an `insert`. The connection uses `advancedCount` and `filledGap` to decide when to send an ACK
    /// (contract behavior F5). Only tests use `storedCount` and `rejectedForRangeLimit` to check buffer behavior.
    package struct Insertion: Sendable, Equatable {
        /// The amount by which `RCV.NXT` advanced. Greater than 0 for data that arrived in order or filled a gap.
        package var advancedCount = 0
        /// The number of newly stored bytes. Excludes overlap with existing bytes and bytes trimmed outside the window.
        package var storedCount = 0
        /// `RCV.NXT` advanced while an out-of-order range existed. This filled all or part of a gap, so it requires an
        /// immediate ACK (RFC 5681 §4.2).
        package var filledGap = false
        /// The entire segment was rejected because it needed a new range and there were already 32. The peer retransmits it.
        package var rejectedForRangeLimit = false

        /// Creates the result from its fields. Tests use this to specify expected values.
        package init(
            advancedCount: Int = 0, storedCount: Int = 0, filledGap: Bool = false, rejectedForRangeLimit: Bool = false
        ) {
            self.advancedCount = advancedCount
            self.storedCount = storedCount
            self.filledGap = filledGap
            self.rejectedForRangeLimit = rejectedForRangeLimit
        }
    }

    private var ring: ByteRing
    private var extents: [Extent] = []
    /// The number of `insert` calls that placed bytes within the window. The range's `lastInsertion` gets this value.
    private var insertionCount: UInt64 = 0

    /// `RCV.NXT`, the end of data without counting FIN. All bytes before this number have been received without gaps.
    package private(set) var nextSequence: SequenceNumber
    /// The number of bytes available for the app to read.
    package private(set) var readableCount = 0

    /// Creates an empty buffer with `nextSequence` (`RCV.NXT`) set to `initialSequence` and capacity `capacity`.
    /// `initialSequence` is the peer's first data byte number (`IRS + 1`). Capacity must be at most 2³⁰ for sequence
    /// number ordering to be correct.
    package init(initialSequence: SequenceNumber, capacity: Int = ReceiveBuffer.defaultCapacity) {
        precondition(capacity <= 1 << 30, "Capacity exceeds the sequence number comparison range")
        ring = ByteRing(capacity: capacity)
        nextSequence = initialSequence
        extents.reserveCapacity(Self.maximumOutOfOrderRanges)
    }

    /// Storage capacity in bytes. The receive window cannot exceed it.
    package var capacity: Int { ring.capacity }

    /// The largest window the buffer allows, measured from `RCV.NXT` and including any buffered out-of-order data.
    /// The connection applies SWS avoidance and rounds down for window scaling before advertising it.
    package var windowSize: Int { capacity - readableCount }

    /// The right edge of the window (`RCV.NXT + windowSize`). Advances only when the app reads and never retreats.
    package var windowEnd: SequenceNumber { nextSequence.advanced(by: UInt32(windowSize)) }

    /// The number of out-of-order ranges. 0 ... 32.
    package var outOfOrderRangeCount: Int { extents.count }

    /// The total number of bytes stored out of order.
    package var outOfOrderByteCount: Int { extents.reduce(0) { $0 + ($1.end - $1.start) } }

    /// The number of bytes actually allocated for storage (for tests and measurement). Never exceeds capacity.
    package var allocatedByteCount: Int { ring.allocatedByteCount }

    /// Accepts the part of the peer's `bytes` within the receive window. `sequence` is the first byte's number.
    ///
    /// - Drops bytes that extend to the left (already received) or right (past `windowEnd`) of the window and keeps only the bytes inside it.
    /// - Keeps existing bytes on overlap, whether they are readable or out of order.
    /// - Rejects the entire segment if a new range would exceed 32 (`rejectedForRangeLimit`).
    /// - Filling a gap advances `RCV.NXT` to the end of contiguous data.
    ///
    /// The connection checks sequence numbers and decides whether to answer with RST or ACK. This function handles only
    /// bytes inside the window.
    package mutating func insert(_ bytes: ArraySlice<UInt8>, at sequence: SequenceNumber) -> Insertion {
        // Compute the in-window range [lower, upper) as distances from `RCV.NXT`.
        let start = Int(sequence.distance(from: nextSequence))
        let skipped = max(0, -start)
        let lower = max(0, start)
        guard skipped < bytes.count, lower < windowSize else { return Insertion() }
        let upper = lower + min(bytes.count - skipped, windowSize - lower)
        let payload = bytes[bytes.startIndex + skipped..<bytes.startIndex + skipped + (upper - lower)]

        // The existing ranges that overlap or touch the new range are at indices `first..<last`.
        let first = extents.firstIndex { $0.end >= lower } ?? extents.count
        let last = extents[first...].firstIndex { $0.start > upper } ?? extents.count
        if first == last, lower > 0, extents.count >= Self.maximumOutOfOrderRanges {
            return Insertion(rejectedForRangeLimit: true)
        }

        // Write only the gaps not covered by existing ranges. On overlap, the bytes received first win.
        var storedCount = 0
        var cursor = lower
        for extent in extents[first..<last] {
            if extent.start > cursor {
                storedCount += write(payload, from: cursor, to: extent.start, payloadBase: lower)
            }
            cursor = max(cursor, extent.end)
        }
        if cursor < upper {
            storedCount += write(payload, from: cursor, to: upper, payloadBase: lower)
        }

        // Merge the overlapping ranges into one. The merged range contains this segment and becomes the most recent range.
        insertionCount &+= 1
        let merged = Extent(
            start: first < last ? min(lower, extents[first].start) : lower,
            end: first < last ? max(upper, extents[last - 1].end) : upper,
            lastInsertion: insertionCount
        )
        let hadOutOfOrderData = !extents.isEmpty
        extents.replaceSubrange(first..<last, with: [merged])

        // The range that reaches `RCV.NXT` becomes readable bytes. Subtract that length from the remaining ranges' offsets.
        var advancedCount = 0
        if merged.start == 0 {
            advancedCount = merged.end
            extents.removeFirst()
            for index in extents.indices {
                extents[index].start -= advancedCount
                extents[index].end -= advancedCount
            }
            readableCount += advancedCount
            nextSequence = nextSequence.advanced(by: UInt32(advancedCount))
        }
        return Insertion(
            advancedCount: advancedCount, storedCount: storedCount, filledGap: advancedCount > 0 && hadOutOfOrderData)
    }

    /// Returns out-of-order ranges as up to `limit` SACK blocks, most recently updated by a segment first (RFC 2018 §4).
    ///
    /// - The first block is the range in which the last `insert` placed bytes. If that segment advanced `RCV.NXT` and
    ///   the range disappeared by becoming readable bytes, use the next most recent range. This is the first rule in
    ///   RFC 2018 §4, the block containing the segment that triggered this ACK, unless that segment advanced the
    ///   Acknowledgment Number. The connection immediately ACKs every out-of-order segment (contract behavior F5), so
    ///   the segment that triggered this ACK is the last `insert`.
    /// - Remaining blocks are in reverse order of segment insertion. A range was reported as the first block in the ACK
    ///   each time it received a segment, so this is the third rule's order of most recently reported first blocks.
    ///   Ranges do not overlap, so no block is a subset of an earlier block (the third rule), and none points to bytes
    ///   that have become readable.
    /// - Returns an empty array if there are no ranges. An ACK after all gaps are filled carries no SACK.
    package func sackBlocks(limit: Int) -> [TCPSegment.SACKBlock] {
        extents.sorted { $0.lastInsertion > $1.lastInsertion }.prefix(max(0, limit)).map { extent in
            TCPSegment.SACKBlock(
                leftEdge: nextSequence.advanced(by: UInt32(extent.start)),
                rightEdge: nextSequence.advanced(by: UInt32(extent.end)))
        }
    }

    /// Takes up to `maximumLength` readable bytes from the front. Opens the window by the amount taken.
    ///
    /// shortcut: Copies into a new array per call, for the same reason as `SendBuffer.bytes`.
    package mutating func read(upTo maximumLength: Int) -> [UInt8] {
        let count = min(max(maximumLength, 0), readableCount)
        guard count > 0 else { return [] }
        let bytes = ring.copy(from: 0, count: count)
        ring.discard(count)
        readableCount -= count
        if readableCount == 0, extents.isEmpty {
            ring.rewind()
        }
        return bytes
    }

    /// Writes `payload`'s distance range `[from, to)` into its place in storage and returns the number of bytes
    /// written. The payload starts at distance `payloadBase`.
    private mutating func write(
        _ payload: ArraySlice<UInt8>, from: Int, to: Int, payloadBase: Int
    ) -> Int {
        let begin = payload.startIndex + (from - payloadBase)
        ring.write(payload[begin..<begin + (to - from)], at: readableCount + from)
        return to - from
    }
}
