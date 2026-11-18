import Testing

@testable import SwiftailNetstack

/// Receive buffer (contract behaviors F1·F4, X6, M). Express sequence numbers as offsets from `RCV.NXT`.
@Suite("Receive buffer")
struct ReceiveBufferTests {
    private static let start = SequenceNumber(1000)

    /// Inserts the bytes at offset `range` into `buffer` (their values are determined by the offset).
    @discardableResult
    private func insert(
        _ buffer: inout ReceiveBuffer, _ range: Range<Int>, base: SequenceNumber = ReceiveBufferTests.start
    ) -> ReceiveBuffer.Insertion {
        buffer.insert(ArraySlice(patternBytes(range)), at: base.advanced(by: UInt32(range.lowerBound)))
    }

    // MARK: In-order, out-of-order, overlapping, and duplicate data

    @Test("In-order data advances RCV.NXT and can be read")
    func inOrder() {
        var buffer = ReceiveBuffer(initialSequence: Self.start, capacity: 64)
        let first = insert(&buffer, 0..<10)
        #expect(first == .init(advancedCount: 10, storedCount: 10))
        let second = insert(&buffer, 10..<25)
        #expect(second == .init(advancedCount: 15, storedCount: 15))
        #expect(buffer.nextSequence == Self.start.advanced(by: 25))
        #expect(buffer.readableCount == 25)
        #expect(buffer.read(upTo: 100) == patternBytes(0..<25))
        #expect(buffer.readableCount == 0)
    }

    @Test("Zero bytes change nothing")
    func zeroBytes() {
        var buffer = ReceiveBuffer(initialSequence: Self.start, capacity: 64)
        #expect(buffer.insert([], at: Self.start) == .init())
        #expect(buffer.insert([], at: Self.start.advanced(by: 30)) == .init())
        #expect(buffer.nextSequence == Self.start)
        #expect(buffer.outOfOrderRangeCount == 0)
        #expect(buffer.allocatedByteCount == 0)
        #expect(buffer.read(upTo: 10).isEmpty)
    }

    @Test("Out-of-order data stays in place and RCV.NXT advances to the end once the gap is filled")
    func outOfOrderThenFill() {
        var buffer = ReceiveBuffer(initialSequence: Self.start, capacity: 64)
        let early = insert(&buffer, 10..<20)
        #expect(early == .init(advancedCount: 0, storedCount: 10))
        #expect(buffer.nextSequence == Self.start)
        #expect(buffer.readableCount == 0)
        #expect(buffer.outOfOrderRangeCount == 1)
        #expect(buffer.outOfOrderByteCount == 10)
        let fill = insert(&buffer, 0..<10)
        #expect(fill == .init(advancedCount: 20, storedCount: 10, filledGap: true))
        #expect(buffer.outOfOrderRangeCount == 0)
        #expect(buffer.read(upTo: 100) == patternBytes(0..<20))
    }

    @Test("Filling part of a gap leaves the range and pulls the remaining range forward")
    func partialFill() {
        var buffer = ReceiveBuffer(initialSequence: Self.start, capacity: 64)
        insert(&buffer, 10..<20)
        insert(&buffer, 30..<40)
        let partial = insert(&buffer, 0..<5)
        #expect(partial == .init(advancedCount: 5, storedCount: 5, filledGap: true))
        #expect(buffer.outOfOrderRangeCount == 2)
        #expect(buffer.outOfOrderByteCount == 20)
        // Verify that the range moved by filling the gap before it.
        insert(&buffer, 5..<10)
        #expect(buffer.readableCount == 20)
        insert(&buffer, 20..<30)
        #expect(buffer.readableCount == 40)
        #expect(buffer.read(upTo: 100) == patternBytes(0..<40))
    }

    @Test("A segment filling the gap between two ranges merges them into one")
    func bridgingTwoRanges() {
        var buffer = ReceiveBuffer(initialSequence: Self.start, capacity: 64)
        insert(&buffer, 10..<20)
        insert(&buffer, 30..<40)
        let bridge = insert(&buffer, 20..<30)
        #expect(bridge == .init(advancedCount: 0, storedCount: 10))
        #expect(buffer.outOfOrderRangeCount == 1)
        #expect(buffer.outOfOrderByteCount == 30)
        let head = insert(&buffer, 0..<10)
        #expect(head.advancedCount == 40)
        #expect(buffer.read(upTo: 100) == patternBytes(0..<40))
    }

    @Test("Adjacent ranges also merge")
    func adjacentRangesMerge() {
        var buffer = ReceiveBuffer(initialSequence: Self.start, capacity: 64)
        insert(&buffer, 10..<20)
        insert(&buffer, 20..<30)
        #expect(buffer.outOfOrderRangeCount == 1)
        insert(&buffer, 5..<10)
        #expect(buffer.outOfOrderRangeCount == 1)
        #expect(buffer.outOfOrderByteCount == 25)
    }

    @Test("Keeps the first bytes received when ranges overlap at the front, back, middle, or across the entire range")
    func overlapKeepsFirstReceived() {
        func corrupt(_ range: Range<Int>) -> ArraySlice<UInt8> {
            ArraySlice(patternBytes(range).map { ~$0 })
        }
        var buffer = ReceiveBuffer(initialSequence: Self.start, capacity: 128)
        insert(&buffer, 20..<40)
        // Front overlap (10..<25), back overlap (35..<50), interior (25..<30), and full coverage (5..<60). Send incorrect bytes in the overlapping portions.
        let seq = { (offset: Int) in Self.start.advanced(by: UInt32(offset)) }
        var stored = 0
        stored += buffer.insert(corrupt(10..<25), at: seq(10)).storedCount
        stored += buffer.insert(corrupt(35..<50), at: seq(35)).storedCount
        stored += buffer.insert(corrupt(25..<30), at: seq(25)).storedCount
        #expect(stored == 10 + 10)  // Only 10..<20 and 40..<50 were newly stored
        #expect(buffer.outOfOrderRangeCount == 1)
        let cover = buffer.insert(corrupt(5..<60), at: seq(5))
        #expect(cover.storedCount == 5 + 10)  // 5..<10 and 50..<60
        // Fill the initial 0..<5 with correct bytes. In all of 5..<60, the bytes received first must win.
        insert(&buffer, 0..<5)
        let bytes = buffer.read(upTo: 100)
        #expect(bytes.count == 60)
        #expect(Array(bytes[0..<5]) == patternBytes(0..<5))
        #expect(Array(bytes[5..<10]) == patternBytes(5..<10).map { ~$0 })  // The covering segment arrived first for 5..<10
        #expect(Array(bytes[10..<20]) == patternBytes(10..<20).map { ~$0 })  // The front overlap arrived first for 10..<20
        #expect(Array(bytes[20..<40]) == patternBytes(20..<40))  // Correct bytes that arrived first
        #expect(Array(bytes[40..<50]) == patternBytes(40..<50).map { ~$0 })  // The back overlap arrived first
        #expect(Array(bytes[50..<60]) == patternBytes(50..<60).map { ~$0 })
    }

    @Test("A duplicate of previously received data changes nothing")
    func duplicates() {
        var buffer = ReceiveBuffer(initialSequence: Self.start, capacity: 64)
        insert(&buffer, 0..<10)
        // Duplicate before reading
        #expect(insert(&buffer, 0..<10) == .init())
        #expect(insert(&buffer, 3..<8) == .init())
        #expect(buffer.read(upTo: 4) == patternBytes(0..<4))
        // Duplicate after reading (sequence numbers already consumed)
        #expect(insert(&buffer, 0..<10) == .init())
        // Duplicate of an out-of-order range
        insert(&buffer, 20..<30)
        #expect(insert(&buffer, 20..<30) == .init())
        #expect(insert(&buffer, 22..<25) == .init())
        #expect(buffer.outOfOrderRangeCount == 1)
        #expect(buffer.readableCount == 6)
    }

    // MARK: 32 ranges

    @Test("Accepts up to 32 ranges and rejects the 33rd")
    func thirtyTwoRanges() {
        var buffer = ReceiveBuffer(initialSequence: Self.start, capacity: 1000)
        for index in 0..<32 {
            let result = insert(&buffer, (2 * index + 2)..<(2 * index + 3))  // 1 byte at offsets 2, 4, ... 64
            #expect(result.storedCount == 1)
            #expect(!result.rejectedForRangeLimit)
        }
        #expect(buffer.outOfOrderRangeCount == 32)
        let windowEnd = buffer.windowEnd

        let rejected = insert(&buffer, 66..<67)
        #expect(rejected == .init(rejectedForRangeLimit: true))
        #expect(buffer.outOfOrderRangeCount == 32)
        #expect(buffer.outOfOrderByteCount == 32)
        #expect(buffer.windowEnd == windowEnd)

        // A segment extending an existing range does not add a range, so it is accepted even at 32 ranges.
        let extend = insert(&buffer, 3..<5)  // Only the gap (3..<4) between 2..<3 and 4..<5 contains new bytes, and the two ranges merge into one (2..<5)
        #expect(extend.storedCount == 1 && !extend.rejectedForRangeLimit)
        #expect(buffer.outOfOrderRangeCount == 31)
        let again = insert(&buffer, 66..<67)
        #expect(again.storedCount == 1)
        #expect(buffer.outOfOrderRangeCount == 32)
    }

    @Test("Accepts a segment that touches RCV.NXT even when there are 32 ranges")
    func inOrderWhenFull() {
        var buffer = ReceiveBuffer(initialSequence: Self.start, capacity: 1000)
        for index in 0..<32 {
            insert(&buffer, (2 * index + 2)..<(2 * index + 3))
        }
        let result = insert(&buffer, 0..<1)
        #expect(result == .init(advancedCount: 1, storedCount: 1, filledGap: true))
        #expect(buffer.readableCount == 1)
        #expect(buffer.outOfOrderRangeCount == 32)  // The ranges stay the same and only their offsets decrease by 1
    }

    @Test("Accepts no portion of a segment that would create a 33rd range, even inside the window")
    func rejectedSegmentStoresNothing() {
        var buffer = ReceiveBuffer(initialSequence: Self.start, capacity: 1000)
        for index in 0..<32 {
            insert(&buffer, (2 * index + 2)..<(2 * index + 3))
        }
        let rejected = insert(&buffer, 100..<200)
        #expect(rejected.rejectedForRangeLimit)
        #expect(rejected.storedCount == 0)
        #expect(buffer.outOfOrderByteCount == 32)
    }

    @Test("Merging one range frees a slot so the buffer accepts data again")
    func mergeFreesARangeSlot() {
        var buffer = ReceiveBuffer(initialSequence: Self.start, capacity: 1000)
        for index in 0..<32 {
            insert(&buffer, (2 * index + 2)..<(2 * index + 3))
        }
        // Filling the gap (3..<4) between 2..<3 and 4..<5 merges them into one.
        insert(&buffer, 3..<4)
        #expect(buffer.outOfOrderRangeCount == 31)
        #expect(insert(&buffer, 100..<101).storedCount == 1)
        #expect(buffer.outOfOrderRangeCount == 32)
    }

    // MARK: Both window edges

    @Test("Only the in-window portion of a segment overlapping the left edge is accepted")
    func leftEdge() {
        var buffer = ReceiveBuffer(initialSequence: Self.start, capacity: 32)
        insert(&buffer, 0..<10)
        #expect(buffer.read(upTo: 10).count == 10)
        // Segment overlapping the 4 bytes before RCV.NXT (offsets 6..<16)
        let result = insert(&buffer, 6..<16)
        #expect(result == .init(advancedCount: 6, storedCount: 6))
        #expect(buffer.read(upTo: 100) == patternBytes(10..<16))
        // Very old sequence number
        let stale = buffer.insert(ArraySlice(patternBytes(0..<10)), at: Self.start)
        #expect(stale == .init())
    }

    @Test("Only the in-window portion of a segment overlapping the right edge is accepted. The out-of-window portion is rejected")
    func rightEdge() {
        var buffer = ReceiveBuffer(initialSequence: Self.start, capacity: 16)
        let straddle = insert(&buffer, 10..<20)
        #expect(straddle == .init(advancedCount: 0, storedCount: 6))  // 10..<16
        #expect(buffer.outOfOrderByteCount == 6)
        #expect(insert(&buffer, 16..<20) == .init())  // Starts at the window's right edge
        #expect(insert(&buffer, 40..<50) == .init())
        insert(&buffer, 0..<10)
        #expect(buffer.readableCount == 16)
        #expect(buffer.read(upTo: 100) == patternBytes(0..<16))
    }

    @Test("A segment overlapping both ends contributes exactly the whole window")
    func bothEdges() {
        var buffer = ReceiveBuffer(initialSequence: Self.start, capacity: 16)
        insert(&buffer, 0..<4)
        #expect(buffer.read(upTo: 4).count == 4)
        let result = insert(&buffer, 0..<100)  // RCV.NXT is at offset 4. The first 4 bytes were already received, and the rest extends to 16 bytes
        #expect(result == .init(advancedCount: 16, storedCount: 16))
        #expect(buffer.read(upTo: 100) == patternBytes(4..<20))
    }

    // MARK: Reading, available space, and capacity

    @Test("Reading opens the window and its right edge does not retreat")
    func windowAndRead() {
        var buffer = ReceiveBuffer(initialSequence: Self.start, capacity: 16)
        let edge = buffer.windowEnd
        #expect(edge == Self.start.advanced(by: 16))
        insert(&buffer, 0..<10)
        #expect(buffer.windowSize == 6)
        #expect(buffer.windowEnd == edge)
        insert(&buffer, 12..<16)  // Out-of-order data is also within the window, so the right edge stays put
        #expect(buffer.windowEnd == edge)
        #expect(buffer.read(upTo: 4).count == 4)
        #expect(buffer.windowSize == 10)
        #expect(buffer.windowEnd == edge.advanced(by: 4))  // Advances to the right by only the amount read
        #expect(buffer.read(upTo: 0).isEmpty)
        #expect(buffer.read(upTo: -3).isEmpty)
        #expect(buffer.windowEnd == edge.advanced(by: 4))
    }

    @Test("At capacity the window is 0 and accepts nothing further. It accepts only as much as was read")
    func fullAtCapacity() {
        var buffer = ReceiveBuffer(initialSequence: Self.start, capacity: 16)
        #expect(insert(&buffer, 0..<16).advancedCount == 16)
        #expect(buffer.windowSize == 0)
        #expect(insert(&buffer, 16..<20) == .init())
        #expect(buffer.read(upTo: 5) == patternBytes(0..<5))
        #expect(buffer.windowSize == 5)
        #expect(insert(&buffer, 16..<30).storedCount == 5)
        #expect(buffer.read(upTo: 100) == patternBytes(5..<21))
    }

    @Test("Contents stay correct when storage wraps")
    func ringWrapsAround() {
        var buffer = ReceiveBuffer(initialSequence: Self.start, capacity: 16)
        var offset = 0
        var output: [UInt8] = []
        for round in 0..<40 {
            let length = 5 + round % 8  // 5...12. After reading, 3 bytes remain, so the front does not reset to the beginning of storage.
            let accepted = insert(&buffer, offset..<offset + length)
            #expect(accepted.advancedCount == length)
            offset += length
            output += buffer.read(upTo: buffer.readableCount - 3 > 0 ? buffer.readableCount - 3 : 0)
        }
        output += buffer.read(upTo: 100)
        #expect(output == patternBytes(0..<offset))
    }

    @Test("Contents stay correct when an out-of-order range wraps past the end of storage")
    func outOfOrderAcrossRingEnd() {
        var buffer = ReceiveBuffer(initialSequence: Self.start, capacity: 16)
        insert(&buffer, 0..<12)
        #expect(buffer.read(upTo: 10) == patternBytes(0..<10))  // The front is at index 10 in storage and 2 bytes remain
        insert(&buffer, 14..<20)  // Spans 14..<16 and 0..<4 in storage
        let fill = insert(&buffer, 12..<14)
        #expect(fill.advancedCount == 8)
        #expect(buffer.read(upTo: 100) == patternBytes(10..<20))
    }

    @Test("Storage for a sporadically used connection does not grow to capacity")
    func lightUseStaysSmall() {
        var buffer = ReceiveBuffer(initialSequence: Self.start)
        #expect(buffer.allocatedByteCount == 0)
        var offset = 0
        for _ in 0..<1000 {
            insert(&buffer, offset..<offset + 100)
            #expect(buffer.read(upTo: 100).count == 100)
            offset += 100
        }
        #expect(buffer.allocatedByteCount <= 4096)
    }

    // MARK: Sequence numbers crossing 2³²

    @Test("Works across 2³² with in-order, out-of-order, and overlapping data")
    func sequenceWrap() {
        let base = SequenceNumber(0xFFFF_FFF0)
        var buffer = ReceiveBuffer(initialSequence: base, capacity: 64)
        // The out-of-order range crosses 0 and the gap is before 0.
        insert(&buffer, 20..<30, base: base)
        insert(&buffer, 4..<10, base: base)
        #expect(buffer.outOfOrderRangeCount == 2)
        let fill = insert(&buffer, 0..<4, base: base)  // 0xFFFF_FFF0 ..< 0xFFFF_FFF4
        #expect(fill.advancedCount == 10)
        #expect(buffer.nextSequence == SequenceNumber(0xFFFF_FFFA))
        insert(&buffer, 10..<20, base: base)  // Range that crosses 0xFFFF_FFFA and wraps to 0
        #expect(buffer.nextSequence == SequenceNumber(0xFFFF_FFF0).advanced(by: 30))
        #expect(buffer.nextSequence.rawValue == 14)
        #expect(buffer.read(upTo: 100) == patternBytes(0..<30))
        // A duplicate after wraparound has already been received.
        #expect(insert(&buffer, 5..<25, base: base) == .init())
        #expect(buffer.windowEnd == SequenceNumber(14).advanced(by: 64))
    }

    // MARK: Memory (X6)

    @Test("Sending 10,000 spaced-out 1-byte segments still leaves 32 ranges and keeps storage within capacity")
    func tinySegmentsStayBounded() {
        var buffer = ReceiveBuffer(initialSequence: Self.start)
        for index in 0..<10_000 {
            let distance = 2 * index + 2  // 1 byte with no overlap or adjacency
            insert(&buffer, distance..<distance + 1)
            #expect(buffer.outOfOrderRangeCount <= ReceiveBuffer.maximumOutOfOrderRanges)
        }
        #expect(buffer.outOfOrderRangeCount == 32)
        #expect(buffer.outOfOrderByteCount == 32)
        #expect(buffer.allocatedByteCount <= ReceiveBuffer.defaultCapacity)
        // Storage grew only as far as the offset of the 32nd range.
        #expect(buffer.allocatedByteCount <= 4096)
    }

    @Test("Storage stays within capacity even when out-of-order ranges are scattered across the entire window")
    func scatteredAcrossWindow() {
        var buffer = ReceiveBuffer(initialSequence: Self.start)
        var generator = BufferTestGenerator(seed: 1)
        for _ in 0..<5_000 {
            let distance = Int.random(in: 0..<ReceiveBuffer.defaultCapacity + 100, using: &generator)
            insert(&buffer, distance..<distance + Int.random(in: 1...64, using: &generator))
        }
        #expect(buffer.allocatedByteCount <= ReceiveBuffer.defaultCapacity)
        #expect(buffer.outOfOrderRangeCount <= ReceiveBuffer.maximumOutOfOrderRanges)
        #expect(buffer.outOfOrderByteCount <= ReceiveBuffer.defaultCapacity)
    }
}
