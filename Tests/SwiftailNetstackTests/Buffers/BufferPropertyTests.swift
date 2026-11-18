import Testing

@testable import SwiftailNetstack

/// Property tests (fixed seed) that recover the original bytes after inserting chunks in arbitrary order, sizes, overlaps, and duplicates, plus a transfer of more than 4GiB.
@Suite("Buffer property tests")
struct BufferPropertyTests {
    /// Receive buffer: Recover the entire stream by inserting and reading arbitrary ranges of the stream inside and outside the window.
    ///
    /// The model independently tracks "which bytes have already arrived." Previously received and out-of-window bytes are sent with **incorrect values**, so
    /// violating either rule (the first byte received wins, and out-of-window bytes are rejected) changes the recovered stream.
    @Test("The receive buffer produces the original stream for any chunking", arguments: Array(UInt64(1)...24))
    func receiveReassemblesStream(seed: UInt64) {
        var generator = BufferTestGenerator(seed: seed)
        let capacity = [64, 1000, 4096][Int(seed % 3)]
        let initial = SequenceNumber(seed.isMultiple(of: 2) ? 0xFFFF_FF00 : UInt32(truncatingIfNeeded: seed &* 0x1234_5678))
        let streamLength = 60_000
        let stream = (0..<streamLength).map { _ in UInt8.random(in: .min ... .max, using: &generator) }

        var buffer = ReceiveBuffer(initialSequence: initial, capacity: capacity)
        var received = [Bool](repeating: false, count: streamLength)
        var output: [UInt8] = []
        var rejectedCount = 0
        var iterations = 0

        while output.count < streamLength {
            iterations += 1
            guard iterations < 2_000_000 else {
                Issue.record("seed \(seed): did not finish (\(output.count)/\(streamLength))")
                return
            }
            let nextOffset = output.count + buffer.readableCount  // Stream position of RCV.NXT
            if Int.random(in: 0..<10, using: &generator) < 3 {
                output += buffer.read(upTo: Int.random(in: 0...capacity / 2 + 1, using: &generator))
                continue
            }

            // Pick an arbitrary position and length spanning the inside and outside of the window. Occasionally start exactly at RCV.NXT to ensure eventual progress.
            let windowEndOffset = nextOffset + buffer.windowSize
            var from = nextOffset + Int.random(in: -12...buffer.windowSize + 12, using: &generator)
            if Int.random(in: 0..<12, using: &generator) == 0 { from = nextOffset }
            from = min(max(from, 0), streamLength)
            let maximumLength = Int.random(in: 0..<3, using: &generator) == 0 ? 1 : 150
            let to = min(streamLength, from + Int.random(in: 1...maximumLength, using: &generator))
            guard from < to else { continue }

            let segment: [UInt8] = (from..<to).map { position in
                let insideWindow = position >= nextOffset && position < windowEndOffset
                return insideWindow && !received[position] ? stream[position] : ~stream[position]
            }
            let edgeBefore = buffer.windowEnd
            let nextBefore = buffer.nextSequence
            let result = buffer.insert(ArraySlice(segment), at: initial.advanced(by: UInt32(truncatingIfNeeded: from)))

            if result.rejectedForRangeLimit {
                rejectedCount += 1
                #expect(result.storedCount == 0 && result.advancedCount == 0)
            } else {
                for position in max(from, nextOffset)..<max(max(from, nextOffset), min(to, windowEndOffset)) {
                    received[position] = true
                }
            }

            // Invariants
            #expect(buffer.windowEnd.distance(from: edgeBefore) >= 0, "seed \(seed): the window's right edge moved left")
            #expect(buffer.nextSequence.distance(from: nextBefore) == Int32(result.advancedCount))
            #expect(buffer.outOfOrderRangeCount <= ReceiveBuffer.maximumOutOfOrderRanges)
            #expect(buffer.readableCount + buffer.outOfOrderByteCount <= capacity)
            #expect(buffer.allocatedByteCount <= capacity)
            if result.advancedCount == 0 { #expect(!result.filledGap) }
        }
        output += buffer.read(upTo: Int.max)

        #expect(output == stream, "seed \(seed)")
        #expect(buffer.outOfOrderRangeCount == 0)
        if capacity == 4096 {
            #expect(rejectedCount > 0, "seed \(seed): never hit the 32-range limit")
        }
    }

    /// Transfer spanning more than a full sequence number cycle: Both buffers work when the sequence number crosses 2³² and returns to 0. The total slightly exceeds 4GiB.
    ///
    /// Bytes written to the send buffer are taken out in segments and inserted in the receive buffer. When the app reads them, an ACK returns and clears the send buffer.
    /// The bytes use a repeating pattern determined by stream position. Check the start, middle, and end of each received chunk against its position,
    /// and compare entire chunks at regular intervals (checking all of them is too slow in a debug build. The property test above does the full comparison for each chunking).
    @Test("Both buffers work when sequence numbers wrap during a transfer of more than 4GiB")
    func transferBeyondFourGiB() {
        let capacity = 64 * 1024
        let period = 65_521  // Period that does not align with the capacity
        let pattern = patternBytes(0..<period) + patternBytes(0..<period)  // Repeat the period twice to take a single slice at any phase
        func expectedByte(at position: Int) -> UInt8 { pattern[position % period] }

        let total = Int(UInt32.max) + 1 + 5 * capacity + 123
        let isn = SequenceNumber(0x8000_0000)
        var sender = SendBuffer(firstSequence: isn, capacity: capacity)
        var receiver = ReceiveBuffer(initialSequence: isn, capacity: capacity)

        var written = 0
        var sent = 0  // Number of bytes sent but not acknowledged, relative to sender.startSequence
        var delivered = 0
        var chunkCount = 0
        var failures = 0
        while delivered < total {
            let length = min(sender.freeSpace, total - written, period)
            let phase = written % period
            written += sender.append(pattern[phase..<phase + length])

            // Sender: Insert each segment in the receive buffer and return a cumulative ACK (the receive buffer's RCV.NXT) every two segments.
            var segmentIndex = 0
            while sent < sender.count {
                let payload = sender.bytes(from: sent, upTo: 16_000)
                let result = receiver.insert(
                    ArraySlice(payload), at: sender.startSequence.advanced(by: UInt32(sent)))
                if result.advancedCount != payload.count { failures += 1 }
                sent += payload.count
                segmentIndex += 1
                if segmentIndex.isMultiple(of: 2) {
                    sent -= sender.acknowledge(upTo: receiver.nextSequence)
                }
            }
            sent -= sender.acknowledge(upTo: receiver.nextSequence)
            if sender.count != 0 || sent != 0 { failures += 1 }

            // Reading app: Read the chunk in two parts (the ACK was sent on receipt. Reading only opens the window).
            for limit in [10_000, Int.max] {
                let chunk = receiver.read(upTo: limit)
                guard let first = chunk.first, let last = chunk.last else { continue }
                if first != expectedByte(at: delivered) || last != expectedByte(at: delivered + chunk.count - 1)
                    || chunk[chunk.count / 2] != expectedByte(at: delivered + chunk.count / 2)
                {
                    failures += 1
                }
                chunkCount += 1
                if chunkCount.isMultiple(of: 512) {
                    let expected = (delivered..<delivered + chunk.count).map(expectedByte(at:))
                    if chunk != expected { failures += 1 }
                }
                delivered += chunk.count
            }
        }

        #expect(failures == 0)
        #expect(delivered == total)
        #expect(total > Int(UInt32.max))  // The sequence number wrapped once
        #expect(receiver.nextSequence == isn.advanced(by: UInt32(truncatingIfNeeded: total)))
        #expect(sender.startSequence == receiver.nextSequence)
        #expect(sender.count == 0)
        #expect(receiver.readableCount == 0)
    }
}
