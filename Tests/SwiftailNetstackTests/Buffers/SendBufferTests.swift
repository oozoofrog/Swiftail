import Testing

@testable import SwiftailNetstack

/// Send buffer (contract behavior F6). Express sequence numbers as offsets from the first byte (the initial value of `startSequence`).
@Suite("Send buffer")
struct SendBufferTests {
    private static let first = SequenceNumber(5000)

    @Test("Retains written bytes in order and allows retrieval by range")
    func appendAndSlice() {
        var buffer = SendBuffer(firstSequence: Self.first, capacity: 64)
        #expect(buffer.append(ArraySlice(patternBytes(0..<10))) == 10)
        #expect(buffer.append(ArraySlice(patternBytes(10..<25))) == 15)
        #expect(buffer.count == 25)
        #expect(buffer.freeSpace == 39)
        #expect(buffer.startSequence == Self.first)
        #expect(buffer.endSequence == Self.first.advanced(by: 25))
        #expect(buffer.bytes(from: 0, upTo: 100) == patternBytes(0..<25))
        #expect(buffer.bytes(from: 0, upTo: 4) == patternBytes(0..<4))
        #expect(buffer.bytes(from: 7, upTo: 5) == patternBytes(7..<12))
        #expect(buffer.bytes(from: 20, upTo: 100) == patternBytes(20..<25))
    }

    @Test("Out-of-range requests and zero-byte requests return empty arrays")
    func degenerateSlices() {
        var buffer = SendBuffer(firstSequence: Self.first, capacity: 64)
        #expect(buffer.append([]) == 0)
        #expect(buffer.bytes(from: 0, upTo: 10).isEmpty)
        _ = buffer.append(ArraySlice(patternBytes(0..<10)))
        #expect(buffer.bytes(from: 10, upTo: 5).isEmpty)  // Just past the end
        #expect(buffer.bytes(from: 99, upTo: 5).isEmpty)
        #expect(buffer.bytes(from: -1, upTo: 5).isEmpty)
        #expect(buffer.bytes(from: 3, upTo: 0).isEmpty)
        #expect(buffer.bytes(from: 3, upTo: -4).isEmpty)
    }

    @Test("Accepts only up to capacity and returns the count accepted")
    func capacityLimit() {
        var buffer = SendBuffer(firstSequence: Self.first, capacity: 16)
        #expect(buffer.append(ArraySlice(patternBytes(0..<10))) == 10)
        #expect(buffer.append(ArraySlice(patternBytes(10..<30))) == 6)  // Room for only 6 bytes
        #expect(buffer.freeSpace == 0)
        #expect(buffer.append(ArraySlice(patternBytes(16..<20))) == 0)
        #expect(buffer.count == 16)
        #expect(buffer.bytes(from: 0, upTo: 100) == patternBytes(0..<16))
        // A single write larger than capacity fills only up to capacity.
        var other = SendBuffer(firstSequence: Self.first, capacity: 16)
        #expect(other.append(ArraySlice(patternBytes(0..<100))) == 16)
        #expect(other.bytes(from: 0, upTo: 100) == patternBytes(0..<16))
    }

    @Test("A partial ACK discards bytes from the front and advances SND.UNA")
    func partialAcknowledgement() {
        var buffer = SendBuffer(firstSequence: Self.first, capacity: 64)
        _ = buffer.append(ArraySlice(patternBytes(0..<30)))
        #expect(buffer.acknowledge(upTo: Self.first.advanced(by: 10)) == 10)
        #expect(buffer.startSequence == Self.first.advanced(by: 10))
        #expect(buffer.count == 20)
        #expect(buffer.bytes(from: 0, upTo: 100) == patternBytes(10..<30))
        #expect(buffer.acknowledge(upTo: Self.first.advanced(by: 25)) == 15)
        #expect(buffer.bytes(from: 0, upTo: 100) == patternBytes(25..<30))
        #expect(buffer.endSequence == Self.first.advanced(by: 30))  // The ACK does not move the end sequence number
    }

    @Test("A full ACK empties the buffer, allowing subsequent writes")
    func fullAcknowledgement() {
        var buffer = SendBuffer(firstSequence: Self.first, capacity: 16)
        _ = buffer.append(ArraySlice(patternBytes(0..<16)))
        #expect(buffer.acknowledge(upTo: Self.first.advanced(by: 16)) == 16)
        #expect(buffer.count == 0)
        #expect(buffer.freeSpace == 16)
        #expect(buffer.startSequence == buffer.endSequence)
        #expect(buffer.bytes(from: 0, upTo: 10).isEmpty)
        #expect(buffer.append(ArraySlice(patternBytes(16..<30))) == 14)
        #expect(buffer.bytes(from: 0, upTo: 100) == patternBytes(16..<30))
    }

    @Test("Old, duplicate, and out-of-range ACKs change nothing")
    func unusableAcknowledgements() {
        var buffer = SendBuffer(firstSequence: Self.first, capacity: 64)
        _ = buffer.append(ArraySlice(patternBytes(0..<20)))
        #expect(buffer.acknowledge(upTo: Self.first.advanced(by: 8)) == 8)
        // Duplicate (equal to SND.UNA) and old ACK (before SND.UNA)
        #expect(buffer.acknowledge(upTo: Self.first.advanced(by: 8)) == 0)
        #expect(buffer.acknowledge(upTo: Self.first.advanced(by: 3)) == 0)
        #expect(buffer.acknowledge(upTo: Self.first.advanced(by: 0xFFFF_FFF0)) == 0)  // Very old sequence number
        // Beyond retained bytes (an ACK claiming to acknowledge unsent data)
        #expect(buffer.acknowledge(upTo: Self.first.advanced(by: 21)) == 0)
        #expect(buffer.acknowledge(upTo: Self.first.advanced(by: 5000)) == 0)
        #expect(buffer.startSequence == Self.first.advanced(by: 8))
        #expect(buffer.count == 12)
        #expect(buffer.bytes(from: 0, upTo: 100) == patternBytes(8..<20))
    }

    @Test("Writing into the space freed by an ACK preserves contents even across a storage wrap")
    func ringReuse() {
        var buffer = SendBuffer(firstSequence: Self.first, capacity: 16)
        var written = 0
        var acknowledged = 0
        for round in 0..<60 {
            let length = 3 + round % 9
            let accepted = buffer.append(ArraySlice(patternBytes(written..<written + length)))
            written += accepted
            // The entire retained range is correct (including ranges that wrap past the end of storage).
            #expect(buffer.bytes(from: 0, upTo: 100) == patternBytes(acknowledged..<written))
            let ack = min(5, buffer.count)
            #expect(buffer.acknowledge(upTo: buffer.startSequence.advanced(by: UInt32(ack))) == ack)
            acknowledged += ack
        }
        #expect(buffer.count == written - acknowledged)
    }

    @Test("Works when sequence numbers cross 2³²")
    func sequenceWrap() {
        let first = SequenceNumber(0xFFFF_FFF0)
        var buffer = SendBuffer(firstSequence: first, capacity: 64)
        #expect(buffer.append(ArraySlice(patternBytes(0..<40))) == 40)
        #expect(buffer.endSequence == SequenceNumber(24))
        // ACK before crossing 0
        #expect(buffer.acknowledge(upTo: SequenceNumber(0xFFFF_FFF8)) == 8)
        // ACK after crossing 0
        #expect(buffer.acknowledge(upTo: SequenceNumber(5)) == 13)
        #expect(buffer.startSequence == SequenceNumber(5))
        #expect(buffer.bytes(from: 0, upTo: 100) == patternBytes(21..<40))
        // After wraparound, an earlier sequence number is an old ACK.
        #expect(buffer.acknowledge(upTo: SequenceNumber(0xFFFF_FFF0)) == 0)
        #expect(buffer.acknowledge(upTo: SequenceNumber(24)) == 19)
        #expect(buffer.count == 0)
    }

    @Test("Storage for a sporadically used connection does not grow to capacity")
    func lightUseStaysSmall() {
        var buffer = SendBuffer(firstSequence: Self.first)
        #expect(buffer.allocatedByteCount == 0)
        for _ in 0..<1000 {
            _ = buffer.append(ArraySlice(patternBytes(0..<100)))
            #expect(buffer.acknowledge(upTo: buffer.endSequence) == 100)
        }
        #expect(buffer.allocatedByteCount <= 4096)
    }

    @Test("Arbitrary writes, retrievals, and ACKs match the model")
    func randomOperationsMatchModel() {
        for seed in UInt64(1)...20 {
            var generator = BufferTestGenerator(seed: seed)
            let capacity = [16, 100, 1024, 4096].randomElement(using: &generator) ?? 100
            let first = SequenceNumber(UInt32.random(in: .min ... .max, using: &generator) | (seed.isMultiple(of: 2) ? 0xFFFF_F000 : 0))
            var buffer = SendBuffer(firstSequence: first, capacity: capacity)
            var model: [UInt8] = []  // Retained bytes
            var nextStreamIndex = 0

            for _ in 0..<2_000 {
                switch Int.random(in: 0..<10, using: &generator) {
                case 0..<4:
                    let length = Int.random(in: 0...capacity + 20, using: &generator)
                    let chunk = patternBytes(nextStreamIndex..<nextStreamIndex + length)
                    let accepted = buffer.append(ArraySlice(chunk))
                    #expect(accepted == min(length, capacity - model.count), "seed \(seed)")
                    model += chunk.prefix(accepted)
                    nextStreamIndex += accepted
                case 4..<7:
                    let offset = Int.random(in: -3...model.count + 3, using: &generator)
                    let length = Int.random(in: -2...200, using: &generator)
                    let expected: [UInt8] =
                        offset >= 0 && offset < model.count && length > 0
                        ? Array(model[offset..<min(model.count, offset + length)]) : []
                    #expect(buffer.bytes(from: offset, upTo: length) == expected, "seed \(seed)")
                default:
                    let delta = Int.random(in: -3...model.count + 3, using: &generator)
                    let ack = buffer.startSequence.advanced(by: UInt32(truncatingIfNeeded: delta))
                    let released = buffer.acknowledge(upTo: ack)
                    let expectedReleased = delta > 0 && delta <= model.count ? delta : 0
                    #expect(released == expectedReleased, "seed \(seed)")
                    model.removeFirst(expectedReleased)
                }
                #expect(buffer.count == model.count, "seed \(seed)")
                #expect(buffer.endSequence == buffer.startSequence.advanced(by: UInt32(model.count)), "seed \(seed)")
                #expect(buffer.allocatedByteCount <= capacity, "seed \(seed)")
            }
        }
    }
}
