import Testing

@testable import SwiftailNetstack

/// 보내는 버퍼(계약 동작 F6). 번호는 첫 바이트(`startSequence`의 처음 값)에서의 거리로 말한다.
@Suite("보내는 버퍼")
struct SendBufferTests {
    private static let first = SequenceNumber(5000)

    @Test("쓴 바이트는 순서대로 쥐고 구간으로 꺼낼 수 있다")
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

    @Test("범위 밖 구간과 0바이트는 빈 배열이다")
    func degenerateSlices() {
        var buffer = SendBuffer(firstSequence: Self.first, capacity: 64)
        #expect(buffer.append([]) == 0)
        #expect(buffer.bytes(from: 0, upTo: 10).isEmpty)
        _ = buffer.append(ArraySlice(patternBytes(0..<10)))
        #expect(buffer.bytes(from: 10, upTo: 5).isEmpty)  // 끝 바로 뒤
        #expect(buffer.bytes(from: 99, upTo: 5).isEmpty)
        #expect(buffer.bytes(from: -1, upTo: 5).isEmpty)
        #expect(buffer.bytes(from: 3, upTo: 0).isEmpty)
        #expect(buffer.bytes(from: 3, upTo: -4).isEmpty)
    }

    @Test("용량까지만 받아들이고 받아들인 수를 돌려준다")
    func capacityLimit() {
        var buffer = SendBuffer(firstSequence: Self.first, capacity: 16)
        #expect(buffer.append(ArraySlice(patternBytes(0..<10))) == 10)
        #expect(buffer.append(ArraySlice(patternBytes(10..<30))) == 6)  // 자리가 6개뿐
        #expect(buffer.freeSpace == 0)
        #expect(buffer.append(ArraySlice(patternBytes(16..<20))) == 0)
        #expect(buffer.count == 16)
        #expect(buffer.bytes(from: 0, upTo: 100) == patternBytes(0..<16))
        // 용량보다 큰 한 번의 쓰기는 용량까지만.
        var other = SendBuffer(firstSequence: Self.first, capacity: 16)
        #expect(other.append(ArraySlice(patternBytes(0..<100))) == 16)
        #expect(other.bytes(from: 0, upTo: 100) == patternBytes(0..<16))
    }

    @Test("부분 ACK는 앞에서부터 버리고 SND.UNA를 옮긴다")
    func partialAcknowledgement() {
        var buffer = SendBuffer(firstSequence: Self.first, capacity: 64)
        _ = buffer.append(ArraySlice(patternBytes(0..<30)))
        #expect(buffer.acknowledge(upTo: Self.first.advanced(by: 10)) == 10)
        #expect(buffer.startSequence == Self.first.advanced(by: 10))
        #expect(buffer.count == 20)
        #expect(buffer.bytes(from: 0, upTo: 100) == patternBytes(10..<30))
        #expect(buffer.acknowledge(upTo: Self.first.advanced(by: 25)) == 15)
        #expect(buffer.bytes(from: 0, upTo: 100) == patternBytes(25..<30))
        #expect(buffer.endSequence == Self.first.advanced(by: 30))  // 끝 번호는 ACK로 움직이지 않는다
    }

    @Test("전체 ACK는 버퍼를 비운다. 이어 쓸 수 있다")
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

    @Test("오래된·중복·범위 밖 ACK는 아무것도 바꾸지 않는다")
    func unusableAcknowledgements() {
        var buffer = SendBuffer(firstSequence: Self.first, capacity: 64)
        _ = buffer.append(ArraySlice(patternBytes(0..<20)))
        #expect(buffer.acknowledge(upTo: Self.first.advanced(by: 8)) == 8)
        // 중복(SND.UNA와 같음)과 오래된 ACK(앞)
        #expect(buffer.acknowledge(upTo: Self.first.advanced(by: 8)) == 0)
        #expect(buffer.acknowledge(upTo: Self.first.advanced(by: 3)) == 0)
        #expect(buffer.acknowledge(upTo: Self.first.advanced(by: 0xFFFF_FFF0)) == 0)  // 아주 오래된 번호
        // 쥔 바이트 너머(보내지 않은 것을 확인한다는 ACK)
        #expect(buffer.acknowledge(upTo: Self.first.advanced(by: 21)) == 0)
        #expect(buffer.acknowledge(upTo: Self.first.advanced(by: 5000)) == 0)
        #expect(buffer.startSequence == Self.first.advanced(by: 8))
        #expect(buffer.count == 12)
        #expect(buffer.bytes(from: 0, upTo: 100) == patternBytes(8..<20))
    }

    @Test("ACK로 난 자리에 이어 쓰면 저장소를 한 바퀴 돌아도 내용이 맞다")
    func ringReuse() {
        var buffer = SendBuffer(firstSequence: Self.first, capacity: 16)
        var written = 0
        var acknowledged = 0
        for round in 0..<60 {
            let length = 3 + round % 9
            let accepted = buffer.append(ArraySlice(patternBytes(written..<written + length)))
            written += accepted
            // 쥔 구간 전체가 맞다(저장소의 끝을 넘어 되감기는 구간 포함).
            #expect(buffer.bytes(from: 0, upTo: 100) == patternBytes(acknowledged..<written))
            let ack = min(5, buffer.count)
            #expect(buffer.acknowledge(upTo: buffer.startSequence.advanced(by: UInt32(ack))) == ack)
            acknowledged += ack
        }
        #expect(buffer.count == written - acknowledged)
    }

    @Test("번호가 2³²을 넘어도 맞다")
    func sequenceWrap() {
        let first = SequenceNumber(0xFFFF_FFF0)
        var buffer = SendBuffer(firstSequence: first, capacity: 64)
        #expect(buffer.append(ArraySlice(patternBytes(0..<40))) == 40)
        #expect(buffer.endSequence == SequenceNumber(24))
        // 0을 넘기기 전의 ACK
        #expect(buffer.acknowledge(upTo: SequenceNumber(0xFFFF_FFF8)) == 8)
        // 0을 넘긴 ACK
        #expect(buffer.acknowledge(upTo: SequenceNumber(5)) == 13)
        #expect(buffer.startSequence == SequenceNumber(5))
        #expect(buffer.bytes(from: 0, upTo: 100) == patternBytes(21..<40))
        // 한 바퀴 돈 뒤의 앞선 번호는 오래된 ACK다.
        #expect(buffer.acknowledge(upTo: SequenceNumber(0xFFFF_FFF0)) == 0)
        #expect(buffer.acknowledge(upTo: SequenceNumber(24)) == 19)
        #expect(buffer.count == 0)
    }

    @Test("가끔 쓰는 연결은 저장소가 용량까지 자라지 않는다")
    func lightUseStaysSmall() {
        var buffer = SendBuffer(firstSequence: Self.first)
        #expect(buffer.allocatedByteCount == 0)
        for _ in 0..<1000 {
            _ = buffer.append(ArraySlice(patternBytes(0..<100)))
            #expect(buffer.acknowledge(upTo: buffer.endSequence) == 100)
        }
        #expect(buffer.allocatedByteCount <= 4096)
    }

    @Test("임의의 쓰기·꺼내기·ACK를 모형과 견주어도 같다")
    func randomOperationsMatchModel() {
        for seed in UInt64(1)...20 {
            var generator = BufferTestGenerator(seed: seed)
            let capacity = [16, 100, 1024, 4096].randomElement(using: &generator) ?? 100
            let first = SequenceNumber(UInt32.random(in: .min ... .max, using: &generator) | (seed.isMultiple(of: 2) ? 0xFFFF_F000 : 0))
            var buffer = SendBuffer(firstSequence: first, capacity: capacity)
            var model: [UInt8] = []  // 쥐고 있는 바이트
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
