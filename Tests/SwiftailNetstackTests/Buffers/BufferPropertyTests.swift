import Testing

@testable import SwiftailNetstack

/// 임의의 순서·크기·겹침·중복으로 쪼개 넣어도 원래 바이트열이 그대로 나오는 성질 시험(고정 씨앗)과, 4GiB를 넘는 전송.
@Suite("버퍼 성질 시험")
struct BufferPropertyTests {
    /// 받는 버퍼: 흐름의 임의 구간을 창 안팎으로 마구 넣고 읽어 가며 흐름 전체를 되찾는다.
    ///
    /// 모형은 "어느 바이트를 이미 받았는가"를 따로 센다. 이미 받은 바이트·창 밖의 바이트는 **틀린 값**으로 보내므로,
    /// 먼저 받은 바이트가 이긴다는 규칙과 창 밖을 받지 않는다는 규칙이 어기면 되찾은 흐름이 달라진다.
    @Test("받는 버퍼는 어떤 쪼개기에도 원래 흐름을 낸다", arguments: Array(UInt64(1)...24))
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
                Issue.record("seed \(seed): 끝나지 않는다(\(output.count)/\(streamLength))")
                return
            }
            let nextOffset = output.count + buffer.readableCount  // RCV.NXT의 흐름 위치
            if Int.random(in: 0..<10, using: &generator) < 3 {
                output += buffer.read(upTo: Int.random(in: 0...capacity / 2 + 1, using: &generator))
                continue
            }

            // 창 안팎에 걸쳐 임의의 위치·길이로 고른다. 가끔은 정확히 RCV.NXT에서 시작해 끝내 진행하게 한다.
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

            // 불변 조건
            #expect(buffer.windowEnd.distance(from: edgeBefore) >= 0, "seed \(seed): 창의 오른쪽 끝이 왼쪽으로 갔다")
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
            #expect(rejectedCount > 0, "seed \(seed): 구간 32개 상한을 한 번도 건드리지 못했다")
        }
    }

    /// 한 바퀴를 넘는 전송: 번호가 2³²을 넘어 0으로 돌아와도 두 버퍼가 맞는다. 총량은 4GiB를 조금 넘는다.
    ///
    /// 보내는 버퍼에 쓴 바이트가 세그먼트로 꺼내져 받는 버퍼에 들어가고, 앱이 읽어 가면 ACK가 돌아와 보내는 버퍼가 비워진다.
    /// 바이트는 흐름 위치에서 정해지는 반복 무늬다. 받은 바이트는 조각마다 처음·가운데·끝을 위치로 견주고
    /// 일정한 간격으로 조각 전체를 견준다(전부 견주면 디버그 빌드에서 너무 느리다. 쪼개기마다의 전체 비교는 위의 성질 시험이 한다).
    @Test("4GiB를 넘는 전송에서 번호가 한 바퀴 돌아도 두 버퍼가 맞는다")
    func transferBeyondFourGiB() {
        let capacity = 64 * 1024
        let period = 65_521  // 용량과 맞물리지 않는 주기
        let pattern = patternBytes(0..<period) + patternBytes(0..<period)  // 주기를 두 번 이어 어느 위상에서도 한 번에 잘라 쓴다
        func expectedByte(at position: Int) -> UInt8 { pattern[position % period] }

        let total = Int(UInt32.max) + 1 + 5 * capacity + 123
        let isn = SequenceNumber(0x8000_0000)
        var sender = SendBuffer(firstSequence: isn, capacity: capacity)
        var receiver = ReceiveBuffer(initialSequence: isn, capacity: capacity)

        var written = 0
        var sent = 0  // sender.startSequence 기준으로 이미 보냈지만 확인받지 못한 바이트 수
        var delivered = 0
        var chunkCount = 0
        var failures = 0
        while delivered < total {
            let length = min(sender.freeSpace, total - written, period)
            let phase = written % period
            written += sender.append(pattern[phase..<phase + length])

            // 보내기: 세그먼트마다 받는 버퍼에 넣고, 둘에 한 번 누적 ACK(받는 버퍼의 RCV.NXT)가 돌아온다.
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

            // 읽는 앱: 조각을 둘로 나눠 읽는다(ACK는 받은 시점에 이미 나갔다. 읽기는 창만 연다).
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
        #expect(total > Int(UInt32.max))  // 번호가 한 바퀴를 돌았다
        #expect(receiver.nextSequence == isn.advanced(by: UInt32(truncatingIfNeeded: total)))
        #expect(sender.startSequence == receiver.nextSequence)
        #expect(sender.count == 0)
        #expect(receiver.readableCount == 0)
    }
}
