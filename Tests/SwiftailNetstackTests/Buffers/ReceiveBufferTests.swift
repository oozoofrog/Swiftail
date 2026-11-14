import Testing

@testable import SwiftailNetstack

/// 받는 버퍼(계약 동작 F1·F4, X6, M). 번호는 `RCV.NXT`에서의 거리로 말한다.
@Suite("받는 버퍼")
struct ReceiveBufferTests {
    private static let start = SequenceNumber(1000)

    /// 거리 `range`의 바이트를 `buffer`에 넣는다(바이트는 거리에서 정해진다).
    @discardableResult
    private func insert(
        _ buffer: inout ReceiveBuffer, _ range: Range<Int>, base: SequenceNumber = ReceiveBufferTests.start
    ) -> ReceiveBuffer.Insertion {
        buffer.insert(ArraySlice(patternBytes(range)), at: base.advanced(by: UInt32(range.lowerBound)))
    }

    // MARK: 순서대로·어긋나게·겹치게·중복으로

    @Test("순서대로 온 데이터는 RCV.NXT를 나아가게 하고 읽을 수 있다")
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

    @Test("0바이트는 아무것도 바꾸지 않는다")
    func zeroBytes() {
        var buffer = ReceiveBuffer(initialSequence: Self.start, capacity: 64)
        #expect(buffer.insert([], at: Self.start) == .init())
        #expect(buffer.insert([], at: Self.start.advanced(by: 30)) == .init())
        #expect(buffer.nextSequence == Self.start)
        #expect(buffer.outOfOrderRangeCount == 0)
        #expect(buffer.allocatedByteCount == 0)
        #expect(buffer.read(upTo: 10).isEmpty)
    }

    @Test("어긋나게 먼저 온 데이터는 제자리에 두고, 빈 곳이 메워지면 RCV.NXT가 끝까지 나아간다")
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

    @Test("빈 곳의 일부만 메우면 구간은 남고 나머지 구간은 앞으로 당겨진다")
    func partialFill() {
        var buffer = ReceiveBuffer(initialSequence: Self.start, capacity: 64)
        insert(&buffer, 10..<20)
        insert(&buffer, 30..<40)
        let partial = insert(&buffer, 0..<5)
        #expect(partial == .init(advancedCount: 5, storedCount: 5, filledGap: true))
        #expect(buffer.outOfOrderRangeCount == 2)
        #expect(buffer.outOfOrderByteCount == 20)
        // 구간이 당겨졌는지는 그 앞의 빈 곳을 메워 확인한다.
        insert(&buffer, 5..<10)
        #expect(buffer.readableCount == 20)
        insert(&buffer, 20..<30)
        #expect(buffer.readableCount == 40)
        #expect(buffer.read(upTo: 100) == patternBytes(0..<40))
    }

    @Test("두 구간 사이를 메우는 세그먼트는 둘을 하나로 잇는다")
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

    @Test("맞닿기만 하는 구간도 하나로 합친다")
    func adjacentRangesMerge() {
        var buffer = ReceiveBuffer(initialSequence: Self.start, capacity: 64)
        insert(&buffer, 10..<20)
        insert(&buffer, 20..<30)
        #expect(buffer.outOfOrderRangeCount == 1)
        insert(&buffer, 5..<10)
        #expect(buffer.outOfOrderRangeCount == 1)
        #expect(buffer.outOfOrderByteCount == 25)
    }

    @Test("겹치는 바이트는 먼저 받은 것을 둔다: 앞·뒤·가운데·완전히 덮음")
    func overlapKeepsFirstReceived() {
        func corrupt(_ range: Range<Int>) -> ArraySlice<UInt8> {
            ArraySlice(patternBytes(range).map { ~$0 })
        }
        var buffer = ReceiveBuffer(initialSequence: Self.start, capacity: 128)
        insert(&buffer, 20..<40)
        // 앞쪽으로 걸침(10..<25), 뒤쪽으로 걸침(35..<50), 가운데(25..<30), 완전히 덮음(5..<60). 겹친 부분은 틀린 바이트로 보낸다.
        let seq = { (offset: Int) in Self.start.advanced(by: UInt32(offset)) }
        var stored = 0
        stored += buffer.insert(corrupt(10..<25), at: seq(10)).storedCount
        stored += buffer.insert(corrupt(35..<50), at: seq(35)).storedCount
        stored += buffer.insert(corrupt(25..<30), at: seq(25)).storedCount
        #expect(stored == 10 + 10)  // 10..<20과 40..<50만 새로 저장했다
        #expect(buffer.outOfOrderRangeCount == 1)
        let cover = buffer.insert(corrupt(5..<60), at: seq(5))
        #expect(cover.storedCount == 5 + 10)  // 5..<10과 50..<60
        // 앞의 0..<5는 바른 바이트로 채운다. 5..<60은 모두 먼저 받은 것이 이긴 결과여야 한다.
        insert(&buffer, 0..<5)
        let bytes = buffer.read(upTo: 100)
        #expect(bytes.count == 60)
        #expect(Array(bytes[0..<5]) == patternBytes(0..<5))
        #expect(Array(bytes[5..<10]) == patternBytes(5..<10).map { ~$0 })  // 5..<10은 덮는 세그먼트가 처음
        #expect(Array(bytes[10..<20]) == patternBytes(10..<20).map { ~$0 })  // 10..<20은 앞쪽 걸침이 처음
        #expect(Array(bytes[20..<40]) == patternBytes(20..<40))  // 먼저 온 바른 바이트
        #expect(Array(bytes[40..<50]) == patternBytes(40..<50).map { ~$0 })  // 뒤쪽 걸침이 처음
        #expect(Array(bytes[50..<60]) == patternBytes(50..<60).map { ~$0 })
    }

    @Test("이미 받은 데이터의 중복은 아무것도 바꾸지 않는다")
    func duplicates() {
        var buffer = ReceiveBuffer(initialSequence: Self.start, capacity: 64)
        insert(&buffer, 0..<10)
        // 읽기 전의 중복
        #expect(insert(&buffer, 0..<10) == .init())
        #expect(insert(&buffer, 3..<8) == .init())
        #expect(buffer.read(upTo: 4) == patternBytes(0..<4))
        // 읽은 뒤의 중복(이미 소비한 번호)
        #expect(insert(&buffer, 0..<10) == .init())
        // 어긋난 구간의 중복
        insert(&buffer, 20..<30)
        #expect(insert(&buffer, 20..<30) == .init())
        #expect(insert(&buffer, 22..<25) == .init())
        #expect(buffer.outOfOrderRangeCount == 1)
        #expect(buffer.readableCount == 6)
    }

    // MARK: 구간 32개

    @Test("구간은 32개까지 받고 33번째는 받지 않는다")
    func thirtyTwoRanges() {
        var buffer = ReceiveBuffer(initialSequence: Self.start, capacity: 1000)
        for index in 0..<32 {
            let result = insert(&buffer, (2 * index + 2)..<(2 * index + 3))  // 거리 2, 4, ... 64의 1바이트
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

        // 기존 구간을 늘리는 세그먼트는 구간이 늘지 않으므로 32개에서도 받는다.
        let extend = insert(&buffer, 3..<5)  // 2..<3과 4..<5 사이(3..<4)만 새 바이트이고 둘이 하나(2..<5)가 된다
        #expect(extend.storedCount == 1 && !extend.rejectedForRangeLimit)
        #expect(buffer.outOfOrderRangeCount == 31)
        let again = insert(&buffer, 66..<67)
        #expect(again.storedCount == 1)
        #expect(buffer.outOfOrderRangeCount == 32)
    }

    @Test("구간이 32개여도 RCV.NXT에 닿는 세그먼트는 받는다")
    func inOrderWhenFull() {
        var buffer = ReceiveBuffer(initialSequence: Self.start, capacity: 1000)
        for index in 0..<32 {
            insert(&buffer, (2 * index + 2)..<(2 * index + 3))
        }
        let result = insert(&buffer, 0..<1)
        #expect(result == .init(advancedCount: 1, storedCount: 1, filledGap: true))
        #expect(buffer.readableCount == 1)
        #expect(buffer.outOfOrderRangeCount == 32)  // 구간은 그대로이고 거리만 1 당겨졌다
    }

    @Test("33번째 구간을 만들 세그먼트는 창 안의 일부도 받지 않는다")
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

    @Test("구간 하나를 합치면 자리가 나서 다시 받는다")
    func mergeFreesARangeSlot() {
        var buffer = ReceiveBuffer(initialSequence: Self.start, capacity: 1000)
        for index in 0..<32 {
            insert(&buffer, (2 * index + 2)..<(2 * index + 3))
        }
        // 2..<3 과 4..<5 사이(3..<4)를 메우면 둘이 하나가 된다.
        insert(&buffer, 3..<4)
        #expect(buffer.outOfOrderRangeCount == 31)
        #expect(insert(&buffer, 100..<101).storedCount == 1)
        #expect(buffer.outOfOrderRangeCount == 32)
    }

    // MARK: 창의 양 끝

    @Test("창의 왼쪽으로 걸친 세그먼트는 창 안의 부분만 받는다")
    func leftEdge() {
        var buffer = ReceiveBuffer(initialSequence: Self.start, capacity: 32)
        insert(&buffer, 0..<10)
        #expect(buffer.read(upTo: 10).count == 10)
        // RCV.NXT 앞의 4바이트가 걸친 세그먼트(거리 6..<16)
        let result = insert(&buffer, 6..<16)
        #expect(result == .init(advancedCount: 6, storedCount: 6))
        #expect(buffer.read(upTo: 100) == patternBytes(10..<16))
        // 아주 오래된 번호
        let stale = buffer.insert(ArraySlice(patternBytes(0..<10)), at: Self.start)
        #expect(stale == .init())
    }

    @Test("창의 오른쪽으로 걸친 세그먼트는 창 안의 부분만 받고, 창 밖은 받지 않는다")
    func rightEdge() {
        var buffer = ReceiveBuffer(initialSequence: Self.start, capacity: 16)
        let straddle = insert(&buffer, 10..<20)
        #expect(straddle == .init(advancedCount: 0, storedCount: 6))  // 10..<16
        #expect(buffer.outOfOrderByteCount == 6)
        #expect(insert(&buffer, 16..<20) == .init())  // 창의 오른쪽 끝에서 시작
        #expect(insert(&buffer, 40..<50) == .init())
        insert(&buffer, 0..<10)
        #expect(buffer.readableCount == 16)
        #expect(buffer.read(upTo: 100) == patternBytes(0..<16))
    }

    @Test("한 세그먼트가 양쪽 끝에 걸치면 창 전체만 받는다")
    func bothEdges() {
        var buffer = ReceiveBuffer(initialSequence: Self.start, capacity: 16)
        insert(&buffer, 0..<4)
        #expect(buffer.read(upTo: 4).count == 4)
        let result = insert(&buffer, 0..<100)  // RCV.NXT는 거리 4. 앞 4바이트는 이미 받은 것, 뒤는 16바이트까지
        #expect(result == .init(advancedCount: 16, storedCount: 16))
        #expect(buffer.read(upTo: 100) == patternBytes(4..<20))
    }

    // MARK: 읽기와 자리, 용량

    @Test("읽어 가면 창이 열리고 창의 오른쪽 끝은 줄지 않는다")
    func windowAndRead() {
        var buffer = ReceiveBuffer(initialSequence: Self.start, capacity: 16)
        let edge = buffer.windowEnd
        #expect(edge == Self.start.advanced(by: 16))
        insert(&buffer, 0..<10)
        #expect(buffer.windowSize == 6)
        #expect(buffer.windowEnd == edge)
        insert(&buffer, 12..<16)  // 어긋난 데이터도 창 안이라 오른쪽 끝은 그대로
        #expect(buffer.windowEnd == edge)
        #expect(buffer.read(upTo: 4).count == 4)
        #expect(buffer.windowSize == 10)
        #expect(buffer.windowEnd == edge.advanced(by: 4))  // 읽은 만큼만 오른쪽으로 나아간다
        #expect(buffer.read(upTo: 0).isEmpty)
        #expect(buffer.read(upTo: -3).isEmpty)
        #expect(buffer.windowEnd == edge.advanced(by: 4))
    }

    @Test("용량을 꽉 채우면 창이 0이고 더는 받지 않는다. 읽은 만큼만 다시 받는다")
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

    @Test("저장소를 한 바퀴 돌아도 내용이 맞다")
    func ringWrapsAround() {
        var buffer = ReceiveBuffer(initialSequence: Self.start, capacity: 16)
        var offset = 0
        var output: [UInt8] = []
        for round in 0..<40 {
            let length = 5 + round % 8  // 5...12. 읽고 남는 3바이트가 있어 맨 앞이 저장소의 처음으로 되돌아가지 않는다.
            let accepted = insert(&buffer, offset..<offset + length)
            #expect(accepted.advancedCount == length)
            offset += length
            output += buffer.read(upTo: buffer.readableCount - 3 > 0 ? buffer.readableCount - 3 : 0)
        }
        output += buffer.read(upTo: 100)
        #expect(output == patternBytes(0..<offset))
    }

    @Test("어긋난 구간이 저장소의 끝을 넘어 되감겨도 내용이 맞다")
    func outOfOrderAcrossRingEnd() {
        var buffer = ReceiveBuffer(initialSequence: Self.start, capacity: 16)
        insert(&buffer, 0..<12)
        #expect(buffer.read(upTo: 10) == patternBytes(0..<10))  // 맨 앞이 저장소의 10에 있고 2바이트가 남는다
        insert(&buffer, 14..<20)  // 저장소의 14..<16과 0..<4에 걸쳐 놓인다
        let fill = insert(&buffer, 12..<14)
        #expect(fill.advancedCount == 8)
        #expect(buffer.read(upTo: 100) == patternBytes(10..<20))
    }

    @Test("가끔 쓰는 연결은 저장소가 용량까지 자라지 않는다")
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

    // MARK: 시퀀스 번호가 2³²을 넘는 경우

    @Test("번호가 2³²을 넘어도 맞다: 순서대로, 어긋나게, 걸치게")
    func sequenceWrap() {
        let base = SequenceNumber(0xFFFF_FFF0)
        var buffer = ReceiveBuffer(initialSequence: base, capacity: 64)
        // 어긋난 구간이 0을 넘고, 빈 곳은 0 앞에 있다.
        insert(&buffer, 20..<30, base: base)
        insert(&buffer, 4..<10, base: base)
        #expect(buffer.outOfOrderRangeCount == 2)
        let fill = insert(&buffer, 0..<4, base: base)  // 0xFFFF_FFF0 ..< 0xFFFF_FFF4
        #expect(fill.advancedCount == 10)
        #expect(buffer.nextSequence == SequenceNumber(0xFFFF_FFFA))
        insert(&buffer, 10..<20, base: base)  // 0xFFFF_FFFA을 넘어 0으로 돌아가는 구간
        #expect(buffer.nextSequence == SequenceNumber(0xFFFF_FFF0).advanced(by: 30))
        #expect(buffer.nextSequence.rawValue == 14)
        #expect(buffer.read(upTo: 100) == patternBytes(0..<30))
        // 한 바퀴 돈 뒤의 중복은 이미 받은 것이다.
        #expect(insert(&buffer, 5..<25, base: base) == .init())
        #expect(buffer.windowEnd == SequenceNumber(14).advanced(by: 64))
    }

    // MARK: 메모리(X6)

    @Test("1바이트 세그먼트를 띄엄띄엄 만 개 보내도 구간은 32개, 저장소는 용량 안이다")
    func tinySegmentsStayBounded() {
        var buffer = ReceiveBuffer(initialSequence: Self.start)
        for index in 0..<10_000 {
            let distance = 2 * index + 2  // 겹치지도 맞닿지도 않는 1바이트
            insert(&buffer, distance..<distance + 1)
            #expect(buffer.outOfOrderRangeCount <= ReceiveBuffer.maximumOutOfOrderRanges)
        }
        #expect(buffer.outOfOrderRangeCount == 32)
        #expect(buffer.outOfOrderByteCount == 32)
        #expect(buffer.allocatedByteCount <= ReceiveBuffer.defaultCapacity)
        // 32개째 구간이 놓인 거리까지만 저장소가 자랐다.
        #expect(buffer.allocatedByteCount <= 4096)
    }

    @Test("어긋난 구간이 창 전체에 흩어져도 저장소는 용량을 넘지 않는다")
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
