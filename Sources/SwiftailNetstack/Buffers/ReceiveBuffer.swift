/// 연결 하나의 받는 버퍼(계약 `docs/contracts/SwiftailNetstack.md` 동작 F1·F4, 동작 X6).
///
/// `RCV.NXT`부터 빈 곳 없이 이어진 바이트(읽을 수 있는 것)와, 받는 창 안에서 순서가 어긋나 먼저 도착한 구간을
/// 고정 용량의 원형 저장소 한 덩어리 안에 둔다. 어긋난 데이터도 자기 자리(`RCV.NXT`에서의 거리)에 바로 쓰므로,
/// 세그먼트를 따로 쥐거나 나중에 옮겨 적지 않는다. 그래서 1바이트짜리 세그먼트를 띄엄띄엄 보내도 쥐는 메모리는
/// 용량(256KiB)과 구간 표(32개)가 전부다.
///
/// 받는 창은 `RCV.NXT`에서 `windowSize`바이트다. 읽지 않은 바이트가 자리를 차지하고 순서가 어긋난 바이트는 창 안에
/// 놓이므로, 창의 오른쪽 끝(`windowEnd`)은 데이터가 들어오는 것만으로는 움직이지 않고 앱이 읽을 때만 오른쪽으로
/// 나아간다. 오른쪽 끝을 왼쪽으로 옮기지 않는다는 SHLD-14(RFC 9293 3.8.6)는 이 성질에서 나온다.
///
/// FIN은 시퀀스 번호를 하나 쓰지만 데이터가 아니다. 이 버퍼의 `nextSequence`는 **데이터**의 끝이고, FIN을 소비한 뒤의
/// `RCV.NXT`(= `nextSequence + 1`)는 연결이 쥔다.
package struct ReceiveBuffer: Sendable {
    /// 계약 동작 F1: 연결마다 256KiB.
    package static let defaultCapacity = 256 * 1024
    /// 계약 동작 F4: 순서가 어긋난 구간은 32개까지.
    package static let maximumOutOfOrderRanges = 32

    /// `RCV.NXT`에서의 거리로 나타낸 순서가 어긋난 구간 `[start, end)`.
    /// 목록은 `start`순이고 서로 겹치지도 맞닿지도 않으며 `start >= 1`이다(`RCV.NXT`에 닿으면 읽을 수 있는 바이트가 된다).
    private struct Extent: Sendable {
        var start: Int
        var end: Int
    }

    /// 한 번의 `insert`가 한 일. 연결이 ACK를 언제 낼지 정하는 데 쓴다(계약 동작 F5).
    package struct Insertion: Sendable, Equatable {
        /// `RCV.NXT`가 나아간 양. 순서대로 온 데이터이거나 빈 곳을 메운 데이터면 0보다 크다.
        package var advancedCount = 0
        /// 이번에 새로 저장한 바이트 수. 이미 있던 바이트와 겹친 부분, 창 밖으로 잘려 나간 부분은 세지 않는다.
        package var storedCount = 0
        /// 순서가 어긋난 구간이 있는 채로 `RCV.NXT`가 나아갔다. 빈 곳의 전부나 일부를 메운 것이라 곧바로 ACK해야 한다(RFC 5681 4.2).
        package var filledGap = false
        /// 새 구간을 만들어야 하는데 이미 32개라서 세그먼트 전체를 받지 않았다. 상대가 다시 보낸다.
        package var rejectedForRangeLimit = false

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

    /// `RCV.NXT`(FIN을 빼고 센 데이터의 끝). 이 번호 앞까지는 빈 곳 없이 받았다.
    package private(set) var nextSequence: SequenceNumber
    /// 앱이 읽어 갈 수 있는 바이트 수.
    package private(set) var readableCount = 0

    /// `nextSequence`(`RCV.NXT`)가 `initialSequence`이고 용량이 `capacity`인 빈 버퍼.
    /// `initialSequence`는 상대의 첫 데이터 바이트 번호(`IRS + 1`)다. 용량은 2³⁰ 이하여야 시퀀스 번호의 앞뒤 판정이 맞다.
    package init(initialSequence: SequenceNumber, capacity: Int = ReceiveBuffer.defaultCapacity) {
        precondition(capacity <= 1 << 30, "용량이 시퀀스 번호의 비교 범위를 넘는다")
        ring = ByteRing(capacity: capacity)
        nextSequence = initialSequence
        extents.reserveCapacity(Self.maximumOutOfOrderRanges)
    }

    package var capacity: Int { ring.capacity }

    /// 광고할 수 있는 창의 최대치: `RCV.NXT`에서 버퍼의 남은 자리까지. 연결은 여기서 SWS 회피와 창 확장의 내림을 적용해 광고한다.
    package var windowSize: Int { capacity - readableCount }

    /// 창의 오른쪽 끝(`RCV.NXT + windowSize`). 앱이 읽을 때만 나아가고 줄지 않는다.
    package var windowEnd: SequenceNumber { nextSequence.advanced(by: UInt32(windowSize)) }

    /// 순서가 어긋난 구간의 수. 0 ... 32.
    package var outOfOrderRangeCount: Int { extents.count }

    /// 순서가 어긋난 채로 저장된 바이트의 합.
    package var outOfOrderByteCount: Int { extents.reduce(0) { $0 + ($1.end - $1.start) } }

    /// 저장소로 실제 잡힌 바이트 수(시험·측정용). 용량을 넘지 않는다.
    package var allocatedByteCount: Int { ring.allocatedByteCount }

    /// 상대가 보낸 데이터 `bytes`(첫 바이트의 번호가 `sequence`)를 받는 창 안의 부분만 받는다.
    ///
    /// - 창의 왼쪽(이미 받은 쪽)이나 오른쪽(`windowEnd` 너머)으로 걸친 부분은 버리고 창 안의 부분만 둔다.
    /// - 이미 있는 바이트(읽을 수 있는 것, 순서가 어긋난 채 있는 것)와 겹치면 먼저 받은 것을 그대로 둔다.
    /// - 새 구간이 필요한데 32개를 넘으면 세그먼트 전체를 받지 않는다(`rejectedForRangeLimit`).
    /// - 빈 곳이 메워지면 `RCV.NXT`가 이어진 끝까지 나아간다.
    ///
    /// 시퀀스 검사(RST·ACK로 답할지)는 연결이 한다. 이 함수는 창 안의 바이트만 다룬다.
    package mutating func insert(_ bytes: ArraySlice<UInt8>, at sequence: SequenceNumber) -> Insertion {
        // 창 안의 구간 [lower, upper)를 `RCV.NXT`에서의 거리로 구한다.
        let start = Int(sequence.distance(from: nextSequence))
        let skipped = max(0, -start)
        let lower = max(0, start)
        guard skipped < bytes.count, lower < windowSize else { return Insertion() }
        let upper = lower + min(bytes.count - skipped, windowSize - lower)
        let payload = bytes[bytes.startIndex + skipped..<bytes.startIndex + skipped + (upper - lower)]

        // 새 구간과 겹치거나 맞닿는 기존 구간은 first..<last다.
        let first = extents.firstIndex { $0.end >= lower } ?? extents.count
        let last = extents[first...].firstIndex { $0.start > upper } ?? extents.count
        if first == last, lower > 0, extents.count >= Self.maximumOutOfOrderRanges {
            return Insertion(rejectedForRangeLimit: true)
        }

        // 기존 구간이 덮지 않은 틈만 쓴다(겹치는 바이트는 먼저 받은 것이 이긴다).
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

        // 겹친 구간을 하나로 합친다.
        let merged = Extent(
            start: first < last ? min(lower, extents[first].start) : lower,
            end: first < last ? max(upper, extents[last - 1].end) : upper
        )
        let hadOutOfOrderData = !extents.isEmpty
        extents.replaceSubrange(first..<last, with: [merged])

        // `RCV.NXT`에 닿은 구간은 읽을 수 있는 바이트가 되고 나머지 구간은 그만큼 앞으로 당겨진다.
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

    /// 읽을 수 있는 바이트를 앞에서부터 `maximumLength`바이트까지 꺼낸다. 꺼낸 만큼 창이 열린다.
    ///
    /// shortcut: 호출마다 새 배열 하나에 복사한다(`SendBuffer.bytes`와 같은 까닭).
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

    /// `payload`(거리 `payloadBase`부터)의 `[from, to)` 거리 구간을 저장소의 제자리에 쓰고 쓴 바이트 수를 돌려준다.
    private mutating func write(
        _ payload: ArraySlice<UInt8>, from: Int, to: Int, payloadBase: Int
    ) -> Int {
        let begin = payload.startIndex + (from - payloadBase)
        ring.write(payload[begin..<begin + (to - from)], at: readableCount + from)
        return to - from
    }
}
