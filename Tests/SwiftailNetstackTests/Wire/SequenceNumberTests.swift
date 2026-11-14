import Testing

@testable import SwiftailNetstack

/// 시퀀스 번호의 순환 산술(RFC 9293 3.4). 계약 `docs/contracts/SwiftailNetstack.md` 시험 6(4GiB를 넘는 전송)의 바탕이다.
@Suite("TCP 시퀀스 번호")
struct SequenceNumberTests {
    @Test("더하기는 2³²에서 돈다")
    func advancingWraps() {
        #expect(SequenceNumber(0xFFFF_FFFF).advanced(by: 1) == SequenceNumber(0))
        #expect(SequenceNumber(0xFFFF_FFF0).advanced(by: 0x20) == SequenceNumber(0x10))
        #expect(SequenceNumber(7).advanced(by: 0) == SequenceNumber(7))
    }

    @Test("앞뒤는 차이의 부호로 정하고, 한 바퀴 돈 번호가 뒤다")
    func orderingAcrossWrap() {
        let beforeWrap = SequenceNumber(0xFFFF_FF00)
        let afterWrap = SequenceNumber(0x0000_0100)
        #expect(beforeWrap.precedes(afterWrap))
        #expect(!afterWrap.precedes(beforeWrap))
        #expect(afterWrap.distance(from: beforeWrap) == 0x200)
        #expect(beforeWrap.distance(from: afterWrap) == -0x200)
    }

    @Test("같은 번호는 앞이 아니고, 같거나 앞이다")
    func equality() {
        let number = SequenceNumber(42)
        #expect(!number.precedes(number))
        #expect(number.precedesOrEquals(number))
        #expect(number.distance(from: number) == 0)
    }

    @Test("거리의 경계: 2³¹ − 1까지는 뒤, 2³¹은 앞으로 읽힌다")
    func halfSpaceBoundary() {
        let origin = SequenceNumber(1000)
        #expect(origin.precedes(origin.advanced(by: 0x7FFF_FFFF)))
        // 2³¹ 떨어진 두 번호의 앞뒤는 정해지지 않는다. 창이 2³⁰ 미만이라 이 거리는 생기지 않는다.
        #expect(origin.advanced(by: 0x8000_0000).distance(from: origin) == Int32.min)
    }
}
