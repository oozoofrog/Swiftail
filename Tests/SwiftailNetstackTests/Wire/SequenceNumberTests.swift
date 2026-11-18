import Testing

@testable import SwiftailNetstack

/// Sequence number wraparound arithmetic (RFC 9293 3.4). Underlies contract `docs/contracts/SwiftailNetstack.md` test 6 (transfers over 4GiB).
@Suite("TCP sequence numbers")
struct SequenceNumberTests {
    @Test("Addition wraps at 2³²")
    func advancingWraps() {
        #expect(SequenceNumber(0xFFFF_FFFF).advanced(by: 1) == SequenceNumber(0))
        #expect(SequenceNumber(0xFFFF_FFF0).advanced(by: 0x20) == SequenceNumber(0x10))
        #expect(SequenceNumber(7).advanced(by: 0) == SequenceNumber(7))
    }

    @Test("The sign of the difference determines order, and a wrapped number comes later")
    func orderingAcrossWrap() {
        let beforeWrap = SequenceNumber(0xFFFF_FF00)
        let afterWrap = SequenceNumber(0x0000_0100)
        #expect(beforeWrap.precedes(afterWrap))
        #expect(!afterWrap.precedes(beforeWrap))
        #expect(afterWrap.distance(from: beforeWrap) == 0x200)
        #expect(beforeWrap.distance(from: afterWrap) == -0x200)
    }

    @Test("An equal number is not before, but is at or before")
    func equality() {
        let number = SequenceNumber(42)
        #expect(!number.precedes(number))
        #expect(number.precedesOrEquals(number))
        #expect(number.distance(from: number) == 0)
    }

    @Test("Distance boundary: up to 2³¹ − 1 is read as after, and 2³¹ is read as before")
    func halfSpaceBoundary() {
        let origin = SequenceNumber(1000)
        #expect(origin.precedes(origin.advanced(by: 0x7FFF_FFFF)))
        // The order of two numbers 2³¹ apart is undefined. Windows are below 2³⁰, so this distance does not occur.
        #expect(origin.advanced(by: 0x8000_0000).distance(from: origin) == Int32.min)
    }
}
