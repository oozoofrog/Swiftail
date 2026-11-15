import Testing

@testable import SwiftailTKA

/// 계약 7절 시험 1: 정준 쓰기(동작 E1, E4의 기준 바이트).
@Suite("CBOR 쓰기")
struct CBORWriterTests {
    @Test(
        "정수는 가장 짧은 머리로 쓴다",
        arguments: [
            (UInt64(0), "00"), (23, "17"), (24, "1818"), (255, "18ff"), (256, "190100"), (65_535, "19ffff"),
            (65_536, "1a00010000"), (4_294_967_295, "1affffffff"), (4_294_967_296, "1b0000000100000000"),
            (UInt64.max, "1bffffffffffffffff"),
        ] as [(UInt64, String)]
    )
    func shortestUnsigned(value: UInt64, expected: String) {
        var writer = CBORWriter()
        writer.unsigned(value)
        #expect(CBORTesting.hex(writer.bytes) == expected)
    }

    @Test(
        "길이도 가장 짧은 머리로 쓴다(bstr·tstr·배열·맵)",
        arguments: [(0, "00"), (23, "17"), (24, "1818"), (255, "18ff"), (256, "190100"), (65_535, "19ffff"), (65_536, "1a00010000")]
    )
    func shortestLengths(count: Int, argument: String) throws {
        // 머리 바이트의 주 타입 비트만 다르고 인자의 꼴은 정수와 같다.
        let first = try #require(UInt8(argument.prefix(2), radix: 16))
        func expected(_ major: UInt8) -> String {
            CBORTesting.hex([major << 5 | first]) + argument.dropFirst(2)
        }
        var bytes = CBORWriter()
        bytes.byteString([UInt8](repeating: 0xab, count: count))
        #expect(CBORTesting.hex(Array(bytes.bytes.prefix(argument.count / 2))) == expected(2))
        #expect(bytes.bytes.count == argument.count / 2 + count)

        var text = CBORWriter()
        text.textString(utf8: [UInt8](repeating: 0x61, count: count))
        #expect(CBORTesting.hex(Array(text.bytes.prefix(argument.count / 2))) == expected(3))
        #expect(text.bytes.count == argument.count / 2 + count)

        var array = CBORWriter()
        array.arrayHeader(count: count)
        #expect(CBORTesting.hex(array.bytes) == expected(4))

        var map = CBORWriter()
        map.mapHeader(count: count)
        #expect(CBORTesting.hex(map.bytes) == expected(5))
    }

    @Test("4바이트를 넘는 배열·맵 머리는 8바이트 인자다")
    func largeHeaders() {
        var writer = CBORWriter()
        writer.arrayHeader(count: 1 << 32)
        writer.mapHeader(count: 0xffff_ffff)
        #expect(CBORTesting.hex(writer.bytes) == "9b0000000100000000" + "baffffffff")
    }

    @Test("null은 f6이다")
    func null() {
        var writer = CBORWriter()
        writer.null()
        #expect(writer.bytes == [0xf6])
    }

    /// 동작 E4의 기준 바이트(노트 8.1의 Go 실행). 구조의 필드를 정해진 순서로 쓰면 이 바이트가 나와야 한다.
    @Test("동작 E4의 기준 바이트")
    func referenceBytes() {
        // UpdateKey{KeyID:[1], Votes:&0, Meta:{}}: 빈 Meta는 빠지고 0인 Votes는 남는다.
        var updateKey = CBORWriter()
        updateKey.mapHeader(count: 4)
        updateKey.unsigned(1)
        updateKey.unsigned(4)
        updateKey.unsigned(2)
        updateKey.null()
        updateKey.unsigned(4)
        updateKey.byteString([1])
        updateKey.unsigned(6)
        updateKey.unsigned(0)
        #expect(CBORTesting.hex(updateKey.bytes) == "a4010402f60441010600")

        // NoOp{PrevAUMHash: []byte{}}: 길이 0인 bstr은 null이 아니다.
        var noOp = CBORWriter()
        noOp.mapHeader(count: 2)
        noOp.unsigned(1)
        noOp.unsigned(3)
        noOp.unsigned(2)
        noOp.byteString([])
        #expect(CBORTesting.hex(noOp.bytes) == "a201030240")

        // State의 StateID1=2^40 쌍.
        var stateID = CBORWriter()
        stateID.unsigned(4)
        stateID.unsigned(1 << 40)
        #expect(CBORTesting.hex(stateID.bytes) == "041b0000010000000000")
    }

    @Test("텍스트는 받은 바이트를 그대로 쓴다")
    func textBytesVerbatim() {
        // U+00E9를 한 글자(c3a9)로 쓴 것과 e + U+0301(65cc81)로 쓴 것은 String으로는 같지만 바이트가 다르다(동작 E3).
        var composed = CBORWriter()
        composed.textString(utf8: [0xc3, 0xa9])
        var decomposed = CBORWriter()
        decomposed.textString(utf8: [0x65, 0xcc, 0x81])
        #expect(CBORTesting.hex(composed.bytes) == "62c3a9")
        #expect(CBORTesting.hex(decomposed.bytes) == "6365cc81")
    }
}
