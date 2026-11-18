import Testing

@testable import SwiftailTKA

/// Contract §7 test 1: canonical writing (reference bytes for behaviors E1 and E4).
@Suite("CBOR writing")
struct CBORWriterTests {
    @Test(
        "Writes integers with the shortest header",
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
        "Also writes lengths with the shortest header (bstr, tstr, arrays, and maps)",
        arguments: [(0, "00"), (23, "17"), (24, "1818"), (255, "18ff"), (256, "190100"), (65_535, "19ffff"), (65_536, "1a00010000")]
    )
    func shortestLengths(count: Int, argument: String) throws {
        // Only the major type bits of the header byte differ. The argument has the same form as for integers.
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

    @Test("Array and map headers for lengths beyond 4 bytes use 8-byte arguments")
    func largeHeaders() {
        var writer = CBORWriter()
        writer.arrayHeader(count: 1 << 32)
        writer.mapHeader(count: 0xffff_ffff)
        #expect(CBORTesting.hex(writer.bytes) == "9b0000000100000000" + "baffffffff")
    }

    @Test("null is f6")
    func null() {
        var writer = CBORWriter()
        writer.null()
        #expect(writer.bytes == [0xf6])
    }

    /// Reference bytes for behavior E4 (Go run in note §8.1). Writing the structure fields in the prescribed order must yield these bytes.
    @Test("Reference bytes for behavior E4")
    func referenceBytes() {
        // UpdateKey{KeyID:[1], Votes:&0, Meta:{}}: omits empty Meta and retains Votes of 0.
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

        // NoOp{PrevAUMHash: []byte{}}: a zero-length bstr is distinct from null.
        var noOp = CBORWriter()
        noOp.mapHeader(count: 2)
        noOp.unsigned(1)
        noOp.unsigned(3)
        noOp.unsigned(2)
        noOp.byteString([])
        #expect(CBORTesting.hex(noOp.bytes) == "a201030240")

        // The State pair for StateID1=2^40.
        var stateID = CBORWriter()
        stateID.unsigned(4)
        stateID.unsigned(1 << 40)
        #expect(CBORTesting.hex(stateID.bytes) == "041b0000010000000000")
    }

    @Test("Writes text bytes as received")
    func textBytesVerbatim() {
        // U+00E9 as one character (c3a9) and e + U+0301 (65cc81) are equal as String values and differ in bytes (behavior E3).
        var composed = CBORWriter()
        composed.textString(utf8: [0xc3, 0xa9])
        var decomposed = CBORWriter()
        decomposed.textString(utf8: [0x65, 0xcc, 0x81])
        #expect(CBORTesting.hex(composed.bytes) == "62c3a9")
        #expect(CBORTesting.hex(decomposed.bytes) == "6365cc81")
    }
}
