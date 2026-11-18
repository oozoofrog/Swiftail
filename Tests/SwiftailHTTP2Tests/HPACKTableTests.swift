// HPACK static and Huffman code tables, and padding rules for Huffman decoding (RFC 7541 §5.2).
// The table values come from comparing Appendices A and B with the Go `hpack` tables. Check the structure and representative values here.

import Testing

@testable import SwiftailHTTP2

@Suite("HPACK tables")
struct HPACKTableTests {
    @Test("The static table has 61 entries and matches the original at both ends and for representative entries")
    func staticTable() {
        let fields = HPACKStaticTable.fields
        #expect(fields.count == 61)
        #expect(fields[0] == HeaderField(":authority", ""))
        #expect(fields[1] == HeaderField(":method", "GET"))
        #expect(fields[7] == HeaderField(":status", "200"))
        #expect(fields[15] == HeaderField("accept-encoding", "gzip, deflate"))
        #expect(fields[60] == HeaderField("www-authenticate", ""))
    }

    @Test("There are 257 Huffman codes and all 30 EOS bits are 1")
    func huffmanTable() {
        let codes = HPACKHuffmanTable.codes
        #expect(codes.count == 257)
        #expect(codes[Int(UInt8(ascii: "a"))].bits == 0x3 && codes[Int(UInt8(ascii: "a"))].bitCount == 5)
        #expect(codes[Int(UInt8(ascii: "/"))].bits == 0x18 && codes[Int(UInt8(ascii: "/"))].bitCount == 6)  // Example from Appendix B of the original
        #expect(codes[HPACKHuffmanTable.endOfString].bits == 0x3fff_ffff && codes[HPACKHuffmanTable.endOfString].bitCount == 30)
    }

    @Test("The codes form a complete prefix code. The sum of 2^-length is exactly 1.")
    func huffmanIsComplete() {
        let total = HPACKHuffmanTable.codes.reduce(0) { $0 + (1 << (30 - Int($1.bitCount))) }
        #expect(total == 1 << 30)
    }
}

@Suite("HPACK Huffman decoding")
struct HPACKHuffmanTests {
    private func decode(_ bytes: [UInt8]) throws(HPACKError) -> [UInt8] {
        try HPACKHuffman.decode(bytes[...])
    }

    @Test("The code generated from the table round-trips for every byte value")
    func everySymbol() throws {
        for symbol in 0..<256 {
            let code = HPACKHuffmanTable.codes[symbol]
            // Expand the code into bits and pad with 1s to form bytes.
            var bits = (0..<Int(code.bitCount)).map { code.bits >> UInt32(Int(code.bitCount) - 1 - $0) & 1 }
            while bits.count % 8 != 0 { bits.append(1) }
            let bytes = stride(from: 0, to: bits.count, by: 8).map { start in
                bits[start..<start + 8].reduce(UInt8(0)) { $0 << 1 | UInt8($1) }
            }
            #expect(try decode(bytes) == [UInt8(symbol)])
        }
    }

    @Test("Padding uses only 1s and is at most 7 bits")
    func padding() throws {
        #expect(try decode([0x1f]) == Array("a".utf8))  // 00011 + padding 111
        #expect(throws: HPACKError.invalidHuffman) { try decode([0x18]) }  // Padding 000
        #expect(throws: HPACKError.invalidHuffman) { try decode([0x1e]) }  // Padding 110
        #expect(throws: HPACKError.invalidHuffman) { try decode([0x1f, 0xff]) }  // 11 bits of padding
    }

    @Test("EOS in the string is an error")
    func endOfString() {
        #expect(throws: HPACKError.invalidHuffman) { try decode([0xff, 0xff, 0xff, 0xfc]) }
        #expect(throws: HPACKError.invalidHuffman) { try decode([0xff, 0xff, 0xff, 0xff]) }
    }

    @Test("Empty string")
    func empty() throws {
        #expect(try decode([]) == [])
    }
}
