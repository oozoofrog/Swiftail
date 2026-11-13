// HPACK 정적 표와 허프만 부호표, 허프만 해제의 패딩 규칙(RFC 7541 §5.2).
// 표의 값은 부록 A·B 원문과 Go `hpack`의 표를 대조해 만들었다. 여기서는 구조와 대표 값을 확인한다.

import Testing

@testable import SwiftailHTTP2

@Suite("HPACK 표")
struct HPACKTableTests {
    @Test("정적 표는 61개이고 양 끝과 대표 항목이 원문과 같다")
    func staticTable() {
        let fields = HPACKStaticTable.fields
        #expect(fields.count == 61)
        #expect(fields[0] == HeaderField(":authority", ""))
        #expect(fields[1] == HeaderField(":method", "GET"))
        #expect(fields[7] == HeaderField(":status", "200"))
        #expect(fields[15] == HeaderField("accept-encoding", "gzip, deflate"))
        #expect(fields[60] == HeaderField("www-authenticate", ""))
    }

    @Test("허프만 부호는 257개이고 EOS는 30비트 모두 1이다")
    func huffmanTable() {
        let codes = HPACKHuffmanTable.codes
        #expect(codes.count == 257)
        #expect(codes[Int(UInt8(ascii: "a"))].bits == 0x3 && codes[Int(UInt8(ascii: "a"))].bitCount == 5)
        #expect(codes[Int(UInt8(ascii: "/"))].bits == 0x18 && codes[Int(UInt8(ascii: "/"))].bitCount == 6)  // 원문 부록 B의 예
        #expect(codes[HPACKHuffmanTable.endOfString].bits == 0x3fff_ffff && codes[HPACKHuffmanTable.endOfString].bitCount == 30)
    }

    @Test("부호는 완전한 접두 부호다: 2^-길이의 합이 정확히 1")
    func huffmanIsComplete() {
        let total = HPACKHuffmanTable.codes.reduce(0) { $0 + (1 << (30 - Int($1.bitCount))) }
        #expect(total == 1 << 30)
    }
}

@Suite("HPACK 허프만 해제")
struct HPACKHuffmanTests {
    private func decode(_ bytes: [UInt8]) throws(HPACKError) -> [UInt8] {
        try HPACKHuffman.decode(bytes[...])
    }

    @Test("모든 바이트 값은 부호표로 만든 부호가 왕복한다")
    func everySymbol() throws {
        for symbol in 0..<256 {
            let code = HPACKHuffmanTable.codes[symbol]
            // 부호를 비트열로 펴고 1로 패딩해 바이트로 묶는다.
            var bits = (0..<Int(code.bitCount)).map { code.bits >> UInt32(Int(code.bitCount) - 1 - $0) & 1 }
            while bits.count % 8 != 0 { bits.append(1) }
            let bytes = stride(from: 0, to: bits.count, by: 8).map { start in
                bits[start..<start + 8].reduce(UInt8(0)) { $0 << 1 | UInt8($1) }
            }
            #expect(try decode(bytes) == [UInt8(symbol)])
        }
    }

    @Test("패딩은 1로만, 7비트 이하")
    func padding() throws {
        #expect(try decode([0x1f]) == Array("a".utf8))  // 00011 + 패딩 111
        #expect(throws: HPACKError.invalidHuffman) { try decode([0x18]) }  // 패딩 000
        #expect(throws: HPACKError.invalidHuffman) { try decode([0x1e]) }  // 패딩 110
        #expect(throws: HPACKError.invalidHuffman) { try decode([0x1f, 0xff]) }  // 패딩 11비트
    }

    @Test("EOS가 문자열에 들어 있으면 오류")
    func endOfString() {
        #expect(throws: HPACKError.invalidHuffman) { try decode([0xff, 0xff, 0xff, 0xfc]) }
        #expect(throws: HPACKError.invalidHuffman) { try decode([0xff, 0xff, 0xff, 0xff]) }
    }

    @Test("빈 문자열")
    func empty() throws {
        #expect(try decode([]) == [])
    }
}
