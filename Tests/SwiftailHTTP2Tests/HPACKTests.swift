// Contract test 1: HPACK. Uses the examples from RFC 7541 Appendix C verbatim in base-16.
// Origin: https://www.rfc-editor.org/rfc/rfc7541#appendix-C

import Testing

@testable import SwiftailHTTP2

@Suite("HPACK integers (RFC 7541 C.1)")
struct HPACKIntegerTests {
    private func decode(_ bytes: [UInt8], prefixBits: Int) throws(HPACKError) -> Int {
        var reader = ByteReader(bytes)
        return try reader.hpackInteger(prefixBits: prefixBits)
    }

    private func encode(_ value: Int, prefixBits: Int, flags: UInt8 = 0) -> [UInt8] {
        var output: [UInt8] = []
        HPACKEncoding.appendInteger(value, prefixBits: prefixBits, flags: flags, to: &output)
        return output
    }

    @Test("C.1.1: 10 with a 5-bit prefix")
    func tenInFiveBits() throws {
        #expect(encode(10, prefixBits: 5) == [0x0a])
        // The top 3 bits indicate the representation and have no effect on the value.
        #expect(try decode([0b1110_1010], prefixBits: 5) == 10)
    }

    @Test("C.1.2: 1337 with a 5-bit prefix")
    func fiveBitsLarge() throws {
        #expect(encode(1337, prefixBits: 5) == [0x1f, 0x9a, 0x0a])
        #expect(try decode([0x1f, 0x9a, 0x0a], prefixBits: 5) == 1337)
    }

    @Test("C.1.3: 42 starting at an octet boundary")
    func fortyTwoInEightBits() throws {
        #expect(encode(42, prefixBits: 8) == [0x2a])
        #expect(try decode([0x2a], prefixBits: 8) == 42)
    }

    @Test("Maximum prefix value boundary and representation bits")
    func boundary() throws {
        #expect(encode(31, prefixBits: 5, flags: 0x20) == [0x3f, 0x00])
        #expect(try decode([0x1f, 0x00], prefixBits: 5) == 31)
        #expect(encode(30, prefixBits: 5, flags: 0x20) == [0x3e])
    }

    @Test("All values round-trip")
    func roundTrip() throws {
        for value in [0, 1, 126, 127, 128, 254, 255, 256, 16_383, 16_384, 65_535, 1 << 20, 1 << 28] {
            for prefixBits in 1...8 {
                #expect(try decode(encode(value, prefixBits: prefixBits), prefixBits: prefixBits) == value)
            }
        }
    }

    @Test("Truncated and overflowing integers")
    func malformed() {
        #expect(throws: HPACKError.truncated) { try decode([], prefixBits: 5) }
        #expect(throws: HPACKError.truncated) { try decode([0x1f, 0x80], prefixBits: 5) }
        // Reject integers with endlessly set continuation bits without overflowing.
        #expect(throws: HPACKError.integerOverflow) { try decode([0x1f] + [UInt8](repeating: 0xff, count: 20), prefixBits: 5) }
    }
}

@Suite("HPACK header representations (RFC 7541 C.2)")
struct HPACKRepresentationTests {
    @Test("C.2.1: Literal with indexing and a new name")
    func literalWithIndexing() throws {
        var decoder = HPACKDecoder()
        let block = hex("400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572")
        #expect(try decoder.decode(block) == [HeaderField("custom-key", "custom-header")])
        // The entry went into dynamic table index 62.
        #expect(try decoder.decode([0xbe]) == [HeaderField("custom-key", "custom-header")])
    }

    @Test("C.2.2: Literal without indexing and with an indexed name")
    func literalWithoutIndexing() throws {
        var decoder = HPACKDecoder()
        #expect(try decoder.decode(hex("040c 2f73 616d 706c 652f 7061 7468")) == [HeaderField(":path", "/sample/path")])
        // The table is empty.
        #expect(throws: HPACKError.invalidIndex) { try decoder.decode([0xbe]) }
    }

    @Test("C.2.3: Never-indexed literal")
    func literalNeverIndexed() throws {
        var decoder = HPACKDecoder()
        #expect(try decoder.decode(hex("1008 7061 7373 776f 7264 0673 6563 7265 74")) == [HeaderField("password", "secret")])
        #expect(throws: HPACKError.invalidIndex) { try decoder.decode([0xbe]) }
    }

    @Test("C.2.4: Indexed field")
    func indexed() throws {
        var decoder = HPACKDecoder()
        #expect(try decoder.decode(hex("82")) == [HeaderField(":method", "GET")])
    }
}

/// Three requests share the dynamic table of one connection. The examples without Huffman coding (C.3) and with it (C.4) yield the same list.
@Suite("HPACK requests (RFC 7541 C.3, C.4)")
struct HPACKRequestTests {
    private let first = [
        HeaderField(":method", "GET"), HeaderField(":scheme", "http"), HeaderField(":path", "/"),
        HeaderField(":authority", "www.example.com"),
    ]
    private let second = [
        HeaderField(":method", "GET"), HeaderField(":scheme", "http"), HeaderField(":path", "/"),
        HeaderField(":authority", "www.example.com"), HeaderField("cache-control", "no-cache"),
    ]
    private let third = [
        HeaderField(":method", "GET"), HeaderField(":scheme", "https"), HeaderField(":path", "/index.html"),
        HeaderField(":authority", "www.example.com"), HeaderField("custom-key", "custom-value"),
    ]

    @Test("C.3: Without Huffman coding")
    func withoutHuffman() throws {
        var decoder = HPACKDecoder()
        #expect(try decoder.decode(hex("8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d")) == first)
        #expect(try decoder.decode(hex("8286 84be 5808 6e6f 2d63 6163 6865")) == second)
        #expect(try decoder.decode(hex("8287 85bf 400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65")) == third)
    }

    @Test("C.4: With Huffman coding")
    func withHuffman() throws {
        var decoder = HPACKDecoder()
        #expect(try decoder.decode(hex("8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff")) == first)
        #expect(try decoder.decode(hex("8286 84be 5886 a8eb 1064 9cbf")) == second)
        #expect(try decoder.decode(hex("8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf")) == third)
    }
}

/// The connection advertised SETTINGS_HEADER_TABLE_SIZE of 256. The dynamic table fills up and evicts entries.
@Suite("HPACK responses and table eviction (RFC 7541 C.5, C.6)")
struct HPACKResponseTests {
    private let first = [
        HeaderField(":status", "302"), HeaderField("cache-control", "private"),
        HeaderField("date", "Mon, 21 Oct 2013 20:13:21 GMT"), HeaderField("location", "https://www.example.com"),
    ]
    private let second = [
        HeaderField(":status", "307"), HeaderField("cache-control", "private"),
        HeaderField("date", "Mon, 21 Oct 2013 20:13:21 GMT"), HeaderField("location", "https://www.example.com"),
    ]
    private let third = [
        HeaderField(":status", "200"), HeaderField("cache-control", "private"),
        HeaderField("date", "Mon, 21 Oct 2013 20:13:22 GMT"), HeaderField("location", "https://www.example.com"),
        HeaderField("content-encoding", "gzip"),
        HeaderField("set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"),
    ]

    @Test("C.5: Without Huffman coding")
    func withoutHuffman() throws {
        var decoder = HPACKDecoder(tableSizeLimit: 256)
        #expect(try decoder.decode(hex("""
            4803 3330 3258 0770 7269 7661 7465 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133
            2032 303a 3133 3a32 3120 474d 546e 1768 7474 7073 3a2f 2f77 7777 2e65 7861 6d70
            6c65 2e63 6f6d
            """)) == first)
        #expect(try decoder.decode(hex("4803 3330 37c1 c0bf")) == second)
        #expect(try decoder.decode(hex("""
            88c1 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 2032 303a 3133 3a32 3220 474d
            54c0 5a04 677a 6970 7738 666f 6f3d 4153 444a 4b48 514b 425a 584f 5157 454f 5049
            5541 5851 5745 4f49 553b 206d 6178 2d61 6765 3d33 3630 303b 2076 6572 7369 6f6e
            3d31
            """)) == third)
    }

    @Test("C.6: With Huffman coding")
    func withHuffman() throws {
        var decoder = HPACKDecoder(tableSizeLimit: 256)
        #expect(try decoder.decode(hex("""
            4882 6402 5885 aec3 771a 4b61 96d0 7abe 9410 54d4 44a8 2005 9504 0b81 66e0 82a6
            2d1b ff6e 919d 29ad 1718 63c7 8f0b 97c8 e9ae 82ae 43d3
            """)) == first)
        #expect(try decoder.decode(hex("4883 640e ffc1 c0bf")) == second)
        #expect(try decoder.decode(hex("""
            88c1 6196 d07a be94 1054 d444 a820 0595 040b 8166 e084 a62d 1bff c05a 839b d9ab
            77ad 94e7 821d d7f2 e6c7 b335 dfdf cd5b 3960 d5af 2708 7f36 72c1 ab27 0fb5 291f
            9587 3160 65c0 03ed 4ee5 b106 3d50 07
            """)) == third)
    }
}

@Suite("HPACK decoder rules")
struct HPACKDecoderRuleTests {
    @Test("Index 0 and out-of-table indexes")
    func invalidIndex() {
        var decoder = HPACKDecoder()
        #expect(throws: HPACKError.invalidIndex) { try decoder.decode([0x80]) }
        #expect(throws: HPACKError.invalidIndex) { try decoder.decode([0xbe]) }
        // The end of the static table (61) is valid and 62 belongs to the dynamic table.
        #expect((try? decoder.decode([0xbd])) == [HeaderField("www-authenticate", "")])
    }

    @Test("Dynamic table size updates are allowed only at the start of a block and within the advertised limit")
    func tableSizeUpdate() throws {
        var decoder = HPACKDecoder(tableSizeLimit: 256)
        #expect(try decoder.decode([0x3f, 0xe1, 0x01]) == [])  // 0x20 | 31, 31 + 225 = 256
        #expect(throws: HPACKError.invalidTableSizeUpdate) { try decoder.decode([0x3f, 0xe2, 0x01]) }  // 257
        #expect(throws: HPACKError.invalidTableSizeUpdate) { try decoder.decode([0x82, 0x20]) }
        #expect(try decoder.decode([0x20, 0x82]) == [HeaderField(":method", "GET")])
    }

    @Test("Reducing the size to 0 empties the table, and an entry larger than the table only empties it")
    func eviction() throws {
        var decoder = HPACKDecoder()
        _ = try decoder.decode(hex("400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572"))
        #expect(try decoder.decode([0xbe]) == [HeaderField("custom-key", "custom-header")])
        _ = try decoder.decode([0x20])
        #expect(throws: HPACKError.invalidIndex) { try decoder.decode([0xbe]) }

        var small = HPACKDecoder(tableSizeLimit: 40)
        _ = try small.decode(hex("400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572"))  // 55 bytes > 40
        #expect(throws: HPACKError.invalidIndex) { try small.decode([0xbe]) }
    }

    @Test("A string truncated at the end of a block is an error")
    func truncatedString() {
        var decoder = HPACKDecoder()
        #expect(throws: HPACKError.truncated) { try decoder.decode(hex("4005 6162")) }
    }

    @Test("Non-UTF-8 string")
    func invalidUTF8() {
        var decoder = HPACKDecoder()
        #expect(throws: HPACKError.invalidUTF8) { try decoder.decode(hex("4001 61 01 ff")) }
    }

    @Test("Exceeding the decoded size limit is an error")
    func headerListLimit() throws {
        var decoder = HPACKDecoder(headerListSizeLimit: 100)
        // One entry is 73 bytes = 1 name byte + 40 value bytes.
        var block: [UInt8] = [0x40, 0x01, 0x61, 40] + [UInt8](repeating: 0x62, count: 40)
        #expect(try decoder.decode(block).count == 1)
        block += [0xbe]  // Refer to the same entry again. 146 > 100.
        #expect(throws: HPACKError.headerListTooLarge) { try decoder.decode(block) }
    }
}

@Suite("HPACK encoder")
struct HPACKEncoderTests {
    @Test("Literal without indexing, with a new name and no Huffman coding")
    func literalEncoding() {
        #expect(HPACKEncoder.encode([HeaderField(":path", "/sample/path")]) == hex("00 05 3a70617468 0c 2f73616d706c652f70617468"))
    }

    @Test("The decoder recovers the original list, including strings at least 127 bytes long.")
    func roundTrip() throws {
        let fields = [
            HeaderField(":method", "POST"), HeaderField("content-type", "application/json"),
            HeaderField("x-long", String(repeating: "v", count: 300)), HeaderField("x-empty", ""),
            HeaderField("x-utf8", "값"),
        ]
        var decoder = HPACKDecoder()
        #expect(try decoder.decode(HPACKEncoder.encode(fields)) == fields)
    }
}
