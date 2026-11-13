// 계약 시험 1: HPACK. RFC 7541 부록 C의 예제를 원문의 16진 값 그대로 쓴다.
// 출처: https://www.rfc-editor.org/rfc/rfc7541#appendix-C

import Testing

@testable import SwiftailHTTP2

@Suite("HPACK 정수 (RFC 7541 C.1)")
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

    @Test("C.1.1: 5비트 prefix에 10")
    func tenInFiveBits() throws {
        #expect(encode(10, prefixBits: 5) == [0x0a])
        // 윗 3비트는 표현 형식이므로 값에 영향이 없다.
        #expect(try decode([0b1110_1010], prefixBits: 5) == 10)
    }

    @Test("C.1.2: 5비트 prefix에 1337")
    func fiveBitsLarge() throws {
        #expect(encode(1337, prefixBits: 5) == [0x1f, 0x9a, 0x0a])
        #expect(try decode([0x1f, 0x9a, 0x0a], prefixBits: 5) == 1337)
    }

    @Test("C.1.3: 옥텟 경계에서 시작하는 42")
    func fortyTwoInEightBits() throws {
        #expect(encode(42, prefixBits: 8) == [0x2a])
        #expect(try decode([0x2a], prefixBits: 8) == 42)
    }

    @Test("prefix 최댓값 경계와 표현 형식 비트")
    func boundary() throws {
        #expect(encode(31, prefixBits: 5, flags: 0x20) == [0x3f, 0x00])
        #expect(try decode([0x1f, 0x00], prefixBits: 5) == 31)
        #expect(encode(30, prefixBits: 5, flags: 0x20) == [0x3e])
    }

    @Test("모든 값은 왕복한다")
    func roundTrip() throws {
        for value in [0, 1, 126, 127, 128, 254, 255, 256, 16_383, 16_384, 65_535, 1 << 20, 1 << 28] {
            for prefixBits in 1...8 {
                #expect(try decode(encode(value, prefixBits: prefixBits), prefixBits: prefixBits) == value)
            }
        }
    }

    @Test("잘린 정수와 넘치는 정수")
    func malformed() {
        #expect(throws: HPACKError.truncated) { try decode([], prefixBits: 5) }
        #expect(throws: HPACKError.truncated) { try decode([0x1f, 0x80], prefixBits: 5) }
        // 이어짐 비트가 끝없이 켜진 정수는 넘침 없이 거절한다.
        #expect(throws: HPACKError.integerOverflow) { try decode([0x1f] + [UInt8](repeating: 0xff, count: 20), prefixBits: 5) }
    }
}

@Suite("HPACK 헤더 표현 (RFC 7541 C.2)")
struct HPACKRepresentationTests {
    @Test("C.2.1: 색인하는 리터럴, 새 이름")
    func literalWithIndexing() throws {
        var decoder = HPACKDecoder()
        let block = hex("400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572")
        #expect(try decoder.decode(block) == [HeaderField("custom-key", "custom-header")])
        // 동적 표 색인 62에 들어갔다.
        #expect(try decoder.decode([0xbe]) == [HeaderField("custom-key", "custom-header")])
    }

    @Test("C.2.2: 색인 없는 리터럴, 색인된 이름")
    func literalWithoutIndexing() throws {
        var decoder = HPACKDecoder()
        #expect(try decoder.decode(hex("040c 2f73 616d 706c 652f 7061 7468")) == [HeaderField(":path", "/sample/path")])
        // 표는 비어 있다.
        #expect(throws: HPACKError.invalidIndex) { try decoder.decode([0xbe]) }
    }

    @Test("C.2.3: 색인되지 않는 리터럴")
    func literalNeverIndexed() throws {
        var decoder = HPACKDecoder()
        #expect(try decoder.decode(hex("1008 7061 7373 776f 7264 0673 6563 7265 74")) == [HeaderField("password", "secret")])
        #expect(throws: HPACKError.invalidIndex) { try decoder.decode([0xbe]) }
    }

    @Test("C.2.4: 색인된 필드")
    func indexed() throws {
        var decoder = HPACKDecoder()
        #expect(try decoder.decode(hex("82")) == [HeaderField(":method", "GET")])
    }
}

/// 요청 세 개가 한 연결의 동적 표를 공유한다. 허프만을 쓰지 않는 것(C.3)과 쓰는 것(C.4)이 같은 목록을 낸다.
@Suite("HPACK 요청 (RFC 7541 C.3, C.4)")
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

    @Test("C.3: 허프만 없음")
    func withoutHuffman() throws {
        var decoder = HPACKDecoder()
        #expect(try decoder.decode(hex("8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d")) == first)
        #expect(try decoder.decode(hex("8286 84be 5808 6e6f 2d63 6163 6865")) == second)
        #expect(try decoder.decode(hex("8287 85bf 400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65")) == third)
    }

    @Test("C.4: 허프만")
    func withHuffman() throws {
        var decoder = HPACKDecoder()
        #expect(try decoder.decode(hex("8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff")) == first)
        #expect(try decoder.decode(hex("8286 84be 5886 a8eb 1064 9cbf")) == second)
        #expect(try decoder.decode(hex("8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf")) == third)
    }
}

/// SETTINGS_HEADER_TABLE_SIZE를 256으로 알린 연결. 동적 표가 가득 차 항목이 밀려난다.
@Suite("HPACK 응답과 표 축출 (RFC 7541 C.5, C.6)")
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

    @Test("C.5: 허프만 없음")
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

    @Test("C.6: 허프만")
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

@Suite("HPACK 해제기의 규칙")
struct HPACKDecoderRuleTests {
    @Test("색인 0과 표 밖 색인")
    func invalidIndex() {
        var decoder = HPACKDecoder()
        #expect(throws: HPACKError.invalidIndex) { try decoder.decode([0x80]) }
        #expect(throws: HPACKError.invalidIndex) { try decoder.decode([0xbe]) }
        // 정적 표의 끝(61)은 유효하고 62는 동적 표다.
        #expect((try? decoder.decode([0xbd])) == [HeaderField("www-authenticate", "")])
    }

    @Test("동적 표 크기 갱신은 블록 맨 앞에서만, 알린 한도 이하로만")
    func tableSizeUpdate() throws {
        var decoder = HPACKDecoder(tableSizeLimit: 256)
        #expect(try decoder.decode([0x3f, 0xe1, 0x01]) == [])  // 0x20 | 31, 31 + 225 = 256
        #expect(throws: HPACKError.invalidTableSizeUpdate) { try decoder.decode([0x3f, 0xe2, 0x01]) }  // 257
        #expect(throws: HPACKError.invalidTableSizeUpdate) { try decoder.decode([0x82, 0x20]) }
        #expect(try decoder.decode([0x20, 0x82]) == [HeaderField(":method", "GET")])
    }

    @Test("크기를 0으로 줄이면 표가 비고, 표보다 큰 항목은 표를 비우기만 한다")
    func eviction() throws {
        var decoder = HPACKDecoder()
        _ = try decoder.decode(hex("400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572"))
        #expect(try decoder.decode([0xbe]) == [HeaderField("custom-key", "custom-header")])
        _ = try decoder.decode([0x20])
        #expect(throws: HPACKError.invalidIndex) { try decoder.decode([0xbe]) }

        var small = HPACKDecoder(tableSizeLimit: 40)
        _ = try small.decode(hex("400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572"))  // 55바이트 > 40
        #expect(throws: HPACKError.invalidIndex) { try small.decode([0xbe]) }
    }

    @Test("문자열이 블록 끝에서 잘리면 오류")
    func truncatedString() {
        var decoder = HPACKDecoder()
        #expect(throws: HPACKError.truncated) { try decoder.decode(hex("4005 6162")) }
    }

    @Test("UTF-8이 아닌 문자열")
    func invalidUTF8() {
        var decoder = HPACKDecoder()
        #expect(throws: HPACKError.invalidUTF8) { try decoder.decode(hex("4001 61 01 ff")) }
    }

    @Test("해제 결과가 한도를 넘으면 오류")
    func headerListLimit() throws {
        var decoder = HPACKDecoder(headerListSizeLimit: 100)
        // 이름 1바이트 + 값 40바이트 = 73바이트가 한 항목.
        var block: [UInt8] = [0x40, 0x01, 0x61, 40] + [UInt8](repeating: 0x62, count: 40)
        #expect(try decoder.decode(block).count == 1)
        block += [0xbe]  // 같은 항목을 한 번 더 부른다: 146 > 100
        #expect(throws: HPACKError.headerListTooLarge) { try decoder.decode(block) }
    }
}

@Suite("HPACK 압축기")
struct HPACKEncoderTests {
    @Test("색인 없는 리터럴, 새 이름, 허프만 없이")
    func literalEncoding() {
        #expect(HPACKEncoder.encode([HeaderField(":path", "/sample/path")]) == hex("00 05 3a70617468 0c 2f73616d706c652f70617468"))
    }

    @Test("해제기가 원래 목록으로 되돌린다. 127바이트 이상의 문자열 길이도")
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
