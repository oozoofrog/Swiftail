// DNS 코덱 시험. 계약 `docs/contracts/SwiftailTunnel.md` "시험" 1, 노트 `dns-state-node.md` 3.1·4.2.4.
//
// 고정 바이트 벡터는 Go로 얻었다: `Tools/interop` 모듈(golang.org/x/net v0.60.0, tailscale.com v1.104.6)에서
// 임시 프로그램이 `dnsmessage.Builder`로 질의를 만들고, `tailscale.com/net/dns/resolver`의 `Resolver.Query(…, "udp", …)`가
// 낸 응답을 16진으로 찍었다. SOA SERIAL 4바이트는 Go가 쓴 시각 대신 1_800_000_000(0x6b49d200)으로 바꿨다.
// 포인터·형식 오류 질의의 기대값은 같은 프로그램에서 `dnsmessage.Parser.Start`·`Question`의 결과로 확인했다.

import Foundation
import Testing

import SwiftailBase
@testable import SwiftailEngine

@Suite("DNS 메시지 코덱")
struct DNSMessageTests {
    /// 머리 12바이트: ID 0x0161, 플래그 0, QDCOUNT 1. ID 두 바이트는 레이블 `a`(01 61)로도 읽혀, 뒤의 0 플래그 바이트에서 끝난다.
    private let pointerHeader: [UInt8] = [0x01, 0x61, 0x00, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]

    private func question(_ nameBytes: [UInt8], header: [UInt8]? = nil) -> [UInt8] {
        (header ?? pointerHeader) + nameBytes + [0, 1, 0, 1]
    }

    // MARK: 질의 해석

    @Test("Go dnsmessage가 만든 A 질의를 읽는다")
    func goQuery() throws {
        let bytes = try hexBytes("1234010000010000000000000f72642d6d61632d3161326233633464087461696c30303031027473036e65740000010001")
        let query = try DNSMessage.Query(parsing: bytes)
        #expect(query.header.id == 0x1234)
        #expect(query.header.flags == .recursionDesired)
        #expect(query.question.name == DNSMessage.Name("rd-mac-1a2b3c4d.tail0001.ts.net."))
        #expect(query.question.type == .a)
        #expect(query.question.recordClass == 1)
    }

    @Test("질문이 둘이면 첫 질문만 읽고 나머지는 보지 않는다")
    func twoQuestions() throws {
        let bytes = DNSWire.header(id: 7, flags: 0, questions: 2)
            + DNSWire.question("first.tail0001.ts.net.", type: 1)
            + [0xFF, 0xFF]  // 두 번째 질문 자리의 깨진 바이트도 읽지 않는다
        let query = try DNSMessage.Query(parsing: bytes)
        #expect(query.question.name == DNSMessage.Name("first.tail0001.ts.net."))
    }

    @Test("머리가 짧거나, 응답이거나, 질문이 없거나, QTYPE·QCLASS가 잘리면 해석하지 않는다")
    func malformedQueries() throws {
        let valid = DNSWire.query("a.tail0001.ts.net.", type: 1)
        #expect(throws: DNSMessage.Query.ParseError.truncatedHeader) { try DNSMessage.Query(parsing: []) }
        #expect(throws: DNSMessage.Query.ParseError.truncatedHeader) { try DNSMessage.Query(parsing: Array(valid.prefix(11))) }

        var response = valid
        response[2] |= 0x80
        #expect(throws: DNSMessage.Query.ParseError.notAQuery) { try DNSMessage.Query(parsing: response) }

        var noQuestion = valid
        noQuestion[5] = 0
        #expect(throws: DNSMessage.Query.ParseError.noQuestion) { try DNSMessage.Query(parsing: noQuestion) }

        #expect(throws: DNSMessage.Query.ParseError.truncatedQuestion) { try DNSMessage.Query(parsing: Array(valid.dropLast())) }
        #expect(throws: DNSMessage.Query.ParseError.malformedName(.truncated)) {
            try DNSMessage.Query(parsing: Array(valid.prefix(14)))
        }
    }

    // MARK: 이름과 포인터

    @Test("뒤를 가리키는 포인터를 따라간다")
    func backwardPointer() throws {
        // www + 오프셋 0으로의 포인터. Go: "www.a."
        let query = try DNSMessage.Query(parsing: question([3, 0x77, 0x77, 0x77, 0xC0, 0x00]))
        #expect(query.question.name == DNSMessage.Name("www.a."))
    }

    @Test("앞을 가리키는 포인터도 Go처럼 따라가고, 질문의 끝은 포인터 바로 뒤다")
    func forwardPointer() throws {
        // 질문 뒤(오프셋 22)에 놓인 tail0001.ts.net.을 가리킨다. Go: "www.tail0001.ts.net."
        let bytes = question([3, 0x77, 0x77, 0x77, 0xC0, 22]) + DNSWire.name("tail0001.ts.net.")
        let query = try DNSMessage.Query(parsing: bytes)
        #expect(query.question.name == DNSMessage.Name("www.tail0001.ts.net."))
        #expect(query.question.type == .a)
    }

    @Test("자기 자신을 가리키는 포인터는 고리이고 10번 넘게 따라가지 않는다")
    func selfPointerLoop() {
        #expect(throws: DNSMessage.Query.ParseError.malformedName(.tooManyPointers)) {
            try DNSMessage.Query(parsing: question([0xC0, 12]))
        }
    }

    @Test("포인터 10개 사슬은 읽고 11번째 포인터는 거절한다")
    func pointerChainLimit() throws {
        // 오프셋 12부터 2바이트마다 다음 칸을 가리키고 마지막에 레이블 x가 있다.
        func chain(_ count: Int) -> [UInt8] {
            var bytes = pointerHeader
            for index in 0..<count {
                let next = 12 + 2 * (index + 1)
                bytes += [0xC0 | UInt8(next >> 8), UInt8(next & 0xFF)]
            }
            return bytes + [1, 0x78, 0] + [0, 1, 0, 1]
        }
        #expect(try DNSMessage.Query(parsing: chain(10)).question.name == DNSMessage.Name("x."))
        #expect(throws: DNSMessage.Query.ParseError.malformedName(.tooManyPointers)) {
            try DNSMessage.Query(parsing: chain(11))
        }
    }

    @Test("범위 밖을 가리키거나 둘째 바이트가 없는 포인터는 잘린 이름이다")
    func pointerOutOfRange() {
        #expect(throws: DNSMessage.Name.ParseError.truncated) {
            try DNSMessage.Name.read(from: pointerHeader + [0xC0, 0xFF], at: 12)
        }
        #expect(throws: DNSMessage.Name.ParseError.truncated) {
            try DNSMessage.Name.read(from: pointerHeader + [0xFF], at: 12)
        }
        #expect(throws: DNSMessage.Name.ParseError.truncated) {
            try DNSMessage.Name.read(from: pointerHeader + [5, 0x61, 0x62], at: 12)
        }
    }

    @Test("레이블 형식 01·10은 예약이라 거절한다")
    func reservedLabelTypes() {
        for lead: UInt8 in [0x41, 0x81] {
            #expect(throws: DNSMessage.Query.ParseError.malformedName(.reservedLabelType)) {
                try DNSMessage.Query(parsing: question([lead, 0x61, 0]))
            }
        }
    }

    @Test("레이블 안의 점은 거절한다")
    func dotInsideLabel() {
        #expect(throws: DNSMessage.Query.ParseError.malformedName(.labelContainsDot)) {
            try DNSMessage.Query(parsing: question([3, 0x61, 0x2E, 0x62, 0]))
        }
    }

    @Test("끝 점을 포함한 표기 254바이트는 받고 255바이트는 거절한다")
    func nameLengthBoundary() throws {
        let longest = DNSWire.nameText(presentationLength: 254)
        let query = try DNSMessage.Query(parsing: question(DNSWire.name(longest)))
        #expect(query.question.name.wireFormat.count == 255)
        #expect(query.question.name == DNSMessage.Name(longest))

        let tooLong = DNSWire.nameText(presentationLength: 255)
        #expect(throws: DNSMessage.Query.ParseError.malformedName(.tooLong)) {
            try DNSMessage.Query(parsing: question(DNSWire.name(tooLong)))
        }
    }

    @Test("포인터로 이어 붙인 이름도 254바이트 한도를 넘지 못한다")
    func pointerCannotExceedLength() {
        // 63바이트 레이블 넷(256바이트 표기)을 포인터로 이어 붙인다.
        let label = [63] + [UInt8](repeating: 0x61, count: 63)
        var bytes = pointerHeader + label + label + [0xC0, 12]
        bytes += [0, 1, 0, 1]
        #expect(throws: DNSMessage.Query.ParseError.malformedName(.tooLong)) { try DNSMessage.Query(parsing: bytes) }
    }

    @Test("문자열 이름은 Go dnsname.ToFQDN과 같은 것을 받는다")
    func nameFromText() {
        #expect(DNSMessage.Name("rd-mac-1a2b3c4d.tail0001.ts.net")?.labels.count == 4)
        #expect(DNSMessage.Name("rd-mac-1a2b3c4d.tail0001.ts.net.") == DNSMessage.Name("rd-mac-1a2b3c4d.tail0001.ts.net"))
        #expect(DNSMessage.Name(".tail0001.ts.net.") == DNSMessage.Name("tail0001.ts.net."))
        #expect(DNSMessage.Name("")?.labels.isEmpty == true)
        #expect(DNSMessage.Name(".")?.labels.isEmpty == true)
        #expect(DNSMessage.Name("a..b") == nil)
        #expect(DNSMessage.Name("a b.ts.net") == nil)
        #expect(DNSMessage.Name("a\u{7F}.ts.net") == nil)
        #expect(DNSMessage.Name(String(repeating: "a", count: 64) + ".ts.net") == nil)
        #expect(DNSMessage.Name(DNSWire.nameText(presentationLength: 254)) != nil)
        #expect(DNSMessage.Name(DNSWire.nameText(presentationLength: 255)) == nil)
    }

    @Test("소문자 변환은 ASCII A-Z만 바꾸고 영역 포함은 레이블 단위다")
    func lowercasingAndZones() throws {
        // É(C3 89)는 ASCII가 아니므로 그대로 남는다.
        let mixed = try #require(DNSMessage.Name("Rd\u{C9}.TS"))
        #expect(mixed.lowercased().labels == [[0x72, 0x64, 0xC3, 0x89], Array("ts".utf8)])

        let zone = try #require(DNSMessage.Name("tail0001.ts.net"))
        #expect(try #require(DNSMessage.Name("a.tail0001.ts.net")).isWithin(zone))
        #expect(zone.isWithin(zone))
        #expect(try #require(DNSMessage.Name("xtail0001.ts.net")).isWithin(zone) == false)
        #expect(try #require(DNSMessage.Name("ts.net")).isWithin(zone) == false)
        #expect(zone.isWithin(try #require(DNSMessage.Name("."))))
    }

    // MARK: 응답 쓰기

    @Test("A 답변을 압축 없이 Go와 같은 바이트로 쓴다")
    func encodesAddressAnswer() throws {
        let name = try #require(DNSMessage.Name("rd-mac-1a2b3c4d.tail0001.ts.net."))
        let response = DNSMessage.Response(
            header: DNSMessage.Header(id: 0xBEEF, flags: DNSMessage.Header.Flags(rawValue: 0x8580)),
            question: DNSMessage.Question(name: name, type: .a, recordClass: 1),
            answer: .address(try #require(IPAddress("100.64.0.1")))
        )
        #expect(response.encoded() == (try hexBytes(
            "beef858000010001000000000f72642d6d61632d3161326233633464087461696c30303031027473036e657400000100010f72642d6d61632d3161326233633464087461696c30303031027473036e6574000001000100000005000464400001"
        )))
    }

    @Test("NXDOMAIN의 SOA를 Go와 같은 바이트로 쓴다")
    func encodesStartOfAuthority() throws {
        let response = DNSMessage.Response(
            header: DNSMessage.Header(id: 0xBEEF, flags: DNSMessage.Header.Flags(rawValue: 0x8583)),
            question: DNSMessage.Question(name: try #require(DNSMessage.Name("nope.tail0001.ts.net.")), type: .a, recordClass: 1),
            authority: .init(zone: try #require(DNSMessage.Name("tail0001.ts.net.")), serial: 1_800_000_000)
        )
        #expect(response.encoded() == (try hexBytes(
            "beef85830001000000010000046e6f7065087461696c30303031027473036e65740000010001087461696c30303031027473036e657400000600010000000a0036087461696c30303031027473036e657400087461696c30303031027473036e6574006b49d2000000000a0000000a0000000a0000000a"
        )))
    }

    @Test("PTR 답변을 Go와 같은 바이트로 쓴다")
    func encodesPointerAnswer() throws {
        let response = DNSMessage.Response(
            header: DNSMessage.Header(id: 0xBEEF, flags: DNSMessage.Header.Flags(rawValue: 0x8580)),
            question: DNSMessage.Question(name: try #require(DNSMessage.Name("1.0.64.100.in-addr.arpa.")), type: .ptr, recordClass: 1),
            answer: .pointer(try #require(DNSMessage.Name("rd-mac-1a2b3c4d.tail0001.ts.net.")))
        )
        #expect(response.encoded() == (try hexBytes(
            "beef85800001000100000000013101300236340331303007696e2d61646472046172706100000c0001013101300236340331303007696e2d61646472046172706100000c00010000000500210f72642d6d61632d3161326233633464087461696c30303031027473036e657400"
        )))
    }

    @Test("질문이 없는 응답은 머리 12바이트이고, 답변은 질문이 있을 때만 쓴다")
    func encodesWithoutQuestion() throws {
        let response = DNSMessage.Response(
            header: DNSMessage.Header(id: 0, flags: DNSMessage.Header.Flags(rawValue: 0x8401)),
            answer: .address(try #require(IPAddress("100.64.0.1")))
        )
        #expect(response.encoded() == [0, 0, 0x84, 0x01, 0, 0, 0, 0, 0, 0, 0, 0])
    }

    @Test("크기 한도를 넘으면 TC만 켜고 자르지 않는다")
    func truncationFlag() throws {
        let response = DNSMessage.Response(
            header: DNSMessage.Header(id: 1, flags: .response),
            question: DNSMessage.Question(name: try #require(DNSMessage.Name("a.")), type: .a, recordClass: 1)
        )
        let plain = response.encoded()
        #expect(plain.count == 19)
        #expect(response.encoded(udpPayloadLimit: 19) == plain)
        let truncated = response.encoded(udpPayloadLimit: 18)
        #expect(truncated.count == 19)
        #expect(truncated[2] == 0x82)
        #expect(Array(truncated[3...]) == Array(plain[3...]))
    }

    // MARK: EDNS 광고 크기

    @Test("질의 끝의 옵션 없는 OPT만 광고 크기로 읽는다")
    func advertisedPayloadSize() {
        let name = "a.tail0001.ts.net."
        #expect(DNSMessage.udpPayloadLimit(ofQuery: DNSWire.query(name, type: 1, udpPayloadSize: 4096)) == 4096)
        #expect(DNSMessage.udpPayloadLimit(ofQuery: DNSWire.query(name, type: 1, udpPayloadSize: 20)) == 20)
        #expect(DNSMessage.udpPayloadLimit(ofQuery: DNSWire.query(name, type: 1)) == 512)
        #expect(DNSMessage.udpPayloadLimit(ofQuery: []) == 512)

        // ARCOUNT가 0이면 OPT 모양의 꼬리도 보지 않는다.
        var noCount = DNSWire.query(name, type: 1, udpPayloadSize: 4096)
        noCount[11] = 0
        #expect(DNSMessage.udpPayloadLimit(ofQuery: noCount) == 512)

        // EDNS 버전이 0이 아니면 보지 않는다.
        var version1 = DNSWire.query(name, type: 1, udpPayloadSize: 4096)
        version1[version1.count - 5] = 1
        #expect(DNSMessage.udpPayloadLimit(ofQuery: version1) == 512)

        // 옵션이 붙은 OPT(RDLEN ≠ 0)는 끝 11바이트가 OPT 머리가 아니므로 보지 않는다.
        let withOption = DNSWire.header(id: 1, flags: 0, questions: 1, additionals: 1) + DNSWire.question(name, type: 1)
            + [0] + DNSWire.bigEndian(41) + DNSWire.bigEndian(4096) + [0, 0, 0, 0] + DNSWire.bigEndian(4) + [0, 10, 0, 0]
        #expect(DNSMessage.udpPayloadLimit(ofQuery: withOption) == 512)
    }

    // MARK: 임의 입력

    @Test("임의 바이트와 일부를 바꾼 질의에서 트랩 없이 끝난다")
    func randomInput() {
        var random = FuzzRandom(seed: 0x5EED_D115)
        let seeds = [
            DNSWire.query("rd-mac-1a2b3c4d.tail0001.ts.net.", type: 1),
            DNSWire.query("a.tail0001.ts.net.", type: 28, udpPayloadSize: 1232),
            question([3, 0x77, 0x77, 0x77, 0xC0, 0x00]),
        ]
        for round in 0..<20_000 {
            var bytes: [UInt8]
            if round.isMultiple(of: 2) {
                bytes = random.bytes(Int.random(in: 0...300, using: &random))
            } else {
                bytes = seeds[round % seeds.count]
                for _ in 0..<Int.random(in: 1...4, using: &random) {
                    bytes[Int.random(in: 0..<bytes.count, using: &random)] = UInt8.random(in: .min ... .max, using: &random)
                }
            }
            if let query = try? DNSMessage.Query(parsing: bytes) {
                #expect(query.question.name.wireFormat.count <= 255)
            }
            _ = DNSMessage.udpPayloadLimit(ofQuery: bytes)
        }
    }
}
