// 계약 단위 2 시험: early payload 있음·없음·잘못됨.

import Testing

@testable import SwiftailControl

@Suite("early payload")
struct EarlyPayloadTests {
    private let magic: [UInt8] = [0xFF, 0xFF, 0xFF, 0x54, 0x53]
    /// 서버의 첫 HTTP/2 SETTINGS 프레임 머리(payload 18바이트).
    private let settingsHeader: [UInt8] = [0x00, 0x00, 0x12, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]
    private let challengeHex = String(repeating: "5a", count: 32)

    private func frame(_ json: String) -> [UInt8] {
        let body = Array(json.utf8)
        return magic + UInt32(body.count).bigEndianBytes + body
    }

    @Test("매직이 아니면 9바이트를 포함해 전부 HTTP/2에 넘긴다")
    func absent() throws {
        var parser = EarlyPayloadParser()
        #expect(try parser.receive(Array(settingsHeader[..<8])) == nil)
        let received = try parser.receive([settingsHeader[8], 0xEE])
        let result = try #require(received)
        #expect(result.payload == nil)
        #expect(result.remainder == settingsHeader + [0xEE])
        #expect(throws: ControlTransportError.closed) { try parser.receive([]) }
    }

    @Test("nodeKeyChallenge를 읽고 뒤의 바이트를 넘긴다. 조각나 와도 같다")
    func present() throws {
        let bytes = frame("{\"nodeKeyChallenge\":\"chalpub:\(challengeHex)\",\"future\":[1,2]}") + settingsHeader
        let expected = EarlyPayloadParser.EarlyPayload(nodeKeyChallenge: ChallengePublicKey(rawValue: [UInt8](repeating: 0x5A, count: 32)))

        var whole = EarlyPayloadParser()
        let received = try whole.receive(bytes)
        let result = try #require(received)
        #expect(result.payload == expected)
        #expect(result.remainder == settingsHeader)

        // Go 시험 서버처럼 매직·길이·JSON이 따로 오거나, 한 바이트씩 와도 같다.
        var split = EarlyPayloadParser()
        var last: (payload: EarlyPayloadParser.EarlyPayload?, remainder: [UInt8])?
        for byte in bytes {
            #expect(last == nil)
            last = try split.receive([byte])
            if last != nil { break }
        }
        let splitResult = try #require(last)
        #expect(splitResult.payload == expected)
        // 마지막 JSON 바이트에서 판단이 끝나므로 뒤의 SETTINGS 머리는 아직 오지 않았다.
        #expect(splitResult.remainder.isEmpty)
    }

    @Test("JSON null은 payload 없음, 빈 객체·0 키는 challenge 없음")
    func emptyForms() throws {
        var null = EarlyPayloadParser()
        let received = try null.receive(frame(" null "))
        let nullResult = try #require(received)
        #expect(nullResult.payload == nil)

        for json in ["{}", "{\"nodeKeyChallenge\":null}", "{\"nodeKeyChallenge\":\"chalpub:\(String(repeating: "0", count: 64))\"}"] {
            var parser = EarlyPayloadParser()
            let received = try parser.receive(frame(json))
            let result = try #require(received)
            #expect(result.payload == EarlyPayloadParser.EarlyPayload(nodeKeyChallenge: nil))
        }
    }

    @Test("JSON이 비었거나 틀리거나, 키 형식이 틀리면 malformed", arguments: [
        "",
        "{",
        "[]",
        "1",
        "{} {}",
        "{\"nodeKeyChallenge\":\"mkey:\(String(repeating: "5a", count: 32))\"}",
        "{\"nodeKeyChallenge\":\"chalpub:5a5a\"}",
        "{\"nodeKeyChallenge\":\"chalpub:\(String(repeating: "zz", count: 32))\"}",
        "{\"nodeKeyChallenge\":7}",
    ])
    func malformed(_ json: String) throws {
        var parser = EarlyPayloadParser()
        #expect(throws: ControlTransportError.malformed) { try parser.receive(frame(json)) }
        #expect(throws: ControlTransportError.closed) { try parser.receive([]) }
    }

    @Test("길이가 10MiB를 넘으면 본문을 기다리지 않고 messageTooLarge")
    func tooLarge() throws {
        var parser = EarlyPayloadParser()
        #expect(throws: ControlTransportError.messageTooLarge) {
            try parser.receive(magic + UInt32((10 << 20) + 1).bigEndianBytes)
        }
    }

    @Test("길이가 10MiB 정각이면 본문을 기다린다")
    func atLimit() throws {
        var parser = EarlyPayloadParser()
        #expect(try parser.receive(magic + UInt32(10 << 20).bigEndianBytes) == nil)
    }
}
