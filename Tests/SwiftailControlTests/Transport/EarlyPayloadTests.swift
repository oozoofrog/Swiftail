// Contract unit test 2: Present, absent, and invalid early payloads.

import SwiftailBase
import Testing

@testable import SwiftailControl

@Suite("early payload")
struct EarlyPayloadTests {
    private let magic: [UInt8] = [0xFF, 0xFF, 0xFF, 0x54, 0x53]
    /// Header of the server's first HTTP/2 SETTINGS frame (18-byte payload).
    private let settingsHeader: [UInt8] = [0x00, 0x00, 0x12, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]
    private let challengeHex = String(repeating: "5a", count: 32)

    private func frame(_ json: String) -> [UInt8] {
        let body = Array(json.utf8)
        return magic + UInt32(body.count).bigEndianBytes + body
    }

    @Test("If the magic does not match, forwards everything to HTTP/2, including the 9 bytes")
    func absent() throws {
        var parser = EarlyPayloadParser()
        #expect(try parser.receive(Array(settingsHeader[..<8])) == nil)
        let received = try parser.receive([settingsHeader[8], 0xEE])
        let result = try #require(received)
        #expect(result.payload == nil)
        #expect(result.remainder == settingsHeader + [0xEE])
        #expect(throws: ControlTransportError.closed) { try parser.receive([]) }
    }

    @Test("Reads nodeKeyChallenge and forwards the bytes after it, even across fragments")
    func present() throws {
        let bytes = frame("{\"nodeKeyChallenge\":\"chalpub:\(challengeHex)\",\"future\":[1,2]}") + settingsHeader
        let expected = EarlyPayloadParser.EarlyPayload(nodeKeyChallenge: ChallengePublicKey(rawValue: [UInt8](repeating: 0x5A, count: 32)))

        var whole = EarlyPayloadParser()
        let received = try whole.receive(bytes)
        let result = try #require(received)
        #expect(result.payload == expected)
        #expect(result.remainder == settingsHeader)

        // The result is the same when magic, length, and JSON arrive separately as with the Go test server, or one byte at a time.
        var split = EarlyPayloadParser()
        var last: (payload: EarlyPayloadParser.EarlyPayload?, remainder: [UInt8])?
        for byte in bytes {
            #expect(last == nil)
            last = try split.receive([byte])
            if last != nil { break }
        }
        let splitResult = try #require(last)
        #expect(splitResult.payload == expected)
        // The last JSON byte completes the decision, so the SETTINGS header has yet to arrive.
        #expect(splitResult.remainder.isEmpty)
    }

    @Test("JSON null means no payload, and an empty object or a key of 0 means no challenge")
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

    @Test("Empty or invalid JSON or an invalid key format yields malformed", arguments: [
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

    @Test("A length over 10MiB yields messageTooLarge without waiting for the body")
    func tooLarge() throws {
        var parser = EarlyPayloadParser()
        #expect(throws: ControlTransportError.messageTooLarge) {
            try parser.receive(magic + UInt32((10 << 20) + 1).bigEndianBytes)
        }
    }

    @Test("A length of exactly 10MiB waits for the body")
    func atLimit() throws {
        var parser = EarlyPayloadParser()
        #expect(try parser.receive(magic + UInt32(10 << 20).bigEndianBytes) == nil)
    }
}
