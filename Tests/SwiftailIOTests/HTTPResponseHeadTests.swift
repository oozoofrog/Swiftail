import Testing

@testable import SwiftailIO

@Suite("HTTP response head")
struct HTTPResponseHeadTests {
    private let sample = Array("HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n".utf8)

    private func parse(_ text: String) throws(HTTPResponseHead.ParseError) -> HTTPResponseHead? {
        var parser = HTTPResponseHead.Parser()
        return try parser.receive(Array(text.utf8))
    }

    @Test("Reads the status code and headers")
    func statusAndHeaders() throws {
        var parser = HTTPResponseHead.Parser()
        let head = try #require(try parser.receive(sample))
        #expect(head.status == 101)
        #expect(head.headers.count == 2)
        #expect(head.firstValue(ofHeader: "upgrade") == Array("DERP".utf8))
        #expect(head.remainder.isEmpty)
    }

    @Test("Matches header names case-insensitively, trims spaces and tabs around values, and keeps the first value for each name")
    func lookup() throws {
        let head = try #require(try parse("HTTP/1.1 200\r\nX-Name:\t a b  \r\nx-name: second\r\n\r\n"))
        #expect(head.status == 200)
        #expect(head.firstValue(ofHeader: "X-NAME") == Array("a b".utf8))
        #expect(head.firstValue(ofHeader: "absent") == nil)
    }

    @Test("Returns bytes that have already arrived after the response head")
    func remainder() throws {
        var parser = HTTPResponseHead.Parser()
        let head = try #require(try parser.receive(sample + [1, 2, 3]))
        #expect(head.remainder == [1, 2, 3])
        #expect(throws: HTTPResponseHead.ParseError.closed) { try parser.receive([]) }
    }

    @Test("Stops at the blank line even when bytes arrive one at a time")
    func byteByByte() throws {
        var parser = HTTPResponseHead.Parser()
        for byte in sample.dropLast() {
            #expect(try parser.receive([byte]) == nil)
        }
        let head = try #require(try parser.receive([sample[sample.count - 1]]))
        #expect(head.status == 101)
        #expect(head.remainder == [])
    }

    @Test("Finds the blank line even when it spans two chunks", arguments: 1...3)
    func splitTerminator(tail: Int) throws {
        var parser = HTTPResponseHead.Parser()
        #expect(try parser.receive(Array(sample.dropLast(tail))) == nil)
        let head = try #require(try parser.receive(Array(sample.suffix(tail)) + [9]))
        #expect(head.remainder == [9])
    }

    @Test("An incorrectly formatted status line yields malformedStatusLine", arguments: [
        "\r\n\r\n",
        "HTTP/2 101 x\r\n\r\n",
        "HTTP/1.1 1O1 x\r\n\r\n",
        "HTTP/1.1 1011 x\r\n\r\n",
        "HTTP/1.1101\r\n\r\n",
    ])
    func malformedStatusLine(_ head: String) {
        #expect(throws: HTTPResponseHead.ParseError.malformedStatusLine) { try parse(head) }
    }

    @Test("An incorrectly formatted header line yields malformedHeader with the status code", arguments: [
        "HTTP/1.1 404 x\r\nNoColon\r\n\r\n",
        "HTTP/1.1 404 x\r\nBad Name: v\r\n\r\n",
        "HTTP/1.1 404 x\r\n: v\r\n\r\n",
    ])
    func malformedHeader(_ head: String) {
        #expect(throws: HTTPResponseHead.ParseError.malformedHeader(status: 404)) { try parse(head) }
    }

    @Test("Rejects a bare CR, LF, or control character in the status line or a header value", arguments: [
        "X-Test: x\ny", "X-Test: x\ry", "X-Test: x\0y", "X-Test: x\u{7F}y", "X-Test: \u{1B}",
    ])
    func controlCharacter(_ line: String) {
        #expect(throws: HTTPResponseHead.ParseError.malformedHeader(status: 200)) {
            try parse("HTTP/1.1 200 OK\r\n\(line)\r\n\r\n")
        }
        #expect(throws: HTTPResponseHead.ParseError.malformedStatusLine) {
            try parse("HTTP/1.1 200 O\u{1}K\r\n\r\n")
        }
    }

    @Test("Accepts tabs and bytes at or above 0x80 in a header value")
    func tabAndObsText() throws {
        var parser = HTTPResponseHead.Parser()
        let bytes = Array("HTTP/1.1 200 OK\r\nX-Test: a\tb ".utf8) + [0xC3, 0xA9] + Array("\r\n\r\n".utf8)
        let head = try #require(try parser.receive(bytes))
        #expect(head.firstValue(ofHeader: "x-test") == Array("a\tb ".utf8) + [0xC3, 0xA9])
    }

    @Test("Discards received bytes and rejects later calls after exceeding the limit")
    func oversizedInputIsDropped() {
        var parser = HTTPResponseHead.Parser()
        #expect(throws: HTTPResponseHead.ParseError.tooLarge) {
            try parser.receive([UInt8](repeating: UInt8(ascii: "a"), count: 1_000_000))
        }
        #expect(parser.buffer.isEmpty)
        #expect(throws: HTTPResponseHead.ParseError.closed) { try parser.receive([]) }
    }

    @Test("Reaching 16KiB without a blank line yields tooLarge")
    func headTooLarge() throws {
        var parser = HTTPResponseHead.Parser()
        let start = Array("HTTP/1.1 101 x\r\nX-Pad: ".utf8)
        #expect(try parser.receive(start) == nil)
        #expect(throws: HTTPResponseHead.ParseError.tooLarge) {
            try parser.receive([UInt8](repeating: UInt8(ascii: "a"), count: HTTPResponseHead.Parser.maximumHeadSize - start.count))
        }
    }

    @Test("Accepts a blank line that ends within 16KiB")
    func headAtLimit() throws {
        var parser = HTTPResponseHead.Parser()
        let prefix = Array("HTTP/1.1 101 x\r\nX-Pad: ".utf8)
        let padding = [UInt8](repeating: UInt8(ascii: "a"), count: HTTPResponseHead.Parser.maximumHeadSize - prefix.count - 4)
        let head = try #require(try parser.receive(prefix + padding + Array("\r\n\r\n".utf8) + [7]))
        #expect(head.remainder == [7])
    }

    @Test("Rejects further calls after returning the response head")
    func closedAfterHead() throws {
        var parser = HTTPResponseHead.Parser()
        _ = try parser.receive(sample)
        #expect(throws: HTTPResponseHead.ParseError.closed) { try parser.receive(sample) }
    }
}
