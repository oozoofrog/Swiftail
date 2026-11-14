import Testing

@testable import SwiftailIO

@Suite("HTTP 응답 머리")
struct HTTPResponseHeadTests {
    private let sample = Array("HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n".utf8)

    private func parse(_ text: String) throws(HTTPResponseHead.ParseError) -> HTTPResponseHead? {
        var parser = HTTPResponseHead.Parser()
        return try parser.receive(Array(text.utf8))
    }

    @Test("상태 코드와 헤더를 읽는다")
    func statusAndHeaders() throws {
        var parser = HTTPResponseHead.Parser()
        let head = try #require(try parser.receive(sample))
        #expect(head.status == 101)
        #expect(head.headers.count == 2)
        #expect(head.firstValue(ofHeader: "upgrade") == Array("DERP".utf8))
        #expect(head.remainder.isEmpty)
    }

    @Test("헤더 이름은 대소문자를 가리지 않고, 값 앞뒤 공백·탭을 걷어 내며, 같은 이름은 첫 값을 쓴다")
    func lookup() throws {
        let head = try #require(try parse("HTTP/1.1 200\r\nX-Name:\t a b  \r\nx-name: second\r\n\r\n"))
        #expect(head.status == 200)
        #expect(head.firstValue(ofHeader: "X-NAME") == Array("a b".utf8))
        #expect(head.firstValue(ofHeader: "absent") == nil)
    }

    @Test("머리 뒤에 이미 온 바이트를 돌려준다")
    func remainder() throws {
        var parser = HTTPResponseHead.Parser()
        let head = try #require(try parser.receive(sample + [1, 2, 3]))
        #expect(head.remainder == [1, 2, 3])
        #expect(throws: HTTPResponseHead.ParseError.closed) { try parser.receive([]) }
    }

    @Test("한 바이트씩 와도 빈 줄에서 끝난다")
    func byteByByte() throws {
        var parser = HTTPResponseHead.Parser()
        for byte in sample.dropLast() {
            #expect(try parser.receive([byte]) == nil)
        }
        let head = try #require(try parser.receive([sample[sample.count - 1]]))
        #expect(head.status == 101)
        #expect(head.remainder == [])
    }

    @Test("빈 줄이 두 조각에 걸쳐도 찾는다", arguments: 1...3)
    func splitTerminator(tail: Int) throws {
        var parser = HTTPResponseHead.Parser()
        #expect(try parser.receive(Array(sample.dropLast(tail))) == nil)
        let head = try #require(try parser.receive(Array(sample.suffix(tail)) + [9]))
        #expect(head.remainder == [9])
    }

    @Test("상태 줄의 형식이 틀리면 malformedStatusLine", arguments: [
        "\r\n\r\n",
        "HTTP/2 101 x\r\n\r\n",
        "HTTP/1.1 1O1 x\r\n\r\n",
        "HTTP/1.1 1011 x\r\n\r\n",
        "HTTP/1.1101\r\n\r\n",
    ])
    func malformedStatusLine(_ head: String) {
        #expect(throws: HTTPResponseHead.ParseError.malformedStatusLine) { try parse(head) }
    }

    @Test("헤더 줄의 형식이 틀리면 상태 코드와 함께 malformedHeader", arguments: [
        "HTTP/1.1 404 x\r\nNoColon\r\n\r\n",
        "HTTP/1.1 404 x\r\nBad Name: v\r\n\r\n",
        "HTTP/1.1 404 x\r\n: v\r\n\r\n",
    ])
    func malformedHeader(_ head: String) {
        #expect(throws: HTTPResponseHead.ParseError.malformedHeader(status: 404)) { try parse(head) }
    }

    @Test("상태 줄이나 헤더 값에 홀로 있는 CR·LF나 제어 문자가 있으면 거절한다", arguments: [
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

    @Test("헤더 값 안의 탭과 0x80 이상의 바이트는 받는다")
    func tabAndObsText() throws {
        var parser = HTTPResponseHead.Parser()
        let bytes = Array("HTTP/1.1 200 OK\r\nX-Test: a\tb ".utf8) + [0xC3, 0xA9] + Array("\r\n\r\n".utf8)
        let head = try #require(try parser.receive(bytes))
        #expect(head.firstValue(ofHeader: "x-test") == Array("a\tb ".utf8) + [0xC3, 0xA9])
    }

    @Test("한도를 넘겨 실패하면 받은 바이트를 쥐고 있지 않고 이후 호출을 거절한다")
    func oversizedInputIsDropped() {
        var parser = HTTPResponseHead.Parser()
        #expect(throws: HTTPResponseHead.ParseError.tooLarge) {
            try parser.receive([UInt8](repeating: UInt8(ascii: "a"), count: 1_000_000))
        }
        #expect(parser.buffer.isEmpty)
        #expect(throws: HTTPResponseHead.ParseError.closed) { try parser.receive([]) }
    }

    @Test("빈 줄 없이 16KiB에 이르면 tooLarge")
    func headTooLarge() throws {
        var parser = HTTPResponseHead.Parser()
        let start = Array("HTTP/1.1 101 x\r\nX-Pad: ".utf8)
        #expect(try parser.receive(start) == nil)
        #expect(throws: HTTPResponseHead.ParseError.tooLarge) {
            try parser.receive([UInt8](repeating: UInt8(ascii: "a"), count: HTTPResponseHead.Parser.maximumHeadSize - start.count))
        }
    }

    @Test("빈 줄이 16KiB 안에 끝나면 받는다")
    func headAtLimit() throws {
        var parser = HTTPResponseHead.Parser()
        let prefix = Array("HTTP/1.1 101 x\r\nX-Pad: ".utf8)
        let padding = [UInt8](repeating: UInt8(ascii: "a"), count: HTTPResponseHead.Parser.maximumHeadSize - prefix.count - 4)
        let head = try #require(try parser.receive(prefix + padding + Array("\r\n\r\n".utf8) + [7]))
        #expect(head.remainder == [7])
    }

    @Test("머리를 돌려준 뒤에는 다시 부를 수 없다")
    func closedAfterHead() throws {
        var parser = HTTPResponseHead.Parser()
        _ = try parser.receive(sample)
        #expect(throws: HTTPResponseHead.ParseError.closed) { try parser.receive(sample) }
    }
}
