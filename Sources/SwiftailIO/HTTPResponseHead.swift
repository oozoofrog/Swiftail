/// HTTP/1.1 응답 머리: 상태 코드, 헤더, 머리 뒤에 이미 도착한 바이트.
///
/// TCP 읽기 한 번에 머리와 그 뒤의 프로토콜 바이트(Noise, DERP 프레임)가 함께 들어올 수 있다. 그래서 `Parser`가
/// 머리를 다 읽었을 때 `remainder`로 남은 바이트를 돌려줘 다음 계층에 넘기게 한다.
///
/// 줄 끝은 CRLF만 받는다(Go 서버가 그렇게 보낸다). 상태 줄과 헤더 값 안에 홀로 있는 CR·LF와 탭 외의
/// C0 제어 문자, DEL이 있으면 거절한다. 헤더 이름은 HTTP token 문자만, 값은 앞뒤 공백·탭을 걷어 낸다.
///
/// `docs/protocol-notes/control-transport.md` 3.6절, 4.4절 2단계 3~4
/// (출처: tailscale.com `control/controlhttp/client.go`).
package struct HTTPResponseHead: Sendable {
    /// 헤더 한 줄. 이름과 값은 바이트 그대로다(값에 0x80 이상의 바이트가 올 수 있다).
    package struct Header: Sendable, Equatable {
        package let name: [UInt8]
        package let value: [UInt8]
    }

    /// 상태 코드(`HTTP/1.1 101 ...`의 101).
    package let status: Int
    /// 머리에 적힌 순서대로의 헤더.
    package let headers: [Header]
    /// 머리의 빈 줄 바로 뒤에 이미 도착한 바이트.
    package let remainder: [UInt8]

    /// 이름이 같은 첫 헤더의 값. 이름은 대소문자를 가리지 않는다(Go의 `Header.Get`처럼 첫 값을 쓴다).
    package func firstValue(ofHeader name: String) -> [UInt8]? {
        let wanted = name.utf8.map(Self.lowercased)
        return headers.first { $0.name.map(Self.lowercased) == wanted }?.value
    }

    private static func lowercased(_ byte: UInt8) -> UInt8 {
        (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains(byte) ? byte | 0x20 : byte
    }
}

extension HTTPResponseHead {
    /// 머리를 읽지 못한 이유.
    package enum ParseError: Error, Sendable, Equatable {
        /// 상태 줄의 형식이 틀리거나 상태 줄에 제어 문자가 있다.
        case malformedStatusLine
        /// 상태 줄은 읽었으나 헤더 줄의 형식이 틀리거나 값에 제어 문자가 있다. 부르는 쪽이 상태를 먼저 판단할 수 있게
        /// 상태 코드를 함께 낸다.
        case malformedHeader(status: Int)
        /// 빈 줄에 닿기 전에 머리가 `maximumHeadSize`에 이르렀다.
        case tooLarge
        /// 머리를 이미 돌려줬거나 실패한 뒤에 다시 불렀다.
        case closed
    }

    /// 조각난 입력에서 응답 머리를 읽는다. 소켓도 시계도 갖지 않는다.
    package struct Parser: Sendable {
        /// 빈 줄까지 포함한 응답 머리의 한도.
        package static let maximumHeadSize = 16 * 1024

        /// 아직 빈 줄에 닿지 않은 머리. 끝나거나 실패하면 비운다.
        package private(set) var buffer: [UInt8] = []
        private var isDone = false

        package init() {}

        /// 머리가 아직 다 오지 않았으면 nil.
        ///
        /// - Throws: `ParseError` 참고. 머리를 돌려줬거나 실패한 뒤에는 `closed`.
        package mutating func receive(_ bytes: [UInt8]) throws(ParseError) -> HTTPResponseHead? {
            guard !isDone else { throw .closed }
            // 앞서 받은 끝 3바이트와 이어서 빈 줄이 완성될 수 있다.
            let searchStart = max(0, buffer.count - 3)
            buffer += bytes

            let searchEnd = min(buffer.count, Self.maximumHeadSize)
            guard let headEnd = Self.endOfHead(in: buffer, from: searchStart, to: searchEnd) else {
                guard buffer.count < Self.maximumHeadSize else {
                    isDone = true
                    buffer = []
                    throw .tooLarge
                }
                return nil
            }

            isDone = true
            let head = buffer[..<(headEnd - 4)]
            let remainder = Array(buffer[headEnd...])
            buffer = []
            return try Self.parse(head, remainder: remainder)
        }

        /// `\r\n\r\n` 바로 뒤의 인덱스. `searchEnd`를 넘는 곳은 보지 않는다.
        private static func endOfHead(in bytes: [UInt8], from searchStart: Int, to searchEnd: Int) -> Int? {
            let firstEnd = searchStart + 4
            guard firstEnd <= searchEnd else { return nil }
            for end in firstEnd...searchEnd where bytes[(end - 4)..<end].elementsEqual(crlfcrlf) {
                return end
            }
            return nil
        }

        private static func parse(_ head: ArraySlice<UInt8>, remainder: [UInt8]) throws(ParseError) -> HTTPResponseHead {
            var lines = head.split(separator: crlf, omittingEmptySubsequences: false)
            let status = try statusCode(of: lines.removeFirst())
            var headers: [Header] = []
            for line in lines {
                guard let header = Header(parsing: line) else { throw .malformedHeader(status: status) }
                headers.append(header)
            }
            return HTTPResponseHead(status: status, headers: headers, remainder: remainder)
        }

        /// `HTTP/1.x SP 3DIGIT [SP reason]`의 상태 코드.
        private static func statusCode(of line: ArraySlice<UInt8>) throws(ParseError) -> Int {
            let parts = line.split(separator: UInt8(ascii: " "), maxSplits: 2, omittingEmptySubsequences: false)
            guard !line.contains(where: isForbiddenControl),
                  parts.count >= 2,
                  parts[0].count == 8,
                  parts[0].starts(with: "HTTP/1.".utf8),
                  let minor = parts[0].last, isDigit(minor),
                  parts[1].count == 3,
                  parts[1].allSatisfy(isDigit)
            else { throw .malformedStatusLine }
            return parts[1].reduce(0) { $0 * 10 + Int($1 - UInt8(ascii: "0")) }
        }

        private static func isDigit(_ byte: UInt8) -> Bool {
            (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte)
        }

        /// 줄 안에 올 수 없는 바이트: 탭을 뺀 C0 제어 문자와 DEL (RFC 9110 5.5의 field-value, RFC 9112 4의 reason-phrase).
        fileprivate static func isForbiddenControl(_ byte: UInt8) -> Bool {
            (byte < 0x20 && byte != 0x09) || byte == 0x7F
        }

        private static let crlf: [UInt8] = [0x0D, 0x0A]
        private static let crlfcrlf: [UInt8] = [0x0D, 0x0A, 0x0D, 0x0A]
    }
}

extension HTTPResponseHead.Header {
    /// `name: value` 한 줄을 읽는다. 형식이 틀리면 nil.
    fileprivate init?(parsing line: ArraySlice<UInt8>) {
        guard let colon = line.firstIndex(of: UInt8(ascii: ":")) else { return nil }
        let name = line[..<colon]
        guard !name.isEmpty, name.allSatisfy(Self.isTokenCharacter) else { return nil }

        var value = line[(colon + 1)...]
        guard !value.contains(where: HTTPResponseHead.Parser.isForbiddenControl) else { return nil }
        while let first = value.first, Self.isWhitespace(first) { value = value.dropFirst() }
        while let last = value.last, Self.isWhitespace(last) { value = value.dropLast() }
        self.init(name: Array(name), value: Array(value))
    }

    private static func isWhitespace(_ byte: UInt8) -> Bool {
        byte == UInt8(ascii: " ") || byte == UInt8(ascii: "\t")
    }

    /// RFC 9110 5.6.2 token.
    private static func isTokenCharacter(_ byte: UInt8) -> Bool {
        switch byte {
        case UInt8(ascii: "0")...UInt8(ascii: "9"), UInt8(ascii: "a")...UInt8(ascii: "z"), UInt8(ascii: "A")...UInt8(ascii: "Z"):
            true
        default:
            Array("!#$%&'*+-.^_`|~".utf8).contains(byte)
        }
    }
}
