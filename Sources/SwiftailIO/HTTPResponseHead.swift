/// An HTTP/1.1 response head with its status code, headers, and any bytes already received after the head.
///
/// One TCP read can contain both the head and protocol bytes after it (Noise, DERP frames). When `Parser` finishes the
/// head, it returns any remaining bytes in `remainder` for the next layer.
///
/// Accepts only CRLF line endings, as sent by the Go server. Rejects bare CR or LF, C0 control characters other than
/// tab, and DEL in the status line and header values. Header names accept only HTTP token characters. Leading and
/// trailing spaces and tabs are stripped from values.
///
/// `docs/protocol-notes/control-transport.md` §3.6, §4.4 step 2, items 3~4 (origin: tailscale.com
/// `control/controlhttp/client.go`).
package struct HTTPResponseHead: Sendable {
    /// One header line. The name and value retain their original bytes. A value can contain bytes of 0x80 or higher.
    package struct Header: Sendable, Equatable {
        package let name: [UInt8]
        package let value: [UInt8]
    }

    /// The status code (101 in `HTTP/1.1 101 ...`).
    package let status: Int
    /// The headers in the order they appear in the head.
    package let headers: [Header]
    /// The bytes already received immediately after the head's blank line.
    package let remainder: [UInt8]

    /// Returns the value of the first header with the given name. Matching is case-insensitive and uses the first
    /// value, like Go's `Header.Get`.
    package func firstValue(ofHeader name: String) -> [UInt8]? {
        let wanted = name.utf8.map(Self.lowercased)
        return headers.first { $0.name.map(Self.lowercased) == wanted }?.value
    }

    private static func lowercased(_ byte: UInt8) -> UInt8 {
        (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains(byte) ? byte | 0x20 : byte
    }
}

extension HTTPResponseHead {
    /// The reason the head could not be read.
    package enum ParseError: Error, Sendable, Equatable {
        /// The status line is malformed or contains a control character.
        case malformedStatusLine
        /// The status line was read, but a header line is malformed or its value contains a control character. Includes
        /// the status code so the caller can handle it first.
        case malformedHeader(status: Int)
        /// The head reached `maximumHeadSize` before the blank line.
        case tooLarge
        /// The parser was called again after returning a head or failing.
        case closed
    }

    /// Parses a response head from fragmented input. It has no socket or clock.
    package struct Parser: Sendable {
        /// The response head size limit, including the blank line.
        package static let maximumHeadSize = 16 * 1024

        /// The head accumulated before reaching a blank line. Cleared on completion or failure.
        package private(set) var buffer: [UInt8] = []
        private var isDone = false

        package init() {}

        /// Returns nil if the head is still incomplete.
        ///
        /// - Throws: See `ParseError`. Throws `closed` after returning the head or failing.
        package mutating func receive(_ bytes: [UInt8]) throws(ParseError) -> HTTPResponseHead? {
            guard !isDone else { throw .closed }
            // The last 3 bytes from the previous input may be part of the blank line.
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

        /// Returns the index immediately after `\r\n\r\n`. Does not look past `searchEnd`.
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

        /// Returns the status code from `HTTP/1.x SP 3DIGIT [SP reason]`.
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

        /// Rejects DEL and all C0 control characters except tab (RFC 9110 §5.5 for field-value and RFC 9112 §4 for
        /// reason-phrase).
        fileprivate static func isForbiddenControl(_ byte: UInt8) -> Bool {
            (byte < 0x20 && byte != 0x09) || byte == 0x7F
        }

        private static let crlf: [UInt8] = [0x0D, 0x0A]
        private static let crlfcrlf: [UInt8] = [0x0D, 0x0A, 0x0D, 0x0A]
    }
}

extension HTTPResponseHead.Header {
    /// Parses one `name: value` line. Returns nil if malformed.
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
