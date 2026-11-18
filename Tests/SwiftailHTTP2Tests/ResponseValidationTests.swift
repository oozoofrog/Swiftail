// Incorporates review findings on response header and trailer validation (RFC 9113 §8.2, §8.3), body length and content-length (§8.1.1), and 101 (§8.6).

import Testing

@testable import SwiftailHTTP2

/// Test helper that acts as the server (peer) and sends DATA and trailers after the response headers.
private struct Exchange {
    var connection: HTTP2ClientConnection
    let id: HTTP2StreamID

    init(method: String = "GET") throws {
        connection = try HTTP2ClientConnection.established()
        id = try connection.startRequest(
            HTTP2ClientConnection.Request(method: method, path: "/", authority: "tail0001"), body: nil)
        _ = connection.takeOutboundBytes()
    }

    mutating func receive(_ bytes: [UInt8]) throws -> [HTTP2ClientConnection.Event] {
        try connection.receive(bytes)
    }

    /// Sends the header block (list of fields) as-is in HEADERS (END_HEADERS).
    static func headers(_ fields: [HeaderField], endStream: Bool = false) -> [UInt8] {
        frameBytes(1, flags: 0x4 | (endStream ? 0x1 : 0), stream: 1, payload: HPACKEncoder.encode(fields))
    }
}

@Suite("Response header validation")
struct ResponseHeaderValidationTests {
    @Test("A response with an invalid name, value, or connection-specific field yields PROTOCOL_ERROR on that stream")
    func invalidFields() throws {
        let bad: [HeaderField] = [
            HeaderField("", "x"),                       // Empty name
            HeaderField("a:b", "x"),                    // ':' inside the name
            HeaderField("a b", "x"),                    // Name containing a space
            HeaderField("X-Upper", "x"),                // Uppercase
            HeaderField("x", "a\r\nb: c"),              // Value containing CR or LF
            HeaderField("x", "a\nb"),
            HeaderField("x", "a\rb"),
            HeaderField("x", "a\u{0}b"),                // NUL
            HeaderField("connection", "close"),         // Connection-specific field
            HeaderField("keep-alive", "timeout=5"),
            HeaderField("proxy-connection", "keep-alive"),
            HeaderField("transfer-encoding", "chunked"),
            HeaderField("upgrade", "h2c"),
            HeaderField("te", "gzip"),                  // te other than trailers
        ]
        for field in bad {
            var exchange = try Exchange()
            let events = try exchange.receive(Exchange.headers([HeaderField(":status", "200"), field]))
            #expect(events == [.streamClosed(exchange.id, resetCode: 1)], "\(field)")
            #expect(try exchange.connection.takeOutboundFrames() == [.rstStream(exchange.id, code: 1)], "\(field)")
        }
    }

    @Test("Accepts te: trailers and names containing token symbols")
    func validFields() throws {
        var exchange = try Exchange()
        let fields = [HeaderField("te", "trailers"), HeaderField("x-a.b_c~d", "a b\tc"), HeaderField("grpc-status", "0")]
        let events = try exchange.receive(Exchange.headers([HeaderField(":status", "200")] + fields))
        #expect(events == [.responseHead(exchange.id, status: 200, headers: fields)])
    }

    @Test("Pseudo-headers or invalid fields in trailers are a stream error")
    func invalidTrailers() throws {
        let bad: [HeaderField] = [
            HeaderField(":status", "200"), HeaderField(":path", "/"), HeaderField("X-Upper", "1"), HeaderField("a:b", "1"),
            HeaderField("x", "a\r\nb"), HeaderField("connection", "close"), HeaderField("", "1"),
        ]
        for field in bad {
            var exchange = try Exchange()
            let events = try exchange.receive(
                responseHeadBytes(stream: 1) + dataBytes(stream: 1, [1]) + Exchange.headers([field], endStream: true))
            #expect(events.suffix(2) == [.responseData(exchange.id, [1]), .streamClosed(exchange.id, resetCode: 1)], "\(field)")
            #expect(try exchange.connection.takeOutboundFrames().contains(.rstStream(exchange.id, code: 1)), "\(field)")
        }
    }

    @Test("Request headers follow the same rules. ':' inside the name and connection-specific fields yield invalidRequest")
    func invalidRequestHeaders() throws {
        var connection = try HTTP2ClientConnection.established()
        let bad: [HeaderField] = [
            HeaderField("a:b", "x"), HeaderField("connection", "close"), HeaderField("keep-alive", "1"),
            HeaderField("proxy-connection", "x"), HeaderField("transfer-encoding", "chunked"), HeaderField("upgrade", "h2c"),
            HeaderField("te", "gzip"), HeaderField("x", "a\u{0}b"),
        ]
        for field in bad {
            let request = HTTP2ClientConnection.Request(method: "GET", path: "/", authority: "tail0001", headers: [field])
            #expect(throws: HTTP2Error.invalidRequest, "\(field)") { try connection.startRequest(request, body: nil) }
        }
        let allowed = HTTP2ClientConnection.Request(
            method: "GET", path: "/", authority: "tail0001", headers: [HeaderField("te", "trailers")])
        #expect(try connection.startRequest(allowed, body: nil).rawValue == 1)
    }
}

@Suite("Body length and status")
struct BodyLengthTests {
    private let length2 = HeaderField("content-length", "2")

    @Test("Ending short of content-length is a stream error")
    func shortBody() throws {
        var exchange = try Exchange()
        let events = try exchange.receive(
            Exchange.headers([HeaderField(":status", "200"), length2]) + dataBytes(stream: 1, [1], endStream: true))
        #expect(events == [
            .responseHead(exchange.id, status: 200, headers: [length2]), .responseData(exchange.id, [1]),
            .streamClosed(exchange.id, resetCode: 1),
        ])
        #expect(try exchange.connection.takeOutboundFrames().contains(.rstStream(exchange.id, code: 1)))
    }

    @Test("Exceeding content-length is a stream error and the excess DATA is not emitted")
    func longBody() throws {
        var exchange = try Exchange()
        let events = try exchange.receive(
            Exchange.headers([HeaderField(":status", "200"), length2]) + dataBytes(stream: 1, [1]) + dataBytes(stream: 1, [2, 3]))
        #expect(events == [
            .responseHead(exchange.id, status: 200, headers: [length2]), .responseData(exchange.id, [1]),
            .streamClosed(exchange.id, resetCode: 1),
        ])
    }

    @Test("A total matching content-length ends cleanly even across several DATA frames")
    func exactBody() throws {
        var exchange = try Exchange()
        let events = try exchange.receive(
            Exchange.headers([HeaderField(":status", "200"), length2]) + dataBytes(stream: 1, [1]) + dataBytes(stream: 1, [2], endStream: true))
        #expect(events.last == .streamClosed(exchange.id, resetCode: nil))
        #expect(events.count == 4)
    }

    @Test("END_STREAM without a body is a stream error when content-length is other than 0")
    func missingBody() throws {
        var exchange = try Exchange()
        let events = try exchange.receive(Exchange.headers([HeaderField(":status", "200"), length2], endStream: true))
        #expect(events == [.responseHead(exchange.id, status: 200, headers: [length2]), .streamClosed(exchange.id, resetCode: 1)])
    }

    @Test("Validates total body length even when trailers end the stream")
    func trailerAfterShortBody() throws {
        var exchange = try Exchange()
        let events = try exchange.receive(
            Exchange.headers([HeaderField(":status", "200"), length2]) + dataBytes(stream: 1, [1])
                + Exchange.headers([HeaderField("grpc-status", "0")], endStream: true))
        #expect(events.last == .streamClosed(exchange.id, resetCode: 1))
    }

    @Test("Multiple content-length fields or a nonnumeric content-length are a stream error")
    func invalidContentLength() throws {
        let bad: [[HeaderField]] = [
            [HeaderField("content-length", "1"), HeaderField("content-length", "1")],
            [HeaderField("content-length", "abc")], [HeaderField("content-length", "-1")], [HeaderField("content-length", "+1")],
            [HeaderField("content-length", "")], [HeaderField("content-length", "1 ")],
            [HeaderField("content-length", "99999999999999999999999")],
        ]
        for fields in bad {
            var exchange = try Exchange()
            let events = try exchange.receive(Exchange.headers([HeaderField(":status", "200")] + fields))
            #expect(events == [.streamClosed(exchange.id, resetCode: 1)], "\(fields)")
        }
    }

    @Test("HEAD, 204, and 304 responses end cleanly without a body even with content-length")
    func noBodyResponses() throws {
        let length = HeaderField("content-length", "5")
        for (method, status) in [("HEAD", "200"), ("GET", "204"), ("GET", "304")] {
            var exchange = try Exchange(method: method)
            let events = try exchange.receive(Exchange.headers([HeaderField(":status", status), length], endStream: true))
            #expect(events == [
                .responseHead(exchange.id, status: Int(status) ?? 0, headers: [length]), .streamClosed(exchange.id, resetCode: nil),
            ], "\(method) \(status)")
        }
    }

    @Test("HTTP/2 does not use 101, so it yields a stream error instead of being skipped as informational")
    func switchingProtocols() throws {
        var exchange = try Exchange()
        let events = try exchange.receive(responseHeadBytes(stream: 1, status: "101"))
        #expect(events == [.streamClosed(exchange.id, resetCode: 1)])
        #expect(try exchange.connection.takeOutboundFrames() == [.rstStream(exchange.id, code: 1)])
    }
}
