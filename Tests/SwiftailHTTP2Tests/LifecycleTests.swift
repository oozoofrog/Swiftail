// Contract test 4: Lifecycle. SETTINGS ACK, PING response, rejection of new requests after GOAWAY, RST_STREAM, and increasing odd stream IDs.

import Testing

@testable import SwiftailHTTP2

@Suite("Connection startup and SETTINGS")
struct HandshakeTests {
    @Test("Sends a 24-byte preface and SETTINGS with push disabled")
    func clientPreface() throws {
        var connection = HTTP2ClientConnection()
        let bytes = connection.takeOutboundBytes()
        #expect(Array(bytes.prefix(24)) == Array("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8))
        let frames = try parseFrames(Array(bytes.dropFirst(24)))
        #expect(frames == [.settings([.init(identifier: 2, value: 0), .init(identifier: 6, value: 65_536)])])
        #expect(connection.takeOutboundBytes().isEmpty)
    }

    @Test("Acknowledges server SETTINGS with ACK and leaves ACK unanswered")
    func settingsAcknowledged() throws {
        var connection = HTTP2ClientConnection()
        _ = connection.takeOutboundBytes()
        _ = try connection.receive(settingsBytes([(3, 250), (5, 1_048_576), (4, 1_048_576), (1, 4_096)]))
        #expect(try connection.takeOutboundFrames() == [.settingsAcknowledgement])
        _ = try connection.receive(frameBytes(4, flags: 0x1))
        #expect(connection.takeOutboundBytes().isEmpty)
    }

    @Test("Ignores unknown SETTINGS and unknown frame types")
    func unknownIgnored() throws {
        var connection = HTTP2ClientConnection()
        _ = connection.takeOutboundBytes()
        _ = try connection.receive(settingsBytes([(0x00ff, 12345)]))
        _ = connection.takeOutboundBytes()
        #expect(try connection.receive(frameBytes(0xee, stream: 5, payload: [1, 2, 3])).isEmpty)
        #expect(connection.takeOutboundBytes().isEmpty)
    }

    @Test("A server first frame other than SETTINGS is a connection error")
    func firstFrameMustBeSettings() throws {
        var connection = HTTP2ClientConnection()
        _ = connection.takeOutboundBytes()
        #expect(throws: HTTP2Error.connectionFailed(code: 1)) { try connection.receive(windowUpdateBytes(stream: 0, increment: 1)) }
    }

    @Test("Out-of-spec SETTINGS values are connection errors")
    func invalidSettings() throws {
        for setting: (UInt16, UInt32) in [(2, 1), (2, 2), (5, 16_383), (5, 16_777_216)] {
            var connection = HTTP2ClientConnection()
            #expect(throws: HTTP2Error.connectionFailed(code: 1)) { try connection.receive(settingsBytes([setting])) }
        }
    }

    @Test("PUSH_PROMISE is a connection error")
    func pushPromiseRejected() throws {
        var connection = try HTTP2ClientConnection.established()
        _ = try connection.startRequest(getRequest, body: nil)
        _ = connection.takeOutboundBytes()
        #expect(throws: HTTP2Error.connectionFailed(code: 1)) {
            try connection.receive(frameBytes(5, flags: 0x4, stream: 1, payload: [0, 0, 0, 2, 0x82]))
        }
    }
}

@Suite("PING, GOAWAY, and behavior after errors")
struct ConnectionLifetimeTests {
    @Test("Acknowledges PING with the same 8 bytes and leaves ACK unanswered")
    func ping() throws {
        var connection = try HTTP2ClientConnection.established()
        let data: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8]
        _ = try connection.receive(frameBytes(6, payload: data))
        #expect(try connection.takeOutboundFrames() == [.ping(ack: true, data: data)])
        _ = try connection.receive(frameBytes(6, flags: 0x1, payload: data))
        #expect(connection.takeOutboundBytes().isEmpty)
    }

    @Test("Rejects new requests after GOAWAY and receives processed streams to completion")
    func goAway() throws {
        var connection = try HTTP2ClientConnection.established()
        let first = try connection.startRequest(getRequest, body: nil)
        let second = try connection.startRequest(getRequest, body: nil)
        _ = connection.takeOutboundBytes()
        let events = try connection.receive(goAwayBytes(lastStream: 1, code: 0))
        #expect(events == [.goAway(lastStreamID: first, code: 0)])
        #expect(throws: HTTP2Error.connectionClosed) { try connection.startRequest(getRequest, body: nil) }

        // The processed stream 1 can finish its response. Unprocessed stream 3 was discarded.
        let rest = try connection.receive(responseHeadBytes(stream: 1, endStream: true) + responseHeadBytes(stream: 3, endStream: true))
        #expect(rest == [.responseHead(first, status: 200, headers: []), .streamClosed(first, resetCode: nil)])
        _ = second
    }

    @Test("Reports GOAWAY with an error code as an event and rejects new requests")
    func goAwayWithError() throws {
        var connection = try HTTP2ClientConnection.established()
        let events = try connection.receive(goAwayBytes(lastStream: 0, code: 1))
        #expect(events == [.goAway(lastStreamID: HTTP2StreamID(0), code: 1)])
        #expect(throws: HTTP2Error.connectionClosed) { try connection.startRequest(getRequest, body: nil) }
    }

    @Test("After a connection error, GOAWAY remains and subsequent input and requests get connectionClosed")
    func afterConnectionError() throws {
        var connection = try HTTP2ClientConnection.established()
        #expect(throws: HTTP2Error.connectionFailed(code: 1)) { try connection.receive(dataBytes(stream: 0, [1])) }
        #expect(try connection.takeOutboundFrames() == [.goAway(lastStreamID: .connection, code: 1)])
        #expect(throws: HTTP2Error.connectionClosed) { try connection.receive([]) }
        #expect(throws: HTTP2Error.connectionClosed) { try connection.startRequest(getRequest, body: nil) }
        connection.cancel(HTTP2StreamID(1))
        #expect(connection.takeOutboundBytes().isEmpty)
    }
}

@Suite("Stream lifecycle")
struct StreamLifetimeTests {
    @Test("Stream IDs increase through odd numbers starting at 1")
    func oddIncreasingIDs() throws {
        var connection = try HTTP2ClientConnection.established()
        let ids = try (0..<4).map { _ in try connection.startRequest(getRequest, body: nil).rawValue }
        #expect(ids == [1, 3, 5, 7])
        let frames = try connection.takeOutboundFrames()
        #expect(frames.count == 4)
        guard case .headers(let id, _, let endStream, let endHeaders) = frames[0] else { Issue.record("Expected HEADERS"); return }
        #expect(id == HTTP2StreamID(1) && endStream && endHeaders)
    }

    @Test("Request HEADERS place pseudo-headers first and use https for :scheme")
    func requestHeaders() throws {
        var connection = try HTTP2ClientConnection.established()
        let request = HTTP2ClientConnection.Request(
            method: "POST", path: "/machine/map", authority: "tail0001",
            headers: [HeaderField("content-type", "application/json"), HeaderField("ts-lb", "nodekey:abc")])
        _ = try connection.startRequest(request, body: [1, 2])
        guard case .headers(_, let block, _, _) = try connection.takeOutboundFrames().first else { Issue.record("Expected HEADERS"); return }
        var decoder = HPACKDecoder()
        #expect(try decoder.decode(block) == [
            HeaderField(":method", "POST"), HeaderField(":scheme", "https"), HeaderField(":authority", "tail0001"),
            HeaderField(":path", "/machine/map"), HeaderField("content-type", "application/json"), HeaderField("ts-lb", "nodekey:abc"),
        ])
    }

    @Test("Receiving RST_STREAM closes the stream with its error code")
    func receivedReset() throws {
        var connection = try HTTP2ClientConnection.established()
        let id = try connection.startRequest(getRequest, body: nil)
        #expect(try connection.receive(rstStreamBytes(stream: 1, code: 7)) == [.streamClosed(id, resetCode: 7)])
        // Ignore RST_STREAM on an already completed stream.
        #expect(try connection.receive(rstStreamBytes(stream: 1, code: 0)).isEmpty)
    }

    @Test("A frame on a stream that was never requested is a connection error")
    func idleStream() throws {
        for frame in [rstStreamBytes(stream: 3, code: 0), dataBytes(stream: 3, [1]), responseHeadBytes(stream: 2), windowUpdateBytes(stream: 5, increment: 1)] {
            var connection = try HTTP2ClientConnection.established()
            _ = try connection.startRequest(getRequest, body: nil)
            #expect(throws: HTTP2Error.connectionFailed(code: 1)) { try connection.receive(frame) }
        }
    }

    @Test("cancel sends RST_STREAM(CANCEL) and has no effect on a completed stream")
    func cancel() throws {
        var connection = try HTTP2ClientConnection.established()
        let id = try connection.startRequest(getRequest, body: nil)
        _ = connection.takeOutboundBytes()
        connection.cancel(id)
        #expect(try connection.takeOutboundFrames() == [.rstStream(id, code: 8)])
        connection.cancel(id)
        connection.cancel(HTTP2StreamID(99))
        #expect(connection.takeOutboundBytes().isEmpty)
        // Silently discard late responses on canceled streams while still decoding their header blocks.
        let late = try connection.receive(responseHeadBytes(stream: 1, headers: [HeaderField("x", "y")]))
        #expect(late.isEmpty)
    }

    @Test("Concurrent streams are limited to the peer's MAX_CONCURRENT_STREAMS")
    func tooManyStreams() throws {
        var connection = try HTTP2ClientConnection.established(serverSettings: [(3, 2)])
        let first = try connection.startRequest(getRequest, body: nil)
        _ = try connection.startRequest(getRequest, body: nil)
        #expect(throws: HTTP2Error.tooManyStreams) { try connection.startRequest(getRequest, body: nil) }
        _ = try connection.receive(responseHeadBytes(stream: 1, endStream: true))
        let third = try connection.startRequest(getRequest, body: nil)
        #expect(third.rawValue == 5)
        _ = first
    }

    @Test("Invalid requests")
    func invalidRequests() throws {
        var connection = try HTTP2ClientConnection.established()
        let bad: [HTTP2ClientConnection.Request] = [
            .init(method: "", path: "/", authority: "tail0001"),
            .init(method: "GET", path: "", authority: "tail0001"),
            .init(method: "GET", path: "/", authority: ""),
            .init(method: "GET", path: "/ a", authority: "tail0001"),
            .init(method: "GET", path: "/", authority: "tail0001", headers: [HeaderField("Content-Type", "x")]),
            .init(method: "GET", path: "/", authority: "tail0001", headers: [HeaderField(":path", "/")]),
            .init(method: "GET", path: "/", authority: "tail0001", headers: [HeaderField("", "x")]),
            .init(method: "GET", path: "/", authority: "tail0001", headers: [HeaderField("x", "a\r\nb: c")]),
        ]
        for request in bad {
            #expect(throws: HTTP2Error.invalidRequest) { try connection.startRequest(request, body: nil) }
        }
        // Rejected requests do not consume stream IDs.
        #expect(try connection.startRequest(getRequest, body: nil).rawValue == 1)
    }
}

@Suite("Response processing")
struct ResponseTests {
    @Test("Small GET with headers, body, and end of stream")
    func smallGet() throws {
        var connection = try HTTP2ClientConnection.established()
        let id = try connection.startRequest(getRequest, body: nil)
        let events = try connection.receive(
            responseHeadBytes(stream: 1, headers: [HeaderField("content-type", "application/json")])
                + dataBytes(stream: 1, Array("{}".utf8), endStream: true))
        #expect(events == [
            .responseHead(id, status: 200, headers: [HeaderField("content-type", "application/json")]),
            .responseData(id, Array("{}".utf8)),
            .streamClosed(id, resetCode: nil),
        ])
    }

    @Test("An endless response progresses alongside another request")
    func interleavedStreams() throws {
        var connection = try HTTP2ClientConnection.established()
        let long = try connection.startRequest(getRequest, body: nil)
        let short = try connection.startRequest(getRequest, body: nil)
        let events = try connection.receive(
            responseHeadBytes(stream: 1) + dataBytes(stream: 1, [1])
                + responseHeadBytes(stream: 3, endStream: true) + dataBytes(stream: 1, [2]))
        #expect(events == [
            .responseHead(long, status: 200, headers: []), .responseData(long, [1]),
            .responseHead(short, status: 200, headers: []), .streamClosed(short, resetCode: nil),
            .responseData(long, [2]),
        ])
    }

    @Test("Skips informational 1xx responses and emits the final response")
    func informational() throws {
        var connection = try HTTP2ClientConnection.established()
        let id = try connection.startRequest(getRequest, body: nil)
        let events = try connection.receive(responseHeadBytes(stream: 1, status: "100") + responseHeadBytes(stream: 1, status: "204", endStream: true))
        #expect(events == [.responseHead(id, status: 204, headers: []), .streamClosed(id, resetCode: nil)])
    }

    @Test("An invalid response closes only its stream with RST_STREAM(PROTOCOL_ERROR)")
    func malformedResponse() throws {
        let bad: [[HeaderField]] = [
            [HeaderField("x", "y")],                                         // Missing :status
            [HeaderField(":status", "200"), HeaderField(":status", "200")],  // Duplicate
            [HeaderField("x", "y"), HeaderField(":status", "200")],          // Pseudo-header after regular headers
            [HeaderField(":status", "20")],                                  // Not three digits
            [HeaderField(":status", "2x0")],
            [HeaderField(":status", "200"), HeaderField(":path", "/")],      // Pseudo-header not allowed in a response
            [HeaderField(":status", "200"), HeaderField("X-Upper", "1")],    // Uppercase name
        ]
        for fields in bad {
            var connection = try HTTP2ClientConnection.established()
            let first = try connection.startRequest(getRequest, body: nil)
            let second = try connection.startRequest(getRequest, body: nil)
            _ = connection.takeOutboundBytes()
            let block = HPACKEncoder.encode(fields)
            let events = try connection.receive(frameBytes(1, flags: 0x4, stream: 1, payload: block))
            #expect(events == [.streamClosed(first, resetCode: 1)])
            #expect(try connection.takeOutboundFrames() == [.rstStream(first, code: 1)])
            // Other streams are unaffected.
            #expect(try connection.receive(responseHeadBytes(stream: 3)) == [.responseHead(second, status: 200, headers: [])])
        }
    }

    @Test("DATA before response headers is a stream error")
    func dataBeforeHead() throws {
        var connection = try HTTP2ClientConnection.established()
        let id = try connection.startRequest(getRequest, body: nil)
        _ = connection.takeOutboundBytes()
        #expect(try connection.receive(dataBytes(stream: 1, [1])) == [.streamClosed(id, resetCode: 1)])
        #expect(try connection.takeOutboundFrames().contains(.rstStream(id, code: 1)))
    }

    @Test("A header block after the body (trailers) requires END_STREAM")
    func trailers() throws {
        var connection = try HTTP2ClientConnection.established()
        let id = try connection.startRequest(getRequest, body: nil)
        let trailer = frameBytes(1, flags: 0x5, stream: 1, payload: HPACKEncoder.encode([HeaderField("grpc-status", "0")]))
        let events = try connection.receive(responseHeadBytes(stream: 1) + dataBytes(stream: 1, [1]) + trailer)
        #expect(events.last == .streamClosed(id, resetCode: nil))

        var invalid = try HTTP2ClientConnection.established()
        let other = try invalid.startRequest(getRequest, body: nil)
        let notEnding = frameBytes(1, flags: 0x4, stream: 1, payload: HPACKEncoder.encode([HeaderField("grpc-status", "0")]))
        #expect(try invalid.receive(responseHeadBytes(stream: 1) + notEnding).last == .streamClosed(other, resetCode: 1))
    }

    @Test("Discards the rest of the request body if the server finishes its response before receiving the full body")
    func earlyResponse() throws {
        var connection = try HTTP2ClientConnection.established()
        let id = try connection.startRequest(
            HTTP2ClientConnection.Request(method: "POST", path: "/", authority: "tail0001"), body: [UInt8](repeating: 0, count: 100_000))
        _ = connection.takeOutboundBytes()
        let events = try connection.receive(responseHeadBytes(stream: 1, status: "413", endStream: true))
        #expect(events == [.responseHead(id, status: 413, headers: []), .streamClosed(id, resetCode: nil)])
        #expect(try connection.takeOutboundFrames() == [.rstStream(id, code: 8)])
        // Send no more data even after the window opens.
        _ = try connection.receive(windowUpdateBytes(stream: 0, increment: 100_000) + windowUpdateBytes(stream: 1, increment: 100_000))
        #expect(try connection.takeOutboundFrames().isEmpty)
    }
}
