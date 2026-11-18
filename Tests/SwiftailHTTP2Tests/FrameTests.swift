// Contract test 2: Frames. Parsing each type, identical events with one-byte chunks, CONTINUATION assembly, and padding.

import Testing

@testable import SwiftailHTTP2

@Suite("Frame parsing")
struct FrameParsingTests {
    private func parse(_ bytes: [UInt8]) throws -> Frame? {
        try parseFrames(bytes).first
    }

    private func expectConnectionError(_ code: HTTP2ErrorCode, _ bytes: [UInt8], sourceLocation: SourceLocation = #_sourceLocation) {
        #expect(throws: HTTP2Error.connection(code), sourceLocation: sourceLocation) { try parseFrames(bytes) }
    }

    @Test("DATA")
    func data() throws {
        #expect(try parse(dataBytes(stream: 1, [1, 2, 3], endStream: true)) == .data(HTTP2StreamID(1), [1, 2, 3], endStream: true, flowControlledLength: 3))
    }

    @Test("Padded DATA excludes padding from content and counts it toward the flow-control length")
    func paddedData() throws {
        // Pad Length 2, 3 content bytes, and 2 padding bytes.
        let frame = frameBytes(0, flags: 0x8, stream: 1, payload: [2, 7, 8, 9, 0, 0])
        #expect(try parse(frame) == .data(HTTP2StreamID(1), [7, 8, 9], endStream: false, flowControlledLength: 6))
        // Padding can also take up all the content.
        #expect(try parse(frameBytes(0, flags: 0x8, stream: 1, payload: [1, 0])) == .data(HTTP2StreamID(1), [], endStream: false, flowControlledLength: 2))
    }

    @Test("Padding beyond the payload yields PROTOCOL_ERROR, and missing Pad Length yields FRAME_SIZE_ERROR")
    func invalidPadding() {
        expectConnectionError(.protocolError, frameBytes(0, flags: 0x8, stream: 1, payload: [4, 7, 8, 9]))
        expectConnectionError(.frameSizeError, frameBytes(0, flags: 0x8, stream: 1))
    }

    @Test("HEADERS strips padding and priority fields")
    func headers() throws {
        #expect(try parse(frameBytes(1, flags: 0x5, stream: 3, payload: [0x82])) == .headers(HTTP2StreamID(3), blockFragment: [0x82], endStream: true, endHeaders: true))
        // PADDED | PRIORITY | END_HEADERS: Pad Length 1, 5 priority bytes, block 0x82, and 1 padding byte.
        let payload: [UInt8] = [1, 0, 0, 0, 0, 16, 0x82, 0]
        #expect(try parse(frameBytes(1, flags: 0x8 | 0x20 | 0x4, stream: 3, payload: payload)) == .headers(HTTP2StreamID(3), blockFragment: [0x82], endStream: false, endHeaders: true))
        expectConnectionError(.frameSizeError, frameBytes(1, flags: 0x20, stream: 3, payload: [0, 0, 0]))
    }

    @Test("Reads and discards PRIORITY")
    func priority() throws {
        #expect(try parse(frameBytes(2, stream: 3, payload: [0, 0, 0, 1, 15])) == .priority)
        expectConnectionError(.frameSizeError, frameBytes(2, stream: 3, payload: [0, 0, 0, 1]))
    }

    @Test("RST_STREAM")
    func rstStream() throws {
        #expect(try parse(rstStreamBytes(stream: 5, code: 8)) == .rstStream(HTTP2StreamID(5), code: 8))
        expectConnectionError(.frameSizeError, frameBytes(3, stream: 5, payload: [0, 0, 0]))
        expectConnectionError(.protocolError, rstStreamBytes(stream: 0, code: 8))
    }

    @Test("SETTINGS and ACK")
    func settings() throws {
        #expect(try parse(settingsBytes([(3, 100), (4, 65_535)])) == .settings([.init(identifier: 3, value: 100), .init(identifier: 4, value: 65_535)]))
        #expect(try parse(settingsBytes()) == .settings([]))
        #expect(try parse(frameBytes(4, flags: 0x1)) == .settingsAcknowledgement)
        expectConnectionError(.frameSizeError, frameBytes(4, flags: 0x1, payload: [0, 0, 0, 0, 0, 0]))
        expectConnectionError(.frameSizeError, frameBytes(4, payload: [0, 3, 0, 0, 0]))
        expectConnectionError(.protocolError, frameBytes(4, stream: 1))
    }

    @Test("Only distinguishes PUSH_PROMISE")
    func pushPromise() throws {
        #expect(try parse(frameBytes(5, flags: 0x4, stream: 1, payload: [0, 0, 0, 2, 0x82])) == .pushPromise)
    }

    @Test("PING")
    func ping() throws {
        let data: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8]
        #expect(try parse(frameBytes(6, payload: data)) == .ping(ack: false, data: data))
        #expect(try parse(frameBytes(6, flags: 0x1, payload: data)) == .ping(ack: true, data: data))
        expectConnectionError(.frameSizeError, frameBytes(6, payload: [1, 2, 3]))
        expectConnectionError(.protocolError, frameBytes(6, stream: 1, payload: data))
    }

    @Test("GOAWAY discards debug data")
    func goAway() throws {
        #expect(try parse(goAwayBytes(lastStream: 7, code: 0)) == .goAway(lastStreamID: HTTP2StreamID(7), code: 0))
        let withDebug = frameBytes(7, payload: [0, 0, 0, 9, 0, 0, 0, 2] + Array("debug".utf8))
        #expect(try parse(withDebug) == .goAway(lastStreamID: HTTP2StreamID(9), code: 2))
        expectConnectionError(.frameSizeError, frameBytes(7, payload: [0, 0, 0, 1]))
    }

    @Test("WINDOW_UPDATE ignores the reserved bit")
    func windowUpdate() throws {
        #expect(try parse(windowUpdateBytes(stream: 0, increment: 983_041)) == .windowUpdate(.connection, increment: 983_041))
        #expect(try parse(windowUpdateBytes(stream: 3, increment: 0x8000_0010)) == .windowUpdate(HTTP2StreamID(3), increment: 0x10))
        expectConnectionError(.frameSizeError, frameBytes(8, payload: [0, 0, 1]))
    }

    @Test("CONTINUATION")
    func continuation() throws {
        #expect(try parse(frameBytes(9, flags: 0x4, stream: 1, payload: [0x82])) == .continuation(HTTP2StreamID(1), blockFragment: [0x82], endHeaders: true))
        expectConnectionError(.protocolError, frameBytes(9, payload: [0x82]))
    }

    @Test("Ignores unknown types and discards the reserved bit of the stream identifier")
    func unknown() throws {
        #expect(try parse(frameBytes(0xfa, stream: 0x8000_0001, payload: [1, 2, 3])) == .unknown(type: 0xfa))
        let reserved = frameBytes(0, stream: 0x8000_0001, payload: [9])
        #expect(try parse(reserved) == .data(HTTP2StreamID(1), [9], endStream: false, flowControlledLength: 1))
    }

    @Test("DATA and HEADERS on stream 0 yield PROTOCOL_ERROR")
    func streamZero() {
        expectConnectionError(.protocolError, dataBytes(stream: 0, [1]))
        expectConnectionError(.protocolError, frameBytes(1, flags: 0x4, payload: [0x82]))
    }

    @Test("Outbound frames parse back to the same values")
    func encoderRoundTrip() throws {
        let id = HTTP2StreamID(1)
        #expect(try parseFrames(FrameEncoder.settings([.init(identifier: 2, value: 0)])) == [.settings([.init(identifier: 2, value: 0)])])
        #expect(try parseFrames(FrameEncoder.settingsAcknowledgement()) == [.settingsAcknowledgement])
        #expect(try parseFrames(FrameEncoder.rstStream(id, code: .cancel)) == [.rstStream(id, code: 8)])
        #expect(try parseFrames(FrameEncoder.pingAcknowledgement([1, 2, 3, 4, 5, 6, 7, 8])) == [.ping(ack: true, data: [1, 2, 3, 4, 5, 6, 7, 8])])
        #expect(try parseFrames(FrameEncoder.goAway(lastStreamID: id, code: 1)) == [.goAway(lastStreamID: id, code: 1)])
        #expect(try parseFrames(FrameEncoder.windowUpdate(id, increment: 99)) == [.windowUpdate(id, increment: 99)])
        #expect(try parseFrames(FrameEncoder.data(id, [1, 2][...], endStream: true)) == [.data(id, [1, 2], endStream: true, flowControlledLength: 2)])
    }

    @Test("A long header block is split into HEADERS and CONTINUATION")
    func headerBlockSplit() throws {
        let block = [UInt8](0..<10)
        let frames = try parseFrames(FrameEncoder.headers(HTTP2StreamID(1), block: block, endStream: true, maximumPayloadLength: 4))
        #expect(frames == [
            .headers(HTTP2StreamID(1), blockFragment: [0, 1, 2, 3], endStream: true, endHeaders: false),
            .continuation(HTTP2StreamID(1), blockFragment: [4, 5, 6, 7], endHeaders: false),
            .continuation(HTTP2StreamID(1), blockFragment: [8, 9], endHeaders: true),
        ])
        // Even when the block divides evenly, the last fragment carries END_HEADERS and there is no empty CONTINUATION.
        let exact = try parseFrames(FrameEncoder.headers(HTTP2StreamID(1), block: [1, 2, 3, 4], endStream: false, maximumPayloadLength: 2))
        #expect(exact == [
            .headers(HTTP2StreamID(1), blockFragment: [1, 2], endStream: false, endHeaders: false),
            .continuation(HTTP2StreamID(1), blockFragment: [3, 4], endHeaders: true),
        ])
    }
}

@Suite("Frame boundaries and header block assembly")
struct FrameBoundaryTests {
    /// Server-side exchange: SETTINGS, connection window increase, response headers (two headers), two body chunks, and end of stream.
    private let transcript: [UInt8] = settingsBytes([(3, 250), (5, 16_384)])
        + windowUpdateBytes(stream: 0, increment: 983_041)
        + responseHeadBytes(stream: 1, headers: [HeaderField("content-type", "application/json"), HeaderField("x-n", "1")])
        + dataBytes(stream: 1, Array("hello ".utf8))
        + dataBytes(stream: 1, Array("world".utf8), endStream: true)

    @Test("Feeding one byte at a time produces the same events as feeding all bytes at once")
    func byteByByte() throws {
        var whole = HTTP2ClientConnection()
        let id = try whole.startRequest(getRequest, body: nil)
        let wholeEvents = try whole.receive(transcript)

        var pieces = HTTP2ClientConnection()
        _ = try pieces.startRequest(getRequest, body: nil)
        var pieceEvents: [HTTP2ClientConnection.Event] = []
        for byte in transcript { pieceEvents += try pieces.receive([byte]) }

        #expect(wholeEvents == pieceEvents)
        #expect(wholeEvents == [
            .responseHead(id, status: 200, headers: [HeaderField("content-type", "application/json"), HeaderField("x-n", "1")]),
            .responseData(id, Array("hello ".utf8)),
            .responseData(id, Array("world".utf8)),
            .streamClosed(id, resetCode: nil),
        ])
        #expect(whole.takeOutboundBytes() == pieces.takeOutboundBytes())
    }

    @Test("Splitting into two arbitrary chunks yields the same events")
    func everySplit() throws {
        var reference = HTTP2ClientConnection()
        _ = try reference.startRequest(getRequest, body: nil)
        let expected = try reference.receive(transcript)
        for split in 0...transcript.count {
            var connection = HTTP2ClientConnection()
            _ = try connection.startRequest(getRequest, body: nil)
            let events = try connection.receive(Array(transcript[..<split])) + connection.receive(Array(transcript[split...]))
            #expect(events == expected)
        }
    }

    @Test("HEADERS and CONTINUATION form a single response header section")
    func continuationJoined() throws {
        var connection = try HTTP2ClientConnection.established()
        let id = try connection.startRequest(getRequest, body: nil)
        let block = HPACKEncoder.encode([HeaderField(":status", "200"), HeaderField("x-a", "1"), HeaderField("x-b", "2")])
        let events = try connection.receive(
            frameBytes(1, flags: 0x0, stream: 1, payload: Array(block[..<5]))
                + frameBytes(9, stream: 1, payload: Array(block[5..<12]))
                + frameBytes(9, flags: 0x4, stream: 1, payload: Array(block[12...])))
        #expect(events == [.responseHead(id, status: 200, headers: [HeaderField("x-a", "1"), HeaderField("x-b", "2")])])
    }

    @Test("Another frame between header block fragments yields PROTOCOL_ERROR")
    func interleaved() throws {
        var connection = try HTTP2ClientConnection.established()
        _ = try connection.startRequest(getRequest, body: nil)
        _ = connection.takeOutboundBytes()
        let block = HPACKEncoder.encode([HeaderField(":status", "200")])
        #expect(throws: HTTP2Error.connection(.protocolError)) {
            try connection.receive(frameBytes(1, stream: 1, payload: block) + frameBytes(6, payload: [UInt8](repeating: 0, count: 8)))
        }
        #expect(try connection.takeOutboundFrames() == [.goAway(lastStreamID: .connection, code: 1)])
    }

    @Test("CONTINUATION on another stream and CONTINUATION without a start")
    func wrongContinuation() throws {
        var other = try HTTP2ClientConnection.established()
        _ = try other.startRequest(getRequest, body: nil)
        #expect(throws: HTTP2Error.connection(.protocolError)) {
            try other.receive(frameBytes(1, stream: 1, payload: [0x88]) + frameBytes(9, flags: 0x4, stream: 3, payload: []))
        }
        var stray = try HTTP2ClientConnection.established()
        #expect(throws: HTTP2Error.connection(.protocolError)) { try stray.receive(frameBytes(9, flags: 0x4, stream: 1)) }
    }

    @Test("Padded DATA yields a body without padding and restores window credit including padding")
    func paddedDataEvent() throws {
        var connection = try HTTP2ClientConnection.established()
        let id = try connection.startRequest(getRequest, body: nil)
        _ = connection.takeOutboundBytes()
        let events = try connection.receive(
            responseHeadBytes(stream: 1) + frameBytes(0, flags: 0x8, stream: 1, payload: [2, 7, 8, 9, 0, 0]))
        #expect(events == [.responseHead(id, status: 200, headers: []), .responseData(id, [7, 8, 9])])
        #expect(try connection.takeOutboundFrames() == [.windowUpdate(.connection, increment: 6), .windowUpdate(id, increment: 6)])
    }

    @Test("Processes every frame when several arrive at once")
    func manyFramesAtOnce() throws {
        var connection = try HTTP2ClientConnection.established()
        let first = try connection.startRequest(getRequest, body: nil)
        let second = try connection.startRequest(getRequest, body: nil)
        let events = try connection.receive(
            responseHeadBytes(stream: 3, endStream: true) + responseHeadBytes(stream: 1, status: "404", endStream: true))
        #expect(events == [
            .responseHead(second, status: 200, headers: []), .streamClosed(second, resetCode: nil),
            .responseHead(first, status: 404, headers: []), .streamClosed(first, resetCode: nil),
        ])
    }
}
