// 계약 시험 2: 프레임. 각 type의 해석, 한 바이트씩 쪼개 넣어도 같은 사건, CONTINUATION 결합, 패딩.

import Testing

@testable import SwiftailHTTP2

@Suite("프레임 해석")
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

    @Test("패딩된 DATA: 내용에서는 빼고 흐름 제어 길이에는 센다")
    func paddedData() throws {
        // Pad Length 2, 내용 3바이트, 패딩 2바이트.
        let frame = frameBytes(0, flags: 0x8, stream: 1, payload: [2, 7, 8, 9, 0, 0])
        #expect(try parse(frame) == .data(HTTP2StreamID(1), [7, 8, 9], endStream: false, flowControlledLength: 6))
        // 패딩이 내용을 모두 차지하는 경우도 유효하다.
        #expect(try parse(frameBytes(0, flags: 0x8, stream: 1, payload: [1, 0])) == .data(HTTP2StreamID(1), [], endStream: false, flowControlledLength: 2))
    }

    @Test("패딩이 payload를 넘으면 PROTOCOL_ERROR, Pad Length가 없으면 FRAME_SIZE_ERROR")
    func invalidPadding() {
        expectConnectionError(.protocolError, frameBytes(0, flags: 0x8, stream: 1, payload: [4, 7, 8, 9]))
        expectConnectionError(.frameSizeError, frameBytes(0, flags: 0x8, stream: 1))
    }

    @Test("HEADERS: 패딩과 우선순위 필드를 벗긴다")
    func headers() throws {
        #expect(try parse(frameBytes(1, flags: 0x5, stream: 3, payload: [0x82])) == .headers(HTTP2StreamID(3), blockFragment: [0x82], endStream: true, endHeaders: true))
        // PADDED | PRIORITY | END_HEADERS: Pad Length 1, 우선순위 5바이트, 블록 0x82, 패딩 1바이트.
        let payload: [UInt8] = [1, 0, 0, 0, 0, 16, 0x82, 0]
        #expect(try parse(frameBytes(1, flags: 0x8 | 0x20 | 0x4, stream: 3, payload: payload)) == .headers(HTTP2StreamID(3), blockFragment: [0x82], endStream: false, endHeaders: true))
        expectConnectionError(.frameSizeError, frameBytes(1, flags: 0x20, stream: 3, payload: [0, 0, 0]))
    }

    @Test("PRIORITY는 읽고 버린다")
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

    @Test("SETTINGS와 ACK")
    func settings() throws {
        #expect(try parse(settingsBytes([(3, 100), (4, 65_535)])) == .settings([.init(identifier: 3, value: 100), .init(identifier: 4, value: 65_535)]))
        #expect(try parse(settingsBytes()) == .settings([]))
        #expect(try parse(frameBytes(4, flags: 0x1)) == .settingsAcknowledgement)
        expectConnectionError(.frameSizeError, frameBytes(4, flags: 0x1, payload: [0, 0, 0, 0, 0, 0]))
        expectConnectionError(.frameSizeError, frameBytes(4, payload: [0, 3, 0, 0, 0]))
        expectConnectionError(.protocolError, frameBytes(4, stream: 1))
    }

    @Test("PUSH_PROMISE는 구분만 한다")
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

    @Test("GOAWAY: 디버그 데이터는 버린다")
    func goAway() throws {
        #expect(try parse(goAwayBytes(lastStream: 7, code: 0)) == .goAway(lastStreamID: HTTP2StreamID(7), code: 0))
        let withDebug = frameBytes(7, payload: [0, 0, 0, 9, 0, 0, 0, 2] + Array("debug".utf8))
        #expect(try parse(withDebug) == .goAway(lastStreamID: HTTP2StreamID(9), code: 2))
        expectConnectionError(.frameSizeError, frameBytes(7, payload: [0, 0, 0, 1]))
    }

    @Test("WINDOW_UPDATE: 예약 비트는 무시")
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

    @Test("모르는 type은 무시하고, 스트림 식별자의 예약 비트는 버린다")
    func unknown() throws {
        #expect(try parse(frameBytes(0xfa, stream: 0x8000_0001, payload: [1, 2, 3])) == .unknown(type: 0xfa))
        let reserved = frameBytes(0, stream: 0x8000_0001, payload: [9])
        #expect(try parse(reserved) == .data(HTTP2StreamID(1), [9], endStream: false, flowControlledLength: 1))
    }

    @Test("스트림 0의 DATA·HEADERS는 PROTOCOL_ERROR")
    func streamZero() {
        expectConnectionError(.protocolError, dataBytes(stream: 0, [1]))
        expectConnectionError(.protocolError, frameBytes(1, flags: 0x4, payload: [0x82]))
    }

    @Test("보내는 프레임을 되읽으면 같다")
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

    @Test("긴 헤더 블록은 HEADERS와 CONTINUATION으로 나뉜다")
    func headerBlockSplit() throws {
        let block = [UInt8](0..<10)
        let frames = try parseFrames(FrameEncoder.headers(HTTP2StreamID(1), block: block, endStream: true, maximumPayloadLength: 4))
        #expect(frames == [
            .headers(HTTP2StreamID(1), blockFragment: [0, 1, 2, 3], endStream: true, endHeaders: false),
            .continuation(HTTP2StreamID(1), blockFragment: [4, 5, 6, 7], endHeaders: false),
            .continuation(HTTP2StreamID(1), blockFragment: [8, 9], endHeaders: true),
        ])
        // 정확히 나누어떨어져도 마지막 조각에 END_HEADERS가 붙고 빈 CONTINUATION은 없다.
        let exact = try parseFrames(FrameEncoder.headers(HTTP2StreamID(1), block: [1, 2, 3, 4], endStream: false, maximumPayloadLength: 2))
        #expect(exact == [
            .headers(HTTP2StreamID(1), blockFragment: [1, 2], endStream: false, endHeaders: false),
            .continuation(HTTP2StreamID(1), blockFragment: [3, 4], endHeaders: true),
        ])
    }
}

@Suite("프레임 경계와 헤더 블록 결합")
struct FrameBoundaryTests {
    /// 서버가 보내는 대화: SETTINGS, 연결 창 증가, 응답 머리(헤더 두 개), 본문 두 조각, 스트림 끝.
    private let transcript: [UInt8] = settingsBytes([(3, 250), (5, 16_384)])
        + windowUpdateBytes(stream: 0, increment: 983_041)
        + responseHeadBytes(stream: 1, headers: [HeaderField("content-type", "application/json"), HeaderField("x-n", "1")])
        + dataBytes(stream: 1, Array("hello ".utf8))
        + dataBytes(stream: 1, Array("world".utf8), endStream: true)

    @Test("한 바이트씩 쪼개 넣어도 한 번에 넣은 것과 같은 사건")
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

    @Test("임의의 두 조각으로 나눠도 같은 사건")
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

    @Test("HEADERS + CONTINUATION은 하나의 응답 머리가 된다")
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

    @Test("헤더 블록 사이에 다른 프레임이 끼면 PROTOCOL_ERROR")
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

    @Test("다른 스트림의 CONTINUATION과, 시작 없는 CONTINUATION")
    func wrongContinuation() throws {
        var other = try HTTP2ClientConnection.established()
        _ = try other.startRequest(getRequest, body: nil)
        #expect(throws: HTTP2Error.connection(.protocolError)) {
            try other.receive(frameBytes(1, stream: 1, payload: [0x88]) + frameBytes(9, flags: 0x4, stream: 3, payload: []))
        }
        var stray = try HTTP2ClientConnection.established()
        #expect(throws: HTTP2Error.connection(.protocolError)) { try stray.receive(frameBytes(9, flags: 0x4, stream: 1)) }
    }

    @Test("패딩된 DATA는 패딩을 뺀 본문을 내고 창은 패딩까지 돌려준다")
    func paddedDataEvent() throws {
        var connection = try HTTP2ClientConnection.established()
        let id = try connection.startRequest(getRequest, body: nil)
        _ = connection.takeOutboundBytes()
        let events = try connection.receive(
            responseHeadBytes(stream: 1) + frameBytes(0, flags: 0x8, stream: 1, payload: [2, 7, 8, 9, 0, 0]))
        #expect(events == [.responseHead(id, status: 200, headers: []), .responseData(id, [7, 8, 9])])
        #expect(try connection.takeOutboundFrames() == [.windowUpdate(.connection, increment: 6), .windowUpdate(id, increment: 6)])
    }

    @Test("한 번에 여러 프레임이 와도 모두 처리한다")
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
