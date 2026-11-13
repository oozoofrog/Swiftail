// 계약 시험 4: 수명. SETTINGS ACK, PING 응답, GOAWAY 뒤 새 요청 거절, RST_STREAM, 스트림 ID가 홀수로 증가.

import Testing

@testable import SwiftailHTTP2

@Suite("연결 시작과 SETTINGS")
struct HandshakeTests {
    @Test("프리페이스 24바이트와 SETTINGS(푸시 끔)를 보낸다")
    func clientPreface() throws {
        var connection = HTTP2ClientConnection()
        let bytes = connection.takeOutboundBytes()
        #expect(Array(bytes.prefix(24)) == Array("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8))
        let frames = try parseFrames(Array(bytes.dropFirst(24)))
        #expect(frames == [.settings([.init(identifier: 2, value: 0), .init(identifier: 6, value: 65_536)])])
        #expect(connection.takeOutboundBytes().isEmpty)
    }

    @Test("서버 SETTINGS에는 ACK로 답하고 ACK에는 답하지 않는다")
    func settingsAcknowledged() throws {
        var connection = HTTP2ClientConnection()
        _ = connection.takeOutboundBytes()
        _ = try connection.receive(settingsBytes([(3, 250), (5, 1_048_576), (4, 1_048_576), (1, 4_096)]))
        #expect(try connection.takeOutboundFrames() == [.settingsAcknowledgement])
        _ = try connection.receive(frameBytes(4, flags: 0x1))
        #expect(connection.takeOutboundBytes().isEmpty)
    }

    @Test("모르는 SETTINGS와 모르는 프레임 type은 무시한다")
    func unknownIgnored() throws {
        var connection = HTTP2ClientConnection()
        _ = connection.takeOutboundBytes()
        _ = try connection.receive(settingsBytes([(0x00ff, 12345)]))
        _ = connection.takeOutboundBytes()
        #expect(try connection.receive(frameBytes(0xee, stream: 5, payload: [1, 2, 3])).isEmpty)
        #expect(connection.takeOutboundBytes().isEmpty)
    }

    @Test("서버의 첫 프레임이 SETTINGS가 아니면 연결 오류")
    func firstFrameMustBeSettings() throws {
        var connection = HTTP2ClientConnection()
        _ = connection.takeOutboundBytes()
        #expect(throws: HTTP2Error.connectionFailed(code: 1)) { try connection.receive(windowUpdateBytes(stream: 0, increment: 1)) }
    }

    @Test("규격 밖 SETTINGS 값은 연결 오류")
    func invalidSettings() throws {
        for setting: (UInt16, UInt32) in [(2, 1), (2, 2), (5, 16_383), (5, 16_777_216)] {
            var connection = HTTP2ClientConnection()
            #expect(throws: HTTP2Error.connectionFailed(code: 1)) { try connection.receive(settingsBytes([setting])) }
        }
    }

    @Test("PUSH_PROMISE는 연결 오류")
    func pushPromiseRejected() throws {
        var connection = try HTTP2ClientConnection.established()
        _ = try connection.startRequest(getRequest, body: nil)
        _ = connection.takeOutboundBytes()
        #expect(throws: HTTP2Error.connectionFailed(code: 1)) {
            try connection.receive(frameBytes(5, flags: 0x4, stream: 1, payload: [0, 0, 0, 2, 0x82]))
        }
    }
}

@Suite("PING, GOAWAY, 오류 뒤")
struct ConnectionLifetimeTests {
    @Test("PING은 같은 8바이트로 ACK하고 ACK에는 답하지 않는다")
    func ping() throws {
        var connection = try HTTP2ClientConnection.established()
        let data: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8]
        _ = try connection.receive(frameBytes(6, payload: data))
        #expect(try connection.takeOutboundFrames() == [.ping(ack: true, data: data)])
        _ = try connection.receive(frameBytes(6, flags: 0x1, payload: data))
        #expect(connection.takeOutboundBytes().isEmpty)
    }

    @Test("GOAWAY 뒤에는 새 요청을 거절하고, 처리된 스트림은 끝까지 받는다")
    func goAway() throws {
        var connection = try HTTP2ClientConnection.established()
        let first = try connection.startRequest(getRequest, body: nil)
        let second = try connection.startRequest(getRequest, body: nil)
        _ = connection.takeOutboundBytes()
        let events = try connection.receive(goAwayBytes(lastStream: 1, code: 0))
        #expect(events == [.goAway(lastStreamID: first, code: 0)])
        #expect(throws: HTTP2Error.connectionClosed) { try connection.startRequest(getRequest, body: nil) }

        // 처리된 스트림 1은 응답을 마칠 수 있다. 처리되지 않은 3은 버려졌다.
        let rest = try connection.receive(responseHeadBytes(stream: 1, endStream: true) + responseHeadBytes(stream: 3, endStream: true))
        #expect(rest == [.responseHead(first, status: 200, headers: []), .streamClosed(first, resetCode: nil)])
        _ = second
    }

    @Test("오류 코드가 있는 GOAWAY도 사건으로 알리고 새 요청은 거절한다")
    func goAwayWithError() throws {
        var connection = try HTTP2ClientConnection.established()
        let events = try connection.receive(goAwayBytes(lastStream: 0, code: 1))
        #expect(events == [.goAway(lastStreamID: HTTP2StreamID(0), code: 1)])
        #expect(throws: HTTP2Error.connectionClosed) { try connection.startRequest(getRequest, body: nil) }
    }

    @Test("연결 오류 뒤: GOAWAY가 남고, 이후 입력과 요청은 connectionClosed")
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

@Suite("스트림 수명")
struct StreamLifetimeTests {
    @Test("스트림 ID는 1부터 홀수로 증가한다")
    func oddIncreasingIDs() throws {
        var connection = try HTTP2ClientConnection.established()
        let ids = try (0..<4).map { _ in try connection.startRequest(getRequest, body: nil).rawValue }
        #expect(ids == [1, 3, 5, 7])
        let frames = try connection.takeOutboundFrames()
        #expect(frames.count == 4)
        guard case .headers(let id, _, let endStream, let endHeaders) = frames[0] else { Issue.record("HEADERS가 아니다"); return }
        #expect(id == HTTP2StreamID(1) && endStream && endHeaders)
    }

    @Test("요청 HEADERS는 의사 헤더가 앞에 오고 :scheme은 https다")
    func requestHeaders() throws {
        var connection = try HTTP2ClientConnection.established()
        let request = HTTP2ClientConnection.Request(
            method: "POST", path: "/machine/map", authority: "tail0001",
            headers: [HeaderField("content-type", "application/json"), HeaderField("ts-lb", "nodekey:abc")])
        _ = try connection.startRequest(request, body: [1, 2])
        guard case .headers(_, let block, _, _) = try connection.takeOutboundFrames().first else { Issue.record("HEADERS가 아니다"); return }
        var decoder = HPACKDecoder()
        #expect(try decoder.decode(block) == [
            HeaderField(":method", "POST"), HeaderField(":scheme", "https"), HeaderField(":authority", "tail0001"),
            HeaderField(":path", "/machine/map"), HeaderField("content-type", "application/json"), HeaderField("ts-lb", "nodekey:abc"),
        ])
    }

    @Test("RST_STREAM을 받으면 스트림이 오류 코드와 함께 닫힌다")
    func receivedReset() throws {
        var connection = try HTTP2ClientConnection.established()
        let id = try connection.startRequest(getRequest, body: nil)
        #expect(try connection.receive(rstStreamBytes(stream: 1, code: 7)) == [.streamClosed(id, resetCode: 7)])
        // 이미 끝난 스트림의 RST_STREAM은 무시한다.
        #expect(try connection.receive(rstStreamBytes(stream: 1, code: 0)).isEmpty)
    }

    @Test("요청한 적 없는 스트림의 프레임은 연결 오류")
    func idleStream() throws {
        for frame in [rstStreamBytes(stream: 3, code: 0), dataBytes(stream: 3, [1]), responseHeadBytes(stream: 2), windowUpdateBytes(stream: 5, increment: 1)] {
            var connection = try HTTP2ClientConnection.established()
            _ = try connection.startRequest(getRequest, body: nil)
            #expect(throws: HTTP2Error.connectionFailed(code: 1)) { try connection.receive(frame) }
        }
    }

    @Test("cancel은 RST_STREAM(CANCEL)을 보내고, 끝난 스트림에는 아무 일도 없다")
    func cancel() throws {
        var connection = try HTTP2ClientConnection.established()
        let id = try connection.startRequest(getRequest, body: nil)
        _ = connection.takeOutboundBytes()
        connection.cancel(id)
        #expect(try connection.takeOutboundFrames() == [.rstStream(id, code: 8)])
        connection.cancel(id)
        connection.cancel(HTTP2StreamID(99))
        #expect(connection.takeOutboundBytes().isEmpty)
        // 취소한 스트림에 늦게 온 응답은 조용히 버리되 헤더 블록은 해제한다.
        let late = try connection.receive(responseHeadBytes(stream: 1, headers: [HeaderField("x", "y")]))
        #expect(late.isEmpty)
    }

    @Test("동시 스트림 수는 상대의 MAX_CONCURRENT_STREAMS까지")
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

    @Test("잘못된 요청")
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
        // 거절한 요청은 스트림 ID를 쓰지 않는다.
        #expect(try connection.startRequest(getRequest, body: nil).rawValue == 1)
    }
}

@Suite("응답 처리")
struct ResponseTests {
    @Test("작은 GET: 머리, 본문, 끝")
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

    @Test("끝나지 않는 응답은 다른 요청과 함께 진행된다")
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

    @Test("1xx 임시 응답은 건너뛰고 최종 응답을 낸다")
    func informational() throws {
        var connection = try HTTP2ClientConnection.established()
        let id = try connection.startRequest(getRequest, body: nil)
        let events = try connection.receive(responseHeadBytes(stream: 1, status: "100") + responseHeadBytes(stream: 1, status: "204", endStream: true))
        #expect(events == [.responseHead(id, status: 204, headers: []), .streamClosed(id, resetCode: nil)])
    }

    @Test("잘못된 응답은 그 스트림만 RST_STREAM(PROTOCOL_ERROR)으로 끊는다")
    func malformedResponse() throws {
        let bad: [[HeaderField]] = [
            [HeaderField("x", "y")],                                         // :status 없음
            [HeaderField(":status", "200"), HeaderField(":status", "200")],  // 중복
            [HeaderField("x", "y"), HeaderField(":status", "200")],          // 의사 헤더가 뒤에
            [HeaderField(":status", "20")],                                  // 세 자리가 아님
            [HeaderField(":status", "2x0")],
            [HeaderField(":status", "200"), HeaderField(":path", "/")],      // 응답에 없는 의사 헤더
            [HeaderField(":status", "200"), HeaderField("X-Upper", "1")],    // 대문자 이름
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
            // 다른 스트림은 영향이 없다.
            #expect(try connection.receive(responseHeadBytes(stream: 3)) == [.responseHead(second, status: 200, headers: [])])
        }
    }

    @Test("응답 머리 전의 DATA는 스트림 오류")
    func dataBeforeHead() throws {
        var connection = try HTTP2ClientConnection.established()
        let id = try connection.startRequest(getRequest, body: nil)
        _ = connection.takeOutboundBytes()
        #expect(try connection.receive(dataBytes(stream: 1, [1])) == [.streamClosed(id, resetCode: 1)])
        #expect(try connection.takeOutboundFrames().contains(.rstStream(id, code: 1)))
    }

    @Test("본문 뒤의 헤더 블록(트레일러)은 END_STREAM일 때만")
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

    @Test("서버가 요청 본문을 다 받기 전에 응답을 끝내면 남은 본문을 접는다")
    func earlyResponse() throws {
        var connection = try HTTP2ClientConnection.established()
        let id = try connection.startRequest(
            HTTP2ClientConnection.Request(method: "POST", path: "/", authority: "tail0001"), body: [UInt8](repeating: 0, count: 100_000))
        _ = connection.takeOutboundBytes()
        let events = try connection.receive(responseHeadBytes(stream: 1, status: "413", endStream: true))
        #expect(events == [.responseHead(id, status: 413, headers: []), .streamClosed(id, resetCode: nil)])
        #expect(try connection.takeOutboundFrames() == [.rstStream(id, code: 8)])
        // 창이 열려도 더는 보내지 않는다.
        _ = try connection.receive(windowUpdateBytes(stream: 0, increment: 100_000) + windowUpdateBytes(stream: 1, increment: 100_000))
        #expect(try connection.takeOutboundFrames().isEmpty)
    }
}
