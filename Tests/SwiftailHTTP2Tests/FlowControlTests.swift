// 계약 시험 3: 흐름 제어. 창보다 큰 본문이 WINDOW_UPDATE를 기다린다.
// SETTINGS_INITIAL_WINDOW_SIZE가 열린 스트림의 창을 바꾼다. 받은 DATA만큼 WINDOW_UPDATE를 낸다.

import Testing

@testable import SwiftailHTTP2

private let post = HTTP2ClientConnection.Request(method: "POST", path: "/machine/register", authority: "tail0001")

/// 보낸 프레임 가운데 DATA의 바이트 수 합과 END_STREAM 여부.
private func dataSent(_ frames: [Frame]) -> (bytes: Int, ended: Bool) {
    var total = 0
    var ended = false
    for case .data(_, let payload, let endStream, _) in frames {
        total += payload.count
        ended = ended || endStream
    }
    return (total, ended)
}

@Suite("보내는 쪽 흐름 제어")
struct SendFlowControlTests {
    @Test("창(65,535)보다 큰 본문은 연결과 스트림 창이 열릴 때까지 기다린다")
    func bodyWaitsForWindowUpdate() throws {
        var connection = try HTTP2ClientConnection.established()
        let id = try connection.startRequest(post, body: [UInt8](repeating: 7, count: 100_000))
        var sent = dataSent(try connection.takeOutboundFrames())
        #expect(sent.bytes == 65_535)
        #expect(!sent.ended)

        // 연결 창만 열어서는 나가지 않는다: 스트림 창이 0이다.
        _ = try connection.receive(windowUpdateBytes(stream: 0, increment: 40_000))
        #expect(try connection.takeOutboundFrames().isEmpty)

        // 스트림 창도 열리면 나머지 34,465바이트가 나가고 END_STREAM이 붙는다.
        _ = try connection.receive(windowUpdateBytes(stream: 1, increment: 40_000))
        sent = dataSent(try connection.takeOutboundFrames())
        #expect(sent.bytes == 34_465)
        #expect(sent.ended)
        _ = id
    }

    @Test("프레임은 상대의 MAX_FRAME_SIZE로 나뉜다")
    func splitByMaxFrameSize() throws {
        var connection = try HTTP2ClientConnection.established()
        _ = try connection.startRequest(post, body: [UInt8](repeating: 1, count: 40_000))
        let sizes = try connection.takeOutboundFrames().compactMap { frame -> Int? in
            if case .data(_, let payload, _, _) = frame { return payload.count }
            return nil
        }
        #expect(sizes == [16_384, 16_384, 7_232])

        var larger = try HTTP2ClientConnection.established(serverSettings: [(5, 30_000)])
        _ = try larger.startRequest(post, body: [UInt8](repeating: 1, count: 40_000))
        let largerSizes = try larger.takeOutboundFrames().compactMap { frame -> Int? in
            if case .data(_, let payload, _, _) = frame { return payload.count }
            return nil
        }
        #expect(largerSizes == [30_000, 10_000])
    }

    @Test("본문이 비어 있으면 빈 DATA로 요청을 끝낸다")
    func emptyBody() throws {
        var connection = try HTTP2ClientConnection.established()
        let id = try connection.startRequest(post, body: [])
        let frames = try connection.takeOutboundFrames()
        #expect(frames.count == 2)
        guard case .headers(_, _, let headersEnd, _) = frames[0] else { Issue.record("HEADERS가 아니다"); return }
        #expect(!headersEnd)
        #expect(frames[1] == .data(id, [], endStream: true, flowControlledLength: 0))
    }

    @Test("SETTINGS_INITIAL_WINDOW_SIZE가 서버 SETTINGS 전에 열린 스트림의 창을 바꾼다")
    func initialWindowSizeChangesOpenStreams() throws {
        var connection = try HTTP2ClientConnection.established(serverSettings: [(4, 10)])
        _ = try connection.startRequest(post, body: [UInt8](repeating: 1, count: 25))
        #expect(dataSent(try connection.takeOutboundFrames()).bytes == 10)

        // 10 → 30: 열린 스트림의 창이 +20 되어 나머지 15바이트가 나간다.
        _ = try connection.receive(settingsBytes([(4, 30)]))
        let frames = try connection.takeOutboundFrames()
        #expect(frames.first == .settingsAcknowledgement)
        let sent = dataSent(frames)
        #expect(sent.bytes == 15)
        #expect(sent.ended)
    }

    @Test("INITIAL_WINDOW_SIZE를 줄이면 창이 음수가 되고, 0 이하일 때는 보내지 않는다")
    func windowCanGoNegative() throws {
        var connection = try HTTP2ClientConnection.established(serverSettings: [(4, 100)])
        let id = try connection.startRequest(post, body: [UInt8](repeating: 1, count: 150))
        #expect(dataSent(try connection.takeOutboundFrames()).bytes == 100)  // 창 0

        _ = try connection.receive(settingsBytes([(4, 50)]))  // 창 -50
        _ = connection.takeOutboundBytes()
        _ = try connection.receive(windowUpdateBytes(stream: 1, increment: 40))  // 창 -10
        #expect(dataSent(try connection.takeOutboundFrames()).bytes == 0)

        _ = try connection.receive(windowUpdateBytes(stream: 1, increment: 60))  // 창 50
        let sent = dataSent(try connection.takeOutboundFrames())
        #expect(sent.bytes == 50)
        #expect(sent.ended)
        _ = id
    }

    @Test("연결 창은 스트림들이 나눠 쓴다")
    func connectionWindowShared() throws {
        var connection = try HTTP2ClientConnection.established(serverSettings: [(4, 1_000_000)])
        _ = try connection.startRequest(post, body: [UInt8](repeating: 1, count: 50_000))
        _ = try connection.startRequest(post, body: [UInt8](repeating: 2, count: 50_000))
        let sent = dataSent(try connection.takeOutboundFrames())
        #expect(sent.bytes == 65_535)  // 두 스트림이 연결 창 하나를 나눈다
    }

    @Test("창을 2^31-1 넘게 키우면 연결은 FLOW_CONTROL_ERROR, 스트림은 RST_STREAM")
    func windowOverflow() throws {
        var connection = try HTTP2ClientConnection.established()
        #expect(throws: HTTP2Error.connection(.flowControlError)) { try connection.receive(windowUpdateBytes(stream: 0, increment: 0x7fff_ffff)) }

        var streamLevel = try HTTP2ClientConnection.established()
        let id = try streamLevel.startRequest(post, body: [1])
        _ = streamLevel.takeOutboundBytes()
        let events = try streamLevel.receive(windowUpdateBytes(stream: 1, increment: 0x7fff_ffff))
        #expect(events == [.streamClosed(id, resetCode: 3)])
        #expect(try streamLevel.takeOutboundFrames() == [.rstStream(id, code: 3)])

        var settings = try HTTP2ClientConnection.established()
        #expect(throws: HTTP2Error.connection(.flowControlError)) { try settings.receive(settingsBytes([(4, 0x8000_0000)])) }
    }

    @Test("증가량 0은 연결이면 PROTOCOL_ERROR, 스트림이면 RST_STREAM")
    func zeroIncrement() throws {
        var connection = try HTTP2ClientConnection.established()
        let id = try connection.startRequest(getRequest, body: nil)
        _ = connection.takeOutboundBytes()
        #expect(try connection.receive(windowUpdateBytes(stream: 1, increment: 0)) == [.streamClosed(id, resetCode: 1)])
        #expect(throws: HTTP2Error.connection(.protocolError)) { try connection.receive(windowUpdateBytes(stream: 0, increment: 0)) }
    }
}

@Suite("받는 쪽 흐름 제어")
struct ReceiveFlowControlTests {
    @Test("받은 DATA만큼 연결과 스트림 창을 곧바로 돌려준다")
    func windowUpdatesForData() throws {
        var connection = try HTTP2ClientConnection.established()
        let id = try connection.startRequest(getRequest, body: nil)
        _ = connection.takeOutboundBytes()
        _ = try connection.receive(responseHeadBytes(stream: 1))
        #expect(try connection.takeOutboundFrames().isEmpty)

        _ = try connection.receive(dataBytes(stream: 1, [UInt8](repeating: 9, count: 1_000)))
        #expect(try connection.takeOutboundFrames() == [.windowUpdate(.connection, increment: 1_000), .windowUpdate(id, increment: 1_000)])
    }

    @Test("END_STREAM이 붙은 DATA는 연결 창만 돌려준다")
    func finalData() throws {
        var connection = try HTTP2ClientConnection.established()
        _ = try connection.startRequest(getRequest, body: nil)
        _ = connection.takeOutboundBytes()
        _ = try connection.receive(responseHeadBytes(stream: 1))
        _ = try connection.receive(dataBytes(stream: 1, [1, 2, 3], endStream: true))
        #expect(try connection.takeOutboundFrames() == [.windowUpdate(.connection, increment: 3)])
    }

    @Test("취소한 스트림에 늦게 도착한 DATA도 연결 창은 돌려준다")
    func dataAfterCancel() throws {
        var connection = try HTTP2ClientConnection.established()
        let id = try connection.startRequest(getRequest, body: nil)
        connection.cancel(id)
        _ = connection.takeOutboundBytes()
        let events = try connection.receive(dataBytes(stream: 1, [UInt8](repeating: 0, count: 500)))
        #expect(events.isEmpty)
        #expect(try connection.takeOutboundFrames() == [.windowUpdate(.connection, increment: 500)])
    }

    @Test("빈 DATA는 창을 돌려주지 않는다")
    func emptyData() throws {
        var connection = try HTTP2ClientConnection.established()
        _ = try connection.startRequest(getRequest, body: nil)
        _ = connection.takeOutboundBytes()
        _ = try connection.receive(responseHeadBytes(stream: 1) + dataBytes(stream: 1, []))
        #expect(try connection.takeOutboundFrames().isEmpty)
    }
}
