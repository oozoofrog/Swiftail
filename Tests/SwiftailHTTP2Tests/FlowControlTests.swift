// Contract test 3: Flow control. A body larger than the window waits for WINDOW_UPDATE.
// SETTINGS_INITIAL_WINDOW_SIZE changes open stream windows. Send WINDOW_UPDATE for the amount of DATA received.

import Testing

@testable import SwiftailHTTP2

private let post = HTTP2ClientConnection.Request(method: "POST", path: "/machine/register", authority: "tail0001")

/// Total DATA bytes and whether END_STREAM is present in the sent frames.
private func dataSent(_ frames: [Frame]) -> (bytes: Int, ended: Bool) {
    var total = 0
    var ended = false
    for case .data(_, let payload, let endStream, _) in frames {
        total += payload.count
        ended = ended || endStream
    }
    return (total, ended)
}

@Suite("Send-side flow control")
struct SendFlowControlTests {
    @Test("A body larger than the window (65,535) waits for both the connection and stream windows to open")
    func bodyWaitsForWindowUpdate() throws {
        var connection = try HTTP2ClientConnection.established()
        let id = try connection.startRequest(post, body: [UInt8](repeating: 7, count: 100_000))
        var sent = dataSent(try connection.takeOutboundFrames())
        #expect(sent.bytes == 65_535)
        #expect(!sent.ended)

        // Opening only the connection window sends nothing because the stream window is 0.
        _ = try connection.receive(windowUpdateBytes(stream: 0, increment: 40_000))
        #expect(try connection.takeOutboundFrames().isEmpty)

        // When the stream window also opens, the remaining 34,465 bytes go out with END_STREAM.
        _ = try connection.receive(windowUpdateBytes(stream: 1, increment: 40_000))
        sent = dataSent(try connection.takeOutboundFrames())
        #expect(sent.bytes == 34_465)
        #expect(sent.ended)
        _ = id
    }

    @Test("Frames are split at the peer's MAX_FRAME_SIZE")
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

    @Test("An empty body ends the request with empty DATA")
    func emptyBody() throws {
        var connection = try HTTP2ClientConnection.established()
        let id = try connection.startRequest(post, body: [])
        let frames = try connection.takeOutboundFrames()
        #expect(frames.count == 2)
        guard case .headers(_, _, let headersEnd, _) = frames[0] else { Issue.record("Expected HEADERS"); return }
        #expect(!headersEnd)
        #expect(frames[1] == .data(id, [], endStream: true, flowControlledLength: 0))
    }

    @Test("SETTINGS_INITIAL_WINDOW_SIZE changes the window of a stream opened before server SETTINGS")
    func initialWindowSizeChangesOpenStreams() throws {
        var connection = try HTTP2ClientConnection.established(serverSettings: [(4, 10)])
        _ = try connection.startRequest(post, body: [UInt8](repeating: 1, count: 25))
        #expect(dataSent(try connection.takeOutboundFrames()).bytes == 10)

        // 10 → 30: The open stream's window grows by +20, sending the remaining 15 bytes.
        _ = try connection.receive(settingsBytes([(4, 30)]))
        let frames = try connection.takeOutboundFrames()
        #expect(frames.first == .settingsAcknowledgement)
        let sent = dataSent(frames)
        #expect(sent.bytes == 15)
        #expect(sent.ended)
    }

    @Test("Reducing INITIAL_WINDOW_SIZE makes the window negative, and nothing is sent while it is 0 or less")
    func windowCanGoNegative() throws {
        var connection = try HTTP2ClientConnection.established(serverSettings: [(4, 100)])
        let id = try connection.startRequest(post, body: [UInt8](repeating: 1, count: 150))
        #expect(dataSent(try connection.takeOutboundFrames()).bytes == 100)  // Window 0

        _ = try connection.receive(settingsBytes([(4, 50)]))  // Window -50
        _ = connection.takeOutboundBytes()
        _ = try connection.receive(windowUpdateBytes(stream: 1, increment: 40))  // Window -10
        #expect(dataSent(try connection.takeOutboundFrames()).bytes == 0)

        _ = try connection.receive(windowUpdateBytes(stream: 1, increment: 60))  // Window 50
        let sent = dataSent(try connection.takeOutboundFrames())
        #expect(sent.bytes == 50)
        #expect(sent.ended)
        _ = id
    }

    @Test("If an open stream window exceeds 2^31-1 partway through one SETTINGS frame, the result is FLOW_CONTROL_ERROR even if the final difference is 0")
    func intermediateWindowOverflowInOneSettings() throws {
        func connectionWithFullStreamWindow() throws -> HTTP2ClientConnection {
            var connection = try HTTP2ClientConnection.established()
            _ = try connection.startRequest(getRequest, body: nil)
            // Increase the stream window from its initial value of 65,535 to 2^31-1.
            _ = try connection.receive(windowUpdateBytes(stream: 1, increment: UInt32(FlowControlWindow.maximum - 65_535)))
            _ = connection.takeOutboundBytes()
            return connection
        }
        var overflowing = try connectionWithFullStreamWindow()
        #expect(throws: HTTP2Error.connection(.flowControlError)) {
            try overflowing.receive(settingsBytes([(4, UInt32(FlowControlWindow.maximum)), (4, 65_535)]))
        }

        // A single identical value (difference 0) is fine. The reverse order (decrease, then increase) also stays within the limit.
        var unchanged = try connectionWithFullStreamWindow()
        _ = try unchanged.receive(settingsBytes([(4, 65_535)]))
        var decreasing = try connectionWithFullStreamWindow()
        _ = try decreasing.receive(settingsBytes([(4, 0), (4, 65_535)]))
        #expect(try decreasing.takeOutboundFrames() == [.settingsAcknowledgement])
    }

    @Test("Streams share the connection window")
    func connectionWindowShared() throws {
        var connection = try HTTP2ClientConnection.established(serverSettings: [(4, 1_000_000)])
        _ = try connection.startRequest(post, body: [UInt8](repeating: 1, count: 50_000))
        _ = try connection.startRequest(post, body: [UInt8](repeating: 2, count: 50_000))
        let sent = dataSent(try connection.takeOutboundFrames())
        #expect(sent.bytes == 65_535)  // Two streams share one connection window
    }

    @Test("Increasing a window beyond 2^31-1 produces FLOW_CONTROL_ERROR for the connection window or RST_STREAM for a stream window")
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

    @Test("An increment of 0 produces PROTOCOL_ERROR for the connection window or RST_STREAM for a stream window")
    func zeroIncrement() throws {
        var connection = try HTTP2ClientConnection.established()
        let id = try connection.startRequest(getRequest, body: nil)
        _ = connection.takeOutboundBytes()
        #expect(try connection.receive(windowUpdateBytes(stream: 1, increment: 0)) == [.streamClosed(id, resetCode: 1)])
        #expect(throws: HTTP2Error.connection(.protocolError)) { try connection.receive(windowUpdateBytes(stream: 0, increment: 0)) }
    }
}

@Suite("Receive-side flow control")
struct ReceiveFlowControlTests {
    @Test("Immediately restores the connection and stream windows by the amount of DATA received")
    func windowUpdatesForData() throws {
        var connection = try HTTP2ClientConnection.established()
        let id = try connection.startRequest(getRequest, body: nil)
        _ = connection.takeOutboundBytes()
        _ = try connection.receive(responseHeadBytes(stream: 1))
        #expect(try connection.takeOutboundFrames().isEmpty)

        _ = try connection.receive(dataBytes(stream: 1, [UInt8](repeating: 9, count: 1_000)))
        #expect(try connection.takeOutboundFrames() == [.windowUpdate(.connection, increment: 1_000), .windowUpdate(id, increment: 1_000)])
    }

    @Test("DATA with END_STREAM restores only the connection window")
    func finalData() throws {
        var connection = try HTTP2ClientConnection.established()
        _ = try connection.startRequest(getRequest, body: nil)
        _ = connection.takeOutboundBytes()
        _ = try connection.receive(responseHeadBytes(stream: 1))
        _ = try connection.receive(dataBytes(stream: 1, [1, 2, 3], endStream: true))
        #expect(try connection.takeOutboundFrames() == [.windowUpdate(.connection, increment: 3)])
    }

    @Test("Late DATA on a canceled stream still restores the connection window")
    func dataAfterCancel() throws {
        var connection = try HTTP2ClientConnection.established()
        let id = try connection.startRequest(getRequest, body: nil)
        connection.cancel(id)
        _ = connection.takeOutboundBytes()
        let events = try connection.receive(dataBytes(stream: 1, [UInt8](repeating: 0, count: 500)))
        #expect(events.isEmpty)
        #expect(try connection.takeOutboundFrames() == [.windowUpdate(.connection, increment: 500)])
    }

    @Test("Empty DATA does not restore window credit")
    func emptyData() throws {
        var connection = try HTTP2ClientConnection.established()
        _ = try connection.startRequest(getRequest, body: nil)
        _ = connection.takeOutboundBytes()
        _ = try connection.receive(responseHeadBytes(stream: 1) + dataBytes(stream: 1, []))
        #expect(try connection.takeOutboundFrames().isEmpty)
    }
}
