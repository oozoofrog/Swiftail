// Contract test 5: Limits and arbitrary input. Input over the limit is a connection error, and random bytes do not cause a crash.

import Testing

@testable import SwiftailHTTP2

@Suite("Limits")
struct LimitTests {
    @Test("A frame length over 16,384 yields FRAME_SIZE_ERROR from the header alone")
    func frameTooLarge() throws {
        var connection = try HTTP2ClientConnection.established()
        // Do not send the payload. The advertised length alone triggers rejection, so the connection neither waits for nor buffers it.
        let header = Array(frameBytes(0, stream: 1).prefix(9))
        let oversized = [0x00, 0x40, 0x01] + header.dropFirst(3)
        #expect(throws: HTTP2Error.connectionFailed(code: 6)) { try connection.receive(Array(oversized)) }
        #expect(try connection.takeOutboundFrames() == [.goAway(lastStreamID: .connection, code: 6)])
    }

    @Test("A frame length of 16,384 is allowed")
    func frameAtLimit() throws {
        var connection = try HTTP2ClientConnection.established()
        let id = try connection.startRequest(getRequest, body: nil)
        let events = try connection.receive(responseHeadBytes(stream: 1) + dataBytes(stream: 1, [UInt8](repeating: 1, count: 16_384)))
        #expect(events.last == .responseData(id, [UInt8](repeating: 1, count: 16_384)))
    }

    @Test("A total header block length over 64KiB is a connection error")
    func headerBlockTooLarge() throws {
        var connection = try HTTP2ClientConnection.established()
        _ = try connection.startRequest(getRequest, body: nil)
        // 4 fragments of 16,384 bytes = 65,536, within the limit. One more byte exceeds it.
        let chunk = [UInt8](repeating: 0, count: 16_384)
        _ = try connection.receive(frameBytes(1, stream: 1, payload: chunk) + frameBytes(9, stream: 1, payload: chunk)
            + frameBytes(9, stream: 1, payload: chunk) + frameBytes(9, stream: 1, payload: chunk))
        #expect(throws: HTTP2Error.connectionFailed(code: 11)) { try connection.receive(frameBytes(9, stream: 1, payload: [0])) }
    }

    @Test("A small block that exceeds the limit after decoding is also a connection error")
    func decompressionBomb() throws {
        var connection = try HTTP2ClientConnection.established()
        _ = try connection.startRequest(getRequest, body: nil)
        // Insert a 4,000-byte value into the dynamic table and reference it 20 times with a 1-byte index to get 80KB.
        var block: [UInt8] = [0x40, 0x01, 0x61]
        HPACKEncoding.appendInteger(4_000, prefixBits: 7, flags: 0, to: &block)
        block += [UInt8](repeating: 0x62, count: 4_000)
        block += [UInt8](repeating: 0xbe, count: 20)
        #expect(throws: HTTP2Error.connectionFailed(code: 11)) { try connection.receive(frameBytes(1, flags: 0x4, stream: 1, payload: block)) }
    }

    @Test("HPACK errors yield COMPRESSION_ERROR")
    func hpackErrors() throws {
        let blocks: [[UInt8]] = [
            [0x80],                // Index 0
            [0xff, 0xff, 0xff],    // Truncated integer
            [0x3f, 0xe2, 0x1f],    // Table size update above the advertised limit (4,096)
            [0x82, 0x20],          // Table size update after a field
        ]
        for block in blocks {
            var connection = try HTTP2ClientConnection.established()
            _ = try connection.startRequest(getRequest, body: nil)
            #expect(throws: HTTP2Error.connectionFailed(code: 9)) { try connection.receive(frameBytes(1, flags: 0x4, stream: 1, payload: block)) }
        }
    }

    // Byte limit for queued control frames requested by the peer (`maximumPendingControlBytes`). A PING ACK is 17 bytes.
    @Test("PING ACKs can accumulate up to the limit. One more yields ENHANCE_YOUR_CALM")
    func pingFloodLimit() throws {
        let ping = frameBytes(6, payload: [1, 2, 3, 4, 5, 6, 7, 8])
        let allowed = HTTP2ClientConnection.maximumPendingControlBytes / 17

        var connection = try HTTP2ClientConnection.established()
        _ = try connection.receive(Array(repeating: ping, count: allowed).flatMap { $0 })
        #expect(try connection.takeOutboundFrames().count == allowed)

        var overflowing = try HTTP2ClientConnection.established()
        #expect(throws: HTTP2Error.connectionFailed(code: 11)) {
            try overflowing.receive(Array(repeating: ping, count: allowed + 1).flatMap { $0 })
        }
        // GOAWAY follows the queued replies that exceeded the limit.
        #expect(try overflowing.takeOutboundFrames().last == .goAway(lastStreamID: .connection, code: 11))
        #expect(throws: HTTP2Error.connectionClosed) { try overflowing.receive([]) }
    }

    @Test("Draining the pending bytes clears them, so the limit can be received multiple times")
    func pendingBytesResetWhenTaken() throws {
        let ping = frameBytes(6, payload: [1, 2, 3, 4, 5, 6, 7, 8])
        let allowed = HTTP2ClientConnection.maximumPendingControlBytes / 17
        var connection = try HTTP2ClientConnection.established()
        for _ in 0..<3 {
            _ = try connection.receive(Array(repeating: ping, count: allowed).flatMap { $0 })
            _ = connection.takeOutboundBytes()
        }
    }

    @Test("With no draining, exceeding the total limit is a connection error even across multiple receives")
    func pendingBytesAccumulateAcrossReceives() throws {
        let ping = frameBytes(6, payload: [1, 2, 3, 4, 5, 6, 7, 8])
        let allowed = HTTP2ClientConnection.maximumPendingControlBytes / 17
        var connection = try HTTP2ClientConnection.established()
        _ = try connection.receive(Array(repeating: ping, count: allowed).flatMap { $0 })
        #expect(throws: HTTP2Error.connectionFailed(code: 11)) { try connection.receive(ping) }
    }

    @Test("Queued SETTINGS ACKs count toward the same limit")
    func settingsFloodLimit() throws {
        let empty = settingsBytes()
        let allowed = HTTP2ClientConnection.maximumPendingControlBytes / 9
        var connection = try HTTP2ClientConnection.established()
        _ = try connection.receive(Array(repeating: empty, count: allowed).flatMap { $0 })
        #expect(try connection.takeOutboundFrames().count == allowed)
        #expect(throws: HTTP2Error.connectionFailed(code: 11)) {
            try connection.receive(Array(repeating: empty, count: allowed + 1).flatMap { $0 })
        }
    }

    @Test("Small DATA frames arriving together generate one WINDOW_UPDATE each for the connection and stream")
    func smallDataFramesShareOneWindowUpdate() throws {
        func connectionWithHead() throws -> HTTP2ClientConnection {
            var connection = try HTTP2ClientConnection.established()
            _ = try connection.startRequest(getRequest, body: nil)
            _ = try connection.receive(responseHeadBytes(stream: 1))
            _ = connection.takeOutboundBytes()
            return connection
        }
        // 3,000 1-byte DATA frames (30,000 bytes) make a valid response. Queuing a reply for each frame would reach 78,000 bytes,
        // hitting the pending control frame limit (64KiB) and making success depend on how TCP chunks are split.
        let frames = (0..<3_000).map { _ in dataBytes(stream: 1, [0x61]) }

        var coalesced = try connectionWithHead()
        let events = try coalesced.receive(frames.flatMap { $0 })
        #expect(events.count == 3_000)
        #expect(try coalesced.takeOutboundFrames() == [
            .windowUpdate(.connection, increment: 3_000), .windowUpdate(HTTP2StreamID(1), increment: 3_000),
        ])
        #expect(coalesced.takeOutboundBytes().isEmpty)

        // Only counts accumulate, even across many small receives without draining.
        var fragmented = try connectionWithHead()
        for frame in frames { _ = try fragmented.receive(frame) }
        #expect(try fragmented.takeOutboundFrames() == [
            .windowUpdate(.connection, increment: 3_000), .windowUpdate(HTTP2StreamID(1), increment: 3_000),
        ])
    }

    @Test("Decodes header blocks on closed streams to keep the dynamic table in sync")
    func closedStreamHeadersKeepTableInSync() throws {
        var connection = try HTTP2ClientConnection.established()
        let first = try connection.startRequest(getRequest, body: nil)
        connection.cancel(first)
        let second = try connection.startRequest(getRequest, body: nil)
        // The response on canceled stream 1 inserts one entry into the dynamic table.
        let inserted: [UInt8] = [0x40, 0x01, 0x78, 0x01, 0x79]  // Index x: y
        _ = try connection.receive(frameBytes(1, flags: 0x4, stream: 1, payload: [0x88] + inserted))
        // The response on stream 3 references that entry (index 62).
        let events = try connection.receive(frameBytes(1, flags: 0x4, stream: 3, payload: [0x88, 0xbe]))
        #expect(events == [.responseHead(second, status: 200, headers: [HeaderField("x", "y")])])
    }
}

@Suite("Arbitrary input")
struct FuzzTests {
    @Test("Random bytes do not cause a crash")
    func randomBytes() throws {
        var random = SplitMix64(state: 0x5eed)
        for _ in 0..<3_000 {
            var connection = try HTTP2ClientConnection.established()
            _ = try connection.startRequest(getRequest, body: [1, 2, 3])
            let input = random.bytes(count: Int(random.next() % 300))
            _ = try? connection.receive(input)
            _ = connection.takeOutboundBytes()
        }
    }

    @Test("Random frame-shaped input with varying type, flags, and stream")
    func randomFrames() throws {
        var random = SplitMix64(state: 0xf4a3e)
        for _ in 0..<3_000 {
            var settings: [(UInt16, UInt32)] = []
            if random.next() % 2 == 0 { settings.append((4, UInt32(truncatingIfNeeded: random.next() % 200))) }
            var connection = try HTTP2ClientConnection.established(serverSettings: settings)
            _ = try connection.startRequest(getRequest, body: nil)
            _ = try connection.startRequest(HTTP2ClientConnection.Request(method: "POST", path: "/", authority: "tail0001"), body: random.bytes(count: 300))
            var input: [UInt8] = []
            for _ in 0..<Int(random.next() % 6) {
                let payload = random.bytes(count: Int(random.next() % 40))
                input += frameBytes(UInt8(random.next() % 11), flags: UInt8(truncatingIfNeeded: random.next()), stream: UInt32(random.next() % 6), payload: payload)
            }
            _ = try? connection.receive(input)
            _ = connection.takeOutboundBytes()
        }
    }

    @Test("Flipping each byte of a valid exchange individually does not cause a crash")
    func flippedBytes() throws {
        let transcript = settingsBytes([(3, 100)]) + responseHeadBytes(stream: 1, headers: [HeaderField("x-a", "b")])
            + dataBytes(stream: 1, [1, 2, 3, 4]) + goAwayBytes(lastStream: 1, code: 0)
        for index in transcript.indices {
            for mask: UInt8 in [0x01, 0x80, 0xff] {
                var corrupted = transcript
                corrupted[index] ^= mask
                var connection = HTTP2ClientConnection()
                _ = try connection.startRequest(getRequest, body: nil)
                _ = try? connection.receive(corrupted)
                _ = connection.takeOutboundBytes()
            }
        }
    }

    @Test("HPACK and Huffman decoders do not crash on random bytes")
    func hpackRandom() {
        var random = SplitMix64(state: 0xabcdef)
        var decoder = HPACKDecoder()
        for _ in 0..<5_000 {
            let input = random.bytes(count: Int(random.next() % 120))
            _ = try? decoder.decode(input)
            _ = try? HPACKHuffman.decode(input[...])
        }
    }

    @Test("After a connection error, any subsequent input gets connectionClosed")
    func failedStaysFailed() throws {
        var connection = try HTTP2ClientConnection.established()
        _ = try? connection.receive(dataBytes(stream: 0, [1]))
        var random = SplitMix64(state: 7)
        for _ in 0..<50 {
            #expect(throws: HTTP2Error.connectionClosed) { try connection.receive(random.bytes(count: 20)) }
        }
    }
}
