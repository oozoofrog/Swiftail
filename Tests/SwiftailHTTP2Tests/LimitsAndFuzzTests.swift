// 계약 시험 5: 한도와 임의 입력. 한도를 넘는 입력은 연결 오류이고, 무작위 바이트로 죽지 않는다.

import Testing

@testable import SwiftailHTTP2

@Suite("한도")
struct LimitTests {
    @Test("프레임 길이 16,384 초과는 머리만 받고도 FRAME_SIZE_ERROR")
    func frameTooLarge() throws {
        var connection = try HTTP2ClientConnection.established()
        // payload는 보내지 않는다. 길이를 알린 것만으로 거절하므로 기다리며 쌓지 않는다.
        let header = Array(frameBytes(0, stream: 1).prefix(9))
        let oversized = [0x00, 0x40, 0x01] + header.dropFirst(3)
        #expect(throws: HTTP2Error.connectionFailed(code: 6)) { try connection.receive(Array(oversized)) }
        #expect(try connection.takeOutboundFrames() == [.goAway(lastStreamID: .connection, code: 6)])
    }

    @Test("프레임 길이 16,384는 허용")
    func frameAtLimit() throws {
        var connection = try HTTP2ClientConnection.established()
        let id = try connection.startRequest(getRequest, body: nil)
        let events = try connection.receive(responseHeadBytes(stream: 1) + dataBytes(stream: 1, [UInt8](repeating: 1, count: 16_384)))
        #expect(events.last == .responseData(id, [UInt8](repeating: 1, count: 16_384)))
    }

    @Test("헤더 블록 합계가 64KiB를 넘으면 연결 오류")
    func headerBlockTooLarge() throws {
        var connection = try HTTP2ClientConnection.established()
        _ = try connection.startRequest(getRequest, body: nil)
        // 16,384바이트씩 4조각 = 65,536은 한도 안이고, 한 바이트 더 오면 넘친다.
        let chunk = [UInt8](repeating: 0, count: 16_384)
        _ = try connection.receive(frameBytes(1, stream: 1, payload: chunk) + frameBytes(9, stream: 1, payload: chunk)
            + frameBytes(9, stream: 1, payload: chunk) + frameBytes(9, stream: 1, payload: chunk))
        #expect(throws: HTTP2Error.connectionFailed(code: 11)) { try connection.receive(frameBytes(9, stream: 1, payload: [0])) }
    }

    @Test("작은 블록이 해제 뒤 한도를 넘는 경우도 연결 오류")
    func decompressionBomb() throws {
        var connection = try HTTP2ClientConnection.established()
        _ = try connection.startRequest(getRequest, body: nil)
        // 4,000바이트 값을 동적 표에 넣고, 1바이트 색인으로 20번 불러 80KB가 된다.
        var block: [UInt8] = [0x40, 0x01, 0x61]
        HPACKEncoding.appendInteger(4_000, prefixBits: 7, flags: 0, to: &block)
        block += [UInt8](repeating: 0x62, count: 4_000)
        block += [UInt8](repeating: 0xbe, count: 20)
        #expect(throws: HTTP2Error.connectionFailed(code: 11)) { try connection.receive(frameBytes(1, flags: 0x4, stream: 1, payload: block)) }
    }

    @Test("HPACK 오류는 COMPRESSION_ERROR")
    func hpackErrors() throws {
        let blocks: [[UInt8]] = [
            [0x80],                // 색인 0
            [0xff, 0xff, 0xff],    // 잘린 정수
            [0x3f, 0xe2, 0x1f],    // 알린 한도(4,096)를 넘는 표 크기 갱신
            [0x82, 0x20],          // 필드 뒤의 표 크기 갱신
        ]
        for block in blocks {
            var connection = try HTTP2ClientConnection.established()
            _ = try connection.startRequest(getRequest, body: nil)
            #expect(throws: HTTP2Error.connectionFailed(code: 9)) { try connection.receive(frameBytes(1, flags: 0x4, stream: 1, payload: block)) }
        }
    }

    // 상대가 요구해서 쌓이는 제어 프레임의 대기 바이트 한도(`maximumPendingControlBytes`). PING ACK는 17바이트다.
    @Test("PING ACK가 한도 직전까지 쌓이는 것은 허용하고, 한 개 넘으면 ENHANCE_YOUR_CALM")
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
        // 한도를 넘겨 쌓인 답 뒤에 GOAWAY가 붙는다.
        #expect(try overflowing.takeOutboundFrames().last == .goAway(lastStreamID: .connection, code: 11))
        #expect(throws: HTTP2Error.connectionClosed) { try overflowing.receive([]) }
    }

    @Test("대기 바이트는 꺼내 가면 비워지므로 한도를 여러 번 받아도 된다")
    func pendingBytesResetWhenTaken() throws {
        let ping = frameBytes(6, payload: [1, 2, 3, 4, 5, 6, 7, 8])
        let allowed = HTTP2ClientConnection.maximumPendingControlBytes / 17
        var connection = try HTTP2ClientConnection.established()
        for _ in 0..<3 {
            _ = try connection.receive(Array(repeating: ping, count: allowed).flatMap { $0 })
            _ = connection.takeOutboundBytes()
        }
    }

    @Test("꺼내 가지 않고 여러 번 나눠 받아도 합계가 한도를 넘으면 연결 오류")
    func pendingBytesAccumulateAcrossReceives() throws {
        let ping = frameBytes(6, payload: [1, 2, 3, 4, 5, 6, 7, 8])
        let allowed = HTTP2ClientConnection.maximumPendingControlBytes / 17
        var connection = try HTTP2ClientConnection.established()
        _ = try connection.receive(Array(repeating: ping, count: allowed).flatMap { $0 })
        #expect(throws: HTTP2Error.connectionFailed(code: 11)) { try connection.receive(ping) }
    }

    @Test("SETTINGS ACK가 쌓이는 것도 같은 한도")
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

    @Test("작은 DATA가 낳는 WINDOW_UPDATE가 쌓이는 것도 같은 한도")
    func windowUpdateFloodLimit() throws {
        // DATA 한 프레임(END_STREAM 없음)마다 연결·스트림 WINDOW_UPDATE 13바이트씩 26바이트를 낳는다.
        let allowed = HTTP2ClientConnection.maximumPendingControlBytes / 26
        func connectionWithHead() throws -> HTTP2ClientConnection {
            var connection = try HTTP2ClientConnection.established()
            _ = try connection.startRequest(getRequest, body: nil)
            _ = try connection.receive(responseHeadBytes(stream: 1))
            _ = connection.takeOutboundBytes()
            return connection
        }
        let data = dataBytes(stream: 1, [0])
        var connection = try connectionWithHead()
        _ = try connection.receive(Array(repeating: data, count: allowed).flatMap { $0 })
        #expect(try connection.takeOutboundFrames().count == allowed * 2)

        var overflowing = try connectionWithHead()
        #expect(throws: HTTP2Error.connectionFailed(code: 11)) {
            try overflowing.receive(Array(repeating: data, count: allowed + 1).flatMap { $0 })
        }
    }

    @Test("닫힌 스트림의 헤더 블록도 해제해 동적 표를 맞춘다")
    func closedStreamHeadersKeepTableInSync() throws {
        var connection = try HTTP2ClientConnection.established()
        let first = try connection.startRequest(getRequest, body: nil)
        connection.cancel(first)
        let second = try connection.startRequest(getRequest, body: nil)
        // 취소한 스트림 1에 온 응답이 동적 표에 항목 하나를 넣는다.
        let inserted: [UInt8] = [0x40, 0x01, 0x78, 0x01, 0x79]  // x: y를 색인
        _ = try connection.receive(frameBytes(1, flags: 0x4, stream: 1, payload: [0x88] + inserted))
        // 스트림 3의 응답이 그 항목(색인 62)을 부른다.
        let events = try connection.receive(frameBytes(1, flags: 0x4, stream: 3, payload: [0x88, 0xbe]))
        #expect(events == [.responseHead(second, status: 200, headers: [HeaderField("x", "y")])])
    }
}

@Suite("임의 입력")
struct FuzzTests {
    @Test("무작위 바이트를 넣어도 죽지 않는다")
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

    @Test("프레임 모양의 무작위 입력(type·flags·stream을 바꿔 가며)")
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

    @Test("올바른 대화의 바이트를 하나씩 뒤집어도 죽지 않는다")
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

    @Test("HPACK 해제기와 허프만 해제는 무작위 바이트에도 죽지 않는다")
    func hpackRandom() {
        var random = SplitMix64(state: 0xabcdef)
        var decoder = HPACKDecoder()
        for _ in 0..<5_000 {
            let input = random.bytes(count: Int(random.next() % 120))
            _ = try? decoder.decode(input)
            _ = try? HPACKHuffman.decode(input[...])
        }
    }

    @Test("연결 오류가 난 연결은 이후 어떤 입력에도 connectionClosed")
    func failedStaysFailed() throws {
        var connection = try HTTP2ClientConnection.established()
        _ = try? connection.receive(dataBytes(stream: 0, [1]))
        var random = SplitMix64(state: 7)
        for _ in 0..<50 {
            #expect(throws: HTTP2Error.connectionClosed) { try connection.receive(random.bytes(count: 20)) }
        }
    }
}
