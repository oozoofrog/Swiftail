/// 받은 프레임의 처리: 프레임 종류마다 상태를 바꾸고, 보낼 답을 쌓고, 사건을 낸다.
///
/// 오류는 두 층이다. 연결 오류(규격 위반, 압축 상태 어긋남)는 던져서 연결을 끝낸다. 스트림 오류(잘못된
/// 응답 하나)는 그 스트림만 RST_STREAM으로 끊고 `streamClosed` 사건으로 알린다(RFC 9113 §5.4).
extension HTTP2ClientConnection {
    mutating func handle(_ frame: Frame, events: inout [Event]) throws(HTTP2Error) {
        // 서버의 첫 프레임은 SETTINGS여야 한다(§3.4).
        if !hasReceivedSettings {
            guard case .settings = frame else { throw .connection(.protocolError) }
        }
        // 헤더 블록 중간에는 같은 스트림의 CONTINUATION만 올 수 있다(§6.10).
        if headerBlock != nil {
            guard case .continuation(let stream, let fragment, let endHeaders) = frame, stream == headerBlock?.stream else {
                throw .connection(.protocolError)
            }
            try appendToHeaderBlock(fragment, endHeaders: endHeaders, events: &events)
            return
        }

        switch frame {
        case .data(let id, let payload, let endStream, let flowControlledLength):
            try receiveData(id, payload, endStream: endStream, flowControlledLength: flowControlledLength, events: &events)
        case .headers(let id, let fragment, let endStream, let endHeaders):
            // 요청한 적 없는 스트림(짝수 포함)의 응답은 규격 위반이다. 이미 닫힌 스트림이면 헤더 블록을
            // 그래도 해제해야 한다: 동적 표가 상대와 어긋나지 않게 하기 위해서다.
            try requireNotIdle(id)
            headerBlock = HeaderBlockInProgress(stream: id, bytes: [], endStream: endStream)
            try appendToHeaderBlock(fragment, endHeaders: endHeaders, events: &events)
        case .continuation:
            throw .connection(.protocolError)
        case .rstStream(let id, let code):
            try requireNotIdle(id)
            if let stream = streams.removeValue(forKey: id), stream.receiving != .ended {
                events.append(.streamClosed(id, resetCode: code))
            }
        case .settings(let settings):
            try applyPeerSettings(settings)
        case .settingsAcknowledgement, .priority, .unknown:
            break
        case .pushPromise:
            // ENABLE_PUSH=0을 알렸으므로 PUSH_PROMISE는 연결 오류다(§6.6).
            // shortcut: 서버 푸시는 받지 않는다, 푸시를 쓰는 서버와 말해야 할 때 올린다.
            throw .connection(.protocolError)
        case .ping(let ack, let data):
            if !ack { queueControl(FrameEncoder.pingAcknowledgement(data)) }
        case .goAway(let lastStreamID, let code):
            receiveGoAway(lastStreamID: lastStreamID, code: code, events: &events)
        case .windowUpdate(let id, let increment):
            try receiveWindowUpdate(id, increment: Int(increment), events: &events)
        }
    }

    // MARK: 스트림 식별자

    /// 요청한 적 없는 스트림이면 연결 오류. 클라이언트가 연 스트림은 홀수이고 `nextStreamID` 미만이다.
    private func requireNotIdle(_ id: HTTP2StreamID) throws(HTTP2Error) {
        guard id.rawValue % 2 == 1, id.rawValue < nextStreamID else { throw .connection(.protocolError) }
    }

    /// 상대가 요구해서 생긴 제어 프레임을 보낼 바이트에 쌓는다. 쌓인 양의 한도는 `receive`가 프레임마다 확인한다.
    private mutating func queueControl(_ frame: [UInt8]) {
        outbound += frame
        pendingControlBytes += frame.count
    }

    // MARK: DATA

    private mutating func receiveData(
        _ id: HTTP2StreamID, _ payload: [UInt8], endStream: Bool, flowControlledLength: Int, events: inout [Event]
    ) throws(HTTP2Error) {
        try requireNotIdle(id)
        // 받은 만큼 곧바로 창을 돌려준다. 연결 창은 스트림이 닫혔어도 이미 줄었으므로 늘 돌려준다.
        // shortcut: 받는 쪽 역압은 없다(소비가 느려도 서버를 늦추지 못한다), 큰 응답을 스트리밍으로 소비해야 할 때 올린다.
        if flowControlledLength > 0 {
            queueControl(FrameEncoder.windowUpdate(.connection, increment: flowControlledLength))
        }
        guard let stream = streams[id] else { return }
        switch stream.receiving {
        case .awaitingHead:
            resetStream(id, code: .protocolError, events: &events)
        case .ended:
            resetStream(id, code: .streamClosed, events: &events)
        case .receivingBody:
            // content-length보다 많이 오면 더 받지 않고 끊는다(§8.1.1).
            let received = stream.receivedBodyLength + payload.count
            if let declared = stream.declaredBodyLength, received > declared {
                resetStream(id, code: .protocolError, events: &events)
                return
            }
            streams[id]?.receivedBodyLength = received
            if flowControlledLength > 0 && !endStream {
                queueControl(FrameEncoder.windowUpdate(id, increment: flowControlledLength))
            }
            if !payload.isEmpty { events.append(.responseData(id, payload)) }
            if endStream { finishResponse(id, events: &events) }
        }
    }

    // MARK: 헤더 블록

    /// 헤더 블록 조각을 이어 붙이고, 마지막 조각이면 해제해서 스트림에 전달한다.
    private mutating func appendToHeaderBlock(_ fragment: [UInt8], endHeaders: Bool, events: inout [Event]) throws(HTTP2Error) {
        guard var block = headerBlock else { throw .connection(.protocolError) }
        guard block.bytes.count + fragment.count <= Self.maximumHeaderBlockSize else { throw .connection(.enhanceYourCalm) }
        block.bytes += fragment
        guard endHeaders else {
            headerBlock = block
            return
        }
        headerBlock = nil
        let fields: [HeaderField]
        do throws(HPACKError) {
            fields = try decoder.decode(block.bytes)
        } catch {
            throw .connection(error == .headerListTooLarge ? .enhanceYourCalm : .compressionError)
        }
        receiveHeaders(block.stream, fields, endStream: block.endStream, events: &events)
    }

    /// 해제한 헤더 필드를 스트림에 전달한다. 응답 머리, 1xx 임시 응답, 트레일러 셋 중 하나다.
    private mutating func receiveHeaders(_ id: HTTP2StreamID, _ fields: [HeaderField], endStream: Bool, events: inout [Event]) {
        guard let stream = streams[id] else { return }
        switch stream.receiving {
        case .ended:
            resetStream(id, code: .streamClosed, events: &events)
        case .awaitingHead:
            guard let head = ResponseHead(validating: fields) else {
                resetStream(id, code: .protocolError, events: &events)
                return
            }
            if (100...199).contains(head.status) {
                // 101은 HTTP/2에서 쓰지 않는다(§8.6). 그 밖의 임시 응답(100 Continue 등)은 전달하지 않고
                // 최종 응답을 기다린다(§8.1). 임시 응답이 스트림을 끝내면 안 된다.
                if endStream || head.status == 101 { resetStream(id, code: .protocolError, events: &events) }
                return
            }
            streams[id]?.receiving = .receivingBody
            // HEAD 응답과 204·304는 본문이 없으므로 content-length가 있어도 본문 길이와 맞춰 보지 않는다(§8.1.1).
            let hasNoBody = stream.isHeadRequest || head.status == 204 || head.status == 304
            streams[id]?.declaredBodyLength = hasNoBody ? nil : head.contentLength
            events.append(.responseHead(id, status: head.status, headers: head.headers))
            if endStream { finishResponse(id, events: &events) }
        case .receivingBody:
            // shortcut: 트레일러는 검증만 하고 버린다, 트레일러가 의미를 갖는 응답을 다루게 되면 올린다.
            // 본문 뒤의 헤더 블록은 트레일러이고 END_STREAM이 있어야 하며, 의사 헤더를 가질 수 없다(§8.1, §8.1.1).
            guard endStream, fields.allSatisfy({ $0.name.utf8.first != UInt8(ascii: ":") && HeaderValidation.isValid($0) }) else {
                resetStream(id, code: .protocolError, events: &events)
                return
            }
            finishResponse(id, events: &events)
        }
    }

    // MARK: 스트림 끝

    /// 응답이 END_STREAM으로 끝났다. 받은 본문이 `content-length`와 다르면 잘못된 응답이다(§8.1.1).
    private mutating func finishResponse(_ id: HTTP2StreamID, events: inout [Event]) {
        if let stream = streams[id], let declared = stream.declaredBodyLength, stream.receivedBodyLength != declared {
            resetStream(id, code: .protocolError, events: &events)
        } else {
            finishReceiving(id, events: &events)
        }
    }

    /// 응답이 END_STREAM으로 끝났다. 요청을 다 보냈으면 스트림을 잊고, 아직 보낼 본문이 남았으면 서버가
    /// 본문을 기다리지 않고 응답한 것이므로 남은 본문을 접는다(§8.1).
    private mutating func finishReceiving(_ id: HTTP2StreamID, events: inout [Event]) {
        events.append(.streamClosed(id, resetCode: nil))
        guard let stream = streams[id] else { return }
        if stream.unsentBody != nil {
            queueControl(FrameEncoder.rstStream(id, code: .cancel))
        }
        streams.removeValue(forKey: id)
    }

    /// 스트림 오류: 그 스트림만 RST_STREAM으로 끊는다. 응답을 끝까지 받은 스트림이면 사건은 이미 났으므로
    /// 다시 알리지 않는다.
    private mutating func resetStream(_ id: HTTP2StreamID, code: HTTP2ErrorCode, events: inout [Event]) {
        guard let stream = streams.removeValue(forKey: id) else { return }
        queueControl(FrameEncoder.rstStream(id, code: code))
        if stream.receiving != .ended {
            events.append(.streamClosed(id, resetCode: code.rawValue))
        }
    }

    // MARK: SETTINGS, WINDOW_UPDATE, GOAWAY

    private mutating func applyPeerSettings(_ settings: [Frame.Setting]) throws(HTTP2Error) {
        hasReceivedSettings = true
        // 열린 스트림의 창은 초깃값이 바뀐 만큼 함께 바뀐다(§6.9.2). 설정은 받은 순서대로 하나씩 적용하고
        // 매번 넘침을 확인한다: 한 프레임 안에서 창이 잠시 2^31-1을 넘었다가 돌아오는 경우도 오류다.
        for setting in settings {
            let windowDelta = try peerSettings.apply([setting])
            guard windowDelta != 0 else { continue }
            do throws(FlowControlWindow.Overflow) {
                for id in streams.keys {
                    try streams[id]?.sendWindow.adjust(by: windowDelta)
                }
            } catch {
                throw .connection(.flowControlError)
            }
        }
        queueControl(FrameEncoder.settingsAcknowledgement())
        sendPendingBodies()
    }

    private mutating func receiveWindowUpdate(_ id: HTTP2StreamID, increment: Int, events: inout [Event]) throws(HTTP2Error) {
        if id == .connection {
            guard increment > 0 else { throw .connection(.protocolError) }
            do throws(FlowControlWindow.Overflow) {
                try sendWindow.adjust(by: increment)
            } catch {
                throw .connection(.flowControlError)
            }
            sendPendingBodies()
            return
        }
        try requireNotIdle(id)
        guard streams[id] != nil else { return }
        guard increment > 0 else {
            resetStream(id, code: .protocolError, events: &events)
            return
        }
        do throws(FlowControlWindow.Overflow) {
            try streams[id]?.sendWindow.adjust(by: increment)
        } catch {
            resetStream(id, code: .flowControlError, events: &events)
            return
        }
        sendBody(of: id)
    }

    /// GOAWAY: `lastStreamID`보다 큰 스트림은 서버가 처리하지 않았으므로 버린다. 나머지는 끝까지 받는다.
    /// 새 요청은 더 시작하지 않는다.
    private mutating func receiveGoAway(lastStreamID: HTTP2StreamID, code: UInt32, events: inout [Event]) {
        if phase == .open { phase = .draining }
        streams = streams.filter { $0.key.rawValue <= lastStreamID.rawValue }
        events.append(.goAway(lastStreamID: lastStreamID, code: code))
    }
}
