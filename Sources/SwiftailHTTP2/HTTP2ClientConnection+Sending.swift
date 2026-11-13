/// 요청 시작, 스트림 취소, 요청 본문 전송.
extension HTTP2ClientConnection {
    /// 요청을 시작한다. `:scheme`은 늘 https다. body가 nil이면 HEADERS에서 요청이 끝난다.
    /// 본문은 흐름 제어 창이 허락하는 만큼씩 나간다.
    ///
    /// shortcut: 본문은 한 번에 통째로 받고 점진적으로 공급받지 않으며, 트레일러도 보내지 않는다. 요청 본문이 커서 메모리가 문제가 될 때 올린다.
    public mutating func startRequest(_ request: Request, body: [UInt8]?) throws(HTTP2Error) -> HTTP2StreamID {
        guard phase == .open, nextStreamID <= 0x7fff_ffff else { throw .connectionClosed }
        let fields = try request.headerFields()
        guard streams.count < peerSettings.maxConcurrentStreams else { throw .tooManyStreams }

        let id = HTTP2StreamID(nextStreamID)
        nextStreamID += 2
        streams[id] = StreamState(
            sendWindowSize: peerSettings.initialWindowSize, body: body, isHeadRequest: request.method == "HEAD")
        outbound += FrameEncoder.headers(
            id, block: HPACKEncoder.encode(fields), endStream: body == nil,
            maximumPayloadLength: peerSettings.maxFrameSize)
        sendBody(of: id)
        return id
    }

    /// 스트림을 버린다(RST_STREAM CANCEL). 이미 끝난 스트림이면 아무 일도 하지 않는다.
    /// 그 스트림의 사건은 더 나오지 않는다(`streamClosed`도 없다). 부른 쪽이 스스로 정리한다.
    public mutating func cancel(_ stream: HTTP2StreamID) {
        guard phase != .failed, streams.removeValue(forKey: stream) != nil else { return }
        outbound += FrameEncoder.rstStream(stream, code: .cancel)
    }

    /// 창이 허락하는 만큼 본문을 DATA 프레임으로 내보낸다. 창이 모자라면 남겨 두고, WINDOW_UPDATE나
    /// SETTINGS가 창을 열 때 다시 부른다. 마지막 조각에 END_STREAM을 붙인다. 본문이 비어 있으면 빈
    /// DATA 하나로 끝낸다.
    mutating func sendBody(of id: HTTP2StreamID) {
        guard var stream = streams[id], var body = stream.unsentBody else { return }
        while true {
            // 창은 음수일 수 있다(SETTINGS_INITIAL_WINDOW_SIZE 감소, §6.9.2).
            let allowance = max(0, min(sendWindow.available, stream.sendWindow.available, peerSettings.maxFrameSize))
            let size = min(body.count, allowance)
            if size == 0 && !body.isEmpty { break }
            let chunk = body.prefix(size)
            body = body.dropFirst(size)
            let isLast = body.isEmpty
            outbound += FrameEncoder.data(id, chunk, endStream: isLast)
            sendWindow.consume(size)
            stream.sendWindow.consume(size)
            if isLast { break }
        }
        stream.unsentBody = body.isEmpty ? nil : body
        if stream.unsentBody == nil && stream.receiving == .ended {
            streams.removeValue(forKey: id)
        } else {
            streams[id] = stream
        }
    }

    /// 연결 창이 열렸을 때 기다리던 모든 스트림을 낮은 번호부터 보낸다.
    mutating func sendPendingBodies() {
        for id in streams.keys.sorted(by: { $0.rawValue < $1.rawValue }) {
            sendBody(of: id)
        }
    }
}

extension HTTP2ClientConnection.Request {
    /// 의사 헤더를 앞에 두고 일반 헤더를 이어 붙인 헤더 목록. 규격에 어긋나면 `invalidRequest`.
    ///
    /// 보낼 값은 여기서 한 번 확인한다: method·path·authority는 비어 있거나 공백·제어 문자를 가지면
    /// 안 된다(RFC 9113 §8.3.1). 일반 헤더는 응답을 받을 때와 같은 `HeaderValidation` 규칙을 따른다
    /// (소문자 token 이름, NUL·CR·LF 없는 값, 연결 전용 필드 금지. §8.2).
    func headerFields() throws(HTTP2Error) -> [HeaderField] {
        for pseudo in [method, path, authority] {
            guard !pseudo.isEmpty, !pseudo.utf8.contains(where: { $0 <= 0x20 || $0 == 0x7f }) else { throw .invalidRequest }
        }
        guard headers.allSatisfy(HeaderValidation.isValid) else { throw .invalidRequest }
        return [
            HeaderField(":method", method),
            HeaderField(":scheme", "https"),
            HeaderField(":authority", authority),
            HeaderField(":path", path),
        ] + headers
    }
}
