/// Starts requests, cancels streams, and sends request bodies.
extension HTTP2ClientConnection {
    /// Starts a request. `:scheme` is always https. If body is nil, the request ends with HEADERS.
    /// The body is sent in chunks as the flow control windows allow.
    ///
    /// shortcut: accepts the full body at once without incremental input and sends no trailers. Add support when large request bodies pose a memory problem.
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

    /// Cancels the stream with RST_STREAM CANCEL. If the stream has already ended, this has no effect.
    /// Emits no further events for the stream, including `streamClosed`. The caller cleans up.
    public mutating func cancel(_ stream: HTTP2StreamID) {
        guard phase != .failed, streams.removeValue(forKey: stream) != nil else { return }
        outbound += FrameEncoder.rstStream(stream, code: .cancel)
    }

    /// Sends body data in DATA frames as the windows allow. Retains unsent data if window credit runs out. Call again when WINDOW_UPDATE
    /// or SETTINGS opens the window. Sets END_STREAM on the last fragment. An empty body ends with one empty
    /// DATA frame.
    mutating func sendBody(of id: HTTP2StreamID) {
        guard var stream = streams[id], var body = stream.unsentBody else { return }
        while true {
            // The window can be negative (a decrease in SETTINGS_INITIAL_WINDOW_SIZE, §6.9.2).
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

    /// When the connection window opens, sends pending data for all waiting streams in ascending order.
    mutating func sendPendingBodies() {
        for id in streams.keys.sorted(by: { $0.rawValue < $1.rawValue }) {
            sendBody(of: id)
        }
    }
}

extension HTTP2ClientConnection.Request {
    /// The header list, with pseudo-headers first and regular headers afterward. Violations produce `invalidRequest`.
    ///
    /// Validates outgoing values once. method, path, and authority must be nonempty and free of whitespace and control
    /// characters (RFC 9113 §8.3.1). Regular headers follow the same `HeaderValidation` rules as incoming responses
    /// (lowercase token names, values without NUL, CR, or LF, and no connection-specific fields, §8.2).
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
