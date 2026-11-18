/// Handles incoming frames by updating state, queuing replies, and emitting events according to the frame type.
///
/// Errors have two levels. Connection errors (specification violations or divergent compression state) throw and end the connection. A stream error
/// (a single invalid response) resets only that stream with RST_STREAM and reports a `streamClosed` event (RFC 9113 §5.4).
extension HTTP2ClientConnection {
    mutating func handle(_ frame: Frame, events: inout [Event]) throws(HTTP2Error) {
        // The server's first frame must be SETTINGS (§3.4).
        if !hasReceivedSettings {
            guard case .settings = frame else { throw .connection(.protocolError) }
        }
        // Only a CONTINUATION for the same stream can arrive within a header block (§6.10).
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
            // A response on a never-requested stream (including even-numbered streams) violates the specification. For an already closed stream,
            // still decode its header block to keep the dynamic table synchronized with the peer.
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
            // We advertised ENABLE_PUSH=0, so PUSH_PROMISE is a connection error (§6.6).
            // shortcut: rejects server push, add support when interoperability with a push server is required.
            throw .connection(.protocolError)
        case .ping(let ack, let data):
            if !ack { queueControl(FrameEncoder.pingAcknowledgement(data)) }
        case .goAway(let lastStreamID, let code):
            receiveGoAway(lastStreamID: lastStreamID, code: code, events: &events)
        case .windowUpdate(let id, let increment):
            try receiveWindowUpdate(id, increment: Int(increment), events: &events)
        }
    }

    // MARK: Stream identifiers

    /// Throws a connection error for a stream the client never opened. Client-initiated streams have odd identifiers below `nextStreamID`.
    private func requireNotIdle(_ id: HTTP2StreamID) throws(HTTP2Error) {
        guard id.rawValue % 2 == 1, id.rawValue < nextStreamID else { throw .connection(.protocolError) }
    }

    /// Queues control frames required by the peer in the outbound bytes. `receive` checks the queued size after each frame.
    private mutating func queueControl(_ frame: [UInt8]) {
        outbound += frame
        pendingControlBytes += frame.count
    }

    // MARK: DATA

    private mutating func receiveData(
        _ id: HTTP2StreamID, _ payload: [UInt8], endStream: Bool, flowControlledLength: Int, events: inout [Event]
    ) throws(HTTP2Error) {
        try requireNotIdle(id)
        // Return window credit for the amount received. The connection window has already decreased even for a closed stream, so always return its credit.
        // Record the credit to return and emit it together in `takeOutboundBytes()`, avoiding a WINDOW_UPDATE per frame.
        // This keeps a burst of small DATA frames from queuing one reply per frame.
        // shortcut: no receive-side backpressure (slow consumption cannot slow the server), add it when large responses need streaming consumption.
        pendingConnectionWindowCredit += flowControlledLength
        guard let stream = streams[id] else { return }
        switch stream.receiving {
        case .awaitingHead:
            resetStream(id, code: .protocolError, events: &events)
        case .ended:
            resetStream(id, code: .streamClosed, events: &events)
        case .receivingBody:
            // Reset the stream if the received length exceeds content-length and stop receiving more (§8.1.1).
            let received = stream.receivedBodyLength + payload.count
            if let declared = stream.declaredBodyLength, received > declared {
                resetStream(id, code: .protocolError, events: &events)
                return
            }
            streams[id]?.receivedBodyLength = received
            if !endStream { streams[id]?.pendingWindowCredit += flowControlledLength }
            if !payload.isEmpty { events.append(.responseData(id, payload)) }
            if endStream { finishResponse(id, events: &events) }
        }
    }

    // MARK: Header blocks

    /// Appends a header block fragment. Decodes the block and delivers it to the stream on the last fragment.
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

    /// Delivers decoded header fields to the stream. They are a response head, a 1xx informational response, or trailers.
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
                // HTTP/2 does not use 101 (§8.6). Ignore other informational responses (such as 100 Continue) and
                // wait for the final response (§8.1). An informational response must not end the stream.
                if endStream || head.status == 101 { resetStream(id, code: .protocolError, events: &events) }
                return
            }
            streams[id]?.receiving = .receivingBody
            // HEAD responses and 204 and 304 responses have no body, so skip the body length check even if content-length is present (§8.1.1).
            let hasNoBody = stream.isHeadRequest || head.status == 204 || head.status == 304
            streams[id]?.declaredBodyLength = hasNoBody ? nil : head.contentLength
            events.append(.responseHead(id, status: head.status, headers: head.headers))
            if endStream { finishResponse(id, events: &events) }
        case .receivingBody:
            // shortcut: validates and discards trailers, add support when handling responses where trailers carry meaning.
            // A header block after the final response head is trailers. It must have END_STREAM and cannot contain pseudo-headers (§8.1, §8.1.1).
            guard endStream, fields.allSatisfy({ $0.name.utf8.first != UInt8(ascii: ":") && HeaderValidation.isValid($0) }) else {
                resetStream(id, code: .protocolError, events: &events)
                return
            }
            finishResponse(id, events: &events)
        }
    }

    // MARK: Stream end

    /// The response ended with END_STREAM. A received body length different from `content-length` is a malformed response (§8.1.1).
    private mutating func finishResponse(_ id: HTTP2StreamID, events: inout [Event]) {
        if let stream = streams[id], let declared = stream.declaredBodyLength, stream.receivedBodyLength != declared {
            resetStream(id, code: .protocolError, events: &events)
        } else {
            finishReceiving(id, events: &events)
        }
    }

    /// Finishes a response that ended with END_STREAM and removes the stream. If any request body remains unsent, the server
    /// responded without waiting for it, so send RST_STREAM CANCEL and abandon the rest (§8.1).
    private mutating func finishReceiving(_ id: HTTP2StreamID, events: inout [Event]) {
        events.append(.streamClosed(id, resetCode: nil))
        guard let stream = streams[id] else { return }
        if stream.unsentBody != nil {
            queueControl(FrameEncoder.rstStream(id, code: .cancel))
        }
        streams.removeValue(forKey: id)
    }

    /// A stream error resets only that stream with RST_STREAM. If the full response has already been received, the event has already
    /// been emitted, so skip the duplicate notification.
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
        // The windows of open streams change by the same amount as the initial value (§6.9.2). Apply settings one at a time in received order
        // and check for overflow each time. Even a window that briefly exceeds 2^31-1 within one frame and then returns is an error.
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

    /// Handles GOAWAY by discarding streams above `lastStreamID`, which the server left unprocessed. Lets the remaining streams finish.
    /// Blocks new requests.
    private mutating func receiveGoAway(lastStreamID: HTTP2StreamID, code: UInt32, events: inout [Event]) {
        if phase == .open { phase = .draining }
        streams = streams.filter { $0.key.rawValue <= lastStreamID.rawValue }
        events.append(.goAway(lastStreamID: lastStreamID, code: code))
    }
}
