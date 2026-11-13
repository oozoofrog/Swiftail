/// 보낼 프레임을 바이트로 만든다(RFC 9113 §4.1, §6).
///
/// 보내는 프레임은 받는 프레임보다 단순하다. 패딩과 우선순위를 쓰지 않고, 길이가 상대의
/// MAX_FRAME_SIZE를 넘지 않게 나누는 일은 부르는 쪽(연결)이 한다.
enum FrameEncoder {
    private static func frame(_ type: FrameType, flags: UInt8 = 0, stream: HTTP2StreamID = .connection, payload: [UInt8] = []) -> [UInt8] {
        FrameHeader(payloadLength: payload.count, type: type, flags: flags, streamID: stream).bytes + payload
    }

    static func settings(_ settings: [Frame.Setting]) -> [UInt8] {
        let payload = settings.flatMap { setting in
            [UInt8(truncatingIfNeeded: setting.identifier >> 8), UInt8(truncatingIfNeeded: setting.identifier)] + setting.value.bigEndianBytes
        }
        return frame(.settings, payload: payload)
    }

    static func settingsAcknowledgement() -> [UInt8] {
        frame(.settings, flags: FrameFlag.acknowledgement)
    }

    /// 헤더 블록을 HEADERS 하나와 이어지는 CONTINUATION들로 나눈다. `maximumPayloadLength` 이하씩 담는다.
    static func headers(_ stream: HTTP2StreamID, block: [UInt8], endStream: Bool, maximumPayloadLength: Int) -> [UInt8] {
        var output: [UInt8] = []
        var rest = block[...]
        var isFirst = true
        repeat {
            let fragment = rest.prefix(maximumPayloadLength)
            rest = rest.dropFirst(fragment.count)
            var flags: UInt8 = rest.isEmpty ? FrameFlag.endHeaders : 0
            if isFirst && endStream { flags |= FrameFlag.endStream }
            output += frame(isFirst ? .headers : .continuation, flags: flags, stream: stream, payload: Array(fragment))
            isFirst = false
        } while !rest.isEmpty
        return output
    }

    static func data(_ stream: HTTP2StreamID, _ payload: ArraySlice<UInt8>, endStream: Bool) -> [UInt8] {
        frame(.data, flags: endStream ? FrameFlag.endStream : 0, stream: stream, payload: Array(payload))
    }

    static func rstStream(_ stream: HTTP2StreamID, code: HTTP2ErrorCode) -> [UInt8] {
        frame(.rstStream, stream: stream, payload: code.rawValue.bigEndianBytes)
    }

    static func pingAcknowledgement(_ data: [UInt8]) -> [UInt8] {
        frame(.ping, flags: FrameFlag.acknowledgement, payload: data)
    }

    static func goAway(lastStreamID: HTTP2StreamID, code: UInt32) -> [UInt8] {
        frame(.goAway, payload: lastStreamID.rawValue.bigEndianBytes + code.bigEndianBytes)
    }

    static func windowUpdate(_ stream: HTTP2StreamID, increment: Int) -> [UInt8] {
        frame(.windowUpdate, stream: stream, payload: UInt32(truncatingIfNeeded: increment).bigEndianBytes)
    }
}
