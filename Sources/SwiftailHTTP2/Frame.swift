/// 받은 HTTP/2 프레임.
///
/// 프레임은 9바이트 머리(길이 24비트, type 8비트, flags 8비트, 예약 1비트와 스트림 식별자 31비트)와
/// payload로 이루어진다(RFC 9113 §4.1). 상대가 보낸 바이트는 여기서 한 번 해석해 이 타입이 되고,
/// 이후 단계는 오프셋이나 flags를 다시 다루지 않는다. 패딩과 PRIORITY 필드는 이 단계에서 벗겨 낸다.
///
/// 해석은 프레임 한 개로 끝나는 규칙(길이, 스트림 0 여부, 패딩 범위)만 확인한다. 프레임 순서나
/// 스트림 상태에 걸린 규칙은 연결이 확인한다.
enum Frame: Equatable {
    /// SETTINGS의 매개변수 하나(§6.5.1).
    struct Setting: Equatable {
        var identifier: UInt16
        var value: UInt32
    }

    /// `flowControlledLength`는 패딩을 포함한 payload 길이로, 흐름 제어 창이 줄어드는 양이다(§6.9.1).
    case data(HTTP2StreamID, [UInt8], endStream: Bool, flowControlledLength: Int)
    case headers(HTTP2StreamID, blockFragment: [UInt8], endStream: Bool, endHeaders: Bool)
    /// 길이만 확인하고 버린다.
    case priority
    case rstStream(HTTP2StreamID, code: UInt32)
    case settings([Setting])
    case settingsAcknowledgement
    case pushPromise
    case ping(ack: Bool, data: [UInt8])
    case goAway(lastStreamID: HTTP2StreamID, code: UInt32)
    /// 스트림 0이면 연결 창이다. 증가량 0의 처리는 연결이 정한다.
    case windowUpdate(HTTP2StreamID, increment: UInt32)
    case continuation(HTTP2StreamID, blockFragment: [UInt8], endHeaders: Bool)
    /// 모르는 type. 규격은 무시하라고 한다(§4.1).
    case unknown(type: UInt8)
}

/// 프레임 머리(§4.1).
struct FrameHeader: Equatable {
    static let size = 9

    var payloadLength: Int
    var type: UInt8
    var flags: UInt8
    var streamID: HTTP2StreamID

    /// 머리 9바이트를 해석한다. 바이트가 모자라면 `nil`.
    init?(parsing bytes: ArraySlice<UInt8>) {
        var reader = ByteReader(bytes)
        guard let high = reader.uint8(), let low = reader.uint16(), let type = reader.uint8(),
              let flags = reader.uint8(), let streamID = reader.uint32()
        else { return nil }
        payloadLength = Int(high) << 16 | Int(low)
        self.type = type
        self.flags = flags
        // 최상위 비트는 예약이다. 받는 쪽은 무시한다.
        self.streamID = HTTP2StreamID(streamID & 0x7fff_ffff)
    }

    init(payloadLength: Int, type: FrameType, flags: UInt8 = 0, streamID: HTTP2StreamID) {
        self.payloadLength = payloadLength
        self.type = type.rawValue
        self.flags = flags
        self.streamID = streamID
    }

    var bytes: [UInt8] {
        let length = UInt32(truncatingIfNeeded: payloadLength)
        return [UInt8(truncatingIfNeeded: length >> 16), UInt8(truncatingIfNeeded: length >> 8), UInt8(truncatingIfNeeded: length), type, flags]
            + streamID.rawValue.bigEndianBytes
    }
}

/// 프레임 type(§6). 모르는 type은 `Frame.unknown`이 된다.
enum FrameType: UInt8 {
    case data = 0x0
    case headers = 0x1
    case priority = 0x2
    case rstStream = 0x3
    case settings = 0x4
    case pushPromise = 0x5
    case ping = 0x6
    case goAway = 0x7
    case windowUpdate = 0x8
    case continuation = 0x9
}

/// 프레임 flags 비트(§6).
enum FrameFlag {
    static let endStream: UInt8 = 0x1
    static let acknowledgement: UInt8 = 0x1
    static let endHeaders: UInt8 = 0x4
    static let padded: UInt8 = 0x8
    static let priority: UInt8 = 0x20
}

extension Frame {
    /// 머리와 payload로 프레임을 해석한다. 길이나 패딩이 규격과 맞지 않으면 연결 오류.
    init(header: FrameHeader, payload: ArraySlice<UInt8>) throws(HTTP2Error) {
        let stream = header.streamID
        let flags = header.flags
        var reader = ByteReader(payload)
        guard let type = FrameType(rawValue: header.type) else {
            self = .unknown(type: header.type)
            return
        }
        switch type {
        case .data:
            guard stream != .connection else { throw .connection(.protocolError) }
            let data = try Self.removingPadding(from: payload, flags: flags)
            self = .data(stream, Array(data), endStream: flags & FrameFlag.endStream != 0, flowControlledLength: payload.count)
        case .headers:
            guard stream != .connection else { throw .connection(.protocolError) }
            let hasPriority = flags & FrameFlag.priority != 0
            let content = try Self.removingPadding(from: payload, flags: flags, prefixSize: hasPriority ? 5 : 0)
            // 우선순위 필드(의존 스트림 4바이트, 가중치 1바이트)는 버린다.
            let fragment = content.dropFirst(hasPriority ? 5 : 0)
            self = .headers(stream, blockFragment: Array(fragment), endStream: flags & FrameFlag.endStream != 0, endHeaders: flags & FrameFlag.endHeaders != 0)
        case .priority:
            guard stream != .connection else { throw .connection(.protocolError) }
            guard payload.count == 5 else { throw .connection(.frameSizeError) }
            // shortcut: 우선순위는 따르지 않는다(RFC 9113이 이미 폐기 방향), 우선순위를 요구하는 상대를 만나면 올린다.
            self = .priority
        case .rstStream:
            guard stream != .connection else { throw .connection(.protocolError) }
            guard payload.count == 4, let code = reader.uint32() else { throw .connection(.frameSizeError) }
            self = .rstStream(stream, code: code)
        case .settings:
            guard stream == .connection else { throw .connection(.protocolError) }
            if flags & FrameFlag.acknowledgement != 0 {
                guard payload.isEmpty else { throw .connection(.frameSizeError) }
                self = .settingsAcknowledgement
                return
            }
            guard payload.count % 6 == 0 else { throw .connection(.frameSizeError) }
            var settings: [Setting] = []
            while let identifier = reader.uint16(), let value = reader.uint32() {
                settings.append(Setting(identifier: identifier, value: value))
            }
            self = .settings(settings)
        case .pushPromise:
            self = .pushPromise
        case .ping:
            guard stream == .connection else { throw .connection(.protocolError) }
            guard payload.count == 8 else { throw .connection(.frameSizeError) }
            self = .ping(ack: flags & FrameFlag.acknowledgement != 0, data: Array(payload))
        case .goAway:
            guard stream == .connection else { throw .connection(.protocolError) }
            // 8바이트 뒤의 디버그 데이터는 쓰지 않는다.
            guard let last = reader.uint32(), let code = reader.uint32() else { throw .connection(.frameSizeError) }
            self = .goAway(lastStreamID: HTTP2StreamID(last & 0x7fff_ffff), code: code)
        case .windowUpdate:
            guard payload.count == 4, let increment = reader.uint32() else { throw .connection(.frameSizeError) }
            self = .windowUpdate(stream, increment: increment & 0x7fff_ffff)
        case .continuation:
            guard stream != .connection else { throw .connection(.protocolError) }
            self = .continuation(stream, blockFragment: Array(payload), endHeaders: flags & FrameFlag.endHeaders != 0)
        }
    }

    /// PADDED flag가 있으면 Pad Length를 읽고 뒤쪽 패딩을 뺀 payload를 돌려준다(§6.1, §6.2).
    /// `prefixSize`는 패딩을 뺀 내용 앞에 반드시 있어야 하는 고정 필드(HEADERS의 우선순위)의 크기다.
    /// 패딩이 payload를 넘으면 PROTOCOL_ERROR, 내용이 고정 필드보다 짧으면 FRAME_SIZE_ERROR인 연결 오류.
    private static func removingPadding(
        from payload: ArraySlice<UInt8>, flags: UInt8, prefixSize: Int = 0
    ) throws(HTTP2Error) -> ArraySlice<UInt8> {
        var content = payload
        if flags & FrameFlag.padded != 0 {
            guard let padLength = content.first else { throw .connection(.frameSizeError) }
            content = content.dropFirst()
            guard Int(padLength) <= content.count else { throw .connection(.protocolError) }
            content = content.dropLast(Int(padLength))
        }
        guard content.count >= prefixSize else { throw .connection(.frameSizeError) }
        return content
    }
}

extension UInt32 {
    var bigEndianBytes: [UInt8] {
        [UInt8(truncatingIfNeeded: self >> 24), UInt8(truncatingIfNeeded: self >> 16), UInt8(truncatingIfNeeded: self >> 8), UInt8(truncatingIfNeeded: self)]
    }
}
