/// A received HTTP/2 frame.
///
/// A frame consists of a 9-byte header (24-bit length, 8-bit type, 8-bit flags, 1 reserved bit, and a 31-bit stream identifier)
/// and a payload (RFC 9113 §4.1). The peer's bytes are parsed into this type once, so later stages avoid working with
/// offsets or flags again. This stage strips the padding and PRIORITY fields.
///
/// Parsing checks rules local to a single frame (length, whether stream ID 0 is valid for the frame type, and padding bounds). The connection
/// checks frame ordering and rules that depend on stream state.
enum Frame: Equatable {
    /// One SETTINGS parameter (§6.5.1).
    struct Setting: Equatable {
        var identifier: UInt16
        var value: UInt32
    }

    /// `flowControlledLength` is the payload length including padding, equal to the decrement in the flow control window (§6.9.1).
    case data(HTTP2StreamID, [UInt8], endStream: Bool, flowControlledLength: Int)
    case headers(HTTP2StreamID, blockFragment: [UInt8], endStream: Bool, endHeaders: Bool)
    /// Checks the stream identifier and payload length, then discards the priority information.
    case priority
    case rstStream(HTTP2StreamID, code: UInt32)
    case settings([Setting])
    case settingsAcknowledgement
    case pushPromise
    case ping(ack: Bool, data: [UInt8])
    case goAway(lastStreamID: HTTP2StreamID, code: UInt32)
    /// Stream 0 refers to the connection window. The connection decides how to handle a zero increment.
    case windowUpdate(HTTP2StreamID, increment: UInt32)
    case continuation(HTTP2StreamID, blockFragment: [UInt8], endHeaders: Bool)
    /// An unknown type. The specification requires ignoring it (§4.1).
    case unknown(type: UInt8)
}

/// A frame header (§4.1).
struct FrameHeader: Equatable {
    static let size = 9

    var payloadLength: Int
    var type: UInt8
    var flags: UInt8
    var streamID: HTTP2StreamID

    /// Parses the 9-byte header. Returns `nil` if there are too few bytes.
    init?(parsing bytes: ArraySlice<UInt8>) {
        var reader = ByteReader(bytes)
        guard let high = reader.uint8(), let low = reader.uint16(), let type = reader.uint8(),
              let flags = reader.uint8(), let streamID = reader.uint32()
        else { return nil }
        payloadLength = Int(high) << 16 | Int(low)
        self.type = type
        self.flags = flags
        // The high bit is reserved. Receivers ignore it.
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

/// The frame type (§6). An unknown type becomes `Frame.unknown`.
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

/// The frame's flag bits (§6).
enum FrameFlag {
    static let endStream: UInt8 = 0x1
    static let acknowledgement: UInt8 = 0x1
    static let endHeaders: UInt8 = 0x4
    static let padded: UInt8 = 0x8
    static let priority: UInt8 = 0x20
}

extension Frame {
    /// Parses a frame from its header and payload. Invalid length or padding is a connection error.
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
            // Discard the priority fields (4 bytes of stream dependency and 1 byte of weight).
            let fragment = content.dropFirst(hasPriority ? 5 : 0)
            self = .headers(stream, blockFragment: Array(fragment), endStream: flags & FrameFlag.endStream != 0, endHeaders: flags & FrameFlag.endHeaders != 0)
        case .priority:
            guard stream != .connection else { throw .connection(.protocolError) }
            guard payload.count == 5 else { throw .connection(.frameSizeError) }
            // shortcut: ignores priority (RFC 9113 is already moving to deprecate it), add support when a peer requires priority.
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
            // The debug data after the first 8 bytes is unused.
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

    /// Reads Pad Length if the PADDED flag is set and returns the payload without trailing padding (§6.1, §6.2).
    /// `prefixSize` is the size of the fixed fields that must start the unpadded content (the HEADERS priority fields).
    /// Padding beyond the payload is a PROTOCOL_ERROR connection error. Content shorter than the fixed fields is a FRAME_SIZE_ERROR connection error.
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
