/// Splits the byte stream from the peer into frames.
///
/// TCP and Noise records do not preserve frame boundaries. Buffers received chunks until the 9-byte header and
/// full payload are available, then emits one frame. It checks the length against the limit as soon as it reads the header,
/// so a large advertised length cannot make it wait for and buffer that many bytes.
struct FrameBuffer {
    /// The initial advertised SETTINGS_MAX_FRAME_SIZE (§6.5.2). This connection never increases it.
    static let defaultMaximumPayloadLength = 16_384

    private let maximumPayloadLength: Int
    private var bytes: [UInt8] = []
    /// The first position in `bytes` not yet emitted as a frame.
    private var start = 0

    init(maximumPayloadLength: Int = defaultMaximumPayloadLength) {
        self.maximumPayloadLength = maximumPayloadLength
    }

    mutating func append(_ newBytes: [UInt8]) {
        bytes.append(contentsOf: newBytes)
    }

    /// Takes one complete frame. Returns `nil` if more bytes are needed.
    /// A length over the limit is a FRAME_SIZE_ERROR connection error (§4.2).
    mutating func nextFrame() throws(HTTP2Error) -> Frame? {
        guard let header = FrameHeader(parsing: bytes[start...].prefix(FrameHeader.size)) else { return nil }
        guard header.payloadLength <= maximumPayloadLength else { throw .connection(.frameSizeError) }
        let end = start + FrameHeader.size + header.payloadLength
        guard bytes.count >= end else { return nil }
        let frame = try Frame(header: header, payload: bytes[start + FrameHeader.size..<end])
        start = end
        return frame
    }

    /// Discards bytes already emitted. Call once after taking all frames to keep the buffered data at or below one frame.
    mutating func discardConsumedBytes() {
        bytes.removeFirst(start)
        start = 0
    }
}
