/// 상대가 보낸 바이트 스트림을 프레임으로 자른다.
///
/// TCP나 Noise 레코드는 프레임 경계를 지켜 주지 않는다. 받은 조각을 쌓아 두었다가 머리 9바이트와
/// payload가 다 모이면 프레임 하나를 내놓는다. 길이는 머리를 읽는 즉시 한도와 비교하므로, 상대가
/// 큰 길이를 알려도 그만큼의 바이트를 기다리며 쌓지 않는다.
struct FrameBuffer {
    /// 알린 SETTINGS_MAX_FRAME_SIZE의 초깃값(§6.5.2). 이 연결은 더 키우지 않는다.
    static let defaultMaximumPayloadLength = 16_384

    private let maximumPayloadLength: Int
    private var bytes: [UInt8] = []
    /// `bytes`에서 아직 프레임으로 내놓지 않은 첫 위치.
    private var start = 0

    init(maximumPayloadLength: Int = defaultMaximumPayloadLength) {
        self.maximumPayloadLength = maximumPayloadLength
    }

    mutating func append(_ newBytes: [UInt8]) {
        bytes.append(contentsOf: newBytes)
    }

    /// 완성된 프레임 하나를 꺼낸다. 더 모아야 하면 `nil`.
    /// 길이가 한도를 넘으면 FRAME_SIZE_ERROR(§4.2)인 연결 오류.
    mutating func nextFrame() throws(HTTP2Error) -> Frame? {
        guard let header = FrameHeader(parsing: bytes[start...].prefix(FrameHeader.size)) else { return nil }
        guard header.payloadLength <= maximumPayloadLength else { throw .connection(.frameSizeError) }
        let end = start + FrameHeader.size + header.payloadLength
        guard bytes.count >= end else { return nil }
        let frame = try Frame(header: header, payload: bytes[start + FrameHeader.size..<end])
        start = end
        return frame
    }

    /// 이미 내놓은 바이트를 버린다. 프레임을 다 꺼낸 뒤 한 번 부르면 쌓인 양이 한 프레임 이하로 유지된다.
    mutating func discardConsumedBytes() {
        bytes.removeFirst(start)
        start = 0
    }
}
