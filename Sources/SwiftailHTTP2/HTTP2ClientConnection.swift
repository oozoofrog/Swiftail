/// HTTP/2 클라이언트 연결 하나를 입출력 없는 값 타입 상태 기계로 만든 것.
///
/// 소켓도 시계도 갖지 않는다. 호출하는 쪽(actor)이 상대에게서 받은 바이트를 `receive`로 넣으면
/// 사건이 나오고, 상대에게 보낼 바이트는 `takeOutboundBytes()`로 꺼내 소켓에 쓴다. 연결 하나에 스트림 여러
/// 개를 다중화한다. 구현은 파일마다 한 가지 일을 한다:
///
/// - 바이트 ↔ 프레임: `FrameBuffer`, `Frame`, `FrameEncoder`
/// - 헤더 압축: `HPACKDecoder`, `HPACKEncoder` (정수·문자열 `HPACKPrimitives`, 허프만 `HPACKHuffman`, 표 `HPACKStaticTable`·`HPACKDynamicTable`)
/// - 흐름 제어와 스트림: `FlowControlWindow`, `PeerSettings`, `StreamState`
/// - 프레임 처리: `HTTP2ClientConnection+Receiving`, 요청과 본문 전송: `HTTP2ClientConnection+Sending`
///
/// 규격: RFC 9113(HTTP/2), RFC 7541(HPACK).
public struct HTTP2ClientConnection: Sendable {
    public struct Request: Sendable {
        public var method: String
        public var path: String
        public var authority: String
        /// 의사 헤더를 뺀 나머지.
        public var headers: [HeaderField]

        public init(method: String, path: String, authority: String, headers: [HeaderField] = []) {
            self.method = method
            self.path = path
            self.authority = authority
            self.headers = headers
        }
    }

    public enum Event: Sendable, Equatable {
        case responseHead(HTTP2StreamID, status: Int, headers: [HeaderField])
        case responseData(HTTP2StreamID, [UInt8])
        /// 스트림이 끝났다. resetCode가 nil이면 정상 종료(END_STREAM), 아니면 RST_STREAM의 오류 코드.
        case streamClosed(HTTP2StreamID, resetCode: UInt32?)
        /// 상대가 GOAWAY를 보냈다. lastStreamID보다 큰 스트림은 처리되지 않았다.
        case goAway(lastStreamID: HTTP2StreamID, code: UInt32)
    }

    enum Phase {
        case open
        /// GOAWAY를 받았다. 진행 중인 스트림은 끝까지 받지만 새 요청은 시작하지 않는다.
        case draining
        /// 연결 오류로 끝났다.
        case failed
    }

    /// 이어지는 CONTINUATION을 기다리는 헤더 블록(§4.3). 그 사이에는 다른 프레임이 끼어들 수 없다.
    struct HeaderBlockInProgress {
        var stream: HTTP2StreamID
        var bytes: [UInt8]
        var endStream: Bool
    }

    /// 클라이언트 연결 프리페이스의 첫 24바이트(§3.4).
    static let preface = Array("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)

    /// 알리는 SETTINGS 식별자(§6.5.2).
    static let enablePushIdentifier: UInt16 = 0x2
    static let maxHeaderListSizeIdentifier: UInt16 = 0x6

    /// 헤더 블록(CONTINUATION을 합친 것)의 한도.
    static let maximumHeaderBlockSize = 65_536

    /// 상대가 요구해서 쌓인 제어 프레임(PING·SETTINGS ACK, RST_STREAM)의 대기 바이트 한도.
    ///
    /// 상대는 작은 프레임을 얼마든지 보낼 수 있고(PING 하나는 17바이트이고 17바이트 ACK를 낳는다), 답은
    /// 호출하는 쪽이 `takeOutboundBytes()`로 꺼내 가야 비워진다. 소켓이 막혀 있으면 쌓이기만 하므로 상한을
    /// 둔다. 한도는 헤더 블록 한도와 같은 64KiB다. Go의 `x/net/http2` 서버도 대기 제어 프레임을 10,000개로
    /// 묶는다. 넘으면 ENHANCE_YOUR_CALM 연결 오류로 끝내고(§7), 그 GOAWAY(17바이트)는 한도와 상관없이
    /// 뒤에 붙는다.
    ///
    /// WINDOW_UPDATE는 여기에 들지 않는다. 정상 서버도 작은 DATA 프레임을 많이 보낼 수 있으므로, 프레임마다
    /// 답을 쌓지 않고 돌려줄 창의 양만 적어 둔다(`pendingConnectionWindowCredit`).
    static let maximumPendingControlBytes = 65_536

    var phase = Phase.open
    var outbound: [UInt8]
    /// `outbound` 가운데 상대가 요구해서 쌓인 제어 프레임의 바이트. `takeOutboundBytes()`가 비운다.
    var pendingControlBytes = 0
    /// 받은 DATA만큼 돌려줄 연결 창. `takeOutboundBytes()`가 WINDOW_UPDATE 하나로 내보낸다.
    /// 스트림 몫은 `StreamState.pendingWindowCredit`에 있다.
    var pendingConnectionWindowCredit = 0
    var frames = FrameBuffer()
    var decoder = HPACKDecoder()
    var peerSettings = PeerSettings()
    /// 연결 전체의 보내는 창.
    var sendWindow = FlowControlWindow()
    var streams: [HTTP2StreamID: StreamState] = [:]
    var nextStreamID: UInt32 = 1
    var headerBlock: HeaderBlockInProgress?
    /// 상대의 첫 프레임은 SETTINGS여야 한다(§3.4).
    var hasReceivedSettings = false

    /// 연결을 시작한다. 프리페이스와 SETTINGS가 보낼 바이트로 준비된다.
    ///
    /// SETTINGS로 서버 푸시를 끄고(ENABLE_PUSH=0), 받을 헤더 목록의 한도를 알린다. 흐름 제어 창과
    /// 프레임 크기는 초깃값 그대로 둔다.
    public init() {
        let settings = [
            Frame.Setting(identifier: Self.enablePushIdentifier, value: 0),
            Frame.Setting(identifier: Self.maxHeaderListSizeIdentifier, value: UInt32(HPACKDecoder.defaultHeaderListSize)),
        ]
        outbound = Self.preface + FrameEncoder.settings(settings)
    }

    /// 상대에게 보낼 바이트를 꺼낸다. 없으면 빈 배열. `init`, `startRequest`, `cancel`, `receive` 뒤에 부른다.
    public mutating func takeOutboundBytes() -> [UInt8] {
        if phase != .failed { queueWindowUpdates() }
        defer {
            outbound = []
            pendingControlBytes = 0
        }
        return outbound
    }

    /// 적어 둔 창을 WINDOW_UPDATE로 바꾼다: 연결 하나, 그리고 스트림마다 하나(식별자 순).
    private mutating func queueWindowUpdates() {
        outbound += Self.windowUpdates(.connection, credit: pendingConnectionWindowCredit)
        pendingConnectionWindowCredit = 0
        for id in streams.keys.sorted(by: { $0.rawValue < $1.rawValue }) {
            guard let credit = streams[id]?.pendingWindowCredit, credit > 0 else { continue }
            outbound += Self.windowUpdates(id, credit: credit)
            streams[id]?.pendingWindowCredit = 0
        }
    }

    /// 한 프레임의 증가분은 2³¹−1까지다(§6.9). 그보다 크면 나눠 낸다.
    private static func windowUpdates(_ stream: HTTP2StreamID, credit: Int) -> [UInt8] {
        var bytes: [UInt8] = []
        var remaining = credit
        while remaining > 0 {
            let increment = min(remaining, FlowControlWindow.maximum)
            bytes += FrameEncoder.windowUpdate(stream, increment: increment)
            remaining -= increment
        }
        return bytes
    }

    /// 상대에게서 받은 바이트를 넣는다. 프레임 경계와 무관하게 임의의 조각이어도 된다.
    /// 오류를 던지면 연결은 끝난 것이다. 그때도 `takeOutboundBytes()`에 GOAWAY가 남아 있을 수 있다.
    public mutating func receive(_ bytes: [UInt8]) throws(HTTP2Error) -> [Event] {
        guard phase != .failed else { throw .connectionClosed }
        var events: [Event] = []
        do throws(HTTP2Error) {
            frames.append(bytes)
            while let frame = try frames.nextFrame() {
                try handle(frame, events: &events)
                guard pendingControlBytes <= Self.maximumPendingControlBytes else { throw .connection(.enhanceYourCalm) }
            }
            frames.discardConsumedBytes()
        } catch {
            fail(with: error)
            throw error
        }
        return events
    }

    /// 연결 오류를 상대에게 알리고(GOAWAY) 연결을 끝낸다. 상대가 시작한 스트림은 받지 않으므로 last-stream-id는 0이다.
    private mutating func fail(with error: HTTP2Error) {
        phase = .failed
        guard case .connectionFailed(let code) = error else { return }
        outbound += FrameEncoder.goAway(lastStreamID: .connection, code: code)
    }
}
