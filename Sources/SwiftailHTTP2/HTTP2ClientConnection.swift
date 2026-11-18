/// An HTTP/2 client connection implemented as a value-type state machine with no I/O.
///
/// Holds neither a socket nor a clock. The caller (an actor) feeds bytes from the peer to `receive` to produce
/// events, then takes bytes to send with `takeOutboundBytes()` and writes them to the socket. One connection
/// multiplexes several streams. Each implementation file covers one responsibility.
///
/// - Bytes ↔ frames: `FrameBuffer`, `Frame`, `FrameEncoder`
/// - Header compression: `HPACKDecoder`, `HPACKEncoder` (integers and strings in `HPACKPrimitives`, Huffman in `HPACKHuffman`, tables in `HPACKStaticTable` and `HPACKDynamicTable`)
/// - Flow control and streams: `FlowControlWindow`, `PeerSettings`, `StreamState`
/// - Frame handling in `HTTP2ClientConnection+Receiving`, request and body sending in `HTTP2ClientConnection+Sending`
///
/// Specifications are RFC 9113 (HTTP/2) and RFC 7541 (HPACK).
public struct HTTP2ClientConnection: Sendable {
    public struct Request: Sendable {
        public var method: String
        public var path: String
        public var authority: String
        /// The request's regular header fields, excluding pseudo-headers.
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
        /// The stream ended. A nil resetCode indicates a normal end (END_STREAM). Otherwise, it contains the RST_STREAM error code.
        case streamClosed(HTTP2StreamID, resetCode: UInt32?)
        /// The peer sent GOAWAY. It left streams above lastStreamID unprocessed.
        case goAway(lastStreamID: HTTP2StreamID, code: UInt32)
    }

    enum Phase {
        case open
        /// GOAWAY was received. In-flight streams can finish, and new requests are blocked.
        case draining
        /// The connection ended with a connection error.
        case failed
    }

    /// A header block waiting for CONTINUATION frames (§4.3). No other frame may intervene.
    struct HeaderBlockInProgress {
        var stream: HTTP2StreamID
        var bytes: [UInt8]
        var endStream: Bool
    }

    /// The first 24 bytes of the client connection preface (§3.4).
    static let preface = Array("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)

    /// The SETTINGS identifiers to advertise (§6.5.2).
    static let enablePushIdentifier: UInt16 = 0x2
    static let maxHeaderListSizeIdentifier: UInt16 = 0x6

    /// The limit on a header block, including its CONTINUATION frames.
    static let maximumHeaderBlockSize = 65_536

    /// The byte limit for queued control frames generated in response to the peer (PING ACK, SETTINGS ACK, and RST_STREAM).
    ///
    /// The peer can send arbitrarily many small frames (a 17-byte PING produces a 17-byte ACK). Replies stay queued
    /// until the caller drains them via `takeOutboundBytes()`. If the socket is blocked, replies only accumulate,
    /// so the queue has a cap. The limit matches the 64KiB header block limit. Go's `x/net/http2` server also caps queued
    /// control frames at 10,000. Exceeding the limit ends the connection with ENHANCE_YOUR_CALM (§7) and appends
    /// the 17-byte GOAWAY regardless of the limit.
    ///
    /// WINDOW_UPDATE is exempt. Even a well-behaved server can send many small DATA frames, so track only the
    /// total window credit to return (`pendingConnectionWindowCredit`) and avoid queuing a reply for each frame.
    static let maximumPendingControlBytes = 65_536

    var phase = Phase.open
    var outbound: [UInt8]
    /// The bytes in `outbound` for queued control frames required by the peer. `takeOutboundBytes()` clears them.
    var pendingControlBytes = 0
    /// The connection window credit to return for received DATA. `takeOutboundBytes()` emits it in one WINDOW_UPDATE.
    /// The stream's share is in `StreamState.pendingWindowCredit`.
    var pendingConnectionWindowCredit = 0
    var frames = FrameBuffer()
    var decoder = HPACKDecoder()
    var peerSettings = PeerSettings()
    /// The connection-wide send window.
    var sendWindow = FlowControlWindow()
    var streams: [HTTP2StreamID: StreamState] = [:]
    var nextStreamID: UInt32 = 1
    var headerBlock: HeaderBlockInProgress?
    /// The peer's first frame must be SETTINGS (§3.4).
    var hasReceivedSettings = false

    /// Creates a client connection and queues the preface and SETTINGS for transmission.
    ///
    /// SETTINGS disables server push (ENABLE_PUSH=0) and advertises the limit on incoming header lists. The flow control window
    /// and frame size keep their initial values.
    public init() {
        let settings = [
            Frame.Setting(identifier: Self.enablePushIdentifier, value: 0),
            Frame.Setting(identifier: Self.maxHeaderListSizeIdentifier, value: UInt32(HPACKDecoder.defaultHeaderListSize)),
        ]
        outbound = Self.preface + FrameEncoder.settings(settings)
    }

    /// Takes bytes to send to the peer, returning an empty array when there are none. Call after `init`, `startRequest`, `cancel`, or `receive`.
    public mutating func takeOutboundBytes() -> [UInt8] {
        if phase != .failed { queueWindowUpdates() }
        defer {
            outbound = []
            pendingControlBytes = 0
        }
        return outbound
    }

    /// Converts recorded window credit to WINDOW_UPDATE frames, one for the connection and one per stream in identifier order.
    private mutating func queueWindowUpdates() {
        outbound += Self.windowUpdates(.connection, credit: pendingConnectionWindowCredit)
        pendingConnectionWindowCredit = 0
        for id in streams.keys.sorted(by: { $0.rawValue < $1.rawValue }) {
            guard let credit = streams[id]?.pendingWindowCredit, credit > 0 else { continue }
            outbound += Self.windowUpdates(id, credit: credit)
            streams[id]?.pendingWindowCredit = 0
        }
    }

    /// One frame can increase the window by up to 2³¹−1 (§6.9). Split larger increases.
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

    /// Accepts bytes received from the peer. Chunks may have any size and need not align with frame boundaries.
    /// A thrown error means the connection has ended. A GOAWAY may still be pending in `takeOutboundBytes()`.
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

    /// Reports a connection error to the peer (GOAWAY) and ends the connection. The client accepts no peer-initiated streams, so last-stream-id is 0.
    private mutating func fail(with error: HTTP2Error) {
        phase = .failed
        guard case .connectionFailed(let code) = error else { return }
        outbound += FrameEncoder.goAway(lastStreamID: .connection, code: code)
    }
}
