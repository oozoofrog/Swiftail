/// The SETTINGS values advertised by the peer (RFC 9113 §6.5.2).
///
/// Stores only values this connection must honor as a sender. The encoder uses no dynamic table, so the peer's HEADER_TABLE_SIZE
/// is irrelevant. For ENABLE_PUSH, it checks only that the server cannot advertise 1.
struct PeerSettings: Equatable {
    private enum Identifier: UInt16 {
        case enablePush = 0x2
        case maxConcurrentStreams = 0x3
        case initialWindowSize = 0x4
        case maxFrameSize = 0x5
    }

    /// The concurrent stream count allowed by the peer. Unlimited if the peer omits it.
    var maxConcurrentStreams = Int.max
    var initialWindowSize = FlowControlWindow.defaultInitialSize
    /// The maximum frame payload length accepted by the peer.
    var maxFrameSize = 16_384
    // shortcut: ignores the peer's MAX_HEADER_LIST_SIZE (request headers are small), check it when sending large headers.

    /// Applies SETTINGS. An out-of-range value is a connection error, and unknown identifiers are ignored.
    /// On success, returns the change in INITIAL_WINDOW_SIZE to add to open stream windows. Values in one SETTINGS frame must be
    /// applied to windows in arrival order to catch intermediate overflows (§6.9.2), so the connection calls this once per setting.
    mutating func apply(_ settings: [Frame.Setting]) throws(HTTP2Error) -> Int {
        let previousInitialWindowSize = initialWindowSize
        for setting in settings {
            let value = Int(setting.value)
            switch Identifier(rawValue: setting.identifier) {
            case .enablePush:
                // A server advertising 1, or any value other than 0 and 1, is a PROTOCOL_ERROR.
                guard setting.value == 0 else { throw .connection(.protocolError) }
            case .maxConcurrentStreams:
                maxConcurrentStreams = value
            case .initialWindowSize:
                guard value <= FlowControlWindow.maximum else { throw .connection(.flowControlError) }
                initialWindowSize = value
            case .maxFrameSize:
                guard (16_384...16_777_215).contains(value) else { throw .connection(.protocolError) }
                maxFrameSize = value
            case nil:
                continue
            }
        }
        return initialWindowSize - previousInitialWindowSize
    }
}
