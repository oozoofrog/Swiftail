/// The send-side flow control window (RFC 9113 §5.2, §6.9).
///
/// The number of DATA bytes the peer has agreed to receive. Each DATA frame reduces it, and WINDOW_UPDATE from the peer
/// increases it. The connection and each stream have separate windows, and both must allow a DATA frame to be sent.
/// If the peer decreases SETTINGS_INITIAL_WINDOW_SIZE, a stream's window can become negative (§6.9.2).
struct FlowControlWindow: Equatable {
    /// The window cannot exceed 2^31-1 (§6.9.1).
    static let maximum = Int(Int32.max)
    /// The initial value of the connection and stream windows (§6.9.2).
    static let defaultInitialSize = 65_535

    /// An attempt to increase a window past 2^31-1. A connection window produces a connection error, and a stream window produces a stream error.
    struct Overflow: Error {}

    private(set) var available: Int

    init(_ available: Int = defaultInitialSize) {
        self.available = available
    }

    /// Decreases the window by the amount sent. The caller requests at most `available`.
    mutating func consume(_ count: Int) {
        available -= count
    }

    /// Adjusts the window by `delta` due to WINDOW_UPDATE or a change in INITIAL_WINDOW_SIZE. `delta` may be negative.
    mutating func adjust(by delta: Int) throws(Overflow) {
        guard available + delta <= Self.maximum else { throw Overflow() }
        available += delta
    }
}
