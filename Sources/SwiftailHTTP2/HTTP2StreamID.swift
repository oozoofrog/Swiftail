/// A stream identifier (RFC 9113 §5.1.1).
///
/// Client-initiated streams use increasing odd numbers starting at 1. The value 0 identifies the connection as a whole and is reserved outside streams.
public struct HTTP2StreamID: Hashable, Sendable {
    public let rawValue: UInt32

    /// The connection-wide identifier 0. A WINDOW_UPDATE with this identifier updates the connection's flow control window.
    static let connection = HTTP2StreamID(0)

    init(_ rawValue: UInt32) {
        self.rawValue = rawValue
    }
}
