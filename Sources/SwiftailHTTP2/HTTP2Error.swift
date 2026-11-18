/// An error thrown by `HTTP2ClientConnection`.
public enum HTTP2Error: Error, Sendable, Equatable {
    /// The peer violated the specification or reported a connection error. The connection has ended. `code` is an RFC 9113 §7 error code.
    case connectionFailed(code: UInt32)
    /// The connection ended or received GOAWAY, so it cannot start new requests.
    case connectionClosed
    /// The peer's concurrent stream limit was exceeded.
    case tooManyStreams
    /// The request is invalid (for example, an empty method or path or an uppercase header name).
    case invalidRequest
}

/// An error code from RFC 9113 §7. Connection errors (GOAWAY) and stream errors (RST_STREAM) share the same codes.
enum HTTP2ErrorCode: UInt32 {
    case noError = 0x0
    case protocolError = 0x1
    case flowControlError = 0x3
    case streamClosed = 0x5
    case frameSizeError = 0x6
    case cancel = 0x8
    case compressionError = 0x9
    case enhanceYourCalm = 0xb
}

extension HTTP2Error {
    /// An error that requires ending the connection with this code.
    static func connection(_ code: HTTP2ErrorCode) -> HTTP2Error {
        .connectionFailed(code: code.rawValue)
    }
}
