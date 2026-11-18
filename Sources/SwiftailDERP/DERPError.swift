/// The reason a DERP connection failed or rejected a request.
///
/// Failures originating in bytes sent by the server (`malformed` through `tooManyPendingReplies`) end the connection. Subsequent calls throw
/// `closed`. The `packetTooLarge` and `notReady` cases are caller errors and leave the connection open.
///
/// `docs/protocol-notes/derp-stun.md` Chapter 3, §4.2~§4.3.
public enum DERPError: Error, Sendable, Equatable {
    /// The frame, response head, or JSON violates the specification. Also covers invalid initialization arguments (`host` or nonce).
    case malformed
    /// The upgrade response status differs from 101.
    case upgradeRejected(status: Int)
    /// ServerKey verification failed or ServerInfo could not be opened.
    case handshakeFailed
    /// The received frame body exceeds the limit.
    case frameTooLarge
    /// The queue of Pings to answer is over its limit. The server is either failing to read or flooding the connection with Ping frames.
    case tooManyPendingReplies
    /// The outgoing packet exceeds `MaxPacketSize` (65,536 bytes).
    case packetTooLarge
    /// The caller invoked `send` before the handshake completed.
    case notReady
    /// The call is on a connection that already failed.
    case closed
}
