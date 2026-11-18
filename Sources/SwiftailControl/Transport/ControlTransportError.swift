/// The reason the control transport layer (upgrade, Noise handshake, records, early payload) rejected input.
///
/// Every case leaves the connection unusable. After throwing an error, the state machine throws `closed` on subsequent calls.
/// Errors omit key material and strings sent by the server.
///
/// `docs/protocol-notes/control-transport.md` Chapter 3, §4.4, §4.5, §4.6.
public enum ControlTransportError: Error, Sendable, Equatable {
    /// The length, type, or format violates the specification.
    case malformed
    /// The upgrade response status differs from 101.
    case upgradeRejected(status: Int)
    /// The handshake failed due to response decryption failure, a server error message, or a zero shared secret.
    case handshakeFailed
    /// Transport-phase record decryption failed. Discard the connection.
    case authenticationFailed
    /// A record, early payload, or upgrade response head exceeds the limit.
    case messageTooLarge
    /// A call was made on a state machine that failed or already finished.
    case closed
}
