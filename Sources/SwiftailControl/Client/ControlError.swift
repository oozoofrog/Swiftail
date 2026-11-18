/// A control client failure.
///
/// `ControlClient.run()` backs off and retries recoverable failures (`connection`, `http`) internally. It throws only
/// failures that retrying cannot help. Messages omit keys, auth keys, and file paths.
///
/// `docs/contracts/SwiftailControl.md` unit 4, `docs/protocol-notes/control-map.md` §4.4.
public enum ControlError: Error, Sendable {
    /// The configuration is invalid (server URL or hostname).
    case invalidConfiguration(String)
    /// The identity file could not be read or written.
    case storage(String)
    /// A connection or transport layer failure. Retries.
    case connection(String)
    /// A response other than 200. Handles the wait internally for 429, and for 503 when `Retry-After` is present.
    case http(status: Int)
    /// The server rejected registration that included an auth key (`RegisterResponse.Error`). The key was invalid, expired, or previously used.
    /// The server supplies no error kind that distinguishes these reasons. The associated value is the server's diagnostic message. Use app-provided wording for users.
    case authKeyRejected(String)
    /// The server rejected registration without an auth key (`RegisterResponse.Error`). This may be due to administrator policy or another reason.
    /// The associated value is a server diagnostic message.
    case registrationRejected(String)
    /// Registration with a fresh node key still reports expiration.
    case nodeKeyExpired
}

extension ControlError {
    /// Whether to back off and retry this failure.
    var isRetryable: Bool {
        switch self {
        case .connection, .http: true
        case .invalidConfiguration, .storage, .authKeyRejected, .registrationRejected, .nodeKeyExpired: false
        }
    }
}
