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
    /// A response other than 200. Handles the wait for 429 and 503 with `Retry-After` internally.
    case http(status: Int)
    /// The server rejected registration that included an auth key (`RegisterResponse.Error`). The key was invalid, expired, or previously used.
    /// The server does not specify which as an error kind. The associated value is a server diagnostic message and is unsuitable for user-facing copy.
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
