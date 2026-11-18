import SwiftailControl

/// A `TailnetNode` failure. `init` throws configuration errors and `run()` throws failures that restarting would not resolve.
///
/// `run()` does not throw transient failures (disconnects, temporary server errors, or timeouts). The node backs off
/// and retries internally. `logOut()` does not retry and throws these as `control(.connection)` or
/// `control(.http(status:))`. Messages omit keys, auth keys, file paths, and descriptor numbers. The app selects
/// user-facing text by error kind and uses the associated strings only for diagnosis.
public enum NodeError: Error, Sendable {
    /// A failure that ended the control client: registration rejected with an auth key (`authKeyRejected`) or without
    /// one (`registrationRejected`), node key expiration even with a new key (`nodeKeyExpired`), or an identity file
    /// failure (`storage`).
    ///
    /// Tailnet lock does not cause a failure. A locked node still reaches `.running`. Check `NodeStatus.tailnetLock` for the lock state.
    case control(ControlError)
    /// Invalid configuration: state directory, control server URL, hostname, utun descriptor, or MTU. Calling `run()` twice also falls here.
    case invalidConfiguration(String)
    /// Could not open or bind the UDP socket. The message contains only the errno name (for example, `EADDRINUSE`).
    case udpUnavailable(String)
    /// Another node in the same process is running with this state directory.
    case stateDirectoryInUse
    /// Can no longer read the tunnel device (utun read error or end of file). The message contains only the errno name,
    /// or `EOF` at end of file.
    case tunnelDeviceClosed(String)
}

extension NodeError {
    /// Converts a control client failure to a node failure. Configuration errors remain configuration errors.
    init(_ error: ControlError) {
        if case let .invalidConfiguration(message) = error {
            self = .invalidConfiguration(message)
        } else {
            self = .control(error)
        }
    }
}
