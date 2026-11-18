import Foundation

/// The node state. Keeps only the states the app uses from Go `ipn.State` (`docs/protocol-notes/dns-state-node.md` §4.5).
///
/// Stop and failure are outside the state model. A stop is a return from `TailnetNode.run()`, and a failure is a
/// `NodeError` thrown by `run()`.
public enum NodeState: Sendable, Equatable {
    /// Waiting for registration, a netmap, and the first connection.
    case starting
    /// The user must sign in at this URL. The control server supplies this URL when registration requires interactive login.
    ///
    /// The URL itself grants login access, so it is never logged.
    case needsLogin(URL)
    /// A tailnet administrator must approve this device (the local node's `MachineAuthorized` in the netmap is false).
    case needsMachineAuth
    /// The node has received a netmap and has established either a home DERP connection or a WireGuard session with at
    /// least one peer. The state persists if the connection later drops, including while reconnecting.
    case running
}
