import Foundation

/// A value type that determines the node state. Checks the table below from top to bottom on each input and returns a
/// new state only when it changes.
///
/// | # | Condition (top to bottom) | Result |
/// | --- | --- | --- |
/// | 1 | Control emitted `loginRequired(url)` and no `registered` followed | `.needsLogin(url)` |
/// | 2 | No netmap | `.starting` |
/// | 3 | The local node is not `MachineAuthorized` | `.needsMachineAuth` |
/// | 4 | The previous state was `.running` | `.running` |
/// | 5 | A home DERP connection was established or a session was established with a peer | `.running` |
/// | 6 | Otherwise | `.starting` |
///
/// Adapts the table in Go `nextStateLocked` (`ipn/ipnlocal/local.go`) to Swiftail's inputs. On local key expiration,
/// the control client registers again with a new key and reports `loginRequired`, leading to 1. If the connection drops
/// after `.running`, 4 keeps it `.running`. `docs/contracts/SwiftailTunnel.md` behavior B,
/// `docs/protocol-notes/dns-state-node.md` §4.5.
struct NodeStateMachine: Sendable, Equatable {
    private(set) var state: NodeState = .starting
    /// The URL from 1. `registered` clears it, with the same effect as Go clearing the URL on entering `Running`.
    private var loginURL: URL?
    /// 2. At least one netmap has been received.
    private var hasNetmap = false
    /// 3. The local node in the last netmap was authorized.
    private var machineAuthorized = false
    /// 5. A home DERP connection or a session with a peer has been established.
    private var hasConnected = false

    /// The control server supplied a login URL.
    mutating func loginRequired(_ url: URL) -> NodeState? {
        loginURL = url
        return reevaluate()
    }

    /// Registration completed.
    mutating func registered() -> NodeState? {
        loginURL = nil
        return reevaluate()
    }

    /// A netmap was received.
    mutating func receivedNetmap(machineAuthorized: Bool) -> NodeState? {
        hasNetmap = true
        self.machineAuthorized = machineAuthorized
        return reevaluate()
    }

    /// A home DERP connection or a WireGuard session with a peer was established.
    mutating func connected() -> NodeState? {
        hasConnected = true
        return reevaluate()
    }

    private mutating func reevaluate() -> NodeState? {
        let next: NodeState
        if let loginURL {
            next = .needsLogin(loginURL)
        } else if !hasNetmap {
            next = .starting
        } else if !machineAuthorized {
            next = .needsMachineAuth
        } else if state == .running || hasConnected {
            next = .running
        } else {
            next = .starting
        }
        guard next != state else { return nil }
        state = next
        return next
    }
}
