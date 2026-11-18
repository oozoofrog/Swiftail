import SwiftailBase

/// The default interface reported by the app and the local addresses read at that time. Determines whether to rebind or just restart STUN.
///
/// Tests cannot construct an `NWInterface`, so copy only the name and index needed for the decision. The decision is an
/// I/O-free function. `docs/contracts/SwiftailTunnel.md` behavior N 1 and 2, `docs/protocol-notes/dns-state-node.md`
/// §4.6.2.
struct DefaultLink: Sendable, Equatable {
    /// The interface name (such as `en0` or `pdp_ip0`).
    var name: String
    /// The interface index (`NWInterface.index`). Used to bind sockets.
    var index: Int
    /// The local IPv4 addresses read at that time (regular and loopback from `LocalInterfaceAddresses.current()`).
    var addresses: [IPAddress]
    var loopbackAddresses: [IPAddress]

    /// The action for the node to take on a notification.
    enum Change: Sendable, Equatable {
        /// This is the node's own utun. Ignore it, as Go's `netns_darwin.go` excludes Tailscale utun from default interfaces.
        case ignore
        /// The interface and addresses are unchanged. Restart only the STUN round (Go calls `ReSTUN` on every link change).
        case restartSTUN
        /// This is the first notification, or the interface or addresses changed. Rebind DERP, UDP, and control to the
        /// new interface (Go `RebindLikelyRequired`).
        case rebind
    }

    /// Returns what to do on a notification that changes `previous` to `self`. Nil `previous` means no interface is bound yet.
    ///
    /// Checks only the interface reported by the app and that interface's addresses. Go also checks for changes in
    /// available protocols, cost, and PAC.
    ///
    /// - Parameter tunnelName: This node's utun name. Nil for an in-memory device.
    func change(from previous: DefaultLink?, tunnelName: String?) -> Change {
        if let tunnelName, name == tunnelName { return .ignore }
        return self == previous ? .restartSTUN : .rebind
    }
}
