/// A change reported by `TailnetNode`. Receive it through `TailnetNode.events`.
///
/// Read current values such as addresses and names from `TailnetNode.status`. Events omit them so the same information
/// is reported only one way (`docs/contracts/SwiftailTunnel.md`, lead session confirmation T1).
///
/// Events from one update (one netmap or state transition) arrive in this order: `tailnetLockChanged` →
/// `peerPathChanged` → `stateChanged` → `statusChanged`. When each event arrives, `status` already reflects the update.
public enum NodeEvent: Sendable, Equatable {
    /// The state changed. Repeated states are suppressed. The initial `.starting` state emits no event.
    case stateChanged(NodeState)
    /// The peer's path changed. Has the same meaning as `TailnetNode.path(toPeerNamed:)`.
    ///
    /// Nil means the peer left the data plane or neither sent nor received traffic for more than 45 seconds (idle).
    /// When traffic resumes, emits another event with the path at that time. A peer with an empty name produces no
    /// event.
    ///
    /// - Parameter fqdn: The node name in the netmap with its trailing dot removed (`rd-mac-1a2b3c4d.tail0001.ts.net`).
    case peerPathChanged(fqdn: String, path: PeerPath?)
    /// The tailnet lock state changed. The value matches `NodeStatus.tailnetLock` at that time. Repeated values are
    /// suppressed. The initial `.disabled` value emits no event.
    ///
    /// This comes first among events from a netmap. It precedes a locked node's `stateChanged(.running)`, so the app
    /// sees the signing instructions (`signingRequest`) before showing “Connected.” Once a signing device signs the
    /// node, the next netmap emits the new value with a nil `signingRequest` without a restart.
    /// `docs/contracts/SwiftailTailnetLock.md` decision L4, first adopter review F2.
    case tailnetLockChanged(TailnetLockStatus)
    /// The value of `TailnetNode.status` changed. Read current values from `status`.
    ///
    /// Emitted only when `status` actually differs from the previously reported value in at least one of peer count,
    /// local name, addresses, or `StableID`, certificate names, tunnel settings, state, or tailnet lock. Changes to
    /// state or lock also emit this after `stateChanged` or `tailnetLockChanged`. Those two report the transitions
    /// themselves, such as opening a login URL or showing signing instructions. This event tells the app to read the
    /// state it should display. An app that only updates its display needs only this event.
    ///
    /// Keeps only one unread event. A new event removes its predecessor and goes at the end. It therefore does not
    /// count toward the event buffer limit or displace other events. The initial snapshot (`.starting`, no netmap)
    /// emits no event, so the app reads `status` once at startup.
    case statusChanged
}
