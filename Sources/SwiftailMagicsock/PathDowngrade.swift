/// The reason a peer's path downgraded from `direct` to `relayed` or from a reported path to nil (contract behavior G4).
///
/// Used only in the node's diagnostic logs. In real device logs, distinguishes among missing Pongs, candidate removal, disco key changes, and socket changes
/// when a path becomes `relayed` during transmission. The state machine’s behavior is independent of this reason.
package enum PathDowngrade: Sendable, Equatable {
    /// `trustDuration` (6.5 seconds) elapsed after the last Pong. Includes clearing `bestAddr` on a later Ping deadline.
    case trustExpired
    /// Removed the candidate that was `bestAddr` (absent from the netmap, stale Ping-learned candidate, or absent from the next CallMeMaybe).
    case candidateRemoved
    /// Rebound the UDP socket (`noteConnectivityChange`).
    case rebind
    /// The peer's active disco key changed (netmap, TSMP advertisement, or disco with the inactive key). Clearing send history makes the path nil.
    case discoKeyChanged
    /// `sessionActiveTimeout` (45 seconds) elapsed after the last WireGuard send.
    case idle
    /// The peer was removed from the netmap (a node key change is equivalent).
    case peerRemoved
}
