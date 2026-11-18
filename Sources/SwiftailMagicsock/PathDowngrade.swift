/// The reason a peer's path downgraded from `direct` to `relayed` or from a reported path to nil (contract behavior G4).
///
/// Used only in the node's diagnostic logs. On a real device, distinguishes whether "`relayed` during transmission" means Pongs stopped arriving,
/// a candidate was removed, or a disco key or socket changed. The state machine does not use it for behavior.
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
