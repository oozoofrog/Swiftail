/// The reason `LoopbackBridge.forward(_:toLoopbackPort:)` could not forward a connection. In every case, the tailnet
/// connection has already been aborted with RST.
///
/// A disconnect or failure on either side after forwarding begins (`reset`, `timedOut`, `peerRemoved`, loopback
/// failure, or node stop) is not an error. The bridge cleans up both connections and returns. Messages omit addresses
/// and names (contract behavior K).
public enum LoopbackBridgeError: Error, Sendable, Equatable {
    /// No identity for the peer address was found in the netmap.
    case unknownPeer
    /// The bridge reached its concurrent connection limit (256).
    case limitReached
    /// Could not connect to the loopback port (no listener, timeout, or failure to record or send the token).
    case loopbackUnavailable(String)
    /// The calling Task was canceled.
    case cancelled
}
