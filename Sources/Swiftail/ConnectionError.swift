/// A failure while listening, connecting, or using a connection (`TailnetNode.listen(port:)`,
/// `TailnetNode.connect(to:port:)`, `TailnetListener`, `TailnetConnection`). Contract
/// `docs/contracts/SwiftailNetstack.md`, “Public API” and behavior A.
///
/// Messages describe only what went wrong. They omit addresses, names, and payload data (behavior K).
public enum ConnectionError: Error, Sendable, Equatable {
    /// The device is not `.inProcess`, the port is 0, the host is empty, or the read length is less than 1.
    case invalidConfiguration(String)
    /// The node is not running (`run()` ended). `connect` also throws this when the state is not `.running`.
    case notRunning
    /// The name is missing from the netmap, or no peer has that address.
    case unknownHost
    /// The port already has a listener.
    case addressInUse
    /// The connection or listener count reached its limit.
    case limitReached
    /// The peer refused the outgoing connection (RST in response to SYN).
    case refused
    /// The peer did not respond (retransmission limit, unanswered keep-alive, or a deadline during closure).
    case timedOut
    /// The peer aborted the connection (RST).
    case reset
    /// The peer left the netmap, the owner of its address changed, or this node's address changed.
    case peerRemoved
    /// The connection or listener was already closed or aborted. Also applies to `write` after `finishWriting`.
    case closed
    /// The calling Task was canceled.
    case cancelled
    /// A call in the same direction is already waiting (two reads or two writes).
    case concurrentUse
}
