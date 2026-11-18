import SwiftailBase
import SwiftailNetstack

/// An established TCP connection returned by `TailnetNode.connect(to:port:)` or `TailnetListener`. Corresponds to tsnet's `net.Conn`.
///
/// One read and one write may run simultaneously on separate Tasks. A second call in the same direction returns
/// `ConnectionError.concurrentUse`. There is no time limit argument. Set a time limit by canceling the calling Task. If
/// released without closing (`deinit`), aborts with RST.
///
/// After the peer ends the connection, `read`, `write`, and `finishWriting` throw the reason (`reset`, `timedOut`, or
/// `peerRemoved`). After the app calls `close` or `abort`, they throw `closed`. After the node's `run()` ends, they
/// throw `notRunning`. Contract `docs/contracts/SwiftailNetstack.md`, “Public API” and behavior A.
public final class TailnetConnection: Sendable {
    /// This node's address and port.
    public let localEndpoint: IPEndpoint
    /// The peer's tailnet address and port. The address belongs to the WireGuard-authenticated peer because its
    /// AllowedIPs are used to check the source.
    public let remoteEndpoint: IPEndpoint
    let node: TailnetNode
    let id: TCPStack.ConnectionID

    init(node: TailnetNode, id: TCPStack.ConnectionID, localEndpoint: IPEndpoint, remoteEndpoint: IPEndpoint) {
        self.node = node
        self.id = id
        self.localEndpoint = localEndpoint
        self.remoteEndpoint = remoteEndpoint
    }

    deinit {
        node.handleReleases.yield(.connection(id))
    }

    /// Returns received bytes in order. Immediately returns what is buffered (at least 1 byte and at most
    /// `maximumLength`), or waits for bytes if empty. Opens the receive window by the number of bytes read. If the app
    /// does not read, the peer stalls at 256KiB.
    ///
    /// - Returns: Nil if the peer closed its write side and no bytes remain.
    /// - Throws: `invalidConfiguration` for `maximumLength` of 0 or less, `concurrentUse` if another `read` is waiting,
    ///   `notRunning` if the node's `run()` ended, `closed` after app `close` or `abort` (including a waiting `read`),
    ///   the peer-related reason (`reset`, `timedOut`, or `peerRemoved`) if it ended due to the peer, or `cancelled` if
    ///   the calling Task is canceled (the connection and buffered data stay intact).
    public func read(upTo maximumLength: Int = 65_536) async throws(ConnectionError) -> [UInt8]? {
        try await node.readConnection(id, upTo: maximumLength)
    }

    /// Waits until all bytes enter the send buffer. This does not mean the peer received them. If the buffer (256KiB)
    /// fills, waits for space without holding the node during the wait.
    ///
    /// - Throws: `concurrentUse` if another `write` is waiting, `notRunning` if the node's `run()` ended, `closed`
    ///   after `finishWriting`, `close`, or `abort` (including a waiting `write`), the peer-related reason (`reset`,
    ///   `timedOut`, or `peerRemoved`) if it ended due to the peer, or `cancelled` after aborting with RST if the
    ///   calling Task is canceled, because the number of accepted bytes is unknown. If `finishWriting` wakes a pending
    ///   `write`, all bytes already in the buffer go out before FIN.
    public func write(_ bytes: [UInt8]) async throws(ConnectionError) {
        try await node.writeConnection(id, bytes)
    }

    /// Finishes sending (FIN). FIN follows all buffered data. Reads can continue. Corresponds to tsnet `CloseWrite`.
    /// May be called twice. Any waiting `write` wakes with `closed`.
    ///
    /// - Throws: `notRunning` if the node's `run()` ended, `closed` after `close` or `abort`, or the peer-related
    ///   reason (`reset`, `timedOut`, or `peerRemoved`) if it ended due to the peer.
    public func finishWriting() async throws(ConnectionError) {
        try await node.finishWritingConnection(id)
    }

    /// Closes the connection. Sends remaining buffered data and finishes with FIN. Returns immediately and lets the
    /// node finish in `run()`. Aborts with RST if there is unread data or data arrives after closing. Pending `read`
    /// and `write` calls wake with `closed`. Does not throw. Has no effect on an already closed connection. Corresponds
    /// to tsnet `Close`.
    public func close() async {
        await node.closeConnection(id)
    }

    /// Immediately aborts the connection (RST) and drops buffered data. Does not throw. Pending `read` and `write`
    /// calls wake with `closed`. Corresponds to tsnet's `SetLinger(0)` followed by `Close`.
    public func abort() async {
        await node.abortConnection(id)
    }
}
