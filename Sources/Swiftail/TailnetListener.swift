/// A TCP port listening on this node's tailnet addresses (IPv4 and IPv6). Emits established connections in arrival
/// order. Created by `TailnetNode.listen(port:)` and corresponds to tsnet `Listener` (`Accept`, `Close`).
///
/// The stream ends when the listener closes or the node's `run()` ends. Canceling a Task waiting on the stream ends
/// only that Task's stream and leaves the listener in place. Only one Task can run at a time. If another Task is
/// already waiting, the later Task's stream ends immediately. Release (`deinit`) closes the listener. The next
/// `listen(port:)` on the same port succeeds immediately before or during `run()`. During `run()`, the node promptly
/// closes the stack listener and aborts queued connections (RST) asynchronously. If the same node calls `listen(port:)`
/// sooner, that call closes them first. Each listener keeps up to 32 established connections that have not been
/// accepted (contract behavior S5, decision D6).
///
/// ```swift
/// let listener = try await node.listen(port: 443)
/// for await connection in listener {
///     group.addTask { await serve(connection) }
/// }
/// ```
public final class TailnetListener: AsyncSequence, Sendable {
    public typealias Element = TailnetConnection
    public typealias Failure = Never

    /// The listening port.
    public let port: UInt16
    let node: TailnetNode
    /// The number identifying this listener within the node. Reopening the same port assigns a new number so an old
    /// handle's `deinit` cannot close the new listener.
    let token: UInt64

    init(node: TailnetNode, token: UInt64, port: UInt16) {
        self.node = node
        self.token = token
        self.port = port
    }

    deinit {
        node.handleReleases.yield(.listener(token))
    }

    /// Stops listening. Aborts connections not yet accepted with RST. Leaves accepted connections alone. May be called twice.
    public func close() async {
        await node.closeListener(token)
    }

    public func makeAsyncIterator() -> Iterator {
        Iterator(listener: self)
    }

    /// The listener's stream. Waits for the next connection to establish.
    public struct Iterator: AsyncIteratorProtocol {
        let listener: TailnetListener

        /// The next connection. Returns nil if the listener closed, `run()` ended, the calling Task was canceled, or
        /// another Task is already waiting.
        public mutating func next() async -> TailnetConnection? {
            await listener.node.nextConnection(from: listener.token)
        }
    }
}
