import Synchronization

/// The node events the app has not read. `TailnetNode.events` pulls one at a time. One subscriber is recommended. Two
/// readers split events, with the first to wait receiving the first event. Neither reader ends the other's stream.
///
/// When consumption falls behind, the queue drops events by kind.
///
/// - `stateChanged`, `tailnetLockChanged`, and `peerPathChanged`: Keeps only the newest `TailnetNode.eventBufferLimit`
///   events and drops the oldest first.
/// - `statusChanged`: One unread event suffices because it is a signal to read again with no value. A new event removes
///   its predecessor and goes at the end. It therefore does not count toward the limit or displace other events. If
///   `status` changes after the app reads an event, a `statusChanged` always follows.
///
/// The `AsyncStream` buffer cannot remove by kind, so hold the buffer here and let the consumer pull through
/// `AsyncStream(unfolding:)` (same design as `DERPClient.EventQueue`).
final class NodeEventQueue: Sendable {
    private struct State {
        var events: [NodeEvent] = []
        /// Consumers waiting for events, in the order they started waiting. Their numbers identify which consumer to remove on cancellation.
        var waiters: [(id: UInt64, continuation: CheckedContinuation<NodeEvent?, Never>)] = []
        var nextWaiterID: UInt64 = 0
        var isFinished = false
    }

    private let state = Mutex(State())

    /// Enqueues an event or delivers it directly to a waiting consumer. Drops it after `finish()`.
    func push(_ event: NodeEvent) {
        let waiter: CheckedContinuation<NodeEvent?, Never>? = state.withLock { state in
            guard !state.isFinished else { return nil }
            // The queue is empty if a consumer is waiting.
            if !state.waiters.isEmpty { return state.waiters.removeFirst().continuation }
            if event == .statusChanged {
                state.events.removeAll { $0 == .statusChanged }
            } else if state.events.count(where: { $0 != .statusChanged }) >= TailnetNode.eventBufferLimit,
                      let oldest = state.events.firstIndex(where: { $0 != .statusChanged }) {
                state.events.remove(at: oldest)
            }
            state.events.append(event)
            return nil
        }
        waiter?.resume(returning: event)
    }

    /// Ends the stream once all remaining events have been read.
    func finish() {
        let waiters = state.withLock { state in
            state.isFinished = true
            defer { state.waiters = [] }
            return state.waiters
        }
        for waiter in waiters { waiter.continuation.resume(returning: nil) }
    }

    /// Returns the next event, waiting if necessary. Returns nil if finished or if the consumer's Task is canceled.
    func next() async -> NodeEvent? {
        let id = state.withLock { state in
            defer { state.nextWaiterID &+= 1 }
            return state.nextWaiterID
        }
        return await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<NodeEvent?, Never>) in
                let ready: NodeEvent?? = state.withLock { state in
                    if !state.events.isEmpty { return .some(state.events.removeFirst()) }
                    // If already canceled, the cancellation handler ran first, so do not wait.
                    if state.isFinished || Task.isCancelled { return .some(nil) }
                    state.waiters.append((id, continuation))
                    return .none
                }
                if let ready { continuation.resume(returning: ready) }
            }
        } onCancel: {
            let waiter = state.withLock { state in
                state.waiters.firstIndex { $0.id == id }.map { state.waiters.remove(at: $0) }
            }
            waiter?.continuation.resume(returning: nil)
        }
    }
}
