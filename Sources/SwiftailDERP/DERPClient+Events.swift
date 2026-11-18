import Synchronization

extension DERPClient {
    /// Events the consumer has yet to read. `events` pulls them from here one at a time.
    ///
    /// The events dropped when the consumer is slow depend on their type.
    ///
    /// - `attemptFailed`, `packet`, and `peerGone`: Keep up to the newest `eventBufferLimit` events and drop the oldest first. Packets are datagrams.
    ///   Also keep at most `eventBufferByteLimit` total bytes of packet bodies and drop the oldest packets when above the limit
    ///   (`peerGone` has no bytes and is exempt from the byte limit).
    /// - `connected` and `disconnected`: Preserve the latest unread connection state event. Prior
    ///   states are no longer meaningful, and this keeps the queue from growing during repeated reconnection if consumption stalls.
    ///
    /// `AsyncStream` buffering cannot drop selectively by type. When it overflowed, `connected` was pushed out (the node thought it
    /// had disconnected). Keep the buffer here and let the consumer pull via `AsyncStream(unfolding:)`. There is one subscriber.
    final class EventQueue: Sendable {
        private struct State {
            var events: [Event] = []
            /// The total bytes of packet bodies in `events`.
            var packetBytes = 0
            /// The consumer waiting for an event.
            var waiter: CheckedContinuation<Event?, Never>?
            var isFinished = false

            /// Discards the event at `index`.
            mutating func drop(at index: Int) {
                packetBytes -= events.remove(at: index).packetSize
            }
        }

        private let state = Mutex(State())

        /// Adds an event, delivering it directly to a waiting consumer if present. Discards it after `finish()`.
        func push(_ event: Event) {
            let waiter: CheckedContinuation<Event?, Never>? = state.withLock { state in
                guard !state.isFinished else { return nil }
                // The queue is empty if a consumer is waiting.
                if let waiter = state.waiter.take() { return waiter }
                if event.isLinkState {
                    state.events.removeAll(where: \.isLinkState)
                } else {
                    if state.events.count(where: { !$0.isLinkState }) >= DERPClient.eventBufferLimit,
                       let oldest = state.events.firstIndex(where: { !$0.isLinkState }) {
                        state.drop(at: oldest)
                    }
                    // Drop the oldest packets until the new packet fits. One packet is smaller than the limit, so this terminates.
                    while state.packetBytes + event.packetSize > DERPClient.eventBufferByteLimit,
                          let oldest = state.events.firstIndex(where: { $0.packetSize > 0 }) {
                        state.drop(at: oldest)
                    }
                }
                state.events.append(event)
                state.packetBytes += event.packetSize
                return nil
            }
            waiter?.resume(returning: event)
        }

        /// Ends the stream once the remaining events are read.
        func finish() {
            let waiter = state.withLock { state in
                state.isFinished = true
                return state.waiter.take()
            }
            waiter?.resume(returning: nil)
        }

        /// The next event, waiting for one if needed. Returns nil after the stream ends or the consumer's Task is canceled.
        func next() async -> Event? {
            await withTaskCancellationHandler {
                await withCheckedContinuation { (continuation: CheckedContinuation<Event?, Never>) in
                    let ready: Event?? = state.withLock { state in
                        if !state.events.isEmpty {
                            let event = state.events.removeFirst()
                            state.packetBytes -= event.packetSize
                            return .some(event)
                        }
                        // If already canceled, the cancellation handler ran first, so skip waiting. A second subscriber also skips waiting.
                        if state.isFinished || Task.isCancelled || state.waiter != nil { return .some(nil) }
                        state.waiter = continuation
                        return .none
                    }
                    if let ready { continuation.resume(returning: ready) }
                }
            } onCancel: {
                state.withLock { $0.waiter.take() }?.resume(returning: nil)
            }
        }
    }
}

extension DERPClient.Event {
    /// The packet body size in bytes, or 0 for a nonpacket event.
    fileprivate var packetSize: Int {
        if case .packet(let bytes, from: _) = self { bytes.count } else { 0 }
    }

    /// Whether this is a connection state event (`connected` or `disconnected`).
    fileprivate var isLinkState: Bool {
        switch self {
        case .connected, .disconnected: true
        case .attemptFailed, .packet, .peerGone: false
        }
    }
}
