import Synchronization

extension DERPClient {
    /// 소비자가 아직 읽지 않은 사건. `events`가 여기서 하나씩 당겨 간다.
    ///
    /// 소비가 느릴 때 버리는 것은 종류에 따라 다르다.
    ///
    /// - `packet`·`peerGone`: 가장 새 것 `eventBufferLimit`개까지만 쥐고 오래된 것부터 버린다. 패킷은 데이터그램이다.
    ///   패킷 본문의 바이트 합도 `eventBufferByteLimit`까지만 쥐고, 넘치면 오래된 패킷부터 버린다(`peerGone`은 바이트가
    ///   없으므로 바이트 한도 때문에는 버리지 않는다).
    /// - `connected`·`disconnected`: 버리지 않는다. 다만 읽지 않은 연결 상태 사건은 가장 새 것 하나만 남긴다. 지난
    ///   상태는 이미 뜻이 없고, 이렇게 해야 소비가 멈춘 채 재연결이 되풀이되어도 큐가 자라지 않는다.
    ///
    /// `AsyncStream`의 버퍼는 종류를 가려 버리지 못해, 넘치면 `connected`가 밀려 사라졌다(노드가 `reconnecting`에
    /// 머물렀다). 그래서 버퍼를 여기서 쥐고 `AsyncStream(unfolding:)`으로 소비자가 당겨 가게 한다. 구독자는 하나다.
    final class EventQueue: Sendable {
        private struct State {
            var events: [Event] = []
            /// `events`에 든 패킷 본문의 바이트 합.
            var packetBytes = 0
            /// 사건을 기다리는 소비자.
            var waiter: CheckedContinuation<Event?, Never>?
            var isFinished = false

            /// `index`의 사건을 버린다.
            mutating func drop(at index: Int) {
                packetBytes -= events.remove(at: index).packetSize
            }
        }

        private let state = Mutex(State())

        /// 사건을 넣는다. 기다리는 소비자가 있으면 곧바로 넘긴다. `finish()` 뒤에는 버린다.
        func push(_ event: Event) {
            let waiter: CheckedContinuation<Event?, Never>? = state.withLock { state in
                guard !state.isFinished else { return nil }
                // 기다리는 소비자가 있으면 큐는 비어 있다.
                if let waiter = state.waiter.take() { return waiter }
                if event.isLinkState {
                    state.events.removeAll(where: \.isLinkState)
                } else {
                    if state.events.count(where: { !$0.isLinkState }) >= DERPClient.eventBufferLimit,
                       let oldest = state.events.firstIndex(where: { !$0.isLinkState }) {
                        state.drop(at: oldest)
                    }
                    // 새 패킷이 들어갈 자리가 날 때까지 오래된 패킷부터 버린다. 패킷 하나는 한도보다 작으므로 끝난다.
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

        /// 남은 사건을 다 읽으면 흐름이 끝나게 한다.
        func finish() {
            let waiter = state.withLock { state in
                state.isFinished = true
                return state.waiter.take()
            }
            waiter?.resume(returning: nil)
        }

        /// 다음 사건. 없으면 올 때까지 기다린다. 끝났거나 소비자의 Task가 취소되면 nil.
        func next() async -> Event? {
            await withTaskCancellationHandler {
                await withCheckedContinuation { (continuation: CheckedContinuation<Event?, Never>) in
                    let ready: Event?? = state.withLock { state in
                        if !state.events.isEmpty {
                            let event = state.events.removeFirst()
                            state.packetBytes -= event.packetSize
                            return .some(event)
                        }
                        // 이미 취소되었으면 취소 처리기가 먼저 돌았으므로 기다리지 않는다. 두 번째 구독자도 기다리게 하지 않는다.
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
    /// 패킷 본문의 바이트 수. 패킷이 아니면 0.
    fileprivate var packetSize: Int {
        if case .packet(let bytes, from: _) = self { bytes.count } else { 0 }
    }

    /// 연결 상태 사건이다(`connected`·`disconnected`).
    fileprivate var isLinkState: Bool {
        switch self {
        case .connected, .disconnected: true
        case .packet, .peerGone: false
        }
    }
}
