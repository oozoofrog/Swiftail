import Synchronization

/// 앱이 아직 읽지 않은 노드 사건. `TailnetNode.events`가 여기서 하나씩 당겨 간다. 구독자는 하나를 권한다. 둘이 함께
/// 읽으면 사건을 나눠 받는다(먼저 기다린 쪽이 먼저 받는다). 한쪽이 다른 쪽의 흐름을 끝내지는 않는다.
///
/// 소비가 느릴 때 버리는 것은 종류에 따라 다르다.
///
/// - `stateChanged`·`tailnetLockChanged`·`peerPathChanged`: 가장 새 것 `TailnetNode.eventBufferLimit`개까지만 쥐고 오래된
///   것부터 버린다.
/// - `statusChanged`: 값이 없는 "다시 읽어라" 신호라 읽지 않은 것은 하나면 된다. 새로 들어오면 앞의 것을 지우고 맨 뒤에
///   둔다. 그래서 한도에 세지 않고 다른 사건을 밀어내지 않는다. 앱이 어느 사건을 읽은 뒤에 `status`가 바뀌었으면 그 뒤에
///   반드시 `statusChanged`가 하나 있다.
///
/// `AsyncStream`의 버퍼는 종류를 가려 지우지 못하므로 버퍼를 여기서 쥐고 `AsyncStream(unfolding:)`으로 소비자가 당겨 가게
/// 한다(`DERPClient.EventQueue`와 같은 모양).
final class NodeEventQueue: Sendable {
    private struct State {
        var events: [NodeEvent] = []
        /// 사건을 기다리는 소비자들. 기다리기 시작한 차례대로다. 번호는 취소한 소비자를 가려 지우는 데 쓴다.
        var waiters: [(id: UInt64, continuation: CheckedContinuation<NodeEvent?, Never>)] = []
        var nextWaiterID: UInt64 = 0
        var isFinished = false
    }

    private let state = Mutex(State())

    /// 사건을 넣는다. 기다리는 소비자가 있으면 곧바로 넘긴다. `finish()` 뒤에는 버린다.
    func push(_ event: NodeEvent) {
        let waiter: CheckedContinuation<NodeEvent?, Never>? = state.withLock { state in
            guard !state.isFinished else { return nil }
            // 기다리는 소비자가 있으면 큐는 비어 있다.
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

    /// 남은 사건을 다 읽으면 흐름이 끝나게 한다.
    func finish() {
        let waiters = state.withLock { state in
            state.isFinished = true
            defer { state.waiters = [] }
            return state.waiters
        }
        for waiter in waiters { waiter.continuation.resume(returning: nil) }
    }

    /// 다음 사건. 없으면 올 때까지 기다린다. 끝났거나 소비자의 Task가 취소되면 nil.
    func next() async -> NodeEvent? {
        let id = state.withLock { state in
            defer { state.nextWaiterID &+= 1 }
            return state.nextWaiterID
        }
        return await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<NodeEvent?, Never>) in
                let ready: NodeEvent?? = state.withLock { state in
                    if !state.events.isEmpty { return .some(state.events.removeFirst()) }
                    // 이미 취소되었으면 취소 처리기가 먼저 돌았으므로 기다리지 않는다.
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
