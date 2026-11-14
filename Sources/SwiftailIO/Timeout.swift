import Dispatch

/// `withTimeout`이 기한을 넘겼을 때 던진다.
package struct TimeoutError: Error, Sendable, Equatable {
    /// 넘긴 기한.
    package let duration: Duration
}

/// `operation`을 `duration` 안에 끝내지 못하면 취소하고 `TimeoutError`를 던진다.
///
/// 작업과 타이머를 한 TaskGroup의 두 자식으로 경쟁시킨다. 먼저 끝난 쪽이 결과가 되고 나머지는 취소된다.
/// 작업이 취소에 응하지 않으면 끝날 때까지 기다리므로, 소켓처럼 취소하면 닫히는 작업에만 쓴다.
///
/// 타이머는 `Task.sleep`이 아니라 취소할 수 있는 디스패치 타이머다. 취소된 `Task.sleep`은 곧바로 돌아오지만 그 Task와
/// 타이머는 원래 기한까지 남는다(Swift 6.4 런타임에서 잼: 곧 끝나는 작업에 5초 기한을 초당 약 6천 번 걸면 5초 동안
/// 약 23MB가 쌓였다가 그대로 머문다). 여기서는 작업이 먼저 끝나면 타이머를 그 자리에서 취소하므로 남는 것이 없다.
/// 그래도 부를 때마다 자식 Task 둘과 타이머 하나를 만들므로, 데이터 하나마다 거는 자주 부르는 경로에는 쓰지 않는다
/// (그런 곳은 연결 하나에 감시 하나를 둔다. `DERPClient`의 쓰기 기한).
///
/// 기한은 시스템이 잠든 동안 흐르지 않는다(`DispatchTime`).
package func withTimeout<Result: Sendable>(
    _ duration: Duration,
    _ operation: @escaping @Sendable () async throws -> Result
) async throws -> Result {
    try await withThrowingTaskGroup(of: Result.self) { group in
        group.addTask { try await operation() }
        group.addTask {
            try await sleepCancellably(for: duration)
            throw TimeoutError(duration: duration)
        }
        defer { group.cancelAll() }
        guard let result = try await group.next() else { throw CancellationError() }
        return result
    }
}

/// `duration`만큼 기다린다. 취소되면 타이머를 거두고 `CancellationError`를 던진다.
private func sleepCancellably(for duration: Duration) async throws {
    let (fired, firing) = AsyncStream.makeStream(of: Void.self)
    let timer = DispatchSource.makeTimerSource()
    timer.setEventHandler { firing.finish() }
    timer.schedule(deadline: .now() + .nanoseconds(duration.nanoseconds))
    timer.activate()
    defer { timer.cancel() }
    // 타이머가 흐름을 끝내거나, Task가 취소되어 반복이 끝난다.
    for await _ in fired {}
    try Task.checkCancellation()
}

extension Duration {
    /// 나노초 수. `Int`를 넘는 기한(약 292년)은 `Int.max`로 자른다.
    fileprivate var nanoseconds: Int {
        let (seconds, attoseconds) = components
        let (whole, overflow) = seconds.multipliedReportingOverflow(by: 1_000_000_000)
        guard !overflow else { return seconds < 0 ? 0 : .max }
        let (total, sumOverflow) = whole.addingReportingOverflow(attoseconds / 1_000_000_000)
        return sumOverflow ? .max : max(0, Int(clamping: total))
    }
}
