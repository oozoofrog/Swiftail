import Dispatch

/// The error `withTimeout` throws when a deadline expires.
package struct TimeoutError: Error, Sendable, Equatable {
    /// The duration that elapsed.
    package let duration: Duration
}

/// Cancels `operation` and throws `TimeoutError` if it does not finish within `duration`.
///
/// Races the operation and timer as two children in a single TaskGroup. The first to finish supplies the result and the
/// other is canceled. If the operation ignores cancellation, this waits until it finishes, so use it only for
/// operations that close on cancellation, such as socket operations.
///
/// The timer uses a cancelable dispatch timer in place of `Task.sleep`. A canceled `Task.sleep` returns immediately, but its Task and timer remain
/// until the original deadline. In measurements on the Swift 6.4 runtime, applying a 5-second deadline to operations
/// that finish quickly about 6,000 times per second accumulated about 23MB over 5 seconds and stayed at that level.
/// Here, when the operation finishes first, the timer is canceled immediately and leaves nothing behind. Each call
/// still creates two child Tasks and one timer, so avoid using it on heavily used paths that set a deadline for every
/// data item. Use one watchdog per connection there, as with the `DERPClient` write deadline.
///
/// Time spent in system sleep does not count toward the deadline (`DispatchTime`).
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

/// Waits for `duration`. On cancellation, cancels the timer and throws `CancellationError`.
private func sleepCancellably(for duration: Duration) async throws {
    let (fired, firing) = AsyncStream.makeStream(of: Void.self)
    let timer = DispatchSource.makeTimerSource()
    timer.setEventHandler { firing.finish() }
    timer.schedule(deadline: .now() + .nanoseconds(duration.nanoseconds))
    timer.activate()
    defer { timer.cancel() }
    // Iteration ends when the timer finishes the stream or the Task is canceled.
    for await _ in fired {}
    try Task.checkCancellation()
}

extension Duration {
    /// The nanosecond count. Durations beyond `Int` (about 292 years) are capped at `Int.max`.
    fileprivate var nanoseconds: Int {
        let (seconds, attoseconds) = components
        let (whole, overflow) = seconds.multipliedReportingOverflow(by: 1_000_000_000)
        guard !overflow else { return seconds < 0 ? 0 : .max }
        let (total, sumOverflow) = whole.addingReportingOverflow(attoseconds / 1_000_000_000)
        return sumOverflow ? .max : max(0, Int(clamping: total))
    }
}
