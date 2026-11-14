/// `withTimeout`이 기한을 넘겼을 때 던진다.
package struct TimeoutError: Error, Sendable, Equatable {
    /// 넘긴 기한.
    package let duration: Duration
}

/// `operation`을 `duration` 안에 끝내지 못하면 취소하고 `TimeoutError`를 던진다.
///
/// 작업과 타이머를 한 TaskGroup의 두 자식으로 경쟁시킨다. 먼저 끝난 쪽이 결과가 되고 나머지는 취소된다.
/// 작업이 취소에 응하지 않으면 끝날 때까지 기다리므로, 소켓처럼 취소하면 닫히는 작업에만 쓴다.
package func withTimeout<Result: Sendable>(
    _ duration: Duration,
    _ operation: @escaping @Sendable () async throws -> Result
) async throws -> Result {
    try await withThrowingTaskGroup(of: Result.self) { group in
        group.addTask { try await operation() }
        group.addTask {
            try await Task.sleep(for: duration, clock: .continuous)
            throw TimeoutError(duration: duration)
        }
        defer { group.cancelAll() }
        guard let result = try await group.next() else { throw CancellationError() }
        return result
    }
}
