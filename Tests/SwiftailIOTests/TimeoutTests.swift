import Darwin
import Testing

@testable import SwiftailIO

@Suite("Timeouts")
struct TimeoutTests {
    @Test("Returns the result when the operation completes within the deadline")
    func finishes() async throws {
        let value = try await withTimeout(.seconds(5)) { 42 }
        #expect(value == 42)
    }

    @Test("Exceeding the deadline cancels the operation and throws TimeoutError")
    func expires() async {
        await #expect(throws: TimeoutError(duration: .milliseconds(50))) {
            try await withTimeout(.milliseconds(50)) {
                try await Task.sleep(for: .seconds(3_600))
            }
        }
    }

    /// Before the fix, the timeout child used `Task.sleep`, so even if the operation finished first and canceled it, the Task and timer stayed around until the original deadline
    /// (roughly 700 bytes per call). A 60-second deadline ensures none are freed during this test, so all retained allocations accumulate.
    @Test("Repeated deadlines on operations that finish quickly leave no canceled timers in memory")
    func cancelledTimersDoNotAccumulate() async throws {
        // `phys_footprint` is process-wide, so it includes allocations from other tests running in the same process (under load,
        // more than 16MiB from those tests made this test flaky). Retention is proportional to the call count and other allocations are temporary, so measure several intervals
        // and check **the increase per call in the quietest interval**. Before the fix, any interval retained roughly 700 bytes per call.
        var quietest = Int.max
        var fewestCalls = Int.max
        for _ in 0..<4 {
            let before = try #require(Self.footprint())
            let started = ContinuousClock.now
            var calls = 0
            while ContinuousClock.now - started < .seconds(1) {
                _ = try await withTimeout(.seconds(60)) { 1 }
                calls += 1
            }
            let growth = try #require(Self.footprint()) - before
            quietest = min(quietest, max(growth, 0) / max(calls, 1))
            fewestCalls = min(fewestCalls, calls)
        }
        #expect(fewestCalls > 2_000, "Too few calls to detect retention: \(fewestCalls)")
        #expect(quietest < 200, "Even in the quietest interval, phys_footprint grew by \(quietest) bytes per call")
    }

    /// Returns this process's `phys_footprint` in bytes, or nil if it cannot be read.
    ///
    /// `task_info` fills a C structure through a pointer, so keep the pointer scoped to this function.
    static func footprint() -> Int? {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
        let result = withUnsafeMutablePointer(to: &info) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        return result == KERN_SUCCESS ? Int(info.phys_footprint) : nil
    }
}
