import Darwin
import Testing

@testable import SwiftailIO

@Suite("기한")
struct TimeoutTests {
    @Test("기한 안에 끝나면 결과를 돌려준다")
    func finishes() async throws {
        let value = try await withTimeout(.seconds(5)) { 42 }
        #expect(value == 42)
    }

    @Test("기한을 넘기면 작업을 취소하고 TimeoutError를 던진다")
    func expires() async {
        await #expect(throws: TimeoutError(duration: .milliseconds(50))) {
            try await withTimeout(.milliseconds(50)) {
                try await Task.sleep(for: .seconds(3_600))
            }
        }
    }

    /// 고치기 전에는 기한 쪽 자식이 `Task.sleep`이라, 작업이 먼저 끝나 취소해도 그 Task와 타이머가 원래 기한까지 남았다
    /// (부를 때마다 약 700바이트). 기한을 60초로 두면 이 시험 동안 하나도 풀리지 않으므로 남는 것이 모두 쌓인다.
    @Test("곧 끝나는 작업에 기한을 수없이 걸어도 취소된 타이머가 메모리에 남지 않는다")
    func cancelledTimersDoNotAccumulate() async throws {
        // `phys_footprint`는 프로세스 전체의 값이라 같은 프로세스에서 함께 도는 다른 시험의 할당이 섞인다(부하가 걸리면
        // 16MiB 넘게 섞여 이 시험이 흔들렸다). 남는 것은 호출 수에 비례하고 섞이는 것은 한때뿐이므로, 구간을 여럿 재서
        // **가장 조용한 구간의 호출당 증가량**을 본다. 고치기 전 기준이면 어느 구간이든 호출당 약 700바이트가 남는다.
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
        #expect(fewestCalls > 2_000, "호출이 너무 적어 남는 것을 가려내지 못한다: \(fewestCalls)")
        #expect(quietest < 200, "가장 조용한 구간에서도 호출당 phys_footprint가 \(quietest)바이트 늘었다")
    }

    /// 이 프로세스의 `phys_footprint`(바이트). 읽지 못하면 nil.
    ///
    /// `task_info`는 C 구조체를 포인터로 채우는 호출이라 포인터를 이 함수 안에만 가둔다.
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
