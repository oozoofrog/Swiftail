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
}
