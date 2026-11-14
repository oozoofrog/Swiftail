import Foundation
import Testing

@testable import SwiftailControl

@Suite("run()은 한 번만")
struct ControlClientRunTests {
    @Test("끝난 뒤 다시 부른 run()은 invalidConfiguration으로 거절한다")
    func runAfterCancellation() async throws {
        let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-run-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        // 아무도 듣지 않는 포트. 두 번째 run()이 거절되지 않으면 연결을 되풀이하며 돌아오지 않는다.
        let client = ControlClient(
            configuration: .init(serverURL: try #require(URL(string: "http://127.0.0.1:1")), hostname: "rd-mac-1a2b3c4d"),
            identityStore: NodeIdentityStore(directory: directory)
        )
        let first = Task { try await client.run() }
        first.cancel()
        _ = await first.result

        let second = Task<ControlError?, Never> {
            do throws(ControlError) { try await client.run(); return nil } catch { return error }
        }
        let timer = Task {
            try await Task.sleep(for: .seconds(3))
            second.cancel()
        }
        defer { timer.cancel() }
        guard case .invalidConfiguration? = await second.value else {
            Issue.record("두 번째 run()이 invalidConfiguration으로 곧바로 끝나지 않았다")
            return
        }
    }
}
