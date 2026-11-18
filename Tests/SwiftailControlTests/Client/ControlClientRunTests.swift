import Foundation
import Testing

@testable import SwiftailControl

@Suite("run() runs only once")
struct ControlClientRunTests {
    @Test("Calling run() again after it finishes yields invalidConfiguration")
    func runAfterCancellation() async throws {
        let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-run-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        // A port with no listener. If the second run() is accepted, it keeps retrying the connection and never returns.
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
            Issue.record("The second run() did not immediately end with invalidConfiguration")
            return
        }
    }
}
