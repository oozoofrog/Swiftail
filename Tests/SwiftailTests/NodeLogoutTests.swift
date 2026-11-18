import Foundation
import Testing
@testable import Swiftail

/// Startup validation for `TailnetNode.logOut()`. Contract `docs/contracts/SwiftailHost.md`, "Logout," behaviors O1·O2.
/// `LogoutTests` in `SwiftailControlTests` covers the request format and response. Interop tests cover server-side results.
@Suite("Node logout")
struct NodeLogoutTests {
    @Test("An active run() for the same state directory causes stateDirectoryInUse and creates nothing")
    func rejectsClaimedDirectory() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            let claim = try #require(StateDirectoryClaims.shared.claim(directory))
            defer { StateDirectoryClaims.shared.release(claim) }
            let node = try TailnetNode(configuration: try NodeTestSupport.configuration(stateDirectory: directory))
            do throws(NodeError) {
                try await node.logOut()
                Issue.record("logOut() did not throw")
            } catch {
                guard case .stateDirectoryInUse = error else {
                    Issue.record("Expected stateDirectoryInUse, got \(error)")
                    return
                }
            }
            #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path).isEmpty)
        }
    }

    @Test("A node that has never registered returns without connecting, creating an identity file, or leaving a claim")
    func noIdentity() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            // The control server address (127.0.0.1:9) is unreachable. An attempt to connect would have thrown a failure.
            let node = try TailnetNode(configuration: try NodeTestSupport.configuration(stateDirectory: directory))
            try await node.logOut()
            #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path).isEmpty)
            let claim = try #require(StateDirectoryClaims.shared.claim(directory), "logOut() leaves no claim")
            StateDirectoryClaims.shared.release(claim)
        }
    }
}
