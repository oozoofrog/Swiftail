import Foundation
import Testing
@testable import Swiftail

/// Verifies that configuration and node values do not expose the auth key. Node API contract behavior 7.
@Suite("Redacting secrets in node configuration")
struct NodeConfigurationTests {
    /// A fake auth key. It only mimics the real key format.
    private static let authKey = "tskey-auth-fake0000-swiftail0000"

    private static func configuration(stateDirectory: String = "file:///var/empty/swiftail-test/") throws -> NodeConfiguration {
        NodeConfiguration(
            stateDirectory: try #require(URL(string: stateDirectory)),
            hostname: "rd-mac-1a2b3c4d",
            controlURL: try #require(URL(string: "http://127.0.0.1:9")),
            authKey: authKey
        )
    }

    @Test("description omits the auth key")
    func description() throws {
        let text = String(describing: try Self.configuration())
        #expect(!text.contains(Self.authKey))
        #expect(text.contains("<redacted>"))
    }

    @Test("dump omits the auth key")
    func dumpOutput() throws {
        var text = ""
        dump(try Self.configuration(), to: &text)
        #expect(!text.contains(Self.authKey))
        #expect(text.contains("rd-mac-1a2b3c4d"))
    }

    @Test("Dumping the node omits secrets from its configuration")
    func nodeDump() throws {
        var text = ""
        dump(try TailnetNode(configuration: try Self.configuration()), to: &text)
        #expect(!text.contains(Self.authKey))
    }

    @Test("Calling run() twice yields invalidConfiguration")
    func runTwice() async throws {
        let node = try TailnetNode(configuration: try Self.configuration())
        // The first call ends immediately because the state directory cannot be created and the identity file cannot be written. It still counts as a call.
        await #expect(throws: NodeError.self) { try await node.run() }
        do {
            try await node.run()
            Issue.record("The second run() did not throw")
        } catch {
            guard case .invalidConfiguration = error else {
                Issue.record("Expected invalidConfiguration, got \(error)")
                return
            }
        }
    }
}
