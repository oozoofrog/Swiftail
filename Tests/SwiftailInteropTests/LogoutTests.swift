// Logout gate (testcontrol) covering the interop item under "Tests and Gates" in "Logout" in the `docs/contracts/SwiftailHost.md` contract.
//
// The counterpart is the `tailnet` tool. The testcontrol copy treats registration with a past `Expiry` as expiration of that node key (README "testcontrol Copy").
// Send the Go peer's (go-peer-b) logout to the same server and compare the two requests.

import Foundation
import Swiftail
import Testing

@Suite("Logout gate with testcontrol", .enabled(if: tailnetBinary != nil, "Skipping the logout gate because SWIFTAIL_TAILNET is missing"),
       .serialized, .timeLimit(.minutes(5)))
struct LogoutGateTests {
    /// Go `time.Unix(123, 0)`.
    private static let logoutExpiry = "1970-01-01T00:02:03Z"

    @Test("After logOut(), the server expires the node key (the request has the same form as Go logout), and another peer receives that expiry. Calling run() again with the same state directory registers a new key, then ends with nodeKeyExpired")
    func logOut() async throws {
        let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-logout-\(UUID().uuidString)")
        let tool = GoTailnet(temporaryDirectory: directory)
        defer {
            if FileManager.default.fileExists(atPath: directory.path) {
                do { try FileManager.default.removeItem(at: directory) }
                catch { Issue.record("Could not clean up the logout gate state directory: \(redacted(String(describing: error)))") }
            }
        }
        var run: Task<Void, any Error>?
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let ready = try await tool.start()
            let controlURL = try #require(ready.controlURL)
            _ = try await tool.command(.init(cmd: "addPeer", name: "go-peer-a"), expecting: "peer")
            let configuration = NodeConfiguration(stateDirectory: directory, hostname: "rd-mac-1a2b3c4d", controlURL: controlURL)

            // 1. Register, reach running, and stop (app order: cancel run() → wait for it to finish → logOut()).
            let node = try TailnetNode(configuration: configuration)
            run = Task { try await node.run() }
            let addresses = try await running(node)
            let nodes = try #require(await tool.command(.init(cmd: "nodes"), expecting: "nodes").nodes)
            let key = try #require(nodes.first { Set($0.addresses) == Set(addresses.map(\.description)) }?.nodeKey)
            #expect(nodes.first { $0.nodeKey == key }?.keyExpiry == "", "There is no expiry immediately after registration")
            run?.cancel()
            _ = await run?.result
            run = nil
            await tool.checkpoint("Logout: stopped run() after registration and running")

            // 2. Log out.
            try await node.logOut()
            let afterLogout = try #require(await tool.command(.init(cmd: "nodes"), expecting: "nodes").nodes)
            #expect(afterLogout.first { $0.nodeKey == key }?.keyExpiry == Self.logoutExpiry, "The node key appears expired on the server")
            let registrations = try #require(await tool.command(.init(cmd: "lockRegistrations"), expecting: "lockRegistrations").registrations)
            let swift = try #require(registrations.last)
            #expect(swift.nodeKey == key, "No new node key is generated")
            #expect(swift.expiry == Self.logoutExpiry)
            #expect(swift.expiryUnix == 123)
            #expect(!swift.auth)
            #expect(swift.oldNodeKey == "")
            #expect(!swift.nlKey.isEmpty)
            #expect(swift.signature == "none")
            await tool.checkpoint("Logout: server keyExpiry \(Self.logoutExpiry), one request")

            // 3. As seen by another peer (Go), the node stays in the netmap with the key expiring at that time.
            let deadline = ContinuousClock.now + .seconds(20)
            var seen: GoTailnet.Event.Node?
            while seen == nil {
                let status = try await tool.command(.init(cmd: "peerStatus", name: "go-peer-a"), expecting: "peerStatus")
                seen = status.peers?.first { $0.nodeKey == key && $0.keyExpiry == Self.logoutExpiry }
                if seen == nil {
                    guard ContinuousClock.now < deadline else { throw GateFailure("go-peer-a did not receive the logged-out node's expiry within 20 seconds") }
                    try await Task.sleep(for: .milliseconds(100))
                }
            }
            await tool.checkpoint("Logout: go-peer-a saw node keyExpiry \(seen?.keyExpiry ?? ""), expired \(seen?.expired.map(String.init) ?? "none")")

            // 4. Send the Go peer's logout to the same server and compare requests.
            _ = try await tool.command(.init(cmd: "addPeer", name: "go-peer-b"), expecting: "peer")
            let loggedOut = try await tool.command(.init(cmd: "peerLogout", name: "go-peer-b"), expecting: "peerLogout")
            let all = try #require(await tool.command(.init(cmd: "lockRegistrations"), expecting: "lockRegistrations").registrations)
            let go = try #require(all.last)
            #expect(go.expiryUnix == swift.expiryUnix, "Same time as Go (Go formats it in local time: \(go.expiry))")
            #expect(go.auth == swift.auth)
            #expect(go.oldNodeKey == swift.oldNodeKey)
            #expect(go.nlKey.isEmpty == swift.nlKey.isEmpty)
            #expect(go.signature == swift.signature)
            await tool.checkpoint("Logout: Go request expiry \(go.expiry), auth \(go.auth), BackendState \(loggedOut.backendState ?? "")")

            // 5. Call run() again with the same state directory. The identity file is unchanged (local file cleanup is the app's responsibility, and the app does not take this path).
            //    This is for the record. When a key is rotated, testcontrol clones the old node and copies the expiry time too, so the new key also appears expired
            //    and the run ends with nodeKeyExpired. A production server may behave differently (contract "Decisions Made During Implementation").
            let again = try TailnetNode(configuration: configuration)
            let rerun = Task { () async -> Result<Void, NodeError> in
                do throws(NodeError) {
                    try await again.run()
                    return .success(())
                } catch {
                    return .failure(error)
                }
            }
            // If it has not finished, stop it at 60 seconds and let the result check below record the failure.
            let watchdog = Task {
                try? await Task.sleep(for: .seconds(60))
                rerun.cancel()
            }
            var states: [String] = []
            for await event in again.events {
                if case let .stateChanged(state) = event { states.append(String(describing: state)) }
            }
            let result = await rerun.value
            watchdog.cancel()
            let tail = try #require(await tool.command(.init(cmd: "lockRegistrations"), expecting: "lockRegistrations").registrations)
                .dropFirst(all.count)
            await tool.checkpoint("run() after logout with the same directory: states \(states), result \(redacted(String(describing: result))), registrations \(tail.map { "old=\($0.oldNodeKey.isEmpty ? "none" : ($0.oldNodeKey == key ? "logged-out key" : "different key")) same key=\($0.nodeKey == key)" })")
            guard case .failure(.control(.nodeKeyExpired)) = result else {
                throw GateFailure("The second run() did not return control(.nodeKeyExpired): \(redacted(String(describing: result)))")
            }
            #expect(tail.first?.nodeKey == key && tail.first?.oldNodeKey == "", "Initially registers with the saved (logged-out) key")
            #expect(tail.dropFirst().first.map { $0.nodeKey != key && $0.oldNodeKey == key } == true, "Switches to a new key and registers after the expiry response")
            await tool.stop()
        } catch {
            run?.cancel()
            _ = await run?.result
            await tool.stop()
            throw GateFailure("\(redacted(String(describing: error)))\n\(await tool.diagnostics())")
        }
    }
}
