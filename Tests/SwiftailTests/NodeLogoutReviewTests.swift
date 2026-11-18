import CryptoKit
import Foundation
import Network
import Synchronization
import Testing

import SwiftailControl
@testable import Swiftail

/// Tests added by the independent review of `TailnetNode.logOut()`. Contract `docs/contracts/SwiftailHost.md`, "Logout," behaviors O1·O6.
/// Tests calls at the wrong time (overlapping `logOut()`, active `run()`, cancellation) and checks that every path releases the state directory claim.
@Suite("Node logout review", .timeLimit(.minutes(1)))
struct NodeLogoutReviewTests {
    /// Saves a previously registered identity in `directory` and returns the file's bytes.
    private static func saveRegisteredIdentity(in directory: URL) throws -> Data {
        var identity = NodeIdentity()
        identity.nodeKey = Curve25519.KeyAgreement.PrivateKey()
        try NodeIdentityStore(directory: directory).save(identity)
        return try identityFile(in: directory)
    }

    /// The bytes of the state directory's only file (the identity file).
    private static func identityFile(in directory: URL) throws -> Data {
        let names = try FileManager.default.contentsOfDirectory(atPath: directory.path)
        try #require(names.count == 1, "Found \(names.count) files instead of just the identity file")
        return try Data(contentsOf: directory.appending(path: names[0]))
    }

    private static func logOutError(_ node: TailnetNode) async -> NodeError? {
        do throws(NodeError) {
            try await node.logOut()
            return nil
        } catch {
            return error
        }
    }

    /// Starts a loopback listener that accepts connections but sends no response, and passes its address and the number of connections accepted.
    private static func withSilentServer<T>(_ body: (URL, @Sendable () -> Int) async throws -> T) async throws -> T {
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: .any)
        let listener = try NWListener(using: parameters)
        let connections = Mutex<[NWConnection]>([])
        listener.newConnectionHandler = { connection in
            connections.withLock { $0.append(connection) }
            connection.start(queue: .global())
        }
        defer {
            listener.cancel()
            for connection in connections.withLock({ $0 }) { connection.cancel() }
        }
        let port = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<UInt16, any Error>) in
            let once = Mutex<CheckedContinuation<UInt16, any Error>?>(continuation)
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    if let port = listener.port?.rawValue { once.withLock { $0.take() }?.resume(returning: port) }
                case .failed(let error):
                    once.withLock { $0.take() }?.resume(throwing: error)
                default:
                    break
                }
            }
            listener.start(queue: .global())
        }
        return try await body(try #require(URL(string: "http://127.0.0.1:\(port)")), { connections.withLock { $0.count } })
    }

    @Test("A throw when the server is unreachable leaves no claim and preserves the identity file")
    func throwingReleasesClaim() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            let before = try Self.saveRegisteredIdentity(in: directory)
            // There is no control server at 127.0.0.1:9.
            let node = try TailnetNode(configuration: try NodeTestSupport.configuration(stateDirectory: directory))
            guard case .control(.connection)? = await Self.logOutError(node) else {
                Issue.record("Expected control(.connection)")
                return
            }
            let claim = try #require(StateDirectoryClaims.shared.claim(directory), "A logOut() that throws leaves no claim")
            StateDirectoryClaims.shared.release(claim)
            #expect(try Self.identityFile(in: directory) == before)
        }
    }

    @Test("Overlapping logOut() yields stateDirectoryInUse (on the same node or a different one), a canceled logOut() releases the claim, and a run() started in the meantime is rejected")
    func overlapAndCancellation() async throws {
        try await Self.withSilentServer { url, connectionCount in
            try await NodeTestSupport.withTemporaryDirectory { directory in
                let before = try Self.saveRegisteredIdentity(in: directory)
                let configuration = NodeConfiguration(stateDirectory: directory, hostname: "rd-mac-1a2b3c4d", controlURL: url)
                let node = try TailnetNode(configuration: configuration)
                let other = try TailnetNode(configuration: configuration)

                let first = Task { await Self.logOutError(node) }
                // Once the first logOut() reaches the server, it holds the directory and waits for the response to `/key`.
                let deadline = ContinuousClock.now + .seconds(5)
                while connectionCount() == 0, ContinuousClock.now < deadline { try await Task.sleep(for: .milliseconds(10)) }
                try #require(connectionCount() == 1)

                for overlapping in [node, other] {
                    guard case .stateDirectoryInUse? = await Self.logOutError(overlapping) else {
                        Issue.record("Overlapping logOut() did not yield stateDirectoryInUse")
                        return
                    }
                }
                // A run() started while logOut() is active also ends with the same error (before opening files or sockets).
                do throws(NodeError) {
                    try await other.run()
                    Issue.record("run() did not throw")
                } catch {
                    guard case .stateDirectoryInUse = error else {
                        Issue.record("run() did not yield stateDirectoryInUse: \(error)")
                        return
                    }
                }
                #expect(connectionCount() == 1, "A rejected call does not reach the server")

                let start = ContinuousClock.now
                first.cancel()
                guard case .control(.connection)? = await first.value else {
                    Issue.record("Canceled logOut() did not yield control(.connection)")
                    return
                }
                #expect(ContinuousClock.now - start < .seconds(3), "Cancellation does not wait for the deadline (10 seconds)")
                let claim = try #require(StateDirectoryClaims.shared.claim(directory), "A canceled logOut() leaves no claim")
                StateDirectoryClaims.shared.release(claim)
                #expect(try Self.identityFile(in: directory) == before)
            }
        }
    }

    @Test("While the same node's run() is active or has just been canceled and is still ending, logOut() yields stateDirectoryInUse. It succeeds once run() has ended")
    func whileRunning() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            // At 127.0.0.1:9, run() fails to connect, backs off, and retries (it cannot register, so no node key is created).
            let node = try TailnetNode(configuration: try NodeTestSupport.configuration(stateDirectory: directory))
            let run = Task { () -> NodeError? in
                do throws(NodeError) {
                    try await node.run()
                    return nil
                } catch {
                    return error
                }
            }
            // Do not probe the claim table directly (run() would be rejected at that moment). Wait until the node reports it is running.
            let deadline = ContinuousClock.now + .seconds(5)
            while !(await node.isRunning) {
                try #require(ContinuousClock.now < deadline, "run() is not running")
                try await Task.sleep(for: .milliseconds(10))
            }
            guard case .stateDirectoryInUse? = await Self.logOutError(node) else {
                Issue.record("logOut() during run() did not yield stateDirectoryInUse")
                return
            }

            run.cancel()
            // Immediately after cancellation, logOut() is rejected if run() has yet to end and succeeds if it has ended. Neither case yields any other error.
            switch await Self.logOutError(node) {
            case nil, .stateDirectoryInUse?: break
            case let error?: Issue.record("logOut() immediately after cancellation: \(error)")
            }
            #expect(await run.value == nil)
            // After run() ends, logOut() returns without sending anything because the node has never registered.
            #expect(await Self.logOutError(node) == nil)
            let claim = try #require(StateDirectoryClaims.shared.claim(directory))
            StateDirectoryClaims.shared.release(claim)
        }
    }
}
