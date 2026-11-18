// Shared bridge test helpers for an `.inProcess` node running without a control server, a tailnet connection pair established to the node's own address, and a bridged connection.
//
// Uses the same approach as `Tests/SwiftailTests/NetstackTestSupport.swift` and `WhoIsTestSupport.swift`. Those files are in the `SwiftailTests`
// target and are unavailable here, so duplicate only what is needed. The node calls `run()` against a loopback port with no control server (registration
// retries indefinitely), and the test creates the engine directly and applies the netmap. The engine loops back packets sent to the node's own address, so one node
// is both the listener and the caller. The peer address on the listener's accepted connection is the node's own address, so `whoIs` returns the node's own identity.

import CryptoKit
import Foundation
import SwiftailBase
import SwiftailControl
import SwiftailEngine
import Synchronization
import Testing
@testable import Swiftail
@testable import SwiftailLoopback

enum BridgeTestSupport {
    static let selfIdentity = PeerIdentity(
        stableID: "nStableSelf", name: "rd-mac-1a2b3c4d.tail0001.ts.net", computedName: "rd-mac-1a2b3c4d",
        loginName: "alice@example.com")

    /// A netmap containing only the local node (`rd-mac-1a2b3c4d`). If `withProfile` is false, there is no user profile and `whoIs` returns nil.
    static func netmap(
        selfAddresses: [String] = ["100.64.0.1/32", "fd7a:115c:a1e0::1/128"], withProfile: Bool = true
    ) throws -> Netmap {
        let addresses = selfAddresses.map { "\"\($0)\"" }.joined(separator: ",")
        let key = "nodekey:" + [UInt8](repeating: 0x11, count: 32).hex
        let selfNode = #"{"ID":1,"StableID":"nStableSelf","Name":"rd-mac-1a2b3c4d.tail0001.ts.net.","User":101,"#
            + #""Key":"\#(key)","Addresses":[\#(addresses)],"MachineAuthorized":true}"#
        let profiles = withProfile ? #"{"ID":101,"LoginName":"alice@example.com"}"# : ""
        let json = #"{"Node":\#(selfNode),"Peers":[],"UserProfiles":[\#(profiles)],"Domain":"tail0001.ts.net"}"#
        let response = try JSONDecoder().decode(MapResponse.self, from: Data(json.utf8))
        var session = MapSession()
        return try #require(try session.apply(response, receivedAt: Date()).netmap)
    }

    /// Runs an `.inProcess` node, applies `netmap`, sets the state to `.running`, and passes the node to `body`. The function passed to `body`
    /// stops the node's `run()` and waits for it to finish. When `body` ends, stops the node if it has not already stopped.
    static func withRunningNode(
        _ netmap: Netmap, _ body: (TailnetNode, _ stop: @escaping @Sendable () async -> Void) async throws -> Void
    ) async throws {
        let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-bridge-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let configuration = NodeConfiguration(
            stateDirectory: directory, hostname: "rd-mac-1a2b3c4d",
            controlURL: try #require(URL(string: "http://127.0.0.1:9")))
        let node = try TailnetNode(configuration: configuration, device: .inProcess)
        // If `run()` ends on its own before the test stops it, record why (so a stopped node is not mistaken for a bridge failure).
        let stopping = Mutex(false)
        let run = Task {
            do throws(NodeError) {
                try await node.run()
            } catch {
                if !stopping.withLock({ $0 }) { Issue.record("run() ended during the test: \(error)") }
            }
        }
        let stop: @Sendable () async -> Void = {
            stopping.withLock { $0 = true }
            run.cancel()
            _ = await run.result
        }
        do {
            try await waitUntil("run() started") { await node.isRunning }
            await node.prepareForTesting(netmap)
            try await body(node, stop)
        } catch {
            await stop()
            throw error
        }
        await stop()
    }

    /// A connection pair made to the node's own address. `server` is the accepted connection passed to the bridge. Also returns the listener (dropping it closes it).
    static func connectedPair(
        _ node: TailnetNode, port: UInt16 = 9_000
    ) async throws -> (client: TailnetConnection, server: TailnetConnection, listener: TailnetListener) {
        let listener = try await node.listen(port: port)
        let client = try await node.connect(to: "100.64.0.1", port: port)
        var connections = listener.makeAsyncIterator()
        let server = try #require(await connections.next())
        return (client, server, listener)
    }

    /// One bridged connection with the tailnet caller (`client`), the connection accepted by the loopback server (`peer`), and the running `forward`.
    struct Bridged {
        var client: TailnetConnection
        var server: TailnetConnection
        var listener: TailnetListener
        var peer: PeerConnection
        var forwarding: Task<LoopbackBridgeError?, Never>

        /// Waits for `forward` to return. Returns the thrown error, or nil on normal return. When the waiting Task is canceled (test deadline),
        /// cancels `forward`.
        func finished() async -> LoopbackBridgeError? {
            let forwarding = forwarding
            return await withTaskCancellationHandler { await forwarding.value } onCancel: { forwarding.cancel() }
        }
    }

    /// Bridges a tailnet connection accepted on `port` to `server`.
    static func bridge(
        _ node: TailnetNode, _ bridge: LoopbackBridge, to server: PlainLoopbackServer, port: UInt16 = 9_000
    ) async throws -> Bridged {
        let pair = try await connectedPair(node, port: port)
        let forwarding = forward(pair.server, with: bridge, toLoopbackPort: server.port)
        let peer = try await server.next()
        return Bridged(client: pair.client, server: pair.server, listener: pair.listener, peer: peer, forwarding: forwarding)
    }

    /// The Task running `forward`. Returns the thrown error, or nil on normal return.
    static func forward(
        _ connection: TailnetConnection, with bridge: LoopbackBridge, toLoopbackPort port: UInt16
    ) -> Task<LoopbackBridgeError?, Never> {
        Task {
            do throws(LoopbackBridgeError) {
                try await bridge.forward(connection, toLoopbackPort: port)
                return nil
            } catch {
                return error
            }
        }
    }

    /// Checks `condition` every 10ms until it becomes true. Fails if it does not become true within 5 seconds.
    static func waitUntil(_ what: String, _ condition: () async -> Bool) async throws {
        for _ in 0..<500 {
            if await condition() { return }
            try await Task.sleep(for: .milliseconds(10))
        }
        Issue.record("Did not happen within 5 seconds: \(what)")
        throw CancellationError()
    }

    /// A deterministic pattern of `length` bytes. The period is long enough for the hash to detect misaligned chunks.
    static func pattern(_ length: Int, seed: UInt8 = 0) -> [UInt8] {
        (0..<length).map { UInt8(truncatingIfNeeded: ($0 &* 31) ^ ($0 >> 9) &+ Int(seed)) }
    }

    static func digest(_ bytes: [UInt8]) -> SHA256.Digest {
        SHA256.hash(data: bytes)
    }

    /// Reads until the peer closes its write direction.
    static func readToEnd(_ connection: TailnetConnection) async throws -> [UInt8] {
        var received: [UInt8] = []
        while let chunk = try await connection.read() { received += chunk }
        return received
    }

    /// Returns the `ConnectionError` thrown by `body`, or nil if it does not throw. Other errors fail the test.
    static func error<T>(_ body: () async throws -> T) async -> ConnectionError? {
        do {
            _ = try await body()
            return nil
        } catch let error as ConnectionError {
            return error
        } catch {
            Issue.record("Expected ConnectionError, got \(error)")
            return nil
        }
    }
}

extension TailnetNode {
    /// Creates the engine without registering, applies the netmap, and sets the state to `.running`.
    func prepareForTesting(_ netmap: Netmap) {
        engine = TailnetEngine(nodeKey: Curve25519.KeyAgreement.PrivateKey(), discoKey: .zero, now: .now, wallClock: Date())
        apply(netmap)
        announce(stateMachine.connected())
    }
}
