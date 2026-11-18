// Shared helpers for `.inProcess` node tests: a netmap with selectable peers, a node run without a control server, and a connection pair to the node's own address.
//
// The node calls `run()` against a loopback port with no control server (registration retries indefinitely), and the test creates the engine directly and applies the
// netmap. The engine loops back packets sent to the node's own address (tunnel contract behavior L), so one node acts as both listener and caller. The SYN for a connection to a peer address
// does not go out because there is no `Magicsock` (used to create connections that never establish).

import CryptoKit
import Foundation
import SwiftailBase
import SwiftailControl
import SwiftailEngine
import Testing
@testable import Swiftail

enum NetstackTestSupport {
    struct Peer {
        var id: Int64
        var key: UInt8
        var name: String
        var addresses: [String]
    }

    static let phone = Peer(
        id: 2, key: 0x22, name: "rd-phone-1a2b3c4d.tail0001.ts.net.", addresses: ["100.64.0.2/32", "fd7a:115c:a1e0::2/128"])

    /// A netmap with the local node (ID 1, `rd-mac-1a2b3c4d.tail0001.ts.net.`) and `peers`. Peers have home DERP 1 and enter the data plane.
    static func netmap(
        selfAddresses: [String] = ["100.64.0.1/32", "fd7a:115c:a1e0::1/128"], peers: [Peer] = []
    ) throws -> Netmap {
        func list(_ values: [String]) -> String { values.map { "\"\($0)\"" }.joined(separator: ",") }
        let selfNode = #"{"ID":1,"StableID":"nStable1","Name":"\#(NodeTestSupport.selfName)","User":101,"#
            + #""Key":"\#(NodeTestSupport.nodeKey(0x11))","Addresses":[\#(list(selfAddresses))],"MachineAuthorized":true}"#
        let peerList = peers.map { peer in
            #"{"ID":\#(peer.id),"Name":"\#(peer.name)","User":101,"Key":"\#(NodeTestSupport.nodeKey(peer.key))","#
                + #""Addresses":[\#(list(peer.addresses))],"AllowedIPs":[\#(list(peer.addresses))],"HomeDERP":1}"#
        }
        let json = #"{"Node":\#(selfNode),"Peers":[\#(peerList.joined(separator: ","))],"Domain":"tail0001.ts.net"}"#
        let response = try JSONDecoder().decode(MapResponse.self, from: Data(json.utf8))
        var session = MapSession()
        return try #require(try session.apply(response, receivedAt: Date()).netmap)
    }

    /// Runs an `.inProcess` node, applies `netmap`, sets the state to `.running`, and passes the node to `body`. Stops `run()` afterward.
    static func withRunningNode(
        _ netmap: Netmap, _ body: (TailnetNode) async throws -> Void
    ) async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            let node = try TailnetNode(
                configuration: try NodeTestSupport.configuration(stateDirectory: directory), device: .inProcess)
            let run = Task { try await node.run() }
            do {
                try await waitUntil("run() started") { await node.isRunning }
                await node.prepareForTesting(netmap)
                try await body(node)
            } catch {
                run.cancel()
                _ = await run.result
                throw error
            }
            run.cancel()
            _ = await run.result
        }
    }

    /// A connection pair to the node's own address. Also returns the listener (dropping it closes it).
    static func connectedPair(
        _ node: TailnetNode, port: UInt16 = 9_000, host: String = "100.64.0.1"
    ) async throws -> (client: TailnetConnection, server: TailnetConnection, listener: TailnetListener) {
        let listener = try await node.listen(port: port)
        let client = try await node.connect(to: host, port: port)
        var connections = listener.makeAsyncIterator()
        let server = try #require(await connections.next())
        return (client, server, listener)
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

    /// A deterministic pattern of `length` bytes.
    static func pattern(_ length: Int, seed: UInt8 = 0) -> [UInt8] {
        (0..<length).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ Int(seed)) }
    }

    /// Reads all `length` bytes. If the stream ends sooner, returns what it read.
    static func read(_ length: Int, from connection: TailnetConnection) async throws -> [UInt8] {
        var received: [UInt8] = []
        while received.count < length, let chunk = try await connection.read() {
            received += chunk
        }
        return received
    }

    /// Returns the `ConnectionError` thrown by `body`, or nil if it does not throw. Other errors fail the test (`Task.value` throws an untyped error).
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

    func isReading(_ connection: TailnetConnection) -> Bool {
        netstack?.connections[connection.id]?.readWaiter != nil
    }

    func isWriting(_ connection: TailnetConnection) -> Bool {
        netstack?.connections[connection.id]?.writeWaiter != nil
    }

    func isAccepting(_ listener: TailnetListener) -> Bool {
        listenerRecords[listener.token]?.waiter != nil
    }

    /// The number of connections the application holds or is establishing.
    var trackedConnectionCount: Int {
        netstack?.connections.count ?? 0
    }

    /// Whether a connection attempt is waiting to establish.
    var isConnecting: Bool {
        netstack?.connections.values.contains { $0.writeWaiter != nil && !$0.isEstablished } ?? false
    }
}
