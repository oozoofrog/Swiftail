import Foundation
import SwiftailBase
import Testing
@testable import Swiftail

/// Tests connections whose address owner changes (contract `docs/contracts/SwiftailNetstack.md` behaviors X10·S9·N7, unit test 15).
///
/// A connection to a peer remains in progress because the SYN does not go out. The node still compares the owner and drops it using the same path as for an established connection
/// (`TCPStack.removeConnections(toRemoteAddress:)` disregards connection state). Test changes to the node's own address with established connections.
@Suite("Node TCP address ownership changes", .timeLimit(.minutes(1)))
struct NetstackPeerRemovalTests {
    private typealias Support = NetstackTestSupport

    private static func pendingConnect(_ node: TailnetNode) async throws -> Task<TailnetConnection, any Error> {
        let connector = Task { () async throws -> TailnetConnection in
            try await node.connect(to: "100.64.0.2", port: 80)
        }
        try await Support.waitUntil("connect is waiting") { await node.isConnecting }
        return connector
    }

    @Test("When a peer disappears from the netmap, connections for its address end with peerRemoved")
    func peerRemoved() async throws {
        try await Support.withRunningNode(try Support.netmap(peers: [Support.phone])) { node in
            let connector = try await Self.pendingConnect(node)
            await node.apply(try Support.netmap())
            #expect(await Support.error { try await connector.value } == .peerRemoved)
            #expect(await node.trackedConnectionCount == 0)
        }
    }

    @Test("When the same address belongs to a different key, the connection ends with peerRemoved")
    func ownerChanged() async throws {
        try await Support.withRunningNode(try Support.netmap(peers: [Support.phone])) { node in
            let connector = try await Self.pendingConnect(node)
            var heir = Support.phone
            heir.id = 9
            heir.key = 0x99
            await node.apply(try Support.netmap(peers: [heir]))
            #expect(await Support.error { try await connector.value } == .peerRemoved)
        }
    }

    @Test("When the previous owner's key expires and the address passes to another node, the connection ends and the whoIs and stack owners change together, even without a new netmap")
    func ownerKeyExpires() async throws {
        var low = WhoIsTestSupport.phone
        low.stableID = "nStableLow"
        var high = WhoIsTestSupport.phone
        high.id = 5
        high.stableID = "nStableHigh"
        high.key = 0x55
        let (owner, heir) = (low, high)
        let stableIDs = [
            NodeTestSupport.nodeKey(low.key): "nStableLow", NodeTestSupport.nodeKey(high.key): "nStableHigh",
        ]
        try await Support.withRunningNode(try WhoIsTestSupport.netmap(peers: [owner, heir])) { node in
            let address = try #require(IPAddress("100.64.0.2"))
            // A netmap in which the owner's key (the lower node ID) will expire soon. The owner stays the same, so applying this map leaves the connection intact.
            var expiring = owner
            expiring.keyExpiry = Date().addingTimeInterval(2)
            await node.apply(try WhoIsTestSupport.netmap(peers: [expiring, heir]))
            let connector = try await Self.pendingConnect(node)
            #expect(await node.ownerViews(of: address).identity == "nStableLow")

            // Check until the expiration time passes and the engine changes the peer. Throughout, whoIs returns the owner held by the stack.
            try await Support.waitUntil("Key expiration was processed") {
                let views = await node.ownerViews(of: address)
                #expect(views.identity == views.stackOwner.flatMap { stableIDs[$0.description] })
                return views.identity == "nStableHigh"
            }
            try await Support.waitUntil("The previous owner's connection ended") { await !node.isConnecting }
            #expect(await Support.error { try await connector.value } == .peerRemoved)
        }
    }

    @Test("A netmap with the same owner leaves the connection intact")
    func unchangedOwnerKeepsConnection() async throws {
        try await Support.withRunningNode(try Support.netmap(peers: [Support.phone])) { node in
            let connector = try await Self.pendingConnect(node)
            var renamed = Support.phone
            renamed.name = "rd-phone-renamed.tail0001.ts.net."
            await node.apply(try Support.netmap(peers: [renamed]))
            try await Task.sleep(for: .milliseconds(50))
            #expect(await node.isConnecting)
            connector.cancel()
            #expect(await Support.error { try await connector.value } == .cancelled)
        }
    }

    @Test("When the node's own address changes, both sides of an established connection end with peerRemoved")
    func selfAddressChanged() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node in
            let pair = try await Support.connectedPair(node)
            let reader = Task { () async throws -> [UInt8]? in try await pair.server.read() }
            try await Support.waitUntil("read is waiting") { await node.isReading(pair.server) }
            await node.apply(try Support.netmap(selfAddresses: ["100.64.0.9/32"]))
            #expect(await Support.error { try await reader.value } == .peerRemoved)
            #expect(await Support.error { try await pair.client.write([1]) } == .peerRemoved)
            await pair.client.close()
            await pair.server.close()
            #expect(await node.trackedConnectionCount == 0)
        }
    }
}

extension TailnetNode {
    /// Returns the `whoIs` result (`StableID`) and the key the stack holds as the address owner in one actor execution.
    func ownerViews(of address: IPAddress) -> (identity: String?, stackOwner: NodePublicKey?) {
        (whoIs(address)?.stableID, netstack?.addressOwners[address])
    }
}
