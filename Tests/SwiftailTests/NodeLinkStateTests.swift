import CryptoKit
import Foundation
import SwiftailBase
import SwiftailControl
import Testing
@testable import Swiftail

/// DERP region connection lifetime and state. Node API contract behaviors 3·4 and `docs/contracts/SwiftailTunnel.md` behavior B.
@Suite("Node connection state")
struct NodeLinkStateTests {
    private static let derpNode =
        #"{"Name":"1a","RegionID":1,"HostName":"derp.example.com","IPv4":"127.0.0.1","IPv6":"none","DERPPort":8443}"#

    /// A netmap with local address `100.64.0.1`. `regions` is the JSON inside the DERPMap's `Regions`.
    private static func netmap(regions: String) throws -> Netmap {
        try NodeTestSupport.netmap(regions: regions)
    }

    /// In M4, if the home region disappeared while DERP was disconnected, DERP stayed on the list of disconnected links, so `running` was not emitted again.
    /// In M5, disconnection does not change the state (behavior B), so in the same situation check that `running` is emitted once and remains in effect.
    @Test("After running, a netmap that removes the home region leaves running in effect without emitting it again")
    func homeLossKeepsRunning() async throws {
        let node = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
        await node.apply(try Self.netmap(regions: #""1":{"RegionID":1,"Nodes":[\#(Self.derpNode)]}"#))
        await node.markHomeDERPConnectedForTesting()
        await node.apply(try Self.netmap(regions: ""))

        #expect(await node.status.state == .running)
        node.eventQueue.finish()
        let seen = await NodeTestSupport.drain(node.events)
        #expect(seen == [.stateChanged(.running), .statusChanged])
    }

    /// Before the fix, only regions removed from the DERPMap were closed, so a region with a changed server kept trying to reconnect to the old server.
    @Test("Closes a region's connection when its server definition changes, and reopens it to the new server if it is home. An identical definition leaves the connection intact")
    func redefinedRegionIsReopened() async throws {
        let node = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
        func region(_ id: Int, host: String) -> String {
            #""\#(id)":{"RegionID":\#(id),"Nodes":[{"Name":"\#(id)a","RegionID":\#(id),"HostName":"\#(host)","IPv4":"127.0.0.1","IPv6":"none","DERPPort":8443}]}"#
        }
        await node.setNodeKeyForTesting(Curve25519.KeyAgreement.PrivateKey())
        await node.apply(try Self.netmap(regions: region(1, host: "a.example.com") + "," + region(2, host: "b.example.com")))
        await node.homeRegionChanged(to: 1)
        await node.openDERPLink(to: 2)
        let home = try #require(await node.derpLinks[1])
        let other = try #require(await node.derpLinks[2])

        // The connection stays the same when the same definition arrives again.
        await node.apply(try Self.netmap(regions: region(1, host: "a.example.com") + "," + region(2, host: "b.example.com")))
        #expect(await node.derpLinks[1]?.client === home.client)
        #expect(await node.derpLinks[2]?.client === other.client)

        // The hosts in both regions change. The home region reopens to the new server, and the non-home region stays closed until the next send.
        await node.apply(try Self.netmap(regions: region(1, host: "c.example.com") + "," + region(2, host: "d.example.com")))
        let reopened = try #require(await node.derpLinks[1])
        #expect(reopened.client !== home.client)
        #expect(reopened.servers.map(\.hostName) == ["c.example.com"])
        #expect(await node.derpLinks[2] == nil)
    }
}

private extension TailnetNode {
    /// Set only the node key without registering. A DERP connection requires a node key to open.
    func setNodeKeyForTesting(_ key: Curve25519.KeyAgreement.PrivateKey) {
        nodeKey = key
    }

    /// Updates the state machine as if the home DERP connection came up.
    func markHomeDERPConnectedForTesting() {
        announce(stateMachine.connected())
    }
}
