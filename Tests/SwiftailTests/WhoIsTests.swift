import Foundation
import SwiftailBase
import SwiftailControl
import SwiftailEngine
import Testing
@testable import Swiftail

/// `whoIs`: address → node identity (contract `docs/contracts/SwiftailHost.md` behaviors W1~W6, unit test 1).
@Suite("whoIs: looking up node identity by address", .timeLimit(.minutes(1)))
struct WhoIsTests {
    private typealias Support = WhoIsTestSupport

    private static func address(_ text: String) throws -> IPAddress {
        try #require(IPAddress(text))
    }

    private static func node() throws -> TailnetNode {
        try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
    }

    /// Looks up the identity of address `text` on a node that has applied `netmap`.
    private static func whoIs(_ text: String, in netmap: Netmap) async throws -> PeerIdentity? {
        let node = try node()
        await node.apply(netmap)
        return await node.whoIs(try address(text))
    }

    // MARK: Lookup

    @Test("The local addresses (IPv4 and IPv6) identify the local node")
    func selfAddress() async throws {
        let netmap = try Support.netmap(peers: [Support.phone])
        for text in ["100.64.0.1", "fd7a:115c:a1e0::1"] {
            let identity = try #require(try await Self.whoIs(text, in: netmap))
            #expect(identity == PeerIdentity(
                stableID: "nStableSelf", name: "rd-mac-1a2b3c4d.tail0001.ts.net", computedName: "rd-mac-1a2b3c4d",
                loginName: "alice@example.com"))
        }
    }

    @Test("A peer's IPv4 and IPv6 addresses identify that peer")
    func peerAddresses() async throws {
        let netmap = try Support.netmap(peers: [Support.phone])
        for text in ["100.64.0.2", "fd7a:115c:a1e0::2"] {
            let identity = try #require(try await Self.whoIs(text, in: netmap))
            #expect(identity == PeerIdentity(
                stableID: "nStablePhone", name: "rd-phone-1a2b3c4d.tail0001.ts.net", computedName: "rd-phone-1a2b3c4d",
                loginName: "alice@example.com"))
        }
    }

    @Test("Converts IPv4-mapped IPv6 addresses to IPv4 before lookup")
    func mappedAddress() async throws {
        let netmap = try Support.netmap(peers: [Support.phone])
        #expect(try await Self.whoIs("::ffff:100.64.0.2", in: netmap)?.stableID == "nStablePhone")
        #expect(try await Self.whoIs("::ffff:100.64.0.1", in: netmap)?.stableID == "nStableSelf")
        // Leaves non-IPv4-mapped ::ffff:0:a.b.c.d and other prefixes unchanged.
        #expect(try await Self.whoIs("::100.64.0.2", in: netmap) == nil)
    }

    @Test("An unknown address yields nil")
    func unknownAddress() async throws {
        let netmap = try Support.netmap(peers: [Support.phone])
        for text in ["100.64.0.3", "fd7a:115c:a1e0::3", "8.8.8.8", "0.0.0.0"] {
            #expect(try await Self.whoIs(text, in: netmap) == nil)
        }
    }

    @Test("Returns nil before receiving a netmap")
    func beforeNetmap() async throws {
        let node = try Self.node()
        #expect(await node.whoIs(try Self.address("100.64.0.1")) == nil)
    }

    @Test("Skips subnet route (AllowedIPs) addresses and prefixes that cover more than one address")
    func subnetRoutes() async throws {
        var router = Support.phone
        router.allowedIPs = ["100.64.0.2/32", "fd7a:115c:a1e0::2/128", "192.168.1.0/24", "10.0.0.0/8"]
        router.addresses.append("100.64.9.0/24")
        let netmap = try Support.netmap(peers: [router])
        #expect(try await Self.whoIs("100.64.0.2", in: netmap)?.stableID == "nStablePhone")
        for text in ["192.168.1.5", "192.168.1.0", "10.1.2.3", "100.64.9.0", "100.64.9.7"] {
            #expect(try await Self.whoIs(text, in: netmap) == nil)
        }
    }

    @Test("Finds offline peers and yields nil for a peer's address if its key expired and it did not enter the data plane")
    func expiredAndOfflinePeers() async throws {
        var offline = Support.phone
        offline.online = false
        #expect(try await Self.whoIs("100.64.0.2", in: try Support.netmap(peers: [offline]))?.stableID == "nStablePhone")

        var expired = Support.phone
        expired.expired = true
        let netmap = try Support.netmap(peers: [expired])
        #expect(EnginePeer.peers(in: netmap, at: Date()).isEmpty)
        #expect(try await Self.whoIs("100.64.0.2", in: netmap) == nil)
    }

    @Test("When several nodes have the same address, returns the identity of the peer to which the data plane assigned the address (the lower node ID)")
    func duplicateAddressFollowsDataPlane() async throws {
        // Order the entries in the netmap differently from node ID order.
        var high = Support.phone
        high.id = 5
        high.stableID = "nStableHigh"
        high.key = 0x55
        var low = Support.phone
        low.id = 2
        low.stableID = "nStableLow"
        var last = Support.phone
        last.id = 9
        last.stableID = "nStableLast"
        last.key = 0x99
        let netmap = try Support.netmap(peers: [high, low, last])

        for text in ["100.64.0.2", "fd7a:115c:a1e0::2"] {
            let address = try Self.address(text)
            let prefix = try #require(IPPrefix(address: address, length: address.bytes.count * 8))
            // Only one peer has the address as an AllowedIPs entry (can send packets from it).
            let owners = EnginePeer.peers(in: netmap, at: Date()).filter { $0.allowedIPs.contains(prefix) }
            #expect(owners.map(\.key.description) == [NodeTestSupport.nodeKey(low.key)])
            #expect(try await Self.whoIs(text, in: netmap)?.stableID == "nStableLow")
        }

        // When the peer assigned the address expires and is removed, the next node gets it.
        low.expired = true
        let afterExpiry = try Support.netmap(peers: [high, low, last])
        #expect(try await Self.whoIs("100.64.0.2", in: afterExpiry)?.stableID == "nStableHigh")
    }

    @Test("If a data-plane peer also has the local address, returns nil because the connection's owner is ambiguous")
    func peerClaimingSelfAddress() async throws {
        var impostor = Support.phone
        impostor.id = 3
        impostor.stableID = "nStableImpostor"
        impostor.key = 0x33
        impostor.addresses = ["100.64.0.1/32"]
        let netmap = try Support.netmap(peers: [impostor])
        let claimed = try #require(IPPrefix("100.64.0.1/32"))
        // The ambiguity lasts only while this peer can send packets from that address.
        if EnginePeer.peers(in: netmap, at: Date()).contains(where: { $0.allowedIPs.contains(claimed) }) {
            #expect(try await Self.whoIs("100.64.0.1", in: netmap) == nil)
        } else {
            #expect(try await Self.whoIs("100.64.0.1", in: netmap)?.stableID == "nStableSelf")
        }
        #expect(try await Self.whoIs("100.64.0.1", in: netmap)?.stableID != "nStableImpostor")
        // Non-overlapping local addresses still identify the local node.
        #expect(try await Self.whoIs("fd7a:115c:a1e0::1", in: netmap)?.stableID == "nStableSelf")
    }

    @Test("A single-address AllowedIPs entry admitted by the data plane identifies that peer even if the address is absent from Addresses")
    func allowedSingleAddress() async throws {
        var peer = Support.phone
        peer.allowedIPs = ["100.64.0.2/32", "fd7a:115c:a1e0::2/128", "100.64.0.77/32"]
        let netmap = try Support.netmap(peers: [peer])
        let extra = try #require(IPPrefix("100.64.0.77/32"))
        #expect(EnginePeer.peers(in: netmap, at: Date()).first?.allowedIPs.contains(extra) == true)
        #expect(try await Self.whoIs("100.64.0.77", in: netmap)?.stableID == "nStablePhone")
    }

    // MARK: Rejection

    @Test("A node whose user profile is absent from the netmap yields nil (without falling through to another node)")
    func missingProfile() async throws {
        var stranger = Support.phone
        stranger.user = 999
        let netmap = try Support.netmap(peers: [stranger])
        #expect(try await Self.whoIs("100.64.0.2", in: netmap) == nil)
        #expect(try await Self.whoIs("100.64.0.1", in: netmap)?.stableID == "nStableSelf")
        // With no profiles, even the local node yields nil.
        #expect(try await Self.whoIs("100.64.0.1", in: try Support.netmap(profiles: [])) == nil)
    }

    @Test("A node with an empty StableID yields nil")
    func emptyStableID() async throws {
        var anonymous = Support.phone
        anonymous.stableID = ""
        #expect(try await Self.whoIs("100.64.0.2", in: try Support.netmap(peers: [anonymous])) == nil)
    }

    // MARK: Names and users

    @Test("A node with an empty name has an empty name string and the hostname as computedName")
    func emptyName() async throws {
        var unnamed = Support.phone
        unnamed.name = ""
        unnamed.hostname = "Alice's iPhone.local"
        let identity = try #require(try await Self.whoIs("100.64.0.2", in: try Support.netmap(peers: [unnamed])))
        #expect(identity.name == "")
        #expect(identity.computedName == "alices-iphone")
    }

    @Test("A node with an empty name and hostname has the node public key text as computedName")
    func emptyNameAndHostname() async throws {
        var unnamed = Support.phone
        unnamed.name = ""
        let identity = try #require(try await Self.whoIs("100.64.0.2", in: try Support.netmap(peers: [unnamed])))
        #expect(identity.computedName == NodeTestSupport.nodeKey(0x22))
    }

    @Test("A node shared from another tailnet gets an FQDN without the trailing dot as computedName and uses the owner's login name")
    func sharedFromOtherTailnet() async throws {
        var shared = Support.phone
        shared.name = "rd-shared-9f9f9f9f.tail0002.ts.net."
        shared.user = 202
        let netmap = try Support.netmap(peers: [shared], profiles: [Support.alice, (202, "bob@example.com")])
        let identity = try #require(try await Self.whoIs("100.64.0.2", in: netmap))
        #expect(identity.name == "rd-shared-9f9f9f9f.tail0002.ts.net")
        #expect(identity.computedName == "rd-shared-9f9f9f9f.tail0002.ts.net")
        #expect(identity.loginName == "bob@example.com")
    }

    @Test("A tagged node uses the profile of the user who created it as is")
    func taggedNode() async throws {
        var tagged = Support.phone
        tagged.tags = ["tag:phone"]
        tagged.user = 303
        let netmap = try Support.netmap(peers: [tagged], profiles: [Support.alice, (303, "tagged-devices")])
        #expect(try await Self.whoIs("100.64.0.2", in: netmap)?.loginName == "tagged-devices")
    }

    @Test("If the local name has no dot, the suffix is the name itself, so peer names without dots stay unchanged")
    func suffixlessSelfName() async throws {
        var bare = Support.selfNode
        bare.name = "mac"
        var peer = Support.phone
        peer.name = "mac"
        let netmap = try Support.netmap(selfNode: bare, peers: [peer])
        // A name equal to the suffix has no label boundary, so the suffix stays.
        #expect(try await Self.whoIs("100.64.0.2", in: netmap)?.computedName == "mac")
    }

    // MARK: Netmap changes (behavior W6)

    @Test("When the netmap changes, answers reflect changes to the address owner")
    func ownerChanges() async throws {
        let node = try Self.node()
        let phoneAddress = try Self.address("100.64.0.2")
        await node.apply(try Support.netmap(peers: [Support.phone]))
        #expect(await node.whoIs(phoneAddress)?.stableID == "nStablePhone")

        // Another node took over the same address.
        var heir = Support.phone
        heir.id = 9
        heir.stableID = "nStableHeir"
        heir.key = 0x99
        heir.name = "rd-heir.tail0001.ts.net."
        await node.apply(try Support.netmap(peers: [heir]))
        let identity = try #require(await node.whoIs(phoneAddress))
        #expect(identity.stableID == "nStableHeir")
        #expect(identity.computedName == "rd-heir")

        // When only the name changes and the owner stays the same, the lookup sees the new name.
        heir.name = "rd-renamed.tail0001.ts.net."
        await node.apply(try Support.netmap(peers: [heir]))
        #expect(await node.whoIs(phoneAddress)?.computedName == "rd-renamed")
    }

    @Test("An address yields nil after the peer disappears from the netmap")
    func peerDisappears() async throws {
        let node = try Self.node()
        await node.apply(try Support.netmap(peers: [Support.phone]))
        #expect(await node.whoIs(try Self.address("fd7a:115c:a1e0::2")) != nil)
        await node.apply(try Support.netmap())
        #expect(await node.whoIs(try Self.address("fd7a:115c:a1e0::2")) == nil)
        #expect(await node.whoIs(try Self.address("100.64.0.1"))?.stableID == "nStableSelf")
    }

    @Test("The owner is determined when the netmap is applied. Even if the previous owner's key expires before lookup, the answer stays the same until the data plane changes")
    func answerDoesNotDependOnQueryTime() async throws {
        var low = Support.phone
        low.stableID = "nStableLow"
        low.keyExpiry = Date().addingTimeInterval(2)
        var high = Support.phone
        high.id = 5
        high.stableID = "nStableHigh"
        high.key = 0x55
        // Since the node is not running, there is no timer to handle key expiration. The data-plane owner is still the one selected when the netmap was applied.
        let node = try Self.node()
        await node.apply(try Support.netmap(peers: [low, high]))
        let address = try Self.address("100.64.0.2")
        #expect(await node.whoIs(address)?.stableID == "nStableLow")
        try await Task.sleep(for: .seconds(3))
        #expect(await node.whoIs(address)?.stableID == "nStableLow")
    }

    @Test("By the time a change of address owner ends a connection with peerRemoved, whoIs already points to the new owner")
    func tableChangesWithConnectionTeardown() async throws {
        try await NetstackTestSupport.withRunningNode(try Support.netmap(peers: [Support.phone])) { node in
            let phoneAddress = try Self.address("100.64.0.2")
            let connector = Task { () async throws -> TailnetConnection in
                try await node.connect(to: "100.64.0.2", port: 80)
            }
            try await NetstackTestSupport.waitUntil("connect is waiting") { await node.isConnecting }
            #expect(await node.whoIs(phoneAddress)?.stableID == "nStablePhone")

            var heir = Support.phone
            heir.id = 9
            heir.stableID = "nStableHeir"
            heir.key = 0x99
            await node.apply(try Support.netmap(peers: [heir]))
            #expect(await NetstackTestSupport.error { try await connector.value } == .peerRemoved)
            #expect(await node.whoIs(phoneAddress)?.stableID == "nStableHeir")
        }
    }
}
