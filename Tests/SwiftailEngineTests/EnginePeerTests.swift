// Contract behavior 2. Convert a netmap to data plane peers. Item 7 in §7 of the notes (netmap-engine.md).

import Foundation
import Testing

import SwiftailBase
import SwiftailControl
import SwiftailEngine

@Suite("Peer calculation")
struct EnginePeerTests {
    static let selfNode = makeNodeJSON(id: 1, key: makeNodeKey(byte: 1), addresses: ["100.64.0.1/32", "fd7a:115c:a1e0::1/128"])
    static let reachable = #","DiscoKey":"\#(discoKeyText)","HomeDERP":1"#

    /// The peer computed from a netmap with one peer (ID 2, addresses 100.64.0.2 and fd7a:115c:a1e0::2).
    private func peers(_ extra: String = reachable, addresses: [String] = ["100.64.0.2/32", "fd7a:115c:a1e0::2/128"], at now: Date = wallClockStart) throws -> [EnginePeer] {
        let peer = makeNodeJSON(id: 2, key: makeNodeKey(byte: 2), addresses: addresses, extra: extra)
        return EnginePeer.peers(in: try makeNetmap(selfNode: Self.selfNode, peers: [peer]), at: now)
    }

    @Test("A regular peer without AllowedIPs uses its own addresses as AllowedIPs")
    func ordinaryPeer() throws {
        let peers = try peers()
        #expect(peers.count == 1)
        #expect(peers.first?.key == makeNodeKey(byte: 2))
        #expect(peers.first?.allowedIPs == ["100.64.0.2/32", "fd7a:115c:a1e0::2/128"].compactMap(IPPrefix.init))
        #expect(peers.first?.homeDERP == 1)
    }

    @Test("Exclude peers whose keyExpiry is at or before the current time")
    func expiryBoundary() throws {
        let expiry = #","KeyExpiry":"2027-01-15T08:00:00Z""#
        #expect(try peers(Self.reachable + expiry, at: wallClockStart).isEmpty)
        #expect(try peers(Self.reachable + expiry, at: wallClockStart + 1).isEmpty)
        #expect(try peers(Self.reachable + expiry, at: wallClockStart - 1).count == 1)
    }

    @Test("Always include peers with no expiry (omitted or zero time). Exclude peers marked Expired")
    func noExpiry() throws {
        let farFuture = Date(timeIntervalSince1970: 4_000_000_000)
        #expect(try peers(Self.reachable, at: farFuture).count == 1)
        #expect(try peers(Self.reachable + #","KeyExpiry":"0001-01-01T00:00:00Z""#, at: farFuture).count == 1)
        #expect(try peers(Self.reachable + #","Expired":true"#).isEmpty)
    }

    @Test("Exclude peers with a zero ID or key")
    func zeroIdentity() throws {
        let zeroKey = makeNodeJSON(id: 3, key: .zero, addresses: ["100.64.0.3/32"], extra: Self.reachable)
        let zeroID = makeNodeJSON(id: 0, key: makeNodeKey(byte: 4), addresses: ["100.64.0.4/32"], extra: Self.reachable)
        let netmap = try makeNetmap(selfNode: Self.selfNode, peers: [zeroKey, zeroID])
        #expect(EnginePeer.peers(in: netmap, at: wallClockStart).isEmpty)
    }

    @Test("Exclude peers with neither a disco key nor a home DERP. Either one is sufficient")
    func reachability() throws {
        #expect(try peers("").isEmpty)
        #expect(try peers(#","HomeDERP":1"#).count == 1)
        #expect(try peers(#","DiscoKey":"\#(discoKeyText)""#).first?.homeDERP == 0)
    }

    @Test("Exclude peers with empty AllowedIPs")
    func emptyAllowedIPs() throws {
        #expect(try peers(Self.reachable + #","AllowedIPs":[]"#).isEmpty)
    }

    @Test("Remove subnet routes and /0 from AllowedIPs. Exclude the peer if nothing remains")
    func routesAreExcluded() throws {
        let allowed = #","AllowedIPs":["100.64.0.2/32","10.0.0.0/24","0.0.0.0/0","::/0","fd7a:115c:a1e0::2/128"]"#
        #expect(try peers(Self.reachable + allowed).first?.allowedIPs == ["100.64.0.2/32", "fd7a:115c:a1e0::2/128"].compactMap(IPPrefix.init))

        let routesOnly = #","AllowedIPs":["10.0.0.0/24","0.0.0.0/0"]"#
        #expect(try peers(Self.reachable + routesOnly).isEmpty)
    }

    @Test("Keep only single-address prefixes for tailnet addresses or addresses listed in addresses")
    func selfPrefixRule() throws {
        // 100.64.0.9/32 is a tailnet address even when absent from addresses. 100.115.92.5/32 is in the ChromeOS range instead.
        // 10.1.2.3/32 is outside the tailnet range but appears in addresses. 100.64.0.0/24 is in the tailnet range but spans multiple addresses.
        let allowed = #","AllowedIPs":["100.64.0.9/32","100.115.92.5/32","10.1.2.3/32","100.64.0.0/24","fd7a:115c:a1e0::9/128","fd7a:115c:a1e1::9/128","100.64.0.9/32"]"#
        let peers = try peers(Self.reachable + allowed, addresses: ["100.64.0.2/32", "10.1.2.3/32"])
        #expect(peers.first?.allowedIPs == ["100.64.0.9/32", "10.1.2.3/32", "fd7a:115c:a1e0::9/128"].compactMap(IPPrefix.init))
    }

    @Test("Remove prefixes spanning multiple addresses even if listed in addresses. Exclude the peer if nothing remains")
    func widePrefixInAddressesIsExcluded() throws {
        let wide = try peers(addresses: ["100.64.0.2/32", "100.64.0.0/10", "fd7a:115c:a1e0::/48", "0.0.0.0/0"])
        #expect(wide.first?.allowedIPs == ["100.64.0.2/32"].compactMap(IPPrefix.init))
        #expect(try peers(addresses: ["100.64.0.0/10"]).isEmpty)
    }

    @Test("Exclude IPv4-mapped IPv6 addresses (::ffff:a.b.c.d/128) from AllowedIPs even if listed in Addresses")
    func mappedAddressIsExcluded() throws {
        let addresses = ["100.64.0.2/32", "::ffff:100.64.0.9/128"]
        let peers = try peers(addresses: addresses)
        #expect(peers.first?.allowedIPs == ["100.64.0.2/32"].compactMap(IPPrefix.init))
        // Exclude peers with only those addresses.
        #expect(try self.peers(addresses: ["::ffff:100.64.0.9/128"]).isEmpty)
    }

    @Test("Exclude this node's own addresses from the peer's AllowedIPs")
    func selfAddressIsExcluded() throws {
        let allowed = #","AllowedIPs":["100.64.0.2/32","100.64.0.1/32","fd7a:115c:a1e0::1/128"]"#
        #expect(try peers(Self.reachable + allowed).first?.allowedIPs == ["100.64.0.2/32"].compactMap(IPPrefix.init))
        #expect(try peers(addresses: ["100.64.0.1/32"]).isEmpty, "Exclude a peer that advertises only this node's own address")
    }

    @Test("Exclude unsupported peers (WireGuard-only, jailed, masquerade, and unsigned peers)")
    func unsupportedPeers() throws {
        #expect(try peers(Self.reachable + #","UnsignedPeerAPIOnly":true"#).isEmpty)
        #expect(try peers(Self.reachable + #","IsWireGuardOnly":true"#).isEmpty)
        #expect(try peers(Self.reachable + #","IsJailed":true"#).isEmpty)
        #expect(try peers(Self.reachable + #","SelfNodeV4MasqAddrForThisPeer":"100.64.9.9""#).isEmpty)
        #expect(try peers(Self.reachable + #","SelfNodeV6MasqAddrForThisPeer":"fd7a:115c:a1e0::99""#).isEmpty)
    }

    @Test("If two nodes advertise the same prefix, only the one with the lower node ID keeps it (a source address is bound to one peer)")
    func prefixHasOneOwner() throws {
        let bob = makeNodeJSON(id: 2, key: makeNodeKey(byte: 2), addresses: ["100.64.0.2/32"], extra: Self.reachable)
        // carol advertises bob's address in AllowedIPs in addition to its own.
        let carol = makeNodeJSON(
            id: 3, key: makeNodeKey(byte: 3), addresses: ["100.64.0.3/32"],
            extra: Self.reachable + #","AllowedIPs":["100.64.0.3/32","100.64.0.2/32"]"#)
        let netmap = try makeNetmap(selfNode: Self.selfNode, peers: [carol, bob])
        let peers = EnginePeer.peers(in: netmap, at: wallClockStart)
        #expect(peers.map(\.key) == [makeNodeKey(byte: 2), makeNodeKey(byte: 3)])
        #expect(peers.map { $0.allowedIPs.map(\.description) } == [["100.64.0.2/32"], ["100.64.0.3/32"]])
    }

    @Test("Exclude nodes that advertise only another node's prefixes and nodes that advertise the same key again")
    func duplicateKeyAndOnlyClaimedPrefixes() throws {
        let bob = makeNodeJSON(id: 2, key: makeNodeKey(byte: 2), addresses: ["100.64.0.2/32"], extra: Self.reachable)
        let sameAddress = makeNodeJSON(id: 3, key: makeNodeKey(byte: 3), addresses: ["100.64.0.2/32"], extra: Self.reachable)
        let sameKey = makeNodeJSON(id: 4, key: makeNodeKey(byte: 2), addresses: ["100.64.0.4/32"], extra: Self.reachable)
        let netmap = try makeNetmap(selfNode: Self.selfNode, peers: [sameKey, sameAddress, bob])
        let peers = EnginePeer.peers(in: netmap, at: wallClockStart)
        #expect(peers.map(\.key) == [makeNodeKey(byte: 2)])
        #expect(peers.first?.allowedIPs.map(\.description) == ["100.64.0.2/32"])
    }

    @Test("Sort by node ID in ascending order")
    func ordering() throws {
        let nodes = [5, 3, 4].map { id in
            makeNodeJSON(id: Int64(id), key: makeNodeKey(byte: UInt8(id)), addresses: ["100.64.0.\(id)/32"], extra: Self.reachable)
        }
        let netmap = try makeNetmap(selfNode: Self.selfNode, peers: nodes)
        #expect(EnginePeer.peers(in: netmap, at: wallClockStart).map(\.key) == [3, 4, 5].map { makeNodeKey(byte: $0) })
    }
}
