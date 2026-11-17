// 계약 동작 2: netmap → 데이터면 피어. 노트(netmap-engine.md) 7절 7의 항목.

import Foundation
import Testing

import SwiftailBase
import SwiftailControl
import SwiftailEngine

@Suite("피어 계산")
struct EnginePeerTests {
    static let selfNode = makeNodeJSON(id: 1, key: makeNodeKey(byte: 1), addresses: ["100.64.0.1/32", "fd7a:115c:a1e0::1/128"])
    static let reachable = #","DiscoKey":"\#(discoKeyText)","HomeDERP":1"#

    /// 피어 하나(ID 2, 주소 100.64.0.2·fd7a:115c:a1e0::2)를 넣은 netmap에서 계산한 피어.
    private func peers(_ extra: String = reachable, addresses: [String] = ["100.64.0.2/32", "fd7a:115c:a1e0::2/128"], at now: Date = wallClockStart) throws -> [EnginePeer] {
        let peer = makeNodeJSON(id: 2, key: makeNodeKey(byte: 2), addresses: addresses, extra: extra)
        return EnginePeer.peers(in: try makeNetmap(selfNode: Self.selfNode, peers: [peer]), at: now)
    }

    @Test("일반 피어: AllowedIPs가 없으면 자기 주소가 AllowedIPs다")
    func ordinaryPeer() throws {
        let peers = try peers()
        #expect(peers.count == 1)
        #expect(peers.first?.key == makeNodeKey(byte: 2))
        #expect(peers.first?.allowedIPs == ["100.64.0.2/32", "fd7a:115c:a1e0::2/128"].compactMap(IPPrefix.init))
        #expect(peers.first?.homeDERP == 1)
    }

    @Test("만료 경계: keyExpiry가 지금과 같거나 앞서면 올리지 않는다")
    func expiryBoundary() throws {
        let expiry = #","KeyExpiry":"2027-01-15T08:00:00Z""#
        #expect(try peers(Self.reachable + expiry, at: wallClockStart).isEmpty)
        #expect(try peers(Self.reachable + expiry, at: wallClockStart + 1).isEmpty)
        #expect(try peers(Self.reachable + expiry, at: wallClockStart - 1).count == 1)
    }

    @Test("만료 없음(생략·0 시각)은 언제나 올린다. Expired 표지는 올리지 않는다")
    func noExpiry() throws {
        let farFuture = Date(timeIntervalSince1970: 4_000_000_000)
        #expect(try peers(Self.reachable, at: farFuture).count == 1)
        #expect(try peers(Self.reachable + #","KeyExpiry":"0001-01-01T00:00:00Z""#, at: farFuture).count == 1)
        #expect(try peers(Self.reachable + #","Expired":true"#).isEmpty)
    }

    @Test("ID가 0이거나 키가 0이면 올리지 않는다")
    func zeroIdentity() throws {
        let zeroKey = makeNodeJSON(id: 3, key: .zero, addresses: ["100.64.0.3/32"], extra: Self.reachable)
        let zeroID = makeNodeJSON(id: 0, key: makeNodeKey(byte: 4), addresses: ["100.64.0.4/32"], extra: Self.reachable)
        let netmap = try makeNetmap(selfNode: Self.selfNode, peers: [zeroKey, zeroID])
        #expect(EnginePeer.peers(in: netmap, at: wallClockStart).isEmpty)
    }

    @Test("disco 키와 홈 DERP가 모두 없으면 올리지 않는다. 하나만 있으면 올린다")
    func reachability() throws {
        #expect(try peers("").isEmpty)
        #expect(try peers(#","HomeDERP":1"#).count == 1)
        #expect(try peers(#","DiscoKey":"\#(discoKeyText)""#).first?.homeDERP == 0)
    }

    @Test("빈 AllowedIPs는 올리지 않는다")
    func emptyAllowedIPs() throws {
        #expect(try peers(Self.reachable + #","AllowedIPs":[]"#).isEmpty)
    }

    @Test("서브넷 경로와 /0은 AllowedIPs에서 뺀다. 남는 것이 없으면 올리지 않는다")
    func routesAreExcluded() throws {
        let allowed = #","AllowedIPs":["100.64.0.2/32","10.0.0.0/24","0.0.0.0/0","::/0","fd7a:115c:a1e0::2/128"]"#
        #expect(try peers(Self.reachable + allowed).first?.allowedIPs == ["100.64.0.2/32", "fd7a:115c:a1e0::2/128"].compactMap(IPPrefix.init))

        let routesOnly = #","AllowedIPs":["10.0.0.0/24","0.0.0.0/0"]"#
        #expect(try peers(Self.reachable + routesOnly).isEmpty)
    }

    @Test("한 주소짜리 tailnet 주소, 또는 addresses에 있는 접두만 남긴다")
    func selfPrefixRule() throws {
        // 100.64.0.9/32는 addresses에 없어도 tailnet 주소다. 100.115.92.5/32(ChromeOS 대역)는 아니다.
        // 10.1.2.3/32는 tailnet 주소가 아니지만 addresses에 있다. 100.64.0.0/24는 tailnet 범위지만 한 주소가 아니다.
        let allowed = #","AllowedIPs":["100.64.0.9/32","100.115.92.5/32","10.1.2.3/32","100.64.0.0/24","fd7a:115c:a1e0::9/128","fd7a:115c:a1e1::9/128","100.64.0.9/32"]"#
        let peers = try peers(Self.reachable + allowed, addresses: ["100.64.0.2/32", "10.1.2.3/32"])
        #expect(peers.first?.allowedIPs == ["100.64.0.9/32", "10.1.2.3/32", "fd7a:115c:a1e0::9/128"].compactMap(IPPrefix.init))
    }

    @Test("addresses에 있어도 한 주소짜리가 아닌 접두는 뺀다. 남는 것이 없으면 올리지 않는다")
    func widePrefixInAddressesIsExcluded() throws {
        let wide = try peers(addresses: ["100.64.0.2/32", "100.64.0.0/10", "fd7a:115c:a1e0::/48", "0.0.0.0/0"])
        #expect(wide.first?.allowedIPs == ["100.64.0.2/32"].compactMap(IPPrefix.init))
        #expect(try peers(addresses: ["100.64.0.0/10"]).isEmpty)
    }

    @Test("IPv4-mapped IPv6 주소(::ffff:a.b.c.d/128)는 Addresses에 있어도 AllowedIPs에 넣지 않는다")
    func mappedAddressIsExcluded() throws {
        let addresses = ["100.64.0.2/32", "::ffff:100.64.0.9/128"]
        let peers = try peers(addresses: addresses)
        #expect(peers.first?.allowedIPs == ["100.64.0.2/32"].compactMap(IPPrefix.init))
        // 그것뿐인 피어는 올리지 않는다.
        #expect(try self.peers(addresses: ["::ffff:100.64.0.9/128"]).isEmpty)
    }

    @Test("이 노드 자신의 주소는 피어의 AllowedIPs에 넣지 않는다")
    func selfAddressIsExcluded() throws {
        let allowed = #","AllowedIPs":["100.64.0.2/32","100.64.0.1/32","fd7a:115c:a1e0::1/128"]"#
        #expect(try peers(Self.reachable + allowed).first?.allowedIPs == ["100.64.0.2/32"].compactMap(IPPrefix.init))
        #expect(try peers(addresses: ["100.64.0.1/32"]).isEmpty, "자기 주소만 내세운 피어는 올리지 않는다")
    }

    @Test("지원하지 않는 피어(WireGuard 전용, jailed, masquerade, 서명 없는 피어)는 올리지 않는다")
    func unsupportedPeers() throws {
        #expect(try peers(Self.reachable + #","UnsignedPeerAPIOnly":true"#).isEmpty)
        #expect(try peers(Self.reachable + #","IsWireGuardOnly":true"#).isEmpty)
        #expect(try peers(Self.reachable + #","IsJailed":true"#).isEmpty)
        #expect(try peers(Self.reachable + #","SelfNodeV4MasqAddrForThisPeer":"100.64.9.9""#).isEmpty)
        #expect(try peers(Self.reachable + #","SelfNodeV6MasqAddrForThisPeer":"fd7a:115c:a1e0::99""#).isEmpty)
    }

    @Test("같은 접두를 두 노드가 내세우면 node ID가 작은 쪽만 갖는다 (출발 주소는 피어 하나에 묶인다)")
    func prefixHasOneOwner() throws {
        let bob = makeNodeJSON(id: 2, key: makeNodeKey(byte: 2), addresses: ["100.64.0.2/32"], extra: Self.reachable)
        // carol은 자기 주소에 더해 bob의 주소도 AllowedIPs에 내세운다.
        let carol = makeNodeJSON(
            id: 3, key: makeNodeKey(byte: 3), addresses: ["100.64.0.3/32"],
            extra: Self.reachable + #","AllowedIPs":["100.64.0.3/32","100.64.0.2/32"]"#)
        let netmap = try makeNetmap(selfNode: Self.selfNode, peers: [carol, bob])
        let peers = EnginePeer.peers(in: netmap, at: wallClockStart)
        #expect(peers.map(\.key) == [makeNodeKey(byte: 2), makeNodeKey(byte: 3)])
        #expect(peers.map { $0.allowedIPs.map(\.description) } == [["100.64.0.2/32"], ["100.64.0.3/32"]])
    }

    @Test("남의 접두만 내세운 노드와 같은 키를 다시 내세운 노드는 올리지 않는다")
    func duplicateKeyAndOnlyClaimedPrefixes() throws {
        let bob = makeNodeJSON(id: 2, key: makeNodeKey(byte: 2), addresses: ["100.64.0.2/32"], extra: Self.reachable)
        let sameAddress = makeNodeJSON(id: 3, key: makeNodeKey(byte: 3), addresses: ["100.64.0.2/32"], extra: Self.reachable)
        let sameKey = makeNodeJSON(id: 4, key: makeNodeKey(byte: 2), addresses: ["100.64.0.4/32"], extra: Self.reachable)
        let netmap = try makeNetmap(selfNode: Self.selfNode, peers: [sameKey, sameAddress, bob])
        let peers = EnginePeer.peers(in: netmap, at: wallClockStart)
        #expect(peers.map(\.key) == [makeNodeKey(byte: 2)])
        #expect(peers.first?.allowedIPs.map(\.description) == ["100.64.0.2/32"])
    }

    @Test("순서는 node ID 오름차순이다")
    func ordering() throws {
        let nodes = [5, 3, 4].map { id in
            makeNodeJSON(id: Int64(id), key: makeNodeKey(byte: UInt8(id)), addresses: ["100.64.0.\(id)/32"], extra: Self.reachable)
        }
        let netmap = try makeNetmap(selfNode: Self.selfNode, peers: nodes)
        #expect(EnginePeer.peers(in: netmap, at: wallClockStart).map(\.key) == [3, 4, 5].map { makeNodeKey(byte: $0) })
    }
}
