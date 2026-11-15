import CryptoKit
import Testing

import SwiftailBase
@testable import SwiftailMagicsock

// TSMP disco 키 광고를 받았을 때의 활성 키 판정(계약 "TSMP disco 키 광고" 동작 T3~T5).
// 기대값은 tailscale.com v1.104.7 `wgengine/magicsock/endpoint.go`(`updateDiscoKey`, `updateTSMPDiscoKey`,
// `checkAndUpdateDiscoKey`)와 `magicsock.go`(`HandleDiscoKeyAdvertisement`, BSD-3-Clause)에서 정했다.

private func discoKey(_ byte: UInt8) -> DiscoPublicKey {
    DiscoPublicKey(rawValue: [UInt8](repeating: byte, count: 32))!
}

@Suite("PeerDiscoKeys 활성 키 판정표")
struct PeerDiscoKeysTests {
    let control = discoKey(0xC1)
    let newer = discoKey(0xC2)
    let tsmp = discoKey(0x71)

    @Test("netmap 키만 있으면 그것이 활성이고, 같은 키가 다시 오면 바뀌지 않는다")
    func netmapOnly() {
        var keys = PeerDiscoKeys()
        #expect(keys.active == nil)
        let result1 = keys.updateNetmap(nil)
        #expect(result1 == false)
        let result2 = keys.updateNetmap(control)
        #expect(result2)
        #expect(keys.active == control)
        let result3 = keys.updateNetmap(control)
        #expect(result3 == false)
        let result4 = keys.updateNetmap(newer)
        #expect(result4)
        #expect(keys.active == newer)
    }

    @Test("TSMP 광고가 오면 그 키가 활성이 된다. 같은 키가 다시 오면 바뀌지 않는다")
    func tsmpWins() {
        var keys = PeerDiscoKeys()
        _ = keys.updateNetmap(control)
        let result5 = keys.updateTSMP(tsmp)
        #expect(result5)
        #expect(keys.active == tsmp)
        let result6 = keys.updateTSMP(tsmp)
        #expect(result6 == false)
        #expect(keys.netmap == control)
    }

    @Test("처음 온 광고가 netmap 키와 같아도 Go처럼 바뀐 것으로 본다(경로를 다시 찾는다)")
    func firstAdvertisementEqualToNetmap() {
        var keys = PeerDiscoKeys()
        _ = keys.updateNetmap(control)
        let result7 = keys.updateTSMP(control)
        #expect(result7)
        #expect(keys.active == control)
        #expect(keys.tsmpActive)
        let result8 = keys.updateTSMP(control)
        #expect(result8 == false)
    }

    @Test("TSMP 키가 활성이면 netmap이 나중에 다른 키를 줘도 활성은 TSMP 키다. 바뀐 것으로는 본다")
    func netmapLaterWithDifferentKey() {
        var keys = PeerDiscoKeys()
        _ = keys.updateNetmap(control)
        _ = keys.updateTSMP(tsmp)
        let result9 = keys.updateNetmap(newer)
        #expect(result9)
        #expect(keys.active == tsmp)
        #expect(keys.netmap == newer)
    }

    @Test("netmap이 나중에 TSMP와 같은 키를 주면(따라잡음) 활성은 그대로고 바뀐 것으로 본다")
    func netmapCatchesUp() {
        var keys = PeerDiscoKeys()
        _ = keys.updateNetmap(control)
        _ = keys.updateTSMP(tsmp)
        let result10 = keys.updateNetmap(tsmp)
        #expect(result10)
        #expect(keys.active == tsmp)
    }

    @Test("netmap보다 먼저 온 광고: 활성은 TSMP 키이고, 뒤에 온 netmap 키는 활성을 바꾸지 않는다")
    func tsmpBeforeNetmap() {
        var keys = PeerDiscoKeys()
        let result11 = keys.updateTSMP(tsmp)
        #expect(result11)
        #expect(keys.active == tsmp)
        let result12 = keys.updateNetmap(control)
        #expect(result12)
        #expect(keys.active == tsmp)
    }

    @Test("TSMP가 netmap보다 낡은 키를 줘도 TSMP 키가 활성이다(Go는 순서를 따지지 않는다)")
    func staleAdvertisement() {
        var keys = PeerDiscoKeys()
        _ = keys.updateNetmap(newer)
        let result13 = keys.updateTSMP(control)
        #expect(result13)
        #expect(keys.active == control)
    }

    @Test("비활성 키로 온 disco를 보면 활성을 그쪽으로 바꾼다. 그 뒤 같은 광고는 되돌리지 않는다")
    func seenInactiveKey() {
        var keys = PeerDiscoKeys()
        _ = keys.updateNetmap(control)
        _ = keys.updateTSMP(tsmp)
        let result14 = keys.noteSeen(tsmp)
        #expect(result14 == (true, false))
        let result15 = keys.noteSeen(newer)
        #expect(result15 == (false, false))
        let result16 = keys.noteSeen(control)
        #expect(result16 == (true, true))
        #expect(keys.active == control)
        let result17 = keys.updateTSMP(tsmp)
        #expect(result17 == false)
        #expect(keys.active == control)
        let result18 = keys.noteSeen(tsmp)
        #expect(result18 == (true, true))
        #expect(keys.active == tsmp)
    }

    @Test("netmap 키가 없어지면 TSMP 키가 활성이고, 둘 다 없어지면 disco를 하지 않는다")
    func keysRemoved() {
        var keys = PeerDiscoKeys()
        _ = keys.updateNetmap(control)
        _ = keys.updateTSMP(tsmp)
        _ = keys.noteSeen(control)
        let result19 = keys.updateNetmap(nil)
        #expect(result19)
        #expect(keys.active == tsmp)
        let result20 = keys.updateTSMP(nil)
        #expect(result20)
        #expect(keys.active == nil)
        #expect(keys == PeerDiscoKeys())
    }
}

@Suite("Magicsock TSMP disco 키 광고 받기")
struct MagicsockDiscoAdvertisementTests {
    let a: TestIdentity
    let b: TestIdentity
    let c: TestIdentity
    /// b가 다시 켜져 만든 새 disco 키. 봉하기·열기에만 쓰므로 node 키는 보지 않는다(b의 node 키를 따로 넘긴다).
    let restartedB: TestIdentity

    init() throws {
        a = try TestIdentity(1, address: "192.0.2.1:41641")
        b = try TestIdentity(2, address: "192.0.2.2:41641")
        c = try TestIdentity(3, address: "192.0.2.3:41641")
        restartedB = try TestIdentity(9, address: "192.0.2.2:41641")
    }

    private func makeSock(peers: [Magicsock.Peer]) -> Magicsock {
        var sock = a.magicsock()
        _ = sock.setPeers(peers, at: sockT0)
        return sock
    }

    /// `peer`에게 데이터를 보내 Ping을 내고, Pong을 돌려 직접 경로를 세운다.
    private func establishDirect(_ sock: inout Magicsock, with peer: TestIdentity, at time: ContinuousClock.Instant, random: inout PathTestRandom) throws {
        let outputs = sock.send(testDatagram(1), to: peer.nodeKey, at: time, using: &random)
        let ping = try #require(outputs.compactMap(\.discoPacket).first { $0.udp == peer.address })
        guard case .ping(let id, _) = try peer.open(ping.bytes) else {
            Issue.record("Ping이 아니다")
            return
        }
        let pong = try peer.seal(.pong(id, source: a.address), to: a.discoPublicKey)
        #expect(sock.receiveUDP(pong, from: peer.address, at: time + .milliseconds(2), using: &random)
            == [.pathChanged(peer.nodeKey, .direct(peer.address))])
    }

    @Test("광고된 새 키로 봉한 disco를 netmap 갱신 없이 받고, 그 키로 봉해 답한다. 옛 netmap 키도 계속 안다")
    func advertisedKeyIsUsed() throws {
        var sock = makeSock(peers: [b.peer(endpoints: [b.address])])
        var random = PathTestRandom(state: 7)
        let ping = try restartedB.seal(.ping(try #require(TransactionID([UInt8](repeating: 1, count: 12))), nodeKey: b.nodeKey), to: a.discoPublicKey)
        #expect(sock.receiveUDP(ping, from: b.address, at: sockTime(1), using: &random) == [.dropped(.unknownDiscoKey)])

        #expect(sock.receiveDiscoKeyAdvertisement(restartedB.discoPublicKey, from: b.nodeKey, at: sockTime(2)).isEmpty)
        #expect(sock.peers[b.nodeKey]?.discoKey == restartedB.discoPublicKey)
        #expect(Set(sock.discoPeers.keys) == [b.discoPublicKey, restartedB.discoPublicKey])

        let outputs = sock.receiveUDP(ping, from: b.address, at: sockTime(3), using: &random)
        let pong = try #require(outputs.compactMap(\.discoPacket).first { $0.udp == b.address })
        guard case .pong = try restartedB.open(pong.bytes) else {
            Issue.record("Pong이 아니다")
            return
        }
        // 보내는 Ping도 새 키로 봉한다.
        let sent = sock.send(testDatagram(2), to: b.nodeKey, at: sockTime(4), using: &random)
        let newPing = try #require(sent.compactMap(\.discoPacket).first { $0.udp == b.address })
        guard case .ping = try restartedB.open(newPing.bytes) else {
            Issue.record("새 키로 열리지 않는다")
            return
        }
    }

    @Test("활성 키가 바뀌면 신뢰와 진행 중인 Ping을 지운다. 같은 광고가 다시 오면 아무것도 하지 않는다")
    func advertisementResetsPath() throws {
        var sock = makeSock(peers: [b.peer(endpoints: [b.address])])
        var random = PathTestRandom(state: 7)
        try establishDirect(&sock, with: b, at: sockT0, random: &random)
        #expect(sock.receiveDiscoKeyAdvertisement(restartedB.discoPublicKey, from: b.nodeKey, at: sockTime(10))
            == [.pathChanged(b.nodeKey, nil)])
        #expect(sock.peers[b.nodeKey]?.path.trustedUntil == nil)
        #expect(sock.peers[b.nodeKey]?.path.sentPings.isEmpty == true)
        #expect(sock.receiveDiscoKeyAdvertisement(restartedB.discoPublicKey, from: b.nodeKey, at: sockTime(11)).isEmpty)

        // 그다음 TSMP 키가 다시 바뀌면 앞의 TSMP 키는 잊는다(netmap 키는 남는다).
        let third = try TestIdentity(10, address: "192.0.2.2:41641")
        _ = sock.receiveDiscoKeyAdvertisement(third.discoPublicKey, from: b.nodeKey, at: sockTime(12))
        #expect(Set(sock.discoPeers.keys) == [b.discoPublicKey, third.discoPublicKey])
    }

    @Test("0 키, 모르는 피어의 광고는 아무것도 바꾸지 않는다")
    func ignoredAdvertisements() {
        var sock = makeSock(peers: [b.peer(endpoints: [b.address])])
        #expect(sock.receiveDiscoKeyAdvertisement(.zero, from: b.nodeKey, at: sockTime(1)).isEmpty)
        #expect(sock.receiveDiscoKeyAdvertisement(restartedB.discoPublicKey, from: c.nodeKey, at: sockTime(1)).isEmpty)
        #expect(sock.peers[b.nodeKey]?.discoKeys == {
            var keys = PeerDiscoKeys()
            _ = keys.updateNetmap(b.discoPublicKey)
            return keys
        }())
        #expect(Array(sock.discoPeers.keys) == [b.discoPublicKey])
    }

    @Test("광고는 보낸 피어의 키만 바꾼다. 다른 피어가 쓰는 disco 키를 광고하면 받지 않는다(동작 B1)")
    func advertisingAnotherPeersKey() throws {
        var sock = makeSock(peers: [b.peer(endpoints: [b.address]), c.peer(endpoints: [c.address])])
        var random = PathTestRandom(state: 7)
        try establishDirect(&sock, with: b, at: sockT0, random: &random)
        #expect(sock.receiveDiscoKeyAdvertisement(b.discoPublicKey, from: c.nodeKey, at: sockTime(10)).isEmpty)
        #expect(sock.discoPeers[b.discoPublicKey]?.node == b.nodeKey)
        #expect(sock.peers[c.nodeKey]?.discoKey == c.discoPublicKey)
        #expect(sock.path(to: b.nodeKey, at: sockTime(10)) == .direct(b.address))

        // b가 TSMP로 쥔 키도 같다: c가 그 키를 광고해도 b의 것이다.
        _ = sock.receiveDiscoKeyAdvertisement(restartedB.discoPublicKey, from: b.nodeKey, at: sockTime(11))
        #expect(sock.receiveDiscoKeyAdvertisement(restartedB.discoPublicKey, from: c.nodeKey, at: sockTime(12)).isEmpty)
        #expect(sock.discoPeers[restartedB.discoPublicKey]?.node == b.nodeKey)
        #expect(sock.peers[c.nodeKey]?.discoKey == c.discoPublicKey)
    }

    @Test("netmap 갱신은 TSMP 키를 남긴다. 다른 피어가 netmap 키로 그 키를 가져가면 TSMP 키를 잃는다")
    func netmapKeepsTSMPKey() {
        var sock = makeSock(peers: [b.peer(endpoints: [b.address]), c.peer(endpoints: [c.address])])
        _ = sock.receiveDiscoKeyAdvertisement(restartedB.discoPublicKey, from: b.nodeKey, at: sockTime(1))
        _ = sock.setPeers([b.peer(endpoints: [b.address]), c.peer(endpoints: [c.address])], at: sockTime(2))
        #expect(sock.peers[b.nodeKey]?.discoKey == restartedB.discoPublicKey)
        #expect(sock.discoPeers[restartedB.discoPublicKey]?.node == b.nodeKey)

        var cWithThatKey = c.peer(endpoints: [c.address])
        cWithThatKey.discoKey = restartedB.discoPublicKey
        _ = sock.setPeers([b.peer(endpoints: [b.address]), cWithThatKey], at: sockTime(3))
        #expect(sock.discoPeers[restartedB.discoPublicKey]?.node == c.nodeKey)
        #expect(sock.peers[b.nodeKey]?.discoKey == b.discoPublicKey)
    }

    @Test("DERP로 온 CallMeMaybe가 비활성 키로 봉했으면 받고 활성을 그 키로 바꾼다")
    func callMeMaybeFromInactiveKey() throws {
        var sock = makeSock(peers: [b.peer(endpoints: [b.address]), c.peer(endpoints: [c.address])])
        var random = PathTestRandom(state: 7)
        _ = sock.receiveDiscoKeyAdvertisement(restartedB.discoPublicKey, from: b.nodeKey, at: sockTime(1))
        let callMeMaybe = try b.seal(.callMeMaybe([b.address]), to: a.discoPublicKey)
        let outputs = sock.receiveDERP(callMeMaybe, from: b.nodeKey, region: 1, at: sockTime(2), using: &random)
        #expect(!outputs.contains(.dropped(.misroutedDisco)))
        #expect(sock.peers[b.nodeKey]?.discoKey == b.discoPublicKey)
        // DERP 보낸 쪽의 키가 아닌 것(다른 피어의 키)으로 봉한 CallMeMaybe는 여전히 버린다.
        let stranger = try c.seal(.callMeMaybe([c.address]), to: a.discoPublicKey)
        #expect(sock.receiveDERP(stranger, from: b.nodeKey, region: 1, at: sockTime(3), using: &random) == [.dropped(.misroutedDisco)])
    }

    @Test("UDP로 온 Ping의 node 키가 그 피어면 비활성 키여도 활성을 바꾼다. node 키가 다르면 바꾸지 않는다")
    func pingFromInactiveKey() throws {
        var sock = makeSock(peers: [b.peer(endpoints: [b.address])])
        var random = PathTestRandom(state: 7)
        _ = sock.receiveDiscoKeyAdvertisement(restartedB.discoPublicKey, from: b.nodeKey, at: sockTime(1))
        let txID = try #require(TransactionID([UInt8](repeating: 2, count: 12)))
        let withoutNodeKey = try b.seal(.ping(txID, nodeKey: nil), to: a.discoPublicKey)
        _ = sock.receiveUDP(withoutNodeKey, from: b.address, at: sockTime(2), using: &random)
        #expect(sock.peers[b.nodeKey]?.discoKey == restartedB.discoPublicKey)
        let withNodeKey = try b.seal(.ping(txID, nodeKey: b.nodeKey), to: a.discoPublicKey, nonce: 2)
        _ = sock.receiveUDP(withNodeKey, from: b.address, at: sockTime(3), using: &random)
        #expect(sock.peers[b.nodeKey]?.discoKey == b.discoPublicKey)
    }
}
