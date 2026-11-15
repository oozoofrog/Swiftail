import Testing

import SwiftailBase
@testable import SwiftailMagicsock

// TSMP disco 키 광고의 독립 검토 시험(magicsock 쪽). 한 피어가 광고로 바꿀 수 있는 범위를 Go와 견준다.
// 기준: tailscale.com v1.104.7 `wgengine/magicsock/magicsock.go`(`HandleDiscoKeyAdvertisement`,
// `unambiguousNodeKeyOfPingLocked`, `handlePingLocked`), `peermap.go`(`upsertEndpoint`, `nodesOfDisco`는 키 하나에
// node 여럿을 담는 집합이다). BSD-3-Clause.

@Suite("검토: 다른 피어가 먼저 광고한 disco 키")
struct DiscoKeyAdvertisementReviewTests {
    let a: TestIdentity
    /// 다시 켜져 새 disco 키를 쓰는 정직한 피어.
    let b: TestIdentity
    /// b의 새 disco 키를 알게 된 악의적인 피어(같은 tailnet, WireGuard로 인증됨).
    let c: TestIdentity
    /// b가 다시 켜진 뒤의 disco 키. node 키는 b의 것을 따로 쓴다.
    let restartedB: TestIdentity

    init() throws {
        a = try TestIdentity(1, address: "192.0.2.1:41641")
        b = try TestIdentity(2, address: "192.0.2.2:41641")
        c = try TestIdentity(3, address: "192.0.2.3:41641")
        restartedB = try TestIdentity(9, address: "192.0.2.2:41641")
    }

    /// a의 netmap에는 b의 옛 disco 키만 있다(netmap 갱신이 늦다). c가 b보다 먼저 b의 새 키를 광고한다.
    private func squatted() -> Magicsock {
        var sock = a.magicsock()
        _ = sock.setPeers([b.peer(endpoints: [b.address]), c.peer(endpoints: [c.address])], at: sockT0)
        _ = sock.receiveDiscoKeyAdvertisement(restartedB.discoPublicKey, from: c.nodeKey, at: sockTime(1))
        return sock
    }

    @Test("c가 먼저 b의 새 키를 광고하면 b 자신의 광고가 거절된다(Go는 둘 다 받아 b의 활성 키가 새 키가 된다)")
    func ownerAdvertisementIsRejectedAfterSquat() {
        var sock = squatted()
        _ = sock.receiveDiscoKeyAdvertisement(restartedB.discoPublicKey, from: b.nodeKey, at: sockTime(2))
        withKnownIssue("동작 T5: TSMP 키도 먼저 쥔 피어의 것이라, 키를 아는 다른 피어가 b의 광고를 막을 수 있다") {
            #expect(sock.peers[b.nodeKey]?.discoKey == restartedB.discoPublicKey)
        }
    }

    @Test("그 뒤 b가 새 키로 봉해 UDP로 보낸 Ping(node 키 = b)이 b의 활성 키를 바꾸지 못한다")
    func ownersPingIsAttributedToSquatter() throws {
        var sock = squatted()
        var random = PathTestRandom(state: 11)
        _ = sock.receiveDiscoKeyAdvertisement(restartedB.discoPublicKey, from: b.nodeKey, at: sockTime(2))
        let txID = try #require(TransactionID([UInt8](repeating: 5, count: 12)))
        let ping = try restartedB.seal(.ping(txID, nodeKey: b.nodeKey), to: a.discoPublicKey)
        _ = sock.receiveUDP(ping, from: b.address, at: sockTime(3), using: &random)
        // Go와 같은 점: 그 키를 쥔 c도 b의 주소를 후보로 얻는다(`handlePingLocked`의 `forEachEndpointWithDiscoKey`).
        #expect(sock.peers[c.nodeKey]?.path.candidates.contains { $0.address == b.address } == true)
        // Go: b도 그 키를 쥐고 있어 Ping의 node 키로 b를 확정한다(`unambiguousNodeKeyOfPingLocked`). b의 후보는 netmap
        // 엔드포인트로 이미 있으므로 보지 않는다.
        withKnownIssue("키를 먼저 쥔 c 하나에게만 가서, b는 새 키로 경로를 찾지 못한다") {
            #expect(sock.peers[b.nodeKey]?.discoKey == restartedB.discoPublicKey)
        }
    }

    @Test("c의 경로가 b의 주소로 직접이 된다: a가 c에게 보내는 WireGuard가 b에게 간다(Go도 같다. c는 자기 트래픽만 잃는다)")
    func squatterPathPointsAtOwner() throws {
        var sock = squatted()
        var random = PathTestRandom(state: 11)
        let txID = try #require(TransactionID([UInt8](repeating: 5, count: 12)))
        let ping = try restartedB.seal(.ping(txID, nodeKey: b.nodeKey), to: a.discoPublicKey)
        _ = sock.receiveUDP(ping, from: b.address, at: sockTime(3), using: &random)

        // a가 c에게 데이터를 보내면 c의 활성 키(= b의 새 키)로 봉한 Ping이 b의 주소로도 간다. b는 열 수 있으므로 답한다.
        let sent = sock.send(testDatagram(1), to: c.nodeKey, at: sockTime(4), using: &random)
        let pingToB = try #require(sent.compactMap(\.discoPacket).first { $0.udp == b.address })
        guard case .ping(let id, _) = try restartedB.open(pingToB.bytes) else {
            Issue.record("b가 열 수 있는 Ping이 아니다")
            return
        }
        let pong = try restartedB.seal(.pong(id, source: a.address), to: a.discoPublicKey, nonce: 2)
        let outputs = sock.receiveUDP(pong, from: b.address, at: sockTime(5), using: &random)
        // Go도 Pong을 그 키의 모든 피어에게 묻고(`forEachEndpointWithDiscoKey`) TxID가 맞는 c의 경로가 된다.
        #expect(outputs.contains(.pathChanged(c.nodeKey, .direct(b.address))))
    }

    @Test("netmap이 b의 새 키를 주면 회복한다: b가 netmap 키로 갖고 c는 TSMP 키를 잃는다")
    func recoversOnNetmap() {
        var sock = squatted()
        var newB = b.peer(endpoints: [b.address])
        newB.discoKey = restartedB.discoPublicKey
        _ = sock.setPeers([newB, c.peer(endpoints: [c.address])], at: sockTime(10))
        #expect(sock.peers[b.nodeKey]?.discoKey == restartedB.discoPublicKey)
        #expect(sock.discoPeers[restartedB.discoPublicKey]?.node == b.nodeKey)
        #expect(sock.peers[c.nodeKey]?.discoKey == c.discoPublicKey)
    }

    @Test("한 피어가 키를 계속 바꿔 광고해도 표는 피어마다 키 둘을 넘지 않는다(Go도 옛 TSMP 키를 지운다)")
    func rotatingAdvertisementsAreBounded() throws {
        var sock = a.magicsock()
        _ = sock.setPeers([b.peer(endpoints: [b.address])], at: sockT0)
        for seed in UInt8(20)..<UInt8(120) {
            let rotated = try TestIdentity(seed, address: "192.0.2.2:41641")
            _ = sock.receiveDiscoKeyAdvertisement(rotated.discoPublicKey, from: b.nodeKey, at: sockTime(Int64(seed)))
        }
        #expect(sock.discoPeers.count == 2)
        #expect(sock.peers[b.nodeKey]?.discoKeys.netmap == b.discoPublicKey)
    }
}
