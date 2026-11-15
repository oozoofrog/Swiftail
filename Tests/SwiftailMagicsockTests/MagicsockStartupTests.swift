import Testing

import SwiftailBase
@testable import SwiftailMagicsock

// 실기기 관찰(오래 유휴인 호스트와 방금 켠 터널 사이에 첫 접촉 뒤 25·44초 동안 중계)을 상태 기계로 옮긴 시험이다.
// `docs/contracts/SwiftailMagicsock.md` "직접 경로 지연의 조사 (2026-11-16)".

/// 노드 0("호스트")은 120초 동안 유휴라 주기 STUN이 멈췄고, 노드 1("터널")은 120초에 새로 켜진다. 둘의 홈 지역은 7이다.
/// 호스트는 받은 데이터를 되보낸다. `hostKnowsTunnel`이 nil이면 호스트의 netmap은 터널의 지금 키와 주소를 갖는다.
private func lateStartNetwork(hostKnowsTunnel stale: Magicsock.Peer? = nil) throws -> TestNetwork {
    let host = try TestIdentity(1, address: "192.0.2.1:41641")
    let tunnel = try TestIdentity(2, address: "192.0.2.2:50000")
    var network = try TestNetwork([host, tunnel])
    network.nodes[0].echo = true
    let region = Magicsock.Region(id: 7, stunServers: [network.stunServer])
    network.setPeers(0, [stale ?? tunnel.peer(homeDERP: 7, endpoints: [tunnel.address])])
    network.setRegions(0, [region])
    network.run(until: sockTime(120_000))
    #expect(network.nodes[0].sock.netcheck.nextDeadline == nil, "호스트의 주기 STUN이 멈춰 있어야 한다")

    network.nodes[1].sock = tunnel.magicsock(at: sockTime(120_000))
    network.setPeers(1, [host.peer(homeDERP: 7, endpoints: [host.address])])
    network.setRegions(1, [region])
    return network
}

@Suite("Magicsock 늦게 켠 피어")
struct MagicsockStartupTests {
    @Test("유휴 호스트와 30초 전에 켠 터널: 첫 데이터 뒤 양쪽 CallMeMaybe는 주기 회차를 기다리지 않고 3초 안에, 양쪽 직접은 1초 안에")
    func firstContactAfterIdle() throws {
        // 호스트는 터널의 옛 주소만 안다. 터널의 엔드포인트도 27초보다 낡아 CallMeMaybe가 회차 뒤로 미뤄진다.
        let oldTunnel = try TestIdentity(2, address: "192.0.2.2:49999")
        var network = try lateStartNetwork(hostKnowsTunnel: oldTunnel.peer(homeDERP: 7, endpoints: [oldTunnel.address]))
        let host = network.nodes[0].identity, tunnel = network.nodes[1].identity
        let first = sockTime(150_000)
        network.run(until: first)
        network.sendRepeatedly(from: 1, to: 0, every: .milliseconds(500))
        network.run(until: first + .seconds(30))

        // 노트 4.8 4.1: 낡은 엔드포인트는 곧바로 시작한 회차(최대 3초)가 끝나면 보낸다. 주기 회차(20–26초)를 기다리지 않는다.
        for (from, to) in [(1, 0), (0, 1)] {
            let callMeMaybe = try #require(network.discoLog.first {
                $0.from == from && $0.to == to && $0.time >= first && $0.message.callMeMaybeEndpoints != nil
            })
            #expect(callMeMaybe.time < first + Netcheck.roundTimeout, "노드 \(from)의 CallMeMaybe")
        }
        let tunnelDirect = try #require(network.pathEvents(1, peer: 0).first { $0.path == .direct(host.address) })
        let hostDirect = try #require(network.pathEvents(0, peer: 1).first { $0.path == .direct(tunnel.address) })
        #expect(tunnelDirect.time < first + .seconds(1))
        #expect(hostDirect.time < first + .seconds(1))
        #expect(network.deadlineViolations == 0)
    }

    @Test("호스트가 터널의 옛 disco 키를 쥔 동안은 disco가 버려져 중계로 남고, netmap이 새 키를 주면 그 뒤 1초 안에 양쪽이 직접이 된다")
    func staleDiscoKeyUntilNetmap() throws {
        // 터널은 켤 때마다 새 disco 키를 만든다. 호스트의 netmap은 아직 옛 키(같은 node 키)를 갖는다.
        let tunnel = try TestIdentity(2, address: "192.0.2.2:50000")
        let oldDisco = try TestIdentity(3, address: "192.0.2.2:49999").discoPublicKey
        let stale = Magicsock.Peer(key: tunnel.nodeKey, discoKey: oldDisco, homeDERP: 7, endpoints: [tunnel.address])
        var network = try lateStartNetwork(hostKnowsTunnel: stale)
        let host = network.nodes[0].identity
        let first = sockTime(135_000)
        network.run(until: first)
        network.sendRepeatedly(from: 1, to: 0, every: .milliseconds(500))
        let keyArrives = first + .seconds(25)
        network.run(until: keyArrives)

        // 그동안 데이터는 DERP로 흐르지만 어느 쪽도 직접이 되지 못한다. 호스트는 터널의 disco를 모르는 키로,
        // 터널은 옛 키로 봉한 호스트의 disco를 열지 못해 버린다(노트 4.2 1, 4.10 4).
        #expect(!network.pathEvents(0, peer: 1).contains { if case .direct = $0.path { true } else { false } })
        #expect(!network.pathEvents(1, peer: 0).contains { if case .direct = $0.path { true } else { false } })
        func drops(_ node: Int, _ reason: Magicsock.Drop) -> Int {
            network.log.filter { $0.node == node && $0.time >= first && $0.output == .dropped(reason) }.count
        }
        #expect(drops(0, .unknownDiscoKey) > 0)
        #expect(drops(1, .malformedDisco) > 0)
        #expect(network.received.contains { $0.node == 0 && $0.time < keyArrives && isTestDatagram($0.bytes) })

        network.setPeers(0, [tunnel.peer(homeDERP: 7, endpoints: [tunnel.address])])
        network.run(until: keyArrives + .seconds(10))

        // 새 키는 신뢰와 송신 기록을 지워 호스트의 경로가 잠깐 nil이 된다(노트 4.4 3). 다음 송신이 다시 찾는다.
        #expect(network.pathEvents(0, peer: 1).contains { $0.time == keyArrives && $0.path == nil })
        let hostDirect = try #require(network.pathEvents(0, peer: 1).first { $0.path == .direct(tunnel.address) })
        let tunnelDirect = try #require(network.pathEvents(1, peer: 0).first { $0.path == .direct(host.address) })
        #expect(hostDirect.time < keyArrives + .seconds(1))
        #expect(tunnelDirect.time < keyArrives + .seconds(1))
        #expect(network.deadlineViolations == 0)
    }

    @Test("호스트가 터널의 옛 disco 키를 쥔 채여도 WireGuard 세션이 서며 온 TSMP 광고로 netmap 갱신 없이 1초 안에 양쪽이 직접이 된다")
    func staleDiscoKeyWithAdvertisement() throws {
        let tunnel = try TestIdentity(2, address: "192.0.2.2:50000")
        let oldDisco = try TestIdentity(3, address: "192.0.2.2:49999").discoPublicKey
        let stale = Magicsock.Peer(key: tunnel.nodeKey, discoKey: oldDisco, homeDERP: 7, endpoints: [tunnel.address])
        var network = try lateStartNetwork(hostKnowsTunnel: stale)
        let host = network.nodes[0].identity
        let first = sockTime(135_000)
        network.run(until: first)
        network.sendRepeatedly(from: 1, to: 0, every: .milliseconds(500))
        // 터널의 첫 데이터가 연 WireGuard 핸드셰이크는 DERP로 오간다(initiation·response 각 10 ms). 시작한 터널은
        // response를 받아(+20 ms) 광고를 보내고 호스트가 +30 ms에 받는다. 호스트는 그 광고로 세션을 확인하고 자기
        // 광고를 보내 터널이 +40 ms에 받는다(wireguard-go `device/receive.go`).
        network.run(until: first + .milliseconds(30))
        network.advertiseDiscoKey(from: 1, to: 0)
        network.run(until: first + .milliseconds(40))
        network.advertiseDiscoKey(from: 0, to: 1)
        network.run(until: first + .seconds(10))

        #expect(network.nodes[0].sock.peers[tunnel.nodeKey]?.discoKey == tunnel.discoPublicKey)
        let hostDirect = try #require(network.pathEvents(0, peer: 1).first { $0.path == .direct(tunnel.address) })
        let tunnelDirect = try #require(network.pathEvents(1, peer: 0).first { $0.path == .direct(host.address) })
        #expect(hostDirect.time < first + .seconds(1))
        #expect(tunnelDirect.time < first + .seconds(1))
        #expect(network.deadlineViolations == 0)
    }
}
