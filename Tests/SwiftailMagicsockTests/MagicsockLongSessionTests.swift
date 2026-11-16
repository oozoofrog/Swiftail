import Testing

import SwiftailBase
@testable import SwiftailMagicsock

// 실기기 관측(같은 Wi-Fi, 내려받는 단말 쪽에서 direct가 선 뒤 약 100초에 `relayed`, 5.8초 뒤 `direct`)을 상태 기계로
// 옮긴 시험이다. `docs/contracts/SwiftailMagicsock.md` "direct가 선 뒤 약 100초에 `relayed`"의 "조사 결과".

/// netmap이 주기적으로 오는 모양.
enum NetmapRefresh: CaseIterable, Sendable {
    /// 처음 한 번뿐이다.
    case none
    /// 30초마다 같은 목록이 온다.
    case same
    /// 30초마다 상대의 엔드포인트 목록이 바뀐다(닿지 않는 주소가 더해지고 빠지며 순서가 바뀐다). 닿는 주소는 늘 있다.
    case changing
    /// 단말의 netmap에는 호스트의 닿는 주소가 없고, 호스트는 자기 엔드포인트를 몰라(STUN 지역 없음) CallMeMaybe를 보내지 못한다.
    /// 단말은 호스트가 보낸 Ping의 출처로만 그 주소를 배운다(마지막 Ping 뒤 45초에 지우는 후보).
    case pingLearned
}

/// 노드 0("호스트")은 내려받기를 보내고, 노드 1("단말")은 받으며 ACK 꼴로 드물게 보낸다. 같은 LAN이고 홈 지역은 7이다.
private struct DownloadSession {
    var network: TestNetwork
    let host: TestIdentity
    let phone: TestIdentity
    let refresh: NetmapRefresh
    private let unreachable: [IPEndpoint]
    private var refreshCount = 0

    init(latency: Duration, refresh: NetmapRefresh) throws {
        host = try TestIdentity(1, address: "192.168.1.10:41641")
        phone = try TestIdentity(2, address: "192.168.1.20:50000")
        unreachable = [try #require(IPEndpoint("203.0.113.9:41641")), try #require(IPEndpoint("203.0.113.10:41641"))]
        self.refresh = refresh
        network = try TestNetwork([host, phone])
        network.udpLatency = latency
        let region = Magicsock.Region(id: 7, stunServers: [network.stunServer])
        applyNetmap()
        if refresh != .pingLearned {
            network.setRegions(0, [region])
        }
        network.setRegions(1, [region])
    }

    /// 지금 netmap을 두 노드에 넣는다. `changing`이면 부를 때마다 목록이 바뀐다.
    mutating func applyNetmap() {
        var hostEndpoints = [host.address], phoneEndpoints = [phone.address]
        switch refresh {
        case .none, .same:
            break
        case .changing:
            if refreshCount % 2 == 1 {
                hostEndpoints = [unreachable[0], host.address, unreachable[1]]
                phoneEndpoints = [unreachable[1], phone.address]
            }
        case .pingLearned:
            hostEndpoints = [unreachable[0]]
        }
        refreshCount += 1
        network.setPeers(0, [phone.peer(homeDERP: 7, endpoints: phoneEndpoints)])
        network.setPeers(1, [host.peer(homeDERP: 7, endpoints: hostEndpoints)])
    }

    /// `seconds` 동안 돌린다. `refresh`가 `.none`이 아니면 30초마다 netmap을 다시 넣는다.
    mutating func run(seconds: Int64) {
        let end = network.now + .seconds(seconds)
        while refresh != .none, nextRefresh <= end {
            network.run(until: nextRefresh)
            applyNetmap()
        }
        network.run(until: end)
    }

    private var nextRefresh: ContinuousClock.Instant {
        sockT0 + .seconds(30 * Int64(refreshCount))
    }

    /// 내려받기 하나: 단말의 요청 하나, 그 뒤 `seconds` 동안 호스트는 20 ms마다, 단말은 100 ms마다 보낸다.
    mutating func download(seconds: Int64) {
        network.send(from: 1, to: 0)
        network.sendRepeatedly(from: 0, to: 1, every: .milliseconds(20))
        network.sendRepeatedly(from: 1, to: 0, every: .milliseconds(100))
        run(seconds: seconds)
        network.sendRepeatedly(from: 0, to: 1, every: nil)
        network.sendRepeatedly(from: 1, to: 0, every: nil)
    }

    /// 노드 `node`가 낸 상대의 경로 사건.
    func events(_ node: Int) -> [(time: ContinuousClock.Instant, path: PeerPath?)] {
        network.pathEvents(node, peer: 1 - node)
    }

    /// 단말이 UDP로 받은 호스트의 Pong 시각.
    var pongsAtPhone: [ContinuousClock.Instant] {
        network.discoLog.filter { $0.from == 0 && $0.to == 1 && !$0.viaDERP && $0.message.isPong }.map(\.time)
    }
}

@Suite("Magicsock 긴 세션")
struct MagicsockLongSessionTests {
    @Test(
        "300초 동안 26초 내려받기와 42초 유휴를 되풀이해도 한 번 direct가 된 뒤에는 relayed도 nil도 나오지 않는다",
        arguments: [2, 10, 30], NetmapRefresh.allCases
    )
    func repeatedDownloads(latencyMilliseconds: Int, refresh: NetmapRefresh) throws {
        var session = try DownloadSession(latency: .milliseconds(Int64(latencyMilliseconds)), refresh: refresh)
        session.run(seconds: 1)
        while session.network.now < sockT0 + .seconds(270) {
            session.download(seconds: 26)
            session.run(seconds: 42)
        }
        session.download(seconds: 26)

        for node in [0, 1] {
            let events = session.events(node)
            let firstDirect = try #require(events.firstIndex { if case .direct = $0.path { true } else { false } }, "노드 \(node)")
            #expect(events[firstDirect].time < sockT0 + .seconds(2), "노드 \(node)의 첫 direct")
            let later = events[(firstDirect + 1)...].map(\.path)
            #expect(later.allSatisfy { if case .direct = $0 { true } else { false } }, "노드 \(node): \(later)")
        }
        if refresh == .pingLearned {
            let learned = session.network.nodes[1].sock.peers[session.host.nodeKey]?.path.candidates.first { $0.address == session.host.address }
            #expect(learned?.lastPingReceived != nil && learned?.fromCallMeMaybe == false, "단말의 bestAddr는 Ping으로 배운 후보여야 한다")
        }
        #expect(session.network.deadlineViolations == 0)
    }

    /// Go와 같은 규칙이다: heartbeat는 3초마다 `bestAddr`에 Ping하고(`endpoint.go:926-930`), Pong이 신뢰를 6.5초 늘리며
    /// (`:2003-2019`), 신뢰가 지나면 DERP로도 보낸다(`:635-652`). 그래서 받는 쪽이 Pong을 연달아 둘 잃으면 마지막 Pong
    /// 뒤 6.5초(heartbeat 시각 + 0.5초 + 왕복 지연)에 relayed가 되고, Pong이 다시 오는 첫 Ping에 direct로 돌아온다.
    @Test("내려받는 동안 호스트의 Pong이 끊기면 마지막 Pong 뒤 6.5초에 relayed(신뢰 만료), 끊김이 끝난 뒤 5초 안의 Ping에 direct")
    func pongLossDuringDownload() throws {
        var session = try DownloadSession(latency: .milliseconds(10), refresh: .none)
        session.run(seconds: 1)
        session.download(seconds: 74)
        // 측정 1처럼 내려받기가 이어지는 동안 heartbeat 셋의 Pong(약 9초)을 잃는다.
        let lossStart = session.network.now, lossEnd = lossStart + .seconds(9)
        session.network.pongLoss = (from: 0, during: lossStart..<lossEnd)
        session.download(seconds: 26)

        let events = session.events(1).filter { $0.time >= lossStart }
        #expect(events.count == 2, "\(events)")
        let relayed = try #require(events.first)
        #expect(relayed.path == .relayed(derpRegion: 7))
        let lastPong = try #require(session.pongsAtPhone.last { $0 < relayed.time })
        #expect(relayed.time == lastPong + PeerPathState.trustDuration + .nanoseconds(1))
        let recovered = try #require(events.last)
        #expect(recovered.path == .direct(session.host.address))
        #expect(recovered.time == session.pongsAtPhone.first { $0 >= lossEnd })
        #expect(recovered.time <= lossEnd + PeerPathState.pingInterval + .milliseconds(20))
        // 호스트 쪽은 단말의 Pong을 받으므로 direct 그대로다.
        #expect(session.events(0).allSatisfy { $0.time < lossStart })
        #expect(session.network.deadlineViolations == 0)
    }

    @Test("경로가 나빠진 까닭: 신뢰 만료, 후보 지움, 재결속, disco 키 바뀜, 유휴, 피어 빠짐")
    func downgradeCauses() throws {
        var session = try DownloadSession(latency: .milliseconds(10), refresh: .none)
        let host = session.host.nodeKey
        session.run(seconds: 1)
        session.network.sendRepeatedly(from: 1, to: 0, every: .milliseconds(100))
        session.run(seconds: 2)
        #expect(session.network.nodes[1].sock.path(to: host, at: session.network.now) == .direct(session.host.address))
        #expect(session.network.nodes[1].sock.downgrade(of: host) == nil)

        // 신뢰 만료: 호스트의 Pong을 잃는다.
        session.network.pongLoss = (from: 0, during: session.network.now..<(session.network.now + .seconds(10)))
        session.run(seconds: 9)
        #expect(session.network.nodes[1].sock.path(to: host, at: session.network.now) == .relayed(derpRegion: 7))
        #expect(session.network.nodes[1].sock.downgrade(of: host) == .trustExpired)
        session.run(seconds: 8)
        #expect(session.network.nodes[1].sock.downgrade(of: host) == nil, "direct로 돌아오면 까닭이 없다")

        // 후보 지움: netmap이 `bestAddr`인 netmap 후보를 뺀다.
        let elsewhere = try #require(IPEndpoint("203.0.113.9:41641"))
        session.network.setPeers(1, [session.host.peer(homeDERP: 7, endpoints: [elsewhere])])
        #expect(session.network.nodes[1].sock.path(to: host, at: session.network.now) == .relayed(derpRegion: 7))
        #expect(session.network.nodes[1].sock.downgrade(of: host) == .candidateRemoved)
        session.network.setPeers(1, [session.host.peer(homeDERP: 7, endpoints: [session.host.address])])
        session.run(seconds: 6)

        // 재결속.
        var random = PathTestRandom(state: 9)
        _ = session.network.nodes[1].sock.rebind(
            localPort: session.phone.address.port, localAddresses: [], loopbackAddresses: [],
            at: session.network.now, using: &random
        )
        #expect(session.network.nodes[1].sock.downgrade(of: host) == .rebind)
        session.run(seconds: 6)
        #expect(session.network.nodes[1].sock.path(to: host, at: session.network.now) == .direct(session.host.address))

        // disco 키 바뀜: 처음 온 TSMP 광고는 netmap 키와 같아도 경로를 다시 찾게 한다(Go와 같다). 송신 기록이 지워져 nil이다.
        session.network.advertiseDiscoKey(from: 0, to: 1)
        #expect(session.network.nodes[1].sock.path(to: host, at: session.network.now) == nil)
        #expect(session.network.nodes[1].sock.downgrade(of: host) == .discoKeyChanged)

        // 유휴: 마지막 송신 뒤 45초.
        session.run(seconds: 1)
        session.network.sendRepeatedly(from: 1, to: 0, every: nil)
        session.run(seconds: 46)
        #expect(session.network.nodes[1].sock.path(to: host, at: session.network.now) == nil)
        #expect(session.network.nodes[1].sock.downgrade(of: host) == .idle)

        // 피어 빠짐.
        session.network.setPeers(1, [])
        #expect(session.network.nodes[1].sock.downgrade(of: host) == .peerRemoved)
    }
}
