// 계약 시험 3: 피어별 경로 상태 기계. 시각을 직접 넘겨 결정적으로 돈다.
//
// 기대값은 `docs/protocol-notes/disco-magicsock.md` 4.4~4.8·5절과 그 출처인 Go 구현에서 정했다.
// 출처: tailscale.com v1.104.6 `wgengine/magicsock/endpoint.go` (`betterAddr`, `heartbeat`, `wantFullPingLocked`,
// `sendDiscoPingsLocked`, `discoPingTimeout`, `handlePongConnLocked`, `handleCallMeMaybe`, `shouldDeleteLocked`).
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import Testing

import SwiftailBase
@testable import SwiftailMagicsock

@Suite("PeerPathState")
struct PeerPathStateTests {
    // MARK: 후보

    @Test("netmap 후보는 IPv4만, IPv4-mapped는 풀고, 포트 0과 중복은 버린다")
    func netmapCandidates() throws {
        let lan = try pathEndpoint("192.168.1.10:41641")
        let mapped = try pathEndpoint("[::ffff:10.0.0.5]:41641")
        let state = PeerPathState(homeDERP: 1, endpoints: [
            lan,
            try pathEndpoint("[2001:db8::1]:41641"),
            try pathEndpoint("[fe80::1]:41641"),
            mapped,
            lan,
            try pathEndpoint("10.0.0.9:0"),
        ])
        #expect(state.candidates.map(\.address) == [lan, try pathEndpoint("10.0.0.5:41641")])
    }

    @Test("첫 송신은 DERP로 보내며 모든 후보에 Ping하고 CallMeMaybe를 낸다")
    func firstSendGoesOverDERPAndStartsDiscovery() throws {
        let a = try pathEndpoint("192.168.1.10:41641")
        let b = try pathEndpoint("203.0.113.7:41641")
        var state = PeerPathState(homeDERP: 7, endpoints: [a, b])
        var random = PathTestRandom(state: 1)

        let plan = state.planSend(at: pathT0, using: &random)
        #expect(plan.udp == nil)
        #expect(plan.derpRegion == 7)
        #expect(plan.actions.pingDestinations == [a, b])
        #expect(plan.actions.last == .callMeMaybe)
        #expect(plan.actions.callMeMaybeCount == 1)
        #expect(state.lastSend == pathT0)
        #expect(state.path(at: pathT0) == .relayed(derpRegion: 7))
        // heartbeat가 3초 뒤로 걸리고, Ping 기한(5초)보다 이르다.
        #expect(state.nextDeadline == pathTime(3000))
    }

    @Test("홈 DERP가 0이면 CallMeMaybe를 내지 않고, 후보도 없으면 보낼 곳이 없다")
    func zeroHomeDERP() throws {
        let a = try pathEndpoint("192.168.1.10:41641")
        var random = PathTestRandom(state: 1)

        var withCandidate = PeerPathState(homeDERP: 0, endpoints: [a])
        let plan = withCandidate.planSend(at: pathT0, using: &random)
        #expect(plan.udp == nil)
        #expect(plan.derpRegion == 0)
        #expect(plan.actions.pingDestinations == [a])
        #expect(plan.actions.callMeMaybeCount == 0)
        #expect(withCandidate.path(at: pathT0) == .relayed(derpRegion: 0))

        var empty = PeerPathState(homeDERP: 0, endpoints: [])
        let noRoute = empty.planSend(at: pathT0, using: &random)
        #expect(noRoute == .init(udp: nil, derpRegion: 0, actions: []))

        // 후보가 없으면 Ping을 하나도 보내지 않았으므로 홈 DERP가 있어도 CallMeMaybe가 없다(노트 4.8 1).
        var noCandidates = PeerPathState(homeDERP: 3, endpoints: [])
        let derpOnly = noCandidates.planSend(at: pathT0, using: &random)
        #expect(derpOnly == .init(udp: nil, derpRegion: 3, actions: []))
    }

    @Test("UDP Ping의 출처를 후보로 넣고, 같은 후보의 같은 TxID에는 Pong하지 않는다")
    func pingSourceBecomesCandidate() throws {
        let source = try pathEndpoint("198.51.100.4:50000")
        var state = PeerPathState(homeDERP: 1, endpoints: [])
        var random = PathTestRandom(state: 1)
        let first = TransactionID.random(using: &random)
        let second = TransactionID.random(using: &random)

        let answers = [
            state.receivePing(first, from: source, at: pathT0),
            state.receivePing(first, from: source, at: pathTime(100)),
            state.receivePing(second, from: source, at: pathTime(200)),
            // 같은 TxID라도 직전 것이 아니면 다시 답한다(Go는 마지막 TxID 하나만 기억한다).
            state.receivePing(first, from: source, at: pathTime(300)),
        ]
        #expect(answers == [true, false, true, true])
        #expect(state.candidates.map(\.address) == [source])
        let plan = state.planSend(at: pathTime(400), using: &random)
        #expect(plan.actions.pingDestinations == [source])
    }

    @Test("IPv6·포트 0 출처의 Ping은 후보가 되지 않고 Pong도 하지 않는다")
    func unsupportedPingSources() throws {
        var state = PeerPathState(homeDERP: 1, endpoints: [])
        var random = PathTestRandom(state: 1)
        let txID = TransactionID.random(using: &random)
        let fromIPv6 = state.receivePing(txID, from: try pathEndpoint("[2001:db8::7]:41641"), at: pathT0)
        let fromPortZero = state.receivePing(txID, from: try pathEndpoint("10.0.0.1:0"), at: pathT0)
        #expect(!fromIPv6)
        #expect(!fromPortZero)
        #expect(state.candidates.isEmpty)

        // IPv4-mapped는 풀어서 넣는다.
        let fromMapped = state.receivePing(txID, from: try pathEndpoint("[::ffff:10.0.0.1]:41641"), at: pathT0)
        #expect(fromMapped)
        #expect(state.candidates.map(\.address) == [try pathEndpoint("10.0.0.1:41641")])
    }

    @Test("netmap 후보는 Ping을 받아도 netmap 출처로 남아 netmap에서 빠지면 지운다")
    func netmapCandidateStaysNetmapSourced() throws {
        let a = try pathEndpoint("192.168.1.10:41641")
        var state = PeerPathState(homeDERP: 1, endpoints: [a])
        var random = PathTestRandom(state: 1)
        let answered = state.receivePing(TransactionID.random(using: &random), from: a, at: pathT0)
        #expect(answered)
        state.update(homeDERP: 1, endpoints: [], at: pathTime(1000))
        #expect(state.candidates.isEmpty)
    }

    @Test("Ping으로 배운 후보는 마지막 Ping 뒤 45초를 넘으면 지운다")
    func pingLearnedCandidateExpires() throws {
        let source = try pathEndpoint("198.51.100.4:50000")
        var state = PeerPathState(homeDERP: 1, endpoints: [])
        var random = PathTestRandom(state: 1)
        _ = state.receivePing(TransactionID.random(using: &random), from: source, at: pathT0)
        // 40초에 다시 받으면 기준이 40초로 옮겨진다.
        _ = state.receivePing(TransactionID.random(using: &random), from: source, at: pathTime(40_000))

        var atLimit = state
        let atLimitPlan = atLimit.planSend(at: pathTime(85_000), using: &random)
        #expect(atLimitPlan.actions.pingDestinations == [source])
        var afterLimit = state
        let plan = afterLimit.planSend(at: pathTime(85_000) + .nanoseconds(1), using: &random)
        #expect(plan.actions.isEmpty)
        #expect(afterLimit.candidates.isEmpty)
    }

    @Test("netmap 갱신은 홈 DERP를 바꾸고 빠진 netmap 후보를 지우며 bestAddr도 함께 지운다")
    func netmapUpdateRemovesCandidateAndBestAddr() throws {
        let a = try pathEndpoint("192.168.1.10:41641")
        let b = try pathEndpoint("192.168.1.11:41641")
        var state = PeerPathState(homeDERP: 1, endpoints: [a, b])
        var random = PathTestRandom(state: 1)
        let ping = state.planSend(at: pathT0, using: &random)
        let accepted = state.receivePong(try ping.actions.txID(to: a), from: a, at: pathTime(1))
        #expect(accepted)
        #expect(state.path(at: pathTime(1)) == .direct(a))

        state.update(homeDERP: 2, endpoints: [b], at: pathTime(2))
        #expect(state.candidates.map(\.address) == [b])
        #expect(state.bestAddr == nil)
        #expect(state.path(at: pathTime(2)) == .relayed(derpRegion: 2))
    }

    // MARK: Pong과 bestAddr

    @Test("후보로 보낸 Ping의 UDP Pong이 bestAddr를 세우고 6.5초 동안 UDP로만 보낸다")
    func pongEstablishesBestAddr() throws {
        let a = try pathEndpoint("192.168.1.10:41641")
        var state = PeerPathState(homeDERP: 1, endpoints: [a])
        var random = PathTestRandom(state: 1)
        let txID = try state.planSend(at: pathT0, using: &random).actions.txID(to: a)

        let accepted = state.receivePong(txID, from: a, at: pathTime(20))
        #expect(accepted)
        #expect(state.bestAddr == .init(address: a, latency: .milliseconds(20)))
        #expect(state.path(at: pathTime(20)) == .direct(a))
        let plan = state.planSend(at: pathTime(1000), using: &random)
        #expect(plan == .init(udp: a, derpRegion: 0, actions: []))
        // 같은 TxID의 두 번째 Pong은 모르는 것이다.
        let duplicate = state.receivePong(txID, from: a, at: pathTime(30))
        #expect(!duplicate)
    }

    @Test("bestAddr는 Pong의 출처가 아니라 Ping을 보낸 후보로 정한다")
    func bestAddrIsPingDestination() throws {
        let a = try pathEndpoint("192.168.1.10:41641")
        var state = PeerPathState(homeDERP: 1, endpoints: [a])
        var random = PathTestRandom(state: 1)
        let txID = try state.planSend(at: pathT0, using: &random).actions.txID(to: a)
        let accepted = state.receivePong(txID, from: try pathEndpoint("203.0.113.99:1234"), at: pathTime(5))
        #expect(accepted)
        #expect(state.path(at: pathTime(5)) == .direct(a))
    }

    @Test("DERP로 온 Pong, 모르는 TxID, 지운 후보로 간 Ping의 Pong은 bestAddr를 세우지 않는다")
    func pongsThatDoNotEstablishPath() throws {
        let a = try pathEndpoint("192.168.1.10:41641")
        var random = PathTestRandom(state: 1)
        var state = PeerPathState(homeDERP: 1, endpoints: [a])
        let txID = try state.planSend(at: pathT0, using: &random).actions.txID(to: a)

        var overDERP = state
        let acceptedOverDERP = overDERP.receivePong(txID, from: nil, at: pathTime(10))
        #expect(acceptedOverDERP)
        #expect(overDERP.bestAddr == nil)
        #expect(overDERP.sentPings.isEmpty)

        var unknown = state
        let acceptedUnknown = unknown.receivePong(TransactionID.random(using: &random), from: a, at: pathTime(10))
        #expect(!acceptedUnknown)
        #expect(unknown.bestAddr == nil)
        #expect(unknown.sentPings.count == 1)

        var removed = state
        removed.update(homeDERP: 1, endpoints: [], at: pathTime(5))
        let acceptedForRemoved = removed.receivePong(txID, from: a, at: pathTime(10))
        #expect(acceptedForRemoved)
        #expect(removed.bestAddr == nil)
        #expect(removed.path(at: pathTime(10)) == .relayed(derpRegion: 1))
    }

    @Test("betterAddr: 없는 것보다 낫고, 같은 주소는 낫지 않다")
    func betterAddrBasics() throws {
        let a = PeerPathState.AddressQuality(address: try pathEndpoint("203.0.113.1:41641"), latency: .milliseconds(10))
        let sameAddressFaster = PeerPathState.AddressQuality(address: a.address, latency: .milliseconds(1))
        #expect(PeerPathState.isBetter(a, than: nil))
        #expect(!PeerPathState.isBetter(sameAddressFaster, than: a))
    }

    @Test("betterAddr: loopback +50이 LAN +20을 이기고, link-local +30이 사설을 이긴다")
    func betterAddrPreferencePoints() throws {
        func quality(_ text: String, _ milliseconds: Int64) throws -> PeerPathState.AddressQuality {
            .init(address: try pathEndpoint(text), latency: .milliseconds(milliseconds))
        }
        let loopback = try quality("127.0.0.1:41641", 1)
        let lan = try quality("192.168.1.10:41641", 1)
        #expect(PeerPathState.isBetter(loopback, than: lan))
        #expect(!PeerPathState.isBetter(lan, than: loopback))

        #expect(PeerPathState.isBetter(try quality("169.254.1.1:41641", 1), than: try quality("10.0.0.1:41641", 1)))
        // 172.16.0.0/12의 경계: 172.31은 사설, 172.32는 공인.
        #expect(PeerPathState.isBetter(try quality("172.31.0.1:41641", 1), than: try quality("172.32.0.1:41641", 1)))
        #expect(!PeerPathState.isBetter(try quality("172.32.0.1:41641", 1), than: try quality("172.16.0.1:41641", 1)))
        // 지연이 크게 다르면 종류 점수를 넘는다: LAN 10 ms 대 loopback 1 ms는 20점 대 90 + 50점.
        #expect(!PeerPathState.isBetter(try quality("192.168.1.10:41641", 10), than: loopback))
    }

    @Test("betterAddr: 지연 비율 점수와 1점 규칙")
    func betterAddrLatencyPoints() throws {
        func quality(_ text: String, _ milliseconds: Int64) throws -> PeerPathState.AddressQuality {
            .init(address: try pathEndpoint(text), latency: .milliseconds(milliseconds))
        }
        // 10 ms 대 20 ms: 빠른 쪽이 100 − 1000/20 = 50점.
        #expect(PeerPathState.isBetter(try quality("203.0.113.1:1", 10), than: try quality("198.51.100.1:1", 20)))
        #expect(!PeerPathState.isBetter(try quality("203.0.113.1:1", 20), than: try quality("198.51.100.1:1", 10)))
        // 99 ms 대 100 ms: 1점이면 바꾸지 않는다. 98 ms는 2점이라 바꾼다.
        #expect(!PeerPathState.isBetter(try quality("203.0.113.1:1", 99), than: try quality("198.51.100.1:1", 100)))
        #expect(PeerPathState.isBetter(try quality("203.0.113.1:1", 98), than: try quality("198.51.100.1:1", 100)))
        // 지연이 모두 0인 공인 주소끼리는 바꾸지 않는다.
        #expect(!PeerPathState.isBetter(try quality("203.0.113.1:1", 0), than: try quality("198.51.100.1:1", 0)))
    }

    @Test("같은 기계의 loopback과 LAN 엔드포인트가 함께 오면 loopback이 bestAddr가 된다(노트 4.7 계산)")
    func loopbackWinsOverLAN() throws {
        let lan = try pathEndpoint("192.168.1.10:41641")
        let loopback = try pathEndpoint("127.0.0.1:41641")
        var state = PeerPathState(homeDERP: 1, endpoints: [lan, loopback])
        var random = PathTestRandom(state: 1)
        let actions = state.planSend(at: pathT0, using: &random).actions
        _ = state.receivePong(try actions.txID(to: lan), from: lan, at: pathTime(1))
        #expect(state.path(at: pathTime(1)) == .direct(lan))
        _ = state.receivePong(try actions.txID(to: loopback), from: loopback, at: pathTime(1))
        #expect(state.path(at: pathTime(1)) == .direct(loopback))
    }

    @Test("신뢰 중에는 더 나쁜 주소로 바꾸지 않고, 신뢰가 지나면 Pong이 온 주소로 바꾼다")
    func replacementRules() throws {
        let loopback = try pathEndpoint("127.0.0.1:41641")
        let publicAddress = try pathEndpoint("203.0.113.7:41641")
        var state = PeerPathState(homeDERP: 1, endpoints: [loopback, publicAddress])
        var random = PathTestRandom(state: 1)

        let first = state.planSend(at: pathT0, using: &random).actions
        _ = state.receivePong(try first.txID(to: loopback), from: loopback, at: pathTime(1))
        _ = state.receivePong(try first.txID(to: publicAddress), from: publicAddress, at: pathTime(2))
        #expect(state.path(at: pathTime(2)) == .direct(loopback))
        // 더 나쁜 주소의 Pong은 신뢰를 늘리지 않는다: loopback Pong(1 ms) + 6.5초.
        #expect(state.trustedUntil == pathTime(6501))

        // 7초: 신뢰가 지나 UDP + DERP로 보내며 두 후보에 다시 Ping한다.
        let retry = state.planSend(at: pathTime(7000), using: &random)
        #expect(retry.udp == loopback)
        #expect(retry.derpRegion == 1)
        #expect(retry.actions.pingDestinations == [loopback, publicAddress])
        // 신뢰가 지났으므로 먼저 온 공인 주소의 Pong이 bestAddr가 된다.
        _ = state.receivePong(try retry.actions.txID(to: publicAddress), from: publicAddress, at: pathTime(7001))
        #expect(state.path(at: pathTime(7001)) == .direct(publicAddress))
        // 같은 지연의 loopback은 50점 더 나아 다시 바꾼다.
        _ = state.receivePong(try retry.actions.txID(to: loopback), from: loopback, at: pathTime(7001))
        #expect(state.path(at: pathTime(7001)) == .direct(loopback))
    }

    // MARK: 신뢰 기간

    @Test("신뢰는 마지막 Pong + 6.5초와 같은 시각까지다")
    func trustBoundary() throws {
        let a = try pathEndpoint("192.168.1.10:41641")
        var state = PeerPathState(homeDERP: 1, endpoints: [a])
        var random = PathTestRandom(state: 1)
        let txID = try state.planSend(at: pathT0, using: &random).actions.txID(to: a)
        _ = state.receivePong(txID, from: a, at: pathTime(10))
        let until = pathTime(6510)

        #expect(state.path(at: until) == .direct(a))
        #expect(state.path(at: until + .nanoseconds(1)) == .relayed(derpRegion: 1))

        var atUntil = state
        let atUntilPlan = atUntil.planSend(at: until, using: &random)
        #expect(atUntilPlan == .init(udp: a, derpRegion: 0, actions: []))

        // 신뢰가 지나면 bestAddr와 DERP로 함께 보내고, 5초가 지난 후보에 다시 Ping한다.
        var afterUntil = state
        let plan = afterUntil.planSend(at: until + .nanoseconds(1), using: &random)
        #expect(plan.udp == a)
        #expect(plan.derpRegion == 1)
        #expect(plan.actions.pingDestinations == [a])
        #expect(plan.actions.last == .callMeMaybe)
    }

    @Test("신뢰 만료는 기한이다: 만료 1나노초 뒤의 advance에서 경로가 DERP로 바뀐다")
    func trustExpiryIsADeadline() throws {
        let a = try pathEndpoint("192.168.1.10:41641")
        var state = PeerPathState(homeDERP: 1, endpoints: [a])
        var random = PathTestRandom(state: 1)
        // CallMeMaybe로 Ping을 내면 송신 기록과 heartbeat가 없어 기한이 Ping과 신뢰뿐이다.
        let txID = try state.receiveCallMeMaybe([], at: pathT0, using: &random).txID(to: a)
        _ = state.receivePong(txID, from: a, at: pathTime(10))
        let expiry = pathTime(6510) + .nanoseconds(1)
        #expect(state.nextDeadline == expiry)

        let actions = state.advance(to: expiry, using: &random)
        #expect(actions.isEmpty)
        #expect(state.path(at: expiry) == .relayed(derpRegion: 1))
        #expect(state.nextDeadline == nil)
        // bestAddr는 남아 UDP로도 함께 보낸다.
        #expect(state.bestAddr?.address == a)
    }

    // MARK: Ping 간격과 기한

    @Test("같은 후보에는 5초 안에 다시 Ping하지 않고, 받은 CallMeMaybe가 그 제한을 푼다")
    func perCandidatePingInterval() throws {
        let a = try pathEndpoint("192.168.1.10:41641")
        var state = PeerPathState(homeDERP: 1, endpoints: [a])
        var random = PathTestRandom(state: 1)
        _ = state.planSend(at: pathT0, using: &random)

        var soon = state
        // 보낸 Ping이 없으므로 CallMeMaybe도 없다.
        let soonPlan = soon.planSend(at: pathTime(4999), using: &random)
        #expect(soonPlan.actions.isEmpty)

        var atInterval = state
        let again = atInterval.planSend(at: pathTime(5000), using: &random).actions
        #expect(again.pingDestinations == [a])
        #expect(again.callMeMaybeCount == 1)

        let c = try pathEndpoint("198.51.100.8:41641")
        var called = state
        let callActions = called.receiveCallMeMaybe([c], at: pathTime(1000), using: &random)
        #expect(callActions.pingDestinations == [a, c])
        // 받은 CallMeMaybe의 전체 Ping은 CallMeMaybe를 되보내지 않는다.
        #expect(callActions.callMeMaybeCount == 0)
    }

    @Test("Ping 기한은 5초다: 직전까지는 Pong을 받고, 그 시각에 지운다")
    func pingTimeoutBoundary() throws {
        let a = try pathEndpoint("192.168.1.10:41641")
        var state = PeerPathState(homeDERP: 1, endpoints: [a])
        var random = PathTestRandom(state: 1)
        let txID = try state.receiveCallMeMaybe([], at: pathT0, using: &random).txID(to: a)
        #expect(state.nextDeadline == pathTime(5000))

        var justBefore = state
        let acceptedJustBefore = justBefore.receivePong(txID, from: a, at: pathTime(5000) - .nanoseconds(1))
        #expect(acceptedJustBefore)
        var atDeadline = state
        let acceptedAtDeadline = atDeadline.receivePong(txID, from: a, at: pathTime(5000))
        #expect(!acceptedAtDeadline)

        var advanced = state
        _ = advanced.advance(to: pathTime(5000) - .nanoseconds(1), using: &random)
        #expect(advanced.sentPings.count == 1)
        _ = advanced.advance(to: pathTime(5000), using: &random)
        #expect(advanced.sentPings.isEmpty)
        #expect(advanced.nextDeadline == nil)
    }

    @Test("기한이 지난 bestAddr Ping은 신뢰가 남았으면 bestAddr를 지키고, 신뢰가 지났으면 지운다")
    func pingTimeoutAndBestAddr() throws {
        let a = try pathEndpoint("127.0.0.1:41641")
        var harness = PathHarness(PeerPathState(homeDERP: 1, endpoints: [a]))
        harness.responders = [a: .milliseconds(1)]
        harness.send()
        // 첫 Pong(1 ms) → 신뢰 6.501초. 3초 heartbeat의 Ping과 Pong으로 이어진다.
        harness.run(until: pathTime(3500))
        #expect(harness.state.trustedUntil == pathTime(9501))

        // 6초 heartbeat의 Ping은 잃고, 9초 heartbeat의 Pong은 받는다.
        harness.responders = [:]
        harness.run(until: pathTime(8000))
        harness.responders = [a: .milliseconds(1)]
        harness.run(until: pathTime(9500))
        #expect(harness.state.trustedUntil == pathTime(15_501))
        // 6초 Ping의 기한(11초)에는 신뢰가 남아 bestAddr를 지킨다.
        harness.run(until: pathTime(11_000))
        #expect(harness.state.sentPings.isEmpty)
        #expect(harness.state.path(at: pathTime(11_000)) == .direct(a))

        // 12초부터 모두 잃는다. 신뢰는 15.501초에 지나고, 12초 Ping의 기한(17초)에 bestAddr를 지운다.
        harness.responders = [:]
        harness.run(until: pathTime(16_999))
        #expect(harness.state.path(at: pathTime(16_999)) == .relayed(derpRegion: 1))
        #expect(harness.state.bestAddr?.address == a)
        harness.run(until: pathTime(17_000))
        #expect(harness.state.bestAddr == nil)
    }

    // MARK: heartbeat와 전체 Ping

    @Test("heartbeat는 3초마다 돌고, 마지막 송신 뒤 45초가 넘으면 멈추며 다음 송신이 다시 건다")
    func heartbeatStopsWhenIdle() throws {
        let a = try pathEndpoint("192.168.1.10:41641")
        var harness = PathHarness(PeerPathState(homeDERP: 1, endpoints: [a]))
        harness.send()
        harness.run(until: pathTime(45_000))
        // 45초 heartbeat는 아직 돈다(45초를 "넘으면" 멈춘다).
        #expect(harness.state.heartbeatDeadline == pathTime(48_000))
        harness.run(until: pathTime(60_000))
        #expect(harness.state.heartbeatDeadline == nil)
        #expect(harness.state.nextDeadline == nil)

        // 답이 없는 후보에는 5초 제한 때문에 6초마다 Ping하고 그때마다 CallMeMaybe를 낸다.
        let expected = [0, 6, 12, 18, 24, 30, 36, 42].map { pathTime(Int64($0) * 1000) }
        #expect(harness.pingTimes(to: a) == expected)
        #expect(harness.actions.filter { $0.action == .callMeMaybe }.map(\.time) == expected)

        let resumed = harness.send()
        #expect(resumed.actions.pingDestinations == [a])
        #expect(harness.state.heartbeatDeadline == pathTime(63_000))
    }

    @Test("지연이 5 ms 이하인 신뢰된 직접 경로에서는 전체 Ping을 하지 않는다")
    func noFullPingWhenGoodEnough() throws {
        let loopback = try pathEndpoint("127.0.0.1:41641")
        let lan = try pathEndpoint("192.168.1.10:41641")
        var harness = PathHarness(PeerPathState(homeDERP: 1, endpoints: [loopback, lan]))
        harness.responders = [loopback: .milliseconds(1), lan: .milliseconds(1)]
        harness.send()
        harness.sendRepeatedly(every: .seconds(1))
        harness.run(until: pathTime(130_000))

        #expect(harness.pingTimes(to: lan) == [pathT0])
        // heartbeat는 3초마다 bestAddr에 Ping한다.
        #expect(harness.pingTimes(to: loopback).count == 1 + 43)
        #expect(harness.state.path(at: pathTime(130_000)) == .direct(loopback))
    }

    @Test("지연이 5 ms보다 큰 직접 경로에서는 마지막 전체 Ping 뒤 1분마다 전체 Ping을 한다")
    func upgradeFullPingEveryMinute() throws {
        let a = try pathEndpoint("203.0.113.10:41641")
        let b = try pathEndpoint("198.51.100.20:41641")
        var harness = PathHarness(PeerPathState(homeDERP: 1, endpoints: [a, b]))
        harness.responders = [a: .milliseconds(10), b: .milliseconds(10)]
        harness.send()
        harness.sendRepeatedly(every: .seconds(1))
        harness.run(until: pathTime(130_000))

        #expect(harness.pingTimes(to: b) == [pathT0, pathTime(60_000), pathTime(120_000)])
        #expect(harness.state.path(at: pathTime(130_000)) == .direct(a))
    }

    @Test("직접 경로를 막으면 신뢰가 지나 UDP + DERP로, 기한 뒤 DERP로만 보내고, 풀면 직접으로 돌아온다")
    func blockAndUnblock() throws {
        let a = try pathEndpoint("127.0.0.1:41641")
        var harness = PathHarness(PeerPathState(homeDERP: 1, endpoints: [a]))
        harness.responders = [a: .milliseconds(1)]
        harness.send()
        harness.sendRepeatedly(every: .seconds(1))
        harness.run(until: pathTime(30_500))
        // 30초 heartbeat의 Pong(30.001초) + 6.5초.
        #expect(harness.state.trustedUntil == pathTime(36_501))

        harness.responders = [:]
        harness.run(until: pathTime(36_501))
        #expect(harness.state.path(at: pathTime(36_501)) == .direct(a))
        harness.run(until: pathTime(36_501) + .nanoseconds(1))
        #expect(harness.state.path(at: pathTime(36_501) + .nanoseconds(1)) == .relayed(derpRegion: 1))

        harness.run(until: pathTime(40_500))
        // 37초: bestAddr와 DERP로 함께. 36초에 Ping한 후보는 5초 제한으로 건너뛴다.
        #expect(try harness.plan(at: pathTime(37_000)) == .init(udp: a, derpRegion: 1, actions: []))
        // 38초: 33초 heartbeat Ping의 기한이 신뢰가 지난 뒤라 bestAddr를 지웠다. DERP로만 보낸다.
        #expect(try harness.plan(at: pathTime(38_000)) == .init(udp: nil, derpRegion: 1, actions: []))

        harness.responders = [a: .milliseconds(1)]
        harness.run(until: pathTime(41_000))
        // 41초 송신: 마지막 Ping(36초) 뒤 5초가 지나 다시 Ping하고 CallMeMaybe를 낸다.
        let retry = try harness.plan(at: pathTime(41_000))
        #expect(retry.actions.pingDestinations == [a])
        #expect(retry.actions.last == .callMeMaybe)
        #expect(harness.state.path(at: pathTime(41_000)) == .relayed(derpRegion: 1))
        harness.run(until: pathTime(41_001))
        #expect(harness.state.path(at: pathTime(41_001)) == .direct(a))
    }

    // MARK: CallMeMaybe

    @Test("받은 CallMeMaybe는 주소를 후보로 넣고, 다음 CallMeMaybe에서 빠진 주소는 출처와 무관하게 지운다")
    func callMeMaybeReplacesPreviousAddresses() throws {
        let a = try pathEndpoint("192.168.1.10:41641")
        let c = try pathEndpoint("198.51.100.8:41641")
        let d = try pathEndpoint("198.51.100.9:41641")
        var state = PeerPathState(homeDERP: 1, endpoints: [a])
        var random = PathTestRandom(state: 1)

        let first = state.receiveCallMeMaybe(
            [a, c, try pathEndpoint("[2001:db8::1]:41641"), try pathEndpoint("[::ffff:198.51.100.9]:41641")],
            at: pathT0, using: &random)
        #expect(first.pingDestinations == [a, c, d])
        #expect(state.candidates.map(\.address) == [a, c, d])
        _ = state.receivePong(try first.txID(to: c), from: c, at: pathTime(1))
        #expect(state.path(at: pathTime(1)) == .direct(c))

        // netmap 출처이기도 한 a도, bestAddr인 c도 지운다.
        _ = state.receiveCallMeMaybe([d], at: pathTime(1000), using: &random)
        #expect(state.candidates.map(\.address) == [d])
        #expect(state.bestAddr == nil)

        // CallMeMaybe 후보는 netmap에서 빠져도, 45초가 지나도 남는다.
        state.update(homeDERP: 1, endpoints: [a], at: pathTime(100_000))
        #expect(state.candidates.map(\.address) == [d, a])
    }

    // MARK: disco 키 변경

    @Test("disco 키가 바뀌면 신뢰와 기다리던 Ping을 버리고 bestAddr 주소는 남겨 곧바로 다시 찾는다")
    func resetForNewDiscoKey() throws {
        let a = try pathEndpoint("192.168.1.10:41641")
        var state = PeerPathState(homeDERP: 1, endpoints: [a])
        var random = PathTestRandom(state: 1)
        let firstPing = try state.planSend(at: pathT0, using: &random).actions.txID(to: a)
        _ = state.receivePong(firstPing, from: a, at: pathTime(1))
        let heartbeat = state.advance(to: pathTime(3000), using: &random)
        let pendingPing = try heartbeat.txID(to: a)

        state.resetForNewDiscoKey()
        #expect(state.path(at: pathTime(3001)) == .relayed(derpRegion: 1))
        #expect(state.bestAddr?.address == a)
        #expect(state.lastSend == nil)
        let acceptedOldPong = state.receivePong(pendingPing, from: a, at: pathTime(3002))
        #expect(!acceptedOldPong)

        // 송신이 없으면 다음 heartbeat에서 멈춘다.
        var idle = state
        let idleActions = idle.advance(to: pathTime(6000), using: &random)
        #expect(idleActions.isEmpty)
        #expect(idle.heartbeatDeadline == nil)

        // 다음 송신은 UDP + DERP로 보내고, 3초 전에 Ping한 후보에도 곧바로 다시 Ping한다.
        let plan = state.planSend(at: pathTime(3100), using: &random)
        #expect(plan.udp == a)
        #expect(plan.derpRegion == 1)
        #expect(plan.actions.pingDestinations == [a])
        #expect(plan.actions.last == .callMeMaybe)
    }

    // MARK: 한도

    @Test("후보는 128개를 넘지 않고, 받은 Ping이 넘쳐도 있는 bestAddr를 밀어내지 않는다")
    func candidateLimitKeepsBestAddr() throws {
        let a = try pathEndpoint("192.168.1.10:41641")
        let late = try pathEndpoint("192.168.1.11:41641")
        var state = PeerPathState(homeDERP: 1, endpoints: [a])
        var random = PathTestRandom(state: 1)
        let txID = try state.planSend(at: pathT0, using: &random).actions.txID(to: a)
        _ = state.receivePong(txID, from: a, at: pathTime(1))

        for index in 0..<300 {
            let source = IPEndpoint(
                address: try #require(IPAddress(bytes: [10, 1, UInt8(index / 256), UInt8(index % 256)])),
                port: 41641)
            // 넣지 못해도 Pong은 한다.
            let answered = state.receivePing(TransactionID.random(using: &random), from: source, at: pathTime(2))
            #expect(answered)
        }
        #expect(state.candidates.count == PeerPathState.maxCandidates)
        #expect(state.path(at: pathTime(2)) == .direct(a))

        // 가득 찬 표에 새 netmap 후보가 오면 Ping으로만 배운 후보 하나를 밀어내고 들어간다. Ping으로 배운 후보는 45초를
        // 넘기면 지워진다.
        state.update(homeDERP: 1, endpoints: [a, late], at: pathTime(3))
        #expect(state.candidates.contains { $0.address == late })
        #expect(state.candidates.count == PeerPathState.maxCandidates)
        #expect(state.path(at: pathTime(3)) == .direct(a))
        state.update(homeDERP: 1, endpoints: [a, late], at: pathTime(45_002) + .nanoseconds(1))
        #expect(state.candidates.map(\.address) == [a, late])
    }

    /// 10.1.x.y:41641. 캡처한 Ping을 다시 보내는 출처로 쓴다.
    private func replaySource(_ index: Int) throws -> IPEndpoint {
        IPEndpoint(
            address: try #require(IPAddress(bytes: [10, 1, UInt8(index / 256), UInt8(index % 256)])), port: 41641)
    }

    @Test("캡처한 Ping 128개를 서로 다른 주소에서 넣어 표가 가득 차도, 새 Ping이 온 주소는 가장 오래된 것을 밀어내고 후보가 된다")
    func fullTableAdmitsNewPingSource() throws {
        var state = PeerPathState(homeDERP: 1, endpoints: [])
        var random = PathTestRandom(state: 1)
        // 같은 Ping 하나를 되풀이하는 것으로는 후보가 하나만 생긴다(`knownPingFromNewSourceIsNotCandidate`).
        for index in 0..<PeerPathState.maxCandidates {
            let captured = TransactionID.random(using: &random)
            #expect(state.receivePing(captured, from: try replaySource(index), at: pathTime(Int64(index))) == true)
        }
        #expect(state.candidates.count == PeerPathState.maxCandidates)

        let real = try pathEndpoint("203.0.113.7:41641")
        #expect(state.receivePing(TransactionID.random(using: &random), from: real, at: pathTime(1_000)) == true)
        #expect(state.candidates.contains { $0.address == real })
        #expect(state.candidates.count == PeerPathState.maxCandidates)
        // 밀려난 것은 Ping을 받은 지 가장 오래된 후보 하나다.
        #expect(!state.candidates.contains { $0.address == (try? replaySource(0)) })
        #expect(state.candidates.contains { $0.address == (try? replaySource(1)) })
    }

    @Test("가득 찬 표에서 netmap·CallMeMaybe 후보와 bestAddr는 밀려나지 않는다. 밀어낼 것이 없으면 새 후보를 넣지 않는다")
    func fullTableKeepsTrustedSources() throws {
        let fromNetmap = try pathEndpoint("192.168.1.10:41641")
        let called = try pathEndpoint("192.168.1.11:41641")
        let best = try pathEndpoint("192.168.1.12:41641")
        var state = PeerPathState(homeDERP: 1, endpoints: [fromNetmap])
        var random = PathTestRandom(state: 1)
        // `best`는 Ping으로 배운 뒤 Pong이 확인한 주소다. 가장 먼저 배웠으므로 Ping을 받은 지 가장 오래됐다.
        #expect(state.receivePing(TransactionID.random(using: &random), from: best, at: pathT0) == true)
        let actions = state.receiveCallMeMaybe([called], at: pathTime(1), using: &random)
        #expect(state.receivePong(try actions.txID(to: best), from: best, at: pathTime(2)) == true)
        #expect(state.path(at: pathTime(2)) == .direct(best))

        for index in 0..<300 {
            _ = state.receivePing(TransactionID.random(using: &random), from: try replaySource(index), at: pathTime(3))
        }
        #expect(state.candidates.count == PeerPathState.maxCandidates)
        #expect(Array(state.candidates.map(\.address).prefix(3)) == [fromNetmap, best, called])
        #expect(state.path(at: pathTime(3)) == .direct(best))

        // 표가 netmap 후보로만 가득이면 밀어낼 것이 없다. Ping에는 답하되 후보로 넣지 않는다.
        var endpoints: [IPEndpoint] = []
        for index in 0..<PeerPathState.maxCandidates {
            endpoints.append(IPEndpoint(
                address: try #require(IPAddress(bytes: [10, 2, UInt8(index / 256), UInt8(index % 256)])), port: 41641))
        }
        var pinned = PeerPathState(homeDERP: 1, endpoints: endpoints)
        let stranger = try pathEndpoint("203.0.113.7:41641")
        #expect(pinned.receivePing(TransactionID.random(using: &random), from: stranger, at: pathT0) == true)
        #expect(pinned.candidates.map(\.address) == endpoints)
    }

    @Test("같은 TxID의 재전송은 Ping으로 배운 후보의 수명(45초)을 늘리지 않는다. 새 TxID의 Ping은 늘린다")
    func duplicatePingDoesNotExtendLifetime() throws {
        let source = try pathEndpoint("203.0.113.7:41641")
        var random = PathTestRandom(state: 1)
        let first = TransactionID.random(using: &random)

        var replayed = PeerPathState(homeDERP: 1, endpoints: [])
        #expect(replayed.receivePing(first, from: source, at: pathT0) == true)
        #expect(replayed.receivePing(first, from: source, at: pathTime(30_000)) == false)
        replayed.update(homeDERP: 1, endpoints: [], at: pathTime(45_000))
        #expect(replayed.candidates.map(\.address) == [source])
        replayed.update(homeDERP: 1, endpoints: [], at: pathTime(45_000) + .nanoseconds(1))
        #expect(replayed.candidates.isEmpty)

        var refreshed = PeerPathState(homeDERP: 1, endpoints: [])
        #expect(refreshed.receivePing(first, from: source, at: pathT0) == true)
        #expect(refreshed.receivePing(TransactionID.random(using: &random), from: source, at: pathTime(30_000)) == true)
        refreshed.update(homeDERP: 1, endpoints: [], at: pathTime(45_000) + .nanoseconds(1))
        #expect(refreshed.candidates.map(\.address) == [source])
        refreshed.update(homeDERP: 1, endpoints: [], at: pathTime(75_000) + .nanoseconds(1))
        #expect(refreshed.candidates.isEmpty)
    }

    @Test("이미 본 두 TxID를 번갈아 넣어도 후보의 수명(45초)은 늘지 않는다")
    func alternatingKnownPingsDoNotExtendLifetime() throws {
        let source = try pathEndpoint("203.0.113.7:41641")
        var random = PathTestRandom(state: 1)
        let first = TransactionID.random(using: &random)
        let second = TransactionID.random(using: &random)
        var state = PeerPathState(homeDERP: 1, endpoints: [])
        #expect(state.receivePing(first, from: source, at: pathT0) == true)
        #expect(state.receivePing(second, from: source, at: pathTime(1_000)) == true)
        // 두 Ping을 10초마다 번갈아 다시 넣는다. 직전 TxID와는 늘 다르다.
        for (round, txID) in [first, second, first, second].enumerated() {
            _ = state.receivePing(txID, from: source, at: pathTime(Int64(round + 1) * 10_000))
        }
        // 새 TxID를 마지막으로 받은 것은 1초다.
        state.update(homeDERP: 1, endpoints: [], at: pathTime(46_000))
        #expect(state.candidates.map(\.address) == [source])
        state.update(homeDERP: 1, endpoints: [], at: pathTime(46_000) + .nanoseconds(1))
        #expect(state.candidates.isEmpty)
    }

    @Test("이미 본 TxID를 다른 출처에서 넣어도 후보가 생기지 않는다. disco 키가 바뀌면 본 TxID를 잊는다")
    func knownPingFromNewSourceIsNotCandidate() throws {
        let source = try pathEndpoint("203.0.113.7:41641")
        let elsewhere = try pathEndpoint("198.51.100.4:50000")
        var random = PathTestRandom(state: 1)
        let seen = TransactionID.random(using: &random)
        var state = PeerPathState(homeDERP: 1, endpoints: [])
        #expect(state.receivePing(seen, from: source, at: pathT0) == true)
        _ = state.receivePing(seen, from: elsewhere, at: pathTime(1_000))
        #expect(state.candidates.map(\.address) == [source])

        // 새 TxID는 어느 출처에서든 전과 같이 후보가 된다.
        #expect(state.receivePing(TransactionID.random(using: &random), from: elsewhere, at: pathTime(2_000)) == true)
        #expect(state.candidates.map(\.address) == [source, elsewhere])

        // 새 disco 키의 Ping은 옛 키로 본 TxID와 견주지 않는다.
        var rekeyed = PeerPathState(homeDERP: 1, endpoints: [])
        #expect(rekeyed.receivePing(seen, from: source, at: pathT0) == true)
        rekeyed.resetForNewDiscoKey()
        #expect(rekeyed.receivePing(seen, from: elsewhere, at: pathTime(1_000)) == true)
        #expect(rekeyed.candidates.map(\.address) == [source, elsewhere])
    }

    @Test("본 TxID는 32개까지 기억한다. 그보다 많은 Ping이 지나가면 가장 먼저 본 것을 잊는다")
    func knownPingRingIsBounded() throws {
        let source = try pathEndpoint("203.0.113.7:41641")
        let elsewhere = try pathEndpoint("198.51.100.4:50000")
        var random = PathTestRandom(state: 1)
        let oldest = TransactionID.random(using: &random)
        var state = PeerPathState(homeDERP: 1, endpoints: [])
        _ = state.receivePing(oldest, from: source, at: pathT0)
        for _ in 0..<31 {
            _ = state.receivePing(TransactionID.random(using: &random), from: source, at: pathT0)
        }
        var remembered = state
        _ = remembered.receivePing(oldest, from: elsewhere, at: pathTime(1_000))
        #expect(remembered.candidates.map(\.address) == [source])

        _ = state.receivePing(TransactionID.random(using: &random), from: source, at: pathT0)
        _ = state.receivePing(oldest, from: elsewhere, at: pathTime(1_000))
        #expect(state.candidates.map(\.address) == [source, elsewhere])
    }

    @Test("CallMeMaybe와 netmap의 주소는 앞에서부터 128개까지만 넣는다")
    func candidateLimitKeepsLeadingAddresses() throws {
        var addresses: [IPEndpoint] = []
        for index in 0..<300 {
            addresses.append(IPEndpoint(
                address: try #require(IPAddress(bytes: [10, 2, UInt8(index / 256), UInt8(index % 256)])),
                port: 41641))
        }
        var random = PathTestRandom(state: 1)

        var called = PeerPathState(homeDERP: 1, endpoints: [])
        _ = called.receiveCallMeMaybe(addresses, at: pathT0, using: &random)
        #expect(called.candidates.map(\.address) == Array(addresses.prefix(PeerPathState.maxCandidates)))

        let fromNetmap = PeerPathState(homeDERP: 1, endpoints: addresses)
        #expect(fromNetmap.candidates.map(\.address) == Array(addresses.prefix(PeerPathState.maxCandidates)))
    }

    @Test("기다리는 Ping은 128개를 넘지 않고, 기한이 표를 비우면 다시 보낸다")
    func sentPingLimit() throws {
        var addresses: [IPEndpoint] = []
        for index in 0..<PeerPathState.maxCandidates {
            addresses.append(IPEndpoint(
                address: try #require(IPAddress(bytes: [10, 3, 0, UInt8(index)])),
                port: 41641))
        }
        var state = PeerPathState(homeDERP: 1, endpoints: [])
        var random = PathTestRandom(state: 1)
        let first = state.receiveCallMeMaybe(addresses, at: pathT0, using: &random)
        #expect(first.count == PeerPathState.maxSentPings)
        let whileFull = state.receiveCallMeMaybe(addresses, at: pathTime(1000), using: &random)
        #expect(whileFull.isEmpty)
        #expect(state.sentPings.count == PeerPathState.maxSentPings)

        _ = state.advance(to: pathTime(5000), using: &random)
        #expect(state.sentPings.isEmpty)
        let afterTimeout = state.receiveCallMeMaybe(addresses, at: pathTime(5000), using: &random)
        #expect(afterTimeout.count == PeerPathState.maxSentPings)
    }

    // MARK: 임의 입력열

    @Test("임의 입력열(시각 역행, 중복·모르는 TxID, 포트 0, IPv6 포함)로 죽지 않고 불변식을 지키며 결정적이다")
    func randomInputSequences() throws {
        let first = try runRandomSequence(seed: 0x5EED)
        let second = try runRandomSequence(seed: 0x5EED)
        #expect(first == second)
        #expect(first != (try runRandomSequence(seed: 0x5EED + 1)))
    }

    /// 고정 시드로 5,000단계를 돌려 낸 것을 모두 적는다. 단계마다 불변식을 확인한다.
    private func runRandomSequence(seed: UInt64) throws -> [String] {
        var random = PathTestRandom(state: seed)
        var pool: [IPEndpoint] = try [
            "10.0.0.1:41641", "10.0.0.2:41641", "10.0.0.2:41642", "127.0.0.1:41641", "192.168.1.10:41641",
            "169.254.1.1:41641", "203.0.113.5:41641", "10.0.0.1:0", "[2001:db8::1]:41641", "[fe80::1]:41641",
            "[::ffff:10.0.0.3]:41641",
        ].map(pathEndpoint)
        for index in 0..<40 {
            pool.append(IPEndpoint(address: try #require(IPAddress(bytes: [10, 9, 0, UInt8(index)])), port: 41641))
        }
        var state = PeerPathState(homeDERP: 1, endpoints: Array(pool.prefix(3)))
        var now = pathT0
        var seenTxIDs: [TransactionID] = []
        var log: [String] = []

        func anyTxID(_ random: inout PathTestRandom) -> TransactionID {
            if !seenTxIDs.isEmpty, Bool.random(using: &random), let known = seenTxIDs.randomElement(using: &random) {
                return known
            }
            return TransactionID.random(using: &random)
        }
        func someAddresses(_ random: inout PathTestRandom) -> [IPEndpoint] {
            (0..<Int.random(in: 0...6, using: &random)).compactMap { _ in pool.randomElement(using: &random) }
        }
        func note(_ actions: [PeerPathState.Action]) {
            for case let .ping(txID, _) in actions { seenTxIDs.append(txID) }
            log.append("\(actions)")
        }

        for _ in 0..<5000 {
            if Int.random(in: 0..<20, using: &random) == 0 {
                now = now - .milliseconds(Int64.random(in: 0...2000, using: &random))
            } else {
                now = now + .milliseconds(Int64.random(in: 0...4000, using: &random))
            }
            switch Int.random(in: 0..<8, using: &random) {
            case 0:
                state.update(homeDERP: Int64.random(in: 0...2, using: &random), endpoints: someAddresses(&random), at: now)
            case 1:
                state.resetForNewDiscoKey()
            case 2:
                let plan = state.planSend(at: now, using: &random)
                note(plan.actions)
                log.append("\(String(describing: plan.udp)) \(plan.derpRegion)")
            case 3:
                let source = try #require(pool.randomElement(using: &random))
                log.append("\(state.receivePing(anyTxID(&random), from: source, at: now))")
            case 4, 5:
                let source = Bool.random(using: &random) ? pool.randomElement(using: &random) : nil
                log.append("\(state.receivePong(anyTxID(&random), from: source, at: now))")
            case 6:
                note(state.receiveCallMeMaybe(someAddresses(&random), at: now, using: &random))
            default:
                note(state.advance(to: now, using: &random))
            }
            log.append("\(state.path(at: now)) \(String(describing: state.nextDeadline.map { $0 - pathT0 }))")

            #expect(state.candidates.count <= PeerPathState.maxCandidates)
            #expect(state.sentPings.count <= PeerPathState.maxSentPings)
            #expect(Set(state.candidates.map(\.address)).count == state.candidates.count)
            #expect(state.candidates.allSatisfy { $0.address.address.isIPv4 && $0.address.port != 0 })
            if let best = state.bestAddr {
                #expect(state.candidates.contains { $0.address == best.address })
                #expect(best.latency >= .zero && best.latency < PeerPathState.pingTimeout)
            } else {
                #expect(state.trustedUntil == nil)
            }
        }
        return log
    }
}
