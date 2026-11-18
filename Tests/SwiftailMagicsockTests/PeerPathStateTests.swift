// Contract test 3 covers the per-peer path state machine. Passing times directly makes the tests deterministic.
//
// Expected values come from `docs/protocol-notes/disco-magicsock.md` §§4.4–4.8 and §5 and the Go implementation cited there.
// Origin is tailscale.com v1.104.6 `wgengine/magicsock/endpoint.go` (`betterAddr`, `heartbeat`, `wantFullPingLocked`,
// `sendDiscoPingsLocked`, `discoPingTimeout`, `handlePongConnLocked`, `handleCallMeMaybe`, `shouldDeleteLocked`).
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import Testing

import SwiftailBase
@testable import SwiftailMagicsock

@Suite("PeerPathState")
struct PeerPathStateTests {
    // MARK: Candidates

    @Test("Netmap candidates are IPv4 only, with IPv4-mapped addresses unwrapped and port 0 and duplicates discarded")
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

    @Test("The first send uses DERP, Pings all candidates, and emits CallMeMaybe")
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
        // The heartbeat is scheduled for 3 seconds later, before the Ping deadline (5 seconds).
        #expect(state.nextDeadline == pathTime(3000))
    }

    @Test("Home DERP 0 suppresses CallMeMaybe, and without candidates there is nowhere to send")
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

        // With no candidates, there are no Pings and therefore no CallMeMaybe even if there is a home DERP (notes §4.8 1).
        var noCandidates = PeerPathState(homeDERP: 3, endpoints: [])
        let derpOnly = noCandidates.planSend(at: pathT0, using: &random)
        #expect(derpOnly == .init(udp: nil, derpRegion: 3, actions: []))
    }

    @Test("Adds the source of a UDP Ping as a candidate and skips a Pong for the same TxID from the same candidate")
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
            // It replies again if the same TxID was not the one immediately before (Go remembers only the last TxID).
            state.receivePing(first, from: source, at: pathTime(300)),
        ]
        #expect(answers == [true, false, true, true])
        #expect(state.candidates.map(\.address) == [source])
        let plan = state.planSend(at: pathTime(400), using: &random)
        #expect(plan.actions.pingDestinations == [source])
    }

    @Test("Pings from IPv6 or port 0 sources create no candidate and get no Pong")
    func unsupportedPingSources() throws {
        var state = PeerPathState(homeDERP: 1, endpoints: [])
        var random = PathTestRandom(state: 1)
        let txID = TransactionID.random(using: &random)
        let fromIPv6 = state.receivePing(txID, from: try pathEndpoint("[2001:db8::7]:41641"), at: pathT0)
        let fromPortZero = state.receivePing(txID, from: try pathEndpoint("10.0.0.1:0"), at: pathT0)
        #expect(!fromIPv6)
        #expect(!fromPortZero)
        #expect(state.candidates.isEmpty)

        // Unwrap IPv4-mapped addresses before adding them.
        let fromMapped = state.receivePing(txID, from: try pathEndpoint("[::ffff:10.0.0.1]:41641"), at: pathT0)
        #expect(fromMapped)
        #expect(state.candidates.map(\.address) == [try pathEndpoint("10.0.0.1:41641")])
    }

    @Test("A netmap candidate retains its netmap origin after a Ping and is deleted if removed from netmap")
    func netmapCandidateStaysNetmapSourced() throws {
        let a = try pathEndpoint("192.168.1.10:41641")
        var state = PeerPathState(homeDERP: 1, endpoints: [a])
        var random = PathTestRandom(state: 1)
        let answered = state.receivePing(TransactionID.random(using: &random), from: a, at: pathT0)
        #expect(answered)
        state.update(homeDERP: 1, endpoints: [], at: pathTime(1000))
        #expect(state.candidates.isEmpty)
    }

    @Test("Removes a candidate learned from a Ping more than 45 seconds after the last Ping")
    func pingLearnedCandidateExpires() throws {
        let source = try pathEndpoint("198.51.100.4:50000")
        var state = PeerPathState(homeDERP: 1, endpoints: [])
        var random = PathTestRandom(state: 1)
        _ = state.receivePing(TransactionID.random(using: &random), from: source, at: pathT0)
        // Receiving another Ping at 40 seconds moves the reference time to 40 seconds.
        _ = state.receivePing(TransactionID.random(using: &random), from: source, at: pathTime(40_000))

        var atLimit = state
        let atLimitPlan = atLimit.planSend(at: pathTime(85_000), using: &random)
        #expect(atLimitPlan.actions.pingDestinations == [source])
        var afterLimit = state
        let plan = afterLimit.planSend(at: pathTime(85_000) + .nanoseconds(1), using: &random)
        #expect(plan.actions.isEmpty)
        #expect(afterLimit.candidates.isEmpty)
    }

    @Test("A netmap update changes home DERP, deletes removed netmap candidates, and clears bestAddr as well")
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

    // MARK: Pong and bestAddr

    @Test("A UDP Pong for a Ping to a candidate establishes bestAddr and sends use only UDP for 6.5 seconds")
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
        // A second Pong with the same TxID is unrecognized.
        let duplicate = state.receivePong(txID, from: a, at: pathTime(30))
        #expect(!duplicate)
    }

    @Test("bestAddr is the candidate the Ping was sent to, independent of the Pong source")
    func bestAddrIsPingDestination() throws {
        let a = try pathEndpoint("192.168.1.10:41641")
        var state = PeerPathState(homeDERP: 1, endpoints: [a])
        var random = PathTestRandom(state: 1)
        let txID = try state.planSend(at: pathT0, using: &random).actions.txID(to: a)
        let accepted = state.receivePong(txID, from: try pathEndpoint("203.0.113.99:1234"), at: pathTime(5))
        #expect(accepted)
        #expect(state.path(at: pathTime(5)) == .direct(a))
    }

    @Test("A DERP Pong, an unknown TxID, or a Pong for a Ping to a removed candidate leaves bestAddr unset")
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

    @Test("betterAddr favors an address over none and gives an equal address no preference")
    func betterAddrBasics() throws {
        let a = PeerPathState.AddressQuality(address: try pathEndpoint("203.0.113.1:41641"), latency: .milliseconds(10))
        let sameAddressFaster = PeerPathState.AddressQuality(address: a.address, latency: .milliseconds(1))
        #expect(PeerPathState.isBetter(a, than: nil))
        #expect(!PeerPathState.isBetter(sameAddressFaster, than: a))
    }

    @Test("betterAddr favors loopback +50 over LAN +20 and link-local +30 over private")
    func betterAddrPreferencePoints() throws {
        func quality(_ text: String, _ milliseconds: Int64) throws -> PeerPathState.AddressQuality {
            .init(address: try pathEndpoint(text), latency: .milliseconds(milliseconds))
        }
        let loopback = try quality("127.0.0.1:41641", 1)
        let lan = try quality("192.168.1.10:41641", 1)
        #expect(PeerPathState.isBetter(loopback, than: lan))
        #expect(!PeerPathState.isBetter(lan, than: loopback))

        #expect(PeerPathState.isBetter(try quality("169.254.1.1:41641", 1), than: try quality("10.0.0.1:41641", 1)))
        // The boundary of 172.16.0.0/12. 172.31 is private and 172.32 is public.
        #expect(PeerPathState.isBetter(try quality("172.31.0.1:41641", 1), than: try quality("172.32.0.1:41641", 1)))
        #expect(!PeerPathState.isBetter(try quality("172.32.0.1:41641", 1), than: try quality("172.16.0.1:41641", 1)))
        // A large latency difference outweighs address type points. LAN at 10 ms versus loopback at 1 ms scores 20 versus 90 + 50 points.
        #expect(!PeerPathState.isBetter(try quality("192.168.1.10:41641", 10), than: loopback))
    }

    @Test("betterAddr latency ratio score and 1-point rule")
    func betterAddrLatencyPoints() throws {
        func quality(_ text: String, _ milliseconds: Int64) throws -> PeerPathState.AddressQuality {
            .init(address: try pathEndpoint(text), latency: .milliseconds(milliseconds))
        }
        // 10 ms versus 20 ms. The faster address scores 100 − 1000/20 = 50 points.
        #expect(PeerPathState.isBetter(try quality("203.0.113.1:1", 10), than: try quality("198.51.100.1:1", 20)))
        #expect(!PeerPathState.isBetter(try quality("203.0.113.1:1", 20), than: try quality("198.51.100.1:1", 10)))
        // 99 ms versus 100 ms. A 1-point advantage keeps the address. 98 ms gives 2 points and switches it.
        #expect(!PeerPathState.isBetter(try quality("203.0.113.1:1", 99), than: try quality("198.51.100.1:1", 100)))
        #expect(PeerPathState.isBetter(try quality("203.0.113.1:1", 98), than: try quality("198.51.100.1:1", 100)))
        // Public addresses with all latencies at 0 do not trigger a switch.
        #expect(!PeerPathState.isBetter(try quality("203.0.113.1:1", 0), than: try quality("198.51.100.1:1", 0)))
    }

    @Test("When both loopback and LAN endpoints arrive from the same machine, loopback becomes bestAddr (calculation in notes §4.7)")
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

    @Test("Trust prevents switching to a worse address. After trust expires, a Pong can switch the address")
    func replacementRules() throws {
        let loopback = try pathEndpoint("127.0.0.1:41641")
        let publicAddress = try pathEndpoint("203.0.113.7:41641")
        var state = PeerPathState(homeDERP: 1, endpoints: [loopback, publicAddress])
        var random = PathTestRandom(state: 1)

        let first = state.planSend(at: pathT0, using: &random).actions
        _ = state.receivePong(try first.txID(to: loopback), from: loopback, at: pathTime(1))
        _ = state.receivePong(try first.txID(to: publicAddress), from: publicAddress, at: pathTime(2))
        #expect(state.path(at: pathTime(2)) == .direct(loopback))
        // A Pong from a worse address does not extend trust. It lasts through loopback Pong (1 ms) + 6.5 seconds.
        #expect(state.trustedUntil == pathTime(6501))

        // At 7 seconds, trust has expired. Send over UDP + DERP and Ping both candidates again.
        let retry = state.planSend(at: pathTime(7000), using: &random)
        #expect(retry.udp == loopback)
        #expect(retry.derpRegion == 1)
        #expect(retry.actions.pingDestinations == [loopback, publicAddress])
        // Trust has expired, so the first Pong, from the public address, makes that address bestAddr.
        _ = state.receivePong(try retry.actions.txID(to: publicAddress), from: publicAddress, at: pathTime(7001))
        #expect(state.path(at: pathTime(7001)) == .direct(publicAddress))
        // With the same latency, loopback scores 50 points higher, so switch back.
        _ = state.receivePong(try retry.actions.txID(to: loopback), from: loopback, at: pathTime(7001))
        #expect(state.path(at: pathTime(7001)) == .direct(loopback))
    }

    // MARK: Trust period

    @Test("Trust includes the exact time of the last Pong + 6.5 seconds")
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

        // Once trust expires, send to both bestAddr and DERP and Ping candidates whose 5 seconds have elapsed.
        var afterUntil = state
        let plan = afterUntil.planSend(at: until + .nanoseconds(1), using: &random)
        #expect(plan.udp == a)
        #expect(plan.derpRegion == 1)
        #expect(plan.actions.pingDestinations == [a])
        #expect(plan.actions.last == .callMeMaybe)
    }

    @Test("Trust expiration is a deadline. advance 1 nanosecond after expiration switches the path to DERP")
    func trustExpiryIsADeadline() throws {
        let a = try pathEndpoint("192.168.1.10:41641")
        var state = PeerPathState(homeDERP: 1, endpoints: [a])
        var random = PathTestRandom(state: 1)
        // When CallMeMaybe emits a Ping, there is no send history or heartbeat, so the only deadlines are Ping and trust.
        let txID = try state.receiveCallMeMaybe([], at: pathT0, using: &random).txID(to: a)
        _ = state.receivePong(txID, from: a, at: pathTime(10))
        let expiry = pathTime(6510) + .nanoseconds(1)
        #expect(state.nextDeadline == expiry)

        let actions = state.advance(to: expiry, using: &random)
        #expect(actions.isEmpty)
        #expect(state.path(at: expiry) == .relayed(derpRegion: 1))
        #expect(state.nextDeadline == nil)
        // bestAddr remains, so it still sends over UDP as well.
        #expect(state.bestAddr?.address == a)
    }

    // MARK: Ping interval and deadline

    @Test("A candidate is not Pinged again within 5 seconds unless an incoming CallMeMaybe lifts the limit")
    func perCandidatePingInterval() throws {
        let a = try pathEndpoint("192.168.1.10:41641")
        var state = PeerPathState(homeDERP: 1, endpoints: [a])
        var random = PathTestRandom(state: 1)
        _ = state.planSend(at: pathT0, using: &random)

        var soon = state
        // No Ping went out, so there is no CallMeMaybe either.
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
        // The full Ping sweep triggered by an incoming CallMeMaybe sends no CallMeMaybe back.
        #expect(callActions.callMeMaybeCount == 0)
    }

    @Test("The Ping deadline is 5 seconds. Accepts a Pong up to just before it and clears the Ping at that instant")
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

    @Test("An expired bestAddr Ping leaves bestAddr in place if still trusted and clears it if trust has expired")
    func pingTimeoutAndBestAddr() throws {
        let a = try pathEndpoint("127.0.0.1:41641")
        var harness = PathHarness(PeerPathState(homeDERP: 1, endpoints: [a]))
        harness.responders = [a: .milliseconds(1)]
        harness.send()
        // The first Pong (1 ms) sets trust through 6.501 seconds. The 3-second heartbeat Ping and Pong extend it.
        harness.run(until: pathTime(3500))
        #expect(harness.state.trustedUntil == pathTime(9501))

        // Drop the Ping for the 6-second heartbeat and receive the Pong for the 9-second heartbeat.
        harness.responders = [:]
        harness.run(until: pathTime(8000))
        harness.responders = [a: .milliseconds(1)]
        harness.run(until: pathTime(9500))
        #expect(harness.state.trustedUntil == pathTime(15_501))
        // At the 6-second Ping's deadline (11 seconds), trust remains and bestAddr stays in place.
        harness.run(until: pathTime(11_000))
        #expect(harness.state.sentPings.isEmpty)
        #expect(harness.state.path(at: pathTime(11_000)) == .direct(a))

        // Drop all from 12 seconds on. Trust expires at 15.501 seconds, and the 12-second Ping's deadline (17 seconds) clears bestAddr.
        harness.responders = [:]
        harness.run(until: pathTime(16_999))
        #expect(harness.state.path(at: pathTime(16_999)) == .relayed(derpRegion: 1))
        #expect(harness.state.bestAddr?.address == a)
        harness.run(until: pathTime(17_000))
        #expect(harness.state.bestAddr == nil)
    }

    // MARK: Heartbeat and full Ping sweeps

    @Test("Heartbeat runs every 3 seconds, stops more than 45 seconds after the last send, and restarts on the next send")
    func heartbeatStopsWhenIdle() throws {
        let a = try pathEndpoint("192.168.1.10:41641")
        var harness = PathHarness(PeerPathState(homeDERP: 1, endpoints: [a]))
        harness.send()
        harness.run(until: pathTime(45_000))
        // The 45-second heartbeat still runs (it stops after "more than" 45 seconds).
        #expect(harness.state.heartbeatDeadline == pathTime(48_000))
        harness.run(until: pathTime(60_000))
        #expect(harness.state.heartbeatDeadline == nil)
        #expect(harness.state.nextDeadline == nil)

        // The 5-second limit causes Pings to an unresponsive candidate every 6 seconds, each with a CallMeMaybe.
        let expected = [0, 6, 12, 18, 24, 30, 36, 42].map { pathTime(Int64($0) * 1000) }
        #expect(harness.pingTimes(to: a) == expected)
        #expect(harness.actions.filter { $0.action == .callMeMaybe }.map(\.time) == expected)

        let resumed = harness.send()
        #expect(resumed.actions.pingDestinations == [a])
        #expect(harness.state.heartbeatDeadline == pathTime(63_000))
    }

    @Test("A trusted direct path with latency of 5 ms or less skips full Ping sweeps")
    func noFullPingWhenGoodEnough() throws {
        let loopback = try pathEndpoint("127.0.0.1:41641")
        let lan = try pathEndpoint("192.168.1.10:41641")
        var harness = PathHarness(PeerPathState(homeDERP: 1, endpoints: [loopback, lan]))
        harness.responders = [loopback: .milliseconds(1), lan: .milliseconds(1)]
        harness.send()
        harness.sendRepeatedly(every: .seconds(1))
        harness.run(until: pathTime(130_000))

        #expect(harness.pingTimes(to: lan) == [pathT0])
        // Heartbeat Pings bestAddr every 3 seconds.
        #expect(harness.pingTimes(to: loopback).count == 1 + 43)
        #expect(harness.state.path(at: pathTime(130_000)) == .direct(loopback))
    }

    @Test("A direct path with more than 5 ms latency runs a full Ping sweep at 1-minute intervals after the last full sweep")
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

    @Test("Blocking the direct path causes sends over UDP + DERP after trust expires, then DERP only after the deadline. Unblocking restores direct")
    func blockAndUnblock() throws {
        let a = try pathEndpoint("127.0.0.1:41641")
        var harness = PathHarness(PeerPathState(homeDERP: 1, endpoints: [a]))
        harness.responders = [a: .milliseconds(1)]
        harness.send()
        harness.sendRepeatedly(every: .seconds(1))
        harness.run(until: pathTime(30_500))
        // The 30-second heartbeat's Pong (30.001 seconds) + 6.5 seconds.
        #expect(harness.state.trustedUntil == pathTime(36_501))

        harness.responders = [:]
        harness.run(until: pathTime(36_501))
        #expect(harness.state.path(at: pathTime(36_501)) == .direct(a))
        harness.run(until: pathTime(36_501) + .nanoseconds(1))
        #expect(harness.state.path(at: pathTime(36_501) + .nanoseconds(1)) == .relayed(derpRegion: 1))

        harness.run(until: pathTime(40_500))
        // At 37 seconds, use both bestAddr and DERP. Skip candidates Pinged at 36 seconds due to the 5-second limit.
        #expect(try harness.plan(at: pathTime(37_000)) == .init(udp: a, derpRegion: 1, actions: []))
        // At 38 seconds, the 33-second heartbeat Ping's deadline has cleared bestAddr because trust expired. Send only over DERP.
        #expect(try harness.plan(at: pathTime(38_000)) == .init(udp: nil, derpRegion: 1, actions: []))

        harness.responders = [a: .milliseconds(1)]
        harness.run(until: pathTime(41_000))
        // On the send at 41 seconds, 5 seconds have passed since the last Ping (36 seconds), so Ping again and emit CallMeMaybe.
        let retry = try harness.plan(at: pathTime(41_000))
        #expect(retry.actions.pingDestinations == [a])
        #expect(retry.actions.last == .callMeMaybe)
        #expect(harness.state.path(at: pathTime(41_000)) == .relayed(derpRegion: 1))
        harness.run(until: pathTime(41_001))
        #expect(harness.state.path(at: pathTime(41_001)) == .direct(a))
    }

    // MARK: CallMeMaybe

    @Test("An incoming CallMeMaybe adds addresses as candidates. Addresses omitted from the next CallMeMaybe are removed regardless of source")
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

        // Removes both a, which also came from netmap, and c, which is bestAddr.
        _ = state.receiveCallMeMaybe([d], at: pathTime(1000), using: &random)
        #expect(state.candidates.map(\.address) == [d])
        #expect(state.bestAddr == nil)

        // CallMeMaybe candidates persist even if removed from netmap and after 45 seconds.
        state.update(homeDERP: 1, endpoints: [a], at: pathTime(100_000))
        #expect(state.candidates.map(\.address) == [d, a])
    }

    // MARK: Disco key changes

    @Test("A disco key change clears trust and pending Pings and retains the bestAddr address for immediate rediscovery")
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

        // If there are no sends, the next heartbeat stops.
        var idle = state
        let idleActions = idle.advance(to: pathTime(6000), using: &random)
        #expect(idleActions.isEmpty)
        #expect(idle.heartbeatDeadline == nil)

        // The next send uses UDP + DERP and immediately Pings even candidates that were Pinged 3 seconds ago.
        let plan = state.planSend(at: pathTime(3100), using: &random)
        #expect(plan.udp == a)
        #expect(plan.derpRegion == 1)
        #expect(plan.actions.pingDestinations == [a])
        #expect(plan.actions.last == .callMeMaybe)
    }

    // MARK: Limits

    @Test("Candidates are capped at 128, and excess incoming Pings do not evict an existing bestAddr")
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
            // Still send a Pong if the candidate cannot be added.
            let answered = state.receivePing(TransactionID.random(using: &random), from: source, at: pathTime(2))
            #expect(answered)
        }
        #expect(state.candidates.count == PeerPathState.maxCandidates)
        #expect(state.path(at: pathTime(2)) == .direct(a))

        // When a new netmap candidate arrives and the table is full, it displaces a candidate learned only from a Ping. Once Ping-learned candidates exceed 45 seconds of age,
        // they are removed.
        state.update(homeDERP: 1, endpoints: [a, late], at: pathTime(3))
        #expect(state.candidates.contains { $0.address == late })
        #expect(state.candidates.count == PeerPathState.maxCandidates)
        #expect(state.path(at: pathTime(3)) == .direct(a))
        state.update(homeDERP: 1, endpoints: [a, late], at: pathTime(45_002) + .nanoseconds(1))
        #expect(state.candidates.map(\.address) == [a, late])
    }

    /// 10.1.x.y:41641. Used as a source when replaying captured Pings.
    private func replaySource(_ index: Int) throws -> IPEndpoint {
        IPEndpoint(
            address: try #require(IPAddress(bytes: [10, 1, UInt8(index / 256), UInt8(index % 256)])), port: 41641)
    }

    @Test("Even if 128 captured Pings from different addresses fill the table, the source of a new Ping becomes a candidate and evicts the oldest one")
    func fullTableAdmitsNewPingSource() throws {
        var state = PeerPathState(homeDERP: 1, endpoints: [])
        var random = PathTestRandom(state: 1)
        // Repeating one Ping creates only one candidate (`knownPingFromNewSourceIsNotCandidate`).
        for index in 0..<PeerPathState.maxCandidates {
            let captured = TransactionID.random(using: &random)
            #expect(state.receivePing(captured, from: try replaySource(index), at: pathTime(Int64(index))) == true)
        }
        #expect(state.candidates.count == PeerPathState.maxCandidates)

        let real = try pathEndpoint("203.0.113.7:41641")
        #expect(state.receivePing(TransactionID.random(using: &random), from: real, at: pathTime(1_000)) == true)
        #expect(state.candidates.contains { $0.address == real })
        #expect(state.candidates.count == PeerPathState.maxCandidates)
        // The evicted candidate is the one whose last Ping was received longest ago.
        #expect(!state.candidates.contains { $0.address == (try? replaySource(0)) })
        #expect(state.candidates.contains { $0.address == (try? replaySource(1)) })
    }

    @Test("A full table never evicts netmap or CallMeMaybe candidates or bestAddr. With no candidate to evict, the new candidate is omitted")
    func fullTableKeepsTrustedSources() throws {
        let fromNetmap = try pathEndpoint("192.168.1.10:41641")
        let called = try pathEndpoint("192.168.1.11:41641")
        let best = try pathEndpoint("192.168.1.12:41641")
        var state = PeerPathState(homeDERP: 1, endpoints: [fromNetmap])
        var random = PathTestRandom(state: 1)
        // `best` was learned from a Ping and confirmed by a Pong. It was learned first, so its Ping was received longest ago.
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

        // If the table is filled with netmap candidates only, nothing can be evicted. Reply to the Ping without adding a candidate.
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

    @Test("Replaying the same TxID leaves a Ping-learned candidate's lifetime (45 seconds) unchanged. A Ping with a new TxID extends it")
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

    @Test("Alternating two previously seen TxIDs leaves the candidate's lifetime (45 seconds) unchanged")
    func alternatingKnownPingsDoNotExtendLifetime() throws {
        let source = try pathEndpoint("203.0.113.7:41641")
        var random = PathTestRandom(state: 1)
        let first = TransactionID.random(using: &random)
        let second = TransactionID.random(using: &random)
        var state = PeerPathState(homeDERP: 1, endpoints: [])
        #expect(state.receivePing(first, from: source, at: pathT0) == true)
        #expect(state.receivePing(second, from: source, at: pathTime(1_000)) == true)
        // Replay the two Pings in alternating order every 10 seconds. Each TxID differs from the immediately preceding one.
        for (round, txID) in [first, second, first, second].enumerated() {
            _ = state.receivePing(txID, from: source, at: pathTime(Int64(round + 1) * 10_000))
        }
        // The last new TxID arrived at 1 second.
        state.update(homeDERP: 1, endpoints: [], at: pathTime(46_000))
        #expect(state.candidates.map(\.address) == [source])
        state.update(homeDERP: 1, endpoints: [], at: pathTime(46_000) + .nanoseconds(1))
        #expect(state.candidates.isEmpty)
    }

    @Test("Replaying a seen TxID from another source creates no candidate. Changing the disco key clears seen TxIDs")
    func knownPingFromNewSourceIsNotCandidate() throws {
        let source = try pathEndpoint("203.0.113.7:41641")
        let elsewhere = try pathEndpoint("198.51.100.4:50000")
        var random = PathTestRandom(state: 1)
        let seen = TransactionID.random(using: &random)
        var state = PeerPathState(homeDERP: 1, endpoints: [])
        #expect(state.receivePing(seen, from: source, at: pathT0) == true)
        _ = state.receivePing(seen, from: elsewhere, at: pathTime(1_000))
        #expect(state.candidates.map(\.address) == [source])

        // A new TxID from any source still creates a candidate as before.
        #expect(state.receivePing(TransactionID.random(using: &random), from: elsewhere, at: pathTime(2_000)) == true)
        #expect(state.candidates.map(\.address) == [source, elsewhere])

        // A Ping under the new disco key is never compared with TxIDs seen under the old key.
        var rekeyed = PeerPathState(homeDERP: 1, endpoints: [])
        #expect(rekeyed.receivePing(seen, from: source, at: pathT0) == true)
        rekeyed.resetForNewDiscoKey()
        #expect(rekeyed.receivePing(seen, from: elsewhere, at: pathTime(1_000)) == true)
        #expect(rekeyed.candidates.map(\.address) == [source, elsewhere])
    }

    @Test("Remembers up to 32 seen TxIDs and forgets the earliest seen once more Pings have passed through")
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

    @Test("Adds only the first 128 CallMeMaybe and netmap addresses")
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

    @Test("Caps pending Pings at 128 and sends again once deadlines clear the table")
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

    // MARK: Arbitrary input sequences

    @Test("Arbitrary sequences (including backward time, duplicate and unknown TxIDs, port 0, and IPv6) do not crash, preserve invariants, and are deterministic")
    func randomInputSequences() throws {
        let first = try runRandomSequence(seed: 0x5EED)
        let second = try runRandomSequence(seed: 0x5EED)
        #expect(first == second)
        #expect(first != (try runRandomSequence(seed: 0x5EED + 1)))
    }

    /// Runs 5,000 steps with a fixed seed and records all outputs. Checks invariants at each step.
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
