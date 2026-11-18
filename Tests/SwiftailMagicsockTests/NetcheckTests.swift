import Testing

import SwiftailBase

@testable import SwiftailMagicsock

/// Tests STUN rounds, local endpoint lists, and home region selection (contract E2–E6, DERP notes §4.10 5). Pass times directly with `Harness.at(_:)`.
///
/// Reference values are the constants and conditions in Go `net/netcheck/netcheck.go` (line references are in `Netcheck.swift` and `Netcheck+Home.swift`).
/// In these tests, region `n` has STUN server `192.0.2.n:3478`, so the request destination identifies the region.
@Suite("Netcheck")
struct NetcheckTests {
    private typealias Action = Netcheck.Action
    private typealias Region = Magicsock.Region
    private typealias Endpoint = Magicsock.Endpoint

    /// A deterministic generator (SplitMix64) for tests only.
    private struct SplitMix: RandomNumberGenerator {
        var state: UInt64
        mutating func next() -> UInt64 {
            state &+= 0x9e37_79b9_7f4a_7c15
            var z = state
            z = (z ^ (z >> 30)) &* 0xbf58_476d_1ce4_e5b9
            z = (z ^ (z >> 27)) &* 0x94d0_49bb_1331_11eb
            return z ^ (z >> 31)
        }
    }

    private static func endpoint(_ text: String) -> IPEndpoint { IPEndpoint(text)! }
    private static func address(_ text: String) -> IPAddress { IPAddress(text)! }

    private static func region(_ id: Int64, servers: Int = 1, score: Double = 0) -> Region {
        let stun = (0..<servers).map { endpoint("192.0.2.\(id):\(3478 + $0)") }
        return Region(id: id, stunServers: stun, score: score)
    }

    private static func local(_ text: String) -> Endpoint { Endpoint(address: endpoint(text), source: .local) }
    private static func stun(_ text: String) -> Endpoint { Endpoint(address: endpoint(text), source: .stun) }

    /// One request with its TxID and destination.
    private struct Request: Equatable {
        var txID: TransactionID
        var server: IPEndpoint
        var region: Int64 { Int64(server.address.bytes[3]) }
    }

    /// The `Netcheck`, generator, and reference time for one test.
    private struct Harness {
        var netcheck = Netcheck(
            localPort: 41641,
            localAddresses: [NetcheckTests.address("10.0.0.5"), NetcheckTests.address("192.168.1.2")],
            loopbackAddresses: [NetcheckTests.address("127.0.0.1")]
        )
        var generator = SplitMix(state: 42)
        let origin = ContinuousClock.now

        func at(_ milliseconds: Int) -> ContinuousClock.Instant { origin + .milliseconds(milliseconds) }

        mutating func setRegions(_ regions: [Region], atMs ms: Int = 0) -> [Action] {
            netcheck.setRegions(regions, at: at(ms), using: &generator)
        }

        mutating func reSTUN(atMs ms: Int) -> [Action] {
            netcheck.reSTUN(at: at(ms), using: &generator)
        }

        mutating func advance(toMs ms: Int, isActive: Bool = true) -> [Action] {
            netcheck.advance(to: at(ms), isActive: isActive, using: &generator)
        }

        mutating func receive(_ request: Request, mapped: String = "203.0.113.7:50000", atMs ms: Int) -> [Action]? {
            netcheck.receive(request.txID, mapped: NetcheckTests.endpoint(mapped), at: at(ms))
        }

        /// Starts a new round at `startMs`, answers each first request at the region's latency in ms, and finishes at the 3-second deadline if still running.
        /// Returns actions other than outgoing requests.
        mutating func runRound(startMs: Int, latencies: [Int64: Int], mapped: String = "203.0.113.7:50000") -> [Action] {
            var actions = reSTUN(atMs: startMs)
            let requests = Self.requests(in: actions)
            for (region, latency) in latencies.sorted(by: { ($0.value, $0.key) < ($1.value, $1.key) }) {
                guard let request = requests.first(where: { $0.region == region }) else { continue }
                actions += receive(request, mapped: mapped, atMs: startMs + latency) ?? []
            }
            if netcheck.round != nil {
                actions += advance(toMs: startMs + 3000)
            }
            return Self.withoutRequests(actions)
        }

        /// Sends all three requests per region (0, 100, and 200 ms), then supplies one reply for each (region, external address) pair in the given order.
        /// Matches replies from the same region to that region's requests in send order. If any region has yet to reply, finishes at the 3-second deadline.
        /// Returns actions other than outgoing requests.
        mutating func runRoundWithAddresses(startMs: Int, responses: [(region: Int64, mapped: String)]) -> [Action] {
            var actions = reSTUN(atMs: startMs)
            actions += advance(toMs: startMs + 100)
            actions += advance(toMs: startMs + 200)
            var requests = Self.requests(in: actions)
            for (index, response) in responses.enumerated() {
                guard let position = requests.firstIndex(where: { $0.region == response.region }) else { continue }
                let request = requests.remove(at: position)
                actions += receive(request, mapped: response.mapped, atMs: startMs + 200 + 10 * (index + 1)) ?? []
            }
            if netcheck.round != nil { actions += advance(toMs: startMs + 3000) }
            return Self.withoutRequests(actions)
        }

        /// Returns actions other than outgoing requests. Use this to see only round results (endpoints, home, and refresh).
        static func withoutRequests(_ actions: [Action]) -> [Action] {
            actions.filter { if case .sendSTUN = $0 { false } else { true } }
        }

        static func requests(in actions: [Action]) -> [Request] {
            actions.compactMap { action in
                guard case let .sendSTUN(bytes, to: server) = action, let txID = TransactionID(bytes[8..<20]) else { return nil }
                return Request(txID: txID, server: server)
            }
        }
    }

    // MARK: Round starts and requests

    @Test("Sends one request per region at 0, 100, and 200 ms to stunServers[try % count]")
    func requestSchedule() throws {
        var harness = Harness()
        let first = harness.setRegions([Self.region(1, servers: 2)])
        #expect(first.first == .homeRegionChanged(1))
        let initial = Harness.requests(in: first)
        #expect(initial.map(\.server) == [Self.endpoint("192.0.2.1:3478")])
        // The request is 40 bytes as in notes §3.8 and contains a TxID.
        guard case let .sendSTUN(bytes, to: _) = first[1] else { Issue.record("Missing the first request"); return }
        #expect(bytes == STUNMessage.bindingRequest(initial[0].txID))
        #expect(bytes.count == 40)

        #expect(harness.netcheck.nextDeadline == harness.at(100))
        #expect(harness.advance(toMs: 99).isEmpty)
        let second = Harness.requests(in: harness.advance(toMs: 100))
        #expect(second.map(\.server) == [Self.endpoint("192.0.2.1:3479")])
        #expect(harness.netcheck.nextDeadline == harness.at(200))
        let third = Harness.requests(in: harness.advance(toMs: 200))
        #expect(third.map(\.server) == [Self.endpoint("192.0.2.1:3478")])
        #expect(harness.netcheck.nextDeadline == harness.at(3000))

        let ids = Set([initial[0].txID, second[0].txID, third[0].txID])
        #expect(ids.count == 3)
    }

    @Test("One round sends at most the number of regions × 3 requests")
    func requestCountIsBounded() {
        var harness = Harness()
        var actions = harness.setRegions([Self.region(1), Self.region(2, servers: 3), Self.region(3)])
        for ms in stride(from: 50, through: 2900, by: 50) {
            actions += harness.advance(toMs: ms)
        }
        #expect(Harness.requests(in: actions).count == 9)
        #expect(harness.netcheck.round?.inFlight.count == 9)
    }

    @Test("A late call still sends every past-due request")
    func lateAdvanceSendsAllDueRequests() {
        var harness = Harness()
        _ = harness.setRegions([Self.region(1)])
        let requests = Harness.requests(in: harness.advance(toMs: 250))
        #expect(requests.count == 2)
    }

    @Test("A region's first response cancels all remaining requests for that region")
    func answerCancelsRemainingRequestsOfRegion() throws {
        var harness = Harness()
        let initial = Harness.requests(in: harness.setRegions([Self.region(1), Self.region(2)]))
        let one = try #require(initial.first { $0.region == 1 })
        _ = harness.receive(one, atMs: 40)
        let later = Harness.requests(in: harness.advance(toMs: 100))
        #expect(later.map(\.region) == [2])
        #expect(harness.netcheck.nextDeadline == harness.at(200))
    }

    @Test("If no region has a STUN server, the round ends immediately without sending requests")
    func regionsWithoutSTUNServersEndImmediately() {
        var harness = Harness()
        let actions = harness.setRegions([Region(id: 4, stunServers: []), Region(id: 9, stunServers: [])])
        #expect(actions == [
            .homeRegionChanged(4),
            .endpointsChanged([Self.local("10.0.0.5:41641"), Self.local("192.168.1.2:41641")]),
            .endpointsRefreshed,
        ])
        #expect(harness.netcheck.round == nil)
    }

    // MARK: Matching responses

    @Test("Accepts responses whose TxID matches a request in the active round and yields nil otherwise")
    func matchesResponsesToInFlightRequests() throws {
        var harness = Harness()
        let request = try #require(Harness.requests(in: harness.setRegions([Self.region(1), Self.region(2)])).first)
        let stranger = try #require(TransactionID([UInt8](repeating: 0xee, count: 12)))
        #expect(harness.netcheck.receive(stranger, mapped: Self.endpoint("203.0.113.7:50000"), at: harness.at(10)) == nil)
        #expect(harness.receive(request, atMs: 10) != nil)
        // A second response with the same TxID is rejected.
        #expect(harness.receive(request, atMs: 11) == nil)
    }

    @Test("Responses after a round finishes or with no active round yield nil")
    func responsesOutsideRoundAreRejected() throws {
        var harness = Harness()
        let stranger = try #require(TransactionID([UInt8](repeating: 0x11, count: 12)))
        #expect(harness.netcheck.receive(stranger, mapped: Self.endpoint("203.0.113.7:50000"), at: harness.at(0)) == nil)

        let request = try #require(Harness.requests(in: harness.setRegions([Self.region(1), Self.region(2)])).first)
        _ = harness.advance(toMs: 3000)
        #expect(harness.receive(request, atMs: 3001) == nil)
    }

    @Test("Changing regions rejects responses from the old round")
    func regionChangeDropsOldRound() throws {
        var harness = Harness()
        let old = try #require(Harness.requests(in: harness.setRegions([Self.region(1)])).first)
        let actions = harness.setRegions([Self.region(1), Self.region(2)], atMs: 50)
        #expect(harness.receive(old, atMs: 60) == nil)
        #expect(Harness.requests(in: actions).map(\.region) == [1, 2])
    }

    @Test("An unchanged region list leaves the round running")
    func sameRegionsKeepRound() throws {
        var harness = Harness()
        let request = try #require(Harness.requests(in: harness.setRegions([Self.region(1)])).first)
        #expect(harness.setRegions([Self.region(1)], atMs: 10).isEmpty)
        #expect(harness.receive(request, atMs: 20) != nil)
    }

    @Test("Removing all regions stops the round and preserves endpoints and home")
    func emptyRegionsStopRounds() throws {
        var harness = Harness()
        let request = try #require(Harness.requests(in: harness.setRegions([Self.region(1)])).first)
        #expect(harness.setRegions([], atMs: 10).isEmpty)
        #expect(harness.receive(request, atMs: 20) == nil)
        #expect(harness.netcheck.nextDeadline == nil)
        #expect(harness.netcheck.homeRegion == 1)
        #expect(harness.reSTUN(atMs: 30).isEmpty)
    }

    @Test("With no regions, endpoints are left undetermined")
    func noRegionsNoEndpoints() {
        var harness = Harness()
        #expect(harness.setRegions([]).isEmpty)
        #expect(harness.reSTUN(atMs: 5).isEmpty)
        #expect(harness.netcheck.endpoints.isEmpty)
        #expect(harness.netcheck.endpointsRefreshedAt == nil)
        #expect(harness.netcheck.homeRegion == 0)
    }

    // MARK: Deadline

    @Test("The round finishes 3 seconds after it starts")
    func roundEndsAfterThreeSeconds() throws {
        var harness = Harness()
        _ = harness.setRegions([Self.region(1)])
        _ = harness.advance(toMs: 200)
        #expect(harness.advance(toMs: 2999).isEmpty)
        #expect(harness.netcheck.round != nil)
        let actions = harness.advance(toMs: 3000)
        #expect(actions.last == .endpointsRefreshed)
        #expect(harness.netcheck.round == nil)
        #expect(harness.netcheck.endpointsRefreshedAt == harness.at(3000))
    }

    @Test("If every region replies, the round finishes without waiting 3 seconds")
    func roundEndsWhenAllRegionsAnswer() throws {
        var harness = Harness()
        let requests = Harness.requests(in: harness.setRegions([Self.region(1), Self.region(2)]))
        let firstResult = harness.receive(requests[0], atMs: 20)
        let first = try #require(firstResult)
        #expect(first.isEmpty)
        #expect(harness.netcheck.round != nil)
        let secondResult = harness.receive(requests[1], atMs: 30)
        let second = try #require(secondResult)
        #expect(second.last == .endpointsRefreshed)
        #expect(harness.netcheck.round == nil)
        #expect(harness.netcheck.endpointsRefreshedAt == harness.at(30))
    }

    @Test("The round ends at 3 seconds if a region's STUN servers do not reply, and it never waits for a region with no STUN server")
    func regionWithoutServersIsNotAwaited() throws {
        var harness = Harness()
        let requests = Harness.requests(in: harness.setRegions([Self.region(1), Region(id: 2, stunServers: [])]))
        #expect(requests.map(\.region) == [1])
        let actionsResult = harness.receive(requests[0], atMs: 15)
        let actions = try #require(actionsResult)
        #expect(actions.last == .endpointsRefreshed)
    }

    @Test("A region counts as having replied even if the external address is IPv6 or has port 0")
    func unusableMappedAddressStillCountsAsAnswer() throws {
        var harness = Harness()
        let requests = Harness.requests(in: harness.setRegions([Self.region(1), Self.region(2)]))
        _ = harness.receive(requests[0], mapped: "[2001:db8::1]:50000", atMs: 10)
        let actionsResult = harness.receive(requests[1], mapped: "203.0.113.7:0", atMs: 20)
        let actions = try #require(actionsResult)
        #expect(actions.contains(.endpointsChanged([Self.local("10.0.0.5:41641"), Self.local("192.168.1.2:41641")])))
    }

    // MARK: Endpoint list

    @Test("STUN addresses precede interface addresses in the endpoint list")
    func endpointOrder() throws {
        var harness = Harness()
        let request = try #require(Harness.requests(in: harness.setRegions([Self.region(1)])).first)
        let actionsResult = harness.receive(request, atMs: 12)
        let actions = try #require(actionsResult)
        let expected = [Self.stun("203.0.113.7:50000"), Self.local("10.0.0.5:41641"), Self.local("192.168.1.2:41641")]
        #expect(actions == [.endpointsChanged(expected), .endpointsRefreshed])
        #expect(harness.netcheck.endpoints == expected)
    }

    @Test("Keeps only the first occurrence of an address")
    func duplicatesKeepFirst() throws {
        var harness = Harness()
        let request = try #require(Harness.requests(in: harness.setRegions([Self.region(1)])).first)
        _ = harness.receive(request, mapped: "10.0.0.5:41641", atMs: 12)
        #expect(harness.netcheck.endpoints == [Self.stun("10.0.0.5:41641"), Self.local("192.168.1.2:41641")])
    }

    @Test("Uses loopback addresses only if there are no other endpoints")
    func loopbackOnlyWhenNothingElse() throws {
        var bare = Harness()
        bare.netcheck = Netcheck(localPort: 7000, localAddresses: [], loopbackAddresses: [Self.address("127.0.0.1")])
        _ = bare.setRegions([Self.region(1)])
        _ = bare.advance(toMs: 3000)
        #expect(bare.netcheck.endpoints == [Self.local("127.0.0.1:7000")])

        // A STUN address precludes loopback.
        var withSTUN = Harness()
        withSTUN.netcheck = Netcheck(localPort: 7000, localAddresses: [], loopbackAddresses: [Self.address("127.0.0.1")])
        let request = try #require(Harness.requests(in: withSTUN.setRegions([Self.region(1)])).first)
        _ = withSTUN.receive(request, mapped: "127.0.0.1:7000", atMs: 3)
        #expect(withSTUN.netcheck.endpoints == [Self.stun("127.0.0.1:7000")])

        // An interface address precludes loopback.
        var regular = Harness()
        _ = regular.setRegions([Self.region(1)])
        _ = regular.advance(toMs: 3000)
        #expect(!regular.netcheck.endpoints.contains(Self.local("127.0.0.1:41641")))
    }

    @Test("STUN global addresses are the first response address and addresses observed at least twice")
    func globalAddressRule() throws {
        var harness = Harness()
        var requests = Harness.requests(in: harness.setRegions([Self.region(1), Self.region(2), Self.region(3)]))
        requests += Harness.requests(in: harness.advance(toMs: 100))  // Second request for each region
        #expect(requests.count == 6)
        let regionOne = requests.filter { $0.region == 1 }
        let regionTwo = try #require(requests.first { $0.region == 2 })
        let regionThree = try #require(requests.first { $0.region == 3 })
        let a = "203.0.113.1:1000"
        let b = "203.0.113.2:2000"
        let c = "203.0.113.3:3000"
        _ = harness.receive(regionOne[0], mapped: a, atMs: 110)  // First response. One observation.
        _ = harness.receive(regionOne[1], mapped: b, atMs: 111)
        let second = harness.receive(regionTwo, mapped: b, atMs: 112)  // b has been observed twice.
        #expect(second == [])
        let actions = harness.receive(regionThree, mapped: c, atMs: 113)  // c has been observed once and is omitted from the published list.
        let expected = [Self.stun(a), Self.stun(b), Self.local("10.0.0.5:41641"), Self.local("192.168.1.2:41641")]
        #expect(actions?.contains(.endpointsChanged(expected)) == true)
    }

    @Test("Identical endpoint sets emit endpointsRefreshed without endpointsChanged, even if the order changes")
    func setComparisonIgnoresOrder() throws {
        var harness = Harness()
        _ = harness.setRegions([Self.region(1), Self.region(2)])
        _ = harness.advance(toMs: 3000)
        let a = "203.0.113.1:1000"
        let b = "203.0.113.2:2000"
        let first = harness.runRoundWithAddresses(startMs: 10_000, responses: [(1, a), (1, b), (2, b)])
        #expect(first.contains(.endpointsChanged([Self.stun(a), Self.stun(b), Self.local("10.0.0.5:41641"), Self.local("192.168.1.2:41641")])))
        // In the second round, b replies first and a is observed twice, so the list is [b, a, …].
        let second = harness.runRoundWithAddresses(startMs: 40_000, responses: [(1, b), (1, a), (2, a)])
        #expect(second == [.endpointsRefreshed])
        #expect(harness.netcheck.endpoints.prefix(2).map(\.address) == [Self.endpoint(b), Self.endpoint(a)])
        #expect(harness.netcheck.endpointsRefreshedAt == harness.at(40_000 + 230))
    }

    @Test("A change to the list emits endpointsChanged")
    func changedSetIsReported() throws {
        var harness = Harness()
        _ = harness.setRegions([Self.region(1)])
        _ = harness.advance(toMs: 3000)
        _ = harness.runRound(startMs: 10_000, latencies: [1: 10], mapped: "203.0.113.1:1000")
        let actions = harness.runRound(startMs: 30_000, latencies: [1: 10], mapped: "203.0.113.9:9000")
        #expect(actions.contains(.endpointsChanged([Self.stun("203.0.113.9:9000"), Self.local("10.0.0.5:41641"), Self.local("192.168.1.2:41641")])))
        // Losing the STUN result also counts as a change.
        let silent = harness.runRound(startMs: 60_000, latencies: [:])
        #expect(silent.contains(.endpointsChanged([Self.local("10.0.0.5:41641"), Self.local("192.168.1.2:41641")])))
    }

    // MARK: Periodic rounds

    @Test("When a round ends, schedules the next round 20–26 seconds later and starts it then")
    func periodicRound() throws {
        for seed in UInt64(0)..<20 {
            var harness = Harness()
            harness.generator = SplitMix(state: seed)
            let request = try #require(Harness.requests(in: harness.setRegions([Self.region(1)])).first)
            _ = harness.receive(request, atMs: 10)
            let deadline = try #require(harness.netcheck.nextDeadline)
            let delay = harness.at(10).duration(to: deadline)
            #expect(delay >= .seconds(20) && delay <= .seconds(26))
            #expect(harness.netcheck.round == nil)

            let milliseconds = Int((harness.origin.duration(to: deadline) / .milliseconds(1)).rounded())
            // Nothing happens just before the deadline. A new round starts at the deadline.
            #expect(harness.advance(toMs: milliseconds - 1).isEmpty)
            let started = harness.advance(toMs: milliseconds)
            #expect(Harness.requests(in: started).map(\.region) == [1])
            #expect(harness.netcheck.round != nil)
        }
    }

    @Test("The periodic interval depends on the generator")
    func periodicIntervalVaries() throws {
        var delays: Set<Duration> = []
        for seed in UInt64(0)..<10 {
            var harness = Harness()
            harness.generator = SplitMix(state: seed)
            let request = try #require(Harness.requests(in: harness.setRegions([Self.region(1)])).first)
            _ = harness.receive(request, atMs: 0)
            delays.insert(harness.at(0).duration(to: try #require(harness.netcheck.nextDeadline)))
        }
        #expect(delays.count > 1)
    }

    @Test("Idleness stops periodic rounds and reSTUN restarts them")
    func idleStopsPeriodicRounds() throws {
        var harness = Harness()
        let request = try #require(Harness.requests(in: harness.setRegions([Self.region(1)])).first)
        _ = harness.receive(request, atMs: 10)
        #expect(harness.netcheck.nextDeadline != nil)

        // Reporting idleness cancels the scheduled periodic round, so no round starts even when the deadline arrives.
        #expect(harness.advance(toMs: 1000, isActive: false).isEmpty)
        #expect(harness.netcheck.nextDeadline == nil)
        #expect(harness.advance(toMs: 60_000, isActive: false).isEmpty)
        #expect(harness.advance(toMs: 60_001, isActive: true).isEmpty)
        #expect(harness.netcheck.nextDeadline == nil)

        // When the next send calls reSTUN, a round runs again and periodic scheduling resumes when it finishes.
        let restarted = Harness.requests(in: harness.reSTUN(atMs: 70_000))
        #expect(restarted.map(\.region) == [1])
        _ = harness.receive(restarted[0], atMs: 70_020)
        #expect(harness.netcheck.nextDeadline != nil)
    }

    @Test("A round that ends at its deadline also leaves periodic scheduling stopped when idle")
    func timeoutEndDuringIdleDoesNotSchedule() {
        var harness = Harness()
        _ = harness.setRegions([Self.region(1)])
        _ = harness.advance(toMs: 3000, isActive: false)
        #expect(harness.netcheck.round == nil)
        #expect(harness.netcheck.nextDeadline == nil)
    }

    @Test("reSTUN does nothing while a round is in progress")
    func reSTUNDuringRoundIsNoOp() {
        var harness = Harness()
        _ = harness.setRegions([Self.region(1)])
        #expect(harness.reSTUN(atMs: 50).isEmpty)
        #expect(harness.netcheck.nextDeadline == harness.at(100))
    }

    @Test("Starting a new round clears the scheduled periodic round")
    func startingRoundClearsPeriodic() throws {
        var harness = Harness()
        let request = try #require(Harness.requests(in: harness.setRegions([Self.region(1)])).first)
        _ = harness.receive(request, atMs: 10)
        #expect(harness.netcheck.nextDeadline != nil)
        _ = harness.reSTUN(atMs: 5000)
        #expect(harness.netcheck.nextDeadline == harness.at(5100))
    }

    // MARK: Home selection

    @Test("When regions arrive and home is unset, immediately emits the region with the lowest ID as home")
    func fallbackHomeIsSmallestRegion() {
        var harness = Harness()
        let actions = harness.setRegions([Self.region(5), Self.region(2), Self.region(9)])
        #expect(actions.first == .homeRegionChanged(2))
        #expect(harness.netcheck.homeRegion == 2)
    }

    @Test("Reselects home if it is missing from the new region list and keeps it if present")
    func homeFollowsRegionList() {
        var harness = Harness()
        _ = harness.setRegions([Self.region(1), Self.region(2)])
        #expect(!harness.setRegions([Self.region(1), Self.region(2), Self.region(3)], atMs: 10).contains(.homeRegionChanged(1)))
        #expect(harness.netcheck.homeRegion == 1)
        #expect(harness.setRegions([Self.region(7), Self.region(6)], atMs: 20).first == .homeRegionChanged(6))
    }

    @Test("Chooses the region with the lowest latency")
    func picksLowestLatency() {
        var harness = Harness()
        _ = harness.setRegions([Self.region(1), Self.region(2), Self.region(3)])
        _ = harness.advance(toMs: 3000)
        let actions = harness.runRound(startMs: 30_000, latencies: [1: 50, 2: 20, 3: 80])
        #expect(actions.contains(.homeRegionChanged(2)))
        #expect(harness.netcheck.homeRegion == 2)
    }

    @Test("Keeps the old home if its difference from the new candidate is less than 10 ms")
    func keepsHomeUnderTenMilliseconds() {
        var harness = Harness()
        _ = harness.setRegions([Self.region(1), Self.region(2)])
        // The baseline for retention is a home chosen by measurement. Establish home 1 with a round where only region 1 replies.
        _ = harness.advance(toMs: 3000)
        _ = harness.runRound(startMs: 10_000, latencies: [1: 29])
        #expect(!harness.runRound(startMs: 30_000, latencies: [1: 29, 2: 20]).contains(.homeRegionChanged(2)))
        #expect(harness.netcheck.homeRegion == 1)
    }

    @Test("Keeps the old home if the new candidate's latency is greater than 2/3 of the old home's latency")
    func keepsHomeAboveTwoThirds() {
        var harness = Harness()
        _ = harness.setRegions([Self.region(1), Self.region(2)])
        _ = harness.advance(toMs: 3000)
        _ = harness.runRound(startMs: 10_000, latencies: [1: 100])
        // 100 ms versus 70 ms. The difference is 30 ms, but 70 > 66.6.
        #expect(!harness.runRound(startMs: 30_000, latencies: [1: 100, 2: 70]).contains(.homeRegionChanged(2)))
        #expect(harness.netcheck.homeRegion == 1)
        // 100 ms versus 66 ms. Switch because 66 < 66.6.
        #expect(harness.runRound(startMs: 60_000, latencies: [1: 100, 2: 66]).contains(.homeRegionChanged(2)))
    }

    @Test("Switches home if the difference is exactly 10 ms and the 2/3 condition also does not apply")
    func movesAtExactlyTenMilliseconds() {
        var harness = Harness()
        _ = harness.setRegions([Self.region(1), Self.region(2)])
        _ = harness.advance(toMs: 3000)
        _ = harness.runRound(startMs: 10_000, latencies: [1: 30])
        // Old home 30 ms, new candidate 20 ms. The difference is 10 ms (no less), and 20 > 20 (= 30/3×2) is also false.
        #expect(harness.runRound(startMs: 30_000, latencies: [1: 30, 2: 20]).contains(.homeRegionChanged(2)))
    }

    @Test("Multiplies latency by score only when score is positive")
    func scoreScalesLatency() {
        var harness = Harness()
        _ = harness.setRegions([Self.region(1), Self.region(2, score: 0.5)])
        _ = harness.advance(toMs: 3000)
        // 100 ms versus 100 × 0.5 = 50 ms. Switch because 50 < 66.6 and the difference is 50 ms.
        #expect(harness.runRound(startMs: 30_000, latencies: [1: 100, 2: 100]).contains(.homeRegionChanged(2)))

        for score in [0.0, -1.0, .nan] {
            var plain = Harness()
            _ = plain.setRegions([Self.region(1), Self.region(2, score: score)])
            _ = plain.advance(toMs: 3000)
            // If the score is ignored, the comparison is 100 ms versus 100 ms and the home stays.
            #expect(!plain.runRound(startMs: 30_000, latencies: [1: 100, 2: 100]).contains(.homeRegionChanged(2)))
        }
    }

    @Test("An overflow in score-weighted latency does not crash")
    func scoreOverflowIsClamped() {
        #expect(Netcheck.scaled(Int64.max, by: 1e300) == .max)
        #expect(Netcheck.scaled(Int64.max, by: .infinity) == .max)
        #expect(Netcheck.scaled(1_000_000, by: 0.5) == 500_000)
        #expect(Netcheck.scaled(1_000_000, by: 0) == 1_000_000)
        #expect(Netcheck.scaled(1_000_000, by: .nan) == 1_000_000)
        #expect(Netcheck.nanoseconds(.seconds(Int64.max)) == .max)
        #expect(Netcheck.nanoseconds(.seconds(-5)) == 0)
        #expect(Netcheck.nanoseconds(.milliseconds(1500)) == 1_500_000_000)
    }

    @Test("Compares each region's minimum latency from the last 5 minutes and 5 seconds of history")
    func usesRecentHistory() {
        /// Record A is timestamped at 10,200 ms, at the end of the first round. The second round ends 300 ms after it starts, so the record's age is
        /// `secondStartMs + 300 - 10_200`. It is kept through 305 seconds (deletion uses `>`) and deleted when older.
        func homeAfterSecondRound(secondStartMs: Int) -> Int64 {
            var harness = Harness()
            _ = harness.setRegions([Self.region(1), Self.region(2)])
            _ = harness.advance(toMs: 3000)
            // Record A has region 1 as the fastest. Home is 1.
            _ = harness.runRound(startMs: 10_000, latencies: [1: 10, 2: 200])
            #expect(harness.netcheck.homeRegion == 1)
            // Region 2 is faster in this round alone, but home stays the same if region 1's 10 ms remains in the history.
            _ = harness.runRound(startMs: secondStartMs, latencies: [1: 300, 2: 100])
            return harness.netcheck.homeRegion
        }
        #expect(homeAfterSecondRound(secondStartMs: 60_000) == 1)
        #expect(homeAfterSecondRound(secondStartMs: 10_200 + 305_000 - 300) == 1)
        #expect(homeAfterSecondRound(secondStartMs: 10_200 + 305_000 - 300 + 1) == 2)
    }

    @Test("Keeps the old home even without a STUN reply if a DERP packet arrived within 8 seconds")
    func keepsHomeWithRecentDERPActivity() {
        func scenario(activityMsBeforeEnd: Int?) -> Int64 {
            var harness = Harness()
            _ = harness.setRegions([Self.region(1), Self.region(2)])
            // Establish home 1 with a round where only region 1 replies (the retention baseline is a measured home).
            _ = harness.advance(toMs: 3000)
            _ = harness.runRound(startMs: 10_000, latencies: [1: 20])
            // Only region 2 replies in this round, at 20 ms. The round waits for region 1 and ends at 3 seconds.
            let endMs = 100_000 + 3000
            if let activityMsBeforeEnd {
                harness.netcheck.noteDERPActivity(region: 1, at: harness.at(endMs - activityMsBeforeEnd))
            }
            _ = harness.runRound(startMs: 100_000, latencies: [2: 20])
            return harness.netcheck.homeRegion
        }
        #expect(scenario(activityMsBeforeEnd: nil) == 2)
        #expect(scenario(activityMsBeforeEnd: 7_999) == 1)
        // Exactly 8 seconds earlier is outside "recent" (`>`) and before the round started (3 seconds earlier).
        #expect(scenario(activityMsBeforeEnd: 8_000) == 2)
        // A packet received after the round started is also within 8 seconds.
        #expect(scenario(activityMsBeforeEnd: 500) == 1)
    }

    @Test("Records DERP activity only for candidate home regions")
    func activityOfUnknownRegionIsIgnored() {
        var harness = Harness()
        _ = harness.setRegions([Self.region(1)])
        harness.netcheck.noteDERPActivity(region: 99, at: harness.at(5))
        #expect(harness.netcheck.derpActivity.isEmpty)
        harness.netcheck.noteDERPActivity(region: 1, at: harness.at(5))
        #expect(harness.netcheck.derpActivity == [1: harness.at(5)])
        _ = harness.setRegions([Self.region(2)], atMs: 10)
        #expect(harness.netcheck.derpActivity.isEmpty)
    }

    @Test("The fallback home is ineligible as a retention baseline. The first measured round chooses the fastest region even if the difference is small")
    func firstMeasuredRoundIgnoresFallbackHome() {
        var harness = Harness()
        #expect(harness.setRegions([Self.region(1), Self.region(2)]).first == .homeRegionChanged(1))
        // A round that ends without measurements also creates no baseline.
        _ = harness.advance(toMs: 3000)
        // 30 ms versus 25 ms. The 5 ms difference and 25 > 20 both meet the retention conditions, but home 1 was chosen without measurements.
        #expect(harness.runRound(startMs: 30_000, latencies: [1: 30, 2: 25]).contains(.homeRegionChanged(2)))
        // Region 2 is now the measured home, so it stays with the same difference.
        #expect(!harness.runRound(startMs: 60_000, latencies: [1: 20, 2: 25]).contains(.homeRegionChanged(1)))
        #expect(harness.netcheck.homeRegion == 2)
    }

    @Test("After a round without measurements, only a home that received a DERP packet within 120 seconds remains a retention baseline")
    func measuredHomeSurvivesGapOnlyWithDERPActivity() {
        func homeAfterGap(activityMsBeforeEnd: Int?) -> Int64 {
            var harness = Harness()
            _ = harness.setRegions([Self.region(1), Self.region(2)])
            _ = harness.advance(toMs: 3000)
            _ = harness.runRound(startMs: 10_000, latencies: [1: 30])
            // No region replies in this round. It ends at the 3-second deadline (203,000 ms).
            if let activityMsBeforeEnd {
                harness.netcheck.noteDERPActivity(region: 1, at: harness.at(203_000 - activityMsBeforeEnd))
            }
            _ = harness.runRound(startMs: 200_000, latencies: [:])
            #expect(harness.netcheck.homeRegion == 1)
            // With a 5 ms difference, keep 1 if the baseline remains and switch to 2 if it is gone.
            _ = harness.runRound(startMs: 400_000, latencies: [1: 30, 2: 25])
            return harness.netcheck.homeRegion
        }
        #expect(homeAfterGap(activityMsBeforeEnd: nil) == 2)
        #expect(homeAfterGap(activityMsBeforeEnd: 119_999) == 1)
        // Exactly 120 seconds earlier is outside "within" (`>`).
        #expect(homeAfterGap(activityMsBeforeEnd: 120_000) == 2)
    }

    @Test("Keeps the old home when there are no measurements")
    func noMeasurementKeepsHome() {
        for activity in [nil, 1_000, 119_000, 500_000] as [Int?] {
            var harness = Harness()
            _ = harness.setRegions([Self.region(3), Self.region(5)])
            _ = harness.advance(toMs: 3000)
            #expect(harness.netcheck.homeRegion == 3)
            if let activity {
                harness.netcheck.noteDERPActivity(region: 3, at: harness.at(200_000 - activity))
            }
            let actions = harness.runRound(startMs: 200_000, latencies: [:])
            #expect(!actions.contains(.homeRegionChanged(5)))
            #expect(harness.netcheck.homeRegion == 3)
        }
    }

    @Test("Emits homeRegionChanged only when home changes")
    func homeChangeReportedOnce() {
        var harness = Harness()
        _ = harness.setRegions([Self.region(1), Self.region(2)])
        _ = harness.advance(toMs: 3000)
        #expect(harness.runRound(startMs: 30_000, latencies: [1: 100, 2: 10]).filter { $0 == .homeRegionChanged(2) }.count == 1)
        let again = harness.runRound(startMs: 60_000, latencies: [1: 100, 2: 10])
        #expect(again == [.endpointsRefreshed])
    }

    @Test("Equal latencies favor the lower region ID")
    func tieBreaksBySmallestID() {
        var harness = Harness()
        _ = harness.setRegions([Self.region(4), Self.region(2), Self.region(3)])
        // Home is fallback home 2. The result is determinate even though 3 and 4 have equal latency and 2 is unreachable.
        harness.netcheck.homeRegion = 0
        _ = harness.advance(toMs: 3000)
        _ = harness.runRound(startMs: 30_000, latencies: [4: 10, 3: 10])
        #expect(harness.netcheck.homeRegion == 3)
    }
}
