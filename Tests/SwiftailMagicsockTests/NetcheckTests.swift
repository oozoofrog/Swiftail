import Testing

import SwiftailBase

@testable import SwiftailMagicsock

/// STUN 회차, 자기 엔드포인트 목록, 홈 지역 선택(계약 E2~E6, DERP 노트 4.10 5). 시각은 `Harness.at(_:)`로 직접 넘긴다.
///
/// 기준값은 Go `net/netcheck/netcheck.go`의 상수와 조건이다(`Netcheck.swift`·`Netcheck+Home.swift`에 줄이 있다).
/// 시험에서 지역 `n`의 STUN 서버는 `192.0.2.n:3478`이다. 그래서 요청의 목적지로 지역을 알 수 있다.
@Suite("Netcheck")
struct NetcheckTests {
    private typealias Action = Netcheck.Action
    private typealias Region = Magicsock.Region
    private typealias Endpoint = Magicsock.Endpoint

    /// 시험 전용 결정적 생성기(SplitMix64).
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

    /// 요청 하나: TxID와 보낸 곳.
    private struct Request: Equatable {
        var txID: TransactionID
        var server: IPEndpoint
        var region: Int64 { Int64(server.address.bytes[3]) }
    }

    /// 시험 하나가 쓰는 `Netcheck`, 생성기, 기준 시각.
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

        /// 새 회차를 `startMs`에 시작하고, 지역별 지연(ms)대로 첫 요청에 답한 뒤 끝나지 않았으면 3초 마감으로 끝낸다.
        /// 보낸 요청을 뺀 행동을 돌려준다.
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

        /// 지역마다 요청을 세 번씩 모두 내보낸 뒤(0·100·200 ms) 응답을 `(지역, 바깥 주소)` 순서대로 한 건씩 준다.
        /// 같은 지역의 응답은 그 지역의 요청을 보낸 순서대로 대응한다. 모든 지역이 답하지 않으면 3초 마감으로 끝낸다.
        /// 보낸 요청을 뺀 행동을 돌려준다.
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

        /// 보낸 요청을 뺀 행동. 회차의 결과(엔드포인트·홈·갱신)만 보고 싶을 때 쓴다.
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

    // MARK: 회차의 시작과 요청

    @Test("지역마다 0·100·200 ms에 stunServers[try % count]로 요청을 하나씩 보낸다")
    func requestSchedule() throws {
        var harness = Harness()
        let first = harness.setRegions([Self.region(1, servers: 2)])
        #expect(first.first == .homeRegionChanged(1))
        let initial = Harness.requests(in: first)
        #expect(initial.map(\.server) == [Self.endpoint("192.0.2.1:3478")])
        // 요청은 노트 3.8의 40바이트이고 TxID가 담겨 있다.
        guard case let .sendSTUN(bytes, to: _) = first[1] else { Issue.record("첫 요청이 없다"); return }
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

    @Test("회차 하나가 보내는 요청은 지역 수 × 3을 넘지 않는다")
    func requestCountIsBounded() {
        var harness = Harness()
        var actions = harness.setRegions([Self.region(1), Self.region(2, servers: 3), Self.region(3)])
        for ms in stride(from: 50, through: 2900, by: 50) {
            actions += harness.advance(toMs: ms)
        }
        #expect(Harness.requests(in: actions).count == 9)
        #expect(harness.netcheck.round?.inFlight.count == 9)
    }

    @Test("늦게 불러도 기한이 지난 요청을 모두 보낸다")
    func lateAdvanceSendsAllDueRequests() {
        var harness = Harness()
        _ = harness.setRegions([Self.region(1)])
        let requests = Harness.requests(in: harness.advance(toMs: 250))
        #expect(requests.count == 2)
    }

    @Test("지역이 첫 응답을 주면 그 지역의 남은 요청은 취소된다")
    func answerCancelsRemainingRequestsOfRegion() throws {
        var harness = Harness()
        let initial = Harness.requests(in: harness.setRegions([Self.region(1), Self.region(2)]))
        let one = try #require(initial.first { $0.region == 1 })
        _ = harness.receive(one, atMs: 40)
        let later = Harness.requests(in: harness.advance(toMs: 100))
        #expect(later.map(\.region) == [2])
        #expect(harness.netcheck.nextDeadline == harness.at(200))
    }

    @Test("STUN 서버가 없는 지역만 있으면 요청 없이 곧바로 끝난다")
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

    // MARK: 응답 대응

    @Test("응답의 TxID가 진행 중인 회차의 요청이면 받고 아니면 nil이다")
    func matchesResponsesToInFlightRequests() throws {
        var harness = Harness()
        let request = try #require(Harness.requests(in: harness.setRegions([Self.region(1), Self.region(2)])).first)
        let stranger = try #require(TransactionID([UInt8](repeating: 0xee, count: 12)))
        #expect(harness.netcheck.receive(stranger, mapped: Self.endpoint("203.0.113.7:50000"), at: harness.at(10)) == nil)
        #expect(harness.receive(request, atMs: 10) != nil)
        // 같은 TxID의 두 번째 응답은 받지 않는다.
        #expect(harness.receive(request, atMs: 11) == nil)
    }

    @Test("회차가 끝난 뒤의 응답과 회차가 없을 때의 응답은 nil이다")
    func responsesOutsideRoundAreRejected() throws {
        var harness = Harness()
        let stranger = try #require(TransactionID([UInt8](repeating: 0x11, count: 12)))
        #expect(harness.netcheck.receive(stranger, mapped: Self.endpoint("203.0.113.7:50000"), at: harness.at(0)) == nil)

        let request = try #require(Harness.requests(in: harness.setRegions([Self.region(1), Self.region(2)])).first)
        _ = harness.advance(toMs: 3000)
        #expect(harness.receive(request, atMs: 3001) == nil)
    }

    @Test("지역을 바꾸면 옛 회차의 응답은 받지 않는다")
    func regionChangeDropsOldRound() throws {
        var harness = Harness()
        let old = try #require(Harness.requests(in: harness.setRegions([Self.region(1)])).first)
        let actions = harness.setRegions([Self.region(1), Self.region(2)], atMs: 50)
        #expect(harness.receive(old, atMs: 60) == nil)
        #expect(Harness.requests(in: actions).map(\.region) == [1, 2])
    }

    @Test("지역이 그대로면 회차를 다시 시작하지 않는다")
    func sameRegionsKeepRound() throws {
        var harness = Harness()
        let request = try #require(Harness.requests(in: harness.setRegions([Self.region(1)])).first)
        #expect(harness.setRegions([Self.region(1)], atMs: 10).isEmpty)
        #expect(harness.receive(request, atMs: 20) != nil)
    }

    @Test("지역이 모두 없어지면 회차를 멈추고 엔드포인트와 홈은 그대로 둔다")
    func emptyRegionsStopRounds() throws {
        var harness = Harness()
        let request = try #require(Harness.requests(in: harness.setRegions([Self.region(1)])).first)
        #expect(harness.setRegions([], atMs: 10).isEmpty)
        #expect(harness.receive(request, atMs: 20) == nil)
        #expect(harness.netcheck.nextDeadline == nil)
        #expect(harness.netcheck.homeRegion == 1)
        #expect(harness.reSTUN(atMs: 30).isEmpty)
    }

    @Test("지역이 없으면 엔드포인트를 정하지 않는다")
    func noRegionsNoEndpoints() {
        var harness = Harness()
        #expect(harness.setRegions([]).isEmpty)
        #expect(harness.reSTUN(atMs: 5).isEmpty)
        #expect(harness.netcheck.endpoints.isEmpty)
        #expect(harness.netcheck.endpointsRefreshedAt == nil)
        #expect(harness.netcheck.homeRegion == 0)
    }

    // MARK: 마감

    @Test("회차는 시작 뒤 3초에 끝난다")
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

    @Test("모든 지역이 답하면 3초를 기다리지 않고 끝난다")
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

    @Test("답하지 않은 STUN 서버가 있는 지역도 3초에 끝나고 STUN 서버가 없는 지역은 기다리지 않는다")
    func regionWithoutServersIsNotAwaited() throws {
        var harness = Harness()
        let requests = Harness.requests(in: harness.setRegions([Self.region(1), Region(id: 2, stunServers: [])]))
        #expect(requests.map(\.region) == [1])
        let actionsResult = harness.receive(requests[0], atMs: 15)
        let actions = try #require(actionsResult)
        #expect(actions.last == .endpointsRefreshed)
    }

    @Test("바깥 주소가 IPv6이거나 포트 0이어도 그 지역은 답한 것으로 센다")
    func unusableMappedAddressStillCountsAsAnswer() throws {
        var harness = Harness()
        let requests = Harness.requests(in: harness.setRegions([Self.region(1), Self.region(2)]))
        _ = harness.receive(requests[0], mapped: "[2001:db8::1]:50000", atMs: 10)
        let actionsResult = harness.receive(requests[1], mapped: "203.0.113.7:0", atMs: 20)
        let actions = try #require(actionsResult)
        #expect(actions.contains(.endpointsChanged([Self.local("10.0.0.5:41641"), Self.local("192.168.1.2:41641")])))
    }

    // MARK: 엔드포인트 목록

    @Test("엔드포인트는 STUN 주소, 인터페이스 주소 순서다")
    func endpointOrder() throws {
        var harness = Harness()
        let request = try #require(Harness.requests(in: harness.setRegions([Self.region(1)])).first)
        let actionsResult = harness.receive(request, atMs: 12)
        let actions = try #require(actionsResult)
        let expected = [Self.stun("203.0.113.7:50000"), Self.local("10.0.0.5:41641"), Self.local("192.168.1.2:41641")]
        #expect(actions == [.endpointsChanged(expected), .endpointsRefreshed])
        #expect(harness.netcheck.endpoints == expected)
    }

    @Test("같은 주소는 처음 것만 남긴다")
    func duplicatesKeepFirst() throws {
        var harness = Harness()
        let request = try #require(Harness.requests(in: harness.setRegions([Self.region(1)])).first)
        _ = harness.receive(request, mapped: "10.0.0.5:41641", atMs: 12)
        #expect(harness.netcheck.endpoints == [Self.stun("10.0.0.5:41641"), Self.local("192.168.1.2:41641")])
    }

    @Test("다른 엔드포인트가 하나도 없을 때만 loopback 주소를 쓴다")
    func loopbackOnlyWhenNothingElse() throws {
        var bare = Harness()
        bare.netcheck = Netcheck(localPort: 7000, localAddresses: [], loopbackAddresses: [Self.address("127.0.0.1")])
        _ = bare.setRegions([Self.region(1)])
        _ = bare.advance(toMs: 3000)
        #expect(bare.netcheck.endpoints == [Self.local("127.0.0.1:7000")])

        // STUN 주소가 있으면 loopback은 쓰지 않는다.
        var withSTUN = Harness()
        withSTUN.netcheck = Netcheck(localPort: 7000, localAddresses: [], loopbackAddresses: [Self.address("127.0.0.1")])
        let request = try #require(Harness.requests(in: withSTUN.setRegions([Self.region(1)])).first)
        _ = withSTUN.receive(request, mapped: "127.0.0.1:7000", atMs: 3)
        #expect(withSTUN.netcheck.endpoints == [Self.stun("127.0.0.1:7000")])

        // 인터페이스 주소가 있으면 loopback은 쓰지 않는다.
        var regular = Harness()
        _ = regular.setRegions([Self.region(1)])
        _ = regular.advance(toMs: 3000)
        #expect(!regular.netcheck.endpoints.contains(Self.local("127.0.0.1:41641")))
    }

    @Test("STUN 전역 주소는 첫 응답 주소와 두 번 이상 관측된 주소다")
    func globalAddressRule() throws {
        var harness = Harness()
        var requests = Harness.requests(in: harness.setRegions([Self.region(1), Self.region(2), Self.region(3)]))
        requests += Harness.requests(in: harness.advance(toMs: 100))  // 지역마다 두 번째 요청
        #expect(requests.count == 6)
        let regionOne = requests.filter { $0.region == 1 }
        let regionTwo = try #require(requests.first { $0.region == 2 })
        let regionThree = try #require(requests.first { $0.region == 3 })
        let a = "203.0.113.1:1000"
        let b = "203.0.113.2:2000"
        let c = "203.0.113.3:3000"
        _ = harness.receive(regionOne[0], mapped: a, atMs: 110)  // 첫 응답. 한 번 관측.
        _ = harness.receive(regionOne[1], mapped: b, atMs: 111)
        let second = harness.receive(regionTwo, mapped: b, atMs: 112)  // b는 두 번 관측.
        #expect(second == [])
        let actions = harness.receive(regionThree, mapped: c, atMs: 113)  // c는 한 번 관측. 올리지 않는다.
        let expected = [Self.stun(a), Self.stun(b), Self.local("10.0.0.5:41641"), Self.local("192.168.1.2:41641")]
        #expect(actions?.contains(.endpointsChanged(expected)) == true)
    }

    @Test("목록이 집합으로 같으면 순서가 달라도 endpointsChanged를 내지 않고 endpointsRefreshed는 낸다")
    func setComparisonIgnoresOrder() throws {
        var harness = Harness()
        _ = harness.setRegions([Self.region(1), Self.region(2)])
        _ = harness.advance(toMs: 3000)
        let a = "203.0.113.1:1000"
        let b = "203.0.113.2:2000"
        let first = harness.runRoundWithAddresses(startMs: 10_000, responses: [(1, a), (1, b), (2, b)])
        #expect(first.contains(.endpointsChanged([Self.stun(a), Self.stun(b), Self.local("10.0.0.5:41641"), Self.local("192.168.1.2:41641")])))
        // 두 번째 회차: 첫 응답이 b이고 a가 두 번 관측되어 목록이 [b, a, …]다.
        let second = harness.runRoundWithAddresses(startMs: 40_000, responses: [(1, b), (1, a), (2, a)])
        #expect(second == [.endpointsRefreshed])
        #expect(harness.netcheck.endpoints.prefix(2).map(\.address) == [Self.endpoint(b), Self.endpoint(a)])
        #expect(harness.netcheck.endpointsRefreshedAt == harness.at(40_000 + 230))
    }

    @Test("목록이 달라지면 endpointsChanged를 낸다")
    func changedSetIsReported() throws {
        var harness = Harness()
        _ = harness.setRegions([Self.region(1)])
        _ = harness.advance(toMs: 3000)
        _ = harness.runRound(startMs: 10_000, latencies: [1: 10], mapped: "203.0.113.1:1000")
        let actions = harness.runRound(startMs: 30_000, latencies: [1: 10], mapped: "203.0.113.9:9000")
        #expect(actions.contains(.endpointsChanged([Self.stun("203.0.113.9:9000"), Self.local("10.0.0.5:41641"), Self.local("192.168.1.2:41641")])))
        // STUN 결과가 없어져도 달라진 것이다.
        let silent = harness.runRound(startMs: 60_000, latencies: [:])
        #expect(silent.contains(.endpointsChanged([Self.local("10.0.0.5:41641"), Self.local("192.168.1.2:41641")])))
    }

    // MARK: 주기

    @Test("회차가 끝나면 20~26초 뒤에 다음 회차를 걸고, 그때 새 회차를 시작한다")
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
            // 기한 직전에는 아무것도 하지 않고, 기한에 새 회차를 시작한다.
            #expect(harness.advance(toMs: milliseconds - 1).isEmpty)
            let started = harness.advance(toMs: milliseconds)
            #expect(Harness.requests(in: started).map(\.region) == [1])
            #expect(harness.netcheck.round != nil)
        }
    }

    @Test("주기의 간격은 생성기에 따라 달라진다")
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

    @Test("유휴이면 주기를 멈추고 reSTUN이 다시 건다")
    func idleStopsPeriodicRounds() throws {
        var harness = Harness()
        let request = try #require(Harness.requests(in: harness.setRegions([Self.region(1)])).first)
        _ = harness.receive(request, atMs: 10)
        #expect(harness.netcheck.nextDeadline != nil)

        // 유휴가 알려지면 건 주기가 사라지고, 기한이 와도 회차를 시작하지 않는다.
        #expect(harness.advance(toMs: 1000, isActive: false).isEmpty)
        #expect(harness.netcheck.nextDeadline == nil)
        #expect(harness.advance(toMs: 60_000, isActive: false).isEmpty)
        #expect(harness.advance(toMs: 60_001, isActive: true).isEmpty)
        #expect(harness.netcheck.nextDeadline == nil)

        // 다음 송신이 reSTUN을 부르면 회차가 다시 돌고, 끝나면 주기도 이어진다.
        let restarted = Harness.requests(in: harness.reSTUN(atMs: 70_000))
        #expect(restarted.map(\.region) == [1])
        _ = harness.receive(restarted[0], atMs: 70_020)
        #expect(harness.netcheck.nextDeadline != nil)
    }

    @Test("마감으로 끝나는 회차도 유휴이면 주기를 걸지 않는다")
    func timeoutEndDuringIdleDoesNotSchedule() {
        var harness = Harness()
        _ = harness.setRegions([Self.region(1)])
        _ = harness.advance(toMs: 3000, isActive: false)
        #expect(harness.netcheck.round == nil)
        #expect(harness.netcheck.nextDeadline == nil)
    }

    @Test("회차가 진행 중이면 reSTUN은 아무것도 하지 않는다")
    func reSTUNDuringRoundIsNoOp() {
        var harness = Harness()
        _ = harness.setRegions([Self.region(1)])
        #expect(harness.reSTUN(atMs: 50).isEmpty)
        #expect(harness.netcheck.nextDeadline == harness.at(100))
    }

    @Test("새 회차를 시작하면 걸어 둔 주기는 사라진다")
    func startingRoundClearsPeriodic() throws {
        var harness = Harness()
        let request = try #require(Harness.requests(in: harness.setRegions([Self.region(1)])).first)
        _ = harness.receive(request, atMs: 10)
        #expect(harness.netcheck.nextDeadline != nil)
        _ = harness.reSTUN(atMs: 5000)
        #expect(harness.netcheck.nextDeadline == harness.at(5100))
    }

    // MARK: 홈 선택

    @Test("홈이 없는 채로 지역이 오면 지역 ID가 가장 작은 것을 곧바로 홈으로 낸다")
    func fallbackHomeIsSmallestRegion() {
        var harness = Harness()
        let actions = harness.setRegions([Self.region(5), Self.region(2), Self.region(9)])
        #expect(actions.first == .homeRegionChanged(2))
        #expect(harness.netcheck.homeRegion == 2)
    }

    @Test("홈이 새 지역 목록에 없으면 다시 고르고, 있으면 건드리지 않는다")
    func homeFollowsRegionList() {
        var harness = Harness()
        _ = harness.setRegions([Self.region(1), Self.region(2)])
        #expect(!harness.setRegions([Self.region(1), Self.region(2), Self.region(3)], atMs: 10).contains(.homeRegionChanged(1)))
        #expect(harness.netcheck.homeRegion == 1)
        #expect(harness.setRegions([Self.region(7), Self.region(6)], atMs: 20).first == .homeRegionChanged(6))
    }

    @Test("가장 낮은 지연의 지역을 고른다")
    func picksLowestLatency() {
        var harness = Harness()
        _ = harness.setRegions([Self.region(1), Self.region(2), Self.region(3)])
        _ = harness.advance(toMs: 3000)
        let actions = harness.runRound(startMs: 30_000, latencies: [1: 50, 2: 20, 3: 80])
        #expect(actions.contains(.homeRegionChanged(2)))
        #expect(harness.netcheck.homeRegion == 2)
    }

    @Test("옛 홈과 새 후보의 차이가 10 ms 미만이면 옛 홈을 유지한다")
    func keepsHomeUnderTenMilliseconds() {
        var harness = Harness()
        _ = harness.setRegions([Self.region(1), Self.region(2)])
        _ = harness.advance(toMs: 3000)
        #expect(!harness.runRound(startMs: 30_000, latencies: [1: 29, 2: 20]).contains(.homeRegionChanged(2)))
        #expect(harness.netcheck.homeRegion == 1)
    }

    @Test("새 후보가 옛 홈 지연의 2/3보다 크면 옛 홈을 유지한다")
    func keepsHomeAboveTwoThirds() {
        var harness = Harness()
        _ = harness.setRegions([Self.region(1), Self.region(2)])
        _ = harness.advance(toMs: 3000)
        // 100 ms 대 70 ms: 30 ms 차이지만 70 > 66.6이다.
        #expect(!harness.runRound(startMs: 30_000, latencies: [1: 100, 2: 70]).contains(.homeRegionChanged(2)))
        #expect(harness.netcheck.homeRegion == 1)
        // 100 ms 대 66 ms: 66 < 66.6이므로 옮긴다.
        #expect(harness.runRound(startMs: 60_000, latencies: [1: 100, 2: 66]).contains(.homeRegionChanged(2)))
    }

    @Test("차이가 정확히 10 ms이고 2/3 조건도 아니면 옮긴다")
    func movesAtExactlyTenMilliseconds() {
        var harness = Harness()
        _ = harness.setRegions([Self.region(1), Self.region(2)])
        _ = harness.advance(toMs: 3000)
        // 옛 홈 30 ms, 새 후보 20 ms: 차이 10 ms(미만이 아님), 20 > 20(= 30/3×2)도 아니다.
        #expect(harness.runRound(startMs: 30_000, latencies: [1: 30, 2: 20]).contains(.homeRegionChanged(2)))
    }

    @Test("score는 양수일 때만 지연에 곱한다")
    func scoreScalesLatency() {
        var harness = Harness()
        _ = harness.setRegions([Self.region(1), Self.region(2, score: 0.5)])
        _ = harness.advance(toMs: 3000)
        // 100 ms 대 100 × 0.5 = 50 ms. 50 < 66.6이고 차이가 50 ms라 옮긴다.
        #expect(harness.runRound(startMs: 30_000, latencies: [1: 100, 2: 100]).contains(.homeRegionChanged(2)))

        for score in [0.0, -1.0, .nan] {
            var plain = Harness()
            _ = plain.setRegions([Self.region(1), Self.region(2, score: score)])
            _ = plain.advance(toMs: 3000)
            // 점수가 무시되면 100 ms 대 100 ms라 옮기지 않는다.
            #expect(!plain.runRound(startMs: 30_000, latencies: [1: 100, 2: 100]).contains(.homeRegionChanged(2)))
        }
    }

    @Test("점수를 곱한 지연이 넘쳐도 죽지 않는다")
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

    @Test("지연은 최근 5분 5초 기록의 지역별 최소값으로 비교한다")
    func usesRecentHistory() {
        /// 기록 A의 시각은 첫 회차가 끝난 10,200 ms다. 두 번째 회차는 시작 뒤 300 ms에 끝나므로 기록의 나이는
        /// `secondStartMs + 300 - 10_200`이다. 305초까지는 남고(`>`로 지운다), 그보다 오래되면 지워진다.
        func homeAfterSecondRound(secondStartMs: Int) -> Int64 {
            var harness = Harness()
            _ = harness.setRegions([Self.region(1), Self.region(2)])
            _ = harness.advance(toMs: 3000)
            // 기록 A: 지역 1이 빠르다. 홈은 1이다.
            _ = harness.runRound(startMs: 10_000, latencies: [1: 10, 2: 200])
            #expect(harness.netcheck.homeRegion == 1)
            // 이번 회차만 보면 지역 2가 빠르지만, 기록에 지역 1의 10 ms가 남아 있으면 홈은 그대로다.
            _ = harness.runRound(startMs: secondStartMs, latencies: [1: 300, 2: 100])
            return harness.netcheck.homeRegion
        }
        #expect(homeAfterSecondRound(secondStartMs: 60_000) == 1)
        #expect(homeAfterSecondRound(secondStartMs: 10_200 + 305_000 - 300) == 1)
        #expect(homeAfterSecondRound(secondStartMs: 10_200 + 305_000 - 300 + 1) == 2)
    }

    @Test("옛 홈이 STUN에 답하지 않아도 8초 안에 DERP 패킷을 받았으면 유지한다")
    func keepsHomeWithRecentDERPActivity() {
        func scenario(activityMsBeforeEnd: Int?) -> Int64 {
            var harness = Harness()
            _ = harness.setRegions([Self.region(1), Self.region(2)])
            _ = harness.advance(toMs: 3000)
            // 이번 회차에서 지역 2만 20 ms에 답한다. 회차는 지역 1을 기다리다 3초에 끝난다.
            let endMs = 100_000 + 3000
            if let activityMsBeforeEnd {
                harness.netcheck.noteDERPActivity(region: 1, at: harness.at(endMs - activityMsBeforeEnd))
            }
            _ = harness.runRound(startMs: 100_000, latencies: [2: 20])
            return harness.netcheck.homeRegion
        }
        #expect(scenario(activityMsBeforeEnd: nil) == 2)
        #expect(scenario(activityMsBeforeEnd: 7_999) == 1)
        // 정확히 8초 전은 "최근"이 아니고(`>`), 회차 시작(3초 전)보다 앞이다.
        #expect(scenario(activityMsBeforeEnd: 8_000) == 2)
        // 회차 시작 뒤에 받았으면 8초 안이기도 하다.
        #expect(scenario(activityMsBeforeEnd: 500) == 1)
    }

    @Test("DERP 활동은 홈 후보 지역만 기록한다")
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

    @Test("측정이 하나도 없으면 옛 홈을 유지한다")
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

    @Test("홈이 바뀌었을 때만 homeRegionChanged를 낸다")
    func homeChangeReportedOnce() {
        var harness = Harness()
        _ = harness.setRegions([Self.region(1), Self.region(2)])
        _ = harness.advance(toMs: 3000)
        #expect(harness.runRound(startMs: 30_000, latencies: [1: 100, 2: 10]).filter { $0 == .homeRegionChanged(2) }.count == 1)
        let again = harness.runRound(startMs: 60_000, latencies: [1: 100, 2: 10])
        #expect(again == [.endpointsRefreshed])
    }

    @Test("같은 지연이면 지역 ID가 작은 쪽을 고른다")
    func tieBreaksBySmallestID() {
        var harness = Harness()
        _ = harness.setRegions([Self.region(4), Self.region(2), Self.region(3)])
        // 홈은 대체 홈 2다. 3과 4의 지연이 같고 2가 닿지 않아도 결과가 정해진다.
        harness.netcheck.homeRegion = 0
        _ = harness.advance(toMs: 3000)
        _ = harness.runRound(startMs: 30_000, latencies: [4: 10, 3: 10])
        #expect(harness.netcheck.homeRegion == 3)
    }
}
