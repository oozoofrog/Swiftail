import Testing

import SwiftailBase
@testable import SwiftailMagicsock

/// 시험의 기준 시각. 모든 시각은 여기서 몇 밀리초 뒤로 적는다.
let pathT0 = ContinuousClock.now

/// 기준 시각에서 `milliseconds` 뒤.
func pathTime(_ milliseconds: Int64) -> ContinuousClock.Instant {
    pathT0 + .milliseconds(milliseconds)
}

/// `"주소:포트"`를 읽는다. 읽지 못하면 시험 실패다.
func pathEndpoint(_ text: String) throws -> IPEndpoint {
    try #require(IPEndpoint(text))
}

/// 고정 시드 난수(SplitMix64). 같은 시드면 같은 TxID열이 나온다.
struct PathTestRandom: RandomNumberGenerator {
    var state: UInt64

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

extension [PeerPathState.Action] {
    /// Ping의 목적지들(순서대로).
    var pingDestinations: [IPEndpoint] {
        compactMap { if case let .ping(_, to) = $0 { to } else { nil } }
    }

    /// `destination`으로 간 첫 Ping의 TxID.
    func txID(to destination: IPEndpoint) throws -> TransactionID {
        let found = compactMap { action -> TransactionID? in
            if case let .ping(txID, to) = action, to == destination { txID } else { nil }
        }.first
        return try #require(found)
    }

    var callMeMaybeCount: Int { filter { $0 == .callMeMaybe }.count }
}

/// `PeerPathState` 하나를 메모리 "망"에 물려 시각 순서대로 돌린다.
///
/// `responders`의 주소로 간 Ping에는 그 지연 뒤에 그 주소에서 Pong이 온다. 같은 시각에는 Pong 배달,
/// `advance`, 송신 순서로 처리한다. 상태 기계가 낸 기한(`nextDeadline`)마다 `advance`를 부른다.
struct PathHarness {
    var state: PeerPathState
    var random = PathTestRandom(state: 1)
    private(set) var now = pathT0
    /// Ping에 답하는 주소와 그 왕복 지연.
    var responders: [IPEndpoint: Duration] = [:]
    /// 낸 Action과 그 시각.
    private(set) var actions: [(time: ContinuousClock.Instant, action: PeerPathState.Action)] = []
    /// 송신마다의 계획과 그 시각.
    private(set) var plans: [(time: ContinuousClock.Instant, plan: PeerPathState.SendPlan)] = []
    private var pendingPongs: [(time: ContinuousClock.Instant, txID: TransactionID, from: IPEndpoint)] = []
    private var sendInterval: Duration?
    private var nextSend: ContinuousClock.Instant?

    init(_ state: PeerPathState) {
        self.state = state
    }

    /// 지금 WireGuard 데이터그램 하나를 보낸다.
    @discardableResult
    mutating func send() -> PeerPathState.SendPlan {
        let plan = state.planSend(at: now, using: &random)
        plans.append((now, plan))
        record(plan.actions)
        return plan
    }

    /// 지금부터 `interval`마다 보낸다. nil이면 멈춘다.
    mutating func sendRepeatedly(every interval: Duration?) {
        sendInterval = interval
        nextSend = interval.map { now + $0 }
    }

    /// `end`까지 사건을 시각 순서로 처리하고 시각을 `end`로 둔다.
    mutating func run(until end: ContinuousClock.Instant) {
        while let next = [pendingPongs.map(\.time).min(), state.nextDeadline, nextSend].compactMap({ $0 }).min(),
              next <= end {
            now = next
            let due = pendingPongs.filter { $0.time <= next }
            pendingPongs.removeAll { $0.time <= next }
            for pong in due {
                _ = state.receivePong(pong.txID, from: pong.from, at: now)
            }
            if let deadline = state.nextDeadline, deadline <= now {
                record(state.advance(to: now, using: &random))
            }
            if let scheduled = nextSend, let sendInterval, scheduled <= now {
                send()
                nextSend = scheduled + sendInterval
            }
        }
        now = end
    }

    /// `destination`으로 Ping을 보낸 시각들.
    func pingTimes(to destination: IPEndpoint) -> [ContinuousClock.Instant] {
        actions.compactMap { entry in
            if case let .ping(_, to) = entry.action, to == destination { entry.time } else { nil }
        }
    }

    /// `time`에 한 송신의 계획.
    func plan(at time: ContinuousClock.Instant) throws -> PeerPathState.SendPlan {
        try #require(plans.last { $0.time == time }?.plan)
    }

    private mutating func record(_ newActions: [PeerPathState.Action]) {
        for action in newActions {
            actions.append((now, action))
            if case let .ping(txID, to) = action, let latency = responders[to] {
                pendingPongs.append((now + latency, txID, to))
            }
        }
    }
}
