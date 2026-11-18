import Testing

import SwiftailBase
@testable import SwiftailMagicsock

/// The test reference time. All times are given in milliseconds after it.
let pathT0 = ContinuousClock.now

/// Returns the time `milliseconds` after the reference time.
func pathTime(_ milliseconds: Int64) -> ContinuousClock.Instant {
    pathT0 + .milliseconds(milliseconds)
}

/// Parses `"address:port"`. The test fails if parsing fails.
func pathEndpoint(_ text: String) throws -> IPEndpoint {
    try #require(IPEndpoint(text))
}

/// A fixed-seed random generator (SplitMix64). The same seed yields the same TxID sequence.
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
    /// Returns Ping destinations in order.
    var pingDestinations: [IPEndpoint] {
        compactMap { if case let .ping(_, to) = $0 { to } else { nil } }
    }

    /// Returns the TxID of the first Ping to `destination`.
    func txID(to destination: IPEndpoint) throws -> TransactionID {
        let found = compactMap { action -> TransactionID? in
            if case let .ping(txID, to) = action, to == destination { txID } else { nil }
        }.first
        return try #require(found)
    }

    var callMeMaybeCount: Int { filter { $0 == .callMeMaybe }.count }
}

/// Connects one `PeerPathState` to an in-memory "network" and runs it in time order.
///
/// A Ping to an address in `responders` gets a Pong from that address after its delay. At the same time, process Pong delivery,
/// `advance`, and sends in that order. Call `advance` at every deadline (`nextDeadline`) emitted by the state machine.
struct PathHarness {
    var state: PeerPathState
    var random = PathTestRandom(state: 1)
    private(set) var now = pathT0
    /// The addresses that answer Pings and their round-trip latencies.
    var responders: [IPEndpoint: Duration] = [:]
    /// The emitted Action and its time.
    private(set) var actions: [(time: ContinuousClock.Instant, action: PeerPathState.Action)] = []
    /// The plan and time for each send.
    private(set) var plans: [(time: ContinuousClock.Instant, plan: PeerPathState.SendPlan)] = []
    private var pendingPongs: [(time: ContinuousClock.Instant, txID: TransactionID, from: IPEndpoint)] = []
    private var sendInterval: Duration?
    private var nextSend: ContinuousClock.Instant?

    init(_ state: PeerPathState) {
        self.state = state
    }

    /// Sends one WireGuard datagram now.
    @discardableResult
    mutating func send() -> PeerPathState.SendPlan {
        let plan = state.planSend(at: now, using: &random)
        plans.append((now, plan))
        record(plan.actions)
        return plan
    }

    /// Sends every `interval` starting now. Nil stops sending.
    mutating func sendRepeatedly(every interval: Duration?) {
        sendInterval = interval
        nextSend = interval.map { now + $0 }
    }

    /// Processes events in time order through `end` and sets the time to `end`.
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

    /// Returns the times of Pings to `destination`.
    func pingTimes(to destination: IPEndpoint) -> [ContinuousClock.Instant] {
        actions.compactMap { entry in
            if case let .ping(_, to) = entry.action, to == destination { entry.time } else { nil }
        }
    }

    /// Returns the send plan at `time`.
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
