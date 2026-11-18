// The round's request plan follows Tailscale's `net/netcheck/netcheck.go` (BSD-3-Clause, Copyright (c) Tailscale Inc & contributors),
// specifically `makeProbePlanInitial` (:559-587), `runProbe`, and `addNodeLatency`. The code was written from scratch in Swift.

import SwiftailBase

extension Netcheck {
    /// A request that has yet to be sent.
    struct PendingRequest: Sendable, Equatable {
        var due: ContinuousClock.Instant
        var region: Int64
        var server: IPEndpoint
    }

    /// A sent request awaiting a response.
    struct SentRequest: Sendable, Equatable {
        var region: Int64
        var sentAt: ContinuousClock.Instant
    }

    /// One round, discarded when it ends (so the table cannot exceed the number of regions × 3, contract H).
    struct Round: Sendable {
        let start: ContinuousClock.Instant
        /// Unsent requests in scheduled send order.
        var pending: [PendingRequest]
        /// Sent requests. A response belongs to this round only if its TxID is here (DERP notes 4.10 1).
        var inFlight: [TransactionID: SentRequest] = [:]
        /// The regions this round waits for, namely those with STUN servers.
        let expected: Set<Int64>
        /// Minimum latency per region (nanoseconds).
        var latency: [Int64: Int64] = [:]
        /// External addresses observed in replies and how often they were seen, in first-seen order (notes 4.9 1.2).
        var observations: [(address: IPEndpoint, count: Int)] = []
    }

    /// Starts a round and emits the first requests. A round with no destinations ends immediately.
    ///
    /// Schedules 3 requests per region using `stunServers[try % count]`, one each at 0, 100, and 200 ms. At the start, clears the periodic deadline
    /// and draws the next periodic interval in advance.
    mutating func startRound(at now: ContinuousClock.Instant, using generator: inout some RandomNumberGenerator) -> [Action] {
        periodicAt = nil
        periodicInterval = .milliseconds(Int.random(in: Self.periodicIntervalMilliseconds, using: &generator))
        var pending: [PendingRequest] = []
        for attempt in 0..<Self.requestsPerRegion {
            for region in regions where !region.stunServers.isEmpty {
                pending.append(PendingRequest(
                    due: now + Self.retransmitInterval * attempt,
                    region: region.id,
                    server: region.stunServers[attempt % region.stunServers.count]
                ))
            }
        }
        let expected = Set(regions.filter { !$0.stunServers.isEmpty }.map(\.id))
        round = Round(start: now, pending: pending, expected: expected)

        var actions = sendDueRequests(at: now, using: &generator)
        if expected.isEmpty { actions += finishRound(at: now) }
        return actions
    }

    /// Draws TxIDs and emits due requests. Requests for regions that already replied have already been removed from the plan.
    mutating func sendDueRequests(at now: ContinuousClock.Instant, using generator: inout some RandomNumberGenerator) -> [Action] {
        guard var current = round else { return [] }
        let dueCount = current.pending.prefix(while: { $0.due <= now }).count
        var actions: [Action] = []
        for request in current.pending.prefix(dueCount) {
            let txID = TransactionID.random(using: &generator)
            current.inFlight[txID] = SentRequest(region: request.region, sentAt: now)
            actions.append(.sendSTUN(STUNMessage.bindingRequest(txID), to: request.server))
        }
        current.pending.removeFirst(dueCount)
        round = current
        return actions
    }

    /// Matches a STUN response. Returns nil if it is not a response to a request sent in the active round (`unexpectedSTUN`).
    ///
    /// The first response sets the region's latency and cancels its unsent requests (Go `cancelSet`). Other in-flight requests can still lower the recorded latency.
    /// Rejects a second response with the same TxID. Ends the round once every region it is waiting for has answered.
    mutating func receive(
        _ txID: TransactionID,
        mapped: IPEndpoint,
        at now: ContinuousClock.Instant
    ) -> [Action]? {
        guard var current = round, let sent = current.inFlight.removeValue(forKey: txID) else { return nil }
        let elapsed = Self.nanoseconds(sent.sentAt.duration(to: now))
        current.latency[sent.region] = min(current.latency[sent.region] ?? .max, elapsed)
        current.pending.removeAll { $0.region == sent.region }
        // The single IPv4 socket prevents publishing external IPv6 or port 0 addresses as endpoints. Still counts the region as having answered.
        if mapped.address.isIPv4, mapped.port != 0 {
            if let index = current.observations.firstIndex(where: { $0.address == mapped }) {
                current.observations[index].count += 1
            } else {
                current.observations.append((mapped, 1))
            }
        }
        round = current
        guard current.expected.isSubset(of: Set(current.latency.keys)) else { return [] }
        return finishRound(at: now)
    }

    /// Finishes the round, recomputes the home region and endpoint list, and continues or stops periodic rounds.
    ///
    /// Emits `.endpointsChanged`, `.homeRegionChanged`, and `.endpointsRefreshed` in that order. `.endpointsRefreshed` comes last
    /// so CallMeMaybe messages sent afterward include the new list.
    mutating func finishRound(at now: ContinuousClock.Instant) -> [Action] {
        guard let finished = round else { return [] }
        round = nil
        periodicAt = isActive ? now + periodicInterval : nil

        var actions: [Action] = []
        let newEndpoints = endpointList(from: finished)
        if !Self.sameSet(newEndpoints, endpoints) {
            actions.append(.endpointsChanged(newEndpoints))
        }
        endpoints = newEndpoints
        endpointsRefreshedAt = now

        let newHome = selectHome(after: finished, at: now)
        if newHome != homeRegion {
            homeRegion = newHome
            actions.append(.homeRegionChanged(newHome))
        }
        actions.append(.endpointsRefreshed)
        return actions
    }
}
