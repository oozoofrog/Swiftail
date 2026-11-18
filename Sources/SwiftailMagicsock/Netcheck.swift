// STUN rounds and home region selection follow the rules in Tailscale's `net/netcheck/netcheck.go` and
// `wgengine/magicsock/magicsock.go` (BSD-3-Clause, Copyright (c) Tailscale Inc & contributors).
// The constants and decision criteria were ported. The code was written from scratch in Swift.

import SwiftailBase

/// A state machine that determines the local external addresses (endpoints) and home DERP region. It has no sockets or clock.
///
/// Runs a **round** that sends requests to STUN servers in DERP regions, gathers local external addresses and per-region latencies from responses,
/// and recomputes the endpoint list and home region at the end. The node sends `Action` values of `.sendSTUN` through the UDP socket,
/// passes received STUN responses to `receive`, and calls `advance` when the time reaches `nextDeadline`. Time and randomness (TxID and the next round interval)
/// are arguments that tests can provide directly.
///
/// See `docs/protocol-notes/derp-stun.md` 4.8 (home region) and 4.10 (STUN queries and home selection), `disco-magicsock.md` 4.9 (endpoints),
/// and contract `docs/contracts/SwiftailMagicsock.md` §E for the procedure. This file holds state and entry points. Rounds are in `Netcheck+Round.swift`,
/// the endpoint list is in `Netcheck+Endpoints.swift`, and home selection is in `Netcheck+Home.swift`.
///
/// - `shortcut:` Skips HTTPS latency measurements when UDP is blocked and no STUN responses arrive (DERP notes 4.10 4). Keeps the existing home
///   in that case. This will be needed when a gate shows the wrong home being retained on a network that blocks UDP.
/// - `shortcut:` Skips DNS lookups for DERP nodes with empty `ipv4` (the value type cannot resolve DNS). The node extracts STUN addresses as IPv4 literals
///   and puts them in `Magicsock.Region.stunServers`. This will be needed when a DERPMap without literals is encountered.
/// - `shortcut:` Skips Go's incremental rounds (remeasuring only home and nearby regions) and its "stop after 2 times the latency once three regions reply" rule. Rounds
///   always measure every region and end when all reply or 3 seconds elapse. This will be needed if round cost becomes a problem for a DERPMap with many regions.
struct Netcheck: Sendable {
    enum Action: Sendable, Equatable {
        /// Sends to `to` through the UDP socket. It must share the WireGuard and disco socket for the response address to become an endpoint (DERP notes 4.10 2).
        case sendSTUN([UInt8], to: IPEndpoint)
        /// The set of endpoints to publish changed (order matters, notes 4.9 1).
        case endpointsChanged([Magicsock.Endpoint])
        /// The home region changed.
        case homeRegionChanged(Int64)
        /// A round finished and refreshed the local endpoints, even if the list stayed the same. It is time to send deferred CallMeMaybe messages.
        case endpointsRefreshed
    }

    // MARK: Constants. They match Go and are not configurable.

    /// Requests sent per region, one each at 0, 100, and 200 ms (`netcheck.go:559-587`, `makeProbePlanInitial`).
    static let requestsPerRegion = 3
    /// The interval between requests to the same region (`netcheck.go:87` `defaultInitialRetransmitTime`).
    static let retransmitInterval = Duration.milliseconds(100)
    /// The maximum round length. Regions that do not respond within this time are omitted (`netcheck.go:66` `stunProbeTimeout`).
    static let roundTimeout = Duration.seconds(3)
    /// The range of intervals between periodic rounds (milliseconds). Shorter than a common NAT mapping lifetime of 30 seconds (`magicsock.go:904`).
    static let periodicIntervalMilliseconds = 20_000...26_000
    /// Retention period for round history used in home selection, 5 minutes + 5 seconds of report time (`netcheck.go:1379`, `:1416`).
    static let historyRetention = Duration.seconds(5 * 60 + 5)
    /// A new candidate must be at least this much faster than the old home to replace it (`netcheck.go:1387` `preferredDERPAbsoluteDiff`).
    static let homeAbsoluteDifference = Duration.milliseconds(10)
    /// A region that sent a DERP packet within this time is considered reachable even without a STUN response (`netcheck.go:1396` `PreferredDERPFrameTime`).
    static let homeFrameRecency = Duration.seconds(8)
    /// The age of DERP activity that keeps a measured home as the reference after a round with no measurements (Go `PreferredDERPKeepAliveTimeout`, 2 × 60 seconds).
    static let homeKeepAliveTimeout = Duration.seconds(120)

    // MARK: Inputs

    /// The socket's bound port and the interface addresses, inputs to the endpoint list that only `rebind` changes.
    private(set) var localPort: UInt16
    private(set) var localAddresses: [IPAddress]
    private(set) var loopbackAddresses: [IPAddress]

    // MARK: State

    /// Candidate home regions. Keeps only the first occurrence of a duplicate ID.
    var regions: [Magicsock.Region] = []
    /// The active round, or nil if none.
    var round: Round?
    /// The next periodic round time. Nil means the periodic rounds stopped.
    var periodicAt: ContinuousClock.Instant?
    /// The next round interval. Drawn when the round starts so no randomness is needed if the round ends in `receive`.
    var periodicInterval = Duration.milliseconds(Self.periodicIntervalMilliseconds.lowerBound)
    /// The last `isActive` passed to `advance`. Determines whether a round ending in `receive` continues the periodic schedule.
    var isActive = true
    /// Minimum latencies per region from recent rounds, used for home selection.
    var history: [LatencyRecord] = []
    /// When the last DERP packet was received from each region (candidate home regions only).
    var derpActivity: [Int64: ContinuousClock.Instant] = [:]

    /// The current home region, or 0 if none yet.
    var homeRegion: Int64 = 0
    /// The home selected by measurements in the last round (Go's previous report's `PreferredDERP`). 0 for a fallback home or if measurements stopped. The reference for deciding whether to keep home.
    var measuredHome: Int64 = 0
    /// The last computed list of local endpoints. Empty until the first round completes.
    var endpoints: [Magicsock.Endpoint] = []
    /// When a round last completed. Used to check the 27-second freshness window for CallMeMaybe (notes 4.8 4.1).
    var endpointsRefreshedAt: ContinuousClock.Instant?

    init(localPort: UInt16, localAddresses: [IPAddress], loopbackAddresses: [IPAddress]) {
        self.localPort = localPort
        self.localAddresses = localAddresses
        self.loopbackAddresses = loopbackAddresses
    }

    // MARK: Entry points

    /// Synchronizes candidate home regions. If they changed, adjusts home and immediately starts a new round.
    ///
    /// If home is absent or missing from the new list, immediately emits the lowest region ID as home. This lets the node connect to DERP without waiting for
    /// the first round (3 seconds) (DERP notes 4.8 1, contract E6 "Fallback home"). Runs no round if no regions exist. Go also neither stores nor publishes endpoints
    /// without a DERPMap and STUN results (notes 4.9 5).
    mutating func setRegions(
        _ regions: [Magicsock.Region],
        at now: ContinuousClock.Instant,
        using generator: inout some RandomNumberGenerator
    ) -> [Action] {
        var unique: [Magicsock.Region] = []
        for region in regions where !unique.contains(where: { $0.id == region.id }) {
            unique.append(region)
        }
        guard unique != self.regions else { return [] }
        self.regions = unique
        derpActivity = derpActivity.filter { id, _ in unique.contains { $0.id == id } }
        round = nil
        periodicAt = nil
        guard let fallback = unique.map(\.id).min() else { return [] }

        var actions: [Action] = []
        if !unique.contains(where: { $0.id == measuredHome }) {
            measuredHome = 0
        }
        if homeRegion == 0 || !unique.contains(where: { $0.id == homeRegion }) {
            homeRegion = fallback
            actions.append(.homeRegionChanged(fallback))
        }
        isActive = true
        actions += startRound(at: now, using: &generator)
        return actions
    }

    /// Starts a round if none is active (ReSTUN in notes 4.8 4.1). Does nothing if there are no regions.
    ///
    /// Also call when sending to a peer while the schedule is stopped (`nextDeadline` is nil) to re-arm periodic rounds.
    mutating func reSTUN(at now: ContinuousClock.Instant, using generator: inout some RandomNumberGenerator) -> [Action] {
        guard round == nil, !regions.isEmpty else { return [] }
        isActive = true
        return startRound(at: now, using: &generator)
    }

    /// Reports that a socket was newly bound (notes 4.11 2). Replaces endpoint inputs, discards the active round, and immediately starts a new one.
    ///
    /// Requests in the previous round went out on the old socket, so their replies no longer match any request (`unexpectedSTUN`). If there are
    /// no regions, starts no round. When regions arrive, `setRegions` starts a round with the new inputs.
    ///
    /// Also clears the time when endpoints were set. The current list belongs to the old socket, so CallMeMaybe before the new round completes is deferred and
    /// sent with new endpoints (behavior F2). Go keeps that time, so CallMeMaybe just after rebinding contains old endpoints
    /// (`enqueueCallMeMaybe` in `magicsock.go`). Old addresses are useless to the peer after a network change, so this does not follow Go.
    mutating func rebind(
        localPort: UInt16,
        localAddresses: [IPAddress],
        loopbackAddresses: [IPAddress],
        at now: ContinuousClock.Instant,
        using generator: inout some RandomNumberGenerator
    ) -> [Action] {
        self.localPort = localPort
        self.localAddresses = localAddresses
        self.loopbackAddresses = loopbackAddresses
        round = nil
        periodicAt = nil
        endpointsRefreshedAt = nil
        return reSTUN(at: now, using: &generator)
    }

    /// Notes a packet received from a DERP region. Used to determine whether the old home remains reachable (DERP notes 4.10 5). Ignores regions outside the candidates.
    mutating func noteDERPActivity(region: Int64, at now: ContinuousClock.Instant) {
        guard regions.contains(where: { $0.id == region }) else { return }
        derpActivity[region] = now
    }

    /// Handles due work, including the next request in the round, the round cutoff, and the start of the periodic round.
    ///
    /// - Parameter isActive: There are peers and a send occurred within 45 seconds. If false, stops periodic rounds (notes 4.9 5).
    ///   `reSTUN` re-arms the stopped schedule.
    mutating func advance(
        to now: ContinuousClock.Instant,
        isActive: Bool,
        using generator: inout some RandomNumberGenerator
    ) -> [Action] {
        self.isActive = isActive
        if !isActive { periodicAt = nil }
        if let round {
            if now >= round.start + Self.roundTimeout {
                return finishRound(at: now)
            }
            return sendDueRequests(at: now, using: &generator)
        }
        if let periodicAt, now >= periodicAt {
            return startRound(at: now, using: &generator)
        }
        return []
    }

    /// The next time to call `advance`. Nil if there is neither an active round nor a periodic schedule.
    var nextDeadline: ContinuousClock.Instant? {
        guard let round else { return periodicAt }
        return periodicAt.earlier(round.start + Self.roundTimeout).earlier(round.pending.first?.due)
    }

    // MARK: Value conversion

    /// Converts latency to `Int64` nanoseconds. Clamps negatives to 0 and overflow to the maximum (contract H requires no integer overflow).
    static func nanoseconds(_ duration: Duration) -> Int64 {
        let (seconds, attoseconds) = duration.components
        guard seconds >= 0 else { return 0 }
        let (scaled, overflow) = seconds.multipliedReportingOverflow(by: 1_000_000_000)
        guard !overflow else { return .max }
        let (total, addOverflow) = scaled.addingReportingOverflow(attoseconds / 1_000_000_000)
        return addOverflow ? .max : total
    }
}
