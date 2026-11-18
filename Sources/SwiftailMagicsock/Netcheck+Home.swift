// Home region selection follows Tailscale's `net/netcheck/netcheck.go` (`addReportHistoryAndSetPreferredDERP`, :1426-1531) and
// `wgengine/magicsock/derp.go` (`pickDERPFallback`) (BSD-3-Clause, Copyright (c) Tailscale Inc & contributors).
// The code was written from scratch in Swift.

import SwiftailBase

extension Netcheck {
    /// Minimum latency measured per region when a round completed (nanoseconds).
    struct LatencyRecord: Sendable, Equatable {
        var at: ContinuousClock.Instant
        var latency: [Int64: Int64]
    }

    /// Chooses the home region at the end of a round (DERP notes 4.10 5, contract E6).
    ///
    /// 1. Finds each region's minimum latency in the last 5 minutes 5 seconds of round history and multiplies it by `score` if positive. Among regions that replied this round,
    ///    the lowest result is the candidate (ties go to the smaller ID).
    /// 2. If the **previous measured home** (`measuredHome`) would change and is still reachable, keep it when the retention condition below holds. "Reachable" means there is a latency for this
    ///    round or a DERP packet was received from that region after the round started or within 8 seconds. Retention requires the difference from the new candidate
    ///    to be under 10 ms or the new candidate's latency to be greater than 2/3 of the previous home's latency.
    ///    The current home (`homeRegion`) is not the reference for retention. A fallback home selected without measurements (the lowest region ID) does not qualify,
    ///    so the first round with measurements chooses the fastest region without applying the retention condition. This matches Go, which bases retention on the previous report's
    ///    `PreferredDERP` (`netcheck.go:1431`), without feeding magicsock's fallback home back into that report.
    /// 3. With no measurements (no candidate), keep the current home. If there is no current home, choose the lowest region ID (DERP notes
    ///    4.8 1). In this case, `measuredHome` is retained only if the last DERP packet from that region arrived within 120 seconds, and reset to 0 otherwise (Go
    ///    `PreferredDERPKeepAliveTimeout`). Once it is 0, the next round with measurements chooses without applying the retention condition.
    ///
    /// Calculates with `Int64` nanoseconds and caps the weighted value to prevent overflow.
    mutating func selectHome(after round: Round, at now: ContinuousClock.Instant) -> Int64 {
        history.append(LatencyRecord(at: now, latency: round.latency))
        history.removeAll { $0.at.duration(to: now) > Self.historyRetention }

        let scores = Dictionary(regions.map { ($0.id, $0.score) }, uniquingKeysWith: { first, _ in first })
        func scaled(_ latency: Int64, region: Int64) -> Int64 {
            Self.scaled(latency, by: scores[region] ?? 0)
        }

        let previous = measuredHome
        var candidate: Int64 = 0
        var bestRecent: Int64 = 0
        var currentLatencyOfPrevious: Int64?
        for region in round.latency.keys.sorted() {
            let recent = history.compactMap { $0.latency[region] }.min() ?? 0
            let best = scaled(recent, region: region)
            if candidate == 0 || best < bestRecent {
                candidate = region
                bestRecent = best
            }
            if region == previous, let latency = round.latency[region] {
                currentLatencyOfPrevious = scaled(latency, region: region)
            }
        }

        let lastHeard = derpActivity[previous]
        guard candidate != 0 else {
            let keepsAlive = lastHeard.map { $0 > now - Self.homeKeepAliveTimeout } ?? false
            measuredHome = keepsAlive ? previous : 0
            return homeRegion != 0 ? homeRegion : regions.map(\.id).min() ?? 0
        }
        measuredHome = keptHome(
            previous: previous, candidate: candidate, bestRecent: bestRecent,
            currentLatencyOfPrevious: currentLatencyOfPrevious,
            heardRecently: lastHeard.map { $0 > round.start || $0 > now - Self.homeFrameRecency } ?? false
        )
        return measuredHome
    }

    /// The retention condition from step 2. Returns `previous` if retaining the old home, or `candidate` otherwise.
    private func keptHome(
        previous: Int64, candidate: Int64, bestRecent: Int64, currentLatencyOfPrevious: Int64?, heardRecently: Bool
    ) -> Int64 {
        guard previous != 0, candidate != previous else { return candidate }
        guard currentLatencyOfPrevious != nil || heardRecently else { return candidate }
        let current = currentLatencyOfPrevious ?? 0
        if current - bestRecent < Self.nanoseconds(Self.homeAbsoluteDifference) || bestRecent > current / 3 * 2 {
            return previous
        }
        return candidate
    }

    /// Multiplies latency by the region score from DERPMap only when positive, and clamps the result to 0 through `Int64.max`.
    static func scaled(_ nanoseconds: Int64, by score: Double) -> Int64 {
        guard score > 0 else { return nanoseconds }
        let value = Double(nanoseconds) * score
        guard value < Double(Int64.max) else { return .max }
        return Int64(value)
    }
}
