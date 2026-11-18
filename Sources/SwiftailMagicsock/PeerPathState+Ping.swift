// Rules for sending Pings, handling Pongs, Ping deadlines, full Pings, and heartbeats are ported from the Go implementation.
// Origin: tailscale.com v1.104.6 `wgengine/magicsock/endpoint.go` (`startDiscoPingLocked`,
// `sendDiscoPingsLocked`, `discoPingTimeout`, `handlePongConnLocked`, `heartbeat`, `wantFullPingLocked`).
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import SwiftailBase

/// Pings candidates and uses Pongs to establish `bestAddr` and trust.
///
/// - A sent Ping waits `pingTimeout` (5 seconds) for a Pong. Removes it on expiration, and clears `bestAddr` only if the Ping went there
///   and trust already expired. One lost Ping does not invalidate the path (notes 4.6 3).
/// - A Pong received over UDP measures latency for the candidate that was pinged. If that candidate is better than `bestAddr` or trust expired,
/// it becomes `bestAddr`. A Pong for `bestAddr` renews trust for 6.5 seconds from receipt (notes §4.6, item 4).
/// - A full Ping Pings every candidate that was not pinged within `pingInterval` (5 seconds) (notes 4.8 1).
/// - The heartbeat Pings `bestAddr` every 3 seconds while sends continue and runs a full Ping if needed (notes 4.8 3).
///
/// The sent Ping table cannot exceed `maxSentPings`. When full, new Pings are skipped and deadlines free entries (contract H).
extension PeerPathState {
    /// A Ping awaiting a Pong. Go `sentPing`.
    struct SentPing: Sendable, Equatable {
        let destination: IPEndpoint
        let sentAt: ContinuousClock.Instant
    }

    /// A direct address confirmed by a Pong and the round-trip latency at that time. Go `addrQuality` without MTU and relay (VNI).
    struct AddressQuality: Sendable, Equatable {
        var address: IPEndpoint
        /// At least 0 and less than `pingTimeout` (Pongs for expired Pings are ignored).
        var latency: Duration
    }

    /// The maximum number of Pings awaiting Pongs per peer (contract H).
    static let maxSentPings = 128

    /// Returns true if the Pong answers a Ping sent to this peer (notes §4.6, item 4). A nil `source` means it arrived over DERP.
    ///
    /// A Pong for an expired Ping is treated like an unknown TxID (Go's deadline timer would already have removed it). Leave the Ping in
    /// the table for the next `advance` to handle expiration.
    mutating func receivePong(_ txID: TransactionID, from source: IPEndpoint?, at now: ContinuousClock.Instant) -> Bool {
        guard let ping = sentPings[txID], now < ping.sentAt + Self.pingTimeout else { return false }
        sentPings[txID] = nil
        // A Pong over DERP does not prove a direct path.
        guard source != nil else { return true }
        // Skip the candidate if it has since been removed. Use the Ping destination to decide (as in Go), regardless of the Pong's source.
        guard candidates.contains(where: { $0.address == ping.destination }) else { return true }

        // If time went backward on this call, treat latency as 0.
        let pong = AddressQuality(address: ping.destination, latency: max(.zero, now - ping.sentAt))
        if Self.isBetter(pong, than: bestAddr) || !isTrusted(at: now) {
            bestAddr = pong
        }
        if bestAddr?.address == pong.address {
            bestAddr?.latency = pong.latency
            trustedUntil = now + Self.trustDuration
        }
        return true
    }

    /// Runs a full Ping (notes 4.8 1, Go `sendDiscoPingsLocked`). Removes eligible candidates and Pings each candidate not pinged within
    /// `pingInterval`. If at least one Ping went out, `sendCallMeMaybe` is set, and there is a home DERP, emits CallMeMaybe too.
    mutating func pingAllCandidates(
        at now: ContinuousClock.Instant,
        sendCallMeMaybe: Bool,
        using generator: inout some RandomNumberGenerator
    ) -> [Action] {
        lastFullPing = now
        removeStaleCandidates(at: now)
        var actions: [Action] = []
        for candidate in candidates {
            if let lastPingSent = candidate.lastPingSent, now - lastPingSent < Self.pingInterval { continue }
            if let ping = startPing(to: candidate.address, at: now, using: &generator) {
                actions.append(ping)
            }
        }
        // Go has no Ping table limit, so it checks whether it tried to send to any candidate. Here at least one Ping must actually be sent.
        if !actions.isEmpty, sendCallMeMaybe, homeDERP != 0 {
            actions.append(.callMeMaybe)
        }
        return actions
    }

    /// Pings one candidate (Go `startDiscoPingLocked`). Skips the send if the address is not a candidate or the Ping table is full.
    private mutating func startPing(
        to address: IPEndpoint,
        at now: ContinuousClock.Instant,
        using generator: inout some RandomNumberGenerator
    ) -> Action? {
        guard sentPings.count < Self.maxSentPings,
              let index = candidates.firstIndex(where: { $0.address == address })
        else { return nil }
        candidates[index].lastPingSent = now
        let txID = TransactionID.random(using: &generator)
        sentPings[txID] = SentPing(destination: address, sentAt: now)
        return .ping(txID, to: address)
    }

    /// Removes Pings past their deadline (`pingTimeout`) (notes 4.6 3, Go `discoPingTimeout`).
    ///
    /// Remove all expired Pings at once because the result is independent of processing order.
    mutating func expirePings(at now: ContinuousClock.Instant) {
        let expired = sentPings.filter { $0.value.sentAt + Self.pingTimeout <= now }
        for (txID, ping) in expired {
            sentPings[txID] = nil
            if ping.destination == bestAddr?.address, !isTrusted(at: now) {
                // The path is already relayed because trust expired. The reason is the same as for trust expiration (no Pong arrived).
                clearBestAddr(because: .trustExpired)
            }
        }
    }

    /// Runs one heartbeat (notes 4.8 3, Go `heartbeat`). Re-arms it for 3 seconds later if the peer is active.
    mutating func heartbeat(at now: ContinuousClock.Instant, using generator: inout some RandomNumberGenerator) -> [Action] {
        heartbeatDeadline = nil
        // Stops without send history (the disco key changed). If more than 45 seconds have passed since the last send, stops until the next send re-arms it.
        guard let lastSend, now - lastSend <= Self.sessionActiveTimeout else { return [] }
        var actions: [Action] = []
        // Checks `bestAddr` regardless of trust.
        if let bestAddr, let ping = startPing(to: bestAddr.address, at: now, using: &generator) {
            actions.append(ping)
        }
        if wantsFullPing(at: now) {
            actions += pingAllCandidates(at: now, sendCallMeMaybe: true, using: &generator)
        }
        heartbeatDeadline = now + Self.heartbeatInterval
        return actions
    }

    /// Whether the heartbeat should run a full Ping (Go `wantFullPingLocked`). With a trusted direct path of 5 ms latency or less,
    /// stops looking. With a slower trusted path, looks for a better path once per minute.
    private func wantsFullPing(at now: ContinuousClock.Instant) -> Bool {
        guard let bestAddr, let lastFullPing, isTrusted(at: now) else { return true }
        if bestAddr.latency <= Self.goodEnoughLatency { return false }
        return now - lastFullPing >= Self.upgradeInterval
    }
}
