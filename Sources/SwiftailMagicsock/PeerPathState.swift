// Path selection, trust duration, and timer values are ported from the Go implementation.
// Origin: tailscale.com v1.104.6 `wgengine/magicsock/endpoint.go` (`addrForSendLocked`, `send`,
// `noteTxActivityExtTriggerLocked`, `updateFromNode`, `changedActiveDiscoLocked`, `populatePeerStatus`,
// `noteConnectivityChange`, `clearBestAddrLocked`, `endpointState.clear`),
// `wgengine/magicsock/magicsock.go` (constants).
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import SwiftailBase

/// A state machine that discovers and maintains a direct UDP path to one peer. It corresponds to the path portion of Go's `magicsock.endpoint`.
///
/// Sends disco Pings to candidates and selects the best address that returned a Pong as `bestAddr`. Sends only to that address
/// for 6.5 seconds after the last Pong. If trust expires or there is no direct address, also sends over the peer's home DERP while rediscovering the path.
///
/// Has no socket, clock, or cryptography. Takes time and randomness (TxID) as arguments and returns items to send as `Action` values.
/// `Magicsock` seals and sends disco messages and fills CallMeMaybe with local endpoints.
///
/// This file contains state and path selection. `+Candidates` covers the candidate table. `+Ping` covers Ping, Pong, and heartbeat.
/// `+BetterAddress` compares two addresses.
///
/// `docs/protocol-notes/disco-magicsock.md` §§4.4~4.8 and `docs/contracts/SwiftailMagicsock.md` behavior D.
struct PeerPathState: Sendable {
    enum Action: Sendable, Equatable {
        /// Sends a disco Ping to a candidate.
        case ping(TransactionID, to: IPEndpoint)
        /// Sends CallMeMaybe over the peer's home DERP. `Magicsock` adds local endpoints.
        case callMeMaybe
    }

    /// Where to send one WireGuard datagram (notes 4.5).
    struct SendPlan: Sendable, Equatable {
        /// The direct address for sending over UDP, or nil if absent.
        var udp: IPEndpoint?
        /// The peer's home region if also sending over DERP. 0 disables sending over DERP.
        var derpRegion: Int64
        /// Disco messages to send along with this send.
        var actions: [Action]
    }

    // MARK: Constants (notes §5. These values determine when Go peers downgrade and recover, so they must match Go and cannot change)

    /// The deadline for a Pong to a sent Ping. `pingTimeoutDuration` (`magicsock.go:4119`, `tsconst/ping.go:11`).
    static let pingTimeout: Duration = .seconds(5)
    /// The minimum interval before pinging the same candidate again. Receiving CallMeMaybe clears it.
    /// `discoPingInterval`(`magicsock.go:4125`, `tsconst/ping.go:15`).
    static let pingInterval: Duration = .seconds(5)
    /// How often to Ping `bestAddr` and look for a better path while sends continue. `heartbeatInterval` (`magicsock.go:4099`).
    static let heartbeatInterval: Duration = .seconds(3)
    /// How long after a Pong to send exclusively to `bestAddr`. `trustUDPAddrDuration` (`magicsock.go:4103`).
    static let trustDuration: Duration = .milliseconds(6500)
    /// Stops the heartbeat this long after the last send. Also removes candidates learned from Pings this long after the last Ping.
    /// `sessionActiveTimeout`(`magicsock.go:4083`).
    static let sessionActiveTimeout: Duration = .seconds(45)
    /// Skips a full Ping to look for a better path when `bestAddr` latency is at or below this value. `goodEnoughLatency` (`magicsock.go:4107`).
    static let goodEnoughLatency: Duration = .milliseconds(5)
    /// The interval between full Pings on a direct path with latency above `goodEnoughLatency`.
    /// `upgradeUDPDirectInterval`(`magicsock.go:4087`).
    static let upgradeInterval: Duration = .seconds(60)

    // MARK: State

    /// The peer's home DERP region. 0 means unknown.
    private(set) var homeDERP: Int64
    /// Direct path candidates. Preserves insertion order so the same input sequence produces the same Ping order (`+Candidates`).
    var candidates: [Candidate] = []
    /// TxIDs of recent UDP Pings (in receive order, up to `recentPingLimit` entries). A TxID in this list is a replay regardless of
    /// its source (`+Candidates`).
    var recentPingTxIDs: [TransactionID] = []
    /// Pings awaiting Pongs. Maps TxID to destination and send time (`+Ping`).
    var sentPings: [TransactionID: SentPing] = [:]
    /// The best direct address confirmed by a Pong. It is always in `candidates` (removing the candidate also clears it).
    var bestAddr: AddressQuality?
    /// Sends only to `bestAddr` through this time, inclusive. Nil means no trust (Go's time 0).
    var trustedUntil: ContinuousClock.Instant?
    /// When the last full Ping ran.
    var lastFullPing: ContinuousClock.Instant?
    /// When the next heartbeat runs. Nil means it is stopped.
    var heartbeatDeadline: ContinuousClock.Instant?
    /// When the last external send (WireGuard datagram) occurred, or nil if none. `Magicsock` uses it to detect idleness and stop ReSTUN.
    private(set) var lastSend: ContinuousClock.Instant?
    /// Why `bestAddr` was last cleared. Used only in diagnostic logs (`Magicsock.downgrade(of:)`).
    private(set) var bestAddrLoss: PathDowngrade?

    init(homeDERP: Int64, endpoints: [IPEndpoint]) {
        self.homeDERP = homeDERP
        candidates = Self.candidateAddresses(endpoints).prefix(Self.maxCandidates).map {
            Candidate(address: $0, inNetmap: true)
        }
    }

    /// Applies a netmap update (notes 4.4 1 and 2). Updates home DERP and synchronizes netmap candidates.
    mutating func update(homeDERP: Int64, endpoints: [IPEndpoint], at now: ContinuousClock.Instant) {
        self.homeDERP = homeDERP
        replaceNetmapCandidates(with: endpoints, at: now)
    }

    /// The peer's disco key changed (notes 4.4 3).
    ///
    /// Pongs for Pings sent with the old key will not arrive with the new key, so discard outstanding Pings and trust and restart discovery.
    /// Keep `bestAddr` so sends continue over UDP as well until a new path is established. The heartbeat stops at its next deadline if there is
    /// no send history (as in Go). Also forget TxIDs of Pings received with the old key.
    mutating func resetForNewDiscoKey() {
        recentPingTxIDs = []
        trustedUntil = nil
        lastSend = nil
        lastFullPing = nil
        sentPings = [:]
        for index in candidates.indices {
            candidates[index].lastPingSent = nil
        }
    }

    /// A new UDP socket was bound, so the old path is no longer trustworthy (notes 4.11 2, Go `noteConnectivityChange`).
    ///
    /// Clears `bestAddr` and trust, each candidate's Ping history (last Ping time and received Ping TxID), and outstanding Pings.
    /// Retains candidates and their origins (netmap, received Pings, CallMeMaybe), last send time, and heartbeat (Go leaves `lastSendExt` and
    /// `lastFullPing` alone. Those are affected by `resetForNewDiscoKey` when the disco key changes). The next
    /// send therefore also uses DERP because trust is absent, Pings all candidates, and emits CallMeMaybe.
    ///
    /// Go retains outstanding Pings (`sentPing`). Discard them here because even a late Pong for a Ping sent on the old socket
    /// cannot prove a path on the new socket.
    ///
    /// shortcut: Go also clears CallMeMaybe timestamps via `endpointState.clear`, allowing those candidates to be removed on the next netmap update.
    /// Here, keep CallMeMaybe candidates until the next CallMeMaybe removes them (there is one origin marker). This will be needed
    /// if a gate shows wasted Pings to CallMeMaybe candidates from the old network after rebinding.
    mutating func noteConnectivityChange() {
        clearBestAddr(because: .rebind)
        sentPings = [:]
        for index in candidates.indices {
            candidates[index].lastPingSent = nil
            candidates[index].lastPingReceivedTxID = nil
        }
    }

    /// Selects where to send a WireGuard datagram (notes 4.5 1–5, 4.8 2).
    ///
    /// If `bestAddr` is within its trust duration, sends only to that address. Otherwise sends to both `bestAddr` (if present) and home DERP
    /// and runs a full Ping (including CallMeMaybe). If neither is available, `udp` is nil and `derpRegion` is 0 (`noRouteToPeer`).
    ///
    /// shortcut: Reverse DERP regions (notes 4.5 4) are unused for peers with home DERP 0. This will be needed when such
    /// a peer is seen at a real tailnet gate.
    mutating func planSend(at now: ContinuousClock.Instant, using generator: inout some RandomNumberGenerator) -> SendPlan {
        // As in Go, choose the send destination before running a full Ping.
        let trusted = isTrusted(at: now)
        let udp = bestAddr?.address
        let derpRegion = trusted ? 0 : homeDERP
        let actions = trusted ? [] : pingAllCandidates(at: now, sendCallMeMaybe: true, using: &generator)
        lastSend = now
        if heartbeatDeadline == nil {
            heartbeatDeadline = now + Self.heartbeatInterval
        }
        return SendPlan(udp: udp, derpRegion: derpRegion, actions: actions)
    }

    /// Clears expired Pings and runs the heartbeat (notes 4.6 3, 4.8 3).
    ///
    /// For equal deadlines, handle Ping expiration first. The heartbeat does not Ping a cleared `bestAddr`.
    mutating func advance(to now: ContinuousClock.Instant, using generator: inout some RandomNumberGenerator) -> [Action] {
        expirePings(at: now)
        var actions: [Action] = []
        if let deadline = heartbeatDeadline, deadline <= now {
            actions = heartbeat(at: now, using: &generator)
        }
        if let until = trustedUntil, now > until {
            // Expired trust is equivalent to no trust. Clear it so `nextDeadline` does not keep returning a past time.
            trustedUntil = nil
        }
        return actions
    }

    /// The earliest of a Ping deadline, heartbeat, and trust expiration.
    ///
    /// Trust includes the exact time `trustedUntil`, so schedule expiration 1 nanosecond later. After `advance` at that time,
    /// `path(at:)` changes to `.relayed` so `Magicsock` can emit a path event (contract D7).
    var nextDeadline: ContinuousClock.Instant? {
        var earliest = heartbeatDeadline.earlier(trustedUntil.map { $0 + .nanoseconds(1) })
        for ping in sentPings.values {
            earliest = earliest.earlier(ping.sentAt + Self.pingTimeout)
        }
        return earliest
    }

    /// The peer's current path. Equivalent to Go's `curAddr` (notes 7.1).
    func path(at now: ContinuousClock.Instant) -> PeerPath {
        if let bestAddr, isTrusted(at: now) {
            return .direct(bestAddr.address)
        }
        return .relayed(derpRegion: homeDERP)
    }

    /// `bestAddr` exists and `now ≤ trustedUntil` (Go `!now.After(trustBestAddrUntil)`).
    func isTrusted(at now: ContinuousClock.Instant) -> Bool {
        guard bestAddr != nil, let trustedUntil else { return false }
        return now <= trustedUntil
    }

    /// Clears `bestAddr` and trust together (Go `clearBestAddrLocked`). Records the reason for diagnostic logs.
    mutating func clearBestAddr(because loss: PathDowngrade) {
        bestAddr = nil
        trustedUntil = nil
        bestAddrLoss = loss
    }
}
