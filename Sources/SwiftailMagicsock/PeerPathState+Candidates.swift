// Candidate origins, removal rules, and handling of received Pings and CallMeMaybe are ported from the Go implementation.
// Origin: tailscale.com v1.104.6 `wgengine/magicsock/endpoint.go` (`endpointState.shouldDeleteLocked`,
// `deleteEndpointLocked`, `setEndpointsLocked`, `addCandidateEndpoint`, `handleCallMeMaybe`).
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import SwiftailBase

/// The candidate address table of addresses that might reach the peer directly and their origins.
///
/// Candidates come from three places (notes 4.4 1). These are netmap `Endpoints`, sources of Pings received over UDP, and addresses
/// in CallMeMaybe received over DERP. Local STUN results and Pong Src are excluded. Removal rules differ by origin (notes 4.4 2).
///
/// Received Pings and CallMeMaybe are peer-controlled inputs. The table cannot exceed `maxCandidates`. When it fills, first remove
/// eligible entries. If still full, evict the oldest candidate learned only from a Ping. Candidates learned from a netmap or CallMeMaybe
/// and `bestAddr` are protected from eviction. If nothing can be evicted, skip the new candidate (contract H).
extension PeerPathState {
    /// A candidate, its origins, and its measurement history. Go `endpointState`.
    struct Candidate: Sendable, Equatable {
        let address: IPEndpoint
        /// Appeared in the last netmap.
        var inNetmap = false
        /// When the last Ping arrived for a candidate learned from a UDP Ping. Stays nil for candidates first learned from netmap or CallMeMaybe (as in Go).
        var lastPingReceived: ContinuousClock.Instant?
        /// The TxID of the last Ping received from this address. Prevents sending two Pongs for a replayed Ping.
        var lastPingReceivedTxID: TransactionID?
        /// Appeared in the last CallMeMaybe. Remove this candidate only if it is absent from the next CallMeMaybe.
        var fromCallMeMaybe = false
        /// When the last Ping was sent to this address. A full Ping skips the address if it was pinged within `pingInterval`.
        var lastPingSent: ContinuousClock.Instant?
    }

    /// The per-peer candidate limit. This contract H limit is above Go's cleanup threshold (100).
    static let maxCandidates = 128
    /// When adding a candidate learned from a Ping exceeds this count, remove eligible entries. Go `addCandidateEndpoint` (`endpoint.go:1835`).
    static let candidatePruneThreshold = 100

    /// The number of recently received Ping TxIDs to remember (contract H).
    static let recentPingLimit = 32

    /// Handles a Ping received over UDP (notes 4.2 4.2). Adds the source as a candidate and returns true if it should send a Pong.
    ///
    /// A recently seen TxID (`recentPingTxIDs`) is a replay regardless of source. A replay does not extend a candidate's lifetime (45 seconds after the last Ping)
    /// or create a new candidate. Disco has no replay protection (contract H), so replaying a captured Ping alone could otherwise keep a
    /// candidate alive forever or fill the table (Go checks only the immediately preceding TxID per candidate and updates the timestamp even
    /// for a replay). A legitimate peer uses a new TxID for each Ping.
    ///
    /// Pong handling matches Go. Suppress a Pong only when the same candidate sends the same TxID as last time. Send a Pong even for a Ping not added
    /// as a candidate (a Ping requires a shared key, and a Pong is about the same size as a Ping, so it cannot amplify traffic). An unsupported
    /// source (IPv6 or port 0) cannot receive a reply, so returns false.
    mutating func receivePing(_ txID: TransactionID, from source: IPEndpoint, at now: ContinuousClock.Instant) -> Bool {
        guard let address = Self.candidateAddress(source) else { return false }
        let isReplay = recentPingTxIDs.contains(txID)
        if !isReplay {
            if recentPingTxIDs.count >= Self.recentPingLimit {
                recentPingTxIDs.removeFirst()
            }
            recentPingTxIDs.append(txID)
        }
        if let index = candidates.firstIndex(where: { $0.address == address }) {
            let isDuplicate = candidates[index].lastPingReceivedTxID == txID
            candidates[index].lastPingReceivedTxID = txID
            if !isReplay, !isDuplicate, candidates[index].lastPingReceived != nil {
                candidates[index].lastPingReceived = now
            }
            return !isDuplicate
        }
        guard !isReplay else { return true }
        var candidate = Candidate(address: address)
        candidate.lastPingReceived = now
        candidate.lastPingReceivedTxID = txID
        insertCandidate(candidate, at: now)
        if candidates.count > Self.candidatePruneThreshold {
            removeStaleCandidates(at: now)
        }
        return true
    }

    /// Handles CallMeMaybe received over DERP (notes 4.8 5). `Magicsock` has already verified the source.
    ///
    /// Treats the listed addresses as CallMeMaybe candidates. Removes addresses that appeared in the previous CallMeMaybe and are absent from this one, even if they have another origin. Then
    /// clears per-candidate Ping intervals and Pings every candidate immediately. This full Ping sends no CallMeMaybe back.
    mutating func receiveCallMeMaybe(
        _ endpoints: [IPEndpoint],
        at now: ContinuousClock.Instant,
        using generator: inout some RandomNumberGenerator
    ) -> [Action] {
        let wanted = Self.candidateAddresses(endpoints)
        let wantedSet = Set(wanted)
        // Go adds new addresses before removing absent ones. The result is the same, and removing first makes room in a full table.
        candidates.removeAll { $0.fromCallMeMaybe && !wantedSet.contains($0.address) }
        dropBestAddrIfRemoved()
        for index in candidates.indices where wantedSet.contains(candidates[index].address) {
            candidates[index].fromCallMeMaybe = true
        }
        let known = Set(candidates.map(\.address))
        for address in wanted where !known.contains(address) {
            insertCandidate(Candidate(address: address, fromCallMeMaybe: true), at: now)
        }
        for index in candidates.indices {
            candidates[index].lastPingSent = nil
        }
        return pingAllCandidates(at: now, sendCallMeMaybe: false, using: &generator)
    }

    /// Synchronizes netmap candidates with the netmap's endpoints (Go `setEndpointsLocked`).
    mutating func replaceNetmapCandidates(with endpoints: [IPEndpoint], at now: ContinuousClock.Instant) {
        let wanted = Self.candidateAddresses(endpoints)
        let wantedSet = Set(wanted)
        for index in candidates.indices {
            candidates[index].inNetmap = wantedSet.contains(candidates[index].address)
        }
        removeStaleCandidates(at: now)
        let known = Set(candidates.map(\.address))
        for address in wanted where !known.contains(address) {
            insertCandidate(Candidate(address: address, inNetmap: true), at: now)
        }
    }

    /// Removes candidates that are due for removal (notes 4.4 2, Go `shouldDeleteLocked`). Also clears `bestAddr` if it was removed.
    ///
    /// - Retains CallMeMaybe candidates.
    /// - Removes candidates that have never received a Ping (netmap origin) if absent from the netmap.
    /// - Removes Ping-learned candidates after `sessionActiveTimeout` since the last Ping, even if still in the netmap (as in Go).
    mutating func removeStaleCandidates(at now: ContinuousClock.Instant) {
        candidates.removeAll { candidate in
            if candidate.fromCallMeMaybe { return false }
            guard let received = candidate.lastPingReceived else { return !candidate.inNetmap }
            return now - received > Self.sessionActiveTimeout
        }
        dropBestAddrIfRemoved()
    }

    /// Adds a candidate absent from the table. If full, first removes eligible entries. If still full, evicts the candidate learned only from Pings
    /// whose last received Ping is oldest (excluding `bestAddr`). If nothing can be evicted, skips insertion.
    ///
    /// A candidate learned from a Ping is only a peer-controlled source. A table filled with them must not block the peer's new address. Go has no limit,
    /// so it also has no such eviction.
    private mutating func insertCandidate(_ candidate: Candidate, at now: ContinuousClock.Instant) {
        if candidates.count >= Self.maxCandidates {
            removeStaleCandidates(at: now)
        }
        if candidates.count >= Self.maxCandidates {
            var oldest: (index: Int, received: ContinuousClock.Instant)?
            for (index, existing) in candidates.enumerated() {
                guard let received = existing.lastPingReceived, !existing.inNetmap, !existing.fromCallMeMaybe,
                      existing.address != bestAddr?.address
                else { continue }
                if oldest.map({ received < $0.received }) ?? true {
                    oldest = (index, received)
                }
            }
            guard let oldest else { return }
            candidates.remove(at: oldest.index)
        }
        candidates.append(candidate)
    }

    /// `bestAddr` is always a candidate. If removed from the candidates, clears `bestAddr` and trust (Go `deleteEndpointLocked`).
    private mutating func dropBestAddrIfRemoved() {
        if let bestAddr, !candidates.contains(where: { $0.address == bestAddr.address }) {
            clearBestAddr(because: .candidateRemoved)
        }
    }

    /// Addresses eligible as candidates, in input order with only the first occurrence of each address retained.
    static func candidateAddresses(_ endpoints: [IPEndpoint]) -> [IPEndpoint] {
        var seen: Set<IPEndpoint> = []
        return endpoints.compactMap(candidateAddress).filter { seen.insert($0).inserted }
    }

    /// Returns the address if it is eligible as a candidate. Unmaps IPv4-mapped IPv6 to IPv4. Rejects port 0 because it cannot send to it.
    ///
    /// shortcut: The single IPv4 socket rules out IPv6 candidates (contract D1, "UDP socket" in the "Decisions" table). This will be needed
    /// when M5 real-device testing encounters an IPv6-only network (some cellular networks). Then filter out only IPv6 link-local addresses, as Go does.
    static func candidateAddress(_ endpoint: IPEndpoint) -> IPEndpoint? {
        guard endpoint.port != 0 else { return nil }
        let bytes = endpoint.address.bytes
        if bytes.count == 4 {
            return endpoint
        }
        let mappedPrefix: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF]
        guard bytes.count == 16, bytes.starts(with: mappedPrefix),
              let unmapped = IPAddress(bytes: bytes.suffix(4))
        else { return nil }
        return IPEndpoint(address: unmapped, port: endpoint.port)
    }
}
