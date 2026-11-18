// Endpoint collection and set comparison follow Tailscale's `net/netcheck/netcheck.go` (`GetGlobalAddrs`, :137-167) and
// `wgengine/magicsock/magicsock.go`(`determineEndpoints`, `endpointSetsEqual`, :1278-1473)(BSD-3-Clause,
// Copyright (c) Tailscale Inc & contributors). The code was written from scratch in Swift.

import SwiftailBase

extension Netcheck {
    /// Builds the local endpoint list from a completed round (`disco-magicsock.md` 4.9 1, contract E4).
    ///
    /// Lists global STUN addresses (`.stun`) first, then `address:socket port` for each interface address (`.local`). If both are empty, uses loopback addresses
    /// (`.local`). Keeps only the first occurrence of each address. Global STUN addresses include the round's first response address and any other address observed at least
    /// twice. This also advertises old mappings on networks where NAT issues a new mapping (Go `GetGlobalAddrs`).
    ///
    /// - `shortcut:` Omits port mapping, fixed-port endpoints for destination-dependent mappings, the 5-minute 10-second advertisement cache, and fixed
    ///   endpoints (notes 6.2). This will be needed if the final gate fails with hard NAT.
    func endpointList(from round: Round) -> [Magicsock.Endpoint] {
        let global = round.observations.enumerated()
            .filter { $0.offset == 0 || $0.element.count > 1 }
            .map(\.element.address)
        let local = localAddresses.map { IPEndpoint(address: $0, port: localPort) }
        let fallback = global.isEmpty && local.isEmpty ? loopbackAddresses.map { IPEndpoint(address: $0, port: localPort) } : []

        var list: [Magicsock.Endpoint] = []
        let candidates = global.map { ($0, Magicsock.Endpoint.Source.stun) } + (local + fallback).map { ($0, .local) }
        for (address, source) in candidates where !list.contains(where: { $0.address == address }) {
            list.append(Magicsock.Endpoint(address: address, source: source))
        }
        return list
    }

    /// Whether two lists are equal as sets, ignoring order (Go `endpointSetsEqual`). Neither list has duplicate addresses.
    static func sameSet(_ first: [Magicsock.Endpoint], _ second: [Magicsock.Endpoint]) -> Bool {
        first.count == second.count && first.allSatisfy { second.contains($0) }
    }
}
