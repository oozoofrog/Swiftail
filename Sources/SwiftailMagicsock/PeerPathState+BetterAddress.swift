// Comparison of two direct addresses is ported from the Go implementation.
// Origin: tailscale.com v1.104.6 `wgengine/magicsock/endpoint.go` (`betterAddr`),
// and the Go standard library `net/netip` (IPv4 ranges for `Addr.IsLoopback`, `IsLinkLocalUnicast`, and `IsPrivate`).
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import SwiftailBase

/// Whether an address that just returned a Pong is better than the current `bestAddr` (notes 4.7).
///
/// Both addresses start at 0 points. The faster one receives a score equal to the percentage by which it is faster than the slower one. Each address
/// gets bonus points by type (loopback +50, link-local +30, private +20). If the new address is only 1% faster or less, keep the old one to avoid switching
/// between similar paths. If a Go peer on the same machine advertises both `127.0.0.1:p` and a LAN address, comparable latency makes
/// loopback win (notes 4.7 calculation).
///
/// shortcut: Omits Go's same-address MTU comparison (path MTU measurement), peer relay (Geneve) path comparison, and IPv6 +10 points because MTU is
/// unmeasured, relay is unused, and only IPv4 candidates exist (contract "Exclusions"). Each becomes necessary when adding path MTU measurement,
/// peer relay, or IPv6 candidates, respectively.
extension PeerPathState {
    /// Returns true if `a` is better than `b`. It is always better if `b` is absent. An identical address is never better.
    ///
    /// Latency is at least 0 and below `pingTimeout` (5 seconds). Clamp other values to the range so multiplying nanoseconds by 100 cannot exceed
    /// `Int64`.
    static func isBetter(_ a: AddressQuality, than b: AddressQuality?) -> Bool {
        guard let b else { return true }
        if a.address == b.address { return false }

        let aLatency = nanoseconds(a.latency)
        let bLatency = nanoseconds(b.latency)
        var aPoints: Int64 = 0
        var bPoints: Int64 = 0
        if aLatency > bLatency, aLatency > 0 {
            bPoints = 100 - (bLatency * 100) / aLatency
        } else if bLatency > 0 {
            aPoints = 100 - (aLatency * 100) / bLatency
        }
        aPoints += preferencePoints(a.address.address)
        bPoints += preferencePoints(b.address.address)

        if aPoints <= 1, bPoints == 0 { return false }
        return aPoints > bPoints
    }

    /// Bonus points by address type. Favors nearby addresses that are likely to cost nothing.
    private static func preferencePoints(_ address: IPAddress) -> Int64 {
        let bytes = address.bytes
        guard bytes.count == 4 else { return 0 }
        switch (bytes[0], bytes[1]) {
        case (127, _): return 50                        // loopback 127.0.0.0/8
        case (169, 254): return 30                      // link-local 169.254.0.0/16
        case (10, _), (192, 168): return 20             // Private 10.0.0.0/8, 192.168.0.0/16
        case (172, let second) where second & 0xF0 == 16: return 20  // Private 172.16.0.0/12
        default: return 0
        }
    }

    /// Integer nanoseconds, as in Go `time.Duration`. Clamps between 0 and `pingTimeout`.
    private static func nanoseconds(_ duration: Duration) -> Int64 {
        let (seconds, attoseconds) = min(max(duration, .zero), pingTimeout).components
        return seconds * 1_000_000_000 + attoseconds / 1_000_000_000
    }
}
