// The token rules are ported from wireguard-go.
// Origin: github.com/tailscale/wireguard-go v0.0.0-20261106233718-9e0ab45c16ca `ratelimiter/ratelimiter.go`.
// Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved. SPDX-License-Identifier: MIT

/// Limits handshake messages with valid mac2 per source host under load.
///
/// The cookie proves only that the sender can receive replies at that source. An attacker with a real address can still force
/// X25519 computations after obtaining a cookie, so process at most 20 per second per host (burst of 5).
///
/// The table is state that grows with input. wireguard-go removes entries unused for more than 1 second every 1 second and has no count limit.
/// Here, the count is capped at `maximumEntries`, and entries unused for more than 1 second are removed only when the table is full. If it remains full,
/// new hosts are denied (fail closed, preserving existing hosts' allowance and keeping memory from growing with the input).
/// Delaying removal of old entries gives the same result. An entry idle for more than 1 second is full of tokens, so it accepts its first message
/// and leaves 4 messages' worth of burst capacity, just like an entry that was removed and recreated.
///
/// The rate limiter in “mac1, mac2, and cookie” in `docs/protocol-notes/wireguard.md`.
struct RateLimiter {
    private struct Bucket {
        var tokens: Duration
        var lastTime: ContinuousClock.Instant
    }

    /// The cost of one message, at 20 per second (`packetsPerSecond`).
    private static let packetCost: Duration = .seconds(1) / 20
    /// The token capacity (`packetsBurstable`, enough for 5 messages).
    private static let maxTokens = packetCost * 5
    /// Entries unused for longer than this can be removed (`garbageCollectTime`).
    private static let idleTime: Duration = .seconds(1)
    /// The maximum number of table entries. See “Sending cookie replies (2026-11-15)” in `docs/contracts/SwiftailWireGuard.md` for the rationale.
    static let maximumEntries = 4096

    private var buckets: [[UInt8]: Bucket] = [:]

    /// Returns whether a message from `host` can be processed now and consumes its allowance if so.
    ///
    /// A new host's first message is accepted, leaving `maxTokens − packetCost` tokens. For known hosts, replenish tokens based on elapsed time
    /// up to `maxTokens` and accept only when the balance is **greater than** `packetCost` (the same strict comparison as in Go).
    mutating func allow(_ host: [UInt8], at now: ContinuousClock.Instant) -> Bool {
        guard var bucket = buckets[host] else {
            if buckets.count >= Self.maximumEntries {
                buckets = buckets.filter { now - $0.value.lastTime <= Self.idleTime }
            }
            guard buckets.count < Self.maximumEntries else { return false }
            buckets[host] = Bucket(tokens: Self.maxTokens - Self.packetCost, lastTime: now)
            return true
        }
        bucket.tokens = min(bucket.tokens + (now - bucket.lastTime), Self.maxTokens)
        bucket.lastTime = now
        let allowed = bucket.tokens > Self.packetCost
        if allowed {
            bucket.tokens -= Self.packetCost
        }
        buckets[host] = bucket
        return allowed
    }
}

extension RateLimiter: CustomReflectable {
    /// Shows only the entry count so `print` and `dump` do not expose source addresses.
    var customMirror: Mirror {
        Mirror(self, children: ["count": buckets.count], displayStyle: .struct)
    }
}
