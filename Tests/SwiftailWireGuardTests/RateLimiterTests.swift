// Rate-limiting tests. The first test was ported from wireguard-go.
// Origin is `ratelimiter/ratelimiter_test.go` in github.com/tailscale/wireguard-go v0.0.0-20261106233718-9e0ab45c16ca.
// Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved. SPDX-License-Identifier: MIT

import Testing

import SwiftailBase
@testable import SwiftailWireGuard

@Suite("Per-source rate limiting")
struct RateLimiterTests {
    @Test("Go TestRatelimiter allows a burst of 5, 1 every 50 ms, and 2 after 100 ms")
    func goSchedule() throws {
        let packetCost = Duration.milliseconds(50)
        // (Wait time, expected result). Go adds 1 ns to the wait time at each step.
        let schedule: [(wait: Duration, allowed: Bool)] = [
            (.zero, true), (.zero, true), (.zero, true), (.zero, true), (.zero, true),  // Initial burst
            (.zero, false),             // After the burst
            (packetCost, true),         // Refilled enough for one packet
            (.zero, false),             // Insufficient refill
            (packetCost * 2, true),     // Enough for two packets
            (.zero, true),              // Second packet of the two-packet burst
            (.zero, false),             // Next packet
        ]
        let hosts = try ["127.0.0.1", "192.168.1.1", "172.167.2.3", "97.231.252.215", "248.97.91.167", "188.208.233.47",
                         "104.2.183.179", "72.129.46.120", "2001:0db8:0a0b:12f0:0000:0000:0000:0001",
                         "f5c2:818f:c052:655a:9860:b136:6894:25f0", "b2d7:15ab:48a7:b07c:a541:f144:a9fe:54fc",
                         "a47b:786e:1671:a22b:d6f9:4ab0:abc7:c918", "ea1e:d155:7f7a:98fb:2bf5:9483:80f6:5445",
                         "3f0e:54a2:f5b4:cd19:a21d:58e1:3746:84c4"].map { try #require(IPAddress($0)).bytes }

        var limiter = RateLimiter()
        var now = t0
        for (step, entry) in schedule.enumerated() {
            now += entry.wait + .nanoseconds(1)
            for host in hosts {
                let result = limiter.allow(host, at: now)
                #expect(result == entry.allowed, "Step \(step)")
            }
        }
    }

    @Test("A full table rejects new hosts and accepts them after deleting entries idle for more than 1 second")
    func tableLimit() {
        var limiter = RateLimiter()
        func host(_ i: Int) -> [UInt8] { [10, UInt8(i >> 16 & 0xFF), UInt8(i >> 8 & 0xFF), UInt8(i & 0xFF)] }
        func allow(_ host: [UInt8], at now: ContinuousClock.Instant) -> Bool { limiter.allow(host, at: now) }
        for i in 0..<RateLimiter.maximumEntries {
            #expect(allow(host(i), at: t0))
        }
        let newcomer = host(RateLimiter.maximumEntries)
        #expect(!allow(newcomer, at: t0))
        // At exactly 1 second, the entries stay (Go also waits until more than 1 second has elapsed). Existing hosts are still accepted.
        #expect(!allow(newcomer, at: t0 + .seconds(1)))
        #expect(allow(host(0), at: t0 + .seconds(1)))
        // After that, idle entries are deleted and a new host is accepted. The recently used host(0) stays.
        #expect(allow(newcomer, at: t0 + .seconds(1) + .nanoseconds(1)))
        #expect(allow(host(1), at: t0 + .seconds(1) + .nanoseconds(2)))
    }
}
