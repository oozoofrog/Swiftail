// 속도 제한 시험. 첫 시험은 wireguard-go의 시험을 옮겼다.
// 출처: github.com/tailscale/wireguard-go v0.0.0-20261106233718-9e0ab45c16ca `ratelimiter/ratelimiter_test.go`.
// Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved. SPDX-License-Identifier: MIT

import Testing

import SwiftailBase
@testable import SwiftailWireGuard

@Suite("출처별 속도 제한")
struct RateLimiterTests {
    @Test("Go TestRatelimiter: 버스트 5개, 50ms마다 1개, 100ms면 2개")
    func goSchedule() throws {
        let packetCost = Duration.milliseconds(50)
        // (기다릴 시간, 기대) — Go는 단계마다 기다릴 시간에 1ns를 더한다.
        let schedule: [(wait: Duration, allowed: Bool)] = [
            (.zero, true), (.zero, true), (.zero, true), (.zero, true), (.zero, true),  // 처음 버스트
            (.zero, false),             // 버스트 뒤
            (packetCost, true),         // 한 개분을 채웠다
            (.zero, false),             // 덜 찼다
            (packetCost * 2, true),     // 두 개분
            (.zero, true),              // 두 개 버스트의 두 번째
            (.zero, false),             // 그다음
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
                #expect(result == entry.allowed, "단계 \(step)")
            }
        }
    }

    @Test("표가 차면 새 호스트를 받지 않고, 1초 넘게 쉰 항목을 지운 뒤에는 받는다")
    func tableLimit() {
        var limiter = RateLimiter()
        func host(_ i: Int) -> [UInt8] { [10, UInt8(i >> 16 & 0xFF), UInt8(i >> 8 & 0xFF), UInt8(i & 0xFF)] }
        func allow(_ host: [UInt8], at now: ContinuousClock.Instant) -> Bool { limiter.allow(host, at: now) }
        for i in 0..<RateLimiter.maximumEntries {
            #expect(allow(host(i), at: t0))
        }
        let newcomer = host(RateLimiter.maximumEntries)
        #expect(!allow(newcomer, at: t0))
        // 1초 정각에는 아직 지우지 않는다(Go도 1초를 넘어야 지운다). 이미 있는 호스트는 그대로 받는다.
        #expect(!allow(newcomer, at: t0 + .seconds(1)))
        #expect(allow(host(0), at: t0 + .seconds(1)))
        // 그 뒤에는 쉰 항목을 지우고 받는다. 방금 쓴 host(0)은 남는다.
        #expect(allow(newcomer, at: t0 + .seconds(1) + .nanoseconds(1)))
        #expect(allow(host(1), at: t0 + .seconds(1) + .nanoseconds(2)))
    }
}
