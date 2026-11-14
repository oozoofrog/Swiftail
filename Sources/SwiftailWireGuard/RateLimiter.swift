// 토큰 규칙은 wireguard-go를 옮겼다.
// 출처: github.com/tailscale/wireguard-go v0.0.0-20261106233718-9e0ab45c16ca `ratelimiter/ratelimiter.go`.
// Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved. SPDX-License-Identifier: MIT

/// 부하 상태에서 mac2까지 맞은 핸드셰이크 메시지를 출처 호스트별로 제한한다.
///
/// cookie는 그 출처에서 답장을 받을 수 있음을 증명할 뿐이다. 실제 주소를 가진 공격자는 cookie를 얻은 뒤에도
/// X25519를 계속 시킬 수 있으므로, 호스트마다 초당 20개(버스트 5)까지만 처리한다.
///
/// 표는 입력으로 커지는 상태다. wireguard-go는 1초 넘게 쓰지 않은 항목을 1초마다 지우고 개수 상한이 없다.
/// 여기서는 개수를 `maximumEntries`로 묶고, 표가 찼을 때만 1초 넘게 쓰지 않은 항목을 지운다. 그래도 차 있으면 새
/// 호스트는 받지 않는다(닫힌 쪽: 이미 표에 있는 호스트의 몫을 지키고, 메모리가 입력만큼 자라지 않는다).
/// 오래된 항목을 늦게 지워도 결과는 같다: 1초 넘게 쉰 항목의 토큰은 상한까지 차 있으므로, 지우고 새로 만든 항목과
/// 똑같이 첫 메시지를 받고 버스트 4개분을 남긴다.
///
/// `docs/protocol-notes/wireguard.md` "mac1·mac2와 cookie"의 rate limiter.
struct RateLimiter {
    private struct Bucket {
        var tokens: Duration
        var lastTime: ContinuousClock.Instant
    }

    /// 메시지 하나의 값: 초당 20개(`packetsPerSecond`).
    private static let packetCost: Duration = .seconds(1) / 20
    /// 쌓을 수 있는 토큰(`packetsBurstable` 5개분).
    private static let maxTokens = packetCost * 5
    /// 이보다 오래 쓰지 않은 항목은 지울 수 있다(`garbageCollectTime`).
    private static let idleTime: Duration = .seconds(1)
    /// 표의 항목 수 상한. 근거는 `docs/contracts/SwiftailWireGuard.md` "cookie reply 보내기".
    static let maximumEntries = 4096

    private var buckets: [[UInt8]: Bucket] = [:]

    /// 호스트 `host`의 메시지 하나를 지금 처리해도 되는가. 되면 그 몫을 쓴다.
    ///
    /// 새 호스트는 첫 메시지를 받고 토큰 `maxTokens − packetCost`로 시작한다. 아는 호스트는 지난 시간만큼 토큰을
    /// 채우되 `maxTokens`를 넘지 않고, 토큰이 `packetCost`보다 **클 때만** 받는다(Go와 같은 엄격한 비교).
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
    /// 출처 주소가 `print`·`dump`에 펼쳐지지 않게 항목 수만 보인다.
    var customMirror: Mirror {
        Mirror(self, children: ["count": buckets.count], displayStyle: .struct)
    }
}
