// 두 직접 주소의 비교는 Go 구현을 따라 옮겼다.
// 출처: tailscale.com v1.104.6 `wgengine/magicsock/endpoint.go` (`betterAddr`),
// Go 표준 라이브러리 `net/netip` (`Addr.IsLoopback`, `IsLinkLocalUnicast`, `IsPrivate`의 IPv4 범위).
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import SwiftailBase

/// 새로 Pong이 온 주소가 지금의 `bestAddr`보다 나은가(노트 4.7).
///
/// 두 주소는 0점에서 시작한다. 느린 쪽에 대해 빠른 쪽이 몇 퍼센트 빠른지가 빠른 쪽의 점수가 되고, 주소의 종류로
/// 점수를 더한다(loopback +50, link-local +30, 사설 +20). 새 주소가 1% 이하로만 빠르면 바꾸지 않아 비슷한
/// 두 경로 사이를 오가지 않는다. 같은 기계의 Go 피어가 `127.0.0.1:p`와 LAN 주소를 함께 알리면 지연이 비슷한 한
/// loopback이 이긴다(노트 4.7 계산).
///
/// shortcut: Go의 같은 주소 MTU 비교(경로 MTU 측정), peer relay(Geneve) 경로 비교, IPv6 +10점은 없다. MTU를
/// 재지 않고 relay를 쓰지 않으며 후보가 IPv4뿐이기 때문이다(계약 "제외"). 필요해지는 시점: 각각 경로 MTU 측정,
/// peer relay, IPv6 후보를 넣을 때.
extension PeerPathState {
    /// `a`가 `b`보다 나으면 true. `b`가 없으면 언제나 낫고, 같은 주소는 낫지 않다.
    ///
    /// 지연은 0 이상 `pingTimeout`(5초) 미만이다. 그 밖의 값은 그 범위로 잘라 나노초에 100을 곱해도 `Int64`를
    /// 넘지 않게 한다.
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

    /// 주소의 종류에 따른 가산점. 비용이 들지 않을 가능성이 큰 가까운 주소를 고른다.
    private static func preferencePoints(_ address: IPAddress) -> Int64 {
        let bytes = address.bytes
        guard bytes.count == 4 else { return 0 }
        switch (bytes[0], bytes[1]) {
        case (127, _): return 50                        // loopback 127.0.0.0/8
        case (169, 254): return 30                      // link-local 169.254.0.0/16
        case (10, _), (192, 168): return 20             // 사설 10.0.0.0/8, 192.168.0.0/16
        case (172, let second) where second & 0xF0 == 16: return 20  // 사설 172.16.0.0/12
        default: return 0
        }
    }

    /// Go `time.Duration`과 같은 나노초 정수. 0과 `pingTimeout` 사이로 자른다.
    private static func nanoseconds(_ duration: Duration) -> Int64 {
        let (seconds, attoseconds) = min(max(duration, .zero), pingTimeout).components
        return seconds * 1_000_000_000 + attoseconds / 1_000_000_000
    }
}
