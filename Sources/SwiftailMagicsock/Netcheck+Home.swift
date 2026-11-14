// 홈 지역 선택은 Tailscale의 `net/netcheck/netcheck.go`(`addReportHistoryAndSetPreferredDERP`, :1426-1531)와
// `wgengine/magicsock/derp.go`(`pickDERPFallback`)(BSD-3-Clause, Copyright (c) Tailscale Inc & contributors)를
// 따른다. 코드는 Swift로 새로 썼다.

import SwiftailBase

extension Netcheck {
    /// 한 회차가 끝났을 때 잰 지역별 최소 지연(나노초).
    struct LatencyRecord: Sendable, Equatable {
        var at: ContinuousClock.Instant
        var latency: [Int64: Int64]
    }

    /// 회차가 끝났을 때 홈 지역을 고른다(DERP 노트 4.10 5, 계약 E6).
    ///
    /// 1. 최근 5분 5초의 회차 기록에서 지역별 최소 지연을 구하고, 양수인 `score`를 곱한다. 이번 회차에 답한 지역 가운데
    ///    가장 작은 것이 후보다(같으면 ID가 작은 쪽).
    /// 2. 옛 홈이 바뀌려 하는데 아직 닿으면 옛 홈을 유지한다. "닿는다"는 이번 회차에 지연이 있거나, 회차 시작 뒤 또는 8초
    ///    안에 그 지역에서 DERP 패킷을 받았다는 뜻이다. 유지 조건은 새 후보와의 차이가 10 ms 미만이거나, 새 후보가 옛 홈
    ///    지연의 2/3보다 크다.
    /// 3. 측정이 하나도 없으면(후보가 없으면) 옛 홈을 유지한다. 옛 홈도 없으면 지역 ID가 가장 작은 것이다(DERP 노트 4.8 1).
    ///    Go는 마지막 DERP 패킷이 120초 안일 때만 옛 홈을 잇지만 그 뒤의 대체 선택도 옛 홈을 고르므로 결과가 같다.
    ///
    /// 계산은 나노초 `Int64`로 하고, 점수를 곱한 값은 넘치지 않게 막는다.
    mutating func selectHome(after round: Round, at now: ContinuousClock.Instant) -> Int64 {
        history.append(LatencyRecord(at: now, latency: round.latency))
        history.removeAll { $0.at.duration(to: now) > Self.historyRetention }

        let scores = Dictionary(regions.map { ($0.id, $0.score) }, uniquingKeysWith: { first, _ in first })
        func scaled(_ latency: Int64, region: Int64) -> Int64 {
            Self.scaled(latency, by: scores[region] ?? 0)
        }

        var candidate: Int64 = 0
        var bestRecent: Int64 = 0
        var currentLatencyOfHome: Int64?
        for region in round.latency.keys.sorted() {
            let recent = history.compactMap { $0.latency[region] }.min() ?? 0
            let best = scaled(recent, region: region)
            if candidate == 0 || best < bestRecent {
                candidate = region
                bestRecent = best
            }
            if region == homeRegion, let latency = round.latency[region] {
                currentLatencyOfHome = scaled(latency, region: region)
            }
        }

        guard candidate != 0 else {
            return homeRegion != 0 ? homeRegion : regions.map(\.id).min() ?? 0
        }
        guard homeRegion != 0, candidate != homeRegion else { return candidate }

        let lastHeard = derpActivity[homeRegion]
        let heardRecently = lastHeard.map { $0 > round.start || $0 > now - Self.homeFrameRecency } ?? false
        guard currentLatencyOfHome != nil || heardRecently else { return candidate }

        let current = currentLatencyOfHome ?? 0
        let difference = current - bestRecent
        if difference < Self.nanoseconds(Self.homeAbsoluteDifference) || bestRecent > current / 3 * 2 {
            return homeRegion
        }
        return candidate
    }

    /// 지연에 DERPMap의 지역 점수를 곱한다. 점수가 양수일 때만 곱하고, 결과는 0 이상 `Int64.max` 이하로 막는다.
    static func scaled(_ nanoseconds: Int64, by score: Double) -> Int64 {
        guard score > 0 else { return nanoseconds }
        let value = Double(nanoseconds) * score
        guard value < Double(Int64.max) else { return .max }
        return Int64(value)
    }
}
