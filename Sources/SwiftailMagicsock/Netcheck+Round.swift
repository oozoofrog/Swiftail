// 회차의 요청 계획은 Tailscale의 `net/netcheck/netcheck.go`(BSD-3-Clause, Copyright (c) Tailscale Inc & contributors)
// `makeProbePlanInitial`(:559-587)과 `runProbe`, `addNodeLatency`를 따른다. 코드는 Swift로 새로 썼다.

import SwiftailBase

extension Netcheck {
    /// 아직 보내지 않은 요청 하나.
    struct PendingRequest: Sendable, Equatable {
        var due: ContinuousClock.Instant
        var region: Int64
        var server: IPEndpoint
    }

    /// 보내고 응답을 기다리는 요청 하나.
    struct SentRequest: Sendable, Equatable {
        var region: Int64
        var sentAt: ContinuousClock.Instant
    }

    /// 회차 하나. 회차가 끝나면 버린다(그래서 표의 크기는 지역 수 × 3을 넘지 않는다. 계약 H).
    struct Round: Sendable {
        let start: ContinuousClock.Instant
        /// 보낼 시각 순으로 늘어놓은, 아직 보내지 않은 요청.
        var pending: [PendingRequest]
        /// 보낸 요청. 응답의 TxID가 여기 있을 때만 이번 회차의 응답이다(DERP 노트 4.10 1).
        var inFlight: [TransactionID: SentRequest] = [:]
        /// 이 회차가 기다리는 지역: STUN 서버가 있는 지역.
        let expected: Set<Int64>
        /// 지역별 최소 지연(나노초).
        var latency: [Int64: Int64] = [:]
        /// 응답에서 본 바깥 주소와 관측 횟수. 처음 본 순서대로다(노트 4.9 1.2).
        var observations: [(address: IPEndpoint, count: Int)] = []
    }

    /// 회차를 시작하고 첫 요청들을 낸다. 보낼 곳이 없는 회차는 곧바로 끝난다.
    ///
    /// 지역마다 `stunServers[try % count]`로 0, 100, 200 ms에 하나씩, 지역당 3개를 계획한다. 시작하면서 주기 시각을 비우고
    /// 다음 주기 간격을 미리 뽑는다.
    mutating func startRound(at now: ContinuousClock.Instant, using generator: inout some RandomNumberGenerator) -> [Action] {
        periodicAt = nil
        periodicInterval = .milliseconds(Int.random(in: Self.periodicIntervalMilliseconds, using: &generator))
        var pending: [PendingRequest] = []
        for attempt in 0..<Self.requestsPerRegion {
            for region in regions where !region.stunServers.isEmpty {
                pending.append(PendingRequest(
                    due: now + Self.retransmitInterval * attempt,
                    region: region.id,
                    server: region.stunServers[attempt % region.stunServers.count]
                ))
            }
        }
        let expected = Set(regions.filter { !$0.stunServers.isEmpty }.map(\.id))
        round = Round(start: now, pending: pending, expected: expected)

        var actions = sendDueRequests(at: now, using: &generator)
        if expected.isEmpty { actions += finishRound(at: now) }
        return actions
    }

    /// 보낼 시각이 된 요청을 TxID를 뽑아 낸다. 이미 답한 지역의 요청은 계획에서 이미 빠졌다.
    mutating func sendDueRequests(at now: ContinuousClock.Instant, using generator: inout some RandomNumberGenerator) -> [Action] {
        guard var current = round else { return [] }
        let dueCount = current.pending.prefix(while: { $0.due <= now }).count
        var actions: [Action] = []
        for request in current.pending.prefix(dueCount) {
            let txID = TransactionID.random(using: &generator)
            current.inFlight[txID] = SentRequest(region: request.region, sentAt: now)
            actions.append(.sendSTUN(STUNMessage.bindingRequest(txID), to: request.server))
        }
        current.pending.removeFirst(dueCount)
        round = current
        return actions
    }

    /// STUN 응답 하나를 맞춰 본다. 진행 중인 회차에서 보낸 요청의 응답이 아니면 nil이다(`unexpectedSTUN`).
    ///
    /// 첫 응답이 그 지역의 지연을 정하고 그 지역의 남은 요청을 취소한다(Go `cancelSet`). 같은 TxID의 두 번째 응답은
    /// 받지 않는다. 기다리는 지역이 모두 답하면 회차를 끝낸다.
    mutating func receive(
        _ txID: TransactionID,
        mapped: IPEndpoint,
        at now: ContinuousClock.Instant
    ) -> [Action]? {
        guard var current = round, let sent = current.inFlight.removeValue(forKey: txID) else { return nil }
        let elapsed = Self.nanoseconds(sent.sentAt.duration(to: now))
        current.latency[sent.region] = min(current.latency[sent.region] ?? .max, elapsed)
        current.pending.removeAll { $0.region == sent.region }
        // 소켓이 IPv4 하나이므로 IPv6나 포트 0인 바깥 주소는 엔드포인트로 올리지 않는다. 그래도 그 지역이 답했다는 사실은 센다.
        if mapped.address.isIPv4, mapped.port != 0 {
            if let index = current.observations.firstIndex(where: { $0.address == mapped }) {
                current.observations[index].count += 1
            } else {
                current.observations.append((mapped, 1))
            }
        }
        round = current
        guard current.expected.isSubset(of: Set(current.latency.keys)) else { return [] }
        return finishRound(at: now)
    }

    /// 회차를 끝낸다: 홈 지역과 엔드포인트 목록을 다시 정하고 주기를 잇거나 멈춘다.
    ///
    /// 낸 순서는 `.endpointsChanged`, `.homeRegionChanged`, `.endpointsRefreshed`다. `.endpointsRefreshed`가 마지막인 것은
    /// 그 뒤에 보내는 CallMeMaybe가 새 목록을 담게 하기 위해서다.
    mutating func finishRound(at now: ContinuousClock.Instant) -> [Action] {
        guard let finished = round else { return [] }
        round = nil
        periodicAt = isActive ? now + periodicInterval : nil

        var actions: [Action] = []
        let newEndpoints = endpointList(from: finished)
        if !Self.sameSet(newEndpoints, endpoints) {
            actions.append(.endpointsChanged(newEndpoints))
        }
        endpoints = newEndpoints
        endpointsRefreshedAt = now

        let newHome = selectHome(after: finished, at: now)
        if newHome != homeRegion {
            homeRegion = newHome
            actions.append(.homeRegionChanged(newHome))
        }
        actions.append(.endpointsRefreshed)
        return actions
    }
}
