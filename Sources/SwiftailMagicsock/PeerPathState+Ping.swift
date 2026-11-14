// Ping 보내기, Pong 처리, Ping 기한, 전체 Ping, heartbeat의 규칙은 Go 구현을 따라 옮겼다.
// 출처: tailscale.com v1.104.6 `wgengine/magicsock/endpoint.go` (`startDiscoPingLocked`,
// `sendDiscoPingsLocked`, `discoPingTimeout`, `handlePongConnLocked`, `heartbeat`, `wantFullPingLocked`).
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import SwiftailBase

/// 후보에 Ping을 보내고 Pong으로 `bestAddr`와 신뢰를 세우는 일.
///
/// - 보낸 Ping은 `pingTimeout`(5초) 동안 Pong을 기다린다. 기한이 지나면 지우되, 그 Ping이 `bestAddr`로 갔고
///   신뢰도 이미 지났을 때만 `bestAddr`를 지운다. Ping 하나의 유실로 경로를 버리지 않는다(노트 4.6 3).
/// - UDP로 온 Pong은 Ping을 보낸 후보의 지연을 재고, 그 후보가 `bestAddr`보다 낫거나 신뢰가 지났으면
///   `bestAddr`로 삼는다. `bestAddr`의 Pong이면 신뢰를 6.5초 늘린다(노트 4.6 4).
/// - 전체 Ping은 `pingInterval`(5초) 안에 Ping하지 않은 모든 후보에 Ping한다(노트 4.8 1).
/// - heartbeat는 송신이 이어지는 동안 3초마다 `bestAddr`에 Ping하고 필요하면 전체 Ping을 한다(노트 4.8 3).
///
/// 보낸 Ping 표는 `maxSentPings`를 넘지 않는다. 가득 차면 새 Ping을 보내지 않고 기한이 표를 비운다(계약 H).
extension PeerPathState {
    /// Pong을 기다리는 Ping 하나. Go `sentPing`.
    struct SentPing: Sendable, Equatable {
        let destination: IPEndpoint
        let sentAt: ContinuousClock.Instant
    }

    /// Pong이 확인한 직접 주소와 그때의 왕복 지연. Go `addrQuality`에서 MTU와 relay(VNI)를 뺀 것이다.
    struct AddressQuality: Sendable, Equatable {
        var address: IPEndpoint
        /// 0 이상, `pingTimeout` 미만이다(기한이 지난 Ping의 Pong은 받지 않는다).
        var latency: Duration
    }

    /// 피어당 Pong을 기다리는 Ping의 상한(계약 H).
    static let maxSentPings = 128

    /// 이 피어가 보낸 Ping의 Pong이면 true(노트 4.6 4). `source`가 nil이면 DERP로 왔다.
    ///
    /// 기한이 지난 Ping의 Pong은 모르는 TxID와 같다(Go에서는 기한 타이머가 이미 지웠다). 그 Ping은 표에 남겨
    /// 다음 `advance`가 기한 처리를 하게 둔다.
    mutating func receivePong(_ txID: TransactionID, from source: IPEndpoint?, at now: ContinuousClock.Instant) -> Bool {
        guard let ping = sentPings[txID], now < ping.sentAt + Self.pingTimeout else { return false }
        sentPings[txID] = nil
        // DERP로 온 Pong은 직접 경로의 증거가 아니다.
        guard source != nil else { return true }
        // 그 사이 지운 후보면 쓰지 않는다. 판단은 Pong의 출처가 아니라 Ping을 보낸 주소로 한다(Go와 같다).
        guard candidates.contains(where: { $0.address == ping.destination }) else { return true }

        // 시각이 거꾸로 온 호출이면 지연을 0으로 본다.
        let pong = AddressQuality(address: ping.destination, latency: max(.zero, now - ping.sentAt))
        if Self.isBetter(pong, than: bestAddr) || !isTrusted(at: now) {
            bestAddr = pong
        }
        if bestAddr?.address == pong.address {
            bestAddr?.latency = pong.latency
            trustedUntil = now + Self.trustDuration
        }
        return true
    }

    /// 전체 Ping(노트 4.8 1, Go `sendDiscoPingsLocked`). 지울 후보를 지우고, `pingInterval` 안에 Ping하지 않은
    /// 후보마다 Ping한다. 하나라도 보냈고 `sendCallMeMaybe`이며 홈 DERP가 있으면 CallMeMaybe도 낸다.
    mutating func pingAllCandidates(
        at now: ContinuousClock.Instant,
        sendCallMeMaybe: Bool,
        using generator: inout some RandomNumberGenerator
    ) -> [Action] {
        lastFullPing = now
        removeStaleCandidates(at: now)
        var actions: [Action] = []
        for candidate in candidates {
            if let lastPingSent = candidate.lastPingSent, now - lastPingSent < Self.pingInterval { continue }
            if let ping = startPing(to: candidate.address, at: now, using: &generator) {
                actions.append(ping)
            }
        }
        // Go는 Ping 표 한도가 없어 "보내려 한 후보가 있음"을 본다. 여기서는 실제로 보낸 Ping이 있어야 한다.
        if !actions.isEmpty, sendCallMeMaybe, homeDERP != 0 {
            actions.append(.callMeMaybe)
        }
        return actions
    }

    /// 후보 하나에 Ping한다(Go `startDiscoPingLocked`). 후보가 아니거나 Ping 표가 가득이면 보내지 않는다.
    private mutating func startPing(
        to address: IPEndpoint,
        at now: ContinuousClock.Instant,
        using generator: inout some RandomNumberGenerator
    ) -> Action? {
        guard sentPings.count < Self.maxSentPings,
              let index = candidates.firstIndex(where: { $0.address == address })
        else { return nil }
        candidates[index].lastPingSent = now
        let txID = TransactionID.random(using: &generator)
        sentPings[txID] = SentPing(destination: address, sentAt: now)
        return .ping(txID, to: address)
    }

    /// 기한(`pingTimeout`)이 지난 Ping을 지운다(노트 4.6 3, Go `discoPingTimeout`).
    ///
    /// 결과가 처리 순서에 기대지 않으므로 지난 것을 한 번에 지운다.
    mutating func expirePings(at now: ContinuousClock.Instant) {
        let expired = sentPings.filter { $0.value.sentAt + Self.pingTimeout <= now }
        for (txID, ping) in expired {
            sentPings[txID] = nil
            if ping.destination == bestAddr?.address, !isTrusted(at: now) {
                clearBestAddr()
            }
        }
    }

    /// heartbeat 하나(노트 4.8 3, Go `heartbeat`). 유휴가 아니면 3초 뒤로 다시 건다.
    mutating func heartbeat(at now: ContinuousClock.Instant, using generator: inout some RandomNumberGenerator) -> [Action] {
        heartbeatDeadline = nil
        // 송신 기록이 없으면(disco 키가 바뀜) 멈춘다. 마지막 송신 뒤 45초가 넘었으면 멈추고 다음 송신이 다시 건다.
        guard let lastSend, now - lastSend <= Self.sessionActiveTimeout else { return [] }
        var actions: [Action] = []
        // 신뢰와 무관하게 `bestAddr`를 살핀다.
        if let bestAddr, let ping = startPing(to: bestAddr.address, at: now, using: &generator) {
            actions.append(ping)
        }
        if wantsFullPing(at: now) {
            actions += pingAllCandidates(at: now, sendCallMeMaybe: true, using: &generator)
        }
        heartbeatDeadline = now + Self.heartbeatInterval
        return actions
    }

    /// heartbeat가 전체 Ping을 해야 하는가(Go `wantFullPingLocked`). 지연이 5 ms 이하인 신뢰된 직접 경로는
    /// 더 찾지 않고, 그보다 느리면 1분마다 더 나은 길을 찾는다.
    private func wantsFullPing(at now: ContinuousClock.Instant) -> Bool {
        guard let bestAddr, let lastFullPing, isTrusted(at: now) else { return true }
        if bestAddr.latency <= Self.goodEnoughLatency { return false }
        return now - lastFullPing >= Self.upgradeInterval
    }
}
