// 경로 선택, 신뢰 기간, 타이머 값은 Go 구현을 따라 옮겼다.
// 출처: tailscale.com v1.104.6 `wgengine/magicsock/endpoint.go` (`addrForSendLocked`, `send`,
// `noteTxActivityExtTriggerLocked`, `updateFromNode`, `changedActiveDiscoLocked`, `populatePeerStatus`,
// `noteConnectivityChange`, `clearBestAddrLocked`, `endpointState.clear`),
// `wgengine/magicsock/magicsock.go` (상수).
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import SwiftailBase

/// 피어 하나와의 직접 UDP 경로를 찾고 유지하는 상태 기계. Go `magicsock.endpoint`의 경로 부분이다.
///
/// 후보 주소에 disco Ping을 보내 Pong이 온 주소 가운데 가장 나은 것을 `bestAddr`로 삼고, 마지막 Pong 뒤
/// 6.5초 동안은 그 주소로만 보낸다. 신뢰가 지났거나 직접 주소가 없으면 피어의 홈 DERP로도 보내며 다시 찾는다.
///
/// 소켓·시계·암호가 없다. 시각과 난수(TxID)는 인자로 받고 보낼 것은 `Action`으로 돌려준다. disco 메시지를
/// 봉해 보내는 일과 CallMeMaybe에 자기 엔드포인트를 채우는 일은 `Magicsock`이 한다.
///
/// 파일: 여기는 상태와 경로 선택, `+Candidates`는 후보 표, `+Ping`은 Ping·Pong·heartbeat,
/// `+BetterAddress`는 두 주소의 비교다.
///
/// `docs/protocol-notes/disco-magicsock.md` 4.4~4.8, `docs/contracts/SwiftailMagicsock.md` 동작 D.
struct PeerPathState: Sendable {
    enum Action: Sendable, Equatable {
        /// 후보에 disco Ping을 보낸다.
        case ping(TransactionID, to: IPEndpoint)
        /// 피어의 홈 DERP로 CallMeMaybe를 보낸다. 자기 엔드포인트는 `Magicsock`이 채운다.
        case callMeMaybe
    }

    /// WireGuard 데이터그램 하나를 보낼 곳(노트 4.5).
    struct SendPlan: Sendable, Equatable {
        /// UDP로 보낼 직접 주소. 없으면 nil.
        var udp: IPEndpoint?
        /// DERP로도 보낸다면 피어의 홈 지역. 0이면 DERP로 보내지 않는다.
        var derpRegion: Int64
        /// 이 송신과 함께 보낼 disco 메시지.
        var actions: [Action]
    }

    // MARK: 상수 (노트 5절. Go 피어의 하강·복귀 시점이 이 값으로 정해지므로 Go와 같게 두고 바꿀 수 없다)

    /// 보낸 Ping의 Pong을 기다리는 기한. `pingTimeoutDuration`(`magicsock.go:4119`, `tsconst/ping.go:11`).
    static let pingTimeout: Duration = .seconds(5)
    /// 같은 후보에 Ping을 다시 보내기까지의 최소 간격. 받은 CallMeMaybe가 풀어 준다.
    /// `discoPingInterval`(`magicsock.go:4125`, `tsconst/ping.go:15`).
    static let pingInterval: Duration = .seconds(5)
    /// 송신이 이어지는 동안 `bestAddr`에 Ping하고 더 나은 길을 찾는 주기. `heartbeatInterval`(`magicsock.go:4099`).
    static let heartbeatInterval: Duration = .seconds(3)
    /// Pong 뒤 `bestAddr`로만 보내는 기간. `trustUDPAddrDuration`(`magicsock.go:4103`).
    static let trustDuration: Duration = .milliseconds(6500)
    /// 마지막 송신 뒤 이만큼 지나면 heartbeat를 멈춘다. Ping으로 배운 후보도 마지막 Ping 뒤 이만큼 지나면 지운다.
    /// `sessionActiveTimeout`(`magicsock.go:4083`).
    static let sessionActiveTimeout: Duration = .seconds(45)
    /// `bestAddr`의 지연이 이 값 이하면 더 나은 길을 찾는 전체 Ping을 하지 않는다. `goodEnoughLatency`(`magicsock.go:4107`).
    static let goodEnoughLatency: Duration = .milliseconds(5)
    /// 지연이 `goodEnoughLatency`보다 큰 직접 경로에서 전체 Ping을 다시 하는 간격.
    /// `upgradeUDPDirectInterval`(`magicsock.go:4087`).
    static let upgradeInterval: Duration = .seconds(60)

    // MARK: 상태

    /// 피어의 홈 DERP 지역. 0이면 모른다.
    private(set) var homeDERP: Int64
    /// 직접 경로 후보. 들어온 순서를 지켜 같은 입력열에는 같은 순서로 Ping한다(`+Candidates`).
    var candidates: [Candidate] = []
    /// Pong을 기다리는 Ping. TxID → 보낸 곳과 시각(`+Ping`).
    var sentPings: [TransactionID: SentPing] = [:]
    /// Pong이 확인한 가장 나은 직접 주소. 언제나 `candidates`에 있는 주소다(지울 때 함께 지운다).
    var bestAddr: AddressQuality?
    /// 이 시각까지(같은 시각 포함) `bestAddr`로만 보낸다. nil이면 신뢰가 없다(Go의 0 시각).
    var trustedUntil: ContinuousClock.Instant?
    /// 마지막 전체 Ping 시각.
    var lastFullPing: ContinuousClock.Instant?
    /// 다음 heartbeat 시각. nil이면 멈춰 있다.
    var heartbeatDeadline: ContinuousClock.Instant?
    /// 마지막 외부 송신(WireGuard 데이터그램) 시각. 없으면 nil. `Magicsock`이 유휴(ReSTUN 멈춤)를 판단한다.
    private(set) var lastSend: ContinuousClock.Instant?

    init(homeDERP: Int64, endpoints: [IPEndpoint]) {
        self.homeDERP = homeDERP
        candidates = Self.candidateAddresses(endpoints).prefix(Self.maxCandidates).map {
            Candidate(address: $0, inNetmap: true)
        }
    }

    /// netmap 갱신(노트 4.4 1·2). 홈 DERP를 바꾸고 netmap 후보를 다시 맞춘다.
    mutating func update(homeDERP: Int64, endpoints: [IPEndpoint], at now: ContinuousClock.Instant) {
        self.homeDERP = homeDERP
        replaceNetmapCandidates(with: endpoints, at: now)
    }

    /// 피어의 disco 키가 바뀌었다(노트 4.4 3).
    ///
    /// 옛 키로 보낸 Ping의 Pong은 새 키로 오지 않으므로 기다리던 Ping과 신뢰를 버리고 처음부터 다시 찾는다.
    /// `bestAddr` 주소는 남겨 새 경로가 설 때까지 UDP로도 함께 보낸다. heartbeat는 다음 기한에 송신 기록이
    /// 없으면 멈춘다(Go와 같다).
    mutating func resetForNewDiscoKey() {
        trustedUntil = nil
        lastSend = nil
        lastFullPing = nil
        sentPings = [:]
        for index in candidates.indices {
            candidates[index].lastPingSent = nil
        }
    }

    /// UDP 소켓이 새로 묶여 옛 경로를 믿을 수 없다(노트 4.11 2, Go `noteConnectivityChange`).
    ///
    /// 지우는 것: `bestAddr`와 신뢰, 후보마다의 Ping 기록(마지막 Ping 시각과 받은 Ping의 TxID), 기다리던 Ping.
    /// 남기는 것: 후보와 그 출처(netmap, 받은 Ping, CallMeMaybe), 마지막 송신 시각, heartbeat(Go는 `lastSendExt`·
    /// `lastFullPing`을 건드리지 않는다. 그것은 disco 키가 바뀔 때의 `resetForNewDiscoKey`다). 그러므로 다음
    /// 송신은 신뢰가 없어 DERP로도 보내고, 모든 후보에 Ping하며 CallMeMaybe를 낸다.
    ///
    /// Go는 기다리던 Ping(`sentPing`)을 지우지 않는다. 여기서는 지운다: 옛 소켓에서 보낸 Ping의 Pong이 뒤늦게 와도
    /// 새 소켓의 경로 증거가 아니기 때문이다.
    ///
    /// shortcut: Go는 `endpointState.clear`로 CallMeMaybe 시각도 지워 그 후보가 다음 netmap 갱신에서 지워질 수 있게
    /// 한다. 여기서는 CallMeMaybe 후보를 다음 CallMeMaybe가 빼 줄 때까지 둔다(출처 표시가 하나다). 필요해지는 시점:
    /// 재결속 뒤 옛 망의 CallMeMaybe 후보에 Ping이 낭비되는 것이 관문에서 보일 때.
    mutating func noteConnectivityChange() {
        clearBestAddr()
        sentPings = [:]
        for index in candidates.indices {
            candidates[index].lastPingSent = nil
            candidates[index].lastPingReceivedTxID = nil
        }
    }

    /// WireGuard 데이터그램 하나를 보낼 곳을 정한다(노트 4.5 1–5, 4.8 2).
    ///
    /// 신뢰 기간 안의 `bestAddr`가 있으면 그 주소로만 보낸다. 아니면 `bestAddr`(있으면)와 홈 DERP로 함께
    /// 보내고 전체 Ping(CallMeMaybe 포함)을 한다. 둘 다 없으면 `udp`가 nil, `derpRegion`이 0이다(`noRouteToPeer`).
    ///
    /// shortcut: 홈 DERP가 0인 피어를 위한 역방향 DERP 지역(노트 4.5 4)은 쓰지 않는다. 필요해지는 시점: 그런
    /// 피어가 실제 tailnet 관문에서 보일 때.
    mutating func planSend(at now: ContinuousClock.Instant, using generator: inout some RandomNumberGenerator) -> SendPlan {
        // Go처럼 보낼 곳을 먼저 정하고 전체 Ping을 한다.
        let trusted = isTrusted(at: now)
        let udp = bestAddr?.address
        let derpRegion = trusted ? 0 : homeDERP
        let actions = trusted ? [] : pingAllCandidates(at: now, sendCallMeMaybe: true, using: &generator)
        lastSend = now
        if heartbeatDeadline == nil {
            heartbeatDeadline = now + Self.heartbeatInterval
        }
        return SendPlan(udp: udp, derpRegion: derpRegion, actions: actions)
    }

    /// 기한이 지난 Ping을 정리하고 heartbeat를 돌린다(노트 4.6 3, 4.8 3).
    ///
    /// 같은 시각에 걸린 것은 Ping 기한을 먼저 처리한다. heartbeat는 지운 `bestAddr`에 Ping하지 않는다.
    mutating func advance(to now: ContinuousClock.Instant, using generator: inout some RandomNumberGenerator) -> [Action] {
        expirePings(at: now)
        var actions: [Action] = []
        if let deadline = heartbeatDeadline, deadline <= now {
            actions = heartbeat(at: now, using: &generator)
        }
        if let until = trustedUntil, now > until {
            // 지난 신뢰는 없는 신뢰와 뜻이 같다. 지워야 `nextDeadline`이 지난 시각을 계속 내지 않는다.
            trustedUntil = nil
        }
        return actions
    }

    /// Ping 기한, heartbeat, 신뢰 만료 가운데 가장 이른 것.
    ///
    /// 신뢰는 `trustedUntil`과 같은 시각까지 남으므로 만료 기한은 그보다 1나노초 뒤다. 그 시각의 `advance` 뒤
    /// `path(at:)`가 `.relayed`로 바뀌어 `Magicsock`이 경로 사건을 낼 수 있다(계약 D7).
    var nextDeadline: ContinuousClock.Instant? {
        let pingDeadlines = sentPings.values.map { $0.sentAt + Self.pingTimeout }
        let trustExpiry = trustedUntil.map { $0 + .nanoseconds(1) }
        return (pingDeadlines + [heartbeatDeadline, trustExpiry].compactMap { $0 }).min()
    }

    /// 피어의 지금 경로. Go `curAddr`와 같은 뜻이다(노트 7.1).
    func path(at now: ContinuousClock.Instant) -> PeerPath {
        if let bestAddr, isTrusted(at: now) {
            return .direct(bestAddr.address)
        }
        return .relayed(derpRegion: homeDERP)
    }

    /// `bestAddr`가 있고 `now ≤ trustedUntil`이다(Go `!now.After(trustBestAddrUntil)`).
    func isTrusted(at now: ContinuousClock.Instant) -> Bool {
        guard bestAddr != nil, let trustedUntil else { return false }
        return now <= trustedUntil
    }

    /// `bestAddr`와 신뢰를 함께 지운다(Go `clearBestAddrLocked`).
    mutating func clearBestAddr() {
        bestAddr = nil
        trustedUntil = nil
    }
}
