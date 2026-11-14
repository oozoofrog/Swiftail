// STUN 회차와 홈 지역 선택은 Tailscale의 `net/netcheck/netcheck.go`와
// `wgengine/magicsock/magicsock.go`(BSD-3-Clause, Copyright (c) Tailscale Inc & contributors)의 규칙을 따른다.
// 상수와 판정 조건을 옮겼고 코드는 Swift로 새로 썼다.

import SwiftailBase

/// 자기 바깥 주소(엔드포인트)와 홈 DERP 지역을 정하는 상태 기계. 소켓도 시계도 갖지 않는다.
///
/// 하는 일: DERP 지역의 STUN 서버에 요청을 보내는 **회차**를 돌리고, 응답으로 자기 바깥 주소와 지역별 지연을 모으고,
/// 회차가 끝나면 엔드포인트 목록과 홈 지역을 다시 정한다. 노드는 `Action`의 `.sendSTUN`을 UDP 소켓으로 보내고,
/// 받은 STUN 응답을 `receive`에, 시각이 `nextDeadline`에 이르면 `advance`에 넣는다. 시각과 난수(TxID, 다음 회차 간격)는
/// 인자로 받으므로 시험이 직접 넘길 수 있다.
///
/// 절차: `docs/protocol-notes/derp-stun.md` 4.8(홈 지역)·4.10(STUN 질의와 홈 선택), `disco-magicsock.md` 4.9(엔드포인트),
/// 계약 `docs/contracts/SwiftailMagicsock.md` E절. 이 파일은 상태와 진입점을 담고, 회차는 `Netcheck+Round.swift`,
/// 엔드포인트 목록은 `Netcheck+Endpoints.swift`, 홈 선택은 `Netcheck+Home.swift`에 있다.
///
/// - `shortcut:` UDP가 막혀 STUN 응답이 하나도 없을 때의 HTTPS 지연 측정(DERP 노트 4.10 4)은 하지 않는다. 그때는 기존 홈을
///   유지한다. 필요해지는 시점: UDP가 막힌 망에서 홈이 잘못 남는 것이 관문에서 보일 때.
/// - `shortcut:` `ipv4`가 빈 DERP 노드의 DNS 조회는 하지 않는다(값 타입은 DNS를 못 한다). STUN 주소는 노드가 IPv4 리터럴로
///   뽑아 `Magicsock.Region.stunServers`에 넣는다. 필요해지는 시점: 리터럴 없는 DERPMap을 만날 때.
/// - `shortcut:` Go의 증분 회차(홈과 가까운 지역만 다시 재기)와 "세 지역이 답하면 지연의 2배 뒤 마감"은 쓰지 않는다. 회차는
///   언제나 모든 지역을 재고 모두 답하거나 3초가 지나면 끝난다. 필요해지는 시점: 지역이 많은 DERPMap에서 회차 비용이 문제일 때.
struct Netcheck: Sendable {
    enum Action: Sendable, Equatable {
        /// UDP 소켓으로 `to`에 보낸다. WireGuard·disco와 같은 소켓이어야 응답의 주소가 엔드포인트가 된다(DERP 노트 4.10 2).
        case sendSTUN([UInt8], to: IPEndpoint)
        /// 올릴 엔드포인트 목록이 집합으로 바뀌었다(순서는 의미가 있다. 노트 4.9 1).
        case endpointsChanged([Magicsock.Endpoint])
        /// 홈 지역이 바뀌었다.
        case homeRegionChanged(Int64)
        /// 회차가 끝나 자기 엔드포인트를 다시 정했다(목록이 같아도). 미뤄 둔 CallMeMaybe를 보낼 때다.
        case endpointsRefreshed
    }

    // MARK: 상수. Go와 같다. 바꿀 수 있게 하지 않는다.

    /// 지역마다 보내는 요청 수. 0, 100, 200 ms에 하나씩이다(`netcheck.go:559-587`, `makeProbePlanInitial`).
    static let requestsPerRegion = 3
    /// 같은 지역의 요청 사이 간격(`netcheck.go:87` `defaultInitialRetransmitTime`).
    static let retransmitInterval = Duration.milliseconds(100)
    /// 회차의 최대 길이. 이 시간 안에 답하지 않은 지역은 빠진다(`netcheck.go:66` `stunProbeTimeout`).
    static let roundTimeout = Duration.seconds(3)
    /// 주기 회차 간격의 범위(밀리초). 30초인 흔한 NAT 매핑 수명보다 짧다(`magicsock.go:904`).
    static let periodicIntervalMilliseconds = 20_000...26_000
    /// 홈 선택에 쓰는 회차 기록의 보존 기간: 5분 + 보고 시간 5초(`netcheck.go:1379`, `:1416`).
    static let historyRetention = Duration.seconds(5 * 60 + 5)
    /// 홈을 옮기려면 새 후보가 옛 홈보다 이만큼 이상 빨라야 한다(`netcheck.go:1387` `preferredDERPAbsoluteDiff`).
    static let homeAbsoluteDifference = Duration.milliseconds(10)
    /// 이 안에 DERP 패킷을 받은 지역은 STUN 응답이 없어도 닿는다고 본다(`netcheck.go:1396` `PreferredDERPFrameTime`).
    static let homeFrameRecency = Duration.seconds(8)

    // MARK: 입력

    /// 소켓이 묶인 포트와 인터페이스 주소. 엔드포인트 목록의 입력이고 `rebind`만 바꾼다.
    private(set) var localPort: UInt16
    private(set) var localAddresses: [IPAddress]
    private(set) var loopbackAddresses: [IPAddress]

    // MARK: 상태

    /// 홈 후보 지역(중복 ID는 앞의 것만 갖는다).
    var regions: [Magicsock.Region] = []
    /// 진행 중인 회차. 없으면 nil.
    var round: Round?
    /// 다음 주기 회차의 시각. nil이면 주기가 멈췄다.
    var periodicAt: ContinuousClock.Instant?
    /// 다음 회차 간격. 회차를 시작할 때 뽑아 두므로 회차가 `receive`로 끝나도 난수가 필요 없다.
    var periodicInterval = Duration.milliseconds(Self.periodicIntervalMilliseconds.lowerBound)
    /// `advance`가 마지막으로 받은 `isActive`. `receive`로 끝나는 회차가 주기를 이을지 정한다.
    var isActive = true
    /// 최근 회차들의 지역별 최소 지연(홈 선택의 입력).
    var history: [LatencyRecord] = []
    /// 지역별로 DERP 패킷을 마지막으로 받은 시각(홈 후보 지역만).
    var derpActivity: [Int64: ContinuousClock.Instant] = [:]

    /// 지금 홈 지역. 0이면 아직 없다.
    var homeRegion: Int64 = 0
    /// 마지막으로 정한 자기 엔드포인트 목록. 첫 회차가 끝나기 전에는 비어 있다.
    var endpoints: [Magicsock.Endpoint] = []
    /// 마지막으로 회차를 끝낸 시각. CallMeMaybe의 27초 신선도(노트 4.8 4.1)를 판단하는 데 쓴다.
    var endpointsRefreshedAt: ContinuousClock.Instant?

    init(localPort: UInt16, localAddresses: [IPAddress], loopbackAddresses: [IPAddress]) {
        self.localPort = localPort
        self.localAddresses = localAddresses
        self.loopbackAddresses = loopbackAddresses
    }

    // MARK: 진입점

    /// 홈 후보 지역을 맞춘다. 바뀌었으면 홈을 보정하고 곧바로 새 회차를 시작한다.
    ///
    /// 홈이 없거나 새 목록에 없으면 지역 ID가 가장 작은 것을 곧바로 홈으로 낸다. 첫 회차(3초)를 기다리지 않고 DERP에 붙기
    /// 위해서다(DERP 노트 4.8 1, 계약 E6 "대체 홈"). 지역이 하나도 없으면 회차를 돌리지 않는다. Go도 DERPMap과 STUN 결과가
    /// 없는 엔드포인트는 저장하지도 올리지도 않는다(노트 4.9 5).
    mutating func setRegions(
        _ regions: [Magicsock.Region],
        at now: ContinuousClock.Instant,
        using generator: inout some RandomNumberGenerator
    ) -> [Action] {
        var unique: [Magicsock.Region] = []
        for region in regions where !unique.contains(where: { $0.id == region.id }) {
            unique.append(region)
        }
        guard unique != self.regions else { return [] }
        self.regions = unique
        derpActivity = derpActivity.filter { id, _ in unique.contains { $0.id == id } }
        round = nil
        periodicAt = nil
        guard let fallback = unique.map(\.id).min() else { return [] }

        var actions: [Action] = []
        if homeRegion == 0 || !unique.contains(where: { $0.id == homeRegion }) {
            homeRegion = fallback
            actions.append(.homeRegionChanged(fallback))
        }
        isActive = true
        actions += startRound(at: now, using: &generator)
        return actions
    }

    /// 회차가 진행 중이 아니면 새로 시작한다(노트 4.8 4.1의 ReSTUN). 지역이 없으면 아무것도 하지 않는다.
    ///
    /// 주기가 멈춘 상태(`nextDeadline`이 nil)에서 피어에게 보낼 때도 이것을 불러 주기를 다시 건다.
    mutating func reSTUN(at now: ContinuousClock.Instant, using generator: inout some RandomNumberGenerator) -> [Action] {
        guard round == nil, !regions.isEmpty else { return [] }
        isActive = true
        return startRound(at: now, using: &generator)
    }

    /// 소켓이 새로 묶였다(노트 4.11 2). 엔드포인트의 입력을 바꾸고, 진행 중인 회차를 버리고 새 회차를 곧바로 시작한다.
    ///
    /// 진행 중이던 회차는 옛 소켓에서 보낸 것이라 그 응답은 이제 어떤 요청과도 맞지 않는다(`unexpectedSTUN`). 지역이
    /// 없으면 회차를 시작하지 않고, 지역이 올 때 `setRegions`가 새 입력으로 회차를 시작한다.
    mutating func rebind(
        localPort: UInt16,
        localAddresses: [IPAddress],
        loopbackAddresses: [IPAddress],
        at now: ContinuousClock.Instant,
        using generator: inout some RandomNumberGenerator
    ) -> [Action] {
        self.localPort = localPort
        self.localAddresses = localAddresses
        self.loopbackAddresses = loopbackAddresses
        round = nil
        periodicAt = nil
        return reSTUN(at: now, using: &generator)
    }

    /// DERP 지역에서 패킷을 받았다. 옛 홈이 아직 닿는지 판단하는 데 쓴다(DERP 노트 4.10 5). 후보가 아닌 지역은 무시한다.
    mutating func noteDERPActivity(region: Int64, at now: ContinuousClock.Instant) {
        guard regions.contains(where: { $0.id == region }) else { return }
        derpActivity[region] = now
    }

    /// 기한이 지난 일을 처리한다: 회차의 다음 요청, 회차 마감, 주기 회차 시작.
    ///
    /// - Parameter isActive: 피어가 있고 45초 안에 송신이 있었다. 거짓이면 주기 회차를 멈춘다(노트 4.9 5).
    ///   멈춘 주기는 `reSTUN`이 다시 건다.
    mutating func advance(
        to now: ContinuousClock.Instant,
        isActive: Bool,
        using generator: inout some RandomNumberGenerator
    ) -> [Action] {
        self.isActive = isActive
        if !isActive { periodicAt = nil }
        if let round {
            if now >= round.start + Self.roundTimeout {
                return finishRound(at: now)
            }
            return sendDueRequests(at: now, using: &generator)
        }
        if let periodicAt, now >= periodicAt {
            return startRound(at: now, using: &generator)
        }
        return []
    }

    /// 다음에 `advance`를 불러야 하는 시각. 회차도 주기도 없으면 nil.
    var nextDeadline: ContinuousClock.Instant? {
        var deadlines: [ContinuousClock.Instant] = []
        if let round {
            deadlines.append(round.start + Self.roundTimeout)
            if let next = round.pending.first { deadlines.append(next.due) }
        }
        if let periodicAt { deadlines.append(periodicAt) }
        return deadlines.min()
    }

    // MARK: 값 변환

    /// 지연을 나노초 `Int64`로 바꾼다. 음수는 0으로, 넘치면 최댓값으로 막는다(계약 H: 정수 넘침 없음).
    static func nanoseconds(_ duration: Duration) -> Int64 {
        let (seconds, attoseconds) = duration.components
        guard seconds >= 0 else { return 0 }
        let (scaled, overflow) = seconds.multipliedReportingOverflow(by: 1_000_000_000)
        guard !overflow else { return .max }
        let (total, addOverflow) = scaled.addingReportingOverflow(attoseconds / 1_000_000_000)
        return addOverflow ? .max : total
    }
}
