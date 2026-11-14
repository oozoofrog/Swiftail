// 주기 ReSTUN의 유휴 판단은 Go 구현을 따랐다.
// 출처: tailscale.com v1.104.6 `wgengine/magicsock/magicsock.go` (`shouldDoPeriodicReSTUNLocked`, `sessionActiveTimeout`).
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import SwiftailBase

/// 기한과 STUN 회차(계약 동작 D7·E·G1·G3, 노트 4.6 3·4.8 3·4.9 5).
///
/// `Magicsock`의 기한은 부품들의 기한을 합친 것이다: 피어마다 Ping 기한·heartbeat·신뢰 만료(`PeerPathState`), 그리고
/// STUN 회차의 다음 요청·마감·주기(`Netcheck`), 그리고 피어가 유휴가 되는 시각(동작 G3). 노드는 `nextDeadline`에
/// `advance(to:)`를 부르고, `advance`는 기한이 된 부품만 돌린다. 신뢰가 만료된 피어는 그 기한의 `advance`에서
/// `.pathChanged(.relayed)`가, 유휴가 된 피어는 `.pathChanged(nil)`이 나온다.
///
/// STUN 회차의 결과(`Netcheck.Action`)도 여기서 출력으로 바꾼다. 회차가 끝나 엔드포인트를 다시 정하면 미뤄 둔
/// CallMeMaybe를 보낸다.
extension Magicsock {
    /// 홈 후보 지역을 맞춘다. 바뀌면 곧바로 STUN 회차를 시작한다. 홈이 없으면 대체 홈을 곧바로 고른다.
    public mutating func setRegions(_ regions: [Region], at now: ContinuousClock.Instant) -> [Output] {
        var random = SystemRandomNumberGenerator()
        return setRegions(regions, at: now, using: &random)
    }

    /// now까지 기한이 지난 타이머를 처리한다(Ping 기한, heartbeat, 신뢰 만료, STUN 회차).
    public mutating func advance(to now: ContinuousClock.Instant) -> [Output] {
        var random = SystemRandomNumberGenerator()
        return advance(to: now, using: &random)
    }

    /// 다음에 `advance`를 불러야 하는 시각. 걸린 타이머가 없으면 nil.
    ///
    /// 피어마다 경로 상태 기계의 기한과, 알린 경로가 유휴로 nil이 되는 시각(동작 G3)을 넣는다.
    public var nextDeadline: ContinuousClock.Instant? {
        let peerDeadlines = peers.values.flatMap { [$0.path.nextDeadline, Self.idleDeadline(of: $0)] }
        return (peerDeadlines + [netcheck.nextDeadline]).compactMap { $0 }.min()
    }

    /// `setRegions(_:at:)`과 같다. 난수를 `generator`에서 뽑는다.
    mutating func setRegions(
        _ regions: [Region],
        at now: ContinuousClock.Instant,
        using generator: inout some RandomNumberGenerator
    ) -> [Output] {
        handle(netcheck.setRegions(regions, at: now, using: &generator), at: now, using: &generator)
    }

    /// `advance(to:)`와 같다. 난수를 `generator`에서 뽑는다.
    ///
    /// 피어는 `setPeers`의 순서로 돌리고, 그다음 STUN 회차를 돌린다. 기한이 되지 않은 부품은 건드리지 않는다.
    mutating func advance(to now: ContinuousClock.Instant, using generator: inout some RandomNumberGenerator) -> [Output] {
        var outputs: [Output] = []
        for key in peerOrder {
            guard let entry = peers[key] else { continue }
            let pathDue = entry.path.nextDeadline.map { $0 <= now } ?? false
            let idleDue = Self.idleDeadline(of: entry).map { $0 <= now } ?? false
            guard pathDue || idleDue else { continue }
            if pathDue, let actions = peers[key]?.path.advance(to: now, using: &generator) {
                outputs += handle(actions, for: key, at: now, using: &generator)
            }
            reportPathChange(of: key, at: now, into: &outputs)
        }
        if let deadline = netcheck.nextDeadline, deadline <= now {
            let actions = netcheck.advance(to: now, isActive: isActive(at: now), using: &generator)
            outputs += handle(actions, at: now, using: &generator)
        }
        return outputs
    }

    /// 주기 회차를 이어 갈 만큼 쓰이고 있는가(동작 E5): 피어가 있고, 어느 피어든 마지막 송신 뒤 45초가 지나지 않았다.
    ///
    /// Go는 TUN 송수신의 유휴 시간을 보지만(`idleFor > sessionActiveTimeout`이면 멈춤), 이 타입은 WireGuard 송신 시각으로
    /// 대신한다(계약 E5).
    func isActive(at now: ContinuousClock.Instant) -> Bool {
        peers.values.contains { entry in
            entry.path.lastSend.map { now - $0 <= PeerPathState.sessionActiveTimeout } ?? false
        }
    }

    /// STUN 회차가 낸 일을 출력으로 바꾼다. 엔드포인트를 다시 정했으면 미뤄 둔 CallMeMaybe를 보낸다(동작 F2).
    mutating func handle(
        _ actions: [Netcheck.Action],
        at now: ContinuousClock.Instant,
        using generator: inout some RandomNumberGenerator
    ) -> [Output] {
        var outputs: [Output] = []
        for action in actions {
            switch action {
            case .sendSTUN(let request, let server):
                outputs.append(.udp(request, to: server))
            case .endpointsChanged(let endpoints):
                outputs.append(.endpointsChanged(endpoints))
            case .homeRegionChanged(let region):
                outputs.append(.homeRegionChanged(region))
            case .endpointsRefreshed:
                outputs += sendPendingCallMeMaybe(at: now, using: &generator)
            }
        }
        return outputs
    }
}
