// CallMeMaybe를 보내는 조건과 미루기는 Go 구현을 따랐다.
// 출처: tailscale.com v1.104.6 `wgengine/magicsock/magicsock.go` (`enqueueCallMeMaybe`, `endpointsFreshEnoughDuration`),
// `wgengine/magicsock/endpoint.go` (`send`). Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import SwiftailBase

/// WireGuard 데이터그램 보내기와 disco 메시지 보내기(계약 동작 D3·D4·F, 노트 4.5·4.8 4).
///
/// 경로는 피어의 `PeerPathState`가 고른다. 신뢰된 직접 주소면 UDP로만, 아니면 직접 주소(있으면)와 피어의 홈 DERP로
/// 함께 보내며 다시 찾는다. 이 파일은 그 계획을 출력으로 바꾸고, 계획에 딸린 disco Ping을 봉하고, CallMeMaybe에
/// 자기 엔드포인트를 채운다. 엔드포인트가 낡았으면 CallMeMaybe를 미루고 STUN 회차를 돌려 끝난 뒤에 보낸다.
extension Magicsock {
    /// CallMeMaybe에 담을 자기 엔드포인트가 이보다 오래됐으면 회차를 다시 돌린 뒤에 보낸다.
    /// `endpointsFreshEnoughDuration`(`magicsock.go:4112`, 노트 4.8 4.1).
    static let endpointsFreshness: Duration = .seconds(27)

    /// 엔진이 낸 WireGuard 데이터그램 하나를 피어에게 보낸다. 경로를 고른다.
    public mutating func send(_ datagram: [UInt8], to peer: NodePublicKey, at now: ContinuousClock.Instant) -> [Output] {
        var random = SystemRandomNumberGenerator()
        return send(datagram, to: peer, at: now, using: &random)
    }

    /// `send(_:to:at:)`과 같다. 난수를 `generator`에서 뽑는다.
    ///
    /// 출력은 데이터그램(UDP, DERP 순), 딸린 disco Ping과 CallMeMaybe, 멈춘 주기를 다시 건 STUN 요청, 경로 사건 순이다.
    /// 직접 주소도 DERP 지역도 없으면 데이터그램은 `noRouteToPeer`로 버리고 Ping은 그대로 보낸다.
    mutating func send(
        _ datagram: [UInt8],
        to peer: NodePublicKey,
        at now: ContinuousClock.Instant,
        using generator: inout some RandomNumberGenerator
    ) -> [Output] {
        guard let plan = peers[peer]?.path.planSend(at: now, using: &generator) else { return [.dropped(.noRouteToPeer)] }

        var outputs: [Output] = []
        if let udp = plan.udp {
            outputs.append(.udp(datagram, to: udp))
        }
        if plan.derpRegion != 0 {
            outputs.append(.derp(datagram, to: peer, region: plan.derpRegion))
        }
        if outputs.isEmpty {
            outputs.append(.dropped(.noRouteToPeer))
        }
        outputs += handle(plan.actions, for: peer, at: now, using: &generator)
        // 유휴로 멈춘 주기 회차는 다음 송신이 다시 건다(동작 E5).
        if netcheck.nextDeadline == nil {
            outputs += handle(netcheck.reSTUN(at: now, using: &generator), at: now, using: &generator)
        }
        reportPathChange(of: peer, at: now, into: &outputs)
        return outputs
    }

    /// 피어의 경로 상태 기계가 낸 일을 출력으로 바꾼다. Ping은 봉해 UDP로, CallMeMaybe는 `callMeMaybe(to:)`로.
    mutating func handle(
        _ actions: [PeerPathState.Action],
        for peer: NodePublicKey,
        at now: ContinuousClock.Instant,
        using generator: inout some RandomNumberGenerator
    ) -> [Output] {
        guard let discoKey = peers[peer]?.discoKey else { return [] }
        var outputs: [Output] = []
        for action in actions {
            switch action {
            case .ping(let txID, let destination):
                if let ping = seal(.ping(txID, nodeKey: nodeKey), to: discoKey, using: &generator) {
                    outputs.append(.udp(ping, to: destination))
                }
            case .callMeMaybe:
                outputs += callMeMaybe(to: peer, at: now, using: &generator)
            }
        }
        return outputs
    }

    /// 피어의 홈 DERP로 자기 엔드포인트 전체를 담은 CallMeMaybe를 보낸다(동작 F1).
    ///
    /// 엔드포인트를 정한 지 27초가 지났거나 아직 정하지 않았으면 피어를 미룬 목록에 넣고(피어당 한 칸) 회차를 시작한다.
    /// 회차가 끝나면 `sendPendingCallMeMaybe`가 보낸다(동작 F2). 엔드포인트 종류는 담지 않는다(노트 4.8 4.2).
    mutating func callMeMaybe(
        to peer: NodePublicKey,
        at now: ContinuousClock.Instant,
        using generator: inout some RandomNumberGenerator
    ) -> [Output] {
        guard let entry = peers[peer], let discoKey = entry.discoKey, entry.path.homeDERP != 0 else { return [] }
        guard let refreshed = netcheck.endpointsRefreshedAt, now - refreshed < Self.endpointsFreshness else {
            if !pendingCallMeMaybe.contains(peer) {
                pendingCallMeMaybe.append(peer)
            }
            return handle(netcheck.reSTUN(at: now, using: &generator), at: now, using: &generator)
        }
        let message = DiscoMessage.callMeMaybe(netcheck.endpoints.map(\.address))
        guard let packet = seal(message, to: discoKey, using: &generator) else { return [] }
        return [.derp(packet, to: peer, region: entry.path.homeDERP)]
    }

    /// 엔드포인트를 다시 정했다. 미뤄 둔 CallMeMaybe를 보낸다.
    mutating func sendPendingCallMeMaybe(at now: ContinuousClock.Instant, using generator: inout some RandomNumberGenerator) -> [Output] {
        let waiting = pendingCallMeMaybe
        pendingCallMeMaybe = []
        var outputs: [Output] = []
        for peer in waiting {
            outputs += callMeMaybe(to: peer, at: now, using: &generator)
        }
        return outputs
    }
}
