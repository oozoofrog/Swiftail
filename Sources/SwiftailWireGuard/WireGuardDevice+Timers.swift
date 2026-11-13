/// 타이머 처리: 기한이 지난 타이머를 이른 순서로 하나씩 처리한다.
///
/// 만료 처리는 `now` 기준으로 다음 타이머를 다시 건다. 호출이 늦어져도 wireguard-go의 늦게 깬 타이머와
/// 같은 결과가 된다. 각 처리는 그 타이머를 지우거나 `now`보다 뒤로 다시 걸므로 반복은 끝난다.
///
/// 백서 §6.2–§6.5, `docs/protocol-notes/wireguard.md` "타이머"
/// (출처: wireguard-go `device/timers.go`).
extension WireGuardDevice {
    /// now까지 기한이 지난 타이머를 모두 처리한다.
    public mutating func advance(to now: ContinuousClock.Instant) -> [Output] {
        var outputs: [Output] = []
        while case let (owner, kind)? = expiredTimer(at: now), var peer = peers[owner] {
            peer.timers[kind] = nil
            outputs += fire(kind, for: &peer, at: now)
            store(peer)
        }
        return outputs
    }

    /// 기한이 지난 타이머 가운데 가장 이른 것.
    private func expiredTimer(at now: ContinuousClock.Instant) -> (PublicKey, PeerTimers.Kind)? {
        let earliest = peers.compactMap { key, peer in
            peer.timers.earliest.map { (key: key, kind: $0.kind, deadline: $0.deadline) }
        }.min { $0.deadline < $1.deadline }
        guard let earliest, earliest.deadline <= now else { return nil }
        return (earliest.key, earliest.kind)
    }

    private func fire(_ kind: PeerTimers.Kind, for peer: inout Peer, at now: ContinuousClock.Instant) -> [Output] {
        switch kind {
        case .retransmitHandshake:
            if peer.timers.handshakeAttempts > Constants.maxTimerHandshakes {
                // 처음 1회 + 재시도 19회 = 20번 보내도 답이 없다. 포기하고 대기열을 버린다.
                // 남은 핸드셰이크 상태는 540초 뒤 지운다.
                peer.timers[.sendKeepalive] = nil
                peer.staged = []
                if peer.timers[.zeroKeyMaterial] == nil {
                    peer.timers[.zeroKeyMaterial] = now + Constants.rejectAfterTime * 3
                }
                return []
            }
            peer.timers.handshakeAttempts += 1
            return sendHandshakeInitiation(&peer, isRetry: true, at: now)

        case .sendKeepalive:
            let outputs = sendKeepalive(&peer, at: now)
            if peer.timers.needAnotherKeepalive {
                peer.timers.needAnotherKeepalive = false
                peer.timers[.sendKeepalive] = now + Constants.keepaliveTimeout
            }
            return outputs

        case .newHandshake:
            // 데이터를 보냈는데 15초 넘게 아무것도 받지 못했다.
            return sendHandshakeInitiation(&peer, isRetry: false, at: now)

        case .zeroKeyMaterial:
            peer.zeroKeyMaterial()
            return []
        }
    }
}
