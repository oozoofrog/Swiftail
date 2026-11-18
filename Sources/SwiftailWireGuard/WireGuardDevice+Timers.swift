/// Processes expired timers one at a time, in deadline order.
///
/// Handles expiration by arming the next timer relative to `now`. A late call has the same result as a wireguard-go timer
/// that wakes late. Each step clears the timer or re-arms it later than `now`, so the loop ends.
///
/// Whitepaper §6.2–§6.5, `docs/protocol-notes/wireguard.md` "Timers"
/// (origin: wireguard-go `device/timers.go`).
extension WireGuardDevice {
    /// Processes all timers due by now.
    public mutating func advance(to now: ContinuousClock.Instant) -> [Output] {
        var outputs: [Output] = []
        while let timer = earliestTimer(), timer.deadline <= now {
            let fired = edit(timer.owner) { device, peer in
                peer.timers[timer.kind] = nil
                return device.fire(timer.kind, for: &peer, at: now)
            }
            guard let fired else { break }
            outputs += fired
        }
        return outputs
    }

    private func fire(_ kind: PeerTimers.Kind, for peer: inout Peer, at now: ContinuousClock.Instant) -> [Output] {
        switch kind {
        case .retransmitHandshake:
            if peer.timers.handshakeAttempts > Constants.maxTimerHandshakes {
                // No reply after 1 initial send + 19 retries = 20 sends. Give up and discard the queue.
                // If no key-material timer is armed, schedule it to clear the remaining handshake state in 540 seconds.
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
            // No authenticated packet arrived after sending data and waiting 15 seconds plus jitter.
            return sendHandshakeInitiation(&peer, isRetry: false, at: now)

        case .zeroKeyMaterial:
            peer.zeroKeyMaterial()
            return []
        }
    }
}
