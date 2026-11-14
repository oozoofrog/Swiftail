/// 타이머: 기한이 지난 것을 이른 순서로 하나씩 처리한다.
///
/// 처리마다 그 타이머를 지우거나 `now`보다 뒤로 다시 건다(재전송·탐침·keep-alive는 `now` 기준으로 다음 간격을 잰다).
/// 그래서 `advance(to:)`의 반복은 끝나고, 처리한 뒤의 `nextDeadline`은 늘 `now`보다 뒤이거나 `nil`이다.
extension TCPConnection {
    /// 가장 이른 타이머의 기한. 끝난 연결은 `nil`.
    package var nextDeadline: ContinuousClock.Instant? {
        state == .closed ? nil : timers.earliest?.deadline
    }

    /// `now`까지 기한이 지난 타이머를 모두 처리한다. 미뤄 둔 ACK도 여기서 나간다.
    package mutating func advance(to now: ContinuousClock.Instant) -> [Output] {
        var outputs: [Output] = []
        while state != .closed, let (kind, deadline) = timers.earliest, deadline <= now {
            timers[kind] = nil
            fire(kind, at: now, into: &outputs)
        }
        return outputs
    }

    private mutating func fire(_ kind: ConnectionTimers.Kind, at now: ContinuousClock.Instant, into outputs: inout [Output]) {
        switch kind {
        case .timeWait:
            terminate(.finished, into: &outputs)
        case .finWait2Linger:
            terminate(.timedOut, into: &outputs)
        case .retransmission:
            retransmissionTimerExpired(at: now, into: &outputs)
        case .zeroWindowProbe:
            sendZeroWindowProbe(at: now, into: &outputs)
        case .sillyWindowOverride:
            transmit(at: now, overridingSillyWindowAvoidance: true, into: &outputs)
        case .keepalive:
            sendKeepalive(at: now, into: &outputs)
        case .acknowledgment:
            sendAcknowledgment(into: &outputs)
        }
    }

    /// 재전송 타이머 만료(RFC 6298 5.4~5.6, 계약 동작 R3·R4·R7).
    ///
    /// SYN·SYN-ACK는 7번까지 다시 보내고, 그 뒤의 만료(247초)에 끝낸다. 데이터·FIN은 15번까지다. RTO를 두 배로 하고
    /// 혼잡 제어에 알린 뒤(cwnd 1 세그먼트), `SND.UNA`부터 slow start가 허락하는 대로 다시 보낸다(go-back-N).
    ///
    /// 데이터가 날아가는 중에 상대가 창을 0으로 줄였고 마지막 만료 뒤에도 ACK했으면, 그 만료는 15번에 세지 않는다. 살아 있는
    /// 상대가 창 밖의 데이터를 받지 않을 뿐이다(RFC 9293 3.8.6: 창 밖 데이터가 확인되지 않는다고 끊지 않는다 SHLD-17, 창이 0이면
    /// 탐침한다 MUST-35. gVisor는 이때 0 창 탐침으로 바꾸고 재전송 수를 보지 않는다, `snd.go:556`). 다시 보내는 세그먼트가
    /// 탐침을 겸한다. 다만 응용이 `close`로 놓은 연결은 이 예외 없이 세고, 한도에서 RST를 보내 상대가 쥔 상태도 놓게 한다
    /// (0 창 탐침의 한도와 같은 까닭이다. `sendZeroWindowProbe`).
    private mutating func retransmissionTimerExpired(at now: ContinuousClock.Instant, into outputs: inout [Output]) {
        switch state {
        case .synSent, .synReceived:
            guard retransmissionCount < Self.synchronizeRetransmissionLimit else {
                terminate(.timedOut, into: &outputs)
                return
            }
            retransmissionCount += 1
            retransmissionEstimator.retransmissionTimerExpired(forSYN: true)
            timers[.retransmission] = now + retransmissionTimeout
            outputs.append(.segment(synchronizeSegment()))
        default:
            guard hasOutstandingData else { return }
            let peerIsAnswering = sendWindow == 0 && acknowledgedSinceRetransmissionTimeout
            acknowledgedSinceRetransmissionTimeout = false
            if !peerIsAnswering || readClosed {
                guard retransmissionCount < Self.dataRetransmissionLimit else {
                    if peerIsAnswering {
                        outputs.append(.segment(resetSegment(sequence: sendNext)))
                    }
                    terminate(.timedOut, into: &outputs)
                    return
                }
                retransmissionCount += 1
            }
            retransmissionEstimator.retransmissionTimerExpired()
            congestionControl.retransmissionTimerExpired(sendUnacknowledged: sendUnacknowledged, sendNext: sendNext)
            roundTripSample = nil
            transmitNext = sendUnacknowledged
            timers[.retransmission] = now + retransmissionTimeout
            transmit(at: now, into: &outputs)
        }
    }

    /// 0 창 탐침(RFC 9293 3.8.6.1, 계약 동작 F8). `<SEQ=SND.UNA−1><ACK=RCV.NXT><CTL=ACK>`에 0 한 바이트를 싣는다
    /// (gVisor `snd.go:1009-1034`와 같은 형식). 이미 확인된 번호라 상대는 데이터로 받지 않고 지금의 창을 담은 ACK로 답한다.
    /// 상대가 ACK하는 동안은 끝내지 않고(MUST-37), 아무 ACK 없이 15번이면 끝낸다. 간격은 RTO에서 두 배씩, 60초까지(SHLD-30).
    ///
    /// 응용이 `close`로 놓은 연결은 상대가 답해도 진전 없이 15번이면 RST를 보내고 끝낸다(계약 동작 F8). 상대가 창 0을 둔 채
    /// 탐침에 ACK만 하면 주인 없는 연결이 칸 하나와 보내는 버퍼를 무기한 쥐기 때문이다. MUST-37의 이 예외는 RFC 9293 3.8.6.1이
    /// 가리키는 자원 관리다(RFC 6429 3·4: 주인 없는 연결을 운영체제가 끊을 수 있다).
    private mutating func sendZeroWindowProbe(at now: ContinuousClock.Instant, into outputs: inout [Output]) {
        guard zeroWindowProbeCount < Self.zeroWindowProbeLimit else {
            if readClosed {
                outputs.append(.segment(resetSegment(sequence: sendNext)))
            }
            terminate(.timedOut, into: &outputs)
            return
        }
        zeroWindowProbeCount += 1
        outputs.append(
            .segment(acknowledgingSegment(sequence: sendUnacknowledged.advanced(by: .max), flags: [.ack], payload: [0])))
        zeroWindowProbeInterval = min(zeroWindowProbeInterval * 2, Self.maximumZeroWindowProbeInterval)
        timers[.zeroWindowProbe] = now + zeroWindowProbeInterval
    }

    /// keep-alive(계약 동작 T8, RFC 9293 3.8.4). 받은 것 없이 2시간이 지나면 `<SEQ=SND.NXT−1><ACK=RCV.NXT><CTL=ACK>`를
    /// 75초마다 보내고, 9번 보내도록 답이 없으면 끝낸다. 확인받지 못한 데이터나 보낼 것이 있으면 재전송·탐침 타이머가 맡으므로
    /// 탐침을 보내지 않는다(MUST-26).
    private mutating func sendKeepalive(at now: ContinuousClock.Instant, into outputs: inout [Output]) {
        switch state {
        case .established, .closeWait, .finWait2: break
        default: return
        }
        if hasOutstandingData || unsentDataCount > 0 || (finRequested && !finSent) {
            timers[.keepalive] = now + Self.keepaliveIdle
            return
        }
        guard keepaliveProbeCount < Self.keepaliveProbeLimit else {
            terminate(.timedOut, into: &outputs)
            return
        }
        keepaliveProbeCount += 1
        outputs.append(.segment(acknowledgingSegment(sequence: sendNext.advanced(by: .max), flags: [.ack])))
        timers[.keepalive] = now + Self.keepaliveInterval
    }
}
