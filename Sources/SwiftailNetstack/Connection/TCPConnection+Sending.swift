/// 보내기: 데이터·FIN 세그먼트, 재전송, ACK, 광고하는 창.
///
/// 보낼 수 있는 양은 `min(cwnd, SND.WND) − FlightSize`다(계약 동작 R5). 새 데이터는 보내는 쪽 SWS 회피(RFC 9293 3.8.6.2.1)를
/// 거치고, `SND.NXT` 앞의 구간(RTO 뒤의 go-back-N)은 재전송이라 상대의 창을 보지 않고 cwnd만 본다
/// (RFC 7323 2.4 4: 보낼 때 창 안이었던 세그먼트의 재전송). 재전송은 늘 `SND.UNA`부터다(계약 동작 R7. 받은 SACK 블록은 아직 쓰지 않는다, M6-10b).
extension TCPConnection {
    /// 지금 보낼 수 있는 데이터와 FIN을 보내고, 보내기에 딸린 타이머(재전송, 0 창 탐침, SWS override)를 맞춘다.
    ///
    /// - Parameter overridingSillyWindowAvoidance: override 타이머가 만료됐다. SWS 회피의 조건 없이 창이 허락하는 만큼 보낸다.
    mutating func transmit(
        at now: ContinuousClock.Instant, overridingSillyWindowAvoidance: Bool = false, into outputs: inout [Output]
    ) {
        switch state {
        case .established, .closeWait, .finWait1, .closing, .lastAck: break
        default: return
        }
        // 데이터를 한동안 보내지 않았다면 cwnd를 줄인다(RFC 5681 4.1, 계약 동작 R8).
        if !hasOutstandingData, let lastDataSentAt, unsentDataCount > 0 {
            congestionControl.restartAfterIdle(
                idleDuration: now - lastDataSentAt, retransmissionTimeout: retransmissionTimeout)
        }
        var override = overridingSillyWindowAvoidance
        var blockedBySillyWindow = false
        // 받는 버퍼는 보내는 동안 바뀌지 않으므로, 이 호출이 내는 세그먼트는 모두 같은 SACK 옵션을 싣는다.
        let payloadLimit = segmentPayloadLimit
        while true {
            let isRetransmission = transmitNext.precedes(sendNext)
            var length = min(payloadLimit, unsentDataCount)
            if isRetransmission {
                length = min(length, Int(sendNext.distance(from: transmitNext)))
            }
            let windowRoom = max(0, Int(sendWindowEnd.distance(from: transmitNext)))
            if !isRetransmission, length > 0 {
                // 보내는 쪽 SWS 회피(계약 동작 F7): min(D, U) >= MSS, D <= U, min(D, U) >= Max(SND.WND)/2, 또는 override.
                let pending = unsentDataCount
                let usable = min(pending, windowRoom)
                guard usable > 0 else { break }
                guard usable >= payloadLimit || pending <= windowRoom
                    || usable * 2 >= maximumSendWindow || override
                else {
                    blockedBySillyWindow = true
                    break
                }
                length = min(length, windowRoom)
            }
            // cwnd에 잘린 작은 세그먼트를 만들지 않는다. 날아가는 것이 있으므로 ACK가 cwnd를 다시 연다.
            let flight = Int(transmitNext.distance(from: sendUnacknowledged))
            if length > 0, congestionControl.congestionWindow - flight < length { break }

            let segmentEnd = transmitNext.advanced(by: UInt32(length))
            var fin = false
            if finRequested, segmentEnd == finSequence {
                // 다시 보내는 FIN은 창을 보지 않는다. 처음 보내는 FIN은 창 안이어야 한다(창이 0이면 상대가 받지 않는다).
                fin = finSequence.precedes(sendNext) || windowRoom > length
            }
            guard length > 0 || fin else { break }

            let start = transmitNext
            let end = segmentEnd.advanced(by: fin ? 1 : 0)
            outputs.append(.segment(dataSegment(from: start, length: length, fin: fin)))
            if isRetransmission {
                statistics.retransmittedBytes += length
                discardRoundTripSample(overlapping: start, end)
            } else {
                statistics.sentBytes += length
                if roundTripSample == nil {
                    roundTripSample = RoundTripSample(start: start, end: end, sentAt: now)
                }
            }
            if sendNext.precedes(end) { sendNext = end }
            transmitNext = end
            if length > 0 { lastDataSentAt = now }
            if timers[.retransmission] == nil {
                timers[.retransmission] = now + retransmissionTimeout
            }
            if fin {
                if state == .established { state = .finWait1 }
                if state == .closeWait { state = .lastAck }
            }
            override = false
        }
        updateTransmissionTimers(at: now, blockedBySillyWindow: blockedBySillyWindow)
    }

    /// `transmitNext`부터 아직 보내지 않은(또는 go-back-N으로 다시 보낼) 데이터 바이트 수.
    var unsentDataCount: Int {
        max(0, Int(sendBuffer.endSequence.distance(from: transmitNext)))
    }

    /// 보내기에 딸린 타이머를 맞춘다.
    ///
    /// - 재전송(RFC 6298 5.2): 확인받지 못한 것이 없으면 끈다. 켜는 일은 보낼 때와 ACK가 한다.
    /// - 0 창 탐침(RFC 9293 3.8.6.1, 계약 동작 F8): 날아가는 것이 없고, 보낼 데이터나 FIN이 있고, 창이 닫혔으면 RTO 뒤에.
    /// - SWS override(계약 동작 F7): 창이 작아 SWS 회피가 막았으면 200ms 뒤에.
    mutating func updateTransmissionTimers(at now: ContinuousClock.Instant, blockedBySillyWindow: Bool) {
        if !hasOutstandingData {
            timers[.retransmission] = nil
        }
        let hasPending = unsentDataCount > 0 || (finRequested && !finSent)
        let windowClosed = Int(sendWindowEnd.distance(from: transmitNext)) <= 0
        if hasPending, !hasOutstandingData, windowClosed {
            if timers[.zeroWindowProbe] == nil {
                zeroWindowProbeInterval = retransmissionTimeout
                timers[.zeroWindowProbe] = now + zeroWindowProbeInterval
            }
        } else {
            timers[.zeroWindowProbe] = nil
        }
        if blockedBySillyWindow {
            if timers[.sillyWindowOverride] == nil {
                timers[.sillyWindowOverride] = now + Self.sillyWindowOverrideTimeout
            }
        } else {
            timers[.sillyWindowOverride] = nil
        }
    }

    /// `SND.UNA`부터 한 세그먼트를 다시 보낸다(fast retransmit, partial ACK. RFC 5681 3.2, RFC 6582 3.2).
    /// 창과 cwnd를 보지 않는다. `SND.NXT`를 넘지 않는다.
    mutating func retransmitFirstUnacknowledgedSegment(at now: ContinuousClock.Instant, into outputs: inout [Output]) {
        let start = sendUnacknowledged
        let available = max(0, Int(sendBuffer.endSequence.distance(from: start)))
        let length = min(segmentPayloadLimit, available, Int(sendNext.distance(from: start)))
        let fin = finSent && start.advanced(by: UInt32(length)) == finSequence
        guard length > 0 || fin else { return }
        let end = start.advanced(by: UInt32(length + (fin ? 1 : 0)))
        outputs.append(.segment(dataSegment(from: start, length: length, fin: fin)))
        statistics.retransmittedBytes += length
        discardRoundTripSample(overlapping: start, end)
        if transmitNext.precedes(end) { transmitNext = end }
    }

    /// 재전송한 구간 `[start, end)`가 재고 있는 세그먼트와 겹치면 그 측정을 버린다(Karn, 계약 동작 R2).
    mutating func discardRoundTripSample(overlapping start: SequenceNumber, _ end: SequenceNumber) {
        guard let sample = roundTripSample else { return }
        if sample.start.precedes(end), start.precedes(sample.end) {
            roundTripSample = nil
        }
    }

    // MARK: 세그먼트 만들기

    /// `start`부터 `length`바이트의 데이터와(있으면) FIN을 실은 세그먼트. ACK와 지금의 창을 싣는다.
    /// 마지막 버퍼 바이트를 싣는 세그먼트에는 PSH를 켠다.
    mutating func dataSegment(from start: SequenceNumber, length: Int, fin: Bool) -> TCPSegment {
        let offset = Int(start.distance(from: sendBuffer.startSequence))
        var flags: TCPSegment.Flags = [.ack]
        if fin { flags.insert(.fin) }
        if length > 0, start.advanced(by: UInt32(length)) == sendBuffer.endSequence { flags.insert(.psh) }
        return acknowledgingSegment(
            sequence: start, flags: flags, payload: sendBuffer.bytes(from: offset, upTo: length))
    }

    /// ACK가 켜진 세그먼트. RCV.NXT와 지금의 창, SACK 블록(`sackBlocksToSend`)을 싣고, 미뤄 둔 ACK를 지운다(이 세그먼트가
    /// 그 ACK다). 순수 ACK, 데이터에 실린 ACK, 0 창 탐침, keep-alive가 모두 여기를 지나므로 빈 곳이 있는 동안 나가는 모든 ACK에
    /// SACK이 실린다(RFC 2018 4).
    mutating func acknowledgingSegment(
        sequence: SequenceNumber, flags: TCPSegment.Flags, payload: [UInt8] = []
    ) -> TCPSegment {
        let window = advertisedWindowField()
        timers[.acknowledgment] = nil
        unacknowledgedByteCount = 0
        return TCPSegment(
            source: localEndpoint, destination: remoteEndpoint, sequenceNumber: sequence,
            acknowledgmentNumber: receiveNext, flags: flags, window: window, sackBlocks: sackBlocksToSend,
            payload: payload)
    }

    /// 지금 ACK에 실을 SACK 블록: 받는 버퍼의 순서가 어긋난 구간을 최근 순서로 4개까지(RFC 2018 4, `ReceiveBuffer.sackBlocks`).
    /// 상대가 SACK-Permitted를 보내지 않았으면 늘 비어 있다(RFC 2018 4 MUST NOT).
    ///
    /// shortcut: D-SACK(RFC 2883, 이미 받은 데이터를 다시 받았다고 알리는 첫 블록)은 내지 않는다. 상대의 헛된 재전송을 알아내는
    /// 데만 쓰이고 회복을 빠르게 하지는 않는다. 필요해지는 시점: 상대의 재정렬 감지(RACK 등)가 문제가 될 때.
    var sackBlocksToSend: [TCPSegment.SACKBlock] {
        peerPermitsSACK ? receiveBuffer.sackBlocks(limit: TCPSegment.maximumSACKBlockCount) : []
    }

    /// 지금 보내는 데이터 세그먼트의 데이터 상한: Eff.snd.MSS에서 그 세그먼트에 실릴 SACK 옵션의 길이를 뺀 값(RFC 9293 3.7.1,
    /// 계약 동작 T5). 광고하는 MSS가 MTU 1280을 꽉 채우므로 옵션이 붙으면 데이터를 줄여야 IP 패킷이 1280을 넘지 않는다.
    var segmentPayloadLimit: Int {
        guard peerPermitsSACK else { return sendMaximumSegmentSize }
        let blockCount = min(receiveBuffer.outOfOrderRangeCount, TCPSegment.maximumSACKBlockCount)
        return sendMaximumSegmentSize - TCPSegment.sackOptionLength(blockCount: blockCount)
    }

    /// `<SEQ=sequence><CTL=RST>`.
    func resetSegment(sequence: SequenceNumber) -> TCPSegment {
        TCPSegment(source: localEndpoint, destination: remoteEndpoint, sequenceNumber: sequence, flags: [.rst])
    }

    // MARK: ACK

    /// ACK를 기한으로 둔다. 곧바로 보낼 것은 기한이 지금이다(같은 시각의 `advance(to:)`나 응용 호출의 끝에서 나간다).
    /// 이미 더 이른 기한이 있으면 그대로 둔다(지연 ACK의 40ms를 미루지 않는다).
    mutating func scheduleAcknowledgment(immediately: Bool, at now: ContinuousClock.Instant) {
        let deadline = immediately ? now : now + Self.delayedAcknowledgmentTimeout
        if let existing = timers[.acknowledgment], existing <= deadline { return }
        timers[.acknowledgment] = deadline
    }

    /// 기한이 된 ACK가 있으면 `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>`로 보낸다.
    mutating func flushAcknowledgment(at now: ContinuousClock.Instant, into outputs: inout [Output]) {
        guard let deadline = timers[.acknowledgment], deadline <= now else { return }
        sendAcknowledgment(into: &outputs)
    }

    mutating func sendAcknowledgment(into outputs: inout [Output]) {
        switch state {
        case .synSent, .closed:
            timers[.acknowledgment] = nil
        default:
            outputs.append(.segment(acknowledgingSegment(sequence: sendNext, flags: [.ack])))
        }
    }

    // MARK: 광고하는 창

    /// 보내는 세그먼트(SYN이 아닌 것)의 창 필드 `RCV.WND >> Rcv.Wind.Shift`(RFC 7323 2.3).
    ///
    /// 받는 쪽 SWS 회피(RFC 9293 3.8.6.2.2, 계약 동작 F3): 버퍼가 허락하는 오른쪽 끝이 광고한 끝보다
    /// `min(버퍼/2, Eff.snd.MSS)` 이상 멀어졌을 때만 광고한 끝을 옮긴다. 옮긴 끝은 shift로 내림한 값이고, 줄이지 않는다
    /// (SHLD-14). 내림 탓에 필드가 가리키는 끝이 전보다 앞이어도 전에 광고한 끝까지는 받는다(RFC 7323 2.4).
    mutating func advertisedWindowField() -> UInt16 {
        let receiveNext = self.receiveNext
        let candidateEnd = receiveWindowEnd
        let threshold = min(receiveBuffer.capacity / 2, sendMaximumSegmentSize)
        if Int(candidateEnd.distance(from: advertisedWindowEnd)) >= threshold {
            let span = max(0, Int(candidateEnd.distance(from: receiveNext)))
            let field = min(Int(UInt16.max), span >> receiveWindowShift)
            let quantizedEnd = receiveNext.advanced(by: UInt32(field << receiveWindowShift))
            if advertisedWindowEnd.precedes(quantizedEnd) {
                advertisedWindowEnd = quantizedEnd
            }
        }
        let span = max(0, Int(advertisedWindowEnd.distance(from: receiveNext)))
        return UInt16(min(Int(UInt16.max), span >> receiveWindowShift))
    }

    /// 응용이 읽은 뒤 순수 창 갱신 ACK를 곧바로 보낼 때다(계약 동작 F3): 마지막으로 광고한 남은 창(광고한 오른쪽 끝 − RCV.NXT)이
    /// 받는 버퍼의 절반 이하이고, 광고한 끝을 SWS 회피의 문턱(`min(버퍼/2, MSS)`) 이상 옮길 수 있다.
    ///
    /// 남은 창이 절반보다 크면 상대는 아직 보낼 자리가 넉넉하다. 그때 새 창은 데이터에 대한 ACK(2×MSS 또는 40ms)와 나가는
    /// 데이터에 실린다. 그래서 응용이 조금씩 읽을 때마다 순수 ACK가 나가지 않는다. 창이 0이거나 작으면 남은 창이 절반 이하이므로
    /// 읽어서 문턱만큼 열리는 즉시 알린다(멈춤이 없다).
    var windowUpdateIsDue: Bool {
        let remaining = Int(advertisedWindowEnd.distance(from: receiveNext))
        guard remaining <= receiveBuffer.capacity / 2 else { return false }
        let threshold = min(receiveBuffer.capacity / 2, sendMaximumSegmentSize)
        return Int(receiveWindowEnd.distance(from: advertisedWindowEnd)) >= threshold
    }

    /// 지금 광고할 수 있는 창의 오른쪽 끝: 버퍼의 남은 자리와 `receiveWindowLimit`이 함께 허락하는 데까지.
    private var receiveWindowEnd: SequenceNumber {
        let limit = min(receiveBuffer.capacity, receiveWindowLimit)
        return receiveBuffer.nextSequence.advanced(by: UInt32(max(0, limit - receiveBuffer.readableCount)))
    }
}
