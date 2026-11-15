/// 세그먼트 받기. 동기화된 상태(SYN-RECEIVED 이후)의 처리는 RFC 9293 3.10.7.4의 순서 그대로다:
/// 시퀀스 검사 → RST → SYN → ACK → 데이터 → FIN(계약 동작 T2). gVisor의 순서(데이터를 먼저, ACK를 나중에)는 따르지 않는다.
/// RST·SYN·ACK의 검사는 RFC 5961을 따른다(계약 동작 X3).
extension TCPConnection {
    /// 상대가 보낸 세그먼트 하나를 처리한다. 4-튜플이 이 연결의 것인지는 스택이 이미 보았다.
    ///
    /// 곧바로 보낼 ACK(순서가 어긋난 데이터, 빈 곳을 메운 데이터, 2×MSS가 쌓인 데이터, FIN, 창 밖 세그먼트 등)는 이 세그먼트의
    /// 출력으로 나온다. 그래서 묶음으로 받아도 세그먼트마다 ACK가 하나씩 나간다(RFC 5681 4.2의 immediate ACK. 상대의 fast
    /// retransmit이 중복 ACK 셋을 센다). 미룰 수 있는 ACK(순서대로 온 데이터가 2×MSS 미만)만 40ms 기한으로 둔다(타입 문서).
    /// 어떤 세그먼트를 넣어도 죽지 않는다(계약 동작 X1).
    package mutating func receive(_ segment: TCPSegment, at now: ContinuousClock.Instant) -> [Output] {
        var outputs: [Output] = []
        switch state {
        case .closed:
            return []
        case .synSent:
            receiveInSynSent(segment, at: now, into: &outputs)
        default:
            receiveSynchronized(segment, at: now, into: &outputs)
            if isFastRetransmitPending {
                isFastRetransmitPending = false
                if state != .closed { retransmitFirstUnacknowledgedSegment(at: now, into: &outputs) }
            }
            // 처리한 뒤의 상태로 잰다(이 세그먼트로 FIN-WAIT-2·CLOSE-WAIT가 된 연결도 keep-alive를 갖는다).
            refreshKeepalive(at: now)
        }
        transmit(at: now, into: &outputs)
        // 나가는 데이터가 있었으면 ACK는 거기에 실려 기한이 지워졌다. 남은 "지금" 기한의 ACK를 여기서 낸다.
        flushAcknowledgment(at: now, into: &outputs)
        return outputs
    }

    /// 시퀀스 검사를 통과하고 창 밖을 잘라 낸 데이터와 FIN.
    struct InboundText {
        /// 남은 데이터의 첫 번호. `RCV.NXT` 이상이다.
        var sequence: SequenceNumber
        var payload: ArraySlice<UInt8>
        /// FIN이 창 안에 있다. 번호는 `sequence + payload.count`다.
        var fin: Bool
        /// 창이 0이라 데이터를 모두 버렸다(RFC 9293 3.10.7.4 첫째의 "창 0의 특별 허용").
        var droppedForZeroWindow: Bool
    }

    mutating func receiveSynchronized(_ segment: TCPSegment, at now: ContinuousClock.Instant, into outputs: inout [Output]) {
        let flags = segment.flags

        // TIME-WAIT에서 상대 FIN의 재전송(이미 소비한 FIN)은 시퀀스 검사로는 받지 않는 세그먼트다. 먼저 보아 ACK로 답하고
        // 60초를 다시 잰다(RFC 9293 3.10.7.4 다섯째·여덟째의 TIME-WAIT, 계약 동작 T6). 든 때부터 240초는 넘기지 않는다
        // (RFC 9293 3.6.1의 2MSL. 피어가 59초마다 FIN을 다시 보내 연결을 쥐지 못하게 한다. M6 검토 A).
        if state == .timeWait, flags.contains(.fin), !flags.contains(.rst), !flags.contains(.syn),
            segment.sequenceNumber.advanced(by: UInt32(clamping: segment.payload.count))
                == receiveNext.advanced(by: .max)  // RCV.NXT − 1
        {
            let lifetimeEnd = (timeWaitEnteredAt ?? now) + Self.maximumTimeWaitLifetime
            timers[.timeWait] = min(now + Self.timeWaitDuration, lifetimeEnd)
            scheduleAcknowledgment(immediately: true, at: now)
            return
        }

        // 첫째: 시퀀스 검사(표 6). 받지 않는 세그먼트에는 ACK로 답하고 버린다(RST면 조용히 버린다).
        // 데이터 없는 세그먼트에 대한 답은 속도 제한을 받는다(계약 동작 X2).
        guard let text = acceptedText(of: segment) else {
            if !flags.contains(.rst), !segment.payload.isEmpty || challengeLimiter.permit(at: now) {
                scheduleAcknowledgment(immediately: true, at: now)
            }
            return
        }

        // 둘째: RST(RFC 5961 3.2). 창 안이지만 RCV.NXT가 아니면 challenge ACK. 원래 SEG.SEQ로 본다.
        if flags.contains(.rst) {
            if segment.sequenceNumber == receiveNext {
                terminate(.reset, into: &outputs)
            } else {
                sendChallengeAcknowledgment(at: now)
            }
            return
        }

        // 넷째: SYN. 수동 열기의 SYN-RECEIVED는 LISTEN으로 돌아간다(스택이 조용히 지운다).
        // 동기화된 상태에서는 번호와 상관없이 challenge ACK를 보내고 버린다(RFC 5961 4.2).
        if flags.contains(.syn) {
            if state == .synReceived {
                terminate(.reset, into: &outputs)
            } else {
                sendChallengeAcknowledgment(at: now)
            }
            return
        }

        // 다섯째: ACK.
        guard flags.contains(.ack) else { return }
        if state == .synReceived {
            guard completeHandshake(segment, at: now, into: &outputs) else { return }
        } else {
            guard processAcknowledgment(segment, at: now, into: &outputs) else { return }
        }

        // 여섯째(URG)는 쓰지 않는다(계약 제외 표). 일곱째·여덟째.
        if text.droppedForZeroWindow {
            scheduleAcknowledgment(immediately: true, at: now)
        }
        processText(text, at: now, into: &outputs)
    }

    // MARK: 첫째: 시퀀스 검사

    /// 받아들일 조건(RFC 9293 3.10.7.4 표 6)을 보고, 받는다면 창 밖(이미 받은 쪽과 광고한 오른쪽 끝 너머)을 잘라 낸다.
    ///
    /// RCV.WND는 광고한 가장 먼 오른쪽 끝까지다(계약 동작 F1, RFC 7323 2.4). 창이 0이면 데이터 있는 세그먼트는
    /// 받지 않는 것이 원칙이지만, RCV.NXT에서 시작하는 것은 데이터를 버리고 ACK·RST만 본다
    /// (같은 절의 "창 0의 특별 허용". 그렇지 않으면 창을 닫은 쪽이 상대의 ACK를 놓친다).
    ///
    /// 창이 0이어도 RCV.NXT에 온 **데이터 없는 FIN**은 받는다(계약 동작 T6). 표 6으로는 길이 1이라 받지 않는 세그먼트지만
    /// FIN은 버퍼를 쓰지 않는다. gVisor는 길이를 데이터로만 재어 이 FIN을 받고(`rcv.go:460`, `header/tcp.go:682-685`) 자기도
    /// 창과 상관없이 보낸다. 받지 않으면 그 재전송이 RTO로 물러나 EOF가 최대 120초 늦고 상대의 재전송 한도에 닿을 수 있다
    /// (M6 검토 A). 데이터가 든 FIN은 위 원칙대로 데이터와 함께 버린다.
    func acceptedText(of segment: TCPSegment) -> InboundText? {
        let receiveNext = self.receiveNext
        let window = max(0, Int(advertisedWindowEnd.distance(from: receiveNext)))
        let start = Int(segment.sequenceNumber.distance(from: receiveNext))
        let length = Int(segment.sequenceLength)
        if length == 0 {
            guard window == 0 ? start == 0 : (0 <= start && start < window) else { return nil }
        } else if window == 0 {
            guard start == 0 else { return nil }
            let isBareFin = segment.payload.isEmpty && segment.flags.contains(.fin) && !segment.flags.contains(.syn)
            return InboundText(sequence: receiveNext, payload: [], fin: isBareFin, droppedForZeroWindow: !isBareFin)
        } else {
            let last = start + length - 1
            guard (0 <= start && start < window) || (0 <= last && last < window) else { return nil }
        }

        // 데이터는 SYN 다음 번호부터다. 왼쪽(RCV.NXT 앞)과 오른쪽(광고한 끝 너머)을 잘라 낸다. 잘린 FIN은 소비하지 않는다.
        var sequence = segment.sequenceNumber.advanced(by: segment.flags.contains(.syn) ? 1 : 0)
        var payload = segment.payload[...]
        let behind = Int(receiveNext.distance(from: sequence))
        if behind > 0 {
            let dropped = min(behind, payload.count)
            payload = payload.dropFirst(dropped)
            sequence = sequence.advanced(by: UInt32(dropped))
        }
        let room = max(0, Int(advertisedWindowEnd.distance(from: sequence)))
        // FIN의 번호는 원래 데이터의 끝이다. RCV.NXT 앞(이미 소비한 것)이거나 광고한 끝 너머면 소비하지 않는다.
        let fin = segment.flags.contains(.fin) && behind <= segment.payload.count && payload.count < room
        if payload.count > room {
            payload = payload.prefix(room)
        }
        return InboundText(sequence: sequence, payload: payload, fin: fin, droppedForZeroWindow: false)
    }

    // MARK: 다섯째: ACK

    /// SYN-RECEIVED의 ACK. `SND.UNA < SEG.ACK =< SND.NXT`면 ESTABLISHED로 가고 창을 이 세그먼트로 채운다.
    /// 아니면 `<SEQ=SEG.ACK><CTL=RST>`(계약 동작 T4). 이 상태에는 RFC 5961 5.2의 범위 검사를 먼저 하지 않는다:
    /// 틀린 ACK는 모두 RST다(Linux·gVisor와 같다).
    mutating func completeHandshake(
        _ segment: TCPSegment, at now: ContinuousClock.Instant, into outputs: inout [Output]
    ) -> Bool {
        let ack = segment.acknowledgmentNumber
        guard sendUnacknowledged.precedes(ack), ack.precedesOrEquals(sendNext) else {
            outputs.append(.segment(resetSegment(sequence: ack)))
            return false
        }
        sendUnacknowledged = ack
        let peerWindow = scaledWindow(of: segment)
        sendWindow = peerWindow
        maximumSendWindow = max(maximumSendWindow, peerWindow)
        lastPeerWindow = peerWindow
        sendWindowUpdateSequence = segment.sequenceNumber
        sendWindowUpdateAcknowledgment = ack
        establish(at: now, into: &outputs)
        return true
    }

    /// 동기화된 상태의 ACK 처리. 계속 처리할 세그먼트면 `true`.
    ///
    /// 1. RFC 5961 5.2: `SND.UNA − MAX.SND.WND =< SEG.ACK =< SND.NXT` 밖이면 버리고 ACK로 답한다(계약 동작 X3, 속도 제한 X4).
    /// 2. 새 데이터를 확인하면 버퍼·RTT·혼잡 제어·타이머를 고친다. `SEG.ACK = SND.UNA`면 중복 ACK인지 본다(RFC 5681 2).
    /// 3. 창 갱신은 `SND.UNA =< SEG.ACK =< SND.NXT`이고 WL1·WL2 규칙이 맞을 때만(계약 동작 F9).
    /// 4. 이 쪽 FIN이 확인되면 상태를 옮긴다.
    mutating func processAcknowledgment(
        _ segment: TCPSegment, at now: ContinuousClock.Instant, into outputs: inout [Output]
    ) -> Bool {
        let ack = segment.acknowledgmentNumber
        guard Int(ack.distance(from: sendUnacknowledged)) >= -maximumSendWindow, ack.precedesOrEquals(sendNext) else {
            if challengeLimiter.permit(at: now) {
                scheduleAcknowledgment(immediately: true, at: now)
            }
            return false
        }
        acknowledgedSinceRetransmissionTimeout = true
        let peerWindow = scaledWindow(of: segment)
        // 탐침에 답했으니 다시 센다(MUST-37). 응용이 놓은 연결은 진전이 있을 때만이다(계약 동작 F8).
        if !readClosed || sendUnacknowledged.precedes(ack) || peerWindow > 0 {
            zeroWindowProbeCount = 0
        }

        // shortcut: 받은 SACK 블록(`segment.sackBlocks`)은 쓰지 않는다. 잃은 구간을 골라 다시 보내는 일(RFC 6675)은 M6-10b다.
        // 상대가 SACK을 내는지는 통계로 센다(M6-10b S1).
        if !segment.sackBlocks.isEmpty { statistics.acknowledgmentsWithSACK += 1 }
        if sendUnacknowledged.precedes(ack) {
            acknowledge(upTo: ack, at: now, into: &outputs)
        } else if ack == sendUnacknowledged, isDuplicateAcknowledgment(segment, peerWindow: peerWindow) {
            statistics.duplicateAcknowledgments += 1
            let threshold = congestionControl.slowStartThreshold
            let instruction = congestionControl.receiveDuplicateACK(ackNumber: ack, sendNext: sendNext)
            if instruction == .retransmitFirstUnacknowledgedSegment {
                isFastRetransmitPending = true
                statistics.fastRetransmits += 1
                if congestionControl.slowStartThreshold < threshold { statistics.slowStartThresholdReductions += 1 }
            }
        }
        lastPeerWindow = peerWindow

        if sendUnacknowledged.precedesOrEquals(ack),
            sendWindowUpdateSequence.precedes(segment.sequenceNumber)
                || (sendWindowUpdateSequence == segment.sequenceNumber
                    && sendWindowUpdateAcknowledgment.precedesOrEquals(ack))
        {
            sendWindow = peerWindow
            maximumSendWindow = max(maximumSendWindow, peerWindow)
            sendWindowUpdateSequence = segment.sequenceNumber
            sendWindowUpdateAcknowledgment = ack
        }

        guard finAcknowledged else { return true }
        switch state {
        case .finWait1:
            enterFinWait2(at: now)
        case .closing:
            enterTimeWait(at: now)
            return false
        case .lastAck:
            terminate(.finished, into: &outputs)
            return false
        default:
            break
        }
        return true
    }

    /// 새 데이터를 확인하는 ACK(RFC 9293 3.10.7.4 다섯째 ESTABLISHED, RFC 6298 5.2·5.3).
    mutating func acknowledge(upTo ack: SequenceNumber, at now: ContinuousClock.Instant, into outputs: inout [Output]) {
        let acknowledgedCount = Int(ack.distance(from: sendUnacknowledged))
        // FIN의 ACK는 버퍼 밖의 번호다. 데이터 쪽은 FIN 번호까지만 버린다.
        let released = sendBuffer.acknowledge(upTo: finAcknowledgedBy(ack) ? finSequence : ack)
        sendUnacknowledged = ack
        if transmitNext.precedes(ack) { transmitNext = ack }
        retransmissionCount = 0
        if let sample = roundTripSample, sample.end.precedesOrEquals(ack) {
            retransmissionEstimator.recordSample(now - sample.sentAt)
            roundTripSample = nil
        }
        let instruction = congestionControl.acknowledgeNewData(
            bytes: acknowledgedCount, ackNumber: ack, sendNext: sendNext)
        timers[.retransmission] = hasOutstandingData ? now + retransmissionTimeout : nil
        if instruction == .retransmitFirstUnacknowledgedSegment {
            isFastRetransmitPending = true
            statistics.partialAcknowledgmentRetransmits += 1
        } else if !congestionControl.isInFastRecovery {
            statistics.maximumCongestionWindow = max(
                statistics.maximumCongestionWindow, congestionControl.congestionWindow)
        }
        if released > 0, isWriteBlocked {
            isWriteBlocked = false
            outputs.append(.event(.writable))
        }
    }

    /// 중복 ACK(RFC 5681 2): 확인받지 못한 데이터가 있고, 데이터·SYN·FIN이 없고, ACK가 지금까지의 최댓값(SND.UNA)과 같고,
    /// 광고한 창이 직전 ACK와 같다.
    func isDuplicateAcknowledgment(_ segment: TCPSegment, peerWindow: Int) -> Bool {
        hasOutstandingData && segment.payload.isEmpty && !segment.flags.contains(.syn)
            && !segment.flags.contains(.fin) && segment.acknowledgmentNumber == sendUnacknowledged
            && peerWindow == lastPeerWindow
    }

    func finAcknowledgedBy(_ ack: SequenceNumber) -> Bool {
        finRequested && ack == finSequence.advanced(by: 1)
    }

    /// SYN이 아닌 세그먼트의 창: `SEG.WND << Snd.Wind.Shift`(RFC 7323 2.3).
    func scaledWindow(of segment: TCPSegment) -> Int {
        Int(segment.window) << sendWindowShift
    }

    // MARK: 일곱째·여덟째: 데이터와 FIN

    /// 데이터는 ESTABLISHED·FIN-WAIT-1·FIN-WAIT-2에서만 받는다. FIN은 그 앞의 데이터가 빈 곳 없이 도착했을 때만 소비한다
    /// (계약 동작 T2). 그 밖의 상태에서는 상대가 이미 FIN을 보냈으므로 데이터와 FIN을 무시한다.
    mutating func processText(_ text: InboundText, at now: ContinuousClock.Instant, into outputs: inout [Output]) {
        switch state {
        case .established, .finWait1, .finWait2: break
        default: return
        }
        if !text.payload.isEmpty {
            // close 뒤에 온 새 데이터: RST로 데이터를 잃었다고 알리고 끝낸다(SHLD-3, 계약 동작 T6).
            if readClosed {
                outputs.append(.segment(resetSegment(sequence: sendNext)))
                terminate(.aborted, into: &outputs)
                return
            }
            let wasReadable = receiveBuffer.readableCount > 0
            let inOrder = text.sequence == receiveBuffer.nextSequence
            let insertion = receiveBuffer.insert(text.payload, at: text.sequence)
            // 순서가 어긋난 데이터, 빈 곳을 메우는 데이터는 곧바로 ACK한다(RFC 5681 4.2). 순서대로 온 데이터는 2×RMSS가
            // 쌓이면 곧바로, 아니면 40ms 안에(계약 동작 F5).
            if !inOrder || insertion.filledGap || insertion.advancedCount == 0 {
                scheduleAcknowledgment(immediately: true, at: now)
            } else {
                unacknowledgedByteCount += insertion.advancedCount
                scheduleAcknowledgment(
                    immediately: unacknowledgedByteCount >= 2 * receiveMaximumSegmentSize, at: now)
            }
            if !wasReadable, receiveBuffer.readableCount > 0 {
                outputs.append(.event(.readable))
            }
        }
        if text.fin {
            // FIN에는 곧바로 ACK한다. 앞에 빈 곳이 있으면 자리만 적어 두고, 빈 곳이 메워질 때 소비한다(SHLD-31. 상대가
            // FIN을 다시 보내기를 기다리면 닫기가 RTO만큼 늦는다).
            scheduleAcknowledgment(immediately: true, at: now)
            pendingFinSequence = text.sequence.advanced(by: UInt32(text.payload.count))
        }
        // 적어 둔 FIN 앞의 데이터가 빈 곳 없이 다 왔는가. 이 세그먼트가 빈 곳을 메웠을 수도 있다.
        guard let finSequence = pendingFinSequence, finSequence.precedesOrEquals(receiveBuffer.nextSequence) else { return }
        pendingFinSequence = nil
        scheduleAcknowledgment(immediately: true, at: now)
        finReceived = true
        outputs.append(.event(.endOfStream))
        switch state {
        case .established:
            state = .closeWait
        case .finWait1:
            if finAcknowledged { enterTimeWait(at: now) } else { state = .closing }
        case .finWait2:
            enterTimeWait(at: now)
        default:
            break
        }
    }

    // MARK: 상태 옮기기

    /// FIN-WAIT-2. `close`를 부른 연결은 60초 안에 상대의 FIN이 오지 않으면 끝난다(계약 동작 T6).
    mutating func enterFinWait2(at now: ContinuousClock.Instant) {
        state = .finWait2
        if readClosed {
            timers[.finWait2Linger] = now + Self.finWait2Linger
        }
    }

    /// TIME-WAIT. 다른 타이머를 모두 끄고 60초를 잰다(RFC 9293 3.10.7.4 여덟째, 계약 동작 T6).
    /// 미뤄 둔 ACK(FIN에 대한 것)는 남긴다.
    mutating func enterTimeWait(at now: ContinuousClock.Instant) {
        state = .timeWait
        let acknowledgment = timers[.acknowledgment]
        timers.removeAll()
        timers[.acknowledgment] = acknowledgment
        timers[.timeWait] = now + Self.timeWaitDuration
        timeWaitEnteredAt = now
        roundTripSample = nil
    }

    /// 무엇이든 받으면 keep-alive를 다시 2시간으로(계약 동작 T8). 그 밖의 상태에서는 끈다.
    mutating func refreshKeepalive(at now: ContinuousClock.Instant) {
        keepaliveProbeCount = 0
        switch state {
        case .established, .closeWait, .finWait2:
            timers[.keepalive] = now + Self.keepaliveIdle
        default:
            timers[.keepalive] = nil
        }
    }

    /// challenge ACK(RFC 5961 3.2·4.2): `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>`. 5초에 10개까지(계약 동작 X4).
    mutating func sendChallengeAcknowledgment(at now: ContinuousClock.Instant) {
        if challengeLimiter.permit(at: now) {
            scheduleAcknowledgment(immediately: true, at: now)
        }
    }
}
