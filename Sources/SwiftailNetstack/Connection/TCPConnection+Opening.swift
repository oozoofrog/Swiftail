import SwiftailBase

/// 연결 맺기: 능동 열기, 수동 열기, SYN-SENT의 세그먼트 처리(RFC 9293 3.5, 3.10.7.3), MSS와 창 확장의 협상.
extension TCPConnection {
    /// 능동 열기. SYN(MSS, SACK-Permitted, Window Scale)을 보내고 SYN-SENT가 된다(계약 동작 T3).
    ///
    /// - Parameters:
    ///   - local: 이 쪽 주소와 포트. 스택이 목적지와 같은 계열의 자기 주소와 빈 포트를 고른다(계약 동작 S8).
    ///   - remote: 상대 주소와 포트.
    ///   - initialSequenceNumber: ISS(RFC 6528, 스택이 만든다).
    ///   - now: 지금.
    /// - Returns: 연결과, 보낼 SYN.
    package static func connect(
        from local: IPEndpoint,
        to remote: IPEndpoint,
        initialSequenceNumber: SequenceNumber,
        at now: ContinuousClock.Instant
    ) -> (connection: TCPConnection, outputs: [Output]) {
        var connection = TCPConnection(
            state: .synSent, local: local, remote: remote,
            initialSendSequence: initialSequenceNumber, initialReceiveSequence: SequenceNumber(0),
            offersWindowScale: true, at: now)
        connection.timers[.retransmission] = now + connection.retransmissionTimeout
        return (connection, [.segment(connection.synchronizeSegment())])
    }

    /// 수동 열기. 스택이 리스너에 온 SYN을 넘기면 SYN-ACK를 보내고 SYN-RECEIVED가 된다(RFC 9293 3.10.7.2, 계약 동작 T4).
    ///
    /// SYN에 실린 데이터와 FIN은 받지 않는다(확인하지 않으므로 상대가 맺어진 뒤 다시 보낸다). 이 쪽 주소는 SYN의 목적지다.
    ///
    /// - Parameters:
    ///   - syn: ACK·RST가 없는 SYN.
    ///   - initialSequenceNumber: ISS.
    ///   - now: 지금.
    /// - Returns: 연결과, 보낼 SYN-ACK.
    /// - Throws: `AcceptError`. 상대 MSS가 64보다 작으면 그 SYN에 답할 RST를 담는다(계약 동작 X9).
    package static func accept(
        _ syn: TCPSegment,
        initialSequenceNumber: SequenceNumber,
        at now: ContinuousClock.Instant
    ) throws(AcceptError) -> (connection: TCPConnection, outputs: [Output]) {
        guard syn.flags.contains(.syn), !syn.flags.contains(.ack), !syn.flags.contains(.rst) else {
            throw .notInitialSYN
        }
        guard let peerSize = acceptablePeerSegmentSize(syn) else {
            // RFC 9293 3.10.7.1: ACK가 없는 세그먼트에는 <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>.
            throw .unacceptableMaximumSegmentSize(
                reset: TCPSegment(
                    source: syn.destination, destination: syn.source, sequenceNumber: SequenceNumber(0),
                    acknowledgmentNumber: syn.sequenceNumber.advanced(by: syn.sequenceLength), flags: [.rst, .ack]))
        }
        var connection = TCPConnection(
            state: .synReceived, local: syn.destination, remote: syn.source,
            initialSendSequence: initialSequenceNumber, initialReceiveSequence: syn.sequenceNumber,
            offersWindowScale: syn.windowScale != nil, at: now)
        connection.adoptPeerSynchronize(syn, peerSegmentSize: peerSize)
        connection.timers[.retransmission] = now + connection.retransmissionTimeout
        return (connection, [.segment(connection.synchronizeSegment())])
    }

    /// 이 쪽의 SYN(SYN-SENT) 또는 SYN-ACK(SYN-RECEIVED). 처음 보낼 때와 다시 보낼 때 같다.
    /// 창은 확장하지 않고(RFC 7323 2.2), MSS는 늘 싣고(SHLD-5), Window Scale은 `offersWindowScale`일 때만 싣는다(계약 동작 F2).
    /// SACK-Permitted는 SYN에는 늘, SYN-ACK에는 상대의 SYN에 있었을 때만 싣는다(RFC 2018 2. 수동 쪽의 조건은 RFC가 정하지
    /// 않지만 gVisor `connect.go`의 SYN-ACK와 같다).
    func synchronizeSegment() -> TCPSegment {
        let acknowledges = state == .synReceived
        return TCPSegment(
            source: localEndpoint, destination: remoteEndpoint, sequenceNumber: initialSendSequence,
            acknowledgmentNumber: acknowledges ? receiveNext : SequenceNumber(0),
            flags: acknowledges ? [.syn, .ack] : [.syn], window: UInt16(Self.synchronizeWindow),
            maximumSegmentSize: UInt16(receiveMaximumSegmentSize),
            windowScale: offersWindowScale ? UInt8(Self.ownWindowShift) : nil,
            sackPermitted: !acknowledges || peerPermitsSACK)
    }

    // MARK: SYN-SENT (RFC 9293 3.10.7.3)

    /// SYN-SENT의 세그먼트 처리: ACK 검사 → RST → SYN. 3.10.7.4의 순서를 따르지 않는다(계약 동작 T2).
    mutating func receiveInSynSent(_ segment: TCPSegment, at now: ContinuousClock.Instant, into outputs: inout [Output]) {
        let flags = segment.flags
        let ack = segment.acknowledgmentNumber
        // 첫째: ACK. SEG.ACK =< ISS 또는 SEG.ACK > SND.NXT면 RST(RST가 아니면)로 답하고 버린다.
        var acknowledgesSynchronize = false
        if flags.contains(.ack) {
            if ack.precedesOrEquals(initialSendSequence) || sendNext.precedes(ack) {
                if !flags.contains(.rst) { outputs.append(.segment(resetSegment(sequence: ack))) }
                return
            }
            acknowledgesSynchronize = sendUnacknowledged.precedes(ack)
        }
        // 둘째: RST. ACK가 받아들일 만했으면 거절이다(계약 동작 T3. RFC는 "connection reset", gVisor는 refused).
        if flags.contains(.rst) {
            if acknowledgesSynchronize { terminate(.refused, into: &outputs) }
            return
        }
        // 넷째: SYN. ACK 없는 SYN(동시 열기)은 버린다(계약 제외 표). SYN도 RST도 없으면 버린다(다섯째).
        guard flags.contains(.syn), acknowledgesSynchronize else { return }
        guard let peerSize = Self.acceptablePeerSegmentSize(segment) else {
            outputs.append(.segment(resetSegment(sequence: ack)))
            terminate(.refused, into: &outputs)
            return
        }
        receiveBuffer = ReceiveBuffer(initialSequence: segment.sequenceNumber.advanced(by: 1))
        advertisedWindowEnd = receiveNext.advanced(by: UInt32(Self.synchronizeWindow))
        adoptPeerSynchronize(segment, peerSegmentSize: peerSize)
        sendUnacknowledged = ack
        sendWindowUpdateAcknowledgment = ack
        establish(at: now, into: &outputs)
        // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>. 쓴 데이터가 있으면 거기에 실린다.
        // SYN-ACK에 실린 데이터·FIN은 받지 않는다(확인하지 않으므로 상대가 다시 보낸다).
        scheduleAcknowledgment(immediately: true, at: now)
    }

    // MARK: 협상

    /// 상대 SYN의 MSS(없으면 기본값). 64보다 작으면 `nil`(계약 동작 X9).
    static func acceptablePeerSegmentSize(_ syn: TCPSegment) -> Int? {
        let size = syn.maximumSegmentSize.map(Int.init) ?? defaultPeerMaximumSegmentSize(for: syn.source.address)
        return size >= minimumPeerSegmentSize ? size : nil
    }

    /// 상대 SYN(또는 SYN-ACK)의 MSS·Window Scale·SACK-Permitted·창을 받아들인다.
    ///
    /// - MSS: `min(상대 MSS, 자기 MTU의 MSS)`(계약 동작 T5). 데이터 세그먼트에 SACK 옵션이 실리면 그만큼 데이터를 줄인다
    ///   (`segmentPayloadLimit`).
    /// - SACK: 상대 SYN에 SACK-Permitted가 있으면 이 쪽이 SACK 블록을 보낼 수 있다(RFC 2018 4). 방향마다 따로다.
    /// - 창 확장: 양쪽 SYN에 다 있을 때만 켠다. 보내는 창은 상대의 shift(14까지)로, 광고하는 창은 자기 shift로(RFC 7323 2.3).
    /// - 창: SYN의 창 필드는 확장하지 않는다(RFC 7323 2.2). SND.WL1은 SYN의 번호다.
    mutating func adoptPeerSynchronize(_ syn: TCPSegment, peerSegmentSize: Int) {
        sendMaximumSegmentSize = min(peerSegmentSize, receiveMaximumSegmentSize)
        peerPermitsSACK = syn.sackPermitted
        statistics.sackPermitted = syn.sackPermitted
        if offersWindowScale, let shift = syn.windowScale {
            sendWindowShift = min(Int(shift), Self.maximumWindowShift)
            receiveWindowShift = Self.ownWindowShift
        }
        sendWindow = Int(syn.window)
        maximumSendWindow = sendWindow
        lastPeerWindow = sendWindow
        sendWindowUpdateSequence = syn.sequenceNumber
    }

    /// 맺어졌다. SYN-SENT와 SYN-RECEIVED가 함께 쓴다.
    ///
    /// SYN을 다시 보내지 않았으면 핸드셰이크의 왕복이 RTT의 첫 표본이다(Karn, RFC 6298 3). 다시 보냈으면 RTO를
    /// 3초 이상으로 둔다(RFC 6298 5.7). 혼잡 제어는 실제 MSS로 여기서 만든다(SYN의 ACK는 창을 키우지 않는다, RFC 6928 2).
    mutating func establish(at now: ContinuousClock.Instant, into outputs: inout [Output]) {
        state = .established
        if retransmissionCount == 0 {
            retransmissionEstimator.recordSample(now - synchronizeSentAt)
        }
        retransmissionEstimator.handshakeCompleted()
        retransmissionCount = 0
        congestionControl = NewRenoCongestionControl(
            maximumSegmentSize: sendMaximumSegmentSize, initialSequenceNumber: initialSendSequence)
        statistics.maximumCongestionWindow = congestionControl.congestionWindow
        timers[.retransmission] = nil
        timers[.keepalive] = now + Self.keepaliveIdle
        outputs.append(.event(.established))
    }
}
