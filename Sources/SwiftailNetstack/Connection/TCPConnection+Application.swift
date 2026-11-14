/// 응용의 호출: 쓰기, 읽기, 쓰기 끝내기, 닫기, 끊기(RFC 9293 3.10.2~3.10.5, 계약 동작 T6).
///
/// 각 호출은 끝에서 보낼 수 있는 것을 보내고 기한이 된 ACK를 낸다. 끝난 연결에서는 아무것도 하지 않는다
/// (읽기만은 남은 데이터를 돌려준다).
extension TCPConnection {
    /// 바이트를 보내는 버퍼에 자리가 있는 만큼 넣는다. 맺어지기 전(SYN-SENT, SYN-RECEIVED)에 쓴 것은 맺어진 뒤에 나간다.
    ///
    /// - Returns: 받아들인 바이트 수와 출력. 다 받지 못했으면 자리가 날 때 `.writable`이 나온다.
    ///   쓰기를 끝냈거나(`finishWriting`·`close`) 쓸 수 없는 상태면 0이다.
    package mutating func write(
        _ bytes: ArraySlice<UInt8>, at now: ContinuousClock.Instant
    ) -> (accepted: Int, outputs: [Output]) {
        guard canWrite else { return (0, []) }
        let accepted = sendBuffer.append(bytes)
        if accepted < bytes.count { isWriteBlocked = true }
        var outputs: [Output] = []
        completeCall(at: now, into: &outputs)
        return (accepted, outputs)
    }

    /// 읽을 수 있는 바이트를 앞에서부터 `maximumLength`까지 꺼낸다. 읽은 만큼 받는 창이 열리고, SWS 회피의 문턱을 넘으면
    /// 창 갱신 ACK가 나간다(계약 동작 F3).
    package mutating func read(
        upTo maximumLength: Int, at now: ContinuousClock.Instant
    ) -> (bytes: [UInt8], outputs: [Output]) {
        let bytes = receiveBuffer.read(upTo: maximumLength)
        var outputs: [Output] = []
        guard state != .closed else { return (bytes, []) }
        if !bytes.isEmpty, !finReceived, windowUpdateIsDue {
            switch state {
            case .established, .finWait1, .finWait2:
                scheduleAcknowledgment(immediately: true, at: now)
            default:
                break
            }
        }
        completeCall(at: now, into: &outputs)
        return (bytes, outputs)
    }

    /// 보내기를 끝낸다(반닫힘). 보내는 버퍼가 비면 FIN이 나간다: ESTABLISHED → FIN-WAIT-1, CLOSE-WAIT → LAST-ACK.
    /// 읽기는 계속할 수 있다. 맺어지기 전에 부르면 맺어진 뒤에 나간다.
    package mutating func finishWriting(at now: ContinuousClock.Instant) -> [Output] {
        guard canWrite else { return [] }
        finRequested = true
        var outputs: [Output] = []
        completeCall(at: now, into: &outputs)
        return outputs
    }

    /// 연결을 닫는다: `finishWriting`에 더해 읽기를 끝낸다(RFC 9293 3.10.4, 계약 동작 T6).
    ///
    /// - 읽지 않은 데이터가 있으면 곧바로 `<SEQ=SND.NXT><CTL=RST>`를 보내고 끝난다(SHLD-3).
    /// - 이 뒤에 새 데이터가 오면 RST를 보내고 끝난다.
    /// - FIN-WAIT-2에서 60초 안에 상대의 FIN이 오지 않으면 끝난다.
    /// - SYN-SENT면 아무것도 보내지 않고 끝난다(RFC 9293 3.10.4: TCB를 지운다).
    package mutating func close(at now: ContinuousClock.Instant) -> [Output] {
        var outputs: [Output] = []
        switch state {
        case .closed:
            return []
        case .synSent:
            terminate(.aborted, into: &outputs)
            return outputs
        case .timeWait:
            readClosed = true
            receiveBuffer = ReceiveBuffer(initialSequence: receiveBuffer.nextSequence)
            return []
        default:
            break
        }
        readClosed = true
        if receiveBuffer.readableCount > 0 {
            outputs.append(.segment(resetSegment(sequence: sendNext)))
            terminate(.aborted, into: &outputs)
            return outputs
        }
        if canWrite { finRequested = true }
        if state == .finWait2, timers[.finWait2Linger] == nil {
            timers[.finWait2Linger] = now + Self.finWait2Linger
        }
        completeCall(at: now, into: &outputs)
        return outputs
    }

    /// 연결을 곧바로 끊는다(RFC 9293 3.10.5). 버퍼의 것은 버린다.
    ///
    /// SYN-SENT는 아무것도 보내지 않는다. CLOSING·LAST-ACK·TIME-WAIT도 보내지 않는다(양쪽 데이터가 이미 끝났다. 같은 절).
    /// 그 밖에는 `<SEQ=SND.NXT><CTL=RST>`를 보낸다.
    package mutating func abort() -> [Output] {
        var outputs: [Output] = []
        switch state {
        case .closed:
            return []
        case .synSent, .closing, .lastAck, .timeWait:
            break
        case .synReceived, .established, .finWait1, .finWait2, .closeWait:
            outputs.append(.segment(resetSegment(sequence: sendNext)))
        }
        terminate(.aborted, into: &outputs)
        return outputs
    }

    /// 응용이 아직 쓸 수 있다: 쓰기를 끝내지 않았고, 상태가 이 쪽 FIN 전이다.
    var canWrite: Bool {
        guard !finRequested else { return false }
        switch state {
        case .synSent, .synReceived, .established, .closeWait: return true
        default: return false
        }
    }

    /// 응용 호출의 끝: 보낼 수 있는 것을 보내고 기한이 된 ACK를 낸다(데이터 세그먼트가 나갔으면 거기에 실렸다).
    private mutating func completeCall(at now: ContinuousClock.Instant, into outputs: inout [Output]) {
        guard state != .closed else { return }
        transmit(at: now, into: &outputs)
        flushAcknowledgment(at: now, into: &outputs)
    }
}
