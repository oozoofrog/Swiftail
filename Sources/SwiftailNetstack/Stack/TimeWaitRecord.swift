/// TIME-WAIT에 든 연결 대신 남기는 기록(계약 동작 S6).
///
/// 먼저 닫은 쪽은 TIME-WAIT에 머물며 상대의 FIN 재전송에 ACK하고, 앞 연결의 늦은 세그먼트가 같은 4-튜플의 새 연결에
/// 섞이지 않게 한다(RFC 9293 3.6.1, MUST-13). 버퍼를 쥔 연결을 60초씩 두지 않으려고 4-튜플(표의 열쇠)과 시퀀스 번호 둘,
/// 기한만 남긴다. 기록은 기한 전에 버리지 않는다.
struct TimeWaitRecord: Sendable, Equatable {
    /// SND.NXT: 이 쪽 FIN의 다음 번호.
    var sendNext: SequenceNumber
    /// RCV.NXT: 상대 FIN의 다음 번호.
    var receiveNext: SequenceNumber
    /// 기록이 사라지는 시각.
    var deadline: ContinuousClock.Instant

    /// 이 4-튜플로 온 세그먼트에 답할 세그먼트. 답하지 않으면 `nil`. FIN 재전송이면 기한을 60초 뒤로 다시 잰다.
    ///
    /// - RST는 무시한다. RFC 9293 3.10.7.4 둘째는 TIME-WAIT의 RST에 CLOSED로 가라고 하지만, 계약 동작 S6이 기록을 기한 전에
    ///   버리지 않기로 했다(gVisor도 TIME-WAIT의 RST를 무시한다, TCP 노트 4.2. RFC 1337의 TIME-WAIT 암살을 막는다).
    /// - 이미 소비한 상대 FIN의 재전송(`SEG.SEQ + 데이터 길이 = RCV.NXT − 1`)에는 ACK하고 기한을 다시 잰다
    ///   (RFC 9293 3.10.7.4 다섯째·여덟째의 TIME-WAIT, 계약 동작 T6. `TCPConnection`의 TIME-WAIT 예외와 같은 조건이다).
    /// - SYN에는 challenge ACK로 답한다(RFC 5961 4.2, RFC 9293 3.10.7.4 넷째). 같은 4-튜플로 새 연결을 바로 열지 않는다
    ///   (RFC 9293 3.6.1의 MAY를 쓰지 않는다).
    /// - 그 밖에 시퀀스 번호를 쓰는 세그먼트(데이터, 다른 FIN)에는 ACK로 답한다(시퀀스 검사의 "받지 않는 세그먼트에 ACK").
    /// - 데이터 없는 ACK에는 답하지 않는다(ACK 고리를 막는다). 받은 세그먼트 하나에 답은 많아야 하나라 증폭이 없다(계약 동작 X8).
    ///
    /// 답은 `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>`이고 창은 0이다(이 연결은 더 받지 않는다).
    mutating func reply(to segment: TCPSegment, at now: ContinuousClock.Instant) -> TCPSegment? {
        let flags = segment.flags
        if flags.contains(.rst) { return nil }
        let isFinRetransmission =
            flags.contains(.fin) && !flags.contains(.syn)
            && segment.sequenceNumber.advanced(by: UInt32(clamping: segment.payload.count))
                == receiveNext.advanced(by: .max)  // RCV.NXT − 1
        if isFinRetransmission {
            deadline = now + TCPConnection.timeWaitDuration
        } else if segment.sequenceLength == 0 {
            return nil
        }
        return TCPSegment(
            source: segment.destination, destination: segment.source, sequenceNumber: sendNext,
            acknowledgmentNumber: receiveNext, flags: [.ack])
    }
}
