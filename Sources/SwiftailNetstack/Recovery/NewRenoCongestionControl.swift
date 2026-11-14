/// 연결 하나의 NewReno 혼잡 제어: slow start, congestion avoidance, fast retransmit·fast recovery(RFC 5681, RFC 6582).
///
/// 입력과 출력이 수(바이트 수, 시퀀스 번호, 시간)뿐인 값 타입이다. 소켓도 시계도 없다.
/// 연결은 ACK가 올 때마다 **중복 ACK인지 새 데이터를 확인하는 ACK인지를 먼저 가려**(중복 ACK의 정의는 RFC 5681 2절: 날아가는 데이터가 있고,
/// 데이터가 없고, SYN·FIN이 없고, ACK 번호가 지금까지의 최댓값과 같고, 광고한 창이 직전과 같다) 알맞은 메서드를 부른다.
/// 이 타입이 알려 주는 것은 두 가지다. 지금 보낼 수 있는 양(`sendableBytes(peerWindow:flightSize:)`)과
/// "`SND.UNA`부터 한 세그먼트를 다시 보내라"는 지시(`Instruction`)다. 재전송 타이머를 켜고 끄는 일은 연결이 한다.
/// RFC 6582 3.2의 "첫 partial ACK에서 재전송 타이머를 다시 켠다"는 RFC 6298 5.3(새 데이터를 확인하는 ACK마다 다시 켠다)에 포함되므로 따로 알리지 않는다.
///
/// SACK은 없다(계약 총괄 확정 N3). 한 창에서 여러 세그먼트가 손실되면 partial ACK마다 한 세그먼트씩 다시 보내며 회복한다.
///
/// 연결이 불러야 하는 때:
/// - 연결이 맺어진 직후: `init(maximumSegmentSize:initialSequenceNumber:)`. SYN과 SYN-ACK의 ACK는 창을 키우지 않는다(RFC 6928 2).
/// - 새 데이터를 처음 보내기 전: `restartAfterIdle(idleDuration:retransmissionTimeout:)`.
/// - 새 데이터를 확인하는 ACK: `acknowledgeNewData(bytes:ackNumber:sendNext:)`.
/// - 중복 ACK: `receiveDuplicateACK(ackNumber:sendNext:)`.
/// - 재전송 타이머 만료(데이터): `retransmissionTimerExpired(sendUnacknowledged:sendNext:)`. SYN의 만료에는 부르지 않는다(이 타입은 맺어진 뒤에 만든다).
package struct NewRenoCongestionControl: Sendable, Equatable {
    /// 입력에 대해 연결이 해야 하는 일.
    package enum Instruction: Sendable, Equatable {
        /// 지시 없음.
        case none
        /// `SND.UNA`부터 한 세그먼트를 다시 보낸다(RFC 5681 3.2 단계 3, RFC 6582 3.2 3의 partial ACK).
        case retransmitFirstUnacknowledgedSegment
    }

    /// cwnd의 상한. 창 확장을 써도 창은 2³⁰ 미만이라(RFC 7323 2.3) 이보다 큰 cwnd는 쓸 수 없고,
    /// 상한을 두면 부풀리기·큰 입력에도 덧셈이 넘치지 않는다.
    package static let maximumWindow = 1 << 30
    /// 중복 ACK가 몇 번 오면 fast retransmit을 하는가(RFC 5681 3.2).
    package static let duplicateACKThreshold = 3
    /// MSS 옵션은 16비트다.
    private static let maximumSegmentSizeRange = 1...65_535

    /// SMSS. 광고된 MSS를 자기 MTU로 묶은 값이다(계약 동작 T5).
    package let maximumSegmentSize: Int
    /// cwnd(바이트).
    package private(set) var congestionWindow: Int
    /// ssthresh(바이트). 처음엔 사실상 무한이다(RFC 5681 3.1: 임의로 높게).
    package private(set) var slowStartThreshold = NewRenoCongestionControl.maximumWindow
    /// SND.UNA가 그대로인 채로 연속해 온 중복 ACK의 수. 새 데이터를 확인하는 ACK나 만료에 0이 된다.
    package private(set) var duplicateACKCount = 0
    /// fast recovery 중인가.
    package private(set) var isInFastRecovery = false
    /// RFC 6582의 `recover`: fast recovery를 시작했거나 RTO가 만료됐을 때의 `SND.NXT`(그때 보낸 가장 높은 번호의 다음 번호).
    ///
    /// RFC 6582 3.2는 `recover`를 "지금까지 보낸 가장 높은 번호"로 두고 `ACK − 1 > recover`로 견준다. 같은 식을
    /// 한 칸 뒤 번호로 저장해 `ACK > recover`로 견주는 것이다. 문자 그대로 쓰면 초기값 ISS에서 첫 창의 손실(ACK = ISS + 1)이 fast retransmit에 걸리지 않는다.
    /// 새 데이터가 확인되어 ACK가 `recover`를 넘으면 `recover`를 ACK 바로 앞으로 끌어올린다.
    /// 번호는 2³² 순환이라 낡은 `recover`는 2³¹ 넘게 떨어지면 앞뒤가 뒤집히기 때문이다(4GiB 전송, 계약 시험 6).
    package private(set) var recover: SequenceNumber

    /// 가장 최근 RTO 만료가 다시 보낸 세그먼트의 첫 번호. 같은 세그먼트의 반복 만료를 가린다(RFC 5681 3.1). 새 데이터가 확인되면 지운다.
    private var lastTimeoutSegment: SequenceNumber?
    private let initialWindow: Int

    /// - Parameters:
    ///   - maximumSegmentSize: SMSS. 1…65535로 묶는다.
    ///   - initialSequenceNumber: 이 쪽의 ISS. `recover`의 초기값이다(RFC 6582 3.2 1).
    package init(maximumSegmentSize: Int, initialSequenceNumber: SequenceNumber) {
        let size = Self.clamped(maximumSegmentSize)
        self.maximumSegmentSize = size
        initialWindow = Self.initialWindow(maximumSegmentSize: size)
        congestionWindow = initialWindow
        recover = initialSequenceNumber
    }

    /// 초기 창 `min(10·MSS, max(2·MSS, 14600))`(RFC 6928 2의 식 1).
    package static func initialWindow(maximumSegmentSize: Int) -> Int {
        let size = clamped(maximumSegmentSize)
        return min(10 * size, max(2 * size, 14_600))
    }

    /// 지금 보낼 수 있는 바이트 수: `min(cwnd, SND.WND) − FlightSize`. 0 아래로는 내려가지 않는다(창이 줄어도 새 데이터를 보내지 않는다. RFC 9293 MUST-34).
    ///
    /// - Parameters:
    ///   - peerWindow: `SND.WND`. 상대가 광고한 창(창 확장을 적용한 값).
    ///   - flightSize: `SND.NXT − SND.UNA`.
    package func sendableBytes(peerWindow: Int, flightSize: Int) -> Int {
        max(0, min(congestionWindow, max(0, peerWindow)) - max(0, flightSize))
    }

    // MARK: 새 데이터를 확인하는 ACK

    /// 새 데이터를 확인하는 ACK를 받았다(`SND.UNA`가 `ackNumber`로 앞서 갔다).
    ///
    /// fast recovery 밖에서는 slow start(`cwnd < ssthresh`)가 `cwnd += min(N, SMSS)`(RFC 5681 식 2),
    /// 그 밖(`cwnd >= ssthresh`)은 congestion avoidance가 `cwnd += SMSS·SMSS/cwnd`(식 3)다. 식 3의 정수 나눗셈이 0이면 1바이트를 올린다(3.1의 SHOULD).
    /// `cwnd == ssthresh`는 RFC가 어느 쪽이든 허용하며 congestion avoidance로 본다.
    ///
    /// fast recovery 중에는 RFC 6582 3.2 3이다. ACK가 `recover`까지 모두 확인하면(full ACK) `cwnd = min(ssthresh, max(FlightSize, SMSS) + SMSS)`로 하고 회복에서 나온다
    /// (두 방식 중 새 창이 한꺼번에 쏟아지지 않는 앞의 것). 아니면(partial ACK) 첫 미확인 세그먼트를 다시 보내라고 알리고,
    /// cwnd에서 확인된 만큼을 빼고, 1 SMSS 이상 확인됐으면 SMSS를 더하고, 회복을 이어 간다.
    ///
    /// - Parameters:
    ///   - bytes: 이 ACK가 새로 확인한 바이트 수(N). 0 이하면 새 데이터를 확인한 ACK가 아니므로 아무것도 하지 않는다.
    ///   - ackNumber: ACK 번호. 이 호출 뒤의 `SND.UNA`다.
    ///   - sendNext: `SND.NXT`.
    package mutating func acknowledgeNewData(bytes: Int, ackNumber: SequenceNumber, sendNext: SequenceNumber) -> Instruction {
        guard bytes > 0 else { return .none }
        duplicateACKCount = 0
        lastTimeoutSegment = nil
        var instruction = Instruction.none
        if isInFastRecovery {
            if ackNumber.precedes(recover) {
                // partial ACK(RFC 6582 3.2 3). 부풀린 cwnd를 확인된 만큼 되돌린다. 1 세그먼트 아래로는 내려가지 않는다.
                congestionWindow = max(maximumSegmentSize, congestionWindow - bytes)
                if bytes >= maximumSegmentSize { grow(by: maximumSegmentSize) }
                instruction = .retransmitFirstUnacknowledgedSegment
            } else {
                // full ACK.
                let flightSize = Self.flightSize(from: ackNumber, to: sendNext)
                congestionWindow = min(slowStartThreshold, max(flightSize, maximumSegmentSize) + maximumSegmentSize)
                isInFastRecovery = false
            }
        } else if congestionWindow < slowStartThreshold {
            grow(by: min(bytes, maximumSegmentSize))
        } else {
            grow(by: max(1, maximumSegmentSize * maximumSegmentSize / congestionWindow))
        }
        if !isInFastRecovery, recover.precedes(ackNumber) {
            recover = ackNumber.advanced(by: .max)   // ACK − 1
        }
        return instruction
    }

    // MARK: 중복 ACK

    /// 중복 ACK를 받았다.
    ///
    /// 첫째·둘째는 세기만 한다(RFC 5681 3.2 단계 1의 limited transmit은 넣지 않는다. 계약 제외 표).
    /// 셋째에서 ACK가 `recover`를 넘으면(RFC 6582 3.2 2) fast retransmit이다: `ssthresh = max(FlightSize/2, 2·SMSS)`(식 4),
    /// `cwnd = ssthresh + 3·SMSS`, `recover = SND.NXT`, 한 세그먼트를 다시 보내라고 알린다(단계 2·3).
    /// 넘지 못하면(RTO 뒤의 불필요한 재전송이 낳은 중복 ACK일 수 있다. RFC 6582 4) 들어가지 않고 ssthresh를 건드리지 않는다.
    /// fast recovery 중의 중복 ACK마다 `cwnd += SMSS`다(단계 4).
    ///
    /// - Parameters:
    ///   - ackNumber: ACK 번호(= `SND.UNA`).
    ///   - sendNext: `SND.NXT`.
    package mutating func receiveDuplicateACK(ackNumber: SequenceNumber, sendNext: SequenceNumber) -> Instruction {
        if duplicateACKCount < Int.max { duplicateACKCount += 1 }
        if isInFastRecovery {
            // shortcut: RFC 5681 3.2 단계 4의 MAY(부풀리기를 날아가는 세그먼트 수로 묶기)는 넣지 않는다. 보내는 양은 SND.WND와 2³⁰이 막는다.
            grow(by: maximumSegmentSize)
            return .none
        }
        guard duplicateACKCount == Self.duplicateACKThreshold, recover.precedes(ackNumber) else { return .none }
        slowStartThreshold = lossThreshold(flightSize: Self.flightSize(from: ackNumber, to: sendNext))
        recover = sendNext
        congestionWindow = min(slowStartThreshold + 3 * maximumSegmentSize, Self.maximumWindow)
        isInFastRecovery = true
        return .retransmitFirstUnacknowledgedSegment
    }

    // MARK: RTO 만료

    /// 데이터의 재전송 타이머가 만료됐다. 연결은 `SND.UNA`부터 한 세그먼트를 다시 보낸다.
    ///
    /// 처음 만료이면 `ssthresh = max(FlightSize/2, 2·SMSS)`(식 4)이고, 같은 세그먼트에서 되풀이되는 만료이면 ssthresh를 지킨다(RFC 5681 3.1).
    /// 어느 쪽이든 `cwnd`는 1 세그먼트(loss window)이고 slow start가 창을 다시 연다. fast recovery 중이었으면 나오고,
    /// `recover`를 `SND.NXT`로 한다(RFC 6582 3.2 4).
    ///
    /// - Parameters:
    ///   - sendUnacknowledged: `SND.UNA`. 같은 세그먼트의 반복 만료인지 가리는 데 쓴다.
    ///   - sendNext: `SND.NXT`.
    package mutating func retransmissionTimerExpired(sendUnacknowledged: SequenceNumber, sendNext: SequenceNumber) {
        if lastTimeoutSegment != sendUnacknowledged {
            slowStartThreshold = lossThreshold(flightSize: Self.flightSize(from: sendUnacknowledged, to: sendNext))
        }
        lastTimeoutSegment = sendUnacknowledged
        congestionWindow = maximumSegmentSize
        duplicateACKCount = 0
        isInFastRecovery = false
        recover = sendNext
    }

    // MARK: 유휴 뒤

    /// 데이터를 한동안 보내지 않았다가 다시 보내려 한다. 보내기 전에 부른다.
    /// 유휴가 RTO보다 길었으면 `cwnd = min(IW, cwnd)`로 줄인다(RFC 5681 4.1의 RW).
    ///
    /// - Parameters:
    ///   - idleDuration: 마지막으로 데이터를 보낸 뒤 지난 시간(RFC 5681 4.1은 "보내지 않은" 시간을 말한다).
    ///   - retransmissionTimeout: 지금의 RTO.
    package mutating func restartAfterIdle(idleDuration: Duration, retransmissionTimeout: Duration) {
        if idleDuration > retransmissionTimeout {
            congestionWindow = min(initialWindow, congestionWindow)
        }
    }

    // MARK: 도우미

    /// 식 4: `max(FlightSize/2, 2·SMSS)`.
    private func lossThreshold(flightSize: Int) -> Int {
        max(flightSize / 2, 2 * maximumSegmentSize)
    }

    private mutating func grow(by increment: Int) {
        congestionWindow = min(congestionWindow + increment, Self.maximumWindow)
    }

    /// `from`부터 `to`까지의 거리. `to`가 앞서 있으면 0.
    private static func flightSize(from: SequenceNumber, to: SequenceNumber) -> Int {
        Int(max(0, to.distance(from: from)))
    }

    private static func clamped(_ size: Int) -> Int {
        min(max(size, maximumSegmentSizeRange.lowerBound), maximumSegmentSizeRange.upperBound)
    }
}
