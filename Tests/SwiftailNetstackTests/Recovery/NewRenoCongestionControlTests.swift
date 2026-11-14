import Testing

@testable import SwiftailNetstack

/// NewReno 혼잡 제어(RFC 5681, 6582, 6928). 계약 `docs/contracts/SwiftailNetstack.md` 동작 R5~R8과 시험 8.
/// 기대값은 RFC의 식을 손으로 계산한 것이다. 시퀀스 번호는 `SND.UNA` = 1001에서 시작하는 한 흐름이다.
@Suite("NewReno 혼잡 제어")
struct NewRenoCongestionControlTests {
    private typealias Control = NewRenoCongestionControl

    private let iss = SequenceNumber(1000)
    private let mss = 1220
    /// SYN이 확인된 뒤의 `SND.UNA`.
    private var una: SequenceNumber { iss.advanced(by: 1) }

    private func control(mss: Int? = nil, iss: SequenceNumber? = nil) -> Control {
        Control(maximumSegmentSize: mss ?? self.mss, initialSequenceNumber: iss ?? self.iss)
    }

    /// 첫 창 20 세그먼트를 보낸 뒤의 `SND.NXT`.
    private var windowEnd: SequenceNumber { sendNext(from: una, segments: 20) }

    /// 확인되지 않은 세그먼트 `segments`개(`SND.UNA`부터 한 세그먼트씩)가 날아가는 중인 상태의 `SND.NXT`.
    private func sendNext(from una: SequenceNumber, segments: Int, mss: Int = 1220) -> SequenceNumber {
        una.advanced(by: UInt32(segments * mss))
    }

    /// 첫 창 20개를 보내고 세 번째 중복 ACK로 fast recovery에 들어간 상태. `recover`는 `una + 20·mss`다.
    private func enteringFastRecovery() -> Control {
        var control = control()
        let sendNext = windowEnd
        _ = control.receiveDuplicateACK(ackNumber: una, sendNext: sendNext)
        _ = control.receiveDuplicateACK(ackNumber: una, sendNext: sendNext)
        let instruction = control.receiveDuplicateACK(ackNumber: una, sendNext: sendNext)
        #expect(instruction == .retransmitFirstUnacknowledgedSegment)
        return control
    }

    // MARK: 초기 창(RFC 6928 2, 식 1)

    @Test("초기 창은 min(10·MSS, max(2·MSS, 14600))이다", arguments: [
        (1220, 12_200),     // IPv6 터널의 MSS: 10 세그먼트
        (1240, 12_400),     // IPv4 터널의 MSS: 10 세그먼트
        (536, 5_360),       // MSS 옵션이 없을 때의 IPv4 기본값
        (1460, 14_600),     // 10·MSS가 14600과 같다
        (1500, 14_600),     // 14600이 상한이다
        (7_300, 14_600),    // 2·MSS = 14600
        (10_000, 20_000),   // 2·MSS가 14600보다 크면 2 세그먼트
    ])
    func initialWindow(maximumSegmentSize: Int, expected: Int) {
        let control = control(mss: maximumSegmentSize)
        #expect(control.congestionWindow == expected)
        #expect(Control.initialWindow(maximumSegmentSize: maximumSegmentSize) == expected)
        #expect(!control.isInFastRecovery)
        #expect(control.duplicateACKCount == 0)
        #expect(control.slowStartThreshold >= 1 << 30)   // 처음엔 사실상 무한이다
    }

    // MARK: 보낼 수 있는 양(동작 R5)

    @Test("보낼 수 있는 양은 min(cwnd, SND.WND) − 날아가는 양이고 0 아래로 내려가지 않는다")
    func sendableBytes() {
        let control = control()   // cwnd 12200
        #expect(control.sendableBytes(peerWindow: 100_000, flightSize: 3_000) == 9_200)
        #expect(control.sendableBytes(peerWindow: 5_000, flightSize: 3_000) == 2_000)
        #expect(control.sendableBytes(peerWindow: 100_000, flightSize: 12_200) == 0)
        #expect(control.sendableBytes(peerWindow: 100_000, flightSize: 50_000) == 0)   // 창이 줄었거나 cwnd가 줄었다
        #expect(control.sendableBytes(peerWindow: 0, flightSize: 0) == 0)
        #expect(control.sendableBytes(peerWindow: -1, flightSize: 0) == 0)
        #expect(control.sendableBytes(peerWindow: 100, flightSize: -5) == 100)
        #expect(control.sendableBytes(peerWindow: Int.max, flightSize: Int.max) == 0)
        #expect(control.sendableBytes(peerWindow: Int.max, flightSize: Int.min) == 12_200)
        #expect(control.sendableBytes(peerWindow: Int.min, flightSize: Int.min) == 0)
    }

    // MARK: slow start와 congestion avoidance(식 2·3)

    @Test("slow start: 새로 확인된 바이트 N마다 cwnd += min(N, SMSS)(식 2)")
    func slowStart() {
        var control = control()
        let sendNext = sendNext(from: una, segments: 20)
        _ = control.acknowledgeNewData(bytes: 1_220, ackNumber: una.advanced(by: 1_220), sendNext: sendNext)
        #expect(control.congestionWindow == 13_420)
        _ = control.acknowledgeNewData(bytes: 100, ackNumber: una.advanced(by: 1_320), sendNext: sendNext)
        #expect(control.congestionWindow == 13_520)
        // 한 ACK가 여러 세그먼트를 확인해도 SMSS를 넘겨 올리지 않는다(ACK Division 대비)
        _ = control.acknowledgeNewData(bytes: 5_000, ackNumber: una.advanced(by: 6_320), sendNext: sendNext)
        #expect(control.congestionWindow == 14_740)
    }

    /// cwnd = 1220, ssthresh = 50000인 상태. 한 번 만료로 만든다(FlightSize 100000 → 식 4).
    private func afterFirstTimeout() -> Control {
        var control = control()
        control.retransmissionTimerExpired(sendUnacknowledged: una, sendNext: una.advanced(by: 100_000))
        #expect(control.congestionWindow == 1_220)
        #expect(control.slowStartThreshold == 50_000)
        return control
    }

    @Test("cwnd가 ssthresh를 넘으면 congestion avoidance로 바뀌고 cwnd += SMSS²/cwnd(식 3)")
    func congestionAvoidance() {
        var control = afterFirstTimeout()
        var ack = una
        let sendNext = una.advanced(by: 1_000_000)
        // 1220 → 2440 → … 40번 확인하면 1220·41 = 50020 > 50000
        for _ in 0..<40 {
            ack = ack.advanced(by: 1_220)
            _ = control.acknowledgeNewData(bytes: 1_220, ackNumber: ack, sendNext: sendNext)
        }
        #expect(control.congestionWindow == 50_020)
        // 1220·1220/50020 = 29.76 → 29
        ack = ack.advanced(by: 1_220)
        _ = control.acknowledgeNewData(bytes: 1_220, ackNumber: ack, sendNext: sendNext)
        #expect(control.congestionWindow == 50_049)
    }

    @Test("cwnd == ssthresh에서는 congestion avoidance를 쓴다")
    func equalWindowUsesCongestionAvoidance() {
        var control = control(mss: 10)   // cwnd 100
        control.retransmissionTimerExpired(sendUnacknowledged: una, sendNext: una.advanced(by: 40))   // ssthresh = max(20, 20), cwnd = 10
        #expect(control.slowStartThreshold == 20)
        _ = control.acknowledgeNewData(bytes: 10, ackNumber: una.advanced(by: 10), sendNext: una.advanced(by: 40))   // slow start: 10 → 20
        #expect(control.congestionWindow == 20)
        _ = control.acknowledgeNewData(bytes: 10, ackNumber: una.advanced(by: 20), sendNext: una.advanced(by: 40))   // 100/20 = 5
        #expect(control.congestionWindow == 25)
    }

    @Test("식 3의 정수 나눗셈이 0이면 1바이트를 올린다")
    func congestionAvoidanceGrowsByOneByte() {
        var control = control(mss: 10)
        control.retransmissionTimerExpired(sendUnacknowledged: una, sendNext: una.advanced(by: 40))   // ssthresh 20, cwnd 10
        var ack = una
        let sendNext = una.advanced(by: 10_000)
        func ackOnce() {
            ack = ack.advanced(by: 10)
            _ = control.acknowledgeNewData(bytes: 10, ackNumber: ack, sendNext: sendNext)
        }
        while control.congestionWindow <= 100 { ackOnce() }   // SMSS² = 100
        let before = control.congestionWindow
        #expect(before > 100)
        ackOnce()
        #expect(control.congestionWindow == before + 1)   // 100/101 = 0 → 1
    }

    @Test("새로 확인된 바이트가 0 이하면 아무것도 바꾸지 않는다")
    func nonPositiveAcknowledgement() {
        var control = control()
        let original = control
        #expect(control.acknowledgeNewData(bytes: 0, ackNumber: una, sendNext: una) == .none)
        #expect(control.acknowledgeNewData(bytes: -1, ackNumber: una, sendNext: una) == .none)
        #expect(control == original)
    }

    // MARK: RTO 만료(RFC 5681 3.1 식 4, 6582 3.2 4)

    @Test("처음 만료: ssthresh = max(FlightSize/2, 2·SMSS), cwnd = 1 세그먼트")
    func firstTimeout() {
        var control = control()
        control.retransmissionTimerExpired(sendUnacknowledged: una, sendNext: una.advanced(by: 100_000))
        #expect(control.slowStartThreshold == 50_000)
        #expect(control.congestionWindow == 1_220)
    }

    @Test("FlightSize/2가 2·SMSS보다 작으면 2·SMSS가 ssthresh다")
    func timeoutWithSmallFlight() {
        var control = control()
        control.retransmissionTimerExpired(sendUnacknowledged: una, sendNext: una.advanced(by: 1_000))
        #expect(control.slowStartThreshold == 2_440)
        #expect(control.congestionWindow == 1_220)
    }

    @Test("같은 세그먼트에서 되풀이되는 만료는 ssthresh를 다시 줄이지 않는다")
    func repeatedTimeoutHoldsSlowStartThreshold() {
        var control = control()
        control.retransmissionTimerExpired(sendUnacknowledged: una, sendNext: una.advanced(by: 100_000))
        #expect(control.slowStartThreshold == 50_000)
        // 날아가는 양이 줄었어도(식 4면 2440) 반복 만료는 값을 지킨다
        control.retransmissionTimerExpired(sendUnacknowledged: una, sendNext: una.advanced(by: 1_000))
        control.retransmissionTimerExpired(sendUnacknowledged: una, sendNext: una.advanced(by: 1_000))
        #expect(control.slowStartThreshold == 50_000)
        #expect(control.congestionWindow == 1_220)
    }

    @Test("새 데이터가 확인된 뒤의 만료는 다른 세그먼트의 처음 만료라 식 4를 다시 쓴다")
    func timeoutAfterProgress() {
        var control = control()
        control.retransmissionTimerExpired(sendUnacknowledged: una, sendNext: una.advanced(by: 100_000))
        let progressed = una.advanced(by: 1_220)
        _ = control.acknowledgeNewData(bytes: 1_220, ackNumber: progressed, sendNext: una.advanced(by: 100_000))
        control.retransmissionTimerExpired(sendUnacknowledged: progressed, sendNext: progressed.advanced(by: 20_000))
        #expect(control.slowStartThreshold == 10_000)
        #expect(control.congestionWindow == 1_220)
    }

    @Test("fast recovery 중의 만료는 회복에서 나오고 처음 만료로 센다")
    func timeoutInsideFastRecovery() {
        var control = enteringFastRecovery()
        let sendNext = windowEnd
        #expect(control.isInFastRecovery)
        control.retransmissionTimerExpired(sendUnacknowledged: una, sendNext: sendNext)
        #expect(!control.isInFastRecovery)
        #expect(control.duplicateACKCount == 0)
        #expect(control.congestionWindow == 1_220)
        #expect(control.slowStartThreshold == 12_200)   // 식 4: 24400/2
        #expect(control.recover == sendNext)
    }

    @Test("만료 뒤의 중복 ACK 셋은 recover를 넘지 않아 fast retransmit에 들어가지 않는다(RFC 6582 4)")
    func duplicateACKsAfterTimeoutDoNotEnterFastRetransmit() {
        var control = control()
        let sendNext = sendNext(from: una, segments: 20)
        control.retransmissionTimerExpired(sendUnacknowledged: una, sendNext: sendNext)
        let ssthresh = control.slowStartThreshold
        // 불필요한 재전송 때문에 상대가 같은 번호를 거듭 확인한다. 확인 번호가 recover(= 만료 때의 SND.NXT)보다 작다.
        let ack = una.advanced(by: 5 * 1_220)
        for _ in 0..<6 {
            #expect(control.receiveDuplicateACK(ackNumber: ack, sendNext: sendNext) == .none)
        }
        #expect(!control.isInFastRecovery)
        #expect(control.slowStartThreshold == ssthresh)
        #expect(control.congestionWindow == 1_220)
    }

    // MARK: 중복 ACK 셋(RFC 5681 3.2, 6582 3.2 2)

    @Test("첫째·둘째 중복 ACK는 세고 아무것도 바꾸지 않는다")
    func firstTwoDuplicateACKs() {
        var control = control()
        let sendNext = sendNext(from: una, segments: 20)
        let original = control.congestionWindow
        #expect(control.receiveDuplicateACK(ackNumber: una, sendNext: sendNext) == .none)
        #expect(control.duplicateACKCount == 1)
        #expect(control.receiveDuplicateACK(ackNumber: una, sendNext: sendNext) == .none)
        #expect(control.duplicateACKCount == 2)
        #expect(control.congestionWindow == original)
        #expect(!control.isInFastRecovery)
    }

    @Test("셋째 중복 ACK: ssthresh는 식 4, 한 세그먼트를 다시 보내고 cwnd = ssthresh + 3·SMSS, recover = SND.NXT")
    func thirdDuplicateACK() {
        let control = enteringFastRecovery()
        let sendNext = windowEnd
        #expect(control.slowStartThreshold == 12_200)   // max(24400/2, 2440)
        #expect(control.congestionWindow == 12_200 + 3 * 1_220)
        #expect(control.isInFastRecovery)
        #expect(control.recover == sendNext)
        #expect(control.duplicateACKCount == 3)
    }

    @Test("fast recovery 중의 중복 ACK마다 cwnd += SMSS(단계 4)이고 다시 보내라고 하지 않는다")
    func additionalDuplicateACKs() {
        var control = enteringFastRecovery()
        let sendNext = windowEnd
        let entered = control.congestionWindow
        #expect(control.receiveDuplicateACK(ackNumber: una, sendNext: sendNext) == .none)
        #expect(control.congestionWindow == entered + 1_220)
        #expect(control.receiveDuplicateACK(ackNumber: una, sendNext: sendNext) == .none)
        #expect(control.congestionWindow == entered + 2 * 1_220)
        #expect(control.slowStartThreshold == 12_200)
        #expect(control.recover == sendNext)
    }

    @Test("회복 중 보낸 새 데이터가 있어도 recover는 회복을 시작할 때의 SND.NXT에 머문다")
    func recoverStaysDuringRecovery() {
        var control = enteringFastRecovery()
        let sendNext = windowEnd
        _ = control.receiveDuplicateACK(ackNumber: una, sendNext: sendNext.advanced(by: 2_440))
        #expect(control.recover == sendNext)
    }

    @Test("셋째 중복 ACK의 확인 번호가 recover 이하면 들어가지 않고 ssthresh를 바꾸지 않는다")
    func thirdDuplicateACKNotCoveringRecover() {
        var control = enteringFastRecovery()
        let sendNext = windowEnd
        // 회복을 full ACK로 끝낸다(ACK = recover). 같은 번호의 중복 ACK 셋은 recover를 넘지 못한다.
        _ = control.acknowledgeNewData(bytes: 24_400, ackNumber: sendNext, sendNext: sendNext.advanced(by: 2_440))
        #expect(!control.isInFastRecovery)
        let ssthresh = control.slowStartThreshold
        let window = control.congestionWindow
        let newNext = sendNext.advanced(by: 2_440)
        for _ in 0..<5 {
            #expect(control.receiveDuplicateACK(ackNumber: sendNext, sendNext: newNext) == .none)
        }
        #expect(!control.isInFastRecovery)
        #expect(control.slowStartThreshold == ssthresh)
        #expect(control.congestionWindow == window)
    }

    @Test("recover를 한 발 넘는 확인이 오면 다음 손실의 중복 ACK 셋이 다시 fast retransmit에 들어간다")
    func reentryAfterAdvancing() {
        var control = enteringFastRecovery()
        let sendNext = windowEnd
        let newNext = sendNext.advanced(by: 20 * 1_220)
        _ = control.acknowledgeNewData(bytes: 24_400, ackNumber: sendNext, sendNext: newNext)
        // 다음 세그먼트 하나가 확인되어 recover를 넘는다
        let ack = sendNext.advanced(by: 1_220)
        _ = control.acknowledgeNewData(bytes: 1_220, ackNumber: ack, sendNext: newNext)
        _ = control.receiveDuplicateACK(ackNumber: ack, sendNext: newNext)
        _ = control.receiveDuplicateACK(ackNumber: ack, sendNext: newNext)
        #expect(control.receiveDuplicateACK(ackNumber: ack, sendNext: newNext) == .retransmitFirstUnacknowledgedSegment)
        #expect(control.isInFastRecovery)
        #expect(control.recover == newNext)
    }

    @Test("첫 창의 첫 세그먼트가 손실돼도 중복 ACK 셋이 fast retransmit에 들어간다(recover의 초기값 = ISS)")
    func firstWindowLoss() {
        var control = control()
        let sendNext = sendNext(from: una, segments: 10)
        _ = control.receiveDuplicateACK(ackNumber: una, sendNext: sendNext)
        _ = control.receiveDuplicateACK(ackNumber: una, sendNext: sendNext)
        #expect(control.receiveDuplicateACK(ackNumber: una, sendNext: sendNext) == .retransmitFirstUnacknowledgedSegment)
        #expect(control.slowStartThreshold == 6_100)   // max(12200/2, 2440)
    }

    @Test("날아가는 양이 작으면 ssthresh는 2·SMSS다")
    func fastRetransmitWithSmallFlight() {
        var control = control()
        let sendNext = sendNext(from: una, segments: 2)
        for _ in 0..<3 { _ = control.receiveDuplicateACK(ackNumber: una, sendNext: sendNext) }
        #expect(control.slowStartThreshold == 2_440)
        #expect(control.congestionWindow == 2_440 + 3_660)
    }

    @Test("새 ACK가 오면 중복 ACK 수가 0으로 돌아가 셋을 다시 센다")
    func newACKResetsDuplicateCount() {
        var control = control()
        let sendNext = sendNext(from: una, segments: 20)
        _ = control.receiveDuplicateACK(ackNumber: una, sendNext: sendNext)
        _ = control.receiveDuplicateACK(ackNumber: una, sendNext: sendNext)
        let ack = una.advanced(by: 1_220)
        _ = control.acknowledgeNewData(bytes: 1_220, ackNumber: ack, sendNext: sendNext)
        #expect(control.duplicateACKCount == 0)
        _ = control.receiveDuplicateACK(ackNumber: ack, sendNext: sendNext)
        #expect(control.receiveDuplicateACK(ackNumber: ack, sendNext: sendNext) == .none)
        #expect(!control.isInFastRecovery)
    }

    // MARK: full ACK와 partial ACK(RFC 6582 3.2 3)

    @Test("full ACK: cwnd = min(ssthresh, max(FlightSize, SMSS) + SMSS)로 줄이고 회복에서 나온다")
    func fullACK() {
        var control = enteringFastRecovery()
        let sendNext = windowEnd
        _ = control.receiveDuplicateACK(ackNumber: una, sendNext: sendNext)   // 더 부풀린다
        let newNext = sendNext.advanced(by: 2_440)                             // 회복 중 새 데이터 2 세그먼트
        let instruction = control.acknowledgeNewData(bytes: 24_400, ackNumber: sendNext, sendNext: newNext)
        #expect(instruction == .none)
        #expect(!control.isInFastRecovery)
        #expect(control.duplicateACKCount == 0)
        // FlightSize = 2440 → max(2440, 1220) + 1220 = 3660 < ssthresh 12200
        #expect(control.congestionWindow == 3_660)
        #expect(control.slowStartThreshold == 12_200)
    }

    @Test("full ACK에서 날아가는 양이 많으면 ssthresh가 상한이다")
    func fullACKCappedBySlowStartThreshold() {
        var control = enteringFastRecovery()
        let sendNext = windowEnd
        let newNext = sendNext.advanced(by: 100_000)
        _ = control.acknowledgeNewData(bytes: 24_400, ackNumber: sendNext, sendNext: newNext)
        #expect(control.congestionWindow == 12_200)
    }

    @Test("full ACK에서 날아가는 양이 0이면 max(FlightSize, SMSS) + SMSS = 2·SMSS")
    func fullACKWithEmptyFlight() {
        var control = enteringFastRecovery()
        let sendNext = windowEnd
        _ = control.acknowledgeNewData(bytes: 24_400, ackNumber: sendNext, sendNext: sendNext)
        #expect(control.congestionWindow == 2_440)
    }

    @Test("recover를 넘어선 확인도 full ACK다")
    func ackBeyondRecover() {
        var control = enteringFastRecovery()
        let sendNext = windowEnd
        let newNext = sendNext.advanced(by: 5_000)
        _ = control.acknowledgeNewData(bytes: 25_000, ackNumber: sendNext.advanced(by: 600), sendNext: newNext)
        #expect(!control.isInFastRecovery)
    }

    @Test("partial ACK: 첫 미확인 세그먼트를 다시 보내고, 확인된 만큼 줄이고, 1 SMSS 이상이면 SMSS를 더한다")
    func partialACK() {
        var control = enteringFastRecovery()
        let sendNext = windowEnd
        _ = control.receiveDuplicateACK(ackNumber: una, sendNext: sendNext)   // cwnd = 15860 + 1220 = 17080
        #expect(control.congestionWindow == 17_080)
        let ack = una.advanced(by: 3 * 1_220)
        let instruction = control.acknowledgeNewData(bytes: 3 * 1_220, ackNumber: ack, sendNext: sendNext)
        #expect(instruction == .retransmitFirstUnacknowledgedSegment)
        #expect(control.isInFastRecovery)
        #expect(control.congestionWindow == 17_080 - 3_660 + 1_220)
        #expect(control.slowStartThreshold == 12_200)
        #expect(control.recover == sendNext)
    }

    @Test("1 SMSS보다 적게 확인한 partial ACK는 줄이기만 하고 SMSS를 더하지 않는다")
    func partialACKBelowOneSegment() {
        var control = enteringFastRecovery()
        let sendNext = windowEnd
        let before = control.congestionWindow   // 15860
        let instruction = control.acknowledgeNewData(bytes: 500, ackNumber: una.advanced(by: 500), sendNext: sendNext)
        #expect(instruction == .retransmitFirstUnacknowledgedSegment)
        #expect(control.congestionWindow == before - 500)
    }

    @Test("partial ACK 뒤에도 회복은 계속되고 중복 ACK는 단계 4로 cwnd를 부풀린다")
    func duplicateACKAfterPartialACK() {
        var control = enteringFastRecovery()
        let sendNext = windowEnd
        let ack = una.advanced(by: 1_220)
        _ = control.acknowledgeNewData(bytes: 1_220, ackNumber: ack, sendNext: sendNext)
        #expect(control.duplicateACKCount == 0)
        let before = control.congestionWindow
        #expect(control.receiveDuplicateACK(ackNumber: ack, sendNext: sendNext) == .none)
        #expect(control.congestionWindow == before + 1_220)
        #expect(control.isInFastRecovery)
        #expect(control.slowStartThreshold == 12_200)   // 다시 줄이지 않는다
    }

    @Test("partial ACK가 연달아 와도 마지막에 full ACK로 나온다")
    func successivePartialACKs() {
        var control = enteringFastRecovery()
        let sendNext = windowEnd
        var ack = una
        for _ in 0..<19 {
            ack = ack.advanced(by: 1_220)
            #expect(control.acknowledgeNewData(bytes: 1_220, ackNumber: ack, sendNext: sendNext) == .retransmitFirstUnacknowledgedSegment)
            #expect(control.isInFastRecovery)
            #expect(control.congestionWindow >= 1_220)
        }
        ack = ack.advanced(by: 1_220)
        #expect(control.acknowledgeNewData(bytes: 1_220, ackNumber: ack, sendNext: sendNext) == .none)
        #expect(!control.isInFastRecovery)
    }

    @Test("partial ACK로 확인된 양이 cwnd보다 커도 cwnd는 1 세그먼트 아래로 내려가지 않는다")
    func partialACKDoesNotUnderflow() {
        var control = enteringFastRecovery()
        let sendNext = windowEnd
        _ = control.acknowledgeNewData(bytes: Int.max, ackNumber: una.advanced(by: 1_220), sendNext: sendNext)
        #expect(control.congestionWindow >= 1_220)
    }

    // MARK: 시퀀스 번호가 한 바퀴 돌 때

    @Test("ISS가 2³² 근처여도 번호가 넘어가는 곳의 fast recovery가 같다")
    func recoveryAcrossSequenceWrap() {
        let wrappingISS = SequenceNumber(0xFFFF_F000)
        var control = control(iss: wrappingISS)
        let una = wrappingISS.advanced(by: 1)
        let sendNext = una.advanced(by: 20 * 1_220)   // 0xFFFF_F001 + 24400은 한 바퀴 넘어 0x…5xxx
        #expect(sendNext.rawValue < una.rawValue)
        for _ in 0..<2 { _ = control.receiveDuplicateACK(ackNumber: una, sendNext: sendNext) }
        #expect(control.receiveDuplicateACK(ackNumber: una, sendNext: sendNext) == .retransmitFirstUnacknowledgedSegment)
        #expect(control.recover == sendNext)
        // 번호가 0을 넘은 뒤의 partial ACK와 full ACK
        let partial = una.advanced(by: 10 * 1_220)
        #expect(control.acknowledgeNewData(bytes: 10 * 1_220, ackNumber: partial, sendNext: sendNext) == .retransmitFirstUnacknowledgedSegment)
        #expect(control.isInFastRecovery)
        #expect(control.acknowledgeNewData(bytes: 10 * 1_220, ackNumber: sendNext, sendNext: sendNext) == .none)
        #expect(!control.isInFastRecovery)
    }

    @Test("손실 없이 3GiB를 보낸 뒤에도 낡은 recover 때문에 fast retransmit이 막히지 않는다")
    func staleRecoverAfterLongTransfer() {
        var control = control(iss: SequenceNumber(0))
        // 한 ACK에 1GiB씩 세 번: 확인 번호가 ISS에서 2³¹ 넘게 떨어진다. recover를 ISS에 둔 채면 비교가 뒤집힌다.
        var ack = SequenceNumber(1)
        let step: UInt32 = 1 << 30
        for _ in 0..<3 {
            ack = ack.advanced(by: step)
            _ = control.acknowledgeNewData(bytes: Int(step), ackNumber: ack, sendNext: ack.advanced(by: 10_000))
        }
        #expect(ack.distance(from: SequenceNumber(0)) < 0)   // 0xC000_0001: 부호 있는 차이로는 ISS보다 "앞"이다
        let sendNext = ack.advanced(by: 12_200)
        for _ in 0..<2 { _ = control.receiveDuplicateACK(ackNumber: ack, sendNext: sendNext) }
        #expect(control.receiveDuplicateACK(ackNumber: ack, sendNext: sendNext) == .retransmitFirstUnacknowledgedSegment)
    }

    @Test("만료 때 기록한 recover도 번호가 한 바퀴 돈 뒤에는 막지 않는다")
    func staleRecoverAfterTimeout() {
        var control = control(iss: SequenceNumber(0))
        let una = SequenceNumber(1)
        control.retransmissionTimerExpired(sendUnacknowledged: una, sendNext: una.advanced(by: 12_200))
        var ack = una
        let step: UInt32 = 1 << 30
        for _ in 0..<3 {
            ack = ack.advanced(by: step)
            _ = control.acknowledgeNewData(bytes: Int(step), ackNumber: ack, sendNext: ack.advanced(by: 10_000))
        }
        let sendNext = ack.advanced(by: 12_200)
        for _ in 0..<2 { _ = control.receiveDuplicateACK(ackNumber: ack, sendNext: sendNext) }
        #expect(control.receiveDuplicateACK(ackNumber: ack, sendNext: sendNext) == .retransmitFirstUnacknowledgedSegment)
    }

    // MARK: 유휴 뒤(RFC 5681 4.1)

    @Test("유휴가 RTO보다 길면 cwnd를 min(IW, cwnd)로 줄인다")
    func restartAfterIdle() {
        var control = afterFirstTimeout()
        var ack = una
        let sendNext = una.advanced(by: 1_000_000)
        for _ in 0..<41 {
            ack = ack.advanced(by: 1_220)
            _ = control.acknowledgeNewData(bytes: 1_220, ackNumber: ack, sendNext: sendNext)
        }
        #expect(control.congestionWindow > 12_200)
        control.restartAfterIdle(idleDuration: .milliseconds(301), retransmissionTimeout: .milliseconds(300))
        #expect(control.congestionWindow == 12_200)
        #expect(control.slowStartThreshold == 50_000)   // ssthresh는 건드리지 않는다
    }

    @Test("유휴가 RTO 이하이면 그대로 둔다")
    func notIdleLongEnough() {
        var control = control()
        let sendNext = sendNext(from: una, segments: 20)
        _ = control.acknowledgeNewData(bytes: 1_220, ackNumber: una.advanced(by: 1_220), sendNext: sendNext)
        let before = control.congestionWindow
        control.restartAfterIdle(idleDuration: .milliseconds(300), retransmissionTimeout: .milliseconds(300))
        #expect(control.congestionWindow == before)
        control.restartAfterIdle(idleDuration: .zero, retransmissionTimeout: .milliseconds(300))
        control.restartAfterIdle(idleDuration: .milliseconds(-1), retransmissionTimeout: .milliseconds(300))
        #expect(control.congestionWindow == before)
    }

    @Test("cwnd가 이미 초기 창보다 작으면 유휴 뒤에도 키우지 않는다")
    func idleNeverGrowsWindow() {
        var control = afterFirstTimeout()   // cwnd 1220
        control.restartAfterIdle(idleDuration: .seconds(60), retransmissionTimeout: .seconds(1))
        #expect(control.congestionWindow == 1_220)
    }

    // MARK: 죽지 않음

    @Test("MSS가 범위 밖이어도 죽지 않고 1…65535로 묶는다")
    func maximumSegmentSizeIsClamped() {
        #expect(control(mss: 0).maximumSegmentSize == 1)
        #expect(control(mss: -7).maximumSegmentSize == 1)
        #expect(control(mss: Int.max).maximumSegmentSize == 65_535)
        #expect(control(mss: Int.min).maximumSegmentSize == 1)
        #expect(Control.initialWindow(maximumSegmentSize: Int.max) == 2 * 65_535)
        #expect(control(mss: 1).congestionWindow == 10)
    }

    @Test("큰 바이트 수와 어긋난 번호에도 cwnd는 상한 안이고 음수가 되지 않는다")
    func extremeInputs() {
        var control = control()
        let far = SequenceNumber(0x8000_0000)
        _ = control.acknowledgeNewData(bytes: Int.max, ackNumber: far, sendNext: una)       // SND.NXT가 ACK보다 앞
        _ = control.receiveDuplicateACK(ackNumber: far, sendNext: una)
        control.retransmissionTimerExpired(sendUnacknowledged: far, sendNext: una)
        control.restartAfterIdle(idleDuration: .seconds(Int64.max), retransmissionTimeout: .seconds(Int64.min))
        #expect(control.congestionWindow >= control.maximumSegmentSize)
        #expect(control.slowStartThreshold >= 2 * control.maximumSegmentSize)
    }

    @Test("부풀리기를 오래 해도 cwnd는 2³⁰을 넘지 않는다")
    func congestionWindowIsCapped() {
        var control = enteringFastRecovery()
        let sendNext = windowEnd
        for _ in 0..<1_000_000 { _ = control.receiveDuplicateACK(ackNumber: una, sendNext: sendNext) }
        #expect(control.congestionWindow <= 1 << 30)
        #expect(control.congestionWindow > 1 << 29)
        var growing = Control(maximumSegmentSize: 65_535, initialSequenceNumber: iss)
        var ack = una
        for _ in 0..<20_000 {
            ack = ack.advanced(by: 65_535)
            _ = growing.acknowledgeNewData(bytes: 65_535, ackNumber: ack, sendNext: ack.advanced(by: 1_000))
        }
        #expect(growing.congestionWindow <= 1 << 30)
    }
}
