import Testing

@testable import SwiftailNetstack

/// NewReno congestion control (RFC 5681, 6582, 6928). Contract `docs/contracts/SwiftailNetstack.md` behaviors R5~R8 and test 8.
/// Expected values are calculated by hand from the RFC formulas. Sequence numbers belong to a single stream starting at `SND.UNA` = 1001.
@Suite("NewReno congestion control")
struct NewRenoCongestionControlTests {
    private typealias Control = NewRenoCongestionControl

    private let iss = SequenceNumber(1000)
    private let mss = 1220
    /// `SND.UNA` after SYN is acknowledged.
    private var una: SequenceNumber { iss.advanced(by: 1) }

    private func control(mss: Int? = nil, iss: SequenceNumber? = nil) -> Control {
        Control(maximumSegmentSize: mss ?? self.mss, initialSequenceNumber: iss ?? self.iss)
    }

    /// `SND.NXT` after sending the first window of 20 segments.
    private var windowEnd: SequenceNumber { sendNext(from: una, segments: 20) }

    /// `SND.NXT` with `segments` unacknowledged segments in flight (one segment at a time from `SND.UNA`).
    private func sendNext(from una: SequenceNumber, segments: Int, mss: Int = 1220) -> SequenceNumber {
        una.advanced(by: UInt32(segments * mss))
    }

    /// State after sending the first window of 20 and entering fast recovery on the third duplicate ACK. `recover` is `una + 20·mss`.
    private func enteringFastRecovery() -> Control {
        var control = control()
        let sendNext = windowEnd
        _ = control.receiveDuplicateACK(ackNumber: una, sendNext: sendNext)
        _ = control.receiveDuplicateACK(ackNumber: una, sendNext: sendNext)
        let instruction = control.receiveDuplicateACK(ackNumber: una, sendNext: sendNext)
        #expect(instruction == .retransmitFirstUnacknowledgedSegment)
        return control
    }

    // MARK: Initial window (RFC 6928 2, equation 1)

    @Test("The initial window is min(10·MSS, max(2·MSS, 14600))", arguments: [
        (1220, 12_200),     // IPv6 tunnel MSS: 10 segments
        (1240, 12_400),     // IPv4 tunnel MSS: 10 segments
        (536, 5_360),       // IPv4 default when the MSS option is absent
        (1460, 14_600),     // 10·MSS equals 14600
        (1500, 14_600),     // 14600 is the cap
        (7_300, 14_600),    // 2·MSS = 14600
        (10_000, 20_000),   // 2 segments when 2·MSS exceeds 14600
    ])
    func initialWindow(maximumSegmentSize: Int, expected: Int) {
        let control = control(mss: maximumSegmentSize)
        #expect(control.congestionWindow == expected)
        #expect(Control.initialWindow(maximumSegmentSize: maximumSegmentSize) == expected)
        #expect(!control.isInFastRecovery)
        #expect(control.duplicateACKCount == 0)
        #expect(control.slowStartThreshold >= 1 << 30)   // Effectively unlimited at first
    }

    // MARK: Sendable bytes (behavior R5)

    @Test("Sendable bytes are min(cwnd, SND.WND) − bytes in flight, floored at 0")
    func sendableBytes() {
        let control = control()   // cwnd 12200
        #expect(control.sendableBytes(peerWindow: 100_000, flightSize: 3_000) == 9_200)
        #expect(control.sendableBytes(peerWindow: 5_000, flightSize: 3_000) == 2_000)
        #expect(control.sendableBytes(peerWindow: 100_000, flightSize: 12_200) == 0)
        #expect(control.sendableBytes(peerWindow: 100_000, flightSize: 50_000) == 0)   // The window or cwnd shrank
        #expect(control.sendableBytes(peerWindow: 0, flightSize: 0) == 0)
        #expect(control.sendableBytes(peerWindow: -1, flightSize: 0) == 0)
        #expect(control.sendableBytes(peerWindow: 100, flightSize: -5) == 100)
        #expect(control.sendableBytes(peerWindow: Int.max, flightSize: Int.max) == 0)
        #expect(control.sendableBytes(peerWindow: Int.max, flightSize: Int.min) == 12_200)
        #expect(control.sendableBytes(peerWindow: Int.min, flightSize: Int.min) == 0)
    }

    // MARK: Slow start and congestion avoidance (equations 2·3)

    @Test("Slow start: cwnd += min(N, SMSS) for N newly acknowledged bytes (equation 2)")
    func slowStart() {
        var control = control()
        let sendNext = sendNext(from: una, segments: 20)
        _ = control.acknowledgeNewData(bytes: 1_220, ackNumber: una.advanced(by: 1_220), sendNext: sendNext)
        #expect(control.congestionWindow == 13_420)
        _ = control.acknowledgeNewData(bytes: 100, ackNumber: una.advanced(by: 1_320), sendNext: sendNext)
        #expect(control.congestionWindow == 13_520)
        // An ACK covering multiple segments still increases cwnd by at most SMSS (guards against ACK Division)
        _ = control.acknowledgeNewData(bytes: 5_000, ackNumber: una.advanced(by: 6_320), sendNext: sendNext)
        #expect(control.congestionWindow == 14_740)
    }

    /// State with cwnd = 1220 and ssthresh = 50000. Create it with one expiration (FlightSize 100000 → equation 4).
    private func afterFirstTimeout() -> Control {
        var control = control()
        control.retransmissionTimerExpired(sendUnacknowledged: una, sendNext: una.advanced(by: 100_000))
        #expect(control.congestionWindow == 1_220)
        #expect(control.slowStartThreshold == 50_000)
        return control
    }

    @Test("When cwnd exceeds ssthresh, switches to congestion avoidance and applies cwnd += SMSS²/cwnd (equation 3)")
    func congestionAvoidance() {
        var control = afterFirstTimeout()
        var ack = una
        let sendNext = una.advanced(by: 1_000_000)
        // 1220 → 2440 → … 40 acknowledgments give 1220·41 = 50020 > 50000
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

    @Test("Uses congestion avoidance when cwnd == ssthresh")
    func equalWindowUsesCongestionAvoidance() {
        var control = control(mss: 10)   // cwnd 100
        control.retransmissionTimerExpired(sendUnacknowledged: una, sendNext: una.advanced(by: 40))   // ssthresh = max(20, 20), cwnd = 10
        #expect(control.slowStartThreshold == 20)
        _ = control.acknowledgeNewData(bytes: 10, ackNumber: una.advanced(by: 10), sendNext: una.advanced(by: 40))   // slow start: 10 → 20
        #expect(control.congestionWindow == 20)
        _ = control.acknowledgeNewData(bytes: 10, ackNumber: una.advanced(by: 20), sendNext: una.advanced(by: 40))   // 100/20 = 5
        #expect(control.congestionWindow == 25)
    }

    @Test("Adds 1 byte if the integer division in equation 3 yields 0")
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

    @Test("Zero or fewer newly acknowledged bytes change nothing")
    func nonPositiveAcknowledgement() {
        var control = control()
        let original = control
        #expect(control.acknowledgeNewData(bytes: 0, ackNumber: una, sendNext: una) == .none)
        #expect(control.acknowledgeNewData(bytes: -1, ackNumber: una, sendNext: una) == .none)
        #expect(control == original)
    }

    // MARK: RTO expiration (RFC 5681 3.1 equation 4, 6582 3.2 4)

    @Test("First expiration: ssthresh = max(FlightSize/2, 2·SMSS), cwnd = 1 segment")
    func firstTimeout() {
        var control = control()
        control.retransmissionTimerExpired(sendUnacknowledged: una, sendNext: una.advanced(by: 100_000))
        #expect(control.slowStartThreshold == 50_000)
        #expect(control.congestionWindow == 1_220)
    }

    @Test("If FlightSize/2 is less than 2·SMSS, ssthresh is 2·SMSS")
    func timeoutWithSmallFlight() {
        var control = control()
        control.retransmissionTimerExpired(sendUnacknowledged: una, sendNext: una.advanced(by: 1_000))
        #expect(control.slowStartThreshold == 2_440)
        #expect(control.congestionWindow == 1_220)
    }

    @Test("Repeated expiration for the same segment does not reduce ssthresh again")
    func repeatedTimeoutHoldsSlowStartThreshold() {
        var control = control()
        control.retransmissionTimerExpired(sendUnacknowledged: una, sendNext: una.advanced(by: 100_000))
        #expect(control.slowStartThreshold == 50_000)
        // Even if fewer bytes are in flight (2440 by equation 4), repeated expiration preserves the value
        control.retransmissionTimerExpired(sendUnacknowledged: una, sendNext: una.advanced(by: 1_000))
        control.retransmissionTimerExpired(sendUnacknowledged: una, sendNext: una.advanced(by: 1_000))
        #expect(control.slowStartThreshold == 50_000)
        #expect(control.congestionWindow == 1_220)
    }

    @Test("Expiration after new data is acknowledged is the first expiration for a different segment, so applies equation 4 again")
    func timeoutAfterProgress() {
        var control = control()
        control.retransmissionTimerExpired(sendUnacknowledged: una, sendNext: una.advanced(by: 100_000))
        let progressed = una.advanced(by: 1_220)
        _ = control.acknowledgeNewData(bytes: 1_220, ackNumber: progressed, sendNext: una.advanced(by: 100_000))
        control.retransmissionTimerExpired(sendUnacknowledged: progressed, sendNext: progressed.advanced(by: 20_000))
        #expect(control.slowStartThreshold == 10_000)
        #expect(control.congestionWindow == 1_220)
    }

    @Test("Expiration during fast recovery exits recovery and counts as a first expiration")
    func timeoutInsideFastRecovery() {
        var control = enteringFastRecovery()
        let sendNext = windowEnd
        #expect(control.isInFastRecovery)
        control.retransmissionTimerExpired(sendUnacknowledged: una, sendNext: sendNext)
        #expect(!control.isInFastRecovery)
        #expect(control.duplicateACKCount == 0)
        #expect(control.congestionWindow == 1_220)
        #expect(control.slowStartThreshold == 12_200)   // Equation 4: 24400/2
        #expect(control.recover == sendNext)
    }

    @Test("Three duplicate ACKs after expiration do not pass recover, so they do not enter fast retransmit (RFC 6582 4)")
    func duplicateACKsAfterTimeoutDoNotEnterFastRetransmit() {
        var control = control()
        let sendNext = sendNext(from: una, segments: 20)
        control.retransmissionTimerExpired(sendUnacknowledged: una, sendNext: sendNext)
        let ssthresh = control.slowStartThreshold
        // Unnecessary retransmission makes the peer repeatedly acknowledge the same number. The acknowledgment is below recover (= SND.NXT at expiration).
        let ack = una.advanced(by: 5 * 1_220)
        for _ in 0..<6 {
            #expect(control.receiveDuplicateACK(ackNumber: ack, sendNext: sendNext) == .none)
        }
        #expect(!control.isInFastRecovery)
        #expect(control.slowStartThreshold == ssthresh)
        #expect(control.congestionWindow == 1_220)
    }

    // MARK: Three duplicate ACKs (RFC 5681 3.2, 6582 3.2 2)

    @Test("Counts the first and second duplicate ACKs and makes no other changes")
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

    @Test("Third duplicate ACK: ssthresh follows equation 4, one segment is retransmitted, cwnd = ssthresh + 3·SMSS, recover = SND.NXT")
    func thirdDuplicateACK() {
        let control = enteringFastRecovery()
        let sendNext = windowEnd
        #expect(control.slowStartThreshold == 12_200)   // max(24400/2, 2440)
        #expect(control.congestionWindow == 12_200 + 3 * 1_220)
        #expect(control.isInFastRecovery)
        #expect(control.recover == sendNext)
        #expect(control.duplicateACKCount == 3)
    }

    @Test("Each duplicate ACK during fast recovery applies cwnd += SMSS (step 4) and does not request retransmission")
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

    @Test("Even if new data is sent during recovery, recover stays at SND.NXT from the start of recovery")
    func recoverStaysDuringRecovery() {
        var control = enteringFastRecovery()
        let sendNext = windowEnd
        _ = control.receiveDuplicateACK(ackNumber: una, sendNext: sendNext.advanced(by: 2_440))
        #expect(control.recover == sendNext)
    }

    @Test("If the acknowledgment on the third duplicate ACK is at or below recover, skips entry and leaves ssthresh unchanged")
    func thirdDuplicateACKNotCoveringRecover() {
        var control = enteringFastRecovery()
        let sendNext = windowEnd
        // Finish recovery with a full ACK (ACK = recover). Three duplicate ACKs for the same number cannot pass recover.
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

    @Test("Once an acknowledgment advances one step past recover, three duplicate ACKs for the next loss reenter fast retransmit")
    func reentryAfterAdvancing() {
        var control = enteringFastRecovery()
        let sendNext = windowEnd
        let newNext = sendNext.advanced(by: 20 * 1_220)
        _ = control.acknowledgeNewData(bytes: 24_400, ackNumber: sendNext, sendNext: newNext)
        // One more segment is acknowledged, passing recover
        let ack = sendNext.advanced(by: 1_220)
        _ = control.acknowledgeNewData(bytes: 1_220, ackNumber: ack, sendNext: newNext)
        _ = control.receiveDuplicateACK(ackNumber: ack, sendNext: newNext)
        _ = control.receiveDuplicateACK(ackNumber: ack, sendNext: newNext)
        #expect(control.receiveDuplicateACK(ackNumber: ack, sendNext: newNext) == .retransmitFirstUnacknowledgedSegment)
        #expect(control.isInFastRecovery)
        #expect(control.recover == newNext)
    }

    @Test("Three duplicate ACKs enter fast retransmit even if the first segment of the initial window is lost (initial recover = ISS)")
    func firstWindowLoss() {
        var control = control()
        let sendNext = sendNext(from: una, segments: 10)
        _ = control.receiveDuplicateACK(ackNumber: una, sendNext: sendNext)
        _ = control.receiveDuplicateACK(ackNumber: una, sendNext: sendNext)
        #expect(control.receiveDuplicateACK(ackNumber: una, sendNext: sendNext) == .retransmitFirstUnacknowledgedSegment)
        #expect(control.slowStartThreshold == 6_100)   // max(12200/2, 2440)
    }

    @Test("With few bytes in flight, ssthresh is 2·SMSS")
    func fastRetransmitWithSmallFlight() {
        var control = control()
        let sendNext = sendNext(from: una, segments: 2)
        for _ in 0..<3 { _ = control.receiveDuplicateACK(ackNumber: una, sendNext: sendNext) }
        #expect(control.slowStartThreshold == 2_440)
        #expect(control.congestionWindow == 2_440 + 3_660)
    }

    @Test("A new ACK resets the duplicate ACK count to 0, so it counts three again")
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

    // MARK: Full ACK and partial ACK (RFC 6582 3.2 3)

    @Test("Full ACK: deflates to cwnd = min(ssthresh, max(FlightSize, SMSS) + SMSS) and exits recovery")
    func fullACK() {
        var control = enteringFastRecovery()
        let sendNext = windowEnd
        _ = control.receiveDuplicateACK(ackNumber: una, sendNext: sendNext)   // Inflate further
        let newNext = sendNext.advanced(by: 2_440)                             // 2 segments of new data during recovery
        let instruction = control.acknowledgeNewData(bytes: 24_400, ackNumber: sendNext, sendNext: newNext)
        #expect(instruction == .none)
        #expect(!control.isInFastRecovery)
        #expect(control.duplicateACKCount == 0)
        // FlightSize = 2440 → max(2440, 1220) + 1220 = 3660 < ssthresh 12200
        #expect(control.congestionWindow == 3_660)
        #expect(control.slowStartThreshold == 12_200)
    }

    @Test("On a full ACK with many bytes in flight, ssthresh is the cap")
    func fullACKCappedBySlowStartThreshold() {
        var control = enteringFastRecovery()
        let sendNext = windowEnd
        let newNext = sendNext.advanced(by: 100_000)
        _ = control.acknowledgeNewData(bytes: 24_400, ackNumber: sendNext, sendNext: newNext)
        #expect(control.congestionWindow == 12_200)
    }

    @Test("On a full ACK with 0 bytes in flight, max(FlightSize, SMSS) + SMSS = 2·SMSS")
    func fullACKWithEmptyFlight() {
        var control = enteringFastRecovery()
        let sendNext = windowEnd
        _ = control.acknowledgeNewData(bytes: 24_400, ackNumber: sendNext, sendNext: sendNext)
        #expect(control.congestionWindow == 2_440)
    }

    @Test("An acknowledgment beyond recover is also a full ACK")
    func ackBeyondRecover() {
        var control = enteringFastRecovery()
        let sendNext = windowEnd
        let newNext = sendNext.advanced(by: 5_000)
        _ = control.acknowledgeNewData(bytes: 25_000, ackNumber: sendNext.advanced(by: 600), sendNext: newNext)
        #expect(!control.isInFastRecovery)
    }

    @Test("Partial ACK: retransmits the first unacknowledged segment, deflates by the amount acknowledged, and adds SMSS if the amount is at least 1 SMSS")
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

    @Test("A partial ACK acknowledging less than 1 SMSS only deflates cwnd and does not add SMSS")
    func partialACKBelowOneSegment() {
        var control = enteringFastRecovery()
        let sendNext = windowEnd
        let before = control.congestionWindow   // 15860
        let instruction = control.acknowledgeNewData(bytes: 500, ackNumber: una.advanced(by: 500), sendNext: sendNext)
        #expect(instruction == .retransmitFirstUnacknowledgedSegment)
        #expect(control.congestionWindow == before - 500)
    }

    @Test("Recovery continues after a partial ACK, and duplicate ACKs inflate cwnd using step 4")
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
        #expect(control.slowStartThreshold == 12_200)   // Does not reduce it again
    }

    @Test("Even after consecutive partial ACKs, recovery ends on the final full ACK")
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

    @Test("cwnd stays at or above 1 segment even if the amount acknowledged by a partial ACK exceeds cwnd")
    func partialACKDoesNotUnderflow() {
        var control = enteringFastRecovery()
        let sendNext = windowEnd
        _ = control.acknowledgeNewData(bytes: Int.max, ackNumber: una.advanced(by: 1_220), sendNext: sendNext)
        #expect(control.congestionWindow >= 1_220)
    }

    // MARK: Sequence number wraparound

    @Test("Fast recovery behaves the same across sequence wraparound even if ISS is near 2³²")
    func recoveryAcrossSequenceWrap() {
        let wrappingISS = SequenceNumber(0xFFFF_F000)
        var control = control(iss: wrappingISS)
        let una = wrappingISS.advanced(by: 1)
        let sendNext = una.advanced(by: 20 * 1_220)   // 0xFFFF_F001 + 24400 wraps to 0x…5xxx
        #expect(sendNext.rawValue < una.rawValue)
        for _ in 0..<2 { _ = control.receiveDuplicateACK(ackNumber: una, sendNext: sendNext) }
        #expect(control.receiveDuplicateACK(ackNumber: una, sendNext: sendNext) == .retransmitFirstUnacknowledgedSegment)
        #expect(control.recover == sendNext)
        // Partial and full ACKs after sequence numbers cross 0
        let partial = una.advanced(by: 10 * 1_220)
        #expect(control.acknowledgeNewData(bytes: 10 * 1_220, ackNumber: partial, sendNext: sendNext) == .retransmitFirstUnacknowledgedSegment)
        #expect(control.isInFastRecovery)
        #expect(control.acknowledgeNewData(bytes: 10 * 1_220, ackNumber: sendNext, sendNext: sendNext) == .none)
        #expect(!control.isInFastRecovery)
    }

    @Test("Even after sending 3GiB without loss, a stale recover does not block fast retransmit")
    func staleRecoverAfterLongTransfer() {
        var control = control(iss: SequenceNumber(0))
        // Three ACKs of 1GiB each: the acknowledgment moves more than 2³¹ away from ISS. If recover stays at ISS, the comparison reverses.
        var ack = SequenceNumber(1)
        let step: UInt32 = 1 << 30
        for _ in 0..<3 {
            ack = ack.advanced(by: step)
            _ = control.acknowledgeNewData(bytes: Int(step), ackNumber: ack, sendNext: ack.advanced(by: 10_000))
        }
        #expect(ack.distance(from: SequenceNumber(0)) < 0)   // 0xC000_0001: by signed difference, it is "before" ISS
        let sendNext = ack.advanced(by: 12_200)
        for _ in 0..<2 { _ = control.receiveDuplicateACK(ackNumber: ack, sendNext: sendNext) }
        #expect(control.receiveDuplicateACK(ackNumber: ack, sendNext: sendNext) == .retransmitFirstUnacknowledgedSegment)
    }

    @Test("recover recorded at expiration also does not block after sequence numbers wrap")
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

    // MARK: After idle (RFC 5681 4.1)

    @Test("Reduces cwnd to min(IW, cwnd) if idle longer than RTO")
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
        #expect(control.slowStartThreshold == 50_000)   // Does not change ssthresh
    }

    @Test("Leaves cwnd unchanged if idle for at most RTO")
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

    @Test("If cwnd is already below the initial window, does not increase it after idle")
    func idleNeverGrowsWindow() {
        var control = afterFirstTimeout()   // cwnd 1220
        control.restartAfterIdle(idleDuration: .seconds(60), retransmissionTimeout: .seconds(1))
        #expect(control.congestionWindow == 1_220)
    }

    // MARK: Crash resistance

    @Test("Handles out-of-range MSS without crashing and clamps it to 1…65535")
    func maximumSegmentSizeIsClamped() {
        #expect(control(mss: 0).maximumSegmentSize == 1)
        #expect(control(mss: -7).maximumSegmentSize == 1)
        #expect(control(mss: Int.max).maximumSegmentSize == 65_535)
        #expect(control(mss: Int.min).maximumSegmentSize == 1)
        #expect(Control.initialWindow(maximumSegmentSize: Int.max) == 2 * 65_535)
        #expect(control(mss: 1).congestionWindow == 10)
    }

    @Test("Even with large byte counts and misordered sequence numbers, cwnd stays within the limit and never goes negative")
    func extremeInputs() {
        var control = control()
        let far = SequenceNumber(0x8000_0000)
        _ = control.acknowledgeNewData(bytes: Int.max, ackNumber: far, sendNext: una)       // SND.NXT precedes the ACK
        _ = control.receiveDuplicateACK(ackNumber: far, sendNext: una)
        control.retransmissionTimerExpired(sendUnacknowledged: far, sendNext: una)
        control.restartAfterIdle(idleDuration: .seconds(Int64.max), retransmissionTimeout: .seconds(Int64.min))
        #expect(control.congestionWindow >= control.maximumSegmentSize)
        #expect(control.slowStartThreshold >= 2 * control.maximumSegmentSize)
    }

    @Test("cwnd stays within 2³⁰ even after prolonged inflation")
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
