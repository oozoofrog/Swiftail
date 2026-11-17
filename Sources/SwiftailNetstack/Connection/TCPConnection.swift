import SwiftailBase

/// TCP 연결 하나의 상태 기계(RFC 9293 3.3.2, 3.10).
///
/// 소켓·시계·난수가 없는 값 타입이다. 입력은 받은 세그먼트(`receive(_:at:)`), 응용의 호출(`write`·`read`·
/// `finishWriting`·`close`·`abort`), 시각(`advance(to:)`)이고, 출력은 보낼 세그먼트와 사건(`Output`)이다.
/// ISN은 인자로 받는다(스택이 RFC 6528로 만든다). 호출하는 쪽은 `nextDeadline`에 맞춰 `advance(to:)`를 부르고,
/// 시각은 호출마다 줄어들지 않아야 한다.
///
/// 만들기: 능동 열기는 `connect(from:to:initialSequenceNumber:at:)`, 수동 열기는 스택이 받은 SYN을 넘기는
/// `accept(_:initialSequenceNumber:at:)`다. LISTEN 상태는 이 타입에 없다(계약 동작 S3).
///
/// ACK는 기한으로 둔다. 순서대로 온 데이터는 40ms 뒤(또는 2×MSS가 쌓이면 지금), 순서가 어긋난 데이터·빈 곳을 메운 데이터·
/// FIN·창 밖 세그먼트는 지금이 기한이다. 기한이 지금인 ACK는 그 세그먼트를 받은 `receive`의 출력으로 곧바로 나가고(세그먼트마다
/// 하나, RFC 5681 4.2), 40ms 기한의 ACK만 `advance(to:)`에서 나간다. 그래서 묶음 안에서 합쳐지는 것은 순서대로 온 데이터의
/// ACK뿐이다(2×MSS마다 하나, MUST-58·59, 계약 동작 F5·N4). 나가는 데이터 세그먼트가 있으면 ACK는 거기에 실리고 기한은 지워진다.
///
/// 이 파일은 타입의 선언과 상태를 담는다. 여는 일·세그먼트 받기·보내기·응용 호출·타이머는 같은 이름의
/// `TCPConnection+…` 파일에 있다. 계약: `docs/contracts/SwiftailNetstack.md` 동작 T·R·F·X.
/// 노트: `docs/protocol-notes/tcp-netstack.md` 4절.
package struct TCPConnection: Sendable {
    /// 연결의 상태(RFC 9293 3.3.2). LISTEN은 스택이 맡는다.
    package enum State: Sendable, Equatable {
        /// SYN-SENT: SYN을 보내고 SYN-ACK를 기다린다.
        case synSent
        /// SYN-RECEIVED: SYN에 SYN-ACK로 답하고 ACK를 기다린다.
        case synReceived
        /// ESTABLISHED: 양쪽이 데이터를 주고받는다.
        case established
        /// FIN-WAIT-1: 이 쪽 FIN을 보냈고 확인을 기다린다.
        case finWait1
        /// FIN-WAIT-2: 이 쪽 FIN이 확인됐고 상대 FIN을 기다린다.
        case finWait2
        /// CLOSE-WAIT: 상대 FIN을 받았고 응용이 닫기를 기다린다.
        case closeWait
        /// CLOSING: 양쪽 FIN이 엇갈려 이 쪽 FIN의 확인을 기다린다.
        case closing
        /// LAST-ACK: 상대 FIN 뒤에 보낸 이 쪽 FIN의 확인을 기다린다.
        case lastAck
        /// TIME-WAIT: 먼저 닫은 쪽이 상대 FIN의 재전송에 답하며 머문다(계약 동작 T6).
        case timeWait
        /// CLOSED: 끝났다. 더 내는 것이 없다.
        case closed
    }

    /// 상태 기계가 내놓는 일. 낸 순서대로 처리해야 한다(계약 동작 S10).
    package enum Output: Sendable, Equatable {
        /// 상대에게 보낼 세그먼트. 시퀀스 순서로 나온다.
        case segment(TCPSegment)
        /// 응용이나 스택에 알릴 일.
        case event(Event)
    }

    /// 응용이나 스택에 알릴 일(계약 "구조" 1).
    package enum Event: Sendable, Equatable {
        /// 세 방향 핸드셰이크가 끝났다. 수동 열기면 스택이 이 연결을 accept 대기열에 넣는다.
        case established
        /// 읽을 바이트가 없다가 생겼다. 기다리던 `read`를 깨운다.
        case readable
        /// 보내는 버퍼가 차서 `write`가 다 받지 못한 뒤, 확인받은 만큼 자리가 났다. 기다리던 `write`를 깨운다.
        case writable
        /// 상대가 쓰기를 닫았다(FIN). 그 전에 받은 데이터는 모두 읽을 수 있다(RFC 9293 3.10.7.4 여덟째, MUST-12).
        case endOfStream
        /// 연결이 끝났다. 이 뒤로는 출력이 없다.
        case closed(CloseReason)
    }

    /// 연결이 끝난 까닭.
    package enum CloseReason: Sendable, Equatable {
        /// 양쪽 FIN이 오가고 끝났다(LAST-ACK에서 FIN이 확인됨, TIME-WAIT가 다 됨). 읽지 않은 데이터는 남는다.
        case finished
        /// 상대가 RST로 끊었다(RFC 9293 3.10.7.4 둘째). 수동 열기의 SYN-RECEIVED에서는 "LISTEN으로 돌아감"이다:
        /// 아직 `.established`를 내지 않았으므로 스택은 응용에 알리지 않고 지운다. 버퍼는 비운다.
        case reset
        /// 능동 열기가 거절됐다(SYN에 RST), 또는 상대가 광고한 MSS가 64보다 작다(계약 동작 T3, X9).
        case refused
        /// 상대가 답하지 않는다: 재전송 한도(SYN·SYN-ACK 7번, 데이터 15번), 0 창 탐침 15번, keep-alive 9번,
        /// `close` 뒤 FIN-WAIT-2의 60초(계약 동작 R4, F8, T8, T6). 응용이 `close`로 놓은 연결이 창 0에서 진전 없이 한도에
        /// 닿은 것도 여기다(상대가 답했으면 RST를 보낸다. 계약 동작 F8). 버퍼는 비운다.
        case timedOut
        /// 이 쪽이 끊었다: `abort`, 읽지 않은 데이터가 있을 때의 `close`, `close` 뒤에 온 데이터(SHLD-3). 버퍼는 비운다.
        case aborted
    }

    /// 수동 열기를 거절한 까닭.
    package enum AcceptError: Error, Sendable, Equatable {
        /// 넘긴 세그먼트가 ACK·RST 없는 SYN이 아니다. 스택의 LISTEN 규칙(TCP 노트 4.2)이 먼저 걸렀어야 한다. 아무것도 보내지 않는다.
        case notInitialSYN
        /// 상대가 광고한 MSS가 64보다 작다(계약 동작 X9). 그 SYN에 답할 RST(RFC 9293 3.10.7.1의 ACK 없는 세그먼트의 형식)를 담는다.
        case unacceptableMaximumSegmentSize(reset: TCPSegment)
    }

    // MARK: 값

    /// tailnet MTU(계약 결정 D9).
    static let maximumTransmissionUnit = 1280
    /// 자기 Window Scale shift(계약 동작 F2: `65535 << 3 >= 262144`가 되는 가장 작은 값).
    static let ownWindowShift = 3
    /// 상대의 shift 상한(RFC 7323 2.3).
    static let maximumWindowShift = 14
    /// SYN·SYN-ACK에 싣는 창. SYN의 창은 확장하지 않으므로(RFC 7323 2.2) 16비트 최댓값이다. 받는 창의 상한이 더 작으면
    /// 그 값을 싣는다(`receiveWindowLimit`).
    static let synchronizeWindow = min(Int(UInt16.max), ReceiveBuffer.defaultCapacity)
    /// 리스너의 대기열에 있는(응용이 아직 받아 가지 않은) 연결의 받는 창. 받는 버퍼는 쓴 자리까지 자라므로, 창을 다 열어 두면
    /// 받아 가기도 전에 상대가 연결마다 256KiB를 잡게 할 수 있다. 16KiB는 상대의 첫 창(RFC 6928의 10×MSS, MSS 1240에서
    /// 12,400바이트)을 담는 가장 작은 2의 거듭제곱이고, SYN-ACK의 확장하지 않는 창 필드에 그대로 실리며 자기 shift(3)의
    /// 배수다(계약 동작 M).
    static let unacceptedReceiveWindow = 16 * 1024
    /// 상대가 광고한 MSS가 이보다 작으면 연결을 맺지 않는다(계약 동작 X9).
    static let minimumPeerSegmentSize = 64
    /// SYN·SYN-ACK의 재전송 한도. 일곱 번째 재전송의 타이머가 만료되는 247초에 버린다(계약 동작 R4).
    static let synchronizeRetransmissionLimit = 7
    /// 데이터·FIN의 재전송 한도(계약 동작 R4).
    static let dataRetransmissionLimit = 15
    /// 아무 ACK도 받지 못한 0 창 탐침의 한도. 응용이 놓은 연결은 진전 없는 탐침의 한도다(계약 동작 F8).
    static let zeroWindowProbeLimit = 15
    /// 0 창 탐침 간격의 상한(계약 동작 F8).
    static let maximumZeroWindowProbeInterval = Duration.seconds(60)
    /// 지연 ACK의 기한(계약 동작 F5. RFC 9293 3.8.6.3 MUST-40은 0.5초 미만).
    static let delayedAcknowledgmentTimeout = Duration.milliseconds(40)
    /// 보내는 쪽 SWS 회피의 override 시간(계약 동작 F7. RFC 9293 3.8.6.2.1은 0.1~1초).
    static let sillyWindowOverrideTimeout = Duration.milliseconds(200)
    /// keep-alive: 유휴 2시간, 간격 75초, 9번(계약 동작 T8, gVisor 기본값). RFC 9293 3.8.4는 기본 꺼짐(MUST-25)이지만
    /// 계약 총괄 확정 N5가 늘 켜기로 정했다.
    static let keepaliveIdle = Duration.seconds(2 * 60 * 60)
    static let keepaliveInterval = Duration.seconds(75)
    static let keepaliveProbeLimit = 9
    /// TIME-WAIT(계약 동작 T6, gVisor의 값. RFC 9293의 2MSL은 4분이다).
    static let timeWaitDuration = Duration.seconds(60)
    /// FIN 재전송이 TIME-WAIT를 다시 재어도 넘지 않는 끝: 든 때부터 2MSL = 4분(RFC 9293 3.6.1 MUST-13. MSL은 같은 RFC의
    /// 용어 정의에서 2분). 스택의 TIME-WAIT 기록도 이 끝을 이어받는다.
    static let maximumTimeWaitLifetime = Duration.seconds(240)
    /// `close` 뒤 FIN-WAIT-2에 머무는 한도(계약 동작 T6, gVisor linger 기본값).
    static let finWait2Linger = Duration.seconds(60)

    // MARK: 연결

    /// 지금 상태.
    package internal(set) var state: State
    /// 이 쪽 주소와 포트.
    package let localEndpoint: IPEndpoint
    /// 상대 주소와 포트.
    package let remoteEndpoint: IPEndpoint

    // MARK: 보내는 쪽 (RFC 9293 3.3.1)

    /// ISS. SYN·SYN-ACK를 만들 때만 쓴다(맺어진 뒤에는 2³¹ 넘게 멀어질 수 있어 견주지 않는다).
    let initialSendSequence: SequenceNumber
    /// SND.UNA.
    package internal(set) var sendUnacknowledged: SequenceNumber
    /// SND.NXT. 지금까지 보낸 가장 높은 번호의 다음이다. RTO 뒤의 go-back-N에서도 되돌리지 않는다(되돌리는 것은 `transmitNext`).
    package internal(set) var sendNext: SequenceNumber
    /// 다음에 보낼 세그먼트의 첫 번호. 보통 `sendNext`와 같고, RTO가 만료되면 `sendUnacknowledged`로 돌아가
    /// 거기서부터 slow start가 허락하는 대로 다시 보낸다(계약 동작 R7). `sendNext` 앞의 구간을 보내는 것은 재전송이다.
    var transmitNext: SequenceNumber
    /// SND.WND(창 확장을 적용한 값).
    package internal(set) var sendWindow: Int
    /// 지금까지 받은 가장 큰 SND.WND. RFC 5961 5.2의 MAX.SND.WND이자 보내는 쪽 SWS 회피의 Max(SND.WND)다.
    var maximumSendWindow: Int
    /// SND.WL1·SND.WL2: 창을 마지막으로 갱신한 세그먼트의 SEQ·ACK.
    var sendWindowUpdateSequence: SequenceNumber
    var sendWindowUpdateAcknowledgment: SequenceNumber
    /// 직전에 받은 ACK의 창. 중복 ACK의 조건 "광고한 창이 직전과 같다"(RFC 5681 2)에 쓴다.
    var lastPeerWindow: Int
    /// Snd.Wind.Shift: 받은 창에 곱하는 shift(RFC 7323 2.3). 창 확장이 꺼져 있으면 0.
    var sendWindowShift = 0
    /// Eff.snd.MSS: 보내는 세그먼트의 데이터 상한(계약 동작 T5).
    package internal(set) var sendMaximumSegmentSize: Int
    /// 보내는 버퍼. SYN·FIN은 이 밖의 번호다.
    var sendBuffer: SendBuffer
    /// 응용이 쓰기를 끝냈다(`finishWriting`·`close`). FIN의 번호는 `sendBuffer.endSequence`로 굳는다.
    var finRequested = false
    /// `write`가 바이트를 다 받지 못했다. 자리가 나면 `.writable`을 낸다.
    var isWriteBlocked = false

    // MARK: 받는 쪽

    /// 이 쪽이 광고하는 MSS. 1280 − IP 머리 − 20(계약 동작 T5). 지연 ACK의 2×RMSS에도 쓴다(RFC 9293 3.8.6.3).
    let receiveMaximumSegmentSize: Int
    /// Rcv.Wind.Shift: 광고하는 창을 나누는 shift(RFC 7323 2.3). 창 확장이 꺼져 있으면 0.
    var receiveWindowShift = 0
    /// 이 쪽 SYN에 Window Scale을 실었는가. 능동 열기는 늘, 수동 열기는 상대의 SYN에 있을 때만(계약 동작 F2).
    let offersWindowScale: Bool
    /// 상대의 SYN(SYN-ACK)에 SACK-Permitted가 있었다. 이때만 ACK에 SACK 블록을 싣는다(RFC 2018 4 MUST NOT, 계약 동작 F5 아래).
    /// 이 쪽 SYN의 SACK-Permitted는 능동 열기면 늘, 수동 열기면 이 값일 때만 싣는다(계약 동작 T3·T4).
    var peerPermitsSACK = false
    /// 받는 버퍼. 상대의 데이터만 담는다(FIN은 `finReceived`).
    var receiveBuffer: ReceiveBuffer
    /// 받는 창의 상한: 읽지 않은 바이트와 광고하는 창의 합이 이것을 넘지 않는다. 보통은 받는 버퍼의 용량이고, 스택이 리스너의
    /// 대기열에 둔 연결만 `unacceptedReceiveWindow`로 시작해 응용이 받아 갈 때 연다(`openReceiveWindow(at:)`).
    var receiveWindowLimit: Int
    /// 지금까지 광고한 창의 가장 먼 오른쪽 끝. 왼쪽으로 옮기지 않고(SHLD-14), 이것을 넘는 바이트는 받지 않는다
    /// (RFC 7323 2.4 1: 보낸 어느 ACK의 창 안이었던 것은 받는다).
    var advertisedWindowEnd: SequenceNumber
    /// 상대의 FIN을 소비했다.
    var finReceived = false
    /// 빈 곳 너머에 먼저 도착한 상대 FIN의 번호. 그 앞의 데이터가 다 도착하면 소비한다(RFC 9293 3.10.7.4 SHLD-31).
    var pendingFinSequence: SequenceNumber?
    /// 응용이 `close`로 읽기를 끝냈다. 그 뒤에 온 데이터에는 RST로 답한다(SHLD-3). 0 창 탐침과 줄어든 창의 재전송은 상대가
    /// 답해도 한도에서 끝난다(계약 동작 F8).
    var readClosed = false
    /// 마지막 ACK 뒤에 순서대로 받은 바이트 수. 2×RMSS가 되면 곧바로 ACK한다(SHLD-19).
    var unacknowledgedByteCount = 0

    // MARK: 재전송과 혼잡 제어

    var retransmissionEstimator = RTOEstimator()
    var congestionControl: NewRenoCongestionControl
    /// 같은 세그먼트(또는 SYN)를 다시 보낸 횟수. `SND.UNA`가 나아가면 0이 된다.
    var retransmissionCount = 0
    /// 지금 처리하는 세그먼트의 ACK가 fast retransmit을 시켰다(중복 ACK 셋, partial ACK). 그 세그먼트의 데이터까지 받는 버퍼에
    /// 넣은 뒤에 다시 보낸다. 다시 보내는 세그먼트가 싣는 SACK의 첫 블록이 방금 받은 데이터의 구간이어야 하기 때문이다
    /// (RFC 2018 4).
    var isFastRetransmitPending = false
    /// 마지막 재전송 타이머 만료 뒤에 받아들일 수 있는 ACK를 받았다. 창이 0으로 줄었을 때 그 만료를 한도에 셀지 정한다
    /// (계약 동작 F8 아래).
    var acknowledgedSinceRetransmissionTimeout = false
    /// 왕복 시간을 재는 세그먼트(한 번에 하나, 계약 동작 R2). 재전송되면 버린다(Karn, RFC 6298 3).
    var roundTripSample: RoundTripSample?
    /// SYN·SYN-ACK를 처음 보낸 시각. 다시 보내지 않았으면 맺어질 때 왕복 시간의 첫 표본이 된다.
    let synchronizeSentAt: ContinuousClock.Instant
    /// 마지막으로 데이터를 보낸 시각(RFC 5681 4.1의 유휴 판단).
    var lastDataSentAt: ContinuousClock.Instant?
    /// 전송 통계. 연결이 끝날 때 스택이 `.closed`에 실어 낸다.
    package internal(set) var statistics: Statistics

    // MARK: 타이머

    var timers = ConnectionTimers()
    /// TIME-WAIT에 든 시각. FIN 재전송이 기한을 늘리는 끝(`maximumTimeWaitLifetime`)을 이것에서 잰다.
    var timeWaitEnteredAt: ContinuousClock.Instant?
    /// 아무 ACK도 받지 못한 채 보낸 0 창 탐침의 수. 응용이 놓은 연결(`readClosed`)은 상대가 답해도 진전(새 데이터의 확인,
    /// 열린 창)이 없으면 줄이지 않는다(계약 동작 F8).
    var zeroWindowProbeCount = 0
    /// 다음 0 창 탐침까지의 간격. 탐침마다 두 배, 상한 60초.
    var zeroWindowProbeInterval = Duration.zero
    /// 답 없이 보낸 keep-alive 탐침의 수.
    var keepaliveProbeCount = 0
    var challengeLimiter = ChallengeACKLimiter()

    /// 왕복 시간을 재는 세그먼트: `[start, end)`를 `sentAt`에 처음 보냈다.
    struct RoundTripSample: Sendable {
        var start: SequenceNumber
        var end: SequenceNumber
        var sentAt: ContinuousClock.Instant
    }

    /// 두 열기가 함께 쓰는 초기화. 상대 쪽 값(IRS, 창, MSS, shift)은 열기가 채운다.
    init(
        state: State,
        local: IPEndpoint,
        remote: IPEndpoint,
        initialSendSequence: SequenceNumber,
        initialReceiveSequence: SequenceNumber,
        offersWindowScale: Bool,
        receiveWindowLimit: Int = ReceiveBuffer.defaultCapacity,
        at now: ContinuousClock.Instant
    ) {
        self.state = state
        localEndpoint = local
        remoteEndpoint = remote
        self.initialSendSequence = initialSendSequence
        sendUnacknowledged = initialSendSequence
        sendNext = initialSendSequence.advanced(by: 1)
        transmitNext = sendNext
        sendWindow = 0
        maximumSendWindow = 0
        sendWindowUpdateSequence = initialReceiveSequence
        sendWindowUpdateAcknowledgment = initialSendSequence
        lastPeerWindow = 0
        let ownSize = Self.ownMaximumSegmentSize(for: local.address)
        receiveMaximumSegmentSize = ownSize
        sendMaximumSegmentSize = ownSize
        sendBuffer = SendBuffer(firstSequence: sendNext)
        self.offersWindowScale = offersWindowScale
        let receiveNext = initialReceiveSequence.advanced(by: 1)
        receiveBuffer = ReceiveBuffer(initialSequence: receiveNext)
        self.receiveWindowLimit = receiveWindowLimit
        advertisedWindowEnd = receiveNext.advanced(by: UInt32(min(Self.synchronizeWindow, receiveWindowLimit)))
        congestionControl = NewRenoCongestionControl(
            maximumSegmentSize: ownSize, initialSequenceNumber: initialSendSequence)
        synchronizeSentAt = now
        statistics = Statistics(openedAt: now)
    }

    // MARK: 읽을 수 있는 값

    /// RCV.NXT. 상대의 FIN을 소비했으면 그 다음 번호다.
    package var receiveNext: SequenceNumber {
        receiveBuffer.nextSequence.advanced(by: finReceived ? 1 : 0)
    }

    /// 응용이 지금 읽을 수 있는 바이트 수.
    package var readableByteCount: Int { receiveBuffer.readableCount }

    /// 보내는 버퍼의 남은 자리. `write`가 지금 받아들일 수 있는 최대치다.
    package var writableByteCount: Int { sendBuffer.freeSpace }

    /// 보내는 버퍼에 남은 바이트 수(확인받지 못한 것 + 아직 보내지 않은 것).
    package var unacknowledgedSendByteCount: Int { sendBuffer.count }

    /// 상대가 쓰기를 닫았다(FIN을 소비했다).
    package var hasReceivedEndOfStream: Bool { finReceived }

    /// 지금의 RTO.
    package var retransmissionTimeout: Duration { retransmissionEstimator.retransmissionTimeout }

    /// 지금의 cwnd.
    package var congestionWindow: Int { congestionControl.congestionWindow }

    // MARK: 도우미

    /// 자기 MTU에서 나오는 MSS: 1280 − IP 머리(IPv4 20, IPv6 40) − TCP 머리 20(계약 동작 T5, TCP 노트 7절).
    static func ownMaximumSegmentSize(for address: IPAddress) -> Int {
        maximumTransmissionUnit - (address.isIPv4 ? 20 : 40) - 20
    }

    /// 상대의 SYN에 MSS 옵션이 없을 때의 값: IPv4 536, IPv6 1220(RFC 9293 3.7.1 MUST-15).
    static func defaultPeerMaximumSegmentSize(for address: IPAddress) -> Int {
        address.isIPv4 ? 536 : 1220
    }

    /// 데이터 쪽의 FIN 번호. `finRequested`일 때만 뜻이 있다(그 뒤로 버퍼에 붙는 바이트가 없다).
    var finSequence: SequenceNumber { sendBuffer.endSequence }

    /// 이 쪽 FIN을 보냈다.
    var finSent: Bool { finRequested && sendNext == finSequence.advanced(by: 1) }

    /// 이 쪽 FIN이 확인됐다.
    var finAcknowledged: Bool { finRequested && sendUnacknowledged == finSequence.advanced(by: 1) }

    /// 확인받지 못한 번호가 있다(SYN·데이터·FIN).
    var hasOutstandingData: Bool { sendUnacknowledged != sendNext }

    /// `SND.UNA + SND.WND`: 상대가 받겠다고 한 오른쪽 끝.
    var sendWindowEnd: SequenceNumber { sendUnacknowledged.advanced(by: UInt32(clamping: sendWindow)) }

    /// 연결을 끝낸다. `.finished`가 아니면 버퍼를 비운다(RST·시간 초과·중단 뒤의 데이터는 쓸 수 없다).
    mutating func terminate(_ reason: CloseReason, into outputs: inout [Output]) {
        state = .closed
        timers.removeAll()
        roundTripSample = nil
        if reason != .finished {
            receiveBuffer = ReceiveBuffer(initialSequence: receiveBuffer.nextSequence)
        }
        sendBuffer = SendBuffer(firstSequence: sendBuffer.endSequence)
        outputs.append(.event(.closed(reason)))
    }
}
