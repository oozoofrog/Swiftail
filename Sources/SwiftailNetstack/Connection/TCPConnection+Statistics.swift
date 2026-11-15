extension TCPConnection {
    /// 연결 하나의 전송 통계. 연결이 끝날 때 스택이 `.closed` 사건에 실어 내고, 노드가 로그 한 줄로 남긴다
    /// (계약 "연결 종료 통계 로그"). 보내는 쪽 SACK 회복(M6-10b)을 열지 정하는 데 쓴다(계약 M6-10b S1).
    ///
    /// 값은 사건이 일어나는 자리에서 한 번씩 센다. 주소·포트·데이터는 담지 않는다.
    package struct Statistics: Sendable, Equatable {
        /// SYN(능동 열기) 또는 SYN-ACK(수동 열기)를 처음 보낸 시각. 수명은 끝난 시각에서 이것을 뺀 값이다.
        package let openedAt: ContinuousClock.Instant
        /// 상대 SYN에 SACK-Permitted가 있었다. 이 쪽은 능동 열기면 늘, 수동 열기면 상대가 보냈을 때만 실으므로 서로 협상했다는 뜻이다.
        package var sackPermitted = false
        /// 처음 보낸 데이터 바이트(SYN·FIN 제외).
        package var sentBytes = 0
        /// 다시 보낸 데이터 바이트(RTO 뒤의 go-back-N, fast retransmit, partial ACK). 0 창 탐침의 1바이트는 세지 않는다.
        package var retransmittedBytes = 0
        /// 데이터·FIN의 재전송 타이머가 만료된 횟수(SYN·SYN-ACK의 만료는 세지 않는다).
        package var retransmissionTimeouts = 0
        /// 중복 ACK 셋으로 fast retransmit에 들어간 횟수(RFC 5681 3.2).
        package var fastRetransmits = 0
        /// fast recovery 중의 partial ACK로 한 세그먼트를 다시 보낸 횟수(RFC 6582 3.2 3).
        package var partialAcknowledgmentRetransmits = 0
        /// 받은 중복 ACK의 수(RFC 5681 2의 정의).
        package var duplicateAcknowledgments = 0
        /// 받은 세그먼트 가운데 ACK 검사(RFC 5961 5.2)를 통과했고 SACK 옵션이 실려 있던 것의 수. 블록은 아직 쓰지 않는다(M6-10b).
        package var acknowledgmentsWithSACK = 0
        /// fast recovery 밖에서 새 데이터를 확인한 직후 cwnd의 최댓값(바이트). 회복 중의 부풀린 값은 넣지 않는다.
        package var maximumCongestionWindow = 0
        /// 손실(중복 ACK 셋, 처음 RTO 만료)로 ssthresh가 전보다 작아진 횟수.
        package var slowStartThresholdReductions = 0

        package init(openedAt: ContinuousClock.Instant) {
            self.openedAt = openedAt
        }
    }
}
