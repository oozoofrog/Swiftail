# TCP와 프로세스 내 netstack 노트

- 기준: `tailscale.com v1.104.6`, `gvisor.dev/gvisor v0.0.0-20260915211658-a6f909f08a72`(`tailscale.com/go.mod:156`이 고정한 버전), RFC 9293·6298·5681·6582·7323·2018·5961·6528·6928(rfc-editor.org의 원문을 2026-11-15에 받아 읽음)
- 작성: Claude Fable 5.2, 2026-11-15
- 검증: 아직 안 됨(M6 시작 전에 다른 세션이 Go 소스·RFC와 대조한다)

## 1. 범위

M6(`docs/contracts/SwiftailNetstack.md`)의 Swift TCP를 구현하는 데 필요한 사실만 적는다.

다루는 것: TCP 머리와 옵션의 형식, 상태 기계와 세그먼트 처리 순서, 재전송 타이머, 창과 흐름 제어, 혼잡 제어, 옵션마다 상호 운용에 필수인지, Tailscale이 gVisor를 어떻게 설정해 쓰는지, tailnet 경로의 MTU와 MSS, tsnet `Listen`·`Dial`의 동작, 첫 사용처가 쓰는 범위.

다루지 않는 것: UDP·ICMP 소켓, IP 단편화 재조립, ECN, TCP Fast Open, MPTCP, 서브넷 라우터의 TCP 전달(`forwardTCP`), Funnel·Serve, gVisor의 내부 구조(디스패처, 세그먼트 큐, 잠금).

## 2. 근거 표기

- Go 소스는 모듈 루트 기준 상대 경로와 줄 번호다. `netstack.go`는 `tailscale.com/wgengine/netstack/netstack.go`, `tsnet.go`는 `tailscale.com/tsnet/tsnet.go`, `gvisor/…`는 `gvisor.dev/gvisor@v0.0.0-20260915211658-a6f909f08a72/pkg/tcpip/…`다.
- RFC는 번호와 절(예: RFC 9293 3.10.7.4)이고, 요구 사항 번호가 있으면 함께 적는다(MUST-14).
- "관찰"이라고 적지 않은 문장은 모두 소스나 RFC에서 읽은 것이다. 읽지 못한 것은 11절에 모았다.

## 3. 와이어 형식

### 3.1 TCP 머리 (RFC 9293 3.1)

| 오프셋 | 길이 | 필드 | 인코딩 |
| --- | --- | --- | --- |
| 0 | 2 | source port | 빅엔디언 |
| 2 | 2 | destination port | 빅엔디언 |
| 4 | 4 | sequence number(SEG.SEQ) | 빅엔디언, 2^32 순환 |
| 8 | 4 | acknowledgment number(SEG.ACK) | ACK 비트가 켜졌을 때만 뜻이 있다 |
| 12 | 1 | 위 4비트 data offset(32비트 낱말 수, 5…15), 아래 4비트 예약 | |
| 13 | 1 | 제어 비트: CWR 0x80, ECE 0x40, URG 0x20, ACK 0x10, PSH 0x08, RST 0x04, SYN 0x02, FIN 0x01 | |
| 14 | 2 | window(SEG.WND) | 빅엔디언. SYN이 아닌 세그먼트는 창 확장 shift를 곱해 읽는다(4.6) |
| 16 | 2 | checksum | 의사 머리 + TCP 머리 + 데이터의 인터넷 체크섬 |
| 18 | 2 | urgent pointer | URG일 때만 |
| 20 | 0…40 | options | data offset이 가리키는 곳까지. 남는 자리는 0으로 채운다(MUST-69) |

- SEG.LEN은 데이터 바이트 수에 SYN과 FIN을 1씩 더한 값이다(RFC 9293 3.4).
- 체크섬의 의사 머리는 IPv4가 출발 주소·목적 주소·0·프로토콜 6·TCP 길이(16비트), IPv6가 출발 주소·목적 주소·길이(32비트)·0 셋·next header 6이다(RFC 9293 3.1, RFC 8200 8.1). 저장소의 `Sources/SwiftailEngine/Tunnel/ServiceIPReply+Checksum.swift`가 같은 계산을 이미 한다.
- Tailscale은 netstack에 넣기 전에 IPv4·TCP·UDP 체크섬을 검사한다(`tailscale.com/wgengine/netstack/gro/gro.go:22-31`, `link_endpoint.go:319-323`). gVisor는 체크섬이 틀린 SYN을 받지 않는다(`gvisor/transport/tcp/forwarder.go:74`). **Swiftail이 내는 체크섬은 정확해야 한다.**

### 3.2 옵션

| Kind | 길이 | 이름 | 형식 | 근거 |
| --- | --- | --- | --- | --- |
| 0 | 1 | End of Option List | 뒤는 읽지 않는다 | RFC 9293 3.2 |
| 1 | 1 | No-Operation | 정렬용. 낱말 경계에 맞지 않아도 읽어야 한다(MUST-64) | RFC 9293 3.2 |
| 2 | 4 | Maximum Segment Size | 16비트 MSS. SYN에만 | RFC 9293 3.2, 3.7.1 |
| 3 | 3 | Window Scale | shift.cnt 1바이트. SYN에만 | RFC 7323 2.2 |
| 4 | 2 | SACK-Permitted | SYN에만 | RFC 2018 2 |
| 5 | 가변 | SACK | 블록마다 왼쪽·오른쪽 끝 32비트 둘 | RFC 2018 3 |
| 8 | 10 | Timestamps | TSval·TSecr 32비트 둘 | RFC 7323 3.2 |

- 모르는 옵션은 길이 필드로 건너뛴다(MUST-6). EOL·NOP 밖의 옵션은 모두 길이 필드가 있다(MUST-68). 길이가 0이거나 머리 밖으로 나가는 옵션에 대비해야 한다(MUST-7. 권고 절차는 연결을 reset하는 것).
- 어떤 세그먼트에도 옵션이 올 수 있다(MUST-5).

## 4. 절차와 상태 기계

### 4.1 상태와 변수 (RFC 9293 3.3.1, 3.3.2)

상태: LISTEN, SYN-SENT, SYN-RECEIVED, ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT, CLOSED.

보내는 쪽: SND.UNA(가장 오래된 미확인), SND.NXT(다음에 보낼 번호), SND.WND(상대가 준 창), SND.WL1·SND.WL2(창을 마지막으로 갱신한 세그먼트의 SEQ·ACK), ISS. 받는 쪽: RCV.NXT, RCV.WND, IRS.

시퀀스 번호의 비교는 모두 2^32 순환 산술이다(RFC 9293 3.4).

### 4.2 세그먼트 도착 처리 (RFC 9293 3.10.7)

**연결이 없을 때(CLOSED, 3.10.7.1)**: RST가 켜진 세그먼트는 버린다. 아니면 RST로 답한다. ACK가 꺼져 있으면 `<SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>`, 켜져 있으면 `<SEQ=SEG.ACK><CTL=RST>`. gVisor도 같다(`gvisor/transport/tcp/protocol.go:185-200`, `replyWithReset` `:223`).

**LISTEN(3.10.7.2)**, 차례대로: ① RST는 무시. ② ACK가 켜져 있으면 `<SEQ=SEG.ACK><CTL=RST>`. ③ SYN이면 RCV.NXT = SEG.SEQ+1, IRS = SEG.SEQ, ISS를 골라 `<SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>`, SND.NXT = ISS+1, SND.UNA = ISS, SYN-RECEIVED로. ④ 그 밖은 버린다.

**SYN-SENT(3.10.7.3)**, 차례대로:

1. ACK가 켜져 있고 `SEG.ACK =< ISS` 또는 `SEG.ACK > SND.NXT`면 `<SEQ=SEG.ACK><CTL=RST>`를 보내고(RST가 켜진 세그먼트면 보내지 않고) 버린다.
2. RST가 켜져 있으면: ACK가 받아들일 만했으면 "connection reset"을 알리고 CLOSED. ACK가 없으면 버린다.
3. SYN이 켜져 있으면 RCV.NXT = SEG.SEQ+1, IRS = SEG.SEQ, ACK가 있으면 SND.UNA = SEG.ACK. `SND.UNA > ISS`면 ESTABLISHED로 가고 `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>`를 보낸다. 아니면(동시 열기) SYN-RECEIVED로 가고 `<SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>`를 보낸다.
4. SYN도 RST도 없으면 버린다.

gVisor는 2에서 Linux처럼 "connection refused"를 돌려준다(`gvisor/transport/tcp/connect.go:289-301`).

**그 밖의 상태(3.10.7.4)**, 차례대로:

1. **시퀀스 검사.** 받아들일 조건(표 6):

   | SEG.LEN | RCV.WND | 조건 |
   | --- | --- | --- |
   | 0 | 0 | SEG.SEQ = RCV.NXT |
   | 0 | >0 | RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND |
   | >0 | 0 | 받지 않는다 |
   | >0 | >0 | 첫 바이트나 마지막 바이트가 창 안 |

   받지 않는 세그먼트에는 `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>`를 보내고 버린다(RST가 켜져 있으면 보내지 않는다). 창이 0이어도 유효한 ACK·RST는 처리한다. 창 밖으로 걸친 부분은 잘라 내고, RCV.NXT보다 뒤에서 시작하는 세그먼트는 뒤에 처리하도록 둔다(SHLD-31). 한꺼번에 처리하는 세그먼트들의 ACK는 모아서 한 번 보낸다(MUST-58, MUST-59).
2. **RST**(RFC 5961 3.2를 따르는 구현): 창 밖이면 조용히 버린다. SEG.SEQ = RCV.NXT면 연결을 끊는다. 창 안이지만 RCV.NXT와 다르면 challenge ACK `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>`를 보내고 버린다. 끊을 때: SYN-RECEIVED에서 수동 열기였으면 LISTEN으로 조용히 돌아가고, 능동 열기였으면 "connection refused". ESTABLISHED·FIN-WAIT-1·FIN-WAIT-2·CLOSE-WAIT는 "connection reset"을 알리고 CLOSED. CLOSING·LAST-ACK·TIME-WAIT는 CLOSED.
3. (보안 검사는 쓰지 않는다.)
4. **SYN**: SYN-RECEIVED에서 수동 열기였으면 LISTEN으로 돌아간다. 동기화된 상태에서는 시퀀스 번호와 상관없이 challenge ACK를 보내고 버린다(RFC 5961 4.2. gVisor `connect.go:1337-1359`).
5. **ACK**: ACK가 꺼져 있으면 버린다. RFC 5961 5.2를 따르면 `SND.UNA - MAX.SND.WND =< SEG.ACK =< SND.NXT`가 아닌 세그먼트는 버리고 ACK를 보낸다(MAY-12).
   - SYN-RECEIVED: `SND.UNA < SEG.ACK =< SND.NXT`면 ESTABLISHED로 가고 SND.WND·WL1·WL2를 이 세그먼트로 채운다. 아니면 `<SEQ=SEG.ACK><CTL=RST>`.
   - ESTABLISHED: `SND.UNA < SEG.ACK =< SND.NXT`면 SND.UNA = SEG.ACK, 재전송 큐에서 확인된 것을 지운다. `SEG.ACK =< SND.UNA`는 중복이다. `SEG.ACK > SND.NXT`면 ACK를 보내고 버린다. 창 갱신: `SND.WL1 < SEG.SEQ` 또는 (`SND.WL1 = SEG.SEQ` 그리고 `SND.WL2 =< SEG.ACK`)일 때만 SND.WND = SEG.WND, WL1 = SEG.SEQ, WL2 = SEG.ACK.
   - FIN-WAIT-1: 위에 더해 우리 FIN이 확인되면 FIN-WAIT-2. CLOSING: 우리 FIN이 확인되면 TIME-WAIT. LAST-ACK: 우리 FIN이 확인되면 CLOSED. TIME-WAIT: 상대 FIN의 재전송이면 ACK하고 2MSL을 다시 잰다.
6. URG(쓰지 않는다. 9절).
7. **데이터**: ESTABLISHED·FIN-WAIT-1·FIN-WAIT-2에서만 받는다. RCV.NXT를 올리고 `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>`를 보낸다(지연 ACK는 4.6). RCV.NXT+RCV.WND는 줄이지 않는다. 그 밖의 상태에서는 데이터를 무시한다.
8. **FIN**: RCV.NXT를 FIN 너머로 올리고 ACK한다. SYN-RECEIVED·ESTABLISHED → CLOSE-WAIT. FIN-WAIT-1 → 우리 FIN이 확인됐으면 TIME-WAIT, 아니면 CLOSING. FIN-WAIT-2 → TIME-WAIT. TIME-WAIT → 2MSL을 다시 잰다.

gVisor의 순서도 같다: RST → SYN → ACK가 있는 세그먼트의 수신 처리 → 송신 쪽 ACK 처리(`gvisor/transport/tcp/connect.go:1328-1395`). 창 밖 세그먼트에는 데이터가 있을 때는 늘, 없을 때는 속도 제한 안에서 ACK를 보낸다(`rcv.go:465-468`, `snd.go:1885-1891`).

### 4.3 연결 맺기와 ISN

1. 3-way handshake는 4.2의 LISTEN·SYN-SENT·SYN-RECEIVED 규칙 그대로다(RFC 9293 3.5).
2. ISN은 시계로 움직여야 하고(MUST-8) `ISN = M + F(localip, localport, remoteip, remoteport, secretkey)`를 써야 한다(SHLD-1, RFC 6528 3). M은 4마이크로초마다 1씩 느는 값, F는 밖에서 계산할 수 없는 함수다(MUST-9). gVisor는 스택마다 16바이트 비밀을 뽑고(`gvisor/transport/tcp/protocol.go:588-597`의 `seqnumSecret`) SHA-256(비밀 ‖ 주소 ‖ 포트)에 64ns 단위 시계를 더한다(`connect.go:226-250`).
3. SYN 재전송: 처음 RTO는 1초다(RFC 6298 2.1. gVisor `InitialRTO`, `connect.go:41`). 만료마다 두 배로 늘린다(RFC 6298 5.5). gVisor의 재시도 횟수 기본값은 6이다(`protocol.go:68`, `:617`). RFC는 SYN의 R2를 3분 이상으로 두라고 한다(MUST-23). SYN의 재전송 타이머가 만료된 적이 있고 RTO가 3초보다 작으면 데이터 전송을 시작할 때 RTO를 3초로 다시 잡는다(RFC 6298 5.7).
4. 여는 쪽이 받는 RST는 "거절"이다(4.2 SYN-SENT 2).

### 4.4 닫기 (RFC 9293 3.6)

- FIN은 시퀀스 번호 하나를 쓴다. 보낸 FIN이 확인되고 상대의 FIN을 받아 ACK해야 양쪽이 닫힌다.
- 두 방향은 따로 닫힌다. 한쪽만 닫은 상태에서 열린 방향으로 계속 보낼 수 있다(3.6.1).
- 닫은 뒤에 읽지 않은 데이터가 남았거나 새 데이터가 오면 RST를 보내 데이터가 사라졌음을 알리는 것이 권고다(SHLD-3).
- 먼저 닫은 쪽은 TIME-WAIT에서 2×MSL 동안 머문다(MUST-13). gVisor의 TIME-WAIT 기본값은 60초(`protocol.go:64`), FIN-WAIT-2에서 상대 FIN을 기다리는 한도(linger)의 기본값도 60초다(`protocol.go:56`).
- 상대가 FIN으로 닫았는지 RST로 끊었는지를 응용에 구분해 알려야 한다(MUST-12).

### 4.5 재전송 타이머 (RFC 6298, RFC 9293 3.8.1 MUST-18)

1. RTT를 재기 전의 RTO는 1초(2.1).
2. 첫 측정 R: `SRTT = R`, `RTTVAR = R/2`, `RTO = SRTT + max(G, 4*RTTVAR)`(2.2).
3. 그 뒤 측정 R': `RTTVAR = 3/4*RTTVAR + 1/4*|SRTT - R'|`, `SRTT = 7/8*SRTT + 1/8*R'`(이 순서로), `RTO = SRTT + max(G, 4*RTTVAR)`(2.3).
4. 1초보다 작으면 1초로 올리는 것이 SHOULD다(2.4). 상한을 둔다면 60초 이상(2.5). **gVisor는 하한 200ms, 상한 120초를 쓴다**(`gvisor/transport/tcp/snd.go:32`, `:35`).
5. 재전송한 세그먼트로는 RTT를 재지 않는다(Karn, 3절). 타임스탬프 옵션을 쓰면 잴 수 있다(RFC 7323 4).
6. 타이머 관리(5절): 데이터를 보낼 때 타이머가 꺼져 있으면 RTO로 켠다(5.1). 모두 확인되면 끈다(5.2). 새 데이터를 확인하는 ACK를 받으면 지금 RTO로 다시 켠다(5.3). 만료되면 가장 오래된 미확인 세그먼트를 다시 보내고(5.4) RTO를 두 배로 하고(5.5) 다시 켠다(5.6).
7. 같은 세그먼트의 재전송이 R2에 이르면 연결을 닫는다. R2는 100초 이상이 SHOULD다(RFC 9293 3.8.3 MUST-20, SHLD-11). gVisor는 15번이다(`snd.go:50`, `protocol.go:620`).

### 4.6 창과 흐름 제어

1. 받는 쪽은 창의 오른쪽 끝(RCV.NXT+RCV.WND)을 왼쪽으로 옮기지 않는다(SHLD-14). 보내는 쪽은 상대가 그렇게 해도 견뎌야 한다(MUST-34).
2. **0 창 탐침**: 상대의 창이 0이면 주기적으로 탐침해야 한다(MUST-36). 첫 탐침은 창이 RTO만큼 0이었을 때, 간격은 지수로 늘린다(SHLD-29, SHLD-30). 상대가 탐침에 ACK하는 한 연결을 유지한다(MUST-37).
3. **SWS 회피**: 보내는 쪽(MUST-38)은 `U = SND.UNA + SND.WND - SND.NXT`, 보낼 데이터 D에 대해 ① `min(D,U) >= Eff.snd.MSS`이거나 ② 밀린 데이터를 모두 보낼 수 있거나(`D <= U`) ③ `min(D,U) >= Max(SND.WND)/2`이거나 ④ 덮어쓰기 타이머(0.1~1초)가 만료되면 보낸다(3.8.6.2.1). 받는 쪽(MUST-39)은 `RCV.BUFF - RCV.USER - RCV.WND >= min(RCV.BUFF/2, Eff.snd.MSS)`가 될 때까지 창의 오른쪽 끝을 올리지 않는다(3.8.6.2.2).
4. **지연 ACK**(3.8.6.3, RFC 5681 4.2): 구현이 SHOULD이고(SHLD-18), 미루는 시간은 0.5초 미만이어야 하고(MUST-40), 꽉 찬 세그먼트 둘마다 적어도 한 번 ACK하는 것이 SHOULD다(SHLD-19). 순서가 어긋난 세그먼트와 빈 곳을 메우는 세그먼트에는 곧바로 ACK한다(RFC 5681 4.2). 세그먼트 하나에 ACK를 둘 이상 내지 않는다(창 갱신은 예외, RFC 5681 4.2).
5. **창 확장**(RFC 7323 2.3): SYN에 Window Scale 옵션이 왔을 때만 SYN-ACK에 싣는다. 양쪽 SYN에 다 있어야 켜지고, 아니면 두 shift 모두 0이다. SYN의 창 필드는 확장하지 않는다. 그 밖의 세그먼트는 받을 때 `SND.WND = SEG.WND << Snd.Wind.Shift`, 보낼 때 `SEG.WND = RCV.WND >> Rcv.Wind.Shift`. shift는 14까지다. gVisor는 받는 버퍼 크기에서 shift를 고른다(`connect.go:199-212`: 창이 65,536 미만이면 0, 아니면 `65535 << s`가 창 이상이 되는 가장 작은 s).
6. Nagle은 SHOULD이고(SHLD-7) 끌 수 있어야 한다(MUST-17, RFC 9293 3.7.4).
7. keep-alive는 선택이다(MAY-5). 넣는다면 연결마다 켜고 끌 수 있어야 하고(MUST-24) 기본은 꺼짐이며(MUST-25) 유휴 간격의 기본은 2시간 이상이다(MUST-28). 탐침은 `SEG.SEQ = SND.NXT-1`인 세그먼트다(3.8.4). 탐침 하나에 답이 없다고 죽었다고 보지 않는다(MUST-29).

### 4.7 혼잡 제어 (RFC 5681, RFC 6582)

필수는 slow start, congestion avoidance, RTO의 지수 물러나기다(RFC 9293 3.8.2 MUST-19).

1. 변수: cwnd, ssthresh. 보낼 수 있는 양은 `min(cwnd, SND.WND)`다(RFC 5681 3.1).
2. 초기 창: RFC 5681 3.1은 SMSS에 따라 2~4 세그먼트, RFC 6928(실험)은 `min(10*MSS, max(2*MSS, 14600))`이다. gVisor는 10 세그먼트다(`snd.go:41`).
3. slow start(`cwnd < ssthresh`): 새 데이터를 확인하는 ACK마다 `cwnd += min(N, SMSS)`(N은 새로 확인된 바이트, 식 2). congestion avoidance: `cwnd += SMSS*SMSS/cwnd`(식 3).
4. 손실을 감지하면 `ssthresh = max(FlightSize/2, 2*SMSS)`(식 4). RTO로 감지했으면 cwnd를 1 세그먼트(loss window)로 한다.
5. fast retransmit·fast recovery(RFC 5681 3.2): 중복 ACK 셋째에서 ssthresh를 식 4로 잡고(단계 2), SND.UNA의 세그먼트를 다시 보내고 `cwnd = ssthresh + 3*SMSS`(단계 3), 중복 ACK가 더 올 때마다 `cwnd += SMSS`(단계 4), 창이 허락하면 새 데이터를 보낸다(단계 5), 새 데이터를 확인하는 ACK가 오면 `cwnd = ssthresh`(단계 6).
6. NewReno(RFC 6582 3.2): 변수 `recover`를 ISS로 시작한다. 중복 ACK 셋째에서 `SEG.ACK - 1 > recover`일 때만 fast retransmit에 들어가고 `recover = 지금까지 보낸 가장 높은 번호`로 둔다. 회복 중의 ACK가 recover까지 모두 확인하면(full ACK) `cwnd = min(ssthresh, max(FlightSize, SMSS) + SMSS)` 또는 ssthresh로 하고 나온다. 아니면(partial ACK) 첫 미확인 세그먼트를 다시 보내고, cwnd를 새로 확인된 만큼 줄이고, 1 SMSS 이상 확인됐으면 SMSS를 더하고, 회복을 계속한다. 첫 partial ACK에서는 재전송 타이머를 다시 켠다. RTO가 만료되면 recover에 가장 높은 번호를 적고 회복에서 나온다.
7. 중복 ACK의 정의(RFC 5681 2): 미확인 데이터가 있고, 데이터가 없고, SYN·FIN이 없고, ACK 번호가 지금까지의 최댓값과 같고, 광고한 창이 직전 ACK와 같다.
8. 유휴가 RTO보다 길었으면 cwnd를 `min(IW, cwnd)` 이하로 줄이는 것이 SHOULD다(RFC 5681 4.1).

### 4.8 옵션과 기능: 상호 운용에 필수인가

| 기능 | 규격의 요구 | 빼면 | gVisor(Tailscale 설정) |
| --- | --- | --- | --- |
| MSS 옵션 보내기·받기 | 필수(MUST-14). 못 받으면 IPv4 536, IPv6 1220으로 본다(MUST-15) | 상대가 536바이트로 보낸다 | 보낸다(`connect.go:584-590`의 `MSS: h.ep.amss`) |
| 체크섬 | 필수 | 상대가 버린다(3.1) | 검사한다 |
| 창 확장 | 선택(RFC 7323). 한쪽이 안 보내면 꺼진다 | 창이 65,535바이트로 묶인다 | 보낸다(`connect.go:585`) |
| SACK | 선택(RFC 2018). SACK-Permitted를 안 보내면 꺼진다 | 한 창에 손실이 여럿이면 회복이 느리다 | 켜져 있다(`protocol.go:610`). 상대가 허용할 때만 쓴다 |
| 타임스탬프 | 선택(RFC 7323 3.2). 양쪽 SYN에 있어야 켜진다. 켜지면 RST가 아닌 모든 세그먼트에 실어야 한다 | 재전송 중에 RTT를 재지 못한다. PAWS가 없다 | SYN에 싣는다(`connect.go:586`) |
| RFC 5961 | RST 검사는 SHOULD, ACK 범위 검사는 MAY | 창 안의 RST·SYN 하나로 연결이 끊긴다 | RST·SYN 규칙을 따른다(`connect.go:1227-1239`, `:1337-1359`) |
| 지연 ACK | SHOULD | ACK가 두 배 | 기본으로 미루지 않는다(`endpoint.go:897`의 `SetQuickAck(true)`. 해석은 11절) |
| Nagle | SHOULD | 작은 쓰기가 작은 세그먼트로 나간다 | 스택 옵션(`TCPDelayEnabled`)이 켜졌을 때만(`endpoint.go:921-924`). Tailscale은 켜지 않는다 |
| keep-alive | MAY | 죽은 상대와의 유휴 연결이 남는다 | Tailscale이 받는 연결마다 켠다(5절) |
| urgent | MUST-30 | urgent 데이터를 보통 데이터로 읽는다 | 읽지 않음 |
| ECN | SHOULD(SHLD-8) | 없음 | 읽지 않음 |

### 4.9 RFC 5961의 속도 제한

challenge ACK는 속도를 제한하는 것이 SHOULD다. 예로 든 값은 5초에 10개다(RFC 5961 7). 타이머 없이 시각과 세는 값으로 구현할 수 있다.

## 5. Tailscale netstack(gVisor)의 설정

| 항목 | 값 | 근거 |
| --- | --- | --- |
| 혼잡 제어 | CUBIC | `netstack.go:406-407` |
| 손실 회복 | RACK을 끈다(`TS_NETSTACK_ENABLE_RACK`으로 켤 수 있다). 꺼지면 RFC 6675 SACK 회복 | `netstack.go:141-153`, `:412-417` |
| SACK | 켜짐(gVisor 기본) | `gvisor/transport/tcp/protocol.go:610` |
| 받는 버퍼(최소/기본/최대) | 4KiB / 1MiB / 8MiB. iOS는 최대 4MiB | `netstack_tcpbuf_default.go`, `netstack_tcpbuf_ios.go`, `gvisor/transport/tcp/protocol.go:41-52` |
| 보내는 버퍼(최소/기본/최대) | 4KiB / 1MiB / 6MiB. iOS는 최대 4MiB | 같은 곳 |
| 받는 버퍼 자동 조정 | 켜짐 | `protocol.go:613` |
| 순서가 어긋난 세그먼트 | 받는 버퍼의 75%까지 쥔다 | `gvisor/transport/tcp/rcv.go:488-510` |
| NIC MTU | 1280(`TS_DEBUG_MTU`로 바꿀 수 있다) | `netstack.go:434`, `tailscale.com/net/tstun/mtu.go:79`, `:133-148` |
| 광고하는 MSS | 경로 MTU − 20. 경로 MTU는 NIC MTU − IP 머리(IPv4 20, IPv6 40) → IPv4 1240, IPv6 1220 | `gvisor/transport/tcp/endpoint.go:638-648`, `gvisor/network/ipv4/ipv4.go:419-425`, `gvisor/network/ipv6/ipv6.go:736-742` |
| 초기 cwnd | 10 세그먼트 | `snd.go:41` |
| RTO | 처음 1초, 하한 200ms, 상한 120초 | `connect.go:41`, `snd.go:32`, `:35` |
| 재전송 한도 | 15번 | `snd.go:50` |
| SYN 재시도 | 6번 | `protocol.go:68` |
| 중복 ACK 문턱 | 3 | `snd.go:45` |
| keep-alive | 받는 연결마다 켠다. 유휴 2시간, 간격 75초, 9번(환경 변수 `TS_NETSTACK_KEEPALIVE_IDLE`·`_INTERVAL`로 줄일 수 있다) | `netstack.go:125-139`, `:1677-1702`, `protocol.go:72-80` |
| TIME-WAIT, linger | 60초, 60초 | `protocol.go:56`, `:64` |
| 맺는 중인 연결의 상한 | 모바일 1,024, Linux 8,192, 그 밖(macOS) 2,048. 상대 하나는 그 2/3 | `netstack.go:85-103`, `:111-120`, `:669` |
| 상한을 넘은 SYN | 응답 없이 버린다 | `gvisor/transport/tcp/forwarder.go:88-92` |
| GRO·GSO | Linux에서만 | `netstack.go:427-432` |

## 6. tsnet `Listen`·`Dial`

### 6.1 `Listen(network, addr)` (`tsnet.go:1321-1323`, `:2115-2158`)

1. `network`는 `tcp`·`tcp4`·`tcp6`(와 UDP)다. `addr`의 호스트는 비었거나 IP 리터럴이어야 한다. `0.0.0.0`·`::`는 빈 호스트와 같다(`tsnet.go:2069-2096`).
2. 호스트가 빈 리스너는 **자기 노드의 tailnet IPv4·IPv6 주소로 온 것만** 받는다. `tcp`는 두 계열을 다 받는다(`tsnet.go:1238-1266`).
3. 같은 (network, 주소, 포트)에 이미 리스너가 있으면 오류다(`tsnet.go:2209-2213`).
4. 포트 0은 10002…19999에서 고른다(`tsnet.go:2111-2112`, `:2189-2196`).
5. `Listen`은 노드를 시작하지만 `Running`을 기다리지 않는다(`tsnet.go:2124-2126`).

### 6.2 들어오는 연결의 길

1. tsnet의 기본(가짜 TUN)에서는 자기 주소로 온 패킷을 모두 netstack이 처리한다(`tsnet.go:921-927`).
2. 패킷은 WireGuard 복호화 → 필터를 거친 뒤 netstack에 들어간다(`netstack.go:1472-1512`의 `injectInbound`는 `tstun` 래퍼의 필터 뒤 훅이다). 필터는 TCP에서 SYN만 규칙에 견준다(`Sources/SwiftailEngine/PacketFilter.swift`, 엔진 노트 4.4~4.6).
3. SYN(ACK 없음, 체크섬 맞음)마다 forwarder가 요청을 만들고(`gvisor/transport/tcp/forwarder.go:66-104`) `acceptTCP`가 처리한다(`netstack.go:1602`).
4. `acceptTCP`는 `GetTCPHandlerForFlow`(tsnet의 리스너 찾기)를 부른다. 리스너가 없으면 **RST**(`netstack.go:1748-1754`, `tsnet.go:1289-1303`). 있으면 엔드포인트를 만들어 핸드셰이크를 하고 keep-alive를 켠 뒤 리스너에 넘긴다(`netstack.go:1666-1722`).
5. 리스너의 `Accept`가 1초 안에 받아 가지 않으면 그 연결을 닫는다(`tsnet.go:2406-2418`). 통로에 버퍼가 없다(`tsnet.go:2349`).
6. SYN이 아닌 세그먼트가 연결 없는 곳에 오면 gVisor가 RST로 답한다(4.2).
7. 서비스 IP의 TCP는 53(DNS)과 몇 포트만 받고 나머지는 RST다(`netstack.go:1724-1735`, `:1770-1787`). Swiftail은 M5에서 모두 RST로 답한다(터널 계약 D4).

### 6.3 `Dial(ctx, network, address)` (`tsnet.go:382-390`)

1. `Running`이 될 때까지 기다린다(`tsnet.go:396`의 `awaitRunning`).
2. 주소 해석(`tailscale.com/net/tsdial/tsdial.go:401-417`, `:423-436`): IP 리터럴이면 그대로. 아니면 소문자로 바꾸고 끝 점을 뗀 이름을 netmap에서 찾는다. 피어의 FQDN, 짧은 이름, `ExtraRecords`를 받는다(`tailscale.com/ipn/ipnlocal/resolve.go:54-75`). `tcp`면 그 노드의 IPv4를 먼저 고르고 없으면 IPv6다(`resolve.go:115-140`).
3. netmap에 없는 이름은 시스템 DNS로 찾는다(`tsdial.go:438-470`).
4. 주소가 어느 피어의 것이면(`PeerForIP`) netstack으로 건다. 출발 주소는 목적지와 같은 계열의 자기 tailnet 주소다(`tsnet.go:935-950`). 그 밖의 주소는 OS 소켓으로 건다(`tsdial.go:608-624`).
5. 돌려주는 연결(`gonet.TCPConn`)에는 `CloseWrite`·`CloseRead`가 있다(`gvisor/adapters/gonet/gonet.go:446`, `:457`).

## 7. MTU와 MSS

- Tailscale TUN의 기본 MTU는 1280이다(`tailscale.com/net/tstun/mtu.go:79`). 첫 사용처의 터널도 1280…1420이다(터널 계약 동작 U1).
- MTU 1280에서 MSS는 IPv4 1240(1280 − 20 − 20), IPv6 1220(1280 − 40 − 20)이다. gVisor 피어가 광고하는 값과 같다(5절).
- 보내는 세그먼트의 크기는 `min(상대가 광고한 MSS, 자기 MTU − IP 머리 − TCP 머리)`다(RFC 9293 3.7.1 MUST-16). 옵션을 실으면 그만큼 데이터를 줄인다.
- 엔진은 조각난 패킷을 받지 않는다(`Sources/SwiftailEngine/IPPacket.swift`의 `ParseError.fragment`). MSS가 MTU 안에 있으면 TCP는 조각나지 않는다.

## 8. 첫 사용처가 쓰는 범위

첫 사용처 저장소의 커밋된 상태(`286c214`)에서 읽었다.

1. **Mac 호스트**(`core/internal/node/node.go`의 `startHostListener`, `tls.go`): `Running`이 된 뒤 `srv.Listen("tcp", ":<port>")`(기본 443)를 한 번 열고, `tls.NewListener`(인증서는 `GetCertificate`)로 감싸 `http.Server`에 넘긴다. HTTP 서버의 시간 제한은 `ReadHeaderTimeout` 10초, `IdleTimeout` 60초다. 가짜 tailnet 시험에서는 TLS 없이 같은 리스너를 쓴다.
2. 요청마다 `r.RemoteAddr`로 WhoIs를 부른다(`core/internal/host/host.go`의 `identify`, 5초 제한). 연결의 원격 주소가 필요하다.
3. **주고받는 양**(`docs/protocol.md` 4·5절, `docs/protocol-addenda.md`): 서버 → 클라이언트가 크다. IPA(`GET /i/{token}/app.ipa`, Range 지원)와 파일(`GET /v1/resources/{id}`, 하나에 4GiB까지, Range). 클라이언트 → 서버는 작다(로그·크래시 본문 4MB까지).
4. **상대의 TCP 스택**: iPhone의 커널(패킷 터널 뒤의 URLSession, iOS 설치기, 백그라운드 전송, 공식 Tailscale 앱 뒤의 Safari)과 gVisor(프록시 모드의 `srv.Dial`).
5. **프록시 모드**(`core/internal/proxy/proxy.go`): `srv.Dial(ctx, "tcp", "<fqdn>:443")`을 15초 제한으로 부르고, 돌려받은 연결의 `RemoteAddr`가 tailnet 주소인지 확인하고, 두 방향을 복사하다 한쪽이 끝나면 `CloseWrite`로 반만 닫는다. 프록시 모드는 진단용으로만 남아 있다(`docs/tunnel.md` "변경 이유").
6. tsnet의 다른 것(`ListenPacket`, `ListenTLS`, `ListenFunnel`, `HTTPClient`, `Loopback`, `RegisterFallbackTCPHandler`)은 쓰지 않는다(`core/` 안의 `srv.` 호출은 `Listen`·`Dial`·`Up`·`LocalClient`·`Start`·`Close`뿐이다).

## 9. Swiftail에 필요한 최소 부분

계약 `docs/contracts/SwiftailNetstack.md`의 "지원 범위"가 정한다. 이 노트의 근거로 넣을 수 있는 것과 뺄 수 있는 것:

- 뺄 수 없는 것(상대가 버리거나 연결이 서지 않는다): 체크섬, MSS 옵션, 4.2의 처리 순서, 재전송, 0 창 탐침, slow start·congestion avoidance·RTO 물러나기.
- 빼도 연결은 되는 것: 창 확장(창이 64KiB로 묶인다), SACK, 타임스탬프, 지연 ACK, Nagle, keep-alive, urgent, ECN, 동시 열기.

## 10. 상호 운용 시험에서 확인할 것

1. gVisor 피어가 Swiftail의 SYN·SYN-ACK를 받아 ESTABLISHED가 된다(체크섬, MSS, 창 확장 옵션).
2. 리스너 없는 포트로 온 SYN에 RST가 가고 Go의 `Dial`이 제한 시간 전에 거절로 끝난다.
3. 양방향 100MB 전송의 해시가 같다. 창 확장이 켜졌는지는 광고한 창이 65,535를 넘는 것으로 본다.
4. 손실 1%·5%에서 전송이 끝난다.
5. 반닫힘: 한쪽이 FIN을 보낸 뒤에도 반대 방향 데이터가 끝까지 간다.
6. Swiftail이 RST로 끊으면 Go 쪽 읽기가 reset 오류로 끝나고, Go가 끊으면 Swiftail이 reset으로 안다.
7. macOS·iOS 커널 스택이 상대일 때 1~6.

## 11. 확인하지 못한 것

1. gVisor가 지연 ACK를 실제로 하지 않는지. `SetQuickAck(true)`(`endpoint.go:897`)만 보았고 ACK를 미루는 코드 경로를 따라가지 않았다.
2. gVisor의 SYN 재전송 간격과 6번이 걸리는 전체 시간(`connect.go:621-666`의 `retransmitHandlerLocked`를 끝까지 읽지 않았다).
3. gVisor CUBIC의 동작(`cubic.go`). Swiftail은 CUBIC을 구현하지 않으므로 읽지 않았다.
4. macOS·iOS 커널 스택(XNU)의 기본값: 광고하는 MSS, 창 확장 shift, SACK·타임스탬프 사용, 지연 ACK 시간. 소스를 읽지 않았다. 관문에서 패킷을 잡아 기록한다.
5. Go에서 피어가 netmap에서 빠지거나 주소의 주인이 바뀔 때 gVisor의 열린 연결이 어떻게 되는지.
6. 첫 사용처의 `http.Server`가 HTTP/2를 쓰는지. `tls.Config`에 `NextProtos`가 없다는 것만 보았다(`tls.go`).
7. RFC 2018의 SACK 생성 규칙(4절), RFC 6675, RFC 8985(RACK), RFC 7323의 PAWS(5절)는 절 제목만 확인했다. M6 최소 범위에서 쓰지 않는다.
8. utun을 만드는 데 관리자 권한이 필요한지는 XNU 소스로 확인하지 않았다. 저장소의 터널 계약(시험 9)이 그렇게 적고 있다.
