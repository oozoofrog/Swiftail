# TCP와 프로세스 내 netstack 노트

- 기준: `tailscale.com v1.104.6`, `gvisor.dev/gvisor v0.0.0-20260915211658-a6f909f08a72`(`tailscale.com/go.mod:156`이 고정한 버전), RFC 9293·6298·5681·6582·5961·6528·6928·7323·2018·1071·8200·791(RFC Editor 공식 원문, 2026-11-15 대조)
- 작성: Claude Fable 5.2, 2026-11-15
- 검증: GPT-6.1 Sol, 2026-11-15. 위 RFC 12개와 고정된 Tailscale·gVisor 소스, 첫 사용처의 `286c214`를 작성 세션과 독립적으로 대조하고 정정했다. 실행으로 확인한 동작은 없으며, 남은 미확인 범위는 11절에 적었다.

## 1. 범위

M6(`docs/contracts/SwiftailNetstack.md`)의 Swift TCP를 구현하는 데 필요한 사실만 적는다.

다루는 것: TCP 머리와 옵션의 형식, 상태 기계와 세그먼트 처리 순서, 재전송 타이머, 창과 흐름 제어, 혼잡 제어, 옵션마다 상호 운용에 필수인지, Tailscale이 gVisor를 어떻게 설정해 쓰는지, tailnet 경로의 MTU와 MSS, tsnet `Listen`·`Dial`의 동작, 첫 사용처가 쓰는 범위.

다루지 않는 것: UDP·ICMP 소켓, IP 단편화 재조립, ECN, TCP Fast Open, MPTCP, 서브넷 라우터의 TCP 전달(`forwardTCP`), Funnel·Serve, gVisor의 내부 구조(디스패처, 세그먼트 큐, 잠금).

## 2. 근거 표기

- Go 소스는 모듈 루트 기준 상대 경로와 줄 번호다. `netstack.go`는 `tailscale.com/wgengine/netstack/netstack.go`, `tsnet.go`는 `tailscale.com/tsnet/tsnet.go`, `gvisor/…`는 `gvisor.dev/gvisor@v0.0.0-20260915211658-a6f909f08a72/pkg/tcpip/…`다.
- `connect.go`·`snd.go`·`rcv.go`·`endpoint.go`·`protocol.go`만 적었을 때도 위 gVisor 버전의 `pkg/tcpip/transport/tcp/` 기준이다. `link_endpoint.go`·`netstack_tcpbuf_*.go`는 Tailscale의 `wgengine/netstack/` 기준이다. 첫 사용처 경로는 별도 표시한 커밋 기준이다.
- RFC는 번호와 절(예: RFC 9293 3.10.7.4)이고, 요구 사항 번호가 있으면 함께 적는다(MUST-14).
- 사실은 RFC의 요구와 고정 버전 구현의 동작을 구별한다. 식에서 계산한 값은 그 입력의 출처를 함께 적는다. 9절의 범위 선택과 10절의 시험은 제안이며 실행 결과가 아니다. 읽지 못한 것은 11절에 모았다.
- 공식 원문: [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293), [6298](https://www.rfc-editor.org/rfc/rfc6298), [5681](https://www.rfc-editor.org/rfc/rfc5681), [6582](https://www.rfc-editor.org/rfc/rfc6582), [5961](https://www.rfc-editor.org/rfc/rfc5961), [6528](https://www.rfc-editor.org/rfc/rfc6528), [6928](https://www.rfc-editor.org/rfc/rfc6928), [7323](https://www.rfc-editor.org/rfc/rfc7323), [2018](https://www.rfc-editor.org/rfc/rfc2018), [1071](https://www.rfc-editor.org/rfc/rfc1071), [8200](https://www.rfc-editor.org/rfc/rfc8200), [791](https://www.rfc-editor.org/rfc/rfc791). 이번 대조는 발행된 RFC 본문 기준이며 별도 errata의 판정은 포함하지 않는다.

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
| 14 | 2 | window(SEG.WND) | 빅엔디언. SYN이 아닌 세그먼트는 `2^shift`를 곱해 읽는다(4.6) |
| 16 | 2 | checksum | 의사 머리 + TCP 머리 + 데이터의 인터넷 체크섬 |
| 18 | 2 | urgent pointer | URG일 때만 |
| 20 | 0…40 | options | data offset이 가리키는 곳까지. 남는 자리는 0으로 채운다(MUST-69) |

- SEG.LEN은 데이터 바이트 수에 SYN과 FIN을 1씩 더한 값이다(RFC 9293 3.4).
- 체크섬의 의사 머리는 IPv4가 출발 주소·목적 주소·0·프로토콜 6·TCP 길이(16비트), IPv6가 출발 주소·목적 주소·길이(32비트)·0 셋·next header 6이다(RFC 9293 3.1, RFC 8200 8.1). TCP 길이는 옵션을 포함한 TCP 머리와 데이터의 합이며 IP 머리·확장 헤더는 포함하지 않는다. IPv6 Routing header가 있으면 최종 목적 주소를 쓴다(RFC 8200 8.1). 저장소의 `Sources/SwiftailEngine/Tunnel/ServiceIPReply+Checksum.swift:27-46`가 이 의사 머리를 만든다.
- 체크섬은 16비트 낱말의 1의 보수 합을 다시 보수로 만든다. 계산할 때 checksum 필드를 0으로 두고, 홀수 끝 바이트의 오른쪽에 0을 붙여 계산하되 그 0은 보내지 않는다. 검사할 때는 수신 checksum을 포함한 합이 `0xFFFF`여야 한다(RFC 9293 3.1 MUST-2·MUST-3, RFC 1071 1·2절). 저장소의 합 구현은 `Sources/SwiftailEngine/Tunnel/ServiceIPReply+Checksum.swift:51-63`이다.
- Tailscale은 netstack에 넣기 전에 IPv4 머리와 비단편 TCP·UDP 체크섬을 검사한다(`tailscale.com/wgengine/netstack/gro/gro.go:22-31`, `tailscale.com/wgengine/netstack/link_endpoint.go:238-251`, `:319-323`). gVisor는 체크섬이 틀린 SYN을 받지 않는다(`gvisor/transport/tcp/forwarder.go:74`). **Swiftail이 내는 체크섬은 정확해야 한다.**

### 3.2 옵션

| Kind | 길이 | 이름 | 형식 | 근거 |
| --- | --- | --- | --- | --- |
| 0 | 1 | End of Option List | 뒤는 읽지 않는다 | RFC 9293 3.2 |
| 1 | 1 | No-Operation | 정렬용. 낱말 경계에 맞지 않아도 읽어야 한다(MUST-64) | RFC 9293 3.2 |
| 2 | 4 | Maximum Segment Size | 16비트 MSS. SYN에만 | RFC 9293 3.2, 3.7.1 |
| 3 | 3 | Window Scale | shift.cnt 1바이트. SYN에만 | RFC 7323 2.2 |
| 4 | 2 | SACK-Permitted | SYN에만. SYN이 아닌 세그먼트에 보내면 안 된다(MUST NOT) | RFC 2018 2 |
| 5 | 2+8×블록 수 | SACK | 블록마다 왼쪽·오른쪽 끝 32비트 둘(네트워크 바이트 순서). 왼쪽 끝은 블록의 첫 번호, 오른쪽 끝은 마지막 바이트 다음 번호. 옵션 공간 40바이트에 블록 4개까지, 타임스탬프(10 + 채움 2)와 함께면 3개까지 | RFC 2018 3 |
| 8 | 10 | Timestamps | TSval·TSecr 32비트 둘 | RFC 7323 3.2 |

- 모르는 옵션은 길이 필드로 건너뛴다(MUST-6). EOL·NOP 밖의 옵션은 모두 길이 필드가 있다(MUST-68). 길이가 0이거나 머리 밖으로 나가는 옵션에 대비해야 한다(MUST-7. 원문이 제시하는 한 절차는 연결 reset과 오류 원인 기록이며, reset 자체가 MUST인 것은 아니다).
- 어떤 세그먼트에도 옵션이 올 수 있다(MUST-5).
- SACK 블록 내기(RFC 2018 4, RFC Editor 원문 2026-11-15 대조): 상대 SYN에서 SACK-Permitted를 받았을 때만 SACK을 낼 수 있고(MAY), 받지 않았으면 내면 안 된다(MUST NOT). 낸다면 허락된 모든 경우에 낸다(SHOULD). 큐의 가장 높은 번호를 확인하지 않는 모든 ACK, 곧 받는 쪽이 이어지지 않은 데이터를 쥔 동안의 ACK에 싣는다(SHOULD). 새 데이터가 든 유효한 세그먼트마다 ACK를 보내고 그 "중복" ACK마다 SACK을 싣는다(SHOULD). 첫 블록은 이 ACK를 일으킨 세그먼트가 든 이어진 블록이어야 한다(MUST). 그 세그먼트가 Acknowledgment Number를 나아가게 했으면 예외다. 가능한 한 많은 서로 다른 블록을 싣는다(SHOULD). 나머지는 가장 최근에 알린 블록(이전 SACK의 첫 블록 기준) 가운데 이미 넣은 블록의 부분 집합이 아닌 것을 되풀이해 채운다(SHOULD). 첫 블록 뒤의 순서는 자유다. 7절 Case 1~3이 이 규칙의 예다(Case 3: 6000–6500, 7000–7500, 8000–8500을 쥔 뒤 6500이 오면 블록은 6000–7500, 8000–8500. 5500이 오면 ACK 7500과 8000–8500). 받는 쪽이 SACK으로 알린 데이터를 나중에 버리는 것(reneging)은 허용되지만 권하지 않고, 그때는 8절의 규칙이 더 붙는다. Swiftail은 버리지 않는다(계약 동작 F5 아래).

## 4. 절차와 상태 기계

### 4.1 상태와 변수 (RFC 9293 3.3.1, 3.3.2)

상태: LISTEN, SYN-SENT, SYN-RECEIVED, ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT, CLOSED.

보내는 쪽: SND.UNA(가장 오래된 미확인), SND.NXT(다음에 보낼 번호), SND.WND(상대가 준 창), SND.WL1·SND.WL2(창을 마지막으로 갱신한 세그먼트의 SEQ·ACK), ISS. 받는 쪽: RCV.NXT, RCV.WND, IRS.

시퀀스 번호의 비교는 모두 2^32 순환 산술이다(RFC 9293 3.4).

### 4.2 세그먼트 도착 처리 (RFC 9293 3.10.7)

**연결이 없을 때(CLOSED, 3.10.7.1)**: RST가 켜진 세그먼트는 버린다. 아니면 RST로 답한다. ACK가 꺼져 있으면 `<SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>`, 켜져 있으면 `<SEQ=SEG.ACK><CTL=RST>`. gVisor도 같다(`gvisor/transport/tcp/protocol.go:185-200`, `replyWithReset` `:223`).

**LISTEN(3.10.7.2)**, 차례대로: ① RST는 무시. ② ACK가 켜져 있으면 `<SEQ=SEG.ACK><CTL=RST>`. ③ SYN이면 RCV.NXT = SEG.SEQ+1, IRS = SEG.SEQ, ISS를 골라 `<SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>`, SND.NXT = ISS+1, SND.UNA = ISS, SYN-RECEIVED로. SYN에 함께 온 데이터·다른 제어는 나중에 처리하도록 보관하며 SYN·ACK 검사를 반복하지 않는다. ④ 그 밖은 버린다.

**SYN-SENT(3.10.7.3)**, 차례대로:

1. ACK가 켜져 있고 `SEG.ACK =< ISS` 또는 `SEG.ACK > SND.NXT`면 `<SEQ=SEG.ACK><CTL=RST>`를 보내고(RST가 켜진 세그먼트면 보내지 않고) 버린다.
2. RST가 켜져 있으면: ACK가 받아들일 만했으면 "connection reset"을 알리고 CLOSED. ACK가 없으면 버린다.
3. SYN이 켜져 있으면 RCV.NXT = SEG.SEQ+1, IRS = SEG.SEQ, ACK가 있으면 SND.UNA = SEG.ACK. `SND.UNA > ISS`면 ESTABLISHED로 가고 `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>`를 보낸다. 이 경로에 함께 온 데이터·제어가 있으면 3.10.7.4의 여섯째(URG)부터 이어 처리한다. `SND.UNA > ISS`가 아니면(동시 열기) SYN-RECEIVED로 가고 `<SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>`를 보낸다. 이때 SND.WND·WL1·WL2를 채우고 데이터·다른 제어는 ESTABLISHED 이후 처리하도록 보관한다.
4. SYN도 RST도 없으면 버린다.

gVisor는 2에서 Linux처럼 "connection refused"를 돌려준다(`gvisor/transport/tcp/connect.go:289-301`).

**그 밖의 상태(3.10.7.4)**, 차례대로. 이 목록을 SYN-SENT·LISTEN·CLOSED에 적용하면 안 된다. RFC 5961을 적용할 때 RST의 원래 SEG.SEQ를 데이터 자르기로 바꾸거나, 창 안이지만 RCV.NXT와 다른 RST를 순서 대기열에 넣어 challenge ACK를 생략하면 안 된다. 동기화된 상태의 SYN은 시퀀스와 관계없이 challenge ACK의 대상이다(RFC 5961 3.2·4.2, RFC 9293 3.10.7.4).

1. **시퀀스 검사.** 받아들일 조건(표 6):

   | SEG.LEN | RCV.WND | 조건 |
   | --- | --- | --- |
   | 0 | 0 | SEG.SEQ = RCV.NXT |
   | 0 | >0 | RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND |
   | >0 | 0 | 받지 않는다 |
   | >0 | >0 | 첫 바이트나 마지막 바이트가 창 안 |

   받지 않는 세그먼트에는 `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>`를 보내고 버린다(RST가 켜져 있으면 보내지 않는다). 창이 0이어도 유효한 ACK·URG·RST에는 특별 처리를 둔다. 창 밖으로 걸친 부분은 잘라 내고, RCV.NXT보다 뒤에서 시작하는 세그먼트는 뒤에 처리하도록 둔다(SHLD-31). 가능하면 ACK를 모으고, 대기열의 연속 세그먼트는 모두 처리한 뒤 ACK를 보낸다(MUST-58, MUST-59). 이를 모든 예외 ACK까지 무조건 한 개로 줄이라는 규칙으로 읽지 않는다.
2. **RST**(RFC 5961 3.2를 따르는 구현): 창 밖이면 조용히 버린다. SEG.SEQ = RCV.NXT면 연결을 끊는다. 창 안이지만 RCV.NXT와 다르면 challenge ACK `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>`를 보내고 버린다. 끊을 때: SYN-RECEIVED에서 수동 열기였으면 LISTEN으로 조용히 돌아가고, 능동 열기였으면 "connection refused". ESTABLISHED·FIN-WAIT-1·FIN-WAIT-2·CLOSE-WAIT는 "connection reset"을 알리고 CLOSED. CLOSING·LAST-ACK·TIME-WAIT는 CLOSED.
3. (보안 검사는 쓰지 않는다.)
4. **SYN**: SYN-RECEIVED에서 수동 열기였으면 LISTEN으로 돌아간다. 동기화된 상태에서는 시퀀스 번호와 상관없이 challenge ACK를 보내고 버린다(RFC 5961 4.2. gVisor `connect.go:1337-1359`).
5. **ACK**: ACK가 꺼져 있으면 버린다. RFC 5961 5.2를 따르면 `SND.UNA - MAX.SND.WND =< SEG.ACK =< SND.NXT`가 아닌 세그먼트는 버리고 ACK를 보낸다(MAY-12).
   - SYN-RECEIVED: `SND.UNA < SEG.ACK =< SND.NXT`면 ESTABLISHED로 가고 SND.WND·WL1·WL2를 이 세그먼트로 채운다. 아니면 `<SEQ=SEG.ACK><CTL=RST>`.
   - ESTABLISHED: `SND.UNA < SEG.ACK =< SND.NXT`면 SND.UNA = SEG.ACK, 재전송 큐에서 확인된 것을 지운다. `SEG.ACK =< SND.UNA`는 중복이다. `SEG.ACK > SND.NXT`면 ACK를 보내고 버린다. 창 갱신은 먼저 `SND.UNA =< SEG.ACK =< SND.NXT`여야 한다. 그 안에서 `SND.WL1 < SEG.SEQ` 또는 (`SND.WL1 = SEG.SEQ` 그리고 `SND.WL2 =< SEG.ACK`)일 때만 SND.WND = SEG.WND, WL1 = SEG.SEQ, WL2 = SEG.ACK.
   - FIN-WAIT-1: 위에 더해 우리 FIN이 확인되면 FIN-WAIT-2. FIN-WAIT-2·CLOSE-WAIT도 ESTABLISHED의 ACK 처리를 한다. CLOSING: 우리 FIN이 확인되면 TIME-WAIT. LAST-ACK: 우리 FIN이 확인되면 CLOSED. TIME-WAIT: 상대 FIN의 재전송이면 ACK하고 2MSL을 다시 잰다.
6. URG(쓰지 않는다. 9절).
7. **데이터**: ESTABLISHED·FIN-WAIT-1·FIN-WAIT-2에서만 받는다. RCV.NXT를 올리고 `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>`를 보낸다(지연 ACK는 4.6). RCV.NXT+RCV.WND는 줄이지 않는다. 그 밖의 상태에서는 데이터를 무시한다.
8. **FIN**: 앞선 데이터까지 순서대로 받아 FIN이 RCV.NXT에 닿았을 때 RCV.NXT를 FIN 너머로 올리고 ACK한다. 창 밖으로 잘린 FIN이나 앞에 빈 곳이 있는 FIN을 먼저 소비하지 않는다(첫째·일곱째 단계). SYN-RECEIVED·ESTABLISHED → CLOSE-WAIT. FIN-WAIT-1 → 우리 FIN이 확인됐으면 TIME-WAIT, 아니면 CLOSING. FIN-WAIT-2 → TIME-WAIT. TIME-WAIT → 2MSL을 다시 잰다. CLOSE-WAIT·CLOSING·LAST-ACK는 상태를 유지한다.

gVisor의 구현 순서는 RFC 목록과 같지 않다: RST → SYN → ACK가 있는 세그먼트의 수신 처리 → 송신 쪽 ACK 처리(`gvisor/transport/tcp/connect.go:1328-1395`). 따라서 이 코드를 RFC의 ACK 검사·데이터 처리 순서의 대체 명세로 삼지 않는다. gVisor의 엄격한 RST 검사는 `connect.go:1227-1239`이지만, SYN-RECEIVED는 별도 `synRcvdState`에서 창 안 RST를 받는다(`connect.go:394-402`). TIME-WAIT도 별도 경로이며 RST를 무시하고, `SEG.SEQ+1 = RCV.NXT`인 FIN에 ACK한 뒤 시간을 연장한다(`rcv.go:552-567`, `:600-604`). 일반 시퀀스 검사에서 `RCV.NXT-1`인 중복 FIN을 먼저 버리면 이 연장이 빠지므로 TIME-WAIT 예외를 명시해야 한다(RFC 9293 3.10.7.4의 ACK·FIN 단계). 창 밖 세그먼트에는 데이터가 있을 때는 늘, 없을 때는 속도 제한 안에서 ACK를 보낸다(`rcv.go:465-468`, `snd.go:1885-1891`).

### 4.3 연결 맺기와 ISN

1. 3-way handshake는 4.2의 LISTEN·SYN-SENT·SYN-RECEIVED 규칙 그대로다(RFC 9293 3.5).
2. ISN은 시계로 움직여야 하고(MUST-8) `ISN = M + F(localip, localport, remoteip, remoteport, secretkey)`가 권고다(SHLD-1, RFC 9293 3.4.1·RFC 6528 3). M은 대략 4마이크로초에 적어도 1씩 느는 시계 성분이다. F는 밖에서 계산할 수 없는 함수다(MUST-9). gVisor는 스택마다 16바이트 비밀을 뽑고(`gvisor/transport/tcp/protocol.go:588-597`의 `seqnumSecret`) SHA-256(비밀 ‖ 주소 ‖ 포트)에 64ns 단위 시계를 더한다(`connect.go:226-252`).
3. SYN 재전송: 처음 RTO 1초가 권고다(RFC 6298 2.1. gVisor `InitialRTO`, `connect.go:41`). 만료마다 두 배로 늘린다(RFC 6298 5.5). gVisor는 `DefaultSynRetries = 6`을 정의하지만(`protocol.go:68`, `:617`), 실제 handshake 타이머는 횟수가 아니라 `InitialRTO = 1초`, `MaxRTO = 120초`를 쓰는 `backoffTimer`로 끝난다(`connect.go:181`, `:621-643`, `:721-736`). 정상적인 무응답 경로에서 SYN·SYN-ACK를 t=0에 보내고 t=1·3·7·15·31·63초에 여섯 번 재전송하며 t=127초에 다음 간격 128초가 상한 120초를 넘어서 실패한다(소스의 식으로 계산, 실행 측정 아님). 별도 `maxSynRetries` 필드는 이 경로의 판정에 쓰이지 않는다(`endpoint.go:931-934`, `connect.go:730-736`). 이 127초 기본 경로는 RFC 9293 3.8.3의 SYN R2 ≥ 3분(MUST-23)을 충족하지 않는다. gVisor의 현재 동작을 RFC 요구와 혼동하면 안 된다. SYN의 재전송 타이머가 만료된 적이 있고 RTO가 3초보다 작으면 데이터 전송을 시작할 때 RTO를 3초로 다시 잡는다(RFC 6298 5.7).
4. gVisor는 여는 쪽의 SYN을 확인하는 유효한 RST를 "거절"로 알린다. RFC 9293의 SYN-SENT 설명은 "connection reset"이다(4.2 SYN-SENT 2와 `connect.go:289-301`).

### 4.4 닫기 (RFC 9293 3.6)

- FIN은 시퀀스 번호 하나를 쓴다. 보낸 FIN이 확인되고 상대의 FIN을 받아 ACK해야 양쪽이 닫힌다.
- 두 방향은 따로 닫힌다. 한쪽만 닫은 상태에서 열린 방향으로 계속 보낼 수 있다(3.6.1).
- 읽기까지 금지하는 half-duplex CLOSE를 택한 구현에서 읽지 않은 데이터가 남았거나 CLOSE 뒤 새 데이터가 오면 RST로 데이터 손실을 알리는 것이 권고다(SHLD-3). 송신만 끝내는 반닫힘에 이 규칙을 적용하지 않는다(3.6.1).
- 먼저 닫은 쪽은 TIME-WAIT에서 2×MSL 동안 머문다(MUST-13). gVisor의 TIME-WAIT 기본값은 60초(`protocol.go:64`), FIN-WAIT-2 linger의 기본값도 60초지만(`protocol.go:56`), 앱이 `Close`한 연결에 적용하며 송신만 반닫힌 모든 연결의 수명을 60초로 제한하는 규칙은 아니다(`endpoint.go:1131-1174`). RFC 9293은 MSL을 2분으로 정하므로(3.4.3·4절) RFC의 2MSL은 4분이고, gVisor의 60초는 별도 구현값이다.
- 상대가 FIN으로 닫았는지 RST로 끊었는지를 응용에 구분해 알려야 한다(MUST-12).

### 4.5 재전송 타이머 (RFC 6298, RFC 9293 3.8.1 MUST-18)

1. RTT를 재기 전 RTO는 1초가 SHOULD이며 1초보다 큰 값도 허용된다(2.1).
2. 첫 측정 R: `SRTT = R`, `RTTVAR = R/2`, `RTO = SRTT + max(G, 4*RTTVAR)`(2.2).
3. 그 뒤 측정 R': `RTTVAR = 3/4*RTTVAR + 1/4*|SRTT - R'|`, `SRTT = 7/8*SRTT + 1/8*R'`(이 순서로), `RTO = SRTT + max(G, 4*RTTVAR)`(2.3).
4. 1초보다 작으면 1초로 올리는 것이 SHOULD다(2.4). 상한을 둔다면 60초 이상(2.5). **gVisor는 하한 200ms, 상한 120초를 쓴다**(`gvisor/transport/tcp/snd.go:32`, `:35`).
5. 재전송한 세그먼트로는 RTT를 재지 않는다(Karn, 3절). 타임스탬프 옵션을 쓰면 잴 수 있다(RFC 7323 4).
6. 타이머 관리(5절): 데이터를 보낼 때 타이머가 꺼져 있으면 RTO로 켠다(5.1). 모두 확인되면 끈다(5.2). 새 데이터를 확인하는 ACK를 받으면 지금 RTO로 다시 켠다(5.3). 만료되면 가장 오래된 미확인 세그먼트를 다시 보내고(5.4) RTO를 두 배로 하고(5.5) 다시 켠다(5.6).
7. R2는 같은 세그먼트의 재전송 횟수 또는 시간 문턱이며, 도달하면 연결을 닫는다. R2는 100초 이상이 SHOULD다(RFC 9293 3.8.3 MUST-20, SHLD-11). gVisor는 최대 재전송 15번을 기본으로 둔다(`snd.go:50`, `protocol.go:620`). 최초 전송도 포함하는 `xmitCount`가 15를 넘었는지를 다음 RTO에서 검사하므로 마지막 재전송 뒤 기다릴 시간도 있다(`snd.go:674-680`, `:1814-1822`).

### 4.6 창과 흐름 제어

1. 받는 쪽은 창의 오른쪽 끝(RCV.NXT+RCV.WND)을 왼쪽으로 옮기지 않는 것이 SHOULD다(SHLD-14). 물리 버퍼의 빈 바이트 수만으로 이미 약속한 수신 시퀀스 범위를 줄이지 않는다(3.8.6·3.8.6.2.2). 보내는 쪽은 창 축소를 견뎌야 하고(MUST-34), 새 데이터는 보내지 않되 이미 보낸 미확인 데이터의 재전송은 별도로 다룬다(SHLD-15·16).
2. **0 창 탐침**: 상대의 창이 0이면 주기적으로 탐침해야 한다(MUST-36). 첫 탐침은 창이 RTO만큼 0이었을 때, 간격은 지수로 늘린다(SHLD-29, SHLD-30). 상대가 탐침에 ACK하는 한 연결을 유지한다(MUST-37).
3. **SWS 회피**: 보내는 쪽(MUST-38)은 `U = SND.UNA + SND.WND - SND.NXT`, 보낼 데이터 D에 대해 ① `min(D,U) >= Eff.snd.MSS`이거나 ② PUSH된 밀린 데이터를 모두 보낼 수 있거나(`D <= U`) ③ `min(D,U) >= Max(SND.WND)/2`이거나 ④ 덮어쓰기 타이머(0.1~1초)가 만료되면 보낸다(3.8.6.2.1). Nagle을 켜면 ②·③에는 `SND.NXT = SND.UNA`도 요구한다. 덮어쓰기 타이머는 창이 0인 때뿐 아니라 0이 아닌 작은 창에서의 교착도 풀어야 한다. 받는 쪽(MUST-39)은 `RCV.BUFF - RCV.USER - RCV.WND >= min(RCV.BUFF/2, Eff.snd.MSS)`가 될 때까지 창의 오른쪽 끝을 올리지 않는다(3.8.6.2.2).
4. **지연 ACK**(3.8.6.3, RFC 5681 4.2): 구현이 SHOULD이고(SHLD-18), 미루는 시간은 0.5초 미만이어야 하고(MUST-40), 꽉 찬 세그먼트 둘마다 적어도 한 번 ACK하는 것이 SHOULD다(SHLD-19). 순서가 어긋난 데이터와 빈 곳의 전부나 일부를 메우는 데이터에는 즉시 ACK가 SHOULD다(RFC 5681 4.2). 여기서 2×MSS 기준의 MSS는 수신자가 광고한 RMSS다(RFC 9293 3.8.6.3). 세그먼트 하나에 ACK를 둘 이상 내지 않는다(창 갱신은 예외, RFC 5681 4.2).
5. **창 확장**(RFC 7323 2.3): SYN에 Window Scale 옵션이 왔을 때만 SYN-ACK에 싣는다. 양쪽 SYN에 다 있어야 켜지고, 아니면 두 shift 모두 0이다. SYN의 창 필드는 확장하지 않는다. 그 밖의 세그먼트는 받을 때 `SND.WND = SEG.WND << Snd.Wind.Shift`, 보낼 때 `SEG.WND = RCV.WND >> Rcv.Wind.Shift`. shift는 14까지다. gVisor는 자동 조정이 켜져 있으면 최대 수신 버퍼, 꺼져 있으면 현재 수신 버퍼로 shift를 고른다(`endpoint.go:3220-3237`). `FindWndScale`은 창이 65,536 미만이면 0, 아니면 `65535 << s`가 창 이상이 되는 가장 작은 s를 고르되 14를 상한으로 둔다(`connect.go:199-212`).
   창 확장의 양자화 때문에 가장 최근 광고 창 끝이 작아질 수 있어도, 수신자는 이전 ACK에서 창 안이었던 세그먼트를 계속 받아들여야 한다. 실제 최대 수신 창 끝을 따로 추적하는 것이 SHOULD다. 송신자의 최초 전송은 최신 ACK의 창 안이어야 한다(RFC 7323 2.4).
6. Nagle은 SHOULD이고(SHLD-7) 끌 수 있어야 한다(MUST-17, RFC 9293 3.7.4).
7. keep-alive는 선택이다(MAY-5). 넣는다면 연결마다 켜고 끌 수 있어야 하고(MUST-24) 기본은 꺼짐이며(MUST-25) 유휴 간격의 기본은 2시간 이상이다(MUST-28). 탐침은 보통 `SEG.SEQ = SND.NXT-1`이고 데이터 없는 ACK가 권고다(3.8.4 SHLD-12). 미확인 송신 데이터가 없고 유휴 간격 동안 데이터·ACK를 받지 않았을 때만 보내며(MUST-26), 간격을 설정할 수 있어야 한다(MUST-27). 탐침 하나에 답이 없다고 죽었다고 보지 않는다(MUST-29).

### 4.7 혼잡 제어 (RFC 5681, RFC 6582)

필수는 slow start, congestion avoidance, RTO의 지수 물러나기다(RFC 9293 3.8.2 MUST-19).

1. 변수: cwnd, ssthresh. 전체 미확인 데이터의 한도는 `min(cwnd, SND.WND)`이고, 새로 보낼 양은 여기서 FlightSize를 뺀 범위다(RFC 5681 2·3.1).
2. 초기 창의 상한: RFC 5681 3.1은 SMSS에 따라 2~4 세그먼트, RFC 6928(실험)은 `min(10*MSS, max(2*MSS, 14600))`이다. gVisor의 `InitialCwnd`는 10 세그먼트다(`snd.go:41`). RFC 6928 2절은 SYN·SYN-ACK의 ACK로 IW를 늘리지 않으며, SYN 손실 뒤에도 IW를 무조건 1로 줄이지 않는 수정과 손실이 난 초기·재시작 창 뒤 RW를 RFC 3390 수준으로 줄이는 권고도 포함한다.
3. slow start(`cwnd < ssthresh`): 새 데이터를 확인하는 ACK마다 `cwnd += min(N, SMSS)`(N은 새로 확인된 바이트, 식 2). congestion avoidance: 새 데이터를 확인하는 ACK마다 `cwnd += SMSS*SMSS/cwnd`(허용된 식 3). 정수 나눗셈이 0이면 1바이트로 올리는 것이 SHOULD다. RTT마다 증가는 SMSS 이하여야 하고, `cwnd == ssthresh`일 때는 두 방식을 택할 수 있다(3.1).
4. RTO로 아직 재전송하지 않은 세그먼트의 손실을 처음 RTO로 감지하면 `ssthresh <= max(FlightSize/2, 2*SMSS)`(식 4), 같은 세그먼트의 반복 RTO에서는 ssthresh를 유지한다. RTO 뒤 cwnd는 1 SMSS(loss window) 이하다(RFC 5681 3.1). fast retransmit 진입에서도 식 4가 상한이다(3.2 단계 2).
5. fast retransmit·fast recovery(RFC 5681 3.2): 중복 ACK 셋째에서 ssthresh를 식 4로 잡고(단계 2), SND.UNA의 세그먼트를 다시 보내고 `cwnd = ssthresh + 3*SMSS`(단계 3), 중복 ACK가 더 올 때마다 `cwnd += SMSS`(단계 4), 창이 허락하면 새 데이터를 보낸다(단계 5), 새 데이터를 확인하는 ACK가 오면 `cwnd = ssthresh`(단계 6).
6. NewReno(RFC 6582 3.2): 변수 `recover`를 ISS로 시작한다. 중복 ACK 셋째에서 `SEG.ACK - 1 > recover`일 때만 fast retransmit에 들어가고 `recover = 지금까지 보낸 가장 높은 번호`로 둔다. 회복 중의 ACK가 recover까지 모두 확인하면(full ACK) `cwnd = min(ssthresh, max(FlightSize, SMSS) + SMSS)` 또는 ssthresh로 하고 나온다. 아니면(partial ACK) 첫 미확인 세그먼트를 다시 보내고, cwnd를 새로 확인된 만큼 줄이고, 1 SMSS 이상 확인됐으면 SMSS를 더하고, 회복을 계속한다. 첫 partial ACK에서는 재전송 타이머를 다시 켠다. RTO가 만료되면 recover에 가장 높은 번호를 적고 회복에서 나온다.
7. 중복 ACK의 정의(RFC 5681 2): 미확인 데이터가 있고, 데이터가 없고, SYN·FIN이 없고, ACK 번호가 지금까지의 최댓값과 같고, 광고한 창이 직전 ACK와 같다.
8. **데이터를 보내지 않은 시간**이 RTO보다 길었으면 cwnd를 `min(IW, cwnd)` 이하로 줄이는 것이 SHOULD다(RFC 5681 4.1).

### 4.8 옵션과 기능: 상호 운용에 필수인가

| 기능 | 규격의 요구 | 빼면 | gVisor(Tailscale 설정) |
| --- | --- | --- | --- |
| MSS 옵션 보내기·받기 | 양쪽 기능 구현은 필수(MUST-14). 매 SYN 광고는 기본값과 다르면 SHOULD(SHLD-5). 못 받으면 IPv4 536, IPv6 1220(MUST-15) | 옵션 생략만으로 연결이 안 되는 것은 아니다. 규격상 상대의 기본 전송 한도는 IPv4 536·IPv6 1220 | 광고한다(`connect.go:584-590`). 단, 수신 옵션이 없을 때 이 버전 파서는 IP 계열과 관계없이 536을 기본으로 쓴다(`gvisor/header/tcp.go:439-450`, `connect.go:748-755`) |
| 체크섬 | 필수 | 상대가 버린다(3.1) | 검사한다 |
| 창 확장 | 선택(RFC 7323). 한쪽이 안 보내면 꺼진다 | 창이 65,535바이트로 묶인다 | 보낸다(`connect.go:585`) |
| SACK | 선택(RFC 2018 2·4). 각 방향에서 상대 SYN의 SACK-Permitted를 받아야 SACK 블록을 보낼 수 있다(4절 MUST NOT) | 한 창에 손실이 여럿이면 회복이 느리다 | 켜져 있다(`protocol.go:610`). 상대가 허용할 때만 쓴다. SYN 옵션 순서는 MSS, NOP 둘과 SACK-Permitted, NOP와 WS(`connect.go`의 `makeSynOptions`), 블록은 NOP 둘 뒤에 싣고 ESTABLISHED에서 순서가 어긋난 세그먼트를 쥔 동안의 ACK에만 싣는다(같은 파일 `makeOptions`·`sendRaw`). 블록 목록은 새 세그먼트의 블록을 맨 앞에 두고 겹치는 블록을 합친다(`sack.go`의 `UpdateSACKBlocks`) |
| 타임스탬프 | 선택(RFC 7323 3.2). 양쪽 SYN에 있어야 켜진다. 켜지면 RST가 아닌 모든 세그먼트에 실어야 한다 | 재전송 중에 RTT를 재지 못한다. PAWS가 없다 | SYN에 싣는다(`connect.go:586`) |
| RFC 5961 | RST·SYN 완화는 SHOULD, ACK 범위 검사는 MAY(3.2·4.2·5.2) | 구 RFC 793 동작이면 창 안 RST·SYN으로 연결이 끊길 수 있다 | 동기화 상태의 RST·SYN 규칙을 따른다(`connect.go:1227-1239`, `:1333-1360`). SYN-RECEIVED와 TIME-WAIT의 차이는 4.2 |
| 지연 ACK | SHOULD(RFC 9293 3.8.6.3) | ACK 수가 늘 수 있지만 수신 묶음·piggyback에 따라 다르다 | 시간으로 미루지 않고 수신 묶음 끝에서 필요하면 ACK한다(`connect.go:1272-1306`). 순서가 어긋나면 즉시 ACK(`rcv.go:482-515`). `SetQuickAck(true)`만으로 추정한 결론이 아니다 |
| Nagle | SHOULD | 작은 쓰기가 작은 세그먼트로 나간다 | 스택 옵션(`TCPDelayEnabled`)이 켜졌을 때만(`endpoint.go:921-924`). Tailscale 생성 경로는 이를 켜지 않는다(`netstack.go:388-435`, `protocol.go:598-625`) |
| keep-alive | MAY | 죽은 상대와의 유휴 연결이 남는다 | Tailscale이 받는 연결마다 켠다(5절) |
| urgent | MUST-30 | urgent 데이터를 보통 데이터로 읽는다 | 읽지 않음 |
| ECN | SHOULD(RFC 9293 3.8.2 SHLD-8) | 손실 기반 혼잡 감지를 쓴다(RFC 5681 3절) | 미지원이라고 적고 ECN 비트를 지운다(`endpoint.go:1943-1954`) |

### 4.9 RFC 5961의 속도 제한

challenge ACK는 속도를 제한하는 것이 SHOULD다. 예로 든 값은 5초에 10개다(RFC 5961 7). 타이머 없이 시각과 세는 값으로 구현할 수 있다.

## 5. Tailscale netstack(gVisor)의 설정

| 항목 | 값 | 근거 |
| --- | --- | --- |
| 혼잡 제어 | CUBIC | `netstack.go:406-407` |
| 손실 회복 | 기본 RACK 끔. `TS_NETSTACK_ENABLE_RACK=true`일 때만 켠다. RACK이 꺼졌을 때 SACK 협상 성공이면 SACK 회복, 아니면 Reno 회복 | 실제 설정 `netstack.go:412-418`(위 `:141-153` 주석의 기본값 설명과 불일치하므로 실행 분기를 기준으로 한다), `gvisor/transport/tcp/snd.go:356-361` |
| SACK | 켜짐(gVisor 기본). 능동 SYN에서 제안하고 수동 SYN-ACK에서는 상대가 허용했을 때만 광고 | `gvisor/transport/tcp/protocol.go:610`, `connect.go:584-603`, `endpoint.go:3271-3281` |
| 창 확장 | 능동 SYN에서 제안, 수동 SYN-ACK는 상대 SYN에 있을 때만. 자동 조정 기본 설정의 shift는 !iOS 8, iOS 7(최대 수신 버퍼로 계산) | `connect.go:199-212`, `:584-603`, `endpoint.go:3200-3207`, `:3220-3237`, 아래 버퍼 상한 |
| 타임스탬프 | 능동 SYN에서 제안, 수동 SYN-ACK는 상대 SYN에 있을 때만 | `connect.go:584-603`, `endpoint.go:3249-3255` |
| 받는 버퍼(최소/기본/최대) | 4KiB / 1MiB / 8MiB. iOS는 최대 4MiB | `tailscale.com/wgengine/netstack/netstack_tcpbuf_default.go:12-20`, `netstack_tcpbuf_ios.go:17-23`, `netstack.go:309-345`, `gvisor/transport/tcp/protocol.go:41-52` |
| 보내는 버퍼(최소/기본/최대) | 4KiB / 1MiB / 6MiB. iOS는 최대 4MiB | 같은 곳 |
| 받는 버퍼 자동 조정 | 켜짐 | `gvisor/transport/tcp/protocol.go:613`, `endpoint.go:916-918` |
| 순서가 어긋난 세그먼트 | 순서 대기열의 메모리 사용량 + 새 payload 길이가 받는 버퍼의 75% 미만일 때만 큐에 더한다 | `gvisor/transport/tcp/rcv.go:488-510` |
| NIC MTU | 1280(`TS_DEBUG_MTU`로 바꿀 수 있다) | `netstack.go:434`, `tailscale.com/net/tstun/mtu.go:79`, `:133-148` |
| 광고하는 MSS | 경로 MTU − 20. 경로 MTU는 NIC MTU − IP 머리(IPv4 20, IPv6 40) → IPv4 1240, IPv6 1220 | `gvisor/transport/tcp/endpoint.go:638-648`, `gvisor/network/ipv4/ipv4.go:419-425`, `gvisor/network/ipv6/ipv6.go:736-742` |
| 초기 cwnd | 10 세그먼트 | `snd.go:41` |
| RTO | 처음 1초, 하한 200ms, 상한 120초 | `connect.go:41`, `snd.go:32`, `:35` |
| 재전송 한도 | 15번 | `snd.go:50` |
| SYN·SYN-ACK 재전송 | 무응답이면 1·3·7·15·31·63초에 재전송, 127초에 실패(계산값). 실제 종료 조건은 간격의 120초 상한 | `connect.go:181`, `:621-643`, `:721-736`. `protocol.go:68`의 6이라는 상수만으로 추정하지 않는다 |
| 중복 ACK 문턱 | 3 | `snd.go:45` |
| keep-alive | 받는 연결마다 켠다. 유휴 2시간, 간격 75초, 9번(환경 변수 `TS_NETSTACK_KEEPALIVE_IDLE`·`_INTERVAL`로 줄일 수 있다) | `netstack.go:125-139`, `:1677-1702`, `protocol.go:72-80` |
| TIME-WAIT, linger | 60초, 60초 | `protocol.go:56`, `:64` |
| 맺는 중인 연결의 상한 | 모바일 1,024, Linux 8,192, 그 밖(macOS) 2,048. 상대 하나는 그 2/3 | `netstack.go:85-105`, `:111-120`, `:669` |
| 상한을 넘은 SYN | 응답 없이 버린다 | `gvisor/transport/tcp/forwarder.go:88-92` |
| GRO·GSO | Linux이고 `buildfeatures.HasGRO`일 때 활성화 | `netstack.go:427-433` |

### 5.1 작은 MSS와 0 창 탐침의 구현 차이

- 상대가 광고한 0이 아닌 MSS를 gVisor는 최소 **48**로 올린다(`gvisor/header/tcp.go:463-470`). 이는 `TCPMinimumSendMSS = TCPOptionsMaximumSize(40) + MinIPFragmentPayloadSize(8)`이다(`gvisor/header/tcp.go:208`, `:228-230`, `gvisor/header/ipv4.go:138-140`). `MaxSegOption`으로 응용이 지정하는 MSS의 최소 **88**(`endpoint.go:1957-1964`, `gvisor/header/tcp.go:224-226`)과 다르다. 광고 MSS 0은 옵션 파싱을 중단하고 그때까지의 기본값을 유지한다(`gvisor/header/tcp.go:442-465`).
- 이 최소값 보정은 고정 버전의 구현 동작이지 RFC 9293 3.7.1 MUST-16의 허용 규칙이 아니다. 상대 MSS보다 큰 데이터를 보내면 그 상대의 수신 한도를 넘는다. Swiftail의 임의 64바이트 하한도 같은 위험이 있다. MSS가 너무 작아 지원할 수 없으면 그 한도를 지키거나 연결 시도를 거절하는 정책을 명시해야 한다(같은 절의 effective send MSS 식).
- gVisor의 0 창 탐침은 `SND.UNA-1`에 0 한 바이트를 실은 ACK이며, 이미 확인된 번호로 응답을 유도한다(`snd.go:1009-1034`). 이는 새 데이터가 있으면 최소 한 바이트를 보내거나 재전송하라는 RFC 9293 3.8.6.1의 서술과 구별된다. 간격은 현재 RTO부터 두 배씩 최대 120초, ACK 없는 탐침 15개 뒤 다음 만료에서 실패하고, 답 ACK를 받으면 미응답 수를 줄인다(`snd.go:597-608`, `:664-670`, `:1018-1034`, `:1631-1634`).

### 5.2 피어 제거와 열린 연결

- netmap 갱신은 `UpdateNetstackIPs`를 부른다(`tailscale.com/ipn/ipnlocal/local.go:7476-7481`). 이 함수는 자기 주소·서비스 주소를 갱신하며, 피어별 node 키를 열린 TCP 연결에 연결해 제거하거나 주소 주인 변경 때 abort하는 분기는 없다(`netstack.go:729-835`). TCP의 상대 식별자는 IP·포트 4-튜플이다(`gvisor/stack/registration.go:34-51`, `connect.go:644-654`).
- **정적 소스 대조 결과**, 피어가 netmap에서 빠졌다는 사실만으로 gVisor TCP 연결을 즉시 닫지 않는다. 무응답이면 데이터 재전송·keep-alive·응용의 취소/닫기가 끝내며, 수신 연결의 기본 keep-alive는 2시간부터다(`netstack.go:125-139`, `:1677-1702`, `gvisor/transport/tcp/connect.go:1401-1465`). 스택 전체 종료는 별개로 모든 등록 엔드포인트를 Abort한다(`netstack.go:471-477`, `gvisor/stack/stack.go:2064-2067`). 같은 IP를 다른 키가 물려받는 상황의 패킷 시험은 하지 않았으므로, 실제 전송이 이어지는지는 확인하지 못했다. Swiftail의 `peerRemoved`는 이 Go 동작의 복제가 아니라 별도 보호 정책이다.

## 6. tsnet `Listen`·`Dial`

### 6.1 `Listen(network, addr)` (`tsnet.go:1321-1323`, `:2115-2158`)

1. `network`는 빈 문자열·`tcp`·`tcp4`·`tcp6`(와 `udp`·`udp4`·`udp6`)를 받는다(`tsnet.go:2115-2119`). `addr`의 호스트는 비었거나 IP 리터럴이어야 한다. `0.0.0.0`·`::`는 빈 호스트와 같다(`tsnet.go:2069-2096`).
2. 호스트가 빈 리스너는 **자기 노드의 tailnet IPv4·IPv6 주소로 온 것만** 받는다. `tcp`는 두 계열을 다 받는다(`tsnet.go:1238-1266`).
3. 같은 (network, 주소, 포트)에 이미 리스너가 있으면 오류다(`tsnet.go:2209-2213`).
4. 기본 가짜 TUN 모드의 포트 0은 10002…19999에서 고른다(`tsnet.go:2111-2112`, `:2189-2196`). 실제 TUN 모드의 TCP 리스너는 gVisor에 맡긴다(`tsnet.go:2131-2146`).
5. `Listen`은 노드를 시작하지만 `Running`을 기다리지 않는다(`tsnet.go:2124-2126`).

### 6.2 들어오는 연결의 길

1. tsnet의 기본(가짜 TUN)에서는 자기 주소로 온 패킷을 모두 netstack이 처리한다(`tsnet.go:921-927`).
2. 패킷은 WireGuard 복호화 → 필터를 거친 뒤 netstack에 들어간다(`netstack.go:1472-1512`의 `injectInbound`는 `tstun` 래퍼의 필터 뒤 훅이다). 이 훅의 등록은 `netstack.go:465`, 필터 호출 뒤 훅 순서는 `tailscale.com/net/tstun/wrap.go:1193-1248`이다. Swiftail 필터는 새 연결(SYN, ACK 없음)만 ACL 규칙에 견준다(`Sources/SwiftailEngine/PacketFilter.swift:14`, `:84-88`).
3. 기존 연결로 배달되지 않은 SYN(ACK 없음, 체크섬 맞음)을 forwarder가 받으며, 같은 4-튜플의 진행 중 요청이 있거나 상한에 닿으면 새 요청을 만들지 않고 버린다. 나머지는 요청을 만들고(`gvisor/transport/tcp/forwarder.go:66-104`) `acceptTCP`가 처리한다(`netstack.go:1602`).
4. `acceptTCP`는 `GetTCPHandlerForFlow`(tsnet의 리스너 찾기)를 부른다. 리스너가 없으면 **RST**(`netstack.go:1748-1754`, `tsnet.go:1289-1303`). 있으면 엔드포인트에서 비동기로 핸드셰이크를 시작하고 keep-alive를 켠 뒤 리스너에 넘긴다. 맺어지기 전에는 연결의 `RemoteAddr`·`LocalAddr`가 nil일 수 있으며, 읽기·쓰기는 핸드셰이크 완료를 기다린다(`netstack.go:1666-1720`, `:1748-1759`).
5. 기본 가짜 TUN 모드에서 리스너의 `Accept`가 전달 시작부터 1초 안에 받아 가지 않으면 그 연결을 닫는다(`tsnet.go:2406-2418`). 통로에 버퍼가 없다(`tsnet.go:2349`). 실제 TUN 모드의 `Accept`는 gVisor 리스너로 바로 위임하므로 이 1초 규칙의 대상이 아니다(`tsnet.go:2359-2365`).
6. 연결이 없고 RST가 아닌 유효한 세그먼트에는 gVisor가 RST로 답한다. 받은 RST·체크섬 오류에는 답하지 않는다(`gvisor/transport/tcp/protocol.go:185-199`, 4.2).
7. 서비스 IP의 TCP는 53(DNS)과 몇 포트만 받고 나머지는 RST다(`netstack.go:1724-1735`, `:1770-1787`). Swiftail은 M5에서 모두 RST로 답한다(터널 계약 D4).

### 6.3 `Dial(ctx, network, address)` (`tsnet.go:382-390`)

1. `Running`이 될 때까지 기다린다(`tsnet.go:383-389`의 `Start`·`awaitRunning`).
2. 주소 해석(`tailscale.com/net/tsdial/tsdial.go:401-417`, `:423-436`): IP 리터럴이면 그대로. 아니면 소문자로 바꾸고 끝 점을 뗀 이름을 netmap에서 찾는다. 피어의 FQDN, 짧은 이름, `ExtraRecords`를 받는다(`tailscale.com/net/tsdial/dnsmap.go:14-18`, `tailscale.com/ipn/ipnlocal/resolve.go:54-75`). `tcp`면 그 노드의 IPv4를 먼저 고르고 없으면 IPv6다(`tailscale.com/ipn/ipnlocal/resolve.go:115-143`).
3. netmap에 없는 이름은 `net.Resolver`로 찾는다. 보통 시스템 DNS지만 exit-node DoH가 설정되고 관련 build feature가 있으면 그 리졸버를 쓴다(`tailscale.com/net/tsdial/tsdial.go:438-470`).
4. 주소가 어느 피어의 것이면(`PeerForIP`) netstack으로 건다. 출발 주소는 목적지와 같은 계열의 자기 tailnet 주소다(`tsnet.go:935-950`). 그 밖에서도 Tailscale 경로이면 peer dialer, 아니면 system/std dialer로 간다. 따라서 `PeerForIP` 실패가 곧바로 OS 직접 연결이라는 뜻은 아니다(`tailscale.com/net/tsdial/tsdial.go:608-638`).
5. 돌려주는 연결(`gonet.TCPConn`)에는 `CloseWrite`·`CloseRead`가 있다(`gvisor/adapters/gonet/gonet.go:446`, `:457`).

## 7. MTU와 MSS

- Tailscale TUN의 기본 MTU는 1280이다(`tailscale.com/net/tstun/mtu.go:79`). 첫 사용처의 터널도 1280…1420이다(터널 계약 동작 U1).
- MTU 1280에서 MSS는 IPv4 1240(1280 − 20 − 20), IPv6 1220(1280 − 40 − 20)이다. 기본 NIC MTU를 쓰는 gVisor 피어의 광고값도 이 계산이다(5절의 소스).
- **보낼 데이터 길이**는 RFC 9293 3.7.1 MUST-16의 `min(SendMSS+20, MMS_S) − TCPhdrsize − IPoptionsize` 이하다. MTU 1280·기본 IP 머리라면 `min(SendMSS, 1280 − 고정 IP 머리 − 20) − TCP 옵션 길이 − IP 옵션/확장 헤더 길이`다. 상대 MSS 쪽 한도에서도 옵션 길이를 빼야 하며, 광고 MSS 자체에서는 고정 머리만 뺀다(같은 절 MUST-67).
- 엔진은 조각난 패킷을 받지 않는다(`Sources/SwiftailEngine/IPPacket.swift:167`, `:183`). 자기 NIC의 MTU에 MSS를 맞추는 것만으로 경로 중간의 더 작은 MTU까지 보장하지는 않는다. IPv4는 중간 경로 MTU·DF에 따라 단편화되거나 버려질 수 있다(RFC 791 2.3·3.1). IPv6는 1280 이하로 보내면 PMTUD를 생략할 수 있으나, IPv6 일반 노드의 재조립 요구까지 면제되지는 않는다(RFC 8200 5). tailnet MTU 1280이라는 전제와 IP 옵션 길이 차감이 필요하다.

## 8. 첫 사용처가 쓰는 범위

첫 사용처 저장소의 커밋 `286c214`에서 읽었다. 이 절의 경로·줄 번호는 그 커밋 기준이며 현재 작업 파일의 상태를 뜻하지 않는다.

1. **Mac 호스트**: `Running`이고 아직 듣지 않을 때 리스너를 연다(`core/internal/node/node.go:604-608`). TLS 경로는 `Up` 뒤 `srv.Listen("tcp", ":<port>")`을 `tls.NewListener`(`GetCertificate`)로 감싸며(`core/internal/node/tls.go:22-41`), 비TLS 경로는 `srv.Listen`을 직접 쓴다(`core/internal/node/node.go:780-791`). 기본 포트는 443(`core/internal/node/config.go:104-105`). `http.Server`는 `ReadHeaderTimeout` 10초·`IdleTimeout` 60초로 `Serve`한다(`core/internal/node/node.go:812-818`).
2. tailnet 요청의 `identify`는 `r.RemoteAddr`로 WhoIs를 부른다(5초 제한). 직접 연결의 인증된 peer가 context에 있으면 이 조회를 생략한다(`core/internal/host/host.go:230-244`). tailnet 연결에는 원격 주소가 필요하다.
3. **주고받는 양**: 서버 → 클라이언트에는 IPA의 Range 전송(`docs/protocol.md:53`, `docs/protocol-addenda.md:140-156`)과 파일 전송(하나에 4GiB까지, Range·HEAD 지원, `docs/protocol-addenda.md:334-355`)이 있다. 로그 본문은 전체 4MB까지다(`docs/protocol-addenda.md:484`). 모든 요청 본문의 상한이 같다는 뜻은 아니다.
4. **상대의 TCP 스택에 관한 경로 추론**: iPhone의 일반 VPN 경로(`docs/tunnel.md:9-14`)에서 시스템 URLSession·설치기와 파일의 백그라운드 전송, 공식 Tailscale 앱 뒤 Safari를 쓰므로(`docs/protocol.md:236`, `docs/protocol-addenda.md:219`, `:355`) 상대는 커널 TCP일 것으로 본다. 프록시 모드의 `srv.Dial` 상대는 tsnet/gVisor 경로다(아래 5와 6.3). 실제 SYN 캡처로 스택·옵션을 식별하지는 않았다.
5. **프록시 모드**: 노드는 `srv.Dial`을 프록시의 dial 함수로 넘긴다(`core/internal/node/node.go:952`). 프록시는 허용한 CONNECT 대상에 `"tcp"`로 15초 제한을 두고 걸어 원격 주소가 tailnet인지 확인한다(`core/internal/proxy/proxy.go:17`, `:116-137`). 두 방향을 복사하며 정상 EOF이고 지원되면 `CloseWrite`로 반닫고, 오류면 양쪽을 닫는다(`core/internal/proxy/proxy.go:156-176`). 진단용이라는 범위는 `docs/tunnel.md:14`다.
6. **제품 경로와 시험 도구를 구별한다**: 위 `core/internal/node/` 제품 경로는 `Listen`·`Dial`·`Up`·`LocalClient`·`Start`·`Close`를 쓴다(`core/internal/node/node.go:349`, `:421`, `:790`, `:952`, `:1004`, `core/internal/node/tls.go:23-37`). 하지만 `core/` 전체가 그것만 쓴다는 기존 주장은 틀렸다. 시험 도구는 `HTTPClient`(`core/cmd/rdtestenv/main.go:140`, `core/e2e/helpers_test.go:82`)와 `ListenPacket`(`core/e2e/tunnel/tunnel_test.go:192`)도 쓴다.

## 9. Swiftail에 필요한 최소 부분

계약 `docs/contracts/SwiftailNetstack.md`의 "지원 범위"가 정한다. 이 노트의 근거로 넣을 수 있는 것과 뺄 수 있는 것:

- 규격상 필수인 부분: 체크섬(RFC 9293 3.1 MUST-2·3), MSS 옵션 송수신 기능(3.7.1 MUST-14), 상태별 세그먼트 처리(3.10.7), RFC 6298의 재전송 타이머(3.8.1 MUST-18), 0 창 탐침(3.8.6.1 MUST-36), slow start·congestion avoidance·RTO 물러나기(3.8.2 MUST-19). 모두가 단순히 "없으면 handshake 실패"인 것은 아니다. 특히 MSS 옵션 광고 생략은 기본 MSS로 연결할 수 있다(4.8).
- 기본 TCP 상호 운용에 선택적인 옵션: 창 확장·SACK·타임스탬프(RFC 9293 3.2.1). 창 확장이 없으면 창 필드 한도는 65,535다(RFC 7323 2절). 협상하지 않은 TS는 무시하고, 상대가 SACK-Permitted를 보내지 않았으면 SACK 블록을 보내면 안 된다(RFC 7323 3.2, RFC 2018 4의 MUST NOT). SACK-Permitted를 받은 뒤에도 SACK을 내는 것은 MAY다(RFC 2018 4 첫 문단). 따라서 이 옵션을 보내지 않는다는 사실만으로 상대가 연결을 거절해야 하는 규칙은 없다.
- 지연 ACK·Nagle·ECN은 SHOULD(각각 RFC 9293 3.8.6.3·3.7.4·3.8.2), keep-alive는 MAY(3.8.4)다. urgent와 동시 열기는 규격상 MUST(3.8.5 MUST-30, 3.5 MUST-10)이며 **선택 기능으로 분류하면 안 된다**. 계약에서 쓰지 않기로 한 범위 선택과 RFC 준수는 별개다. 이들의 배제는 위 첫 사용처 경로와 계약의 제외 표에 대한 구현 선택이며, 모든 TCP 응용과 상호 운용한다는 보장이 아니다.

## 10. 상호 운용 시험에서 확인할 것

아래는 시험 계획이다. 이번 문서 대조에서 패킷 시험을 실행한 결과가 아니다.

1. gVisor 피어가 Swiftail의 SYN·SYN-ACK를 받아 ESTABLISHED가 된다(체크섬, MSS, 창 확장 옵션).
2. 리스너 없는 포트로 온 SYN에 RST가 가고 Go의 `Dial`이 제한 시간 전에 거절로 끝난다.
3. 양방향 100MB 전송의 해시가 같다. 창 확장은 양쪽 SYN의 옵션과 협상한 shift로 해석한 창을 함께 확인한다. 와이어의 16비트 window 필드 자체가 65,535를 넘을 수는 없다(RFC 7323 2.2·2.3).
4. 손실 1%·5%에서 전송이 끝난다.
5. 반닫힘: 한쪽이 FIN을 보낸 뒤에도 반대 방향 데이터가 끝까지 간다.
6. Swiftail이 RST로 끊으면 Go 쪽 읽기가 reset 오류로 끝나고, Go가 끊으면 Swiftail이 reset으로 안다.
7. macOS·iOS 커널 스택이 상대일 때 1~6.

## 11. 확인하지 못한 것

공식 RFC 12개는 모두 내려받아 위에서 인용한 절을 읽었고, 필요한 Tailscale·gVisor 소스도 모두 있었다. 문서 다운로드 실패나 소스 누락으로 남긴 항목은 없다. 기존 미확인 항목 중 지연 ACK·SYN 재전송·MSS 최솟값·활성 옵션·피어 제거의 정적 경로는 4.2·4.3·5절에서 해소했다. 아래는 읽기·실행 범위를 명시적으로 남긴다.

1. gVisor CUBIC의 전체 창 갱신 알고리즘(`gvisor/transport/tcp/cubic.go`). CUBIC을 선택하는 Tailscale 설정만 확인했다(5절). Swiftail의 NewReno 근거는 RFC 5681·6582다.
2. macOS·iOS XNU의 기본 MSS·창 확장 shift·SACK·타임스탬프·지연 ACK 시간. XNU 소스와 실기기 SYN은 읽거나 캡처하지 않았다. 10절 관문에서 확인해야 한다.
3. 피어 제거·같은 IP의 키 변경·자기 주소 변경의 실제 연결 수명. 5.2는 정적 소스 결과이며 패킷 시험은 하지 않았다. 자기 주소 제거의 gVisor route 유효성까지 추적하지 않았으므로 피어 제거와 같은 결과라고 단정하지 않는다.
4. 첫 사용처 `http.Server`의 HTTP/2 사용 여부. `core/internal/node/tls.go:41`에 `NextProtos`가 없다는 것과 `core/internal/node/node.go:818`이 `Serve`를 부르는 것까지 확인했으며, 고정 Go toolchain의 TLS·net/http 자동 설정 경로와 ALPN은 대조하지 않았다.
5. RFC 6675·8985 본문, RFC 7323 5절 PAWS의 전체 처리 절차는 이번 범위에서 대조하지 않았다. SACK 생성 규칙은 RFC 2018 4절을 읽어 4.8·9절의 허용 조건을 확인했으나 전체 SACK 구현·회복 알고리즘 검증은 하지 않았다.
6. utun 생성의 관리자 권한 요구. XNU 소스를 읽지 않았으며, 저장소의 `docs/contracts/SwiftailTunnel.md` 시험 9의 전제만 확인했다.
7. gVisor의 SYN 127초와 ACK 전송 경로는 소스에서 계산·추적했다. 실행 시각·스케줄러 지연·실제 패킷 간격은 측정하지 않았다.
