# DERP와 STUN

기준은 `tailscale.com` v1.104.6이며 작성 모델은 GPT-6.1 Terra, 검증 상태는 미검증이다. (tailscale.com/derp/derp.go:46)

## 범위

DERP의 일반 노드 전송과 지역 선택, STUN 바인딩 및 로컬 시험을 다루며 WireGuard 암호화와 control의 지도 배포 절차는 다루지 않는다. DERP는 Curve25519 공개키를 주소로 하여 암호화된 WireGuard 패킷을 중계한다. (tailscale.com/derp/derp.go:4)

## 와이어 형식

### DERP 공통 헤더

오프셋은 프레임 시작 기준이며 길이는 헤더를 제외한다. 정수는 big-endian이다. (tailscale.com/derp/derp.go:51)

| 오프셋 | 길이 | 필드 | 인코딩 |
| --- | --- | --- | --- |
| 0 | 1 | type | 아래 표 |
| 1 | 4 | length | uint32, 페이로드 바이트 수 |
| 5 | length | payload | 타입별 아래 표 |

아래 오프셋은 **페이로드 시작 기준**이다. C는 클라이언트, S는 서버다. 가변 길이 프레임의 나머지는 해당 프레임의 `length`로 결정한다. (tailscale.com/derp/derp.go:51)

| 타입 | 방향 | 오프셋·길이·내용 |
| --- | --- | --- |
| `FrameServerKey` `0x01` | S→C | 0:8 매직 `44 45 52 50 f0 9f 94 91`, 8:32 서버 공개키, 40:나머지 확장. (tailscale.com/derp/derp.go:30, tailscale.com/derp/derp.go:72) |
| `FrameClientInfo` `0x02` | C→S | 0:32 클라이언트 공개키, 32:24 nonce, 56:나머지 NaCl box JSON. (tailscale.com/derp/derp.go:73) |
| `FrameServerInfo` `0x03` | S→C | 0:24 nonce, 24:나머지 NaCl box JSON. (tailscale.com/derp/derp.go:74) |
| `FrameSendPacket` `0x04` | C→S | 0:32 목적지 공개키, 32:나머지 패킷. (tailscale.com/derp/derp.go:75) |
| `FrameRecvPacket` `0x05` | S→C | 버전 2에서 0:32 발신자 공개키, 32:나머지 패킷; 이전 버전 0/1에는 발신자 필드가 없다. (tailscale.com/derp/derp.go:46, tailscale.com/derp/derp.go:77) |
| `FrameKeepAlive` `0x06` | S→C | 빈 페이로드. (tailscale.com/derp/derp.go:78) |
| `FrameNotePreferred` `0x07` | C→S | 0:1, 홈이면 `01`, 아니면 `00`. (tailscale.com/derp/derp.go:79) |
| `FramePeerGone` `0x08` | S→C | 0:32 피어 공개키, 32:1 이유; 구형은 이유가 없으며 `0x00`으로 취급한다. `0x00`은 연결 종료, `0x01`은 서버가 경로를 모름; `0xf0`은 로컬 전용이다. (tailscale.com/derp/derp.go:81, tailscale.com/derp/derp.go:136, tailscale.com/derp/derp_client.go:604) |
| `FramePeerPresent` `0x09` | S→C | 0:32 공개키, 선택적 32:16 IP, 48:2 포트 BE, 50:1 flags, 51:1 이름 길이, 52:가변 AppName; 오래된 서버의 짧은 메시지도 허용한다. flags 비트 0/1/2/3은 regular/mesh/prober/not ideal이다. (tailscale.com/derp/derp.go:90, tailscale.com/derp/derp.go:146) |
| `FrameForwardPacket` `0x0a` | C→S, mesh | 0:32 발신자 키, 32:32 목적지 키, 64:나머지 패킷. (tailscale.com/derp/derp.go:76) |
| `FrameWatchConns` `0x10` | C→S, mesh | 빈 페이로드; 권한이 없으면 연결 종료. (tailscale.com/derp/derp.go:104) |
| `FrameClosePeer` `0x11` | C→S, mesh | 0:32 닫을 피어 공개키. (tailscale.com/derp/derp.go:112) |
| `FramePing` `0x12`, `FramePong` `0x13` | 양방향 | 0:8 불투명 바이트; pong은 ping 내용을 그대로 돌려준다. (tailscale.com/derp/derp.go:118, tailscale.com/derp/derp_client.go:466) |
| `FrameHealth` `0x14` | S→C | 0:전체 오류 텍스트; 빈 문자열은 정상으로 복귀. (tailscale.com/derp/derp.go:121) |
| `FrameRestarting` `0x15` | S→C | 0:4 `ReconnectIn`, 4:4 `TryFor`, 각각 BE uint32 밀리초. (tailscale.com/derp/derp.go:128) |

### STUN

요청의 정수는 BE이고 총 40바이트다. TxID는 암호학적 난수 12바이트다. (tailscale.com/net/stun/stun.go:29, tailscale.com/net/stun/stun.go:37, tailscale.com/net/stun/stun.go:48)

| 오프셋 | 길이 | 필드 | 인코딩 |
| --- | --- | --- | --- |
| 0 | 2 | type | binding request `00 01` |
| 2 | 2 | length | `00 14`, 헤더 뒤 20바이트 |
| 4 | 4 | magic cookie | `21 12 a4 42` |
| 8 | 12 | TxID | 난수 |
| 20 | 2 | SOFTWARE type | `80 22` |
| 22 | 2 | SOFTWARE length | `00 08` |
| 24 | 8 | SOFTWARE | ASCII `tailnode` |
| 32 | 2 | FINGERPRINT type | `80 28` |
| 34 | 2 | FINGERPRINT length | `00 04` |
| 36 | 4 | FINGERPRINT | 앞 32바이트의 IEEE CRC32 XOR `0x5354554e`; 헤더 length에는 이 속성도 포함. (tailscale.com/net/stun/stun.go:48, tailscale.com/net/stun/stun.go:73) |

응답 헤더는 오프셋 0:2가 `01 01`, 2:2가 속성 총 길이, 4:4가 같은 cookie, 8:12가 요청 TxID다. 각 속성은 0:2 타입, 2:2 값 길이, 4:길이 값 및 4바이트 정렬 패딩으로 구성된다. (tailscale.com/net/stun/stun.go:134, tailscale.com/net/stun/stun.go:154)

| 주소 속성 값 오프셋 | 길이 | 필드 | 인코딩 |
| --- | --- | --- | --- |
| 0 | 1 | reserved | 응답 생성 시 0 |
| 1 | 1 | family | `01` IPv4, `02` IPv6 |
| 2 | 2 | port | BE; XOR 속성에서는 `port XOR 0x2112` |
| 4 | 4 또는 16 | address | XOR 속성은 첫 4바이트에 cookie, IPv6 나머지 12바이트에 TxID를 각각 XOR; 일반 속성은 원래 주소 그대로. (tailscale.com/net/stun/stun.go:175, tailscale.com/net/stun/stun.go:252) |

`XOR-MAPPED-ADDRESS` 타입은 `0x0020`, 대체 타입은 `0x8020`, `MAPPED-ADDRESS`는 `0x0001`이며 XOR 값을 우선하고 없으면 일반 주소로 대체한다. (tailscale.com/net/stun/stun.go:17, tailscale.com/net/stun/stun.go:211)

## 절차와 상태 기계

1. `DERPRegion.Nodes`를 순서대로 시도하며 `STUNOnly`를 건너뛴다. 각 노드는 TCP IPv4/IPv6을 경쟁시키고 주소가 비어 있으면 `HostName`을 DNS로 사용하며 명시 주소가 잘못된 주소 계열이면 해당 계열을 끈다. TCP 연결에 성공한 첫 노드에서 TLS를 시작하므로 TLS 실패 시 같은 호출 안에서 다음 노드까지 자동으로 시도하는 것은 아니다. (tailscale.com/derp/derphttp/derphttp_client.go:640, tailscale.com/derp/derphttp/derphttp_client.go:684, tailscale.com/derp/derphttp/derphttp_client.go:721)
2. TLS ClientHello의 이름은 `HostName`이며 기본 포트는 443, `DERPPort`가 지정되면 그 값이다. `CertName`이 비어 있으면 `HostName`으로 인증하고, 이름이 있으면 그 이름으로 검증한다. `sha256-raw:` 뒤의 hex SHA256은 인증서 해시 고정이며 `InsecureForTests`는 테스트용 검증 비활성화다. (tailscale.com/derp/derphttp/derphttp_client.go:273, tailscale.com/derp/derphttp/derphttp_client.go:663, tailscale.com/derp/derphttp/derphttp_client.go:796, tailscale.com/tailcfg/derpmap.go:198)
3. 지역 클라이언트는 `GET /derp`에 `Upgrade: DERP`, `Connection: Upgrade`를 보내고 일반 경로에서 HTTP 101을 요구한다. 첫 노드가 아니면 `Ideal-Node`에 첫 노드 이름을 넣는다. TLS 1.3의 meta cert에서 서버 키와 버전을 찾은 경우 `Derp-Fast-Start: 1`을 보내 HTTP 응답과 서버 키 대기를 생략하고 인증 프레임을 이어 쓴다. 최적화를 생략하면 일반 경로로 동작한다. (tailscale.com/derp/derphttp/derphttp_client.go:488, tailscale.com/derp/derphttp/derphttp_client.go:511, tailscale.com/derp/derphttp/derphttp_client.go:530)
4. 일반 경로에서 `FrameServerKey`의 타입, 최소 40바이트와 매직을 검증하고 서버 공개키를 읽는다. 최대 1024바이트까지 허용하며 40바이트 뒤 확장 부분은 버린다. (tailscale.com/derp/derp_client.go:157)
5. `ClientInfo` JSON의 `version`은 2, `CanAckPings`는 응답 가능 여부이며 선택 필드는 `meshKey`, `IsProber`, `AppName`이다. 클라이언트 개인키와 서버 공개키, 무작위 24바이트 nonce, JSON 평문을 NaCl box에 넣고 `nonce || box`를 출력하여 클라이언트 공개키 뒤에 붙인다. 서버는 서버 개인키와 클라이언트 공개키로 인증 복호화하고 JSON과 `AppName`을 검증한다. (tailscale.com/derp/derp_client.go:194, tailscale.com/derp/derp_client.go:232, tailscale.com/types/key/node.go:130, tailscale.com/derp/derpserver/derpserver.go:1919)
6. `FrameServerInfo`는 서버 개인키, 클라이언트 공개키와 무작위 nonce로 봉한 JSON이며 클라이언트는 자신의 개인키와 서버 공개키로 연다. `version`, `TokenBucketBytesPerSecond`, `TokenBucketBytesBurst`가 필드다. 인증 실패, 짧거나 너무 긴 정보, 잘못된 JSON은 수신 오류다. Go는 이 프레임을 기다려야만 송신을 시작하지 않는다. (tailscale.com/derp/derpserver/derpserver.go:1903, tailscale.com/derp/derp.go:302, tailscale.com/derp/derp_client.go:174, tailscale.com/derp/derp_client.go:580)
7. 홈 연결에는 `NotePreferred(true)`를 알리고 홈이 바뀌면 열린 연결들에 각각 현재 홈 여부를 보낸다. 연결은 목적지 키를 프레임마다 지정하므로 여러 피어가 공유한다. 수신의 발신 키로 피어를 식별한다. (tailscale.com/wgengine/magicsock/derp.go:283, tailscale.com/derp/derp_client.go:254, tailscale.com/derp/derp_client.go:665)
8. keepalive에는 응답하지 않고 ping은 같은 8바이트 pong으로 답한다. 8바이트 미만 ping/pong 또는 restarting, 32바이트 미만 패킷과 peer 통지는 버리고, 알 수 없는 타입도 건너뛴다. `health`의 텍스트는 상태이며 빈 값은 해제다. `Restarting`은 재연결 대기와 재시도 총 시간에 대한 권고이고 재시도 간격은 정해져 있지 않다. (tailscale.com/derp/derp_client.go:478, tailscale.com/derp/derp_client.go:500, tailscale.com/derp/derp_client.go:580, tailscale.com/derp/derp_client.go:675)
9. 읽기 오류 후 해당 DERP 클라이언트는 다시 쓸 수 없으며 상위 계층이 연결을 새로 만든다. magicsock은 피어 경로를 지우고 재측정 및 재연결을 시도한다. 연속 실패 번호 `n`에 대해 `min(n² × 10ms, 5s) × [0.5, 1.5)`로 기다리며 성공 수신 시 초기화한다. (tailscale.com/derp/derp_client.go:519, tailscale.com/wgengine/magicsock/derp.go:558, tailscale.com/util/backoff/backoff.go:47)
10. STUN 응답은 최소 20바이트, 상위 2비트가 0, cookie 일치, 성공 타입, 선언된 속성 길이와 각 속성의 길이·패딩 및 주소 family/길이를 검사한다. 선언 길이 뒤의 바이트는 무시하며, 유효 주소가 없으면 오류다. netcheck는 TxID를 진행 중인 요청에 대조한다. 요청 파서는 추가로 SOFTWARE 값, 마지막 FINGERPRINT 및 CRC를 확인한다. 응답 파서가 FINGERPRINT를 확인하는 동작은 없다. (tailscale.com/net/stun/stun.go:83, tailscale.com/net/stun/stun.go:134, tailscale.com/net/stun/stun.go:193, tailscale.com/net/stun/stun.go:307, tailscale.com/net/netcheck/netcheck.go:331)

### 지도, 경로와 측정

`DERPMap`은 `HomeParams.RegionScore`, `Regions`와 `OmitDefaultRegions`를 가진다. 점수는 양수일 때 지연에 곱하며 누락은 1이고 nil 점수 맵은 변경 없음, 빈 맵은 초기화다. `DERPRegion`의 필드는 `RegionID`, `RegionCode`, `RegionName`, `Latitude`, `Longitude`, 구식 `Avoid`, `NoMeasureNoHome`, 순서 있는 `Nodes`다. `NoMeasureNoHome`은 홈 선택과 측정을 금지하지만 그 지역을 홈으로 광고한 피어와 통신하기 위한 연결은 허용한다. (tailscale.com/tailcfg/derpmap.go:15, tailscale.com/tailcfg/derpmap.go:49, tailscale.com/tailcfg/derpmap.go:109, tailscale.com/tailcfg/derpmap.go:145)

`DERPNode` 필드는 `Name`, `RegionID`, `HostName`, `CertName`, `IPv4`, `IPv6`, `STUNPort`, `STUNOnly`, `DERPPort`, `InsecureForTests`, `STUNTestIP`, `CanPort80`이다. `STUNPort` 0은 3478, -1은 비활성화이고 `STUNTestIP`는 시험용 재정의, `CanPort80`은 captive portal 검사에 쓰인다. (tailscale.com/tailcfg/derpmap.go:186, tailscale.com/tailcfg/derpmap.go:230)

홈은 netcheck의 `PreferredDERP`로 정하고 값이 없으면 기존 홈 또는 임의의 지역을 사용한다. control에 연결되지 않았고 기존 홈이 있으면 강제 변경이 아닌 한 홈을 유지한다. 홈 연결은 유지하고 피어의 홈 지역 연결이 이미 있으면 재사용하며, 없으면 수신에서 배운 유효한 역방향 `derpRoute`를 먼저 사용하고 그렇지 않으면 해당 지역에 연결한다. 패킷의 발신 공개키와 지역·연결을 경로로 기록하고 `PeerGone` 또는 수신 오류 때 일치하는 경로를 지운다. 홈 이외 연결은 마지막 쓰기 채널 요청 이후 60초가 지나면 15초 간격 정리에서 닫는다. (tailscale.com/wgengine/magicsock/derp.go:108, tailscale.com/wgengine/magicsock/derp.go:154, tailscale.com/wgengine/magicsock/derp.go:339, tailscale.com/wgengine/magicsock/derp.go:613, tailscale.com/wgengine/magicsock/derp.go:990, tailscale.com/wgengine/magicsock/derp.go:1071)

netcheck는 STUN 응답의 왕복 지연을 지역별로 기록하며 UDP 응답이 전혀 없으면 측정 가능한 지역에 HTTPS를 시도한다. HTTPS는 TLS 연결을 먼저 만든 뒤 `GET /derp/latency-check`의 요청 시간을 측정하고 299 초과 상태를 실패로 취급한다. 전체 보고 시간은 5초, STUN 대기는 최대 3초다. (tailscale.com/net/netcheck/netcheck.go:57, tailscale.com/net/netcheck/netcheck.go:684, tailscale.com/net/netcheck/netcheck.go:1000, tailscale.com/net/netcheck/netcheck.go:1149)

선택에는 현재 보고에서 응답한 지역들에 대해 최근 5분 5초 동안의 지역별 최소 지연과 `RegionScore`를 사용한다. 기존 지역이 접근 가능하면 현재 기존 지연과 새 후보의 차이가 10ms 미만이거나 후보가 기존 지연의 2/3보다 느릴 때 기존 지역을 유지한다. 최근 8초의 DERP 프레임도 접근 가능 신호이며, 지연 데이터가 없으면 최근 120초에 프레임이 있었던 기존 홈을 유지한다. (tailscale.com/net/netcheck/netcheck.go:1373, tailscale.com/net/netcheck/netcheck.go:1404, tailscale.com/net/netcheck/netcheck.go:1424)

지역별 magicsock 송신 큐는 32개이며 가득 차면 오래된 패킷을 꺼내고 새 패킷 삽입을 최대 3회 시도한 뒤 실패하면 새 패킷을 버린다. 서버도 목적지 큐가 가득 차면 앞의 패킷을 버려 공간을 만든다. 서버가 토큰 버킷을 광고하면 클라이언트는 초당 바이트·burst를 적용하고 헤더와 목적지 키를 포함한 바이트 수에 토큰이 없으면 대기하지 않고 패킷을 버리되 성공을 반환한다. (tailscale.com/wgengine/magicsock/derp.go:316, tailscale.com/wgengine/magicsock/magicsock.go:1696, tailscale.com/derp/derpserver/derpserver.go:2196, tailscale.com/derp/derp_client.go:266, tailscale.com/derp/derp_client.go:709)

## 상수와 타이머

| 항목 | 값과 범위 | 출처 |
| --- | --- | --- |
| `ProtocolVersion` | 2 | tailscale.com/derp/derp.go:46 |
| `MaxPacketSize` | 65536바이트, 프레임 오버헤드 제외 | tailscale.com/derp/derp.go:25 |
| 일반 수신 프레임 | 페이로드 1 MiB 초과면 오류 | tailscale.com/derp/derp_client.go:552 |
| 서버 clientInfo | 56바이트 미만 또는 256 KiB 초과 거부 | tailscale.com/derp/derpserver/derpserver.go:1927 |
| `MaxInfoLen` | 1 MiB; serverInfo 파서 상한은 nonce 24 + 이 값, 별도의 일반 수신 상한도 적용 | tailscale.com/derp/derp.go:34, tailscale.com/derp/derp_client.go:174, tailscale.com/derp/derp_client.go:556 |
| 연결 | 전체 10초; 노드 TCP 1.5초, IPv6 우선 시 IPv4 200ms 지연 | tailscale.com/derp/derphttp/derphttp_client.go:359, tailscale.com/derp/derphttp/derphttp_client.go:733, tailscale.com/derp/derphttp/derphttp_client.go:782 |
| keepalive와 읽기 | 서버 60초 + 0 이상 5초 미만 jitter, 클라이언트 읽기 제한 120초 | tailscale.com/derp/derp.go:41, tailscale.com/derp/derpserver/derpserver.go:2632, tailscale.com/derp/derp_client.go:519 |
| 비홈 유휴 정리 | 60초, 검사 주기 15초 | tailscale.com/wgengine/magicsock/derp.go:1071 |

## Swiftail 최소 부분과 생략

M3에서 로컬 서버 하나를 양쪽 피어가 홈으로 사용하도록 정하면 지역 탐색 없이도 해당 지역으로 연결하여 목적지 공개키와 패킷을 보내고, 발신 공개키와 패킷을 수신할 수 있다. 이는 단일 지역 구성에 대한 구현 선택이며 실제 노드 간 WireGuard 키·설정과 피어의 홈 정보는 별도로 필요하다. 일반 HTTP 업그레이드, 서버 키 검증, NaCl box 인증, 버전 2 패킷, 읽기 루프와 ping 대응이 핵심이다. (tailscale.com/tailcfg/derpmap.go:109, tailscale.com/derp/derp.go:56, tailscale.com/derp/derp_client.go:232)

고정 지역의 로컬 관문에서는 STUN 기반 지역 측정, HTTPS 폴백, 다중 지역 경로 최적화와 fast-start를 뒤로 미룰 수 있다. WebSocket은 별도의 선택 경로이고 일반 TCP/TLS HTTP 업그레이드 경로가 존재한다. mesh의 `MeshKey`, watch, forward, close는 신뢰된 서버 간 기능이며 일반 클라이언트에는 필요하지 않다. (tailscale.com/derp/derphttp/derphttp_client.go:400, tailscale.com/derp/derphttp/derphttp_client.go:437, tailscale.com/derp/derp_client.go:194, tailscale.com/derp/derp.go:104)

## 상호 운용 시험에서 확인할 것

1. Go 시험에서 `key.NewNode()`로 서버 키를 만들고 `derpserver.New(key, logf)`와 `derpserver.Handler(s)`를 HTTP 서버에 설치하며 loopback 임시 포트로 띄운다. TLS 시험은 `httptest.NewUnstartedServer(derpserver.Handler(s))` 후 `StartTLS()`를 사용하고, 시험 지역의 `DERPPort`와 `InsecureForTests: true`를 설정한 사례가 있다. 평문 시험 사례는 `TLSNextProto`를 빈 맵으로 설정하고 `http.Server.Serve`를 쓴다. (tailscale.com/derp/derphttp/derphttp_test.go:41, tailscale.com/derp/derphttp/derphttp_test.go:682)
2. `stuntest.Serve(t)`는 `testing.TB`를 받아 UDP4 임시 포트를 열고 주소와 cleanup을 돌려준다. 요청을 `ParseBindingRequest`로 검증한 뒤 관찰한 발신 주소를 `stun.Response`로 돌려주므로 요청 fingerprint와 TxID, XOR 주소를 검증할 수 있다. (tailscale.com/net/stun/stuntest/stuntest.go:31, tailscale.com/net/stun/stuntest/stuntest.go:57)
3. 두 클라이언트의 서로 다른 키로 양방향 payload와 수신 발신 키, 복수 목적지, ping echo, keepalive, 오류 후 재연결과 큐 포화를 확인한다. STUN은 IPv4·IPv6 XOR 및 일반 주소, 잘린 속성, 틀린 cookie·TxID·fingerprint를 시험한다. 각 오류 처리의 기준은 위 파서와 큐 동작이다. (tailscale.com/derp/derp_client.go:259, tailscale.com/derp/derp_client.go:604, tailscale.com/net/stun/stun.go:83, tailscale.com/net/stun/stun.go:193)

## 확인하지 못한 것

- NaCl box의 구체적인 내부 primitive 명칭과 인증 태그의 바이트 배치는 지정된 소스에서 직접 확인하지 못했다. 소스가 요구하는 API는 `golang.org/x/crypto/nacl/box`의 `Seal`/`Open`이며 nonce와 키 방향은 위와 같다. (tailscale.com/types/key/node.go:130)
- 실제 로컬 Go tsnet 피어의 완전한 생성·control 설정과 WireGuard 왕복 시험 절차는 이 노트 범위에서 확인하지 못했다.
- 전체 netcheck 프로브 스케줄의 모든 재전송·동시성 분기와 서버 재시작 권고의 상위 계층별 실행은 확인하지 못했다.
