# DERP와 STUN

## 1. 머리말

| 항목 | 값 |
| --- | --- |
| 기준 소스 | `tailscale.com` v1.104.6 (CapabilityVersion 148, `docs/protocol-notes/README.md` 기준 소스 표) |
| 작성 모델 | GPT-6.1 Terra |
| 검증 상태 | 검증: Claude Opus 5.5, 2026-11-14, 수정 13건 |

출처는 모듈 루트 기준 `tailscale.com/<경로>:<줄>`이다. 의존 모듈은 `golang.org/x/crypto@v0.58.0/...`(`tailscale.com/go.mod:139`), 표준 라이브러리는 `Go 1.27.3/src/...`, 이 저장소의 파일은 저장소 루트 기준 경로로 적는다.

## 2. 범위

다루는 것(M3): DERP 클라이언트가 Go `derpserver`와 맞물리는 데 필요한 HTTP 업그레이드, 프레임 형식, 핸드셰이크, 송수신, 재연결, 서버가 연결을 끊는 조건, 홈 지역 선택과 알림, 피어별 지역 선택. 이 저장소의 `Tools/interop` `tailnet`이 띄우는 시험 서버의 조건.

다루는 것(M4 준비): STUN 바인딩 요청·응답 바이트 형식, netcheck의 홈 지역 선택 규칙 요약.

다루지 않는 것: mesh(서버 간) 동작의 상세, WebSocket·HTTP 프록시 경로, DERP 서버 구현, WireGuard·disco 메시지 내용(`wireguard.md`, `disco-magicsock.md`), DERPMap을 맵 응답에서 받는 규칙(`control-map.md`).

## 3. 와이어 형식

### 3.1 프레임 헤더

모든 DERP 프레임은 5바이트 헤더 뒤에 본문이 붙는다. 길이는 헤더를 뺀 본문 길이다(`tailscale.com/derp/derp.go:36`, `:51-53`, `:209-216`).

| 오프셋 | 길이 | 필드 | 인코딩 |
| --- | --- | --- | --- |
| 0 | 1 | frame type | u8, 3.2 표 |
| 1 | 4 | length | uint32 BE, 본문 바이트 수 |
| 5 | length | 본문 | 타입별 |

받기 상한: 클라이언트는 본문이 1 MiB(`1<<20`)를 넘으면 오류로 연결을 버린다(`tailscale.com/derp/derp_client.go:556-558`). 보내기 상한: 패킷 본문(목적지 키 제외)은 `MaxPacketSize = 65536`바이트 이하다(`tailscale.com/derp/derp.go:28`, `tailscale.com/derp/derp_client.go:266-268`).

### 3.2 프레임 종류

C는 클라이언트, S는 서버다. "Go 클라이언트 처리"는 `derp.Client.Recv`와 magicsock의 읽기 루프 기준이다.

| 타입 | 값 | 방향 | 본문 | Go 클라이언트 처리 | 출처 |
| --- | --- | --- | --- | --- | --- |
| `FrameServerKey` | `0x01` | S→C | 3.3 | 핸드셰이크에서만 읽는다. 그 뒤에 오면 모르는 프레임처럼 건너뛴다 | `derp/derp.go:72`, `derp/derp_client.go:157-171`, `:581-582` |
| `FrameClientInfo` | `0x02` | C→S | 3.4 | | `derp/derp.go:73` |
| `FrameServerInfo` | `0x03` | S→C | 3.5 | 열어서 속도 제한을 설정한다. 열기 실패는 연결 오류 | `derp/derp.go:74`, `derp/derp_client.go:583-599` |
| `FrameSendPacket` | `0x04` | C→S | 0:32 목적지 node 공개 키, 32:나머지 패킷 | | `derp/derp.go:75`, `derp/derp_client.go:278-287` |
| `FrameRecvPacket` | `0x05` | S→C | 0:32 보낸 쪽 node 공개 키, 32:나머지 패킷(프로토콜 버전 2) | 본문 32바이트 미만은 버린다 | `derp/derp.go:47-49`, `:77`, `derp/derp_client.go:665-673` |
| `FrameKeepAlive` | `0x06` | S→C | 없음(길이 0) | 응답하지 않는다 | `derp/derp.go:78`, `derp/derp_client.go:600-603` |
| `FrameNotePreferred` | `0x07` | C→S | 1바이트: 홈이면 `0x01`, 아니면 `0x00` | | `derp/derp.go:79`, `derp/derp_client.go:350-371` |
| `FramePeerGone` | `0x08` | S→C | 0:32 피어 공개 키, 32:1 이유(3.6) | 32바이트 미만은 버린다. 이유 바이트가 없으면 `0x00` | `derp/derp.go:88`, `derp/derp_client.go:604-618` |
| `FramePeerPresent` | `0x09` | S→C | 0:32 키, 32:16 IP, 48:2 포트 BE, 50:1 flags, 51:1 이름 길이 n, 52:n AppName. 32바이트 뒤는 모두 선택 | mesh 감시 연결에만 온다 | `derp/derp.go:93-102`, `:154-157`, `derp/derp_client.go:620-663` |
| `FrameForwardPacket` | `0x0a` | mesh | 0:32 보낸 쪽, 32:32 목적지, 64:패킷 | 일반 클라이언트는 쓰지 않는다 | `derp/derp.go:76` |
| `FrameWatchConns` | `0x10` | mesh | 없음 | 일반 클라이언트가 보내면 서버가 끊는다 | `derp/derp.go:110`, `derp/derpserver/derpserver.go:1323-1332` |
| `FrameClosePeer` | `0x11` | mesh | 0:32 닫을 피어 키 | 일반 클라이언트가 보내면 서버가 끊는다 | `derp/derp.go:116`, `derp/derpserver/derpserver.go:1357-1363` |
| `FramePing` | `0x12` | C→S, S→C | 8바이트 불투명 값 | 받으면 같은 8바이트로 `FramePong`을 보낸다. 8바이트 미만은 버린다 | `derp/derp.go:118`, `derp/derp_client.go:675-682`, `wgengine/magicsock/derp.go:640-648` |
| `FramePong` | `0x13` | C→S, S→C | 받은 ping의 8바이트 | 자기가 보낸 ping과 맞으면 소비한다 | `derp/derp.go:119`, `derp/derphttp/derphttp_client.go:1129-1136` |
| `FrameHealth` | `0x14` | S→C | 본문 전체가 오류 문자열. 빈 문자열은 정상 복귀 | 상태 표시에만 쓴다 | `derp/derp.go:121-126`, `derp/derp_client.go:693-694`, `wgengine/magicsock/derp.go:649-651` |
| `FrameRestarting` | `0x15` | S→C | 0:4 `ReconnectIn` ms, 4:4 `TryFor` ms, 각각 uint32 BE | 8바이트 미만은 버린다. magicsock은 무시한다 | `derp/derp.go:128-133`, `derp/derp_client.go:696-704`, `wgengine/magicsock/derp.go:667-669` |

(출처 경로는 `tailscale.com/` 생략.)

모르는 타입: 클라이언트는 본문을 끝까지 읽고 건너뛴다(`tailscale.com/derp/derp_client.go:581-582`). 서버는 본문이 `MaxPacketSize + 32 = 65568`바이트 이하면 버리고, 넘으면 연결을 끊는다(`tailscale.com/derp/derpserver/derpserver.go:1296`, `:1303-1309`). 서버는 클라이언트가 보낸 `FramePong`도 모르는 프레임으로 버린다(`derpserver.go:1263-1278`).

이 버전의 `derpserver`가 실제로 보내는 프레임은 ServerKey, ServerInfo, RecvPacket, KeepAlive, PeerGone, PeerPresent, Pong뿐이다. `FramePing`·`FrameHealth`·`FrameRestarting`을 쓰는 곳은 `derpserver` 패키지에 없다(`derp/derpserver/derpserver.go`의 `WriteFrameHeader` 호출: `:1910`, `:2746`, `:2753`, `:2781`, `:2793`, `:2889`, `sendServerKey` `:1828-1835`). 다른 서버 구현이 보낼 수 있으므로 클라이언트는 위 표대로 처리한다.

### 3.3 FrameServerKey 본문 (S→C)

| 오프셋 | 길이 | 필드 | 값 |
| --- | --- | --- | --- |
| 0 | 8 | magic | `44 45 52 50 f0 9f 94 91` (`"DERP🔑"`) |
| 8 | 32 | 서버 DERP 공개 키 | Curve25519, raw |
| 40 | 나머지 | 향후 확장 | 무시 |

클라이언트는 타입이 `0x01`, 길이 40 이상, magic 일치를 확인하고 본문이 1024바이트를 넘으면 거절한다. 40바이트 뒤는 버린다(`tailscale.com/derp/derp.go:32`, `tailscale.com/derp/derp_client.go:157-171`). 서버는 정확히 40바이트를 보낸다(`tailscale.com/derp/derpserver/derpserver.go:1828-1835`).

### 3.4 FrameClientInfo 본문 (C→S)

| 오프셋 | 길이 | 필드 | 인코딩 |
| --- | --- | --- | --- |
| 0 | 32 | 클라이언트 node 공개 키 | raw. WireGuard 공개 키와 같은 키(magicsock의 `privateKey`로 클라이언트를 만든다) |
| 32 | 24 | nonce | 무작위 |
| 56 | 16 | Poly1305 태그 | |
| 72 | n | JSON 암호문 | XSalsa20 |

출처: `tailscale.com/derp/derp_client.go:232-249`, `tailscale.com/types/key/node.go:136-143`, `tailscale.com/wgengine/magicsock/derp.go:399`.

암호화(NaCl `box.Seal`, `golang.org/x/crypto@v0.58.0/nacl/box/box.go:81-93`, `nacl/secretbox/secretbox.go:47-119`):

1. `s = X25519(클라이언트 개인 키, 서버 공개 키)`.
2. `k = HSalsa20(key: s, input: 0^16)`.
3. `subKey = HSalsa20(key: k, input: nonce[0..<16])`, XSalsa20 스트림의 nonce는 `nonce[16..<24]`.
4. 블록 0의 앞 32바이트가 Poly1305 키, 평문은 블록 0의 32번째 바이트부터의 키 스트림과 XOR한다.
5. 출력은 `tag(16) ‖ ciphertext`. 태그는 암호문 전체의 Poly1305다.

이 저장소의 `SwiftailCrypto`에 같은 구성이 있다: `NaClBox.sharedKey`가 1–2단계, `NaClSecretBox.seal`·`open`이 3–5단계다(`Sources/SwiftailCrypto/NaCl.swift:4-56`).

평문 JSON(`ClientInfo`, `tailscale.com/derp/derp_client.go:196-219`). Go는 구조체 선언 순서로 쓴다. 서버는 순서와 무관하게 읽는다.

| JSON 키 | 타입 | 생략 규칙 | Go magicsock이 보내는 값 |
| --- | --- | --- | --- |
| `meshKey` | 문자열 | 0값이면 생략 | 생략 |
| `version` | 정수 | 0이면 생략 | `2` (`ProtocolVersion`, `derp/derp.go:49`) |
| `CanAckPings` | bool | 항상 | `true` (`wgengine/magicsock/derp.go:422`) |
| `IsProber` | bool | false면 생략 | 생략 |
| `AppName` | 문자열 | 빈 값이면 생략. 32바이트 이하의 출력 가능한 ASCII(`0x20`–`0x7e`)여야 한다 | magicsock `Options.DERPAppName`(`wgengine/magicsock/derp.go:417`) |

예: `{"version":2,"CanAckPings":true}`(32바이트)면 본문은 32 + 24 + 16 + 32 = 104바이트, 프레임은 109바이트다.

서버 검증(`tailscale.com/derp/derpserver/derpserver.go:1922-1956`): 타입이 `0x02`가 아니거나, 본문이 56바이트 미만이거나 256 KiB(`256<<10`)를 넘거나, box가 열리지 않거나, JSON이 틀리거나, `AppName`이 규칙을 어기면 연결을 끊는다. `AppName` 규칙: `tailscale.com/derp/derp_client.go:97-112`.

### 3.5 FrameServerInfo 본문 (S→C)

| 오프셋 | 길이 | 필드 |
| --- | --- | --- |
| 0 | 24 | nonce |
| 24 | 16 | Poly1305 태그 |
| 40 | n | JSON 암호문 |

서버는 서버 개인 키·클라이언트 공개 키로 봉한다. 클라이언트는 자기 개인 키·서버 공개 키로 연다. X25519가 대칭이므로 3.4와 같은 `k`를 쓴다(`tailscale.com/derp/derpserver/derpserver.go:1903-1917`, `tailscale.com/types/key/node.go:148-157`, `tailscale.com/derp/derp_client.go:174-192`).

평문 JSON(`tailscale.com/derp/derp.go:304-309`): `version`(정수, 0이면 생략), `TokenBucketBytesPerSecond`, `TokenBucketBytesBurst`(정수, 0이면 생략). 이 버전의 서버는 `{"version":2}`만 보낸다(`derpserver.go:1904`). 이때 본문은 24 + 16 + 13 = 53바이트다.

클라이언트 검증: 본문 24바이트 미만, `24 + 1 MiB` 초과, 열기 실패, JSON 오류는 연결 오류다(`tailscale.com/derp/derp_client.go:174-192`, `:590-593`).

### 3.6 PeerGone 이유 코드

| 값 | 이름 | 뜻 |
| --- | --- | --- |
| `0x00` | `PeerGoneReasonDisconnected` | 전에 이 클라이언트에게 패킷을 보낸 피어가 지역에서 끊겼다 |
| `0x01` | `PeerGoneReasonNotHere` | 보낸 목적지를 서버가 모른다 |
| `0xf0` | `PeerGoneReasonMeshConnBroke` | 클라이언트 내부용. 선로에 오지 않는다 |

출처: `tailscale.com/derp/derp.go:141-143`. 서버는 `NotHere`를 목적지가 없고 패킷이 disco 메시지일 때만, 클라이언트 연결마다 초당 1개(버스트 3)까지 보낸다(`tailscale.com/derp/derpserver/derpserver.go:1092-1100`, `:1174`, `:1497-1502`). `Disconnected`는 지역에서 사라진 피어에 대해 보낸다(`derpserver.go:1694-1696`).

### 3.7 HTTP 업그레이드 요청과 응답

요청(클라이언트가 쓰는 바이트, Go `http.Request.Write`):

```
GET /derp HTTP/1.1\r\n
Host: <HostName>[:<DERPPort>]\r\n
User-Agent: Go-http-client/1.1\r\n
Connection: Upgrade\r\n
Upgrade: DERP\r\n
[Ideal-Node: <Region.Nodes[0].Name>\r\n]
\r\n
```

- 경로는 `/derp`, 포트는 443(TLS)·80(평문 URL)과 다를 때만 Host에 붙는다(`tailscale.com/derp/derphttp/derphttp_client.go:280-295`, `:511`).
- `Upgrade: DERP`, `Connection: Upgrade`를 넣는다(`derphttp_client.go:515-516`). 서버는 `Upgrade` 값만 대소문자 무시로 `derp` 또는 `websocket`인지 본다. 아니면 426을 돌려준다(`tailscale.com/derp/derpserver/handler.go:34-41`).
- `Ideal-Node`는 연결한 노드가 지역의 첫 노드가 아닐 때만 넣는다. 서버 통계용이다(`derphttp_client.go:517-520`, `tailscale.com/derp/derp.go:160-164`).
- Host 머리는 빠뜨리지 않는다. Go HTTP/1.1 서버는 Host가 없으면 400을 돌려준다(`Go 1.27.3/src/net/http/server.go:1072`).
- `Derp-Fast-Start: 1`은 TLS 1.3에서 서버의 meta 인증서로 서버 키를 미리 안 경우에만 보낸다(4.2).

응답(fast-start가 아닐 때, 서버가 소켓에 직접 쓰는 바이트, `tailscale.com/derp/derpserver/handler.go:58-78`):

```
HTTP/1.1 101 Switching Protocols\r\n
Upgrade: DERP\r\n
Connection: Upgrade\r\n
Derp-Version: 2\r\n
Derp-Public-Key: <서버 공개 키 64자리 소문자 hex>\r\n
\r\n
```

서버는 바로 이어 같은 연결에 `FrameServerKey`를 쓴다(`handler.go:108`, `tailscale.com/derp/derpserver/derpserver.go:1137-1143`). 클라이언트는 응답 머리의 끝(`\r\n\r\n`) 뒤에 이미 받은 바이트를 버리지 말고 프레임 읽기에 넘긴다. Go 클라이언트도 같은 버퍼로 응답과 프레임을 읽는다(`derphttp_client.go:508`, `:552`, `:562`). Go 클라이언트는 상태 코드가 101인지만 확인하고 `Derp-Version`·`Derp-Public-Key`는 읽지 않는다(`derphttp_client.go:552-561`). 101이 아니면 본문 앞 1 KiB를 오류에 담는다(`derphttp_client.go:340`, `:556-559`).

### 3.8 STUN 바인딩 요청 (M4)

정수는 BE다. Go가 만드는 요청은 40바이트다(`tailscale.com/net/stun/stun.go:17-34`, `:48-71`).

| 오프셋 | 길이 | 필드 | 값 |
| --- | --- | --- | --- |
| 0 | 2 | message type | `00 01` (binding request) |
| 2 | 2 | message length | `00 14` (헤더 뒤 20바이트, FINGERPRINT 포함) |
| 4 | 4 | magic cookie | `21 12 a4 42` |
| 8 | 12 | transaction ID | 암호학적 난수 (`stun.go:40-46`) |
| 20 | 2 | 속성 타입 SOFTWARE | `80 22` |
| 22 | 2 | 속성 길이 | `00 08` |
| 24 | 8 | 값 | ASCII `tailnode` (패딩 없음) |
| 32 | 2 | 속성 타입 FINGERPRINT | `80 28` |
| 34 | 2 | 속성 길이 | `00 04` |
| 36 | 4 | 값 | `CRC32-IEEE(바이트 0..<32) XOR 0x5354554e` |

Go STUN 서버(`net/stunserver`, `stuntest`, `Tools/interop`의 `tailnet`)는 `ParseBindingRequest`로 요청을 거른다. SOFTWARE 값이 정확히 `tailnode`이고, 마지막 속성이 FINGERPRINT이고, CRC가 맞아야 응답한다. 아니면 조용히 버린다(`tailscale.com/net/stun/stun.go:87-122`, `tailscale.com/net/stunserver/stunserver.go:110`, `Tools/interop/cmd/tailnet/main.go:77-80`). 그러므로 Swiftail은 위 40바이트를 그대로 만들어야 한다.

### 3.9 STUN 바인딩 응답 (M4)

| 오프셋 | 길이 | 필드 | 값 |
| --- | --- | --- | --- |
| 0 | 2 | message type | `01 01` (success) |
| 2 | 2 | message length | 속성 전체 길이 |
| 4 | 4 | magic cookie | `21 12 a4 42` |
| 8 | 12 | transaction ID | 요청 값 |
| 20 | … | 속성들 | 각 속성: 0:2 타입, 2:2 값 길이 L, 4:L 값, 이어서 4바이트 정렬 패딩 |

주소 속성의 값:

| 오프셋 | 길이 | 필드 | 인코딩 |
| --- | --- | --- | --- |
| 0 | 1 | 예약 | Go 서버는 0 |
| 1 | 1 | family | `01` IPv4, `02` IPv6. 그 밖은 형식 오류 |
| 2 | 2 | port | BE. XOR 속성은 `port XOR 0x2112` |
| 4 | 4 또는 16 | address | XOR 속성은 앞 4바이트를 cookie와, IPv6의 나머지 12바이트를 transaction ID와 XOR. MAPPED-ADDRESS는 그대로 |

속성 타입: XOR-MAPPED-ADDRESS `0x0020`, 대체 `0x8020`(같게 처리), MAPPED-ADDRESS `0x0001`(`stun.go:17-27`). Go 서버의 응답은 XOR-MAPPED-ADDRESS 하나뿐이고 FINGERPRINT를 넣지 않는다(`stun.go:155-191`). 출처: `stun.go:134-152`, `:175-189`, `:252-305`.

## 4. 절차와 상태 기계

### 4.1 노드 선택, TCP, TLS

1. 지역의 `Nodes`를 순서대로 본다. `STUNOnly` 노드는 건너뛴다. 노드마다 TCP 연결을 시도해 처음 성공한 노드를 쓴다. TLS 실패는 다음 노드로 넘어가지 않고 이번 연결 시도 전체의 실패다(`tailscale.com/derp/derphttp/derphttp_client.go:640-661`, `:477-486`).
2. 노드 하나의 TCP: `IPv4`가 비어 있으면 `HostName`을 DNS로, IPv4 주소면 그 주소로, 그 밖의 값(관례상 `"none"`)이면 IPv4를 쓰지 않는다. IPv6도 같다. 둘 다 쓰지 않으면 실패다. 둘을 동시에 시도해 먼저 성공한 쪽을 쓴다. IPv6가 낫다고 판단되면 IPv4 시도를 200 ms 늦춘다(`derphttp_client.go:725-731`, `:769-821`, `tailscale.com/tailcfg/derpmap.go:216-228`).
3. 포트: `DERPPort`가 0이 아니면 그 값, 아니면 TLS 443(평문이면 3340)(`derphttp_client.go:796-802`).
4. 지역 클라이언트(magicsock이 쓰는 `NewRegionClient`)는 항상 TLS다. 평문은 URL을 `http://`로 준 `NewClient`나 환경 변수 `TS_DEBUG_USE_DERP_HTTP`일 때만이다(`derphttp_client.go:252`, `:261-270`). 따라서 Go 피어와 맞물리는 시험에서도 DERP는 TLS다.
5. TLS 서버 이름은 `HostName`이다(`derphttp_client.go:273-278`, `:667`). 인증서 검증:
   - `InsecureForTests`가 참이면 검증하지 않는다(`derphttp_client.go:669-672`).
   - `CertName`이 `sha256-raw:<hex>`면 meta 인증서를 뺀 인증서가 정확히 하나이고, 그 DER 전체의 SHA-256 hex가 같아야 한다. 그 인증서는 지금 유효 기간 안이어야 하고, SNI로 나간 이름이 있으면 그 이름에 유효해야 한다. `HostName`이 IP 리터럴이면 SNI가 나가지 않으므로(`crypto/tls`의 `hostnameInSNI`) 이름은 보지 않는다(`derphttp_client.go:673-679`, `tailscale.com/net/tlsdial/tlsdial.go:316-358`. 2026-11-15 M8 ③ 구현 때 소스로 확인해 보탬).
   - 그 밖의 `CertName`은 그 이름으로 인증서를 검증한다. 비어 있으면 `HostName`으로 검증한다(`tailscale.com/tailcfg/derpmap.go:204-214`, `tlsdial.go:242-272`).
6. 연결 전체(DNS·TCP·TLS·HTTP·DERP 핸드셰이크)의 상한은 10초, 노드 하나의 TCP 시도는 1.5초다(`derphttp_client.go:359-363`, `:733`, `:764`).

### 4.2 HTTP 업그레이드

1. 3.7의 요청을 쓰고 flush한다.
2. 응답 머리를 읽는다. 101이 아니면 실패다.
3. 머리 뒤에 남은 바이트를 그대로 DERP 프레임 읽기의 시작으로 쓴다.

fast-start(선택): TLS 1.3이고 서버 인증서 체인에 CN이 `derpkey<64자리 hex>`인 인증서가 있으며 그 일련번호가 8비트 이하면, 클라이언트는 그 키를 서버 키로, 일련번호를 프로토콜 버전으로 삼는다(`derphttp_client.go:499-503`, `:1198-1209`, `tailscale.com/derp/derpconst/derpconst.go:11`). 이때 요청에 `Derp-Fast-Start: 1`을 넣고 응답을 기다리지 않고 바로 `FrameClientInfo`를 쓴다(`derphttp_client.go:530-543`). 서버는 101 응답을 쓰지 않지만 `FrameServerKey`는 여전히 보낸다(`tailscale.com/derp/derpserver/handler.go:43`, `:58`, `derpserver.go:1141`). 서버가 meta 인증서를 붙이는 것은 운영자가 `ModifyTLSConfigToAddMetaCert`를 쓸 때뿐이다(`derpserver.go:851-874`).

### 4.3 DERP 핸드셰이크

1. `FrameServerKey`를 읽고 검증한다(3.3). fast-start면 이 단계를 건너뛴다(`tailscale.com/derp/derp_client.go:142-148`).
2. `FrameClientInfo`를 쓴다(3.4).
3. `FrameNotePreferred`: 이 연결이 홈 지역이면 바로 `0x01`을 쓴다(`tailscale.com/derp/derphttp/derphttp_client.go:572-577`). 홈이 아니면 보내지 않는다.
4. 이제 송신할 수 있다. Go 클라이언트는 `FrameServerInfo`를 기다리지 않고 읽기 루프에서 처리한다(`derp_client.go:583-589`).
5. 서버는 ServerKey 보내기와 ClientInfo 받기에 각각 10초 기한을 두고, 검증이 끝나면 기한을 없앤 뒤 `FrameServerInfo`를 보낸다(`tailscale.com/derp/derpserver/derpserver.go:1139-1156`, `:1200`).

### 4.4 송신

1. `FrameSendPacket`: 헤더(`0x04`, 길이 32 + n), 목적지 공개 키 32바이트, 패킷 n바이트(n ≤ 65536)를 한 덩어리로 쓴다. Go는 쓰기 잠금을 잡고 한 프레임을 다 쓴 뒤 flush한다. 여러 작업이 같은 연결에 쓸 때 프레임이 섞이면 안 된다(`tailscale.com/derp/derp_client.go:259-288`).
2. 속도 제한: `FrameServerInfo`가 `TokenBucketBytesPerSecond`를 0이 아닌 값으로 주면 클라이언트는 그 속도·버스트의 토큰 버킷을 두고, `5 + 32 + n` 토큰이 없으면 패킷을 조용히 버린다(오류 아님). 0이면 제한을 없앤다(`derp_client.go:272-277`, `:709-720`). 이 버전의 서버는 값을 보내지 않는다(3.5).
3. magicsock은 지역 연결마다 깊이 32의 쓰기 큐를 둔다. 가득 차면 가장 오래된 요청 하나를 꺼내 버리고 다시 넣기를 최대 3번 해 보고, 그래도 안 되면 새 패킷을 버린다(`tailscale.com/wgengine/magicsock/derp.go:329`, `tailscale.com/wgengine/magicsock/magicsock.go:1696-1718`).
4. 서버 쪽 목적지 큐도 깊이 32이며, 가득 차면 맨 앞(가장 오래된) 패킷을 버린다(`tailscale.com/derp/derpserver/derpserver.go:89`, `:2204-2223`).

### 4.5 수신 루프

클라이언트는 연결이 살아 있는 동안 계속 읽는다. 읽기마다 120초 기한을 둔다(`tailscale.com/derp/derp_client.go:525-541`). 서버는 60초 + [0, 5)초마다 KeepAlive를 보내므로 이 기한 안에 무언가 온다(`tailscale.com/derp/derp.go:41-44`, `tailscale.com/derp/derpserver/derpserver.go:2635-2637`).

프레임별 처리(3.2 표의 Go 처리를 따른다):

1. `FrameRecvPacket`: 앞 32바이트가 보낸 쪽 node 공개 키다. 이 키로 피어를 찾는다. 찾지 못한 키의 패킷은 버린다. 보낸 키를 이 지역 연결의 역방향 경로로 기록한다(4.7). 패킷이 disco magic(`54 53 f0 9f 92 ac`, `"TS💬"`)으로 시작하고 6 + 32 + 24 = 62바이트 이상이면 disco 메시지이므로 WireGuard로 넘기지 않는다(`tailscale.com/wgengine/magicsock/derp.go:613-628`, `tailscale.com/wgengine/magicsock/magicsock.go:747-753`, `tailscale.com/disco/disco.go:35`, `:62-67`).
2. `FramePing`: 같은 8바이트로 `FramePong`을 보낸다(`tailscale.com/wgengine/magicsock/derp.go:640-648`).
3. `FramePeerGone`: 그 피어의 역방향 경로가 이 연결이면 지운다(`wgengine/magicsock/derp.go:652-666`).
4. `FrameServerInfo`: 열고 속도 제한을 설정한다(4.4 2).
5. KeepAlive, Health, Restarting, PeerPresent, Pong(자기 ping이 아닌 것), 모르는 타입: 상태 기록 외에는 무시한다(`wgengine/magicsock/derp.go:607-670`).

서버는 클라이언트에게 쓸 때 2초 쓰기 기한을 둔다. 클라이언트가 읽지 않아 이 기한을 넘기면 서버 쓰기가 실패해 연결이 끝난다(`tailscale.com/derp/derpserver/derpserver.go:90`, `:2716-2741`). 받은 패킷을 위 계층이 늦게 가져가더라도 소켓 읽기를 오래 멈추지 않는다.

### 4.6 끊김과 재연결

1. 읽기·쓰기 중 오류가 나면 그 `derp.Client`는 다시 쓰지 않는다(읽기 오류는 고정된다, `tailscale.com/derp/derp_client.go:519-539`). `derphttp.Client`가 TCP 연결을 닫고, 다음 `Send`·`Recv` 때 4.1부터 새로 연결한다(`tailscale.com/derp/derphttp/derphttp_client.go:937-946`, `:1124-1145`, `:1183-1194`).
2. magicsock의 읽기 루프는 오류가 나면 이 연결에서 배운 역방향 경로를 모두 지우고, STUN 재측정을 시작하고, 물러난 뒤 다시 읽기(곧 재연결)를 부른다(`tailscale.com/wgengine/magicsock/derp.go:563-598`).
3. 물러나기: 연속 실패 수 n에 대해 `min(n² × 10 ms, 5 s)`에 [0.5, 1.5) 사이 난수를 곱한 만큼 기다린다. 메시지를 하나라도 받으면 n을 0으로 되돌린다(`tailscale.com/util/backoff/backoff.go:49-77`, `wgengine/magicsock/derp.go:558`, `:599`).
4. 새 연결은 처음부터 핸드셰이크를 다시 하고, 홈이면 `NotePreferred(true)`를 다시 보낸다(4.3).
5. 같은 키로 서버에 연결이 둘 이상 있으면 서버는 기본 정책(`lastWriterIsActive`)에서 가장 최근에 프레임을 보낸 연결에만 패킷을 넘긴다(`tailscale.com/derp/derpserver/derpserver.go:112`, `:1860-1862`). 재연결 전에 이전 연결을 닫는다.

### 4.7 서버가 연결을 끊는 조건 (일반 클라이언트)

| 조건 | 출처 (`tailscale.com/derp/derpserver/`) |
| --- | --- |
| 업그레이드 뒤 10초 안에 올바른 `FrameClientInfo`가 오지 않음, 또는 3.4 검증 실패 | `derpserver.go:1139-1148`, `:1922-1956` |
| 클라이언트 검증 실패(운영 서버의 tailscaled·admission URL 설정 때. 시험 서버에는 없다) | `derpserver.go:1761-1826` |
| `FrameNotePreferred` 본문이 1바이트가 아님 | `derpserver.go:1311-1314` |
| `FrameSendPacket` 본문이 32바이트 미만이거나 패킷이 65536바이트 초과 | `derpserver.go:1962-1972` |
| `FramePing` 본문이 8바이트 미만이거나 1000바이트 초과 | `derpserver.go:1334-1344` |
| mesh 키 없이 `FrameWatchConns`·`FrameClosePeer`, 또는 그 길이가 틀림 | `derpserver.go:1323-1332`, `:1357-1363` |
| 모르는 타입의 본문이 65568바이트 초과 | `derpserver.go:1296-1309` |
| 서버가 2초 안에 쓰지 못함 | `derpserver.go:2716-2741` |

목적지가 없는 패킷은 끊지 않고 버린다(3.6, `derpserver.go:1483-1508`).

### 4.8 홈 지역 선택과 알림

Go magicsock의 동작:

1. netcheck 보고의 `PreferredDERP`를 쓴다. 0이면(UDP가 막혀 측정이 없는 경우) 기존 홈을, 기존 홈도 없으면 `DERPMap`의 지역 ID 중 하나를 고른다(`tailscale.com/wgengine/magicsock/derp.go:114-148`, `:197-202`).
2. 제어 서버와 맵 스트림이 연결되어 있지 않으면, 강제가 아닌 한 기존 홈을 바꾸지 않는다. 피어에게 바뀐 홈을 알릴 수 없기 때문이다(`derp.go:160-195`).
3. 홈이 바뀌면 열린 모든 지역 연결에 `NotePreferred(그 지역 == 홈)`을 보내고 홈 지역 연결을 연다(`derp.go:283-295`, `:423`). `NotePreferred`는 서버 통계에만 쓰인다(`tailscale.com/derp/derp_client.go:347-349`).
4. 고른 홈을 `Hostinfo.NetInfo.PreferredDERP`에 넣어 제어 서버에 올린다(`tailscale.com/wgengine/magicsock/magicsock.go:1075`, `tailscale.com/tailcfg/tailcfg.go:1128-1135`). 제어 서버는 이 값을 다른 노드에게 그 노드의 `HomeDERP`로 내려준다. testcontrol은 맵 요청의 `NetInfo.PreferredDERP`가 0이 아니면 노드의 `HomeDERP`로 저장한다(`tailscale.com/tstest/integration/testcontrol/testcontrol.go:1471-1496`).
5. `NoMeasureNoHome` 지역은 측정하지 않고 홈으로 고르지 않는다. 피어가 그 지역을 홈으로 알리면 그 피어와 통신하기 위해 연결할 수는 있다(`tailscale.com/tailcfg/derpmap.go:161-169`). 1의 대체 선택은 이 필드를 보지 않고 모든 지역 ID에서 고른다(`derpmap.go:40-47`, `derp.go:121-147`).

M3에서 고정 선택으로 충분한 근거: netcheck 결과가 없을 때 Go도 측정 없이 지역 하나를 고른다(1). 시험 DERPMap에는 지역이 1 하나뿐이므로(7절) Go 피어도 측정 결과와 무관하게 홈이 1이 되고, Swiftail이 1을 고르면 양쪽이 같은 서버에 있게 된다. Swiftail이 `PreferredDERP`를 올리지 않으면 Go 피어가 아는 Swiftail의 `HomeDERP`가 0이 되어, Swiftail이 먼저 보내 역방향 경로가 생기기 전까지 Go 피어가 보낼 곳이 없다(4.9 3).

### 4.9 피어에게 보낼 때 쓸 지역과 받은 패킷의 출처

1. 피어의 홈 지역은 맵의 `Node.HomeDERP`다. 옛 서버가 보내는 `DERP` 문자열(`"127.3.3.40:<지역 ID>"`)은 맵 처리에서 `HomeDERP`로 바뀐다(`tailscale.com/tailcfg/tailcfg.go:406-423`). magicsock은 이를 가짜 주소 `127.3.3.40:<지역 ID>`로 표현해 WireGuard의 엔드포인트로 쓴다(`tailscale.com/wgengine/magicsock/endpoint.go:1733-1753`, `tailscale.com/tailcfg/tailcfg.go:3072-3079`).
2. 보낼 연결 고르기(`tailscale.com/wgengine/magicsock/derp.go:339-475`):
   1. 피어 홈 지역의 연결이 이미 열려 있으면 그것을 쓴다.
   2. 없으면, 그 피어의 패킷을 받은 적 있는 지역 연결(역방향 경로)이 아직 같은 연결이면 그것을 쓴다.
   3. 둘 다 아니면 피어 홈 지역으로 새 연결을 연다.
3. 직접 경로가 없고 피어의 `HomeDERP`도 0이면, 그 피어의 역방향 경로 지역을 쓰고, 그것도 없으면 보내지 못한다(`tailscale.com/wgengine/magicsock/endpoint.go:635-652`, `:1133-1143`).
4. 받은 패킷의 출처는 `FrameRecvPacket`의 보낸 쪽 키와 받은 지역이다. magicsock은 WireGuard에 출처를 `127.3.3.40:<받은 지역 ID>`로 넘긴다(`tailscale.com/wgengine/magicsock/magicsock.go:747`). 역방향 경로는 연결 오류 때와, 그 연결에서 그 피어의 `FramePeerGone`을 받을 때 지운다(4.5, 4.6).
5. 홈이 아닌 지역 연결은 마지막 쓰기 요청 뒤 60초가 지나면 닫는다. 검사는 15초 주기다(`tailscale.com/wgengine/magicsock/derp.go:990-1019`, `:1071-1077`).

### 4.10 STUN 질의와 netcheck의 홈 선택 (M4)

1. 지역마다 노드의 `STUNPort`(0이면 3478, -1이면 끔)로 3.8의 요청을 보낸다. 보낸 transaction ID를 진행 중 표에 넣고, 응답의 ID가 표에 있을 때만 그 지역의 지연과 바깥 주소로 쓴다(`tailscale.com/net/netcheck/netcheck.go:1608-1643`, `:331-353`, `tailscale.com/tailcfg/derpmap.go:230-233`).
2. STUN은 WireGuard와 같은 UDP 소켓으로 보낸다. 그래야 응답의 주소가 WireGuard 엔드포인트가 된다(`tailscale.com/wgengine/magicsock/magicsock.go:713`, `:1632-1644`).
3. 응답 파싱(`tailscale.com/net/stun/stun.go:195-250`, `:307-312`): 20바이트 이상, 첫 바이트 상위 2비트가 0, cookie 일치, 타입 `01 01`, 선언 길이가 남은 바이트 이하(초과 바이트는 버림), 속성마다 길이·패딩이 남은 바이트 안에 있어야 한다. XOR 주소가 있으면 그것을, 없으면 MAPPED-ADDRESS를 쓴다. 둘 다 없으면 오류다. 주소 속성의 family가 틀리거나 짧으면 응답 전체가 오류다. 응답의 FINGERPRINT는 검사하지 않는다.
4. 보고 시간은 5초, STUN 대기는 3초다(`netcheck.go:61`, `:66`). UDP 응답이 전혀 없으면 HTTPS `GET https://<HostName>/derp/latency-check`의 왕복으로 대신 잰다. 300 이상 상태는 실패다(`netcheck.go:1198-1216`).
5. 홈 선택(`netcheck.go:1426-1531`): 최근 5분 5초(`fullReportInterval + ReportTimeout`) 보고에서 지역별 최소 지연에 `HomeParams.RegionScore`(양수일 때만)를 곱해 가장 작은 지역을 고른다. 기존 홈이 아직 닿고(이번 보고에 지연이 있거나 최근 8초 안에 DERP 프레임을 받음), 새 후보와의 차이가 10 ms 미만이거나 새 후보가 기존 지연의 2/3보다 크면 기존 홈을 유지한다. 측정이 하나도 없으면 최근 120초 안에 프레임을 받은 기존 홈을 유지한다(`netcheck.go:1379-1401`, `:1416`).

## 5. 상수와 타이머

| 항목 | 값 | 출처 (`tailscale.com/`) |
| --- | --- | --- |
| `ProtocolVersion` | 2 | `derp/derp.go:49` |
| 프레임 헤더 | 5바이트 | `derp/derp.go:36` |
| `MaxPacketSize` | 65536바이트(목적지 키·헤더 제외) | `derp/derp.go:28` |
| 클라이언트 수신 본문 상한 | 1 MiB | `derp/derp_client.go:556` |
| ServerKey 본문 상한(클라이언트) | 1024바이트 | `derp/derp_client.go:159` |
| ClientInfo 본문(서버) | 56 이상 256 KiB 이하 | `derp/derpserver/derpserver.go:1927-1935` |
| ServerInfo 본문(클라이언트) | 24 이상 24 + 1 MiB 이하 | `derp/derp.go:38`, `derp/derp_client.go:175-182` |
| 서버 KeepAlive | 60초 + [0, 5)초 | `derp/derp.go:44`, `derp/derpserver/derpserver.go:2635-2637` |
| 클라이언트 읽기 기한 | 120초 | `derp/derp_client.go:526` |
| 서버 핸드셰이크 기한 | 단계마다 10초 | `derp/derpserver/derpserver.go:1139`, `:1144` |
| 서버 쓰기 기한 | 2초 | `derp/derpserver/derpserver.go:90`, `:2716-2741` |
| 연결 전체 상한 | 10초 | `derp/derphttp/derphttp_client.go:362` |
| 노드 TCP 상한 | 1.5초, IPv6 우선 시 IPv4 200 ms 지연 | `derp/derphttp/derphttp_client.go:733`, `:784-795` |
| `derphttp.Client.Ping` 대기 상한 | 5초 | `derp/derphttp/derphttp_client.go:982-988` |
| 재연결 물러나기 | `min(n²×10ms, 5s) × [0.5, 1.5)` | `util/backoff/backoff.go:60-66`, `wgengine/magicsock/derp.go:558` |
| magicsock 지역 쓰기 큐 | 32, 넣기 시도 3번 | `wgengine/magicsock/derp.go:329`, `wgengine/magicsock/magicsock.go:1699-1718` |
| 서버 목적지 큐 | 32, 가득 차면 가장 오래된 것 버림 | `derp/derpserver/derpserver.go:89`, `:2204-2223` |
| 비홈 연결 정리 | 60초 미사용, 15초 주기 | `wgengine/magicsock/derp.go:1071-1077` |
| `AppName` | 32바이트 이하 ASCII `0x20`–`0x7e` | `derp/derp_client.go:97-112` |
| STUN 포트 기본값 | 3478(0일 때), -1은 끔 | `tailcfg/derpmap.go:230-233` |
| netcheck 보고·STUN 대기 | 5초, 3초 | `net/netcheck/netcheck.go:61`, `:66` |

## 6. Swiftail에 필요한 최소 부분과 생략할 수 있는 부분 (M3)

필요한 것:

1. TCP + TLS(4.1). 지역 클라이언트는 항상 TLS이고 시험 서버도 TLS다(4.1 4, 7절). `InsecureForTests` 노드에서만 인증서 검증을 끄고, 그 밖에는 `CertName` 또는 `HostName`으로 검증한다.
2. HTTP 업그레이드(3.7, 4.2)와 남은 바이트 이어받기.
3. 핸드셰이크(4.3): ServerKey 검증, NaCl box로 ClientInfo(`version` 2, `CanAckPings` true), 홈이면 NotePreferred(true), ServerInfo 열기.
4. SendPacket·RecvPacket, Ping에 Pong, PeerGone으로 역방향 경로 지우기, 모르는 프레임 건너뛰기, 받은 disco 메시지를 WireGuard로 넘기지 않기(4.4, 4.5).
5. 오류 시 연결을 버리고 물러난 뒤 재연결(4.6).
6. 홈 지역 고정 선택과 `NetInfo.PreferredDERP` 보고(4.8), 피어 홈 지역으로 보내기(4.9).
7. 맵 요청에 0이 아닌 `DiscoKey`를 넣는다. Go magicsock은 `DiscoKey`가 0인 피어(WireGuard 전용 노드가 아닌 경우)를 피어로 만들지 않으므로 DERP 경로도 생기지 않는다(`tailscale.com/wgengine/magicsock/magicsock.go:3305-3309`). disco 메시지에 답하지 않아도 Go 피어는 직접 경로가 없으면 DERP로 보낸다(`tailscale.com/wgengine/magicsock/endpoint.go:635-652`).

생략할 수 있는 것:

| 항목 | 근거 |
| --- | --- |
| STUN·netcheck 전체 | DERP 송수신은 node 키만으로 주소를 정한다(3.2). 피어는 Swiftail의 `HomeDERP`로 보내므로 Swiftail의 바깥 주소가 필요 없다(4.8 4, 4.9). 지역 측정과 홈 변경은 M4 범위다(`docs/plan.md` 5절 모듈 표의 `SwiftailMagicsock`) |
| fast-start | 시험 서버는 meta 인증서를 붙이지 않아 Go 클라이언트도 쓰지 않는다(4.2, 7절) |
| `sha256-raw:` 인증서 고정 | M8 ③에서 넣었다(계약 `SwiftailDERP.md` "M8 ③") |
| 다중 지역·역방향 경로·비홈 연결 정리 | 시험 지역이 하나다. 4.9 2의 1번만으로 모든 피어에 닿는다 |
| 클라이언트 토큰 버킷 | 이 버전 서버는 값을 보내지 않는다(3.5). 넣더라도 몇 줄이다 |
| `Ideal-Node`, `AppName` | 서버 통계용이다(3.7, `tailscale.com/derp/derp_client.go:89-95`) |
| Health·Restarting의 동작 | Go magicsock도 상태 기록 외에는 무시한다(4.5 5) |
| mesh 프레임(0x0a, 0x10, 0x11)과 PeerPresent | mesh 키가 있는 서버 간 연결 전용이다(3.2) |
| WebSocket, HTTP 프록시 | 별도 경로다(`tailscale.com/derp/derphttp/derphttp_client.go:403-436`, `:742-757`) |

## 7. 상호 운용 시험에서 확인할 것

### 7.1 `Tools/interop` `tailnet`이 띄우는 서버

| 항목 | 값 | 출처 |
| --- | --- | --- |
| DERP 서버 | `derpserver.New(key.NewNode(), …)`, 기본 설정(검증 URL·mesh 키 없음) | `Tools/interop/cmd/tailnet/main.go:83` |
| HTTP 경로 | `ServeMux`에 `/derp`(정확히 이 경로)와 `/derp/probe` | `main.go:84-86` |
| TLS | `httptest.NewUnstartedServer(mux).StartTLS()`. 루프백 임의 포트. Go 시험용 자체 서명 RSA 2048 인증서(이름 `127.0.0.1`, `::1`, `example.com`, `*.example.com`). ALPN은 `http/1.1`. meta 인증서 없음(fast-start 없음) | `main.go:87-89`, `Go 1.27.3/src/net/http/httptest/server.go:349-368`, `Go 1.27.3/src/net/http/internal/testcert/testcert.go:11-13` |
| DERPMap | 지역 1개: `RegionID` 1, `RegionCode`·`RegionName` `"test"`. 노드 1개: `Name` `"1a"`, `HostName`·`IPv4` `"127.0.0.1"`, `IPv6` `"none"`, `DERPPort`·`STUNPort`는 임의 포트, `InsecureForTests` true | `main.go:90` |
| STUN 서버 | `udp4` `127.0.0.1` 임의 포트. `ParseBindingRequest`가 통과한 요청에만 `stun.Response`(XOR-MAPPED-ADDRESS 하나)로 답한다 | `main.go:66-82` |
| `ready` 출력 | `derp.regionID` 1, `host` `127.0.0.1`, `port`, `stunPort` | `main.go:111-113` |
| 제어 서버 | 평문 HTTP testcontrol. 맵 요청의 `NetInfo.PreferredDERP`로 노드의 `HomeDERP`를 정한다 | `main.go:90-99`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1471-1496` |

Swiftail이 만날 조건: 연결 주소 `127.0.0.1:<port>`, Host `127.0.0.1:<port>`, TLS 이름 `127.0.0.1`, 자체 서명 인증서(검증을 꺼야 함), HTTP/1.1, 101 응답 뒤 바로 ServerKey 프레임. 같은 프로세스의 Go tsnet 피어도 같은 DERPMap을 받으므로 홈이 1이다(4.8).

### 7.2 확인 항목

1. 핸드셰이크: Swiftail이 101과 ServerKey를 받고, ClientInfo를 보낸 뒤 ServerInfo를 열어 `{"version":2}`를 얻는다. 서버 로그에 거절이 없다.
2. Swiftail ↔ Go tsnet 피어: Swiftail의 맵에서 Go 피어의 `HomeDERP`가 1이고, Go 피어의 `peerStatus`에서 Swiftail의 홈이 1로 보인다(`relay` 값, `Tools/interop/README.md` tailnet 절). M3 관문(UDP 에코 왕복, TCP SYN-ACK)이 DERP만으로 통과한다(`docs/plan.md` 7절 M3).
3. 받은 `FrameRecvPacket`의 보낸 키가 Go 피어의 node 키와 같다. Go 피어가 보낸 disco 메시지가 WireGuard로 들어가지 않는다.
4. Ping/Pong: Swiftail이 `FramePing`을 보내면 같은 8바이트의 `FramePong`이 온다(`tailscale.com/derp/derpserver/derpserver.go:1334-1355`).
5. KeepAlive: 60–65초마다 `FrameKeepAlive`가 오고 120초 읽기 기한에 걸리지 않는다.
6. 재연결: Swiftail의 DERP TCP 연결을 강제로 닫으면 물러난 뒤 재연결하고 왕복이 다시 된다.
7. 경계 입력: 짧은 RecvPacket·PeerGone·Ping은 버리고 연결을 유지한다. 1 MiB 초과 프레임, 틀린 magic, 열리지 않는 ServerInfo는 연결을 버린다(3.2, 3.3, 3.5). 이 항목은 Go 서버가 만들지 않으므로 Swift 단위 시험으로 확인한다.
8. 알려진 값 시험: NaCl box는 `SwiftailCrypto`의 기존 시험 벡터를 쓴다. ClientInfo 바이트 배치는 Go `derp.Client`와 같은 키·nonce로 만든 프레임과 비교한다(nonce 주입은 Go 쪽 시험 도구가 필요하다).
9. STUN(M4): `tailnet`의 STUN 서버에 3.8의 요청을 보내 `127.0.0.1:<Swiftail UDP 포트>`가 돌아오는지, SOFTWARE나 FINGERPRINT를 바꾼 요청에는 응답이 없는지 확인한다.

## 8. 확인하지 못한 것

- 운영 DERP 서버(Tailscale 운영 인프라)가 `FramePing`·`FrameHealth`·`FrameRestarting`을 언제 보내는지, `TokenBucketBytesPerSecond`를 광고하는지. 공개 소스의 `derpserver`에는 보내는 곳이 없다(3.2).
- Network 프레임워크 TLS가 Go `crypto/tls` 서버와 맺는 실제 버전·암호 조합, IP 주소 이름(`127.0.0.1`)일 때 SNI를 보내는지. 실행해 보지 않았다.
- testcontrol이 Swiftail의 `DiscoKey`·`PreferredDERP`를 받아 Go 피어의 맵에 반영하는 시점(맵 스트림 갱신 지연). 코드 경로만 확인했다(`testcontrol.go:1471-1498`).
