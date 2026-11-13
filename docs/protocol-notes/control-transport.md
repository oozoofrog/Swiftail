# 제어 전송 계층 (ts2021: controlhttp · controlbase · HTTP/2)

## 1. 머리말

| 항목 | 값 |
| --- | --- |
| 기준 소스 | `tailscale.com` v1.104.6 (CapabilityVersion 148, `tailscale.com/tailcfg/tailcfg.go:200`) |
| 작성 모델 | Claude Opus 5.5 |
| 검증 상태 | 검증: GPT-6.1 Sol, 2026-11-14, 수정 28건 |

출처는 모듈 루트 기준 `tailscale.com/<경로>:<줄>`이며, 같은 절에서 파일명만 쓴 출처는 앞서 적은 경로를 따른다. 의존 모듈 `golang.org/x/net` v0.60.0·`golang.org/x/crypto` v0.58.0도 캐시의 실제 소스를 대조했다(`tailscale.com/go.mod:139-143`). 이 모듈들은 경로 앞에 모듈명과 버전을 붙인다. 표준 라이브러리 출처 `Go 1.27.3/src/...`는 실행에 쓴 Go 소스 기준이다. RFC 원문 등 대조하지 않은 범위는 8장에 적는다.

## 2. 범위

다루는 것:

- 서버 Noise 공개 키를 얻는 `/key` 요청
- `/ts2021` HTTP 업그레이드와 80·443 포트 경쟁, ControlDialPlan (프록시·웹소켓·ACE는 요약만)
- controlbase: Noise IK 핸드셰이크와 레코드 계층
- ts2021: early payload(EarlyNoise)와 그 위의 HTTP/2 사용 방식
- 최소 HTTP/2 클라이언트 요구 사항 (저장소에서 확인되는 것과 안 되는 것을 나눔)
- `types/key`의 키 텍스트·바이너리 형식
- 핸드셰이크의 capability version
- 재사용할 수 있는 Go 시험과 testcontrol 시험 상대

다루지 않는 것: `/machine/register`, `/machine/map` 요청·응답의 내용과 map 스트림 안쪽 프레이밍(`control-map.md`), DERP·disco·WireGuard, 서버 쪽 구현.

## 3. 와이어 형식

3장의 고정 폭 다중 바이트 정수는 빅 엔디언이다(`controlbase/messages.go:43-45`, `controlbase/conn.go:170`, `:395`, `ts2021/conn.go:143`). HTTP/2·HPACK의 정수 형식은 6.3을 따른다.

### 3.1 Noise 핸드셰이크 initiation (클라이언트 → 서버, 101바이트)

| 오프셋 | 길이 | 필드 | 인코딩 | 출처 |
| --- | --- | --- | --- | --- |
| 0 | 2 | protocol version (= 기본 capability version, 4.5) | uint16 BE | `tailscale.com/control/controlbase/messages.go:32`, `:43` |
| 2 | 1 | message type = `0x01` (`msgTypeInitiation`) | u8 | `messages.go:10`, `:44` |
| 3 | 2 | payload length = 96 | uint16 BE | `messages.go:34`, `:45` |
| 5 | 32 | 클라이언트 임시(ephemeral) 공개 키, 평문 | X25519 공개 키 | `messages.go:36`, `:56-58` |
| 37 | 48 | 클라이언트 machine 공개 키 암호문(32) + 태그(16) | ChaCha20-Poly1305 | `messages.go:37`, `:59-61` |
| 85 | 16 | 빈 페이로드의 태그 | Poly1305 태그 | `messages.go:38`, `:62` |

헤더 길이 `initiationHeaderLen = 5`(`messages.go:26`). 예: 버전 148이면 헤더는 `00 94 01 00 60`이다.

### 3.2 Noise 핸드셰이크 response (서버 → 클라이언트, 51바이트)

| 오프셋 | 길이 | 필드 | 인코딩 | 출처 |
| --- | --- | --- | --- | --- |
| 0 | 1 | message type = `0x02` (`msgTypeResponse`) | u8 | `messages.go:12`, `:75` |
| 1 | 2 | payload length = 48 | uint16 BE | `messages.go:68`, `:76` |
| 3 | 32 | 서버 임시 공개 키, 평문 | X25519 공개 키 | `messages.go:69`, `:86` |
| 35 | 16 | 빈 페이로드의 태그 | Poly1305 태그 | `messages.go:70`, `:87` |

response에는 버전 필드가 없다. 헤더 길이 `headerLen = 3`(`messages.go:24`).

### 3.3 error (서버 → 클라이언트, 핸드셰이크 중에만)

| 오프셋 | 길이 | 필드 | 인코딩 | 출처 |
| --- | --- | --- | --- | --- |
| 0 | 1 | message type = `0x03` (`msgTypeError`) | u8 | `messages.go:19`, `handshake.go:218` |
| 1 | 2 | 메시지 길이 n | uint16 BE | `handshake.go:219` |
| 3 | n | 사람이 읽는 오류 문자열 | 바이트열, 암호화·인증 없음 | `messages.go:13-18`, `handshake.go:223` |

인증되지 않으므로 힌트로만 쓴다(`messages.go:16-18`). HTTP 업그레이드 경로에서는 이 메시지가 클라이언트에 도착하지 않을 수 있다(4.4의 6단계).

### 3.4 record (전송 단계, 양방향)

| 오프셋 | 길이 | 필드 | 인코딩 | 출처 |
| --- | --- | --- | --- | --- |
| 0 | 1 | message type = `0x04` (`msgTypeRecord`) | u8 | `messages.go:21`, `conn.go:169` |
| 1 | 2 | 암호문 길이 n = 평문 길이 + 16 | uint16 BE | `conn.go:170` |
| 3 | n | ChaCha20-Poly1305 암호문 + 16바이트 태그, AD 없음 | | `conn.go:171`, `:146` |

- 한 레코드의 전체 크기(헤더 포함) 최대 `maxMessageSize = 4096`, 암호문 최대 4093, 평문 최대 4077(`conn.go:28-34`).
- 받는 쪽은 `3 + n > 4096`이면 비일시적 `errReadTooBig`를 반환한다(`conn.go:97-99`, `:375-382`). 이 분기는 수신 키를 지우지는 않으며, 인증 실패 때만 키를 지우는 분기와 다르다(`conn.go:149-155`, `:230-233`). Swift에서는 잘못된 종류·길이·nonce 고갈·인증 실패를 받으면 연결을 폐기하는 정책으로 처리한다. 이는 경계 오류 뒤 재개하지 않기 위한 구현 정책이며 Go의 모든 읽기 오류가 자동으로 키를 지운다는 뜻은 아니다.
- 유효한 암호문 길이는 16~4093이다. 16 미만은 태그가 모자라 인증 실패다(`golang.org/x/crypto@v0.58.0/chacha20poly1305/chacha20poly1305.go:74-85`). 평문 0바이트 레코드도 16바이트 태그를 인증하고 nonce를 소비한 뒤 건너뛴다(`conn.go:146-147`, `:249-257`). 다만 Go의 `Write([])` 자체는 레코드를 만들지 않는다(`conn.go:300-320`).
- 쓰는 쪽은 한 번의 Write를 평문 4077바이트 단위로 잘라 여러 레코드로 보낸다(`conn.go:300-305`). 레코드 경계는 상위 데이터의 경계와 무관하다.

### 3.5 전송 nonce (12바이트)

| 오프셋 | 길이 | 값 | 출처 |
| --- | --- | --- | --- |
| 0 | 4 | 항상 0 | `conn.go:388` |
| 4 | 8 | 방향별 카운터, **uint64 빅 엔디언** | `conn.go:388`, `:395` |

- 카운터는 방향마다 0에서 시작해 레코드 하나(암호화 또는 복호화 시도 하나)마다 1 증가한다(`conn.go:146-147`, `:171-172`).
- 카운터가 `^uint64(0)`(2^64−1)이 되면 더 쓰지 못한다(`errCipherExhausted`, `handshake.go:43`, `conn.go:163-167`, `:142-144`).
- Noise 명세의 ChaChaPoly nonce는 리틀 엔디언이다(저장소 밖). 저장소 안의 참조 구현 Noise Explorer 코드도 리틀 엔디언을 쓴다(`tailscale.com/control/controlbase/noiseexplorer_test.go:164`, `:173`). 그러나 상호 운용 시험은 방향마다 전송 메시지를 하나만(카운터 0) 주고받으므로 두 방식의 차이가 드러나지 않는다(`interop_test.go:161-187`, `:237-253`). **Tailscale과 붙으려면 `conn.go`의 빅 엔디언을 따라야 한다.** 둘은 카운터 1부터 달라진다.
- 핸드셰이크 안의 암호화는 매번 새 키를 쓰고 nonce는 12바이트 전부 0이다(`handshake.go:464-494`).

### 3.6 HTTP 업그레이드 요청 (HTTP/1.1, 클라이언트 → 서버)

| 항목 | 값 | 출처 |
| --- | --- | --- |
| 메서드 | `POST` | `tailscale.com/control/controlhttp/client.go:540` |
| 경로 | `/ts2021` (`serverUpgradePath`) | `controlhttp/constants.go:26`, `client.go:251-260` |
| `Upgrade` | `tailscale-control-protocol` | `controlhttp/controlhttpcommon/controlhttpcommon.go:10`, `client.go:543` |
| `Connection` | `upgrade` | `client.go:544` |
| `X-Tailscale-Handshake` | 3.1의 initiation 101바이트를 표준 base64(패딩 포함, `base64.StdEncoding`)로 인코딩 | `controlhttpcommon.go:15`, `client.go:545` |
| `Host` | 업그레이드 URL의 호스트와 포트 | `Go 1.27.3/src/net/http/request.go:611-620`, `:683-689` |
| `Content-Length` | Go는 `0`을 보냄. testcontrol은 생략도 허용(7.3 실행 확인) | `Go 1.27.3/src/net/http/transfer.go:262-274` |
| 본문 | 없음. 헤더 끝은 `\r\n\r\n`이며 initiation을 본문에 중복 송신하지 않음 | `client.go:539-547`, `controlhttpserver.go:61-66`, `:100` |

HTTP/1.1 `Host`를 빠뜨리면 testcontrol의 핸들러에 도달하기 전에 400이 된다(`Go 1.27.3/src/net/http/server.go:1069-1075`, 7.3 실행 확인).

서버 응답:

| 항목 | 값 | 출처 |
| --- | --- | --- |
| 상태 | `101 Switching Protocols` | `controlhttpserver/controlhttpserver.go:80` |
| `Upgrade` | `tailscale-control-protocol` | `controlhttpserver.go:78` |
| `Connection` | `upgrade` | `controlhttpserver.go:79` |

101 응답 헤더 바로 뒤의 바이트부터 3.2 response가 온다. 같은 TCP 읽기에 HTTP 헤더와 Noise 바이트가 함께 들어올 수 있으므로, HTTP/1.1 파서가 읽어 둔 나머지 바이트를 Noise 계층에 넘겨야 한다(`client.go:517-525`, `:559-562`).

### 3.7 early payload (서버 → 클라이언트, Noise 평문 스트림의 맨 앞, 선택)

| 오프셋 | 길이 | 필드 | 인코딩 | 출처 |
| --- | --- | --- | --- | --- |
| 0 | 5 | `EarlyPayloadMagic` = `ff ff ff 54 53` (`"\xff\xff\xffTS"`) | 바이트 | `tailscale.com/control/ts2021/conn.go:91` |
| 5 | 4 | JSON 길이 L | uint32 BE | `conn.go:143`, `client_test.go:433-434` |
| 9 | L | `tailcfg.EarlyNoise` JSON | UTF-8 JSON | `conn.go:148-156` |

- 이 9바이트 헤더는 HTTP/2 프레임 헤더 크기와 같다. 서버가 보내는 Noise 평문의 첫 9바이트는 HTTP/2 SETTINGS 프레임 헤더이거나 이 헤더다(`conn.go:81-87`).
- L > 10 MiB(`10<<20`), 첫 9바이트 또는 본문의 중간 EOF, JSON 해석 실패는 오류이며 이후 읽기도 같은 오류가 된다(`conn.go:127-156`). L=0은 빈 JSON이어서 실패한다. JSON은 길이 L만큼 읽고 한 번 해석하며 줄바꿈으로 구분하지 않는다(`conn.go:148-156`).
- 매직이 아니면 읽은 9바이트를 되돌려 HTTP/2 입력으로 그대로 쓴다(`conn.go:137-141`).
- JSON 객체의 알려진 필드는 `{"nodeKeyChallenge":"chalpub:<64 hex>"}`다(`tailcfg/tailcfg.go:3087-3091`, `types/key/chal.go:19`, `:76-77`). Go는 포인터에 `json.Unmarshal`하므로 `null`은 payload 없음, `{}`는 0 challenge, 알 수 없는 필드는 무시한다. 알려진 키 필드가 잘못된 접두사·길이·hex이면 실패한다(`ts2021/conn.go:153-157`, `types/key/chal.go:85-87`; `Go 1.27.3/src/encoding/json/decode.go:30-49`, `:72-95`).
- 용도: 클라이언트가 WireGuard(node) 개인 키를 가졌음을 증명하는 데 쓰라고 연결마다 주는 임의 공개 키(`tailcfg.go:3088-3089`). 이 버전의 클라이언트 코드에서 `GetEarlyPayload`나 `NodeKeyChallenge`를 쓰는 곳은 시험 외에 없다(저장소 전체 검색 결과, `ts2021/conn.go:63` 정의만 존재).
- 서버 시험 구현은 매직·길이·JSON을 각각 따로 Write하므로 여러 Noise 레코드에 나뉘어 올 수 있다(`client_test.go:437-445`, `controlbase/conn.go:300-305`).

### 3.8 `/key` 응답 (`tailcfg.OverTLSPublicKeyResponse`)

| JSON 필드 | 형식 | 의미 | 출처 |
| --- | --- | --- | --- |
| `legacyPublicKey` | `"mkey:<64 hex>"` | 옛 NaCl crypto_box 키. 충분히 새 클라이언트(`v` 인자 기준)에는 0일 수 있음 | `tailcfg.go:2977-2983` |
| `publicKey` | `"mkey:<64 hex>"` | Noise 핸드셰이크에 쓸 서버 정적 공개 키 | `tailcfg.go:2985-2988` |

0 키도 접두사 + 0 64개로 직렬화된다(`types/key/machine.go:252-254`에 0 검사 없음).

## 4. 절차와 상태 기계

### 4.1 서버 공개 키 얻기 (`/key`)

1. `GET <serverURL>/key?v=<CurrentCapabilityVersion>`을 보낸다. 제어 서버 URL 그대로(scheme 포함)에 붙인다(`tailscale.com/control/controlclient/direct.go:1535-1537`, `control/tsp/tsp.go:112`). 이 요청은 Noise가 아닌 일반 HTTP(S)다. HTTPS 키 조회에서는 인증서 검증 오류를 반환하는 `tlsdial.Config`를 쓰며, 업그레이드의 인증서 오류 무시 정책(4.4)을 여기에 적용하면 안 된다(`direct.go:355-359`, `net/tlsdial/tlsdial.go:111-115`, `:166-226`). testcontrol의 평문 `/key`는 로컬 시험용 신뢰 전제다.
2. 응답 본문은 64 KiB(`64<<10`)까지만 읽는다(`direct.go:1546`).
3. 상태가 200이 아니면 실패(`direct.go:1551-1553`).
4. 본문을 3.8의 JSON으로 해석한다. 실패하면 옛 형식(접두사 없는 64자 hex 하나 = legacy 키)으로 다시 해석하고, 그것도 실패하면 두 오류를 합쳐 실패한다(`direct.go:1554-1568`, `types/key/machine.go:196-202`).
5. `publicKey`가 0이면 "control server is too old; no noise key"로 중단한다(`direct.go:700-702`).
6. 캐시: 결과를 `serverLegacyKey`·`serverNoiseKey`에 저장하고, 로그인 시 `serverLegacyKey`가 0일 때만 다시 가져온다(`direct.go:641-642`, `:675-692`). 가져온 뒤 TLS 유휴 연결을 닫는다(`direct.go:694-697`). `loadServerPubKeys` 자체에는 재시도가 없다(`direct.go:1535-1569`).
7. testcontrol은 `v` 값이 비어 있으면(누락 또는 `?v=`) `text/plain`으로 legacy 키의 접두사 없는 hex만 주고, 비어 있지 않으면 JSON을 준다. 숫자 변환·버전 범위 검사는 하지 않는다(`tstest/integration/testcontrol/testcontrol.go:525-537`). 따라서 `v=148`을 붙인다. 첫 `/key` 요청이 시험 서버의 Noise 키 쌍도 생성하므로 `/ts2021`보다 먼저 호출한다(`testcontrol.go:487-490`, `:508-526`).

### 4.2 dial 전체 흐름 (`ts2021.Client.dial`)

1. 서버 URL에서 포트를 정한다(`tailscale.com/control/ts2021/client.go:134-156`).
   - 기본: HTTP 80, HTTPS 443.
   - 명시 포트 + `https`: HTTP 포트 `""`, HTTPS 포트 = 명시 포트. HTTP 포트 `""`는 controlhttp에서 다시 80이 된다(`controlhttp/client.go:253`).
   - 명시 포트 + `http`: HTTP 포트 = 명시 포트, HTTPS 443. 단 호스트가 사설·루프백 IP이거나 `localhost`면 HTTPS 없음.
   - 포트 없음 + `http` + 사설 호스트: HTTP 80, HTTPS 없음.
   - HTTPS 없음은 `NoPort`(`"none"`)로 전달된다(`client.go:250`, `controlhttp/constants.go:32`).
2. 전체 dial 제한 시간: 기본 5초, DialPlan이 있으면 후보들 중 `DialStartDelaySec + DialTimeoutSec`의 최댓값(5보다 클 때). 여기에 핸드셰이크용 5초를 더하고 [5, 60]초로 자른다(`ts2021/client.go:213-245`). 같은 문맥의 마감 시각이 핸드셰이크 중 소켓 마감으로 걸린다(`controlbase/handshake.go:127-134`).
3. DialPlan이 있고 후보가 1개 이상이면 4.3, 아니면 4.4의 포트 경쟁을 바로 한다(`controlhttp/client.go:102-107`).

### 4.3 ControlDialPlan (요약)

- 형식: `ControlDialPlan{Candidates []ControlIPCandidate}`, 후보 필드 `IP`, `ACEHost`, `DialStartDelaySec`, `DialTimeoutSec`, `Priority`(`tailcfg.go:2335-2365`). 맵 응답의 `ControlDialPlan` 필드로 내려온다(`tailcfg.go:2197-2200`).
- 후보마다 `DialStartDelaySec` 뒤에 병렬로 시작하고, 후보마다 `DialTimeoutSec` 제한을 건다. DNS 대신 후보 IP로 접속하되 URL 호스트명은 원래 이름을 유지한다(`controlhttp/client.go:122-151`, `:410-415`).
- 처음 성공한 연결을 쓰고 나머지는 닫는다. 모두 실패하면 DNS로 4.4를 한다(`client.go:153-170`).
- 이 dial 코드는 `Priority`를 읽지 않는다(`client.go:122-151`).
- `ACEHost`가 있으면 HTTPS CONNECT 터널을 쓰고 443 시도는 하지 않는다(`tailcfg.go:2346-2351`, `controlhttp/client.go:261-263`, `:427-436`, `:464-469`).
- 환경 변수 `TS_USE_CONTROL_DIAL_PLAN`로 끌 수 있다(`client.go:104`).

### 4.4 포트 경쟁과 HTTP 업그레이드

1. 경쟁 규칙(`controlhttp/client.go:239-340`):
   1. 443 강제가 아니면(또는 443이 없으면) `http://host:HTTPPort/ts2021` 시도를 바로 시작한다(`:291-293`).
   2. 443이 있으면 500ms 뒤에 `https://host:HTTPSPort/ts2021` 시도를 시작한다. 443 강제면 지연 0(`:87-94`, `:298-305`).
   3. 80 시도가 실패하고 443 타이머가 아직 안 돌았으면 443을 즉시 시작한다(`:320-329`).
   4. 처음 성공한 연결을 반환한다. 양쪽을 시도한 경우 두 오류가 모이면 실패한다(`:315-337`). HTTPS가 비활성화된 경우에는 HTTP 실패만으로 이 조건이 성립하지 않아 문맥 마감·취소까지 기다린다(`:261-263`, `:307-336`). Swift에서 단일 후보 실패를 즉시 반환하는 것은 별도 구현 정책이다. 나머지 시도는 문맥 취소로 닫힌다(`:240-244`, `:281-284`).
   5. 443 강제 조건: 환경 변수 `TS_FORCE_NOISE_443`, plan9, 또는 직전 Noise dial이 2분 안에 있었을 때(`client.go:181-214`, `health/health.go:1414-1425`).
2. 시도 하나(`dialURL`, `client.go:346-363`):
   1. 4.5의 1~8단계로 initiation 101바이트를 만든다.
   2. TCP(또는 TLS)로 접속해 3.6의 요청을 보낸다. TLS일 때 ALPN은 비운다(HTTP/2로 협상되면 업그레이드를 못 하므로, `client.go:479-481`). 인증서 검증 실패는 기록만 하고 연결을 계속한다. Noise가 서버를 인증하기 때문이다(`client.go:493-502`). 응답 압축은 끈다(`client.go:505`).
   3. 상태가 101이 아니면 `unexpected HTTP response`로 실패(`client.go:555-557`).
   4. 응답 `Upgrade` 값이 정확히 `tailscale-control-protocol`이 아니면 실패(`client.go:569-572`). 클라이언트는 `Connection` 헤더를 검사하지 않는다.
   5. 4.5의 9단계 이후를 같은 소켓에서 이어 간다. 실패하면 소켓을 닫는다(`client.go:355-359`).
3. 서버 쪽 동작(상대가 무엇을 기대하는지):
   1. `Upgrade` 값을 소문자로 바꿔 비교한다. 비어 있으면 400, `websocket`이면 웹소켓 경로, 그 밖의 값이면 400(`controlhttpserver.go:48-59`).
   2. `X-Tailscale-Handshake`가 없거나 base64가 틀리면 400(`controlhttpserver.go:61-70`).
   3. HTTP/1이 아니어서 hijack할 수 없으면 400 "make request over HTTP/1"(`controlhttpserver.go:72-76`).
   4. 101을 쓰고 연결을 가로챈 뒤 버퍼에 남은 클라이언트 바이트를 먼저 읽게 한다(`controlhttpserver.go:78-96`).
   5. 쓰기를 "cork"해 둔 채 핸드셰이크를 하고, early payload를 쓴 다음 한 번에 내보낸다(`controlhttpserver.go:98-119`, `:174-230`). 그래서 response 51바이트와 early payload 레코드가 함께 도착할 수 있다.
   6. 핸드셰이크가 실패하면 cork 버퍼를 내보내지 않고 연결을 닫는다(`controlhttpserver.go:87-91`, `:100-103`). 따라서 HTTP 업그레이드 경로에서는 3.3 error 메시지 대신 101 뒤의 EOF를 볼 수 있다. 클라이언트는 101 직후 EOF를 핸드셰이크 실패로 처리한다.
   7. AcceptHTTP 자체는 메서드를 검사하지 않는다. testcontrol은 `/ts2021`에서 POST와 GET만 받는다(`testcontrol.go:476-485`).
4. 프록시(요약): 평문·TLS 모두 HTTP 프록시 설정을 따른다(`client.go:470-477`). 시험 사례: 프록시 없음, port80 MITM, SOCKS5, HTTP→HTTP/HTTPS 프록시 등(`controlhttp/http_test.go:56-140`).
5. 웹소켓(요약): JS 빌드 전용 경로. 기본은 `wss://host/ts2021`이지만 사용자 지정 HTTP 포트 조건에서는 `ws://host:port/ts2021`이다(`controlhttp/client_js.go:31-40`). `X-Tailscale-Handshake` 쿼리 값은 initiation의 표준 base64를 URL 쿼리 인코딩한 것이다(`client_js.go:41-49`). `+` 등을 그대로 붙이면 폼 해석 시 달라질 수 있으므로 인코딩을 생략하지 않는다. 하위 프로토콜은 `tailscale-control-protocol`, 바이너리 메시지 위에 같은 Noise 바이트 스트림을 싣는다(`client_js.go:51-58`, `controlhttpserver.go:144-165`).

### 4.5 controlbase 핸드셰이크 (클라이언트 = initiator)

표기: `h`, `ck`는 32바이트. `BLAKE2s`는 BLAKE2s-256, 키 없음(`handshake.go:440-450`). `HKDF(ck, ikm)`는 BLAKE2s 기반 HKDF로 salt = `ck`, 입력 키 재료 = `ikm`, info 없음이며 출력 앞 32바이트와 다음 32바이트를 쓴다(`handshake.go:376-383`, `:422-428`; HKDF 자체 정의는 `golang.org/x/crypto@v0.58.0/hkdf/hkdf.go:27-37`, `:63-70`, `:90-99`). `MixHash(x)`: `h = BLAKE2s(h ‖ x)`(`handshake.go:350-358`). `MixDH(priv, pub)`: `dh = X25519(priv, pub)`, `(ck, k) = HKDF(ck, dh)`, k는 한 번만 쓰는 ChaCha20-Poly1305 키(`handshake.go:360-385`). `EncryptAndHash(k, pt)`: `c = Seal(k, nonce=0¹², ad=h, pt)`, `MixHash(c)`(`handshake.go:387-397`). `DecryptAndHash(k, c)`: `Open(k, nonce=0¹², ad=h, c)`가 성공하면 `MixHash(c)`(`handshake.go:399-413`).

여기서 HKDF의 두 출력은 `prk = HMAC-BLAKE2s(key=ck, data=ikm)`, `t1 = HMAC-BLAKE2s(key=prk, data=01)`, `t2 = HMAC-BLAKE2s(key=prk, data=t1 ‖ 02)`의 `(t1, t2)`다. `01`·`02`는 각각 1바이트이며 BLAKE2s keyed hash로 HMAC를 대신하면 안 된다(`golang.org/x/crypto@v0.58.0/hkdf/hkdf.go:27-37`, `:63-70`, `:90-99`; `Go 1.27.3/src/crypto/internal/fips140/hkdf/hkdf.go:13-24`).

1. `h = BLAKE2s("Noise_IK_25519_ChaChaPoly_BLAKE2s")`, `ck = h`(`handshake.go:31`, `:344-348`). 이름은 33바이트라 Noise 규칙(32바이트 이하면 0 채움)으로도 해시 경로를 탄다(`noiseexplorer_test.go:182-189`).
2. `MixHash(prologue)`. prologue = ASCII `"Tailscale Control Protocol v"` + 버전의 10진 문자열, 종료 문자 없음. 예: 버전 148 → `Tailscale Control Protocol v148`(`handshake.go:42`, `:46-50`, `:73`).
3. `MixHash(서버 정적 공개 키 32바이트)`(`handshake.go:77`).
4. 임시 키 쌍 e를 만든다. `key.NewMachine()`은 32바이트 난수를 X25519 규칙으로 clamp한다(`handshake.go:81-82`, `types/key/machine.go:42-46`, `types/key/util.go:51-54`). `e.pub`을 initiation[5:37]에 쓰고 `MixHash(e.pub)`(`handshake.go:83-84`).
5. es: `k1 = MixDH(e.priv, 서버 정적 공개 키)`(`handshake.go:85`).
6. `EncryptAndHash(k1, 클라이언트 machine 공개 키 32바이트)` → 48바이트를 initiation[37:85]에(`handshake.go:89-90`).
7. ss: `k2 = MixDH(machine 개인 키, 서버 정적 공개 키)`(`handshake.go:91`).
8. `EncryptAndHash(k2, 빈 평문)` → 16바이트 태그를 initiation[85:101]에(`handshake.go:95`). 3.6처럼 헤더에 실어 보낸다.
9. 3바이트 헤더를 읽는다. 종류가 `0x02`가 아니면: `0x03`이면 길이만큼 읽어 "server error"로 실패, 그 밖이면 "unexpected response message type"으로 실패(`handshake.go:137-150`).
10. 길이가 48이 아니면 실패. 48바이트를 읽는다(`handshake.go:151-156`).
11. `re`(서버 임시 공개 키)로 `MixHash(re)`(`handshake.go:159-160`).
12. ee: `MixDH(e.priv, re)`. 반환된 키는 버리고 `ck`만 갱신한다(`handshake.go:161-163`).
13. se: `k3 = MixDH(machine 개인 키, re)`(`handshake.go:164-167`).
14. `DecryptAndHash(k3, 태그 16바이트)`. 실패하면 "decrypting payload"로 중단(`handshake.go:168-170`).
15. Split: `(k_a, k_b) = HKDF(ck, 빈 입력)`(`handshake.go:418-437`). 클라이언트 송신 = `k_a`, 수신 = `k_b`. 서버는 반대(`handshake.go:177-188`, `:313-324`). 두 방향 nonce는 각각 0에서 시작한다.
16. 최종 `h`가 handshake hash다(`handshake.go:181`, `conn.go:76-82`). 이 저장소에서 시험 밖에서 읽는 곳은 없다.

X25519 입력은 각각 32바이트여야 하며, 저차수 공개 키 등 공유 비밀이 모두 0이 되는 입력은 오류로 거부한다(`golang.org/x/crypto@v0.58.0/curve25519/curve25519.go:20-26`, `:77-92`). 해당 단계 이름으로 실패시키며 0 공유 비밀을 HKDF에 넣고 계속하지 않는다(`handshake.go:369-374`). 서버는 버전 값으로 핸드셰이크를 막지 않고 프롤로그에만 섞는다(`handshake.go:241-246`, `:262`). 서버 쪽 initiation 검증 실패 문구: 크기 오류 "wrong handshake initiation size", 종류 오류 "unexpected handshake message type", 길이 오류 "wrong handshake initiation length"(`handshake.go:233-252`).

핸드셰이크의 모든 AEAD는 nonce=0¹², AAD=그 연산 직전의 `h`다. initiation·response의 type·length 헤더 자체는 `MixHash`하거나 AAD에 직접 넣지 않는다. 버전만 프롤로그를 통해 인증된다(`handshake.go:71-95`, `:159-168`, `:387-413`). 레코드는 이와 달리 AAD가 없으며 헤더도 AAD가 아니다(`conn.go:146`, `:169-171`).

capability version은 `/key?v=148`, initiation의 uint16 BE, 프롤로그의 십진 문자열에 각각 실린다(`direct.go:1536`, `messages.go:43`, `handshake.go:46-50`). 응답에 버전을 되돌려 협상하지 않는다. `ts2021.ClientOpts.ProtocolVersion`이 0이 아니면 핸드셰이크에는 그 값을 쓰고, 0이면 현재 값 148을 쓴다(`ts2021/client.go:253`). 상위 요청 JSON의 `Version`은 해당 요청이 별도로 넣는 필드이며 HTTP/2 프레임 버전이나 헤더가 아니다(예: `tailcfg.go:2595-2601`, `:2648-2650`; 등록·맵은 `control-map.md`).

### 4.6 전송 단계 상태

1. 읽기: 3바이트 헤더 → 길이만큼 읽기 → 종류가 `0x04`가 아니면 오류 → nonce 검사 → 복호화 → nonce 증가(`conn.go:131-157`, `:196-239`).
2. 복호화가 한 번이라도 실패하면 수신 키를 버리고 이후 읽기는 모두 `net.ErrClosed`(`conn.go:149-155`, `:246-248`).
3. 쓰기 오류(부분 쓰기, 마감 시간 초과 포함)가 한 번이라도 나면 이후 쓰기는 모두 실패한다(`conn.go:37-40`, `:274-293`, `:311-317`).
4. 종료: 별도 종료 메시지가 없다(종류는 1~4뿐, `messages.go:8-21`). 밑단 소켓을 닫고 암호 상태 참조를 제거한다(`conn.go:323-338`).

### 4.7 ts2021 위의 HTTP/2 사용 (저장소에서 확인되는 부분)

1. 클라이언트는 Go `net/http` Transport를 "암호화 없는 HTTP/2 전용"으로 설정하고 dial 훅에서 Noise 연결을 돌려준다(`ts2021/client.go:166-178`). 이 HTTP/2 구현은 Go 표준 라이브러리 것이다(`Go 1.27.3/src/net/http/internal/http2/transport.go:673-687`).
2. 호스트당 연결 1개(`MaxConnsPerHost: 1`, `client.go:168`). 모든 요청이 한 HTTP/2 연결에서 다중화된다. 연결 풀은 보통 0~1개, 네트워크 장애 후 재연결 중 잠시 2개(`client.go:284-286`).
3. 요청 URL은 `"https://" + host + path`다(`client.go:304`). 즉 `:scheme`은 `https`, `:authority`는 제어 서버 호스트명이 된다(`Go 1.27.3/src/net/http/internal/httpcommon/httpcommon.go:285-297`).
4. 본문이 있는 요청은 JSON, `Content-Type: application/json`, node 키가 0이 아니면 `Ts-Lb: nodekey:<hex>` 헤더(`client.go:299-318`, `tailcfg.go:3093-3109`).
5. 응답 본문은 기본 1 MiB(`httpbody.DefaultMaxSize = 1 << 20`)에서 잘라 오류로 처리한다(`client.go:320-336`, `util/httpbody/httpbody.go:30-34`). map 스트림은 상한을 끈다(`controlclient/direct.go:1150-1157`). map 응답 본문은 크기 접두사가 붙은 메시지들의 끝없는 스트림이다(`direct.go:1150-1154`, 상세는 `control-map.md`).
6. 연결이 끊기면 Transport가 다음 요청 때 다시 dial하고, dial마다 새 Noise 핸드셰이크를 한다(`client.go:174-176`, `controlhttp/client.go:346-363`). 클라이언트를 닫으면 살아 있는 Noise 연결을 모두 닫는다(`ts2021/client.go:182-197`, `controlclient/direct.go:422-436`).
7. 서버(testcontrol, ts2021 시험)는 Noise 연결 위에서 `golang.org/x/net/http2`의 `Server.ServeConn`을 기본 설정으로 돌린다(`testcontrol.go:497-505`, `ts2021/client_test.go:456-458`). 버전은 `golang.org/x/net v0.60.0`(`go.mod:143`). 다만 Go 1.27 기본 빌드에서는 x/net의 `Server`가 Go 표준 라이브러리 HTTP/2에 위임한다. x/net의 `server.go`는 `http2legacy` 빌드 경로다(`golang.org/x/net@v0.60.0/http2/server_wrap.go:5-7`, `:115-166`, `http2/server.go:5`). 이 검증의 실제 실행 경로는 Go 1.27.3의 `src/net/http/internal/http2`다.
8. early payload를 받으려면 HTTP/2 입력을 읽기 전에 3.7의 9바이트 검사를 먼저 해야 한다(`ts2021/conn.go:103-106`, `:122-157`). Go 클라이언트는 이 검사를 첫 Read 때 지연 실행하므로 early payload를 기다리지 않고 바로 HTTP/2 프리페이스를 보낼 수 있다(`conn.go:103-106`).

## 5. 상수와 타이머

| 이름 | 값 | 출처 |
| --- | --- | --- |
| `protocolName` | `Noise_IK_25519_ChaChaPoly_BLAKE2s` | `controlbase/handshake.go:31` |
| `protocolVersionPrefix` | `Tailscale Control Protocol v` | `handshake.go:42` |
| 프로토콜 버전 | 기본 `CurrentCapabilityVersion` = 148, 명시적 `ProtocolVersion`이 있으면 그 값 | `ts2021/client.go:253`, `tailcfg.go:200` |
| `msgTypeInitiation` / `Response` / `Error` / `Record` | 1 / 2 / 3 / 4 | `controlbase/messages.go:10-21` |
| `headerLen` / `initiationHeaderLen` | 3 / 5 | `messages.go:24-26` |
| initiation / response 크기 | 101 / 51 | `messages.go:39`, `:71` |
| `maxMessageSize` | 4096 | `controlbase/conn.go:28` |
| `maxCiphertextSize` / `maxPlaintextSize` | 4093 / 4077 | `conn.go:31-34` |
| `invalidNonce` | 2^64−1 | `handshake.go:43` |
| `serverUpgradePath` | `/ts2021` | `controlhttp/constants.go:26` |
| `UpgradeHeaderValue` | `tailscale-control-protocol` | `controlhttpcommon.go:10` |
| `HandshakeHeaderName` | `X-Tailscale-Handshake` | `controlhttpcommon.go:15` |
| `NoPort` | `none` | `controlhttp/constants.go:32` |
| 443 대기 | 500ms | `controlhttp/client.go:87-94` |
| 최근 dial로 443 강제 | 2분 | `health/health.go:1414-1425` |
| dial 제한 시간 | 기본 5+5초, [5, 60]초로 자름 | `ts2021/client.go:213-243` |
| `EarlyPayloadMagic` | `ff ff ff 54 53` | `ts2021/conn.go:91` |
| early payload 헤더 / 최대 | 9바이트 / 10 MiB | `ts2021/conn.go:87`, `:144` |
| `LBHeader` | `Ts-Lb` | `tailcfg.go:3109` |
| 응답 본문 기본 상한 | 1 MiB | `util/httpbody/httpbody.go:34` |
| `/key` 응답 상한 | 64 KiB | `controlclient/direct.go:1546` |
| 프로토콜 버전 최대 | `math.MaxUint16` (넘으면 panic) | `ts2021/client.go:202-206` |

### 5.1 키 문자열·바이너리 형식 (`types/key`)

모든 텍스트 형식은 `접두사 + 키 바이트의 hex`다(`types/key/util.go:56-61`). 읽을 때 접두사가 정확히 맞아야 하고, hex 길이는 키 길이의 2배여야 하며 대소문자 hex를 모두 받는다(`util.go:63-101`). 저장소 시험 벡터는 소문자다(`types/key/machine_test.go:43-44`). JSON에서는 이 텍스트가 JSON 문자열로 들어간다(MarshalText 구현, 예: `machine_test.go:42-45`, `node_test.go:58-60`).

| 키 | 개인 키 텍스트 | 공개 키 텍스트 | 바이트 길이 | 출처 |
| --- | --- | --- | --- | --- |
| machine (X25519) | `privkey:` | `mkey:` | 32 | `machine.go:24`, `:31`, `:71-83`, `:252-264` |
| node (X25519, WireGuard) | `privkey:` | `nodekey:` | 32 | `node.go:29`, `:36`, `:116-128`, `:333-347` |
| disco (X25519) | 텍스트 형식 없음 | `discokey:` | 32 | `disco.go:23`, `:56-77`, `:188-200` |
| challenge (X25519) | 직렬화 거부 | `chalpub:` | 32 | `chal.go:19`, `:45-47`, `:76-88` |
| network-lock (Ed25519) | `nlpriv:` (64바이트 → 128 hex) | `nlpub:` (읽을 때 `tlpub:`도 허용, CLI 표시는 `tlpub:`) | 개인 64 / 공개 32 | `nl.go:18-29`, `:36`, `:60-72`, `:116`, `:133-157` |

- node 공개 키 바이너리 형식: ASCII `np` + 32바이트(총 34), 다른 길이·접두사는 오류(`node.go:40`, `:350-369`).
- machine 공개 키의 접두사 없는 hex 파서는 이 전송 경로의 `/key` 옛 형식에 쓰인다(`control/controlclient/direct.go:1560-1568`, `types/key/machine.go:196-202`). node 공개 키에도 별도 파서가 있으며 DERP 등의 다른 경로에서도 쓴다. `/key` 전용이라는 일반화는 하면 안 된다(`types/key/node.go:203`, `derp/derphttp/derphttp_client.go:1203`).
- 짧은 표시(`ShortString`): `[` + 표준 base64의 앞 5자 + `]`, 0 키는 빈 문자열(`util.go:103-120`). 로그용이며 와이어 형식이 아니다.
- machine·node·disco 개인 키는 생성 시 clamp한다(`machine.go:45`, `node.go:61`, `disco.go:41`). challenge 키는 node 키와 같은 방식으로 만든다(`chal.go:32-34`). 텍스트 역직렬화는 machine·node 개인 키를 다시 clamp하지 않고 입력 바이트를 보존한다(`machine.go:81-82`, `node.go:126-127`). Noise에서 사용하는 키 바이트는 접두사 없는 raw 32바이트이며 `mkey:` 텍스트나 node의 34바이트 `np` 형식이 아니다(`controlbase/handshake.go:77-90`, `:369`).
- initiation은 HTTP 업그레이드에서는 `X-Tailscale-Handshake` 헤더, WebSocket에서는 같은 이름의 URL 쿼리 값에 표준 base64로 들어간다. 키 텍스트의 hex와 혼동하지 않는다(`controlhttp/client.go:545`, `controlhttp/client_js.go:47-49`).

## 6. Swiftail에 필요한 최소 부분과 생략할 수 있는 부분

M2 관문(전송 부분): "Swift 클라이언트가 testcontrol과 Noise 핸드셰이크를 마치고 HTTP/2 요청 하나를 주고받는다."

### 6.1 꼭 구현할 것

1. `/key?v=148` 평문 HTTP/1.1 GET과 JSON의 `publicKey`(`mkey:` hex) 해석. testcontrol은 평문 HTTP로만 뜬다(`cmd/testcontrol/testcontrol.go:25`, `:40-43`, `:54-57`).
2. 평문 TCP 위 HTTP/1.1 업그레이드 요청 작성, 101 응답 검증(상태, `Upgrade` 값), 헤더 뒤 남은 바이트 인계(3.6, 4.4).
3. 4.5의 클라이언트 핸드셰이크 전체. 필요한 원시 연산: X25519, BLAKE2s-256, HMAC-BLAKE2s 기반 HKDF, ChaCha20-Poly1305.
4. 3.4·3.5의 레코드 계층: 빅 엔디언 nonce, 쓰기 4077바이트 분할, 읽기 4096 상한, 0바이트 레코드 건너뛰기, 복호화 실패 시 연결 폐기.
5. 3.7 early payload 검사. testcontrol은 보내지 않지만(`testcontrol.go:490`에서 earlyWrite가 nil), 클라이언트가 버전 49 이상을 알리면 서버가 보낼 수 있다(`tailcfg.go:100`). 매직을 못 걸러내면 HTTP/2 파싱이 깨지므로 처음부터 넣는다. M2는 challenge를 사용하지 않아도 되지만, 길이 상한·완전한 본문 수신·JSON 해석과 알려진 키 필드의 유효성 검사는 유지한다(`ts2021/conn.go:143-157`, `types/key/chal.go:85-87`).
6. 4.7에 맞는 HTTP/2 클라이언트 최소 기능: 연결 1개, 요청 스트림 1개 이상, `:scheme https`, `:authority` = 호스트. 프레임·HPACK·흐름 제어의 필수 처리는 6.3을 따른다.
7. testcontrol에서 받을 경로를 고른다. testcontrol은 Noise 위 HTTP/2 요청도 같은 mux로 처리하며(`testcontrol.go:500-505`), 등록되지 않은 경로를 받으면 고루틴에서 panic해 프로세스가 죽는다(`testcontrol.go:413`, `:430-434`). M2용 요청은 `GET /generate_204`(204, 본문 없음, `testcontrol.go:414-416`) 또는 `GET /key?v=148`(JSON 본문, `testcontrol.go:417`, `:525-537`)을 권한다. 후자는 DATA 프레임 수신까지 확인한다.

### 6.2 뒤로 미룰 수 있는 것과 근거

| 항목 | 근거 |
| --- | --- |
| 443 TLS 폴백, 80·443 경쟁, 443 강제 | testcontrol은 사설 주소 `http://` URL이라 HTTPS 시도가 아예 없다(`ts2021/client.go:143-150`, `controlhttp/client.go:261-263`, `:291-293`) |
| ControlDialPlan, ACE | 맵 응답을 받은 뒤에야 생기는 정보다(`tailcfg.go:2197-2200`) |
| HTTP 프록시, SOCKS5, 웹소켓 | 운영 환경 호환용(`controlhttp/client.go:470-477`, `client_js.go`) |
| handshake hash 노출 | 저장소 안 시험 외 사용처 없음(4.5의 16단계) |
| `Ts-Lb` 헤더 | node 키가 0이면 붙이지 않는다(`ts2021/client.go:313-318`). M2 요청에는 node 키가 없다 |
| legacy 키, `/key` 옛 형식 | Noise 경로에는 `publicKey`만 쓴다(`direct.go:700-702`) |
| 응답 크기 상한의 요청별 조정 | 기본 1 MiB와 `/key`의 64 KiB 상한은 M2부터 유지한다. map처럼 끝없는 스트림을 위한 상한 해제만 뒤로 미룬다(`ts2021/client.go:320-336`, `controlclient/direct.go:1546`, `util/httpbody/httpbody.go:39-45`) |
| 연결 재사용·재연결 정책 | M2는 연결 1개 요청 1개다. 이후 4.7의 2·6단계를 따른다 |
| error 메시지(종류 3) 송신 | 서버만 보낸다(`handshake.go:211-227`). 클라이언트는 수신 분기만 필요하다 |

### 6.3 HTTP/2 최소 요구 사항 정리

저장소에서 확인되는 것:

- 클라이언트가 먼저 HTTP/2를 시작하는 쪽이다. 서버는 Noise 핸드셰이크와 early payload 뒤 `ServeConn`을 시작한다(`controlhttpserver.go:100-121`, `testcontrol.go:490-505`).
- 서버의 첫 HTTP/2 바이트는 SETTINGS 프레임 헤더다(`ts2021/conn.go:81-84`의 설명).
- 한 연결에서 여러 요청을 다중화하며, map 스트림처럼 끝나지 않는 응답 본문이 다른 요청과 함께 흐른다(4.7의 2·5단계).
- 서버 구현은 `golang.org/x/net/http2` v0.60.0, 기본 설정(4.7의 7단계).

의존 모듈과 실행에 사용한 Go 1.27.3 표준 라이브러리에서 확인한 최소 요구 사항(4.7의 위임 경로 참조):

- early payload 제거 뒤 Noise 평문 바이트 스트림 위에 HTTP/2를 바로 시작한다. 외부 `/ts2021`의 HTTP/1.1 업그레이드 뒤 안쪽에서 다시 HTTP/1.1 또는 `h2c` 업그레이드를 하지 않는다(`testcontrol.go:490-505`, `Go 1.27.3/src/net/http/internal/http2/server.go:793`, `:965-994`). 클라이언트는 ASCII `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` 24바이트와 non-ACK SETTINGS를 먼저 보낸다. 빈 SETTINGS도 가능하다. 프리페이스의 서버 대기는 10초, 첫 SETTINGS는 2초 제한이다(`Go 1.27.3/src/net/http/internal/http2/http2.go:65-67`, `server.go:58-59`, `:817`, `:1441-1446`, `golang.org/x/net@v0.60.0/http2/frame.go:878-884`). 서버의 non-ACK SETTINGS를 적용하고 빈 ACK SETTINGS(`00 00 00 04 01 00 00 00 00`)를 돌려주며, 수신 ACK에는 다시 ACK하지 않는다(`Go 1.27.3/src/net/http/internal/http2/server.go:1616-1641`, `golang.org/x/net@v0.60.0/http2/frame.go:887-893`). 서버 SETTINGS를 기다리느라 프리페이스 송신을 미루지 않는다.
- HTTP/2 프레임 헤더는 아래 9바이트다. payload 길이만큼 스트림에서 모아야 하며 Noise 레코드 경계와 무관하다(`http2/frame.go:249-259`, `controlbase/conn.go:258-259`, `:300-305`).

| 오프셋 | 길이 | 필드 | 인코딩 | 출처 |
| --- | --- | --- | --- | --- |
| 0 | 3 | payload length | uint24 BE, 헤더 제외 | `golang.org/x/net@v0.60.0/http2/frame.go:255` |
| 3 | 1 | type | DATA=0, HEADERS=1, SETTINGS=4, PING=6, GOAWAY=7, WINDOW_UPDATE=8, CONTINUATION=9 | `http2/frame.go:32-43` |
| 4 | 1 | flags | END_STREAM=1, END_HEADERS=4, SETTINGS/PING ACK=1(종류별 의미) | `http2/frame.go:76-95` |
| 5 | 4 | reserved bit + stream ID | uint32 BE의 하위 31비트 | `http2/frame.go:258` |

- SETTINGS payload는 `ID:uint16 BE + value:uint32 BE`의 6바이트 항목 나열이며 stream ID=0, ACK payload는 빈 값이다(`golang.org/x/net@v0.60.0/http2/frame.go:766-825`, `:878-893`).
- 요청은 stream 1부터 홀수 ID를 증가시킨다(`Go 1.27.3/src/net/http/internal/http2/server.go:1865-1903`). 본문 없는 GET은 HEADERS에 END_STREAM을 붙이고, 헤더 블록 종료는 END_HEADERS다. 응답은 HEADERS 또는 DATA의 END_STREAM까지 읽으며, CONTINUATION은 END_HEADERS까지 같은 스트림의 헤더 블록으로 합친다(`golang.org/x/net@v0.60.0/http2/frame.go:76-95`, `:590-617`, `:1588-1590`). M2에는 `:method GET`, `:scheme https`, `:authority tail0001`(시험용 호스트), `:path /key?v=148`을 보낼 수 있다(`ts2021/client.go:304`, 7.3 실행 확인). 의사 헤더는 일반 헤더보다 앞서고 이름은 소문자여야 한다(`golang.org/x/net@v0.60.0/http2/frame.go:1730-1738`).
- 응답 HPACK는 정적 테이블뿐 아니라 기본 4096바이트 동적 테이블, indexed/literal 표현·table size update·허프만 문자열을 처리해야 한다. 서버는 일치하는 항목을 인덱스로 쓰고, 민감하지 않고 크기가 맞는 필드를 동적 테이블에 넣으며, 허프만이 짧아지면 사용한다(`Go 1.27.3/src/net/http/internal/http2/server.go:305-306`, `golang.org/x/net@v0.60.0/http2/hpack/encode.go:49-99`, `:138-140`, `:215-227`). HPACK 정수는 BE 고정 폭이 아니라 첫 바이트의 n비트 prefix와 이어지는 하위 7비트 단위 가변 길이 정수다. indexed는 `1`+7비트, incremental literal은 `01`+6비트, without indexing은 `0000`+4비트, never indexed는 `0001`+4비트, table size update는 `001`+5비트이며, 문자열은 Huffman 플래그 1비트+7비트 prefix 길이 뒤에 바이트가 온다(`http2/hpack/hpack.go:303-330`, `:433-500`). 송신 인코더는 literal·허프만 미사용으로 시작해도 되지만 수신 디코더에서 허프만을 생략할 수는 없다. 클라이언트가 처음 SETTINGS_HEADER_TABLE_SIZE=0을 보내 동적 항목 생성을 막는 단순화는 가능하되, 서버의 SETTINGS 처리 전 응답·table size update까지 고려해야 한다(`Go 1.27.3/src/net/http/internal/http2/server.go:1653-1659`, `:1166-1174`).
- 연결·스트림의 초기 송신 창은 각각 65535바이트, 초기 최대 프레임 payload는 16384바이트다(`golang.org/x/net@v0.60.0/http2/http2.go:74-85`, `http2/flow.go:87-89`). testcontrol 기본 서버는 MAX_FRAME_SIZE=1048576, MAX_CONCURRENT_STREAMS=250, MAX_HEADER_LIST_SIZE=1048896, HEADER_TABLE_SIZE=4096, INITIAL_WINDOW_SIZE=1048576을 알리고, 연결 창 증가 WINDOW_UPDATE(0, 983041)도 보낸다(`Go 1.27.3/src/net/http/internal/http2/config.go:50-75`, `server.go:58-61`, `:769-791`; 7.3 실행 확인). 확장 SETTINGS도 올 수 있으므로 모르는 ID는 무시한다(`Go 1.27.3/src/net/http/internal/http2/server.go:1670-1683`). 이 서버 값들을 클라이언트 자신의 수신 한도와 혼동하지 않는다.
- DATA 송수신은 연결·스트림 양쪽 흐름 제어를 적용한다. SETTINGS_INITIAL_WINDOW_SIZE는 스트림 창을 바꾸고 연결 창은 WINDOW_UPDATE(stream 0)가 바꾼다(`golang.org/x/net@v0.60.0/http2/flow.go:68-105`, `Go 1.27.3/src/net/http/internal/http2/server.go:1517-1550`, `:1688-1701`). 긴 map 응답은 소비한 DATA에 대해 두 창 모두 WINDOW_UPDATE로 돌려줘야 멎지 않는다(`golang.org/x/net@v0.60.0/http2/transport.go:2235-2278`; Go 1.27 경로도 `Go 1.27.3/src/net/http/internal/http2/transport.go:2431-2448`). 서버도 요청 본문을 소비하면 창을 돌려주며, 작은 증가는 누적한다(`Go 1.27.3/src/net/http/internal/http2/server.go:2406-2436`, `golang.org/x/net@v0.60.0/http2/flow.go:29-55`). 한 번의 작은 GET에서는 창 보충이 필요 없더라도 WINDOW_UPDATE 수신 처리는 필요하다.
- PING은 non-ACK일 때 같은 8바이트를 ACK로 돌려주고 ACK에는 응답하지 않는다(`Go 1.27.3/src/net/http/internal/http2/server.go:1493-1514`). testcontrol 기본 설정은 IdleTimeout·SendPingTimeout=0이므로 주기적 PING·유휴 종료 타이머를 켜지 않는다. 설정되면 타이머를 켜며 PingTimeout 기본은 15초다(`Go 1.27.3/src/net/http/internal/http2/server.go:804-813`, `config.go:65`). 연결 오류는 GOAWAY, 스트림 오류는 RST_STREAM으로 올 수 있으므로 M2에서도 실패로 종료하고 새 요청을 무작정 보내지 않는다(`Go 1.27.3/src/net/http/internal/http2/server.go:1412-1435`). 정상 GOAWAY를 받은 연결에도 새 스트림을 시작하지 않는다(`Go 1.27.3/src/net/http/internal/http2/transport.go:856-863`).
- 일반 요청의 `:method`·`:path`는 비어 있으면 안 되고 `:scheme`은 `http` 또는 `https`여야 한다. `:authority`가 없으면 Host를 쓰며, authority의 userinfo(`@`)를 거부한다(`Go 1.27.3/src/net/http/internal/http2/server.go:2132-2157`, `Go 1.27.3/src/net/http/internal/httpcommon/httpcommon.go:587-593`). x/net legacy 경로는 authority와 Host의 불일치·잘못된 Host 문자도 검사하지만, 이 검사를 Go 1.27 위임 경로에 그대로 일반화하지 않는다(`golang.org/x/net@v0.60.0/internal/httpcommon/request.go:437-470`). Swift 송신은 유효한 authority를 쓰고 Host를 중복하지 않는다(`Go 1.27.3/src/net/http/internal/httpcommon/httpcommon.go:289-309`). Noise 위의 `https` scheme은 추가 TLS 핸드셰이크를 뜻하지 않는다(`testcontrol.go:490-505`, `ts2021/client.go:170-175`).
- 실제 Go 표준 클라이언트는 프리페이스 뒤 ENABLE_PUSH=0, INITIAL_WINDOW_SIZE=4 MiB, MAX_FRAME_SIZE=1 MiB, MAX_HEADER_LIST_SIZE=10 MiB의 SETTINGS와 연결 WINDOW_UPDATE 증가량 1 GiB를 보낸다. 이는 Go 1.27.3의 선택이지 Swift의 필수 값이 아니다(`Go 1.27.3/src/net/http/internal/http2/transport.go:43-50`, `:673-687`, `:82-91`, `config.go:50-65`, `http2.go:82`). Swift는 프로토콜 기본 수신 창으로 작은 요청부터 시작할 수 있다.

## 7. 상호 운용 시험에서 확인할 것

### 7.1 저장소의 Go 시험과 재사용할 수 있는 것

| 시험 | 내용 | Swift 시험에 재사용 | 출처 |
| --- | --- | --- | --- |
| `TestHandshake` | 양쪽 handshake hash·버전·상대 키 일치 | 같은 검사를 Swift 클라이언트·Swift 서버 쌍(시험용)으로 | `controlbase/handshake_test.go:18-56` |
| `TestNoReuse` | 같은 장기 키로 반복해도 와이어 바이트와 hash가 매번 다름 | 그대로 옮길 수 있음 | `handshake_test.go:60` 이후 |
| `TestTampering` | initiation 101바이트·response 51바이트 전체와 첫 서버 레코드의 앞 30바이트를 변조해 실패 확인. 그 레코드는 평문 14 + 태그 16 + 헤더 3 = 실제 33바이트 | Swift에서는 레코드의 마지막 태그 3바이트까지 포함해 전체 33바이트를 변조 | `handshake_test.go:163-240`, `conn.go:169-171` |
| `TestMessageSize` | 암호문 최대가 65535 이하 | 상수 검사 | `controlbase/conn_test.go:28-39` |
| `TestBigData` | 큰 데이터 전송 뒤 양방향 nonce 동기(클라이언트 4, 서버 8) | nonce 진행 검사 | `conn_test.go:117-160` |
| `TestDataTrickle`, `TestConnStd` | 조금씩 도착하는 데이터, net.Conn 규약 | 부분 읽기 처리 검사 | `conn_test.go:175`, `:192` |
| `FuzzWholeMessageLocked`, `FuzzDecryptLocked` | 레코드 파서 퍼징. 0 키 AEAD로 만든 시드 프레임 | 시드 구성 방식(`sealFrame`) 참고 | `controlbase/fuzz_test.go:19`, `:49-72` |
| `TestInteropClient`/`Server` | Noise Explorer 참조 구현과 핸드셰이크 + 전송 메시지 1개씩 | 핸드셰이크 검증에만 유효. nonce 엔디언은 검증 못함(3.5) | `controlbase/interop_test.go:19-112`, `noiseexplorer_test.go` |
| `TestControlHTTP` | 업그레이드, 프록시 종류별, early write | 업그레이드 요청 형식 확인 | `controlhttp/http_test.go:56-140` |
| `TestDialPlan` | DialPlan 경쟁 | 미룸 | `http_test.go:574` |
| `TestNoiseClientHTTP2Upgrade(_earlyPayload)` | Noise 위 HTTP/2 요청, early payload 유무 | early payload를 보내는 시험 서버(`Upgrader`)의 동작을 기준으로 삼음 | `ts2021/client_test.go:55-63`, `:387-459` |
| `TestNoiseClientMaxResponseBodySize` | 응답 본문 상한 | 상한 구현 시 | `ts2021/client_test.go:65-71` |
| `TestMachineSerialization` 등 | `privkey:`/`mkey:`/`nodekey:`/`discokey:` JSON 직렬화 벡터 | 키 텍스트 형식 시험 벡터로 그대로 사용 | `types/key/machine_test.go:41-79`, `node_test.go:58-60`, `disco_test.go:41-42` |

원본 Go 시험에는 고정 키·고정 임시 키 핸드셰이크 벡터가 없다(`handshake_test.go:21-22`). 별도로 생성·대조한 재사용 벡터는 7.3에 적었다.

### 7.2 testcontrol을 상대로 확인할 것

시험 상대 준비: `cmd/testcontrol`은 `--addr`(기본 `127.0.0.1:9911`)에 평문 HTTP로 뜨고 같은 IP에 DERP·STUN도 띄운다(`cmd/testcontrol/testcontrol.go:24-58`). 통합 시험 환경도 `httptest.NewUnstartedServer` + `Start()`로 평문 HTTP다(`tstest/integration/integration.go:579`, `:596`). 필요한 경로는 `/key`, `/ts2021`, 그리고 Noise 위에서 부를 `/generate_204` 또는 `/key`다(`testcontrol.go:411-423`).

1. `/key?v=148`이 JSON을 주고 `publicKey`가 `mkey:` + 64 hex인지. `v`가 없거나 비어 있으면 text/plain hex인지(`testcontrol.go:525-537`).
2. 업그레이드 응답이 101과 `Upgrade: tailscale-control-protocol`인지, response 51바이트가 바로 뒤따르는지.
3. 틀린 서버 키로 핸드셰이크하면 서버가 machine 키 복호화에 실패하고 101 뒤 EOF가 오는지(4.4의 3-6).
4. initiation을 100바이트로 줄여 보내면 101 뒤 EOF인지(서버 쪽 "wrong handshake initiation size", `handshake.go:233-236`).
5. HTTP/2 요청 하나가 성공하는지. HTTP/2 교환은 양방향 레코드가 여러 개 필요하므로 nonce 빅 엔디언 구현이 여기서 검증된다.
6. `X-Tailscale-Handshake` 누락·잘못된 base64·`Upgrade` 누락에 400이 오는지(`controlhttpserver.go:48-70`).
7. 4077바이트를 넘는 요청 본문이 여러 레코드로 나뉘어 받아지는지.
8. early payload 처리: testcontrol은 보내지 않으므로, `ts2021/client_test.go`의 `Upgrader`처럼 매직·길이·JSON을 따로 쓰는 서버로 따로 확인한다.
9. 6.3의 HTTP/2 처리(허프만, 동적 테이블, 창 크기, PING, GOAWAY)를 Swift 구현에서도 프레임 기록으로 대조한다. Go의 기본값을 고정 가정하지 않고 수신 SETTINGS를 적용하는지 확인한다(`golang.org/x/net@v0.60.0/http2/server.go:780-801`, `:1654-1695`).

### 7.3 고정 입력 시험 벡터와 실행 결과

2026-11-14, Go 1.27.3에서 v1.104.6의 수정하지 않은 `controlbase.ClientDeferred`·`Server`·`Conn.Write`를 실행했다. **아래 키는 전부 공개된 시험 전용 고정 값이며 실제 연결에 재사용하지 않는다.** version=148, nonce는 핸드셰이크마다 0¹², 전송은 방향별 0부터다. 4.5를 별도 코드로 계산하되 HKDF는 직접 HMAC 두 블록으로 전개하고, X25519는 `crypto/ecdh`, BLAKE2s·ChaCha20-Poly1305만 primitive로 사용했다. 그 결과 initiation·response·양쪽 handshake hash와 양방향 레코드 0·1·2가 바이트 단위로 일치했다(절차 근거: `controlbase/handshake.go:67-95`, `:159-188`, `:264-324`, `:344-437`, `controlbase/conn.go:162-172`, `:391-395`). 의존 모듈은 `golang.org/x/crypto` v0.58.0·`golang.org/x/net` v0.60.0이며, 별도로 `controlbase`·`types/key`·`controlhttp`·`ts2021`의 Go 시험도 모두 통과했다.

입력은 raw 32바이트 hex다. 원래 연속 바이트열 00..1f·20..3f·40..5f·60..7f에 4.5의 clamp를 적용한 개인 키와 그 공개 키를 함께 적는다(`types/key/util.go:51-54`, `machine.go:61-67`).

| 키 | 개인 키 (hex) | 공개 키 (hex) |
| --- | --- | --- |
| 클라이언트 machine | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e5f` | `8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f` |
| 서버 정적 | `202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e7f` | `358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254` |
| 클라이언트 임시 | `404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f` | `79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a` |
| 서버 임시 | `606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f` | `675dd574ed7789310b3d2e7681f3790b466c773b1521fecf36577958371ea52f` |

중간값은 모두 32바이트 hex다. AAD는 바로 앞의 hash를 사용한다. es·ss·se 키는 각각 machine 공개 키·initiation 빈 payload·response 빈 payload의 AEAD 키이며, ee 키는 버린다(`handshake.go:85-95`, `:161-168`, `:376-413`).

| 단계 | hash / ck / AEAD key (hex) |
| --- | --- |
| 초기 h=ck | `bbea022b948cf3bc5857d70804229179e1116bc40cb8cc074835349c464bca36` |
| 프롤로그 뒤 h | `fec1c32c3bfa98e7b8fe17ed6a11ca98010faf537dfe04facd365dcc7278c6e3` |
| 서버 정적 공개 키 뒤 h | `4ff25d533e57e80cde501455476df3c74d6105a0404fd2367b2fe2bb4bba0ac1` |
| 클라이언트 임시 공개 키 뒤 h = 첫 AEAD AAD | `8f4d3fee07c8dca8b9193141d281d1a219a6020d14f310b55b11664105de1e99` |
| es 뒤 ck | `638c46b2fa99a1d28c6eb68e133c5d220eaf490852adf740ac083beb644259fa` |
| es 키 | `61d19a096c56c8c57f13d65d3d35f392b87fecc40b9be69c2431d14021761348` |
| machine 암호문 뒤 h = initiation 태그 AAD | `a46b7bce53ea6f082652cfbe415cbc3d09124ac9a1c5917c42c8a028b4df851c` |
| ss 뒤 ck | `859ff0aa416be42ccff019b9b0a8c90127042d9022f1b7653360236214fabc5c` |
| ss 키 | `27d4bfb4f102b7b35e13f29013edb4f8297fd35051466874ee42f211a7a26251` |
| initiation 태그 뒤 h | `771e5e7a343ed7076b5956fa19a2ec6ac6179f4457291c0cf14cebf949988998` |
| 서버 임시 공개 키 뒤 h = response 태그 AAD | `0a4c2fc98dedfaed302eb21c6766a44475caeb9875fc68b16f77687547edf9d2` |
| ee 뒤 ck | `4d7a28f286cc2ba50b46631421d591b895a65b320c6ecc06ae9257c3892ee374` |
| se 뒤 ck | `6cbc50260668a0a00ce3581cf60c6b0917f53b1237ec69031af3e2564ece36b4` |
| se 키 | `3924ede1bd3140a5e6600880c30b3a717c8b726a300233b30e9684aadcf40ca9` |
| 최종 handshake hash | `e1450d6bb0ab8e06a5cda35ff6c7ec232f7f2f6be0cc5f93433c43dc11abc66f` |
| Split k_a: 클라이언트 → 서버 | `b5a6c358cd51a1fc717517315852e009148ee5480cf70a3caf4d4f9498c9ca8e` |
| Split k_b: 서버 → 클라이언트 | `d8ebca0df9236e3c51fcc4e5d506d473b019dd191d7ac7112d1e046898a1e78d` |

전체 와이어 메시지는 헤더와 태그를 포함한 hex다. initiation은 101바이트, response는 51바이트다(`messages.go:39-45`, `:71-76`).

initiation:

```text
009401006079a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51aad5b8febedeb97415be53612205e6bfab385e34cb127dd8854c4f9afb10f9b0e635d32b6eacf64ca7ce3a83fdf2f525f62cda6ef940fef0c11064f09a292d01e
```

response:

```text
020030675dd574ed7789310b3d2e7681f3790b466c773b1521fecf36577958371ea52fe938fd4935979fcc3489231f7ef4c9c7
```

레코드 평문은 표의 UTF-8 문자열이며 줄바꿈·NUL은 없다. 모든 레코드는 AAD 없음, nonce=`00000000 ‖ uint64BE(counter)`다. 표의 hex에는 `04`와 uint16 BE 길이를 포함했다(`conn.go:169-172`, `:395`).

| 방향 | counter | 평문 | 전체 레코드 hex |
| --- | --- | --- | --- |
| 클라이언트 → 서버 | 0 | `client-0` | `0400184d8db142648da2b8ceb16a43dbdb67e57ba92f2c667e173e` |
| 서버 → 클라이언트 | 0 | `server-0` | `040018775de2b464bfc78e7ed71c2598a5bf25f9c23ad37efcd53e` |
| 클라이언트 → 서버 | 1 | `client-1` | `040018848768a068cbdd2364ed56d8293a3f5264a340bdf735bb5a` |
| 서버 → 클라이언트 | 1 | `server-1` | `040018a0b7204f4127b4280c93761eceed2305f8f1ec9fa93d8760` |
| 클라이언트 → 서버 | 2 | `client-2` | `0400186f62b5bf6af70eaae2e7bd9d858d139300bdedcb660f97df` |
| 서버 → 클라이언트 | 2 | `server-2` | `0400180096fa0ae79135bea550c3d6d6a63c427e2b5eb1980579f4` |
| 클라이언트 → 서버 | 3 | 빈 평문 | `04001002e188736cdfc5af317a26b1fed85ca0` |
| 클라이언트 → 서버 | 4 | `after-empty` | `04001b8a5c4fe32e73ff64383e91d49bec27571d8e198737eae631cbd94a` |

counter 3의 빈 레코드와 counter 4의 레코드는 primitive 계산으로 만든 뒤 Go 서버에 직접 주입해, 첫 레코드를 인증·건너뛰고 `after-empty`를 반환하는 것을 확인했다. 서버 → 클라이언트 counter 3 레코드의 태그 1바이트를 변조하면 첫 Read는 인증 오류, 다음 Read는 `net.ErrClosed`였다(`conn.go:146-155`, `:246-257`). 실행 출력: `PASS: 독립 primitive 계산 = controlbase initiation/response/hash/양방향 nonce 0·1·2; 빈 레코드 건너뛰기; 인증 실패 뒤 net.ErrClosed`.

같은 날 testcontrol을 `httptest.NewServer`로 실행해 7.2의 `/key` 두 형식, 101 뒤 Noise + HTTP/2 `GET /key?v=148`(200, JSON DATA 176바이트), `Content-Length: 0` 유무를 확인했다. `Host` 누락·잘못된 base64는 400, 100바이트 initiation·틀린 서버 키는 101 뒤 `reading response header: EOF`였다. 초기 SETTINGS와 WINDOW_UPDATE는 6.3의 값과 일치했다(상대 코드: `testcontrol.go:476-537`, `controlhttpserver.go:48-119`, `Go 1.27.3/src/net/http/internal/http2/server.go:769-793`). 원래 `controlhttp`·`ts2021` 시험의 early payload 유무·업그레이드·프록시 사례도 통과했다. 이 실행은 Swift 구현이나 운영 서버의 시험은 아니다.

## 8. 확인하지 못한 것

- 운영 제어 서버(비공개)와 headscale의 실제 동작: early payload 송신, HTTP/2 설정, 유휴 연결 정책, `/ts2021`에 GET 허용 여부. 이 검증은 Go v1.104.6 소스와 로컬 testcontrol·Go 시험까지다.
- `/key` 실패 뒤 상위 재시도·백오프. `loadServerPubKeys` 내부에 재시도가 없다는 것만 대조했다(`controlclient/direct.go:1535-1569`).
- HTTP 프록시·SOCKS5·ACE·JS WebSocket은 4.3·4.4의 소스와 기존 Go 시험을 대조했으나 별도 실제 네트워크 환경에서 실행하지 않았다. TLS 포트 경쟁·인증서 실패 경로도 별도 실행하지 않았다.
- HTTP/2의 전체 RFC 9113·HPACK RFC 7541 적합성 시험, 악의적 입력 전 범위, 긴 map 스트림과 실제 PING·GOAWAY·유휴 타이머 발동의 실측은 하지 않았다. 6.3의 해당 동작은 의존 모듈 소스 대조 결과다.
- Noise 명세 원문과 원시 암호의 RFC 전체는 대조하지 않았다. nonce 차이는 `controlbase/conn.go:395`와 `noiseexplorer_test.go:164`의 비교이며, 고정 입력에서의 실제 상호 운용은 7.3으로 확인했다.
