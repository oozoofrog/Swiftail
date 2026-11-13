# 제어 전송 계층 (ts2021: controlhttp · controlbase · HTTP/2)

## 1. 머리말

| 항목 | 값 |
| --- | --- |
| 기준 소스 | `tailscale.com` v1.104.6 (CapabilityVersion 148, `tailscale.com/tailcfg/tailcfg.go:200`) |
| 작성 모델 | Claude Opus 5.5 |
| 검증 상태 | 미검증 (다른 제공자 모델의 Go 소스 대조 전) |

출처는 모듈 루트 기준 `tailscale.com/<경로>:<줄>`이다. 저장소 밖(Go 표준 라이브러리, `golang.org/x/net`, `golang.org/x/crypto`, RFC)에 기대는 문장은 "저장소 밖"이라고 표시하고 8장에 다시 적는다.

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

모든 정수는 빅 엔디언이다.

### 3.1 Noise 핸드셰이크 initiation (클라이언트 → 서버, 101바이트)

| 오프셋 | 길이 | 필드 | 인코딩 | 출처 |
| --- | --- | --- | --- | --- |
| 0 | 2 | protocol version (= capability version, 7장) | uint16 BE | `tailscale.com/control/controlbase/messages.go:32`, `:43` |
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
- 받는 쪽은 `3 + n > 4096`이면 `errReadTooBig`로 영구 실패한다(`conn.go:97-99`, `:375-382`). 길이 필드는 16비트라 더 큰 값을 적을 수 있지만 상대가 거부한다.
- 평문 0바이트 레코드가 허용되며 받는 쪽은 건너뛰고 다음 레코드를 읽는다(`conn.go:249-257`).
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
| 본문 | 없음 | `client.go:539-547` |

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
- L > 10 MiB(`10<<20`)면 오류(`conn.go:144-147`).
- 매직이 아니면 읽은 9바이트를 되돌려 HTTP/2 입력으로 그대로 쓴다(`conn.go:137-141`).
- JSON 형식: `{"nodeKeyChallenge":"chalpub:<64 hex>"}` (`tailcfg/tailcfg.go:3087-3091`, `types/key/chal.go:19`, `:76-77`).
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

1. `GET <serverURL>/key?v=<CurrentCapabilityVersion>`을 보낸다. 제어 서버 URL 그대로(scheme 포함)에 붙인다(`tailscale.com/control/controlclient/direct.go:1535-1537`, `control/tsp/tsp.go:112`). 이 요청은 Noise가 아닌 일반 HTTP(S)다.
2. 응답 본문은 64 KiB(`64<<10`)까지만 읽는다(`direct.go:1546`).
3. 상태가 200이 아니면 실패(`direct.go:1551-1553`).
4. 본문을 3.8의 JSON으로 해석한다. 실패하면 옛 형식(접두사 없는 64자 hex 하나 = legacy 키)으로 다시 해석하고, 그것도 실패하면 두 오류를 합쳐 실패한다(`direct.go:1554-1568`, `types/key/machine.go:196-202`).
5. `publicKey`가 0이면 "control server is too old; no noise key"로 중단한다(`direct.go:700-702`).
6. 캐시: 결과를 `serverLegacyKey`·`serverNoiseKey`에 저장하고, 로그인 시 `serverLegacyKey`가 0일 때만 다시 가져온다(`direct.go:641-642`, `:675-692`). 가져온 뒤 TLS 유휴 연결을 닫는다(`direct.go:694-697`). `loadServerPubKeys` 자체에는 재시도가 없다(`direct.go:1535-1569`).
7. testcontrol은 `v`가 없으면 `text/plain`으로 legacy 키의 접두사 없는 hex만 주고, 있으면 JSON을 준다(`tstest/integration/testcontrol/testcontrol.go:525-537`). 따라서 `v`를 반드시 붙인다.

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
   4. 처음 성공한 연결을 반환한다. 둘 다 실패해야 실패한다(`:315-337`). 나머지 시도는 문맥 취소로 닫힌다(`:240-244`, `:281-284`).
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
5. 웹소켓(요약): JS 빌드 전용 경로. `wss://host/ts2021?X-Tailscale-Handshake=<base64>`, 하위 프로토콜 `tailscale-control-protocol`, 바이너리 메시지 위에 같은 Noise 바이트 스트림을 싣는다(`controlhttp/client_js.go:31-57`, `controlhttpserver.go:126-171`).

### 4.5 controlbase 핸드셰이크 (클라이언트 = initiator)

표기: `h`, `ck`는 32바이트. `BLAKE2s`는 BLAKE2s-256, 키 없음(`handshake.go:440-450`). `HKDF(ck, ikm)`는 BLAKE2s 기반 HKDF로 salt = `ck`, 입력 키 재료 = `ikm`, info 없음이며 출력 앞 32바이트와 다음 32바이트를 쓴다(`handshake.go:376-383`, `:422-428`; HKDF 자체 정의는 `golang.org/x/crypto/hkdf`, 저장소 밖). `MixHash(x)`: `h = BLAKE2s(h ‖ x)`(`handshake.go:350-358`). `MixDH(priv, pub)`: `dh = X25519(priv, pub)`, `(ck, k) = HKDF(ck, dh)`, k는 한 번만 쓰는 ChaCha20-Poly1305 키(`handshake.go:360-385`). `EncryptAndHash(k, pt)`: `c = Seal(k, nonce=0¹², ad=h, pt)`, `MixHash(c)`(`handshake.go:387-397`). `DecryptAndHash(k, c)`: `Open(k, nonce=0¹², ad=h, c)`가 성공하면 `MixHash(c)`(`handshake.go:399-413`).

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

X25519가 오류를 내면(어떤 입력에서 내는지는 `x/crypto` 내부, 저장소 밖) 해당 단계 이름으로 실패한다(`handshake.go:369-374`). 서버는 버전 값으로 핸드셰이크를 막지 않고 프롤로그에만 섞는다(`handshake.go:241-246`, `:262`). 서버 쪽 initiation 검증 실패 문구: 크기 오류 "wrong handshake initiation size", 종류 오류 "unexpected handshake message type", 길이 오류 "wrong handshake initiation length"(`handshake.go:233-252`).

### 4.6 전송 단계 상태

1. 읽기: 3바이트 헤더 → 길이만큼 읽기 → 종류가 `0x04`가 아니면 오류 → nonce 검사 → 복호화 → nonce 증가(`conn.go:131-157`, `:196-239`).
2. 복호화가 한 번이라도 실패하면 수신 키를 버리고 이후 읽기는 모두 `net.ErrClosed`(`conn.go:149-155`, `:246-248`).
3. 쓰기 오류(부분 쓰기, 마감 시간 초과 포함)가 한 번이라도 나면 이후 쓰기는 모두 실패한다(`conn.go:37-40`, `:274-293`, `:311-317`).
4. 종료: 별도 종료 메시지가 없다(종류는 1~4뿐, `messages.go:8-21`). 밑단 소켓을 닫고 키를 지운다(`conn.go:323-338`).

### 4.7 ts2021 위의 HTTP/2 사용 (저장소에서 확인되는 부분)

1. 클라이언트는 Go `net/http` Transport를 "암호화 없는 HTTP/2 전용"으로 설정하고 dial 훅에서 Noise 연결을 돌려준다(`ts2021/client.go:166-178`). 이 HTTP/2 구현은 Go 표준 라이브러리 것이다(저장소 밖).
2. 호스트당 연결 1개(`MaxConnsPerHost: 1`, `client.go:168`). 모든 요청이 한 HTTP/2 연결에서 다중화된다. 연결 풀은 보통 0~1개, 네트워크 장애 후 재연결 중 잠시 2개(`client.go:284-286`).
3. 요청 URL은 `"https://" + host + path`다(`client.go:304`). 즉 `:scheme`은 `https`, `:authority`는 제어 서버 호스트명이 된다(의사 헤더 매핑은 저장소 밖 동작).
4. 본문이 있는 요청은 JSON, `Content-Type: application/json`, node 키가 0이 아니면 `Ts-Lb: nodekey:<hex>` 헤더(`client.go:299-318`, `tailcfg.go:3093-3109`).
5. 응답 본문은 기본 1 MiB(`httpbody.DefaultMaxSize = 1 << 20`)에서 잘라 오류로 처리한다(`client.go:320-336`, `util/httpbody/httpbody.go:30-34`). map 스트림은 상한을 끈다(`controlclient/direct.go:1150-1157`). map 응답 본문은 크기 접두사가 붙은 메시지들의 끝없는 스트림이다(`direct.go:1150-1154`, 상세는 `control-map.md`).
6. 연결이 끊기면 Transport가 다음 요청 때 다시 dial하고, dial마다 새 Noise 핸드셰이크를 한다(`client.go:174-176`, `controlhttp/client.go:346-363`). 클라이언트를 닫으면 살아 있는 Noise 연결을 모두 닫는다(`ts2021/client.go:182-197`, `controlclient/direct.go:422-436`).
7. 서버(testcontrol, ts2021 시험)는 Noise 연결 위에서 `golang.org/x/net/http2`의 `Server.ServeConn`을 기본 설정으로 돌린다(`testcontrol.go:497-505`, `ts2021/client_test.go:456-458`). 버전은 `golang.org/x/net v0.60.0`(`go.mod:143`).
8. early payload를 받으려면 HTTP/2 입력을 읽기 전에 3.7의 9바이트 검사를 먼저 해야 한다(`ts2021/conn.go:103-106`, `:122-157`). Go 클라이언트는 이 검사를 첫 Read 때 지연 실행하므로 early payload를 기다리지 않고 바로 HTTP/2 프리페이스를 보낼 수 있다(`conn.go:103-106`).

## 5. 상수와 타이머

| 이름 | 값 | 출처 |
| --- | --- | --- |
| `protocolName` | `Noise_IK_25519_ChaChaPoly_BLAKE2s` | `controlbase/handshake.go:31` |
| `protocolVersionPrefix` | `Tailscale Control Protocol v` | `handshake.go:42` |
| 프로토콜 버전 | `CurrentCapabilityVersion` = 148 | `ts2021/client.go:253`, `tailcfg.go:200` |
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
- 접두사 없는 hex 파서는 `/key` 옛 형식에만 쓴다(`machine.go:196-202`, `node.go:203`).
- 짧은 표시(`ShortString`): `[` + 표준 base64의 앞 5자 + `]`, 0 키는 빈 문자열(`util.go:103-120`). 로그용이며 와이어 형식이 아니다.
- machine·node·disco 개인 키는 생성 시 clamp한다(`machine.go:45`, `node.go:61`, `disco.go:41`). challenge 키는 node 키와 같은 방식으로 만든다(`chal.go:32-34`).
- base64가 와이어에 쓰이는 곳은 이 노트 범위에서 `X-Tailscale-Handshake`뿐이다(`controlhttp/client.go:545`).

## 6. Swiftail에 필요한 최소 부분과 생략할 수 있는 부분

M2 관문(전송 부분): "Swift 클라이언트가 testcontrol과 Noise 핸드셰이크를 마치고 HTTP/2 요청 하나를 주고받는다."

### 6.1 꼭 구현할 것

1. `/key?v=148` 평문 HTTP/1.1 GET과 JSON의 `publicKey`(`mkey:` hex) 해석. testcontrol은 평문 HTTP로만 뜬다(`cmd/testcontrol/testcontrol.go:25`, `:40-43`, `:54-57`).
2. 평문 TCP 위 HTTP/1.1 업그레이드 요청 작성, 101 응답 검증(상태, `Upgrade` 값), 헤더 뒤 남은 바이트 인계(3.6, 4.4).
3. 4.5의 클라이언트 핸드셰이크 전체. 필요한 원시 연산: X25519, BLAKE2s-256, HMAC-BLAKE2s 기반 HKDF, ChaCha20-Poly1305.
4. 3.4·3.5의 레코드 계층: 빅 엔디언 nonce, 쓰기 4077바이트 분할, 읽기 4096 상한, 0바이트 레코드 건너뛰기, 복호화 실패 시 연결 폐기.
5. 3.7 early payload 검사. testcontrol은 보내지 않지만(`testcontrol.go:490`에서 earlyWrite가 nil), 클라이언트가 버전 49 이상을 알리면 서버가 보낼 수 있다(`tailcfg.go:100`). 매직을 못 걸러내면 HTTP/2 파싱이 깨지므로 처음부터 넣는다. JSON 내용은 M2에서 버려도 된다(4.7과 3.7의 사용처 참고).
6. 4.7에 맞는 HTTP/2 클라이언트 최소 기능: 연결 1개, 요청 스트림 1개 이상, `:scheme https`, `:authority` = 호스트. 프레임·HPACK 세부는 6.3의 미확인 항목을 시험으로 확정한다.
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
| 응답 크기 상한 | 방어용. 운영 서버 상대 전에는 넣는다(`ts2021/client.go:320-336`) |
| 연결 재사용·재연결 정책 | M2는 연결 1개 요청 1개다. 이후 4.7의 2·6단계를 따른다 |
| error 메시지(종류 3) 송신 | 서버만 보낸다(`handshake.go:211-227`). 클라이언트는 수신 분기만 필요하다 |

### 6.3 HTTP/2 최소 요구 사항 정리

저장소에서 확인되는 것:

- 클라이언트가 먼저 HTTP/2를 시작하는 쪽이다. 서버는 Noise 핸드셰이크와 early payload 뒤 `ServeConn`을 시작한다(`controlhttpserver.go:100-121`, `testcontrol.go:490-505`).
- 서버의 첫 HTTP/2 바이트는 SETTINGS 프레임 헤더다(`ts2021/conn.go:81-84`의 설명).
- 한 연결에서 여러 요청을 다중화하며, map 스트림처럼 끝나지 않는 응답 본문이 다른 요청과 함께 흐른다(4.7의 2·5단계).
- 서버 구현은 `golang.org/x/net/http2` v0.60.0, 기본 설정(4.7의 7단계).

저장소 밖이라 확인하지 못한 것(RFC 9113·7541과 x/net 동작에 의존, 구현 전에 testcontrol 실측으로 확정):

- 클라이언트 연결 프리페이스 문자열과 첫 SETTINGS의 필수 여부·값, 서버 SETTINGS에 대한 ACK 의무.
- 서버가 응답 헤더를 허프만 인코딩하는지, 동적 테이블에 넣는지. 넣는다면 Swift 디코더는 허프만 디코딩과 동적 테이블을 모두 지원해야 한다. 안전한 쪽은 둘 다 구현하는 것이다.
- 초기 흐름 제어 창 크기, 서버가 보내는 WINDOW_UPDATE 시점, 클라이언트가 긴 map 스트림을 받으면서 WINDOW_UPDATE를 언제 보내야 하는지.
- x/net 서버의 PING 송신 여부, 유휴 시간 초과, GOAWAY를 보내는 조건.
- x/net 서버가 `:scheme`·`:authority`를 검증하는 방식.
- Go 표준 HTTP/2 클라이언트가 실제로 보내는 SETTINGS·WINDOW_UPDATE 값(그대로 흉내 낼지 판단용).

## 7. 상호 운용 시험에서 확인할 것

### 7.1 저장소의 Go 시험과 재사용할 수 있는 것

| 시험 | 내용 | Swift 시험에 재사용 | 출처 |
| --- | --- | --- | --- |
| `TestHandshake` | 양쪽 handshake hash·버전·상대 키 일치 | 같은 검사를 Swift 클라이언트·Swift 서버 쌍(시험용)으로 | `controlbase/handshake_test.go:18-56` |
| `TestNoReuse` | 같은 장기 키로 반복해도 와이어 바이트와 hash가 매번 다름 | 그대로 옮길 수 있음 | `handshake_test.go:60` 이후 |
| `TestTampering` | initiation 101바이트, response 51바이트, 첫 레코드 30바이트의 각 바이트 변조 시 실패 | 바이트 위치 범위를 그대로 사용 | `handshake_test.go:163-230` |
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

고정 키·고정 임시 키로 만든 핸드셰이크 바이트 벡터는 저장소에 없다(위 시험은 모두 `key.NewMachine()` 난수 키를 쓴다, 예: `handshake_test.go:21-22`).

### 7.2 testcontrol을 상대로 확인할 것

시험 상대 준비: `cmd/testcontrol`은 `--addr`(기본 `127.0.0.1:9911`)에 평문 HTTP로 뜨고 같은 IP에 DERP·STUN도 띄운다(`cmd/testcontrol/testcontrol.go:24-58`). 통합 시험 환경도 `httptest.NewUnstartedServer` + `Start()`로 평문 HTTP다(`tstest/integration/integration.go:579`, `:596`). 필요한 경로는 `/key`, `/ts2021`, 그리고 Noise 위에서 부를 `/generate_204` 또는 `/key`다(`testcontrol.go:411-423`).

1. `/key?v=148`이 JSON을 주고 `publicKey`가 `mkey:` + 64 hex인지. `v` 없이 부르면 text/plain hex인지.
2. 업그레이드 응답이 101과 `Upgrade: tailscale-control-protocol`인지, response 51바이트가 바로 뒤따르는지.
3. 틀린 서버 키로 핸드셰이크하면 서버가 machine 키 복호화에 실패하고 101 뒤 EOF가 오는지(4.4의 3-6).
4. initiation을 100바이트로 줄여 보내면 101 뒤 EOF인지(서버 쪽 "wrong handshake initiation size", `handshake.go:233-236`).
5. HTTP/2 요청 하나가 성공하는지. HTTP/2 교환은 양방향 레코드가 여러 개 필요하므로 nonce 빅 엔디언 구현이 여기서 검증된다.
6. `X-Tailscale-Handshake` 누락·잘못된 base64·`Upgrade` 누락에 400이 오는지(`controlhttpserver.go:48-70`).
7. 4077바이트를 넘는 요청 본문이 여러 레코드로 나뉘어 받아지는지.
8. early payload 처리: testcontrol은 보내지 않으므로, `ts2021/client_test.go`의 `Upgrader`처럼 매직·길이·JSON을 따로 쓰는 서버로 따로 확인한다.
9. 6.3의 HTTP/2 미확인 항목(허프만, 동적 테이블, 창 크기, PING, GOAWAY)을 프레임 기록으로 확정한다.

## 8. 확인하지 못한 것

- `golang.org/x/net/http2` 서버 내부 동작: 초기 SETTINGS 값, HPACK 허프만·동적 테이블 사용, 흐름 제어 창, PING·유휴 시간 초과·GOAWAY 조건, 의사 헤더 검증. 이 저장소에 소스가 없다.
- Go 표준 라이브러리 HTTP/2 클라이언트가 보내는 프리페이스 뒤 SETTINGS·WINDOW_UPDATE 값.
- 업그레이드 POST에 Go가 `Content-Length: 0`과 `Host`를 어떻게 넣는지(표준 라이브러리 동작). 서버가 이를 요구하는지도 미확인.
- HKDF·HMAC·X25519의 세부(RFC 5869·2104·7748 그대로인지, X25519가 어떤 입력에서 오류를 내는지)는 `golang.org/x/crypto` 쪽이라 이 저장소에서 확인하지 않았다. Noise Explorer 참조 구현과의 상호 운용 시험이 통과하는 것(`interop_test.go`)만 확인했다.
- 운영 제어 서버(비공개)와 headscale의 동작: early payload를 보내는지, HTTP/2 설정, 유휴 연결 정책, `/ts2021`에 GET을 받는지.
- `/key` 실패 뒤의 상위 재시도·백오프. `loadServerPubKeys`에는 재시도가 없고 호출자 쪽은 이 노트 범위에서 읽지 않았다.
- `/key` 요청의 TLS 인증서 검증 방식(`tlsdial.Config`, `direct.go:355`)의 세부.
- 고정 입력의 Noise 핸드셰이크 시험 벡터. 저장소에 없으므로 Swift 쪽 벡터는 Go 코드로 따로 생성해야 한다.
- Noise 명세 원문(nonce 엔디언, 프로토콜 이름 처리)은 저장소 밖이다. 이 노트의 "명세는 리틀 엔디언" 비교는 저장소 안의 `noiseexplorer_test.go:164` 구현으로만 확인했다.
