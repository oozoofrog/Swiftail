# WireGuard 데이터면

기준은 `github.com/tailscale/wireguard-go` v0.0.0-20261106233718-9e0ab45c16ca와 `tailscale.com` v1.104.6이다. 작성 모델은 Claude Opus 5.5이고, 검증 상태는 미검증이다.

출처 표기는 `wireguard-go/…`(위 포크의 모듈 루트)와 `tailscale.com/…`(모듈 루트)를 쓴다. 이 노트에서 "wireguard-go"는 별도 표시가 없으면 Tailscale 포크를 뜻한다.

## 범위

다루는 것:

- 메시지 4종의 바이트 배치
- Noise IKpsk2 핸드셰이크(초기자와 응답자)
- mac1·mac2·cookie와 부하 상태
- 전송 데이터의 nonce, 패딩, keepalive, 재전송 방지, AllowedIPs 검사
- 타이머와 keypair 교체 상태 기계
- Tailscale 포크의 확장 지점(`conn.Bind`·`conn.Endpoint`, 지연 피어 생성)과 Tailscale이 넘기는 설정
- 재사용할 수 있는 시험과 M1 관문에 필요한 최소 구현

다루지 않는 것:

- magicsock의 경로 선택, disco, DERP 전송(`disco-magicsock.md`, `derp-stun.md`)
- TUN·netstack 쪽 패킷 처리
- UAPI 텍스트 프로토콜 전체
- 성능용 배치·풀·GSO, 플랫폼별 sticky socket

## 와이어 형식

모든 메시지의 첫 4바이트는 type이다. 1바이트 type 뒤에 0 세 바이트가 오며, 수신 측은 이를 little-endian `uint32`로 읽는다(`wireguard-go/device/noise-protocol.go:81`, `wireguard-go/device/receive.go:142`). 따라서 예약 바이트가 0이 아니면 알 수 없는 type으로 버려진다(`wireguard-go/device/receive.go:209`). 정수 필드(type, sender, receiver, counter)는 모두 little-endian이다(`wireguard-go/device/noise-protocol.go:128`, `wireguard-go/device/noise-protocol.go:144`, `wireguard-go/device/send.go:588`).

| type 값 | 메시지 | 크기 |
| --- | --- | --- |
| 1 | `MessageInitiationType` | 148 (`MessageInitiationSize`) |
| 2 | `MessageResponseType` | 92 (`MessageResponseSize`) |
| 3 | `MessageCookieReplyType` | 64 (`MessageCookieReplySize`) |
| 4 | `MessageTransportType` | 32 이상(헤더 16 + 태그 16) |

출처: `wireguard-go/device/noise-protocol.go:58`, `wireguard-go/device/noise-protocol.go:65`, `wireguard-go/device/noise-protocol.go:70`.

### Handshake initiation (148바이트)

| 오프셋 | 길이 | 필드 | 내용 |
| --- | --- | --- | --- |
| 0 | 4 | Type | `1`, LE uint32 |
| 4 | 4 | Sender | 초기자가 고른 로컬 index, LE uint32 |
| 8 | 32 | Ephemeral | 초기자 임시 공개키 평문 |
| 40 | 48 | Static | 초기자 정적 공개키 32 + Poly1305 태그 16 |
| 88 | 28 | Timestamp | TAI64N 12 + 태그 16 |
| 116 | 16 | MAC1 | keyed BLAKE2s-128 |
| 132 | 16 | MAC2 | keyed BLAKE2s-128 또는 0 |

출처: `wireguard-go/device/noise-protocol.go:87`, `wireguard-go/device/noise-protocol.go:139`.

### Handshake response (92바이트)

| 오프셋 | 길이 | 필드 | 내용 |
| --- | --- | --- | --- |
| 0 | 4 | Type | `2` |
| 4 | 4 | Sender | 응답자 로컬 index |
| 8 | 4 | Receiver | initiation의 Sender 값 |
| 12 | 32 | Ephemeral | 응답자 임시 공개키 |
| 44 | 16 | Empty | 빈 평문의 AEAD 태그 |
| 60 | 16 | MAC1 | |
| 76 | 16 | MAC2 | |

출처: `wireguard-go/device/noise-protocol.go:97`, `wireguard-go/device/noise-protocol.go:171`.

### Cookie reply (64바이트)

| 오프셋 | 길이 | 필드 | 내용 |
| --- | --- | --- | --- |
| 0 | 4 | Type | `3` |
| 4 | 4 | Receiver | 거절된 메시지의 Sender 값(오프셋 4) |
| 8 | 24 | Nonce | 무작위 XChaCha20 nonce |
| 32 | 32 | Cookie | 암호화된 cookie 16 + 태그 16 |

출처: `wireguard-go/device/noise-protocol.go:114`, `wireguard-go/device/noise-protocol.go:200`, `wireguard-go/device/send.go:258`.

### Transport data

| 오프셋 | 길이 | 필드 | 내용 |
| --- | --- | --- | --- |
| 0 | 4 | Type | `4` |
| 4 | 4 | Receiver | 상대가 핸드셰이크에서 보낸 Sender index |
| 8 | 8 | Counter | LE uint64, nonce로도 쓰인다 |
| 16 | n+16 | Content | 패딩된 평문 n의 ChaCha20-Poly1305 암호문 + 태그 |

출처: `wireguard-go/device/noise-protocol.go:76`, `wireguard-go/device/send.go:588`.

- keepalive는 평문 길이가 0인 transport이며 총 32바이트다(`MessageKeepaliveSize`, `wireguard-go/device/noise-protocol.go:71`).
- `MessageEncapsulatingTransportSize` = 8은 `conn.Bind.Send`에 넘기는 버퍼 앞의 여유 공간이고, WireGuard 와이어 바이트에 포함되지 않는다(`wireguard-go/device/noise-protocol.go:69`, `wireguard-go/device/peer.go:226`).

## 절차와 상태 기계

### 기본 연산

- **HASH(x)**: BLAKE2s-256(`wireguard-go/device/noise-protocol.go:240`).
- **MAC(key, x)**: keyed BLAKE2s-128이다. HMAC이 아니라 BLAKE2s의 key 매개변수를 쓴다(`wireguard-go/device/cookie.go:79`).
- **HMAC(key, x)**: HMAC 구성이며, 해시는 BLAKE2s-256이다(`wireguard-go/device/noise-helpers.go:24`).
- **KDF1/2/3(key, input)** (`wireguard-go/device/noise-helpers.go:43`):
  1. prk = HMAC(key, input)
  2. T0 = HMAC(prk, 0x01)
  3. T1 = HMAC(prk, T0 ‖ 0x02)
  4. T2 = HMAC(prk, T1 ‖ 0x03)

  KDF1은 T0, KDF2는 (T0, T1), KDF3는 (T0, T1, T2)를 돌려준다. KDF1은 prk를 별도로 두지 않고 t0에 덮어쓰지만 결과는 같다(`wireguard-go/device/noise-helpers.go:44`).
- **mixHash(h, d)** = HASH(h ‖ d), **mixKey(ck, d)** = KDF1(ck, d)(`wireguard-go/device/noise-protocol.go:236`).
- **AEAD**: ChaCha20-Poly1305 IETF(키 32, nonce 12, 태그 16)다. 핸드셰이크 안의 모든 AEAD는 nonce 12바이트 0(`ZeroNonce`)과 AAD = 현재 hash를 쓴다(`wireguard-go/device/noise-protocol.go:233`, `wireguard-go/device/noise-protocol.go:312`).
- **DH(sk, pk)**: X25519다. 결과 32바이트가 모두 0이면 `errInvalidPublicKey`로 실패한다(`wireguard-go/device/noise-helpers.go:100`).
- **비밀키 clamp**: 비밀키는 생성할 때와 hex로 읽을 때 clamp한다. `sk[0] &= 248`, `sk[31] = (sk[31] & 127) | 64`(`wireguard-go/device/noise-helpers.go:80`, `wireguard-go/device/noise-types.go:48`).
- **index**: 암호학적 난수 uint32다. 사용 중인 값과 겹치면 다시 뽑는다(`wireguard-go/device/indextable.go:25`, `wireguard-go/device/indextable.go:58`).

### 초기 상수

- `NoiseConstruction` = `"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"`
- `WGIdentifier` = `"WireGuard v1 zx2c4 Jason@zx2c4.com"`
- `WGLabelMAC1` = `"mac1----"`
- `WGLabelCookie` = `"cookie--"`

출처: `wireguard-go/device/noise-protocol.go:51`.

- `InitialChainKey` = HASH(`NoiseConstruction`)
- `InitialHash` = HASH(`InitialChainKey` ‖ `WGIdentifier`)

출처: `wireguard-go/device/noise-protocol.go:267`.

### 초기자: initiation 만들기

S_i/S_r은 정적 키, E_i/E_r은 임시 키, ck는 chaining key, h는 hash다(`wireguard-go/device/noise-protocol.go:272`).

1. ck = InitialChainKey, h = InitialHash, E_i를 새로 만든다(`:282`).
2. h = mixHash(h, S_r.pub)(`:289`).
3. msg.Ephemeral = E_i.pub. ck = mixKey(ck, E_i.pub), h = mixHash(h, E_i.pub)(`:296`).
4. (ck, k) = KDF2(ck, DH(E_i, S_r.pub)). msg.Static = AEAD(k, 0, S_i.pub, AAD=h). h = mixHash(h, msg.Static)(`:300`–`:313`).
5. precomputed DH(S_i, S_r.pub)가 0이면 `errInvalidPublicKey`로 중단한다(`:316`). 이 값은 피어를 만들 때와 비밀키를 바꿀 때 미리 계산한다(`wireguard-go/device/peer.go:155`, `wireguard-go/device/device.go:440`).
6. (ck, k) = KDF2(ck, DH(S_i, S_r.pub)). msg.Timestamp = AEAD(k, 0, TAI64N.now, AAD=h)(`:319`–`:327`).
7. 새 index를 msg.Sender로 정한다. 이전 handshake index는 지운다(`:330`).
8. h = mixHash(h, msg.Timestamp). 상태는 `handshakeInitiationCreated`가 된다(`:337`).
9. 직렬화한 뒤 mac1·mac2를 붙인다(`wireguard-go/device/send.go:198`).

### 응답자: initiation 소비

출처는 `wireguard-go/device/noise-protocol.go:342`이다.

1. type이 1이 아니면 버린다(`:348`).
2. h = HASH(HASH(InitialHash ‖ S_r.pub) ‖ E_i.pub), ck = KDF1(InitialChainKey, E_i.pub)(`:360`).
3. (ck, k) = KDF2(ck, DH(S_r, E_i.pub)). msg.Static을 AEAD로 연다(AAD=h). 실패하면 버린다. h = mixHash(h, msg.Static)(`:367`–`:377`).
4. Endpoint가 `conn.InitiationAwareEndpoint`이면 복호한 공개키로 `InitiationMessagePublicKey`를 호출한다(`:381`).
5. `LookupPeer`로 피어를 찾는다. 없거나 실행 중이 아니면 버린다(`:386`). 지연 생성은 아래 Tailscale 절에서 다룬다.
6. precomputed static-static이 0이면 버린다. (ck, k) = KDF2(ck, DH(S_r, S_i.pub))로 Timestamp를 연다. 실패하면 버린다. h = mixHash(h, msg.Timestamp)(`:399`–`:415`).
7. **재전송 방지**: 복호한 timestamp가 피어별 `lastTimestamp`보다 바이트 비교로 엄격히 크지 않으면 replay로 버린다(`:419`).
8. **flood 방지**: 마지막 initiation 소비 후 `HandshakeInitationRate`(20ms) 이내이면 버린다(`:420`).
9. h, ck, remoteIndex = msg.Sender, remoteEphemeral를 저장한다. `lastTimestamp`와 `lastInitiationConsumption`을 갱신하고, 상태는 `handshakeInitiationConsumed`가 된다(`:435`–`:446`).

`lastTimestamp`는 `Handshake.Clear`에서 지워지지 않는다(`wireguard-go/device/noise-protocol.go:248`). 피어 객체가 사라질 때만 초기화된다. 따라서 초기자는 같은 정적 키로 재시작해도 벽시계가 앞으로 가야 한다.

### 응답자: response 만들기

출처는 `wireguard-go/device/noise-protocol.go:456`이다.

1. 상태가 `handshakeInitiationConsumed`가 아니면 오류다(`:461`).
2. 새 index를 Sender로, remoteIndex를 Receiver로 쓴다(`:468`).
3. E_r를 만든다. h = mixHash(h, E_r.pub), ck = mixKey(ck, E_r.pub)(`:481`).
4. ck = mixKey(ck, DH(E_r, E_i.pub)). 이어서 ck = mixKey(ck, DH(E_r, S_i.pub))(`:489`–`:498`).
5. (ck, τ, k) = KDF3(ck, PSK). h = mixHash(h, τ)(`:505`–`:513`). PSK를 쓰지 않으면 32바이트 0을 넣는다. 0이 "PSK 계층 꺼짐"을 뜻한다(`wireguard-go/device/peer.go:195`).
6. msg.Empty = AEAD(k, 0, 빈 평문, AAD=h), 즉 태그 16바이트다. h = mixHash(h, msg.Empty). 상태는 `handshakeResponseCreated`가 된다(`:515`–`:519`).

### 초기자: response 소비

출처는 `wireguard-go/device/noise-protocol.go:524`이다.

1. Receiver index로 index table을 찾는다. handshake 항목이 없으면 버린다. 그 index가 이미 keypair로 바뀌었으면 "duplicate"로 취급해 로그 없이 버린다(`:531`, `wireguard-go/device/receive.go:390`).
2. 상태가 `handshakeInitiationCreated`가 아니면 버린다(`:556`).
3. h = mixHash(h, E_r.pub), ck = mixKey(ck, E_r.pub)이다. 이어서 ck = mixKey(ck, DH(E_i, E_r.pub)), ck = mixKey(ck, DH(S_i, E_r.pub))이다(`:562`–`:576`).
4. (ck, τ, k) = KDF3(ck, PSK)이고 h = mixHash(h, τ)다. msg.Empty를 AEAD로 연다(AAD=h). 실패하면 버린다. h = mixHash(h, msg.Empty)(`:583`–`:599`).
5. 잠금을 다시 잡은 뒤 상태가 여전히 `handshakeInitiationCreated`이고 localIndex가 Receiver와 같을 때만 반영한다. 반영하면 상태는 `handshakeResponseConsumed`, remoteIndex = msg.Sender가 된다(`:614`).

### 전송 키 유도 (`BeginSymmetricSession`)

출처는 `wireguard-go/device/noise-protocol.go:635`이다.

- 초기자(`handshakeResponseConsumed`): (sendKey, recvKey) = KDF2(ck, 빈 입력)(`:647`).
- 응답자(`handshakeResponseCreated`): (recvKey, sendKey) = KDF2(ck, 빈 입력)(`:655`).
- 그 밖의 상태는 오류다(`:664`).
- ck, h, 임시 비밀키를 지우고 상태를 `handshakeZeroed`로 돌린다(`:669`).
- 새 keypair는 sendNonce 0, 빈 replay filter, `created` = now, `isInitiator`를 가진다. localIndex·remoteIndex는 handshake 값을 그대로 쓴다(`:683`–`:687`).
- index table의 handshake 항목은 같은 index의 keypair 항목으로 바뀐다(`:691`, `wireguard-go/device/indextable.go:44`). 즉 transport의 Receiver는 핸드셰이크 때 보낸 Sender index와 같다.

### keypair 교체(previous/current/next)

`BeginSymmetricSession`의 동작(`wireguard-go/device/noise-protocol.go:704`):

| 쪽 | next가 있을 때 | next가 없을 때 |
| --- | --- | --- |
| 초기자 | previous ← next, 옛 current 삭제, next ← nil | previous ← current |
| 초기자 공통 | 옛 previous 삭제, current ← 새 keypair | |
| 응답자 | next ← 새 keypair, 옛 next 삭제, previous ← nil(옛 previous 삭제), current는 유지 | |

- **응답자의 확인**: 응답자는 새 keypair로 처음 인증된 transport를 받을 때 확정한다. 이때 `ReceivedWithKeypair`가 previous ← current, current ← next, next ← nil로 바꾸고 옛 previous를 지운다(`wireguard-go/device/noise-protocol.go:724`, `wireguard-go/device/receive.go:480`).
- **응답자의 송신 대기**: 송신은 항상 `current`만 쓴다(`wireguard-go/device/send.go:488`). 그래서 응답자는 확인 전까지 새 keypair로 보내지 않는다.
- **세션이 처음인 응답자**: current가 없으므로 보낼 패킷이 생기면 initiation을 시도한다. 하지만 response를 보낼 때 `lastSentHandshake`가 갱신되어 `RekeyTimeout` 동안 막힌다(`wireguard-go/device/send.go:170`, `wireguard-go/device/send.go:220`). 패킷은 staged에 남았다가 확인 시점에 나간다(`wireguard-go/device/receive.go:484`).
- **초기자의 확인 유도**: 초기자는 response를 처리한 직후 keepalive를 보내 응답자가 확인하게 한다(`wireguard-go/device/receive.go:414`–`:417`).
- **keypair 삭제의 의미**: index table 항목만 지운다(`wireguard-go/device/keypair.go:48`). 지운 index로 오는 transport는 keypair를 찾지 못해 버려진다(`wireguard-go/device/receive.go:161`).

### mac1·mac2와 cookie

**키**(`wireguard-go/device/cookie.go:44`, `wireguard-go/device/cookie.go:173`):

- 수신 측(`CookieChecker`)은 자기 공개키 M으로 키를 만든다. mac1 키 = HASH(`"mac1----"` ‖ M), cookie 암호 키 = HASH(`"cookie--"` ‖ M)다. 비밀키를 바꿀 때 다시 초기화한다(`wireguard-go/device/device.go:433`).
- 송신 측(`CookieGenerator`)은 피어마다 상대 공개키로 같은 식의 키를 만든다(`wireguard-go/device/peer.go:137`).

**mac 붙이기**(`AddMacs`, `wireguard-go/device/cookie.go:215`):

1. mac1 = MAC(mac1키, msg[0 : len−32])(`:229`).
2. 그 mac1을 `lastMAC1`으로 기억한다(`:234`).
3. 받은 cookie가 없거나 받은 지 `CookieRefreshTime`(120초)을 넘었으면 mac2는 건드리지 않는다. 버퍼가 새로 할당되므로 0이 남는다(`:239`, `wireguard-go/device/send.go:196`).
4. 그렇지 않으면 mac2 = MAC(cookie 16바이트, msg[0 : len−16])(`:243`).

**검사**(`wireguard-go/device/receive.go:310`):

- initiation과 response는 항상 mac1을 상수 시간 비교로 검사하고, 틀리면 버린다(`:314`, `wireguard-go/device/cookie.go:69`).
- `IsUnderLoad()`일 때만 추가로 검사한다(`:321`).
  1. mac2를 검사한다. 틀리면 cookie reply를 보내고 원 메시지를 버린다(`:325`).
  2. mac2가 맞으면 송신 IP별 rate limiter를 통과해야 한다(`:332`).

**cookie 값과 비밀**(`wireguard-go/device/cookie.go:86`, `wireguard-go/device/cookie.go:117`):

- 수신 측 cookie = MAC(secret 32바이트, src)이다.
- src는 `Endpoint.DstToBytes()`다. 표준 bind에서는 `netip.AddrPort`의 binary 표현이다(`wireguard-go/conn/bind_std.go:113`).
- secret은 마지막 갱신 후 120초가 지나면 `CreateReply` 때 새 난수로 바뀐다(`:126`).
- secret이 120초보다 오래되면 `CheckMAC2`는 무조건 실패한다(`:90`).
- cookie는 송신 측이 그대로 되돌려주는 불투명 값이므로 src 인코딩은 상호 운용에 영향이 없다.

**cookie reply 만들기**(`wireguard-go/device/cookie.go:155`, `wireguard-go/device/send.go:255`):

- Receiver = 거절된 메시지 오프셋 4의 Sender, Nonce = 24바이트 난수다.
- Cookie = XChaCha20-Poly1305(키 = cookie 암호 키, nonce, 평문 = cookie 16바이트, AAD = 거절된 메시지의 mac1)다.
- 수신 Endpoint로 바로 보낸다.

**cookie reply 소비**(`wireguard-go/device/receive.go:280`, `wireguard-go/device/cookie.go:194`):

1. Receiver index로 피어를 찾는다. handshake 항목이든 keypair 항목이든 된다.
2. 피어가 아직 mac1을 보낸 적이 없으면(`hasLastMAC1`이 false) 실패한다.
3. `lastMAC1`을 AAD로 열어 cookie와 받은 시각을 저장한다.
4. 실패해도 로그만 남긴다. 저장한 cookie는 다음 `AddMacs`부터 mac2에 쓰인다. 같은 initiation을 즉시 다시 보내지는 않는다.

**부하 상태 판정**(`wireguard-go/device/device.go:385`):

- 핸드셰이크 큐 길이가 max(1, `queueHandshakeSize`/8) 이상이면 부하 상태다. 이때 `underLoadUntil` = now + `UnderLoadAfterTime`(1초)으로 기록한다.
- 그 밖에는 `underLoadUntil`이 아직 지나지 않았는지로 판정한다.
- 기본 큐 크기 1024에서 문턱은 128이다(`wireguard-go/device/queueconstants_default.go:16`).
- 큐가 가득 차면 핸드셰이크 패킷은 버려진다(`wireguard-go/device/receive.go:223`).

**rate limiter**(`wireguard-go/ratelimiter/ratelimiter.go:14`, `wireguard-go/ratelimiter/ratelimiter.go:99`):

- 키는 `Endpoint.DstIP()`다.
- 초당 20개, 버스트 5개다(`packetCost` = 1e9/20 ns, `maxTokens` = `packetCost`×5).
- 새 IP는 첫 패킷을 허용하고 토큰 `maxTokens−packetCost`로 시작한다.

### TAI64N

출처는 `wireguard-go/tai64n/tai64n.go:15`이다.

- 12바이트 = big-endian uint64(`0x400000000000000a` + Unix 초) ‖ big-endian uint32(나노초 & ^`0xFFFFFF`)다.
- 나노초 하위 24비트를 지워 해상도를 약 16.8ms로 낮춘다(`whitenerMask`).
- 비교는 12바이트 사전식 비교다(`wireguard-go/tai64n/tai64n.go:35`).
- 시험상 10ms 차이는 "after"가 아니고 20ms 차이는 "after"다(`wireguard-go/tai64n/tai64n_test.go:15`).

### 전송 데이터: 보내기

1. **nonce 배정**: 패킷마다 `sendNonce`를 원자적으로 1 늘리고 이전 값을 counter로 쓴다. 첫 counter는 0이다(`wireguard-go/device/send.go:501`).
2. **nonce 한도**: counter가 `RejectAfterMessages` 이상이면 nonce를 그 값에 고정하고 패킷을 다시 staged에 넣는다(`wireguard-go/device/send.go:502`).
3. **보낼 수 없는 경우**: 아래 중 하나면 staged 패킷을 두고 `SendHandshakeInitiation(false)`를 부른다(`wireguard-go/device/send.go:488`).
   - current keypair가 없다.
   - nonce가 소진됐다.
   - `created`로부터 `RejectAfterTime`(180초) 이상 지났다.
4. **staged 큐**: 기본 크기는 128이다(`DefaultQueueStagedSize` = `conn.IdealBatchSize`). 넘치면 가장 오래된 묶음부터 버린다(`wireguard-go/device/queueconstants_default.go:13`, `wireguard-go/conn/conn.go:19`, `wireguard-go/device/send.go:456`).
5. **헤더**: type 4, Receiver = keypair.remoteIndex, Counter = nonce를 LE로 쓴다(`wireguard-go/device/send.go:588`).
6. **패딩**: 0으로 채운다. `calculatePaddingSize(len, mtu)`의 규칙(`wireguard-go/device/send.go:552`, `wireguard-go/device/send.go:593`):
   - mtu == 0이면 16의 배수로 올림한다.
   - 아니면 len > mtu일 때 len %= mtu를 하고, 16의 배수로 올림하되 mtu를 넘지 않는다.
   - keepalive(0바이트)는 패딩이 0이다.
   - TUN이 MTU를 주지 못하면 `DefaultMTU` = 1420을 쓴다(`wireguard-go/device/tun.go:14`, `wireguard-go/device/device.go:468`).
7. **암호화**: AEAD nonce 12바이트 = 0x00000000 ‖ LE uint64(counter)이고, AAD는 없다(`wireguard-go/device/send.go:599`).
8. **크기 한도**: TUN에서 읽은 평문은 1 ≤ size ≤ `MaxContentSize`(= `MaxSegmentSize` − 32 − 8)여야 한다(`wireguard-go/device/send.go:380`, `wireguard-go/device/constants.go:32`).
9. **경로 선택**: IP 버전(첫 nibble 4/6)과 최소 헤더 길이를 확인한다. 목적지 주소로 AllowedIPs trie를 찾는다. `PeerByIPPacketFunc`가 있으면 그 결과의 공개키로 `LookupPeer`를 부른다(`wireguard-go/device/send.go:390`, `wireguard-go/device/allowedips.go:363`).
10. **keepalive**: staged 큐가 비어 있으면 빈 패킷 하나를 넣고 staged를 비운다. 비어 있지 않으면 대기 중인 패킷만 보낸다(`wireguard-go/device/send.go:85`).
11. **송신 후**: 묶음을 보낸 뒤 `keepKeyFreshSending`이 아래 중 하나면 initiation을 부른다(`wireguard-go/device/send.go:275`, `wireguard-go/device/send.go:699`).
    - `handshakeOnUserSend`가 켜져 있다.
    - nonce > `RekeyAfterMessages`다.
    - 초기자 keypair이고 나이 > `RekeyAfterTime`(120초)이다.

### 전송 데이터: 받기

출처는 `wireguard-go/device/receive.go`이다.

1. **크기와 type**: 데이터그램이 `MinMessageSize`(32)보다 작으면 type도 보지 않고 버린다(`:135`). 핸드셰이크 3종은 정확한 크기가 아니면 버리고, 알 수 없는 type도 버린다(`:194`–`:211`).
2. **keypair 찾기**: transport는 Receiver index로 keypair를 찾는다. 다음 경우 버린다(`:158`–`:171`).
   - 항목이 없거나 handshake 단계 index다.
   - keypair 나이가 `RejectAfterTime`(180초)을 넘었다.
3. **복호**: nonce = 0x00000000 ‖ LE counter, AAD는 없다. 복호에 실패하면 조용히 버린다(`:243`–`:259`, `:469`).
4. **재전송 방지**: 복호에 성공한 뒤 keypair별 replay filter로 counter를 검사한다(`:474`). 한도는 `RejectAfterMessages`다. 
   - 창은 64비트 블록 128개 링이고, 크기는 `windowSize` = (128−1)×64 = 8128이다(`wireguard-go/replay/replay.go:11`).
   - counter ≥ limit이면 거부한다.
   - `last`보다 크면 창을 앞으로 민다. 이때 건너뛴 블록을 비우며, 최대 링 전체다.
   - `last − counter` > 8128이면 거부한다.
   - 그 밖에는 비트가 이미 켜져 있으면 거부하고, 아니면 켜고 허용한다(`wireguard-go/replay/replay.go:37`).
5. **next 확정**: `ReceivedWithKeypair`로 next를 확정한다. 확정되면 핸드셰이크 완료 타이머, priority message, staged 송신이 이어진다(`:480`).
6. **피어 통지**: Endpoint가 `conn.PeerAwareEndpoint`이면 `FromPeer(피어 공개키)`를 부른다(`:486`).
7. **keepalive**: 평문 길이 0은 keepalive이고 TUN에 쓰지 않는다(`:491`).
8. **IP 검사**(`:497`–`:536`):
   - 첫 nibble이 4이면 길이 ≥ 20을 확인한다. total length(BE, 오프셋 2)가 [20, len] 안에 있어야 하며, 그 길이로 잘라 패딩을 뗀다.
   - 6이면 길이 ≥ 40을 확인한다. payload length(BE, 오프셋 4) + 40 ≤ len이어야 하며, 그 길이로 자른다.
   - 그 밖의 버전은 버린다.
9. **AllowedIPs**: **원천 주소**가 그 피어의 AllowedIPs 안에 있어야 한다(`:510`, `:528`). 포크는 `SetAllowedIPs`가 만든 피어 전용 판정 함수를 먼저 쓰고, 없으면 공용 trie에서 원천 주소의 주인이 그 피어인지 본다(`wireguard-go/device/allowedips.go:412`).
10. **타이머**: 묶음에 유효 패킷이 하나라도 있으면 `keepKeyFreshReceiving`, `timersAnyAuthenticatedPacketTraversal`, `timersAnyAuthenticatedPacketReceived`를 부른다. 데이터가 있으면 `timersDataReceived`도 부른다(`:543`). 
    - `keepKeyFreshReceiving`: current가 초기자 keypair이고 나이 > `RejectAfterTime − KeepaliveTimeout − RekeyTimeout`(165초)이면 initiation을 한 번 보낸다. `sentLastMinuteHandshake`가 중복을 막는다(`:63`).

### 엔드포인트 로밍

이 포크에서 피어의 endpoint 값을 바꾸는 곳은 세 군데뿐이다(`wireguard-go/device/peer.go:161`, `wireguard-go/device/device.go:571`, `wireguard-go/device/uapi.go:345`).

- `NewPeer`의 초기화(nil)
- 지연 생성 시 `NewPeerConfig.Endpoint`
- UAPI `endpoint=`

수신 경로에는 받은 패킷의 출발지로 endpoint를 갱신하는 코드가 없다(`wireguard-go/device/receive.go:479`–`:489`). 그 자리에서 `PeerAwareEndpoint.FromPeer`로 Bind에 알릴 뿐이다.

그래서 endpoint가 없는 피어에게 보내면 `"no known endpoint for peer"` 오류가 난다(`wireguard-go/device/peer.go:216`). 응답자가 response를 보낼 때도 마찬가지다. 로밍은 Bind(magicsock)의 책임이다.

`tests/netns.sh`는 endpoint 변경을 검사하지만(`wireguard-go/tests/netns.sh:196`), 이 포크 코드와 맞는지는 확인하지 못했다.

### 핸드셰이크 송신 규칙

`SendHandshakeInitiation`(`wireguard-go/device/send.go:164`):

- isRetry가 아니면 시도 횟수를 0으로 되돌린다.
- 마지막 핸드셰이크 메시지(initiation이든 response든) 송신 후 `RekeyTimeout`(5초)이 지나지 않았으면 아무것도 하지 않는다(`wireguard-go/device/send.go:170`).
- 보낸 뒤 `timersHandshakeInitiated`를 부른다.
- `Peer.Start`는 `lastSentHandshake`를 now − 6초로 두어 첫 시도를 막지 않는다(`wireguard-go/device/peer.go:294`).

응답자는 response를 만든 즉시 keypair를 유도해 next에 둔다. 이어 `timersSessionDerived`를 부르고 response를 보낸다(`wireguard-go/device/send.go:218`).

### 타이머

`Timer.Mod(d)`는 대기 중이든 아니든 d 뒤로 다시 건다. `Del`은 취소한다(`wireguard-go/device/timers.go:48`). 지터는 `fastrandn(334)`, 즉 0–333ms다(`wireguard-go/device/timers.go:159`). 타이머 동작은 피어 실행 중이고 장치가 up일 때만 한다(`wireguard-go/device/timers.go:75`).

| 타이머 | 거는 곳 | 푸는 곳 | 만료 동작 |
| --- | --- | --- | --- |
| retransmitHandshake | initiation 송신 후 `RekeyTimeout`+지터(`timers.go:189`) | 핸드셰이크 완료(`timers.go:197`) | 시도 횟수가 `MaxTimerHandshakes`(18)를 넘으면 포기한다: sendKeepalive 해제, staged 폐기, zeroKeyMaterial이 없으면 540초로 건다. 아니면 횟수+1, endpoint src 지움 표시, 재시도 initiation(`timers.go:79`). 결과적으로 initiation은 최대 20번이다(`timers.go:81`). |
| sendKeepalive | 데이터 수신 시 대기 중이 아니면 `KeepaliveTimeout`(10초). 대기 중이면 `needAnotherKeepalive` 표시(`timers.go:164`) | 인증된 패킷 송신 시(`timers.go:175`), 포기 시 | keepalive 송신. 표시가 있으면 지우고 10초로 다시 건다(`timers.go:110`). |
| newHandshake | 데이터 송신 후 대기 중이 아니면 `KeepaliveTimeout+RekeyTimeout`+지터(15초+)(`timers.go:157`) | 인증된 패킷 수신 시(`timers.go:182`) | endpoint src 지움 표시 후 새 initiation(`timers.go:120`) |
| sessionExpired | 세션 유도 시 `RejectAfterTime`(180초)(`timers.go:213`) | 피어 정지·키 삭제(`peer.go:321`) | 포크 전용. 세션 상태 콜백에 `PeerSessionExpired`를 알린다(`timers.go:140`). |
| zeroKeyMaterial | 세션 유도 시 `RejectAfterTime×3`(540초)(`timers.go:214`), 포기 시, 지연 생성 피어 시작 시(`peer.go:314`) | 다시 걸 때 갱신 | keypair·handshake 전부 삭제. 지연 생성 피어이면 장치에서 제거(`timers.go:127`). |
| persistentKeepalive | 인증된 패킷 송수신 시 간격이 0보다 크면 그 간격으로 건다(`timers.go:221`) | | 간격이 0보다 크면 keepalive(`timers.go:150`) |

"인증된 패킷"에는 핸드셰이크 메시지도 포함된다. initiation을 받은 응답자와 response를 받은 초기자는 traversal·received 타이머 함수를 부른다(`wireguard-go/device/receive.go:366`, `wireguard-go/device/receive.go:401`). initiation·response를 보낼 때는 traversal·sent 함수를 부른다(`wireguard-go/device/send.go:201`, `wireguard-go/device/send.go:243`).

`timersHandshakeComplete`(`wireguard-go/device/timers.go:197`)는 다음을 한다.

- retransmit 해제
- 시도 횟수와 `sentLastMinuteHandshake` 초기화
- `lastHandshakeNano` 기록

이 함수를 부르는 시점은 두 가지다.

- 초기자: response 소비 직후(`wireguard-go/device/receive.go:415`)
- 응답자: next 확정 시(`wireguard-go/device/receive.go:482`)

### 키 변경과 피어 정지

`SetPrivateKey`(`wireguard-go/device/device.go:399`):

- 키가 같으면 아무것도 하지 않는다.
- 새 공개키와 같은 공개키를 가진 피어를 제거한다.
- cookie checker를 다시 초기화한다.
- 모든 피어의 precomputed static-static을 다시 계산한다.
- `ExpireCurrentKeypairs`를 부른다. 이 함수는 handshake를 지우고 current·next의 sendNonce를 `RejectAfterMessages`로 만들어, 다음 송신 때 새 핸드셰이크가 일어나게 한다(`wireguard-go/device/peer.go:353`).

피어를 정지하면 타이머를 모두 동기 해제하고 keypair·handshake·staged를 지운다(`wireguard-go/device/peer.go:484`, `wireguard-go/device/peer.go:319`).

## Tailscale 포크와 Tailscale의 사용 방식

이 절은 포크 소스에 있는 것만 적는다. 원본 wireguard-go와의 차이로 단정하지 않는다.

### `conn.Bind`와 `conn.Endpoint`

**`Bind`**(`wireguard-go/conn/conn.go:46`):

| 메서드 | 동작 |
| --- | --- |
| `Open(port)` | `ReceiveFunc` 목록과 실제 포트를 돌려준다 |
| `Close` | 열린 수신 함수가 `net.ErrClosed`를 돌려주게 한다 |
| `SetMark` | 소켓 mark 설정 |
| `Send(bufs, ep, offset)` | `offset` 앞 공간은 Bind가 써도 된다 |
| `ParseEndpoint(s)` | 문자열에서 Endpoint를 만든다 |
| `BatchSize` | 한 번에 다루는 버퍼 수 |

- `ReceiveFunc`는 slab에 패킷을 쓰고 `ReceivedPacket{Offset, Size, Endpoint}`를 채운다(`wireguard-go/conn/conn.go:22`, `wireguard-go/conn/conn.go:40`).
- 장치는 수신 함수마다 루프를 하나씩 돌린다(`wireguard-go/device/device.go:947`).

**`Endpoint`**(`wireguard-go/conn/conn.go:92`):

| 메서드 | 장치 안에서의 쓰임 |
| --- | --- |
| `ClearSrc` | 재시도 시 송신 전에 부른다(`wireguard-go/device/peer.go:220`) |
| `SrcToString` | |
| `DstToString` | |
| `DstToBytes` | mac2 cookie의 src |
| `DstIP` | rate limiter 키 |
| `SrcIP` | |

**선택 인터페이스**(포크에 있음):

- `InitiationAwareEndpoint.InitiationMessagePublicKey([32]byte)`: initiation의 정적 키를 복호한 직후, 피어 조회 전에 부른다(`wireguard-go/conn/conn.go:109`, `wireguard-go/device/noise-protocol.go:381`).
- `PeerAwareEndpoint.FromPeer([32]byte)`: transport를 복호하고 replay 검사를 통과한 뒤 부른다(`wireguard-go/conn/conn.go:127`, `wireguard-go/device/receive.go:486`).

**magicsock 구현**:

- `connBind.Open`은 IPv4·IPv6·DERP 수신 함수 세 개를 돌려주고, 포트 인자는 무시한다(`tailscale.com/wgengine/magicsock/magicsock.go:3543`).
- `SetMark`는 아무것도 하지 않는다(`tailscale.com/wgengine/magicsock/magicsock.go:3565`).
- `BatchSize`는 linux 128, 그 밖은 1이다(`tailscale.com/wgengine/magicsock/magicsock.go:3528`).
- `ParseEndpoint`는 **노드 공개키 hex 문자열**을 받아 그 피어의 `*endpoint`를 돌려준다(`tailscale.com/wgengine/magicsock/magicsock.go:3946`). 즉 wireguard-go의 피어 endpoint는 피어마다 고정된 객체이고, 실제 경로는 magicsock이 고른다.
- `*endpoint`의 메서드(`tailscale.com/wgengine/magicsock/endpoint.go:619`, `tailscale.com/wgengine/magicsock/endpoint.go:568`, `tailscale.com/wgengine/magicsock/magicsock.go:3929`):
  - `DstToString` = 공개키 hex
  - `DstIP` = 노드의 첫 tailnet 주소
  - `DstToBytes` = 가짜 주소 `fakeWGAddr`를 IP 바이트 ‖ 포트 LE 2바이트로 묶은 값
- 출발지로 피어를 정할 수 없거나 확인이 필요하면 magicsock은 `*lazyEndpoint`를 넘긴다(`tailscale.com/wgengine/magicsock/magicsock.go:1914`, `tailscale.com/wgengine/magicsock/magicsock.go:1936`). 이 Endpoint는 두 선택 인터페이스로 출발지 주소와 피어 키를 연결한다(`tailscale.com/wgengine/magicsock/magicsock.go:4487`, `tailscale.com/wgengine/magicsock/magicsock.go:4530`).
- 부하 상태에서 cookie reply가 `*lazyEndpoint`로 나가면 출발지 UDP 주소로 직접 쓴다(`tailscale.com/wgengine/magicsock/magicsock.go:1514`).

### 지연 피어 설정

**피어 생성 콜백**:

- `Device.SetPeerLookupFunc(f)`를 설정하면 `LookupPeer`가 모르는 공개키에 대해 f를 부른다. f가 `NewPeerConfig{AllowedIPs, PresharedKey, Endpoint}`를 돌려주면 피어를 만들어 시작한다(`wireguard-go/device/device.go:542`, `wireguard-go/device/device.go:634`).
- 이렇게 만든 피어는 `deleteOnIdle`이고, zeroKeyMaterial 만료(540초) 때 제거된다(`wireguard-go/device/device.go:568`, `wireguard-go/device/timers.go:130`).
- `LookupPeer`는 initiation 수신(`wireguard-go/device/noise-protocol.go:386`)과 `PeerByIPPacketFunc`를 통한 송신(`wireguard-go/device/allowedips.go:370`)에서 불린다.
- `LookupActivePeer`는 피어를 만들지 않는다(`wireguard-go/device/device.go:585`).

**그 밖의 포크 API**:

| API | 동작 | 출처 |
| --- | --- | --- |
| `SetPeerByIPPacketFunc` | 송신 경로에서 (src, dst, 패킷)으로 피어 공개키를 정한다 | `wireguard-go/device/device.go:670`, `:710` |
| `SetSessionStateFunc` | 피어 세션 상태 None/Handshake/Established/Expired 변화를 알린다 | `wireguard-go/device/device.go:672`, `:725` |
| `SetPriorityMessageOnEstablishmentFunc` | keypair가 확정될 때 최대 512바이트(`MaxPriorityMessageContentSize`) 메시지를 staged를 거치지 않고 보낸다 | `wireguard-go/device/device.go:738`, `wireguard-go/device/send.go:111` |
| `ScheduleHandshakeOnUserSend` | 다음 송신 뒤 initiation을 예약한다. 키가 없는 피어에게는 효과가 없다 | `wireguard-go/device/device.go:772` |
| `RemoveMatchingPeers` | 조건에 맞는 피어를 제거한다 | `wireguard-go/device/device.go:619` |
| `WithMetrics` 등 `Option` | 큐 크기와 지표 | `wireguard-go/device/device.go:127`, `:193` |

### Tailscale이 넘기는 설정

**`wgcfg.Config`**(`tailscale.com/wgengine/wgcfg/config.go:23`):

- `PrivateKey`와 `Addresses`만 가진다.
- 피어 목록은 설정에 없다. 피어마다 `PeerConfig{AllowedIPs, PresharedKey}`를 콜백으로 준다.

**장치와 피어 생성**:

- 장치는 `wgcfg.NewDevice`로 만들고, Bind는 `magicConn.Bind()`다(`tailscale.com/wgengine/userspace.go:519`).
- 피어 생성은 `SetPeerConfigFunc`가 설치하는 `PeerLookupFunc` 하나로 처리한다(`tailscale.com/wgengine/userspace.go:687`).
- 그 함수는 `bind.ParseEndpoint(공개키 hex)`로 endpoint를 만들어 `NewPeerConfig`에 넣는다(`tailscale.com/wgengine/wgcfg/device.go:47`).

**PSK**:

- 실제 콜백 `LocalBackend.peerConfig`는 `AllowedIPs`만 채운다(`tailscale.com/ipn/ipnlocal/resolve.go:49`). 따라서 PSK는 항상 0이고, KDF3에는 32바이트 0이 들어간다.
- 비시험 코드에서 PSK를 0이 아닌 값으로 정하는 곳을 찾지 못했다(`PresharedKey` 검색 결과는 `tailscale.com/wgengine/userspace.go:714`, `tailscale.com/wgengine/wgcfg/device.go:60` 전달뿐).

**PersistentKeepalive**: `tailscale.com` 비시험 코드에서 `PersistentKeepalive`·`persistent_keepalive`를 찾지 못했다. 따라서 wireguard-go의 persistentKeepalive 타이머는 Tailscale에서 꺼져 있다(간격 0, `wireguard-go/device/timers.go:151`).

**피어 동기화와 정리**:

- netmap 변화 시 `SyncDevicePeer`가 동작한다(`tailscale.com/wgengine/userspace.go:698`).
  - 설정이 없으면 피어를 제거한다.
  - 이미 있는 피어면 PSK·AllowedIPs를 갱신한다.
  - 없는 피어는 만들지 않는다.
- 유휴 피어 정리는 위의 `deleteOnIdle`와 540초 타이머에 맡긴다.
- 상태 조회는 `LookupActivePeer`를 써서 피어를 만들지 않는다(`tailscale.com/wgengine/userspace.go:1015`).

**그 밖의 연결**:

- 송신 경로 조회는 `SetPeerByIPPacketFunc`로 목적지 주소만 쓴다(`tailscale.com/wgengine/userspace.go:739`, `tailscale.com/ipn/ipnlocal/resolve.go:28`).
- 세션 상태 콜백, priority message, `ScheduleHandshakeOnUserSend`를 연결한다(`tailscale.com/wgengine/userspace.go:720`, `:752`, `:769`).
- 비밀키는 magicsock과 wireguard-go 양쪽에 넣는다(`tailscale.com/wgengine/userspace.go:891`, `:895`).

### 메모리 관련 상수

| 플랫폼 | staged | outbound | inbound | handshake | 미리 할당 버퍼/풀 | `MaxSegmentSize` | 출처 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 기본 | 128 | 1024 | 1024 | 1024 | 0(무제한) | 65535 | `wireguard-go/device/queueconstants_default.go:12` |
| iOS | 128 | 1024 | 1024 | 1024 | 1024 | 1700 | `wireguard-go/device/queueconstants_ios.go:13` |
| Android | 128 | 1024 | 1024 | 1024 | 4096 | 2200 | `wireguard-go/device/queueconstants_android.go:12` |
| Windows | 128 | 1024 | 1024 | 1024 | 0 | 2016 | `wireguard-go/device/queueconstants_windows.go:8` |

- **Tailscale iOS**: 다섯 값을 모두 64로 덮어쓴다(staged·outbound·inbound·handshake·미리 할당). 따라서 부하 판정 문턱은 64/8 = 8이다(`tailscale.com/wgengine/wgcfg/mem_ios.go:20`).
- **Tailscale 그 밖의 플랫폼**: inbound·outbound만 min(1024, CPU 수×4)로 바꾼다(`tailscale.com/wgengine/wgcfg/mem_notios.go:37`).
- **iOS의 데이터그램 크기**: `MaxSegmentSize` 1700은 받을 수 있는 데이터그램 크기의 상한이다. iOS에서 평문 상한은 1700−40 = 1660바이트다(`wireguard-go/device/constants.go:32`).

## 상수와 타이머

| 이름 | 값 | 출처 |
| --- | --- | --- |
| `RekeyAfterMessages` | 2^60 | `wireguard-go/device/constants.go:15` |
| `RejectAfterMessages` | 2^64 − 2^13 − 1 | `wireguard-go/device/constants.go:16` |
| `RekeyAfterTime` | 120초 | `wireguard-go/device/constants.go:17` |
| `RekeyAttemptTime` | 90초 (코드에서 직접 쓰지 않고 `MaxTimerHandshakes` 계산의 근거) | `wireguard-go/device/constants.go:18` |
| `RekeyTimeout` | 5초 | `wireguard-go/device/constants.go:19` |
| `MaxTimerHandshakes` | 90/5 = 18 | `wireguard-go/device/constants.go:20` |
| `RekeyTimeoutJitterMaxMs` | 334 | `wireguard-go/device/constants.go:21` |
| `RejectAfterTime` | 180초 | `wireguard-go/device/constants.go:22` |
| `KeepaliveTimeout` | 10초 | `wireguard-go/device/constants.go:23` |
| `CookieRefreshTime` | 120초 | `wireguard-go/device/constants.go:24` |
| `HandshakeInitationRate` | 1초/50 = 20ms | `wireguard-go/device/constants.go:25` |
| `PaddingMultiple` | 16 | `wireguard-go/device/constants.go:26` |
| `MinMessageSize` | 32 (`MessageKeepaliveSize`) | `wireguard-go/device/constants.go:30` |
| `MaxMessageSize` | `MaxSegmentSize` | `wireguard-go/device/constants.go:31` |
| `MaxContentSize` | `MaxSegmentSize` − 32 − 8 | `wireguard-go/device/constants.go:32` |
| `UnderLoadAfterTime` | 1초 | `wireguard-go/device/constants.go:38` |
| `MaxPeers` | 65536 | `wireguard-go/device/constants.go:39` |
| `DefaultMTU` | 1420 | `wireguard-go/device/tun.go:14` |
| replay `windowSize` | 8128 | `wireguard-go/replay/replay.go:15` |
| ratelimiter | 20 pps, burst 5 | `wireguard-go/ratelimiter/ratelimiter.go:15` |
| `MaxPriorityMessageContentSize` | 512 | `wireguard-go/device/device.go:738` |
| `conn.IdealBatchSize` | 128 | `wireguard-go/conn/conn.go:19` |

백서 대조: 위 시간·메시지 한도, 레이블 문자열, KDF 정의, mac1/mac2/cookie 구성, 패딩 16의 배수는 백서 기억과 같다. 백서의 "90초 동안 재시도"는 소스에서 "재시도 횟수 18 초과 시 포기"로 구현되어 있다(`wireguard-go/device/timers.go:80`). 이 노트는 소스를 따른다.

## Swiftail에 필요한 최소 부분과 생략할 수 있는 부분

M1 관문: Swift 피어와 wireguard-go 피어가 UDP 루프백으로 핸드셰이크하고, 양방향으로 패킷을 주고받으며, rekey 뒤에도 연결이 유지된다.

### 필수

1. **암호 기본 연산**: X25519(clamp, 0 공유 비밀 거부), BLAKE2s-256, keyed BLAKE2s-128, HMAC-BLAKE2s와 KDF1/2/3, ChaCha20-Poly1305 IETF.
2. **TAI64N**: 생성과 바이트 비교. 피어별 `lastTimestamp` 재전송 검사와 20ms flood 검사도 필요하다. Go 응답자가 같은 검사를 하므로, Swift 초기자는 단조 증가 timestamp를 내야 한다.
3. **mac1 생성·검사**: Go 수신 측이 항상 검사한다(`wireguard-go/device/receive.go:314`). mac2는 cookie가 없으면 0으로 둔다.
4. **메시지 4종의 직렬화**: type 예약 바이트 0, LE 정수.
5. **초기자·응답자 상태 기계**: index table(handshake index → keypair index 교체), previous/current/next 교체, 응답자의 next 확정, 초기자의 확인용 keepalive.
6. **transport 암복호**: 12바이트 nonce = 0⁴ ‖ LE counter, sendNonce 한도, replay filter(8128 창), keypair 나이 180초 거부.
7. **수신 IP 처리**: 길이 검사, 패딩 제거, 원천 주소 AllowedIPs 검사. 상대 Go가 패딩을 붙여 보낸다.
8. **rekey 유지에 필요한 타이머·규칙**:
   - `RekeyAfterTime`(초기자 송신 시)
   - `keepKeyFreshReceiving`(165초)
   - `RejectAfterTime`
   - retransmitHandshake(5초+지터, 최대 20회)
   - `RekeyTimeout` 송신 억제
   - sendKeepalive(10초)
   - newHandshake(15초+)
   - zeroKeyMaterial(540초)

   rekey는 양쪽 역할로 모두 시험해야 한다. Swift가 초기자인 rekey와, Go가 120초 뒤 초기자로 rekey할 때 Swift가 응답자로 next를 받아 확정하는 경우다.
9. **송신 패딩**: Go 수신 측은 IP 길이로 패딩을 떼므로 패딩이 없어도 받는다. 다만 구현 비용이 작아 함께 넣는 것이 낫다.

### 뒤로 미룰 수 있는 것

| 항목 | 미룰 수 있는 근거 |
| --- | --- |
| cookie reply 생성·소비, XChaCha20-Poly1305, 부하 판정, rate limiter | Go는 부하 상태(핸드셰이크 큐 128개 이상)에서만 cookie를 보낸다(`wireguard-go/device/receive.go:321`). 루프백 1:1 시험에서는 생기지 않는다. 받은 type 3은 M1에서 무시해도 핸드셰이크 재시도로 회복된다. 다만 크기 64 검사와 무시 처리는 넣는다. |
| PSK | Tailscale은 0만 쓴다(위 절). KDF3 입력을 32바이트 0으로 고정하면 된다. 0이 아닌 PSK 지원은 같은 코드 경로라 비용이 거의 없다. |
| persistentKeepalive | Tailscale이 쓰지 않는다. |
| 엔드포인트 로밍 | 포크에도 없다. M1에서는 피어마다 고정 UDP 주소를 둔다. |
| `PeerLookupFunc`류 지연 생성, `deleteOnIdle` 제거, `PeerByIPPacketFunc`, 세션 상태 콜백, priority message, `ScheduleHandshakeOnUserSend` | magicsock·netmap 연동(M3–M5) 기능이며 와이어 형식과 무관하다. |
| Endpoint 선택 인터페이스(`InitiationAwareEndpoint`, `PeerAwareEndpoint`) | magicsock 대체 단계(M4)에서 필요하다. M1의 Swift 설계에서는 "initiation 정적 키 복호 직후"와 "transport 복호·replay 통과 직후" 두 지점에 끼어들 수 있게 열어 두면 된다. |
| 배치 수신, 다중 큐, 버퍼 풀, GSO, `SetMark`, sticky socket | 성능·플랫폼 기능이다. iOS 메모리 상한(Tailscale iOS 큐 64)은 큐 크기를 상수로 두는 정도로 충분하다. |

## 상호 운용 시험에서 확인할 것

### 재사용할 수 있는 시험

- **KDF 시험 벡터**(`wireguard-go/device/kdf_test.go:30`): (key, input, T0, T1, T2) 세 묶음이 hex로 있다. 빈 key·빈 input 경우도 포함한다. KDF1·KDF2는 같은 벡터의 앞부분을 쓴다(`:68`, `:78`). HMAC-BLAKE2s 구현을 고정하는 유일한 고정 벡터이므로 그대로 Swift 단위 시험으로 옮긴다.
- **replay 시험**(`wireguard-go/replay/replay_test.go:19`): 34개 고정 순서 사례와 bulk 사례 6개가 있다. 창 경계와 `RejectAfterMessages` 경계를 다룬다. 입력과 기대값이 상수이므로 그대로 옮길 수 있다.
- **TAI64N 단조성**(`wireguard-go/tai64n/tai64n_test.go:15`): 10ms 차이는 after가 아니고 20ms 차이는 after다.
- **cookie 왕복**(`wireguard-go/device/cookie_test.go:12`): 무작위 키로 왕복 성질을 시험한다. mac1 생성·검사, mac2는 cookie가 없으면 실패, cookie reply 생성·소비 후 mac2 성공, 바이트 하나를 바꾸거나 src가 다르면 실패하는지 본다. 고정 벡터가 아니므로 성질 시험으로 옮긴다.
- **핸드셰이크 왕복**(`wireguard-go/device/noise_test.go:80`): 무작위 키로 두 장치를 만든다. initiation, response, 양쪽 `BeginSymmetricSession` 뒤 양방향 Seal/Open이 되는지 보고, `InitiationAwareEndpoint` 호출 여부도 본다. 고정 벡터가 없으므로 Swift 쪽은 성질 시험으로 쓰고, 실제 상호 운용은 Go 피어와 교차해서 확인해야 한다.
- **Go 쪽 시험 피어 재료**:
  - `tun/tuntest`의 `NewChannelTUN`(MTU 1420)과 ICMPv4 패킷 생성 `Ping`(`wireguard-go/tun/tuntest/tuntest.go:92`, `wireguard-go/tun/tuntest/tuntest.go:17`, `wireguard-go/tun/tuntest/tuntest.go:170`)
  - 표준 bind `conn.NewDefaultBind`와 `ip:port` 형식 `ParseEndpoint`(`wireguard-go/conn/bind_std.go:90`)
  - 두 장치를 UAPI로 묶는 `device_test.go`의 구성(`wireguard-go/device/device_test.go:68`)

### M1 교차 시험 항목

1. Go 피어에 Swift의 UDP 주소를 `endpoint=`로 반드시 넣는다. 로밍이 없으므로 넣지 않으면 Go가 응답자일 때 response를 보내지 못한다(`wireguard-go/device/peer.go:216`).
2. Swift 초기자 → Go 응답자: Go 로그에 "Received handshake initiation"이 남는지 본다. Swift는 response 직후 keepalive를 보내고, Go가 next를 확정해 Go→Swift 데이터가 흐르는지 확인한다.
3. Go 초기자 → Swift 응답자: Swift가 확인 전까지 새 keypair로 보내지 않는지, 확인 뒤 보내는지 확인한다.
4. 양방향 ICMP 또는 임의 IP 패킷: Go 쪽 패딩(MTU 1420 기준)을 Swift가 IP 길이로 떼는지, keepalive(32바이트)를 데이터로 오인하지 않는지 확인한다.
5. 재전송·flood 경계:
   - 같은 initiation 재전송은 Go가 replay로 버린다.
   - 20ms 안의 두 번째 initiation은 flood로 버린다.
   - Go 쪽 `RekeyTimeout` 억제(5초) 때문에 Go는 response를 보낸 뒤 5초 안에 initiation을 보내지 않는다.
6. rekey:
   - 120초 넘게 트래픽을 흘려 초기자 쪽 시간 기반 rekey를 확인한다.
   - previous keypair로 온 지연 패킷이 받아지는지 확인한다.
   - 180초 넘은 keypair의 패킷이 버려지는지 확인한다.
   - Swift가 응답자일 때 previous/current/next 교체가 올바른지 확인한다.
7. counter 경계: replay 창 밖(8128 초과로 뒤처진) 패킷과 중복 counter가 거부되는지 확인한다.
8. 오류 분기: 잘못된 mac1, 크기가 틀린 핸드셰이크, 알 수 없는 type, 0이 아닌 예약 바이트를 Go가 조용히 버리는지 확인한다. Swift도 같은 입력에서 상태를 바꾸지 않아야 한다.

## 확인하지 못한 것

- **원본 wireguard-go와의 차이**: 원본(zx2c4) 소스가 참고 소스에 없어 바이트 단위로 비교하지 못했다. 위 "Tailscale 포크" 절의 API(`PeerLookupFunc`, 두 선택 Endpoint 인터페이스, 세션 상태, priority message, `ScheduleHandshakeOnUserSend`, 메트릭)와 수신 경로의 로밍 부재가 포크 고유인지는 기억에 기댄 판단이라 단정하지 않는다.
- **`golang.org/x/crypto` 내부**: 모듈 캐시에 없어 확인하지 못했다(BLAKE2s 블록 크기와 HMAC 결합, keyed BLAKE2s의 key 처리, XChaCha20 HChaCha 단계, `curve25519.ScalarMult`의 내부 clamp). KDF는 `kdf_test.go` 벡터로 고정할 수 있지만 XChaCha20-Poly1305와 keyed BLAKE2s-128에는 이 소스 트리에 고정 벡터가 없다.
- **`netip.AddrPort.MarshalBinary` 형식**: 표준 bind의 `DstToBytes` 형식은 Go 표준 라이브러리라 확인하지 못했다. cookie src는 수신 측 내부 값이라 상호 운용에는 영향이 없다.
- **고정 Noise 핸드셰이크 벡터**: 소스 트리에서 찾지 못했다. 핸드셰이크 정확성은 Go 피어와의 교차 시험으로만 확인할 수 있다.
- **`tests/netns.sh`의 로밍 검사**: endpoint 로밍 검사(`wireguard-go/tests/netns.sh:196`, `:202`)가 이 포크에서 통과하는지 확인하지 못했다.
- **magicsock 측 keepalive·경로 유지**: magicsock이 wireguard-go persistentKeepalive 대신 자체 keepalive를 하는지는 `disco-magicsock.md` 범위로 남긴다. `receiveIP`의 `lazyEndpoint` 선택 조건 세부도 이 노트에서는 읽지 않았다.
- **Swift 쪽 지원**: Apple 프레임워크가 BLAKE2s·XChaCha20-Poly1305를 제공하는지는 이 노트의 소스 범위 밖이라 확인하지 않았다.
