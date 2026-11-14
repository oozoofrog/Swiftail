# disco와 magicsock

## 1. 머리말

| 항목 | 값 |
| --- | --- |
| 기준 소스 | `tailscale.com` v1.104.6 (CapabilityVersion 148, `docs/protocol-notes/README.md` 기준 소스 표) |
| 작성 모델 | GPT-6.1 Sol |
| 검증 상태 | 검증: Claude Opus 5.5, 2026-11-15, 수정 7건 + M4 절차·결정·시험 보충 |

출처는 모듈 루트 기준 `tailscale.com/<경로>:<줄>`이다. 의존 모듈은 `golang.org/x/crypto@v0.58.0/...`(`tailscale.com/go.mod:139`)와 `wireguard-go/...`(README 기준 소스 표의 Tailscale 포크), 이 저장소의 파일은 저장소 루트 기준 경로로 적는다. "구현 제안"과 "계산"이라고 적은 문장은 Go의 동작이 아니라 Go 규칙에서 끌어낸 Swiftail 쪽 판단이다.

## 2. 범위

다루는 것(M4): disco 메시지 형식과 암호, 받은 UDP 데이터그램의 분류, 피어별 후보 주소와 경로 선택(`bestAddr`), Ping·Pong·CallMeMaybe를 언제 보내는가, 자기 엔드포인트를 알아내 제어 서버에 올리는 것, TSMP disco 키 광고, M4 관문에 필요한 범위의 네트워크 변경, Go 피어가 상대에게 기대하는 것(peer relay·peer MTU) 가운데 무시해도 되는 것의 근거, `Tools/interop` `tailnet`으로 하는 시험.

다루지 않는 것: STUN 바이트 형식과 netcheck의 홈 지역 선택(`derp-stun.md` 3.8·3.9·4.10), DERP 프레임과 지역 연결(`derp-stun.md`), WireGuard 자체(`wireguard.md`), 맵 요청의 나머지 필드(`control-map.md`), peer relay의 서버·클라이언트 절차(형식만 적는다), Wi-Fi↔셀룰러 전환과 iOS 소켓 결속의 세부(M5).

## 3. 와이어 형식

### 3.1 disco 겉 형식

UDP 데이터그램이나 DERP 패킷 본문이 그대로 이 형식이다(Geneve로 감싼 peer relay 경로는 3.6) (`tailscale.com/disco/disco.go:6-19`, `tailscale.com/wgengine/magicsock/magicsock.go:2041-2051`).

| 오프셋 | 길이 | 필드 | 값 |
| --- | --- | --- | --- |
| 0 | 6 | magic | `54 53 f0 9f 92 ac` (`"TS💬"`) (`disco/disco.go:35`) |
| 6 | 32 | 보낸 쪽 disco 공개 키 | raw 32바이트 (`magicsock.go:2042`) |
| 38 | 24 | nonce | 메시지마다 새 난수 (`tailscale.com/types/key/disco.go:223-225`) |
| 62 | 16 | Poly1305 tag | secretbox 출력의 앞 16바이트 (`golang.org/x/crypto@v0.58.0/nacl/secretbox/secretbox.go:76-118`) |
| 78 | L | 암호문 | 3.3의 평문(L바이트)을 XSalsa20으로 암호화한 것 |

길이(계산, `tailscale.com/wgengine/magicsock/endpoint.go:1294-1298`): 겉 형식은 평문보다 78바이트 길다. 지금 Go가 보내는 Ping(NodeKey 포함, 패딩 없음)은 124바이트, NodeKey 없는 Ping은 92바이트, Pong은 110바이트, 주소 N개짜리 CallMeMaybe는 80 + 18N바이트다.

### 3.2 암호

1. disco 개인 키: 난수 32바이트를 `b[0] &= 248`, `b[31] = (b[31] & 127) | 64`로 clamp한다. 공개 키는 X25519 기점 곱이다. node 키와 따로 만들며 node 키에서 유도하지 않는다(`tailscale.com/types/key/disco.go:36-43`, `:65-74`, `tailscale.com/types/key/util.go:51-54`, `tailscale.com/wgengine/magicsock/magicsock.go:579-580`).
2. 공유 키: 자기 **disco** 개인 키와 상대의 **disco** 공개 키로 `box.Precompute`를 부른다. 이는 `X25519(개인, 상대 공개)`의 결과에 `HSalsa20(key: 그 결과, input: 0^16, sigma)`를 적용한 32바이트다(`tailscale.com/types/key/disco.go:76-84`, `golang.org/x/crypto@v0.58.0/nacl/box/box.go:81-84`). Swiftail의 `NaClBox.sharedKey(privateKey:peerPublicKey:)`가 같은 계산이다(`Sources/SwiftailCrypto/NaCl.swift:39-44`).
3. 봉인: 새 난수 nonce N(24바이트)으로 `secretbox.Seal(평문, N, 공유 키)`(XSalsa20-Poly1305, 출력 = tag 16 ‖ 암호문)을 만들고 `N ‖ 출력`을 magic·공개 키 뒤에 붙인다. 추가 인증 데이터는 없다. magic과 보낸 쪽 공개 키는 암호로 묶이지 않는다(`tailscale.com/types/key/disco.go:219-226`, `golang.org/x/crypto@v0.58.0/nacl/box/box.go:97-99`). Swiftail의 `NaClSecretBox.seal`이 같은 배치다(`Sources/SwiftailCrypto/NaCl.swift:4-11`).
4. 열기: 오프셋 38부터를 받아 앞 24바이트를 nonce로, 나머지를 secretbox로 연다. 24바이트 미만이거나 tag가 틀리면 실패다(`tailscale.com/types/key/disco.go:231-240`, `golang.org/x/crypto@v0.58.0/nacl/secretbox/secretbox.go:125-128`).
5. 캐시: Go는 상대 disco 공개 키마다 공유 키를 한 번 계산해 표에 둔다. 표는 netmap에 있는 disco 키(또는 TSMP로 배운 키, 4.10)에 대해서만 만든다. 자기 disco 키를 바꾸면 표 전체를 비운다(`tailscale.com/wgengine/magicsock/magicsock.go:2742-2753`, `:1261`).
6. 실패: 모르는 disco 키, 열리지 않는 box, 파싱 실패는 모두 아무 응답 없이 버린다. 열리지 않은 패킷을 WireGuard로 넘기지도 않는다(`tailscale.com/wgengine/magicsock/magicsock.go:2245-2253`, `:2267-2286`, `:2295-2307`, `:1875-1876`).

Go와의 차이 한 가지: Go의 `curve25519.ScalarMult`는 결과가 전부 0이면(저차수 공개 키) 0을 그대로 쓰고 계속한다(`golang.org/x/crypto@v0.58.0/curve25519/curve25519.go:23-31`). Swiftail의 `sharedKey`는 이때 `invalidKey`를 던진다(`Sources/SwiftailCrypto/NaCl.swift:43`). 그런 키의 메시지는 버리면 된다(구현 제안).

### 3.3 평문 머리와 메시지 종류

| 평문 오프셋 | 길이 | 필드 | 값 |
| --- | --- | --- | --- |
| 0 | 1 | type | 아래 표 |
| 1 | 1 | version | 보낼 때 항상 0 |
| 2 | … | 본문 | 종류별 (3.4, 3.5) |

(`tailscale.com/disco/disco.go:44-56`, `:119-132`)

| type | 이름 | v0 본문 길이 | Go 파서 |
| --- | --- | --- | --- |
| `0x01` | `Ping` | 12, 44, 또는 그 이상(패딩) | version을 보지 않는다. 12 미만이면 오류. 뒤 바이트 허용 |
| `0x02` | `Pong` | 30 | version을 보지 않는다. 30 미만이면 오류. 뒤 바이트 무시 |
| `0x03` | `CallMeMaybe` | 18N | version ≠ 0, 길이 0, 18의 배수가 아니면 **오류 없이 주소 0개** |
| `0x04` | `BindUDPRelayEndpoint` | 72 | version을 보지 않는다. 72 미만이면 오류 |
| `0x05` | `BindUDPRelayEndpointChallenge` | 72 | 위와 같다 |
| `0x06` | `BindUDPRelayEndpointAnswer` | 72 | 위와 같다 |
| `0x07` | `CallMeMaybeVia` | 124 + 18N (N ≥ 1) | version ≠ 0이면 빈 메시지. 길이가 맞지 않으면 오류 |
| `0x08` | `AllocateUDPRelayEndpointRequest` | 68 | version ≠ 0이면 빈 메시지. 68 미만이면 오류 |
| `0x09` | `AllocateUDPRelayEndpointResponse` | 128 + 18N (N ≥ 1) | version ≠ 0이면 빈 메시지. 길이가 맞지 않으면 오류 |

(`tailscale.com/disco/disco.go:81-109`, `:169-189`, `:232-247`, `:271-284`, `:385-397`, `:491-505`, `:526-537`, `:594-598`, `:651-658`)

평문이 2바이트 미만이거나 모르는 type이면 파싱 오류이고, 수신 쪽은 이를 조용히 버린다(새 버전의 메시지로 본다) (`disco/disco.go:82-84`, `:106-107`, `tailscale.com/wgengine/magicsock/magicsock.go:2299-2307`). Swiftail은 version이나 뒤 바이트를 Go보다 엄격하게 거르지 않는다(구현 제안: 위 표의 규칙을 그대로 따른다).

### 3.4 Ping, Pong, CallMeMaybe

본문 오프셋(평문 오프셋 − 2). 정수는 BE다.

| 메시지 | 오프셋 | 길이 | 필드 | 값 |
| --- | --- | --- | --- | --- |
| `Ping` | 0 | 12 | TxID | 보낼 때마다 새 난수 (`tailscale.com/wgengine/magicsock/endpoint.go:1405`) |
| `Ping` | 12 | 32 | NodeKey | 보낸 쪽 WireGuard(node) 공개 키 raw. 0이면 쓰지 않는다 |
| `Ping` | 12 또는 44 | P | 패딩 | 0으로 채운다. 경로 MTU 측정용 |
| `Pong` | 0 | 12 | TxID | 받은 Ping의 TxID |
| `Pong` | 12 | 16 | Src IP | Ping의 관측 출발 IP. IPv4는 IPv4-mapped IPv6(`::ffff:a.b.c.d`) |
| `Pong` | 28 | 2 | Src port | Ping의 관측 출발 포트 |
| `CallMeMaybe` | 18i | 16 | 주소 i의 IP | IPv4는 IPv4-mapped. 받을 때 unmap |
| `CallMeMaybe` | 18i + 16 | 2 | 주소 i의 포트 | 개수 필드 없이 길이로 센다 |

(`tailscale.com/disco/disco.go:134-189`, `:219-247`, `:249-284`)

- Ping 파싱: TxID 뒤가 32바이트 이상이고 그 32바이트가 전부 0이 아니면 NodeKey로, 나머지를 패딩으로 본다. 32바이트가 전부 0이면 NodeKey 없이 모두 패딩이다(`disco/disco.go:169-189`).
- Go가 보내는 Ping은 항상 자기 NodeKey를 넣는다. 패딩은 경로 MTU 측정이 켜졌을 때만 있다(`tailscale.com/wgengine/magicsock/endpoint.go:1309-1317`, 4.12).
- Go는 Pong의 Src를 기록과 로그에만 쓴다. 경로 선택이나 자기 엔드포인트에는 쓰지 않는다(`tailscale.com/wgengine/magicsock/endpoint.go:1966-1975`, `:1993-1997`). 그래도 Swiftail은 Go처럼 관측한 출발 주소를 넣는다(구현 제안).

### 3.5 peer relay 메시지 (식별만)

Swiftail은 이 종류를 보내지 않고 받으면 버린다(4.12). 형식은 시험 자료와 경계 검사를 위해 적는다.

`0x04`·`0x05`·`0x06` 본문(72바이트, `tailscale.com/disco/disco.go:342-397`):

| 오프셋 | 길이 | 필드 |
| --- | --- | --- |
| 0 | 4 | VNI (u32 BE, Geneve VNI와 같아야 한다) |
| 4 | 4 | Generation (u32 BE) |
| 8 | 32 | RemoteKey (relay 너머 상대의 disco 공개 키) |
| 40 | 32 | Challenge |

relay 엔드포인트 E(`tailscale.com/disco/disco.go:539-623`): 0:32 ServerDisco, 32:32 ClientDisco[0], 64:32 ClientDisco[1], 96:8 LamportID(u64 BE), 104:4 VNI(u32 BE), 108:8 BindLifetime(u64 BE, 나노초), 116:8 SteadyStateLifetime(u64 BE, 나노초), 124부터 18바이트 주소 N개(3.4 CallMeMaybe와 같은 배치, N ≥ 1). `CallMeMaybeVia` 본문은 E, `AllocateUDPRelayEndpointResponse` 본문은 `Generation(u32 BE) ‖ E`다(`disco/disco.go:517-523`, `:644-649`). `AllocateUDPRelayEndpointRequest` 본문은 ClientDisco[0] 32 ‖ ClientDisco[1] 32 ‖ Generation u32 BE(`disco/disco.go:477-489`).

### 3.6 Geneve 머리 (peer relay 경로)

peer relay 경로의 UDP는 disco나 WireGuard 앞에 8바이트 Geneve 머리를 붙인다. Go가 보내는 값: byte 0 = 0, byte 1 = Control 비트(`0x80`) 또는 0, byte 2–3 = protocol(u16 BE, disco `0x7A11`, WireGuard `0x7A12`), byte 4–6 = VNI(24비트 BE), byte 7 = 0(`tailscale.com/net/packet/geneve.go:18-22`, `:100-118`). 이 경로를 쓰지 않는 Swiftail에게는 4.1의 분류 규칙만 필요하다.

### 3.7 STUN

요청·응답 바이트 형식과 Go STUN 서버의 거르기는 `derp-stun.md` 3.8·3.9를 따른다. magicsock에서 중요한 점은 STUN을 데이터·disco와 **같은 UDP 소켓**으로 보내고 받는다는 것이다(`derp-stun.md` 4.10 2, `tailscale.com/wgengine/magicsock/magicsock.go:1632-1644`, `:1877-1881`).

### 3.8 TSMP disco 키 광고

WireGuard 터널 안의 IP 패킷이다(바깥 UDP의 disco가 아니다). IP 머리의 protocol은 99(TSMP), 출발지·목적지는 양쪽의 Tailscale 주소다(`tailscale.com/types/ipproto/ipproto.go:67`, `tailscale.com/net/packet/tsmp.go:291-315`).

| IP 본문 오프셋 | 길이 | 필드 | 값 |
| --- | --- | --- | --- |
| 0 | 1 | TSMP type | `0x61` (`'a'`) |
| 1 | 32 | disco 공개 키 | raw |

받는 쪽 파서는 본문 33바이트 이상과 첫 바이트만 본다(`tailscale.com/net/packet/tsmp.go:80`, `:318-331`).

## 4. 절차와 상태 기계

### 4.1 받은 UDP 데이터그램의 분류

순서대로 본다(`tailscale.com/wgengine/magicsock/magicsock.go:2143-2191`, `:1849-1921`).

1. **STUN**: 길이 ≥ 20, 첫 바이트의 상위 2비트가 0, 바이트 4–7이 `21 12 a4 42`, 그리고 바이트 1이 `0x01`이면 STUN binding으로 보고 netcheck에 넘긴다. WireGuard로 넘기지 않는다(`tailscale.com/net/stun/stun.go:308-312`, `magicsock.go:2144-2147`, `:1877-1881`). 응답 검증은 `derp-stun.md` 4.10 3이다.
2. **Geneve**: 길이 ≥ 8, `b[0] & 0xC0 == 0`, `b[1] & 0x3F == 0`, `b[7] == 0`이고 protocol이 `0x7A11`이며 8바이트 뒤가 disco(아래 3)이면 Geneve disco, protocol이 `0x7A12`이면 Geneve WireGuard다. `0x7A11`인데 뒤가 disco가 아니면 맨 WireGuard로 본다. 다른 protocol 값이면 3으로 내려간다(`magicsock.go:2158-2184`).
3. **disco**: 길이 ≥ 38이고 앞 6바이트가 magic이면 disco다(`magicsock.go:2103`, `:2151-2156`, `:2186-2187`). 62바이트 기준의 `disco.LooksLikeDiscoWrapper`와 다르다(`tailscale.com/disco/disco.go:62-67`). 38–61바이트의 disco는 열기에서 실패해 버려진다(3.2 4).
4. **나머지**는 WireGuard로 본다(`magicsock.go:2188-2190`). 자기 node 개인 키가 없으면 버린다(`magicsock.go:1887-1892`).

출발 주소와 피어의 연결:

- disco는 주소가 아니라 **보낸 쪽 disco 공개 키**로 피어를 찾는다(4.2).
- Go는 WireGuard 패킷의 출발 주소를 주소→피어 표에서 찾고, 없으면 임시 엔드포인트로 WireGuard에 넘겨 복호화로 피어가 정해진 뒤 표에 넣는다(`magicsock.go:1905-1921`, `:4524`). Swiftail의 WireGuard 장치는 receiver index로 피어를 정하고 `.ipPacket(_, from:)`으로 알려 주므로(`docs/contracts/SwiftailWireGuard.md` `Output`), 복호화에 주소→피어 표가 필요 없다(구현 제안).
- 주소→피어 표가 쓰이는 곳은 Go에서 UDP 수신 시각 기록과 heartbeat를 끈 피어의 신뢰 연장뿐이다(`magicsock.go:1922-1924`, `tailscale.com/wgengine/magicsock/endpoint.go:579-606`). 일반 피어는 WireGuard 패킷을 받았다고 신뢰를 연장하지 않는다(`endpoint.go:588-597`).

### 4.2 disco 메시지 받기

1. 보낸 쪽 disco 키가 netmap(또는 TSMP)으로 아는 피어의 키가 아니면 버린다(`tailscale.com/wgengine/magicsock/magicsock.go:2234-2253`). Geneve Control 비트가 선 것은 relay 서버와의 핸드셰이크용이며 Swiftail은 버린다(`magicsock.go:2236-2244`).
2. 공유 키로 열고(3.2 4) 파싱한다(3.3). 실패는 버린다.
3. 종류별 처리(`magicsock.go:2329-2444`):
   - **Ping** → 아래 4.
   - **Pong** → 그 disco 키를 가진 피어들에게 차례로 넘겨, TxID가 자기 것이라고 답한 첫 피어에서 멈춘다(4.6 4).
   - **CallMeMaybe** → DERP로 왔고 DERP 보낸 쪽 node 키가 0이 아니어야 한다. 그 node 키의 피어가 있고, 메시지의 disco 키가 그 피어의 키와 같아야 한다. UDP로 온 CallMeMaybe는 버린다. 통과하면 4.8 5(`magicsock.go:2352-2443`).
   - **CallMeMaybeVia, Allocate…, Bind…** → peer relay 경로. Swiftail은 버린다(4.12).
4. **Ping 처리**(`tailscale.com/wgengine/magicsock/magicsock.go:2581-2684`):
   1. UDP로 온 Ping이면 출발 주소를 어느 node의 것으로 확정할 수 있을 때 주소→node 표에 넣는다. 확정 순서: (가) DERP로 왔고 DERP 보낸 쪽 node 키의 피어가 이 disco 키를 가짐 → (나) Ping의 NodeKey의 피어가 이 disco 키를 가짐 → (다) 이 disco 키를 가진 node가 netmap에 정확히 하나(`magicsock.go:2547-2577`, `:2617-2621`). NodeKey만으로는 믿지 않는다(`disco/disco.go:138-142`).
   2. UDP로 온 Ping이면 이 disco 키를 가진 각 피어의 후보에 **출발 주소**를 넣는다(4.4 1의 Ping 출처). 그 후보가 직전에 받은 Ping과 TxID가 같으면 중복으로 보고 Pong을 보내지 않는다(`magicsock.go:2643-2657`, `tailscale.com/wgengine/magicsock/endpoint.go:1810-1845`).
   3. DERP로 온 Ping은 후보를 넣지 않는다. DERP 보낸 쪽 node 키가 모르는 피어면 버린다(`magicsock.go:2636-2639`, `:2665-2668`).
   4. `Pong{TxID: 받은 TxID, Src: 출발 주소}`를 **온 길로** 보낸다. UDP로 온 것은 그 출발 주소로, DERP로 온 것은 같은 DERP 지역으로 보낸 쪽 node 키에게 보낸다. DERP의 Src는 `127.3.3.40:<지역 ID>`가 된다(`magicsock.go:2678-2683`).

### 4.3 DERP로 받은 것

DERP `FrameRecvPacket` 본문도 4.1 3의 disco 판정(≥ 38바이트, magic)을 거친다. disco면 출발 주소 `127.3.3.40:<받은 지역 ID>`와 DERP 보낸 쪽 node 키를 붙여 4.2로 보내고, 아니면 보낸 쪽 node 키의 피어가 있을 때만 WireGuard로 넘긴다(`tailscale.com/wgengine/magicsock/derp.go:734-777`). M3 계약은 DERP로 온 disco를 62바이트 기준으로 알아보고 버린다(`docs/contracts/SwiftailEngine.md` 받기 5). M4에서는 위 기준으로 4.2에 넘긴다(구현 제안).

### 4.4 피어별 상태와 후보 주소

Go는 disco 키가 0인 피어(WireGuard 전용이 아닌 경우)를 아예 만들지 않는다(`tailscale.com/wgengine/magicsock/magicsock.go:3305-3307`). 피어마다 두는 것(`tailscale.com/wgengine/magicsock/endpoint.go:635-652`, `:1356-1419`, `:1929-2022`):

- DERP 주소: netmap의 `HomeDERP`가 0이 아니면 `127.3.3.40:<지역 ID>`, 0이면 없음(`endpoint.go:1733-1753`). 지역 연결 고르기는 `derp-stun.md` 4.9.
- 후보 주소 표: 주소마다 마지막 Ping 보낸 시각, 마지막 받은 Ping 시각·TxID, CallMeMaybe로 받은 시각, Pong 기록(지연).
- 보낸 Ping 표: TxID → (보낸 주소, 보낸 시각, 목적, 크기, 5초 타이머).
- `bestAddr`(주소, 지연, wire MTU), `trustBestAddrUntil`, `lastFullPing`, `lastSendExt`(외부 송신 활동), heartbeat 타이머.

1. **후보의 출처**:
   - netmap의 `Node.Endpoints`. 맵이 갱신될 때마다 다시 맞춘다(아래 2) (`endpoint.go:1755-1757`, `:1762-1801`).
   - UDP로 받은 Ping의 출발 주소(4.2 4.2).
   - DERP로 받은 CallMeMaybe의 주소 목록(4.8 5). IPv6 link-local은 넣지 않는다(`endpoint.go:2163-2168`).
   - 자기 STUN 결과는 **상대의 후보가 아니다**. 자기 엔드포인트로 제어 서버와 CallMeMaybe에 올린다(4.9).
   - Pong의 Src도 후보가 아니다(3.4).
2. **지우기**(`endpoint.go:510-521`): CallMeMaybe로 받은 시각이 있으면 지우지 않는다. 받은 Ping이 없는 후보(netmap 출처)는 netmap에서 빠지면 지운다. Ping으로 배운 후보는 마지막 Ping을 받고 45초가 지나면 지운다. 검사는 netmap 갱신 때, 전체 Ping을 보낼 때, 후보가 100개를 넘을 때 한다(`endpoint.go:1796-1800`, `:1429-1433`, `:1835-1843`). 다음 CallMeMaybe에 빠진 이전 CallMeMaybe 주소는 출처를 따지지 않고 지운다(`endpoint.go:2197-2204`). 지운 주소가 `bestAddr`면 `bestAddr`도 비운다(`endpoint.go:547-563`).
3. netmap에서 피어의 disco 키가 바뀌면 신뢰와 진행 중인 Ping·`lastPing`·`lastFullPing`·`lastSendExt`를 지운다. `bestAddr` 주소 자체는 남긴다(`endpoint.go:1719-1727`, `:1694-1697`, `:2294-2310`).

### 4.5 보내기: 경로 선택

WireGuard 데이터그램을 피어에게 보낼 때(`tailscale.com/wgengine/magicsock/endpoint.go:635-652`, `:1107-1206`):

1. `bestAddr`가 있고 `now ≤ trustBestAddrUntil`이면 **UDP `bestAddr`로만** 보낸다.
2. 아니면 UDP `bestAddr`(남아 있으면)와 DERP 주소 **둘 다**로 같은 바이트를 보낸다. 신뢰가 지난 `bestAddr`는 지우지 않고 계속 쓴다(지우는 곳은 4.6 3의 Pong 기한, 4.5 6, 4.4 2, 4.11 2뿐이다).
3. 1이 아니면(직접 경로가 아니거나 신뢰가 지남) 보내기 전에 전체 Ping(4.8 1)을 한다(`endpoint.go:1123-1128`).
4. 둘 다 없으면 그 피어의 패킷을 받은 DERP 지역(역방향 경로)으로 보내고, 그것도 없으면 보내지 못한다(`endpoint.go:1133-1143`, `derp-stun.md` 4.9 3).
5. 외부 송신 활동을 기록하고 heartbeat가 없으면 3초 뒤로 건다(`endpoint.go:1020-1025`, `:1129`).
6. UDP 송신이 `EHOSTUNREACH`면 `bestAddr`와 신뢰를 지우고 그 후보의 측정 상태를 비운다(`endpoint.go:1151-1153`, `:1860-1871`, `tailscale.com/wgengine/magicsock/endpoint_default.go:15-22`). DERP로 모두 보냈으면 UDP 오류가 있어도 성공이다(`endpoint.go:1184-1205`).

### 4.6 Ping 보내기와 Pong 받기

1. 후보 주소로 Ping을 보낼 때(`tailscale.com/wgengine/magicsock/endpoint.go:1356-1419`): 그 후보의 `lastPing`을 지금으로 적고, 새 TxID로 보낸 Ping 표에 넣고 5초 타이머를 건 뒤 Ping을 보낸다. 표에 없는 후보에는 보내지 않는다(CLI Ping 제외). Ping 본문은 `TxID ‖ 자기 node 공개 키`다(`endpoint.go:1309-1317`).
2. 보내기가 실패하면 그 TxID를 표에서 지운다(`endpoint.go:1318-1321`, `:1262-1268`).
3. **5초 기한**(`endpoint.go:1244-1259`): 표에 남아 있으면 지운다. 그 Ping의 주소가 `bestAddr`이고 **그 시각에 신뢰가 이미 지났으면** `bestAddr`·신뢰를 지운다. 그 밖에는 아무것도 바꾸지 않는다(Ping 하나의 유실로 경로를 버리지 않는다).
4. **Pong 받기**(`endpoint.go:1929-2022`):
   1. TxID가 보낸 Ping 표에 없으면 무시한다(다음 피어에 넘긴다, 4.2 3).
   2. 표에서 지우고 지연 = 지금 − 보낸 시각.
   3. DERP로 온 Pong이면 여기서 끝난다(직접 경로로 쓰지 않는다).
   4. UDP로 온 Pong: 보낸 주소(`sp.to`)가 후보 표에 없으면 끝난다. 있으면 Pong의 실제 출발 주소를 이 피어의 주소→피어 표에 넣고, 후보 `sp.to`에 지연을 기록한다.
   5. 후보 `sp.to`(Pong 출발 주소가 아니다)를 `betterAddr`(4.7)로 현재 `bestAddr`와 비교한다. 더 낫거나 현재 신뢰가 지났으면 `bestAddr`로 바꾼다.
   6. `bestAddr`가 `sp.to`면 지연과 시각을 갱신하고 `trustBestAddrUntil = 지금 + 6.5초`.

### 4.7 `betterAddr` (a가 b보다 나은가)

(`tailscale.com/wgengine/magicsock/endpoint.go:2059-2144`)

1. 주소가 같으면 a의 wire MTU가 더 클 때만 낫다.
2. b가 없으면 a가 낫다. a가 없으면 낫지 않다.
3. 직접 경로가 peer relay(Geneve) 경로보다 낫다.
4. 점수: 둘 다 0에서 시작. `a.latency > b.latency`이고 `a.latency > 0`이면 `bPoints = 100 − (b.latency × 100) / a.latency`(정수 나눗셈), 아니고 `b.latency > 0`이면 `aPoints = 100 − (a.latency × 100) / b.latency`. 지연은 나노초 정수다.
5. 주소마다 loopback +50, 아니면 link-local unicast +30, 아니면 사설(RFC 1918·ULA) +20. 따로 IPv6면 +10.
6. `aPoints ≤ 1`이고 `bPoints == 0`이면 낫지 않다. 아니면 `aPoints > bPoints`일 때 낫다.

계산: 같은 기계에서 Go의 엔드포인트가 `127.0.0.1:p`와 LAN 주소 `192.168.x.y:p`로 함께 오면 지연이 비슷한 한 loopback 쪽이 이긴다.

### 4.8 언제 무엇을 보내는가

1. **전체 Ping**(`tailscale.com/wgengine/magicsock/endpoint.go:1423-1459`): `lastFullPing`을 지금으로 적고, 후보마다 지울 것은 지우고, `lastPing`이 5초 안이면 건너뛰고, 나머지에 Ping을 보낸다. 하나라도 보냈고 CallMeMaybe를 보내라는 호출이며 피어의 DERP 주소가 있으면 CallMeMaybe를 예약한다(아래 4).
2. **첫 패킷과 그 뒤 보낼 때마다**: 4.5 3에 따라, 신뢰된 직접 경로가 없는 동안 보내는 패킷마다 전체 Ping(CallMeMaybe 포함)을 부른다. 후보별 5초 제한 때문에 실제 Ping과 CallMeMaybe는 피어당 대략 5초에 한 번이다(계산). discovery Ping은 후보(직접 주소)에만 가고 DERP로는 가지 않는다. DERP로 Ping하는 것은 CLI Ping뿐이다(`endpoint.go:1429-1449`, `:1064-1066`).
3. **heartbeat**(`endpoint.go:872-941`, `:1001-1018`): 외부 송신 활동이 있으면 3초마다 돈다.
   - 마지막 외부 송신 뒤 45초가 지났으면 멈춘다(다음 송신이 다시 건다).
   - `bestAddr`가 있으면(신뢰와 무관하게) 그 주소로 Ping 하나.
   - 다음 중 하나면 전체 Ping: `bestAddr`가 직접 경로가 아님, 전체 Ping을 한 적 없음, 신뢰가 지남, 또는 지연이 5 ms보다 크고 마지막 전체 Ping 뒤 1분이 지남. 지연이 5 ms 이하인 신뢰된 직접 경로면 전체 Ping을 하지 않는다.
   - heartbeat의 전체 Ping도 CallMeMaybe를 예약한다(`endpoint.go:933`).
4. **CallMeMaybe 보내기**(`tailscale.com/wgengine/magicsock/magicsock.go:2693-2732`):
   1. 자기 엔드포인트를 마지막으로 정한 시각(4.9 5)이 27초보다 오래됐으면 지금 보내지 않는다. 엔드포인트 갱신이 끝나면 다시 시도하도록 걸어 두고 ReSTUN을 시작한다.
   2. 새로우면 마지막으로 정한 자기 엔드포인트 주소 전체를 `MyNumber`로 넣어, DERP 주소(피어의 홈 지역)로 피어의 node 키에게, 피어의 disco 키로 봉인해 보낸다. 엔드포인트 종류(`EndpointType`)는 넣지 않는다.
   3. UDP Ping을 먼저 보내 상대 쪽 NAT를 연 뒤 CallMeMaybe가 가야 하지만, Go는 둘을 따로 예약하므로 순서를 보장하지 않는다(`tailscale.com/disco/disco.go:191-198`, `endpoint.go:1448`, `:1457`).
5. **CallMeMaybe 받기**(`endpoint.go:2150-2230`): 4.2 3의 검사를 통과하면, 주소마다(IPv6 link-local 제외) 후보로 넣거나 CallMeMaybe 시각을 갱신하고, 이번 목록에 없는 이전 CallMeMaybe 주소를 지운다(4.4 2). 그리고 **모든 후보의 `lastPing`을 0으로** 해서 5초 제한을 풀고 전체 Ping을 바로 보낸다. 이 전체 Ping은 CallMeMaybe를 다시 보내지 않는다.
6. **받은 Ping에는 Pong만** 보낸다(4.2 4). Ping을 받았다고 되받아 Ping하지는 않는다. 상대 주소는 다음 송신이나 heartbeat 때 후보로 Ping된다.

계산 — Go 피어가 먼저 보낼 때: Swiftail이 엔드포인트를 올리지 않았고 아직 Ping도 보내지 않았다면 Go의 후보 표가 비어 Ping도 CallMeMaybe도 나가지 않고(1의 "하나라도 보냈고"), DERP로만 보낸다. Swiftail이 그 패킷에 응답하며 Ping을 보내면 Go가 출발 주소를 후보로 배워(4.2 4.2) 다음 송신부터 직접 경로를 찾는다.

### 4.9 자기 엔드포인트 알아내기와 올리기

1. **모으기 순서**(`tailscale.com/wgengine/magicsock/magicsock.go:1278-1442`), 중복 주소는 처음 것만:
   1. 포트 매핑(UPnP·NAT-PMP·PCP) 외부 주소 → `EndpointPortmapped`(3). 포트 매퍼가 없으면 건너뛴다.
   2. netcheck의 IPv4 전역 주소들, IPv6 전역 주소들 → `EndpointSTUN`(2). 전역 주소는 IPv4는 첫 STUN 응답의 주소, IPv6는 마지막 응답의 주소이고, 그 밖에 두 번 이상 관측된 주소를 더한다(`tailscale.com/net/netcheck/netcheck.go:137-167`, `:705-733`). loopback 주소를 거르지 않는다.
   3. 목적지에 따라 IPv4 매핑이 달랐고(`MappingVariesByDestIP`) 고정 로컬 포트가 설정됐으면 `(첫 IPv4 전역 IP, 로컬 포트)` → `EndpointSTUN4LocalPort`(4).
   4. 디버그용 가짜 주소 → `EndpointExplicitConf`(5). 클라우드 메타데이터의 공인 IP + 소켓 포트 → `EndpointLocal`(1).
   5. 5분 10초 동안 이전에 광고한 주소를 다시 더한다(같은 IP당 6개까지) (`tailscale.com/wgengine/magicsock/endpoint_tracker.go:18-22`, `:37`, `:117`).
   6. 사용자 고정 엔드포인트 → `EndpointExplicitConf`(5).
   7. IPv4 소켓이 와일드카드에 묶였으면 인터페이스 주소마다 `(IP, IPv4 소켓 포트)` → `EndpointLocal`(1). IPv6 주소에도 IPv4 소켓의 포트를 붙인다. 일반 주소가 없고 앞에서 모은 것도 없을 때만 loopback 주소를 쓴다. 특정 IP에 묶였으면 그 주소 하나(`magicsock.go:1406-1426`).
2. **유형 값**: 0 unknown, 1 local, 2 STUN, 3 portmapped, 4 STUN4LocalPort, 5 explicit (`tailscale.com/tailcfg/tailcfg.go:1392-1397`). Go 피어가 상대의 유형을 쓰는 곳은 찾지 못했다(8절).
3. **STUN**: 지역의 DERP 노드 STUN 포트로 같은 UDP 소켓에서 보낸다(3.7, `derp-stun.md` 4.10). 받은 응답의 주소가 위 2의 전역 주소다.
4. **제어 서버에 올리기**: 바뀐 목록을 `MapRequest.Endpoints`(주소)와 같은 순서의 `EndpointTypes`(유형)로, `DiscoKey`·`Hostinfo`와 함께 `Stream=false, OmitPeers=true`인 맵 요청으로 보낸다. 바뀌었을 때만 보낸다(`tailscale.com/control/controlclient/auto.go:888-896`, `tailscale.com/control/controlclient/direct.go:1052-1099`, `docs/contracts/SwiftailControl.md` 상태 올리기). Version ≥ 68의 스트림 요청에 넣은 값은 서버가 무시할 수 있다(`tailcfg.go:1494-1498`). testcontrol은 non-stream 요청을 받을 때마다 노드의 `Endpoints`·`DiscoKey`·`Cap`(= 요청의 `Version`)을 **요청 값으로 통째로 덮는다**. 그러므로 상태를 올리는 요청마다 현재 `DiscoKey`와 엔드포인트 전체를 넣어야 한다. IPv6 link-local과 zone 있는 주소는 거른다(`tailscale.com/tstest/integration/testcontrol/testcontrol.go:1452-1497`, `:1941-1962`).
5. **시점**(`magicsock.go:887-989`, `:3683-3712`, `:3720-3753`): 엔드포인트 갱신(= netcheck + 위 모으기)은 ReSTUN이 부른다. 끝날 때마다 "마지막으로 정한 시각"을 갱신하고(목록이 같아도), 목록이 바뀌었을 때만 위 4로 올린다. 다음 경우에 반복한다: 활성 상태면 20–26초 무작위 간격. 네트워크가 내려갔거나 홈이 없거나 피어가 없거나 node 키가 없으면 멈추고, 45초 넘게 유휴면 멈춘다. 그 밖에 DERPMap 변경, node 키 설정, 포트 매핑 변경, 고정 엔드포인트 변경, 링크 변경, 오래된 엔드포인트로 CallMeMaybe를 보내려 할 때(4.8 4) ReSTUN한다(`tailscale.com/wgengine/magicsock/derp.go:875`, `magicsock.go:1005`, `:2717`, `:3714`, `tailscale.com/wgengine/userspace.go:1218-1224`). DERPMap이 없고 STUN 결과도 없는 목록은 올리지 않는다(`magicsock.go:964-976`).
6. **홈 DERP**: netcheck 결과로 홈을 고르는 규칙은 `derp-stun.md` 4.10 5와 4.8이다. magicsock에서는 그 결과가 `NetInfo.PreferredDERP`가 되어 맵 요청에 실리고(`magicsock.go:1075`), 제어 서버가 다른 노드에게 이 노드의 `HomeDERP`로 내려주며, 다른 노드는 그것을 이 노드의 DERP 주소로 쓴다(4.4).
7. **`NetInfo`의 다른 필드**(`MappingVariesByDestIP`, `WorkingUDP`, `WorkingIPv6`, `DERPLatency`, `HavePortMap` 등, `magicsock.go:1054-1078`): wgengine·magicsock·ipnlocal에서 **피어의** NetInfo를 읽는 곳이 없다(`grep NetInfo()` 결과 없음). Go 피어의 경로 동작에 영향을 주는 것은 `PreferredDERP`(→ `HomeDERP`)뿐이다.

### 4.10 disco 키가 바뀔 때와 TSMP 광고

1. **Go가 보내는 TSMP 광고**: Tailscale 포크 wireguard-go는 세션 키가 생길 때 "priority message"를 터널 안으로 하나 보낸다. 시작한 쪽은 핸드셰이크 응답을 받았을 때, 응답한 쪽은 새 키로 된 첫 transport를 받았을 때다(`wireguard-go/device/receive.go:416`, `:483`, `wireguard-go/device/send.go:111-140`). Go는 이 메시지로 3.8의 광고를 만든다. 조건은 자기 disco 키가 있고, 피어가 WireGuard 전용이 아니고, 피어의 첫 주소와 같은 주소 계열의 자기 Tailscale 주소가 있는 것이다. 상대의 CapabilityVersion은 보지 않는다(`tailscale.com/wgengine/magicsock/magicsock.go:4631-4676`, `tailscale.com/ipn/ipnlocal/local.go:645`). 그러므로 Swiftail은 WireGuard 세션이 설 때마다 이 패킷을 받는다.
2. **Go가 받았을 때**: TSMP 광고는 앱으로 올리지 않는다(`tailscale.com/net/tstun/wrap.go:1133-1146`). 키가 0이 아니고 이전에 TSMP로 배운 키와 다르면 그 피어의 "TSMP 키"로 저장하고 활성 키로 삼으며, 활성 키가 바뀌면 4.4 3처럼 신뢰와 진행 중인 Ping을 지운다(`magicsock.go:4579-4622`, `tailscale.com/wgengine/userspace.go:608-623`, `tailscale.com/wgengine/magicsock/endpoint.go:1595-1620`). netmap 키와 TSMP 키 가운데 하나만 활성이고, 비활성 키로 온 disco 메시지를 받으면 활성을 그 키로 바꾼다(`tailscale.com/wgengine/magicsock/endpoint.go:386-392`, `:1645-1688`).
3. **Swiftail이 보내야 하는가**: 아니다. Go는 netmap의 `DiscoKey`로 Swiftail의 disco 메시지를 연다(4.2 1). 광고는 netmap보다 빨리 새 키를 알리는 보조 수단이다(`tailscale.com/tailcfg/tailcfg.go:195`). 받는 쪽은 M3 계약처럼 소비하고 올리지 않으면 된다(`docs/contracts/SwiftailEngine.md` TSMP 줄).
4. **자기 disco 키**: Swiftail은 시작마다 새 disco 키를 만든다(`docs/contracts/SwiftailEngine.md` 시작 1). 새 키는 4.9 4의 요청으로 올라가고 Go 피어의 맵에 반영될 때까지 Go는 Swiftail의 disco 메시지를 버린다(4.2 1). 그동안도 DERP 데이터는 흐른다(4.5 2).

### 4.11 네트워크 변경

Go의 동작(`tailscale.com/wgengine/userspace.go:1207-1224`, `tailscale.com/wgengine/magicsock/magicsock.go:3777-3926`):

1. 링크 변경: 네트워크 상태를 갱신한다. 올라가 있고 큰 변경(재결속이 필요해 보임)이면 Rebind 뒤 ReSTUN, 작은 변경이면 ReSTUN만 한다. 내려갔으면 DERP를 닫고 아무것도 하지 않는다(`magicsock.go:2755-2773`).
2. Rebind: UDP 소켓을 닫고 새로 묶는다. 포트 우선순위는 설정 포트 → 현재 포트 → 0(OS가 고름). IPv6 실패는 무시하고 IPv4 실패만 오류다. 그 뒤 모든 피어의 `bestAddr`·신뢰를 지우고 후보마다 Ping 기록을 비운다(`magicsock.go:3800-3807`, `:3880-3926`, `tailscale.com/wgengine/magicsock/endpoint.go:1876-1885`). DERP 연결의 로컬 주소가 기본 인터페이스 주소가 아니면 닫고, 맞으면 3초 안의 DERP Ping으로 확인한다(`tailscale.com/wgengine/magicsock/derp.go:905-950`).
3. 송신 오류가 broken pipe·`EPERM`이면 5초에 한 번까지 Rebind + ReSTUN한다(`magicsock.go:1612-1625`, `tailscale.com/wgengine/magicsock/magicsock_notplan9.go:17-33`). `EHOSTUNREACH`는 4.5 6이다.

M4 관문에 필요한 것: 없다. "직접 경로를 막으면 DERP로, 풀면 직접으로"는 소켓이나 주소가 바뀌지 않는 상황이며 4.5·4.6·4.8의 신뢰 만료·Pong 기한·heartbeat만으로 일어난다(7.2 3). M5로 미루는 것: 링크 변경 감지, Rebind, 주소 변경 뒤 ReSTUN, 오류 시 Rebind, DERP 연결의 재확인, iOS 인터페이스 결속.

### 4.12 Go 피어가 상대에게 기대하는 것: peer relay와 peer MTU

**peer relay**: Go는 상대의 `Node.Cap`(CapabilityVersion)이 121 이상이면 relay를 쓸 줄 안다고 본다(`tailscale.com/wgengine/magicsock/magicsock.go:2921-2923`, `tailscale.com/wgengine/magicsock/endpoint.go:1759`). 별도 capability나 확인 메시지는 없다. 그래도 Swiftail이 148을 선언하고 relay를 구현하지 않아 직접 경로나 DERP 경로가 깨지는 곳은 없다. 근거:

1. relay 경로 찾기는 netmap에 relay 서버 후보가 있어야만 한다. 후보는 CapabilityVersion ≥ 121이고 패킷 필터가 `tailscale.com/cap/relay-target` peer capability를 준 노드다(`magicsock.go:2977-2998`, `tailscale.com/tailcfg/peercap/peercap.go:57-60`, `endpoint.go:960-971`). testcontrol의 기본 맵에는 이런 권한이 없다(8절에 확인 범위).
2. relay 찾기는 신뢰된 직접 경로가 있으면 하지 않는다(`endpoint.go:975-977`). 직접 경로 찾기(4.8)와 DERP 송신(4.5 2)은 relay와 무관하게 그대로 돈다.
3. Go가 Swiftail에게 보낼 수 있는 relay 메시지는 DERP로 오는 `CallMeMaybeVia`(0x07)와, Swiftail이 relay 서버 후보일 때의 `AllocateUDPRelayEndpointRequest`(0x08)다(`magicsock.go:2437`, `:2445-2536`). Swiftail이 버리면 Go 쪽 relay 핸드셰이크와 할당이 시간 초과로 끝난다(할당 대기 10초, 핸드셰이크 `min(BindLifetime, 30초)`) (`tailscale.com/wgengine/magicsock/relaymanager.go:1036`, `:928-932`). 이 동안에도 직접·DERP 경로는 영향을 받지 않는다(2).
4. Geneve로 감싼 패킷은 relay 서버를 거쳐서만 오며, 서버는 양쪽이 Bind를 마친 뒤에만 넘긴다(`tailscale.com/net/udprelay/server.go:289-310`, `:344-348`). Swiftail이 Bind하지 않으므로 오지 않는다. 와도 4.1 2로 알아보고 버린다.

결론: 무시해도 된다. 받은 0x04–0x09와 Geneve는 버린다. Swiftail을 relay 서버로 쓰지 않는다(그런 권한을 주지 않는다).

**peer MTU**: Go는 경로 MTU 측정이 켜져 있을 때만 패딩 Ping(wire MTU 1280, 1360, 1400, 1500, 8000, 9000에서 IPv4 28바이트, IPv6 48바이트를 뺀 UDP 본문 길이)을 보낸다(`endpoint.go:1379-1394`, `:1910-1923`, `tailscale.com/net/tstun/mtu.go:85-92`). 기본은 꺼져 있고 iOS 빌드에는 없다(`tailscale.com/wgengine/magicsock/peermtu.go:38-56`, `tailscale.com/wgengine/magicsock/peermtu_stubs.go:4`, `:14-20`). Swiftail은 패딩 Ping을 3.4대로 파싱해 보통 Pong(110바이트)으로 답하면 된다. 측정을 하지 않는다.

## 5. 상수와 타이머

| 이름 | 값 | 쓰임 | 출처 (`tailscale.com/`) |
| --- | --- | --- | --- |
| nonce | 24바이트 | 3.1 | `disco/disco.go:40` |
| 겉 형식 최소(분류) | 38바이트 | 4.1 3, 4.3 | `wgengine/magicsock/magicsock.go:2103` |
| `pingTimeoutDuration` | 5초 | Pong 기한(4.6 3) | `wgengine/magicsock/magicsock.go:4119`, `tsconst/ping.go:11` |
| `discoPingInterval` | 5초 | 후보별 Ping 최소 간격. CallMeMaybe 받기가 풀어 준다 | `wgengine/magicsock/magicsock.go:4125`, `tsconst/ping.go:15` |
| `heartbeatInterval` | 3초 | heartbeat 주기 | `wgengine/magicsock/magicsock.go:4099` |
| `trustUDPAddrDuration` | 6.5초 | Pong 뒤 UDP 단독 송신 기간 | `wgengine/magicsock/magicsock.go:4103` |
| `sessionActiveTimeout` | 45초 | heartbeat·주기 STUN 멈춤, Ping으로 배운 후보 만료 | `wgengine/magicsock/magicsock.go:4083` |
| `goodEnoughLatency` | 5 ms | 이하면 개선용 전체 Ping 생략 | `wgengine/magicsock/magicsock.go:4107` |
| `upgradeUDPDirectInterval` | 1분 | 느린 직접 경로의 개선 전체 Ping | `wgengine/magicsock/magicsock.go:4087` |
| `endpointsFreshEnoughDuration` | 27초 | CallMeMaybe 전 자기 엔드포인트 신선도 | `wgengine/magicsock/magicsock.go:4112` |
| 주기 ReSTUN | 20–26초 무작위 | 4.9 5 | `wgengine/magicsock/magicsock.go:904` |
| 후보 정리 문턱 | 100개 초과 | 4.4 2 | `wgengine/magicsock/endpoint.go:1835` |
| `pongHistoryCount` | 64 | 후보별 Pong 기록. 비교에는 최신 값만 쓴다 | `wgengine/magicsock/endpoint.go:490`, `:525-530` |
| `endpointTrackerLifetime` / 주소당 | 5분 10초 / 6 | 4.9 1.5 | `wgengine/magicsock/endpoint_tracker.go:22`, `:37` |
| relay 할당 대기 / 핸드셰이크 상한 | 10초 / 30초 | 4.12 3 | `wgengine/magicsock/relaymanager.go:1036`, `:928-932` |
| relay 찾기 최소 간격 / 개선 | 30초 / 1분 | 4.12 | `wgengine/magicsock/magicsock.go:4095`, `:4091` |
| 오류 Rebind 간격 | 5초 | 4.11 3 | `wgengine/magicsock/magicsock.go:1618` |
| Rebind 뒤 DERP Ping 대기 | 3초 | 4.11 2 | `wgengine/magicsock/derp.go:923` |

## 6. Swiftail에 필요한 최소 부분과 생략할 수 있는 부분 (M4)

### 6.1 루프백·LAN 관문에 꼭 필요한 것

1. UDP 소켓 하나(IPv4, 와일드카드, OS가 고른 포트)와 4.1의 분류. 받은 소켓으로 답한다.
2. disco 겉 형식·암호(3.1, 3.2)와 Ping·Pong·CallMeMaybe 코덱(3.3, 3.4). 피어 disco 키별 공유 키 캐시.
3. 받은 Ping에 Pong(4.2 4): UDP는 출발 주소로, DERP는 DERP로. UDP Ping의 출발 주소를 후보에 넣는다. 같은 후보의 같은 TxID는 Pong하지 않는다.
4. 피어별 후보·보낸 Ping 표·`bestAddr`·신뢰(4.4, 4.6)와 `betterAddr`(4.7).
5. 경로 선택(4.5 1–4): 신뢰된 `bestAddr`면 UDP만, 아니면 UDP `bestAddr` + DERP.
6. 전체 Ping과 heartbeat(4.8 1–3): 5초 후보 제한, 5초 Pong 기한, 3초 heartbeat, 45초 유휴, 6.5초 신뢰. **값을 Go와 같게 한다.** Go 피어의 하강·복귀 시점이 이 값들로 정해지고 관문이 그것을 본다.
7. CallMeMaybe 받기(4.8 5)와 보내기(4.8 4). 루프백·LAN만이면 Ping으로 배우는 주소(4.8 6)로도 경로가 서지만, NAT 뒤 기기와의 M4 마무리 관문에는 필요하다.
8. 자기 엔드포인트: STUN(같은 소켓, 홈 지역 노드)과 인터페이스 주소를 모아 `EndpointSTUN`·`EndpointLocal`로 올린다(4.9 1의 2·7, 4). 바뀌었을 때와 20–26초 주기(활성일 때). 올릴 때마다 `DiscoKey`도 넣는다.
9. DERP로 온 disco를 4.2로 넘긴다(4.3). M3 계약의 "알아보고 버린다"를 바꾼다.

### 6.2 생략할 수 있는 것

| 항목 | 근거 |
| --- | --- |
| peer relay(0x04–0x09, Geneve) 송신·처리 | 4.12. 받으면 버린다 |
| 경로 MTU 측정 | 4.12. 기본 꺼짐, iOS에 없음 |
| 포트 매핑(UPnP·NAT-PMP·PCP) | 선택 기능이다(4.9 1.1). 시험 도구도 끈다(`Tools/interop/cmd/tailnet/main.go:60`) |
| `EndpointSTUN4LocalPort`, 클라우드 메타데이터, 5분 10초 광고 캐시 | 단단한 NAT·클라우드용 보강이다(4.9 1.3–1.5). 루프백·LAN에 쓰이지 않는다 |
| TSMP 광고 보내기, TSMP 키 활성 전환 | 4.10 3. 받은 광고는 지금처럼 소비만 한다 |
| 주소→피어 표 | 4.1. WireGuard 장치가 피어를 알려 준다 |
| IPv6 소켓·IPv6 엔드포인트 | 관문은 IPv4로 된다. Go는 IPv6 로컬 주소에도 IPv4 포트를 붙이므로(4.9 1.7) 넣을 때는 두 소켓을 같은 포트에 묶는다(구현 제안) |
| Rebind·링크 변경·오류 시 재결속 | 4.11. M5 |
| Pong 기록 64개, UDP 수명 측정, 고정 엔드포인트 | 비교에는 최신 지연만 쓴다(`tailscale.com/wgengine/magicsock/endpoint.go:525-530`). 나머지는 설정할 때만 켜지는 기능이다(`endpoint.go:1709-1716`) |
| 역방향 DERP 지역(홈이 0인 피어) | M3 계약대로 한다(`derp-stun.md` 4.9 3) |

### 6.3 총괄이 계약에서 정할 것

| 결정 | 선택지 | 권고 |
| --- | --- | --- |
| UDP 소켓 | IPv4 하나 / IPv4+IPv6 둘(Go) / 이중 스택 하나 | IPv4 하나. 이중 스택이면 받은 주소를 unmap해야 하고 Go와 표가 달라진다 |
| 타이머 값 | Go와 같게 / 시험용으로 줄임 | Go와 같게. 시험에서 시계를 주입할 수 있게 한다(M3 엔진 계약의 시각 인자 방식) |
| 홈 지역 | M3처럼 고정 / netcheck로 선택 | STUN은 엔드포인트에 필요하므로 넣고, 홈 선택은 `derp-stun.md` 4.10 5 규칙으로 넣는다. 시험 지역이 하나라 관문 결과는 같다 |
| 올릴 엔드포인트 | local+STUN / Go 전체 | local+STUN. 관문 시험에서 Go 엔드포인트의 loopback이 STUN에서 나오므로 충분하다(7절) |
| CapabilityVersion | 148 유지 / 121 미만으로 낮춤 | 148 유지(4.12). 낮추면 다른 서버 동작이 바뀔 수 있다(`docs/plan.md` 위험 13) |
| relay·Geneve 메시지 | 버림 / 오류로 끊음 | 버림. 끊으면 Go 피어가 정상적으로 보낸 메시지로 경로가 깨진다 |
| TSMP 광고 | 보내지 않음 / 보냄 | 보내지 않음(4.10 3) |
| 직접 경로 차단 시험 수단 | Swift 쪽 시험용 UDP 거르개 / 도구의 Go 디버그 노브 / 둘 다 | 둘 다(7절 3). 거르개는 시험 대상 내부가 아니라 소켓 경계에 둔다 |
| 경로 조회 API (`path(toPeerNamed:)`) | `bestAddr`+신뢰 여부 / Go의 `curAddr` 의미 | Go의 `curAddr`과 같은 의미(신뢰된 직접 주소, 아니면 DERP)로 맞춘다(`tailscale.com/wgengine/magicsock/endpoint.go:2246-2252`) |

## 7. 상호 운용 시험에서 확인할 것

### 7.1 `tailnet` 환경에서 일어나는 일

- STUN 서버는 `127.0.0.1`에, DERP 지역은 하나(ID 1, 코드 `test`)다(`Tools/interop/cmd/tailnet/main.go:66-90`, `derp-stun.md` 7.1). 포트 매퍼는 꺼져 있다(`main.go:60`).
- 계산: Go tsnet 피어는 와일드카드 소켓에서 `127.0.0.1`의 STUN 서버로 묻으므로 STUN 결과가 `127.0.0.1:<Go 포트>`이고, netcheck가 loopback을 거르지 않아 이것이 `EndpointSTUN`으로 올라간다(4.9 1.2). 그 밖에 기계의 LAN 주소들이 `EndpointLocal`로 같은 포트에 붙는다(4.9 1.7). Swiftail도 같은 방식이면 `127.0.0.1:<Swiftail 포트>`를 올리게 된다. 그러므로 루프백 시험에 고정 엔드포인트가 필요 없다.
- testcontrol은 Swiftail의 맵 요청 `Version`을 그대로 `Node.Cap`으로, `Endpoints`·`DiscoKey`를 그대로 노드에 넣는다(4.9 4). 패킷 필터 capability를 주지 않으므로 relay 후보가 없다(4.12 1).
- `peerStatus`의 `curAddr`는 Go가 그 피어로 **신뢰된 직접 경로만** 쓸 때의 주소이고, DERP를 함께 쓰거나 DERP만 쓰면 빈 문자열이다. `relay`는 그 피어의 홈 DERP 지역 코드(`test`)로, 지금 DERP를 쓰는지와 무관하다(`tailscale.com/wgengine/magicsock/endpoint.go:2232-2253`). `curAddr`는 Go가 그 피어에게 보낸 적이 있어야 채워진다(`endpoint.go:2238-2240`).
- `peerPing` `type=disco`: 신뢰된 직접 경로가 있으면 그 주소와 DERP로, 없으면 DERP와 모든 후보로 Ping하고 **먼저 온 Pong**으로 답한다. 직접 Pong이면 `Endpoint`, DERP Pong이면 `DERPRegionID`·`DERPRegionCode`가 채워진다. CLI Ping도 외부 송신 활동으로 쳐 heartbeat를 시작한다(`endpoint.go:1044-1099`, `:1400-1402`, `tailscale.com/wgengine/magicsock/magicsock.go:1208-1221`).

### 7.2 확인 항목

1. **코덱·암호(Swift 단위 시험)**: Go `disco.Ping/Pong/CallMeMaybe.AppendMarshal`과 같은 바이트, 3.3 표의 길이·version 경계(CallMeMaybe 17·19바이트, version 1 → 주소 0개; Pong 29바이트 → 버림; Ping 12·44·45바이트, 0 NodeKey), IPv4-mapped 주소, nonce를 고정한 봉인 결과를 Go와 비교(nonce 주입은 Go 쪽 시험 도구가 필요하다). 변조한 nonce·tag·공개 키, 모르는 disco 키, 38–61바이트 disco가 상태를 바꾸지 않는다.
2. **직접 경로 성립(관문)**: Swiftail과 Go 피어(`addPeer`) 사이에 UDP 에코를 주고받은 뒤, Go `peerStatus`의 Swiftail 항목 `curAddr`가 Swiftail이 올린 엔드포인트 가운데 하나(기대: `127.0.0.1:<Swiftail 포트>`, 4.7 계산)이고, Swiftail의 경로 조회도 직접 주소를 낸다. Swift→Go 먼저 보내기와 Go→Swift 먼저 보내기(Go `peerPing` `type=ICMP` 또는 `TSMP`로 시작)를 둘 다 한다.
3. **막기와 풀기(관문)**: 두 가지 수단으로 한다.
   - Swift 쪽 거르개(권고): Swiftail의 UDP 소켓 경계에서 Go 피어 포트와 주고받는 데이터그램을 모두 버린다. 계산된 기대: 마지막 Pong 뒤 6.5초에 양쪽 신뢰가 지나 UDP + DERP 이중 송신으로 바뀌고, 그 뒤 기한이 지난 heartbeat Ping(5초 기한)이 `bestAddr`를 지워(4.6 3) DERP만 남는다. Go `curAddr`는 신뢰가 지나는 시점부터 빈 문자열이다. 그동안 UDP 에코가 DERP로 계속 된다. 거르개를 풀면 다음 송신·heartbeat의 전체 Ping(5초 제한 안)과 Pong으로 `curAddr`가 돌아온다.
   - Go 쪽 노브: 도구에 `setNeverDirectUDP {enabled}` 명령을 더해 `envknob.Setenv("TS_DEBUG_NEVER_DIRECT_UDP", "true"/"false")`를 부른다. 켜면 Go가 UDP Ping에 답하지 않고 직접 Ping과 CallMeMaybe를 보내지 않는다(`tailscale.com/wgengine/magicsock/debugknobs.go:65-68`, `magicsock.go:2606-2608`, `endpoint.go:1360-1362`, `:1424-1426`, `tailscale.com/envknob/envknob.go:94-108`). Go는 기한 처리할 Ping이 없어 `bestAddr`를 지우지 않으므로 UDP 데이터는 계속 이중으로 흐른다. 확인할 것은 Swiftail이 Pong을 못 받아 UDP + DERP로 내려가고 Go `curAddr`가 비는 것, 끄면 둘 다 직접으로 돌아오는 것이다. 노브는 도구 프로세스의 모든 Go 피어에 걸린다.
4. **CallMeMaybe**: Swiftail이 엔드포인트를 올리기 전에 Go가 먼저 보내게 해(4.8 계산) Swiftail의 응답 Ping으로 경로가 서는지, Swiftail이 보낸 CallMeMaybe를 Go가 받아 즉시 Ping하는지(Go 디버그 로그 또는 Swift 쪽 수신 시각). 27초 넘게 엔드포인트를 갱신하지 않은 뒤의 CallMeMaybe가 ReSTUN 뒤에 나가는지(4.8 4.1)는 Swift 단위 시험으로 본다.
5. **유휴**: 45초 동안 보내지 않으면 Swiftail의 heartbeat가 멈추고, 다시 보내면 전체 Ping부터 한다(4.8 3).
6. **TSMP 광고**: 세션이 설 때 Go가 보낸 3.8 패킷을 Swiftail이 소비하고 앱으로 올리지 않는다(M3 계약과 같다).
7. **relay 무시**: Go가 relay 메시지를 보내게 하려면 relay 서버와 capability 부여가 필요해 이 도구로는 만들 수 없다. 대신 Swift 단위 시험에서 0x04–0x09와 Geneve 패킷이 상태를 바꾸지 않음을 본다.

도구에 더하자고 제안하는 것: 위 `setNeverDirectUDP`, 그리고 `peerStatus`에 Go 노드 자신의 엔드포인트 목록(`Status.Self.Addrs`, `magicsock.go:4026-4028`)과 피어별 `active`·`lastWrite`(`endpoint.go:2243-2244`)를 더하면 Go 포트와 heartbeat 상태를 직접 볼 수 있다.

## 8. 확인하지 못한 것

- 실행 결과가 아니다. 7절의 기대 시점(6.5초 뒤 이중 송신, 기한 Ping 뒤 DERP 단독, 복귀 시점)과 `tailnet`에서 Go의 STUN 엔드포인트가 `127.0.0.1:<포트>`가 된다는 것은 코드에서 계산했다.
- Go 피어가 상대의 `EndpointTypes`를 쓰는 곳은 wgengine·magicsock에서 찾지 못했다. 운영 제어 서버가 유형이나 loopback 엔드포인트를 어떻게 다루는지(거르는지, 다른 노드에게 그대로 내려주는지)는 공개 소스에 없다.
- testcontrol 기본 맵의 패킷 필터에 `tailscale.com/cap/relay-target` capability가 없다는 것은 `tailnet` 도구가 필터나 capability를 설정하지 않는다는 데서 끌어냈다(`Tools/interop/cmd/tailnet/main.go:90`). testcontrol의 기본 필터 내용 자체는 확인하지 않았다.
- `envknob.Setenv`로 노브를 실행 중에 바꾸는 것은 잠금 없이 읽히는 값을 바꾼다(`tailscale.com/envknob/envknob.go:165-176`). 시험 도구에서의 경쟁 영향은 실행해 보지 않았다.
- 운영 tailnet에서 relay 서버가 있을 때 Go 피어가 Swiftail에게 `CallMeMaybeVia`를 보내고 시간 초과하는 동안의 실제 지연·로그는 보지 않았다(M4 마무리 관문에서 관찰).
- 실제 NAT(한쪽·양쪽, 단단한 NAT)에서의 직접 경로 성공 여부와 iOS·macOS 소켓 결속(`IP_BOUND_IF` 등, `tailscale.com/net/netns/netns_darwin.go:295`)의 Swift 쪽 동등성. M4 마무리와 M5에서 확인한다.
