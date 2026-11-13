# disco와 magicsock: M4 직접 경로 구현 명세

## 1. 머리말

- 기준 소스: `tailscale.com` v1.104.6, `CurrentCapabilityVersion=148`. 이 노트에서 버전은 disco의 `messageVersion`과 제어 프로토콜의 `CapabilityVersion`을 구별한다. (`tailscale.com/tailcfg/tailcfg.go:200`, `tailscale.com/disco/disco.go:17`, `tailscale.com/tailcfg/tailcfg.go:1437`)
- 작성 모델: GPT-6.1-sol. 검증 상태: 지정 소스를 직접 대조해 작성했으며, 다른 제공자 모델의 독립 검증과 Swift↔Go 실행 시험은 하지 않았다.
- 아래의 **구현 제안**, **시험 항목**, **미확인**은 작성자의 설계·검증 범위이며 Go의 보장으로 읽지 않는다. 그 밖의 동작 설명에는 모듈 루트 기준 출처를 붙였다.

## 2. 범위

다루는 것은 disco 직렬화·암호화 경계, UDP 수신 분류, 피어와 주소의 대응, 직접 경로 선택·유지·복구, DERP와의 병행, 자기 엔드포인트 발견·광고, 재결속, WireGuard 접점이다. peer relay와 peer MTU 탐색은 와이어 식별과 생략 판단에 필요한 수준까지 다룬다. (`tailscale.com/disco/disco.go:6`, `tailscale.com/wgengine/magicsock/magicsock.go:1849`, `tailscale.com/wgengine/magicsock/endpoint.go:635`, `tailscale.com/wgengine/magicsock/relaymanager.go:886`, `tailscale.com/wgengine/magicsock/peermtu.go:36`)

제어 연결의 인증·전체 netmap 형식, DERP 프레임 전체, WireGuard의 Noise·재전송·replay window 자체는 범위 밖이다. 이 모듈은 그 경계에서 `MapRequest`, `derphttp.Client.Send`, `conn.Bind` 및 외부 `wireguard-go/device`를 사용한다. (`tailscale.com/control/controlclient/direct.go:1092`, `tailscale.com/wgengine/magicsock/derp.go:696`, `tailscale.com/wgengine/magicsock/magicsock.go:3509`)

## 3. 와이어 형식

### 3.1 disco 외피와 암호 연산

아래 오프셋은 Geneve 없는 UDP 데이터그램 또는 DERP가 운반한 disco 데이터의 시작 기준이다. (`tailscale.com/disco/disco.go:6`, `tailscale.com/wgengine/magicsock/magicsock.go:2027`, `tailscale.com/wgengine/magicsock/derp.go:747`)

| 오프셋 | 길이 | 필드 | 인코딩·의미 | 출처 |
| --- | --- | --- | --- | --- |
| 0 | 6 | `Magic` | `54 53 f0 9f 92 ac` (`TS💬`) | `tailscale.com/disco/disco.go:34` |
| 6 | 32 | `senderDiscoPub` | 보낸 쪽 disco 공개 키의 raw bytes | `tailscale.com/disco/disco.go:10`, `tailscale.com/wgengine/magicsock/magicsock.go:2041` |
| 38 | 24 | `nonce` | 매 Seal마다 무작위 24바이트 | `tailscale.com/types/key/disco.go:219` |
| 62 | `16 + L` | NaCl box 출력 | `L`바이트 평문을 `box.SealAfterPrecomputation`으로 봉인한 결과; 인증자 크기 16 | `tailscale.com/types/key/disco.go:225`, `tailscale.com/wgengine/magicsock/endpoint.go:1294` |

1. disco 비밀 키는 무작위 32바이트를 생성한 뒤 `b[0] &= 248`, `b[31] = (b[31] & 127) | 64`로 clamp한다. 공개 키는 `curve25519.ScalarBaseMult`의 32바이트 출력이다. (`tailscale.com/types/key/disco.go:36`, `tailscale.com/types/key/disco.go:65`, `tailscale.com/types/key/util.go:51`)
2. 자기 disco 비밀 키와 상대 disco 공개 키를 입력으로 `box.Precompute`를 수행해 32바이트 `DiscoShared`를 만든다. 이는 단순히 node key를 재사용하는 경로가 아니다. (`tailscale.com/types/key/disco.go:76`, `tailscale.com/types/key/disco.go:202`, `tailscale.com/wgengine/magicsock/magicsock.go:580`, `tailscale.com/wgengine/magicsock/magicsock.go:2742`)
3. 평문 `P = type || version || payload`, 새 무작위 nonce `N`, 위 shared key `K`로 `box.SealAfterPrecomputation`을 호출한다. `DiscoShared.Seal(P)`의 반환값은 `N || box(P,N,K)`이므로 외피 조립 시 nonce를 다시 붙이지 않는다. magic·공개 키를 별도 AAD로 넘기는 인자는 없다. (`tailscale.com/disco/disco.go:125`, `tailscale.com/types/key/disco.go:219`, `tailscale.com/wgengine/magicsock/magicsock.go:2041`)
4. 수신자는 외피 공개 키가 알려진 피어인지 먼저 확인하고, offset 38부터를 `DiscoShared.Open`에 전달한다. Open은 앞 24바이트를 nonce로, 나머지를 box 입력으로 사용하며 실패 시 폐기한다. 복호화 후 파싱 실패도 폐기한다. (`tailscale.com/wgengine/magicsock/magicsock.go:2234`, `tailscale.com/wgengine/magicsock/magicsock.go:2267`, `tailscale.com/types/key/disco.go:231`, `tailscale.com/wgengine/magicsock/magicsock.go:2295`)

**구현 제안:** Swift 암호 계층의 계약은 위 NaCl box API와 동일하게 둔다. 단순 Curve25519 공유 출력만으로 다른 AEAD를 조합하지 않는다. 허용 소스에는 `golang.org/x/crypto/nacl/box` 내부가 없으므로 그 내부 KDF·스트림 암호·태그 위치의 독립 명세는 §8의 미확인 사항이다. 호출 계약의 근거는 `box.Precompute`와 `SealAfterPrecomputation`/`OpenAfterPrecomputation` 호출이다. (`tailscale.com/types/key/disco.go:82`, `tailscale.com/types/key/disco.go:225`, `tailscale.com/types/key/disco.go:239`)

### 3.2 공통 평문 헤더와 타입 목록

이후 모든 **페이로드 오프셋**은 복호화한 평문의 2바이트 헤더 뒤를 0으로 센다. 송신기는 아래 9종 모두 `version=0`을 사용한다. (`tailscale.com/disco/disco.go:56`, `tailscale.com/disco/disco.go:125`, `tailscale.com/disco/disco.go:161`, `tailscale.com/disco/disco.go:222`, `tailscale.com/disco/disco.go:263`, `tailscale.com/disco/disco.go:405`, `tailscale.com/disco/disco.go:427`, `tailscale.com/disco/disco.go:448`, `tailscale.com/disco/disco.go:480`, `tailscale.com/disco/disco.go:517`, `tailscale.com/disco/disco.go:644`)

| 평문 오프셋 | 길이 | 필드 | 인코딩 | 출처 |
| --- | --- | --- | --- | --- |
| 0 | 1 | `messageType` | 아래 표의 값 | `tailscale.com/disco/disco.go:44` |
| 1 | 1 | `messageVersion` | 송신은 0; 수신 검사는 타입별로 다름 | `tailscale.com/disco/disco.go:85`, `tailscale.com/disco/disco.go:56` |
| 2 | 가변 | `message-payload` | 아래 타입별 표 | `tailscale.com/disco/disco.go:85` |

| 타입 | 값 | v0 페이로드 길이 | Go 파서의 버전·길이 처리 | 출처 |
| --- | --- | --- | --- | --- |
| `Ping` | `0x01` | 최소 12; 보통 44 + padding | 버전 검사 없음; 12 미만 오류; 나머지는 아래 규칙 | `tailscale.com/disco/disco.go:45`, `tailscale.com/disco/disco.go:169` |
| `Pong` | `0x02` | 30 | 버전 검사 없음; 30 미만 오류; 뒤의 바이트 허용 | `tailscale.com/disco/disco.go:46`, `tailscale.com/disco/disco.go:271` |
| `CallMeMaybe` | `0x03` | `18 × N` | `ver!=0`, 빈 payload, 18의 배수 아님이면 오류 없이 빈 메시지 | `tailscale.com/disco/disco.go:47`, `tailscale.com/disco/disco.go:232` |
| `BindUDPRelayEndpoint` | `0x04` | 72 | 버전 검사 없음; 72 미만 오류; 뒤의 바이트 허용 | `tailscale.com/disco/disco.go:48`, `tailscale.com/disco/disco.go:384`, `tailscale.com/disco/disco.go:411` |
| `BindUDPRelayEndpointChallenge` | `0x05` | 72 | 위 common decoder와 같음 | `tailscale.com/disco/disco.go:49`, `tailscale.com/disco/disco.go:433` |
| `BindUDPRelayEndpointAnswer` | `0x06` | 72 | 위 common decoder와 같음 | `tailscale.com/disco/disco.go:50`, `tailscale.com/disco/disco.go:454` |
| `CallMeMaybeVia` | `0x07` | `124 + 18 × N`, `N>=1` | `ver!=0`이면 빈 메시지; v0은 최소 길이·나머지 검사 | `tailscale.com/disco/disco.go:51`, `tailscale.com/disco/disco.go:594`, `tailscale.com/disco/disco.go:651` |
| `AllocateUDPRelayEndpointRequest` | `0x08` | 68 | `ver!=0`이면 빈 메시지; v0은 68 미만 오류, 뒤 바이트 허용 | `tailscale.com/disco/disco.go:52`, `tailscale.com/disco/disco.go:475`, `tailscale.com/disco/disco.go:491` |
| `AllocateUDPRelayEndpointResponse` | `0x09` | `128 + 18 × N`, `N>=1` | `ver!=0`이면 빈 메시지; v0은 4바이트 Generation과 endpoint decoder 검사 | `tailscale.com/disco/disco.go:53`, `tailscale.com/disco/disco.go:526`, `tailscale.com/disco/disco.go:594` |

평문 2바이트 미만과 알 수 없는 타입은 Parse 오류다. 수신 처리는 유효한 box 안의 모르는 메시지를 상위 계층에 넘기거나 연결을 끊지 않고 무시한다. “모든 미지 버전을 거절” 또는 “모든 후행 바이트를 무시”라는 일괄 규칙을 적용하면 위 파서와 달라진다. (`tailscale.com/disco/disco.go:81`, `tailscale.com/disco/disco.go:106`, `tailscale.com/wgengine/magicsock/magicsock.go:2295`)

### 3.3 Ping, Pong, CallMeMaybe

| 메시지 | 페이로드 오프셋 | 길이 | 필드 | 인코딩·규칙 | 출처 |
| --- | --- | --- | --- | --- | --- |
| `Ping` | 0 | 12 | `TxID` | 무작위 불투명 바이트; 응답에서 그대로 반환 | `tailscale.com/disco/disco.go:134`, `tailscale.com/net/stun/stun.go:39` |
| `Ping` | 12 | 선택적 32 | `NodeKey` | 보낸 쪽 WireGuard 공개 키 raw; zero key면 송신 시 생략 | `tailscale.com/disco/disco.go:138`, `tailscale.com/disco/disco.go:154` |
| `Ping` | 12 또는 44 | 가변 | `Padding` | 송신은 0으로 채움; 수신은 TxID 뒤 32바이트 이상이고 그 첫 32바이트가 nonzero key이면 NodeKey로 해석, 나머지를 padding 길이로 계산 | `tailscale.com/disco/disco.go:145`, `tailscale.com/disco/disco.go:169` |
| `Pong` | 0 | 12 | `TxID` | 받은 Ping의 값 | `tailscale.com/disco/disco.go:253`, `tailscale.com/wgengine/magicsock/magicsock.go:2680` |
| `Pong` | 12 | 16 | `Src.IP` | Ping을 받은 쪽이 관측한 송신자의 IP; IPv4는 IPv4-mapped IPv6 | `tailscale.com/disco/disco.go:249`, `tailscale.com/disco/disco.go:255`, `tailscale.com/disco/disco.go:262` |
| `Pong` | 28 | 2 | `Src.Port` | big-endian u16; IP는 수신 후 Unmap | `tailscale.com/disco/disco.go:267`, `tailscale.com/disco/disco.go:279` |
| `CallMeMaybe` | `18 × i` | 16 | `MyNumber[i].IP` | `As16()`; IPv4-mapped IPv6; 개수 필드 없음 | `tailscale.com/disco/disco.go:219` |
| `CallMeMaybe` | `18 × i + 16` | 2 | `MyNumber[i].Port` | big-endian u16; 전체 길이에서 개수 계산 | `tailscale.com/disco/disco.go:226`, `tailscale.com/disco/disco.go:232` |

현재 Go의 일반 Ping은 자기 NodeKey를 포함한다. 따라서 padding 없는 disco Ping 전체는 `6+32+24+16+2+44=124`바이트, 구형 NodeKey 없는 Ping은 92바이트, Pong은 110바이트다. 이 값은 외피·인증자·메시지 길이로 계산한 것이며 IP/UDP/Geneve 헤더는 제외한다. (`tailscale.com/wgengine/magicsock/endpoint.go:1294`, `tailscale.com/wgengine/magicsock/endpoint.go:1313`, `tailscale.com/disco/disco.go:152`, `tailscale.com/disco/disco.go:260`)

### 3.4 피어 릴레이 관련 메시지

`0x04`·`0x05`·`0x06`의 payload는 동일한 `BindUDPRelayEndpointCommon` 배치다. `Generation`은 새 handshake마다 nonzero 새 값이고, `RemoteKey`는 릴레이 너머 상대 피어의 disco 키다. `Challenge`는 서버가 만들어 클라이언트가 그대로 echo하며, 최초 Bind에서는 같은 길이를 유지하기 위한 padding이다. (`tailscale.com/disco/disco.go:340`, `tailscale.com/disco/disco.go:348`)

| 페이로드 오프셋 | 길이 | 필드 | 인코딩 | 출처 |
| --- | --- | --- | --- | --- |
| 0 | 4 | `VNI` | big-endian u32; 외부 Geneve의 24비트 VNI와 일치해야 함 | `tailscale.com/disco/disco.go:353`, `tailscale.com/disco/disco.go:374` |
| 4 | 4 | `Generation` | big-endian u32 | `tailscale.com/disco/disco.go:377` |
| 8 | 32 | `RemoteKey` | raw disco 공개 키 | `tailscale.com/disco/disco.go:379` |
| 40 | 32 | `Challenge` | 불투명 32바이트 | `tailscale.com/disco/disco.go:381` |

`UDPRelayEndpoint`의 공통 배치를 E라고 하면 `CallMeMaybeVia` payload는 E이며, `AllocateUDPRelayEndpointResponse`는 `Generation:u32-BE || E`다. 아래 오프셋은 E 시작 기준이므로 Response에서는 모두 4를 더한다. 수명은 문자열이 아니라 `time.Duration`의 정수값을 u64-BE로 캐스팅한 값이며, 단위는 나노초다. 소스의 직렬화 fixture에서도 1초가 `00 00 00 00 3b 9a ca 00`(1,000,000,000)으로 나온다. (`tailscale.com/disco/disco.go:517`, `tailscale.com/disco/disco.go:539`, `tailscale.com/disco/disco.go:568`, `tailscale.com/disco/disco.go:609`, `tailscale.com/disco/disco.go:644`, `tailscale.com/disco/disco_test.go:33`, `tailscale.com/disco/disco_test.go:135`)

| E 오프셋 | 길이 | 필드 | 인코딩 | 출처 |
| --- | --- | --- | --- | --- |
| 0 | 32 | `ServerDisco` | 릴레이 서버 disco 공개 키 raw | `tailscale.com/disco/disco.go:568` |
| 32 | 32 | `ClientDisco[0]` | 허용 참가자 disco 키 raw | `tailscale.com/disco/disco.go:572`, `tailscale.com/net/udprelay/endpoint/endpoint.go:29` |
| 64 | 32 | `ClientDisco[1]` | 다른 참가자 disco 키 raw | `tailscale.com/disco/disco.go:572` |
| 96 | 8 | `LamportID` | u64-BE; 같은 ServerDisco에서 할당 식별·순서 비교 | `tailscale.com/disco/disco.go:577`, `tailscale.com/net/udprelay/endpoint/endpoint.go:33` |
| 104 | 4 | `VNI` | u32-BE | `tailscale.com/disco/disco.go:579` |
| 108 | 8 | `BindLifetime` | u64-BE duration; 양쪽 Bind 완료 전 할당 수명 | `tailscale.com/disco/disco.go:581`, `tailscale.com/net/udprelay/endpoint/endpoint.go:55` |
| 116 | 8 | `SteadyStateLifetime` | u64-BE duration; 양쪽 Bind 후 양방향 흐름 없는 동안의 수명 | `tailscale.com/disco/disco.go:583`, `tailscale.com/net/udprelay/endpoint/endpoint.go:60` |
| `124 + 18 × i` | 16 | `AddrPorts[i].IP` | As16; decoder는 Unmap | `tailscale.com/disco/disco.go:585`, `tailscale.com/disco/disco.go:613` |
| `140 + 18 × i` | 2 | `AddrPorts[i].Port` | u16-BE; 개수 필드 없이 끝까지, 최소 1개 | `tailscale.com/disco/disco.go:588`, `tailscale.com/disco/disco.go:594` |

| `AllocateUDPRelayEndpointRequest` payload 오프셋 | 길이 | 필드 | 인코딩 | 출처 |
| --- | --- | --- | --- | --- |
| 0 | 32 | `ClientDisco[0]` | raw disco 공개 키 | `tailscale.com/disco/disco.go:480` |
| 32 | 32 | `ClientDisco[1]` | raw disco 공개 키 | `tailscale.com/disco/disco.go:482` |
| 64 | 4 | `Generation` | u32-BE; 응답이 echo | `tailscale.com/disco/disco.go:469`, `tailscale.com/disco/disco.go:487` |

### 3.5 Geneve 외피

피어 릴레이 UDP는 아래 8바이트 뒤에 disco 외피 또는 원래 WireGuard 메시지를 둔다. Go 송신은 version 0, option 없음이며 WireGuard의 `Control`은 false, 서버 Bind·Answer의 `Control`은 true다. (`tailscale.com/net/packet/geneve.go:54`, `tailscale.com/net/packet/geneve.go:100`, `tailscale.com/wgengine/magicsock/magicsock.go:1995`, `tailscale.com/wgengine/magicsock/magicsock.go:2028`, `tailscale.com/wgengine/magicsock/rebinding_conn.go:82`)

| 오프셋 | 길이 | 필드 | 인코딩 | 출처 |
| --- | --- | --- | --- | --- |
| 0 | 1 | `Version`, Opt Len | 상위 2비트 version; 송신 byte 0 | `tailscale.com/net/packet/geneve.go:110` |
| 1 | 1 | `Control`와 나머지 비트 | Control은 `0x80`; 송신은 그 외 0 | `tailscale.com/net/packet/geneve.go:111` |
| 2 | 2 | `Protocol` | u16-BE; disco `0x7A11`, WireGuard `0x7A12` | `tailscale.com/net/packet/geneve.go:18`, `tailscale.com/net/packet/geneve.go:116` |
| 4 | 3 | `VNI` | 24비트 big-endian | `tailscale.com/net/packet/geneve.go:117`, `tailscale.com/net/packet/geneve.go:132` |
| 7 | 1 | Reserved | 송신 0 | `tailscale.com/net/packet/geneve.go:117` |
| 8 | 가변 | 내부 패킷 | disco 또는 WireGuard | `tailscale.com/wgengine/magicsock/magicsock.go:1867`, `tailscale.com/wgengine/magicsock/magicsock.go:1897` |

### 3.6 자기 주소 측정에 필요한 STUN 경계

netcheck는 DERP map의 노드 주소·`STUNPort`에 Binding Request를 보내며 0 포트는 3478, 음수는 비활성이다. 반드시 데이터·disco를 보내는 동일 UDP 소켓으로 STUN을 송수신한다. Go도 `SendPacket=c.sendUDPNetcheck`로 연결하고 pconn4/pconn6에 직접 쓴다. (`tailscale.com/net/netcheck/netcheck.go:1608`, `tailscale.com/net/netcheck/netcheck.go:1660`, `tailscale.com/wgengine/magicsock/magicsock.go:710`, `tailscale.com/wgengine/magicsock/magicsock.go:1632`)

| STUN 오프셋 | 길이 | 필드 | 인코딩 | 출처 |
| --- | --- | --- | --- | --- |
| 0 | 2 | message type | Request `00 01`, Success Response `01 01` | `tailscale.com/net/stun/stun.go:30`, `tailscale.com/net/stun/stun.go:200` |
| 2 | 2 | attributes length | u16-BE; 20바이트 헤더 제외 | `tailscale.com/net/stun/stun.go:55`, `tailscale.com/net/stun/stun.go:203` |
| 4 | 4 | magic cookie | `21 12 a4 42` | `tailscale.com/net/stun/stun.go:31` |
| 8 | 12 | `TxID` | 무작위; in-flight 요청과 대응 | `tailscale.com/net/stun/stun.go:39`, `tailscale.com/net/netcheck/netcheck.go:344` |
| 20 이후 | 가변 | attributes | type:u16-BE, length:u16-BE, value, 4바이트 경계 padding | `tailscale.com/net/stun/stun.go:135` |

Go Request에는 SOFTWARE=`tailnode`와 마지막 FINGERPRINT가 들어간다. FINGERPRINT는 그 attribute 이전 바이트의 `CRC32-IEEE ^ 0x5354554e`다. 응답은 `XOR-MAPPED-ADDRESS`(`0x0020`, 대체 `0x8020`)를 우선하고 없으면 `MAPPED-ADDRESS`(`0x0001`)로 대체한다. 주소 attribute value는 reserved 1바이트, family 1바이트(`0x01` IPv4 / `0x02` IPv6), port 2바이트 BE, IP 4/16바이트 순서다. XOR port는 `^0x2112`, IPv4 주소는 cookie와 XOR, IPv6는 `cookie || TxID`와 XOR한다. (`tailscale.com/net/stun/stun.go:20`, `tailscale.com/net/stun/stun.go:50`, `tailscale.com/net/stun/stun.go:73`, `tailscale.com/net/stun/stun.go:213`, `tailscale.com/net/stun/stun.go:252`, `tailscale.com/net/stun/stun.go:280`)

## 4. 절차와 상태 기계

### 4.1 수신 분류와 피어 식별

1. **분류 순서:** 먼저 `stun.Is`(길이 >=20, 첫 바이트 상위 2비트 0, cookie 일치) 및 `msg[1]==0x01`이면 STUN Binding으로 처리하고 WireGuard에 넘기지 않는다. 이는 응답의 성공 여부를 검증하는 절차와 별개다. (`tailscale.com/net/stun/stun.go:308`, `tailscale.com/wgengine/magicsock/magicsock.go:2143`, `tailscale.com/wgengine/magicsock/magicsock.go:1877`)
2. 다음은 길이 >=8, `msg[0]&0xC0==0`, `msg[1]&0x3F==0`, `msg[7]==0`이면 protocol을 확인한다. `0x7A11`은 8바이트 뒤 disco magic와 최소 38바이트를 검사하여 disco로 분류하고, 불일치면 naked WireGuard 가정으로 되돌아간다. `0x7A12`는 Geneve WireGuard다. **수신 분류기는 Opt Len=0과 `0x40` 비트를 추가 검사하지 않는다**; 옵션 지원을 의미하지 않는다. (`tailscale.com/wgengine/magicsock/magicsock.go:2151`, `tailscale.com/wgengine/magicsock/magicsock.go:2158`, `tailscale.com/net/packet/geneve.go:54`)
3. naked disco는 길이 >=38와 magic 일치로 분류하며 나머지는 잠재적 WireGuard로 넘긴다. `disco.LooksLikeDiscoWrapper`의 길이 조건은 >=62로 더 강하므로 두 함수를 혼동하지 않는다. box가 너무 짧거나 인증에 실패하면 후단 Open에서 탈락한다. (`tailscale.com/wgengine/magicsock/magicsock.go:2151`, `tailscale.com/wgengine/magicsock/magicsock.go:2186`, `tailscale.com/disco/disco.go:62`, `tailscale.com/types/key/disco.go:235`)
4. WireGuard 입력은 Geneve이면 8바이트를 제거하고, 출발 `epAddr=(IP:port, optional VNI)`로 `peerMap.byEpAddr`를 찾는다. `byNodeKey`/`byNodeID`는 피어 인덱스이고 `nodesOfDisco`는 **하나의 disco key에 여러 node key가 연결될 수 있는 집합**이다. 일반 netmap Endpoints를 받았다는 이유만으로 Tailscale 피어의 주소 대응을 확정하지 않는다. (`tailscale.com/wgengine/magicsock/magicsock.go:1894`, `tailscale.com/wgengine/magicsock/peermap.go:32`, `tailscale.com/wgengine/magicsock/peermap.go:147`)
5. disco는 알려진 disco key의 유효한 box만 처리한다. Ping의 node key는 단독으로 신뢰하지 않는다. 대응 확정은 DERP의 node source와 disco 키 일치 → Ping.NodeKey와 알려진 피어 disco 키 일치 → 해당 disco 키에 피어가 정확히 하나인 경우 순서로 시도한다. 비 DERP Ping의 출발 주소는 이 판단이 성공했을 때 주소→node 인덱스에 넣는다. (`tailscale.com/disco/disco.go:138`, `tailscale.com/wgengine/magicsock/magicsock.go:2245`, `tailscale.com/wgengine/magicsock/magicsock.go:2547`, `tailscale.com/wgengine/magicsock/magicsock.go:2617`)
6. 유효한 UDP Ping은 해당 disco 키의 피어 후보 목록에 **실제 출발 주소**를 추가하고 같은 TxID의 중복은 억제한다. 원래 출발지로 `Pong{TxID, Src=관측한 출발 IP:port}`를 보낸다. DERP Ping은 UDP 후보를 추가하지 않고 DERP로 응답한다. (`tailscale.com/wgengine/magicsock/magicsock.go:2634`, `tailscale.com/wgengine/magicsock/magicsock.go:2678`, `tailscale.com/wgengine/magicsock/endpoint.go:1810`)
7. **모르는 UDP 출발 주소를 무조건 폐기하지 않는다.** Go는 `lazyEndpoint`로 WireGuard에 넘기고, initiation의 공개 키 통지로 활동을 기록하며, 성공적인 복호화 후 `FromPeer`의 알려진 node key로 주소 대응을 확정한다. handshake 부하 시 cookie reply도 그 임시 출발 주소로 보낼 수 있다. (`tailscale.com/wgengine/magicsock/magicsock.go:1909`, `tailscale.com/wgengine/magicsock/magicsock.go:4481`, `tailscale.com/wgengine/magicsock/magicsock.go:4524`, `tailscale.com/wgengine/magicsock/magicsock.go:1514`)
8. DERP 수신은 프레임의 node source로 피어를 찾는다. naked disco는 일반 disco 수신기로 보내며 DERP의 source node key도 전달한다. 나머지 데이터는 모르는 node key면 폐기하고 알려진 피어의 WireGuard 데이터로 반환한다. (`tailscale.com/wgengine/magicsock/derp.go:613`, `tailscale.com/wgengine/magicsock/derp.go:734`)

### 4.2 피어 후보 목록

1. netmap의 `Node.Endpoints`를 후보로 넣고, `HomeDERP`는 별도 DERP 경로로 저장한다. 후자는 내부 표현 `DerpMagicIPAddr:regionID`이며 `DerpMagicIP=127.3.3.40`은 UDP로 송신할 인터넷 엔드포인트가 아니다. (`tailscale.com/wgengine/magicsock/endpoint.go:1733`, `tailscale.com/wgengine/magicsock/endpoint.go:1755`, `tailscale.com/tailcfg/tailcfg.go:3072`, `tailscale.com/wgengine/magicsock/magicsock.go:1679`)
2. netmap 갱신 시 각 후보를 일단 삭제 표시하고 현재 목록에 있는 것을 되살린다. netmap에서 사라지고 다른 유지 사유가 없는 후보는 제거한다. 런타임 Ping 출발지로 배운 후보는 마지막 수신 Ping 이후 45초가 지나면 제거 대상이고, `callMeMaybeTime`이 있는 후보는 일반 만료 검사에서는 유지한다. (`tailscale.com/wgengine/magicsock/endpoint.go:1762`, `tailscale.com/wgengine/magicsock/endpoint.go:509`)
3. CallMeMaybe 주소 집합은 다음 메시지로 대체된다. 이전 CallMeMaybe 집합에 있었고 새 메시지에 없는 주소는 netmap 출처 여부를 별도로 검사하지 않고 `deleteEndpointLocked`로 제거하므로 이를 영구 추가 목록처럼 구현하지 않는다. 그 주소가 best였다면 best도 비운다. IPv6 link-local은 여기서는 무시한다. (`tailscale.com/wgengine/magicsock/endpoint.go:2158`, `tailscale.com/wgengine/magicsock/endpoint.go:2197`, `tailscale.com/wgengine/magicsock/endpoint.go:547`)

### 4.3 송신·탐색·Pong 승격·경로 강등

**구현 제안:** 피어마다 `candidates`, `sentPing[TxID]={to,at,timeout,purpose,size}`, `bestAddr`, `latency`, `wireMTU`, `trustBestAddrUntil`, `lastFullPing`, `lastSendExt`, heartbeat 상태를 둔다. 시간 비교는 Go와 같이 단조 시계를 쓰고, 자기 광고 주소 캐시는 별도 상태로 둔다. 상태의 근거는 endpoint의 송신·응답·heartbeat와 별도 endpointTracker다. (`tailscale.com/wgengine/magicsock/endpoint.go:1356`, `tailscale.com/wgengine/magicsock/endpoint.go:1929`, `tailscale.com/wgengine/magicsock/endpoint.go:872`, `tailscale.com/wgengine/magicsock/endpoint_tracker.go:109`, `tailscale.com/tstime/mono/mono.go:24`)

1. WireGuard 데이터를 보낼 때 유효하고 신뢰 기간이 남은 `bestAddr`가 있으면 그 UDP 경로만 반환한다. 없거나 만료되었으면 기존 UDP best와 DERP 주소를 함께 반환한다. 만료된 best는 당장 삭제되지 않으므로 회복 가능한 UDP에도 계속 보내면서 DERP로 복제할 수 있다. (`tailscale.com/wgengine/magicsock/endpoint.go:635`)
2. best가 직접 경로가 아니거나 신뢰가 만료되었으면 모든 직접 후보에 discovery Ping을 시도한다. 후보마다 최근 Ping 5초 미만이면 건너뛰고, 실제 탐색을 예약한 후보가 있으며 DERP가 유효하면 CallMeMaybe를 enqueue한다. TxID는 새 무작위 12바이트이며 송신 전에 5초 응답 타이머를 등록한다. (`tailscale.com/wgengine/magicsock/endpoint.go:1123`, `tailscale.com/wgengine/magicsock/endpoint.go:1423`, `tailscale.com/wgengine/magicsock/endpoint.go:1404`, `tailscale.com/tsconst/ping.go:9`)
3. 데이터는 선택된 UDP와 DERP에 같은 WireGuard 바이트로 보낸다. 직접·DERP 주소가 모두 없으면 상대가 최근 수신에 사용한 DERP region을 fallback으로 시도하고, 그것도 없으면 `errNoUDPOrDERP`다. DERP 전송 성공이면 해당 send는 성공으로 반환할 수 있다. (`tailscale.com/wgengine/magicsock/endpoint.go:1133`, `tailscale.com/wgengine/magicsock/endpoint.go:1145`, `tailscale.com/wgengine/magicsock/endpoint.go:1184`)
4. 인증된 Pong도 `sentPing`에 TxID가 없으면 직접 경로 측정으로 채택하지 않는다. 대응되는 요청을 제거하고 RTT=`now-sp.at`를 계산한다. 직접 Pong이면 실제 응답 출발 주소 `src`를 해당 피어의 주소 인덱스에 등록하고, 이력은 **Ping을 보낸 후보 `sp.to`** 아래 저장한다. (`tailscale.com/wgengine/magicsock/endpoint.go:1933`, `tailscale.com/wgengine/magicsock/endpoint.go:1952`)
5. best 후보 비교 대상도 `sp.to`다. Pong의 `Src`는 상대가 본 **자기 쪽** 주소이고 새 상대 엔드포인트가 아니다. `betterAddr`가 참이거나 기존 best의 신뢰가 만료되었으면 승격한다. 결과 best가 이번 후보와 같으면 RTT·`bestAddrAt`를 갱신하고 신뢰를 `now+6500ms`까지 연장한다. DERP Pong은 CLI RTT 응답에는 쓸 수 있어도 직접 best로 승격하지 않는다. (`tailscale.com/disco/disco.go:249`, `tailscale.com/wgengine/magicsock/endpoint.go:1966`, `tailscale.com/wgengine/magicsock/endpoint.go:1982`, `tailscale.com/wgengine/magicsock/endpoint.go:1990`)
6. Pong timeout은 그 요청 목적지가 현재 best와 같고 **현재 best가 이미 신뢰 만료**일 때만 best를 지운다. 따라서 Ping 한 번 유실이 곧바로 경로 삭제를 뜻하지 않는다. `EHOSTUNREACH`는 즉시 best를 지우고 해당 후보의 측정 상태를 비우는 별도 경로다. (`tailscale.com/wgengine/magicsock/endpoint.go:1244`, `tailscale.com/wgengine/magicsock/endpoint_default.go:20`, `tailscale.com/wgengine/magicsock/endpoint.go:1857`)
7. 외부 송신 활동은 heartbeat를 시작·갱신한다. 활동 중 3초마다 best에 Ping하고, best가 직접 경로가 아니거나 미탐색·만료이면 전체 탐색한다. 신뢰된 직접 경로의 RTT <=5ms면 개선 탐색을 생략하고, 그보다 느리면 마지막 전체 탐색 후 1분 이상일 때 다시 시도한다. (`tailscale.com/wgengine/magicsock/endpoint.go:1020`, `tailscale.com/wgengine/magicsock/endpoint.go:926`, `tailscale.com/wgengine/magicsock/endpoint.go:1001`)
8. `lastSendExt` 이후 45초를 넘으면 heartbeat를 중단한다. 유휴 판정 기준은 단순히 마지막 수신 데이터가 아니라 외부 송신 활동이며, CLI disco Ping도 외부 활동으로 기록된다. 선택적 UDP lifetime 측정은 이 유휴 전환 뒤 별도로 예약될 수 있다. (`tailscale.com/wgengine/magicsock/endpoint.go:887`, `tailscale.com/wgengine/magicsock/endpoint.go:1396`)
9. 일반 disco 피어는 UDP WireGuard 패킷을 받았다는 것만으로 매번 trust를 연장하지 않는다. `heartbeatDisabled`인 피어의 현재 best에서 받은 경우는 예외로 6.5초 연장한다. 최소 구현이 일반 heartbeat 모드를 쓴다면 Pong 기반 신뢰와 이 예외를 구분한다. (`tailscale.com/wgengine/magicsock/endpoint.go:579`)

### 4.4 `betterAddr`의 정확한 판단 순서

1. 같은 `epAddr`이면 새 측정의 `wireMTU`가 클 때만 better이며, 주소가 다르면 기존 주소가 invalid인 경우 새 주소를 택하고 새 주소가 invalid이면 거절한다. (`tailscale.com/wgengine/magicsock/endpoint.go:2059`)
2. 주소가 다르고 직접 경로와 Geneve 릴레이가 경쟁하면 직접 경로가 우선한다. 그 뒤부터 latency 점수를 계산한다. (`tailscale.com/wgengine/magicsock/endpoint.go:2078`)
3. 처음 양쪽 0점. `a.latency>b.latency && a.latency>0`이면 b에 `100-floor(b.latency*100/a.latency)`점, 그렇지 않고 `b.latency>0`이면 a에 `100-floor(a.latency*100/b.latency)`점을 준다. Go 정수 연산과 같은 순서로 계산한다. (`tailscale.com/wgengine/magicsock/endpoint.go:2092`)
4. 각 주소에 loopback +50, 아니면 link-local unicast +30, 아니면 private +20을 더하고, 별도로 IPv6이면 +10을 더한다. (`tailscale.com/wgengine/magicsock/endpoint.go:2107`)
5. `aPoints<=1 && bPoints==0`이면 바꾸지 않고, 그 밖에는 `aPoints>bPoints`일 때만 바꾼다. 단, 이 비교 함수는 시간 신뢰를 다루지 않으며 호출자가 best 만료 시 새 Pong 후보를 선택할 수 있다. (`tailscale.com/wgengine/magicsock/endpoint.go:2131`, `tailscale.com/wgengine/magicsock/endpoint.go:1998`)

### 4.5 CallMeMaybe와 DERP

1. 전제는 자기 쪽에서 후보들로 UDP Ping을 먼저 보내 NAT·방화벽 상태를 여는 것이다. 그 탐색과 함께 상대의 DERP에 CallMeMaybe를 보낸다. Go는 Ping 송신과 enqueue를 비동기로 예약하므로 엄격한 패킷 도착 순서를 보장하는 장치는 아니다. (`tailscale.com/disco/disco.go:191`, `tailscale.com/wgengine/magicsock/endpoint.go:1417`, `tailscale.com/wgengine/magicsock/endpoint.go:1448`)
2. 자기 주소 측정 시각이 27초 이내가 아니면 CallMeMaybe를 즉시 보내지 않는다. endpoint refresh 완료 콜백을 등록하고 `ReSTUN("refresh-for-peering")` 후 재시도한다. 목록 내용이 같아도 측정 시각과 대기 콜백은 갱신된다. (`tailscale.com/wgengine/magicsock/magicsock.go:2693`, `tailscale.com/wgengine/magicsock/magicsock.go:978`)
3. 준비되면 `lastEndpoints`의 주소만 `MyNumber`로 만들어 상대 node key를 DERP 목적지로, 상대 disco key를 box 수신자로 지정한다. DERP에는 UDP용 disco와 동일한 암호 외피를 넣는다. 내부 magic 주소는 실제 UDP에 쓰지 않고 region으로 해석한다. (`tailscale.com/wgengine/magicsock/magicsock.go:2721`, `tailscale.com/wgengine/magicsock/magicsock.go:2041`, `tailscale.com/wgengine/magicsock/magicsock.go:1679`, `tailscale.com/wgengine/magicsock/derp.go:696`)
4. 수신은 DERP 경로이고 nonzero DERP source node key여야 한다. 그 node가 알려져 있고 source disco key가 해당 node의 알려진 키와 일치해야 한다. 일반 UDP로 온 CallMeMaybe는 처리하지 않는다. (`tailscale.com/wgengine/magicsock/magicsock.go:2352`, `tailscale.com/wgengine/magicsock/magicsock.go:2371`, `tailscale.com/wgengine/magicsock/magicsock.go:2405`)
5. 주소 집합을 갱신한 뒤 **모든 후보의 `lastPing`을 0으로 초기화**하고, 5초 rate limit을 우회해 즉시 전체 Ping을 보낸다. 이때 `sendCallMeMaybe=false`이므로 CallMeMaybe를 서로 무한 반사하지 않는다. (`tailscale.com/wgengine/magicsock/endpoint.go:2197`, `tailscale.com/wgengine/magicsock/endpoint.go:2206`)

### 4.6 자기 엔드포인트 발견·광고

1. 선택적 port mapper 캐시를 조회/시작하고 netcheck를 실행한다. port mapper는 빌드·설정에 따라 아예 nil일 수 있으며, 없을 때도 STUN과 로컬 주소 발견을 진행한다. (`tailscale.com/wgengine/magicsock/magicsock.go:681`, `tailscale.com/wgengine/magicsock/magicsock.go:1278`)
2. 유효하고 중복되지 않는 주소를 순서대로 모은다: port mapping → STUN IPv4·IPv6 → hard NAT의 STUN IPv4+고정 로컬 포트 후보 → 명시/클라우드 후보 → 이전 광고 캐시 → 사용자 static endpoint → 로컬 인터페이스 주소. 이 순서와 달리 현대 클라이언트는 목록 순서를 경로 선택 기준으로 삼지 않는다. (`tailscale.com/wgengine/magicsock/magicsock.go:1315`, `tailscale.com/wgengine/magicsock/magicsock.go:1325`, `tailscale.com/wgengine/magicsock/magicsock.go:1355`, `tailscale.com/wgengine/magicsock/magicsock.go:1384`, `tailscale.com/wgengine/magicsock/magicsock.go:1402`, `tailscale.com/wgengine/magicsock/magicsock.go:1428`)
3. STUN global 목록에는 대표 관측 주소와, 추가로 2번 이상 관측된 주소만 넣는다. IPv4에서 서로 다른 관측 주소가 나오면 `MappingVariesByDestIP=true`다. 이 값은 직접 경로 성공을 보증하는 값이 아니다. (`tailscale.com/net/netcheck/netcheck.go:133`, `tailscale.com/net/netcheck/netcheck.go:719`, `tailscale.com/wgengine/magicsock/endpoint.go:1990`)
4. wildcard UDP bind이면 활성 인터페이스의 로컬 주소에 실제 UDP 로컬 포트를 붙인다. 특정 IP bind이면 그 IP만 광고한다. 기본 인터페이스 열거는 Tailscale IP와 IPv6 link-local을 제외하고 IPv6 동일 subnet에서는 기본 최대 2개를 선택하며, 사용 가능한 일반 주소가 하나도 없을 때 IPv4 link-local·IPv6 ULA를 대체 후보로 쓴다. (`tailscale.com/wgengine/magicsock/magicsock.go:1406`, `tailscale.com/net/netmon/state.go:65`, `tailscale.com/net/netmon/state.go:94`, `tailscale.com/net/netmon/state.go:119`)
5. loopback은 일반 로컬 주소도 없고 다른 발견 endpoint도 없을 때에만 자동 광고한다. **구현 제안:** M4 loopback 시험은 명시적 static endpoint를 사용하거나 실제 loopback-only 환경으로 구성한다. Go는 static endpoint를 도달성 사전 검증 없이 광고한다. (`tailscale.com/wgengine/magicsock/magicsock.go:1411`, `tailscale.com/wgengine/magicsock/magicsock.go:1272`, `tailscale.com/wgengine/magicsock/magicsock.go:1402`)
6. `endpoint_tracker.go`는 상대 후보 상태 기계가 아니라 **자기 광고 캐시**다. 로컬 인터페이스 주소를 덧붙이기 전에 갱신하므로 그 로컬 주소는 캐시하지 않는다. 과거 후보를 마지막 발견부터 5분 10초 유지하고 같은 IP당 최대 6개 포트를 보관한다. (`tailscale.com/wgengine/magicsock/endpoint_tracker.go:18`, `tailscale.com/wgengine/magicsock/endpoint_tracker.go:117`, `tailscale.com/wgengine/magicsock/magicsock.go:1384`)
7. 바뀐 목록은 `EndpointsFunc` → engine status → `LocalBackend` → `Auto.UpdateEndpoints` → `Direct.SetEndpoints`로 전달된다. `MapRequest.Endpoints`와 같은 인덱스의 `EndpointTypes`에 나누어 넣고 `DiscoKey`도 함께 보낸다. 주소 type은 disco CallMeMaybe에는 들어가지 않는다. (`tailscale.com/wgengine/magicsock/magicsock.go:945`, `tailscale.com/wgengine/userspace.go:422`, `tailscale.com/ipn/ipnlocal/local.go:2982`, `tailscale.com/control/controlclient/auto.go:888`, `tailscale.com/control/controlclient/direct.go:1052`, `tailscale.com/control/controlclient/direct.go:1092`, `tailscale.com/disco/disco.go:221`)
8. endpoint 변경은 제어 update를 유발한다. **구현 제안:** 이미 열린 map stream에 의존하지 말고 `Stream=false, OmitPeers=true, ReadOnly=false`의 갱신 요청을 보낸다. Version >=68의 `Stream=true` 요청에 있는 Endpoints는 서버가 무시할 수 있으며, 비스트리밍 갱신은 기존 stream을 깨지 않고 수행할 수 있다. (`tailscale.com/control/controlclient/auto.go:892`, `tailscale.com/tailcfg/tailcfg.go:1494`, `tailscale.com/tailcfg/tailcfg.go:1513`)
9. 주기 갱신은 활성 상태에서 무작위 20~26초 간격이다. 네트워크 down/homeless, 피어 없음, node 비밀 키 없음이면 중단하며 idleFunc가 45초를 넘기면 기본 중단한다(`ForceBackgroundSTUN` 예외). 새 key, 첫 피어, DERP map, port mapping, static endpoint, 링크 변경, 오래된 CallMeMaybe 준비 등이 다시 측정을 촉발한다. netcheck 전체 region 재탐색 기준은 5분이며 매 20~26초마다 모든 region을 탐색한다는 뜻은 아니다. (`tailscale.com/wgengine/magicsock/magicsock.go:899`, `tailscale.com/wgengine/magicsock/magicsock.go:3683`, `tailscale.com/wgengine/magicsock/magicsock.go:2813`, `tailscale.com/wgengine/magicsock/magicsock.go:3202`, `tailscale.com/wgengine/magicsock/derp.go:875`, `tailscale.com/wgengine/magicsock/magicsock.go:3714`, `tailscale.com/wgengine/magicsock/magicsock.go:1005`, `tailscale.com/wgengine/userspace.go:1218`, `tailscale.com/wgengine/magicsock/magicsock.go:2702`, `tailscale.com/net/netcheck/netcheck.go:888`, `tailscale.com/net/netcheck/netcheck.go:1374`)

| `EndpointType` | 값 | 의미 | 출처 |
| --- | --- | --- | --- |
| `EndpointUnknownType` | 0 | 미분류 | `tailscale.com/tailcfg/tailcfg.go:1392` |
| `EndpointLocal` | 1 | 로컬 주소 | `tailscale.com/tailcfg/tailcfg.go:1393`, `tailscale.com/wgengine/magicsock/magicsock.go:1419` |
| `EndpointSTUN` | 2 | STUN 관측 주소 | `tailscale.com/tailcfg/tailcfg.go:1394`, `tailscale.com/wgengine/magicsock/magicsock.go:1334` |
| `EndpointPortmapped` | 3 | port mapping 외부 주소 | `tailscale.com/tailcfg/tailcfg.go:1395`, `tailscale.com/wgengine/magicsock/magicsock.go:1329` |
| `EndpointSTUN4LocalPort` | 4 | hard NAT의 STUN IPv4+고정 로컬 포트 추정 후보 | `tailscale.com/tailcfg/tailcfg.go:1396`, `tailscale.com/wgengine/magicsock/magicsock.go:1343` |
| `EndpointExplicitConf` | 5 | 명시 설정 주소 | `tailscale.com/tailcfg/tailcfg.go:1397`, `tailscale.com/wgengine/magicsock/magicsock.go:1402` |

### 4.7 네트워크 변경·소켓 재결속·Darwin/iOS

1. 링크 변경 시 `SetNetworkUp`으로 상태를 갱신한다. up이고 major(`RebindLikelyRequired`)이면 Rebind 후 ReSTUN, minor이면 ReSTUN만 한다. down이면 그 자리에서 재결속·STUN하지 않는다. (`tailscale.com/wgengine/userspace.go:1208`)
2. `Rebind()`는 UDP 소켓을 새로 만든다. 우선순위는 요청된 고정 포트 → 현재 포트(유지 모드) → OS가 고르는 포트 0이다. IPv6 bind 실패는 허용하고 IPv4 bind 실패는 재결속 실패다. 실제 로컬 포트가 바뀌면 port mapper에도 전달한다. (`tailscale.com/wgengine/magicsock/magicsock.go:3771`, `tailscale.com/wgengine/magicsock/magicsock.go:3798`, `tailscale.com/wgengine/magicsock/magicsock.go:3878`)
3. Unix에서 기존 소켓 자체를 rebind하는 대신 새 소켓으로 교체한다. 이전 소켓에서 read/write 오류가 났는데 그 사이 연결이 교체되었다면 새 소켓으로 재시도한다. **구현 제안:** Swift의 대기 중 receive도 교체 때문에 전체 라이브러리 실패가 되지 않도록 소켓 세대를 구별한다. (`tailscale.com/wgengine/magicsock/rebinding_conn.go:22`, `tailscale.com/wgengine/magicsock/rebinding_conn.go:61`, `tailscale.com/wgengine/magicsock/rebinding_conn.go:123`, `tailscale.com/wgengine/magicsock/rebinding_conn.go:179`)
4. 재결속 뒤 모든 피어의 best와 후보 측정을 초기화하고, ReSTUN은 호출자가 이어서 실행해야 한다. DERP도 기본 경로 인터페이스 주소와 맞지 않는 기존 연결은 닫고, 맞는 연결은 3초 Ping으로 확인해 실패 시 닫는다. home DERP는 다시 연결한다. (`tailscale.com/wgengine/magicsock/magicsock.go:3894`, `tailscale.com/wgengine/magicsock/magicsock.go:3920`, `tailscale.com/wgengine/magicsock/endpoint.go:1876`, `tailscale.com/wgengine/magicsock/derp.go:905`, `tailscale.com/wgengine/magicsock/derp.go:944`)
5. broken pipe/closed-pipe 계열과 `EPERM`은 Rebind+ReSTUN을 시도하는 송신 오류이며, 그 자동 재시도는 5초 제한을 둔다. `EHOSTUNREACH`로 특정 best를 내리는 절차와 구별한다. (`tailscale.com/wgengine/magicsock/magicsock_notplan9.go:17`, `tailscale.com/wgengine/magicsock/magicsock.go:1612`, `tailscale.com/wgengine/magicsock/endpoint_default.go:20`)
6. Go UDP listen은 `netns.Listener`를 거쳐 Darwin control hook을 적용한다. 기본 route interface index에 `IP_BOUND_IF`(IPv4) / `IPV6_BOUND_IF`(IPv6)를 설정하며 localhost는 결속을 생략한다. route 기반 선택 옵션이 켜진 경우 목적지 route index를 구하되 Tailscale utun을 고르면 default interface로 되돌린다. 기본 index는 OS 관측을 netmon 캐시보다 우선한다. (`tailscale.com/wgengine/magicsock/magicsock.go:3757`, `tailscale.com/net/netns/netns.go:87`, `tailscale.com/net/netns/netns_darwin.go:39`, `tailscale.com/net/netns/netns_darwin.go:78`, `tailscale.com/net/netns/netns_darwin.go:112`, `tailscale.com/net/netns/netns_darwin.go:295`)
7. Apple Network Extension에서는 인터페이스 결속을 끄는 별도 설정도 있다. **구현 제안:** iOS에서는 이 Go 동작을 플랫폼 통합의 기준으로 삼되, Swift의 소켓/Network.framework/Packet Tunnel 결속·재시작 방식은 별도 확인한다. 허용 소스에서 확인한 것은 Darwin의 위 sockopt 구현과 Apple extension 예외이며 Swift API의 동등성까지는 아니다. (`tailscale.com/net/netns/netns.go:63`, `tailscale.com/net/netns/netns.go:78`, `tailscale.com/net/netns/netns_darwin.go:40`)

### 4.8 WireGuard 접점과 키 수명

1. Go의 `connBind`는 `conn.Bind` 구현이다. Open은 실제 로컬 포트와 IPv4·IPv6·DERP receive 함수들을 반환하고, UDP 미지원 빌드에서는 DERP receive만 반환한다. Send는 피어 endpoint의 경로 선택으로 들어간다. **구현 제안:** Swift에는 동등한 “암호화된 WireGuard 메시지 송수신” 경계만 있으면 되며 Go batching/락 구조를 복제할 필요는 없다. (`tailscale.com/wgengine/magicsock/magicsock.go:1499`, `tailscale.com/wgengine/magicsock/magicsock.go:3509`, `tailscale.com/wgengine/magicsock/magicsock.go:3543`)
2. Go WireGuard endpoint 문자열은 `IP:port` 대신 untyped 64자리 node 공개 키 hex이고 ParseEndpoint가 peerMap에서 찾는다. `DstIP()`는 피어 node 주소, `DstToBytes()`는 피어별 합성 `fd00` 주소와 포트 12345를 사용한다. 이 합성 주소는 네트워크 송신 목적지가 아니며 packed port는 little-endian이다. (`tailscale.com/types/key/node.go:195`, `tailscale.com/wgengine/magicsock/magicsock.go:3943`, `tailscale.com/wgengine/magicsock/endpoint.go:568`, `tailscale.com/wgengine/magicsock/endpoint.go:622`, `tailscale.com/wgengine/magicsock/magicsock.go:3929`)
3. WireGuard 지연 피어 생성은 공개 키로 최신 AllowedIPs·선택적 PresharedKey를 얻고 Bind.ParseEndpoint로 endpoint를 만든다. **구현 제안:** M4 소수 피어는 미리 구성해도 되지만, 모르는 UDP 주소의 인증된 WireGuard 패킷이 알려진 node로 연결되는 경로는 유지한다. (`tailscale.com/wgengine/wgcfg/device.go:43`, `tailscale.com/wgengine/userspace.go:683`, `tailscale.com/wgengine/magicsock/magicsock.go:4524`)
4. node key는 WireGuard 피어 식별 및 DERP 인증·목적지에 쓰고 disco key는 발견 메시지 box에 쓴다. `Ping.NodeKey`와 netmap/DERP 정보가 둘의 관계를 좁힌다. disco key를 node key로부터 유도하는 코드 경로는 이 구현에 없고 `newConn`에서 별도 `NewDisco()`를 사용한다. (`tailscale.com/wgengine/magicsock/magicsock.go:579`, `tailscale.com/wgengine/magicsock/magicsock.go:2789`, `tailscale.com/wgengine/magicsock/magicsock.go:2547`, `tailscale.com/types/key/disco.go:76`)
5. 이 버전에는 **세션 성립 직후의 TSMP disco 키 광고**가 있다. 새 WireGuard encryption keypair와 주기적 key rotation 성립 콜백이 `PriorityMessageForPeer`를 호출하며 WireGuard-only 피어가 아니면 자기 disco key를 보낸다. TSMP는 IP protocol 99이고, IP 헤더 뒤 payload offset 0에 `'a'=0x61` 1바이트, offset 1에 disco key raw 32바이트다. 이는 외부 UDP disco packet이 아니라 WireGuard 안의 IP packet이다. (`tailscale.com/ipn/ipnlocal/local.go:645`, `tailscale.com/wgengine/userspace.go:760`, `tailscale.com/wgengine/magicsock/magicsock.go:4631`, `tailscale.com/net/packet/tsmp.go:276`, `tailscale.com/types/ipproto/ipproto.go:67`)
6. 수신한 TSMP 광고는 앱 데이터로 전달하지 않고, nonzero 키를 해당 node의 TSMP-learned disco 키로 등록한다. control-learned 키와 TSMP-learned 키를 보관하고 관측한 알려진 비활성 키로 active를 전환할 수 있다. active 키가 바뀌면 trust와 in-flight 탐색을 무효화하되 기존 best 주소는 남겨 데이터가 흐르게 한다. (`tailscale.com/net/tstun/wrap.go:1133`, `tailscale.com/wgengine/magicsock/magicsock.go:4579`, `tailscale.com/wgengine/magicsock/endpoint.go:386`, `tailscale.com/wgengine/magicsock/endpoint.go:1645`, `tailscale.com/wgengine/magicsock/endpoint.go:1690`, `tailscale.com/wgengine/magicsock/endpoint.go:2291`)
7. **구현 제안:** M4 처음에는 control disco 키가 안정된 세션부터 검증하되, Go가 보내는 TSMP 광고를 안전하게 소비하고 이후에는 키 갱신까지 지원한다. WireGuard handshake 성공을 disco Pong 성공으로 간주하지 말고 탐색을 계속한다. Go의 직접 best 승격은 Pong 처리에 있고 TSMP 키 변경 역시 재탐색을 요구한다. (`tailscale.com/wgengine/magicsock/endpoint.go:1990`, `tailscale.com/wgengine/magicsock/endpoint.go:1694`)

### 4.9 피어 릴레이 요약과 생략 판단

1. 릴레이 후보는 `CapabilityVersion>=121`이고 `peercap.RelayTarget` 권한으로 할당 가능한 노드다. 해당 피어도 relay capable이어야 탐색하며, 신뢰된 직접 경로에서는 relay 탐색을 하지 않고 탐색 간 최소 30초·개선 간격 1분을 둔다. (`tailscale.com/wgengine/magicsock/magicsock.go:2921`, `tailscale.com/wgengine/magicsock/magicsock.go:2977`, `tailscale.com/tailcfg/peercap/peercap.go:60`, `tailscale.com/wgengine/magicsock/endpoint.go:960`)
2. DERP로 relay server node에 AllocateRequest를 보내고, 응답의 Generation과 두 disco 키 쌍을 검증한다. 받은 endpoint를 CallMeMaybeVia로 상대에게 DERP 전달한다. 서버의 ServerDisco는 Bind handshake box에, 두 피어의 disco 키는 relayed Ping/Pong box에 쓰인다. (`tailscale.com/wgengine/magicsock/relaymanager.go:1038`, `tailscale.com/wgengine/magicsock/relaymanager.go:1085`, `tailscale.com/wgengine/magicsock/relaymanager.go:864`, `tailscale.com/wgengine/magicsock/relaymanager.go:918`, `tailscale.com/wgengine/magicsock/relaymanager.go:955`)
3. 각 참가자는 Geneve Control=1인 Bind → Challenge → Answer를 서버와 교환한다. 서버는 VNI·RemoteKey·nonzero Generation을 검사하며 Answer는 같은 진행 중 Generation이어야 한다. 클라이언트는 Challenge를 opaque 32바이트로 echo하고, 이어 Control 없는 peer Ping을 보내 Pong을 받아야 경로 준비 완료로 승격한다. 클라이언트는 handshake를 `min(BindLifetime,30초)`로 제한하고 probe Ping은 최대 10개다. (`tailscale.com/net/udprelay/server.go:175`, `tailscale.com/wgengine/magicsock/relaymanager.go:903`, `tailscale.com/wgengine/magicsock/relaymanager.go:928`, `tailscale.com/wgengine/magicsock/relaymanager.go:944`, `tailscale.com/wgengine/magicsock/relaymanager.go:1010`, `tailscale.com/wgengine/magicsock/relaymanager.go:728`)
4. **생략 판단 — M4의 직접 UDP+DERP에 peer relay는 필수 아님:** 기존 송신기는 직접 경로 신뢰 만료 시 DERP 병행으로 내려가며 CallMeMaybe/UDP Ping만으로 다시 직접 경로를 올릴 수 있다. relay 없는 빌드·`disable-relay-client`에서도 일반 CallMeMaybe/Ping 경로는 별도로 남는다. 다만 직접 불가능하고 DERP만 가능한 네트워크에서는 peer relay가 주는 성능 경로를 잃는다. (`tailscale.com/wgengine/magicsock/endpoint.go:635`, `tailscale.com/wgengine/magicsock/endpoint.go:1423`, `tailscale.com/wgengine/magicsock/magicsock.go:2387`, `tailscale.com/wgengine/magicsock/magicsock.go:3078`)
5. **“구현하지 않고 알리지도 않는다”의 한계:** Go는 별도 disco relay 지원 광고 비트가 아니라 **CapabilityVersion >=121**을 지원으로 본다. 따라서 Swiftail이 높은 Version을 광고하면서 relay endpoint만 생략한다고 상대가 미지원으로 아는 것은 아니다. `RelayTarget` 권한을 주지 않아 서버 후보가 되지 않는 것과 relay **클라이언트** 지원 신호는 별개다. `disable-relay-client`는 자기 node의 제어 속성으로 자기 탐색/CallMeMaybeVia 수신을 막는 규칙이며, 여기서 상대에게 보장된 일반 feature-negotiation ACK는 확인되지 않았다. (`tailscale.com/wgengine/magicsock/magicsock.go:2921`, `tailscale.com/wgengine/magicsock/endpoint.go:1759`, `tailscale.com/wgengine/magicsock/magicsock.go:3443`, `tailscale.com/wgengine/magicsock/magicsock.go:2387`, `tailscale.com/tailcfg/nodecap/nodecap.go:292`)
6. **구현 제안:** M4에서는 relay 타입·Geneve를 식별해 명시적으로 미지원 처리하고 직접/DERP 탐색을 유지하며, 시험 tailnet에서 Swiftail을 relay server로 배치하지 않는다. 이 범위의 상호 운용은 위 fallback 코드로 뒷받침되지만 “높은 CapabilityVersion을 포함한 모든 기능 계약을 만족한다”는 주장은 하지 않는다. 제어 서버까지 포함한 capability 광고 정책은 §8에 남긴다. (`tailscale.com/wgengine/magicsock/endpoint.go:1123`, `tailscale.com/wgengine/magicsock/endpoint.go:1184`, `tailscale.com/wgengine/magicsock/magicsock.go:2921`)

### 4.10 peer MTU 요약과 생략 판단

1. Peer MTU는 padded disco Ping으로 탐색한다. enabled이고 discovery 또는 크기 미지정 CLI Ping이면 MTU 후보별 Ping을 보낸다. 후보 wire MTU는 1280, 1360, 1400, 1500, 8000, 9000이며 Ping 길이는 IPv4에서 MTU−28, IPv6에서 MTU−48이다. 성공 Pong의 원래 요청 크기로 wireMTU를 기록하고 같은 주소면 큰 MTU가 더 좋다. (`tailscale.com/wgengine/magicsock/endpoint.go:1379`, `tailscale.com/net/tstun/mtu.go:77`, `tailscale.com/net/tstun/mtu.go:85`, `tailscale.com/wgengine/magicsock/endpoint.go:1910`, `tailscale.com/wgengine/magicsock/endpoint.go:1993`, `tailscale.com/wgengine/magicsock/endpoint.go:2060`)
2. macOS/Linux 지원 경로도 기본 `ShouldPMTUD=false`이고 제어·debug 설정으로 켠다. iOS는 `PeerMTUEnabled=false`인 stub 경로다. macOS의 활성화는 `IP_DONTFRAG`/`IPV6_DONTFRAG`를 설정한다. 이는 상대와 기능 협상 후 켜는 절차가 아니라 로컬 설정이다. (`tailscale.com/wgengine/magicsock/peermtu.go:38`, `tailscale.com/wgengine/magicsock/peermtu_stubs.go:4`, `tailscale.com/wgengine/magicsock/peermtu_stubs.go:14`, `tailscale.com/wgengine/magicsock/peermtu_darwin.go:14`, `tailscale.com/wgengine/magicsock/peermtu.go:86`)
3. **생략 판단:** Swiftail은 능동 MTU probe를 생략해도 된다. 상대가 보낸 padded Ping을 정상 파싱하고 작은 Pong으로 답하며, 내 데이터는 기본 safe TUN MTU=1280(최악 IPv6 WireGuard overhead 80을 포함한 safe wire MTU=1360)을 기준으로 제한한다는 구현 제안이다. 탐색 비활성 상태가 Go 자체의 정상 경로라는 근거는 충분하지만, 이 값조차 통과하지 못하는 특수 경로까지 보장하지 않는다. (`tailscale.com/disco/disco.go:169`, `tailscale.com/wgengine/magicsock/magicsock.go:2680`, `tailscale.com/wgengine/magicsock/peermtu.go:54`, `tailscale.com/net/tstun/mtu.go:38`, `tailscale.com/net/tstun/mtu.go:77`, `tailscale.com/net/tstun/mtu.go:94`, `tailscale.com/net/tstun/mtu.go:151`)

### 4.11 IPv6·hard NAT·UDP 차단

1. IPv4·IPv6는 같은 disco 형식과 경로 상태 기계를 쓰고 IP family에 따라 별도 UDP 소켓으로 보낸다. IPv6 bind 실패로 전체 기능을 끄지 않으며, 동등한 RTT에서는 IPv6가 +10점이다. CallMeMaybe의 IPv6 link-local은 zone을 실을 필드가 없고 Go도 후보에서 무시하므로 M4는 global IPv6를 대상으로 한다는 구현 제안이다. (`tailscale.com/wgengine/magicsock/magicsock.go:1636`, `tailscale.com/wgengine/magicsock/magicsock.go:1652`, `tailscale.com/wgengine/magicsock/magicsock.go:3881`, `tailscale.com/wgengine/magicsock/endpoint.go:2122`, `tailscale.com/disco/disco.go:219`, `tailscale.com/wgengine/magicsock/endpoint.go:2163`)
2. hard NAT는 목적지별 STUN mapping 변화를 기록하고, fixed port가 있으면 STUN IPv4+로컬 고정 포트라는 추가 후보를 시도한다. 성공한 Ping의 실제 출발지를 후보로 학습할 수 있지만, 이것이 모든 hard NAT 조합의 직접 경로를 보장하지는 않는다. **구현 제안:** M4 NAT 직접 연결 합격은 통과 가능한 NAT 구성에서 판정하고, 양쪽 hard NAT 등 직접 불가능 조건에서는 DERP 유지가 합격이다. (`tailscale.com/net/netcheck/netcheck.go:719`, `tailscale.com/wgengine/magicsock/magicsock.go:1343`, `tailscale.com/wgengine/magicsock/magicsock.go:2644`, `tailscale.com/wgengine/magicsock/endpoint.go:635`)
3. UDP가 막혀도 신뢰 가능한 UDP Pong이 없으면 DERP를 선택하는 경로는 남는다. DERP URL은 기본 HTTPS/443이고 node key 대상으로 WireGuard 암호문과 disco box를 전송한다. UDP 미지원 빌드도 DERP만으로 동작하는 코드가 있으며, `OnlyTCP443`에서는 STUN 송신·`sendUDPStd`의 UDP 송신·relay client 탐색을 각각 막는 분기가 있다. **구현 제안:** UDP 차단을 node offline으로 처리하지 말고 DERP 연결·데이터 경로를 유지한다. (`tailscale.com/wgengine/magicsock/endpoint.go:635`, `tailscale.com/derp/derphttp/derphttp_client.go:280`, `tailscale.com/wgengine/magicsock/derp.go:696`, `tailscale.com/wgengine/magicsock/magicsock.go:1535`, `tailscale.com/wgengine/magicsock/magicsock.go:3551`, `tailscale.com/wgengine/magicsock/magicsock.go:1632`, `tailscale.com/wgengine/magicsock/magicsock.go:1648`, `tailscale.com/wgengine/magicsock/magicsock.go:3078`)

## 5. 상수와 타이머

| 이름 | 값 | 구현상 의미 | 출처 |
| --- | --- | --- | --- |
| `NonceLen` | 24 bytes | 매 disco box의 무작위 nonce | `tailscale.com/disco/disco.go:39`, `tailscale.com/types/key/disco.go:223` |
| `poly1305AuthenticatorSize` | 16 bytes | disco 패킷 길이 계산 | `tailscale.com/wgengine/magicsock/endpoint.go:1294` |
| `pingTimeoutDuration` / `DefaultPingTimeout` | 5초 | TxID 응답 대기 | `tailscale.com/wgengine/magicsock/magicsock.go:4117`, `tailscale.com/tsconst/ping.go:9` |
| `discoPingInterval` / `DefaultPingInterval` | 5초 | 후보별 discovery Ping 최소 간격; CallMeMaybe는 초기화로 우회 | `tailscale.com/wgengine/magicsock/magicsock.go:4121`, `tailscale.com/tsconst/ping.go:13`, `tailscale.com/wgengine/magicsock/endpoint.go:2206` |
| `heartbeatInterval` | 3초 | 활성 best 경로 유지·재탐색 tick | `tailscale.com/wgengine/magicsock/magicsock.go:4097` |
| `trustUDPAddrDuration` | 6500ms | best UDP 단독 송신 신뢰 | `tailscale.com/wgengine/magicsock/magicsock.go:4101` |
| `sessionActiveTimeout` | 45초 | 외부 송신 유휴 heartbeat 중단, runtime 후보 만료·STUN idle 기준 | `tailscale.com/wgengine/magicsock/magicsock.go:4079`, `tailscale.com/wgengine/magicsock/endpoint.go:509`, `tailscale.com/wgengine/magicsock/endpoint.go:893` |
| `upgradeUDPDirectInterval` | 1분 | 신뢰된 느린 직접 경로 개선 탐색 | `tailscale.com/wgengine/magicsock/magicsock.go:4085`, `tailscale.com/wgengine/magicsock/endpoint.go:1001` |
| `goodEnoughLatency` | 5ms | 이 이하 신뢰된 직접 경로는 정기 개선 탐색 생략 | `tailscale.com/wgengine/magicsock/magicsock.go:4105` |
| `endpointsFreshEnoughDuration` | 27초 | CallMeMaybe 전 자기 엔드포인트 재측정 기준 | `tailscale.com/wgengine/magicsock/magicsock.go:4109` |
| 주기 ReSTUN | 무작위 20~26초 | 활성 상태의 측정·NAT mapping 유지 | `tailscale.com/wgengine/magicsock/magicsock.go:899` |
| `ReportTimeout` / `stunProbeTimeout` | 5초 / 3초 | netcheck 전체 / UDP STUN phase 제한 | `tailscale.com/net/netcheck/netcheck.go:59` |
| `fullReportInterval` | 5분 | 다음 GetReport에서 모든 DERP region 재탐색 | `tailscale.com/net/netcheck/netcheck.go:1374` |
| `endpointTrackerLifetime` | 5분 10초 | 자기 광고 주소 캐시 | `tailscale.com/wgengine/magicsock/endpoint_tracker.go:18` |
| `endpointTrackerMaxPerAddr` | 6 | 같은 IP당 캐시 endpoint 상한 | `tailscale.com/wgengine/magicsock/endpoint_tracker.go:24` |
| `pongHistoryCount` | 64 | 후보별 RTT 이력 ring 크기; 최소 구현은 최신값만 저장하는 제안 | `tailscale.com/wgengine/magicsock/endpoint.go:489`, `tailscale.com/wgengine/magicsock/endpoint.go:525` |
| runtime 후보 정리 trigger | 후보 수 >100 | 만료 후보 정리; 100개 강제 hard cap은 아님 | `tailscale.com/wgengine/magicsock/endpoint.go:1834` |
| `upgradeUDPRelayInterval` / `discoverUDPRelayPathsInterval` | 1분 / 30초 | relay 개선 / 최소 탐색 간격 | `tailscale.com/wgengine/magicsock/magicsock.go:4089` |
| `allocateUDPRelayEndpointRequestTimeout` / `ServerRetryAfter` | 10초 / 3초 | relay 할당 대기 / 한 번 재요청 | `tailscale.com/wgengine/magicsock/relaymanager.go:1036`, `tailscale.com/wgengine/magicsock/relaymanager.go:1066`, `tailscale.com/net/udprelay/endpoint/endpoint.go:16` |
| `maxHandshakeLifetime` / `limitPings` | 30초 / 10 | relay Bind·probe 클라이언트 상한 | `tailscale.com/wgengine/magicsock/relaymanager.go:928` |
| `defaultBindLifetime` / `defaultSteadyStateLifetime` | 30초 / 5분 | relay 서버 기본 수명; wire에서는 전달받은 값 사용 | `tailscale.com/net/udprelay/server.go:52`, `tailscale.com/wgengine/magicsock/relaymanager.go:932` |
| UDP lifetime 측정 `Cliffs` / `CycleCanStartEvery` | 10·30·60초 / 24시간 | 선택적 유휴 경로 수명 측정 | `tailscale.com/wgengine/magicsock/endpoint.go:270` |
| `udpLifetimeProbeCliffSlack` / `udpLifetimeProbeSchedulingTolerance` | 2초 / 250ms | 선택적 수명 측정 여유 / scheduling 허용차 | `tailscale.com/wgengine/magicsock/endpoint.go:160` |
| 자동 error Rebind 제한 / 재결속 후 DERP Ping 제한 | 5초 / 3초 | 소켓 재시작 폭주 억제 / DERP 생존 확인 | `tailscale.com/wgengine/magicsock/magicsock.go:1618`, `tailscale.com/wgengine/magicsock/derp.go:923` |
| `safeTUNMTU` / `SafeWireMTU()` | 1280 / 1360 bytes | MTU 탐색 생략 시 기준; wire 값은 1280+80 계산 | `tailscale.com/net/tstun/mtu.go:77`, `tailscale.com/net/tstun/mtu.go:107`, `tailscale.com/net/tstun/mtu.go:153` |

## 6. Swiftail 최소 구현과 구현 순서

다음은 **M4를 위한 구현 제안**이다. 각 단계의 근거는 위 Go 송수신 경로이며, 모든 Go 내부 기능을 동일하게 복제하라는 요구가 아니다.

1. **안정적인 DERP 데이터 경로와 피어 식별부터:** netmap의 node key·disco key·HomeDERP·Endpoints를 별도로 저장하고 WireGuard 암호문을 DERP로 주고받는다. 인증으로 판명된 피어와 임시 UDP 출발 주소를 연결할 수 있게 한다. (`tailscale.com/wgengine/magicsock/endpoint.go:1733`, `tailscale.com/wgengine/magicsock/derp.go:734`, `tailscale.com/wgengine/magicsock/magicsock.go:4524`)
2. **disco codec+box, 단일 UDP 수신 분류:** Ping/Pong/CallMeMaybe와 미지 타입·버전 처리를 구현하고, 나머지 relay 타입·Geneve는 식별해 미지원으로 처리한다. IPv4-mapped 주소·BE port·nonce 중복 부착 금지·잘못된 box 폐기를 먼저 검증한다. (`tailscale.com/disco/disco.go:81`, `tailscale.com/disco/disco.go:219`, `tailscale.com/types/key/disco.go:219`, `tailscale.com/wgengine/magicsock/magicsock.go:2143`)
3. **LAN·명시 loopback:** 후보 fan-out Ping → 수신 출발지 학습/Pong → TxID 매칭 → best 승격 → 직접 WireGuard 전송을 완성한다. RTT와 신뢰 타이머를 데이터 송신 경로에 연결한다. (`tailscale.com/wgengine/magicsock/endpoint.go:1423`, `tailscale.com/wgengine/magicsock/magicsock.go:2644`, `tailscale.com/wgengine/magicsock/endpoint.go:1929`, `tailscale.com/wgengine/magicsock/endpoint.go:635`)
4. **NAT 통과:** 동일 UDP 소켓 STUN → 로컬+관측 주소 광고 → 별도 map update → UDP Ping과 DERP CallMeMaybe → 상대의 즉시 역방향 Ping을 연결한다. 자기 주소 27초 freshness와 CallMeMaybe 수신 시 rate-limit 초기화를 포함한다. (`tailscale.com/wgengine/magicsock/magicsock.go:1632`, `tailscale.com/wgengine/magicsock/magicsock.go:2693`, `tailscale.com/wgengine/magicsock/endpoint.go:2206`, `tailscale.com/tailcfg/tailcfg.go:1513`)
5. **하강·재승격:** 3초 heartbeat·6.5초 trust·5초 ping timeout·45초 idle, 만료 시 UDP+DERP 복제, 주기 full ping, network change Rebind+ReSTUN을 구현한다. 직접 단절 뒤 DERP 데이터가 흐르는 동안 복구된 UDP의 새 Pong으로 다시 승격시킨다. (`tailscale.com/wgengine/magicsock/endpoint.go:635`, `tailscale.com/wgengine/magicsock/endpoint.go:872`, `tailscale.com/wgengine/magicsock/endpoint.go:1244`, `tailscale.com/wgengine/magicsock/endpoint.go:1998`, `tailscale.com/wgengine/userspace.go:1218`)
6. **현재 Go 피어와의 수명 통합:** global IPv6와 Darwin/iOS 인터페이스 선택을 더하고, WireGuard 직후 TSMP disco 광고 소비·키 변경 재탐색을 검증한다. (`tailscale.com/net/netns/netns_darwin.go:295`, `tailscale.com/net/packet/tsmp.go:276`, `tailscale.com/wgengine/magicsock/endpoint.go:1694`)

| 뒤로 미룰 부분 | 최소 구현의 경계와 근거 | 출처 |
| --- | --- | --- |
| UPnP/PMP/PCP port mapping | 옵션으로 없어도 로컬+STUN 경로가 존재; hard NAT 성공 범위는 줄 수 있음 | `tailscale.com/wgengine/magicsock/magicsock.go:681`, `tailscale.com/wgengine/magicsock/magicsock.go:1278`, `tailscale.com/wgengine/magicsock/magicsock.go:1334` |
| peer relay 서버·클라이언트 | §4.9의 capability 한계를 문서화하고 직접+DERP를 우선; relay-only 성능은 제공하지 않음 | `tailscale.com/wgengine/magicsock/magicsock.go:2921`, `tailscale.com/wgengine/magicsock/endpoint.go:635` |
| 능동 peer MTU 탐색 | 기본 비활성·iOS stub과 호환; padded Ping 수신/Pong은 유지 | `tailscale.com/wgengine/magicsock/peermtu.go:54`, `tailscale.com/wgengine/magicsock/peermtu_stubs.go:18`, `tailscale.com/disco/disco.go:169` |
| UDP lifetime cliff probe | 켜졌을 때만 별도 구성; 기본 heartbeat·idle 전환 구현을 먼저 완성 | `tailscale.com/wgengine/magicsock/endpoint.go:1710`, `tailscale.com/wgengine/magicsock/endpoint.go:893` |
| 자기 광고 5분 10초 캐시·cloud metadata | 최신 관측 주소와 로컬 주소로 먼저 검증; 캐시는 일시적인 관측 소실 안정화용 | `tailscale.com/wgengine/magicsock/endpoint_tracker.go:105`, `tailscale.com/wgengine/magicsock/magicsock.go:1363`, `tailscale.com/wgengine/magicsock/magicsock.go:1384` |
| lazy peer 생성·batching·raw disco 수신 최적화 | 알려진 소수 피어를 미리 구성하고 일반 UDP receive로 시작; 주소의 인증 후 대응은 유지 | `tailscale.com/wgengine/wgcfg/device.go:43`, `tailscale.com/wgengine/magicsock/magicsock.go:1909`, `tailscale.com/wgengine/magicsock/rebinding_conn.go:127`, `tailscale.com/wgengine/magicsock/endpoint.go:465` |
| 64개 RTT 이력·상세 관측 지표 | 최신 RTT로 best 비교 가능; 이력 조회·통계는 나중에 추가하는 제안 | `tailscale.com/wgengine/magicsock/endpoint.go:489`, `tailscale.com/wgengine/magicsock/endpoint.go:525`, `tailscale.com/wgengine/magicsock/endpoint.go:1993` |

## 7. 상호 운용 시험에서 확인할 것

아래는 **시험 계획이며 실행 결과가 아니다**. 기대 조건은 인용한 Go 분기에서 도출했다.

1. **codec/crypto:** 9종 v0 payload와 모든 offset·길이·BE integer, IPv4-mapped/IPv6, Ping zero NodeKey/padding, 짧은 payload·미지 type·미지 version의 타입별 처리를 대조한다. 서로의 box를 열고 nonce와 공개 키를 변조한 패킷이 채택되지 않는지 확인한다. (`tailscale.com/disco/disco.go:81`, `tailscale.com/disco/disco.go:169`, `tailscale.com/disco/disco.go:232`, `tailscale.com/disco/disco.go:384`, `tailscale.com/disco/disco.go:491`, `tailscale.com/disco/disco.go:594`, `tailscale.com/types/key/disco.go:231`)
2. **LAN/loopback:** Swift→Go와 Go→Swift 각각을 최초 송신자로 삼아 UDP Pong 이후 직접 WireGuard 데이터가 흐르는지 확인한다. loopback은 §4.6의 광고 조건을 명시하고, 같은 LAN 후보와 STUN 후보가 모두 있을 때 betterAddr 점수를 비교한다. (`tailscale.com/wgengine/magicsock/endpoint.go:1990`, `tailscale.com/wgengine/magicsock/endpoint.go:2059`, `tailscale.com/wgengine/magicsock/magicsock.go:1411`)
3. **피어 식별:** 아직 모르는 IP:port의 인증된 Ping, 모르는 주소의 WireGuard initiation/data, 같은 disco key의 복수 node key, 잘못된 Ping.NodeKey·잘못된 DERP source 조합, 미지 TxID Pong이 잘못된 node/best로 반영되지 않는지 확인한다. (`tailscale.com/wgengine/magicsock/magicsock.go:2547`, `tailscale.com/wgengine/magicsock/magicsock.go:1909`, `tailscale.com/wgengine/magicsock/endpoint.go:1935`, `tailscale.com/wgengine/magicsock/magicsock.go:2405`)
4. **NAT:** 양쪽 NAT와 한쪽 NAT 각각에서 STUN→광고→CallMeMaybe→역방향 Ping으로 직접 승격되는지 확인한다. 27초 이상 유휴 뒤 재연결에서 CallMeMaybe가 오래된 주소로 먼저 나가지 않는지, 5초 이내 중복 탐색에도 CallMeMaybe 수신은 새 Ping을 발생시키는지 본다. hard NAT 직접 성공은 구성별 결과로 기록한다. (`tailscale.com/wgengine/magicsock/magicsock.go:2702`, `tailscale.com/wgengine/magicsock/endpoint.go:2206`, `tailscale.com/wgengine/magicsock/magicsock.go:1343`)
5. **M4 하강·회복:** 직접 UDP를 차단하고 DERP는 유지해 마지막 best Pong 이후 6.5초 신뢰 만료부터 DERP 복제가 시작되는지 본다. 단일 Ping loss만으로 즉시 best를 삭제하지 않는지, UDP 허용 복원 후 discovery Pong으로 직접 단독 전송에 복귀하는지 확인한다. 단절 시각부터 항상 정확히 6.5초 안에 도달한다는 별도 SLA로 해석하지 않는다. (`tailscale.com/wgengine/magicsock/endpoint.go:635`, `tailscale.com/wgengine/magicsock/endpoint.go:1244`, `tailscale.com/wgengine/magicsock/endpoint.go:2018`)
6. **유휴·링크 이동:** 외부 송신 45초 후 heartbeat 중단, 다음 활동의 재탐색, 로컬 포트 변경, Wi-Fi↔다른 링크 이동, 이전 receive의 종료와 새 소켓의 수신 재개, DERP의 유지/재연결과 MapRequest 갱신을 확인한다. (`tailscale.com/wgengine/magicsock/endpoint.go:893`, `tailscale.com/wgengine/magicsock/endpoint.go:1123`, `tailscale.com/wgengine/magicsock/rebinding_conn.go:61`, `tailscale.com/wgengine/userspace.go:1218`, `tailscale.com/wgengine/magicsock/derp.go:905`)
7. **선택 기능 생략:** Go PMTUD를 켜고 Swift는 끈 상태에서 padded Ping 응답과 1280 기준 데이터가 동작하는지, relay 서버가 없는/있는 환경에서 미지원 relay 메시지가 직접+DERP 흐름을 방해하지 않는지 검증한다. 후자는 높은 CapabilityVersion을 광고할 때의 실제 상대 행동도 관측한다. (`tailscale.com/wgengine/magicsock/endpoint.go:1385`, `tailscale.com/wgengine/magicsock/endpoint.go:1184`, `tailscale.com/wgengine/magicsock/magicsock.go:2921`)
8. **IPv6/UDP 차단/키:** global IPv6 직접 경로와 IPv4 fallback, UDP 전면 차단 시 DERP 데이터 지속, 새 WireGuard 세션 직후 TSMP 광고 소비, control 키와 TSMP 키가 달라지는 전환에서 disco 재탐색을 확인한다. (`tailscale.com/wgengine/magicsock/magicsock.go:3881`, `tailscale.com/wgengine/magicsock/magicsock.go:3551`, `tailscale.com/net/packet/tsmp.go:276`, `tailscale.com/wgengine/magicsock/endpoint.go:1645`)

## 8. 확인하지 못한 것

- **NaCl box 내부 알고리즘의 독립 구현 명세·test vector:** 허용 모듈에서 직접 확인한 것은 `box.Precompute`, 랜덤 24바이트 nonce, Seal/Open 호출 경계와 인증자 16바이트다. 외부 `golang.org/x/crypto` 소스는 읽지 않았으므로 내부 KDF·스트림 암호·태그의 세부 배치 및 Swift crypto primitive와의 일치 검증은 남는다. (`tailscale.com/types/key/disco.go:76`, `tailscale.com/types/key/disco.go:219`, `tailscale.com/wgengine/magicsock/endpoint.go:1294`)
- **제어 서버까지 포함한 미지원 기능 광고 계약:** Go의 relay 판단은 Version >=121이며 별도 미지원 ACK를 확인하지 못했다. 높은 Version에서 relay를 생략할 때의 모든 정책 조합, 낮은 Version을 택했을 때 다른 기능·서버 동작에 미치는 영향은 이 노트로 보장하지 않는다. (`tailscale.com/wgengine/magicsock/magicsock.go:2921`, `tailscale.com/tailcfg/tailcfg.go:1437`)
- **Swift/iOS 플랫폼 통합의 실제 효과:** Darwin sockopt와 Apple extension 예외는 확인했지만 Swift API의 소켓 결속 동등성, entitlement, suspend/resume, 실제 기기의 Wi-Fi·셀룰러 전환은 시험하지 않았다. (`tailscale.com/net/netns/netns_darwin.go:295`, `tailscale.com/net/netns/netns.go:78`)
- **외부 WireGuard 구현 내부:** lazy endpoint 콜백·세션 성립 priority-message의 tailscale 쪽 연결은 확인했지만 외부 `wireguard-go`의 정확한 실행 순서·Noise 처리·중복 데이터 제거는 허용 소스 밖이므로 검증하지 않았다. (`tailscale.com/wgengine/magicsock/magicsock.go:4481`, `tailscale.com/wgengine/magicsock/magicsock.go:4524`, `tailscale.com/wgengine/userspace.go:760`)
- **환경별 직접 연결 성공률·복구 지연:** 실제 NAT·방화벽·IPv6 경로·Go tailscaled와의 패킷 캡처/실행 검증은 하지 않았다. 관측한 mapping 변화와 후보 탐색·DERP fallback은 소스 근거가 있지만 모든 hard NAT에서 직접 연결을 보장하는 근거는 아니다. (`tailscale.com/net/netcheck/netcheck.go:719`, `tailscale.com/wgengine/magicsock/magicsock.go:1343`, `tailscale.com/wgengine/magicsock/endpoint.go:635`)
