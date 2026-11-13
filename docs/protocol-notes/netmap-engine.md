# netmap → 엔진 계층 (피어 설정 · 경로 · 패킷 필터 · TUN 래퍼)

| 항목 | 값 |
| --- | --- |
| 기준 버전 | `tailscale.com` v1.104.6 (CapabilityVersion 148), `github.com/tailscale/wireguard-go` v0.0.0-20261106233718-9e0ab45c16ca |
| 작성 모델 | Claude Sonnet 5.5 (`claude-sonnet-5-5`), 2026-11-13 |
| 검증 상태 | 미검증. 다른 제공자의 모델이 아래 출처와 대조해야 한다 |
| 쓰는 마일스톤 | M3(netmap 피어와만 통신, ACL 준수), M5(iOS 패킷 터널에 주소·경로 전달) |

출처는 모듈 루트 기준 `경로:줄`이다. `wireguard-go/…`는 위 wireguard-go 모듈 루트 기준이다.

## 1. 범위

**다루는 것**
- netmap 피어 → WireGuard 피어별 `AllowedIPs`, 건너뛰는 피어, 피어 생성·삭제 시점
- 로컬 주소·OS 경로 목록(라우터 설정), iOS의 경로 구성
- `tailcfg.FilterRule` 해석과 수신·송신 판정, 상태 추적, 거절 응답, 로그
- TUN과 WireGuard 사이 래퍼(`net/tstun/wrap.go`)의 처리 순서, 100.100.100.100 가로채기, TSMP
- 필터가 읽는 IP·전송 계층 헤더 필드
- `PeerCapMap`/`CapGrant`와 WhoIs에 필요한 netmap 조회

**다루지 않는 것(다른 노트)**: Noise 핸드셰이크·타이머(wireguard.md), MapResponse 파싱·델타 병합·`PacketFilters` 병합 규칙(control-map.md), disco/magicsock 경로 선택(disco-magicsock.md), MagicDNS 응답·DNS 설정(dns-state-node.md).

### 1.1 먼저 알아 둘 것: 이 버전의 구조는 이전 가정과 다르다

1. **`wgengine/wgcfg/nmcfg`는 없다.** 피어별 AllowedIPs 계산은 `net/routemanager`의 `RouteManager`가 맡는다. `nmcfg`는 테스트 주석에만 남아 있다(`tailscale.com/net/routemanager/routemanager_test.go:559`, `:594`, `:613`).
2. **`wgcfg.Config`에는 피어가 없다.** 개인 키와 로컬 주소만 있다(`tailscale.com/wgengine/wgcfg/config.go:17-27`). 피어는 wireguard-go가 키로 질의할 때(`SetPeerConfigFunc` 콜백)와 netmap 델타마다(`SyncDevicePeer`) 만들어진다(`tailscale.com/wgengine/wgengine.go:187-200`, `tailscale.com/wgengine/userspace.go:683-717`).
3. **송신 피어는 AllowedIPs 트라이가 아니라 콜백으로 고른다.** `SetPeerByIPPacketFunc`가 설치되면 wireguard-go는 트라이를 쓰지 않는다(`wireguard-go/device/allowedips.go:363-372`, `tailscale.com/ipn/ipnlocal/local.go:640`). 수신 시 출발지 검사는 피어별 AllowedIPs로 한다(`wireguard-go/device/receive.go:510`, `:528`).
4. **iOS는 CGNAT 한 경로를 쓰지 않는다(기본).** `shouldUseOneCGNATRoute`는 macOS·android·plan9와 제어 서버 지시에서만 true다(`tailscale.com/ipn/ipnlocal/local.go:6364-6399`). 그래서 iOS는 피어마다 /32이고, 개수가 10,000을 넘을 때만 /10 하나로 합친다(§4.6).
5. **유휴 피어는 wireguard-go가 스스로 지운다.** 지연 생성된 피어는 마지막 세션 이후 540초(`RejectAfterTime*3`)에 제거된다(§4.4).

## 2. 소스 지도

| 역할 | 파일 |
| --- | --- |
| 피어별 AllowedIPs·송신 테이블·OS 경로 계산 | `tailscale.com/net/routemanager/routemanager.go` |
| 위 결과를 엔진에 연결 | `tailscale.com/ipn/ipnlocal/node_backend.go`, `resolve.go`, `local.go`(`authReconfigLocked`, `routerConfigLocked`, `updateFilterLocked`, `setNetMapLocked`) |
| 피어 만료 표시 | `tailscale.com/ipn/ipnlocal/expiry.go` |
| 엔진(Reconfig, 피어 동기화, 로컬 패킷) | `tailscale.com/wgengine/userspace.go` |
| WireGuard 피어 지연 생성 | `tailscale.com/wgengine/wgcfg/device.go`, `wireguard-go/device/device.go` |
| 패킷 필터 | `tailscale.com/wgengine/filter/{filter,match,tailcfg}.go`, `filtertype/filtertype.go` |
| TUN 래퍼 | `tailscale.com/net/tstun/wrap.go` |
| IP 헤더 해석·TSMP | `tailscale.com/net/packet/{packet,ip4,ip6,icmp4,icmp6,tsmp}.go` |
| 라우터 설정 형식·콜백 라우터 | `tailscale.com/wgengine/router/router.go`, `callback.go` |
| 특수 주소 | `tailscale.com/net/tsaddr/tsaddr.go` |

## 3. 와이어 형식

### 3.1 필터가 읽는 IPv4 헤더 필드 (`Parsed.decode4`)

| 오프셋 | 길이 | 필드 | 읽는 방법 | 출처 |
| --- | --- | --- | --- | --- |
| 0 | 4비트 상위 | 버전 | `b[0]>>4`가 4 | `tailscale.com/net/packet/packet.go:114` |
| 0 | 4비트 하위 | IHL | `(b[0]&0x0F)<<2`가 전송 계층 시작 오프셋. 최솟값 검사는 없고 전체 길이보다 크면 Unknown | `packet.go:154-159` |
| 2 | 2 | 전체 길이 | 빅엔디언. `len(b)`가 이보다 작으면 Unknown. 이후 바이트는 무시 | `packet.go:141-146` |
| 6 | 2 | 플래그·조각 오프셋 | `0x2000`=MF, `&0x1FFF`=오프셋(8바이트 단위) | `packet.go:176-178` |
| 9 | 1 | 프로토콜 | 그대로 `IPProto` | `packet.go:140` |
| 12 | 4 | 출발 주소 | | `packet.go:149` |
| 16 | 4 | 목적 주소 | | `packet.go:150` |

버퍼가 20바이트 미만이면 `IPVersion=0`, `IPProto=Unknown`(`packet.go:133-137`). 버퍼 길이 0은 `IPVersion=0`(`packet.go:108-112`)이고 필터는 이를 WireGuard keepalive로 보고 통과시킨다(§4.8).

### 3.2 필터가 읽는 IPv6 헤더 필드 (`Parsed.decode6`)

| 오프셋 | 길이 | 필드 | 읽는 방법 | 출처 |
| --- | --- | --- | --- | --- |
| 0 | 4비트 상위 | 버전 | 6 | `packet.go:114` |
| 4 | 2 | 페이로드 길이 | 전체 길이 = 값 + 40. `len(b)`가 작으면 Unknown | `packet.go:279-284` |
| 6 | 1 | 다음 헤더 | 그대로 `IPProto` | `packet.go:278` |
| 8 | 16 | 출발 주소 | | `packet.go:288` |
| 24 | 16 | 목적 주소 | | `packet.go:289` |

확장 헤더는 **프래그먼트 헤더(다음 헤더 44)만** 해석한다. 기본 헤더의 다음 헤더 값이 44일 때만이며, 홉바이홉·라우팅·목적지 옵션·AH/ESP는 해석하지 않고 Unknown으로 떨어진다(`packet.go:293-311`).

프래그먼트 헤더(8바이트, 전송 계층 시작 오프셋 40에서 시작)(`packet.go:375-409`):

| 오프셋 | 길이 | 필드 | 사용 |
| --- | --- | --- | --- |
| 0 | 1 | 다음 헤더 | 첫 조각이면 이 값이 새 `IPProto` |
| 2 | 2 | 조각 오프셋 | 빅엔디언 값 `>>3` |
| 그 외 | | | 읽지 않음(MF 비트 포함) |

### 3.3 조각화 처리 (IPv4·IPv6 공통 규칙)

| 조건 | 결과 | 출처 |
| --- | --- | --- |
| 첫 조각(오프셋 0) | 일반 패킷처럼 전송 계층 헤더 전체가 들어 있어야 한다. 모자라면 `IPProto=Unknown` | `packet.go:180-248` |
| 첫 조각이 아님, 오프셋 < `minFragBlks`(=(60+20)/8=10블록) | `Unknown` (겹침 공격 방지) | `packet.go:25`, `:251-259`, `:403-406` |
| 첫 조각이 아님, 오프셋 ≥ 10 | `IPProto=Fragment`(0xFF, 내부 표지). 포트·플래그는 읽지 않는다 | `packet.go:266`, `:407` |
| IPv4 TSMP이고 MF 설정 | `Unknown` (조각난 TSMP 금지) | `packet.go:230-235` |
| 와이어에서 프로토콜 값이 0xFF | `Unknown`으로 되돌림 | `packet.go:243-248`, `:359-364` |

### 3.4 전송 계층에서 읽는 필드

| 프로토콜 (번호) | 최소 길이 | 읽는 값 | 출처 |
| --- | --- | --- | --- |
| TCP (6) | 20 | 출발 포트 `sub[0:2]`, 목적 포트 `sub[2:4]`, 플래그 `sub[13]`, 헤더 길이 `(sub[12]&0xF0)>>2`(→ `dataofs`) | `packet.go:202-212`, `:324-334` |
| UDP (17) | 8 | 포트 `sub[0:2]`, `sub[2:4]` | `packet.go:213-221` |
| SCTP (132) | 12 | 포트 `sub[0:2]`, `sub[2:4]` (페이로드 오프셋은 설정하지 않음) | `packet.go:222-229` |
| ICMPv4 (1) | 4 | 포트는 0으로 고정, `dataofs = subofs+4` | `packet.go:185-193` |
| ICMPv6 (58) | 4 | 포트 0, `dataofs = subofs+4` | `packet.go:316-323` |
| IGMP (2) | 8 | 읽는 값 없음 (`IPProto`만 유지) | `packet.go:194-201` |
| TSMP (99) | 7 | `dataofs = subofs` (페이로드 = IP 헤더 바로 뒤 전부) | `tailscale.com/net/packet/tsmp.go:23`, `packet.go:230-242`, `:351-358` |

프로토콜 번호 상수: Unknown 0(내부), ICMPv4 1, IGMP 2, TCP 6, UDP 17, ICMPv6 58, SCTP 132, TSMP 99, Fragment 0xFF(내부) (`tailscale.com/types/ipproto/ipproto.go:46-75`). 정의에서 확인한 값은 TCP 0x06, UDP 0x11, ICMPv6 0x3a, SCTP 0x84이다(`ipproto.go:49-56`).

**구현 주의**: Go의 `Parsed`는 재사용되며 ICMP 외 프로토콜에서는 이전 패킷의 포트·TCP 플래그가 남을 수 있다(`packet.go:53-80`, `:185-248`에서 ICMP만 포트를 0으로 쓴다). Swift에서는 디코드마다 포트와 플래그를 0으로 초기화하는 것이 안전하다. 필터는 포트·플래그를 TCP/UDP/SCTP에서만 읽는다(§4.8).

ICMP 종류 판별(`packet.go:497-539`, 모두 `len(b) >= subofs+8`을 요구):

| 판별 | ICMPv4 | ICMPv6 |
| --- | --- | --- |
| 에코 요청 | type 8, code 0 | type 128, code 0 |
| 에코 응답 | type 0, code 0 | type 129, code 0 |
| 오류 | type 3, 11, 0x12 | type 1, 2, 3, 4 |

값 출처: `tailscale.com/net/packet/icmp4.go:22-26`, `icmp6.go:22-27`. ICMPv4 매개변수 문제 상수가 0x12인 점은 §8에 적는다.

에코 응답 식별(진단 ping용): `EchoIDSeq` = ICMP 헤더 뒤 4바이트(식별자·순번)를 **리틀엔디언 uint32**로 읽은 값, 오프셋은 IPv4 20+4, IPv6 40+4 고정(`packet.go:545-562`).

### 3.5 Swiftail이 직접 만드는 패킷의 IP 헤더 (`IP4Header.Marshal`, `IP6Header.Marshal`)

IPv4(20바이트, 옵션 없음)(`tailscale.com/net/packet/ip4.go:30-60`):

| 오프셋 | 길이 | 값 |
| --- | --- | --- |
| 0 | 1 | `0x45` (버전 4를 위 4비트, IHL 5를 아래 4비트) |
| 1 | 1 | 0 |
| 2 | 2 | 전체 길이(헤더+페이로드), 빅엔디언 |
| 4 | 2 | IPID |
| 6 | 2 | 0 (플래그·오프셋) |
| 8 | 1 | TTL 64 |
| 9 | 1 | 프로토콜 |
| 10 | 2 | 헤더 체크섬(RFC 1071), 계산 전 0 |
| 12 | 4 | 출발 |
| 16 | 4 | 목적 |

IPv6(40바이트)(`tailscale.com/net/packet/ip6.go:26-45`): 바이트 0~3 = `0x60` + 하위 20비트에 IPID(흐름 레이블), 4~5 = 페이로드 길이, 6 = 다음 헤더, 7 = 홉 한도 64, 8~23 출발, 24~39 목적.

응답 만들기(`ToResponse`): 출발·목적을 맞바꾸고 IPID를 반전한다. IPv4는 `^IPID`(16비트), IPv6는 `^IPID & 0xFFFFF`(`ip4.go:66-70`, `ip6.go:51-55`).

### 3.6 TSMP (IP 프로토콜 99, WireGuard 암호화 안에서만 오간다)

IP 헤더 바로 뒤에 타입 1바이트가 온다(`tailscale.com/net/packet/tsmp.go:4-8`, `:66-81`).

| 타입 | 바이트 | 이름 |
| --- | --- | --- |
| `!` (0x21) | 7 또는 8 | 연결 거절 |
| `p` (0x70) | 9 | ping 요청 |
| `o` (0x6F) | 11 (파서는 9 이상 허용) | pong 응답 |
| `a` (0x61) | 33 | disco 키 광고 |

**거절(`!`)** (`tsmp.go:25-60`, `:148-188`, `:194-212`)

| 오프셋(IP 헤더 뒤) | 길이 | 필드 |
| --- | --- | --- |
| 0 | 1 | `'!'` |
| 1 | 1 | 거절된 흐름의 IP 프로토콜 번호 |
| 2 | 1 | 이유: `A` ACL, `S` shields-up, `F` IP 포워딩 꺼짐, `W` 호스트 방화벽, `T` 앱 커넥터 transit IP 미등록 |
| 3 | 2 | 원래 흐름의 **출발 포트**, 빅엔디언 |
| 5 | 2 | 원래 흐름의 **목적 포트**, 빅엔디언 |
| 7 | 1 | (선택) 플래그. 비트 0x1 = MaybeBroken |

- 보낼 때 IP 출발 = 거절한 쪽(원래 패킷의 목적 주소), IP 목적 = 원래 출발 주소이고 IPID는 0이다(`wrap.go:1217-1228`). 받는 쪽은 `Src = (IP 목적 주소, p[3:5])`, `Dst = (IP 출발 주소, p[5:7])`로 원래 흐름을 복원한다(`tsmp.go:199-206`).
- 플래그 바이트는 MaybeBroken일 때만 붙는다(`tsmp.go:128-130`, `:180-186`).
- 가장 작은 크기: IPv4 20+7=27바이트(`Len` 계산 `tsmp.go:132-146`).

**ping(`p`)**: `'p'` + 임의 8바이트 = 9바이트(`tsmp.go:214-233`).
**pong(`o`)**: `'o'` + ping의 8바이트 그대로 + `PeerAPIPort`(uint16 빅엔디언) = 11바이트(`tsmp.go:235-274`). pong의 IP 헤더는 ping 헤더에 `ToResponse`를 적용한 것이다(`wrap.go:1454-1475`). PeerAPI를 열지 않으면 포트는 0이다(`wrap.go:1458-1460`).
**disco 키 광고(`a`)**: `'a'` + 32바이트 disco 공개 키 = 33바이트(`tsmp.go:276-331`). WireGuard 세션이 맺어진 직후 "우선 메시지"로 보내며 길이 상한은 512바이트다(`wireguard-go/device/device.go:738`, `tailscale.com/wgengine/magicsock/magicsock.go:4631-4676`). IP 출발은 자기 주소 중 상대 주소와 같은 계열의 첫 단일 IP, 목적은 상대 주소다(`magicsock.go:4631-4676`).

### 3.7 100.100.100.100로 가는 ICMP 에코 응답

`wrap.go:753-769`: 로컬이 보낸 에코 요청의 목적 `AddrPort`가 `100.100.100.100:0` 또는 `[fd7a:115c:a1e0::53]:0`이면, 요청 헤더에 `ToResponse`(type→에코 응답, code 0, 주소 맞바꿈)를 적용하고 **원래 ICMP 페이로드(식별자·순번·데이터)를 그대로** 붙여 `InjectInboundCopy`로 OS 쪽에 돌려준다. 원 패킷은 `DropSilently`한다(`icmp4.go:94-100`, `icmp6.go:98-104`, `packet.go:467-479`). 체크섬은 표준 ICMP 방식(IPv6는 의사 헤더 포함, `icmp6.go:106-140`)이다.

### 3.8 `tailcfg.FilterRule` (제어 서버가 보내는 JSON 필드)

| 필드 | 타입 | 의미 | 출처 |
| --- | --- | --- | --- |
| `SrcIPs` | 문자열 배열 | 출발지 집합 (문법은 아래) | `tailscale.com/tailcfg/tailcfg.go:1719-1728` |
| `SrcBits` | 정수 배열 | 폐지됨. **비어 있지 않으면 규칙 전체 변환 실패** | `tailcfg.go:1730-1745`, `tailscale.com/wgengine/filter/tailcfg.go:38-40` |
| `DstPorts` | `NetPortRange` 배열 | `{IP 문자열, Bits(폐지), Ports{First, Last}}`. `Bits`가 있으면 변환 실패 | `tailcfg.go:1573-1578`, `filter/tailcfg.go:75-78` |
| `IPProto` | 정수 배열 | 비어 있으면 TCP·UDP·ICMPv4·ICMPv6. 0~255 밖의 값은 무시 | `tailcfg.go:1753-1762`, `filter/tailcfg.go:21-26`, `:50-60` |
| `CapGrant` | `CapGrant` 배열 | `{Dsts []Prefix, Caps []Cap(폐지), CapMap map[Cap][]JSON}` | `tailcfg.go:1581-1596`, `:1764-1774` |

`DstPorts`와 `CapGrant`는 한 규칙에서 동시에 쓰지 않는다(`tailcfg.go:1750`, `:1773`).

문자열 문법(`SrcIPs`, `DstPorts[].IP` 공통, `filter/tailcfg.go:126-180`) — 위에서 아래 순서로 검사한다.

1. `"*"` → `0.0.0.0/0`과 `::/0` 둘 다.
2. `"cap:<이름>"` → 노드 능력 지정. **`SrcIPs`에서만 허용**하고 `DstPorts`에서 나오면 오류(`filter/tailcfg.go:84-87`).
3. `/`를 포함 → CIDR. 호스트 비트가 남아 있으면(마스크한 값과 다르면) 오류.
4. `-`가 정확히 1개 → 두 주소 사이의 포함 범위(`a-b`). 유효하지 않은 범위는 오류. 여러 접두사로 분해한다.
5. 그 외 → 단일 IP(/32 또는 /128).

변환 결과 `Match`(`tailscale.com/wgengine/filter/filtertype/filtertype.go:70-92`): `IPProto`, `Srcs`(접두사 목록), `SrcCaps`, `Dsts`(`{Net, Ports{First..Last}}`), `Caps`(`{Dst, Cap, Values}`). `Caps`는 `CapGrant`의 `Dsts × (Caps ∪ CapMap)`마다 한 항목이다. `Caps` 항목은 `Values` 없음, `CapMap` 항목은 값 목록(`filter/tailcfg.go:98-114`).

오류 처리: 일부 항목이 오류여도 변환된 나머지 `Match`는 유효하고 첫 오류만 돌려준다(`filter/tailcfg.go:30-33`, `:64-67`). 단 `SrcBits`·`DstPorts.Bits` 위반은 `nil`과 오류를 돌려준다.

## 4. 절차와 상태 기계

### 4.1 피어별 AllowedIPs 계산 (`RouteManager`)

입력: 피어 `tailcfg.Node`, prefs 중 `ExitNodeID`(해석된 NodeID, 없으면 0)·`RouteAll`, 테일넷 설정(`OneCGNAT`).

**A. 피어를 후보로 줄이기 (`peerViewOf`, `tailscale.com/net/routemanager/routemanager.go:408-432`)**

1. 피어 ID·키·`IsJailed`·`SelfNodeV4/V6MasqAddrForThisPeer`는 **항상** 기록한다. 아래에서 후보가 없어도 피어는 추적되어 나중에 복구될 수 있다(`routemanager.go:408-415`).
2. `Expired`이면 후보 없음(`:416-418`).
3. `DiscoKey`가 비어 있고 `HomeDERP`가 0이고 WireGuard 전용(`IsWireGuardOnly`)이 아니면 후보 없음(`:419-421`).
4. `Node.AllowedIPs`의 각 항목을 분류한다(`:422-430`). **AllowedIPs가 후보의 유일한 출처다.** `Addresses`에만 있고 AllowedIPs에 없는 주소는 라우팅되지 않는다(`routemanager_test.go:594-610`).
   - **자기 주소(self)**: 단일 IP이고 Tailscale 주소(100.64.0.0/10에서 100.115.92.0/23 제외, 또는 fd7a:115c:a1e0::/48)이거나, 피어의 `Addresses`에 그대로 들어 있는 항목(`tsaddr.go:72-86`, `:89-92`).
   - **광고 경로(route)**: 그 외 전부. 서브넷 경로, 단일 비-Tailscale IP, 출구 노드의 `0.0.0.0/0`·`::/0` 포함.
5. 각 접두사는 IPv4-mapped를 풀고(`Unmap`) 마스크된 형태인지 확인한다. 호스트 비트가 남은 항목은 **로그만 남기고 건너뛴다**(`:665-687`).
6. 한 접두사가 self와 route 양쪽으로 들어오면 비트가 합쳐지고, self가 있으면 항상 적격이다(`:673`, `:828-832`).

**B. 현재 prefs로 적격 여부 (`eligible`, `routemanager.go:827-840`)**

| 종류 | 적격 조건 |
| --- | --- |
| self | 항상 (`DisableIPv4`가 켜진 테일넷에서 IPv4 self만 예외. LocalBackend는 이 값을 설정하지 않는다: `node_backend.go:960`) |
| route 중 정확히 `0.0.0.0/0` 또는 `::/0` | 그 피어가 선택된 출구 노드(`prefs.ExitNodeID != 0`이고 같은 ID)일 때만 (`tsaddr.go:268-273`) |
| route 그 외 | `prefs.RouteAll`일 때만 |
| 추가 허용 IP(`SetExtraAllowedIPs`, 앱 커넥터 확장용) | 항상 (OS 경로에는 넣지 않음) |

**C. 결과**

- 피어의 `AllowedIPs` = 적격 접두사 전체를 `tsaddr.SortPrefixes`(netipx 순서)로 정렬한 목록(`:274-297`, `tsaddr.go:276-278`). 정렬은 변경 감지(`slices.Equal`)에 쓰이므로 안정적으로 같은 순서여야 한다.
- 결과가 비어 있으면 `ok=false`: **그 피어는 WireGuard 장치에 존재하면 안 된다**(`routemanager.go:260-267`, `:292-294`).
- PSK는 설정하지 않는다. `peerConfig`는 `AllowedIPs`만 채워 돌려준다(`tailscale.com/ipn/ipnlocal/resolve.go:49-52`).
- 같은 접두사를 여러 피어가 광고하면 송신 테이블에서 점수가 높은 쪽, 같으면 NodeID가 작은 쪽을 고른다(`routemanager.go:846-863`). 점수는 지금 `SetScore`로만 바뀌며 제어 서버는 같은 CIDR을 두 노드에 보내지 않는다(`:459-475`의 주석).

**D. 보안과 연관된 netmap 정규화(수신 시, control-map 쪽 로직이지만 여기 의존)**
- `AllowedIPs`가 와이어에서 nil이면 `Addresses` 복사본으로 채운다(`tailscale.com/control/controlclient/map.go:266-268`).
- `UnsignedPeerAPIOnly` 피어는 `AllowedIPs`를 `Addresses`로 강제 축소한다(`map.go:271-274`).
- `UnsignedPeerAPIOnly` 피어가 하나라도 있고, 필터의 어떤 규칙이 `Dsts`를 가지면서 그 출발지(`Srcs`)가 이 피어들의 AllowedIPs 접두사와 겹치면 **필터 전체를 버린다**(규칙 0개 필터와 같게 처리). `*` 출발지도 겹친 것으로 본다. 이때 "Invalid packet filter" 경고를 남긴다(`local.go:3568-3600`, `:3459-3463`, `:3382-3387`).

### 4.2 건너뛰는 피어 정리

| 조건 | 결과 | 출처 |
| --- | --- | --- |
| `Expired` (또는 `KeyExpiry`가 지났다고 클라이언트가 표시) | 후보 없음 → WireGuard에서 제거 | `routemanager.go:416` |
| `DiscoKey` 없음 && `HomeDERP`==0 && WireGuard 전용 아님 | 후보 없음 | `routemanager.go:419` |
| 적격 접두사가 0개 | `ok=false` | `routemanager.go:292-294` |
| 호스트 비트가 남은 접두사 | 그 접두사만 제외 | `routemanager.go:669-672` |

클라이언트 쪽 만료 표시(`expiry.go:92-139`): `KeyExpiry`가 0이 아니고 `controlNow`보다 이전이며 아직 `Expired`가 아니면 → `Expired=true`, `Endpoints=nil`, `HomeDERP=0`, **`Key`를 일부러 깨진 값으로 교체**(`key.NodePublicWithBadOldPrefix`). `controlNow = 로컬 now + clockDelta`이고 `clockDelta`는 제어 서버 시각과 로컬 시각 차가 1분을 넘을 때만 저장한다(`expiry.go:28`, `:65-73`). 제어 서버가 준 `ControlTime`이 2023-01-10 이전(`flagExpiredPeersEpoch`)이면 판정을 건너뛴다(`expiry.go:23`, `:95-98`).

자기 노드 키 만료는 netmap 수신 때 `keyExpired`로 기록한다(`SelfKeyExpiry`가 0이 아니고 현재 시각 이전)(`local.go:1925-1929`). 만료 상태에서 로그인 URL이 오면 데이터 플레인을 내린다: 엔진 갱신을 막고(`blockEngineUpdatesLocked(true)`) 엔진을 정지시킨다(`local.go:4468-4472`). `NeedsLogin` 상태로 들어갈 때도 갱신을 막고 빈 `wgcfg.Config`·`router.Config`·`dns.Config`로 `Reconfig`한다(`local.go:6967-6980`). 만료 상태로 들어가는 모든 경로는 §8에 적는다.

### 4.3 송신 대상 피어 선택 (`lookupPeerByIP`)

TUN에서 읽은 패킷마다 wireguard-go가 **목적 주소**만 넘겨 호출한다(`tailscale.com/wgengine/userspace.go:739-750`, `wireguard-go/device/send.go:397`, `:405`). 캐시하지 않으므로 빨라야 한다(`resolve.go:26-28`).

1. `nodeByAddr[dst]`가 있으면 그 노드(자기 자신 포함)의 키를 돌려준다. 이 맵은 **자기 노드와 모든 피어의 단일 IP `Addresses`**로 만든다(`node_backend.go:712-734`).
2. 없으면 RouteManager의 송신 테이블(LPM)에서 `PeerRoute.Key`를 돌려준다(`resolve.go:38-40`). 테이블에는 적격 접두사만 들어 있다(출구 /0 포함 여부는 prefs에 따름).
3. 둘 다 없으면 실패 → wireguard-go가 패킷을 **조용히 버린다**(ICMP 불가달 응답 없음)(`send.go:411-413`, `resolve.go:41`).
4. 키를 얻으면 wireguard-go가 `LookupPeer(key)`로 피어를 찾고, 없으면 `peerConfig(key)`가 성공할 때 만든다(§4.4). 1번에서 찾은 노드가 만료·후보 없음 상태면 `peerConfig`가 실패해 역시 버려진다.

주의: 1번은 `AllowedIPs` 적격 여부를 보지 않는다. 피어의 self 주소가 `AllowedIPs`에서 빠진 채 다른 항목만 남은 경우, 송신은 되지만 그 주소를 출발지로 한 수신은 §4.4의 출발지 검사에서 버려진다.

### 4.4 WireGuard 피어 수명 (지연 생성 · 유휴 삭제)

| 시점 | 동작 | 출처 |
| --- | --- | --- |
| 송신 패킷의 목적 주소가 어떤 피어 키로 해석됨 | `LookupPeer(key)`가 피어가 없으면 `PeerLookupFunc` 호출 | `wireguard-go/device/allowedips.go:363-372`, `device.go:542-576` |
| 알 수 없는 키로 핸드셰이크 개시 메시지 수신 | 개시 메시지를 복호해 정적 키를 얻은 뒤 `LookupPeer`. 결과가 nil이거나 피어가 실행 중이 아니면 **무시** | `wireguard-go/device/noise-protocol.go:386-389` |
| `peerConfig(key)`가 `ok=false` | 피어 만들지 않음 | `device.go:551-554` |
| 만들 때 | `AllowedIPs`·PSK 설정, 엔드포인트는 `bind.ParseEndpoint(공개키 16진수 문자열)`로 고정, `deleteOnIdle=true`, 시작 | `device.go:556-576`, `tailscale.com/wgengine/wgcfg/device.go:47-64` |
| 지연 생성 피어의 정리 타이머 | 시작 시 `RejectAfterTime*3`(540초) 타이머를 건다. 세션 키가 만들어질 때마다, 그리고 핸드셰이크 재시도를 포기할 때 다시 건다 | `wireguard-go/device/peer.go:314-316`, `timers.go:96`, `:214` |
| 타이머 만료 | 키 재료를 지우고 `deleteOnIdle`이면 **피어를 장치에서 제거** | `timers.go:127-138` |
| netmap 변경 | 피어 하나에 `SyncDevicePeer(키)`: `peerConfig`가 `ok=false`면 제거, 활성 피어면 `AllowedIPs`·PSK 갱신(같으면 무동작), 활성이 아니면 아무 일도 안 함(다음 사용 때 새 설정으로 생성) | `userspace.go:698-717`, `device.go:585-592`, `peer.go:179-190` |
| 수신 패킷 | 복호 후 길이를 IP 전체 길이로 자르고, 출발지가 **그 피어의 AllowedIPs 안**이 아니면 버린다(AllowedIPs가 비면 전부 거부) | `receive.go:504-531`, `allowedips.go:412-415`, `:435-438` |
| 개인 키 변경 | 새 키가 현재 키와 같으면 무동작. 새 키의 공개키와 같은 피어를 제거하고 나머지 피어는 현재 키쌍을 만료시킨다 | `device.go:399-452` |

세션 키가 새로 만들어질 때마다(재키 기준 `RekeyAfterTime`은 120초) 540초 타이머가 다시 걸리므로, 트래픽이 이어지는 동안 피어는 남고 유휴 피어는 마지막 세션 수립 후 약 540초에 사라진다(`wireguard-go/device/constants.go:17`, `:22`, `timers.go:214`). netmap에 남아 있는 피어는 다음 송신·수신에서 다시 생성된다.

비활성(생성 전) 피어에는 `SetAllowedIPs`가 필요 없다. 생성 시점에 `peerConfig`가 그때의 설정을 준다(`wgengine.go:187-200`).

### 4.5 netmap 변경을 엔진에 적용하는 순서

**전체 netmap**(`local.go:7458-7510`)
1. `nodeBackend.SetNetMap`: `nodeByAddr`/`nodeByKey`/이름 인덱스 재구성 → RouteManager에 피어 추가·갱신·삭제(`Upsert`/`Remove`)를 한 트랜잭션으로 커밋. 사라진 피어는 삭제, 나머지는 전부 `UpsertPeer` (`node_backend.go:651-673`, `:854-897`).
2. `setDataPlanePeerRoutes()`(§4.9) (`local.go:7487`).
3. magicsock에 netmap 전달.
4. disco 키가 바뀐 피어 → `MarkDevicePeerForHandshake` (`local.go:7502-7504`).
5. `RouteManager`가 알려 준 AllowedIPs 변경 피어마다 `SyncDevicePeer` (`local.go:7508-7510`).
6. 호출자(`setControlClientStatusLocked`)가 이어서 `updateFilterLocked`(`local.go:2061-2062`)를, 마지막에 `authReconfigLocked`(`local.go:2168`)를 부른다. 소스 주석은 이 호출이 netmap을 라우터와 magicsock에 전파하는 지점이라고 적는다(`local.go:2166-2168`).

**델타**(`local.go:2503-2586`)
1. 변경분을 `nodeBackend`와 RouteManager에 반영하고(`node_backend.go:1064-1165`), 반환된 `ChangedAllowedIPs` 피어마다 `SyncDevicePeer` (`local.go:2552-2554`), `setDataPlanePeerRoutes()` (`:2555`).
2. 피어 추가·삭제가 있거나 `peerRouteConfigChanged`(키, disco 키, AllowedIPs, 만료, jailed, WG 전용, masquerade 주소 중 하나가 바뀜)이면 `SetSelfNode` 후 `authReconfigLocked()` (`local.go:2503`, `:2574-2581`, `:2680-2688`). 이 경로가 OS 경로 목록(`router.Config`)을 갱신한다(`local.go:2564-2572`의 주석).

**`authReconfigLocked`**(`local.go:6215-6334`)
1. netmap이 없으면 건너뛴다(`:6231-6234`). `WantRunning`이 아니면 건너뛴다(`:6244-6247`).
2. `RouteAll`이면 서브넷 경로 허용 플래그. PAC가 있고 `DisableSubnetsIfPAC`이면 끈다(`:6249-6258`).
3. 개인 키: 저장된 키의 공개키가 `nm.NodeKey`와 다르면 영(0) 키로 대체한다(`:6271-6274`). `wgcfg.Config{PrivateKey, Addresses: SelfNode.Addresses}` (`:6279-6282`).
4. `OneCGNAT` 결정 → `updateRouteManagerPrefs` → 바뀐 피어마다 `SyncDevicePeer` (`:6288-6300`).
5. `routerConfigLocked`(§4.6).
6. `setDataPlanePeerRoutes()` — `Reconfig` **이전**이어야 새 설정 아래 흐르는 패킷이 오래된 테이블을 보지 않는다(`:6316-6322`).
7. `Engine.Reconfig(cfg, rcfg, dcfg)`. 변경이 없으면 `ErrNoChanges` (`:6324-6327`).

**`Engine.Reconfig`**(`userspace.go:820-971`)
1. `isLocalAddr` 갱신(`LocalAddrs` 포함 여부)과 `tundev.SetWGConfig`(`:828`, `:832`).
2. 엔진 설정(개인 키·주소)·라우터 설정·DNS 설정·수신 포트 중 하나도 바뀌지 않았으면 `ErrNoChanges` (`:854-874`).
3. 개인 키가 바뀌었으면 **magicsock에 먼저** 키를 주고 그다음 wireguard-go에 준다(핸드셰이크가 DERP로 나갈 수 있어야 하므로)(`:886-899`).
4. wireguard-go 피어 재구성은 하지 않는다(`:905-909`).
5. 라우터 설정이 바뀌었으면 `router.Set(rcfg)`. 오류가 나도 DNS 설정은 계속 시도한다(`:914-918`).

### 4.6 라우터 설정 (`routerConfigLocked`)

산출: `router.Config{LocalAddrs, Routes, LocalRoutes, …}`(`tailscale.com/wgengine/router/router.go:106-143`). iOS 패킷 터널에 필요한 필드는 `LocalAddrs`, `Routes`, `NewMTU`(콜백 라우터가 처음 한 번만 채움: `callback.go:45-62`)다.

1. `LocalAddrs` = `SelfNode.Addresses`의 각 접두사. 주소만 `Unmap`하고 비트 수는 유지한다(`local.go:6711`, `:6800-6811`). 보통 IPv4 /32 하나, IPv6 /128 하나다(`router.go:107-109`).
2. `Routes`의 기본 = RouteManager의 OS 경로 집합을 정렬한 것(`node_backend.go:990-997`, `local.go:6716`).
3. 출구 노드가 선택된 경우(`ExitNodeID`나 `ExitNodeIP`가 설정됨): `0.0.0.0/0`·`::/0`이 빠졌으면 **블랙홀로 추가**한다. 이어서 LAN 경로 처리(`local.go:6732-6771`). 이 구간은 M3·M5 범위 밖(§6).
4. `LocalAddrs`에 IPv4 주소가 있으면 `100.100.100.100/32`를, IPv6 주소가 있으면 `fd7a:115c:a1e0::53/128`을 `Routes`에 추가한다(`local.go:6778-6785`, `tsaddr.go:52`, `:66-67`).
5. 자기 노드가 호스팅하는 VIP 서비스 주소 중 위 4에서 켠 계열과 같은 계열인 것을 `/32`·`/128`로 추가한다(`local.go:6775-6790`). 이 목록은 4번 항목 뒤에 붙으므로 정렬되지 않고, 서비스 맵을 순회하는 순서에 따라 정해진다(Go 맵 순회는 순서가 정해져 있지 않다).
6. 이 목록은 `router.Config.Equal`(`reflect.DeepEqual`)로 비교하고 변경이 있을 때만 `router.Set`이 호출된다(`router.go:145-153`, `userspace.go:855`, `:914-917`). 콜백 라우터도 같은 비교로 중복 호출을 막고 `SetBoth(rcfg, dcfg)`를 호출한다(`callback.go:45-62`). 따라서 **경로 순서가 바뀌면 불필요한 재설정**이 일어난다.

**OS 경로 집합의 구성 (`RouteManager`의 `OSRoutes`)** (`routemanager.go:865-892`, `:909-1030`)

| 후보 분류 | 정의 | OS 경로 |
| --- | --- | --- |
| IPv4 CGNAT 단일 주소 | 단일 IP이고 100.64.0.0/10 안 | 기본은 피어마다 /32. 개수가 `임계값`을 넘으면 개별 경로를 모두 빼고 `100.64.0.0/10` 하나. 임계값 = `OneCGNAT`이면 1(= 2개 이상), 아니면 **10,000**(= 10,001개 이상) |
| IPv6 ULA 단일 주소 | 단일 IP이고 fd7a:115c:a1e0::/48 안 | 개별 /128은 **넣지 않는다**. 적격 항목이 1개 이상이면 `fd7a:115c:a1e0::/48` 하나만 |
| 그 외 | 서브넷 경로, ULA/CGNAT가 아닌 단일 IP, `/0` 등 | 적격하면 그대로 |
| 출구 /0 | 출구 노드가 선택됨(해석 실패 포함) | 적격 기여자가 없어도 `0.0.0.0/0`·`::/0`을 넣어 차단한다 |

- 이 분류는 **피어가 기여한 접두사**(자기 주소·VIP 주소 포함)에만 적용된다. 자기 노드 주소는 `LocalAddrs`에만 있고 경로에는 없다. 따라서 `fd7a:115c:a1e0::/48`은 **ULA 주소를 가진 적격 피어가 한 명 이상 있을 때만** 생긴다. `fd7a:115c:a1e0::53/128`은 위 4번에서 따로 붙는다.
- 분류 기준 `CGNATRange().Contains`는 ChromeOS 대역(100.115.92.0/23)을 제외하지 않는다(`routemanager.go:878`, `tsaddr.go:23-36`). Tailscale 주소 판정(`IsTailscaleIPv4`)은 제외한다(`tsaddr.go:83-85`). 두 정의가 다르다는 점만 기록해 둔다.

**`OneCGNAT` 결정 (`shouldUseOneCGNATRoute`, `local.go:6364-6399`)**
1. 제어 서버 지시가 있으면 그대로: nodeattr `"one-cgnat?v=true"` → true, `"one-cgnat?v=false"` → false (`tailscale.com/tailcfg/nodecap/nodecap.go:148`, `:153`, `tailscale.com/control/controlknobs/controlknobs.go:190-193`).
2. plan9 → true.
3. macOS 또는 android: CGNAT 대역을 쓰는 **다른 인터페이스가 없을 때만** true. 판단 오류 시 false.
4. 그 외(**iOS 포함**, linux, windows 등) → false.

`version.OS()`는 iOS에서 `"iOS"`, tvOS에서 `"tvOS"`, macOS에서 `"macOS"`를 돌려준다(`tailscale.com/version/prop.go:49-55`). iOS를 CGNAT 한 경로로 만든다는 코드는 없다. 이는 Swiftail이 iOS에서 /10 한 경로를 쓰는 것이 **Go 클라이언트와 다른 선택**임을 뜻한다(§6.2).

### 4.7 패킷 필터 구성

**입력과 갱신 지점**
- 규칙: `MapResponse.PacketFilter`("base"라는 이름)와 `PacketFilters`(이름별 조각, `"*"`:nil이면 전부 삭제)를 키 정렬해 이어 붙이고 `MatchesFromFilterRules`로 변환한다(`control/controlclient/map.go:449-479`, `tailcfg.go:2100-2136`). 필터 규칙만 바뀐 응답은 netmap 재구성 없이 `UpdatePacketFilter`로 들어온다(`local.go:2696-2713`).
- 의미(`tailcfg.go:2100-2105`): `PacketFilter`가 nil이면 직전 값 유지, 비어 있지만 nil이 아니면 "필터 없음 = 모두 차단". 이전에 규칙을 한 번도 받지 못했으면 변환 결과는 nil이라 규칙이 0개인 필터가 된다(`map.go:1033-1034`).
- `updateFilterLocked(prefs)`가 다음 입력으로 필터를 새로 만든다(`local.go:3423-3565`). 입력이 이전과 같으면 아무것도 하지 않는다(`:3519-3531`).

**필터 선택 (`local.go:3440-3565`)**

| 조건 | 설치되는 필터 |
| --- | --- |
| netmap 없음 | `NewAllowNone(logNets)`를 일반·jailed 양쪽에 (`:3533-3538`) |
| prefs가 유효하지 않거나 `ShieldsUp` | `NewShieldsUpFilter` (규칙 0개, `shieldsUp=true`) (`:3446`, `:3540-3544`) |
| 그 외 | `filter.New(matches, srcIPHasCap, localNets, logNets, oldFilter)` (`:3545-3552`) |
| 항상 별도로 | jailed 피어용 필터는 **shields-up 필터와 동일**하게 만든다 (`:3554-3555`) |
| 안전 장치 | `UnsignedPeerAPIOnly` 피어와 겹치는 허용 규칙이 있으면 규칙을 비운다(§4.1 D) |

이전 필터와 `shareStateWith`로 UDP 상태 캐시를 공유하므로 규칙을 바꿔도 진행 중인 UDP 흐름이 끊기지 않는다(`filter.go:226-234`). 단 shields-up 필터는 이전 필터가 shields-up일 때만 공유한다(`filter.go:208-216`).

**`localNets`**(이 집합에 없는 목적 주소는 수신 단계에서 정책을 보지도 않고 거부)(`local.go:3440-3470`, `:3500-3503`)
- 자기 노드 `Addresses` 접두사 전부(`:3453-3456`).
- 자기 노드의 서비스 호스팅 능력(`service-host`)에 있는 VIP 주소들(`addServiceIPs`, `:3360-3378`).
- 광고 경로(서브넷 라우터 / 앱 커넥터일 때만): M3·M5 범위 밖.

**`logNets`**(이 집합 안의 주소끼리만 로그에 남긴다): 100.64.0.0/10에서 100.115.92.0/23을 뺀 것, fd7a:115c:a1e0::/48, 광고 경로(`local.go:3449-3452`, `:3496`).

**netmap 이전의 기본값**
- `LocalBackend` 생성 시 일반·jailed 필터를 `AllowNone`으로 설치한다(`local.go:684-687`). `nodeBackend`도 같다(`node_backend.go:192-194`).
- TUN 래퍼의 필터 포인터가 nil이면 양방향 모두 `Drop`이다(`wrap.go:820-822`, `:1190-1192`).
- 래퍼는 `Start`가 불리기 전까지 `Read`를 막는다("corked")(`wrap.go:96-99`, `:864-882`).
- `AllowNone`의 실제 판정은 §4.8의 "규칙 0개, 로컬 주소 0개"와 같다.

### 4.8 수신·송신 판정 절차

**공통 사전 검사 `pre`**(`filter.go:688-720`): 위에서 아래로, 처음 걸리는 것에서 끝낸다.

| 순서 | 조건 | 판정 | 지표 이유 |
| --- | --- | --- | --- |
| 1 | 버퍼 길이 0 (WireGuard keepalive) | Accept | |
| 2 | 길이 < 20 | Drop | `too_short` |
| 3 | `IPProto == Unknown` | Drop | `unknown_protocol` |
| 4 | 목적 주소가 멀티캐스트 | Drop | `multicast` |
| 5 | 목적 주소가 링크로컬 유니캐스트이고 허용 예외가 아님 | Drop | `link_local_unicast` |
| 6 | `IPProto == Fragment` (첫 조각이 아닌 조각) | Accept | |
| 그 외 | | 계속 | |

링크로컬 예외: 목적이 169.254.169.254(GCP DNS)이거나 확장 훅이 허용할 때(`filter.go:672-684`). 5번과 6번은 **로컬 주소 검사보다 먼저**이므로, `AllowNone`이어도 비어 있는 버퍼와 첫 조각이 아닌 조각은 통과한다(`filter_test.go:419-466`에도 같은 기대값이 있다).

**수신 `RunIn(q)`**(`filter.go:443-472`)

1. `pre` 결과가 Accept/Drop이면 그대로 반환.
2. `IPVersion`이 4면 `runIn4`, 6이면 `runIn6`, 그 외 Drop("not-ip").
3. `runIn4`/`runIn6`가 `noVerdict`를 돌려주면 확장 `IngressAllowHooks`를 차례로 실행해 하나라도 true면 Accept, 아니면 **Drop**.

`runIn4`·`runIn6`(두 함수의 구조가 같다. `filter.go:502-622`):

1. 목적 주소가 `localNets`(해당 IP 계열)에 없으면 `noVerdict` ("destination not allowed").
2. 프로토콜별:

| 프로토콜 | 규칙 |
| --- | --- |
| ICMPv4/ICMPv6 | 에코 응답이거나 오류 메시지면 Accept(상태 확인 없음). 아니면 `matchIPsOnly`가 true면 Accept. 그 외 `noVerdict` |
| TCP | **SYN이 아니면 무조건 Accept** (SYN+ACK도 SYN 아님으로 취급: `IsTCPSyn`은 SYN 켜짐 & ACK 꺼짐). SYN이면 `match`가 true일 때 Accept, 아니면 `noVerdict` |
| UDP, SCTP | 상태 캐시에 `(proto, 출발, 목적)` 튜플이 있으면 Accept. 아니면 `match`가 true일 때 Accept. 그 외 `noVerdict` |
| TSMP | 무조건 Accept |
| 그 외 | `matchProtoAndIPsOnlyIfAllPorts`가 true면 Accept, 아니면 `noVerdict` |

이 장에서 **프로토콜·출발지·목적지 규칙**의 의미(`match.go`):

- `match`(`match.go:17-37`): 어떤 `Match` m에 대해 `IPProto ∈ m.IPProto`, 출발 주소가 `m.Srcs`에 속하거나(`SrcsContains`) 출발 주소의 노드가 `m.SrcCaps` 중 하나를 가짐, 그리고 `Dsts` 중 `Net`이 목적 주소를 포함하고 `Ports`가 목적 포트(양끝 포함)를 포함하면 true. 규칙은 순서대로 보고 하나라도 맞으면 끝이다(허용 규칙만 있고 거부 규칙은 없다).
- `matchIPsOnly`(`match.go:62-84`): **프로토콜과 포트를 보지 않고** 출발 주소가 `Srcs`에 속하고 `Dsts`의 `Net` 중 하나가 목적 주소를 포함하면 true. 그다음 `hasCap`이 있으면 **어떤 `Match`든** `SrcCaps`에 출발지가 가진 능력이 하나라도 있으면 true(목적지는 보지 않음). → 어떤 TCP 포트 하나만 열려 있어도 같은 출발지→목적지에 대한 ICMP 에코 요청이 통과한다.
- `matchProtoAndIPsOnlyIfAllPorts`(`match.go:89-107`): 프로토콜이 맞고, 출발지가 맞고, `Ports`가 정확히 `0..65535`인 `Dsts` 항목의 `Net`이 목적을 포함할 때만 true.
- TCP SYN·UDP·SCTP에서만 포트를 비교한다. ICMP 포트는 0이다(§3.4).

`SrcCaps`는 출발 주소가 netmap의 어떤 노드의 **단일 IP `Addresses`**와 정확히 일치하고 그 노드가 `UnsignedPeerAPIOnly`가 아니며 해당 능력을 `CapMap`에 가졌을 때만 true다(`local.go:9318-9334`). 서브넷 경로 뒤의 출발지에는 능력이 없다(`filtertype.go:75-83`).

**규칙 변환 시 걸러지는 것** (`filter.go:267-290`): 한 규칙을 IP 계열(IPv4/IPv6)별로 쪼갤 때 해당 계열의 `Srcs`(또는 `SrcCaps`)와 `Dsts`가 모두 남아야 규칙이 살아남는다. `CapGrant`만 있는 규칙은 `Dsts`가 비므로 패킷 허용에 기여하지 않는다. 출발지가 `cap:`뿐인 규칙은 `Srcs`가 비지만 `SrcCaps`가 있어 살아남는다(`:284`).

**송신 `RunOut(q)`**(`filter.go:476-487`, `:625-650`): `pre`를 거치고(위 표와 동일, 멀티캐스트·링크로컬·너무 짧은 패킷·알 수 없는 프로토콜은 Drop) 나머지는 **모두 Accept**한다. 이때 UDP/SCTP 패킷이면 역방향 튜플(출발·목적 맞바꿈)을 상태 캐시에 넣는다. TCP·ICMP는 기록하지 않는다. 송신 방향에서 출발지·목적지·포트 규칙은 검사하지 않는다.

**상태 캐시**(`filter.go:102-109`, `:539-549`, `:642-650`): LRU, 최대 512개, 키 = (프로토콜, 16바이트 출발 주소, 출발 포트, 16바이트 목적 주소, 목적 포트)(`tailscale.com/net/flowtrack/flowtrack.go:22-45`, `:100-144`). 조회(`Get`)도 항목을 최근 사용으로 올린다. 만료 시간은 없고 용량 초과로만 밀려난다. 필터 교체 시 공유된다.

**로그**
- 기본 플래그는 허용·거절 둘 다 남김(`LogAccepts|LogDrops`)(`wrap.go:321`).
- 두 주소가 모두 `logNets` 안일 때만 남긴다(`filter.go:342-345`, `:723-731`).
- 송신 방향의 멀티캐스트, 링크로컬(GCP 제외), IGMP 거절은 로그에서 제외한다(`filter.go:737-743`).
- 속도 제한: 허용 로그는 10초에 1회·버스트 3, 거절 로그는 5초에 1회·버스트 10(`filter.go:326-327`).
- 형식: `"<Drop 또는 [v1] Accept>: <프로토콜>{<출발> > <목적>} <패킷 길이> <이유>"` + 선택적 헥스덤프(`filter.go:360-364`, `packet.go:82-98`).
- 이유 문자열 예: `tcp non-syn`, `tcp ok`, `ok`, `cached`, `icmp ok`, `icmp response ok`, `tsmp ok`, `other-portless ok`, `destination not allowed`, `no rules matched`, `unknown-protocol-N`, `too short` 등(`filter.go:502-622`, `:694-714`).

### 4.9 TUN 래퍼의 처리 위치 (`net/tstun/wrap.go`)

**송신: OS → WireGuard (`Read`, `wrap.go:879-948`)**

1. 패킷마다 `Decode`. 캡처 훅이 있으면 호출(`:913-917`).
2. `filterPacketOutboundToWireGuard`(`:752-840`)를 통과하지 못하면 그 패킷만 버린다(`:918-925`). 순서:
   1. ICMP 에코 요청의 목적이 `100.100.100.100:0`이나 `[fd7a:115c:a1e0::53]:0`이면 §3.7의 응답을 OS로 주입하고 `DropSilently`(`:753-769`).
   2. IP 프로토콜 99(TSMP)는 로컬에서 나올 수 없으므로 `DropSilently`(`:771-777`).
   3. UDP이고 자기 disco 패킷이면 `DropSilently`(`:779-788`).
   4. netstack 가로채기 훅(있을 때): 100.100.100.100·fd7a:115c:a1e0::53으로 가는 모든 패킷은 **프로토콜·포트와 무관하게 netstack이 흡수**한다. 흡수하지 않으면 피어 없는 주소로 WireGuard에 들어가 "no associated peer" 로그와 tailnet 유출이 생긴다고 소스가 적고 있다(`:790-797`, `tailscale.com/wgengine/netstack/netstack.go:866-896`).
   5. 엔진 훅 `handleLocalPackets`: **darwin·ios에서만** 목적 주소가 자기 터널 주소(`LocalAddrs`)이면 패킷을 OS로 되돌려 주입하고 `Drop`한다(Network Extension이 로컬 주소로 가는 패킷도 터널로 보내기 때문)(`:798-804`, `userspace.go:652-667`, `:828`).
   6. 앱 커넥터 훅(M3·M5 범위 밖).
   7. 일반 필터 선택(jailed 피어로 가면 jailed 필터), 필터가 nil이면 Drop, `RunOut`이 Accept가 아니면 Drop(`:812-832`).
   8. 후처리 훅(`:834-838`).
3. **필터 통과 후에** 출발지 주소 변환(SNAT)을 한다. 흐름 추적이 원래 출발 주소를 봐야 하므로 순서가 중요하다(`:932-934`). masquerade가 없으면(`SelfNodeV4/V6MasqAddrForThisPeer`가 없고 jailed 피어도 없음) 전혀 개입하지 않는다(`:557-563`, `:721-745`, `tailscale.com/ipn/ipnlocal/local.go:6346-6357`).
4. 남은 패킷을 wireguard-go에 넘긴다. 이후 §4.3의 피어 선택.

**수신: WireGuard → OS (`Write`, `wrap.go:1261-1305`)**: wireguard-go가 출발지 검사(§4.4)를 이미 통과시킨 패킷이 들어온다.

1. `Decode` → 목적 주소 변환(DNAT, 필요할 때만)(`:1270-1271`).
2. `filterPacketInboundFromWireGuard`(`:1128-1255`) 순서:
   1. TSMP면: ping이면 pong을 주입하고 `DropSilently`(`:1134-1137`), disco 키 광고면 키가 0이 아닐 때 이벤트로 발행하고 `DropSilently`(`:1138-1145`), pong이면 콜백만 부르고 **계속 진행**(`:1146-1149`), 거절이면 transit IP 미등록일 때만 콜백(`:1150-1156`).
   2. 에코 응답이고 등록된 진단 ping의 식별자·순번과 맞으면 흡수하고 `DropSilently`(`:1159-1165`).
   3. UDP 자기 disco이면 `DropSilently`(`:1167-1176`).
   4. 사전 필터 훅(디버그 기본 켜짐): TSMP 거절 메시지를 소비하고 `DropSilently` (transit IP 미등록 이유는 통과)(`:1178-1182`, `userspace.go:473-482`, `tailscale.com/wgengine/pendopen.go:67-90`).
   5. 필터 선택: **출발 주소가 jailed 피어의 것이면 jailed 필터**, 아니면 일반 필터. nil이면 Drop(`:1184-1191`).
   6. `RunIn`(`:1193`).
   7. 결과가 Accept가 아니고 TCP SYN이고 목적이 PeerAPI 포트이면 Accept로 바꾼다(PeerAPI는 L7에서 ACL을 검사하므로)(`:1195-1204`).
   8. 여전히 Accept가 아니면 Drop. 이때 **IPv4 TCP SYN이면 TSMP 거절을 보낸다**(§3.6): 이유는 shields-up이면 `S`, 아니면 `A`(`:1206-1236`). IPv6, UDP, ICMP에는 거절을 보내지 않는다. TCP RST도 보내지 않는다(`:1231` TODO).
   9. 후처리 훅(앱 커넥터, netstack 등)(`:1239-1252`).
3. 통과한 패킷만 OS TUN에 쓴다(`:1289-1304`).

**주입 경로**
- `InjectOutbound(pkt)`: 로컬이 보낸 것처럼 WireGuard로 보낸다. **송신 필터를 거치지 않지만** UDP/SCTP 역방향 상태는 기록하고 SNAT는 한다(`wrap.go:1477-1492`, `:1052-1072`, `:1099`). TSMP pong·거절·ICMP 진단 요청이 이 경로로 나간다.
- `InjectInboundCopy`/`InjectInboundDirect`: **수신 필터를 거치지 않고** OS TUN에 쓴다(`wrap.go:1413-1452`). 100.100.100.100 에코 응답과 darwin/ios의 자기 주소 되돌림이 이 경로다.

**다른 TUN 속성**: 기본 MTU는 `safeTUNMTU`=1280이다(`tailscale.com/net/tstun/mtu.go:76-79`). 활동 시각은 읽기·쓰기마다 갱신하며 `IdleDuration`으로 노출한다(`wrap.go:843-853`).

### 4.10 TSMP 처리 정리

| 방향 | 메시지 | Go의 동작 | 출처 |
| --- | --- | --- | --- |
| 수신 | ping | pong을 만들어 같은 피어에 보내고 소비 | `wrap.go:1134-1137`, `:1454-1475` |
| 수신 | pong | 8바이트로 대기 중인 콜백을 깨움(10초 타임아웃) | `userspace.go:491-500`, `:1368-1413` |
| 수신 | disco 키 광고 | 발행해 magicsock이 처리(`HandleDiscoKeyAdvertisement`) | `wrap.go:1138-1145`, `userspace.go:608-624`, `magicsock.go:4579-4622` |
| 수신 | 거절 | 진행 중 연결 추적을 지우고 알림, 이후 소비 | `pendopen.go:67-90` |
| 송신 | 거절 | IPv4 TCP SYN을 필터로 거부할 때만 | `wrap.go:1216-1236` |
| 송신 | 진단 ping | LocalAPI/CLI의 `ping --tsmp`일 때만 | `userspace.go:1272-1298` |
| 송신 | disco 키 광고 | 세션 수립 직후 우선 메시지 | `magicsock.go:4631-4676` |

**주의**: pong 수신은 콜백 후 `DropSilently`를 돌려주지 않아 §4.8의 TSMP "무조건 Accept"를 거쳐 OS TUN까지 쓰일 수 있다(`wrap.go:1146-1149`, `filter.go:551`). Swiftail은 TSMP를 소비하고 OS에 쓰지 않는 쪽이 안전하다(이 판단은 소스에 있는 동작이 아니라 설계 권고다).

### 4.11 WhoIs와 피어 능력

**WhoIs(IP → 노드 → 사용자)** (`local.go:1753-1812`)
1. 입력 주소의 IPv4-mapped를 푼다(`:1758`).
2. `nodeByAddr[주소]`로 NodeID를 찾는다. 자기 노드와 피어의 **단일 IP `Addresses`만** 색인되어 있다(`node_backend.go:712-734`). VIP 서비스 주소·서브넷 경로 안의 주소는 찾지 못한다.
3. netmap이 없으면 실패(`:1799-1802`).
4. `NodeByID`로 노드를 얻는다(`:1803`).
5. `UserByID(node.User())`로 `UserProfile`을 얻고, 프로필이 없으면 **전체 실패**(`:1807-1810`). 태그가 붙은 노드의 `User`는 만든 사용자일 수 있고 ACL 신원이 아니다(`tailcfg.go:380-382`).
6. userspace 네트워킹용 `ProxyMapper` 대체 조회는 M3·M5에 해당하지 않는다(`:1773-1798`).

색인 갱신은 전체 netmap에서 재구성하고, 델타에서는 변경 전 항목을 **그 노드 소유일 때만** 지운 뒤 새 항목을 넣는다. 제어 서버가 새 피어에 주소를 재할당하고 옛 피어 삭제가 늦게 오는 경우를 막기 위해서다(`node_backend.go:1028-1042`, `:1090-1127`).

**PeerCaps(출발 IP → 능력 맵)**
- `PeerCaps(src)`: 자기 노드 주소 중 단일 IP이고 `src`와 같은 계열인 **첫 주소**를 목적지로 삼아 `filter.CapsWithValues(src, dst)`를 호출한다(`node_backend.go:443-467`). 필터가 없으면 nil.
- `PeerCapsForIP(src, dst)`: 목적지를 직접 지정(`node_backend.go:473-488`).
- `CapsWithValues`(`filter.go:410-435`): 출발 계열에 맞는 `cap4`/`cap6` 규칙 중 `SrcsContains(src)`인 것의 `Caps` 항목을 보고, `Cap != ""`이고 `Dst`가 목적지를 포함하면 결과 `map[Cap][]JSON`에 값을 이어 붙인다(첫 항목은 값 배열을 복제). 여러 규칙의 같은 능력은 값이 누적된다. `Caps`(폐지 필드)로 온 능력은 값이 없지만 키는 존재한다(`HasCapability`는 키 존재 검사, `tailcfg.go:1706-1712`).
- `cap4`/`cap6`는 `Caps`가 있고 **`Srcs`가 남은** 규칙만 모은다(`filter.go:294-312`). 출발지가 `cap:` 표현만인 규칙은 `SrcCaps`만 있고 `Srcs`가 비어 능력 부여에 쓰이지 않는다.
- `UnsignedPeerAPIOnly` 피어에는 `PeerCapabilityIngress`(`https://tailscale.com/cap/ingress`) 하나만 남긴다(`node_backend.go:415-441`, `tailscale.com/tailcfg/peercap/peercap.go`의 `Ingress`).

## 5. 상수와 타이머

| 이름 | 값 | 의미 | 출처 |
| --- | --- | --- | --- |
| CGNAT 임계값 | 10,000 | 이 개수를 넘으면 /10 하나로 합침 | `routemanager.go:148` |
| `OneCGNAT` 임계값 | 1 | 2개 이상이면 /10 | `routemanager.go:887-892` |
| 필터 상태 캐시 | 512개(LRU) | UDP·SCTP 역방향 흐름 | `filter.go:109` |
| 허용 로그 제한 | 10초당 1회, 버스트 3 | | `filter.go:326` |
| 거절 로그 제한 | 5초당 1회, 버스트 10 | | `filter.go:327` |
| `minFragBlks` | 10(8바이트 단위) | 이보다 낮은 오프셋의 비첫 조각은 Unknown | `packet.go:25` |
| `minTSMPSize` | 7 | TSMP 최소 페이로드 | `tsmp.go:23` |
| TSMP 크기 | 거절 7(+1), ping 9, pong 11, disco 광고 33 | IP 헤더 제외 | `tsmp.go:25-331` |
| 우선 메시지 상한 | 512바이트 | disco 광고 포함 | `wireguard-go/device/device.go:738` |
| 지연 피어 정리 | 540초(`RejectAfterTime`180초 ×3) | 마지막 세션 이후 유휴 삭제 | `wireguard-go/device/constants.go:22`, `peer.go:315` |
| 재키 주기 | 120초 | `RekeyAfterTime` | `constants.go:17` |
| 핸드셰이크 재시도 | 5초 간격, 최대 90초 시도 | | `constants.go:18-20` |
| keepalive 타임아웃 | 10초 | | `constants.go:23` |
| 클럭 보정 문턱 | 1분 | 제어 서버 시각과 차이가 이 이상일 때만 보정 | `expiry.go:28` |
| 진단 ping 타임아웃 | 10초 | | `userspace.go:1351`, `:1393` |
| TUN MTU 기본 | 1280 | | `tstun/mtu.go:79` |
| iOS WireGuard 큐 | 64 (staged/outbound/inbound/handshake, 풀 64) | 확장 메모리 한도 때문 | `tailscale.com/wgengine/wgcfg/mem_ios.go:10-26` |
| 특수 주소 | 100.100.100.100, fd7a:115c:a1e0::53 | Tailscale 서비스 IP | `tsaddr.go:66-67` |
| Tailscale 대역 | 100.64.0.0/10(100.115.92.0/23 제외), fd7a:115c:a1e0::/48 | | `tsaddr.go:23-36`, `:89-92` |
| 출구 경로 | 0.0.0.0/0, ::/0 | | `tsaddr.go:257-258` |

## 6. Swiftail에 필요한 최소 부분과 생략할 수 있는 부분

### 6.1 M3 ("netmap의 피어와만 패킷을 주고받고 ACL을 지킨다")

**필수**

| # | 구성 | 내용 | 근거 |
| --- | --- | --- | --- |
| 1 | 노드 색인 | 자기 노드와 피어의 단일 IP `Addresses` → 노드, 공개키 → 노드, NodeID → 노드 | WhoIs·송신 선택이 이 색인에 의존(§4.3, §4.11) |
| 2 | 피어 후보·AllowedIPs 계산 | §4.1 전체. `RouteAll=false`, 출구 노드 없음이 기본이므로 결과는 "self 항목"만 남지만, **분류 규칙(self/route)은 구현해야 한다** | 서브넷 경로를 실수로 허용하면 임의 출발지를 받게 된다. tsnet 테스트도 `RouteAll`을 명시로 켠다(`tailscale.com/tsnet/tsnet_test.go:2004-2010`) |
| 3 | 만료 표시 | `KeyExpiry` 지남 → `Expired`, 키 깨뜨림(§4.2). 시각 보정은 제어 서버 시각과 1분 이상 차이날 때만 | §4.2 |
| 4 | 송신 피어 선택 | `nodeByAddr` 우선, 그다음 경로 테이블(M3는 비어 있어도 됨) | §4.3 |
| 5 | WireGuard 피어 연동 | `peerConfig(key)`와 델타 동기화. 수신 출발지 검사는 피어별 AllowedIPs. 알 수 없는 키·후보 없음 피어는 핸드셰이크 무시 | §4.4 |
| 6 | 패킷 파서 | §3.1~3.4 | 필터 입력 |
| 7 | 패킷 필터 | §3.8 변환, §4.7 `localNets`, §4.8 `RunIn`/`RunOut`/`pre`, UDP 상태 캐시(512, LRU), 규칙 교체 시 캐시 공유, shields-up 필터, 기본 `AllowNone` | M3 관문의 핵심 |
| 8 | 필터 안전 장치 | `UnsignedPeerAPIOnly` 피어가 있으면 §4.1 D 검사. 없으면 의미 없지만 제어 서버 신뢰 가정에 대한 방어 | `local.go:3568-3600` |
| 9 | jailed 피어 | `IsJailed`인 피어에서 온 패킷에는 shields-up 필터를 쓴다 | `wrap.go:667-687`, `:1184-1191`, `local.go:3554-3555` |
| 10 | TUN 래퍼 처리 순서 | §4.9의 송신·수신 단계 중 100.100.100.100 가로채기(최소한 흡수·차단), TSMP 처리, 필터, (darwin·ios) 자기 주소 되돌림 | §4.9 |
| 11 | TSMP | 수신: ping에 pong 응답, disco 키 광고·거절·pong 소비 후 OS로 쓰지 않음. 송신 쪽은 아래 6.3 | §4.10 |
| 12 | 로그·지표 | 거절 이유(`acl`, `shields` 등)를 지표용 문자열로 노출 | `usermetric/metrics.go:24-48` |

9번은 `Jailed`가 의미를 갖는 경우가 제한적이어도 수신 필터 선택 한 줄이므로 M3에서 구현하는 편이 ACL 관문 시험에 안전하다.

**권고하는 구현 방식(소스에 있는 동작을 옮긴 것이 아니라 설계 선택)**
- RouteManager는 "피어별 후보 접두사 목록 + prefs → 적격 목록·송신 테이블·OS 경로"를 계산하는 **순수 함수/값 타입**으로 두면 델타·전체 netmap 둘 다에서 `이전 AllowedIPs ≠ 새 AllowedIPs`인 피어 키만 내보낼 수 있다(`routemanager.go:626-649`). Go는 이를 이용해 `SyncDevicePeer` 호출을 제한한다.
- iOS 확장은 메모리 한도가 빡빡하므로(`tailscale.com/wgengine/wgcfg/mem_ios.go:11-14`) 지연 생성·유휴 삭제(§4.4)를 따르는 편이 Go와 같은 동작이다. 모든 피어를 미리 만드는 대안도 호환에는 문제가 없지만 후보 없음 피어는 만들면 안 된다.

### 6.2 M5 ("iOS 패킷 터널에 주소·경로를 내준다")

- 전달 값: `LocalAddrs`(§4.6 1), `Routes`(§4.6 2~5), MTU(기본 1280, §5). Go는 이 값을 `CallbackRouter.SetBoth`로 앱 코드에 넘기고(`callback.go:12-15`, `:45-62`), iOS 앱 쪽 코드는 이 저장소에 없다(§8).
- **Go iOS와 같게 하려면**: 피어마다 CGNAT /32, 첫 ULA 피어가 생기면 `fd7a:115c:a1e0::/48`, `100.100.100.100/32`, `fd7a:115c:a1e0::53/128`(자기 주소 계열에 따라), VIP 서비스 주소.
- **이 선택은 Swiftail이 정할 일이다.** Go iOS 기본은 per-peer /32이고, `OneCGNAT`은 제어 서버 지시가 있을 때만 켠다. macOS·android가 /10을 선호하는 이유로 소스는 "VPN 설정 갱신 비용(기존 연결이 끊김)"을 든다(`local.go:6378-6384`). iOS에 대한 근거는 소스에 없다. 따라서 Swiftail이 iOS에서 /10 + /48을 항상 쓰기로 한다면 **Go와 다른 결정**이며, 피어 변경마다 터널 설정을 다시 적용하지 않는 이점과 CGNAT 대역을 쓰는 다른 인터페이스를 가리는 위험을 함께 검토해야 한다. 어떤 쪽이든 nodeattr `"one-cgnat?v=true"/"…false"`가 오면 따르도록 해 두면 제어 서버가 되돌릴 수 있다(§4.6).
- 경로 변경이 있을 때만 설정을 다시 적용한다. 같은 목록이라도 순서가 다르면 재적용되므로 `OSRoutes` 정렬(`netipx` 순서)과 추가 항목의 순서를 고정한다(`router.go:145-153`).
- DNS는 이 노트 밖이지만 MagicDNS를 쓰면 OS 설정의 네임서버가 100.100.100.100(과 fd7a:115c:a1e0::53)이 되므로 위 경로가 필요하다(`tailscale.com/net/dns/config.go:76-96`).
- 패킷을 넘겨받는 쪽에서 자기 주소로 가는 패킷을 되돌리거나 버려야 한다(§4.9 송신 5).

### 6.3 뒤로 미룰 수 있는 것과 근거

| 항목 | 미뤄도 되는 근거 | 미룰 때 지킬 것 |
| --- | --- | --- |
| 서브넷 경로 수락(`RouteAll`) | 기본 false. 이 경우 route 항목은 AllowedIPs에서 빠지고(`routemanager.go:833-837`) OS 경로에도 없다 | self/route 분류는 구현. `RouteAll`이 true로 오면 지원하지 않는다고 명시적으로 거부 |
| 출구 노드 사용 | 선택하지 않으면 `0.0.0.0/0`·`::/0`이 후보에서 제외됨(`routemanager.go:834-836`) | 출구 노드를 선택하는 기능을 노출하지 않는다 |
| 서브넷 라우터·출구 노드 제공, 앱 커넥터 | 광고 경로가 없으면 `localNets`는 자기 주소뿐이고 포워딩이 필요 없다(`local.go:3470-3503`) | 필터의 `localNets`에 광고 경로를 넣지 않는다 |
| masquerade(`SelfNode…MasqAddrForThisPeer`), SNAT/DNAT | 값이 있는 피어가 없으면 래퍼가 개입하지 않는다(`routemanager.go:100-104`, `wrap.go:721-745`) | 이 값이 있는 피어는 AllowedIPs에서 제외하거나 통신하지 않는다(침묵 오동작 방지) |
| 확장 허용 IP(conn25 transit IP) | 확장 훅이 없으면 비어 있음(`local.go:6303-6315`) | 구현 불필요 |
| TSMP 거절 송신 | 실패해도 상대는 연결 시간 초과로만 알 수 있어 기능이 막히지는 않는다(`wrap.go:1212-1214`의 설명은 "GUI/CLI에 거절 이력 표시") | 필터 거절은 반드시 수행하고 거절 메시지만 생략. 보낼 때는 IPv4 TCP SYN만, 이유 `A`/`S` |
| TSMP ping 송신, ICMP 진단 ping | `tailscale ping`용 진단(`userspace.go:1272-1298`) | pong 응답은 구현 |
| TSMP disco 키 광고 송신·수신 | 수신은 disco 키가 제어 서버보다 먼저 바뀐 피어에 유용(`magicsock.go:4579-4622`). 연결 자체는 netmap의 disco 키로 가능 | M4 노트에서 결정. 수신 패킷은 소비해야 한다 |
| `PeerAPI` 우회(필터의 SYN 예외) | PeerAPI를 열지 않으면 불필요(`wrap.go:1195-1204`) | PeerAPI를 열 때 구현 |
| VIP 서비스, 4via6 | 서비스 호스팅 노드가 아니면 불필요(`local.go:3360-3378`, `netstack.go:897-927`) | 구현 불필요 |
| `DisableIPv4`(테일넷) | LocalBackend가 설정하지 않는다(`node_backend.go:960`) | 구현 불필요 |
| 점수(`SetScore`) | 같은 접두사 중복 광고가 없다(`routemanager.go:459-475`) | 같은 접두사가 두 피어에서 오면 NodeID 작은 쪽 |
| LAN 접근·로컬 경로(`LocalRoutes`), 블랙홀 | 출구 노드를 쓰지 않으면 해당 없음 | |
| 네트워크 흐름 로그, pendopen 연결 추적, BIRD | 진단·부가 기능 | |

## 7. 상호 운용 시험에서 확인할 것

1. **ACL 포트 규칙**: Go 노드가 Swiftail로 TCP 22만 허용되는 ACL에서 22 SYN은 통과, 23 SYN은 거절됨(IPv4면 `!` TSMP 수신)을 확인. 같은 출발지의 에코 요청은 22가 열려 있기만 하면 통과(§4.8 `matchIPsOnly`). TCP 비SYN 패킷은 규칙과 무관하게 통과.
2. **UDP 상태**: Swiftail이 먼저 UDP를 보내면 응답은 통과하고, 먼저 오는 UDP는 규칙이 없으면 거절. 512개를 넘는 흐름에서 가장 오래 안 쓴 흐름부터 밀려남. 규칙 교체 뒤에도 기존 흐름 유지.
3. **netmap 이전**: 연결 직후 netmap을 받기 전에는 어떤 수신 패킷도 TUN에 쓰이지 않음(빈 버퍼와 비첫 조각 제외).
4. **shields-up**: 어떤 SYN도 거절, 응답 패킷(ICMP 에코 응답·UDP 흐름·TCP 비SYN)은 통과, 거절 이유 `S`.
5. **서브넷 경로 피어**: 피어가 `10.0.0.0/24`를 광고해도 `RouteAll=false`에서는 AllowedIPs에 없고 OS 경로에도 없음. 그 대역 목적 패킷은 조용히 버려짐(ICMP 불가달 없음).
6. **만료·후보 없음 피어**: `Expired`, disco 키와 홈 DERP 둘 다 없음, AllowedIPs 빔 각각에서 WireGuard 피어가 만들어지지 않고 핸드셰이크가 무시됨. 만료가 풀리면 복구.
7. **델타**: 피어 추가·삭제·AllowedIPs 변경 후 `SyncDevicePeer` 동등 동작과 라우터 설정 갱신. 같은 netmap을 다시 받아도 라우터·엔진이 무동작.
8. **지연 피어 정리**: 마지막 핸드셰이크 후 약 540초에 유휴 피어가 사라지고 다음 송신에서 다시 만들어짐.
9. **TSMP**: Go 노드의 `tailscale ping --tsmp`에 pong(11바이트, PeerAPI 포트 0)으로 응답. 잘못된 크기(ping 9바이트 미만)는 무시. TSMP는 OS TUN에 나가지 않음.
10. **100.100.100.100**: ICMP 에코 요청에 응답, 그 밖의 패킷은 WireGuard로 새어 나가지 않음.
11. **조각화**: 첫 조각(IPv4·IPv6 프래그먼트 헤더 포함)은 포트로 필터링, 비첫 조각은 통과, 너무 짧은 첫 조각과 오프셋 10블록 미만 비첫 조각은 거절(`filter_test.go`의 `TestRunInIPv6FirstFragment`가 같은 기대).
12. **jailed 피어**: jailed 피어가 연 SYN은 규칙과 무관하게 거절, Swiftail이 먼저 연 연결의 응답은 통과.
13. **능력(CapGrant)**: `CapMap`/`Caps`로 부여한 능력이 `PeerCaps`로 보이고, 값이 여러 규칙에서 누적됨. 출발지가 `cap:`뿐인 규칙의 `CapGrant`는 나타나지 않음.
14. **WhoIs**: 피어의 두 주소 모두로 같은 노드·사용자가 나옴. 서브넷 주소는 실패. 사용자 프로필이 없는 노드는 실패.
15. **iOS 경로 출력**: 피어 N명일 때 `LocalAddrs`, `Routes`의 목록·정렬 순서를 §4.6과 대조. `fd7a:115c:a1e0::/48`은 ULA 주소를 가진 피어가 있을 때만, `100.100.100.100/32`는 IPv4 자기 주소가 있을 때만. `one-cgnat?v=true` 수신 시 2명 이상부터 /10 하나.

## 8. 확인하지 못한 것

1. **iOS 앱이 `router.Config`를 `NEPacketTunnelNetworkSettings`로 바꾸는 방법**: 이 저장소에는 iOS 호스트 코드가 없고, 콜백 형식(`CallbackRouter.SetBoth`)만 확인했다.
2. **netstack 없이 100.100.100.100:53(MagicDNS)을 어디서 응답하는지**: tstun은 ICMP 에코만 처리하고, UDP/TCP 흡수는 netstack의 `handleLocalPackets`가 한다(`netstack.go:866-896`). 엔진의 `handleLocalPackets`는 이를 처리하지 않는다(`userspace.go:652-681`). Swiftail이 netstack을 쓰지 않는 경우의 처리는 dns-state-node.md에서 결정해야 한다.
3. **`ICMP4ParamProblem`이 0x12인 이유**: 소스 상수가 0x12(`icmp4.go:26`)이다. 이것이 표준 ICMPv4 값과 같은지는 이 소스에서 확인하지 못했다. 소스를 그대로 따르고, 상호 운용 시험에서 오류 판정 영향을 확인한다.
4. **장치 정지 시 WireGuard 피어가 지워지는지**: `NeedsLogin`/`Stopped`에서 빈 `wgcfg.Config`로 `Reconfig`하면 개인 키가 0으로 바뀐다(`local.go:6977`, `userspace.go:886-899`). 이때 `device.SetPrivateKey`는 새 키의 공개키와 같은 피어를 지우고 나머지 피어의 키쌍을 만료시킨다(`wireguard-go/device/device.go:399-452`). 기존 피어 객체가 그대로 남는지, 유휴 타이머로만 정리되는지는 확인하지 못했다.
5. **제어 서버가 `AllowedIPs`를 채우는 규칙**: 서브넷 승인·출구 노드 승인이 `AllowedIPs`에 어떻게 반영되는지는 서버 쪽 동작이며 이 소스에 없다. 클라이언트 쪽 정의는 `tailcfg.go:399-402`("IP ranges to route to this node")뿐이다.
6. **`wireguard-go`의 인바운드 핸드셰이크 수신 경로 전체**(쿠키·MAC 검증 등)는 wireguard.md 범위로 두고 여기서는 피어 조회 지점만 확인했다(`noise-protocol.go:386-389`).
7. **`PreFilterPacketInboundFromWireGuard`(pendopen)가 기본 빌드에서 켜지는지**: 환경변수 `TS_DEBUG_CONNECT_FAILURES`가 기본 참(`userspace.go:473-482`)이고 `buildfeatures.HasDebug`일 때만이라는 것까지 확인했고, 빌드 태그별 실제 활성 여부는 확인하지 않았다.
8. **`PeerAPIPort` 응답값의 사용처**: pong에 실리는 포트는 `GetPeerAPIPort`에서 오며(`local.go:5754-`), PeerAPI가 없을 때 0이라는 점만 확인했다.
9. **자기 키 만료로 `NeedsLogin`에 들어가는 모든 경로**: `keyExpired` 기록(`local.go:1925-1929`)과 로그인 URL 수신 시 정지(`:4468-4472`)만 확인했다. 상태 기계 전체는 dns-state-node.md 몫이다.
10. **`ShieldsUp` prefs의 기본값**과 tsnet이 쓰는 prefs 기본값: `prefs.Valid()`가 아닐 때 shields-up이라는 것(`local.go:3446`)만 확인했다.
11. **IPv6 확장 헤더가 붙은 패킷의 실제 빈도·영향**: 프래그먼트 외 확장 헤더는 Unknown으로 거절된다는 코드 동작만 확인했다(`packet.go:293-311`).
