# netmap → 엔진 계층 (피어 설정 · 패킷 필터 · 경로)

| 항목 | 값 |
| --- | --- |
| 기준 버전 | `tailscale.com` v1.104.6 (CapabilityVersion 148), `wireguard-go` v0.0.0-20261106233718-9e0ab45c16ca — [기준 소스](README.md#기준-소스) |
| 작성 모델 | Claude Sonnet 5.5 (`claude-sonnet-5-5`), 2026-11-13 |
| 검증 상태 | GPT-6.1 Sol, 2026-11-14, 소스 대조 완료. 사실 오류 수정 10건(§8.3), 구현 누락 보완(§4.3·4.7·6). 실행 상호 운용은 미실시 |
| 쓰는 마일스톤 | M3(DERP만으로 UDP 에코·TCP SYN-ACK·ACL 차단), M5(iOS 터널 설정) — `docs/plan.md:193-195` |

출처는 모듈 루트 기준 `경로:줄`이다. `wireguard-go/`는 위 포크 모듈, `gvisor/`는 Go의 의존 모듈 `gvisor.dev/gvisor` v0.0.0-20260915211658-a6f909f08a72의 루트다(버전: `tailscale.com/go.mod:156`). `Sources/`·`docs/`는 Swiftail 저장소 기준이다. 아래 **권고·설계 선택·시험 계획**은 Go의 필수 와이어 동작과 구별한다.

## 1. 범위

M3 구현자는 §3의 패킷 입력, §4.1~4.6의 피어·필터 변환, §4.7의 프로세스 내 수신 경계, §6.1의 절차를 따른다. OS 주소·경로·DNS 설정 산출은 M5로 모았다(§4.8·6.2, 마일스톤: `docs/plan.md:193-195`).

Noise·재키는 [wireguard.md](wireguard.md), 맵 JSON·델타 병합은 [control-map.md](control-map.md), 직접 UDP·disco·DERP 경로 선택은 [disco-magicsock.md](disco-magicsock.md), MagicDNS 응답은 [dns-state-node.md](dns-state-node.md)의 범위로 둔다.

## 2. 소스 지도와 현재 모듈 경계

| 역할 | 확인 지점 |
| --- | --- |
| netmap → 피어별 AllowedIPs | `tailscale.com/net/routemanager/routemanager.go:260-297`, `:408-431`, `:665-687`, `:827-862` |
| 송신 피어 선택·피어 설정 공급 | `tailscale.com/ipn/ipnlocal/resolve.go:20-52` |
| 피어 설정 동기화·로컬 패킷 | `tailscale.com/wgengine/userspace.go:652-750` |
| 필터 규칙 변환·일치·판정 | `tailscale.com/wgengine/filter/tailcfg.go:30-180`, `tailscale.com/wgengine/filter/match.go:17-107`, `tailscale.com/wgengine/filter/filter.go:443-720` |
| WireGuard 뒤의 필터·netstack 연결 | `tailscale.com/net/tstun/wrap.go:1128-1254`, `tailscale.com/wgengine/netstack/netstack.go:465-466` |
| OS 경로 | `tailscale.com/net/routemanager/routemanager.go:874-892`, `:909-1029`, `tailscale.com/ipn/ipnlocal/local.go:6710-6797` |

이 버전의 `wgcfg.Config`에는 `PrivateKey`·`Addresses`만 있고 피어 배열은 없다. `PeerConfig`에는 `AllowedIPs`·`PresharedKey`만 있다. 따라서 옛 `wgcfg/nmcfg` 방식의 피어 배열 생성으로 설명하면 안 된다(`tailscale.com/wgengine/wgcfg/config.go:17-35`).

Swiftail의 `Netmap`은 self·피어·DERP 지도·필터 규칙·`controlTime`을 보관한다. WireGuard 모듈은 `addPeer`·`removePeer`와 공개 키를 대상으로 하는 `send`를 제공하고, `ipPacket` 출력은 복호화·AllowedIPs 검사를 이미 통과했다. 엔진은 필터와 송신 피어 선택을 그 바깥에 둔다(`Sources/SwiftailControl/Netmap/Netmap.swift:7-26`, `Sources/SwiftailWireGuard/WireGuardDevice.swift:19-29`, `:57-78`, `docs/contracts/SwiftailWireGuard.md:70-101`).

## 3. 패킷 입력과 와이어 필드

### 3.1 필터가 읽는 IP·전송 헤더

오프셋은 IP 패킷 시작 기준이고 정수는 별도 표기가 없으면 빅엔디언이다. Go 파서는 버전·주소·포트·플래그를 추출하며 아래 길이 검사를 한다(`tailscale.com/net/packet/packet.go:104-160`, `:202-229`, `:271-365`).

| 형식 | 오프셋:길이 → 의미 | 길이·파싱 조건과 출처 |
| --- | --- | --- |
| IPv4 | `0` 상위 4비트 버전, 하위 4비트×4 IHL; `2:2` 전체 길이; `6:2` MF=`0x2000`·오프셋=`&0x1fff`; `9:1` 프로토콜; `12:4` 출발·`16:4` 목적 | 20바이트 미만, 선언 길이가 버퍼보다 큼, IHL이 선언 길이보다 크면 Unknown. IHL 최솟값은 검사하지 않음 — `tailscale.com/net/packet/packet.go:132-178` |
| IPv6 | `0` 상위 4비트 버전; `4:2` 페이로드 길이(+40=전체); `6:1` next-header; `8:16` 출발·`24:16` 목적 | 40바이트 미만 또는 선언 길이가 버퍼보다 크면 Unknown — `tailscale.com/net/packet/packet.go:271-311` |
| TCP(6) | 전송 헤더 `0:2` 출발 포트·`2:2` 목적 포트·`12` 상위 4비트×4 헤더 길이·`13:1` 플래그 | 최소 20바이트 — `tailscale.com/net/packet/packet.go:202-212`, `:324-334` |
| UDP(17)·SCTP(132) | 전송 헤더 `0:2` 출발 포트·`2:2` 목적 포트 | 최소 8·12바이트 — `tailscale.com/net/packet/packet.go:213-229`, `:335-350` |
| ICMPv4(1)·ICMPv6(58) | 전송 헤더 `0:1` type·`1:1` code, 포트는 0 | 파서는 최소 4바이트, echo·error 판별은 8바이트 필요 — `tailscale.com/net/packet/packet.go:185-193`, `:316-323`, `:497-539` |
| TSMP(99) | IP 헤더 뒤 전체가 TSMP 페이로드 | 최소 7바이트 — `tailscale.com/net/packet/packet.go:230-242`, `:351-358`, `tailscale.com/net/packet/tsmp.go:23` |

Go `Parsed`는 선언 IP 길이 이후 바이트까지 `Buffer`와 전송 헤더 길이 검사에 사용할 수 있고, `Payload`만 선언 길이로 자른다. WireGuard 수신 경로는 그 전에 패킷을 IP 길이로 자르지만, 로컬 입력의 `Parsed.Decode` 자체가 이를 보장하지는 않는다(`tailscale.com/net/packet/packet.go:161-162`, `:312-313`, `:461-478`, `wireguard-go/device/receive.go:497-528`). **Swiftail 권고:** 입력 경계에서 선언 길이·IHL·TCP 헤더 길이를 검증하고 자른 뒤 파싱하며, 매 패킷마다 포트·플래그를 초기화한다. Go의 재사용 필드나 약한 검사를 안전성 요구로 옮기지 않는다(Go의 필드 갱신 범위: `tailscale.com/net/packet/packet.go:104-123`, `:185-248`).

### 3.2 조각과 IPv6 확장 헤더

| 조건 | Go의 실제 결과 | 출처 |
| --- | --- | --- |
| IPv4 첫 조각(오프셋 0) | TCP·UDP 등 알려진 프로토콜은 전송 헤더 최소 길이를 검사하고 포트를 읽음 | `tailscale.com/net/packet/packet.go:180-242` |
| IPv6 기본 next-header가 44 | 8바이트 Fragment 헤더를 한 번 건너뜀. 내부 `0:1`=next-header, `2:2 >> 3`=오프셋. 첫 조각은 전송 헤더 검사 | `tailscale.com/net/packet/packet.go:307-311`, `:375-408` |
| IPv4·IPv6 비첫 조각 | 오프셋 <10블록(80바이트)이면 Unknown, 그 이상이면 내부 `Fragment` 표지. 재조립·첫 조각과의 연관 검사는 필터에 없음 | `tailscale.com/net/packet/packet.go:249-267`, `:400-408`, `tailscale.com/wgengine/filter/filter.go:712-716` |
| IPv4 TSMP 첫 조각에 MF | Unknown. IPv6 Fragment 헤더의 MF에는 같은 검사가 없음 | `tailscale.com/net/packet/packet.go:230-235`, `:351-358`, `:383-397` |
| 와이어 프로토콜 255 | 첫 조각·비조각 파싱의 switch에서 Unknown으로 바꿈(내부 Fragment와 구분) | `tailscale.com/net/packet/packet.go:243-248`, `:359-364` |

**주석과 코드 불일치:** `decode6` 주석은 다른 확장 헤더를 Unknown으로 버린다고 적지만, 실제 switch에는 그 처리가 없다. next-header 0은 Unknown(0)으로 버려지지만, 0이 아니고 switch에 없는 값(예: 43·60)은 남아 필터의 기타 프로토콜 분기로 간다. 그 번호를 명시하고 목적지 포트 범위가 전부인 규칙이면 허용될 수 있다. 확장 헤더 체인을 순회해 내부 TCP 포트를 읽지는 않는다(`tailscale.com/net/packet/packet.go:278`, `:302-365`, `tailscale.com/types/ipproto/ipproto.go:46-75`, `tailscale.com/wgengine/filter/filter.go:615-619`, `tailscale.com/wgengine/filter/match.go:89-107`).

**M3 권고:** 비첫 조각 허용은 재조립을 맡는 수신 스택이 있어야 완결된다. M3 메모리 시험 장치가 재조립을 지원하지 않는다면 모든 조각을 명시적으로 버리고 관문은 비조각 패킷으로 제한한다. Go와의 차이는 시험에 남긴다(Go의 재조립 전제: `tailscale.com/net/packet/packet.go:260-265`, `:293-300`; 결정은 §6.3).

### 3.3 TSMP 최소 형식

IP 프로토콜 99 안의 메시지이며 아래 오프셋은 IP 헤더 뒤 기준이다(`tailscale.com/net/packet/tsmp.go:66-81`).

| 타입 | 오프셋·길이·내용 | 출처 |
| --- | --- | --- |
| `p` ping | `0:1`=`p`, `1:8` 그대로 돌려받을 데이터. 파서는 9바이트 이상 허용 | `tailscale.com/net/packet/tsmp.go:214-233` |
| `o` pong | `0:1`=`o`, `1:8` ping 데이터, `9:2` PeerAPI 포트. 송신 11바이트, 수신은 9바이트도 허용 | `tailscale.com/net/packet/tsmp.go:235-273` |
| `!` 거절 | `0:1`=`!`, `1:1` 원 프로토콜, `2:1` 이유(`A` ACL·`S` shields-up), `3:2` 원 출발 포트, `5:2` 원 목적 포트, 선택 `7:1` bit0=MaybeBroken | `tailscale.com/net/packet/tsmp.go:25-60`, `:91-107`, `:174-210` |
| `a` disco 광고 | `0:1`=`a`, `1:32` disco 공개 키. 파서는 33바이트 이상 허용 | `tailscale.com/net/packet/tsmp.go:276-330` |

ping에 대한 Go pong은 주소를 맞바꾸고 ping 데이터 8바이트를 복사하며 PeerAPI가 없으면 포트 0을 쓴다. TSMP 거절은 원 목적지→원 출발지로 보내고 포트 필드는 원래 순서를 유지한다(`tailscale.com/net/tstun/wrap.go:1216-1229`, `:1454-1475`).

## 4. 절차와 상태 기계

### 4.1 netmap 피어 → WireGuard 설정

입력은 정규화된 `Node`다. `AllowedIPs`가 JSON에서 생략·null이면 `Addresses` 복사본, 빈 배열이면 그대로 빈 배열이고, `UnsignedPeerAPIOnly`는 `Addresses`로 강제 축소한다. Swiftail의 `Node`도 이 정규화를 한다(`tailscale.com/control/controlclient/map.go:266-274`, `Sources/SwiftailControl/Tailcfg/Node.swift:123-124`, `:146-148`).

1. NodeID·`Key`로 피어를 식별한다. `Key`는 `Machine`·`DiscoKey`와 별개인 WireGuard 공개 키다. magicsock은 NodeID=0 또는 `Key`=0을 오류로 취급하고 endpoint를 만들지 않는다. **Swiftail 권고:** 엔진 입구에서 이 피어를 거부하고 이미 등록된 옛 키를 제거한다. RouteManager 자체에는 zero-key 검사가 없으므로 AllowedIPs만 보고 유효 키라고 판단하지 않는다(`tailscale.com/tailcfg/tailcfg.go:388-395`, `tailscale.com/wgengine/magicsock/magicsock.go:3237-3251`, `tailscale.com/net/routemanager/routemanager.go:408-431`).
2. `Expired`면 후보 접두사가 없다. 또한 `DiscoKey`=0이고 `HomeDERP`=0이고 `IsWireGuardOnly=false`면 후보가 없다. 그 밖에는 **`AllowedIPs`만** 순회한다(`tailscale.com/net/routemanager/routemanager.go:408-431`).
3. 각 접두사 `p`를 `(p.IsSingleIP && IsTailscaleIP(p.Addr)) || Addresses.contains(p)`이면 self, 그 외 route로 분류한다. 여기서 self는 **피어 자신의 주소**이며 로컬 self 노드 주소를 뜻하지 않는다. `Addresses.contains(p)` 분기는 단일 IP 조건을 요구하지 않는다(`tailscale.com/net/routemanager/routemanager.go:422-429`).
4. Tailscale 주소는 IPv4 `100.64.0.0/10`에서 `100.115.92.0/23`을 제외한 것 또는 IPv6 `fd7a:115c:a1e0::/48`이다. IPv4-mapped는 Unmap한다. 접두사 주소를 Unmap한 후 호스트 비트가 남은 항목은 그 항목만 제외한다(`tailscale.com/net/tsaddr/tsaddr.go:23-36`, `:72-91`, `tailscale.com/net/routemanager/routemanager.go:665-687`).
5. 아래 적격 조건을 적용하고 중복을 합쳐 정렬한다. 비어 있으면 그 피어는 WireGuard에 두지 않는다. `Addresses`에 있다고 AllowedIPs에 새로 추가하지 않는다(`tailscale.com/net/routemanager/routemanager.go:260-297`, `:400-407`, `:827-840`).

| 분류 | AllowedIPs에 남길 조건 | 출처 |
| --- | --- | --- |
| self | 기본 항상. `DisableIPv4`가 true이면 IPv4 self 예외(현 LocalBackend는 이를 설정하지 않음) | `tailscale.com/net/routemanager/routemanager.go:828-832`, `tailscale.com/ipn/ipnlocal/node_backend.go:954-960` |
| route 중 정확히 `0.0.0.0/0`·`::/0` | 해석된 `ExitNodeID != 0`이며 그 피어 ID와 같음. `RouteAll`만으로는 허용 안 됨 | `tailscale.com/net/routemanager/routemanager.go:833-837`, `tailscale.com/net/tsaddr/tsaddr.go:270-272` |
| 그 밖의 route | `RouteAll=true` | `tailscale.com/net/routemanager/routemanager.go:837` |
| 확장 훅의 extra AllowedIPs | 본래 유효한 self/route 기여가 있는 피어에만 추가. 수신에는 허용하되 OS 경로는 만들지 않음 | `tailscale.com/net/routemanager/routemanager.go:681-684`, `:825-839`, `:853-855` |

| WireGuard 설정 | 값·주의 | 출처 |
| --- | --- | --- |
| 공개 키 | 피어 `Node.Key` | `tailscale.com/ipn/ipnlocal/resolve.go:29-51`, `tailscale.com/ipn/ipnlocal/node_backend.go:275-288` |
| AllowedIPs | 위에서 남긴 피어별 출발 주소 접두사. 송신 winner의 접두사만으로 축소하지 않음 | `tailscale.com/net/routemanager/routemanager.go:282-296`, `:846-862` |
| PSK | 이 LocalBackend 경로에서는 zero. PSK 계층을 설정하지 않음 | `tailscale.com/ipn/ipnlocal/resolve.go:49-52`, `tailscale.com/wgengine/wgcfg/config.go:33-35` |
| PersistentKeepalive | 0(비활성). 현 `PeerConfig`와 지연 생성 경로는 값을 설정하지 않음. WireGuard의 데이터 기반 keepalive와는 별개 | `tailscale.com/wgengine/wgcfg/config.go:28-35`, `wireguard-go/device/device.go:551-575`, `wireguard-go/device/peer.go:97`, `:134-135`, `wireguard-go/device/timers.go:110-116`, `:220-225` |
| endpoint | 공개 키의 접두사 없는 hex 문자열을 `bind.ParseEndpoint`에 주어 얻은 **magicsock 피어 객체**. `Node.Endpoints`나 DERP 서버 IP를 WireGuard endpoint로 넣지 않음 | `tailscale.com/wgengine/wgcfg/device.go:47-64`, `tailscale.com/wgengine/magicsock/magicsock.go:3943-3965` |

**만료:** Go는 보정된 현재 시각 `controlNow = localNow + clockDelta`에 대해 nonzero `KeyExpiry <= controlNow`이면 `Expired=true`, `Endpoints=nil`, `HomeDERP=0`, 공개 키를 의도적으로 깨진 값으로 바꾼다. `abs(ControlTime-localNow) > 1분`일 때만 delta를 저장하고 아니면 0으로 되돌린다. 판정 중단 조건은 **보정된 현재 시각**이 epoch `1673373066`보다 이전인 것이지, 마지막 `ControlTime` 필드 자체가 오래된 것이 아니다(`tailscale.com/ipn/ipnlocal/expiry.go:23-28`, `:65-73`, `:92-135`). **Swiftail 권고:** `Node`를 변조하기보다 엔진의 파생 상태에서 만료를 계산하여 WireGuard 피어·relay 송신 자격을 제거하고 만료 기한에도 다시 계산한다. Go도 다음 만료 시각을 계산한다(`tailscale.com/ipn/ipnlocal/expiry.go:139-181`).

### 4.2 송신 피어 선택과 게으른 구성

Go 송신 선택은 (1) self와 모든 피어의 **단일 IP `Addresses`** 정확 일치 → (2) 적격 경로의 LPM → (3) 실패면 조용히 버림이다. 같은 접두사의 winner는 높은 점수, 동점이면 작은 NodeID다. 정확 일치 경로는 AllowedIPs 포함 여부를 보지 않지만, 이어지는 피어 설정 조회에서 후보 없음·만료 피어가 걸러진다(`tailscale.com/ipn/ipnlocal/node_backend.go:712-734`, `tailscale.com/ipn/ipnlocal/resolve.go:20-52`, `tailscale.com/net/routemanager/routemanager.go:846-862`, `wireguard-go/device/send.go:388-413`).

| 사건 | Go의 동작 | 출처 |
| --- | --- | --- |
| 송신 또는 수신 initiation이 피어 키를 조회 | 없으면 live `peerConfig`를 조회해 생성. 수신만 있어도 생성 가능 | `wireguard-go/device/device.go:542-575`, `wireguard-go/device/noise-protocol.go:386-389` |
| netmap 변경의 `SyncDevicePeer` | 설정 불가면 제거. 이미 존재하면 AllowedIPs·PSK만 갱신. **아직 없는 피어는 생성하지 않음** | `tailscale.com/wgengine/userspace.go:698-717` |
| 지연 피어 생성 | `deleteOnIdle=true`. 시작 때 540초 정리 타이머 | `wireguard-go/device/device.go:568`, `wireguard-go/device/peer.go:310-316` |
| 세션 키 파생 | 정리 타이머를 다시 540초로 설정 | `wireguard-go/device/timers.go:206-214` |
| 핸드셰이크 포기 | 정리 타이머가 **아직 없을 때만** 540초 설정. 이미 진행 중인 타이머를 연장하지 않음 | `wireguard-go/device/timers.go:80-98` |
| 정리 타이머 만료 | 키를 지우고 `deleteOnIdle` 피어 제거 | `wireguard-go/device/timers.go:127-138` |

**M3 설계 선택:** 지연 생성·유휴 피어 삭제는 상호 운용에 필수인 와이어 규칙이 아니다. 이 결론은 생성 시점이 로컬 조회 콜백으로 정해지고 일반 `NewPeer`도 있는 구조에서 도출한 것이다. 유효한 모든 피어를 netmap 적용 때 `addPeer`하고 삭제·만료·AllowedIPs 변경을 동기화하는 방식을 권고한다. Swiftail은 수신 전 피어 등록이 필요하고 540초 타이머도 키만 지운다(`wireguard-go/device/device.go:542-575`, `wireguard-go/device/peer.go:117-170`, `Sources/SwiftailWireGuard/WireGuardDevice.swift:57-78`, `Sources/SwiftailWireGuard/WireGuardDevice+Receiving.swift:35-43`, `Sources/SwiftailWireGuard/WireGuardDevice+Timers.swift:57-59`).

### 4.3 엔진 → DERP/magicsock 경계

| netmap에서 뽑을 정보 | 전달 목적·M3/M4 경계 | 출처 |
| --- | --- | --- |
| `Node.ID`·`Key` | 피어 식별. 키 회전·삭제 때 옛 키의 relay 경로도 제거 | `tailscale.com/wgengine/magicsock/magicsock.go:3192-3198`, `:3237-3251` |
| 피어 `HomeDERP`, 전역 `DERPMap` | 지역 ID→DERP 서버 연결 정보. HomeDERP=0은 모름. DERP 지도는 self/peer 목록과 별도로 갱신 | `tailscale.com/tailcfg/tailcfg.go:418-423`, `tailscale.com/ipn/ipnlocal/local.go:2094-2109`, `tailscale.com/wgengine/magicsock/endpoint.go:1733-1752` |
| `DiscoKey`·`Endpoints`·`Cap`·`Expired` | disco 키·직접 UDP 후보·peer relay 지원·만료 상태. M3에서는 직접 UDP 후보를 사용하지 않아도 되지만 필드를 WireGuard 키와 섞지 않음 | `tailscale.com/wgengine/magicsock/endpoint.go:1717-1759` |
| self 주소·자기 node private key·disco private key | TSMP 광고 주소 선택, DERP 인증, disco. 개인 키는 DERP 준비 후 WireGuard에 적용하는 순서 | `tailscale.com/wgengine/magicsock/magicsock.go:4631-4665`, `tailscale.com/wgengine/userspace.go:886-899` |
| `IsJailed`·masquerade 주소 | 엔진의 필터 선택·SNAT/DNAT 입력. 직접 경로 탐색과 별개 | `tailscale.com/net/tstun/wrap.go:667-687`, `:707-731` |

RouteManager의 후보 조건은 magicsock의 endpoint 조건과 다르다. 예컨대 `HomeDERP != 0`만으로 RouteManager에는 남을 수 있지만 magicsock은 `DiscoKey=0`인 비-WireGuard-only 피어를 지원하지 않는다. zero node key도 endpoint로 만들지 않는다(`tailscale.com/net/routemanager/routemanager.go:416-421`, `tailscale.com/wgengine/magicsock/magicsock.go:3242-3244`, `:3258-3267`, `:3305-3308`). **M3 권고:** 일반 Go tsnet 피어·유효한 HomeDERP/DERPMap만 지원 대상으로 정하고, WireGuard-only·masquerade 같은 미지원 모드는 명시적으로 거부한다. 세부 경로 선택·DERP return-route는 다른 노트의 계약으로 둔다.

### 4.4 `FilterRule` → 일치 규칙

Swiftail `Netmap.packetFilter`는 이미 이름별 묶음을 이은 **원시 `FilterRule`** 목록이다. `SrcIPs` 등 문자열 해석은 엔진 몫이다. Go control은 같은 병합 뒤 변환 결과를 보관한다(`Sources/SwiftailControl/Netmap/Netmap.swift:16-17`, `Sources/SwiftailControl/Tailcfg/FilterRule.swift:5-9`, `tailscale.com/control/controlclient/map.go:449-480`).

1. `SrcBits`가 비어 있지 않거나 `DstPorts[].Bits != nil`이면 **전체 변환 결과 nil + 오류**다. Go 호출자는 오류를 기록하고 이 nil 결과를 설치한다. Swiftail도 이전의 넓은 허용 규칙을 그대로 유지하는 방식으로 실패하지 않도록 한다(`tailscale.com/wgengine/filter/tailcfg.go:38-40`, `:75-78`, `tailscale.com/control/controlclient/map.go:475-480`).
2. `IPProto`가 nil/빈 배열이면 `{6,17,1,58}`(TCP·UDP·ICMPv4·ICMPv6). 명시된 배열에서는 0...255만 남긴다. 명시 배열이 모두 범위 밖이면 결과는 빈 프로토콜 집합이며 기본 집합으로 되돌리지 않는다(`tailscale.com/wgengine/filter/tailcfg.go:21-26`, `:50-60`).
3. `SrcIPs`와 `DstPorts[].IP`의 각 문자열을 아래 순서로 해석한다. 출발지 목록은 OR이며 출발 포트 조건은 없다(`tailscale.com/wgengine/filter/tailcfg.go:62-96`, `:138-180`, `tailscale.com/wgengine/filter/match.go:17-53`).
4. 각 목적지 접두사와 원래 `Ports.First...Last`를 묶어 `Dsts`를 만든다. 범위는 양끝 포함이며 First>Last이면 아무 포트도 일치하지 않는다(`tailscale.com/wgengine/filter/tailcfg.go:88-96`, `tailscale.com/wgengine/filter/filtertype/filtertype.go:21-40`).
5. `CapGrant`는 `Dsts × (Caps와 CapMap의 각 항목)`을 능력 목록으로 변환한다. 폐지된 `Caps`에는 값이 없고 `CapMap`에는 JSON 값 목록이 있다. 이는 패킷 허용과 별개다. 스키마는 `DstPorts`와 `CapGrant`의 동시 non-nil을 금하지만 이 변환 함수가 상호 배제를 검사하지는 않는다(`tailscale.com/wgengine/filter/tailcfg.go:75-114`, `tailscale.com/tailcfg/tailcfg.go:1580-1595`, `:1750`, `:1764-1774`).
6. IPv4·IPv6별로 출발·목적 접두사를 나눈다. 패킷 규칙은 `(Srcs가 있거나 SrcCaps가 있음) && Dsts가 있음`인 것만 남긴다. 능력 규칙은 해당 계열의 **Srcs**와 능력 항목이 있을 때만 남긴다(`tailscale.com/wgengine/filter/filter.go:267-312`).

| 문자열 | 해석·오류 | 출처 |
| --- | --- | --- |
| `*` | IPv4 /0와 IPv6 /0 둘 다 | `tailscale.com/wgengine/filter/tailcfg.go:138-145` |
| `cap:<이름>` | SrcCaps에 노드 capability 이름. 목적지에 nonempty capability면 오류·그 항목 제외. 빈 `cap:`는 결과 없음 | `tailscale.com/wgengine/filter/tailcfg.go:69-71`, `:84-87`, `:146-148` |
| `/`를 포함 | CIDR. 호스트 비트가 남으면 오류(조용히 mask하지 않음) | `tailscale.com/wgengine/filter/tailcfg.go:149-157` |
| `-`가 정확히 하나 | 같은 주소 계열의 양끝 포함 IP 범위. 역순·잘못된 범위는 오류, 유효 범위는 접두사들로 분해 | `tailscale.com/wgengine/filter/tailcfg.go:159-173` |
| 그 외 | 단일 IP → /32 또는 /128 | `tailscale.com/wgengine/filter/tailcfg.go:175-179` |

주소 표현 오류는 변환 가능한 나머지 항목을 유지한다. Go는 보통 첫 오류를 보관하지만 **목적지 capability 오류는 기존 오류를 덮어쓸 수 있다**. 규칙 전체를 원자적으로 버리는 구현도 아니며, 모든 오류가 전체 nil을 만드는 것도 아니다(`tailscale.com/wgengine/filter/tailcfg.go:30-33`, `:62-86`, `:116-118`).

| 일치 함수 | 조건 | 출처 |
| --- | --- | --- |
| `match` (TCP SYN·UDP·SCTP) | 같은 규칙에서 프로토콜 일치 AND (출발 주소∈Srcs OR 출발 노드의 capability∈SrcCaps) AND 어느 Dst의 주소·목적 포트 일치. 허용의 합이며 deny 규칙·우선순위 없음 | `tailscale.com/wgengine/filter/match.go:17-53` |
| `matchIPsOnly` (ICMP) | 프로토콜·포트 무시. Srcs와 Dsts 주소가 맞으면 허용. 별도 SrcCaps 경로는 capability만 맞아도 허용하며 목적지 재검사 없음 | `tailscale.com/wgengine/filter/match.go:62-84` |
| 기타 프로토콜 | 프로토콜·Srcs·목적지 주소가 맞고 Ports가 정확히 `0...65535`. **SrcCaps는 검사하지 않음** | `tailscale.com/wgengine/filter/match.go:89-107` |

SrcCaps 조회는 `Addresses`의 단일 IP→노드 색인을 쓰고 `UnsignedPeerAPIOnly`는 false로 판정한다. 서브넷 뒤의 주소에 capability를 상속하지 않는다. CapGrant만 있는 규칙은 패킷 허용에 기여하지 않는다(`tailscale.com/ipn/ipnlocal/node_backend.go:719-734`, `tailscale.com/ipn/ipnlocal/local.go:9318-9334`, `tailscale.com/wgengine/filter/filter.go:267-312`).

능력 조회 `CapsWithValues(src,dst)`는 Srcs와 목적 접두사를 맞춰 같은 capability의 JSON 값 목록을 누적한다. SrcCaps·프로토콜·포트 조건은 능력 조회에 사용하지 않는다. Node capability 검사는 `CapMap`의 키 존재 검사다(`tailscale.com/wgengine/filter/filter.go:294-312`, `:410-434`, `tailscale.com/tailcfg/tailcfg.go:574-575`).

### 4.5 필터 설치와 상태

1. netmap 이전에는 `NewAllowNone`(규칙 없음·localNets 없음)을 설치한다. nil 필터도 수신·송신 모두 Drop이다(`tailscale.com/ipn/ipnlocal/local.go:3533-3538`, `tailscale.com/wgengine/filter/filter.go:199-201`, `tailscale.com/net/tstun/wrap.go:820-822`, `:1190-1192`).
2. M3의 `localNets`는 self `Addresses`만으로 정한다는 설계를 권고한다. Go는 여기에 호스팅 VIP·광고 경로·앱 커넥터용 주소도 넣지만 이들은 M3 관문 밖이다(`tailscale.com/ipn/ipnlocal/local.go:3452-3511`, `docs/plan.md:193`).
3. prefs가 유효하지 않거나 ShieldsUp이면 규칙 없는 shields-up 필터, 아니면 변환한 규칙을 설치한다. jailed 피어용은 별도의 shields-up 필터다(`tailscale.com/ipn/ipnlocal/local.go:3446`, `:3541-3555`).
4. `UnsignedPeerAPIOnly` 피어의 AllowedIPs와 Srcs가 겹치는 패킷 허용 규칙(Dsts가 있음)이 하나라도 있으면 전체 패킷 규칙을 비운다. SrcCaps 검사는 이 안전장치에 들어 있지 않다(`tailscale.com/ipn/ipnlocal/local.go:3459-3463`, `:3568-3598`).
5. 일반 필터 교체는 이전 UDP/SCTP 상태를 공유한다. shields-up 필터를 만들 때는 이전 것도 shields-up인 경우만 공유하며, jailed 캐시는 일반 캐시와 별도로 유지한다(`tailscale.com/wgengine/filter/filter.go:204-234`, `tailscale.com/ipn/ipnlocal/local.go:3553-3555`).

Go의 jailed 필터 선택은 피어 경로 테이블에서 수신 **출발 IP**, 송신 **목적 IP**를 LPM 조회한 `Jailed` 값으로 한다. WireGuard 피어의 실제 출처 검증은 이 선택보다 앞에 있다(`tailscale.com/net/tstun/wrap.go:667-687`, `:812-819`, `:1184-1189`, `wireguard-go/device/receive.go:510-528`).

캐시 키는 `(IPProto, srcIP, srcPort, dstIP, dstPort)`이고 최대 512개 LRU다. 송신 UDP/SCTP의 **역방향 튜플**을 넣고 수신에서 조회하며, 조회도 최근 사용 순서를 갱신한다. TTL은 없다. 수신 허용 자체는 캐시에 새 항목을 넣지 않는다. TCP·ICMP 연결 상태는 이 캐시에 기록하지 않는다(`tailscale.com/wgengine/filter/filter.go:102-109`, `:538-550`, `:600-611`, `:625-650`, `tailscale.com/net/flowtrack/flowtrack.go:22-44`, `:102-151`).

### 4.6 패킷 판정과 출처 검사

**계층 순서:** WireGuard의 인증·재전송 방지 → IP 길이 정리·**그 인증 피어의 AllowedIPs로 출발지 검사** → 필요하면 DNAT → TSMP 등 엔진 제어 패킷 → 수신 필터 → netstack 또는 TUN이다. DERP 프레임에 적힌 출발 키나 ACL 규칙만으로 WireGuard의 출처 검사를 대체하지 않는다(`wireguard-go/device/receive.go:465-539`, `tailscale.com/net/tstun/wrap.go:1270-1277`, `:1128-1254`).

`RunIn`·`RunOut`의 공통 `pre`는 다음 순서에서 첫 판정으로 끝낸다(`tailscale.com/wgengine/filter/filter.go:688-720`).

| 순서 | 조건 | 판정·출처 |
| --- | --- | --- |
| 1 | 길이 0 | Accept. 실제 WireGuard keepalive는 장치에서 소비되어 스택으로 올라오지 않음 — `tailscale.com/wgengine/filter/filter.go:689-691`, `wireguard-go/device/receive.go:491-494` |
| 2 | 길이 <20 | Drop — `tailscale.com/wgengine/filter/filter.go:693-696` |
| 3 | Unknown(0) | Drop — `tailscale.com/wgengine/filter/filter.go:698-701` |
| 4 | 목적이 multicast | Drop — `tailscale.com/wgengine/filter/filter.go:703-706` |
| 5 | 목적이 link-local unicast | `169.254.169.254` 또는 확장 훅 예외 외 Drop — `tailscale.com/wgengine/filter/filter.go:672-684`, `:707-710` |
| 6 | 내부 Fragment 표지 | Accept. **localNets·ACL보다 먼저** — `tailscale.com/wgengine/filter/filter.go:712-716` |

수신은 그다음 IP 계열을 고르고, 우선 목적지가 localNets 안인지 검사한다. 밖이면 noVerdict다. 아래도 noVerdict이면 Go는 IngressAllowHooks를 시도한 뒤 최종 Drop하며, M3 권고는 훅 없이 Drop이다. 따라서 일반 패킷의 비자기 목적지는 허용 ACL이 있어도 버린다. **비첫 조각과 앞에서 소비되는 TSMP는 별도**라는 점에 유의한다(`tailscale.com/wgengine/filter/filter.go:443-471`, `:502-509`, `:564-570`, `tailscale.com/net/tstun/wrap.go:1133-1157`).

| 프로토콜 | localNets 검사 뒤 수신 판정 | 출처 |
| --- | --- | --- |
| ICMPv4·ICMPv6 | echo reply·error는 상태 확인 없이 Accept. 그 외 `matchIPsOnly`면 Accept | `tailscale.com/wgengine/filter/filter.go:510-522`, `:572-584` |
| TCP | SYN=1 AND ACK=0인 패킷만 `match`. SYN-ACK·ACK·RST·그 밖의 non-SYN은 Accept. **TCP 세션 추적을 해서 허용하는 것이 아님** | `tailscale.com/wgengine/filter/filter.go:523-537`, `:585-599`, `tailscale.com/net/packet/packet.go:491-495` |
| UDP·SCTP | 캐시 적중 OR `match`이면 Accept | `tailscale.com/wgengine/filter/filter.go:538-550`, `:600-612` |
| TSMP | 필터까지 왔다면 Accept | `tailscale.com/wgengine/filter/filter.go:551-552`, `:613-614` |
| 그 밖 | §4.4의 기타 프로토콜 조건일 때 Accept | `tailscale.com/wgengine/filter/filter.go:553-559`, `:615-621` |

ICMP echo는 v4 type 8/0, v6 type 128/0이고 reply는 v4 0/0, v6 129/0이다. Go 오류 판별의 type 집합은 v4 `{3,11,0x12}`, v6 `{1,2,3,4}`다. `0x12`는 소스 상수 그대로이며 표준 적합성은 §8로 남긴다(`tailscale.com/net/packet/icmp4.go:22-26`, `tailscale.com/net/packet/icmp6.go:22-27`, `tailscale.com/net/packet/packet.go:497-539`).

**송신:** 앞단 TUN 래퍼는 host에서 나온 TSMP와 자기 disco UDP를 먼저 버린다. 그 뒤 `RunOut`은 `pre`를 통과하면 모두 Accept하며 ACL의 SrcIPs·DstPorts를 역으로 검사하지 않는다. UDP/SCTP 역방향 상태를 기록한 후 SNAT한다. **프로세스 내 스택 주입은 `RunOut`을 건너뛰지만 같은 상태 기록은 반드시 수행**한다. jailed 대상 송신도 jailed 필터의 캐시에 기록해야 응답이 같은 필터에서 허용된다(`tailscale.com/net/tstun/wrap.go:771-788`, `tailscale.com/wgengine/filter/filter.go:476-487`, `:625-650`, `tailscale.com/net/tstun/wrap.go:812-832`, `:932-934`, `:1052-1072`, `:1099`).

**거절 응답:** Go 필터 거절은 TCP RST를 만들지 않는다. `IPv4 && TCP && SYN 비트 켜짐 && !disableTSMPRejected`이면 `!` TSMP를 보낸다. 이 조건은 SYN-ACK도 포함하므로 `IsTCPSyn`과 같지 않다. PeerAPI 포트의 SYN 비트 패킷은 거절 후 L7 검사 예외로 Accept가 될 수 있다. M3 권고는 PeerAPI를 열지 않고 TSMP 거절 송신을 생략하되 원 패킷은 반드시 버리는 것이다(`tailscale.com/net/tstun/wrap.go:1195-1236`).

### 4.7 프로세스 내 수신: UDP·TCP·ping

Go netstack은 `PostFilterPacketInboundFromWireGuard`에 설치된다. tsnet은 기본 fake TUN일 때 `ProcessLocalIPs=true`·`ProcessSubnets=true`를 켠다. self 주소는 netmap에서 스택 NIC에 등록하며, local 여부는 self `Addresses` 집합으로 판단한다(`tailscale.com/wgengine/netstack/netstack.go:465-466`, `:729-770`, `:810-825`, `tailscale.com/tsnet/tsnet.go:916-933`).

1. 복호화·출처 검사·수신 필터를 통과한 패킷만 이 경계에 넣는다. `ProcessLocalIPs && isLocal`이면 프로토콜에 관계없이 netstack 처리 대상이다. PeerAPI·서비스·4via6 가로채기와 `ProcessSubnets`는 별도 조건이며 M3의 자기 주소 UDP/TCP 관문에는 필요 없다(`tailscale.com/net/tstun/wrap.go:1193-1252`, `tailscale.com/wgengine/netstack/netstack.go:1279-1357`).
2. 준비가 안 되었거나 종료 중이면 조용히 버린다. 처리 대상은 link endpoint로 전달하고 `DropSilently`로 TUN에 중복 전달되는 것을 막는다(`tailscale.com/wgengine/netstack/netstack.go:1472-1513`).
3. 수신 스택이 만든 응답은 WireGuard 방향 큐→`InjectOutboundPacketBuffer`로 보낸다. 이 경로에서도 §4.6의 UDP 상태를 기록하고 목적지로 피어를 선택한다(`tailscale.com/wgengine/netstack/netstack.go:1047-1083`, `tailscale.com/net/tstun/wrap.go:1052-1072`, `wireguard-go/device/send.go:388-413`).

| 자기 주소로 받은 패킷 | Go tsnet에서 응답하는 곳·조건 | M3 관문에 주는 의미와 출처 |
| --- | --- | --- |
| UDP | `ListenPacket`은 gVisor UDP endpoint를 등록. 미등록 흐름은 UDP forwarder에서 tsnet handler를 조회하고, 리스너가 없으면 닫아 소비(자동 echo 아님) | UDP 에코는 **시험용 앱/피어 리스너**가 구현. 미취급 UDP에 ICMP port-unreachable을 보내지 않도록 forwarder는 true 반환 — `tailscale.com/tsnet/tsnet.go:1305-1310`, `:1392-1420`, `tailscale.com/wgengine/netstack/netstack.go:2000-2010`, `:2054-2067` |
| TCP SYN, 처리할 리스너·handler 있음 | TCP endpoint 생성으로 handshake 시작, 완료 뒤 handler에 연결 제공 | 허용된 포트에 리스너가 있어야 SYN-ACK를 기대할 수 있음 — `tailscale.com/tsnet/tsnet.go:1289-1302`, `tailscale.com/wgengine/netstack/netstack.go:1662-1673`, `:1712-1719`, `:1748-1760` |
| TCP SYN, 리스너·fallback 없음 | tsnet의 `(nil,true)` 결과에 `Complete(true)` 호출 → RST | **ACL 차단(스택 전 Drop)**과 **닫힌 포트(스택 RST)**를 다른 시험으로 둠 — `tailscale.com/tsnet/tsnet.go:1289-1300`, `tailscale.com/wgengine/netstack/netstack.go:1748-1753`, `:1607-1611`, `tailscale.com/net/tstun/wrap.go:1206-1236` |
| ICMP echo request | Tailscale 주소는 subnet ping 대리 처리에서 제외되어 gVisor로 들어감. IPv4·IPv6 스택은 소비하는 별도 handler 등이 없으면 echo reply 생성 | ping은 ACL 통과와 reply 생성을 구분. **필터 Accept 자체가 echo reply를 만들지는 않음** — `tailscale.com/wgengine/netstack/netstack.go:1484-1505`, `:1570-1584`, `gvisor/pkg/tcpip/network/ipv4/icmp.go:346-380`, `gvisor/pkg/tcpip/network/ipv6/icmp.go:655-678` |

**M3 설계 권고:** Swiftail에 완성 TCP/UDP 스택을 추가하지 않는다. 메모리 패킷 경계를 제공하고 Go tsnet 쪽 UDP echo·TCP 리스너로 관문을 검증한다. Swiftail 수신 응답도 관문에 넣는다면 시험 전용 UDP echo·TCP SYN 응답 장치를 경계에 연결한다. 실제 공개 listen/dial 스택은 M6 범위다(`docs/plan.md:57`, `:193-196`).

### 4.8 TUN·라우터 설정 (M5, M3에서는 건너뜀)

로컬 송신 TUN에서는 서비스 IP `100.100.100.100`·`fd7a:115c:a1e0::53`의 ICMP echo를 래퍼가 로컬 reply로 주입하고, netstack은 해당 두 IP의 모든 프로토콜·포트를 흡수한다. darwin/ios 자기 터널 주소 목적 패킷은 엔진이 OS로 반사한다. netstack 자체의 self 목적 송신은 별도 loopback 큐를 쓴다(`tailscale.com/net/tstun/wrap.go:752-769`, `tailscale.com/wgengine/netstack/netstack.go:866-896`, `:1047-1060`, `tailscale.com/wgengine/userspace.go:652-667`).

1. `LocalAddrs`는 self `Addresses`를 Unmap한 목록이다. `Routes`는 적격 피어 기여 접두사에서 아래 규칙으로 산출한 집합을 정렬한다(`tailscale.com/ipn/ipnlocal/local.go:6710-6716`, `:6800-6810`, `tailscale.com/ipn/ipnlocal/node_backend.go:988-996`).
2. self에 IPv4가 있으면 `100.100.100.100/32`, IPv6가 있으면 `fd7a:115c:a1e0::53/128`을 추가한다. 호스팅 VIP는 같은 계열 주소가 있는 경우 뒤에 추가한다(`tailscale.com/ipn/ipnlocal/local.go:6773-6790`).
3. exit node를 선택했다면 라우팅 가능한 피어가 없어도 두 /0을 OS 경로에 남겨 블랙홀로 만든다. LAN·로컬 경로 조정도 있지만 M3 및 기본 M5에서는 exit node 기능을 노출하지 않는 설계를 권고한다(`tailscale.com/net/routemanager/routemanager.go:1009-1014`, `tailscale.com/ipn/ipnlocal/local.go:6726-6771`).
4. 변경 때만 router callback을 호출한다. Go의 `Config.Equal`은 순서까지 비교한다. CallbackRouter의 `InitialMTU`는 첫 Set에만 `NewMTU`로 전달하며, 0은 변경 없음이다. **권고:** Swiftail 산출 목록도 순서를 고정한다(`tailscale.com/wgengine/router/router.go:123-126`, `:145-152`, `tailscale.com/wgengine/router/callback.go:27-31`, `:45-67`).

| 적격 접두사 분류 | OS Routes | 출처 |
| --- | --- | --- |
| CGNAT 안 단일 IPv4 | 기본 개별 /32. 고유 접두사 수가 10,000 초과면 /10 하나. OneCGNAT=true면 임계값 1(2개부터 /10) | `tailscale.com/net/routemanager/routemanager.go:148`, `:874-891`, `:959-972` |
| Tailscale ULA 안 단일 IPv6 | 개별 /128 대신 적격 기여가 하나라도 있으면 /48 하나 | `tailscale.com/net/routemanager/routemanager.go:881-883`, `:934-957` |
| 그 외 | 적격 접두사 그대로. extra AllowedIPs는 제외 | `tailscale.com/net/routemanager/routemanager.go:846-884`, `:948-952` |

OS 집계는 **피어 기여**에서 계산하며 self 주소 자체가 /48 경로를 만들지는 않는다. OS의 /10·/48 집계를 WireGuard AllowedIPs에 사용해서는 안 된다. CGNAT 집계 판정은 ChromeOS 대역을 포함하지만 self 주소 분류의 `IsTailscaleIP`는 제외한다(`tailscale.com/net/routemanager/routemanager.go:282-296`, `:408-431`, `:874-883`, `:986-1025`, `tailscale.com/net/tsaddr/tsaddr.go:83-90`).

`OneCGNAT`은 제어 지시가 최우선, plan9는 true, macOS·android는 다른 CGNAT 인터페이스가 없을 때 true, 나머지(iOS 포함)는 false다. 따라서 **iOS 기본은 개별 /32**다. `one-cgnat?v=true/false` 해석은 controlknobs가 담당한다(`tailscale.com/ipn/ipnlocal/local.go:6364-6398`, `tailscale.com/control/controlknobs/controlknobs.go:190-193`, `tailscale.com/tailcfg/nodecap/nodecap.go:148-153`).

## 5. 상수와 타이머

| 항목 | 값 | 출처 |
| --- | --- | --- |
| 필터 캐시 | 512개 LRU, TTL 없음 | `tailscale.com/wgengine/filter/filter.go:102-109`, `tailscale.com/net/flowtrack/flowtrack.go:102-151` |
| 비첫 조각 최소 오프셋 | 10×8=80바이트 | `tailscale.com/net/packet/packet.go:25`, `:251-266`, `:403-407` |
| 지연 피어 정리 | 540초(RejectAfterTime×3). 시작·키 파생·포기 시 조건은 §4.2 | `wireguard-go/device/constants.go:22`, `wireguard-go/device/peer.go:314-315`, `wireguard-go/device/timers.go:95-96`, `:214` |
| 시계 delta 저장 | 차이 절댓값이 **1분 초과** | `tailscale.com/ipn/ipnlocal/expiry.go:28`, `:65-73` |
| 기본 안전 TUN MTU | 1280(다른 정보가 없을 때) | `tailscale.com/net/tstun/mtu.go:76-79` |
| OS CGNAT 집계 | 기본 10,000 초과, OneCGNAT는 1 초과 | `tailscale.com/net/routemanager/routemanager.go:148`, `:887-891`, `:959` |

WireGuard의 재키·핸드셰이크 재시도·keepalive 타이머는 [wireguard.md](wireguard.md)의 검증된 표를 따른다. 여기서 재시도 상수 하나만 보고 “정확히 90초 뒤 종료”로 바꾸지 않는다. 실제 종료는 시도 횟수와 지터에 의존한다(`wireguard-go/device/constants.go:17-25`, `wireguard-go/device/timers.go:80-106`, `:185-192`).

## 6. Swiftail에 필요한 최소 부분과 생략할 수 있는 부분

### 6.1 M3 권고 절차

다음은 **엔진 계약 제안**이다. Go의 소유 구조·콜백 이름까지 재현할 필요는 없다(입출력 없는 WireGuard 계약: `docs/contracts/SwiftailWireGuard.md:3-13`; 관문: `docs/plan.md:193`).

1. `Netmap`과 시각을 받아 §4.1의 자격·AllowedIPs, 자기 목적지 집합, 주소→피어/키 색인, §4.4의 필터를 값으로 계산한다. `RouteAll=false`·exit node 없음으로 범위를 고정한다. 미지원 WireGuard-only·masquerade·tailnet lock은 지원하지 않음을 명시한다(필드: `Sources/SwiftailControl/Netmap/Netmap.swift:22-25`, `Sources/SwiftailControl/Tailcfg/Node.swift:69-76`; 계산 근거: §4.1·4.3).
2. 한 엔진 소유자가 패킷 처리를 직렬화하면서 삭제·키 회전·만료 피어를 `removePeer`, 유효 피어를 `addPeer`한다. 기존 같은 키의 AllowedIPs 갱신은 세션을 유지한다. relay 지역·피어 정보를 먼저 준비한 뒤 핸드셰이크 출력이 나가게 한다(`Sources/SwiftailWireGuard/WireGuardDevice.swift:57-78`, Go 순서 근거: `tailscale.com/wgengine/magicsock/magicsock.go:3957-3962`, `tailscale.com/wgengine/userspace.go:886-899`).
3. DERP에서 받은 WireGuard 바이트를 장치에 넣는다. 장치의 `ipPacket`만 §4.6 수신 필터로 보내고 Accept만 메모리 패킷 경계에 전달한다. 일반·jailed 필터를 구분하고 noVerdict는 Drop으로 끝낸다(출력 계약: `Sources/SwiftailWireGuard/WireGuardDevice.swift:18-31`; 판정 근거: §4.5~4.7).
4. 로컬 패킷은 구조 검증→특수 목적지 로컬 처리→§4.6 송신 판정·상태 기록→§4.2 피어 선택→`send`로 보낸다. `.datagram(to:)`를 공개 키에 대응하는 DERP 경로로 전달한다. netmap·만료·필터 갱신도 같은 소유자에서 적용한다(장치 경계: `docs/contracts/SwiftailWireGuard.md:70-101`; Go 주입·순서 근거: §4.3·4.6).
5. `nextDeadline`에 맞춰 `advance`를 호출한다. TCP SYN-ACK·UDP echo 응답 생성의 책임은 §4.7처럼 수신 장치/시험 피어에 둔다. 필터가 응답 스택을 겸하지 않게 한다(`Sources/SwiftailWireGuard/WireGuardDevice.swift:80-82`, `docs/contracts/SwiftailWireGuard.md:113`; Go 근거: §4.7).

### 6.2 M5로 미루거나 별도 마일스톤인 것

| 항목 | 범위·생략 근거 | 출처 |
| --- | --- | --- |
| 주소·OS 경로·DNS 설정, utun, 자기 주소 반사, 서비스 IP 로컬 처리 | M5. §4.8에서 산출, MagicDNS UDP 응답은 dns-state-node 노트와 결합 | `docs/plan.md:195`, `tailscale.com/net/tstun/wrap.go:752-769`, `tailscale.com/wgengine/netstack/netstack.go:875-896` |
| 직접 UDP 후보·disco 탐색 | M4. M3은 DERP 전용 | `docs/plan.md:193-194` |
| 공개 TCP/UDP listen·dial, 완전한 재조립 스택 | M6. M3 관문은 메모리 패킷 경계·Go tsnet 리스너로 검증 | `docs/plan.md:57`, `:193-196` |
| 서브넷·exit node 수락·제공, VIP·4via6, 앱 커넥터 | M3 및 기본 M5에서 미지원으로 고정하는 권고. false prefs·광고 없음이면 해당 경로가 필요 없음 | `tailscale.com/net/routemanager/routemanager.go:827-839`, `tailscale.com/ipn/ipnlocal/local.go:3470-3511` |
| 지연 생성·유휴 피어 제거 | M3 생략 가능(§4.2). M5 메모리 측정 때 재검토 권고 | `wireguard-go/device/device.go:542-575`, `docs/plan.md:199` |
| TSMP ping/pong·거절·광고 | 진단 ping과 disco 갱신용. UDP/TCP 관문에서는 송신 생략 가능이라는 설계 판단. 수신은 앱 IP 입력과 분리해 소비하고, ping 진단을 제공하면 §3.3의 pong 구현 | `tailscale.com/wgengine/userspace.go:1272-1298`, `tailscale.com/net/tstun/wrap.go:1133-1157`, `:1454-1475`, `tailscale.com/wgengine/magicsock/magicsock.go:4631-4677` |
| WhoIs·PeerCaps 공개 API | M7. CapGrant를 패킷 허용으로 잘못 해석하지 않는 처리는 M3부터 필요 | `docs/plan.md:197`, `tailscale.com/wgengine/filter/filter.go:267-312`, `:410-434` |
| 로그 속도 제한·흐름 로그·pendopen·PeerAPI 예외 | M3 관문에 필수 아님. Drop 판정과 캐시를 생략하는 근거는 아님 | `tailscale.com/wgengine/filter/filter.go:326-327`, `tailscale.com/net/tstun/wrap.go:1178-1204` |

Go의 TSMP ping·disco 광고는 수신 필터 전에 소비되지만 pong은 콜백 뒤 계속 진행할 수 있다. **Swiftail 권고:** TSMP 전부를 엔진에서 소비하고 일반 앱 스택에 내보내지 않는다. Go 그대로 “모든 TSMP가 항상 소비된다”고 해석하면 안 된다(`tailscale.com/net/tstun/wrap.go:1133-1157`, `tailscale.com/wgengine/filter/filter.go:551-552`).

### 6.3 총괄이 계약에서 정할 결정

| 결정 | 선택지 | 권고 |
| --- | --- | --- |
| 피어 수명 | netmap마다 선등록 / Go식 지연 생성 | M3 선등록. 삭제·만료 즉시 반영. M5에서 메모리 측정 후 재검토(§4.2) |
| 관문 응답 주체 | Go tsnet 리스너 + Swift 메모리 입력 / Swift 시험 응답 장치도 추가 | 양방향 관문은 시험 응답 장치 추가. 공개 TCP 스택은 M6(§4.7) |
| 조각·IPv6 확장 헤더 | Go 필터 동작 재현 / 미지원 패킷 명시 Drop | M3 재조립 없는 장치는 조각·확장 헤더 명시 Drop, 비조각 UDP/TCP 관문부터. 차이를 계약에 기록(§3.2) |
| 제어 패킷 | TSMP 소비만 / pong·거절 송신까지 | 소비는 M3, pong은 진단을 시험할 때, 거절·광고 송신은 후속(§3.3·6.2) |
| 잘못된 원시 CIDR 검사 위치 | control 해독 / 엔진 | FilterRule 문자열은 엔진에서 검사. Node 접두사는 현재 타입에서 원문 호스트 비트가 이미 지워지므로 총괄이 control 경계 변경 여부 결정(§8.1) |
| 서버 시각 표본 전달 | netmap 수신 시각으로 추정 / ControlTime과 실제 수신 시각을 별도 전달 | 후자 권고. 저장된 옛 ControlTime에서 매번 delta를 재계산하지 않음(§8.1) |
| disco 키 변경 복구 | 피어 제거 후 재등록 / WireGuard에 재핸드셰이크 예약 API 추가 | M3은 변경 시 제거·재등록을 명시적 단순화로 사용. M4에서 Go식 예약 API 검토(§8.1) |

## 7. 상호 운용 시험에서 확인할 것

아래는 **아직 실행하지 않은 시험 계획**이다. 괄호는 기대값의 소스 근거다.

1. **DERP 전용 관문:** 직접 UDP를 막고 로컬 DERP만 사용. Go tsnet UDP echo listener까지 데이터 왕복, TCP listener에 SYN을 보내 SYN-ACK 수신. IPv4·IPv6를 각각 시험하고 Swift 수신 장치도 붙이면 역방향을 반복한다(`docs/plan.md:193`, §4.3·4.7).
2. **ACL과 닫힌 포트:** 허용 TCP listener의 SYN-ACK, ACL 차단 포트의 무응답/Drop, ACL은 허용하지만 리스너 없는 Go 포트의 RST를 구분. TSMP `!`는 선택 진단이므로 필수 기대값으로 두지 않는다(`tailscale.com/net/tstun/wrap.go:1193-1236`, `tailscale.com/wgengine/netstack/netstack.go:1748-1753`, `tailscale.com/tsnet/tsnet.go:1289-1300`).
3. **필터 변환:** SrcIPs `*`·CIDR·단일 IP·범위·cap, 포트 양끝, 빈 IPProto·명시 프로토콜·범위 밖 번호, 잘못된 CIDR·SrcBits·DstBits. CapGrant만 있는 규칙은 UDP/TCP를 열지 않아야 한다(§4.4).
4. **UDP 응답 상태:** 허용 규칙이 없어도 Swift가 먼저 보낸 UDP의 정확한 역방향 응답은 통과. 포트·주소·프로토콜 중 하나가 다르면 실패. 일반 송신·스택 주입 양쪽을 시험하고, LRU 513번째 삽입·조회 순서·규칙 교체·shields-up 전환·jailed 별도 캐시를 확인한다(§4.5·4.6).
5. **TCP·ICMP 판정:** 허용되지 않은 SYN은 Drop, 같은 자기 목적지의 SYN-ACK·ACK·RST는 TCP 상태 없이 필터 통과. TCP 한 포트만 허용한 출발지의 ICMP echo도 IP-only 규칙으로 통과하며, echo reply/error는 캐시 없이 통과. 통과와 실제 ping reply 생성을 구분한다(§4.6·4.7).
6. **출발·목적 위조:** 정상 세션 피어가 AllowedIPs 밖 출발지를 보내면 ACL보다 먼저 거절. 자기 주소 밖 목적지는 넓은 ACL이 있어도 거절. 조각·TSMP 예외 또는 Swiftail의 명시 Drop 정책을 별도 확인한다(§3.2·4.6).
7. **피어 갱신:** 만료 경계의 `==`·`<`·`>`, nonexpiring, 시계 차 ±60초·그 이상, zero node key·후보 없음·빈 AllowedIPs·삭제·키 회전·복구. `RouteAll=false`에서 서브넷·/0을 출발지로 받지 않는지 확인한다(§4.1). 기존 키가 새 키로 잘못 재사용되지 않아야 한다(`tailscale.com/net/routemanager/routemanager.go:626-647`).
8. **shields-up·jailed:** 새 SYN/미등록 UDP는 버리고 먼저 보낸 UDP의 응답·non-SYN은 허용. 필터 없는 시작 상태에서는 정상 앱 패킷을 전달하지 않는다. Go의 빈 버퍼·비첫 조각 `pre` 예외는 따로 시험한다(§4.5·4.6).
9. **TSMP 선택 관문:** ping/pong을 구현했다면 8바이트 데이터 복사·PeerAPI 포트 0·짧은 입력을 시험. disco 광고가 UDP echo로 잘못 전달되지 않는지 확인한다(§3.3·6.2).
10. **M5 설정:** iOS 개별 /32·적격 ULA 피어 존재 시 /48·self 계열별 서비스 경로, OneCGNAT 임계값·동일 netmap 무변경·삭제 후 경로 제거·자기 주소 반사·서비스 IP 유출 방지를 확인한다(§4.8).

## 8. 확인하지 못한 것과 검증 한계

### 8.1 총괄에 넘길 구현 경계

- **Node 원문 접두사의 호스트 비트:** Go는 비정규 AllowedIPs를 제외하지만 Swift `IPPrefix`는 생성 때 이미 mask한다. 엔진이 `Netmap`만 받으면 원문이 비정규였는지 복원할 수 없다. 소유 범위 밖이므로 고치지 않았다. 반면 FilterRule의 IP 문자열은 남아 있어 엔진에서 검사 가능하다(`tailscale.com/net/routemanager/routemanager.go:665-672`, `Sources/SwiftailBase/IPPrefix.swift:12-28`, `Sources/SwiftailControl/Tailcfg/Node.swift:123-124`, `Sources/SwiftailControl/Tailcfg/FilterRule.swift:13-22`).
- **disco 키 변경 시 재핸드셰이크:** Go는 nonzero disco 키 변경에 다음 사용자 transport 송신 뒤 handshake를 예약한다. 즉시 피어 제거·키쌍 flush는 실제 호출의 동작이 아니다. 현 Swift WireGuard에는 이에 대응하는 공개 API가 없어 총괄이 재등록 또는 API 추가를 결정해야 한다(`tailscale.com/ipn/ipnlocal/node_backend.go:899-911`, `tailscale.com/wgengine/userspace.go:719-725`, `wireguard-go/device/device.go:765-782`, `Sources/SwiftailWireGuard/WireGuardDevice.swift:57-82`).
- **ControlTime의 관측 시각:** Go는 ControlTime 사건 수신 때 로컬 시각과 delta를 계산하지만, 현재 Swift `MapSession`은 마지막 ControlTime만 저장하고 그것만 달라진 netmap은 내보내지 않는다. `ControlClient.Event`에도 별도 시각 사건이 없다. 따라서 엔진이 뒤늦게 받은 netmap의 저장 시각을 “지금 서버 시각”으로 간주하면 잘못 보정할 수 있다. 실제 수신 시각과 함께 전달할 경계를 총괄이 정해야 한다(`tailscale.com/ipn/ipnlocal/expiry.go:56-73`, `Sources/SwiftailControl/Netmap/MapSession.swift:43-49`, `:82-88`, `Sources/SwiftailControl/Client/ControlClient.swift:40-49`).

### 8.2 미검증 범위

- **실행 증거:** 이 검증은 고정 버전 소스 대조와 출처 확인이다. Swift 빌드·단위 시험·Go tsnet 상호 운용·iOS 실기기 시험은 실행하지 않았다. §7은 통과 보고가 아니다.
- **제어 서버 정책:** 서버가 서브넷·exit node 승인을 어떻게 AllowedIPs로 만드는지는 이 클라이언트 소스만으로 검증하지 않았다. 클라이언트가 받은 AllowedIPs를 줄이는 조건만 확인했다(`tailscale.com/tailcfg/tailcfg.go:397-402`, `tailscale.com/net/routemanager/routemanager.go:827-840`).
- **OS 앱 어댑터:** `NEPacketTunnelNetworkSettings` 적용·DNS 설정 정책·인터페이스 전환 복구는 이 노트에서 검증하지 않았다. Go callback 경계만 확인했다(`tailscale.com/wgengine/router/callback.go:12-31`, `:45-67`; M5 관문 `docs/plan.md:195`).
- **ICMPv4 ParamProblem:** Go 상수 `0x12`는 확인했으나 표준 값과의 차이·정책은 별도 검토가 필요하다(`tailscale.com/net/packet/icmp4.go:26`).
- **전체 로그인·정지 상태 기계와 부가 기능:** 자기 키 만료로 데이터면을 내리는 전체 경로, PeerAPI/SSH/Serve/앱 커넥터·4via6 전체는 검증 범위 밖이다. M3에서는 지원 범위를 좁힌 계약이 필요하다(관련 진입점: `tailscale.com/ipn/ipnlocal/local.go:6967-6980`, `tailscale.com/wgengine/netstack/netstack.go:1287-1350`).

### 8.3 사실 정정 집계

10건은 같은 오류의 반복 서술을 한 건으로 센 것이다. 출처 표기 보완·섹션 재배치·새 구현 설명은 여기에 포함하지 않는다.

| # | 고친 주장 | 확인 출처 |
| --- | --- | --- |
| 1 | netmap 동기화가 없는 WireGuard 피어도 만든다 → 기존 피어만 갱신 | `tailscale.com/wgengine/userspace.go:698-717` |
| 2 | `Parsed.Decode`가 선언 IP 길이 뒤 바이트를 모두 무시한다 → 전송 파싱·Buffer에는 남을 수 있음 | `tailscale.com/net/packet/packet.go:161-162`, `:461-478` |
| 3 | IPv6의 나머지 확장 헤더는 모두 Unknown → 실제 switch는 일부 번호 유지 | `tailscale.com/net/packet/packet.go:278-365` |
| 4 | `KeyExpiry`가 현재보다 이전일 때 만료 → 같은 시각도 만료 | `tailscale.com/ipn/ipnlocal/expiry.go:104-109` |
| 5 | 오래된 ControlTime 필드이면 만료 판정 생략 → 보정된 현재 시각을 epoch와 비교 | `tailscale.com/ipn/ipnlocal/expiry.go:92-98` |
| 6 | 시계 보정 문턱이 1분 이상 → 정확히 1분은 보정 안 함 | `tailscale.com/ipn/ipnlocal/expiry.go:65-73` |
| 7 | 규칙 변환은 언제나 첫 오류만 반환 → 목적지 capability 오류가 덮어쓸 수 있음 | `tailscale.com/wgengine/filter/tailcfg.go:80-86` |
| 8 | handshake 포기 때 540초 정리 타이머를 항상 다시 건다 → 타이머가 없을 때만 | `wireguard-go/device/timers.go:92-97` |
| 9 | TSMP 거절 송신을 단순 TCP SYN 검사로 설명 → ACK와 무관한 SYN 비트와 disable 플래그 조건 | `tailscale.com/net/tstun/wrap.go:1216-1234` |
| 10 | handshake를 최대 90초 시도로 설명 → 실제 포기는 횟수와 5초+지터 타이머에 의존 | `wireguard-go/device/constants.go:18-21`, `wireguard-go/device/timers.go:80-106`, `:188-192` |
