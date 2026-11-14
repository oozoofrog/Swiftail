# DNS·상태 저장·노드 표면 노트

## 1. 머리말

| 항목 | 내용 |
| --- | --- |
| 기준 버전 | `tailscale.com` v1.104.6 (CapabilityVersion 148). DNS 메시지 파서는 `golang.org/x/net` v0.60.0(`tailscale.com/go.mod:143`), gVisor 상수는 go.mod가 고정한 `gvisor.dev/gvisor@v0.0.0-20260915211658-a6f909f08a72` |
| 쓰는 마일스톤 | M5(iOS 패킷 터널), M6(프로세스 내 리스너·다이얼), M7(WhoIs, ts.net 인증서, Go 상태 파일 이관) |
| 작성 모델 | Claude Sonnet 5.5 (`claude-sonnet-5-5`) |
| 검증 | Claude Opus 5.5, 2026-11-15. 사실 정정 16건(8.3), 출처 줄 정정 12건, M5 절차(4.1.4, 4.2, 4.3)와 결정 표(6.4) 보충 |

읽는 법: 절 제목의 `[M5]`·`[M6]`·`[M7]`은 그 절이 필요한 마일스톤이다. M5 구현자는 3.1, 4.1~4.6, 6.1, 6.4만 읽으면 된다(3.2는 M7 이관용). TUN 주소·경로 산출은 [netmap-engine.md](netmap-engine.md) 4.8을, 링크 변경 뒤 magicsock 재결속의 세부는 [disco-magicsock.md](disco-magicsock.md) 4.11을 따르고 여기서 되풀이하지 않는다. 출처는 모듈 루트 기준 `경로:줄`이다. 첫 사용처(RemoteDebug)의 요구 사항은 그 저장소 HEAD의 경로로 적는다. 예시 값은 가짜(`rd-mac-1a2b3c4d.tail0001.ts.net`, `100.64.0.1`)다.

## 2. 범위

다루는 것
- [M5] netmap `DNSConfig` → OS DNS 설정(`OSConfig`)과 내장 리졸버 설정의 산출, MagicDNS 응답 규칙과 DNS 바이트 형식, 서비스 IP(`100.100.100.100`, `fd7a:115c:a1e0::53`) 패킷의 가로채기, 상태 저장 형식과 재시작, backend state 기계, 링크 변경(Wi-Fi ↔ 셀룰러) 처리와 소켓 결속.
- [M6] tsnet `Listen`·`Dial`과 netstack 설정.
- [M7] `WhoIs`, ts.net 인증서(ACME DNS-01과 제어의 `set-dns`), Go 상태 파일 이관에 필요한 키와 형식.

다루지 않는 것
- WireGuard, DERP, disco, 제어 프로토콜(다른 노트). 제어 쪽은 `/machine/set-dns`의 형태만 적는다.
- Linux·Windows의 OS DNS 구성기, 출구 노드 DNS 프록시(DoH·PeerAPI DNS), Taildrive, SSH, Serve/Funnel, 앱 커넥터, tailnet lock.
- iOS 앱 쪽 코드(`OSConfig` → `NEDNSSettings` 변환, `GetBaseConfig` 구현). Tailscale의 iOS 앱 코드는 기준 소스에 없다(8장).

## 3. 와이어 형식과 저장 형식

### 3.1 [M5] DNS 메시지 — 응답기가 다루는 부분

Go는 `golang.org/x/net/dns/dnsmessage`로 머리와 **첫 질문 하나만** 읽는다(`tailscale.com/net/dns/resolver/tsdns.go:1020-1033`). 질문이 둘 이상이면 나머지는 읽지 않고, 응답에는 첫 질문만 싣는다.

머리(12바이트, 빅엔디언. 배치는 RFC 1035 4.1.1, AD·CD 비트는 RFC 4035)

| 오프셋 | 길이 | 필드 | 응답에서의 값(Go 로컬 응답) |
| --- | --- | --- | --- |
| 0 | 2 | ID | 질의 값 |
| 2 | 2 | QR·Opcode(4)·AA·TC·RD·RA·Z·AD·CD·RCODE(4) | 질의 머리를 그대로 복사한 뒤 QR=1, AA=1, RD=1이면 RA=1로 덮는다. 그 밖의 비트(Opcode, TC, AD, CD, RD=0일 때의 RA)는 질의 값이 남는다. Opcode는 검사하지 않는다(`tsdns.go:1009-1011`, `:1203-1208`) |
| 4 | 2 | QDCOUNT | 1(질문을 싣는 경우) 또는 0 |
| 6 | 2 | ANCOUNT | 0 또는 1 |
| 8 | 2 | NSCOUNT | 부정 응답에 SOA를 붙이면 1 |
| 10 | 2 | ARCOUNT | 0. 질의의 EDNS OPT를 응답에 싣지 않는다(`tsdns.go:1203-1287`) |

질문 구역은 RCODE가 NOERROR이거나 질문의 TYPE이 0이 아닐 때 싣는다(`tsdns.go:1222-1232`). 즉 질문을 읽지 못한 FORMERR만 질문 없이 나간다.

이름
- 읽기: 길이 바이트(0x00~0x3F) + 레이블, 0x00으로 끝. 상위 두 비트가 11이면 14비트 오프셋 포인터이고, 한 이름에서 포인터는 10번까지 따라간다. 01·10은 오류. 레이블 안에 `.` 바이트가 있으면 오류. 이어 붙인 이름(끝 점 포함)이 254바이트 이상이면 오류(`golang.org/x/net@v0.60.0/dns/dnsmessage/message.go:2039-2111`). 오류는 FORMERR로 이어진다.
- 비교: ASCII `A`-`Z`만 소문자로 바꾸고(`tsdns.go:1320-1331`), 끝 점이 있는 FQDN으로 정규화한다. 바이트 0x20 이하나 0x7F가 있거나, 빈 레이블·64바이트 이상 레이블이 있거나, 끝 점을 더해 254바이트를 넘으면 유효한 FQDN이 아니다(`tailscale.com/util/dnsname/dnsname.go:29-84`). 비교는 소문자 이름으로 하지만 응답의 질문과 답변 이름은 **질의에 온 대소문자 그대로** 쓴다(`tsdns.go:1009-1011`, `:1037-1094`).
- 쓰기: Go 로컬 응답은 이름 압축을 쓰지 않는다. 압축은 `resp.IPs`가 둘 이상일 때만 켜는데 로컬 경로는 `resp.IP` 하나만 채운다(`tsdns.go:1213-1218`, `:1484`). Swiftail도 압축 없이 쓰면 Go와 바이트가 같다.

답변 레코드(모두 CLASS IN)

| 타입 | 소유자 이름 | TTL | RDATA | 출처 |
| --- | --- | --- | --- | --- |
| A | 질문 이름 | 5초 | IPv4 4바이트 | `tsdns.go:58`, `:1037-1049` |
| AAAA | 질문 이름 | 5초 | IPv6 16바이트 | `tsdns.go:1053-1065` |
| PTR | 질문 이름 | 5초 | 노드 FQDN(끝 점 포함, 압축 없음) | `tsdns.go:1079-1094` |
| SOA(권한 구역) | 권한 영역 이름 | 10초 | MNAME·RNAME = 영역 이름, SERIAL = 현재 유닉스 초, REFRESH·RETRY·EXPIRE·MINIMUM = 10 | `tsdns.go:68`, `:1177-1199` |

- A·AAAA·ANY 답은 최대 하나다. 노드가 주소를 여럿 가져도 질의 타입에 맞는 첫 주소만 나간다(`tsdns.go:791-822`, `:1484`).
- SOA는 부정 응답에만 붙는다: NXDOMAIN, 그리고 A·AAAA·ANY 질의에서 이름은 있으나 그 타입 주소가 없는 NOERROR. 권한 영역(4.1.3의 `LocalDomains` 가운데 이름을 포함하는 것)을 찾지 못하면 붙이지 않는다(`tsdns.go:1405-1414`, `:1427-1429`, `:1486-1496`).
- 응답 크기: 압축이 없으므로 이론상 최대는 머리 12 + 질문 259 + SOA(영역 이름 ≤255를 세 번 + 고정 30) ≈ 1,066바이트다. 실제 tailnet 영역(`tail0001.ts.net.`, 역방향 영역)에서는 질문 이름이 최대여도 약 350바이트라 512바이트를 넘지 않는다(계산. 4.2.4).

RCODE 규칙(로컬 판단, 위에서부터)

| 상황 | 결과 | 출처 |
| --- | --- | --- |
| 머리를 읽지 못함, 질의가 QR=1, 질문이 없음 | FORMERR, 질문 없음 | `tsdns.go:1028-1032`, `:1447-1459` |
| 질문 이름이 유효한 FQDN이 아님 | FORMERR, 질문 포함 | `tsdns.go:1461-1468` |
| PTR 질의 | 역방향 규칙(4.2.2 5) | `tsdns.go:1473-1475` |
| 이름이 `.onion`으로 끝남 | NXDOMAIN(SOA는 영역 안일 때만) | `tsdns.go:727-731` |
| `magicdns.localhost-tailscale-daemon.`의 A / AAAA | `100.100.100.100` / `fd7a:115c:a1e0::53` | `tsdns.go:45`, `:736-743` |
| 이름을 찾지 못함, `LocalDomains` 안 | NXDOMAIN + SOA | `tsdns.go:772-778` |
| 이름을 찾지 못함, `LocalDomains` 밖 | 로컬 답 없음 → 전달 단계(4.2.3) | `tsdns.go:779-782`, `:1477-1480` |
| 찾음, A: IPv4 있음 / 없음 | A 1개 / NOERROR 빈 답 + SOA | `tsdns.go:792-800` |
| 찾음, AAAA: IPv6 있음 / 없음 | AAAA 1개 / NOERROR 빈 답 + SOA | `tsdns.go:801-809` |
| 찾음, ANY(255) | 주소 목록의 첫 주소(A 또는 AAAA) 1개, 주소가 없으면 NOERROR 빈 답 + SOA | `tsdns.go:810-820` |
| 찾음, NS·SOA·AXFR·HINFO | NOTIMP(SOA 없음) | `tsdns.go:824-826` |
| 찾음, 그 밖의 타입 | NOERROR 빈 답(SOA 없음) | `tsdns.go:834-837` |

TCP 프레임(Go가 TCP 53을 받을 때): 2바이트 빅엔디언 길이 + 메시지. 요청 길이가 4096을 넘으면 연결을 닫는다. 한 연결에서 여러 질의를 받고 응답 순서는 보장하지 않는다. 유휴 45초(`tailscale.com/net/dns/manager.go:678-688`, `:743-815`).

### 3.2 [M5·M7] Go 상태 파일(FileStore) 형식

M5는 Swiftail 자신의 저장(`Sources/SwiftailControl/Client/NodeIdentityStore.swift`)을 쓰므로 이 형식이 필요 없다. M7의 이관 결정과 상호 운용 시험에 쓴다.

- 파일은 JSON 객체 하나다. 타입은 `map[ipn.StateKey][]byte`이므로 키는 문자열, 값은 표준 base64 문자열이다(`tailscale.com/ipn/store/stores.go:145-150`, Go `encoding/json`의 `[]byte` 규칙). 쓸 때마다 두 칸 들여쓰기 `MarshalIndent`로 통째로 다시 쓰고, 같은 디렉터리의 임시 파일 → 이름 바꾸기로 0600 파일을 교체한다. 값이 같으면 쓰지 않고, `nil`을 쓰면 키를 지운다(`stores.go:211-227`, `tailscale.com/atomicfile/atomicfile.go:21-51`). 디렉터리는 0700(`tailscale.com/paths/paths.go:147-152`).
- 파일이 없거나 비어 있으면 `{}`를 써 보고 빈 저장소로 시작한다(`stores.go:158-190`).
- tsnet은 `Dir/tailscaled.state`를 `store.New`로 연다(`tailscale.com/tsnet/tsnet.go:965-972`). 첫 사용처의 iOS 터널도 같은 이름의 FileStore를 App Group 컨테이너 안에 둔다(RemoteDebug `core/internal/tunnel/tunnel.go:134-139`).

키(단일 사용자, Windows 아님)

| 키 | 값(base64를 푼 바이트) | 출처 |
| --- | --- | --- |
| `_machinekey` | `privkey:` + 소문자 hex 64자(머신 개인 키 32바이트) | `tailscale.com/ipn/store.go:24`, `tailscale.com/types/key/machine.go:24`, `:76-78` |
| `_current-profile` | 현재 프로필의 키 문자열(예: `profile-3fa2`) | `ipn/store.go:55-57`, `tailscale.com/ipn/ipnlocal/profiles.go:657-667` |
| `_profiles` | JSON 객체 `{프로필 ID: LoginProfile}`. `store.go`의 주석은 배열이라 하지만 실제 타입은 맵이다 | `ipn/store.go:51-53`, `profiles.go:819-826`, `:912-926` |
| `profile-<id>` | 그 프로필의 `Prefs` JSON(탭 들여쓰기). `<id>`는 난수 2바이트의 소문자 hex 4자 | `profiles.go:494-504`, `:563-572`, `tailscale.com/ipn/prefs.go:650-656` |
| `_daemon` | 프로필 도입 전의 단일 prefs. 프로필이 하나도 없을 때만 읽어 이주하고 지우지 않는다. iOS·샌드박스 macOS는 `ipn-go-bridge`, Android는 `ipn-android`를 읽는다 | `ipn/store.go:26-40`, `tailscale.com/ipn/ipnlocal/profiles_notwindows.go:16-30`, `profiles.go:951-958` |

그 밖에 `server-mode-start-key`(Windows), `_taildrop-received`가 있다(`ipn/store.go:49`, `:62`). 인증서는 이 파일에 들어가지 않는다(4.9 1).

`LoginProfile` JSON: `ID`, `Name`, `NetworkProfile`, `Key`, `UserProfile`, `NodeID`, `LocalUserID`, `ControlURL`, `Created`(0이면 생략)(`ipn/prefs.go:1077-1124`).

`Prefs` JSON에서 `Persist`는 키 이름 `Config`로 들어간다(`ipn/prefs.go:319`). `Persist` 필드(`tailscale.com/types/persist/persist.go:20-38`):

| 필드 | 형식 |
| --- | --- |
| `PrivateNodeKey` | `privkey:` + hex 64자(`tailscale.com/types/key/node.go:29`, `:115-123`) |
| `OldPrivateNodeKey` | 같은 형식. 키 교체 요청에 쓴다. 없으면 0바이트 32개의 텍스트 |
| `UserProfile` | `tailcfg.UserProfile` |
| `NetworkLockKey` | `nlpriv:` + hex(`tailscale.com/types/key/nl.go:18`) |
| `NodeID` | `tailcfg.StableNodeID` 문자열 |
| `AttestationKey` | 하드웨어 증명 키. 0이면 생략 |
| `DisallowedTKAStateIDs` | 문자열 배열. 비면 생략 |

## 4. 절차와 상태 기계

### 4.1 [M5] netmap `DNSConfig` → OS DNS 설정

#### 4.1.1 `DNSConfig` 필드와 M5에서의 쓰임

필드 정의는 `tailscale.com/tailcfg/tailcfg.go:1788-1872`. Swiftail 모델은 `Sources/SwiftailControl/Tailcfg/DNSConfig.swift`(`Nameservers`, `ExitNodeFilteredSet`이 없다).

| 필드 | Go가 쓰는 곳 | M5 |
| --- | --- | --- |
| `Proxied` | 참이면 MagicDNS 루트 영역(4.1.2 6)을 내장 리졸버가 권한을 갖는 라우트로 넣는다. 주석대로 "MagicDNS 켜짐"의 뜻이다(`tailscale.com/ipn/ipnlocal/node_backend.go:1539-1551`). 거짓이면 점 없는 짧은 이름을 찾지 않는다(`node_backend.go:1276-1278`) | 필요 |
| `Routes` | 빈 목록 = 내장 리졸버가 답하는 영역(`LocalDomains`, match 도메인). 리졸버가 있는 목록 = 그 리졸버로 전달하는 분할 DNS(`tailscale.com/net/dns/manager.go:341-353`) | 빈 목록 키는 필요. 리졸버가 있는 라우트는 결정 D2 |
| `ExtraRecords` | `Type`이 `""`·`A`·`AAAA`이고 값이 IP인 것만 내장 리졸버의 호스트 표에 넣는다. 그 이름을 덮는 라우트가 없으면 이름 자체를 빈 라우트로 더한다(`node_backend.go:1497-1521`, `:1592-1606`) | 필요 |
| `Resolvers` | 비어 있지 않으면 기본 리졸버. 이 경우 iOS에서도 quad-100이 모든 이름의 1차 리졸버가 된다(4.1.3 표 3행) | 결정 D2 |
| `Domains` | 검색 도메인. Apple 확장은 1차 리졸버 모드에서만 설치한다는 주석이 있다(`manager.go:361-366`) | 결정 D3 |
| `FallbackResolvers` | 출구 노드를 쓰는데 기본 리졸버가 없을 때만 기본 리졸버로 쓴다(`node_backend.go:1657-1677`) | 무시(출구 노드 미지원) |
| `ExitNodeFilteredSet` | 이 노드가 출구 노드 DNS 프록시일 때만 쓴다(`tailcfg.go:1835-1848`) | 무시 |
| `Nameservers` | 폐기(MapRequest.Version 9 이상 14 미만 전용). 클라이언트 코드는 읽지 않는다(`tailcfg.go:1817-1821`) | 무시 |
| `CertDomains` | DNS 응답에 쓰지 않는다. 인증서 발급 대상(4.9) | M7 |

#### 4.1.2 `dnsConfigForNetmap` — netmap → `dns.Config`

`tailscale.com/ipn/ipnlocal/node_backend.go:1435-1680`. 출구 노드·앱 커넥터 분기는 생략한다.

1. netmap이 없으면 설정 없음. 자기 노드 키가 만료됐으면 빈 설정(DNS 없음)(`:1436-1453`).
2. 자기 주소가 IPv6뿐이면 `OnlyIPv6`. 자기 노드의 `AllCaps`에 `magicdns-aaaa`(`nodecap.MagicDNSPeerAAAA`)가 있으면 피어 AAAA를 허용한다(`:1461-1470`, `tailscale.com/tailcfg/nodecap/nodecap.go:306`).
3. 노드 이름 → 주소는 설정에 넣지 않는다(Windows만 예외). 리졸버가 질의 때 가져간다(4.2.1)(`:1472-1496`).
4. `ExtraRecords` → `Hosts`(같은 이름의 주소는 이어 붙임)(`:1497-1521`).
5. prefs `CorpDNS`가 거짓이면 여기서 끝. 라우트가 없으므로 OS 설정도 없다(`:1523-1525`, 4.1.3 1행).
6. `Domains` → 검색 도메인(FQDN으로 못 바꾸면 버림)(`:1527-1538`). `Proxied`면 다음을 빈 라우트로 넣는다: MagicDNS 접미사(자기 노드 `Name`에서 앞뒤 점을 떼고 첫 레이블을 뗀 나머지), `0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.`, `64.100.in-addr.arpa.`부터 `127.100.in-addr.arpa.`까지 64개(`:1539-1542`, `tailscale.com/ipn/ipnlocal/local.go:6665-6687`, `tailscale.com/types/netmap/netmap.go:256-270`). 거짓이면 `MagicDNSHostsUnrouted = SelfNode.Valid()`(`:1543-1551`).
7. `Resolvers` → 기본 리졸버(`:1640-1641`). `Routes` → 각 접미사를 FQDN으로 바꿔 복제(빈 목록도 항목을 만든다)(`:1557-1568`, `:1649`). 라우트로 덮이지 않는 `ExtraRecords` 이름을 빈 라우트로 더한다(`:1592-1606`, `:1651`).

#### 4.1.3 `compileConfig` — `dns.Config` → (리졸버 설정, `OSConfig`), `goos == "ios"`

`tailscale.com/net/dns/manager.go:334-526`. `OSConfig`는 `Nameservers`, `SearchDomains`, `MatchDomains`(비면 1차 리졸버로 설치), `Hosts`(Windows), `Resolvers`(입력 전용)다(`tailscale.com/net/dns/osconfig.go:55-80`).

공통(`:338-366`)
- 빈 목록 라우트의 키는 리졸버의 `LocalDomains`(정렬)가 되고, 리졸버가 있는 라우트만 전달 라우트가 된다.
- `ocfg.SearchDomains = 검색 도메인`(분할 DNS 접미사는 더하지 않는다).
- `serviceIPs`: `OnlyIPv6`면 `[fd7a:115c:a1e0::53]`. 아니면 `[100.100.100.100, fd7a:115c:a1e0::53]`. 단 제어가 `force-register-magicdns-ipv4-only` 능력을 주면 `[100.100.100.100]`(`tailscale.com/net/dns/config.go:79-94`, `tailscale.com/control/controlknobs/controlknobs.go:248-250`, `nodecap.go:362`).
- `matchDomains`: 모든 라우트 키를 끝 점 포함 문자열 순으로 정렬한 목록(`config.go:232-242`).

iOS 절차(위에서부터 처음 맞는 것)

| # | 조건 | 결과 | 출처 |
| --- | --- | --- | --- |
| 1 | 기본 리졸버도 라우트도 없음 | 검색 도메인만. 네임서버 없음 | `manager.go:373-377`, `config.go:112-120` |
| 2 | 기본 리졸버가 모두 `IP:53`(DoH 전용 IP 아님)이고 라우트가 없고 라우트로 덮이지 않은 호스트 없음 | `Nameservers` = 그 IP들(1차 리졸버). quad-100 없음 | `manager.go:378-390`, `config.go:123-151` |
| 3 | 기본 리졸버가 있음 | `Nameservers = serviceIPs`, `MatchDomains` 없음(1차), 전달 라우트 + `"." = 기본 리졸버` | `manager.go:391-397` |
| 4 | (분할 DNS) 범위 지정 가능(`scopeApple`) | `Nameservers = serviceIPs`, `MatchDomains = matchDomains`. 이어 `GetBaseConfig`로 OS 기본 리졸버를 읽어 `"."` 라우트로 둔다. 기본 리졸버가 비어도 오류가 아니다(quad-100에 직접 온 tailnet 밖 질의만 답을 못 한다) | `manager.go:434`, `:446-451`, `:463`, `:491-515` |
| 5 | (분할 DNS) 범위 지정 불가 | `Nameservers = serviceIPs`, `MatchDomains` 없음(1차). OS 기본 리졸버를 `"."`로 쓰고 그 검색 도메인을 뒤에 붙인다. 기본 리졸버가 비면 `errEmptyBaseConfig`로 실패하고 OS 설정을 바꾸지 않는다(Apple은 재시도하지 않고 앱이 `RecompileDNSConfig`를 다시 부르기를 기다린다) | `manager.go:463-525`, `:207-214` |

- `scopeApple` = iOS이고 제어가 `disable-split-dns-when-no-custom-resolvers` 능력을 주지 않았음 **그리고** 리졸버가 있는 라우트가 없음(`ts.net` 라우트는 예외로 무시) **그리고** 라우트로 덮이지 않은 호스트가 없음(MagicDNS가 꺼져 `MagicDNSHostsUnrouted`이면 거짓) **그리고** `Hosts`의 모든 주소의 역방향 이름이 라우트로 덮임(`manager.go:446-449`, `:557-559`, `tailscale.com/net/dns/resolver/tsdns.go:209-226`, `config.go:137-189`, `nodecap.go:227`).
- iOS는 분할 DNS를 OS에 직접 맡기는 분기(`:421-429`)와 기본 설정 없이 끝나는 분기(`:453-455`)를 타지 않는다. `GetBaseConfig`가 `ErrGetBaseConfigNotSupported`를 돌려주고 범위 지정이 가능하면 `"."` 없이 4행으로 끝난다(`:473-484`).
- 표 4·5행은 `OSConfigurator.SupportsSplitDNS()`가 참일 때다. iOS의 `OSConfigurator`는 앱 쪽 코드라 기준 소스에 없다(`tailscale.com/wgengine/userspace.go:330-337`). 첫 사용처는 참을 돌려주고, `GetBaseConfig`로 "상위 리졸버 없음"을 뜻하는 가짜 리졸버를 돌려준다(RemoteDebug `core/internal/tunnel/settings.go:227-251`).
- 결론: MagicDNS가 켜져 있고 tailnet이 전역 네임서버·사용자 지정 분할 DNS를 쓰지 않으면, iOS의 Go는 `dnsServers = serviceIPs`, `matchDomains = [MagicDNS 접미사, ip6.arpa 영역, in-addr.arpa 64개, ExtraRecords 이름…]`을 내놓는다(4행). 그 밖에는 quad-100이 모든 이름의 1차 리졸버가 되고 상위 전달이 필요하다(3·5행).

#### 4.1.4 Swiftail M5 산출 절차(권고)

Go의 4행만 구현하고 3·5행은 결정 D2의 권고대로 범위를 좁힌다. 첫 사용처가 Go 위에서 하는 일과 같다: 1차 리졸버 설정이 나오면 "quad-100이 스스로 답하는 접미사"로 좁히고, 접미사가 없으면 DNS를 설정하지 않는다(RemoteDebug `core/internal/tunnel/settings.go:179-215`, `docs/tunnel.md:111-114`).

1. netmap이 없거나 자기 키가 만료됐으면 DNS 없음(`dnsServers = []`, `dnsMatchDomains = []`). 4.1.2 1.
2. `localZones` = (`Proxied`면 4.1.2 6의 66개 영역) ∪ (`Routes`에서 리졸버 목록이 빈 키) ∪ (어느 영역에도 덮이지 않는 유효한 `ExtraRecords` 이름). 모두 소문자 FQDN.
3. `localZones`가 비면 DNS 없음.
4. `dnsServers`: 자기 주소에 IPv4가 있으면 `100.100.100.100`, IPv6가 있으면 `fd7a:115c:a1e0::53`(IPv4 먼저). Go의 `serviceIPs`는 IPv4 전용 노드에도 IPv6 서비스 IP를 넣지만 그 노드에는 `fd7a:115c:a1e0::53/128` 경로가 없으므로([netmap-engine.md](netmap-engine.md) 4.8 2) 첫 사용처처럼 뺀다(RemoteDebug `settings.go:58-77`). `force-register-magicdns-ipv4-only`이면 IPv4만.
5. `dnsMatchDomains`: `localZones`를 끝 점 포함 문자열 순으로 정렬하고 끝 점을 뗀다(`config.go:232-242`, RemoteDebug `settings.go:78-80`).
6. 같은 리졸버 설정을 4.2의 응답기에 준다: `LocalDomains = localZones`, 호스트 표 = `ExtraRecords`, 노드 색인 = netmap.
7. `TunnelNetworkSettings`는 이전 값과 다를 때만 `NodeEvent.networkSettings`로 낸다. DNS만 바뀌어도 낸다(RemoteDebug `docs/tunnel.md:170-174`). 주소·경로·MTU는 [netmap-engine.md](netmap-engine.md) 4.8.

### 4.2 [M5] MagicDNS 응답기

#### 4.2.1 이름 색인

v1.104.6은 노드 레코드를 설정으로 밀어 넣지 않고 질의 때 netmap 색인에서 가져간다(`tsdns.go:253-300`, 설치 `tailscale.com/ipn/ipnlocal/local.go:647-651`).

- 이름 색인(`nodeByName`): 자기 노드와 모든 피어(이 순서로 넣고 뒤가 덮는다)의 `Name`을 끝 점을 떼고 소문자로 만든 키, 그리고 MagicDNS 접미사로 끝나면 그 접미사를 뗀 짧은 이름 키. `Name`이 빈 노드는 넣지 않는다(`node_backend.go:778-787`, `:805-821`).
- 정방향(`LookupHost`): 질의 이름을 끝 점을 떼고 소문자로 만든 뒤 `Proxied`가 거짓이고 점이 없으면 모른다. 색인에 없으면 모른다. 노드에 주소가 **하나도 없으면 모른다**(`node_backend.go:1198-1220`, `:1266-1282`).
- 답할 주소(`magicDNSAddrs`, `node_backend.go:1299-1325`): 자기가 IPv6 전용이면 대상의 IPv6 주소만. 아니면 대상의 주소 전부이되, 대상에 IPv4가 있고 `magicdns-aaaa` 능력이 없으면 IPv6를 뺀다. 결과는 대상 `Addresses` 순서다. 예: IPv4·IPv6를 모두 가진 피어의 AAAA 질의는 기본으로 NOERROR 빈 답 + SOA다.
- 역방향(`LookupPTR`): 노드 자신의 주소(서브넷 라우트 제외) → 노드 `Name`의 FQDN(`node_backend.go:119-121`, `:1214-1233`).
- `ExtraRecords`: 리졸버의 호스트 표가 노드 색인보다 먼저 조회되고, 역방향 표도 이 호스트 표에서 만든다(`tsdns.go:347-372`, `:756-759`, `:943-946`).
- 서브도메인: 호스트 표·색인에 없으면 부모 이름을 하나씩 올라가며, 부모가 `dns-subdomain-resolve` 능력을 가진 노드면 그 노드의 주소로 답한다(`tsdns.go:760-771`, `node_backend.go:1246-1264`). M5에서는 생략할 수 있다(6.1).

#### 4.2.2 질의 처리 절차

`Resolver.Query`(`tsdns.go:408-439`) → `respond`(`tsdns.go:1437-1499`).

1. 머리와 첫 질문을 읽는다. 실패하면 FORMERR(3.1 RCODE 표).
2. 질문 이름을 소문자 FQDN으로 바꾼다. 실패하면 FORMERR(질문 포함).
3. PTR이면 5로. 아니면 `resolveLocal`(`tsdns.go:725-839`): `.onion` → 상징 이름 → 4via6 이름 → 호스트 표 → 노드 색인 → 서브도메인 → 영역 판정 → 타입별 결과. 결과가 "모름 + 영역 밖"이면 전달 단계(4.2.3).
4. 4via6 이름(`<점 대신 하이픈을 쓴 IPv4>-via-<사이트 ID>`, 뒤가 없거나 `ts.net`·`tailscale.net` 이하): A는 이름만 있는 NOERROR, AAAA·ANY는 Via 범위의 IPv6(`tsdns.go:850-900`). M5에서 생략 가능.
5. 역방향(`tsdns.go:903-958`, `:1416-1433`):
   - 첫 레이블이 `b`·`db`·`r`·`dr`·`lb`이고 다음이 `_dns-sd._udp.`인 이름(Bonjour)은 로컬에서 답하지 않고 전달 단계로 보낸다. 전달 단계는 이를 상위로 보내지 않고 NXDOMAIN(질문 포함, RA = RD, AA 없음)으로 답한다(`tsdns.go:1304-1316`, `tailscale.com/net/dns/resolver/forwarder.go:1296-1306`, `:1510-1528`).
   - `*.in-addr.arpa.`는 앞부분을 점 넷 IPv4로 읽어 뒤집는다. `*.ip6.arpa.`는 앞부분이 정확히 63바이트(니블 32개, 점 31개)여야 한다. 둘 다 아니거나 파싱에 실패하면 전달 단계로(`tsdns.go:1343-1397`).
   - 주소가 `fd7a:115c:a1e0:ab12:4843:cd96:6200::/104` 안이면 `100.x.y.z`(마지막 3바이트)로 먼저 찾는다(`tailscale.com/net/tsaddr/tsaddr.go:104-110`, `:151-157`).
   - 서비스 IP 두 개는 `magicdns.localhost-tailscale-daemon.`. 그 밖에는 호스트 표의 역방향 → 노드 색인. 못 찾으면 질의 이름이 `LocalDomains` 안이면 NXDOMAIN + SOA, 밖이면 전달 단계.
6. 응답을 만든 뒤 UDP이면 크기 검사(4.2.4).

#### 4.2.3 모르는 이름과 tailnet 밖의 이름

- Go: 로컬 답이 없으면 전달기로 넘긴다(질의 전체 제한 10초). 라우트를 레이블 수가 많은 순으로 보고 이름을 포함하는 첫 라우트의 리졸버로 보낸다. `"."`은 모든 이름에 맞는다. 맞는 라우트가 없거나 리졸버가 비면 SERVFAIL(질문 포함, AA=1, RA는 질의 값 그대로)로 답한다(`tsdns.go:403-431`, `forwarder.go:491-494`, `:1180-1200`, `:1316-1330`, `:1534-1551`). 전송 방식(UDP 뒤 2초 후 TCP 경쟁, DoH, 응답 집계, 지연)은 `forwarder.go:96-112`, `:383-443`, `:683-810`, `:1358-1459`.
- M5에서 OS가 quad-100에 보내는 이름은 match 도메인 안의 이름뿐이다(4.1.4. `matchDomains`의 OS 쪽 의미는 Apple 문서 `NEDNSSettings.matchDomains` 항목에 근거하며 이 소스 밖이다. 8장). 그 안의 이름은 모두 `LocalDomains` 안이므로 로컬에서 NOERROR·NXDOMAIN으로 끝나고 전달이 일어나지 않는다. 전달이 필요한 것은 사용자가 `dig @100.100.100.100 example.com`처럼 quad-100에 직접 묻는 경우뿐이다.
- 권고: M5는 전달을 구현하지 않고 Go의 "라우트 없음"과 같은 SERVFAIL로 답한다. 첫 사용처도 상위 리졸버 없이 SERVFAIL을 낸다(RemoteDebug `settings.go:244-251`, `tunnel.go:118-122`). Bonjour 역방향 이름은 NXDOMAIN(5).

#### 4.2.4 UDP 크기·잘림·EDNS

- 로컬 응답의 UDP 검사(`forwarder.go:220-261`): 질의 끝에 유효한 OPT가 있으면 그 광고 크기를, 없으면 512바이트를 넘을 때 TC 비트만 켠다. 응답을 자르지는 않는다. TCP 질의는 검사하지 않는다.
- OPT 인식(`forwarder.go:148-191`): ARCOUNT가 0이 아니고, 메시지의 **마지막 11바이트**가 NAME 0, TYPE 41, 버전(오프셋 6) 0, RDLEN 0인 레코드일 것. 옵션이 붙은 OPT는 EDNS로 인식하지 않는다(512 규칙이 적용된다).
- 3.1의 크기 계산대로 tailnet 영역의 로컬 응답은 512바이트를 넘지 않으므로 TC가 서는 일은 사실상 없다. 그래도 검사는 몇 줄이므로 Go와 같게 둔다(권고). 응답 IP 패킷은 1,066 + 48 < 1280이라 TUN MTU 안이다.
- 상위 전달 응답(M5에서 쓰지 않음): 질의의 OPT 광고 크기를 4095로 깎아 보내고, 4096바이트 버퍼로 받아 넘치면 잘라 TC를 켠다(`forwarder.go:193-210`, `:868-941`, `tsdns.go:50`).

#### 4.2.5 TCP 53

Go는 서비스 IP의 TCP 53을 netstack에서 받아 3.1의 TCP 프레임으로 처리한다(`tailscale.com/wgengine/netstack/netstack.go:1723-1734`). Swiftail M5는 TCP 스택이 없다(plan 8절 위험 12). 로컬 응답에 TC가 서지 않으므로 OS가 TCP로 다시 물을 일은 없다. 결정 D4.

### 4.3 [M5] 서비스 IP 패킷의 가로채기

OS가 TUN으로 보낸(utun에서 읽은) 패킷은 WireGuard로 가기 전에 `filterPacketOutboundToWireGuard`를 지난다(`tailscale.com/net/tstun/wrap.go:752-830`, `:920`).

1. ICMP echo 요청이고 목적지가 `100.100.100.100` 또는 `fd7a:115c:a1e0::53`이면 tstun 래퍼가 머리를 응답으로 바꿔(주소 맞바꿈, echo reply) payload를 그대로 실은 패킷을 OS 쪽으로 주입하고 원래 패킷은 버린다(`wrap.go:752-769`).
2. TSMP·자기 disco 패킷 버림(`wrap.go:773-789`).
3. netstack 가로채기: 목적지가 두 서비스 IP이면 프로토콜·포트와 무관하게 netstack으로 흡수하고 WireGuard로 보내지 않는다(`wrap.go:790-796`, `netstack.go:866-897`).
   - UDP 53 → `handleMagicDNSUDP`: 같은 흐름의 질의를 150ms 읽기 기한의 루프로 받고, 각 질의를 `Manager.Query(…, "udp", 발신지)`에 넘겨 응답을 같은 흐름으로 돌려준다. `Query`가 오류(동시 질의 256개 초과 등)면 답하지 않는다(`netstack.go:2036-2041`, `:2080-2113`, `manager.go:652-676`).
   - 그 밖의 UDP 포트: 엔드포인트를 닫고 답하지 않는다. ICMP port unreachable도 보내지 않는다(`netstack.go:2000-2011`, `:2042-2051`).
   - TCP 53 → `HandleTCPConn`. 80·8080(웹 클라이언트·Taildrive)과 디버그 루프백 포트는 각 핸들러. 그 밖의 TCP 포트는 RST(`netstack.go:1723-1787`, `tailscale.com/ipn/ipnlocal/netstack.go:21-39`).
   - 그 밖의 프로토콜: 흡수되어 사라진다(netstack에 핸들러가 없다).
4. 응답 방향: netstack이 낸 패킷 가운데 출발지가 서비스 IP인 것은 OS 쪽(TUN 쓰기)으로 나간다(`netstack.go:1047-1062`, `:1119-1147`).
5. darwin·ios에서는 이어서 엔진이 자기 터널 주소로 가는 패킷을 OS로 되돌린다(`wgengine/userspace.go:652-667`).

[netmap-engine.md](netmap-engine.md) 4.8 첫 문단(ICMP echo는 래퍼가, 나머지는 netstack이)과 맞는다. 이 노트의 이전 판이 echo 처리를 "확인하지 못함"으로 둔 것이 틀렸다.

Swiftail M5 권고(패킷 단위 처리, TCP 스택 없음)
- UDP 53(IPv4·IPv6): 4.2의 응답을 출발지·목적지 주소와 포트를 맞바꾼 UDP로 돌려준다. IPv6 UDP는 체크섬이 필수다(RFC 8200 8.1). 응답 하나가 1280 안에 들어가므로 단편화가 필요 없다(4.2.4).
- ICMP·ICMPv6 echo: echo reply를 돌려준다(Go와 같음).
- 그 밖의 패킷: 버리고 WireGuard로 보내지 않는다. TCP는 결정 D4.

### 4.4 [M5] 상태 저장과 신원

#### 4.4.1 Go가 시작할 때 읽는 순서

1. `_current-profile`을 읽는다(`profiles.go:898-910`). `_profiles`를 읽어 맵을 만든다. 없으면 빈 맵(`:912-926`).
2. 키가 있으면 그 프로필을 찾는다. 키도 프로필도 없으면 `_daemon`(iOS는 `ipn-go-bridge`)에서 이주를 시도한다. 그래도 없으면 저장되지 않은 새 프로필이다. 새 프로필의 prefs는 `NewPrefs()`에 `LoggedOut=true`, `WantRunning=false`(`profiles.go:860-866`, `:952-977`).
3. 프로필 키의 값을 `NewPrefs()` 위에 덮어 읽는다. 값이 없거나 비면 2의 기본 prefs. 저장된 `ControlURL`이 기본 제어 서버의 동의어면 비운다(`profiles.go:669-720`).
4. `Start`는 상태를 `NoState`로 두고(`local.go:3151`), `WantRunning`이면 `_machinekey`를 읽는다. 없을 때만 새로 만들어 쓴다. 있는데 파싱 실패이거나 0이면 오류로 멈춘다(`local.go:3207-3211`, `:4619-4651`).

#### 4.4.2 쓰는 시점

- 프로필은 `Persist.NodeID`와 `Persist.UserProfile.LoginName`이 모두 채워져야(= 로그인이 끝나 netmap의 자기 노드를 받아야) 저장소에 생긴다. 그 전의 prefs는 메모리에만 있다. 따라서 첫 로그인 전 파일에 남는 것은 `_machinekey`뿐이다(`profiles.go:350-356`, `:425-428`, `:545-551`).
- 로그인 뒤: 같은 노드·사용자의 프로필이 있으면 그것을 쓰고 중복은 지운다. 새 프로필이면 ID·키를 만들고 `_profiles` → `profile-<id>` → `_current-profile` 순으로 쓴다(`profiles.go:357-404`, `:411-492`, `:657-667`).
- 노드 키: 등록 때 `PrivateNodeKey`가 0이거나 재생성이 요청되면 새 키를 만들고 이전 키를 `OldPrivateNodeKey`로 옮긴다. `NetworkLockKey`가 0이면 새로 만든다(`tailscale.com/control/controlclient/direct.go:704-723`).
- tsnet은 `Start`마다 `NewPrefs()`에 `Hostname`·`WantRunning=true`·`ControlURL`·`RunWebClient`·`AdvertiseTags`를 채워 `UpdatePrefs`로 넘기고, 이것이 `Persist`를 뺀 저장 prefs를 모두 덮는다(`tsnet/tsnet.go:991-1004`, `ipn/backend.go:685-690`, `local.go:3157-3173`).

#### 4.4.3 "다시 시작해도 같은 노드"에 필요한 것

| 항목 | 구분 | 근거 |
| --- | --- | --- |
| 노드 개인 키 | 필수. 등록이 이 키로 같은 노드를 가리킨다. 없으면 새 키를 만든다 | `direct.go:704-713` |
| 머신 개인 키 | 필수(보존). 없으면 새로 만든다. 바뀐 머신 키를 서버가 어떻게 다루는지는 확인하지 못했다(8장) | `local.go:4619-4651` |
| 이전 노드 키, NetworkLock 키 | 키 교체·tailnet lock용. Swiftail은 등록 요청의 `NLKey`를 0으로 보낸다 | `direct.go:714-723`, `Sources/SwiftailControl/Tailcfg/RegisterRequest.swift:38` |
| `NodeID`, `UserProfile`, 프로필 | Go 프로필 관리용. 재등록에는 쓰지 않는다 | `profiles.go:350-356` |
| disco 키 | 저장하지 않는다. 시작마다 새로 만든다 | `tailscale.com/wgengine/magicsock/magicsock.go:580` |
| netmap 디스크 캐시 | 선택 기능 | `tailscale.com/ipn/ipnlocal/diskcache.go:32-65` |

Swiftail의 `identity.json`(머신 키 + 노드 키)이 이 최소 집합이다. M5에서 더할 것은 위치와 보호다: 첫 사용처는 상태를 App Group 컨테이너 아래에 두고, 파일 보호 등급 `completeUntilFirstUserAuthentication`, 백업 제외로 만든다(잠긴 기기에서 재부팅 뒤 첫 잠금 해제 전에는 읽을 수 없다). 같은 상태 디렉터리로 두 번 시작하면 거절한다(RemoteDebug `Apps/iOSTunnel/Shared/TunnelStorage.swift:5-56`, `core/internal/api/api.go:75-90`). 보호 등급의 의미는 Apple 문서 `FileProtectionType.completeUntilFirstUserAuthentication` 항목이다.

`ipn.Prefs` 가운데 노드에 의미 있는 것(`ipn/prefs.go:59-320`): `ControlURL`(비면 `https://controlplane.tailscale.com`, `:42`), `Hostname`, `WantRunning`, `LoggedOut`, `CorpDNS`, `RouteAll`, `AdvertiseTags`, `ShieldsUp`, `Persist`. `NewPrefs()`의 기본은 `CorpDNS=true`, `WantRunning=false`, `NoStatefulFiltering=true`, `NetfilterMode=on`, `AutoUpdate.Check=true`, 그리고 `RouteAll`은 플랫폼별로 windows·android·**ios에서 true**, 샌드박스 macOS에서 true, 그 밖은 false다(`prefs.go:734-757`, `:787-799`). 첫 사용처는 iOS에서 `RouteAll=false`, `CorpDNS=true`, `WantRunning=true`로 덮는다(RemoteDebug `core/internal/tunnel/tunnel.go:155-160`). Swiftail M5는 서브넷 라우트를 받지 않는다([netmap-engine.md](netmap-engine.md) 6.1 1).

### 4.5 [M5] 노드 상태 기계

값: `NoState`=0, `InUseOtherUser`=1, `NeedsLogin`=2, `NeedsMachineAuth`=3, `Stopped`=4, `Starting`=5, `Running`=6(`ipn/backend.go:25-35`). `nextStateLocked`가 위에서부터 처음 맞는 규칙을 쓴다(`local.go:7024-7097`).

| # | 조건 | 결과 | 줄 |
| --- | --- | --- | --- |
| 0 | 상태 저장소 초기화 실패 | `NoState` | `:7026-7028` |
| 1 | `WantRunning` 거짓, `LoggedOut` 거짓, 엔진 차단 아님, 노드 키 있음 | `Stopped` | `:7048-7049` |
| 2 | netmap 없음 + (제어 클라이언트가 사람 없이 인증을 계속할 수 없음 또는 `LoggedOut`) | `NeedsLogin` | `:7050-7055` |
| 3 | netmap 없음, 이전 `Stopped` / `NoState` / `Starting`·`Running`·`NeedsLogin` | `Starting` / `NoState` / 이전 유지 | `:7056-7072` |
| 4 | netmap 있음, `WantRunning` 거짓 | `Stopped` | `:7074-7075` |
| 5 | 자기 키 만료: netmap 자기 노드의 `KeyExpiry`가 0이 아니고 현재 시각보다 이전 | `NeedsLogin` | `:7076-7079`, `local.go:1924-1929` |
| 6 | 자기 노드가 `MachineAuthorized`가 아님(자기 노드가 없으면 Unknown) | `NeedsMachineAuth` | `:7080-7082`, `types/netmap/netmap.go:200-208` |
| 7 | 이전 `NeedsMachineAuth` | `Starting` | `:7083-7085` |
| 8 | 이전 `Starting`: 핸드셰이크가 한 번이라도 된 피어가 있거나 활성 DERP 연결이 있음 | `Running`, 아니면 `Starting` | `:7086-7091`, `local.go:4920-4934` |
| 9 | 이전 `Running` | `Running` | `:7092-7093` |
| 10 | 그 밖 | `Starting` | `:7094-7095` |

- 로그인 URL: 제어가 준 URL을 6일 23시간까지 재사용한다(`local.go:4818-4823`). `Running`에 처음 들어갈 때 지운다(`local.go:6934-6937`). tsnet은 시작 직후 `NeedsLogin`이면 `StartLoginInteractive`를 부른다(`tsnet.go:1008-1016`).
- 상태 진입 부작용(`local.go:6917-7000`): 바뀔 때만 `Notify{State}`. `NeedsLogin`은 엔진 갱신을 막고 `NeedsLogin`·`Stopped`·`NoState`는 엔진·라우터·DNS를 빈 설정으로 되돌린다(= OS 설정의 주소·DNS가 빠진다). `Starting`·`NeedsMachineAuth`는 설정을 다시 계산한다.

plan 6절 `NodeState`와 첫 사용처 사건의 대응(권고)

| Go | 첫 사용처가 내는 값 | Swiftail `NodeState` |
| --- | --- | --- |
| `NoState` | `Starting` | `.starting` |
| `NeedsLogin` | `NeedsLogin`(+ authURL, https만) | `.needsLogin` + `authURL` |
| `NeedsMachineAuth` | 그대로 | `.needsMachineAuth` |
| `Starting`, `Running`, `Stopped` | 그대로 | 같은 이름 |
| `InUseOtherUser`, 백엔드 오류 메시지(Running 아님), TUN 읽기 오류로 엔진 종료 | `Error` + 메시지. 엔진 종료는 stop 전까지 풀리지 않음 | `.failed` + `errorMessage` |

출처: RemoteDebug `core/internal/node/node.go:409-484`, `:577-627`, `:876-878`, `Apps/iOSTunnel/Shared/TunnelStateMapping.swift:45-88`. 첫 사용처는 `NeedsLogin`인데 URL도 인증 키도 없으면 30초마다 대화형 로그인을 다시 요청한다(`node.go:54`, `:752-778`).

### 4.6 [M5] 네트워크 전환(Wi-Fi ↔ 셀룰러)

#### 4.6.1 기본 인터페이스

- iOS 앱이 `NWPathMonitor`에서 만족된 경로의 인터페이스 이름을 `UpdateLastKnownDefaultRouteInterface(name)`로 넘긴다. 빈 이름은 무시한다. 이 값은 그 인터페이스가 있고 올라와 있고 주소가 하나라도 있을 때만 기본 경로로 쓰이고, 아니면 라우팅 테이블에서 찾는다(`tailscale.com/net/netmon/defaultroute_darwin.go:16-112`). 이유: NetworkExtension이 위임 인터페이스를 터널 생성 때 한 번만 정한다(`:38-48`의 주석).
- 이름만 바꾸면 아무 일도 일어나지 않는다. 즉시 다시 계산하려면 `netmon.InjectEvent()`를 부른다. `InjectEvent`는 상태가 같아도 통지를 강제하고 `Poll`은 상태가 바뀐 경우에만 통지한다(`tailscale.com/net/netmon/netmon.go:544-570`, `:640-648`). 첫 사용처는 이름이 바뀌면 둘을 차례로 부르고, 시작 전에 utun 이름을 `SetTailscaleInterfaceProps`로 알린다(GOOS=ios에서는 스스로 알아보지 못한다)(RemoteDebug `core/internal/tunnel/tunnel.go:85-91`, `:211-229`). 이름 검사: 15자 이하, 영숫자와 `_.-`(`docs/tunnel.md:130`).
- darwin 빌드(iOS 포함)의 `netmon`은 `AF_ROUTE` 소켓을 읽고 흥미롭지 않은 인터페이스(`llw`, `awdl`, `ipsec`, `gif`, `XHC`, `anpi`, `lo`, `utun` 접두)의 메시지를 버린다. 확인 사이 최소 간격은 1초다(`netmon_darwin.go:19-46`, `:110-178`, `netmon.go:583-630`). 폴링 구현은 darwin이 아닌 곳에만 있다(`polling.go:4`).

#### 4.6.2 변화의 판정(`ChangeDelta`)

`netmon.go:153-209`. 이전 상태가 없으면 처음 상태. 아니면 `DefaultInterfaceChanged`(기본 인터페이스 이름), `InterfaceIPsChanged`, `AvailableProtocolsChanged`(HaveV4·HaveV6), `IsLessExpensive`, `HasPACOrProxyConfigChanged`를 계산한다. `DefaultInterfaceMaybeViable` = 기본 인터페이스가 올라와 있고 Tailscale 인터페이스가 아님. `RebindLikelyRequired` = (처음 상태 ∨ 10분 이상 시계 점프 ∨ 위 변화 중 하나) ∧ `DefaultInterfaceMaybeViable`. iOS는 시계 점프 감시를 하지 않는다(`netmon.go:726`).

#### 4.6.3 통지를 받는 쪽과 하는 일

1. 엔진(`wgengine/userspace.go:1155-1225`): 올라온 인터페이스가 없으면 DNS 캐시를 비우고 magicsock에 네트워크 내려감을 알려 모든 DERP 연결을 닫는다(`magicsock.go:2755-2773`). `RebindLikelyRequired`이고 올라와 있으면 DNS 캐시를 비우고, iOS에서 마지막 DNS 설정을 다시 적용한 뒤 VPN 설정을 필요하면 다시 낸다. 올라와 있으면 홈 DERP 연결을 시작하고, `RebindLikelyRequired`면 `Rebind`, 이어서 항상 `ReSTUN`(엔드포인트 재수집과 제어 갱신).
2. `Rebind`: UDP 소켓을 같은 포트로 다시 결속하고, 기본 인터페이스 주소를 로컬 주소로 갖지 않는 DERP 연결은 닫거나 다시 잇고(홈), 나머지는 3초 핑으로 확인하며, 모든 피어의 경로 상태를 지운다. 세부는 [disco-magicsock.md](disco-magicsock.md) 4.11(`magicsock.go:3880-3916`, `derp.go:908-938`).
3. 백엔드(`local.go:1128-1164`, `:1215-1250`): 올라온 인터페이스가 없으면 제어 클라이언트를 일시 정지하고, 있으면 재개한다. 패킷 필터를 다시 계산한다.
4. 시스템 연결(`tailscale.com/net/tsdial/tsdial.go:301-355`): `SystemDial`로 연 TCP 연결(제어 등)은 처음 상태가 아니면서 기본 인터페이스나 PAC·프록시가 바뀌었거나, 기본 인터페이스 이름이 비었거나, 연결의 로컬 IP가 사라졌으면 닫혀 상위가 다시 잇는다.

#### 4.6.4 소켓 결속

- 루프 방지를 위해 제어·DERP·magicsock UDP·netcheck·포트매퍼 소켓을 기본 인터페이스에 결속한다. IPv4는 `IP_BOUND_IF`, IPv6는 `IPV6_BOUND_IF`를 `setsockopt`로 건다. 로컬호스트 주소는 결속하지 않고, 인덱스를 얻지 못하면 결속 없이 진행한다(`tailscale.com/net/netns/netns_darwin.go:38-55`, `:295-315`). iOS에서는 기본으로 켜진다. 끄는 스위치는 일반용 `SetDisableBindConnToInterface`(기본 꺼짐)와 macOS GUI 변형에서만 듣는 Apple 확장용이다(`netns_darwin.go:40`, `tailscale.com/net/netns/netns.go:61-95`).
- 인덱스: `UpdateLastKnownDefaultRouteInterface`로 받은 인터페이스가 우선이고 없으면 `netmon` 캐시. 고른 것이 Tailscale `utun`이면 무효(`netns_darwin.go:57-145`).
- 결속은 소켓을 열 때 한 번이다. 인터페이스가 바뀌면 4.6.3의 Rebind·DERP 재연결·시스템 연결 닫기로 새 소켓이 새 인덱스를 얻는다.

M5에 필요한 것(권고): `setDefaultInterface(name)` → 이름 검사 → 바뀌었으면 기본 인터페이스 갱신과 링크 변경 처리(엔진 1의 순서: DERP 닫기·다시 잇기, UDP 재결속, ReSTUN, 제어 연결 재연결, DNS 설정 다시 내기). `disco-magicsock.md`가 M5로 미룬 링크 변경 감지·Rebind·ReSTUN·DERP 재확인·iOS 결속이 이것이다. Swiftail에는 `AF_ROUTE` 감시가 없으므로 앱이 부르는 `setDefaultInterface`가 유일한 통지원이다(결정 D6).

### 4.7 [M6] tsnet 리스너와 다이얼

#### 4.7.1 수신 경로

가짜 TUN(`Tun == nil`) 경로(`tsnet.go:922-934`).

1. 복호화된 패킷이 패킷 필터를 통과한 뒤 netstack으로 온다(`netstack.go:465`, `:1472-1480`). 목적지가 자기 주소이고 `ProcessLocalIPs`면 netstack이 처리한다(`netstack.go:1352-1354`).
2. 진행 중 TCP 연결 상한: 전역 모바일 1024·Linux 8192·그 밖 2048, 원격 IP당 그 2/3. 같은 4-튜플의 SYN 재전송은 무시(`netstack.go:76-120`, `:539-627`).
3. `acceptTCP`: 서비스 IP 처리 → `TCPHandlerForDst`(quad-100의 80·Drive, VIP 서비스, 22, 웹 클라이언트, PeerAPI, serve. tsnet 리스너보다 먼저 가져간다. 리스너 포트가 PeerAPI 포트와 겹치면 PeerAPI가 이긴다) → tsnet `getTCPHandlerForFlow`(`netstack.go:1736-1762`, `ipnlocal/netstack.go:21-72`).
4. 리스너 조회: (`tcp4`/`tcp6`, 도착 IP, 포트) → (`tcp`, IP, 포트) → (`tcp4`/`tcp6`, 호스트 없음, 포트) → (`tcp`, 호스트 없음, 포트). 호스트 없는 리스너는 목적지가 자기 노드 주소일 때만. 없으면 RST(`tsnet.go:1238-1266`, `:1289-1303`).
5. `CreateEndpoint`는 핸드셰이크를 **시작만** 하고, 곧바로 keepalive를 켠 `gonet.TCPConn`을 리스너에 넘긴다. 그래서 `Accept`가 돌려준 연결은 핸드셰이크가 끝나지 않았을 수 있고(읽기·쓰기는 끝날 때까지 막힌다), 그 전에는 주소 조회가 비어 있다(`netstack.go:1666-1673`, `:1702`, `:1712-1720`). 버퍼 없는 채널로 넘기며 1초 안에 `Accept`가 가져가지 않으면 닫는다(`tsnet.go:2406-2417`).

`Listen`(`tsnet.go:1321-1323`, `:2090-2094`, `:2115-2271`): `0.0.0.0`·`::`는 호스트 없음으로 정규화. 포트 0은 10002~19999에서 `nextEphemeralPort`부터 순환 할당. 같은 키로 다시 열면 `listener already open` 오류. `Server.Tun`을 쓰는 경우 `tcp`·빈 값은 `tcp4`/`tcp6`으로 바뀌고 호스트가 없으면 tcp6 듀얼 스택이다(`tsnet.go:2160-2180`).

#### 4.7.2 다이얼

1. 주소가 IP가 아니면 MagicDNS 콜백(노드 FQDN·짧은 이름·`Type`이 빈 `ExtraRecords`)으로 푼다. `tcp`이면 IPv4 우선. quad-100을 거치지 않는다. 못 풀면 시스템 리졸버(`tsdial.go:401-489`, `ipnlocal/resolve.go:60-77`, `:115-146`, `node_backend.go:823-836`).
2. 주소가 여럿이면 300ms 간격 경쟁(`tsdial.go:640-656`).
3. `PeerForIP`가 성공하면(테일넷 주소 또는 라우트를 가진 피어) netstack 다이얼, 아니면 OS 네트워크(`tsnet.go:935-939`, `tsdial.go:608-638`, `ipnlocal/resolve.go:166-198`). 출발지는 같은 계열의 자기 테일넷 IP(`tsnet.go:940-951`).
4. tsnet `Dial`은 상태가 `Running`이 될 때까지 기다린다(`NeedsLogin`·`Starting`이면 대기, 그 밖의 상태는 오류)(`tsnet.go:382-419`).

#### 4.7.3 netstack 설정(Swift TCP의 비교 기준)

| 항목 | 값 | 출처 |
| --- | --- | --- |
| 프로토콜 | IPv4·IPv6, TCP·UDP·ICMPv4·ICMPv6, NIC 1개(프로미스큐어스), 두 기본 경로 | `netstack.go:388-391`, `:436-464` |
| MTU·큐 | 1280(`DefaultTUNMTU`), 512 | `netstack.go:434`, `tailscale.com/net/tstun/mtu.go:77-79` |
| 혼잡 제어·손실 복구 | `cubic`, RACK 끔(`TS_NETSTACK_ENABLE_RACK=true`일 때만 켬. 같은 파일 `:141-145` 주석은 반대로 적혀 있으나 코드를 따랐다) | `netstack.go:405-417` |
| 수신 버퍼 | 최소 4096, 기본 1MiB, 최대 8MiB(iOS는 gVisor 최대 4MiB) | `netstack_tcpbuf_default.go:13-19`, `netstack_tcpbuf_ios.go:13-23`, `gvisor/pkg/tcpip/transport/tcp/protocol.go:41-52` |
| 송신 버퍼 | 최소 4096, 기본 1MiB, 최대 6MiB(iOS 4MiB). 기본 상수 이름이 송·수신 뒤바뀌어 있으나 값이 같다 | 같음 |
| 포워더 수신 윈도 인자 | 1MiB | `netstack.go:669` |
| keepalive | 수락 연결에 켬. idle 2시간, interval 75초, count 9 | `gvisor/pkg/tcpip/transport/tcp/protocol.go:72-80` |

iOS가 최대 버퍼를 gVisor 기본(4MiB)으로 두는 것은 NetworkExtension 메모리 한도에 압박을 더하지 않으려는 것이다(`netstack_tcpbuf_ios.go:13-16`).

### 4.8 [M7] `WhoIs`

`LocalBackend.WhoIs(proto, ipport)`(`local.go:1753-1805`):

1. `::ffff:a.b.c.d`를 IPv4로 바꾼다.
2. `nodeByAddr`(노드 자신의 주소, 자기 노드 포함)에서 찾는다. 테일넷 주소면 포트 0이어도 된다(`node_backend.go:119-121`).
3. 못 찾으면(빌드에 netstack 기능이 있을 때) 포트가 0이면 실패, 아니면 `ProxyMapper`로 (proto, ip:port)를 실제 원격 IP로 바꿔 다시 찾는다. `proto`가 비면 tcp, udp 순(`local.go:1773-1797`). tsnet 리스너가 받은 연결은 원격 주소가 이미 피어 주소다.
4. netmap이 없으면 실패. 노드의 `User`로 사용자 프로필을 찾고, 없으면 실패(`local.go:1799-1805`).

로컬 API `GET /localapi/v0/whois?addr=`(`ip`, `ip:port`, `nodekey:…`. 그 밖에 `proto`, `svc_name`, `dst_ip`)의 응답(`tailscale.com/ipn/localapi/localapi.go:516-629`, `tailscale.com/client/tailscale/apitype/apitype.go:35-42`):

| 키 | 내용 |
| --- | --- |
| `Node` | `tailcfg.Node` 전체 |
| `UserProfile` | `ID`, `LoginName`, `DisplayName`, `ProfilePicURL`(빈 값 생략), `Groups`(빈 값 생략)(`tailcfg.go:307-319`) |
| `CapMap` | src = 원격 노드의 첫 주소, dst = 같은 계열의 자기 노드 첫 주소로 패킷 필터의 `CapsWithValues(src, dst)`. `UnsignedPeerAPIOnly` 피어는 ingress 능력만. 노드에 주소가 없으면 생략(`node_backend.go:443-466`) |

상태 코드: 읽기 권한 없음 403, `addr` 없음·잘못됨 400, 못 찾음 404. tsnet에는 `WhoIs` 메서드가 없고 `LocalClient().WhoIs`를 쓴다. 404는 `ErrPeerNotFound`(`tailscale.com/client/local/local.go:353-362`). 첫 사용처는 `Node.StableID`(필수, 없으면 거절), `Node.Name`의 첫 레이블(비면 `ComputedName`), `UserProfile.LoginName`만 읽는다(RemoteDebug `core/internal/node/node.go:526-551`).

### 4.9 [M7] ts.net 인증서

1. 저장 위치(`tailscale.com/feature/acme/certstore.go:64-104`, `:247-261`): 상태 저장소가 FileStore나 메모리 저장소면 `<varRoot>/certs/`(0700) 아래 파일. 그 밖의 저장소이고 Kubernetes 환경이면 상태 저장소 안의 같은 이름 키. varRoot가 비면 실패. tsnet은 varRoot = `Dir`이다(`tsnet.go:848-862`, `:984`).

   | 파일 | 내용 | 권한 |
   | --- | --- | --- |
   | `<도메인>.key` | 인증서 개인 키, PEM `EC PRIVATE KEY`(SEC1, P-256) | 0600 |
   | `<도메인>.crt` | 체인, PEM `CERTIFICATE` 블록 나열 | 0644 |
   | `acme-account.key.pem` | ACME 계정 키, PEM `EC PRIVATE KEY`(P-256) | 0600 |

   와일드카드의 `*.`는 파일 이름에서 `wildcard_.`(`certstore.go:116-169`, `:284-330`, `:361-389`).
2. 호출 경로: `LocalClient.CertPair` → `GET /localapi/v0/cert/<도메인>?type=pair&min_validity=` → 개인 키 PEM 뒤에 인증서 PEM(`client/local/cert.go:102-135`, `ipn/localapi/cert.go:21-70`). 이 로컬 API 핸들러의 빌드 태그는 `!ios && !android && !js && !ts_omit_acme`다(`ipn/localapi/cert.go:4`). `feature/acme` 자체는 iOS에도 링크되지만 tsnet의 TLS는 로컬 API를 거치므로 iOS에서 Go tsnet의 `ListenTLS`는 인증서를 얻지 못한다(`tsnet/maybe_acme.go:4`, `tsnet.go:1505-1511`에서의 추론).
3. `GetCertificate`: SNI가 없으면 오류, 점이 없으면 `CertDomains`에서 그 이름으로 시작하고 다음이 점인 항목으로 확장, 1분 제한(`client/local/cert.go:162-205`). `ListenTLS`는 `tcp`만 받고, `Up`이 끝날 때까지 기한 없이 기다린 뒤 `MagicDNSEnabled`와 비지 않은 `CertDomains`를 요구한다. `min_validity=0`이라 핸드셰이크는 캐시를 받고 갱신은 비동기다(`tsnet.go:1458-1481`). 첫 사용처는 `ListenTLS` 대신 `Listen` + `tls.NewListener(GetCertificate)`를 쓰고 `CertPair`로 예열한다(30초부터 10분까지 늘려 재시도)(RemoteDebug `core/internal/node/tls.go:22-51`, `node.go:825-859`).
4. 발급(`feature/acme/cert.go:81-168`, `:345-447`, `:487-654`):
   1. 끝 점을 떼고 이름을 검사한다(점 필수, `..`·`:`·`/`·`\`·NUL 금지, `*`는 `*.`로 시작할 때만)(`:96-100`, `:662-678`).
   2. netmap 필요. `CertDomains`에 정확히 있는 이름만(BYO Funnel 도메인은 예외). `*.<도메인>`은 `dns-subdomain-resolve` 능력이 필요(`:689-728`).
   3. 저장된 쌍을 읽어 `DNSName`과 현재 시각으로 체인 검증(시스템 루트 → 내장 Let's Encrypt 루트)(`certstore.go:135-154`, `:411-474`).
   4. 갱신 판정: `min_validity`가 0이 아니면 남은 기간이 그보다 짧을 때 동기 갱신. 0이면 ARI 제안 구간의 무작위 시각이 지났을 때(ARI 조회 5초 실패 시 수명의 2/3 지점) 도메인별로 하나씩 비동기 갱신하고 현재 것을 돌려준다(`:138-251`, `:306-340`).
   5. 계정 키(없으면 P-256 생성·저장), 디렉터리 기본 `https://acme-v02.api.letsencrypt.org/directory`(`TS_DEBUG_ACME_DIRECTORY_URL`로 바꿈), HTTP는 `http.DefaultClient`(`certstore.go:361-404`, `tempfork/acme/acme.go:47`, `tempfork/acme/http.go:264-269`). `GetReg` → 없으면 `Register` → `valid` 확인(`cert.go:386-392`, `:451-473`).
   6. 주문(이전 인증서가 있으면 ARI `replaces`) → 권한마다 DNS-01(TLS-ALPN-01은 :443 Funnel + 이전 인증서 또는 BYO Funnel일 때만)(`:253-275`, `:394-446`, `:515-536`).
   7. DNS-01: TXT 값 = `base64url(SHA-256(token + "." + JWK 지문))`(패딩 없음), 이름 = `_acme-challenge.<도메인>`. 시스템 리졸버로 500ms 안에 이미 있는지 보고, 없으면 제어에 노이즈 채널 `POST /machine/set-dns`, JSON `SetDNSRequest{Version, NodeKey, Name, Type: "TXT", Value}`(Version은 `CurrentCapabilityVersion`으로 채워진다). 200이 아니면 오류, 200이면 `{}`를 해독(`:615-654`, `tempfork/acme/acme.go:591-598`, `local.go:7809-7839`, `direct.go:1758-1781`, `tailcfg.go:2595-2621`). 그 뒤 `Accept`.
   8. `WaitOrder` → 새 P-256 키, CSR(`CN`·SAN = 도메인) → `CreateOrderCert(bundle=true)` → 키 파일, 인증서 파일 순으로 저장(`:563-613`, `certstore.go:164-169`, `:305-330`).
5. 백그라운드 갱신 루프(1시간, 첫 회 즉시): 상태가 `Running`이고 serve 설정에 Web 항목이나 `TerminateTLS`가 있을 때만 돈다. `Listen`·`ListenTLS`·`ListenFunnel`만 쓰면 돌지 않고, `ListenService`(HTTP 모드·`TerminateTLS`)를 쓰면 돈다. `TS_CERT_SHARE_MODE=ro`면 발급·갱신하지 않는다(`feature/acme/refresh.go:21-76`, `:134-155`, `tsnet.go:2007-2039`, `cert.go:123-125`).

### 4.10 [M6·M7] tsnet 표면 요약

| 호출 | 요지 | 출처 |
| --- | --- | --- |
| `Up` | 버스를 초기 상태와 함께 구독, `Running`이면 `Status` 반환, `ErrMessage`면 실패, `NeedsLogin`·`NeedsMachineAuth`는 계속 대기. 첫 `Up`에서 serve 설정을 비운다 | `tsnet.go:573-636` |
| `Status` | `ipnstate.Status`: `Version`, `TUN`, `BackendState`, `HaveNodeKey`, `AuthURL`, `TailscaleIPs`, `Self`, `ExitNodeStatus`, `Health`, `MagicDNSSuffix`, `CurrentTailnet`, `CertDomains`, `Peer`, `User`, `ClientVersion` | `ipn/ipnstate/ipnstate.go:32-91` |
| `WatchIPNBus` | `Notify` JSON 스트림(`State`, `ErrMessage`, `BrowseToURL`, `LoginFinished`, `Prefs`, `InitialStatus` 등) | `client/local/local.go:1516-1544`, `ipn/backend.go:84-227`, `:335-509` |
| `StartLoginInteractive` | 유효한 URL이 있으면 바로 알림, 없으면 대화형 로그인 요청 | `local.go:4798-4839` |

## 5. 상수와 타이머

| 이름 | 값 | 출처 |
| --- | --- | --- |
| [M5] 서비스 IP | `100.100.100.100`, `fd7a:115c:a1e0::53` | `tailscale.com/net/tsaddr/tsaddr.go:52-68` |
| [M5] 4to6 범위 | `fd7a:115c:a1e0:ab12:4843:cd96:6200::/104` | `tsaddr.go:104-110` |
| [M5] 로컬 응답 TTL(A·AAAA·PTR) | 5초 | `tsdns.go:58` |
| [M5] SOA TTL·REFRESH·RETRY·EXPIRE·MINIMUM | 10 | `tsdns.go:68`, `:1186-1198` |
| [M5] UDP 기본 최대(EDNS 없음) | 512바이트 | `forwarder.go:228` |
| [M5] 동시 DNS 질의 | 256 | `manager.go:60` |
| [M5] 서비스 IP UDP 읽기 기한 | 150ms | `netstack.go:2085` |
| [M5] DNS TCP 유휴·최대 요청 | 45초·4096바이트 | `manager.go:682`, `:687` |
| [M5] 질의 전체 제한(전달) | 10초 | `tsdns.go:406` |
| [M5] 전달 응답 최대 | 4095바이트(버퍼 4096) | `tsdns.go:50` |
| [M5] 이름 포인터 최대 | 10 | `golang.org/x/net@v0.60.0/dns/dnsmessage/message.go:2097` |
| [M5] TUN MTU 기본 | 1280 | `tailscale.com/net/tstun/mtu.go:79` |
| [M5] `netmon` 최소 확인 간격 | 1초 | `netmon.go:627` |
| [M5] 큰 시계 점프(iOS는 감시 안 함) | 10분 | `netmon.go:42`, `:726` |
| [M5] Rebind 뒤 DERP 핑 | 3초 | `derp.go:923` |
| [M5] 로그인 URL 재사용 | 6일 23시간 | `local.go:4822` |
| [M5] 빈 기본 설정 재시도(Apple 아님) | 1초부터 2배, 6회 | `manager.go:54-55` |
| [M6] 진행 중 연결 상한 | 모바일 1024, Linux 8192, 그 밖 2048, 원격 IP당 2/3 | `netstack.go:85-120` |
| [M6] `Accept` 전달 대기 | 1초 | `tsnet.go:2412` |
| [M6] 임시 포트 | 10002~19999 | `tsnet.go:2110-2113` |
| [M6] 다이얼 경쟁 간격 | 300ms | `tsdial.go:643` |
| [M7] 인증서 갱신 루프 | 1시간(첫 회 즉시), 호출당 2분 | `refresh.go:21`, `:84-132` |
| [M7] ARI 실패 시 갱신 지점 | 수명의 2/3 | `cert.go:248` |
| [M7] ARI 조회·TXT 사전 조회 | 5초·500ms | `cert.go:306-340`, `:615-636` |
| [M7] `GetCertificate` 제한 | 1분 | `client/local/cert.go:162-205` |

## 6. Swiftail에 필요한 최소 부분과 생략할 수 있는 부분

### 6.1 M5 — iOS 패킷 터널

필요한 최소 구현
1. DNS 설정 산출: 4.1.4의 1~7. 결과를 `TunnelNetworkSettings.dnsServers`·`dnsMatchDomains`로 낸다.
2. 응답기: 3.1의 바이트 형식(머리, 질문 하나, 포인터를 따르는 이름 읽기, 압축 없는 쓰기)과 RCODE 표, 4.2.1 색인 규칙, 4.2.2의 1~3·5·6, 4.2.3의 SERVFAIL, 4.2.4의 TC 검사.
3. 서비스 IP 가로채기: 4.3 권고(UDP 53 응답, echo 응답, 나머지 버림).
4. 상태: 기존 `identity.json`을 App Group 경로·파일 보호 등급과 함께 쓰기, 같은 디렉터리 중복 시작 거절(4.4.3).
5. 상태 기계: 4.5 표(netmap·`MachineAuthorized`·`KeyExpiry`·라이브 여부)와 `NodeState` 대응. 키 만료·`NeedsLogin`이면 DNS·주소를 빈 설정으로 되돌린다.
6. 네트워크 전환: 4.6 끝의 권고와 [disco-magicsock.md](disco-magicsock.md) 4.11, 소켓 결속(4.6.4).

생략 가능(근거)
- 상위 전달 전체(라우트 선택, UDP·TCP·DoH, 응답 집계): match 도메인만 주면 OS가 tailnet 밖 이름을 quad-100에 보내지 않는다(4.2.3). 첫 사용처도 전달하지 않는다.
- `GetBaseConfig`와 1차 리졸버 모드(4.1.3 3·5행): 결정 D2.
- TCP 53: 로컬 응답은 TC가 서지 않는다(4.2.4). 결정 D4.
- 4via6 이름, 서브도메인 규칙(`dns-subdomain-resolve`), `.onion`(한 줄이라 넣어도 된다), `FallbackResolvers`·`ExitNodeFilteredSet`·`Nameservers`(4.1.1).
- Go 상태 파일 형식(3.2): M7.

### 6.2 M6 — 프로세스 내 리스너·다이얼

필요한 최소 구현: 4.7.1의 수신 경로(필터 뒤 수신, 리스너 조회 4단계, 리스너 없으면 RST, `Accept` 1초, 진행 중 연결 상한, keepalive), `Listen`의 정규화·임시 포트·중복 오류, 4.7.2의 다이얼(이름은 MagicDNS 색인으로, quad-100을 거치지 않음, 출발지 자기 IP). Accept 시점의 연결 상태(핸드셰이크 완료 여부)는 M6 계약에서 정한다(Go는 미완료 상태로 넘긴다).

생략 가능: `ListenPacket`, `ListenTLS`/Funnel/Service, 서브넷, PeerAPI·SSH·웹 클라이언트(`TCPHandlerForDst`), `ProxyMapper`.

### 6.3 M7 — 첫 사용처 대체 검증

필요한 최소 구현
- `whoIs`: 4.8의 1·2·4와 `Node`·`UserProfile` 반환. 첫 사용처가 읽는 것은 `StableID`, `Name`(또는 `ComputedName`), `LoginName`.
- 인증서: 4.9 4의 1~8(DNS-01만), 1의 파일 형식, 요청 시 갱신 판정(2/3 규칙으로 충분). 필요한 부품: ACME(RFC 8555) 클라이언트, ES256 JWS, P-256 키·SEC1 PEM, PKCS#10 CSR, X.509 체인 검증, 제어 `set-dns`, 도메인별 잠금. ACME HTTP 요청의 결속 정책은 따로 정한다(Go는 OS 기본 경로).
- Go 상태 파일 이관: 3.2의 `_machinekey`와 `_current-profile` → `profile-<id>` → `Config.PrivateNodeKey`(필요하면 `OldPrivateNodeKey`)만 읽으면 Swiftail `identity.json`을 만들 수 있다. 값은 base64를 푼 뒤 `privkey:` + hex.

생략 가능: ARI·`replaces`, 와일드카드, TLS-ALPN-01, 백그라운드 루프, Kubernetes 저장소, 프로필 여럿.

### 6.4 M5 계약에서 총괄이 정할 결정

| # | 결정 | 선택지 | 권고 |
| --- | --- | --- | --- |
| D1 | DNS를 OS에 주는 방식 | (가) match 도메인만(Go 4행, 첫 사용처) / (나) Go 그대로 1차 리졸버 모드까지 | (가). (나)는 상위 전달과 NE 안에서 OS 기본 리졸버를 읽는 방법이 필요한데 후자는 확인하지 못했다(8장) |
| D2 | `DNSConfig.Resolvers`(전역 네임서버)·리졸버가 있는 `Routes`(사용자 지정 분할 DNS)가 올 때 | (가) 무시하고 로컬 영역만 match(첫 사용처) / (나) 그 접미사도 match에 넣고 SERVFAIL / (다) 전달 구현 | (가). 지원하지 않음을 계약과 상태에 기록한다. 해당 이름은 OS 기본 DNS로 간다 |
| D3 | 검색 도메인(`Domains`)과 `matchDomainsNoSearch` | (가) 내지 않음, 앱은 `matchDomainsNoSearch = true`(첫 사용처. 짧은 이름은 풀리지 않음) / (나) `TunnelNetworkSettings`에 검색 도메인 필드 추가 | (가). Go 주석상 Apple 범위 지정 모드는 match 도메인을 검색 목록으로 쓰는데, 그러면 역방향 영역 65개도 검색 목록이 된다(8장) |
| D4 | 서비스 IP TCP(53 포함) | (가) 조용히 버림 / (나) RST를 만들어 보냄 / (다) M6 TCP 스택 연결 | (나). Go도 53 밖의 포트는 RST다. 53은 M6 뒤 (다) |
| D5 | 서비스 IP의 ICMP echo | 응답 / 버림 | 응답(Go와 같고 진단에 쓰인다) |
| D6 | 링크 변경의 통지원 | (가) `setDefaultInterface`만 / (나) Swiftail 안에 `NWPathMonitor` | (가). 라이브러리는 NetworkExtension·Network 프레임워크 정책을 앱에 둔다(plan 6절). 이름이 같아도 앱이 다시 부르면 재평가한다(Go `InjectEvent`처럼) |
| D7 | 피어 AAAA | Go 규칙(IPv4가 있으면 AAAA 없음, `magicdns-aaaa`면 허용) / 항상 AAAA | Go 규칙 |
| D8 | 상태 디렉터리 | 첫 사용처의 Go 상태 파일과 같은 디렉터리 / 별도 | 별도 디렉터리. 이관은 M7 결정(6.3) |
| D9 | `Running` 판정 | Go 규칙(핸드셰이크된 피어 또는 DERP 연결) / netmap 수신만 | Go 규칙. 피어가 없는 tailnet에서도 DERP로 `Running`이 된다 |

## 7. 상호 운용 시험에서 확인할 것

아래는 실행하지 않은 계획이다.

M5 DNS(메모리 TUN, Go 노드와 비교)
1. 설정 산출: MagicDNS 켬·끔, `ExtraRecords`(라우트로 덮임·안 덮임), 빈 라우트, 리졸버가 있는 라우트, 전역 `Resolvers`, IPv4 전용·IPv6 전용 노드, `force-register-magicdns-ipv4-only`. Go `dns.NewManager(goos "ios")`의 `OSConfig`와 4.1.4 결과를 나란히 기록한다(첫 사용처의 시험 `docs/tunnel.md:175-176`과 같은 방식).
2. `100.100.100.100:53`·`[fd7a:115c:a1e0::53]:53`에 A, AAAA, ANY, PTR(IPv4·IPv6·4to6·서비스 IP), NS, SOA, TXT, 모르는 타입을 보내 Go와 바이트 단위 비교: RCODE, AA, RA(RD 0·1), TTL, SOA 유무·내용(SERIAL 제외), 질문 대소문자 보존.
3. 짧은 이름, FQDN, 대소문자 섞인 이름, 끝 점 없는 이름, 주소 없는 노드, 영역 밖 이름(SERVFAIL), `.onion`, Bonjour 역방향 이름, 질문 0개·2개, QR=1, 포인터 압축된 질문, 잘못된 레이블(FORMERR).
4. EDNS(`+bufsize=4096`)에서 응답에 OPT가 없음, 512바이트 경계 TC.
5. 서비스 IP: UDP 다른 포트 무응답, TCP RST(D4), ICMP·ICMPv6 echo 응답, 어떤 패킷도 WireGuard로 나가지 않음.

M5 상태·전환
6. 같은 디렉터리로 다시 시작하면 `NeedsLogin` 없이 같은 IP, 새 디렉터리면 다른 IP(첫 사용처 `docs/tunnel.md:163`). 키 만료 → `NeedsLogin`과 DNS·주소 제거, 머신 미승인 → `NeedsMachineAuth`, 피어 없는 tailnet에서 DERP만으로 `Running`.
7. 실기기 Wi-Fi ↔ 셀룰러, 비행기 모드 해제: DERP 재연결·UDP 재결속·제어 재연결까지의 시간, 전환 뒤 FQDN 해석.

M6·M7
8. 리스너 없는 포트 RST, `Accept` 1초, 원격 IP당 상한, Accept 시점 상태(6.2).
9. `whoIs`가 Go `LocalClient.WhoIs`와 같은 `Node.StableID`·`LoginName`을 돌려줌.
10. Let's Encrypt 스테이징 디렉터리로 발급, 제어가 `set-dns`를 받는지(testcontrol `tstest/integration/testcontrol/testcontrol.go:605`), 갱신 판정.
11. Go `tailscaled.state`에서 이관한 노드가 같은 IP로 올라오는지.

## 8. 확인하지 못한 것

### 8.1 미확인 사실

- iOS 앱 쪽 Go 바깥 코드: Tailscale iOS 앱의 `OSConfigurator`(`SupportsSplitDNS`, `GetBaseConfig`)와 `OSConfig` → `NEDNSSettings` 변환은 기준 소스에 없다. `manager.go:361-366`, `:436-445`의 주석("Apple 확장은 1차 모드에서만 검색 도메인을 설치하고 범위 지정 모드에서는 match 도메인을 검색 목록으로 쓴다", "`NEDNSSettings.searchDomains`는 configd가 지운다")은 주석으로만 확인했다.
- `NEDNSSettings.matchDomains`의 OS 동작(match 밖 이름을 터널 DNS로 보내지 않음, `matchDomainsNoSearch`)은 Apple 문서 항목에 근거해야 하며 이 검증에서 문서를 대조하지 않았다. NE 확장 안에서 OS 기본 리졸버를 읽는 방법도 확인하지 못했다(D1).
- `selfExpired`일 때: 설정은 비지만 리졸버의 노드 색인 조회는 설정과 무관하다(`tsdns.go:756-759`). 다만 OS 경로·DNS가 빠지므로(4.5) quad-100으로 패킷이 오지 않는 것으로 보인다. 실행으로 확인하지 않았다.
- 머신 키가 바뀐 노드를 제어 서버가 어떻게 다루는지, `NLKey`를 0으로 보내는 것의 영향(제어 노트의 몫).
- `force-register-magicdns-ipv4-only`·`disable-split-dns-when-no-custom-resolvers`를 운영 제어 서버가 언제 주는지.
- iOS에서 `AF_ROUTE` 소켓(`netmon_darwin.go`)이 확장 샌드박스에서 실제로 열리는지. Go는 `GOOS=ios`도 `darwin` 빌드 태그에 맞춘다는 Go 빌드 규칙에 기대고 있다.
- `ProxyMapper`가 채워지는 정확한 조건, `InUseOtherUser`를 만드는 경로(Windows 전용으로 보임).
- ACME: `tempfork/acme`의 JWS·논스·폴링 간격 세부, Let's Encrypt 속도 제한.
- tsnet `Listen("")`(빈 network)으로 등록한 리스너를 수신 경로가 찾지 못하는 것은 코드 관찰이다(`tsnet.go:2117`, `:1238-1266`).

### 8.2 첫 사용처 요구 가운데 plan·계약에 아직 없는 것

- 상태 파일의 파일 보호 등급·백업 제외·App Group 경로, 같은 상태 디렉터리 중복 시작 거절(4.4.3).
- 설정 사건의 규칙: 주소가 없으면 내지 않음, 같으면 내지 않음, DNS만 바뀌어도 냄, 큐에는 최신 하나만(RemoteDebug `core/internal/tunnel/settings.go:125-142`, `core/internal/node/node.go:396-407`).
- 엔진 종료(TUN 읽기 오류) → 오류 상태, stop 전까지 유지(`docs/tunnel.md:162`).
- utun fd 처리: dup, close-on-exec, non-blocking, `UTUN_OPT_IFNAME`으로 `utun*` 확인, 호출자 fd를 닫지 않음(`core/internal/tunnel/utun_darwin.go:16-60`). MTU 1280~1420(기본 1280)과 상태의 mtu 보고(`docs/tunnel.md` 시험 10·11).
- `setDefaultInterface` 이름 검사와 즉시 재평가(4.6.1).
- `NeedsLogin`에서 URL·인증 키가 없을 때 30초 간격 대화형 로그인 재요청(4.5).
- 상태에 노출되는 값: `CertDomains`, 자기 FQDN, 자기 `StableID`(페어링이 `StableID`에 묶인다, `docs/tunnel.md:28`).

### 8.3 사실 정정 집계

같은 오류의 반복은 한 건으로 셌다. 출처 줄만 고친 것(12건)과 새로 채운 절은 세지 않았다.

| # | 고친 주장 | 확인 출처 |
| --- | --- | --- |
| 1 | 서비스 IP ICMP echo 처리는 확인하지 못함 → tstun 래퍼가 echo reply를 주입 | `tailscale.com/net/tstun/wrap.go:752-769` |
| 2 | 모드 B만 구현해도 동작은 모드 A와 같다 → 모드 B는 quad-100을 모든 이름의 1차 리졸버로 만들어 상위 전달과 OS 기본 리졸버가 있어야 하며, 기본 리졸버가 비면 OS 설정 자체를 바꾸지 않는다 | `manager.go:463-525`, `:207-214` |
| 3 | 로컬 응답은 512바이트를 넘지 않는다 → 압축이 없어 이론상 약 1,066바이트까지 가능, tailnet 영역에서는 넘지 않음 | `tsdns.go:1213-1218`, `:1177-1199` |
| 4 | 이름이 있으면 주소가 비어도 "이름은 있음" → 주소가 하나도 없는 노드는 모르는 이름 | `node_backend.go:1205-1207` |
| 5 | FORMERR는 모두 질문 없이 → 유효하지 않은 FQDN의 FORMERR는 질문 포함 | `tsdns.go:1222`, `:1461-1468` |
| 6 | RA는 RD가 1일 때만 1 → RD가 0이면 질의의 RA 값이 그대로 남음(머리 전체 복사) | `tsdns.go:1009-1011`, `:1206-1208` |
| 7 | `NewPrefs()` 기본값 목록에 `RouteAll` 없음 → iOS에서 `RouteAll=true`가 기본 | `ipn/prefs.go:756`, `:787-799` |
| 8 | `InjectEvent`·`Poll` 모두 즉시 재계산 → `InjectEvent`만 상태가 같아도 통지를 강제 | `netmon.go:544-570`, `:640-648` |
| 9 | 수락 연결은 핸드셰이크 완료 뒤 넘긴다 → 시작만 하고 넘긴다 | `netstack.go:1666-1720` |
| 10 | iOS 최대 버퍼를 "줄이지 않고" → gVisor 최대(4MiB)가 다른 플랫폼보다 작으며 "올리지 않는" 것 | `gvisor/pkg/tcpip/transport/tcp/protocol.go:52`, `netstack_tcpbuf_ios.go:13-16` |
| 11 | 인증서 갱신 루프는 tsnet에서 돌지 않는다 → `ListenService`(Web·`TerminateTLS`)를 쓰면 돈다 | `feature/acme/refresh.go:36`, `:134-155`, `tsnet.go:2007-2039` |
| 12 | 인증서는 늘 `<varRoot>/certs/` → Kubernetes 환경의 비파일 저장소는 상태 저장소 키 | `feature/acme/certstore.go:83-104`, `:247-261` |
| 13 | WhoIs: 포트 0이면 ProxyMapper를 건너뜀 → 실패. netmap 없음도 실패 | `local.go:1773-1802` |
| 14 | `Server.Tun` 경로는 `tcp4`/`tcp6`만 → tsnet이 `tcp`·빈 값을 바꿔 줌 | `tsnet.go:2160-2180` |
| 15 | 인증서 로컬 API 빌드 태그 `!ios && !android` → `!ios && !android && !js && !ts_omit_acme`, iOS Go tsnet `ListenTLS`는 인증서를 못 얻음 | `ipn/localapi/cert.go:4`, `tsnet/maybe_acme.go:4` |
| 16 | 비동기 갱신은 한 번에 하나 → 도메인별 하나. `CertDomains`가 비어도 BYO Funnel 도메인은 통과 | `feature/acme/cert.go:212-221`, `:700`, `:723-725` |
