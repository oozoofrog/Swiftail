# DNS·상태 저장·노드 표면 노트

## 1. 머리말

| 항목 | 내용 |
| --- | --- |
| 기준 버전 | `tailscale.com` v1.104.6 (CapabilityVersion 148) |
| 쓰는 마일스톤 | M5(iOS 패킷 터널), M6(프로세스 내 리스너), M7(첫 사용처 대체) |
| 작성 모델 | Claude Sonnet 5.5 (`claude-sonnet-5-5`) |
| 검증 상태 | 미검증. 작성한 제공자와 다른 제공자의 모델이 Go 소스와 대조해야 한다. |

구성: 1부 MagicDNS와 2부 상태 저장·신원은 구현 명세 수준으로, 3부 tsnet 표면과 4부 네트워크 감시는 범위 산정용 요약으로 쓴다. 절 번호는 `README.md`의 노트 형식을 따르고, 각 절 안에서 1~4부를 나눈다. 출처는 모듈 루트 기준 `경로:줄`이다. 예시 값은 가짜(`tail0001.ts.net`, `100.64.0.x`)다.

## 2. 범위

다루는 것
- 1부: `tailcfg.DNSConfig`가 엔진의 DNS 설정(`dns.Config`)과 리졸버 설정(`resolver.Config`)으로 바뀌는 규칙, `100.100.100.100`/`fd7a:115c:a1e0::53` 리졸버의 응답 규칙, 이 주소로 가는 패킷이 리졸버에 닿는 경로.
- 2부: `ipn/store` 파일 저장 형식, 키 이름과 값, 재시작 시 보존할 것, `ipn.Prefs`, `ipn.State` 전이.
- 3부: `tsnet.Server`의 `Up`·`Listen`·`Dial`, `LocalClient`의 `WhoIs`·`Status`·`WatchIPNBus`·`StartLoginInteractive`·`CertPair`·`GetCertificate`가 쓰는 하위 기능.
- 4부: `net/netmon`, `net/netns`(darwin·iOS), 링크 변경이 엔진에 미치는 일.

다루지 않는 것
- WireGuard 데이터 평면, DERP, disco(다른 노트).
- 제어 프로토콜 자체(`control-*` 노트). 여기서는 `/machine/set-dns` 호출 형태만 적는다.
- OS에 DNS를 쓰는 Linux·Windows 구현(NetworkManager, resolved, NRPT 등), 출구 노드 DNS 프록시(DoH), Taildrive, SSH, Serve/Funnel, 앱 커넥터, 테일넷 락.
- gVisor 내부(기준 소스에 gVisor가 없다).

## 3. 와이어 형식과 저장 형식

### 3.1 [1부] DNS 메시지 — 로컬 응답 형식

리졸버는 RFC 1035 메시지를 받아 `golang.org/x/net/dns/dnsmessage`로 파싱한다. 첫 질문 하나만 읽는다(`tailscale.com/net/dns/resolver/tsdns.go:1020-1033`).

헤더 규칙(로컬에서 만든 응답)

| 필드 | 값 | 출처 |
| --- | --- | --- |
| ID, RD, 기타 헤더 비트 | 질의 헤더를 복사 | `tailscale.com/net/dns/resolver/tsdns.go:1009-1011` |
| QR | 1 | `tailscale.com/net/dns/resolver/tsdns.go:1204` |
| AA | 1 | `tailscale.com/net/dns/resolver/tsdns.go:1205` |
| RA | 질의 RD가 1일 때만 1 | `tailscale.com/net/dns/resolver/tsdns.go:1206-1208` |
| RCODE | 아래 RCODE 표 | |
| 질문 구역 | 질의의 질문 그대로(성공이거나 질문 타입이 0이 아닐 때) | `tailscale.com/net/dns/resolver/tsdns.go:1222-1232` |
| 추가(additional) 구역 | 만들지 않는다. 질의의 EDNS OPT 레코드를 응답에 싣지 않는다. | `tailscale.com/net/dns/resolver/tsdns.go:1203-1287` |

답변 레코드

| 타입 | 이름 | 클래스·TTL | RDATA | 출처 |
| --- | --- | --- | --- | --- |
| A | 질문 이름 그대로 | IN, 5초 | IPv4 4바이트 | `tailscale.com/net/dns/resolver/tsdns.go:58`, `:1037-1049` |
| AAAA | 질문 이름 그대로 | IN, 5초 | IPv6 16바이트 | `tailscale.com/net/dns/resolver/tsdns.go:1053-1065` |
| PTR | 질문 이름 그대로 | IN, 5초 | 노드 FQDN(끝 점 포함) | `tailscale.com/net/dns/resolver/tsdns.go:1079-1094` |
| SOA | 권한 있는 영역(`LocalDomains`의 접미사) | IN, 10초 | NS·MBOX는 영역 이름, Serial은 현재 유닉스 초, Refresh·Retry·Expire·MinTTL은 모두 10 | `tailscale.com/net/dns/resolver/tsdns.go:68`, `:1177-1199` |

- A·AAAA 질의에 대해 답변 RR은 최대 하나다. `respond`는 `resp.IP`만 채우고 `resp.IPs`는 채우지 않는다(`tailscale.com/net/dns/resolver/tsdns.go:1483-1485`). 노드가 여러 주소를 가져도 질의 타입에 맞는 첫 주소 하나만 나간다(`tailscale.com/net/dns/resolver/tsdns.go:791-809`).
- SOA는 부정 응답에만 붙는다: NXDOMAIN, 그리고 A/AAAA/ANY 질의에서 이름은 있으나 해당 타입 주소가 없는 NOERROR(`tailscale.com/net/dns/resolver/tsdns.go:1486-1496`). 영역을 찾지 못하면(`authoritativeZoneFor`가 빈 값) 붙이지 않는다(`tailscale.com/net/dns/resolver/tsdns.go:1405-1414`, `:1236`, `:1277`).
- 상징 이름: `magicdns.localhost-tailscale-daemon.`의 A는 `100.100.100.100`, AAAA는 `fd7a:115c:a1e0::53`(`tailscale.com/net/dns/resolver/tsdns.go:45`, `:736-743`). 서비스 IP의 PTR은 이 이름을 돌려준다(`tailscale.com/net/dns/resolver/tsdns.go:939-941`).

RCODE 규칙(로컬 판단)

| 상황 | 결과 | 출처 |
| --- | --- | --- |
| 헤더·질문 파싱 실패, 질의가 QR=1, 이름이 유효한 FQDN이 아님 | FORMERR 응답(질문 구역 없음) | `tailscale.com/net/dns/resolver/tsdns.go:1447-1469`, `:1028-1030` |
| 이름이 `.onion` 접미사 | NXDOMAIN | `tailscale.com/net/dns/resolver/tsdns.go:727-731` |
| 이름을 호스트 표·MagicDNS 색인·서브도메인 규칙으로 찾지 못함, 그러나 `LocalDomains` 접미사 안 | NXDOMAIN + SOA | `tailscale.com/net/dns/resolver/tsdns.go:772-779` |
| 이름을 찾지 못함, `LocalDomains` 밖 | 로컬 답 없음. 업스트림으로 전달(4.1.5) | `tailscale.com/net/dns/resolver/tsdns.go:780-783`, `:1478-1481` |
| 찾았고 A: v4 있음 / 없음 | A 1개 / NOERROR 빈 답 + SOA | `tailscale.com/net/dns/resolver/tsdns.go:792-800` |
| 찾았고 AAAA: v6 있음 / 없음 | AAAA 1개 / NOERROR 빈 답 + SOA | `tailscale.com/net/dns/resolver/tsdns.go:801-809` |
| 찾았고 ANY(255) | 첫 주소 1개(A 또는 AAAA), 주소가 없으면 NOERROR 빈 답 | `tailscale.com/net/dns/resolver/tsdns.go:810-820` |
| 찾았고 NS·SOA·AXFR·HINFO | NOTIMP | `tailscale.com/net/dns/resolver/tsdns.go:824-826` |
| 찾았고 그 밖의 타입 | NOERROR 빈 답 | `tailscale.com/net/dns/resolver/tsdns.go:834-837` |
| PTR을 찾지 못함, `LocalDomains` 접미사 안 | NXDOMAIN + SOA | `tailscale.com/net/dns/resolver/tsdns.go:947-953`, `:1427-1429` |
| 업스트림이 없는 이름 | SERVFAIL(AA=1, 질문 포함) | `tailscale.com/net/dns/resolver/forwarder.go:1316-1336`, `:1534-1552` |
| Bonjour 서비스 탐색 PTR 이름(첫 레이블이 b, db, r, dr, lb 중 하나이고 뒤가 `_dns-sd._udp.`). 로컬 판단은 건너뛰고 전달 단계에서 | NXDOMAIN(RA=RD), 업스트림으로 보내지 않음 | `tailscale.com/net/dns/resolver/tsdns.go:1417-1420`, `tailscale.com/net/dns/resolver/forwarder.go:1296-1308`, `:1510-1531` |

TCP 프레임(`HandleTCPConn`): 2바이트 빅엔디언 길이 + DNS 메시지. 한 연결에서 여러 질의를 받고 응답 순서는 보장하지 않는다(`tailscale.com/net/dns/manager.go:731-738`, `:757-799`).

### 3.2 [2부] 상태 파일 형식(FileStore)

- 파일은 JSON 객체 하나다. 키는 `StateKey` 문자열, 값은 Go의 `[]byte`이므로 JSON에서 base64 문자열이다(표준 base64, `encoding/json`의 `[]byte` 규칙). 타입이 `map[ipn.StateKey][]byte`다(`tailscale.com/ipn/store/stores.go:145-150`). 쓸 때마다 들여쓰기 2칸 `MarshalIndent`로 통째로 다시 쓰고(`tailscale.com/ipn/store/stores.go:222`), 임시 파일에 쓰고 `Sync` 후 이름을 바꾸는 방식으로 권한 0600 파일을 교체한다(`tailscale.com/ipn/store/stores.go:226`, `tailscale.com/atomicfile/atomicfile.go:21-51`). 디렉터리는 0700이다(`tailscale.com/paths/paths.go:147-151`).
- 파일이 없거나 비어 있으면 `{}`를 써서 쓰기 가능 여부를 확인한 뒤 시작한다(`tailscale.com/ipn/store/stores.go:164-186`).
- `WriteState(key, nil)`은 키 삭제다(`tailscale.com/ipn/store.go:95-102`, `tailscale.com/ipn/store/stores.go:217-219`). 같은 값이면 쓰지 않는다(`tailscale.com/ipn/store/stores.go:214-216`).
- `tsnet`은 `Dir/tailscaled.state`에 FileStore를 만든다(`tailscale.com/tsnet/tsnet.go:965-972`). 메모리 저장소는 Ephemeral 노드에만 허용한다(`tailscale.com/tsnet/tsnet.go:849-854`).

저장되는 키(단일 사용자 Unix 계열 기준)

| 키 | 값 | 출처 |
| --- | --- | --- |
| `_machinekey` | 머신 개인키 텍스트 `privkey:` + 소문자 hex 64자(32바이트) | `tailscale.com/ipn/store.go:24`, `tailscale.com/types/key/machine.go:24`, `:76-78`, `tailscale.com/types/key/node.go:116-118` |
| `_current-profile` | 현재 프로필의 `StateKey` 문자열(예: `profile-3fa2`) | `tailscale.com/ipn/store.go:55-57`, `:82-87`, `tailscale.com/ipn/ipnlocal/profiles.go:657-667` |
| `_profiles` | JSON 객체 `{프로필ID: LoginProfile}` | `tailscale.com/ipn/store.go:51-53`, `tailscale.com/ipn/ipnlocal/profiles.go:819-826` |
| `profile-<id>` | 그 프로필의 `Prefs` JSON(탭 들여쓰기). `<id>`는 난수 2바이트의 hex 4자 | `tailscale.com/ipn/ipnlocal/profiles.go:494-504`, `:563-572`, `tailscale.com/ipn/prefs.go:650-656` |
| `_daemon` | 프로필 도입 이전의 단일 상태. 프로필이 없을 때 한 번 읽어 이주하고 지우지 않는다. iOS·샌드박스 macOS는 `ipn-go-bridge`를 읽는다 | `tailscale.com/ipn/store.go:26-40`, `tailscale.com/ipn/ipnlocal/profiles_notwindows.go:15-30` |

이 밖에 `server-mode-start-key`(Windows용, `tailscale.com/ipn/store.go:42-49`)와 `_taildrop-received`(`tailscale.com/ipn/store.go:59-62`)가 있으나 Swiftail은 쓰지 않는다.

`LoginProfile` JSON 필드: `ID`, `Name`, `NetworkProfile`, `Key`, `UserProfile`, `NodeID`, `LocalUserID`, `ControlURL`, `Created`(0이면 생략) (`tailscale.com/ipn/prefs.go:1077-1124`).

`Prefs` JSON에서 `Persist`는 `Config`라는 이름으로 들어간다(`tailscale.com/ipn/prefs.go:314-319`). `Persist` 필드(`tailscale.com/types/persist/persist.go:20-38`):

| 필드 | 형식 |
| --- | --- |
| `PrivateNodeKey` | 노드 개인키 텍스트 `privkey:` + hex 64자 (`tailscale.com/types/key/node.go:29`, `:116-118`) |
| `OldPrivateNodeKey` | 같은 형식. 키 교체 요청에 필요(없으면 영값) |
| `UserProfile` | `tailcfg.UserProfile` |
| `NetworkLockKey` | `nlpriv:` + hex (`tailscale.com/types/key/nl.go:18`) |
| `NodeID` | `tailcfg.StableNodeID` 문자열 |
| `AttestationKey` | 하드웨어 증명 키. 생략 가능 |
| `DisallowedTKAStateIDs` | 문자열 배열. 생략 가능 |

### 3.3 [3부] 인증서 저장 형식

인증서는 `tailscaled.state` 안에 넣지 않고 `<varRoot>/certs/` 디렉터리 파일로 둔다(`tsnet`은 `Dir`를 varRoot로 설정, `tailscale.com/tsnet/tsnet.go:984`).

| 파일 | 내용 | 권한 | 출처 |
| --- | --- | --- | --- |
| `<도메인>.key` | 인증서 개인키, PEM `EC PRIVATE KEY`(SEC1, P-256) | 0600 | `tailscale.com/feature/acme/certstore.go:160-162`, `:284-286`, `tailscale.com/feature/acme/certstore.go:323-330` |
| `<도메인>.crt` | 인증서 체인, PEM `CERTIFICATE` 블록 나열 | 0644 | `tailscale.com/feature/acme/certstore.go:156-158`, `:287-289`, `tailscale.com/feature/acme/cert.go:600-606` |
| `acme-account.key.pem` | ACME 계정 키, PEM ECDSA P-256 | 0600 | `tailscale.com/feature/acme/certstore.go:116-133`, `:361-389` |

와일드카드 도메인의 `*.`는 파일명에서 `wildcard_.`로 바뀐다(`tailscale.com/feature/acme/certstore.go:284-289`).

## 4. 절차와 상태 기계

### 4.1 [1부] MagicDNS

#### 4.1.1 `DNSConfig` 입력과 `dnsConfigForNetmap` 규칙

`tailcfg.DNSConfig` 필드(`tailscale.com/tailcfg/tailcfg.go:1788-1854`): `Resolvers`(`:1790`), `Routes`(맵, 접미사 → 리졸버 목록; 빈 목록은 "100.100.100.100이 직접 처리"라는 뜻, `:1802`), `FallbackResolvers`(`:1808`), `Domains`(검색 도메인, 끝 점 없음, `:1811`), `Proxied`(MagicDNS 켜짐, `:1816`), `Nameservers`(Version 9 이상 14 미만 전용, 폐기, `:1821`), `CertDomains`(`:1829`), `ExtraRecords`(`:1833`). `DNSRecord`는 `Name`, `Type`(비어 있으면 A/AAAA), `Value`(IP 문자열)이다(`tailscale.com/tailcfg/tailcfg.go:1857-1872`). `dnstype.Resolver`는 `Addr`(IP, IP:포트, `https://…`, `http://…`), `BootstrapResolution`, `UseWithExitNode`다(`tailscale.com/types/dnstype/dnstype.go:15-43`).

`dnsConfigForNetmap(nm, peers, prefs, selfExpired, logf, goos)`가 `dns.Config`를 만든다(`tailscale.com/ipn/ipnlocal/node_backend.go:1435-1680`). 호출은 `authReconfig`에서 일어난다(`tailscale.com/ipn/ipnlocal/local.go:6240`).

1. `nm`이 nil이면 nil(`:1436-1438`). 자기 노드 키가 만료(`selfExpired`)면 빈 `Config`(`:1451-1453`). 주석은 이때 quad-100도 답을 멈춘다고 하지만(`:1448-1449`), `resolveLocal`은 MagicDNS 색인을 설정과 무관하게 조회한다(`tailscale.com/net/dns/resolver/tsdns.go:756-759`). 실제 동작은 8장에 둔다.
2. `AcceptDNS = prefs.CorpDNS`, `Routes`·`Hosts`는 빈 맵으로 시작(`:1455-1459`).
3. 자신이 IPv6 주소만 가지면 `OnlyIPv6 = true`(`:1461-1467`). 자기 노드의 `AllCaps`에 `nodecap.MagicDNSPeerAAAA`가 있으면 피어 AAAA를 허용한다(`:1468-1470`).
4. 노드 이름→주소 표는 `Hosts`에 넣지 않는다. Windows에서만 모든 노드를 `Hosts`에 넣는다(`:1472-1496`). `Hosts`에는 `DNS.ExtraRecords`만 들어간다: `Type`이 `""`, `"A"`, `"AAAA"`인 레코드만, `Value`를 IP로 파싱하고 `Name`을 FQDN으로 바꿀 수 있을 때만 쓴다. 같은 이름의 주소는 이어 붙인다(`:1497-1521`).
5. `CorpDNS`가 꺼져 있으면 여기서 반환한다. 즉 검색 도메인·라우트·기본 리졸버가 없는 `Config`이고 `Hosts`(ExtraRecords)만 있다(`:1523-1525`).
6. `Domains`의 각 항목을 FQDN으로 바꿔 `SearchDomains`로 둔다. 변환 실패 항목은 버린다(`:1527-1538`).
7. `Proxied`(MagicDNS)가 켜져 있으면 `magicDNSRootDomains(nm)`의 각 이름을 `Routes[이름] = nil`로 둔다(`:1539-1542`). 끄면 `MagicDNSHostsUnrouted = SelfNode.Valid()`(`:1543-1551`).
8. 기본 리졸버: `nm.DNS.Resolvers`가 비어 있지 않으면 `DefaultResolvers`(`:1640-1641`). 비면 WireGuard 출구 노드의 리졸버(`:1642-1646`, 함수 `tailscale.com/ipn/ipnlocal/local.go:8077`). 출구 노드가 DoH 프록시를 할 수 있으면 그쪽이 우선한다(`:1619-1635`).
9. 분할 DNS: `nm.DNS.Routes`의 각 `(접미사, 리졸버 목록)`을 `Routes[FQDN] = 복제본`으로 넣는다. 빈 목록도 항목을 만든다(권한 있는 영역, 이슈 2706, `:1557-1577`, `:1649`).
10. 라우트가 없는 `ExtraRecords` 이름마다 `Routes[이름] = nil`을 추가해 "이 이름은 quad-100이 답한다"고 표시한다(`:1579-1605`, `:1651`).
11. 출구 노드가 설정돼 있는데 기본 리졸버가 없으면 `FallbackResolvers`를 기본으로 쓴다(`:1657-1677`).

`magicDNSRootDomains`: `MagicDNSSuffix`(자기 노드 이름의 첫 레이블을 떼고 앞뒤 점을 뗀 값), `0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.`, `64.100.in-addr.arpa.`부터 `127.100.in-addr.arpa.`까지 64개(`tailscale.com/ipn/ipnlocal/local.go:6665-6687`, `tailscale.com/types/netmap/netmap.go:256-270`). 역방향 영역이 CGNAT 100.64.0.0/10 전체를 덮는다.

주요 `dns.Config` 필드(`tailscale.com/net/dns/config.go:28-72`): `AcceptDNS`, `DefaultResolvers`, `Routes`, `SearchDomains`, `Hosts`, `SubdomainHosts`, `OnlyIPv6`, `MagicDNSHostsUnrouted`. 이 버전의 `dnsConfigForNetmap`은 `SubdomainHosts`를 채우지 않고(`tailscale.com/ipn/ipnlocal/node_backend.go:1435-1680`), `compileConfig`가 값을 그대로 복사할 뿐이다(`tailscale.com/net/dns/manager.go:339`). 저장소 전체에서 이 필드에 값을 넣는 다른 코드는 찾지 못했다. 서브도메인 해석은 노드의 `DNSSubdomainResolve` 능력(`nodecap.DNSSubdomainResolve`)으로만 일어난다(`tailscale.com/ipn/ipnlocal/node_backend.go:1246-1260`).

#### 4.1.2 노드 이름 조회(주문형 호스트 표)

v1.104.6은 노드별 레코드를 `Config.Hosts`로 밀어 넣지 않고 리졸버가 질의 때 `MagicDNSHosts` 인터페이스로 가져간다(`tailscale.com/net/dns/resolver/tsdns.go:253-300`, 설치 `tailscale.com/ipn/ipnlocal/local.go:647-651`). Swiftail 리졸버도 이 방식으로 만든다.

- `LookupHost(fqdn)`: `nodeByFQDN`으로 노드를 찾고(`tailscale.com/ipn/ipnlocal/node_backend.go:1198-1218`). 이름은 소문자화하고 끝 점을 뗀 값으로 `nodeByName`을 조회한다. MagicDNS가 꺼져 있으면(`!DNS.Proxied`) 점이 없는 짧은 이름은 찾지 않는다(`:1266-1284`).
- `nodeByName`의 키: 노드 `Name`의 FQDN(끝 점 없음, 소문자)과, `MagicDNSSuffix`가 붙어 있으면 그것을 뗀 짧은 이름(`:779-787`). 다른 노드가 이미 같은 키를 가졌으면 지울 때 건드리지 않는다(`:791-802`). 자기 노드와 모든 피어가 대상이다(`:807-838`).
- 주소 선택 `magicDNSAddrs`(`:1299-1329`): 자신이 IPv6 전용이면 대상의 IPv6 주소 전부. 그 외에는 대상에 IPv4가 있고 피어 AAAA 능력(`wantAAAA`)이 없으면 IPv6를 제외하고 나머지 주소 전부. 결과가 비어도 "이름은 있음"이다.
- `LookupPTR(ip)`: `nodeByAddr[ip]`의 노드 이름(FQDN)(`:1222-1241`). `nodeByAddr`는 노드 자신의 주소만 담는다(서브넷 라우트 제외, `:119-121`).
- `ExtraRecords`: 리졸버의 `Hosts`가 먼저 조회된다(`tailscale.com/net/dns/resolver/tsdns.go:756-758`). 별도로 `extraDNS`(Type이 빈 문자열인 레코드만)는 `Dial`의 이름 해석에 쓰인다(`tailscale.com/ipn/ipnlocal/node_backend.go:828-852`).
- 서브도메인: 호스트 표에 없으면 이름의 부모를 하나씩 올라가며 `SubdomainHosts` 포함 여부 또는 `SubdomainHost(parent)`(노드가 `DNSSubdomainResolve` 능력을 가짐)를 검사해 부모의 주소를 그대로 답한다(`tailscale.com/net/dns/resolver/tsdns.go:760-771`).

`CertDomains`는 DNS 응답에 쓰이지 않는다. 인증서 발급 대상 목록으로만 쓴다(4.3.5).

#### 4.1.3 `dns.Manager`의 설정 계산

`Manager.Set(cfg)`가 `compileConfig`로 (`resolver.Config`, `OSConfig`)를 만든다(`tailscale.com/net/dns/manager.go:201-236`, `:334-526`).

공통(`:335-353`): `rcfg.Hosts`, `SubdomainHosts`, `AcceptDNS`는 그대로. `Routes` 중 리졸버가 없는 접미사는 `rcfg.LocalDomains`(정렬)로 가고, 나머지는 포워더 라우트다. `LocalDomains`에 속한 이름은 호스트 표에 없으면 NXDOMAIN이 된다(3.1).

`OSConfig`(`tailscale.com/net/dns/osconfig.go:55-80`): `Hosts`(Windows 전용), `Nameservers`, `SearchDomains`, `MatchDomains`, `Resolvers`(입력 전용).

| 조건 (위에서부터) | 결과 | 출처 |
| --- | --- | --- |
| OS 리졸버가 필요 없음(`DefaultResolvers`도 `Routes`도 없음) | `SearchDomains`만 설정. 리졸버 라우트 없음 | `tailscale.com/net/dns/manager.go:373-377`, `tailscale.com/net/dns/config.go:110-118` |
| 기본 리졸버가 모두 IP:53이고 라우트가 없고, 라우트로 덮이지 않는 호스트가 없음 | OS 네임서버를 그 IP들로 직접 설정 | `tailscale.com/net/dns/manager.go:378-390`, `tailscale.com/net/dns/config.go:123-151` |
| 기본 리졸버가 있음(그 밖의 경우) | 네임서버 = quad-100. 리졸버 라우트 = 분할 라우트 + `"." = DefaultResolvers` | `tailscale.com/net/dns/manager.go:391-397` |
| 분할 DNS(기본 리졸버 없음). OS가 분할 DNS를 지원하고 Windows·샌드박스 Apple이 아니며 모든 분할 라우트가 같은 IP 리졸버 | 네임서버 = 그 IP들, `MatchDomains` = 라우트 접미사. quad-100을 거치지 않음 | `tailscale.com/net/dns/manager.go:421-429` |
| 분할 DNS, 그 밖의 경우 | 네임서버 = `serviceIPs`, 리졸버 라우트 = 분할 라우트 | `tailscale.com/net/dns/manager.go:431-435` |

- `serviceIPs`: `OnlyIPv6`면 `fd7a:115c:a1e0::53`만. 아니면 기본은 `100.100.100.100`과 `fd7a:115c:a1e0::53` 둘 다이고, 제어 서버의 `ShouldForceRegisterMagicDNSIPv4Only` 노브가 켜져 있으면 IPv4만(`tailscale.com/net/dns/config.go:79-94`).
- `MatchDomains`는 `Routes` 키를 끝 점 포함 문자열 순으로 정렬한 목록이다(`tailscale.com/net/dns/config.go:231-241`).
- 검색 도메인은 제어 서버가 준 순서 그대로 둔다. 분할 DNS 접미사는 검색 도메인에 더하지 않는다(`tailscale.com/net/dns/manager.go:361-366`).

darwin·ios 분기

- `goos == "ios"`면 `isIOS`, `darwin`이고 `version.IsSandboxedMacOS()`면 `isSandboxedMac`(`tailscale.com/net/dns/manager.go:355-359`). 샌드박스 Apple은 분할 DNS를 OS에 직접 맡기지 않는다(`:421`).
- Apple 터널은 `NEDNSSettings.searchDomains`가 `configd`에서 제거되므로 전역 검색 도메인을 `matchDomains`(`matchDomainsNoSearch=false`)로만 줄 수 있다. 그래서 단순한 설정(모드 A)만 `MatchDomains`로 범위를 좁히고, 나머지는 quad-100을 기본 리졸버로 설치한다(모드 B)(`tailscale.com/net/dns/manager.go:436-445`).
- 범위 지정 조건(iOS는 기본 켜짐, 제어 노브 `DisableSplitDNSWhenNoCustomResolvers`로 끔. 샌드박스 macOS는 `NodeAttrScopeQuad100OnMacOS` 능력 또는 환경 변수가 있을 때만): 모든 라우트가 커스텀 리졸버 없이 quad-100이 직접 답하는 형태(`RoutesRequireNoCustomResolvers`, `ts.net` 라우트는 무시)이고, `requiresPrimaryResolver`가 거짓(라우트로 덮이지 않는 호스트 없음)이고, `Hosts`의 모든 PTR 이름이 라우트로 덮여야 한다(`tailscale.com/net/dns/manager.go:446-449`, `:557-573`, `tailscale.com/net/dns/resolver/tsdns.go:209-226`, `tailscale.com/net/dns/config.go:153-189`).
- iOS는 범위 지정이어도 기본 설정을 다시 읽는다(직접 quad-100에 온 질의를 하위 리졸버로 전달하려고). 읽기 실패 `ErrGetBaseConfigNoResolvers`는 비-Apple에서만 재시도 루프를 돌리고(1초 간격, 2배씩, 6회), Apple은 OS가 알려줄 때 `RecompileDNSConfig`를 다시 부른다(`tailscale.com/net/dns/manager.go:451-512`, `:53-56`, `:575-619`).
- 모드 B에서는 OS 기본 리졸버(`GetBaseConfig`)를 `rcfg.Routes["."]`로 쓰고, 그 검색 도메인을 뒤에 이어 붙인다(`tailscale.com/net/dns/manager.go:515-523`, `:537-555`).
- 이 소스에서 iOS의 `OSConfigurator`를 주입하는 쪽은 `wgengine.Config.DNS`이며 비어 있으면 아무것도 하지 않는 구현을 쓴다(`tailscale.com/wgengine/userspace.go:330-337`, `tailscale.com/net/dns/noop.go:7-20`). `NEDNSSettings` 변환은 앱 쪽 코드이므로 소스에 없다.
- `manager_darwin.go`의 `darwinConfigurator`는 macOS용(`/etc/resolver`, `scutil`)이다(`tailscale.com/net/dns/manager_darwin.go:29-48`). iOS 패킷 터널에서 쓰지 않는다.

#### 4.1.4 리졸버의 질의 처리 절차

진입점 `Manager.Query` → `Resolver.Query`(`tailscale.com/net/dns/manager.go:652-676`, `tailscale.com/net/dns/resolver/tsdns.go:408-439`).

1. 동시 질의 256개를 넘으면 거부한다(`tailscale.com/net/dns/manager.go:60`, `:660-664`).
2. `respond`(`tailscale.com/net/dns/resolver/tsdns.go:1437-1499`): 파싱 → 이름 소문자화 → PTR이면 역방향 처리, 아니면 `resolveLocal`.
3. `resolveLocal` 순서(`tailscale.com/net/dns/resolver/tsdns.go:725-839`): `.onion` → 상징 이름 → 4via6 이름 → 호스트 표(`Hosts` → `MagicDNSHosts.LookupHost`) → 서브도메인 규칙 → 영역 판정 → 타입별 결과.
4. 4via6 이름: `<IPv4를 하이픈으로 이은 값>-via-<사이트ID>[.ts.net 또는 .tailscale.net 이하]`. A 질의는 이름이 있다는 의미의 빈 NOERROR, AAAA/ANY는 `MapVia(사이트ID, IPv4/32)`의 IPv6 주소(`tailscale.com/net/dns/resolver/tsdns.go:850-900`).
5. 역방향(`tailscale.com/net/dns/resolver/tsdns.go:903-958`, `:1416-1433`): `*.in-addr.arpa.`와 `*.ip6.arpa.`(32니블)만 파싱한다. 파싱에 실패하면 로컬 답 없음(전달). IPv6 4-to-6 범위면 대응하는 IPv4를 먼저 조회한다. 서비스 IP는 상징 이름. 그 외는 `Hosts`의 역방향 맵 → `LookupPTR`. 못 찾으면 `LocalDomains` 안이면 NXDOMAIN, 밖이면 전달. Bonjour 서비스 탐색 PTR(`b|db|r|dr|lb._dns-sd._udp.…`)은 로컬에서 답하지 않고 전달 경로로 보낸다(`tailscale.com/net/dns/resolver/tsdns.go:1294-1316`, `:1417-1420`).
6. 로컬 응답이 만들어지면 UDP일 때 `checkResponseSizeAndSetTC`로 크기를 검사한다(4.1.6).

#### 4.1.5 모르는 이름의 전달 규칙

- 로컬 답이 없으면 `forwardWithDestChan`으로 넘긴다. 질의 전체 제한 시간은 10초(`tailscale.com/net/dns/resolver/tsdns.go:403-406`, `:420-431`).
- 라우트 선택: 라우트를 접미사 레이블 수가 많은 순서로 정렬하고(`tailscale.com/net/dns/resolver/forwarder.go:491-494`), 질의 이름을 포함하는 첫 라우트를 쓴다. `"."`은 모든 이름과 일치한다(`tailscale.com/net/dns/resolver/forwarder.go:1180-1200`).
- 질의 전달 전 처리: Bonjour 역방향 이름은 NXDOMAIN으로 즉시 응답, EDNS OPT의 광고 UDP 크기를 4095로 깎는다(4.1.6), 라우트의 리졸버가 없으면 SERVFAIL(`tailscale.com/net/dns/resolver/forwarder.go:1292-1336`).
- 리졸버 목록은 동시에 모두 질의하고 먼저 온 응답을 쓴다. 시작 지연: 알려진 공개 DNS의 DoH는 즉시, 같은 제공자의 평문 UDP는 500ms 뒤, 같은 제공자의 두 번째 IP는 200ms 더 뒤(`tailscale.com/net/dns/resolver/forwarder.go:96-104`, `:383-443`, `:1358-1383`).
- 오류 집계: 모든 리졸버가 REFUSED면 그 응답을 돌려준다. 하나라도 SERVFAIL이나 전송 오류면 업스트림 SERVFAIL 또는 합성 SERVFAIL을 돌려준다(`tailscale.com/net/dns/resolver/forwarder.go:1403-1459`).
- 업스트림 전송(`tailscale.com/net/dns/resolver/forwarder.go:683-810`): `http://`는 PeerAPI DoH, `https://`는 DoH(알려진 공개 IP나 `BootstrapResolution`이 있을 때만), `tls://`는 미지원, 그 밖에는 UDP. 클라이언트 질의가 UDP면 UDP를 먼저 보내고 2초 안에 답이 없으면 TCP를 함께 시작한다. 클라이언트 질의가 TCP면 UDP가 잘렸을 때 TCP로 재시도한다. TCP 질의 제한 시간은 5초다(`tailscale.com/net/dns/resolver/forwarder.go:108-112`, `:728-810`).
- 업스트림 소켓(UDP): 업스트림 IP가 테일넷 경로(`UseNetstackForIP`)면 netstack UDP로 보낸다. 아니면 `packetListener`가 `PickLink`의 인터페이스 이름을 본다. 이름이 있으면(업스트림이 터널 위에 있을 때, macOS는 루프백이면 `lo0`) 그 인터페이스 인덱스에 결속하고(`ts_macext` 빌드에서만), 이름이 비어 있으면 결속하지 않은 일반 UDP 소켓이다. 이 경로에는 `netns` 호출이 없다(`tailscale.com/net/dns/resolver/forwarder.go:503-523`, `:958-1000`, `tailscale.com/net/dns/resolver/macios_ext.go:14-26`, `tailscale.com/wgengine/userspace.go:1533-1544`).
- 업스트림 소켓(TCP): `ShouldUseRoutes`가 참이면 `UserDial`, 아니면 `SystemDial`(netns 결속)이다. iOS와 Android에서는 제어의 `user-dial-routes` 능력이 있을 때만 참이다(`tailscale.com/net/dns/resolver/forwarder.go:1038-1042`, `:1002-1036`).

#### 4.1.6 UDP 크기·잘림·EDNS

- 로컬 응답의 UDP 검사 `checkResponseSizeAndSetTC`(`tailscale.com/net/dns/resolver/forwarder.go:220-261`): 질의에 유효한 EDNS OPT가 없으면 512바이트 초과 시, 있으면 광고된 크기 초과 시 응답의 TC 비트를 켠다. 응답을 자르지는 않는다. TCP 질의는 검사하지 않는다.
- OPT 인식 조건 `findOPTRecord`: 메시지의 마지막 11바이트가 OPT 레코드(NAME=0, TYPE=41, RDLEN=0, 버전 0)이고 additional 개수가 0이 아닐 것(`tailscale.com/net/dns/resolver/forwarder.go:148-191`). 옵션 코드가 하나라도 있으면 EDNS로 인식하지 않는다.
- `clampEDNSSize`: 질의가 광고한 UDP 크기가 4095보다 크면 4095로 고쳐 업스트림에 보낸다(`tailscale.com/net/dns/resolver/forwarder.go:193-210`, `tailscale.com/net/dns/resolver/tsdns.go:50`).
- 업스트림 UDP 응답 버퍼는 4096바이트. 4095바이트를 넘으면 잘라 TC를 켠다(`tailscale.com/net/dns/resolver/forwarder.go:868-941`).
- 로컬 응답은 OPT 없이 나간다(3.1). 로컬 응답은 레코드가 최대 1개라 512바이트를 넘지 않는다.
- UDP 질의에 대한 응답이 TC이면 그대로 클라이언트에 돌려준다. 클라이언트가 TCP로 다시 물어야 한다(`tailscale.com/net/dns/resolver/forwarder.go:757-764`).

#### 4.1.7 quad-100 패킷이 리졸버에 닿는 경로

OS가 `100.100.100.100`이나 `fd7a:115c:a1e0::53`으로 보낸 패킷이 TUN에서 나와 리졸버까지 가는 경로(`wgengine/netstack`).

1. `netstack.Create`가 TUN 래퍼의 "WireGuard로 나가는 패킷 사전 필터"에 `handleLocalPackets`를 건다(`tailscale.com/wgengine/netstack/netstack.go:466`).
2. `handleLocalPackets`는 목적지가 두 서비스 IP이면 프로토콜·포트와 무관하게 패킷을 netstack으로 흡수하고(`DropSilently`) WireGuard 쪽으로 보내지 않는다. 피어가 없어 로그가 지저분해지고 quad-100 트래픽이 테일넷으로 새는 것을 막으려는 것이다(`tailscale.com/wgengine/netstack/netstack.go:866-897`, `:964-969`).
3. 스택 구성: IPv4·IPv6, TCP·UDP·ICMPv4·ICMPv6, NIC 1개를 프로미스큐어스로 두고 IPv4·IPv6 기본 경로를 모두 이 NIC로 보낸다(`tailscale.com/wgengine/netstack/netstack.go:388-391`, `:436-464`). TCP·UDP 포워더로 새 흐름마다 핸들러를 부른다(`:669-672`).
4. UDP: 목적지가 서비스 IP이고 포트 53이면 `handleMagicDNSUDP`. 읽기 제한 150ms의 루프로 같은 소켓의 여러 질의를 처리하고 각각 `Manager.Query(…, "udp", 발신지)` 결과를 되돌려 쓴다(`tailscale.com/wgengine/netstack/netstack.go:2036-2041`, `:2080-2113`). 다른 포트는 엔드포인트를 닫고 응답하지 않는다(ICMP도 보내지 않는다)(`:2000-2011`, `:2042-2051`).
5. TCP: 서비스 IP의 포트 53이면 연결을 수락하고 `Manager.HandleTCPConn`으로 넘긴다(`tailscale.com/wgengine/netstack/netstack.go:1723-1734`). 80과 8080(Taildrive)은 `TCPHandlerForDst`가 처리한다(`tailscale.com/ipn/ipnlocal/netstack.go:21-39`). 그 밖의 포트는 RST로 거부한다(`tailscale.com/wgengine/netstack/netstack.go:1770-1787`).
6. 응답 패킷 방향: gVisor가 낸 패킷의 출발지가 서비스 IP이면 "호스트로" 큐에 넣고 TUN 쓰기(OS로 주입)로 내보낸다. 그 외 출발지는 WireGuard 쪽 큐로 간다(`tailscale.com/wgengine/netstack/netstack.go:1048-1062`, `:1119-1147`, `:1173-1238`).
7. NIC MTU는 `DefaultTUNMTU()`, 환경 변수가 없으면 1280이다. 링크 엔드포인트 큐는 512개다(`tailscale.com/wgengine/netstack/netstack.go:434`, `tailscale.com/net/tstun/mtu.go:77-79`, `:126-142`).

#### 4.1.8 TCP 스택 없이 IP·UDP 패킷을 직접 만들어 답하는 최소 구현이 놓치는 것

아래 항목의 근거는 위 4.1.7이고, "최소 구현" 평가는 설계 판단이다.

| 놓치는 것 | 무엇이 일어나는가 | Tailscale의 동작 |
| --- | --- | --- |
| TCP 53 | 클라이언트가 TC 응답을 받거나 TCP를 택하면 연결이 맺어지지 않아 해석이 실패하거나 지연된다 | 포트 53 TCP를 수락해 `HandleTCPConn`이 길이 접두 프레임으로 처리(`tailscale.com/wgengine/netstack/netstack.go:1724-1733`, `tailscale.com/net/dns/manager.go:757-815`) |
| 그 밖의 서비스 IP TCP 포트 | 조용히 버리면 클라이언트는 타임아웃까지 기다린다 | RST로 즉시 거부(`tailscale.com/wgengine/netstack/netstack.go:1786`) |
| 서비스 IP로 가는 다른 프로토콜·포트 | WireGuard로 새어 나갈 수 있다 | 전부 흡수(`tailscale.com/wgengine/netstack/netstack.go:875-897`) |
| MTU를 넘는 응답 | 업스트림 응답은 최대 4095바이트인데 터널 MTU는 1280이다. 단편화하거나 줄이지 않으면 전송되지 않는다 | gVisor가 IP 계층에서 처리하는지 이 소스로는 확인하지 못했다(8장). 코드 쪽은 TC 비트만 세우고 자르지 않는다(`tailscale.com/net/dns/resolver/forwarder.go:225-226`) |
| IPv6 서비스 주소 | UDP 체크섬이 필수이고 의사 헤더에 128비트 주소가 들어간다(RFC 8200. 이 소스에 없는 일반 규칙) | 스택이 처리 |
| ICMP | 서비스 IP로의 에코·UDP 포트 불가 | UDP는 응답 없음. 에코는 확인하지 못했다(8장) |
| 한 UDP 소켓의 여러 질의 | 문제 없다(패킷 단위로 처리하면 됨) | 150ms 읽기 루프(`tailscale.com/wgengine/netstack/netstack.go:2093-2113`) |
| EDNS OPT 응답 | 필요 없다 | 로컬 응답에 OPT를 싣지 않는다(3.1) |
| 동시 질의 한도 | 한도가 없으면 자원 소진 | 256개(`tailscale.com/net/dns/manager.go:60`) |

### 4.2 [2부] 상태 저장과 신원

#### 4.2.1 시작 시 읽는 순서

1. `_current-profile`을 읽어 현재 프로필 키를 얻는다. Windows는 `server-mode-start-key`를 쓴다(`tailscale.com/ipn/ipnlocal/profiles.go:898-910`).
2. `_profiles`를 읽어 프로필 맵을 만든다. 없으면 빈 맵(`tailscale.com/ipn/ipnlocal/profiles.go:912-926`).
3. 키가 있으면 그 프로필을 찾는다. 키가 없고 프로필도 없으면 `_daemon`(iOS는 `ipn-go-bridge`)에서 이주를 시도한다(`tailscale.com/ipn/ipnlocal/profiles.go:951-967`).
4. 그래도 없으면 새 프로필(저장되지 않은 상태)을 만든다. 새 프로필의 기본 prefs는 `NewPrefs()`에 `LoggedOut=true`, `WantRunning=false`를 더한 값이다(`tailscale.com/ipn/ipnlocal/profiles.go:860-866`, `:968-977`).
5. 프로필 키의 값을 읽어 `Prefs`로 파싱한다. 값이 없거나 비면 기본 prefs. 저장된 `ControlURL`이 구 로그인 서버 동의어면 비운다(`tailscale.com/ipn/ipnlocal/profiles.go:669-721`).
6. `Start`에서 `WantRunning`이면 `_machinekey`를 읽고, 없을 때만 새로 만들어 쓴다. 값이 있는데 영값이거나 파싱할 수 없으면 오류로 멈춘다(`tailscale.com/ipn/ipnlocal/local.go:3206-3211`, `:4619-4651`).

#### 4.2.2 쓰는 시점

- 프로필은 `Persist.NodeID`와 `Persist.UserProfile.LoginName`이 모두 채워질 때까지 디스크에 만들어지지 않는다. 그 전의 prefs 변경은 메모리에만 있다(`tailscale.com/ipn/ipnlocal/profiles.go:350-356`, `:424-429`, `:545-551`). 따라서 첫 로그인이 끝나기 전에 저장소에 남는 것은 `_machinekey`뿐이다.
- 로그인 후: 프로필 ID와 키 생성, `_profiles` 갱신, 프로필 prefs 쓰기, `_current-profile` 쓰기 순서(`tailscale.com/ipn/ipnlocal/profiles.go:411-492`, `:657-667`).
- 같은 노드·사용자의 프로필이 이미 있으면 재사용하고 중복 프로필의 상태는 지운다(`tailscale.com/ipn/ipnlocal/profiles.go:357-373`).
- `Start`는 `Options.UpdatePrefs`가 있으면 저장된 prefs를 `Persist`를 빼고 전부 덮어쓴다(`tailscale.com/ipn/backend.go:685-690`, `tailscale.com/ipn/ipnlocal/local.go:3156-3172`). `tsnet`은 매번 새 `NewPrefs()`에 `Hostname`, `WantRunning=true`, `ControlURL`, `RunWebClient`, `AdvertiseTags`를 채워 넘기므로(`tailscale.com/tsnet/tsnet.go:991-1004`) 이 항목 외의 저장 prefs는 재시작마다 기본값으로 돌아간다.
- 노드 키 교체: 등록 때 `PrivateNodeKey`가 비었거나 재생성이 요청되면 새 키를 만들고 이전 키를 `OldPrivateNodeKey`로 옮긴다. `NetworkLockKey`가 비어 있으면 새로 만든다(`tailscale.com/control/controlclient/direct.go:706-722`).

#### 4.2.3 보존해야 하는 것과 매번 새로 만들어도 되는 것

| 항목 | 구분 | 근거 |
| --- | --- | --- |
| `Persist.PrivateNodeKey` | 반드시 보존. 노드 신원 | 등록 요청이 이 키로 갱신을 시도한다(`tailscale.com/control/controlclient/direct.go:706-722`). 없으면 `hasNodeKeyLocked`가 거짓(`tailscale.com/ipn/ipnlocal/local.go:7003-7008`) |
| `Persist.NodeID`, `UserProfile` | 보존 | 프로필 저장 조건(`tailscale.com/ipn/ipnlocal/profiles.go:352-355`) |
| `_machinekey` | 보존 권장 | 지우고 `Start`하면 새로 만든다(`tailscale.com/ipn/ipnlocal/local.go:4619-4651`, `:4655-4664`). 바꿨을 때 제어 서버가 어떻게 반응하는지는 소스에서 확인하지 못했다 |
| `_profiles`, `_current-profile` | 보존. 없으면 프로필을 못 찾고 새 프로필이 된다 | `tailscale.com/ipn/ipnlocal/profiles.go:951-977` |
| `Persist.NetworkLockKey`, `OldPrivateNodeKey` | 보존(비어 있으면 새로 만들 수 있음) | `tailscale.com/control/controlclient/direct.go:712-722` |
| `Prefs.WantRunning`, `LoggedOut` | 보존하되 `tsnet`식 사용은 시작 때 덮어씀 | 기본 프로필은 `LoggedOut=true`(`tailscale.com/ipn/ipnlocal/profiles.go:860-866`) |
| disco 키 | 매번 새로 만들어도 된다. 프로세스 시작마다 `key.NewDisco()`로 만들고 저장하지 않는다 | `tailscale.com/wgengine/magicsock/magicsock.go:580`. 저장 코드는 찾지 못했다(`NewDisco` 호출은 `newConn`과 `RotateDiscoKey`뿐, `:1256`) |
| netmap 디스크 캐시 | 생략 가능(오프라인 시작 속도용) | `buildfeatures.HasCacheNetMap`로 선택 기능(`tailscale.com/ipn/ipnlocal/diskcache.go:32-65`) |
| 인증서·ACME 계정 키 | 보존하면 재발급을 피한다 | 3.3 |

#### 4.2.4 `ipn.Prefs` 중 내장 노드에 의미 있는 필드

`Prefs` 정의는 `tailscale.com/ipn/prefs.go:59-320`. 기본값 `NewPrefs()`: `CorpDNS=true`, `WantRunning=false`, `NoStatefulFiltering=true`, `AutoUpdate.Check=true`(`tailscale.com/ipn/prefs.go:734-757`). 기본 제어 서버 `https://controlplane.tailscale.com`(`tailscale.com/ipn/prefs.go:42`).

| 필드 | 의미 | 내장 노드 |
| --- | --- | --- |
| `ControlURL` | 제어 서버. 비면 기본값 | 필요 (`tailscale.com/ipn/prefs.go:75`) |
| `Hostname` | 제어 서버에 알리는 호스트 이름 | 필요 (`tailscale.com/ipn/prefs.go:174`) |
| `WantRunning` | 네트워크를 켤지 | 필요. 상태 판정에 직접 쓰임 (`tailscale.com/ipn/prefs.go:150`) |
| `LoggedOut` | 사용자가 로그아웃을 원함 | 필요 (`tailscale.com/ipn/prefs.go:158`) |
| `CorpDNS` | 테일넷 DNS 설정을 적용할지 | 필요 (`tailscale.com/ipn/prefs.go:135`) |
| `ShieldsUp` | 모든 수신 연결 차단 | 선택 (`tailscale.com/ipn/prefs.go:164`) |
| `AdvertiseTags` | ACL 태그 요청 | 선택 (`tailscale.com/ipn/prefs.go:170`) |
| `RouteAll` | 서브넷 라우트 수락 | 선택 (`tailscale.com/ipn/prefs.go:81`) |
| `ProfileName`, `Persist`(`Config`) | 표시 이름, 신원 | `Persist` 필요 (`tailscale.com/ipn/prefs.go:255`, `:319`) |
| `ExitNodeID`, `ExitNodeIP`, `ExitNodeAllowLANAccess`, `AutoExitNode`, `InternalExitNodePrior` | 출구 노드 | 첫 사용처 불필요 |
| `AdvertiseRoutes`, `AdvertiseServices`, `NoSNAT`, `NoStatefulFiltering`, `NetfilterMode`, `NetfilterKind` | 서브넷 라우터·Linux 전용 | 불필요 |
| `RunSSH`, `RunWebClient`, `DriveShares`, `AppConnector`, `PostureChecking`, `RemoteConfig`, `RelayServer*`, `AutoUpdate`, `OperatorUser`, `NotepadURLs`, `ForceDaemon`, `Egg`, `Sync` | 부가 기능·플랫폼 전용 | 불필요 |

`MaskedPrefs`는 필드마다 `<이름>Set` 불리언을 두어 부분 갱신을 표현한다(`tailscale.com/ipn/prefs.go:356-393`, `:417-453`).

#### 4.2.5 `ipn.State`와 전이

값: `NoState`=0, `InUseOtherUser`=1, `NeedsLogin`=2, `NeedsMachineAuth`=3, `Stopped`=4, `Starting`=5, `Running`=6(`tailscale.com/ipn/backend.go:25-35`). `InUseOtherUser`는 `nextStateLocked`가 만들지 않는다(Windows 다중 사용자용).

`nextStateLocked`가 위에서부터 첫 번째로 맞는 규칙을 적용한다(`tailscale.com/ipn/ipnlocal/local.go:7024-7097`).

| 순서 | 조건 | 결과 | 줄 |
| --- | --- | --- | --- |
| 0 | 상태 저장소 초기화 실패 경고가 켜짐 | `NoState` | `:7026-7028` |
| 1 | `WantRunning` 거짓, `LoggedOut` 거짓, 차단 아님, 노드 키 있음 | `Stopped` | `:7048-7049` |
| 2 | netmap 없음, 그리고 (제어 클라이언트가 인증을 계속할 수 없거나 `LoggedOut`) | `NeedsLogin` | `:7050-7055` |
| 3 | netmap 없음, 이전 상태가 `Stopped` | `Starting` | `:7056-7062` |
| 4 | netmap 없음, 이전 상태가 `NoState` | `NoState` | `:7063-7067` |
| 5 | netmap 없음, 이전 상태가 `Starting`/`Running`/`NeedsLogin` | 이전 상태 유지 | `:7068-7069` |
| 6 | netmap 있음, `WantRunning` 거짓 | `Stopped` | `:7074-7075` |
| 7 | 자기 노드 키 만료 | `NeedsLogin` | `:7076-7079` |
| 8 | 자기 노드가 `MachineAuthorized`가 아님 | `NeedsMachineAuth` | `:7080-7082`, `tailscale.com/types/netmap/netmap.go:200-208` |
| 9 | 이전 상태가 `NeedsMachineAuth` | `Starting` | `:7083-7085` |
| 10 | 이전 상태가 `Starting`: `NumLive > 0` 또는 `LiveDERPs > 0` | `Running`, 아니면 `Starting` 유지 | `:7086-7091` |
| 11 | 이전 상태가 `Running` | `Running` | `:7092-7093` |
| 12 | 그 밖 | `Starting` | `:7094-7095` |

- `NumLive`는 마지막 핸드셰이크 시각이 0이 아닌 피어 수, `LiveDERPs`는 활성 DERP 연결 수다(`tailscale.com/ipn/ipnlocal/local.go:4922-4934`). 피어가 하나도 없는 테일넷에서도 DERP 연결이 있으면 `Running`이 된다.
- 만료 판정: netmap의 자기 키 만료 시각이 0이 아니고 현재 시각보다 이르면 만료(`tailscale.com/ipn/ipnlocal/local.go:1925-1929`).
- `Start`는 상태를 `NoState`로 되돌린다(`tailscale.com/ipn/ipnlocal/local.go:3151`).
- 상태 진입 부작용(`enterStateLocked`, `tailscale.com/ipn/ipnlocal/local.go:6910-7000`): 상태가 바뀔 때 `Notify{State}`를 보낸다. `NeedsLogin`은 엔진 갱신을 막고, `NeedsLogin`·`Stopped`·`NoState`는 엔진을 빈 설정으로 되돌린다. `Starting`·`NeedsMachineAuth`는 `authReconfig`를 부르고 `Running`은 대기 중인 인증 URL을 지운다. `Running`을 벗어나면 PeerAPI 리스너를 닫는다.
- 인증 URL은 제어 서버가 준 뒤 6일 23시간까지만 재사용한다(`tailscale.com/ipn/ipnlocal/local.go:4818-4823`).

### 4.3 [3부] 첫 사용처가 쓰는 tsnet 표면(요약)

#### 4.3.1 호출별 요지와 필요한 하위 기능

| 호출 | 구현 요지 | Swift로 다시 만들 때 필요한 하위 기능 |
| --- | --- | --- |
| `Up(ctx)` | `Start()`(1회 초기화) 후 IPN 버스를 `NotifyInitialState`로 구독하고 `State == Running`인 알림이 오면 `Status`를 읽어 반환. `ErrMessage`가 오면 실패, `Running`인데 IP가 없으면 실패. `NeedsLogin`·`NeedsMachineAuth`에서는 실패하지 않고 계속 기다림. 첫 `Up`에서 저장된 serve 설정과 `AdvertiseServices`를 비운다(`tailscale.com/tsnet/tsnet.go:573-636`) | 상태 머신과 알림 스트림, `Status` 스냅샷 |
| `start()` | 상태 디렉터리 → 로거 → `netmon` → `tsdial.Dialer` → 엔진(가짜 TUN) → netstack(`ProcessLocalIPs`·`ProcessSubnets` 켜짐) → 상태 저장소 → `LocalBackend` → `Start(prefs)` → 로컬 API 서버(메모리 파이프)(`tailscale.com/tsnet/tsnet.go:814-1043`) | 엔진, 사용자 공간 스택, 저장소, 로컬 백엔드 |
| `Listen("tcp", ":port")` | 포트 0이면 10002~19999에서 비어 있는 포트를 할당. 리스너 맵에 `(네트워크, 호스트, 포트, funnel)` 키로 등록(`tailscale.com/tsnet/tsnet.go:2062-2156`, `:2184-2271`) | 리스너 레지스트리, 수신 TCP 연결 |
| `Dial(ctx, net, addr)` | `Start` 후 상태가 `Running`이 될 때까지 기다린 뒤(`NeedsLogin`·`Starting`이면 대기, 그 밖의 상태는 오류) `UserDial`(`tailscale.com/tsnet/tsnet.go:382-419`) | 이름 해석, 사용자 공간 TCP 클라이언트 |
| `WhoIs` | 4.3.4 | 노드·주소 색인, 사용자 프로필 |
| `Status` | `ipnstate.Status`: `Version`, `TUN`, `BackendState`(문자열), `HaveNodeKey`, `AuthURL`, `TailscaleIPs`, `Self`, `Health`, `MagicDNSSuffix`, `CurrentTailnet`(`MagicDNSEnabled` 포함), `CertDomains`, `ExtraRecords`, `Peer`(맵), `User`(맵)(`tailscale.com/ipn/ipnstate/ipnstate.go:32-91`) | netmap에서 만드는 스냅샷 |
| `WatchIPNBus(mask)` | `GET /localapi/v0/watch-ipn-bus?mask=`의 JSON 스트림. `Notify` 필드: `Version`, `SessionID`(첫 메시지), `ErrMessage`, `LoginFinished`, `State`, `Prefs`, `SelfChange`, `InitialStatus`, `PeersChanged`/`PeersRemoved`/`PeerChangedPatch`, `UserProfiles`, `Engine`, `BrowseToURL`, `Health` 등(`tailscale.com/client/local/local.go:1516-1544`, `tailscale.com/ipn/backend.go:335-470`). `mask` 비트: `NotifyInitialState`=1<<1, `NotifyInitialPrefs`=1<<2, `NotifyWatchEngineUpdates`=1<<0 등(`tailscale.com/ipn/backend.go:75-130`) | 구독자별 큐와 초기 상태 전송 |
| `StartLoginInteractive` | 유효한 저장 인증 URL이 있으면 바로 `BrowseToURL`로 알리고, 없으면 제어 클라이언트에 `LoginInteractive` 로그인을 요청해 URL이 오면 알린다(`tailscale.com/ipn/ipnlocal/local.go:4798-4839`). `Start` 직후 상태가 `NeedsLogin`이면 `tsnet`이 스스로 부른다(`tailscale.com/tsnet/tsnet.go:1008-1016`) | 제어 클라이언트의 대화형 로그인 |
| `CertPair`, `GetCertificate` | 4.3.5 | ACME 클라이언트, 인증서 저장소, 제어의 `set-dns` |

`StartLoginInteractive`가 끝난 뒤 로그인이 다른 사용자·노드로 완료되면 기존 프로필로 전환하거나 현재 프로필을 갱신한다(`tailscale.com/client/local/local.go:1065-1070`의 문서 주석).

#### 4.3.2 TCP 리스너·수신 연결 규칙

가짜 TUN(`Tun == nil`)을 쓸 때의 경로(`tailscale.com/tsnet/tsnet.go:922-934`):

1. WireGuard에서 복호화된 패킷이 패킷 필터를 거친 뒤 `injectInbound`로 온다(`PostFilterPacketInboundFromWireGuard`, `tailscale.com/wgengine/netstack/netstack.go:465`, `:1472-1480`). 필터가 거부한 패킷은 여기에 오지 않는다.
2. `shouldProcessInbound`: 목적지가 자기 주소이고 `ProcessLocalIPs`가 켜져 있으면 netstack이 처리한다(`tailscale.com/wgengine/netstack/netstack.go:1352-1354`).
3. TCP 핸들러 래퍼가 클라이언트(원격 IP)별 진행 중 연결 수를 센다. 상한은 전역 상한의 2/3, 전역 상한은 모바일 1024·Linux 8192·그 밖 2048(`tailscale.com/wgengine/netstack/netstack.go:76-120`, `:539-627`). 초과하면 그 연결을 처리하지 않는다. 같은 4-튜플의 SYN 재전송은 진행 중으로 보고 무시한다(`:566-573`).
4. `acceptTCP`: 서비스 IP 처리를 먼저 하고(4.1.7), `LocalBackend.TCPHandlerForDst`(PeerAPI·SSH·웹 클라이언트·serve가 있을 때만 핸들러를 반환)를 부른다. 핸들러가 없으면 `GetTCPHandlerForFlow`(= tsnet의 `getTCPHandlerForFlow`)로 간다(`tailscale.com/wgengine/netstack/netstack.go:1736-1762`).
5. `getTCPHandlerForFlow`: 리스너 조회 순서는 (`tcp4`/`tcp6`, 도착 IP, 포트) → (`tcp`, IP, 포트) → (`tcp4`/`tcp6`, 호스트 없음, 포트) → (`tcp`, 호스트 없음, 포트)이고, 호스트 없는 리스너는 목적지가 자기 노드의 IPv4·IPv6일 때만 맞는다(`tailscale.com/tsnet/tsnet.go:1238-1266`). 일치하는 리스너가 없고 대체 핸들러도 없으면 `(nil, true)`를 돌려 연결을 거부한다(RST)(`tailscale.com/tsnet/tsnet.go:1289-1303`, `tailscale.com/wgengine/netstack/netstack.go:1748-1754`).
6. 수락 시점에 엔드포인트를 만들고 핸드셰이크를 완료한 뒤 TCP keepalive를 켠다(`tailscale.com/wgengine/netstack/netstack.go:1666-1720`). `Accept` 쪽으로는 버퍼 없는 채널로 전달하며 1초 안에 `Accept`가 가져가지 않으면 연결을 닫는다(`tailscale.com/tsnet/tsnet.go:2406-2417`).
7. 포트 53(서비스 IP)과 달리 일반 포트는 `TCPHandlerForDst`와 `tsnet` 리스너만이 수락 경로다. 호스트 루프백으로 포워딩하는 경로(`isTailscaleIP` 분기)는 `tsnet`이 리스너가 없으면 `intercept=true`로 막으므로 닿지 않는다(`tailscale.com/wgengine/netstack/netstack.go:1799-1801`).

`Server.Tun`을 직접 넘기면 gVisor TCP 리스너(`ListenTCP`)를 쓰고 `tcp4`/`tcp6`만 지원한다(`tailscale.com/tsnet/tsnet.go:2131-2147`, `tailscale.com/wgengine/netstack/netstack.go:1967-1998`). Swiftail의 첫 사용처는 이 경로가 아니다.

#### 4.3.3 다이얼과 gVisor 설정

`Dial` 경로(`tailscale.com/net/tsdial/tsdial.go:423-490`, `:588-638`):

1. 주소가 IP 리터럴이면 그대로. 아니면 `MagicDNS` 콜백(`LocalBackend.resolveMagicDNS`)으로 푼다. 콜백은 노드 이름(FQDN·짧은 이름)과 `ExtraRecords` 이름을 찾고, 네트워크 문자열(`tcp4`/`tcp6`/`tcp`)에 맞는 주소를 고른다. `tcp`이면 IPv4를 우선하고 없으면 IPv6(`tailscale.com/net/tsdial/tsdial.go:401-415`, `tailscale.com/ipn/ipnlocal/resolve.go:59-76`, `:115-146`). 이 해석은 quad-100을 거치지 않는다.
2. 콜백이 못 풀면 시스템 리졸버(`net.Resolver`)로 푼다(`tailscale.com/net/tsdial/tsdial.go:442-489`).
3. TCP이고 주소가 여럿이면 300ms 간격의 행복한 눈알 경쟁(`tailscale.com/net/tsdial/tsdial.go:640-656`).
4. `UseNetstackForIP(ip)`는 `LocalBackend.PeerForIP(ip)`가 성공하는지다. 테일넷 주소이거나 서브넷·출구 라우트로 갈 피어가 있으면 netstack 다이얼, 그렇지 않으면 일반 `net.Dialer`(OS 네트워크)로 나간다(`tailscale.com/tsnet/tsnet.go:935-939`, `tailscale.com/net/tsdial/tsdial.go:608-638`, `tailscale.com/ipn/ipnlocal/resolve.go:166-198`).
5. netstack 다이얼은 목적지 주소 계열에 맞는 자기 테일넷 IP를 출발지로 묶는다(`tailscale.com/tsnet/tsnet.go:940-951`, `tailscale.com/wgengine/netstack/netstack.go:990-1007`).

gVisor 설정(`tailscale.com/wgengine/netstack/netstack.go:309-345`, `:388-464`, `:669-672`):

| 항목 | 값 |
| --- | --- |
| 네트워크 프로토콜 | IPv4, IPv6 |
| 전송 프로토콜 | TCP, UDP, ICMPv4, ICMPv6 |
| NIC | 1개(`nicID=1`), 프로미스큐어스, IPv4·IPv6 기본 경로 둘 다 이 NIC |
| MTU·큐 | `DefaultTUNMTU()`(기본 1280), 큐 512 |
| TCP 혼잡 제어 | `cubic` |
| TCP 손실 복구 | `TCPRecovery(0)`(RACK 끔). 환경 변수 `TS_NETSTACK_ENABLE_RACK=true`일 때만 `TCPRACKLossDetection` |
| TCP 수신 버퍼 | 최소 `tcp.MinBufferSize`, 기본 `tcp.DefaultSendBufferSize`, 최대 8MiB(iOS는 `tcp.MaxBufferSize`) |
| TCP 송신 버퍼 | 최소 `tcp.MinBufferSize`, 기본 `tcp.DefaultReceiveBufferSize`, 최대 6MiB(iOS는 `tcp.MaxBufferSize`) |
| TCP 포워더 | 수신 윈도 인자 = 수신 버퍼 기본값, 동시 진행 연결 상한은 위 3 |
| keepalive | 수락한 연결에 켬. idle·interval은 netstack 기본(주석: 2시간 남짓, 75초)이고 환경 변수로만 바꾼다 |

- 수신 버퍼의 "기본"에 gVisor의 송신 기본 상수를, 송신 버퍼의 "기본"에 수신 기본 상수를 넣는 것은 소스 그대로다(`tailscale.com/wgengine/netstack/netstack_tcpbuf_default.go:13-19`, `tailscale.com/wgengine/netstack/netstack_tcpbuf_ios.go:17-23`). `tcp.*BufferSize` 상수의 실제 값은 gVisor 소스에 있어 확인하지 못했다.
- iOS에서 최대 버퍼를 줄이지 않고 gVisor 기본으로 두는 이유는 네트워크 확장 메모리 한도를 늘리지 않으려는 것이라고 주석에 있다(`tailscale.com/wgengine/netstack/netstack_tcpbuf_ios.go:12-15`).
- Swift에서 필요한 사용자 공간 스택의 기능 목록(설계 판단): IPv4·IPv6 파싱·생성, TCP 상태 머신(핸드셰이크, 재전송, 윈도 확장, 손실 복구, 혼잡 제어, keepalive, RST·FIN), 수락 대기열과 진행 중 연결 상한, UDP, 선택적으로 ICMP 에코.

#### 4.3.4 `WhoIs`

`LocalBackend.WhoIs(proto, ip:port)`(`tailscale.com/ipn/ipnlocal/local.go:1753-1805`):

1. IPv4 매핑 IPv6 주소(`::ffff:a.b.c.d`)를 IPv4로 정규화.
2. `nodeByAddr[ip]`로 노드 ID를 찾는다. 테일넷 주소이면 포트는 0이어도 된다. 인덱스는 노드 자신의 주소(자기 노드 포함)만 담는다(`tailscale.com/ipn/ipnlocal/node_backend.go:119-121`).
3. 못 찾고 netstack이 있으면 `ProxyMapper`로 (proto, ip:port)를 로컬이 대신 열어 준 연결의 실제 원격 IP로 바꿔 다시 찾는다. 포트가 0이면 건너뛴다. `tsnet`의 직접 수신 연결은 원격 IP가 이미 피어 주소이므로 이 경로가 필요 없다.
4. 노드의 `User`로 사용자 프로필을 찾는다. 없으면 실패.
5. 로컬 API는 `GET /localapi/v0/whois?addr=`(`ip`, `ip:port`, `nodekey:…` 허용). 응답: `Node`, `UserProfile`, `CapMap`(원격의 첫 주소가 이 노드에 가지는 피어 능력). 없으면 404(`tailscale.com/ipn/localapi/localapi.go:516-627`).

#### 4.3.5 `ts.net` 인증서(`CertPair`, `GetCertificate`)

호출 경로: `LocalClient.CertPair(domain)` → `GET /localapi/v0/cert/<domain>?type=pair&min_validity=<기간>` → `LocalBackend.GetCertPEMWithValidity` → `feature/acme`의 `getCertPEMWithValidity`(`tailscale.com/client/local/cert.go:102-135`, `tailscale.com/ipn/localapi/cert.go:21-70`, `tailscale.com/ipn/ipnlocal/cert.go:97-102`). 로컬 API 핸들러는 `!ios && !android` 빌드에서만 존재한다(`tailscale.com/ipn/localapi/cert.go:5`). 응답은 개인키 PEM 뒤에 인증서 PEM이 이어진 본문이다(`tailscale.com/client/local/cert.go:117-135`).

`GetCertificate(hi)`: SNI가 없으면 오류. SNI에 점이 없으면 `StatusWithoutPeers`의 `CertDomains` 중 그 이름으로 시작하고 바로 다음이 점인 항목으로 확장. 그런 뒤 `CertPair`와 `tls.X509KeyPair`로 인증서를 만든다. 제한 시간 1분(`tailscale.com/client/local/cert.go:162-205`). `ListenTLS`는 `Up`이 끝난 뒤 `MagicDNSEnabled`와 `CertDomains`가 비어 있지 않을 때만 열리고 핸드셰이크마다 이 경로를 탄다(`tailscale.com/tsnet/tsnet.go:1458-1479`, `:1505-1511`).

발급 절차(`tailscale.com/feature/acme/cert.go:81-168`, `:345-447`, `:487-613`):

1. 도메인의 끝 점을 뗀다. 이름이 그럴듯한지 검사한다(점 필수, `..`·`:`·`/`·`\`·NUL 금지, `*`는 `*.`로 시작할 때만)(`:96-100`, `:662-678`).
2. `resolveCertDomain`: netmap 필요. `CertDomains`가 비어 있으면 실패("계정이 TLS 인증서를 지원하지 않음"). 정확히 `CertDomains`에 있는 이름만 허용한다. `*.<도메인>`은 `DNSSubdomainResolve` 능력이 있어야 한다. `app.node.ts.net` 같은 하위 이름은 거부한다(`:689-728`).
3. 인증서 저장소에서 읽는다. 인증서·키 한 쌍을 X.509로 파싱하고, `DNSName=<도메인>`·현재 시각으로 체인을 검증한다. 시스템 루트 → 실패하면 내장 루트(Let's Encrypt)(`tailscale.com/feature/acme/certstore.go:135-154`, `:411-474`). 없으면 `ErrStateNotExist`, 만료·검증 실패면 `errCertExpired`.
4. 유효한 캐시가 있으면 갱신 여부를 판정한다. `min_validity`가 0이 아니면 `NotAfter - 지금 < min_validity`일 때 동기 갱신(`:153-156`, `:173-180`). 0이면: ARI(ACME Renewal Information)가 주는 제안 구간에서 난수 시각을 골라 그 시각이 지났을 때 갱신하고, ARI 조회(5초 제한)가 실패하면 인증서 수명의 2/3 지점이 지났을 때 갱신한다. 결과는 도메인별로 메모리에 기억한다(`:181-199`, `:233-251`, `:306-340`). 갱신은 백그라운드에서 한 번에 하나만 돌리고 현재 인증서를 즉시 돌려준다(`:138-152`, `:207-231`).
5. 새로 발급할 때(`getCertPEM`): 도메인별 잠금. 이미 다른 호출이 갱신했는지 다시 확인. 캐시된 인증서가 없으면 건강 경고 `certPendingWarnable`을 켠다(`:345-375`).
6. ACME 계정 키: 저장소에서 `acme-account.key.pem`을 읽고, 없으면 ECDSA P-256 키를 만들어 저장한다(`tailscale.com/feature/acme/certstore.go:361-389`). 클라이언트의 디렉터리 URL은 기본 `https://acme-v02.api.letsencrypt.org/directory`이고 `TS_DEBUG_ACME_DIRECTORY_URL`이 있으면 그 값이다. HTTP 클라이언트는 따로 지정하지 않아 `http.DefaultClient`다(`tailscale.com/tempfork/acme/acme.go:47`, `tailscale.com/feature/acme/certstore.go:391-404`, `tailscale.com/tempfork/acme/http.go:264-268`).
7. 계정 확인: `GetReg`, 계정이 없으면(`ErrNoAccount`) 약관 동의로 `Register`, 이미 있다고 하면 다시 `GetReg`. 상태가 `valid`가 아니면 실패(`tailscale.com/feature/acme/cert.go:386-392`, `:451-473`).
8. 이전 인증서가 있으면 주문에 ARI `replaces`를 붙여 갱신으로 표시한다(`:394-419`).
9. 챌린지 종류: tsnet의 첫 발급은 DNS-01이다. TLS-ALPN-01은 해당 도메인의 :443에 Funnel이 켜져 있고 이전 인증서가 있거나 BYO Funnel 도메인일 때만 시도한다(`:253-275`, `:428-446`). 와일드카드는 DNS-01만(`:254-257`).
10. 주문: `AuthorizeOrder([{dns, <도메인>}])`(와일드카드는 `*.도메인`과 기본 도메인 둘) → 각 `AuthzURL`마다 `GetAuthorization`(`:515-536`).
11. DNS-01 응답(`:615-654`):
    - 챌린지 `dns-01`을 찾는다.
    - TXT 값 = `base64url(SHA-256(token + "." + JWK 지문))`, 패딩 없음(`tailscale.com/tempfork/acme/acme.go:591-598`, 지문 계산 `:783`).
    - 이름 = `_acme-challenge.<도메인>`(와일드카드는 기본 도메인에 붙인다).
    - 시스템 리졸버로 그 TXT를 500ms 안에 조회해 이미 있으면 올리지 않는다.
    - 없으면 `SetDNS(이름, 값)`을 부른다. 이것이 제어 서버 호출이다. 노이즈 채널로 `POST /machine/set-dns`, 본문은 JSON `SetDNSRequest{Version: CurrentCapabilityVersion, NodeKey: 현재 노드 공개키, Name, Type: "TXT", Value}`. 응답이 200이 아니면 오류, 200이면 본문(`SetDNSResponse`, 빈 JSON 객체)을 디코드한다(`tailscale.com/ipn/ipnlocal/local.go:7809-7839`, `tailscale.com/control/controlclient/direct.go:1758-1781`, `tailscale.com/tailcfg/tailcfg.go:2595-2621`). 제어 클라이언트 연결이 없거나 노드 키가 없으면 실패한다.
    - 그런 뒤 `Accept(챌린지)`.
12. `WaitOrder(주문 URI)`로 준비될 때까지 기다린다(`:563-575`).
13. 인증서 키: 새 ECDSA P-256 키. CSR(PKCS#10): `CN=<도메인>`, SAN `DNSNames=[도메인]`(와일드카드는 기본 도메인도 포함). `CreateOrderCert(finalizeURL, csr, bundle=true)`로 DER 체인을 받아 `CERTIFICATE` PEM 블록들로 인코딩한다(`:578-606`, `tailscale.com/feature/acme/certstore.go:305-330`).
14. 저장: 키 파일, 그다음 인증서 파일 순서로 쓴다(`:607-609`, `tailscale.com/feature/acme/certstore.go:164-169`). 메모리의 갱신 예정 시각을 지운다(`:610`).

백그라운드 갱신 루프는 상태가 `Running`이고 serve 설정에 HTTPS 항목이 있을 때만 1시간 간격으로 돈다(`tailscale.com/feature/acme/refresh.go:21-82`). `tsnet.Up`은 첫 호출에서 serve 설정을 비우므로(`tailscale.com/tsnet/tsnet.go:608-621`) 이 루프는 `tsnet` 사용에서 돌지 않는다. 이 문장은 두 코드를 맞대어 낸 추론이다. 실제로는 핸드셰이크 때의 갱신 판정(4번)이 갱신 시점이 된다.

필요한 요소 목록: HTTPS 클라이언트, RFC 8555 ACME 클라이언트(디렉터리·논스·ES256 JWS·계정·주문·권한·챌린지·완료·인증서 다운로드), ARI 조회, ECDSA P-256 키 생성과 SEC1 PEM, PKCS#10 CSR, X.509 체인 검증(루트 포함), 제어의 `set-dns` 호출, 도메인별 잠금, 파일 저장소.

### 4.4 [4부] 네트워크 감시와 소켓 결속(요약)

#### 4.4.1 기본 경로 인터페이스 결정

`netmon.State.DefaultRouteInterface`는 `DefaultRoute()`의 인터페이스 이름이다(`tailscale.com/net/netmon/state.go:622-623`, `:898-902`). darwin·iOS의 `defaultRoute()`(빌드 태그 `darwin || ios`, `tailscale.com/net/netmon/defaultroute_darwin.go:4`, `:44-80`):

1. `OSDefaultRoute()`: 앱이 `UpdateLastKnownDefaultRouteInterface(ifName)`로 넘긴 이름을 쓴다. 인터페이스가 존재하고 올라와 있고 주소가 하나라도 있을 때만 유효하다(`tailscale.com/net/netmon/defaultroute_darwin.go:20-43`, `:82-120`). 빈 이름은 무시한다.
2. 이유: NetworkExtension이 위임 인터페이스를 터널 생성 시점에 한 번만 정하고 와이파이→셀룰러 전환에서는 갱신하지 않는다. 그래서 Swift 쪽 `NWPathMonitor`가 만족된 첫 경로의 인터페이스 이름을 넘긴다(`tailscale.com/net/netmon/defaultroute_darwin.go:44-60`).
3. 위가 실패하면 BSD 방식: 라우팅 테이블(`NET_RT_DUMP2`)에서 `RTF_GATEWAY`가 있고 `RTF_IFSCOPE`가 없는 `0.0.0.0/0` 또는 `::/0` 기본 게이트웨이를 찾는다. 터널(`utun*`)이면 `SIOCGIFDELEGATE` ioctl로 위임된 실제 인터페이스를 따라간다(`tailscale.com/net/netmon/interfaces_bsd.go:30-68`, `:115-153`, `tailscale.com/net/netmon/interfaces_darwin.go:20-26`, `:40-100`).
4. `State`는 인터페이스별 IP를 모으되 내려가 있거나 터널 자신이거나 "흥미롭지 않은" 인터페이스(`llw`, `awdl`, `ipsec`, `gif`, `XHC`, `anpi`, `lo`, `utun` 접두)는 `HaveV4`·`HaveV6` 계산에서 뺀다(`tailscale.com/net/netmon/state.go:591-620`, `tailscale.com/net/netmon/netmon_darwin.go:19-23`, `:134-141`). 터널 인터페이스 이름은 `SetTailscaleInterfaceProps`로 알려 주지 않으면 `utun` + 테일넷 IP 보유로 추정한다(`tailscale.com/net/netmon/state.go:562-581`, `tailscale.com/net/netmon/interfaces.go:50-82`).

#### 4.4.2 소켓을 물리 인터페이스에 결속하는 방법과 이유

- 이유: 테일스케일이 만든 패킷이 테일스케일 경로로 다시 들어가는 루프를 막는다(`tailscale.com/net/netns/netns.go:4-13`).
- 대상: DERP 연결(`tailscale.com/derp/derphttp/derphttp_client.go:616`, `:718`), 제어 연결(`SystemDial`, `tailscale.com/net/tsdial/tsdial.go:539-578`, `tailscale.com/control/ts2021/client.go:254`), magicsock UDP 소켓(`tailscale.com/wgengine/magicsock/magicsock.go:3768`)과 핑(`:4144`), netcheck·포트매퍼(`tailscale.com/net/netcheck/netcheck.go:928`, `:1241`, `tailscale.com/net/portmapper/portmapper.go:389`), DNS 포워더의 TCP(`SystemDial`). DNS 포워더의 UDP는 `netns`를 거치지 않는다(4.1.5).
- 방법(`tailscale.com/net/netns/netns_darwin.go:39-55`, `:295-315`): `controlLogf`가 `net.Dialer.Control`/`ListenConfig.Control`에서 소켓을 연다. 로컬호스트(`localhost`, 루프백 IP) 주소는 결속하지 않는다. 인덱스를 얻으면 IPv4 소켓은 `IP_BOUND_IF`, IPv6는 `IPV6_BOUND_IF`를 `setsockopt`로 건다. IPv6 판별은 주소에 `]:`가 있거나 네트워크 이름이 `6`으로 끝나는지다. 인덱스를 얻지 못하면 결속하지 않고 그대로 연결한다.
- 인덱스 선택(`tailscale.com/net/netns/netns_darwin.go:57-145`): 기본은 "기본 경로 인터페이스". OS가 넘겨준 값(`OSDefaultRoute`)이 있으면 그 값을 우선하고, 없으면 `netmon`의 캐시를 쓴다. 두 값이 다르면 경고를 로그로 남긴다. 고른 인덱스가 테일스케일 `utun`이면 무효로 본다. `TS_BIND_TO_INTERFACE_BY_ROUTE`(또는 `SetBindToInterfaceByRoute`)가 켜지면 목적지별로 `AF_ROUTE` `RTM_GET`을 보내 그 목적지의 인터페이스를 찾는다(게이트웨이면 한 번 더 재귀). 결과가 터널이면 기본값으로 되돌린다.
- 끄는 스위치: `SetEnabled(false)`, `SetDisableBindConnToInterface`, macOS 확장 전용 `SetDisableBindConnToInterfaceAppleExt`(`tailscale.com/net/netns/netns.go:20-95`). 앱 확장 전용 스위치는 `version.IsMacGUIVariant()`일 때만 적용되며 iOS에서는 거짓이다(`tailscale.com/net/netns/netns_darwin.go:40`, `tailscale.com/version/prop.go:60-67`, `:132-134`). 따라서 iOS는 결속이 기본으로 항상 켜진다.
- `defaultroute_darwin.go`는 `darwin || ios` 빌드 태그가 명시돼 있어 iOS에서도 쓰인다(`tailscale.com/net/netmon/defaultroute_darwin.go:4`). `netns_darwin.go`는 `darwin` 빌드 태그이고(`tailscale.com/net/netns/netns_darwin.go:4`), Go는 `GOOS=ios`를 `darwin` 태그에도 맞추므로 iOS에서 컴파일된다(Go 빌드 규칙. 이 소스로 직접 확인한 것은 아니다).
- `tailscale.com/net/netns/netns_darwin.go:282-293`의 `SetListenConfigInterfaceIndex`는 지정한 인덱스에 결속한 `ListenConfig`를 만든다. DNS 포워더가 터널 인터페이스를 고를 때 쓴다(4.1.5).

#### 4.4.3 링크 변경이 엔진에 전달되어 일어나는 일

1. `netmon`: darwin 구현은 `AF_ROUTE` 소켓을 읽는다(파일 이름이 `_darwin`이라 iOS 빌드에도 포함되나, iOS 샌드박스에서 이 소켓이 실제로 열리는지는 확인하지 못했다. 8장). 흥미롭지 않은 인터페이스와 링크로컬 목적지의 라우트 메시지, `RTM_MISS`는 건너뛴다(`tailscale.com/net/netmon/netmon_darwin.go:34-46`, `:60-109`, `:110-178`). 메시지가 있으면 `Poll()`로 상태를 다시 계산하고, 직전 확인과 같으면 알리지 않는다. 확인 사이 최소 간격은 1초(디바운스)다(`tailscale.com/net/netmon/netmon.go:583-630`, `:643-681`).
2. 시각 점프: 15초마다 벽시계가 22.5초 넘게 점프했는지 본다. iOS·Android에서는 끈다(배터리). 점프가 10분 이상이면 "큰 점프"로 보고 상태가 같아도 재결속이 필요하다고 판단한다(`tailscale.com/net/netmon/netmon.go:33-42`, `:709-746`).
3. `ChangeDelta`: 새·이전 상태, `DefaultRouteInterface`, `DefaultInterfaceChanged`, `InterfaceIPsChanged`, `HasPACOrProxyConfigChanged`, `AvailableProtocolsChanged`, `IsLessExpensive`, `DefaultInterfaceMaybeViable`(올라와 있고 터널 자신이 아님), `RebindLikelyRequired`(처음 상태이거나 큰 시각 점프이거나 기본 인터페이스·IP·프록시·프로토콜·비용 중 하나가 바뀌고, 기본 인터페이스가 쓸 만할 때)(`tailscale.com/net/netmon/netmon.go:98-209`).
4. `ChangeDelta`는 이벤트 버스로 발행되고 등록된 콜백에도 전달된다(`tailscale.com/net/netmon/netmon.go:677-680`). 받는 쪽은 셋이다.
   - 엔진(`userspaceEngine.linkChange`): 올라온 링크가 없으면 `health`에 알리고 DERP를 닫는다(`SetNetworkUp(false)`). 큰 변화이거나 모두 내려가면 DNS 캐시를 비운다. 큰 변화이고 올라와 있으면 linux·android·ios·darwin·openbsd에서 마지막 DNS 설정을 `dns.Set`으로 다시 적용하고 VPN 설정을 재구성한다. 올라와 있으면 `SetNetworkUp(true)`로 DERP 홈 연결을 시작하고, 큰 변화면 `magicsock.Rebind()`, 이어서 항상 `ReSTUN`(`tailscale.com/wgengine/userspace.go:1155-1225`).
   - `magicsock.Rebind`: UDP 소켓을 닫고 같은 포트로 다시 결속(IPv6는 실패해도 무시, IPv4 실패는 오류)하고 포트매퍼의 로컬 포트를 갱신한다. 이어 기본 인터페이스의 IP를 로컬 주소로 갖지 않는 DERP 연결은 닫고, 가진 것은 3초 제한으로 핑해 실패하면 닫고 다시 연결한다(홈 DERP). 모든 피어의 엔드포인트 선택 상태를 초기화한다(`tailscale.com/wgengine/magicsock/magicsock.go:3880-3924`, `tailscale.com/wgengine/magicsock/derp.go:905-933`).
   - `LocalBackend.linkChange`: 인터페이스 상태를 저장하고 제어 클라이언트를 일시 정지·재개한다. 올라온 링크가 없으면 정지하고(테스트·`AssumeNetworkUp` 제외) 있으면 재개한다. 출구 노드 LAN 접근이나 PAC 변경 시 `authReconfig`를 다시 돌리고 패킷 필터를 갱신한다(`tailscale.com/ipn/ipnlocal/local.go:1128-1164`, `:1215-1265`).
5. 제어 연결·시스템 연결 재연결: `tsdial.Dialer`가 `ChangeDelta`를 구독하고, `SystemDial`로 만든 TCP 연결이 영향을 받으면 닫아 상위가 다시 연결하게 한다. 영향 판정: 기본 인터페이스가 바뀌었거나 PAC·프록시 설정이 바뀌었거나, 기본 경로 인터페이스 이름이 비어 있거나(Android·macOS·iOS에서 흔함, 보수적으로 전부 영향), 연결의 출발지 IP가 사라진 경우. 처음 상태는 영향 없음(`tailscale.com/net/tsdial/tsdial.go:282-355`).
6. 앱 쪽이 알려야 하는 것: `NWPathMonitor` 경로 변화마다 `UpdateLastKnownDefaultRouteInterface`와 같은 동작(인터페이스 이름 전달). `netmon.InjectEvent()`/`Poll()`로 즉시 재계산을 강제할 수 있다(`tailscale.com/net/netmon/netmon.go:540-570`). 엔진 주석은 DNS 서버가 바뀔 때 네트워크 확장이 `dns.Manager.RecompileDNSConfig`를 직접 부르라고 한다(`tailscale.com/wgengine/userspace.go:1176-1186`, `tailscale.com/net/dns/manager.go:169-179`).

## 5. 상수와 타이머

| 이름 | 값 | 출처 |
| --- | --- | --- |
| 서비스 IP | `100.100.100.100`, `fd7a:115c:a1e0::53` | `tailscale.com/net/tsaddr/tsaddr.go:52-68` |
| 로컬 응답 TTL(A·AAAA·PTR) | 5초 | `tailscale.com/net/dns/resolver/tsdns.go:58` |
| 부정 응답(SOA) TTL·Refresh·Retry·Expire·MinTTL | 10초 | `tailscale.com/net/dns/resolver/tsdns.go:68`, `:1186-1198` |
| 전달 응답 최대 크기 | 4095바이트(UDP 버퍼는 4096) | `tailscale.com/net/dns/resolver/tsdns.go:50` |
| UDP 기본 최대 크기(EDNS 없음) | 512바이트 | `tailscale.com/net/dns/resolver/forwarder.go:228` |
| DNS 질의 전체 제한 | 10초 | `tailscale.com/net/dns/resolver/tsdns.go:406` |
| 동시 DNS 질의 | 256 | `tailscale.com/net/dns/manager.go:60` |
| DNS TCP 유휴 | 45초 | `tailscale.com/net/dns/manager.go:682` |
| DNS TCP 최대 요청 길이 | 4096바이트 | `tailscale.com/net/dns/manager.go:687` |
| 서비스 IP UDP 읽기 제한 | 150ms | `tailscale.com/wgengine/netstack/netstack.go:2085` |
| 업스트림 UDP→TCP 경쟁 시작 | 2초 | `tailscale.com/net/dns/resolver/forwarder.go:108` |
| 업스트림 TCP 제한 | 5초 | `tailscale.com/net/dns/resolver/forwarder.go:112` |
| DoH 선행 시간·같은 제공자 두 번째 IP 지연 | 500ms·200ms | `tailscale.com/net/dns/resolver/forwarder.go:99`, `:104` |
| 기본 설정 재시도 | 1초 간격 2배, 6회 | `tailscale.com/net/dns/manager.go:54-55` |
| TUN MTU | 1280(기본) | `tailscale.com/net/tstun/mtu.go:79` |
| netstack 진행 중 연결 상한 | 모바일 1024, Linux 8192, 그 밖 2048. 클라이언트당 2/3 | `tailscale.com/wgengine/netstack/netstack.go:85-120` |
| 리스너 → `Accept` 전달 대기 | 1초 | `tailscale.com/tsnet/tsnet.go:2412` |
| tsnet 임시 포트 범위 | 10002~19999 | `tailscale.com/tsnet/tsnet.go:2110-2113` |
| 다이얼 행복한 눈알 간격 | 300ms | `tailscale.com/net/tsdial/tsdial.go:643` |
| 인증 URL 재사용 한도 | 6일 23시간 | `tailscale.com/ipn/ipnlocal/local.go:4822` |
| `netmon` 디바운스 | 1초 | `tailscale.com/net/netmon/netmon.go:627` |
| 벽시계 점프 확인 주기·큰 점프 기준 | 15초·10분 | `tailscale.com/net/netmon/netmon.go:33`, `:42` |
| 폴링 `netmon`(OS 알림이 없는 플랫폼, 기본 10초. Android는 10분) | 10초 | `tailscale.com/net/netmon/polling.go:59-66` |
| 인증서 갱신 루프 주기 | 1시간 | `tailscale.com/feature/acme/refresh.go:21` |
| 인증서 갱신 지점(ARI 실패 시) | 수명의 2/3 | `tailscale.com/feature/acme/cert.go:248` |
| ARI 조회 제한·TXT 사전 조회 제한 | 5초·500ms | `tailscale.com/feature/acme/cert.go:306-340`, `:615-636` |
| 인증서 갱신 호출 제한(루프) | 2분 | `tailscale.com/feature/acme/refresh.go:84-132` |
| DERP 재결속 후 핑 제한 | 3초 | `tailscale.com/wgengine/magicsock/derp.go:905-933` |

## 6. Swiftail에 필요한 최소 부분과 생략할 수 있는 부분

### 6.1 M5 — iOS 패킷 터널

필요한 최소 구현
- 상태 저장: FileStore 호환 JSON을 App Group 컨테이너에 두는 것. 키 4종(`_machinekey`, `_profiles`, `_current-profile`, `profile-<id>`)과 `Persist` 필드(3.2).
- DNS 설정 계산: `dnsConfigForNetmap` 규칙 1~11 중 출구 노드 부분을 뺀 것(4.1.1)과 `compileConfig`의 iOS 분기(4.1.3). 결과를 `NEDNSSettings`(서버 = `serviceIPs`, `matchDomains`, 검색 도메인)로 옮기는 변환은 앱 쪽에서 새로 짠다.
- 터널 안 리졸버: 서비스 IP 두 주소로 가는 UDP 53을 WireGuard로 보내지 않고 흡수해 응답한다. 호스트 표는 `nodeByName`·`nodeByAddr`·`ExtraRecords` 색인에서 질의 때 조회하고(4.1.2), 응답 규칙은 3.1을 따른다. 모르는 이름의 전달은 `Routes` 최장 접미사 선택, UDP 업스트림, 2초 후 TCP, SERVFAIL·REFUSED 집계까지(4.1.5). 서비스 IP로 가는 나머지 모든 패킷도 WireGuard로 보내지 않는다.
- 네트워크 감시: `NWPathMonitor` → 기본 경로 인터페이스 이름 주입, `AF_ROUTE` `netmon`(또는 폴링), `ChangeDelta`의 `RebindLikelyRequired` 계산, 링크 변경 시 DERP 닫기/재연결, UDP 재결속, `ReSTUN`, 시스템 연결 닫기, DNS 설정 재적용(4.4).
- 소켓 결속: 제어·DERP·magicsock UDP·핑·DNS 업스트림 TCP 소켓에 `IP_BOUND_IF`/`IPV6_BOUND_IF`(4.4.2). Tailscale의 DNS 업스트림 UDP는 결속하지 않으므로(4.1.5) Swiftail이 같은 동작을 따를지 결속할지는 설계 결정으로 남는다.

뒤로 미룰 수 있는 것(근거)
- 서비스 IP TCP 53 수락: M6에서 사용자 공간 TCP 스택이 생긴 뒤 같은 스택에 붙이는 것이 가장 단순하다(설계 판단). 그때까지는 UDP만 받고, 응답이 TUN MTU(1280)에서 IP 헤더와 UDP 헤더를 뺀 크기를 넘으면 단편화하거나 TC를 세운다는 정책을 정해야 한다(4.1.8). 업스트림이 큰 응답을 줄 수 있으므로 질의의 EDNS 광고 크기를 그에 맞춰 깎는 방법이 있다. Tailscale도 4095로 깎는다(`tailscale.com/net/dns/resolver/forwarder.go:193-210`).
- DoH·PeerAPI 리졸버, 출구 노드 DNS, 4via6 이름, Bonjour 규칙(전달 전 NXDOMAIN은 배터리 절약 용도, `tailscale.com/net/dns/resolver/forwarder.go:1292-1295`), `.onion` 규칙(한 줄이라 포함 권장).
- 모드 A·B 중 모드 B만 먼저 구현해도 동작은 같다(모드 A는 범위를 좁히는 최적화). 다만 모드 B는 `GetBaseConfig`로 OS 기본 리졸버를 읽어야 한다(`tailscale.com/net/dns/manager.go:463-523`). 터널 내부에서 이를 읽는 방법은 이 소스에 없다(8장).
- netmap 디스크 캐시, 서브도메인 규칙(`DNSSubdomainResolve`).

### 6.2 M6 — 프로세스 내 리스너

필요한 최소 구현
- 가짜 TUN 위의 사용자 공간 IP·TCP 스택(4.3.3의 기능 목록). 수신은 패킷 필터 뒤에서 받는다.
- 리스너 레지스트리: `(네트워크, 호스트, 포트)` 키, 조회 순서 4단계, 임시 포트 할당, 대체 핸들러 없음, 리스너가 없으면 RST, `Accept` 1초 대기 후 닫기(4.3.2).
- 진행 중 연결 상한(전역·클라이언트별), TCP keepalive, 닫힌 포트에 RST.
- 다이얼: 자기 IP를 출발지로, `PeerForIP`로 테일넷 경로 판정, 이름은 MagicDNS 콜백(노드 이름·짧은 이름·`ExtraRecords`)으로 푼다. quad-100을 거치지 않는다(4.3.3). 이 모드에서는 quad-100 리졸버가 데이터 경로에 없다.
- 상태 머신(4.2.5)과 알림 스트림, `Status` 스냅샷, 파일 저장(3.2).

뒤로 미룰 수 있는 것: UDP 리스너(`ListenPacket`), `ListenTLS`/Funnel/Service, 서브넷 라우팅(`ProcessSubnets`), 핑, PeerAPI, SSH, 웹 클라이언트, `ProxyMapper`, GRO·GSO(Linux 전용, `tailscale.com/wgengine/netstack/netstack.go:429-433`).

### 6.3 M7 — 첫 사용처 대체

필요한 최소 구현
- `Up`, `Listen("tcp", ":포트")`, `Dial`, `Status`, `WatchIPNBus`, `StartLoginInteractive`(4.3.1), `WhoIs`(4.3.4).
- `CertPair`·`GetCertificate`: 4.3.5의 ACME 절차 전부(DNS-01만). 필요한 것은 ACME 클라이언트, ECDSA P-256과 CSR, X.509 체인 검증(루트 포함), 제어의 `set-dns` 호출, `certs/` 파일 저장, 요청 시 갱신 판정. 갱신 판정은 수명 2/3 규칙으로 충분하다.
- 인증서 요청용 HTTP는 `http.DefaultClient`와 같이 OS 기본 경로로 나가므로(`tailscale.com/tempfork/acme/http.go:264-268`), 확장이나 터널 환경에서 쓰려면 별도로 결속 정책을 정해야 한다.

뒤로 미룰 수 있는 것: ARI 조회·`replaces`, 와일드카드, TLS-ALPN-01·BYO Funnel, 갱신 백그라운드 루프, 인증서 건강 경고, Kubernetes 저장소, `acme-account.key.pem` 공유.

### 6.4 생략할 수 있는 부분

| 항목 | 근거 |
| --- | --- |
| OS DNS 구성기(NetworkManager, resolved, resolvconf, NRPT) | 대상은 iOS와 프로세스 내 노드. 가짜 DNS 구성기가 기본값(`tailscale.com/wgengine/userspace.go:330-337`) |
| 출구 노드 DNS, DoH | 첫 사용처가 출구 노드를 쓰지 않는다는 전제. 확인 필요 |
| 프로필 여러 개·Windows 사용자 | 첫 사용처는 하나의 프로필. 구조는 호환시키되 전환 기능은 생략 |
| `MaskedPrefs` 전체 | 부분 갱신 API가 없으면 불필요 |
| 하드웨어 증명 키, TPM 저장소 | 선택 기능 |

## 7. 상호 운용 시험에서 확인할 것

DNS(quad-100)
- 같은 테일넷에서 Swiftail 노드와 Tailscale 클라이언트에 `dig @100.100.100.100`을 보내 A, AAAA, PTR, ANY, NS, SOA, 모르는 타입을 비교한다. RCODE, AA, RA, TTL(5초), SOA 유무(부정 응답), 질문 구역, 답변 개수(1개)를 확인한다.
- 짧은 이름·FQDN·대소문자 섞인 이름, MagicDNS를 끈 테일넷(짧은 이름이 풀리지 않는 것), 피어에 IPv4가 있을 때 AAAA가 비는지, `ExtraRecords`의 A·AAAA·그 밖 타입.
- 역방향: `.in-addr.arpa.`, `.ip6.arpa.`, 4-to-6 주소, 서비스 IP, `LocalDomains` 안·밖의 미등록 주소(NXDOMAIN vs 전달).
- EDNS 질의(`+bufsize=4096`)와 응답에 OPT가 없는 것, 513바이트 이상의 전달 응답에서 TC 비트, `+tcp` 질의(M5에서는 실패해야 정상인지, 아니면 구현했는지를 표로 기록).
- 서비스 IP의 다른 포트: TCP는 RST, UDP는 무응답.
- 분할 DNS 라우트(`Routes`)의 최장 접미사 선택, 빈 라우트의 NXDOMAIN, 업스트림이 없는 이름의 SERVFAIL.
- iOS 실기기: 모드 A·B에서 `scutil --dns` 해당 정보(`matchDomains`, 검색 도메인), 모바일 데이터↔와이파이 전환 시 DNS 복구.

상태 저장
- Tailscale `tsnet`이 만든 `tailscaled.state`를 Swiftail이 읽어 같은 노드로 올라오는지, 반대 방향도. 값이 base64이고 키 텍스트가 `privkey:` + hex인지, `_current-profile`이 프로필 키를 가리키는지.
- 첫 로그인 전 파일에는 `_machinekey`만 남는지, 로그인 후 프로필이 생기는 순서, 중복 프로필이 정리되는지.
- 재시작 후 `NeedsLogin` 없이 `Starting` → `Running`으로 가는지, 노드 키 만료 시 `NeedsLogin`, 머신 승인 필요 시 `NeedsMachineAuth`.

tsnet 표면
- 다른 노드가 Swiftail의 `Listen`에 접속하고 `WhoIs`가 그 노드·사용자를 돌려주는지. 리스너가 없는 포트에 RST가 가는지. 진행 중 연결 한도 초과 동작.
- `Dial`로 이름·짧은 이름·IPv4·IPv6 주소에 접속하는지. 테일넷 밖 주소가 OS 경로로 나가는지.
- `GetCertificate`로 TLS 서버를 열고 브라우저로 접속, 인증서 만료 임박 시 요청 때 갱신. Let's Encrypt 스테이징 디렉터리(`TS_DEBUG_ACME_DIRECTORY_URL` 값에 해당하는 설정)로 시험해 속도 제한을 피한다.

네트워크 감시
- 와이파이↔셀룰러 전환, 비행기 모드, 슬립 복귀 후 DERP 재연결·UDP 재결속·제어 재연결 시간. 기본 경로 인터페이스를 앱이 주입하지 않았을 때(BSD 폴백)와 주입했을 때의 차이.

## 8. 확인하지 못한 것

- gVisor가 기준 소스에 없어 확인하지 못했다: `tcp.MinBufferSize`·`DefaultSendBufferSize`·`DefaultReceiveBufferSize`·`MaxBufferSize`의 값, SACK·윈도 확장·타임스탬프의 기본값, 수락 대기열(backlog) 크기, IP 단편화와 ICMP 응답(서비스 IP로의 에코 포함) 동작.
- 머신 키가 바뀐 노드를 제어 서버가 어떻게 취급하는지. 새 disco 키가 매 시작마다 제어에 어떻게 반영되는지(제어 프로토콜 노트의 몫).
- iOS에서 `OSConfigurator`를 주입하는 주체와 `OSConfig`를 `NEDNSSettings`로 바꾸는 규칙. 앱 쪽 코드라 이 소스에 없다. iOS에서 `AF_ROUTE` 소켓(`netmon_darwin.go`)이 샌드박스에서 실제로 쓰이는지도 확인하지 못했다.
- `selfExpired`일 때 quad-100이 실제로 응답을 멈추는지(주석은 멈춘다고 하나 코드상 `MagicDNSHosts` 조회는 설정과 무관하다).
- `tsnet`에서 `dialer.SetRoutes`가 설정되는지(`resolver.ShouldUseRoutes`의 조건)와 그에 따른 테일넷 밖 `Dial` 경로.
- `ShouldForceRegisterMagicDNSIPv4Only` 제어 노브의 기본값과 쓰임(IPv4만 설치할지 여부에 영향).
- ACME: `tempfork/acme`의 JWS·논스·요청 본문 세부와 오류 처리는 호출 지점만 읽었다. Let's Encrypt의 속도 제한과 ARI draft의 세부. `Accept` 이후 `WaitOrder`가 폴링하는 간격.
- `SubdomainHosts`에 값을 넣는 코드는 저장소에서 찾지 못했다(`dnsConfigForNetmap`에 대입이 없고 `manager.go:339`는 복사뿐). 쓰이지 않는 필드인지 확인하지 못했다.
- `ipn.State.InUseOtherUser`를 설정하는 코드 경로(Windows 전용으로 보임).
- `ProxyMapper`가 채워지는 정확한 조건(서브넷 라우터·exit-node 포워딩)과 `WhoIs`에 미치는 영향의 범위.
- 시험에서 확인할 항목 중 Swiftail이 이미 따르는 것과 아직 모르는 것의 구분은 구현 후에 해야 한다.
