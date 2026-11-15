# WhoIs·ts.net 인증서·Go 상태 파일 노트

## 1. 머리말

| 항목 | 내용 |
| --- | --- |
| 기준 버전 | `tailscale.com` v1.104.6 (CapabilityVersion 148). ACME 클라이언트는 그 안의 `tempfork/acme`(`golang.org/x/crypto/acme`의 포크) |
| 규격 | RFC 8555(ACME), RFC 7515(JWS), RFC 7518(JWA), RFC 7638(JWK 지문), RFC 2986(PKCS#10), RFC 5280(X.509 확장), RFC 5480·5758·5915(EC 키와 서명의 ASN.1), RFC 9773(ARI). RFC Editor의 원문(`https://www.rfc-editor.org/rfc/rfcNNNN.txt`)에서 조항을 확인했다 |
| 쓰는 마일스톤 | M7(`docs/contracts/SwiftailHost.md`) |
| 작성 모델 | Claude Fable 5.2 (`claude-fable-5-2`), 2026-11-15 |
| 검증 | **아직 검증 전이다.** 작성한 세션과 다른 세션이 Go 소스·RFC와 대조한 뒤에 M7 구현을 시작한다 |

[dns-state-node.md](dns-state-node.md)의 3.2(Go 상태 파일), 4.8(`WhoIs`), 4.9(ts.net 인증서)를 M7 구현에 필요한 깊이로 넓힌 노트다. 그 노트에 이미 있는 사실은 되풀이하지 않고 절 번호로 가리킨다(아래에서 "DNS 노트"). 출처는 모듈 루트 기준 `경로:줄`이다. 첫 사용처(RemoteDebug)의 코드는 그 저장소 `2814b2c`의 경로로 적는다. 예시 값은 가짜(`rd-mac-1a2b3c4d.tail0001.ts.net`, `100.64.0.1`)다.

Apple 프레임워크에 관한 사실은 SDK 머리 파일(`MacOSX27.2.sdk`의 `Security.framework/Headers/`)과, 저장소 밖에서 돌린 실험(2026-11-15, 샌드박스 밖의 명령줄 프로그램)에서 확인했다. 실험으로 본 것은 그렇게 적는다.

## 2. 범위

다루는 것

- `WhoIs`: 주소에서 노드와 사용자를 찾는 규칙, 사용자 프로필이 netmap에 들어오는 길, 태그·공유 노드, capability.
- ts.net 인증서: Go의 발급·저장·갱신 흐름, 제어 서버의 `set-dns`, ACME(RFC 8555)에서 DNS-01 발급에 필요한 부분, JWS(ES256)와 CSR의 바이트 형식, Apple 플랫폼에서 그것을 만드는 길.
- Go 상태 디렉터리: tsnet이 두는 파일, 노드 신원이 든 키, Swiftail 신원 저장과의 대응.

다루지 않는 것

- TLS-ALPN-01, 와일드카드 인증서, BYO Funnel 도메인, Kubernetes 저장소, 계정 키 교체, 인증서 폐기(쓰지 않는다. 6장).
- TLS 자체와 HTTP 서버. 첫 사용처가 Network 프레임워크로 한다(`docs/contracts/SwiftailNetstack.md` "첫 사용처 검토 결과" 1).
- tailnet lock, 프로필 여럿, Windows.

## 3. 와이어 형식과 저장 형식

### 3.1 `WhoIs`의 응답(Go)

`WhoIsResponse`는 `Node`(`tailcfg.Node` 전체), `UserProfile`, `CapMap` 셋이다(`tailscale.com/client/tailscale/apitype/apitype.go:35-42`). `UserProfile`의 필드는 `ID`, `LoginName`, `DisplayName`, `ProfilePicURL`, `Groups`다(`tailscale.com/tailcfg/tailcfg.go:307-319`). 첫 사용처가 읽는 것은 `Node.StableID`(비면 거절), `Node.Name`의 첫 레이블(비면 `Node.ComputedName`), `UserProfile.LoginName`뿐이다(RemoteDebug `core/internal/node/node.go:526-551`).

`tailcfg.Node`에서 신원에 쓰이는 필드(`tailcfg/tailcfg.go:370-386`, `:436`, `:501`):

| 필드 | 뜻 |
| --- | --- |
| `StableID` | 노드의 바뀌지 않는 문자열 ID. 첫 사용처의 허용 목록이 이것에 묶인다 |
| `Name` | FQDN, 끝에 점이 있다(`rd-phone-1a2b3c4d.tail0001.ts.net.`) |
| `User` | 노드를 만든 사용자의 ID. 태그 노드면 "그 노드가 동작하는 ACL 신원"을 반영하지 않는다(소스 주석 `:380-383`) |
| `Sharer` | 0이 아니면 이 노드를 공유해 준 사용자 |
| `Tags` | ACL 태그. 하나라도 있으면 태그 노드다(`IsTagged`, `:635-637`) |
| `ComputedName` | 와이어에 없다. 클라이언트가 계산한다(4.1 5) |

### 3.2 `set-dns` 요청(제어 서버)

Noise 채널(ts2021의 HTTP/2) 위의 `POST /machine/set-dns`다(`tailcfg/tailcfg.go:2589-2594`, `tailscale.com/control/controlclient/direct.go:1765`).

요청 본문은 JSON 객체 `SetDNSRequest`다(`tailcfg/tailcfg.go:2595-2618`):

| 키 | 값 |
| --- | --- |
| `Version` | `CurrentCapabilityVersion`(148). `LocalBackend.SetDNS`는 1을 넣지만 Noise로 보내기 직전에 덮어쓴다(`tailscale.com/ipn/ipnlocal/local.go:7813-7818`, `direct.go:1759-1760`) |
| `NodeKey` | 지금의 node 공개 키(`nodekey:` + hex) |
| `Name` | `_acme-challenge.<도메인>` |
| `Type` | `"TXT"` |
| `Value` | TXT 레코드에 넣을 값(3.5) |

요청 머리: `Content-Type: application/json`, 그리고 node 키가 0이 아니면 부하 분산용 머리(`tailcfg.LBHeader`)에 node 키 텍스트를 싣는다(`tailscale.com/control/ts2021/client.go:299-318`). 다른 Noise 요청(등록, 맵)과 같은 규칙이다.

응답: 상태가 200이 아니면 실패이고 본문의 앞 200자를 오류에 싣는다. 200이면 본문을 `SetDNSResponse`(빈 객체)로 해석한다. 해석에 실패하면 오류다(`direct.go:1770-1778`, `tailcfg/tailcfg.go:2620-2621`).

### 3.3 ACME 요청의 틀(JWS)

모든 POST의 본문은 Flattened JWS JSON 직렬화 객체 하나다(RFC 8555 6.2, RFC 7515 7.2.2). `Content-Type`은 `application/jose+json`이다(RFC 8555 6.2).

```json
{"protected":"<base64url(보호 머리 JSON)>","payload":"<base64url(본문 JSON)>","signature":"<base64url(서명)>"}
```

| 부분 | 규칙 | 출처 |
| --- | --- | --- |
| 보호 머리 | `alg`, `nonce`, `url`, 그리고 `jwk`와 `kid` 가운데 정확히 하나. 보호되지 않는 머리는 쓰지 않는다 | RFC 8555 6.2 |
| `alg` | P-256 계정 키면 `"ES256"`. 서버는 ES256을 반드시 구현한다 | RFC 8555 6.2, `tailscale.com/tempfork/acme/jws.go:231-247` |
| `jwk` | newAccount 요청(과 인증서 키로 서명하는 폐기 요청)에만. 계정 공개 키 | RFC 8555 6.2 |
| `kid` | 그 밖의 모든 요청. newAccount 응답의 `Location` 머리로 받은 계정 URL | RFC 8555 6.2, 7.3 |
| `url` | 이 요청을 보내는 URL 그대로 | RFC 8555 6.4.1 |
| `nonce` | 서버가 `Replay-Nonce` 머리로 준 값 하나. 한 번 쓰면 버린다 | RFC 8555 6.5, 6.5.2 |
| `payload` | 본문 JSON의 base64url. **POST-as-GET**(자원을 읽는 요청)은 빈 문자열 `""`이다(`"{}"`의 인코딩이 아니다) | RFC 8555 6.3 |
| 서명할 바이트 | ASCII(`protected` + `"."` + `payload`) | RFC 7515 5.1, `jws.go:106-107` |
| `signature` | ES256이면 SHA-256 위의 ECDSA 서명을 **R(32바이트) ‖ S(32바이트)**, 64바이트로 이은 것. DER가 아니다 | RFC 7518 3.4, `jws.go:200-227` |

base64url은 `-`·`_` 알파벳에 채움 문자(`=`)가 없는 형식이다(RFC 7515 2절, RFC 4648 5절).

Go는 계정 키로 P-256을 만든다(`tailscale.com/feature/acme/certstore.go:377`). RSA·P-384·P-521 키도 서명할 수 있게 되어 있지만(`jws.go:231-247`) Tailscale이 만드는 키는 P-256뿐이다.

### 3.4 JWK와 지문

P-256 공개 키의 JWK는 `crv`(`"P-256"`), `kty`(`"EC"`), `x`, `y` 네 멤버다. `x`·`y`는 좌표를 32바이트 빅엔디언으로 채운 뒤 base64url로 적는다(RFC 7518 6.2.1, `jws.go:160-196`).

지문(thumbprint)은 **필수 멤버만, 이름의 사전 순서로, 공백 없이** 적은 JSON의 SHA-256이다(RFC 7638 3절, 3.2, 3.3). P-256이면 입력은 정확히 다음 바이트열이다(`jws.go:189-193`이 같은 문자열을 만든다):

```
{"crv":"P-256","kty":"EC","x":"<x>","y":"<y>"}
```

지문의 텍스트 표현은 그 32바이트의 base64url이다(`jws.go:250-257`). Go는 `jwk` 머리에도 이 정렬된 문자열을 그대로 넣는다(`jws.go:81-87`).

### 3.5 DNS-01 값

```
keyAuthorization = token ‖ "." ‖ base64url(JWK 지문)
TXT 값           = base64url(SHA-256(keyAuthorization))
레코드 이름       = "_acme-challenge." ‖ 도메인
```

RFC 8555 8.1(키 인가), 8.4(DNS challenge). Go는 `tempfork/acme/acme.go:591-598`(`DNS01ChallengeRecord`), `:783-789`(`keyAuth`), `feature/acme/cert.go:626`(이름)이다. `token`은 base64url 알파벳의 문자만으로 된 문자열이어야 한다(RFC 8555 8.4).

### 3.6 CSR(PKCS#10)

finalize 요청은 `{"csr":"<base64url(CSR의 DER)>"}`다. PEM 머리 없이 DER를 base64url로 적는다(RFC 8555 7.4, `tempfork/acme/rfc8555.go:371-375`).

Go가 만드는 CSR: 주체는 `CN=<도메인>` 하나, 확장은 SAN(`dNSName` = 도메인) 하나, 키는 새로 만든 P-256, 서명은 ECDSA-SHA256이다(`feature/acme/certstore.go:306-317`, `feature/acme/cert.go:578-589`).

구조(RFC 2986 4절):

```
CertificationRequest ::= SEQUENCE {
  certificationRequestInfo  SEQUENCE {
    version        INTEGER 0,
    subject        Name,                    -- RDNSequence { SET { SEQUENCE { OID 2.5.4.3, UTF8String 도메인 } } }
    subjectPKInfo  SubjectPublicKeyInfo,    -- RFC 5480 2절. id-ecPublicKey + secp256r1 + 압축하지 않은 점
    attributes     [0] IMPLICIT SET OF Attribute
                   -- Attribute { OID 1.2.840.113549.1.9.14(extensionRequest),
                   --   SET { Extensions { Extension { OID 2.5.29.17(subjectAltName),
                   --     OCTET STRING { GeneralNames { [2] IA5String 도메인 } } } } } }
  },
  signatureAlgorithm  SEQUENCE { OID 1.2.840.10045.4.3.2 },   -- ecdsa-with-SHA256, 매개변수 없음(RFC 5758 3.2)
  signature           BIT STRING            -- 안 쓰는 비트 0 + DER ECDSA-Sig-Value(SEQUENCE { r INTEGER, s INTEGER })
}
```

SAN의 형식은 RFC 5280 4.2.1.6이다. `id-ecPublicKey`는 1.2.840.10045.2.1, `secp256r1`은 1.2.840.10045.3.1.7이다(RFC 5480 2.1.1, 2.1.1.1). `extensionRequest`의 OID는 PKCS#9(RFC 2985 5.4.2)의 것이다. **RFC 2985 원문은 이번에 대조하지 못했다**(8장). 서명의 입력은 `certificationRequestInfo`의 DER 바이트다(RFC 2986 4.2).

### 3.7 인증서 사슬과 개인 키의 저장 형식

Go의 파일 형식과 이름은 DNS 노트 4.9 1에 있다. 보탤 것:

- 인증서 응답은 `application/pem-certificate-chain`이다: `CERTIFICATE` PEM 블록을 leaf부터 차례로 잇는다(RFC 8555 7.4.2, 9.1). `-----BEGIN` 뒤에 `CERTIFICATE`가 아닌 것이 오면 **파일 전체를 거부해야 한다**(RFC 8555 11.4). 악의적인 서버가 개인 키 블록을 끼워 넣는 공격의 방어다. Go는 블록의 종류가 `CERTIFICATE`가 아니면 실패하고, 사슬은 5장까지, 본문은 약 5MiB까지 받는다(`tempfork/acme/rfc8555.go:405-447`, `tempfork/acme/acme.go:62-67`).
- Go는 받은 사슬을 블록마다 다시 PEM으로 적어 `<도메인>.crt`에 쓴다(`feature/acme/cert.go:600-609`).
- 개인 키는 SEC1 `ECPrivateKey`(RFC 5915 3절)를 `EC PRIVATE KEY` PEM으로 적는다(`feature/acme/certstore.go:323-330`). 계정 키를 읽을 때는 PKCS#1, PKCS#8, SEC1을 차례로 시도하므로(`certstore.go:340-359`) PKCS#8(`PRIVATE KEY`) PEM도 읽는다. 인증서 키는 Go 표준 라이브러리의 `tls.X509KeyPair`로 읽는다(`certstore.go:415`).
- 쓰는 순서는 키 파일 다음 인증서 파일이다. 각각 임시 파일 → 이름 바꾸기다(`certstore.go:156-169`, `tailscale.com/atomicfile/atomicfile.go:21-51`).

## 4. 절차와 상태 기계

### 4.1 `WhoIs`

`LocalBackend.WhoIs`의 단계는 DNS 노트 4.8에 있다. M7 구현에 필요한 세부:

1. **주소 표**: netmap이 바뀔 때마다 자기 노드와 모든 피어의 `Addresses` 가운데 **한 주소짜리 접두(/32, /128)만** 주소 → 노드 ID 표에 넣는다(`tailscale.com/ipn/ipnlocal/node_backend.go:712-732`). `AllowedIPs`(서브넷 경로 등)는 넣지 않는다. 키가 만료된 피어나 오프라인 피어를 거르지 않는다. netmap에 있으면 표에 있다.
2. **찾기**: IPv4-mapped IPv6 주소(`::ffff:100.64.0.1`)는 IPv4로 바꾼 뒤 찾는다(`local.go:1756-1758`). 표에 없으면 `ProxyMapper`로 넘어가는데(`local.go:1773-1797`), 이것은 tailscaled가 대신 맺어 준 로컬 연결의 주소를 되돌리는 길이라 tailnet 주소를 그대로 받는 리스너에는 해당이 없다.
3. **사용자**: 노드의 `User`로 프로필을 찾는다. `Sharer`가 아니라 `User`다. 프로필이 없으면 **실패**다(`local.go:1806-1811`).
4. **프로필이 netmap에 들어오는 길**: 맵 응답의 `UserProfiles`는 바뀐 것만 온다. 클라이언트는 받은 프로필을 모두 쌓아 두고(지우지 않는다), netmap을 만들 때 자기 노드의 `User`와 피어마다 `Sharer`·`User`의 프로필만 골라 넣는다(`tailscale.com/control/controlclient/map.go:384-387`, `:1054-1058`, `:674-685`). 증분으로 다시 나타난 피어의 프로필도 쌓아 둔 것에서 다시 낸다(`map.go:302-346`). Swiftail의 `MapSession`이 같은 방식이다(`Sources/SwiftailControl/Netmap/MapSession.swift:36-38`, `:198-206`).
5. **`ComputedName`**: `Name`에서 tailnet의 MagicDNS 접미사를 뗀 것이다. 그것이 비면 `Hostinfo.Hostname`을 DNS 레이블로 다듬은 것, 그것도 없으면 node 키의 텍스트다(`tailcfg/tailcfg.go:660-689`). 접미사는 자기 노드 이름에서 첫 레이블을 뗀 나머지다(`tailscale.com/types/netmap/netmap.go:268-270`). 클라이언트가 맵 응답을 받을 때 노드마다 계산한다(`direct.go:1416-1434`).
6. **태그 노드**: `User`는 노드를 만든 사용자의 ID로 남는다(3.1). 기준 소스의 한 도구는 `UserProfile.LoginName`이 `"tagged-devices"`이면 `Node.Tags`를 신원으로 쓴다(`tailscale.com/cmd/pgproxy/pgproxy.go:218-222`). 운영 제어 서버가 태그 노드의 프로필로 무엇을 보내는지는 클라이언트 소스에 없다(8장).
7. **capability**: `CapMap`은 패킷 필터의 `CapGrant`에서 나온다. 원격 노드의 첫 주소를 출발지로, 같은 주소 계열의 자기 주소를 목적지로 견준다. `UnsignedPeerAPIOnly` 피어는 ingress capability만 가질 수 있다(`node_backend.go:443-467`, `tailscale.com/ipn/localapi/localapi.go:603-620`). 첫 사용처는 읽지 않는다.
8. **로컬 API의 실패**: 못 찾으면 404이고 클라이언트는 `ErrPeerNotFound`로 받는다(`localapi.go:593-596`, `tailscale.com/client/local/local.go:353-362`). 첫 사용처는 어떤 실패든 403 `not_paired`로 답한다(RemoteDebug `core/internal/host/host.go:232-244`).

Swiftail이 이미 가진 것과 더 받아야 하는 것:

| 필요한 것 | Swiftail | 비고 |
| --- | --- | --- |
| 노드의 `StableID`, `Name`, `User`, `Sharer`, `Tags`, `Addresses`, `Hostinfo` | 있다(`Sources/SwiftailControl/Tailcfg/Node.swift`) | |
| 사용자 프로필(`LoginName`, `DisplayName`, `ProfilePicURL`) | 있다(`Netmap.userProfiles`, `Sources/SwiftailControl/Netmap/Netmap.swift:19`) | `Groups`는 해석하지 않는다(`Tailcfg/UserProfile.swift`) |
| 주소 → 노드 표 | 없다. netmap에서 만들면 된다 | 새로 받을 것은 없다 |
| `ComputedName` | 없다. 5의 규칙으로 계산하면 된다 | MagicDNS 접미사는 이름 해석 코드가 이미 구한다(`Sources/Swiftail/Netmap+HostResolution.swift`) |
| `CapMap` | 규칙은 해석한다(`Tailcfg/FilterRule.swift`의 `capGrant`). 주소 쌍으로 모으는 코드는 없다 | 첫 사용처가 쓰지 않는다 |

제어 서버에서 더 받아야 하는 것은 없다. `WhoIs`는 netmap만으로 답할 수 있다.

### 4.2 Go의 인증서 흐름(요약과 보충)

발급의 여덟 단계는 DNS 노트 4.9 4에 있다. 보탤 것:

1. **도메인별 잠금**: 발급 함수는 도메인마다 뮤텍스를 잡고, 잡은 뒤 저장된 인증서를 다시 읽어 그 사이 다른 호출이 갱신했는지 본다(`feature/acme/cert.go:345-363`).
2. **계정 준비**: 계정 키로 `onlyReturnExisting` 요청을 보내 계정을 찾고, `accountDoesNotExist`면 `termsOfServiceAgreed`로 등록한다. 등록이 "이미 있음"으로 끝나면 다시 찾는다. 계정 상태가 `valid`가 아니면 실패다(`cert.go:451-473`, `:386-392`, `tempfork/acme/rfc8555.go:126-138`, `:45-92`). 연락처는 보내지 않는다(`new(xacme.Account)`, `cert.go:460`).
3. **이미 있는 TXT 레코드**: `set-dns` 전에 시스템 리졸버로 500ms 동안 그 TXT 레코드를 찾아보고 값이 이미 있으면 `set-dns`를 건너뛴다. "최선을 다할 뿐이고, 최악의 경우 이미 있는 것을 서버에 다시 만들어 달라고 한다"는 주석이 있다(`cert.go:628-643`).
4. **`set-dns` 뒤**: 기다리지 않고 곧바로 challenge에 응답한다(`cert.go:639-650`). 레코드가 DNS에 보이기까지의 시간은 제어 서버가 응답을 미루는 것으로 맞추는 것으로 보인다(추정. 8장).
5. **challenge 응답 뒤**: authorization이 아니라 **order**를 `ready` 또는 `valid`가 될 때까지 되풀이해 읽는다. 간격은 `Retry-After`이고 없으면 1초다. `invalid`면 실패다(`cert.go:563-576`, `rfc8555.go:283-318`).
6. **인증서 키**: order가 `ready`가 된 뒤에 새 P-256 키를 만든다. 갱신 때마다 키가 바뀐다(`cert.go:578-585`).
7. **이미 `valid`인 authorization**: Go는 authorization의 상태를 보지 않고 dns-01 challenge에 늘 응답한다(`cert.go:531-561`, `:615-651`). 서버가 authorization을 재사용해 이미 `valid`인 것을 줄 때 어떻게 되는지는 실행으로 확인하지 못했다(8장).
8. **실패한 발급의 뒤처리**: 없다. 다음 호출이 처음부터 다시 한다. 재시도 간격은 호출하는 쪽의 몫이다. 첫 사용처는 30초에서 10분까지 두 배씩 늘린다(RemoteDebug `core/internal/node/node.go:825-859`).
9. **조건**: 발급 전에 netmap의 `DNS.CertDomains`를 본다. 비어 있으면 "계정이 TLS 인증서를 지원하지 않는다"로 실패하고, 요청한 이름이 목록에 **정확히** 있어야 한다(`cert.go:689-728`). 첫 사용처는 여기에 더해 `MagicDNSEnabled`를 본다(RemoteDebug `core/internal/node/tls.go:27-32`).
10. **User-Agent**: `tailscaled/<버전>` 뒤에 ACME 패키지 이름을 붙인다(`certstore.go:399-403`, `tempfork/acme/http.go:295-304`). RFC 8555 6.1은 클라이언트가 User-Agent를 보내야 한다고 정한다.

### 4.3 ACME 절차(DNS-01, 식별자 하나)

Swiftail이 구현할 순서다. 조항은 RFC 8555, 괄호는 Go의 같은 단계다.

1. **디렉터리**: `GET <디렉터리 URL>`. 응답 JSON에서 `newNonce`, `newAccount`, `newOrder`와 `meta.termsOfService`를 읽는다(7.1.1. `tempfork/acme/acme.go:166-213`). `newOrder`가 없으면 RFC 8555 서버가 아니다(`acme.go:199-201`).
2. **nonce**: 손에 쥔 nonce가 없으면 `HEAD <newNonce>`의 `Replay-Nonce` 머리에서 얻는다(7.2). POST의 응답(성공이든 오류든)이 주는 `Replay-Nonce`를 다음 요청에 쓴다(6.5). `Replay-Nonce`의 값이 base64url 문자가 아니면 무시한다(6.5.1).
3. **계정 찾기**: `POST <newAccount>`, `jwk` 머리, 본문 `{"onlyReturnExisting":true}`. 200이면 `Location` 머리가 계정 URL(`kid`)이다. 오류 종류가 `urn:ietf:params:acme:error:accountDoesNotExist`면 4로 간다(7.3.1).
4. **계정 만들기**: `POST <newAccount>`, `jwk` 머리, 본문 `{"termsOfServiceAgreed":true}`. 201(새 계정) 또는 200(같은 키의 계정이 이미 있음)이고 둘 다 `Location`이 계정 URL이다(7.3). 응답 본문의 `status`가 `valid`여야 한다(7.1.2, 7.1.6).
5. **주문**: `POST <newOrder>`, `kid` 머리, 본문 `{"identifiers":[{"type":"dns","value":"<도메인>"}]}`. 201이고 `Location`이 주문 URL이다. 본문에서 `status`, `authorizations`(URL 배열), `finalize`(URL)를 읽는다(7.4, 7.1.3).
6. **authorization 읽기**: 각 URL에 POST-as-GET. `status`, `identifier`, `challenges`를 읽는다(7.5, 7.1.4). `status`가 `valid`면 이 authorization은 끝난 것이다(7.1.6). `pending`이면 `type`이 `dns-01`인 challenge의 `url`과 `token`을 쓴다(8.4). 그 밖의 상태(`invalid`, `deactivated`, `expired`, `revoked`)는 실패다.
7. **레코드 올리기**: 3.5의 값으로 3.2의 `set-dns`를 보낸다.
8. **challenge 응답**: `POST <challenge url>`, 본문 `{}`(7.5.1). Go는 200과 202를 성공으로 본다(`acme.go:570-573`).
9. **기다리기**: 주문 URL에 POST-as-GET을 되풀이한다. `ready`면 10, `valid`면 12, `invalid`면 실패, `pending`·`processing`이면 `Retry-After`(없으면 1초) 뒤에 다시(7.1.6, 7.4).
10. **finalize**: `POST <finalize>`, 본문 `{"csr":"…"}`(3.6). 200과 갱신된 주문 객체가 온다. 주문이 `ready`가 아니었으면 403 `orderNotReady`다(7.4).
11. **발급 기다리기**: 주문이 `processing`이면 `Retry-After` 뒤에 주문 URL을 다시 읽는다. `valid`가 되면 `certificate` URL이 생긴다(7.4).
12. **내려받기**: `certificate` URL에 POST-as-GET. `Accept: application/pem-certificate-chain`(7.4.2). 3.7의 규칙으로 해석한다.

오류 응답은 `application/problem+json` 문서이고 `type`이 `urn:ietf:params:acme:error:` 아래의 종류다(6.7). 이 절차에서 따로 다루는 종류:

| 종류 | 대응 | 출처 |
| --- | --- | --- |
| `badNonce` | 그 오류 응답의 `Replay-Nonce`로 같은 요청을 다시 서명해 보낸다 | 6.5(클라이언트는 그 nonce를 써야 한다), `tempfork/acme/http.go:184-198` |
| `accountDoesNotExist` | 3 → 4 | 7.3.1 |
| `rateLimited` | `Retry-After`가 있으면 그때까지 시도하지 않는다 | 6.6 |
| `orderNotReady` | 주문을 다시 읽고 상태에 따라 간다 | 7.4 |
| `userActionRequired` | 서비스 약관이 바뀌었다. 실패로 알린다 | 7.3.3 |

Go의 일반 재시도: 상태가 399 이하이거나 500 이상이거나 429이면 다시 시도할 수 있는 응답으로 보고, `Retry-After`(없으면 1·2·4…초, 10초 상한)에 지터(1~1000ms)를 더해 기다린다(`http.go:68-90`, `:321-323`). 횟수의 상한은 없고 호출의 기한(context)이 끊는다.

### 4.4 갱신

1. Go의 기본 판정은 ARI(RFC 9773)다. 디렉터리의 `renewalInfo` URL에서 제안된 구간을 받아 그 안의 무작위 시각이 지났으면 갱신한다. 조회가 5초 안에 실패하면 **인증서 수명의 2/3 지점**이 지났는지로 본다(`feature/acme/cert.go:173-198`, `:233-251`, `:306-340`). 판정한 시각은 도메인마다 메모리에 적어 두고 다시 묻지 않는다.
2. 갱신 주문에는 이전 인증서를 가리키는 `replaces` 필드를 싣는다(RFC 9773 5절. `cert.go:394-420`, `rfc8555.go:227-228`).
3. 갱신이 필요하고 호출이 유효 기간을 요구하지 않았으면(`min_validity = 0`) 지금 인증서를 돌려주고 갱신은 뒤에서 한다. 도메인마다 하나만 돈다(`cert.go:138-153`, `:212-222`).
4. tsnet의 `Listen`만 쓰는 노드에서는 1시간짜리 백그라운드 갱신 루프가 돌지 않는다(DNS 노트 4.9 5). 그래서 첫 사용처의 Go 호스트에서 갱신은 **TLS 핸드셰이크가 올 때**(`GetCertificate`) 시작된다(RemoteDebug `core/internal/node/tls.go:41`).
5. 저장된 인증서는 읽을 때마다 검증한다: 키와 인증서가 짝이 맞고, 사슬이 그 도메인과 지금 시각으로 시스템 루트(실패하면 내장한 Let's Encrypt 루트)까지 검증되어야 한다. 실패하면 "만료"로 보고 새로 발급한다(`certstore.go:135-154`, `:411-459`).

### 4.5 Let's Encrypt의 속도 제한

`https://letsencrypt.org/docs/rate-limits/`(2026-08-05 갱신본, 2026-11-15에 읽음)에서 확인한 것이다. 구현의 재시도 간격과 관문의 발급 횟수를 이 값이 묶는다.

| 제한 | 값 | 이 구현에 주는 뜻 |
| --- | --- | --- |
| 같은 식별자 집합의 새 인증서 | 7일에 5장(34시간에 1장씩 회복). 예외 신청 불가 | **상태를 지우고 같은 이름으로 다시 발급하는 일을 되풀이하면 닿는다.** 시험은 스테이징이나 로컬 ACME 서버로 한다 |
| 등록 도메인의 새 인증서 | 7일에 50장 | "등록 도메인"은 Public Suffix List로 정한다. `ts.net` 아래 tailnet 이름이 어떻게 나뉘는지는 확인하지 못했다(8장) |
| 계정의 새 주문 | 3시간에 300개 | 닿지 않는다 |
| 식별자·계정의 authorization 실패 | 1시간에 5번(12분에 1번씩 회복) | 검증 실패 뒤의 재시도는 12분보다 촘촘하면 안 된다 |
| IP 주소의 새 계정 | 3시간에 10개 | 계정 키를 저장해 다시 쓴다 |
| 갱신의 예외 | ARI로 `replaces`를 실은 주문은 모든 제한에서 빠진다. ARI 없이 식별자 집합이 같은 주문은 "새 주문"·"등록 도메인" 제한에서만 빠지고 "같은 식별자 집합 5장"에는 걸린다 | 수명의 2/3마다 한 번 갱신하면 ARI 없이도 닿지 않는다 |
| 제한에 닿았을 때 | 오류 응답에 `Retry-After` 머리 | 4.3의 `rateLimited` |

같은 페이지가 클라이언트를 개발·시험할 때는 스테이징 환경을 쓰라고 적는다.

### 4.6 Apple 플랫폼에서 만드는 길

외부 패키지·C 코드 없이 CryptoKit과 Security 프레임워크로 되는지 따진 결과다.

| 필요한 것 | 길 | 확인 |
| --- | --- | --- |
| P-256 키 만들기 | `P256.Signing.PrivateKey()` | CryptoKit |
| JWS 서명(R ‖ S 64바이트) | `signature(for:)`의 `rawRepresentation` | 실험: 64바이트 |
| CSR 서명(DER) | 같은 서명의 `derRepresentation` | 실험: `openssl req -verify`가 통과했다 |
| JWK의 `x`·`y` | 공개 키 `x963Representation`(`04 ‖ X ‖ Y`, 65바이트)에서 자른다 | 실험: 65바이트 |
| CSR의 `SubjectPublicKeyInfo` | 공개 키 `derRepresentation`(91바이트)을 그대로 넣는다 | 실험 |
| Go가 쓴 SEC1 PEM 키 읽기 | `P256.Signing.PrivateKey(pemRepresentation:)` | 실험: OpenSSL이 만든 `EC PRIVATE KEY`를 읽었다 |
| 키 저장 | `pemRepresentation`. **PKCS#8(`PRIVATE KEY`)로 나온다.** SEC1이 아니다 | 실험. Go는 PKCS#8도 읽는다(3.7) |
| CSR의 나머지 DER | 직접 쓴다. SEQUENCE, SET, INTEGER, OID, UTF8String, OCTET STRING, BIT STRING, 문맥 태그의 **쓰기만** 필요하다. 길이는 3바이트 형식(65,535까지)이면 된다 | 실험: 열다섯 줄 안팎의 코드로 만든 295바이트 CSR이 검증됐다 |
| 인증서의 유효 기간 읽기 | `SecCertificateCopyNotValidBeforeDate`·`SecCertificateCopyNotValidAfterDate` | macOS 15·iOS 18부터(`SecCertificate.h:204-223`). 실험 |
| 사슬 검증(도메인, 시각, 루트) | `SecPolicyCreateSSL` + `SecTrustCreateWithCertificates` + `SecTrustSetVerifyDate` + `SecTrustEvaluateWithError` | 공개 API. 실험하지 않았다 |
| 인증서의 공개 키가 우리 키인지 | `SecCertificateCopyKey` + `SecKeyCopyExternalRepresentation`을 `x963Representation`과 견준다 | 공개 API. 실험하지 않았다 |
| HTTPS 요청 | `URLSession`(Foundation) | plan 4절(c)가 허용한 프레임워크 |
| base64url, PEM | 직접 쓴다(Foundation의 base64에 문자 둘을 바꾸고 채움을 뗀다) | |

X.509 인증서를 **해석하는** ASN.1 코드는 쓰지 않아도 된다. 필요한 값(유효 기간, 공개 키, 검증 결과)은 모두 Security 프레임워크가 준다.

TLS 서버 쪽(첫 사용처의 몫이지만 인증서 API의 모양을 정하는 사실이다):

- `SecIdentityCreate(allocator, certificate, privateKey)`가 공개 머리 파일에 있다(macOS 10.12·iOS 11.2부터. `SecIdentity.h:57-70`). **키체인 없이** `SecCertificate`와 `SecKey`로 `SecIdentity`를 만든다.
- 실험: `SecKeyCreateWithData`(P-256 개인 키의 X9.63 표현 `04 ‖ X ‖ Y ‖ K`, 97바이트)로 만든 키와 `SecCertificateCreateWithData`로 만든 인증서를 `SecIdentityCreate`에 넣고, 그 신원을 `sec_identity_create`로 감싸 `NWListener`(TLS, 최소 1.2, ALPN `http/1.1`)에 주었더니 루프백의 TLS 클라이언트와 핸드셰이크가 끝났고 ALPN이 `http/1.1`로 협상됐다. 키체인에 넣은 것은 없다.
- `SecPKCS12Import`도 macOS 15·iOS 18부터 `kSecImportToMemoryOnly`로 키체인을 거치지 않는다(`SecImportExport.h:652-661`, `:711-712`). PKCS#12를 만들어야 하므로 쓰지 않는다.
- 이 실험은 **App Sandbox 밖**에서 돌렸다. 샌드박스 안에서도 같은지는 확인하지 못했다(8장).

### 4.7 Go 상태 디렉터리와 신원

`tailscaled.state`의 형식과 키는 DNS 노트 3.2, 시작할 때 읽는 순서는 4.4.1, 다시 시작해도 같은 노드가 되는 데 필요한 것은 4.4.3에 있다. M7의 이관 결정에 보탤 것:

1. **tsnet이 상태 디렉터리에 두는 것**(`Dir`이 곧 varRoot다. `tailscale.com/tsnet/tsnet.go:848-869`, `:984`):

   | 경로 | 내용 | 출처 |
   | --- | --- | --- |
   | `tailscaled.state` | 신원과 prefs(JSON, 값은 base64) | `tsnet.go:965-972` |
   | `tailscaled.log.conf` | 로그 업로드용 ID 설정 | `tsnet.go:1104` |
   | `tailscaled`로 시작하는 로그 버퍼 파일 | 업로드 전의 로그 | `tsnet.go:1120` |
   | `certs/` | 인증서, 인증서 키, ACME 계정 키(3.7) | `feature/acme/certstore.go:64-81` |

   첫 사용처는 같은 디렉터리에 직접 연결 리스너의 `direct.json`, `direct-key.pem`, `direct-cert.pem`도 둔다(RemoteDebug `core/internal/direct/direct.go:30-35`). 이 셋은 Tailscale의 것이 아니다. iPhone이 그 키를 고정하므로 호스트를 바꿔도 남아야 한다.

2. **신원이 든 값**: `_machinekey`(machine 개인 키), `_current-profile`이 가리키는 `profile-<id>`의 `Config.PrivateNodeKey`(node 개인 키), 같은 곳의 `Config.OldPrivateNodeKey`, `Config.NetworkLockKey`, `Config.NodeID`, `Config.UserProfile`, 그리고 prefs의 `ControlURL`·`LoggedOut`(DNS 노트 3.2). 키의 텍스트는 `privkey:` + hex 64자다(`tailscale.com/types/key/node.go:29`, `:115-127`).

3. **Swiftail과의 대응**:

   | Go | Swiftail `identity.json` | 비고 |
   | --- | --- | --- |
   | `_machinekey` | `MachineKey` | 텍스트 형식이 같다(`Sources/SwiftailControl/Client/NodeIdentityStore.swift`의 형식 설명) |
   | `Config.PrivateNodeKey` | `NodeKey` | 같다. Go에서 0이면(로그인한 적 없음) Swiftail은 키를 비운다 |
   | `Config.OldPrivateNodeKey` | 없다 | 키를 바꾸는 등록 요청에만 쓴다. 가져올 때는 필요 없다 |
   | `Config.NetworkLockKey` | 없다 | Swiftail은 `NLKey`를 0으로 보낸다(8장) |
   | `Config.NodeID`, `Config.UserProfile`, `_profiles` | 없다 | Go의 프로필 관리용이다. 재등록에 쓰지 않는다(DNS 노트 4.4.3) |
   | prefs의 `ControlURL` | 없다(`NodeConfiguration.controlURL`이 준다) | 가져올 때 둘이 같은 서버인지 견줘야 한다. Go에서 비어 있으면 기본 제어 서버다(DNS 노트 4.4.3) |
   | prefs의 `LoggedOut` | 없다 | 참이면 그 노드는 로그아웃된 상태다 |
   | `certs/<도메인>.crt`·`.key`, `certs/acme-account.key.pem` | 같은 이름으로 둘 수 있다 | 4.6: Go의 SEC1 PEM을 CryptoKit이 읽는다 |

4. **같은 node 키를 두 구현이 함께 쓰면**: 제어 서버에는 같은 노드의 맵 세션이 둘 열리고, 두 프로세스가 서로 다른 엔드포인트와 disco 키를 올린다. DERP에는 같은 키의 클라이언트가 둘 붙는다. 서버 쪽이 이것을 어떻게 다루는지는 클라이언트 소스로 알 수 없다(8장). 한쪽이 node 키를 바꾸면(만료 뒤 재인증) 다른 쪽이 쥔 키는 등록 요청의 `OldNodeKey`로만 뜻이 있고 그 상태 파일은 옛 신원이 된다(`tailscale.com/control/controlclient/direct.go:704-723`).

## 5. 상수와 타이머

| 이름 | 값 | 출처 |
| --- | --- | --- |
| Let's Encrypt 디렉터리 | `https://acme-v02.api.letsencrypt.org/directory` | `tempfork/acme/acme.go:47` |
| 디렉터리 바꾸기(Go) | 환경 변수 `TS_DEBUG_ACME_DIRECTORY_URL` | `feature/acme/certstore.go:402` |
| 사슬의 인증서 수 상한 | 5 | `acme.go:63`, `rfc8555.go:439` |
| 인증서 한 장의 크기 상한 | 1MiB | `acme.go:64` |
| nonce 보관 상한 | 100개("보통 1~2개") | `acme.go:69-71` |
| 재시도 물러나기 | 1·2·4…초, 10초 상한, 지터 1~1000ms. `Retry-After`가 있으면 그 값 | `http.go:68-90` |
| 주문 다시 읽기 간격 | `Retry-After`, 없으면 1초 | `rfc8555.go:303-308` |
| ARI 조회 기한 | 5초 | `feature/acme/cert.go:324` |
| 갱신 시점(ARI 없이) | 수명의 2/3 | `cert.go:248` |
| TXT 사전 조회 기한 | 500ms | `cert.go:632` |
| 인증서 디렉터리 | `<varRoot>/certs`, 0700 | `certstore.go:64-81` |
| 파일 권한 | 키·계정 키 0600, 인증서 0644 | `certstore.go:130-162` |
| 첫 사용처: 발급 한 번의 기한 | 2분 | RemoteDebug `core/internal/node/node.go:836` |
| 첫 사용처: 재시도 간격 | 30초에서 10분까지 두 배씩 | RemoteDebug `node.go:55-56`, `:849` |
| 첫 사용처: WhoIs 기한 | 5초 | RemoteDebug `core/internal/host/host.go:236` |

## 6. Swiftail에 필요한 최소 부분과 생략할 수 있는 부분

필요한 최소

- `whoIs`: 4.1의 1~3과 5. 반환은 `StableID`, 이름, `ComputedName`, 태그, 사용자 프로필(`LoginName`, `DisplayName`).
- 제어 `set-dns`: 3.2.
- ACME: 4.3의 열두 단계, 3.3~3.6의 형식, `badNonce`·`rateLimited` 처리, P-256 계정 키 하나와 인증서 키.
- 저장: 3.7의 파일 이름과 PEM. Go와 같은 이름을 쓰면 Go가 받아 둔 인증서를 그대로 읽을 수 있다(4.6의 SEC1 읽기).
- 검증: 4.4 5(읽을 때마다), 내려받은 사슬의 3.7 규칙.
- 갱신: 수명의 2/3.

생략(근거)

| 생략 | 근거 |
| --- | --- |
| ARI와 `replaces` | 2/3 규칙이면 "같은 식별자 집합 5장"에 닿지 않는다(4.5). Go도 ARI가 실패하면 2/3로 간다 |
| TXT 사전 조회 | Go의 주석대로 최악이 "이미 있는 것을 다시 올림"이다(4.2 3). 터널 밖의 시스템 리졸버에 기대는 코드가 준다 |
| TLS-ALPN-01, 와일드카드, BYO 도메인 | Funnel·Serve용이다(plan 3절 제외). 첫 사용처는 자기 FQDN 하나만 쓴다 |
| RSA·P-384 키, 외부 계정 결속(EAB), 연락처, 계정 키 교체, 계정 비활성화, 인증서 폐기 | Go의 Tailscale 통합이 쓰지 않는다(4.2 2) |
| 대체 사슬(`Link: rel="alternate"`) | Go가 쓰지 않는다 |
| nonce 여러 개 보관 | 요청을 차례로 보내므로 마지막 응답의 것 하나면 된다 |
| `CapMap`, node 키로 찾기, `ProxyMapper` | 첫 사용처가 쓰지 않는다(4.1 2·7) |
| X.509 해석기 | 4.6 |
| Kubernetes 저장소, `TS_CERT_SHARE_MODE` | 해당 없음 |

## 7. 상호 운용 시험에서 확인할 것

1. **Go 기준값**: 같은 계정 키와 입력으로 Go(`tempfork/acme`와 표준 라이브러리)가 만든 JWK 문자열, 지문, 키 인가, DNS-01 TXT 값, JWS의 보호 머리·서명 입력과, Swift가 만든 것이 바이트까지 같다. ECDSA 서명은 실행마다 다르므로 서명은 상대 구현이 검증하는 것으로 본다(Go가 만든 JWS를 Swift가, Swift가 만든 것을 Go가).
2. **CSR**: Swift가 만든 CSR을 Go `x509.ParseCertificateRequest` + `CheckSignature`가 받아들이고 주체·SAN이 같다. Go `certRequest`가 만든 CSR과 서명 앞부분(`certificationRequestInfo`)의 구조가 같다(공개 키가 같을 때 바이트까지).
3. **`set-dns`**: `testcontrol`의 `/machine/set-dns` 처리기는 요청을 검사한다. `Type`이 `TXT`, `Name`·`Value`가 비지 않음, node 키가 그 machine 키의 것, `Name`이 `_acme-challenge.` + 그 노드의 cert 도메인(`tailscale.com/tstest/integration/testcontrol/testcontrol.go:605-649`). `OnSetDNS` 훅으로 받은 값을 시험이 볼 수 있다(`:66`, `:641-646`).
4. **cert 도메인**: `testcontrol`은 `DNSConfig`가 있고 `MagicDNSDomain`이 비지 않으면 netmap의 `CertDomains`에 `<Hostinfo.Hostname>.<MagicDNSDomain>`을 더한다(`testcontrol.go:1655-1668`, `:651-663`). Swiftail의 시험 도구는 `MagicDNSDomain`을 이미 준다(`Tools/interop/cmd/tailnet/main.go:115`).
5. **전체 발급**: 로컬 ACME 서버(pebble)를 상대로 4.3의 열두 단계가 끝나고 받은 사슬이 그 서버의 루트로 검증된다. pebble은 `va.New(…, customResolverAddr, …)`로 DNS 검증에 쓸 리졸버를 받고(`github.com/letsencrypt/pebble/v2@v2.10.3/va/va.go:121-140`), challtestsrv는 `AddDNSTXTRecord(host, content)`로 TXT 레코드를 넣는 DNS 서버를 낸다(`github.com/letsencrypt/challtestsrv@v1.4.2`). `testcontrol`의 `OnSetDNS`를 그것에 이으면 계정 없이 `set-dns` → DNS-01 검증 → 발급이 한 프로세스에서 돈다. pebble은 환경 변수로 nonce 거부 비율(`PEBBLE_WFE_NONCEREJECT`)과 authorization 재사용(`PEBBLE_AUTHZREUSE`)을 조절하므로 `badNonce` 재시도와 4.2 7의 경우를 함께 볼 수 있다. **두 모듈을 받아 구조만 읽었고 빌드해 보지는 않았다**(8장).
6. **`WhoIs` 대조**: 같은 netmap에서 Go 피어의 `LocalClient().WhoIs(주소)`가 돌려준 `StableID`·`Name`·`ComputedName`·`LoginName`과 Swift `whoIs`의 값이 같다. 자기 주소, 피어의 IPv4·IPv6 주소, 없는 주소.
7. **Go 상태 파일**: Go tsnet 노드가 쓴 `tailscaled.state`에서 읽은 machine 키·node 키로 Swift 노드를 띄우면 같은 node 키·같은 tailnet IP·같은 `StableID`로 뜬다. Go가 쓴 `certs/` 아래 파일을 Swift가 읽어 검증한다.
8. **실제 Let's Encrypt**(계정 필요): 실제 제어 서버의 `set-dns`가 받아 주고, 발급된 인증서로 iOS 설치기(`itms-services`)가 내려받는다. 로컬에서는 확인할 수 없다.

## 8. 확인하지 못한 것

- **운영 제어 서버의 `set-dns`**: 요청을 받아들이는 조건(HTTPS가 켜진 tailnet, 임시 노드, 선언한 CapabilityVersion), 레코드가 권한 DNS에 보일 때까지 응답을 미루는지, 호출 빈도 제한, 오류 본문의 형식. 클라이언트 소스에는 요청과 200 판정만 있다. `testcontrol`의 처리기는 운영 서버의 구현이 아니다.
- **태그 노드와 공유 노드의 프로필**: 운영 서버가 태그 노드의 `User`와 그 프로필(`LoginName`)로 무엇을 보내는지, 공유받은 노드의 `User`·`Sharer` 프로필이 늘 함께 오는지. 근거는 4.1 6의 도구 코드와 주석뿐이다.
- **authorization 재사용**: Let's Encrypt가 이미 `valid`인 authorization을 주는지와 그때 Go 흐름(4.2 7)이 어떻게 끝나는지.
- **`ts.net`과 Public Suffix List**: "등록 도메인의 새 인증서 50장" 제한이 tailnet마다인지 `ts.net` 전체인지.
- **MagicDNS와 HTTPS의 관계**: `CertDomains`가 비지 않으면 MagicDNS가 늘 켜져 있는지. 첫 사용처는 둘을 따로 본다(4.2 9).
- **RFC 2985 원문**: `extensionRequest` 속성의 OID와 형식(3.6). OpenSSL이 그 CSR을 받아들이는 것으로만 확인했다.
- **App Sandbox 안**: `SecIdentityCreate`, `SecKeyCreateWithData`, 루프백의 `NWListener`, `URLSession`이 네트워크 서버·클라이언트 권한만으로 도는지. 실험은 샌드박스 밖에서 했다.
- **`SecTrust`로 하는 사슬 검증과 공개 키 비교**(4.6): API가 공개라는 것만 확인했고 돌려 보지 않았다. 중간 인증서를 TLS 핸드셰이크에 싣는 길(`sec_identity_create_with_certificates`)도 돌려 보지 않았다.
- **pebble·challtestsrv를 `Tools/interop`에 넣기**: 모듈(MPL-2.0, `go 1.25`)을 받아 패키지와 함수 서명을 읽었다. 빌드와 실행은 하지 않았다. `testcontrol`과 한 프로세스에서 도는지, 의존 모듈이 `tailscale.com`의 고정 버전과 충돌하지 않는지 모른다.
- **Go 상태를 가져온 노드의 재등록**: Swiftail은 등록 요청의 `NLKey`를 0으로 보낸다. Go가 `NLKey`를 실어 등록한 노드가 0으로 다시 붙을 때 서버가 어떻게 하는지(DNS 노트 8.1과 같은 물음), 같은 node 키로 두 구현이 동시에 맵 스트림을 열 때 서버와 DERP의 동작.
- **Let's Encrypt의 인증서 수명**: 2/3 규칙은 수명에 비례하므로 수명이 줄어도 맞지만, 지금 운영 서버가 주는 수명을 실제 발급으로 확인하지 못했다.
