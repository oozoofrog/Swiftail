# WhoIs·ts.net 인증서·Go 상태 파일 노트

## 1. 머리말

| 항목 | 내용 |
| --- | --- |
| 기준 버전 | `tailscale.com` v1.104.6 (CapabilityVersion 148). ACME 클라이언트는 그 안의 `tempfork/acme`(`golang.org/x/crypto/acme`의 포크) |
| 규격 | RFC 8555(ACME), RFC 7515(JWS), RFC 7517(JWK), RFC 7518(JWA), RFC 7638(JWK 지문), RFC 2985(PKCS#9)·2986(PKCS#10), RFC 5280(X.509 확장), RFC 3279·5480·5758·5915(EC 키와 서명의 ASN.1), RFC 7807(문제 문서), RFC 8737(TLS-ALPN-01, 제외 경계), RFC 9773(ARI). RFC Editor의 원문(`https://www.rfc-editor.org/rfc/rfcNNNN.txt`)에서 조항을 확인했다 |
| 쓰는 마일스톤 | M7(`docs/contracts/SwiftailHost.md`) |
| 작성 모델 | Claude Fable 5.2 (`claude-fable-5-2`), 2026-11-15 |
| 검증 | **검증됨**: GPT-6.1 Sol, 2026-11-15. Tailscale v1.104.6, RFC Editor 원문 20개, Let's Encrypt 공식 문서·PSL, Go 1.27.3 표준 라이브러리, SDK 대조. 주장별 판정은 9장, 남은 미확인은 8장 |

[dns-state-node.md](dns-state-node.md)의 3.2(Go 상태 파일), 4.8(`WhoIs`), 4.9(ts.net 인증서)를 M7 구현에 필요한 깊이로 넓힌 노트다. 그 노트에 이미 있는 사실은 되풀이하지 않고 절 번호로 가리킨다(아래에서 "DNS 노트"). 출처는 모듈 루트 기준 `경로:줄`이다. 첫 사용처(RemoteDebug)의 코드는 그 저장소 `2814b2c`의 경로로 적는다. 예시 값은 가짜(`rd-mac-1a2b3c4d.tail0001.ts.net`, `100.64.0.1`)다.

검증 출처의 `tailscale.com/`은 v1.104.6 모듈 루트다. 이 버전의 인증서 구현은 `ipn/ipnlocal/cert.go`가 아니라 `feature/acme/cert.go`·`certstore.go`이고, backend의 hook은 `feature/acme/acme.go:198-212`가 잇는다. Go 표준 라이브러리 경로는 **Go 1.27.3의 `src/` 기준**이다. RFC 원문은 RFC Editor의 `https://www.rfc-editor.org/rfc/rfcNNNN.txt`에서 모두 수신했다: 1034·1123·2985·2986·3279·4648·5280·5480·5758·5915·7231·7468·7515·7517·7518·7638·7807·8555·8737·9773.

Apple API 선언은 `MacOSX.sdk`의 `Security.framework/Headers/`와 `CryptoKit.framework/Modules/CryptoKit.swiftmodule/arm64e-apple-macos.swiftinterface`(이하 `CryptoKit.swiftinterface`)에 대조했다. 4.6의 작은 형식 검증만 이번 세션에서 다시 실행했다. 작성 세션의 CSR·TLS 네트워크 실험은 자료가 없어 8장으로 옮겼다. 구현 제안과 앞으로 할 시험은 검증된 실행 결과와 구별한다.

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
| `ComputedName` | control이 계산해 보내는 필드가 아니다. 클라이언트가 계산한다(4.1 5). JSON 태그는 있으므로 LocalAPI의 `Node` JSON에는 나타날 수 있다(`tailcfg/tailcfg.go:496-503`) |

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

응답: 상태가 200이 아니면 실패이고, 읽은 본문을 `TrimSpace`한 뒤 최대 200 Unicode code point를 오류에 싣는다(Go `fmt`의 `%.200s`는 바이트가 아니라 rune 수다; `fmt/doc.go:116-130`). 200이면 `SetDNSResponse`(필드 없는 Go 구조체)로 JSON 한 값을 decode한다. 빈 본문은 EOF로 실패하지만, `{}`만 허용하는 검사는 아니며 Go `encoding/json`은 `null`도 받아들인다(`direct.go:1770-1778`, `tailcfg/tailcfg.go:2620-2621`, Go `encoding/json/decode.go:94-98`). Noise 응답의 기본 본문 한도는 1MiB다(`control/ts2021/client.go:320-336`, `util/httpbody/httpbody.go:30-34`). Swiftail 계약 D3의 4KiB·JSON 객체 한정·오류 본문 비노출은 별도 제한이다.

`LocalBackend.SetDNS`는 control client가 없으면 `not connected`, node 키가 0이면 `no nodekey`로 즉시 실패한다(`ipn/ipnlocal/local.go:7820-7839`). 맵 스트림과 **같은 Noise client**를 쓰지만 같은 HTTP/2 물리 연결 하나를 보장하는 뜻은 아니다(`control/controlclient/direct.go:1761-1765`, `control/ts2021/client.go:254-290`).

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

이 노트에서 만드는 P-256 공개 키의 최소 JWK는 `crv`(`"P-256"`), `kty`(`"EC"`), `x`, `y` 네 멤버다. `x`·`y`는 좌표를 32바이트 빅엔디언으로 채운 뒤 base64url로 적는다(RFC 7517 4.1, RFC 7518 6.2.1, `jws.go:160-196`).

ACME의 지문(thumbprint)은 **필수 멤버만, 이름의 Unicode code point 순서로, 공백 없이** 적은 JSON의 UTF-8 바이트에 SHA-256을 적용한다. RFC 7638 자체는 해시 H를 매개변수로 두며, SHA-256을 고정하는 것은 RFC 8555 8.1이다(RFC 7638 3·3.2·3.3·3.4). P-256이면 입력은 정확히 다음 바이트열이다(`jws.go:189-193`이 같은 문자열을 만든다):

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

RFC 8555 8.1(키 인가), 8.4(DNS challenge). Go는 `tempfork/acme/acme.go:591-598`(`DNS01ChallengeRecord`), `:783-789`(`keyAuth`), `feature/acme/cert.go:626`(이름)이다. `token`은 채움 없는 base64url 알파벳만 써야 하고 서버가 최소 128비트 엔트로피로 만들어야 한다. 클라이언트가 문자열만 보고 엔트로피를 증명할 수는 없다(RFC 8555 8.4). P-256 JWK 좌표는 선행 0을 버리지 않고 각각 32바이트를 유지한다(RFC 7518 6.2.1.2·6.2.1.3). TXT 값은 SHA-256 32바이트의 base64url이므로 43 ASCII 바이트이며, JSON `Value`에는 DNS 표시용 따옴표를 덧붙이지 않는다(위 식, `feature/acme/cert.go:620-639`).

### 3.6 CSR(PKCS#10)

finalize 요청은 `{"csr":"<base64url(CSR의 DER)>"}`다. PEM 머리 없이 DER를 base64url로 적는다(RFC 8555 7.4, `tempfork/acme/rfc8555.go:371-375`).

Go가 만드는 CSR: 주체는 `CN=<도메인>` 하나, 확장은 SAN(`dNSName` = 도메인) 하나, 키는 새로 만든 P-256, 서명은 ECDSA-SHA256이다(`feature/acme/certstore.go:306-317`, `feature/acme/cert.go:578-589`).

구조(RFC 2986 4절):

```
CertificationRequest ::= SEQUENCE {
  certificationRequestInfo  SEQUENCE {
    version        INTEGER 0,
    subject        Name,                    -- RDNSequence { SET { SEQUENCE { OID 2.5.4.3, PrintableString 도메인 } } }
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

위 주체의 `PrintableString`(tag 0x13)은 이 노트의 ASCII 이름에 대한 **Go와 같은 인코딩**이다. `UTF8String`(0x0C)도 이름의 DirectoryString 선택지지만 Go와 DER 바이트가 달라진다(RFC 5280 4.1.2.4, Go `crypto/x509/pkix/pkix.go:258-259`, `encoding/asn1/marshal.go:638-652`). 이번 검증 프로그램에서도 CN tag 19, ECDSA-SHA256, SAN 하나, `CheckSignature=<nil>`을 확인했다.

SAN의 형식은 RFC 5280 4.2.1.6이다. `dNSName`은 `[2] IMPLICIT IA5String`(tag 0x82)이고 SAN을 감싸는 `extnValue`는 OCTET STRING이다. `critical`은 기본값 false이므로 위 요청에서는 생략한다(RFC 5280 4.1·4.2, Go `crypto/x509/x509.go:1614-1630`). `id-ecPublicKey`는 1.2.840.10045.2.1, `secp256r1`은 1.2.840.10045.3.1.7이다(RFC 5480 2.1.1, 2.1.1.1). `extensionRequest`의 OID와 단일 `Extensions` 값은 PKCS#9(RFC 2985 5.4.2·부록 A)에서 확인했다. ECDSA의 `(r,s)`는 DER SEQUENCE 안의 양수 INTEGER 두 개다(RFC 3279 2.2.3); 필요한 선행 0x00을 넣으며 JWS의 고정 64바이트와 혼동하지 않는다. 서명의 입력은 `certificationRequestInfo`의 DER 바이트다(RFC 2986 4.2).

### 3.7 인증서 사슬과 개인 키의 저장 형식

기본 파일 저장소는 `<varRoot>/certs/`(생성 권한 0700) 아래 `acme-account.key.pem`(0600), `<도메인>.key`(0600), `<도메인>.crt`(0644)다(`feature/acme/certstore.go:64-81`, `:116-168`, `:284-288`). `MkdirAll`은 기존 디렉터리 권한을 고친다는 보장이 아니다. 보탤 것:

- 인증서 응답은 `application/pem-certificate-chain`이다: `CERTIFICATE` PEM 블록을 leaf부터 차례로 잇는다(RFC 8555 7.4.2, 9.1). `-----BEGIN` 뒤에 `CERTIFICATE`가 아닌 것이 오면 **파일 전체를 거부해야 한다**(RFC 8555 11.4). 악의적인 서버가 개인 키 블록을 끼워 넣는 공격의 방어다. Go의 bundle 경로는 **PEM decode에 성공한** 블록의 종류가 `CERTIFICATE`가 아니면 실패하고, 빈 사슬·6장 이상을 거절한다. 본문 상한은 정확히 `5 × 1MiB + floor(5 × 1MiB / 33)` = 5,401,755바이트다. RFC 경로에서는 각 DER가 1MiB 이하인지 따로 검사하지 않는다(`tempfork/acme/rfc8555.go:412-446`, `acme.go:62-67`). `pem.Decode`가 nil이면 루프를 끝내므로 잘못된 BEGIN/남은 쓰레기를 모두 거부하는 구현도 아니다. Swiftail은 RFC 8555 9.1·11.4에 맞춰 전체 입력을 검사해야 한다.
- Go는 받은 사슬을 블록마다 다시 PEM으로 적어 `<도메인>.crt`에 쓴다(`feature/acme/cert.go:600-609`).
- 개인 키는 SEC1 `ECPrivateKey`(RFC 5915 3절)를 `EC PRIVATE KEY` PEM으로 적는다(`feature/acme/certstore.go:323-330`). 계정 키를 읽을 때는 PKCS#1, PKCS#8, SEC1을 차례로 시도하므로(`certstore.go:340-359`) PKCS#8(`PRIVATE KEY`) PEM도 읽는다. 인증서 키는 Go 표준 라이브러리의 `tls.X509KeyPair`로 읽는다(`certstore.go:415`).
- 쓰는 순서는 키 파일 다음 인증서 파일이다. 각각 같은 디렉터리의 임시 파일 → 권한 설정 → `Sync` → 닫기 → 이름 바꾸기다. **두 파일을 묶은 트랜잭션은 아니다**. 둘 사이에 멈추면 다음 읽기의 키 짝 검증이 불일치를 잡는다(`certstore.go:156-169`, `atomicfile/atomicfile.go:21-51`, `certstore.go:415-417`).
- 인증서 응답의 대체 사슬은 같은 leaf를 두고 `Link: rel="alternate"`로 올 수 있다(RFC 8555 7.4.2). `tempfork/acme`에는 `ListCertAlternates`가 있지만(`rfc8555.go:475-492`), Tailscale의 발급 경로는 `CreateOrderCert(..., true)`가 고른 기본 사슬만 저장한다(`feature/acme/cert.go:594-607`). 루트 인증서는 응답에서 **생략할 수 있을 뿐 반드시 없어야 하는 것은 아니다**(RFC 8555 9.1).

## 4. 절차와 상태 기계

### 4.1 `WhoIs`

`LocalBackend.WhoIs`의 단계는 DNS 노트 4.8에 있다. M7 구현에 필요한 세부:

1. **주소 표**: netmap이 바뀔 때마다 자기 노드와 모든 피어의 `Addresses` 가운데 **한 주소짜리 접두(/32, /128)만** 주소 → 노드 ID 표에 넣는다(`tailscale.com/ipn/ipnlocal/node_backend.go:712-732`). `AllowedIPs`(서브넷 경로 등)는 넣지 않는다. 키가 만료된 피어나 오프라인 피어를 거르지 않는다. netmap에 있으면 표에 있다.
2. **찾기**: IPv4-mapped IPv6 주소(`::ffff:100.64.0.1`)는 IPv4로 바꾼 뒤 찾는다(`local.go:1756-1758`). 표에 없으면 `ProxyMapper`로 넘어가는데(`local.go:1773-1797`), 이것은 tailscaled가 대신 맺어 준 로컬 연결의 주소를 되돌리는 길이라 tailnet 주소를 그대로 받는 리스너에는 해당이 없다.
3. **사용자**: 노드의 `User`로 프로필을 찾는다. `Sharer`가 아니라 `User`다. 프로필이 없으면 **실패**다(`local.go:1806-1811`).
4. **프로필이 netmap에 들어오는 길**: 맵 응답의 `UserProfiles`는 바뀐 것만 온다. 클라이언트는 받은 프로필을 모두 쌓아 두고(지우지 않는다), netmap을 만들 때 자기 노드의 `User`와 피어마다 `Sharer`·`User`의 프로필만 골라 넣는다(`tailscale.com/control/controlclient/map.go:384-387`, `:1054-1058`, `:674-685`). 증분으로 다시 나타난 피어의 프로필도 쌓아 둔 것에서 다시 낸다(`map.go:302-346`). Swiftail의 `MapSession`이 같은 방식이다(`Sources/SwiftailControl/Netmap/MapSession.swift:36-38`, `:198-206`).
5. **`ComputedName`**: `dnsname.TrimSuffix(Name, suffix)`다. 자기 tailnet의 접미사가 레이블 경계에서 일치할 때만 떼고, 끝 점을 뗀다. **다른 tailnet에서 공유받은 이름은 접미사가 다르므로 FQDN(끝 점 없음)이 남는다.** 결과가 비면 `Hostinfo.Hostname`에서 `.local`·`.localdomain`·`.lan`을 떼고 `SanitizeLabel`한 것, 그것도 비면 `Node.Key.String()`(`nodekey:` + hex)이다(`tailcfg/tailcfg.go:660-689`, `util/dnsname/dnsname.go:203-239`, `:162-200`, `types/key/node.go:322-328`). 접미사는 자기 이름 양 끝의 점을 모두 뗀 뒤 첫 점 뒤의 나머지이며, 점이 없으면 이름 그대로다(`types/netmap/netmap.go:256-270`). 맵 응답의 자기 노드·Peers·PeersChanged에 대해 계산한다(`control/controlclient/direct.go:1419-1434`).
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

주소로 `Node`·`UserProfile`을 찾는 데 제어 서버에서 더 받아야 하는 필드는 없다(`local.go:1771-1811`). `CapMap`까지 재현하려면 netmap에서 만든 현재 패킷 필터도 있어야 한다(`node_backend.go:443-467`).

LocalAPI 경로는 `tsnet.Server.LocalClient()` → `client/local.Client.WhoIs` → `GET /localapi/v0/whois?addr=<URL escape>` → `serveWhoIs` → backend다(`tsnet/tsnet.go:449-453`, `client/local/local.go:353-361`, `ipn/localapi/localapi.go:552-599`). `addr`는 IP, IP:port 또는 node 공개 키이며 누락·파싱 실패는 400, 읽기 권한 없음은 403, 찾기 실패는 404다(`localapi.go:552-596`). 기본 WhoIs는 proxy 주소를 TCP 다음 UDP 순서로 찾는다(`local.go:1773-1797`). `svc_name`·`dst_ip`를 주면 capability의 목적지가 달라진다(`localapi.go:601-620`). Swiftail 최소 범위는 주소 조회와 기본 신원뿐이다(6장).

### 4.2 Go의 인증서 흐름(요약과 보충)

발급의 여덟 단계는 DNS 노트 4.9 4에 있다. 보탤 것:

1. **도메인별 잠금**: 발급 함수는 도메인마다 뮤텍스를 잡고, 잡은 뒤 저장된 인증서를 다시 읽어 그 사이 다른 호출이 갱신했는지 본다(`feature/acme/cert.go:345-363`).
2. **계정 준비**: 계정 키로 `onlyReturnExisting` 요청을 보내 계정을 찾고, `accountDoesNotExist`면 `termsOfServiceAgreed`로 등록한다(Go는 directory에 약관 URL이 있을 때만 이 true 필드를 보낸다; `rfc8555.go:49-61`). 등록이 "이미 있음"으로 끝나면 다시 찾는다. 계정 상태가 `valid`가 아니면 실패다(`cert.go:451-473`, `:386-392`, `tempfork/acme/rfc8555.go:126-138`, `:45-92`). 연락처는 보내지 않는다(`new(xacme.Account)`, `cert.go:460`).
3. **이미 있는 TXT 레코드**: `set-dns` 전에 시스템 리졸버로 500ms 동안 그 TXT 레코드를 찾아보고 값이 이미 있으면 `set-dns`를 건너뛴다. "최선을 다할 뿐이고, 최악의 경우 이미 있는 것을 서버에 다시 만들어 달라고 한다"는 주석이 있다(`cert.go:628-643`).
4. **`set-dns` 뒤**: 클라이언트 쪽 전파 대기·재조회 없이 곧바로 challenge에 응답한다(`cert.go:639-650`). 운영 서버가 응답을 미루는지는 확인하지 못했다(8장).
5. **challenge 응답 뒤**: authorization이 아니라 **order**를 `ready` 또는 `valid`가 될 때까지 되풀이해 읽는다. 간격은 `Retry-After`이고 없으면 1초다. `invalid`면 실패다(`cert.go:563-576`, `rfc8555.go:283-318`).
6. **인증서 키**: `WaitOrder`가 `ready` 또는 `valid`를 돌려준 뒤에 새 P-256 키를 만들고, 어느 경우든 CSR과 finalize를 보낸다(`cert.go:564-594`). 정상 새 발급은 `ready` 경로다. 갱신 때마다 키가 바뀐다(`cert.go:578-585`).
7. **이미 `valid`인 authorization**: Go는 authorization의 상태를 보지 않고 dns-01 challenge에 늘 응답한다(`cert.go:531-561`, `:615-651`). 서버가 authorization을 재사용해 이미 `valid`인 것을 줄 때 어떻게 되는지는 실행으로 확인하지 못했다(8장).
8. **실패한 발급의 뒤처리**: DNS-01 경로에는 TXT 삭제·주문 취소·주문 URL 재개 저장이 없다(`cert.go:487-654`); TLS-ALPN-01은 임시 challenge 인증서를 `defer cleanup`으로 지운다(`cert.go:547-548`). 잠금과 갱신 중 표시는 성공·실패 모두 해제된다(`cert.go:145-149`, `:346-348`). 저장된 계정 키·인증서는 남고 다음 발급 호출은 새 주문으로 시작한다. ACME HTTP 요청 내부 재시도(4.3)와 발급 전체 재시도를 구분한다. 첫 사용처는 30초에서 10분까지 두 배씩 늘린다(RemoteDebug `core/internal/node/node.go:825-859`).
9. **조건**: M7 범위인 일반 ts.net 이름은 netmap이 있어야 하고 `DNS.CertDomains`가 비지 않아야 하며 목록에 **정확히** 있어야 한다(`cert.go:689-728`). Go 전체에는 capability가 허용한 와일드카드와 BYO Funnel 예외가 있다(`cert.go:700-724`). 캐시 읽기보다 먼저 끝 점 하나를 떼고 경로용 이름 검사와 이 허용 검사를 한다(`cert.go:91-121`). 경로 검사는 빈 이름·`..`·`:`·`/`·`\`·NUL·점 없는 이름을 거절하고 `*.` 이외의 별표를 거절한다. 일반 DNS 레이블 길이·문자 전체를 검증하는 함수는 아니다(`cert.go:656-677`). 첫 사용처는 여기에 더해 `MagicDNSEnabled`를 본다(RemoteDebug `core/internal/node/tls.go:27-32`).
10. **User-Agent**: `tailscaled/<버전>` 뒤에 ACME 패키지 이름을 붙인다(`certstore.go:399-403`, `tempfork/acme/http.go:295-304`). RFC 8555 6.1은 클라이언트가 User-Agent를 보내야 한다고 정한다.
11. **범위 밖 challenge 분기**: Go는 와일드카드면 DNS-01, Funnel `:443`이 아니어도 DNS-01이다. BYO Funnel은 첫 발급부터 TLS-ALPN-01, 일반 Funnel은 유효한 이전 인증서가 있을 때 TLS-ALPN-01을 먼저 시도한다. 실패하면 context 취소·BYO인 경우 오류로 끝내고, 나머지는 DNS-01 새 주문으로 fallback한다(`cert.go:253-290`, `:428-446`). TLS-ALPN-01은 RFC 8737 3·4절의 `acme-tls/1`과 critical `acmeIdentifier` 확장을 쓰는 별도 challenge이므로 DNS-01의 TXT와 혼합하지 않는다.
12. **캐시·읽기 전용 분기**: 갱신 판정 자체가 실패해도 유효한 캐시는 반환한다(`cert.go:128-134`). `TS_CERT_SHARE_MODE=ro`는 유효 캐시만 반환하고 없거나 무효면 발급하지 않는다(`cert.go:123-125`, `:158-160`). 사용 가능한 캐시가 없는 발급 중에는 health 경고를 켰다 끝날 때 해제한다(`cert.go:367-375`, `:730-748`). 이 사용자 표시·공유 모드는 M7 최소 범위 밖이다.


### 4.3 ACME 절차(DNS-01, 식별자 하나)

Swiftail이 구현할 순서다. 조항은 RFC 8555, 괄호는 Go의 같은 단계다.

1. **디렉터리**: `GET <디렉터리 URL>`. 응답 JSON에서 `newNonce`, `newAccount`, `newOrder`와 `meta.termsOfService`를 읽는다(7.1.1. `tempfork/acme/acme.go:166-213`). Go는 `newOrder`가 없으면 pre-RFC로 판정해 실패한다(`acme.go:199-201`). Swiftail도 발급에 필요한 세 URL 누락을 실패로 본다(구현 제안; RFC 8555 7.1.1).
2. **nonce**: 손에 쥔 유효한 nonce가 없으면 `HEAD <newNonce>`의 `Replay-Nonce` 머리에서 얻는다(7.2). POST의 응답(성공이든 오류든)이 주는 `Replay-Nonce`를 다음 요청에 쓴다(6.5). `Replay-Nonce`는 RFC 7515 2절의 채움 없는 base64url 인코딩이어야 하고 유효하지 않은 값은 무시한다(6.5.1). 이는 RFC 규칙이며 Go의 `nonceFromHeader`는 비지 않은 문자열을 그대로 받는다(`acme.go:722-759`).
3. **계정 찾기**: `POST <newAccount>`, `jwk` 머리, 본문 `{"onlyReturnExisting":true}`. 200이면 `Location` 머리가 계정 URL(`kid`)이다. 오류 종류가 `urn:ietf:params:acme:error:accountDoesNotExist`면 4로 간다(7.3.1).
4. **계정 만들기**: `POST <newAccount>`, `jwk` 머리, 본문 `{"termsOfServiceAgreed":true}`. 201(새 계정) 또는 200(같은 키의 계정이 이미 있음)이고 둘 다 `Location`이 계정 URL이다(7.3). 응답 본문의 `status`가 `valid`여야 한다(7.1.2, 7.1.6).
5. **주문**: 계정 키와 **다른** 인증서 키를 쓴다(RFC 8555 11.1). `POST <newOrder>`, `kid` 머리, 본문 `{"identifiers":[{"type":"dns","value":"<도메인>"}]}`. 201이고 `Location`이 주문 URL이다. 본문에서 `status`, `identifiers`, `authorizations`(URL 배열), `finalize`(URL)를 읽는다(7.4, 7.1.3). **식별자와 authorization은 1:1 보장이 없고 배열 순서에도 기대면 안 된다.** `authorizations`를 모두 확인하고 요청한 식별자 집합이 유지되는지 검증한다(7.1.3·7.4). 반환 `status`를 먼저 분기해 이미 `ready`면 바로 finalize 준비로 간다(7.1.3·7.1.6).
6. **authorization 읽기**: 각 URL에 POST-as-GET. `status`, `identifier`, `challenges`를 읽는다(7.5, 7.1.4). `status`가 `valid`면 이 authorization은 끝난 것이다(7.1.6). `pending`이면 `type`이 `dns-01`인 challenge 하나의 `url`과 `token`을 쓴다(7.1.4·8.4). 여러 종류를 모두 수행할 필요는 없다. Go는 첫 dns-01을 고르고 없으면 실패하며, authorization·challenge의 `status`를 별도로 검사하지 않는다(`feature/acme/cert.go:531-561`, `:615-653`). Swiftail은 `identifier.type == "dns"`·예상 이름·비와일드카드인지 확인하고, `invalid`·`deactivated`·`expired`·`revoked` 및 알 수 없는 상태는 실패로 본다(구현 제안; 7.1.4). challenge가 이미 `processing`이면 TXT를 준비했는지 확인한 뒤 상태를 다시 읽고, `valid`면 다시 응답하지 않는다(7.1.6·8.2).
7. **레코드 올리기**: 3.5의 값으로 3.2의 `set-dns`를 보낸다.
8. **challenge 응답**: `POST <challenge url>`, 본문 `{}`(7.5.1). Go는 200과 202를 성공으로 본다(`acme.go:570-573`).
9. **기다리기**: 주문 URL에 POST-as-GET을 되풀이한다. `ready`면 10, `invalid`면 그 주문을 버리고 오류 객체(`error`)와 함께 실패로 알린다. `pending`·`processing`이면 `Retry-After` 뒤에 다시 읽는다(7.1.3·7.1.6·7.4). 없을 때 1초는 **Go의 선택값**이지 RFC 상수가 아니다(`rfc8555.go:303-308`). `valid`는 발급 완료이므로 12로 가지만 **그 주문의 CSR에 쓴 개인 키가 이미 있어야 한다**. 새 주문에서 아직 CSR을 보내지 않았는데 `valid`가 오면 새 키를 만들어 조합하지 말고 실패로 본다(구현 제안; 7.4, 키 짝 검증은 3.7·4.4 5). RFC 7.5.1의 전형적인 흐름은 authorization URL 폴링이고, Go가 order를 폴링하는 방식과 구별한다.
10. **finalize**: `POST <finalize>`, 본문 `{"csr":"…"}`(3.6). 200과 갱신된 주문 객체가 온다. 주문이 `ready`가 아니었으면 403 `orderNotReady`다(7.4).
11. **발급 기다리기**: finalize 응답의 `status`를 즉시 분기한다. `valid`면 `certificate` URL로 진행, `processing`이면 `Retry-After` 후 주문 URL을 다시 읽는다. `invalid`는 실패, `pending`은 아직 pending인 authorization을 확인, `ready`는 **같은 키·CSR**로 finalize가 필요한 상태다. 모르는 상태는 실패로 본다(7.4의 다섯 분기, 키·CSR 유지와 모르는 상태 거절은 구현 제안). Go는 `valid` 이외면 `WaitOrder`를 부른 뒤 결과가 `valid`가 아니면 실패한다(`rfc8555.go:381-398`).
12. **내려받기**: `certificate` URL에 POST-as-GET. `application/pem-certificate-chain`이 기본 형식이다. `Accept`를 명시하는 것은 Swiftail의 선택이다(7.4.2; Go `fetchCertRFC`는 별도 Accept를 설정하지 않는다, `rfc8555.go:405-410`, `http.go:214-241`). 3.7의 규칙으로 해석한다.

HTTP 오류에는 RFC 7807 문제 문서를 덧붙이는 것이 **SHOULD**이며, JSON 매체형은 `application/problem+json`이다(RFC 8555 6.7, RFC 7807 3절). `type`은 URI reference다. 표준 ACME 오류는 `urn:ietf:params:acme:error:` 아래지만 서버 고유 URI도 올 수 있고, `type` 누락의 기본값은 `about:blank`다(RFC 8555 6.7, RFC 7807 3.1·4.2). HTTP 상태와 문제 문서를 함께 보존하고 JSON 아닌 오류도 다뤄야 한다. `status`·`title`·`detail`·`instance`, 그리고 `subproblems`와 그 안의 `identifier`를 구분한다(RFC 7807 3.1, RFC 8555 6.7.1). 주문의 `error`와 challenge의 `error`도 문제 문서다(RFC 8555 7.1.3·8절). 이 절차에서 따로 다루는 종류:

| 종류 | 대응 | 출처 |
| --- | --- | --- |
| `badNonce` | 그 오류 응답의 `Replay-Nonce`로 같은 요청을 다시 서명해 보낸다 | 6.5(클라이언트는 그 nonce를 써야 한다), `tempfork/acme/http.go:184-198` |
| `accountDoesNotExist` | 3 → 4 | 7.3.1 |
| `rateLimited` | `Retry-After`가 있으면 그때까지 시도하지 않는다 | 6.6 |
| `orderNotReady` | 주문을 다시 읽고 상태에 따라 간다 | 7.4 |
| `userActionRequired` | 약관 변경 등 사용자의 조치가 필요하다. `instance`와 `Link: rel="terms-of-service"`를 확인할 수 있게 실패로 알린다 | 6.7, 7.3.3 |

Go의 일반 HTTP 재시도: **기대한 성공 상태가 아닌 응답** 중 상태가 399 이하·500 이상·429이면 재시도 가능으로 본다. 네트워크 전송 오류는 이 루프에서 즉시 반환한다(`http.go:128-154`, `:172-198`, `:321-323`). `Retry-After`가 있으면 그 값 + 지터(암호 난수 추출 성공 시 1~1000ms), 없으면 `min(2^(n−1)초 + 지터, 10초)`다. 횟수 상한은 없고 기본 backoff에서는 context 취소가 끊는다(`http.go:39-90`).

`badNonce`를 재시도한다면 **그 오류 응답의 nonce를 사용해야 한다**(RFC 8555 6.5). Go는 응답 nonce를 넣은 후 `clearNonces`로 전부 지워 다음 시도에서 HEAD로 다시 얻는다. Swiftail은 이 동작을 복제하지 않는다(`http.go:187-198`, `:240`, `acme.go:692-718`). `Retry-After`는 정수 초 또는 HTTP-date이며 날짜는 현재 벽시계에 의존한다(RFC 7231 7.1.3, `http.go:92-104`). 유효한 서버 대기값을 임의의 30초·24시간 상한으로 줄여 더 일찍 **요청**하지 않는다. 전체 기한보다 길면 그 시도를 끝내거나 그때까지 재시도 보류 상태를 보존한다(구현 제안; RFC 8555 6.6·7.4).

### 4.4 갱신

1. Go의 기본 판정은 ARI(RFC 9773)다. 디렉터리의 `renewalInfo` URL에서 제안된 구간을 받아 그 안의 무작위 시각이 지났으면 갱신한다. 조회가 5초 안에 실패하면 **인증서 수명의 2/3 지점**이 지났는지로 본다(`feature/acme/cert.go:173-198`, `:233-251`, `:306-340`). 판정한 시각은 도메인마다 메모리에 적되 **갱신 성공 뒤 지우므로** 새 인증서에서는 다시 계산한다(`cert.go:183-204`, `:610`). `minValidity != 0`이면 ARI·2/3 대신 남은 수명과 요청 기간을 비교한다(`cert.go:174-180`). RFC 9773 4.2·4.3은 ARI 응답의 `Retry-After`에 따라 다시 조회하는 절차도 정하지만 Go의 이 캐시를 그 절차와 같다고 보면 안 된다.
2. Go는 **유효한 이전 인증서**를 캐시에서 얻고 파싱할 수 있으며 `TS_DEBUG_ACME_FORCE_RENEWAL`이 꺼졌을 때 `replaces`를 넣는다. 저장소의 `ARIReplacesAllower`가 명시적으로 false면 생략하고, 그 검사 오류는 넣는 쪽으로 진행한다(`cert.go:353-363`, `:394-420`). 만료·검증 실패로 `previous`가 nil이면 넣지 않는다. RFC의 certID는 AKI keyIdentifier와 **DER INTEGER 내용 바이트**의 serial을 각각 채움 없는 base64url로 적어 점으로 잇는다. serial의 부호용 선행 0x00도 포함한다(RFC 9773 4.1·5의 예). 반면 Go 포크는 `SerialNumber.Bytes()`를 써 그 0x00을 포함하지 않는다(`tempfork/acme/acme.go:299-302`, `rfc8555.go:227-228`). 이 차이를 RFC와 같다고 옮기면 안 된다. ARI는 M7 최소 범위 밖이다(6장).
3. 갱신이 필요하고 호출이 유효 기간을 요구하지 않았으면(`min_validity = 0`) 지금 인증서를 돌려주고 갱신은 뒤에서 한다. 도메인마다 하나만 돈다(`cert.go:138-153`, `:212-222`).
4. tsnet의 `Listen`만 쓰는 노드에서는 1시간짜리 백그라운드 갱신 루프가 돌지 않는다(DNS 노트 4.9 5). 그래서 첫 사용처의 Go 호스트에서 갱신은 **TLS 핸드셰이크가 올 때**(`GetCertificate`) 시작된다(RemoteDebug `core/internal/node/tls.go:41`).
5. 저장된 인증서는 읽을 때마다 키 짝·인증서 파싱·이름·현재 시각·사슬을 검증한다. 기본 시스템 루트가 실패하면 내장 Let's Encrypt 루트로 다시 검사한다. 시험 루트를 명시했다면 그 루트만 쓴다(`certstore.go:135-154`, `:411-459`). **비운영 디렉터리**에서는 최종 오류가 `UnknownAuthorityError`이면 통과시키는 Go 디버그 예외가 있다(`certstore.go:461-477`). Swiftail은 이 예외 대신 명시적 시험 앵커를 쓴다(계약 X3). 검증 실패는 `errCertExpired`, 파일 부재는 `ErrStateNotExist`로 새 발급 길로 가지만 그 밖의 읽기 오류는 반환한다(`cert.go:353-365`). Go는 새로 내려받은 인증서의 키 짝·사슬을 저장 전에 직접 검증하지 않는다(`cert.go:594-612`); Swiftail의 저장 전 검증은 더 강한 경계다(계약 C8).
6. Go는 읽기 전 `now`를 얻어 잠금 뒤 재검사에도 같은 값을 넘긴다(`cert.go:107`, `:162`, `:353`). 시계 차이를 보정하거나 `NotBefore`에 허용 오차를 더하는 코드는 이 경로에 없다(`certstore.go:444-449`). 벽시계가 틀리면 검증이 실패할 수 있다. Swiftail은 긴 대기 뒤 현재 시각을 새로 읽는 것으로 정하고 시계를 검증 입력으로 주입한다(구현 제안).

### 4.5 Let's Encrypt의 속도 제한

[Let's Encrypt Rate Limits](https://letsencrypt.org/docs/rate-limits/)(2026-08-05 갱신본, 2026-11-15 재확인)의 각 제한명과 같은 절에서 확인했다. 값은 프로토콜 상수가 아니라 그 날짜의 운영 정책이다. 구현의 재시도 간격과 관문의 발급 횟수를 이 값이 묶는다.

| 제한 | 값 | 이 구현에 주는 뜻 |
| --- | --- | --- |
| 같은 식별자 집합의 새 인증서 | 7일에 5장(34시간에 1장씩 회복). 예외 신청 불가 | **상태를 지우고 같은 이름으로 다시 발급하는 일을 되풀이하면 닿는다.** 시험은 스테이징이나 로컬 ACME 서버로 한다 |
| 등록 도메인의 새 인증서 | 7일에 50장 | "등록 도메인"은 Public Suffix List로 정한다. 공개 PSL의 `ts.net` 규칙으로는 일반 예시의 등록 도메인이 `tail0001.ts.net`이다(아래 출처·추론). 운영 서버의 배포 목록·별도 예외는 8장 |
| 계정의 새 주문 | 3시간에 300개 | 단일 노드의 정상 갱신 빈도는 낮지만, 같은 계정의 다른 호출까지 포함하므로 도달하지 않는다고 보장할 수 없다 |
| 식별자·계정의 authorization 실패 | 1시간에 5번(12분에 1번씩 회복) | 12분은 token bucket의 회복률이며 요청 사이의 의무 최소 간격은 아니다. 실패 재시도 정책을 정할 근거로 쓴다 |
| IP 주소의 새 계정 | 3시간에 10개 | 계정 키를 저장해 다시 쓴다 |
| 갱신의 예외 | ARI 갱신으로 인정되려면 `replaces`의 이전 인증서와 식별자가 하나 이상 겹치고 그 인증서가 이미 ARI로 대체되지 않았어야 한다. 인정된 주문은 모든 제한에서 빠진다. ARI 없이 식별자 집합이 같은 주문은 "새 주문"·"등록 도메인" 제한에서만 빠지고 "같은 식별자 집합 5장"에는 걸린다 | 2/3만으로 제한 회피를 보장하지 않는다. 인증서 수명·동일 집합의 다른 발급·실패와 재시도도 영향을 준다 |
| 제한에 닿았을 때 | 오류 응답에 `Retry-After` 머리 | 4.3의 `rateLimited` |

[공식 Public Suffix List](https://publicsuffix.org/list/public_suffix_list.dat)(직접 수신본 VERSION `2026-11-14_18-11-30_UTC`, commit `6f1e25ba61adfd473749ba1cdda658e25de97ec7`, `:16249-16250`)에 `ts.net`과 `*.c.ts.net` 규칙이 있다. 따라서 그 목록의 규칙을 적용한 **추론**으로 일반 이름 `rd-mac-1a2b3c4d.tail0001.ts.net`의 eTLD+1은 `tail0001.ts.net`이다. Let's Encrypt의 실제 배포 PSL 버전이나 별도 override를 조회한 것은 아니다.

같은 페이지의 "Consecutive Authorization Failures per Identifier per Account"는 연속 실패 1,152회, 하루 1회분 회복과 성공 시 연속 횟수 초기화도 정한다. 영구 실패를 6시간마다 계속 재시도하는 정책은 결국 이 제한에 닿을 수 있다. 같은 페이지는 개발·시험에 스테이징을 권한다.

수명은 [Certificate Lifetime Rationale and Plans](https://letsencrypt.org/docs/cert-lifetimes/)(2026-07-22)의 기본 90일·선택 6일, [64-Day Certificate Lifetimes Coming Feb 2027](https://letsencrypt.org/2026/10/07/64-day-certs)(2026-10-07)의 운영 기본 64일 전환일 **2027-02-10**, 스테이징 전환일 **2026-10-14**를 확인했다. 실제 이번 노드에 발급한 결과는 아니므로 8장의 관문은 남긴다. 예를 들어 6일 인증서를 2/3마다 갱신하는 정상 단일 흐름은 4일 간격이지만 수명에 하한이 없는 일반 ACME 서버에는 같은 제한 회피 결론을 적용하지 않는다(계산).

### 4.6 Apple 플랫폼에서 만드는 길

다음은 SDK 선언 대조와 **이번 검증 세션에서 다시 실행한** 작은 형식 검사다(2026-11-15, 샌드박스 밖). 이 검사는 ACME 발급·CSR 전체·TLS 네트워크 성공을 뜻하지 않는다.

| 필요한 것 | 길 | 확인한 근거 |
| --- | --- | --- |
| P-256 키 만들기 | `P256.Signing.PrivateKey()` | `CryptoKit.swiftinterface:1267-1274`, 생성·PEM 재읽기 검사 통과 |
| JWS 서명(R ‖ S) | `signature(for:)`의 `rawRepresentation` | `CryptoKit.swiftinterface:1629-1646`, 실행값 64바이트와 서명 검증 통과 |
| CSR의 DER 서명 | 같은 서명의 `derRepresentation` | `CryptoKit.swiftinterface:1630-1637`. 실제 CSR 전체 검증은 8장 |
| JWK의 `x`·`y` | 공개 키 `x963Representation`의 `04 ‖ X ‖ Y` | `CryptoKit.swiftinterface:1251-1253`, 공개 표현 65바이트 확인. EC 형식은 `SecKey.h:824-826` |
| CSR의 SubjectPublicKeyInfo | 공개 키 `derRepresentation` | `CryptoKit.swiftinterface:1258-1260`, 실행값 91바이트이고 id-ecPublicKey·secp256r1 OID, BIT STRING과 X9.63 점의 일치를 검사했다. SPKI 구조는 RFC 5480 2절; CSR 조립은 별도 검증 필요 |
| Go가 쓴 SEC1 키 읽기 | `P256.Signing.PrivateKey(pemRepresentation:)` | Go `x509.MarshalECPrivateKey`로 만든 임시 `EC PRIVATE KEY`를 읽음. `CryptoKit.swiftinterface:1271-1274` |
| 키 저장 | `pemRepresentation` | 실행값 `BEGIN PRIVATE KEY`이고 Go `x509.ParsePKCS8PrivateKey`가 ECDSA 키로 읽었다. Go의 PKCS#8 읽기는 `feature/acme/certstore.go:344-352` |
| CSR의 나머지 DER | 3.6의 제한된 ASN.1 쓰기 | 구현 제안이다. CN을 Go와 맞추려면 PrintableString도 필요하다. 짧은·긴 길이와 양수 INTEGER의 선행 0을 시험한다(RFC 2986 4절, RFC 3279 2.2.3) |
| 유효 기간 | `SecCertificateCopyNotValidBeforeDate`·`SecCertificateCopyNotValidAfterDate` | `SecCertificate.h:204-223`, macOS 15·iOS 18부터, 실패 시 NULL 가능 |
| 사슬 검증 | `SecPolicyCreateSSL` + `SecTrustCreateWithCertificates` + `SecTrustSetVerifyDate` + `SecTrustEvaluateWithError` | `SecPolicy.h:196`, `SecTrust.h:231-233`, `:347-348`, `:426-428`. 선언만 확인; 실행은 8장 |
| 공개 키 비교 | `SecCertificateCopyKey` + `SecKeyCopyExternalRepresentation` | `SecCertificate.h:149-157`, `SecKey.h:843-855`. EC 공개 키의 X9.63 표현을 비교하는 제안; 실행은 8장 |
| HTTPS 요청 | Foundation의 `URLSession` | 사용 가능한 프레임워크 범위는 `docs/plan.md` 4절(c)의 프로젝트 정책이다 |
| base64url·PEM | Foundation base64에 URL 알파벳 변환·채움 제거, PEM 감싸기 | 구현 제안; RFC 4648 5절, RFC 7515 2절, RFC 7468 2·5절 |

`SecIdentityCreate(allocator, certificate, privateKey)`는 공개 API이며 macOS 10.12·iOS 11.2부터다. 키가 인증서의 공개 키와 맞지 않으면 NULL이다(`SecIdentity.h:57-70`). `SecKeyCreateWithData`는 키체인에 추가하지 않으며 EC 개인 키 입력은 `04 ‖ X ‖ Y ‖ K`다(`SecKey.h:812-829`). 이번 CryptoKit 검사에서 그 표현은 97바이트였다. `SecPKCS12Import`의 `kSecImportToMemoryOnly`는 macOS 15·iOS 18부터 키체인 저장을 생략하는 옵션이다(`SecImportExport.h:652-661`, `:711-712`). M7은 PKCS#12 생성 대신 앞의 API를 쓰는 제안이다.

인증서의 유효 기간·공개 키·신뢰 판정만 필요하다면 위 Security API로 값을 얻는 설계를 할 수 있다. 이는 직접 X.509 ASN.1 파서를 생략하는 근거이며, 중간 사슬 전달·샌드박스 실행 성공까지 검증했다는 뜻은 아니다(8장).

### 4.7 Go 상태 디렉터리와 신원

`tailscaled.state`의 형식과 키는 DNS 노트 3.2, 시작할 때 읽는 순서는 4.4.1, 다시 시작해도 같은 노드가 되는 데 필요한 것은 4.4.3에 있다. M7의 이관 결정에 보탤 것:

1. **tsnet이 상태 디렉터리에 두는 것**(`Dir`이 비지 않으면 varRoot다. 비면 사용자 설정 디렉터리의 `tsnet-<프로그램>`으로 정한다. `tailscale.com/tsnet/tsnet.go:848-869`, `:984`):

   | 경로 | 내용 | 출처 |
   | --- | --- | --- |
   | `tailscaled.state` | `Server.Store == nil`일 때의 기본 FileStore. 신원과 prefs(JSON, 값은 base64) | `tsnet.go:965-972` |
   | `tailscaled.log.conf` | 로그 업로드용 ID 설정 | `tsnet.go:1104` |
   | `tailscaled`로 시작하는 로그 버퍼 파일 | 업로드 전의 로그 | `tsnet.go:1120` |
   | `certs/` | 인증서, 인증서 키, ACME 계정 키(3.7) | `feature/acme/certstore.go:64-81` |

   첫 사용처는 같은 디렉터리에 직접 연결 리스너의 `direct.json`, `direct-key.pem`, `direct-cert.pem`도 둔다(RemoteDebug `core/internal/direct/direct.go:30-35`). 이 셋은 Tailscale의 것이 아니다. 첫 사용처의 iPhone은 인증서 SPKI의 SHA-256을 고정하므로 이관 설계에서 따로 보존해야 한다(RemoteDebug `2814b2c`의 `core/internal/direct/direct.go:55-60`, `docs/protocol-addenda.md:657-663`, `:756-760`).

2. **신원이 든 값**: `_machinekey`(machine 개인 키), `_current-profile`이 가리키는 `profile-<id>`의 `Config.PrivateNodeKey`(node 개인 키), 같은 곳의 `Config.OldPrivateNodeKey`, `Config.NetworkLockKey`, `Config.NodeID`, `Config.UserProfile`, 그리고 prefs의 `ControlURL`·`LoggedOut`(DNS 노트 3.2). machine·node 개인 키는 `privkey:` + hex 64자지만 `NetworkLockKey`는 Ed25519의 별도 타입과 `nlpriv:` 머리를 쓴다(`types/key/machine.go:24`, `:68-82`, `types/key/node.go:29`, `:115-127`, `types/key/nl.go:16-18`, `:32-36`, `:60-66`). `Persist`는 Swiftail 신원 파일과 이름이 같은 독립 JSON 객체가 아니라 prefs의 **`Config`** 필드다(`ipn/prefs.go:314-319`, `types/persist/persist.go:18-39`).

3. **Swiftail과의 대응**:

   | Go | Swiftail `identity.json` | 비고 |
   | --- | --- | --- |
   | `_machinekey` | `MachineKey` | 텍스트 형식이 같다(`Sources/SwiftailControl/Client/NodeIdentityStore.swift`의 형식 설명) |
   | `Config.PrivateNodeKey` | `NodeKey` | 형식이 같다. Go에서 0이거나 없으면 이관하지 않는 것이 계약 G3의 선택이다. 0이라는 사실만으로 로그인 이력은 판정할 수 없다 |
   | `Config.OldPrivateNodeKey` | 없다 | Go는 값이 있으면 재등록에도 `OldNodeKey`로 싣는다(`direct.go:718-720`, `:759-763`). 생략은 현재 키가 서버에 등록 완료된 정상 상태만 대상으로 하는 제한이다. 키 교체 중단 상태까지 신원 보존을 보장하지 않는다 |
   | `Config.NetworkLockKey` | 없다 | Swiftail은 `NLKey`를 0으로 보낸다(8장) |
   | `Config.NodeID`, `Config.UserProfile`, `_profiles` | 없다 | Go의 프로필 관리용이다. 재등록에 쓰지 않는다(DNS 노트 4.4.3) |
   | prefs의 `ControlURL` | 없다(`NodeConfiguration.controlURL`이 준다) | 가져올 때 둘이 같은 서버인지 견줘야 한다. Go에서 비면 기본 제어 서버다(`ipn/prefs.go:60-64`). 과거 공식 로그인 URL의 동의어도 기본값으로 이주한다(`ipn/ipnlocal/profiles.go:701-708`) |
   | prefs의 `LoggedOut` | 없다 | 참이면 그 노드는 로그아웃된 상태다 |
   | `certs/<도메인>.crt`·`.key`, `certs/acme-account.key.pem` | 같은 이름으로 둘 수 있다 | 4.6: Go의 SEC1 PEM을 CryptoKit이 읽는다 |

4. **같은 node 키를 두 구현이 함께 쓰면**: 각 프로세스가 같은 공개 키로 등록·맵·DERP 연결을 시도하면서 엔드포인트와 disco 키를 따로 알릴 수 있다. 두 세션이 모두 계속 유지되는지, 어느 쪽으로 패킷이 가는지는 이 경로의 클라이언트 소스로 보장할 수 없다(8장). Go가 키를 바꿀 때 현재 키를 `OldPrivateNodeKey`로 옮기고 `OldNodeKey`를 넣는 것은 확인되지만, 이전 키로 재시작한 다른 구현을 서버가 반드시 거절한다거나 `OldNodeKey`로만 인정한다는 결론은 나오지 않는다(`control/controlclient/direct.go:704-723`, `:759-768`).

5. **FileStore를 실제로 읽는 순서와 경계**:
   - 바깥은 `map[StateKey][]byte`를 JSON으로 적으므로 값은 **표준 base64**다. 그 바이트를 푼 뒤 `_current-profile`은 `profile-<id>`라는 문자열이고, 그 키의 값은 다시 prefs JSON이다. `Config` 안의 키 문자열을 base64url로 해석하지 않는다(`ipn/store/stores.go:145-150`, `:192-194`, `ipn/ipnlocal/profiles.go:898-925`, `ipn/prefs.go:314-319`; Go `encoding/json/encode.go:90-93`).
   - `_profiles`의 실제 값은 `{프로필 ID: LoginProfile}`인 JSON 맵이다. 프로필 ID는 난수 2바이트의 hex 4자이며 `_current-profile`에는 ID만이 아니라 `profile-`가 붙은 **키 전체**가 든다(`profiles.go:494-503`, `:657-666`, `:819-825`). Go는 이 키를 `_profiles`에서 찾아 시작 프로필을 정한다(`profiles.go:318-328`, `:951-977`). 없으면 빈 프로필을 만들며, 키가 아예 없고 알려진 프로필도 없을 때만 legacy prefs 이주를 시도한다(`profiles.go:961-974`, `ipn/store.go:26-40`). M7이 legacy·여러 프로필을 지원하지 않는다면 명시적으로 거절해야 한다(구현 제안).
   - Go는 파일이 없거나 길이가 0이면 `{}`를 0600으로 써서 시작하고, JSON 파싱 오류는 반환한다. 값이 같으면 쓰지 않고 nil 값은 키 삭제, 쓰기는 전체 JSON을 원자적으로 교체한다(`stores.go:158-196`, `:211-226`). 인증서와 달리 신원 가져오기는 파일 부재·잘못된 base64·잘못된 키·없는 프로필을 새 신원 생성으로 바꾸면 안 된다(구현 제안; 계약 G2·G3).
   - `mem.Store`를 쓴 tsnet은 `Ephemeral`이어야 하지만 root 디렉터리와 `certs/`는 여전히 디스크를 쓴다. FileStore·mem.Store 이외 저장소이면서 Kubernetes일 때만 인증서를 상태 저장소 키로 읽고 쓴다(`tsnet/tsnet.go:848-869`, `feature/acme/certstore.go:83-104`, `:223-260`). 그러므로 메모리 상태를 쓴다는 이유로 ACME 계정 키도 메모리 전용이라고 가정하지 않는다.

이관으로 같은 주소·StableID를 보존한다는 것은 **관문의 기대 결과**다. machine·node 키만으로 어떤 운영 서버·tailnet lock·키 교체 중단 상태에서도 성립한다고 검증한 보장이 아니다(위 3·4, 8장).

### 4.8 구현에서 지킬 입력 경계와 Go의 한계

- **URL**: JWS `url`은 서버가 준 URL 문자열을 재인코딩 없이 그대로 서명해야 한다(RFC 8555 6.4). HTTPS와 응답 크기·기한·URL 길이 제한은 가장자리에서 검사한다. Go의 ACME 경로는 `http.DefaultClient`를 기본으로 사용하므로 Swiftail 계약의 “리다이렉트 금지·URL 2,048바이트·JSON 64KiB”가 Go와 같은 제한은 아니다(`tempfork/acme/http.go:231-268`; 계약 X1·X2).
- **상태와 식별자**: authorization과 challenge 상태 이름을 혼동하지 않는다. account는 `valid`·`deactivated`·`revoked`, order는 `pending`·`ready`·`processing`·`valid`·`invalid`, authorization은 `pending`·`valid`·`invalid`·`deactivated`·`expired`·`revoked`, challenge는 `pending`·`processing`·`valid`·`invalid`다(RFC 8555 7.1.2-7.1.6). 요청한 이름·종류·wildcard 여부와 주문의 식별자 집합을 확인하며, 모르는 상태를 무한 폴링으로 바꾸지 않는 것은 Swiftail의 경계 정책이다(4.3).
- **DNS 정리와 재시도**: RFC는 challenge 완료 뒤 TXT 해제를 SHOULD로 권하지만 Tailscale의 `SetDNSRequest`에는 삭제 동작 필드가 없고 이 발급 함수도 삭제를 보내지 않는다(RFC 8555 8.4, `tailcfg/tailcfg.go:2595-2618`, `feature/acme/cert.go:615-654`). 빈 `Value`를 삭제 신호로 추정하지 않는다. Go의 `WaitOrder`는 JSON 해석 오류도 재시도하고 알 수 없는 상태도 폴링한다(`tempfork/acme/rfc8555.go:292-308`); Swiftail의 잘못된 상태 거절·전체 기한은 별도로 필요하다.
- **계정과 동시성**: 도메인 잠금 외에도 계정 키 읽기/생성/저장과 계정 조회/등록에 `accountMu`가 있다. 키 파일 오류를 “없음”으로 덮어 새 계정을 만들지 않는다(`feature/acme/certstore.go:361-388`, `feature/acme/cert.go:451-473`). Go 잠금은 같은 backend extension 안의 잠금이며 프로세스 사이 파일 잠금은 아니다(`feature/acme/acme.go:76-89`).
- **검증과 저장**: 사슬만 파싱하거나 시스템 루트만 확인해서는 키·이름·기간 검증을 대신할 수 없다(3.7·4.4 5). 기존 계정 키가 손상됐을 때 실패시키는 것과, 인증서 캐시가 손상됐을 때 재발급하는 것을 구분한다(`certstore.go:150-151`, `:367-374`). 디렉터리·파일 권한은 생성 시점의 값이며 기존 항목에 대한 모든 경로 보안 검사를 대신하지 않는다(`certstore.go:76-78`, `atomicfile/atomicfile.go:22-26`).
- **시각**: 인증서 검증·HTTP-date·ARI 제안 시각은 벽시계에 기대므로 시계 차이를 시험한다(RFC 9773 6절, `tempfork/acme/http.go:95-104`, `certstore.go:444-449`). Go의 ARI 구간 선택은 `randv2.N(end.Sub(start))`이고 이 함수 앞에 `end > start` 검사가 없다(`feature/acme/cert.go:334-338`). ARI를 나중에 넣는다면 잘못된 구간·시각 입력부터 거절해야 한다(구현 제안).

## 5. 상수와 타이머

| 이름 | 값 | 출처 |
| --- | --- | --- |
| Let's Encrypt 디렉터리 | `https://acme-v02.api.letsencrypt.org/directory` | `tempfork/acme/acme.go:47` |
| 디렉터리 바꾸기(Go) | 환경 변수 `TS_DEBUG_ACME_DIRECTORY_URL` | `feature/acme/certstore.go:402` |
| 사슬의 인증서 수 상한 | 5 | `acme.go:63`, `rfc8555.go:439` |
| 크기 계산 상수 `maxCertSize` | 1MiB(DER 기준 상수). RFC 발급 경로의 실효 제한은 3.7의 전체 본문 한도이며 개별 DER 길이 검사는 없다 | `acme.go:64-67`, `rfc8555.go:412-446` |
| nonce 보관 상한 | 100개("보통 1~2개") | `acme.go:69-71` |
| 재시도 물러나기 | `min(1·2·4…초 + 지터, 10초)`. `Retry-After`가 있으면 그 값 + 지터(10초 상한 없음). 난수 실패 시 지터 0 | `http.go:68-90` |
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
| ARI와 `replaces` | 최소 범위를 위한 **정책 선택**이다. Go도 ARI 실패 시 2/3로 가지만, 조기 갱신 통지·ARI 제한 면제는 잃으며 2/3만으로 속도 제한 회피가 보장되지 않는다(4.4·4.5) |
| TXT 사전 조회 | Go의 주석대로 최악이 "이미 있는 것을 다시 올림"이다(4.2 3). 터널 밖의 시스템 리졸버에 기대는 코드가 준다 |
| TLS-ALPN-01, 와일드카드, BYO 도메인 | Funnel·Serve용이다(plan 3절 제외). 첫 사용처는 자기 FQDN 하나만 쓴다 |
| RSA·P-384 키, 외부 계정 결속(EAB), 연락처, 계정 키 교체, 계정 비활성화, 인증서 폐기 | Go의 Tailscale 통합이 쓰지 않는다(4.2 2) |
| 대체 사슬(`Link: rel="alternate"`) | Tailscale 통합의 발급 경로가 쓰지 않는다. ACME 포크에는 조회 API가 있다(3.7). 기본 사슬이 신뢰되지 않을 때 다른 사슬로 성공할 기회를 생략하는 선택이다 |
| nonce 여러 개 보관 | 요청을 차례로 보내므로 마지막 응답의 것 하나면 된다 |
| `CapMap`, node 키로 찾기, `ProxyMapper` | 첫 사용처가 쓰지 않는다(4.1 2·7) |
| X.509 해석기 | 4.6 |
| Kubernetes 저장소, `TS_CERT_SHARE_MODE` | 해당 없음 |

## 7. 상호 운용 시험에서 확인할 것

1. **Go 기준값**: 같은 계정 키와 입력으로 Go(`tempfork/acme`와 표준 라이브러리)가 만든 JWK 문자열, 지문, 키 인가, DNS-01 TXT 값이 Swift와 바이트까지 같다. JWS 보호 머리·본문의 **JSON 멤버 순서는 규격상 고정이 아니므로**, 의미·복호화한 머리·실제 서명 입력과 상대 구현의 서명 검증을 확인한다(RFC 7515 5.1, `jws.go:70-107`). Go와 같은 JSON 직렬화 순서까지 택한 경우에만 머리·서명 입력의 바이트 일치를 요구한다. ECDSA 서명은 실행마다 다르므로 서명은 상대 구현이 검증하는 것으로 본다(Go가 만든 JWS를 Swift가, Swift가 만든 것을 Go가).
2. **CSR**: Swift가 만든 CSR을 Go `x509.ParseCertificateRequest` + `CheckSignature`가 받아들이고 주체·SAN이 같다. Go `certRequest`가 만든 CSR과 `certificationRequestInfo`의 구조가 같다. 같은 공개 키·같은 속성·Go와 같은 CN 문자열 태그와 DER 규칙을 택한 경우 바이트까지 같아야 한다(3.6). UTF8String을 선택한 CSR은 유효해도 그 바이트 동일성 기준과 다르다.
3. **`set-dns`**: `testcontrol`의 `/machine/set-dns` 처리기는 요청을 검사한다. `Type`이 `TXT`, `Name`·`Value`가 비지 않음, node 키가 그 machine 키의 것, `Name`이 `_acme-challenge.` + 그 노드의 cert 도메인(`tailscale.com/tstest/integration/testcontrol/testcontrol.go:605-649`). `OnSetDNS` 훅으로 받은 값을 시험이 볼 수 있다(`:66`, `:641-646`).
4. **cert 도메인**: `testcontrol`은 `DNSConfig`가 있고 `MagicDNSDomain`이 비지 않으면 netmap의 `CertDomains`에 `<Hostinfo.Hostname>.<MagicDNSDomain>`을 더한다(`testcontrol.go:1655-1668`, `:651-663`). Swiftail의 시험 도구는 `MagicDNSDomain`만 주고 `DNSConfig`는 아직 주지 않는다(`Tools/interop/cmd/tailnet/main.go:115`). 따라서 **현재 도구 그대로는 netmap의 CertDomains가 생기지 않는다**. ACME 관문을 만들 때 DNSConfig도 설정해야 한다(`testcontrol.go:1651-1668`).
5. **전체 발급**: 로컬 ACME 서버(pebble)를 상대로 4.3의 열두 단계가 끝나고 받은 사슬이 그 서버의 루트로 검증된다. pebble은 `va.New(…, customResolverAddr, …)`로 DNS 검증에 쓸 리졸버를 받고(`github.com/letsencrypt/pebble/v2@v2.10.3/va/va.go:121-140`), challtestsrv는 `AddDNSTXTRecord(host, content)`로 TXT 레코드를 넣는 DNS 서버를 낸다(`github.com/letsencrypt/challtestsrv@v1.4.2/dns.go:75-80`). `testcontrol`의 `OnSetDNS`를 그것에 잇고 `set-dns` → DNS-01 검증 → 발급을 한 프로세스에서 돌리는 것이 **시험 설계**다. 실제 tailnet 계정은 필요 없지만 로컬 ACME 계정은 만든다(RFC 8555 7.3). pebble은 환경 변수로 nonce 거부 비율(`PEBBLE_WFE_NONCEREJECT`)과 authorization 재사용(`PEBBLE_AUTHZREUSE`)을 조절하므로 `badNonce` 재시도와 4.2 7의 경우를 함께 볼 수 있다. **두 모듈의 API·설정·라이선스는 재대조했으나 통합 빌드·실행은 하지 않았다**(8장).
6. **`WhoIs` 대조**: 같은 netmap에서 Go 피어의 `LocalClient().WhoIs(주소)`가 돌려준 `StableID`·`Name`·`ComputedName`·`LoginName`과 Swift `whoIs`의 값이 같다. 자기 주소, 피어의 IPv4·IPv6 주소, 없는 주소.
7. **Go 상태 파일**: Go tsnet 노드를 멈추고 `tailscaled.state`에서 읽은 machine·node 키로 Swift 노드를 띄웠을 때 같은 공개 키·tailnet IP·StableID인지 검증한다. 이는 미실행 관문의 기대값이다(4.7). Go가 쓴 `certs/` 아래 파일을 Swift가 읽어 검증한다.
8. **실제 Let's Encrypt**(계정 필요): 실제 제어 서버의 `set-dns`가 받아 주고, 발급된 인증서로 iOS 설치기(`itms-services`)가 내려받는다. 로컬에서는 확인할 수 없다.

## 8. 확인하지 못한 것

- **운영 제어 서버의 `set-dns`**: 요청을 받아들이는 조건(HTTPS가 켜진 tailnet, 임시 노드, 선언한 CapabilityVersion), 레코드가 권한 DNS에 보일 때까지 응답을 미루는지, 호출 빈도 제한, 오류 본문의 형식. 클라이언트 소스에는 요청과 200 판정만 있다. `testcontrol`의 처리기는 운영 서버의 구현이 아니다.
- **태그 노드와 공유 노드의 프로필**: 운영 서버가 태그 노드의 `User`와 그 프로필(`LoginName`)로 무엇을 보내는지, 공유받은 노드의 `User`·`Sharer` 프로필이 늘 함께 오는지. 근거는 4.1 6의 도구 코드와 주석뿐이다.
- **이번 주문의 authorization 재사용과 Go 결과**: 공식 2026-10-07 안내는 현재 30일인 재사용 기간을 2027년에 10일로 줄인다고 설명한다([공식 안내](https://letsencrypt.org/2026/10/07/64-day-certs)). 재사용 제도는 확인했으나 이번 계정·주문에서 `valid`가 재사용될 때 Go 흐름(4.2 7)이 끝나는지는 실행하지 않았다.
- **Let's Encrypt의 실제 PSL 배포·예외**: 공개 PSL에서 일반 ts.net 이름의 eTLD+1은 확인·계산했다(4.5). 운영 CA의 배포 snapshot과 Tailscale용 override까지 확인하지는 못했으므로 실제 제한 경계의 운영 보장은 남긴다.
- **MagicDNS와 HTTPS의 관계**: `CertDomains`가 비지 않으면 MagicDNS가 늘 켜져 있는지. 첫 사용처는 둘을 따로 본다(4.2 9).
- **App Sandbox 안**: `SecIdentityCreate`, `SecKeyCreateWithData`, 루프백의 `NWListener`, `URLSession`이 네트워크 서버·클라이언트 권한만으로 도는지. 실험은 샌드박스 밖에서 했다.
- **`SecTrust`로 하는 사슬 검증과 공개 키 비교**(4.6): API가 공개라는 것만 확인했고 돌려 보지 않았다. 중간 인증서를 TLS 핸드셰이크에 싣는 길(`sec_identity_create_with_certificates`)도 돌려 보지 않았다.
- **pebble·challtestsrv를 `Tools/interop`에 넣기**: 모듈(둘 다 MPL-2.0, pebble `go 1.25.0`, challtestsrv `go 1.24`; 각각 `LICENSE:1`, `go.mod:3`)을 받아 패키지와 함수 서명을 읽었다. 빌드와 실행은 하지 않았다. `testcontrol`과 한 프로세스에서 도는지, 의존 모듈이 `tailscale.com`의 고정 버전과 충돌하지 않는지 모른다.
- **Go 상태를 가져온 노드의 재등록**: Swiftail은 등록 요청의 `NLKey`를 0으로 보낸다. Go가 `NLKey`를 실어 등록한 노드가 0으로 다시 붙을 때 서버가 어떻게 하는지(DNS 노트 8.1과 같은 물음), 같은 node 키로 두 구현이 동시에 맵 스트림을 열 때 서버와 DERP의 동작.
- **이번 노드의 인증서 수명과 실제 발급**: 공식 운영 정책은 4.5에서 확인했다. 이번 작업에서 운영·스테이징 발급은 하지 않았으므로 실제 발급된 기간·전파 시간·소요 시간은 확인하지 못했다.
- **작성 세션의 Apple 실험**: “열다섯 줄로 295바이트 CSR을 만들고 OpenSSL 검증”, “NWListener와 TLS 1.2 이상·ALPN http/1.1 협상”, “키체인 쓰기 없음”의 재현 자료·출력을 받지 못해 확인 불가다. 이번에는 4.6의 크기·PEM 읽기/쓰기와 서명 검증만 다시 실행했다. 샌드박스·중간 사슬 전달·SecTrust 실행까지 확대 해석하지 않는다.
- **두 세션·키 교체 후 재등록의 서버 결과**: 이전 키가 반드시 OldNodeKey로만 통한다는 주장도 클라이언트 코드로 확인되지 않아 본문의 단정에서 뺐다(4.7 4).

## 9. 원문 주장별 검증 기록

2026-11-15, 작성 세션과 다른 GPT-6.1 Sol 세션의 판정이다. **수정 전 원문**의 사실을 아래 단위로 나눴다. 같은 주장의 타이머 표·최소 범위·미확인 절 재인용은 중복 집계하지 않았으며, 미래 시험의 통과 기준과 생략할 기능이라는 설계 결정은 실행된 사실로 세지 않았다. 한 필드 목록이나 조건식은 같은 근거로 함께 판정할 수 있을 때 한 주장으로 묶고, 틀린 부분이나 확인 불가 부분은 따로 분리했다. “맞음”도 필요한 분기·근거 줄을 보충했다. 출처 열에서 Go 경로는 본문과 같은 모듈 기준이며, 단축한 파일명은 해당 본문 절의 전체 경로를 따른다.

총 **248개**: 맞음 **208**, 틀림 **18**, 확인 불가 **22**. 새로 발견해 보탠 사실은 본문에 근거를 달았으며 원문 주장 수에 더하지 않았다.

| ID | 원문 절·주장 | 판정 | 대조 근거·조치 |
| --- | --- | --- | --- |
| V001 | 1: 기준 Tailscale v1.104.6·CapabilityVersion 148 | 맞음 | `tailcfg/tailcfg.go:200`, 기준 모듈 |
| V002 | 1: ACME는 x/crypto의 tempfork | 맞음 | `tempfork/acme/README.md:1-5` |
| V003 | 1: Apple 실험을 실행해 확인했다는 작성 이력 | 확인 불가 | 작성 세션 실행 자료 없음. 4.6 재실행 항목 외에는 8장으로 이동 |
| V004 | 2: M7은 WhoIs·인증서·상태 이관을 사용한다 | 맞음 | `docs/contracts/SwiftailHost.md` 1·3절 |
| V005 | 2: 첫 사용처가 Network 프레임워크로 TLS를 끝내려 한다 | 맞음 | `docs/contracts/SwiftailNetstack.md` 첫 사용처 검토 결과 1(설계) |
| V006 | 3.1: WhoIsResponse의 Node·UserProfile·CapMap | 맞음 | `client/tailscale/apitype/apitype.go:35-42` |
| V007 | 3.1: UserProfile의 다섯 필드 | 맞음 | `tailcfg/tailcfg.go:307-319` |
| V008 | 3.1: 첫 사용처는 StableID가 비면 거절한다 | 맞음 | RemoteDebug `2814b2c` `core/internal/node/node.go:535-536` |
| V009 | 3.1: 첫 사용처의 짧은 이름과 ComputedName fallback | 맞음 | RemoteDebug `node.go:538-550` |
| V010 | 3.1: 첫 사용처가 프로필에서 읽는 것은 LoginName | 맞음 | RemoteDebug `node.go:542-544` |
| V011 | 3.1: StableID는 허용 목록에 쓸 안정된 노드 ID | 맞음 | `tailcfg/tailcfg.go:249-259`, RemoteDebug의 `host.Peer.StableID` |
| V012 | 3.1: Node.Name은 끝 점 있는 FQDN | 맞음 | `tailcfg/tailcfg.go:374-378` |
| V013 | 3.1: Node.User는 생성 사용자이며 태그 ACL 신원과 다르다 | 맞음 | `tailcfg/tailcfg.go:380-383` |
| V014 | 3.1: Sharer는 공유한 사용자이고 User와 다를 때 설정 | 맞음 | `tailcfg/tailcfg.go:385-386` |
| V015 | 3.1: Tags가 하나라도 있으면 IsTagged | 맞음 | `tailcfg/tailcfg.go:635-637` |
| V016 | 3.1: ComputedName은 control 와이어에서 오지 않고 클라이언트가 계산 | 맞음 | `tailcfg/tailcfg.go:496-503`. LocalAPI Node JSON에는 나타나는 차이를 명확히 함 |
| V017 | 3.2: set-dns는 Noise 위 POST /machine/set-dns | 맞음 | `control/controlclient/direct.go:1756-1765` |
| V018 | 3.2: SetDNSRequest의 다섯 JSON 필드 | 맞음 | `tailcfg/tailcfg.go:2595-2618` |
| V019 | 3.2: Version 1은 전송 직전 현재 capability로 교체 | 맞음 | `ipn/ipnlocal/local.go:7813-7818`, `direct.go:1759-1760` |
| V020 | 3.2: NodeKey는 현재 node 공개 키 텍스트 | 맞음 | `local.go:7822-7823`, `types/key/node.go:331-340` |
| V021 | 3.2: Name·Type·Value는 DNS-01 이름·TXT·digest | 맞음 | `feature/acme/cert.go:620-639`, `local.go:7813-7818` |
| V022 | 3.2: Content-Type과 0이 아닌 node 키의 LBHeader | 맞음 | `control/ts2021/client.go:299-318` |
| V023 | 3.2: 200 이외 응답은 오류이며 본문 앞 200자를 담음 | 맞음 | 공백 제거 뒤 최대 200 rune이다(`direct.go:1770-1772`, Go `fmt/doc.go:116-130`). Noise 기본 본문 한도 보충 |
| V024 | 3.2: 200이면 SetDNSResponse로 decode하고 실패 시 오류 | 맞음 | `direct.go:1774-1778`. 객체 전용 검사가 아님을 보충 |
| V025 | 3.3: POST는 Flattened JWS이고 application/jose+json | 맞음 | RFC 8555 6.2·6.3, RFC 7515 7.2.2 |
| V026 | 3.3: protected·payload·signature는 각각 base64url 문자열 | 맞음 | RFC 7515 7.2.2, `tempfork/acme/jws.go:95-117` |
| V027 | 3.3: 보호 머리는 alg·nonce·url·jwk 또는 kid | 맞음 | RFC 8555 6.2(이 노트 범위의 바깥 요청) |
| V028 | 3.3: 보호되지 않는 머리는 금지 | 맞음 | RFC 8555 6.2 |
| V029 | 3.3: P-256은 ES256이며 서버 필수 구현 | 맞음 | RFC 8555 6.2, `jws.go:231-245` |
| V030 | 3.3: newAccount·인증서 키로 하는 revoke는 jwk | 맞음 | RFC 8555 6.2 |
| V031 | 3.3: 그 밖의 요청은 계정 URL kid | 맞음 | RFC 8555 6.2·7.3 |
| V032 | 3.3: url은 실제 대상 URL 그대로 | 맞음 | RFC 8555 6.4·6.4.1 |
| V033 | 3.3: nonce는 Replay-Nonce 값이며 한 번만 사용 | 맞음 | RFC 8555 6.5 |
| V034 | 3.3: POST-as-GET payload는 빈 문자열 | 맞음 | RFC 8555 6.3 |
| V035 | 3.3: 서명 입력은 ASCII(protected + 점 + payload) | 맞음 | RFC 7515 5.1, `jws.go:106-108` |
| V036 | 3.3: ES256 서명은 R32·S32 64바이트이며 DER 아님 | 맞음 | RFC 7518 3.4, `jws.go:200-223` |
| V037 | 3.3: base64url은 URL 알파벳·채움 없음 | 맞음 | RFC 7515 2절, RFC 4648 5절 |
| V038 | 3.3: Tailscale이 새로 생성하는 계정 키는 P-256 | 맞음 | `feature/acme/certstore.go:377` |
| V039 | 3.3: 포크는 RSA·P-384·P-521 서명도 지원 | 맞음 | `jws.go:231-245` |
| V040 | 3.4: 최소 P-256 JWK의 crv·kty·x·y | 맞음 | RFC 7517 4.1, RFC 7518 6.2.1 |
| V041 | 3.4: x·y는 32바이트 big-endian base64url | 맞음 | RFC 7518 6.2.1.2·6.2.1.3, `jws.go:172-193` |
| V042 | 3.4: 필수 멤버·사전 순서·공백 없는 지문 입력 | 맞음 | RFC 7638 3·3.2·3.3 |
| V043 | 3.4: ACME 지문은 SHA-256 | 맞음 | `jws.go:250-257`, RFC 8555 8.1. 일반 RFC 7638의 해시 H와 구별하는 출처 보충 |
| V044 | 3.4: 지문 입력 JSON은 crv·kty·x·y 순서 | 맞음 | RFC 7638 3.2, `jws.go:189-193` |
| V045 | 3.4: Go 지문 텍스트는 SHA-256의 base64url | 맞음 | `jws.go:250-257` |
| V046 | 3.4: Go는 jwk 머리에도 정렬된 JSON 사용 | 맞음 | `jws.go:81-87` |
| V047 | 3.5: keyAuthorization은 token·점·지문 텍스트 | 맞음 | RFC 8555 8.1, `acme.go:783-789` |
| V048 | 3.5: TXT 값은 keyAuthorization SHA-256의 base64url | 맞음 | RFC 8555 8.4, `acme.go:591-598` |
| V049 | 3.5: 레코드 이름은 _acme-challenge + 도메인 | 맞음 | RFC 8555 8.4, `feature/acme/cert.go:626` |
| V050 | 3.5: token은 base64url 알파벳만 사용 | 맞음 | RFC 8555 8.4. 최소 128비트 엔트로피·채움 금지를 보충 |
| V051 | 3.6: finalize csr 값은 PEM 아닌 CSR DER의 base64url | 맞음 | RFC 8555 7.4, `rfc8555.go:371-375` |
| V052 | 3.6: Go 일반 도메인 CSR은 CN 하나와 SAN 하나 | 맞음 | `certstore.go:306-320`, `cert.go:587` |
| V053 | 3.6: 새 P-256 인증서 키와 ECDSA-SHA256 | 맞음 | `cert.go:578-587`, Go `crypto/x509/x509.go:1653-1657`; 실행 확인 |
| V054 | 3.6: CertificationRequest의 Info·알고리즘·서명 구조 | 맞음 | RFC 2986 4.1·4.2 |
| V055 | 3.6: CSR version은 INTEGER 0 | 맞음 | RFC 2986 4.1 |
| V056 | 3.6: Go ASCII 도메인의 CN은 UTF8String | 틀림 | Go는 PrintableString 선택. Go `encoding/asn1/marshal.go:638-652`, 실행 tag 19 |
| V057 | 3.6: SPKI는 id-ecPublicKey·secp256r1·비압축 점 | 맞음 | RFC 5480 2.1.1·2.1.1.1·2.2 |
| V058 | 3.6: attributes는 [0] IMPLICIT SET OF Attribute | 맞음 | RFC 2986 4.1·부록 A의 IMPLICIT TAGS |
| V059 | 3.6: extensionRequest의 OID 1.2.840.113549.1.9.14 | 맞음 | RFC 2985 5.4.2·부록 A를 이번에 수신해 확인 |
| V060 | 3.6: SAN OID 2.5.29.17·OCTET STRING·dNSName [2] IA5String | 맞음 | RFC 5280 4.1·4.2.1.6 |
| V061 | 3.6: ecdsa-with-SHA256 OID·매개변수 없음 | 맞음 | RFC 5758 3.2 |
| V062 | 3.6: 서명 BIT STRING 안은 DER r·s SEQUENCE | 맞음 | RFC 2986 4.2, RFC 3279 2.2.3 |
| V063 | 3.6: CSR 서명 대상은 Info의 DER | 맞음 | RFC 2986 4.2 |
| V064 | 3.7: 기본 인증서·키·계정 키 파일 이름과 위치 | 맞음 | `certstore.go:64-81`, `:116`, `:284-288`(기본 파일 저장소) |
| V065 | 3.7: 인증서 응답은 leaf부터의 PEM 사슬 | 맞음 | RFC 8555 7.4.2·9.1 |
| V066 | 3.7: CERTIFICATE 아닌 BEGIN은 전체 거부해야 함 | 맞음 | RFC 8555 11.4. Go의 decode 실패 잔여 입력 한계 보충 |
| V067 | 3.7: Go는 다른 PEM 종류·6장 이상·빈 사슬 거절 | 맞음 | `rfc8555.go:423-446`(bundle=true 경로) |
| V068 | 3.7: Go 인증서 응답 전체 본문은 약 5MiB | 맞음 | `rfc8555.go:412-420`. 정확히 5,401,755바이트로 보충 |
| V069 | 3.7: Go는 받은 사슬을 다시 PEM으로 저장 | 맞음 | `feature/acme/cert.go:600-609` |
| V070 | 3.7: Go 개인 키 저장은 SEC1 EC PRIVATE KEY | 맞음 | RFC 5915 3절, `certstore.go:323-330` |
| V071 | 3.7: 계정 키는 PKCS#1·PKCS#8·SEC1 차례로 읽음 | 맞음 | `certstore.go:340-359` |
| V072 | 3.7: 인증서 키는 tls.X509KeyPair로 읽음 | 맞음 | `certstore.go:415` |
| V073 | 3.7: 키 다음 인증서·각각 원자적 파일 교체 | 맞음 | `certstore.go:164-168`, `atomicfile/atomicfile.go:21-51` |
| V074 | 4.1.1: 자기·피어 Addresses의 단일 IP만 주소 표에 넣음 | 맞음 | `ipn/ipnlocal/node_backend.go:712-733` |
| V075 | 4.1.1: AllowedIPs·만료·오프라인 필터 없음 | 맞음 | `node_backend.go:719-732` |
| V076 | 4.1.2: IPv4-mapped IPv6는 Unmap 후 찾음 | 맞음 | `ipn/ipnlocal/local.go:1756-1758` |
| V077 | 4.1.2: 직접 주소가 없으면 ProxyMapper 경로 | 맞음 | `local.go:1773-1797`(포트·buildfeatures 조건 보충) |
| V078 | 4.1.2: 직접 tailnet 주소 리스너는 ProxyMapper 불필요 | 맞음 | `local.go:1771-1773`, tsnet 직접 연결 주소 경로에서의 범위 판단 |
| V079 | 4.1.3: User로 프로필을 찾고 없으면 WhoIs 실패 | 맞음 | `local.go:1807-1811` |
| V080 | 4.1.4: UserProfiles는 변경분이며 Go 캐시에 누적 | 맞음 | `control/controlclient/map.go:384-387`, 같은 파일 `:302-313` |
| V081 | 4.1.4: 최종 netmap은 자기 User·피어 User와 Sharer만 포함 | 맞음 | `map.go:674-685`, `:1054-1058` |
| V082 | 4.1.4: 증분 upsert의 프로필을 캐시에서 재공급 | 맞음 | `map.go:302-346` |
| V083 | 4.1.4: Swiftail MapSession도 프로필을 누적·선별 | 맞음 | `Sources/SwiftailControl/Netmap/MapSession.swift:36-38`, `:198-213` |
| V084 | 4.1.5: ComputedName의 접미사 제거·hostname·key fallback | 맞음 | `tailcfg/tailcfg.go:660-689`; 공유받은 FQDN·점 처리 보충 |
| V085 | 4.1.5: 접미사는 자기 이름 첫 레이블 뒤의 나머지 | 맞음 | `types/netmap/netmap.go:256-270`; 점 없는 이름 분기 보충 |
| V086 | 4.1.5: 맵 응답의 노드마다 표시 이름 계산 | 맞음 | `control/controlclient/direct.go:1419-1434` |
| V087 | 4.1.6: 태그 노드 User는 생성 사용자 의미 | 맞음 | `tailcfg/tailcfg.go:380-383` |
| V088 | 4.1.6: pgproxy는 tagged-devices일 때 Tags 사용 | 맞음 | `cmd/pgproxy/pgproxy.go:218-222` |
| V089 | 4.1.6: 운영 서버의 태그 프로필 값 | 확인 불가 | 도구의 분기는 운영 서버 보장이 아니다(8장) |
| V090 | 4.1.7: CapMap은 현재 필터·첫 원격 주소·같은 계열 자기 주소 | 맞음 | `ipn/localapi/localapi.go:601-620`, `node_backend.go:443-467` |
| V091 | 4.1.7: UnsignedPeerAPIOnly는 ingress capability만 | 맞음 | `node_backend.go:429-440`, `:460-462` |
| V092 | 4.1.7: 첫 사용처는 CapMap을 읽지 않음 | 맞음 | RemoteDebug `node.go:526-545` |
| V093 | 4.1.8: WhoIs 찾기 실패 404 → ErrPeerNotFound | 맞음 | `localapi.go:593-596`, `client/local/local.go:353-362` |
| V094 | 4.1.8: 첫 사용처 WhoIs 실패는 403 not_paired | 맞음 | RemoteDebug `core/internal/host/host.go:230-243` |
| V095 | 4.1 표: Swiftail Node에 필요한 신원·주소·Hostinfo 필드 존재 | 맞음 | `Sources/SwiftailControl/Tailcfg/Node.swift` |
| V096 | 4.1 표: Swiftail UserProfile에 Groups 해석 없음 | 맞음 | `Sources/SwiftailControl/Tailcfg/UserProfile.swift` |
| V097 | 4.1 표: Swiftail 주소 표·ComputedName 계산은 아직 없음 | 맞음 | `Sources/Swiftail/` 검색, `Netmap+HostResolution.swift`의 이름 해석과 구분 |
| V098 | 4.1 표: Swiftail은 capGrant만 해석하고 주소쌍 수집 없음 | 맞음 | `Sources/SwiftailControl/Tailcfg/FilterRule.swift`, `Sources/` 검색 |
| V099 | 4.1 끝: 최소 WhoIs 신원 조회는 netmap의 정보로 답할 수 있음 | 맞음 | `local.go:1771-1811`. 전체 CapMap은 파생한 현재 필터 계산도 필요(`node_backend.go:443-450`) |
| V100 | 4.2.1: 도메인 잠금 뒤 캐시 다시 읽기 | 맞음 | `feature/acme/cert.go:345-363` |
| V101 | 4.2.2: onlyReturnExisting → ErrNoAccount면 Register | 맞음 | `cert.go:451-473`, `rfc8555.go:126-137` |
| V102 | 4.2.2: 등록이 이미 있음이면 계정 재조회 | 맞음 | `cert.go:460-462` |
| V103 | 4.2.2: 약관 동의는 termsOfServiceAgreed로 전송 | 맞음 | `rfc8555.go:49-61`; directory에 약관 URL 있을 때 전송함을 보충 |
| V104 | 4.2.2: 계정 valid 검사·연락처 없음 | 맞음 | `cert.go:390-392`, `:460`, `rfc8555.go:54` |
| V105 | 4.2.3: 시스템 TXT 조회 기한 500ms·같은 값이면 생략 | 맞음 | `cert.go:628-643` |
| V106 | 4.2.4: set-dns 직후 전파 대기 없이 Accept | 맞음 | `cert.go:639-650` |
| V107 | 4.2.4: 운영 set-dns가 DNS 전파 때까지 응답을 미룬다 | 확인 불가 | 클라이언트 호출 순서로 서버 대기 보장 추론 불가. 8장으로 이동 |
| V108 | 4.2.5: challenge 후 WaitOrder ready·valid, invalid 실패 | 맞음 | `cert.go:563-576`, `rfc8555.go:283-318` |
| V109 | 4.2.5: WaitOrder는 Retry-After 또는 1초 | 맞음 | `rfc8555.go:303-308` |
| V110 | 4.2.6: ready가 된 뒤에만 새 인증서 키를 생성 | 틀림 | WaitOrder는 valid도 반환하나 호출부는 늘 새 키 생성·finalize(`cert.go:564-594`) |
| V111 | 4.2.6: 갱신마다 새 P-256 키 | 맞음 | `cert.go:578-587` |
| V112 | 4.2.7: Go는 이미 valid인 authorization도 dns-01 응답 시도 | 맞음 | `cert.go:531-561`, `:615-651` |
| V113 | 4.2.7: authorization 재사용 시 Go 실제 발급 결과 | 확인 불가 | 실행하지 않음. 코드 동작과 운영 성공을 구분(8장) |
| V114 | 4.2.8: DNS-01 실패 뒤 TXT 삭제·주문 취소가 없음 | 맞음 | `cert.go:487-654`. 잠금 해제·재시도·범위 밖 TLS-ALPN 정리와 구별해 보충 |
| V115 | 4.2.8: 발급 재시도는 새 주문부터이며 호출자가 간격 결정 | 맞음 | `cert.go:525`, RemoteDebug `node.go:825-859`; HTTP 내부 재시도와 구별 |
| V116 | 4.2.8: 첫 사용처 재시도 30초~10분 두 배 | 맞음 | RemoteDebug `node.go:55-56`, `:849` |
| V117 | 4.2.9: 일반 ts.net 이름은 비지 않은 CertDomains의 정확한 항목이어야 함 | 맞음 | `cert.go:699-718`. 범위 밖 wildcard·BYO Funnel 예외도 보충(`:700-724`) |
| V118 | 4.2.9: 첫 사용처는 MagicDNSEnabled도 검사 | 맞음 | RemoteDebug `core/internal/node/tls.go:27-32` |
| V119 | 4.2.10: Go User-Agent의 tailscaled와 ACME 패키지명 | 맞음 | `certstore.go:399-403`, `tempfork/acme/http.go:295-304` |
| V120 | 4.2.10: ACME User-Agent는 필수 | 맞음 | RFC 8555 6.1 |
| V121 | 4.3.1: 디렉터리 GET·필요 URL과 meta.termsOfService | 맞음 | RFC 8555 7.1.1, `acme.go:166-216` |
| V122 | 4.3.1: Go는 newOrder가 없으면 pre-RFC 오류 | 맞음 | `acme.go:199-201` |
| V123 | 4.3.2: newNonce HEAD·Replay-Nonce 취득 | 맞음 | RFC 8555 7.2 |
| V124 | 4.3.2: 성공·오류 응답에서 nonce를 수집 | 맞음 | RFC 8555 6.5, `http.go:240` |
| V125 | 4.3.2: 잘못된 nonce는 무시해야 함 | 맞음 | RFC 8555 6.5.1; Go는 검증하지 않는 차이 보충 |
| V126 | 4.3.3: onlyReturnExisting의 JWK·200·Location·미존재 오류 | 맞음 | RFC 8555 7.3.1 |
| V127 | 4.3.4: 계정 생성의 약관 동의·201 또는 기존 200·Location | 맞음 | RFC 8555 7.3·7.3.1 |
| V128 | 4.3.4: 계정 valid 상태 확인 | 맞음 | RFC 8555 7.1.2·7.1.6, `cert.go:390-392` |
| V129 | 4.3.5: newOrder는 dns 식별자·kid·201·Location | 맞음 | RFC 8555 7.4 |
| V130 | 4.3.5: order는 status·authorizations·finalize 포함 | 맞음 | RFC 8555 7.1.3 |
| V131 | 4.3.6: authorization POST-as-GET과 valid 건너뛰기 | 맞음 | RFC 8555 7.1.3·7.1.4·7.1.6 |
| V132 | 4.3.6: pending에서 dns-01 선택, 나머지 종료 상태 실패 | 맞음 | RFC 8555 7.1.4·7.1.6·8.4(미지원 상태 거절은 구현 정책) |
| V133 | 4.3.7: TXT 설정 후 challenge 응답 | 맞음 | RFC 8555 8.4, `feature/acme/cert.go:639-646` |
| V134 | 4.3.8: challenge 응답은 빈 JSON 객체 | 맞음 | RFC 8555 7.5.1 |
| V135 | 4.3.8: Go Accept는 200과 202 허용 | 맞음 | `tempfork/acme/acme.go:570-573` |
| V136 | 4.3.9: order ready·valid·invalid 분기 | 맞음 | RFC 8555 7.1.6·7.4; valid에는 기존 CSR 키가 필요한 조건 보충 |
| V137 | 4.3.9: pending·processing 폴링의 기본 1초 | 맞음 | Go의 선택값(`rfc8555.go:303-308`); RFC 상수와 구별 |
| V138 | 4.3.10: finalize 200·갱신 order, 준비 전 403 orderNotReady | 맞음 | RFC 8555 7.4 |
| V139 | 4.3.11: processing을 폴링하고 valid에서 certificate URL | 맞음 | RFC 8555 7.4; finalize 직후 invalid·pending·ready 분기 보충 |
| V140 | 4.3.12: 인증서 POST-as-GET과 기본 PEM 사슬 형식 | 맞음 | RFC 8555 7.4.2 |
| V141 | 4.3.12: Accept 머리를 사용하는 절차 | 맞음 | 허용된 구현 선택이다. RFC 필수·Go 동작과는 구별 |
| V142 | 4.3 오류: 오류는 항상 problem+json이고 type은 ACME URN뿐 | 틀림 | 문제 문서는 SHOULD, 다른 URI·about:blank 가능(RFC 8555 6.7, RFC 7807 3.1) |
| V143 | 4.3 오류: badNonce 재시도는 오류 응답 nonce를 사용해야 함 | 맞음 | RFC 8555 6.5. Go의 실제 캐시 삭제 차이를 보충 |
| V144 | 4.3 오류: accountDoesNotExist·rateLimited·orderNotReady 대응 | 맞음 | RFC 8555 7.3.1·6.6·7.4 |
| V145 | 4.3 오류: userActionRequired는 약관 변경을 알릴 때 사용 | 맞음 | RFC 8555 7.3.3. 다른 사용자 조치와 instance 링크도 보충 |
| V146 | 4.3 끝: Go 재시도 후보는 <=399·>=500·429 | 맞음 | `http.go:321-323`; 기대한 성공 응답 제외·전송 오류 즉시 반환 보충 |
| V147 | 4.3 끝: 지터를 10초 상한 뒤에 더한다 | 틀림 | 헤더 없을 때 min(지수+지터,10초), 헤더 있으면 헤더+지터(`http.go:68-90`) |
| V148 | 4.3 끝: 기본 재시도 횟수 무제한·context로 중단 | 맞음 | `http.go:39-59`, `:172-198` |
| V149 | 4.4.1: 기본 갱신 판정은 ARI의 무작위 제안 시각 | 맞음 | `feature/acme/cert.go:187-198`, `:334-339` |
| V150 | 4.4.1: ARI 조회 기한 5초·실패하면 수명 2/3 | 맞음 | `cert.go:188-191`, `:233-251`, `:324-328` |
| V151 | 4.4.1: 갱신 시각을 캐시하고 다시 묻지 않음 | 틀림 | 성공 후 캐시 삭제해 다시 계산(`cert.go:201-204`, `:610`) |
| V152 | 4.4.2: 갱신마다 replaces를 싣는다 | 틀림 | 유효 previous·파싱·debug·저장소 허용 조건이 있음(`cert.go:394-420`) |
| V153 | 4.4.3: min_validity=0이면 기존 인증서를 주고 비동기 갱신 | 맞음 | `cert.go:138-153` |
| V154 | 4.4.3: 비동기 갱신은 도메인별 하나 | 맞음 | `cert.go:212-230` |
| V155 | 4.4.4: Listen만이면 1시간 refresh 루프가 돌지 않음 | 맞음 | `feature/acme/refresh.go:35-76`, `:134-153` |
| V156 | 4.4.4: 첫 사용처의 핸드셰이크가 갱신을 촉발 | 맞음 | RemoteDebug `tls.go:41`; 초기 warmup 이후 경로 |
| V157 | 4.4.5: 캐시 읽기는 키 짝·이름·시각·시스템/내장 루트 검증 | 맞음 | `certstore.go:135-154`, `:411-459`(기본 운영 디렉터리) |
| V158 | 4.4.5: 검증 실패면 만료로 보고 재발급 | 맞음 | `certstore.go:150-151`, `cert.go:353-365`; 일반 I/O 오류와 디버그 루트 예외 보충 |
| V159 | 4.5: 같은 식별자 집합 5장/7일·34시간 회복·예외 불가 | 맞음 | Let’s Encrypt Rate Limits의 해당 절(2026-11-15) |
| V160 | 4.5: 등록 도메인 50장/7일·PSL 사용 | 맞음 | 같은 공식 문서의 New Certificates per Registered Domain |
| V161 | 4.5: 계정 새 주문 300개/3시간 | 맞음 | 같은 공식 문서의 New Orders per Account |
| V162 | 4.5: 새 주문 한도에는 닿지 않는다 | 틀림 | 계정 공유·오류 재시도까지 포함하므로 보장 불가. 4.5 조건부 설명으로 정정 |
| V163 | 4.5: authorization 실패 5회/시간·12분 회복 | 맞음 | 같은 공식 문서의 Authorization Failures per Identifier per Account |
| V164 | 4.5: 회복률 12분은 반드시 지킬 최소 요청 간격 | 틀림 | token bucket 회복률이며 burst도 허용됨. 4.5 정정 |
| V165 | 4.5: 새 계정 10개/IP/3시간 | 맞음 | 같은 공식 문서의 New Registrations per IP Address |
| V166 | 4.5: replaces만 넣으면 모든 제한 면제 | 틀림 | 겹치는 식별자·미대체 인증서 등의 ARI 갱신 인정 조건 필요. 공식 ARI Renewals 절 |
| V167 | 4.5: 비ARI 동일 집합은 새주문·등록도메인 면제, 동일집합 제한 적용 | 맞음 | 공식 Non-ARI Renewals 절 |
| V168 | 4.5: 2/3 갱신이면 속도 제한에 닿지 않는다는 일반 결론 | 틀림 | 수명·동시 발급·실패 조건 없는 보장은 성립하지 않음. 4.5·6장 수정 |
| V169 | 4.5: 제한 오류의 Retry-After·스테이징 권고 | 맞음 | 공식 Retry-After Header 절과 개발·시험 안내 |
| V170 | 4.6: CryptoKit P256.Signing.PrivateKey 생성 | 맞음 | SDK 선언과 이번 형식 검사(4.6) |
| V171 | 4.6: CryptoKit raw ECDSA 서명은 64바이트 | 맞음 | 이번 서명 생성·검증 실행 |
| V172 | 4.6: derRepresentation으로 CSR 서명 표현을 얻을 수 있음 | 맞음 | `CryptoKit.swiftinterface:1630-1637` |
| V173 | 4.6: 작성 세션의 CSR이 openssl req -verify 통과 | 확인 불가 | 프로그램·출력 없음. 8장으로 이동 |
| V174 | 4.6: 공개 x963은 04·X·Y 65바이트 | 맞음 | 이번 형식 검사, `SecKey.h:824-826` |
| V175 | 4.6: 공개 derRepresentation은 91바이트 | 맞음 | 이번 형식 검사, SPKI는 RFC 5480 2절 |
| V176 | 4.6: Go SEC1 EC PRIVATE KEY를 CryptoKit이 읽음 | 맞음 | 이번 Go 생성 → CryptoKit import 통과 |
| V177 | 4.6: CryptoKit pemRepresentation은 PKCS#8 PRIVATE KEY | 맞음 | 이번 PEM label·키 재읽기 통과 |
| V178 | 4.6: CSR 쓰기에 제시한 태그만 필요하고 Go와 맞음 | 틀림 | Go와 맞추려면 PrintableString 필요. 고정 3바이트 길이 한계는 구현 선택으로 분리 |
| V179 | 4.6: 열다섯 줄·295바이트 CSR이 검증됐다는 실험 | 확인 불가 | 작성 세션 자료 없음. 8장으로 이동 |
| V180 | 4.6: 유효 기간 API는 macOS15·iOS18부터 | 맞음 | `SecCertificate.h:204-223` |
| V181 | 4.6: 해당 유효 기간 API의 작성 세션 실행 성공 | 확인 불가 | SDK 선언만 재확인. 8장으로 이동 |
| V182 | 4.6: SecTrust와 SSL policy API가 공개 | 맞음 | `SecPolicy.h:196`, `SecTrust.h:231`, `:347`, `:426` |
| V183 | 4.6: 인증서 공개 키 추출·external representation API 공개 | 맞음 | `SecCertificate.h:149-157`, `SecKey.h:843-855` |
| V184 | 4.6: URLSession은 프로젝트가 허용한 프레임워크 | 맞음 | `docs/plan.md` 4절(c)(정책) |
| V185 | 4.6: 필요 인증서 값은 Security API로 얻을 수 있음 | 맞음 | 위 SDK 선언; 실행·샌드박스 검증과 구별 |
| V186 | 4.6: SecIdentityCreate 공개·macOS10.12·iOS11.2부터 | 맞음 | `SecIdentity.h:57-70` |
| V187 | 4.6: SecKeyCreateWithData의 개인 키 X9.63 97바이트 | 맞음 | `SecKey.h:812-829`, 이번 CryptoKit 크기 검사 |
| V188 | 4.6: SecIdentityCreate 경로의 TLS·ALPN 협상 실행 성공 | 확인 불가 | 작성 세션 네트워크 실험 자료 없음. 8장으로 이동 |
| V189 | 4.6: 그 네트워크 실험이 키체인에 전혀 쓰지 않았음 | 확인 불가 | 호출 선언과 실행 부작용 검증은 다름. 8장으로 이동 |
| V190 | 4.6: PKCS12 memory-only 옵션·macOS15·iOS18부터 | 맞음 | `SecImportExport.h:652-661`, `:711-712` |
| V191 | 4.6: App Sandbox 안에서도 동작하는지 | 확인 불가 | SDK 선언만으로 entitlements·실행 결과 보장 불가(8장) |
| V192 | 4.7.1: tsnet Dir가 varRoot | 맞음 | `tsnet/tsnet.go:848-869`, `:984`; 비면 기본 디렉터리인 분기 보충 |
| V193 | 4.7.1: tsnet 기본 상태 파일·로그 설정·로그 버퍼 이름 | 맞음 | `tsnet.go:965-972`, `:1104`, `:1120`; Store 지정·시험 logger 예외 보충 |
| V194 | 4.7.1: certs 디렉터리에 세 종류 파일 | 맞음 | `feature/acme/certstore.go:64-81`, `:116-168` |
| V195 | 4.7.1: 직접 연결의 세 파일은 첫 사용처 소유 | 맞음 | RemoteDebug `2814b2c` `core/internal/direct/direct.go:30-35` |
| V196 | 4.7.1: iPhone이 직접 연결 키를 고정하므로 보존 필요 | 맞음 | RemoteDebug `direct.go:55-60`, `docs/protocol-addenda.md` 직접 연결 TLS 설명 |
| V197 | 4.7.2: _machinekey·현재 profile의 Config·prefs 경로 | 맞음 | `ipn/store.go:24`, `:55-57`, `profiles.go:657-666`, `ipn/prefs.go:314-319` |
| V198 | 4.7.2: Persist의 node 키·이전 키·NLKey·ID·프로필 필드 | 맞음 | `types/persist/persist.go:21-39` |
| V199 | 4.7.2: 나열한 모든 개인 키가 privkey + hex64 | 틀림 | NetworkLockKey는 nlpriv 머리·Ed25519 타입(`types/key/nl.go:16-18`, `:32-36`) |
| V200 | 4.7.3: Go machine·node 텍스트와 Swiftail 저장 텍스트 동일 | 맞음 | `NodeIdentityStore.swift:5-11`, `types/key/machine.go:24`, `types/key/node.go:29` |
| V201 | 4.7.3: node 키가 0이면 로그인한 적 없다는 뜻 | 틀림 | 키 부재만으로 로그인 이력 추론 불가. G3의 이관 거절 조건으로 분리 |
| V202 | 4.7.3: OldPrivateNodeKey는 교체 요청에만 쓰고 이관 불필요 | 틀림 | 재등록에서도 값이 있으면 전송. 정상 등록 완료 키만 이관한다는 범위 필요(`direct.go:718-720`, `:761`) |
| V203 | 4.7.3: Swiftail은 NLKey를 0으로 전송 | 맞음 | `Sources/SwiftailControl/Client/ControlClient+Registration.swift:44-53`, `Tailcfg/RegisterRequest.swift` |
| V204 | 4.7.3: NodeID·UserProfile·_profiles는 Swiftail 신원 파일에 없음 | 맞음 | `NodeIdentityStore.swift`, `NodeIdentity.swift` |
| V205 | 4.7.3: 이 메타데이터는 Go RegisterRequest 신원 키가 아님 | 맞음 | `control/controlclient/direct.go:759-770`; Go 프로필 선택과 분리 |
| V206 | 4.7.3: 빈 ControlURL은 기본 서버 | 맞음 | `ipn/prefs.go:60-64`; 공식 과거 URL 동의어 이주 보충 |
| V207 | 4.7.3: LoggedOut은 의도적 로그아웃 상태 | 맞음 | `ipn/prefs.go:152-159` |
| V208 | 4.7.3: P-256 SEC1·PKCS#8 인증서 파일 호환 경로 | 맞음 | 이번 import 검사, `certstore.go:340-359`, `:415`; 신뢰 검증은 별도 |
| V209 | 4.7.4: 동일 node 키의 두 맵·DERP 세션이 유지됨 | 확인 불가 | 각 클라이언트의 연결 시도는 알 수 있으나 서버 중복 세션 정책 미확인. 단정 삭제 |
| V210 | 4.7.4: 키 교체는 현재 키를 OldPrivateNodeKey로 옮김 | 맞음 | `control/controlclient/direct.go:704-720` |
| V211 | 4.7.4: 다른 구현의 옛 키는 OldNodeKey로만 의미 있음 | 확인 불가 | 클라이언트가 이전 키를 넣는 사실로 서버의 옛 키 취급 결론을 낼 수 없음 |
| V212 | 5: 캐시 nonce 상한 100·보통 1~2개 | 맞음 | `tempfork/acme/acme.go:69-71` |
| V213 | 5: 인증서 한 장마다 1MiB 크기 상한 검사 | 틀림 | RFC 경로는 합산 본문 상한만 검사(`rfc8555.go:412-446`) |
| V214 | 5: 키·계정키0600·인증서0644·디렉터리0700 | 맞음 | `certstore.go:76-78`, `:130-162` |
| V215 | 5: 첫 사용처 발급 기한2분·WhoIs 기한5초 | 맞음 | RemoteDebug `node.go:836`, `host.go:236` |
| V216 | 6: Go의 Tailscale 계정 등록은 EAB·연락처를 안 씀 | 맞음 | `feature/acme/cert.go:460`, `rfc8555.go:49-69` |
| V217 | 6: RSA·P-384 등은 새 키 생성의 최소 경로에서 안 씀 | 맞음 | `feature/acme/certstore.go:377`, `cert.go:578`; 기존 키 읽기 지원은 별개 |
| V218 | 6: Tailscale의 Go 발급 경로는 대체 사슬을 쓰지 않음 | 맞음 | `feature/acme/cert.go:594-607`. 포크의 ListCertAlternates API는 별도로 존재(`rfc8555.go:475-498`) |
| V219 | 6: wireguard 신원에 ProxyMapper·node 키 조회·CapMap 생략 가능 | 맞음 | 첫 사용처 호출 범위에 대한 선택. `node.go:526-545` |
| V220 | 6: TLS-ALPN-01·wildcard·BYO는 이번 최소 범위 밖 | 맞음 | `docs/plan.md` 3절과 계약 제외 표; Go의 분기는 별도 존재 |
| V221 | 7.1: JWK·지문·DNS-01 동일 입력의 바이트 일치 시험 가능 | 맞음 | 결정적 식의 대조 설계(`jws.go:160-196`, `:250-257`, `acme.go:591-598`) |
| V222 | 7.1: JWS 보호 머리·서명 입력이 구현 간 반드시 바이트 동일 | 틀림 | JSON 멤버 순서는 고정 아님. RFC 7515 5.1; 동일 직렬화 선택 시만 바이트 비교 |
| V223 | 7.1: ECDSA 서명은 바이트 대신 상대 구현의 검증으로 대조 | 맞음 | Go `jws.go:205`, CryptoKit 서명 API; 시험 설계 |
| V224 | 7.2: 같은 공개 키의 CSR Info는 항상 바이트 동일 | 틀림 | CN 태그·속성·DER 선택까지 같아야 함. 3.6·7.2 정정 |
| V225 | 7.3: testcontrol은 TXT·비지 않은 이름/값·node/machine 소유 검사 | 맞음 | `tstest/integration/testcontrol/testcontrol.go:605-649` |
| V226 | 7.3: testcontrol은 cert 도메인과 ACME 접두 검사·OnSetDNS 제공 | 맞음 | `testcontrol.go:636-648`, `:66` |
| V227 | 7.4: DNSConfig와 MagicDNSDomain이 있으면 netmap CertDomains 추가 | 맞음 | `testcontrol.go:1651-1668` |
| V228 | 7.4: 현재 도구는 MagicDNSDomain을 제공 | 맞음 | `Tools/interop/cmd/tailnet/main.go:115`; DNSConfig 부재도 보충 |
| V229 | 7.5: pebble va.New는 custom resolver를 받음 | 맞음 | `github.com/letsencrypt/pebble/v2@v2.10.3/va/va.go:121-142` |
| V230 | 7.5: challtestsrv는 TXT 추가 DNS 서버 API 제공 | 맞음 | `github.com/letsencrypt/challtestsrv@v1.4.2/dns.go:75-80` |
| V231 | 7.5: OnSetDNS와 연결하면 한 프로세스 발급이 동작함 | 확인 불가 | API는 있지만 통합 빌드·실행 안 함. 관문 설계로 정정 |
| V232 | 7.5: pebble nonce 거부·authorization 재사용 환경 변수 | 맞음 | `github.com/letsencrypt/pebble/v2@v2.10.3/wfe/wfe.go:86`, `:111` |
| V233 | 7.7: Go 키 가져오기로 같은 IP·StableID가 됨 | 확인 불가 | 실행 전 관문의 기대 결과다. 정상 등록 완료 상태 외 보장 삭제 |
| V234 | 7.8: 실제 set-dns·발급·itms-services는 로컬 시험만으로 미확인 | 맞음 | 관문 범위. 이번 실제 발급 없음 |
| V235 | 8: 운영 set-dns 수락·응답 지연·빈도·오류 형식 | 확인 불가 | 클라이언트·testcontrol은 운영 제어 서버 구현이 아님 |
| V236 | 8: 태그·공유 노드 프로필의 운영 보장 | 확인 불가 | 클라이언트 타입·조회 규칙만 대조 가능 |
| V237 | 8: ts.net의 실제 운영 CA 제한 경계 | 확인 불가 | 공개 PSL의 일반 이름 eTLD+1은 4.5에서 확인·계산. CA 배포 snapshot·override는 미확인 |
| V238 | 8: CertDomains가 있으면 MagicDNS가 반드시 켜짐 | 확인 불가 | 첫 사용처가 따로 검사. 서버 관계 보장은 없음 |
| V239 | 8: SecTrust·공개 키 비교·중간 사슬 전달 실행 | 확인 불가 | SDK 선언만 대조. 실행하지 않음 |
| V240 | 8: pebble·challtestsrv 통합 빌드와 버전 충돌 여부 | 확인 불가 | 의존성 서명만 대조. 실행하지 않음 |
| V241 | 8: 두 모듈은 MPL-2.0 | 맞음 | 각 모듈 `LICENSE:1` |
| V242 | 8: 두 모듈 모두 go1.25 | 틀림 | pebble go1.25.0, challtestsrv go1.24(각 `go.mod:3`) |
| V243 | 8: NLKey 0으로 다시 붙을 때 운영 서버 결과 | 확인 불가 | 클라이언트 송신 형식만 확인 |
| V244 | 8: 현재 이번 노드에 실제 발급된 인증서 수명 | 확인 불가 | 공식 기본 수명은 4.5로 이동, 실제 발급은 하지 않음 |
| V245 | 5: 기본 ACME directory URL은 Let’s Encrypt 운영 URL | 맞음 | `tempfork/acme/acme.go:45-47` |
| V246 | 5: TS_DEBUG_ACME_DIRECTORY_URL로 directory 변경 | 맞음 | `feature/acme/certstore.go:399-403` |
| V247 | 6: 순차 요청은 nonce 하나만 보관하는 구현 가능 | 맞음 | RFC 8555 6.5·7.2. 없을 때 HEAD 취득·badNonce 전용 nonce 사용 필요 |
| V248 | 6: Tailscale 통합은 계정 키 교체·계정 비활성화·폐기를 호출하지 않음 | 맞음 | `feature/acme/` 호출 검색과 `cert.go:451-473`, `:525-607`; 포크 API 지원과 구별 |

## 10. 계약 초안과의 대조(계약 파일은 수정하지 않음)

다음은 `docs/contracts/SwiftailHost.md`의 W·D·C·S·R·G를 이 노트와 대조한 결과다. Go와 다른 제한을 택하는 것 자체는 오류가 아니다. 아래는 프로토콜과의 충돌, 이 노트의 정정이 반영되어야 하는 곳, 또는 선택의 한계를 더 적어야 하는 곳이다.

| 동작 | 수정·명시할 내용 | 근거 |
| --- | --- | --- |
| W4, 공개 `computedName` 주석 | 공유받은 다른 tailnet 이름은 **FQDN 유지**, 같은 접미사는 레이블 경계에서만 제거, 끝 점 제거, hostname 공통 접미사 정리를 적는다. W1~W3·W5는 현재 Go 주소 조회와 맞으며 StableID 빈 값 거절은 첫 사용처의 추가 정책이다 | 4.1 1~5, `tailcfg/tailcfg.go:660-689`, `util/dnsname/dnsname.go:203-239` |
| D1~D3 | 같은 **Noise client**와 같은 HTTP/2 물리 연결 보장을 구별한다. D2의 연결 대기 60초는 Go의 즉시 오류와 다른 선택이며, D3의 객체만·4KiB·본문 비노출도 더 좁은 선택임을 유지한다. “Go와 같은 동작”으로 확대 해석하지 않는다 | 3.2, `local.go:7826-7830`, `control/ts2021/client.go:320-336` |
| C2 | 경로 검사와 DNS 이름 유효성 검사를 구별한다. DNS 이름을 검증하려면 각 레이블의 **처음·끝은 영숫자**, 끝 점 없는 전체 길이는 DNS wire의 255바이트 한도를 만족하도록 정한다(ASCII 일반 이름이면 최대 253자). `_acme-challenge.`를 붙인 최종 레코드 이름도 별도로 이 한도를 검사한다. 현재 글의 255바이트·문자 집합만으로는 이 조건이 안 나온다 | RFC 1034 3.1·3.5, RFC 1123 2.1, `util/dnsname/dnsname.go:129-158`; Go `validLookingCertDomain`은 완전 DNS 검사가 아님 |
| C4, S2, G6 | 계정 키 읽기/생성/등록의 동시성·손상 계정 키 오류를 명시한다. P-256만 지원하는 최소 구현은 Go가 읽을 수 있는 기존 RSA 계정 키까지 호환한다고 보장하지 않는다. S2의 PKCS#8·SEC1 읽기 경로는 이번 검사로 확인했다 | 3.7·4.6·4.8, `certstore.go:340-388` |
| C5 | 식별자 하나라고 `authorizations.count == 1`을 강제하는 근거가 없다. 모든 authorization을 상태별 처리하고 `identifier.type`·값·wildcard 여부를 확인한다. 주문이 이미 ready인 분기도 명시한다 | RFC 8555 7.1.3·7.1.4·7.4, 4.3 5·6 |
| C7, R4, X2·X5, 한도 표 | 유효한 `Retry-After`를 30초·24시간으로 줄여 그 전에 **새 HTTP 요청**을 보내면 서버가 알려 준 대기 시각을 따르지 않는다. 기한 뒤 실패하거나 대기 시각을 보존한다. 24시간마다 로컬 상태만 재평가하는 것과 요청 재시도를 구별한다 | RFC 8555 6.6·7.4, RFC 7231 7.1.3, 4.3·4.5 |
| C7, `CertificateFailure.validationFailed`, R4 | finalize 응답의 valid·invalid·pending·ready·processing을 모두 다룬다. CSR을 보내기 전 valid에는 대응 개인 키가 없으므로 다운로드만 진행하면 안 된다. order invalid는 DNS 실패뿐 아니라 만료·CSR/발급 오류도 가능하므로 모든 invalid를 “DNS 확인 실패”라고 단정하지 않는다 | RFC 8555 7.1.6·7.4, 4.3 9~11 |
| C·R의 문제 문서, 공개 `CertificateFailure.acme` 주석 | `type`은 ACME URN의 접미사만이 아니라 임의 URI reference·about:blank도 허용한다. HTTP 상태·JSON 아닌 오류·subproblems도 표현 가능하게 정한다 | RFC 8555 6.7·6.7.1, RFC 7807 3.1, 4.3 오류 처리 |
| C8, S3 | 저장 전 키·이름·사슬 검증은 유지한다. S3의 시스템 루트만 쓰는 선택은 Go의 내장 루트 fallback과 다르다. 시험에는 명시적 앵커를 쓰며 Go의 비운영 UnknownAuthorityError 무시는 복제하지 않는다 | 4.4 5, `certstore.go:440-477` |
| S1~S3, 공개 `chain` 주석 | 새 디렉터리의 0700과 기존 디렉터리 권한 검사를 구별한다. 두 파일은 한 트랜잭션이 아니다. “루트는 없다”는 ACME 와이어 보장이 아니므로, 루트 제거가 API 정책이면 검증 후 처리 규칙을 명시한다 | 3.7, RFC 8555 9.1, `atomicfile/atomicfile.go:21-51` |
| R1·R4, H6·shortcut 근거 | 2/3는 최소 정책으로 유지할 수 있지만 속도 제한 회피 보장은 삭제한다. ARI 면제 조건·인증서 수명·동일 집합의 타 발급·연속 authorization 실패 제한을 함께 반영한다. 영구 실패를 끝없이 재발급하지 않도록 사용자 조치 필요 상태도 정한다 | 4.4·4.5, 공식 [Rate Limits](https://letsencrypt.org/docs/rate-limits/) |
| G2~G4 | 정상 등록 완료된 단일 프로필만 이관한다는 범위를 적고 `_current-profile`의 전체 키·Config 구조·0 machine 키·불일치한 _profiles·legacy 상태의 거절 규칙을 정한다. OldPrivateNodeKey 생략은 교체 중단 상태에서 Go와 같지 않다. 과거 공식 ControlURL 동의어도 기본 서버와 비교할 때 정규화할지 정한다 | 4.7 2~5, `profiles.go:318-328`, `:701-708`, `:951-977`, `direct.go:718-720` |
| G3 | “스킴·호스트·포트 같음”을 “등록한 서버가 같음”과 무조건 같다고 쓰지 않는다. 사용자 지정 control URL의 경로·query·fragment 허용 범위를 먼저 정하거나 금지한다(userinfo는 기존 ControlEndpoint가 이미 거절한다). 기본 서버 동의어만 별도로 다룬다 | Go는 `ServerURL`을 보존해 control endpoint를 만든다(`control/controlclient/direct.go:810-817`, `:1535-1537`, `Sources/SwiftailControl/Client/ControlEndpoint.swift:46-52`); 보수적인 이관 경계 제안 |
| G 공개 API, G4·G7·관문(가)11 | 가져오면 같은 IP·StableID라는 무조건 보장과 이전 키 재시작의 결과 단정을 완화한다. NLKey 0·키 교체 중단·서버 중복 세션 결과는 실제 이관 관문 전에는 확인되지 않았다 | 4.7·8장. G1·G5의 원본 읽기 전용·Go 중단 요구는 유지 |

계약의 시험 절에도 반영할 것: CSR 기준값의 CN 태그와 JWS JSON 순서를 구별한다(7장 1·2). 관문 도구는 DNSConfig도 제공해야 한다(7장 4). 계약 7절·9절의 **확인되지 않은 Apple 실험을 구현 완료 근거로 쓰지 않는다**(4.6·8장).

## 11. 이번 검증의 실행 결과

2026-11-15, `eyebuild run m7-note-check -- …`로 작은 Go·Swift 형식 검증 프로그램을 실행했다. Go는 1.27.3, Swift 컴파일은 `-swift-version 6 -strict-concurrency=complete -warnings-as-errors`였으며 컴파일 진단은 없었다. 키는 실행 중 무작위 생성해 작업용 디렉터리에서만 주고받았고 출력에는 키 바이트를 넣지 않았다. 결과:

```text
CryptoKit: signature raw=64, public x963=65, private x963=97, public DER=91
CryptoKit PEM label: -----BEGIN PRIVATE KEY-----; Go SEC1 import: 통과
CryptoKit SPKI의 OID·BIT STRING 구조: 통과
CryptoKit 출력의 Go PKCS#8 파싱: 통과
Go CSR: CN tag=19, signature=ECDSA-SHA256, SAN count=1, CheckSignature=<nil>
```

문서 검사는 판정 ID 248개의 연속성·집계, README 한 행만 변경, 표 열 수·코드 블록 짝, 출처의 전체 경로·SDK·RemoteDebug `2814b2c` 파일과 줄 범위 204건, RFC 원문 20개의 수신을 확인했다. 줄 범위 자동 검사는 본문의 의미 대조를 대신하지 않으며, 의미는 9장의 근거와 함께 읽어 대조했다. `git diff --check`를 통과했다. 라이브러리 코드 변경이 없어 저장소 전체 Swift 시험은 실행하지 않았다. 실제 발급·pebble 통합·TLS·샌드박스 시험도 실행하지 않았으며 8장에 남겼다.
