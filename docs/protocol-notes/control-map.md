# 제어 등록과 맵 내용 계층

## 1. 머리말

- 기준: `tailscale.com` v1.104.6, `CurrentCapabilityVersion = 148`. 버전 번호와 의미의 근거는 `tailscale.com/tailcfg/tailcfg.go:38`, `tailscale.com/tailcfg/tailcfg.go:198`이다.
- 작성 모델: GPT-6.1 Sol. 검증: Claude Opus 5.5, 2026-11-14, 수정 16건. JSON 형태는 기준 모듈의 tailcfg 타입을 Go 1.27.3 `encoding/json`으로 직접 marshal/unmarshal해 확인했다.
- 아래의 **구현 제안**과 **시험 항목**은 Swiftail에 대한 제안이다. 그 밖의 동작 설명은 각 행·문장에 붙인 기준 소스의 관찰 결과다.

## 2. 범위

등록 JSON, 로그인 상태, 맵 요청·응답, 프레임, 증분 상태 복원, 부가 호출 및 시험 서버를 다룬다. `/machine/register`와 `/machine/map`에 JSON을 POST하는 내용 계층이 대상이다. (`tailscale.com/tailcfg/tailcfg.go:1313`, `tailscale.com/tailcfg/tailcfg.go:1427`)

Noise 위 HTTP/2 연결이 이미 있다고 전제한다. Noise 핸드셰이크, HTTP 업그레이드, HTTP/2 구현 및 로드밸런서 헤더의 전송 상세는 `control-transport.md`의 범위로 둔다. 기준 클라이언트는 등록·맵 요청에 Noise 클라이언트를 사용한다. (`tailscale.com/control/controlclient/direct.go:805`, `tailscale.com/control/controlclient/direct.go:1162`)

## 3. 와이어 형식

### 3.1 메시지 외피와 기본 타입

오프셋은 각 HTTP 본문 또는 각 맵 프레임의 시작 기준이다. JSON 객체의 내부 필드에는 고정 바이트 오프셋이 없다. 요청은 JSON marshal 결과이고 등록 응답은 JSON unmarshal 대상이다. (`tailscale.com/control/controlclient/direct.go:1438`, `tailscale.com/control/controlclient/direct.go:1522`)

| 메시지 | 오프셋 | 길이 | 필드 | 인코딩·엔디언 | 출처 |
| --- | ---: | --- | --- | --- | --- |
| RegisterRequest | 0 | 본문 전체 | 요청 객체 | JSON, 길이 접두 없음 | `tailscale.com/control/controlclient/direct.go:813` |
| RegisterResponse | 0 | 본문 전체 | 응답 객체 | 비압축 JSON, 길이 접두 없음 | `tailscale.com/control/controlclient/direct.go:840`, `tailscale.com/control/controlclient/direct.go:1438`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1124` |
| MapRequest | 0 | 본문 전체 | 요청 객체 | JSON, 응답의 `Compress`와 무관하게 요청 자체는 JSON | `tailscale.com/control/controlclient/direct.go:1139`, `tailscale.com/control/controlclient/direct.go:1522` |
| MapResponse 프레임 | 0 | 4바이트 | `N` | unsigned 32-bit little-endian, 뒤따르는 페이로드만의 길이 | `tailscale.com/control/controlclient/direct.go:1467`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1895` |
| MapResponse 프레임 | 4 | `N`바이트 | 응답 페이로드 | `Compress="zstd"`이면 zstd로 압축한 JSON, 빈 값이면 JSON | `tailscale.com/tailcfg/tailcfg.go:1444`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1918` |
| 다음 MapResponse | `4+N` | 반복 | 다음 프레임 | 동일 HTTP 본문에서 연속 프레임, 한 번짜리 응답도 같은 형식 | `tailscale.com/control/controlclient/direct.go:1259`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1570` |
| SetDNSRequest/Response | 0 | 본문 전체 | 객체 / `{}` | JSON, 맵 프레임 없음 | `tailscale.com/control/controlclient/direct.go:1765`, `tailscale.com/control/controlclient/direct.go:1774`, `tailscale.com/tailcfg/tailcfg.go:2620` |
| SetDeviceAttributesRequest | 0 | 본문 전체 | 객체 | JSON, HTTP 메서드는 PATCH | `tailscale.com/control/controlclient/direct.go:1889`, `tailscale.com/control/controlclient/direct.go:1903` |
| HealthChangeRequest | 0 | 본문 전체 | 객체 | JSON POST | `tailscale.com/tailcfg/tailcfg.go:2623` |
| c2n 요청 | 0 | `Payload` 해독 길이 | HTTP 요청 | JSON의 바이트열 `Payload` 안에 HTTP/1.0 또는 HTTP/1.1 요청 | `tailscale.com/tailcfg/tailcfg.go:1932` |
| c2n 응답 POST | 0 | 본문 전체 | HTTP 응답 | 상태줄·헤더·본문을 포함해 직렬화한 HTTP 응답 | `tailscale.com/feature/c2n/c2n.go:52`, `tailscale.com/feature/c2n/c2n.go:58` |

타입 표에서 `?`는 nullable/생략 가능한 값, `[]`는 JSON 배열, `{문자열: T}`는 JSON 객체다. 정수 ID는 `int64` 기반이며 오래된 ID는 `2^53-1`을 넘을 수 있으므로 Swift에서는 부동소수점 경유 없이 보존해야 한다. `StableNodeID`·`StableTailnetID`는 불투명 문자열이다. (`tailscale.com/tailcfg/tailcfg.go:202`, `tailscale.com/tailcfg/tailcfg.go:230`, `tailscale.com/tailcfg/tailcfg.go:249`, `tailscale.com/tailcfg/tailcfg.go:265`)

공개 키는 JSON 문자열에 들어가는 타입 접두+hex 표현이다. `NodePublic`은 `nodekey:`, `DiscoPublic`은 `discokey:`, `MachinePublic`은 `mkey:`, `NLPublic`은 `nlpub:`를 쓴다. `NodePublic`·`DiscoPublic`의 원시 길이는 32바이트다. 전송에 짧은 로그용 키 표현을 사용하지 않는다. (`tailscale.com/types/key/node.go:31`, `tailscale.com/types/key/node.go:331`, `tailscale.com/types/key/disco.go:18`, `tailscale.com/types/key/disco.go:187`, `tailscale.com/types/key/machine.go:26`, `tailscale.com/types/key/machine.go:251`, `tailscale.com/types/key/nl.go:140`, `tailscale.com/types/key/util.go:56`)

`time.Time`은 Go JSON 시간 문자열, `netip.Addr`·`Prefix`·`AddrPort`는 각각 IP·CIDR·IP:port 문자열로 취급한다. 같은 모듈의 JSON 크기 계산에도 RFC3339 시간 문자열과 대괄호로 감싼 IPv6:port 문자열 형태가 나타난다. `[]byte`와 `MarshaledSignature`는 표준 base64 문자열로 취급한다. 모듈 내 시험 서버 주석도 encoding/json의 []byte 해독이 `base64.StdEncoding`임을 명시한다. 타입 표에는 JSON marshal/unmarshal에 전달되는 Go 타입을 함께 적으며, 표준 라이브러리 인코더 자체는 지정된 모듈에 포함되지 않는다. (`tailscale.com/tailcfg/tailcfg.go:388`, `tailscale.com/tailcfg/tailcfg.go:395`, `tailscale.com/tailcfg/tailcfg.go:404`, `tailscale.com/types/netlogtype/netlogtype.go:37`, `tailscale.com/types/netlogtype/netlogtype.go:50`, `tailscale.com/types/tkatype/tkatype.go:21`, `tailscale.com/tstest/natlab/vnet/fake_acme.go:480`, `tailscale.com/control/controlclient/direct.go:1447`, `tailscale.com/control/controlclient/direct.go:1523`)

`opt.Bool`은 문자열 `"true"`·`"false"`를 보내는 타입이 아니다. JSON에서는 `true`·`false`·`null`이며, 미설정과 명시적 false를 구분한다. `Get()`이 값을 돌려주는 경우만 상태를 바꾼다. 문자열 `"true"`를 받으면 unmarshal 자체가 오류이고(실행 확인), `null`은 명시적 미설정으로 해독된다. (`tailscale.com/types/opt/bool.go:49`, `tailscale.com/types/opt/bool.go:110`, `tailscale.com/types/opt/bool.go:122`)

실행으로 확인한 JSON 세부(Go 1.27.3 `encoding/json`, 기준 모듈 타입):

- 태그가 없는 필드는 zero여도 나간다. `RegisterRequest`의 `NodeKey`·`OldNodeKey`·`NLKey`·`Expiry`·`Followup`·`Hostinfo`·`NodeKeySignature`, `MapRequest`의 `NodeKey`·`DiscoKey`·`Hostinfo`, `Node`의 `ID`·`StableID`·`Name`·`User`·`Key`·`Addresses`가 그렇다. zero 공개 키는 생략되지 않고 접두 뒤 hex `0` 64자로(`nodekey:000…0`), zero `time.Time`은 `"0001-01-01T00:00:00Z"`로, nil 포인터·슬라이스는 `null`로 나간다. (`tailscale.com/tailcfg/tailcfg.go:1318`, `tailscale.com/tailcfg/tailcfg.go:1436`, `tailscale.com/tailcfg/tailcfg.go:370`)
- 키 텍스트 해독은 접두가 정확히 일치하고 hex 길이가 정확히 원시 길이의 두 배여야 한다. 빈 문자열은 오류다. 인코더는 소문자 hex를 낸다. (`tailscale.com/types/key/util.go:56`, `tailscale.com/types/key/util.go:70`)
- `time.Time`은 RFC 3339에 소수 초(뒤 0 제거, 최대 9자리)와 UTC 아닌 오프셋이 붙을 수 있다. 예: `"2026-01-02T03:04:05.123456789+09:00"`. Go 클라이언트의 로그아웃 `Expiry=time.Unix(123,0)`도 로컬 시간대 오프셋으로 나간다. Swift 해독기는 소수 초와 오프셋을 모두 받아야 한다. (`tailscale.com/control/controlclient/direct.go:772`)
- `map[NodeID]…`·`map[DERPRegionID]…` 키(`PeerSeenChange`, `OnlineChange`, `DERPMap.Regions`, `DERPHomeParams.RegionScore`)는 JSON에서 10진 정수 문자열이다. 예: `{"OnlineChange":{"5":true}}`. (`tailscale.com/tailcfg/tailcfg.go:2073`, `tailscale.com/tailcfg/derpmap.go:19`)
- `[]byte`·`MarshaledSignature`는 패딩 있는 표준 base64다. 예: 바이트 `01 02 03` → `"AQID"`.
- `NodeCapMap`의 값은 nil 슬라이스면 `null`이다. 예: `"CapMap":{"cap/x":null}`. 해독기는 `null`과 `[]`를 모두 "인자 없음"으로 받아야 한다. (`tailscale.com/tailcfg/tailcfg.go:486`, `tailscale.com/control/controlclient/map.go:194`)

시험 fixture용 예(가짜 값, `<64hex>`는 소문자 hex 64자):

| 메시지 | JSON |
| --- | --- |
| 인증 키 첫 등록 요청(Go 기본 경로, 서명 없음) | `{"Version":148,"NodeKey":"nodekey:<64hex>","OldNodeKey":"nodekey:<0 64개>","NLKey":"nlpub:<64hex>","Auth":{"AuthKey":"tskey-auth-fake"},"Expiry":"0001-01-01T00:00:00Z","Followup":"","Hostinfo":{"BackendLogID":"fake-log-id","Hostname":"rd-mac-1a2b3c4d"},"NodeKeySignature":null}` |
| zero `RegisterResponse` | `{"User":{"ID":0,"DisplayName":""},"Login":{"ID":0,"Provider":"","LoginName":"","DisplayName":""},"NodeKeyExpired":false,"MachineAuthorized":false,"AuthURL":"","NodeKeySignature":null,"Error":""}` |
| 스트림 맵 요청 | `{"Version":148,"Compress":"zstd","KeepAlive":true,"NodeKey":"nodekey:<64hex>","DiscoKey":"discokey:<64hex>","Stream":true,"Hostinfo":null,"Endpoints":["[2001:db8::1]:41641","192.0.2.1:41641"],"EndpointTypes":[1,2]}` |
| keepalive 페이로드 | `{"KeepAlive":true}` (`tailscale.com/control/controlclient/direct.go:1452`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1609`) |

**구현 제안:** JSON 모델에서 생략/`null`과 `[]`·`{}`를 구분한다. 맵의 여러 필드에서 `nil`은 유지, 비어 있지만 non-nil인 값은 지우기다. Go 타입의 `omitempty`만 보고 서버가 빈 배열을 보내지 않는다고 가정하면 안 된다. 운영 제어 서버는 일부 필드를 별도 marshal 타입으로 만든다는 주석이 있다. (`tailscale.com/tailcfg/tailcfg.go:1996`, `tailscale.com/tailcfg/tailcfg.go:2100`)

### 3.2 `/machine/register`

아래 필드명은 JSON 이름이며 `RegisterRequest`의 공개 필드를 모두 나열한다. (`tailscale.com/tailcfg/tailcfg.go:1318`)

| 필드 | JSON 타입 / Go 타입 | 의미·최소 입력 | 출처 |
| --- | --- | --- | --- |
| `Version` | 정수 / `CapabilityVersion` | Noise에서 클라이언트 capability. 기준 클라이언트는 최종 전송 전에 148로 설정한다 | `tailscale.com/tailcfg/tailcfg.go:1321`, `tailscale.com/control/controlclient/direct.go:805` |
| `NodeKey` | 문자열 / `key.NodePublic` | 등록하거나 갱신할 WireGuard 노드 공개 키 | `tailscale.com/tailcfg/tailcfg.go:1328`, `tailscale.com/control/controlclient/direct.go:762` |
| `OldNodeKey` | 문자열 / `key.NodePublic` | 키 교체 때 이전 노드 키. 처음 등록이면 zero key | `tailscale.com/tailcfg/tailcfg.go:1329`, `tailscale.com/control/controlclient/direct.go:704` |
| `NLKey` | 문자열 / `key.NLPublic` | 노드의 tailnet lock 공개 키. Go는 lock 활성화 여부와 별개로 로컬 키를 생성해 전송 | `tailscale.com/tailcfg/tailcfg.go:1330`, `tailscale.com/control/controlclient/direct.go:721` |
| `Auth` | 객체? / `*RegisterResponseAuth` | 인증 키가 있을 때 `Auth.AuthKey` 문자열. 인증 키에 tailnet lock용 `--TL` 접미가 있으면 그 앞부분만 보낸다. 인증 키가 없으면 필드 생략. `Oauth2Token` 객체는 pre-1.66 Android 전용이며 두 인증 수단 중 최대 하나 | `tailscale.com/tailcfg/tailcfg.go:1302`, `tailscale.com/control/controlclient/direct.go:780`, `tailscale.com/tka/sig.go:467` |
| `Expiry` | 시간 문자열 / `time.Time` | 요청 만료 시각, 서버 정책이 덮어쓸 수 있음. 현재 키+과거 시각이면 만료 요청 | `tailscale.com/tailcfg/tailcfg.go:1332` |
| `Followup` | 문자열 | 이전 응답의 `AuthURL`; 방문 완료까지 응답을 기다리는 등록 재요청 | `tailscale.com/tailcfg/tailcfg.go:1337`, `tailscale.com/control/controlclient/direct.go:529` |
| `Hostinfo` | 객체? / `*Hostinfo` | 호스트 정보. testcontrol은 등록 시 `Hostname`을 직접 읽으므로 객체 필요 | `tailscale.com/tailcfg/tailcfg.go:1338`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1086` |
| `Ephemeral` | bool | 비활성화 후 자동 삭제되는 노드를 요청. 기본 false | `tailscale.com/tailcfg/tailcfg.go:1340`, `tailscale.com/control/controlclient/direct.go:767` |
| `NodeKeySignature` | 바이트열 / `tkatype.MarshaledSignature` | 새 노드 키에 맞게 다시 서명한 tailnet lock 서명 | `tailscale.com/tailcfg/tailcfg.go:1345` |
| `SignatureType` | 문자열 / Go 내부 `SignatureType` int | 기기 인증서 기반 등록 요청 서명 종류. `signature-none`, `signature-v1`, `signature-v2`. 기본 `SignatureNone`은 생략 가능 | `tailscale.com/tailcfg/tailcfg.go:1233`, `tailscale.com/tailcfg/tailcfg.go:1260`, `tailscale.com/tailcfg/tailcfg.go:1287`, `tailscale.com/tailcfg/tailcfg.go:1354` |
| `Timestamp` | 시간 문자열? / `*time.Time` | `SignatureV1` 요청 생성 시각, 재전송 공격 방지용 | `tailscale.com/tailcfg/tailcfg.go:1352` |
| `DeviceCert` | 바이트열 | `SignatureV1`의 X.509 기기 인증서 | `tailscale.com/tailcfg/tailcfg.go:1356` |
| `Signature` | 바이트열 | `SignatureType`에 따른 등록 요청 서명 | `tailscale.com/tailcfg/tailcfg.go:1357` |
| `Tailnet` | 문자열 | 선택할 네트워크 힌트. `required:` 접두는 지정 네트워크 강제 요청, 빈 값은 힌트 없음 | `tailscale.com/tailcfg/tailcfg.go:1359` |

기본 서명 없는 등록에서는 DeviceCert·Signature를 비우고 SignatureType을 생략할 수 있다. 인증서 서명이 필요한 구성은 Go가 `SignatureV2`를 사용한다. 입력을 `UTC Timestamp의 RFC3339 텍스트 || serverURL || DeviceCert 바이트 || server 공개 키 텍스트 || machine 공개 키 텍스트`로 순서대로 연결하여 SHA-256하고, 인증서 private key로 RSA-PSS(SHA-256, salt length=hash length) 서명하여 Signature에 넣는다. V1은 공개 키 대신 ShortString을 넣는 deprecated 방식이다. 이는 NLKey로 하는 tailnet lock 노드 서명과 별개다. (`tailscale.com/tailcfg/tailcfg.go:1240`, `tailscale.com/control/controlclient/sign.go:22`, `tailscale.com/control/controlclient/sign_supported.go:180`, `tailscale.com/control/controlclient/direct.go:734`)

`RegisterResponse`는 다음 전체 필드를 가진다. HTTP 200이어도 `Error`가 비어 있지 않으면 다른 상태 필드를 무시한다. (`tailscale.com/tailcfg/tailcfg.go:1372`, `tailscale.com/control/controlclient/direct.go:854`)

| 필드 | 타입 | 처리 | 출처 |
| --- | --- | --- | --- |
| `User` | 객체 / `User` | `ID` 정수, `DisplayName`·`ProfilePicURL` 문자열, `Created` 시간. `User.ID`가 프로필 연결 키 | `tailscale.com/tailcfg/tailcfg.go:286`, `tailscale.com/tailcfg/tailcfg.go:1373`, `tailscale.com/control/controlclient/direct.go:869` |
| `Login` | 객체 / `Login` | `ID` 정수, `Provider`·`LoginName`·`DisplayName`·`ProfilePicURL` 문자열. Go 등록 경로는 표시 프로필을 여기서 구성 | `tailscale.com/tailcfg/tailcfg.go:295`, `tailscale.com/control/controlclient/direct.go:869` |
| `NodeKeyExpired` | bool | true면 키 재생성 및 재등록 필요 | `tailscale.com/tailcfg/tailcfg.go:1375`, `tailscale.com/control/controlclient/direct.go:861` |
| `MachineAuthorized` | bool | 승인 여부. false를 인증 키 실패와 혼동하지 말 것; 맵의 self `Node.MachineAuthorized`가 후속 상태 기준 | `tailscale.com/tailcfg/tailcfg.go:1376`, `tailscale.com/types/netmap/netmap.go:199`, `tailscale.com/ipn/ipnlocal/local.go:7080` |
| `AuthURL` | 문자열 | 비어 있지 않으면 사용자 인증 대기 | `tailscale.com/tailcfg/tailcfg.go:1377`, `tailscale.com/control/controlclient/direct.go:882` |
| `NodeKeySignature` | 바이트열 | 이전 서명을 새 키로 재서명해야 함. Go는 `NodeKeyExpired`보다 먼저 이 분기를 처리 | `tailscale.com/tailcfg/tailcfg.go:1379`, `tailscale.com/control/controlclient/direct.go:857` |
| `Error` | 문자열 | 승인 실패 이유. 다른 상태 필드보다 우선 | `tailscale.com/tailcfg/tailcfg.go:1383` |

### 3.3 최소 Hostinfo와 NetInfo

**구현 제안:** M2에서는 `Hostinfo` 객체에 `Hostname`, 라이브러리 버전을 식별하는 `IPNVersion`, 실제 OS인 `OS`, 합성한 비밀이 아닌 `BackendLogID`, userspace 구현임을 나타내는 `Userspace=true`를 채운다. 이는 Swiftail의 상호 운용용 선택이며 운영 서버의 필수 스키마라고 주장하지 않는다. Go 클라이언트는 등록과 맵 전송 모두에서 빈 `BackendLogID`를 로컬 오류로 거부하고, testcontrol은 `Hostinfo.Hostname`을 노드 이름으로 쓴다. (`tailscale.com/tailcfg/tailcfg.go:890`, `tailscale.com/tailcfg/tailcfg.go:921`, `tailscale.com/tailcfg/tailcfg.go:961`, `tailscale.com/control/controlclient/direct.go:749`, `tailscale.com/control/controlclient/direct.go:1077`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1087`)

| Hostinfo 필드 | 타입 | 사용할 조건·의미 | 출처 |
| --- | --- | --- | --- |
| `IPNVersion`, `BackendLogID`, `FrontendLogID`, `OS`, `OSVersion`, `Hostname`, `App` | 문자열 | 클라이언트 버전·로그 ID·OS·호스트명. `App`은 tsnet 앱 구분용 | `tailscale.com/tailcfg/tailcfg.go:890`, `tailscale.com/tailcfg/tailcfg.go:906`, `tailscale.com/tailcfg/tailcfg.go:914`, `tailscale.com/tailcfg/tailcfg.go:921` |
| `Userspace`, `UserspaceRouter`, `AppConnector` | optional bool | 각 동작 모드 보고. 미구현 기능을 true로 광고하지 않는 입력 제안 | `tailscale.com/tailcfg/tailcfg.go:961` |
| `NetInfo` | `NetInfo` 객체? | Go는 별도 저장한 NetInfo를 Hostinfo에 끼워 보내며, 갱신 시 별도 map update를 예약 | `tailscale.com/control/controlclient/direct.go:575`, `tailscale.com/control/controlclient/auto.go:694` |
| `RoutableIPs`, `RequestTags` | CIDR 문자열 배열, 문자열 배열 | 광고할 서브넷과 원하는 ACL 태그. M2는 빈 값 제안 | `tailscale.com/tailcfg/tailcfg.go:954` |
| `Services`, `ShieldsUp` | Service 배열, bool | 서비스 광고와 인바운드 차단 상태. 서비스 보고 요청은 `CollectServices`로 옴 | `tailscale.com/tailcfg/tailcfg.go:922`, `tailscale.com/tailcfg/tailcfg.go:957`, `tailscale.com/tailcfg/tailcfg.go:2094` |
| `RemoteConfig`, `AllowsUpdate`, `PeerRelay`, `WireIngress`, `IngressEnabled` | bool | 원격 관리·업데이트·릴레이·Funnel 기능 광고. M2는 기본 false 제안 | `tailscale.com/tailcfg/tailcfg.go:926`, `tailscale.com/tailcfg/tailcfg.go:934`, `tailscale.com/tailcfg/tailcfg.go:944`, `tailscale.com/tailcfg/tailcfg.go:965` |

NetInfo의 공개 필드는 아래와 같다. DERP가 아직 없으면 M2에서 `NetInfo`를 생략하거나 `PreferredDERP=0`으로 두는 구현을 제안한다. testcontrol은 NetInfo가 없어도 갱신하며, 0이 아닌 PreferredDERP만 노드에 반영한다. (`tailscale.com/tailcfg/tailcfg.go:1128`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1472`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1494`)

| NetInfo 필드 | JSON 타입 | 의미 | 출처 |
| --- | --- | --- | --- |
| `MappingVariesByDestIP` | optional bool | 목적 IP별 NAT 매핑 변화 | `tailscale.com/tailcfg/tailcfg.go:1094` |
| `WorkingIPv6`, `OSHasIPv6` | optional bool | 인터넷 IPv6 동작 / OS IPv6 지원 | `tailscale.com/tailcfg/tailcfg.go:1098` |
| `WorkingUDP`, `WorkingICMPv4` | optional bool | 인터넷 UDP·ICMPv4 동작. ICMP 미설정은 미검사 | `tailscale.com/tailcfg/tailcfg.go:1105` |
| `HavePortMap` | bool | 열린 UPnP/PMP/PCP 포트 매핑 존재 | `tailscale.com/tailcfg/tailcfg.go:1112` |
| `UPnP`, `PMP`, `PCP` | optional bool | LAN에서 각 포트 매핑 수단 감지, 미설정은 미검사 | `tailscale.com/tailcfg/tailcfg.go:1116` |
| `PreferredDERP` | 정수 / `DERPRegionID` | 이 노드가 수신 대기하는 home DERP. 0은 미연결·미확인 | `tailscale.com/tailcfg/tailcfg.go:1128` |
| `LinkType` | 문자열 | 알고 있으면 wired/wifi/mobile 등 | `tailscale.com/tailcfg/tailcfg.go:1137` |
| `DERPLatency` | `{문자열: number}` | `regionID-v4`·`regionID-v6`별 초 단위 최저 최근 지연. 의미 있는 변화 때만 갱신 | `tailscale.com/tailcfg/tailcfg.go:1140` |
| `FirewallMode` | 문자열 | Linux 방화벽 모드·선택 이유, 미관리면 빈 값 | `tailscale.com/tailcfg/tailcfg.go:1150` |

### 3.4 `/machine/map` 요청 필드 전부

| 필드 | JSON 타입 / Go 타입 | 의미·전송 조건 | 출처 |
| --- | --- | --- | --- |
| `Version` | 정수 / `CapabilityVersion` | 지원하는 프로토콜 의미의 버전 | `tailscale.com/tailcfg/tailcfg.go:1437` |
| `Compress` | 문자열 | `"zstd"` 또는 `""`(비압축) | `tailscale.com/tailcfg/tailcfg.go:1444` |
| `KeepAlive` | bool | 서버의 keepalive 응답 요청 | `tailscale.com/tailcfg/tailcfg.go:1445` |
| `NodeKey` | 문자열 / `key.NodePublic` | 현재 등록된 키 | `tailscale.com/tailcfg/tailcfg.go:1446`, `tailscale.com/control/controlclient/direct.go:1090` |
| `DiscoKey` | 문자열 / `key.DiscoPublic` | 현재 discovery 공개 키 | `tailscale.com/tailcfg/tailcfg.go:1447`, `tailscale.com/control/controlclient/direct.go:1096` |
| `HardwareAttestationKey` | `key.HardwareAttestationPublic` 문자열 | 선택적 하드웨어 identity attestation 공개 키. `hwattestpub:`+65바이트 uncompressed P-256의 hex, zero면 생략 | `tailscale.com/tailcfg/tailcfg.go:1449`, `tailscale.com/types/key/hardware_attestation.go:20`, `tailscale.com/types/key/hardware_attestation.go:96` |
| `HardwareAttestationKeySignature` | 바이트열 | attestation 키로 노드 키와 시각을 서명 | `tailscale.com/tailcfg/tailcfg.go:1452` |
| `HardwareAttestationKeySignatureTimestamp` | 시간 / `time.Time` | 서명 생성 시각. Go 입력은 Unix seconds와 NodeKey 문자열을 `|`로 이어 SHA-256 후 서명 | `tailscale.com/tailcfg/tailcfg.go:1455`, `tailscale.com/control/controlclient/direct.go:1114` |
| `Stream` | bool | true: 동일 HTTP 응답에 여러 맵. false: 한 맵 후 종료. Version>=68의 true는 상태 갱신용 필드를 무시하는 읽기 전용 요청 | `tailscale.com/tailcfg/tailcfg.go:1460` |
| `Hostinfo` | 객체? / `*Hostinfo` | 현재 호스트 정보. Go는 스트림에도 넣지만 Version>=68에서 서버가 무시 가능 | `tailscale.com/tailcfg/tailcfg.go:1470` |
| `MapSessionHandle` | 문자열 | 이전 세션 재접속용 불투명 핸들. Stream일 때만, 서버가 거부하고 새 세션을 줄 수 있음 | `tailscale.com/tailcfg/tailcfg.go:1475` |
| `MapSessionSeq` | 정수 / `int64` | 재개 요청 시 마지막 처리 sequence. 수락되면 이것보다 큰 응답만 반환 | `tailscale.com/tailcfg/tailcfg.go:1487` |
| `Endpoints` | IP:port 문자열 배열 | magicsock UDP 후보 endpoint. Version>=68 스트림에서 무시 가능 | `tailscale.com/tailcfg/tailcfg.go:1494` |
| `EndpointTypes` | 정수 배열 / `[]EndpointType` | Endpoints와 같은 순서의 출처. 0 unknown, 1 local, 2 STUN, 3 portmapped, 4 STUN4LocalPort, 5 explicit config | `tailscale.com/tailcfg/tailcfg.go:1388`, `tailscale.com/tailcfg/tailcfg.go:1418`, `tailscale.com/tailcfg/tailcfg.go:1497` |
| `TKAHead` | 문자열 | 적용한 최신 AUM hash의 `tka.AUMHash.MarshalText` 표현 | `tailscale.com/tailcfg/tailcfg.go:1500` |
| `ReadOnly` | bool | 예전 초기 DERP map 조회용. Version>=68은 항상 false인 deprecated 필드 | `tailscale.com/tailcfg/tailcfg.go:1505` |
| `OmitPeers` | bool | 피어 생략 허용. `Stream=false, ReadOnly=false`이면 기존 스트림을 끊지 않는 상태 갱신; 응답 본문 전체 생략도 가능 | `tailscale.com/tailcfg/tailcfg.go:1513` |
| `DebugFlags` | 문자열 배열 | 불안정한 개발용 선택지. 문서상 `warn-ip-forwarding-off`, `warn-router-unhealthy`; 버전 협상 수단으로 사용 금지 | `tailscale.com/tailcfg/tailcfg.go:1529` |
| `ConnectionHandleForTest` | 문자열 | 특정 연결 식별용 불투명 테스트 값, 프로토콜 의미 없음 | `tailscale.com/tailcfg/tailcfg.go:1543` |

### 3.5 압축·크기·KeepAlive

`Compress=""`이 비압축이라는 스키마 근거와 서버 근거는 모두 있다. testcontrol은 `req.Compress != ""`일 때만 zstd 압축하고, 빈 값이면 JSON 바이트를 그대로 프레임에 넣는다. 다만 값이 `"zstd"`인지 검사하지 않아 임의의 비어 있지 않은 문자열도 압축으로 처리하는 시험 서버의 단순화가 있다. (`tailscale.com/tailcfg/tailcfg.go:1444`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1526`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1918`)

클라이언트 쪽 확인 결과는 더 좁다. 기준 Go 클라이언트는 **항상** `Compress="zstd"`를 넣고, decoder는 모든 프레임을 zstd로 해독한다. 따라서 이 버전 Go 클라이언트에 비압축 수신 분기가 있다고 주장할 수 없고, 빈 Compress 사용은 Swift decoder가 직접 비압축 JSON 분기를 선택해야 한다. (`tailscale.com/control/controlclient/direct.go:1139`, `tailscale.com/control/controlclient/direct.go:1488`)

압축 단위는 프레임 하나다. Go는 각 프레임의 N바이트를 독립된 완전한 zstd 프레임(RFC 8878)으로 보고 한 번에 해독(`DecodeAll`)하며, 프레임 사이에 압축 사전이나 스트림 문맥을 이어 쓰지 않는다. testcontrol도 메시지마다 따로 `AppendEncode`한다. 따라서 Swift는 프레임마다 새 zstd 해독을 하면 되지만, 전부 Swift 방침에서는 zstd 해독기를 직접 구현하거나 운영 서버가 `Compress=""`를 따르는지 확인해야 한다(8절). (`tailscale.com/control/controlclient/direct.go:1496`, `tailscale.com/util/zstdframe/zstd.go:69`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1927`)

프레임 접두는 정확히 4바이트, 그 뒤 정확히 N바이트를 누적해서 읽는다. HTTP/2 DATA 경계를 맵 메시지 경계로 쓰지 않는다. N이 `256<<20`보다 크면 할당 전에 실패하며 zstd 해제 크기도 `1<<30`으로 제한한다. 스트림 전체 본문은 메시지 개수가 무제한이므로 전체 크기 제한을 제거한다. 맵 이외의 Noise 응답 본문(등록 응답, 맵 요청의 non-200 오류 본문)은 `1<<20`바이트로 제한된다. (`tailscale.com/control/controlclient/direct.go:1157`, `tailscale.com/control/controlclient/direct.go:1208`, `tailscale.com/control/controlclient/direct.go:1439`, `tailscale.com/util/httpbody/httpbody.go:34`, `tailscale.com/control/controlclient/direct.go:1454`, `tailscale.com/control/controlclient/direct.go:1471`)

`KeepAlive=true`는 netmap 증분이 아니다. 스키마는 `PingRequest`, `ControlTime`, `PopBrowserURL`만 같이 유효하다고 규정한다. 실제 Direct는 이 세 필드 외에 `ClientVersion`·`ControlDialPlan`도 KeepAlive 분기 전에 처리하므로, 구현에서는 이 관찰 차이를 구분한다. KeepAlive에서 Node/Peers/정책을 갱신하지 않는다. (`tailscale.com/tailcfg/tailcfg.go:2021`, `tailscale.com/control/controlclient/direct.go:1299`, `tailscale.com/control/controlclient/direct.go:1312`, `tailscale.com/control/controlclient/direct.go:1324`)

첫 **non-KeepAlive** 응답에 Node가 없으면 오류로 스트림을 끝낸다. HTTP 200만으로 netmap 동기화 성공으로 보지 않는다. 읽기 실패·zstd 실패·JSON 실패도 현재 세션을 끝내는 오류다. (`tailscale.com/control/controlclient/direct.go:1269`, `tailscale.com/control/controlclient/direct.go:1286`, `tailscale.com/control/controlclient/direct.go:1353`)

### 3.6 MapResponse 필드 전부

유지 범위는 원칙적으로 같은 HTTP map poll 세션이다. 첫 응답은 전체 상태, 후속 응답은 증분이며, 아래의 유지 규칙은 새 세션으로 무조건 승계하는 규칙이 아니다. (`tailscale.com/tailcfg/tailcfg.go:1985`, `tailscale.com/control/controlclient/map.go:42`)

| JSON 필드 | 타입 | 전체/증분 의미와 생략·zero 시 규칙 | 출처 |
| --- | --- | --- | --- |
| `MapSessionHandle` | string | 첫 응답의 선택적 세션 식별자. 요청 핸들과 같으면 재개, 생략 가능 | `tailscale.com/tailcfg/tailcfg.go:2007` |
| `Seq` | int64 | 세션 내 순번. KeepAlive 등 상태를 바꾸지 않는 응답은 생략 가능, 마지막 처리값을 재개에 사용 | `tailscale.com/tailcfg/tailcfg.go:2014` |
| `KeepAlive` | bool | true면 keepalive, false/생략이면 일반 맵 메시지 | `tailscale.com/tailcfg/tailcfg.go:2021` |
| `PingRequest` | `PingRequest`? | 이번 요청 이벤트. nil이면 없음, 상태 유지 필드 아님 | `tailscale.com/tailcfg/tailcfg.go:2026`, `tailscale.com/control/controlclient/direct.go:1299` |
| `PopBrowserURL` | string | 사용자 동작 URL 이벤트. 같은 URL 중복 억제, 빈 값이면 동작 없음 | `tailscale.com/tailcfg/tailcfg.go:2033`, `tailscale.com/control/controlclient/direct.go:1303` |
| `Node` | `Node`? | self 노드 객체 전체 교체. v18부터 nil 유지, 첫 non-KeepAlive에는 필수 | `tailscale.com/tailcfg/tailcfg.go:2040`, `tailscale.com/control/controlclient/direct.go:1353` |
| `DERPMap` | `DERPMap`? | nil 유지, non-nil 객체는 하위 필드별 부분 유지 규칙 적용 | `tailscale.com/tailcfg/tailcfg.go:2044`, `tailscale.com/control/controlclient/map.go:389` |
| `Peers` | `Node[]` | 길이>0이면 전체 목록 교체, 모든 피어 증분을 배제. nil 또는 길이0이면 증분 경로 | `tailscale.com/tailcfg/tailcfg.go:2048`, `tailscale.com/control/controlclient/map.go:558` |
| `PeersChanged` | `Node[]` | ID별 새 노드 추가 또는 해당 노드 객체 전체 교체. 생략/빈 배열이면 작업 없음 | `tailscale.com/tailcfg/tailcfg.go:2056`, `tailscale.com/control/controlclient/map.go:589` |
| `PeersRemoved` | `NodeID[]` | 지정 ID 제거. 모르는 ID는 무시, 생략/빈 배열은 작업 없음 | `tailscale.com/tailcfg/tailcfg.go:2061`, `tailscale.com/control/controlclient/map.go:582` |
| `PeersChangedPatch` | `PeerChange[]` | 기존 노드의 일부 필드 교체. 모르는 NodeID 무시, 전체 Peers 경로에서는 적용 안 됨 | `tailscale.com/tailcfg/tailcfg.go:2064`, `tailscale.com/control/controlclient/map.go:578`, `tailscale.com/control/controlclient/map.go:621` |
| `PeerSeenChange` | `{NodeID: bool}` | true는 LastSeen=수신 시각, false는 LastSeen=nil. 피어를 삭제하지 않음. 없는 항목은 유지 | `tailscale.com/tailcfg/tailcfg.go:2073`, `tailscale.com/control/controlclient/map.go:599` |
| `OnlineChange` | `{NodeID: bool}` | Online 포인터를 명시적 true/false로 설정. 없는 항목 유지 | `tailscale.com/tailcfg/tailcfg.go:2078`, `tailscale.com/control/controlclient/map.go:612` |
| `DNSConfig` | `DNSConfig`? | nil 유지, 객체가 있으면 DNS 설정 전체 교체 | `tailscale.com/tailcfg/tailcfg.go:2081`, `tailscale.com/control/controlclient/map.go:482` |
| `Domain` | string | 네트워크 이름. 빈 문자열 유지 | `tailscale.com/tailcfg/tailcfg.go:2085`, `tailscale.com/control/controlclient/map.go:492` |
| `CollectServices` | optional bool | 값이 설정되면 교체. 미설정/null 유지 | `tailscale.com/tailcfg/tailcfg.go:2094`, `tailscale.com/control/controlclient/map.go:489` |
| `PacketFilter` | `FilterRule[]` | v6부터 nil 유지, `[]`는 base 규칙 없음. non-nil은 이름 `base`의 규칙 교체 | `tailscale.com/tailcfg/tailcfg.go:2100`, `tailscale.com/control/controlclient/map.go:447` |
| `PacketFilters` | `{string: FilterRule[]?}` | 이름별 부분 교체/삭제. 값 null은 삭제, `"*":null`은 모든 기존 이름 삭제 후 나머지 적용. nil/빈 객체는 실질 변경 없음 | `tailscale.com/tailcfg/tailcfg.go:2114`, `tailscale.com/control/controlclient/map.go:454` |
| `UserProfiles` | `UserProfile[]` | v5부터 ID별 새 값/갱신만. 생략/빈 배열은 유지, 삭제 신호 없음 | `tailscale.com/tailcfg/tailcfg.go:2138`, `tailscale.com/control/controlclient/map.go:384` |
| `Health` | string[] | nil 유지, `[]`는 정상으로 초기화, non-empty는 문제 목록 교체 | `tailscale.com/tailcfg/tailcfg.go:2143`, `tailscale.com/control/controlclient/map.go:498` |
| `DisplayMessages` | `{DisplayMessageID: DisplayMessage?}` | ID별 upsert, null 삭제, `"*":null` 전체 초기화. nil/빈 객체 유지. Health와 동시에 보내지 않는 계약 | `tailscale.com/tailcfg/tailcfg.go:2156`, `tailscale.com/control/controlclient/map.go:501` |
| `SSHPolicy` | `SSHPolicy`? | non-nil이면 전체 SSH 정책 교체, nil 유지 | `tailscale.com/tailcfg/tailcfg.go:2172`, `tailscale.com/control/controlclient/map.go:485` |
| `ControlTime` | 시간? / `*time.Time` | 현재 서버 시각 이벤트. nil/zero는 무시, 유효값은 시계 보정 측에 전달 | `tailscale.com/tailcfg/tailcfg.go:2176`, `tailscale.com/control/controlclient/direct.go:1315` |
| `TKAInfo` | `TKAInfo`? | 첫 nil은 lock 비활성 상태, 이후 nil은 유지. non-nil은 전체 교체 | `tailscale.com/tailcfg/tailcfg.go:2179`, `tailscale.com/control/controlclient/map.go:516` |
| `DomainDataPlaneAuditLogID` | string | tailnet 데이터면 감사 로그 ID. 비어 있으면 유지 | `tailscale.com/tailcfg/tailcfg.go:2189`, `tailscale.com/control/controlclient/map.go:495` |
| `Debug` | `Debug`? | 이번 메시지의 제어 동작. nil이면 동작 없음, 일반 맵 적용 전에 처리 | `tailscale.com/tailcfg/tailcfg.go:2193`, `tailscale.com/control/controlclient/map.go:167` |
| `ControlDialPlan` | `ControlDialPlan`? | 제어 서버 연결 계획 전체 교체. 최초 nil은 빈 계획, 이후 nil 유지 | `tailscale.com/tailcfg/tailcfg.go:2197`, `tailscale.com/control/controlclient/direct.go:1324` |
| `ClientVersion` | `ClientVersion`? | 최신 배포 버전 알림. nil은 유지/알림 없음 | `tailscale.com/tailcfg/tailcfg.go:2202`, `tailscale.com/control/controlclient/direct.go:1312` |
| `DefaultAutoUpdate` | optional bool / Go `DeprecatedDefaultAutoUpdate` | 구 JSON 이름은 이 이름. 로컬 저장 후 후속 변경 무시라는 계약, 현재는 self CapMap 속성으로 대체 | `tailscale.com/tailcfg/tailcfg.go:2207`, `tailscale.com/control/controlclient/direct.go:1337` |

`DisplayMessage` 객체에는 `Title`·`Text` 문자열, `Severity` 문자열(`high`/`medium`/`low`), `ImpactsConnectivity` bool, 선택적 `PrimaryAction`이 있으며 action은 `URL`, `Label` 문자열을 가진다. 현재 mapSession은 DisplayMessages가 비어 있고 Health가 남아 있으면 Health를 표시 메시지로 변환한다. (`tailscale.com/tailcfg/tailcfg.go:2220`, `tailscale.com/tailcfg/tailcfg.go:2255`, `tailscale.com/tailcfg/tailcfg.go:2290`, `tailscale.com/control/controlclient/map.go:1010`)

`ClientVersion` 객체는 `RunningLatest`, `UrgentSecurityUpdate`, `Notify` bool과 `LatestVersion`, `NotifyURL`, `NotifyText` 문자열을 가진다. `ControlDialPlan`의 `Candidates`는 `IP` 문자열, `ACEHost` 문자열, `DialStartDelaySec`·`DialTimeoutSec` float64, `Priority` int인 객체 배열이며 빈 배열은 기본 DNS 연결 계획이다. 전송 연결 선택 상세는 이 노트에서 다루지 않는다. (`tailscale.com/tailcfg/tailcfg.go:2303`, `tailscale.com/tailcfg/tailcfg.go:2331`)

### 3.7 Node·DERPMap·DNSConfig·UserProfile의 필요한 데이터

아래 Node 필드는 데이터면, DNS, WhoIs 및 접근 제어 판단을 위해 보존할 대상으로 제안한다. 객체 전체 교체가 오는 경우 개별 zero 필드를 이전 노드에서 메우지 않는다. 이는 `PeersChanged`·self Node를 통째로 교체하는 기준 구현과 맞는다. (`tailscale.com/control/controlclient/map.go:371`, `tailscale.com/control/controlclient/map.go:589`)

| Node JSON 필드 | 타입 | 사용 의미 | 출처 |
| --- | --- | --- | --- |
| `ID`, `StableID`, `StableTailnetID` | int64, string, string | 증분 키 / 안정 노드 식별자 / self의 tailnet 식별자. StableTailnetID는 self에만 채움 | `tailscale.com/tailcfg/tailcfg.go:370`, `tailscale.com/tailcfg/tailcfg.go:558` |
| `Name` | string | 끝에 점이 있는 MagicDNS FQDN | `tailscale.com/tailcfg/tailcfg.go:374` |
| `User`, `Sharer` | UserID 정수 | 소유자 및 공유한 사람. User는 태그 사용 시 ACL 실행 identity와 다를 수 있음 | `tailscale.com/tailcfg/tailcfg.go:380` |
| `Key`, `Machine`, `DiscoKey` | 각 공개 키 문자열 | WireGuard 키 / machine 식별 / discovery 키 | `tailscale.com/tailcfg/tailcfg.go:388` |
| `KeyExpiry`, `Expired`, `KeySignature` | 시간, bool, 바이트열 | 만료 시각(zero는 만료 없음), 만료 상태, tailnet lock 서명 | `tailscale.com/tailcfg/tailcfg.go:389`, `tailscale.com/tailcfg/tailcfg.go:508` |
| `Addresses`, `AllowedIPs` | CIDR[] | 노드 주소 / 해당 노드로 라우팅할 prefix. v112부터 AllowedIPs=nil은 Addresses와 같음, `[]`와 구분 | `tailscale.com/tailcfg/tailcfg.go:394` |
| `Endpoints` | IP:port[] | UDP direct 후보 | `tailscale.com/tailcfg/tailcfg.go:404` |
| `HomeDERP`, `DERP` | DERPRegionID 정수, string | 현대 home region / legacy `127.3.3.40:N`. Go 이름 `LegacyDERPString`의 JSON 이름은 `DERP` | `tailscale.com/tailcfg/tailcfg.go:406` |
| `Hostinfo`, `Cap`, `Tags`, `PrimaryRoutes` | 객체, 정수, string[], CIDR[] | 호스트 서비스·이름 보조 정보 / peer capability / ACL 태그 / 현재 주 서브넷 경로 | `tailscale.com/tailcfg/tailcfg.go:425`, `tailscale.com/tailcfg/tailcfg.go:429` |
| `LastSeen`, `Online` | 시간?, bool? | 마지막 온라인 시각 / control 연결 여부. nil은 미확인 또는 조회 권한 없음; Online=true일 때 LastSeen은 갱신하지 않음 | `tailscale.com/tailcfg/tailcfg.go:444` |
| `MachineAuthorized` | bool | self 기기 승인 상태 | `tailscale.com/tailcfg/tailcfg.go:455`, `tailscale.com/types/netmap/netmap.go:199` |
| `Capabilities`, `CapMap` | string[], `{string: RawMessage[]?}` | 구 속성 목록 / 현재 속성과 인자. CapMap 값은 `null`일 수 있다(3.1). self 행동 속성과 peer 속성을 구분, 애플리케이션 접근 권한은 PacketFilter(s)에 있음 | `tailscale.com/tailcfg/tailcfg.go:457` |
| `UnsignedPeerAPIOnly` | bool | lock 서명 검증 예외지만 일반 네트워크 접근 불가. AllowedIPs를 자체 Addresses로 제한 | `tailscale.com/tailcfg/tailcfg.go:488`, `tailscale.com/control/controlclient/map.go:269` |
| `SelfNodeV4MasqAddrForThisPeer`, `SelfNodeV6MasqAddrForThisPeer` | IP 문자열? | 해당 peer가 self를 인식하는 주소; self에서 peer·그 subnet으로 나가는 원본 주소 masquerade용 | `tailscale.com/tailcfg/tailcfg.go:514`, `tailscale.com/tailcfg/tailcfg.go:529` |
| `IsWireGuardOnly`, `ExitNodeDNSResolvers` | bool, Resolver[] | Disco·DERP 없는 WireGuard peer; endpoint 필요, exit DNS resolver 별도 제공 | `tailscale.com/tailcfg/tailcfg.go:544`, `tailscale.com/tailcfg/tailcfg.go:554` |
| `IsJailed` | bool | 해당 노드가 연결 시작 불가, 해당 노드로의 연결은 가능 | `tailscale.com/tailcfg/tailcfg.go:549` |

`ComputedName`·`ComputedNameWithHost`는 control이 주는 권위 있는 이름이 아니라 클라이언트가 계산하는 필드다. `Created`와 `DataPlaneAuditLogID`는 생성 시각·감사 로깅용이다. M2에서는 Name·Hostinfo.Hostname으로 표시하고 이 세 가지 부가 기능을 미룰 수 있다. (`tailscale.com/tailcfg/tailcfg.go:425`, `tailscale.com/tailcfg/tailcfg.go:496`, `tailscale.com/tailcfg/tailcfg.go:505`)

| DERP 구조 | 필요한 필드와 타입·의미 | 출처 |
| --- | --- | --- |
| `DERPMap` | `HomeParams` 객체?, `Regions`={정수 문자열: DERPRegion}, JSON `omitDefaultRegions` bool. 마지막 필드는 Regions non-nil일 때만 의미 있음 | `tailscale.com/tailcfg/derpmap.go:19` |
| `DERPHomeParams` | `RegionScore`={region ID: float64}. home 선택 지연 배수, 누락 region=1.0, 0 이하 무시, nil 유지, 빈 map은 점수 초기화 | `tailscale.com/tailcfg/derpmap.go:49` |
| `DERPRegion` | `RegionID` int64, `RegionCode`·`RegionName` string, `Nodes` DERPNode[] 우선순위 순. `NoMeasureNoHome=true`는 측정·home 선택 금지지만 peer의 home이면 연결 가능 | `tailscale.com/tailcfg/derpmap.go:117`, `tailscale.com/tailcfg/derpmap.go:161` |
| `DERPNode` | `Name` string, `RegionID` 정수, `HostName` string, `CertName` string. CertName 비어 있으면 HostName 인증, `sha256-raw:`는 인증서 SHA256 고정 | `tailscale.com/tailcfg/derpmap.go:187` |
| 주소·포트 | `IPv4`·`IPv6` string은 IP 강제 지정, 빈 값은 DNS, `"none"`은 해당 family 비활성. `STUNPort` int=0→3478, -1→STUN 비활성; `DERPPort` int=0→443; `STUNOnly` bool이면 DERP 서버 아님 | `tailscale.com/tailcfg/derpmap.go:216` |
| 시험·보조 | `InsecureForTests` bool, `STUNTestIP` string은 시험용. `CanPort80` bool은 captive portal 검사 지원 | `tailscale.com/tailcfg/derpmap.go:245` |

| DNSConfig 필드 | 타입·의미 | 출처 |
| --- | --- | --- |
| `Resolvers` | Resolver[]; 기본 DNS resolver의 우선순위 | `tailscale.com/tailcfg/tailcfg.go:1788` |
| `Routes` | {suffix: Resolver[]}; split DNS suffix, 앞 점 없음·끝 점 선택. 빈 resolver 배열은 내장 resolver가 ExtraRecords 등을 처리 | `tailscale.com/tailcfg/tailcfg.go:1792` |
| `FallbackResolvers` | Resolver[]; 기본 resolver 없이는 split DNS가 동작하지 않는 구성의 보조 | `tailscale.com/tailcfg/tailcfg.go:1804` |
| `Domains` | string[]; 검색 도메인은 끝 점 없는 FQDN | `tailscale.com/tailcfg/tailcfg.go:1809` |
| `Proxied` | bool; netmap 기기 이름 자동 해석(MagicDNS) | `tailscale.com/tailcfg/tailcfg.go:1812` |
| `Nameservers` | IP[]; v9 이상 v14 미만만 사용하는 구 필드 | `tailscale.com/tailcfg/tailcfg.go:1818` |
| `CertDomains` | string[]; 인증서 지원 이름, 끝 점·`_acme-challenge.` 접두 없음 | `tailscale.com/tailcfg/tailcfg.go:1823` |
| `ExtraRecords` | DNSRecord[]; `Name` string(FQDN, 끝 점 선택), `Type` string(빈 값이면 주소에 따라 A/AAAA, 다른 값은 현재 무시), `Value` IP string | `tailscale.com/tailcfg/tailcfg.go:1831`, `tailscale.com/tailcfg/tailcfg.go:1856` |
| `ExitNodeFilteredSet` | string[]; exit DNS proxy에서 응답하지 않을 이름·suffix, 소문자·끝 점 없음, 앞 점이면 하위 suffix만 | `tailscale.com/tailcfg/tailcfg.go:1835` |
| `TempCorpIssue13969` | string; 임시 내부 실험 URL | `tailscale.com/tailcfg/tailcfg.go:1850` |

`Resolver`는 `Addr` string(IP, 시험 IP:port, DoH URL, WireGuard 위 HTTP URL), `BootstrapResolution` IP[], `UseWithExitNode` bool을 가진다. IP만 주면 resolver port는 53이다. (`tailscale.com/types/dnstype/dnstype.go:14`, `tailscale.com/types/dnstype/dnstype.go:45`)

`UserProfile`은 `ID` UserID, `LoginName`, `DisplayName`, `ProfilePicURL` 문자열, `Groups` 문자열 배열이다. 이 버전 구조체에는 Groups가 있지만 capability 주석은 v87에서 제거했다고 적으므로 필수라고 가정하지 않는다. WhoIs는 노드를 IP/키로 찾은 후 Node.User에 해당하는 프로필을 연결하며, 애플리케이션 capability는 별도의 `PacketFilter.CapGrant`에서 나온다. (`tailscale.com/tailcfg/tailcfg.go:307`, `tailscale.com/tailcfg/tailcfg.go:138`, `tailscale.com/ipn/ipnlocal/local.go:1728`, `tailscale.com/ipn/ipnlocal/local.go:1803`, `tailscale.com/tailcfg/tailcfg.go:1764`, `tailscale.com/ipn/localapi/localapi.go:597`)

## 4. 절차와 상태 기계

### 4.1 등록·인증·승인·키 교체

1. 로컬 machine identity와 현재 노드 키를 준비한다. Go는 machine 키가 zero면 실패하고, 노드 키가 없거나 만료·interactive login이면 새 노드 키를 만든다. 키 교체에서는 이전 private node key를 별도로 보존하여 `OldNodeKey`를 채운다. (`tailscale.com/control/controlclient/direct.go:649`, `tailscale.com/control/controlclient/direct.go:657`, `tailscale.com/control/controlclient/direct.go:704`)
2. 인증 키 로그인은 `Auth={AuthKey: …}`를 넣어 등록한다. 인증 키가 없으면 Auth를 생략하고 등록 응답의 AuthURL 분기를 따른다. Go는 `--TL`이 들어 있는 wrapped auth key를 `--TL` 앞의 AuthKey와 lock 서명 재료로 나누어, 앞부분만 `Auth.AuthKey`로 보내고 재료로는 `NodeKeySignature`를 만든다. `--TL`이 없으면 키 문자열 전체를 그대로 보낸다. Swift가 lock을 지원하지 않더라도 wrapped key 전체를 AuthKey로 보내면 안 된다. (`tailscale.com/tka/sig.go:467`, `tailscale.com/control/controlclient/direct.go:643`, `tailscale.com/control/controlclient/direct.go:739`, `tailscale.com/control/controlclient/direct.go:779`)
3. HTTP 200 이후에도 `Error`→`NodeKeySignature`→`NodeKeyExpired` 순으로 분기한다. Error는 실패, 서명 반환은 재서명과 재등록, NodeKeyExpired는 새 키로 한 번 재시도한다. 이미 재생성했는데 다시 expired면 오류다. (`tailscale.com/control/controlclient/direct.go:534`, `tailscale.com/control/controlclient/direct.go:854`)
4. AuthURL이 있으면 사용자에게 전달하고, **동일한 후보 NodeKey**로 `Followup=AuthURL`인 등록 POST를 보낸다. Followup은 long poll이다. 새 AuthURL이면 교체하고, 같은 URL이 즉시 반복되면 backoff한다. 아직 인증되지 않은 후보를 현재 키로 확정하지 않는다. (`tailscale.com/control/controlclient/direct.go:526`, `tailscale.com/control/controlclient/direct.go:708`, `tailscale.com/control/controlclient/direct.go:888`, `tailscale.com/control/controlclient/auto.go:359`, `tailscale.com/control/controlclient/auto.go:376`)
5. AuthURL이 비면 Go는 후보를 현재 private node key로 확정하고 로그인 성공 뒤 map을 시작한다. `RegisterResponse.MachineAuthorized`는 이 함수에서 실패 분기로 사용하지 않는다. 따라서 인증 성공과 기기 승인은 별도 상태다. (`tailscale.com/control/controlclient/direct.go:888`, `tailscale.com/control/controlclient/auto.go:410`, `tailscale.com/control/controlclient/auto.go:428`)
6. map self Node의 `MachineAuthorized=false`이면 `NeedsMachineAuth`로 두고 스트림을 유지하여 승인을 기다린다. testcontrol은 `CompleteDeviceApproval`로 true를 설정하고 self 갱신을 깨우며, true가 된 뒤 Go backend는 Starting으로 전환한다. (`tailscale.com/types/netmap/netmap.go:199`, `tailscale.com/ipn/ipnlocal/local.go:7080`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:950`)
7. self KeyExpiry가 만료되면 Go backend는 NeedsLogin으로 전환한다. 다음 등록은 만료된 키를 교체하는 경로를 따른다. peer는 `Expired`를 보존하고, `ControlTime` 기반 시계 차이를 반영하여 만료를 계산한다. 단순 Endpoints 제거만으로 통신을 끊는 것은 충분하지 않다는 주석이 있다. (`tailscale.com/ipn/ipnlocal/local.go:1924`, `tailscale.com/ipn/ipnlocal/local.go:7076`, `tailscale.com/control/controlclient/direct.go:646`, `tailscale.com/ipn/ipnlocal/expiry.go:63`, `tailscale.com/ipn/ipnlocal/expiry.go:100`)
8. 로그아웃은 별도 `/logout` 경로가 아니라 현재 NodeKey로 register하면서 `Expiry`를 과거로 지정한다. Go는 `time.Unix(123,0)`을 쓰며 등록 시도 후 persist를 비운다. Auto는 성공하면 로그인 상태와 map/auth 작업을 종료한다. (`tailscale.com/tailcfg/tailcfg.go:1332`, `tailscale.com/control/controlclient/direct.go:505`, `tailscale.com/control/controlclient/direct.go:706`, `tailscale.com/control/controlclient/direct.go:771`, `tailscale.com/control/controlclient/auto.go:856`)

Ephemeral은 등록 요청의 서버 측 수명 정책 요청이다. 기준 testcontrol의 등록 처리에는 Ephemeral에 따른 자동 삭제나 Expiry를 저장하는 분기가 없으므로, 이 서버로 production ephemeral GC·로그아웃 삭제까지 검증했다고 볼 수 없다. (`tailscale.com/tailcfg/tailcfg.go:1340`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:973`)

### 4.2 맵 시작·갱신·재연결

1. 등록 완료 후 상태 업로드와 수신을 구분한다. **구현 제안:** 처음에는 `Stream=false, OmitPeers=true, ReadOnly=false`로 Hostinfo·NetInfo·DiscoKey·Endpoints를 올려 HTTP 200을 확인하고, 그 뒤 `Stream=true, OmitPeers=false, KeepAlive=true`로 수신을 시작한다. 이 순서는 결정적인 초기 상태를 위한 Swiftail 제안이며, Go Auto 자체는 로그인 후 restartMap에서 두 작업을 예약하므로 완료 선후를 보장하지 않는다. (`tailscale.com/tailcfg/tailcfg.go:1466`, `tailscale.com/tailcfg/tailcfg.go:1518`, `tailscale.com/control/controlclient/auto.go:303`, `tailscale.com/control/controlclient/auto.go:428`)
2. 스트리밍 요청의 Version>=68에서는 Hostinfo뿐 아니라 상태 갱신용 다른 값도 믿고 전달하지 않는다. testcontrol은 Hostinfo·Endpoints·DiscoKey 등을 통째로 무시한다. UDP 주소, DiscoKey, Hostinfo, NetInfo, TKAHead 변화는 non-streaming update로 따로 보낸다. (`tailscale.com/tailcfg/tailcfg.go:1466`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1452`, `tailscale.com/control/controlclient/auto.go:259`, `tailscale.com/control/controlclient/auto.go:681`, `tailscale.com/control/controlclient/auto.go:706`, `tailscale.com/control/controlclient/auto.go:888`)
3. 갱신 요청은 HTTP 상태만 확인하고 응답은 소비 후 버린다. 서버가 본문을 완전히 생략해도 되므로 map 프레임을 반드시 기다리지 않는다. 한 세션을 읽으면서 갱신 요청을 병행할 수 있다. (`tailscale.com/tailcfg/tailcfg.go:1518`, `tailscale.com/control/controlclient/direct.go:1223`, `tailscale.com/control/controlclient/direct.go:971`)
4. 초기 non-KeepAlive의 Node를 받은 뒤 세션 상태를 만들고 후속 프레임을 순서대로 적용한다. map 상태는 이 스트림에 종속된다. EOF·timeout·decode 오류 시 재연결하고, 재개를 구현하지 않는 최소 클라이언트는 새 전체 맵으로 상태를 다시 시작한다. Go Direct도 매 요청마다 새 mapSession을 만들며 요청에 MapSessionHandle/Seq를 설정하지 않는다. (`tailscale.com/control/controlclient/direct.go:1092`, `tailscale.com/control/controlclient/direct.go:1228`, `tailscale.com/control/controlclient/direct.go:1269`, `tailscale.com/control/controlclient/direct.go:1353`)
5. 갱신은 최신 로컬 상태의 세대 번호를 추적하여 성공한 세대만 완료 처리한다. 실패해도 현재 스트림을 바로 끊지 않고 갱신 자체를 backoff 후 재시도한다. (`tailscale.com/control/controlclient/auto.go:59`, `tailscale.com/control/controlclient/auto.go:90`)

### 4.3 mapSession의 증분 적용 알고리즘

1. KeepAlive에서 허용되는 부가 이벤트는 앞서 처리하고 netmap 갱신을 건너뛴다. 일반 메시지는 Debug 동작을 먼저 처리한다. (`tailscale.com/control/controlclient/direct.go:1299`, `tailscale.com/control/controlclient/direct.go:1332`, `tailscale.com/control/controlclient/map.go:167`)
2. self와 새/변경 peer를 정규화한다. HomeDERP가 0이고 legacy `DERP`가 `127.3.3.40:N`이면 N을 HomeDERP로 옮긴다. AllowedIPs가 nil이면 Addresses를 복사한다. UnsignedPeerAPIOnly이면 자체 Addresses 이외의 AllowedIPs를 제거한다. self의 구 Capabilities 중 CapMap에 없는 키는 값 없는 CapMap 항목으로 추가한다. (`tailscale.com/control/controlclient/map.go:182`, `tailscale.com/control/controlclient/map.go:244`)
3. 피어 저장소를 `NodeID → Node`로 둔다. `Peers.count>0`이면 그 목록으로 저장소를 대체하고 이 메시지의 모든 피어 delta 처리를 끝낸다. `Peers=[]`로 기존 peer를 비우지 않는다. 처음에는 저장소가 비어 있으므로 최초 peer 0명 상태는 표현 가능하지만, 기존 마지막 peer 제거는 PeersRemoved로 해야 한다. (`tailscale.com/control/controlclient/map.go:550`)
4. 전체 Peers가 없으면 `PeersRemoved`→`PeersChanged`→`PeerSeenChange`→`OnlineChange`→`PeersChangedPatch` 순서다. Removed는 삭제, Changed는 **노드 전체 upsert**다. Seen=false는 LastSeen=nil이며 삭제가 아니다. Seen=true는 수신 측 현재 시각, Online은 값 그대로 저장한다. 둘 다 모르는 ID는 무시한다. (`tailscale.com/control/controlclient/map.go:582`)
5. patch는 기존 NodeID에만 적용한다. `DERPRegion`·`Cap`은 nonzero일 때, `Endpoints`·`KeySignature`·`CapMap`은 non-nil일 때 교체한다. `Key`, `DiscoKey`, `Online`, `LastSeen`, `KeyExpiry`는 포인터가 non-nil이면 그 값으로 교체한다. 따라서 `Endpoints=[]`·`CapMap={}`는 비우기, `Online=false`는 오프라인 설정이며, nil LastSeen patch는 clear가 아니다(LastSeen clear는 Seen=false 사용). (`tailscale.com/tailcfg/tailcfg.go:3031`, `tailscale.com/control/controlclient/map.go:621`)
6. Go는 `PeersChanged`의 노드가 기존 노드와 patch로 표현되는 필드(Key, KeyExpiry, KeySignature, DiscoKey, Endpoints, HomeDERP, Cap, CapMap, Online, LastSeen)에서만 다르면 통째 교체 대신 그 차이를 patch로 바꿔 `PeersChangedPatch` 뒤에 붙인다(`patchifyPeersChanged`). 차이가 없으면 항목을 버린다. 대부분의 응답에서는 통째 교체와 결과가 같지만 **동등하지는 않다**: patch는 맨 뒤에, 그때 남아 있는 피어에만 적용되므로, 한 응답이 같은 피어를 `PeersRemoved`로 지우면서 `PeersChanged`로 바꾸면 patch로 옮겨지는 변화는 사라지고(지우기가 이긴다) 그 밖의 필드가 바뀐 경우만 피어가 되살아난다. Go의 실제 mapSession에서 뽑은 자료(`Tests/SwiftailControlTests/Fixtures/map-sessions.json`의 `peer-upsert-remove`)로 확인했다. Swift도 같은 규칙을 따른다. 저장소를 외부에 전달할 때는 Node.ID 순으로 정렬한다. (`tailscale.com/control/controlclient/map.go:210`, `tailscale.com/control/controlclient/map.go:694-720`, `tailscale.com/control/controlclient/map.go:758`)
7. self Node가 있으면 객체 전체를 바꾸고 capability 집합을 다시 만든다. UserProfiles는 ID별 upsert이며 지우지 않는다. netmap 내 프로필은 self.User, peer.User, peer.Sharer에 해당하는 보존 프로필에서 선택한다. (`tailscale.com/control/controlclient/map.go:371`, `tailscale.com/control/controlclient/map.go:384`, `tailscale.com/control/controlclient/map.go:674`, `tailscale.com/control/controlclient/map.go:1054`)
8. DERPMap=nil이면 유지한다. non-nil의 Regions에서 값이 nil인 region은 제거한다. 이전 DERPMap이 있고 새 Regions=nil이면 이전 Regions **및 OmitDefaultRegions**를 보존한다. Regions={}이면 전체 region 목록을 비운다. HomeParams=nil이면 이전 객체, HomeParams가 있고 RegionScore=nil이면 이전 점수만 유지한다. 빈 RegionScore={}는 점수 초기화다. region ID별 patch라고 가정하지 않는다. (`tailscale.com/control/controlclient/map.go:389`, `tailscale.com/tailcfg/derpmap.go:63`)
9. PacketFilter가 non-nil이면 named filter의 `base`만 먼저 교체한다. PacketFilters에 `"*":null`이 있으면 **그 base를 포함하여** 모든 기존 이름을 비운 뒤, 나머지 이름은 non-nil이면 교체, null이면 삭제한다. 최종 규칙은 이름 정렬 후 배열들을 연결한 것이다. 빈 base만으로 다른 이름의 규칙이 지워지지 않는다. (`tailscale.com/tailcfg/tailcfg.go:2114`, `tailscale.com/control/controlclient/map.go:447`)
10. DNSConfig·SSHPolicy·TKAInfo는 non-nil 객체 전체 교체다. CollectServices는 설정된 bool만 적용하고 Domain·DomainDataPlaneAuditLogID는 nonempty만 교체한다. Health는 non-nil 배열 전체 교체, DisplayMessages는 `*` 초기화 후 ID별 upsert/delete다. (`tailscale.com/control/controlclient/map.go:482`)
11. 복원한 상태에서 전체 netmap을 만들어도 상호 운용된다. Go의 내부 delta 최적화 API를 재현할 필요는 없다. 그 최적화도 처리 불가능한 변화는 복원 상태에서 전체 netmap을 재생성한다. (`tailscale.com/control/controlclient/map.go:212`, `tailscale.com/control/controlclient/map.go:1004`)

PacketFilter 데이터는 `FilterRule.SrcIPs` string[]와 선택적 `SrcBits` int[], `DstPorts` NetPortRange[], `IPProto` int[], `CapGrant` CapGrant[]다. SrcIPs는 IP·`*`·CIDR·범위·`cap:` 표현을 허용하고, IPProto 빈 값은 TCP/UDP/ICMP다. DstPorts와 CapGrant는 서로 배타적이며 전자는 네트워크 허용, 후자는 WhoIs 애플리케이션 권한이다. `NetPortRange`는 `IP` string, 구 `Bits` int?, `Ports={First:uint16,Last:uint16}`이며 CapGrant는 `Dsts` CIDR[], 구 `Caps` string[], `CapMap`={cap:string → raw JSON 값 배열}이다. (`tailscale.com/tailcfg/tailcfg.go:1550`, `tailscale.com/tailcfg/tailcfg.go:1572`, `tailscale.com/tailcfg/tailcfg.go:1580`, `tailscale.com/tailcfg/tailcfg.go:1714`)

### 4.4 HTTP 오류·재시도

| 상황 | 기준 동작·구현에 필요한 구분 | 출처 |
| --- | --- | --- |
| register/map HTTP 200 | 등록은 JSON 및 Error 확인; map lite는 본문 소비, stream은 프레임 읽기 | `tailscale.com/control/controlclient/direct.go:834`, `tailscale.com/control/controlclient/direct.go:854`, `tailscale.com/control/controlclient/direct.go:1223` |
| HTTP 429 | Retry-After를 해석하는 rateLimitError, 일반 backoff 대신 지정 대기 | `tailscale.com/control/controlclient/direct.go:624`, `tailscale.com/control/controlclient/auto.go:369`, `tailscale.com/control/controlclient/auto.go:647` |
| HTTP 503 + Retry-After 있음 | 429와 동일한 rate limit 분기 | `tailscale.com/control/controlclient/direct.go:624` |
| HTTP 503 헤더 없음, 기타 non-200(400/401/403/404/5xx 등) | register/map Direct는 일반 오류로 반환. 이 코드에는 401/403이면 자동 키 삭제·교체하는 전용 분기 없음 | `tailscale.com/control/controlclient/direct.go:834`, `tailscale.com/control/controlclient/direct.go:1205` |
| Retry-After 값 | 정수 초 또는 HTTP-date. <=0 또는 >1시간/파싱 실패는 실제 코드상 `5s + rand.N(5s)` 대체; 이후 Auto가 최대 5분으로 제한 | `tailscale.com/control/controlclient/direct.go:600`, `tailscale.com/control/controlclient/auto.go:653` |
| 네트워크·EOF·프레임·decode 오류 | 현재 PollNetMap 종료 후 로그인 상태이면 재요청. context 취소는 의도한 중단으로 취급 | `tailscale.com/control/controlclient/direct.go:1269`, `tailscale.com/control/controlclient/auto.go:603`, `tailscale.com/control/controlclient/auto.go:625` |
| 서버 `RegisterResponse.Error` | HTTP 성공과 별도로 승인 실패를 노출. Auto auth loop는 다른 일반 오류와 같이 재시도 | `tailscale.com/control/controlclient/direct.go:854`, `tailscale.com/control/controlclient/auto.go:366` |
| 키 만료 | 일반 HTTP 오류와 구분. NodeKeyExpired는 재생성 분기, 새 키도 expired면 오류; self KeyExpiry 만료는 NeedsLogin | `tailscale.com/control/controlclient/direct.go:861`, `tailscale.com/ipn/ipnlocal/local.go:7076` |

일반 auth/map/update backoff는 기준값 최대 30초로 설정된다. 실제 지연은 `min(n²×10ms,30s) × [0.5,1.5)`이므로 지터 적용 후 30초를 넘을 수 있다. 전체 netmap 수신은 map backoff를 reset하고 update 성공은 update backoff를 reset한다. (`tailscale.com/control/controlclient/auto.go:63`, `tailscale.com/control/controlclient/auto.go:104`, `tailscale.com/control/controlclient/auto.go:317`, `tailscale.com/control/controlclient/auto.go:473`, `tailscale.com/control/controlclient/auto.go:588`, `tailscale.com/util/backoff/backoff.go:47`)

### 4.5 부가 호출과 서버 발신 요청

| 대상 | 처리 내용 | 최소 구현에서 미룰 때의 결과·근거 | 출처 |
| --- | --- | --- | --- |
| 빈 Types의 `PingRequest` | URL에 HEAD; URLIsNoise면 Noise, 아니면 일반 HTTP client. URL 중복 억제 | 서버가 long poll 연결을 확인하는 수단을 잃음. production에서 이후 끊는지 등은 미확인. 기본 HEAD 응답은 구현 제안 | `tailscale.com/tailcfg/tailcfg.go:1890`, `tailscale.com/tailcfg/tailcfg.go:1900`, `tailscale.com/control/controlclient/direct.go:1602`, `tailscale.com/control/controlclient/direct.go:1621` |
| `Types="disco,TSMP,ICMP,peerapi"` | 쉼표로 분리, `IP`로 각 probe 후 `PingResponse` JSON을 URL에 POST | 진단 결과가 전달되지 않음. Go도 pinger/IP/URL 없으면 로그 후 반환, 모르는 타입은 무시 | `tailscale.com/control/controlclient/direct.go:1653`, `tailscale.com/control/controlclient/direct.go:1811`, `tailscale.com/control/controlclient/direct.go:1830` |
| `Types="c2n"` | URLIsNoise 무시, Noise만 사용. Payload HTTP 요청을 로컬 handler로 처리해 직렬화한 HTTP 응답을 URL에 POST | Go도 HasC2N=false 또는 handler 없으면 처리 안 함. 원격 진단·관리 기능을 제공하지 못하고 testcontrol 호출자는 응답 또는 context 종료를 기다림 | `tailscale.com/tailcfg/tailcfg.go:1922`, `tailscale.com/control/controlclient/direct.go:1640`, `tailscale.com/feature/c2n/c2n.go:28`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:292` |
| `PopBrowserURL` | 동일 URL 반복 억제 후 사용자에게 동작 URL 전달 | 사용자 동작이 완료되지 않을 수 있음. Go도 callback 없으면 로그만 남김 | `tailscale.com/tailcfg/tailcfg.go:2033`, `tailscale.com/control/controlclient/direct.go:1303` |
| `/machine/update-health` | `Subsys` string, `Error` string(빈 값=해소), `NodeKey` 공개 키 JSON POST | 2025-10-02부터 proactive 전송 중단. M2에서 호출 불필요; testcontrol은 본문 버리고 204 | `tailscale.com/tailcfg/tailcfg.go:2623`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:568` |
| `/machine/set-dns` | Version·NodeKey·Name·Type·Value. ACME dns-01용 `_acme-challenge.`+CertDomain, Type=TXT. 200과 `{}` 해독 | 등록·netmap·MagicDNS 자체를 켜는 호출이 아님. 생략하면 이 경로의 인증서 DNS challenge를 수행 못함. Go도 ACME 기능 없으면 unavailable | `tailscale.com/tailcfg/tailcfg.go:2586`, `tailscale.com/control/controlclient/direct.go:1758`, `tailscale.com/control/controlclient/direct.go:1785` |
| `/machine/set-device-attr` | PATCH, `Version` int, `NodeKey`, `Update`={attribute: string/number/bool/null}; null 삭제, 미포함 유지 | 기기 posture 속성 갱신을 제공하지 않음. 해당 정책의 로그인·접근 결과는 이 소스로 확인 못함. 현재 주석상 experimental dev feature | `tailscale.com/tailcfg/tailcfg.go:2639`, `tailscale.com/tailcfg/tailcfg.go:2661`, `tailscale.com/control/controlclient/direct.go:1901` |
| `Debug` | Exit int?, DisableLogTail bool, SleepSeconds float64. Go는 종료·로그 비활성·대기를 실행 | Sleep은 폭주 클라이언트를 늦추는 서버 수단. 라이브러리가 호스트 프로세스를 종료할지는 Swiftail 정책 결정으로 남기고 M2에서 알림·대기 지원 제안 | `tailscale.com/tailcfg/tailcfg.go:2371`, `tailscale.com/control/controlclient/direct.go:1398` |
| ClientVersion·업데이트·SSH·감사 로그 | 메타데이터 보존 및 기능별 처리 | M2의 등록·netmap 관문에서는 미루는 제안. 해당 기능의 의미는 위 응답 표에 유지하며 범용 지원을 주장하지 않음 | `tailscale.com/tailcfg/tailcfg.go:2172`, `tailscale.com/tailcfg/tailcfg.go:2189`, `tailscale.com/tailcfg/tailcfg.go:2202` |

`PingRequest`의 나머지 필드는 `Log` bool(성공 로그 요청), `Payload` []byte, `IP` netip.Addr다. `PingResponse`는 `Type`, `IP`, `NodeIP`, `NodeName`, `Err`, `Endpoint`, `PeerRelay`, `DERPRegionCode` 문자열, `LatencySeconds` float64, `DERPRegionID` 정수, `PeerAPIPort` uint16, `IsLocalIP` bool을 가진다. 실패 진단은 Err에 담기며 성공 지연이 없으면 Err에 원인을 담는 계약이다. (`tailscale.com/tailcfg/tailcfg.go:1915`, `tailscale.com/tailcfg/tailcfg.go:1929`, `tailscale.com/tailcfg/tailcfg.go:1941`)

### 4.6 tailnet lock와 capability 선택

TKAInfo의 `Head` string은 최신 AUM hash, `Disabled` bool은 비활성화 의사 표시다. head가 다르면 별도 동기화 RPC를 해야 하고, Disabled=true만 믿고 로컬 lock을 지우지 않는다. Go는 bootstrap으로 disablement secret을 받아 검증하며, TKAInfo=nil인 증분은 기존 상태를 유지한다. (`tailscale.com/tailcfg/tka.go:85`, `tailscale.com/tailcfg/tailcfg.go:2179`, `tailscale.com/ipn/ipnlocal/tailnet-lock.go:340`)

**구현 제안:** M2를 lock 미활성 tailnet에 한정하면 `TKAHead`·서명·AUM 동기화를 미룰 수 있다. 조건은 로컬에 이미 신뢰하는 lock 상태가 없고 서버 TKA가 활성화되어 있지 않다는 것이다. lock이 켜진 tailnet에서 무시하면 Go peer는 서명 없는 Swift 노드를 netmap에서 제거하고, Swift 쪽 검증 생략은 lock의 보안 의미를 지키지 못한다. `UnsignedPeerAPIOnly` 예외를 일반 통신 우회 수단으로 쓰면 안 된다. (`tailscale.com/control/controlclient/map.go:1039`, `tailscale.com/ipn/ipnlocal/tailnet-lock.go:185`, `tailscale.com/tailcfg/tailcfg.go:488`)

NLKey 자체를 보내지 않아도 운영 서버가 항상 허용하는지는 확인하지 못했다. 기준 Go는 항상 NL 키를 생성하고, wrapped auth key는 추가 lock 서명을 만들며, 키 교체 시 반환된 NodeKeySignature를 NL 키로 다시 서명한다. 따라서 최소 클라이언트에서 lock 미지원과 NLKey 생성 생략은 같은 결정이 아니다. (`tailscale.com/control/controlclient/direct.go:721`, `tailscale.com/control/controlclient/direct.go:734`, `tailscale.com/control/controlclient/direct.go:759`)

148은 단일 기능 비트가 아니라 누적되는 capability 수준이다. 148을 광고하면 해당 버전 이력의 의미들을 이해한다고 신호하는 것이다. 제어 내용 계층에서 특히 다음 경계가 설계에 영향을 준다. (`tailscale.com/tailcfg/tailcfg.go:38`, `tailscale.com/tailcfg/tailcfg.go:53`)

| 버전 | 서버에 알리는 관련 의미 | 출처 |
| ---: | --- | --- |
| 4~18 | opt-in 압축·keepalive, peer/profile delta, nil PacketFilter/DNSConfig/Node 유지, Domain 빈 값 유지, Seen/Online 변화 | `tailscale.com/tailcfg/tailcfg.go:55` |
| 28, 33, 36, 38, 40, 47, 48, 53 | Noise, peer patch와 추가 patch 필드, Noise ping, lock 서명·회전, UnsignedPeerAPIOnly, 만료 상태 처리 | `tailscale.com/tailcfg/tailcfg.go:80` |
| 65, 68, 74, 81 | DERPMap 부분 갱신, stream과 업로드 분리, NodeCapMap, PacketFilters | `tailscale.com/tailcfg/tailcfg.go:116` |
| 84, 85, 114, 126 | SeamlessKeyRenewal, MaxKeyDuration, 기본 seamless renewal. 다만 이력 이상의 갱신 스케줄 알고리즘은 여기서 확인 못함 | `tailscale.com/tailcfg/tailcfg.go:135`, `tailscale.com/tailcfg/tailcfg.go:165`, `tailscale.com/tailcfg/tailcfg.go:177` |
| 89, 94, 111, 112 | peer patch의 구 Capabilities 제거, IsJailed, HomeDERP, nil AllowedIPs=Addresses | `tailscale.com/tailcfg/tailcfg.go:140`, `tailscale.com/tailcfg/tailcfg.go:145`, `tailscale.com/tailcfg/tailcfg.go:162` |
| 117, 125, 130 | DisplayMessages, Resolver.UseWithExitNode, hardware attestation | `tailscale.com/tailcfg/tailcfg.go:168`, `tailscale.com/tailcfg/tailcfg.go:176`, `tailscale.com/tailcfg/tailcfg.go:181` |
| 137, 147, 148 | register 429, machine endpoint의 429/503 Retry-After, StableTailnetID | `tailscale.com/tailcfg/tailcfg.go:188`, `tailscale.com/tailcfg/tailcfg.go:198` |

이력에는 c2n·SSH·방화벽·DNS·peer relay 등 제어 내용 이외의 동작도 포함되어 있다. 따라서 위 표만 구현하고 148 전체 호환이라고 선언할 근거는 없다. `tailnet.maxKeyDuration` 속성은 초 단위 float64 하나로 전달되며 기본값이면 생략된다. (`tailscale.com/tailcfg/tailcfg.go:95`, `tailscale.com/tailcfg/tailcfg.go:147`, `tailscale.com/tailcfg/tailcfg.go:171`, `tailscale.com/tailcfg/nodecap/nodecap.go:276`)

낮은 Version으로 요구를 줄이는 **단서**는 있다. Peers delta는 v5, PacketFilter nil 의미는 v6, stream 분리는 v68처럼 실제 분기·주석이 존재하고 testcontrol은 등록 Version이 0인지만 검사한다. 그러나 운영 서버의 최소 허용 버전·구버전별 응답 협상 구현은 이 소스에서 확인하지 못했으므로, 낮은 버전을 임의 선택하면 production 접속이 보장된다고 결론내릴 수 없다. 기준 Direct는 148을 고정 전송한다. (`tailscale.com/tailcfg/tailcfg.go:2050`, `tailscale.com/tailcfg/tailcfg.go:2102`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:985`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1458`, `tailscale.com/control/controlclient/direct.go:805`, `tailscale.com/control/controlclient/direct.go:1093`)

## 5. 상수와 타이머

| 이름·용도 | 값 | 출처 |
| --- | --- | --- |
| `CurrentCapabilityVersion` | 148 | `tailscale.com/tailcfg/tailcfg.go:200` |
| `watchdogTimeout` | 120초. 초기 요청 전부터 감시, 네트워크 읽기마다 reset, 메시지 처리 동안 stop | `tailscale.com/control/controlclient/direct.go:1015`, `tailscale.com/control/controlclient/direct.go:1169`, `tailscale.com/control/controlclient/direct.go:1267`, `tailscale.com/control/controlclient/direct.go:1291` |
| 예상 keepalive | Go 주석은 매분 수신 기대 | `tailscale.com/control/controlclient/direct.go:1015` |
| testcontrol keepalive | 스트림당 `50초 + rand.N(8초)`, 이후 같은 간격으로 반복. 이 구현은 req.KeepAlive를 조건으로 검사하지 않음 | `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1439`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1580` |
| 맵 프레임 wire 크기 | 최대 `256<<20` = 268435456바이트; client와 testcontrol 동일 | `tailscale.com/control/controlclient/direct.go:1460`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1891` |
| 맵 압축 해제 크기 | 최대 `1<<30` = 1073741824바이트 | `tailscale.com/control/controlclient/direct.go:1465` |
| 등록 응답 읽기 제한 | `1<<20` 바이트의 LimitReader | `tailscale.com/control/controlclient/direct.go:1438` |
| testcontrol 등록·맵 요청 | `msgLimit=1<<20`, decode에서 길이가 정확히 limit이면 오류 | `tailscale.com/tstest/integration/testcontrol/testcontrol.go:52`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:974`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1405`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1911` |
| 일반 backoff | `min(n²×10ms,30s) × [0.5,1.5)` | `tailscale.com/control/controlclient/auto.go:317`, `tailscale.com/control/controlclient/auto.go:588`, `tailscale.com/util/backoff/backoff.go:60` |
| Retry-After 비정상값 대체 | 5초 이상 10초 미만. 주석은 default 10s라고 하지만 실제 식 기준 | `tailscale.com/control/controlclient/direct.go:615` |
| `maxRetryWindow` | 5분 | `tailscale.com/control/controlclient/auto.go:39`, `tailscale.com/control/controlclient/auto.go:653` |
| HEAD ping / probe / 결과 POST | 각각 15초 / 10초 / 15초 | `tailscale.com/control/controlclient/direct.go:1663`, `tailscale.com/control/controlclient/direct.go:1818`, `tailscale.com/control/controlclient/direct.go:1839` |
| c2n handler / reply | 기본 각각 1분, handler는 `C2n-Handler-Timeout` 헤더로 변경 | `tailscale.com/feature/c2n/c2n.go:41`, `tailscale.com/feature/c2n/c2n.go:55` |
| device attribute 호출 | 30초 | `tailscale.com/control/controlclient/direct.go:1901` |
| Debug Sleep 상한 | 5분 | `tailscale.com/control/controlclient/direct.go:1689` |
| peer 만료 시계 차이 적용 기준 | ControlTime과 로컬 시각 차이가 1분 초과면 차이를 저장 | `tailscale.com/ipn/ipnlocal/expiry.go:28`, `tailscale.com/ipn/ipnlocal/expiry.go:63` |

## 6. Swiftail 최소 부분과 미룰 부분

### 6.1 M2 관문을 위한 구현 제안

1. 등록 JSON 모델과 공개 키 텍스트, 현재/후보/이전 node key 상태를 구현한다. testcontrol 인증 없음·RequireAuthKey 로그인부터 통과시키되 HTTP 200의 Error와 AuthURL·만료 분기를 별도로 둔다. (`tailscale.com/tstest/integration/testcontrol/testcontrol.go:995`, `tailscale.com/control/controlclient/direct.go:854`)
2. Hostinfo를 넣는 lite update와 map stream을 분리한다. 요청의 Version은 테스트에서 명시적으로 고정하고, 단순화를 위해 비압축 모드 또는 zstd 모드 하나를 먼저 선택하되 decoder와 요청 Compress를 맞춘다. (`tailscale.com/tailcfg/tailcfg.go:1444`, `tailscale.com/tailcfg/tailcfg.go:1466`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1526`)
3. 4바이트 LE 프레임, 크기 제한, 정확한 길이 누적 읽기, KeepAlive, watchdog, EOF 재연결을 구현한다. netmap은 self + NodeID 사전 + 프로필/정책/DNS/DERP 보존 상태로 관리하고 최초 Node를 요구한다. (`tailscale.com/control/controlclient/direct.go:1169`, `tailscale.com/control/controlclient/direct.go:1353`, `tailscale.com/control/controlclient/direct.go:1471`, `tailscale.com/control/controlclient/map.go:82`)
4. 전체 Peers와 PeersChanged/PeersRemoved를 반드시 구현한다. 이후 patch·Seen·Online·정책·DERP 부분 갱신을 이 노트의 알고리즘대로 추가한다. 148을 광고하는 동안 운영 서버는 이 증분들을 보낼 수 있으므로, 실제 tailnet 관문 전에는 모두 적용해야 한다. 무시하면 피어의 키·endpoint·home DERP·온라인 상태와 필터가 낡은 채 남는다. testcontrol은 자동으로 증분을 만들지 않으므로 이 누락이 testcontrol 시험에서는 드러나지 않는다. M2 합격 시험은 raw delta를 주입하여 마지막 peer 제거까지 확인한다. (`tailscale.com/control/controlclient/map.go:550`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:328`)
5. 승인 전·만료 상태는 Ready로 노출하지 않는다. 기본 HEAD PingRequest, rate-limit 대기, 일반 backoff를 구현한다. lock 활성 상태는 미지원으로 명시하고 일반 통신을 시작하지 않는 정책을 제안한다. (`tailscale.com/ipn/ipnlocal/local.go:7076`, `tailscale.com/control/controlclient/direct.go:1636`, `tailscale.com/control/controlclient/direct.go:624`, `tailscale.com/ipn/ipnlocal/tailnet-lock.go:185`)

**미뤄도 되는 부분의 조건:** M2의 판정이 등록·netmap 수신에 한정되고 lock·서브넷·exit node·SSH·Funnel·원격 관리·production posture 정책을 사용하지 않는 시험 구성이라면, 데이터면 WireGuard 연결, DERP/STUN 측정, MagicDNS 질의 처리, WhoIs 공개 API, c2n handler 세부 경로, ACME·device attrs·감사 로깅·자동 업데이트를 뒤로 미루는 구현 제안이다. 맵은 데이터면 설정과 DNS 등을 전달하지만 위 부가 기능은 별도 handler·호출로 구현되어 있으므로 netmap 내용을 보존하는 것과 기능을 실행하는 것을 나눌 수 있다. (`tailscale.com/tailcfg/tailcfg.go:1985`, `tailscale.com/control/controlclient/direct.go:1640`, `tailscale.com/control/controlclient/direct.go:1758`, `tailscale.com/control/controlclient/direct.go:1877`, `tailscale.com/ipn/localapi/localapi.go:597`)

PacketFilter를 이해하지 않은 채 production에서 모든 트래픽을 허용하는 것은 이 제안에 포함하지 않는다. 필터 빈 배열은 block-all이고, UnsignedPeerAPIOnly 노드는 네트워크 접근을 얻으면 안 되는 계약이다. M2에서 정책은 저장·증분 복원만 검증하고 데이터면 연결을 시작하는 단계에서 반드시 집행한다. (`tailscale.com/tailcfg/tailcfg.go:2100`, `tailscale.com/tailcfg/tailcfg.go:488`)

### 6.2 testcontrol의 실제 지원과 한계

| 항목 | 확인한 동작과 한계 | 출처 |
| --- | --- | --- |
| 기본 성격 | 메모리 안의 단일 tailnet. BaseURL은 ExplicitBaseURL 또는 HTTPTestServer로 설정 | `tailscale.com/tstest/integration/testcontrol/testcontrol.go:54`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:127`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:208` |
| 인증 키 | RequireAuthKey와 정확히 같은 Auth.AuthKey 문자열 요구; 불일치는 HTTP 200+Error. production의 키 만료·재사용 횟수·태그 정책을 구현한 검증기가 아님 | `tailscale.com/tstest/integration/testcontrol/testcontrol.go:995` |
| 대화형 인증 | RequireAuth이면 AuthURL 생성. Followup은 해당 경로 완료까지 대기하고 CompleteAuth로 해제. 실패 완료는 TODO라 성공만 모델링. RequireAuthKey와 RequireAuth를 함께 켜면 올바른 키도 대화형 요구를 자동 생략하지 않음 | `tailscale.com/tstest/integration/testcontrol/testcontrol.go:995`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1004`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1111`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:925` |
| 기기 승인 | RequireMachineAuth=false면 자동 승인, true면 CompleteDeviceApproval로 self Node 승인 상태 변경 | `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1053`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:950` |
| 주소·이름 | 등록 시 ID 기반 v4 /32·v6 /128을 할당, Hostname과 MagicDNSDomain으로 이름 구성. MagicDNSDomain이 비면 `Name`은 Hostname 그대로라 끝 점이 없으므로, Swift가 Name의 끝 점을 필수로 검사하면 이 서버에서 실패한다. 등록 Version은 Node.Cap | `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1056`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1087`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1098` |
| 키 교체·만료 | OldNodeKey가 알려져 있으면 후보 노드 복제, Followup 완료 시 이전 key entry 제거. allExpired이면 항상, 아니면 OldNodeKey가 zero인 요청에서만 기존 KeyExpiry로 expired 응답 가능. production 전체 renewal 정책은 아님 | `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1022`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1102` |
| 기본 맵 필드 | Node·DERPMap·Domain·CollectServices·PacketFilter·DNSConfig·SSHPolicy·ControlTime, 전체 정렬 Peers와 UserProfiles. 옵션에 따라 TKAInfo·PingRequest·masquerade·routes·jailed·unsigned·caps 추가 | `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1688`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1704`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1745`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1770` |
| 시간·온라인 | 기본 ControlTime은 실제 현재 시각이 아니라 고정된 2020년 날짜. AllOnline=true는 모든 peer를 online으로 표시하는 거친 대체 수단이며 개별 online/offline 추적은 없음 | `tailscale.com/tstest/integration/testcontrol/testcontrol.go:104`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1665`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1739` |
| 자동 증분 | 자동 맵에는 delta를 계산하는 단계가 없음(`TODO: add minner`). 매번 전체 Peers. AddRawMapResponse는 증분 주입용이며 처음 사용한 뒤 그 노드에 대한 자동 맵 응답을 계속 억제. 억제는 이후의 새 스트림에도 적용되어, 재연결한 스트림은 Node가 든 첫 응답 없이 keepalive만 받는다. 스트리밍 poll이 등록되어 있지 않으면 false를 돌려주고 넣지 않는다 | `tailscale.com/tstest/integration/testcontrol/testcontrol.go:328`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1554`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1742` |
| 임의 스트림 | AltMapStream은 serveMap 처리를 통째로 대체하며 스트림 생존 책임도 callback에 있음. lite 요청에도 호출되므로 따로 처리 필요 | `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1430`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1848` |
| 같은 노드의 스트림 교체 | 같은 노드에서 새 `Stream=true` 요청이 오면 이전 스트림을 닫는다. `Stream=false, OmitPeers=false`(한 번짜리 전체 맵)도 이전 스트림을 닫는다. `Stream=false, OmitPeers=true`(lite)와 `ReadOnly=true`만 기존 스트림을 유지한다. 따라서 스트림이 열린 동안 상태 갱신은 반드시 lite로 보낸다 | `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1508`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1977` |
| lite 응답 본문 | lite 요청에도 자동 맵 응답이 억제되지 않았으면 전체 MapResponse 프레임 하나를 보내고 끝낸다. 클라이언트는 본문을 끝까지 읽어 버린다 | `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1544`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1574` |
| 잘못된 입력 | 맵 요청의 NodeKey가 등록되지 않았거나 machine 키가 다르면 HTTP 400. 등록 요청의 JSON 해독 실패·zero NodeKey는 `go panic`, Version 0은 panic으로 시험 프로세스 자체가 죽는다. 잘못된 요청 시험은 testcontrol이 아니라 단위 시험으로 한다 | `tailscale.com/tstest/integration/testcontrol/testcontrol.go:983`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:986`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:989`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1444` |
| 피어 추가 | Go tsnet도 register+map 경로로 들어오며, non-streaming map 갱신이 기존 peer에게 알림. UpdateNode는 추가·변경 후 모든 연결에 알림. AddFakeNode는 저장만 하고 다른 노드 알림은 TODO | `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1077`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1498`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1519`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1305`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:807` |
| 피어 제거 | 스트림 종료 자체로 nodes에서 제거하는 경로는 serveMap에 없음. 마지막 peer 제거 delta는 AddRawMapResponse의 PeersRemoved로 시험할 필요가 있음. 자동 production ephemeral 삭제와 동등하게 보지 말 것 | `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1588`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:328`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:973` |
| DERP·DNS 설정 | Server.DERPMap·DNSConfig·MagicDNSDomain을 시험 시작 전에 설정. DERPMap 필드 주석은 nil=prod라고 하지만 MapResponse 구현은 그대로 전달하므로 nil일 때 실제 prod map 주입을 이 파일에서 확인 못함. AddDNSRecords는 DNSConfig를 만들고 ExtraRecords 추가 후 노드에 알림 | `tailscale.com/tstest/integration/testcontrol/testcontrol.go:58`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:63`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:769`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1651`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1688` |
| 압축·keepalive | Compress 빈 값이면 비압축, nonempty면 zstd. 길이 접두 동일, keepalive 50~58초 미만 간격 | `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1439`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1526`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1886` |
| set-dns | TXT·nonempty Name/Value·알려진 NodeKey·machine 일치·CertDomain challenge 검사, OnSetDNS hook 후 `{}`. 실제 외부 DNS 반영을 수행하는 구현은 이 handler에 없음 | `tailscale.com/tstest/integration/testcontrol/testcontrol.go:605` |
| 기타 machine 호출 | update-health는 204로 버림. machine dispatcher는 POST만 허용하며 set-device-attr PATCH 지원 없음. 미지원 경로는 단순 404 대신 panic을 발생시키는 시험 구현 | `tailscale.com/tstest/integration/testcontrol/testcontrol.go:539`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:561`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:430` |
| 오류 주입 | MaybeRejectRequest·RejectRequestForPath로 상태·Retry-After·본문 주입. ModifyFirstMapResponse로 첫 응답 수정 | `tailscale.com/tstest/integration/testcontrol/testcontrol.go:131`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1560`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1996` |
| lock | tkaStorage nil이면 비활성. 시험 TKA init/bootstrap/sync/sign handler는 있지만 일반 등록이 production lock 정책을 완전히 재현하는 것은 아님 | `tailscale.com/tstest/integration/testcontrol/testcontrol.go:199`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1138`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1770` |

시험 응답 생성에도 한계가 있다. AddRawMapResponse의 이름은 raw이지만 실제 입력은 `*tailcfg.MapResponse`이고 다시 JSON marshal하므로 `omitempty`인 빈 PacketFilter·Health 등은 명시적 `[]`로 내보낼 수 없다. AltMapStream의 SendMapMessage도 같은 타입을 encode한다. 이런 비우기 의미는 **직접 작성한 JSON decoder fixture** 등으로 따로 시험하는 것을 제안한다. PeersRemoved에 실제 ID를 넣는 M2 제거 시험에는 이 제한이 없다. (`tailscale.com/tailcfg/tailcfg.go:1996`, `tailscale.com/tailcfg/tailcfg.go:2061`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:337`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1840`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1882`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1918`)

## 7. 상호 운용 시험에서 확인할 것

아래는 실행 결과가 아니라 **시험 설계 제안**이다.

1. `RequireAuthKey`만 켠 testcontrol에 Swift 등록: 잘못된 키는 200+Error, 올바른 키는 NodeKey 확정과 첫 self Node 수신을 확인한다. 추가로 RequireAuth+CompleteAuth로 후보 키를 유지한 Followup을 시험한다. (`tailscale.com/tstest/integration/testcontrol/testcontrol.go:995`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1004`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:925`)
2. 초기 lite 완료 뒤 stream 시작, Go tsnet 피어의 register+lite 이후 Swift에 전체 peer가 보이는지 확인한다. stream의 낡은 Hostinfo·Endpoints가 lite의 새 값을 덮지 않는지도 확인한다. (`tailscale.com/tstest/integration/testcontrol/testcontrol.go:1452`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1483`)
3. **M2 핵심:** Swift의 stream 준비 후 Go 노드 정보를 사용한 PeersChanged를 AddRawMapResponse로 보내 추가/교체를 확인한다. 이어 그 ID를 PeersRemoved로 보내 마지막 peer가 사라지는지 확인한다. raw 주입 뒤 자동 맵이 억제되므로, Go tsnet의 연결 종료가 자동 delta를 만든다는 가정 없이 시험 harness가 명시적으로 제거 응답을 보낸다. (`tailscale.com/tstest/integration/testcontrol/testcontrol.go:328`, `tailscale.com/control/controlclient/map.go:582`)
4. raw 주입 또는 AltMapStream으로 unknown ID patch 무시, Online=false, Seen=false, Endpoints=[], CapMap={}, key/expiry 변경, full Peers 우선순위를 확인한다. `Peers=[]`가 기존 목록 삭제로 해석되지 않는지도 확인한다. (`tailscale.com/tstest/integration/testcontrol/testcontrol.go:1848`, `tailscale.com/control/controlclient/map.go:558`, `tailscale.com/control/controlclient/map.go:599`, `tailscale.com/control/controlclient/map.go:621`)
5. PacketFilter의 null/[] 차이, base와 이름별 규칙 혼합, `"*":null`, DNSConfig 전체 교체, DERP Regions=nil/{}와 HomeParams 부분 유지, 프로필 ID별 upsert를 확인한다. helper가 빈 값을 생략하는 경우는 직접 작성한 JSON decoder fixture로 보완한다. (`tailscale.com/tailcfg/tailcfg.go:1996`, `tailscale.com/control/controlclient/map.go:384`, `tailscale.com/control/controlclient/map.go:426`, `tailscale.com/control/controlclient/map.go:447`, `tailscale.com/control/controlclient/map.go:482`)
6. 압축/비압축을 각각 요청하고, 프레임을 임의 네트워크 조각으로 나눠 읽는다. 크기 한도 초과, 중간 EOF, 잘못된 zstd·JSON, 첫 Node 누락에서 실패 후 새 전체 세션으로 복구하는지 확인한다. (`tailscale.com/tstest/integration/testcontrol/testcontrol.go:1886`, `tailscale.com/control/controlclient/direct.go:1269`, `tailscale.com/control/controlclient/direct.go:1353`, `tailscale.com/control/controlclient/direct.go:1471`)
7. KeepAlive+PingRequest가 peer를 비우지 않는지, 120초 침묵 재접속, 429/503의 정수·날짜·비정상 Retry-After, 일반 403 오류가 키 만료 분기와 섞이지 않는지 확인한다. (`tailscale.com/control/controlclient/direct.go:600`, `tailscale.com/control/controlclient/direct.go:1015`, `tailscale.com/control/controlclient/direct.go:1205`, `tailscale.com/control/controlclient/direct.go:1299`)
8. RequireMachineAuth→승인, NodeKeyExpired→새 키·OldNodeKey, 이미 재생성한 키의 재거부, lock 활성 상태의 명시적 미지원 처리를 별도로 확인한다. testcontrol 고정 ControlTime이 실시간 만료 시험을 오염시키지 않도록 첫 응답 시간을 수정한다. (`tailscale.com/tstest/integration/testcontrol/testcontrol.go:950`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1022`, `tailscale.com/control/controlclient/direct.go:861`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:136`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1665`)

## 8. 확인하지 못한 것

- 운영 제어 서버의 최소 허용 capability와 낮은 Version별 실제 응답 선택·장기 지원 정책. 공개 타입에는 버전별 단서가 있으나 여기서 읽은 클라이언트는 148 고정이다. (`tailscale.com/tailcfg/tailcfg.go:53`, `tailscale.com/control/controlclient/direct.go:805`, `tailscale.com/control/controlclient/direct.go:1093`)
- 운영 서버가 요구하는 최소 Hostinfo/NetInfo·NLKey, 인증 키 종류별 정책, interactive login UI의 완료/실패 조건. testcontrol의 문자열 비교·성공 Followup 모델 이상은 확인하지 못했다. (`tailscale.com/control/controlclient/direct.go:749`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:995`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1017`)
- PingRequest/c2n 미응답 이후 운영 서버가 스트림을 끊거나 접근을 제한하는 구체 정책. 요청의 목적과 client의 무응답 분기는 확인했지만 서버 결과 정책은 이 코드에 없다. (`tailscale.com/tailcfg/tailcfg.go:1890`, `tailscale.com/control/controlclient/direct.go:1640`)
- production ephemeral 제거 시점과 로그아웃의 서버 측 효과·전파, seamless key renewal의 실제 일정·협상 알고리즘. 요청과 이력은 확인했지만 testcontrol은 해당 production 정책을 재현하지 않는다. (`tailscale.com/tailcfg/tailcfg.go:1340`, `tailscale.com/tailcfg/tailcfg.go:177`, `tailscale.com/control/controlclient/direct.go:771`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:973`)
- MapSessionHandle/Seq 재개를 운영 서버가 수락하는 조건과 재개 캐시 수명. 타입 계약은 있으나 기준 Direct의 요청 생성·세션 생성에는 재개 구현이 없다. (`tailscale.com/tailcfg/tailcfg.go:1475`, `tailscale.com/control/controlclient/direct.go:1092`, `tailscale.com/control/controlclient/direct.go:1228`)
- 실측 패킷. JSON 형태는 기준 모듈 타입을 Go 1.27.3 `encoding/json`으로 marshal/unmarshal해 확인했지만(3.1), 실제 클라이언트·서버 사이의 패킷 캡처와 상호 운용 시험은 수행하지 않았다. 운영 서버가 Go `encoding/json`이 아닌 별도 marshal 타입으로 보내는 필드(3.1의 `[]` 구분)의 실제 바이트도 보지 못했다. (`tailscale.com/tailcfg/tailcfg.go:1996`, `tailscale.com/control/controlclient/direct.go:1523`)
- 운영 제어 서버가 `MapRequest.Compress=""`를 받으면 실제로 비압축 프레임을 보내는지. 스키마 주석과 testcontrol은 비압축을 지원하지만 기준 Go 클라이언트는 항상 `"zstd"`를 보내므로 운영 서버의 비압축 경로는 쓰이지 않는다. 전부 Swift 방침에서 zstd 해독기를 만들지 말지가 이 확인에 달려 있다. (`tailscale.com/tailcfg/tailcfg.go:1444`, `tailscale.com/control/controlclient/direct.go:1139`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1526`)
- testcontrol의 `DERPMap=nil` 주석과 실제 prod map 제공 경로의 불일치 해소. 해당 필드를 명시적으로 채운 시험만 전제로 삼았다. (`tailscale.com/tstest/integration/testcontrol/testcontrol.go:58`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1690`)
