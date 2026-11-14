# wgpeer

Swift WireGuard 구현과 UDP 루프백으로 통신하는 wireguard-go 시험 피어다. 의존성은 `github.com/tailscale/wireguard-go` `v0.0.0-20261106233718-9e0ab45c16ca`이며 MIT 라이선스다. 기본 bind는 모든 주소를 열기 때문에 루프백 전용 UDP bind와 기본 endpoint 파서를 쓴다.

저장소 루트에서 빌드한다.

```sh
sh Scripts/build-interop-tools.sh
```

시험은 다음과 같이 실행한다.

```sh
cd Tools/interop
GOCACHE="$(eyebuild dir interop-tools)/gocache" GOMODCACHE="$(eyebuild dir ref-src)/gomod" GOFLAGS=-modcacherw go test -count=1 ./...
```

표준 입력의 첫 줄은 JSON 설정이다. 키는 각각 32바이트의 16진수이며 `peerEndpoint`는 상대의 `127.0.0.1:포트`다. `listenPort`가 0이면 사용 가능한 포트를 고른다. `allowedIPs`에는 상대의 IP 접두를 넣는다.

```json
{"privateKey":"<64자리 16진>","peerPublicKey":"<64자리 16진>","peerEndpoint":"127.0.0.1:12345","allowedIPs":["10.99.0.1/32"],"listenPort":0}
```

준비되면 표준 출력에 `{"event":"ready","listenPort":12345,"publicKey":"<16진>"}`를 한 줄 쓴다. 이후 입력은 한 줄에 JSON 명령 하나다.

- `{"cmd":"send","packet":"<16진 IP 패킷>"}`: 상대에게 패킷을 보낸다.
- `{"cmd":"stats"}`: `{"event":"stats","lastHandshakeSec":0,"lastHandshakeNsec":0,"txBytes":0,"rxBytes":0}`을 출력한다.
- `{"cmd":"quit"}` 또는 EOF: 장치를 닫는다.

복호화한 패킷마다 `{"event":"recv","packet":"<16진>"}`을 출력한다. 잘못된 입력은 `{"event":"error","message":"…"}`를 출력하며 설정 오류는 종료 코드가 0이 아니다. 로그는 표준 오류로 보낸다. 송신 패킷의 목적지와 수신 패킷의 출발지는 각각 해당 피어의 `allowedIPs`에 들어야 한다.

# tailnet

`sh Scripts/build-interop-tools.sh tailnet`으로 빌드한다. 인자 없는 호출은 기존과 같이 `wgpeer` 경로 한 줄을 출력한다. `tailnet`은 루프백의 평문 testcontrol, 자체 서명 TLS DERP, STUN 서버를 시작하고 `ready` JSON을 출력한다. DERPMap의 `InsecureForTests`는 인증서 검증을 끄므로 Swift 시험에서도 이 시험 서버에 한정해 자체 서명 인증서를 허용해야 한다. STUN은 `stuntest`가 실행 프로그램에서 사용할 수 없는 `testing.TB`를 요구하므로 같은 `stun` 패키지로 구현한다.

표준 입력은 줄마다 `id`와 `cmd`가 있는 JSON이며 출력은 각 명령의 `id`가 포함된 JSON 한 줄이다. 오류는 `error` 사건이다. `quit` 또는 EOF는 종료한다.

- `addPeer`의 `name`은 소문자 DNS 레이블이다. 임시 tsnet 노드를 시작하고 TCP·UDP 포트 7에서 에코한다. `peer` 사건에 공개 nodeKey, addresses, fqdn이 있다.
- `removePeer`는 노드와 임시 상태를 닫고 `removed`를 돌려준다. testcontrol에는 노드 삭제 API가 없어 `nodes`와 다른 피어의 맵에서 자동으로 없어지지 않는다.
- `nodes`는 testcontrol의 등록 목록이다. `online`은 testcontrol에 개별 연결 추적이 없으므로 실제 접속 상태로 해석하면 안 된다.
- `peerStatus`는 `name` 노드가 보는 `peers`의 nodeKey, addresses, online, curAddr, relay를 돌려준다.
- `peerPing`은 `name`, 대상 IP `to`, `type` (`disco`, `TSMP`, `ICMP`)을 받는다. `result`는 LocalClient PingResult이며 `Err`가 비어 있어야 성공이다.
- `injectMapResponse`는 대상 `nodeKey`와 `response` 객체를 받는다. 스트림이 연결된 경우에만 큐에 넣으며 실제 전송은 스트림 처리 시점이다. 첫 주입부터 해당 노드에 대한 자동 맵이 계속 억제된다. `MapResponse` 타입으로 다시 JSON 인코딩하므로 빈 배열 등의 원래 JSON 표현은 보존되지 않는다.
- `setAuth`는 첫 제어 요청 전에 `requireAuth`와 `authKey`를 설정한다. 키는 testcontrol이 단일 문자열로 비교하며 만료·재사용·태그 정책은 없다. 대화형 인증은 반환받은 로그인 URL을 `authURL`로 넘겨 성공 완료한다. 실패 완료와 기기 승인 조작은 지원하지 않는다. 키를 요구하면 addPeer에도 같은 키를 사용한다. 대화형 인증을 요구하는 동안 addPeer는 완료까지 대기하므로 Swift 노드의 등록 시험에 사용한다.

기본 등록은 자동 승인이다. testcontrol의 기본 맵은 self Node, 전체 Peers, DERPMap, DNSConfig, PacketFilter 등을 포함하며 ControlTime은 고정 시각이다. 시험 로그 업로드는 `logtail.Disable()`과 `TS_NO_LOGS_NO_SUPPORT=true`로 끄고 portmapper도 비활성화한다. testcontrol의 인증 키 비교는 상수 시간이 아닌 upstream 구현이므로 시험용 값만 사용한다.

# h2server

`sh Scripts/build-interop-tools.sh h2server`으로 빌드한다. `127.0.0.1`의 임의 포트에서 TLS·HTTP/1 업그레이드 없는 prior knowledge HTTP/2를 받는다. 준비 출력은 `{"event":"ready","port":12345}` 한 줄이다. `golang.org/x/net/http2` v0.60.0의 `Server.ServeConn`을 기본 설정으로 사용한다. Go 1.27.3에서는 이것이 표준 라이브러리 HTTP/2 서버에 위임된다. `ConfigureServer`는 `http.Server.Shutdown`의 정상 GOAWAY 경로를 연결하기 위해 사용한다(testcontrol의 ServeConn과 같은 프레임 구현).

| 요청 | 응답 |
| --- | --- |
| `GET /small` | 200, `ok` |
| `POST /echo` | 200, 요청 본문 그대로. 최대 8MiB, 초과하면 413 |
| `GET /bytes?size=N` | 200, N바이트. 0부터 세어 i번째 바이트는 `i % 251`. N은 0…8MiB |
| `GET /stream?count=N&intervalMs=M` | 200, M밀리초 대기 후 `0\n`, `1\n`, …을 각각 flush. N=0이면 취소될 때까지. N은 0…1,000,000, M은 0…60,000 |
| `GET /headers?count=N&size=S` | 200, `x-test-0`…`x-test-(N-1)`. 각 값은 j번째 문자가 `a + j % 26`인 S바이트 문자열. N≤1024, S≤64KiB, `N*(S+64)`≤1MiB |
| `GET /status?code=N` | 최종 상태 N(200…599), 빈 본문 |

음수·누락·범위 밖 숫자는 400, 다른 메서드는 405, 다른 경로는 404다. Date 헤더는 생성하지 않는다. `/stream`은 응답 헤더부터 flush하므로 첫 줄 전에도 다른 요청을 보낼 수 있다. 큰 `/headers`는 CONTINUATION과 허프만 해독을 시험한다. 동적 표를 재사용하는 시험은 같은 연결에서 `/headers?count=4&size=20`을 두 번 호출한다. 큰 헤더 전체는 4096바이트 동적 표에 남을 수 없으므로 그 경우 모든 필드의 재색인을 기대하면 안 된다.

표준 입력은 JSON 줄이다. `{"cmd":"goaway"}`는 리스너를 닫고 정상 Shutdown으로 GOAWAY를 보내 새 스트림을 거절한다. 기존 스트림은 계속된다. `{"cmd":"quit"}` 또는 EOF는 모든 연결을 닫는다. 잘못된 명령은 `{"event":"error","message":"…"}` 한 줄이다. 표준 출력은 JSON 줄만, 로그는 표준 오류다. 기본 서버 설정을 유지하므로 서버 발신 PING을 강제로 발생시키는 명령은 없다.

# HPACK 자료 생성

다음 명령은 저장소 루트에서 실행한다. 외부 네트워크 없이 이미 받은 기준 모듈과 도구 체인을 사용한다.

```sh
export GOCACHE="$(eyebuild dir interop-tools)/gocache"
export GOMODCACHE="$(eyebuild dir ref-src)/gomod"
export GOFLAGS=-modcacherw GOPROXY=off GOSUMDB=off
(cd Tools/interop && go run ./cmd/h2server -hpack-fixtures ../../Tests/SwiftailHTTP2Tests/Fixtures/hpack.json)
```

`hpack.json`은 연결 배열이다. 연결의 `name`은 설명, `blocks`는 순서 있는 헤더 블록 배열이다. 블록의 `hex`는 HPACK 바이트의 소문자 16진 문자열, `headers`는 기대 헤더 배열이다. 헤더는 `name`, `value`, `sensitive`를 모두 가진다. 연결마다 새 해독기를 만들고 같은 연결의 블록 사이에는 동적 표를 유지한다. 해독기의 허용 최대 동적 표 크기는 4096이다.

Go `golang.org/x/net/http2/hpack.Encoder`가 허프만과 표현 방식을 선택한다. 2연결·10블록으로 정적 색인, 동적 추가·재색인·축출, 4096→128→0→4096 및 한 블록의 0→512 표 크기 갱신, 빈 값, 4096바이트 값, `Sensitive=true`의 never indexed를 포함한다. 생성된 모든 블록은 Go Decoder로 다시 해독하여 검증한다.

# mapfixtures

맵 응답을 Go의 실제 `mapSession`에 차례로 넣고 정규화한 상태와 요청 JSON을 생성한다. Swift 구현은 읽거나 호출하지 않는다. 빌드는 `sh Scripts/build-interop-tools.sh mapfixtures`, 실행은 `Tools/interop`을 현재 폴더로 한다. 위 환경 변수를 설정한 뒤 저장소 루트에서 실행한다.

```sh
(cd Tools/interop && go run ./cmd/mapfixtures ../../Tests/SwiftailControlTests/Fixtures)
```

`tailscale.com` v1.104.6을 `go list -m`으로 찾고 `eyebuild dir interop-tools` 아래에 임시 복사한다. Go는 GOMODCACHE 내부 overlay를 거부하고 embed는 링크 파일을 거부하므로 복사본이 필요하다. 임시 `-modfile`의 로컬 replace로 그 복사본을 지정하고, `-overlay`로 `control/controlclient/swiftail_fixtures.go` 한 파일만 추가한다. 추가 파일은 `newMapSession`과 `HandleNonKeepAliveMapResponse`를 호출하고 `NetmapUpdater.UpdateFullNetmap`에서 실제 netmap을 받는다. delta updater는 구현하지 않아 Go의 전체 netmap 출력 경로를 사용한다. 적용 로직은 다시 구현하지 않는다. `KeepAlive`만 upstream `direct.go`처럼 mapSession 진입 전에 건너뛴다. 모듈 캐시는 수정하지 않으며 임시 복사본·overlay·modfile은 종료 시 지운다.

`PeerSeenChange=true`에 쓰이는 패키지 시계와 세션 시계는 `2026-01-02T03:04:05.123456789Z`로 고정한다. 공개 키는 `SHA-256("swiftail-fixtures/node/<번호>")` 또는 `.../disco/<번호>`를 X25519 private 입력으로 사용해 유도한다. NLKey는 `SHA-256("swiftail-fixtures/lock")`을 Ed25519 시드로 사용한다. 시험용 공개 시드이며 운영 키가 아니다. 현재 시각·난수·실제 tailnet은 자료에 들어가지 않는다.

`map-sessions.json`은 시나리오 배열이다. `name`과 `steps`를 가지며 단계는 설명 `name`, 원문 문자열 `response`, 정규화 객체 또는 null인 `netmap`이다. `response`를 한 번 더 JSON 해독한 값을 Go에 전달한다. 원문을 tailcfg 타입으로 재부호화하지 않아 키 생략·`null`·`[]`·`{}`를 보존한다. 단계의 정규화 상태가 이전 상태와 같으면 `netmap`은 null이다(Go 콜백 발생 여부를 뜻하지 않는다). 각 시나리오는 새 세션으로 시작한다.

정규화한 netmap은 아래 키를 항상 가진다. 객체 키의 순서는 의미가 없다. 64비트 ID는 부동소수점을 거치지 않고 비교한다.

| 키 | 형식 |
| --- | --- |
| `SelfNode` | 아래 Node 투영 객체 |
| `Peers` | ID 숫자 오름차순의 Node 투영 배열. 비면 `[]` |
| `DERPMap` | null 또는 Go `tailcfg.DERPMap`의 JSON. `Regions`는 10진 ID 문자열→지역 객체, 각 지역의 `Nodes`는 Go 순서다. `omitDefaultRegions`는 소문자로 시작하며 false이면 생략된다. `HomeParams.RegionScore`는 비면 생략된다 |
| `DNSConfig` | Go `tailcfg.DNSConfig` JSON 객체. 초기 zero 객체도 출력한다. nil DNSConfig 응답은 이전 객체 유지 |
| `PacketFilter` | 이름 순으로 연결된 적용 후 `tailcfg.FilterRule` 배열. 비면 `[]`. 각 규칙은 Go JSON 그대로 |
| `UserProfiles` | 현재 self.User·peer.User·peer.Sharer에 필요한 프로필만 있는 10진 UserID 문자열→Go `tailcfg.UserProfile` JSON 객체 |
| `Domain` | 문자열 |
| `TKAEnabled` | bool |

Node 투영은 `ID`, `StableID`, `Name`, `Key`, `DiscoKey`, `Addresses`, `AllowedIPs`, `Endpoints`, `HomeDERP`, `Online`, `LastSeen`, `KeyExpiry`, `Expired`, `Cap`, `CapMap`, `User`, `Sharer`, `MachineAuthorized`를 항상 출력한다. ID·User·Sharer·HomeDERP·Cap은 정수, StableID·Name은 문자열, 키는 `nodekey:`/`discokey:`+64자리 hex다. Addresses·AllowedIPs는 CIDR 문자열 배열, Endpoints는 IP:port 문자열 배열이며 이 세 배열의 nil은 `[]`로 정규화한다. Online은 bool 또는 null, LastSeen은 RFC3339Nano 문자열 또는 null, KeyExpiry는 RFC3339Nano 문자열(zero면 `0001-01-01T00:00:00Z`), Expired·MachineAuthorized는 bool이다. 시간은 Go가 보존한 오프셋을 그대로 쓴다. CapMap은 null 또는 capability 문자열→raw JSON 값 배열/null 객체이며 null과 빈 배열을 임의로 합치지 않는다. 그 밖의 Node 필드·계산한 표시 이름·ControlTime은 이 투영에서 제외한다.

`requests.json`은 사례 배열이다. `name`, `type`(`RegisterRequest` 또는 `MapRequest`), `input`(명시적으로 채운 값의 JSON 객체), `json`(Go `encoding/json.Marshal` 원문 문자열)을 가진다. input에 없는 필드는 해당 Go 타입의 zero 값이다. 중첩 객체도 같은 규칙이다. 비교 대상은 json의 공백·키 순서가 아니라 해독한 객체와 필드의 존재 여부다. zero RegisterRequest·MapRequest, 인증 키·Followup·OldNodeKey·Expiry, 스트림·상태 갱신, Hostinfo·NetInfo 사례가 `omitempty`/`omitzero` 차이를 드러낸다.

특히 `peer-full-empty-omitted`에서 Peers의 빈 배열과 생략은 모두 피어를 유지한다(전체 교체 조건은 `len(Peers)>0`). `derp-replacement-and-preservation`에서 Regions 객체는 지역별 patch가 아니라 전체 교체이며 nil 지역은 제거된다. Regions가 null이면 이전 Regions와 omitDefaultRegions를 함께 유지한다. `packet-filters`에서 빈 PacketFilter는 `base`만 비우고 다른 이름은 남긴다. `"*":null`은 같은 응답의 PacketFilter 적용 뒤 모든 이름을 비운다. `profiles-domain-tka`에서 프로필 저장소는 누적되지만 출력 netmap에는 현재 참조하는 사용자만 나타난다. `peer-patches`에서 과거 KeyExpiry만으로 Expired가 true가 되지 않으며, seen·online 변경 뒤 patch가 적용된다.

전체 Go 검증은 다음과 같다. `interop-tools`·`ref-src` 폴더는 유지한다.

```sh
(cd Tools/interop && go vet ./... && go test -count=1 ./...)
```

# controlfaults

`ControlClient`의 회귀 시험용 제어 서버다. 빌드는 `sh Scripts/build-interop-tools.sh controlfaults`, 실행은 `controlfaults <모드>`이다. `127.0.0.1`의 임의 포트에서 듣고 표준 출력의 첫 줄에 서버 URL(`http://127.0.0.1:12345`)을 쓴다. 표준 입력이 닫히면(EOF) 끝난다. 로그는 표준 오류로 보내며 요청 본문과 키는 출력하지 않는다. 서버 키는 실행할 때마다 새로 만든다.

`/key`와 `/ts2021`(업그레이드·Noise·HTTP/2)은 `tailscale.com/control/controlhttp/controlhttpserver`와 `golang.org/x/net/http2`로 진짜 제어 서버처럼 처리하고, 그 안의 `/machine/register`·`/machine/map` 응답만 모드에 따라 바꾼다. testcontrol은 쓰지 않는다.

| 모드 | 동작 |
| --- | --- |
| `basic` | 등록은 곧바로 `MachineAuthorized`. 상태 갱신(`Stream=false`)은 빈 200. 맵 스트림은 self Node(`ID` 1, 요청의 NodeKey) 하나를 보내고 붙잡는다 |
| `initialUploadHang` | `basic`과 같되 상태 갱신에 답하지 않는다 |
| `interactiveRace` | 첫 등록 요청을 `/release`가 올 때까지 붙잡는다. 그 뒤의 등록은 곧바로 승인한다 |
| `followupReconnect` | Followup이 빈 등록에는 `AuthURL`(`<서버 URL>/login/1`)을 준다. 첫 Followup 요청은 스트림을 끊고(RST_STREAM) 두 번째 Followup부터 승인한다 |
| `followupHold` | Followup이 빈 등록에는 그 요청의 순번이 든 `AuthURL`(`<서버 URL>/login/<순번>`)을 준다. Followup 요청은 `/release`가 올 때까지 붙잡았다가 승인한다 |
| `sameAuthURL` | `/release` 전까지 모든 등록(Followup 포함)에 같은 `AuthURL`(`<서버 URL>/login/1`)을 곧바로 준다. 그 뒤에는 승인한다 |
| `expiryTimer` | 맵 스트림의 self Node `KeyExpiry`를 응답 시각 + 1초로 준다 |
| `alwaysExpired` | 맵 스트림의 self Node `KeyExpiry`를 응답 시각 − 1시간으로 준다 |
| `authEcho` | `Auth`가 있는 등록을 `{"Error":"invalid authkey: <받은 AuthKey>"}`로 거절한다 |
| `manyMaps` | 첫 맵 스트림에 self Node 응답과 `Domain`만 다른 응답 199개(`d1`…`d199`)를 보내고 스트림을 끝낸다. 다음 맵 스트림은 머리만 보내고 붙잡는다 |

평문 HTTP 경로:

- `GET /probe`: 지금까지 센 값. `{"connections":0,"registers":0,"followups":0,"maps":0,"nodeKeys":0}`. `connections`는 `/ts2021` 연결, `maps`는 스트림과 상태 갱신을 합친 `/machine/map` 요청, `nodeKeys`는 등록 요청에 나온 서로 다른 NodeKey의 수다(키 자체는 내놓지 않는다).
- `GET /release`: `interactiveRace`에서 붙잡은 첫 등록을 놓아 준다. 여러 번 불러도 된다.

Swift 시험은 `SWIFTAIL_CONTROLFAULTS`에 도구 경로를 넣어 돌린다. 값이 없으면 건너뛴다.

```sh
SWIFTAIL_CONTROLFAULTS="$(sh Scripts/build-interop-tools.sh controlfaults)" eyebuild swift <용도> -- test --filter ControlFaultsTests
```
