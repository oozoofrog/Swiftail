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
- `nodes`는 testcontrol의 등록 목록이다. 각 노드의 `endpoints`는 제어 서버가 맵 상태 갱신에서 받아 보관한 IP:port 문자열 배열이며 없으면 `[]`다. `AllNodes()`가 돌려주는 복제본의 `Endpoints`를 그대로 쓴다(`tailscale.com` v1.104.6 `tstest/integration/testcontrol/testcontrol.go:853-862`, `:1452-1486`). `online`은 testcontrol에 개별 연결 추적이 없으므로 실제 접속 상태로 해석하면 안 된다.
- `peerStatus`는 `name` 노드가 보는 `peers`의 nodeKey, addresses, online, curAddr, relay, `active`, `lastWrite`와 자기 엔드포인트 `selfAddrs`를 돌려준다. `selfAddrs`는 `Status.Self.Addrs`의 IP:port 문자열 배열이며 없으면 `[]`다. `active`는 bool, `lastWrite`는 Go `time.Time`의 RFC3339Nano 문자열(송신 전에는 `0001-01-01T00:00:00Z`)이다. magicsock은 외부 송신 활동(데이터·CLI Ping) 뒤 45초 안이면 active로 보고, 그 마지막 활동 시각을 lastWrite로 기록한다. heartbeat 송신만으로는 이 시각을 연장하지 않는다(`wgengine/magicsock/endpoint.go:2232-2253`, `magicsock.go:4026-4028`, `:4083`). `curAddr`는 신뢰된 직접 경로로만 보낼 때의 주소이며 DERP를 함께 쓰면 빈 문자열이다. `relay`는 피어의 홈 DERP 지역 코드이므로 현재 DERP 사용 여부를 뜻하지 않는다.
- `peerPing`은 `name`, 대상 IP `to`, `type` (`disco`, `TSMP`, `ICMP`)을 받는다. `result`는 LocalClient PingResult이며 `Err`가 비어 있어야 성공이다.
- `peerSend`는 `{"id":1,"cmd":"peerSend","name":"go-peer-a","to":"100.64.0.2","port":42001,"proto":"udp","payload":"010203"}`처럼 보낸다. `proto`는 `udp` 또는 `tcp`, `port`는 1…65535, `payload`는 65507바이트 이하의 hex다(빈 값 허용). 지정 피어의 tsnet으로 UDP 데이터그램 하나를 쓰거나, 2초 제한으로 TCP 연결을 시도한 뒤 연결되면 payload를 쓴다. 결과는 `{"id":1,"event":"peerSend","name":"go-peer-a","attempted":true,"sent":true,"error":""}`다. 전송 실패도 `peerSend` 사건으로 `sent:false`와 오류 문자열을 돌려주고, 잘못된 명령 입력은 기존 `error` 사건이다. `sent`는 payload 쓰기 완료를 뜻하며 상대의 수신을 보장하지 않는다. TCP 스택이 없는 Swift 대상은 보통 제한 시간으로 `sent:false`가 된다. SYN 송신 여부는 수신 패킷으로 확인해야 한다. TCP·UDP 소켓은 명령이 끝날 때 닫는다.
- `injectMapResponse`는 대상 `nodeKey`와 `response` 객체를 받는다. 스트림이 연결된 경우에만 큐에 넣으며 실제 전송은 스트림 처리 시점이다. 첫 주입부터 해당 노드에 대한 자동 맵이 계속 억제된다. `MapResponse` 타입으로 다시 JSON 인코딩하므로 빈 배열 등의 원래 JSON 표현은 보존되지 않는다.
- `setAuth`는 첫 제어 요청 전에 `requireAuth`와 `authKey`를 설정한다. 키는 testcontrol이 단일 문자열로 비교하며 만료·재사용·태그 정책은 없다. 대화형 인증은 반환받은 로그인 URL을 `authURL`로 넘겨 성공 완료한다. 실패 완료와 기기 승인 조작은 지원하지 않는다. 키를 요구하면 addPeer에도 같은 키를 사용한다. 대화형 인증을 요구하는 동안 addPeer는 완료까지 대기하므로 Swift 노드의 등록 시험에 사용한다.
- `setNeverDirectUDP`는 `{"id":1,"cmd":"setNeverDirectUDP","enabled":true}`처럼 bool을 받아 `{"id":1,"event":"neverDirectUDP","enabled":true}`를 돌려준다. `false`로 되돌릴 수 있고 같은 값을 반복해도 된다. `enabled` 누락·null·다른 타입은 `error` 사건이다. `envknob.Setenv("TS_DEBUG_NEVER_DIRECT_UDP", "true"/"false")`로 등록된 노브 캐시까지 바꾸므로, 이미 실행 중인 피어와 나중에 더할 피어를 포함해 도구 프로세스의 모든 Go 피어에 적용된다. `id` 반환·오류 규약은 다른 명령과 같다.

`setNeverDirectUDP`는 UDP 차단기가 아니다. 켜면 새 직접 disco Ping 송신·UDP Ping에 대한 Pong 응답·전체 직접 탐색과 그에 딸린 CallMeMaybe 송신을 막지만 DERP Ping과 UDP 데이터 송수신은 계속된다(`tailscale.com` v1.104.6 `wgengine/magicsock/debugknobs.go:65-68`, `endpoint.go:1360-1362`, `:1424-1426`, `magicsock.go:2606-2608`). 이미 잡힌 `bestAddr`와 신뢰 기간을 즉시 지우지 않으므로 마지막 유효 Pong 뒤 6.5초까지는 UDP 단독, 신뢰가 지나면 UDP와 DERP 이중 송신이 된다. 이때 `curAddr`는 빈 문자열이어도 UDP 데이터는 계속 흐를 수 있다(`endpoint.go:635-653`, `:1107-1205`). 끄면 다음 송신·heartbeat·CLI Ping에서 직접 탐색을 재개하고 유효 Pong으로 직접 경로가 돌아온다. 명령 응답 자체는 경로 전환 완료를 뜻하지 않는다.

전환 전에 이미 보낸 Ping과 예약된 CallMeMaybe·송신 goroutine을 취소하지 않는다. 따라서 진행 중인 탐색의 Pong은 켠 뒤에도 처리해 신뢰를 연장할 수 있고, 기존 Ping 타이머는 만료 때 신뢰가 끝난 bestAddr를 지울 수 있다(`endpoint.go:1244-1256`, `:1405-1419`, `:1929-2018`). 새 직접 Ping은 예약하지 않으므로 보통 bestAddr가 남아 UDP 이중 송신을 계속한다는 노트 7.2의 설명은 맞지만, 모든 전환 순간에 보장되는 것은 아니다. 또한 upstream `envknob.Setenv`는 등록된 노브의 동시 읽기에 안전하지 않다고 명시한다(`envknob/envknob.go:89-108`, `:162-177`). 계약에 따른 시험용 런타임 전환의 한계이며 데이터 경쟁 없는 전환을 보장하지 않는다.

전환 시간은 `peerStatus`를 반복해 읽으며 잰다. 노트 7.1의 설명과 달리, 크기 0인 기본 disco Ping은 신뢰된 직접 경로가 있으면 DERP로 함께 보내지 않는다(`endpoint.go:720-722`, `:1061-1070`). 이 상태에서 노브를 켠 직후 `peerPing type=disco`를 부르면 직접 Ping 송신도 막혀 명령 제한 시간까지 응답을 기다릴 수 있다. 전환 관찰에는 UDP 데이터를 계속 보내며 status를 읽는 방식을 쓴다.

직접 경로가 선 직후 노브를 켜고 disco Ping을 호출한 실제 재현에서는 30.002초 뒤 다음 응답을 받았다. 도구가 명령을 순서대로 처리하므로 그동안 status 명령도 기다리게 된다.

```json
{"event":"error","id":8,"message":"error Post \"http://local-tailscaled.sock/localapi/v0/ping?ip=100.64.0.2&size=0&type=disco\": context deadline exceeded: "}
```

2026-11-14 Go 피어 둘의 실제 JSON 명령 관찰(KST): 서로 disco Ping으로 loopback 직접 경로를 확인한 뒤 양방향 UDP를 1초 간격으로 쓰고 status를 약 0.1초 간격으로 읽었다. `selfAddrs`와 `nodes.endpoints`의 loopback 주소도 일치했다.

- 23:31:49.820에 노브를 켰다. peer-b의 curAddr는 23:31:56.272(+6.451초), peer-a는 23:31:56.422(+6.602초)에 비었고 active는 둘 다 true였다. 켠 채 14초까지 빈 상태였으며 양방향 UDP 쓰기는 계속 성공했다(쓰기만으로 수신을 보장하지는 않는다).
- 23:32:03.978에 노브를 끄고 UDP를 다시 썼다. 23:32:04.017(+약 0.040초)에 양쪽 curAddr가 직접 주소로 돌아왔다. 이 값은 이 루프백 실행의 관찰값이며 일반 네트워크의 상한을 뜻하지 않는다.
- 별도 Go 시험 `TestNeverDirectUDPLeavesUDPData`는 양쪽 curAddr가 빈 뒤 DERP 서버와 리스너를 닫고도 새 UDP 에코 3회가 돌아옴을 확인한다. 따라서 노브가 직접 UDP 데이터를 막지 않는다는 소스 해석과 일치한다.

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

# filterfixtures

`tailscale.com` v1.104.6의 공개 `wgengine/filter`를 직접 실행하여
`Tests/SwiftailEngineTests/Fixtures/filter-verdicts.json`을 만든다.
Swift 구현은 읽거나 실행하지 않는다. `mapfixtures`와 같은 캐시 환경을 쓰며,
필터 함수들은 공개되어 있어 임시 복사본·overlay가 필요 없다. Go 모듈 캐시는 고치지 않는다.
빌드 정보에서 기준 버전과 replace 부재를 확인한다.

저장소 루트에서 실행한다. `interop-tools`·`ref-src`는 지우지 않는다.

```sh
export GOCACHE="$(eyebuild dir interop-tools)/gocache"
export GOMODCACHE="$(eyebuild dir ref-src)/gomod"
export GOFLAGS=-modcacherw GOPROXY=off GOSUMDB=off
sh Scripts/build-interop-tools.sh filterfixtures
(cd Tools/interop && go vet ./... && go run ./cmd/filterfixtures ../../Tests/SwiftailEngineTests/Fixtures)
```

시나리오의 규칙 **원문 문자열**을 Go `[tailcfg.FilterRule]`로 해독하여
`filter.MatchesFromFilterRules` → `filter.New`를 호출한다.
`localNets`는 자기 주소의 /32·/128만 넣으며 `logIPs=nil`, `logger.Discard`, 실행 플래그 0으로
로그를 끈다. 주소 문자열 오류는 오류와 함께 반환된 부분 일치 목록을 그대로 설치한다.
`SrcBits`·`DstPorts.Bits` 오류 때 반환되는 nil도 그대로 설치한다. 모든 변환 오류를 nil로
바꾸는 것은 실제 Go 동작이 아니다(`wgengine/filter/tailcfg.go:30-118`).

각 패킷마다 새 `packet.Parsed`에 `Decode`하고 수신은 `RunIn`의 최종 Accept/Drop을 기록한다.
송신은 `RunOut`을 호출해 역방향 흐름을 적고 Accept인지 확인한다.
같은 시나리오 안에서는 필터를 유지하며, 규칙 교체는 `filter.New`의 `shareStateWith`에 이전
필터를 넘긴다. 시나리오 사이에는 상태를 공유하지 않는다.
모든 시나리오를 새 필터들로 한 번 더 실행하고 판정·변환 오류를 포함한 JSON 전체가 같은지
확인한 뒤 쓴다. 현재 시각·난수·소켓을 사용하지 않는다.

자료는 최상위 `reference`(기준 모듈·버전)와 `scenarios` 배열을 가진다.

| 시나리오 키 | 뜻 |
| --- | --- |
| `name` | 한국어 시나리오 이름. 유일하며 IPv4·IPv6를 구별한다 |
| `rules` | `tailcfg.FilterRule` 배열의 원문 JSON **문자열**. Swift도 그대로 `[FilterRule]`로 해독한다 |
| `localAddresses` | 자기 주소 문자열 배열. 접두사나 경로가 아니다 |
| `capabilitySources` | 선택 사항. 이 가짜 출발지들에만 `fixture:test` capability를 주는 결정적 Go callback을 설치한다. 생략하면 callback은 nil. Swift는 이 능력을 지원하지 않는다 |
| `conversionError` | 선택 사항. 최초 규칙 변환에서 Go가 반환한 오류 문자열. 판정을 대체하지 않는다 |
| `steps` | 같은 필터 상태를 이어 가며 실행하는 단계 배열 |

| 단계 키 | 뜻 |
| --- | --- |
| `name` | 해당 단계의 설명 |
| `direction` | `in` 수신, `out` 송신 상태 기록, `replace` 규칙·자기 주소 교체 |
| `packet` | `in`·`out`의 완전한 IP 패킷을 보존한 소문자 hex. 이름에 적은 잘못된 길이·조각 등도 그대로 보존 |
| `verdict` | `in`에서 실제 `RunIn`이 내놓은 `accept` 또는 `drop`. `out`·`replace`에는 없다 |
| `rules`, `localAddresses` | `replace`에서 새로 적용하는 규칙 원문과 자기 주소. 빈 규칙 `"[]"`도 교체다 |
| `conversionError` | 선택 사항. `replace`에서 실제 Go 변환 오류 |
| `swiftailDiffers` | 선택 사항. Go 판정과 별개로 M3 계약을 확인해야 하는 이유. 값이 같아도 의도한 처리 경계가 다르면 표시한다 |
| `swiftailExpected` | 차이 표시와 함께 존재하는 Swift 계약 기대값. 아래 표 참조 |

| `swiftailExpected` | Swift 시험이 확인하는 것 | 단계 수 |
| --- | --- | --- |
| `fragment` | `IPPacket.ParseError.fragment` | 7 |
| `extensionHeader` | `IPPacket.ParseError.extensionHeader` | 8 |
| `malformed` | `IPPacket.ParseError.malformed`(IHL 4, 선언 길이 밖의 UDP 머리) | 3 |
| `accept`, `drop` | 해석 성공 후 `checkInbound` 판정. `cap:` 항목만 제거, ICMPv4 type 12·18의 차이 | 12 |
| `trimmedAccept` | 선언 길이로 자른 바이트와 허용 판정을 함께 확인 | 2 |
| `tsmp` | `.tsmp` 해석을 확인. 엔진에서 소비하는 동작은 이 필터 시험의 API 범위 밖 | 2 |

전체는 **91개 시나리오·2,429개 단계**(수신 333개·송신 2,058개·교체 38개),
차이 표시 **34개**다. IPv4·IPv6에 각각 아래 공통 43개 시나리오를 둔다.
각 행은 자료의 시나리오 이름을 묶은 것이며, 별도 명시한 개수만큼 각각 독립된 필터를 만든다.

| 공통 시나리오 이름·목록 | 계열당 개수 |
| --- | --- |
| 출발지 전체·CIDR·단일 주소·양끝 포함 범위 | 4 |
| 프로토콜 6 포트 범위·프로토콜 17 포트 범위·포트 전체와 역순 범위 | 3 |
| 기본 프로토콜 빈 배열·null, TCP만·UDP만·ICMP만·기타 47만·기타 254만, 범위 밖 번호만·범위 밖 번호와 UDP | 9 |
| 기타 프로토콜은 포트 전체만·명시 프로토콜 번호 경계·SCTP 번호 132의 특별 취급·IPProto 생략 | 4 |
| 호스트 비트 CIDR·해석 불가 주소·역순 주소 범위 각각의 출발지와 목적지(오류 항목만/유효 항목 추가) | 6 |
| SrcBits 전체 닫힘·DstPorts.Bits 전체 닫힘(넓은 이전 규칙과 교체 포함) | 2 |
| CapGrant만으로 열리지 않음·TCP 플래그와 무상태 허용 | 2 |
| UDP 역방향 튜플·수신 허용은 흐름을 만들지 않음·규칙 교체와 흐름 유지 | 3 |
| UDP LRU 513개 조회갱신=false·true | 2 |
| ICMP 응답과 오류는 무상태·ICMP는 프로토콜과 포트 무시 | 2 |
| 목적지 자기 주소 검사·multicast와 link-local 목적지(자기 주소로 등록한 경우도 거절) | 2 |
| cap 출발지는 항목만 버림·TSMP는 엔진 제어 패킷 | 2 |
| 선언 길이 뒤의 바이트·선언 길이 밖의 전송 머리 | 2 |

추가로 IPv4에는 조각(MF·오프셋 1·10), IHL 최솟값, ICMPv4 type 18의 주소 규칙을
각각 한 시나리오로 둔다. IPv6에는 조각(atomic·첫 조각·오프셋 1·10)과 확장 헤더
(0·43·50·51·60·135·139·140)를 각각 한 시나리오로 둔다. 따라서 IPv4 46개·IPv6 45개다.
UDP 튜플 시험은 목적 주소만 다른 입력도 자기 주소에 포함하여 `notForUs`가 캐시 비교를
가리지 않게 한다. LRU는 512개 삽입 뒤 513번째를 넣는 경우와, 그 직전에 흐름 0을 조회하는
경우를 분리하여 FIFO와 조회 순서 갱신을 구별한다.

실행 결과가 드러낸 **계약의 누락**은 다음과 같다. 의도한 M3 차이로 합의된 항목이 아니므로
`swiftailDiffers`를 달지 않아 대조 시험이 불일치를 드러내게 했다.

- 와이어 프로토콜 0·255는 명시적인 전체 포트 규칙으로도 Go가 거절한다. 0은 Unknown이고
  255는 파서가 Unknown으로 바꾼다. 계약의 0…255와 “그 밖의 프로토콜” 문구에는 이 예외가 없다
  (`net/packet/packet.go:243-248`, `:359-364`). IPv6의 0은 이미 확장 헤더 차이로 따로 표시한다.
- SCTP(132)는 Go에서 UDP와 같은 포트 판정·송신 역방향 캐시를 쓴다. 계약은 SCTP를 별도
  프로토콜로 두지 않으며 UDP만 기록한다고 명시한다. 따라서 일부 포트만 여는 규칙과
  규칙 없는 응답의 Go 허용 판정은 계약만으로 재현되지 않는다
  (`wgengine/filter/filter.go:538-550`, `:600-612`, `:642-650`).

두 동작은 노트 3.2·4.5·4.6에는 이미 적혀 있다. 그 밖에 노트와 다른 새 Go 동작은 찾지 못했다.
또한 `IPProto`가 전부 범위 밖이어도 주소 규칙이 남으면 ICMP 요청은 허용된다.
이는 ICMP에서 프로토콜·포트를 무시하는 노트 4.4와 일치한다.

Swift 대조 시험은 `IPPacket(parsing:)`, `bytes`, `transportProtocol`, `ParseError`,
`PacketFilter(rules:localAddresses:)`, `checkInbound`, `recordOutbound`,
`replaceRules(_:localAddresses:)`, `Verdict.accept`에만 의존한다(`@testable` 없음).
구현이 없는 worktree에서 작성하여 시험 타깃의 컴파일·실행은 하지 않았다.
병합 뒤 총괄이 계약 시그니처와 실제 구현의 일치를 확인해야 한다.
TSMP의 `TailnetEngine.receive` 소비, 실제 WireGuard·AllowedIPs·DERP 경로, 시간 경과는
이 값 타입 필터 대조에서 확인하지 않는다. UDP 캐시는 Go와 계약 모두 TTL이 없다.

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
