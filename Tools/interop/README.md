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

## M6 TCP 전송 명령

모든 명령은 기존 JSON 줄 규약대로 `id`를 받고 같은 `id`로 곧바로 답한다. `peerDial`의 연결·전송과 `peerServe`의 accept·전송은 뒤에서 돌며 표준 출력에 비동기 사건을 쓰지 않는다. 진행은 `transfers`로 조회한다. 피어는 먼저 `addPeer`로 만든다.

```json
{"id":1,"cmd":"peerServe","name":"go-peer-b","port":9100,"timeoutSec":60}
{"id":2,"cmd":"peerDial","name":"go-peer-a","to":"100.64.0.2","port":9100,"send":104857600,"seed":1,"timeoutSec":60}
{"id":3,"cmd":"transfers"}
{"id":4,"cmd":"peerClose","name":"go-peer-b","port":9100}
```

- `peerServe`: `name`, `port`(1…65535), 선택 `timeoutSec`. 응답은 `{"id":1,"event":"peerServe","name":"go-peer-b","port":9100}`다. 같은 피어에서 여러 포트를 들을 수 있고 중복 포트는 오류다. 연결마다 아래 16바이트 머리를 읽어 송신 길이·씨앗을 정한다.
- `peerDial`: `name`, `to`(zone 없는 IPv4·IPv6 리터럴), `port`, `send`(0…4294967296의 정수), `seed`(0…18446744073709551615의 정수), 선택 `timeoutSec`. `send`·`seed`는 필수이며 null을 허용하지 않는다. 응답은 `{"id":2,"event":"peerDial","name":"go-peer-a","transferID":1}`다. 연결 거절·전송 실패는 이 응답 이후 전송 기록의 `error`로 나타난다. UInt64 씨앗은 부동소수점으로 읽지 않는다.
- `transfers`: `{"id":3,"event":"transfers","transfers":[...]}`. 선택 `name`은 피어 이름 필터다. 빈 목록은 `[]`, 순서는 시작 순서다. 항목은 `transferID`(프로세스 안에서 1부터 증가), `name`, `remote`(IP:port, IPv6는 대괄호), `sent`, `sentSHA256`, `received`, `receivedSHA256`, `elapsedMs`, `error`, `state`를 항상 가진다. `state`는 `dialing`, `running`, `complete`, `error`다. 미완료 중에도 누적 바이트와 그 구간의 해시를 읽을 수 있다. 해시는 소문자 hex이며 빈 흐름은 SHA-256(empty)다. `remote`는 Dial 시작 때 목적지, accept 쪽은 머리를 다 읽은 뒤 실제 원격 주소가 된다(그전에는 빈 문자열). `elapsedMs`는 Dial 시작 또는 Accept부터의 경과 시간이다. 정상은 빈 `error`, 실패는 원래 Go 오류를 감싼 문장이다. 완료 기록은 피어·리스너를 닫아도 프로세스 종료까지 남는다.
- `peerClose`: `name`, `port`. 그 리스너만 닫고 `{"id":4,"event":"peerClose","name":"go-peer-b","port":9100}`로 답한다. 이미 받은 연결은 계속되며 포트는 다시 열 수 있다. 없는 리스너는 오류다. `removePeer`·`quit`·EOF는 관련 리스너·연결·진행 중 Dial을 취소하고 goroutine을 회수한다.

`timeoutSec`는 생략 또는 null이면 15, 지정하면 1…3600의 정수다. Dial은 연결 시작부터, accept는 연결을 받은 때부터 머리·양방향 전송 전체에 한 번 적용한다. 리스너 자체에는 기한이 없다. `peerClose`는 기한이 필요 없다.

### 전송 바이트 규약

연결을 건 쪽만 먼저 16바이트를 쓴다: 처음 8바이트는 **듣는 쪽이 보낼 바이트 수 UInt64 big endian**, 다음 8바이트는 **듣는 쪽이 쓸 씨앗 UInt64 big endian**이다. ACK나 응답 머리는 없다. Go `peerDial`은 자기 `send`·`seed`를 이 머리에도 넣으므로 두 방향이 같은 길이·씨앗으로 전송된다. Swift가 걸 때는 자기 송신 길이·씨앗을 독립적으로 골라도 된다. 머리가 잘렸거나 요구 길이가 4GiB를 넘으면 해당 전송은 오류로 끝난다.

머리 뒤에는 각자 별도 쓰기 흐름과 읽기 흐름을 동시에 돌린다. 쓰기는 정한 길이의 데이터를 보낸 뒤 `CloseWrite`(FIN)하고, 읽기는 상대의 EOF까지 계속한다. **16바이트 머리는 양쪽의 바이트 수와 해시에서 제외한다.** 받은 데이터의 길이나 내용은 자동으로 같은 값이라고 가정하지 않는다. 시험 호출자가 상대의 `sent`/`sentSHA256`과 자기의 `received`/`receivedSHA256`을 교차 비교한다. 서로 다른 길이의 반닫힘도 같은 규약으로 검증할 수 있다.

가짜 난수 흐름은 운영 암호용이 아닌 공개 시험용 **LCG64**다. 상태는 `x₀ = seed`(UInt64), `xₙ₊₁ = (6364136223846793005 × xₙ + 1442695040888963407) mod 2⁶⁴`. 매 갱신 뒤의 `xₙ₊₁`을 **little endian 8바이트**(최하위 바이트 먼저)로 내보낸다. 필요한 길이에서 마지막 낱말을 자른다. 읽기·쓰기 청크 경계와 무관하게 남은 낱말 바이트를 이어 쓴다. 씨앗 0도 그대로 허용한다. Swift는 `&*`·`&+`로 같은 순환 산술을 쓸 수 있다. 씨앗 1의 처음 32바이트는 다음과 같다.

```text
7c00fd43ac6f576c1b1b4a86b38668820eaa972099e1faa5c5579311cd550362
```

이 32바이트의 SHA-256은 `d96bbb8821f933a5b368b9c127d725ed65b2d2f89f5b6d4505545306e834537d`다. 전송마다 32KiB 송신 버퍼와 32KiB 수신 버퍼, SHA-256 상태만 유지하므로 100MiB 이상도 전체 데이터를 보관하지 않는다.

공개 nodeKey를 반복 기록하는 testcontrol 기본 등록 로그도 끈다.

Go 쪽 손실·지연 주입 명령은 없다. M6 관문 8·9는 계약의 Swift `setInProcessLoss(rate:seed:)`를 쓴다. `addKernelPeer`는 **아직 없음**이다.

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

# magicsockvectors

`SwiftailMagicsock` 단위 시험의 고정 벡터를 `tailscale.com` v1.104.6의 공개 패키지(`disco`, `types/key`, `net/stun`)와 `golang.org/x/crypto/nacl`로 만들어 `Tests/SwiftailMagicsockTests/Fixtures/magicsock-vectors.json`에 쓴다. Swift 구현은 읽거나 실행하지 않는다. 키는 `SHA-256("swiftail-vectors/disco/<번호>")`(1, 2)를 X25519 개인 키 입력으로 쓰는 시험용 공개 값이고 nonce는 메시지 번호에서 정해진다. 시각·난수·운영 값이 없어 같은 입력이면 출력이 바이트 단위로 같다. 빌드 정보에서 기준 버전과 replace 부재를 확인한다.

저장소 루트에서 실행한다. `interop-tools`·`ref-src`는 지우지 않는다.

```sh
export GOCACHE="$(eyebuild dir interop-tools)/gocache"
export GOMODCACHE="$(eyebuild dir ref-src)/gomod"
export GOFLAGS=-modcacherw GOPROXY=off GOSUMDB=off
(cd Tools/interop && go vet ./... && go run ./cmd/magicsockvectors ../../Tests/SwiftailMagicsockTests/Fixtures/magicsock-vectors.json)
```

출력 파일을 주지 않으면 표준 출력에 쓴다. 담는 것:

- `keys`: 시험용 disco 키 `a`, `b`의 `seed`(개인 키 입력)와 `public`.
- `disco.messages`: Ping(NodeKey 있음·없음·패딩), Pong(IPv4·IPv6), CallMeMaybe(주소 0·1·3개)의 `plaintext`(`AppendMarshal` 바이트)와, 같은 평문을 `box.Precompute` + `secretbox.Seal`(고정 `nonce`)로 봉한 겉 형식 전체 `packet`. 도구는 `packet`을 `key.DiscoPrivate.Shared(...).Open`으로 다시 열어 평문과 같은지, `disco.Source`가 보낸 쪽 키를 돌려주는지 확인한 뒤에 쓴다. Go의 `Seal`은 nonce를 안에서 뽑아 고정 nonce 봉인은 같은 계산을 직접 부른다.
- `disco.parse`: 경계 평문(0·1바이트, Ping 11·12·13·43·44·45바이트와 0 NodeKey, Pong 29·30·31바이트, CallMeMaybe 17·18·19·35·36바이트와 version 1, 종류 0x00·0x04–0x09·0x0a·0xff)을 `disco.Parse`에 넣은 결과. 해석되면 `result`, 아니면 Go의 오류 문장이 `error`다. `kind: "relay"`는 Go가 해석하지만 Swiftail은 해석하지 않는 종류(0x04–0x09)다.
- `stun.requests`: `stun.Request(txID)`의 바이트.
- `stun.parse`: `stun.Response`로 만든 IPv4·IPv6 응답과 손으로 바꾼 응답(0x8020, MAPPED-ADDRESS만, 속성 앞 SOFTWARE, 선언 길이 뒤의 바이트, 거절 사례)을 `stun.ParseResponse`에 넣은 결과와, 같은 패킷이 `looksLikeSTUN`(`stun.Is`와 바이트 1이 `0x01`)인지.

# MagicDNS 기준 자료 생성 (`dnsfixtures`)

`tailscale.com v1.104.6`의 실제 UDP 응답 바이트를 `Tests/SwiftailEngineTests/Fixtures/magicdns-fixtures.json`에 쓴다. Swift 파일은 바꾸지 않는다. 아래 환경은 두 도구와 전체 Go 검증에 공통이다. 기준 모듈은 `Scripts/fetch-reference-sources.sh`로 미리 받아 두어야 한다.

```sh
export GOCACHE="$(eyebuild dir interop-tools)/gocache"
export GOMODCACHE="$(eyebuild dir ref-src)/gomod"
export GOFLAGS=-modcacherw
export GOPROXY=off
export GOSUMDB=off
(cd Tools/interop && go run ./cmd/dnsfixtures ../../Tests/SwiftailEngineTests/Fixtures)
```

`sh Scripts/build-interop-tools.sh dnsfixtures`로 빌드한 실행 파일도 같은 환경에서 `dnsfixtures <Engine Fixtures 폴더>`로 실행한다. 인자는 필수이며 파일 이름은 고정이다.

호출 경로는 `resolver.New` → `SetConfig(Hosts, LocalDomains)` → `SetMagicDNSHosts` → 단계별 `Query(context, query, "udp", 100.64.0.1:42001)`다(`net/dns/resolver/tsdns.go`). 응답 생성·타입 선택·RCODE·SOA·EDNS·TC 로직은 복제하지 않는다. 내보내지 않은 `ipnlocal`의 노드 색인은 계약대로 고정 표로 대신한다. `nodes[].addresses`는 PTR용 원래 주소, `answerAddresses`는 D7에 맞춰 미리 정한 정방향 주소, `aliases`는 인식할 FQDN·짧은 이름이다. 주소 없는 노드는 별칭을 넣지 않는다. `subdomain`도 명시적 시험 표다. 이 자료로 색인 구현 자체의 정확성을 입증할 수는 없다.

SOA의 현재 시각을 자료에 넣지 않기 위해 `mapfixtures`와 같이 모듈의 임시 복사본에 `-overlay`로 작은 bridge를 넣고, upstream의 시험용 `timeNow` hook만 `1767323045`(고정 Unix 초)로 설정한다. 응답 바이트는 그 뒤 `Query`가 돌려준 그대로다. 모듈 캐시는 읽기만 하고 임시 모듈 복사본·bridge·worker·overlay·modfile·sum은 성공·실패 뒤 모두 지운다. 임시 파일은 `interop-tools` 아래에만 둔다.

자료 머리는 `reference`, `scenarioCount: 8`, `stepCount: 85`, `soaSerial: 1767323045`, `scenarios`다. 각 시나리오는 `name`, `magicDNSSuffix`(끝 점 포함), `proxied`, `capabilities`, `nodes`, `localDomains`, `hosts`, `steps`를 가진다. `hosts`는 Go `Config.Hosts`로 줄 ExtraRecords 표다.

단계의 키:

| 키 | 뜻 |
| --- | --- |
| `name` | 질의의 목적 |
| `query`, `response` | UDP DNS 메시지 전체의 소문자 hex. IP·UDP 머리는 없음 |
| `decoded.id`, `rcode`, `flags` | 응답 ID, 숫자 RCODE, 16비트 머리 플래그 |
| `decoded.qr/aa/tc/rd/ra` | 자주 비교하는 머리 비트. Opcode·AD·CD 등은 `flags`로 비교 |
| `decoded.questions` | `name`·숫자 `type`·`class`의 배열. 응답의 첫 질문 또는 빈 배열 |
| `decoded.answers/authorities/additionals` | `type`·`name`·`class`·`ttl`·`value`의 배열. 이름은 끝 점 포함 |
| 레코드의 `value` | A·AAAA는 주소 문자열, PTR은 FQDN, SOA는 `ns/mbox/serial/refresh/retry/expire/minimum` 객체 |
| `swiftailDiffers` | 계약에 근거한 의도적 차이의 이유. 없으면 Go 결과를 그대로 비교 |

Swift 대조 시험은 고정 시각을 넘겨 전체 hex를 비교하거나, 계약대로 SOA SERIAL 필드만 비교에서 빼면 된다. 질의 이름의 끝 점 유무는 wire에서 구별할 수 없다. 끝 점 없이 만든 입력도 같은 절대 DNS 이름으로 인코딩한다. `decoded`의 질문·레코드 이름은 Go가 만든 응답의 실제 대소문자를 보존한다. 빈 목록은 `[]`다.

시나리오 목록:

1. 기본 노드·질의 형식(61단계): self·피어·IPv4 전용·IPv6 전용의 A/AAAA/ANY, IPv4·IPv6·4to6·서비스 PTR, 표기 차이, 모르는 이름·PTR, 주소 없는 노드, 영역 밖, onion·Bonjour, TXT/MX/NS/SOA/AXFR/HINFO/미지 타입, 서비스 이름, 머리 비트, 질문 0·2개, 정상 압축·고리·11회 초과 포인터, 잘림·잘못된 레이블·FQDN, EDNS.
2. `magicdns-aaaa` 능력 있음(3단계).
3. 자기가 IPv6 전용(4단계).
4. MagicDNS 끔(3단계).
5. ExtraRecords 우선과 역방향(3단계).
6. 자기 키 만료 또는 netmap 없음(4단계): 빈 표·빈 영역과 서비스 이름/PTR 예외.
7. 긴 로컬 영역의 큰 SOA 응답(4단계): 512 초과, EDNS 1232·512, 옵션 있는 OPT. 512바이트 초과와 TC 결과를 자체 검사한다.
8. M5 제외 4via6와 서브도메인(3단계).

`swiftailDiffers`는 마지막 시나리오의 **3단계**다: 4via6 이름 생략 2개, `dns-subdomain-resolve` 생략 1개(동작 D8·제외). 상위 전달은 설정하지 않아 영역 밖 질의는 Go의 “라우트 없음” SERVFAIL이며, Swiftail과 차이가 없으므로 표시하지 않는다.

관찰된 계약의 빈틈: 동작 D7은 자기 키 만료·netmap 없음에서 “모든 이름이 SERVFAIL”이라고 하지만, Go는 빈 색인·빈 `LocalDomains`에서도 `magicdns.localhost-tailscale-daemon.`의 A와 서비스 IPv4 PTR에 정상 응답한다. 두 단계에는 의도적 차이 표시를 달지 않았다. 서비스 응답은 색인보다 먼저 처리된다(`resolveLocal`, `resolveLocalReverse`). 노트의 서비스 특수 처리 규칙과는 맞는다.

# 터널 설정 기준 자료 생성 (`tunnelfixtures`)

같은 환경에서 실행한다.

```sh
(cd Tools/interop && go run ./cmd/tunnelfixtures ../../Tests/SwiftailEngineTests/Fixtures)
# 또는 sh Scripts/build-interop-tools.sh tunnelfixtures 로 빌드한 뒤:
# tunnelfixtures <Engine Fixtures 폴더>
```

출력은 `tunnel-settings-fixtures.json`이다. Go의 원본 결과와 계약 S의 형태로 좁힌 결과를 함께 보존한다.

- 경로: 공개 `routemanager.New` → `Begin` → `SetPrefs(RouteAll:false, exit node 없음)` → `SetTailnetConfig` → `UpsertPeer` → `Commit` → `OSRoutes().All()`을 정렬한다. `controlknobs.UpdateFromNodeAttributes`로 `one-cgnat?v=true/false`를 해석한다. 모르는 제어 지시를 직접 해석하지 않는다.
- DNS·로컬 주소·서비스 경로: upstream LocalBackend 시험의 방식대로 메모리 store·fake TUN 엔진을 가진 Go 노드 하나를 만든다. 임시 복사본의 `ipn/ipnlocal`에 overlay bridge를 더해, 고정 netmap과 prefs를 넣고 실제 `LocalBackend.authReconfigLocked`를 실행한다. `Engine`을 포함한 캡처 타입이 `Reconfig`만 가로채 `dns.Config`와 `router.Config`를 받는다. 내보내지 않은 `dnsConfigForNetmap`·`routerConfigLocked`의 산출 로직을 옮겨 적지 않는다. 제어 서버 연결과 실제 OS 설정 적용은 하지 않는다.
- 캡처한 `dns.Config`는 공개 `dns.NewManager(..., goos:"ios")` → `Set`으로 컴파일한다. `OSConfigurator`는 `SupportsSplitDNS=true`, `GetBaseConfig`는 고정 가짜 기본 리졸버 `192.0.2.54`를 반환하고 `SetDNS`는 값을 받기만 한다. `Resolver.TestOnlySetHook`으로 실제 `LocalDomains`를 받는다. 기본 리졸버가 필요한 1차 모드에서도 호스트 OS의 DNS를 읽지 않는다.
- `router.Config.LocalAddrs`·서비스 경로는 Go가 만든 그대로 받는다. 공개 RouteManager의 피어 경로에 자기 주소 계열별 서비스 경로를 붙인 결과가 캡처한 전체 Go 경로와 같은지 자체 검사한다.
- `settings`에는 S1·S4·S5와 D1~D3의 정책만 적용한다: 자기 주소가 없으면 `null`, 자기 주소가 없는 계열의 경로·DNS 서버 제외, Go에서 받은 `LocalDomains`만 DNS match로 사용, 검색 도메인·전역 리졸버·리졸버 있는 Routes를 설정에 넣지 않음. DNS 로컬 영역을 도구가 다시 산출하지 않는다. 의도적 차이 표시가 없는 만료 경계도 Go 값을 그대로 남긴다.

두 번째 도구도 임시 복사·overlay·modfile을 종료 시 지우며, 기준 모듈의 버전·replace 유무를 검사한다. `TS_DEBUG_MAGIC_DNS_DUAL_STACK=false`를 프로세스 시작 때 고정해 외부 환경이 IPv4-only 지시를 덮지 않게 한다. 시험 노드의 로그 업로드·portmapper도 끈다. 현재 시각이나 생성한 신원·소켓 주소는 자료에 싣지 않는다.

자료 머리는 `reference`, `scenarioCount: 27`, `stepCount: 32`, `now: "2026-01-02T03:04:05Z"`, `baseResolvers`, `scenarios`다. 시나리오마다 `name`, `steps`가 있다. 각 단계는 독립된 전체 netmap 입력이다. 이전 단계에 대한 delta가 아니다.

| 키 | 뜻 |
| --- | --- |
| `input.self`, `input.peers` | `id/name/addresses/allowedIPs/expired/keyExpiry/homeDERP`. 주소는 CIDR 문자열. disco 키는 없고, `homeDERP`가 데이터면 후보 여부를 결정한다. 시험 공개 키는 ID에서 고정 생성하며 출력하지 않음 |
| `input.dnsConfig` | 제어의 `tailcfg.DNSConfig` JSON. Go의 원래 대문자 키(`Proxied`, `Routes`, `Resolvers`, `Domains`, `ExtraRecords` 등)를 보존 |
| `input.capMap` | 자기 노드의 제어 capability map |
| `input.routeAll`, `exitNode` | 각각 고정 `false`, 빈 문자열 |
| `input.selfExpired` | LocalBackend에 주는 키 만료 스냅샷. 도구는 실행 시각으로 만료를 다시 판단하지 않음 |
| `input.mtu` | 계약 설정으로 옮길 MTU(1280) |
| `go.addresses` | Go `router.Config.LocalAddrs` |
| `go.peerRoutes`, `go.routes` | 공개 RouteManager의 정렬된 피어 경로, LocalBackend가 서비스 경로까지 붙인 원본 경로 |
| `go.dns` | iOS OSConfig의 `servers/matchDomains/searchDomains`와 실제 리졸버의 `localDomains`. 도메인은 끝 점을 뗀 문자열 |
| `go.dnsConfig` | 엔진이 받은 원본 `dns.Config`. Go 구조체 키와 끝 점 포함 FQDN을 보존. 선택 필드의 `null`도 원본 그대로 |
| `settings` | 계약 형태의 `addresses/routes/dnsServers/dnsMatchDomains/mtu`, 또는 자기 주소가 없으면 `null` |
| `swiftailDiffers` | 원본 Go 설정을 그대로 비교하면 안 되는 계약상의 의도적 차이 |

Swift 대조 시험은 `input`으로 netmap을 만들고 `settings`를 비교한다. 다만 아래의 **표시 없는 관찰 차이**는 계약 보완 여부를 먼저 확인해야 한다. Go 원본을 조사할 때는 `go`를 본다. Go `dnsConfig`의 `null`과 달리 정규화한 출력 목록은 항상 `[]`이며, IPv4 경로가 IPv6보다 먼저다. Go의 서비스 경로는 정렬된 피어 경로 뒤에 IPv4·IPv6 순서로 온다. `settings`에서 빠진 검색 도메인은 `go.dns.searchDomains`에 보존된다.

시나리오 목록(OneCGNAT만 6단계, 나머지는 각 1단계):

- IPv4만·IPv6만·둘 다 × 피어 0·1·3(9개): 자기 주소, 피어별 경로, 계열 필터, 서비스 경로, MagicDNS와 검색 도메인.
- 검색 도메인 없는 IPv4 피어, ULA 한 피어의 /48 집계(2개).
- OneCGNAT 문턱과 제어 지시(1개, 6단계): 지시 없음·true·false × CGNAT 피어 1·2. true일 때 1개는 /32, 2개는 /10. 기본 10,000 경계 대신 계약이 허용한 문턱 1로 경계만 확인한다.
- 만료 피어, 지난 KeyExpiry와 Expired false, disco·DERP 없는 피어, 서브넷·exit 광고 거절(4개).
- MagicDNS 끔, 접미사 없음, 빈 Routes, 사용자 지정 분할 DNS, 전역 리졸버, 전역 리졸버만 있음(6개).
- 덮이지 않은 ExtraRecords, 사용자 라우트가 ExtraRecords를 덮음, IPv4 DNS만 등록 지시, 자기 키 만료, 자기 주소 없음(5개).

`swiftailDiffers`는 **16단계**다. 중복을 포함한 근거별 수는 검색 도메인 생략(D3) 10개, 자기 주소 계열 필터(S4·S5) 5개, 1차 DNS·전역 리졸버·사용자 분할 DNS를 로컬 match로 좁히기(D1·D2) 5개, 자기 주소 없음에서 설정 생략(S1) 1개다. 한 단계에 여러 근거가 있을 수 있다.

관찰된 차이·주의점:

- `Expired=false`이고 `KeyExpiry`가 고정 `now`보다 과거인 피어도 Go RouteManager와 LocalBackend 경로에 남는다. RouteManager는 `Expired`만 검사한다(`peerViewOf`). 계약 S2가 참조하는 `EnginePeer.peers(in:at:)`의 시간 검사와 다르며, 이를 의도적 차이로 정한 계약은 없어 **표시하지 않았다**. 이 단계의 `settings`에도 Go 경로를 보존했다.
- 자기 `Name`이 비면 Go `magicDNSRootDomains`는 역방향 영역까지 전부 생략한다. 계약 S5 요약을 읽을 때 `Proxied`만으로 역방향 65개를 항상 더한다고 해석하지 않아야 한다. DNS 노트의 출처 함수가 가진 접미사 검사다.
- MagicDNS 끔·Routes 없음·전역 리졸버 없음은 `MagicDNSHostsUnrouted=true`여도 `needsOSResolver`의 이른 반환으로 네임서버가 없다. 빈 Routes 하나가 있으면 같은 flag 때문에 Go가 1차 모드를 고른다. flag의 설명만 보고 항상 1차 모드라고 추론하면 안 된다.

# 두 자료의 재현·회귀 검증

저장소 루트에서 위 공통 환경 변수를 설정한 뒤 실행한다. `go test`는 두 새 도구의 embedded worker·bridge도 실제로 컴파일·실행해 저장 자료와 바이트 단위로 비교한다. `dnsfixtures`는 각 질의의 RCODE와 큰 응답의 길이·TC도 검사한다.

```sh
(cd Tools/interop && go vet ./... && go test -count=1 ./...)
check_dir=$(mktemp -d "$(eyebuild dir interop-tools)/m5-fixture-check.XXXXXX")
(cd Tools/interop && go run ./cmd/dnsfixtures "$check_dir/first")
(cd Tools/interop && go run ./cmd/dnsfixtures "$check_dir/second")
(cd Tools/interop && go run ./cmd/tunnelfixtures "$check_dir/first")
(cd Tools/interop && go run ./cmd/tunnelfixtures "$check_dir/second")
cmp "$check_dir/first/magicdns-fixtures.json" "$check_dir/second/magicdns-fixtures.json"
cmp "$check_dir/first/tunnel-settings-fixtures.json" "$check_dir/second/tunnel-settings-fixtures.json"
rm -r "$check_dir"
eyebuild swift m5-fixtures -- build --build-tests 2>&1 | grep -E "warning|error"; echo build-done
eyebuild rm m5-fixtures
```

실기기 OS 적용, 실제 Go 피어에 대한 이름 질의, Swift 대조 시험은 이 도구의 검증 범위가 아니다. 노드 색인 규칙은 고정 표이므로 별도 단위 시험과 M5 관문 (가)에서 검증한다.

M5 메모리 관문의 관측 명령:

- `startCapture`(`name`): 해당 Go 피어의 공개 `StreamDebugCapture`를 시작하고 pcap 머리를 읽은 뒤 `captureStarted`로 답한다. 피어당 한 번만 시작하며 피어 제거·도구 종료 때 닫는다.
- `captureStatus`(`name`, `port` 1…65535): `FromPeer` 패킷 중 목적지가 두 서비스 IP인 수(`servicePackets`)와 UDP 출발 포트가 `port`인 수(`observedPackets`)를 반환한다. 원문·주소는 보관하거나 출력하지 않는다. 일반 UDP 에코의 관측을 양성 대조로 삼고, 후속 에코가 관측될 때까지 기다려 읽기 경계를 확인한다. 관측 흐름 종료·잘못된 경계는 오류다.
- `networkStatus`: `controlConnections`(`/ts2021` 요청 수), `derpConnections`(`/derp` 요청 수), `stunRequests`(유효 STUN Binding 요청 수)를 반환한다. 인터페이스 재결속·같은 인터페이스 재평가를 주소 없이 관측하기 위한 프로세스 전체 누적 수다.

- `setMagicDNS`(`enabled` bool): 첫 제어 요청 전에 `DNSConfig.Proxied`를 설정하고 `magicDNS`로 답한다. `MagicDNSDomain`은 이름 접미사만 정하므로 DNS 관문은 이 명령으로 MagicDNS를 켠 뒤 피어·Swift 노드를 등록한다. 누락된 bool·등록 뒤 변경은 거절한다.

# TCP 세그먼트 기준 자료 생성 (`tcpfixtures`)

고정 gVisor `v0.0.0-20260915211658-a6f909f08a72`의 `pkg/tcpip/header`·`checksum` 공개 API를 호출한다. `IPv4.Encode`·`IPv6.Encode`·`TCP.Encode`·옵션 인코더로 패킷을 만들고 `TCPValid`·`ParseSynOptions`로 읽는다. Swift 구현은 읽거나 부르지 않는다. 바이트 변형은 잘못된 경계를 만들 때만 한다. 네트워크·난수·시각을 사용하지 않는다.

```sh
fixture_tool="$(sh Scripts/build-interop-tools.sh tcpfixtures)"
"$fixture_tool" Tests/SwiftailNetstackTests/Fixtures
```

인자는 필수 폴더이며 `tcp-segments.json`을 쓴다. 자료 머리는 `reference`, `caseCount: 49`, `cases`다. 사례는 `name`, `packet`(IP 머리를 포함한 소문자 hex), `go`, `swiftail`, 선택 `swiftailDiffers`다. `go`는 실제 Go 반환값, `swiftail`은 W2·T5·X9에서 의도적으로 정한 차이만 적용한 기대값이다. 차이가 없으면 두 객체가 같다.

각 결과의 키:

| 키 | 뜻 |
| --- | --- |
| `error` | 성공은 빈 문자열, 실패는 `malformed`, `badChecksum`, `notTCP`. gVisor의 bool 결과를 도구가 정규화한 이름이며 Go 오류 문자열이 아님 |
| `ipChecksumValid` | IPv4 머리 체크섬. IPv6 또는 검사 전 잘림이면 null |
| `checksumValid` | TCP 체크섬. data offset 등 구조를 읽을 수 없으면 null |
| `decoded` | TCP 구조를 읽었으면 해석 객체. 체크섬 오류에서도 진단용으로 남기며 `error`가 있으면 수용할 패킷이 아님. 머리를 읽을 수 없으면 null |

`decoded`에는 `ipVersion`, `source`, `destination`, `ipHeaderLength`, `sourcePort`, `destinationPort`, `sequenceNumber`, `ackNumber`, `flags`(8비트 원값), `window`(와이어의 16비트 원값), `tcpHeaderLength`, `optionsHex`, `mss`, `windowScale`, `dataLength`가 있다. `mss`는 SYN의 **유효 MSS**로 옵션 생략 시 기본값도 포함한다(Swift 코덱의 `maximumSegmentSize`는 옵션이 없으면 nil이고, 기본값은 연결 상태 기계가 계약 T5로 채운다. 대조 시험은 nil을 기본값으로 읽어 견준다). `windowScale`은 SYN에서 옵션 없으면 -1이며, SYN이 아니면 MSS·WS 모두 null이다. data offset 길이는 바이트 단위다. `swiftail.error`가 `malformed`인 사례의 `decoded`는 Go가 읽은 진단 값이며 성공한 Swift 해석을 뜻하지 않는다.

49개 사례:

- 각 IPv4·IPv6에 SYN(MSS·WS), SYN-ACK, 홀수 길이 데이터, 반복 올림 체크섬, FIN-ACK, RST, SYN 아닌 MSS·WS, 옵션 생략, MSS 0, shift 15, 틀린 체크섬(22개).
- IPv4 옵션, NOP로 어긋난 정렬, EOL 뒤 잘못된 바이트 무시, 모르는 옵션, SACK·timestamp와 MSS·WS 조합, shift 14, 최대 60바이트 TCP 머리, 작은 MSS 1(8개).
- 옵션 길이 0·1·머리 밖, 마지막 옵션 길이 필드 누락, MSS 본문 잘림(5개. 계약은 `malformed`), MSS 길이 3·WS 길이 2(2개. 계약도 gVisor처럼 값을 읽지 않고 건너뛴다).
- TCP 0·1·19바이트, IP 0·1·19·39바이트 잘림(7개).
- data offset 4·6·15(세그먼트 밖), 16을 넣으면 4비트가 0으로 순환하는 사례(4개). 와이어에는 16을 담을 수 없다.
- 프로토콜이 TCP가 아닌 IPv4(1개).

`swiftailDiffers`는 **11개**다: IPv6 기본 MSS(Go 536, 계약 1220) 1개, MSS 0에서 Go가 옵션 해석을 중단하여 뒤 WS를 무시하는 사례 2개(IPv6 MSS도 536), 작은 MSS(Go 48, 계약 코덱 1) 1개, 옵션 오류에서 Go가 앞부분만 반환하지만 계약은 `malformed`로 버리는 7개다. 작은 MSS는 코덱에서 올리지 않고 연결 상태 기계가 X9에 따라 64 미만을 거절한다. shift 15는 양쪽 모두 14로 읽으므로 차이 표시가 없다. 일반 `ParseTCPOptions`에 MSS·WS가 없다는 사실을 SYN 옵션의 동작 차이로 표시하지 않는다.

다음 검증은 저장 자료와 재생성 결과의 바이트 일치·연속 실행의 재현성, gVisor 접근자 경계의 결정적인 임의 바이트 1만 입력, 새 명령의 경계 입력·JSON `id`·빈 목록·제어 머리 오류, 실제 tsnet 피어 둘의 양방향 100MiB와 IPv6 동시 전송·빈 전송·3바이트 대 1MiB의 비대칭 반닫힘·연결 거절·취소를 확인한다. 임의 입력 시험은 Go 도구의 안전성 검사이며 Swift 코덱의 별도 1만 입력 시험을 대신하지 않는다.

```sh
check_dir="$(eyebuild dir m6-tools)"
mkdir -p "$check_dir/tmp"
export TMPDIR="$check_dir/tmp"
export GOCACHE="$(eyebuild dir interop-tools)/gocache"
export GOMODCACHE="$(eyebuild dir ref-src)/gomod"
export GOFLAGS=-modcacherw GOPROXY=off GOSUMDB=off
(cd Tools/interop && go test -count=1 ./cmd/tcpfixtures ./cmd/tailnet)
eyebuild rm m6-tools
```

`Package.swift`의 `SwiftailNetstackTests`에는 아직 Fixtures 리소스 선언이 없다. Swift 대조 시험을 붙이는 세션에서 `resources: [.copy("Fixtures")]`를 더해야 한다. 이 도구 작업은 Swift 코드와 패키지 선언을 바꾸지 않는다.
