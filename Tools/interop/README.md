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
