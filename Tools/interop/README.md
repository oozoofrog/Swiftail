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
