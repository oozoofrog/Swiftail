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

`sh Scripts/build-interop-tools.sh tailnet`으로 빌드한다. 인자 없는 호출은 기존과 같이 `wgpeer` 경로 한 줄을 출력한다. `tailnet`은 루프백의 평문 testcontrol, 자체 서명 TLS DERP, STUN 서버를 시작하고 `ready` JSON을 출력한다. DERPMap의 `InsecureForTests`는 인증서 검증을 끄므로 Swift 시험에서도 이 시험 서버에 한정해 자체 서명 인증서를 허용해야 한다(`setDERPCertificate`로 바꾸면 인증서 고정이다. 아래 "DERP 인증서 고정"). STUN은 `stuntest`가 실행 프로그램에서 사용할 수 없는 `testing.TB`를 요구하므로 같은 `stun` 패키지로 구현한다.

표준 입력은 줄마다 `id`와 `cmd`가 있는 JSON이며 출력은 각 명령의 `id`가 포함된 JSON 한 줄이다. 오류는 `error` 사건이다. `quit` 또는 EOF는 종료한다.

- `addPeer`의 `name`은 소문자 DNS 레이블이다. 임시 tsnet 노드를 시작하고 TCP·UDP 포트 7에서 에코한다. `peer` 사건에 공개 nodeKey, addresses, fqdn이 있다.
- `removePeer`는 노드와 임시 상태를 닫고 `removed`를 돌려준다. testcontrol에는 노드 삭제 API가 없어 `nodes`와 다른 피어의 맵에서 자동으로 없어지지 않는다.
- `nodes`는 testcontrol의 등록 목록이다. 각 노드의 `endpoints`는 제어 서버가 맵 상태 갱신에서 받아 보관한 IP:port 문자열 배열이며 없으면 `[]`다. `AllNodes()`가 돌려주는 복제본의 `Endpoints`를 그대로 쓴다(`tailscale.com` v1.104.6 `tstest/integration/testcontrol/testcontrol.go:853-862`, `:1452-1486`). `online`은 testcontrol에 개별 연결 추적이 없으므로 실제 접속 상태로 해석하면 안 된다. `keyExpiry`는 서버가 쥔 그 노드의 node 키 만료 시각(UTC RFC 3339)이고 없으면 `""`다. 로그아웃하면 `1970-01-01T00:02:03Z`가 된다("로그아웃 관문 명령").
- `peerStatus`는 `name` 노드가 보는 `peers`의 nodeKey, addresses, online, curAddr, relay, `active`, `lastWrite`와 자기 엔드포인트 `selfAddrs`를 돌려준다. `selfAddrs`는 `Status.Self.Addrs`의 IP:port 문자열 배열이며 없으면 `[]`다. `active`는 bool, `lastWrite`는 Go `time.Time`의 RFC3339Nano 문자열(송신 전에는 `0001-01-01T00:00:00Z`)이다. magicsock은 외부 송신 활동(데이터·CLI Ping) 뒤 45초 안이면 active로 보고, 그 마지막 활동 시각을 lastWrite로 기록한다. heartbeat 송신만으로는 이 시각을 연장하지 않는다(`wgengine/magicsock/endpoint.go:2232-2253`, `magicsock.go:4026-4028`, `:4083`). `curAddr`는 신뢰된 직접 경로로만 보낼 때의 주소이며 DERP를 함께 쓰면 빈 문자열이다. `relay`는 피어의 홈 DERP 지역 코드이므로 현재 DERP 사용 여부를 뜻하지 않는다. `keyExpiry`는 그 피어의 node 키 만료 시각(UTC RFC 3339, 없으면 `""`), `expired`는 Go가 그 피어를 만료로 표시했는지다. Go는 `KeyExpiry`의 바뀜을 델타로 받고 `expired`는 전체 netmap을 받을 때만 계산하므로(`ipn/ipnlocal/local.go:1895`의 `flagExpiredPeers`), 만료 직후에는 `keyExpiry`만 바뀌고 `expired`는 `false`일 수 있다.
- `peerPing`은 `name`, 대상 IP `to`, `type` (`disco`, `TSMP`, `ICMP`)을 받는다. `result`는 LocalClient PingResult이며 `Err`가 비어 있어야 성공이다.
- `peerSend`는 `{"id":1,"cmd":"peerSend","name":"go-peer-a","to":"100.64.0.2","port":42001,"proto":"udp","payload":"010203"}`처럼 보낸다. `proto`는 `udp` 또는 `tcp`, `port`는 1…65535, `payload`는 65507바이트 이하의 hex다(빈 값 허용). 지정 피어의 tsnet으로 UDP 데이터그램 하나를 쓰거나, 2초 제한으로 TCP 연결을 시도한 뒤 연결되면 payload를 쓴다. 결과는 `{"id":1,"event":"peerSend","name":"go-peer-a","attempted":true,"sent":true,"error":""}`다. 전송 실패도 `peerSend` 사건으로 `sent:false`와 오류 문자열을 돌려주고, 잘못된 명령 입력은 기존 `error` 사건이다. `sent`는 payload 쓰기 완료를 뜻하며 상대의 수신을 보장하지 않는다. TCP 스택이 없는 Swift 대상은 보통 제한 시간으로 `sent:false`가 된다. SYN 송신 여부는 수신 패킷으로 확인해야 한다. TCP·UDP 소켓은 명령이 끝날 때 닫는다.
- `injectMapResponse`는 대상 `nodeKey`와 `response` 객체를 받는다. 스트림이 연결된 경우에만 큐에 넣으며 실제 전송은 스트림 처리 시점이다. 첫 주입부터 해당 노드에 대한 자동 맵이 계속 억제된다. `MapResponse` 타입으로 다시 JSON 인코딩하므로 빈 배열 등의 원래 JSON 표현은 보존되지 않는다.
- `restartPeer`는 `name` 피어의 tsnet을 닫고 같은 상태 폴더로 다시 띄운다. node 키·주소는 그대로이고 disco 키와 UDP 포트는 새것이다(magicsock이 시작할 때 disco 키를 만든다). 결과는 `addPeer`와 같은 `peer` 사건이다. 포트 7 에코는 다시 연다. `startCapture`·`peerServe`로 연 것은 옮기지 않는다. TSMP disco 키 광고 관문(`DiscoAdvertisementTests`)에서 Go 피어의 disco 키를 바꾸는 데 쓴다.
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

## Swiftail 노드 둘을 시험 제어 서버에 붙여 `listen`·`connect` 돌리기

계정·인증 키 없이 로컬 `testcontrol`·DERP·STUN에 Swift 노드 둘을 등록할 수 있다. 저장소 루트에서 `sh Scripts/build-interop-tools.sh tailnet`이 출력한 실행 파일을 터미널에서 실행한다. 첫 JSON 줄 `ready`의 `controlURL`을 아래 함수에 넘긴다. 도구는 표준 입력 EOF에서 끝나므로 이 터미널을 열어 둔다. `addPeer`는 필요 없다. 시험이 끝나면 `{"id":1,"cmd":"quit"}`을 입력한다.

통합 시험 타깃은 `Swiftail`과 `SwiftailBase`에 의존한다. 아래 코드는 두 노드의 상태 디렉터리를 따로 만들며, `.running`과 상대의 netmap 반영을 기다린다. `listen`은 `run()` 전에 열어도 되지만 `connect`는 `.running` 뒤에 부른다. `run()`은 시험이 끝날 때 취소하고 반드시 회수한다. `controlURL`은 실행 때 받은 값이고, `root`는 시험이 만든 빈 임시 디렉터리다.

```swift
import Foundation
import Swiftail
import SwiftailBase

func exchangeWithTwoNodes(controlURL: URL, root: URL) async throws {
    let server = try TailnetNode(configuration: .init(
        stateDirectory: root.appending(path: "server"),
        hostname: "rd-mac-1a2b3c4d", controlURL: controlURL), device: .inProcess)
    let client = try TailnetNode(configuration: .init(
        stateDirectory: root.appending(path: "client"),
        hostname: "rd-mac-5e6f7a8b", controlURL: controlURL), device: .inProcess)
    let listener = try await server.listen(port: 9_200)
    let serverRun = Task { try await server.run() }
    let clientRun = Task { try await client.run() }
    do {
        let deadline = ContinuousClock.now + .seconds(25)
        while true {
            let serverStatus = await server.status
            let clientStatus = await client.status
            if serverStatus.state == .running, clientStatus.state == .running,
               serverStatus.peerCount >= 1, clientStatus.peerCount >= 1 { break }
            guard ContinuousClock.now < deadline else { throw CancellationError() }
            try await Task.sleep(for: .milliseconds(50))
        }
        let status = await server.status
        guard let address = status.addresses.first(where: { $0.isIPv4 }) else {
            throw ConnectionError.unknownHost
        }
        let connection = try await client.connect(to: address.description, port: listener.port)
        var iterator = listener.makeAsyncIterator()
        guard let accepted = await iterator.next() else { throw ConnectionError.closed }
        try await connection.write([1, 2, 3])
        try await connection.finishWriting()
        var request: [UInt8] = []
        while let bytes = try await accepted.read() { request += bytes }
        guard request == [1, 2, 3] else { throw ConnectionError.reset }
        try await accepted.write([4, 5])
        try await accepted.finishWriting()
        var response: [UInt8] = []
        while let bytes = try await connection.read() { response += bytes }
        guard response == [4, 5] else { throw ConnectionError.reset }
        await connection.close()
        await accepted.close()
        await listener.close()
        serverRun.cancel()
        clientRun.cancel()
        _ = await (serverRun.result, clientRun.result)
    } catch {
        await listener.close()
        serverRun.cancel()
        clientRun.cancel()
        _ = await (serverRun.result, clientRun.result)
        throw error
    }
}
```

실제 시험은 이 함수 전체를 취소 가능한 기한(예: 60초) 안에서 실행하고, 끝나면 `root`를 지운다. 공개 API에는 deadline 인자가 없으므로 시간 제한을 건 Task가 취소되어야 한다. 큰 본문은 이 작은 예제처럼 모으지 말고 청크별로 소비한다. `NetstackTests.twoSwiftNodes`가 같은 등록·반닫힘·요청/응답 흐름을 실제 서버에서 검증한다. 다른 프로젝트는 `root`와 `controlURL`만 주입하고 위의 바이트 교환 자리에 자체 프로토콜 시험을 올리면 된다.

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

## M7 호스트 관문 명령

기존 명령과 JSON 형식은 유지한다. M7 DNS 동작은 `acmeStart`, `setCertDomains`, `setDNSConfig` 가운데 하나를 실행할 때 켜진다. 기본 `DNSConfig`는 `Proxied:true`, `CertDomains:["<hostname>.tail0001.test"]`다. 먼저 기존 `setMagicDNS`를 썼으면 그 `Proxied`를 유지한다. 기존 `setMagicDNS`의 등록 전 전용 규약도 유지한다. 등록 뒤 MagicDNS를 바꾸려면 새 `setDNSConfig`를 쓴다.

pebble `github.com/letsencrypt/pebble/v2 v2.10.3`과 challtestsrv `github.com/letsencrypt/challtestsrv v1.4.2`를 고정한다. **둘 다 MPL-2.0이며 시험 도구에만 링크된다.** Swift 라이브러리에는 링크되지 않는다. 두 모듈의 `LICENSE`가 MPL-2.0 원문이다. ACME HTTPS·DNS TCP/UDP는 `127.0.0.1`에서만 듣는다. pebble은 challtestsrv만 DNS 리졸버로 쓰며 실제 DNS나 Let's Encrypt로 보내지 않는다. HTTP-01·TLS-ALPN-01 리스너는 열지 않는다. `peerHTTP`도 등록된 tailnet 주소로만 연결하고 리다이렉트를 따라가지 않는다.

새 명령도 모든 응답에 원래 `id`를 돌려주며, 입력·요청 실패는 `{"id":1,"event":"error","message":"…"}`다. **`peerHTTP`만 요청을 뒤에서 실행하고 완료 때 응답 한 줄을 쓴다.** 따라서 다른 명령 응답이 먼저 올 수 있다. `id`로 대응시키고, 전송 도중 `removePeer`나 `peerClose(stop:true)`를 보낼 수 있다. `quit`·EOF는 진행 중 HTTP를 취소하고 회수하며, `quit` 응답은 마지막이다. 다른 명령은 기존대로 순서대로 처리한다.

| 명령 | 입력(`id`, `cmd` 외) | 성공 응답(`id` 외) |
| --- | --- | --- |
| `acmeStart` | 선택 `nonceReject`(0…100, 기본 0), `authzReuse`(0…100, 기본 0), `validationDelaySec`(0…60, 기본 0) | `{"event":"acmeStart","directoryURL":"https://127.0.0.1:<port>/dir","rootPEM":"-----BEGIN CERTIFICATE-----\n…","dnsAddress":"127.0.0.1:<port>","nonceReject":0,"authzReuse":0,"validationDelaySec":0}` |
| `setCertDomains` | 필수 `domains` 문자열 배열, 선택 `nodeKey` | `{"event":"certDomains","nodeKey":"","domains":[]}`. `nodeKey`를 주면 응답에도 그 공개 키가 있다 |
| `setDNSConfig` | 필수 `enabled` bool | `{"event":"dnsConfig","enabled":false}` |
| `setDNSLog` | 없음 | `{"event":"setDNSLog","requests":[{"name":"_acme-challenge.rd-mac-1a2b3c4d.tail0001.test","type":"TXT","value":"<TXT 값>","nodeKeySummary":"<공개 키 요약>","time":"2026-01-02T03:04:05.123456789Z"}]}` |
| `setDNSFault` | 필수 `count`(0…10000), 아래 결함 하나 | `{"event":"setDNSFault","count":1}` |
| `peerWhoIs` | `name`(조회하는 Go 피어), `to`(IP 또는 IP:port, IPv6 포트는 대괄호) | `{"event":"peerWhoIs","name":"go-peer-a","stableID":"<StableID>","nodeName":"rd-mac-1a2b3c4d.tail0001.test","computedName":"rd-mac-1a2b3c4d","loginName":"<시험 사용자 로그인>"}` |
| `peerHTTP` | `name`, `url`, 선택 `method`(기본 GET), `headers`(값은 문자열 배열), `send`·`seed`(한 쌍), `range`, `rootPEM`, `to`, `timeoutSec` | `{"event":"peerHTTP","name":"go-peer-a","status":206,"headers":{"Content-Range":["bytes 0-52428799/104857600"]},"bodyLength":52428800,"bodySHA256":"<소문자 SHA-256 hex>","elapsedMs":1234}` |
| `goState` | `name` | `{"event":"goState","name":"go-peer-a","directory":"<상태 디렉터리>","stopped":false}` |
| `peerClose`의 추가 모드 | `name`, `stop:true`, `port` 생략 | `{"event":"peerClose","name":"go-peer-a","stopped":true}` |

`acmeStart`는 프로세스의 네트워크당 한 번만 시작한다. 루트·계정·발급 자료는 이 실행의 시험 자료이며 다시 시작하면 달라진다. `rootPEM`은 **인증서 PEM만** 담고 개인 키는 내보내지 않는다. Swift 시험은 이를 디렉터리 HTTPS와 발급 사슬 검증의 명시적 시험 앵커로 쓴다. `nonceReject`는 유효 nonce의 무작위 거절 백분율이며 100이면 발급이 끝나지 않는다. `authzReuse:100`이면 같은 계정·도메인의 valid authorization을 재사용한다. `validationDelaySec:0`은 pebble의 무작위 검증 대기를 끄고, 양수는 pebble이 고르는 무작위 대기의 상한 초다. 검증 자체는 항상 수행한다. API를 제공하지 않는 pebble 검증 작업자의 대기 goroutine은 프로세스 수명까지 남고, 도구가 연 HTTP·DNS 리스너는 종료 때 닫는다.

`setCertDomains`는 자동 FQDN에 추가하는 것이 아니라 **그 목록 전체를 교체**한다. `[]`는 자동 FQDN까지 지워 HTTPS를 끈다. `nodeKey`가 없으면 현재와 미래 노드 모두에 적용하고 기존 노드별 덮어쓰기도 지운다. 있으면 등록된 해당 노드만 바꾼다. 도메인은 끝 점 없는 소문자 ASCII DNS 이름이고 각 레이블은 1…63자, `_acme-challenge.`를 붙인 이름은 최대 253자다. `setDNSConfig`는 모든 노드의 `DNSConfig.Proxied`만 바꾼다. 바뀐 설정과 기존 피어·엔드포인트 변경은 50ms 간격으로 비교하여 다음 맵에 싣는다. 원시 맵 주입 뒤 재접속도 첫 맵을 받도록 내용이 같아도 1초마다 전체 맵을 다시 보낸다. 응답은 맵 수신 완료를 보장하지 않으므로 Swift의 사실 스트림이나 Go status가 바뀔 때까지 기다린다. 기존 `injectMapResponse`로 수동 맵을 주입한 노드는 이 갱신 대상에서 계속 제외된다(기존 자동 맵 억제 규약).

`set-dns`는 기존 testcontrol의 Noise 처리기를 사용한다. 도구는 `MaybeRejectRequest`에서 원래 요청을 기록하고 설정된 cert 도메인을 검사한다. 사용자 지정 도메인도 받기 위해 내부 요청의 이름을 testcontrol이 아는 자동 FQDN으로 바꾸고, 원래 요청을 내부 값에 담는다. testcontrol의 TXT·빈 필드·node 키·**machine 소유** 검사를 통과한 뒤 `OnSetDNS`에서 원래 요청을 복원해 challtestsrv에 TXT를 올린다. 같은 이름의 이전 TXT는 교체한다. `setDNSLog`에는 결함·도메인 거절을 포함해 JSON으로 해석된 요청의 **원래** 이름·종류·값만 받은 순서대로 남으며, node 공개 키는 `ShortString` 요약만 낸다. 잘못된 JSON은 기록하지 않는다. 시각은 실제 UTC RFC3339Nano다. 목록은 누적이고 빈 목록은 `[]`다. 레코드 삭제·운영 DNS 전파는 시험하지 않는다.

`setDNSFault`는 다음 `count`개의 해석 가능한 `set-dns` 요청에 다음 중 **하나**를 적용한다. 새 명령은 남은 결함 설정을 교체하고, `count:0`에 결함 필드를 생략하면 지운다.

- `status`: 200…599의 최종 HTTP 상태로 답한다(예: 403 거절, 201 같은 비정상 성공 상태).
- `delayMs`: 1…3600000ms 대기한 뒤 정상 처리한다. 요청 취소·도구 종료는 대기를 끝낸다.
- `body`: `large`(8192자 padding을 가진 객체), `null`, `array`(`[]`), `scalar`(`"test"`), `empty`(공백 본문). 200으로 답하고 TXT는 올리지 않는다. testcontrol 훅이 `http.Error`로 응답하므로 `Content-Type:text/plain`과 끝 줄바꿈을 사용한다. Swift의 객체·4KiB 검사는 본문을 기준으로 검증한다. Go는 `null`과 큰 객체를 받는다.
- `wrongTXT:true`: 정상 응답하지만 DNS에 `swiftail-invalid-txt`를 올린다. 로그의 값은 원래 요청 값이다.

`peerWhoIs.nodeName`은 Go `Node.Name`의 끝 점을 뗀 값이다. 응답의 `name`은 조회를 수행한 Go 피어 이름이다. `computedName`은 Go가 실제 계산한 값이고 로그인 이름은 Go `UserProfile.LoginName`이다. 조회 실패는 `error` 사건이다.

`peerHTTP.headers`는 `{"Authorization":["Bearer <시험 토큰>"],"Content-Type":["application/octet-stream"]}` 모양이다. `send`는 0…4294967296, `seed`는 UInt64 전체 범위이며 M6의 LCG64 바이트열을 그대로 스트리밍한다. 둘을 생략하면 본문이 없다. `range`는 `Range` 머리를 설정하며 같은 이름의 `headers`보다 우선한다. 응답 헤더 값도 항상 배열이고 본문은 저장하거나 출력하지 않는다. SHA-256과 길이는 실제로 읽은 응답 바이트(Go HTTP의 transfer decoding 뒤, content encoding은 그대로)를 기준으로 한다. `elapsedMs`는 연결·TLS·응답 본문 전체를 포함한다. `timeoutSec`는 M6와 같은 기본 15초·범위 1…3600이다. 큰 요청과 응답에도 32KiB 단위 버퍼를 쓰며 본문 전체를 메모리에 모으지 않는다.

HTTPS의 `rootPEM`을 생략하면 `acmeStart`가 만든 루트만 쓴다. 명시하면 그 PEM 앵커만 쓴다. 시스템 루트나 검증 끄기는 사용하지 않는다. TLS 서버 이름은 URL의 호스트이며, `to`로 주소를 덮어써도 이름 검증은 그대로다. URL의 호스트가 등록 노드의 FQDN이나 IP이면 그 tailnet 주소로 연결한다. 임의 cert 도메인은 `to:"100.64.0.1"`처럼 등록 노드 주소를 명시한다. 이 연결은 OS DNS를 질의하지 않는다. IPv6도 지원한다. 각 요청은 독립 연결이며 TLS 실패·기한·잘린 응답은 본문·URL을 노출하지 않는 `error` 사건이다. 4xx·5xx HTTP 응답 자체는 성공 사건으로 status·해시를 반환한다.

관문에서 쓰는 순서(도메인·주소는 예시이며 실제 값은 해당 실행의 `nodes`·맵에서 받는다):

```json
{"id":1,"cmd":"acmeStart","nonceReject":25,"authzReuse":100}
{"id":2,"cmd":"addPeer","name":"go-peer-a"}
{"id":3,"cmd":"addPeer","name":"go-peer-b"}
{"id":4,"cmd":"peerWhoIs","name":"go-peer-a","to":"100.64.0.2"}
{"id":5,"cmd":"setDNSLog"}
{"id":6,"cmd":"peerHTTP","name":"go-peer-a","url":"https://rd-mac-1a2b3c4d.tail0001.test/pair","method":"POST","send":32,"seed":1}
{"id":7,"cmd":"peerHTTP","name":"go-peer-a","url":"https://rd-mac-1a2b3c4d.tail0001.test/ipa","range":"bytes=0-52428799","timeoutSec":60}
{"id":8,"cmd":"peerHTTP","name":"go-peer-a","url":"https://rd-mac-1a2b3c4d.tail0001.test/ipa","range":"bytes=52428800-104857599","timeoutSec":60}
{"id":9,"cmd":"setCertDomains","domains":[]}
{"id":10,"cmd":"setCertDomains","domains":["rd-mac-1a2b3c4d.tail0001.test"]}
{"id":11,"cmd":"setDNSConfig","enabled":false}
{"id":12,"cmd":"setDNSConfig","enabled":true}
{"id":13,"cmd":"setDNSFault","count":1,"status":403}
{"id":14,"cmd":"setDNSFault","count":1,"wrongTXT":true}
{"id":15,"cmd":"goState","name":"go-peer-a"}
{"id":16,"cmd":"peerClose","name":"go-peer-a","stop":true}
{"id":17,"cmd":"goState","name":"go-peer-a"}
```

1 뒤 Swift 노드를 `ready.controlURL`에 붙이고, 반환한 directory·루트를 시험용 발급기에 준다. 발급 뒤 5의 TXT 값을 대조한다. 다시 시작·갱신·재사용은 Swift 시험의 노드·시계·저장소로 유도한다. 6~8 사이에는 앞 요청의 완료를 기다려 서버가 준 세션·토큰을 후속 머리에 넣는다. 전송 중 제거를 보려면 `peerHTTP` 완료 전에 `removePeer`를 보낸다. 기존 `removePeer`는 testcontrol의 노드 목록을 지우지 않으므로, **netmap의 피어 제거**까지 보려면 Swift 노드에 `injectMapResponse`의 `PeersRemoved`를 별도로 주입한다(필요한 NodeID는 시험 맵에서 얻는다). 도구가 Swift의 origin 표·TLS 리스너·파일 권한·갱신 시계를 대신 검사하지 않는다.

상태 가져오기는 **15로 경로를 얻고 → 16의 응답을 기다리고 → 17의 `stopped:true`를 확인한 뒤** `tailscaled.state`·`certs/`를 읽거나 복사한다. 기존 `peerClose(name,port)`는 리스너만 닫으므로 이 용도로 쓰면 안 된다. 멈춘 노드의 디렉터리는 `removePeer`·`quit`·EOF에서 삭제된다. 읽기를 마치기 전에는 이들을 보내지 않는다. Go 인증서 캐시는 자동으로 만들어 주지 않으며 필요하면 시험이 준비한다.

빌드·실행·Go 회귀 시험의 임시 파일도 전용 eyebuild 아래에 둔다. `go mod download` 이외 네트워크는 루프백과 로컬 tailnet 시험뿐이다.

```sh
check_dir="$(eyebuild dir m7-tailnet-tool)"
mkdir -p "$check_dir/tmp"
export TMPDIR="$check_dir/tmp"
export GOCACHE="$(eyebuild dir interop-tools)/gocache"
export GOMODCACHE="$(eyebuild dir ref-src)/gomod"
export GOFLAGS=-modcacherw
(cd Tools/interop && go mod download)
export GOPROXY=off GOSUMDB=off
(cd Tools/interop && go test -count=1 ./...)
# 실행이 필요하면 같은 환경에서:
# tailnet_tool="$(sh Scripts/build-interop-tools.sh tailnet)"
# "$tailnet_tool"
eyebuild rm m7-tailnet-tool
```

`TestHostTools`는 명령 검증·실제 Noise `SetDNS`·응답 결함·잘못된 TXT의 발급 실패·독립 Go ACME 클라이언트의 DNS-01 발급과 사슬/이름 검증·authorization 재사용·HTTPS Range와 100MiB 업로드·HTTP·상태 보존과 같은 Go 신원의 재접속을 확인한다. `TestPeerHTTPConcurrentRemove`는 JSON 실행 중 HTTP를 기다리면서 실제 Go 피어를 제거할 수 있음을 확인한다. Swift 관문·실기기·운영 서버는 이 Go 시험의 확인 범위 밖이다.

## Tailnet Lock 관문 명령

계정 없이 lock이 켜진 tailnet을 흉내 낸다(`docs/contracts/SwiftailTailnetLock.md` 7절 "관문 (가)", 결정 L15). Go 피어(tsnet)가 서명 기기 노릇을 하고, 서버 쪽은 testcontrol 사본이 맡는다. 기존 명령과 JSON 형식은 그대로다.

### testcontrol 사본

`tailnet`은 upstream 패키지 대신 `internal/testcontrol/`을 쓴다. `tailscale.com` v1.104.6(`go.mod`가 빌드하는 판. v1.104.7과 이 디렉터리는 같다)의 `tstest/integration/testcontrol/`에서 `doc.go`·`testcontrol.go`·`testcontrol_test.go`·`capability_default_test.go`를 옮겨 적었고, 파일마다 원본의 BSD-3-Clause 머리말과 출처 줄을 두었다. 모듈의 `LICENSE`를 같은 디렉터리에 두었다. `h2server` 등 다른 도구는 원본 패키지를 그대로 쓴다.

옮기지 않은 것: `reco-experiment.go`·`capability_reco_test.go`·`reco.md`(`experiment.reco` 빌드 태그의 대체 구현). 그래서 `testcontrol.go`·`capability_default_test.go`의 `//go:build !experiment.reco`를 지웠다. `testcontrol_test.go`는 import 경로만 사본으로 바꿨다. 옮겨 적은 직후, 보탬을 넣기 전에 `go test ./internal/testcontrol ./cmd/tailnet`이 통과하는 것을 기준선으로 확인했다.

원본과 다른 점(코드에는 "원본에 없는 보탬" 또는 "원본과 다름" 주석이 있다. 보탬의 본체는 `internal/testcontrol/tka.go`. 로그아웃(`Expiry`)의 보탬은 `logout.go`이고 "로그아웃 관문 명령"의 표에 적었다):

| 자리 | 다른 점 | 근거 |
| --- | --- | --- |
| `/machine/tka/sync/send` | 처리기를 더했다. 받은 AUM을 `tkatest.HandleTKASyncSend`로 검증해 들이고(`Inform`) 서버 머리를 답한다. 머리가 바뀌면 모든 노드에 새 맵을 보낸다. lock이 없으면 400. 원본은 처리기가 없어 프로세스가 panic한다 | `tstest/tkatest/tkatest.go`의 `HandleTKASyncSend`, `ipn/ipnlocal/tailnet-lock_test.go`의 `TestTKASync` |
| `/machine/tka/disable` | 처리기를 더했다. `Version`이 `CurrentCapabilityVersion`이고 비밀이 서버 상태의 `ValidDisablement`를 통과하면 서버의 lock 상태를 지우고 비밀을 기억한다. 틀리면 400. 머리 일치는 보지 않는다 | 요청 모양은 `ipn/ipnlocal/tailnet-lock.go`의 `tkaDoDisablement`, `TestTKADisable`. 서버가 무엇을 검사하는지는 **추측** |
| `/machine/tka/bootstrap` | 끈 뒤에는 `DisablementSecret`(기억한 비밀, 또는 `wrongSecret`이면 `0x42`×32)을 준다. `setLockBootstrapFault`가 켜지면 `GenesisAUM`의 마지막 바이트를 잘라 준다. 잘못된 요청(다른 `Version` 등)에 panic하지 않고 400만 쓴다 | `TestTKADisablementFlow`의 가짜 서버 |
| `/machine/tka/sync/offer` | lock이 없으면 400(원본은 nil 저장소를 열다 panic). 교차 없음 같은 실패에 panic하지 않는다. 틀린 끄기 비밀을 받은 Go 노드는 서버가 lock을 끈 뒤에도 동기화를 잇기 때문이다 | `ipn/ipnlocal/tailnet-lock.go:399-418` |
| `/machine/tka/sign` | 검증 실패와 등록되지 않은 node 키에 panic하지 않는다(후자는 이미 200을 쓴 뒤라 서명만 버린다) | — |
| `init/begin`·`init/finish` | begin은 끈 상태를 지운다. finish 뒤 모든 노드에 새 맵을 보낸다(원본은 다음 맵 요청까지 기다린다) | — |
| 맵 응답 | `setLockCapability`가 켜지면 자기 노드 `CapMap`에 `https://tailscale.com/cap/tailnet-lock`(`[]`)을 싣는다. 끈 뒤에는 `TKAInfo{Disabled: true}`를 싣고, `omitTKAInfo`면 싣지 않는다 | 원본은 `DefaultNodeCapabilities`로 등록 때의 `Capabilities`에만 실을 수 있고, 맵 응답의 `CapMap`은 `SetNodeCapMap`의 값으로 덮인다. 운영 서버가 끈 뒤 무엇을 보내는지는 **추측** |
| 등록 | 요청의 `NodeKeySignature`를 서버 상태의 `NodeKeyAuthorized`로 검증해 통과하면 노드의 `KeySignature`로 둔다. 실패해도 등록은 하고 서명만 붙이지 않는다. `lockRequestResign`으로 고른 node 키가 다음에 `OldNodeKey` 없이 등록하면 응답 `NodeKeySignature`에 지금 서명을 실어 재서명을 요청한다. 재서명한 키 교체가 받아들여지면 옛 키의 항목을 곧바로 지운다(원본은 인증 URL을 마친 뒤에만 지워, 인증 없는 교체에서는 같은 노드 ID의 항목이 둘 남는다) | 클라이언트 쪽은 `control/controlclient/direct.go:534-545`·`:704-747`. 서명 실패의 처리, 재서명을 요청하는 때, 옛 키의 처리는 **추측** |
| 기록 | `/machine/tka/` 요청(경로, `NodeKey`, `Head`)과 등록 요청(서명 판정, 해독한 본문)을 쌓는다 | — |

`tkatest`의 offer·send 처리기는 받은 요청과 응답(공개 node 키, AUM 바이트)을 Go `log`로 표준 오류에 쓴다. 원본 패키지라 끄지 않았다. 비밀은 들어 있지 않다. 사본은 upstream 버전을 올릴 때 다시 맞춘다.

### 명령

모든 응답에 원래 `id`가 있고, 실패는 `error` 사건이다. `name`은 명령을 수행하는 Go 피어다. 키 텍스트는 node 키가 `nodekey:<hex>`, lock 키가 `tlpub:<hex>`(입력은 `nlpub:`도 받는다), 머리가 AUM 해시의 base32(52자)다.

| 명령 | 입력(`id`, `cmd` 외) | 성공 응답(`id` 외) |
| --- | --- | --- |
| `setLockCapability` | `enabled` bool | `{"event":"lockCapability","enabled":true}`. 언제 바꿔도 되고 모든 노드에 새 맵을 보낸다 |
| `lockInit` | `name`, 선택 `signers`(신뢰 키로 넣을 Go 피어 이름들, 기본 `[name]`) | `lockStatus`와 같은 필드의 `{"event":"lockInit",…}`. 끄기 비밀 하나를 만들어 도구 안에만 쥔다. 그때 등록된 모든 노드가 `name`의 서명을 받는다(회전 키 없음). `signers`가 서버 머리에 닿을 때까지 기다린 뒤 답한다 |
| `lockStatus` | `name` | `{"event":"lockStatus","name":"go-peer-a","enabled":true,"head":"<base32>","nodeKey":"nodekey:…","lockKey":"tlpub:…","nodeKeySigned":true,"trustedKeys":["tlpub:…"],"visiblePeers":["nodekey:…"],"filteredPeers":["nodekey:…"],"controlHead":"<서버 머리, 없으면 \"\">","controlDisabled":false}`. Go `TailnetLockStatus`를 그대로 옮긴다. `nodeKeySigned:false`가 자기 잠김이다. lock이 꺼진 피어는 `visiblePeers`·`filteredPeers`가 비므로 보이는 피어는 `peerStatus`로 본다 |
| `lockSign` | `name`, `nodeKey`, 선택 `lockKey`(회전 키) | `{"event":"lockSign","name":"go-peer-a","nodeKey":"nodekey:…"}`. Swift 노드의 `signingRequest` 두 값을 그대로 넣는다. `lockKey`를 주어야 그 노드가 뒤에 스스로 재서명할 수 있다 |
| `lockWrapAuthKey` | `name`, 선택 `authKey`(기본: `setAuth`의 키) | `{"event":"lockWrapAuthKey","name":"go-peer-a","authKey":"<인증 키>--TL<credential>-<개인 키>"}`. `tailscale lock sign <인증 키>`처럼 credential 전용 lock 키를 새로 만들어 감싸고 그 키를 신뢰 키로 더한다(사슬이 한 칸 자란다). 응답의 키는 **개인 키를 담은 시험 전용 값**이므로 로그에 남기지 않는다. `addPeer`의 `authKey`로 Go 피어를 등록할 수도 있다 |
| `lockModify` | `name`, `addKeys`·`removeKeys`(`tlpub:` 배열, 하나 이상) | `lockStatus`와 같은 필드의 `{"event":"lockModify",…}`. 투표 1의 키로 더하고 뺀다. `name`이 서버 머리에 닿을 때까지 기다린 뒤 답한다(다음 명령이 낡은 머리 위에 갈래를 만들지 않게) |
| `lockDisable` | `name`, 선택 `wrongSecret`·`omitTKAInfo` bool | `{"event":"lockDisable","name":"go-peer-a","wrongSecret":false,"omitTKAInfo":false,"alreadyDisabled":false}`. 서버가 줄 비밀과 맵의 모양을 먼저 정하고 `name`이 `lockInit`의 비밀로 끈다. `wrongSecret`이면 bootstrap이 틀린 비밀을 줘서 노드가 lock을 유지한다. 서버가 이미 꺼졌으면(`alreadyDisabled:true`) 피어 RPC 없이 그 두 설정만 바꾸고 새 맵을 보낸다. 그래서 `wrongSecret` 뒤 다시 부르면 노드들이 맞는 비밀을 받는다 |
| `setLockBootstrapFault` | `enabled` bool | `{"event":"lockBootstrapFault","enabled":true}`. 켜진 동안 bootstrap의 `GenesisAUM`이 깨진다. 바꿀 때 새 맵을 보낸다(Go는 netmap을 받을 때만 다시 시도한다) |
| `lockRequestResign` | `nodeKey`(서명이 있는 등록된 노드) | `{"event":"lockRequestResign","nodeKey":"nodekey:…"}`. 그 노드의 다음 등록 응답 하나에 재서명 요청을 싣는다 |
| `lockRegistrations` | 없음 | `{"event":"lockRegistrations","registrations":[{"nodeKey":"nodekey:…","oldNodeKey":"","nlKey":"tlpub:…","auth":false,"expiry":"0001-01-01T00:00:00Z","expiryUnix":0,"signature":"accepted","signatureError":"","resignRequested":false,"wrappedKeyTrace":false}]}`. 받은 순서다. Tailnet Lock과 상관없는 등록(로그아웃 포함)도 모두 쌓인다. `auth`는 요청에 `Auth`가 실렸는지, `expiry`는 요청 JSON의 `Expiry` 문자열(선 위의 표기 그대로), `expiryUnix`는 그 Unix 초(0 시각이면 0)다. `nlKey`는 0이면 `""`. `signature`는 `none`·`noLock`·`accepted`·`rejected`(Go `NodeKeyAuthorized`의 판정). `wrappedKeyTrace`는 요청 JSON의 문자열 값에 `--TL`이나 이 도구가 감싼 개인 키·시드(base64 세 형식, 16진)가 있는지다. credential은 서명의 `Nested`에 늘 실리는 공개 값이라 보지 않는다 |
| `lockRequests` | 없음 | `{"event":"lockRequests","requests":[{"path":"/machine/tka/bootstrap","nodeKey":"nodekey:…","head":""}]}`. 받은 `/machine/tka/` 요청 전부다. 다시 시작 뒤 bootstrap이 없었는지, lock 없는 tailnet에서 TKA 요청이 없었는지를 이것으로 본다 |

`addPeer`는 선택 `authKey`를 받는다(없으면 기존대로 `setAuth`의 키).

끈 뒤의 `TKAInfo`: 기본은 `{"Disabled":true}`라 연결된 노드가 곧바로 끄기 절차로 간다. `omitTKAInfo`면 `TKAInfo`가 없는데, Go와 계약 동작 O1은 맵 세션 도중에 빠진 `TKAInfo`를 "변화 없음"으로 보므로 맵 스트림을 다시 이은 노드만 끄기 절차로 간다. 이미 `Disabled:true`를 받은 세션은 계속 그 값을 쥔다.

재서명: `lockSign`에 `lockKey`를 넣어 서명한 노드에 `lockRequestResign`을 건 뒤 그 노드가 다시 등록하면(Go는 다시 시작할 때 등록한다), 노드가 새 node 키를 만들어 `OldNodeKey`와 재서명한 `NodeKeySignature`로 다시 등록한다. 받아들여지면 서버가 옛 키의 항목을 지우므로, 다른 피어의 netmap에서 옛 키가 사라지는 것은 Go 클라이언트의 낡은 키 거르기(`rotationTracker`)가 아니라 서버가 지운 결과다.

Go 피어끼리의 흐름(관문 (가)의 Go 쪽 기준):

```json
{"id":1,"cmd":"setLockCapability","enabled":true}
{"id":2,"cmd":"addPeer","name":"go-peer-a"}
{"id":3,"cmd":"lockInit","name":"go-peer-a"}
{"id":4,"cmd":"addPeer","name":"go-peer-c"}
{"id":5,"cmd":"lockStatus","name":"go-peer-a"}
{"id":6,"cmd":"lockSign","name":"go-peer-a","nodeKey":"nodekey:<c>","lockKey":"tlpub:<c>"}
{"id":7,"cmd":"lockWrapAuthKey","name":"go-peer-a"}
{"id":8,"cmd":"lockModify","name":"go-peer-a","addKeys":["tlpub:<b>"]}
{"id":9,"cmd":"lockDisable","name":"go-peer-a","wrongSecret":true}
{"id":10,"cmd":"lockDisable","name":"go-peer-a"}
```

`TestTailnetLock`(`cmd/tailnet/lock_test.go`)이 Go 피어만으로 이 흐름을 돈다: lock 켜기와 켤 때 있던 피어의 서명, 서명 없는 피어가 다른 피어의 netmap에서 빠지고 스스로 잠김, 서명 뒤 나타남, 서명된 인증 키로 등록한 피어가 처음부터 보이고 그 등록의 서명이 `accepted`이며 흔적이 없음, 늦게 온 피어가 bootstrap 뒤 `sync/offer`·`sync/send`로 머리를 따라잡음, 키를 더해 다른 서명 기기가 서명한 피어가 그 키를 뺀 뒤 함께 빠짐, 재서명 요청 뒤 새 키로 바뀜, 깨진 bootstrap 뒤 lock을 켜지 못했다가 되돌리면 켬, 틀린 끄기 비밀이면 lock 유지, 맞는 비밀이면 모두 끄고 서명 없는 피어가 다시 보임, 끈 뒤의 맵 응답 모양. Swift 노드는 이 시험의 범위 밖이다(`Tests/SwiftailInteropTests/TailnetLockTests.swift`).

## 로그아웃 관문 명령

`docs/contracts/SwiftailHost.md` "로그아웃"의 상호 운용 시험이 쓴다. testcontrol 사본에 보탠 것은 `internal/testcontrol/logout.go`다(아래 표).

| 자리 | 다른 점 | 근거 |
| --- | --- | --- |
| 등록 | 요청의 `Expiry`가 0이 아니고 지금보다 앞이면 로그아웃으로 받아, 그 node 키의 노드 `KeyExpiry`를 요청의 값으로 두고 모든 노드에 새 맵을 보낸다. 응답의 `NodeKeyExpired`는 원본 검사가 그 `KeyExpiry`로 정하므로 참이다(요청에 `OldNodeKey`가 있으면 원본 검사를 건너뛰어 거짓). 노드는 지우지 않는다. 모르는 node 키면 원본 코드가 방금 만든 노드가 곧바로 만료된다. 미래의 `Expiry`(`SetExpirySooner`)는 다루지 않는다. 원본은 `Expiry`를 읽지 않는다 | `tailcfg/tailcfg.go`의 `RegisterRequest.Expiry` 주석, `control/controlclient/direct.go`의 `doLogin`(`loginOpt.Logout`). 응답 모양과 노드를 남기는 것은 **추측** |

| 명령 | 입력(`id`, `cmd` 외) | 성공 응답(`id` 외) |
| --- | --- | --- |
| `peerLogout` | `name` | `{"event":"peerLogout","name":"go-peer-b","backendState":"NeedsLogin"}`. Go 피어가 LocalAPI `Logout`을 부른다(`tailscale logout`과 같은 길). 응답은 로그아웃이 끝난 뒤의 `BackendState`다 |

Go 피어의 로그아웃 요청은 `Expiry`를 `time.Unix(123, 0)`로 싣는데 Go의 `time.Unix`는 로컬 시간대라, 선 위의 표기는 그 프로세스의 시간대를 따른다(예: `1970-01-01T09:02:03+09:00`). 같은 시각인지는 `expiryUnix`로 견준다.

`TestPeerLogout`(`cmd/tailnet/logout_test.go`)이 Go 피어만으로 본다: 로그아웃 요청의 `Expiry`가 Unix 123초이고 node 키가 그대로인 것, 서버의 그 노드 `keyExpiry`, 다른 피어의 netmap에 그 노드가 남되 `keyExpiry`가 바뀐 것, 같은 상태 디렉터리로 다시 띄우면(Go는 로그아웃 때 프로필을 지웠다) 새 node 키로 새 노드가 되는 것. Swift 쪽은 `Tests/SwiftailInteropTests/LogoutTests.swift`다.

## DERP 인증서 고정 (M8 ③)

`setDERPCertificate`는 첫 제어 요청 전에만 받는다(`{"id":1,"cmd":"setDERPCertificate","mode":"pinned"}`). DERP 서버의 인증서를 derper의 수동 인증서 모드가 IP 주소 hostname에 만드는 자체 서명 인증서(`cmd/derper/cert.go`의 `createSelfSignedIPCert`와 같은 모양: P-256, CN과 IP SAN `127.0.0.1`, 서버 인증 EKU, 지금부터 1년)로 바꾸고, derper처럼 `derpserver.ModifyTLSConfigToAddMetaCert`로 meta 인증서를 뒤에 붙인다. DERPMap 노드는 `InsecureForTests: false`, `CertName: "sha256-raw:<서버 인증서 DER의 SHA-256 소문자 16진>"`가 된다. `mode`가 `wrongPin`이면 서버가 함께 내는 meta 인증서의 해시를 알린다(어떤 클라이언트도 붙지 못한다). `leafNotFirst`는 고정 인증서의 키 없이 그 서버 행세를 하는 목록이다: 새로 만든 키의 CN `derpkey00` 인증서를 첫 자리에, 고정 인증서를 뒤에 낸다(`presented` 2. Go 클라이언트는 받는다. Swiftail은 받지 않는다). `named`는 인증서를 바꾸지 않고(httptest의 기본 자체 서명 인증서) 노드의 `CertName`만 `derp-cert.example.test`로 둔다(`InsecureForTests`는 그대로 true. `CertName`의 검증이 앞서므로 붙지 못한다). `dottedHostName`은 인증서를 바꾸지 않고 노드의 `HostName`을 `localhost.`로 둔다(SNI가 `localhost`로 오는지 본다). 응답은 `{"id":1,"event":"derpCertificate","mode":"pinned","certName":"sha256-raw:…","presented":2}`이고 `presented`는 서버가 내는 인증서 수다. Go 피어도 같은 DERPMap으로 `tlsdial.SetConfigExpectedCertHash` 검증을 거친다.

서버는 `tls.Config.GetConfigForClient`로 인증서를 고른다. `GetCertificate`는 `Certificates`가 있고 SNI가 없으면 불리지 않는데(Go `crypto/tls` `Config.getCertificate`), httptest가 기본 인증서를 `Certificates`에 채우므로 IP로 붙는 클라이언트를 놓치기 때문이다. 고정 모드가 아니면 nil을 돌려 httptest의 기본 인증서를 그대로 쓴다.

`tailnet certificate-fixtures`는 `Tests/SwiftailIOTests/ServerCertificateFixtures.swift`의 고정 인증서를 JSON(이름 → base64 DER, 그리고 `ipLeafSHA256`·`dnsLeafSHA256`·`metaSHA256`)으로 표준 출력에 쓴다. 독립 검토의 인증서 넷(`reviewFixtures`: 10년짜리, EKU 없음, Ed25519 키, CN이 VisibleString인 `derpkey00`)과 그 해시도 함께 쓴다(`Tests/SwiftailIOTests/ServerCertificateReviewTests.swift`). 자체 서명 인증서는 위와 같은 모양에 날짜를 2026-01-01 ..< 2027-01-01로 고정하고(IP `100.64.0.1`, DNS 이름 `derp1a.example.test`, 같은 모양의 다른 키 하나), 시험 루트와 그것이 발급한 `derp-cert.example.test` 인증서, 실제 `derpserver.Server.MetaCert()`를 더한다. 키와 서명이 난수라 실행마다 바이트가 다르다.

```sh
cd Tools/interop
GOCACHE="$(eyebuild dir interop-tools)/gocache" GOMODCACHE="$(eyebuild dir ref-src)/gomod" GOFLAGS=-modcacherw go run ./cmd/tailnet certificate-fixtures
```

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

# tsmpvectors

`SwiftailEngine` 단위 시험의 TSMP disco 키 광고 벡터를 `tailscale.com` v1.104.6의 `packet.TSMPDiscoKeyAdvertisement.Marshal`과 `Parsed.AsTSMPDiscoAdvertisement`로 만들어 `Tests/SwiftailEngineTests/Fixtures/tsmp-vectors.json`에 쓴다(v1.104.7과 코드가 같다). 키는 `SHA-256("swiftail-vectors/tsmp/<번호>")`(1, 2)를 X25519 개인 키 입력으로 쓰는 시험용 공개 값이고 주소는 시험용 tailnet 주소다. 시각·난수·운영 값이 없어 같은 입력이면 출력이 바이트 단위로 같다. 만든 바이트는 다시 해석해 같은 주소·키가 나오는지 확인한 뒤에 쓴다. 빌드 정보에서 기준 버전과 replace 부재를 확인한다.

```sh
export GOCACHE="$(eyebuild dir interop-tools)/gocache"
export GOMODCACHE="$(eyebuild dir ref-src)/gomod"
export GOFLAGS=-modcacherw GOPROXY=off GOSUMDB=off
(cd Tools/interop && go vet ./cmd/tsmpvectors && go run ./cmd/tsmpvectors ../../Tests/SwiftailEngineTests/Fixtures/tsmp-vectors.json)
```

담는 것: `advertisements`(IPv4 둘·IPv6 하나의 `src`·`dst`·`key`와 `Marshal` 바이트 `packet`), `parse`(IPv4 TSMP 본문 33·34·32바이트, 종류 `'p'`, 0 키, IPv6 광고, IPv4 조각(MF, offset 1, offset 10), IPv6 조각 머리가 붙은 첫 조각(M 1·0)과 뒤 조각을 `Parsed.Decode`와 `AsTSMPDiscoAdvertisement`로 해석한 결과. 광고가 아니면 `key`가 없다). `key`는 Go의 판정 그대로다. IPv6 첫 조각 둘은 Go가 받고 Swiftail은 버린다. `TSMPVectorTests`가 이 둘을 알려진 차이로 따로 확인한다.

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
- `networkStatus`: `controlConnections`(`/ts2021` 요청 수), `derpConnections`(`/derp` 요청 수), `derpTLSHandshakes`(DERP 서버가 받은 TLS ClientHello 수), `derpServerNames`(그 ClientHello의 SNI 값들을 정렬한 것. SNI가 없으면 `""`), `stunRequests`(유효 STUN Binding 요청 수)를 반환한다. 인터페이스 재결속·같은 인터페이스 재평가를 주소 없이 관측하기 위한 프로세스 전체 누적 수다.

- `setMagicDNS`(`enabled` bool): 첫 제어 요청 전에 `DNSConfig.Proxied`를 설정하고 `magicDNS`로 답한다. `MagicDNSDomain`은 이름 접미사만 정하므로 DNS 관문은 이 명령으로 MagicDNS를 켠 뒤 피어·Swift 노드를 등록한다. 누락된 bool·등록 뒤 변경은 거절한다.

# TCP 세그먼트 기준 자료 생성 (`tcpfixtures`)

고정 gVisor `v0.0.0-20260915211658-a6f909f08a72`의 `pkg/tcpip/header`·`checksum` 공개 API를 호출한다. `IPv4.Encode`·`IPv6.Encode`·`TCP.Encode`·옵션 인코더로 패킷을 만들고 `TCPValid`·`ParseSynOptions`로 읽는다. Swift 구현은 읽거나 부르지 않는다. 바이트 변형은 잘못된 경계를 만들 때만 한다. 네트워크·난수·시각을 사용하지 않는다.

```sh
fixture_tool="$(sh Scripts/build-interop-tools.sh tcpfixtures)"
"$fixture_tool" Tests/SwiftailNetstackTests/Fixtures
```

인자는 필수 폴더이며 `tcp-segments.json`을 쓴다. 자료 머리는 `reference`, `caseCount: 62`, `cases`다. 사례는 `name`, `packet`(IP 머리를 포함한 소문자 hex), `go`, `swiftail`, 선택 `swiftailDiffers`다. `go`는 실제 Go 반환값, `swiftail`은 W2·T5·X9에서 의도적으로 정한 차이만 적용한 기대값이다. 차이가 없으면 두 객체가 같다.

각 결과의 키:

| 키 | 뜻 |
| --- | --- |
| `error` | 성공은 빈 문자열, 실패는 `malformed`, `badChecksum`, `notTCP`. gVisor의 bool 결과를 도구가 정규화한 이름이며 Go 오류 문자열이 아님 |
| `ipChecksumValid` | IPv4 머리 체크섬. IPv6 또는 검사 전 잘림이면 null |
| `checksumValid` | TCP 체크섬. data offset 등 구조를 읽을 수 없으면 null |
| `decoded` | TCP 구조를 읽었으면 해석 객체. 체크섬 오류에서도 진단용으로 남기며 `error`가 있으면 수용할 패킷이 아님. 머리를 읽을 수 없으면 null |

`decoded`에는 `ipVersion`, `source`, `destination`, `ipHeaderLength`, `sourcePort`, `destinationPort`, `sequenceNumber`, `ackNumber`, `flags`(8비트 원값), `window`(와이어의 16비트 원값), `tcpHeaderLength`, `optionsHex`, `mss`, `windowScale`, `sackPermitted`(SYN에서만), `sackBlocks`(SYN이 아닌 세그먼트에서만. 블록마다 [왼쪽 끝, 오른쪽 끝]), `dataLength`가 있다. `mss`는 SYN의 **유효 MSS**로 옵션 생략 시 기본값도 포함한다(Swift 코덱의 `maximumSegmentSize`는 옵션이 없으면 nil이고, 기본값은 연결 상태 기계가 계약 T5로 채운다. 대조 시험은 nil을 기본값으로 읽어 견준다). `windowScale`은 SYN에서 옵션 없으면 -1이며, SYN이 아니면 MSS·WS 모두 null이다. data offset 길이는 바이트 단위다. `swiftail.error`가 `malformed`인 사례의 `decoded`는 Go가 읽은 진단 값이며 성공한 Swift 해석을 뜻하지 않는다.

62개 사례:

- 각 IPv4·IPv6에 SYN(MSS·WS), SYN-ACK, 홀수 길이 데이터, 반복 올림 체크섬, FIN-ACK, RST, SYN 아닌 MSS·WS, 옵션 생략, MSS 0, shift 15, 틀린 체크섬(22개).
- IPv4 옵션, NOP로 어긋난 정렬, EOL 뒤 잘못된 바이트 무시, 모르는 옵션, SACK·timestamp와 MSS·WS 조합, shift 14, 최대 60바이트 TCP 머리, 작은 MSS 1(8개).
- 옵션 길이 0·1·머리 밖, 마지막 옵션 길이 필드 누락, MSS 본문 잘림(5개. 계약은 `malformed`), MSS 길이 3·WS 길이 2(2개. 계약도 gVisor처럼 값을 읽지 않고 건너뛴다).
- TCP 0·1·19바이트, IP 0·1·19·39바이트 잘림(7개).
- data offset 4·6·15(세그먼트 밖), 16을 넣으면 4비트가 0으로 순환하는 사례(4개). 와이어에는 16을 담을 수 없다.
- 프로토콜이 TCP가 아닌 IPv4(1개).
- SACK(13개, M6-10a): SYN의 SACK-Permitted(IPv4·IPv6), ACK의 블록 하나·넷(번호 순환 포함)·데이터와 함께, 같은 옵션 둘, SYN에 실린 SACK 블록, SYN이 아닌 세그먼트의 SACK-Permitted, 길이가 틀린 SACK-Permitted(3)·SACK(2, 9), 머리 밖으로 나가는 SACK, 블록 5개.

`swiftailDiffers`는 **11개**다: IPv6 기본 MSS(Go 536, 계약 1220) 1개, MSS 0에서 Go가 옵션 해석을 중단하여 뒤 WS를 무시하는 사례 2개(IPv6 MSS도 536), 작은 MSS(Go 48, 계약 코덱 1) 1개, 옵션 오류에서 Go가 앞부분만 반환하지만 계약은 `malformed`로 버리는 7개(머리 밖으로 나가는 SACK과 블록 5개의 둘 포함)다. 작은 MSS는 코덱에서 올리지 않고 연결 상태 기계가 X9에 따라 64 미만을 거절한다. shift 15는 양쪽 모두 14로 읽으므로 차이 표시가 없다. 일반 `ParseTCPOptions`에 MSS·WS가 없다는 사실을 SYN 옵션의 동작 차이로 표시하지 않는다.

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

# ACME 기준 자료 생성 (`acmefixtures`)

`tailscale.com` v1.104.6의 `tempfork/acme`와 Go 1.27.3 표준 라이브러리를 직접 호출한다. Swift 소스는 읽거나 실행하지 않는다. `sha256("swiftail-fixtures/acme/<번호>")`를 `ecdsa.ParseRawPrivateKey`로 읽어 시험 키를 정한다. 첫 키와, 이후 X·Y 좌표의 첫 바이트가 각각 0인 키를 차례로 찾는다(최대 4096개 씨앗). **자료에 든 개인 키는 공개된 시험 전용 값이다. 운영에 쓰면 안 된다.** 네트워크·현재 시각·외부 난수는 자료 생성에 쓰지 않는다.

```sh
check_dir="$(eyebuild dir m7-acmefixtures)"
mkdir -p "$check_dir/tmp"
export TMPDIR="$check_dir/tmp" GOTMPDIR="$check_dir/tmp"
export GOPROXY=off GOSUMDB=off
fixture_tool="$(sh Scripts/build-interop-tools.sh acmefixtures)"
"$fixture_tool" Tests/SwiftailCertificatesTests/Fixtures
# 인자가 없으면 같은 JSON을 표준 출력에 쓴다.
"$fixture_tool" > "$check_dir/recreated.json"
cmp "$check_dir/recreated.json" Tests/SwiftailCertificatesTests/Fixtures/acme-fixtures.json
export GOCACHE="$(eyebuild dir interop-tools)/gocache"
export GOMODCACHE="$(eyebuild dir ref-src)/gomod"
export GOFLAGS=-mod=readonly
(cd Tools/interop && eyebuild run m7-acmefixtures -- go test -count=1 ./cmd/acmefixtures)
eyebuild rm m7-acmefixtures
```

폴더 인자가 있으면 `acme-fixtures.json`을 쓴다. `reference`에는 실제 빌드의 `go`·`tailscale` 버전이 있고, tailscale 버전이 다르거나 replace되어 있으면 거절한다. `caseCount: 22`는 다음 네 배열 길이의 합이다. 모든 hex는 소문자, base64url은 채움 없는 정규형이다.

| 배열 | 수 | 키와 뜻 |
| --- | --- | --- |
| `keys` | 3 | `id`(`account`, `leading-zero-x`, `leading-zero-y`), `testOnly: true`, 공개 씨앗 `seed`, 32바이트 개인 스칼라 `scalarHex`, 공개 JWK `publicKey`(`crv`, `kty`, 32바이트 좌표의 base64url `x`·`y`), RFC 7638 정규형 `jwkJSON` 문자열, `thumbprint`, SEC1 `sec1PEM`, PKCS#8 `pkcs8PEM` |
| `challenges` | 9 | `keyID`, `token`, `keyAuthorization`(`token.thumbprint`), `dns01TXT`(따옴표 없는 43바이트). 키마다 서로 다른 token 세 개 |
| `jws` | 6 | `keyID`, `mode`(`jwk`·`kid`), 복호화한 `protectedJSON`·`payloadJSON`, ASCII `signingInput`, `verifiedExample`(`protected`, `payload`, `signature`). 키마다 newAccount와 POST-as-GET 예 하나씩 |
| `csrs` | 4 | `name`, `keyID`, `domain`, 전체 CSR의 `derHex`, 서명 입력 DER의 `certificationRequestInfoHex`, `cnStringTag`(19 = PrintableString) |

CSR은 `account` 키로 짧은 이름(`a.ts.net`), 보통 이름(`rd-mac-1a2b3c4d.tail0001.ts.net`), 63자 레이블, 253자 이름을 만든다. 마지막 것은 DER 길이 경계 자료이며 `_acme-challenge.`를 붙이면 DNS 이름 한도를 넘으므로 실제 DNS-01 발급 대상 예시가 아니다. 각 CSR의 주체는 CN 하나, SAN은 같은 이름 하나, `ExtraExtensions`는 nil이다. x509가 SAN을 extensionRequest 속성에 넣는다.

값을 얻는 경로와 직접 호출할 수 없는 부분:

- JWK JSON과 JWS: 공개 `Client.Register`·`Client.GetAuthorization`이 만든 요청을 메모리 `http.RoundTripper`로 포착한다. 비공개 `jwkEncode`·`jwsEncodeJSON`을 복제하지 않는다. newAccount 본문은 `{}`, POST-as-GET 본문은 0바이트다. 가짜 URL은 `https://acme.invalid`, 고정 nonce는 `AAECAwQFBgcICQoLDA0ODw`, kid는 `https://acme.invalid/account/1`이다.
- 지문은 `acme.JWKThumbprint`, 키 인가는 `Client.HTTP01ChallengeResponse`(같은 내부 `keyAuth`), TXT는 `Client.DNS01ChallengeRecord`를 부른다.
- CSR의 `feature/acme.certRequest`는 비공개이고 이를 독립적으로 호출할 공개 경로가 없다. `ipn/ipnlocal/cert.go`는 feature hook으로 위임한다. 실제 발급 경로 `feature/acme/cert.go:578-589`의 `certRequest(key, domain, nil)`과 같은 일반 이름 템플릿(`certstore.go:306-320`)을 `x509.CreateCertificateRequest`에 넘긴다. wildcard는 이 자료의 범위 밖이다.
- 계정·인증서 키 저장의 SEC1 형식은 `encodeECDSAKey`(`certstore.go:323-330`)와 같은 `x509.MarshalECPrivateKey` + `pem.EncodeToMemory`이다. PKCS#8은 `x509.MarshalPKCS8PrivateKey`로 만든다. Go 저장소의 `parsePrivateKey`(`certstore.go:340-359`)와 같은 표준 파서를 쓰되 이 도구는 P-256만 받는다.
- 서명은 `crypto.Signer`가 `ecdsa.PrivateKey.Sign(nil, digest, opts)`를 불러 Go 표준 RFC 6979로 만든다. acme가 넘긴 난수 reader는 읽지 않는다. 자료 전체의 재현성을 위한 시험 정책이며 실제 Go 클라이언트의 무작위 서명 정책과 다르다. JWS·CSR 예는 생성 중 검증하며, 서명 바이트 자체는 Swift와 비교하지 않는다.

세 검증 명령은 **표준 입력으로 JSON 객체 한 개**를 받아 JSON 한 줄을 쓰고 끝난다. 성공은 종료 코드 0과 `ok:true`, 오류는 종료 코드 1과 `{"ok":false,"error":"한국어 설명"}`이다. 입력은 256KiB 이하, DER·PEM은 각각 64KiB 이하, JSON 중첩은 32단계 이하다. 중복 멤버·알 수 없는 필드·필드명의 잘못된 대소문자·뒤따르는 JSON·비정규 base64url은 거절한다. 명령은 파일을 쓰거나 네트워크를 열지 않는다.

`acmefixtures verify-jws` 입력:

```json
{"jws":{"protected":"<base64url>","payload":"<base64url 또는 빈 문자열>","signature":"<64바이트 R ‖ S의 base64url>"},"jwk":{"crv":"P-256","kty":"EC","x":"<32바이트 base64url>","y":"<32바이트 base64url>"},"expectedNonce":"AAECAwQFBgcICQoLDA0ODw","expectedURL":"https://acme.invalid/new-account"}
```

`expectedNonce`·`expectedURL`은 필수다. kid 머리에는 `expectedKID`도 필수이며, jwk 머리에서는 생략하거나 빈 문자열을 넣는다. 자료의 kid 예를 검증할 때 `expectedURL`은 `https://acme.invalid/authz/1`, `expectedKID`는 `https://acme.invalid/account/1`이다. 제공하는 공개 키는 자료에서 `keyID`로 찾은 `keys[].publicKey`, JWS는 `jws[].verifiedExample`이다.

성공 출력은 `{"ok":true,"protected":{…},"payloadHex":"<복호화한 본문 hex>","signingInput":"<protected.payload>"}`다. `protected`는 문자열이 아닌 객체다. ES256·64바이트 서명·P-256 곡선과 좌표 길이, jwk/kid의 배타성, 포함 JWK와 제공 공개 키의 일치, nonce·URL·kid와 기대값의 일치를 검사하고 `ecdsa.Verify`로 실제 서명 입력을 검증한다. 머리는 8KiB 이하, URL·kid는 2048바이트 이하 HTTPS이며 userinfo·fragment가 없어야 한다. 서버 계정 소유권이나 nonce 사용 이력은 검사하지 않는다. 본문은 JSON으로 재직렬화하지 않고 받은 바이트를 검증한다.

`acmefixtures verify-csr` 입력은 `{"derHex":"<CSR 전체 DER hex>"}`다. `x509.ParseCertificateRequest`와 `CheckSignature`가 모두 성공해야 한다. 성공 출력:

```json
{"ok":true,"commonName":"a.ts.net","dnsNames":["a.ts.net"],"publicKey":{"crv":"P-256","kty":"EC","x":"<32바이트 base64url>","y":"<32바이트 base64url>"},"signatureAlgorithm":"ECDSA-SHA256","certificationRequestInfoHex":"<DER hex>","cnStringTag":19}
```

CSR의 구문·자기 서명과 P-256 키를 검사한다. 이름·SAN·태그가 원하는 값인지와 Info 바이트가 같은지는 호출자가 비교한다. UTF8String도 유효한 CSR이면 받아들이고 `cnStringTag:12`를 반환한다.

`acmefixtures parse-key` 입력은 `{"pem":"-----BEGIN EC PRIVATE KEY-----\n…\n-----END EC PRIVATE KEY-----\n"}`다. SEC1 `EC PRIVATE KEY`는 `x509.ParseECPrivateKey`, PKCS#8 `PRIVATE KEY`는 `x509.ParsePKCS8PrivateKey`로 읽는다. 성공 출력은 `{"ok":true,"format":"EC PRIVATE KEY","publicKey":{"crv":"P-256","kty":"EC","x":"<32바이트 base64url>","y":"<32바이트 base64url>"}}`다. PKCS#8의 `format`은 `PRIVATE KEY`다. 단일 블록·PEM header 없음·앞뒤 쓰레기 없음·P-256만 허용한다. 개인 키 바이트는 결과에 넣지 않는다.

노트 7장 1·2대로 JWK 정규형·지문·키 인가·TXT는 **바이트 비교**, CSR Info는 같은 키·SAN 속성·CN 태그·DER 규칙을 택했을 때 **바이트 비교**한다. Go 보호 머리의 실제 순서는 `alg,jwk,nonce,url`과 `alg,kid,nonce,url`이지만, JWS JSON 순서·공백은 **의미 비교**한다. 서명은 Go↔Swift의 상대 검증이며 서명 바이트 일치를 요구하지 않는다. Go 시험은 저장 자료 일치·연속 재생성, 모든 예의 검증, 변조 JWS·CSR 거절, 순서를 바꿔 다시 서명한 JWS 수용, UTF8String CSR의 유효성과 Info 차이, 경계 입력 거절을 확인한다.

# Ed25519 검증 기준 자료 생성 (`ed25519fixtures`)

`sh Scripts/build-interop-tools.sh ed25519fixtures`로 빌드한다. 고정 씨앗으로 만든 입력마다 `ed25519consensus.Verify`(`zip215`)와 `crypto/ed25519.Verify`(`standard`, 공개 키 길이가 틀리면 Go가 panic하므로 거짓으로 적는다)의 판정을 쓴다. 인자로 폴더를 주면 `ed25519-verify.json`을 쓰고, 없으면 표준 출력에 쓴다. Swift 시험은 `SWIFTAIL_ED25519FIXTURES=<도구 경로>`이면 새로 뽑은 판정과도 견준다. `go test ./cmd/ed25519fixtures`는 연속 생성의 일치, 저장 자료(`Tests/SwiftailCryptoTests/Vectors/ed25519-verify.json`)와의 일치, 앞 196개가 `zip215_test.go`와 같음을 본다. 사례 종류: `zip215`, `valid`, `flipSignature`·`flipPublicKey`·`flipMessage`, `nonCanonicalS`, `highBits`, `smallOrderA`·`smallOrderZeroS`, `nonCanonicalA`·`nonCanonicalR`, `torsionR`·`torsionA`, `offCurve`, `length`.

# Argon2i 기준값 생성 (`argon2fixtures`)

`sh Scripts/build-interop-tools.sh argon2fixtures`로 빌드하고, 인자 없이 실행하면 `golang.org/x/crypto` `argon2.Key` 출력 75개를 JSON으로 표준 출력에 쓴다(`argon2fixtures > Tests/SwiftailCryptoTests/Vectors/argon2i-go.json`). 마지막 항목은 TKA 끄기 비밀의 인자 그대로이며 `tka.DisablementKDF`와 다르면 실패한다. 입력은 시험 전용 고정 패턴이다. Swift 시험은 `SWIFTAIL_ARGON2FIXTURES=<경로>`가 있으면 새로 뽑아 견준다.

# 페어링 기준 벡터 생성 (`pairingvectors`)

`sh Scripts/build-interop-tools.sh pairingvectors`로 빌드하고, 인자 없이 실행하면 페어링 절차(`docs/contracts/SwiftailPairing.md` 5절)의 고정 벡터 4개를 JSON으로 표준 출력에 쓴다(`pairingvectors > Tests/SwiftailPairingTests/Fixtures/pairing-vectors.json`). 계약의 글만 보고 Go 표준 라이브러리(`crypto/hmac`, `crypto/sha256`, `net/netip`)로 썼고 Swift 구현은 읽거나 호출하지 않는다. 벡터마다 입력(`secret`, `offerHost`, `offerPort`, `deviceName`, 두 nonce, 연결의 두 끝)과 그 결과인 `commitment`(들어오는 쪽 nonce의 약속), `hello`(판 2), `challenge`(상태 0)·`challengeNoOffer`(상태 1), `transcript`(T, 198바이트), `proof`(nonceJ ‖ HMAC), `accepted`, `confirmationCode`, `approved`·`denied`·`timedOut`(`decision`의 본문 ‖ HMAC)를 16진으로 싣는다. 입력은 시험 전용 고정 패턴이다. 경우: IPv4의 두 끝, IPv6의 두 끝과 한글 기기 이름·빈 표시 이름, 가장 긴 이름들(기기 이름 64바이트, `StableID` 255바이트, 표시 이름 64바이트), 확인 숫자가 0으로 시작하는 것(들어오는 쪽 nonce의 첫 바이트를 0부터 올려 처음 나오는 값). `go test ./cmd/pairingvectors`는 연속 생성의 일치와 저장 자료와의 일치를 본다. Swift 시험(`ProtocolVectorTests`)은 저장 자료를 코덱·계산 하나하나와 견주고, 두 상태 기계를 맞물려 선 위의 바이트가 같은지 본다.

# TKA 기준 자료 생성 (`tkafixtures`)

Tailnet Lock 계약(`docs/contracts/SwiftailTailnetLock.md`) 7절 "Go 기준값 대조"의 도구다. `tailscale.com` v1.104.6의 `tka` 패키지가 낸 판정을 JSON으로 쓴다. Swift 소스는 읽거나 실행하지 않는다. 네트워크·현재 시각·외부 난수를 쓰지 않는다. 키는 모두 `SHA-256("swiftail-fixtures/tka/<역할>/<번호>")`를 Ed25519 씨앗이나 node 키(X25519 개인 키) 입력으로 쓴다(역할: `lock`·`nl`·`credential`·`fork`·`node`·`disablement`). **자료에 든 개인 키는 공개된 시험 전용 값이다.** Go의 Ed25519 서명은 결정적이라 다시 뽑아도 같은 바이트가 나온다.

```sh
check_dir="$(eyebuild dir tl5-fixtures)"
mkdir -p "$check_dir/tmp"
export TMPDIR="$check_dir/tmp" GOTMPDIR="$check_dir/tmp"
export GOCACHE="$(eyebuild dir interop-tools)/gocache"
export GOMODCACHE="$(eyebuild dir ref-src)/gomod"
export GOFLAGS=-modcacherw GOPROXY=off GOSUMDB=off
fixture_tool="$(sh Scripts/build-interop-tools.sh tkafixtures)"
# 현재 폴더는 Tools/interop여야 한다(피어 집합의 overlay 빌드가 그 go.mod를 쓴다).
(cd Tools/interop && "$fixture_tool" ../../Tests/SwiftailTKATests/Fixtures)
# 인자가 없으면 같은 JSON을 표준 출력에 쓴다.
(cd Tools/interop && "$fixture_tool" > "$check_dir/recreated.json")
cmp "$check_dir/recreated.json" Tests/SwiftailTKATests/Fixtures/tka-fixtures.json
(cd Tools/interop && go vet ./cmd/tkafixtures && go test -count=1 ./cmd/tkafixtures)
eyebuild rm tl5-fixtures
```

`GOCACHE`가 비어 있으면 실행하지 않는다(홈의 Go 캐시를 만들지 않게). `go test`는 연속 생성의 일치, 저장 자료와의 바이트 일치, `caseCount`가 0이 아니고 배열 길이의 합과 같음, 파일이 2MB 이하임, `genesis.go`에 옮긴 Go 시험 값이 원본 시험 파일에 그대로 있음, `verify-nks`가 자료와 같은 판정을 내고 잘못된 입력을 거절함을 본다.

판정은 모두 `tka`의 공개 API가 낸다: `AUM.Unserialize`·`StaticValidate`·`Serialize`·`Hash`·`SigHash`, `NodeKeySignature.Unserialize`·`Serialize`·`SigHash`, `Bootstrap`·`Inform`·`Head`·`Keys`·`StateIDs`, `SyncOffer`·`MissingAUMs`·`FromSyncOffer`, `NodeKeyAuthorizedWithDetails`, `ValidDisablement`·`DisablementKDF`, `DecodeWrappedAuthkey`·`SignByCredential`·`ResignNKS`, `MakeRetroactiveRevocation`, `AUMHash.String`·`UnmarshalText`, `key.NLPublic`·`NLPrivate`·`NodePublic`의 텍스트. 예외는 둘이다.

- 상태의 끄기 값은 공개 접근자가 없다. `ChonkMem.AUM`으로 머리부터 거꾸로 가 처음 만나는 체크포인트의 `State.DisablementValues`를 읽는다(Go의 상태 적용은 체크포인트에서만 이 값을 바꾼다, `tka/state.go:162-254`).
- 피어 거르기(`rotationTracker` 포함)는 `ipn/ipnlocal`의 내보내지 않은 함수다. `mapfixtures`와 같이 `tailscale.com`을 `eyebuild dir interop-tools` 아래 임시 사본으로 복사하고, `-overlay`로 `ipn/ipnlocal/swiftail_fixtures.go`(`bridge.go.txt`) 한 파일을 얹어 실제 `tkaFilterNetmapLocked`를 부르는 작은 프로그램(`worker.go.txt`)을 빌드해 실행한다. 거르기 로직을 옮겨 적지 않는다. 모듈 캐시는 고치지 않고 임시 사본은 끝나면 지운다.
- Key·State 단독의 정준 바이트(`encodings`)는 `tka`가 따로 `Serialize`하지 않으므로 `tka`와 같은 인코더 설정 `cbor.CTAP2EncOptions()`로 만든다.

일부러 틀리게 만든 입력은 CBOR 바이트를 직접 조립한다(`cbor.go`의 `rawAUMCases`·`rawNKSCases`, `chains.go`의 서명된 AUM 변형). 위수 2인 점을 R에 더한 서명과 비정준 항등원 공개 키의 서명은 `filippo.io/edwards25519`로 계산한다(`keys.go`).

출력은 JSON 객체 하나이고 배열 원소 하나를 한 줄에 쓴다. 바이트는 모두 소문자 16진이고 nil은 `null`이다(빈 바이트열은 `""`). 64비트 StateID는 10진 문자열이다. 최상위 키:

| 키 | 내용 |
| --- | --- |
| `reference` | `go`·`tailscale` 버전. tailscale이 v1.104.6이 아니거나 replace되어 있으면 거절한다 |
| `caseCount` | 아래 시나리오 배열 길이의 합(`sync`는 안쪽 `cases`의 수). `keys`·`authorities`는 세지 않는다 |
| `keys` | 시험 키: `role`, `index`, `seed`(SHA-256 입력 문자열), `private`(씨앗 32바이트), `public`, `text`(`tlpub:`·`nodekey:`) |
| `authorities` | 판정에 쓰는 신뢰 상태: `name`, `aums`(첫 것이 부트스트랩, 나머지는 한 묶음의 `Inform`), `head`, `state` |
| `text` | `kind`(`aumHash.encode`·`aumHash.decode`·`nlPublic.*`·`nlPrivate.*`·`nodePublic.*`), `input`, `ok`, `output`, `error` |
| `encodings` | Key·State 값(`value`)과 정준 CBOR(`encoded`) |
| `cbor` | `type`(`aum`·`nks`), `input`, `decoded`, `staticValid`(AUM만, NKS는 null), `accepted`(AUM은 디코딩과 정적 검사 통과, NKS는 디코딩), `error`, 디코딩했으면 `reencoded`·`canonical`(재인코딩이 입력과 같음)·`hash`(AUM)·`sigHash` |
| `chains` | `bootstrap`, `bootstrapOK`, `bootstrapError`, `initial`(상태), `steps`(`name`, `aums`: 한 번의 `Inform`에 넣은 바이트, `ok`, `error`, `after`: 단계 뒤의 상태) |
| `sync` | 묶음마다 `pool`(AUM 바이트)과 `cases`. 사례의 `local`·`remote`는 `aums`(pool 번호, 첫 것으로 부트스트랩), `offer`(16진과 `FromSyncOffer` 텍스트), `missing`(상대 제안에 대한 `MissingAUMs`: `ok`, `error`, `count`, `digest` = 해시들을 이은 것의 SHA-256, 100개 이하면 `hashes`), 상대의 목록을 들인 `informOK`, `headAfter` |
| `signatures` | `authority`, `nodeKey`(32바이트), `nks`, `sigHash`(디코딩되면), `authorized`, `error`, `rotation`(`prevNodeKeys` 새것부터, `initialKind`, `initialWrappingPubkey`) |
| `peerSets` | `authority`, `peers`(`nodeKey`, `signature`, `unsignedPeerAPIOnly`), `kept`(`tkaFilterNetmapLocked`가 남긴 node 키, 순서 유지) |
| `disablement` | `authority`, `secret`, `kdf`(`DisablementKDF`), `valid`(`ValidDisablement`) |
| `authKeys` | `input`, `DecodeWrappedAuthkey`의 `authKey`·`isWrapped`·`returnedInput`(원문 전체를 돌려줬는지)·`credential`(재인코딩)·`privateKeyLength`, 감싼 것이면 `SignByCredential`(node/8)의 `sign`(`ok`·`error`·`panic`)·`signError`·`nks`, 신뢰 상태가 있으면 `verdict` |
| `resign` | `nlKey`(키의 seed 문자열), `oldNKS`, `nodeKey`, `ResignNKS`의 `ok`·`error`·`result`·`sigHash`·`sameAsOld`·`depth`, 결과의 `verdict` |
| `unorderedPeerSets` | Go의 답이 맵 순회 순서로 갈리는 피어 집합: `authority`, `peers`, `runs`(같은 입력으로 돌린 횟수, 256), `outcomes`(나온 서로 다른 `kept`를 정렬한 것). `peerSets`의 사례는 `runs`(64)번 모두 같은 답이어야 생성이 성공한다 |
| `limits` | 뿌리에서 2,000개가 넘는 사슬: 묶음마다 `pool`(같은 AUM을 쓰는 `sync` 묶음 이름), `extra`(그 pool 뒤에 잇는 AUM), `cases`(`baseCount`: 번호 0부터 그만큼으로 부트스트랩+한 묶음, `baseHead`, `steps`: `aums` 번호, `ok`, `error`, `head`) |
| `padded` | Swiftail 바이트 한도(NKS 8KiB, AUM 512KiB)를 넘긴 입력. 바이트 대신 만드는 법을 싣는다: 입력 = (`base`의 맵 머리 + 1) ‖ `base[1:]` ‖ uint(`padKey`) ‖ bstr(0 × `padLength`), 길이 `length`. `kind`(`authorize`·`resign`·`inform`·`authKey`)마다 Go의 `ok`·`error`·`head`·`sigHash`·`verdict`. `authKey`의 입력 문자열은 `controlValue` ‖ `--TL` ‖ RawStd(입력) ‖ `-` ‖ RawStd(`privateKey`) |
| `openedStates` | Bootstrap으로는 만들 수 없는 상태(Key25519가 아닌 키)를 `CommitVerifiedAUMs`·`SetLastActiveAncestor`·`tka.Open`으로 연 뒤의 `NodeKeyAuthorizedWithDetails`: `checkpoint`, `openOK`, `nodeKey`, `nks`, 판정 |
| `reviewChains` | TL-11a 검토가 더한 사슬(`review.go`). 모양은 `chains`와 같다 |
| `reviewSignatures` | TL-11a 검토가 더한 NKS 판정(`review.go`). 모양은 `signatures`와 같다 |

`caseCount`에는 `unorderedPeerSets`·`padded`·`openedStates`·`reviewChains`·`reviewSignatures`의 줄과 `limits`의 `cases`도 든다.

`cbor` 사례 이름의 앞머리는 노트·계약이 예상한 디코딩 판정이다: `accept/`는 디코딩되는 것, `reject/`는 디코딩에서 거절되는 것(자료에서 그대로 맞는지 확인했다), `probe/`는 노트·계약이 Go 판정을 실행으로 확인하지 않았던 입력, `value/`는 `tka.AUM` 값을 `Serialize`한 정적 검사의 경계다. 판정 자체는 이름이 아니라 `decoded`·`accepted`로 견준다. 계약 동작 E6·D8대로 정적 검사를 통과하지 못한 AUM은 Swift가 판정만 견준다.

시나리오(계약 7절의 1~8):

- `cbor`: 노트 8.1의 받아들임·거절 표 전부, 모르는 필드 값의 모든 주요 타입·단순값(한 바이트 0~19·99·255, 두 바이트 0·23·24·31·32), 음수·정수 키의 끝값(−2^63, −2^63−1, −2^64, 2^63−1, 2^63, 2^64−1), 텍스트 키, 비최단 정수·길이·맵 머리, 알려진 필드마다 null·undefined, `Signatures`의 null 원소, 비최단으로 쓴 같은 키의 중복, 구조·`Meta`·Key·State·Signature 맵의 중복, 길이 미정·태그·예약된 추가 정보 28~30·31·`break`, 맨 바깥이 맵이 아닌 것(null·undefined 포함), 바이트열 자리의 정수 배열, 중첩 16/17단(배열·맵), 배열 4096/4097, 맵 1024/1025(값 안과 맨 바깥), 정적 검사의 종류별 필수·금지 필드와 경계(`Votes` 0·1·4096·4097, `Meta` 512·513바이트, 서명 KeyID 31·32·33·서명 63·64·65바이트, 끄기 값 0·1·32·33개·31·33바이트·중복, 키 0·1·512·513개·중복, `PrevAUMHash` 0·1·33바이트), NKS의 디코딩 변형.
- `chains`: 직선 사슬(AddKey → UpdateKey(`Votes`, `Meta`) → RemoveKey → NoOp → Checkpoint → AddKey → 묶음 셋), 부트스트랩(나중 체크포인트, Go 시험의 genesis, 체크포인트 아님, 서명 없음, 믿지 않는 키, `LastAUMHash` 있음, 틀린 서명), 거절(빈 묶음, 서명 없음, 모르는 키 섞임, 틀린 서명, 부모 없음, 부모 모름, 31·33바이트 `PrevAUMHash`, 중복 AddKey, StateID가 다른 체크포인트, 없는 키의 Remove/Update, `Votes` 0·4097로 갱신, 서명된 정적 위반, 틀린 AUM이 든 묶음(앞·뒤), 이미 쥔 AUM, 순서가 뒤바뀐 묶음, 마지막 키 제거, 지운 키의 서명), 받아들여지는 이상한 것(종류 0·9·255, 필드를 더 실은 NoOp, `Public`이 null·빈 값·31·33바이트인 AddKey와 그 뒤의 Remove/Update/체크포인트, 모르는 필드와 비최단 정수, 정렬 안 된 키, 바이트열을 정수 배열로 쓴 `PrevAUMHash`·서명, `Meta` 값의 null, 각각의 다음 AUM), ZIP-215(위수 2 성분의 R, 비정준 항등원 공개 키), 갈래(가중치, 서명 둘 대 하나, 같은 키 두 번, RemoveKey 우선, 해시, 진 갈래의 자손, 소급 철회 체크포인트, 여러 단과 갈래를 만드는 묶음). 갈래 사례는 앞 규칙의 답이 해시 비교와 다르도록 해시의 대소를 골랐다.
- `sync`: `basic`(같은 머리, 뒤처짐, 앞섬, 갈라짐, 상대만 아는 체크포인트, 상대가 genesis뿐, 교차 없음), `checkpoint-51`(51번째 체크포인트의 조상 목록, 머리 교차), `long`(체크포인트 깊이 999·1000으로 조상 목록 1000회 한도, 앞으로 감기 1999·2000회로 2000회 한도).
- `signatures`: direct(회전 키 유무, 다른 node 키, 믿지 않는 키, 지운 키, `Nested`가 붙음, 31바이트 신뢰 키, 틀린 서명, ZIP-215 전용 서명, 비정준 항등원 키, KeyID·Pubkey 없음, 종류 0·4, 뒤 바이트, 모르는 필드), credential 혼자, rotation 1~16겹, 중간 `WrappingPubkey`, 회전 키 없음·31바이트, `np`가 아닌 안쪽 Pubkey, 바깥의 ZIP-215 전용 서명, `Nested` 없음, 다른 서명 키, credential → rotation(다른 node 키, 믿지 않는 credential, 다른 서명 키, `np` Pubkey, 쓰레기 Pubkey, 그 위의 rotation).
- `peerSets`: 서명 없음·틀린 서명·`UnsignedPeerAPIOnly`, 회전으로 낡은 키, 같은 회전 키 묶음의 가장 긴 내력, 같은 길이면 모두 빠짐, 낡은 키는 묶음에서 빠짐, credential 사슬은 묶지 않음, 다른 회전 키, 지운 서명 키.
- `disablement`: 0xa5 × 32(KDF `c3fea8a0…4e2f`), 끄기 값 셋 가운데 맞는 것, 틀린 것, 빈 비밀, 31바이트, 체크포인트로 값이 바뀐 앞뒤.
- `authKeys`: Go 시험 문자열(`tka/sig_test.go:479`), 정상, 감싸지 않음, `-` 없음, 채움 붙은 base64, URL 알파벳, `-`가 더 있음, CBOR이 아님, credential이 아닌 A, 32·63·65바이트 B(Go panic), 뒤 32바이트가 다른 B, `WrappingPubkey`가 다른 A, 믿지 않는 credential, 빈 두 부분.
- `resign`: 같은 node 키(그대로), 회전 키가 NL 키인 direct, 다른 NL 키, 회전 키 없는 direct, credential 사슬, Pubkey 14~17개 사슬(16개부터 줄임, 17개는 디코딩 거절), 디코딩되지 않는 옛 서명.

TL-5 대조 시험이 더한 것(계약 5절 "구현하며 정해진 것"에서 실행으로 확정하지 않았다고 적은 입력과, Swiftail 한도의 경계):

- `cbor`: 정수 필드의 단순값(`MessageKind` `e3`·`f3`·`f863`·`f8ff`, `Votes` `f820`, Key의 `Kind`·`Votes` `e1`, `StateID` `e7`, NKS `SigKind` `e1`·`f8c8`), `MessageKind` false, 바이트열 자리 정수 배열의 단순값·null(`8401e5f618ff`)·undefined·true·실수·배열 원소, `Meta` 키의 단순값·undefined·false와 값의 단순값, `Meta`의 null 키와 빈 키의 중복, 구조 맵의 단순값 키.
- `text`: `AUMHash` 텍스트 안의 `\r`·`\n`(50·51·48자 + 줄바꿈, 가운데·앞, 52자 + 줄바꿈).
- `chains`: `batch-duplicates`(한 묶음 안의 같은 AUM: 두 번, 자식을 사이에 둔 두 번, 이미 쥔 것 두 번, 갈래 두 번, 서명 없는 것 두 번, 자식 뒤의 부모).
- `sync`: `long`의 `head-intersection-distance-999`·`-1000`(머리 교차 1,000회를 넘어 꼬리 교차로 넘어가는 경계).
- `signatures`: rotation 안쪽 direct의 빈 `Pubkey`, 가운데 rotation의 빈 `Pubkey`.
- `peerSets`: `UnsignedPeerAPIOnly` 피어가 회전으로 낡은 키가 됨, 그런 피어의 rotation은 다른 피어를 낡은 키로 만들지 않음. `unorderedPeerSets`: 같은 node 키가 서로 다른 회전 키의 묶음에 함께 듦.
- `authKeys`: credential·감싼 키 base64의 0이 아닌 남는 비트, 줄바꿈(`\n`, `\r\n`, 끝의 `\n`).
- `limits`: 뿌리에서 2,000개가 넘는 직선 사슬(빠른 길), 뿌리에서 1,999·2,000번째 갈래, 이미 쥔 AUM이 섞인 묶음과 그 뒤(실패한 묶음이 Go 저장소에 남는다), 체크포인트부터 부모까지 2,000·2,001개.
- `padded`: NKS 8,192·8,193바이트의 판정, 재서명의 옛 서명 8,193바이트, AUM 524,288·524,289바이트의 들이기, credential 8,193바이트의 감싼 인증 키.
- `openedStates`: Key25519가 아닌 키가 서명 키 앞·뒤에 있는 상태.

TL-11a 검토(`SwiftailTKA` 보안 검토)가 더한 것(`review.go`, Swift 쪽 대조는 `TKAReviewTests.swift`):

- `reviewChains`: 서명 목록만 바꾼 변종(서명 되풀이로 해시가 더 작은 변종이 원본을 이기고 원본의 자식 RemoveKey가 진 갈래에 남음, 더 큰 변종은 짐, 한 묶음에 원본·변종을 두 순서로), 서명 둘의 순서만 바꾼 형제, 서명 목록 변조(믿지 않는 키 덧붙임, 틀린 사본 앞·뒤, 다른 AUM의 서명, 빈 목록, 같은 서명 1,024번), 모르는 필드로 1KiB 부풀린 사본과 원본, 지운 키를 같은 KeyID로 다시 더하기(그 사이의 서명, 두 번 더하기, 마지막 키 제거), Votes 0·4,096·4,097과 Meta 512·513바이트(AddKey·UpdateKey), 빈 Meta(`07a0`)만 있는 UpdateKey와 Votes·Meta가 다 없는 UpdateKey, `Votes` 최댓값으로 갱신, 무거운 서명 둘 대 가벼운 하나, 진 갈래 안의 체크포인트(그 아래는 체크포인트의 키로 검증), 같은 AUM 나무를 세 순서의 한 묶음·나눈 묶음·자식이 먼저인 묶음으로, 지울 키가 더 무거울 때 지워진 키가 옛 부모에서 만든 형제, 부모 해시가 31·32·33바이트·빈 값인 체크포인트의 부트스트랩, 믿지 않는 서명이 섞이거나 서명을 되풀이한 부트스트랩.
- `reviewSignatures`: direct·rotation 서명 63·65·0바이트, 33바이트 회전 키, 같은 node 키로의 회전, 바깥 rotation의 KeyID(쓰이지 않음), 회전 키가 신뢰 키 자신, 지운 키(전후)의 credential, credential을 감싼 rotation 위의 rotation(가운데 `WrappingPubkey`, 틀린 서명 키), 잘린 NKS, 비최단 `SigKind`.

`tkafixtures verify-nks`는 표준 입력으로 JSON 객체 하나 `{"aums":["<16진>",…],"nodeKey":"<32바이트 16진>","nks":"<16진>"}`를 받는다. `aums`의 첫 것으로 부트스트랩하고 나머지를 `Inform`한 상태에서 `NodeKeyAuthorizedWithDetails`로 판정해 `{"ok":true,"authorized":…,"error":…,"rotation":…}` 한 줄을 쓰고 0으로 끝난다(판정이 거절이어도 0이다). 입력이 4MiB를 넘거나, JSON 객체 하나가 아니거나, 모르는 필드·대문자 16진이 있거나, 부트스트랩·`Inform`이 실패하면 `{"ok":false,"error":"…"}`를 쓰고 1로 끝난다. Swift가 만든 서명(`SignByCredential`·재서명. CryptoKit 서명은 결정적이지 않다)을 이것으로 확인한다.

# 인증 키 발급 기록 서버 (`authkeyrecorder`)

M9 관문 (가) 7(`docs/contracts/SwiftailPairing.md` 7절)의 도구다. Go의 인증 키 발급 흐름과 Swift `AuthKeyIssuer`가 같은 서버에 보낸 요청을 견주게 한다. 빌드는 `sh Scripts/build-interop-tools.sh authkeyrecorder`. 의존성은 `golang.org/x/oauth2` v0.37.0(BSD-3-Clause)과 `tailscale.com` v1.104.6의 공개 `client/tailscale`(BSD-3-Clause)이다. 실제 관리 API(`api.tailscale.com`)는 부르지 않는다.

`authkeyrecorder serve [-reject-basic]`는 `127.0.0.1`의 임의 포트에서 듣고 표준 출력의 첫 줄에 서버 URL(`http://127.0.0.1:12345`)을 쓴다. 표준 입력이 닫히면(EOF) 끝난다. `-reject-basic`이면 `Authorization`이 있거나 폼에 `client_id`·`client_secret`이 없는 토큰 요청을 401 `{"error":"invalid_client"}`로 거절한다(요청은 적는다). 두 클라이언트가 머리 방식에서 본문 방식으로 다시 묻는 길을 견주는 데 쓴다.

- `/api/v2/oauth/token`: 요청을 적고 `{"access_token":"tskey-api-EXAMPLE-token","token_type":"Bearer","expires_in":3600}`을 돌려준다.
- `/api/v2/tailnet/-/keys`: 요청을 적고 `{"id":"kEXAMPLE","key":"tskey-auth-EXAMPLE","created":"2026-01-01T00:00:00Z","expires":"2026-01-01T00:10:00Z","capabilities":{…}}`를 돌려준다.
- `GET /recorded`: 적은 요청을 받은 순서대로 JSON 배열로 내놓고 비운다. 한 줄은 `{"method","path","authorization","contentType","body","json","form"}`이다. `json`은 본문이 JSON이면 키를 정렬해 다시 쓴 것, `form`은 JSON이 아닌 폼 본문이면 `url.Values.Encode()`로 다시 쓴 것(키 정렬)이고 아니면 `""`다. 본문은 64KiB까지만 읽는다.

기록 서버는 받은 `Authorization` 머리를 그대로 내놓는다. 가짜 값만 다루는 시험 도구이므로 실제 OAuth 클라이언트 비밀을 넣지 않는다.

`authkeyrecorder issue -base <서버 URL> -tags tag:a,tag:b -expiry <초>`는 `cmd/get-authkey`(tailscale.com v1.104.7)와 같은 짜임으로 키 하나를 만들어 표준 출력에 쓴다: `clientcredentials.Config{TokenURL: <base>/api/v2/oauth/token}.Client`를 HTTP 클라이언트로 쓰는 `tailscale.NewClient("-", nil)`의 `CreateKeyWithExpiry`. get-authkey가 쓰는 `internal/client/tailscale`은 모듈 밖에서 쓸 수 없어 같은 코드의 공개 패키지를 쓰고 `I_Acknowledge_This_API_Is_Unstable`을 켠다. get-authkey의 `CreateKey`는 만료가 0(본문에서 `expirySeconds` 생략)이므로 수명을 주는 `CreateKeyWithExpiry`를 부른다. 클라이언트 ID와 비밀은 get-authkey처럼 `TS_API_CLIENT_ID`·`TS_API_CLIENT_SECRET`에서 읽는다. `-base`는 루프백 주소의 `http`만 받는다. 키의 `reusable`·`ephemeral`·`preauthorized`는 계약 4절 K3대로 거짓·거짓·참으로 고정한다. 머리 방식이 실패하면 `x/oauth2`가 본문 방식으로 한 번 다시 묻는다(`internal/token.go` `RetrieveToken`). 보통의 `serve`에서는 첫 시도가 200이라 다시 묻지 않는다.

Go `client/tailscale`은 키 요청에 `Content-Type`을 싣지 않는다(`keys.go`의 `CreateKeyWithExpiry`, `tailscale.go`의 `Do`). Swift는 `application/json`을 싣는다. 관문 시험은 이 차이를 따로 확인하고 나머지(요청 수와 순서, 메서드, 경로, `Authorization` 값 전체(본문 방식은 빈 값), 토큰 요청의 `Content-Type`, 폼·JSON 본문의 정규형)는 같아야 한다. 보통의 `serve`와 `-reject-basic` 둘 다 견준다.

Swift 시험은 `SWIFTAIL_AUTHKEYRECORDER`에 도구 경로를 넣어 돌린다. 값이 없으면 건너뛴다.

```sh
SWIFTAIL_AUTHKEYRECORDER="$(sh Scripts/build-interop-tools.sh authkeyrecorder)" eyebuild swift <용도> -- test --filter AuthKeyInteropTests
```
