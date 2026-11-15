# SwiftailDERP 계약 (M3)

DERP 중계 서버 하나와의 연결이다. 프레임 해석과 핸드셰이크는 **입출력 없는 값 타입 상태 기계**(`DERPConnection`)가 맡고, TLS 소켓·시계·재연결은 그것을 감싼 actor(`DERPClient`)가 맡는다.

프로토콜 세부는 [protocol-notes/derp-stun.md](../protocol-notes/derp-stun.md)(검증됨)를 따른다. 이 문서는 모듈 경계와 M3 범위만 정한다.

## 타깃

| 타깃 | 의존 | 내용 |
| --- | --- | --- |
| `SwiftailBase` | Foundation, Network | 기존 내용 + **키 타입**(`PrefixedKey`와 그 별칭. `SwiftailControl/Keys.swift`에서 옮긴다) |
| `SwiftailIO` (새 타깃, 제품으로 내보내지 않는다) | Foundation, Network, Synchronization | 가장자리 입출력의 공용 부품. 선언은 `package` 접근 수준이다 |
| `SwiftailDERP` | `SwiftailBase`, `SwiftailCrypto`, `SwiftailIO`, CryptoKit | 아래 API |

`SwiftailDERP`는 `SwiftailControl`에 의존하지 않는다. DERPMap(tailcfg)에서 연결 정보를 뽑아 넘기는 일은 엔진이 한다.

## 단위 0: 공용 부품 정리

M2의 `ControlClient`와 M3의 `DERPClient`가 같은 것을 둘씩 갖지 않게, 구현 전에 다음을 옮긴다. 동작은 바꾸지 않는다(기존 시험과 M2 관문이 그대로 통과해야 한다).

1. `Sources/SwiftailControl/Keys.swift` → `Sources/SwiftailBase/Keys.swift`. 공개 이름은 그대로다. 시험도 `SwiftailBaseTests`로 옮긴다. `PrefixedKey.init(_: Curve25519.KeyAgreement.PublicKey)`(지금 `NodeIdentity.swift`에 internal로 있다)도 같이 옮겨 `public`으로 둔다.
2. 새 타깃 `SwiftailIO`에 `package` 접근 수준으로 둔다:
   - `NetworkSocket`: NWConnection 하나를 async 바이트 스트림으로 감싼다(지금 `SwiftailControl/Client/NetworkSocket.swift`). 오류는 자체 타입 `SocketError`(연결 실패, 읽기 실패. 쓰기는 기다리지 않으므로 그 실패는 다음 읽기에서 드러난다)로 내고 `ControlError`로 옮기는 일은 부르는 쪽이 한다. TLS는 세 가지다: 없음, 시스템 검증(서버 이름 지정), 시험용 검증 생략(서버 이름 지정). `write`는 네트워크 스택이 바이트를 받아 갈 때까지 기다리고(`send`는 기다리지 않는다), 버린 소켓은 연결을 닫는다.
   - `withTimeout`(지금 `Client/Timeout.swift`).
   - `Backoff.delay(failures:maximum:jitter:)`: `min(n² × 10ms, maximum) × (0.5 + jitter)`, `jitter`는 [0, 1)의 난수. 제어(30초)와 DERP(5초)가 같은 식에 상한만 다르다(Go도 `util/backoff` 하나를 쓴다). `RetryPolicy`의 `Retry-After` 해석은 제어 쪽에 남긴다.
   - `HTTPResponseHead`: HTTP/1.1 응답 머리를 조각난 입력에서 읽어 상태 코드와 헤더, 머리 뒤에 이미 도착한 바이트를 돌려준다(16KiB 한도, 줄 안의 제어 문자 거절, 실패 시 버퍼 비움). `UpgradeResponseParser`는 이것을 써서 `Upgrade` 값만 검사하는 얇은 층이 된다. 공개 API와 오류 종류는 그대로다.
3. `Package.swift`에 M3 타깃을 미리 만든다(자리만): `SwiftailIO`, `SwiftailDERP`, `SwiftailEngine`, `Swiftail`과 시험 타깃 `SwiftailIOTests`, `SwiftailDERPTests`, `SwiftailDERPInteropTests`, `SwiftailEngineTests`, `SwiftailInteropTests`. 뒤 단위들이 `Package.swift`를 건드리지 않고 병렬로 일하게 하기 위해서다.

## 공개 API

```swift
/// DERP 서버 하나에 닿는 방법. 엔진이 `tailcfg.DERPNode`에서 뽑는다.
public struct DERPServer: Sendable, Equatable {
    /// TLS 서버 이름이자 HTTP `Host`.
    public var hostName: String
    /// 연결을 걸 곳들. `DERPClient`가 모두 함께 걸어 먼저 붙는 연결을 쓰고 나머지는 닫는다. 비어 있으면 붙을 수 없다.
    public var targets: [Target]
    public var port: UInt16
    public var verification: Verification

    public enum Target: Sendable, Equatable {
        /// `hostName`을 DNS로 찾아 건다. 찾은 주소 가운데 어느 쪽으로 걸지는 Network 프레임워크가 고른다.
        case hostName
        /// 이 IP 주소로 건다.
        case address(IPAddress)
    }

    public enum Verification: Sendable, Equatable {
        /// 시스템 신뢰 저장소로 `hostName`을 검증한다.
        case system
        /// 검증하지 않는다. DERPMap이 `InsecureForTests`인 노드에만 쓴다.
        case noneForTests
    }
    public init(hostName: String, targets: [Target] = [.hostName], port: UInt16 = 443, verification: Verification = .system)
}

public enum DERPError: Error, Sendable, Equatable {
    case malformed                    // 프레임·응답 머리·JSON이 규격과 다름
    case upgradeRejected(status: Int) // 101이 아님
    case handshakeFailed              // ServerKey 검증 실패, ServerInfo를 열지 못함
    case frameTooLarge                // 받은 프레임 본문이 한도를 넘음
    case tooManyPendingReplies        // 답해야 할 Ping이 한도를 넘게 쌓임
    case packetTooLarge               // 보낼 패킷이 65,536바이트를 넘음
    case notReady                     // 핸드셰이크가 끝나기 전에 send를 부름
    case closed                       // 실패한 뒤의 호출
}

/// DERP 연결 하나의 상태 기계. 소켓·시계·난수를 갖지 않는다.
///
/// 만들자마자 `takeOutboundBytes()`가 HTTP 업그레이드 요청을 내놓는다. 서버가 보낸 바이트를 `receive`에
/// 넣으면 101 응답 → ServerKey → (ClientInfo와 NotePreferred를 내보냄) → 준비 순서로 나아간다.
public struct DERPConnection: Sendable {
    public enum Event: Sendable, Equatable {
        /// 핸드셰이크가 끝났다. 이제 `send`를 부를 수 있다.
        case ready
        /// 피어가 이 서버를 거쳐 보낸 패킷. 내용(WireGuard인지 disco인지)은 보지 않는다.
        case packet([UInt8], from: NodePublicKey)
        /// 서버가 그 피어를 이제 모른다.
        case peerGone(NodePublicKey, reason: PeerGoneReason)
    }
    public enum PeerGoneReason: Sendable, Equatable { case disconnected, notHere, unknown(UInt8) }

    /// - Parameters:
    ///   - privateKey: 이 노드의 node 개인 키(WireGuard 키와 같다).
    ///   - host: HTTP `Host` 값.
    ///   - isPreferred: 이 서버가 홈 지역이면 true. 핸드셰이크 끝에 NotePreferred를 보낸다.
    ///   - clientInfoNonce: ClientInfo를 봉할 24바이트 난수. 부르는 쪽이 시스템 난수로 뽑는다.
    public init(privateKey: Curve25519.KeyAgreement.PrivateKey, host: String, isPreferred: Bool, clientInfoNonce: [UInt8]) throws(DERPError)

    /// 서버가 보낸 바이트를 넣는다. 바이트 경계는 프레임 경계와 무관하다.
    public mutating func receive(_ bytes: [UInt8]) throws(DERPError) -> [Event]
    /// 패킷 하나를 피어에게 보낸다(SendPacket 프레임 하나).
    public mutating func send(_ packet: [UInt8], to peer: NodePublicKey) throws(DERPError)
    /// 서버에 보낼 바이트를 꺼낸다. 없으면 빈 배열. `init`, `receive`, `send` 뒤에 부른다.
    public mutating func takeOutboundBytes() -> [UInt8]
}

/// DERP 서버 하나와의 연결을 유지한다. 끊기면 물러났다가 다시 잇는다.
public actor DERPClient {
    public enum Event: Sendable {
        case connected
        case disconnected
        /// 연결을 열지 못한 시도 하나. `consecutiveFailures`는 마지막으로 연결을 연 뒤 연달아 열지 못한 수(1부터).
        case attemptFailed(AttemptFailure, consecutiveFailures: Int)
        case packet([UInt8], from: NodePublicKey)
        case peerGone(NodePublicKey)
    }

    /// 연결을 열지 못한 이유의 종류. 주소·키·이름을 담지 않는다.
    public enum AttemptFailure: Sendable, Equatable {
        case timedOut          // 연결을 걸기 시작해 ready까지 10초를 넘김
        case connectionFailed  // TCP·TLS 연결을 맺지 못함(거부, 경로 없음, 이름 풀기, 인증서를 가르지 못한다)
        case handshakeFailed   // 업그레이드·핸드셰이크 중 거절, 규격 위반, 끊김
        case noServers         // 걸 대상이 없음
    }

    /// - Parameters:
    ///   - servers: 한 지역의 서버들. 앞에서부터 차례로 시도한다.
    ///   - interface: 연결을 내보낼 인터페이스. nil이면 묶지 않는다. 바꾸려면 닫고 새로 만든다.
    public init(servers: [DERPServer], privateKey: Curve25519.KeyAgreement.PrivateKey, isPreferred: Bool, interface: NWInterface? = nil)

    /// 사건의 흐름. 구독자는 하나다. `run()`이 끝나면 흐름도 끝난다.
    public nonisolated var events: AsyncStream<Event> { get }

    /// 연결하고, 읽고, 끊기면 다시 잇는다. 호출한 Task가 취소될 때까지 돌아오지 않는다.
    public func run() async

    /// 패킷을 보낸다. 연결되어 있지 않으면 다음 연결 때까지 큐에 둔다. 기다리지 않는다.
    public func send(_ packet: [UInt8], to peer: NodePublicKey)
}
```

## 동작

`DERPConnection`(노트 3장, 4.2~4.5):

1. 업그레이드 요청은 `GET /derp`, `Host`, `Connection: Upgrade`, `Upgrade: DERP`다. `User-Agent`·`Ideal-Node`·fast-start는 보내지 않는다.
2. 응답은 상태가 101인지만 본다(Go와 같다). **머리 뒤에 이미 도착한 바이트를 프레임 해석에 넘긴다**(서버가 101에 ServerKey를 붙여 쓴다).
3. ServerKey: 타입 `0x01`, 본문 40바이트 이상 1,024바이트 이하, magic 일치. 어기면 `handshakeFailed`.
4. ClientInfo: `{"version":2,"CanAckPings":true}`를 NaCl box로 봉한다(`SwiftailCrypto`의 `NaClBox`·`NaClSecretBox`). `isPreferred`면 바로 NotePreferred(`0x01`)를 잇는다. 여기서 `ready`.
5. 준비된 뒤: RecvPacket → `packet`(본문 32바이트 미만은 버린다), PeerGone → `peerGone`, Ping → 같은 8바이트의 Pong을 내보낼 바이트에 넣는다, ServerInfo → 열어 본다(열리지 않으면 `handshakeFailed`. 속도 제한 값은 쓰지 않는다), KeepAlive·Health·Restarting·PeerPresent·Pong·모르는 타입 → 본문을 건너뛴다.
6. 한도(신뢰할 수 없는 입력): 응답 머리 16KiB, 프레임 본문 1MiB(Go 값), 답하지 않은 Pong의 대기 바이트 64KiB(넘으면 `tooManyPendingReplies`. `takeOutboundBytes()`가 비운다). 한도를 넘거나 실패하면 받아 둔 바이트를 버리고 이후 호출은 `closed`다. 어떤 바이트열로도 프로세스가 죽지 않는다.
7. 개인 키와 공유 키를 쥐므로 `CustomReflectable`로 자식을 감춘다.

`DERPClient`(노트 4.1, 4.4~4.6):

1. **연결**: `interface`가 있으면 그 인터페이스로만 내보낸다(M5, `SwiftailTunnel` 계약 동작 N. 루프백 서버는 묶지 않는다). 서버 목록을 앞에서부터 TCP로 시도해(서버당 1.5초) 처음 붙는 곳에 TLS를 맺는다(`shortcut:` 소켓 감싸개가 TCP와 TLS를 한 번에 맺으므로, 마지막이 아닌 서버는 평문 TCP로 닿는지만 먼저 본 뒤 먼저 붙은 대상에 TLS로 다시 맺는다. 마지막 서버는 대상마다 TCP와 TLS를 함께 맺어 먼저 끝나는 쪽을 쓴다). TLS 실패는 다음 서버로 넘어가지 않고 이번 시도의 실패다. 연결부터 `ready`까지 10초를 넘기면 실패다.
   - **대상 동시 걸기**(Go `dialNode`): 서버 하나의 `targets`를 모두 함께 걸어 먼저 붙는 연결을 쓴다. 진 쪽은 닫고(취소가 닿기 전에 붙은 것도 닫는다), 모두 실패하면 가장 먼저 온 실패가 그 서버의 실패다. 연결마다 TaskGroup의 자식이므로 취소되면 열던 연결이 모두 닫힌다. 루프백 대상(`127.0.0.0/8`, `::1`)은 인터페이스에 묶지 않는다.
   - **걸 대상**(엔진의 `DERPNode` 변환, Go `shouldDialProto`): `IPv4`·`IPv6` 칸마다, 비었으면 `hostName`, 그 칸의 체계의 IP 리터럴이면 그 주소, 그 밖의 값(관례상 `"none"`, 다른 체계의 주소, 쓰레기)이면 그 체계로는 걸지 않는다. 두 칸 모두 `hostName`이면 대상은 `hostName` 하나다(Network 프레임워크가 이름을 풀어 두 체계를 스스로 시도한다). 대상이 없으면 그 노드는 쓰지 않는다. 순서는 IPv4 칸, IPv6 칸이다.
   - **실패 알림**: 연결을 열지 못한 시도마다(취소는 빼고) `attemptFailed`를 낸다. 노드는 연달아 실패한 첫 번째와 그 뒤 10번째마다 지역 번호와 실패 종류만 로그에 남긴다.
2. **읽기**: 연결이 살아 있는 동안 소켓 읽기를 멈추지 않는다(서버의 쓰기 기한이 2초다). 120초 동안 아무것도 오지 않으면 끊는다. `events`의 소비가 느리면 `attemptFailed`·`packet`·`peerGone`은 가장 새 것 256개까지, 그리고 패킷 바이트의 합 1MiB까지만 쥐고 오래된 것부터 버린다(패킷은 데이터그램이므로 버려도 된다. 바이트 한도는 M5의 확장 메모리 때문이다. 개수만으로는 Go 서버의 패킷 한도 64KiB로 16MiB, 프레임 본문 한도 1MiB를 채워 보내는 서버면 256MiB까지 쌓인다). `connected`·`disconnected`는 버리지 않고, 읽지 않은 것 가운데 가장 새 것 하나만 남긴다.
3. **쓰기**: 연결 상태와 무관하게 보낼 패킷을 32개까지 쥐고, 가득 차면 가장 오래된 것을 버린다(Go의 지역별 쓰기 큐와 같다). 그때까지 쌓인 Pong과 큐의 앞쪽 패킷들을 한 덩어리(프레임을 이어 붙인 바이트 하나)로 쓰고, 소켓이 받아 가기 전에는 다음 덩어리를 꺼내지 않는다. 그래서 소켓이 앞 덩어리를 받아 가는 동안 쌓인 패킷들이 다음 덩어리 하나로 나간다. 한 덩어리의 패킷은 큐 한도대로 32개 이하이고, SendPacket 프레임의 합이 64KiB를 넘기 전까지만 넣는다(첫 패킷은 크기와 무관하게 넣으므로 덩어리는 패킷 프레임 최대 65,573바이트와 Pong 64KiB 이하다). 프레임은 상태 기계에 들어간 순서대로 나간다. 덩어리 하나가 5초 안에 소켓으로 넘어가지 않으면 연결 오류로 보고 끊은 뒤 다시 잇는다(Go는 일반 송신에 기한이 없다. 메모리를 묶기 위한 Swiftail의 선택이다). 연결이 끊길 때 소켓에 넘기던 덩어리(패킷 32개 이하)는 잃고, 큐에 남은 패킷은 다음 연결이 보낸다(끊긴 뒤에는 큐에서 더 꺼내지 않는다). 이 기한은 쓰기마다 Task나 타이머를 만들지 않고, 연결의 TaskGroup 자식인 감시 하나가 진행 중인 쓰기의 시작 시각을 보아 지킨다(쓰기마다 `withTimeout`을 걸면 취소된 기한 Task와 타이머가 5초까지 남아 쓰기 속도에 비례해 메모리가 쌓였다). 쓰기가 막힌 동안 Pong이 64KiB를 넘게 쌓이면 `tooManyPendingReplies`로 끊긴다. 읽기는 쓰기가 막혀도 멈추지 않는다.
   - `connected`는 ClientInfo를 보낸 시점이다. 서버가 이 클라이언트를 등록하기 전에 보낸 패킷은 서버가 버릴 수 있다. 위 계층(WireGuard)의 재시도가 이를 메운다.
4. **재연결**: 오류가 나면 소켓을 닫고 `disconnected`를 낸 뒤 `min(n² × 10ms, 5초) × [0.5, 1.5)`만큼 기다렸다가 처음부터 다시 잇는다. 핸드셰이크 뒤의 프레임(보통 ServerInfo)을 하나라도 처리에 성공하면 n을 0으로 되돌린다(ServerKey만 주고 끊는 서버에 물러나기 없이 다시 붙지 않게 한다). 이전 소켓을 닫은 뒤에만 새로 잇는다(같은 키의 연결이 둘이면 서버가 한쪽에만 패킷을 넘긴다).
5. **구조적 동시성**: `run()`을 부른 Task의 취소로 모든 것이 멈춘다. 분리된 Task를 만들지 않는다. 소켓과 continuation이 새지 않는다.

제외(`shortcut:` 주석으로 남긴다):

- fast-start. (`sha256-raw:` 인증서 고정과 `CertName`이 `HostName`과 다른 경우는 M8 ③에서 넣었다. 아래 "M8 ③" 절.)
- IPv4 늦추기: Go는 IPv6를 선호하는 망에서 IPv4를 200ms 늦게 건다(`preferIPv6`). Swiftail에는 주소 체계 선호 판단이 없으므로 모든 대상을 곧바로 건다.
- 체계를 정한 이름 풀기: Go는 빈 칸을 그 체계로만 푼다(`tcp4`·`tcp6`). Swiftail은 `hostName`을 체계 구분 없이 걸므로, 한 칸만 비고 다른 칸이 `"none"`이어도 막힌 체계로 걸 수 있다.
- 실패의 세분: `connectionFailed`는 연결 거부·경로 없음·이름 풀기·TLS 실패를 가르지 않는다(`SocketError.connectFailed`가 Network 프레임워크 오류를 문자열로만 넘긴다).
- 서버가 알려 주는 속도 제한(토큰 버킷): 이 버전의 서버는 값을 보내지 않는다.
- 여러 지역, 역방향 경로, 홈이 아닌 연결의 정리: M4(`SwiftailMagicsock`).
- WebSocket, HTTP 프록시, mesh 프레임.

## 시험

단위 시험(`Tests/SwiftailDERPTests`, 소켓 없음):

- 프레임 부호화·해석: 노트 3장의 바이트 표 그대로의 고정 벡터(SendPacket, RecvPacket, NotePreferred, Ping/Pong, PeerGone과 이유 코드).
- 핸드셰이크: 고정 키·고정 nonce로 만든 ClientInfo 본문이 Go `box.Seal`의 출력과 같다(벡터는 Go로 뽑아 시험에 둔다). ServerInfo 열기. 한 바이트씩 온 입력, 101 머리와 ServerKey가 한 조각에 온 입력.
- 거절: 101이 아닌 상태, magic이 틀린 ServerKey, 열리지 않는 ServerInfo, 한도 초과(머리, 프레임, Pong 대기), 준비 전 `send`, 65,537바이트 패킷, 실패 뒤 `closed`와 버퍼 비움.
- 모르는 프레임·Health·Restarting·KeepAlive를 건너뛰고 그 뒤 프레임을 읽는다.
- 임의 입력으로 죽지 않는다. `dump`에 키가 나오지 않는다.

상호 운용 시험(`Tests/SwiftailDERPInteropTests`, 환경 변수 `SWIFTAIL_TAILNET`, 없으면 건너뛴다): `tailnet` 도구의 Go DERP 서버(자체 서명 TLS)에 `DERPClient` 둘을 서로 다른 키로 붙여

1. 양쪽이 `connected`가 된다(Network 프레임워크 TLS가 Go 시험 서버와 맺어진다).
2. A → B, B → A로 패킷이 간다(1바이트, 1,280바이트, 65,536바이트). 보낸 쪽 키가 맞다.
3. 없는 키로 보내도 연결이 끊기지 않는다.
4. B를 취소하면 A가 그 뒤에도 정상이고, B를 다시 띄우면 다시 주고받는다.
5. 70초 넘게 유지된다(서버 KeepAlive를 넘긴다).

## M8 ③: 인증서 이름과 인증서 고정

운영 DERPMap에는 `CertName`이 `HostName`과 다른 노드와 `sha256-raw:`로 인증서를 고정한 노드(자체 서명 derper)가 있을 수 있다. 이 단위 전에는 엔진이 그런 노드를 건너뛰었다(`DERPServer.init?(_:)`). 이 단위에서 건너뛰지 않고 Go와 같은 규칙으로 검증한다. 근거: 노트 `derp-stun.md` 4.1 5, Go `derp/derphttp/derphttp_client.go`의 `tlsClient`, `net/tlsdial/tlsdial.go`의 `SetConfigExpectedCert`·`SetConfigExpectedCertHash`, `derp/derpconst`.

fast-start는 이 단위의 범위가 아니다.

### API

`DERPServer.Verification`에 두 경우를 더한다.

- `.named(String)`: 시스템 신뢰 저장소로 사슬을 검증하되 인증서의 이름은 이 값으로 본다. SNI와 HTTP `Host`는 그대로 `hostName`이다.
- `.pinned(sha256Hex: String)`: 서버가 낸 인증서의 SHA-256이 이 값과 같아야 한다. 사슬은 검증하지 않는다.

`DERPServer.init?(_ node:)`가 고르는 규칙(Go `tlsClient`와 같은 차례):

1. `certName`이 `sha256-raw:`로 시작하면 `.pinned(나머지)`. 나머지는 고치지 않고 그대로 담는다(대문자나 길이가 다른 값은 Go에서도 어떤 인증서와도 맞지 않아 연결이 실패한다. 건너뛰지 않는다).
2. `certName`이 비어 있지 않고 `hostName`과 다르면 `.named(certName)`.
3. 그 밖에는 지금처럼 `insecureForTests`면 `.noneForTests`, 아니면 `.system`.

1·2는 `insecureForTests`보다 앞선다(Go에서도 `CertName`이 있으면 검증 훅이 다시 걸린다).

### 동작 V: 검증

1. `.named`: 서버가 낸 사슬을 시스템 신뢰 저장소로 검증하고, 이름은 `certName`으로 확인한다. Go에 있는 내장 Let's Encrypt 루트로의 대체 검증은 두지 않는다(시스템 저장소에 그 루트가 있다).
2. `.pinned`: 서버가 낸 인증서 가운데 주체 CN이 `derpconst.MetaCertCommonNamePrefix`로 시작하는 것(DERP 서버가 덧붙이는 meta 인증서)을 뺀 나머지가 **정확히 하나**여야 한다. 그 하나에 대해 ① DER 전체의 SHA-256을 소문자 16진으로 쓴 것이 고정 값과 글자 그대로 같고 ② SNI로 나가는 이름이 있으면(`hostName`이 IP 리터럴이 아니면) 인증서가 그 이름에 유효하고(IP 리터럴이면 Go도 이름을 보지 않는다. 처음 적은 "IP SAN을 본다"는 틀렸다) ③ 지금이 유효 기간 안이어야 한다. 하나도 없거나 둘 이상이면 실패다.
3. 검증 실패는 지금의 TLS 실패와 같은 길로 간다(이번 연결 시도의 실패, `attemptFailed`). 다음 서버로 넘어가지 않는다(Go와 같다).
4. 검증 판정은 연결 없이 시험할 수 있어야 한다(인증서 DER 목록, 이름, 시각, 고정 값을 받는 함수. `.named`는 시험이 앵커를 넣을 수 있게 `package` 범위에서만 연다).
5. `hostName`이 IP 리터럴일 때의 SNI는 Go(`crypto/tls`는 IP에 SNI를 보내지 않는다)와 플랫폼의 동작을 확인해 적는다.

②③을 플랫폼의 `SecTrust`(그 인증서만 앵커로, SSL 서버 정책과 이름)로 볼지 직접 볼지는 구현이 정하되, Go의 derper가 실제로 만드는 자체 서명 인증서(`cmd/derper`의 수동 인증서 모드, IP 주소용)가 통과하는 것을 시험으로 보인다. 플랫폼이 Go보다 엄격해 그 인증서를 거절하면 규칙을 풀지 말고 보고한다.

### 시험과 관문

- 단위: 맞는 고정, 다른 해시, meta 인증서가 섞인 목록, meta가 아닌 것이 둘, 하나도 없음, 이름 불일치, 기한 지남·아직 아님, 대문자 고정 값, `.named`의 이름 일치·불일치(시험 앵커). `DERPServer.init?(_:)`의 세 갈래와 `insecureForTests`와의 차례.
- 상호 운용: `Tools/interop`의 tailnet 도구가 DERP 노드를 `InsecureForTests` 대신 `CertName: sha256-raw:<그 서버 인증서의 해시>`로 알리는 모드. Swiftail 노드가 그 DERP로 Go 피어와 통신한다(Go derper는 meta 인증서를 함께 낸다). 틀린 해시를 알리면 DERP 연결이 실패한다.
- 고정 검사를 일부러 망가뜨려(해시 비교를 건너뜀, meta가 아닌 인증서 수를 세지 않음) 시험이 잡는지 확인한다.

## M8 ③ 구현하며 정해진 것

- **IP 리터럴 `hostName`의 이름 검사(계약과 다름, Go를 따름)**: 동작 V 2 ②는 "IP 리터럴이면 IP SAN을 본다"고 했으나, Go는 보지 않는다. `SetConfigExpectedCertHash`는 `tls.ConnectionState.ServerName`이 비면 이름 검사를 건너뛰고(`net/tlsdial/tlsdial.go:340`, "it's empty when dialing a derper by IP with no hostname"), 클라이언트의 `ServerName`은 `hostnameInSNI`가 IP 리터럴을 빈 문자열로 바꾼 값이다(Go 1.27.3 `crypto/tls/handshake_client.go:78`, `:280`, `:1305-1320`, `conn.go:1629`). 그래서 `hostName`이 IP 리터럴(괄호, `%`범위 포함)이면 이름을 보지 않고, 이름이면 끝의 점을 뗀 이름으로 본다(`ServerCertificate.sniHostName`).
- **판정의 자리**: `SwiftailIO`의 `ServerCertificate.checkPinned`·`checkNamed`(`package`). DER 목록·이름·시각(`.named`는 앵커도)을 받아 typed error(`ServerCertificate.Failure`)를 던진다. `NetworkSocket.TLS`에 `.named(serverName:certificateName:)`·`.pinned(serverName:sha256Hex:)`를 더했고, 검증 블록이 `sec_protocol_metadata_access_peer_certificate_chain`으로 서버가 낸 인증서를 모아 판정에 넘긴다. 검증 블록의 큐는 연결마다 따로다(판정이 `SecTrustEvaluateWithError`로 큐를 막는다).
- **②③은 `SecTrust`로 본다**: 고정한 인증서 하나만 앵커로 두고(`SecTrustSetAnchorCertificatesOnly`), SSL 서버 정책(이름은 위 규칙, IP 리터럴이면 이름 없음), 검증 시각 지금, 네트워크 가져오기 끔. 그래서 Go가 보지 않는 Apple의 TLS 서버 인증서 조건(서버 인증 EKU, 825일 이하의 유효 기간 등)도 걸린다. derper의 IP 수동 인증서(`cmd/derper/cert.go`의 `createSelfSignedIPCert`: P-256, 서버 인증 EKU, IP SAN, 1년)는 통과한다(단위 시험의 고정 인증서와 상호 운용 시험). 이 조건을 어기는 자체 서명 인증서는 Go 클라이언트가 받아도 Swiftail은 받지 않는다.
- **`.named`**: 받은 첫 인증서를 leaf로, 나머지를 사슬 후보로 두고 SSL 서버 정책(`certName`)과 시스템 신뢰 저장소로 평가한다. meta 인증서가 후보에 섞여도 된다. 네트워크 가져오기는 시스템 기본값 그대로다.
- **해시 비교**: DER 전체의 SHA-256을 소문자 16진으로 바꿔 글자 그대로 견준다. 공개된 인증서의 해시라 상수 시간 비교가 아니다. meta 인증서 판정은 `SecCertificateCopyCommonName`(주체 CN)이 `derpkey`로 시작하는지다. 읽히지 않는 인증서가 하나라도 있으면 실패다(Go는 그런 인증서면 핸드셰이크가 먼저 실패한다).
- **SHA-256의 의존**: `SwiftailIO`가 CryptoKit(시스템 프레임워크)과 Security를 쓴다. `Package.swift`는 바꾸지 않았다.
- **확인한 플랫폼 동작**: ① `SecTrust`가 derper 모양의 IP 자체 서명 인증서를 그 인증서만 앵커로 받는다. ② `sec_protocol_options_set_tls_server_name`에 IP 리터럴(`127.0.0.1`)을 주면 Network 프레임워크도 SNI를 보내지 않는다(도구가 본 ClientHello의 SNI가 빈 문자열. Go와 같다). ③ 검증 블록의 `sec_protocol_metadata_access_peer_certificate_chain`은 서버가 낸 인증서 전부를 낸 차례대로 준다(도구가 낸 [leaf, meta]의 해시를 그 차례로 받았다). 플랫폼이 사슬을 다시 짠 결과가 아니므로 "정확히 하나"를 서버가 낸 목록에서 센다.
- **상호 운용 도구**: `tailnet`의 `setDERPCertificate`(`mode`: `pinned`·`wrongPin`, 첫 제어 요청 전)가 DERP 서버 인증서를 derper의 IP 수동 인증서 모드와 같은 것으로 바꾸고 `derpserver.ModifyTLSConfigToAddMetaCert`로 meta 인증서를 붙인다. DERPMap 노드는 `InsecureForTests: false`, `CertName: sha256-raw:<해시>`가 된다. `wrongPin`은 서버가 함께 내는 meta 인증서의 해시를 알린다. `networkStatus`가 TLS ClientHello 수(`derpTLSHandshakes`)와 본 SNI(`derpServerNames`)를 더해 돌려준다. 단위 시험의 고정 인증서는 같은 도구의 `tailnet certificate-fixtures`가 만든다.

## M8 ③ 독립 검토 결과 (2026-11-15)

작성한 세션과 다른 세션이 Go(v1.104.6, Go 1.27.3)를 실제로 돌려 얻은 판정과 견줬다. 재현 시험은 `Tests/SwiftailIOTests/ServerCertificateReviewTests.swift`. 치명 없음, 높음 1, 보통 2, 낮음 6. 아래가 위의 절들보다 앞선다.

### 고친 것

- **고정 인증서는 첫 자리여야 한다(높음. Go와 다르게, 더 엄격하게)**: TLS 핸드셰이크는 첫 인증서의 키만 증명한다. Go의 판정은 자리를 보지 않아서, 고정 인증서의 키가 없는 서버가 자기 키로 만든 CN `derpkey…` 인증서를 첫 자리에 내고 누구나 받아 볼 수 있는 고정 인증서를 뒤에 붙이면 통과한다(Go 클라이언트와 고치기 전의 Swiftail이 그런 서버에 붙는 것을 실행으로 확인). 그러면 고정은 서버를 알아보지 못한다. 동작 V 2에 조건을 더한다: **meta가 아닌 그 하나가 목록의 첫 자리여야 한다**(`Failure.candidateNotLeaf`). derper는 서버 인증서를 첫 자리에, meta 인증서를 뒤에 내므로 정상 서버는 걸리지 않는다. 관문: 도구의 `leafNotFirst` 모드에서 붙지 못한다. Go 쪽의 같은 동작을 Tailscale에 알릴지는 사용자가 정한다(총괄은 외부로 보내지 않는다).
- **IP로 붙는 고정 DERP는 기간만 본다(보통)**: `SecTrust`의 SSL 서버 정책은 Go보다 엄격해 운영자가 직접 만든 자체 서명 인증서(유효 기간 826일 이상, 서버 인증 EKU 없음, RSA 1024, Ed25519 키)를 거절한다. `hostName`이 IP 리터럴이면 이름을 보지 않으므로 그때는 기본 X.509 정책으로 평가한다(기간과 자기 서명만). 10년짜리·EKU 없음·Ed25519 인증서가 통과하고 기간 밖은 거절된다. **이름으로 붙는 고정 DERP에서는 SSL 서버 정책이 그대로 걸린다**(`shortcut:` 이름과 기간을 직접 보려면 SAN 해석이 필요하다. 필요해지는 시점: 그런 DERP에 붙어야 할 때).
- **`.named`의 연결 경로에 관문이 없었다(보통)**: 연결에서 검증을 빼도 시험이 통과했다. 도구의 `named` 모드를 더했다: `CertName`이 `HostName`과 다르고 서버 인증서가 시스템이 믿지 않는 것이면 `InsecureForTests`가 켜져 있어도 붙지 못한다. 맞는 이름으로 붙는 쪽은 시스템 신뢰 저장소가 필요해 단위 시험(시험 앵커)으로만 본다.
- **재개된 세션은 검증 블록을 건너뛴다(낮음)**: 세션 표를 켠 TLS 1.2에서 재개된 연결은 블록이 불리지 않았다(실험). 기본 옵션에서는 재개가 일어나지 않았지만, 검증 블록을 거는 옵션에서는 재개와 세션 표를 명시적으로 끈다.
- **끝에 점이 있는 `hostName`(낮음)**: Network 프레임워크는 그런 이름에 SNI를 보내지 않는다. Go는 점을 떼고 보낸다(`hostnameInSNI`). 점을 떼어 넘긴다. 관문: 도구의 `dottedHostName` 모드에서 SNI가 `localhost`로 온다.
- **네 자리를 넘는 IPv6 묶음(낮음)**: `IPAddress`가 `00000::1`을 받았다(Go는 받지 않는다). 그런 문자열이 IP로 읽혀 이름 검사가 빠졌다. `IPAddress`가 거절한다.

고침 셋(첫 자리 검사, `.named`의 검증, 점 떼기)을 하나씩 뺐을 때 새 시험이 잡는 것을 확인했다.

### 그대로 둔 것

- **읽히지 않는 인증서**: Network 프레임워크가 검증 블록에 주기 전에 버린다. `[고정, 깨진 DER]`을 Go는 핸드셰이크에서 거절하고 Swiftail은 받는다. 첫 자리의 고정 인증서는 검증되므로 서버를 잘못 알아보지 않는다. 위 절의 "읽히지 않는 인증서가 하나라도 있으면 실패"와 "서버가 낸 인증서 전부를 준다"는 판정 함수에만 맞고 연결 경로에는 맞지 않는다.
- **CN의 문자열 형**: Security는 VisibleString CN을 읽고 Go는 비운다. 뒤에 붙은 그런 `derpkey…` 인증서를 Go는 세고(거절) Swiftail은 meta로 뺀다(받음). 첫 자리 조건이 있으므로 무해하다.
- **앞자리 0이 붙은 점 십진 서버 이름**(`100.064.0.1`): SSL 정책이 IP로 읽어 IP SAN과 맞춘다(Go는 이름으로 견줘 거절). 고정 값이 맞는 인증서에서만 갈린다.
- **zone의 `%`에 결합 문자가 붙은 서버 이름**: Swiftail이 이름으로 보아 더 엄격하다.
- Apple 플랫폼의 Go는 시스템 검증에 같은 `SecTrust`를 쓴다. `.named`와 `.system`의 엄격함은 그쪽 Go와 같고 Linux의 Go와만 다르다.

### 확인하지 못한 것

- TLS 1.3 재개에서 검증 블록이 불리는지(재개를 일으키지 못했다. 재개를 껐으므로 지금은 해당 없음).
- iOS에서의 동작(실행은 macOS에서만).
- `.named`의 네트워크 가져오기가 빠진 중간 인증서를 받아 통과시키는지, 그 요청이 지정한 인터페이스 밖으로 나가는지.
- SCT를 TLS 확장으로만 주는 서버에서 DER만 다시 평가해 거절되는지.
- Go는 `CertName` 없는 IP `hostName` 노드에서 이름을 보지 않는다고 검토가 읽었다(`tlsdial.go`). Swiftail `.system`은 IP SAN을 본다(더 엄격). 실행으로 견주지 않았다.
- `CertName`이 다른 실제 운영 DERP 노드, 운영 DERPMap 전체.
