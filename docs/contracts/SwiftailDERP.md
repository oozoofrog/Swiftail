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
    /// 연결할 주소. nil이면 `hostName`을 DNS로 찾는다.
    public var address: IPAddress?
    public var port: UInt16
    public var verification: Verification

    public enum Verification: Sendable, Equatable {
        /// 시스템 신뢰 저장소로 `hostName`을 검증한다.
        case system
        /// 검증하지 않는다. DERPMap이 `InsecureForTests`인 노드에만 쓴다.
        case noneForTests
    }
    public init(hostName: String, address: IPAddress? = nil, port: UInt16 = 443, verification: Verification = .system)
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
        case packet([UInt8], from: NodePublicKey)
        case peerGone(NodePublicKey)
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

1. **연결**: `interface`가 있으면 그 인터페이스로만 내보낸다(M5, `SwiftailTunnel` 계약 동작 N. 루프백 서버는 묶지 않는다). 서버 목록을 앞에서부터 TCP로 시도해(서버당 1.5초) 처음 붙는 곳에 TLS를 맺는다(`shortcut:` 소켓 감싸개가 TCP와 TLS를 한 번에 맺으므로, 마지막이 아닌 서버는 평문 TCP로 닿는지만 먼저 본 뒤 TLS로 다시 맺는다). TLS 실패는 다음 서버로 넘어가지 않고 이번 시도의 실패다. 연결부터 `ready`까지 10초를 넘기면 실패다.
2. **읽기**: 연결이 살아 있는 동안 소켓 읽기를 멈추지 않는다(서버의 쓰기 기한이 2초다). 120초 동안 아무것도 오지 않으면 끊는다. `events`의 소비가 느리면 `packet`·`peerGone`은 가장 새 것 256개까지, 그리고 패킷 바이트의 합 1MiB까지만 쥐고 오래된 것부터 버린다(패킷은 데이터그램이므로 버려도 된다. 바이트 한도는 M5의 확장 메모리 때문이다. 개수만으로는 Go 서버의 패킷 한도 64KiB로 16MiB, 프레임 본문 한도 1MiB를 채워 보내는 서버면 256MiB까지 쌓인다). `connected`·`disconnected`는 버리지 않고, 읽지 않은 것 가운데 가장 새 것 하나만 남긴다.
3. **쓰기**: 연결 상태와 무관하게 보낼 패킷을 32개까지 쥐고, 가득 차면 가장 오래된 것을 버린다(Go의 지역별 쓰기 큐와 같다). 패킷 하나와 그때까지 쌓인 Pong을 한 덩어리로 쓰고, 소켓이 받아 가기 전에는 다음 덩어리를 꺼내지 않는다. 덩어리 하나가 5초 안에 소켓으로 넘어가지 않으면 연결 오류로 보고 끊은 뒤 다시 잇는다(Go는 일반 송신에 기한이 없다. 메모리를 묶기 위한 Swiftail의 선택이다). 쓰기가 막힌 동안 Pong이 64KiB를 넘게 쌓이면 `tooManyPendingReplies`로 끊긴다. 읽기는 쓰기가 막혀도 멈추지 않는다.
   - `connected`는 ClientInfo를 보낸 시점이다. 서버가 이 클라이언트를 등록하기 전에 보낸 패킷은 서버가 버릴 수 있다. 위 계층(WireGuard)의 재시도가 이를 메운다.
4. **재연결**: 오류가 나면 소켓을 닫고 `disconnected`를 낸 뒤 `min(n² × 10ms, 5초) × [0.5, 1.5)`만큼 기다렸다가 처음부터 다시 잇는다. 핸드셰이크 뒤의 프레임(보통 ServerInfo)을 하나라도 처리에 성공하면 n을 0으로 되돌린다(ServerKey만 주고 끊는 서버에 물러나기 없이 다시 붙지 않게 한다). 이전 소켓을 닫은 뒤에만 새로 잇는다(같은 키의 연결이 둘이면 서버가 한쪽에만 패킷을 넘긴다).
5. **구조적 동시성**: `run()`을 부른 Task의 취소로 모든 것이 멈춘다. 분리된 Task를 만들지 않는다. 소켓과 continuation이 새지 않는다.

제외(`shortcut:` 주석으로 남긴다):

- fast-start, `sha256-raw:` 인증서 고정, `CertName`이 `HostName`과 다른 경우: 운영 DERP와 맺기 전(M4 마무리 관문)에 넣는다. `DERPServer`를 만들 때 엔진이 이런 노드를 건너뛴다.
- IPv4·IPv6 동시 시도: 주소 하나만 시도한다.
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
