# SwiftailMagicsock 계약 (M4)

M4의 목표는 **직접 연결**이다. Go 피어와 루프백·LAN에서 직접 UDP 경로가 잡히고, 직접 경로를 막으면 DERP로 내려가고 풀면 다시 올라온다(`docs/plan.md` 7절 M4). M3까지는 UDP 소켓이 없고 모든 패킷이 홈 DERP 지역을 거친다.

`SwiftailMagicsock`은 **입출력 없는 값 타입**만 담는다. disco 메시지의 봉하기·열기, 피어별 경로 상태 기계(후보 주소, Ping·Pong, `bestAddr`와 신뢰 기간, heartbeat), STUN 해석과 자기 엔드포인트·홈 지역 결정, 그리고 이들을 묶어 "WireGuard 데이터그램을 어디로 보낼지"와 "받은 데이터그램이 무엇인지"를 정하는 `Magicsock` 상태 기계다. UDP 소켓(POSIX)·인터페이스 주소 읽기는 `SwiftailIO`에, 타이머·DERP 연결·소켓 읽기 루프는 `TailnetNode`(가장자리 actor)에 둔다. 엔진은 지금처럼 "이 피어에게 보낼 WireGuard 데이터그램"만 내고 경로는 `Magicsock`이 고른다(`docs/contracts/SwiftailWireGuard.md` "왜 이 구조인가").

프로토콜 세부는 [protocol-notes/disco-magicsock.md](../protocol-notes/disco-magicsock.md)(검증됨, 아래에서 "노트")와 [derp-stun.md](../protocol-notes/derp-stun.md) 3.8·3.9·4.8~4.10(아래에서 "DERP 노트")을 따른다. 이 문서는 모듈 경계, M4 범위, 시험과 관문만 정한다. 엔진·노드 쪽 변경은 [SwiftailEngine.md](SwiftailEngine.md)의 "M4에서 바뀌는 것"에 있다.

## 타깃

| 타깃 | 의존 | 내용 |
| --- | --- | --- |
| `SwiftailBase` | Foundation, Network | 기존 내용 + **`IPEndpoint`**(`SwiftailControl/Tailcfg/IPEndpoint.swift`에서 옮긴다. 공개 이름 그대로. `Codable` 확장은 `IPAddress+Codable.swift`처럼 `SwiftailControl`에 남긴다) |
| `SwiftailIO` | `SwiftailBase`(새로 더함), Foundation, Network, Synchronization | 기존 내용 + `DatagramSocket`, `LocalInterfaceAddresses`(둘 다 `package`) |
| `SwiftailMagicsock` (새 타깃, 제품으로 내보낸다) | `SwiftailBase`, `SwiftailCrypto`, CryptoKit | 아래 API. 소켓·시계·actor 없음 |
| `Swiftail` | 기존 + `SwiftailMagicsock` | 노드 통합(엔진 계약의 "M4에서 바뀌는 것") |

`SwiftailMagicsock`은 `SwiftailControl`·`SwiftailDERP`·`SwiftailWireGuard`·`SwiftailEngine`에 의존하지 않는다. netmap·DERPMap(tailcfg)에서 필요한 값(피어의 disco 키·엔드포인트·홈 지역, 지역별 STUN 주소)은 노드가 뽑아 넘긴다. `SwiftailDERP`가 `DERPServer`를 받는 것과 같은 방식이다.

`docs/plan.md` 5절의 의존 그림은 `SwiftailEngine`이 `SwiftailMagicsock`에 기대는 모양이지만, 이 계약은 노드가 둘을 잇는다(아래 총괄 확정 Q1). 모듈 표의 "UDP 소켓과 재결속"은 소켓 감싸개가 `SwiftailIO`로, 재결속이 M5로 간다.

## 구조

```
                 TailnetNode (actor, 가장자리: 시계·소켓·DERP 연결·타이머)
   IP 패킷 ─► TailnetEngine ─ .datagram(to: 피어) ─► Magicsock ─ .udp / .derp ─► DatagramSocket / DERPClient(지역별)
   IP 패킷 ◄─ TailnetEngine ◄─ receive ─────────── Magicsock ◄─ receiveUDP / receiveDERP ◄─ 소켓 / DERPClient
                                                    │
                                                    ├ .endpointsChanged, .homeRegionChanged ─► ControlClient.setLocalStatus
                                                    └ .pathChanged ─► NodeEvent
```

`Magicsock` 안의 값 타입과 책임:

| 타입 | 접근 | 책임 | 단위 |
| --- | --- | --- | --- |
| `TransactionID` | internal | disco·STUN이 함께 쓰는 12바이트 ID | 0 |
| `DiscoMessage` | internal | 평문 Ping·Pong·CallMeMaybe의 부호화·해석(노트 3.3·3.4) | 1 |
| `DiscoPacket`, `DiscoSharedKey` | internal | 겉 형식 판정, 보낸 쪽 disco 키 읽기, 봉하기·열기(노트 3.1·3.2) | 1 |
| `PeerPathState` | internal | 피어 하나의 후보 주소·보낸 Ping·`bestAddr`·신뢰·heartbeat·경로 선택(노트 4.4~4.8) | 2 |
| `STUNMessage` | internal | 바인딩 요청 만들기, 응답 해석(DERP 노트 3.8·3.9·4.10 3) | 3 |
| `Netcheck` | internal | STUN 회차, 지역별 지연, 자기 엔드포인트 목록, 홈 지역 선택(노트 4.9, DERP 노트 4.8·4.10) | 3 |
| `Magicsock` | public | 위를 묶는다: 받은 것의 분류, disco 키 표와 공유 키, 피어 묶음, CallMeMaybe, 경로 사건 | 4 |
| `PeerPath` | public | 피어 경로의 공개 표현(Go `curAddr`와 같은 뜻) | 0 |

내부 타입은 `@testable import`로 시험한다(`SwiftailWireGuard`와 같다). 공개 범위는 노드가 쓰는 `Magicsock`과 그 입출력 타입, `PeerPath`뿐이다.

## 공개 API (`SwiftailMagicsock`)

```swift
/// 피어에게 가는 길. Go `ipnstate.PeerStatus`의 `CurAddr`와 같은 뜻이다(노트 6.3 마지막 줄, 7.1).
public enum PeerPath: Sendable, Equatable {
    /// 신뢰 기간 안의 직접 UDP 주소로만 보낸다.
    case direct(IPEndpoint)
    /// DERP를 거친다. 직접 주소로 함께 보내는 중(신뢰가 지난 `bestAddr`)이어도 여기에 든다.
    /// - Parameter derpRegion: 피어의 홈 DERP 지역. 0이면 모른다.
    case relayed(derpRegion: Int64)
}

/// 피어 사이의 직접 경로를 찾고 유지하는 상태 기계. 소켓·시계·actor를 갖지 않는다.
///
/// 노드는 받은 UDP 데이터그램, DERP로 받은 패킷, 엔진이 낸 WireGuard 데이터그램, netmap에서 뽑은 피어 정보,
/// 그리고 지금 시각을 넣는다. `Magicsock`은 상태를 바꾸고 "UDP·DERP로 보낼 것", "WireGuard 장치에 넣을 것",
/// "제어 서버에 올릴 것", "경로가 바뀐 피어"를 돌려준다. 모든 진입점은 던지지 않는다. 버린 것은 `.dropped`로 알린다.
///
/// 난수(disco nonce, TxID, ReSTUN 간격)는 이 타입이 시스템 난수로 뽑는다(`WireGuardDevice`와 같다). 그 아래의
/// 단계(`PeerPathState`, `Netcheck`, `DiscoPacket.seal`)는 난수를 인자로 받는다.
public struct Magicsock: Sendable {
    /// netmap의 피어 하나 가운데 경로 찾기에 필요한 부분. 노드가 `EnginePeer`에서 만든다.
    public struct Peer: Sendable, Equatable {
        public var key: NodePublicKey
        /// 0이면 이 피어와 disco를 하지 않는다(DERP만).
        public var discoKey: DiscoPublicKey
        /// 0이면 모른다.
        public var homeDERP: Int64
        /// netmap의 `Endpoints`. IPv4만 후보로 쓴다(동작 D1).
        public var endpoints: [IPEndpoint]
        public init(key: NodePublicKey, discoKey: DiscoPublicKey, homeDERP: Int64, endpoints: [IPEndpoint])
    }

    /// 홈으로 고를 수 있는 DERP 지역. 노드가 DERPMap에서 뽑는다(엔진 계약 M4 동작 N3).
    public struct Region: Sendable, Equatable {
        public var id: Int64
        /// STUN을 물을 주소. 비면 이 지역은 재지 않는다(측정이 없을 때의 대체 홈으로만 고른다).
        public var stunServers: [IPEndpoint]
        /// DERPMap `HomeParams.RegionScore`. 양수일 때만 지연에 곱한다. 없으면 0.
        public var score: Double
        public init(id: Int64, stunServers: [IPEndpoint], score: Double = 0)
    }

    /// 제어 서버에 올릴 자기 엔드포인트 하나.
    public struct Endpoint: Sendable, Equatable {
        public enum Source: Sendable, Equatable {
            /// 인터페이스 주소 + 소켓 포트. tailcfg `EndpointLocal`(1).
            case local
            /// STUN 응답의 바깥 주소. tailcfg `EndpointSTUN`(2).
            case stun
        }
        public var address: IPEndpoint
        public var source: Source
    }

    public enum Output: Sendable, Equatable {
        /// UDP 소켓으로 보낸다(WireGuard, disco, STUN 모두 같은 소켓이다).
        case udp([UInt8], to: IPEndpoint)
        /// DERP 지역 `region`의 연결로 피어에게 보낸다. 그 지역에 연결이 없으면 노드가 연다.
        case derp([UInt8], to: NodePublicKey, region: Int64)
        /// WireGuard 장치(엔진의 `receive`)에 넣을 데이터그램.
        case wireGuard([UInt8])
        /// 제어 서버에 올릴 자기 엔드포인트가 바뀌었다(순서가 의미 있다. 노트 4.9 1).
        case endpointsChanged([Endpoint])
        /// 홈 DERP 지역이 바뀌었다. `NetInfo.preferredDERP`로 올리고 그 지역에 연결한다.
        case homeRegionChanged(Int64)
        /// 피어의 경로가 바뀌었다. nil은 그 피어가 빠졌거나 유휴라는 뜻이다(동작 G3).
        case pathChanged(NodePublicKey, PeerPath?)
        /// 버린 것. 진단과 시험용이다.
        case dropped(Drop)
    }

    public enum Drop: Sendable, Equatable {
        /// 보낸 쪽 disco 키가 아는 피어의 것이 아니다.
        case unknownDiscoKey
        /// 열리지 않거나 해석할 수 없는 disco 메시지.
        case malformedDisco
        /// 처리하지 않는 disco 종류(peer relay 0x04–0x09), Geneve로 감싼 데이터그램.
        case unsupportedDisco
        /// 경로 규칙을 어긴 disco(UDP로 온 CallMeMaybe, 키가 맞지 않는 CallMeMaybe, 모르는 DERP 보낸 쪽).
        case misroutedDisco
        /// 진행 중인 회차의 것이 아니거나 해석할 수 없는 STUN 응답.
        case unexpectedSTUN
        /// DERP 보낸 쪽 키가 아는 피어가 아니다.
        case unknownDERPSender
        /// 직접 주소도 DERP 지역도 없어 보낼 곳이 없다.
        case noRouteToPeer
        /// 받을 수 없는 출처(IPv6, 포트 0).
        case unsupportedSource
    }

    /// - Parameters:
    ///   - discoKey: 이 노드의 disco 개인 키. 노드가 시작할 때 만들고 저장하지 않는다.
    ///   - nodeKey: 이 노드의 node 공개 키. 보내는 Ping에 넣는다(노트 4.6 1).
    ///   - localPort: UDP 소켓이 묶인 포트.
    ///   - localAddresses: 인터페이스의 IPv4 주소(loopback 제외). `LocalInterfaceAddresses`가 고른다.
    ///   - loopbackAddresses: loopback IPv4 주소. 다른 엔드포인트가 하나도 없을 때만 쓴다(노트 4.9 1.7).
    public init(
        discoKey: Curve25519.KeyAgreement.PrivateKey,
        nodeKey: NodePublicKey,
        localPort: UInt16,
        localAddresses: [IPAddress],
        loopbackAddresses: [IPAddress],
        now: ContinuousClock.Instant
    )

    public var discoPublicKey: DiscoPublicKey { get }

    /// netmap의 피어를 맞춘다. 순서가 주인을 정한다(같은 disco 키는 앞의 피어만 갖는다). 노드는 node ID 순으로 넘긴다.
    public mutating func setPeers(_ peers: [Peer], at now: ContinuousClock.Instant) -> [Output]
    /// 홈 후보 지역을 맞춘다. 바뀌면 곧바로 STUN 회차를 시작한다. 홈이 없으면 대체 홈을 곧바로 고른다.
    public mutating func setRegions(_ regions: [Region], at now: ContinuousClock.Instant) -> [Output]

    /// 엔진이 낸 WireGuard 데이터그램 하나를 피어에게 보낸다. 경로를 고른다.
    public mutating func send(_ datagram: [UInt8], to peer: NodePublicKey, at now: ContinuousClock.Instant) -> [Output]
    /// UDP 소켓에서 받은 데이터그램 하나.
    public mutating func receiveUDP(_ datagram: [UInt8], from source: IPEndpoint, at now: ContinuousClock.Instant) -> [Output]
    /// DERP 지역 `region`의 연결에서 받은 패킷 하나. `peer`는 DERP 프레임의 보낸 쪽 키다.
    public mutating func receiveDERP(_ packet: [UInt8], from peer: NodePublicKey, region: Int64, at now: ContinuousClock.Instant) -> [Output]

    /// now까지 기한이 지난 타이머를 처리한다(Ping 기한, heartbeat, 신뢰 만료, STUN 회차).
    public mutating func advance(to now: ContinuousClock.Instant) -> [Output]
    /// 다음에 `advance`를 불러야 하는 시각.
    public var nextDeadline: ContinuousClock.Instant? { get }

    /// 피어의 지금 경로. 데이터면에 없는 피어면 nil.
    public func path(to peer: NodePublicKey, at now: ContinuousClock.Instant) -> PeerPath?

    /// (M5) UDP 소켓이 새로 묶였다. 모든 피어의 직접 경로를 버리고 STUN 회차를 곧바로 시작한다.
    /// 규칙은 `SwiftailTunnel` 계약 동작 N 3.3.
    public mutating func rebind(localPort: UInt16, localAddresses: [IPAddress], loopbackAddresses: [IPAddress], at now: ContinuousClock.Instant) -> [Output]
    /// (M5) 소켓은 그대로이고 링크만 바뀌었다. STUN 회차만 다시 시작한다(Go `ReSTUN`).
    public mutating func restartSTUN(at now: ContinuousClock.Instant) -> [Output]
}
```

입력은 기존 상태 기계(`WireGuardDevice`, `DERPConnection`, `TailnetEngine`)와 같이 메서드로 받는다.

| 입력 | 메서드 |
| --- | --- |
| 받은 UDP 데이터그램과 출처 주소 | `receiveUDP(_:from:at:)` |
| DERP로 받은 패킷(보낸 쪽 키, 받은 지역) | `receiveDERP(_:from:region:at:)` |
| 엔진이 보낼 WireGuard 데이터그램 | `send(_:to:at:)` |
| netmap에서 뽑은 피어 정보 | `setPeers(_:at:)` |
| DERPMap에서 뽑은 홈 후보 지역 | `setRegions(_:at:)` |
| 시각 | 모든 메서드의 `at`, `advance(to:)` |
| 난수 | 안에서 시스템 난수로 뽑는다(위 문서 주석) |

### 내부 API (단위 간 약속)

병렬 구현을 위해 시그니처를 정한다. 이름은 바꾸지 않는다. 내부 구현 세부(저장 방식, 보조 함수)는 각 단위가 정한다.

```swift
// 단위 0 — Sources/SwiftailMagicsock/TransactionID.swift
struct TransactionID: Hashable, Sendable {
    static let byteCount = 12
    let bytes: [UInt8]
    init?(_ bytes: some Collection<UInt8>)                       // 12바이트가 아니면 nil
    static func random(using generator: inout some RandomNumberGenerator) -> TransactionID
}

// 단위 1 — DiscoMessage.swift, DiscoPacket.swift
enum DiscoError: Error, Sendable, Equatable {
    case malformed               // 길이·형식이 노트 3.3·3.4 표와 다름
    case unknownType(UInt8)      // 0x01–0x03이 아닌 type(0x04–0x09 포함)
    case authenticationFailed    // secretbox가 열리지 않음
    case invalidKey              // 저차수 공개 키(공유 키가 0)
}

enum DiscoMessage: Sendable, Equatable {
    /// - nodeKey: 보낸 쪽 node 공개 키. 없거나 0이면 nil. 패딩은 버린다.
    case ping(TransactionID, nodeKey: NodePublicKey?)
    /// - source: Ping의 관측 출발 주소. IPv4-mapped는 풀어서 담는다.
    case pong(TransactionID, source: IPEndpoint)
    /// 주소 목록. version ≠ 0, 0바이트, 18의 배수가 아닌 본문은 빈 목록이다(오류가 아니다).
    case callMeMaybe([IPEndpoint])

    init(parsing plaintext: [UInt8]) throws(DiscoError)
    /// 평문(type ‖ version 0 ‖ 본문). Ping은 패딩 없이, nodeKey가 nil이면 12바이트 본문.
    var plaintext: [UInt8] { get }
}

/// 자기 disco 개인 키와 상대 disco 공개 키의 NaCl box 공유 키(노트 3.2 2). 비밀이다. `customMirror`가 감춘다.
struct DiscoSharedKey: Sendable {
    init(privateKey: Curve25519.KeyAgreement.PrivateKey, peerPublicKey: DiscoPublicKey) throws(DiscoError)
}

enum DiscoPacket {
    static let magic: [UInt8]            // 54 53 f0 9f 92 ac
    static let classificationLength = 38 // 노트 4.1 3
    /// 길이 ≥ 38이고 magic으로 시작한다. 열어 보지 않는다.
    static func isDisco(_ bytes: [UInt8]) -> Bool
    /// 보낸 쪽 disco 공개 키(오프셋 6..<38). `isDisco`가 참일 때만 값이 있다.
    static func senderKey(of bytes: [UInt8]) -> DiscoPublicKey?
    /// magic ‖ sender ‖ nonce ‖ secretbox(plaintext). nonce는 24바이트.
    static func seal(_ message: DiscoMessage, sender: DiscoPublicKey, sharedKey: DiscoSharedKey, nonce: [UInt8]) -> [UInt8]
    static func open(_ bytes: [UInt8], sharedKey: DiscoSharedKey) throws(DiscoError) -> DiscoMessage
}

// 단위 2 — PeerPathState.swift (+ 필요하면 PeerPathState+Ping.swift)
struct PeerPathState: Sendable {
    enum Action: Sendable, Equatable {
        /// 후보에 disco Ping을 보낸다.
        case ping(TransactionID, to: IPEndpoint)
        /// 피어의 홈 DERP로 CallMeMaybe를 보낸다. 자기 엔드포인트는 `Magicsock`이 채운다.
        case callMeMaybe
    }
    /// WireGuard 데이터그램 하나를 보낼 곳(노트 4.5).
    struct SendPlan: Sendable, Equatable {
        var udp: IPEndpoint?
        /// DERP로도 보낸다면 피어의 홈 지역. 0이면 DERP로 보내지 않는다.
        var derpRegion: Int64
        var actions: [Action]
    }

    init(homeDERP: Int64, endpoints: [IPEndpoint])
    /// netmap 갱신(노트 4.4 1·2).
    mutating func update(homeDERP: Int64, endpoints: [IPEndpoint], at now: ContinuousClock.Instant)
    /// 피어의 disco 키가 바뀌었다(노트 4.4 3).
    mutating func resetForNewDiscoKey()
    /// 노트 4.5 1–5, 4.8 2.
    mutating func planSend(at now: ContinuousClock.Instant, using generator: inout some RandomNumberGenerator) -> SendPlan
    /// UDP로 온 Ping(노트 4.2 4.2). Pong을 보내야 하면 true(같은 후보의 같은 TxID면 false).
    mutating func receivePing(_ txID: TransactionID, from source: IPEndpoint, at now: ContinuousClock.Instant) -> Bool
    /// 이 피어가 보낸 Ping의 Pong이면 true(노트 4.6 4). `source`가 nil이면 DERP로 왔다.
    mutating func receivePong(_ txID: TransactionID, from source: IPEndpoint?, at now: ContinuousClock.Instant) -> Bool
    /// DERP로 온 CallMeMaybe(노트 4.8 5).
    mutating func receiveCallMeMaybe(_ endpoints: [IPEndpoint], at now: ContinuousClock.Instant, using generator: inout some RandomNumberGenerator) -> [Action]
    /// Pong 기한, heartbeat(노트 4.6 3, 4.8 3).
    mutating func advance(to now: ContinuousClock.Instant, using generator: inout some RandomNumberGenerator) -> [Action]
    /// Ping 기한, heartbeat, 신뢰 만료 가운데 가장 이른 것.
    var nextDeadline: ContinuousClock.Instant? { get }
    /// 마지막 외부 송신 시각. 없으면 nil. `Magicsock`이 유휴(ReSTUN 멈춤)를 판단한다.
    var lastSend: ContinuousClock.Instant? { get }
    func path(at now: ContinuousClock.Instant) -> PeerPath
}

// 단위 3 — STUNMessage.swift, Netcheck.swift
enum STUNMessage {
    /// DERP 노트 3.8의 40바이트 요청.
    static func bindingRequest(_ txID: TransactionID) -> [UInt8]
    /// 노트 4.1 1의 STUN 판정(길이 ≥ 20, 상위 2비트 0, cookie, 바이트 1이 0x01).
    static func looksLikeSTUN(_ bytes: [UInt8]) -> Bool
    /// DERP 노트 4.10 3의 응답 해석. 실패하면 nil.
    static func parseBindingResponse(_ bytes: [UInt8]) -> (TransactionID, IPEndpoint)?
}

struct Netcheck: Sendable {
    enum Action: Sendable, Equatable {
        case sendSTUN([UInt8], to: IPEndpoint)
        case endpointsChanged([Magicsock.Endpoint])
        case homeRegionChanged(Int64)
        /// 회차가 끝나 자기 엔드포인트를 다시 정했다(목록이 같아도). 미뤄 둔 CallMeMaybe를 보낼 때다.
        case endpointsRefreshed
    }
    init(localPort: UInt16, localAddresses: [IPAddress], loopbackAddresses: [IPAddress])
    mutating func setRegions(_ regions: [Magicsock.Region], at now: ContinuousClock.Instant, using generator: inout some RandomNumberGenerator) -> [Action]
    /// 회차가 진행 중이 아니면 새로 시작한다(노트 4.8 4.1의 ReSTUN).
    mutating func reSTUN(at now: ContinuousClock.Instant, using generator: inout some RandomNumberGenerator) -> [Action]
    mutating func receive(_ txID: TransactionID, mapped: IPEndpoint, at now: ContinuousClock.Instant) -> [Action]?   // nil: 이번 회차의 것이 아님
    /// DERP 지역에서 패킷을 받았다(홈 유지 판단, DERP 노트 4.10 5).
    mutating func noteDERPActivity(region: Int64, at now: ContinuousClock.Instant)
    /// - isActive: 피어가 있고 45초 안에 송신이 있었다. 거짓이면 주기 ReSTUN을 멈춘다.
    mutating func advance(to now: ContinuousClock.Instant, isActive: Bool, using generator: inout some RandomNumberGenerator) -> [Action]
    var nextDeadline: ContinuousClock.Instant? { get }
    var endpoints: [Magicsock.Endpoint] { get }
    /// 마지막으로 회차를 끝낸 시각. CallMeMaybe의 27초 신선도(노트 4.8 4.1).
    var endpointsRefreshedAt: ContinuousClock.Instant? { get }
    var homeRegion: Int64 { get }
}

// 단위 3 — Sources/SwiftailIO (package)
// `SocketError`에 `bindFailed(String)`, `sendFailed(String)`을 더한다. 메시지에는 errno 이름만 담는다.
// POSIX 호출과 주소 재해석은 이 파일에만 가두고 이유를 주석으로 남긴다(선례: Tests/SwiftailWireGuardInteropTests/POSIXIO.swift).
// 읽기는 DispatchSource 읽기 사건으로 깨어나 EAGAIN까지 읽는다(폴링하지 않는다). 파일 기술자는 Mutex로 지킨다.
package final class DatagramSocket: Sendable {
    /// IPv4 와일드카드(0.0.0.0)에 묶는다. port 0이면 OS가 고른다. 비차단.
    package init(port: UInt16 = 0) throws(SocketError)
    package var localPort: UInt16 { get }
    /// 받은 데이터그램의 흐름. 구독자는 하나다. 소비가 느리면 오래된 것부터 버린다(256개).
    package var datagrams: AsyncStream<(bytes: [UInt8], source: IPEndpoint)> { get }
    /// 보낸다. 기다리지 않는다. IPv6 목적지와 실패는 `SocketError`로 알린다(부르는 쪽이 버린다).
    package func send(_ bytes: [UInt8], to destination: IPEndpoint) throws(SocketError)
    package func close()
}

package enum LocalInterfaceAddresses {
    /// 지금 인터페이스의 IPv4 주소를 Go `netmon.LocalAddresses` 규칙으로 고른다(동작 E1).
    package static func current() throws(SocketError) -> (regular: [IPAddress], loopback: [IPAddress])
}
```

## 동작

번호는 시험과 검토에서 가리키는 이름이다. 프로토콜 세부는 괄호 안의 노트 절을 따른다.

### A. 받은 것의 분류 (`receiveUDP`, `receiveDERP`)

1. **UDP 분류 순서**(노트 4.1): 출처가 IPv6이거나 포트가 0이면 `unsupportedSource`. → STUN(`looksLikeSTUN`)이면 E2의 회차 표와 맞춘다. → Go가 Geneve로 보는 것(노트 4.1 2: 머리 조건이 맞고 protocol이 `0x7A12`, 또는 `0x7A11`이고 8바이트 뒤가 disco)이면 `unsupportedDisco`. `0x7A11`인데 뒤가 disco가 아니거나 다른 protocol이면 Go처럼 다음 단계로 내려간다. → disco(`isDisco`, 38바이트 기준)면 C. → 나머지는 `.wireGuard`.
2. **DERP 분류**(노트 4.3): disco(38바이트 기준)면 C(출처는 "DERP 지역 `region`, 보낸 쪽 `peer`"). 아니면 `peer`가 `setPeers`로 받은 피어일 때만 `.wireGuard`, 아니면 `unknownDERPSender`. 받은 모든 패킷은 `Netcheck.noteDERPActivity(region:)`에 알린다.
3. `.wireGuard`는 내용을 보지 않는다. 피어를 정하는 일은 WireGuard 장치가 receiver index로 한다(노트 4.1 "출발 주소와 피어의 연결"). 주소→피어 표를 두지 않는다.

### B. disco 키와 공유 키

1. **disco 키의 주인**: `setPeers`의 순서대로 disco 키 하나에 피어 하나만 둔다. 0인 disco 키의 피어는 disco를 하지 않는다(DERP만). 같은 disco 키를 내세운 뒤의 피어도 disco 없이 DERP만 쓴다. (Go는 같은 disco 키의 모든 피어에 Ping을 나눈다(노트 4.2 3·4). 키와 접두의 주인을 하나로 정한 엔진 규칙과 맞추고, 같은 disco 키가 둘인 정상적인 경우가 없어서다.)
2. **공유 키 캐시**(노트 3.2 5): `setPeers`에서 새 disco 키마다 한 번 계산하고, 빠진 키는 지운다. **받은 패킷마다 X25519를 하지 않는다**(모르는 키로 CPU를 쓰게 하지 못한다). 계산이 `invalidKey`면 그 피어는 disco 없이 DERP만 쓴다.
3. **피어의 disco 키가 바뀌면** `PeerPathState.resetForNewDiscoKey()`(노트 4.4 3).
4. `setPeers`에서 빠진 피어는 상태를 지우고 `.pathChanged(key, nil)`을 낸다(이미 nil을 알린 피어면 다시 내지 않는다). 새 피어는 아직 보낸 것이 없어 유휴이므로(G3) 사건을 내지 않는다. disco 키가 바뀐 피어의 경로는 nil이 된다(Go `invalidateDiscoPathLocked`가 마지막 송신 시각을 지우는 것과 같다). `.pathChanged`의 nil은 "빠졌거나 유휴"다.

### C. disco 받기 (노트 4.2)

1. 보낸 쪽 disco 키가 B1의 표에 없으면 `unknownDiscoKey`. 열기·해석 실패는 `malformedDisco`, `unknownType`은 `unsupportedDisco`. 어느 경우든 상태는 바뀌지 않는다.
2. **Ping**:
   - UDP로 왔으면 그 피어의 `receivePing(txID, from: 출처)`. true면 `Pong{txID, src: 출처}`를 그 출처로 UDP로 보낸다.
   - DERP로 왔으면 DERP 보낸 쪽 `peer`가 아는 피어여야 한다(아니면 `misroutedDisco`). 후보를 넣지 않고 `Pong{txID, src: 127.3.3.40:<region>}`을 같은 지역으로 그 `peer`에게 보낸다(노트 4.2 4.3·4.4).
   - Ping의 `nodeKey`는 쓰지 않는다(B1이 disco 키로 피어를 정한다. 노트 4.2 4.1의 주소→node 표가 없으므로 필요 없다).
3. **Pong**: 그 피어의 `receivePong(txID, from: UDP 출처 또는 nil)`. false면 무시한다(같은 disco 키의 다른 피어가 없으므로 넘길 곳이 없다).
4. **CallMeMaybe**: DERP로 왔고, DERP 보낸 쪽 `peer`의 피어가 있고, 그 피어의 disco 키가 메시지의 보낸 쪽 키와 같을 때만 `receiveCallMeMaybe`. 아니면 `misroutedDisco`(노트 4.2 3).
5. Pong이나 CallMeMaybe가 경로를 바꿨으면 `.pathChanged`.

### D. 경로 상태 기계 (`PeerPathState`, 노트 4.4~4.8)

1. **후보**(노트 4.4 1): netmap `Endpoints`, UDP Ping의 출처, DERP CallMeMaybe의 주소. **IPv4만** 받는다(소켓이 IPv4 하나다. 결정 표 "UDP 소켓"). IPv4-mapped는 푼다. IPv4 link-local(169.254/16)은 받는다(Go는 IPv6 link-local만 거른다). 자기 STUN 결과와 Pong의 Src는 후보가 아니다.
2. **지우기**(노트 4.4 2)와 **disco 키 변경**(노트 4.4 3)은 노트대로다.
3. **경로 선택**(노트 4.5 1–4): 신뢰 기간 안의 `bestAddr` → UDP만. 아니면 `bestAddr`(있으면) UDP + 피어 홈 DERP. 홈 DERP가 0이고 `bestAddr`도 없으면 `noRouteToPeer`로 버린다. (`shortcut:` 역방향 DERP 지역(노트 4.5 4, DERP 노트 4.9 3)은 쓰지 않는다. 홈 DERP가 0인 피어는 Go에서도 드물다. 필요해지는 시점: 그런 피어가 실제 tailnet 관문에서 보일 때.)
4. **보낼 때마다**(노트 4.5 3·5, 4.8 2): 신뢰된 직접 경로가 아니면 전체 Ping(CallMeMaybe 포함). 외부 송신 시각을 적고 heartbeat가 없으면 3초 뒤로 건다.
5. **Ping·Pong·기한**(노트 4.6), **`betterAddr`**(노트 4.7), **전체 Ping·heartbeat·CallMeMaybe 받기**(노트 4.8 1·3·5)는 노트대로다. 받은 Ping에는 Pong만 보낸다(노트 4.8 6).
6. **타이머 값은 Go와 같다**(노트 5절): Ping 기한 5초, 후보별 Ping 간격 5초, heartbeat 3초, 신뢰 6.5초, 유휴 45초, 좋은 지연 5 ms, 개선 Ping 1분, Ping으로 배운 후보 45초. 바꿀 수 있게 하지 않는다. 시험은 시각을 넘겨 확인한다.
7. **신뢰 만료도 기한이다**: `nextDeadline`에 `trustBestAddrUntil`을 넣어, 만료 시각의 `advance`에서 `Magicsock`이 `.pathChanged(.relayed)`를 낼 수 있게 한다.
8. `path(at:)`: `bestAddr`가 있고 `now ≤ trustBestAddrUntil`이면 `.direct(bestAddr)`, 아니면 `.relayed(derpRegion: homeDERP)`(노트 7.1의 `curAddr`).

### E. 자기 엔드포인트, STUN, 홈 지역 (`Netcheck`)

1. **인터페이스 주소**(`LocalInterfaceAddresses`, Go `net/netmon/state.go:38-143`): 올라와 있고 이름이 `zt`로 시작하지 않으며 `wt0`이 아닌 인터페이스의 IPv4 주소 가운데, Tailscale 주소(`100.64.0.0/10`, 단 `100.115.92.0/23` 제외)를 빼고, loopback 인터페이스나 loopback 주소는 `loopback`으로, link-local(169.254/16)은 따로 모아 일반 주소가 없을 때만 `regular`로 쓴다. 각 목록은 주소 오름차순. `getifaddrs` 호출은 이 파일에만 가두고 이유를 주석으로 남긴다.
   - 노드가 **시작할 때 한 번** 읽어 `Magicsock.init`에 넘긴다. `shortcut:` 주소 변경 감지는 M5(링크 변경과 함께, 노트 4.11).
2. **STUN 회차**(DERP 노트 4.10 1, Go `net/netcheck/netcheck.go:559-587`): `stunServers`가 있는 지역마다 0, 100, 200 ms에 `stunServers[try % count]`로 요청을 하나씩 보낸다(지역당 3개). 보낸 TxID를 이번 회차 표에 둔다. 지역의 첫 응답이 그 지역의 지연(보낸 시각부터)과 바깥 주소다. 모든 지역이 답했거나 시작 뒤 3초가 지나면 회차를 끝낸다. 회차의 것이 아닌 응답은 `unexpectedSTUN`.
3. **STUN 주소**(Go `netcheck.go:1665-1700`): 노드가 DERPMap에서 뽑는다. `stunTestIP`가 있으면 그 주소, 아니면 `ipv4`가 IPv4 리터럴일 때 그 주소. `stunPort` 0은 3478, 음수는 그 노드를 쓰지 않는다. `shortcut:` `ipv4`가 빈 노드의 DNS 조회는 하지 않는다(값 타입은 DNS를 할 수 없다. 운영 DERPMap은 IPv4 리터럴을 준다. 필요해지는 시점: 리터럴 없는 DERPMap을 만날 때 노드가 조회해 넘긴다).
4. **엔드포인트 목록**(노트 4.9 1의 2·7): 회차가 끝나면 `[STUN 전역 주소들(.stun)] + [localAddresses의 각 주소:localPort(.local)]`, 둘 다 비었으면 loopback 주소들:localPort(.local). 중복은 처음 것만. STUN 전역 주소는 회차의 첫 응답 주소와, 두 번 이상 관측된 주소다(노트 4.9 1.2). 회차가 끝날 때마다 `endpointsRefreshedAt`을 갱신하고 `.endpointsRefreshed`를 낸다. 목록이 **집합으로** 바뀌었을 때만 `.endpointsChanged`(Go `magicsock.go:1448-1473`은 순서가 달라도 같은 집합이면 같다고 본다). 지역이 하나도 없고 STUN 결과도 없는 목록은 내지 않는다(노트 4.9 5).
5. **주기**(노트 4.9 5, Go `magicsock.go:887-923`, `:3683-3712`): 회차가 끝나면 `isActive`일 때 20–26초 무작위 뒤에 다음 회차를 건다. `isActive`는 "피어가 하나 이상 있고, 어느 피어든 마지막 송신(`lastSend`) 뒤 45초가 지나지 않음"이다. 아니면 주기를 멈추고, 다음 `send`가 다시 건다. `setRegions`의 변경과 CallMeMaybe를 보내려는데 엔드포인트가 낡은 경우(F2)는 곧바로 회차를 시작한다.
   - Go의 유휴 판단은 TUN 송수신 시각이다(`net/tstun/wrap.go:842-853`, `wgengine/userspace.go:435`). 이 계약은 WireGuard 송신 시각으로 대신한다. 차이는 트래픽이 멈춘 뒤 WireGuard keepalive만큼(최대 둘, 약 20초. wireguard-go의 `needAnotherKeepalive`를 옮긴 동작이다) STUN이 더 돌고 유휴 판정(G3의 nil)이 늦는 것이다. Go 피어와 맞춰 본 값(2026-11-15): 마지막 트래픽 뒤 약 55~64초에 nil.
6. **홈 지역 선택**(DERP 노트 4.10 5, Go `netcheck.go:1426-1531`): 회차가 끝날 때 최근 5분 5초의 회차 기록에서 지역별 최소 지연에 `score`(양수일 때)를 곱해 가장 작은 지역을 고르고, 기존 홈이 아직 닿으면(이번 회차에 지연이 있거나 회차 시작 뒤 또는 8초 안에 그 지역에서 DERP 패킷을 받음) 차이가 10 ms 미만이거나 새 후보가 기존의 2/3보다 크면 유지한다. 측정이 하나도 없으면 120초 안에 DERP 패킷을 받은 기존 홈을 유지하고, 그래도 0이면 기존 홈을 유지한다(DERP 노트 4.8 1).
   - **대체 홈**: 홈이 0인 채로 `setRegions`가 오면 곧바로 지역 ID가 가장 작은 것을 홈으로 낸다(M3 규칙). 첫 회차(3초)를 기다리지 않고 DERP에 붙기 위해서다. 회차가 끝나면 6의 규칙으로 다시 고른다. 대체 홈은 6의 "기존 홈"이 아니다: 유지 조건의 기준은 **앞 회차가 측정해서 고른 홈**이고(Go는 앞 보고서의 `PreferredDERP`, `netcheck.go:1431`. magicsock의 대체 홈은 거기에 되들어가지 않는다), 처음 측정한 회차는 유지 조건 없이 가장 빠른 지역을 고른다. 측정이 없는 회차 뒤에는 120초 안에 DERP 패킷을 받은 경우에만 그 기준이 이어진다(M4 검토 A, 2026-11-15).
   - 홈이 바뀌면 `.homeRegionChanged`. `shortcut:` Go는 제어 서버와 맵 스트림이 끊긴 동안 홈을 바꾸지 않는다(DERP 노트 4.8 2). 이 계약은 바꾸되, 노드가 옛 홈 연결을 닫지 않으므로(엔진 계약 M4 동작 N3) 아직 옛 홈으로 보내는 피어의 패킷도 받는다. 바뀐 홈은 제어가 다시 이어진 뒤 올라간다.
   - `shortcut:` UDP가 막혀 STUN 응답이 없을 때의 HTTPS 지연 측정(DERP 노트 4.10 4)은 하지 않는다. 그때는 위 규칙대로 기존 홈을 유지한다.
   - DERP 활동은 `receiveDERP`로 받은 패킷만 센다. `DERPClient`는 KeepAlive를 올리지 않는다. 기존 홈이 STUN에는 답하지 않고 KeepAlive만 오는 드문 경우에 홈을 더 일찍 옮길 수 있다.

### F. CallMeMaybe 보내기 (노트 4.8 4)

1. `PeerPathState`의 `.callMeMaybe`를 받으면, `endpointsRefreshedAt`이 27초 안이면 지금 엔드포인트 **전체**를 주소만(`EndpointType` 없이) 담아 피어의 disco 키로 봉하고 `.derp(_, to: 피어, region: 피어 홈 DERP)`로 낸다. 홈 DERP가 0이면 보내지 않는다.
2. 낡았으면 그 피어를 "엔드포인트 갱신 뒤 보낼 목록"에 넣고 `reSTUN`을 부른다. `.endpointsRefreshed`가 오면 목록의 피어에게 1을 한다(목록은 피어당 한 칸).
3. UDP Ping과 CallMeMaybe의 순서는 보장하지 않는다(노트 4.8 4.3. Go도 같다).

### G. 경로 사건

1. `Magicsock`은 상태를 바꾼 모든 호출 끝에서, 영향을 받은 피어의 `path(at:)`가 마지막으로 알린 값과 다르면 `.pathChanged`를 낸다. `advance`에서는 신뢰가 만료된 피어도 본다(D7).
2. 같은 값은 다시 내지 않는다. `.direct(a)` → `.direct(b)`는 바뀐 것이다.
3. 유휴 피어의 경로는 nil이다(2026-11-15 첫 사용처 검토 뒤 더함): 그 피어로 마지막 WireGuard 데이터그램을 보낸 지 45초(유휴 판단, D의 타이머 값)가 넘었으면 `path(to:at:)`는 nil이고, 넘는 시각의 `advance`가 `.pathChanged(key, nil)`을 낸다. 다시 보내면 그때의 경로로 `.pathChanged`가 나온다.

### H. 한도 (신뢰할 수 없는 입력)

| 대상 | 한도 | 넘으면 |
| --- | --- | --- |
| 받은 UDP 데이터그램 | 65,535바이트(소켓 읽기 버퍼) | 소켓이 자른 것은 WireGuard·disco가 형식 오류로 버린다 |
| 피어당 후보 | 128개(Go의 정리 문턱 100 위의 상한) | 노트 4.4 2의 정리를 먼저 하고, 그래도 가득이면 새 후보를 넣지 않는다. CallMeMaybe 목록은 앞에서부터 넣는다 |
| 피어당 보낸 Ping 표 | 128개 | 새 Ping을 보내지 않는다(기한 5초로 비워진다) |
| STUN 회차 표 | 지역 수 × 3 | 회차가 끝나면 비운다 |
| CallMeMaybe를 미룬 피어 | 피어 수(피어당 한 칸) | 해당 없음 |
| 받은 CallMeMaybe 주소 | 데이터그램 길이로 묶인다 | 후보 한도가 막는다 |

- 실패는 닫힌 쪽이다. 해석·열기·경로 규칙을 어긴 disco는 상태를 바꾸지 않고 버린다. 응답(Pong)도 보내지 않는다. 열리지 않은 패킷을 WireGuard로 넘기지 않는다(노트 3.2 6).
- 어떤 바이트열을 `receiveUDP`·`receiveDERP`에 넣어도 죽지 않는다. 범위를 넘는 인덱스, 정수 넘침(지연 점수 계산은 나노초 `Int64`, 노트 4.7 4)이 없어야 한다.
- disco 메시지에는 재전송 방지가 없다(Go도 TxID 중복만 본다, 노트 4.2 4.2). 캡처한 Ping을 다른 주소에서 다시 보내면 그 주소가 후보가 된다. Ping은 그 주소로 가고, Pong이 와야만 `bestAddr`가 되므로 경로를 빼앗지는 못한다.

### I. 비밀

1. disco 개인 키와 공유 키는 `Magicsock`·`DiscoSharedKey`의 `customMirror`로 감춘다. `Magicsock`의 mirror는 `discoPublicKey`, 피어 수, 홈 지역만 보인다.
2. 출력(`Output`, `Drop`)에 키 재료가 없다. 봉한 바이트만 나간다.
3. disco 키는 저장하지 않는다(시작마다 새로, 노트 4.10 4).

## 결정 (노트 6.3 "총괄이 계약에서 정할 것")

| 결정 | 정한 것 | 근거 |
| --- | --- | --- |
| UDP 소켓 | IPv4 와일드카드 하나, OS가 고른 포트 | 관문이 IPv4로 된다. 이중 스택이면 받은 주소를 unmap해야 하고 Go와 표가 달라진다 |
| 타이머 값 | Go와 같게. 시각을 인자로 받아 시험이 넘긴다 | Go 피어의 하강·복귀 시점이 이 값으로 정해지고 관문이 그것을 본다 |
| 홈 지역 | STUN으로 재고 DERP 노트 4.10 5 규칙으로 고른다(E6). HTTPS 측정은 뺀다 | STUN은 엔드포인트에 어차피 필요하다. 시험 지역이 하나라 관문 결과는 같고 규칙은 단위 시험이 덮는다 |
| 올릴 엔드포인트 | local + STUN | 관문에서 Go의 loopback 엔드포인트가 STUN에서 나오므로 충분하다(노트 7.1) |
| CapabilityVersion | 148 유지 | 낮추면 다른 서버 동작이 바뀔 수 있다(노트 4.12, plan 위험 13) |
| relay·Geneve 메시지 | 버림 | 끊으면 Go 피어가 정상적으로 보낸 메시지로 경로가 깨진다(노트 4.12) |
| TSMP 광고 | 보내지 않음. 받은 것은 엔진이 소비만 한다 | Go는 netmap의 `DiscoKey`로 연다(노트 4.10 3) |
| 직접 경로 차단 시험 수단 | 둘 다: Swift 쪽 소켓 경계의 거르개 + 도구의 Go 노브 | 아래 "M4 관문" 3·4 |
| 경로 조회 API | Go `curAddr`과 같은 뜻(`PeerPath`) | Go 쪽 `peerStatus`와 같은 기준으로 관문을 판정할 수 있다 |

### 총괄 확정 (2026-11-15)

세 결정 모두 권고대로 정했다: Q1 (가), Q2 (가), Q3 (나). 아래 표는 선택지와 근거의 기록이다.

| # | 결정 | 선택지 | 권고 |
| --- | --- | --- | --- |
| Q1 | 엔진과 `Magicsock`을 어디서 잇는가 | (가) 노드가 두 값 타입을 저장 프로퍼티로 쥐고 출력을 서로에게 넘긴다 / (나) `TailnetEngine`이 `Magicsock`을 품고 UDP·DERP 출력을 낸다(plan 5절 의존 그림) | (가). 엔진 출력이 "피어에게 보낼 데이터그램"으로 남아 `SwiftailWireGuard` 계약의 원칙과 맞고, 엔진이 UDP·STUN·DERP 지역을 몰라도 된다. 대가는 잇는 코드(출력 네 갈래)가 actor에 있어 그 부분은 단위 시험 대신 노드 시험·관문이 덮는다 |
| Q2 | 경로 사건의 모양(RemoteDebug: "페어링한 Mac 하나의 경로 상태") | (가) `NodeEvent.peerPathChanged(fqdn:path:)`를 모든 피어에 대해 낸다 + `path(toPeerNamed:)` 조회 / (나) 피어별 `AsyncStream<PeerPath?>` / (다) 조회만 | (가). 사건 흐름이 하나라 앱이 따로 구독할 것이 없고, 경로 변화는 신뢰 기간(6.5초)보다 잦지 않다. 사건 버퍼(64개)가 다른 사건을 밀어낼 만큼 쌓이지 않는다 |
| Q3 | WireGuard cookie reply 보내기·부하 판정(M1 계약이 "신뢰할 수 없는 네트워크에 UDP 포트를 여는 M4"로 미룬 것) | (가) 이번 M4 단위에 넣는다 / (나) M4 마무리 관문(실제 네트워크) 전에 `SwiftailWireGuard` 계약 변경으로 따로 넣는다 / (다) M5 | (나). 관문(루프백·LAN)에는 필요 없고 `SwiftailMagicsock` 범위 밖이다. 다만 UDP 포트를 인터넷에 여는 마무리 관문 전에는 있어야 한다(node 공개 키는 비밀이 아니므로 initiation 홍수로 X25519를 강요할 수 있다) |

## 제외 (`shortcut:` 주석으로 남긴다)

| 제외 | 근거 | 필요해지는 시점 |
| --- | --- | --- |
| peer relay(0x04–0x09, Geneve) 송신·처리 | 노트 4.12. 받으면 버린다 | 측정에서 NAT 통과율이 문제일 때(plan 위험 4) |
| 경로 MTU 측정(패딩 Ping 보내기) | 노트 4.12. Go 기본 꺼짐, iOS에 없음. 받은 패딩 Ping에는 보통 Pong으로 답한다 | 해당 없음 |
| 포트 매핑(UPnP·NAT-PMP·PCP) | plan 3절 제외. 노트 6.2 | plan 위험 4의 측정 뒤 |
| IPv6 소켓·IPv6 엔드포인트·IPv6 후보 | 관문은 IPv4로 된다(노트 6.2) | IPv6만 되는 망(셀룰러 일부)을 M5 실기기에서 만날 때. 넣을 때는 두 소켓을 같은 포트에 묶는다 |
| Rebind, 링크 변경 감지, 주소 변경 뒤 ReSTUN, 송신 오류(`EHOSTUNREACH`·`EPERM`·broken pipe) 처리 | 노트 4.11, 4.5 6. 관문 상황에서 소켓·주소가 바뀌지 않는다. 송신 오류는 무시한다(DERP가 함께 나간다) | M5(`setDefaultInterface`, Wi-Fi ↔ 셀룰러) |
| `EndpointSTUN4LocalPort`, 클라우드 메타데이터, 5분 10초 광고 캐시, 고정 엔드포인트 | 노트 6.2 | 단단한 NAT에서 마무리 관문이 실패할 때 |
| TSMP 광고 보내기, TSMP 키 활성 전환 | 노트 4.10 3 | 해당 없음 |
| 주소→피어 표 | 노트 4.1. WireGuard가 피어를 알려 준다 | 해당 없음 |
| 역방향 DERP 지역(홈이 0인 피어) | 동작 D3. 노트 6.2 | 실제 tailnet에서 그런 피어가 보일 때 |
| Pong 기록 64개, UDP 수명 측정 | 비교에는 최신 지연만 쓴다(노트 6.2) | 해당 없음 |
| HTTPS 지연 측정, 맵 스트림이 끊긴 동안 홈 고정, DNS가 필요한 STUN 노드 | E3, E6 | E3, E6에 적음 |
| 홈이 아닌 DERP 연결의 정리(60초 미사용) | 열린 연결 수는 DERPMap 지역 수로 묶인다 | M5 메모리 측정에서 문제일 때(엔진 계약 M4 동작 N3) |
| CLI Ping(DERP로 보내는 disco Ping) | 관문은 Go 쪽 `peerPing`만 쓴다 | 해당 없음 |

## 시험

### 단위 시험 (`Tests/SwiftailMagicsockTests`, 소켓·시계 없음, 시각을 넘겨 결정적으로)

1. **`DiscoMessage`**: Go 기준값과 같은 평문 바이트(NodeKey 있는·없는 Ping, IPv4·IPv6 Pong, 주소 0·1·3개 CallMeMaybe). 노트 7.2 1의 경계: CallMeMaybe 17·19바이트와 version 1 → 빈 목록, Pong 29바이트 → `malformed`, Ping 12·44·45바이트(패딩), 32바이트 0 NodeKey → nil, 평문 0·1바이트, type 0x04–0x0A → `unknownType`, IPv4-mapped를 풀기.
2. **`DiscoPacket`**: 고정 키·고정 nonce로 봉한 바이트가 Go 기준값과 같다. Go가 봉한 바이트를 연다. nonce·tag·암호문·보낸 쪽 키 한 바이트 변조 → `authenticationFailed`. 37·38·61바이트의 판정. 저차수 공개 키 → `invalidKey`. `dump`에 공유 키가 나오지 않는다.
3. **`PeerPathState`**: 노트 4.7의 `betterAddr` 표(같은 주소 MTU, 없음, loopback +50 대 LAN +20, 지연 비율 점수, 1점 규칙)와 노트 4.7 계산(loopback이 LAN을 이긴다). 경로 선택 세 갈래와 `noRouteToPeer`. 신뢰 6.5초 경계(`==`). 후보별 Ping 5초 제한과 CallMeMaybe가 푸는 것. Pong 기한 5초: 신뢰가 남았을 때는 `bestAddr`를 지키고, 지났을 때만 지운다. heartbeat 3초, 45초 유휴 뒤 멈춤과 다음 송신에서 다시 걸림, 전체 Ping 조건(5 ms 이하면 생략, 1분 개선). 후보 지우기(netmap에서 빠짐, Ping으로 배운 것 45초, CallMeMaybe 교체)와 `bestAddr` 함께 지우기. 같은 후보·같은 TxID의 Ping에 Pong하지 않음. disco 키 변경. IPv6·IPv6 link-local 후보를 넣지 않음. 후보 128개·보낸 Ping 128개 한도.
4. **`STUNMessage`**: 고정 TxID의 요청이 Go `stun.Request`와 같다. Go `stun.Response`로 만든 IPv4·IPv6 응답, `0x8020`, MAPPED-ADDRESS만 있는 응답을 해석한다. 거절: 19바이트, cookie 틀림, 타입 `01 01` 아님, 선언 길이 초과, 속성 길이가 남은 바이트 초과, family 3, 주소 속성 없음. 무작위 입력으로 죽지 않음.
5. **`Netcheck`**: 회차의 요청 시각(0·100·200 ms)과 대상(`try % count`), 응답 대응과 회차 밖 응답, 3초 마감과 전 지역 응답 시 조기 마감, 엔드포인트 목록의 순서·중복·loopback 대체 규칙, STUN 전역 주소 규칙, 집합 비교(순서만 바뀌면 `.endpointsChanged` 없음), 주기 20–26초와 유휴·피어 없음에서 멈춤, 홈 선택(DERP 노트 4.10 5의 각 조건: 5분 5초 기록, `score`, 10 ms, 2/3, 8초 DERP 활동, 측정 없음 120초, 대체 홈 즉시 선택).
6. **`Magicsock`**: 둘을 메모리 "망"으로 맞물린다(각자 주소를 갖고 `.udp`는 상대의 `receiveUDP`로, `.derp`는 상대의 `receiveDERP`로. 망은 데이터그램을 버리거나 지연시킬 수 있다). 확인할 것:
   - 엔드포인트를 서로 netmap으로 알 때와 모를 때(Ping 출처로 배움, 노트 4.8 계산) 직접 경로가 선다. `.pathChanged(.direct)`가 나온다.
   - UDP를 막으면: 마지막 Pong + 6.5초에 `.relayed`, 그 사이 데이터는 UDP + DERP로 나간다, heartbeat Ping 기한(5초) 뒤 UDP 송신이 멈춘다. 풀면 다음 heartbeat(3초) 안의 전체 Ping으로 `.direct`. (관문 3의 계산된 시점을 시각으로 확인한다.)
   - DERP로 온 Ping에 같은 지역 DERP로 Pong(Src `127.3.3.40:<지역>`). UDP로 온 CallMeMaybe, 키가 맞지 않는 CallMeMaybe, 모르는 DERP 보낸 쪽의 Ping은 버리고 응답하지 않는다.
   - 모르는 disco 키의 패킷은 공유 키를 새로 계산하지 않고 버린다(공유 키 캐시 크기가 피어 수를 넘지 않음으로 확인).
   - peer relay 종류(0x04–0x09)와 Geneve 머리 데이터그램은 상태를 바꾸지 않는다(노트 7.2 7).
   - 회차 밖 STUN 응답은 WireGuard로 가지 않는다. 일반 데이터그램은 `.wireGuard`로 그대로 간다.
   - CallMeMaybe: 엔드포인트가 27초보다 낡았으면 미루고 회차를 시작하며, 회차가 끝나면 보낸다(노트 7.2 4의 Swift 쪽). 받으면 모든 후보에 즉시 Ping.
   - `setPeers`로 피어가 빠지면 `.pathChanged(_, nil)`. disco 키가 바뀌면 신뢰를 지운다.
   - 임의 바이트열(길이 0~200, disco magic으로 시작하는 것 포함)로 죽지 않는다. `dump`에 disco 개인 키·공유 키가 나오지 않는다.
7. **`SwiftailIO`**: `DatagramSocket` 둘이 루프백으로 주고받는다(포트, 출처 주소, 65,535바이트, `close` 뒤 흐름 끝남). `LocalInterfaceAddresses`의 고르기 규칙은 `getifaddrs` 결과를 흉내 낸 입력으로 시험한다(내부 함수를 `@testable`로).

### Go 기준값 대조

- **`Tools/interop/cmd/magicsockvectors`**(새 Go 도구, 단위 1이 쓴다): 시험용 공개 시드(`SHA-256("swiftail-vectors/disco/<번호>")`을 X25519 개인 입력으로)로 만든 disco 키 둘과 고정 nonce·TxID로 다음을 JSON(`Tests/SwiftailMagicsockTests/Fixtures/magicsock-vectors.json`)에 쓴다.
  - `disco.Ping/Pong/CallMeMaybe`의 `AppendMarshal` 평문(위 단위 시험 1의 사례).
  - 같은 평문을 `golang.org/x/crypto/nacl/box.Precompute` + `secretbox.Seal`(고정 nonce)로 봉한 겉 형식 전체. 도구는 그 바이트를 `key.DiscoPrivate.Shared(...).Open`으로 다시 열어 Go의 실제 열기 경로와 같은지 확인한 뒤 쓴다(Go의 `Seal`은 nonce를 안에서 뽑으므로 고정 nonce 봉인은 같은 계산을 직접 부른다. 노트 3.2 3).
  - 경계 사례(노트 7.2 1)를 `disco.Parse`에 넣은 결과(메시지 또는 오류).
  - `stun.Request(txID)`, `stun.Response(txID, addrPort)`(IPv4·IPv6), 그리고 그 응답을 `stun.ParseResponse`로 해석한 결과.
- 대조 시험은 구현자와 다른 세션이 쓴다(M3 필터 대조와 같다). 자료에는 현재 시각·운영 키가 없다.
- `betterAddr`와 타이머 동작은 Go 함수가 공개되어 있지 않으므로 노트 4.7·5절 표를 시험으로 옮긴다(파일 머리에 출처와 BSD-3-Clause).

## M4 관문

`Tools/interop`의 `tailnet`(testcontrol + DERP 지역 1개 + `127.0.0.1`의 STUN + Go tsnet 피어. 피어는 TCP·UDP 포트 7에서 에코한다)을 상대로 한다. Swift 노드는 실제 UDP 소켓을 연다. 시험은 `Tests/SwiftailInteropTests/DirectPathTests.swift`에 두고 `SWIFTAIL_TAILNET`이 없으면 건너뛴다.

### 도구에 더할 것 (`Tools/interop/cmd/tailnet`, README 갱신 포함)

1. `{"cmd":"setNeverDirectUDP","enabled":true|false}` → `envknob.Setenv("TS_DEBUG_NEVER_DIRECT_UDP", "true"/"false")`. 도구 프로세스의 모든 Go 피어에 걸린다(노트 7.2 3).
2. `peerStatus` 확장: 응답에 그 Go 노드 자신의 엔드포인트 `selfAddrs`(`Status.Self.Addrs`)와, 피어마다 `active`·`lastWrite`(노트 7.2 끝, Go `endpoint.go:2232-2253`).
3. `nodes` 확장: testcontrol에 등록된 노드마다 `endpoints`(testcontrol이 맵 요청에서 받아 둔 값, 노트 4.9 4). Swift 노드가 올린 엔드포인트를 Go 쪽에서 확인한다.

### Swift 쪽 시험용 UDP 거르개

`TailnetNode`의 UDP 가장자리에 둔다(엔진 계약 M4 동작 N8). `package func setBlockedUDPPorts(_ ports: Set<UInt16>)`: 그 원격 포트로 보낼 UDP와 그 포트에서 온 UDP를 소켓 경계에서 버린다. `Magicsock`은 모른다(시험 대상 내부가 아니라 소켓 경계, 노트 6.3). 공개 API가 아니다.

### 확인 항목

Go 피어와 Swift 노드 사이의 관찰(2026-11-15, 단위 4b, 5번 실행): 엔드포인트는 `running` 뒤 0.1초 안에 올라갔고, 첫 에코 뒤 약 0.9~1.0초에 양쪽 직접, Swift 쪽 차단 뒤 6.38~6.51초에 `.relayed`(한 번은 3.44초. 차단이 heartbeat Pong 직전에 걸리면 신뢰가 마지막 Pong부터 세어져 이르다), 풀면 0.11~0.20초(한 번 2.0초)에 직접, Go 노브를 켜면 5.0~6.2초에 중계, 끄면 0.07~0.9초에 직접, 130초 유지에서 에코 유실 0. 관문의 "6.5초(+3초) 안에"는 상한이지 하한이 아니다.

기준 관찰(2026-11-14, Go 피어 둘 사이, 도구의 `setNeverDirectUDP`): 켠 뒤 양쪽 `curAddr`가 6.45초·6.60초에 비었고(신뢰 기간 6.5초와 맞다), 끈 뒤 UDP를 보내자 약 0.04초에 직접 경로로 돌아왔다. 이 노브가 켜져 있어도 UDP 데이터는 계속 흐른다(탐색 Ping만 막는다). 노브를 켠 직후의 `peerPing`(disco)은 30초 뒤 시간 초과로 실패한다. 아래 시각 기대값은 이 관찰과 노트의 계산에 여유를 더한 것이다.

Go 피어 하나(`addPeer`)와 Swift 노드 하나로 시작한다. 시각 기대값은 노트 7.2 3의 계산이다. 시험은 기대 시각 + 여유(아래 괄호)까지 조건을 기다린다.

1. **엔드포인트**: Swift 노드가 `running` 뒤 10초 안에 `nodes`의 Swift 항목 `endpoints`에 `127.0.0.1:<Swift 포트>`가 있다(STUN 결과). Go `peerStatus`의 `selfAddrs`에서 Go 포트를 얻는다.
2. **직접 경로 성립(Swift가 먼저)**: Swift가 Go 피어의 IPv4 주소 포트 7로 UDP 에코를 1초 간격으로 보낸다. 15초 안에 (가) Go `peerStatus`의 Swift 항목 `curAddr`가 Swift가 올린 엔드포인트 가운데 하나이고(계산은 `127.0.0.1:<Swift 포트>`지만 Go가 LAN 주소를 고르는 것이 약 10번의 전환 가운데 2번 관찰됐다. 어느 것이든 받는다), (나) Swift `path(toPeerNamed:)`가 `.direct(127.0.0.1:<Go 포트>)`이며, (다) `peerPathChanged` 사건이 `.direct`로 나왔다. 에코는 계속 돌아온다.
3. **Swift 쪽 차단과 복귀**: `setBlockedUDPPorts([Go 포트])`. 에코를 계속 보내며
   - 6.5초(+3초) 안에 Swift 경로가 `.relayed(derpRegion: 1)`이고 Go `curAddr`가 빈 문자열이다.
   - 차단 직후 신뢰 기간에는 양쪽이 UDP로만 보내므로 에코가 빠진다. 신뢰가 지난 뒤(차단 + 9.5초)부터는 에코가 하나도 빠지지 않는다(UDP와 DERP로 함께, 이어서 DERP로만 나간다).
   - 차단을 푼다. 10초 안에 둘 다 직접 경로로 돌아오고 에코가 이어진다.
4. **Go 쪽 노브**: `setNeverDirectUDP true`. 6.5초(+3초) 안에 Swift 경로 `.relayed`, Go `curAddr` 빈 문자열. 에코는 계속된다. `false`로 되돌리면 10초 안에 둘 다 직접. (Go는 기한 처리할 Ping이 없어 UDP도 함께 보낸다. 노트 7.2 3.)
5. **Go가 먼저**: Swift 노드가 `running`이 된 뒤 새 Go 피어를 더하고, Swift가 그 피어에게 아무것도 보내지 않은 상태에서 Go 피어가 `peerPing`(disco)이나 `peerSend`로 Swift 주소를 1초 간격으로 부른다(ICMP `peerPing`은 쓰지 않는다. 메모리 장치의 Swift 노드에는 ICMP 응답기가 없어 늘 시간 초과다). 15초 안에 2의 (가)·(나)가 성립한다(Go가 netmap의 Swift 엔드포인트로 Ping하고, Swift가 Pong하며 Go의 출처를 후보로 배운다). Swift가 엔드포인트를 올리기 전에 Go가 먼저 보내는 경우(노트 4.8 계산)는 단위 시험 6이 덮는다.
6. **유휴와 재개**: 에코를 멈추고 50초 기다린다. Go `peerStatus`의 Swift 항목 `active`가 거짓이다(Go도 45초 유휴). 멈춘 뒤 75초 안에 Swift `path(toPeerNamed:)`가 nil이고 `peerPathChanged`가 nil로 나왔다(45초 + keepalive 최대 둘). 다시 보내면 15초 안에 직접 경로.
7. **2분 넘는 유지**: 직접 경로에서 에코를 1초 간격으로 130초 보낸다. 10초마다 본 Swift 경로와 Go `curAddr`가 모두 직접이고, 에코가 모두 돌아온다(WireGuard rekey 120초, heartbeat, 주기 STUN을 넘긴다).
8. **TSMP 광고**: 세션이 선 뒤 Go가 보낸 TSMP disco 광고가 `inboundPackets`에 나오지 않는다(M3과 같다).
9. **M3 관문 회귀**: M3 관문 2~7(UDP·TCP 에코, ACL, 피어 제거)을 직접 경로가 선 상태에서 다시 통과한다.

마무리 관문(실제 tailnet)은 이 관문과 Q3을 마친 뒤 총괄이 사용자에게 먼저 알리고 비밀 입력으로 인증 키를 받아 한다. 확인할 것: NAT 뒤 기기(사용자가 고른 실제 기기)와의 Swift `path(toPeerNamed:)`가 `.direct`가 되는지, 홈 지역이 STUN 측정으로 정해지는지, relay 서버가 있는 tailnet에서 Go 피어의 `CallMeMaybeVia`가 와도 직접·DERP 경로가 유지되는지(plan 위험 13).

## 구현 단위

소유 파일이 겹치지 않게 나눈다. 단위 0은 총괄이 먼저 한다(M3 단위 0과 같은 방식).

| 단위 | 내용 | 소유 파일 | 의존 |
| --- | --- | --- | --- |
| 0 | 자리 만들기: `IPEndpoint`를 `SwiftailBase`로 옮김(시험도), `SwiftailIO`에 `SwiftailBase` 의존, `SwiftailMagicsock`·`SwiftailMagicsockTests` 타깃, `Swiftail`·`SwiftailTests`·`SwiftailInteropTests`의 새 의존, `TransactionID.swift`, `PeerPath.swift`. 동작은 바꾸지 않는다(기존 시험 통과) | `Package.swift`, `Sources/SwiftailBase/IPEndpoint.swift`, `Sources/SwiftailControl/Tailcfg/IPEndpoint.swift`(Codable만 남김), `Sources/SwiftailMagicsock/{TransactionID,PeerPath}.swift` | 없음 |
| 1 | disco 코덱·암호와 Go 벡터 도구 | `Sources/SwiftailMagicsock/{DiscoMessage,DiscoPacket}.swift`, `Tests/SwiftailMagicsockTests/{DiscoMessageTests,DiscoPacketTests}.swift`, `Tools/interop/cmd/magicsockvectors/`, `Tests/SwiftailMagicsockTests/Fixtures/magicsock-vectors.json` | 0 |
| 2 | 경로 상태 기계 | `Sources/SwiftailMagicsock/PeerPathState*.swift`, `Tests/SwiftailMagicsockTests/PeerPathStateTests.swift` | 0 |
| 3 | STUN·Netcheck, UDP 소켓과 인터페이스 주소 | `Sources/SwiftailMagicsock/{STUNMessage,Netcheck}*.swift`, `Sources/SwiftailIO/{DatagramSocket,LocalInterfaceAddresses}.swift`, `Tests/SwiftailMagicsockTests/{STUNMessageTests,NetcheckTests}.swift`, `Tests/SwiftailIOTests/{DatagramSocketTests,LocalInterfaceAddressesTests}.swift` | 0. STUN 기준값 대조는 단위 1의 자료가 나온 뒤 |
| 4 | `Magicsock` 묶음 + 엔진·노드 통합(엔진 계약 "M4에서 바뀌는 것") | `Sources/SwiftailMagicsock/Magicsock*.swift`, `Tests/SwiftailMagicsockTests/MagicsockTests.swift`, `Sources/SwiftailEngine/*`, `Tests/SwiftailEngineTests/*`, `Sources/Swiftail/*`, `Tests/SwiftailTests/*` | 1, 2, 3 |
| 5 | 관문: 도구 명령과 Swift 관문 시험 | `Tools/interop/cmd/tailnet/*`, `Tools/interop/README.md`의 tailnet 절, `Tests/SwiftailInteropTests/DirectPathTests.swift` | 도구 부분은 0과 함께 시작. Swift 시험은 4 뒤 |

순서: 0 → (1, 2, 3, 5의 도구) 병렬 → 4 → 5의 Swift 시험 → 다른 세션의 검토 → 총괄이 관문을 다시 돌림. 단위 4가 가장 크다(상태 기계 묶음과 actor 통합). 둘로 나눈다면 4a(`Magicsock`)와 4b(엔진·노드, 4a의 공개 시그니처만 보고 시작)로 나누고 4b는 4a 병합 뒤 빌드한다. 대조 시험(벡터 자료를 읽는 시험)은 구현자와 다른 세션이 쓴다.
