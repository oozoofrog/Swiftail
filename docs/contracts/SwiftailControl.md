# SwiftailControl 계약 (M2)

제어 서버와의 대화 전체: 서버 키 조회, HTTP 업그레이드, Noise 연결, 그 위의 HTTP/2로 등록과 맵 스트림, 받은 맵을 netmap으로 유지하는 일.

프로토콜 세부는 교차 검증된 두 노트를 따른다.

- [protocol-notes/control-transport.md](../protocol-notes/control-transport.md): 업그레이드, Noise, 레코드, early payload, 키 형식. 7.3절에 고정 시험 벡터가 있다.
- [protocol-notes/control-map.md](../protocol-notes/control-map.md): 등록, 맵 요청·응답, 증분 적용, JSON 세부.

## 구조

M1과 같다. 프로토콜 로직은 입출력 없는 값 타입이고, 소켓과 시계는 가장자리의 actor 하나(`ControlClient`)만 갖는다.

```
 ControlClient (actor: TCP 연결, 시계, 재연결)                     ← 단위 4
   │ 바이트
   ├─ UpgradeRequest / UpgradeResponseParser   HTTP/1.1 업그레이드  ┐
   ├─ ControlHandshake → ControlSession        Noise IK, 레코드     ├ 단위 2 (Transport/)
   ├─ EarlyPayloadParser                       서버의 선행 메시지    ┘
   ├─ HTTP2ClientConnection                    SwiftailHTTP2        ← 단위 1
   ├─ MapResponseFramer                        길이 접두 프레임      ┐
   ├─ tailcfg 모델 (Codable)                   요청·응답 JSON       ├ 단위 3 (Tailcfg/, Netmap/)
   └─ MapSession → Netmap                      증분 적용            ┘
```

`Sources/SwiftailControl/Keys.swift`(공용 키 타입 `MachinePublicKey`, `NodePublicKey`, `DiscoPublicKey`, `ChallengePublicKey`)는 이미 있다.

## 단위 2: 전송 (`Sources/SwiftailControl/Transport/`)

```swift
public enum ControlTransportError: Error, Sendable, Equatable {
    case malformed                 // 길이·type·형식이 규격과 다름
    case upgradeRejected(status: Int)   // 101이 아님
    case handshakeFailed           // 복호화 실패, 서버의 error 메시지, 0 공유 비밀
    case authenticationFailed      // 전송 단계 레코드의 복호화 실패. 연결을 버려야 한다
    case messageTooLarge           // 레코드·early payload·업그레이드 응답 머리가 한도를 넘음
    case closed                    // 실패했거나 이미 끝난(결과를 돌려준) 상태 기계를 다시 부름. 송신 카운터 고갈
}

/// `POST /ts2021` 업그레이드 요청의 바이트.
public enum UpgradeRequest {
    public static func bytes(host: String, initiation: [UInt8]) -> [UInt8]
}

/// 업그레이드 응답을 읽는다. 머리가 다 오면 검증하고, 머리 뒤에 이미 도착한 바이트를 돌려준다.
public struct UpgradeResponseParser: Sendable {
    public init()
    /// 머리가 아직 다 오지 않았으면 nil. 다 왔으면 남은 바이트(Noise 계층의 것).
    public mutating func receive(_ bytes: [UInt8]) throws(ControlTransportError) -> [UInt8]?
}

/// 제어 Noise(Noise_IK_25519_ChaChaPoly_BLAKE2s)의 초기자.
public struct ControlHandshake: Sendable {
    /// 서버 키가 저차 점이라 공유 비밀이 0이면 `handshakeFailed`.
    public init(machineKey: Curve25519.KeyAgreement.PrivateKey, serverKey: MachinePublicKey, protocolVersion: UInt16 = 148) throws(ControlTransportError)
    /// 서버에 보낼 initiation 101바이트.
    public var initiation: [UInt8] { get }
    /// 서버가 보낸 바이트를 넣는다. response가 다 오지 않았으면 nil.
    /// 다 왔으면 전송 단계 세션과, response 뒤에 이미 도착한 바이트.
    public mutating func receive(_ bytes: [UInt8]) throws(ControlTransportError) -> (session: ControlSession, remainder: [UInt8])?
}

/// 전송 단계: 평문 바이트 스트림 ↔ 레코드.
public struct ControlSession: Sendable {
    /// 평문을 레코드(들)로 만든다. 한 레코드의 평문은 최대 4,077바이트다.
    public mutating func seal(_ plaintext: [UInt8]) throws(ControlTransportError) -> [UInt8]
    /// 받은 바이트를 넣고, 완성된 레코드들의 평문을 이어 돌려준다. 덜 온 레코드는 안에 둔다.
    public mutating func receive(_ bytes: [UInt8]) throws(ControlTransportError) -> [UInt8]
}

/// Noise 평문 스트림 맨 앞에 올 수 있는 서버의 선행 메시지를 걸러 낸다.
public struct EarlyPayloadParser: Sendable {
    public struct EarlyPayload: Sendable, Equatable {
        public var nodeKeyChallenge: ChallengePublicKey?
    }
    public init()
    /// 판단하기에 바이트가 모자라면 nil. 판단이 끝나면 (있었다면) 선행 메시지와 그 뒤의 바이트(HTTP/2의 것).
    public mutating func receive(_ plaintext: [UInt8]) throws(ControlTransportError) -> (payload: EarlyPayload?, remainder: [UInt8])?
}
```

규칙:

- 임시 키는 `ControlHandshake.init`에서 시스템 난수로 만든다. 고정 벡터 시험을 위한 internal 생성자(임시 키를 인자로 받는다)를 둔다.
- 레코드 nonce는 빅엔디언 카운터다(Noise 규격의 리틀엔디언이 아니다). 노트 3.5절.
- 복호화가 한 번 실패하면 세션은 `closed`가 되고 키를 버린다.
- 한도: 레코드 4,096바이트, early payload 10MiB, 업그레이드 응답 머리 16KiB. 한도를 넘거나 실패하면 받아 둔 바이트를 버린다.
- 업그레이드 응답의 상태 줄과 헤더 값에 홀로 있는 CR·LF, 탭 외의 제어 문자가 있으면 `malformed`.
- 키를 쥔 공개 타입(`ControlHandshake`, `ControlSession`)은 `CustomReflectable`로 자식을 감춘다. `print`·`dump`에 키 재료가 나오지 않는다.

시험: 노트 7.3절의 고정 벡터(initiation, response, 방향별 키, 카운터 0·1·2의 레코드, 빈 레코드), 조각난 입력(한 바이트씩), 4,077바이트 경계 분할, 변조된 레코드 뒤 `closed`, 서버 error 메시지, 101 뒤 EOF 처리에 필요한 상태, early payload 있음·없음·잘못됨, 업그레이드 응답의 상태·`Upgrade` 값 검증, 임의 입력으로 죽지 않음.

## 단위 3: 맵 (`Sources/SwiftailControl/Tailcfg/`, `Sources/SwiftailControl/Netmap/`)

### tailcfg 모델

Go의 `tailcfg` 타입에 대응하는 `Codable` 구조체. JSON 키는 Go 필드 이름 그대로다(대문자 시작).

- 요청: `RegisterRequest`, `MapRequest`, `Hostinfo`, `NetInfo`, `RegisterResponseAuth`
- 응답: `RegisterResponse`, `MapResponse`, `Node`, `PeerChange`, `DERPMap`, `DERPRegion`, `DERPNode`, `DNSConfig`, `UserProfile`, `Login`·`User`(등록 응답), `FilterRule`, `PingRequest`, `TKAInfo`
- 이름은 Go와 같게 둔다(프로토콜 용어다). 필드는 노트 3.2~3.7절의 표에서 "최소 클라이언트에 필요"한 것과 증분 적용에 쓰이는 것을 넣는다. 그 밖의 필드는 넣지 않아도 되지만 **모르는 키가 있어도 해독이 실패하면 안 된다.**
- 노트 3.1절의 JSON 규칙을 지킨다:
  - 보낼 때: `omitempty`가 없는 필드는 비어 있어도 내보낸다(0 키는 `nodekey:000…`, 0 시각은 `0001-01-01T00:00:00Z`). `omitempty`가 있는 필드는 비어 있으면 뺀다.
  - 받을 때: 시각의 소수 초와 UTC가 아닌 오프셋, 숫자 ID를 10진 문자열 키로 쓴 map, `null`인 `CapMap` 값, `opt.Bool`의 `true`·`false`·`null`.
  - 증분에서 의미가 갈리는 필드는 "키 없음"·`null`·빈 배열을 구분해 해독한다.

### 프레이밍과 증분 적용

```swift
/// 맵 스트림 본문을 프레임(4바이트 리틀엔디언 길이 + JSON)으로 자른다.
public struct MapResponseFramer: Sendable {
    public init()
    /// 받은 바이트를 넣고 완성된 응답들을 돌려준다. 프레임 경계는 HTTP/2 DATA 경계와 무관하다.
    public mutating func receive(_ bytes: [UInt8]) throws(MapError) -> [MapResponse]
}

public enum MapError: Error, Sendable, Equatable {
    case frameTooLarge              // 길이 접두가 한도를 넘음
    case malformed                  // JSON 해독 실패, 중첩 깊이·값 수 한도 초과
    case missingSelfNode            // 첫 일반 응답에 Node가 없음
    case stateTooLarge              // 세션이 쥔 상태가 한도를 넘음. 세션을 버리고 새로 시작한다
}

/// 지금의 tailnet 모습. 맵 응답을 차례로 적용한 결과다.
public struct Netmap: Sendable, Equatable {
    public var selfNode: Node
    public var peers: [Node]                       // Node ID 오름차순
    public var derpMap: DERPMap?
    public var dnsConfig: DNSConfig?
    public var packetFilter: [FilterRule]
    public var userProfiles: [Int64: UserProfile]  // 사용자 ID → 프로필
    public var domain: String
    public var tailnetLock: TailnetLockStatus      // M8부터. `ControlClient`가 낸 netmap은 이미 걸러져 있다(`SwiftailTailnetLock.md`). M2~M7에는 `tailnetLockEnabled: Bool`(감지만)이었다
    public var controlTime: Date?
}

/// 맵 스트림 하나의 상태. 응답을 적용해 netmap을 만든다.
public struct MapSession: Sendable {
    public struct Update: Sendable {
        /// 이 응답으로 바뀐 뒤의 netmap. 바뀐 것이 없으면 nil(KeepAlive, 같은 내용의 재전송, 서버 시각만 바뀐 응답).
        public var netmap: Netmap?
        /// 서버가 답을 요구한 핑. 호출하는 쪽이 처리한다.
        public var pingRequest: PingRequest?
    }
    public init()
    /// now는 응답을 받은 시각이다("지금 보였다"는 증분의 마지막 온라인 시각이 된다).
    public mutating func apply(_ response: MapResponse, receivedAt now: Date) throws(MapError) -> Update
}
```

- 증분 적용은 노트 4.3절의 알고리즘과 순서를 따른다: `Peers`(전체 교체), `PeersChanged`, `PeersRemoved`, `PeersChangedPatch`, `PeerSeenChange`, `OnlineChange`, `DERPMap`(부분 유지 규칙), `DNSConfig`, `PacketFilter`·`PacketFilters`(이름 붙은 증분, 빈 배열은 "모두 차단"), `UserProfiles`, `Domain`, `TKAInfo`, `ControlTime`.
- 한도(프레임): 8MiB(Go는 256MiB다. iOS 확장의 메모리 한도 때문에 낮춘다. 한도를 채운 정상 자료의 해독 최고치가 프레임 크기의 약 1.7배로 재어져, 8MiB면 약 14MB다. 큰 tailnet의 실제 맵 크기는 재지 못했다), JSON 중첩 깊이 64, 값(배열 원소 + 객체 멤버) 1,000,000개. 깊이와 값 수는 `JSONDecoder`에 넘기기 전에 바이트를 훑어 센다. 넘으면 `malformed`. 0 바이트가 든 페이로드도 `malformed`다(UTF-16·UTF-32로 쓴 JSON을 걸러 UTF-8만 해독기에 넘긴다).
- 한도(세션): 피어 20,000, 사용자 프로필 40,000, 이름 붙은 필터 256개, 필터 규칙 합 50,000. 넘으면 `stateTooLarge`. Go처럼 프로필은 세션 동안 지우지 않는다.
- 실패한 프레이머와 세션은 받아 둔 바이트·상태를 버리고 같은 오류만 반복한다.
- 상태 필드가 없는 응답(KeepAlive, 서버 시각·핑만 있는 것)은 netmap을 다시 만들지 않는다.
- `JSONValue`의 수는 `integer(Int64)` → `unsignedInteger(UInt64)` → `number(Double)` 순으로 해독한다. 64비트 범위를 넘는 정수와 고정밀 소수는 `Double`로 반올림된다.
- `RegisterResponseAuth`는 `CustomReflectable`로 인증 키를 가린다(`print`·`dump`에 길이만 나온다).
- `shortcut:` 값 수 한도는 해독을 끝낼 수 있는 크기로 묶을 뿐 확장의 메모리 한도(약 50MB)를 보장하지 않는다(빈 노드로 채운 최악의 프레임은 약 1.3GB, 정상 자료로 채우면 약 110MB. Debug 측정). M5에서 실기기 측정과 함께 `Peers` 원소 수를 해독 중에 제한하는 방식으로 조인다.
- 알려진 차이(고치지 않는다. 제어 서버는 Noise로 인증된 상대이고 Go 서버는 이런 JSON을 만들지 않는다): 유니코드 정규화로 같은 문자열이 되는 필터 이름은 하나로 합쳐진다(Go는 바이트로 구분). 중복 키는 Go와 다른 쪽이 남을 수 있다. 정수 자리에 `1.0`·`1e0`을 받는다(Go는 거절).
- zstd는 구현하지 않는다. `Compress`를 비워 비압축을 요청한다. `shortcut:` 운영 서버가 비압축을 받아 주지 않으면 해제기를 추가한다(M2 마무리 관문에서 확인).

시험: 노트 3.1절의 JSON 예와 Go가 만든 자료(`Tests/SwiftailControlTests/Fixtures/`, 다른 단위가 만든다)로 해독·부호화를 확인한다. 증분 적용은 Go의 실제 `mapSession`에 같은 응답 열을 넣어 얻은 결과와 비교한다. `null`·빈 배열·생략의 구분, 마지막 피어 제거, 조각난 프레임, 한도 초과(깊이·값 수·세션 상태의 경계, 보조 스레드의 작은 스택), 첫 응답에 Node 없음, 한 응답 안에서 같은 피어에 겹친 증분, 비밀이 `dump`에 나오지 않음.

## 단위 4: ControlClient (`Sources/SwiftailControl/Client/`)

단위 1~3의 상태 기계를 실제 연결에 잇는 가장자리다. 소켓과 시계는 여기에만 있다.

```swift
/// 노드의 신원: 기기를 가리키는 machine 키와 WireGuard에 쓰는 node 키.
public struct NodeIdentity: Sendable {
    public var machineKey: Curve25519.KeyAgreement.PrivateKey
    /// 등록을 마친 node 키. 아직 등록한 적이 없으면 nil.
    public var nodeKey: Curve25519.KeyAgreement.PrivateKey?
    public init()                                   // 새 machine 키, node 키 없음
    public var machinePublicKey: MachinePublicKey { get }
    public var nodePublicKey: NodePublicKey? { get }
}

/// 신원을 디렉터리의 파일 하나에 둔다. 다시 시작해도 같은 노드로 뜨게 하는 유일한 상태다.
public struct NodeIdentityStore: Sendable {
    public init(directory: URL)
    public func load() throws(ControlError) -> NodeIdentity?    // 파일이 없으면 nil
    public func save(_ identity: NodeIdentity) throws(ControlError)
}

public enum ControlError: Error, Sendable {
    case invalidConfiguration(String)
    case storage(String)                    // 신원 파일을 읽거나 쓰지 못함
    case connection(String)                 // 연결·전송 계층 실패(재시도 대상)
    case http(status: Int)                  // 200이 아닌 응답(429·503의 대기는 내부에서 처리)
    case authKeyRejected(String)            // 인증 키를 실은 등록의 RegisterResponse.Error
    case registrationRejected(String)       // 인증 키 없는 등록의 RegisterResponse.Error
    case nodeKeyExpired                     // 새 키로 다시 등록해도 만료
    // M2~M7에는 `tailnetLockEnabled`(lock이 켜진 tailnet을 거절)가 있었다. M8에서 없앴다(`SwiftailTailnetLock.md` 결정 L5)
}

public actor ControlClient {
    public struct Configuration: Sendable {
        public var serverURL: URL             // http:// 또는 https://
        public var hostname: String
        public var authKey: String?           // 새 node 키를 등록할 때 보낸다. 로그에 남기지 않는다
        public var ephemeral: Bool
        public init(serverURL: URL, hostname: String, authKey: String? = nil, ephemeral: Bool = false)
    }

    public enum Event: Sendable {
        /// 사용자가 이 URL에서 로그인해야 등록이 끝난다.
        case loginRequired(URL)
        /// 등록이 끝났다. 신원은 저장되었다.
        case registered(NodePublicKey)
        /// netmap이 바뀌었다(맵 스트림의 첫 응답 포함).
        case netmap(Netmap)
        /// 맵 스트림이 끊겼다. 물러났다가 다시 잇는다. 그동안 마지막 netmap은 유효하다.
        case disconnected
    }

    /// 지금 알려 둘 이 노드의 상태. 맵 스트림과 별개의 요청으로 올라간다.
    public struct LocalStatus: Sendable, Equatable {
        public var discoKey: DiscoPublicKey
        public var endpoints: [IPEndpoint]
        public var endpointTypes: [EndpointType]
        public var netInfo: NetInfo?
        public init(discoKey: DiscoPublicKey = .zero, endpoints: [IPEndpoint] = [], endpointTypes: [EndpointType] = [], netInfo: NetInfo? = nil)
    }

    public init(configuration: Configuration, identityStore: NodeIdentityStore)

    /// 사건의 흐름. 구독자는 하나다. `run()`이 끝나면 흐름도 끝난다.
    /// 읽지 않은 사건은 가장 새 것 64개만 남고 오래된 것부터 버린다(netmap 사건은 늘 전체 상태다).
    public nonisolated var events: AsyncStream<Event> { get }

    /// 등록하고, 상태를 올리고, 맵 스트림을 유지한다. 끊기면 물러났다가 다시 잇는다.
    /// 호출한 Task가 취소될 때까지 돌아오지 않는다. 다시 시도해도 소용없는 실패는 던진다.
    /// 클라이언트 하나에 한 번만 부른다. 겹쳐 부르든 끝난 뒤에 부르든 다시 부르면 `invalidConfiguration`.
    public func run() async throws(ControlError)

    /// 상태를 바꾼다. 연결되어 있으면 곧 올리고, 아니면 다음 연결 때 올린다. 마지막 값만 남는다.
    public func setLocalStatus(_ status: LocalStatus)

    /// 대화형 로그인 URL을 새로 요청한다(이미 등록되어 있어도). 연결을 새로 맺으므로 `disconnected`가 먼저 나간다.
    public func startInteractiveLogin()

    /// 연결을 내보낼 인터페이스를 바꾼다(nil이면 묶지 않는다). 지금 연결을 끊고 물러남 없이 다시 잇는다.
    public func setNetworkInterface(_ interface: NWInterface?)
}
```

동작(노트 control-map 4.1·4.2·4.4·4.5, control-transport 4장):

1. **연결**(끊긴 뒤의 판정: 연결이 끊겨도 이미 받은 응답으로 낼 결론—등록 거절처럼 다시 시도해도 소용없는 오류—이 연결 오류보다 앞선다. 진행 중이던 요청이 스스로 끝나기를 1초까지 기다린다): `GET <serverURL>/key?v=148`(URLSession)로 서버 키를 얻는다. `http://`이면 그 포트로 TCP, `https://`이면 443으로 TLS 연결을 열고(Network 프레임워크) 업그레이드 → Noise → early payload → HTTP/2. 연결 하나에 요청을 다중화한다. 끊기면 다음 요청 때 새로 맺는다.
   - `shortcut:` 80·443 경쟁, ControlDialPlan, 프록시는 없다. 필요해지는 시점: 443이 막힌 망이 보고될 때.
   - `shortcut:` 받는 쪽이 기한으로 버린 응답 스트림은 그 스트림에 다음 데이터가 올 때에야 RST_STREAM으로 취소한다. 답하지 않는 요청이 쌓여 서버의 동시 스트림 한도에 닿으면 다음 요청이 연결 오류가 되어 다시 연결한다.
   - `/key`의 TLS는 검증한다. 업그레이드 연결의 TLS도 검증한다(Go는 Noise가 서버를 인증하므로 검증 실패를 넘기지만, 여기서는 더 엄격하게 둔다).
2. **등록**: 저장된 node 키가 있으면 그것으로, 없으면 새 후보 키로 `POST /machine/register`.
   - 인증 키는 새 node 키를 등록할 때 보낸다: 처음 등록할 때와, 키가 만료되거나 로그인을 새로 해서 키를 바꿀 때다(재사용 인증 키면 스스로 다시 인증된다). 이미 등록된 저장 키로 다시 붙을 때(재시작)는 보내지 않는다(일회용 키는 이미 쓰였다. Go tsnet도 로그인이 필요한 상태에서만 인증 키를 넘긴다). `--TL`을 담고 있으면 그 앞부분만 보낸다.
   - `AuthURL`이 오면 `loginRequired`를 내고 같은 후보 키로 `Followup` 요청(긴 폴링)을 반복한다. 후보 키는 인증이 끝난 뒤에만 확정·저장한다.
   - `NodeKeyExpired`면 새 키로 한 번 더. `Error`면 인증 키를 실은 요청이었는지에 따라 `authKeyRejected` 또는 `registrationRejected`(앱이 사용자에게 다르게 안내한다. 서버 메시지는 진단용이다). 그 메시지에서 인증 키(원문과 `--TL` 앞부분)는 가리고 200자로 자른다.
   - 기한: 등록 요청 120초(Go에는 없는 값이다), Followup 긴 폴링 10분. 넘기면 연결 오류로 보고 물러났다가 다시 잇는다.
   - 확정 전의 후보 키와 Followup URL은 재연결 너머로 유지한다(사용자가 보고 있는 로그인 URL이 그 후보 키에 묶여 있다). 확정·거절·새 로그인 요청 때만 버린다.
   - 등록이 진행 중일 때 요청한 `startInteractiveLogin()`은 그 등록이 끝난 뒤에도 남아 새 등록을 일으킨다. 로그인을 기다리는 Followup 긴 폴링은 그 자리에서 그만두고 새 후보 키로 다시 시작해 새 URL을 알린다.
3. **상태 올리기**: `Stream=false, OmitPeers=true`인 맵 요청으로 Hostinfo·NetInfo·DiscoKey·Endpoints를 올린다. 응답 본문은 끝까지 읽고 버린다. 응답을 120초 안에 다 받지 못하면 연결 오류다(Go의 감시와 같다). 스트림이 열린 뒤의 변경도 이 형태로만 보낸다(다른 형태는 서버가 기존 스트림을 끊는다).
4. **맵 스트림**: `Stream=true, KeepAlive=true, Compress=""`. 바이트를 `MapResponseFramer` → `MapSession`에 넣고 netmap이 바뀌면 `netmap` 사건을 낸다. 120초 동안 아무것도 오지 않으면 끊고 다시 잇는다. 다시 이을 때는 새 `MapSession`으로 시작한다.
   - (M2~M7) `TKAInfo`로 tailnet lock이 켜진 것을 알면 `tailnetLockEnabled`로 끝냈다. M8부터는 서명 권한 상태를 동기화하고 피어를 거른다(`SwiftailTailnetLock.md` 동작 N).
   - self 노드의 키가 만료되면 등록부터 다시 한다. 새 맵이 오지 않아도 만료 시각이 지나면 그렇게 한다. 새 키로 다시 등록했는데도 만료면 `nodeKeyExpired`로 `run()`을 끝낸다.
   - `PingRequest`(Types가 빈 것)는 그 URL에 HEAD로 답한다. 나머지 종류는 무시한다.
5. **물러나기**: `min(n² × 10ms, 30s) × [0.5, 1.5)`. 전체 netmap을 받으면 초기화한다(self 키가 만료된 netmap은 초기화하지 않는다). 429와 `Retry-After`가 붙은 503은 그 시간만큼 기다린다(최대 5분).
6. **Hostinfo**: 노트 3.3절의 최소 필드. OS 이름과 버전, 호스트 이름, 앱 버전 자리에는 Swiftail임을 드러내는 값을 넣는다(공식 클라이언트로 가장하지 않는다).
7. **신원 파일**: 디렉터리 안의 파일 하나(JSON, 키는 `privkey:` + 16진). 원자적으로 쓰고 소유자만 읽게(0600) 한다. 키를 로그·오류·description에 넣지 않는다. M8부터 `"NLKey":"nlpriv:<시드 32바이트 ‖ 공개 키 32바이트의 16진>"`이 더 있다(tailnet lock 키. `SwiftailTailnetLock.md` 동작 R1). `NLKey`가 없는 옛 파일은 `run()`이 첫 연결 전에 같은 machine·node 키에 새 NL 키를 채워 다시 쓴다(같은 노드로 뜬다). 깨진 `NLKey`(길이, 접두사, 16진, 뒤 32바이트가 시드의 공개 키와 다름)는 `storage`다. 읽을 때는 심볼릭 링크를 따라가지 않고(`O_NOFOLLOW`), 정규 파일만, 64KiB까지만 읽는다(2026-11-17 보안 검증. tailnet lock 상태 파일도 같은 규칙으로 읽고 한도만 17MiB다). 어긋나면 `storage`다. 디렉터리의 주인과 권한은 보지 않는다: 다른 사용자가 쓸 수 없는 디렉터리를 주는 것은 앱의 몫이다(`NodeConfiguration.stateDirectory`).
8. **비밀의 출력**: `NodeIdentity`와 `Configuration`은 `CustomStringConvertible`·`CustomReflectable`을 채택해 `print`·`dump`에 개인 키와 인증 키를 드러내지 않는다(공개 키와 "가림" 표시만).
9. **인터페이스 묶기**(M5, `SwiftailTunnel` 계약 동작 N): `setNetworkInterface(_:)`로 받은 인터페이스로만 업그레이드 연결을 내보낸다(Network 프레임워크의 `requiredInterface`). 목적지가 루프백 주소나 `localhost`면 묶지 않는다.
   - 부를 때마다 지금 연결을 끊고 물러남 없이 다시 잇는다. 연결 중이든 맵을 받는 중이든 물러나는 대기 중이든 같다. 같은 인터페이스를 다시 알려도 다시 잇는다(같은 Wi-Fi에서 주소만 바뀌면 옛 연결은 죽어 있다. 다시 이을지는 부르는 쪽이 정한다). 연달아 부르면 가장 나중 값으로 한 번 다시 잇는다.
   - 등록 상태와 마지막 netmap은 유지되고, 끊긴 연결은 `disconnected`로 나온다. 물러나기 횟수는 0으로 되돌린다(옛 망의 실패가 새 망의 첫 시도를 늦추지 않게 한다).
   - `run()` 전에 부르면 값만 기억해 첫 연결에 쓴다.
   - `shortcut:` `/key` 조회는 URLSession이라 묶지 않는다. 터널이 잡는 경로는 tailnet 주소와 서비스 IP뿐이라 물리 인터페이스로 나간다고 본다. 실기기에서 터널로 들어가는 것이 보이면 `NetworkSocket` 위의 HTTP/1.1로 바꾼다.
   - `shortcut:` 망이 내려간 것(만족된 경로 없음)은 따로 다루지 않는다. 연결 오류와 물러나기로 처리된다.

구조: 연결 하나(소켓, `ControlSession`, `HTTP2ClientConnection`, 읽기 루프)를 감싼 internal 타입을 두고, 그 위에 "요청 하나를 보내 응답을 받는다"와 "응답 본문을 흘려 받는다" 두 가지를 얹는다. 등록·맵·상태 올리기는 그 둘로 쓴다. 구조적 동시성을 쓴다(분리된 Task를 흩뿌리지 않는다. 취소는 `run()`을 부른 Task의 취소로 전파된다).

단위 시험: 신원 저장(왕복, 파일 권한, 손상된 파일), 물러나기 계산, `--TL` 인증 키 자르기, Retry-After 해석, Hostinfo 부호화. 네트워크가 필요한 것은 아래 관문에서 다룬다.

## M2 관문

`Tools/interop`의 `tailnet`(testcontrol + DERP + STUN + Go tsnet 피어)을 상대로:

1. `/key` 조회 → 업그레이드 → Noise → HTTP/2 → 등록(인증 없이, 그리고 인증 키로).
2. 맵 스트림에서 netmap을 받는다: 자기 주소, Go 피어, DERPMap, DNSConfig, 패킷 필터.
3. Go 피어를 더하면 netmap에 나타난다. 주입한 증분(`PeersChanged`, `PeersRemoved`, `PeersChangedPatch`, `OnlineChange`)이 반영된다.
4. 다시 시작해도 같은 node 키와 같은 tailnet 주소다.
5. 스트림이 열린 채로 상태 갱신을 보내도 스트림이 끊기지 않는다. KeepAlive를 넘겨 2분 넘게 유지된다.
6. Go 쪽(`nodes`, `peerStatus`)에서 Swift 노드가 보인다.

마무리(사용자에게 먼저 알린 뒤): 실제 tailnet에 임시 노드로 등록해 운영 서버와의 차이를 확인한다. 특히 비압축 맵 응답, 운영 서버의 HTTP/2 동작, 증분 응답.
