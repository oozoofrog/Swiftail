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
    case messageTooLarge           // 레코드·early payload가 한도를 넘음
    case closed                    // 실패한 뒤의 호출
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
    public init(machineKey: Curve25519.KeyAgreement.PrivateKey, serverKey: MachinePublicKey, protocolVersion: UInt16 = 148)
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
- 한도: 레코드 4,096바이트, early payload 10MiB, 업그레이드 응답 머리 16KiB.

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
    case malformed                  // JSON 해독 실패
    case missingSelfNode            // 첫 일반 응답에 Node가 없음
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
    public var tailnetLockEnabled: Bool            // TKAInfo로 판단. M2는 감지만 한다
    public var controlTime: Date?
}

/// 맵 스트림 하나의 상태. 응답을 적용해 netmap을 만든다.
public struct MapSession: Sendable {
    public struct Update: Sendable {
        /// 이 응답으로 바뀐 뒤의 netmap. KeepAlive처럼 바뀐 것이 없으면 nil.
        public var netmap: Netmap?
        /// 서버가 답을 요구한 핑. 호출하는 쪽이 처리한다.
        public var pingRequest: PingRequest?
    }
    public init()
    public mutating func apply(_ response: MapResponse) throws(MapError) -> Update
}
```

- 증분 적용은 노트 4.3절의 알고리즘과 순서를 따른다: `Peers`(전체 교체), `PeersChanged`, `PeersRemoved`, `PeersChangedPatch`, `PeerSeenChange`, `OnlineChange`, `DERPMap`(부분 유지 규칙), `DNSConfig`, `PacketFilter`·`PacketFilters`(이름 붙은 증분, 빈 배열은 "모두 차단"), `UserProfiles`, `Domain`, `TKAInfo`, `ControlTime`.
- 한도: 프레임 하나 64MiB(Go의 256MiB보다 낮춘다. 확장의 메모리 한도 때문이다).
- zstd는 구현하지 않는다. `Compress`를 비워 비압축을 요청한다. `shortcut:` 운영 서버가 비압축을 받아 주지 않으면 해제기를 추가한다(M2 마무리 관문에서 확인).

시험: 노트 3.1절의 JSON 예와 Go가 만든 자료(`Tests/SwiftailControlTests/Fixtures/`, 다른 단위가 만든다)로 해독·부호화를 확인한다. 증분 적용은 Go의 실제 `mapSession`에 같은 응답 열을 넣어 얻은 결과와 비교한다. `null`·빈 배열·생략의 구분, 마지막 피어 제거, 조각난 프레임, 한도 초과, 첫 응답에 Node 없음.

## 단위 4: ControlClient (단위 1~3이 합쳐진 뒤 계약을 확정한다)

방향만 적는다.

```swift
public actor ControlClient {
    public init(serverURL: URL, identity: NodeIdentity, hostinfo: Hostinfo)
    /// 등록한다. 대화형 로그인이 필요하면 URL을 알리고 완료를 기다린다.
    public func register(authKey: String?) async throws(ControlError) -> RegistrationResult
    /// 맵 스트림을 열고 netmap이 바뀔 때마다 내놓는다. 끊기면 물러났다가 다시 잇는다.
    public func netmaps() -> AsyncThrowingStream<Netmap, Error>
    /// 엔드포인트·disco 키·Hostinfo 변경을 알린다(스트림을 끊지 않는 형태의 요청).
    public func updateStatus(_ status: NodeStatusUpdate) async throws(ControlError)
}
```

신원 저장(machine 키, node 키, 등록 결과)도 이 단위에서 정한다.

## M2 관문

`Tools/interop`의 `tailnet`(testcontrol + DERP + STUN + Go tsnet 피어)을 상대로:

1. `/key` 조회 → 업그레이드 → Noise → HTTP/2 → 등록(인증 없이, 그리고 인증 키로).
2. 맵 스트림에서 netmap을 받는다: 자기 주소, Go 피어, DERPMap, DNSConfig, 패킷 필터.
3. Go 피어를 더하면 netmap에 나타난다. 주입한 증분(`PeersChanged`, `PeersRemoved`, `PeersChangedPatch`, `OnlineChange`)이 반영된다.
4. 다시 시작해도 같은 node 키와 같은 tailnet 주소다.
5. 스트림이 열린 채로 상태 갱신을 보내도 스트림이 끊기지 않는다. KeepAlive를 넘겨 2분 넘게 유지된다.
6. Go 쪽(`nodes`, `peerStatus`)에서 Swift 노드가 보인다.

마무리(사용자에게 먼저 알린 뒤): 실제 tailnet에 임시 노드로 등록해 운영 서버와의 차이를 확인한다. 특히 비압축 맵 응답, 운영 서버의 HTTP/2 동작, 증분 응답.
