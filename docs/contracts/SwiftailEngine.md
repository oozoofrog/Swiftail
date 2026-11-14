# SwiftailEngine·Swiftail 계약 (M3)

netmap을 데이터면으로 바꾸는 층이다. M3의 목표는 **직접 UDP 경로 없이 DERP 중계만으로** Go tsnet 피어와 IP 패킷을 주고받는 것이다(`docs/plan.md` 7절 M3).

- `SwiftailEngine`: 입출력 없는 값 타입들. IP 패킷 해석, 패킷 필터, netmap → WireGuard 피어 계산, 그리고 이들과 `WireGuardDevice`를 묶은 데이터면 상태 기계 `TailnetEngine`.
- `Swiftail`: 공개 actor `TailnetNode`. `ControlClient`, `DERPClient`, `TailnetEngine`, 시계를 잇는 가장자리다.

프로토콜 세부는 [protocol-notes/netmap-engine.md](../protocol-notes/netmap-engine.md)(검증됨)와 [derp-stun.md](../protocol-notes/derp-stun.md) 4.8·4.9절을 따른다.

## 타깃

| 타깃 | 의존 | 내용 |
| --- | --- | --- |
| `SwiftailEngine` | `SwiftailBase`, `SwiftailWireGuard`, `SwiftailControl`, CryptoKit | 아래 "엔진" API. 소켓·시계 없음 |
| `Swiftail` | `SwiftailBase`, `SwiftailEngine`, `SwiftailControl`, `SwiftailDERP`, `SwiftailIO` | `TailnetNode` |

## M3에서 지원하는 범위

지원: 일반 Tailscale 피어(Go tsnet)와 그 자기 주소(/32, /128) 사이의 IPv4·IPv6 패킷. 홈 DERP 지역 하나.

지원하지 않는 것은 **닫힌 쪽으로** 처리한다(피어로 올리지 않거나 패킷을 버린다):

- 서브넷 경로·exit node(`RouteAll=false`, exit node 없음으로 고정), WireGuard 전용 피어(`isWireGuardOnly`), jailed 피어(`isJailed`), masquerade 주소가 있는 피어, tailnet lock 서명이 없는 피어(`unsignedPeerAPIOnly`. Go는 이런 피어와 겹치는 패킷 규칙이 있으면 규칙 전체를 비운다), `cap:` 출발지 규칙, shields-up.
- IP 조각과 IPv6 확장 헤더: 버린다(Go는 일부를 통과시킨다. 재조립하는 스택이 없으므로 M3은 받지 않는다).
- TSMP(IP 프로토콜 99): 받으면 엔진이 소비하고 위로 올리지 않는다. pong·거절·disco 광고는 보내지 않는다. `shortcut:` 위에서 내려온 TSMP를 버리지 않는다(Go는 host가 만든 TSMP를 버린다). TUN을 붙이는 M5에서 넣는다.
- 옛 형식의 규칙(`SrcBits`, `DstPorts[].Bits`)이 있으면 규칙을 모두 비운다. 자기 주소와 UDP 흐름 기록은 남으므로 먼저 보낸 UDP의 응답은 계속 받는다(Go와 같다).
- 직접 UDP, disco, STUN, 홈이 아닌 DERP 지역: M4.

## 엔진 API (`SwiftailEngine`)

```swift
/// 검증을 마친 IP 패킷 하나의 머리. 필터와 경로 선택이 읽는 필드만 담는다.
public struct IPPacket: Sendable, Equatable {
    public enum TransportProtocol: Sendable, Equatable { case tcp, udp, sctp, icmpv4, icmpv6, tsmp, other(UInt8) }
    public enum ParseError: Error, Sendable, Equatable {
        case malformed      // 길이·버전·머리 길이가 맞지 않음
        case fragment       // 조각(첫 조각 포함)
        case extensionHeader // IPv6 확장 헤더
    }

    /// 선언된 길이로 자른 패킷 전체.
    public let bytes: [UInt8]
    public let source: IPAddress
    public let destination: IPAddress
    public let transportProtocol: TransportProtocol
    /// TCP·UDP·SCTP의 포트. 그 밖에는 0.
    public let sourcePort: UInt16
    public let destinationPort: UInt16
    /// TCP에서 SYN이 켜지고 ACK가 꺼진 패킷(새 연결의 시작).
    public let isTCPSYN: Bool

    public init(parsing bytes: [UInt8]) throws(ParseError)
}

/// 들어오는 패킷을 받을지 정한다. tailcfg 필터 규칙과 자기 주소에서 만든다.
public struct PacketFilter: Sendable {
    public enum Verdict: Sendable, Equatable {
        case accept
        case drop(DropReason)
    }
    public enum DropReason: Sendable, Equatable { case notForUs, noRuleMatched, multicastOrLinkLocal }

    /// 규칙도 자기 주소도 없다. 모든 패킷을 버린다(netmap을 받기 전의 상태).
    public static var allowNone: PacketFilter { get }

    /// - Parameters:
    ///   - rules: `Netmap.packetFilter` 그대로.
    ///   - localAddresses: 자기 노드의 주소. 목적지가 여기에 없으면 버린다.
    public init(rules: [FilterRule], localAddresses: [IPAddress])

    /// 받은 패킷을 판정한다. 먼저 보낸 UDP의 응답이면 규칙이 없어도 받는다.
    public mutating func checkInbound(_ packet: IPPacket) -> Verdict
    /// 내보낸 패킷을 적어 둔다(UDP 응답을 받기 위해서다).
    public mutating func recordOutbound(_ packet: IPPacket)
    /// 규칙만 바꾸고 UDP 흐름 기록은 이어 간다.
    public mutating func replaceRules(_ rules: [FilterRule], localAddresses: [IPAddress])
}

/// netmap의 피어 하나를 데이터면에 올린 모습.
public struct EnginePeer: Sendable, Equatable {
    public var key: NodePublicKey
    /// 이 피어가 출발지로 쓸 수 있는 주소. WireGuard AllowedIPs가 된다.
    public var allowedIPs: [IPPrefix]
    /// 이 피어에게 보낼 때 쓸 DERP 지역. 0이면 모른다.
    public var homeDERP: Int64

    /// netmap에서 데이터면에 올릴 피어들을 고른다. 순서는 node ID 오름차순이다.
    public static func peers(in netmap: Netmap, at now: Date) -> [EnginePeer]
}

/// 한 노드의 데이터면: netmap, WireGuard, 패킷 필터를 묶은 상태 기계.
public struct TailnetEngine: Sendable {
    public enum Output: Sendable, Equatable {
        /// DERP로 보낼 WireGuard 메시지.
        case datagram([UInt8], to: NodePublicKey, derpRegion: Int64)
        /// 필터를 통과해 위로 올릴 IP 패킷.
        case ipPacket([UInt8])
        /// 버린 패킷. 진단과 시험용이다.
        case dropped(Drop)
    }
    public enum Drop: Sendable, Equatable {
        case inbound(PacketFilter.DropReason)
        case malformedPacket
        case unsupportedPacket        // 조각, IPv6 확장 헤더
        case consumedControlPacket    // TSMP
        case noPeerForDestination
        case noRouteToPeer            // 피어의 홈 DERP를 모르거나 우리 홈 지역이 아님
        case discoMessage             // M3은 disco를 처리하지 않는다
        case wireGuard(WireGuardError)
    }

    public init(nodeKey: Curve25519.KeyAgreement.PrivateKey, now: ContinuousClock.Instant, wallClock: Date)

    /// netmap을 적용한다: 피어를 더하고 빼고, 필터를 바꾼다. 나가야 할 것이 있으면 돌려준다.
    public mutating func apply(_ netmap: Netmap, homeDERP: Int64, at now: ContinuousClock.Instant, wallClock: Date) -> [Output]
    /// 위에서 내려온 IP 패킷 하나를 보낸다.
    public mutating func send(_ ipPacket: [UInt8], at now: ContinuousClock.Instant) -> [Output]
    /// DERP에서 받은 패킷 하나를 처리한다.
    public mutating func receive(_ packet: [UInt8], from peer: NodePublicKey, at now: ContinuousClock.Instant) -> [Output]
    /// now까지 기한이 지난 타이머를 처리한다(WireGuard 타이머, 피어 키 만료).
    public mutating func advance(to now: ContinuousClock.Instant) -> [Output]
    /// 다음에 advance를 불러야 하는 시각.
    public var nextDeadline: ContinuousClock.Instant? { get }
}
```

### 동작

1. **IP 패킷 해석**(노트 3.1·3.2): 경계에서 한 번 검증한다. IPv4는 20바이트 이상·IHL 5 이상·선언 길이가 버퍼 이하, IPv6는 40바이트 이상·선언 길이가 버퍼 이하, TCP(20)·UDP(8)·SCTP(12)·ICMP는 전송 머리의 최소 길이. 선언 길이 뒤의 바이트는 잘라 낸다. IP 프로토콜 번호 0과 255는 `malformed`다(Go는 둘을 Unknown으로 버린다). IPv4의 MF가 켜졌거나 오프셋이 0이 아니면, IPv6의 next-header가 44면 `fragment`. IPv6 next-header가 0·43·50·51·60·135·139·140이면 `extensionHeader`. Go의 약한 검사(IHL 최솟값 없음, 재사용 필드)는 옮기지 않는다.
2. **피어 계산**(노트 4.1, `RouteAll=false`·exit node 없음):
   - 올리지 않는 피어: `id`가 0, `key`가 0, 만료(`expired`이거나 0이 아닌 `keyExpiry <= now`), `discoKey`가 0이고 `homeDERP`가 0, 위 "지원하지 않는 것"의 피어.
   - AllowedIPs: 피어의 `allowedIPs` 가운데 (한 주소짜리이고 Tailscale 주소 범위) 또는 (피어의 `addresses`에 있는 것)만 남긴다. Tailscale 주소 범위는 `100.64.0.0/10`(단 `100.115.92.0/23` 제외)과 `fd7a:115c:a1e0::/48`. 남는 것이 없으면 올리지 않는다.
   - 키 하나는 피어 하나에만, 접두 하나도 피어 하나에만 준다. 같은 키나 같은 접두를 여러 노드가 내세우면 node ID가 작은 쪽이 갖는다(출발 주소가 피어 하나에 묶여야 한다. wireguard-go의 AllowedIPs도 접두마다 주인이 하나다).
   - `shortcut:` 만료는 로컬 시계로 판단한다(Go는 ControlTime으로 1분 넘는 시계 차를 보정한다). 접두의 호스트 비트가 남은 원문은 구분하지 못한다(`IPPrefix`가 해독 때 지운다).
3. **netmap 적용**(노트 4.2의 설계 선택, 6.1): 계산한 피어를 모두 `WireGuardDevice.addPeer`로 미리 올린다(Go의 지연 생성은 하지 않는다). 사라졌거나 올릴 수 없게 된 키는 `removePeer`. 같은 키의 AllowedIPs 변경은 세션을 유지한다. 필터는 규칙만 바꾸고 UDP 흐름 기록은 잇는다. 다음 키 만료 시각을 `nextDeadline`에 넣어 그때 피어를 내린다.
4. **보내기**: 패킷 해석 → 목적지가 어느 피어의 한 주소짜리 `addresses`와 같은지로 피어를 고른다(없으면 `noPeerForDestination`) → 피어의 `homeDERP`가 우리 홈 지역이 아니면 `noRouteToPeer` → `recordOutbound` → `WireGuardDevice.send`. 장치가 내놓은 `.datagram`에 지역을 붙여 돌려준다. 나가는 패킷에는 ACL을 적용하지 않는다(Go와 같다).
5. **받기**: 패킷이 disco magic `54 53 f0 9f 92 ac`로 시작하고 62바이트 이상이면 `discoMessage`로 버린다. (`shortcut:` Go의 disco 판정 기준은 38바이트다(`disco-magicsock.md`). 그 사이 길이의 것은 WireGuard 장치가 형식 오류로 버리므로 결과는 같다. M4에서 disco를 처리할 때 38로 맞춘다.) 아니면 `WireGuardDevice.receive`에 넣는다. 장치의 `.ipPacket`(복호화와 AllowedIPs 출발지 검사를 통과한 것)만 해석 → TSMP면 소비 → `checkInbound` → `accept`면 `.ipPacket`. 장치의 `.datagram`(핸드셰이크 응답 등)은 지역을 붙여 내보낸다. DERP 프레임의 보낸 쪽 키는 출발지 검사를 대신하지 않는다.
6. **필터**(노트 4.4~4.6):
   - 규칙 변환: `SrcBits`가 있거나 `DstPorts[].Bits`가 있으면 필터 전체가 `allowNone`이 된다(Go와 같다. 넓은 옛 규칙을 남기지 않는다). `IPProto`가 비면 TCP·UDP·ICMPv4·ICMPv6, 있으면 0…255만. 주소 문자열은 `*`, CIDR(호스트 비트가 남으면 그 항목을 버린다), `a-b` 범위, 단일 주소. `cap:`으로 시작하는 출발지와 해석할 수 없는 항목은 그 항목만 버린다. `CapGrant`만 있는 규칙은 패킷을 열지 않는다.
   - 판정 순서: 목적지가 multicast·link-local이면 버린다 → 목적지가 자기 주소가 아니면 `notForUs` → 프로토콜별 판정.
   - TCP: SYN이 켜지고 ACK가 꺼진 패킷만 규칙(프로토콜·출발 주소·목적 주소·목적 포트)을 본다. 나머지 TCP는 받는다(연결 추적이 아니다. Go와 같다).
   - UDP·SCTP: 흐름 기록에 있으면 받고, 아니면 규칙을 본다. 기록은 내보낸 UDP·SCTP의 역방향 튜플(프로토콜, 주소·포트 쌍)이고 512개 LRU, 시간 제한은 없다. 받은 패킷은 기록을 만들지 않는다.
   - ICMP: echo reply와 오류(v4 type 3·11·12, v6 type 1·2·3·4)는 받는다. 그 밖에는 포트를 보지 않고 출발·목적 주소만 맞는 규칙이 있으면 받는다. Go의 v4 오류 집합은 3·11·`0x12`(18)인데, 규격의 Parameter Problem은 12이므로 12를 쓴다(알려진 차이. Go 대조 자료에 표시한다).
   - 그 밖의 프로토콜: 그 번호를 명시하고 포트 범위가 0…65535인 규칙이 있을 때만 받는다.
   - 허용 규칙의 합이다. 거부 규칙과 우선순위는 없다.
7. `TailnetEngine`은 node 개인 키와 WireGuard 세션을 쥐므로 `CustomReflectable`로 자식을 감춘다.

## 노드 API (`Swiftail`)

```swift
public struct NodeConfiguration: Sendable {
    /// 신원 파일을 둘 디렉터리.
    public var stateDirectory: URL
    public var hostname: String
    public var controlURL: URL
    /// 첫 등록에만 쓴다.
    public var authKey: String?
    public var ephemeral: Bool
    public init(stateDirectory: URL, hostname: String, controlURL: URL, authKey: String? = nil, ephemeral: Bool = false)
}

public enum NodeEvent: Sendable {
    /// 사용자가 이 URL에서 로그인해야 한다.
    case loginRequired(URL)
    /// 등록되고 netmap을 받았다. 자기 tailnet 주소다. 주소가 바뀌면 다시 나온다.
    /// `reconnecting` 뒤 끊겼던 연결이 모두 돌아와도 다시 나온다.
    case running(addresses: [IPAddress])
    /// 제어 서버나 DERP와의 연결이 끊겼다. 다시 잇는 중이다.
    case reconnecting
}

public enum NodeError: Error, Sendable {
    case control(ControlError)
    case invalidConfiguration(String)
}

/// tailnet의 노드 하나. M3에서는 IP 패킷을 메모리로 주고받는다(TUN은 M5, 리스너는 M6).
public actor TailnetNode {
    public init(configuration: NodeConfiguration)

    /// 사건의 흐름. 구독자는 하나다. `run()`이 끝나면 흐름도 끝난다.
    public nonisolated var events: AsyncStream<NodeEvent> { get }
    /// 피어가 보냈고 필터를 통과한 IP 패킷. 구독자는 하나다. 소비가 느리면 오래된 것부터 버린다.
    public nonisolated var inboundPackets: AsyncStream<[UInt8]> { get }

    /// 등록하고, netmap을 받아 데이터면을 유지한다. 호출한 Task가 취소될 때까지 돌아오지 않는다.
    /// 다시 시도해도 소용없는 실패는 던진다. 노드 하나에 한 번만 부른다.
    public func run() async throws(NodeError)

    /// IP 패킷 하나를 tailnet으로 보낸다. 보낼 수 없으면 조용히 버린다(IP는 원래 그렇다).
    public func send(_ ipPacket: [UInt8])

    /// 대화형 로그인 URL을 새로 요청한다.
    public func startInteractiveLogin()
}
```

`docs/plan.md` 6절의 초안과 다른 점: `start()`/`stop()` 대신 `run()`과 Task 취소를 쓴다(`ControlClient`·`DERPClient`와 같은 모양이고, 분리된 Task 없이 수명이 호출 범위에 묶인다). `TunnelDevice`와 `TunnelNetworkSettings`는 M5에서 정한다.

### 동작

1. **시작**: `NodeIdentityStore`와 `ControlClient`를 만든다. disco 키를 새로 만들고(저장하지 않는다) 공개 키를 `LocalStatus.discoKey`로 올린다. **0이 아닌 DiscoKey가 없으면 Go 피어는 이 노드를 피어로 만들지 않는다**(노트 derp-stun 6절 7). M3은 disco 메시지에 답하지 않는다.
2. **등록 뒤**: `registered` 사건을 받으면 신원 파일에서 node 개인 키를 읽어 `TailnetEngine`을 만든다(키가 바뀌면 새로 만든다).
3. **홈 DERP**(노트 derp-stun 4.8): 첫 netmap의 DERPMap에서 `noMeasureNoHome`이 아니고 쓸 수 있는 서버(`stunOnly`가 아니고, `certName`이 비었거나 `hostName`과 같은 것)가 있는 지역 가운데 ID가 가장 작은 것을 고른다. `LocalStatus.netInfo.preferredDERP`로 올린다(**올리지 않으면 Go 피어가 보낼 곳을 모른다**). 그 지역에 `DERPClient`를 `isPreferred: true`로 띄운다. DERPMap에서 그 지역이 바뀌면 클라이언트를 다시 띄운다. 쓸 수 있는 지역이 없어지면 클라이언트를 내리고, DERP를 끊긴 연결로 세지 않는다. `shortcut:` 지연 측정 없음, 지역 하나만(M4).
   - `DERPServer` 변환: `hostName` 그대로, `ipv4`가 IPv4 주소면 그 주소·비었으면 DNS·그 밖이면(`"none"`) `ipv6`를 같은 규칙으로, 둘 다 못 쓰면 그 서버를 건너뛴다. `derpPort`가 0이면 443. `insecureForTests`면 `.noneForTests`. `hostName`이 빈 서버는 건너뛴다.
4. **netmap**: 받을 때마다 `engine.apply`. 자기 주소가 정해지면 `running`.
5. **패킷**: `send` → `engine.send`. DERP `packet` 사건 → `engine.receive`. 엔진의 `.datagram` → `DERPClient.send`, `.ipPacket` → `inboundPackets`. `nextDeadline`에 맞춰 `engine.advance`.
6. **구조적 동시성**: `run()` 안의 TaskGroup 하나에 제어, DERP, 타이머가 자식으로 돈다. `run()`을 부른 Task가 취소되면 모두 멈춘다. 엔진 호출은 actor가 직렬화한다.
7. **비밀**: node 개인 키와 disco 개인 키를 사건·오류·`description`·`dump`에 넣지 않는다.

## 시험

단위 시험(`Tests/SwiftailEngineTests`, 소켓·시계 없음. tailcfg 값은 JSON을 해독해 만든다):

- `IPPacket`: IPv4·IPv6의 TCP·UDP·ICMP 고정 패킷, 선언 길이로 자르기, 짧은 머리, IHL 4, 조각(MF, 오프셋, IPv6 44), 확장 헤더, 임의 입력으로 죽지 않음.
- 필터 변환과 판정: 노트 7절 3~6의 항목 — `*`·CIDR·단일 주소·범위·`cap:`, 포트 양끝, 빈 `IPProto`·명시 프로토콜·범위 밖 번호, 잘못된 CIDR·`SrcBits`, `CapGrant`만 있는 규칙, TCP의 SYN과 SYN이 아닌 패킷, ICMP의 주소만 보는 규칙과 echo reply, 자기 주소가 아닌 목적지, UDP 흐름 기록(먼저 보낸 것의 응답, 튜플 하나만 다른 것, 513번째 기록, 규칙 교체 뒤 유지).
- **Go 기준 대조**: Go의 실제 `wgengine/filter`에 같은 규칙과 패킷을 넣어 얻은 판정을 자료(`Tests/SwiftailEngineTests/Fixtures`)로 두고 비교한다. 자료는 `Tools/interop`의 도구가 만들고, 대조 시험은 구현자와 다른 세션이 쓴다. M3에서 일부러 다르게 한 것(조각, 확장 헤더, `cap:` 출발지)은 자료에 표시해 따로 본다.
- 피어 계산: 노트 7절 7 — 만료 경계(`==`, `<`, `>`), 만료 없음, 0 키, 빈 AllowedIPs, 서브넷·`/0`을 AllowedIPs에서 빼는지, 지원하지 않는 피어.
- `TailnetEngine`: 엔진 둘을 메모리에서 맞물려(한쪽의 `.datagram`을 다른 쪽 `receive`에) UDP 패킷이 왕복한다. netmap 갱신으로 피어 추가·삭제·키 교체, AllowedIPs 밖 출발지, disco 메시지, TSMP 소비, 홈 지역이 다른 피어, 키 만료 시각에 피어가 내려감. `dump`에 키가 나오지 않음.

## M3 관문

`Tools/interop`의 `tailnet`(testcontrol + DERP + Go tsnet 피어. 피어는 TCP·UDP 포트 7에서 에코한다)을 상대로, Swift 노드는 UDP 소켓을 열지 않으므로 모든 통신이 DERP를 거친다:

1. Swift 노드가 등록되고 `running`이 된다. Go 피어의 `peerStatus`에 Swift 노드가 보이고 그 경로가 DERP(relay)다.
2. **UDP 에코**: Swift가 Go 피어의 주소 포트 7로 보낸 UDP 패킷의 에코가 `inboundPackets`로 돌아온다. IPv4와 IPv6 각각.
3. **TCP**: Swift가 보낸 SYN에 Go 피어의 SYN-ACK가 돌아온다(포트 7). 리스너가 없는 포트에는 RST가 돌아온다.
4. **ACL**: Swift 노드의 맵에 특정 UDP 포트만 여는 필터를 주입한 뒤, Go 피어가 Swift 주소의 열린 포트로 보낸 UDP는 `inboundPackets`에 나오고 막힌 포트로 보낸 것은 나오지 않는다. TCP SYN도 같다. (Go 피어가 임의 주소·포트로 패킷을 보내는 명령을 도구에 더한다.)
5. Swift가 먼저 보낸 UDP의 응답은 필터가 모두 막힌 상태에서도 돌아온다.
6. 피어를 맵에서 지우면(`PeersRemoved` 주입) 그 피어로 가는 패킷이 더 나가지 않는다.
7. 2분 넘게 유지한 뒤에도 에코가 된다(WireGuard rekey와 DERP KeepAlive를 넘긴다).

마무리 관문(실제 tailnet)은 M4 끝에 한다.
