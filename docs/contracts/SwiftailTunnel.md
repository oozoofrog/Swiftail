# Swiftail 터널 계약 (M5, 초안)

M5의 목표는 **iOS 패킷 터널 노드**다. 앱의 Network Extension(패킷 터널 제공자)이 찾아 준 utun 파일 기술자로 IP 패킷을 주고받고, OS에 줄 주소·경로·DNS 설정을 산출하고, 서비스 IP(`100.100.100.100`, `fd7a:115c:a1e0::53`)로 오는 MagicDNS 질의에 답하고, 다시 시작해도 같은 노드로 뜨고, Wi-Fi ↔ 셀룰러 전환 뒤 복구한다(`docs/plan.md` 7절 M5). 첫 사용처는 iPhone의 패킷 터널 확장이고, 지금 그 자리의 Go 코어(`rd_start`·`rd_next_event`·`rd_status`·`rd_tunnel_*`·`rd_stop`)를 이 계약의 `TailnetNode`로 바꾸는 것이 목적이다. 라이브러리는 NetworkExtension 프레임워크에 의존하지 않는다. `NEPacketTunnelNetworkSettings` 적용, utun 찾기, `NWPathMonitor`는 앱의 몫이다.

이 문서는 **초안**이다. "첫 사용처 확인 필요" 절을 첫 사용처 쪽에 보내 호출 지점과 맞는지 검토받은 뒤 확정한다.

프로토콜 세부는 다음 노트를 따른다(모두 검증됨). 이 문서는 모듈 경계, M5 범위, 공개 API, 시험과 관문만 정한다.

- [dns-state-node.md](../protocol-notes/dns-state-node.md)(아래에서 "DNS 노트"): DNS 산출 4.1.4, 응답기 3.1·4.2, 서비스 IP 4.3, 상태 저장 4.4, 상태 기계 4.5, 네트워크 전환 4.6, 결정 표 6.4.
- [netmap-engine.md](../protocol-notes/netmap-engine.md)(아래에서 "엔진 노트") 4.8: 주소와 OS 경로 산출.
- [disco-magicsock.md](../protocol-notes/disco-magicsock.md)(아래에서 "magicsock 노트") 4.11: 재결속.

기존 계약과의 관계: [SwiftailEngine.md](SwiftailEngine.md)(M3, "M4에서 바뀌는 것" 포함)와 [SwiftailMagicsock.md](SwiftailMagicsock.md)(M4)의 내용은 그대로 두고, 이 문서가 M5의 변경을 덧붙인다. 어긋나면 이 문서가 앞선다. M4 단위 4(`Magicsock` 통합)가 끝난 상태를 출발점으로 삼는다.

## 타깃

| 타깃 | M5에서 더하는 것 | 근거 |
| --- | --- | --- |
| `SwiftailEngine` | DNS 메시지 코덱, MagicDNS 응답기, 서비스 IP 응답 패킷 만들기, 터널 설정 산출(`TunnelNetworkSettings`), `TailnetEngine.send`의 로컬 처리(서비스 IP·자기 주소). 모두 입출력 없는 값 타입 | plan 5절 모듈 표가 "netmap → 경로·DNS, MagicDNS 응답기, TUN"을 엔진 몫으로 둔다. 소켓·시계 없이 시험할 수 있다 |
| `SwiftailIO` (package) | `UTUNDevice`(utun 파일 기술자의 검사·복제·읽기·쓰기), 소켓을 인터페이스에 묶기(`DatagramSocket`의 `IP_BOUND_IF`, `NetworkSocket`의 `requiredInterface`) | POSIX 호출을 가장자리 한 곳에 가둔다(plan 5절 코드 기준) |
| `SwiftailControl` | `ControlClient.setNetworkInterface(_:)`(연결을 끊고 새 인터페이스로 다시 잇기), 맵 프레임 한도를 줄임 | 제어 연결의 재결속(DNS 노트 4.6.3 4)과 메모리 |
| `SwiftailDERP` | `DERPClient`가 인터페이스를 받음, 받은 패킷 버퍼의 바이트 한도 | DERP 연결의 재결속(DNS 노트 4.6.3 2)과 메모리 |
| `SwiftailMagicsock` | `Magicsock.rebind(localPort:localAddresses:loopbackAddresses:at:)` | magicsock 노트 4.11 2 |
| `Swiftail` | 공개 API: `TunnelDevice`, `NodeState`, `NodeStatus`, `TailnetNode`의 M5 모양, 상태 기계, utun 읽기 루프, 상태 디렉터리 중복 거절 | 공개 API는 `Swiftail`에만 둔다(기존 구조) |

새 타깃은 만들지 않는다. 의존 방향도 바뀌지 않는다. `Swiftail`이 Network 프레임워크의 `NWInterface`를 공개 API에 쓴다(plan 4절(c)가 허용한 프레임워크다).

`TunnelNetworkSettings`는 `SwiftailEngine`의 공개 타입이다(`PeerPath`가 `SwiftailMagicsock`의 것인 것과 같다). 앱은 `import Swiftail`, `import SwiftailEngine`(설정 타입), `import SwiftailBase`(`IPAddress`·`IPPrefix`)를 쓴다.

## M5에서 지원하는 범위

지원: utun 하나, IPv4·IPv6 tailnet 주소, 피어별 경로(iOS 규칙), MagicDNS의 UDP 질의(tailnet 이름·역방향 영역·`ExtraRecords`), 서비스 IP의 ICMP echo, `setDefaultInterface`로 알린 기본 인터페이스 전환.

지원하지 않는 것은 닫힌 쪽으로 처리한다(아래 "제외" 표에 근거와 필요해지는 시점). 서브넷 경로·exit node는 M3부터 그대로 받지 않는다.

## 공개 API (`Swiftail`, M5 시점 전체)

```swift
import Network
import SwiftailBase
import SwiftailEngine
import SwiftailMagicsock

/// `TailnetNode` 하나를 띄우는 데 필요한 설정. (M3에서 바뀐 것: `defaultControlURL`)
public struct NodeConfiguration: Sendable {
    /// Tailscale 제어 서버(`https://controlplane.tailscale.com`, Go `ipn.DefaultControlURL`).
    public static let defaultControlURL: URL
    /// 신원 파일(`identity.json`)을 둘 디렉터리. 파일 URL이어야 한다. 노드 둘이 같은 디렉터리를 동시에 쓰지 못한다.
    public var stateDirectory: URL
    public var hostname: String
    public var controlURL: URL
    /// 첫 등록과 node 키를 새로 등록할 때 쓴다(저장된 키로 다시 붙을 때는 보내지 않는다). 저장하지 않는다.
    public var authKey: String?
    public var ephemeral: Bool
    public init(stateDirectory: URL, hostname: String, controlURL: URL = Self.defaultControlURL,
                authKey: String? = nil, ephemeral: Bool = false)
}

/// 노드가 IP 패킷을 주고받는 장치.
public enum TunnelDevice: Sendable {
    /// Network Extension이 만든 utun 제어 소켓. 노드는 이 기술자를 복제해 쓰고 원래 기술자는 닫지도 읽지도 않는다.
    ///
    /// - Parameter mtu: 앱이 `NEPacketTunnelNetworkSettings.mtu`로 적용하는 값. 1280…1420. 노드는 utun의 MTU를
    ///   바꾸지 않고, 이 값을 `TunnelNetworkSettings.mtu`로 돌려준다.
    case utun(fileDescriptor: Int32, mtu: Int = 1280)
    /// 메모리 장치. `TailnetNode.send(_:)`로 넣고 `inboundPackets`로 받는다. 시험과 관문용이며 utun과 같은 처리를 거친다.
    case memory(mtu: Int = 1280)
    /// (M6) 프로세스 안의 TCP 스택. `TailnetNode.listen(port:)`·`connect(to:port:)`는 이 장치에서만 쓴다. MTU는 1280 고정.
    case inProcess
}

/// 노드의 상태. Go `ipn.State`에서 앱이 쓰는 것만 남겼다(DNS 노트 4.5).
public enum NodeState: Sendable, Equatable {
    /// 등록·netmap·첫 연결을 기다린다.
    case starting
    /// 사용자가 이 URL에서 로그인해야 한다. 노드가 등록을 시작하면 제어 서버가 늘 URL을 준다.
    case needsLogin(URL)
    /// tailnet 관리자가 이 기기를 승인해야 한다(netmap 자기 노드의 `MachineAuthorized`가 거짓).
    case needsMachineAuth
    /// netmap을 받았고, 홈 DERP 연결이 섰거나 피어 하나와 WireGuard 핸드셰이크를 마친 적이 있다.
    case running
}

/// 노드가 알리는 변화. `TailnetNode.events`로 받는다. (M4에서 바뀐 것: 아래 "총괄 확인 필요" T1)
public enum NodeEvent: Sendable, Equatable {
    /// 상태가 바뀌었다. 같은 상태는 다시 내지 않는다.
    case stateChanged(NodeState)
    /// 피어의 경로가 바뀌었다. nil은 그 피어가 데이터면에서 빠졌거나 유휴라는 뜻이다(M4 그대로).
    case peerPathChanged(fqdn: String, path: PeerPath?)
    /// (M8) tailnet lock의 모습이 바뀌었다. `docs/contracts/SwiftailTailnetLock.md` 결정 L4.
    case tailnetLockChanged(TailnetLockStatus)
    /// 새로 더함(2026-11-18). `status`의 값이 바뀌었다. 값은 싣지 않는다(T1). 아래 "status 바뀜 사건".
    case statusChanged
}

/// 지금 노드의 모습. 앱의 상태 화면과 진단이 읽는다.
public struct NodeStatus: Sendable, Equatable {
    public var state: NodeState
    /// 자기 tailnet 주소(netmap 자기 노드의 `Addresses`). netmap 전에는 비어 있다.
    public var addresses: [IPAddress]
    /// 자기 MagicDNS 이름에서 끝의 점을 뗀 것(`rd-phone-1a2b3c4d.tail0001.ts.net`). netmap 전에는 nil.
    public var fqdn: String?
    /// 자기 노드의 `StableID`. 첫 사용처의 페어링이 이 값에 묶인다. netmap 전에는 nil.
    public var stableID: String?
    /// ts.net 인증서를 받을 수 있는 이름(netmap `DNSConfig.CertDomains`). M5는 읽어 보여 주기만 한다.
    public var certDomains: [String]
    /// netmap의 피어 수.
    public var peerCount: Int
    /// 마지막으로 `networkSettings`에 낸 설정. 아직 내지 않았으면 nil.
    public var networkSettings: TunnelNetworkSettings?
}

public enum NodeError: Error, Sendable {
    case control(ControlError)
    /// 설정이 잘못되었다: 상태 디렉터리, 제어 서버 URL, 호스트 이름, utun 기술자, MTU. `run()`을 두 번 부른 것도 여기다.
    /// 메시지는 무엇이 잘못됐는지만 담는다(경로·키 없음).
    case invalidConfiguration(String)
    /// UDP 소켓을 열거나 묶지 못했다(M4).
    case udpUnavailable(String)
    /// 새로 더함. 같은 프로세스의 다른 노드가 이 상태 디렉터리로 돌고 있다.
    case stateDirectoryInUse
    /// 새로 더함. 터널 장치를 더 읽을 수 없다(utun 읽기 오류나 끝). 메시지에는 errno 이름만 담는다.
    case tunnelDeviceClosed(String)
}

public actor TailnetNode {
    /// 설정과 장치를 검사한다. 파일·소켓·Task를 만들지 않는다(utun 검사는 읽기만 하는 시스템 호출이다).
    public init(configuration: NodeConfiguration, device: TunnelDevice = .memory()) throws(NodeError)

    /// 상태·경로·lock·모습의 사건. 구독자는 하나다. `run()`이 끝나면 흐름도 끝난다.
    /// 읽지 않은 것은 가장 새 것 64개까지. `statusChanged`는 하나만 맨 뒤에 남고 이 한도에 세지 않는다.
    public nonisolated var events: AsyncStream<NodeEvent> { get }

    /// 새로 더함(2026-11-18). `stateDirectory`에 등록을 마친 신원(node 키가 든 `identity.json`)이 있는가. 아래 동작 P 5.
    public static func hasSavedIdentity(in stateDirectory: URL) throws(NodeError) -> Bool

    /// 앱이 OS에 적용할 터널 설정. 바뀐 경우에만 나오고, 읽지 않은 것은 **가장 새 것 하나만** 남는다.
    /// 구독자는 하나다. `run()`이 끝나면 흐름도 끝난다.
    public nonisolated var networkSettings: AsyncStream<TunnelNetworkSettings> { get }

    /// 메모리 장치일 때 피어가 보냈고 필터를 통과한 IP 패킷과 노드가 로컬에서 만든 응답(MagicDNS 등).
    /// utun 장치일 때는 아무것도 내지 않는다(패킷은 utun으로 간다). 그 밖은 M3 그대로.
    public nonisolated var inboundPackets: AsyncStream<[UInt8]> { get }

    /// 등록하고 데이터면을 유지한다. 호출한 Task가 취소될 때까지 돌아오지 않는다. 노드 하나에 한 번만 부른다.
    /// 다시 시도해도 소용없는 실패(제어의 끝난 실패, 장치 닫힘, 상태 디렉터리 사용 중)만 던진다.
    public func run() async throws(NodeError)

    /// 메모리 장치일 때 IP 패킷 하나를 넣는다(utun에서 읽은 것과 같은 처리). utun 장치일 때는 버린다.
    public func send(_ ipPacket: [UInt8])

    /// 지금 상태.
    public var status: NodeStatus { get }

    /// 대화형 로그인 URL을 새로 요청한다. URL은 `.stateChanged(.needsLogin(url))`로 온다.
    public func startInteractiveLogin()

    /// 기기의 기본 경로가 이 인터페이스로 간다(앱의 `NWPathMonitor`). 노드의 제어·DERP·UDP 소켓을 이 인터페이스에
    /// 묶고, 바뀌었으면 다시 묶는다. 만족된 경로를 받을 때마다 불러도 된다(같은 인터페이스·같은 주소면 STUN만 다시 한다).
    public func setDefaultInterface(_ interface: NWInterface)

    /// 이름이 `fqdn`인 피어의 지금 경로(M4 그대로).
    public func path(toPeerNamed fqdn: String) -> PeerPath?
}
```

`SwiftailEngine`의 공개 타입:

```swift
/// 앱이 `NEPacketTunnelNetworkSettings`로 옮겨 적용할 값. 라이브러리는 NetworkExtension에 의존하지 않는다.
/// 목록의 순서는 정해져 있다(같은 netmap이면 같은 값이 나온다).
public struct TunnelNetworkSettings: Sendable, Equatable {
    /// 자기 주소. IPv4는 /32, IPv6는 /128. 비어 있지 않다.
    public var addresses: [IPPrefix]
    /// 터널로 보낼 경로. 피어 경로(정렬) 뒤에 서비스 IP 경로. 자기 주소가 없는 계열의 경로는 없다.
    public var routes: [IPPrefix]
    /// 비어 있으면 DNS를 설정하지 않는다. 있으면 IPv4 서비스 IP가 먼저다.
    public var dnsServers: [IPAddress]
    /// 끝 점 없는 소문자 이름. `dnsServers`가 비어 있지 않으면 이것도 비어 있지 않다.
    public var dnsMatchDomains: [String]
    public var mtu: Int

    /// netmap에서 설정을 산출한다(아래 동작 S). 자기 주소가 없으면 nil.
    /// - Parameter now: 피어와 자기 노드의 키 만료를 판단할 시각(엔진 계약 M3 동작 2와 같은 시계).
    public init?(netmap: Netmap, mtu: Int, at now: Date)
}
```

`docs/plan.md` 6절 초안과 다른 점(이유):

- `start()`/`stop()` 대신 `run()` + Task 취소(M3 그대로). 정지는 `runTask.cancel()` 뒤 `await runTask.value`다.
  - `Task { }` 안의 `do`-`catch`는 오류 타입을 `any Error`로 추론한다. `NodeError`의 종류로 갈라 보려면 `do throws(NodeError)`로 적는다(첫 사용처가 빌드 변형을 만들며 확인, 2026-11-15):

    ```swift
    let runTask = Task {
        do throws(NodeError) {
            try await node.run()        // 취소로 돌아오면 정상 종료다
        } catch {
            switch error {              // error: NodeError
            case .control(let failure): …
            case .tunnelDeviceClosed, .stateDirectoryInUse, .udpUnavailable, .invalidConfiguration: …
            }
        }
    }
    ```
- `NodeState`에 `stopped`·`failed`가 없다. 정지는 `run()`이 돌아온 것이고, 실패는 `run()`이 던진 `NodeError`다. 둘 다 사건이 아니라 `run()`의 결과로 알린다.
- `NodeEvent.networkSettings` 대신 별도 흐름 `networkSettings`(총괄 확인 필요 T2).
- `TunnelNetworkSettings`의 값은 문자열이 아니라 `IPPrefix`·`IPAddress`다(검증된 값을 넘긴다). 앱은 `description`으로 CIDR 문자열을 얻는다.
- `setDefaultInterface`가 이름 대신 `NWInterface`를 받는다(총괄 확인 필요 T3).
- `init`이 던진다(총괄 확인 필요 T4).
- `TunnelDevice.inProcess`(M6, `docs/contracts/SwiftailNetstack.md` 동작 N 1): 노드는 utun도 메모리 흐름도 쓰지 않는다. 엔진이 장치로 쓰라고 낸 패킷(동작 L의 되돌린 패킷 포함)은 스택이 받고, 스택이 낸 패킷이 엔진의 보내기를 거친다. 이 장치에서 `inboundPackets`는 아무것도 내지 않고 `send(_:)`는 버린다. `networkSettings`는 다른 장치와 같이 나온다(앱은 읽지 않아도 된다). MTU는 1280 고정이고 인자가 없다.

### status 바뀜 사건 (2026-11-18)

샘플 앱(`Examples/PairingDemo`)이 피어 수·자기 이름이 바뀐 것을 알 길이 없어 `status`를 주기적으로 다시 읽던 것을 없앤다.

- `statusChanged`는 `status`(상태, 주소, FQDN, `StableID`, 인증서 이름, 피어 수, 터널 설정, tailnet lock)가 앞서 알린 값과 실제로 다를 때만 나온다. 같은 netmap이 다시 오면 나오지 않는다. 처음 모습(`.starting`, netmap 없음)은 내지 않으므로 앱은 시작할 때 `status`를 한 번 읽는다.
- **겹침**: 상태와 lock이 바뀌면 `stateChanged`·`tailnetLockChanged` 뒤에 `statusChanged`도 나온다. 앞의 둘은 전이 자체를 값과 함께 알리고(로그인 URL, 서명 안내), `statusChanged`는 값 없이 "화면에 보일 모습을 다시 읽어라"만 뜻한다. T1의 "같은 사실을 두 길로 알리지 않는다"는 값을 두 사건에 싣지 않는다는 뜻으로 지킨다. 화면만 맞추는 앱은 `statusChanged`만 보면 된다. `networkSettings` 흐름이 낸 설정도 `status.networkSettings`에 들어 있으므로 설정이 바뀌면 `statusChanged`가 함께 나온다.
- **차례**: 한 갱신(netmap 하나, 상태 전이 하나)에서 `tailnetLockChanged` → `peerPathChanged` → `stateChanged` → `statusChanged`. 어느 사건을 받든 `status`는 이미 그 갱신을 담고 있다.
- **버퍼**: 읽지 않은 `statusChanged`는 하나만 남는다. 새로 나면 앞의 것을 지우고 맨 뒤에 둔다. 그래서 64개 한도에 세지 않고 다른 사건을 밀어내지 않으며, 앱이 어느 사건을 읽은 뒤에 `status`가 바뀌었으면 그 뒤에 반드시 하나가 있다. `AsyncStream`의 버퍼는 종류를 가려 지우지 못하므로 노드가 버퍼(`NodeEventQueue`)를 쥐고 `AsyncStream(unfolding:)`으로 내준다(`DERPClient.EventQueue`와 같은 모양).
- **구독**: 소비하던 Task를 취소하면 `events` 흐름이 끝나 다시 구독할 수 없다. 앱의 한 곳에서 한 번 구독한다.
- 소스 호환: `NodeEvent`에 경우가 늘었으므로 `switch`로 모든 경우를 적은 코드는 `.statusChanged`를 더해야 한다.

### 공개 API에 나오는 다른 모듈의 타입 (2026-11-18)

`import Swiftail`만으로 공개 API의 타입 이름을 쓴다. `Swiftail`의 공개 선언(심볼 그래프에서 다른 모듈의 USR을 가진 타입 식별자를 모은 것)과, 그 타입의 공개 속성·연관 값에 나오는 다른 모듈의 타입:

| 타입 | 원래 모듈 | `Swiftail`에서 나오는 자리 |
| --- | --- | --- |
| `IPAddress` | `SwiftailBase` | `NodeStatus.addresses`, `NodeStatus.init`, `TailnetNode.whoIs(_:)`, `TunnelNetworkSettings.dnsServers`, `IPEndpoint.address` |
| `IPEndpoint` | `SwiftailBase` | `TailnetConnection.localEndpoint`·`remoteEndpoint`, `PeerPath.direct(_:)` |
| `IPPrefix` | `SwiftailBase` | `TunnelNetworkSettings.addresses`·`routes` |
| `ControlError` | `SwiftailControl` | `NodeError.control(_:)` |
| `TailnetLockStatus`(중첩 `Mode`·`Issue`·`SigningRequest` 포함) | `SwiftailControl` | `NodeStatus.tailnetLock`, `NodeStatus.init`, `NodeEvent.tailnetLockChanged(_:)` |
| `TunnelNetworkSettings` | `SwiftailEngine` | `TailnetNode.networkSettings`, `NodeStatus.networkSettings`, `NodeStatus.init` |
| `PeerPath` | `SwiftailMagicsock` | `NodeEvent.peerPathChanged(fqdn:path:)`, `TailnetNode.path(toPeerNamed:)`·`path(toPeerWithStableID:)` |

내보내지 않는 것: `TunnelNetworkSettings.init?(netmap:mtu:at:)`의 `Netmap`(앱은 설정을 노드에서 받는다).

방법: `Swiftail`이 이 이름들만 `public typealias`로 낸다(`Sources/Swiftail/ReexportedTypes.swift`). `@_exported import`는 밑줄 붙은 비공식 기능이고 모듈 전체(tailcfg 모델, 키 타입, 제어 클라이언트)를 `Swiftail`의 표면으로 넓힌다. Swift 6의 `public import`(SE-0409)는 이름을 내보내지 않는다. 별명은 같은 타입이므로 원래 모듈을 함께 가져온 코드와 값을 그대로 주고받는다.

소스 호환: `Swiftail`과 원래 모듈(`SwiftailBase` 등)을 **함께** 가져온 파일에서는 그 이름이 두 선언(별명과 원래 타입)으로 보인다. 타입 자리(`let a: IPAddress`, `[IPAddress: Node]`, `extension IPAddress`)와 호출(`IPAddress("…")`)은 그대로 되지만, 식 안에서 타입을 문법 설탕으로 쓰는 자리와 루트를 적은 키 경로는 모호해져 컴파일되지 않는다(2026-11-18 검토에서 `swiftc -typecheck`로 확인): `[IPAddress]()`·`[IPAddress].self`, `[IPAddress: Int]()`, `IPAddress?.self`·`IPAddress?.none`, `(IPAddress, Int).self`·`(IPAddress).self`(swift-testing의 `@Test(arguments:)`가 만드는 꼴), `IPAddress.Type.self`, 별명을 거친 중첩 타입의 배열 `[TailnetLockStatus.Mode]()`, `\IPEndpoint.address`. `Array<IPAddress>()`·`Set<…>`·`extension`·패턴 매칭·`as?`·`MemoryLayout<IPAddress>`·`TailnetLockStatus.Mode.enforcing`은 된다. 고치는 길은 이제 필요 없는 원래 모듈의 `import`를 지우거나 모듈 이름을 붙이는 것(`SwiftailBase.IPAddress`)이다. 이 저장소에서는 `Tests/SwiftailTests/NodeTailnetLockTests.swift`의 매개변수 하나가 걸려 모듈 이름을 붙였다.

## 동작

번호는 시험과 검토에서 가리키는 이름이다.

### U. utun 장치 (`SwiftailIO.UTUNDevice`, 노드의 읽기 루프)

1. **검사(`init`)**: 기술자가 0 이상이고, `getpeername`의 주소 계열이 `AF_SYSTEM`(32)이고, `getsockopt(SYSPROTO_CONTROL=2, UTUN_OPT_IFNAME=2)`의 이름이 `utun`으로 시작해야 한다. 아니면 `invalidConfiguration`. MTU가 1280…1420 밖이면 `invalidConfiguration`. 검사는 읽기만 하는 호출이므로 부작용이 없다. 근거: 첫 사용처 Go의 `CheckUTUN`(`core/internal/tunnel/utun_darwin.go`), wireguard-go `tun/tun_darwin.go:199-214`의 `Name()`. MTU 범위는 첫 사용처 시험 계약(`docs/tunnel.md` "설정")과 wireguard-go 기본 1420(`device/tun.go:13`).
2. **복제(`run()` 시작)**: `fcntl(F_DUPFD_CLOEXEC)`로 복제하고 복제본에 `O_NONBLOCK`을 건다. `O_NONBLOCK`은 같은 열린 파일 설명을 공유하는 원래 기술자에도 걸린다. 앱은 원래 기술자로 읽고 쓰지 않으므로 문제가 없다(첫 사용처 `docs/tunnel.md` "설정"과 같다). 노드는 `run()`이 끝날 때 **복제본만** 닫는다. 원래 기술자는 끝까지 닫지 않는다.
3. **프로토콜 머리**: utun은 패킷마다 앞에 4바이트를 둔다. 읽을 때 4바이트보다 짧으면 버리고, 머리 값은 보지 않고 나머지를 IP 패킷으로 넘긴다. 쓸 때 IP 버전이 4면 `00 00 00 02`(`AF_INET`), 6이면 `00 00 00 1e`(`AF_INET6`), 그 밖이면 쓰지 않는다. 근거: wireguard-go `tun/tun_darwin.go:224-262`(`Read`는 `n < 4`를 버리고 머리를 보지 않음, `Write`는 버전으로 `AF_INET`/`AF_INET6`을 씀), Darwin 상수 `golang.org/x/sys@v0.49.0/unix/zerrors_darwin_arm64.go:27-28`.
4. **읽기**: `DispatchSource` 읽기 사건으로 깨어나 `EAGAIN`까지 읽는다(폴링하지 않는다. M4 `DatagramSocket`과 같다). `read` 한 번이 패킷 하나다. 버퍼는 재사용하는 하나(4 + 65,535바이트)이고, 읽은 길이만큼만 복사해 넘긴다. 머리뿐이거나(4바이트 이하) MTU를 넘는 패킷은 버린다(OS는 설정한 MTU를 넘는 패킷을 utun에 넣지 않으므로 방어용이다. 읽기 흐름의 상한 256개와 함께 쌓이는 바이트를 256 × MTU로 묶는다. 앱이 MTU를 다르게 적용하면 큰 패킷이 사라지므로 앱은 `TunnelNetworkSettings.mtu`를 그대로 적용한다). `EINTR`는 다시 읽는다. 0바이트(끝)나 `EAGAIN`·`EINTR`가 아닌 오류는 장치가 닫힌 것이다: `run()`이 `tunnelDeviceClosed(errno 이름)`을 던지고 끝난다. Go도 TUN 읽기 오류면 장치를 닫는다(wireguard-go `device/send.go:436-450`). 첫 사용처의 "엔진이 스스로 멈추면 `Error`, `rd_stop` 전까지 풀리지 않음"은 `run()`이 끝나 있는 것으로 같다.
5. **쓰기**: 노드가 만든 패킷마다 한 번 `write`한다. 기다리지 않는다. 실패(`EAGAIN`, `ENOBUFS`, `EMSGSIZE` 등)는 그 패킷을 버리고 계속한다(IP는 원래 그렇다. Go도 TUN 쓰기 오류를 기록만 하고 계속한다, wireguard-go `device/receive.go:552-555`). 쓰기 큐는 없다.
6. POSIX 호출과 주소 재해석은 `UTUNDevice.swift` 한 파일에 가두고 이유를 주석으로 남긴다. 기술자는 `Mutex`로 지킨다.
7. **메모리 장치**: `send`가 3의 읽기 결과 자리에, `inboundPackets`가 5의 쓰기 자리에 들어간다. 그 사이의 처리는 같다. 시험용 `package func failMemoryDevice()`는 4의 읽기 오류와 같은 결과(`tunnelDeviceClosed("test")`)를 낸다.

### L. 로컬 처리 (`TailnetEngine.send`, 장치에서 읽은 패킷)

M3 동작 4(보내기)의 앞에 다음을 둔다. 엔진 출력은 그대로 `.datagram`·`.ipPacket`·`.dropped`이고, 로컬 응답은 `.ipPacket`(장치로 쓸 것)으로 나온다.

1. 패킷 해석(M3 동작 1). 실패는 M3과 같다.
2. **서비스 IP**(DNS 노트 4.3): 목적지가 `100.100.100.100` 또는 `fd7a:115c:a1e0::53`이면 WireGuard로 보내지 않는다.
   - UDP 53: 응답기(동작 D)의 답을 출발·목적 주소와 포트를 맞바꾼 UDP로 돌려준다. 답이 없으면(동작 D의 무응답) 아무것도 내지 않는다. UDP 체크섬은 IPv4·IPv6 모두 계산한다(IPv6는 필수, RFC 8200 8.1).
   - ICMP echo request(v4 type 8, v6 type 128): echo reply(v4 0, v6 129)로 주소를 맞바꾸고 identifier·sequence·payload를 그대로 돌려준다(Go `net/tstun/wrap.go:752-769`. 결정 D5).
   - TCP: RST로 답한다(결정 D4). 들어온 세그먼트에 ACK가 있으면 `seq = SEG.ACK`, RST만. 없으면 `seq = 0`, `ack = SEG.SEQ + SEG.LEN`(SYN·FIN은 1씩), RST+ACK. 들어온 것이 RST면 답하지 않는다(RFC 9293 3.10.7.1).
   - 그 밖(다른 UDP 포트, 다른 프로토콜, ICMP의 다른 타입): 버린다. 응답(ICMP unreachable 포함)을 보내지 않는다(Go와 같다, DNS 노트 4.3 3).
   - 만드는 응답의 TTL·hop limit은 64다(Go `net/packet/ip4.go:49`, `ip6.go:42`. gVisor `pkg/tcpip/network/ipv4/ipv4.go:59`의 기본값도 64).
   - 새 `Drop` 사례: `.serviceIPPacket`(4번째 갈래로 버린 것).
3. **자기 주소**: 목적지가 자기 tailnet 주소면 필터를 거치지 않고 그 패킷을 그대로 `.ipPacket`으로 되돌린다. Network Extension은 터널 주소로 가는 패킷을 커널에서 되돌리지 않고 터널로 보낸다(Go `wgengine/userspace.go:652-667`의 주석과 동작).
4. **TSMP**: 장치에서 온 TSMP(IP 프로토콜 99)는 버린다(`.consumedControlPacket`). 엔진 계약 M3의 `shortcut:`(위에서 내려온 TSMP를 버리지 않음)을 여기서 푼다.
5. 나머지는 M3·M4 그대로(피어 선택 → 흐름 기록 → WireGuard).

구현에서 정해진 것(M5-8a, 2026-11-15):

- 판정 순서는 서비스 IP(2) → TSMP(4) → 자기 주소(3)다. Go도 TSMP를 자기 주소 확인보다 먼저 버린다. 자기 주소로 가는 TSMP는 되돌리지 않고, 서비스 IP로 가는 TSMP는 `.serviceIPPacket`이다.
- UDP 53의 payload는 UDP 길이 필드가 가리키는 만큼만 응답기에 넣는다. 길이 필드가 8보다 작거나 IP 패킷보다 길면 `.serviceIPPacket`이다. 들어온 RST에 답하지 않는 경우도 `.serviceIPPacket`이다.
- 공개 시그니처(`send(_:at:)`, `apply(_:at:wallClock:)`, `advance(to:)`)는 바뀌지 않는다. 노드는 `.ipPacket`을 "장치로 쓸 것"으로 한 가지로 다룬다(로컬 응답, 되돌린 패킷, 피어가 보낸 패킷이 모두 `.ipPacket`이다).

### S. 설정 산출 (`TunnelNetworkSettings.init?(netmap:mtu:at:)`)

1. **주소**: 자기 노드 `Addresses` 가운데 한 주소짜리 접두(IPv4 /32, IPv6 /128)를 netmap 순서대로. 없으면 nil(설정을 내지 않는다).
2. **피어 경로**(엔진 노트 4.8 표): 데이터면에 올린 피어(`EnginePeer.peers(in:at:)`)의 AllowedIPs에서 계산한다.
   - CGNAT(`100.64.0.0/10`) 안의 IPv4 /32: 고유한 것이 10,000개 이하면 하나씩, 넘으면 `100.64.0.0/10` 하나. 자기 노드 `CapMap`에 `one-cgnat?v=true`가 있으면 문턱이 1이다(둘부터 /10). `one-cgnat?v=false`이거나 둘 다 없으면 기본(iOS 규칙: 문턱 10,000). 키 문자열은 Go `tailcfg/nodecap/nodecap.go:148`, `:153`. 제어 지시를 자기 노드 `CapMap`에서 읽는 것은 Go `control/controlclient/map.go:197`, `control/controlknobs/controlknobs.go:155-198`.
   - Tailscale ULA(`fd7a:115c:a1e0::/48`) 안의 IPv6 /128: 하나라도 있으면 `fd7a:115c:a1e0::/48` 하나.
   - M3부터 AllowedIPs에는 Tailscale 범위의 한 주소짜리와 피어 자신의 주소만 남으므로(엔진 계약 M3 동작 2) 그 밖의 접두는 나오지 않는다.
   - 피어 경로는 정렬한다: IPv4가 먼저, 같은 계열은 주소 바이트 순, 같으면 접두 길이 순. 자기 주소는 경로를 만들지 않는다.
3. **서비스 경로**: 자기 주소에 IPv4가 있으면 `100.100.100.100/32`, IPv6가 있으면 `fd7a:115c:a1e0::53/128`을 피어 경로 뒤에 이 순서로 붙인다(엔진 노트 4.8 2).
4. **계열 거르기**: 자기 주소가 없는 계열의 경로는 뺀다(첫 사용처 `core/internal/tunnel/settings.go`의 `buildSettings`와 같다).
5. **DNS**: DNS 노트 4.1.4의 1~5를 그대로 따른다. 요약: 자기 키가 만료됐으면 DNS 없음 → `localZones` = (`Proxied`면 MagicDNS 접미사 + `0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.` + `64`~`127.100.in-addr.arpa.`) ∪ (리졸버가 빈 `Routes` 키) ∪ (어느 영역에도 덮이지 않는 유효한 `ExtraRecords` 이름) → 비면 DNS 없음 → `dnsServers`는 자기 주소 계열에 맞춰 IPv4 서비스 IP 먼저(자기 노드 `CapMap`에 `force-register-magicdns-ipv4-only`가 있으면 IPv4만) → `dnsMatchDomains`는 `localZones`를 끝 점 포함 문자열 순으로 정렬하고 끝 점을 뗀 것. `Resolvers`와 리졸버가 있는 `Routes`는 쓰지 않는다(결정 D1·D2).
6. **MTU**: 장치의 MTU 그대로.
7. 같은 `localZones`와 netmap이 동작 D의 응답기 설정이 된다(DNS 노트 4.1.4 6). 엔진이 netmap을 적용할 때 응답기를 함께 바꾼다.

### E. 설정을 내는 규칙 (`networkSettings` 흐름)

첫 사용처의 규칙(`docs/tunnel.md` "이벤트 `network-settings`", DNS 노트 8.2)을 그대로 따른다.

1. netmap을 적용할 때마다 동작 S로 산출한다. nil(자기 주소 없음)이면 내지 않는다.
2. 마지막으로 낸 값과 같으면(`==`, 목록 순서 포함) 내지 않는다. 설정 적용 → utun 링크 변화 → 다시 적용으로 도는 고리를 막는다. DNS만 바뀌어도(서버, match 도메인) 낸다.
3. 흐름의 버퍼는 `.bufferingNewest(1)`이다. 앱이 아직 읽지 않은 설정은 새 것이 대신한다.
4. `NodeState`가 `.needsLogin`·`.needsMachineAuth`로 바뀌어도 빈 설정을 내지 않는다(1과 같다. 첫 사용처도 주소가 없을 때 내지 않는다). 그동안 데이터면은 netmap이 없거나 만료된 피어를 올리지 않으므로 패킷이 나가지 않는다.
5. `run()`이 끝날 때 설정을 내지 않는다. `status.networkSettings`는 마지막으로 낸 값이다.

### D. MagicDNS 응답기 (`SwiftailEngine`, internal)

DNS 노트 6.1 2의 최소 구현을 그대로 한다. 입력은 질의 바이트와 지금 시각(SOA의 SERIAL)이고, 출력은 응답 바이트 또는 무응답이다. 소켓·시계가 없다.

1. **코덱**(DNS 노트 3.1): 머리와 첫 질문만 읽는다. 이름은 포인터를 10번까지 따라가며 읽고, 응답은 압축 없이 쓴다. 응답 머리는 질의 머리를 복사한 뒤 QR=1, AA=1, RD=1이면 RA=1. 질문·답변 이름은 질의의 대소문자 그대로 쓰고, 비교는 ASCII 소문자로 한다. TTL은 A·AAAA·PTR 5초, SOA 10초.
2. **판정**(DNS 노트 3.1 RCODE 표와 4.2.2의 1~3·5): FORMERR(머리·질문 없음, QR=1 / 유효하지 않은 FQDN은 질문 포함) → PTR은 역방향 규칙 → `.onion`은 NXDOMAIN → `magicdns.localhost-tailscale-daemon.`의 A·AAAA → `ExtraRecords` 호스트 표 → 노드 색인(4.2.1: 자기 노드와 피어의 `Name`, MagicDNS 접미사를 뗀 짧은 이름, 주소가 하나도 없는 노드는 모름) → 타입별 결과(A·AAAA·ANY 하나, 그 타입 주소가 없으면 NOERROR + SOA, NS·SOA·AXFR·HINFO는 NOTIMP, 그 밖은 NOERROR 빈 답) → 모르는 이름이 `localZones` 안이면 NXDOMAIN + SOA.
3. **피어 AAAA**: Go 규칙(결정 D7). 대상에 IPv4가 있고 자기 노드 `capabilities`·`CapMap` 키에 `magicdns-aaaa`가 없으면 IPv6를 답하지 않는다. 자기가 IPv6 전용이면 대상의 IPv6만(DNS 노트 4.2.1 `magicDNSAddrs`).
4. **역방향**(DNS 노트 4.2.2 5): Bonjour 역방향 이름은 NXDOMAIN(질문 포함, RA = RD, AA 없음). `in-addr.arpa`·`ip6.arpa`(니블 32개)를 주소로 읽고, 4to6 범위는 `100.x.y.z`로 먼저 찾는다. 서비스 IP는 `magicdns.localhost-tailscale-daemon.`. 못 찾으면 `localZones` 안이면 NXDOMAIN + SOA.
5. **영역 밖**: 로컬 답이 없고 `localZones` 밖이면 SERVFAIL(질문 포함, AA=1, RA는 질의 값). 상위로 전달하지 않는다(DNS 노트 4.2.3. 결정 D2).
6. **UDP 크기**(DNS 노트 4.2.4): 질의 끝 11바이트가 유효한 OPT면 그 광고 크기, 아니면 512바이트를 넘을 때 TC만 켠다. 자르지 않는다. 응답에 OPT를 싣지 않는다.
7. **자기 키 만료·netmap 없음**: 응답기의 `localZones`가 비고 색인도 비므로 모든 이름이 SERVFAIL이다(닫힌 쪽). 서비스 IP의 고정 이름(`magicdns.localhost-tailscale-daemon.`)에는 계속 답한다(Go와 같다). 자기 키 만료 시각은 엔진의 `nextDeadline`에 들어가고 `advance`가 그 시각에 응답기를 비운다(새 netmap을 기다리지 않는다). SOA SERIAL의 시각은 `apply`의 `wallClock`을 기준점으로 한 엔진의 벽시계다.
8. 생략(DNS 노트 6.1 "생략 가능"): 4via6 이름, `dns-subdomain-resolve` 서브도메인 규칙, 상위 전달 전체.

### B. 상태 기계 (`Swiftail`, internal 값 타입)

DNS 노트 4.5의 대응표를 Swiftail의 입력으로 옮긴다. 입력: 제어 사건(`loginRequired`, `registered`, `netmap`), 홈 DERP 연결이 섬, 엔진이 어떤 피어와 핸드셰이크를 마침. 출력: `NodeState`. 바뀔 때만 `.stateChanged`를 낸다.

| # | 조건(위에서부터) | 결과 | Go 표 |
| --- | --- | --- | --- |
| 1 | 제어가 `loginRequired(url)`를 냈고 그 뒤 `registered`가 오지 않았다 | `.needsLogin(url)` | 2, 5 |
| 2 | netmap 없음 | `.starting` | 3 |
| 3 | 자기 노드가 `MachineAuthorized`가 아님 | `.needsMachineAuth` | 6 |
| 4 | 이전이 `.running` | `.running` | 9 |
| 5 | 홈 DERP 연결이 선 적이 있거나 핸드셰이크를 마친 피어가 있음 | `.running` | 8(결정 D9) |
| 6 | 그 밖 | `.starting` | 7, 10 |

- 자기 키 만료(Go 표 5)는 `ControlClient`가 새 키로 다시 등록하며 처리한다(SwiftailControl 계약 단위 4). 대화형 로그인이 필요하면 `loginRequired`가 오므로 1로 간다. 새 키도 만료면 `ControlClient`가 `nodeKeyExpired`로 끝나고 `run()`이 그것을 던진다.
- `registered`를 받으면 1의 URL을 지운다(Go가 `Running` 진입 때 URL을 지우는 것과 같은 효과, DNS 노트 4.5).
- 첫 사용처의 "URL도 인증 키도 없는 `NeedsLogin`에서 30초마다 로그인 재요청"(DNS 노트 4.5 끝)은 필요 없다. Swiftail의 `ControlClient`는 등록을 시작하면 서버가 준 `AuthURL`로 늘 `loginRequired`를 낸다(`Sources/SwiftailControl/Client/ControlClient+Registration.swift` 문서 주석 3). URL 없는 `needsLogin`이 없으므로 `NodeState.needsLogin`의 URL은 옵셔널이 아니다.
- Go의 `Stopped`·`NoState`·`InUseOtherUser`는 없다. 정지는 `run()`의 끝이다.
- `.running` 뒤 제어·DERP 연결이 끊겨도 `.running`이다(Go 표 9와 같다). M3·M4의 `reconnecting`은 없앤다(총괄 확인 필요 T1).
- 구현에서 정해진 것(M5-8b, 2026-11-15): 처음 상태 `.starting`은 사건으로 내지 않는다(`status`로 읽는다). 표 5의 "핸드셰이크를 마친 피어가 있음"은 엔진이 복호화된 전송 패킷의 출력을 처음 낸 때로 잰다(`shortcut:` Go의 `LastHandshake`보다 한 패킷 늦을 수 있다. 필요해지는 시점: DERP 없이 직접 경로만 쓰는 tailnet에서 `.running`이 늦을 때).

### N. 네트워크 전환 (`setDefaultInterface`)

DNS 노트 4.6과 magicsock 노트 4.11. Swiftail에는 `AF_ROUTE` 감시가 없으므로 앱이 부르는 `setDefaultInterface`가 유일한 통지원이다(결정 D6).

1. **무시하는 것**: 인터페이스 이름이 이 노드의 utun 이름(동작 U1에서 읽은 것)과 같으면 무시한다(Go `net/netns/netns_darwin.go:57-145`가 Tailscale utun을 무효로 보는 것과 같다. `run()` 전의 호출도 기억하지 않고 무시한다). `run()` 전이나 끝난 뒤의 호출은 마지막 값만 기억한다.
2. **판정**: 노드는 마지막 인터페이스(이름과 `index`)와 마지막으로 읽은 로컬 IPv4 주소(`LocalInterfaceAddresses.current()`)를 쥔다. 호출마다 주소를 다시 읽는다.
   - 처음 받은 인터페이스, 또는 인터페이스나 로컬 주소가 바뀜 → 3의 **재결속**. Go `RebindLikelyRequired`(DNS 노트 4.6.2)의 Swiftail판이다(가용 프로토콜·비용·PAC 변화는 보지 않는다).
   - 같음 → `Magicsock.restartSTUN(at:)`으로 STUN 회차만 다시 시작한다(Go: 링크 변경마다 `ReSTUN`, DNS 노트 4.6.3 1). 회차가 진행 중이거나 지역이 없으면 아무 일도 없다(`shortcut:` Go는 진행 중인 회차 뒤에 한 번 더 돌도록 예약한다).
3. **재결속**(Go 엔진의 순서, DNS 노트 4.6.3 1):
   1. 새 인터페이스를 노드의 "지금 인터페이스"로 둔다. 이후 여는 모든 소켓이 이 인터페이스에 묶인다.
   2. DERP: 열린 모든 지역 연결을 닫고 홈 지역부터 다시 연다(`DERPClient`를 새 인터페이스로 새로 만든다). `shortcut:` Go는 로컬 주소가 기본 인터페이스 주소인 연결은 남기고 3초 Ping으로 확인한다(DNS 노트 4.6.3 2). 모두 다시 여는 것이 단순하고, 비용은 홈이 아닌 연결의 재연결뿐이다. 필요해지는 시점: 실기기 전환에서 재연결 지연이 문제일 때.
   3. UDP: 소켓을 닫고 같은 포트로 다시 묶는다. 실패하면 포트 0으로 묶는다. 그것도 실패하면 인터페이스에 묶지 않은 소켓으로 대신하고(알려 준 인터페이스가 그사이 사라진 경우다. 다시 켜도 소용없는 실패가 아니므로 `run()`을 끝내지 않는다), 다음 `setDefaultInterface`가 무엇을 알리든 다시 묶는다. 소켓을 아예 만들 수 없을 때만 `run()`이 `udpUnavailable`을 던진다(M5 검토 B, 2026-11-15). 처음 소켓을 열 때도 같다. 소켓의 읽기가 오류로 멈추면 노드가 같은 절차로 소켓을 새로 연다. 이어서 `Magicsock.rebind(localPort:localAddresses:loopbackAddresses:at:)`: 모든 피어의 `bestAddr`·신뢰·Ping 기록을 지우고(magicsock 노트 4.11 2) STUN 회차를 곧바로 시작한다. 엔드포인트가 바뀌면 M4 N4대로 제어 서버에 올린다. 노드의 순서는 새 소켓 열기 → `rebind` → 출력을 순서대로 처리 → `nextDeadline`에 맞춘 `advance`다. `DatagramSocket.close()`의 `close(2)`는 디스패치 큐에서 늦게 일어나므로, 같은 포트로 다시 묶기는 `run()`의 자식 하나가 20ms 간격으로 25번까지 시도한 뒤 포트 0으로 넘어간다. 그동안 UDP 송신은 버린다. 제어 연결 다시 잇기(3.4)는 새 소켓을 연 뒤에 한다.
      - 지우는 것(Go `noteConnectivityChange`, `endpoint.go:1876`과 같다): `bestAddr`, 신뢰, 후보별 마지막 Ping 시각, 받은 Ping의 TxID, Pong 기록. 남기는 것: 후보와 그 출처, 송신 기록, heartbeat.
      - Go와 다른 곳: ① 보낸 Ping 표도 지운다(옛 소켓에서 보낸 Ping의 Pong은 새 소켓의 증거가 아니다). ② 진행 중인 STUN 회차를 버리고 새로 시작한다(Go는 그대로 두고 `ReSTUN`을 예약한다). 옛 회차의 응답은 `.dropped(.unexpectedSTUN)`이다. ③ 엔드포인트를 정한 시각을 지워, 새 회차가 끝나기 전의 CallMeMaybe는 미뤘다가 새 엔드포인트로 보낸다(Go는 옛 엔드포인트를 담아 곧바로 보낸다). ④ `shortcut:` CallMeMaybe로 배운 후보는 다음 CallMeMaybe가 빼 줄 때까지 둔다(Go는 다음 netmap 갱신 때 지울 수 있게 표시한다).
   4. 제어: `ControlClient.setNetworkInterface(_:)`가 지금 연결을 닫고 물러남 없이 새 인터페이스로 다시 잇는다(Go `tsdial`이 기본 인터페이스가 바뀐 시스템 연결을 닫는 것, DNS 노트 4.6.3 4). 등록 상태와 마지막 netmap은 유지된다.
   5. 설정: 다시 산출하지 않는다. netmap이 바뀌지 않았으므로 동작 E 2에 따라 나갈 것이 없다.
4. **소켓 묶기**(DNS 노트 4.6.4): UDP 소켓은 `setsockopt(IPPROTO_IP, IP_BOUND_IF, index)`. 제어·DERP의 `NWConnection`은 `NWParameters.requiredInterface = interface`. 목적지가 루프백 주소면 묶지 않는다(Go `netns_darwin.go:38-55`. macOS 관문의 루프백 testcontrol·DERP가 이 규칙으로 돈다). 인터페이스를 아직 모르면 묶지 않고 연다.
   - `DatagramSocket(port:interfaceIndex:)`는 `bind` 전에 `IP_BOUND_IF`를 건다. 실패(없는 index 등)는 `bindFailed(errno 이름)`이다. 묶음은 열 때 한 번만 걸리므로 인터페이스가 바뀌면 새 소켓을 연다(동작 N 3.3).
   - macOS에서 관찰한 것(M5-7a, 기기 한 대): 물리 인터페이스에 묶은 UDP 소켓도 루프백과 주고받는다(그래서 UDP 소켓에는 루프백 예외를 두지 않는다. 목적지가 여럿인 소켓이다). lo0에 묶은 소켓이 비루프백 목적지로 보내면 `ENETUNREACH`이고, 자기 기기의 비루프백 주소로 보내면 오류 없이 도착하지 않는다.
5. `shortcut:` 망이 내려감(만족된 경로 없음)의 처리(Go: DERP 닫기, 제어 일시 정지, DNS 노트 4.6.3 1·3)는 없다. 앱은 만족된 경로만 알린다. 끊긴 동안 연결은 각자의 재시도·물러남으로 버틴다. 필요해지는 시점: 실기기에서 망이 없는 동안의 재시도가 배터리·메모리에 문제일 때.
6. `shortcut:` UDP 송신 오류(`EPERM`·broken pipe)에 따른 자동 재결속(magicsock 노트 4.11 3)은 없다. 필요해지는 시점: 실기기 전환 시험에서 `setDefaultInterface` 없이 소켓이 죽는 경우.

### P. 상태 저장과 재시작

1. 신원은 지금의 `identity.json`(머신 키 + 노드 키)이 전부다. DNS 노트 4.4.3이 "다시 시작해도 같은 노드"의 최소 집합으로 확인한 것과 같다. 더 저장하지 않는다. disco 키는 저장하지 않는다(M4 그대로).
2. **파일 보호**(iOS): `identity.json`에 데이터 보호 등급 `completeUntilFirstUserAuthentication`과 `isExcludedFromBackup`을 노드가 직접 건다. 신원 파일은 개인 키이므로 다른 기기로 복원되면 같은 머신 키를 가진 기기가 둘이 된다(총괄 확인 필요 T6). 디렉터리의 위치(App Group 컨테이너)와 디렉터리 자체의 보호는 앱이 정한다.
3. **중복 거절**: 프로세스 전역 표(`Mutex<Set<String>>`, 표준화한 디렉터리 경로)에 `run()`이 시작할 때 디렉터리를 올리고 끝날 때 내린다. 이미 있으면 `run()`이 곧바로 `stateDirectoryInUse`를 던진다(파일·소켓을 열기 전). 다른 프로세스 사이는 막지 않는다(첫 사용처 Go도 프로세스 안에서만 막는다, DNS 노트 4.4.3). 올리기 전에 디렉터리를 0700으로 만든다(`run()`도 `logOut()`도. 만들지 못하면 `control(.storage)`): 없는 경로는 심볼릭 링크가 풀리지 않아, 디렉터리가 생긴 뒤의 같은 자리와 다른 열쇠가 된다. 내릴 때는 올릴 때 얻은 열쇠를 쓴다(2026-11-17 보안 검증).
4. 상태 디렉터리는 첫 사용처 Go 코어의 것과 따로 둔다(결정 D8). Go `tailscaled.state`에서의 이관은 M7 결정이다.
5. **저장된 신원 묻기**(2026-11-18): `TailnetNode.hasSavedIdentity(in:)`는 앱이 노드를 띄우기 전에 "저장된 신원으로 스스로 이을지, 인증 키나 로그인을 받을지"를 정하게 한다. 신원 파일을 `run()`과 같은 규칙(심볼릭 링크를 따라가지 않음, 정규 파일만, 64KiB까지)으로 읽고 형식까지 본다. 있기만 하고 읽을 수 없는 파일은 `run()`도 `control(.storage)`로 끝나므로 같은 실패를 먼저 던진다(앱이 인증 키를 받아 놓고 시작에서 실패하지 않게). node 키가 있어야 true다: machine 키만 있는 파일은 등록 전에 멈춘 것이다(`run()`은 등록 전에 machine 키를 저장한다). 파일이 없으면 false이고 디렉터리를 만들지 않는다. 파일 URL이 아니면 `invalidConfiguration`. true여도 서버가 노드를 지웠거나 키가 만료됐으면 `run()`이 `.needsLogin`이나 실패로 알린다. 키는 내보내지 않는다.

### M. 메모리

목표: 유휴 상주 20MiB 이하(plan 7절), 확장 한도 50MiB(첫 사용처 `docs/tunnel.md` "메모리와 크기"의 보고치. Apple 문서로 확인한 값이 아니다). 확정은 실기기 측정이다(관문 (나)). 계약은 **신뢰할 수 없는 입력이 쌓을 수 있는 버퍼마다 개수와 바이트 합의 상한**을 둔다.

| 버퍼 | 지금 | M5 | 넘으면 |
| --- | --- | --- | --- |
| utun 읽기 | 없음 | 재사용 버퍼 하나 4 + 65,535바이트(동작 U4) | 해당 없음 |
| utun 쓰기 | 없음 | 큐 없음(동작 U5) | 그 패킷을 버림 |
| 맵 응답 프레임(`MapResponseFramer`) | 64MiB | **8MiB**(구현됨, M5-6) | `malformed`. 64MiB 프레임의 해독 최고치는 약 110MB로 측정됐다(SwiftailControl 계약 단위 3 `shortcut:`). 8MiB면 같은 비율로 약 14MB |
| `DERPClient` 받은 사건 | 256개(Go 서버의 패킷 한도 65,536바이트로 최악 16MiB. 프레임 한도 1MiB를 채워 보내는 서버면 256MiB) | 256개 **그리고 1MiB**(구현됨, M5-6) | 오래된 것부터 버림 |
| `DatagramSocket` 받은 데이터그램 | 256개(최대 65,535바이트, 최악 16MiB) | 256개 **그리고 1MiB**(구현됨, M5-7a) | 오래된 것부터 버림 |
| 노드 → DERP 송신 큐 | 256개 | 256개 그리고 1MiB | 오래된 것부터 버림 |
| 노드 → UDP 송신 큐(`DatagramSocket.enqueue`) | 없음(노드 actor가 곧바로 `sendto`) | 256개 그리고 1MiB(구현됨, 2026-11-15. `sendto`를 노드 actor 밖, 소켓의 직렬 큐로 옮겼다. 노드는 처리 한 번 동안 보낼 것을 모아 한꺼번에 넘긴다) | 오래된 것부터 버림. 재결속으로 닫은 소켓에 남은 것은 버리고 닫힌 기술자에 쓰지 않는다. 노드가 멈출 때는 남은 것(netstack 동작 N8의 RST)을 보낸 뒤 닫는다 |
| `inboundPackets`(메모리 장치) | 256개 | 그대로(최악 256 × 64KiB ≈ 16MiB. 확장은 utun 장치를 쓰므로 이 버퍼가 없다. 메모리 장치를 제품 경로에 쓰게 되면 바이트 한도를 넣는다) | 오래된 것부터 버림 |
| `events` | 64개 | 그대로(피어가 64개를 넘고 앱의 소비가 느리면 한꺼번에 나온 경로 사건이 상태 사건을 밀어낼 수 있다. M4 검토 B의 추정이고 재현하지 않았다. 앱은 지금 상태를 `status`로도 읽을 수 있다) | 오래된 것부터 버림 |
| `networkSettings` | 없음 | 1개(동작 E 3) | 새 것이 대신 |

- 쓰기 기한은 메모리를 쌓지 않는다. `DERPClient`는 쓰기마다 기한 Task·타이머를 만들지 않고, 연결 하나에 하나뿐인 감시가 진행 중인 쓰기의 시작 시각으로 5초 기한을 지킨다(SwiftailDERP 계약 `DERPClient` 동작 3). 쓰기마다 `withTimeout`을 걸던 때는 취소된 `Task.sleep`의 Task와 타이머가 기한까지 남아 쓰기 속도에 비례해 쌓였다(DERP 전용 경로 100MiB 양방향, 릴리스: phys_footprint 표본 최고 83MB → 15MB). `withTimeout`도 이제 취소되면 타이머를 그 자리에서 거두지만, 부를 때마다 Task를 만들므로 패킷마다 부르는 경로에는 쓰지 않는다.
- 바이트 한도 1MiB는 이 계약의 제안값이다. 근거는 "최악 16MiB가 한도 50MiB의 3분의 1이라 버퍼 셋이면 넘친다"는 계산뿐이다. 실기기 처리량 측정에서 버림이 보이면 조정한다.
- 기존 `shortcut:` 가운데 M5에서 **조이는 것**: 맵 프레임 한도(SwiftailControl 계약 단위 3. 값 수로 묶던 것을 프레임 크기로 먼저 묶는다).
- 기존 `shortcut:` 가운데 M5에서 **측정 뒤 판단하는 것**(계약은 바꾸지 않고 관문 (나)의 기록으로 결정): 피어 선등록(엔진 계약 M3 동작 3, 엔진 노트 6.3), 홈이 아닌 DERP 연결 정리(엔진 계약 M4 N3), WireGuard 패킷마다의 할당(`Sources/SwiftailWireGuard/Transport.swift`, `WireGuardDevice.swift`의 `shortcut:`), HTTP/2 받는 쪽 역압(SwiftailHTTP2 계약. 프레임 한도가 쌓이는 양을 묶는다).

### C. 한도와 실패

1. 어떤 바이트열을 장치에서 읽어도, 어떤 DNS 질의를 받아도 죽지 않는다. 범위를 넘는 인덱스, 정수 넘침(체크섬 합, `SEG.SEQ + SEG.LEN`의 `UInt32` 넘침은 순환), 끝없는 이름 포인터가 없어야 한다.
2. 응답기의 실패는 닫힌 쪽이다: 해석할 수 없으면 FORMERR, 모르면 NXDOMAIN 또는 SERVFAIL. 질의를 상위로 내보내지 않는다.
3. 서비스 IP로 간 패킷은 어떤 경우에도 WireGuard로 나가지 않는다(동작 L2).
4. `init`의 검사 실패, `stateDirectoryInUse`는 파일·소켓·Task를 만들기 전에 끝난다.

### K. 비밀

1. node·머신·disco 개인 키, 인증 키를 사건·오류·`description`·`dump`에 넣지 않는다(기존 그대로). `NodeStatus`에는 키가 없다.
2. `NodeError.tunnelDeviceClosed`·`udpUnavailable`의 메시지는 errno 이름만 담는다. `invalidConfiguration`의 메시지에 경로·기술자 번호 밖의 값을 넣지 않는다.
3. DNS 질의 내용(이름)을 기록하지 않는다. 이 계약은 로그 API를 만들지 않는다(첫 사용처 확인 필요 F6).

### 응답기 구현에서 정해진 것 (M5-1, 2026-11-15)

Go 기준값 대조(`GoMagicDNSComparisonTests`, `GoTunnelSettingsComparisonTests`): MagicDNS 85단계 가운데 81단계는 Go와 응답 바이트까지 같고, 3단계는 표시된 차이(4via6, 서브도메인 규칙), 1단계는 아래의 질문 누출이다. 터널 설정 32단계 가운데 15단계는 Go와 같고 16단계는 표시된 차이(검색 도메인을 내지 않음, 전역 리졸버·분할 DNS를 무시 등), 1단계는 만료 시각이 지난 피어의 경로다(Go의 경로 산출은 `Expired` 표시만 보고, 그 표시는 앞 단계가 단다. Swiftail은 `keyExpiry <= now`인 피어를 스스로 뺀다).

- 서비스 IP 상수는 `ServiceIP` 한 곳이다(응답기, DNS 서버·경로 산출, 엔진의 로컬 처리가 함께 쓴다).
- 진입점: `MagicDNSResolver(netmap: Netmap?, localZones: [String])`와 `response(to:at:) -> [UInt8]`(internal). 늘 응답 바이트를 낸다(무응답인 경우가 없다). 12바이트보다 짧은 질의에도 Go처럼 ID 0의 FORMERR로 답한다.
- netmap이 없거나 자기 키가 만료되어 `netmap`이 nil이어도 서비스 IP의 PTR 같은 고정 이름에는 답한다(Go와 같다). 그 밖의 이름은 SERVFAIL.
- **Go와 일부러 다르게 한 것**: Go는 머리가 짧거나 응답 비트가 켜진 질의에 답할 때, 다시 쓰는 파서에 남아 있던 **앞 질의의 질문**을 응답에 싣는다(다른 앱의 질의 이름이 새어 나갈 수 있다. Go 출력에서 확인). Swiftail은 질문 없이 답한다. `ExtraRecords`의 이름과 MagicDNS 접미사는 소문자로 맞춰 비교한다(Go는 대소문자 그대로 쓴다).

## 결정 (DNS 노트 6.4)

| # | 결정 | 정한 것 | 근거 |
| --- | --- | --- | --- |
| D1 | DNS를 OS에 주는 방식 | (가) match 도메인만 | 1차 리졸버 모드는 상위 전달과 확장 안에서 OS 기본 리졸버를 읽는 방법이 필요한데 후자를 확인하지 못했다. 첫 사용처도 이렇게 좁힌다 |
| D2 | 전역 `Resolvers`·리졸버가 있는 `Routes` | (가) 무시하고 로컬 영역만 match | 그 이름은 OS 기본 DNS로 간다. 지원하지 않음을 이 문서(제외 표)에 기록한다. 첫 사용처 시험 계약 `TestTunnelIOSDNS`와 같은 결과 |
| D3 | 검색 도메인 | (가) 내지 않음. 앱은 `matchDomainsNoSearch = true` | 첫 사용처 그대로. 짧은 이름은 풀리지 않는다 |
| D4 | 서비스 IP의 TCP | (나) RST | Go도 53·80·8080 밖은 RST다. 53은 M6 TCP 스택 뒤 (다) |
| D5 | 서비스 IP의 ICMP echo | 응답 | Go와 같고 진단에 쓰인다 |
| D6 | 링크 변경의 통지원 | (가) `setDefaultInterface`만 | 경로 감시 정책은 앱에 둔다. 같은 인터페이스로 다시 불러도 주소를 다시 읽고 STUN을 다시 한다(Go `InjectEvent`와 같은 뜻). 인자의 타입은 T3 |
| D7 | 피어 AAAA | Go 규칙 | 동작 D3 |
| D8 | 상태 디렉터리 | 별도 | 이관은 M7. 첫 사용처의 기존 사용자에게는 새 노드가 된다(첫 사용처 확인 필요 F9) |
| D9 | `Running` 판정 | Go 규칙 | 피어 없는 tailnet에서도 DERP로 `running`이 된다(동작 B 5) |

## 총괄 확인 필요

총괄 확정(2026-11-15, 첫 사용처의 검토 뒤): T1~T6은 아래 권고대로 정했다. T7은 권고와 달리 **첫 사용처 터널 확장의 빌드 변형**으로 한다(서명·App Group·실기기 설치 경로가 그쪽에 있고 Go 터널과 같은 기기에서 나란히 견줄 수 있다). Swiftail은 SwiftPM 경로 의존으로 붙는다: 확장은 제품 `Swiftail`을 링크하고, 공개 API가 쓰는 타입 때문에 `SwiftailBase`·`SwiftailControl`·`SwiftailEngine`·`SwiftailMagicsock`을 필요한 만큼 `import`한다(2026-11-18부터는 `import Swiftail`만으로 된다. 위 "공개 API에 나오는 다른 모듈의 타입"). 확장(App Extension)에서 쓸 수 없는 API를 쓰지 않는다.

| # | 무엇 | 선택지 | 권고 |
| --- | --- | --- | --- |
| T1 | `NodeEvent`의 모양 | (가) `loginRequired`·`running(addresses:)`·`reconnecting`을 없애고 `stateChanged(NodeState)`로 바꾼다. 주소는 `status`로 읽는다 / (나) 기존 셋을 두고 `stateChanged`를 더한다 | (가). 같은 사실을 두 길로 알리지 않는다. Go 상태에 `reconnecting`에 해당하는 값이 없고 첫 사용처도 쓰지 않는다. 대가: M3·M4 관문 시험(`Tests/SwiftailInteropTests`)의 사건 기다림을 고친다(구현 단위 M5-8이 함께 한다) |
| T2 | 설정 사건의 통로 | (가) 별도 `AsyncStream<TunnelNetworkSettings>`, `.bufferingNewest(1)` / (나) plan 6절대로 `NodeEvent.networkSettings` | (가). 첫 사용처 규칙 "큐에는 최신 것 하나만"이 버퍼 정책 하나로 표현된다. (나)는 섞인 사건 버퍼(64개)에서 옛 설정만 골라 지울 수 없다 |
| T3 | `setDefaultInterface`의 인자 | (가) `NWInterface`(이름과 `index`가 있고 `Sendable`, iPhoneOS 27.2 SDK `Network.swiftinterface`) / (나) 이름 문자열(plan 6절, Go와 같음) | (가). 제어·DERP 연결은 `NWConnection`이고 그것을 인터페이스에 묶는 길은 `NWParameters.requiredInterface(NWInterface)`뿐이다. 이름만으로는 `NWInterface`를 만들 수 없어 라이브러리 안에 경로 감시가 필요해진다(D6과 어긋남). 앱은 이미 `NWPath.availableInterfaces`의 `NWInterface`를 쥐고 있다. 이름 검사(15자, 허용 문자)도 필요 없어진다 |
| T4 | 설정 검사의 시점 | (가) `init`이 던진다(`throws(NodeError)`) / (나) M3처럼 `run()` 안에서 | (가). 첫 사용처는 잘못된 fd·MTU를 시작 호출에서 곧바로 실패로 받는다(`rd_start`의 `invalid_config`). `run()`은 비동기로 돌기 시작하므로 (나)면 앱이 "시작됨"을 알린 뒤에 실패를 알게 된다. 대가: 기존 `init(configuration:)` 호출에 `try`가 붙는다 |
| T5 | 맵 프레임 한도 | 64MiB 유지 / 8MiB / 실기기 측정 뒤 결정 | 8MiB로 줄이고 관문 (나)에서 확인. 피어 1,000개 tailnet의 비압축 맵이 수 MB라는 것은 추정이며 확인하지 못했다. 큰 tailnet을 쓰는 Mac 호스트(M6·M7)에서 문제가 되면 그때 플랫폼별로 나눈다 |
| T6 | `identity.json`의 보호 등급·백업 제외 | (가) 노드가 파일에 직접 건다(iOS에서만) / (나) 앱의 몫으로 둔다(지금 첫 사용처가 디렉터리에 건다) | (가). 개인 키 파일의 성질이라 라이브러리가 보장하는 편이 안전하다. 확인 필요: 디렉터리의 보호 등급을 새 파일이 물려받는지, 임시 파일 → 이름 바꾸기 뒤에도 유지되는지(Apple 문서 항목으로 확인하지 못했다) |
| T7 | 실기기 관문의 시험용 터널 앱 | (가) Swiftail 저장소에 최소 앱(`Tools/TunnelHarness/`: 컨테이너 앱 + 패킷 터널 확장, 라이브러리 타깃 밖) / (나) 첫 사용처 확장에 Swiftail 빌드 변형 | (가)로 관문을 통과한 뒤 (나)로 교체. 첫 사용처 저장소를 바꾸는 일은 별도 승인이 필요하다(plan 7절 M7). 서명 팀·NE 권한은 plan 9절의 열린 결정이다 |


## 첫 사용처 검토 결과 (2026-11-15)

아래 "첫 사용처 확인 필요"의 질문 16개에 첫 사용처 쪽이 호출 지점의 코드와 대조해 답했다. 질문 절은 기록으로 남기고, 답 가운데 계약을 바꾸는 것만 여기에 적는다. 이 절이 질문 절과 어긋나면 이 절이 우선이다.

1. **오류의 종류(질문 6, 추가 1)**: 앱이 종류마다 사용자 문구를 고르고 5개 언어로 번역하므로, 사용자가 구분해야 하는 종류는 연관 문자열이 아니라 열거형으로 드러나야 한다. `run()`이 던지는 오류에서 다음이 구분된다: 인증 키를 실은 등록이 거절됨(잘못됨·만료·이미 씀을 서버 문자열에서 더 가르지는 않는다. 서버가 종류를 주지 않는다), 인증 키 없는 등록이 거절됨(관리자 정책 등), 새 키로 다시 등록해도 node 키 만료, tailnet lock, 장치·상태 디렉터리·설정 오류. 제어 서버의 응답 오류(HTTP 상태)와 연결 실패는 일시적인 실패로 보고 던지지 않는다(상태는 `.starting`이나 `.running`에 머문다. 로그에 남긴다). 서버가 준 진단 문자열은 연관 값으로 남기되 사용자 문구에 쓰지 않는다. **`run()`이 던지는 것은 다시 켜도 소용없는 실패뿐이다. 일시적인 실패(연결 끊김, 서버의 일시 오류, 시간 초과)는 던지지 않고 안에서 물러났다가 다시 시도한다.** 앱은 `run()`이 던지면 주문형 연결을 끈다.
2. **키 만료와 로그인(질문 8)**: 인증 키 없이 띄운 노드는 node 키가 만료되면 앱이 아무것도 부르지 않아도 새 키로 다시 등록하고, 서버가 준 URL로 `.needsLogin(url)`이 나온다. 인증 키를 실어 띄운 노드는 새 키를 등록할 때 그 키를 다시 보낸다: 재사용 키면 스스로 다시 인증되고, 일회용 키면 거절되어 `run()`이 위 1의 "인증 키를 실은 등록이 거절됨"으로 끝난다. 이미 등록된 저장 키로 다시 붙을 때(재시작)는 인증 키를 보내지 않으므로, 앱이 일회용 키를 설정에 남겨 둔 채 다시 켜도 거절되지 않는다(SwiftailControl 계약 단위 4 동작 2).
3. **경로 조회(질문 12·13)**: `path(toPeerNamed:)`와 `peerPathChanged`는 **경로를 실제로 알 때만** 값을 준다. 최근(Go의 유휴 판단과 같은 45초) 안에 그 피어와 주고받은 것이 없으면 nil이다(첫 사용처의 지금 규칙과 같다. 유휴 피어를 `.relayed`로 보이면 트래픽이 생기면 직접으로 붙을 연결이 "중계"로 표시된다). `.relayed`의 지역은 ID로 충분하다.
4. **상태 디렉터리(추가 2·3)**: `stateDirectoryInUse`는 같은 프로세스 안의 검사다. 서로 다른 프로세스가 같은 디렉터리를 번갈아 쓰는 것(첫 사용처에는 터널 확장이 둘 있고 VPN은 한 번에 하나만 켜진다)을 막지 않으며, 잠금 파일을 남기지 않는다. `identity.json`의 데이터 보호 등급은 `completeUntilFirstUserAuthentication`이다(확장은 잠긴 화면에서도 뜬다. `complete`이면 시작이 실패한다).
5. **로그(질문 14)**: 라이브러리가 `os.Logger(subsystem: "Swiftail")`로 비밀 없는 요약을 남긴다(공개 API는 늘리지 않는다): 상태 전이, 제어·DERP의 연결·끊김과 물러나기, 경로 전환(직접↔중계), 인터페이스 재결속, 설정을 산출한 시점. 키·인증 키·주소 전체·DNS 질의 이름은 남기지 않는다. 로그를 남기는 곳은 가장자리(`Swiftail`의 노드, `SwiftailIO`)뿐이다.
6. **잠자기·깨어나기(추가 5)**: 따로 받는 호출은 없다. 깨어난 뒤 제어·DERP 연결은 기존 재연결 경로로 스스로 돌아온다(M5 관문 (나)에서 확인).
7. **그대로 확정된 것**: `init` 성공 직후 시작 완료를 알림(질문 2), 빈 `controlURL`의 기본값은 앱이 넣음(3), `TunnelNetworkSettings`의 값은 `description`이 `100.64.0.11/32`·`fd7a:…/128` 꼴인 타입으로 주고 앱이 문자열로 옮김(4), 피어별 /32(5), `setDefaultInterface(NWInterface)`를 만족된 경로마다 부름(10), `status.peerCount`는 두고 StableID도 둔다(9. 앱은 쓰지 않지만 M7의 WhoIs와 진단에 쓴다).
8. **기존 사용자의 전환(질문 16)**: 사용자 결정을 기다린다. 답이 오기 전에는 이관을 M5로 당기지 않는다(교체 뒤 기존 기기는 새 노드로 로그인하고 다시 페어링한다. 안내는 첫 사용처가 맡는다).
9. **메모리(질문 15)**: 확장의 실제 한도를 관측한 기록은 없다(50MiB는 보고치). 첫 사용처가 교체 전에 Go 터널의 `phys_footprint`를 유휴·전송 중으로 재어 비교 기준을 준다.

## 첫 사용처 확인 필요

이 절은 첫 사용처의 커밋된 호출 지점(`Apps/iOSTunnel/PacketTunnelProvider.swift`, `docs/tunnel.md`, `docs/protocol-addenda.md` N.3, `core/internal/tunnel/`, `core/capi/include/rdcore.h`의 `rd_tunnel_*`)을 읽고, 이 계약으로 대체할 수 있다고 본 근거와 확인할 질문을 항목별로 적는다.

### F1. 시작과 정지

대응:

```swift
// startTunnel: utun을 찾은 뒤(기존 UTUNLocator 그대로)
let node = try TailnetNode(
    configuration: .init(stateDirectory: stateDir, hostname: config.hostname,
                         controlURL: config.controlURL ?? NodeConfiguration.defaultControlURL,
                         authKey: authKey.isEmpty ? nil : authKey),
    device: .utun(fileDescriptor: found.fd, mtu: 1280))
let runTask = Task { try await node.run() }   // 실패는 F3
// stopTunnel
runTask.cancel(); _ = await runTask.result
```

- `rd_start`의 `invalid_config`(fd·MTU)는 `init`이 던지는 `invalidConfiguration`(T4). `tunnel_in_use`·`state_dir_in_use` 가운데 같은 디렉터리는 `run()`의 `stateDirectoryInUse`.
- `rd_stop`과 "엔진 종료가 몇 초 걸릴 수 있어 직렬 큐에서 부른다"는 Task 취소와 `await`로 바뀐다. 직렬 큐가 필요 없다.
- `goMemLimitMiB`, `logPath`, `hostDisplayName`, `appVersion`에 대응하는 것은 없다.

질문:

1. 다른 상태 디렉터리로 두 번째 터널 노드를 띄우는 것(`tunnel_in_use`)을 Swiftail은 막지 않는다. 확장은 노드를 하나만 띄우므로 앱 쪽 `TunnelLifecycle`로 충분한가?
2. `startTunnel`의 완료를 `init` 성공 직후(`run()`을 기다리지 않고) 알려도 되는가? 지금도 `Running`을 기다리지 않는다. `run()`이 곧바로 던지는 경우(`stateDirectoryInUse`, `udpUnavailable`)는 완료 뒤 `cancelTunnelWithError`로 끝내게 된다.
3. `controlURL`이 빈 문자열이면 기본 제어 서버라는 규칙을 앱이 `NodeConfiguration.defaultControlURL`로 옮겨도 되는가?

### F2. 설정 적용

대응: `for await settings in node.networkSettings { applier.submit(SettingsTranslator.translate(settings)) }`. 규칙은 첫 사용처와 같다(동작 E: 주소가 없거나 같으면 내지 않음, DNS만 바뀌어도 냄, 최신 하나만). `dnsServers`가 비면 `dnsSettings = nil`, `matchDomainsNoSearch = true`, `tunnelRemoteAddress = "127.0.0.1"`, 한 번에 하나만 적용하는 `SerialApplier`는 그대로 둔다.

질문:

4. `SettingsTranslator.translate`는 지금 문자열 CIDR(`NetworkSettingsEvent`)을 받는다. `IPPrefix.description`·`IPAddress.description`으로 같은 문자열을 만들어 넘기는 얇은 변환을 앱에 두는 것으로 충분한가, 아니면 `TunnelNetworkSettings`를 직접 받게 고치는가?
5. 피어 경로는 macOS에서도 iOS 규칙(피어별 /32)으로 나온다. Go는 macOS에서 `100.64.0.0/10` 하나를 낼 수 있었다(`docs/tunnel.md` "routes"). e2e 시험이 /10을 기대하는 곳이 있는가?

### F3. 상태와 오류 표시

대응(첫 사용처 `backendState`):

| 첫 사용처 | Swiftail |
| --- | --- |
| `Starting` | `.stateChanged(.starting)` |
| `NeedsLogin` + `authURL` | `.stateChanged(.needsLogin(url))` |
| `NeedsMachineAuth` | `.stateChanged(.needsMachineAuth)` |
| `Running` | `.stateChanged(.running)` |
| `Error` + `errorMessage`(인증 키 거부, 제어 서버 오류) | `run()`이 던진 `NodeError.control(…)` |
| `Error` + `"TUN 장치가 닫혔습니다."` | `run()`이 던진 `NodeError.tunnelDeviceClosed` → 지금처럼 `cancelTunnelWithError` |
| `Stopped` | `run()`이 돌아옴 |
| `rd_status`의 `fqdn`·`tailscaleIPs`·`certDomains`·`tunnel{…}`·`peerCount` | `await node.status`의 `fqdn`·`addresses`·`certDomains`·`networkSettings`·`peerCount` |

질문:

6. `NodeError`는 사람이 읽을 문장을 주지 않는다(종류와 짧은 진단 문자열뿐이다). 앱이 종류마다 한국어 안내를 고르는 것(`TunnelProviderError`처럼)으로 충분한가? 지금 `backendErrorMessage(cause:)`가 원인으로 붙이는 코어 문장에 해당하는 것은 `NodeError`의 진단 문자열이다.
7. Go와 달리 인증 키 거부·등록 거절이면 노드가 끝난다(`run()`이 던진다). 다시 시도하려면 VPN을 다시 켜야 한다. 지금 UI의 "다시 연결"·"인증 키로 켜기"가 모두 VPN을 다시 켜는 동작이므로 맞는다고 보았다. 맞는가?
8. `NeedsLogin`의 URL이 늘 있으므로 30초마다 로그인을 다시 시작하던 것(`needLoginKick`)이 필요 없다. URL 없는 `NeedsLogin`을 따로 보여 주는 화면이 있는가?
9. 상태 응답에 `stableID`를 더할 수 있다(`NodeStatus.stableID`). 폰 쪽 화면이나 진단에서 쓰는가? 쓰지 않으면 계약에서 뺀다. `peerCount`도 같은 질문이다(시험 계약에는 있다).

### F4. 기본 인터페이스 통지

대응: `PacketTunnelProvider.defaultInterfaceName(_:)`가 이름 대신 `NWInterface`를 돌려주게 하고 `node.setDefaultInterface(interface)`를 부른다(T3). 이름 검사(`bad_request`)는 없어진다.

질문:

10. 지금은 이름이 바뀔 때만 부른다(`TunnelRuntime.updateDefaultInterface`). Swiftail에는 Go `netmon`의 경로 소켓 감시가 없어서, 같은 Wi-Fi에서 주소만 바뀐 경우(다른 AP, DHCP 갱신)는 앱이 알려야만 안다. 만족된 경로를 받을 때마다 거르지 않고 불러 주는 것으로 바꿀 수 있는가? 같은 인터페이스·같은 주소면 노드는 STUN만 다시 한다.
11. 고르는 규칙(루프백·`other`·`utun*`·`ipsec*` 제외의 첫 인터페이스)은 그대로 둔다. 노드도 자기 utun 이름과 같은 인터페이스는 무시한다.

### F5. 경로 상태

대응: `rd_tunnel_set_path_peer(fqdn)` + 상태의 `peerPath` → 상태를 만들 때 `await node.path(toPeerNamed: fqdn)`, 또는 `peerPathChanged`에서 그 피어의 마지막 값을 기억. `PeerPath.direct(endpoint)` → `{"direct": true, "addr": "<endpoint>"}`, `.relayed(derpRegion:)` → `{"direct": false, "relay": …}`.

질문:

12. 첫 사용처의 `relay`는 지역 코드 문자열(`"tok"` 등)인데 Swiftail은 지역 ID(`Int64`)를 준다. 화면에 코드가 필요한가? 필요하면 `NodeStatus`에 DERPMap의 ID → 코드 표를 더하거나 `PeerPath`에 코드를 싣는 변경을 M4 계약에 요청해야 한다.
13. 첫 사용처는 "최근에 주고받은 것이 없는 피어는 경로를 모르므로 넣지 않는다"(`docs/protocol-addenda.md` N.3). Swiftail의 `path(toPeerNamed:)`는 유휴 피어도 `.relayed`(또는 신뢰 기간 안이면 `.direct`)를 준다. 유휴일 때 표시를 빼야 하는가?

### F6. 로그

Swiftail은 로그 API도 로그 사건도 없다. 첫 사용처는 코어 로그를 `os.Logger`에 비공개로 남겨 왔다.

질문:

14. 실기기 진단에 라이브러리 내부 로그가 필요한가? 필요하면 라이브러리 안에서 `os.Logger(subsystem: "Swiftail")`로 비밀 없는 요약만 남기는 방안을 총괄에 올린다(공개 API는 늘리지 않는다).

### F7. 메모리

- `goMemLimitMiB`에 해당하는 설정은 없다. 버퍼 상한은 계약이 고정한다(동작 M).
- 질문 15: `TunnelStatusReply.physFootprintMiB`(앱이 `TASK_VM_INFO`로 잼)를 관문 (나)의 메모리 기록에 그대로 쓰겠다. 유휴·전송 중을 가르는 기록 방법(예: 상태 요청을 일정 간격으로 보내 기록)을 첫 사용처 쪽에서 준비할 수 있는가?

### F8. 상태 파일과 로그인 초기화

- 저장은 `stateDir/identity.json` 하나다. `resetsLogin`의 디렉터리 지우기는 그대로 쓸 수 있다(노드가 돌지 않을 때 지워야 한다. 지금처럼 `startTunnel`에서 시작 전에 지운다).
- 데이터 보호 등급·백업 제외는 노드가 파일에 건다(T6). `TunnelStorage.prepareStateDirectory`의 디렉터리 설정은 그대로 둔다.

### F9. 기존 사용자의 전환 (D8)

16. Swiftail은 Go의 `tailscaled.state`를 읽지 않는다(이관은 M7 결정). 지금 Go 코어로 로그인한 기기가 Swiftail로 바뀌면 새 노드(새 IP, 새 StableID)로 로그인하고 Mac과 다시 페어링해야 한다. 이 전환을 M5 교체 때 받아들일 수 있는가, 아니면 M7 이관을 M5 교체 전으로 당겨야 하는가?

## 제외 (`shortcut:` 주석으로 남긴다)

| 제외 | 근거 | 필요해지는 시점 |
| --- | --- | --- |
| 서브넷 경로·exit node(받기·주기), VIP·4via6 경로 | plan 3절 제외. M3부터 `RouteAll=false` 고정(엔진 계약 M3) | plan 범위를 넓힐 때 |
| 전역 리졸버(`Resolvers`), 리졸버가 있는 `Routes`, 상위 전달(UDP·TCP·DoH), `FallbackResolvers`, `GetBaseConfig`·1차 리졸버 모드 | D1·D2. OS가 match 도메인 밖의 이름을 quad-100에 보내지 않는다(DNS 노트 4.2.3) | 사용자 지정 분할 DNS를 터널로 풀어야 할 때 |
| 검색 도메인 | D3 | 짧은 이름 해석이 요구될 때 |
| 서비스 IP의 TCP 53(DNS over TCP) | D4. 로컬 응답에 TC가 서지 않는다(DNS 노트 4.2.4) | M6 TCP 스택 뒤 |
| 4via6 이름, `dns-subdomain-resolve` 서브도메인 | DNS 노트 6.1 | 그 기능을 쓰는 tailnet을 만날 때 |
| tailnet lock 지원 | M8에서 넣었다(`SwiftailTailnetLock.md`). M5 때는 켜진 tailnet의 접속을 거절했다(`ControlError.tailnetLockEnabled`, 지금은 없다) | — |
| IPv6 UDP 소켓·IPv6 엔드포인트 | magicsock 계약 제외 표. DERP(TLS, 호스트 이름)는 IPv6 전용 망에서도 된다 | 실기기에서 IPv6 전용 셀룰러 망을 만나 직접 경로가 필요할 때 |
| 망이 내려감의 처리, UDP 송신 오류의 자동 재결속, DERP 연결의 선별 유지 | 동작 N 3.2·5·6 | 동작 N에 적음 |
| 다른 프로세스 사이의 상태 디렉터리 중복 막기 | 동작 P 3. App Group 컨테이너의 파일 잠금은 앱 일시 정지와 얽힐 수 있어 들이지 않는다 | 두 프로세스가 같은 디렉터리를 쓰는 사용처가 생길 때 |
| TSMP pong·거절·disco 광고 보내기 | 엔진 계약 M3·M4 그대로 | 해당 없음 |
| 로그 | F6 | F6의 답에 따라 |

## 시험

### 단위 시험 (소켓·파일 기술자 없음, 시각을 넘겨 결정적으로)

`Tests/SwiftailEngineTests/Tunnel/`:

1. **DNS 코덱**: 머리 플래그 복사 규칙(QR·AA·RA, RD 0·1, Opcode·TC·AD·CD 보존), 질문 0·2개, QR=1, 포인터(정상, 앞으로 가는 포인터, 자기 자신을 가리키는 고리, 11번째 포인터), 01·10 레이블 형식, 레이블 안의 `.`, 254바이트 경계, 압축 없는 쓰기의 바이트, 임의 입력으로 죽지 않음.
2. **응답기**: DNS 노트 7절 2~4의 항목 — A·AAAA·ANY·PTR(IPv4·IPv6·4to6·서비스 IP)·NS·SOA·TXT·모르는 타입, 짧은 이름·FQDN·대소문자 섞임·끝 점 없음, 주소 없는 노드, 영역 밖(SERVFAIL), `.onion`, Bonjour 역방향, `magicdns-aaaa` 있음·없음, IPv6 전용 자기 노드, `ExtraRecords`가 노드 색인보다 먼저, EDNS 광고 크기와 512 경계의 TC, 응답에 OPT 없음, SOA의 SERIAL이 넘긴 시각.
3. **설정 산출**: 엔진 노트 7절 10과 DNS 노트 7절 1 — 피어별 /32, 10,000/10,001 경계, `one-cgnat?v=true`·`v=false`·없음, ULA 피어가 있을 때 /48, 자기 주소 계열별 서비스 경로와 DNS 서버, IPv4 전용·IPv6 전용 자기 노드, 자기 주소 없음 → nil, MagicDNS 켬·끔, 빈 라우트, 리졸버가 있는 라우트(무시), 전역 `Resolvers`(무시), `ExtraRecords`(덮임·안 덮임·잘못된 이름), `force-register-magicdns-ipv4-only`, 자기 키 만료 → DNS 없음, match 도메인 정렬과 끝 점, 같은 netmap이면 같은 값(순서 포함).
4. **로컬 처리**(`TailnetEngine.send`. 이 시험만 `Tests/SwiftailEngineTests/TailnetEngineTests.swift`에 두고 M5-8이 쓴다): UDP 53 질의 → 응답 패킷(주소·포트 맞바꿈, IPv4·IPv6 체크섬 검증), ICMP·ICMPv6 echo → reply, TCP SYN·ACK 세그먼트·RST → 동작 L2의 RST 규칙(`UInt32` 순환 포함), 다른 UDP 포트·다른 프로토콜 → `.serviceIPPacket`, 서비스 IP로 간 어떤 패킷도 `.datagram`을 내지 않음, 자기 주소로 간 패킷 → 같은 바이트의 `.ipPacket`, 장치에서 온 TSMP → 버림.

`Tests/SwiftailTests`:

5. **상태 기계**(동작 B 표): 각 행의 경계, `registered`가 URL을 지움, `.running` 뒤 끊김에도 유지, 같은 상태를 다시 내지 않음.
6. **설정 내기**(동작 E): 주소 없음 → 내지 않음, 같은 값 → 내지 않음, DNS 서버만·match 도메인만 바뀜 → 냄, 읽지 않은 설정을 새 것이 대신함(흐름에서 하나만 나옴).
7. **전환 판정**(동작 N 1·2): 처음, 같은 인터페이스·같은 주소(STUN만), 주소만 바뀜(재결속), 인터페이스 바뀜(재결속), utun 이름과 같은 인터페이스(무시). 판정은 입출력 없는 함수로 둔다.
8. **상태 디렉터리 표**(동작 P 3): 같은 경로(표준화 전 다른 표기 포함) 두 번 → 둘째가 `stateDirectoryInUse`, 첫째가 끝난 뒤 다시 가능.

`Tests/SwiftailIOTests`:

9. **`UTUNDevice`**: utun이 아닌 기술자(파이프, `socketpair`, 닫힌 기술자, -1)를 거절하고 호출자의 기술자는 열려 있음. 검사를 건너뛰는 시험 전용 생성자로 `socketpair(AF_UNIX, SOCK_DGRAM)`를 utun 대신 써서: 4바이트 머리 붙이기·떼기(IPv4 → 2, IPv6 → 30, 그 밖 → 쓰지 않음), 4바이트보다 짧은 읽기 버림, 상대가 닫히면 장치 닫힘 오류, 복제본만 닫히고 원래 기술자는 열려 있음, `FD_CLOEXEC`가 복제본에 있음. utun을 만드는 시험은 관리자 권한이 필요하므로 두지 않는다(실기기 관문이 덮는다).
10. **소켓 묶기**: `DatagramSocket`에 루프백 인터페이스 `index`로 `IP_BOUND_IF`를 걸어도 루프백 송수신이 되고, 없는 `index`는 `bindFailed`.

### Go 기준값 대조

M3 `filterfixtures`·M2 `mapfixtures`와 같은 방식이다. 자료는 `Tools/interop`의 Go 도구가 Go의 실제 코드를 실행해 만들고, 대조 시험은 구현자와 다른 세션이 쓴다. 자료에 현재 시각·운영 키·실제 이름이 없다(이름은 `tail0001.ts.net` 같은 가짜).

- **`Tools/interop/cmd/dnsfixtures`**(새 도구): `tailscale.com/net/dns/resolver`의 `New` + `SetConfig`(호스트 표, `LocalDomains`) + `SetMagicDNSHosts`(`tsdns.go:270-300`) + `Query(…, "udp", …)`로, 위 단위 시험 2의 질의 바이트를 넣어 응답 바이트를 얻는다. SOA SERIAL은 자료에 표시해 비교에서 뺀다. 자료: `Tests/SwiftailEngineTests/Fixtures/magicdns-fixtures.json`. 한계: Go의 노드 색인 구현(`MagicDNSHosts`를 채우는 `ipnlocal` 쪽, AAAA 거르기와 짧은 이름)은 내보내지 않은 코드라 도구가 고정 표로 대신한다. 이 자료는 바이트 형식·RCODE·SOA·TC를 대조하고, 색인 규칙(DNS 노트 4.2.1)은 관문 (가)의 Go 피어 상대 질의와 단위 시험이 덮는다.
- **`Tools/interop/cmd/tunnelfixtures`**(새 도구): 경로는 내보낸 `tailscale.com/net/routemanager`(`New`, `Begin`, `UpsertPeer`, `SetTailnetConfig`, `Commit`, `OSRoutes`, `routemanager.go:219-511`)에 같은 피어 집합을 넣어 얻는다. DNS는 Go의 `dnsConfigForNetmap`이 내보내지 않은 함수라(`ipn/ipnlocal/node_backend.go:1435`) 도구가 Go 노드 하나를 띄워 `LocalBackend`가 엔진에 넘기는 `dns.Config`를 가로채고, 그것을 `dns.NewManager(…, goos "ios", …)`(`net/dns/manager.go:97`)와 값을 받기만 하는 `OSConfigurator`로 컴파일해 `OSConfig`를 얻는다. 결과를 동작 S의 형태(D1·D2로 좁힌 뒤)로 옮겨 쓴다. 자료: `Tests/SwiftailEngineTests/Fixtures/tunnel-settings-fixtures.json`. 사례는 단위 시험 3의 netmap들(JSON).
- 일부러 다르게 한 것(D1·D2의 좁히기, 4via6·서브도메인 생략)은 자료에 표시해 따로 본다.

## M5 관문

### (가) 메모리 장치로 첫 사용처의 터널 시험 계약에 대응하는 항목

`Tools/interop`의 `tailnet`(testcontrol + DERP + STUN + Go tsnet 피어, 포트 7 에코)을 상대로, Swift 노드를 `.memory(mtu:)`로 띄운다. 시험은 `Tests/SwiftailInteropTests/TunnelTests.swift`에 두고 `SWIFTAIL_TAILNET`이 없으면 건너뛴다. 왼쪽은 첫 사용처 `docs/tunnel.md` "테스트 계약"의 이름이다.

| 첫 사용처 시험 | Swiftail 관문 항목 |
| --- | --- |
| `TestTunnelDataPath/network-settings` | `.running` 뒤 `networkSettings`의 첫 값: `addresses`에 자기 /32, `routes`에 Go 피어 주소의 /32, `dnsServers[0] == 100.100.100.100`, `dnsMatchDomains`에 tailnet 접미사(끝 점 없음), `mtu == 1280`. `status.networkSettings`가 같은 값이고 `peerCount ≥ 1` |
| `…/udp` | Go 피어 포트 7로 보낸 UDP의 에코가 `inboundPackets`로 온다(1초마다 재시도) |
| `…/tcp` | Go 피어 포트 7로 보낸 SYN에 SYN-ACK가 온다 |
| `…/magicdns` | `100.100.100.100:53`으로 보낸 Go 피어 FQDN의 A 질의에 피어 IPv4가 답으로 온다. 더해서: AAAA → NOERROR 빈 답 + SOA, 피어 주소의 PTR → 피어 FQDN, 영역 안 모르는 이름 → NXDOMAIN, `example.com` → SERVFAIL, `fd7a:115c:a1e0::53`로도 같은 답, ICMP echo → reply, TCP 53 SYN → RST, 그 동안 Go 피어 쪽에서 서비스 IP로 간 패킷이 보이지 않음 |
| `…/stop` | `run()` Task를 취소하면 `run()`이 돌아오고 세 흐름이 끝난다. 그 뒤 Go 피어의 `peerStatus`에서 마지막 송신 시각이 더 늘지 않는다 |
| `TestTunnelEngineDeath` | `failMemoryDevice()` 뒤 `run()`이 `tunnelDeviceClosed`를 던지고, 흐름이 끝나고, 더 사건이 나오지 않는다 |
| `TestTunnelRestartKeepsNode` | 같은 디렉터리로 다시 띄우면 `.needsLogin` 없이 같은 주소, 새 디렉터리면 다른 주소, 옮긴 디렉터리면 원래 주소. `identity.json`이 생긴다 |
| `TestTunnelInUse` | 같은 디렉터리의 두 번째 노드 → `stateDirectoryInUse`, 첫째를 멈춘 뒤 다시 가능(다른 디렉터리는 막지 않음, F1 질문 1) |
| `TestTunnelSlotReleasedOnFailedStart` | 첫째 `run()`이 실패해도 같은 디렉터리로 다음 노드가 돈다. `udpUnavailable`을 일으키는 시험 훅은 두지 않았다(묶지 못하면 묶지 않은 소켓으로 버티게 된 뒤로 그 실패를 만들 길이 없다). 대신 단위 시험 `failMemoryDeviceEndsRun`이 `run()`이 실패로 끝난 뒤 상태 디렉터리가 풀리는 것을 확인한다(점유는 `run()`의 `defer` 하나로 풀린다) |
| `TestTunnelInvalidConfig` | `.utun` -1, 파이프 기술자 → `init`의 `invalidConfiguration`. MTU 1, 1000, 1279, 1421, 1500, 9000, -1280 → MTU 메시지. 거절된 경우 상태 디렉터리에 아무것도 생기지 않음 |
| `TestTunnelMTUBounds` | MTU 1280·1420·기본값이 시작되고 `networkSettings.mtu`가 1280·1420·1280 |
| `TestTunnelSetDefaultInterface`, `…Reevaluates` | `NWPathMonitor`에서 얻은 실제 인터페이스로 `setDefaultInterface`를 부르면 UDP 소켓이 다시 묶이고(포트 같음) 엔드포인트가 다시 올라가며(`nodes`의 `endpoints`), DERP·제어가 다시 이어진 뒤에도 에코가 되고 Go 피어와 직접 경로가 다시 선다(M4 관문 2의 기준). 루프백 목적지는 묶지 않으므로 루프백 tailnet에서 돈다 |
| `TestTunnelIOSDNS`, `TestTunnelScopeDNS`, `TestTunnelSettingsBuild`, `…Equal`, `…SinkFlush`, `…EventReplaced` | 단위 시험 3·6과 Go 기준값 대조(`tunnelfixtures`) |
| `TestTunnelLoginRecovers`, `TestTunnelOpenUTUNKeepsCallerFD` | 해당 없음(Go 패닉 회복) / 단위 시험 9 |
| (더함) 대화형 로그인 | `setAuth`로 대화형 인증을 요구하면 `.needsLogin(url)`, 그 URL로 끝내면 `.starting` → `.running` |
| (더함) M3·M4 관문 회귀 | M3 관문 2~7, M4 관문 2~9가 `.memory` 장치에서 그대로 통과(사건 기다림만 T1에 맞게 고침) |

### (나) 실기기

실기기 확인은 첫 사용처 세션이 맡는다(2026-11-15 합의): RemoteDebug 터널 확장에 Swiftail 구현을 고를 수 있는 빌드 변형(SwiftPM 경로 의존, 로컬 전용 설정)을 만들고, Go 노드의 상태를 건드리지 않도록 **별도 상태 디렉터리**로 띄운다. Swiftail 쪽은 결과에서 나온 결함을 고친다. 시각과 메모리는 확장이 재어 기기 로그로 올린다(Swiftail은 진단 API를 늘리지 않는다. `events`·`status`·`networkSettings`와 `os.Logger(subsystem: "Swiftail")`로 본다).

| # | 확인할 것 | 통과로 볼 기준 | 기록만 하는 것 |
| --- | --- | --- | --- |
| 1 | utun 기술자로 시작 | `TailnetNode(configuration:device: .utun(…))`이 던지지 않고, 인증된 상태에서 `run()` 뒤 30초 안에 `.stateChanged(.running)`과 `networkSettings`의 첫 값이 나온다. `tunnelDeviceClosed`·`udpUnavailable`이 나오지 않는다. 터널을 끄고 다시 켜면 같은 주소·StableID로 다시 `.running`이 된다(복제본만 닫혔다는 증거) | 시작부터 `.running`까지의 시간 |
| 2 | Mac의 tailnet HTTPS에 FQDN으로 접속 | `.running` 뒤 첫 요청이 10초 안에 HTTP 응답을 받는다(DERP 경유여도 된다). 이어서 10번 요청이 모두 성공한다 | `peerPathChanged`가 `.direct`가 된 시각, LAN과 셀룰러 각각의 경로 |
| 3 | MagicDNS와 match 도메인 | 앱(터널 밖의 일반 소켓)에서 Mac의 FQDN이 그 tailnet IPv4로, 그 주소의 PTR이 FQDN으로 풀린다. tailnet 밖 이름(예: 공개 사이트)은 평소대로 풀리고 접속된다(터널이 기기의 일반 DNS를 가로채지 않는다) | match 도메인 수, 해석에 걸린 시간 |
| 4 | 셀룰러와 CGNAT | Wi-Fi를 끄고 셀룰러만 켠 상태에서 터널이 켜진 채 일반 인터넷 HTTPS가 되고, 2도 통과한다 | 통신사가 준 주소 대역이 100.64/10인지 |
| 5 | Wi-Fi ↔ 셀룰러, 비행기 모드 해제 | 전환(확장이 `setDefaultInterface`를 부른 시각)부터 **15초 안에** Mac으로의 요청이 다시 성공한다. 양방향(Wi-Fi→셀룰러, 셀룰러→Wi-Fi)과 비행기 모드 해제 각각 3번씩, 모두 통과. 전환 중에 `run()`이 끝나지 않는다 | 직접 경로가 다시 선 시각(메모리 장치 관문에서는 약 10초), 제어·DERP가 다시 붙은 시각(로그) |
| 6 | 확장의 `phys_footprint` | 유휴 10분 뒤 **20MiB 이하**(plan 7절 목표), 100MB 내려받는 동안의 최고치 **40MiB 이하**(보고된 한도 50MiB에서 10MiB 여유)이고 jetsam으로 죽지 않는다. 같은 절차의 Go 터널 값보다 유휴 값이 크지 않다 | 연결 직후·1분·5분·10분 값, 전송 중 최고치, Go 터널의 같은 값 |
| 7 | 신원 파일의 보호 | 첫 잠금 해제 뒤 `identity.json`의 보호 등급이 `completeUntilFirstUserAuthentication`이고 백업 제외가 켜져 있다(등록 뒤, 그리고 node 키를 바꾼 뒤에도). 재부팅 뒤 **첫 잠금 해제 전**에 주문형으로 시작되면 죽지 않는다: 이미 등록된 기기에서는 파일을 읽지 못해 `run()`이 `control(.storage)`로 끝나거나, 읽혀서 정상으로 뜬다. 어느 쪽이든 잠금 해제 뒤 다시 켜면 같은 노드로 뜬다 | 첫 잠금 해제 전의 실제 동작(둘 중 어느 쪽인지) |
| 8 | 신호와 종료 | 1~6을 하는 동안 확장이 신호나 trap으로 죽은 기록(크래시 로그, 예기치 않은 VPN 끊김)이 0건이다. LAN에서 직접 경로를 탈 때도 같다(macOS에서는 UDP 송신의 SIGPIPE를 재현해 `SO_NOSIGPIPE`로 막았다) | — |
| 9 | 묶이지 않는 요청의 경로 | 기준 없음. 등록과 로그인이 터널이 켜진 상태에서 된다면 통과로 본다 | `/key` 조회와 Noise가 아닌 핑 응답(URLSession)이 물리 인터페이스로 나가는지, 터널로 들어가는지 |
| 10 | 실제 tailnet(마무리, plan 4절(b)) | 2·5가 운영 제어 서버와 운영 DERP에서 통과한다 | 총괄이 사용자에게 먼저 알리고 비밀 입력으로 인증 키를 받는다 |

기준을 못 맞춘 항목은 잰 값과 관련 로그 줄을 그대로 받아 결함으로 다룬다. 6의 숫자는 목표치이며, Go 터널의 기준값(유휴 10분, 100MB 전송)이 채워지면 그 값과 함께 다시 본다.

**Go 터널의 기준값**(2026-11-15, 첫 사용처 세션이 실기기에서 잼. iPhone 14 Pro, iOS 27.2, Wi-Fi, Go 호스트 상대):

| 항목 | 값 |
| --- | --- |
| 연결 직후 `phys_footprint` | 3.9~5.2 → 9.4~10.3 → 11.3~11.8MiB(첫 5초) |
| 유휴 10분 | 13.0MiB(최고 13.2. 확장이 30초마다 스스로 잰 값) |
| 100MiB 받는 동안 | 12.6MiB 미만 |
| 100MiB 받기(HTTPS, Mac → iPhone, 같은 Wi-Fi의 직접 UDP 경로) | 23.0초(4.56MiB/s) |

그래서 6의 "Go 터널 값보다 유휴 값이 크지 않다"는 **유휴 13MiB 이하**를 뜻한다(20MiB는 그 위의 한도로 남는다). 셀룰러와 DERP 전용의 값은 아직 없다.

**Swiftail 터널의 첫 실행**(같은 기기, RemoteDebug 변형 빌드 + Swiftail `966c141`): 실제 utun 기술자로 시작했고(`TailnetNode(configuration:device: .utun(…))`과 `run()`이 돌았고 확장이 죽지 않았다), VPN "연결 중"에서 약 4.3초 뒤 `.needsLogin(url)`이 나와 앱이 "로그인 필요"를 보였다. 로그인을 기다리는 약 90초 동안 `phys_footprint`는 3.1 → 7.8MiB였다. 새 노드로 등록되므로 **사용자가 iPhone에서 로그인해야** 항목 1 이후를 볼 수 있다. 그 노드는 Mac과 페어링되지 않은 새 기기라, Swiftail 터널이 켜진 동안 기기 로그를 Mac으로 올리려면 Mac의 같은 Wi-Fi 직접 연결을 켜 두거나 그 노드를 Mac에 페어링해야 한다(페어링 허용은 사용자 승인).

**로그인 뒤의 결과**(2026-11-15, 같은 기기·같은 빌드. 터널 경로는 `9d87e85`와 같다. 첫 사용처 세션이 기기 로그에서 읽은 값):

| 항목 | 결과 |
| --- | --- |
| 로그인 뒤 `.running` | 됨. `tailnetLockEnabled`로 끝나지 않았다 |
| 1. 시작 뒤 30초 안에 `.running` | **통과.** 로그인된 상태에서 세 번: 4.5초, 6.3초, 4.2초. 앱은 `networkSettings`가 적용된 뒤에 "연결됨"을 보이므로 첫 설정도 그 안이다(설정 사건의 시각은 따로 찍지 않았다) |
| 정지와 다시 시작 | 끄기 요청 뒤 약 0.4초에 꺼졌고, 세 번 모두 같은 상태 디렉터리로 다시 떴다 |
| 6. 유휴 `phys_footprint` | **통과.** 시작 직후 4.0~5.1 → 6.7~7.0MiB(2초), 5분 8.2MiB, 10분 8.7MiB, 43분 동안 8.7~8.8MiB로 평평(최고 8.8). Go 터널은 같은 기기에서 13.0MiB다. 화면이 꺼지고 앱이 뒤로 간 구간에도 확장이 죽거나 다시 뜨지 않았다 |

**전환 시험**(2026-11-15, 같은 기기, 변형 빌드 + Swiftail `dfd7008`. 앱이 1초마다 Mac의 tailnet FQDN으로 HTTPS HEAD(요청마다 새 연결, 제한 3초). 전환은 제어 센터로 조작. "경로"는 터널 확장의 `NWPathMonitor` 기록):

| 전환 | 엔진 | 경로 | 탐침 | 복구까지 | 15초 기준 |
| --- | --- | --- | --- | --- | --- |
| Wi-Fi → 셀룰러 | Swiftail | "경로 없음" 직후 같은 초에 `pdp_ip0` | 3초 뒤 실패(시간 초과). 셀룰러에 있던 41초 동안 한 번도 성공 없음 | 복구 안 됨 | **실패** |
| 셀룰러 → Wi-Fi | Swiftail | `en0` | 4초 뒤 성공 | 약 4초 | 통과 |
| 비행기 모드 켬 12초 → 끔 | Swiftail | 경로 없음 → `en0` | 끈 뒤 2초에 성공 | 약 2초 | 통과 |
| Wi-Fi → 셀룰러 (대조) | Go | 바로 `pdp_ip0` | 실패 1회 뒤 성공 | 약 5초 | 통과 |
| 셀룰러 → Wi-Fi (대조) | Go | `en0` | 실패 없음 | 0초 | 통과 |

각 한 번씩이다(항목 5의 기준은 세 번씩). 같은 Mac·같은 셀룰러 망에서 Go는 복구했으므로 망이나 Mac의 문제가 아니다. 그 구간의 Swiftail 로그는 없다. 그 밖에 받은 값(Swiftail 터널, Wi-Fi): Mac FQDN으로의 첫 HTTPS HEAD 0.27초에 성공, 27초 동안 실패 없음, 다시 시작 4.4초.

**Wi-Fi → 셀룰러 실패의 원인**(재시험으로 확인, 2026-11-15. 변형 빌드에 진단을 더함, Swiftail `597559c` 시점 소스, 셀룰러 66초):

- 셀룰러 경로는 **IPv6 전용 + CLAT**이다. `pdp_ip0`의 `NWPath`는 `supportsIPv4` false·`supportsIPv6` true·`supportsDNS` true이고, 인터페이스에는 `192.0.0.x`(CLAT)의 IPv4 주소와 링크 로컬 밖의 IPv6 주소가 있다. Wi-Fi(`en0`)는 IPv4만 지원한다.
- 그 66초 동안 Swiftail 로그에는 재결속 줄(`기본 인터페이스 재결속: pdp_ip0`, `재결속: UDP 포트 …`, `제어: 연결 끊김, 다시 잇는 중`)만 있고 `DERP 지역 …: 연결됨`이 한 번도 없다. `UDP 소켓을 기본 인터페이스에 묶지 못해…`도 없다(묶기는 됐다). Wi-Fi로 돌아오자 같은 초에 DERP가 붙고 경로가 직접이 됐다.
- 탐침 실패 18번은 모두 3.00~3.01초 시간 초과다(즉시 실패 없음).
- 전환 때 확장이 부른 순서: `en0`(경로는 아직 satisfied인데 `en0`에 주소가 하나도 없는 순간) → "경로 없음"(호출 없음) → `pdp_ip0` 세 번 → (머무는 동안 경로 갱신으로 두 번 더).

읽은 것: Swiftail은 DERP를 DERP 맵의 **IPv4 리터럴 하나로만** 건다(`DERPServer+DERPNode.swift`). IPv4를 지원하지 않는 경로에서 그 연결은 서지 않고(`NetworkSocket`은 `.waiting`을 실패로 본다), `DERPClient`는 붙기 전의 실패를 사건으로도 로그로도 내지 않아 줄이 없었다. Go는 노드마다 IPv4와 IPv6를 함께 걸어 먼저 붙는 쪽을 쓴다(`derp/derphttp/derphttp_client.go` `dialNode`). 고칠 것: ① DERP를 두 주소 체계로 함께 걸기(DERP만 붙어도 중계로 산다) ② 붙지 못한 시도를 로그에 남기기. 그 뒤에 볼 것: `pdp_ip0`에 묶은 `AF_INET` UDP가 CLAT로 실제 나가는지(직접 경로가 서는지), 서지 않으면 바깥쪽 UDP·STUN·엔드포인트의 IPv6. 제어 연결이 셀룰러에서 다시 붙었는지는 로그에 성공 줄이 없어 모른다(제어는 이름으로 걸므로 DNS64의 덕을 본다고 추정).

**고친 뒤의 재시험**(2026-11-15, Swiftail `98cbbf0`. DERP를 IPv4·IPv6 대상으로 함께 걸게 한 뒤. 같은 기기·같은 조작·같은 조건):

| 전환 | 탐침 | 복구까지 | 15초 기준 |
| --- | --- | --- | --- |
| Wi-Fi → 셀룰러 | 실패 1번(3.01초 시간 초과) 뒤 성공(요청 0.26초, 그때 경로는 중계) | 약 4초 | **통과** |
| 셀룰러에 머문 76초 | 59번 연속 성공 | — | — |
| 셀룰러 → Wi-Fi | 실패 1번 뒤 성공(요청 0.09초) | 약 4초 | 통과 |

- 셀룰러로 넘어간 같은 초에 `DERP 지역 7: 연결됨`, 5초 뒤 `피어 경로: direct`. **IPv6 전용 + CLAT 망에서 `AF_INET` UDP가 CLAT를 거쳐 나가 직접 경로가 섰다.** 이 망에서는 바깥쪽 UDP·STUN의 IPv6 없이도 된다(CLAT가 없는 IPv6 전용 망은 보지 못했다). `연결 실패(…)` 줄은 없었다.
- 각 한 번씩이다(항목 5의 기준은 세 번씩).
- 본 것 둘(실패는 아님): ① 셀룰러에 머무는 중 약 70초 뒤 같은 인터페이스(`pdp_ip0`)로의 경로 갱신에서 STUN만 다시 하지 않고 **전체 재결속**이 일어나 경로가 1초 동안 중계로 내려갔다(탐침 실패 없음). 앞선 실패 시험에서도 같은 시점에 있었다. `DefaultLink`가 기본 인터페이스의 주소가 아니라 기기의 모든 IPv4 주소를 견주므로, 다른 인터페이스의 주소가 바뀌어도 재결속으로 판정한다(추정. 그 순간 어느 주소가 바뀌었는지는 기록이 없다). ② 제어 연결이 다시 붙었다는 로그 줄이 없었다. 줄을 더했다(`제어: 다시 이어짐`, 끊긴 뒤 첫 netmap에서 한 번).

시험 조건(첫 사용처 세션이 사용자에게 확인): 이 전환 시험에서 iPhone 앱과 Mac은 **서로 다른 tailnet**에 로그인돼 있었다(같은 사용자. Mac은 iPhone 노드에게 다른 tailnet의 피어로 보인다). Wi-Fi에서는 이 조건으로 직접 경로까지 붙었다. iPhone의 Go 노드와 Swiftail 노드가 같은 tailnet인지는 확인되지 않았다. 고친 뒤의 재확인은 같은 조건으로 한다.

아직 보지 못한 것: 2(Mac의 tailnet HTTPS 요청)·6의 전송 중 메모리·100MiB 받기와 MagicDNS·경로 표시는 그 노드를 Mac에 페어링한 뒤(사용자 승인 대기), 5(Wi-Fi ↔ 셀룰러, 비행기 모드)와 7(첫 잠금 해제 전 시작)은 사용자가 기기를 손으로 조작해야 한다. 첫 사용처 확장의 정식 교체는 별도 승인 뒤다(plan 7절 M7, T7).

## 구현 단위

소유 파일이 겹치지 않게 나눈다. M4 단위 4가 `Sources/Swiftail/**`, `Sources/SwiftailEngine/**`(기존 파일), `Sources/SwiftailMagicsock/Magicsock*.swift`, `Tests/SwiftailEngineTests/*`, `Tests/SwiftailTests/*`를 고치는 중이므로, **M4보다 먼저 시작할 수 있는 단위는 새 파일만 만든다**. 새 파일은 하위 폴더(`Tunnel/`)에 두어 M4의 파일과 이름이 겹치지 않게 한다.

| 단위 | 내용 | 소유 파일 | 선후 |
| --- | --- | --- | --- |
| M5-0 | 총괄: 이 계약 확정(T1~T7, F 질문의 답 반영) | `docs/contracts/SwiftailTunnel.md` | 먼저 |
| M5-1 | DNS 코덱과 응답기(동작 D) | `Sources/SwiftailEngine/Tunnel/{DNSMessage,MagicDNSResolver}*.swift`, `Tests/SwiftailEngineTests/Tunnel/{DNSMessageTests,MagicDNSResolverTests}.swift` | **M4와 병렬** |
| M5-2 | 설정 산출(동작 S, `TunnelNetworkSettings`) | `Sources/SwiftailEngine/Tunnel/TunnelNetworkSettings*.swift`, `Tests/SwiftailEngineTests/Tunnel/TunnelNetworkSettingsTests.swift` | **M4와 병렬**(`EnginePeer.peers`는 M3 시그니처 그대로 읽기만 한다) |
| M5-3 | 서비스 IP 응답 패킷 만들기(UDP·ICMP echo·RST, 체크섬) — 엔진에 붙이기 전의 순수 함수 | `Sources/SwiftailEngine/Tunnel/ServiceIPReply*.swift`, `Tests/SwiftailEngineTests/Tunnel/ServiceIPReplyTests.swift` | **M4와 병렬** |
| M5-4 | `UTUNDevice`(동작 U) | `Sources/SwiftailIO/UTUNDevice.swift`, `Tests/SwiftailIOTests/UTUNDeviceTests.swift` | **M4와 병렬** |
| M5-5 | Go 기준값 도구와 자료 | `Tools/interop/cmd/{dnsfixtures,tunnelfixtures}/`, `Tests/SwiftailEngineTests/Fixtures/{magicdns-fixtures,tunnel-settings-fixtures}.json`, `Tools/interop/README.md`의 새 절 | **M4와 병렬**. 대조 시험은 M5-1·2 뒤 다른 세션이 |
| M5-6 | 묶기와 메모리 한도의 가장자리: `NetworkSocket` `requiredInterface`, `ControlClient.setNetworkInterface`, 맵 프레임 8MiB, `DERPClient` 인터페이스 인자·사건 바이트 한도 | `Sources/SwiftailIO/NetworkSocket*.swift`, `Sources/SwiftailControl/Client/ControlClient*.swift`, `Sources/SwiftailControl/Netmap/MapResponseFramer.swift`, `Sources/SwiftailDERP/DERPClient*.swift`와 각 시험 | **M4와 병렬**(M4가 고치지 않는 파일). `DERPClient`의 생성자 변경은 M4 단위 4의 호출 지점과 맞물리므로 기본값 있는 인자로 더한다 |
| M5-7 | UDP 묶기와 재결속: `DatagramSocket`의 `IP_BOUND_IF`·바이트 한도, `Magicsock.rebind` | `Sources/SwiftailIO/DatagramSocket.swift`, `Sources/SwiftailMagicsock/Magicsock*.swift`와 시험 | **M4 단위 3·4 병합 뒤**. 7a(`DatagramSocket`)는 M4 단위 4와 파일이 겹치지 않아 먼저, 7b(`Magicsock.rebind`)는 단위 4 병합 뒤 |
| M5-8 | 엔진·노드 통합(8a 엔진 b503d5f, 8b 노드 9f1ec00으로 끝남): `TailnetEngine.send`의 로컬 처리(동작 L), 응답기 설치, 상태 기계(동작 B), 설정 내기(동작 E), `TunnelDevice`·utun 읽기 루프, `setDefaultInterface`(동작 N), 상태 디렉터리 표·파일 보호(동작 P), 공개 API 모양(T1~T4), 기존 관문 시험의 사건 기다림 고치기 | `Sources/SwiftailEngine/TailnetEngine*.swift`, `Sources/Swiftail/*`, `Tests/SwiftailEngineTests/TailnetEngineTests.swift`, `Tests/SwiftailTests/*`, `Tests/SwiftailInteropTests/*`(사건 기다림만), `Sources/SwiftailControl/Client/NodeIdentityStore.swift`(보호 등급) | **M4 단위 4 병합 뒤**, M5-1~4·6·7 뒤. 가장 크다. 나눈다면 8a(엔진: 동작 L과 응답기 설치)와 8b(노드)로 나누고 8b는 8a 병합 뒤 빌드한다 |
| M5-9 | 관문 (가): `tailnet` 도구 명령 보강(필요하면), `TunnelTests.swift` | `Tools/interop/cmd/tailnet/*`, `Tests/SwiftailInteropTests/TunnelTests.swift` | 도구는 M4 단위 5 병합 뒤 언제든. Swift 시험은 M5-8 뒤 |
| M5-10 | 관문 (나): 시험용 터널 앱(T7) | `Tools/TunnelHarness/`(라이브러리 타깃 밖) | M5-8 뒤. 서명 결정(plan 9절) 뒤 |

순서: M5-0 → (M5-1, 2, 3, 4, 5, 6) M4와 병렬 → M4 단위 3·4 병합 → M5-7 → M5-8 → M5-9 → 다른 세션의 검토 → 총괄이 관문 (가)를 다시 돌림 → M5-10과 관문 (나) → 첫 사용처 교체(별도 승인). 대조 시험(자료를 읽는 시험)은 구현자와 다른 세션이 쓴다.
