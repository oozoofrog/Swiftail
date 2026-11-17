import SwiftailBase
import SwiftailControl
import SwiftailEngine
import SwiftailMagicsock

// `Swiftail`의 공개 선언에 나오는 다른 모듈의 타입. 앱이 `import Swiftail`만으로 그 이름을 쓰게 같은 타입을 별명으로
// 내보낸다. 그 타입의 공개 속성·연관 값에 나오는 타입(`IPPrefix`)도 함께 낸다. 중첩 타입(`TailnetLockStatus.Mode`)은
// 별명을 거쳐 그대로 쓰인다.
//
// 모듈을 다시 내보내지 않고 이름만 고른 까닭: `@_exported import`는 밑줄 붙은 비공식 기능이고, 모듈 전체(`Netmap`과
// tailcfg 모델, 키 타입, 제어 클라이언트)를 `Swiftail`의 표면으로 넓힌다. Swift 6의 `public import`(SE-0409)는 이름을
// 내보내지 않는다. 별명은 원래 타입과 같은 타입이라, 그 모듈을 함께 가져온 코드와 값을 그대로 주고받는다.
//
// 앱이 쓰지 않을 입력 쪽 선언(`TunnelNetworkSettings.init?(netmap:mtu:at:)`의 `Netmap`)은 내보내지 않는다.

/// IPv4·IPv6 주소. `NodeStatus.addresses`, `TailnetNode.whoIs(_:)`, `TunnelNetworkSettings.dnsServers`에 나온다.
public typealias IPAddress = SwiftailBase.IPAddress

/// 주소와 포트. `TailnetConnection.remoteEndpoint`·`localEndpoint`, `PeerPath.direct(_:)`에 나온다.
public typealias IPEndpoint = SwiftailBase.IPEndpoint

/// 주소 접두(CIDR). `TunnelNetworkSettings.addresses`·`routes`에 나온다.
public typealias IPPrefix = SwiftailBase.IPPrefix

/// 제어 클라이언트가 끝낸 실패. `NodeError.control(_:)`에 실린다.
public typealias ControlError = SwiftailControl.ControlError

/// tailnet lock의 모습. `NodeStatus.tailnetLock`, `NodeEvent.tailnetLockChanged(_:)`에 나온다.
public typealias TailnetLockStatus = SwiftailControl.TailnetLockStatus

/// 앱이 OS에 적용할 터널 설정. `TailnetNode.networkSettings`, `NodeStatus.networkSettings`에 나온다.
public typealias TunnelNetworkSettings = SwiftailEngine.TunnelNetworkSettings

/// 피어까지의 경로(직접·중계). `TailnetNode.path(toPeerNamed:)`, `NodeEvent.peerPathChanged(fqdn:path:)`에 나온다.
public typealias PeerPath = SwiftailMagicsock.PeerPath
