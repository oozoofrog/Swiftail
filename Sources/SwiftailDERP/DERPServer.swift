import SwiftailBase

/// DERP 서버 하나에 닿는 방법. 엔진이 `tailcfg.DERPNode`에서 뽑는다.
///
/// 한 지역에는 서버가 여럿일 수 있다. `DERPClient`는 앞에서부터 TCP로 시도해 처음 붙는 곳을 쓴다
/// (`docs/protocol-notes/derp-stun.md` 4.1절). 서버 하나 안에서는 `targets`를 함께 걸어 먼저 붙는 쪽을 쓴다.
public struct DERPServer: Sendable, Equatable {
    /// TLS 서버 이름이자 HTTP `Host`.
    public var hostName: String
    /// 연결을 걸 곳들. `DERPClient`가 모두 함께 걸어 먼저 붙는 연결을 쓰고 나머지는 닫는다.
    ///
    /// 엔진은 노드의 IPv4·IPv6 칸마다 많아야 하나씩, 같은 것을 두 번 넣지 않고 담는다(두 칸 모두 비었으면
    /// `hostName` 하나). 비어 있으면 이 서버에는 붙을 수 없다.
    public var targets: [Target]
    public var port: UInt16
    public var verification: Verification

    /// 연결을 걸 곳 하나.
    public enum Target: Sendable, Equatable {
        /// `hostName`을 DNS로 찾아 건다. 찾은 주소 가운데 어느 쪽으로 걸지는 Network 프레임워크가 고른다.
        case hostName
        /// 이 IP 주소로 건다.
        case address(IPAddress)
    }

    /// 서버 인증서를 어떻게 확인하는가.
    public enum Verification: Sendable, Equatable {
        /// 시스템 신뢰 저장소로 `hostName`을 검증한다.
        case system
        /// 검증하지 않는다. DERPMap이 `InsecureForTests`인 노드에만 쓴다.
        case noneForTests
    }

    // shortcut: fast-start, `sha256-raw:` 인증서 고정, `CertName`이 `HostName`과 다른 경우는 다루지 않는다. 운영
    // DERP와 맺기 전(M4 마무리 관문)에 넣는다. 그때까지 엔진이 이런 노드로는 `DERPServer`를 만들지 않고 건너뛴다.
    public init(hostName: String, targets: [Target] = [.hostName], port: UInt16 = 443, verification: Verification = .system) {
        self.hostName = hostName
        self.targets = targets
        self.port = port
        self.verification = verification
    }
}
