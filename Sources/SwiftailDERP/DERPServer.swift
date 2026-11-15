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
        /// 시스템 신뢰 저장소로 사슬을 검증하되 인증서의 이름은 이 값으로 본다. SNI와 HTTP `Host`는 그대로
        /// `hostName`이다. DERPMap의 `CertName`이 `HostName`과 다른 노드에 쓴다.
        case named(String)
        /// 서버가 낸 인증서 가운데 meta 인증서(주체 CN이 `derpkey`로 시작)를 뺀 것이 정확히 하나이고, 그 DER 전체의
        /// SHA-256을 소문자 16진으로 쓴 것이 이 값과 글자 그대로 같아야 한다. 그 인증서는 지금 유효 기간 안이고,
        /// `hostName`이 IP 리터럴이 아니면 그 이름에 유효해야 한다. 사슬은 검증하지 않는다. DERPMap의 `CertName`이
        /// `sha256-raw:<hex>`인 노드(자체 서명 derper)에 쓴다.
        case pinned(sha256Hex: String)
        /// 검증하지 않는다. DERPMap이 `InsecureForTests`인 노드에만 쓴다.
        case noneForTests
    }

    // shortcut: fast-start(meta 인증서의 서버 키로 업그레이드 응답을 기다리지 않는 것)는 하지 않는다. 필요해지는 시점:
    // DERP 연결 시간의 왕복 하나가 문제가 될 때.
    public init(hostName: String, targets: [Target] = [.hostName], port: UInt16 = 443, verification: Verification = .system) {
        self.hostName = hostName
        self.targets = targets
        self.port = port
        self.verification = verification
    }
}
