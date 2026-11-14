import SwiftailBase
import SwiftailControl
import SwiftailDERP

/// tailcfg의 DERP 노드를 `DERPClient`가 연결할 서버로 바꾼다. 노드가 지역 연결을 열 때 쓴다.
///
/// 계약 `docs/contracts/SwiftailEngine.md` 노드 API 동작 3, `docs/protocol-notes/derp-stun.md` 4.1.
extension DERPServer {
    /// 지역의 노드 가운데 연결할 수 있는 서버들(DERPMap의 순서대로). 지역이 없거나 쓸 수 있는 노드가 없으면 빈 목록.
    static func servers(of region: DERPRegion?) -> [DERPServer] {
        region?.nodes.compactMap(DERPServer.init) ?? []
    }

    /// tailcfg의 DERP 노드 하나를 연결할 서버로 바꾼다. 이 노드로 연결할 수 없으면 nil.
    ///
    /// - `stunOnly` 노드, 빈 `hostName`, 범위 밖 `derpPort`는 쓰지 않는다.
    /// - 연결 주소: `ipv4`가 IPv4 주소면 그 주소, 비었으면 `hostName`을 DNS로 찾는다. 그 밖의 값(관례상 `"none"`)이면
    ///   `ipv6`를 같은 규칙으로 본다. 둘 다 쓸 수 없으면 nil.
    /// - 포트: `derpPort`가 0이면 443.
    /// - 인증서: `insecureForTests`면 검증하지 않는다.
    // shortcut: `certName`이 `hostName`과 다른 노드(`sha256-raw:` 고정 포함)는 `DERPClient`가 아직 다루지 못하므로 건너뛴다.
    // Go는 IPv4와 IPv6를 함께 시도해 먼저 붙는 쪽을 쓴다(노트 4.1 2). 여기서는 주소 하나만 고른다. 운영 DERP 전(M4)에 넣는다.
    init?(_ node: DERPNode) {
        guard !node.stunOnly, !node.hostName.isEmpty,
              node.certName.isEmpty || node.certName == node.hostName
        else { return nil }
        guard let port = node.derpPort == 0 ? 443 : UInt16(exactly: node.derpPort) else { return nil }
        let address: IPAddress?
        switch (Self.dialChoice(node.ipv4, isIPv4: true), Self.dialChoice(node.ipv6, isIPv4: false)) {
        case let (.use(chosen), _): address = chosen
        case (.unusable, let .use(chosen)): address = chosen
        case (.unusable, .unusable): return nil
        }
        self.init(
            hostName: node.hostName,
            address: address,
            port: port,
            verification: node.insecureForTests ? .noneForTests : .system
        )
    }

    /// `DERPNode`의 `IPv4`·`IPv6` 필드 하나가 연결에 무엇을 뜻하는가.
    private enum DialChoice {
        /// 이 주소로 연결한다. nil이면 `hostName`을 DNS로 찾는다.
        case use(IPAddress?)
        /// 이 주소 종류는 쓰지 않는다.
        case unusable
    }

    private static func dialChoice(_ text: String, isIPv4: Bool) -> DialChoice {
        if text.isEmpty { return .use(nil) }
        guard let address = IPAddress(text), address.isIPv4 == isIPv4 else { return .unusable }
        return .use(address)
    }
}
