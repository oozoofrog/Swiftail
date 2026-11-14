import SwiftailBase
import SwiftailControl
import SwiftailDERP

/// 홈 DERP 지역과 그 지역에 닿는 서버들. 이 노드는 홈 지역의 DERP 서버 하나에 붙어 패킷을 받는다.
///
/// 고르는 일은 입출력 없는 순수 함수다. `TailnetNode`가 netmap을 받을 때마다 부르고, 결과가 바뀌면 DERP 클라이언트를
/// 다시 띄운다.
///
/// `docs/contracts/SwiftailEngine.md` 노드 API 동작 3, `docs/protocol-notes/derp-stun.md` 4.1·4.8.
// shortcut: 지역별 지연을 재지 않고 ID가 가장 작은 지역을 고정으로 고른다. 지역도 하나만 쓴다. netcheck와 다중 지역은
// M4(`SwiftailMagicsock`)다. Go도 측정 결과가 없으면 측정 없이 지역 하나를 고른다(노트 4.8 1).
struct DERPHome: Sendable, Equatable {
    var regionID: Int64
    /// 앞에서부터 시도할 서버들. 비어 있지 않다.
    var servers: [DERPServer]

    /// DERPMap에서 홈 지역을 고른다.
    ///
    /// 지금 홈(`current`)을 계속 쓸 수 있으면 그대로 두고 서버 목록만 새로 읽는다. 아니면(처음이거나 그 지역이 사라졌거나
    /// 쓸 수 없게 되었으면) 쓸 수 있는 지역 가운데 ID가 가장 작은 것을 고른다. 쓸 수 있는 지역은
    /// `noMeasureNoHome`이 아니고 쓸 수 있는 서버가 하나 이상인 지역이다. 그런 지역이 없으면 nil.
    ///
    /// - Parameter current: 지금 홈 지역 ID. 0이면 아직 없다.
    static func choose(from derpMap: DERPMap?, keeping current: Int64) -> DERPHome? {
        let regions = derpMap?.regions ?? [:]
        if let region = regions[current], let home = DERPHome(regionID: current, region: region) {
            return home
        }
        return regions.keys.sorted().lazy.compactMap { id in regions[id].flatMap { DERPHome(regionID: id, region: $0) } }.first
    }

    /// 지역을 홈으로 쓸 수 있으면 만든다.
    private init?(regionID: Int64, region: DERPRegion) {
        let servers = region.nodes.compactMap(DERPServer.init)
        guard !region.noMeasureNoHome, !servers.isEmpty else { return nil }
        self.regionID = regionID
        self.servers = servers
    }
}

extension DERPServer {
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
