// 걸 대상의 규칙은 tailscale.com v1.104.7 `derp/derphttp/derphttp_client.go`의 `shouldDialProto`·`dialNode`를 따랐다
// (Copyright (c) Tailscale Inc & AUTHORS, BSD-3-Clause).

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
    /// - 걸 대상(Go `shouldDialProto`): `ipv4`·`ipv6` 칸마다, 비었으면 `hostName`, 그 칸의 주소 체계의 IP 리터럴이면 그
    ///   주소, 그 밖의 값(관례상 `"none"`, 다른 체계의 주소, 쓰레기)이면 그 체계로는 걸지 않는다. 두 칸이 모두
    ///   `hostName`이면 대상은 `hostName` 하나다(Network 프레임워크가 이름을 풀어 두 체계를 스스로 시도한다). 걸 대상이
    ///   없으면 nil.
    /// - 포트: `derpPort`가 0이면 443.
    /// - 인증서: `insecureForTests`면 검증하지 않는다.
    // shortcut: `certName`이 `hostName`과 다른 노드(`sha256-raw:` 고정 포함)는 `DERPClient`가 아직 다루지 못하므로 건너뛴다.
    // shortcut: Go는 빈 칸을 그 체계로만 푼다(`tcp4`·`tcp6`). 여기서는 `hostName`을 체계 구분 없이 걸므로, 한 칸만 비고
    // 다른 칸이 `"none"`이어도 막힌 체계로 걸 수 있다. 필요해지는 시점: 한 체계를 일부러 막은 DERPMap을 쓸 때.
    init?(_ node: DERPNode) {
        guard !node.stunOnly, !node.hostName.isEmpty,
              node.certName.isEmpty || node.certName == node.hostName
        else { return nil }
        guard let port = node.derpPort == 0 ? 443 : UInt16(exactly: node.derpPort) else { return nil }
        var targets: [Target] = []
        for target in [Self.target(node.ipv4, isIPv4: true), Self.target(node.ipv6, isIPv4: false)] {
            if let target, !targets.contains(target) { targets.append(target) }
        }
        guard !targets.isEmpty else { return nil }
        self.init(
            hostName: node.hostName,
            targets: targets,
            port: port,
            verification: node.insecureForTests ? .noneForTests : .system
        )
    }

    /// `DERPNode`의 `IPv4`·`IPv6` 칸 하나가 뜻하는 대상. 이 체계로 걸지 않으면 nil.
    private static func target(_ text: String, isIPv4: Bool) -> Target? {
        if text.isEmpty { return .hostName }
        guard let address = IPAddress(text), address.isIPv4 == isIPv4 else { return nil }
        return .address(address)
    }
}
