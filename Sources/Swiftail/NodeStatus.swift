import SwiftailBase
import SwiftailControl
import SwiftailEngine

/// 지금 노드의 모습. 앱의 상태 화면과 진단이 `TailnetNode.status`로 읽는다. 키는 담지 않는다.
public struct NodeStatus: Sendable, Equatable {
    public var state: NodeState
    /// 자기 tailnet 주소(netmap 자기 노드의 `Addresses` 가운데 한 주소짜리). netmap 전에는 비어 있다.
    public var addresses: [IPAddress]
    /// 자기 MagicDNS 이름에서 끝의 점을 뗀 것(`rd-phone-1a2b3c4d.tail0001.ts.net`). netmap 전이나 이름이 없으면 nil.
    public var fqdn: String?
    /// 자기 노드의 `StableID`. netmap 전이나 비어 있으면 nil.
    public var stableID: String?
    /// ts.net 인증서를 받을 수 있는 이름(netmap `DNSConfig.CertDomains`). 읽어 보여 주기만 한다.
    public var certDomains: [String]
    /// netmap의 피어 수.
    public var peerCount: Int
    /// 마지막으로 `TailnetNode.networkSettings`에 낸 설정. 아직 내지 않았으면 nil.
    public var networkSettings: TunnelNetworkSettings?

    /// 마지막 netmap에서 읽는다.
    init(state: NodeState, netmap: Netmap?, networkSettings: TunnelNetworkSettings?) {
        self.state = state
        addresses = netmap?.selfNode.addresses
            .filter { $0.length == $0.address.bytes.count * 8 }
            .map(\.address) ?? []
        let name = netmap?.selfNode.name ?? ""
        let trimmed = name.hasSuffix(".") ? String(name.dropLast()) : name
        fqdn = trimmed.isEmpty ? nil : trimmed
        stableID = netmap.flatMap { $0.selfNode.stableID.isEmpty ? nil : $0.selfNode.stableID }
        certDomains = netmap?.dnsConfig?.certDomains ?? []
        peerCount = netmap?.peers.count ?? 0
        self.networkSettings = networkSettings
    }
}
