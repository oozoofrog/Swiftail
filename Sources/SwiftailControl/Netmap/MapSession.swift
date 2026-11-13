import Foundation

/// 맵 스트림 하나의 상태. 응답을 받은 순서대로 적용해 netmap을 만든다.
///
/// 스트림의 첫 일반 응답이 전체 상태이고 그 뒤는 증분이다. 상태는 이 스트림에 묶인다. 스트림이 끊기면
/// 새 `MapSession`으로 전체 맵부터 다시 받는다(세션 재개는 하지 않는다. Go 클라이언트도 그렇다).
///
/// 입출력도 시계도 없는 값이다. 피어가 "지금 보였다"(`PeerSeenChange` true)는 증분의 "지금"은
/// 서버가 마지막으로 알린 `ControlTime`이다. 아직 받지 못했으면 마지막 온라인 시각을 그대로 둔다.
///
/// 적용 순서와 규칙은 Go 클라이언트의 `mapSession`과 같다.
/// `docs/protocol-notes/control-map.md` 4.3 (출처: tailscale.com `control/controlclient/map.go`
/// `updateStateFromResponse`, `updatePeersStateFromResponse`, `netmap`, BSD-3-Clause).
public struct MapSession: Sendable {
    /// 응답 하나를 적용한 결과.
    public struct Update: Sendable {
        /// 이 응답으로 바뀐 뒤의 netmap. KeepAlive처럼 바뀐 것이 없으면 nil.
        public var netmap: Netmap?
        /// 서버가 답을 요구한 핑. 호출하는 쪽이 처리한다.
        public var pingRequest: PingRequest?
    }

    private var selfNode: Node?
    private var peers: [Int64: Node] = [:]
    /// 받은 프로필 전부. 지우지 않는다. netmap에는 쓰이는 것만 고른다.
    private var userProfiles: [Int64: UserProfile] = [:]
    private var derpMap: DERPMap?
    private var dnsConfig: DNSConfig?
    /// 이름 → 규칙 묶음. `PacketFilter`는 이름 `base`로 들어온다.
    private var namedPacketFilters: [String: [FilterRule]] = [:]
    private var domain = ""
    private var tkaInfo: TKAInfo?
    private var controlTime: Date?

    public init() {}

    /// 응답 하나를 적용한다. 스트림의 첫 일반 응답에 `node`가 없으면 `missingSelfNode`를 던진다.
    /// 그 뒤로는 이 세션과 스트림을 버려야 한다.
    public mutating func apply(_ response: MapResponse) throws(MapError) -> Update {
        if let time = response.controlTime {
            controlTime = time
        }
        // KeepAlive에서 유효한 것은 핑과 서버 시각뿐이다(노트 3.5, 4.3의 1).
        guard !response.keepAlive else {
            return Update(netmap: nil, pingRequest: response.pingRequest)
        }
        let currentSelf: Node
        if var node = response.node {
            // 옛 Capabilities 가운데 CapMap에 없는 것은 인자 없는 항목으로 합친다(노트 4.3의 2).
            for capability in node.capabilities where node.capMap[capability] == nil {
                node.capMap[capability] = []
            }
            currentSelf = node
        } else if let selfNode {
            currentSelf = selfNode
        } else {
            throw .missingSelfNode
        }

        selfNode = currentSelf
        applyPeerChanges(response)
        for profile in response.userProfiles ?? [] {
            userProfiles[profile.id] = profile
        }
        if let newMap = response.derpMap {
            derpMap = merged(newMap, over: derpMap)
        }
        applyPacketFilters(response)
        if let config = response.dnsConfig {
            dnsConfig = config
        }
        if !response.domain.isEmpty {
            domain = response.domain
        }
        if let info = response.tkaInfo {
            tkaInfo = info
        }
        return Update(netmap: netmap(selfNode: currentSelf), pingRequest: response.pingRequest)
    }

    /// 피어 저장소에 증분을 적용한다(노트 4.3의 3~5).
    private mutating func applyPeerChanges(_ response: MapResponse) {
        // 비어 있지 않은 전체 목록은 저장소를 바꾸고, 이 응답의 다른 피어 증분을 모두 배제한다.
        if let fullList = response.peers, !fullList.isEmpty {
            peers = Dictionary(fullList.map { ($0.id, $0) }, uniquingKeysWith: { _, last in last })
            return
        }
        for id in response.peersRemoved ?? [] {
            peers[id] = nil
        }
        for node in response.peersChanged ?? [] {
            peers[node.id] = node
        }
        for (id, seen) in response.peerSeenChange ?? [:] where peers[id] != nil {
            if !seen {
                peers[id]?.lastSeen = nil
            } else if let controlTime {
                peers[id]?.lastSeen = controlTime
            }
        }
        for (id, online) in response.onlineChange ?? [:] where peers[id] != nil {
            peers[id]?.online = online
        }
        for patch in response.peersChangedPatch ?? [] {
            guard var node = peers[patch.nodeID] else { continue }
            if patch.derpRegion != 0 { node.homeDERP = patch.derpRegion }
            if patch.cap != 0 { node.cap = patch.cap }
            if let endpoints = patch.endpoints { node.endpoints = endpoints }
            if let key = patch.key { node.key = key }
            if let discoKey = patch.discoKey { node.discoKey = discoKey }
            if let online = patch.online { node.online = online }
            if let lastSeen = patch.lastSeen { node.lastSeen = lastSeen }
            if let keyExpiry = patch.keyExpiry { node.keyExpiry = GoTime.nonZero(keyExpiry) }
            if let keySignature = patch.keySignature { node.keySignature = keySignature }
            if let capMap = patch.capMap { node.capMap = capMap }
            peers[patch.nodeID] = node
        }
    }

    /// DERP 지도의 부분 유지(노트 4.3의 8). 새 지도의 `nil` 하위 필드는 이전 값으로 채운다.
    private func merged(_ newMap: DERPMap, over oldMap: DERPMap?) -> DERPMap {
        guard let oldMap else { return newMap }
        var result = newMap
        if result.regions == nil {
            result.regions = oldMap.regions
            result.omitDefaultRegions = oldMap.omitDefaultRegions
        }
        if result.homeParams == nil {
            result.homeParams = oldMap.homeParams
        } else if result.homeParams?.regionScore == nil {
            result.homeParams?.regionScore = oldMap.homeParams?.regionScore
        }
        return result
    }

    /// 이름 붙은 패킷 필터 묶음의 증분(노트 4.3의 9).
    private mutating func applyPacketFilters(_ response: MapResponse) {
        if let base = response.packetFilter {
            namedPacketFilters["base"] = base
        }
        guard let changes = response.packetFilters else { return }
        // `"*": null`은 base를 포함한 모든 이름을 먼저 지운다. `"*": []`는 아무것도 하지 않는다.
        if changes["*"] == .some(nil) {
            namedPacketFilters = [:]
        }
        for (name, rules) in changes where name != "*" {
            namedPacketFilters[name] = rules
        }
    }

    /// 지금 상태의 netmap.
    private func netmap(selfNode: Node) -> Netmap {
        let sortedPeers = peers.values.sorted { $0.id < $1.id }

        // 프로필은 self와 피어의 소유자·공유자 것만 고른다(노트 4.3의 7). 0은 사용자가 아니다.
        var profiles: [Int64: UserProfile] = [:]
        for id in [selfNode.user] + sortedPeers.flatMap({ [$0.user, $0.sharer] }) where id != 0 {
            profiles[id] = userProfiles[id]
        }

        return Netmap(
            selfNode: selfNode,
            peers: sortedPeers,
            derpMap: derpMap,
            dnsConfig: dnsConfig,
            packetFilter: namedPacketFilters.keys.sorted().flatMap { namedPacketFilters[$0] ?? [] },
            userProfiles: profiles,
            domain: domain,
            // shortcut: Go는 Head가 AUM 해시로 해석되지 않으면 lock이 꺼졌다고 본다. 여기서는 해석하지 않고
            // 켜진 것으로 본다. lock을 구현하지 않는 쪽에서는 이것이 안전한 방향이다.
            tailnetLockEnabled: tkaInfo.map { !$0.disabled } ?? false,
            controlTime: controlTime
        )
    }
}
