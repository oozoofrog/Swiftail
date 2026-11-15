import Foundation

/// 맵 스트림 하나의 상태. 응답을 받은 순서대로 적용해 netmap을 만든다.
///
/// 스트림의 첫 일반 응답이 전체 상태이고 그 뒤는 증분이다. 상태는 이 스트림에 묶인다. 스트림이 끊기면
/// 새 `MapSession`으로 전체 맵부터 다시 받는다(세션 재개는 하지 않는다. Go 클라이언트도 그렇다).
///
/// 입출력도 시계도 없는 값이다. 피어가 "지금 보였다"(`PeerSeenChange` true)는 증분에 필요한 "지금"은
/// 호출하는 쪽이 응답을 받은 시각으로 넘긴다.
///
/// 여기서 나오는 netmap은 **tailnet lock으로 거르기 전**의 것이다(`tailnetLock`은 기본값). 서버가 알린 lock 상태는
/// `Update.serverLock`으로 따로 내고, 검증과 거르기는 `ControlClient`가 한다.
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
        /// 서버가 알린 tailnet lock 상태의 지금 값. netmap이 바뀌지 않은 응답에도 싣는다: 머리만 바뀐 응답은 netmap을
        /// 바꾸지 않지만 동기화의 계기다(계약 `docs/contracts/SwiftailTailnetLock.md` 동작 N1).
        package var serverLock = ServerLockState()
    }

    /// 세션이 쥐는 피어의 최대 수. 목표 규모(피어 10,000명)의 두 배다.
    static let maximumPeerCount = 20_000
    /// 세션이 쥐는 사용자 프로필의 최대 수. 피어마다 소유자와 공유자가 있으므로 피어 한도의 두 배다.
    static let maximumUserProfileCount = 2 * maximumPeerCount
    /// 이름 붙은 패킷 필터 묶음의 최대 수. Go 제어 서버는 `base`를 포함해 몇 개의 이름만 쓴다.
    static let maximumPacketFilterNameCount = 256
    /// 모든 이름 붙은 패킷 필터 묶음의 규칙 수 합의 최대. 노드 하나가 받는 ACL 규칙은 많아야 수천 개다.
    static let maximumPacketFilterRuleCount = 50_000

    /// 한도를 넘어 끝난 세션의 오류. 있으면 상태를 비운 채 같은 오류를 낸다.
    private var failure: MapError?
    private var selfNode: Node?
    private var peers: [Int64: Node] = [:]
    /// 받은 프로필 전부. 지우지 않는다(Go `lastUserProfile`도 지우지 않는다. 다시 나타난 피어의 프로필을
    /// 서버가 다시 보내지 않기 때문이다). 개수 한도를 넘으면 세션을 끝낸다. netmap에는 쓰이는 것만 고른다.
    private var userProfiles: [Int64: UserProfile] = [:]
    private var derpMap: DERPMap?
    private var dnsConfig: DNSConfig?
    /// 이름 → 규칙 묶음. `PacketFilter`는 이름 `base`로 들어온다.
    private var namedPacketFilters: [String: [FilterRule]] = [:]
    private var domain = ""
    private var tkaInfo: TKAInfo?
    private var controlTime: Date?
    /// 지금의 netmap. 응답이 아무것도 바꾸지 않았는지 가리는 데 쓴다.
    private(set) var netmap: Netmap?

    public init() {}

    /// 응답 하나를 적용한다. 스트림의 첫 일반 응답에 `node`가 없으면 `missingSelfNode`를 던진다.
    /// 피어·사용자 프로필·이름 붙은 패킷 필터(이름 수와 규칙 수)가 한도를 넘으면 상태를 비우고
    /// `stateTooLarge`를 던지며, 그 뒤의 호출도 같은 오류를 낸다. 어느 오류든 이 세션과 스트림을 버리고
    /// 새 스트림으로 전체 맵부터 다시 받아야 한다.
    ///
    /// - Parameter now: 이 응답을 받은 시각. "지금 보였다"는 증분의 마지막 온라인 시각이 된다.
    public mutating func apply(_ response: MapResponse, receivedAt now: Date) throws(MapError) -> Update {
        if let failure { throw failure }
        if let time = response.controlTime {
            controlTime = time
        }
        // KeepAlive에서 유효한 것은 핑과 서버 시각뿐이다(노트 3.5, 4.3의 1).
        guard !response.keepAlive else {
            return Update(netmap: nil, pingRequest: response.pingRequest, serverLock: serverLock)
        }
        // 상태 필드가 없는 응답은 netmap을 다시 만들지 않는다. 바뀌는 것은 서버 시각뿐이다.
        if netmap != nil, !response.carriesState {
            netmap?.controlTime = controlTime
            return Update(netmap: nil, pingRequest: response.pingRequest, serverLock: serverLock)
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
        applyPeerChanges(response, receivedAt: now)
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
        guard peers.count <= Self.maximumPeerCount,
              userProfiles.count <= Self.maximumUserProfileCount,
              namedPacketFilters.count <= Self.maximumPacketFilterNameCount,
              namedPacketFilters.values.reduce(0, { $0 + $1.count }) <= Self.maximumPacketFilterRuleCount
        else {
            self = MapSession()
            failure = .stateTooLarge
            throw .stateTooLarge
        }
        // 서버 시각은 응답마다 바뀐다. 그것만 다른 netmap은 변화로 치지 않는다.
        let previous = netmap
        let current = makeNetmap(selfNode: currentSelf)
        netmap = current
        let ignoringControlTime = { (map: Netmap?) in var copy = map; copy?.controlTime = nil; return copy }
        let changed = ignoringControlTime(current) != ignoringControlTime(previous)
        return Update(netmap: changed ? current : nil, pingRequest: response.pingRequest, serverLock: serverLock)
    }

    /// 서버가 알린 lock 상태. 이 세션에서 `TKAInfo`를 받기 전에는 꺼진 것이고, `TKAInfo`가 없는 응답은 바꾸지 않는다
    /// (동작 N1·O1).
    private var serverLock: ServerLockState { ServerLockState(tkaInfo) }

    /// 피어 저장소에 증분을 적용한다(노트 4.3의 3~5).
    private mutating func applyPeerChanges(_ response: MapResponse, receivedAt now: Date) {
        // 비어 있지 않은 전체 목록은 저장소를 바꾸고, 이 응답의 다른 피어 증분을 모두 배제한다.
        if let fullList = response.peers, !fullList.isEmpty {
            peers = Dictionary(fullList.map { ($0.id, $0) }, uniquingKeysWith: { _, last in last })
            return
        }
        // Go 클라이언트는 PeersChanged의 노드가 기존 노드와 "patch로 표현되는 필드"에서만 다르면 통째로
        // 바꾸지 않고 그 차이를 patch로 옮겨 맨 뒤에 적용한다(map.go `patchifyPeersChanged`). 결과가
        // 갈리는 것은 한 응답이 같은 피어를 지우면서 바꾸는 경우 정도지만(지우기가 이긴다) 같은 결과를 낸다.
        let before = peers
        var deferred: [(was: Node, new: Node)] = []
        for id in response.peersRemoved ?? [] {
            peers[id] = nil
        }
        for node in response.peersChanged ?? [] {
            if let was = before[node.id], was.withoutPatchableFields == node.withoutPatchableFields {
                deferred.append((was, node))
            } else {
                peers[node.id] = node
            }
        }
        for (id, seen) in response.peerSeenChange ?? [:] where peers[id] != nil {
            peers[id]?.lastSeen = seen ? now : nil
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
        for (was, new) in deferred {
            peers[new.id]?.applyPatchableDifferences(from: was, to: new)
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
    private func makeNetmap(selfNode: Node) -> Netmap {
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
            controlTime: controlTime
        )
    }
}

extension MapResponse {
    /// 세션 상태를 바꿀 수 있는 필드가 하나라도 있다. 서버 시각·핑·빈 `Peers`·빈 `Domain`만 있는 응답은 false다.
    /// `MapSession.apply`가 쓰는 필드를 더하면 여기에도 더한다.
    fileprivate var carriesState: Bool {
        node != nil || derpMap != nil || !(peers ?? []).isEmpty || peersChanged != nil || peersRemoved != nil
            || peersChangedPatch != nil || peerSeenChange != nil || onlineChange != nil || dnsConfig != nil
            || !domain.isEmpty || packetFilter != nil || packetFilters != nil || userProfiles != nil || tkaInfo != nil
    }
}

extension Node {
    /// patch(`PeerChange`)로 표현되는 필드를 비운 사본. 두 노드가 이 사본에서 같으면 둘의 차이는 patch로 옮길 수 있다.
    fileprivate var withoutPatchableFields: Node {
        var copy = self
        copy.key = .zero
        copy.keyExpiry = nil
        copy.keySignature = []
        copy.discoKey = .zero
        copy.endpoints = []
        copy.homeDERP = 0
        copy.cap = 0
        copy.capMap = [:]
        copy.online = nil
        copy.lastSeen = nil
        return copy
    }

    /// was에서 new로 바뀐 patch 대상 필드만 이 노드에 옮긴다(map.go `peerChangeDiff`).
    fileprivate mutating func applyPatchableDifferences(from was: Node, to new: Node) {
        if new.key != was.key { key = new.key }
        if new.keyExpiry != was.keyExpiry { keyExpiry = new.keyExpiry }
        if new.keySignature != was.keySignature { keySignature = new.keySignature }
        if new.discoKey != was.discoKey { discoKey = new.discoKey }
        if new.endpoints != was.endpoints { endpoints = new.endpoints }
        // patch에서 0은 "바꾸지 않음"이다. 0으로 되돌리는 변화는 patch로 옮겨지지 않는다.
        if new.homeDERP != was.homeDERP, new.homeDERP != 0 { homeDERP = new.homeDERP }
        if new.cap != was.cap, new.cap != 0 { cap = new.cap }
        if new.capMap != was.capMap { capMap = new.capMap }
        // 온라인 여부와 마지막 온라인 시각은 양쪽 모두 값이 있을 때만 patch가 된다.
        if let wasOnline = was.online, let newOnline = new.online, wasOnline != newOnline { online = newOnline }
        if let wasSeen = was.lastSeen, let newSeen = new.lastSeen, wasSeen != newSeen { lastSeen = newSeen }
    }
}
