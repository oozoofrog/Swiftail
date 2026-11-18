import Foundation

/// The state of one map stream. Applies responses in arrival order to build a netmap.
///
/// The first regular response contains the full state, and later responses are deltas. The state belongs to this stream. After a disconnect,
/// a new `MapSession` receives the full map again. Session resumption is unused, as in the Go client.
///
/// A value with no I/O or clock. The caller supplies the response receipt time as "now" for peer seen-now
/// deltas (`PeerSeenChange` true).
///
/// The netmap produced here is **before tailnet lock filtering** (`tailnetLock` has its default value). The server's reported lock state is emitted separately in
/// `Update.serverLock`. `ControlClient` verifies and filters.
///
/// Applies updates in the same order and by the same rules as the Go client's `mapSession`.
/// `docs/protocol-notes/control-map.md` §4.3 (origin: tailscale.com `control/controlclient/map.go`
/// `updateStateFromResponse`, `updatePeersStateFromResponse`, `netmap`, BSD-3-Clause).
public struct MapSession: Sendable {
    /// The result of applying one response.
    public struct Update: Sendable {
        /// The netmap after applying this response. Nil if nothing changed, as with KeepAlive.
        public var netmap: Netmap?
        /// A ping the server requested a reply to. The caller handles it.
        public var pingRequest: PingRequest?
        /// The current tailnet lock state reported by the server. Included even when the netmap stays the same. A head-only response
        /// leaves the netmap unchanged and still triggers synchronization (contract `docs/contracts/SwiftailTailnetLock.md` behavior N1).
        package var serverLock = ServerLockState()
        /// Whether this was a non-KeepAlive map response, even if the netmap stayed the same. This triggers retrying a failed tailnet lock procedure.
        /// Go runs the procedure for every map response (behavior N5).
        package var isMapResponse = false
    }

    /// The maximum number of peers the session retains. Twice the target scale of 10,000 peers.
    static let maximumPeerCount = 20_000
    /// The maximum number of user profiles the session retains. Twice the peer limit, since peers have an owner and a sharer.
    static let maximumUserProfileCount = 2 * maximumPeerCount
    /// The maximum number of named packet filter groups. The Go control server uses only a few names, including `base`.
    static let maximumPacketFilterNameCount = 256
    /// The maximum total rule count across all named packet filter groups. One node receives at most a few thousand ACL rules.
    static let maximumPacketFilterRuleCount = 50_000

    /// The error for a session that ended after exceeding a limit. While it is present, state stays empty and calls yield the same error.
    private var failure: MapError?
    private var selfNode: Node?
    private var peers: [Int64: Node] = [:]
    /// All received profiles. Keeps them indefinitely, as Go's `lastUserProfile` does, because the server does not resend the profile of a peer
    /// that reappears. Ends the session if the count exceeds the limit. Includes only profiles in use in the netmap.
    private var userProfiles: [Int64: UserProfile] = [:]
    private var derpMap: DERPMap?
    private var dnsConfig: DNSConfig?
    /// Name → rule group. `PacketFilter` arrives under the name `base`.
    private var namedPacketFilters: [String: [FilterRule]] = [:]
    private var domain = ""
    private var tkaInfo: TKAInfo?
    private var controlTime: Date?
    /// The current netmap, used to detect responses that leave it unchanged.
    private(set) var netmap: Netmap?

    public init() {}

    /// Applies one response. Throws `missingSelfNode` if the first regular response in the stream lacks `node`.
    /// If peers, user profiles, or named packet filters (count of names or rules) exceed a limit, clears state and
    /// throws `stateTooLarge`. Subsequent calls yield the same error. On either error, discard the session and stream
    /// and start again with a full map from a new stream.
    ///
    /// - Parameter now: The time this response was received. Becomes the last online time for a seen-now delta.
    public mutating func apply(_ response: MapResponse, receivedAt now: Date) throws(MapError) -> Update {
        if let failure { throw failure }
        if let time = response.controlTime {
            controlTime = time
        }
        // Only pings and server time are effective in KeepAlive (notes §3.5, §4.3 item 1).
        guard !response.keepAlive else {
            return Update(netmap: nil, pingRequest: response.pingRequest, serverLock: serverLock)
        }
        // A response with no state fields leaves the netmap in place. Only server time changes.
        if netmap != nil, !response.carriesState {
            netmap?.controlTime = controlTime
            return Update(netmap: nil, pingRequest: response.pingRequest, serverLock: serverLock)
        }
        let currentSelf: Node
        if var node = response.node {
            // Merge legacy Capabilities missing from CapMap as entries with no arguments (notes §4.3, item 2).
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
        // Server time changes with every response. A netmap that differs only in server time does not count as changed.
        let previous = netmap
        let current = makeNetmap(selfNode: currentSelf)
        netmap = current
        let ignoringControlTime = { (map: Netmap?) in var copy = map; copy?.controlTime = nil; return copy }
        let changed = ignoringControlTime(current) != ignoringControlTime(previous)
        return Update(
            netmap: changed ? current : nil, pingRequest: response.pingRequest, serverLock: serverLock, isMapResponse: true)
    }

    /// The lock state reported by the server. Disabled until the first `TKAInfo` in this session. Responses without `TKAInfo` leave the state unchanged
    /// (behaviors N1 and O1).
    private var serverLock: ServerLockState { ServerLockState(tkaInfo) }

    /// Applies deltas to the peer store (notes §4.3, items 3~5).
    private mutating func applyPeerChanges(_ response: MapResponse, receivedAt now: Date) {
        // A nonempty full list replaces the store and takes precedence over all other peer deltas in this response.
        if let fullList = response.peers, !fullList.isEmpty {
            peers = Dictionary(fullList.map { ($0.id, $0) }, uniquingKeysWith: { _, last in last })
            return
        }
        // When a PeersChanged node differs from an existing node only in fields expressible as a patch, the Go client converts
        // the difference into a patch and applies it last, avoiding whole-node replacement (map.go `patchifyPeersChanged`). A potential
        // difference would be one response removing and updating the same peer (removal wins), but this yields the same result.
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

    /// Retains parts of the DERP map (notes §4.3, item 8). Fills `nil` subfields in the new map with their previous values.
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

    /// A delta for named packet filter groups (notes §4.3, item 9).
    private mutating func applyPacketFilters(_ response: MapResponse) {
        if let base = response.packetFilter {
            namedPacketFilters["base"] = base
        }
        guard let changes = response.packetFilters else { return }
        // `"*": null` clears all names first, including base. `"*": []` does nothing.
        if changes["*"] == .some(nil) {
            namedPacketFilters = [:]
        }
        for (name, rules) in changes where name != "*" {
            namedPacketFilters[name] = rules
        }
    }

    /// The netmap for the current state.
    private func makeNetmap(selfNode: Node) -> Netmap {
        let sortedPeers = peers.values.sorted { $0.id < $1.id }

        // Select profiles only for owners and sharers of self and the peers (notes §4.3, item 7). 0 denotes no user.
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
    /// Whether there is at least one field that can change session state. A response with only server time, a ping, empty `Peers`, or empty `Domain` yields false.
    /// When adding fields used by `MapSession.apply`, add them here as well.
    fileprivate var carriesState: Bool {
        node != nil || derpMap != nil || !(peers ?? []).isEmpty || peersChanged != nil || peersRemoved != nil
            || peersChangedPatch != nil || peerSeenChange != nil || onlineChange != nil || dnsConfig != nil
            || !domain.isEmpty || packetFilter != nil || packetFilters != nil || userProfiles != nil || tkaInfo != nil
    }
}

extension Node {
    /// A copy with the fields expressible as a patch (`PeerChange`) cleared. If two nodes have equal copies, their differences can become a patch.
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

    /// Copies only patchable fields that changed from was to new into this node (map.go `peerChangeDiff`).
    fileprivate mutating func applyPatchableDifferences(from was: Node, to new: Node) {
        if new.key != was.key { key = new.key }
        if new.keyExpiry != was.keyExpiry { keyExpiry = new.keyExpiry }
        if new.keySignature != was.keySignature { keySignature = new.keySignature }
        if new.discoKey != was.discoKey { discoKey = new.discoKey }
        if new.endpoints != was.endpoints { endpoints = new.endpoints }
        // Zero in a patch means unchanged. A change back to 0 cannot be represented in a patch.
        if new.homeDERP != was.homeDERP, new.homeDERP != 0 { homeDERP = new.homeDERP }
        if new.cap != was.cap, new.cap != 0 { cap = new.cap }
        if new.capMap != was.capMap { capMap = new.capMap }
        // Online status and last online time become patch fields only when both sides have a value.
        if let wasOnline = was.online, let newOnline = new.online, wasOnline != newOnline { online = newOnline }
        if let wasSeen = was.lastSeen, let newSeen = new.lastSeen, wasSeen != newSeen { lastSeen = newSeen }
    }
}
