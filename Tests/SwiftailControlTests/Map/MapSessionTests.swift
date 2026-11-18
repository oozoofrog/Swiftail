// At least one test for each delta application rule (docs/protocol-notes/control-map.md §4.3).
// The responses are handwritten JSON. The Go test server omits empty arrays, so it cannot represent the distinction between null, empty arrays, and omission (notes §6.2).

import Foundation
import SwiftailBase
import SwiftailTKA
import Testing

@testable import SwiftailControl

@Suite("Map session: Applying deltas")
struct MapSessionTests {
    /// A session with the first response containing the self node applied (extra begins with a comma, as in `,"Peers":[…]`).
    private func session(_ extra: String = "") throws -> MapSession {
        var session = MapSession()
        _ = try session.apply(mapResponse(#"{"Node":\#(selfNodeJSON)\#(extra)}"#), receivedAt: receivedAt)
        return session
    }

    /// The netmap after applying the response. Returns current state even when the response changed nothing (in which case `apply` returns nil).
    private func apply(_ json: String, to session: inout MapSession) throws -> Netmap {
        _ = try session.apply(mapResponse(json), receivedAt: receivedAt)
        return try #require(session.netmap)
    }

    // MARK: Session start and KeepAlive

    @Test("No Node in the first regular response yields missingSelfNode, and KeepAlive can arrive earlier")
    func missingSelfNode() throws {
        var session = MapSession()
        #expect(try session.apply(mapResponse(#"{"KeepAlive":true}"#), receivedAt: receivedAt).netmap == nil)
        #expect(throws: MapError.missingSelfNode) { try session.apply(mapResponse(#"{"Peers":[\#(peerJSON(2))]}"#), receivedAt: receivedAt) }

        // From the second response onward, retain the previous Node when it is absent.
        var started = try self.session()
        let netmap = try apply(#"{"Domain":"tail0001.ts.net"}"#, to: &started)
        #expect(netmap.selfNode.id == 1)
        #expect(netmap.domain == "tail0001.ts.net")
    }

    @Test("KeepAlive forwards only a ping and emits no netmap. Other included fields are ignored")
    func keepAlive() throws {
        var session = try session(#","Peers":[\#(peerJSON(2))]"#)
        let update = try session.apply(mapResponse(#"{"KeepAlive":true,"PingRequest":{"URL":"https://control.example/ping/1","Types":""},"PeersRemoved":[2]}"#), receivedAt: receivedAt)
        #expect(update.netmap == nil)
        #expect(update.pingRequest?.url == "https://control.example/ping/1")
        #expect(try apply("{}", to: &session).peers.map(\.id) == [2])
    }

    @Test("Also forwards pings in regular responses")
    func pingOnRegularResponse() throws {
        var session = MapSession()
        let update = try session.apply(mapResponse(#"{"Node":\#(selfNodeJSON),"PingRequest":{"URL":"https://control.example/ping/2","URLIsNoise":true}}"#), receivedAt: receivedAt)
        #expect(update.netmap != nil)
        #expect(update.pingRequest?.urlIsNoise == true)
    }

    @Test("The self Node is replaced in full and legacy Capabilities merge into CapMap")
    func selfNode() throws {
        var session = try session()
        let netmap = try apply(#"{"Node":{"ID":1,"User":100,"Capabilities":["cap/a","cap/b"],"CapMap":{"cap/b":[1]}}}"#, to: &session)
        #expect(netmap.selfNode.capMap == ["cap/a": [], "cap/b": [.integer(1)]])
        #expect(netmap.selfNode.machineAuthorized == false)  // Does not fill in from previous values
        #expect(netmap.selfNode.addresses.isEmpty)
    }

    // MARK: Peers

    @Test("Nonempty Peers replaces the entire list and is sorted by ascending ID")
    func fullReplacement() throws {
        var session = try session(#","Peers":[\#(peerJSON(3)),\#(peerJSON(2))]"#)
        #expect(try apply("{}", to: &session).peers.map(\.id) == [2, 3])
        #expect(try apply(#"{"Peers":[\#(peerJSON(4)),\#(peerJSON(3))]}"#, to: &session).peers.map(\.id) == [3, 4])
    }

    @Test("A full Peers list discards all other peer deltas in the same response")
    func fullReplacementPrecludesDeltas() throws {
        var session = try session(#","Peers":[\#(peerJSON(2))]"#)
        let netmap = try apply(#"""
            {"Peers":[\#(peerJSON(2)),\#(peerJSON(3))],"PeersRemoved":[2],"PeersChanged":[\#(peerJSON(4))],
             "PeersChangedPatch":[{"NodeID":3,"Cap":99}],"OnlineChange":{"3":true},"PeerSeenChange":{"3":false}}
            """#, to: &session)
        #expect(netmap.peers.map(\.id) == [2, 3])
        #expect(netmap.peers[1].cap == 0)
        #expect(netmap.peers[1].online == nil)
    }

    @Test("Empty, null, or omitted Peers leaves existing peers in place")
    func emptyPeersKeeps() throws {
        var session = try session(#","Peers":[\#(peerJSON(2))]"#)
        for json in [#"{"Peers":[]}"#, #"{"Peers":null}"#, "{}"] {
            #expect(try apply(json, to: &session).peers.map(\.id) == [2], "\(json)")
        }
    }

    @Test("0 peers in the first response")
    func noPeersInitially() throws {
        var session = MapSession()
        #expect(try apply(#"{"Node":\#(selfNodeJSON),"Peers":[]}"#, to: &session).peers.isEmpty)
    }

    @Test("PeersChanged adds peers and replaces entire objects")
    func peersChanged() throws {
        var session = try session(#","Peers":[\#(peerJSON(2, #","Online":true,"Tags":["tag:old"]"#))]"#)
        let netmap = try apply(#"{"PeersChanged":[\#(peerJSON(3)),\#(peerJSON(2, #","Cap":148"#))]}"#, to: &session)
        #expect(netmap.peers.map(\.id) == [2, 3])
        #expect(netmap.peers[0].cap == 148)
        #expect(netmap.peers[0].online == nil)   // Does not fill in from previous values
        #expect(netmap.peers[0].tags.isEmpty)
    }

    @Test("PeersRemoved ignores unknown IDs and removes even the last peer")
    func peersRemoved() throws {
        var session = try session(#","Peers":[\#(peerJSON(2)),\#(peerJSON(3))]"#)
        #expect(try apply(#"{"PeersRemoved":[3,99]}"#, to: &session).peers.map(\.id) == [2])
        #expect(try apply(#"{"PeersRemoved":[2]}"#, to: &session).peers.isEmpty)
        #expect(try apply(#"{"PeersChanged":[\#(peerJSON(2))]}"#, to: &session).peers.map(\.id) == [2])
    }

    @Test("When one response removes and changes the same peer, removal wins for changes converted to patches, while other changes restore the peer")
    func removedAndChangedTogether() throws {
        // Cap can be expressed as a patch. Go converts the change to a patch and applies it last, by which time the peer is gone.
        var session = try session(#","Peers":[\#(peerJSON(2))]"#)
        var netmap = try apply(#"{"PeersRemoved":[2],"PeersChanged":[\#(peerJSON(2, #","Cap":7"#))]}"#, to: &session)
        #expect(netmap.peers.isEmpty)

        // Tags cannot be expressed as a patch. Full replacement applies after removal, so the peer remains.
        session = try self.session(#","Peers":[\#(peerJSON(2))]"#)
        netmap = try apply(#"{"PeersRemoved":[2],"PeersChanged":[\#(peerJSON(2, #","Tags":["tag:server"]"#))]}"#, to: &session)
        #expect(netmap.peers.map(\.tags) == [["tag:server"]])
    }

    @Test("When multiple deltas affect the same peer in one response, use Go's order: removal, replacement, last seen time, online state, patch, then changes converted to patches")
    func overlappingDeltas() throws {
        let seen = "2026-01-01T00:00:00Z"
        let start = [
            peerJSON(2, #","Online":false"#), peerJSON(3, #","Online":true"#), peerJSON(4, #","HomeDERP":1,"Online":false"#),
            peerJSON(5, #","LastSeen":"\#(seen)""#), peerJSON(6),
        ].joined(separator: ",")
        var session = try session(#","Peers":[\#(start)]"#)
        let netmap = try apply(#"""
            {"PeersRemoved":[6],
             "PeersChanged":[\#(peerJSON(3, #","Tags":["tag:new"]"#)),\#(peerJSON(4, #","HomeDERP":3,"Online":true"#)),\#(peerJSON(6, #","Tags":["tag:back"]"#))],
             "PeerSeenChange":{"5":true,"6":false},
             "OnlineChange":{"2":true,"3":true,"4":false,"6":true},
             "PeersChangedPatch":[{"NodeID":2,"Online":false},{"NodeID":4,"DERPRegion":5},{"NodeID":5,"LastSeen":"\#(seen)"},{"NodeID":6,"Cap":9}]}
            """#, to: &session)
        #expect(netmap.peers.map(\.id) == [2, 3, 4, 5, 6])
        // 2: The patch follows OnlineChange.
        #expect(netmap.peers[0].online == false)
        // 3: OnlineChange applies over the fully replaced node, which has no Online field.
        #expect(netmap.peers[1].tags == ["tag:new"])
        #expect(netmap.peers[1].online == true)
        // 4: PeersChanged converted to a patch applies after the explicit patch and OnlineChange.
        #expect(netmap.peers[2].homeDERP == 3)
        #expect(netmap.peers[2].online == true)
        // 5: The patch's LastSeen follows PeerSeenChange.
        #expect(netmap.peers[3].lastSeen == GoTime.parse(seen))
        // 6: The last seen time, online state, and patch from the same response all apply to the node fully reinserted after removal.
        #expect(netmap.peers[4].tags == ["tag:back"])
        #expect(netmap.peers[4].lastSeen == nil)
        #expect(netmap.peers[4].online == true)
        #expect(netmap.peers[4].cap == 9)
    }

    @Test("A response with no changes emits no netmap. A change in server time alone does not count")
    func unchangedResponsesYieldNothing() throws {
        var session = try session(#","Peers":[\#(peerJSON(2))]"#)
        #expect(try session.apply(mapResponse(#"{"PeersChanged":[\#(peerJSON(2))]}"#), receivedAt: receivedAt).netmap == nil)
        #expect(try session.apply(mapResponse(#"{"ControlTime":"2026-01-02T03:04:05Z"}"#), receivedAt: receivedAt).netmap == nil)
        #expect(try session.apply(mapResponse(#"{"PeersRemoved":[2]}"#), receivedAt: receivedAt).netmap != nil)
    }

    @Test("OnlineChange uses the value as-is and ignores unknown IDs")
    func onlineChange() throws {
        var session = try session(#","Peers":[\#(peerJSON(2)),\#(peerJSON(3, #","Online":true"#))]"#)
        let netmap = try apply(#"{"OnlineChange":{"2":true,"3":false,"99":true}}"#, to: &session)
        #expect(netmap.peers.map(\.online) == [true, false])
        #expect(netmap.peers.map(\.id) == [2, 3])
    }

    @Test("For PeerSeenChange, false clears the value and true uses the receipt time, without removing the peer")
    func peerSeenChange() throws {
        let earlier = "2026-01-01T00:00:00Z"
        var session = try session(#","Peers":[\#(peerJSON(2, #","LastSeen":"\#(earlier)""#)),\#(peerJSON(3))]"#)

        // Uses the receipt time instead of the server's ControlTime, as the Go client does.
        let netmap = try apply(#"{"ControlTime":"2026-01-02T03:04:05Z","PeerSeenChange":{"2":false,"3":true,"99":false}}"#, to: &session)
        #expect(netmap.peers.map(\.id) == [2, 3])
        #expect(netmap.peers.map(\.lastSeen) == [nil, receivedAt])
    }

    // MARK: PeersChangedPatch

    @Test("A patch changes each field only if it has a value")
    func patchFields() throws {
        let original = peerJSON(2, #"""
            ,"Key":"\#(keyText("nodekey:", byte: 1))","DiscoKey":"\#(keyText("discokey:", byte: 1))","HomeDERP":1,"Cap":100,
            "Endpoints":["192.0.2.1:1"],"Online":true,"LastSeen":"2026-01-01T00:00:00Z","KeyExpiry":"2027-01-01T00:00:00Z",
            "KeySignature":"AQID","CapMap":{"cap/x":null}
            """#)
        var session = try session(#","Peers":[\#(original)]"#)
        let before = try apply("{}", to: &session).peers[0]

        // 0, null, and omission all mean "unchanged."
        var netmap = try apply(#"""
            {"PeersChangedPatch":[{"NodeID":2,"DERPRegion":0,"Cap":0,"Endpoints":null,"Key":null,"Online":null,"CapMap":null}]}
            """#, to: &session)
        #expect(netmap.peers[0] == before)

        netmap = try apply(#"""
            {"PeersChangedPatch":[{"NodeID":2,"DERPRegion":5,"Cap":148,"Endpoints":["198.51.100.1:2","[2001:db8::2]:3"],
             "Key":"\#(keyText("nodekey:", byte: 2))","DiscoKey":"\#(keyText("discokey:", byte: 2))","Online":false,
             "LastSeen":"2026-06-01T00:00:00Z","KeyExpiry":"2028-01-01T00:00:00Z","KeySignature":"BAU=","CapMap":{"cap/y":[]}}]}
            """#, to: &session)
        let peer = netmap.peers[0]
        #expect(peer.homeDERP == 5)
        #expect(peer.cap == 148)
        #expect(peer.endpoints.map(\.description) == ["198.51.100.1:2", "[2001:db8::2]:3"])
        #expect(peer.key.description == keyText("nodekey:", byte: 2))
        #expect(peer.discoKey.description == keyText("discokey:", byte: 2))
        #expect(peer.online == false)
        #expect(peer.lastSeen == GoTime.parse("2026-06-01T00:00:00Z"))
        #expect(peer.keyExpiry == GoTime.parse("2028-01-01T00:00:00Z"))
        #expect(peer.keySignature == [4, 5])
        #expect(peer.capMap == ["cap/y": []])
        // Fields untouched by the patch remain unchanged.
        #expect(peer.name == before.name && peer.addresses == before.addresses)
    }

    @Test("In a patch, empty Endpoints, CapMap, or KeySignature clears the field, and a KeyExpiry time of 0 means no expiration")
    func patchClears() throws {
        var session = try session(#","Peers":[\#(peerJSON(2, #","Endpoints":["192.0.2.1:1"],"KeyExpiry":"2027-01-01T00:00:00Z","KeySignature":"AQID","CapMap":{"cap/x":[]}"#))]"#)
        let peer = try apply(#"""
            {"PeersChangedPatch":[{"NodeID":2,"Endpoints":[],"CapMap":{},"KeySignature":"","KeyExpiry":"0001-01-01T00:00:00Z"}]}
            """#, to: &session).peers[0]
        #expect(peer.endpoints.isEmpty)
        #expect(peer.capMap.isEmpty)
        #expect(peer.keySignature.isEmpty)
        #expect(peer.keyExpiry == nil)
    }

    @Test("A patch ignores unknown NodeID values")
    func patchUnknownNode() throws {
        var session = try session(#","Peers":[\#(peerJSON(2))]"#)
        let netmap = try apply(#"{"PeersChangedPatch":[{"NodeID":99,"Cap":5},{"NodeID":2,"Cap":6}]}"#, to: &session)
        #expect(netmap.peers.map(\.id) == [2])
        #expect(netmap.peers[0].cap == 6)
    }

    @Test("For Online, the patch applies after OnlineChange")
    func patchAfterOnlineChange() throws {
        var session = try session(#","Peers":[\#(peerJSON(2))]"#)
        let netmap = try apply(#"{"OnlineChange":{"2":true},"PeersChangedPatch":[{"NodeID":2,"Online":false}]}"#, to: &session)
        #expect(netmap.peers[0].online == false)
    }

    // MARK: DERPMap

    private let derpRegions = #"{"1":{"RegionID":1,"RegionCode":"r1","Nodes":[]},"2":{"RegionID":2,"RegionCode":"r2","Nodes":[]}}"#

    @Test("For DERPMap, nil leaves it unchanged, null Regions leaves regions and omitDefaultRegions unchanged, and {} means no regions")
    func derpMapRegions() throws {
        var session = try session(#","DERPMap":{"Regions":\#(derpRegions),"omitDefaultRegions":true}"#)
        var netmap = try apply("{}", to: &session)
        #expect(netmap.derpMap?.regions?.keys.sorted() == [1, 2])

        netmap = try apply(#"{"DERPMap":{"Regions":null,"HomeParams":{"RegionScore":{"1":2.0}}}}"#, to: &session)
        #expect(netmap.derpMap?.regions?.keys.sorted() == [1, 2])
        #expect(netmap.derpMap?.omitDefaultRegions == true)
        #expect(netmap.derpMap?.homeParams?.regionScore == [1: 2.0])

        // New Regions also sets a new omitDefaultRegions value (false if omitted). This does not patch by region ID.
        netmap = try apply(#"{"DERPMap":{"Regions":{"3":{"RegionID":3,"Nodes":[]}}}}"#, to: &session)
        #expect(netmap.derpMap?.regions?.keys.sorted() == [3])
        #expect(netmap.derpMap?.omitDefaultRegions == false)

        netmap = try apply(#"{"DERPMap":{"Regions":{}}}"#, to: &session)
        #expect(netmap.derpMap?.regions?.isEmpty == true)
    }

    @Test("DERPMap discards null regions")
    func derpMapNullRegion() throws {
        var session = MapSession()
        let netmap = try apply(#"{"Node":\#(selfNodeJSON),"DERPMap":{"Regions":{"1":null,"2":{"RegionID":2,"Nodes":null}}}}"#, to: &session)
        #expect(netmap.derpMap?.regions?.keys.sorted() == [2])
        #expect(netmap.derpMap?.regions?[2]?.nodes.isEmpty == true)
    }

    @Test("For DERPMap, nil HomeParams leaves it unchanged, nil RegionScore leaves only scores unchanged, and {} resets scores")
    func derpHomeParams() throws {
        var session = try session(#","DERPMap":{"Regions":\#(derpRegions),"HomeParams":{"RegionScore":{"1":2.0,"2":0.5}}}"#)
        var netmap = try apply(#"{"DERPMap":{"Regions":null}}"#, to: &session)
        #expect(netmap.derpMap?.homeParams?.regionScore == [1: 2.0, 2: 0.5])

        netmap = try apply(#"{"DERPMap":{"Regions":null,"HomeParams":{}}}"#, to: &session)
        #expect(netmap.derpMap?.homeParams?.regionScore == [1: 2.0, 2: 0.5])

        netmap = try apply(#"{"DERPMap":{"Regions":null,"HomeParams":{"RegionScore":{}}}}"#, to: &session)
        #expect(netmap.derpMap?.homeParams?.regionScore?.isEmpty == true)
        #expect(netmap.derpMap?.regions?.keys.sorted() == [1, 2])
    }

    // MARK: DNS, Domain, profiles, tailnet lock, and time

    @Test("DNSConfig is replaced in full and nil leaves it unchanged")
    func dnsConfig() throws {
        var session = MapSession()
        #expect(try apply(#"{"Node":\#(selfNodeJSON)}"#, to: &session).dnsConfig == nil)
        var netmap = try apply(#"{"DNSConfig":{"Resolvers":[{"Addr":"192.0.2.53"}],"Domains":["tail0001.ts.net"],"Proxied":true}}"#, to: &session)
        #expect(netmap.dnsConfig?.resolvers.map(\.addr) == ["192.0.2.53"])

        netmap = try apply(#"{"DNSConfig":null}"#, to: &session)
        #expect(netmap.dnsConfig?.proxied == true)

        netmap = try apply(#"{"DNSConfig":{"Routes":{"corp.example":null,"tail0001.ts.net":[]}}}"#, to: &session)
        #expect(netmap.dnsConfig?.resolvers.isEmpty == true)
        #expect(netmap.dnsConfig?.proxied == false)
        #expect(netmap.dnsConfig?.routes == ["corp.example": [], "tail0001.ts.net": []])
    }

    @Test("An empty Domain string leaves it unchanged")
    func domain() throws {
        var session = try session(#","Domain":"tail0001.ts.net""#)
        #expect(try apply(#"{"Domain":""}"#, to: &session).domain == "tail0001.ts.net")
    }

    @Test("UserProfiles accumulate, and the netmap includes only the owners and sharers of self and peers")
    func userProfiles() throws {
        func profile(_ id: Int64) -> String { #"{"ID":\#(id),"LoginName":"user\#(id)@example.com","DisplayName":"U\#(id)"}"# }
        // 102 is a user with no peer yet. Only the profile arrives first.
        var session = try session(#","UserProfiles":[\#(profile(100)),\#(profile(102)),\#(profile(500))]"#)
        var netmap = try apply("{}", to: &session)
        #expect(netmap.userProfiles.keys.sorted() == [100])

        // When peer 2 (user 102) arrives later, the previously received profile is used. Empty UserProfiles removes nothing.
        netmap = try apply(#"{"PeersChanged":[\#(peerJSON(2))],"UserProfiles":[]}"#, to: &session)
        #expect(netmap.userProfiles.keys.sorted() == [100, 102])

        // The sharer's profile is also included. A profile update replaces the profile by ID.
        netmap = try apply(#"{"PeersChanged":[\#(peerJSON(3, #","Sharer":500"#))],"UserProfiles":[{"ID":102,"DisplayName":"new"}]}"#, to: &session)
        #expect(netmap.userProfiles.keys.sorted() == [100, 102, 500])
        #expect(netmap.userProfiles[102]?.displayName == "new")
        #expect(netmap.userProfiles[102]?.loginName == "")
    }

    @Test("Changing the self node's user switches the netmap profile to the new user, and the old profile stays in the session")
    func selfUserChange() throws {
        func profile(_ id: Int64) -> String { #"{"ID":\#(id),"DisplayName":"U\#(id)"}"# }
        var session = try session(#","Peers":[\#(peerJSON(2))],"UserProfiles":[\#(profile(100)),\#(profile(102)),\#(profile(200))]"#)
        #expect(try apply("{}", to: &session).userProfiles.keys.sorted() == [100, 102])

        let movedSelf = #"{"ID":1,"Name":"rd-mac-1a2b3c4d.tail0001.ts.net.","User":200,"Addresses":["100.64.0.1/32"]}"#
        #expect(try apply(#"{"Node":\#(movedSelf)}"#, to: &session).userProfiles.keys.sorted() == [102, 200])

        // Switching back uses the earlier profile even if the server does not resend it (as in Go lastUserProfile).
        #expect(try apply(#"{"Node":\#(selfNodeJSON)}"#, to: &session).userProfiles.keys.sorted() == [100, 102])
    }

    @Test("Changing a CapMap argument to a different integer near 2^53 also counts as a change")
    func largeIntegerCapMapChange() throws {
        var session = try session()
        let first = #"{"Node":{"ID":1,"User":100,"CapMap":{"cap/x":[9007199254740992]}}}"#
        let second = #"{"Node":{"ID":1,"User":100,"CapMap":{"cap/x":[9007199254740993]}}}"#
        #expect(try session.apply(mapResponse(first), receivedAt: receivedAt).netmap != nil)
        let netmap = try #require(try session.apply(mapResponse(second), receivedAt: receivedAt).netmap)
        #expect(netmap.selfNode.capMap["cap/x"] == [.integer(9_007_199_254_740_993)])
    }

    // MARK: Server-reported tailnet lock state (SwiftailTailnetLock contract behaviors N1 and O1, unit test 17)

    /// The resulting `serverLock` after applying the response and whether the response changed the netmap.
    private func serverLock(_ json: String, in session: inout MapSession) throws -> (lock: ServerLockState, netmapChanged: Bool) {
        let update = try session.apply(mapResponse(json), receivedAt: receivedAt)
        return (update.serverLock, update.netmap != nil)
    }

    /// Test head. The base32 text of a hash filled with one repeated byte.
    private func head(_ byte: UInt8) throws -> (hash: AUMHash, text: String) {
        let hash = try #require(AUMHash([UInt8](repeating: byte, count: 32)))
        return (hash, hash.text)
    }

    @Test("For serverLock, missing TKAInfo in the first response means disabled, presence gives enabled and a head, later omission leaves it unchanged, and Disabled means off")
    func serverLockFollowsTKAInfo() throws {
        let first = try head(0x11)
        var session = MapSession()
        #expect(try serverLock(#"{"Node":\#(selfNodeJSON)}"#, in: &session).lock == ServerLockState())

        var enabled = MapSession()
        let started = try serverLock(#"{"Node":\#(selfNodeJSON),"TKAInfo":{"Head":"\#(first.text)"}}"#, in: &enabled)
        #expect(started.lock == ServerLockState(isEnabled: true, head: first.hash))
        // A response that omits TKAInfo midstream means "no change," whether it changes other state, contains null, or is a KeepAlive.
        #expect(try serverLock(#"{"Domain":"tail0001.ts.net"}"#, in: &enabled).lock == started.lock)
        #expect(try serverLock(#"{"TKAInfo":null}"#, in: &enabled).lock == started.lock)
        #expect(try serverLock(#"{"KeepAlive":true}"#, in: &enabled).lock == started.lock)
        #expect(try serverLock("{}", in: &enabled).lock == started.lock)

        let disabled = try serverLock(#"{"TKAInfo":{"Disabled":true}}"#, in: &enabled)
        #expect(disabled.lock.isEnabled == false)
        // If a response reports disabled and carries a head, read that head (it determines whether to sync when the disablement secret is wrong).
        let both = try serverLock(#"{"TKAInfo":{"Head":"\#(first.text)","Disabled":true}}"#, in: &enabled)
        #expect(both.lock == ServerLockState(isEnabled: false, head: first.hash))
    }

    @Test("For serverLock, unreadable and empty Head mean enabled with an unknown head (contract §5, TL-11b item 3). Disabled means off")
    func serverLockHeadParsing() throws {
        for unreadable in ["AAAA", try head(0x11).text.lowercased(), try head(0x11).text + "A"] {
            var session = MapSession()
            let lock = try serverLock(#"{"Node":\#(selfNodeJSON),"TKAInfo":{"Head":"\#(unreadable)"}}"#, in: &session).lock
            #expect(lock == ServerLockState(isEnabled: true), "\(unreadable)")
            let disabled = try serverLock(#"{"TKAInfo":{"Head":"\#(unreadable)","Disabled":true}}"#, in: &session).lock
            #expect(disabled == ServerLockState(), "\(unreadable)")
        }
        var session = MapSession()
        #expect(try serverLock(#"{"Node":\#(selfNodeJSON),"TKAInfo":{}}"#, in: &session).lock == ServerLockState(isEnabled: true))
        #expect(try serverLock(#"{"TKAInfo":{"Head":""}}"#, in: &session).lock == ServerLockState(isEnabled: true))
    }

    @Test("serverLock carries the new Head even if the netmap is unchanged. The netmap itself does not carry lock state")
    func serverLockChangesWithoutNetmap() throws {
        let (first, second) = (try head(0x11), try head(0x22))
        var session = MapSession()
        let started = try serverLock(#"{"Node":\#(selfNodeJSON),"TKAInfo":{"Head":"\#(first.text)"}}"#, in: &session)
        #expect(started.netmapChanged)
        #expect(session.netmap?.tailnetLock == TailnetLockStatus(), "The unfiltered netmap carries the default lock state")

        let moved = try serverLock(#"{"TKAInfo":{"Head":"\#(second.text)"}}"#, in: &session)
        #expect(moved.lock == ServerLockState(isEnabled: true, head: second.hash))
        #expect(!moved.netmapChanged)
        // Text with a different last character denotes the same head if its 32 bytes match.
        let sameBytes = String(second.text.dropLast()) + "B"
        #expect(sameBytes != second.text)
        #expect(try serverLock(#"{"TKAInfo":{"Head":"\#(sameBytes)"}}"#, in: &session).lock == moved.lock)
    }

    @Test("ControlTime is recorded from KeepAlive too, and a time of 0 is ignored")
    func controlTime() throws {
        var session = try session()
        _ = try session.apply(mapResponse(#"{"KeepAlive":true,"ControlTime":"2026-01-02T03:04:05Z"}"#), receivedAt: receivedAt)
        #expect(try apply(#"{"ControlTime":"0001-01-01T00:00:00Z"}"#, to: &session).controlTime == GoTime.parse("2026-01-02T03:04:05Z"))
    }
}

@Suite("Map session: Packet filter")
struct PacketFilterTests {
    private func rule(_ source: String) -> String {
        #"{"SrcIPs":["\#(source)"],"DstPorts":[{"IP":"*","Ports":{"First":22,"Last":22}}]}"#
    }

    private func sources(_ netmap: Netmap) -> [String] {
        netmap.packetFilter.flatMap(\.srcIPs)
    }

    private func start(_ fields: String) throws -> MapSession {
        var session = MapSession()
        _ = try session.apply(mapResponse(#"{"Node":\#(selfNodeJSON)\#(fields)}"#), receivedAt: receivedAt)
        return session
    }

    /// The netmap after applying the response. Returns current state even when the response changed nothing (in which case `apply` returns nil).
    private func apply(_ json: String, to session: inout MapSession) throws -> Netmap {
        _ = try session.apply(mapResponse(json), receivedAt: receivedAt)
        return try #require(session.netmap)
    }

    @Test("For PacketFilter, null or omission leaves it unchanged and an empty array clears base (denies all)")
    func base() throws {
        var session = try start(#","PacketFilter":[\#(rule("100.64.0.2"))]"#)
        #expect(sources(try apply(#"{"PacketFilter":null}"#, to: &session)) == ["100.64.0.2"])
        #expect(sources(try apply("{}", to: &session)) == ["100.64.0.2"])
        #expect(try apply(#"{"PacketFilter":[]}"#, to: &session).packetFilter.isEmpty)
    }

    @Test("Named groups are concatenated in name order, and null removes only that name")
    func named() throws {
        var session = try start(#","PacketFilter":[\#(rule("base"))],"PacketFilters":{"z":[\#(rule("z"))],"a":[\#(rule("a"))]}"#)
        #expect(sources(try apply("{}", to: &session)) == ["a", "base", "z"])
        #expect(sources(try apply(#"{"PacketFilters":{"a":null,"m":[\#(rule("m"))]}}"#, to: &session)) == ["base", "m", "z"])
        // An empty array leaves that name present but empty.
        #expect(sources(try apply(#"{"PacketFilters":{"m":[]}}"#, to: &session)) == ["base", "z"])
        // An empty base alone leaves rules under other names in place.
        #expect(sources(try apply(#"{"PacketFilter":[]}"#, to: &session)) == ["z"])
        // An empty object changes nothing.
        #expect(sources(try apply(#"{"PacketFilters":{}}"#, to: &session)) == ["z"])
    }

    @Test(#""*": null removes all names including base before applying the rest"#)
    func wildcardReset() throws {
        var session = try start(#","PacketFilter":[\#(rule("base"))],"PacketFilters":{"a":[\#(rule("a"))]}"#)
        #expect(sources(try apply(#"{"PacketFilters":{"*":null,"b":[\#(rule("b"))]}}"#, to: &session)) == ["b"])
        // PacketFilter in the same response is applied first and then removed as well.
        #expect(sources(try apply(#"{"PacketFilter":[\#(rule("base2"))],"PacketFilters":{"*":null}}"#, to: &session)).isEmpty)
    }

    @Test(#""*": [] removes nothing"#)
    func wildcardEmptyArray() throws {
        var session = try start(#","PacketFilters":{"a":[\#(rule("a"))]}"#)
        #expect(sources(try apply(#"{"PacketFilters":{"*":[]}}"#, to: &session)) == ["a"])
    }
}
