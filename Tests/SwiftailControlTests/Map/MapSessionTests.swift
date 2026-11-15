// 증분 적용 규칙(docs/protocol-notes/control-map.md 4.3)마다 하나 이상의 시험.
// 응답은 직접 쓴 JSON이다. Go의 시험 서버는 빈 배열을 생략해 버려서 "null·빈 배열·생략"의 차이를 만들지 못한다(노트 6.2).

import Foundation
import SwiftailBase
import SwiftailTKA
import Testing

@testable import SwiftailControl

@Suite("맵 세션: 증분 적용")
struct MapSessionTests {
    /// self 노드가 든 첫 응답(extra는 `,"Peers":[…]`처럼 쉼표로 시작)을 적용한 세션.
    private func session(_ extra: String = "") throws -> MapSession {
        var session = MapSession()
        _ = try session.apply(mapResponse(#"{"Node":\#(selfNodeJSON)\#(extra)}"#), receivedAt: receivedAt)
        return session
    }

    /// 응답을 적용한 뒤의 netmap. 응답이 아무것도 바꾸지 않았어도(이때 `apply`는 nil을 낸다) 지금 상태를 돌려준다.
    private func apply(_ json: String, to session: inout MapSession) throws -> Netmap {
        _ = try session.apply(mapResponse(json), receivedAt: receivedAt)
        return try #require(session.netmap)
    }

    // MARK: 세션의 시작과 KeepAlive

    @Test("첫 일반 응답에 Node가 없으면 missingSelfNode, KeepAlive는 그 전에 와도 된다")
    func missingSelfNode() throws {
        var session = MapSession()
        #expect(try session.apply(mapResponse(#"{"KeepAlive":true}"#), receivedAt: receivedAt).netmap == nil)
        #expect(throws: MapError.missingSelfNode) { try session.apply(mapResponse(#"{"Peers":[\#(peerJSON(2))]}"#), receivedAt: receivedAt) }

        // 두 번째 응답부터는 Node가 없어도 이전 것을 쓴다.
        var started = try self.session()
        let netmap = try apply(#"{"Domain":"tail0001.ts.net"}"#, to: &started)
        #expect(netmap.selfNode.id == 1)
        #expect(netmap.domain == "tail0001.ts.net")
    }

    @Test("KeepAlive는 netmap을 내지 않고 핑만 전한다. 다른 필드가 실려도 적용하지 않는다")
    func keepAlive() throws {
        var session = try session(#","Peers":[\#(peerJSON(2))]"#)
        let update = try session.apply(mapResponse(#"{"KeepAlive":true,"PingRequest":{"URL":"https://control.example/ping/1","Types":""},"PeersRemoved":[2]}"#), receivedAt: receivedAt)
        #expect(update.netmap == nil)
        #expect(update.pingRequest?.url == "https://control.example/ping/1")
        #expect(try apply("{}", to: &session).peers.map(\.id) == [2])
    }

    @Test("일반 응답의 핑도 전한다")
    func pingOnRegularResponse() throws {
        var session = MapSession()
        let update = try session.apply(mapResponse(#"{"Node":\#(selfNodeJSON),"PingRequest":{"URL":"https://control.example/ping/2","URLIsNoise":true}}"#), receivedAt: receivedAt)
        #expect(update.netmap != nil)
        #expect(update.pingRequest?.urlIsNoise == true)
    }

    @Test("self Node는 통째로 바뀌고 옛 Capabilities는 CapMap에 합쳐진다")
    func selfNode() throws {
        var session = try session()
        let netmap = try apply(#"{"Node":{"ID":1,"User":100,"Capabilities":["cap/a","cap/b"],"CapMap":{"cap/b":[1]}}}"#, to: &session)
        #expect(netmap.selfNode.capMap == ["cap/a": [], "cap/b": [.integer(1)]])
        #expect(netmap.selfNode.machineAuthorized == false)  // 이전 값으로 메우지 않는다
        #expect(netmap.selfNode.addresses.isEmpty)
    }

    // MARK: 피어

    @Test("비어 있지 않은 Peers는 전체 교체이고 ID 오름차순이다")
    func fullReplacement() throws {
        var session = try session(#","Peers":[\#(peerJSON(3)),\#(peerJSON(2))]"#)
        #expect(try apply("{}", to: &session).peers.map(\.id) == [2, 3])
        #expect(try apply(#"{"Peers":[\#(peerJSON(4)),\#(peerJSON(3))]}"#, to: &session).peers.map(\.id) == [3, 4])
    }

    @Test("전체 Peers가 오면 같은 응답의 다른 피어 증분은 모두 버린다")
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

    @Test("Peers의 빈 배열·null·생략은 기존 피어를 지우지 않는다")
    func emptyPeersKeeps() throws {
        var session = try session(#","Peers":[\#(peerJSON(2))]"#)
        for json in [#"{"Peers":[]}"#, #"{"Peers":null}"#, "{}"] {
            #expect(try apply(json, to: &session).peers.map(\.id) == [2], "\(json)")
        }
    }

    @Test("첫 응답의 피어 0명")
    func noPeersInitially() throws {
        var session = MapSession()
        #expect(try apply(#"{"Node":\#(selfNodeJSON),"Peers":[]}"#, to: &session).peers.isEmpty)
    }

    @Test("PeersChanged는 추가와 객체 전체 교체다")
    func peersChanged() throws {
        var session = try session(#","Peers":[\#(peerJSON(2, #","Online":true,"Tags":["tag:old"]"#))]"#)
        let netmap = try apply(#"{"PeersChanged":[\#(peerJSON(3)),\#(peerJSON(2, #","Cap":148"#))]}"#, to: &session)
        #expect(netmap.peers.map(\.id) == [2, 3])
        #expect(netmap.peers[0].cap == 148)
        #expect(netmap.peers[0].online == nil)   // 이전 값으로 메우지 않는다
        #expect(netmap.peers[0].tags.isEmpty)
    }

    @Test("PeersRemoved: 모르는 ID는 무시하고, 마지막 피어도 지운다")
    func peersRemoved() throws {
        var session = try session(#","Peers":[\#(peerJSON(2)),\#(peerJSON(3))]"#)
        #expect(try apply(#"{"PeersRemoved":[3,99]}"#, to: &session).peers.map(\.id) == [2])
        #expect(try apply(#"{"PeersRemoved":[2]}"#, to: &session).peers.isEmpty)
        #expect(try apply(#"{"PeersChanged":[\#(peerJSON(2))]}"#, to: &session).peers.map(\.id) == [2])
    }

    @Test("한 응답이 같은 피어를 지우면서 바꾸면: patch로 옮겨지는 변화는 지우기가 이기고, 그 밖의 변화는 되살린다")
    func removedAndChangedTogether() throws {
        // Cap은 patch로 표현되는 필드다. Go는 이 변화를 patch로 옮겨 맨 뒤에 적용하는데, 그때 피어는 이미 없다.
        var session = try session(#","Peers":[\#(peerJSON(2))]"#)
        var netmap = try apply(#"{"PeersRemoved":[2],"PeersChanged":[\#(peerJSON(2, #","Cap":7"#))]}"#, to: &session)
        #expect(netmap.peers.isEmpty)

        // 태그는 patch로 표현되지 않는다. 통째로 바꾸는 변화는 지운 뒤에 적용되어 피어가 남는다.
        session = try self.session(#","Peers":[\#(peerJSON(2))]"#)
        netmap = try apply(#"{"PeersRemoved":[2],"PeersChanged":[\#(peerJSON(2, #","Tags":["tag:server"]"#))]}"#, to: &session)
        #expect(netmap.peers.map(\.tags) == [["tag:server"]])
    }

    @Test("한 응답의 여러 증분이 같은 피어에 겹치면 Go 순서를 따른다: 지우기, 바꾸기, 본 시각, 온라인, patch, patch로 옮긴 바꾸기")
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
        // 2: OnlineChange 뒤에 patch가 온다.
        #expect(netmap.peers[0].online == false)
        // 3: 통째로 바뀐 노드(Online 없음)에 OnlineChange가 얹힌다.
        #expect(netmap.peers[1].tags == ["tag:new"])
        #expect(netmap.peers[1].online == true)
        // 4: patch로 옮겨진 PeersChanged는 명시한 patch와 OnlineChange보다 뒤에 적용된다.
        #expect(netmap.peers[2].homeDERP == 3)
        #expect(netmap.peers[2].online == true)
        // 5: PeerSeenChange 뒤에 patch의 LastSeen이 온다.
        #expect(netmap.peers[3].lastSeen == GoTime.parse(seen))
        // 6: 지운 뒤 통째로 다시 들어온 노드에 같은 응답의 본 시각·온라인·patch가 모두 얹힌다.
        #expect(netmap.peers[4].tags == ["tag:back"])
        #expect(netmap.peers[4].lastSeen == nil)
        #expect(netmap.peers[4].online == true)
        #expect(netmap.peers[4].cap == 9)
    }

    @Test("바뀐 것이 없는 응답은 netmap을 내지 않는다. 서버 시각만 바뀐 것도 변화가 아니다")
    func unchangedResponsesYieldNothing() throws {
        var session = try session(#","Peers":[\#(peerJSON(2))]"#)
        #expect(try session.apply(mapResponse(#"{"PeersChanged":[\#(peerJSON(2))]}"#), receivedAt: receivedAt).netmap == nil)
        #expect(try session.apply(mapResponse(#"{"ControlTime":"2026-01-02T03:04:05Z"}"#), receivedAt: receivedAt).netmap == nil)
        #expect(try session.apply(mapResponse(#"{"PeersRemoved":[2]}"#), receivedAt: receivedAt).netmap != nil)
    }

    @Test("OnlineChange는 값 그대로, 모르는 ID는 무시")
    func onlineChange() throws {
        var session = try session(#","Peers":[\#(peerJSON(2)),\#(peerJSON(3, #","Online":true"#))]"#)
        let netmap = try apply(#"{"OnlineChange":{"2":true,"3":false,"99":true}}"#, to: &session)
        #expect(netmap.peers.map(\.online) == [true, false])
        #expect(netmap.peers.map(\.id) == [2, 3])
    }

    @Test("PeerSeenChange: false는 지우기, true는 응답을 받은 시각, 피어는 지우지 않는다")
    func peerSeenChange() throws {
        let earlier = "2026-01-01T00:00:00Z"
        var session = try session(#","Peers":[\#(peerJSON(2, #","LastSeen":"\#(earlier)""#)),\#(peerJSON(3))]"#)

        // 서버의 ControlTime이 아니라 받은 시각을 쓴다(Go 클라이언트와 같다).
        let netmap = try apply(#"{"ControlTime":"2026-01-02T03:04:05Z","PeerSeenChange":{"2":false,"3":true,"99":false}}"#, to: &session)
        #expect(netmap.peers.map(\.id) == [2, 3])
        #expect(netmap.peers.map(\.lastSeen) == [nil, receivedAt])
    }

    // MARK: PeersChangedPatch

    @Test("patch: 각 필드는 값이 있을 때만 바뀐다")
    func patchFields() throws {
        let original = peerJSON(2, #"""
            ,"Key":"\#(keyText("nodekey:", byte: 1))","DiscoKey":"\#(keyText("discokey:", byte: 1))","HomeDERP":1,"Cap":100,
            "Endpoints":["192.0.2.1:1"],"Online":true,"LastSeen":"2026-01-01T00:00:00Z","KeyExpiry":"2027-01-01T00:00:00Z",
            "KeySignature":"AQID","CapMap":{"cap/x":null}
            """#)
        var session = try session(#","Peers":[\#(original)]"#)
        let before = try apply("{}", to: &session).peers[0]

        // 0·null·생략은 모두 "그대로"다.
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
        // patch가 건드리지 않는 필드는 그대로다.
        #expect(peer.name == before.name && peer.addresses == before.addresses)
    }

    @Test("patch: 빈 Endpoints·CapMap·KeySignature는 비우기, 0 시각 KeyExpiry는 만료 없음")
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

    @Test("patch: 모르는 NodeID는 무시한다")
    func patchUnknownNode() throws {
        var session = try session(#","Peers":[\#(peerJSON(2))]"#)
        let netmap = try apply(#"{"PeersChangedPatch":[{"NodeID":99,"Cap":5},{"NodeID":2,"Cap":6}]}"#, to: &session)
        #expect(netmap.peers.map(\.id) == [2])
        #expect(netmap.peers[0].cap == 6)
    }

    @Test("Online은 OnlineChange 다음에 patch가 적용된다")
    func patchAfterOnlineChange() throws {
        var session = try session(#","Peers":[\#(peerJSON(2))]"#)
        let netmap = try apply(#"{"OnlineChange":{"2":true},"PeersChangedPatch":[{"NodeID":2,"Online":false}]}"#, to: &session)
        #expect(netmap.peers[0].online == false)
    }

    // MARK: DERPMap

    private let derpRegions = #"{"1":{"RegionID":1,"RegionCode":"r1","Nodes":[]},"2":{"RegionID":2,"RegionCode":"r2","Nodes":[]}}"#

    @Test("DERPMap: nil은 그대로, Regions null은 지역과 omitDefaultRegions를 그대로, {}는 지역 없음")
    func derpMapRegions() throws {
        var session = try session(#","DERPMap":{"Regions":\#(derpRegions),"omitDefaultRegions":true}"#)
        var netmap = try apply("{}", to: &session)
        #expect(netmap.derpMap?.regions?.keys.sorted() == [1, 2])

        netmap = try apply(#"{"DERPMap":{"Regions":null,"HomeParams":{"RegionScore":{"1":2.0}}}}"#, to: &session)
        #expect(netmap.derpMap?.regions?.keys.sorted() == [1, 2])
        #expect(netmap.derpMap?.omitDefaultRegions == true)
        #expect(netmap.derpMap?.homeParams?.regionScore == [1: 2.0])

        // 새 Regions가 오면 omitDefaultRegions도 새 값(생략이면 false)이다. 지역 ID별 patch가 아니다.
        netmap = try apply(#"{"DERPMap":{"Regions":{"3":{"RegionID":3,"Nodes":[]}}}}"#, to: &session)
        #expect(netmap.derpMap?.regions?.keys.sorted() == [3])
        #expect(netmap.derpMap?.omitDefaultRegions == false)

        netmap = try apply(#"{"DERPMap":{"Regions":{}}}"#, to: &session)
        #expect(netmap.derpMap?.regions?.isEmpty == true)
    }

    @Test("DERPMap: null인 지역은 버린다")
    func derpMapNullRegion() throws {
        var session = MapSession()
        let netmap = try apply(#"{"Node":\#(selfNodeJSON),"DERPMap":{"Regions":{"1":null,"2":{"RegionID":2,"Nodes":null}}}}"#, to: &session)
        #expect(netmap.derpMap?.regions?.keys.sorted() == [2])
        #expect(netmap.derpMap?.regions?[2]?.nodes.isEmpty == true)
    }

    @Test("DERPMap: HomeParams nil은 그대로, RegionScore nil은 점수만 그대로, {}는 점수 초기화")
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

    // MARK: DNS, Domain, 프로필, tailnet lock, 시각

    @Test("DNSConfig는 통째로 바뀌고 nil이면 그대로다")
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

    @Test("Domain의 빈 문자열은 그대로")
    func domain() throws {
        var session = try session(#","Domain":"tail0001.ts.net""#)
        #expect(try apply(#"{"Domain":""}"#, to: &session).domain == "tail0001.ts.net")
    }

    @Test("UserProfiles는 누적되고, netmap에는 self와 피어의 소유자·공유자 것만 나온다")
    func userProfiles() throws {
        func profile(_ id: Int64) -> String { #"{"ID":\#(id),"LoginName":"user\#(id)@example.com","DisplayName":"U\#(id)"}"# }
        // 102는 아직 피어가 없는 사용자다. 프로필만 먼저 온다.
        var session = try session(#","UserProfiles":[\#(profile(100)),\#(profile(102)),\#(profile(500))]"#)
        var netmap = try apply("{}", to: &session)
        #expect(netmap.userProfiles.keys.sorted() == [100])

        // 피어 2(사용자 102)가 나중에 오면 이전에 받은 프로필이 쓰인다. 빈 UserProfiles는 아무것도 지우지 않는다.
        netmap = try apply(#"{"PeersChanged":[\#(peerJSON(2))],"UserProfiles":[]}"#, to: &session)
        #expect(netmap.userProfiles.keys.sorted() == [100, 102])

        // 공유자의 프로필도 나온다. 프로필 갱신은 ID별 교체다.
        netmap = try apply(#"{"PeersChanged":[\#(peerJSON(3, #","Sharer":500"#))],"UserProfiles":[{"ID":102,"DisplayName":"new"}]}"#, to: &session)
        #expect(netmap.userProfiles.keys.sorted() == [100, 102, 500])
        #expect(netmap.userProfiles[102]?.displayName == "new")
        #expect(netmap.userProfiles[102]?.loginName == "")
    }

    @Test("self 노드의 사용자가 바뀌면 netmap의 프로필도 새 사용자 것으로 바뀌고, 옛 프로필은 세션에 남는다")
    func selfUserChange() throws {
        func profile(_ id: Int64) -> String { #"{"ID":\#(id),"DisplayName":"U\#(id)"}"# }
        var session = try session(#","Peers":[\#(peerJSON(2))],"UserProfiles":[\#(profile(100)),\#(profile(102)),\#(profile(200))]"#)
        #expect(try apply("{}", to: &session).userProfiles.keys.sorted() == [100, 102])

        let movedSelf = #"{"ID":1,"Name":"rd-mac-1a2b3c4d.tail0001.ts.net.","User":200,"Addresses":["100.64.0.1/32"]}"#
        #expect(try apply(#"{"Node":\#(movedSelf)}"#, to: &session).userProfiles.keys.sorted() == [102, 200])

        // 되돌아가면 서버가 프로필을 다시 보내지 않아도 이전에 받은 것이 쓰인다(Go lastUserProfile과 같다).
        #expect(try apply(#"{"Node":\#(selfNodeJSON)}"#, to: &session).userProfiles.keys.sorted() == [100, 102])
    }

    @Test("CapMap 인자가 2^53 근처의 다른 정수로 바뀌어도 변화로 친다")
    func largeIntegerCapMapChange() throws {
        var session = try session()
        let first = #"{"Node":{"ID":1,"User":100,"CapMap":{"cap/x":[9007199254740992]}}}"#
        let second = #"{"Node":{"ID":1,"User":100,"CapMap":{"cap/x":[9007199254740993]}}}"#
        #expect(try session.apply(mapResponse(first), receivedAt: receivedAt).netmap != nil)
        let netmap = try #require(try session.apply(mapResponse(second), receivedAt: receivedAt).netmap)
        #expect(netmap.selfNode.capMap["cap/x"] == [.integer(9_007_199_254_740_993)])
    }

    // MARK: 서버가 알린 tailnet lock 상태 (계약 SwiftailTailnetLock 동작 N1·O1, 단위 시험 17)

    /// 응답을 적용한 결과의 `serverLock`과, 그 응답이 netmap을 바꿨는지.
    private func serverLock(_ json: String, in session: inout MapSession) throws -> (lock: ServerLockState, netmapChanged: Bool) {
        let update = try session.apply(mapResponse(json), receivedAt: receivedAt)
        return (update.serverLock, update.netmap != nil)
    }

    /// 시험용 머리. 바이트 하나로 채운 해시의 base32 텍스트다.
    private func head(_ byte: UInt8) throws -> (hash: AUMHash, text: String) {
        let hash = try #require(AUMHash([UInt8](repeating: byte, count: 32)))
        return (hash, hash.text)
    }

    @Test("serverLock: 첫 응답에 TKAInfo가 없으면 꺼짐, 있으면 켜짐과 머리, 도중에 빠지면 그대로, Disabled면 꺼짐")
    func serverLockFollowsTKAInfo() throws {
        let first = try head(0x11)
        var session = MapSession()
        #expect(try serverLock(#"{"Node":\#(selfNodeJSON)}"#, in: &session).lock == ServerLockState())

        var enabled = MapSession()
        let started = try serverLock(#"{"Node":\#(selfNodeJSON),"TKAInfo":{"Head":"\#(first.text)"}}"#, in: &enabled)
        #expect(started.lock == ServerLockState(isEnabled: true, head: first.hash))
        // 도중에 TKAInfo가 빠진 응답은 "변화 없음"이다: 상태를 바꾸는 응답이든, null이든, KeepAlive든.
        #expect(try serverLock(#"{"Domain":"tail0001.ts.net"}"#, in: &enabled).lock == started.lock)
        #expect(try serverLock(#"{"TKAInfo":null}"#, in: &enabled).lock == started.lock)
        #expect(try serverLock(#"{"KeepAlive":true}"#, in: &enabled).lock == started.lock)
        #expect(try serverLock("{}", in: &enabled).lock == started.lock)

        let disabled = try serverLock(#"{"TKAInfo":{"Disabled":true}}"#, in: &enabled)
        #expect(disabled.lock.isEnabled == false)
        // 꺼졌다는 응답에 머리가 실려 있으면 그 머리는 읽는다(끄기 비밀이 틀렸을 때 동기화할지를 정한다).
        let both = try serverLock(#"{"TKAInfo":{"Head":"\#(first.text)","Disabled":true}}"#, in: &enabled)
        #expect(both.lock == ServerLockState(isEnabled: false, head: first.hash))
    }

    @Test("serverLock: 읽히지 않는 Head는 꺼짐, 빈 Head는 켜짐이고 머리 없음")
    func serverLockHeadParsing() throws {
        for unreadable in ["AAAA", try head(0x11).text.lowercased(), try head(0x11).text + "A"] {
            var session = MapSession()
            let lock = try serverLock(#"{"Node":\#(selfNodeJSON),"TKAInfo":{"Head":"\#(unreadable)"}}"#, in: &session).lock
            #expect(lock == ServerLockState(), "\(unreadable)")
        }
        var session = MapSession()
        #expect(try serverLock(#"{"Node":\#(selfNodeJSON),"TKAInfo":{}}"#, in: &session).lock == ServerLockState(isEnabled: true))
        #expect(try serverLock(#"{"TKAInfo":{"Head":""}}"#, in: &session).lock == ServerLockState(isEnabled: true))
    }

    @Test("serverLock: netmap은 그대로인데 Head만 바뀌어도 새 값을 싣는다. netmap 자체는 lock을 담지 않는다")
    func serverLockChangesWithoutNetmap() throws {
        let (first, second) = (try head(0x11), try head(0x22))
        var session = MapSession()
        let started = try serverLock(#"{"Node":\#(selfNodeJSON),"TKAInfo":{"Head":"\#(first.text)"}}"#, in: &session)
        #expect(started.netmapChanged)
        #expect(session.netmap?.tailnetLock == TailnetLockStatus(), "거르기 전의 netmap은 lock의 기본값을 싣는다")

        let moved = try serverLock(#"{"TKAInfo":{"Head":"\#(second.text)"}}"#, in: &session)
        #expect(moved.lock == ServerLockState(isEnabled: true, head: second.hash))
        #expect(!moved.netmapChanged)
        // 텍스트의 끝 글자가 달라도 같은 32바이트면 같은 머리다.
        let sameBytes = String(second.text.dropLast()) + "B"
        #expect(sameBytes != second.text)
        #expect(try serverLock(#"{"TKAInfo":{"Head":"\#(sameBytes)"}}"#, in: &session).lock == moved.lock)
    }

    @Test("ControlTime: KeepAlive의 것도 기록하고, 0 시각은 무시한다")
    func controlTime() throws {
        var session = try session()
        _ = try session.apply(mapResponse(#"{"KeepAlive":true,"ControlTime":"2026-01-02T03:04:05Z"}"#), receivedAt: receivedAt)
        #expect(try apply(#"{"ControlTime":"0001-01-01T00:00:00Z"}"#, to: &session).controlTime == GoTime.parse("2026-01-02T03:04:05Z"))
    }
}

@Suite("맵 세션: 패킷 필터")
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

    /// 응답을 적용한 뒤의 netmap. 응답이 아무것도 바꾸지 않았어도(이때 `apply`는 nil을 낸다) 지금 상태를 돌려준다.
    private func apply(_ json: String, to session: inout MapSession) throws -> Netmap {
        _ = try session.apply(mapResponse(json), receivedAt: receivedAt)
        return try #require(session.netmap)
    }

    @Test("PacketFilter: null·생략은 그대로, 빈 배열은 base를 비운다(모두 차단)")
    func base() throws {
        var session = try start(#","PacketFilter":[\#(rule("100.64.0.2"))]"#)
        #expect(sources(try apply(#"{"PacketFilter":null}"#, to: &session)) == ["100.64.0.2"])
        #expect(sources(try apply("{}", to: &session)) == ["100.64.0.2"])
        #expect(try apply(#"{"PacketFilter":[]}"#, to: &session).packetFilter.isEmpty)
    }

    @Test("이름 붙은 묶음은 이름 순으로 이어지고, null은 그 이름만 지운다")
    func named() throws {
        var session = try start(#","PacketFilter":[\#(rule("base"))],"PacketFilters":{"z":[\#(rule("z"))],"a":[\#(rule("a"))]}"#)
        #expect(sources(try apply("{}", to: &session)) == ["a", "base", "z"])
        #expect(sources(try apply(#"{"PacketFilters":{"a":null,"m":[\#(rule("m"))]}}"#, to: &session)) == ["base", "m", "z"])
        // 빈 배열은 그 이름을 비운 채로 둔다.
        #expect(sources(try apply(#"{"PacketFilters":{"m":[]}}"#, to: &session)) == ["base", "z"])
        // 빈 base만으로 다른 이름의 규칙이 지워지지 않는다.
        #expect(sources(try apply(#"{"PacketFilter":[]}"#, to: &session)) == ["z"])
        // 빈 객체는 아무것도 바꾸지 않는다.
        #expect(sources(try apply(#"{"PacketFilters":{}}"#, to: &session)) == ["z"])
    }

    @Test(#""*": null은 base를 포함한 모든 이름을 지운 뒤 나머지를 적용한다"#)
    func wildcardReset() throws {
        var session = try start(#","PacketFilter":[\#(rule("base"))],"PacketFilters":{"a":[\#(rule("a"))]}"#)
        #expect(sources(try apply(#"{"PacketFilters":{"*":null,"b":[\#(rule("b"))]}}"#, to: &session)) == ["b"])
        // 같은 응답의 PacketFilter도 먼저 적용된 뒤 지워진다.
        #expect(sources(try apply(#"{"PacketFilter":[\#(rule("base2"))],"PacketFilters":{"*":null}}"#, to: &session)).isEmpty)
    }

    @Test(#""*": []는 아무것도 지우지 않는다"#)
    func wildcardEmptyArray() throws {
        var session = try start(#","PacketFilters":{"a":[\#(rule("a"))]}"#)
        #expect(sources(try apply(#"{"PacketFilters":{"*":[]}}"#, to: &session)) == ["a"])
    }
}
