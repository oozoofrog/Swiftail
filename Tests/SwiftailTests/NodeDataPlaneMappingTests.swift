import Foundation
import SwiftailBase
import SwiftailControl
import SwiftailEngine
import SwiftailMagicsock
import Testing
@testable import Swiftail

/// Values the node moves between state machines: local endpoints → `LocalStatus` (N4), peer key ↔ name (N6).
/// Contract `docs/contracts/SwiftailEngine.md`, "Changes in M4."
@Suite("Mapping the node's data plane values")
struct NodeDataPlaneMappingTests {
    private static func endpoint(_ text: String) throws -> IPEndpoint {
        try #require(IPEndpoint(text))
    }

    private static func key(_ byte: UInt8) -> String {
        "nodekey:" + [UInt8](repeating: byte, count: 32).hex
    }

    /// A netmap with the local node (ID 1) and `peers` (ID, key bytes, name). Peers have home DERP 1.
    private static func netmap(peers: [(id: Int64, key: UInt8, name: String)]) throws -> Netmap {
        let peerJSON = peers.map { peer in
            #"{"ID":\#(peer.id),"Name":"\#(peer.name)","User":101,"Key":"\#(key(peer.key))","#
                + #""Addresses":["100.64.0.\#(peer.id)/32"],"AllowedIPs":["100.64.0.\#(peer.id)/32"],"HomeDERP":1}"#
        }
        let json = #"{"Node":{"ID":1,"Name":"self.tail0001.ts.net.","User":101,"Key":"\#(key(0x01))","Addresses":["100.64.0.1/32"]},"#
            + #""Peers":[\#(peerJSON.joined(separator: ","))]}"#
        let response = try JSONDecoder().decode(MapResponse.self, from: Data(json.utf8))
        var session = MapSession()
        return try #require(try session.apply(response, receivedAt: Date()).netmap)
    }

    private static func directory(_ peers: [(id: Int64, key: UInt8, name: String)]) throws -> PeerDirectory {
        let netmap = try netmap(peers: peers)
        return PeerDirectory(peers: EnginePeer.peers(in: netmap, at: Date()))
    }

    private static func nodeKey(_ byte: UInt8) throws -> NodePublicKey {
        try #require(NodePublicKey(rawValue: [UInt8](repeating: byte, count: 32)))
    }

    /// Before the fix, the node looked up the name in the netmap by key again, so it used the name of the lowest-ID node with that key regardless of eligibility.
    @Test("When two nodes share a key, uses the name of the node admitted to the data plane")
    func nameComesFromChosenNode() throws {
        // ID 3 has no tailnet address and stays out of the data plane, while ID 5 with the same key is admitted.
        let json = #"{"Node":{"ID":1,"Name":"self.tail0001.ts.net.","User":101,"Key":"\#(Self.key(0x01))","Addresses":["100.64.0.1/32"]},"#
            + #""Peers":[{"ID":3,"Name":"ineligible.tail0001.ts.net.","User":101,"Key":"\#(Self.key(0x07))","AllowedIPs":["10.0.0.0/8"],"HomeDERP":1},"#
            + #"{"ID":5,"Name":"onplane.tail0001.ts.net.","User":101,"Key":"\#(Self.key(0x07))","Addresses":["100.64.0.5/32"],"AllowedIPs":["100.64.0.5/32"],"HomeDERP":1}]}"#
        let response = try JSONDecoder().decode(MapResponse.self, from: Data(json.utf8))
        var session = MapSession()
        let netmap = try #require(try session.apply(response, receivedAt: Date()).netmap)
        let directory = PeerDirectory(peers: EnginePeer.peers(in: netmap, at: Date()))
        #expect(directory.name(of: try Self.nodeKey(0x07)) == "onplane.tail0001.ts.net")
        #expect(directory.key(named: "onplane.tail0001.ts.net") == (try Self.nodeKey(0x07)))
        #expect(directory.key(named: "ineligible.tail0001.ts.net") == nil)
    }

    // MARK: N4

    @Test("Maps endpoints to addresses and types (local 1, stun 2) in the same order and leaves the disco key and home region unchanged")
    func endpointsToLocalStatus() throws {
        var status = ControlClient.LocalStatus(discoKey: try #require(DiscoPublicKey(rawValue: [UInt8](repeating: 0xD1, count: 32))))
        status.netInfo = NetInfo(preferredDERP: 1)
        status.setEndpoints([
            Magicsock.Endpoint(address: try Self.endpoint("198.51.100.7:41641"), source: .stun),
            Magicsock.Endpoint(address: try Self.endpoint("192.0.2.10:41641"), source: .local),
        ])
        #expect(status.endpoints == [try Self.endpoint("198.51.100.7:41641"), try Self.endpoint("192.0.2.10:41641")])
        #expect(status.endpointTypes.map(\.rawValue) == [2, 1])
        #expect(!status.discoKey.isZero)
        #expect(status.netInfo?.preferredDERP == 1)

        status.setEndpoints([])
        #expect(status.endpoints.isEmpty && status.endpointTypes.isEmpty)
    }

    // MARK: N6

    @Test("Stores names with one trailing dot removed and ignores the trailing dot and ASCII case at lookup")
    func nameComparison() throws {
        let directory = try Self.directory([(2, 0x02, "rd-mac-1a2b3c4d.tail0001.ts.net.")])
        let key = try Self.nodeKey(0x02)
        #expect(directory.name(of: key) == "rd-mac-1a2b3c4d.tail0001.ts.net")
        #expect(directory.key(named: "rd-mac-1a2b3c4d.tail0001.ts.net") == key)
        #expect(directory.key(named: "rd-mac-1a2b3c4d.tail0001.ts.net.") == key)
        #expect(directory.key(named: "RD-Mac-1A2B3C4D.Tail0001.TS.net") == key)
        #expect(directory.key(named: "rd-mac-1a2b3c4d.tail0001.ts.net..") == nil)
        #expect(directory.key(named: "rd-mac-1a2b3c4d") == nil)
        #expect(directory.key(named: "") == nil)
    }

    @Test("Leaves the case of non-ASCII characters unchanged")
    func nonASCIINames() throws {
        let directory = try Self.directory([(2, 0x02, "ÄBC.tail0001.ts.net.")])
        #expect(directory.key(named: "Äbc.tail0001.ts.net") == (try Self.nodeKey(0x02)))
        #expect(directory.key(named: "äbc.tail0001.ts.net") == nil)
    }

    @Test("When two nodes share a name, the lower node ID wins. A peer with an empty name has no name")
    func duplicateAndEmptyNames() throws {
        let directory = try Self.directory([(5, 0x05, "dup.tail0001.ts.net."), (3, 0x03, "DUP.tail0001.ts.net."), (4, 0x04, "")])
        #expect(directory.key(named: "dup.tail0001.ts.net") == (try Self.nodeKey(0x03)))
        #expect(directory.name(of: try Self.nodeKey(0x04)) == nil)
        #expect(directory.name(of: try Self.nodeKey(0x09)) == nil)
    }

    @Test("Appends old names after the new table for events from peers being removed. Names in the new table take precedence")
    func keepingOldNames() throws {
        let old = try Self.directory([(2, 0x02, "old.tail0001.ts.net."), (3, 0x03, "gone.tail0001.ts.net.")])
        let new = try Self.directory([(2, 0x02, "renamed.tail0001.ts.net.")])
        let merged = new.keepingNames(of: old)
        #expect(merged.name(of: try Self.nodeKey(0x02)) == "renamed.tail0001.ts.net")
        #expect(merged.name(of: try Self.nodeKey(0x03)) == "gone.tail0001.ts.net")
        #expect(new.name(of: try Self.nodeKey(0x03)) == nil)
    }

    @Test("Path event log lines identify peers by number in first-event order and record the reason for degradation, time since the same peer's previous event (in 0.1-second units), and discarded disco messages by type")
    func pathEventLine() throws {
        let start = ContinuousClock.now
        let first = try Self.nodeKey(0x02), second = try Self.nodeKey(0x03)
        var tally = PathEventTally()
        #expect(tally.line(for: first, path: .relayed(derpRegion: 7), downgrade: nil, at: start)
            == "피어 1 경로: relayed(7) (첫 사건, 버린 disco: 모르는 키 0, 열리지 않음 0, 경로 규칙 0)")
        for drop in [Magicsock.Drop.unknownDiscoKey, .unknownDiscoKey, .malformedDisco, .misroutedDisco, .noRouteToPeer, .unexpectedSTUN] {
            tally.count(drop)
        }
        #expect(tally.line(for: second, path: .relayed(derpRegion: 20), downgrade: nil, at: start + .seconds(1))
            == "피어 2 경로: relayed(20) (첫 사건, 버린 disco: 모르는 키 2, 열리지 않음 1, 경로 규칙 1)")
        // "Since previous event" measures from the previous event for the same peer, even if another peer had an event in between. Discarded disco messages are counted since the previous event for any peer.
        #expect(tally.line(for: first, path: .relayed(derpRegion: 7), downgrade: .trustExpired, at: start + .milliseconds(96_570))
            == "피어 1 경로: relayed(7) (신뢰 만료, 앞 사건 뒤 96.5초, 버린 disco: 모르는 키 0, 열리지 않음 0, 경로 규칙 0)")
        #expect(tally.line(for: second, path: nil, downgrade: .discoKeyChanged, at: start + .seconds(3))
            == "피어 2 경로: none (disco 키 바뀜, 앞 사건 뒤 2.0초, 버린 disco: 모르는 키 0, 열리지 않음 0, 경로 규칙 0)")
    }

    @Test("Deletes path records for peers removed from the netmap, retains the remaining peers' numbers, and never reuses old numbers")
    func pathEventTallyPrunesRemovedPeers() async throws {
        let node = try TailnetNode(configuration: NodeTestSupport.unusedConfiguration())
        let kept = try Self.nodeKey(0x02)
        let removed = try Self.nodeKey(0x03)
        let added = try Self.nodeKey(0x04)
        let start = ContinuousClock.now
        let peer2 = (id: Int64(2), key: UInt8(0x02), name: "kept.tail0001.ts.net.")
        let peer3 = (id: Int64(3), key: UInt8(0x03), name: "removed.tail0001.ts.net.")
        let peer4 = (id: Int64(4), key: UInt8(0x04), name: "added.tail0001.ts.net.")
        await node.apply(try Self.netmap(peers: [peer2, peer3]))
        _ = await node.pathEventLine(for: kept, at: start)
        _ = await node.pathEventLine(for: removed, at: start)

        await node.apply(try Self.netmap(peers: [peer2, peer4]))
        let keptLine = await node.pathEventLine(for: kept, at: start + .seconds(1))
        #expect(keptLine.hasPrefix("피어 1 경로: relayed(1) (앞 사건 뒤 1.0초,"))
        let addedLine = await node.pathEventLine(for: added, at: start + .seconds(1))
        #expect(addedLine.hasPrefix("피어 3 경로: relayed(1) (첫 사건,"))

        await node.apply(try Self.netmap(peers: [peer2, peer3, peer4]))
        let returnedLine = await node.pathEventLine(for: removed, at: start + .seconds(2))
        #expect(returnedLine.hasPrefix("피어 4 경로: relayed(1) (첫 사건,"))
    }
}

private extension TailnetNode {
    func pathEventLine(for peer: NodePublicKey, at now: ContinuousClock.Instant) -> String {
        pathEventTally.line(for: peer, path: .relayed(derpRegion: 1), downgrade: nil, at: now)
    }
}
