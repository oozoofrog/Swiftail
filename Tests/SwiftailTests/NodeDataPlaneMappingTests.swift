import Foundation
import SwiftailBase
import SwiftailControl
import SwiftailEngine
import SwiftailMagicsock
import Testing
@testable import Swiftail

/// 노드가 상태 기계 사이에서 옮기는 값: 자기 엔드포인트 → `LocalStatus`(N4), 피어 키 ↔ 이름(N6).
/// 계약 `docs/contracts/SwiftailEngine.md` "M4에서 바뀌는 것".
@Suite("노드의 데이터면 값 옮기기")
struct NodeDataPlaneMappingTests {
    private static func endpoint(_ text: String) throws -> IPEndpoint {
        try #require(IPEndpoint(text))
    }

    private static func key(_ byte: UInt8) -> String {
        "nodekey:" + [UInt8](repeating: byte, count: 32).hex
    }

    /// 자기 노드(ID 1)와 `peers`(ID, 키 바이트, 이름)의 netmap. 피어는 홈 DERP 1에 있다.
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

    /// 고치기 전에는 이름을 netmap에서 키로 다시 찾아, 같은 키를 가진 노드 가운데 자격과 무관하게 ID가 가장 작은 노드의 이름이 붙었다.
    @Test("같은 키를 가진 노드가 둘이면 데이터면에 오른 노드의 이름을 쓴다")
    func nameComesFromChosenNode() throws {
        // ID 3은 tailnet 주소가 없어 데이터면에 오르지 않고, 같은 키의 ID 5가 오른다.
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

    @Test("엔드포인트를 같은 순서의 주소와 종류(local 1, stun 2)로 옮기고 disco 키와 홈 지역은 그대로 둔다")
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

    @Test("이름은 끝의 점 하나를 떼어 담고, 찾을 때는 끝의 점과 ASCII 대소문자를 무시한다")
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

    @Test("ASCII가 아닌 글자는 대소문자를 바꾸지 않는다")
    func nonASCIINames() throws {
        let directory = try Self.directory([(2, 0x02, "ÄBC.tail0001.ts.net.")])
        #expect(directory.key(named: "Äbc.tail0001.ts.net") == (try Self.nodeKey(0x02)))
        #expect(directory.key(named: "äbc.tail0001.ts.net") == nil)
    }

    @Test("같은 이름이 둘이면 node ID가 작은 쪽이고, 이름이 빈 피어는 이름이 없다")
    func duplicateAndEmptyNames() throws {
        let directory = try Self.directory([(5, 0x05, "dup.tail0001.ts.net."), (3, 0x03, "DUP.tail0001.ts.net."), (4, 0x04, "")])
        #expect(directory.key(named: "dup.tail0001.ts.net") == (try Self.nodeKey(0x03)))
        #expect(directory.name(of: try Self.nodeKey(0x04)) == nil)
        #expect(directory.name(of: try Self.nodeKey(0x09)) == nil)
    }

    @Test("빠지는 피어의 사건에 쓸 옛 이름을 새 표 뒤에 덧붙인다. 새 표의 이름이 앞선다")
    func keepingOldNames() throws {
        let old = try Self.directory([(2, 0x02, "old.tail0001.ts.net."), (3, 0x03, "gone.tail0001.ts.net.")])
        let new = try Self.directory([(2, 0x02, "renamed.tail0001.ts.net.")])
        let merged = new.keepingNames(of: old)
        #expect(merged.name(of: try Self.nodeKey(0x02)) == "renamed.tail0001.ts.net")
        #expect(merged.name(of: try Self.nodeKey(0x03)) == "gone.tail0001.ts.net")
        #expect(new.name(of: try Self.nodeKey(0x03)) == nil)
    }

    @Test("경로 사건 로그의 진단은 앞 사건 뒤 시간(0.1초 단위)과 버린 disco만 종류별로 세고, 다른 까닭은 세지 않는다")
    func pathEventTally() {
        let start = ContinuousClock.now
        #expect(PathEventTally().summary(at: start) == "첫 사건, 버린 disco: 모르는 키 0, 열리지 않음 0, 경로 규칙 0")
        var tally = PathEventTally(since: start)
        for drop in [Magicsock.Drop.unknownDiscoKey, .unknownDiscoKey, .malformedDisco, .misroutedDisco, .noRouteToPeer, .unexpectedSTUN] {
            tally.count(drop)
        }
        #expect(tally.summary(at: start + .milliseconds(25_370))
            == "앞 사건 뒤 25.3초, 버린 disco: 모르는 키 2, 열리지 않음 1, 경로 규칙 1")
    }
}
