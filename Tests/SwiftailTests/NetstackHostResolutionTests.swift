import Foundation
import SwiftailBase
import SwiftailControl
import Testing
@testable import Swiftail

/// `connect(to:port:)`의 이름 해석(계약 `docs/contracts/SwiftailNetstack.md` 동작 A2, 단위 시험 13).
@Suite("노드의 TCP: 이름 해석", .timeLimit(.minutes(1)))
struct NetstackHostResolutionTests {
    private static func netmap() throws -> Netmap {
        try NetstackTestSupport.netmap(peers: [
            // IPv6 주소가 앞에 있어도 IPv4를 고른다.
            .init(id: 2, key: 0x22, name: "rd-phone-1a2b3c4d.tail0001.ts.net.", addresses: ["fd7a:115c:a1e0::2/128", "100.64.0.2/32"]),
            .init(id: 3, key: 0x33, name: "rd-pad-1a2b3c4d.tail0001.ts.net.", addresses: ["fd7a:115c:a1e0::3/128"]),
            .init(id: 4, key: 0x44, name: "", addresses: ["100.64.0.4/32"]),
        ])
    }

    private static func address(_ text: String) throws -> IPAddress {
        try #require(IPAddress(text))
    }

    @Test("IP 주소는 netmap과 무관하게 그대로다")
    func ipLiteral() throws {
        let netmap = try Self.netmap()
        #expect(netmap.address(ofHost: "100.64.0.77") == (try Self.address("100.64.0.77")))
        #expect(netmap.address(ofHost: "fd7a:115c:a1e0::2") == (try Self.address("fd7a:115c:a1e0::2")))
    }

    @Test("FQDN은 대소문자와 끝의 점 하나를 가리지 않고, 그 노드의 IPv4를 먼저 고른다")
    func fullyQualifiedName() throws {
        let netmap = try Self.netmap()
        let phone = try Self.address("100.64.0.2")
        #expect(netmap.address(ofHost: "rd-phone-1a2b3c4d.tail0001.ts.net") == phone)
        #expect(netmap.address(ofHost: "rd-phone-1a2b3c4d.tail0001.ts.net.") == phone)
        #expect(netmap.address(ofHost: "RD-Phone-1A2B3C4D.Tail0001.TS.NET") == phone)
        #expect(netmap.address(ofHost: "rd-phone-1a2b3c4d.tail0001.ts.net..") == nil)
    }

    @Test("MagicDNS 접미사를 뗀 짧은 이름도 찾는다. IPv4가 없는 노드는 IPv6이다")
    func shortName() throws {
        let netmap = try Self.netmap()
        #expect(netmap.address(ofHost: "rd-phone-1a2b3c4d") == (try Self.address("100.64.0.2")))
        #expect(netmap.address(ofHost: "RD-PAD-1A2B3C4D.") == (try Self.address("fd7a:115c:a1e0::3")))
        #expect(netmap.address(ofHost: "rd-phone-1a2b3c4d.tail0001") == nil, "접미사의 일부만 뗀 이름은 없다")
    }

    @Test("자기 이름도 찾는다")
    func selfName() throws {
        let netmap = try Self.netmap()
        #expect(netmap.address(ofHost: "rd-mac-1a2b3c4d.tail0001.ts.net") == (try Self.address("100.64.0.1")))
        #expect(netmap.address(ofHost: "rd-mac-1a2b3c4d") == (try Self.address("100.64.0.1")))
    }

    @Test("모르는 이름, 빈 이름, 이름 없는 노드는 찾지 못한다")
    func unknownNames() throws {
        let netmap = try Self.netmap()
        #expect(netmap.address(ofHost: "rd-tv-1a2b3c4d") == nil)
        #expect(netmap.address(ofHost: "example.com") == nil)
        #expect(netmap.address(ofHost: "") == nil)
        #expect(netmap.address(ofHost: ".") == nil)
        #expect(netmap.address(ofHost: "tail0001.ts.net") == nil)
    }

    @Test("같은 이름이 둘이면 Go의 표처럼 node ID가 큰 쪽(나중에 넣은 것)이다")
    func duplicateNames() throws {
        let netmap = try NetstackTestSupport.netmap(peers: [
            .init(id: 7, key: 0x77, name: "dup.tail0001.ts.net.", addresses: ["100.64.0.7/32"]),
            .init(id: 5, key: 0x55, name: "DUP.tail0001.ts.net.", addresses: ["100.64.0.5/32"]),
        ])
        #expect(netmap.address(ofHost: "dup") == (try Self.address("100.64.0.7")))
    }

    @Test("노드: 피어도 자기도 아닌 주소, 모르는 이름은 unknownHost. 빈 호스트와 포트 0은 invalidConfiguration")
    func nodeRejectsUnknownHosts() async throws {
        try await NetstackTestSupport.withRunningNode(try Self.netmap()) { node in
            #expect(await NetstackTestSupport.error { try await node.connect(to: "100.64.0.77", port: 80) } == .unknownHost)
            #expect(await NetstackTestSupport.error { try await node.connect(to: "rd-tv-1a2b3c4d", port: 80) } == .unknownHost)
            #expect(await NetstackTestSupport.error { try await node.connect(to: "rd-pad-1a2b3c4d", port: 0) }
                == .invalidConfiguration("포트는 0이 아니어야 한다"))
            if case .invalidConfiguration = await NetstackTestSupport.error({ try await node.connect(to: "", port: 80) }) {
            } else {
                Issue.record("빈 호스트는 invalidConfiguration이어야 한다")
            }
            #expect(await node.trackedConnectionCount == 0)
        }
    }

    @Test("노드: 자기 짧은 이름으로 건 연결이 자기 리스너에 닿는다")
    func nodeConnectsBySelfName() async throws {
        try await NetstackTestSupport.withRunningNode(try Self.netmap()) { node in
            let pair = try await NetstackTestSupport.connectedPair(node, host: "rd-mac-1a2b3c4d")
            #expect(pair.client.remoteEndpoint.description == "100.64.0.1:9000")
            #expect(pair.server.remoteEndpoint == pair.client.localEndpoint)
            #expect(pair.server.localEndpoint == pair.client.remoteEndpoint)
            await pair.client.abort()
            await pair.server.abort()
        }
    }
}
