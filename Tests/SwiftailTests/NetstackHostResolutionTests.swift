import Foundation
import SwiftailBase
import SwiftailControl
import Testing
@testable import Swiftail

/// Tests name resolution in `connect(to:port:)` (contract `docs/contracts/SwiftailNetstack.md` behavior A2, unit test 13).
@Suite("Node TCP name resolution", .timeLimit(.minutes(1)))
struct NetstackHostResolutionTests {
    private static func netmap() throws -> Netmap {
        try NetstackTestSupport.netmap(peers: [
            // Select IPv4 even when the IPv6 address is listed first.
            .init(id: 2, key: 0x22, name: "rd-phone-1a2b3c4d.tail0001.ts.net.", addresses: ["fd7a:115c:a1e0::2/128", "100.64.0.2/32"]),
            .init(id: 3, key: 0x33, name: "rd-pad-1a2b3c4d.tail0001.ts.net.", addresses: ["fd7a:115c:a1e0::3/128"]),
            .init(id: 4, key: 0x44, name: "", addresses: ["100.64.0.4/32"]),
        ])
    }

    private static func address(_ text: String) throws -> IPAddress {
        try #require(IPAddress(text))
    }

    @Test("IP addresses pass through regardless of the netmap")
    func ipLiteral() throws {
        let netmap = try Self.netmap()
        #expect(netmap.address(ofHost: "100.64.0.77") == (try Self.address("100.64.0.77")))
        #expect(netmap.address(ofHost: "fd7a:115c:a1e0::2") == (try Self.address("fd7a:115c:a1e0::2")))
    }

    @Test("FQDN matching ignores case and one trailing dot, and selects the node's IPv4 address first")
    func fullyQualifiedName() throws {
        let netmap = try Self.netmap()
        let phone = try Self.address("100.64.0.2")
        #expect(netmap.address(ofHost: "rd-phone-1a2b3c4d.tail0001.ts.net") == phone)
        #expect(netmap.address(ofHost: "rd-phone-1a2b3c4d.tail0001.ts.net.") == phone)
        #expect(netmap.address(ofHost: "RD-Phone-1A2B3C4D.Tail0001.TS.NET") == phone)
        #expect(netmap.address(ofHost: "rd-phone-1a2b3c4d.tail0001.ts.net..") == nil)
    }

    @Test("Resolves short names with the MagicDNS suffix removed. A node without IPv4 resolves to IPv6")
    func shortName() throws {
        let netmap = try Self.netmap()
        #expect(netmap.address(ofHost: "rd-phone-1a2b3c4d") == (try Self.address("100.64.0.2")))
        #expect(netmap.address(ofHost: "RD-PAD-1A2B3C4D.") == (try Self.address("fd7a:115c:a1e0::3")))
        #expect(netmap.address(ofHost: "rd-phone-1a2b3c4d.tail0001") == nil, "A name with only part of the suffix removed does not resolve")
    }

    @Test("Also resolves the node's own name")
    func selfName() throws {
        let netmap = try Self.netmap()
        #expect(netmap.address(ofHost: "rd-mac-1a2b3c4d.tail0001.ts.net") == (try Self.address("100.64.0.1")))
        #expect(netmap.address(ofHost: "rd-mac-1a2b3c4d") == (try Self.address("100.64.0.1")))
    }

    @Test("Unknown names, empty names, and nodes without names do not resolve")
    func unknownNames() throws {
        let netmap = try Self.netmap()
        #expect(netmap.address(ofHost: "rd-tv-1a2b3c4d") == nil)
        #expect(netmap.address(ofHost: "example.com") == nil)
        #expect(netmap.address(ofHost: "") == nil)
        #expect(netmap.address(ofHost: ".") == nil)
        #expect(netmap.address(ofHost: "tail0001.ts.net") == nil)
    }

    @Test("When two nodes share a name, the higher node ID (inserted later) wins, as in Go's table")
    func duplicateNames() throws {
        let netmap = try NetstackTestSupport.netmap(peers: [
            .init(id: 7, key: 0x77, name: "dup.tail0001.ts.net.", addresses: ["100.64.0.7/32"]),
            .init(id: 5, key: 0x55, name: "DUP.tail0001.ts.net.", addresses: ["100.64.0.5/32"]),
        ])
        #expect(netmap.address(ofHost: "dup") == (try Self.address("100.64.0.7")))
    }

    @Test("The node returns unknownHost for an address belonging to neither a peer nor itself, or for an unknown name. An empty host or port 0 yields invalidConfiguration")
    func nodeRejectsUnknownHosts() async throws {
        try await NetstackTestSupport.withRunningNode(try Self.netmap()) { node in
            #expect(await NetstackTestSupport.error { try await node.connect(to: "100.64.0.77", port: 80) } == .unknownHost)
            #expect(await NetstackTestSupport.error { try await node.connect(to: "rd-tv-1a2b3c4d", port: 80) } == .unknownHost)
            #expect(await NetstackTestSupport.error { try await node.connect(to: "rd-pad-1a2b3c4d", port: 0) }
                == .invalidConfiguration("포트는 0이 아니어야 한다"))
            if case .invalidConfiguration = await NetstackTestSupport.error({ try await node.connect(to: "", port: 80) }) {
            } else {
                Issue.record("An empty host should yield invalidConfiguration")
            }
            #expect(await node.trackedConnectionCount == 0)
        }
    }

    @Test("A connection to the node's own short name reaches its listener")
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
