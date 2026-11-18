import Foundation
import Network
import SwiftailBase
import Synchronization
import Testing
@testable import Swiftail
@testable import SwiftailLoopback

/// Tests peer lookup (contract `docs/contracts/SwiftailHost.md` behaviors B1·B2·B6, unit test 14).
@Suite("Loopback bridge: peer lookup", .timeLimit(.minutes(1)))
struct LoopbackOriginTableTests {
    private typealias Support = BridgeTestSupport

    @Test("Looking up a ready connection returns the peer endpoint and whoIs identity once, then nil on the second lookup")
    func originAnsweredOnce() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            let bridge = LoopbackBridge(node: node)
            let server = try await PlainLoopbackServer.start(admittingFor: bridge)
            defer { server.close() }
            let link = try await Support.bridge(node, bridge, to: server)

            let origin = try #require(bridge.origin(of: link.peer.connection))
            #expect(origin.remoteEndpoint == link.server.remoteEndpoint)
            #expect(origin.remoteEndpoint.address == IPAddress("100.64.0.1"))
            #expect(origin.peer == Support.selfIdentity)
            #expect(bridge.origin(of: link.peer.connection) == nil)

            try await link.client.write([1])
            #expect(await link.peer.read() == .bytes([1]))
            await link.client.close()
            #expect(await link.peer.readToEnd() == .end([]))
            link.peer.connection.cancel()
            #expect(await link.finished() == nil)
        }
    }

    /// The framer records admission before making the connection ready. The server can look it up at `.ready` without waiting for the first byte.
    @Test("The lookup always has a result when the server sees .ready, even before it receives the first byte")
    func originAnsweredAtReady() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            let bridge = LoopbackBridge(node: node)
            let server = try await PlainLoopbackServer.start(admittingFor: bridge)
            defer { server.close() }
            for round in 0..<20 {
                let pair = try await Support.connectedPair(node, port: 9_000 + UInt16(round))
                // Send this before the bridge connects. The bridge forwards it immediately after the token.
                try await pair.client.write([UInt8(round)])
                let forwarding = Support.forward(pair.server, with: bridge, toLoopbackPort: server.port)
                let peer = try await server.next()
                #expect(bridge.origin(of: peer.connection) != nil, "Round \(round)")
                #expect(await peer.read() == .bytes([UInt8(round)]))
                await pair.client.abort()
                _ = await forwarding.value
            }
        }
    }

    /// Check the table just before closing for each way of ending loopback (normal close, tailnet RST, cancellation). This catches an implementation that closes before revoking the token.
    /// Use a listener without the protocol so the token stays unconsumed.
    @Test("At loopback connection close, the connection's token has already been revoked, and the token was sent before any other bytes")
    func tokenWithdrawnBeforeLoopbackEnds() async throws {
        let ends = Mutex<[(LoopbackAdmissionTable.Key, LoopbackAdmissionTable.Snapshot)]>([])
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            let bridge = LoopbackBridge(node: node, connectionLimit: 256) { key, snapshot in
                ends.withLock { $0.append((key, snapshot)) }
            }
            let server = try await PlainLoopbackServer.start()
            defer { server.close() }
            for (round, ending) in ["close", "reset", "cancel"].enumerated() {
                let link = try await Support.bridge(node, bridge, to: server, port: 9_000 + UInt16(round))
                try await link.client.write([0xAB])
                var received: [UInt8] = []
                while received.count < LoopbackAdmissionTable.tokenLength + 1, case .bytes(let bytes) = await link.peer.read() {
                    received += bytes
                }
                #expect(received.count == LoopbackAdmissionTable.tokenLength + 1, "\(ending)")
                #expect(received.last == 0xAB, "\(ending)")
                #expect(bridge.admission.snapshot.expected.contains(
                    .init(sourcePort: link.peer.remotePort, listenerPort: server.port)), "\(ending)")
                switch ending {
                case "close":
                    try await link.peer.send([], final: true)
                    #expect(try await link.client.read() == nil)
                    await link.client.close()
                    #expect(await link.peer.readToEnd() == .end([]))
                    #expect(await link.finished() == nil)
                case "reset":
                    await link.client.abort()
                    #expect(await link.finished() == nil)
                default:
                    link.forwarding.cancel()
                    #expect(await link.finished() == .cancelled)
                }
                let recorded = ends.withLock { $0 }
                #expect(recorded.count == round + 1, "\(ending)")
                let (key, snapshot) = try #require(recorded.last)
                #expect(key == .init(sourcePort: link.peer.remotePort, listenerPort: server.port), "\(ending)")
                #expect(!snapshot.expected.contains(key), "\(ending): token was not revoked before closing")
                link.peer.connection.cancel()
            }
        }
    }

    /// If the bridge deletes an admission, a new bridge connection reusing the same 4-tuple can take its place, so a late lookup could obtain the wrong peer.
    @Test("An admission the server did not look up remains after the bridge closes loopback, and a new token cannot be recorded under the same key")
    func unclaimedAdmissionOutlivesLoopback() async throws {
        let ends = Mutex<[LoopbackAdmissionTable.Snapshot]>([])
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            let bridge = LoopbackBridge(node: node, connectionLimit: 256) { _, snapshot in
                ends.withLock { $0.append(snapshot) }
            }
            let server = try await PlainLoopbackServer.start(admittingFor: bridge)
            defer { server.close() }
            let link = try await Support.bridge(node, bridge, to: server)
            let key = LoopbackAdmissionTable.Key(sourcePort: link.peer.remotePort, listenerPort: server.port)
            await link.client.abort()
            #expect(await link.finished() == nil)
            #expect(try #require(ends.withLock { $0.last }).admitted.contains(key))
            #expect(bridge.admission.snapshot.admitted.contains(key))

            let origin = LoopbackBridge.Origin(remoteEndpoint: link.server.remoteEndpoint, peer: Support.selfIdentity)
            #expect(!bridge.admission.expect(LoopbackAdmissionTable.makeToken(), for: key, origin: origin))
            link.peer.connection.cancel()
        }
    }

    @Test("The identity at the start of forwarding remains for the life of the connection")
    func identityFixedAtStart() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            let bridge = LoopbackBridge(node: node)
            let server = try await PlainLoopbackServer.start(admittingFor: bridge)
            defer { server.close() }
            let link = try await Support.bridge(node, bridge, to: server)
            // When the profile disappears without a change of owner, whoIs becomes nil, but the connection stays open and retains its identity.
            await node.apply(try Support.netmap(withProfile: false))
            #expect(await node.whoIs(link.server.remoteEndpoint.address) == nil)
            try await link.client.write([1])
            #expect(await link.peer.read() == .bytes([1]))
            #expect(bridge.origin(of: link.peer.connection)?.peer == Support.selfIdentity)
            await link.client.abort()
            _ = await link.finished()
        }
    }
}
