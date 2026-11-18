import Foundation
import Network
import SwiftailBase
import Synchronization
import Testing
@testable import Swiftail
@testable import SwiftailLoopback

/// Tests the cases identified by the independent review (M7-9b, contract `docs/contracts/SwiftailHost.md`, behavior B, "Changes from the Independent Review").
@Suite("Loopback bridge: review reproductions (M7-9b)", .timeLimit(.minutes(1)))
struct LoopbackAdmissionReviewTests {
    private typealias Support = BridgeTestSupport

    private static let origin = LoopbackBridge.Origin(
        remoteEndpoint: IPEndpoint(address: IPAddress("100.64.0.2")!, port: 41_641), peer: Support.selfIdentity)

    /// On a TLS listener, the framer records admission before the handshake. If the handshake does not finish, the server never sees `.ready`, so it does not
    /// look up admission, as the contract specifies. The admission stays until eviction (deleting it could let a late lookup obtain a new admission for the same key). With the retained
    /// key, `expect` rejects the connection. Before the fix, a bridge connection that picked the same source port again ended with `loopbackUnavailable`.
    @Test("Admission for a bridge connection that ends before the TLS handshake stays marked as ended, and the key cannot be recorded again")
    func admissionOfUnfinishedHandshakeIsLeftAsEnded() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            let bridge = LoopbackBridge(node: node)
            let server = try await PlainLoopbackServer.start(
                admittingFor: bridge, tls: try SelfSignedIdentity.serverOptions(try SelfSignedIdentity.make()))
            defer { server.close() }
            let pair = try await Support.connectedPair(node)
            let forwarding = Support.forward(pair.server, with: bridge, toLoopbackPort: server.port)
            let accepted = try #require(await server.nextConnection())
            let outcome = Task { await PeerConnection.start(accepted) }
            try await Support.waitUntil("Token consumed") { bridge.admission.snapshot.admitted.count == 1 }
            // The tailnet side disconnects without sending ClientHello.
            await pair.client.abort()
            guard case .failed = await outcome.value else {
                Issue.record("Became ready without a handshake")
                return
            }
            server.discard(accepted)
            #expect(await forwarding.value == nil)
            let key = try #require(bridge.admission.snapshot.admitted.first)
            #expect(!bridge.admission.expect(LoopbackAdmissionTable.makeToken(), for: key, origin: Self.origin))
        }
    }

    @Test("If admission remains for the key of the chosen source port, the bridge retries on another port and connects")
    func bridgeRedialsWhenKeyHasLeftoverAdmission() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            // Add admission under the first key the bridge picks, as if left by an earlier connection.
            let leftover = Mutex<LoopbackAdmissionTable.Key?>(nil)
            let bridge = LoopbackBridge(node: node, connectionLimit: 256, willExpect: { key, table in
                guard leftover.withLock({ $0 == nil }) else { return }
                let token = LoopbackAdmissionTable.makeToken()
                guard table.expect(token, for: key, origin: Self.origin), table.admit(token, for: key) else { return }
                leftover.withLock { $0 = key }
            })
            let server = try await PlainLoopbackServer.start(admittingFor: bridge)
            defer { server.close() }
            let pair = try await Support.connectedPair(node)
            let forwarding = Support.forward(pair.server, with: bridge, toLoopbackPort: server.port)
            try await pair.client.write(Array("ping".utf8))

            // The listener gets two connections, the one the bridge dropped without sending a token and the retry.
            var ready: PeerConnection?
            for _ in 0..<2 where ready == nil {
                if case .ready(let peer) = await server.nextOutcome() { ready = peer }
            }
            let peer = try #require(ready)
            let leftoverKey = try #require(leftover.withLock { $0 })
            #expect(peer.remotePort != leftoverKey.sourcePort)
            #expect(bridge.origin(of: peer.connection)?.peer == Support.selfIdentity)
            #expect(await peer.read() == .bytes(Array("ping".utf8)))
            #expect(bridge.admission.snapshot.admitted == [leftoverKey], "The retained admission is still present")

            await pair.client.abort()
            #expect(await forwarding.value == nil)
        }
    }

    @Test("If only keys with retained admissions are picked, tries three connections and gives up")
    func bridgeGivesUpAfterThreeRefusedKeys() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            let refused = Mutex<[LoopbackAdmissionTable.Key]>([])
            let bridge = LoopbackBridge(node: node, connectionLimit: 256, willExpect: { key, table in
                let token = LoopbackAdmissionTable.makeToken()
                if table.expect(token, for: key, origin: Self.origin), table.admit(token, for: key) {
                    refused.withLock { $0.append(key) }
                }
            })
            let server = try await PlainLoopbackServer.start(admittingFor: bridge)
            defer { server.close() }
            let pair = try await Support.connectedPair(node)
            let forwarding = Support.forward(pair.server, with: bridge, toLoopbackPort: server.port)
            #expect(await forwarding.value == .loopbackUnavailable("토큰을 표에 적지 못했다"))
            let keys = refused.withLock { $0 }
            #expect(keys.count == 3)
            #expect(Set(keys.map(\.sourcePort)).count == 3, "The same source port is not picked again while held")
            // The three connections dialed by the bridge end without a token and never become ready.
            for _ in 0..<3 {
                if case .ready = await server.nextOutcome() { Issue.record("Became ready without a token") }
            }
        }
    }

    /// When the admissions above accumulate, the limit (256) evicts the oldest. This can evict admission for a legitimate connection in the middle of its handshake. If one tailnet
    /// peer repeatedly connects and immediately disconnects, it evicts another peer's admission before that peer can finish the handshake.
    @Test("Accumulating bridge connections that disconnect immediately does not evict admission for another connection in its handshake")
    func unfinishedHandshakesDoNotEvictPendingAdmission() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            let bridge = LoopbackBridge(node: node)
            let server = try await PlainLoopbackServer.start(
                admittingFor: bridge, tls: try SelfSignedIdentity.serverOptions(try SelfSignedIdentity.make()))
            defer { server.close() }

            // Legitimate connection: the bridge has sent a token and admission is recorded, but the peer has yet to send ClientHello.
            let pending = try await Support.connectedPair(node, port: 9_000)
            let pendingForwarding = Support.forward(pending.server, with: bridge, toLoopbackPort: server.port)
            let pendingAccepted = try #require(await server.nextConnection())
            let pendingOutcome = Task { await PeerConnection.start(pendingAccepted) }
            try await Support.waitUntil("The legitimate connection's token was consumed") { bridge.admission.snapshot.admitted.count == 1 }
            guard case .hostPort(_, let pendingPort) = pendingAccepted.endpoint else {
                Issue.record("No endpoint")
                return
            }
            let pendingKey = LoopbackAdmissionTable.Key(sourcePort: pendingPort.rawValue, listenerPort: server.port)

            // Another peer connects and immediately disconnects 256 times.
            let flood = try await node.listen(port: 9_001)
            var floodConnections = flood.makeAsyncIterator()
            for round in 0..<LoopbackAdmissionTable.admittedLimit {
                let client = try await node.connect(to: "100.64.0.1", port: 9_001)
                let inbound = try #require(await floodConnections.next())
                let forwarding = Support.forward(inbound, with: bridge, toLoopbackPort: server.port)
                let accepted = try #require(await server.nextConnection())
                let outcome = Task { await PeerConnection.start(accepted) }
                try await Support.waitUntil("Token consumed in round \(round)") { bridge.admission.snapshot.admitted.count >= min(round + 2, 256) }
                await client.abort()
                _ = await outcome.value
                server.discard(accepted)
                _ = await forwarding.value
            }
            #expect(bridge.admission.snapshot.admitted.contains(pendingKey), "Admission for the connection in its handshake was evicted")
            pendingOutcome.cancel()
            _ = await pendingOutcome.value
            await pending.client.abort()
            _ = await pendingForwarding.value
        }
    }

    @Test("Admits a token split across two chunks")
    func splitTokenIsAdmitted() async throws {
        let bridge = try Self.idleBridge()
        let server = try await PlainLoopbackServer.start(admittingFor: bridge)
        defer { server.close() }
        let socket = try RawLoopbackSocket(boundTo: 0, reuseAddress: false)
        let token = LoopbackAdmissionTable.makeToken()
        #expect(bridge.admission.expect(token, for: .init(sourcePort: socket.localPort, listenerPort: server.port), origin: Self.origin))
        try socket.connect(to: server.port)
        try socket.send(Array(token[..<10]))
        try await Task.sleep(for: .milliseconds(300))
        try socket.send(Array(token[10...]) + [7])
        socket.finishWriting()
        let peer = try await server.next()
        #expect(bridge.origin(of: peer.connection) == Self.origin)
        #expect(await peer.readToEnd() == .end([7]))
    }

    @Test("A FIN immediately after the token reaches the server as EOF")
    func finRightAfterTokenReachesServer() async throws {
        let bridge = try Self.idleBridge()
        let server = try await PlainLoopbackServer.start(admittingFor: bridge)
        defer { server.close() }
        let socket = try RawLoopbackSocket(boundTo: 0, reuseAddress: false)
        let token = LoopbackAdmissionTable.makeToken()
        #expect(bridge.admission.expect(token, for: .init(sourcePort: socket.localPort, listenerPort: server.port), origin: Self.origin))
        try socket.connect(to: server.port)
        try socket.send(token)
        socket.finishWriting()
        let peer = try await server.next()
        #expect(bridge.origin(of: peer.connection) == Self.origin)
        #expect(await peer.read(within: .seconds(3)) == .end([]))
        peer.connection.cancel()
    }

    @Test("The bridge and table omit tokens from dump and description")
    func tokenNotInReflection() throws {
        let bridge = try Self.idleBridge()
        let token = [UInt8](repeating: 0xA5, count: LoopbackAdmissionTable.tokenLength)
        #expect(bridge.admission.expect(token, for: .init(sourcePort: 50_000, listenerPort: 9), origin: Self.origin))
        var text = ""
        dump(bridge, to: &text)
        dump(bridge.admission, to: &text)
        text += String(describing: bridge) + String(reflecting: bridge.admission)
        #expect(!text.contains("165"), "\(text)")
        #expect(!text.lowercased().contains("token"), "\(text)")
    }

    private static func idleBridge() throws -> LoopbackBridge {
        let configuration = NodeConfiguration(
            stateDirectory: try #require(URL(string: "file:///var/empty/swiftail-test/")), hostname: "rd-mac-1a2b3c4d",
            controlURL: try #require(URL(string: "http://127.0.0.1:9")))
        return LoopbackBridge(node: try TailnetNode(configuration: configuration))
    }
}
