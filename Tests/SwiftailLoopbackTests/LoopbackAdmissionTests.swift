import Dispatch
import Foundation
import Network
import SwiftailBase
import Testing
@testable import Swiftail
@testable import SwiftailLoopback

/// Only loopback connections opened by the bridge obtain an identity (contract `docs/contracts/SwiftailHost.md` behavior B6, M7-9b).
///
/// Use a POSIX socket (`RawLoopbackSocket`) for operations another process on the same device could perform: bind to the desired source port
/// (`SO_REUSEADDR`), connect to a loopback listener, and send arbitrary bytes. The server looks up identity at `.ready`, as the contract specifies.
@Suite("Loopback bridge: only connections opened by the bridge obtain an identity", .timeLimit(.minutes(1)))
struct LoopbackAdmissionTests {
    private typealias Support = BridgeTestSupport

    /// Bytes that start like a TLS record (something other than a token arrives in its place).
    private static let stray = [UInt8](repeating: 0x16, count: 64)

    // MARK: Review reproductions

    /// Review 1: with only the source port as the table key, a second listener obtained the identity of a connection to the first listener.
    @Test("A connection from the same source port to the second listener does not become ready while the bridge connects to the first")
    func sameSourcePortOnSecondListener() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            let bridge = LoopbackBridge(node: node)
            let first = try await PlainLoopbackServer.start(admittingFor: bridge)
            defer { first.close() }
            let second = try await PlainLoopbackServer.start(admittingFor: bridge)
            defer { second.close() }
            let link = try await Support.bridge(node, bridge, to: first)

            let stranger = try RawLoopbackSocket(boundTo: link.peer.remotePort, reuseAddress: true)
            try stranger.connect(to: second.port)
            try stranger.send(Self.stray)
            await Self.expectRejected(second.nextOutcome(), bridge)

            #expect(bridge.origin(of: link.peer.connection)?.peer == Support.selfIdentity)
            await link.client.abort()
            _ = await link.finished()
        }
    }

    /// Review 2: if the tailnet side sends more after the server responds and closes, the server kernel emits RST and frees the source port before the bridge notices.
    /// The new connection does not become ready even if an admission the server never looked up remains for that 4-tuple (it identifies the peer whose bytes the connection actually carried).
    @Test("A connection to the same listener from a source port freed by RST after the server closed cannot obtain an identity, even if admission remains")
    func portFreedByResetOnSameListener() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            let bridge = LoopbackBridge(node: node)
            let server = try await PlainLoopbackServer.start(admittingFor: bridge)
            defer { server.close() }
            let link = try await Support.bridge(node, bridge, to: server)
            let key = LoopbackAdmissionTable.Key(sourcePort: link.peer.remotePort, listenerPort: server.port)

            try await link.client.write(Array("request".utf8))
            #expect(await link.peer.read() == .bytes(Array("request".utf8)))
            try await link.peer.send(Array("response".utf8), final: true)
            link.peer.connection.cancel()
            #expect(try await Support.readToEnd(link.client) == Array("response".utf8))

            // Sending more to a closed server socket elicits RST and puts the bridge's loopback socket in CLOSED. The same 4-tuple can then be used to connect.
            var stranger: RawLoopbackSocket?
            for _ in 0..<500 where stranger == nil {
                _ = try? await link.client.write([0xEE])
                stranger = Self.connectedStranger(from: key.sourcePort, to: server.port)
                if stranger == nil { try await Task.sleep(for: .milliseconds(10)) }
            }
            let socket = try #require(stranger, "The source port was not released")
            #expect(bridge.admission.snapshot.admitted.contains(key))

            let accepted = try #require(await server.nextConnection())
            // Do not answer even a server that violates the contract by looking up the identity before it is ready.
            #expect(bridge.origin(of: accepted) == nil)
            try socket.send(Self.stray)
            await Self.expectRejected(PeerConnection.start(accepted), bridge)
            #expect(bridge.origin(of: accepted) == nil)
            // The bridge receives nothing more on loopback, so it learns of the RST on its next write. If the tailnet side does not write, the entry remains until then.
            await link.client.abort()
            #expect(await link.finished() == nil)
        }
    }

    /// Second case in review 2: if the server resets while the bridge is receiving, there was a gap between the port being released and the bridge noticing.
    /// Another thread repeatedly tries to connect from that port and gets through as soon as it is released.
    @Test("A connection made immediately from the same source port after the server resets during a receive does not become ready", arguments: 0..<10)
    func probeRightAfterServerReset(round: Int) async throws {
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            let bridge = LoopbackBridge(node: node)
            let server = try await PlainLoopbackServer.start(admittingFor: bridge)
            defer { server.close() }
            let link = try await Support.bridge(node, bridge, to: server)
            #expect(bridge.origin(of: link.peer.connection) != nil)
            let sourcePort = link.peer.remotePort
            let serverPort = server.port
            let probe = Task {
                await withCheckedContinuation { (continuation: CheckedContinuation<RawLoopbackSocket?, Never>) in
                    DispatchQueue.global().async {
                        let deadline = ContinuousClock.now + .seconds(5)
                        while ContinuousClock.now < deadline {
                            if let socket = Self.connectedStranger(from: sourcePort, to: serverPort) {
                                try? socket.send(Self.stray)
                                continuation.resume(returning: socket)
                                return
                            }
                        }
                        continuation.resume(returning: nil)
                    }
                }
            }
            try await Task.sleep(for: .milliseconds(20))
            link.peer.connection.forceCancel()
            let stranger = await probe.value
            #expect(stranger != nil, "Round \(round): the source port was not released")
            if stranger != nil { await Self.expectRejected(server.nextOutcome(), bridge) }
            #expect(await Support.error { try await Support.readToEnd(link.client) } == .reset)
            #expect(await link.finished() == nil)
        }
    }

    // MARK: Tokens

    @Test("A connection with a missing or incorrect token, or one that ends before sending the whole token, does not become ready")
    func invalidTokensAreRejected() async throws {
        let bridge = try Self.idleBridge()
        let server = try await PlainLoopbackServer.start(admittingFor: bridge)
        defer { server.close() }
        let cases: [(String, [UInt8], Bool)] = [
            ("HTTP without a token", Array("GET / HTTP/1.1\r\nHost: rd-mac-1a2b3c4d\r\n\r\n".utf8), false),
            ("Unrecorded token", LoopbackAdmissionTable.makeToken() + [1], false),
            ("FIN after 10 bytes", [UInt8](repeating: 1, count: 10), true),
        ]
        for (what, bytes, finish) in cases {
            let stranger = try RawLoopbackSocket(boundTo: 0, reuseAddress: false)
            try stranger.connect(to: server.port)
            try stranger.send(bytes)
            if finish { stranger.finishWriting() }
            await Self.expectRejected(server.nextOutcome(), bridge, what)
        }
    }

    @Test("A connection that stops before sending the whole token ends after 5 seconds without becoming ready")
    func partialTokenTimesOut() async throws {
        let bridge = try Self.idleBridge()
        let server = try await PlainLoopbackServer.start(admittingFor: bridge)
        defer { server.close() }
        let stranger = try RawLoopbackSocket(boundTo: 0, reuseAddress: false)
        try stranger.connect(to: server.port)
        try stranger.send([UInt8](repeating: 1, count: 10))
        let started = ContinuousClock.now
        await Self.expectRejected(server.nextOutcome(), bridge)
        let elapsed = ContinuousClock.now - started
        #expect(elapsed >= .seconds(4) && elapsed < .seconds(10), "\(elapsed)")
    }

    @Test("A token works once on the connection with the recorded source port and listener port")
    func tokenIsBoundAndSingleUse() async throws {
        let bridge = try Self.idleBridge()
        let server = try await PlainLoopbackServer.start(admittingFor: bridge)
        defer { server.close() }
        let other = try await PlainLoopbackServer.start(admittingFor: bridge)
        defer { other.close() }
        let origin = LoopbackBridge.Origin(
            remoteEndpoint: IPEndpoint(address: try #require(IPAddress("100.64.0.2")), port: 41_641), peer: Support.selfIdentity)

        // The matching connection.
        let rightful = try RawLoopbackSocket(boundTo: 0, reuseAddress: false)
        let token = LoopbackAdmissionTable.makeToken()
        #expect(bridge.admission.expect(token, for: .init(sourcePort: rightful.localPort, listenerPort: server.port), origin: origin))
        try rightful.connect(to: server.port)
        // The token, bytes, and EOF (FIN) arrive together. The bytes and EOF buffered by the framer reach the next layer.
        try rightful.send(token + [7])
        rightful.finishWriting()
        let peer = try await server.next()
        #expect(bridge.origin(of: peer.connection) == origin)
        #expect(await peer.readToEnd() == .end([7]))

        // Reuse the same token.
        let replay = try RawLoopbackSocket(boundTo: 0, reuseAddress: false)
        try replay.connect(to: server.port)
        try replay.send(token)
        await Self.expectRejected(server.nextOutcome(), bridge, "Reused token")

        // Use the token on a different listener. The token is consumed, so it no longer works on its own listener either.
        let misdirected = try RawLoopbackSocket(boundTo: 0, reuseAddress: false)
        let stolen = LoopbackAdmissionTable.makeToken()
        let stolenKey = LoopbackAdmissionTable.Key(sourcePort: misdirected.localPort, listenerPort: server.port)
        #expect(bridge.admission.expect(stolen, for: stolenKey, origin: origin))
        try misdirected.connect(to: other.port)
        try misdirected.send(stolen)
        await Self.expectRejected(other.nextOutcome(), bridge, "Token for a different listener")
        let late = try RawLoopbackSocket(boundTo: stolenKey.sourcePort, reuseAddress: true)
        try late.connect(to: server.port)
        try late.send(stolen)
        await Self.expectRejected(server.nextOutcome(), bridge, "Consumed token")

        // Use the token from a different source port.
        let elsewhere = try RawLoopbackSocket(boundTo: 0, reuseAddress: false)
        let reserved = LoopbackAdmissionTable.makeToken()
        #expect(bridge.admission.expect(reserved, for: .init(sourcePort: 1, listenerPort: server.port), origin: origin))
        try elsewhere.connect(to: server.port)
        try elsewhere.send(reserved)
        await Self.expectRejected(server.nextOutcome(), bridge, "Token for a different source port")
        #expect(bridge.admission.snapshot.expected.isEmpty)
    }

    @Test("Pending tokens and unclaimed admissions are capped at 256")
    func tableLimits() throws {
        let table = LoopbackAdmissionTable()
        let origin = LoopbackBridge.Origin(
            remoteEndpoint: IPEndpoint(address: try #require(IPAddress("100.64.0.2")), port: 41_641), peer: Support.selfIdentity)
        var tokens: [[UInt8]] = []
        for port in 1...UInt16(256) {
            let token = LoopbackAdmissionTable.makeToken()
            tokens.append(token)
            #expect(table.expect(token, for: .init(sourcePort: port, listenerPort: 9), origin: origin))
        }
        #expect(!table.expect(LoopbackAdmissionTable.makeToken(), for: .init(sourcePort: 999, listenerPort: 9), origin: origin))
        for (index, token) in tokens.enumerated() {
            #expect(table.admit(token, for: .init(sourcePort: UInt16(index + 1), listenerPort: 9)))
        }
        // The 257th admission evicts the oldest.
        let extra = LoopbackAdmissionTable.makeToken()
        #expect(table.expect(extra, for: .init(sourcePort: 999, listenerPort: 9), origin: origin))
        #expect(table.admit(extra, for: .init(sourcePort: 999, listenerPort: 9)))
        #expect(table.take(.init(sourcePort: 1, listenerPort: 9)) == nil)
        #expect(table.take(.init(sourcePort: 2, listenerPort: 9)) == origin)
        #expect(table.take(.init(sourcePort: 999, listenerPort: 9)) == origin)
        #expect(table.snapshot.admitted.count == 254)
    }

    // MARK: TLS listener

    /// TLS client → test entry listener → tailnet connection → bridge → TLS listener with the protocol installed. The handshake crosses the bridge.
    @Test("With a TLS listener, a bridged connection obtains an identity after the handshake and bytes travel end to end")
    func tlsEndToEnd() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            let bridge = LoopbackBridge(node: node)
            let server = try await PlainLoopbackServer.start(
                admittingFor: bridge, tls: try SelfSignedIdentity.serverOptions(try SelfSignedIdentity.make()))
            defer { server.close() }
            let entrance = try await PlainLoopbackServer.start()
            defer { entrance.close() }
            let pair = try await Support.connectedPair(node)
            let forwarding = Support.forward(pair.server, with: bridge, toLoopbackPort: server.port)

            let client = NWConnection(
                host: .ipv4(.loopback), port: try #require(NWEndpoint.Port(rawValue: entrance.port)),
                using: NWParameters(tls: SelfSignedIdentity.clientOptions(), tcp: NWProtocolTCP.Options()))
            defer { client.cancel() }
            let clientReady = Task { await PeerConnection.start(client) }
            let inbound = try await entrance.next()
            let upstream = Task {
                while case .bytes(let bytes) = await inbound.read() { try await pair.client.write(bytes) }
                try await pair.client.finishWriting()
            }
            let downstream = Task {
                while let bytes = try await pair.client.read() { try await inbound.send(bytes, final: false) }
            }
            defer {
                upstream.cancel()
                downstream.cancel()
            }

            let tlsPeer = try await server.next()
            #expect(bridge.origin(of: tlsPeer.connection)?.peer == Support.selfIdentity)
            guard case .ready(let tlsClient) = await clientReady.value else {
                Issue.record("The TLS client did not become ready")
                return
            }
            try await tlsClient.send(Array("ping".utf8), final: false)
            #expect(await tlsPeer.read() == .bytes(Array("ping".utf8)))
            try await tlsPeer.send(Array("pong".utf8), final: false)
            #expect(await tlsClient.read() == .bytes(Array("pong".utf8)))

            await pair.client.abort()
            #expect(await forwarding.value == nil)
        }
    }

    @Test("TLS listener: a TLS client that connects without a token and a connection that reuses the bridge's source port do not become ready")
    func tlsRejections() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            let bridge = LoopbackBridge(node: node)
            let server = try await PlainLoopbackServer.start(
                admittingFor: bridge, tls: try SelfSignedIdentity.serverOptions(try SelfSignedIdentity.make()))
            defer { server.close() }
            let plain = try await PlainLoopbackServer.start(admittingFor: bridge)
            defer { plain.close() }

            let direct = NWConnection(
                host: .ipv4(.loopback), port: try #require(NWEndpoint.Port(rawValue: server.port)),
                using: NWParameters(tls: SelfSignedIdentity.clientOptions(), tcp: NWProtocolTCP.Options()))
            defer { direct.cancel() }
            direct.start(queue: DispatchQueue(label: "test.direct"))
            await Self.expectRejected(server.nextOutcome(), bridge, "TLS client without a token")

            let link = try await Support.bridge(node, bridge, to: plain)
            let stranger = try RawLoopbackSocket(boundTo: link.peer.remotePort, reuseAddress: true)
            try stranger.connect(to: server.port)
            try stranger.send(Self.stray)
            await Self.expectRejected(server.nextOutcome(), bridge, "The bridge's source port")
            await link.client.abort()
            _ = await link.finished()
        }
    }

    /// The gate showed that if the server only calls `cancel()` on a rejected connection and retains it, the socket stays open and a TLS client that connects without a token
    /// remains in the process of becoming ready (a TLS listener without a framer behaves the same for a connection that ends before readiness). The server must release ended connections.
    @Test("The peer sees EOF on a rejected connection once the server closes and releases it", arguments: [false, true])
    func rejectedConnectionEndsOnceReleased(tls: Bool) async throws {
        let bridge = try Self.idleBridge()
        let server = try await PlainLoopbackServer.start(
            admittingFor: bridge, tls: tls ? try SelfSignedIdentity.serverOptions(try SelfSignedIdentity.make()) : nil)
        defer { server.close() }
        let stranger = try RawLoopbackSocket(boundTo: 0, reuseAddress: false)
        try stranger.connect(to: server.port)
        try stranger.send(LoopbackAdmissionTable.makeToken() + [1])
        do {
            let accepted = try #require(await server.nextConnection())
            await Self.expectRejected(PeerConnection.start(accepted), bridge)
            server.discard(accepted)
        }
        #expect(stranger.seesEnd(within: 5))
    }

    // MARK: Helpers

    /// A bridge without a running node. Tests only the table and framer.
    private static func idleBridge() throws -> LoopbackBridge {
        let configuration = NodeConfiguration(
            stateDirectory: try #require(URL(string: "file:///var/empty/swiftail-test/")), hostname: "rd-mac-1a2b3c4d",
            controlURL: try #require(URL(string: "http://127.0.0.1:9")))
        return LoopbackBridge(node: try TailnetNode(configuration: configuration))
    }

    /// A socket bound to `127.0.0.1:<sourcePort>` (`SO_REUSEADDR`) and connected to `127.0.0.1:<port>`. Returns nil if the 4-tuple is in use.
    private static func connectedStranger(from sourcePort: UInt16, to port: UInt16) -> RawLoopbackSocket? {
        guard let socket = try? RawLoopbackSocket(boundTo: sourcePort, reuseAddress: true) else { return nil }
        do {
            try socket.connect(to: port)
            return socket
        } catch {
            return nil
        }
    }

    /// Checks that the connection ended without becoming ready. If it did become ready, it must still have obtained no identity (record both as failures).
    private static func expectRejected(
        _ outcome: PeerConnection.Outcome, _ bridge: LoopbackBridge, _ what: String = "",
        sourceLocation: SourceLocation = #_sourceLocation
    ) async {
        guard case .ready(let peer) = outcome else { return }
        let origin = bridge.origin(of: peer.connection)
        Issue.record("\(what): became ready (identity \(origin == nil ? "absent" : "present"))", sourceLocation: sourceLocation)
        peer.connection.cancel()
    }
}
