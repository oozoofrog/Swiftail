import Foundation
import Network
import SwiftailBase
import SwiftailControl
import Synchronization
import Testing
@testable import Swiftail
@testable import SwiftailLoopback

/// Tests the loopback bridge (contract `docs/contracts/SwiftailHost.md` behavior B, unit test 13).
///
/// The tailnet side is one node's connection to itself, and the loopback side is a plaintext `NWListener` in the test with the bridge's protocol installed.
@Suite("Loopback bridge: forwarding and disconnection", .timeLimit(.minutes(2)))
struct LoopbackBridgeTests {
    private typealias Support = BridgeTestSupport

    private static func withBridge(
        _ netmap: Netmap? = nil,
        _ body: (TailnetNode, LoopbackBridge, PlainLoopbackServer, _ stop: @escaping @Sendable () async -> Void) async throws -> Void
    ) async throws {
        try await Support.withRunningNode(try netmap ?? Support.netmap()) { node, stop in
            let bridge = LoopbackBridge(node: node)
            let server = try await PlainLoopbackServer.start(admittingFor: bridge)
            defer { server.close() }
            try await body(node, bridge, server, stop)
        }
    }

    // MARK: Forwarding (behaviors B3·B4)

    @Test("Delivers bytes intact in both directions (4MiB each, compared by hash)")
    func bytesFlowBothWays() async throws {
        try await Self.withBridge { node, bridge, server, _ in
            let link = try await Support.bridge(node, bridge, to: server)
            let upstream = Support.pattern(4 << 20, seed: 1)
            let downstream = Support.pattern(4 << 20, seed: 2)

            async let sent: Void = {
                try await link.client.write(upstream)
                try await link.client.finishWriting()
            }()
            async let clientReceived = Support.readToEnd(link.client)
            async let peerReceived = link.peer.readToEnd()
            try await link.peer.send(downstream, final: true)

            try await sent
            #expect(Support.digest(try await clientReceived) == Support.digest(downstream))
            guard case .end(let received) = await peerReceived else {
                Issue.record("The loopback server's read did not end with a clean EOF")
                return
            }
            #expect(Support.digest(received) == Support.digest(upstream))
            #expect(await link.finished() == nil)
        }
    }

    @Test("When the tailnet side closes its write direction, the loopback server sees EOF, and a subsequent response reaches the tailnet side")
    func tailnetHalfClose() async throws {
        try await Self.withBridge { node, bridge, server, _ in
            let link = try await Support.bridge(node, bridge, to: server)
            try await link.client.write(Array("request".utf8))
            try await link.client.finishWriting()
            #expect(await link.peer.readToEnd() == .end(Array("request".utf8)))

            let response = Support.pattern(300_000, seed: 3)
            try await link.peer.send(response, final: false)
            try await link.peer.send(response, final: true)
            #expect(try await Support.readToEnd(link.client) == response + response)
            #expect(await link.finished() == nil)
        }
    }

    @Test("When the loopback side closes its write direction, the tailnet side sees EOF, and a subsequent request reaches the loopback side")
    func loopbackHalfClose() async throws {
        try await Self.withBridge { node, bridge, server, _ in
            let link = try await Support.bridge(node, bridge, to: server)
            try await link.peer.send(Array("hello".utf8), final: true)
            #expect(try await Support.readToEnd(link.client) == Array("hello".utf8))

            let request = Support.pattern(300_000, seed: 4)
            try await link.client.write(request)
            try await link.client.finishWriting()
            #expect(await link.peer.readToEnd() == .end(request))
            #expect(await link.finished() == nil)
        }
    }

    /// If the write does not wait for the bridge to take the chunk (reads lack backpressure), the caller never blocks and everything is accepted.
    @Test("If the loopback server does not read, writes on the tailnet side block. Once it resumes reading, everything arrives intact")
    func slowLoopbackStopsTailnet() async throws {
        try await Self.withBridge { node, bridge, server, _ in
            let link = try await Support.bridge(node, bridge, to: server)
            let total = BackpressureProbe.attempt
            let data = Support.pattern(total, seed: 5)
            let written = Mutex(0)
            let writer = Task { () async throws in
                var offset = 0
                while offset < total {
                    let end = min(offset + 64 << 10, total)
                    try await link.client.write(Array(data[offset..<end]))
                    offset = end
                    written.withLock { $0 = offset }
                }
                try await link.client.finishWriting()
            }
            let accepted = try await BackpressureProbe.stalled { written.withLock { $0 } }
            #expect(accepted < BackpressureProbe.bound, "Accepted \(accepted) bytes")

            let ended = await link.peer.readToEnd()
            guard case .end(let received) = ended else {
                Issue.record("The loopback server's read did not end with a clean EOF: \(ended), port \(link.peer.remotePort), amount accepted before blocking \(accepted)")
                writer.cancel()
                await link.client.abort()
                return
            }
            #expect(received.count == total)
            #expect(Support.digest(received) == Support.digest(data))
            try await writer.value
            try await link.peer.send([], final: true)
            #expect(try await link.client.read() == nil)
            await link.client.close()
            #expect(await link.finished() == nil)
        }
    }

    @Test("If the tailnet side does not read, writes on the loopback server block. Once it resumes reading, everything arrives intact")
    func slowTailnetStopsLoopback() async throws {
        try await Self.withBridge { node, bridge, server, _ in
            let link = try await Support.bridge(node, bridge, to: server)
            let total = BackpressureProbe.attempt
            let data = Support.pattern(total, seed: 6)
            let written = Mutex(0)
            let writer = Task {
                var offset = 0
                while offset < total {
                    let end = min(offset + 64 << 10, total)
                    try await link.peer.send(Array(data[offset..<end]), final: end == total)
                    offset = end
                    written.withLock { $0 = offset }
                }
            }
            let accepted = try await BackpressureProbe.stalled { written.withLock { $0 } }
            #expect(accepted < BackpressureProbe.bound, "Accepted \(accepted) bytes")

            let received = try await Support.readToEnd(link.client)
            #expect(received.count == total)
            #expect(Support.digest(received) == Support.digest(data))
            try await writer.value
            await link.client.close()
            #expect(await link.finished() == nil)
        }
    }

    // MARK: Disconnection (behavior B5, first adopter review result 7)

    @Test("If the tailnet side resets, the loopback server's read ends with an error instead of a clean EOF")
    func tailnetResetResetsLoopback() async throws {
        try await Self.withBridge { node, bridge, server, _ in
            let link = try await Support.bridge(node, bridge, to: server)
            try await link.client.write([1, 2, 3])
            #expect(await link.peer.read() == .bytes([1, 2, 3]))
            await link.client.abort()
            Self.expectReset(await link.peer.readToEnd())
            #expect(await link.finished() == nil)
        }
    }

    @Test("If the address owner changes and the connection ends with peerRemoved, the bridge resets the loopback connection")
    func peerRemovedResetsLoopback() async throws {
        try await Self.withBridge { node, bridge, server, _ in
            let link = try await Support.bridge(node, bridge, to: server)
            try await link.client.write([1])
            #expect(await link.peer.read() == .bytes([1]))
            #expect(bridge.origin(of: link.peer.connection) != nil)

            await node.apply(try Support.netmap(selfAddresses: ["100.64.0.9/32"]))
            Self.expectReset(await link.peer.readToEnd())
            #expect(await link.finished() == nil)
            #expect(await Support.error { try await link.client.read() } == .peerRemoved)
        }
    }

    @Test("When the node stops, the bridge ends the loopback connection with an error and returns")
    func nodeStopResetsLoopback() async throws {
        try await Self.withBridge { node, bridge, server, stop in
            let link = try await Support.bridge(node, bridge, to: server)
            try await link.client.write([1])
            #expect(await link.peer.read() == .bytes([1]))
            await stop()
            Self.expectReset(await link.peer.readToEnd())
            #expect(await link.finished() == nil)
        }
    }

    @Test("If the loopback server closes normally, the tailnet side sees EOF after the response. The bridge returns when the tailnet side closes")
    func loopbackCloseFinishesTailnet() async throws {
        try await Self.withBridge { node, bridge, server, _ in
            let link = try await Support.bridge(node, bridge, to: server)
            try await link.peer.send(Array("bye".utf8), final: true)
            link.peer.connection.cancel()
            #expect(try await Support.readToEnd(link.client) == Array("bye".utf8))
            await link.client.close()
            #expect(await link.finished() == nil)
        }
    }

    @Test("If the loopback server resets, the tailnet side disconnects with reset")
    func loopbackResetResetsTailnet() async throws {
        try await Self.withBridge { node, bridge, server, _ in
            let link = try await Support.bridge(node, bridge, to: server)
            try await link.peer.send([7], final: false)
            #expect(try await link.client.read() == [7])
            link.peer.connection.forceCancel()
            #expect(await Support.error { try await Support.readToEnd(link.client) } == .reset)
            #expect(await link.finished() == nil)
        }
    }

    /// The loopback connection breaks after FIN has already ended the read direction (loopback → tailnet). Only the write result can reveal it.
    @Test("If the tailnet side keeps writing after the loopback server fully closes, the tailnet side disconnects with reset")
    func writesAfterLoopbackClosedResetTailnet() async throws {
        try await Self.withBridge { node, bridge, server, _ in
            let link = try await Support.bridge(node, bridge, to: server)
            try await link.peer.send([], final: true)
            link.peer.connection.cancel()
            #expect(try await link.client.read() == nil)
            let chunk = [UInt8](repeating: 0xEE, count: 64 << 10)
            var outcome: ConnectionError?
            for _ in 0..<1_000 {
                outcome = await Support.error { try await link.client.write(chunk) }
                if outcome != nil { break }
                try await Task.sleep(for: .milliseconds(5))
            }
            #expect(outcome == .reset)
            #expect(await link.finished() == nil)
        }
    }

    @Test("Canceling the Task that called forward resets both connections and throws cancelled")
    func cancellingForwardResetsBoth() async throws {
        try await Self.withBridge { node, bridge, server, _ in
            let link = try await Support.bridge(node, bridge, to: server)
            try await link.client.write([1])
            #expect(await link.peer.read() == .bytes([1]))
            link.forwarding.cancel()
            #expect(await link.finished() == .cancelled)
            Self.expectReset(await link.peer.readToEnd())
            #expect(await Support.error { try await link.client.read() } == .reset)
        }
    }

    // MARK: Failure before connecting (behavior B1)

    @Test("A port with no listener and port 0 yield loopbackUnavailable and reset the tailnet connection")
    func noListener() async throws {
        try await Self.withBridge { node, bridge, _, _ in
            let closedPort = try await PlainLoopbackServer.unusedPort()
            for (index, port) in [closedPort, UInt16(0)].enumerated() {
                let pair = try await Support.connectedPair(node, port: 9_000 + UInt16(index))
                let forwarding = Support.forward(pair.server, with: bridge, toLoopbackPort: port)
                guard case .loopbackUnavailable = await forwarding.value else {
                    Issue.record("Expected loopbackUnavailable for port \(port)")
                    continue
                }
                #expect(await Support.error { try await pair.client.read() } == .reset)
            }
        }
    }

    @Test("A missing identity yields unknownPeer, skips the loopback connection, and resets the tailnet connection")
    func unknownPeer() async throws {
        try await Self.withBridge(try Support.netmap(withProfile: false)) { node, bridge, server, _ in
            let pair = try await Support.connectedPair(node)
            #expect(await node.whoIs(pair.server.remoteEndpoint.address) == nil)
            #expect(await Support.forward(pair.server, with: bridge, toLoopbackPort: server.port).value == .unknownPeer)
            #expect(await Support.error { try await pair.client.read() } == .reset)
            try await Task.sleep(for: .milliseconds(200))
            #expect(server.acceptedCount == 0)
        }
    }

    @Test("When forwarded connections are at the limit, yields limitReached and resets the tailnet connection. Accepts more when one ends")
    func limitReached() async throws {
        #expect(LoopbackBridge(node: try TailnetNode(configuration: Self.unusedConfiguration())).connectionLimit == 256)
        try await Support.withRunningNode(try Support.netmap()) { node, _ in
            let bridge = LoopbackBridge(node: node, connectionLimit: 2)
            let server = try await PlainLoopbackServer.start(admittingFor: bridge)
            defer { server.close() }
            let first = try await Support.bridge(node, bridge, to: server, port: 9_000)
            let second = try await Support.bridge(node, bridge, to: server, port: 9_001)

            let third = try await Support.connectedPair(node, port: 9_002)
            #expect(await Support.forward(third.server, with: bridge, toLoopbackPort: server.port).value == .limitReached)
            #expect(await Support.error { try await third.client.read() } == .reset)
            #expect(server.acceptedCount == 2)

            await first.client.abort()
            #expect(await first.finished() == nil)
            let fourth = try await Support.bridge(node, bridge, to: server, port: 9_003)
            await second.client.abort()
            await fourth.client.abort()
            #expect(await second.finished() == nil)
            #expect(await fourth.finished() == nil)
        }
    }

    // MARK: Helpers

    private static func expectReset(_ received: PeerConnection.Received, sourceLocation: SourceLocation = #_sourceLocation) {
        guard case .failed(_, let error) = received else {
            Issue.record("The loopback server's read did not end with an error: \(received)", sourceLocation: sourceLocation)
            return
        }
        #expect(error.contains("Connection reset"), "\(error)", sourceLocation: sourceLocation)
    }

    private static func unusedConfiguration() throws -> NodeConfiguration {
        NodeConfiguration(
            stateDirectory: try #require(URL(string: "file:///var/empty/swiftail-test/")), hostname: "rd-mac-1a2b3c4d",
            controlURL: try #require(URL(string: "http://127.0.0.1:9")))
    }
}

/// Criteria for backpressure tests.
///
/// The bridge holds 64KiB per direction. Further data can fit in the tailnet connection's send buffer and receive window (256KiB each),
/// and in `NWConnection`'s buffers and the kernel's loopback TCP buffers. Without backpressure, all the data sent is accepted. On macOS in 2026-11, the amount accepted before blocking was
/// 1.2~1.7MiB.
enum BackpressureProbe {
    /// The amount to send. All of it is accepted if writing never blocks.
    static let attempt = 16 << 20
    /// The upper bound on the amount accepted when writing blocks.
    static let bound = 8 << 20

    /// Returns `progress` once it stays unchanged for 300ms (writing has blocked). If it does not block within 20 seconds, returns the value at that point.
    static func stalled(_ progress: () -> Int) async throws -> Int {
        var last = -1
        var stableSince = ContinuousClock.now
        let deadline = ContinuousClock.now + .seconds(20)
        while ContinuousClock.now < deadline {
            let current = progress()
            if current != last {
                last = current
                stableSince = .now
            } else if ContinuousClock.now - stableSince >= .milliseconds(300) {
                return current
            }
            try await Task.sleep(for: .milliseconds(10))
        }
        return progress()
    }
}
