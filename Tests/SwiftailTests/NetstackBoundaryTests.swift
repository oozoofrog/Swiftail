import Foundation
import SwiftailBase
import Testing
@testable import Swiftail

/// Connection and listener edge cases: rejection, how close and abort wake waiting calls, invalid lengths, `run()` ending at startup validation, and
/// transfer under loss (contract `docs/contracts/SwiftailNetstack.md` behaviors A·N).
///
/// Every connection is from one node to its own address. If a test stalls, the suite's time limit fails it.
@Suite("Node TCP edge cases", .timeLimit(.minutes(1)))
struct NetstackBoundaryTests {
    private typealias Support = NetstackTestSupport

    @Test("Connecting to a local port without a listener yields refused")
    func connectToClosedPortIsRefused() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node in
            #expect(await Support.error { try await node.connect(to: "100.64.0.1", port: 9_001) } == .refused)
            #expect(await node.trackedConnectionCount == 0, "A rejected attempt leaves no record")
        }
    }

    @Test("close wakes a waiting read and write with closed")
    func closeWakesWaiters() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node in
            let pair = try await Support.connectedPair(node)
            // Reads and writes on the same connection can wait concurrently. The server sends nothing, so the client's read waits until the end.
            let reader = Task { () async throws -> [UInt8]? in try await pair.client.read() }
            let writer = Task { () async throws in try await pair.client.write(Support.pattern(1 << 20)) }
            try await Support.waitUntil("read and write are waiting") {
                let reading = await node.isReading(pair.client), writing = await node.isWriting(pair.client)
                return reading && writing
            }
            await pair.client.close()
            #expect(await Support.error { try await reader.value } == .closed)
            #expect(await Support.error { try await writer.value } == .closed)
            await pair.server.close()
        }
    }

    @Test("A peer abort ends a waiting read and write with reset, and a subsequent finishWriting also yields reset")
    func peerAbortEndsWaiters() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node in
            let pair = try await Support.connectedPair(node)
            let reader = Task { () async throws -> [UInt8]? in try await pair.client.read() }
            // The server does not read, so the receive and send buffers fill and write blocks.
            let writer = Task { () async throws in try await pair.client.write(Support.pattern(1 << 20)) }
            try await Support.waitUntil("read and write are waiting") {
                let reading = await node.isReading(pair.client), writing = await node.isWriting(pair.client)
                return reading && writing
            }
            await pair.server.abort()
            #expect(await Support.error { try await reader.value } == .reset)
            #expect(await Support.error { try await writer.value } == .reset)
            #expect(await Support.error { try await pair.client.finishWriting() } == .reset)
            #expect(await Support.error { try await pair.client.read() } == .reset)
            await pair.client.close()
        }
    }

    @Test("A read length of 0 or less yields invalidConfiguration and leaves the connection intact")
    func readRejectsNonPositiveLength() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node in
            let pair = try await Support.connectedPair(node)
            for length in [0, -1] {
                #expect(
                    await Support.error { try await pair.server.read(upTo: length) }
                        == .invalidConfiguration("읽을 길이는 1 이상이어야 한다"))
            }
            try await pair.client.write([5])
            #expect(try await pair.server.read(upTo: 1) == [5])
            await pair.client.close()
            await pair.server.close()
        }
    }

    @Test("If run() ends at startup validation, the stream of a listener opened before run() ends, and subsequent listen calls yield notRunning")
    func listenerEndsWhenRunFailsAtStart() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            let claim = try #require(StateDirectoryClaims.shared.claim(directory))
            defer { StateDirectoryClaims.shared.release(claim) }
            let node = try TailnetNode(
                configuration: try NodeTestSupport.configuration(stateDirectory: directory), device: .inProcess)
            let listener = try await node.listen(port: 9_000)
            let accepter = Task { () async -> TailnetConnection? in
                var connections = listener.makeAsyncIterator()
                return await connections.next()
            }
            try await Support.waitUntil("The stream is waiting") { await node.isAccepting(listener) }

            do throws(NodeError) {
                try await node.run()
                Issue.record("run() did not throw")
            } catch {
                guard case .stateDirectoryInUse = error else {
                    Issue.record("Expected stateDirectoryInUse, got \(error)")
                    return
                }
            }
            #expect(await accepter.value == nil)
            var again = listener.makeAsyncIterator()
            #expect(await again.next() == nil)
            #expect(await Support.error { try await node.listen(port: 9_001) } == .notRunning)
        }
    }

    @Test("All 256KiB arrive byte for byte even with 2% loss")
    func transferSurvivesPacketLoss() async throws {
        let length = 256 * 1_024
        try await Support.withRunningNode(try Support.netmap()) { node in
            let pair = try await Support.connectedPair(node)
            await node.setInProcessLoss(rate: 0.02, seed: 7)
            let upload = Support.pattern(length, seed: 3)
            async let sent: Void = { try await pair.client.write(upload); try await pair.client.finishWriting() }()
            async let received = Support.read(length + 1, from: pair.server)
            try await sent
            #expect(try await received == upload)
            await node.setInProcessLoss(rate: 0, seed: 0)
            await pair.client.close()
            await pair.server.close()
        }
    }

    @Test("Calling finishWriting during a waiting write wakes it with closed, and data already accepted is sent before FIN")
    func finishWritingWakesWaitingWrite() async throws {
        try await Support.withRunningNode(try Support.netmap()) { node in
            let pair = try await Support.connectedPair(node)
            let upload = Support.pattern(1 << 20, seed: 9)
            let writer = Task { () async throws in try await pair.client.write(upload) }
            try await Support.waitUntil("write is waiting") { await node.isWriting(pair.client) }
            try await pair.client.finishWriting()
            #expect(await Support.error { try await writer.value } == .closed)

            let received = try await Support.read(upload.count + 1, from: pair.server)
            #expect(!received.isEmpty && received.count < upload.count)
            #expect(received == Array(upload.prefix(received.count)), "Only data already accepted goes out before FIN, in order")
            #expect(try await pair.server.read() == nil)
            await pair.client.close()
            await pair.server.close()
        }
    }
}
