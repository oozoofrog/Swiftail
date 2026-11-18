import Foundation
import Swiftail
import SwiftailBase
import SwiftailMagicsock
import Testing

/// Rechecks a real-device observation ("the downloading side becomes `relayed` about 100 seconds after a direct path is established") with a real Go peer and real sockets.
/// See "Investigation Results" under "`relayed` About 100 Seconds After a Direct Path Is Established" in `docs/contracts/SwiftailMagicsock.md`.
///
/// Loopback round-trip latency is below 5 ms, so the full Ping path run every minute is rarely exercised. State machine tests
/// (`MagicsockLongSessionTests`) cover that path and Wi-Fi loss.
@Suite("Investigation into the path during a long download", .enabled(if: tailnetBinary != nil,
    "Skipping the long-download investigation because SWIFTAIL_TAILNET is missing"), .serialized, .timeLimit(.minutes(10)))
struct LongDownloadPathTests {
    private static let chunk: UInt64 = 20 * 1_048_576

    @Test("The Swift node's path stays direct for 162 seconds of repeated 26-second downloads from the Go peer and 42-second idle periods")
    func repeatedDownloads() async throws {
        try await withGate(direct: false, device: .inProcess) { gate in
            // Setup verifies that both sides are direct. After that, events arrive only when the path changes.
            let fqdn = try await netstackPrepare(gate)
            let initial = await gate.node.path(toPeerNamed: fqdn)
            let recorder = PathRecorder()
            let started = ContinuousClock.now
            var received: UInt64 = 0
            try await withThrowingTaskGroup(of: UInt64.self) { group in
                defer { group.cancelAll() }
                group.addTask {
                    for await event in gate.node.events {
                        if case let .peerPathChanged(name, path) = event, name == fqdn { await recorder.record(path) }
                    }
                    return 0
                }
                group.addTask {
                    var total: UInt64 = 0
                    for round in 0..<3 {
                        let downloadEnd = started + .seconds(68 * round + 26)
                        while ContinuousClock.now < downloadEnd {
                            let connection = try await netstackDeadline("Long download connect") {
                                try await gate.node.connect(to: gate.peer.address().description, port: 9_100)
                            }
                            try await connection.write(NetstackStream.header(count: Self.chunk, seed: 1))
                            _ = try await netstackExchange(gate, connection: connection, stage: "Long download \(round + 1)",
                                sendCount: 0, receiveCount: Self.chunk)
                            total += Self.chunk
                        }
                        if round < 2 {
                            try await Task.sleep(until: started + .seconds(68 * round + 68), clock: .continuous)
                        }
                    }
                    return total
                }
                received = try #require(try await group.next())
            }
            let events = await recorder.events.map { (started.duration(to: $0.time), $0.path) }
            await gate.tool.checkpoint("Long download: over \(started.duration(to: .now)), \(received / 1_048_576)MiB, path events \(events)")
            #expect(started.duration(to: .now) >= .seconds(150))
            let isDirect: (PeerPath?) -> Bool = { if case .direct = $0 { true } else { false } }
            #expect(isDirect(initial))
            #expect(events.allSatisfy { isDirect($0.1) }, "Path events after direct: \(events)")
        }
    }
}

/// Received path events and their timestamps.
private actor PathRecorder {
    private(set) var events: [(time: ContinuousClock.Instant, path: PeerPath?)] = []

    func record(_ path: PeerPath?) {
        events.append((.now, path))
    }
}
