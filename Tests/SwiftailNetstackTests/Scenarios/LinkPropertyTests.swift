import SwiftailNetstack
import Testing

/// All combinations in contract test 12. Compares the actual bytes for 1MiB in both directions in each combination.
@Suite("Independent link properties", .serialized)
struct LinkPropertyTests {
    struct Scenario: Sendable, CustomTestStringConvertible {
        let loss: Int
        let reorder: Bool
        let duplicate: Bool
        let delay: Int
        let seed: UInt64
        var testDescription: String {
            "loss=\(loss), reorder=\(reorder), duplicate=\(duplicate), delay=\(delay)ms, seed=\(seed)"
        }
        var policy: LinkSimulator.Policy {
            .init(delay: .milliseconds(delay), lossPercent: loss, reorder: reorder, duplicate: duplicate)
        }
    }

    static let scenarios: [Scenario] = [0, 1, 5, 20].flatMap { loss in
        [false, true].flatMap { reorder in
            [false, true].flatMap { duplicate in
                [1, 50, 500].flatMap { delay in
                    [UInt64(1), 0x5EED].map { seed in
                        Scenario(loss: loss, reorder: reorder, duplicate: duplicate, delay: delay, seed: seed)
                    }
                }
            }
        }
    }

    @Test("Transfers 1MiB in both directions for all combinations of loss, reordering, duplication, and delay", arguments: scenarios)
    func bidirectionalMatrix(_ scenario: Scenario) throws {
        var link = try LinkSimulator(seed: scenario.seed, clientPolicy: scenario.policy, serverPolicy: scenario.policy)
        link.recordsTransmissions = false
        do {
            try transferAndClose(&link, size: 1_048_576)
        } catch {
            print("Failure \(scenario.testDescription): \(link.diagnostic)")
            throw error
        }
        let reasons = link.events.map { $0.compactMap { event -> TCPConnection.CloseReason? in
            if case let .closed(reason) = event { reason } else { nil }
        } }
        print("Link \(scenario.testDescription): elapsed=\(link.elapsed), sent=\(link.sentCounts), dropped=\(link.droppedCounts), fingerprint=\(link.fingerprint), closed=\(reasons)")
    }

    @Test("Empty and small writes, MSS boundaries, and sequence wraparound", arguments: [0, 1, 1239, 1240, 1241, 16_384, 1_048_576])
    func sizesAndSequenceWrap(_ size: Int) throws {
        let policy = LinkSimulator.Policy(delay: .milliseconds(3), lossPercent: 5, reorder: true, duplicate: true)
        var link = try LinkSimulator(seed: 42, clientISS: 0xFFFF_F000, serverISS: 0xFFFF_FF00,
                                     clientPolicy: policy, serverPolicy: policy)
        link.recordsTransmissions = false
        try transferAndClose(&link, size: size)
    }

    @Test("The same seed yields the same transmission trace and virtual time")
    func seededReplayIsDeterministic() throws {
        let policy = LinkSimulator.Policy(delay: .milliseconds(7), lossPercent: 20, reorder: true, duplicate: true)
        var first = try LinkSimulator(seed: 711, clientPolicy: policy, serverPolicy: policy)
        var second = try LinkSimulator(seed: 711, clientPolicy: policy, serverPolicy: policy)
        try transferAndClose(&first, size: 32_768)
        try transferAndClose(&second, size: 32_768)
        #expect(first.transmissions == second.transmissions)
        #expect(first.elapsed == second.elapsed)
        #expect(first.fingerprint == second.fingerprint)
    }

    @Test("A peer that does not read stalls at the window and send buffer limits and resumes when it reads")
    func unreadReceiverAppliesBackpressure() throws {
        var link = try LinkSimulator(seed: 53)
        try link.open()
        let bytes = scenarioBytes(786_432)
        var accepted = 0
        try link.run(for: .seconds(10), application: { link in
            if try link.connection(.client).writableByteCount > 0, accepted < bytes.count {
                accepted += try link.write(bytes[accepted...], from: .client)
            }
        }, until: { link in
            link.connections[1]?.readableByteCount == 262_144
                && link.connections[0]?.writableByteCount == 0
                && link.connections[0]?.sendWindow == 0
        })
        #expect(accepted == 524_288)
        try link.advance(by: .seconds(3))
        #expect(try link.connection(.server).readableByteCount == 262_144)
        #expect(try link.connection(.client).unacknowledgedSendByteCount == 262_144)
        var received = 0
        try link.run(for: .seconds(60), application: { link in
            // The application reads all available data. Reading does not always emit a window update ACK (F3), so data remains if it waits for the next event.
            while case let chunk = try link.read(from: .server), !chunk.isEmpty {
                #expect(chunk.elementsEqual(bytes[received..<(received + chunk.count)]))
                received += chunk.count
            }
            if accepted < bytes.count, try link.connection(.client).writableByteCount > 0 {
                accepted += try link.write(bytes[accepted...], from: .client)
            }
        }, until: { link in received == bytes.count && link.connections[0]?.unacknowledgedSendByteCount == 0 })
        #expect(received == bytes.count)
    }

    @Test("Reports a stall when arrivals and timers repeat without byte progress")
    func detectsStall() throws {
        var link = try LinkSimulator(seed: 54)
        try link.open()
        do {
            try link.run(for: .seconds(20_000), stallLimit: .seconds(10), until: { _ in false })
            Issue.record("A link with no progress must be classified as stalled")
        } catch LinkSimulator.Failure.stalled(let seed, _) {
            #expect(seed == 54)
        }
    }

    @Test("Reports a busy loop for unbounded input at the same time")
    func detectsBusyLoop() throws {
        var link = try LinkSimulator(seed: 55)
        try link.open()
        let client = try link.connection(.client)
        let server = try link.connection(.server)
        let acknowledgment = TCPSegment(source: server.localEndpoint, destination: client.localEndpoint,
                                         sequenceNumber: client.receiveNext,
                                         acknowledgmentNumber: client.sendUnacknowledged, flags: .ack, window: 32_768)
        do {
            try link.run(for: .seconds(1), application: { $0.inject(acknowledgment, from: .server) }, until: { _ in false })
            Issue.record("Must detect endless input at the same time")
        } catch LinkSimulator.Failure.busyLoop(let seed) {
            #expect(seed == 55)
        }
    }

    @Test("Also reports a stall for an unfinished link with no input or deadline")
    func detectsMissingDeadline() throws {
        var link = try LinkSimulator(seed: 56, clientPolicy: .init(lossPercent: 100))
        try link.abort(.client)
        do {
            try link.run(for: .seconds(1), until: { _ in false })
            Issue.record("Must not wait indefinitely without input or a deadline")
        } catch LinkSimulator.Failure.noDeadline(let seed) {
            #expect(seed == 56)
        }
    }

    @Test("close with unread data clears both sides' timers with RST")
    func unreadCloseResetsPeer() throws {
        var link = try LinkSimulator(seed: 57)
        try link.open()
        #expect(try link.write([1, 2, 3][...], from: .server) == 3)
        try link.run(for: .seconds(1), until: { $0.connections[0]?.readableByteCount == 3 })
        try link.close(.client)
        try link.run(for: .seconds(1), until: { $0.connections.allSatisfy { $0?.state == .closed } })
        #expect(link.events[0].contains(.closed(.aborted)))
        #expect(link.events[1].contains(.closed(.reset)))
        #expect(link.connections.allSatisfy { $0?.nextDeadline == nil })
    }

    private func transferAndClose(_ link: inout LinkSimulator, size: Int) throws {
        try link.open()
        #expect(try link.write([], from: .client) == 0)
        let payloads = [scenarioBytes(size, salt: 11), scenarioBytes(size, salt: 29)]
        var accepted = [0, 0]
        var received = [0, 0]
        // The R1 RTO cap is 120 seconds. At 20% loss, consecutive losses of retransmissions at the cap and their ACKs can cause a long gap in progress (seed=1,
        // at 1ms delay, five retransmissions and two ACKs were lost in a row, and 960.003 seconds was observed. 2026-11-15). Retransmitting the same segment 15 times
        // ends the connection with `timedOut` (R4), so a longer period without progress means a stall. Set the threshold to 16 times the RTO cap.
        try link.run(for: .seconds(14_400), stallLimit: .seconds(1_920), application: { link in
            for side in LinkSimulator.Side.allCases {
                let index = side.rawValue
                if accepted[index] < size, try link.connection(side).writableByteCount > 0 {
                    accepted[index] += try link.write(payloads[index][accepted[index]...], from: side)
                }
                // Read all available data. Reading does not always emit a window update ACK (F3), so data remains if it waits for the next event.
                while case let chunk = try link.read(from: side.peer), !chunk.isEmpty {
                    // Comparing each read portion with the original catches duplication, reordered bytes, and omissions sooner than a final hash.
                    guard received[index] + chunk.count <= size else {
                        throw LinkSimulator.Failure.invariant(seed: link.seed, detail: "Read more bytes than were sent")
                    }
                    guard chunk.elementsEqual(payloads[index][received[index]..<(received[index] + chunk.count)]) else {
                        throw LinkSimulator.Failure.invariant(seed: link.seed, detail: "Received bytes are not a prefix of the original")
                    }
                    received[index] += chunk.count
                }
            }
        }, until: { link in
            received == [size, size] && link.connections.allSatisfy { $0?.unacknowledgedSendByteCount == 0 }
        })
        try link.finish(.client)
        try link.run(for: .seconds(1_000), until: { $0.connections[1]?.hasReceivedEndOfStream == true })
        try link.finish(.server)
        // The 120-second maximum RTO in R1 is longer than the 60-second TIME-WAIT in contract T6. If the final ACK is lost,
        // the peer can exhaust R4's 15 retransmissions, so set the close limit above 16×120+60 seconds.
        try link.run(for: .seconds(2_000), stallLimit: .seconds(2_000),
                     until: { $0.connections.allSatisfy { $0?.state == .closed } })
        for side in LinkSimulator.Side.allCases {
            #expect(try link.connection(side).nextDeadline == nil)
            #expect(link.events[side.rawValue].contains { if case .closed = $0 { true } else { false } })
        }
    }
}
