import SwiftailNetstack
import Testing

/// 계약 시험 12의 전 조합. 각 조합에서 양방향 1MiB를 실제 바이트로 비교한다.
@Suite("독립 링크 속성", .serialized)
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

    @Test("손실·재정렬·중복·지연 전 조합에서 양방향 1MiB", arguments: scenarios)
    func bidirectionalMatrix(_ scenario: Scenario) throws {
        var link = try LinkSimulator(seed: scenario.seed, clientPolicy: scenario.policy, serverPolicy: scenario.policy)
        link.recordsTransmissions = false
        do {
            try transferAndClose(&link, size: 1_048_576)
        } catch {
            print("실패 \(scenario.testDescription): \(link.diagnostic)")
            throw error
        }
        let reasons = link.events.map { $0.compactMap { event -> TCPConnection.CloseReason? in
            if case let .closed(reason) = event { reason } else { nil }
        } }
        print("링크 \(scenario.testDescription): elapsed=\(link.elapsed), sent=\(link.sentCounts), dropped=\(link.droppedCounts), fingerprint=\(link.fingerprint), closed=\(reasons)")
    }

    @Test("빈 쓰기·작은 쓰기·MSS 경계와 순환 번호", arguments: [0, 1, 1239, 1240, 1241, 16_384, 1_048_576])
    func sizesAndSequenceWrap(_ size: Int) throws {
        let policy = LinkSimulator.Policy(delay: .milliseconds(3), lossPercent: 5, reorder: true, duplicate: true)
        var link = try LinkSimulator(seed: 42, clientISS: 0xFFFF_F000, serverISS: 0xFFFF_FF00,
                                     clientPolicy: policy, serverPolicy: policy)
        link.recordsTransmissions = false
        try transferAndClose(&link, size: size)
    }

    @Test("같은 씨앗이면 전송 기록과 가상 시간이 같다")
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

    @Test("읽지 않는 상대는 창·송신 버퍼에서 멈추고 읽으면 재개한다")
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
            // 응용은 읽을 수 있는 것을 다 읽는다. 읽기가 늘 창 갱신 ACK를 내지는 않으므로(F3) 다음 사건을 기다리면 남는다.
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

    @Test("도착·타이머만 반복하고 바이트 진행이 없으면 멈춤으로 보고한다")
    func detectsStall() throws {
        var link = try LinkSimulator(seed: 54)
        try link.open()
        do {
            try link.run(for: .seconds(20_000), stallLimit: .seconds(10), until: { _ in false })
            Issue.record("진행 없는 링크를 멈춤으로 판정해야 한다")
        } catch LinkSimulator.Failure.stalled(let seed, _) {
            #expect(seed == 54)
        }
    }

    @Test("같은 시각에 무한 입력을 넣으면 바쁜 고리로 보고한다")
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
            Issue.record("같은 시각의 끝없는 입력을 판정해야 한다")
        } catch LinkSimulator.Failure.busyLoop(let seed) {
            #expect(seed == 55)
        }
    }

    @Test("입력·기한 없이 미완료인 링크도 멈춤으로 보고한다")
    func detectsMissingDeadline() throws {
        var link = try LinkSimulator(seed: 56, clientPolicy: .init(lossPercent: 100))
        try link.abort(.client)
        do {
            try link.run(for: .seconds(1), until: { _ in false })
            Issue.record("입력·기한이 없으면 끝없이 기다리지 않아야 한다")
        } catch LinkSimulator.Failure.noDeadline(let seed) {
            #expect(seed == 56)
        }
    }

    @Test("읽지 않은 데이터를 둔 close는 RST로 양쪽 타이머를 정리한다")
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
        // R1의 RTO 상한은 120초다. 손실 20%에서 상한에 닿은 재전송과 그 ACK가 연달아 사라지면 오래 진행이 없다(seed=1,
        // 지연 1ms에서 재전송 다섯과 ACK 둘이 연달아 사라져 960.003초를 관찰했다. 2026-11-15). 같은 세그먼트를 15번 다시
        // 보내면 연결이 `timedOut`으로 끝나므로(R4) 그보다 길게 진행이 없으면 멈춘 것이다. 판정은 RTO 상한의 16배로 둔다.
        try link.run(for: .seconds(14_400), stallLimit: .seconds(1_920), application: { link in
            for side in LinkSimulator.Side.allCases {
                let index = side.rawValue
                if accepted[index] < size, try link.connection(side).writableByteCount > 0 {
                    accepted[index] += try link.write(payloads[index][accepted[index]...], from: side)
                }
                // 읽을 수 있는 것을 다 읽는다. 읽기가 늘 창 갱신 ACK를 내지는 않으므로(F3) 다음 사건을 기다리면 남는다.
                while case let chunk = try link.read(from: side.peer), !chunk.isEmpty {
                    // 읽힌 부분마다 원본과 비교하므로 중복·순서 역전·누락을 마지막 해시보다 일찍 잡는다.
                    guard received[index] + chunk.count <= size else {
                        throw LinkSimulator.Failure.invariant(seed: link.seed, detail: "보낸 것보다 많이 읽음")
                    }
                    guard chunk.elementsEqual(payloads[index][received[index]..<(received[index] + chunk.count)]) else {
                        throw LinkSimulator.Failure.invariant(seed: link.seed, detail: "받은 바이트열이 원본의 앞부분이 아님")
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
        // 계약 T6의 TIME-WAIT 60초보다 R1의 최대 RTO 120초가 길다. 마지막 ACK가 사라지면
        // 상대는 R4의 15회 재전송을 소진할 수 있으므로 종료 상한은 16×120+60초보다 크게 둔다.
        try link.run(for: .seconds(2_000), stallLimit: .seconds(2_000),
                     until: { $0.connections.allSatisfy { $0?.state == .closed } })
        for side in LinkSimulator.Side.allCases {
            #expect(try link.connection(side).nextDeadline == nil)
            #expect(link.events[side.rawValue].contains { if case .closed = $0 { true } else { false } })
        }
    }
}
