import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// TIME-WAIT 기록: FIN 재전송에 ACK하고 기한을 다시 잼, RST 무시, SYN에 challenge ACK, 기한 전에 남음.
/// 계약 `docs/contracts/SwiftailNetstack.md` 동작 S6, T6과 시험 11.
@Suite("스택: TIME-WAIT 기록")
struct StackTimeWaitTests {
    /// 클라이언트가 먼저 닫아 TIME-WAIT 기록 하나가 남은 쌍과 그 기록.
    func pairWithRecord() throws -> (pair: StackPair, tuple: FourTuple, record: TimeWaitRecord) {
        var pair = StackPair()
        let listener = try pair.server.listen(on: 443)
        try pair.closeFromClient(try pair.open(listener: listener))
        guard pair.client.timeWaitRecords.count == 1, pair.client.connections.isEmpty,
            let (tuple, record) = pair.client.timeWaitRecords.first
        else { throw HarnessError(description: "TIME-WAIT 기록이 하나가 아니다") }
        return (pair, tuple, record)
    }

    @Test("기록은 연결의 마지막 번호와 60초 뒤의 기한을 담는다. 기한 전에 남고 기한에 사라진다")
    func recordLifetime() throws {
        var (pair, tuple, record) = try pairWithRecord()
        let lastClientSegment = try #require(pair.clientSent.last)
        #expect(record.sendNext == lastClientSegment.sequenceNumber)
        #expect(record.receiveNext == lastClientSegment.acknowledgmentNumber)
        #expect(record.deadline == pair.now + .seconds(60))
        #expect(tuple.local.address == WireHosts.v4a)
        #expect(pair.client.nextDeadline == record.deadline)
        _ = pair.client.advance(to: record.deadline - .milliseconds(1))
        #expect(pair.client.timeWaitRecords.count == 1)
        _ = pair.client.advance(to: record.deadline)
        #expect(pair.client.timeWaitRecords.isEmpty)
    }

    @Test("상대 FIN의 재전송에 ACK하고 기한을 60초 뒤로 다시 잰다")
    func finRetransmission() throws {
        var (pair, tuple, record) = try pairWithRecord()
        let later = pair.now + .seconds(30)
        let finAgain = peerSegment(
            from: tuple.remote, to: tuple.local, sequence: record.receiveNext.advanced(by: .max).rawValue,
            acknowledgment: record.sendNext, flags: [.fin, .ack])
        let reply = pair.client.receive(finAgain.packet, at: later).segments
        #expect(reply.count == 1)
        #expect(reply.first?.flags == [.ack])
        #expect(reply.first?.sequenceNumber == record.sendNext)
        #expect(reply.first?.acknowledgmentNumber == record.receiveNext)
        #expect(reply.first?.source == tuple.local)
        #expect(pair.client.timeWaitRecords[tuple]?.deadline == later + .seconds(60))
    }

    @Test("RST는 무시하고 기록을 지우지 않는다. 데이터 없는 ACK에는 답하지 않는다")
    func resetAndPureAcknowledgment() throws {
        var (pair, tuple, record) = try pairWithRecord()
        let reset = peerSegment(
            from: tuple.remote, to: tuple.local, sequence: record.receiveNext.rawValue, flags: [.rst])
        #expect(pair.client.receive(reset.packet, at: pair.now).isEmpty)
        let ack = peerSegment(
            from: tuple.remote, to: tuple.local, sequence: record.receiveNext.rawValue,
            acknowledgment: record.sendNext, flags: [.ack])
        #expect(pair.client.receive(ack.packet, at: pair.now).isEmpty)
        #expect(pair.client.timeWaitRecords[tuple] == record)
    }

    @Test("같은 4-튜플의 SYN은 새 연결이 되지 않고 ACK로 답한다(리스너가 있어도)")
    func synchronizeOnRecord() throws {
        var (pair, tuple, record) = try pairWithRecord()
        _ = try pair.client.listen(on: tuple.local.port)
        let syn = peerSegment(from: tuple.remote, to: tuple.local, sequence: 123_456, flags: [.syn])
        let reply = pair.client.receive(syn.packet, at: pair.now).segments
        #expect(reply.map(\.flags) == [[.ack]])
        #expect(reply.first?.acknowledgmentNumber == record.receiveNext)
        #expect(pair.client.connections.isEmpty)
        #expect(pair.client.halfOpenCount == 0)
        // 데이터가 실린 세그먼트에도 ACK로 답한다.
        let data = peerSegment(
            from: tuple.remote, to: tuple.local, sequence: record.receiveNext.rawValue, acknowledgment: record.sendNext,
            flags: [.ack], payload: [1, 2])
        #expect(pair.client.receive(data.packet, at: pair.now).segments.map(\.flags) == [[.ack]])
        #expect(pair.client.timeWaitRecords[tuple] == record)
    }

    @Test("응용이 쓰기만 끝내고 읽지 않은 데이터는 TIME-WAIT 뒤에도 읽히고, close로 놓을 때 사라진다")
    func leftoverDataAfterTimeWait() throws {
        var pair = StackPair()
        let listener = try pair.server.listen(on: 443)
        let ids = try pair.open(listener: listener)
        pair.collect(pair.client.finishWriting(ids.client, at: pair.now), from: .client)
        try pair.deliver()
        _ = pair.write([4, 5, 6], to: ids.server, from: .server)
        pair.collect(pair.server.close(ids.server, at: pair.now), from: .server)
        try pair.deliver()
        #expect(
            pair.clientEvents.suffix(3).map(\.withoutStatistics)
                == [.readable(ids.client), .endOfStream(ids.client), .closed(ids.client, .finished, .unchecked)])
        #expect(pair.client.timeWaitRecords.count == 1)
        #expect(pair.client.connectionsByTuple.isEmpty)
        #expect(pair.client.nextDeadline == pair.client.timeWaitRecords.first?.value.deadline)
        #expect(pair.read(ids.client, from: .client) == [4, 5, 6])
        #expect(pair.client.connections.count == 1)
        #expect(pair.client.close(ids.client, at: pair.now).isEmpty)
        #expect(pair.client.connections.isEmpty)
        expectStackInvariants(pair.client)
    }
}
