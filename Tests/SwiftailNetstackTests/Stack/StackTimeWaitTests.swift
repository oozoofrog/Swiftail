import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// TIME-WAIT records: ACK and restart the timer for retransmitted FIN, ignore RST, send a challenge ACK for SYN, and retain the record until its deadline.
/// Contract `docs/contracts/SwiftailNetstack.md` behaviors S6, T6, and test 11.
@Suite("Stack TIME-WAIT records")
struct StackTimeWaitTests {
    /// Returns a pair in which the client closed first and left one TIME-WAIT record, and the record itself.
    func pairWithRecord() throws -> (pair: StackPair, tuple: FourTuple, record: TimeWaitRecord) {
        var pair = StackPair()
        let listener = try pair.server.listen(on: 443)
        try pair.closeFromClient(try pair.open(listener: listener))
        guard pair.client.timeWaitRecords.count == 1, pair.client.connections.isEmpty,
            let (tuple, record) = pair.client.timeWaitRecords.first
        else { throw HarnessError(description: "Expected exactly one TIME-WAIT record") }
        return (pair, tuple, record)
    }

    @Test("The record contains the connection's final numbers and a deadline 60 seconds away. It stays until the deadline and disappears then")
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

    @Test("Acknowledges the peer's retransmitted FIN and resets the deadline to 60 seconds later")
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

    @Test("Ignores RST without deleting the record. Does not respond to a data-free ACK")
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

    @Test("A SYN for the same 4-tuple gets an ACK and does not become a new connection (even with a listener)")
    func synchronizeOnRecord() throws {
        var (pair, tuple, record) = try pairWithRecord()
        _ = try pair.client.listen(on: tuple.local.port)
        let syn = peerSegment(from: tuple.remote, to: tuple.local, sequence: 123_456, flags: [.syn])
        let reply = pair.client.receive(syn.packet, at: pair.now).segments
        #expect(reply.map(\.flags) == [[.ack]])
        #expect(reply.first?.acknowledgmentNumber == record.receiveNext)
        #expect(pair.client.connections.isEmpty)
        #expect(pair.client.halfOpenCount == 0)
        // Responds with ACK to a segment carrying data as well.
        let data = peerSegment(
            from: tuple.remote, to: tuple.local, sequence: record.receiveNext.rawValue, acknowledgment: record.sendNext,
            flags: [.ack], payload: [1, 2])
        #expect(pair.client.receive(data.packet, at: pair.now).segments.map(\.flags) == [[.ack]])
        #expect(pair.client.timeWaitRecords[tuple] == record)
    }

    @Test("Data the application left unread after only finishing its writes remains readable after TIME-WAIT and disappears when close releases the connection")
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
