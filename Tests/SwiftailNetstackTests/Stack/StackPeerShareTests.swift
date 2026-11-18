import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// One peer cannot exhaust another peer's quota (M6 review A): 64 connections and 64 TIME-WAIT records per remote address,
/// and a record lifetime of 240 seconds. Contract behavior S, "Changes from the Review," M.
@Suite("Stack per-peer quota")
struct StackPeerShareTests {
    static let server = IPEndpoint(address: WireHosts.v4b, port: 443)

    // MARK: Connections

    @Test("Allows up to 64 connections per remote address, including connections released by the application but still closing. Other addresses are unaffected")
    func connectionsPerAddress() throws {
        let now = ContinuousClock.now
        var stack = StackHosts.makeStack(addresses: StackHosts.serverAddresses, now: now)
        let listener = try stack.listen(on: 443)
        let address = StackHosts.peer(1)
        var ids: [TCPStack.ConnectionID] = []
        for port in UInt16(1_000)..<1_064 {
            let peer = IPEndpoint(address: address, port: port)
            ids.append(try stack.acceptHandmade(from: peer, to: Self.server, listener: listener, at: now))
        }
        #expect(stack.connections.count == 64)
        let extra = peerSegment(from: IPEndpoint(address: address, port: 1_064), to: Self.server, flags: [.syn])
        #expect(stack.receive(extra.packet, at: now) == [.dropped(.limitReached(.connectionsPerAddress))])
        expectStackInvariants(stack)
        #expect(throws: TCPStack.ConnectError.limitReached) {
            try stack.connect(to: IPEndpoint(address: address, port: 80), at: now)
        }
        // Accepts connections from and connects to a different address.
        let other = peerSegment(from: IPEndpoint(address: StackHosts.peer(2), port: 1_000), to: Self.server, flags: [.syn])
        #expect(stack.receive(other.packet, at: now).segments.map(\.flags) == [[.syn, .ack]])
        _ = try stack.connect(to: IPEndpoint(address: StackHosts.peer(3), port: 80), at: now)

        // A connection released with close keeps its slot while exchanging FINs.
        _ = stack.close(ids[0], at: now)
        #expect(stack.connections[ids[0]]?.role == .released)
        #expect(stack.receive(extra.packet, at: now) == [.dropped(.limitReached(.connectionsPerAddress))])
        // A connection ended with abort releases its slot. The 65th SYN is accepted afterward.
        _ = stack.abort(ids[1], at: now)
        #expect(stack.receive(extra.packet, at: now).segments.map(\.flags) == [[.syn, .ack]])
        expectStackInvariants(stack)
    }

    // MARK: TIME-WAIT records

    @Test("Allows up to 64 records per remote address. The 65th evicts that address's oldest record. Records for other addresses stay intact")
    func timeWaitRecordsPerAddress() throws {
        let start = ContinuousClock.now
        var stack = StackHosts.makeStack(addresses: StackHosts.serverAddresses, now: start)
        let listener = try stack.listen(on: 443)
        let otherID = try stack.acceptHandmade(
            from: IPEndpoint(address: StackHosts.peer(2), port: 1_000), to: Self.server, listener: listener, at: start)
        let other = try stack.closeIntoTimeWait(otherID, at: start)
        var tuples: [FourTuple] = []
        for index in 0..<65 {
            let now = start + .milliseconds(index + 1)
            let peer = IPEndpoint(address: StackHosts.peer(1), port: UInt16(2_000 + index))
            let id = try stack.acceptHandmade(from: peer, to: Self.server, listener: listener, at: now)
            tuples.append(try stack.closeIntoTimeWait(id, at: now))
            if index == 63 {
                #expect(stack.timeWaitRecords.count == 65)
                #expect(tuples.allSatisfy { stack.timeWaitRecords[$0] != nil })
            }
        }
        #expect(stack.connections.isEmpty)
        #expect(stack.timeWaitRecords[tuples[0]] == nil)
        #expect(tuples.dropFirst().allSatisfy { stack.timeWaitRecords[$0] != nil })
        #expect(stack.timeWaitRecords[other] != nil)
        #expect(stack.timeWaitRecords.count == 65)
        expectStackInvariants(stack)
    }

    @Test("Record lifetime is at most 240 seconds from creation. Each FIN retransmission restarts the 60-second timer without extending it beyond that limit")
    func timeWaitRecordLifetime() throws {
        let created = ContinuousClock.now
        var stack = StackHosts.makeStack(addresses: StackHosts.serverAddresses, now: created)
        let listener = try stack.listen(on: 443)
        let id = try stack.acceptHandmade(
            from: IPEndpoint(address: StackHosts.peer(1), port: 1_000), to: Self.server, listener: listener, at: created)
        let tuple = try stack.closeIntoTimeWait(id, at: created)
        #expect(stack.timeWaitRecords[tuple]?.deadline == created + .seconds(60))

        for second in [59, 118, 177] {
            #expect(stack.retransmitFin(to: tuple, at: created + .seconds(second)).map(\.flags) == [[.ack]])
            #expect(stack.timeWaitRecords[tuple]?.deadline == created + .seconds(second + 60))
        }
        #expect(stack.retransmitFin(to: tuple, at: created + .seconds(236)).map(\.flags) == [[.ack]])
        #expect(stack.timeWaitRecords[tuple]?.deadline == created + .seconds(240))
        #expect(stack.nextDeadline == created + .seconds(240))

        // Just before the deadline, the record remains, answers FIN, and keeps its deadline. It disappears at the deadline.
        let justBefore = created + .seconds(240) - .milliseconds(1)
        _ = stack.advance(to: justBefore)
        #expect(stack.retransmitFin(to: tuple, at: justBefore).map(\.flags) == [[.ack]])
        #expect(stack.timeWaitRecords[tuple]?.deadline == created + .seconds(240))
        expectStackInvariants(stack)
        _ = stack.advance(to: created + .seconds(240))
        #expect(stack.timeWaitRecords.isEmpty)
        expectStackInvariants(stack)
    }

    @Test("An address cannot keep its records even by creating 1,024 and resending FIN every 59 seconds. SYNs and connect still work for other peers")
    func timeWaitRecordsCannotBeHeld() throws {
        let start = ContinuousClock.now
        var stack = StackHosts.makeStack(addresses: StackHosts.serverAddresses, now: start)
        let listener = try stack.listen(on: 443)
        var tuples: [FourTuple] = []
        for index in 0..<1_024 {
            let peer = IPEndpoint(address: StackHosts.peer(1), port: UInt16(2_000 + index))
            let id = try stack.acceptHandmade(from: peer, to: Self.server, listener: listener, at: start)
            tuples.append(try stack.closeIntoTimeWait(id, at: start))
        }
        #expect(stack.timeWaitRecords.count == 64)
        for second in [59, 118, 177, 236, 295] {
            let now = start + .seconds(second)
            _ = stack.advance(to: now)
            for tuple in tuples {
                _ = stack.retransmitFin(to: tuple, at: now)
            }
            expectStackInvariants(stack)
        }
        let now = start + .seconds(295)
        #expect(stack.timeWaitRecords.isEmpty)
        let syn = peerSegment(from: IPEndpoint(address: StackHosts.peer(2), port: 1_000), to: Self.server, flags: [.syn])
        #expect(stack.receive(syn.packet, at: now).segments.map(\.flags) == [[.syn, .ack]])
        _ = try stack.connect(to: IPEndpoint(address: StackHosts.peer(3), port: 80), at: now)
        expectStackInvariants(stack)
    }
}
