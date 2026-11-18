import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// A peer's quota is counted across all of its addresses (IPv4 and IPv6). Counting by address alone would give a peer with two addresses twice the quota, letting it fill the listener queue (32) by itself with
/// 16 × 2 opening connections. Contract `docs/contracts/SwiftailNetstack.md`, behavior S, "Per-Peer Quota," M.
@Suite("Stack quota for a peer with multiple addresses")
struct StackPeerGroupTests {
    static let serverV4 = IPEndpoint(address: WireHosts.v4b, port: 443)
    static let serverV6 = IPEndpoint(address: WireHosts.v6b, port: 443)
    /// Two addresses for one peer.
    static let peerV4 = StackHosts.peer(1)
    static let peerV6 = WireHosts.address("fd7a:115c:a1e0::101")
    /// A different peer.
    static let other = IPEndpoint(address: StackHosts.peer(2), port: 1_000)

    /// A server stack that groups two addresses as one peer.
    func makeServer(now: ContinuousClock.Instant = .now) -> TCPStack {
        var stack = StackHosts.makeStack(addresses: StackHosts.serverAddresses, now: now)
        stack.setRemoteAddressGroups([Self.peerV4: 7, Self.peerV6: 7, Self.other.address: 8])
        return stack
    }

    /// Both ends of that peer's connection at `index`. Even indexes use IPv4 and odd indexes use IPv6.
    func endpoints(_ index: Int) -> (peer: IPEndpoint, server: IPEndpoint) {
        let port = UInt16(1_000 + index)
        return index % 2 == 0
            ? (IPEndpoint(address: Self.peerV4, port: port), Self.serverV4)
            : (IPEndpoint(address: Self.peerV6, port: port), Self.serverV6)
    }

    func syn(_ index: Int) -> [UInt8] {
        let (peer, server) = endpoints(index)
        return peerSegment(from: peer, to: server, flags: [.syn]).packet
    }

    /// Completes the handshake for the connection at `index`.
    func handshake(_ stack: inout TCPStack, _ index: Int, at now: ContinuousClock.Instant) -> [TCPStack.Output] {
        let (peer, server) = endpoints(index)
        let syn = peerSegment(from: peer, to: server, sequence: 1_000, flags: [.syn])
        guard let synAck = stack.receive(syn.packet, at: now).segments.first else { return [] }
        let ack = peerSegment(
            from: peer, to: server, sequence: 1_001, acknowledgment: synAck.sequenceNumber.advanced(by: 1), flags: [.ack])
        return stack.receive(ack.packet, at: now)
    }

    @Test("The 16 opening connections are counted across both addresses. Another peer's SYN gets a SYN-ACK even if the first peer fills its quota")
    func halfOpenAcrossAddresses() throws {
        var stack = makeServer()
        _ = try stack.listen(on: 443)
        for index in 0..<16 {
            #expect(stack.receive(syn(index), at: .now).segments.map(\.flags) == [[.syn, .ack]])
        }
        // Drops the 17th regardless of which address it arrives from.
        #expect(stack.receive(syn(16), at: .now) == [.dropped(.limitReached(.halfOpenConnectionsPerAddress))])
        #expect(stack.receive(syn(17), at: .now) == [.dropped(.limitReached(.halfOpenConnectionsPerAddress))])
        #expect(stack.halfOpenCount == 16)

        let other = peerSegment(from: Self.other, to: Self.serverV4, flags: [.syn])
        #expect(stack.receive(other.packet, at: .now).segments.map(\.flags) == [[.syn, .ack]])
        expectStackInvariants(stack)
    }

    @Test("One peer gets 16 slots in the listener queue (established and opening connections combined). Other peers can use the rest")
    func acceptQueueShare() throws {
        var stack = makeServer()
        let listener = try stack.listen(on: 443)
        // Established connections stop counting as opening, so without the per-listener quota one peer would fill all 32 queue slots.
        for index in 0..<12 {
            #expect(handshake(&stack, index, at: .now) == [.event(.acceptable(listener))])
        }
        for index in 12..<16 {
            #expect(stack.receive(syn(index), at: .now).segments.map(\.flags) == [[.syn, .ack]])
        }
        #expect(stack.receive(syn(16), at: .now) == [.dropped(.limitReached(.acceptQueueShare))])
        #expect(stack.receive(syn(17), at: .now) == [.dropped(.limitReached(.acceptQueueShare))])
        #expect(stack.listeners[listener]?.queue.count == 12)
        #expect(stack.listeners[listener]?.halfOpenCount == 4)

        let other = peerSegment(from: Self.other, to: Self.serverV4, flags: [.syn])
        #expect(stack.receive(other.packet, at: .now).segments.map(\.flags) == [[.syn, .ack]])

        // When the application accepts one, a slot opens for that peer.
        #expect(stack.accept(from: listener, at: .now) != nil)
        #expect(stack.receive(syn(16), at: .now).segments.map(\.flags) == [[.syn, .ack]])
        #expect(stack.receive(syn(17), at: .now) == [.dropped(.limitReached(.acceptQueueShare))])
        _ = try stack.listen(on: 8_443)
        let elsewhere = peerSegment(
            from: IPEndpoint(address: Self.peerV4, port: 3_000), to: IPEndpoint(address: WireHosts.v4b, port: 8_443),
            flags: [.syn])
        // The peer's quota is unused on another listener.
        #expect(stack.receive(elsewhere.packet, at: .now).segments.map(\.flags) == [[.syn, .ack]])
        expectStackInvariants(stack)
    }

    @Test("Each ungrouped address has its own quota")
    func ungroupedAddressesAreSeparate() throws {
        var stack = StackHosts.makeStack(addresses: StackHosts.serverAddresses, now: .now)
        _ = try stack.listen(on: 443)
        _ = try stack.listen(on: 8_443)
        // Fill the 16 opening slots across two listeners to avoid the listener quota (16).
        for index in 0..<32 {
            let (peer, server) = endpoints(index)
            let destination = IPEndpoint(address: server.address, port: index < 16 ? 443 : 8_443)
            let packet = peerSegment(from: peer, to: destination, flags: [.syn]).packet
            #expect(stack.receive(packet, at: .now).segments.map(\.flags) == [[.syn, .ack]])
        }
        #expect(stack.halfOpenCountByAddress == [Self.peerV4: 16, Self.peerV6: 16])
    }

    @Test("The 64 connections are counted across both addresses. connect to either address of that peer yields limitReached")
    func connectionsAcrossAddresses() throws {
        let now = ContinuousClock.now
        var stack = makeServer(now: now)
        let listener = try stack.listen(on: 443)
        for index in 0..<64 {
            let (peer, server) = endpoints(index)
            _ = try stack.acceptHandmade(from: peer, to: server, listener: listener, at: now)
        }
        #expect(stack.receive(syn(64), at: now) == [.dropped(.limitReached(.connectionsPerAddress))])
        #expect(stack.receive(syn(65), at: now) == [.dropped(.limitReached(.connectionsPerAddress))])
        for address in [Self.peerV4, Self.peerV6] {
            #expect(throws: TCPStack.ConnectError.limitReached) {
                try stack.connect(to: IPEndpoint(address: address, port: 80), at: now)
            }
        }
        let other = peerSegment(from: Self.other, to: Self.serverV4, flags: [.syn])
        #expect(stack.receive(other.packet, at: now).segments.map(\.flags) == [[.syn, .ack]])
        expectStackInvariants(stack)
    }

    @Test("The 64 TIME-WAIT records are counted across both addresses. The 65th evicts that peer's oldest record (even if it belongs to the other address)")
    func timeWaitRecordsAcrossAddresses() throws {
        let start = ContinuousClock.now
        var stack = makeServer(now: start)
        let listener = try stack.listen(on: 443)
        let otherID = try stack.acceptHandmade(from: Self.other, to: Self.serverV4, listener: listener, at: start)
        let otherTuple = try stack.closeIntoTimeWait(otherID, at: start)
        var tuples: [FourTuple] = []
        for index in 0..<64 {
            let now = start + .milliseconds(index + 1)
            let (peer, server) = endpoints(index)
            let id = try stack.acceptHandmade(from: peer, to: server, listener: listener, at: now)
            tuples.append(try stack.closeIntoTimeWait(id, at: now))
        }
        #expect(tuples.allSatisfy { stack.timeWaitRecords[$0] != nil })

        // The 65th connection uses the IPv6 address, and the oldest record belongs to the IPv4 address.
        let now = start + .milliseconds(100)
        let peer = IPEndpoint(address: Self.peerV6, port: 5_000)
        let id = try stack.acceptHandmade(from: peer, to: Self.serverV6, listener: listener, at: now)
        let newest = try stack.closeIntoTimeWait(id, at: now)
        #expect(stack.timeWaitRecords[tuples[0]] == nil)
        #expect(tuples.dropFirst().allSatisfy { stack.timeWaitRecords[$0] != nil })
        #expect(stack.timeWaitRecords[newest] != nil)
        #expect(stack.timeWaitRecords[otherTuple] != nil)
        #expect(stack.timeWaitRecords.count == 65)
        expectStackInvariants(stack)
    }

    @Test("Supplying the groups again starts counting by the new groups immediately")
    func regrouping() throws {
        var stack = makeServer()
        _ = try stack.listen(on: 443)
        for index in 0..<16 {
            _ = stack.receive(syn(index), at: .now)
        }
        #expect(stack.receive(syn(16), at: .now) == [.dropped(.limitReached(.halfOpenConnectionsPerAddress))])
        // The two addresses now belong to different peers. Each address is counted as holding 8.
        stack.setRemoteAddressGroups([Self.peerV4: 7, Self.peerV6: 9])
        #expect(stack.receive(syn(16), at: .now).segments.map(\.flags) == [[.syn, .ack]])
        expectStackInvariants(stack)
    }
}
