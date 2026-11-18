import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// The stack survives arbitrary inputs and stays within limits. Cost with 256 connections and 1,024 TIME-WAIT records.
/// Contract `docs/contracts/SwiftailNetstack.md` behaviors X1·X7·X8, M, and test 11.
@Suite("Stack arbitrary input and cost")
struct StackRobustnessTests {
    @Test("A mix of arbitrary packets, SYN floods, application calls, and times does not crash and leaves the tables consistent and within limits", arguments: [1, 2, 3] as [UInt64])
    func randomTraffic(seed: UInt64) {
        var random = WireFuzzRandom(seed: seed)
        var now = ContinuousClock.now
        var stack = StackHosts.makeStack(addresses: StackHosts.serverAddresses, now: now)
        var listeners: [TCPStack.ListenerID] = []
        for port: UInt16 in [443, 8_443] {
            if let id = try? stack.listen(on: port) { listeners.append(id) }
        }
        var owned: [TCPStack.ConnectionID] = []
        var recent: [TCPSegment] = []
        var synAcks: [TCPSegment] = []
        var drops: [TCPStack.Drop] = []

        func remember(_ outputs: [TCPStack.Output]) {
            for segment in outputs.segments where segment.flags == [.syn, .ack] {
                synAcks.append(segment)
            }
            if synAcks.count > 64 { synAcks.removeFirst(synAcks.count - 64) }
            drops += outputs.drops
        }

        for step in 0..<20_000 {
            var outputs: [TCPStack.Output] = []
            let ports: [UInt16] = [443, 8_443, 80, UInt16.random(in: 1...UInt16.max, using: &random)]
            let remote = IPEndpoint(
                address: StackHosts.peer(UInt8.random(in: 1...3, using: &random)),
                port: UInt16.random(in: 1_000...1_100, using: &random))
            let local = IPEndpoint(
                address: WireHosts.v4b, port: ports[Int.random(in: 0..<ports.count, using: &random)])
            switch Int.random(in: 0..<10, using: &random) {
            case 0:
                outputs = stack.receive(random.bytes(Int.random(in: 0...80, using: &random)), at: now)
            case 1, 2:
                let syn = peerSegment(
                    from: remote, to: local, sequence: UInt32.random(in: 0...UInt32.max, using: &random), flags: [.syn])
                recent.append(syn)
                outputs = stack.receive(syn.packet, at: now)
            case 3:
                if let synAck = synAcks.randomElement(using: &random) {
                    let ack = peerSegment(
                        from: synAck.destination, to: synAck.source,
                        sequence: synAck.acknowledgmentNumber.rawValue,
                        acknowledgment: synAck.sequenceNumber.advanced(by: 1), flags: [.ack],
                        payload: random.bytes(Int.random(in: 0...20, using: &random)))
                    recent.append(ack)
                    outputs = stack.receive(ack.packet, at: now)
                }
            case 4:
                if var segment = recent.randomElement(using: &random) {
                    segment.flags = TCPSegment.Flags(rawValue: UInt8.random(in: 0...0x1F, using: &random))
                    segment.sequenceNumber = segment.sequenceNumber.advanced(by: UInt32.random(in: 0...UInt32.max, using: &random))
                    segment.acknowledgmentNumber = SequenceNumber(UInt32.random(in: 0...UInt32.max, using: &random))
                    segment.window = UInt16.random(in: 0...UInt16.max, using: &random)
                    segment.payload = random.bytes(Int.random(in: 0...40, using: &random))
                    var packet = segment.packet
                    if Bool.random(using: &random) {
                        let index = Int.random(in: 0..<packet.count, using: &random)
                        packet[index] = UInt8.random(in: 0...UInt8.max, using: &random)
                    }
                    outputs = stack.receive(packet, at: now)
                }
            case 5:
                now = now + .milliseconds(Int.random(in: 0...2_000, using: &random))
            case 6:
                for listener in listeners {
                    while let accepted = stack.accept(from: listener, at: now) {
                        owned.append(accepted.connection)
                        remember(accepted.outputs)
                    }
                }
            case 7:
                if let id = owned.randomElement(using: &random) {
                    switch Int.random(in: 0..<5, using: &random) {
                    case 0: outputs = stack.write(random.bytes(500)[...], to: id, at: now).outputs
                    case 1: outputs = stack.read(upTo: 1_000, from: id, at: now).outputs
                    case 2: outputs = stack.finishWriting(id, at: now)
                    case 3: outputs = stack.close(id, at: now)
                    default: outputs = stack.abort(id, at: now)
                    }
                }
            case 8:
                outputs = (try? stack.connect(to: remote, at: now).outputs) ?? []
            default:
                // Mix in address owner changes infrequently (if frequent, they clear the flood before it reaches the limit).
                if Int.random(in: 0..<20, using: &random) == 0 {
                    outputs = stack.removeConnections(toRemoteAddress: remote.address)
                }
            }
            remember(outputs)
            remember(stack.advance(to: now))
            if recent.count > 64 { recent.removeFirst(recent.count - 64) }
            if step % 200 == 0 { expectStackInvariants(stack) }
        }
        expectStackInvariants(stack)
        // Also check that a limit actually applied (the flood reached the limit).
        let limits: [TCPStack.Limit] = drops.compactMap { if case .limitReached(let limit) = $0 { limit } else { nil } }
        print("Arbitrary input (seed \(seed)): dropped \(limits.count) SYNs at a limit, types \(Set(limits.map { "\($0)" }).sorted())")
        // With only three remote addresses, per-address limits apply (16 opening, 64 connections. Check the 64-connection limit first).
        #expect(limits.contains(.halfOpenConnectionsPerAddress) || limits.contains(.connectionsPerAddress))
        #expect(drops.contains(.malformed) || drops.contains(.badChecksum))
    }

    @Test("Cost of one packet, deadline lookup, and advance with 256 connections and 1,024 TIME-WAIT records")
    func costAtLimits() throws {
        let start = ContinuousClock.now
        var stack = StackHosts.makeStack(addresses: StackHosts.clientAddresses, now: start)
        // Spread over multiple addresses because each remote address allows up to 64 connections and 64 records (M6 review A).
        for index in 0..<256 {
            let remote = IPEndpoint(address: StackHosts.peer(UInt8(1 + index / 64)), port: UInt16(1_000 + index))
            _ = try stack.connect(to: remote, at: start)
        }
        for index in 0..<1_024 {
            let tuple = FourTuple(
                local: IPEndpoint(address: WireHosts.v4a, port: UInt16(20_000 + index)),
                remote: IPEndpoint(address: StackHosts.peer(UInt8(10 + index / 64)), port: 443))
            stack.addTimeWaitRecord(
                TimeWaitRecord(
                    sendNext: SequenceNumber(1), receiveNext: SequenceNumber(2),
                    deadline: start + .seconds(60) + .milliseconds(index), lifetimeEnd: start + .seconds(240)),
                for: tuple)
        }
        #expect(stack.timeWaitRecords.count == 1_024)
        #expect(stack.connections.count == 256)

        let iterations = 2_000
        let clock = ContinuousClock()
        // A segment that gets no answer (RST without ACK) on a SYN-SENT connection: lookup and processing for one connection.
        let target = try #require(stack.connections.values.first?.connection)
        let ignored = peerSegment(
            from: target.remoteEndpoint, to: target.localEndpoint, sequence: 1, flags: [.rst]
        ).packet
        var deadline: ContinuousClock.Instant?
        let receiveTime = clock.measure {
            for _ in 0..<iterations { _ = stack.receive(ignored, at: start) }
        }
        let deadlineTime = clock.measure {
            for _ in 0..<iterations { deadline = stack.nextDeadline }
        }
        let advanceTime = clock.measure {
            for _ in 0..<iterations { _ = stack.advance(to: start) }
        }
        #expect(deadline == start + .seconds(1))
        print(
            "Stack cost (256 connections, 1,024 records, average): receive \(receiveTime / iterations), "
                + "nextDeadline \(deadlineTime / iterations), advance (no deadline) \(advanceTime / iterations)")
        // At most 1ms per packet even in a debug build (a loose limit that catches only pathological cases).
        #expect(receiveTime / iterations < .milliseconds(1))
        #expect(deadlineTime / iterations < .milliseconds(1))
        #expect(advanceTime / iterations < .milliseconds(1))
    }
}
