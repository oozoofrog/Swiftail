import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// Tests ISN (RFC 6528 3) and address and port selection for outbound connections.
/// Contract `docs/contracts/SwiftailNetstack.md` behaviors S7·S8, K1, and test 11.
@Suite("Stack ISN and ports")
struct StackOpeningTests {
    static let local = IPEndpoint(address: WireHosts.v4a, port: 49_152)
    static let remote = IPEndpoint(address: WireHosts.v4b, port: 443)

    @Test("The ISN for the same 4-tuple increments by 1 every 4µs")
    func clockComponent() {
        let start = ContinuousClock.now
        let generator = InitialSequenceNumberGenerator(secret: StackHosts.secret, origin: start)
        let first = generator.initialSequenceNumber(local: Self.local, remote: Self.remote, at: start)
        let oneSecond = generator.initialSequenceNumber(local: Self.local, remote: Self.remote, at: start + .seconds(1))
        let fourMicroseconds = generator.initialSequenceNumber(
            local: Self.local, remote: Self.remote, at: start + .microseconds(4))
        #expect(oneSecond.distance(from: first) == 250_000)
        #expect(fourMicroseconds.distance(from: first) == 1)
        #expect(generator.clockComponent(at: start + .microseconds(3)) == 0)
        // Wraps at 2³² after roughly 4.7 hours without overflowing.
        #expect(generator.clockComponent(at: start + .seconds(17_180)) == UInt32(truncatingIfNeeded: UInt64(17_180) * 250_000))
        _ = generator.clockComponent(at: start - .seconds(1))
    }

    @Test("Different 4-tuples and different secrets produce distinct ISNs")
    func secretFunction() {
        let start = ContinuousClock.now
        let generator = InitialSequenceNumberGenerator(secret: StackHosts.secret, origin: start)
        let other = InitialSequenceNumberGenerator(secret: Array(StackHosts.secret.reversed()), origin: start)
        let base = generator.initialSequenceNumber(local: Self.local, remote: Self.remote, at: start)
        let tuples = [
            (IPEndpoint(address: WireHosts.v4a, port: 49_153), Self.remote),
            (Self.local, IPEndpoint(address: WireHosts.v4b, port: 444)),
            (Self.local, IPEndpoint(address: StackHosts.peer(3), port: 443)),
            (IPEndpoint(address: WireHosts.v6a, port: 49_152), IPEndpoint(address: WireHosts.v6b, port: 443)),
        ]
        var values = [base]
        for (local, remote) in tuples {
            values.append(generator.initialSequenceNumber(local: local, remote: remote, at: start))
        }
        #expect(Set(values.map(\.rawValue)).count == values.count)
        #expect(other.initialSequenceNumber(local: Self.local, remote: Self.remote, at: start) != base)
    }

    @Test("The SYN from connect and the listener's SYN-ACK use the generator's ISN")
    func stackUsesGenerator() throws {
        let start = ContinuousClock.now
        var stack = StackHosts.makeStack(addresses: StackHosts.clientAddresses, now: start)
        let generator = InitialSequenceNumberGenerator(secret: StackHosts.secret, origin: start)
        let at = start + .milliseconds(10)
        let (_, outputs) = try stack.connect(to: Self.remote, at: at)
        #expect(outputs.segments.first?.sequenceNumber
            == generator.initialSequenceNumber(local: Self.local, remote: Self.remote, at: at))

        _ = try stack.listen(on: 9_000)
        let peer = IPEndpoint(address: WireHosts.v4b, port: 5_000)
        let listening = IPEndpoint(address: WireHosts.v4a, port: 9_000)
        let synAck = stack.receive(peerSegment(from: peer, to: listening, flags: [.syn]).packet, at: at).segments.first
        #expect(synAck?.sequenceNumber == generator.initialSequenceNumber(local: listening, remote: peer, at: at))
    }

    @Test("The ISN secret does not appear in description or dump")
    func secretIsHidden() {
        let secret = [UInt8](repeating: 0xC3, count: 32)
        let stack = TCPStack(isnSecret: secret, now: .now)
        var dumped = ""
        dump(stack, to: &dumped)
        let described = String(describing: stack) + String(reflecting: stack) + dumped
        #expect(!described.contains("195"))  // 0xC3
        #expect(!described.lowercased().contains("c3"))
        #expect(!described.contains("SymmetricKey"))
        #expect(described.contains("비밀 숨김"))
    }

    @Test("Outbound ports are selected in order starting at 49152, and 49152 follows 65535")
    func sequentialPorts() throws {
        var stack = StackHosts.makeStack(addresses: StackHosts.clientAddresses, now: .now)
        let first = try stack.connect(to: Self.remote, at: .now).connection
        let second = try stack.connect(to: Self.remote, at: .now).connection
        #expect(stack.connection(first)?.localEndpoint == Self.local)
        #expect(stack.connection(second)?.localEndpoint.port == 49_153)
        stack.nextEphemeralPort = 65_535
        let last = try stack.connect(to: Self.remote, at: .now).connection
        #expect(stack.connection(last)?.localEndpoint.port == 65_535)
        #expect(stack.nextEphemeralPort == 49_152)
    }

    @Test("Skips a 4-tuple used by a connection or TIME-WAIT record, and reuses the port for a different peer")
    func skipsUsedTuples() throws {
        var stack = StackHosts.makeStack(addresses: StackHosts.clientAddresses, now: .now)
        _ = try stack.connect(to: Self.remote, at: .now)  // 49152
        stack.addTimeWaitRecord(
            TimeWaitRecord(
                sendNext: SequenceNumber(1), receiveNext: SequenceNumber(2), deadline: .now + .seconds(60),
                lifetimeEnd: .now + .seconds(240)),
            for: FourTuple(local: IPEndpoint(address: WireHosts.v4a, port: 49_153), remote: Self.remote))
        stack.nextEphemeralPort = 49_152
        let third = try stack.connect(to: Self.remote, at: .now).connection
        #expect(stack.connection(third)?.localEndpoint.port == 49_154)

        stack.nextEphemeralPort = 49_152
        let otherRemote = IPEndpoint(address: WireHosts.v4b, port: 8_443)
        let reused = try stack.connect(to: otherRemote, at: .now).connection
        #expect(stack.connection(reused)?.localEndpoint.port == 49_152)
        expectStackInvariants(stack)
    }

    @Test("The source address is a local address of the same family as the destination. If absent, yields noLocalAddress")
    func sourceAddressFamily() throws {
        var stack = StackHosts.makeStack(addresses: StackHosts.clientAddresses, now: .now)
        let remote6 = IPEndpoint(address: WireHosts.v6b, port: 443)
        let id = try stack.connect(to: remote6, at: .now).connection
        #expect(stack.connection(id)?.localEndpoint.address == WireHosts.v6a)

        var v4Only = StackHosts.makeStack(addresses: [WireHosts.v4a], now: .now)
        #expect(throws: TCPStack.ConnectError.noLocalAddress) { try v4Only.connect(to: remote6, at: .now) }
        var none = TCPStack(isnSecret: StackHosts.secret, now: .now)
        #expect(throws: TCPStack.ConnectError.noLocalAddress) { try none.connect(to: Self.remote, at: .now) }
    }

    @Test("A refused connect ends with .closed(id, .refused) and is removed")
    func refused() throws {
        var pair = StackPair()
        let (id, outputs) = try pair.client.connect(to: IPEndpoint(address: WireHosts.v4b, port: 80), at: pair.now)
        pair.collect(outputs, from: .client)
        try pair.deliver()
        #expect(pair.clientEvents.map(\.withoutStatistics) == [.closed(id, .refused, .unchecked)])
        #expect(pair.client.connections.isEmpty)
        #expect(pair.client.nextDeadline == nil)
    }
}
