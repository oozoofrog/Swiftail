import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// ISN(RFC 6528 3)과 나가는 연결의 주소·포트 고르기.
/// 계약 `docs/contracts/SwiftailNetstack.md` 동작 S7·S8, K1과 시험 11.
@Suite("스택: ISN과 포트")
struct StackOpeningTests {
    static let local = IPEndpoint(address: WireHosts.v4a, port: 49_152)
    static let remote = IPEndpoint(address: WireHosts.v4b, port: 443)

    @Test("같은 4-튜플의 ISN은 4µs마다 1씩 는다")
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
        // 4.7시간쯤 뒤 2³²에서 돈다. 넘치지 않는다.
        #expect(generator.clockComponent(at: start + .seconds(17_180)) == UInt32(truncatingIfNeeded: UInt64(17_180) * 250_000))
        _ = generator.clockComponent(at: start - .seconds(1))
    }

    @Test("다른 4-튜플, 다른 비밀의 ISN은 서로 다르다")
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

    @Test("connect의 SYN과 리스너의 SYN-ACK는 생성기의 ISN을 쓴다")
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

    @Test("ISN의 비밀은 description과 dump에 나오지 않는다")
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

    @Test("나가는 포트는 49152부터 차례로 고르고, 65535 다음은 49152다")
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

    @Test("연결이나 TIME-WAIT 기록이 쓰는 4-튜플은 건너뛴다. 상대가 다르면 같은 포트를 쓴다")
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

    @Test("출발 주소는 목적지와 같은 계열의 자기 주소다. 없으면 noLocalAddress")
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

    @Test("거절된 connect는 .closed(id, .refused)로 끝나고 지워진다")
    func refused() throws {
        var pair = StackPair()
        let (id, outputs) = try pair.client.connect(to: IPEndpoint(address: WireHosts.v4b, port: 80), at: pair.now)
        pair.collect(outputs, from: .client)
        try pair.deliver()
        #expect(pair.clientEvents == [.closed(id, .refused)])
        #expect(pair.client.connections.isEmpty)
        #expect(pair.client.nextDeadline == nil)
    }
}
