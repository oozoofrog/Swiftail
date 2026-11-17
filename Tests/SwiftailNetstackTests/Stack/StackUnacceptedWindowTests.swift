import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// 응용이 받아 가기 전(리스너의 대기열)의 연결은 받는 창을 16KiB로 묶는다. 받는 버퍼는 쓴 자리까지 자라므로, 창을 다 열어
/// 두면 상대가 순서대로 1바이트와 창 끝의 1바이트만으로 연결마다 256KiB를 잡게 한다. 받아 가면 버퍼 전체로 연다.
/// 계약 `docs/contracts/SwiftailNetstack.md` 동작 S5, M.
@Suite("스택: 받아 가기 전의 받는 창")
struct StackUnacceptedWindowTests {
    static let server = IPEndpoint(address: WireHosts.v4b, port: 443)
    /// 스택의 Window Scale shift.
    static let shift = TCPConnection.ownWindowShift
    /// 계약 동작 M: 받아 가기 전의 받는 창.
    static let unacceptedWindow = 16 * 1024

    /// 창 확장을 켠 상대 `peer`가 핸드셰이크를 끝낸다. 연결은 대기열에 남는다. 상대가 다음에 쓸 ACK 번호를 돌려준다.
    func handshake(
        _ stack: inout TCPStack, from peer: IPEndpoint, at now: ContinuousClock.Instant
    ) throws -> SequenceNumber {
        var syn = peerSegment(from: peer, to: Self.server, sequence: 1_000, flags: [.syn])
        syn.windowScale = 7
        let synAck = try #require(stack.receive(syn.packet, at: now).segments.first)
        #expect(synAck.flags == [.syn, .ack])
        #expect(Int(synAck.window) == Self.unacceptedWindow)
        let acknowledgment = synAck.sequenceNumber.advanced(by: 1)
        let ack = peerSegment(from: peer, to: Self.server, sequence: 1_001, acknowledgment: acknowledgment, flags: [.ack])
        _ = stack.receive(ack.packet, at: now)
        return acknowledgment
    }

    /// 상대가 순서대로 1바이트를 보내 ACK가 광고한 창을 읽고, 그 창의 마지막 자리에 1바이트를 더 보낸다. 광고받은 창을 돌려준다.
    func stretchWindow(
        _ stack: inout TCPStack, from peer: IPEndpoint, acknowledgment: SequenceNumber, at now: ContinuousClock.Instant
    ) throws -> Int {
        let first = peerSegment(
            from: peer, to: Self.server, sequence: 1_001, acknowledgment: acknowledgment, flags: [.ack], payload: [1])
        let outputs = stack.receive(first.packet, at: now) + stack.advance(to: now + .milliseconds(40))
        let ack = try #require(outputs.segments.last)
        #expect(ack.acknowledgmentNumber == SequenceNumber(1_002))
        let window = Int(ack.window) << Self.shift
        let last = peerSegment(
            from: peer, to: Self.server, sequence: UInt32(1_002 + window - 1), acknowledgment: acknowledgment,
            flags: [.ack], payload: [2])
        _ = stack.receive(last.packet, at: now + .milliseconds(40))
        return window
    }

    func allocatedByteCount(_ stack: TCPStack) -> Int {
        stack.connections.values.reduce(0) { $0 + $1.connection.receiveBuffer.allocatedByteCount }
    }

    @Test("대기열의 연결 32개가 창 끝까지 벌려 받아도 받는 버퍼의 합은 32 × 16KiB를 넘지 않는다")
    func queuedConnectionsHoldSmallBuffers() throws {
        let start = ContinuousClock.now
        var stack = StackHosts.makeStack(addresses: StackHosts.serverAddresses, now: start)
        let listener = try stack.listen(on: 443)
        for index in 0..<32 {
            let now = start + .milliseconds(index * 50)
            // 리스너의 대기열에서 피어 하나의 몫은 16개라 주소 둘로 나눈다.
            let peer = IPEndpoint(address: StackHosts.peer(UInt8(1 + index / 16)), port: UInt16(2_000 + index))
            let acknowledgment = try handshake(&stack, from: peer, at: now)
            let window = try stretchWindow(&stack, from: peer, acknowledgment: acknowledgment, at: now)
            #expect(window < Self.unacceptedWindow)
        }
        #expect(stack.listeners[listener]?.queue.count == 32)
        // 연결마다 순서대로 온 1바이트와 창 끝의 1바이트를 쥐고 있다.
        #expect(stack.connections.values.allSatisfy {
            $0.connection.readableByteCount == 1 && $0.connection.receiveBuffer.outOfOrderByteCount == 1
        })
        #expect(allocatedByteCount(stack) <= 32 * Self.unacceptedWindow)
    }

    @Test("받아 가면 창 갱신 ACK가 버퍼 전체의 창을 알리고, 그 창 끝의 데이터를 받는다")
    func acceptOpensWindow() throws {
        let now = ContinuousClock.now
        var stack = StackHosts.makeStack(addresses: StackHosts.serverAddresses, now: now)
        let listener = try stack.listen(on: 443)
        let peer = IPEndpoint(address: StackHosts.peer(1), port: 2_000)
        let acknowledgment = try handshake(&stack, from: peer, at: now)

        let popped = stack.accept(from: listener, at: now)
        let accepted = try #require(popped)
        let update = try #require(accepted.outputs.segments.first)
        #expect(accepted.outputs.segments.count == 1)
        #expect(update.flags == [.ack])
        #expect(update.acknowledgmentNumber == SequenceNumber(1_001))
        let window = Int(update.window) << Self.shift
        #expect(window == ReceiveBuffer.defaultCapacity)

        let last = peerSegment(
            from: peer, to: Self.server, sequence: UInt32(1_001 + window - 1), acknowledgment: acknowledgment,
            flags: [.ack], payload: [9])
        _ = stack.receive(last.packet, at: now)
        #expect(stack.connections[accepted.connection]?.connection.receiveBuffer.outOfOrderByteCount == 1)
        // 응용이 쥔 연결의 버퍼는 전처럼 쓴 자리까지 자란다.
        #expect(allocatedByteCount(stack) == ReceiveBuffer.defaultCapacity)
    }

    @Test("받아 가기 전에는 16KiB까지만 받고, 받아 간 뒤 나머지가 모두 온다")
    func transferAcrossAccept() throws {
        var pair = StackPair()
        let listener = try pair.server.listen(on: 443)
        let (clientID, outputs) = try pair.client.connect(to: Self.server, at: pair.now)
        pair.collect(outputs, from: .client)
        try pair.deliver()

        let upload = patternBytes(count: 200_000, seed: 4)
        var sent = pair.write(upload, to: clientID, from: .client)
        try pair.run(for: .seconds(2))
        let queued = try #require(pair.server.listeners[listener]?.queue.first)
        #expect(pair.server.connection(queued)?.readableByteCount == Self.unacceptedWindow)

        let popped = pair.server.accept(from: listener, at: pair.now)
        let accepted = try #require(popped)
        pair.collect(accepted.outputs, from: .server)
        var received: [UInt8] = []
        let deadline = pair.now + .seconds(30)
        while received.count < upload.count, pair.now < deadline {
            if sent < upload.count { sent += pair.write(Array(upload[sent...]), to: clientID, from: .client) }
            try pair.deliver()
            received += pair.read(accepted.connection, from: .server)
            try pair.run(for: .milliseconds(5))
        }
        #expect(received == upload)
    }
}
