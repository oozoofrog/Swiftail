import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// 상한: 리스너 16, 맺는 중 64·주소당 16, accept 대기열 32, 연결 256, TIME-WAIT 기록 1,024.
/// 넘친 SYN은 응답 없이 버리고 `limitReached`로 알린다. 자리가 나면 다시 받는다.
/// 계약 `docs/contracts/SwiftailNetstack.md` 동작 S3~S6, X7, M과 시험 11.
@Suite("스택: 상한")
struct StackLimitTests {
    static let server = IPEndpoint(address: WireHosts.v4b, port: 443)

    func makeServer() -> TCPStack {
        StackHosts.makeStack(addresses: StackHosts.serverAddresses, now: .now)
    }

    @Test("리스너는 포트 하나에 하나, 16개까지. 닫으면 그 포트를 다시 열 수 있고 옛 ID는 새 리스너를 건드리지 않는다")
    func listeners() throws {
        var stack = makeServer()
        var ids: [TCPStack.ListenerID] = []
        for port in UInt16(1)...16 {
            ids.append(try stack.listen(on: port))
        }
        #expect(throws: TCPStack.ListenError.limitReached) { try stack.listen(on: 17) }
        #expect(throws: TCPStack.ListenError.addressInUse) { try stack.listen(on: 3) }
        _ = stack.stopListening(ids[2])
        let reopened = try stack.listen(on: 3)
        #expect(reopened != ids[2])
        #expect(stack.stopListening(ids[2]).isEmpty)
        #expect(stack.listenersByPort[3] == reopened)
    }

    @Test("상대 주소 하나의 맺는 중인 연결은 16개까지다. 17번째 SYN은 답 없이 버린다")
    func halfOpenPerAddress() throws {
        var stack = makeServer()
        _ = try stack.listen(on: 443)
        let address = StackHosts.peer(1)
        for port in UInt16(1_000)..<1_016 {
            let syn = peerSegment(from: IPEndpoint(address: address, port: port), to: Self.server, flags: [.syn])
            #expect(stack.receive(syn.packet, at: .now).segments.map(\.flags) == [[.syn, .ack]])
        }
        let extra = peerSegment(from: IPEndpoint(address: address, port: 1_016), to: Self.server, flags: [.syn])
        #expect(stack.receive(extra.packet, at: .now) == [.dropped(.limitReached(.halfOpenConnectionsPerAddress))])
        // 다른 주소는 받는다.
        let other = peerSegment(from: IPEndpoint(address: StackHosts.peer(2), port: 1_000), to: Self.server, flags: [.syn])
        #expect(stack.receive(other.packet, at: .now).segments.count == 1)
        #expect(stack.halfOpenCountByAddress[address] == 16)
        expectStackInvariants(stack)
    }

    @Test("맺는 중인 연결은 스택 전체 64개까지다. 247초 안에 사라지면 다시 받는다")
    func halfOpenTotal() throws {
        var stack = makeServer()
        let start = ContinuousClock.now
        _ = try stack.listen(on: 443)
        _ = try stack.listen(on: 8_443)
        for host in UInt8(1)...4 {
            for port in UInt16(1_000)..<1_016 {
                let destination = IPEndpoint(address: WireHosts.v4b, port: port % 2 == 0 ? 443 : 8_443)
                let syn = peerSegment(from: IPEndpoint(address: StackHosts.peer(host), port: port), to: destination, flags: [.syn])
                #expect(stack.receive(syn.packet, at: start).segments.count == 1)
            }
        }
        #expect(stack.halfOpenCount == 64)
        let extra = peerSegment(from: IPEndpoint(address: StackHosts.peer(5), port: 1_000), to: Self.server, flags: [.syn])
        #expect(stack.receive(extra.packet, at: start) == [.dropped(.limitReached(.halfOpenConnections))])
        expectStackInvariants(stack)

        // SYN-ACK 재전송 7번 뒤 247초에 사라진다(계약 동작 R4, X7). 그 전에는 남는다.
        _ = advance(&stack, to: start + .seconds(246))
        #expect(stack.halfOpenCount == 64)
        let late = advance(&stack, to: start + .seconds(248))
        #expect(late.events.isEmpty)
        #expect(stack.halfOpenCount == 0)
        #expect(stack.connections.isEmpty)
        #expect(stack.receive(extra.packet, at: start + .seconds(248)).segments.count == 1)
        expectStackInvariants(stack)
    }

    /// 노드처럼 `nextDeadline`마다 `advance`를 부르며 `limit`까지 간다.
    func advance(_ stack: inout TCPStack, to limit: ContinuousClock.Instant) -> [TCPStack.Output] {
        var outputs: [TCPStack.Output] = []
        while let deadline = stack.nextDeadline, deadline <= limit {
            outputs += stack.advance(to: deadline)
        }
        return outputs + stack.advance(to: limit)
    }

    /// `stack`에 상대 `peer`의 핸드셰이크를 끝까지 한다. 리스너 대기열에 들어가면 그 사건을 돌려준다.
    func handshake(_ stack: inout TCPStack, from peer: IPEndpoint) -> [TCPStack.Output] {
        let syn = peerSegment(from: peer, to: Self.server, sequence: 1_000, flags: [.syn])
        guard let synAck = stack.receive(syn.packet, at: .now).segments.first else { return [] }
        let ack = peerSegment(
            from: peer, to: Self.server, sequence: 1_001, acknowledgment: synAck.sequenceNumber.advanced(by: 1),
            flags: [.ack])
        return stack.receive(ack.packet, at: .now)
    }

    @Test("accept 대기열은 32개까지다. 차면 SYN을 답 없이 버리고, 꺼내면 다시 받는다")
    func acceptQueue() throws {
        var stack = makeServer()
        let listener = try stack.listen(on: 443)
        for port in UInt16(1_000)..<1_032 {
            #expect(handshake(&stack, from: IPEndpoint(address: StackHosts.peer(1), port: port)) == [.event(.acceptable(listener))])
        }
        #expect(stack.listeners[listener]?.queue.count == 32)
        let peer = IPEndpoint(address: StackHosts.peer(1), port: 2_000)
        let syn = peerSegment(from: peer, to: Self.server, flags: [.syn])
        #expect(stack.receive(syn.packet, at: .now) == [.dropped(.limitReached(.acceptQueue))])

        let popped = stack.accept(from: listener)
        let first = try #require(popped)
        #expect(stack.connection(first)?.remoteEndpoint.port == 1_000)
        #expect(handshake(&stack, from: peer) == [.event(.acceptable(listener))])
        expectStackInvariants(stack)
    }

    @Test("맺는 중인 연결도 리스너의 대기열 자리를 쓴다(대기열이 32개를 넘지 않는다)")
    func acceptQueueCountsHalfOpen() throws {
        var stack = makeServer()
        let listener = try stack.listen(on: 443)
        for port in UInt16(1_000)..<1_020 {
            _ = handshake(&stack, from: IPEndpoint(address: StackHosts.peer(1), port: port))
        }
        for host in UInt8(2)...13 {
            let syn = peerSegment(from: IPEndpoint(address: StackHosts.peer(host), port: 1_000), to: Self.server, flags: [.syn])
            #expect(stack.receive(syn.packet, at: .now).segments.count == 1)
        }
        let extra = peerSegment(from: IPEndpoint(address: StackHosts.peer(14), port: 1_000), to: Self.server, flags: [.syn])
        #expect(stack.receive(extra.packet, at: .now) == [.dropped(.limitReached(.acceptQueue))])
        #expect(stack.listeners[listener]?.queue.count == 20)
        #expect(stack.listeners[listener]?.halfOpenCount == 12)
        expectStackInvariants(stack)
    }

    @Test("연결은 256개까지다. 넘으면 connect는 limitReached, SYN은 답 없이 버린다. 하나를 끊으면 다시 된다")
    func connections() throws {
        var stack = StackHosts.makeStack(addresses: StackHosts.clientAddresses, now: .now)
        _ = try stack.listen(on: 9_000)
        let remote = IPEndpoint(address: WireHosts.v4b, port: 443)
        var ids: [TCPStack.ConnectionID] = []
        for _ in 0..<256 {
            ids.append(try stack.connect(to: remote, at: .now).connection)
        }
        #expect(throws: TCPStack.ConnectError.limitReached) { try stack.connect(to: remote, at: .now) }
        let syn = peerSegment(
            from: IPEndpoint(address: WireHosts.v4b, port: 5_000), to: IPEndpoint(address: WireHosts.v4a, port: 9_000),
            flags: [.syn])
        #expect(stack.receive(syn.packet, at: .now) == [.dropped(.limitReached(.connections))])

        #expect(stack.abort(ids[0], at: .now).events == [.closed(ids[0], .aborted)])
        #expect(stack.connections.count == 255)
        _ = try stack.connect(to: remote, at: .now)
        expectStackInvariants(stack)
    }

    @Test("TIME-WAIT 기록은 1,024개까지이고 기한 전에 버리지 않는다. 차 있는 동안 connect·SYN을 받지 않는다")
    func timeWaitRecords() throws {
        var pair = StackPair()
        let start = pair.now
        let listener = try pair.server.listen(on: 443)
        let clientListener = try pair.client.listen(on: 9_000)
        _ = clientListener
        let kept = try pair.open(listener: listener)
        for _ in 0..<1_024 {
            try pair.closeFromClient(try pair.open(listener: listener))
        }
        #expect(pair.client.timeWaitRecords.count == 1_024)
        #expect(pair.client.connections.count == 1)
        #expect(pair.server.connections.count == 1)

        #expect(throws: TCPStack.ConnectError.limitReached) {
            try pair.client.connect(to: IPEndpoint(address: WireHosts.v4b, port: 443), at: pair.now)
        }
        let syn = peerSegment(
            from: IPEndpoint(address: WireHosts.v4b, port: 5_000), to: IPEndpoint(address: WireHosts.v4a, port: 9_000),
            flags: [.syn])
        #expect(pair.client.receive(syn.packet, at: pair.now) == [.dropped(.limitReached(.timeWaitRecords))])

        // 기록이 찬 뒤 TIME-WAIT에 든 연결은 기록이 되지 않고 연결로 남아 TIME-WAIT를 마친다.
        try pair.closeFromClient(kept)
        #expect(pair.client.timeWaitRecords.count == 1_024)
        #expect(pair.client.connections.count == 1)
        #expect(pair.client.connections.values.first?.connection.state == .timeWait)
        expectStackInvariants(pair.client)

        // 그 기록의 4-튜플로 온 FIN 재전송에는 ACK한다.
        let (tuple, record) = try #require(pair.client.timeWaitRecords.first)
        let finAgain = peerSegment(
            from: tuple.remote, to: tuple.local, sequence: record.receiveNext.advanced(by: .max).rawValue,
            acknowledgment: record.sendNext, flags: [.fin, .ack])
        let reply = pair.client.receive(finAgain.packet, at: pair.now).segments
        #expect(reply.map(\.flags) == [[.ack]])
        #expect(reply.first?.acknowledgmentNumber == record.receiveNext)

        try pair.run(until: start + .seconds(59))
        #expect(pair.client.timeWaitRecords.count == 1_024)
        try pair.run(until: start + .seconds(61))
        #expect(pair.client.timeWaitRecords.isEmpty)
        #expect(pair.client.connections.isEmpty)
        _ = try pair.client.connect(to: IPEndpoint(address: WireHosts.v4b, port: 443), at: pair.now)
        expectStackInvariants(pair.client)
        expectStackInvariants(pair.server)
    }
}
