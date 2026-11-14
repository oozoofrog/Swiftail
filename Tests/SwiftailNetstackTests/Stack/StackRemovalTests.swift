import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// 연결을 끝내는 스택의 일: 자기 주소 바뀜, 상대 주소의 주인 바뀜, 리스너 닫기, 응용이 놓은 연결, 옛 ID.
/// 계약 `docs/contracts/SwiftailNetstack.md` 동작 S5·S9, X10과 시험 11.
@Suite("스택: 연결 끝내기")
struct StackRemovalTests {
    static let server = IPEndpoint(address: WireHosts.v4b, port: 443)

    @Test("자기 주소가 아니게 된 주소의 연결은 아무것도 보내지 않고 peerRemoved로 끝난다")
    func localAddressRemoved() throws {
        var pair = StackPair()
        let listener = try pair.server.listen(on: 443)
        let v4 = try pair.open(listener: listener)
        let v6 = try pair.open(listener: listener, ipv6: true)
        let outputs = pair.client.setLocalAddresses([WireHosts.v6a])
        #expect(outputs == [.event(.closed(v4.client, .peerRemoved))])
        #expect(pair.client.connection(v4.client) == nil)
        #expect(pair.client.connection(v6.client) != nil)
        #expect(pair.client.write([1], to: v4.client, at: pair.now) == (0, []))
        // 그 주소로 오는 패킷은 이제 자기 것이 아니다.
        _ = pair.write([1, 2], to: v4.server, from: .server)
        try pair.deliver()
        #expect(pair.clientDrops == [.notForUs])
        expectStackInvariants(pair.client)
    }

    @Test("상대 주소의 연결을 끝낸다: 응용이 쥔 것은 알리고, 대기열·맺는 중인 것은 알리지 않고 지운다")
    func remoteAddressRemoved() throws {
        var stack = StackHosts.makeStack(addresses: StackHosts.serverAddresses, now: .now)
        let listener = try stack.listen(on: 443)
        let peer = StackHosts.peer(7)
        var accepted: [TCPStack.ConnectionID] = []
        for port in UInt16(1_000)..<1_003 {
            let source = IPEndpoint(address: peer, port: port)
            let synOutputs = stack.receive(
                peerSegment(from: source, to: Self.server, sequence: 10, flags: [.syn]).packet, at: .now)
            let synAck = try #require(synOutputs.segments.first)
            let ack = peerSegment(
                from: source, to: Self.server, sequence: 11, acknowledgment: synAck.sequenceNumber.advanced(by: 1),
                flags: [.ack])
            _ = stack.receive(ack.packet, at: .now)
            if port == 1_000, let id = stack.accept(from: listener) { accepted.append(id) }
        }
        _ = stack.receive(
            peerSegment(from: IPEndpoint(address: peer, port: 2_000), to: Self.server, flags: [.syn]).packet, at: .now)
        let other = IPEndpoint(address: StackHosts.peer(8), port: 1_000)
        _ = stack.receive(peerSegment(from: other, to: Self.server, flags: [.syn]).packet, at: .now)
        #expect(stack.connections.count == 5)

        let outputs = stack.removeConnections(toRemoteAddress: peer)
        #expect(outputs == [.event(.closed(accepted[0], .peerRemoved))])
        #expect(stack.connections.count == 1)
        #expect(stack.listeners[listener]?.queue.isEmpty == true)
        #expect(stack.halfOpenCount == 1)
        #expect(stack.halfOpenCountByAddress[peer] == nil)
        expectStackInvariants(stack)
    }

    @Test("리스너를 닫으면 대기열의 연결은 RST로 끊고 맺는 중인 연결은 말없이 버린다. 꺼낸 연결은 그대로다")
    func stopListening() throws {
        var pair = StackPair()
        let listener = try pair.server.listen(on: 443)
        let accepted = try pair.open(listener: listener)
        let (queuedClient, outputs) = try pair.client.connect(to: Self.server, at: pair.now)
        pair.collect(outputs, from: .client)
        try pair.deliver()
        // 맺는 중인 연결 하나: 클라이언트의 마지막 ACK를 잃는다.
        let (_, synOutputs) = try pair.client.connect(to: Self.server, at: pair.now)
        let syn = try #require(synOutputs.packets.first)
        _ = pair.server.receive(syn, at: pair.now)
        #expect(pair.server.halfOpenCount == 1)
        #expect(pair.server.listeners[listener]?.queue.count == 1)

        let closing = pair.server.stopListening(listener)
        let resets = closing.segments
        #expect(resets.count == 1)
        #expect(resets.first?.flags == [.rst])
        #expect(resets.first?.destination == pair.client.connection(queuedClient)?.localEndpoint)
        #expect(closing.events.isEmpty)
        #expect(pair.server.connections.count == 1)
        #expect(pair.server.connection(accepted.server) != nil)
        #expect(pair.server.halfOpenCount == 0)
        #expect(pair.server.listenersByPort.isEmpty)

        pair.collect(closing, from: .server)
        try pair.deliver()
        #expect(pair.clientEvents.contains(.closed(queuedClient, .reset)))
        expectStackInvariants(pair.server)
    }

    @Test("close로 놓은 연결은 마무리를 스택이 하고 사건을 내지 않는다. 옛 ID의 호출은 아무 일도 하지 않는다")
    func releasedConnection() throws {
        var pair = StackPair()
        let listener = try pair.server.listen(on: 443)
        let ids = try pair.open(listener: listener)
        pair.collect(pair.server.close(ids.server, at: pair.now), from: .server)
        let eventsBefore = pair.serverEvents
        _ = pair.write([1, 2, 3], to: ids.client, from: .client)
        pair.collect(pair.client.close(ids.client, at: pair.now), from: .client)
        try pair.run(for: .seconds(1))
        // 닫은 뒤에 온 데이터에는 RST(SHLD-3)지만, 놓은 연결이라 서버에는 사건이 없다.
        #expect(pair.serverEvents == eventsBefore)
        #expect(pair.server.connections.isEmpty)
        #expect(pair.server.read(upTo: 10, from: ids.server, at: pair.now) == ([], []))
        #expect(pair.server.write([1], to: ids.server, at: pair.now) == (0, []))
        #expect(pair.server.close(ids.server, at: pair.now).isEmpty)
        #expect(pair.server.abort(ids.server, at: pair.now).isEmpty)
        #expect(pair.server.finishWriting(ids.server, at: pair.now).isEmpty)
    }

    @Test("대기열의 연결은 꺼내기 전에는 ID로 부를 수 없다")
    func queuedConnectionIsNotApplications() throws {
        var pair = StackPair()
        let listener = try pair.server.listen(on: 443)
        let (_, outputs) = try pair.client.connect(to: Self.server, at: pair.now)
        pair.collect(outputs, from: .client)
        try pair.deliver()
        let queued = try #require(pair.server.listeners[listener]?.queue.first)
        #expect(pair.server.abort(queued, at: pair.now).isEmpty)
        #expect(pair.server.connection(queued)?.state == .established)
    }
}
