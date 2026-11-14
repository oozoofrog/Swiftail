import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// 한 피어가 다른 피어의 몫을 고갈시키지 못한다(M6 검토 A): 상대 주소 하나의 연결 64개, TIME-WAIT 기록 64개,
/// 기록의 수명 240초. 계약 동작 S의 "검토에서 고친 것", M.
@Suite("스택: 피어 하나의 몫")
struct StackPeerShareTests {
    static let server = IPEndpoint(address: WireHosts.v4b, port: 443)

    // MARK: 연결

    @Test("상대 주소 하나의 연결은 64개까지다. 응용이 놓았지만 닫는 중인 것도 센다. 다른 주소는 영향받지 않는다")
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
        // 다른 주소는 받고 건다.
        let other = peerSegment(from: IPEndpoint(address: StackHosts.peer(2), port: 1_000), to: Self.server, flags: [.syn])
        #expect(stack.receive(other.packet, at: now).segments.map(\.flags) == [[.syn, .ack]])
        _ = try stack.connect(to: IPEndpoint(address: StackHosts.peer(3), port: 80), at: now)

        // close로 놓은 연결은 FIN을 주고받는 동안 자리를 쥔다.
        _ = stack.close(ids[0], at: now)
        #expect(stack.connections[ids[0]]?.role == .released)
        #expect(stack.receive(extra.packet, at: now) == [.dropped(.limitReached(.connectionsPerAddress))])
        // abort한 연결은 자리를 놓는다. 그 뒤 65번째 SYN을 받는다.
        _ = stack.abort(ids[1], at: now)
        #expect(stack.receive(extra.packet, at: now).segments.map(\.flags) == [[.syn, .ack]])
        expectStackInvariants(stack)
    }

    // MARK: TIME-WAIT 기록

    @Test("기록은 상대 주소 하나에 64개까지다. 65번째가 생기면 그 주소의 가장 오래된 기록을 지운다. 다른 주소의 기록은 그대로다")
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

    @Test("기록의 수명은 만든 때부터 240초를 넘지 않는다. FIN 재전송마다 60초를 다시 재되 그 끝을 넘겨 늘리지 않는다")
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

        // 직전: 남아서 FIN에 답하고 기한은 그대로다. 그 시각이 되면 사라진다.
        let justBefore = created + .seconds(240) - .milliseconds(1)
        _ = stack.advance(to: justBefore)
        #expect(stack.retransmitFin(to: tuple, at: justBefore).map(\.flags) == [[.ack]])
        #expect(stack.timeWaitRecords[tuple]?.deadline == created + .seconds(240))
        expectStackInvariants(stack)
        _ = stack.advance(to: created + .seconds(240))
        #expect(stack.timeWaitRecords.isEmpty)
        expectStackInvariants(stack)
    }

    @Test("한 주소가 기록 1,024개를 만들고 59초마다 FIN을 다시 보내도 기록을 쥐지 못한다. 다른 피어의 SYN과 connect는 된다")
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
