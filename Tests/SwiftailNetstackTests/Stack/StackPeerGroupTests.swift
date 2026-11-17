import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// 피어 하나의 몫은 그 피어의 주소들(IPv4·IPv6)에 걸쳐 센다. 주소별로만 세면 주소가 둘인 피어가 몫을 두 번 쥐어, 맺는 중인
/// 연결 16 × 2로 리스너의 대기열(32)을 혼자 채운다. 계약 `docs/contracts/SwiftailNetstack.md` 동작 S의 "피어 하나의 몫", M.
@Suite("스택: 주소가 여럿인 피어의 몫")
struct StackPeerGroupTests {
    static let serverV4 = IPEndpoint(address: WireHosts.v4b, port: 443)
    static let serverV6 = IPEndpoint(address: WireHosts.v6b, port: 443)
    /// 한 피어의 두 주소.
    static let peerV4 = StackHosts.peer(1)
    static let peerV6 = WireHosts.address("fd7a:115c:a1e0::101")
    /// 다른 피어.
    static let other = IPEndpoint(address: StackHosts.peer(2), port: 1_000)

    /// 두 주소를 한 피어로 묶은 서버 스택.
    func makeServer(now: ContinuousClock.Instant = .now) -> TCPStack {
        var stack = StackHosts.makeStack(addresses: StackHosts.serverAddresses, now: now)
        stack.setRemoteAddressGroups([Self.peerV4: 7, Self.peerV6: 7, Self.other.address: 8])
        return stack
    }

    /// 그 피어의 `index`번째 연결의 양 끝. 짝수는 IPv4, 홀수는 IPv6로 온다.
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

    /// `index`번째 연결의 핸드셰이크를 끝까지 한다.
    func handshake(_ stack: inout TCPStack, _ index: Int, at now: ContinuousClock.Instant) -> [TCPStack.Output] {
        let (peer, server) = endpoints(index)
        let syn = peerSegment(from: peer, to: server, sequence: 1_000, flags: [.syn])
        guard let synAck = stack.receive(syn.packet, at: now).segments.first else { return [] }
        let ack = peerSegment(
            from: peer, to: server, sequence: 1_001, acknowledgment: synAck.sequenceNumber.advanced(by: 1), flags: [.ack])
        return stack.receive(ack.packet, at: now)
    }

    @Test("맺는 중인 연결 16개는 두 주소를 합친 수다. 그 피어가 몫을 다 써도 다른 피어의 SYN은 SYN-ACK를 받는다")
    func halfOpenAcrossAddresses() throws {
        var stack = makeServer()
        _ = try stack.listen(on: 443)
        for index in 0..<16 {
            #expect(stack.receive(syn(index), at: .now).segments.map(\.flags) == [[.syn, .ack]])
        }
        // 17번째는 어느 주소로 와도 버린다.
        #expect(stack.receive(syn(16), at: .now) == [.dropped(.limitReached(.halfOpenConnectionsPerAddress))])
        #expect(stack.receive(syn(17), at: .now) == [.dropped(.limitReached(.halfOpenConnectionsPerAddress))])
        #expect(stack.halfOpenCount == 16)

        let other = peerSegment(from: Self.other, to: Self.serverV4, flags: [.syn])
        #expect(stack.receive(other.packet, at: .now).segments.map(\.flags) == [[.syn, .ack]])
        expectStackInvariants(stack)
    }

    @Test("리스너의 대기열에서 피어 하나의 몫은 16개다(맺어진 것과 맺는 중인 것을 합쳐). 다른 피어는 나머지에 들어온다")
    func acceptQueueShare() throws {
        var stack = makeServer()
        let listener = try stack.listen(on: 443)
        // 맺어진 연결은 맺는 중인 수에서 빠지므로, 리스너별 몫이 없으면 한 피어가 대기열 32개를 다 채운다.
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

        // 응용이 하나를 받아 가면 그 피어의 자리가 하나 난다.
        #expect(stack.accept(from: listener, at: .now) != nil)
        #expect(stack.receive(syn(16), at: .now).segments.map(\.flags) == [[.syn, .ack]])
        #expect(stack.receive(syn(17), at: .now) == [.dropped(.limitReached(.acceptQueueShare))])
        _ = try stack.listen(on: 8_443)
        let elsewhere = peerSegment(
            from: IPEndpoint(address: Self.peerV4, port: 3_000), to: IPEndpoint(address: WireHosts.v4b, port: 8_443),
            flags: [.syn])
        // 다른 리스너에서는 그 피어의 몫이 비어 있다.
        #expect(stack.receive(elsewhere.packet, at: .now).segments.map(\.flags) == [[.syn, .ack]])
        expectStackInvariants(stack)
    }

    @Test("묶지 않은 주소는 주소 하나가 한 몫이다")
    func ungroupedAddressesAreSeparate() throws {
        var stack = StackHosts.makeStack(addresses: StackHosts.serverAddresses, now: .now)
        _ = try stack.listen(on: 443)
        _ = try stack.listen(on: 8_443)
        // 리스너의 몫(16)과 겹치지 않게 두 리스너로 나눠 맺는 중 16개를 채운다.
        for index in 0..<32 {
            let (peer, server) = endpoints(index)
            let destination = IPEndpoint(address: server.address, port: index < 16 ? 443 : 8_443)
            let packet = peerSegment(from: peer, to: destination, flags: [.syn]).packet
            #expect(stack.receive(packet, at: .now).segments.map(\.flags) == [[.syn, .ack]])
        }
        #expect(stack.halfOpenCountByAddress == [Self.peerV4: 16, Self.peerV6: 16])
    }

    @Test("연결 64개는 두 주소를 합친 수다. 그 피어의 어느 주소로 거는 connect도 limitReached다")
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

    @Test("TIME-WAIT 기록 64개는 두 주소를 합친 수다. 65번째가 생기면 그 피어의 가장 오래된 기록(다른 주소의 것이라도)을 지운다")
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

        // 65번째는 IPv6 주소의 연결이고, 가장 오래된 기록은 IPv4 주소의 것이다.
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

    @Test("묶음을 다시 넘기면 그때부터 새 묶음으로 센다")
    func regrouping() throws {
        var stack = makeServer()
        _ = try stack.listen(on: 443)
        for index in 0..<16 {
            _ = stack.receive(syn(index), at: .now)
        }
        #expect(stack.receive(syn(16), at: .now) == [.dropped(.limitReached(.halfOpenConnectionsPerAddress))])
        // 두 주소가 서로 다른 피어의 것이 됐다. 주소마다 8개씩 쥔 것으로 본다.
        stack.setRemoteAddressGroups([Self.peerV4: 7, Self.peerV6: 9])
        #expect(stack.receive(syn(16), at: .now).segments.map(\.flags) == [[.syn, .ack]])
        expectStackInvariants(stack)
    }
}
