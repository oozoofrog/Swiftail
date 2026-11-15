import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// 찾기, 맞붙인 스택 둘의 열기·전송·닫기, 묶음 ACK, 출력의 순서.
/// 계약 `docs/contracts/SwiftailNetstack.md` 동작 S1·S3·S5·S6·S10과 시험 11.
@Suite("스택: 찾기와 전송")
struct StackLookupTests {
    @Test("스택 둘이 IPv4·IPv6로 열고, 양방향으로 보내고, 닫는다", arguments: [false, true])
    func openTransferClose(ipv6: Bool) throws {
        var pair = StackPair()
        let listener = try pair.server.listen(on: 443)
        let ids = try pair.open(listener: listener, ipv6: ipv6)
        #expect(pair.clientEvents == [.established(ids.client)])
        #expect(pair.serverEvents == [.acceptable(listener)])
        let local = try #require(pair.client.connection(ids.client)?.localEndpoint)
        #expect(local.address == (ipv6 ? WireHosts.v6a : WireHosts.v4a))
        #expect(pair.server.connection(ids.server)?.remoteEndpoint == local)

        let upload = patternBytes(count: 300_000, seed: 1)
        let download = patternBytes(count: 200_000, seed: 2)
        var sentUp = 0
        var sentDown = 0
        var receivedUp: [UInt8] = []
        var receivedDown: [UInt8] = []
        let deadline = pair.now + .seconds(60)
        while receivedUp.count < upload.count || receivedDown.count < download.count {
            #expect(pair.now < deadline)
            guard pair.now < deadline else { break }
            if sentUp < upload.count { sentUp += pair.write(Array(upload[sentUp...]), to: ids.client, from: .client) }
            if sentDown < download.count {
                sentDown += pair.write(Array(download[sentDown...]), to: ids.server, from: .server)
            }
            try pair.deliver()
            receivedUp += pair.read(ids.server, from: .server)
            receivedDown += pair.read(ids.client, from: .client)
            try pair.run(for: .milliseconds(5))
        }
        #expect(receivedUp == upload)
        #expect(receivedDown == download)

        // 클라이언트가 쓰기를 먼저 끝내고, 서버가 닫는다. 클라이언트는 TIME-WAIT에 들어 기록을 남긴다.
        pair.collect(pair.client.finishWriting(ids.client, at: pair.now), from: .client)
        try pair.deliver()
        #expect(pair.serverEvents.last == .endOfStream(ids.server))
        pair.collect(pair.server.close(ids.server, at: pair.now), from: .server)
        try pair.deliver()
        #expect(
            pair.clientEvents.suffix(2).map(\.withoutStatistics)
                == [.endOfStream(ids.client), .closed(ids.client, .finished, .unchecked)])
        #expect(pair.client.connections.isEmpty)
        #expect(pair.client.timeWaitRecords.count == 1)
        #expect(pair.server.connections.isEmpty)
        #expect(!pair.serverEvents.contains { if case .closed = $0 { true } else { false } })

        try pair.run(for: .seconds(61))
        #expect(pair.client.timeWaitRecords.isEmpty)
        #expect(pair.client.nextDeadline == nil)
        #expect(pair.server.nextDeadline == nil)
        expectStackInvariants(pair.client)
        expectStackInvariants(pair.server)
    }

    @Test("같은 상대의 두 연결은 4-튜플로 갈린다")
    func twoConnectionsFromOnePeer() throws {
        var pair = StackPair()
        let listener = try pair.server.listen(on: 443)
        let first = try pair.open(listener: listener)
        let second = try pair.open(listener: listener)
        let firstPort = pair.client.connection(first.client)?.localEndpoint.port
        let secondPort = pair.client.connection(second.client)?.localEndpoint.port
        #expect(firstPort == 49_152)
        #expect(secondPort == 49_153)
        #expect(pair.server.connection(first.server)?.remoteEndpoint.port == firstPort)
        #expect(pair.server.connection(second.server)?.remoteEndpoint.port == secondPort)

        _ = pair.write([1, 1, 1], to: first.client, from: .client)
        _ = pair.write([2, 2], to: second.client, from: .client)
        try pair.deliver()
        #expect(pair.read(first.server, from: .server) == [1, 1, 1])
        #expect(pair.read(second.server, from: .server) == [2, 2])
    }

    @Test("목적지가 자기 주소가 아니면 notForUs로 버리고 답하지 않는다")
    func notForUs() {
        var stack = StackHosts.makeStack(addresses: [WireHosts.v4b], now: .now)
        _ = try? stack.listen(on: 443)
        let syn = peerSegment(
            from: IPEndpoint(address: WireHosts.v4a, port: 40_000),
            to: IPEndpoint(address: StackHosts.peer(9), port: 443), flags: [.syn])
        #expect(stack.receive(syn.packet, at: .now) == [.dropped(.notForUs)])
        // IPv6 주소를 갖지 않은 스택에 온 IPv6 패킷도 같다.
        let syn6 = peerSegment(
            from: IPEndpoint(address: WireHosts.v6a, port: 40_000), to: IPEndpoint(address: WireHosts.v6b, port: 443),
            flags: [.syn])
        #expect(stack.receive(syn6.packet, at: .now) == [.dropped(.notForUs)])
        #expect(stack.connections.isEmpty)
    }

    @Test("TCP가 아니거나 해석되지 않는 패킷은 그 까닭으로 버린다")
    func unparsable() {
        var stack = StackHosts.makeStack(addresses: [WireHosts.v4b], now: .now)
        var udp = peerSegment(
            from: IPEndpoint(address: WireHosts.v4a, port: 40_000), to: IPEndpoint(address: WireHosts.v4b, port: 53),
            flags: [.ack]
        ).packet
        udp[9] = 17
        #expect(stack.receive(udp, at: .now) == [.dropped(.notTCP)])
        #expect(stack.receive([], at: .now) == [.dropped(.malformed)])
        #expect(stack.receive([0x45, 0, 0], at: .now) == [.dropped(.malformed)])
        var corrupted = peerSegment(
            from: IPEndpoint(address: WireHosts.v4a, port: 40_000), to: IPEndpoint(address: WireHosts.v4b, port: 443),
            flags: [.syn]
        ).packet
        corrupted[corrupted.count - 1] ^= 0xFF
        #expect(stack.receive(corrupted, at: .now) == [.dropped(.badChecksum)])
    }

    @Test("묶음으로 받은 데이터 세그먼트 둘(2×MSS)에는 둘째의 receive가 ACK 하나를 내고, 같은 시각의 advance는 내지 않는다")
    func batchAcknowledgment() throws {
        var pair = StackPair()
        let listener = try pair.server.listen(on: 443)
        let ids = try pair.open(listener: listener)
        _ = pair.write(patternBytes(count: 2 * 1_240), to: ids.client, from: .client)
        let packets = pair.toServer
        pair.toServer = []
        #expect(packets.count == 2)

        let first = pair.server.receive(packets[0], at: pair.now)
        let second = pair.server.receive(packets[1], at: pair.now)
        #expect(first.packets.isEmpty)
        #expect(first.events == [.readable(ids.server)])
        #expect(pair.server.advance(to: pair.now).packets.isEmpty)
        let acknowledgments = second.segments
        #expect(acknowledgments.count == 1)
        let expected = try #require(pair.clientSent.last).sequenceNumber.advanced(by: 1_240)
        #expect(acknowledgments.first?.acknowledgmentNumber == expected)
        #expect(acknowledgments.first?.flags == [.ack])
    }

    @Test("출력의 순서: 한 연결의 패킷은 시퀀스 순서, 데이터의 readable이 FIN의 endOfStream보다 앞")
    func outputOrder() throws {
        var pair = StackPair()
        let listener = try pair.server.listen(on: 443)
        let ids = try pair.open(listener: listener)
        _ = pair.write(patternBytes(count: 6_000), to: ids.client, from: .client)
        pair.collect(pair.client.finishWriting(ids.client, at: pair.now), from: .client)
        let segments = pair.toServer.compactMap { try? TCPSegment(parsingIPPacket: $0) }
        #expect(segments.count >= 5)
        for (earlier, later) in zip(segments, segments.dropFirst()) {
            #expect(earlier.sequenceNumber.precedes(later.sequenceNumber))
        }
        try pair.deliver()
        let readable = pair.serverEvents.firstIndex(of: .readable(ids.server))
        let end = pair.serverEvents.firstIndex(of: .endOfStream(ids.server))
        #expect(readable != nil && end != nil)
        if let readable, let end { #expect(readable < end) }
    }

    @Test("맺는 중인 연결이 RST로 끝나면 알리지 않고 지운다")
    func halfOpenReset() throws {
        var stack = StackHosts.makeStack(addresses: [WireHosts.v4b], now: .now)
        let listener = try stack.listen(on: 443)
        let peer = IPEndpoint(address: WireHosts.v4a, port: 40_000)
        let server = IPEndpoint(address: WireHosts.v4b, port: 443)
        let synOutputs = stack.receive(peerSegment(from: peer, to: server, sequence: 100, flags: [.syn]).packet, at: .now)
        let synAck = try #require(synOutputs.segments.first)
        #expect(stack.halfOpenCount == 1)
        let reset = peerSegment(
            from: peer, to: server, sequence: 101, acknowledgment: synAck.sequenceNumber.advanced(by: 1), flags: [.rst])
        let outputs = stack.receive(reset.packet, at: .now) + stack.advance(to: .now)
        #expect(outputs.isEmpty)
        #expect(stack.connections.isEmpty)
        #expect(stack.halfOpenCount == 0)
        #expect(stack.accept(from: listener) == nil)
        expectStackInvariants(stack)
    }

    @Test("대기열에 있는 동안 받은 데이터와 FIN은 사건 없이 남고, 꺼낸 뒤 읽힌다")
    func queuedConnectionKeepsData() throws {
        var pair = StackPair()
        let listener = try pair.server.listen(on: 443)
        let (clientID, outputs) = try pair.client.connect(to: IPEndpoint(address: WireHosts.v4b, port: 443), at: pair.now)
        pair.collect(outputs, from: .client)
        try pair.deliver()
        _ = pair.write([9, 8, 7], to: clientID, from: .client)
        pair.collect(pair.client.finishWriting(clientID, at: pair.now), from: .client)
        try pair.deliver()
        #expect(pair.serverEvents == [.acceptable(listener)])
        let popped = pair.server.accept(from: listener)
        let serverID = try #require(popped)
        #expect(pair.server.connection(serverID)?.readableByteCount == 3)
        #expect(pair.server.connection(serverID)?.hasReceivedEndOfStream == true)
        #expect(pair.read(serverID, from: .server) == [9, 8, 7])
    }
}
