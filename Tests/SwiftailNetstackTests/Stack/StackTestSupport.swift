// 스택 시험의 공용 도우미. 스택 둘을 메모리에서 맞붙이는 `StackPair`, 스택 하나에 손으로 만든 패킷을 넣는 도우미,
// 표의 불변식 검사를 둔다. 손실·재정렬을 주입하는 하네스는 M6-6의 몫이다.

import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// 시험의 가짜 주소와 비밀. 실제 tailnet 주소가 아니다.
enum StackHosts {
    static let clientAddresses = [WireHosts.v4a, WireHosts.v6a]
    static let serverAddresses = [WireHosts.v4b, WireHosts.v6b]
    static let secret = (0..<32).map { UInt8($0) &* 7 &+ 3 }

    /// 100.64.1.`host`.
    static func peer(_ host: UInt8) -> IPAddress {
        WireHosts.address("100.64.1.\(host)")
    }

    static func makeStack(
        addresses: [IPAddress], now: ContinuousClock.Instant, secret: [UInt8] = StackHosts.secret
    ) -> TCPStack {
        var stack = TCPStack(isnSecret: secret, now: now)
        _ = stack.setLocalAddresses(addresses)
        return stack
    }
}

extension Array where Element == TCPStack.Output {
    var packets: [[UInt8]] {
        compactMap { if case .ipPacket(let packet) = $0 { packet } else { nil } }
    }

    /// 낸 패킷을 해석한 세그먼트. 스택이 낸 패킷은 늘 해석된다(아니면 시험이 실패한다).
    var segments: [TCPSegment] {
        packets.map { packet in
            do {
                return try TCPSegment(parsingIPPacket: packet)
            } catch {
                Issue.record("스택이 해석되지 않는 패킷을 냈다: \(error)")
                return TCPSegment(
                    source: IPEndpoint(address: WireHosts.v4a, port: 0),
                    destination: IPEndpoint(address: WireHosts.v4a, port: 0), sequenceNumber: SequenceNumber(0),
                    flags: [])
            }
        }
    }

    var events: [TCPStack.Event] {
        compactMap { if case .event(let event) = $0 { event } else { nil } }
    }

    var drops: [TCPStack.Drop] {
        compactMap { if case .dropped(let drop) = $0 { drop } else { nil } }
    }
}

extension TCPSegment {
    /// 시험이 스택에 넣을 패킷 바이트.
    var packet: [UInt8] {
        guard let packet = ipPacket() else { fatalError("시험의 세그먼트를 패킷으로 만들지 못했다: \(self)") }
        return packet
    }
}

/// 상대가 보내는 세그먼트를 짧게 만든다.
func peerSegment(
    from source: IPEndpoint, to destination: IPEndpoint, sequence: UInt32 = 5_000,
    acknowledgment: SequenceNumber = SequenceNumber(0), flags: TCPSegment.Flags, payload: [UInt8] = [],
    window: UInt16 = 65_535, maximumSegmentSize: UInt16? = nil
) -> TCPSegment {
    TCPSegment(
        source: source, destination: destination, sequenceNumber: SequenceNumber(sequence),
        acknowledgmentNumber: acknowledgment, flags: flags, window: window,
        maximumSegmentSize: maximumSegmentSize ?? (flags.contains(.syn) ? 1_240 : nil), payload: payload)
}

/// 스택 둘(`client`는 IPv4·IPv6 주소 `v4a`·`v6a`, `server`는 `v4b`·`v6b`)을 손실 없는 링크로 잇는다. 시각은 시험이 넘긴다.
///
/// 한 쪽에 쌓인 패킷을 묶음으로 넣은 뒤 같은 시각으로 `advance(to:)`를 불러 미뤄 둔 ACK를 받는다(노드의 묶음 처리와 같다).
struct StackPair {
    enum Side { case client, server }

    var now: ContinuousClock.Instant
    var client: TCPStack
    var server: TCPStack
    var clientEvents: [TCPStack.Event] = []
    var serverEvents: [TCPStack.Event] = []
    var clientDrops: [TCPStack.Drop] = []
    var serverDrops: [TCPStack.Drop] = []
    /// 각 쪽이 낸 세그먼트 전부.
    var clientSent: [TCPSegment] = []
    var serverSent: [TCPSegment] = []
    var toServer: [[UInt8]] = []
    var toClient: [[UInt8]] = []

    init(now: ContinuousClock.Instant = .now) {
        self.now = now
        client = StackHosts.makeStack(addresses: StackHosts.clientAddresses, now: now)
        server = StackHosts.makeStack(addresses: StackHosts.serverAddresses, now: now, secret: Array(StackHosts.secret.reversed()))
    }

    mutating func collect(_ outputs: [TCPStack.Output], from side: Side) {
        for output in outputs {
            switch (output, side) {
            case (.ipPacket(let packet), .client):
                toServer.append(packet)
                if let segment = try? TCPSegment(parsingIPPacket: packet) { clientSent.append(segment) }
            case (.ipPacket(let packet), .server):
                toClient.append(packet)
                if let segment = try? TCPSegment(parsingIPPacket: packet) { serverSent.append(segment) }
            case (.event(let event), .client): clientEvents.append(event)
            case (.event(let event), .server): serverEvents.append(event)
            case (.dropped(let drop), .client): clientDrops.append(drop)
            case (.dropped(let drop), .server): serverDrops.append(drop)
            }
        }
    }

    /// 쌓인 패킷을 모두 건넨다. 받은 쪽은 묶음 하나를 받은 뒤 `advance(to: now)`로 ACK를 낸다.
    mutating func deliver() throws {
        var rounds = 0
        while !toServer.isEmpty || !toClient.isEmpty {
            rounds += 1
            guard rounds < 100_000 else { throw HarnessError(description: "주고받기가 끝나지 않는다") }
            let forServer = toServer
            toServer = []
            for packet in forServer {
                collect(server.receive(packet, at: now), from: .server)
            }
            if !forServer.isEmpty { collect(server.advance(to: now), from: .server) }
            let forClient = toClient
            toClient = []
            for packet in forClient {
                collect(client.receive(packet, at: now), from: .client)
            }
            if !forClient.isEmpty { collect(client.advance(to: now), from: .client) }
        }
    }

    /// `limit`까지 타이머를 돌리며 주고받는다. 끝나면 `now`는 `limit`이다.
    mutating func run(until limit: ContinuousClock.Instant) throws {
        try deliver()
        while let next = [client.nextDeadline, server.nextDeadline].compactMap({ $0 }).min(), next <= limit {
            now = max(now, next)
            collect(client.advance(to: now), from: .client)
            collect(server.advance(to: now), from: .server)
            try deliver()
        }
        now = max(now, limit)
    }

    mutating func run(for duration: Duration) throws {
        try run(until: now + duration)
    }

    /// 클라이언트가 서버의 `port`로 걸고, 서버가 대기열에서 꺼낸다. 두 쪽의 ID를 돌려준다.
    mutating func open(
        port: UInt16 = 443, listener: TCPStack.ListenerID, ipv6: Bool = false
    ) throws -> (client: TCPStack.ConnectionID, server: TCPStack.ConnectionID) {
        let address = ipv6 ? WireHosts.v6b : WireHosts.v4b
        let (clientID, outputs) = try client.connect(to: IPEndpoint(address: address, port: port), at: now)
        collect(outputs, from: .client)
        try deliver()
        guard let serverID = server.accept(from: listener) else {
            throw HarnessError(description: "서버의 대기열이 비었다: \(serverDrops)")
        }
        return (clientID, serverID)
    }

    mutating func write(_ bytes: [UInt8], to id: TCPStack.ConnectionID, from side: Side) -> Int {
        switch side {
        case .client:
            let (accepted, outputs) = client.write(bytes[...], to: id, at: now)
            collect(outputs, from: .client)
            return accepted
        case .server:
            let (accepted, outputs) = server.write(bytes[...], to: id, at: now)
            collect(outputs, from: .server)
            return accepted
        }
    }

    mutating func read(_ id: TCPStack.ConnectionID, from side: Side) -> [UInt8] {
        switch side {
        case .client:
            let (bytes, outputs) = client.read(upTo: .max, from: id, at: now)
            collect(outputs, from: .client)
            return bytes
        case .server:
            let (bytes, outputs) = server.read(upTo: .max, from: id, at: now)
            collect(outputs, from: .server)
            return bytes
        }
    }

    /// 클라이언트가 먼저 닫고 서버가 뒤따라 닫는다. 클라이언트에 TIME-WAIT가 남는다.
    mutating func closeFromClient(_ ids: (client: TCPStack.ConnectionID, server: TCPStack.ConnectionID)) throws {
        collect(client.close(ids.client, at: now), from: .client)
        try deliver()
        collect(server.close(ids.server, at: now), from: .server)
        try deliver()
    }
}

/// 스택의 표가 서로 맞고 상한 안인지 본다(계약 동작 M).
func expectStackInvariants(_ stack: TCPStack, sourceLocation: SourceLocation = #_sourceLocation) {
    #expect(stack.connections.count <= TCPStack.maximumConnections, sourceLocation: sourceLocation)
    #expect(stack.timeWaitRecords.count <= TCPStack.maximumTimeWaitRecords, sourceLocation: sourceLocation)
    #expect(stack.listeners.count <= TCPStack.maximumListeners, sourceLocation: sourceLocation)
    var halfOpenByAddress: [IPAddress: Int] = [:]
    var halfOpenByListener: [TCPStack.ListenerID: Int] = [:]
    for entry in stack.connections.values {
        if case .halfOpen(let listener) = entry.role {
            #expect(entry.connection.state == .synReceived, sourceLocation: sourceLocation)
            halfOpenByAddress[entry.connection.remoteEndpoint.address, default: 0] += 1
            halfOpenByListener[listener, default: 0] += 1
        }
    }
    let halfOpen = halfOpenByAddress.values.reduce(0, +)
    #expect(stack.halfOpenCount == halfOpen, sourceLocation: sourceLocation)
    #expect(halfOpen <= TCPStack.maximumHalfOpenConnections, sourceLocation: sourceLocation)
    #expect(stack.halfOpenCountByAddress == halfOpenByAddress, sourceLocation: sourceLocation)
    #expect(
        halfOpenByAddress.values.allSatisfy { $0 <= TCPStack.maximumHalfOpenConnectionsPerAddress },
        sourceLocation: sourceLocation)
    for (id, listener) in stack.listeners {
        #expect(listener.halfOpenCount == halfOpenByListener[id, default: 0], sourceLocation: sourceLocation)
        #expect(
            listener.queue.count + listener.halfOpenCount <= TCPStack.maximumAcceptQueueLength,
            sourceLocation: sourceLocation)
        for queued in listener.queue {
            #expect(stack.connections[queued]?.role == .queued(id), sourceLocation: sourceLocation)
        }
    }
    #expect(stack.earliestTimeWaitDeadline == stack.timeWaitRecords.values.map(\.deadline).min(), sourceLocation: sourceLocation)
    for (tuple, id) in stack.connectionsByTuple {
        #expect(stack.connections[id]?.tuple == tuple, sourceLocation: sourceLocation)
        #expect(stack.timeWaitRecords[tuple] == nil, sourceLocation: sourceLocation)
    }
}
