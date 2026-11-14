// 연결 시험의 공용 도우미. 연결 둘을 메모리에서 맞붙이는 `ConnectionPair`와, 연결 하나에 손으로 만든 세그먼트를 넣는
// 도우미를 둔다. 손실·재정렬을 주입하는 본격 하네스(`LinkSimulator`)는 M6-6의 몫이고, 여기는 필요한 만큼만이다.

import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// 시험의 가짜 주소. 실제 tailnet 주소가 아니다.
enum ConnectionHosts {
    static let client = IPEndpoint(address: WireHosts.v4a, port: 40_000)
    static let server = IPEndpoint(address: WireHosts.v4b, port: 443)
    static let client6 = IPEndpoint(address: WireHosts.v6a, port: 40_000)
    static let server6 = IPEndpoint(address: WireHosts.v6b, port: 443)
}

struct HarnessError: Error, CustomStringConvertible {
    var description: String
}

extension Array where Element == TCPConnection.Output {
    var segments: [TCPSegment] {
        compactMap { if case .segment(let segment) = $0 { segment } else { nil } }
    }

    var events: [TCPConnection.Event] {
        compactMap { if case .event(let event) = $0 { event } else { nil } }
    }
}

extension TCPSegment {
    /// IP 패킷으로 만들었다가 다시 해석한다. 코덱(체크섬, 옵션)을 함께 거친다.
    func roundTripped() throws -> TCPSegment {
        guard let packet = ipPacket() else { throw HarnessError(description: "IP 패킷을 만들지 못했다: \(self)") }
        return try TCPSegment(parsingIPPacket: packet)
    }
}

/// 시험용 바이트열. 씨앗에서 결정적으로 만든다.
func patternBytes(count: Int, seed: UInt8 = 7) -> [UInt8] {
    (0..<count).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ Int(seed) &+ ($0 >> 8)) }
}

/// 연결 둘(능동 열기의 `client`, 수동 열기의 `server`)을 손실 없는 링크로 잇는다. 시각은 시험이 넘긴다.
///
/// 세그먼트는 IP 패킷으로 만들었다가 다시 해석해 넘긴다. 한 쪽에 쌓인 세그먼트를 묶음으로 넣은 뒤 `advance(to:)`를 불러
/// 미뤄 둔 ACK를 받는다(노드의 묶음 처리와 같다). `drop`으로 특정 세그먼트를 잃게 할 수 있다.
struct ConnectionPair {
    enum Side { case client, server }

    var now: ContinuousClock.Instant
    var client: TCPConnection
    var server: TCPConnection
    var clientEvents: [TCPConnection.Event] = []
    var serverEvents: [TCPConnection.Event] = []
    /// 각 쪽이 낸 세그먼트 전부(잃은 것 포함). 시각과 함께.
    var clientSent: [(at: ContinuousClock.Instant, segment: TCPSegment)] = []
    var serverSent: [(at: ContinuousClock.Instant, segment: TCPSegment)] = []
    var toServer: [TCPSegment] = []
    var toClient: [TCPSegment] = []
    /// 참이면 그 세그먼트를 잃는다.
    var drop: (Side, TCPSegment) -> Bool = { _, _ in false }
    /// 거짓이면 세그먼트마다 `advance`를 불러 ACK를 모으지 않는다(중복 ACK를 하나씩 받게 한다).
    var batched = true

    /// 세 방향 핸드셰이크까지 마친 쌍.
    static func established(
        clientISS: UInt32 = 1_000, serverISS: UInt32 = 900_000,
        client local: IPEndpoint = ConnectionHosts.client, server remote: IPEndpoint = ConnectionHosts.server,
        roundTrip: Duration = .milliseconds(10)
    ) throws -> ConnectionPair {
        var pair = try opened(
            clientISS: clientISS, serverISS: serverISS, client: local, server: remote, roundTrip: roundTrip)
        try pair.deliver()
        guard pair.client.state == .established, pair.server.state == .established else {
            throw HarnessError(description: "맺어지지 않았다: \(pair.client.state), \(pair.server.state)")
        }
        return pair
    }

    /// SYN을 보내고 서버가 SYN-ACK를 낸 쌍. `roundTrip`의 절반마다 한 번 건넌다.
    static func opened(
        clientISS: UInt32 = 1_000, serverISS: UInt32 = 900_000,
        client local: IPEndpoint = ConnectionHosts.client, server remote: IPEndpoint = ConnectionHosts.server,
        roundTrip: Duration = .milliseconds(10)
    ) throws -> ConnectionPair {
        let start = ContinuousClock.now
        let (client, clientOutputs) = TCPConnection.connect(
            from: local, to: remote, initialSequenceNumber: SequenceNumber(clientISS), at: start)
        guard let syn = clientOutputs.segments.first else { throw HarnessError(description: "SYN이 없다") }
        let arrival = start + roundTrip / 2
        let (server, serverOutputs) = try TCPConnection.accept(
            syn.roundTripped(), initialSequenceNumber: SequenceNumber(serverISS), at: arrival)
        var pair = ConnectionPair(now: start + roundTrip, client: client, server: server)
        pair.clientSent = [(start, syn)]
        pair.collect(serverOutputs, from: .server)
        return pair
    }

    mutating func collect(_ outputs: [TCPConnection.Output], from side: Side) {
        for output in outputs {
            switch output {
            case .segment(let segment):
                switch side {
                case .client:
                    clientSent.append((now, segment))
                    if !drop(.client, segment) { toServer.append(segment) }
                case .server:
                    serverSent.append((now, segment))
                    if !drop(.server, segment) { toClient.append(segment) }
                }
            case .event(let event):
                switch side {
                case .client: clientEvents.append(event)
                case .server: serverEvents.append(event)
                }
            }
        }
    }

    /// 쌓인 세그먼트를 모두 건넨다. 받은 쪽은 묶음 하나를 받은 뒤 `advance(to: now)`로 ACK를 낸다.
    mutating func deliver() throws {
        var rounds = 0
        while !toServer.isEmpty || !toClient.isEmpty {
            rounds += 1
            guard rounds < 100_000 else { throw HarnessError(description: "주고받기가 끝나지 않는다") }
            let forServer = toServer
            toServer = []
            for segment in forServer {
                collect(server.receive(try segment.roundTripped(), at: now), from: .server)
                if !batched { collect(server.advance(to: now), from: .server) }
            }
            if !forServer.isEmpty { collect(server.advance(to: now), from: .server) }
            let forClient = toClient
            toClient = []
            for segment in forClient {
                collect(client.receive(try segment.roundTripped(), at: now), from: .client)
                if !batched { collect(client.advance(to: now), from: .client) }
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

    mutating func write(_ bytes: [UInt8], from side: Side) -> Int {
        switch side {
        case .client:
            let (accepted, outputs) = client.write(bytes[...], at: now)
            collect(outputs, from: .client)
            return accepted
        case .server:
            let (accepted, outputs) = server.write(bytes[...], at: now)
            collect(outputs, from: .server)
            return accepted
        }
    }

    mutating func read(_ side: Side, upTo maximumLength: Int = .max) -> [UInt8] {
        switch side {
        case .client:
            let (bytes, outputs) = client.read(upTo: maximumLength, at: now)
            collect(outputs, from: .client)
            return bytes
        case .server:
            let (bytes, outputs) = server.read(upTo: maximumLength, at: now)
            collect(outputs, from: .server)
            return bytes
        }
    }

    mutating func finishWriting(_ side: Side) {
        switch side {
        case .client: collect(client.finishWriting(at: now), from: .client)
        case .server: collect(server.finishWriting(at: now), from: .server)
        }
    }

    mutating func close(_ side: Side) {
        switch side {
        case .client: collect(client.close(at: now), from: .client)
        case .server: collect(server.close(at: now), from: .server)
        }
    }

    /// 양쪽이 동시에 `data`를 보내고 서로 끝까지 읽는다. 받은 바이트를 돌려준다(`client`가 받은 것, `server`가 받은 것).
    /// 타이머가 돌아야 하면(지연 ACK, 재전송) `step`씩 시각을 넘긴다.
    mutating func exchange(
        clientSends: [UInt8], serverSends: [UInt8], step: Duration = .milliseconds(5),
        timeLimit: Duration = .seconds(600)
    ) throws -> (clientReceived: [UInt8], serverReceived: [UInt8]) {
        var clientOffset = 0
        var serverOffset = 0
        var clientReceived: [UInt8] = []
        var serverReceived: [UInt8] = []
        let deadline = now + timeLimit
        while clientReceived.count < serverSends.count || serverReceived.count < clientSends.count {
            guard now < deadline else {
                throw HarnessError(
                    description: "전송이 끝나지 않는다: \(serverReceived.count)/\(clientSends.count), "
                        + "\(clientReceived.count)/\(serverSends.count)")
            }
            if clientOffset < clientSends.count {
                clientOffset += write(Array(clientSends[clientOffset...]), from: .client)
            }
            if serverOffset < serverSends.count {
                serverOffset += write(Array(serverSends[serverOffset...]), from: .server)
            }
            try deliver()
            clientReceived += read(.client)
            serverReceived += read(.server)
            try deliver()
            try run(for: step)
        }
        return (clientReceived, serverReceived)
    }
}

/// 연결 하나에 손으로 만든 세그먼트를 넣는 시험용 상대. 연결은 `server`(수동 열기) 쪽이고, 이 값이 상대(client)의 번호를 쥔다.
struct ManualPeer {
    var connection: TCPConnection
    var now: ContinuousClock.Instant
    /// 상대가 다음에 쓸 번호(상대의 SND.NXT).
    var peerNext: SequenceNumber
    /// 상대의 창 필드.
    var peerWindow: UInt16 = 65_535

    /// 수동 열기로 맺어진 연결. 상대 SYN의 MSS·Window Scale을 고를 수 있다.
    static func established(
        peerISS: UInt32 = 5_000, iss: UInt32 = 70_000, maximumSegmentSize: UInt16? = 1_240,
        windowScale: UInt8? = nil, synWindow: UInt16 = 65_535, ackWindow: UInt16 = 65_535
    ) throws -> ManualPeer {
        let start = ContinuousClock.now
        let syn = TCPSegment(
            source: ConnectionHosts.client, destination: ConnectionHosts.server,
            sequenceNumber: SequenceNumber(peerISS), flags: [.syn], window: synWindow,
            maximumSegmentSize: maximumSegmentSize, windowScale: windowScale)
        let (connection, _) = try TCPConnection.accept(syn, initialSequenceNumber: SequenceNumber(iss), at: start)
        var peer = ManualPeer(connection: connection, now: start, peerNext: SequenceNumber(peerISS).advanced(by: 1))
        peer.peerWindow = ackWindow
        let outputs = peer.send(flags: [.ack])
        guard outputs.events == [.established] else {
            throw HarnessError(description: "맺어지지 않았다: \(outputs)")
        }
        return peer
    }

    /// 상대가 보낸 세그먼트. 번호는 `sequence`(기본 `peerNext`), ACK는 `acknowledgment`(기본 연결의 SND.NXT).
    func segment(
        sequence: SequenceNumber? = nil, acknowledgment: SequenceNumber? = nil, flags: TCPSegment.Flags,
        payload: [UInt8] = [], window: UInt16? = nil
    ) -> TCPSegment {
        TCPSegment(
            source: ConnectionHosts.client, destination: ConnectionHosts.server,
            sequenceNumber: sequence ?? peerNext,
            acknowledgmentNumber: acknowledgment ?? connection.sendNext, flags: flags,
            window: window ?? peerWindow, payload: payload)
    }

    /// 세그먼트를 넣고 같은 시각의 `advance`까지 부른다(미뤄 둔 ACK를 받는다).
    mutating func receive(_ segment: TCPSegment) -> [TCPConnection.Output] {
        connection.receive(segment, at: now) + connection.advance(to: now)
    }

    /// `peerNext`에서 시작하는 세그먼트를 보내고 `peerNext`를 그만큼 옮긴다.
    @discardableResult
    mutating func send(
        flags: TCPSegment.Flags, payload: [UInt8] = [], acknowledgment: SequenceNumber? = nil, window: UInt16? = nil
    ) -> [TCPConnection.Output] {
        let segment = segment(acknowledgment: acknowledgment, flags: flags, payload: payload, window: window)
        peerNext = peerNext.advanced(by: segment.sequenceLength)
        return receive(segment)
    }

    mutating func advance(by duration: Duration) -> [TCPConnection.Output] {
        now = now + duration
        return connection.advance(to: now)
    }
}
