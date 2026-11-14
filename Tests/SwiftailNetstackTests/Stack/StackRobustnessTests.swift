import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// 임의의 입력에 죽지 않고 상한을 넘지 않는다. 연결 256개·TIME-WAIT 기록 1,024개에서의 비용.
/// 계약 `docs/contracts/SwiftailNetstack.md` 동작 X1·X7·X8, M과 시험 11.
@Suite("스택: 임의 입력과 비용")
struct StackRobustnessTests {
    @Test("임의 패킷·SYN 홍수·응용 호출·시각을 섞어 넣어도 죽지 않고 표가 상한 안에서 서로 맞는다", arguments: [1, 2, 3] as [UInt64])
    func randomTraffic(seed: UInt64) {
        var random = WireFuzzRandom(seed: seed)
        var now = ContinuousClock.now
        var stack = StackHosts.makeStack(addresses: StackHosts.serverAddresses, now: now)
        var listeners: [TCPStack.ListenerID] = []
        for port: UInt16 in [443, 8_443] {
            if let id = try? stack.listen(on: port) { listeners.append(id) }
        }
        var owned: [TCPStack.ConnectionID] = []
        var recent: [TCPSegment] = []
        var synAcks: [TCPSegment] = []
        var drops: [TCPStack.Drop] = []

        func remember(_ outputs: [TCPStack.Output]) {
            for segment in outputs.segments where segment.flags == [.syn, .ack] {
                synAcks.append(segment)
            }
            if synAcks.count > 64 { synAcks.removeFirst(synAcks.count - 64) }
            drops += outputs.drops
        }

        for step in 0..<20_000 {
            var outputs: [TCPStack.Output] = []
            let ports: [UInt16] = [443, 8_443, 80, UInt16.random(in: 1...UInt16.max, using: &random)]
            let remote = IPEndpoint(
                address: StackHosts.peer(UInt8.random(in: 1...3, using: &random)),
                port: UInt16.random(in: 1_000...1_100, using: &random))
            let local = IPEndpoint(
                address: WireHosts.v4b, port: ports[Int.random(in: 0..<ports.count, using: &random)])
            switch Int.random(in: 0..<10, using: &random) {
            case 0:
                outputs = stack.receive(random.bytes(Int.random(in: 0...80, using: &random)), at: now)
            case 1, 2:
                let syn = peerSegment(
                    from: remote, to: local, sequence: UInt32.random(in: 0...UInt32.max, using: &random), flags: [.syn])
                recent.append(syn)
                outputs = stack.receive(syn.packet, at: now)
            case 3:
                if let synAck = synAcks.randomElement(using: &random) {
                    let ack = peerSegment(
                        from: synAck.destination, to: synAck.source,
                        sequence: synAck.acknowledgmentNumber.rawValue,
                        acknowledgment: synAck.sequenceNumber.advanced(by: 1), flags: [.ack],
                        payload: random.bytes(Int.random(in: 0...20, using: &random)))
                    recent.append(ack)
                    outputs = stack.receive(ack.packet, at: now)
                }
            case 4:
                if var segment = recent.randomElement(using: &random) {
                    segment.flags = TCPSegment.Flags(rawValue: UInt8.random(in: 0...0x1F, using: &random))
                    segment.sequenceNumber = segment.sequenceNumber.advanced(by: UInt32.random(in: 0...UInt32.max, using: &random))
                    segment.acknowledgmentNumber = SequenceNumber(UInt32.random(in: 0...UInt32.max, using: &random))
                    segment.window = UInt16.random(in: 0...UInt16.max, using: &random)
                    segment.payload = random.bytes(Int.random(in: 0...40, using: &random))
                    var packet = segment.packet
                    if Bool.random(using: &random) {
                        let index = Int.random(in: 0..<packet.count, using: &random)
                        packet[index] = UInt8.random(in: 0...UInt8.max, using: &random)
                    }
                    outputs = stack.receive(packet, at: now)
                }
            case 5:
                now = now + .milliseconds(Int.random(in: 0...2_000, using: &random))
            case 6:
                for listener in listeners {
                    while let id = stack.accept(from: listener) { owned.append(id) }
                }
            case 7:
                if let id = owned.randomElement(using: &random) {
                    switch Int.random(in: 0..<5, using: &random) {
                    case 0: outputs = stack.write(random.bytes(500)[...], to: id, at: now).outputs
                    case 1: outputs = stack.read(upTo: 1_000, from: id, at: now).outputs
                    case 2: outputs = stack.finishWriting(id, at: now)
                    case 3: outputs = stack.close(id, at: now)
                    default: outputs = stack.abort(id, at: now)
                    }
                }
            case 8:
                outputs = (try? stack.connect(to: remote, at: now).outputs) ?? []
            default:
                // 주소의 주인이 바뀌는 일은 드물게 섞는다(잦으면 홍수가 상한에 닿기 전에 지워진다).
                if Int.random(in: 0..<20, using: &random) == 0 {
                    outputs = stack.removeConnections(toRemoteAddress: remote.address)
                }
            }
            remember(outputs)
            remember(stack.advance(to: now))
            if recent.count > 64 { recent.removeFirst(recent.count - 64) }
            if step % 200 == 0 { expectStackInvariants(stack) }
        }
        expectStackInvariants(stack)
        // 상한이 실제로 걸렸는지(홍수가 상한까지 닿았는지)도 본다.
        let limits: [TCPStack.Limit] = drops.compactMap { if case .limitReached(let limit) = $0 { limit } else { nil } }
        print("임의 입력(씨앗 \(seed)): 상한에 닿아 버린 SYN \(limits.count)개, 종류 \(Set(limits.map { "\($0)" }).sorted())")
        #expect(limits.contains(.halfOpenConnectionsPerAddress))
        #expect(drops.contains(.malformed) || drops.contains(.badChecksum))
    }

    @Test("연결 256개와 TIME-WAIT 기록 1,024개에서 패킷 하나·기한 찾기·advance의 비용")
    func costAtLimits() throws {
        let start = ContinuousClock.now
        var stack = StackHosts.makeStack(addresses: StackHosts.clientAddresses, now: start)
        for index in 0..<256 {
            _ = try stack.connect(to: IPEndpoint(address: WireHosts.v4b, port: UInt16(1_000 + index)), at: start)
        }
        for index in 0..<1_024 {
            let tuple = FourTuple(
                local: IPEndpoint(address: WireHosts.v4a, port: UInt16(20_000 + index)),
                remote: IPEndpoint(address: WireHosts.v4b, port: 443))
            stack.addTimeWaitRecord(
                TimeWaitRecord(
                    sendNext: SequenceNumber(1), receiveNext: SequenceNumber(2),
                    deadline: start + .seconds(60) + .milliseconds(index)),
                for: tuple)
        }
        #expect(stack.connections.count == 256)

        let iterations = 2_000
        let clock = ContinuousClock()
        // SYN-SENT 연결에 온, 답하지 않는 세그먼트(ACK 없는 RST): 찾기와 연결 하나의 처리.
        let target = try #require(stack.connections.values.first?.connection)
        let ignored = peerSegment(
            from: target.remoteEndpoint, to: target.localEndpoint, sequence: 1, flags: [.rst]
        ).packet
        var deadline: ContinuousClock.Instant?
        let receiveTime = clock.measure {
            for _ in 0..<iterations { _ = stack.receive(ignored, at: start) }
        }
        let deadlineTime = clock.measure {
            for _ in 0..<iterations { deadline = stack.nextDeadline }
        }
        let advanceTime = clock.measure {
            for _ in 0..<iterations { _ = stack.advance(to: start) }
        }
        #expect(deadline == start + .seconds(1))
        print(
            "스택 비용(연결 256, 기록 1,024, 평균): receive \(receiveTime / iterations), "
                + "nextDeadline \(deadlineTime / iterations), advance(기한 없음) \(advanceTime / iterations)")
        // 디버그 빌드에서도 패킷마다 1ms를 넘지 않는다(병적인 경우만 잡는 느슨한 한계).
        #expect(receiveTime / iterations < .milliseconds(1))
        #expect(deadlineTime / iterations < .milliseconds(1))
        #expect(advanceTime / iterations < .milliseconds(1))
    }
}
