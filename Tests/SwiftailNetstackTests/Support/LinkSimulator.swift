import SwiftailBase
import SwiftailNetstack
import Testing

/// 소켓·실제 대기 없이 연결 둘을 움직인다. 다음 단위도 `open`, `write`, `read`, `run`을 쓸 수 있다.
/// ACK는 같은 시각에 도착한 묶음을 모두 넣은 뒤 `advance`로 꺼낸다(계약 T·F5·N4).
struct LinkSimulator {
    enum Side: Int, CaseIterable, Sendable {
        case client, server
        var peer: Side { self == .client ? .server : .client }
    }

    /// 방향별 송신 순번은 SYN부터 1이다. `rules`의 순번은 조건에 맞은 세그먼트만 센다.
    struct Policy: Sendable {
        var delay: Duration = .milliseconds(1)
        var lossPercent = 0
        var reorder = false
        var duplicate = false
        var droppedOrdinals: Set<Int> = []
        var rules: [DropRule] = []
    }

    struct DropRule: Sendable {
        var occurrences: Set<Int> = [1]
        var matches: @Sendable (TCPSegment) -> Bool
        fileprivate var count = 0

        // Swift 6.3 이하의 멤버별 초기화는 fileprivate 속성 때문에 fileprivate이 되므로 직접 쓴다.
        init(occurrences: Set<Int> = [1], matches: @escaping @Sendable (TCPSegment) -> Bool) {
            self.occurrences = occurrences
            self.matches = matches
        }
    }

    struct Transmission: Sendable, Equatable {
        var side: Side
        var time: Duration
        var ordinal: Int
        var segment: TCPSegment
        var dropped: Bool
    }

    enum Failure: Error, CustomStringConvertible {
        case stalled(seed: UInt64, elapsed: Duration)
        case busyLoop(seed: UInt64)
        case timeLimit(seed: UInt64, elapsed: Duration)
        case noDeadline(seed: UInt64)
        case invariant(seed: UInt64, detail: String)

        var description: String {
            switch self {
            case let .stalled(seed, elapsed): "진행 없음: seed=\(seed), elapsed=\(elapsed)"
            case let .busyLoop(seed): "같은 시각의 바쁜 고리: seed=\(seed)"
            case let .timeLimit(seed, elapsed): "가상 시간 상한: seed=\(seed), elapsed=\(elapsed)"
            case let .noDeadline(seed): "기한도 도착할 세그먼트도 없음: seed=\(seed)"
            case let .invariant(seed, detail): "속성 위반: seed=\(seed), \(detail)"
            }
        }
    }

    private struct Arrival {
        var at: ContinuousClock.Instant
        var order: Int
        var side: Side
        var segment: TCPSegment
    }

    /// RFC 9293의 WL1·WL2를 독립적으로 적용한, 송신자가 실제로 전달받은 광고 창이다.
    private struct Window {
        var sequence: SequenceNumber
        var acknowledgment: SequenceNumber
        var end: SequenceNumber
        var shift: Int
    }

    let seed: UInt64
    let origin: ContinuousClock.Instant
    private(set) var now: ContinuousClock.Instant
    private(set) var connections: [TCPConnection?]
    var policies: [Policy]
    var recordsTransmissions = true
    private(set) var transmissions: [Transmission] = []
    private(set) var events: [[TCPConnection.Event]] = [[], []]
    private(set) var sentCounts = [0, 0]
    private(set) var droppedCounts = [0, 0]
    private(set) var fingerprint: UInt64 = 0
    private var randomState: UInt64
    private var arrivals: [Arrival] = []
    private var arrivalOrder = 0
    private let serverISS: SequenceNumber
    private var windows: [Window?] = [nil, nil]
    private var highestDataEnd: [SequenceNumber]
    private var progress = 0

    var elapsed: Duration { origin.duration(to: now) }

    var diagnostic: String {
        connections.enumerated().map { index, connection in
            guard let connection else { return "side=\(index): 없음" }
            return "side=\(index): state=\(connection.state), UNA=\(connection.sendUnacknowledged.rawValue), NXT=\(connection.sendNext.rawValue), window=\(connection.sendWindow), buffered=\(connection.unacknowledgedSendByteCount), readable=\(connection.readableByteCount), RTO=\(connection.retransmissionTimeout)"
        }.joined(separator: "; ") + "; arrivals=\(arrivals.count), elapsed=\(elapsed)"
    }

    init(seed: UInt64 = 1, clientISS: UInt32 = 10_000, serverISS: UInt32 = 90_000,
         clientPolicy: Policy = Policy(), serverPolicy: Policy = Policy()) throws {
        self.seed = seed
        randomState = seed
        origin = ContinuousClock.now
        now = origin
        self.serverISS = SequenceNumber(serverISS)
        policies = [clientPolicy, serverPolicy]
        highestDataEnd = [SequenceNumber(clientISS).advanced(by: 1), SequenceNumber(serverISS).advanced(by: 1)]
        let local = try #require(IPEndpoint("100.64.0.1:49152"))
        let remote = try #require(IPEndpoint("100.64.0.2:443"))
        let opening = TCPConnection.connect(from: local, to: remote,
                                            initialSequenceNumber: SequenceNumber(clientISS), at: now)
        connections = [opening.connection, nil]
        try emit(opening.outputs, from: .client)
    }

    func connection(_ side: Side) throws -> TCPConnection {
        try #require(connections[side.rawValue])
    }

    mutating func open() throws {
        try run(for: .seconds(248), until: { link in
            link.connections.allSatisfy { $0?.state == .established }
        })
    }

    @discardableResult
    mutating func write(_ bytes: ArraySlice<UInt8>, from side: Side) throws -> Int {
        let result = connections[side.rawValue]?.write(bytes, at: now)
        try emit(result?.outputs ?? [], from: side)
        progress += result?.accepted ?? 0
        return result?.accepted ?? 0
    }

    mutating func read(from side: Side, upTo count: Int = 65_536) throws -> [UInt8] {
        let result = connections[side.rawValue]?.read(upTo: count, at: now)
        try emit(result?.outputs ?? [], from: side)
        progress += result?.bytes.count ?? 0
        return result?.bytes ?? []
    }

    mutating func finish(_ side: Side) throws {
        try emit(connections[side.rawValue]?.finishWriting(at: now) ?? [], from: side)
    }

    mutating func close(_ side: Side) throws {
        try emit(connections[side.rawValue]?.close(at: now) ?? [], from: side)
    }

    mutating func abort(_ side: Side) throws {
        try emit(connections[side.rawValue]?.abort() ?? [], from: side)
    }

    /// 시험이 임의 세그먼트를 링크에 직접 넣을 때도 같은 도착·ACK 묶음 규칙을 쓴다.
    mutating func inject(_ segment: TCPSegment, from side: Side) {
        schedule(segment, from: side, delay: .zero)
    }

    /// 매 단계 응용 호출을 실행한다. 완료 조건은 ACK까지 확인해야 유휴 타이머로 건너뛰지 않는다.
    mutating func run(for limit: Duration, stallLimit: Duration = .seconds(480),
                      application: (inout LinkSimulator) throws -> Void = { _ in },
                      until done: (LinkSimulator) -> Bool) throws {
        let end = now.advanced(by: limit)
        var lastProgressAt = now
        var lastProgress = progress
        var sameTimeSteps = 0
        while true {
            try application(&self)
            try checkInvariants()
            if done(self) { return }
            let deadlines = connections.compactMap { $0?.nextDeadline } + arrivals.map(\.at)
            guard let next = deadlines.min() else { throw Failure.noDeadline(seed: seed) }
            guard next >= now else { throw Failure.invariant(seed: seed, detail: "nextDeadline이 과거") }
            guard next <= end else { throw Failure.timeLimit(seed: seed, elapsed: elapsed) }
            sameTimeSteps = next == now ? sameTimeSteps + 1 : 0
            guard sameTimeSteps < 10_000 else { throw Failure.busyLoop(seed: seed) }
            now = next
            try settle()
            if progress != lastProgress {
                lastProgress = progress
                lastProgressAt = now
            } else if lastProgressAt.duration(to: now) > stallLimit {
                throw Failure.stalled(seed: seed, elapsed: elapsed)
            }
        }
    }

    /// 특정 시각까지 타이머를 빠짐없이 돌린다. 응용의 가상 대기에 쓴다.
    mutating func advance(by duration: Duration) throws {
        let end = now.advanced(by: duration)
        var steps = 0
        while let next = (connections.compactMap { $0?.nextDeadline } + arrivals.map(\.at)).min(), next <= end {
            guard next >= now else { throw Failure.invariant(seed: seed, detail: "nextDeadline이 과거") }
            guard steps < 100_000 else { throw Failure.busyLoop(seed: seed) }
            now = next
            try settle()
            try checkInvariants()
            steps += 1
        }
        now = end
    }

    private mutating func settle() throws {
        let due = arrivals.filter { $0.at <= now }.sorted {
            $0.at == $1.at ? $0.order < $1.order : $0.at < $1.at
        }
        arrivals.removeAll { $0.at <= now }
        for arrival in due {
            let target = arrival.side.peer
            let index = target.rawValue
            if connections[index] == nil {
                guard target == .server, arrival.segment.flags == .syn else { continue }
                let opening = try TCPConnection.accept(arrival.segment, initialSequenceNumber: serverISS, at: now)
                connections[index] = opening.connection
                observeWindow(arrival.segment, for: target)
                try emit(opening.outputs, from: target)
                progress += 1
            } else {
                observeWindow(arrival.segment, for: target)
                let before = connections[index]?.sendUnacknowledged
                let outputs = connections[index]?.receive(arrival.segment, at: now) ?? []
                if before != connections[index]?.sendUnacknowledged { progress += 1 }
                try emit(outputs, from: target)
            }
        }
        for side in Side.allCases {
            try emit(connections[side.rawValue]?.advance(to: now) ?? [], from: side)
        }
    }

    private mutating func observeWindow(_ segment: TCPSegment, for side: Side) {
        let index = side.rawValue
        if segment.flags.contains(.syn) {
            guard let connection = connections[index],
                  (connection.state == .synReceived && segment.flags == .syn)
                    || (connection.state == .synSent && segment.flags.contains(.ack)
                        && segment.acknowledgmentNumber == connection.sendNext) else { return }
            windows[index] = Window(sequence: segment.sequenceNumber, acknowledgment: segment.acknowledgmentNumber,
                                    end: highestDataEnd[index].advanced(by: UInt32(segment.window)),
                                    shift: Int(segment.windowScale ?? 0))
        } else if segment.flags.contains(.ack), let connection = connections[index],
                  connection.sendUnacknowledged.precedesOrEquals(segment.acknowledgmentNumber),
                  segment.acknowledgmentNumber.precedesOrEquals(connection.sendNext),
                  let old = windows[index],
                  old.sequence.precedes(segment.sequenceNumber)
                    || (old.sequence == segment.sequenceNumber
                        && old.acknowledgment.precedesOrEquals(segment.acknowledgmentNumber)) {
            windows[index] = Window(sequence: segment.sequenceNumber, acknowledgment: segment.acknowledgmentNumber,
                                    end: segment.acknowledgmentNumber.advanced(by: UInt32(segment.window) << old.shift),
                                    shift: old.shift)
        }
    }

    private mutating func emit(_ outputs: [TCPConnection.Output], from side: Side) throws {
        let index = side.rawValue
        for output in outputs {
            switch output {
            case let .event(event):
                events[index].append(event)
                progress += 1
            case let .segment(segment):
                let dataEnd = segment.sequenceNumber.advanced(by: UInt32(segment.payload.count))
                if !segment.payload.isEmpty, highestDataEnd[index].precedes(dataEnd) {
                    if let window = windows[index], window.end.precedes(dataEnd) {
                        throw Failure.invariant(seed: seed, detail: "광고 창 초과: side=\(side), seq=\(segment.sequenceNumber.rawValue)")
                    }
                    highestDataEnd[index] = dataEnd
                }
                sentCounts[index] += 1
                let ordinal = sentCounts[index]
                var dropped = policies[index].droppedOrdinals.contains(ordinal)
                for ruleIndex in policies[index].rules.indices {
                    if policies[index].rules[ruleIndex].matches(segment) {
                        policies[index].rules[ruleIndex].count += 1
                        if policies[index].rules[ruleIndex].occurrences.contains(policies[index].rules[ruleIndex].count) {
                            dropped = true
                        }
                    }
                }
                if Int(random() % 100) < policies[index].lossPercent { dropped = true }
                fingerprint = (fingerprint &* 1_099_511_628_211) ^ UInt64(segment.sequenceNumber.rawValue)
                    ^ UInt64(segment.acknowledgmentNumber.rawValue) ^ UInt64(dropped ? 1 : 0)
                if recordsTransmissions {
                    transmissions.append(Transmission(side: side, time: elapsed, ordinal: ordinal,
                                                      segment: segment, dropped: dropped))
                }
                if dropped { droppedCounts[index] += 1; continue }
                let extra = policies[index].reorder ? policies[index].delay * Int(random() % 4) : .zero
                schedule(segment, from: side, delay: policies[index].delay + extra)
                if policies[index].duplicate, random() % 4 == 0 {
                    schedule(segment, from: side, delay: policies[index].delay + extra + .microseconds(1))
                }
            }
        }
    }

    private mutating func schedule(_ segment: TCPSegment, from side: Side, delay: Duration) {
        arrivalOrder += 1
        arrivals.append(Arrival(at: now.advanced(by: delay), order: arrivalOrder, side: side, segment: segment))
    }

    private mutating func random() -> UInt64 {
        // SplitMix64: 씨앗 0도 유효하며 플랫폼에 관계없이 같은 정수열을 낸다.
        randomState &+= 0x9E37_79B9_7F4A_7C15
        var value = randomState
        value = (value ^ (value >> 30)) &* 0xBF58_476D_1CE4_E5B9
        value = (value ^ (value >> 27)) &* 0x94D0_49BB_1331_11EB
        return value ^ (value >> 31)
    }

    private func checkInvariants() throws {
        for connection in connections.compactMap({ $0 }) {
            guard (0...262_144).contains(connection.readableByteCount),
                  (0...262_144).contains(connection.unacknowledgedSendByteCount),
                  connection.writableByteCount + connection.unacknowledgedSendByteCount == 262_144 else {
                throw Failure.invariant(seed: seed, detail: "256KiB 버퍼 상한")
            }
            if connection.state == .closed, connection.nextDeadline != nil {
                throw Failure.invariant(seed: seed, detail: "CLOSED에 남은 타이머")
            }
            if let deadline = connection.nextDeadline, deadline < now {
                throw Failure.invariant(seed: seed, detail: "nextDeadline이 과거")
            }
        }
    }
}
