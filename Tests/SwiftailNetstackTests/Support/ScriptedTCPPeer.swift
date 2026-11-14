import SwiftailBase
import SwiftailNetstack
import Testing

/// 상대 구현을 쓰지 않고 RFC 머리를 직접 만드는 시험용 피어다. 기대 번호는 ISS에서 계산한다.
struct ScriptedTCPPeer {
    var connection: TCPConnection
    let origin: ContinuousClock.Instant
    var now: ContinuousClock.Instant
    let local: IPEndpoint
    let remote: IPEndpoint
    let localStart = SequenceNumber(10_001)
    let peerStart = SequenceNumber(90_001)
    var window: UInt16

    init(window: UInt16 = 32_768, scale: UInt8? = 3, mss: UInt16 = 1240) throws {
        origin = ContinuousClock.now
        now = origin.advanced(by: .milliseconds(1))
        local = try #require(IPEndpoint("100.64.0.1:49152"))
        remote = try #require(IPEndpoint("100.64.0.2:443"))
        self.window = window
        connection = TCPConnection.connect(from: local, to: remote,
                                           initialSequenceNumber: SequenceNumber(10_000), at: origin).connection
        let synAck = TCPSegment(source: remote, destination: local, sequenceNumber: SequenceNumber(90_000),
                                acknowledgmentNumber: localStart, flags: [.syn, .ack], window: window,
                                maximumSegmentSize: mss, windowScale: scale)
        _ = connection.receive(synAck, at: now)
        _ = connection.advance(to: now)
        #expect(connection.state == .established)
    }

    func segment(sequence: SequenceNumber? = nil, acknowledgment: SequenceNumber? = nil,
                 flags: TCPSegment.Flags = .ack, window: UInt16? = nil, payload: [UInt8] = []) -> TCPSegment {
        TCPSegment(source: remote, destination: local, sequenceNumber: sequence ?? peerStart,
                   acknowledgmentNumber: acknowledgment ?? localStart, flags: flags,
                   window: window ?? self.window, payload: payload)
    }

    mutating func receive(_ segment: TCPSegment) -> [TCPConnection.Output] {
        connection.receive(segment, at: now) + connection.advance(to: now)
    }
}

extension Array where Element == TCPConnection.Output {
    var scenarioSegments: [TCPSegment] {
        compactMap { if case let .segment(segment) = $0 { segment } else { nil } }
    }
}

func scenarioBytes(_ count: Int, salt: Int = 0) -> [UInt8] {
    (0..<count).map { UInt8(truncatingIfNeeded: ($0 &* 31) ^ ($0 >> 8) ^ salt) }
}
