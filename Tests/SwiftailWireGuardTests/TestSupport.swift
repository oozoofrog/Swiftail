// 시험 공용 도우미: 메모리에서 이어진 장치 둘, IP 패킷 만들기, 출력 분류.

import CryptoKit
import Foundation
import Testing

import SwiftailBase
@testable import SwiftailWireGuard

/// 시험의 기준 시각. 실제 시간은 기다리지 않고 이 값에 Duration을 더해 넘긴다.
let t0 = ContinuousClock.now

/// 메모리에서 이어진 장치 둘. alice는 100.64.0.1, bob은 100.64.0.2를 쓴다.
struct Pair {
    enum Side {
        case alice, bob

        var other: Side { self == .alice ? .bob : .alice }
    }

    static let aliceAddress = "100.64.0.1"
    static let bobAddress = "100.64.0.2"

    var alice: WireGuardDevice
    var bob: WireGuardDevice

    init(at now: ContinuousClock.Instant = t0) {
        alice = WireGuardDevice(privateKey: .init(), now: now, wallClock: Date(timeIntervalSince1970: 1_800_000_000))
        // 두 노드의 벽시계가 서로 달라도 된다.
        bob = WireGuardDevice(privateKey: .init(), now: now, wallClock: Date(timeIntervalSince1970: 1_700_000_000.5))
        alice.addPeer(bob.publicKey, allowedIPs: [IPPrefix("\(Self.bobAddress)/32")].compactMap { $0 })
        bob.addPeer(alice.publicKey, allowedIPs: [IPPrefix("\(Self.aliceAddress)/32")].compactMap { $0 })
    }

    subscript(side: Side) -> WireGuardDevice {
        get { side == .alice ? alice : bob }
        set {
            if side == .alice { alice = newValue } else { bob = newValue }
        }
    }

    func key(_ side: Side) -> PublicKey { self[side].publicKey }

    /// side가 보내는 IP 패킷(출발 주소는 side의 주소).
    func packet(from side: Side, payload: [UInt8] = [0xAB, 0xCD]) -> [UInt8] {
        ipv4Packet(
            source: side == .alice ? Self.aliceAddress : Self.bobAddress,
            destination: side == .alice ? Self.bobAddress : Self.aliceAddress,
            payload: payload
        )
    }

    /// side의 출력을 상대에게 넘기고, 그 응답을 다시 넘기기를 조용해질 때까지 반복한다.
    /// 양쪽에서 위로 올라온 IP 패킷을 돌려준다. 모든 수신은 성공해야 한다.
    @discardableResult
    mutating func deliver(_ outputs: [WireGuardDevice.Output], from side: Side, at now: ContinuousClock.Instant) throws -> [Side: [[UInt8]]] {
        var delivered: [Side: [[UInt8]]] = [.alice: [], .bob: []]
        var queue = outputs.map { (from: side, output: $0) }
        while !queue.isEmpty {
            let (sender, output) = queue.removeFirst()
            switch output {
            case let .datagram(bytes, to: destination):
                #expect(destination == key(sender.other))
                let replies = try self[sender.other].receive(bytes, at: now)
                queue += replies.map { (from: sender.other, output: $0) }
            case let .ipPacket(bytes, from: source):
                #expect(source == key(sender.other))
                delivered[sender, default: []].append(bytes)
            case .rejectedIPPacket:
                break
            }
        }
        return delivered
    }

    /// alice → bob 핸드셰이크와 데이터 한 번으로 세션을 연다. alice가 초기자다.
    mutating func establish(initiator: Side = .alice, at now: ContinuousClock.Instant = t0) throws {
        let packet = packet(from: initiator)
        let outputs = try self[initiator].send(packet, to: key(initiator.other), at: now)
        let delivered = try deliver(outputs, from: initiator, at: now)
        #expect(delivered[initiator.other] == [packet])
    }

    /// 이 장치가 피어에게 쓰는 keypair.
    func keypairs(of side: Side) -> Keypairs? {
        self[side].peers[key(side.other)]?.keypairs
    }
}

/// 최소 IPv4 패킷: 머리 20바이트(옵션 없음) + payload. 체크섬은 0이다(장치는 보지 않는다).
func ipv4Packet(source: String, destination: String, payload: [UInt8]) -> [UInt8] {
    let total = 20 + payload.count
    let src = IPAddress(source)?.bytes ?? []
    let dst = IPAddress(destination)?.bytes ?? []
    return [0x45, 0, UInt8(total >> 8), UInt8(total & 0xFF), 0, 0, 0, 0, 64, 17, 0, 0] + src + dst + payload
}

/// 최소 IPv6 패킷: 머리 40바이트 + payload.
func ipv6Packet(source: String, destination: String, payload: [UInt8]) -> [UInt8] {
    let src = IPAddress(source)?.bytes ?? []
    let dst = IPAddress(destination)?.bytes ?? []
    return [0x60, 0, 0, 0, UInt8(payload.count >> 8), UInt8(payload.count & 0xFF), 17, 64] + src + dst + payload
}

extension [WireGuardDevice.Output] {
    /// 데이터그램 출력만.
    var datagrams: [[UInt8]] {
        compactMap {
            if case let .datagram(bytes, to: _) = $0 { bytes } else { nil }
        }
    }

    /// 위로 올린 IP 패킷만.
    var ipPackets: [[UInt8]] {
        compactMap {
            if case let .ipPacket(bytes, from: _) = $0 { bytes } else { nil }
        }
    }

    /// 데이터그램들의 메시지 type.
    var messageTypes: [UInt8] {
        datagrams.map { $0.first ?? 0 }
    }
}

extension Array where Element == UInt8 {
    /// offset에서 시작하는 little-endian uint32.
    func uint32(at offset: Int) -> UInt32 {
        self[offset..<offset + 4].reversed().reduce(0) { $0 << 8 | UInt32($1) }
    }
}

/// 재현할 수 있는 의사 난수(SplitMix64). 퍼즈 입력용이다.
struct SplitMix64: RandomNumberGenerator {
    private var state: UInt64

    init(seed: UInt64) { state = seed }

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }

    mutating func bytes(_ count: Int) -> [UInt8] {
        (0..<count).map { _ in UInt8.random(in: .min ... .max, using: &self) }
    }
}
