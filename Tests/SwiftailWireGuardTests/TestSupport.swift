// Shared test helpers for two devices connected in memory, IP packet construction, and output classification.

import CryptoKit
import Foundation
import Testing

import SwiftailBase
@testable import SwiftailWireGuard

/// The reference time for tests. Pass this value plus a Duration to avoid waiting in real time.
let t0 = ContinuousClock.now

/// Two devices connected in memory. alice uses 100.64.0.1 and bob uses 100.64.0.2.
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
        // The two nodes may have different wall-clock times.
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

    /// An IP packet sent by side with side's address as the source.
    func packet(from side: Side, payload: [UInt8] = [0xAB, 0xCD]) -> [UInt8] {
        ipv4Packet(
            source: side == .alice ? Self.aliceAddress : Self.bobAddress,
            destination: side == .alice ? Self.bobAddress : Self.aliceAddress,
            payload: payload
        )
    }

    /// Delivers side's output to the other device and repeats with each reply until there is no more output.
    /// Returns the IP packets delivered upward on both sides. Every receive must succeed.
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
            case let .cookieReply(bytes):
                // Send the reply back to the source of the received datagram, which is the peer that just sent it.
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

    /// Opens a session with an alice → bob handshake and one data send. alice is the initiator.
    mutating func establish(initiator: Side = .alice, at now: ContinuousClock.Instant = t0) throws {
        let packet = packet(from: initiator)
        let outputs = try self[initiator].send(packet, to: key(initiator.other), at: now)
        let delivered = try deliver(outputs, from: initiator, at: now)
        #expect(delivered[initiator.other] == [packet])
    }

    /// Returns the keypair this device uses for the peer.
    func keypairs(of side: Side) -> Keypairs? {
        self[side].peers[key(side.other)]?.keypairs
    }
}

extension WireGuardDevice.Source {
    /// The UDP source `192.0.2.1:41553` for tests where the source does not matter.
    static let test = Self(address: [192, 0, 2, 1, 0x51, 0xA2], host: [192, 0, 2, 1])
}

extension WireGuardDevice {
    /// Receives input as if it always came from `Source.test`, for tests where the source does not matter.
    mutating func receive(_ datagram: [UInt8], at now: ContinuousClock.Instant) throws(WireGuardError) -> [Output] {
        try receive(datagram, from: .test, at: now)
    }
}

/// Builds a minimal IPv4 packet with a 20-byte header (no options) plus payload. The checksum is 0 because the device does not check it.
func ipv4Packet(source: String, destination: String, payload: [UInt8]) -> [UInt8] {
    let total = 20 + payload.count
    let src = IPAddress(source)?.bytes ?? []
    let dst = IPAddress(destination)?.bytes ?? []
    return [0x45, 0, UInt8(total >> 8), UInt8(total & 0xFF), 0, 0, 0, 0, 64, 17, 0, 0] + src + dst + payload
}

/// Builds a minimal IPv6 packet with a 40-byte header plus payload.
func ipv6Packet(source: String, destination: String, payload: [UInt8]) -> [UInt8] {
    let src = IPAddress(source)?.bytes ?? []
    let dst = IPAddress(destination)?.bytes ?? []
    return [0x60, 0, 0, 0, UInt8(payload.count >> 8), UInt8(payload.count & 0xFF), 17, 64] + src + dst + payload
}

extension [WireGuardDevice.Output] {
    /// Returns only the outgoing datagrams.
    var datagrams: [[UInt8]] {
        compactMap {
            if case let .datagram(bytes, to: _) = $0 { bytes } else { nil }
        }
    }

    /// Returns only the IP packets delivered upward.
    var ipPackets: [[UInt8]] {
        compactMap {
            if case let .ipPacket(bytes, from: _) = $0 { bytes } else { nil }
        }
    }

    /// Returns the message types of the datagrams.
    var messageTypes: [UInt8] {
        datagrams.map { $0.first ?? 0 }
    }
}

extension Array where Element == UInt8 {
    /// Reads a little-endian uint32 starting at offset.
    func uint32(at offset: Int) -> UInt32 {
        self[offset..<offset + 4].reversed().reduce(0) { $0 << 8 | UInt32($1) }
    }
}

/// Generates reproducible pseudorandom values (SplitMix64) for fuzz inputs.
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
