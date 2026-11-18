import CryptoKit
import Foundation
import Testing
import SwiftailBase
import SwiftailWireGuard

/// An IP packet with correct length fields and IPv4 checksum. Short sizes put a partial payload after the IP header.
/// When a complete UDP header fits, also fills in its length and pseudo-header checksum to make it valid for IPv6.
func ipPacket(fromSwift: Bool, size: Int = 36, ipv6: Bool = false, marker: UInt8 = 1) throws -> [UInt8] {
    let header = ipv6 ? 40 : 20
    guard size >= header, size <= 65_535 else { throw InteropFailure("Invalid test IP size") }
    let source = ipv6 ? (fromSwift ? "fd00:99::1" : "fd00:99::2") : (fromSwift ? "10.99.0.1" : "10.99.0.2")
    let destination = ipv6 ? (fromSwift ? "fd00:99::2" : "fd00:99::1") : (fromSwift ? "10.99.0.2" : "10.99.0.1")
    guard let src = IPAddress(source), let dst = IPAddress(destination) else {
        throw InteropFailure("Could not parse test IP address")
    }
    let payloadSize = size - header
    var packet: [UInt8]
    if ipv6 {
        packet = [0x60, 0, 0, 0] + bigEndian16(payloadSize) + [17, 64] + src.bytes + dst.bytes
    } else {
        packet = [0x45, 0] + bigEndian16(size) + [0, marker, 0, 0, 64, 17, 0, 0] + src.bytes + dst.bytes
        let checksum = internetChecksum(packet)
        packet[10] = UInt8(checksum >> 8)
        packet[11] = UInt8(checksum & 255)
    }
    var payload = (0..<payloadSize).map { UInt8(truncatingIfNeeded: $0) &+ marker }
    if payloadSize >= 8 {
        payload.replaceSubrange(0..<8, with: [0x12, 0x34, 0x56, 0x78] + bigEndian16(payloadSize) + [0, 0])
        let pseudo = ipv6
            ? src.bytes + dst.bytes + [0, 0] + bigEndian16(payloadSize) + [0, 0, 0, 17]
            : src.bytes + dst.bytes + [0, 17] + bigEndian16(payloadSize)
        let computed = internetChecksum(pseudo + payload)
        let checksum = computed == 0 ? UInt16.max : computed
        payload[6] = UInt8(checksum >> 8)
        payload[7] = UInt8(checksum & 255)
    }
    return packet + payload
}

private func bigEndian16(_ value: Int) -> [UInt8] { [UInt8(value >> 8), UInt8(value & 255)] }

private func internetChecksum(_ bytes: [UInt8]) -> UInt16 {
    var sum: UInt32 = 0
    for offset in stride(from: 0, to: bytes.count, by: 2) {
        sum += UInt32(bytes[offset]) << 8
        if offset + 1 < bytes.count { sum += UInt32(bytes[offset + 1]) }
    }
    while sum >> 16 != 0 { sum = (sum & 65_535) + (sum >> 16) }
    return ~UInt16(sum)
}

struct InteropPair: Sendable {
    let swift: UDPDriver
    let go: GoPeer

    func swiftToGo(size: Int = 36, ipv6: Bool = false, marker: UInt8 = 1, timeout: Duration = .seconds(12)) async throws {
        let sent = try ipPacket(fromSwift: true, size: size, ipv6: ipv6, marker: marker)
        try await swift.send(sent)
        let received = try await go.packet(timeout: timeout)
        guard received == sent else {
            throw InteropFailure("Swift→Go byte mismatch: sent \(sent.count), received \(received.count)")
        }
    }

    func goToSwift(size: Int = 36, ipv6: Bool = false, marker: UInt8 = 2) async throws {
        let sent = try ipPacket(fromSwift: false, size: size, ipv6: ipv6, marker: marker)
        try await go.send(sent)
        let received = try await swift.packet()
        guard received == sent else {
            throw InteropFailure("Go→Swift byte mismatch: sent \(sent.count), received \(received.count)")
        }
    }

    func establish(swiftInitiates: Bool) async throws {
        if swiftInitiates {
            try await swiftToGo()
            try await goToSwift()
        } else {
            try await goToSwift()
            try await swiftToGo()
        }
    }
}

/// If setup or the body fails, closes both I/O resources before throwing with diagnostics.
func withInteropPair(_ body: @Sendable (InteropPair) async throws -> Void) async throws {
    let swiftKey = Curve25519.KeyAgreement.PrivateKey()
    let goKey = Curve25519.KeyAgreement.PrivateKey()
    guard let peer = PublicKey(rawValue: goKey.publicKey.rawRepresentation) else {
        throw InteropFailure("Invalid test public key length")
    }
    let swift = try UDPDriver(privateKey: swiftKey, peer: peer)
    let go = GoPeer()
    do {
        try await go.start(configuration: .init(
            privateKey: Array(goKey.rawRepresentation).hex,
            peerPublicKey: Array(swiftKey.publicKey.rawRepresentation).hex,
            peerEndpoint: "127.0.0.1:\(swift.port)",
            allowedIPs: ["10.99.0.1/32", "fd00:99::1/128"]
        ))
        let ready = try await go.event("ready")
        guard let port = ready.listenPort, port > 0,
              ready.publicKey == Array(goKey.publicKey.rawRepresentation).hex else {
            throw InteropFailure("Invalid wgpeer ready value")
        }
        await swift.start(remotePort: port)
        try await body(InteropPair(swift: swift, go: go))
        await swift.stop()
        await go.stop()
    } catch {
        await swift.stop()
        await go.stop()
        let trace = await swift.diagnostics()
        let log = await go.diagnostics()
        throw InteropFailure("\(error)\n\(trace)\nGo verbose log:\n\(log)")
    }
}
