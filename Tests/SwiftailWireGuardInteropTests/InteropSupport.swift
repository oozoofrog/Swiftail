import CryptoKit
import Foundation
import Testing
import SwiftailBase
import SwiftailWireGuard

/// 길이 필드와 IPv4 체크섬이 맞는 IP 패킷. 짧은 크기는 IP 머리 뒤에 부분 payload를 둔다.
/// 완전한 UDP 머리가 들어가면 길이와 의사 머리 체크섬도 채워 IPv6에서도 유효하게 만든다.
func ipPacket(fromSwift: Bool, size: Int = 36, ipv6: Bool = false, marker: UInt8 = 1) throws -> [UInt8] {
    let header = ipv6 ? 40 : 20
    guard size >= header, size <= 65_535 else { throw InteropFailure("시험 IP 크기 오류") }
    let source = ipv6 ? (fromSwift ? "fd00:99::1" : "fd00:99::2") : (fromSwift ? "10.99.0.1" : "10.99.0.2")
    let destination = ipv6 ? (fromSwift ? "fd00:99::2" : "fd00:99::1") : (fromSwift ? "10.99.0.2" : "10.99.0.1")
    guard let src = IPAddress(source), let dst = IPAddress(destination) else {
        throw InteropFailure("시험 IP 주소 해석 실패")
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
            throw InteropFailure("Swift→Go 바이트 불일치: 송신 \(sent.count), 수신 \(received.count)")
        }
    }

    func goToSwift(size: Int = 36, ipv6: Bool = false, marker: UInt8 = 2) async throws {
        let sent = try ipPacket(fromSwift: false, size: size, ipv6: ipv6, marker: marker)
        try await go.send(sent)
        let received = try await swift.packet()
        guard received == sent else {
            throw InteropFailure("Go→Swift 바이트 불일치: 송신 \(sent.count), 수신 \(received.count)")
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

/// 설정·본문 어느 단계가 실패해도 두 입출력 자원을 닫은 뒤 진단을 함께 던진다.
func withInteropPair(_ body: @Sendable (InteropPair) async throws -> Void) async throws {
    let swiftKey = Curve25519.KeyAgreement.PrivateKey()
    let goKey = Curve25519.KeyAgreement.PrivateKey()
    guard let peer = PublicKey(rawValue: goKey.publicKey.rawRepresentation) else {
        throw InteropFailure("시험 공개 키 길이 오류")
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
            throw InteropFailure("wgpeer ready 값 오류")
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
        throw InteropFailure("\(error)\n\(trace)\nGo verbose 로그:\n\(log)")
    }
}
