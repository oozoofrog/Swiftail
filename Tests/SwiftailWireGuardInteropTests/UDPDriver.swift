import CryptoKit
import Foundation
import SwiftailBase
@testable import SwiftailWireGuard

/// 실제 시각과 UDP 입출력만 맡는다. WireGuard 상태와 훅은 이 actor에서 직렬 처리한다.
actor UDPDriver {
    enum OutboundRule: Sendable { case pass, drop, flipBit, duplicate }
    struct Datagram: Sendable {
        let bytes: [UInt8]
        let time: ContinuousClock.Instant
        let incoming: Bool
        let dropped: Bool
    }

    let port: UInt16
    let publicKey: PublicKey
    private let socket: LoopbackSocket
    private var device: WireGuardDevice
    private let peer: PublicKey
    private var remotePort: UInt16?
    private var worker: Task<Void, Never>?
    private var packets: [[UInt8]] = []
    private var history: [Datagram] = []
    private var errors: [WireGuardError] = []
    private var failure: InteropFailure?
    private var inboundDrops = 0
    private var outboundRule = OutboundRule.pass
    private var stopped = false

    /// Go 피어의 루프백 출처 `127.0.0.1:remotePort`. 출처 포트는 늘 remotePort임을 받을 때 확인한다.
    private var source: WireGuardDevice.Source {
        let port = remotePort ?? 0
        return WireGuardDevice.Source(address: [127, 0, 0, 1, UInt8(port & 0xFF), UInt8(port >> 8)], host: [127, 0, 0, 1])
    }

    init(privateKey: Curve25519.KeyAgreement.PrivateKey, peer: PublicKey) throws {
        socket = try LoopbackSocket()
        port = socket.port
        device = WireGuardDevice(privateKey: privateKey, now: .now, wallClock: Date())
        publicKey = device.publicKey
        self.peer = peer
        device.addPeer(peer, allowedIPs: try ["10.99.0.2/32", "fd00:99::2/128"].map {
            guard let prefix = IPPrefix($0) else { throw InteropFailure("시험 AllowedIPs 해석 실패") }
            return prefix
        })
    }

    func start(remotePort: UInt16) {
        self.remotePort = remotePort
        worker = Task { [weak self] in
            while !Task.isCancelled {
                let delay = await self?.step() ?? .milliseconds(5)
                do { try await Task.sleep(for: delay) } catch { break }
            }
        }
    }

    /// UDP 수신은 비차단 polling하고 타이머는 nextDeadline보다 늦게 재우지 않는다.
    private func step() -> Duration {
        guard !stopped else { return .milliseconds(5) }
        do {
            for _ in 0..<64 {
                guard let datagram = try socket.receive() else { break }
                guard datagram.port == remotePort else { throw InteropFailure("예상하지 않은 UDP 포트") }
                let drop = inboundDrops > 0
                history.append(Datagram(bytes: datagram.bytes, time: .now, incoming: true, dropped: drop))
                if drop { inboundDrops -= 1; continue }
                do { try deliver(device.receive(datagram.bytes, from: source, at: .now)) }
                catch let error as WireGuardError { errors.append(error) }
            }
            if let deadline = device.nextDeadline, deadline <= .now {
                try deliver(device.advance(to: .now))
            }
        } catch { failure = InteropFailure("UDP 구동 실패: \(error)") }
        if let deadline = device.nextDeadline {
            return max(.zero, min(.milliseconds(5), ContinuousClock.now.duration(to: deadline)))
        }
        return .milliseconds(5)
    }

    private func deliver(_ outputs: [WireGuardDevice.Output]) throws {
        for output in outputs {
            switch output {
            case let .ipPacket(bytes, from: source):
                guard source == peer else { throw InteropFailure("다른 피어의 IP 출력") }
                packets.append(bytes)
            case let .rejectedIPPacket(reason, from: _):
                throw InteropFailure("Go가 보낸 IP 패킷을 거절함: \(reason)")
            case let .cookieReply(bytes):
                // 받은 데이터그램의 출처(Go 피어의 루프백 포트)로 되돌린다.
                guard let remotePort else { throw InteropFailure("UDP 목적지 없음") }
                history.append(Datagram(bytes: bytes, time: .now, incoming: false, dropped: false))
                try socket.send(bytes, to: remotePort)
            case let .datagram(bytes, to: destination):
                guard destination == peer, let remotePort else { throw InteropFailure("UDP 목적지 없음") }
                let rule = bytes.first == 4 && bytes.count > 32 ? outboundRule : .pass
                if rule != .pass { outboundRule = .pass }
                history.append(Datagram(bytes: bytes, time: .now, incoming: false, dropped: rule == .drop))
                switch rule {
                case .pass: try socket.send(bytes, to: remotePort)
                case .drop: break
                case .flipBit:
                    var changed = bytes
                    changed[changed.count - 1] ^= 1
                    try socket.send(changed, to: remotePort)
                case .duplicate:
                    try socket.send(bytes, to: remotePort)
                    try socket.send(bytes, to: remotePort)
                }
            }
        }
    }

    func send(_ packet: [UInt8]) throws {
        if let failure { throw failure }
        try deliver(device.send(packet, to: peer, at: .now))
    }

    func dropIncoming(_ count: Int) { inboundDrops = count }
    /// 시험 동안 부하 상태로 둔다(실제로 문턱을 넘기는 대신 판정 결과를 정한다).
    func holdUnderLoad() { device.handshakeLoad.underLoadUntil = .now + .seconds(600) }
    func interceptNextTransport(_ rule: OutboundRule) { outboundRule = rule }
    func datagrams() -> [Datagram] { history }
    func receivedErrors() -> [WireGuardError] { errors }

    /// 캡처한 Go 데이터그램을 네트워크 수신 경로와 같은 공개 API에 다시 넣는다.
    func reinject(_ datagram: [UInt8]) throws {
        try deliver(device.receive(datagram, from: source, at: .now))
    }

    /// 캡처한 Swift 데이터그램을 그대로 다시 보내거나 시험에서 바꾼 바이트를 보낸다.
    func transmit(_ datagram: [UInt8]) throws {
        guard let remotePort else { throw InteropFailure("UDP 목적지 없음") }
        try socket.send(datagram, to: remotePort)
    }

    func packet(timeout: Duration = .seconds(12)) async throws -> [UInt8] {
        let deadline = ContinuousClock.now + timeout
        while ContinuousClock.now < deadline {
            try Task.checkCancellation()
            if let failure { throw failure }
            if !packets.isEmpty { return packets.removeFirst() }
            try await Task.sleep(for: .milliseconds(10))
        }
        throw InteropFailure("Swift IP 수신 제한 시간 초과 (\(timeout))")
    }

    func diagnostics() -> String {
        let origin = history.first?.time ?? .now
        return history.map {
            "\(origin.duration(to: $0.time)) \($0.incoming ? "Go→Swift" : "Swift→Go") type=\($0.bytes.first ?? 0) 길이=\($0.bytes.count)\($0.dropped ? " 버림" : "")"
        }.joined(separator: "\n") + "\nSwift 수신 오류: \(errors)\n구동 오류: \(failure?.description ?? "없음")"
    }

    func stop() {
        stopped = true
        worker?.cancel()
        worker = nil
        socket.close()
    }
}
