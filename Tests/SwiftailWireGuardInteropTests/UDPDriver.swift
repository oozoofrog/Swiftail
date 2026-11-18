import CryptoKit
import Foundation
import SwiftailBase
@testable import SwiftailWireGuard

/// Handles only real time and UDP I/O. The actor serializes access to WireGuard state and hooks.
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

    /// The Go peer's loopback source, `127.0.0.1:remotePort`. Checks on receipt that the source port is always remotePort.
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
            guard let prefix = IPPrefix($0) else { throw InteropFailure("Could not parse test AllowedIPs") }
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

    /// Polls for UDP input without blocking and never sleeps past nextDeadline for timers.
    private func step() -> Duration {
        guard !stopped else { return .milliseconds(5) }
        do {
            for _ in 0..<64 {
                guard let datagram = try socket.receive() else { break }
                guard datagram.port == remotePort else { throw InteropFailure("Unexpected UDP port") }
                let drop = inboundDrops > 0
                history.append(Datagram(bytes: datagram.bytes, time: .now, incoming: true, dropped: drop))
                if drop { inboundDrops -= 1; continue }
                do { try deliver(device.receive(datagram.bytes, from: source, at: .now)) }
                catch let error as WireGuardError { errors.append(error) }
            }
            if let deadline = device.nextDeadline, deadline <= .now {
                try deliver(device.advance(to: .now))
            }
        } catch { failure = InteropFailure("UDP driver failed: \(error)") }
        if let deadline = device.nextDeadline {
            return max(.zero, min(.milliseconds(5), ContinuousClock.now.duration(to: deadline)))
        }
        return .milliseconds(5)
    }

    private func deliver(_ outputs: [WireGuardDevice.Output]) throws {
        for output in outputs {
            switch output {
            case let .ipPacket(bytes, from: source):
                guard source == peer else { throw InteropFailure("IP output from another peer") }
                packets.append(bytes)
            case let .rejectedIPPacket(reason, from: _):
                throw InteropFailure("Rejected an IP packet sent by Go: \(reason)")
            case let .cookieReply(bytes):
                // Send back to the received datagram's source (the Go peer's loopback port).
                guard let remotePort else { throw InteropFailure("No UDP destination") }
                history.append(Datagram(bytes: bytes, time: .now, incoming: false, dropped: false))
                try socket.send(bytes, to: remotePort)
            case let .datagram(bytes, to: destination):
                guard destination == peer, let remotePort else { throw InteropFailure("No UDP destination") }
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
    /// Keeps the driver under load during the test by setting the decision result instead of actually crossing the threshold.
    func holdUnderLoad() { device.handshakeLoad.underLoadUntil = .now + .seconds(600) }
    func interceptNextTransport(_ rule: OutboundRule) { outboundRule = rule }
    func datagrams() -> [Datagram] { history }
    func receivedErrors() -> [WireGuardError] { errors }

    /// Reinjects a captured Go datagram through the same public API as the network receive path.
    func reinject(_ datagram: [UInt8]) throws {
        try deliver(device.receive(datagram, from: source, at: .now))
    }

    /// Resends a captured Swift datagram unchanged or sends bytes changed by the test.
    func transmit(_ datagram: [UInt8]) throws {
        guard let remotePort else { throw InteropFailure("No UDP destination") }
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
        throw InteropFailure("Timed out waiting for Swift IP input (\(timeout))")
    }

    func diagnostics() -> String {
        let origin = history.first?.time ?? .now
        return history.map {
            "\(origin.duration(to: $0.time)) \($0.incoming ? "Go→Swift" : "Swift→Go") type=\($0.bytes.first ?? 0) length=\($0.bytes.count)\($0.dropped ? " dropped" : "")"
        }.joined(separator: "\n") + "\nSwift receive errors: \(errors)\nDriver error: \(failure?.description ?? "none")"
    }

    func stop() {
        stopped = true
        worker?.cancel()
        worker = nil
        socket.close()
    }
}
