import SwiftailIO

/// Connects the tunnel device and engine (`docs/contracts/SwiftailTunnel.md` behavior U).
///
/// ```
/// utun read / send(_:) ─► deliverFromDevice ─► engine.send ─┬ .ipPacket(local reply, looped-back packet) ─► deliverToDevice
///                                                           └ .datagram ─► Magicsock …
/// engine.receive ─ .ipPacket(from peer) ─► deliverToDevice ─┬ utun write
///                                                           └ inboundPackets(in-memory device)
/// ```
///
/// For the in-memory device, `send` takes the place of utun reads and `inboundPackets` takes the place of utun writes.
/// Processing in between is the same. With an `.inProcess` device, the TCP stack is the device. Stack output takes the
/// place of utun reads and stack input takes the place of utun writes
/// (`TailnetNode+Netstack.swift`).
extension TailnetNode {
    /// Passes one IP packet read from the device to the engine. Drops it before registration.
    func deliverFromDevice(_ ipPacket: [UInt8]) {
        let now = ContinuousClock.now
        process(engine?.send(ipPacket, at: now) ?? [], at: now)
    }

    /// Writes one IP packet emitted by the engine for the device. There is no waiting or queue. If a utun write fails
    /// (`EAGAIN`, `ENOBUFS`, `EMSGSIZE`, and so on), drops the packet and continues (behavior U5, as IP allows).
    func deliverToDevice(_ ipPacket: [UInt8]) {
        switch device {
        case .memory:
            inboundContinuation.yield(ipPacket)
        case .inProcess:
            deliverToNetstack(ipPacket)
        case .utun:
            do {
                try tunnel?.write(ipPacket)
            } catch {
                return
            }
        }
    }

    /// Passes packets read from utun to the engine. Returns `tunnelDeviceClosed` if the device closes (read error or
    /// end of file), or nil on cancellation.
    func readTunnel(_ tunnel: UTUNDevice) async -> NodeError? {
        for await packet in tunnel.packets {
            deliverFromDevice(packet)
        }
        guard let failure = tunnel.readFailure else { return nil }
        Self.log.error("utun read ended: \(failure.message, privacy: .public)")
        return .tunnelDeviceClosed(failure.message)
    }

    /// For tests only (outside the public API). Puts the in-memory device in the same state as a utun read error.
    /// `run()` ends with `tunnelDeviceClosed("test")`. If called before `run()`, `run()` ends as soon as it starts. Has no
    /// effect with a utun device (behavior U7).
    package func failMemoryDevice() {
        guard case .memory = device else { return }
        failureContinuation.yield(.tunnelDeviceClosed("test"))
    }
}
