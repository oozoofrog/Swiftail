import SwiftailBase
import SwiftailWireGuard

/// Sends down-stack IP packets to peers and delivers incoming WireGuard datagrams up the stack through the filter.
///
/// The receive layers follow Go's order. WireGuard authentication and replay protection → source validation against the authenticated peer's AllowedIPs →
/// TSMP consumption (reports disco key advertisements up the stack) → inbound filtering. The WireGuard session identifies the sending peer. The datagram source (address or DERP sender)
/// is not used to identify that peer. Its only use is WireGuard's load defense (cookies and per-source rate limiting).
///
/// `docs/protocol-notes/netmap-engine.md` 4.2, 4.6, and 6.1, `docs/contracts/SwiftailEngine.md` behaviors 4 and 5 and M-E1 and M-E2,
/// and `docs/contracts/SwiftailTunnel.md` behavior L.
extension TailnetEngine {

    /// Sends an IP packet received from the upper layer.
    ///
    /// The engine handles packets destined for the service IP or a local address, and TSMP from the device, without sending them through WireGuard
    /// (`TailnetEngine+LocalDelivery.swift`). Sends all other packets to the peer whose AllowedIPs contain the destination.
    /// Outgoing packets bypass the ACL (as in Go). Only flow state is recorded for UDP replies.
    ///
    /// Local responses come out as `.ipPacket`. Write these packets back to the device.
    public mutating func send(_ ipPacket: [UInt8], at now: ContinuousClock.Instant) -> [Output] {
        let packet: IPPacket
        do {
            packet = try IPPacket(parsing: ipPacket)
        } catch {
            return [.dropped(Drop(error))]
        }
        if let local = deliverLocally(packet, at: now) {
            return [local]
        }
        guard let key = addressOwners[packet.destination]?.key else {
            return [.dropped(.noPeerForDestination)]
        }
        filter.recordOutbound(packet)
        do {
            return route(try device.send(packet.bytes, to: PublicKey(key), at: now))
        } catch {
            return [.dropped(.wireGuard(error))]
        }
    }

    /// Processes a datagram classified as WireGuard by `Magicsock` (its `.wireGuard` output).
    ///
    /// Disco and STUN do not reach this entry point. The WireGuard session authenticates the sending peer, and the peer's AllowedIPs
    /// validate the source address. `source` is used only when WireGuard is under load. Return any resulting `.cookieReply` to `source`.
    public mutating func receive(_ datagram: [UInt8], from source: Source, at now: ContinuousClock.Instant) -> [Output] {
        do {
            return route(try device.receive(datagram, from: source, at: now))
        } catch {
            return [.dropped(.wireGuard(error))]
        }
    }

    /// Converts device outputs to engine outputs. Emits datagrams as is (`Magicsock` chooses the path) and filters incoming IP
    /// packets. Handshake responses, retries, and keepalives follow the same path.
    mutating func route(_ outputs: [WireGuardDevice.Output]) -> [Output] {
        outputs.map { output in
            switch output {
            case let .datagram(bytes, to: wireGuardKey):
                return .datagram(bytes, to: NodePublicKey(wireGuardKey))
            case let .ipPacket(bytes, from: wireGuardKey):
                return deliverInbound(bytes, from: NodePublicKey(wireGuardKey))
            case let .rejectedIPPacket(error, from: _):
                return .dropped(.wireGuard(error))
            case let .cookieReply(bytes):
                return .cookieReply(bytes)
            }
        }
    }

    /// Parses and filters a packet that passed decryption and the AllowedIPs source check. `peer` is the WireGuard peer that sent it.
    ///
    /// TSMP is withheld from the upper layer. Emits a disco key advertisement with a key other than 0 as `.discoKeyAdvertised` along with the sending peer (like Go
    /// `net/tstun/wrap.go`, which reports the advertisement as it discards it). Go looks up the peer by source address. Here the source check has already
    /// passed, so use the WireGuard peer that owns the address directly.
    private mutating func deliverInbound(_ bytes: [UInt8], from peer: NodePublicKey) -> Output {
        let packet: IPPacket
        do {
            packet = try IPPacket(parsing: bytes)
        } catch {
            return .dropped(Drop(error))
        }
        // shortcut: Does not send a pong or rejection for a TSMP ping. TSMP other than disco advertisements is consumed without further action.
        if packet.transportProtocol == .tsmp {
            if let advertisement = TSMPDiscoKeyAdvertisement(parsing: packet), !advertisement.key.isZero {
                return .discoKeyAdvertised(advertisement.key, from: peer)
            }
            return .dropped(.consumedControlPacket)
        }
        switch filter.checkInbound(packet) {
        case .accept:
            return .ipPacket(packet.bytes)
        case let .drop(reason):
            return .dropped(.inbound(reason))
        }
    }
}

private extension TailnetEngine.Drop {
    init(_ error: IPPacket.ParseError) {
        switch error {
        case .malformed: self = .malformedPacket
        case .fragment, .extensionHeader: self = .unsupportedPacket
        }
    }
}
