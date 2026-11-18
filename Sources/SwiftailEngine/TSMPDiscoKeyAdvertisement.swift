// The TSMP disco key advertisement format is ported from the Go implementation.
// Origin: tailscale.com v1.104.7 `net/packet/tsmp.go` (`TSMPDiscoKeyAdvertisement`, `Marshal`,
// `AsTSMPDiscoAdvertisement`), `net/packet/ip4.go`·`ip6.go` (`Marshal`), `wgengine/magicsock/magicsock.go`
// (`selfIPMatchingFamily`).
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import SwiftailBase

/// An announcement of the node's own disco public key, sent to the peer through the tunnel whenever a WireGuard session is established (notes `disco-magicsock.md` 3.8).
///
/// The IP header (20 bytes for IPv4 or 40 bytes for IPv6, protocol 99 TSMP, TTL 64, ID 0) is followed by `'a'` and the 32-byte disco key.
/// The receiver opens disco messages with this key without waiting for the netmap ("TSMP disco key advertisement" in the `SwiftailMagicsock` contract).
struct TSMPDiscoKeyAdvertisement: Sendable, Equatable {
    /// IP protocol number 99 (Go `ipproto.TSMP`).
    static let protocolNumber: UInt8 = 99
    /// TSMP type byte `'a'` (Go `TSMPTypeDiscoAdvertisement`).
    static let type = UInt8(ascii: "a")
    /// Length after the IP header is 1 for the type + 32 for the key.
    static let payloadLength = 33

    /// The sending node's tailnet address.
    var source: IPAddress
    /// The receiving peer's tailnet address, in the same family as `source`.
    var destination: IPAddress
    /// The sending node's disco public key.
    var key: DiscoPublicKey

    /// An advertisement to send to peer `destination`. The source is the first local single-address entry in the same family (Go
    /// `selfIPMatchingFamily`). Returns nil if no such address exists or the key is 0 (Go sends nothing in that case).
    ///
    /// - Parameters:
    ///   - selfAddresses: The local `Addresses` in netmap order.
    ///   - destination: The peer's first `Addresses` address (Go `endpoint.nodeAddr`).
    init?(selfAddresses: [IPPrefix], destination: IPAddress, key: DiscoPublicKey) {
        guard !key.isZero,
              let source = selfAddresses.first(where: {
                  $0.length == $0.address.bytes.count * 8 && $0.address.isIPv4 == destination.isIPv4
              })?.address
        else { return nil }
        self.source = source
        self.destination = destination
        self.key = key
    }

    /// The contents of an advertisement in a received packet parsed by the engine. Returns nil if it is not TSMP, its type is not `'a'`, or it is shorter than 33 bytes.
    /// The key may be 0 (the receiver discards it).
    init?(parsing packet: IPPacket) {
        guard packet.transportProtocol == .tsmp else { return nil }
        let payload = packet.bytes[packet.transportOffset...]
        guard payload.count >= Self.payloadLength, payload.first == Self.type,
              let key = DiscoPublicKey(rawValue: payload.dropFirst().prefix(DiscoPublicKey.byteCount))
        else { return nil }
        source = packet.source
        destination = packet.destination
        self.key = key
    }

    /// The IP packet to send (same bytes as Go `TSMPDiscoKeyAdvertisement.Marshal`). 53 bytes for IPv4 and 73 bytes for IPv6.
    var bytes: [UInt8] {
        let payload = [Self.type] + key.rawValue
        if source.isIPv4 {
            let totalLength = 20 + payload.count
            var header: [UInt8] = [
                0x45, 0x00, UInt8(totalLength >> 8), UInt8(totalLength & 0xFF),
                0x00, 0x00, 0x00, 0x00,
                64, Self.protocolNumber, 0x00, 0x00,
            ]
            header += source.bytes + destination.bytes
            let checksum = InternetChecksum.checksum(of: header)
            header[10] = UInt8(checksum >> 8)
            header[11] = UInt8(checksum & 0xFF)
            return header + payload
        }
        let header: [UInt8] = [0x60, 0x00, 0x00, 0x00, UInt8(payload.count >> 8), UInt8(payload.count & 0xFF), Self.protocolNumber, 64]
        return header + source.bytes + destination.bytes + payload
    }
}
