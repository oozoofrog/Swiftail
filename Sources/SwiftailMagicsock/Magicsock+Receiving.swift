// Incoming UDP classification order and disco receive behavior follow the Go implementation.
// Origin: tailscale.com v1.104.6 `wgengine/magicsock/magicsock.go` (`packetLooksLike`, `handleDiscoMessage`,
// `handlePingLocked`, and `unambiguousNodeKeyOfPingLocked` from v1.104.7), `wgengine/magicsock/derp.go` (`processDERPReadResult`),
// v1.104.7 `wgengine/magicsock/peermap.go` (`forEachEndpointWithDiscoKey`), `endpoint.go` (`handlePongConnLocked`).
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import SwiftailBase

/// Classifying incoming data and receiving disco messages (contract behaviors A and C, notes 4.1~4.3).
///
/// Bytes received over UDP or DERP are untrusted input. Classify them once as a STUN response, disco message, or WireGuard
/// datagram. Emit `.dropped` if none matches or a rule is violated. Discarded inputs leave state unchanged apart from the DERP activity tracking described below.
/// Checks, in order of increasing cost, the source, packet signature, length, and sender disco key (table lookup only), then decrypts and applies path rules.
/// Disco messages with unknown keys are dropped without cryptographic operations. Packets that fail to open are never passed to WireGuard (notes 3.2 6).
///
/// WireGuard datagram contents are opaque. The WireGuard device identifies the peer by receiver index (behavior A3). Pass the incoming path
/// along with the datagram. Under load, WireGuard binds the cookie to that path and sends the cookie reply back on it.
extension Magicsock {
    /// The incoming path. Determines disco path rules and where a WireGuard datagram's cookie reply goes.
    public enum Source: Sendable, Hashable {
        /// UDP with a source address.
        case udp(IPEndpoint)
        /// DERP with the sender's node key and the region the packet arrived on.
        case derp(NodePublicKey, region: Int64)
    }

    /// The largest disco packet to try opening is the largest Go path MTU Ping (wire MTU 9000 minus the 28-byte IPv4 and UDP headers,
    /// notes 4.12 "peer MTU"). Normal messages are much smaller (Pong is 110 bytes). Drop longer messages before decryption.
    static let maxDiscoPacketLength = 9000 - 28

    /// The Geneve header length and protocol values used by Go (notes 3.6).
    private static let geneveHeaderLength = 8
    private static let geneveProtocolDisco: UInt16 = 0x7A11
    private static let geneveProtocolWireGuard: UInt16 = 0x7A12
    /// The source address `127.3.3.40` included in a Pong for a Ping received over DERP (Go `tailcfg.DerpMagicIPAddr`, notes 4.2 4.4).
    private static let derpMagicAddress: [UInt8] = [127, 3, 3, 40]

    // MARK: Entry points

    /// A datagram received from the UDP socket.
    public mutating func receiveUDP(_ datagram: [UInt8], from source: IPEndpoint, at now: ContinuousClock.Instant) -> [Output] {
        var random = SystemRandomNumberGenerator()
        return receiveUDP(datagram, from: source, at: now, using: &random)
    }

    /// A packet received on the connection for DERP region `region`. `peer` is the sender key in the DERP frame.
    public mutating func receiveDERP(
        _ packet: [UInt8],
        from peer: NodePublicKey,
        region: Int64,
        at now: ContinuousClock.Instant
    ) -> [Output] {
        var random = SystemRandomNumberGenerator()
        return receiveDERP(packet, from: peer, region: region, at: now, using: &random)
    }

    /// Equivalent to `receiveUDP(_:from:at:)`, drawing random values from `generator`.
    ///
    /// Classification order (behavior A1, notes 4.1) is unsupported source → STUN → Geneve → disco → WireGuard.
    mutating func receiveUDP(
        _ datagram: [UInt8],
        from source: IPEndpoint,
        at now: ContinuousClock.Instant,
        using generator: inout some RandomNumberGenerator
    ) -> [Output] {
        // There is a single IPv4 socket. A source with port 0 cannot receive a reply either.
        guard source.address.isIPv4, source.port != 0 else { return [.dropped(.unsupportedSource)] }
        if STUNMessage.looksLikeSTUN(datagram) {
            return receiveSTUN(datagram, at: now, using: &generator)
        }
        if Self.isGeneveEncapsulated(datagram) {
            // shortcut: Drop peer relay (Geneve) paths because they are unused (contract "Exclusions", notes 4.12).
            // Needed when measurements show that the NAT traversal rate is a problem.
            return [.dropped(.unsupportedDisco)]
        }
        if DiscoPacket.isDisco(datagram) {
            return receiveDisco(datagram, via: .udp(source), at: now, using: &generator)
        }
        return [.wireGuard(datagram, from: .udp(source))]
    }

    /// Equivalent to `receiveDERP(_:from:region:at:)`, drawing random values from `generator`.
    ///
    /// Handles disco according to behavior C. Otherwise forwards to WireGuard only if the sender is a known peer (behavior A2, notes §4.3). Records every packet as
    /// evidence that the region is reachable for home selection.
    mutating func receiveDERP(
        _ packet: [UInt8],
        from peer: NodePublicKey,
        region: Int64,
        at now: ContinuousClock.Instant,
        using generator: inout some RandomNumberGenerator
    ) -> [Output] {
        netcheck.noteDERPActivity(region: region, at: now)
        if DiscoPacket.isDisco(packet) {
            return receiveDisco(packet, via: .derp(peer, region: region), at: now, using: &generator)
        }
        guard peers[peer] != nil else { return [.dropped(.unknownDERPSender)] }
        return [.wireGuard(packet, from: .derp(peer, region: region))]
    }

    // MARK: Classification

    /// Whether Go considers a datagram Geneve-encapsulated (notes 4.1 2).
    ///
    /// Requires a valid header and either WireGuard protocol `0x7A12` or disco protocol `0x7A11` with disco at offset 8.
    /// Returns false for `0x7A11` without disco after the header or for any other protocol. Classification then checks for bare disco before
    /// falling back to raw WireGuard. A datagram with `0x7A11` in bytes 2–3 cannot match the bare disco magic.
    static func isGeneveEncapsulated(_ datagram: [UInt8]) -> Bool {
        guard datagram.count >= geneveHeaderLength,
              datagram[0] & 0xC0 == 0, datagram[1] & 0x3F == 0, datagram[7] == 0
        else { return false }
        switch UInt16(datagram[2]) << 8 | UInt16(datagram[3]) {
        case geneveProtocolWireGuard:
            return true
        case geneveProtocolDisco:
            return datagram.count >= geneveHeaderLength + DiscoPacket.classificationLength
                && datagram[geneveHeaderLength...].starts(with: DiscoPacket.magic)
        default:
            return false
        }
    }

    /// Matches a STUN response to the active round. Drops it if it cannot be parsed or does not belong to the round (behavior E2).
    private mutating func receiveSTUN(
        _ datagram: [UInt8],
        at now: ContinuousClock.Instant,
        using generator: inout some RandomNumberGenerator
    ) -> [Output] {
        guard let (txID, mapped) = STUNMessage.parseBindingResponse(datagram),
              let actions = netcheck.receive(txID, mapped: mapped, at: now)
        else { return [.dropped(.unexpectedSTUN)] }
        return handle(actions, at: now, using: &generator)
    }

    // MARK: Receiving disco (behavior C, notes 4.2)

    /// Opens one disco packet and handles it by type. Also emits `.pathChanged` for each peer holding the key whose path changed.
    ///
    /// Multiple peers may hold the sender's disco key, so resolve the owner per message using the same rules as Go (contract T5).
    /// - Ping: Over UDP, all peers holding the key gain the source as a candidate. If the embedded node key identifies a peer holding this key, only that
    ///   peer switches its active key to this key (Go `unambiguousNodeKeyOfPingLocked`). Over DERP, only replies to the DERP sender.
    /// - Pong: Only the peer that sent the Ping (the one with the matching TxID) receives it.
    /// - CallMeMaybe: Only the DERP sender peer receives it, if it holds the key.
    private mutating func receiveDisco(
        _ packet: [UInt8],
        via path: Source,
        at now: ContinuousClock.Instant,
        using generator: inout some RandomNumberGenerator
    ) -> [Output] {
        guard packet.count <= Self.maxDiscoPacketLength else { return [.dropped(.malformedDisco)] }
        guard let sender = DiscoPacket.senderKey(of: packet), let holders = discoPeers[sender] else {
            return [.dropped(.unknownDiscoKey)]
        }
        let message: DiscoMessage
        do {
            message = try DiscoPacket.open(packet, sharedKey: holders.sharedKey)
        } catch {
            if case .unknownType = error { return [.dropped(.unsupportedDisco)] }
            return [.dropped(.malformedDisco)]
        }

        var outputs: [Output]
        switch message {
        case .ping(let txID, let nodeKey):
            // The party that sealed the Ping (the holder of this key's private key) writes the embedded node key. Use it only if that peer holds this key.
            if case .udp = path, let nodeKey, holders.nodes.contains(nodeKey) {
                _ = noteDiscoKeySeen(sender, from: nodeKey)
            }
            outputs = receivePing(txID, from: sender, holders: holders.nodes, via: path, at: now, using: &generator)
        case .pong(let txID, _):
            // TxIDs are random for each sending peer, so at most one peer owns it. Ignore one that belongs to no peer (behavior C3).
            for node in holders.nodes {
                if peers[node]?.path.receivePong(txID, from: path.udpSource, at: now) == true { break }
            }
            outputs = []
        case .callMeMaybe(let endpoints):
            outputs = receiveCallMeMaybe(endpoints, from: sender, via: path, at: now, using: &generator)
        }
        for node in holders.nodes {
            reportPathChange(of: node, at: now, into: &outputs)
        }
        return outputs
    }

    /// Sends a Pong on the path the Ping arrived on (notes 4.2 4).
    ///
    /// Over UDP, every peer holding the key processes the source as a candidate (Go `forEachEndpointWithDiscoKey`), subject to the candidate and replay rules.
    /// Suppress the reply if any such peer already saw the same TxID from the same candidate. Go iterates in random order and stops at the first duplicate, so it may skip
    /// later peers. Swift checks them all, and Go can catch up on the next Ping. Over DERP, add no candidates and reply to the sender in the same region
    /// only if the sender is a known peer.
    private mutating func receivePing(
        _ txID: TransactionID,
        from sender: DiscoPublicKey,
        holders: [NodePublicKey],
        via path: Source,
        at now: ContinuousClock.Instant,
        using generator: inout some RandomNumberGenerator
    ) -> [Output] {
        switch path {
        case .udp(let source):
            var answer = true
            for node in holders {
                let isNew = peers[node]?.path.receivePing(txID, from: source, at: now) == true
                answer = answer && isNew
            }
            guard answer, let pong = seal(.pong(txID, source: source), to: sender, using: &generator) else { return [] }
            return [.udp(pong, to: source)]
        case .derp(let derpSender, let region):
            guard peers[derpSender] != nil else { return [.dropped(.misroutedDisco)] }
            guard let address = IPAddress(bytes: Self.derpMagicAddress) else { return [] }
            // Go also truncates the region ID to a 16-bit port (`uint16(regionID)`).
            let source = IPEndpoint(address: address, port: UInt16(truncatingIfNeeded: region))
            guard let pong = seal(.pong(txID, source: source), to: sender, using: &generator) else { return [] }
            return [.derp(pong, to: derpSender, region: region)]
        }
    }

    /// Accepts CallMeMaybe only over DERP, and only if the message's sender key is a disco key (netmap or TSMP) of the sending DERP peer
    /// (behavior C4, notes 4.2 3). If the key was inactive, makes it active (Go `checkAndUpdateDiscoKey`). On acceptance, treats those
    /// addresses as candidates and immediately Pings every candidate (notes 4.8 5).
    private mutating func receiveCallMeMaybe(
        _ endpoints: [IPEndpoint],
        from sender: DiscoPublicKey,
        via path: Source,
        at now: ContinuousClock.Instant,
        using generator: inout some RandomNumberGenerator
    ) -> [Output] {
        guard case .derp(let derpSender, _) = path, noteDiscoKeySeen(sender, from: derpSender),
              let actions = peers[derpSender]?.path.receiveCallMeMaybe(endpoints, at: now, using: &generator)
        else { return [.dropped(.misroutedDisco)] }
        return handle(actions, for: derpSender, at: now, using: &generator)
    }
}

extension Magicsock.Source {
    /// The source address over UDP, or nil over DERP.
    var udpSource: IPEndpoint? {
        if case .udp(let source) = self { source } else { nil }
    }
}
