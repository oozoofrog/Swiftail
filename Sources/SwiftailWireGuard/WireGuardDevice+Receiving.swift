/// Parses incoming datagrams and handles them by type.
///
/// - initiation: As responder, authenticates the initiator and sends a response. Holds the new keypair in next until confirmed.
/// - response: As initiator, authenticates the responder and opens the session. Immediately sends the priority message and either the queue or
///   a keepalive to confirm the responder's next.
/// - cookie reply: Stores the cookie for mac2 in the next handshake message.
/// - transport: Decrypts, checks for replays, confirms next (then sends the priority message and queue), and checks the IP packet and AllowedIPs.
///
/// Checks mac1 first for initiation and response. Under load, also checks mac2 and the per-source rate limit (`admitHandshake`).
/// If mac2 is invalid, sends a cookie reply before doing X25519 and skips processing the message.
///
/// Failure in any path throws and leaves state unchanged. An invalid IP packet inside authenticated transport
/// does not invalidate the datagram, so it emits `rejectedIPPacket` without throwing.
///
/// Whitepaper §5.4, §6, `docs/protocol-notes/wireguard.md` "Responder: consuming an initiation", "Initiator: consuming a response",
/// "mac1, mac2, and cookies", and "Transport data: receiving" (origin: wireguard-go `device/receive.go`, `device/noise-protocol.go`).
extension WireGuardDevice {
    /// Processes one datagram received from the network.
    ///
    /// Throwing leaves state unchanged, except for attack accounting in the count of valid mac1 messages for load detection and the rate limit table.
    /// The reference time for the flood check changes only when an initiation is accepted (as in wireguard-go).
    /// If the plaintext of authenticated transport is not a valid IP packet or the source address is outside AllowedIPs, emits
    /// `rejectedIPPacket` without throwing. The packet was authenticated, so updates session state as for a normal receipt.
    ///
    /// - Parameter source: The datagram's source. Under load, binds the cookie and tracks the rate limit. Send any `.cookieReply` output
    ///   back to this source.
    public mutating func receive(_ datagram: [UInt8], from source: Source, at now: ContinuousClock.Instant) throws(WireGuardError) -> [Output] {
        switch try Message(parsing: datagram) {
        case let .initiation(message, macs):
            guard MAC.isValidMAC1(macs, over: message.bytesBeforeMACs, key: mac1Key) else { throw .authenticationFailed }
            if let reply = try admitHandshake(from: message.sender, over: message.bytesBeforeMACs, macs: macs, source: source, at: now) {
                return [.cookieReply(reply)]
            }
            return try receiveInitiation(message, at: now)
        case let .response(message, macs):
            guard MAC.isValidMAC1(macs, over: message.bytesBeforeMACs, key: mac1Key) else { throw .authenticationFailed }
            if let reply = try admitHandshake(from: message.sender, over: message.bytesBeforeMACs, macs: macs, source: source, at: now) {
                return [.cookieReply(reply)]
            }
            return try receiveResponse(message, at: now)
        case let .cookieReply(reply):
            try receiveCookieReply(reply, at: now)
            return []
        case let .transportData(message):
            return try receiveTransportData(message, at: now)
        }
    }

    // MARK: - Handshake

    /// Gates handshake messages that pass mac1 (the `IsUnderLoad` branch of wireguard-go `device/receive.go`).
    ///
    /// Anyone who knows our public key can create mac1. Count the message toward load detection and, under load,
    /// perform two more checks before the expensive X25519.
    /// 1. If mac2 was not computed with the cookie issued to this source, returns a cookie reply and skips the message.
    /// 2. Even if mac2 is valid, throws `rateLimited` when the source host exceeds its allowance.
    /// Checks mac2 only under load.
    ///
    /// - Returns: A cookie reply to send, or nil if the message can be processed.
    private mutating func admitHandshake(
        from sender: UInt32,
        over bytesBeforeMACs: [UInt8],
        macs: MessageMACs,
        source: Source,
        at now: ContinuousClock.Instant
    ) throws(WireGuardError) -> [UInt8]? {
        guard handshakeLoad.record(at: now) else { return nil }
        guard cookieChecker.isValidMAC2(macs, over: bytesBeforeMACs, from: source, at: now) else {
            var random = SystemRandomNumberGenerator()
            guard let reply = cookieChecker.makeReply(to: sender, mac1: macs.mac1, from: source, at: now, using: &random) else {
                throw .authenticationFailed
            }
            return reply.bytes
        }
        guard rateLimiter.allow(source.host, at: now) else { throw .rateLimited }
        return nil
    }

    private mutating func receiveInitiation(_ message: Initiation, at now: ContinuousClock.Instant) throws(WireGuardError) -> [Output] {
        guard let opened = Handshake.openInitiation(message, localStatic: staticKey) else { throw .authenticationFailed }
        guard let outputs = try edit(opened.initiator, { device, peer throws(WireGuardError) in
            try device.acceptInitiation(opened, for: &peer, at: now)
        }) else { throw .unknownPeer }
        return outputs
    }

    private func acceptInitiation(_ opened: OpenedInitiation, for peer: inout Peer, at now: ContinuousClock.Instant) throws(WireGuardError) -> [Output] {
        guard let staticStaticSecret = peer.staticStaticSecret,
              let initiation = Handshake.authenticate(opened, staticStaticSecret: staticStaticSecret)
        else { throw .authenticationFailed }

        // Block replays of the same initiation and floods of closely spaced initiations.
        if let last = peer.lastAcceptedTimestamp, initiation.timestamp <= last { throw .replayed }
        if let last = peer.lastInitiationConsumed, now - last <= Constants.handshakeInitiationRate { throw .replayed }

        let localIndex = freshIndex(avoiding: peer)
        guard case let (response, keys)? = Handshake.makeResponse(to: initiation, localIndex: localIndex, ephemeral: .init()) else {
            throw .authenticationFailed
        }
        peer.lastAcceptedTimestamp = initiation.timestamp
        peer.lastInitiationConsumed = now
        peer.timers.anyAuthenticatedPacketReceived()

        // Discard any initiation we sent that is still awaiting a response. The peer's initiation wins.
        peer.pendingHandshake = nil
        peer.lastSentHandshake = now
        let macs = peer.cookieGenerator.macs(for: response.bytesBeforeMACs, at: now)
        peer.keypairs.install(Keypair(keys: keys, localIndex: localIndex, remoteIndex: initiation.sender, isInitiator: false, created: now))
        peer.timers.sessionDerived(at: now)
        peer.timers.anyAuthenticatedPacketSent()
        return [.datagram(response.bytesBeforeMACs + macs.bytes, to: peer.publicKey)]
    }

    private mutating func receiveResponse(_ message: Response, at now: ContinuousClock.Instant) throws(WireGuardError) -> [Output] {
        guard let owner = indexTable[message.receiver],
              let outputs = try edit(owner, { device, peer throws(WireGuardError) in try device.acceptResponse(message, for: &peer, at: now) })
        else { throw .unknownPeer }
        return outputs
    }

    private func acceptResponse(_ message: Response, for peer: inout Peer, at now: ContinuousClock.Instant) throws(WireGuardError) -> [Output] {
        // If the index already references a keypair, this response has already been processed.
        guard let pending = peer.pendingHandshake, pending.localIndex == message.receiver else { throw .replayed }
        guard let keys = Handshake.consumeResponse(message, pending: pending, localStatic: staticKey) else {
            throw .authenticationFailed
        }

        peer.timers.anyAuthenticatedPacketReceived()
        peer.pendingHandshake = nil
        peer.keypairs.install(Keypair(keys: keys, localIndex: pending.localIndex, remoteIndex: message.sender, isInitiator: true, created: now))
        peer.timers.sessionDerived(at: now)
        peer.timers.handshakeComplete()
        // Send the priority message first. The responder must receive the first packet with this key to confirm next. If the queue is empty,
        // send a keepalive (wireguard-go also calls `SendKeepalive` after the priority message).
        return sendPriorityMessage(&peer, at: now) + sendKeepalive(&peer, at: now)
    }

    private mutating func receiveCookieReply(_ reply: CookieReply, at now: ContinuousClock.Instant) throws(WireGuardError) {
        // Accept either a handshake index or a keypair index as long as it belongs to the peer.
        guard let owner = indexTable[reply.receiver],
              let consumed = try edit(owner, { _, peer throws(WireGuardError) in
                  guard peer.cookieGenerator.consume(reply, at: now) else { throw .authenticationFailed }
                  return true
              })
        else { throw .unknownPeer }
        _ = consumed
    }

    // MARK: - Transport data

    private mutating func receiveTransportData(_ message: TransportData, at now: ContinuousClock.Instant) throws(WireGuardError) -> [Output] {
        guard let owner = indexTable[message.receiver],
              let outputs = try edit(owner, { device, peer throws(WireGuardError) in try device.receiveTransportData(message, for: &peer, at: now) })
        else { throw .unknownPeer }
        return outputs
    }

    private func receiveTransportData(_ message: TransportData, for peer: inout Peer, at now: ContinuousClock.Instant) throws(WireGuardError) -> [Output] {
        guard let slot = peer.keypairs.slot(forLocalIndex: message.receiver) else { throw .unknownPeer }
        // Finish checks that can throw (expiration, decryption, replay window) before modifying the peer. The replay window changes only when it accepts
        // an authenticated counter and stays unchanged on rejection.
        let plaintext = try peer.keypairs.open(message, in: slot, at: now)

        // The packet is now authenticated. Treat it as an authenticated receipt even if the enclosed IP packet is invalid.
        // Confirming next, draining the queue, rekeying, and updating timers are independent of IP validation (as in wireguard-go).
        var outputs: [Output] = []
        if peer.keypairs.confirm(slot) {
            peer.timers.handshakeComplete()
            outputs += sendPriorityMessage(&peer, at: now)
            outputs += sendStagedPackets(&peer, at: now)
        }
        outputs += keepKeyFreshReceiving(&peer, at: now)
        peer.timers.anyAuthenticatedPacketReceived()
        if !plaintext.isEmpty {  // Empty plaintext is a keepalive.
            peer.timers.dataReceived(at: now)
            outputs.append(delivery(of: plaintext, from: peer))
        }
        return outputs
    }

    /// Validates decrypted plaintext as an IP packet. Delivers it up the stack only if its source address is within the peer's AllowedIPs.
    /// This check is WireGuard's cryptokey routing, where "the key is the address."
    private func delivery(of plaintext: [UInt8], from peer: Peer) -> Output {
        guard let packet = InboundIPPacket(plaintext: plaintext) else {
            return .rejectedIPPacket(.malformed, from: peer.publicKey)
        }
        guard peer.allows(source: packet.source) else {
            return .rejectedIPPacket(.disallowedSource, from: peer.publicKey)
        }
        return .ipPacket(packet.bytes, from: peer.publicKey)
    }

    /// After receiving, rekeys once before expiration if the initiator's keypair is older than
    /// 165 seconds (RejectAfterTime − Keepalive − RekeyTimeout). This keeps the session alive even if the initiator only receives.
    private func keepKeyFreshReceiving(_ peer: inout Peer, at now: ContinuousClock.Instant) -> [Output] {
        guard !peer.timers.sentLastMinuteHandshake,
              let current = peer.keypairs.current,
              current.isInitiator,
              now - current.created > Constants.rejectAfterTime - Constants.keepaliveTimeout - Constants.rekeyTimeout
        else { return [] }
        peer.timers.sentLastMinuteHandshake = true
        return sendHandshakeInitiation(&peer, isRetry: false, at: now)
    }
}
