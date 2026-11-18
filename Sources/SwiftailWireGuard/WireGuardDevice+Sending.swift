/// Queues outgoing IP packets and sends them as transport messages when a usable session exists. Otherwise
/// sends an initiation. Also handles keepalive and rekey decisions.
///
/// Whitepaper §5.4.6 and §6.2, `docs/protocol-notes/wireguard.md` "Transport data: sending" and "Handshake sending rules"
/// (origin: wireguard-go `device/send.go`).
extension WireGuardDevice {
    /// Sends one IP packet to a peer. If there is no session, queues the packet and starts a handshake.
    ///
    /// The queue holds 64 packets per peer and discards the oldest packet on overflow.
    /// - Throws: `unknownPeer` for an unregistered peer, `malformed` for an empty packet, or `packetTooLarge` for an oversized packet.
    public mutating func send(_ ipPacket: [UInt8], to peer: PublicKey, at now: ContinuousClock.Instant) throws(WireGuardError) -> [Output] {
        guard let outputs = try edit(peer, { device, state throws(WireGuardError) in
            guard !ipPacket.isEmpty else { throw .malformed }
            guard ipPacket.count <= Constants.maxContentSize else { throw .packetTooLarge }
            state.stage(ipPacket)
            return device.sendStagedPackets(&state, at: now)
        }) else { throw .unknownPeer }
        return outputs
    }

    /// Sends queued packets using the current keypair. If sending is unavailable, leaves the queue in place and attempts an initiation.
    func sendStagedPackets(_ peer: inout Peer, at now: ContinuousClock.Instant) -> [Output] {
        guard !peer.staged.isEmpty else { return [] }
        // The responder's next awaits confirmation and is unavailable for use. Always send with current.
        guard var keypair = peer.keypairs.current, keypair.canSend(at: now) else {
            return sendHandshakeInitiation(&peer, isRetry: false, at: now)
        }

        var outputs: [Output] = []
        var sentData = false
        while !peer.staged.isEmpty, keypair.sendNonce < Constants.rejectAfterMessages {
            let packet = peer.staged.removeFirst()
            outputs.append(.datagram(keypair.seal(packet), to: peer.publicKey))
            sentData = sentData || !packet.isEmpty
        }
        peer.keypairs.current = keypair

        peer.timers.anyAuthenticatedPacketSent()
        if sentData {
            peer.timers.dataSent(at: now)
        }
        if !peer.staged.isEmpty {
            // The counter is exhausted. The remaining packets wait for a new session.
            outputs += sendHandshakeInitiation(&peer, isRetry: false, at: now)
        }
        outputs += keepKeyFreshSending(&peer, at: now)
        return outputs
    }

    /// Sends the priority message using the current keypair when a session is first established (`setPriorityMessage(_:for:)`).
    ///
    /// Bypasses the queue and skips sending if no session is usable, without starting a handshake (wireguard-go
    /// `SendPriorityMessage`). It counts as a data send because the packet is nonempty (wireguard-go `RoutineSequentialSender`).
    func sendPriorityMessage(_ peer: inout Peer, at now: ContinuousClock.Instant) -> [Output] {
        guard let message = peer.priorityMessage, var keypair = peer.keypairs.current, keypair.canSend(at: now) else {
            return []
        }
        let datagram = keypair.seal(message)
        peer.keypairs.current = keypair
        peer.timers.anyAuthenticatedPacketSent()
        peer.timers.dataSent(at: now)
        return [.datagram(datagram, to: peer.publicKey)]
    }

    /// If the queue is empty, adds an empty packet and sends the queue. If it already has packets,
    /// they take the place of the keepalive.
    func sendKeepalive(_ peer: inout Peer, at now: ContinuousClock.Instant) -> [Output] {
        if peer.staged.isEmpty {
            peer.stage([])
        }
        return sendStagedPackets(&peer, at: now)
    }

    /// Creates and sends a new initiation. If less than `rekeyTimeout` has passed since the last handshake message was sent,
    /// does nothing.
    ///
    /// Every retry is also built from scratch (new ephemeral key, sender, and timestamp), without resending stored bytes.
    /// The responder would reject the same timestamp as a replay.
    func sendHandshakeInitiation(_ peer: inout Peer, isRetry: Bool, at now: ContinuousClock.Instant) -> [Output] {
        if !isRetry {
            peer.timers.handshakeAttempts = 0
        }
        if let lastSent = peer.lastSentHandshake, now - lastSent < Constants.rekeyTimeout {
            return []
        }
        peer.lastSentHandshake = now

        guard let staticStaticSecret = peer.staticStaticSecret,
              case let (message, pending)? = Handshake.makeInitiation(
                  localStatic: staticKey,
                  remoteStatic: peer.publicKey,
                  staticStaticSecret: staticStaticSecret,
                  timestamp: timestamp(at: now),
                  localIndex: freshIndex(avoiding: peer),
                  ephemeral: .init()
              )
        else { return [] }
        // Discards the previous pending initiation here. A late response to its index yields `unknownPeer`.
        peer.pendingHandshake = pending
        let macs = peer.cookieGenerator.macs(for: message.bytesBeforeMACs, at: now)

        peer.timers.anyAuthenticatedPacketSent()
        peer.timers.handshakeInitiated(at: now)
        return [.datagram(message.bytesBeforeMACs + macs.bytes, to: peer.publicKey)]
    }

    /// After sending, rekeys if the counter exceeds 2^60 or the initiator's keypair is older than 120 seconds.
    func keepKeyFreshSending(_ peer: inout Peer, at now: ContinuousClock.Instant) -> [Output] {
        guard let current = peer.keypairs.current,
              current.sendNonce > Constants.rekeyAfterMessages
                || (current.isInitiator && now - current.created > Constants.rekeyAfterTime)
        else { return [] }
        return sendHandshakeInitiation(&peer, isRetry: false, at: now)
    }
}
