/// 송신 쪽: IP 패킷을 대기열에 넣고, 쓸 수 있는 세션이 있으면 transport로 내보내고, 없으면
/// initiation을 보낸다. keepalive와 rekey 판단도 여기서 한다.
///
/// 백서 §5.4.6·§6.2, `docs/protocol-notes/wireguard.md` "전송 데이터: 보내기"·"핸드셰이크 송신 규칙"
/// (출처: wireguard-go `device/send.go`).
extension WireGuardDevice {
    /// IP 패킷 하나를 피어에게 보낸다. 세션이 없으면 대기열에 넣고 핸드셰이크를 시작한다.
    ///
    /// 대기열은 피어당 64개이며 넘치면 가장 오래된 것을 버린다.
    /// - Throws: 등록되지 않은 피어면 `unknownPeer`, 빈 패킷이면 `malformed`, 너무 크면 `packetTooLarge`.
    public mutating func send(_ ipPacket: [UInt8], to peer: PublicKey, at now: ContinuousClock.Instant) throws(WireGuardError) -> [Output] {
        guard let outputs = try edit(peer, { device, state throws(WireGuardError) in
            guard !ipPacket.isEmpty else { throw .malformed }
            guard ipPacket.count <= Constants.maxContentSize else { throw .packetTooLarge }
            state.stage(ipPacket)
            return device.sendStagedPackets(&state, at: now)
        }) else { throw .unknownPeer }
        return outputs
    }

    /// 대기열을 current keypair로 내보낸다. 보낼 수 없으면 대기열을 두고 initiation을 시도한다.
    func sendStagedPackets(_ peer: inout Peer, at now: ContinuousClock.Instant) -> [Output] {
        guard !peer.staged.isEmpty else { return [] }
        // 응답자의 next는 확인 전이므로 쓰지 않는다. 보낼 때는 늘 current다.
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
            // counter가 바닥났다. 남은 패킷은 새 세션을 기다린다.
            outputs += sendHandshakeInitiation(&peer, isRetry: false, at: now)
        }
        outputs += keepKeyFreshSending(&peer, at: now)
        return outputs
    }

    /// 세션이 막 섰을 때 priority message를 current keypair로 보낸다(`setPriorityMessage(_:for:)`).
    ///
    /// 대기열을 거치지 않고, 보낼 수 있는 세션이 없으면 핸드셰이크를 시작하지 않고 그만둔다(wireguard-go
    /// `SendPriorityMessage`). 빈 패킷이 아니므로 데이터 송신으로 센다(wireguard-go `RoutineSequentialSender`).
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

    /// 대기열이 비어 있으면 빈 패킷 하나를 넣고 대기열을 내보낸다. 비어 있지 않으면 그 패킷들이
    /// keepalive를 대신한다.
    func sendKeepalive(_ peer: inout Peer, at now: ContinuousClock.Instant) -> [Output] {
        if peer.staged.isEmpty {
            peer.stage([])
        }
        return sendStagedPackets(&peer, at: now)
    }

    /// 새 initiation을 만들어 보낸다. 마지막 핸드셰이크 메시지를 보낸 지 `rekeyTimeout`이 지나지 않았으면
    /// 아무것도 하지 않는다.
    ///
    /// 재시도도 저장한 바이트를 다시 보내지 않고 처음부터 새로 만든다(새 임시 키·sender·timestamp).
    /// 같은 timestamp는 응답자가 재전송으로 거절하기 때문이다.
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
        // 이전에 기다리던 initiation은 여기서 버려진다. 그 index로 늦게 온 response는 `unknownPeer`가 된다.
        peer.pendingHandshake = pending
        let macs = peer.cookieGenerator.macs(for: message.bytesBeforeMACs, at: now)

        peer.timers.anyAuthenticatedPacketSent()
        peer.timers.handshakeInitiated(at: now)
        return [.datagram(message.bytesBeforeMACs + macs.bytes, to: peer.publicKey)]
    }

    /// 보낸 뒤: counter가 2^60을 넘었거나 초기자 keypair가 120초를 넘었으면 rekey한다.
    func keepKeyFreshSending(_ peer: inout Peer, at now: ContinuousClock.Instant) -> [Output] {
        guard let current = peer.keypairs.current,
              current.sendNonce > Constants.rekeyAfterMessages
                || (current.isInitiator && now - current.created > Constants.rekeyAfterTime)
        else { return [] }
        return sendHandshakeInitiation(&peer, isRetry: false, at: now)
    }
}
