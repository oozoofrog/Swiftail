/// 수신 쪽: 데이터그램을 해석해 type별로 처리한다.
///
/// - initiation: 응답자로서 초기자를 인증하고 response를 보낸다. 새 keypair는 확인 전까지 next에 둔다.
/// - response: 초기자로서 응답자를 인증하고 세션을 연다. 응답자의 next를 확인시키려고 곧바로 보낸다.
/// - cookie reply: 다음 핸드셰이크 메시지의 mac2에 쓸 cookie를 보관한다.
/// - transport: 복호화, 재전송 검사, next 확인, IP 패킷 검사와 AllowedIPs 검사.
///
/// initiation과 response는 먼저 mac1을 보고, 부하 상태이면 mac2와 출처별 속도 제한을 본다(`admitHandshake`).
/// mac2가 틀리면 X25519를 하기 전에 cookie reply로 답하고 메시지는 처리하지 않는다.
///
/// 어느 경로든 실패하면 오류를 던지고 상태를 바꾸지 않는다. 인증된 transport 안의 IP 패킷이 잘못된
/// 경우는 데이터그램의 실패가 아니므로 오류가 아니라 `rejectedIPPacket` 출력으로 알린다.
///
/// 백서 §5.4, §6, `docs/protocol-notes/wireguard.md` "응답자: initiation 소비", "초기자: response 소비",
/// "mac1·mac2와 cookie", "전송 데이터: 받기" (출처: wireguard-go `device/receive.go`, `device/noise-protocol.go`).
extension WireGuardDevice {
    /// 네트워크에서 받은 데이터그램 하나를 처리한다.
    ///
    /// 오류를 던진 경우 상태는 바뀌지 않는다. 예외는 공격을 세는 기록이다: initiation flood 검사를 위한 수신 시각,
    /// 부하 판정을 위한 mac1 통과 수, 속도 제한 표.
    /// 인증된 transport의 평문이 올바른 IP 패킷이 아니거나 출발 주소가 AllowedIPs 밖이면 오류를 던지지
    /// 않고 `rejectedIPPacket`을 낸다. 그 패킷도 인증된 수신이므로 세션 상태는 정상 수신과 같이 갱신한다.
    ///
    /// - Parameter source: 데이터그램이 온 곳. 부하 상태에서 cookie를 묶고 속도 제한을 센다. `.cookieReply` 출력은
    ///   이곳으로 되돌려 보낸다.
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

    // MARK: - 핸드셰이크

    /// mac1을 통과한 핸드셰이크 메시지의 문지기(wireguard-go `device/receive.go`의 `IsUnderLoad` 분기).
    ///
    /// mac1은 우리 공개 키를 아는 사람이면 누구나 만들 수 있다. 그래서 이 메시지를 부하 판정에 세고, 부하 상태이면
    /// 비싼 X25519 전에 두 가지를 더 본다.
    /// 1. mac2가 이 출처에 준 cookie로 만든 것이 아니면 cookie reply를 돌려준다. 메시지는 처리하지 않는다.
    /// 2. mac2가 맞아도 출처 호스트의 몫을 넘으면 `rateLimited`.
    /// 부하 상태가 아니면 mac2는 보지 않는다.
    ///
    /// - Returns: 보낼 cookie reply. nil이면 메시지를 처리해도 된다.
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
        guard var peer = peers[opened.initiator] else { throw .unknownPeer }
        guard let staticStaticSecret = peer.staticStaticSecret,
              let initiation = Handshake.authenticate(opened, staticStaticSecret: staticStaticSecret)
        else { throw .authenticationFailed }

        // 같은 initiation의 재전송과 짧은 간격의 initiation 홍수를 막는다.
        if let last = peer.lastAcceptedTimestamp, initiation.timestamp <= last { throw .replayed }
        if let last = peer.lastInitiationConsumed, now - last <= Constants.handshakeInitiationRate { throw .replayed }

        let localIndex = freshIndex(avoiding: peer)
        guard case let (response, keys)? = Handshake.makeResponse(to: initiation, localIndex: localIndex, ephemeral: .init()) else {
            throw .authenticationFailed
        }
        peer.lastAcceptedTimestamp = initiation.timestamp
        peer.lastInitiationConsumed = now
        peer.timers.anyAuthenticatedPacketReceived()

        // 우리가 보낸 initiation이 response를 기다리고 있었다면 버린다. 상대의 initiation이 이긴다.
        peer.pendingHandshake = nil
        peer.lastSentHandshake = now
        let macs = peer.cookieGenerator.macs(for: response.bytesBeforeMACs, at: now)
        peer.keypairs.install(Keypair(keys: keys, localIndex: localIndex, remoteIndex: initiation.sender, isInitiator: false, created: now))
        peer.timers.sessionDerived(at: now)
        peer.timers.anyAuthenticatedPacketSent()
        store(peer)
        return [.datagram(response.bytesBeforeMACs + macs.bytes, to: peer.publicKey)]
    }

    private mutating func receiveResponse(_ message: Response, at now: ContinuousClock.Instant) throws(WireGuardError) -> [Output] {
        guard let owner = indexTable[message.receiver], var peer = peers[owner] else { throw .unknownPeer }
        // index가 이미 keypair로 바뀌었다면 이 response는 처리한 적이 있다.
        guard let pending = peer.pendingHandshake, pending.localIndex == message.receiver else { throw .replayed }
        guard let keys = Handshake.consumeResponse(message, pending: pending, localStatic: staticKey) else {
            throw .authenticationFailed
        }

        peer.timers.anyAuthenticatedPacketReceived()
        peer.pendingHandshake = nil
        peer.keypairs.install(Keypair(keys: keys, localIndex: pending.localIndex, remoteIndex: message.sender, isInitiator: true, created: now))
        peer.timers.sessionDerived(at: now)
        peer.timers.handshakeComplete()
        // 응답자는 이 키로 온 첫 패킷을 받아야 next를 확정한다. 대기열이 비어 있으면 keepalive라도 보낸다.
        let outputs = sendKeepalive(&peer, at: now)
        store(peer)
        return outputs
    }

    private mutating func receiveCookieReply(_ reply: CookieReply, at now: ContinuousClock.Instant) throws(WireGuardError) {
        // 핸드셰이크 index든 keypair index든 그 피어의 것이면 받는다.
        guard let owner = indexTable[reply.receiver], var peer = peers[owner] else { throw .unknownPeer }
        guard peer.cookieGenerator.consume(reply, at: now) else { throw .authenticationFailed }
        store(peer)
    }

    // MARK: - 전송 데이터

    private mutating func receiveTransportData(_ message: TransportData, at now: ContinuousClock.Instant) throws(WireGuardError) -> [Output] {
        guard let owner = indexTable[message.receiver],
              var peer = peers[owner],
              let slot = peer.keypairs.slot(forLocalIndex: message.receiver),
              var keypair = peer.keypairs[slot]
        else { throw .unknownPeer }
        guard keypair.canReceive(at: now) else { throw .noSession }
        guard let plaintext = keypair.open(message) else { throw .authenticationFailed }
        // 재전송 창은 인증된 counter로만 움직인다.
        guard keypair.replayFilter.accept(message.counter) else { throw .replayed }
        peer.keypairs[slot] = keypair

        // 여기부터 패킷은 인증되었다. 안에 든 IP 패킷이 잘못됐더라도 인증된 수신으로 다룬다:
        // next 확정, 대기열 방출, rekey, 타이머 갱신은 IP 검사와 무관하다(wireguard-go와 같다).
        var outputs: [Output] = []
        if peer.keypairs.confirm(slot) {
            peer.timers.handshakeComplete()
            // shortcut: 확인 시점의 priority message(포크의 SetPriorityMessageOnEstablishmentFunc)는 보내지 않는다. 엔진이 필요로 하는 M3–M4에서 올린다.
            outputs += sendStagedPackets(&peer, at: now)
        }
        outputs += keepKeyFreshReceiving(&peer, at: now)
        peer.timers.anyAuthenticatedPacketReceived()
        if !plaintext.isEmpty {  // 빈 평문은 keepalive다.
            peer.timers.dataReceived(at: now)
            outputs.append(delivery(of: plaintext, from: peer))
        }
        store(peer)
        return outputs
    }

    /// 복호화한 평문을 IP 패킷으로 검증한다. 출발 주소가 그 피어의 AllowedIPs 안이어야 위로 올린다.
    /// 이 검사가 "키가 곧 주소"라는 WireGuard의 cryptokey routing이다.
    private func delivery(of plaintext: [UInt8], from peer: Peer) -> Output {
        guard let packet = InboundIPPacket(plaintext: plaintext) else {
            return .rejectedIPPacket(.malformed, from: peer.publicKey)
        }
        guard peer.allows(source: packet.source) else {
            return .rejectedIPPacket(.disallowedSource, from: peer.publicKey)
        }
        return .ipPacket(packet.bytes, from: peer.publicKey)
    }

    /// 받은 뒤: 초기자 keypair가 165초(RejectAfterTime − Keepalive − RekeyTimeout)를 넘었으면
    /// 만료 전에 한 번 rekey한다. 받기만 하고 보내지 않는 초기자도 세션이 끊기지 않게 하기 위해서다.
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
