// 받은 UDP의 분류 순서와 disco 받기는 Go 구현을 따랐다.
// 출처: tailscale.com v1.104.6 `wgengine/magicsock/magicsock.go` (`packetLooksLike`, `handleDiscoMessage`,
// `handlePingLocked`, v1.104.7의 `unambiguousNodeKeyOfPingLocked`), `wgengine/magicsock/derp.go` (`processDERPReadResult`),
// v1.104.7 `wgengine/magicsock/peermap.go` (`forEachEndpointWithDiscoKey`), `endpoint.go` (`handlePongConnLocked`).
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import SwiftailBase

/// 받은 것의 분류와 disco 받기(계약 동작 A·C, 노트 4.1~4.3).
///
/// UDP와 DERP로 온 바이트는 신뢰할 수 없는 입력이다. 여기서 한 번 분류해 STUN 응답, disco 메시지, WireGuard
/// 데이터그램 가운데 하나로 바꾸고, 어느 것에도 맞지 않거나 규칙을 어긴 것은 상태를 바꾸지 않고 `.dropped`로 버린다.
/// 거르는 순서는 싼 것부터다: 출처 → 모양 → 길이 → 보낸 쪽 disco 키(표에서 찾기만 한다) → 복호화 → 경로 규칙.
/// 모르는 키의 disco는 암호 연산 없이 버려지고, 열리지 않은 패킷은 WireGuard로 넘어가지 않는다(노트 3.2 6).
///
/// WireGuard 데이터그램은 내용을 보지 않는다. 피어는 WireGuard 장치가 receiver index로 정한다(동작 A3). 온 길은
/// 함께 싣는다. WireGuard가 부하 상태일 때 cookie를 그 길에 묶고 cookie reply를 그 길로 되돌린다.
extension Magicsock {
    /// 받은 것이 온 길. disco의 경로 규칙과, WireGuard 데이터그램에 답할 곳(cookie reply)을 정한다.
    public enum Source: Sendable, Hashable {
        /// UDP. 출처 주소.
        case udp(IPEndpoint)
        /// DERP. 보낸 쪽 node 키와 받은 지역.
        case derp(NodePublicKey, region: Int64)
    }

    /// 열어 볼 disco 패킷의 최대 길이: 가장 큰 Go 경로 MTU Ping(wire MTU 9000에서 IPv4·UDP 머리 28바이트를 뺀 것,
    /// 노트 4.12 "peer MTU"). 정상 메시지는 이보다 훨씬 작다(Pong 110바이트). 더 긴 것은 복호화 전에 버린다.
    static let maxDiscoPacketLength = 9000 - 28

    /// Geneve 머리 길이와 Go가 쓰는 protocol 값(노트 3.6).
    private static let geneveHeaderLength = 8
    private static let geneveProtocolDisco: UInt16 = 0x7A11
    private static let geneveProtocolWireGuard: UInt16 = 0x7A12
    /// DERP로 온 Ping의 Pong에 담는 출처 주소 `127.3.3.40`(Go `tailcfg.DerpMagicIPAddr`, 노트 4.2 4.4).
    private static let derpMagicAddress: [UInt8] = [127, 3, 3, 40]

    // MARK: 진입점

    /// UDP 소켓에서 받은 데이터그램 하나.
    public mutating func receiveUDP(_ datagram: [UInt8], from source: IPEndpoint, at now: ContinuousClock.Instant) -> [Output] {
        var random = SystemRandomNumberGenerator()
        return receiveUDP(datagram, from: source, at: now, using: &random)
    }

    /// DERP 지역 `region`의 연결에서 받은 패킷 하나. `peer`는 DERP 프레임의 보낸 쪽 키다.
    public mutating func receiveDERP(
        _ packet: [UInt8],
        from peer: NodePublicKey,
        region: Int64,
        at now: ContinuousClock.Instant
    ) -> [Output] {
        var random = SystemRandomNumberGenerator()
        return receiveDERP(packet, from: peer, region: region, at: now, using: &random)
    }

    /// `receiveUDP(_:from:at:)`과 같다. 난수를 `generator`에서 뽑는다.
    ///
    /// 분류 순서(동작 A1, 노트 4.1): 받을 수 없는 출처 → STUN → Geneve → disco → WireGuard.
    mutating func receiveUDP(
        _ datagram: [UInt8],
        from source: IPEndpoint,
        at now: ContinuousClock.Instant,
        using generator: inout some RandomNumberGenerator
    ) -> [Output] {
        // 소켓이 IPv4 하나다. 포트 0인 출처에는 답할 수도 없다.
        guard source.address.isIPv4, source.port != 0 else { return [.dropped(.unsupportedSource)] }
        if STUNMessage.looksLikeSTUN(datagram) {
            return receiveSTUN(datagram, at: now, using: &generator)
        }
        if Self.isGeneveEncapsulated(datagram) {
            // shortcut: peer relay(Geneve) 경로는 쓰지 않으므로 버린다(계약 "제외", 노트 4.12).
            // 필요해지는 시점: 측정에서 NAT 통과율이 문제일 때.
            return [.dropped(.unsupportedDisco)]
        }
        if DiscoPacket.isDisco(datagram) {
            return receiveDisco(datagram, via: .udp(source), at: now, using: &generator)
        }
        return [.wireGuard(datagram, from: .udp(source))]
    }

    /// `receiveDERP(_:from:region:at:)`과 같다. 난수를 `generator`에서 뽑는다.
    ///
    /// disco면 동작 C로, 아니면 보낸 쪽이 아는 피어일 때만 WireGuard로 넘긴다(동작 A2, 노트 4.3). 받은 패킷은 모두
    /// 그 지역이 살아 있다는 표시로 홈 선택에 알린다.
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

    // MARK: 분류

    /// Go가 Geneve로 감싼 것으로 보는 데이터그램인가(노트 4.1 2).
    ///
    /// 머리 조건이 맞고 protocol이 WireGuard(`0x7A12`)이거나, disco(`0x7A11`)이고 8바이트 뒤가 disco면 참이다.
    /// `0x7A11`인데 뒤가 disco가 아니거나 다른 protocol이면 거짓이고, 다음 단계에서 맨 WireGuard가 된다(바이트 2–3이
    /// disco magic이 아니므로 disco일 수 없다).
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

    /// STUN 응답을 진행 중인 회차와 맞춘다. 해석할 수 없거나 회차의 것이 아니면 버린다(동작 E2).
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

    // MARK: disco 받기 (동작 C, 노트 4.2)

    /// disco 패킷 하나를 열어 종류별로 처리한다. 그 키를 쥔 피어 가운데 경로가 바뀐 피어마다 `.pathChanged`도 낸다.
    ///
    /// 보낸 쪽 disco 키를 여러 피어가 쥘 수 있으므로 메시지마다 Go와 같은 규칙으로 주인을 가린다(계약 T5).
    /// - Ping: UDP로 왔으면 그 키를 쥔 모든 피어가 출처를 후보로 얻는다. Ping 안의 node 키가 그 키를 쥔 피어면 그
    ///   피어만 활성 키를 이 키로 바꾼다(Go `unambiguousNodeKeyOfPingLocked`). DERP로 왔으면 DERP 보낸 쪽에게 답만 한다.
    /// - Pong: 그 Ping을 보낸 피어 하나(TxID가 맞는 피어)만 받는다.
    /// - CallMeMaybe: DERP 보낸 쪽 피어가 그 키를 쥐었을 때 그 피어만 받는다.
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
            // Ping 안의 node 키는 봉한 쪽(이 키의 개인 키를 가진 쪽)이 적는다. 그 피어가 이 키를 쥐었을 때만 쓴다.
            if case .udp = path, let nodeKey, holders.nodes.contains(nodeKey) {
                _ = noteDiscoKeySeen(sender, from: nodeKey)
            }
            outputs = receivePing(txID, from: sender, holders: holders.nodes, via: path, at: now, using: &generator)
        case .pong(let txID, _):
            // TxID는 보낸 피어마다 무작위라 많아야 한 피어의 것이다. 아무 피어의 것도 아니면 무시한다(동작 C3).
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

    /// Ping에 온 길로 Pong을 보낸다(노트 4.2 4).
    ///
    /// UDP로 왔으면 출처가 그 키를 쥔 모든 피어의 후보가 되고(Go `forEachEndpointWithDiscoKey`), 어느 피어에게든 같은
    /// 후보의 같은 TxID(재전송)였으면 답하지 않는다. Go는 무작위 순서로 돌다가 중복에서 멈추므로 뒤의 피어에는 후보를
    /// 넣지 않을 수 있다. 여기서는 모두 넣는다(다음 Ping에서 같아진다). DERP로 왔으면 후보를 넣지 않고 DERP 보낸 쪽이
    /// 아는 피어일 때만 같은 지역으로 그 피어에게 답한다.
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
            // Go도 지역 ID를 16비트 포트로 잘라 담는다(`uint16(regionID)`).
            let source = IPEndpoint(address: address, port: UInt16(truncatingIfNeeded: region))
            guard let pong = seal(.pong(txID, source: source), to: sender, using: &generator) else { return [] }
            return [.derp(pong, to: derpSender, region: region)]
        }
    }

    /// CallMeMaybe는 DERP로 왔고, 메시지의 보낸 쪽 키가 DERP 보낸 쪽 피어의 disco 키(netmap 키나 TSMP 키)일 때만
    /// 받는다(동작 C4, 노트 4.2 3). 비활성 키였으면 활성을 그쪽으로 바꾼다(Go `checkAndUpdateDiscoKey`). 받으면 그
    /// 주소들을 후보로 삼고 모든 후보에 곧바로 Ping한다(노트 4.8 5).
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
    /// UDP로 왔으면 출처 주소, DERP로 왔으면 nil.
    var udpSource: IPEndpoint? {
        if case .udp(let source) = self { source } else { nil }
    }
}
