import CryptoKit
import SwiftailBase
import SwiftailIO

/// DERP 연결 하나의 상태 기계. 소켓·시계·난수를 갖지 않는다.
///
/// 만들자마자 `takeOutboundBytes()`가 HTTP 업그레이드 요청을 내놓는다. 서버가 보낸 바이트를 `receive`에
/// 넣으면 101 응답 → ServerKey → (ClientInfo와 NotePreferred를 내보냄) → 준비 순서로 나아간다.
///
/// 입력의 경계는 세 겹이고 서로 섞지 않는다. TCP 조각은 임의로 끊긴다. 응답 머리는 `HTTPResponseHead.Parser`가
/// 모으고, 머리 뒤에 이미 온 바이트(Go 서버는 101에 ServerKey 프레임을 붙여 쓴다)는 `DERPFrameReader`로 넘어간다.
/// 프레임은 거기서 하나씩 나와 타입별로 처리된다. 서버가 보낸 모든 바이트는 이 경계에서 한 번 해석되어 검증된
/// 값(`Event`)이 된다.
///
/// 실패하면 받아 둔 바이트와 내보낼 바이트를 모두 버리고 이후 호출은 `closed`다. 한도는 응답 머리 16KiB,
/// 프레임 본문 1MiB, 답하지 않은 Pong 64KiB다.
///
/// `docs/protocol-notes/derp-stun.md` 3장, 4.2~4.5절, 계약 `docs/contracts/SwiftailDERP.md` "동작" 1~7
/// (출처: tailscale.com `derp/derp_client.go`, BSD-3-Clause).
public struct DERPConnection: Sendable {
    public enum Event: Sendable, Equatable {
        /// 핸드셰이크가 끝났다. 이제 `send`를 부를 수 있다.
        case ready
        /// 피어가 이 서버를 거쳐 보낸 패킷. 내용(WireGuard인지 disco인지)은 보지 않는다.
        case packet([UInt8], from: NodePublicKey)
        /// 서버가 그 피어를 이제 모른다.
        case peerGone(NodePublicKey, reason: PeerGoneReason)
    }

    /// PeerGone의 이유 코드(노트 3.6절). 모르는 값은 그대로 낸다.
    public enum PeerGoneReason: Sendable, Equatable { case disconnected, notHere, unknown(UInt8) }

    /// 보낼 수 있는 패킷의 한도(`MaxPacketSize`, 목적지 키 제외).
    static let maximumPacketSize = 65_536
    /// 답하지 않은 Pong이 쌓일 수 있는 바이트 한도.
    static let maximumPendingReplyBytes = 64 * 1024

    private enum Phase: Sendable {
        case awaitingHead
        case awaitingServerKey
        case ready
        case failed
    }

    private let privateKey: Curve25519.KeyAgreement.PrivateKey
    private let isPreferred: Bool
    private let clientInfoNonce: [UInt8]
    private var phase = Phase.awaitingHead
    private var head = HTTPResponseHead.Parser()
    private var frames = DERPFrameReader()
    private var outbound: [UInt8]
    private var pendingReplyBytes = 0
    /// 서버와의 NaCl 공유 키. ServerKey를 받은 뒤에 있고, ServerInfo를 여는 데 쓴다.
    private var sharedKey: [UInt8] = []
    /// 핸드셰이크 뒤에 프레임을 하나라도 받았다(서버가 ClientInfo를 받아들이고 ServerInfo를 보냈다는 뜻).
    /// `DERPClient`가 물러나기 횟수를 되돌릴 때 쓴다. 실패한 뒤에도 남는다.
    private(set) var hasReceivedFrameAfterHandshake = false

    /// - Parameters:
    ///   - privateKey: 이 노드의 node 개인 키(WireGuard 키와 같다).
    ///   - host: HTTP `Host` 값.
    ///   - isPreferred: 이 서버가 홈 지역이면 true. 핸드셰이크 끝에 NotePreferred를 보낸다.
    ///   - clientInfoNonce: ClientInfo를 봉할 24바이트 난수. 부르는 쪽이 시스템 난수로 뽑는다.
    /// - Throws: `malformed` — `host`가 비었거나 공백·제어 문자를 담았다, nonce가 24바이트가 아니다.
    public init(
        privateKey: Curve25519.KeyAgreement.PrivateKey, host: String, isPreferred: Bool, clientInfoNonce: [UInt8]
    ) throws(DERPError) {
        guard clientInfoNonce.count == DERPHandshake.nonceSize else { throw .malformed }
        self.privateKey = privateKey
        self.isPreferred = isPreferred
        self.clientInfoNonce = clientInfoNonce
        outbound = try DERPHandshake.upgradeRequest(host: host)
    }

    /// 서버가 보낸 바이트를 넣는다. 바이트 경계는 프레임 경계와 무관하다.
    ///
    /// - Throws: 실패하면 연결은 끝난다. 이후의 호출은 `closed`다.
    public mutating func receive(_ bytes: [UInt8]) throws(DERPError) -> [Event] {
        guard phase != .failed else { throw .closed }
        do throws(DERPError) {
            var events: [Event] = []
            if phase == .awaitingHead {
                guard let response = try readHead(bytes) else { return [] }
                guard response.status == 101 else { throw .upgradeRejected(status: response.status) }
                phase = .awaitingServerKey
                frames.append(response.remainder)
            } else {
                frames.append(bytes)
            }
            while let frame = try frames.nextFrame(maximumBody: phase == .awaitingServerKey ? DERPHandshake.maximumServerKeyBody : DERPFrame.maximumBody) {
                try handle(frame, into: &events)
            }
            frames.compact()
            return events
        } catch {
            // ServerKey 본문이 한도(1,024바이트)를 넘는 것은 프레임 한도가 아니라 핸드셰이크 실패다.
            let failure = error == .frameTooLarge && phase == .awaitingServerKey ? DERPError.handshakeFailed : error
            fail()
            throw failure
        }
    }

    /// 패킷 하나를 피어에게 보낸다(SendPacket 프레임 하나).
    ///
    /// - Throws: `closed`(실패한 뒤), `notReady`(핸드셰이크 전), `packetTooLarge`. 이 순서로 검사하고,
    ///   `notReady`와 `packetTooLarge`는 부르는 쪽의 잘못이므로 연결을 끝내지 않는다.
    public mutating func send(_ packet: [UInt8], to peer: NodePublicKey) throws(DERPError) {
        switch phase {
        case .failed: throw .closed
        case .awaitingHead, .awaitingServerKey: throw .notReady
        case .ready: break
        }
        guard packet.count <= Self.maximumPacketSize else { throw .packetTooLarge }
        outbound += DERPFrame.encoded(.sendPacket, body: peer.rawValue + packet)
    }

    /// 서버에 보낼 바이트를 꺼낸다. 없으면 빈 배열. `init`, `receive`, `send` 뒤에 부른다.
    public mutating func takeOutboundBytes() -> [UInt8] {
        pendingReplyBytes = 0
        defer { outbound = [] }
        return outbound
    }

    // MARK: 응답 머리

    private mutating func readHead(_ bytes: [UInt8]) throws(DERPError) -> HTTPResponseHead? {
        do {
            return try head.receive(bytes)
        } catch .malformedHeader(let status) where status != 101 {
            // 101이 아니면 머리가 이상해도 상태가 먼저다. Go도 상태 코드만 본다.
            throw .upgradeRejected(status: status)
        } catch {
            throw .malformed
        }
    }

    // MARK: 프레임

    private mutating func handle(_ frame: DERPFrame, into events: inout [Event]) throws(DERPError) {
        if phase == .awaitingServerKey {
            try acceptServerKey(frame, into: &events)
            return
        }
        hasReceivedFrameAfterHandshake = true
        switch frame.kind {
        case .recvPacket:
            // 보낸 쪽 키(32)가 없는 프레임은 버린다.
            guard let sender = NodePublicKey(rawValue: frame.body.prefix(DERPFrame.keySize)) else { return }
            events.append(.packet(Array(frame.body.dropFirst(DERPFrame.keySize)), from: sender))
        case .peerGone:
            guard let peer = NodePublicKey(rawValue: frame.body.prefix(DERPFrame.keySize)) else { return }
            events.append(.peerGone(peer, reason: Self.reason(frame.body.dropFirst(DERPFrame.keySize).first)))
        case .ping:
            try reply(toPing: frame.body)
        case .serverInfo:
            try DERPHandshake.openServerInfo(frame.body, sharedKey: sharedKey)
        default:
            // KeepAlive·Health·Restarting·PeerPresent·Pong·핸드셰이크 뒤의 ServerKey·모르는 타입: 본문을 건너뛴다.
            // Go magicsock도 상태 기록 말고는 하지 않는다(노트 4.5절 5).
            break
        }
    }

    private mutating func acceptServerKey(_ frame: DERPFrame, into events: inout [Event]) throws(DERPError) {
        let serverKey = try DERPHandshake.serverPublicKey(from: frame)
        let clientInfo = try DERPHandshake.clientInfo(privateKey: privateKey, serverKey: serverKey, nonce: clientInfoNonce)
        sharedKey = clientInfo.sharedKey
        outbound += DERPFrame.encoded(.clientInfo, body: clientInfo.body)
        if isPreferred { outbound += DERPFrame.encoded(.notePreferred, body: [0x01]) }
        phase = .ready
        events.append(.ready)
    }

    /// Ping의 앞 8바이트를 그대로 Pong으로 돌려준다. 8바이트가 안 되면 버린다.
    private mutating func reply(toPing body: [UInt8]) throws(DERPError) {
        guard body.count >= 8 else { return }
        let pong = DERPFrame.encoded(.pong, body: Array(body.prefix(8)))
        pendingReplyBytes += pong.count
        guard pendingReplyBytes <= Self.maximumPendingReplyBytes else { throw .tooManyPendingReplies }
        outbound += pong
    }

    private static func reason(_ byte: UInt8?) -> PeerGoneReason {
        switch byte {
        case nil, 0x00: .disconnected
        case 0x01: .notHere
        case let other?: .unknown(other)
        }
    }

    /// 받아 둔 바이트와 내보낼 바이트를 버리고 이후 호출을 `closed`로 만든다.
    private mutating func fail() {
        phase = .failed
        head = HTTPResponseHead.Parser()
        frames.discard()
        outbound = []
        pendingReplyBytes = 0
        sharedKey = []
    }
}

extension DERPConnection: CustomReflectable {
    /// 개인 키와 공유 키를 쥐므로 자식을 감춘다. `dump`와 `String(describing:)`에 키가 나오지 않는다.
    public var customMirror: Mirror {
        Mirror(self, children: [:])
    }
}
