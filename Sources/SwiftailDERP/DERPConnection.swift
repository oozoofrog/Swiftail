import CryptoKit
import SwiftailBase
import SwiftailIO

/// The state machine for one DERP connection. Holds no socket, clock, or randomness.
///
/// Immediately after initialization, `takeOutboundBytes()` emits the HTTP upgrade request. Feeding server bytes to `receive`
/// progresses through the 101 response → ServerKey → (send ClientInfo and NotePreferred) → ready.
///
/// The input has three distinct layers of framing. TCP chunks can break anywhere. `HTTPResponseHead.Parser` collects
/// the response head, and bytes already received past the head go to `DERPFrameReader` (the Go server writes ServerKey alongside the 101).
/// The reader emits frames one at a time for handling by type. This boundary parses all bytes from the server once and produces validated
/// values (`Event`).
///
/// Failure discards all buffered incoming and outgoing bytes. Subsequent calls throw `closed`. The limits are 16KiB for the response head,
/// 1MiB for the frame body, and 64KiB for pending Pong replies.
///
/// `docs/protocol-notes/derp-stun.md` Chapter 3, §4.2~§4.5, contract `docs/contracts/SwiftailDERP.md` behaviors 1~7
/// (origin: tailscale.com `derp/derp_client.go`, BSD-3-Clause).
public struct DERPConnection: Sendable {
    public enum Event: Sendable, Equatable {
        /// The handshake is complete. The caller can now call `send`.
        case ready
        /// A packet a peer sent through this server. Its contents (WireGuard or disco) are opaque.
        case packet([UInt8], from: NodePublicKey)
        /// The server no longer knows that peer.
        case peerGone(NodePublicKey, reason: PeerGoneReason)
    }

    /// The PeerGone reason code (notes §3.6). Passes unknown values through.
    public enum PeerGoneReason: Sendable, Equatable { case disconnected, notHere, unknown(UInt8) }

    /// The maximum outgoing packet size (`MaxPacketSize`, excluding the destination key).
    static let maximumPacketSize = 65_536
    /// The maximum number of bytes of pending Pong replies.
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
    /// The NaCl shared key with the server. Available after receiving ServerKey and used to open ServerInfo.
    private var sharedKey: [UInt8] = []
    /// Whether at least one frame was received and processed after the handshake (meaning the server accepted ClientInfo and sent ServerInfo).
    /// Frames that failed processing (such as ServerInfo that cannot be opened) do not count. Go also resets backoff only on a successful receive.
    /// `DERPClient` uses this to reset its backoff count. It remains available after failure.
    private(set) var hasReceivedFrameAfterHandshake = false

    /// - Parameters:
    ///   - privateKey: This node's node private key (the same as the WireGuard key).
    ///   - host: The HTTP `Host` value.
    ///   - isPreferred: True if the server is in the home region. Sends NotePreferred at the end of the handshake.
    ///   - clientInfoNonce: 24 random bytes for sealing ClientInfo. The caller draws them from system randomness.
    /// - Throws: `malformed` if `host` is empty or contains whitespace or control characters, or if the nonce is not 24 bytes.
    public init(
        privateKey: Curve25519.KeyAgreement.PrivateKey, host: String, isPreferred: Bool, clientInfoNonce: [UInt8]
    ) throws(DERPError) {
        guard clientInfoNonce.count == DERPHandshake.nonceSize else { throw .malformed }
        self.privateKey = privateKey
        self.isPreferred = isPreferred
        self.clientInfoNonce = clientInfoNonce
        outbound = try DERPHandshake.upgradeRequest(host: host)
    }

    /// Accepts bytes from the server. Byte boundaries need not align with frame boundaries.
    ///
    /// - Throws: Failure ends the connection. Subsequent calls throw `closed`.
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
            // A ServerKey body above its 1,024-byte limit is a handshake failure. The general frame limit does not apply here.
            let failure = error == .frameTooLarge && phase == .awaitingServerKey ? DERPError.handshakeFailed : error
            fail()
            throw failure
        }
    }

    /// Sends one packet to a peer in a single SendPacket frame.
    ///
    /// - Throws: `closed` after failure, `notReady` before the handshake, or `packetTooLarge`, checked in that order.
    ///   The `notReady` and `packetTooLarge` cases are caller errors and leave the connection open.
    public mutating func send(_ packet: [UInt8], to peer: NodePublicKey) throws(DERPError) {
        switch phase {
        case .failed: throw .closed
        case .awaitingHead, .awaitingServerKey: throw .notReady
        case .ready: break
        }
        guard packet.count <= Self.maximumPacketSize else { throw .packetTooLarge }
        outbound += DERPFrame.encoded(.sendPacket, body: peer.rawValue + packet)
    }

    /// Takes bytes to send to the server, returning an empty array when there are none. Call after `init`, `receive`, or `send`.
    public mutating func takeOutboundBytes() -> [UInt8] {
        pendingReplyBytes = 0
        defer { outbound = [] }
        return outbound
    }

    // MARK: Response head

    private mutating func readHead(_ bytes: [UInt8]) throws(DERPError) -> HTTPResponseHead? {
        do {
            return try head.receive(bytes)
        } catch .malformedHeader(let status) where status != 101 {
            // For a status other than 101, give the status precedence even if the head is malformed. Go also checks only the status code.
            throw .upgradeRejected(status: status)
        } catch {
            throw .malformed
        }
    }

    // MARK: Frames

    private mutating func handle(_ frame: DERPFrame, into events: inout [Event]) throws(DERPError) {
        if phase == .awaitingServerKey {
            try acceptServerKey(frame, into: &events)
            return
        }
        switch frame.kind {
        case .recvPacket:
            // Discard frames without a sender key (32 bytes).
            guard let sender = NodePublicKey(rawValue: frame.body.prefix(DERPFrame.keySize)) else { break }
            events.append(.packet(Array(frame.body.dropFirst(DERPFrame.keySize)), from: sender))
        case .peerGone:
            guard let peer = NodePublicKey(rawValue: frame.body.prefix(DERPFrame.keySize)) else { break }
            events.append(.peerGone(peer, reason: Self.reason(frame.body.dropFirst(DERPFrame.keySize).first)))
        case .ping:
            try reply(toPing: frame.body)
        case .serverInfo:
            try DERPHandshake.openServerInfo(frame.body, sharedKey: sharedKey)
        default:
            // Skip the bodies of KeepAlive, Health, Restarting, PeerPresent, Pong, ServerKey after the handshake, and unknown types.
            // Go magicsock also only records state (notes §4.5, item 5).
            break
        }
        hasReceivedFrameAfterHandshake = true
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

    /// Echoes the first 8 bytes of Ping as Pong. Discards payloads shorter than 8 bytes.
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

    /// Discards buffered incoming and outgoing bytes and makes subsequent calls throw `closed`.
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
    /// Hides children because they hold private and shared keys. Keys are omitted from `dump` and `String(describing:)`.
    public var customMirror: Mirror {
        Mirror(self, children: [:])
    }
}
