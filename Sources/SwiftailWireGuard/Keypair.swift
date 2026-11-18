import CryptoKit

/// A transport session from one handshake, with send and receive keys, a send counter, and a receive replay protection window.
///
/// Whitepaper §5.4.6, `docs/protocol-notes/wireguard.md` "Transport key derivation"
/// (origin: wireguard-go `device/keypair.go`, `device/noise-protocol.go`).
struct Keypair {
    let sendKey: SymmetricKey
    let receiveKey: SymmetricKey
    /// The receiver field of incoming transport messages for this session. It is the sender field we sent during the handshake.
    let localIndex: UInt32
    /// The receiver field of outgoing transport messages for this session.
    let remoteIndex: UInt32
    /// Whether this side sent the initiation. Only the initiator performs time-based rekeying.
    let isInitiator: Bool
    let created: ContinuousClock.Instant
    /// The next counter to send.
    var sendNonce: UInt64 = 0
    var replayFilter = ReplayFilter()

    init(keys: SessionKeys, localIndex: UInt32, remoteIndex: UInt32, isInitiator: Bool, created: ContinuousClock.Instant) {
        sendKey = keys.send
        receiveKey = keys.receive
        self.localIndex = localIndex
        self.remoteIndex = remoteIndex
        self.isInitiator = isInitiator
        self.created = created
    }

    /// Whether this session can send. Sending is disabled when the counter is exhausted or at least `rejectAfterTime` has elapsed.
    func canSend(at now: ContinuousClock.Instant) -> Bool {
        sendNonce < Constants.rejectAfterMessages && now - created < Constants.rejectAfterTime
    }

    /// Whether this session can receive transport messages. It stops receiving after `rejectAfterTime`.
    func canReceive(at now: ContinuousClock.Instant) -> Bool {
        now - created <= Constants.rejectAfterTime
    }
}

/// The three keypair slots for a peer.
///
/// - `current`: The session used for sending.
/// - `previous`: The immediately preceding session. It stays available for packets that arrive late just after rekeying.
/// - `next`: The session the responder creates when it sends the response. When the first packet the initiator sends with this key
///   confirms that the initiator has the same key (key confirmation), the responder promotes it to `current`. Sending with this key waits until then.
///
/// Whitepaper §6.1, `docs/protocol-notes/wireguard.md` "Keypair rotation (previous/current/next)"
/// (origin: wireguard-go `device/noise-protocol.go` `BeginSymmetricSession`, `ReceivedWithKeypair`).
struct Keypairs {
    enum Slot: CaseIterable {
        case previous, current, next
    }

    private(set) var previous: Keypair?
    var current: Keypair?
    private(set) var next: Keypair?

    /// Installs a new session. Any displaced keypair is discarded here.
    mutating func install(_ keypair: Keypair) {
        if keypair.isInitiator {
            // The initiator needs no confirmation, so the session becomes current immediately. If an unconfirmed next exists,
            // keep it as previous in place of current because it may be the last key the peer used.
            previous = next ?? current
            next = nil
            current = keypair
        } else {
            next = keypair
            previous = nil
        }
    }

    /// Call when a packet received with `next` authenticates. If `next` matches, promotes it to current and returns `true`.
    mutating func confirm(_ slot: Slot) -> Bool {
        guard slot == .next, let next else { return false }
        previous = current
        current = next
        self.next = nil
        return true
    }

    /// Opens a transport message with the slot's keypair by checking expiration, decrypting, then recording it in the replay window. Only success changes the window.
    ///
    /// Works directly in the slot. Holding a copy of the keypair would copy the entire replay window (1KB) when updating it.
    ///
    /// - Throws: `unknownPeer` if the slot is empty, `noSession` after `rejectAfterTime`, `authenticationFailed` if authentication fails,
    ///   or `replayed` if the packet was already received or falls outside the window.
    mutating func open(_ message: TransportData, in slot: Slot, at now: ContinuousClock.Instant) throws(WireGuardError) -> [UInt8] {
        switch slot {
        case .previous: try Self.open(message, in: &previous, at: now)
        case .current: try Self.open(message, in: &current, at: now)
        case .next: try Self.open(message, in: &next, at: now)
        }
    }

    private static func open(_ message: TransportData, in keypair: inout Keypair?, at now: ContinuousClock.Instant) throws(WireGuardError) -> [UInt8] {
        guard let canReceive = keypair?.canReceive(at: now) else { throw .unknownPeer }
        guard canReceive else { throw .noSession }
        guard let plaintext = keypair?.open(message) else { throw .authenticationFailed }
        // Only authenticated counters advance the replay window.
        guard keypair?.replayFilter.accept(message.counter) == true else { throw .replayed }
        return plaintext
    }

    /// Finds the slot holding the keypair for localIndex.
    func slot(forLocalIndex index: UInt32) -> Slot? {
        // Scan all three slots in order without a set. This runs for every packet.
        if previous?.localIndex == index { return .previous }
        if current?.localIndex == index { return .current }
        if next?.localIndex == index { return .next }
        return nil
    }

    subscript(slot: Slot) -> Keypair? {
        get {
            switch slot {
            case .previous: previous
            case .current: current
            case .next: next
            }
        }
        set {
            switch slot {
            case .previous: previous = newValue
            case .current: current = newValue
            case .next: next = newValue
            }
        }
    }

    var localIndices: [UInt32] {
        Slot.allCases.compactMap { self[$0]?.localIndex }
    }
}
