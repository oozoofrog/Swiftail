import SwiftailBase

/// The complete state of a peer known to the device.
///
/// Removing this value discards the peer's key material. Transport keys are in CryptoKit `SymmetricKey`,
/// which clears their memory on deallocation. Swift does not guarantee clearing `[UInt8]` material such as the chaining key on deallocation.
///
/// `docs/protocol-notes/wireguard.md` "Procedure and state machine" (origin: wireguard-go `device/peer.go`).
struct Peer {
    let publicKey: PublicKey
    var allowedIPs: [IPPrefix]
    /// Precomputed DH (our static key, the peer's static key). A low-order point produces 0, yielding `nil` and preventing a handshake with the peer.
    let staticStaticSecret: [UInt8]?
    var cookieGenerator: CookieGenerator

    /// The initiation we sent that is awaiting a response.
    var pendingHandshake: PendingHandshake?
    var keypairs = Keypairs()
    /// IP packets intended for sending before the session is established. An empty array is a keepalive.
    var staged: [[UInt8]] = []
    /// The plaintext IP packet to send ahead of the queue whenever a session is established with this peer. If nil, sends nothing.
    var priorityMessage: [UInt8]?
    var timers = PeerTimers()

    /// The last accepted initiation timestamp. Retained after key material is erased to prevent replays of old initiations.
    var lastAcceptedTimestamp: TAI64N?
    var lastInitiationConsumed: ContinuousClock.Instant?
    /// The last time an initiation or response was sent. No new initiation is sent within `rekeyTimeout`.
    var lastSentHandshake: ContinuousClock.Instant?

    /// The indices this peer occupies in the device's index table.
    var localIndices: Set<UInt32> {
        var indices = Set(keypairs.localIndices)
        if let pendingHandshake { indices.insert(pendingHandshake.localIndex) }
        return indices
    }

    /// Holds `localIndices` in individual slots without a set. Used on each packet only to check whether the indices changed.
    struct IndexSlots: Equatable {
        var previous: UInt32?
        var current: UInt32?
        var next: UInt32?
        var pending: UInt32?

        /// The indices in occupied slots.
        var all: [UInt32] { [previous, current, next, pending].compactMap { $0 } }
    }

    /// The slots recorded in the device's index table. After the device updates the peer (`edit`), it synchronizes them with `indexSlots`.
    var tabledIndexSlots = IndexSlots()

    /// Synchronizes `tabledIndexSlots` with the current `indexSlots` and returns (previous, current).
    mutating func syncTabledIndexSlots() -> (before: IndexSlots, after: IndexSlots) {
        let before = tabledIndexSlots
        let after = indexSlots
        tabledIndexSlots = after
        return (before, after)
    }

    var indexSlots: IndexSlots {
        IndexSlots(
            previous: keypairs.previous?.localIndex,
            current: keypairs.current?.localIndex,
            next: keypairs.next?.localIndex,
            pending: pendingHandshake?.localIndex
        )
    }

    /// Whether the source address is within this peer's AllowedIPs.
    func allows(source: IPAddress) -> Bool {
        allowedIPs.contains { $0.contains(source) }
    }

    /// Adds a packet to the queue. Discards the oldest packet on overflow.
    mutating func stage(_ packet: [UInt8]) {
        staged.append(packet)
        if staged.count > Constants.maxStagedPackets {
            staged.removeFirst(staged.count - Constants.maxStagedPackets)
        }
    }

    /// Clears all keypairs, the in-progress handshake, and the queue (wireguard-go `ZeroAndFlushAll`).
    mutating func zeroKeyMaterial() {
        keypairs = Keypairs()
        pendingHandshake = nil
        staged = []
    }
}

/// Exposes only public information to keep key material (chaining key, static-static DH, cookie) out of
/// default reflection in `print`, `dump`, and the debugger.
extension Peer: CustomReflectable {
    var customMirror: Mirror {
        Mirror(self, children: ["publicKey": publicKey, "allowedIPs": allowedIPs], displayStyle: .struct)
    }
}
