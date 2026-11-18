import CryptoKit
import Foundation
import SwiftailBase

/// The complete WireGuard state of a node, including its own static key and its peers.
///
/// This state machine has no I/O, sockets, TUN, timers, or clock. The caller supplies received datagrams,
/// outgoing IP packets, and the current time. The machine updates its state and returns "datagrams to send over the network" and
/// "IP packets to deliver up the stack." Because this is a value type, its owner can call it serially.
///
/// The device does not handle addresses. The Tailscale fork of wireguard-go also lacks endpoint roaming.
/// Magicsock chooses the path to the peer, so the output is "bytes to send to this peer."
///
/// Pass a nondecreasing `now` across calls. The caller uses `nextDeadline` to decide when to call
/// `advance(to:)`. `send` and `receive` do not process expired timers first.
///
/// This file defines the public API and manages peers and the index table. Sending, receiving, and timer handling are in the corresponding
/// `WireGuardDevice+…` files. See the contract in `docs/contracts/SwiftailWireGuard.md`.
public struct WireGuardDevice: Sendable {
    /// Actions emitted by the state machine.
    public enum Output: Sendable, Equatable {
        /// A WireGuard message to send over the network. The caller chooses the path.
        case datagram([UInt8], to: PublicKey)
        /// An IP packet that passed decryption and the AllowedIPs check.
        case ipPacket([UInt8], from: PublicKey)
        /// An IP packet from the peer that was withheld from the upper layer. The reason is `malformed` or `disallowedSource`.
        /// There is nothing to send or deliver up the stack. The caller uses this for metrics or logging.
        case rejectedIPPacket(WireGuardError, from: PublicKey)
        /// A cookie reply (64 bytes) sent under load in response to a handshake message with an invalid mac2. Send it as is
        /// back to the source of the datagram just received. The peer is still unknown because the handshake has yet to be opened, so this bypasses peer path selection.
        case cookieReply([UInt8])
    }

    /// The source of a received datagram. The device treats it as opaque and uses it only to bind cookies and track rate limits.
    ///
    /// Distinct sources must have distinct `address` values, and sources on the same host must share the same `host`. For different source types (UDP,
    /// DERP), give both values distinct lengths so they cannot overlap across types.
    public struct Source: Hashable, Sendable {
        /// The value to which the cookie is bound. It identifies where the reply actually goes (address and port for UDP).
        public var address: [UInt8]
        /// The unit that shares a rate limit (IP address for UDP).
        public var host: [UInt8]

        public init(address: [UInt8], host: [UInt8]) {
            self.address = address
            self.host = host
        }
    }

    /// This device's static public key.
    public let publicKey: PublicKey
    let staticKey: Curve25519.KeyAgreement.PrivateKey
    /// The key used to check mac1 on received handshake messages. It is derived from the device's public key.
    let mac1Key: [UInt8]
    /// Checks mac2 and creates cookie replies under load. Holds the secret.
    var cookieChecker: CookieChecker
    var handshakeLoad = HandshakeLoad()
    var rateLimiter = RateLimiter()
    /// Time elapsed since the Unix epoch as of `monotonicOrigin`, used to calculate TAI64N.
    private let monotonicOrigin: ContinuousClock.Instant
    private let wallClockOrigin: Duration

    var peers: [PublicKey: Peer] = [:]
    /// The last accepted initiation timestamp for each removed peer (in removal order). Restore it if a peer with the same key returns.
    /// Discarding it would let an initiation accepted before removal be replayed to the new peer. When full, forget the oldest removals first.
    var retiredTimestamps: [(peer: PublicKey, timestamp: TAI64N)] = []
    /// Maps each index we assigned to the peer that holds it. Includes both active handshake and keypair indices.
    var indexTable: [UInt32: PublicKey] = [:]

    /// - Parameters:
    ///   - privateKey: This node's static private key.
    ///   - now: The current monotonic time.
    ///   - wallClock: The wall-clock time at `now`. Later TAI64N timestamps
    ///     increase monotonically because they are calculated as wallClock + (call time − now). Times before 1970 are treated as 1970.
    public init(privateKey: Curve25519.KeyAgreement.PrivateKey, now: ContinuousClock.Instant, wallClock: Date) {
        staticKey = privateKey
        publicKey = PublicKey(privateKey.publicKey)
        mac1Key = MAC.mac1Key(for: publicKey)
        cookieChecker = CookieChecker(publicKey: publicKey)
        monotonicOrigin = now
        wallClockOrigin = .seconds(wallClock.timeIntervalSince1970)
    }

    /// Registers a peer. For an existing peer, updates only AllowedIPs and preserves the session.
    public mutating func addPeer(_ peer: PublicKey, allowedIPs: [IPPrefix]) {
        if peers[peer] != nil {
            peers[peer]?.allowedIPs = allowedIPs
            return
        }
        var added = Peer(
            publicKey: peer,
            allowedIPs: allowedIPs,
            staticStaticSecret: sharedSecret(staticKey, peer.rawValue),
            cookieGenerator: CookieGenerator(peer: peer)
        )
        if let index = retiredTimestamps.firstIndex(where: { $0.peer == peer }) {
            added.lastAcceptedTimestamp = retiredTimestamps.remove(at: index).timestamp
        }
        peers[peer] = added
    }

    /// Sets the plaintext IP packet to send first through the tunnel whenever new session keys are established with this peer. Pass nil to clear it.
    ///
    /// This matches the priority message in the Tailscale fork of wireguard-go (`device/send.go` `SendPriorityMessage`,
    /// `device/receive.go`). The initiator sends it once on the new session when the response establishes that session. The responder does so
    /// when it receives the first transport message on the new session. It goes ahead of queued packets and keepalives and counts as data. Sending it
    /// does not initiate a handshake. Tailscale uses it to announce its own disco key (a TSMP disco key advertisement).
    ///
    /// - Throws: `unknownPeer` if the peer is unregistered, `malformed` if the packet is empty, or `packetTooLarge` if it exceeds 512 bytes.
    public mutating func setPriorityMessage(_ message: [UInt8]?, for peer: PublicKey) throws(WireGuardError) {
        if let message {
            guard !message.isEmpty else { throw .malformed }
            guard message.count <= Constants.maxPriorityMessageSize else { throw .packetTooLarge }
        }
        guard peers[peer] != nil else { throw .unknownPeer }
        peers[peer]?.priorityMessage = message
    }

    /// Removes the peer and its key material. Subsequent messages using that peer's indices return `unknownPeer`.
    ///
    /// Retains only the last accepted initiation timestamp (up to `maxRetiredTimestamps` entries). A peer registered again with the same key
    /// rejects replays of old initiations. When the table fills, it forgets the earliest removal. The timestamp does
    /// not determine the eviction order because the peer controls that value and peers with far-future timestamps could occupy the table indefinitely.
    public mutating func removePeer(_ peer: PublicKey) {
        guard let removed = peers.removeValue(forKey: peer) else { return }
        for index in removed.localIndices {
            indexTable[index] = nil
        }
        guard let timestamp = removed.lastAcceptedTimestamp else { return }
        retiredTimestamps.append((peer, timestamp))
        if retiredTimestamps.count > Constants.maxRetiredTimestamps {
            retiredTimestamps.removeFirst()
        }
    }

    /// The next time to call `advance(to:)`, or `nil` if no timer is armed.
    public var nextDeadline: ContinuousClock.Instant? {
        earliestTimer()?.deadline
    }

    /// The earliest timer across all peers. Scans once without creating an array.
    // shortcut: Scans all peers (about 1.4µs for 64 peers). Cache the earliest deadline if the peer count reaches hundreds and the scan is confirmed to be a bottleneck.
    func earliestTimer() -> (owner: PublicKey, kind: PeerTimers.Kind, deadline: ContinuousClock.Instant)? {
        var result: (owner: PublicKey, kind: PeerTimers.Kind, deadline: ContinuousClock.Instant)?
        // Read only the timer fields by position to avoid extracting and copying the entire peer.
        for position in peers.indices {
            guard let timer = peers.values[position].timers.earliest else { continue }
            if let best = result, best.deadline <= timer.deadline { continue }
            result = (peers.keys[position], timer.kind, timer.deadline)
        }
        return result
    }

    // MARK: - Peer updates

    /// Updates a peer in place in the table.
    ///
    /// Temporarily moves the table (`peers`) from the device into a local variable and passes the peer in it to `body` as `inout`. This avoids
    /// hashing to remove and reinsert the peer and avoids copying the peer. The device's `peers` table is empty while it is detached, so `body`
    /// must not look up other peers (the index table and the device's own key remain readable).
    ///
    /// **Leaves state unchanged on failure.** All checks that can throw happen before the peer is modified. If `body` throws, the peer
    /// stays in the table unchanged.
    ///
    /// Afterward, checks whether the peer's keypair or handshake indices changed and updates the index table to match.
    ///
    /// - Returns: The result of `body`, or `nil` if the peer does not exist.
    mutating func edit<Result, Failure: Error>(
        _ key: PublicKey,
        _ body: (inout WireGuardDevice, inout Peer) throws(Failure) -> Result
    ) throws(Failure) -> Result? {
        var table: [PublicKey: Peer] = [:]
        swap(&table, &peers)
        guard let position = table.index(forKey: key) else {
            swap(&table, &peers)
            return nil
        }
        defer {
            let (before, after) = table.values[position].syncTabledIndexSlots()
            if before != after {
                for index in before.all where !after.all.contains(index) {
                    indexTable[index] = nil
                }
                for index in after.all {
                    indexTable[index] = key
                }
            }
            swap(&table, &peers)
        }
        return try body(&self, &table.values[position])
    }

    /// Draws a new index absent from both the table and this peer. 0 is valid.
    func freshIndex(avoiding peer: Peer) -> UInt32 {
        let taken = peer.localIndices
        while true {
            let index = UInt32.random(in: .min ... .max)
            if indexTable[index] == nil, !taken.contains(index) {
                return index
            }
        }
    }

    /// The TAI64N timestamp at now.
    func timestamp(at now: ContinuousClock.Instant) -> TAI64N {
        TAI64N(sinceUnixEpoch: wallClockOrigin + (now - monotonicOrigin))
    }
}

extension WireGuardDevice: CustomReflectable {
    /// Shows only the public key and peers to keep the static private key, cookie secret, and source addresses in the rate limit table out of `print`, `dump`, and debugger output
    /// (peers also expose only public information).
    public var customMirror: Mirror {
        Mirror(self, children: ["publicKey": publicKey, "peers": Array(peers.values)], displayStyle: .struct)
    }
}
