# SwiftailWireGuard contract (M1)

The WireGuard data plane is an **I/O-free state machine**. It has no sockets, TUN, timers, or clock. The caller supplies incoming datagrams, outgoing IP packets, and the current time. The state machine updates its state and returns "datagrams to send over the network" and "IP packets to pass up."

Protocol details follow [protocol-notes/wireguard.md](../protocol-notes/wireguard.md) (cross-verified). This document defines the module boundaries and scope.

## Why this structure?

- The Tailscale fork of wireguard-go has no endpoint roaming. Magicsock chooses the peer's actual path (direct UDP or DERP). The module therefore needs no addresses. It outputs "bytes to send to this peer."
- Taking time as an argument makes timer behavior such as rekey (120 seconds) and key disposal (180 seconds) deterministic to test without waiting for real time.
- The value type avoids concurrency issues. Its owner (the future engine actor) calls it serially.

## Targets

| Target | Dependencies | Contents |
| --- | --- | --- |
| `SwiftailBase` | Foundation, Network | `IPAddress`, `IPPrefix`, hexadecimal conversion |
| `SwiftailWireGuard` | `SwiftailBase`, `SwiftailCrypto`, CryptoKit | API below |

## Public API

### SwiftailBase

```swift
/// An IPv4 or IPv6 address. The Network framework's address types parse strings.
public struct IPAddress: Hashable, Sendable, LosslessStringConvertible {
    public init?(_ description: String)            // "100.64.0.1", "fd7a:115c:a1e0::1"
    public init?(bytes: some Collection<UInt8>)    // 4 or 16 bytes
    public var bytes: [UInt8] { get }
    public var isIPv4: Bool { get }
}

/// A CIDR prefix. Host bits are cleared on storage.
public struct IPPrefix: Hashable, Sendable, LosslessStringConvertible {
    public init?(_ description: String)            // "100.64.0.1/32"
    public init?(address: IPAddress, length: Int)
    public var address: IPAddress { get }
    public var length: Int { get }
    public func contains(_ address: IPAddress) -> Bool
}

extension Array where Element == UInt8 {
    public init?(hex: String)        // nil for odd lengths or nonhexadecimal input
    public var hex: String { get }   // lowercase
}
```

### SwiftailWireGuard

```swift
/// A 32-byte Curve25519 public key. It identifies a peer.
public struct PublicKey: Hashable, Sendable, CustomStringConvertible {
    public init?(rawValue: some Collection<UInt8>)   // nil unless 32 bytes
    public let rawValue: [UInt8]
    public var description: String { get }           // For logging. First 8 hexadecimal digits + "…"
}

public enum WireGuardError: Error, Sendable, Equatable {
    case malformed              // Length, type, or reserved bytes do not match the specification
    case unknownPeer            // Unregistered peer or unknown receiver index
    case authenticationFailed   // mac1 or AEAD tag mismatch
    case replayed               // Handshake timestamp or flood check, response already processed, or reused transport counter
    case noSession              // No usable keypair (including expiration)
    case disallowedSource       // Decrypted IP packet source is outside the peer's AllowedIPs (reported only through rejectedIPPacket)
    case packetTooLarge
    case rateLimited            // mac2 passed under load, but the source host exceeded its allowance (20 per second, burst of 5)
}

/// All WireGuard state for a node, including its static key and peers.
public struct WireGuardDevice: Sendable {
    public enum Output: Sendable, Equatable {
        /// A WireGuard message to send over the network. The caller chooses the path.
        case datagram([UInt8], to: PublicKey)
        /// An IP packet that passed decryption and the AllowedIPs check.
        case ipPacket([UInt8], from: PublicKey)
        /// An IP packet sent by the peer and withheld from delivery. The reason is malformed or disallowedSource.
        case rejectedIPPacket(WireGuardError, from: PublicKey)
        /// A cookie reply (64 bytes) for a handshake message whose mac2 fails under load.
        /// Send it back to the source of the datagram just received, over the same path, bypassing peer path selection.
        case cookieReply([UInt8])
    }

    /// The source of an incoming datagram. The device treats its contents as opaque.
    public struct Source: Hashable, Sendable {
        public var address: [UInt8]   // Value the cookie binds to (address ‖ port for UDP)
        public var host: [UInt8]      // Rate limiting unit (address for UDP)
        public init(address: [UInt8], host: [UInt8])
    }

    /// Creates a device with wallClock as the wall-clock time at now. Later TAI64N timestamps
    /// increase monotonically because they are computed as wallClock + (call time − now).
    public init(privateKey: Curve25519.KeyAgreement.PrivateKey, now: ContinuousClock.Instant, wallClock: Date)

    public var publicKey: PublicKey { get }

    /// Registers a peer. For an existing peer, updates only its AllowedIPs and keeps its session.
    public mutating func addPeer(_ peer: PublicKey, allowedIPs: [IPPrefix])
    /// Removes a peer and its key material. The device retains only the last accepted initiation timestamp (see "Included" below).
    public mutating func removePeer(_ peer: PublicKey)
    /// Sets the plaintext IP packet sent first through the tunnel each time session keys are established with this peer (added 2026-11-16, the Tailscale fork's priority
    /// message). nil clears it. An empty packet throws `malformed`, more than 512 bytes throws `packetTooLarge`, and an unknown peer throws `unknownPeer`.
    public mutating func setPriorityMessage(_ message: [UInt8]?, for peer: PublicKey) throws(WireGuardError)

    /// Sends one IP packet to a peer. If there is no session, queues it and starts a handshake.
    public mutating func send(_ ipPacket: [UInt8], to peer: PublicKey, at now: ContinuousClock.Instant) throws(WireGuardError) -> [Output]

    /// Processes one datagram received from the network.
    /// Throwing leaves state unchanged, with documented exceptions for bookkeeping used to detect load.
    public mutating func receive(_ datagram: [UInt8], from source: Source, at now: ContinuousClock.Instant) throws(WireGuardError) -> [Output]

    /// Processes all timers due by now.
    public mutating func advance(to now: ContinuousClock.Instant) -> [Output]

    /// The next time to call advance, or nil when no timers are pending.
    public var nextDeadline: ContinuousClock.Instant? { get }
}
```

If `send` or `receive` throws, peer state stays unchanged. Peers are edited in place in the table (`edit`), so operation order preserves this property. All throwing checks (mac, AEAD, timestamp and replay window, expiration, and size) finish before the peer is edited. The replay window changes only when an authenticated counter is accepted. `Tests/SwiftailWireGuardTests/FailureAtomicityTests.swift` checks each rejected input to confirm the session, counters, replay window, timers, and entire index table remain unchanged. Attack bookkeeping is the exception and includes the count of messages that pass mac1 for load detection and the rate limiting table (the flood check's reference time changes only when an initiation is accepted). Transport that passes AEAD and replay checks does not produce an error even if the contained IP packet is malformed or its source is outside AllowedIPs. It came from an authenticated peer, so next confirmation, queue draining, rekey, and timer updates proceed as for a normal receive, matching wireguard-go. A discarded packet is reported as `rejectedIPPacket`.

Treat a `wallClock` earlier than 1970 as 1970.

Handshake steps are pure functions that take the ephemeral key and index as arguments. Only the device layer draws system randomness (for the index, ephemeral key, and retry jitter).

The device has no MTU information. The send size limit is the wireguard-go default (65535 − 40), and the TUN MTU enforces the actual size limit.

`now` must be nondecreasing across calls. Callers must not assume that `send` or `receive` processes expired timers first internally. Call `advance` at `nextDeadline`.

## M1 scope

Included (everything marked "Required" in the notes):

- Serialization and parsing of all 4 message types, and mac1 generation and verification.
- Noise IKpsk2 initiator and responder. The PSK is fixed at 32 zero bytes, with the KDF3 step intact.
- TAI64N generation, per-peer timestamp replay checks, and initiation flood checks (20ms).
- Last timestamp of a removed peer. `removePeer` retains it on the device (up to 1,024 entries, forgetting the earliest removals first after reaching the limit. The peer chooses the timestamp, so timestamps do not determine eviction order). `addPeer` restores it for the same key. If a peer drops out of the netmap and returns, previously received initiations are still `replayed` (2026-11-17 security verification). wireguard-go discards this value when it deletes a peer. The table is limited to 1,024 entries. When that many more peers leave timestamps and are removed, the timestamp of a peer removed before them is forgotten. When a forgotten peer returns, replays of previously received initiations work again.
- Transport encryption and decryption, counters, padding (multiples of 16), keepalive, and the replay window (8128).
- Keypair transitions among previous, current, and next. The responder promotes next to current only after the first packet using the new key passes AEAD and replay checks.
- Timers and key rotation use the values in the notes' "Constants and timers" table. Each retry creates a new initiation.
- Send queue before session establishment. Up to 64 entries per peer, dropping the oldest on overflow.
- Receiving cookie replies and adding mac2 to subsequent initiations (needed to recover when the remote peer is under load).
- Sending cookie replies (load detection, mac2 checks, per-source rate limiting). Added 2026-11-15. See "Sending cookie replies" below.
- Priority message (2026-11-16, Tailscale fork wireguard-go `SendPriorityMessage`). The initiator sends it once using current when the response establishes the session, ahead of keepalive and the queue. The responder sends it once using current when the first transport on the new session confirms next, ahead of the queue. With no session to send on, it stops without starting a handshake. It counts as a data send (new handshake timer). It is sent again when rekey establishes a new session. Test `Tests/SwiftailWireGuardTests/PriorityMessageTests.swift`.

Excluded (limitations are documented in `shortcut:` comments):

- PSK configuration and persistent keepalive.
- Full reuse of send and receive buffers. Each packet creates a new output array (one array with header, ciphertext, and tag for sending, one plaintext array for receiving) and copies once from the `SealedBox` or `Data` returned by CryptoKit (CryptoKit has no API to write directly to a caller's buffer). `nextDeadline` and `advance` scan all peers (about 1.4µs for 64 peers). Revisit when M5 throughput and memory measurements on a real device identify these copies or the peer count as a bottleneck. Unnecessary copies were removed (2026-11-15). `store` used to copy the whole peer for each packet and now edits it in place in the table. Intermediate message, timer, and nonce arrays were reduced (1,280-byte packets, release build, two in-memory devices, seal 5.1→3.0µs, open 5.5→3.5µs).

## Sending cookie replies (2026-11-15)

The node public key is public, so anyone can create an initiation with a valid mac1, and the receiver computes X25519 each time. Under load, the receiver therefore requires mac2, responds with a cookie reply, and rate-limits each source host (whitepaper §5.3, notes "mac1, mac2, and cookies"). This device also runs inside an iOS extension.

1. **Order** (wireguard-go `device/receive.go`). Check mac1 on initiation and response (a mismatch returns `authenticationFailed` and does not count toward load) → count the message toward load detection → under load, check mac2 and output `.cookieReply` on mismatch without processing the message (before X25519) → if mac2 is valid, return `rateLimited` when the source `host` exceeds its rate limit → proceed as usual. Outside load, ignore mac2.
2. **Load detection** (`HandshakeLoad`). Go checks whether the handshake queue length has reached a threshold (default 1024/8 = 128, or 8 for the Tailscale iOS queue of 64) (`device/device.go` `IsUnderLoad`, `wgengine/wgcfg/mem_ios.go`). This device has no queue and handles messages on receipt, so it detects load when **128 handshake messages pass mac1 within an interval shorter than 1 second**. As in Go, load lasts for 1 second (`UnderLoadAfterTime`) after detection and ends exactly at that time. It is fixed.
   - Rationale. On this development machine (Apple Silicon Mac, release), the responder takes about 211µs to process an initiation and about 20µs to produce a cookie reply (average of 400). The threshold of 128/second caps the X25519 path at about 2.7% of one core (about 4% even assuming an iPhone is 1.5 times slower). Go's queue threshold indicates a processing backlog and has no direct conversion to a per-second rate. A backlog of 128 requires input faster than the processing rate (about 4,700 per second on this machine), so this triggers sooner than Go on desktop and later than Go on iOS (a backlog of 8, or about 2ms of work).
   - Normal tailnet. A peer sends handshake messages at most once per `RekeyTimeout` (5 seconds). Even if the network changes or the device wakes and every active peer handshakes again at once, there are at most 2 messages per peer in 1 second (the peer's initiation and its response to ours). This does not trigger the threshold with up to 64 active peers (128 if only one side initiates). Even on a false trigger, the peer gets a cookie and passes mac2 on retry 5 seconds later (it is only delayed, with no disconnect).
3. **Cookie and secret** (`CookieChecker`, wireguard-go `device/cookie.go`). cookie = MAC(32-byte secret, `source.address`), mac2 = MAC(cookie, bytes preceding mac2). The first reply draws the secret from system randomness. The next reply after 120 seconds (`CookieRefreshTime`) have elapsed since creation replaces it. mac2 always fails if the secret is absent or more than 120 seconds old. reply = type 3 ‖ receiver (sender of the rejected message) ‖ nonce 24 (system randomness) ‖ XChaCha20-Poly1305 (key HASH("cookie--" ‖ own public key), plaintext cookie, AAD mac1 of the rejected message), 64 bytes. The secret, cookie, and source are absent from `description`, `dump`, and errors (`WireGuardDevice`'s `customMirror` exposes only the public key and peers).
4. **Per-source rate limiting** (`RateLimiter`, wireguard-go `ratelimiter/ratelimiter.go`). Each `source.host` gets 20 per second, burst of 5 (`packetCost` 50ms, `maxTokens` 250ms). A new host's first message is accepted, leaving `maxTokens − packetCost` tokens. An existing host refills based on elapsed time up to the cap and is accepted only when its tokens exceed `packetCost`.
   - **Table cap of 4096 entries**. Go has no cap and removes entries idle for more than 1 second once a second. Here, entries idle for more than 1 second are removed only when the table fills. If it is still full, new hosts are rejected (fail closed). Later cleanup gives the same result because entries idle for more than 1 second have a full token balance and behave like new entries. Only hosts that received a cookie at that source and provided a valid mac2 enter the table, so spoofed addresses cannot fill it. A cap of 4096 (roughly 400KB assuming about 100 bytes per entry, unmeasured) is ample for simultaneous rehandshakes in a large tailnet. Failing open by evicting old entries would allow an attacker with many real addresses to erase the allowance of hosts already in the table. Growing the table would make memory grow with input. While the cap is reached, new hosts cannot handshake until an entry goes idle within 1 second.
   - Lead session decision (2026-11-15). Keep the threshold of 128 per 1 second, the cap of 4096, and fail-closed behavior. Bind UDP sources to the actual address and port instead of grouping by peer as Go does (matching the intent of the WireGuard specification. The same peer's UDP and DERP cookies do not match, which can add a round trip). Processing time and table memory on an actual iPhone were unmeasured.
5. **Source**. The node constructs it from the incoming path (engine contract N5 "cookie reply"). The device treats `address` and `host` as opaque.

Tests (`Tests/SwiftailWireGuardTests/CookieReplyTests.swift`, `RateLimiterTests.swift`, interop test `cookieReplyUnderLoad`) cover the threshold and window boundaries, 1-second hold, skipping invalid mac1 in the count, reaching the threshold with actual input, reply format and round trip with the Swift consumer, replies before X25519 even for bodies that cannot be opened or unknown peers, rejection of mac2 from another source or a cookie from an old secret, secret rotation interval, requiring mac2 for responses too, device rate limit boundaries, the Go `TestRatelimiter` schedule, the table cap and cleanup, arbitrary input under load, and `dump`. In the interop test, wireguard-go initiates while Swift is under load. Go receives the cookie reply and completes the handshake by retrying with mac2 (the test sets `underLoadUntil` to simulate load).

## Tests

Unit tests (`Tests/SwiftailWireGuardTests`, no waiting for real time):

1. Connect two Swift devices in memory to test the handshake in both roles, bidirectional data, keepalive, and queue draining.
2. Inject time to test initiator rekey after 120 seconds, responder rekey, rejection of keys older than 180 seconds, handshake retries (5 seconds + jitter) and abandonment, and removal of key material after 540 seconds.
3. Port replay window cases from wireguard-go `replay/replay_test.go` (origin and MIT license in the file header).
4. Test loss and tampering, including recovery after a lost response, an old response failing to overwrite a new handshake, tampered messages leaving state intact, and rejection of a source outside AllowedIPs.
5. Consuming a cookie reply adds mac2. The cookie is no longer used after 120 seconds. See "Sending cookie replies" above for sender tests.
6. No byte sequence passed to `receive` crashes the process (random and boundary inputs of length 0–200).

Interop test gate (`Tests/SwiftailWireGuardInteropTests`, against the wireguard-go peer in `Tools/interop`, over UDP loopback):

1. Swift initiator → Go responder, Go initiator → Swift responder.
2. Bidirectional IP packet exchange (multiple sizes, including padding).
3. After more than 120 seconds of real time, exchange continues after rekey (with Swift as initiator and as responder).
4. Go drops tampered and replayed datagrams and keeps the session.
