# SwiftailDERP Contract (M3)

Represents a connection to one DERP relay server. An **I/O-free value-type state machine** (`DERPConnection`) handles frame parsing and the handshake. The actor wrapping it (`DERPClient`) owns the TLS socket, clock, and reconnection.

Protocol details follow the verified [protocol-notes/derp-stun.md](../protocol-notes/derp-stun.md). This document defines only the module boundaries and the M3 scope.

## Targets

| Target | Dependencies | Contents |
| --- | --- | --- |
| `SwiftailBase` | Foundation, Network | Existing contents + **key types** (`PrefixedKey` and its aliases, moved from `SwiftailControl/Keys.swift`) |
| `SwiftailIO` (new target, not exported as a product) | Foundation, Network, Synchronization | Shared components for I/O at the edge. Declarations use `package` access |
| `SwiftailDERP` | `SwiftailBase`, `SwiftailCrypto`, `SwiftailIO`, CryptoKit | API below |

`SwiftailDERP` has no dependency on `SwiftailControl`. The engine extracts connection information from DERPMap (tailcfg) and passes it in.

## Unit 0 — Shared Components

Before implementation, move the following so that M2's `ControlClient` and M3's `DERPClient` do not each carry a copy. Preserve behavior (the existing tests and M2 gate must still pass).

1. `Sources/SwiftailControl/Keys.swift` → `Sources/SwiftailBase/Keys.swift`. Keep public names. Move the tests to `SwiftailBaseTests` too. Also move `PrefixedKey.init(_: Curve25519.KeyAgreement.PublicKey)` (currently internal in `NodeIdentity.swift`) and make it `public`.
2. Place the following in the new `SwiftailIO` target with `package` access.
   - `NetworkSocket` wraps one NWConnection as an async byte stream (currently `SwiftailControl/Client/NetworkSocket.swift`). It reports errors using its own `SocketError` type (connection and read failures. Writes do not wait, so their failures surface on the next read). The caller translates errors to `ControlError`. There are three TLS modes, no TLS, system verification with a server name, and skipped verification for tests with a server name. `write` waits until the network stack accepts the bytes (`send` does not wait), and discarding the socket closes the connection.
   - `withTimeout` (currently `Client/Timeout.swift`).
   - `Backoff.delay(failures:maximum:jitter:)` uses `min(n² × 10ms, maximum) × (0.5 + jitter)` with random `jitter` in [0, 1). Control (30 seconds) and DERP (5 seconds) use the same formula with different caps (Go also shares one `util/backoff` implementation). `RetryPolicy`'s `Retry-After` parsing stays on the control side.
   - `HTTPResponseHead` reads an HTTP/1.1 response head from fragmented input and returns the status code, headers, and bytes already received after the head (16KiB limit, rejection of control characters within a line, and buffer clearing on failure). `UpgradeResponseParser` becomes a thin layer that uses it and only checks the `Upgrade` value. The public API and error cases stay the same.
3. Add placeholders for the M3 targets in `Package.swift`. The targets are `SwiftailIO`, `SwiftailDERP`, `SwiftailEngine`, and `Swiftail`, and the test targets are `SwiftailIOTests`, `SwiftailDERPTests`, `SwiftailDERPInteropTests`, `SwiftailEngineTests`, and `SwiftailInteropTests`. This lets later units work in parallel without touching `Package.swift`.

## Public API

```swift
/// How to reach one DERP server. The engine extracts this from `tailcfg.DERPNode`.
public struct DERPServer: Sendable, Equatable {
    /// The TLS server name and HTTP `Host`.
    public var hostName: String
    /// Connection targets. `DERPClient` dials them all concurrently, uses the first connection established, and closes the rest. An empty list cannot connect.
    public var targets: [Target]
    public var port: UInt16
    public var verification: Verification

    public enum Target: Sendable, Equatable {
        /// Resolves `hostName` through DNS and dials it. The Network framework chooses which resolved address to dial.
        case hostName
        /// Dials this IP address.
        case address(IPAddress)
    }

    public enum Verification: Sendable, Equatable {
        /// Verifies `hostName` using the system trust store.
        case system
        /// Skips verification. Use only for nodes marked `InsecureForTests` in DERPMap.
        case noneForTests
    }
    public init(hostName: String, targets: [Target] = [.hostName], port: UInt16 = 443, verification: Verification = .system)
}

public enum DERPError: Error, Sendable, Equatable {
    case malformed                    // Frame, response head, or JSON differs from the specification
    case upgradeRejected(status: Int) // Status other than 101
    case handshakeFailed              // ServerKey verification failed or ServerInfo could not be opened
    case frameTooLarge                // Received frame body exceeds the limit
    case tooManyPendingReplies        // Too many Pings awaiting replies
    case packetTooLarge               // Outbound packet exceeds 65,536 bytes
    case notReady                     // send called before the handshake completed
    case closed                       // Call after failure
}

/// State machine for one DERP connection. It has no socket, clock, or randomness.
///
/// Immediately after creation, `takeOutboundBytes()` returns the HTTP upgrade request. Feed bytes from the server to `receive`
/// to progress through the 101 response → ServerKey → (send ClientInfo and NotePreferred) → ready.
public struct DERPConnection: Sendable {
    public enum Event: Sendable, Equatable {
        /// The handshake is complete. `send` can now be called.
        case ready
        /// A packet the peer sent through this server. The contents (WireGuard or disco) are not inspected.
        case packet([UInt8], from: NodePublicKey)
        /// The server no longer knows the peer.
        case peerGone(NodePublicKey, reason: PeerGoneReason)
    }
    public enum PeerGoneReason: Sendable, Equatable { case disconnected, notHere, unknown(UInt8) }

    /// - Parameters:
    ///   - privateKey: This node's private node key (the same as its WireGuard key).
    ///   - host: The HTTP `Host` value.
    ///   - isPreferred: True if this server is in the home region. Sends NotePreferred at the end of the handshake.
    ///   - clientInfoNonce: 24 random bytes to seal ClientInfo. The caller generates them with system randomness.
    public init(privateKey: Curve25519.KeyAgreement.PrivateKey, host: String, isPreferred: Bool, clientInfoNonce: [UInt8]) throws(DERPError)

    /// Feeds bytes from the server. Byte boundaries are independent of frame boundaries.
    public mutating func receive(_ bytes: [UInt8]) throws(DERPError) -> [Event]
    /// Sends one packet to the peer (one SendPacket frame).
    public mutating func send(_ packet: [UInt8], to peer: NodePublicKey) throws(DERPError)
    /// Takes the bytes to send to the server, or an empty array if none are available. Call after `init`, `receive`, and `send`.
    public mutating func takeOutboundBytes() -> [UInt8]
}

/// Maintains a connection to one DERP server. Backs off and reconnects after disconnection.
public actor DERPClient {
    public enum Event: Sendable {
        case connected
        case disconnected
        /// One failed attempt to open a connection. `consecutiveFailures` counts consecutive failures since the last successful connection, starting at 1.
        case attemptFailed(AttemptFailure, consecutiveFailures: Int)
        case packet([UInt8], from: NodePublicKey)
        case peerGone(NodePublicKey)
    }

    /// The category of a connection attempt failure. Contains no addresses, keys, or names.
    public enum AttemptFailure: Sendable, Equatable {
        case timedOut          // More than 10 seconds elapsed from the start of dialing to ready
        case connectionFailed  // TCP or TLS connection failed (refusal, no route, name resolution, and certificate failures are indistinguishable)
        case handshakeFailed   // Rejection, protocol violation, or disconnection during upgrade or handshake
        case noServers         // No targets to dial
    }

    /// - Parameters:
    ///   - servers: Servers in one region. Tries them in order.
    ///   - interface: The outbound interface. Nil leaves the connection unbound. To change it, close the client and create another.
    public init(servers: [DERPServer], privateKey: Curve25519.KeyAgreement.PrivateKey, isPreferred: Bool, interface: NWInterface? = nil)

    /// The event stream has one subscriber and ends when `run()` ends.
    public nonisolated var events: AsyncStream<Event> { get }

    /// Connects, reads, and reconnects after disconnection. Returns only when the calling Task is canceled.
    public func run() async

    /// Sends a packet. If disconnected, queues it until the next connection. Returns without waiting.
    public func send(_ packet: [UInt8], to peer: NodePublicKey)
}
```

## Behavior

`DERPConnection` follows the notes, chapter 3 and §4.2~§4.5.

1. Send an upgrade request with `GET /derp`, `Host`, `Connection: Upgrade`, and `Upgrade: DERP`. Omit `User-Agent`, `Ideal-Node`, and fast-start.
2. For the response, check only that the status is 101 (as in Go). **Pass bytes already received after the head to frame parsing** because the server writes ServerKey along with the 101.
3. ServerKey requires type `0x01`, a body of at least 40 bytes and at most 1,024 bytes, and matching magic. A violation yields `handshakeFailed`.
4. For ClientInfo, seal `{"version":2,"CanAckPings":true}` using NaCl box (`NaClBox` and `NaClSecretBox` from `SwiftailCrypto`). If `isPreferred`, append NotePreferred (`0x01`) immediately. This is the `ready` point.
5. After readiness, RecvPacket → `packet` (discard bodies under 32 bytes), PeerGone → `peerGone`, and Ping → add a Pong with the same 8 bytes to outbound bytes. Open ServerInfo (`handshakeFailed` if it cannot be opened, and the rate limit values are unused). Skip the body of KeepAlive, Health, Restarting, PeerPresent, Pong, and unknown types.
6. Limits for untrusted input are a 16KiB response head, a 1MiB frame body (Go's value), and 64KiB of pending Pong bytes (exceeding this yields `tooManyPendingReplies`, and `takeOutboundBytes()` drains them). Exceeding a limit or failing discards buffered bytes and makes later calls return `closed`. No byte sequence can crash the process.
7. Hide children with `CustomReflectable` because the connection holds private and shared keys.

`DERPClient` follows the notes, §4.1 and §4.4~§4.6.

1. **Connection.** When `interface` is set, send the connection only through that interface (M5, `SwiftailTunnel` contract behavior N. Loopback servers are unbound). Try servers in order over TCP (1.5 seconds per server) and establish TLS with the first one reached. `shortcut:` The socket wrapper establishes TCP and TLS together, so for all but the last server, first check reachability over plain TCP, then reconnect over TLS to the target that connected first. For the last server, establish TCP and TLS together for each target and use the first to finish. A TLS failure fails the attempt without moving to the next server. The attempt fails if more than 10 seconds elapse from dialing to `ready`.
   - **Concurrent target dialing** (Go `dialNode`). Dial all `targets` for one server concurrently and use the first connection established. Close the losing connections, including any established before cancellation reaches them. If all fail, the first failure received is the server's failure. Each connection is a child of the TaskGroup, so cancellation closes all connections being opened. Loopback targets (`127.0.0.0/8`, `::1`) are unbound.
   - **Dial targets** (engine conversion of `DERPNode`, Go `shouldDialProto`). For each of the `IPv4` and `IPv6` fields, use `hostName` if empty, use the address if it is an IP literal of that field's family, and skip dialing that family for all other values (conventionally `"none"`, an address of another family, or garbage). If both fields yield `hostName`, use one `hostName` target (the Network framework resolves it and tries both families itself). Skip the node if it has no targets. Order targets by the IPv4 field, then the IPv6 field.
   - **Failure notification.** Emit `attemptFailed` for each failed attempt to open a connection, excluding cancellation. The node logs only the region number and failure category on the first consecutive failure and every 10th one thereafter.
2. **Reading.** Keep reading the socket while the connection is alive (the server has a 2-second write deadline). Disconnect if nothing arrives for 120 seconds. If consumption of `events` is slow, retain at most the newest 256 `attemptFailed`, `packet`, and `peerGone` events and 1MiB of packet bytes in total, discarding the oldest first. Packets are datagrams and may be dropped. The byte limit is for M5 extension memory. With just a count limit, a Go server's 64KiB packet limit permits 16MiB to accumulate, and a server sending full 1MiB frame bodies could reach 256MiB. Keep `connected` and `disconnected` events, retaining only the newest unread one.
3. **Writing.** Keep up to 32 outbound packets regardless of connection state and discard the oldest when full (as in Go's per-region write queue). Write the accumulated Pongs and packets at the front of the queue as one batch (one byte sequence of concatenated frames), and wait for the socket to accept it before taking the next batch. Packets that accumulate while the socket accepts the preceding batch then go out together in the next batch. A batch contains at most 32 packets, matching the queue limit, and stops before the total of SendPacket frames exceeds 64KiB. Always include the first packet regardless of size, so a batch contains at most 65,573 bytes of packet frames and 64KiB of Pongs. Frames go out in the order they entered the state machine. If the socket has not accepted a batch within 5 seconds, treat it as a connection error, disconnect, and reconnect (Go has no deadline for ordinary sends. Swiftail chooses one to bound memory use). Disconnection loses the batch being handed to the socket (at most 32 packets). The next connection sends the packets still queued (dequeue no more after disconnection). One watchdog, a child of the connection's TaskGroup, enforces the deadline by checking the in-flight write's start time without allocating a Task or timer per write. With per-write `withTimeout`, canceled deadline Tasks and timers remained for up to 5 seconds, so memory accumulated in proportion to the write rate. If more than 64KiB of Pongs accumulate during a blocked write, disconnect with `tooManyPendingReplies`. Blocked writes do not stop reads.
   - `connected` marks the point when ClientInfo is sent. The server may discard packets sent before it registers this client. Retries in the upper layer (WireGuard) cover this.
4. **Reconnection.** On error, close the socket and emit `disconnected`, then wait `min(n² × 10ms, 5 seconds) × [0.5, 1.5)` and reconnect from the beginning. Reset n to 0 after successfully processing at least one post-handshake frame (usually ServerInfo). This avoids reconnecting without backoff to a server that sends only ServerKey and disconnects. Open a new socket only after closing the old one (with two connections for the same key, the server passes packets to only one).
5. **Structured concurrency.** Canceling the Task that called `run()` stops everything. Create no detached Tasks. Sockets and continuations do not leak.

Record the following exclusions in `shortcut:` comments.

- Fast-start. (`sha256-raw:` certificate pinning and support for a `CertName` different from `HostName` were added in M8 ③. See "M8 ③" below.)
- Delaying IPv4. Go waits 200ms before dialing IPv4 on IPv6-preferred networks (`preferIPv6`). Swiftail dials all targets immediately because it does not infer an address family preference.
- Family-specific name resolution. Go resolves an empty field only for its family (`tcp4` or `tcp6`). Swiftail dials `hostName` without specifying a family, so it may dial the disabled family even if one field is empty and the other is `"none"`.
- Finer failure categories. `connectionFailed` does not distinguish connection refusal, no route, name resolution failure, or TLS failure (`SocketError.connectFailed` passes the Network framework error only as a string).
- Server-advertised rate limiting (token bucket). This version of the server does not send the values.
- Multiple regions, reverse paths, and cleaning up non-home connections are part of M4 (`SwiftailMagicsock`).
- WebSocket, HTTP proxies, and mesh frames.

## Tests

Unit tests (`Tests/SwiftailDERPTests`, no sockets) cover the following.

- Frame encoding and parsing. Fixed vectors matching the byte tables in chapter 3 of the notes (SendPacket, RecvPacket, NotePreferred, Ping/Pong, and PeerGone with reason codes).
- Handshake. A ClientInfo body generated from a fixed key and nonce matches Go `box.Seal` output (generate the vector with Go and keep it in the tests). Open ServerInfo. Feed input one byte at a time and feed the 101 head and ServerKey in one chunk.
- Rejection. Status other than 101, incorrect ServerKey magic, a ServerInfo that cannot be opened, exceeded limits (head, frame, and pending Pongs), `send` before readiness, a 65,537-byte packet, and `closed` and a cleared buffer after failure.
- Skip unknown frames, Health, Restarting, and KeepAlive, and read the following frame.
- Arbitrary input does not cause a crash. `dump` exposes no keys.

Interop tests (`Tests/SwiftailDERPInteropTests`, using the `SWIFTAIL_TAILNET` environment variable and skipped if it is absent) connect two `DERPClient` instances with different keys to the `tailnet` tool's Go DERP server (self-signed TLS).

1. Both become `connected` (Network framework TLS connects to the Go test server).
2. Packets travel A → B and B → A (1 byte, 1,280 bytes, 65,536 bytes). The sender keys are correct.
3. Sending to a nonexistent key leaves the connection open.
4. After B is canceled, A continues to work, and both exchange packets again after restarting B.
5. The connection lasts more than 70 seconds, through the server KeepAlive.

## M8 ③ — Certificate Names and Certificate Pinning

Production DERPMaps can contain nodes with a `CertName` different from `HostName` and nodes that pin a certificate using `sha256-raw:` (self-signed derpers). Before this unit, the engine skipped those nodes (`DERPServer.init?(_:)`). This unit verifies them with the same rules as Go. The sources are `derp-stun.md` §4.1 item 5, `tlsClient` in Go's `derp/derphttp/derphttp_client.go`, `SetConfigExpectedCert` and `SetConfigExpectedCertHash` in `net/tlsdial/tlsdial.go`, and `derp/derpconst`.

Fast-start is outside this unit's scope.

### API

Add two cases to `DERPServer.Verification`.

- `.named(String)` verifies the chain with the system trust store and checks the certificate name against this value. SNI and HTTP `Host` still use `hostName`.
- `.pinned(sha256Hex: String)` requires the SHA-256 of the server's certificate to match this value. It does not verify the chain.

`DERPServer.init?(_ node:)` chooses in the same order as Go's `tlsClient`.

1. If `certName` starts with `sha256-raw:`, use `.pinned(remainder)`. Store the remainder as-is (uppercase or differently sized values match no certificate in Go either, so the connection fails. Do not skip the node).
2. If `certName` is nonempty and differs from `hostName`, use `.named(certName)`.
3. Otherwise, as before, use `.noneForTests` for `insecureForTests` and `.system` otherwise.

Steps 1 and 2 take precedence over `insecureForTests` (Go also reinstalls the verification hook when `CertName` is present).

### Behavior V — Verification

1. For `.named`, verify the chain presented by the server using the system trust store and check the name against `certName`. Omit Go's fallback verification using a built-in Let's Encrypt root because the system store has that root.
2. For `.pinned`, remove certificates whose subject CN begins with `derpconst.MetaCertCommonNamePrefix` (meta certificates appended by the DERP server). **Exactly one** certificate must remain. For that certificate, ① the lowercase base-16 SHA-256 of the entire DER must match the pin character for character, ② if a name is sent in SNI (`hostName` is not an IP literal), the certificate must be valid for that name (Go also skips the name check for IP literals. The original statement that it "checks the IP SAN" was wrong), and ③ the current time must be within the validity period. Zero or two or more remaining certificates fail.
3. Verification failures follow the same path as existing TLS failures (the connection attempt fails with `attemptFailed`). Do not move to the next server (as in Go).
4. Verification must be testable without a connection (a function taking a list of certificate DER values, a name, a time, and a pin. Expose `.named` only at `package` scope so tests can supply anchors).
5. Check and document Go and platform behavior for SNI when `hostName` is an IP literal (`crypto/tls` sends no SNI for IP addresses).

The implementation decides whether ② and ③ use the platform's `SecTrust` (only the certificate as anchor, with the SSL server policy and name) or direct checks. A test must show that a self-signed certificate actually generated by Go's derper (the manual certificate mode of `cmd/derper`, for IP addresses) passes. If the platform is stricter than Go and rejects that certificate, report it without loosening the rules.

### Tests and Gate

- Unit tests cover matching pins, different hashes, a list containing a meta certificate, two non-meta certificates, no certificates, name mismatch, expired and not yet valid certificates, uppercase pins, and matching and mismatching names for `.named` (test anchor). Cover the three branches of `DERPServer.init?(_:)` and their precedence relative to `insecureForTests`.
- Interop uses a mode in the tailnet tool in `Tools/interop` that advertises the DERP node with `CertName: sha256-raw:<hash of that server's certificate>` instead of `InsecureForTests`. The Swiftail node communicates with a Go peer over that DERP server (Go derper also presents a meta certificate). Advertising the wrong hash makes the DERP connection fail.
- Deliberately break pin verification (skip hash comparison or skip counting non-meta certificates) and verify that the tests catch it.

## M8 ③ Implementation Decisions

- **Name checking for an IP-literal `hostName` (differs from the contract and follows Go).** Behavior V 2 ② said it "checks the IP SAN for an IP literal," but Go skips it. `SetConfigExpectedCertHash` skips name checking when `tls.ConnectionState.ServerName` is empty (`net/tlsdial/tlsdial.go:340`, "it's empty when dialing a derper by IP with no hostname"). The client's `ServerName` comes from `hostnameInSNI`, which turns an IP literal into an empty string (Go 1.27.3 `crypto/tls/handshake_client.go:78`, `:280`, `:1305-1320`, `conn.go:1629`). Therefore, skip name checking if `hostName` is an IP literal (including brackets and a `%` zone), and otherwise check the name with its trailing dot removed (`ServerCertificate.sniHostName`).
- **Verification location.** `ServerCertificate.checkPinned` and `checkNamed` in `SwiftailIO` (`package`) take DER values, a name, and a time (also anchors for `.named`) and throw a typed error (`ServerCertificate.Failure`). `NetworkSocket.TLS` adds `.named(serverName:certificateName:)` and `.pinned(serverName:sha256Hex:)`. The verification block collects server-presented certificates with `sec_protocol_metadata_access_peer_certificate_chain` and passes them to the verification functions. Each connection has its own verification queue because `SecTrustEvaluateWithError` blocks it.
- **② and ③ use `SecTrust`.** Use only the pinned certificate as anchor (`SecTrustSetAnchorCertificatesOnly`), use the SSL server policy (name as described above, no name for an IP literal), verify at the current time, and disable network fetching. This also applies Apple's TLS server certificate requirements that Go does not check (server authentication EKU, validity period of 825 days or less, and others). The manual IP certificate from derper (`createSelfSignedIPCert` in `cmd/derper/cert.go`, P-256, server authentication EKU, IP SAN, 1 year) passes (fixed certificate in unit tests and interop test). Swiftail rejects self-signed certificates that violate these conditions even if Go accepts them.
- **`.named`.** Evaluate the first received certificate as the leaf and the rest as chain candidates using the SSL server policy (`certName`) and system trust store. Meta certificates can be among the candidates. Network fetching retains the system default.
- **Hash comparison.** Convert the SHA-256 of the entire DER to lowercase base-16 and compare character for character. The certificate is public, so the comparison is not constant-time. Detect a meta certificate by checking whether `SecCertificateCopyCommonName` (subject CN) starts with `derpkey`. An unreadable certificate causes failure (Go fails the handshake first for such a certificate).
- **SHA-256 dependency.** `SwiftailIO` uses CryptoKit (a system framework) and Security. `Package.swift` was not changed.
- **Verified platform behavior.** ① `SecTrust` accepts a derper-style self-signed IP certificate with that certificate as the sole anchor. ② Passing an IP literal (`127.0.0.1`) to `sec_protocol_options_set_tls_server_name` also makes the Network framework omit SNI (the tool saw an empty SNI string in ClientHello, as in Go). ③ In the verification block, `sec_protocol_metadata_access_peer_certificate_chain` returns all certificates in presented order (the hashes for [leaf, meta] from the tool arrived in that order). The platform has not rebuilt the chain, so count "exactly one" in the server-presented list.
- **Interop tool.** The `tailnet` tool's `setDERPCertificate` (`mode`: `pinned` or `wrongPin`, before the first control request) switches the DERP server certificate to one like derper's manual IP certificate and adds a meta certificate using `derpserver.ModifyTLSConfigToAddMetaCert`. The DERPMap node gets `InsecureForTests: false` and `CertName: sha256-raw:<hash>`. `wrongPin` advertises the hash of the meta certificate the server also presents. `networkStatus` now returns the TLS ClientHello count (`derpTLSHandshakes`) and observed SNI values (`derpServerNames`). `tailnet certificate-fixtures` in the same tool generates the fixed unit test certificate.

## M8 ③ Independent Review Results (2026-11-15)

A session other than the authoring session compared the results with verdicts from actually running Go (v1.104.6, Go 1.27.3). Reproduction tests are in `Tests/SwiftailIOTests/ServerCertificateReviewTests.swift`. No critical findings, 1 high, 2 medium, and 6 low. The following takes precedence over the sections above.

### Fixes

- **The pinned certificate must come first (high, stricter than Go).** A TLS handshake proves possession of only the first certificate's key. Go's check ignores position. A server that lacks the pinned certificate's key can therefore pass by presenting a certificate it generated with its own key and a CN of `derpkey…` first, then appending the publicly available pinned certificate (confirmed by running a Go client and the pre-fix Swiftail against such a server). In that case the pin fails to identify the server. Add a condition to behavior V 2. **The one non-meta certificate must be first in the list** (`Failure.candidateNotLeaf`). Derper presents the server certificate first and the meta certificate after it, so normal servers are unaffected. The gate verifies that the tool's `leafNotFirst` mode cannot connect. The owner decides whether to notify Tailscale about Go's behavior (the lead session does not send it externally).
- **Pinned DERP reached by IP checks only the validity period (medium).** The SSL server policy in `SecTrust` is stricter than Go and rejects operator-generated self-signed certificates (validity of at least 826 days, no server authentication EKU, RSA 1024, or Ed25519 keys). When `hostName` is an IP literal, name checking is skipped, so evaluate under the basic X.509 policy (validity period and self-signature only). A 10-year Ed25519 certificate without EKU passes, and certificates outside their validity period are rejected. **Pinned DERP reached by name still uses the SSL server policy** (`shortcut:` Checking name and validity directly requires SAN parsing. This becomes necessary when connecting to such a DERP server).
- **The `.named` connection path lacked a gate (medium).** Tests passed even with verification removed from the connection. Added the tool's `named` mode. When `CertName` differs from `HostName` and the system does not trust the server certificate, the connection fails even if `InsecureForTests` is enabled. Connecting with the correct name requires a system trust store, so that case is only checked in the unit test (test anchor).
- **Resumed sessions bypass the verification block (low).** With TLS 1.2 session tickets enabled, an experiment found that resumed connections did not call the block. Default options did not trigger resumption. Explicitly disable resumption and session tickets in options that install a verification block.
- **`hostName` with a trailing dot (low).** The Network framework sends no SNI for such names. Go removes the dot and sends the name (`hostnameInSNI`). Strip the dot before passing the name on. The gate checks that the tool's `dottedHostName` mode receives `localhost` as SNI.
- **IPv6 groups longer than four digits (low).** `IPAddress` accepted `00000::1` (Go rejects it). Parsing such strings as IP addresses bypassed name checking. `IPAddress` now rejects them.

Verified that the new tests catch each of three fixes when removed individually (first-position check, `.named` verification, and trailing dot removal).

### Items Left as Is

- **Unreadable certificates.** The Network framework discards them before invoking the verification block. Go rejects [pinned certificate, malformed DER] during the handshake, and Swiftail accepts it. The pinned certificate in first position is verified, so the server is not misidentified. The statements above that "an unreadable certificate causes failure" and "all certificates the server presents are returned" apply only to the verification function and not to the connection path.
- **CN string type.** Security reads a VisibleString CN and Go leaves it empty. Go counts such an appended `derpkey…` certificate (rejects), and Swiftail excludes it as meta (accepts). The first-position requirement makes this harmless.
- **Dotted-decimal server name with leading 0s** (`100.064.0.1`). The SSL policy treats it as an IP address and matches it against the IP SAN (Go treats it as a name and rejects it). The difference applies only to certificates with a matching pin.
- **Server name with a combining character on the zone's `%`.** Swiftail is stricter because it treats it as a name.
- Go on Apple platforms uses the same `SecTrust` for system verification. `.named` and `.system` are as strict as Go there and differ only from Go on Linux.

### Unverified

- Whether the verification block is called on TLS 1.3 resumption (resumption could not be triggered. This no longer applies because resumption was disabled).
- Behavior on iOS (execution was on macOS only).
- Whether `.named` network fetching retrieves a missing intermediate and allows verification, and whether that request goes out through an interface other than the one specified.
- Whether reevaluating only DER causes rejection for a server that supplies SCT only via a TLS extension.
- The review read that Go skips name checking for an IP `hostName` node without `CertName` (`tlsdial.go`). Swiftail `.system` checks the IP SAN (stricter). No runtime comparison was performed.
- Real production DERP nodes with a different `CertName` and the full production DERPMap.
