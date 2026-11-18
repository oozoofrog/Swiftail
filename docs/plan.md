# Swiftail Plan

Baseline: `tailscale.com v1.104.6` (CapabilityVersion 148), `github.com/tailscale/wireguard-go v0.0.0-20261106233718-9e0ab45c16ca`. Protocol details are in [protocol-notes/](protocol-notes/README.md).

## 1. Goals

Become a tailnet node in Swift alone, without Go's tsnet or the Tailscale engine.

1. Stay resident below the 50MiB limit inside an iOS Network Extension packet tunnel.
2. Open tailnet listeners and connect to tailnet addresses without privileges inside the app process.
3. Replace the Tailscale features that the Go core of RemoteDebug, the first adopter, depends on.
4. Write the entire library in Swift, with code that serves as a guide for Swift developers (the code standards in §5).

## 2. First Adopter Requirements

The table maps the Tailscale features used by RemoteDebug's Go core to their Swiftail milestones.

| What RemoteDebug uses | Purpose | Swiftail milestone |
| --- | --- | --- |
| Node registration (auth key, interactive login URL, login retries at 30-second intervals), state file | Same node and tailnet IP after a restart | M2 |
| State notifications (`NeedsLogin`, `Running`, etc., `authURL`) | App UI | M2 |
| Tunnel engine + utun fd, MTU 1280–1420 | iOS packet tunnel | M5 |
| Compute address, route, and DNS settings (per-peer /32, 100.100.100.100/32, match domains) | `NEPacketTunnelNetworkSettings` | M5 |
| MagicDNS responses (tailnet names and reverse zones. SERVFAIL for other names) | Host FQDN resolution | M5 |
| Default interface change notification → socket rebinding | Wi-Fi ↔ cellular | M5 |
| Query the path to a peer (direct or relayed) | Status display | M4 |
| `Listen("tcp", ":443")`, `Dial` | HTTPS server on Mac, proxy mode | M6 |
| `WhoIs` (remote address → node and user) | Pairing, identity verification per request | M7 |
| ts.net certificates (`CertPair`, `GetCertificate`) | Valid HTTPS required by the iOS installer | M7 |

## 3. Scope

### Included

- Control protocol (ts2021): registration, login, netmap stream and deltas, key expiration handling
- WireGuard data plane
- DERP relay client
- Direct connections: disco, STUN, endpoint selection, path switching
- Inbound packet filter (ACL)
- MagicDNS responder (tailnet names)
- State storage
- iOS packet tunnel integration (utun I/O, computing settings, interface switching)
- In-process TCP listening and dialing, WhoIs, ts.net certificates

### Excluded

Subnet routers, exit nodes (providing or using them), Tailscale SSH, Taildrop, Taildrive, Funnel and Serve, peer relays, port mapping (UPnP, NAT-PMP, PCP), app connectors, log upload, automatic updates, device posture reporting, Linux and Windows.

Tailnet lock (node key signature verification) was excluded from the initial scope (M0–M7). Before M8, Swiftail detected tailnets with lock enabled and exited with `tailnetLockEnabled` (risk 8 in §8. That error was removed in M8). **Add it in M8** (owner decision, 2026-11-15: "Swiftail must support what RemoteDebug's Go core supports." RemoteDebug's Go core builds with tailnet lock included. The exclusion tags in that repository's `scripts/build-core.sh` do not include `ts_omit_tailnetlock`). Swiftail will not act as a signing device (signing other nodes' keys, enabling or disabling lock, or managing signing authority).

## 4. Decisions

### (a) Userspace TCP/IP Stack

**Implement it directly in Swift** (owner decision, 2026-11-14). Keep C code out of the library. Wrapping lwIP and using Network Extension on Mac were not adopted.

- The initial goal (M0–M5) does not require it. The iOS packet tunnel uses the OS stack. Build it as the `SwiftailNetstack` target in M6.
- Limit the scope to what TCP connections within the tailnet need: passive and active open, MSS, window scaling, RFC 6298 retransmission timer, fast retransmit and NewReno, delayed ACKs, zero-window probes, FIN and RST. Decide on IP fragment reassembly and SACK after measuring.
- Use the same structure as WireGuard: a state machine with no sockets or clock, plus I/O at the edge. Tests can reproduce loss, reordering, and delay deterministically.
- Verify against two counterparts: a Go peer (gVisor netstack) and the macOS kernel stack.

### (b) Interop Test Counterparts

1. **Primary gate: Go `testcontrol` + `derpserver` + `stuntest` + Go tsnet peer.** `Tools/interop` (a Go module) starts them in one process and prints the addresses as JSON. It requires no account and can run under the same conditions each time. This is the same setup as RemoteDebug's fake tailnet. In M1, the same tool starts a wireguard-go peer.
2. **Final gate: a real tailnet.** Since testcontrol can differ from the production control server, verify by connecting to a real tailnet as an ephemeral node once at the end of each of M2, M4, and M5. Notify the owner first each time and receive the auth key through secret input instead of chat.
3. Keep headscale out of the primary gate. Use it as a fallback if a real tailnet becomes unavailable.

### (c) Minimum OS and Dependencies

- iOS 18 and macOS 15 or later. This allows use of `Synchronization` (Mutex, Atomic). The first adopter's deployment target is 26.0.
- The core targets have no external Swift package dependencies. They use only CryptoKit, Network, and Foundation. M7's optional product (`SwiftailCertificates`) also uses Security (to verify the received certificate chain) and Foundation's `URLSession` (for HTTPS with the ACME server) (H8 in `docs/contracts/SwiftailHost.md`).
  - Cryptography: Implement only what CryptoKit lacks in `SwiftailCrypto` (BLAKE2s, XSalsa20-Poly1305, HChaCha20).
  - HTTP/2: Implement a minimal client directly since it uses one control connection and only a few streams. Switch to swift-nio-http2 if interop problems with the production server recur.
  - TLS (control 443, DERP): Network framework.
  - UDP (WireGuard, disco, STUN): Use POSIX sockets because one port must send to and receive from multiple peers.
- Test tools use Go (`Tools/`) because the interop counterpart is a Go implementation. They are not linked into the library.

### (d) Initial Goal

**Through M5: an iOS packet tunnel node.** This is where the advantage over Go (memory) comes from, and it requires no TCP stack. At this point, RemoteDebug's iPhone tunnel extension can switch to Swiftail, and the Mac can keep using Go tsnet and still communicate on the same tailnet. M6 and M7 (replacing the Mac host) are the second goal.

## 5. Modules

Create each target at the milestone that needs it. Arrows show the direction of dependencies.

```
Swiftail ─► SwiftailEngine ─► SwiftailWireGuard ─► SwiftailCrypto
                            └► SwiftailControl ──► SwiftailCrypto, SwiftailHTTP2
Swiftail ─► SwiftailDERP ────────────────────────► SwiftailCrypto
Swiftail ─► SwiftailMagicsock ───────────────────► SwiftailCrypto
Swiftail ─► SwiftailNetstack (internal)
```

Decision from M4: `SwiftailEngine` does not depend on `SwiftailMagicsock`. The engine only emits "a datagram to send to this peer," and the node (`Swiftail`) connects the engine and `Magicsock` (`docs/contracts/SwiftailMagicsock.md`).

All targets use `SwiftailBase` (shared value types such as IP addresses, prefixes, and keys). Targets that open sockets (`SwiftailControl`, `SwiftailDERP`, `Swiftail`) use `SwiftailIO` (socket wrappers and related components).

### Code Standards

This repository also serves as an example of how to write protocols in Swift.

- **Use value types for state machines and keep I/O at the edge.** Write protocol logic as a `struct` with no sockets or clock and pass the time as an argument. Write each protocol step as a pure function that also takes randomness (ephemeral keys, etc.) as an argument, and draw system randomness only in the layer outside the state machine. The actor that wraps it owns sockets and timers. Tests pass time directly to run deterministically.
- **Use typed errors** (`throws(SomeError)`) to show the type of failure in the signature.
- **Use unsafe tools only with a reason.** Use `Unsafe*` pointers, `@unchecked Sendable`, `nonisolated(unsafe)`, forced unwraps, and `try!` only where unavoidable, such as in POSIX calls. Confine each use to a narrow scope and document why in a comment.
- **Parse untrusted input once at the boundary.** Convert byte arrays to validated types before passing them around. No input may crash the process.
- **Follow the Swift API Design Guidelines for names.** Keep protocol terms (initiation, cookie, netmap) as written.
- **Document what and why, and cite the relevant section of the specification.** Each file covers one concept and reads from top to bottom.
- Write sparingly. Readable structure is what makes the code an example to follow, regardless of volume.

| Target | Milestone | Responsibility | Exclusions |
| --- | --- | --- | --- |
| `SwiftailBase` | M1 | IP addresses and prefixes, hex conversion, key types and text formats (moved from `SwiftailControl` in M3) | |
| `SwiftailIO` | M3 | Shared components for edge I/O: socket wrappers, timeouts, backoff, HTTP response headers. Used only within the package | Protocol logic |
| `SwiftailCrypto` | M0 | BLAKE2s, HMAC-BLAKE2s and HKDF-BLAKE2s, NaCl box and secretbox, XChaCha20-Poly1305, constant-time comparison | X25519, ChaCha20-Poly1305 (uses CryptoKit) |
| `SwiftailWireGuard` | M1 | Noise IKpsk2 handshake, cookie, transport encryption and decryption, replay protection, timers and rekeying, AllowedIPs | Sockets, TUN. Datagram sending and IP packet delivery are injected |
| `SwiftailHTTP2` | M2 | Minimal HTTP/2 client connection (including HPACK). Has no knowledge of Tailscale | General-purpose HTTP client |
| `SwiftailControl` | M2 | Key types and encoding, tailcfg models, control Noise, registration and map client, netmap and delta application | Data plane configuration |
| `SwiftailDERP` | M3 | DERP frames, connection and reconnection, per-region connection management | Home region selection |
| `SwiftailMagicsock` | M4 | disco, STUN, latency measurement and home region selection, endpoint state machine, UDP socket and rebinding, send and receive interface for WireGuard | |
| `SwiftailEngine` | M3–M5 | netmap → WireGuard peers, filters, routes, and DNS, packet filter, MagicDNS responder, state storage, TUN (utun fd, memory) | |
| `Swiftail` | M3 onward | Public API (`TailnetNode`) | |
| `SwiftailNetstack` | M6 | TCP value-type state machine in Swift (segment codec, connection, stack). It has `package` access and is not exported as a product. The public listening and connecting APIs are in `Swiftail` (`listen(port:)`, `connect(to:port:)`). **`Swiftail` depends on this target** ([`docs/contracts/SwiftailNetstack.md`](contracts/SwiftailNetstack.md) corrected the original diagram above and supersedes `dial` in the draft in §6) | TLS and HTTP. M7 uses a loopback bridge for TLS |
| `SwiftailCertificates` | M7 | ts.net certificate issuance, storage, and renewal (ACME DNS-01, control server `set-dns`). Optional product that depends on `Swiftail`. Only apps that act as servers link it (`docs/contracts/SwiftailHost.md`) | TLS termination, HTTP server, X.509 parsing (delegated to Security) |
| `SwiftailLoopback` | M7 | A bridge from tailnet connections to an OS TCP listener on `127.0.0.1` and a table for that listener to look up the peer's identity. Optional product | Listener, TLS |
| `SwiftailPairing` | M9 | App-to-app pairing: offer links and QR codes, pairing procedure, paired peer list, and single-use auth key issuance (Tailscale management API). Optional product that depends on `Swiftail`. Also uses CoreImage (QR) and Foundation's `URLSession` (`docs/contracts/SwiftailPairing.md`) | Camera-based QR scanning, approval screen, OAuth client secret storage |
| `SwiftailTKA` | M8 | Tailnet Lock (TKA) data formats (CBOR, AUM, node key signatures) and verification, signing authority state machine. It has `package` access and is not exported as a product. `SwiftailControl` depends on it (`docs/contracts/SwiftailTailnetLock.md`) | Sockets, files, clock, acting as a signing device |

### Findings from the Notes Incorporated into the Design

- WireGuard (the fork) has no endpoint roaming. magicsock chooses the path to the peer. `SwiftailWireGuard` does not handle addresses and only emits "a datagram to send to this peer."
- Tailscale does not use a PSK (0). A cookie arrives only when the peer is under load, so M1 only handled receiving cookies. Sending cookie replies (load detection, mac2 checks, per-source rate limiting) was added after M4, before opening a UDP port to the real internet (`docs/contracts/SwiftailWireGuard.md`, "Sending cookie replies"). mac1 must be correct from the start.
- The control Noise record nonce is a big-endian counter and records are limited to 4096 bytes. HTTP/2 frames are split across records. Handle the early payload the server sends first after the handshake.
- The map stream and state updates (endpoints, Hostinfo) are separate requests. `null`, an empty array, and omission have different meanings when applying deltas.
- Compute per-peer AllowedIPs and routes from the netmap. On iOS, per-peer /32 is the default. Idle peers are not added to WireGuard.
- MagicDNS looks up each query in the netmap without building a host table in advance.
- Generate a new disco key at each start without storing it. Persist the machine key and profile (including the node key).
- A direct path is trusted for 6.5 seconds. When that expires, send over both UDP and DERP and probe again. When the WireGuard session comes up, the Go peer sends a disco key notification (TSMP) inside the tunnel, which must be received and handled.

## 6. Draft Public API

Finalize only what each milestone needs. The following shows the direction.

```swift
public struct NodeConfiguration: Sendable {
    public var stateDirectory: URL
    public var hostname: String
    public var controlURL: URL        // Defaults to the Tailscale control server
    public var authKey: String?       // Used only for initial registration
    public var ephemeral: Bool
}

public enum TunnelDevice: Sendable {
    case utun(fileDescriptor: Int32, mtu: Int)   // iOS packet tunnel. Duplicates the fd before use
    case inProcess                               // M6: SwiftailNetstack
}

public actor TailnetNode {
    public init(configuration: NodeConfiguration, device: TunnelDevice) throws
    public func start() async throws
    public func stop() async
    public var status: NodeStatus { get }
    public nonisolated var events: AsyncStream<NodeEvent> { get }
    public func startInteractiveLogin() async throws
    public func setDefaultInterface(_ name: String)
    public func path(toPeerNamed fqdn: String) -> PeerPath?        // M4
    public func whoIs(_ address: TailnetAddress) -> PeerIdentity?  // M7
}

public enum NodeState: Sendable { case needsLogin, needsMachineAuth, starting, running, stopped, failed }

public enum NodeEvent: Sendable {
    case state(NodeState, authURL: URL?, errorMessage: String?)
    case networkSettings(TunnelNetworkSettings)   // Only when settings change
}

/// Settings the app converts to NEPacketTunnelNetworkSettings and applies. The library does not depend on NetworkExtension.
public struct TunnelNetworkSettings: Sendable, Equatable {
    public var addresses: [String]        // CIDR
    public var routes: [String]           // CIDR
    public var dnsServers: [String]
    public var dnsMatchDomains: [String]
    public var mtu: Int
}

// M6 (SwiftailNetstack)
extension TailnetNode {
    public func listen(port: UInt16) async throws -> TailnetListener
    public func dial(host: String, port: UInt16) async throws -> TailnetConnection
}
```

## 7. Milestones and Gates

Each milestone proceeds in this order: finalize the contract → implement → run unit tests → pass the interop gate → review by another session → commit. The lead session reruns the gate tests to verify them. Passing unit tests alone does not establish protocol behavior.

| Milestone | Contents | Gate (passing conditions) |
| --- | --- | --- |
| M0 ✅ | Cryptographic primitives | Pass all public vectors from the specifications, cross-implementation vectors generated with Go `x/crypto`, and tampering tests. Code review by another provider |
| M1 ✅ | WireGuard | On UDP loopback with a wireguard-go peer: Swift completes handshakes as both initiator and responder, exchanges packets in both directions, stays up through a rekey in real time, and rejects tampered and replayed packets. Verify cookies with vectors from the source tree and Swift-to-Swift tests |
| M2 ✅ (passed the real tailnet final gate, 2026-11-15: registered as an ephemeral node with the production control server, uncompressed map, stayed up for 90 seconds with 0 disconnects, 7 peers and 28 DERP regions, tailnet lock off. Visibility in the admin console was not checked visually) | Control protocol | Register with testcontrol and receive a netmap. The Go tsnet peer joining and leaving is reflected in the map. Since testcontrol sends only full maps by default, verify deltas (peer additions, removals, and patches) by injecting responses from the test tool. Keep the same node key and tailnet IP after restart. Final gate: verify registration as an ephemeral node on a real tailnet, visibility in the admin console, and receipt of an uncompressed map response |
| M3 ✅ | DERP-only communication | Complete a UDP echo round trip with the Go tsnet peer using only a local DERP server, without a direct UDP path. A TCP SYN gets a SYN-ACK. Drop packets to ports blocked by the ACL |
| M4 ✅ (real tailnet final gate remains) | Direct connection | Establish a direct path with the Go peer over loopback and LAN (verify the direct address in Go's status). Fall back to DERP when the direct path is blocked and return to it when unblocked. Final gate: a direct path to a device behind NAT on a real tailnet |
| M5 (gate (a) memory device passed. (b) real device: startup and idle memory passed (8.7MiB, Go 13.0MiB), switching passed: Wi-Fi→cellular in 4 seconds (after fixing a defect that dialed DERP only over IPv4 on IPv6-only cellular with CLAT. A direct path also came up), cellular→Wi-Fi in 4 seconds, and airplane mode off in 2 seconds (one run each). Transfer and start before first unlock remain) | iOS packet tunnel | MagicDNS answers only UDP queries (risk 12 in §8 below). Pass the cases corresponding to the test contract in RemoteDebug's `docs/tunnel.md` using a memory TUN (computing settings, UDP, TCP, MagicDNS, restart, and engine stop). Real device: connect from a test tunnel app to tailnet HTTPS on a Mac, resolve the FQDN, recover after Wi-Fi ↔ cellular switches, and record `phys_footprint` at idle and during transfer |
| M6 (gate (a) passed with Go peer, (b) real device with kernel stack remains) | In-process listener (Swift TCP) | State machine unit tests (inject loss, reordering, duplication, and delay) and matching hashes for 100MB transfers in both directions against a Go peer (gVisor) and the macOS kernel stack. Transfers must not stall under 1% and 5% loss. Record throughput |
| M7 (contract `docs/contracts/SwiftailHost.md`. **Gate (a) 1–10 passed** (2026-11-15: 9 `HostTests`, 100MiB of TLS over the bridge at 38MiB/s, all 1,801 tests passed). **Gate (b) 1 and 2 passed** (production control server + Let's Encrypt staging, tailnet with lock enabled: issued while locked in 40.8 seconds, tailnet TLS with the resulting certificate, restart uses the stored certificate). 11 Go state migration will not be implemented (U1: register again as a new node). Server-side logout `logOut()` merged. Remaining: gate (b) 3–7 (production issuance, iPhone, installation, transfer, sandbox. The first adopter runs these with a minimal HTTPS server)) | Verify the RemoteDebug replacement | WhoIs, ts.net certificate issuance, decision on migrating from the Go state file, mapping for 18 C APIs, and reproducing the RemoteDebug e2e scenario (pairing → installation session → IPA transfer) with Swiftail nodes. Split the gate into (a) without an account (test control server + test ACME server) and (b) real tailnet, Let's Encrypt, and real devices. Changes to the RemoteDebug repository require separate approval |
| M8 (scope finalized 2026-11-15. ①: notes verified, contract `docs/contracts/SwiftailTailnetLock.md`, implementation and three independent reviews complete, **gate (a) items 1–11 passed** (7 `TailnetLockTests`, Go peer and testcontrol. All 2,112 tests passed). Early steps of gate (b) passed: new registration carrying an NL key on a production tailnet with lock disabled, and upgrading a node registered with a pre-M8 version. On a production tailnet with lock enabled, "registration → signing device signs → unlock without restart" and restart passed (Mac command line). Remaining: iPhone tunnel, signed auth key, and synchronization when adding a key. ③ is complete (nodes with a different `CertName` and `sha256-raw:` pinning. Fixed the independent review findings. Requiring the pinned certificate to be first is stricter than Go), UDP IPv6 in ② is deferred) | Production parity: gaps where the Go core works and Swiftail is blocked | ① **Tailnet Lock**: register on a tailnet with lock enabled (signed auth key or a signing device signs later), receive, verify, and store signing authority state (TKA), filter unsigned peers, and handle disabling lock. Compare against Go reference values to check that the decisions match the Go implementation, and set up a gate that requires no account (testcontrol). ② **Outer IPv6**: concurrent IPv4 and IPv6 dials for DERP are complete (on a real device with IPv6-only cellular and CLAT, recovered in 4 seconds and also established a direct path over CLAT). Defer IPv6 for UDP, STUN, and endpoints until an IPv6-only network without CLAT or a direct IPv6 path is needed (the observed network did not require it). ③ **Remaining production DERP configurations**: nodes with a certificate name different from the hostname, `sha256-raw:` pinning. Gate (b): real tailnet with lock enabled, real device on IPv6-only cellular. **The first adopter's Mac host is on a tailnet with lock enabled** (owner, 2026-11-15) (correction from the RemoteDebug session's diagnostic log: lock had always been disabled on the Mac's previous tailnet. At about 2026-11-15 13:26 UTC, the owner moved the Mac to a new tailnet under a new account, enabled lock, and signed the node. This statement has been true since then. The iPhone app's node remains on the old tailnet). Therefore ① must finish before switching the Mac host to Swiftail (the Mac side of the M7 gate (b) e2e follows as well) |
| M9 (contract `docs/contracts/SwiftailPairing.md`. **Gate (a) passed** (2026-11-17: 126 unit tests, request comparison with the Go client, pairing on the test control server, joining with a key and then pairing, OS socket path, design review and code review). **Gate (b) 12 passed** (2026-11-18: issued a key through the real management API, used it on a real iPhone to join a tailnet with lock enabled, paired with the Mac after signing, matching SAS, verified the connection). Remaining: OS socket path through the iPhone tunnel extension (gate 13)) | QR and link pairing between apps | (a) Without an account: unit tests for links, proofs, the procedure, the paired peer list, and QR. Same requests as Go `get-authkey`. Two nodes on the test control server go from offer → approval → pairing. A new node pairs after registering with an offer's auth key. (b) Join a real tailnet with a key created through the real management API and pair |

Memory goal (M5): aim for idle residency of 20MiB or less and finalize the target with measurements on a real device. The Go core's recommended limit setting was 28MiB.

## 8. Risks and Alternatives

| # | Risk | Response |
| --- | --- | --- |
| 1 | Passes testcontrol but fails with the production control server (HTTP/2 behavior, required fields, version requirements) | Use a real tailnet for the M2 final gate. Keep a boundary that allows switching HTTP/2 to swift-nio-http2 |
| 2 | The control protocol is not a public contract. Server changes could break it | Pin the reference version and specify it in the README. Rerun the gate when upgrading |
| 3 | Map response compression (zstd). With `Compress` empty, testcontrol sends uncompressed responses. The Go client always requests zstd, so the reference sources do not establish whether the production server honors a request for an uncompressed map. Apple frameworks do not have zstd | Verify at the M2 final gate. If it fails, implement only a decompressor directly (RFC 8878) |
| 4 | NAT traversal succeeds less often than in Go | Communication always works via DERP. Decide on port mapping and peer relays after measuring |
| 5 | iOS extension: Finding the utun fd relies on an unofficial method. The extension's own sockets may loop back through the tunnel | Follow the method RemoteDebug verified on a real device. Bind sockets to the physical interface |
| 6 | Side channels in handwritten cryptography and lack of an audit | Constant-time implementation rules, review by another provider, README disclosure |
| 7 | Handwritten TCP stalls or slows down with loss or reordering | Separate the state machine from I/O, cover it with deterministic tests, and verify against two independent implementations (gVisor and the macOS kernel). No effect on the initial goal |
| 8 | Accepting peers without signature verification on a tailnet with tailnet lock enabled removes its protection | Decide in M2: until support is available, consider detecting and refusing connections to tailnets with lock enabled as the default |
| 9 | Swift packet path throughput and allocations per packet | Decide on the buffer reuse structure in M1 and measure real-device throughput in M5 |
| 10 | Unverified whether connecting to Tailscale's production server with an unofficial client and using the name comply with terms and trademark rules | The owner verifies before public release. Until then, keep the repository local only |
| 14 | End-to-end verification of ts.net certificate issuance requires the production control server's `set-dns` and Let's Encrypt. The client source does not show the conditions or timing of a `set-dns` response, and Let's Encrypt limits repeated issuance for one name to 5 certificates in 7 days. The device and tailnet names in an issued certificate appear in public CT logs | Use a test ACME server for the local gate. For real issuance, use staging first and limit production issuance to two certificates. Notify the owner first |
| 15 | The loopback TLS bridge turns an authenticated tailnet connection into an anonymous connection on `127.0.0.1` | Bind the peer identity when bridging the connection and pass it through the bridge’s token-verified `origin(of:)` lookup. The server closes loopback connections that have no verified origin ([behavior B in the host contract](contracts/SwiftailHost.md#b-loopback-bridge)) |
| 11 | One person needs to keep up with upstream changes | Keep the scope narrow (exclusions in §3) and automate interop tests |
| 12 | MagicDNS in tunnel mode answers only UDP queries without a TCP stack. It cannot handle TCP 53 or responses larger than the MTU | A, AAAA, and PTR responses for tailnet names are small. If a response is too large, set the truncation flag. Add TCP 53 after M6 |
| 13 | A Go peer assumes its counterpart supports peer relays if the counterpart's CapabilityVersion is 121 or later. Declaring 148 without implementing them may cause the counterpart to try a relay path | Ignore unknown disco messages. Verify DERP and direct paths at the M4 gate against a Go peer with relays enabled. Decide separately in M2 about declaring a lower version because it may change server behavior |

## 9. Open Decisions

| Decision | Deadline | Recommendation |
| --- | --- | --- |
| Whether to set the initial goal at M5 (iOS tunnel) | Before M5 | M5 (M0–M4 are the same either way) |
| Whether to use a real tailnet for the final gate and which tailnet and tag to register with | Before the end of M2 | Ephemeral node |
| Signing the test tunnel app for a real device (team, Network Extension entitlement) | Before M5 | |
| Handling tailnets with tailnet lock enabled | M2 → M8 | Refuse to connect before M8 (Go peers also omit unsigned nodes from the netmap). Support them in M8 (§3) |
| CapabilityVersion to declare | M2 | 148 (same as the reference sources) |
| Whether to migrate node identity from the Go state file (`tailscaled.state`) | M7 | The owner chose to register as a new node ([U1 in `SwiftailHost.md`](contracts/SwiftailHost.md#owner-confirmation-required)). The read-only, one-time, identity-only import remains a design in the contract |
| License and whether to make the repository public | Before public release | |

## 10. Collaboration

- Lead session (Fable 5.2): contracts, integration, gate decisions, reporting.
- Opus 5.5: implementation of protocols with complex state machines (WireGuard, control Noise and map, magicsock).
- Sonnet 5.5: implementation with clear contracts (cryptographic primitives, DERP frames, codecs, state storage, filter).
- Haiku 5.5: mechanical transformations (copying vectors, tables).
- Codex (GPT): cross-review of code written by Claude, independent tests and vectors written from the same contract alone, and fact-checking the notes. Codex writes the material for Claude to review.
- Cryptographic and protocol code passes the gate after review by a different session from the one that wrote it. Use a model from a different provider if possible.
- Before starting each milestone, a session other than the one that wrote the protocol notes checks them against the Go source. Where the Go implementation can run to produce reference values, add tests that compare against those values (in M2 this caught a difference that the notes, verification, and implementation had all missed).
