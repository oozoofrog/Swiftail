# Swiftail Host Contract (M7, Draft)

The goal of M7 is for **the Mac host of the first adopter, RemoteDebug, to do what it does today using Swiftail alone, without the Go core (tsnet)** (`docs/plan.md` §7 M7). The entire Go core is ultimately removed. Through M6, Swiftail listens for and opens TCP connections on tailnet addresses in-process (`listen(port:)` and `connect(to:port:)`, byte streams). M7 adds the rest of what the Go host relied on Tailscale for: identifying the peer on a connection (`WhoIs`), a valid HTTPS certificate required by the iOS installer (a ts.net certificate), a loopback bridge that carries bytes to an OS listener that terminates TLS with that certificate, and a way to import identity from Go state.

This document is a **draft**. Before implementation, send "First Adopter Confirmation Required" to the first adopter session for review, resolve "Lead Session Confirmation Required" and "Owner Confirmation Required," then finalize it.

Protocol details follow [whois-certs-state.md](../protocol-notes/whois-certs-state.md) (the "notes" below. Another session verified them against the Go source and original RFCs on 2026-11-15. The verdicts for individual claims are in notes §9, the comparison against this contract is in notes §10, and the resulting changes are in "Changes from Notes Verification" at the end) and [dns-state-node.md](../protocol-notes/dns-state-node.md) (the "DNS notes" below) §§3.2, 4.8, and 4.9. This document defines only the scope, targets, public API, behavior, limits, tests, and gates.

Relationship to existing contracts: This document closes lead session confirmation N9 (TLS over the connection) and item 1 of the [first adopter review results](SwiftailNetstack.md#first-adopter-review-results-2026-11-15) in `SwiftailNetstack.md` (M6). It carries forward decision D8 (separate state directories) and question 16 (migration for existing users) of [SwiftailTunnel.md](SwiftailTunnel.md) (M5). This document takes precedence in a conflict.

Already decided (the first adopter's answer, "First Adopter Review Results" in `SwiftailNetstack.md`): The first adopter writes the HTTP server in Swift (HTTP/1.1). TLS uses a loopback bridge (`NWListener` on `127.0.0.1`, ALPN `http/1.1`, minimum TLS 1.2). One listener, around 10 connections per device. Proxy mode is not migrated. iOS does not use `.inProcess`.

Investigated: commit `2814b2c` of the first adopter's repository (read-only), `tailscale.com` v1.104.6, original RFCs, macOS SDK headers, and the small format checks in notes §4.6 (key and signature sizes, PEM reading and writing, signature verification. The verification session reran them). The CSR, TLS, and Keychain experiments reported by the authoring session are unverified because there is no record (notes §8). This contract does not rely on them.

## 1. Goals and Scope

| Included | Rationale |
| --- | --- |
| `whoIs`: tailnet address → node and user | For every `/v1/*` and `/i/*` request, the first adopter verifies identity from the connection's remote address and checks the node's `StableID` against the allowlist (RemoteDebug `docs/protocol.md` §3, `core/internal/host/host.go:230-260`) |
| ts.net certificate issuance, storage, and renewal (ACME DNS-01, Let's Encrypt) | The iOS installer requires both the manifest and the IPA to be served over `https` (same document §§4.5 and 11). The Go host obtains the certificates with `CertPair` and `GetCertificate` (RemoteDebug `core/internal/node/tls.go:22-51`) |
| Control server `set-dns` request | The only way to publish the DNS-01 record (notes §3.2) |
| Loopback bridge: Swiftail connection ↔ OS TCP listener on `127.0.0.1`, and a way for that listener to find the peer's identity | `SwiftailNetstack.md` N9. Swiftail provides it because it must convey backpressure and half-close correctly (lead session confirmation H2 required) |
| Import identity from a Go state directory (read-only, once) | Open decision in plan §9. **Include only the design and start implementation after owner decision U1** |
| Mapping for 18 C APIs, basic reproduction of the RemoteDebug e2e scenario | Plan §7 M7 |

| Excluded | Reason | When it becomes necessary |
| --- | --- | --- |
| HTTP server, TLS termination | The first adopter handles these with the Network framework (decided) | — |
| TLS written in Swift, SecureTransport | Excluded in `SwiftailNetstack.md` N9 and review result 1 | — |
| Certificates: TLS-ALPN-01, wildcards, names other than the node's own FQDN, ARI, RSA keys, account contact and EAB, account key rollover, revocation | The first adopter only uses its own FQDN. The rest are for Funnel and Serve or are unused even by Go's Tailscale integration (notes §6) | When such a use case arises |
| `whoIs` capabilities (`CapMap`), lookup by node key | The first adopter does not read them (notes §4.1 item 7) | When an adopter uses ACL grants to divide app permissions |
| Certificates and bridge on iOS | The iOS tunnel extension is not a server. The targets build on iOS too, but the gate covers macOS only | When an adopter listens on iOS |
| Proxy mode (`rd_proxy_start`) | No callers, and it goes away with Go (review result 2) | — |
| Host REST, pairing, sessions, publishing, direct same-network listener, update page | First adopter logic unrelated to Tailscale (§4 mapping) | — |
| Changes to the first adopter's repository | Requires separate approval (plan §7 M7) | After gate (a) passes |

## Targets and Dependency Direction

| Target | Kind | Added in M7 |
| --- | --- | --- |
| `SwiftailControl` | Existing | `ControlClient.setDNS(name:value:)` (`POST /machine/set-dns` over Noise), reading Go state files (`GoStateFile`, `package`) |
| `Swiftail` | Existing | Public: `whoIs(_:)`, `PeerIdentity`, (after U1) `GoStateImport`. `package`: interfaces used by the certificate target (`setDNS`, stream of own FQDN, cert domains and state, and state directory) |
| `SwiftailIO` | Existing (`package`) | `NetworkSocket`: plaintext loopback connection, reading the local port, finishing writes (FIN) |
| `SwiftailCertificates` | **New product** | ACME messages and order procedure (value types), JWS and JWK, DER writing and CSR, PEM, certificate storage and verification, edge `CertificateManager` |
| `SwiftailLoopback` | **New product** | `LoopbackBridge` |

```
SwiftailControl ◄─ Swiftail ◄─┬─ SwiftailCertificates   (CryptoKit, Security, Foundation's URLSession)
                               └─ SwiftailLoopback       (SwiftailIO, Network)
```

- Reason to keep the two new targets outside `Swiftail`: the iOS tunnel extension links only `Swiftail` and is subject to the 50MiB limit and binary size considerations. Only apps acting as servers use ACME, DER, and the bridge. Since they are in the same package, they reach the node's internals through `package` access, and `whoIs` is the only addition to `Swiftail`'s public surface (lead session confirmation H1 required).
- Newly used system frameworks: Security (verify the received chain with `SecCertificate` and `SecTrust`), Foundation's `URLSession` (HTTPS with the ACME server). Security is added to "Only CryptoKit, Network, and Foundation" in plan §4(c) (lead session confirmation H8 required). No external packages or C code.
- The first adopter uses `import Swiftail`, `import SwiftailBase` (`IPAddress` and `IPEndpoint`), `import SwiftailCertificates`, and `import SwiftailLoopback`.

## 2. Draft Public API

### `Swiftail`

```swift
import SwiftailBase

extension TailnetNode {
    /// Looks up the node that owns this tailnet address in the current netmap. tsnet `LocalClient().WhoIs(addr)`.
    ///
    /// Looks up only peers that the data plane treats as owners of the address (peers with that address in WireGuard AllowedIPs)
    /// and the local node. Excludes addresses within subnet routes and addresses of nodes absent from the data plane, for example
    /// because their keys expired. Returns nil without waiting if there is no netmap yet, no node for the address, or no profile in the netmap for the user who created the node.
    ///
    /// Pass `TailnetConnection.remoteEndpoint.address` to identify a connection's peer. The address belongs to the WireGuard-authenticated
    /// peer, and the node closes the connection if the owner of the address changes (`ConnectionError.peerRemoved`).
    public func whoIs(_ address: IPAddress) -> PeerIdentity?
}

/// The identity of one tailnet node, as reported by the control server in the netmap.
public struct PeerIdentity: Sendable, Equatable {
    /// The node's stable ID (`tailcfg.Node.StableID`). Nonempty. Use as the allowlist key.
    public var stableID: String
    /// The MagicDNS name without a trailing dot (`rd-phone-1a2b3c4d.tail0001.ts.net`). Empty if there is no name.
    public var name: String
    /// The display name. Follows Go's `Node.ComputedName` rules (behavior W4): strip the local tailnet suffix only when it matches at a label
    /// boundary, then remove the trailing dot (`rd-phone-1a2b3c4d`). A node shared from another tailnet has a different suffix, so its FQDN
    /// without a trailing dot remains. If the result is empty, use the sanitized hostname, then the public node key text (`nodekey:` + hex) if that too is empty.
    public var computedName: String
    /// The login name of the user who created the node (`alice@example.com`). For display. Does not identify a person on tagged nodes.
    public var loginName: String
}
```

Difference from the draft in `docs/plan.md` §6: the parameter uses `SwiftailBase`'s `IPAddress` instead of `TailnetAddress` (the same type as M6's `IPEndpoint.address`).

### `SwiftailCertificates`

```swift
import CryptoKit
import Foundation
import Swiftail

/// A certificate issued for the node's ts.net name and its private key.
///
/// Because it contains a private key and its name contains the tailnet name, `description` and `dump` expose only the validity period (behaviors K1 and K2).
public struct TailnetCertificate: Sendable {
    /// The certificate name (`rd-mac-1a2b3c4d.tail0001.ts.net`).
    public let domain: String
    /// The DER certificates, with the leaf first, followed by intermediates. The ACME server may include the root (RFC 8555 9.1),
    /// so verify the chain and then strip any trust anchor (root) sent by the server (behavior S6). Pass the result as-is to the TLS identity.
    public let chain: [[UInt8]]
    /// The leaf's private key. Pass `x963Representation` to `SecKeyCreateWithData` to create a `SecKey`.
    public let privateKey: P256.Signing.PrivateKey
    public let notBefore: Date
    public let notAfter: Date
}
extension TailnetCertificate: CustomStringConvertible, CustomReflectable {}

public struct CertificateConfiguration: Sendable {
    /// The Let's Encrypt production server directory.
    public static let letsEncryptDirectoryURL: URL
    /// The ACME directory URL. Must use `https`. Override for tests and staging.
    public var directoryURL: URL
    /// The trusted roots (DER) for validating received and stored chains. nil uses the system trust store. If supplied, trust only these roots.
    /// Use for staging and test servers (behavior X3). An empty list yields `invalidConfiguration`. (Added 2026-11-15: previously the public API
    /// offered no way to use staging. This surfaced while writing the tests for gate (b) 1 and 2.)
    public var trustAnchors: [[UInt8]]?
    public init(directoryURL: URL = CertificateConfiguration.letsEncryptDirectoryURL, trustAnchors: [[UInt8]]? = nil)
}

/// Obtains a certificate for the node's own ts.net name and renews it before expiration. tsnet `CertPair` and `GetCertificate`.
///
/// Stores it in `certs/` under the node's state directory. On restart, validates and reuses the stored certificate.
public actor CertificateManager {
    /// - Throws: `invalidConfiguration` if the directory URL does not use `https`.
    public init(node: TailnetNode, configuration: CertificateConfiguration = CertificateConfiguration()) throws(CertificateError)

    /// Obtains and renews certificates. Run in the same task group as `node.run()`. Runs until canceled.
    ///
    /// Reports issuance failures in `status` without throwing. Failures that require the user to fix tailnet settings (MagicDNS or HTTPS
    /// disabled, name missing from cert domains) wait for a netmap change or a call to `retryNow()`. For other failures (rejection by the ACME server,
    /// connection loss), back off and retry (behavior R4). Throws only failures (`CertificateError`) for which running again would not help.
    public func run() async throws(CertificateError)

    /// The current certificate and each new certificate upon renewal. Emits the stored certificate first if valid. Only one Task may iterate.
    /// If an item has not been consumed, only the newest is retained.
    public nonisolated var certificates: AsyncStream<TailnetCertificate> { get }

    /// The current certificate's expiration, the last failure, and the time of the next attempt.
    public var status: CertificateStatus { get }

    /// Ends a backoff or wait for conditions and checks again immediately. This is the "Retry now" action the user presses after
    /// fixing tailnet settings. Does nothing during issuance or before the time given by the ACME server in `Retry-After` (including
    /// `rateLimited`). Sends no requests to that server before that time (behavior X5).
    public func retryNow()
}

public struct CertificateStatus: Sendable, Equatable {
    /// The name for which a certificate is requested. nil if the node's name is not known yet.
    public var domain: String?
    /// The current certificate's expiration time. nil if there is none.
    public var notAfter: Date?
    /// Why the last attempt failed. Returns to nil on success.
    public var lastFailure: CertificateFailure?
    /// When to attempt issuance or renewal next. Uses the ACME server's `Retry-After` time if later (capped at 7 days,
    /// behavior X5). nil while waiting for conditions (login, MagicDNS, HTTPS, cert domains), with no time-based retry.
    public var nextAttempt: Date?
}

/// Why issuance did not succeed. The app selects user-facing text by case and uses associated strings only for diagnostics.
public enum CertificateFailure: Sendable, Equatable {
    /// The node is not `.running`.
    case nodeNotRunning
    /// MagicDNS is disabled on the tailnet. The user must enable it in the admin console.
    case magicDNSDisabled
    /// HTTPS certificates are disabled on the tailnet (netmap `DNSConfig.CertDomains` is empty). The user must enable them in the admin console.
    case httpsNotEnabled
    /// The node's name is absent from the netmap's cert domains or fails the name checks in behavior C2.
    case domainNotAllowed
    /// The control server rejected the DNS record request. The associated value is the HTTP status code.
    case controlRejected(status: Int)
    /// The ACME server rejected the request with a non-success HTTP response. `status` is the HTTP status code and `type` is the full problem
    /// document `type` string (`urn:ietf:params:acme:error:badCSR`, server-specific URI, `about:blank`). Empty if no problem document exists,
    /// it is not JSON, or it has no `type`. Truncated to 256 bytes. Omits the problem document's `detail` because it may contain
    /// identifiers (behavior K2).
    case acme(status: Int, type: String)
    /// ACME server rate limit (`type` is `urn:ietf:params:acme:error:rateLimited`). Includes the retry time provided by the server.
    case rateLimited(retryAfter: Date?)
    /// The certificate authority could not verify ownership of the name. Authorization is `invalid` (DNS record missing or wrong value).
    /// `type` is the `type` of that challenge's `error` problem document (same rules as `acme`).
    case validationFailed(type: String)
    /// The order became `invalid` without an authorization failure (expiration, CSR or issuance rejected, etc.), or an authorization
    /// prevents the order from proceeding (`deactivated`, `expired`, or `revoked`). `type` is the `type` of the order's `error` problem document.
    case orderFailed(type: String)
    /// The ACME server response violated the specification or this contract's limits (unknown status, authorization for a different name,
    /// oversized body, non-`https` URL, etc. Behaviors C5 and X).
    case unexpectedResponse
    /// The received certificate failed verification (name, validity period, chain, or key).
    case invalidCertificate
    /// The ACME or control server could not be reached.
    case network(String)
    /// Issuance did not finish before the deadline.
    case timedOut
}

public enum CertificateError: Error, Sendable, Equatable {
    /// The directory URL is invalid, or `run()` was called twice.
    case invalidConfiguration(String)
    /// Could not create, write, or read `certs/`, or an existing `certs/` is writable by the group or others (behavior S1).
    /// The message includes only the error code.
    case storage(String)
    /// `certs/acme-account.key.pem` exists but could not be read as a P-256 account key (RSA key left by Go, corrupt file, or excessive size).
    /// Does not overwrite it because creating a new account would lose the account that file pointed to (behavior C4).
    case accountKeyUnreadable
}
```

### `SwiftailLoopback`

```swift
import Network
import Swiftail
import SwiftailBase

/// Bridges an inbound tailnet TCP connection to this device's loopback (`127.0.0.1`) TCP listener.
///
/// Apps use this to terminate TLS and HTTP with the OS stack (`NWListener`). The bridge does not parse bytes. At the far end of
/// the loopback connection, the peer appears as `127.0.0.1`. The server adds the bridge's protocol to the listener and calls `origin(of:)`
/// with the accepted connection to identify the tailnet peer. The bridge sends a single-use token on each loopback connection before
/// the TLS bytes. The protocol only passes connections with a verified token up to TLS. Connections opened by other processes on this device do not become `.ready` for the server (behavior B6).
public final class LoopbackBridge: Sendable {
    /// The tailnet peer of a loopback connection.
    public struct Origin: Sendable, Equatable {
        /// The peer's tailnet address and port.
        public var remoteEndpoint: IPEndpoint
        /// The peer's identity verified when bridging started. Does not change for the life of the connection.
        public var peer: PeerIdentity
    }

    public init(node: TailnetNode)

    /// Returns the protocol for the server's loopback listener. Append to the **end** of `NWParameters.defaultProtocolStack.applicationProtocols`
    /// (below TLS, immediately above TCP). The same applies to plaintext listeners.
    public func makeListenerProtocolOptions() -> NWProtocolFramer.Options

    /// Bridges one connection to `127.0.0.1:<port>` and carries bytes until both directions finish. Closes both connections before returning.
    ///
    /// Verifies the peer's identity before dialing loopback. Closes both connections if the calling Task is canceled. On failure,
    /// aborts `connection` (RST) and throws.
    public func forward(_ connection: TailnetConnection, toLoopbackPort port: UInt16) async throws(LoopbackBridgeError)

    /// Returns the tailnet peer of a loopback connection accepted by the server. Does not wait. Answers only once per connection (then nil).
    ///
    /// Answers only when `connection` is `.ready` and the listener's protocol verified a token from this bridge. If called after `.ready`,
    /// a connection forwarded by the bridge always gets an answer.
    public func origin(of connection: NWConnection) -> Origin?
}

public enum LoopbackBridgeError: Error, Sendable, Equatable {
    /// The peer address's identity was not found in the netmap.
    case unknownPeer
    /// The bridge reached its limit of 256 forwarded connections.
    case limitReached
    /// Could not dial the loopback port (no listener, timeout, or could not record or send the token).
    case loopbackUnavailable(String)
    /// The calling Task was canceled.
    case cancelled
}
```

### `Swiftail` (Only After Owner Decision U1)

```swift
/// Imports node identity from a state directory left by Go tsnet or an app that used it.
public enum GoStateImport {
    /// Reads the machine and node keys from `tailscaled.state` in `directory` and saves them as a Swiftail identity in
    /// `configuration.stateDirectory`. Leaves Go's files untouched. Imports a single fully registered profile and rejects other state (behaviors G2 and G3).
    /// After import, the node starts with the same tailnet address and `StableID` if the control server accepts it as the same node. Whether
    /// the server does so (registration with a zero `NLKey`, simultaneous sessions with the same key) is unverified before the gate (behavior G7).
    ///
    /// Call **only after** the Go node that used this state has stopped. Two nodes must not share the same node key.
    public static func importIdentity(
        fromGoStateDirectory directory: URL, for configuration: NodeConfiguration
    ) throws(GoStateImportError)
}

public enum GoStateImportError: Error, Sendable, Equatable {
    /// The destination directory already has a Swiftail identity. Does not overwrite it.
    case alreadyInitialized
    /// `tailscaled.state` is missing.
    case noGoState
    /// Could not parse the file (JSON, base64, or key text format, zero machine key, etc. Behavior G2).
    case malformed
    /// No registered identity to import: the node key is absent or zero, or `LoggedOut` is true. A zero value does not reveal
    /// whether the node has never logged in.
    case notLoggedIn
    /// State is parseable but unsupported by this import: multiple profiles, missing key pointed to by `_current-profile`, mismatch with
    /// `_profiles`, legacy format, or incomplete key rollover (`OldPrivateNodeKey` present). Behavior G2.
    case unsupportedState
    /// The control server in Go state and `configuration.controlURL` cannot be treated as the same server (behavior G3).
    case controlURLMismatch
    /// Could not read or write. The message includes only the error code.
    case storage(String)
}
```

### Usage (Mac Host)

```swift
let node = try TailnetNode(configuration: configuration, device: .inProcess)
let certificates = try CertificateManager(node: node)
let bridge = LoopbackBridge(node: node)
let listener = try await node.listen(port: 443)

try await withThrowingDiscardingTaskGroup { group in
    group.addTask { try await node.run() }
    group.addTask { try await certificates.run() }
    group.addTask {
        // Start or restart the TLS listener when a certificate arrives or changes. The first adopter owns this code.
        for await certificate in certificates.certificates { await server.restart(with: certificate) }
    }
    for await connection in listener {
        group.addTask {
            guard let port = await server.loopbackPort else { await connection.abort(); return }
            try? await bridge.forward(connection, toLoopbackPort: port)
        }
    }
}

// Server (first adopter): append the bridge protocol to the end of the stack (below TLS) when creating the listener
parameters.defaultProtocolStack.applicationProtocols.append(bridge.makeListenerProtocolOptions())

// Once when the accepted connection becomes `.ready` (TLS handshake complete)
guard let origin = bridge.origin(of: nwConnection) else { nwConnection.cancel(); return }
// For each request: is origin.peer.stableID on the allowlist?
// If the connection becomes `.failed` (connections without a token reach this before readiness), call cancel() and release that NWConnection (behavior B7)
```

## 3. Behavior

The numbers are names used by tests and reviews. Unless stated otherwise, values are proposed by this contract and adjusted based on gate records.

### W. `whoIs`

1. **Address table**: The address owner is **the one selected by the data plane** (2026-11-17). A peer's address belongs to the peer that the engine assigned the single-address prefix (/32, /128) as WireGuard AllowedIPs (the `TailnetEngine.addressOwners` table, built when the engine installs peers. Engine contract behavior 2: an `AllowedIPs` prefix must cover a single address and either be in a tailnet address range or appear in the peer’s `Addresses`. The lower node ID wins if multiple nodes claim the same prefix). The node receives and retains that table whenever the engine recomputes peers (netmap application, key expiration handling), and `whoIs` reads it. It does not recompute from the netmap for each query (W6). Exclude subnet routes. Addresses of nodes absent from the data plane (expired keys, unsupported peers) are absent from the table. Offline nodes are included. For the local node, use the single-address prefixes in `Addresses`.
   - Difference from Go: Go's `WhoIs` consults a table built from the netmap's `Addresses` (notes §4.1 item 1), finds expired nodes too, and selects the later node when several have the same address. In a netmap with overlapping addresses, that table points to a different node than the data plane (the peer that can send packets from that address). The app then sees another node's identity as the connection's peer. In a netmap without overlaps, answers for nodes installed in the data plane match Go (gate (a) 1).
2. **Lookup**: Convert IPv4-mapped IPv6 addresses to IPv4 before lookup (notes §4.1 item 2). Because the data plane does not accept mapped addresses (`::ffff:a.b.c.d/128`) as peer addresses (engine contract behavior 2), a connection with a mapped source address cannot belong to a peer other than the owner of that IPv4 address. Return nil if absent from the table. There is no equivalent of `ProxyMapper`.
3. **User**: Look up the node's `User` in `Netmap.userProfiles`. If the profile is absent, return nil (notes §4.1 item 3. Lead session confirmation H11 required). Return nil for nodes with an empty `StableID` too (the first adopter rejects them).
4. **Name**: `name` is `Node.name` with one trailing dot removed. `computedName` follows the rules of Go's `Node.ComputedName` (notes §4.1 item 5, `tailcfg/tailcfg.go:660-689`): ① Find the local tailnet suffix. Strip all leading and trailing dots from the local node's `Name` and take the part after the first dot, or use the whole name if there is no dot (`types/netmap/netmap.go:256-270`). ② Strip that suffix from the node's `Name` as in Go's `dnsname.TrimSuffix`: remove it only if it matches **at a label boundary** (ends in `.` + suffix), then remove the trailing dot (`util/dnsname/dnsname.go:203-239`). Thus `rd-a.xtail0001.ts.net.` does not lose `tail0001.ts.net`. **A node shared from another tailnet has a different suffix, so its FQDN remains without a trailing dot.** ③ If empty, strip `.local`, `.localdomain`, or `.lan` from `Hostinfo.Hostname` and sanitize it with Go's `dnsname.SanitizeLabel` (truncate to 63 characters, drop nonalphanumeric characters at the start and end, replace internal separators with `-`, discard characters not usable in DNS, and lowercase. The result must match that Go function. `dnsname.go:162-200`). ④ If that too is empty, use the public node key text (`nodekey:` + hex). Use the same rules for the local node and all peers (`control/controlclient/direct.go:1419-1434`). W2 and W3 match Go's address lookup. W1 and W5 differ from Go by following the data plane (W1). W3's rejection of an empty `StableID` is a first adopter policy absent from Go (notes §10).
5. **Local address**: Return the local node's identity (same as Go). A connection dialed to the local address (`SwiftailNetstack.md`, behavior N3) identifies the local node as the peer. However, if the netmap also assigned that address to a data-plane peer (it can send packets from that address), return nil because a connection from that address cannot be distinguished as local or from that peer (fail closed).
6. **Consistency**: `whoIs` reads the node's owner table inside the node actor. The engine builds that table in the same computation that installs peers, and the stack's owner check (`SwiftailNetstack.md`, behavior X10) switches to the same table at the same time: when applying a netmap and when the engine handles key expiration and changes peers (an address owner can change without a new netmap. If two nodes have the same address in a netmap, the other node gets it when the owner's key expires). Connections for addresses whose owner changed are closed then. The answer for a live connection's remote address therefore belongs to the peer that made the connection and does not depend on when the query is made. Querying an address from an already closed connection may return the new owner (behavior B2 closes this gap).
7. Keep full addresses and login names out of logs.

Decisions from implementation (M7-1, updated to follow W1 on 2026-11-17, updated again in the second security verification round that day): The node holds the address table (`TailnetNode.addressOwners`). Right after the engine applies a netmap or handles key expiration and recomputes peers, the node replaces the table with the engine's table and compares stack owners at the same point. If there is no engine (before registration), run the same computation directly on the netmap. Previously each query recomputed from `lastNetmap` using the wall clock at query time, but the stack's owner table changed only when applying a netmap. The instant the owner's key expired, an answer for a live connection could differ from the peer that made it. If multiple nodes have the same address, use the node that the engine assigned the address to (the lower node ID). If that node lacks a `StableID` or profile, return nil without falling back to another node. `whoIs` is a method on the `TailnetNode` actor, so call it with `await` from outside. At M7-1, `PeerIdentity`'s init was internal to `Swiftail` and `whoIs` supplied the values. A public initializer was added on 2026-11-16 to support testing consumers without a node.

### D. Control Server `set-dns`

1. `ControlClient.setDNS(name:value:)` sends `POST /machine/set-dns` with the **same Noise client** (`ControlClient`) as the map stream. See notes §3.2 for the body and headers (`Content-Type`, node key load-balancing header). `Version` is the declared CapabilityVersion (148), and `NodeKey` is the current public node key. Sharing the Noise client and sharing the physical HTTP/2 connection are distinct: Go uses the same Noise client but does not guarantee a single connection (notes §3.2, `control/ts2021/client.go:254-290`). Swiftail's `ControlClient` holds one connection during `run()` and sends on a new stream on it, but that is Swiftail's implementation choice and there is no evidence the server requires it. No other behavior relies on "the same connection."
2. **Swiftail's choice**: If there is no control connection (reconnecting), wait until it comes up. The deadline is 60 seconds. Go fails immediately with `not connected` if there is no control client (notes §3.2, `ipn/ipnlocal/local.go:7820-7839`). If registration is incomplete (missing or zero node key), fail immediately as Go does.
3. **Swiftail's choice**: Read up to 4KiB of the response body. If the status is not 200, include only the status code in the failure (do not log the body either. Its contents are unknown). For 200, the body must be a JSON object (empty body, `null`, and arrays fail). This is narrower than Go: Go reads up to 1MiB of the Noise response, includes up to 200 code points of the body in the error for non-200, and accepts one JSON value for 200 (`null` passes too. Notes §3.2). Do not describe these three choices as "same behavior as Go."
4. `name` accepts only `_acme-challenge.` + the node's own cert domain. There is no public API for publishing other names (this is a `package` interface called only by `CertificateManager`).
5. Notes §8: It is unknown whether the production server replies after publishing the record to authoritative DNS. As in Go, proceed immediately after receiving the reply (behavior C6).

Decisions from implementation (M7-2): Return `ControlError`. Non-200 returns `http(status:)` (the body is not read). Return `connection` on expiry of the 60-second deadline (which covers waiting for the connection and the response), on disconnect, for a response over 4KiB or with a non-object body, or before registration. Empty name or value and names violating D4 return `invalidConfiguration`. An "established connection" has completed registration. The node's `setDNS` returns `connection` unless `.running`, and sends only if the name is `_acme-challenge.` + the node's own FQDN (no trailing dot) and that FQDN is in cert domains. `ControlClient.setDNS` is `package` ("no public API" in D4).

### C. Certificate Issuance

Structure: ACME message creation and parsing and the order procedure are value types with no sockets or clock (plan §5, Code Standards). Pass the account key and certificate key as arguments. Inputs are HTTP responses and time. Outputs are "send this request," "publish this record," "wait this long," "finished (chain)," and "failed (reason)." `CertificateManager` drives the procedure by connecting it to `URLSession` and the node. One exception: CryptoKit draws randomness internally for ECDSA signatures, so signature bytes differ on each run. Tests verify signatures instead of comparing their bytes.

1. **Prerequisites**: Check in this order. ① If the node is not `.running`, `nodeNotRunning`. ② If MagicDNS in the netmap is off (`DNSConfig.Proxied` is false, the origin of Go's `MagicDNSEnabled`, `ipn/ipnlocal/local.go:1541`, DNS notes §3), `magicDNSDisabled` (a condition the first adopter checks. Notes §4.2 item 9). ③ If `DNSConfig.CertDomains` is empty, `httpsNotEnabled`. ④ If the node's own name (FQDN without trailing dot) is absent as an **exact** match in that list, `domainNotAllowed` (notes §4.2 item 9). Report all four in `status` without time-based retries (`nextAttempt` is nil). Recheck only when node status or the netmap changes, or when `retryNow()` is called (behavior R4).
2. **Name validation**: Validate the name before it becomes a filename and a DNS record name. Path safety and DNS name validity are separate checks. Go's `validLookingCertDomain` checks the path only and does not validate every DNS label (notes §§4.2 item 9 and 10). Swiftail covers both with DNS name rules (RFC 1034 3.1 and 3.5, RFC 1123 2.1, notes §10). After removing one trailing dot, the name must ① contain at least two dot-separated labels, ② have 1–63 characters per label, with **alphanumeric first and last characters** and only alphanumerics and `-` inside, ③ be at most 253 characters without the trailing dot, and ④ be at most 253 characters after adding `_acme-challenge.` for the record name (so the name itself is at most 237 characters). Reject names whose final label consists only of digits (see the certificate target review fixes). Accept lowercase letters only (this contract narrows the accepted names to avoid collisions on case-insensitive file systems because they become filenames). Do not issue for invalid names and report `domainNotAllowed` (wait for a netmap change. Lead session confirmation H23 required). These rules exclude `..`, `/`, `\`, `:`, NUL, `*`, and underscores automatically (wildcard exclusion in notes §6). All these allowed characters fit the CSR's `PrintableString` (behavior C7, notes §3.6).
3. **Stored certificate first**: Read the files for that name in `certs/` and verify per behavior S3. If valid and before the renewal time (behavior R1), emit it without issuance.
4. **Account**: Use **only P-256** account keys (notes §6: Tailscale generates only P-256 account keys). Read `certs/acme-account.key.pem` (up to 64KiB) as a PKCS#8 or SEC1 P-256 key (Go writes SEC1 and tries PKCS#1, PKCS#8, then SEC1 when reading. Notes §3.7, the two key formats read by S3 ③ were verified in notes §4.6). Generate, save, and use a new key **only if the file is missing**. If the file exists but cannot be read as a P-256 key (an old Go RSA account key, corrupt file, or too large), do not treat it as absent. End `run()` with `CertificateError.accountKeyUnreadable`. This avoids overwriting and losing Go's account (notes §4.8 "Accounts and concurrency," `feature/acme/certstore.go:361-388`). Other read errors are `storage`. Look up the account (`onlyReturnExisting`), and on `accountDoesNotExist`, agree to the terms and create it. Fail unless account `status` is `valid` (notes §4.3 items 3 and 4). Keep the account URL (`kid`) only in memory (look it up each time on startup). Read, generate, and register the account key one at a time in the `CertificateManager` actor (equivalent to Go's `accountMu`. Notes §4.8). This runs only within the single flow in behavior C9, so actor reentrancy cannot cause overlap.
5. **Order**: One identifier, the node's own name of type `dns` (`{"identifiers":[{"type":"dns","value":"<name>"}]}`). The response's `identifiers` (201, `Location` is the order URL) must match the requested set. **Do not require a specific authorization count**. Identifiers and authorizations are not guaranteed to correspond 1:1, and the array order is not relied on (RFC 8555 7.1.3 and 7.4, notes §4.3 item 5). Set only an upper bound (8, limits table). Exceeding it, or a `pending` order without authorizations, yields `unexpectedResponse`.
   - **Branch on order status first** (RFC 8555 7.1.3 and 7.1.6): `pending` → handle authorizations below. `ready` → skip authorization and go to finalize in C7. `valid` or `processing` → no CSR has been sent for this order, so there is no corresponding private key. Start over with a new order without accepting that certificate (once per attempt. Lead session confirmation H17 required). `invalid` → `orderFailed`. Unknown status → `unexpectedResponse`.
   - **For each authorization** (all of them, any order): Read with POST-as-GET. Require `identifier.type` to be `dns`, the value to equal the requested name, and `wildcard` to be other than true. Otherwise end the attempt with `unexpectedResponse`. By status (RFC 8555 7.1.4 and 7.1.6, notes §4.3 item 6): `valid` → already complete. `pending` → select the first challenge with `type` equal to `dns-01` (`unexpectedResponse` if absent). If the challenge is `pending`, do C6. If `processing`, publish only the C6 record and do not send the response again. If `valid`, skip it. If `invalid`, return `validationFailed`. Authorization `invalid` → `validationFailed`. `deactivated`, `expired`, or `revoked` → cannot continue the order (`orderFailed`). Unknown status → `unexpectedResponse`. Go always responds to dns-01 without checking authorization or challenge status (notes §4.2 item 7). Swiftail's branches fail closed more often.
6. **Record and response**: Send behavior D's `set-dns` with the value from notes §3.5. On success, POST `{}` to the challenge URL (200 and 202 are success. Notes §4.3 items 7 and 8). Do not look up the TXT record in advance (notes §6).
7. **Waiting, finalize, and download** (RFC 8555 7.4, notes §4.3 items 9–12):
   - **Waiting**: After responding to the challenge, reread the order URL with POST-as-GET (same as Go. The typical flow in RFC 8555 7.5.1 reads the authorization. Notes §4.3 item 9). Use behavior X5's `Retry-After` or 1 second if absent (1 second is Go's choice, not an RFC constant. Notes §4.3 item 9). `pending` → reread. `ready` → finalize. `invalid` → reread each authorization for the order once and return `validationFailed` if any is `invalid`, else `orderFailed` (an `invalid` order can be caused by DNS verification failure, expiration, or rejection of the CSR or issuance. Notes §10). `valid` or `processing` → no CSR has been sent, so start over with a new order as in C5 (H17). Unknown status → `unexpectedResponse`.
   - **Finalize**: When `ready`, generate a **new P-256 key** (distinct from the account key. RFC 8555 11.1) and finalize using a CSR (notes §3.6. The subject CN is a `PrintableString` as in Go). Retain the key and CSR until the order ends. Branch immediately on the finalize response's `status` (200 and order object): `valid` → download. `processing` → reread the order at X5 intervals until `valid` (if it becomes `invalid`, classify as above). `invalid` → classify as above. `ready` → send finalize once more with the **same key and CSR**. `pending` → handle the order's authorizations again per C5, then finalize with the same key and CSR. Repeat for `ready` or `pending` only once per order. The second time yields `unexpectedResponse` (H17). Unknown status → `unexpectedResponse`. If finalize returns 403 `orderNotReady`, reread the order and take the branch for its status (error table in notes §4.3). If not `valid`, Go waits with `WaitOrder` without branching and finalizes with a fresh key for either `ready` or `valid` (notes §4.2 item 6, §9 V110). Swiftail does not do this.
   - **Download**: POST-as-GET to the `certificate` URL, `Accept: application/pem-certificate-chain` (Swiftail's choice. Go does not set an explicit `Accept`. Notes §4.3 item 12). Parse per behavior X3.
8. **Verify the received chain**: Behavior X3. On success, save the key file followed by the certificate file (behavior S2) and emit on `certificates`. On failure, save nothing. Verifying key, name, validity, and chain before storage is a stronger boundary than Go's (Go does not directly verify a newly received chain before saving. Notes §4.4 item 5). Trust anchors follow S3 ⑤: system roots only in production, explicit anchors in tests.
9. **One at a time**: Issuance runs serially inside `run()`. Two orders are never sent concurrently. Account preparation (C4) also runs only in this flow. `retryNow()` and netmap changes only wake waits and do not separately start issuance. Do not create two `CertificateManager` instances for one node (nothing prevents two managers or processes from using the same `certs/`. Go's lock is not an interprocess file lock either. Notes §4.8. Document this in a doc comment).
10. **Deadlines**: 30 seconds per HTTP request and 5 minutes per issuance attempt. On timeout, return `timedOut` and discard the order (the next attempt uses a new order). If `Retry-After` gives a time past the deadline, end the attempt immediately without waiting for it. Keep the time in `status.nextAttempt` (behavior X5).
11. **User-Agent**: `Swiftail/<version>` (RFC 8555 6.1. Lead session confirmation H13 required). Do not imitate Go's `tailscaled/…`.
12. **Problem documents** (RFC 8555 6.7, RFC 7807 3.1, notes §4.3): Including a problem document in an error response is only a SHOULD, and `type` can be an ACME URN, server-specific URI, or `about:blank`. The error therefore holds the HTTP status and full problem document `type` string (`acme(status:type:)`). If the body is not a JSON object or `type` is missing or not a string, set `type` to an empty string (do not fill it with RFC 7807's default `about:blank`). Truncate `type` to 256 bytes (at a UTF-8 character boundary). Ignore `detail`, `title`, `instance`, and `subproblems` (including their `identifier`). They can contain identifiers and must stay out of public types (behavior K2). Swiftail handles special types only when `type` **exactly equals** `urn:ietf:params:acme:error:` + the name: `badNonce` (X4), `accountDoesNotExist` (C4), `rateLimited` (`CertificateFailure.rateLimited`, X5), and `orderNotReady` (C7). Every other `type`, including `userActionRequired`, is `acme(status:type:)`. The `error` of an order or challenge is also a problem document and supplies the `type` of `orderFailed` or `validationFailed` by the same rules.

Decisions from implementation (M7-3): Write the JWS protected header with the same serialization as Go's `jwsEncodeJSON` (member order `alg`, `kid` or `jwk`, `nonce`, `url`, no spaces, strings escaped as in Go's `json.Marshal`, e.g. `\u003c`). Test 6 can therefore require matching header and signing input bytes against Go. Assemble the CSR's SubjectPublicKeyInfo directly with DER writing, and pin byte equality with CryptoKit's `derRepresentation` in a test. The fixed key's (RFC 7515 A.3) `certificationRequestInfo` matched the bytes from Go's `x509.CreateCertificateRequest` (go1.27.3) (one-time check by the implementation session. Reference data in M7-8).

Decisions from implementation (M7-4): The order procedure is the value type `ACMEOrderFlow`, with outputs `send`, `wait(until:)`, `publishTXT`, and `finished`. Take the certificate key as input per attempt and create the CSR at first finalize, reusing it for that attempt (C5's new order is before the CSR, so it uses the same key). Account creation sends `termsOfServiceAgreed` even without a terms URL, and a non-`valid` account is `unexpectedResponse`. `ready` and `pending` after finalize is rejected with `orderNotReady` also count toward H17's one repeat. A single request timing out is `timedOut`, and failure to reach the server is `network`. Because `CertificateFailure` is not an `Error`, the TXT publication closure returns the failure without throwing it.

Decisions from implementation (M7-6): If facts change during issuance (name change, node stops), allow the attempt to finish. The next decision sees the changed facts and clears any wait for conditions set by that attempt's failure. Read the stored certificate once per name. Map `set-dns` `ControlError` as follows: `http(status:)` → `controlRejected`, `invalidConfiguration` → `domainNotAllowed`, others → `network` (fixed message). When `run()` returns, `certificates` ends too. If the node facts stream ends, treat it as `nodeNotRunning` and wait for cancellation. The test interface is an `internal` init (facts stream, `setDNS`, state directory, transport, anchors, clock, sleep, and certificate key generation).

### S. Storage

1. **Location and names**: Under `<state directory>/certs/`, store `<name>.crt` (chain, `CERTIFICATE` PEM blocks starting with the leaf), `<name>.key` (private key PEM), and `acme-account.key.pem` (account key PEM). Location and names match Go (notes §3.7, DNS notes §4.9 item 1. Lead session confirmation H7 required). **Permissions**: Create `certs/` with 0700. Leave existing directory permissions as they are (Go's `MkdirAll` does too. Creation permissions do not replace checks on existing entries. Notes §§3.7 and 4.8). If existing `certs/` is writable by the group or others, fail without using it (`run()` ends with `CertificateError.storage`). Do not read from such a directory either because another user may have substituted a key or account key (lead session confirmation H20 required).
2. **Writes**: Write keys with CryptoKit's `pemRepresentation` (PKCS#8 `PRIVATE KEY`) (Go can read it. Notes §4.6). **All newly written files use 0600** (key, account key, certificate). Go writes certificates with 0644 (notes §3.7), but Swiftail keeps certificates at 0600 too (a different choice from Go. Go running as the same user can read them as-is). For each file, write it in full to a temporary file in the same directory, set permissions, flush to disk, and rename it (same order as Go's `atomicfile`. Notes §3.7). Write the key file first and the certificate file second (same as Go). **Writing both files is not a transaction** (nor is it in Go. Notes §3.7). Stopping between them leaves a new key and an old certificate. Thus S3 ④ verifies the key and certificate match when reading, and treats a mismatch as absence (new issuance rewrites both).
3. **Reads and verification**: ① Read both files (up to 64KiB each). ② Check the whole certificate file as in behavior X3 ①: only `CERTIFICATE` blocks, 1–5 certificates. ③ Read P-256 keys in both PKCS#8 and SEC1 (`EC PRIVATE KEY`) formats (Go-written files. Verified in notes §4.6). ④ The leaf's public key must match the key's public key (catches a stop between the two files in S2). ⑤ Verify the chain for the name and current time (`SecTrust`, SSL server policy). **Use only system roots in production**. This differs from Go: if system roots fail, Go retries with built-in Let's Encrypt roots, and for nonproduction directories accepts a final "unknown certificate authority" error (notes §4.4 item 5, `feature/acme/certstore.go:440-477`). Swiftail has no built-in roots and does not adopt that nonproduction exception. Provide explicit anchors under X3 for tests and staging. When provided, use only those anchors. Treat any failure as if no stored certificate exists (leave the files in place. New issuance overwrites them). A corrupt certificate triggers new issuance, but a corrupt account key is a failure (C4. Notes §4.8 distinguishes them).
4. If the name changes (node name or tailnet name change), issue for the new name. Leave the old files (`shortcut:`).
5. When used on iOS, use the same protection class and backup exclusion as `identity.json` (`SwiftailTunnel.md` behavior P 2). Excluded from M7 (exclusions table).
6. **Contents of `chain`**: The chain starts with the leaf (RFC 8555 7.4.2). The root may be omitted from the response but need not be (RFC 8555 9.1, notes §3.7), so the server may include it. **After** verifying the full received chain per S3 ⑤ and X3 ④, remove the trust anchor selected by evaluation from the non-leaf certificates (the one with the same DER as the last certificate from `SecTrustCopyCertificateChain`) and emit the result as `TailnetCertificate.chain` (originally, all certificates with equal subject and issuer were removed. That also dropped self-issued intermediates used for key rollover, so the peer could not build the chain. Fixed in review, 2026-11-15). Write the received chain as-is to the file (`<name>.crt`) (same as Go. Notes §3.7). M7-5 checks the Security API for comparing subject and issuer against the SDK declarations (§9).

Decisions from implementation (M7-5): Open and check `certs/` with a directory descriptor (`O_NOFOLLOW`), then use `openat` and `renameatx_np` for its files. A symbolic link, ownership by someone other than the current user (an additional fail-closed check in this unit), or group or other write permissions yields `storage`. Do not follow file links and read only regular files. Read errors other than absence (link, nonregular file) are `storage` even for certificate files. Only exceeding 64KiB or failures in parsing, matching, or verification count as "absent." Write account keys with `RENAME_EXCL` to avoid overwriting an existing file. Do not create the state directory (if missing, writes are `storage` and reads mean absence). The original M7-5 implementation compared the bytes of `SecCertificateCopyNormalizedSubjectSequence` and `…IssuerSequence` (`SecCertificate.h`, macOS 10.12.4 and iOS 10.3). Review replaced that check with removal of the evaluated trust anchor, as specified in S6.

### R. Renewal and Retry

One value type makes the decision. Inputs are the current time, the node's condition (state, name, cert domains), the certificate's validity period, the last failure, and the consecutive failure count. Outputs are "issue now," "wait until this time," and "wait for a condition." Tests pass time to run deterministically.

1. **Renewal time**: Renew after `notBefore + (notAfter − notBefore) × 2/3` (notes §4.4 item 1. Go uses this rule when ARI lookup fails). Do not use ARI (lead session confirmation H6 required). This rule **does not** guarantee staying below Let's Encrypt's rate limits (notes §4.5, §9 V168): new certificates for the same identifier set are limited to 5 in 7 days, including renewals without ARI. Only orders recognized as ARI renewals are exempt from all limits. To qualify, at least one identifier must overlap with the previous certificate in `replaces`, and that certificate must not have been replaced through ARI yet. Certificate lifetime (production default of 64 days starting 2027-02-10, optional 6 days), other issuances for the same name (deleting state and reissuing, ephemeral nodes), and authorization failure limits also apply.
2. **During renewal**: Continue using the current certificate. Even if renewal fails, emit nothing on the stream before expiration. Once expired, `status.notAfter` retains the past time and the app sees it.
3. **Wake points**: Start of `run()`, changes in node state, name, cert domains, or MagicDNS, renewal time, retry time, and `retryNow()`. In every case, send no requests to the ACME server before the time it specified with `Retry-After` (behavior X5).
4. **Retry interval**: Failures requiring user action have no time-based retry. Back off and retry other failures (Let's Encrypt limits are in notes §4.5).

   | Failure | Next attempt |
   | --- | --- |
   | User action required (`magicDNSDisabled`, `httpsNotEnabled`, `domainNotAllowed`) | No time-based retry (`nextAttempt` is nil). Recheck only on netmap change or a call to `retryNow()` |
   | Node not running (`nodeNotRunning`) | When node state changes (`nextAttempt` is nil) |
   | Unreachable, timeout, or 5xx (`network`, `timedOut`, `acme` with 5xx status), `controlRejected` | Start at 30 seconds and double each time, cap at 10 minutes (first adopter's current values) |
   | Verification failure (`validationFailed`), `orderFailed`, `unexpectedResponse`, other `acme` | Start at 15 minutes and double each time, cap at 6 hours. In the authorization failure limit (5 per hour, refill one per 12 minutes), One token per 12 minutes is the token bucket refill rate (notes §4.5, §9 V164). It imposes no minimum interval between requests. Starting at 15 minutes keeps retries slower than the refill rate. Failing indefinitely every 6 hours eventually reaches the consecutive failure limit (1,152), after which the server replies with `rateLimited` (notes §4.5) |
   | `rateLimited` | Time given by the server (behavior X5, capped at 7 days). If absent or sooner than 15 minutes, wait 15 minutes |
   | `invalidCertificate` | After 6 hours (an issuance was already used. New certificates for the same name are limited to 5 in 7 days) |

   For any row, if the X5 `Retry-After` time is later than the table time, it is `nextAttempt`. `run()` throws `CertificateError` (`storage`, `accountKeyUnreadable`) and does not retry.
5. Clear the consecutive failure count and `lastFailure` on success.
6. Use the wall clock (`Date`) for certificate times. A substantially incorrect device clock causes verification to fail with `invalidCertificate`. Go also does not compensate for clock skew (notes §4.4 item 6). Decisions take time as input and reread the current time after a long wait (`Retry-After`, retry) (notes §4.4 item 6).

Decisions from implementation (M7-5): The exponent for doubling the interval is the consecutive failure count within the same row. When the row changes, start with the initial interval in the new row. No jitter (no formula was specified, and the requests come from one node acting alone). Retain the `Retry-After` time separately from failure history, and do not clear it on a later prerequisite failure or success. A change in prerequisites only ends a wait for prerequisites and leaves backoff intact (`retryNow()` ends both).

Decisions from implementation (M7-6): Do not record unmet prerequisites from C1 and C2 in `RenewalSchedule`. The manager determines them from facts (to avoid clearing the backoff or consecutive failure count). `status.lastFailure` is the unmet prerequisite if there is one, otherwise the last attempt's failure. `retryNow()` does nothing before `Retry-After`, even while waiting for prerequisites.

### X. Untrusted Input

ACME server responses, control server responses, files on disk, and other loopback processes are untrusted. No input may cause a crash.

1. **URL**: Directory, order, authorization, challenge, finalize, and certificate URLs must use `https` and be at most 2,048 bytes. Otherwise return `unexpectedResponse`. Reject userinfo and strings whose characters change when converted to `URL` (spaces, invalid `%`), because the signed `url` differs from the actual request. **Send requests only to URLs with the same origin (scheme, host, port) as the directory**. TLS verified only the directory server, so do not follow a URL supplied by it to another host (including loopback) with an account-key-signed request. RFC 8555 does not require the same origin, but Let's Encrypt and pebble host all resources at the directory's origin (initially unrestricted, tightened after review, 2026-11-15). Do not follow redirects. Put the string from the server into the JWS `url` verbatim without re-encoding (RFC 8555 6.4, notes §4.8). These limits are Swiftail's: Go's ACME path uses `http.DefaultClient`, follows redirects, and does not cap URL length (notes §4.8).
2. **Body and headers**: Read up to 64KiB for JSON responses and 256KiB for certificate chains. Excess yields `unexpectedResponse`. These limits differ from Go's (Go caps the chain body at 5,401,755 bytes and does not check per-certificate size. Notes §§3.7 and 5, §9 V213). Ignore unknown fields. Use `Replay-Nonce` only if it is 1–512 bytes of base64url characters, and ignore it otherwise (RFC 8555 6.5.1. Go does not check it. Notes §4.3 item 2). See behavior X5 for `Retry-After`. `token` must be 1–512 bytes of base64url characters only (RFC 8555 8.4).
3. **Received chain**: ① Check the entire input from start to finish. Discard the entire chain if anything other than `CERTIFICATE` follows any `-----BEGIN`, a block cannot be parsed, or there are non-whitespace bytes outside blocks (RFC 8555 9.1 and 11.4, notes §3.7. Go's `pem.Decode` loop stops where parsing fails without rejecting what follows). ② Require 1–5 certificates. ③ The leaf's public key matches the newly generated key's public key. ④ The chain verifies for the name and current time (anchors in S3 ⑤). ⑤ `notAfter − notBefore` is at least 1 hour (prevents renewal decisions from spinning). In tests, give verification trust anchors as a `package` initializer argument (roots for the local ACME server and staging. Equivalent to Go's `testRoots`, using only those anchors if specified). Do not adopt Go's branch that ignores "unknown certificate authority" errors for nonproduction directories (notes §4.4 item 5). On success, build `chain` per behavior S6. Decisions from implementation (M7-5): apply ①–⑤ to chains read from disk (S3) with the same verification. Production uses default `SecTrust` anchors (OS trust store) and does not fetch missing intermediates over the network (`SecTrustSetNetworkFetchAllowed(false)`). Obtain the validity period from `SecCertificateCopyNotValidBeforeDate` and `…AfterDate` (macOS 15 and iOS 18). Decisions from implementation (M7-3): inside blocks, use the standard grammar in RFC 7468 §3 without enforcing line lengths, and skip whitespace-only lines. An empty body or mismatched BEGIN and END labels makes a block unparseable. Key files (S3 ③, C4) accept exactly one `PRIVATE KEY` or `EC PRIVATE KEY` block.
4. **`badNonce`**: If the error's `type` is `urn:ietf:params:acme:error:badNonce` (behavior C12), sign the same request again with the nonce from that error response and resend it (RFC 8555 6.5). Up to 3 times per request. Hold only the nonce from the last response. Go adds the response nonce, then clears all held nonces and gets another with HEAD. Do not adopt this (notes §4.3).
5. **`Retry-After` and indefinite waits** (RFC 8555 6.6 and 7.4, RFC 7231 7.1.3, notes §§4.3 and 10): Parse `Retry-After` as a nonnegative integer in seconds or an HTTP date. Treat other values as absent. Convert dates to wall-clock times. If in the past, do not wait.
   - **Send no new requests to that ACME server** before the time it gives. "That server" means every URL obtained from that directory (lead session confirmation H21 required). Do not shorten valid values with caps such as 30 seconds or 24 hours to send earlier.
   - Reread orders at the `Retry-After` interval, or 1 second if absent. If shorter than 1 second, use 1 second (only delay further).
   - If a time received while waiting for an order exceeds the issuance attempt's deadline (5 minutes in behavior C10), end the attempt with `timedOut` without waiting. Error responses (`rateLimited`, 5xx, etc.) end the attempt even if the time is within the deadline (behavior R4). In both cases preserve the supplied time in `status.nextAttempt` (use R4's time if later). Even `retryNow()` sends no requests before then.
   - Cap unreasonably distant values (more than 7 days) at 7 days. This caps only the upper end of the "next attempt" time. It does not permit a request within a server-imposed wait of 7 days or less. Local state (netmap, stored certificate) can be rechecked at any time and does not count as a request.
   - Behavior C10's 5-minute deadline stops orders that remain in `processing` or `pending`.
6. **Control server**: Read `set-dns` responses within behavior D3's limits. The control server sets the netmap's `CertDomains`. It already determines this node's name and peers, so it gains no wider authority.
7. **Disk**: Read certificate and key files in `certs/` per behavior S3. Treat oversized or unparseable files as absent. Behavior C4 covers the account key file (fail if unreadable), behavior S1 covers directory permissions, and behavior G2 covers Go state files.
8. **Other loopback processes**: Behaviors B6 and B7.

Decisions from implementation (M7-4): `Retry-After` in any response blocks all requests until that time. Read all three HTTP date formats from RFC 7231 7.1.1.1. The plaintext `http` path for tests exists only in the transport (test initializer argument for `URLSessionACMETransport`, loopback hosts only), and the order procedure always accepts only `https`. The `User-Agent` version is a transport constant (`Swiftail/0.1.1`) because the repository has no version string.

### B. Loopback Bridge

```
iPhone ──tailnet(WireGuard)── TailnetConnection ── LoopbackBridge ── 127.0.0.1:P ── NWListener(TLS) ── HTTP server
        (TLS terminates between the iPhone and NWListener. The bridge carries TLS records)
```

1. **`forward` sequence**: ① If 256 connections are being bridged, return `limitReached`. ② Call `node.whoIs(connection.remoteEndpoint.address)`. Return `unknownPeer` if nil. ③ Dial plaintext TCP to `127.0.0.1:<port>` (IPv4 loopback only, 5-second deadline). On failure, `loopbackUnavailable`. ④ Read the local port of the loopback connection and record a fresh single-use token (32 bytes, `SystemRandomNumberGenerator`) in the "pending tokens" table as `token → ((source port, listener port), Origin(remote endpoint, identity from ②))`. The table refuses if the key is already pending, remains as an unclaimed grant, or the limit (256) has been reached. In that case **keep the socket open and retry from ③** (holding it prevents the kernel from giving out the same source port again, up to 3 attempts total). If all three are refused, return `loopbackUnavailable`. Reset the held sockets without sending tokens (the server sees connections end without becoming ready). ⑤ Send the token as the first bytes of the loopback connection (`loopbackUnavailable` if it cannot be sent). ⑥ Then start copying in both directions. ⑦ At the end, **remove the unconsumed token before** closing the loopback connection. On failure, send a TCP RST on `connection` in ①–③ and on both connections in ④ and ⑤.
2. **Identity is fixed to the connection**: The identity verified in ② is its identity for the life of the connection. If the address owner changed between ② and SYN, the node already closed the connection (`peerRemoved`), so reads fail immediately and no bytes cross. The old owner's bytes are therefore never processed under the new owner's identity. This guarantee is lost if the server calls `whoIs(address)` again for each request: a request still buffered on the loopback side after the connection closes could be read under the new owner's name (lead session confirmation H3 required, first adopter confirmation F1 required).
3. **Copying**: Tailnet → loopback writes the chunk from `read(upTo: 65_536)` to loopback and **waits for the network stack to take it** before reading again. Loopback → tailnet writes each chunk received from loopback and waits for `write(_:)` to return before receiving the next one. The bridge holds one chunk per direction (at most 64KiB). The slower side stops the faster side (receive-window and `write` backpressure carry through).
4. **Half-close**: If the tailnet side closes writes (`read` returns nil), send FIN to loopback and keep forwarding in the opposite direction. If the loopback side closes, call `finishWriting()` and keep forwarding in the opposite direction. `forward` returns once both directions finish.
5. **Disconnect and cancellation**: An error on either side (`reset`, `timedOut`, `peerRemoved`, loopback failure) resets both connections (tailnet `abort()`, loopback `forceCancel()`). The same applies if the Task calling `forward` is canceled or the node stops (`notRunning`). A loopback RST after loopback → tailnet has already ended with FIN is discovered on the next write to loopback. If the tailnet side neither writes again nor closes, `forward` remains pending until then (unrelated to identity. B6).
6. **Only a bridge-opened connection gets an identity** (M7-9b): ① The bridge protocol (`NWProtocolFramer`), below TLS and directly above TCP in the listener stack, reads the first 32 bytes and finds and consumes the matching pending token by **comparing all of them in constant time**. Consume a matching token even if the key differs. ② Only if the token is for that connection's `(source port, listener port)` (both endpoints on `127.0.0.1`), record a grant (`Origin`) under that key, deliver any bytes already buffered upward, then enable pass-through (`passThroughInput`, `passThroughOutput`) and mark the connection ready. ③ Fail the connection if the token is missing, wrong, for another listener or source port, or if all 32 bytes do not arrive within 5 seconds (a connection that ends before sending all bytes also ends at that deadline. Before readiness, the framer gets no callback for the peer's end). No bytes are delivered upward, so they do not reach TLS. The server receives the connection through `newConnectionHandler` but sees `.failed` without `.ready` in `stateUpdateHandler`. ④ The server’s lookup returns the grant once and removes it. Neither the bridge (even when the connection ends) nor the framer's `cleanup` removes grants. When ending the loopback connection, the bridge only marks the remaining grant "bridge side ended." Removal happens only on lookup or when unclaimed grants exceed 256, in which case discard the oldest **among those whose bridge side ended** (lookup for that connection returns nil, fail closed). The bridge forwards up to 256 connections, so live connection grants are never evicted. A connection still being bridged always gets an answer when looked up after `.ready`. ⑤ While a grant with a given key remains, no new token is recorded for that key (B1 ④). ⑥ Lookup answers only for `.ready` connections. ⑦ The table uses synchronous calls protected by one lock. Keep tokens out of logs, error strings, and `description`.
7. **Server requirements** (the first adopter's responsibility, documented in doc comments): Bind the listener only to `127.0.0.1` and let the system choose the port. In the listener's `NWParameters`, add `bridge.makeListenerProtocolOptions()` to the **end** of `defaultProtocolStack.applicationProtocols` (`append`. Inserting at the front puts it above TLS and breaks the handshake with `bad protocol version`). Use one bridge per listener. For every accepted connection, call `origin(of:)` once **after `.ready` and before reading requests**, and close if nil. The grant is recorded before the connection becomes ready, so even plaintext listeners do not wait for the first byte. The answer comes once, so keep that `Origin` for the connection's lifetime. **Call `cancel()` on finished connections and release the reference to the `NWConnection`**. The socket of an accepted connection that ended before readiness closes when the object is released, and `cancel()` alone does not close it (see "Experimentally Verified" below). Retaining it leaves one server file descriptor per tokenless connection and the peer does not see the end.
8. **What other processes on the same device can and cannot do**: They can connect to the loopback port directly, bind to the bridge source port with `SO_REUSEADDR` and connect to another listener, or reuse a source port released after a bridge connection reset to connect to the same listener. In all cases, the missing token prevents readiness (B6 ③). The same holds if an unclaimed grant remains for that 4-tuple: the server asks only about ready connections and lookup answers only for ready connections. The token travels only within the loopback TCP connection between the bridge and that listener port, so observing it requires reading loopback traffic (root or BPF, out of scope). Taking over the listener port: the server passes its port number to `forward`, so if another process opens that port after the server dies, the bridge sends the token and TLS records there. That token is bound to the listener port and does not work on another listener (B6 ②), and the process cannot complete the handshake without the certificate key (contents are visible with a plaintext listener, which is for tests only). This does not prevent a process with the same user's permissions from reading the app's memory or state files (same as the first adopter's non-goals, RemoteDebug `docs/protocol.md` §12).
9. **Entitlements**: The loopback listener needs the App Sandbox incoming connection entitlement (`com.apple.security.network.server`). The bridge and node sockets and `URLSession` need the outgoing connection entitlement (`com.apple.security.network.client`). No other entitlements are used. Swiftail does not use the Keychain (it returns the chain and key as values). The M7-9b tests exercised TLS identity creation without the Keychain (`SecKeyCreateWithData`, `SecIdentityCreate`) outside the sandbox on macOS (the TLS listener completes the handshake with a self-signed certificate). Running inside the sandbox and "no Keychain writes" were unverified (notes §§4.6 and 8, §9 V188, V189, and V191). **Subsequently verified (2026-11-15, first adopter's sandbox probe. macOS 27.2, Swiftail `e56b8c8`, only `app-sandbox`, `network.client`, and `network.server` entitlements)**: ① An `NWListener` with TLS and the bridge framer appended becomes ready on loopback, and TLS round trip through `LoopbackBridge.forward` on a memory device node passes. `origin(of:)` returns a value once, then nil. A direct connection without a token fails before readiness. ② The handshake completes with an identity created by `SecKeyCreateWithData` → `SecCertificateCreateWithData` → `SecIdentityCreate`, and the login Keychain's item count and metadata hash are unchanged (other Keychain backends were not checked). ③ The storage directory in the container is 0700, and files are 0600 (real issuance and `CertificateManager` storage and reload paths remain. Only file I/O was checked). ④ No local network permission dialog appeared and there were no sandbox denial logs. Production issuance, iPhone, and the installer in gate (b) 7 remain. Do not use this as the basis for implementation. **The first adopter session verifies it in the sandboxed version** (first adopter review result 5. If blocked, the first adopter uses the Keychain and the Swiftail API stays the same).
10. **Cost**: Bytes traverse Swift TCP → copying by the bridge → kernel loopback TCP → TLS. Measure throughput and CPU for a 4GiB transfer at the gate.

Decisions from implementation (M7-9): Reset loopback with `NWConnection.forceCancel()` (the plaintext server's read ends with `ECONNRESET`. `cancel()` sends FIN), and close writes with an empty `finalMessage`. Task cancellation does not close the loopback socket, so B1 ⑦ also holds on cancellation. Disconnects after bridging begins clean up and return without throwing (only cancellation throws `cancelled`). One function closes loopback (`endLoopback`), and tests inspect the table immediately before closing through a hook in the internal init.

#### Review Fixes (M7-9b)

Another session reviewed the M7-9 bridge and reproduced **failure of the source port table as an authentication boundary** using a plaintext listener (the server looked up after the first byte per the contract).

1. The table key was only the source port. While the bridge connected to listener L1 (source port P), another process could bind to `127.0.0.1:P` with `SO_REUSEADDR` and connect to a second listener L2 (the kernel accepts it because the 4-tuple differs). L2 got the identity of the L1 connection via P. Old and new listeners run together during certificate renewal (first adopter review result 3).
2. If loopback was reset, the kernel released the source port as soon as TCP reached CLOSED (even while `NWConnection` remained open). The table entry remained until the bridge noticed. If the server sent a response and FIN and closed, and the tailnet side then sent more, the bridge would not notice until the next write, leaving the window open indefinitely. Even while receiving, there was a gap between port release and removal.
3. Normal termination when the server sent FIN first theoretically had the same window because removal followed `finishWriting()`.
4. Tests did not catch an implementation deliberately broken to "close before removal" (`cancel` was asynchronous, so removal always won).
5. The test helpers' (`PlainLoopbackServer.swift`, same code in `NetworkSocketLoopbackTests.swift`) `read()` missed an end arriving with the final bytes, so the next receive failed with `ENODATA` (not a bridge defect). The waiting test did not respond to cancellation after failure.
6. B5's "close loopback when the node stops" actually used RST, and B1 ⑥ omitted RST in ④ (table insertion failed).

"The kernel keeps the 4-tuple of the loopback connection held by the bridge unique" (old B6 ③) holds only while the connection lives. The table did not distinguish listeners, and on peer disconnect the kernel released the port first. Callback-based removal leaves a scheduling-dependent gap.

**Revised design**: A single-use token inside the connection (B1 ④ and ⑤, B6). A reused source port, including use of the same port with another listener, lacks the token, so it cannot reach TLS or become `.ready` to the server. The grant key is `(source port, listener port)`, and the design does not depend on when entries are removed. Neither the bridge nor the framer's `cleanup` removes grants. A remaining grant belongs to the peer on the bridge connection that actually used that 4-tuple, and a new grant with the same key cannot replace it (B6 ⑤), so even a late lookup cannot get another peer. Fixes: In 3, close order is now independent of identity. For 4, consolidate closing in `endLoopback` and assert the table state just before close using a hook. For 5, both helpers remember the end and close the connection if waiting is canceled. For 6, update B1 and B5 wording.

**Experimentally Verified** (macOS 27.2, Swift 6.4.2, small standalone executables outside the tests and this target's tests):

- The `applicationProtocols` of `NWParameters(tls:tcp:)` list protocols from the top (app side). Using `append` puts the framer below TLS: it read the first 32 bytes of the TLS client's ClientHello. Using `insert(at: 0)` put it above TLS and both sides failed with `-9836 bad protocol version`. The same framer runs with a plaintext listener.
- If `start` returns `.willMarkReady`, the server's connection stays in `.preparing` until token verification and `markReady()`. On an incorrect token (`markFailed`), the server sees only `.preparing → .failed` and receives nothing. Without a token (a TLS client dialing directly), the first 32 bytes of ClientHello arrive in the token slot and fail verification. A connection that stalls after 10 bytes fails at the `scheduleWakeup` deadline.
- **An accepted connection that ends before readiness does not close its socket on `cancel()` or `forceCancel()`.** It closes when the `NWConnection` object is released. If the server called `cancel()` and retained a connection that went from `.preparing → .failed` with an incorrect token, the server's socket stayed in `CLOSE_WAIT` (20 connections left 20 descriptors, unchanged after 17 seconds, checked with `lsof`), and the TLS client that dialed without a token stayed in `.preparing`. Releasing the references closed all sockets within 2 seconds. This also happened without the framer: a connection canceled before the handshake on a TLS listener with no framer behaved the same way. Connections canceled after readiness closed immediately (FIN) even when retained. The behavior was unchanged when replacing `markFailed` with `markReady()` followed by `markFailed`, calling `markFailed` inside `framer.async`, or not marking anything. This surfaced when the gate (a) test server held every accepted connection and item 9's direct TLS probe did not finish (2026-11-15). `rejectedConnectionEndsOnceReleased` in `SwiftailLoopbackTests` guards it.
- `passThroughInput()` does not deliver bytes already buffered by the framer to the layer above it (ClientHello or plaintext received with the token was lost and the TLS handshake ended with `-9816`). Measuring those bytes with `parseInput` and delivering them with `deliverInputNoCopy` before enabling pass-through lets TLS work end to end.
- The framer reads values supplied in `NWProtocolFramer.Options` (`options["table"]`) in `init(framer:)`. Its `remote` and `local` are `127.0.0.1:<source port>` and `127.0.0.1:<listener port>`. Values the framer writes to its own `options` (and its `parameters` stack) are not visible in the server's `connection.parameters` (copied per connection), and `connection.metadata(definition:)` is also nil. Framer message metadata reaches the server's receive context only on a plaintext listener. It does not arrive on a TLS listener. The server therefore cannot read identity directly from the connection and looks up the table by key.
- When the peer disconnects with RST, the framer's `stop` and `cleanup` run before the server calls `cancel()` and even before its `.failed` handler. Removing a grant in `cleanup` would allow a new grant with the same key to appear when the server's `.ready` handler is late. This is why it is retained.
- `NWProtocolFramerImplementation` does not require `Sendable`, so it is used under Swift 6 strict concurrency without `@unchecked Sendable`. Input can only be read through the buffer supplied to `parseInput`, so copy bytes inside that closure.
- The TLS listener completed the handshake with a Keychain-free identity (`SecKeyCreateWithData`, `SecCertificateCreateWithData`, `SecIdentityCreate`, with a self-signed certificate generated in the test) (B9).
- Before the fix (old API, server looked up after the first byte), review scenarios 1 and 2 obtained an identity (tests failed). A probe where another thread connected with the same port immediately after a server RST while receiving obtained an identity in 0 of 200 attempts (the old bridge always removed the entry first). In the fixed code, connections in all three cases fail to become ready.

#### Independent Review Fixes (Review of M7-9b, 2026-11-15)

Another session reviewed the token design. It found no way for a connection that the bridge did not forward to get a value from `origin(of:)` (table invariants, constant-time comparison, framer boundary, token exposure, bridge ordering, cleanup of finished connections, concurrency). It reproduced two availability defects and one small discrepancy.

1. **Leftover grants blocked new connections.** On a TLS listener the framer records the grant before the handshake. If the handshake does not finish (tailnet peer disconnects immediately, rejects the certificate, or just opens a connection in advance and closes it), the server never sees `.ready` and does not look up the grant, which remains until evicted. If the bridge picked that source port again, the table refused it and the legitimate connection ended with `loopbackUnavailable` (about 1.6% of new connections with 256 leftover grants and 16,384 source ports, estimated). Fix: If refused, keep that socket and redial with a different port (B1 ④). Keep leftover grants because removing them could let a late lookup get a new grant with the same key (B6 ⑤ still holds).
2. **Leftover grants evicted live grants.** The oldest grant was discarded at the limit, so if one tailnet peer repeated the connection in item 1 256 times (3.9 seconds sequentially), another peer's grant could be evicted during its handshake, causing that connection's lookup to return nil. Substitution is impossible (denial of service only). Fix: Discard grants whose bridge side ended first (B6 ④).
3. **A connection that sent a short prefix and ended** did not fail until the 5-second deadline, contrary to the contract's "fail if it ends before 32 bytes arrive." Lowering the minimum `parseInput` length to 0 did not make `handleInput` run again on FIN (FIN after 10 bytes: one call, `isComplete` false. Same when returning lengths 32, 0, and 11). A framer cannot observe the end before readiness. Fix: Remove the branch that never ran and document the actual behavior (B6 ③).

Remaining (unfixed): Connections that send no token hold a server file descriptor for 5 seconds each. A process with the same user's permissions can fill the app's descriptor limit (out of scope because that process can also terminate the app). How often the real kernel causes the source-port collision in item 1 was not measured (the test injects a collision into the table).

### G. Importing Go State (After U1)

1. **Once, read-only**: Read only from the Go directory. If `identity.json` already exists in the destination, return `alreadyInitialized` (import does not overwrite a live Swiftail identity).
2. **Scope and reading**: Import **only one fully registered profile** (notes §4.7 items 3 and 5, §10). Read `tailscaled.state` up to 1MiB. The outer layer is a JSON object with **standard base64** strings as values (not base64url. Notes §4.7 item 5). Sequence (DNS notes §3.2, notes §4.7 items 2 and 5): ① `_machinekey` (required) is `privkey:` + 64 hex characters. ② The value of `_current-profile` is the **whole key** `profile-<ID>`. ③ The value of `_profiles` is a JSON map `{profile ID: LoginProfile}`. ④ The value of the key pointed to by `_current-profile` is prefs JSON. ⑤ Read prefs `Config.PrivateNodeKey` (`privkey:` + 64 hex characters), `Config.OldPrivateNodeKey`, `LoggedOut`, and `ControlURL`. `Config.NetworkLockKey` has a different type with the `nlpriv:` prefix and is not read (notes §4.7 item 2, §9 V199). All rejections fail closed (do not fill in a new identity. Notes §4.7 item 5):
   - `malformed`: outer layer not a JSON object, nonstandard base64 value, invalid key text format, **zero machine key**, `_current-profile` not of the `profile-` form, or corrupt prefs or `_profiles` JSON.
   - `unsupportedState`: missing `_current-profile` (legacy format or no profile. Go creates an empty profile or migrates legacy prefs in this case), missing key pointed to by `_current-profile`, its ID absent from `_profiles` (mismatch), two or more profiles in `_profiles`, or `Config.OldPrivateNodeKey` present and nonzero (incomplete key rollover. Go still sends that key as `OldNodeKey` on reregistration, `control/controlclient/direct.go:718-720`, notes §4.7 item 3, §9 V202).
3. **When import is refused**: If the node key is absent or zero, or `LoggedOut` is true, return `notLoggedIn`. Do not infer whether zero means "never logged in" (notes §4.7 item 3, §9 V201). Do not import just the machine key (it does not make the same node). **Compare control servers** (do not present a key registered with one server to another. Notes §10): ① Default server: Go treats prefs `ControlURL` as the default if it is empty, `https://controlplane.tailscale.com` (Go `DefaultControlURL`), or `https://login.tailscale.com` (`ipn/prefs.go:42`, `:50-54`'s `IsLoginServerSynonym`, `ipn/ipnlocal/profiles.go:701-708`. Notes §4.7 item 3). Compare strings verbatim. In this case `configuration.controlURL` must also be one of those two strings (Swiftail defaults to `https://controlplane.tailscale.com`). ② Custom server: treat the URLs as the same server only if scheme, host, and port match, **the path is empty or `/`, and there is no query, fragment, or userinfo**. Compare components without normalization (an omitted port and `:443` differ). Otherwise return `controlURLMismatch`. "Same scheme, host, and port" does not guarantee "same server as registration": Go preserves the `ControlURL` path when building control endpoints (notes §10 G3, `control/controlclient/direct.go:810-817`). Therefore reject URLs with paths.
4. **Writing**: Save with `NodeIdentityStore` (0600, atomic, same iOS protection class). Do not migrate `NetworkLockKey` or the profile (notes §4.7 item 3). G2 already rejects state with `OldPrivateNodeKey`, so the import does not encounter cases where omitting it would differ from Go (interrupted key rollover).
5. **Caller requirements**: The Go node that uses the state must be stopped. Do not restart the Go node with that state after import. Swiftail cannot tell whether another process uses the same key (notes §4.7 item 4).
6. **Certificates**: The certificates and key files under Go's `certs/` use the same names and formats. If the first adopter copies them as-is, `CertificateManager` validates and uses them per behavior S3 (CryptoKit's ability to read Go's SEC1 key was verified in notes §4.6). Provide no separate API. This saves against the new-certificate limit for the same name (5 in 7 days). Use the account key (`acme-account.key.pem`) only if P-256. Compatibility with the RSA account keys Go can read is not guaranteed, and copying one causes behavior C4 to end with `accountKeyUnreadable` (notes §10). In that case the first adopter copies without the account key file (a new account is created).
7. **Rollback and unverified points**: If Swiftail later changes the node key (reauthentication after expiry), the key in the Go state is old. A rolled-back Go node may need to log in again. The client source does not establish how the server handles the old key (rejects it or accepts it only as `OldNodeKey`) (notes §4.7 item 4, §9 V211). Whether the imported node is accepted as the same node is **unverified before the gate**: Swiftail sends zero `NLKey` in registration (server behavior when a node registered by Go with an `NLKey` reconnects with zero), and server and DERP behavior when both implementations connect simultaneously with the same node key is also unknown (notes §§4.7 item 4 and 8). Gate (a) 11 and (b) 8 check this.

### K. Secrets and Logs

1. Secrets are the ACME account key, certificate private key, and, during import, the machine and node keys from the Go state. Files use 0600 and in memory the keys are held only in CryptoKit key types. `TailnetCertificate` and `CertificateManager` do not expose keys in `description` or `dump` (`CustomReflectable`).
2. Log (`os.Logger(subsystem: "Swiftail")`) issuance start and finish, failure type, interval until the next attempt, certificate expiration date, and number of bridged connections. Keep keys, JWS bodies, nonce, token and key authorization, account URL, ACME problem document `detail` (it can contain identifiers. Only the failure information described in behavior C12 is exposed via `status`), full domains containing tailnet names, full addresses, and login names out of logs.
   `TailnetCertificate`'s string representation and `dump` redact the domain and show only the validity period.
3. Keep keys, paths, and descriptor numbers out of associated error strings (M5 rule).
4. Certificate verification compares public keys (behaviors S3 ④ and X3 ③). The bridge looks up port numbers and compares its secret tokens in constant time (behavior B6). Use `SwiftailCrypto` for any additional secret comparisons.
5. **Certificates become public**: Certificates issued by Let's Encrypt appear in public Certificate Transparency logs, where they include device and tailnet names (Let's Encrypt's rate limit documentation directs readers to find issued certificates with a CT log search). The current Go host works the same way. Document in owner confirmation U3.

Decisions from implementation (M7-6): `CertificateManager` also conforms to `CustomStringConvertible` and `CustomReflectable` and does not expose names, keys, or account URLs (public conformances absent from the §2 declaration). The log category is `certificates`.

### M. Limits

| Item | Value | On excess |
| --- | --- | --- |
| ACME JSON response | 64KiB | Fail the attempt (`unexpectedResponse`) |
| Certificate chain response | 256KiB, 5 certificates | Fail |
| Order authorization count | 8 (behavior C5) | `unexpectedResponse` |
| Problem document `type` | 256 bytes (behavior C12) | Truncate |
| `set-dns` response body | 4KiB | Fail |
| URL | 2,048 bytes, `https` | Fail |
| One HTTP request | 30 seconds | `timedOut` or `network` |
| One issuance attempt | 5 minutes | `timedOut` (end the attempt if `Retry-After` also exceeds this. Behavior X5) |
| `set-dns` | 60 seconds | `network` |
| `badNonce` retries | 3 per request | Fail |
| Order poll interval | `Retry-After`, 1 second if absent, 1 second if less than 1 second | Only delay. Do not read earlier than the server's value |
| Next attempt set by `Retry-After` | 7 days | Cap at 7 days (upper end only. Behavior X5) |
| Create a new order again within one attempt | 1 time (behaviors C5 and C7, H17) | `orderFailed` |
| Repeat `ready` or `pending` after finalize | 1 time per order (behavior C7, H17) | `unexpectedResponse` |
| Bridged connections | 256 (same as the node connection limit) | `limitReached` |
| Bytes held by the bridge | 64KiB per direction per connection | Stop reading |
| Loopback connection establishment | 5 seconds per attempt. Up to 3 attempts if the table refuses the key | `loopbackUnavailable` |
| Tokens pending in the bridge | 256 (same as the bridged connection limit) | Do not bridge that connection |
| Listener waits for a token | 5 seconds per connection | Connection fails before readiness (`ETIMEDOUT`) |
| Grants unclaimed by the server | 256 | Discard the oldest whose bridge side ended (`origin(of:)` returns nil for that connection) |
| On-disk certificate and key files | 64KiB each | Treat as absent |
| Go state file | 1MiB | `malformed` |

## 4. C API Mapping

The first adopter's Go core exposes 18 C functions (RemoteDebug `core/capi/include/rdcore.h`). Under "Caller," Mac means host mode, and extension means the iPhone packet tunnel extension (tunnel mode). All Swift-side calls go through `Packages/RDCore/Sources/RDCoreBridge/RDCoreBridge.swift`.

| # | Function | What the Go core does (tsnet and Tailscale features used) | Caller | After migration |
| --- | --- | --- | --- | --- |
| 1 | `rd_start` | Validate configuration JSON, one handle per state directory. Host: `tsnet.Server{Dir, Hostname, AuthKey, ControlURL, Ephemeral}.Start`, IPN bus subscription, status check goroutine. Tunnel: `LocalBackend` + utun | Mac, extension | **Swiftail**: `TailnetNode(configuration:device:)` and `run()`. Host uses `.inProcess`, extension uses `.utun` (M5). Duplicate starts yield `NodeError.stateDirectoryInUse`. Configuration JSON and handle table go away |
| 2 | `rd_status` | `LocalClient.Status`: state, login URL, addresses, cert domains, own name and `StableID`, and peer paths. Adds host fields (`tlsReady`, `listening`, publication and device counts, RSS) | Mac, extension | **Swiftail**: `node.status`, `node.events`, `path(toPeerNamed:)`, `CertificateManager.status`. Remaining fields are the first adopter's (table below) |
| 3 | `rd_stop` | Close listener, host, and node (`srv.Close`) | Mac, extension | **Swiftail**: cancel the task group running `run()` |
| 4 | `rd_host_publish` | IPA validation, copying, and list. Does not use tsnet | Mac | First adopter |
| 5 | `rd_host_unpublish` | Same as above | Mac | First adopter |
| 6 | `rd_host_publish_resource` | File sharing list. Does not use tsnet | Mac | First adopter |
| 7 | `rd_host_unpublish_resource` | Same as above | Mac | First adopter |
| 8 | `rd_host_set_agent_board` | Change the document for `GET /v1/agent` | Mac | First adopter |
| 9 | `rd_update_page_set` | Loopback HTTP server (Go `net/http`). The official Tailscale app's `serve` exposes it. Unrelated to the core's tsnet and has no handle | Mac | First adopter (Swift loopback HTTP server). Unrelated to Swiftail |
| 10 | `rd_host_set_devices` | Replace the entire allowlist. Keyed by node `StableID` | Mac | First adopter. `StableID` is `PeerIdentity.stableID` |
| 11 | `rd_host_set_direct` | Direct same-network connection: OS TCP listener, TLS 1.3 with self-signed P-256 certificate (Go `crypto/tls` and `x509`), device token authentication. Does not use tsnet | Mac | First adopter (`NWListener`). The first adopter also writes the certificate generation code (F9) |
| 12 | `rd_host_pairing_open` | Create a pairing code | Mac | First adopter |
| 13 | `rd_host_pairing_decide` | Approve or deny a pairing request. `WhoIs` supplied the identity in the request | Mac | First adopter. Identity comes from `LoopbackBridge.Origin.peer` |
| 14 | `rd_proxy_start` | Loopback CONNECT proxy, `srv.Dial` | No callers | **Removed** (review result 2) |
| 15 | `rd_tunnel_set_default_interface` | Notify engine of a default interface change | Extension | **Swiftail**: `setDefaultInterface(_:)` (M5) |
| 16 | `rd_tunnel_set_path_peer` | Select the peer whose path is reported | Extension | **Swiftail**: `path(toPeerNamed:)` and `NodeEvent.peerPathChanged` (M4 and M5). No separate setting |
| 17 | `rd_next_event` | Wait for an event and remove it from the event queue | Mac, extension | **Swiftail**: `for await` over `node.events`, `node.networkSettings`, and `certificates`. Host events are the first adopter's |
| 18 | `rd_free` | Free a C string | Mac, extension | **Removed** |

Summary: 6 switch to Swiftail APIs (1, 2, 3, 15, 16, and 17. The Mac host uses 1, 2, 3, and 17), 10 are written directly in Swift by the first adopter (4–13), and 2 are removed (14 and 18).

Mapping of the Tailscale features that the Go core used behind these functions (Mac host):

| Go core | Location | After migration |
| --- | --- | --- |
| `srv.Listen("tcp", ":443")`, `Error` after 3 failures | `node.go:780-823` | `node.listen(port: 443)`. Remove retries (review result 4) |
| `tls.NewListener(ln, GetCertificate)` + `http.Server` | `tls.go:41`, `node.go:812-818` | `LoopbackBridge.forward` + first adopter's `NWListener` (TLS) and HTTP server |
| Preload certificate with `CertPair`, retry at 30 seconds to 10 minutes, `tlsReady` | `tls.go:44-51`, `node.go:825-859` | `CertificateManager.run()`. `tlsReady` means "received one from `certificates` and the TLS listener is up" |
| Check MagicDNS and cert domains with `Up` and `Status`, error message if disabled | `tls.go:22-32` | `CertificateFailure.magicDNSDisabled` and `httpsNotEnabled`. First adopter supplies the message |
| `LocalClient.WhoIs(r.RemoteAddr)`, 5-second deadline, per request | `node.go:526-546`, `host.go:230-244` | `LoopbackBridge.origin(of:)` (once per ready connection, no wait). For direct calls, `node.whoIs(_:)` |
| IPN bus `ErrMessage` → `Error` state | `node.go:409-458` | `NodeError` thrown by `run()` and `NodeEvent.stateChanged` |
| `StartLoginInteractive`, 30-second interval | `node.go:752-778` | Per M5 contract (`.needsLogin(URL)`, `startInteractiveLogin()`) |
| Path per paired device (`peerPaths`, key is `StableID`) | `node.go:141-163`, `:658-670` | `path(toPeerNamed:)`. Get the name from `Origin.peer.name` (F10) |
| `NetworkLockStatus` diagnostic logs | `node.go:494-504` | `node.status.tailnetLock` and `NodeEvent.tailnetLockChanged` (M8, `SwiftailTailnetLock.md`). Before M8, ended with `NodeError.control(.tailnetLockEnabled)` on tailnets with lock enabled |
| `logtail.Disable()`, `goMemLimitMiB`, RSS | `node.go:35-38`, `:277` | Not applicable (no log upload, no memory limit setting). RSS is the first adopter's |
| `srv.Dial` | `node.go:952` | `node.connect(to:port:)`. Used only by tests and diagnostics |

Origin of `rd_status` fields (host mode): `backendState` and `authURL` ← `NodeState` and result of `run()`, `hostname` ← configuration, `fqdn`, `tailscaleIPs`, and `certDomains` ← `NodeStatus`, `tlsReady` ← table above, `listening`, `publishedBuilds`, `pairedDevices`, `rssMiB`, and `direct` ← first adopter, `peerPaths` ← table above.

State directory (Go host): `tailscaled.state`, log settings and buffers, `certs/`, and the first adopter's `direct.json`, `direct-key.pem`, and `direct-cert.pem` (notes §4.7 item 1). Swiftail keeps a separate state directory (`SwiftailTunnel.md` D8): `identity.json` and `certs/`. The first adopter migrates the three direct connection files (the iPhone pins that key).

## 5. Decisions

### Lead Session Confirmation Required

| # | Item | Options | Recommendation and rationale |
| --- | --- | --- | --- |
| H1 | Target structure | (a) Two new products: `SwiftailCertificates`, `SwiftailLoopback` / (b) Both in one new product (`SwiftailHost`) / (c) Add them to `Swiftail` | (a). The two are independent (apps may use only certificates or only the bridge). One concept per target. (c) would put ACME, DER, and Security code in the iOS tunnel extension binary. Cost: four targets in `Package.swift` (including tests) |
| H2 | Who writes the bridge | (a) Optional Swiftail product / (b) First adopter | (a). Backpressure, half-close, and disconnect mapping depend on `TailnetConnection` semantics (e.g. canceling `write` causes RST), and the table invariants (behavior B6) are a security property that must be tested in one place. The bridge uses only public APIs (`SwiftailIO` is the only `package` dependency) |
| H3 | How to pass peer identity to the server | (a) Source port table + identity fixed at the start of forwarding (`Origin.peer`) / (b) Source port table gives only the address, and the server calls `whoIs(address)` for every request / (c) Put a framer below TLS, prefix the connection with a secret token, and provide the fixed identity by `(source port, listener port)` for a connection whose token was verified | **Changed to (c) (M7-9b, behavior B6).** In (a), the source port did not distinguish connections, so another process on the device obtained an identity (behavior B, "Review Fixes," 1 and 2). (b) has the gap in behavior B2 and crosses the actor for every request. Experiments verified that (c) runs below TLS. Cost: the server adds one protocol to the listener. Changes to name and login name are not reflected during the connection's lifetime (the allowlist uses `StableID` and is unaffected) |
| H4 | Bridge's loopback socket | (a) `NWConnection` (`SwiftailIO.NetworkSocket`). Read and record the local port after readiness, then send / (b) POSIX socket: at lookup time, check if the bridge socket is alive with `TCP_CONNECTION_INFO` | Keep (a). The identity boundary is the token (H3 (c)), independent of socket type. The kernel-state check in (b) relies on "the kernel protects that 4-tuple while the bridge socket is alive," which does not hold if the server looks up after the connection dies and the port is reused. Experiment: `NWConnection`'s `currentPath.localEndpoint` gives the port when ready, and the accepted connection's `endpoint` and listener-side framer's `remote` give that source port |
| H5 | Key returned by the certificate API | (a) `P256.Signing.PrivateKey` + DER chain / (b) Also a function to build `SecIdentity` | (a). The first adopter requested "chain + key that can become a `SecKey`." Creating `SecIdentity` takes five lines (snippet in §6. Only SDK declarations were checked and it was not run), and it reads well beside listener setup in the first adopter's code |
| H6 | Renewal decision | (a) 2/3 of lifetime / (b) ARI (RFC 9773) and `replaces` | (a). A policy choice for minimal scope (notes §6). 2/3 alone **does not guarantee** avoiding rate limits. Types of limits (same identifier set, 5 certificates in 7 days, etc.) and conditions for ARI renewal exemptions are in notes §4.5 (behavior R1). (b) takes two requests and certificate identifier computation (DER reading of the serial number and AKI. The Go fork's serial encoding differs from RFC 9773, notes §4.4 item 2) |
| H7 | Storage format | (a) Same location, names, and PEM as Go (`certs/`) / (b) Swiftail-only format | (a). Copying is sufficient to use certificates obtained by Go (behavior G6). Keys are written as PKCS#8, which Go also reads (notes §3.7). Also works for rollback |
| H8 | ACME HTTPS | (a) `URLSession` (Foundation) / (b) Write an HTTP/1.1 client directly on `NetworkSocket` | (a). The Mac host uses OS networking directly (outside the tunnel). Make the transport injectable so tests can attach a fake server. Also decide to add Security to the allowed frameworks in plan §4(c) |
| H9 | Retry interval and limit values | Behavior R4 and M tables | Start with the table values and adjust based on gate (b) records. The deadline for one issuance (5 minutes) was chosen without knowing how long `set-dns` takes |
| H10 | Test ACME server | (a) Add pebble and challtestsrv to `Tools/interop` (both MPL-2.0, linked only into test tools) / (b) Only a fake ACME server inside Swift tests / (c) Let's Encrypt staging | Both (a) and (b). Use (b) for independent tests (deterministic, failure injection) and (a) for the gate. An independent ACME implementation is needed to uphold "Passing unit tests alone does not establish protocol behavior" (plan §7). (c) requires an account and a real tailnet, so use it only for gate (b). Verify the test tool's MPL-2.0 dependency is acceptable (U2) and builds (§9) |
| H11 | `whoIs` for a node without a profile | (a) nil (same as Go) / (b) identity with empty login name | (a). Fail closed. The first adopter answers nil with `not_paired` |
| H12 | Shape of Go state import | (a) Read-only, once, identity only (behavior G) / (b) Include profile and prefs / (c) No support | (a) if U1 is "migrate." `identity.json` only needs two keys. If U1 is "re-pair," use (c) and do not start implementation unit M7-11 |
| H13 | ACME User-Agent | `Swiftail/<version>` / prepend an app-supplied string | `Swiftail/<version>`. No parameter. Do not imitate the official client (plan §8 risk 10) |
| H14 | Location of DER writing, PEM, and base64url | (a) In `SwiftailCertificates` (`internal`) / (b) `SwiftailBase` (`package`) | (a). Only the CSR uses it. Revisit if the first adopter wants these components when writing a self-signed certificate for its direct listener in Swift (F9) |
| H15 | Gate (a) e2e scope | (a) Skeleton of "pairing → installation session → IPA transfer" with a minimal HTTP/1.1 server in the test target / (b) Bring in the first adopter's host code | (a). The first adopter's repository is read-only. Run actual host e2e in that repository after separate approval |
| H16 | Failure type for unreadable account key file (behavior C4) | (a) New `CertificateError.accountKeyUnreadable` / (b) Use existing `storage(String)` | Documented as (a). Both fail closed (`run()` ends without overwriting). The app can distinguish "account key left by Go" from disk errors for the user. Cost: one public case |
| H17 | Maximum repeats within an attempt (behaviors C5 and C7) | (a) Restart an order that is `valid` or `processing` before CSR only once with a new order, and repeat `ready` or `pending` after finalize once per order / (b) Only the 5-minute deadline / (c) Fail immediately without repeating | Documented as (a). In (b), if the server repeats the same state, orders and finalize are sent repeatedly until the deadline, consuming the new order limit (notes §4.5). (c) drops the branch proposed in notes §4.3 item 11 (finalize again with the same key and CSR). The second time ends in failure |
| H18 | Failure type for ACME responses violating specification or limits | (a) New `CertificateFailure.unexpectedResponse` / (b) `acme(status:type:)` with empty `type` / (c) `network` | Documented as (a). Cases called simply "failure" in behaviors C5 and X (unknown status, authorization for another name, excess over limits, non-`https` URL) had no public case. Retries match `acme`, 15 minutes to 6 hours (behavior R4) |
| H19 | Associated values for `validationFailed` and `orderFailed` | (a) `type` from the challenge or order `error` problem document (truncated to 256 bytes) / (b) No associated value / (c) Include `detail` | Documented as (a). Omit `detail` for the same reason as decision 4 (behavior K2). `type` alone supports diagnostics such as `dns`, `unauthorized`, and `badCSR` |
| H20 | Existing `certs/` writable by group or others (behavior S1) | (a) End with `storage` without reading or writing / (b) Block writes only and allow reads | Documented as (a). The lead session decision covered "fail without writing" but did not decide on reading. If a key from a directory others can modify is used for TLS identity, that person can decrypt traffic, so reading was blocked too |
| H21 | Scope of `Retry-After` and unreadable values (behavior X5) | (a) Apply to all URLs from the directory and treat unreadable values as absent / (b) Only responding URL or host / (c) Fail the attempt on an unreadable value | Documented as (a). Taking "that server" in its broadest sense fails closed. Treat unreadable values as absent. Order reads never go below 1 second and error responses back off per R4, so requests do not increase |
| H22 | Rule for splitting Go state rejection into two errors (behavior G2) | (a) `malformed` for invalid format, `unsupportedState` for parseable but unsupported state / (b) `malformed` for all | Documented as (a). Multiple profiles, legacy state, and interrupted key rollover are states the user can clean up on the Go side rather than corrupt files, so the messages can differ. A zero machine key is treated as corrupt because Go generates it on startup |
| H23 | Failure type for the node's own name violating validation (behavior C2) | (a) Record `domainNotAllowed` and wait for netmap change / (b) New case / (c) `run()` throws | Documented as (a). The control server sets the name, so a netmap change is required and time-based retry gives the same result. The app displays the same "Cannot obtain a certificate for this name" message. Cost: appears in the user-action branch even when there is nothing to fix in the admin console |

Lead session decision (2026-11-15, draft stage. May change with the first adopter's answer): **Follow the recommendation for all of H1–H15.** Additions:

- H4: Keep (a). Do not add a POSIX socket. The original reasoning was "no bytes are sent before recording in the table, so the server only needs to honor the lookup timing," but the source port table failed as a boundary (M7-9b), and the token in the connection became the identity boundary (H3 (c)). It does not depend on when the server asks.
- H8: Added Security and `URLSession` to plan §4(c). Only `SwiftailCertificates` uses the two frameworks.
- H10: The test tool's MPL-2.0 dependency falls under the Go tool exception for `Tools/`. Decide publication notices with U2.
- H12: Do not start M7-11 (Go state import) until U1 is answered.
- Before implementation, another session verifies `whois-certs-state.md` against the Go source and original RFCs.

### First Adopter Confirmation Required

Assumptions and questions based on reading the Go code and documents at commit `2814b2c` (`core/internal/node/`, `core/internal/host/`, `core/internal/direct/`, `core/e2e/`, `docs/protocol.md`, `docs/protocol-addenda.md`).

| # | Question | Draft assumption | What depends on the answer |
| --- | --- | --- | --- |
| F1 | Today each request calls `WhoIs`. After migration, can the server fix identity **once per connection** (`Origin.peer`) and only check that `StableID` against the allowlist for each request? Swiftail closes the connection if the address owner changes | Yes | H3, behavior B2. If every request must reverify, add a contract rule for the server to compare `whoIs`'s `stableID` with `Origin.peer.stableID` and close on mismatch |
| F2 | Are the `PeerIdentity` fields (`stableID`, `name`, `computedName`, `tags`, `loginName`, `displayName`) sufficient? Is `computedName` needed as a fallback for unnamed nodes? Is any `loginName` acceptable for a tagged iPhone (single-use key in the pairing link, addenda J)? | Sufficient. Keep `computedName` because the current code uses it | Public type. Add the profile picture URL or sharer (`Sharer`) if needed |
| F3 | Certificates arrive through the `certificates` stream (current + renewals) and `status` (expiration, last failure, next attempt). Can the app derive `tlsReady` and an `errorMessage` such as "HTTPS is disabled" from the `CertificateFailure` case? Are failure events needed too (today it reads state every 2 seconds)? | The case is sufficient. No events needed | `CertificateStatus` and `CertificateFailure`. Add a stream if events are needed |
| F4 | On renewal, restart `NWListener` with the new identity (the identity is fixed at construction). The port may change, so `forward` takes it on each call. Does this fit the server? Do existing connections run to completion on the old listener? | Yes | Shape of `forward(_:toLoopbackPort:)`. Scope grows if the bridge should own the listener |
| F5 | The first adopter runs the accept loop and calls `forward` per connection. The bridge limit is 256. `forward` returns only when the connection ends (one Task per connection) | Yes | Behavior B1, limits |
| F6 | On the fake tailnet (`listenTLS=false`), does the same bridge forward to a plaintext loopback listener, or does the server read HTTP directly on `TailnetConnection`? | Same bridge (one server entry point) | Shape of the gate (a) server. If it reads directly, the server has a separate entry point for `TailnetConnection` |
| F7 | Mac host sandbox: committed `Apps/Mac/RemoteDebugMac.entitlements` is an empty dictionary and `README.ko.md` says "App Sandbox is not used." The answer received was "App Sandbox, network server and client entitlements only." Which build is the M7 baseline? Is the sandboxed version's state directory inside the container? | Sandboxed version is the baseline and those are the only two entitlements | Behavior B9, gate (b) 7. Who verifies operation in the sandbox (recommendation: first adopter session) |
| F8 | Will the first adopter copy the certificates Go obtained (the three files in `certs/`) to the new state directory if migrating? | Yes | Behavior G6. If Swiftail should do it, add a parameter to `GoStateImport` |
| F9 | Direct connection listener's self-signed certificate: CryptoKit and Security can read existing `direct-key.pem` and `direct-cert.pem` (notes §4.6). Does the first adopter write the X.509 encoding to **generate a certificate on a freshly installed Mac**? Should Swiftail expose the DER writer? | The first adopter writes it. Do not expose it | H14 |
| F10 | `peerPaths` is keyed by `StableID` but Swiftail's path lookup is by name. `Origin.peer.name` identifies the devices that connected in this run (a device that never connected has no path). Is this sufficient? | Yes | If not, add lookup by `StableID` to `whoIs` |
| F11 | The Go core writes tsnet logs to the `logPath` file. Swiftail logs only to `os.Logger`. Are Swiftail logs required in a file? | No | If needed, define a way to receive logs separately (also affects M5) |
| F12 | Certificate retry intervals change (behavior R4: verification failure starts at 15 minutes). Before receiving a certificate, the tailnet listener is listening and the bridge closes connections because it has no loopback port. Does this conflict with the current `listening` and `tlsReady` display? | No | Behavior R4 values |
| F13 | What is the test counterpart (fake iPhone) after removing the Go core? Keep Go's `rdtestenv peer` and the `core/e2e` tsnet peer as test tools, or switch to a Swiftail node (`connect`)? Swiftail's repository gate uses a Go tsnet peer | Keep Go in the test tools | Reproduction scope of gate (a) item 8, `peerHTTP` in `Tools/interop` |
| F14 | The first adopter writes all remaining host features (REST, pairing, session, publishing, direct connections, update page, and event queue) in Swift. Does it need anything from Swiftail beyond the §4 table? | No | Scope |
| F15 | Does the Mac host run as an ephemeral node outside tests? If state is empty each time an ephemeral node starts again with the same name, it will obtain a new certificate and reach the limit of 5 in 7 days | No in production | If so, add a rule against issuance on ephemeral nodes |
| F16 | The 5-second `WhoIs` deadline goes away (`origin` and `whoIs` do not wait). Does anything rely on the deadline? | No | — |

### First Adopter Review Results (2026-11-15)

The first adopter session answered F1–F16 (based on code after `2814b2c` in its repository). Assumptions that held: F1, F4, F5, F6, F8, F10, F11, F13, F14, F15, F16. Only changes to the draft are listed.

1. **Identity (F1 and F2)**: Checking the per-connection fixed `Origin.peer.stableID` against the allowlist for every request produces the same decision as today (the server checks the list per request, so removal blocks the next request). The host reads only `stableID`, `computedName`, and `loginName`, so remove `tags` and `displayName` from `PeerIdentity`. Keep `name` because it is the key for path lookup (`path(toPeerNamed:)`) (F10: the first adopter remembers `StableID` ↔ name for a device that connected and queries by name even for devices without a current connection). `loginName` can be empty.
2. **Failure types (F3)**: Distinguishing the two the user can fix (`magicDNSDisabled`, `httpsNotEnabled`) from the rest is sufficient. The app adds "Open DNS settings page" to those two. Added `magicDNSDisabled`. No need to emit failure events (reads `status` every 2 seconds).
3. **Renewal and listeners (F4 and F5)**: On renewal the first adopter starts a new `NWListener` and calls `forward` with its port. Established connections finish on the old listener, which stops accepting new connections and closes when the remaining ones finish (renewal does not interrupt a large transfer). The bridge therefore operates **per connection rather than per port** and does not close connections to the old port because of the new port.
4. **Retry (F12)**: Show the next attempt time from `status` on screen. Added **`retryNow()`** for the user to press after fixing settings.
5. **Sandbox (F7)**: Both builds must work and **the sandboxed version is the gate baseline**. The public repository's Mac app does not use the sandbox (the committed entitlements file is indeed empty), and the store version enables App Sandbox (network server and client, user-selected files, bookmarks). The sandboxed version's state directory is in the app container. **The first adopter session verifies sandbox operation (`SecIdentity` creation, loopback listening, bridge).** The sandboxed version can use the Keychain, so if Keychain-free identity creation is blocked, the first adopter uses the Keychain (the Swiftail API stays the same: it returns a chain and key).
6. **DER component (F9)**: The first adopter needs to generate the direct listener's self-signed certificate (X.509 v3) in Swift and would use Swiftail's DER writer if exposed publicly (not urgent). **Do not expose it now** (H14 stands). Do not freeze an internal component used only for CSR as a public API. Revisit after M7-3 defines the component's shape, when the first adopter migrates direct connections.
7. **Propagating disconnects (API feedback)**: If the server closes the loopback connection, the bridge cleans up the tailnet side (behaviors B4 and B5 stand). Conversely, **if the tailnet side ends with an error, loopback must not look like a normal close** (so a partially received body is not read as complete). On a TLS listener, the connection ends without `close_notify` and the server's TLS recognizes truncation. On a plaintext listener (`listenTLS=false`), it must end with RST. When implementing "cancel loopback" in behavior B5, identify which `NWConnection` call sends RST and pin it with a test (add a gate (a) item: if tailnet calls `abort()`, the plaintext loopback server's read ends with an error).
8. **Lookup timing**: The server asks after the connection delivered by `NWListener` becomes `.ready` (handshake complete) and before the first receive. The call at review time was `origin(forLoopbackSourcePort:)`, changed to `origin(of:)` in M7-9b (same timing. Behavior B7).
9. **Test counterpart (F13)**: After migrating the host, the first adopter's fake iPhone uses a Swiftail node (`connect`) for fast tests and this repository's Go tsnet peer in `Tools/interop` for interop. Do not add new Go test tools to that repository. The `tailnet` tool in `Tools/interop` and [the guide to using two Swiftail nodes on the test control server](../../Tools/interop/README.md#run-listen-and-connect-with-two-swiftail-nodes-on-the-test-control-server) are therefore interfaces the first adopter uses (notify them of changes).
10. **Mapping**: No factual discrepancies. `rd_update_page_set` relies on the official Tailscale app and is already absent from the sandboxed version.
11. **Note on the minimal HTTP server for gate (a)** (no contract impact): Cap body size in the test target's server too.

### Certificate Target Review Fixes (2026-11-15)

Another session reviewed all of `SwiftailCertificates`. It found no path for an unverified chain or key to reach the app or be stored. Fixes:

1. **Resubscription**: Every read of `certificateFacts` returns a new stream and finishes the previous one. Previously the node had only one stream, so after canceling the manager's `run()` (canceling the reader Task finishes the stream), a new manager on the same node stayed at `nodeNotRunning` forever.
2. **Name changes during issuance**: The attempt runs to completion and stores the certificate (behavior C, M7-6), but **does not emit it** on `certificates` if the name no longer meets issuance conditions at completion. This prevents a certificate for a name other than the current one from becoming the app's TLS identity.
3. **Removal from `chain`** (behavior S6): Remove the trust anchor selected by evaluation instead of detecting self-signature.
4. **URL** (behavior X1): Reject strings that would be re-encoded and userinfo, and send requests only to the same origin.
5. **Name** (behavior C2): A name with an all-digit final label (of the form `100.64.0.1`) yields `domainNotAllowed`.
6. **Compare the `set-dns` name** (behavior D4): Compare bytes (`String`'s `==` uses Unicode canonical equivalence).
7. **`ACMEOrderFlow.start`** is accepted only once. The transport's test anchor path also does not fetch missing intermediates from the network.
8. **The transport's test anchor path had never run** (found by a gate (a) test): `URLSession.bytes(for:)` asks for server certificate verification only through the task-level delegate method, but only the session-level method was implemented, so a transport given a test root rejected all TLS servers (production path unaffected). The task-level handler now calls the session-level handler. Unit tests missed this because they used only plaintext loopback, and the gate against pebble now exercises this path.

Recorded without fixes:

- **An issuance attempt can exceed its 5-minute deadline by up to about 60 seconds.** The deadline is checked after receiving a response, so the last request (30 seconds) or `set-dns` (60 seconds) is allowed to finish regardless of the remaining time. "5 minutes per issuance" in the limits table excludes this allowance.
- **The `certs/` check looks only at mode bits.** It cannot detect a directory made writable by a macOS ACL. If the process dies while writing, the temporary file (UUID in name, 0600) remains and is not cleaned up. The directory is not synced with fsync (same level as Go).
- **"Trust only these anchors" for test anchors**: Security does not trust other anchors once anchors are set (`SecTrust.h`. Review session verified by running it), so a mutation that removes `SecTrustSetAnchorCertificatesOnly(true)` behaves the same and tests do not catch it. The dangerous mutation passes `false`, but key comparison precedes evaluation, so there is no way to test with a system-root chain. The production path sets no anchors.
- Names of 65–237 characters exceed the CSR CN limit of 64 characters (RFC 5280). Go also puts the name into the CN verbatim. Whether Let's Encrypt rejects it is unverified (gate (b)).
- Accept noncanonical base64 (`QR==`) in a PEM body. DER and `SecTrust` make the final decision.

### Owner Confirmation Required

| # | Item | Options and impact |
| --- | --- | --- |
| U1 | How to migrate existing devices | **Re-pair as a new node**: A device that switches to Swiftail becomes a new node (new tailnet address, new `StableID`, new name on conflict). Migrating the Mac changes its host ID and FQDN, so all iPhones re-pair and a new certificate is issued. Migrating an iPhone requires adding it again to the Mac's allowlist. Delete old nodes in the admin console. / **Migrate Go state**: Behavior G. Continue as the same node and retain pairing and certificates. Cost: the first adopter must follow the sequence that prevents both implementations from using the same key. Rollback is not clean (behavior G7), and the effect of reconnecting with zero `NLKey` is unknown (§9). The Mac and iPhone can be decided separately |
| U2 | Whether to publish Swiftail, and under what license | Plan §9. Additional consideration in M7: whether test tools may depend on MPL-2.0 modules (pebble, challtestsrv) (H10) |
| U3 | What to provide for the real tailnet gate | "What to obtain from the owner" under gate (b). Issuance on a tailnet with HTTPS enabled puts device and tailnet names in public CT logs (behavior K5) |
| U4 | Unofficial client use of the control server's `set-dns` and Let's Encrypt | An extension of plan §8 risk 10. Verify before public release |

**Owner's answers (2026-11-15)**:

- U1: **Register again as a new node**. Do not build Go state migration (behavior G, M7-11, gates (a) 11 and (b) 8). Retain the record of the `tailscaled.state` format (notes).
- U2: **Publish under BSD-3-Clause**. Confirm once more before creating the GitHub repository and pushing. Before that: `LICENSE`, notice for the test tool's MPL-2.0 modules, check full commit history for secrets, real names, and personal paths, and decide whether to exclude `_context/` from the public version.
- U3: **Verify with staging, then issue up to 2 production certificates** (1 initial issuance + 1 renewal verification). This was decided knowing device and tailnet names appear in CT logs. Obtain a tailnet with MagicDNS and HTTPS enabled (the first adopter's tailnet) and a non-ephemeral auth key.
- U4 is to be verified before public release (unchanged).

## 6. Snippet for the First Adopter's Code

An approach recorded as rationale for H5, outside the contract. The SDK declarations verify the functions used (notes §4.6: `SecKeyCreateWithData` input is `04 ‖ X ‖ Y ‖ K`, 97 bytes, and `SecIdentityCreate` returns NULL if the key does not match), and **the gate (a) test server (`Tests/SwiftailInteropTests/Support/MinimalHTTPServer.swift`) ran and verified this snippet outside the sandbox** (the Go peer verified TLS with the test root, ALPN `http/1.1`, 2026-11-15). Whether anything was written to the Keychain was not inspected. The authoring session's reported experiments on TLS and ALPN negotiation and "no Keychain writes" are unverified (notes §8, §9 V188 and V189). Do not use them as the basis for implementation. The first adopter session verifies operation in the sandboxed version (first adopter review result 5).

```swift
// TailnetCertificate → NWListener TLS identity. Does not use the Keychain.
let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPrivate]
let key = SecKeyCreateWithData(Data(certificate.privateKey.x963Representation) as CFData, attributes as CFDictionary, nil)
let leaf = SecCertificateCreateWithData(nil, Data(certificate.chain[0]) as CFData)
let identity = SecIdentityCreate(nil, leaf, key)            // SecIdentity.h, since macOS 10.12 and iOS 11.2
// Include intermediates with sec_identity_create_with_certificates(identity, the rest of the chain without the leaf).
// Passing the full chain sends the leaf a second time (verified by a gate (a) test, 2026-11-15)
sec_protocol_options_set_local_identity(tls.securityProtocolOptions, sec_identity_create(identity))
sec_protocol_options_set_min_tls_protocol_version(tls.securityProtocolOptions, .TLSv12)
sec_protocol_options_add_tls_application_protocol(tls.securityProtocolOptions, "http/1.1")
```

## 7. Tests and Gates

### Unit Tests (No Sockets, Deterministic with Time Passed In)

`Tests/SwiftailTests`:

1. **`whoIs`**: Peer IPv4 and IPv6 addresses, local address, IPv4-mapped address, absent address, before netmap, address only in `AllowedIPs` (subnet), expired node (nil), netmap with address overlap (same node as the peer with the address in AllowedIPs), netmap where a peer owns the local address (nil), node without a profile, node with empty `StableID`, tagged node, answer after netmap changes. `computedName` (behavior W4): node on the same tailnet (strip suffix), node shared from another tailnet (FQDN without trailing dot), name with a suffix match outside a label boundary (leave the suffix on `rd-a.xtail0001.ts.net.`), local name without a dot, hostname of an unnamed node (strip `.local`, `.localdomain`, or `.lan` and sanitize), and node key text. Expected values match Go `Node.ComputedName` (gate (a) 1).

`Tests/SwiftailControlTests`:

2. **`set-dns`**: Request path, headers, and body (key names, `Version` 148, `Type` `TXT`, `Value` is 43 bytes without quotes), 200 and `{}`, 200 and `null`, array, or empty body (failure. Go accepts `null`), non-200 response, body over 4KiB, waiting and deadline when disconnected, failure before registration.
3. **Go state file** (M7-11, behaviors G2 and G3): Valid file (one profile), outer values in base64url (`malformed`), zero machine key, missing `_current-profile` (legacy), missing referenced key, mismatch with `_profiles`, two profiles, `OldPrivateNodeKey` present, zero node key, `LoggedOut`, ignore `NetworkLockKey` if present, malformed base64 or JSON, more than 1MiB, destination already has an identity. Control server: empty value, `https://controlplane.tailscale.com`, or `https://login.tailscale.com` versus default configuration (same), default configuration versus custom server (different), no path versus `/` on the same custom server (same), path, query, fragment, or userinfo present (different), omitted port versus `:443` (different).

`Tests/SwiftailCertificatesTests` (new test target):

4. **Encoding**: base64url (RFC 4648 vectors, unpadded), PEM (multiple blocks, line length, unknown type), DER writing (length boundaries 127, 128, 255, 256, and 65,535, INTEGER 0, OID).
5. **JWK and thumbprint**: The RFC 7638 3.1 example is RSA, so it cannot be used. Use Go reference values (below) for the P-256 vector. RFC 7638 defines the thumbprint input (`{"crv":"P-256","kty":"EC","x":…,"y":…}`), which must match Go **byte for byte** (notes §3.4). Check that `x` and `y` are padded to 32 bytes (key with a leading zero in a coordinate).
6. **JWS**: Protected header fields and parsing regardless of order, `jwk` and `kid` do not appear together, POST-as-GET `payload` is `""`, signature is 64 bytes (R ‖ S) and verifies with the public key. The specification does not prescribe JSON member order in the protected header or body (RFC 7515 5.1, notes §7 item 1, §9 V222), so comparison with Go uses the decoded header's **meaning**, and cross-verification of actual signing input and signature. Require matching header and signing input bytes only if the implementation chooses Go's serialization (member order, no whitespace). This contract does not require that serialization.
7. **CSR**: Subject, SAN, and algorithm structure (fixed key), self-signature verification (Security has no CSR parsing API, so the Go reference value tool verifies it). Subject CN is `PrintableString` (tag 0x13) as in Go. `UTF8String` (0x0C) is valid too but differs from Go in bytes (notes §3.6, §9 V056 and V178). `certificationRequestInfo` bytes must match Go with the **same public key, same attributes (one SAN in extensionRequest), same CN tag, and same DER rules** (notes §7 item 2, §9 V224). The contract sets all four to match Go, so the CSR’s `certificationRequestInfo` for the fixed key must match byte for byte. Test DER short and long lengths and the leading 0x00 of positive INTEGERs (signature r and s) (notes §4.6).
8. **ACME procedure** (inject fake responses in order): Twelve steps of notes §4.3, account exists or is absent, RSA or corrupt account key file (`accountKeyUnreadable`, file unchanged), authorization already `valid`, challenge already `processing`, order initially `ready`, `valid`, or `processing` (retry once with new order, second attempt is `orderFailed`), repeated `processing`, finalize response `valid`, `processing`, `invalid`, `ready`, `pending`, or unknown, finalize `orderNotReady`, order `invalid` (`validationFailed` if authorization is `invalid`, otherwise `orderFailed`), authorization `deactivated`, `expired`, or `revoked`, `badNonce` once and four times, `rateLimited` and `Retry-After` (seconds, date, past date, unreadable value, absent, beyond 5-minute deadline, beyond 7 days), `retryNow()` before `Retry-After` (no request sent), authorization without dns-01, two authorizations (one `valid`) and nine (above the limit), identifier with a different name, a type other than `dns`, or `wildcard`, response `identifiers` differ from request, `http` URL, URL over 2,048 bytes, body over 64KiB, missing `Replay-Nonce` or invalid characters. Problem documents: `application/problem+json`, non-JSON body, missing `type`, `about:blank`, server-specific URI, `type` over 256 bytes, `subproblems` present, `badNonce` imitated as a suffix of a non-ACME-URN `type` (no special handling).
9. **Verify received chain**: Response containing a `PRIVATE KEY` block, garbage bytes after or between blocks, unparseable block, 6 certificates, leaf with different key, leaf with different name, expired leaf, unknown root, chain including root (removed from `chain` after verification and retained in file).
10. **Renewal decision**: Before and after 2/3, after expiry, failures the user must fix (`magicDNSDisabled`, `httpsNotEnabled`, `domainNotAllowed`) do not retry over time, have nil `nextAttempt`, and wake only on netmap change or `retryNow()`, intervals and limits by failure type, `Retry-After` later than table interval, reset after success, and name change.
11. **Storage**: Write and read, new `certs/` at 0700 and new files at 0600 (including certificate), existing `certs/` writable by group or others (no read or write, `storage`), permissions are not changed, stopped after writing only the key (mismatch treated as absent), Go-written SEC1 key file and 0644 certificate (fixture), more than 64KiB, name validation (behavior C2: leading or trailing hyphen, 64-character label, 253 characters, 238-character name that exceeds the limit when `_acme-challenge.` is added, uppercase, path characters).
12. **Secrets**: No key bytes in `description` or `dump` of `TailnetCertificate` or the manager.

`Tests/SwiftailLoopbackTests` (new test target, uses loopback sockets and runs on one node using a connection to its own address):

13. **Bridge**: Hash of 1MiB in both directions, opposite-direction data after one side half-closes, tailnet stalls when loopback does not read (bytes held by the bridge stay within the limit), loopback closes on tailnet RST or `peerRemoved`, tailnet resets on loopback disconnect, `forward` cancellation, port without a listener, 257th connection.
14. **Table**: No bytes cross before registration (lookup always answers when the server receives the first byte), no lookup after ending, no lookup for the port of a direct loopback connection outside the bridge, and no loopback dial for a connection without an identified peer.

### Comparison Against Go Reference Values

`Tools/interop/cmd/acmefixtures` (new tool): Outputs JSON for JWK string, thumbprint, key authorization, DNS-01 TXT value, protected header JSON, and CSR (same arguments as `certRequest` in `feature/acme`) generated with fixed P-256 keys by Go (`tailscale.com/tempfork/acme` and standard library). Also add commands for Go to receive and verify Swift-generated JWS and CSR (signatures differ on each run). Fixtures are in `Tests/SwiftailCertificatesTests/Fixtures/`. A session other than the implementer writes comparison tests. Byte equality and semantic comparison follow notes §7 items 1 and 2: JWK string, thumbprint, key authorization, TXT value, and CSR `certificationRequestInfo` (under the four conditions in test 7) compare bytes, protected header JSON compares decoded meaning (test 6), signatures verify with the other implementation.

Commands to add to `tailnet`: `peerWhoIs` (Go peer `LocalClient().WhoIs(address)` as JSON, for `whoIs` comparison), `goState` (Go tsnet peer state directory path, fixture for import), and the commands for the gate below.

### Gate (a): Without an Account

Use the `tailnet` tool in `Tools/interop` (testcontrol + DERP + STUN + Go tsnet peer). Put tests in `Tests/SwiftailInteropTests/HostTests.swift` and skip if `SWIFTAIL_TAILNET` is absent.

Tool additions: **Give testcontrol `DNSConfig`** (required to produce cert domains. testcontrol adds `<Hostinfo.Hostname>.<MagicDNSDomain>` to netmap `CertDomains` only with a `DNSConfig` and nonempty `MagicDNSDomain`. The current tool supplies only `MagicDNSDomain`, so it produces no `CertDomains` as-is. Notes §7 item 4, `Tools/interop/cmd/tailnet/main.go:115`. Also enable MagicDNS (`Proxied`). Behavior C1 ②), `acmeStart` (start pebble and the challtestsrv DNS server in the same process and return directory URL and root certificate. Connect testcontrol's `OnSetDNS` to challtestsrv's TXT record. This is the test design in notes §7 item 5, and building and running both modules in one process is unverified. Notes §8), `setDNSLog` (list of received `set-dns` requests), `setDNSFault` (reject the next request or publish a different value), `setCertDomains` (clear or populate cert domains), and `peerHTTP` (Go peer sends an HTTP request with tsnet and returns status, headers, body length and SHA-256. Takes a trusted root as an argument).

| # | Check | Pass criteria |
| --- | --- | --- |
| 1 | `whoIs` | `stableID`, `name`, `computedName`, and `loginName` match `peerWhoIs` for IPv4 and IPv6 addresses of two Go peers and the local address. nil after the peer leaves |
| 2 | `set-dns` | testcontrol accepts the request (machine key, node key, and name pass validation), and `setDNSLog` matches the TXT value computed by Swift |
| 3 | Issuance | Receive a certificate from pebble. The chain verifies with the pebble root, the name is the node's own FQDN, and all three files are present in `certs/` with the specified permissions |
| 4 | Restart | Restart with the same state directory and get the stored certificate on `certificates` without ACME requests |
| 5 | `badNonce` and authorization reuse | Pass item 3 with pebble nonce rejection enabled. Pass second issuance with authorization reuse enabled |
| 6 | Renewal | Move the test clock beyond 2/3. A new certificate with a new key appears on `certificates`, and old connections continue |
| 7 | Failure | No cert domains yields `httpsNotEnabled`, MagicDNS off yields `magicDNSDisabled`, no requests are sent, and `nextAttempt` is nil. Restoring them (netmap change) triggers issuance. `set-dns` rejection yields `controlRejected`. Wrong TXT yields `validationFailed` and a next attempt in 15 minutes |
| 8 | **Scenario skeleton**: Swift node listens on 443 and the bridge connects to a test `NWListener` (TLS, certificate from item 3, ALPN `http/1.1`). With `peerHTTP`, a Go peer performs in order ① pairing request (server sends `Origin.peer`'s `stableID` and name in the response), ② create installation session (token bound to that `stableID`), ③ manifest, ④ download 100MB IPA in two Range requests | Go peer verifies TLS with the pebble root. The `stableID` in ① belongs to that Go peer. If another Go peer requests ④ with the token from ②, the server rejects it (different identity). Received bytes have matching SHA-256. Record throughput |
| 9 | Connection outside the bridge | If the test dials TLS directly to the loopback port, the handshake does not complete (it does not even receive the server certificate) and the server-side connection ends before readiness. The server closes it and the peer sees the end (before M7-9b: "`origin` is nil and the server closes") |
| 10 | Owner changes | Removing that Go peer from the tailnet during a transfer closes the loopback connection and ends the server's receive. The connection's `Origin` belonged to that peer |
| 11 | (M7-11) Import | Stop the Go peer, import from its state directory, and start a Swift node with the same node key. testcontrol accepts it as the same node with the same tailnet address and `StableID`. This is an **expected result** that this gate first verifies (end of notes §4.7, §7 item 7, §9 V233). testcontrol's result does not guarantee production handling of zero `NLKey` and duplicate sessions (gate (b) 8). Copy `certs/` in the format Go produced and use it without issuance |
| 12 | Full suite | All `eyebuild swift <purpose> -- test` tests pass, 0 warnings |

### Gate (b): Real Tailnet and Real Devices

Check only what cannot be checked locally. Notify the owner first each time (plan §4(b)).

| # | Check | Pass criteria |
| --- | --- | --- |
| 1 | Real control server | After registering on a tailnet with HTTPS enabled, `certDomains` contains the node's own FQDN |
| 2 | Real `set-dns` + Let's Encrypt **staging** | Issuance completes against the staging directory (supply the staging root as a test anchor). Record `set-dns` duration and total issuance time |
| 3 | Let's Encrypt **production** | Issue once. Verify against system roots. Record certificate lifetime. Reuse the stored certificate on restart (at most two issuances across the gate) |
| 4 | On iPhone | Safari and `URLSession` on an iPhone with the M5 tunnel enabled open `https://<fqdn>/` without warnings |
| 5 | Installer | Fetch manifest and IPA using an `itms-services` link (first adopter session, its minimal HTTPS server or migrated host) |
| 6 | Transfer | Measure 100MB download time on a direct Wi-Fi path and record it alongside the Go host value (`SwiftailNetstack.md` review result 5) |
| 7 | Sandbox | Items 3–5 work in the first adopter's sandboxed version (network server and client entitlements). Keychain-free `SecIdentity` creation, loopback listening, and the bridge in that environment were unverified before this gate and the first adopter session verifies them (first adopter review result 5, notes §8) |
| 8 | (If U1 is migration) Real Go state | Import state from a test Go host node. The production control server accepts it as the same node (same address and `StableID`. First check of reconnecting with zero `NLKey`), and a paired iPhone connects without pairing again |

What to obtain from the owner:

- Tailnet with MagicDNS and HTTPS certificates enabled (DNS settings in the admin console). Confirmation that the names may appear in CT logs (U3).
- Auth key for that tailnet (non-ephemeral node. A single-use key suffices because state is reused without deletion). Receive via secret input instead of chat. Use a fake hostname (of the form `rd-mac-1a2b3c4d`).
- Permission to use production issuance (use up to two of the five certificates per name in seven days).
- An iPhone with the M5 tunnel build installed and the first adopter session to handle 5 and 7.

#### Running the Gate Tests (1 and 2)

The tests are `RealTailnetHostGateTests` in `Tests/SwiftailInteropTests/RealTailnetHostGateTests.swift`. `HostGateFlowTests` in the same file runs the flow (`runHostGateFlow` in `Support/HostGateFlow.swift`) without an account first (testcontrol copy + pebble).

| Environment variable | Meaning |
| --- | --- |
| `SWIFTAIL_REAL_AUTHKEY_FILE` | File containing the auth key (non-ephemeral node). Skip the suite if absent |
| `SWIFTAIL_REAL_HOST_STATE_DIR` | Node state folder. Skip the suite if absent. Create it (0700) if new and **do not delete it**. Folders in `eyebuild dir` are deleted after 3 days without use, so choose a location that will persist until the second run |
| `SWIFTAIL_REAL_ACME_ROOTS` | PEM file with staging root certificates (test anchors). All `CERTIFICATE` blocks are used as anchors, so concatenate the staging roots described by Let's Encrypt into one file. If absent, skip issuance and check only 1 |
| `SWIFTAIL_REAL_ACME_DIRECTORY` | ACME directory. Defaults to Let's Encrypt staging (`https://acme-staging-v02.api.letsencrypt.org/directory`. Origin: tailscale.com v1.104.7 `cmd/k8s-operator/sts.go:119`). The test rejects the production directory host |
| `SWIFTAIL_REAL_SIGN_WAIT_SECONDS` | Maximum wait for a locked node's signature (default 600). Suite timeout is this plus 10 minutes |

```sh
SWIFTAIL_REAL_AUTHKEY_FILE=<key file> SWIFTAIL_REAL_HOST_STATE_DIR=<state folder> SWIFTAIL_REAL_ACME_ROOTS=<staging root PEM> \
  eyebuild swift real-host-gate -- test --filter RealTailnetHostGateTests
```

Flow: The `.inProcess` node with hostname `rd-mac-1a2b3c4d` becomes `.running` (if `needsLogin`, the auth key was not accepted, so fail without printing the URL) → record lock state → check item 1 (own FQDN in `certDomains`) → start the manager (even if locked. Record whether issuance works while locked) → if locked, wait for signing → first certificate → using the received certificate, start tailnet 443 → `LoopbackBridge` → test TLS listener. Connect in the same process to the node's own tailnet address (`NWConnection` through the plaintext loopback relay), verify using only the staging root, and check that `POST /pair` returns 200 and that the bridge reports the local node as the peer.

Signing procedure: If locked, print only "A signature is required. The command is in sign-command.txt in the state directory" on standard output. That file (0600) contains one line, `tailscale lock sign <nodeKey> <lockKey>` (both public keys). Run that line verbatim on a signing device to unlock the node without restarting it. If it does not unlock within the limit, continue locked and record "did not unlock within the deadline" in the summary. The manager runs even while locked. To see whether issuance works while locked, wait a few minutes after the file appears before signing. If the signature arrives before a certificate, "first certificate while locked" is undetermined (`-`), and only the manager's last failure is recorded at that point (`controlRejected` and similar failures indicate the server rejected the locked node's `set-dns`).

Output is a single summary block: state name, time to `.running`, peer count, lock `mode`, locked status, filtered peer count and `issue`, time to unlock by signing and whether it unlocked in the same `run()`, cert domain count and whether own FQDN is present, time from manager start to first certificate (total issuance time), ACME request count, `set-dns` count and each round-trip time, certificate lifetime (days), chain length, verification with the test anchor, whether the first certificate arrived while locked, and tailnet TLS result. Do not print FQDNs, tailnet names, addresses, keys, login names, or hashes. `set-dns` time is the control server round trip measured by wrapping the manager's `set-dns` interface (through an internal initializer argument under `@testable`, outside the public API). Time for TXT to propagate to public DNS and time waiting for the certificate authority's verification were not measured separately and are included in total issuance time.

On the second run: With the same state folder, connect with the stored identity (no `needsLogin`), start signed and `.enforcing` from the stored lock state, and report "started with stored certificate true, used the stored certificate without new issuance true (0 ACME requests, 0 `set-dns` calls)."

Results without an account (2026-11-15): In a tailnet without lock, issuance took about 1 second, 11 ACME requests, 1 `set-dns`, lifetime 90 days (pebble). The second run reused the stored certificate with 0 requests, and tailnet TLS verified using the pebble root. On a tailnet with lock enabled, **the certificate arrived while locked**. The copy of testcontrol's `set-dns` handler does not check lock, so this gate is the first to record production server behavior.


#### Results of Gate (b) Items 1 and 2 (2026-11-15, Run by the Lead Session)

Production control server, **tailnet with Tailnet Lock enabled** (HTTPS enabled), Let's Encrypt staging, non-ephemeral node (unsigned single-use auth key), hostname `rd-mac-1a2b3c4d`, macOS.

| Item | First run | Second run (same state folder) |
| --- | --- | --- |
| Time to `.running` | 4.6 seconds | 4.2 seconds (auth key already used. Reconnected with stored identity) |
| tailnet lock | `enforcing`, locked, 0 filtered peers, no `issue` | `enforcing`, unlocked (from the first netmap, using stored state) |
| Signing | **Unlocked without restart** after running `tailscale lock sign` on the signing device (884 seconds after registration. This depends on when the person signed) | Not applicable |
| 1: Own FQDN in `certDomains` | Present (1 domain) | Present |
| 2: Issuance | **Finished while locked.** 40.8 seconds from manager start, 12 ACME requests, 1 `set-dns` (32.3-second control server round trip), lifetime 64 days, chain of 4 certificates, verified with staging root | No new issuance (0 ACME requests, 0 `set-dns`). Verified and used the stored certificate |
| Tailnet TLS with the received certificate | Own tailnet address port 443 → bridge → TLS listener: handshake and verification succeeded, HTTP 200, bridge reported the local node as the peer | Same |

Findings:

- **The production control server accepts `set-dns` even when the node is locked by tailnet lock.** The Mac host can therefore obtain a certificate in advance while waiting for a signature.
- One `set-dns` round trip took 32 seconds (the server appears to wait for TXT propagation before replying. One measurement). It accounts for most of the total issuance time. The app should allow about 1 minute for initial issuance.
- The staging certificate had a 64-day validity period and the chain had 4 certificates including the leaf (check production in 3).
- A Swiftail node on a tailnet with lock enabled gets the `tailnet-lock` capability (`mode` is `enforcing`. Reconsideration condition for `SwiftailTailnetLock.md` U2: no case without the capability was observed).

This run also covers `SwiftailTailnetLock.md` gate (b) item 2 (a signing device signs later) and the first half of item 4 (restart resumes with stored state). Unverified: registration with a signed auth key (`--TL`) (item 1 of that gate), whether the local TKA head catches up after a signing device adds a key (second half of 4), and the number of AUMs received in bootstrap and sync (omitted from the summary).

The first adopter reuses the state folder (identity, lock state, staging certificate) for gate (b) items 3–6. Empty `certs/` before switching to the production directory.

### Scope of the RemoteDebug e2e Reproduction

The first adopter has three kinds of e2e tests: Go tests (`core/e2e`. Go host and Go tsnet peer, fake tailnet, `listenTLS=false`, 22 tests. The 3 tunnel tests are separate in `core/e2e/tunnel`), Swift package tests (`Packages/MacHost/Tests/MacHostE2ETests`. Real Go core and `rdtestenv`), and scripts (`scripts/e2e-*.sh`). All run that repository's host code.

The Swiftail repository reproduces **only the properties that depend on Tailscale** (gate (a) 8–10): a tailnet connection reaches the HTTP server through TLS, the server knows the peer's `StableID`, the session is bound to that node, and a large body arrives intact through Range requests. It does not reproduce host logic such as pairing code rules, session lifetime, or published build validation. After migrating the host to Swift, the first adopter verifies those by running its e2e tests on Swiftail nodes (after separate approval, using the groundwork in `SwiftailNetstack.md` review result 6).

## 8. Implementation Units

Split units so owned files do not overlap. The declarations in §2 and the `package` declarations below define the interfaces between units. M7-0 finalizes them.

```swift
// Swiftail (package). Used by SwiftailCertificates.
extension TailnetNode {
    package func setDNS(name: String, value: String) async throws(ControlError)
    package nonisolated var certificateFacts: AsyncStream<CertificateFacts> { get }   // On changes to state, own name, cert domains, or MagicDNS enablement
    package nonisolated var stateDirectory: URL { get }
}
// SwiftailIO (package). Used by SwiftailLoopback.
extension NetworkSocket {
    package static func connectLoopback(port: UInt16) async throws(SocketError) -> NetworkSocket
    package var localPort: UInt16? { get }
    package func finishWriting()
}
```

| Unit | Work | Owned files | Order |
| --- | --- | --- | --- |
| M7-0 | Lead session: finalize this contract (H, answers to F, U1), verify notes (another session), add four targets to `Package.swift`, stub the `package` declarations above, update plan | `docs/contracts/SwiftailHost.md`, `docs/plan.md`, `docs/protocol-notes/`, `Package.swift` | First |
| M7-1 | `whoIs` and `PeerIdentity` (behavior W), address table, Go rules for `computedName` (W4) | `Sources/Swiftail/PeerIdentity.swift`, `Sources/Swiftail/TailnetNode+WhoIs.swift`, `Tests/SwiftailTests/WhoIs*` | **Parallel** |
| M7-2 | Control `set-dns` (behavior D) and node `package` interface (include MagicDNS enablement in `CertificateFacts`. Behavior C1 ②) | `Sources/SwiftailControl/Client/ControlClient+SetDNS.swift`, `Sources/SwiftailControl/Tailcfg/SetDNSRequest.swift`, `Sources/Swiftail/TailnetNode+Certificates.swift`, `Tests/SwiftailControlTests/SetDNS*` | **Parallel** |
| M7-3 | Encoding and signing: base64url, PEM (check entire input), DER writing (including `PrintableString`), JWK and thumbprint, JWS, CSR (tests 4–7) | `Sources/SwiftailCertificates/Encoding/*`, `Sources/SwiftailCertificates/JOSE/*`, `Sources/SwiftailCertificates/CSR/*`, test folders with the same names | **Parallel** |
| M7-4 | ACME messages and order procedure value types (behaviors C4–C7 and C12, X1, X2, X4, and X5: handling multiple authorizations by status, the five order and finalize states, problem documents, `Retry-After`), transport protocol and `URLSession` implementation | `Sources/SwiftailCertificates/ACME/*`, `Tests/SwiftailCertificatesTests/ACME/*` (basic path) | After M7-3 declarations are in place. Largest unit |
| M7-5 | Storage and verification (behaviors S and X3: directory permissions check, 0600, key match, system roots only, remove self-signed certificates from `chain`), renewal decision (behavior R: branch for failures the user must fix, preserve `Retry-After` and 7 days) | `Sources/SwiftailCertificates/Store/*`, `Sources/SwiftailCertificates/Renewal/*`, test folders with the same names | **Parallel** (uses only M7-3's PEM) |
| M7-6 | `CertificateManager` and public types (behaviors C1–C3, C8–C11, K. Single flow for the account key and `accountKeyUnreadable`, `retryNow()` sends no request before `Retry-After`) | `Sources/SwiftailCertificates/CertificateManager.swift`, `TailnetCertificate.swift`, `CertificateStatus.swift`, `Tests/SwiftailCertificatesTests/Manager*` | After M7-2, 4, and 5 |
| M7-7 | Independent tests: fake ACME server (in-memory server that follows RFC 8555 state transitions) and scenarios from tests 8 and 9. Write from the contract and notes alone | `Tests/SwiftailCertificatesTests/Support/*`, `Tests/SwiftailCertificatesTests/Scenarios/*` | **Different session** from the one that wrote M7-4. Harness in parallel |
| M7-8 | Go reference value tool and fixtures, comparison tests | `Tools/interop/cmd/acmefixtures/`, `Tests/SwiftailCertificatesTests/Fixtures/*`, `Tests/SwiftailCertificatesTests/GoComparisonTests.swift`, new section in `Tools/interop/README.md` | Tool in **parallel**. Comparison tests by another session after M7-3 |
| M7-9 | Loopback bridge (behavior B) and additions to `NetworkSocket` | `Sources/SwiftailLoopback/*`, `Sources/SwiftailIO/NetworkSocket+Loopback.swift`, `Tests/SwiftailLoopbackTests/*` | After M7-1 (identity). Socket additions in parallel |
| M7-10 | Gate (a): `tailnet` tool `DNSConfig` (cert domains and MagicDNS), `acmeStart`, `setDNSLog`, `setDNSFault`, `setCertDomains`, `peerHTTP`, `peerWhoIs`, `goState`, minimal HTTP/1.1 test server, `HostTests.swift` | `Tools/interop/cmd/tailnet/*`, `Tools/interop/go.mod` and `go.sum`, `tailnet` section in `Tools/interop/README.md`, `Tests/SwiftailInteropTests/HostTests.swift`, `Tests/SwiftailInteropTests/Support/MinimalHTTPServer.swift` | Tool in **parallel**. Tests after M7-6 and 9 |
| M7-11 | Go state import (behavior G: one-profile scope, rejection rules and `unsupportedState`, control server comparison). **Start only if U1 is migration** | `Sources/SwiftailControl/Client/GoStateFile.swift`, `Sources/Swiftail/GoStateImport.swift`, `Tests/SwiftailControlTests/GoStateFile*`, `Tests/SwiftailTests/GoStateImport*` | Parallel |
| M7-12 | Gate (b) and replacement in the first adopter's repository | With the first adopter session. Separate approval | After another session's review and gate (a) |

Order: M7-0 → (M7-1, 2, 3, 5, harness for 7, tool for 8, socket for 9, tool for 10, 11) in parallel → M7-4 → M7-6, M7-9 → tests for M7-7 and 8 → tests for M7-10 → review by another session → lead session reruns gate (a) → gate (b).

### Estimated Size

| Component | Library (lines) | Tests (lines) |
| --- | --- | --- |
| `whoIs` | 200 | 350 |
| `set-dns` and interfaces | 200 | 250 |
| Encoding, JOSE, CSR | 450 | 600 |
| ACME procedure and transport | 1,000 | 1,900 (including fake server) |
| Storage, verification, renewal decision | 450 | 700 |
| `CertificateManager` | 350 | 450 |
| Loopback bridge | 300 | 500 |
| Go state import | 250 | 450 |
| Go tools (`acmefixtures`, `tailnet` additions) | — | Go 800 |
| Gate tests and minimal HTTP server | — | 700 |

About 3,200 library lines and 5,900 Swift test lines (the notes verification added ACME procedure branches, storage permission checks, Go state rejection rules, and `computedName`). Smaller than M6 (TCP stack), with a narrow scope of handwritten formats (DER writing, JWS). The difficulty lies in the parts that cannot be verified locally, rather than the amount of code.

### Largest Risks

1. **Real issuance can only be verified on a real tailnet.** The client source does not show what the production control server's `set-dns` requires or when it replies (notes §8), and testcontrol's handler is for testing. Let's Encrypt limits how often failures can be retried (5 certificates for the same name in 7 days, 5 authorization failures in an hour). Mitigation: verify the ACME side with pebble first, then test `set-dns` on a real tailnet with staging and do only one production issuance.
2. **The loopback bridge crosses an identity boundary.** An authenticated tailnet connection becomes an anonymous `127.0.0.1` connection, so if any table invariant (behavior B6) or server rule (B7) is violated, another process on the Mac can appear to be a paired device or a legitimate connection can be dropped. The first adopter owns the server half. Mitigation: fix identity to the connection (B2), and check both sides with gate (a) items 9 and 10 and unit test 14. Review reproduced a bypass of the source port table, so it changed to a single-use token inside the connection (M7-9b). Also, the cost of going through two TCP stacks and copying during a 4GiB transfer is unknown until measured.
3. **Go state migration affects the owner's real nodes and is hard to roll back.** Server behavior when both implementations use the same node key, and the effect of reconnecting with zero `NLKey`, are unknown. Mitigation: do not implement before owner decision U1. If implemented, limit it to read-only, once, identity only, and run gate (b) 8 first with a test node.

Other points: This repository has not run it inside App Sandbox. The first adopter session checks it in the sandboxed version (review result 5, §9). The test tool brings in MPL-2.0 modules (H10).

### Items to Leave as `shortcut:`

| Deferred item | When needed |
| --- | --- |
| ARI and `replaces` (H6) | When the CA gives an earlier renewal time (mass revocation), or when the ARI renewal exemption is needed (conditions in notes §4.5). The 2/3 rule does not guarantee avoiding limits (behavior R1) |
| Alternate chain (`Link: rel="alternate"`) | When a device cannot verify the default chain with system roots (notes §6. Go's issuance path does not use this either) |
| TXT record lookup in advance | When `set-dns` frequency becomes a problem |
| No persistent account URL (look up at each start) | When one request needs to be saved |
| No deletion of certificate files for old names | An adopter with frequent name changes |
| Store only one nonce | When sending requests concurrently |
| Wildcards, cert domains other than own FQDN, TLS-ALPN-01 | When adding features corresponding to Funnel and Serve |
| `whoIs` `CapMap` | An adopter that uses grants to divide app permissions |
| Per-chunk `[UInt8]` copy in the bridge | When gate throughput records show a bottleneck (with `SwiftailNetstack.md` review result 7) |
| IPv6 loopback (`::1`) in the bridge | An adopter using such a listener |
| Event announcing imminent expiration | When the app stops reading `status` |
| Certificate file protection class on iOS | An adopter listening on iOS |

## 9. Unverified at Draft Time and Later Checks

- **Operation inside App Sandbox**: Whether `SecIdentityCreate`, `SecKeyCreateWithData`, loopback `NWListener` and `NWConnection`, and `URLSession` work with only the network server and client entitlements. The Apple experiments reported by the authoring session (CSR verification, `NWListener` TLS and ALPN negotiation, no Keychain writes) are unverified because there is no record (notes §8, §9 V173, V179, V188, V189, and V191). The verification session reran only the key, signature, and PEM format checks in notes §4.6 (outside the sandbox). Do not use this as the basis for implementation. **The first adopter session verifies it in the sandboxed version** (first adopter review result 5). Verified on 2026-11-15 ("Subsequently verified" in behavior B9). The first adopter's committed Mac app has an empty entitlements file (F7). The entitlement key names in behavior B9 were also not checked against Apple documentation.
- **Original subject and issuer comparison in behavior S6**: The draft did not check the Security API against SDK declarations. M7-5 identified the declarations, and review subsequently replaced the comparison with removal of the evaluated trust anchor (S6).
- **H4's `NWConnection` experiment**: Bridge tests verify that the local port read by the bridge equals the listener-side framer `remote` port (the grant is refused if the `(source port, listener port)` key does not match. M7-9b).
- **Production control server `set-dns`**, tagged and shared node profiles, authorization reuse (result of Go's flow), the registered-domain boundary for `ts.net` (public PSL says `tail0001.ts.net`. Production CA deployment and exceptions unknown), whether MagicDNS is always enabled when `CertDomains` exists, node reconnecting with zero `NLKey`, two sessions with the same node key, and server handling of the old key after rollover: notes §8.
- **`NWConnection` half-close**: Whether sending an empty final message emits TCP FIN, and how a peer FIN appears at an `NWListener` that terminates TLS. M7-9 checks manually first. HTTP/1.1 knows request and response boundaries from lengths, so it does not rely on half-close.
- **Putting `NWProtocolFramer` below TLS** (H3 (c)): Verified outside the sandbox (behavior B, "Experimentally Verified," gate (a) 8–10). Not run inside App Sandbox (first adopter session's responsibility).
- **Passing intermediates** (`sec_identity_create_with_certificates`) and verification with `SecTrust`: Verified only that they are public APIs.
- **pebble and challtestsrv**: Downloaded modules (pebble `go 1.25.0`, challtestsrv `go 1.24`, both MPL-2.0) and read packages and function signatures (notes §8). At that point they had not been built into `Tools/interop`. It was unknown whether they could run in the same process as `testcontrol` or whether their dependencies conflicted with the pinned `tailscale.com` version.
- **Bridge throughput** and CPU use in large transfers.
- **Current lifetime of certificates from Let's Encrypt** and issuance duration.
- For first adopter Swift call sites (callers of `RDCoreBridge.swift`), only uses of function names were counted. The host app's use of state and events was read from the Go-side docs (`docs/protocol.md` §§9 and 10, `docs/protocol-addenda.md` A.5).

## Changes from Notes Verification (2026-11-15)

Incorporated the comparison table in notes §10 and claims marked "incorrect" in §9. The lead session's decisions and first adopter review decisions remain as recorded. New choices are H16–H23.

| Row in notes §10 | Change |
| --- | --- |
| W4, `computedName` comment | Rewrote behavior W4 to match Go (suffix at label boundary, FQDN for shared nodes, trailing dot, hostname sanitization, node key) and recorded W3's empty `StableID` rejection as first adopter policy. `PeerIdentity.computedName` comment, unit test 1 |
| D1–D3 | D1 distinguishes "same Noise client" and "same HTTP/2 connection." Marked D2 and D3 "Swiftail's choice" and described Go's behavior alongside them (immediate failure, 1MiB, accepts `null`, 200 code points). Unit test 2 |
| C2 | Distinguished path checks and DNS name checks. Alphanumeric first and last characters in labels, 1–63 characters, 253 characters, same limit after adding `_acme-challenge.`, relationship to `PrintableString`, failure type on mismatch (H23). Unit test 11 |
| C4, S2, G6 | C4: P-256 only, new key only if file absent, `accountKeyUnreadable` if unreadable (new `CertificateError` case, H16), one flow in the actor. S2 and S3: PKCS#8 and SEC1 reads verified in notes §4.6. G6: no guarantee of RSA account key compatibility |
| C5 | Do not require a specific authorization count and handle all by status, check `identifier.type`, value, and `wildcard`, branch on order `ready`, `valid`, and `processing`, check response `identifiers`. Limit of 8 authorizations in the limits table. Unit test 8 |
| C7, R4, X2, X5, limits table | Do not shorten `Retry-After`. Send no requests to that ACME server before that time. If it exceeds the 5-minute deadline, end the attempt and preserve it as `nextAttempt`, capped at 7 days (upper end only). `retryNow()` also sends no requests before then (X5, C10, R3 and R4, `status` and `retryNow()` comments, H21). Removed the 1–30-second and 24-hour clamps |
| Finalize statuses and `validationFailed` | Rewrote C7 as waiting, finalize, and download, with branches for all five statuses. `valid` before CSR starts a new order (H17). Split `CertificateFailure` into `validationFailed` (authorization `invalid`) and new `orderFailed` (H19). New `unexpectedResponse` for specification violations (H18) |
| Problem document, `CertificateFailure.acme` | `acme(status:type:)`, full `type` string, empty string, 256 bytes, omit `detail`, special cases only for ACME URNs (new behavior C12). Unit test 8 |
| C8, S3 | System roots only in production, explicit anchors in tests, no built-in root fallback or nonproduction exception as in Go, documented as a choice that differs from Go (S3 ⑤, X3, C8). Documented that verification before storage is a stronger boundary than Go's |
| S1–S3, `chain` comment | S1: new `certs/` 0700, preserve existing directory permissions, and fail on group or other writes (H20). S2: all new files 0600, two files are not one transaction, and matching in S3 ④. New behavior S6 and `chain` comment: root may arrive and self-signed certificates are removed after verification. X3 ①: check entire input |
| R1, R4, H6, `shortcut:` | Removed "2/3 stays below limits" and cited the limits and ARI exemption conditions in notes §4.5 (R1, rationale for H6, `shortcut:` table). R4 distinguishes failures the user must fix (no time-based retry, nil `nextAttempt`) and other failures. 12 minutes is a refill rate, not a minimum interval. Consecutive failure limit. Added `magicDNSDisabled` condition to C1 |
| G2–G4 | G2: one-profile scope, standard base64, whole key in `_current-profile`, `_profiles`, classify rejections (zero machine key, missing referenced key, mismatch, multiple profiles, legacy, `OldPrivateNodeKey`) as `malformed` or new `unsupportedState` (H22). G4: difference from Go when omitting `OldPrivateNodeKey` |
| G3 | Default server synonyms (empty value, `https://controlplane.tailscale.com`, `https://login.tailscale.com`), custom servers match only when the path is empty or `/` and there is no query, fragment, or userinfo |
| G public API, G4, G7, gate (a) 11 | Qualified "starts as the same node" to "if the server accepts it as the same node" in the `importIdentity` comment and G7, and stated that results for zero `NLKey`, duplicate sessions, and old keys are unverified before the gate. Criteria for gate (a) 11 and (b) 8 |
| Test section | Distinguished byte and semantic comparisons in unit tests 5–7 and Go reference comparison (CN `PrintableString` and the four CSR conditions, JWS serialization). Added `DNSConfig` to the gate (a) tool. In §6, B9, §9, and gate (b) 7, avoided relying on unverified Apple experiments and pointed to first adopter review result 5 |

Where the 18 claims marked "incorrect" in notes §9 remained in this contract:

- V056, V178, and V224 (CSR CN tag, conditions for byte equality): unit test 7, Go reference comparison, behavior C7.
- V110 (new key only after `ready`): documented Go's actual behavior and Swiftail's difference in behavior C7.
- V142 (problem document and `type`): behavior C12, `CertificateFailure.acme`.
- V162, V166, and V168 (guarantee of avoiding rate limits): behavior R1, rationale for H6, `shortcut:` table.
- V164 (12 minutes is a minimum interval): behavior R4.
- V199 (all keys use `privkey:`): behavior G2.
- V201 (zero node key means never logged in): behavior G3, `notLoggedIn` comment.
- V202 (no need to migrate `OldPrivateNodeKey`): behaviors G2 and G4.
- V213 (1MiB per certificate): documented Go's actual limit in behavior X2.
- V222 (JWS byte equality): unit test 6, Go reference comparison.
- V242 (both modules use go1.25): §9.
- V147 (jitter and 10-second cap), V151 (renewal time cache), V152 (`replaces` with every renewal): the contract did not make those claims (it does not port Go's HTTP retries or ARI).

Also corrected "notes not yet verified" and "small experiments run outside the repository" in the introduction, added `magicDNSDisabled` to the §4 mapping and MagicDNS to the §8 `package` declaration comment, and aligned the implementation unit table and estimates.

## Logout (First Adopter Request, 2026-11-15)

The Mac app added tailnet logout (stop sharing → empty the state folder). Deleting the folder alone leaves the old node on the control server. Go's `tailscale logout` tells the server to expire the node key. Add that request (first adopter request). **RemoteDebug's Go core did not make this request** (its logout only empties the state folder. The first adopter corrected this on 2026-11-15). This is therefore an addition beyond "Whatever the Go core can do, Swiftail can do too." It aims to reduce name collisions from old nodes when logging in to the same tailnet again. Whether it actually does requires checking with the production server.

Basis: `TryLogout` and `doLogin` (`loginOpt.Logout`) in `control/controlclient/direct.go`, and the logout path in `ipn/ipnlocal`. During implementation, confirm details (request fields, response handling, deadline) against the Go source and record them under "Decisions from Implementation."

### API

```swift
extension TailnetNode {
    /// Tells the control server to expire this node's node key (the server-side part of Go `tailscale logout`).
    public func logOut() async throws(NodeError)
}
```

### Behavior O

1. Call only while `run()` is not running (before it starts or after it ends). If a `run()` using the same state directory is running, return `stateDirectoryInUse`.
2. If the stored identity has no node key (never registered), return without sending anything.
3. Use the same path as registration (`/machine/register` over Noise). Use the current node key as-is and set `Expiry` to the same far-past value as Go. Include no auth key or login URL. Do not generate a new node key.
4. Response: If there is `Error`, return `control(.registrationRejected)`. Other responses (including `NodeKeyExpired`) are success. Do not follow `AuthURL` or `NodeKeySignature` (Go's `TryLogout` discards them).
5. Set an overall deadline (check and follow Go's value, or use 10 seconds if none). On timeout, `control(.connection)`. Do not retry.
6. **Leave local files untouched.** The app deletes identity, lock state, and certificates. App sequence: cancel `run()` and wait for it to finish → `logOut()` → empty the state folder. If `logOut()` fails (no network), the app can still delete the folder. The old node then remains on the server.
7. Secrets: Do not log keys from requests, responses, or errors.

### Tests and Gates

- Unit tests: request format (wire representation of `Expiry`, node key unchanged, no auth), send nothing without an identity, `Error` response, deadline.
- Interop (testcontrol): After a registered node calls `logOut()`, its key appears expired on the server. Record what happens when calling `run()` again with the same state folder (Go is asked to log in again).
- Check with the production server (add to gate (b)): how the logged-out node appears in the admin console and whether the new node logging in with the same name gets a numbered suffix. Swiftail is responsible for sending the same request as Go.

### Decisions from Implementation (2026-11-15)

Sources are tailscale.com v1.104.7 `control/controlclient/direct.go` (`TryLogout` lines 505-516, `doLogin` lines 634-903), `control/controlclient/auto.go` (`Logout` lines 856-882), `ipn/ipnlocal/local.go` (`Logout` lines 7253-7305), and `tailcfg/tailcfg.go` (`RegisterRequest.Expiry` lines 1332-1336). Implemented in `Sources/SwiftailControl/Client/ControlClient+Logout.swift` (`ControlClient.logOut()`, `package`) and `Sources/Swiftail/TailnetNode+Logout.swift`.

**Go and Swiftail logout request fields.**

| Field | Go (`doLogin`, `opt.Logout`) | Swiftail |
| --- | --- | --- |
| `NodeKey` | Current node key in the persisted state (`tryingNewKey = persist.PrivateNodeKey`). Error `no nodekey to log out` if absent | Node key in identity file. Success without sending if absent (behavior O2. Same result as `hasNodeKeyLocked` in Go `LocalBackend.Logout`) |
| `OldNodeKey` | `OldPrivateNodeKey` from persist (old key if the key has changed, else zero) | Always zero. Swiftail does not store the old node key |
| `NLKey` | NL public key in persist (generate if absent) | NL public key in identity file (`NodeIdentityStore.load()`. For an old file, a new unsaved key) |
| `Expiry` | `time.Unix(123, 0)`. `time.Unix` returns a time in the local time zone, so JSON reflects the process time zone, for example `1970-01-01T09:02:03+09:00` | `1970-01-01T00:02:03Z` (UTC). Same instant |
| `Auth` | Included if the control client holds an auth key (and `NodeKeySignature` if wrapped). tsnet's `lc.Logout` arrived at testcontrol without `Auth` | Omitted (behavior O3) |
| `Followup` | `""` | `""` |
| `Hostinfo` | Current Hostinfo (including NetInfo) | `Hostinfo.swiftail(…, netInfo: nil)` |
| `Ephemeral` | False (`Flags` is 0) | Omitted (false) |
| `NodeKeySignature` | Only for the wrapped key case above | `null` |
| `Version`, `Timestamp` | `CurrentCapabilityVersion`, current time (for signing) | 148, absent (same as registration) |

A test compares the two requests received by testcontrol (`lockRegistrations`): both have `expiryUnix` 123, `auth` false, no `oldNodeKey`, an `nlKey`, and no signature.

**Response and deadline.** Go's `doLogin` returns errors for non-200 HTTP responses (including 429 and 503 with `Retry-After`), body parse failure, and `Error` present. The rest (`NodeKeySignature`, `NodeKeyExpired`, `AuthURL`) are returned as `mustRegen` and `newURL`, but `TryLogout` discards them and returns only the error. `TryLogout` clears persist in memory regardless of result. `LocalBackend.Logout` deletes the profile only if `cc.Logout` succeeds. Deadline: Go has no logout-specific deadline. `Auto.Logout` and `LocalBackend.Logout` use the supplied context as-is, the CLI uses `context.Background()`, and LocalAPI uses the request context. Thus use behavior O5's 10 seconds (`ControlClient.Timeouts.logout`). This deadline covers receiving the server key, connecting, and receiving the response.

Swiftail errors: non-200 yields `control(.http(status:))` (no wait for 429 or 503 either), parse failure, connection failure, deadline, and cancellation yield `control(.connection)`, `Error` yields `control(.registrationRejected)` (redact auth keys in the message and truncate at 200 characters as in registration), and an unreadable identity file yields `control(.storage)`. No retries.

**Start check.** `logOut()` claims the state directory with the same `StateDirectoryClaims` as `run()` and releases it when finished. An active `run()` for the same directory yields `stateDirectoryInUse`, and a `run()` started during `logOut()` also ends with `stateDirectoryInUse`. If an interface was reported via `setDefaultInterface`, connect through it. The only log messages are "Logout: notified the server of node key expiration" and "Logout failed." Do not log keys or addresses.

**Observed in testcontrol** (`Tests/SwiftailInteropTests/LogoutTests.swift`, `Tools/interop/cmd/tailnet/logout_test.go`). Upstream testcontrol ignores `Expiry`, so the copy adds handling ([Logout gate commands](../../Tools/interop/README.md#logout-gate-commands)): For an `Expiry` in the past, set the node's `KeyExpiry` to that value and send a new map to every node. Production server handling is conjecture.

- After logout, the server retains the node in its listing and its `KeyExpiry` is `1970-01-01T00:02:03Z`. The response is `NodeKeyExpired: true` (the copy's original check), and both implementations treat it as success.
- The node remains in another peer's (Go) netmap with only `KeyExpiry` changed. Go receives this change as a delta (`PeerChange.KeyExpiry`) and computes the peer's `Expired` flag only when receiving a full netmap (`ipn/ipnlocal/local.go:1895` `flagExpiredPeers`), so it initially appears as `Expired: false`, `Online: true`. If the other peer is a Swift node, `EnginePeer` immediately removes peers whose `keyExpiry` has passed from WireGuard (untested).
- Go peer (tsnet) logout: After completion `BackendState` is `NeedsLogin` and Go deletes the profile. Restarting with the same state directory registers a new node key with the auth key and creates a new node on the server (the old node remains expired, making 3 nodes. testcontrol does not number names).
- If the Swift node calls `run()` again with the same state directory and local files intact (without following the app sequence): register with the stored logged-out key → `NodeKeyExpired` → switch to a new key and register (`OldNodeKey` = logged-out key) → testcontrol clones the old node for the new key, copying `KeyExpiry` (1970) too → `.running` appears once, then the node sees its own expiration and registers another new key → expired again → `run()` ends with `control(.nodeKeyExpired)`. The only event is `stateChanged(.running)`. This result depends on testcontrol copying the expiration time when cloning. The production server is expected to require login when registering a new key for an expired node (Go "is asked to log in again"), but that is unverified. The app empties the state directory after `logOut()`, so it does not take this path.

**Differences from the contract.** None. In behavior O4's "other responses are success," HTTP responses other than 200 remain failures (`http(status:)`), as in Go.

### Independent Logout Review Results (2026-11-15)

A session other than the author checked against the Go source (`direct.go:634-790`, `tailcfg.go:1318-1369`) and added 12 tests (`LogoutReviewTests`, `NodeLogoutReviewTests`. All passed). No critical or high findings. It found no difference from Go's logout request likely to affect the server's decision (unverified with the production server). Only documentation was fixed.

- **Behavior O1 holds only within the same process (normally)**: The state directory claims table is in-process. If another process (the tunnel extension) is running `run()` with the same folder, calling `logOut()` is not blocked, and the running node sees its key expire and registers with a new key (with a reusable auth key this reverses logout and creates a new node on the server). The app stops that process first. Documented in the doc comment.
- Overlapping `logOut()` calls and a `run()` started during logout also yield `stateDirectoryInUse` (the behavior was correct and undocumented).
- A `logOut()` canceled or timed out after sending the request yields `control(.connection)`, but the server may already have applied it. Failure does not mean "the old node remains."
- With an old identity file lacking an NL key, the request carries a new unsaved `NLKey` (same as Go). This is unlikely for a node registered by Swiftail because Swiftail saves the NL key before registration. How the production server regards a changed `NLKey` in a logout request is unknown.
- `nodeKeyExpired` when running `run()` again with the same state folder after logout is a property of the testcontrol copy (it copies the expiration time when cloning the old node). The likely production flow (expiration → register new key → require login → store new key) passed against a fake server.
- Reference source versions: the contract uses v1.104.7, and the testcontrol copy and its addition (`logout.go`) use v1.104.6.

Unverified: all production control server handling (response shape, admin console display, whether names get numbered suffixes), 429 and 503 on registration requests, deadlines when stalled in DNS or TLS, and behavior in the tunnel extension.

### Other First Adopter Requests (2026-11-15, Not Urgent)

- **Path lookup by stable ID: added (2026-11-16).** `TailnetNode.path(toPeerWithStableID:)`. Same meaning as `path(toPeerNamed:)`, with a different lookup key. Pairing records contain only the peer's stable ID and short name, so the first adopter removed per-device path display after removing Go. `peerPathChanged` events still report by name (the display polls status).
- **Public initializers for state types: added (2026-11-16).** `NodeStatus`, `PeerIdentity`, `CertificateStatus`. The node and manager do not use them. They allow testing code that receives these values without a node.
- The first adopter said peer enumeration was unnecessary.
