# SwiftailMagicsock Contract (M4)

M4 targets **direct connections**. Establish a direct UDP path to a Go peer over loopback or LAN, fall back to DERP when the direct path is blocked, and return to the direct path when it is unblocked (`docs/plan.md` §7 M4). Through M3 there is no UDP socket, and all packets go through the home DERP region.

`SwiftailMagicsock` contains only **I/O-free value types**. They seal and open disco messages, track per-peer path state (candidate addresses, Ping and Pong, `bestAddr` and trust period, heartbeat), parse STUN, determine local endpoints and the home region, and come together in the `Magicsock` state machine to decide where to send WireGuard datagrams and how to classify incoming datagrams. UDP sockets (POSIX) and interface address lookups live in `SwiftailIO`. Timers, DERP connections, and socket read loops live in `TailnetNode` (the edge actor). As before, the engine only emits "a WireGuard datagram for this peer," and `Magicsock` chooses the path (see [Why this structure?](SwiftailWireGuard.md#why-this-structure) in `docs/contracts/SwiftailWireGuard.md`).

Protocol details follow the verified [protocol-notes/disco-magicsock.md](../protocol-notes/disco-magicsock.md) (the "notes" below) and [derp-stun.md](../protocol-notes/derp-stun.md) §3.8, §3.9, and §4.8~§4.10 (the "DERP notes" below). This document defines only module boundaries, the M4 scope, tests, and gates. See [Changes in M4](SwiftailEngine.md#changes-in-m4) in `SwiftailEngine.md` for engine and node changes.

## Targets

| Target | Dependencies | Contents |
| --- | --- | --- |
| `SwiftailBase` | Foundation, Network | Existing contents + **`IPEndpoint`** (move it from `SwiftailControl/Tailcfg/IPEndpoint.swift` and keep its public name. The `Codable` extension stays in `SwiftailControl`, as with `IPAddress+Codable.swift`) |
| `SwiftailIO` | `SwiftailBase` (new), Foundation, Network, Synchronization | Existing contents + `DatagramSocket` and `LocalInterfaceAddresses` (both `package`) |
| `SwiftailMagicsock` (new target, exported as a product) | `SwiftailBase`, `SwiftailCrypto`, CryptoKit | API below. No socket, clock, or actor |
| `Swiftail` | Existing dependencies + `SwiftailMagicsock` | Node integration ("Changes in M4" in the engine contract) |

`SwiftailMagicsock` has no dependency on `SwiftailControl`, `SwiftailDERP`, `SwiftailWireGuard`, or `SwiftailEngine`. The node extracts and passes in the required values from netmap and DERPMap (tailcfg), including peers' disco keys, endpoints, and home regions, and each region's STUN addresses. This works the same way as `SwiftailDERP` receiving a `DERPServer`.

The dependency diagram in `docs/plan.md` §5 shows `SwiftailEngine` depending on `SwiftailMagicsock`, while this contract has the node connect the two (lead session decision Q1 below). For "UDP sockets and rebinding" in the module table, the socket wrapper goes to `SwiftailIO` and rebinding goes to M5.

## Structure

```
                 TailnetNode (actor, edge: clock, socket, DERP connections, timers)
   IP packet ─► TailnetEngine ─ .datagram(to: peer) ─► Magicsock ─ .udp / .derp ─► DatagramSocket / DERPClient (per region)
   IP packet ◄─ TailnetEngine ◄─ receive ─────────── Magicsock ◄─ receiveUDP / receiveDERP ◄─ socket / DERPClient
                                                    │
                                                    ├ .endpointsChanged, .homeRegionChanged ─► ControlClient.setLocalStatus
                                                    └ .pathChanged ─► NodeEvent
```

Value types in `Magicsock` and their responsibilities follow.

| Type | Access | Responsibility | Unit |
| --- | --- | --- | --- |
| `TransactionID` | internal | 12-byte ID shared by disco and STUN | 0 |
| `DiscoMessage` | internal | Encode and parse plaintext Ping, Pong, and CallMeMaybe (notes §3.3 and §3.4) | 1 |
| `DiscoPacket`, `DiscoSharedKey` | internal | Identify the outer format, read the sender's disco key, seal and open (notes §3.1 and §3.2) | 1 |
| `PeerPathState` | internal | Candidate addresses, sent Pings, `bestAddr`, trust, heartbeat, and path selection for one peer (notes §4.4~§4.8) | 2 |
| `STUNMessage` | internal | Create binding requests and parse responses (DERP notes §3.8, §3.9, and §4.10 item 3) | 3 |
| `Netcheck` | internal | STUN rounds, per-region latencies, local endpoint list, and home region selection (notes §4.9, DERP notes §4.8 and §4.10) | 3 |
| `Magicsock` | public | Integrates the above, classifies inbound traffic, and handles the disco key table and shared keys, the collection of peers, CallMeMaybe, and path events | 4 |
| `PeerPath` | public | Public representation of a peer path (same meaning as Go `curAddr`) | 0 |

Test internal types with `@testable import` (as in `SwiftailWireGuard`). The public scope covers only `Magicsock` and its input and output types, which the node uses, and `PeerPath`.

## Public API (`SwiftailMagicsock`)

```swift
/// A path to a peer. Equivalent to `CurAddr` in Go's `ipnstate.PeerStatus` (notes §6.3, last line, and §7.1).
public enum PeerPath: Sendable, Equatable {
    /// Sends only to a trusted direct UDP address within its trust period.
    case direct(IPEndpoint)
    /// Relays through DERP, including when also sending to a direct address (an expired `bestAddr`).
    /// - Parameter derpRegion: The peer's home DERP region. 0 means unknown.
    case relayed(derpRegion: Int64)
}

/// A state machine that discovers and maintains direct paths between peers. It has no socket, clock, or actor.
///
/// The node supplies received UDP datagrams, packets received through DERP, WireGuard datagrams emitted by the engine, peer information from the netmap,
/// and the current time. `Magicsock` updates state and returns what to send over UDP or DERP, what to feed into the WireGuard device,
/// what to publish to the control server, and which peers changed paths. No entry point throws. Drops are reported as `.dropped`.
///
/// This type uses system randomness for the disco nonce, TxID, and ReSTUN interval (as in `WireGuardDevice`). The layers below it
/// (`PeerPathState`, `Netcheck`, and `DiscoPacket.seal`) take randomness as arguments.
public struct Magicsock: Sendable {
    /// The information needed to discover paths for a single netmap peer. The node builds this from `EnginePeer`.
    public struct Peer: Sendable, Equatable {
        public var key: NodePublicKey
        /// 0 disables disco with this peer, leaving only DERP.
        public var discoKey: DiscoPublicKey
        /// 0 means unknown.
        public var homeDERP: Int64
        /// The netmap's `Endpoints`. Only IPv4 addresses are candidates (behavior D1).
        public var endpoints: [IPEndpoint]
        public init(key: NodePublicKey, discoKey: DiscoPublicKey, homeDERP: Int64, endpoints: [IPEndpoint])
    }

    /// A DERP region eligible to be home. The node extracts it from DERPMap (engine contract M4 behavior N3).
    public struct Region: Sendable, Equatable {
        public var id: Int64
        /// STUN query addresses. An empty list leaves this region unmeasured and eligible as fallback home only when there are no measurements.
        public var stunServers: [IPEndpoint]
        /// DERPMap `HomeParams.RegionScore`. Multiply the latency by this value only if positive. Defaults to 0.
        public var score: Double
        public init(id: Int64, stunServers: [IPEndpoint], score: Double = 0)
    }

    /// The inbound path. Determines the disco path rules and where to reply to a WireGuard datagram.
    public enum Source: Sendable, Hashable {
        case udp(IPEndpoint)
        /// The sender's node key and the region where the packet arrived.
        case derp(NodePublicKey, region: Int64)
    }

    /// A local endpoint to publish to the control server.
    public struct Endpoint: Sendable, Equatable {
        public enum Source: Sendable, Equatable {
            /// The interface address + socket port. tailcfg `EndpointLocal` (1).
            case local
            /// The external address from a STUN response. tailcfg `EndpointSTUN` (2).
            case stun
        }
        public var address: IPEndpoint
        public var source: Source
    }

    public enum Output: Sendable, Equatable {
        /// Sends over the UDP socket (WireGuard, disco, and STUN share it).
        case udp([UInt8], to: IPEndpoint)
        /// Sends to the peer over the connection for DERP region `region`. The node opens one if needed.
        case derp([UInt8], to: NodePublicKey, region: Int64)
        /// The datagram to feed to the WireGuard device (the engine's `receive`) and the path it came from. The node returns any cookie
        /// reply the device generates for this datagram over the same path without peer path selection (engine contract "cookie reply", 2026-11-15).
        case wireGuard([UInt8], from: Source)
        /// The local endpoints to publish to the control server changed (their order matters. Notes §4.9 item 1).
        case endpointsChanged([Endpoint])
        /// The home DERP region changed. Publish it in `NetInfo.preferredDERP` and connect to that region.
        case homeRegionChanged(Int64)
        /// The peer's path changed. Nil means the peer was removed or is idle (behavior G3).
        case pathChanged(NodePublicKey, PeerPath?)
        /// A drop, reported for diagnostics and testing.
        case dropped(Drop)
    }

    public enum Drop: Sendable, Equatable {
        /// The sender's disco key belongs to no known peer.
        case unknownDiscoKey
        /// A disco message that cannot be opened or parsed.
        case malformedDisco
        /// An unsupported disco type (peer relay 0x04–0x09) or a Geneve-encapsulated datagram.
        case unsupportedDisco
        /// A disco message that violates path rules (CallMeMaybe over UDP, CallMeMaybe with mismatched keys, or an unknown DERP sender).
        case misroutedDisco
        /// A STUN response that belongs to no active round or cannot be parsed.
        case unexpectedSTUN
        /// The DERP sender key belongs to no known peer.
        case unknownDERPSender
        /// No destination because there is neither a direct address nor a DERP region.
        case noRouteToPeer
        /// An unacceptable origin (IPv6 or port 0).
        case unsupportedSource
    }

    /// - Parameters:
    ///   - discoKey: This node's private disco key. The node generates it at startup without persisting it.
    ///   - nodeKey: This node's public node key. Included in outbound Pings (notes §4.6 item 1).
    ///   - localPort: The port the UDP socket is bound to.
    ///   - localAddresses: IPv4 interface addresses, excluding loopback. `LocalInterfaceAddresses` selects them.
    ///   - loopbackAddresses: Loopback IPv4 addresses. Used only when no other endpoints exist (notes §4.9 item 1.7).
    public init(
        discoKey: Curve25519.KeyAgreement.PrivateKey,
        nodeKey: NodePublicKey,
        localPort: UInt16,
        localAddresses: [IPAddress],
        loopbackAddresses: [IPAddress],
        now: ContinuousClock.Instant
    )

    public var discoPublicKey: DiscoPublicKey { get }

    /// Reconciles the netmap peers. The node supplies peers in node ID order, which determines peer table and output order. The first entry for a duplicate node key wins. Multiple peers may share a disco key (behavior B1).
    public mutating func setPeers(_ peers: [Peer], at now: ContinuousClock.Instant) -> [Output]
    /// Reconciles candidate home regions. Immediately starts a STUN round on change and chooses a fallback home immediately if there is no home.
    public mutating func setRegions(_ regions: [Region], at now: ContinuousClock.Instant) -> [Output]

    /// Sends one WireGuard datagram emitted by the engine to a peer, choosing the path.
    public mutating func send(_ datagram: [UInt8], to peer: NodePublicKey, at now: ContinuousClock.Instant) -> [Output]
    /// Receives one datagram from the UDP socket.
    public mutating func receiveUDP(_ datagram: [UInt8], from source: IPEndpoint, at now: ContinuousClock.Instant) -> [Output]
    /// Receives one packet on the connection for DERP region `region`. The `peer` is the sender's key in the DERP frame.
    public mutating func receiveDERP(_ packet: [UInt8], from peer: NodePublicKey, region: Int64, at now: ContinuousClock.Instant) -> [Output]

    /// Processes timers due through now (Ping deadlines, heartbeat, trust expiry, and STUN rounds).
    public mutating func advance(to now: ContinuousClock.Instant) -> [Output]
    /// The next time to call `advance`.
    public var nextDeadline: ContinuousClock.Instant? { get }

    /// The peer's current path. Nil if the peer is absent from the data plane.
    public func path(to peer: NodePublicKey, at now: ContinuousClock.Instant) -> PeerPath?

    /// (M5) Handles a newly bound UDP socket. Discards all peers' direct paths and starts a STUN round immediately.
    /// See `SwiftailTunnel` contract behavior N 3.3 for the rules.
    public mutating func rebind(localPort: UInt16, localAddresses: [IPAddress], loopbackAddresses: [IPAddress], at now: ContinuousClock.Instant) -> [Output]
    /// (M5) Handles a link change with the same socket. Restarts only the STUN round (Go `ReSTUN`).
    public mutating func restartSTUN(at now: ContinuousClock.Instant) -> [Output]
}
```

As with the existing state machines (`WireGuardDevice`, `DERPConnection`, and `TailnetEngine`), methods receive inputs.

| Input | Method |
| --- | --- |
| Received UDP datagram and source address | `receiveUDP(_:from:at:)` |
| Packet received via DERP (sender key, receiving region) | `receiveDERP(_:from:region:at:)` |
| Outbound WireGuard datagram from the engine | `send(_:to:at:)` |
| Peer information from the netmap | `setPeers(_:at:)` |
| Candidate home regions from DERPMap | `setRegions(_:at:)` |
| Time | `at` in all methods, `advance(to:)` |
| Randomness | Drawn internally from system randomness (see doc comments above) |

### Internal API (Contract Between Units)

Set the signatures for parallel implementation. Keep the names. Each unit decides internal implementation details (storage and helper functions).

```swift
// Unit 0 — Sources/SwiftailMagicsock/TransactionID.swift
struct TransactionID: Hashable, Sendable {
    static let byteCount = 12
    let bytes: [UInt8]
    init?(_ bytes: some Collection<UInt8>)                       // Nil unless the input contains 12 bytes
    static func random(using generator: inout some RandomNumberGenerator) -> TransactionID
}

// Unit 1 — DiscoMessage.swift, DiscoPacket.swift
enum DiscoError: Error, Sendable, Equatable {
    case malformed               // Length or format differs from the tables in notes §3.3 and §3.4
    case unknownType(UInt8)      // A type other than 0x01–0x03 (including 0x04–0x09)
    case authenticationFailed    // The secretbox cannot be opened
    case invalidKey              // Low-order public key (shared key is 0)
}

enum DiscoMessage: Sendable, Equatable {
    /// - nodeKey: The sender's public node key. Nil if absent or 0. Discard padding.
    case ping(TransactionID, nodeKey: NodePublicKey?)
    /// - source: Observed source address of the Ping. Unwrap IPv4-mapped addresses.
    case pong(TransactionID, source: IPEndpoint)
    /// An address list. A version ≠ 0, a 0-byte body, or a body whose size is not a multiple of 18 yields an empty list (no error).
    case callMeMaybe([IPEndpoint])

    init(parsing plaintext: [UInt8]) throws(DiscoError)
    /// Plaintext (type ‖ version 0 ‖ body). Ping has no padding and has a 12-byte body when nodeKey is nil.
    var plaintext: [UInt8] { get }
}

/// The NaCl box shared key from the local private disco key and the remote public disco key (notes §3.2 item 2). It is secret, and `customMirror` hides it.
struct DiscoSharedKey: Sendable {
    init(privateKey: Curve25519.KeyAgreement.PrivateKey, peerPublicKey: DiscoPublicKey) throws(DiscoError)
}

enum DiscoPacket {
    static let magic: [UInt8]            // 54 53 f0 9f 92 ac
    static let classificationLength = 38 // Notes §4.1 item 3
    /// Checks that the packet is at least 38 bytes long and starts with the magic bytes. It leaves the packet unopened.
    static func isDisco(_ bytes: [UInt8]) -> Bool
    /// The sender's public disco key (offset 6..<38). Present only when `isDisco` is true.
    static func senderKey(of bytes: [UInt8]) -> DiscoPublicKey?
    /// magic ‖ sender ‖ nonce ‖ secretbox(plaintext). The nonce is 24 bytes.
    static func seal(_ message: DiscoMessage, sender: DiscoPublicKey, sharedKey: DiscoSharedKey, nonce: [UInt8]) -> [UInt8]
    static func open(_ bytes: [UInt8], sharedKey: DiscoSharedKey) throws(DiscoError) -> DiscoMessage
}

// Unit 2 — PeerPathState.swift (+ PeerPathState+Ping.swift if needed)
struct PeerPathState: Sendable {
    enum Action: Sendable, Equatable {
        /// Sends a disco Ping to the candidate.
        case ping(TransactionID, to: IPEndpoint)
        /// Sends CallMeMaybe to the peer's home DERP. `Magicsock` supplies the local endpoints.
        case callMeMaybe
    }
    /// The destination for one WireGuard datagram (notes §4.5).
    struct SendPlan: Sendable, Equatable {
        var udp: IPEndpoint?
        /// The peer's home region if also sending over DERP. 0 means do not send over DERP.
        var derpRegion: Int64
        var actions: [Action]
    }

    init(homeDERP: Int64, endpoints: [IPEndpoint])
    /// Applies a netmap update to this peer's path state (notes §4.4 items 1 and 2).
    mutating func update(homeDERP: Int64, endpoints: [IPEndpoint], at now: ContinuousClock.Instant)
    /// Handles a change to the peer's disco key (notes §4.4 item 3).
    mutating func resetForNewDiscoKey()
    /// Notes §4.5 items 1–5 and §4.8 item 2.
    mutating func planSend(at now: ContinuousClock.Instant, using generator: inout some RandomNumberGenerator) -> SendPlan
    /// Handles a Ping received over UDP (notes §4.2 item 4.2). Returns true if a Pong is due (false for the same TxID from the same candidate).
    mutating func receivePing(_ txID: TransactionID, from source: IPEndpoint, at now: ContinuousClock.Instant) -> Bool
    /// Returns true if the Pong matches a Ping sent to this peer by the local state machine (notes §4.6 item 4). A nil `source` means it arrived over DERP.
    mutating func receivePong(_ txID: TransactionID, from source: IPEndpoint?, at now: ContinuousClock.Instant) -> Bool
    /// Handles a CallMeMaybe received over DERP (notes §4.8 item 5).
    mutating func receiveCallMeMaybe(_ endpoints: [IPEndpoint], at now: ContinuousClock.Instant, using generator: inout some RandomNumberGenerator) -> [Action]
    /// Handles Pong deadlines and heartbeats (notes §4.6 item 3 and §4.8 item 3).
    mutating func advance(to now: ContinuousClock.Instant, using generator: inout some RandomNumberGenerator) -> [Action]
    /// The earliest Ping deadline, heartbeat, or trust expiry.
    var nextDeadline: ContinuousClock.Instant? { get }
    /// The last outbound send time, or nil if none. `Magicsock` uses it to detect idleness and stop ReSTUN.
    var lastSend: ContinuousClock.Instant? { get }
    func path(at now: ContinuousClock.Instant) -> PeerPath
}

// Unit 3 — STUNMessage.swift, Netcheck.swift
enum STUNMessage {
    /// The 40-byte request from the DERP notes, §3.8.
    static func bindingRequest(_ txID: TransactionID) -> [UInt8]
    /// Identifies STUN per notes §4.1 item 1 (length ≥ 20, top 2 bits are 0, cookie, and byte 1 is 0x01).
    static func looksLikeSTUN(_ bytes: [UInt8]) -> Bool
    /// Parses a response per DERP notes §4.10 item 3. Returns nil on failure.
    static func parseBindingResponse(_ bytes: [UInt8]) -> (TransactionID, IPEndpoint)?
}

struct Netcheck: Sendable {
    enum Action: Sendable, Equatable {
        case sendSTUN([UInt8], to: IPEndpoint)
        case endpointsChanged([Magicsock.Endpoint])
        case homeRegionChanged(Int64)
        /// The round finished and refreshed local endpoints, even if the list is unchanged. Send any deferred CallMeMaybe now.
        case endpointsRefreshed
    }
    init(localPort: UInt16, localAddresses: [IPAddress], loopbackAddresses: [IPAddress])
    mutating func setRegions(_ regions: [Magicsock.Region], at now: ContinuousClock.Instant, using generator: inout some RandomNumberGenerator) -> [Action]
    /// Starts a new round if none is running (ReSTUN in notes §4.8 item 4.1).
    mutating func reSTUN(at now: ContinuousClock.Instant, using generator: inout some RandomNumberGenerator) -> [Action]
    mutating func receive(_ txID: TransactionID, mapped: IPEndpoint, at now: ContinuousClock.Instant) -> [Action]?   // Nil means it is not from this round
    /// Records a packet received from a DERP region (for deciding whether to keep the home region, DERP notes §4.10 item 5).
    mutating func noteDERPActivity(region: Int64, at now: ContinuousClock.Instant)
    /// - isActive: There are peers and a send occurred within the preceding 45 seconds. False stops periodic ReSTUN.
    mutating func advance(to now: ContinuousClock.Instant, isActive: Bool, using generator: inout some RandomNumberGenerator) -> [Action]
    var nextDeadline: ContinuousClock.Instant? { get }
    var endpoints: [Magicsock.Endpoint] { get }
    /// The last round completion time. CallMeMaybe uses a 27-second freshness window (notes §4.8 item 4.1).
    var endpointsRefreshedAt: ContinuousClock.Instant? { get }
    var homeRegion: Int64 { get }
}

// Unit 3 — Sources/SwiftailIO (package)
// Add `bindFailed(String)` and `sendFailed(String)` to `SocketError`. Messages contain only the errno name.
// Confine POSIX calls and address reinterpretation to this file and document why in comments (precedent: Tests/SwiftailWireGuardInteropTests/POSIXIO.swift).
// Reads wake on DispatchSource read events and drain until EAGAIN, without polling. A Mutex protects the file descriptor.
package final class DatagramSocket: Sendable {
    /// Binds to the IPv4 wildcard (0.0.0.0). If port is 0, the OS chooses it. Nonblocking.
    package init(port: UInt16 = 0) throws(SocketError)
    package var localPort: UInt16 { get }
    /// A stream of received datagrams with one subscriber. Slow consumption drops the oldest datagrams first (256 entries).
    package var datagrams: AsyncStream<(bytes: [UInt8], source: IPEndpoint)> { get }
    /// Sends without waiting. Reports IPv6 destinations and failures as `SocketError` (the caller drops the datagram).
    package func send(_ bytes: [UInt8], to destination: IPEndpoint) throws(SocketError)
    package func close()
}

package enum LocalInterfaceAddresses {
    /// Selects IPv4 addresses on current interfaces according to Go's `netmon.LocalAddresses` rules (behavior E1).
    package static func current() throws(SocketError) -> (regular: [IPAddress], loopback: [IPAddress])
}
```

## Behavior

The numbered items are reference labels for tests and reviews. Protocol details follow the cited sections of the notes.

### A. Classifying Incoming Traffic (`receiveUDP`, `receiveDERP`)

1. **UDP classification order** (notes §4.1). An IPv6 source or port 0 yields `unsupportedSource`. → If STUN (`looksLikeSTUN`), match it against the E2 round table. → If Go considers it Geneve (notes §4.1 item 2, the header conditions hold and either the protocol is `0x7A12` or it is `0x7A11` with disco after the first 8 bytes), yield `unsupportedDisco`. With `0x7A11` followed by something other than disco, or with another protocol, continue to the next step as Go does. → If disco (`isDisco`, 38-byte threshold), see C. → Otherwise emit `.wireGuard`.
2. **DERP classification** (notes §4.3). If disco (38-byte threshold), see C (origin is "DERP region `region`, sender `peer`"). Otherwise emit `.wireGuard` only if `peer` came from `setPeers`, or yield `unknownDERPSender`. Report all incoming packets to `Netcheck.noteDERPActivity(region:)`.
3. `.wireGuard` does not inspect the contents. The WireGuard device identifies the peer by receiver index (see “Associating source addresses with peers” in [notes §4.1](../protocol-notes/disco-magicsock.md#41-classifying-received-udp-datagrams)). There is no address-to-peer table. Include the inbound path (`.udp(source)`, `.derp(sender, region:)`). Peer identification does not use it. The node passes it to WireGuard's load defenses (cookie and per-source rate limiting) and uses it to return cookie replies along that path (2026-11-15). This public type replaced the internal type that represented a disco inbound path.

### B. Disco Keys and Shared Keys

1. **Disco key table.** Multiple peers can hold the same disco key (Go `peermap.go` `nodesOfDisco`. The Go comment lists node sharing and account switching as examples). A peer can hold one netmap key and one TSMP key, one of which is active ("TSMP Disco Key Advertisement" T4). Peers with a disco key of 0 do no disco and use only DERP. C and the T5 decision table determine whose state an incoming disco message changes. A peer can change only its own key state through advertisements or disco. (Changed after the 2026-11-16 independent review. Originally, each key was assigned only to the first peer in `setPeers` order, and later peers used only DERP.)
2. **Shared key cache** (notes §3.2 item 5). Compute once per new disco key in `setPeers` and delete removed keys. **Do not run X25519 for each incoming packet**, so unknown keys cannot consume CPU this way. If calculation yields `invalidKey`, the peer uses only DERP, without disco.
3. **When the peer's disco key changes**, call `PeerPathState.resetForNewDiscoKey()` (notes §4.4 item 3).
4. For peers removed by `setPeers`, delete state and emit `.pathChanged(key, nil)` (skip it if nil was already reported). A new peer is idle (G3) because no traffic has been sent to it yet, so it gets no event. A peer whose disco key changed has a nil path (as when Go's `invalidateDiscoPathLocked` clears the last send time). Nil in `.pathChanged` means "removed or idle."

### C. Receiving Disco (Notes §4.2)

1. A sender disco key absent from the B1 table (no peer holds it as a netmap or TSMP key) yields `unknownDiscoKey`. Opening or parsing failure yields `malformedDisco`, and `unknownType` yields `unsupportedDisco`. None of these changes state.
2. **Ping**:
   - For UDP, call `receivePing(txID, from: source)` for **all** peers holding that key. If all return true (none treats the Ping as a retransmission), send one `Pong{txID, src: source}` to that source over UDP.
   - For DERP, the DERP sender `peer` must be known (otherwise `misroutedDisco`). Add no candidate and send `Pong{txID, src: 127.3.3.40:<region>}` to that `peer` over the same region (notes §4.2 items 4.3 and 4.4).
   - If the UDP Ping's `nodeKey` identifies a peer that holds that key, switch that peer's active key to this key (Go `unambiguousNodeKeyOfPingLocked` → `checkAndUpdateDiscoKey`). Ignore the `nodeKey` of a peer that does not hold the key. There is no address-to-node table (A3).
3. **Pong.** Call `receivePong(txID, from: UDP source or nil)` for peers holding that key in order, stopping at the first that returns true (Go `forEachEndpointWithDiscoKey`). The TxID appears only in the table of the peer state that sent the Ping, so only that peer changes. Ignore if none matches. A Pong does not change the active key.
4. **CallMeMaybe.** Call the peer's `receiveCallMeMaybe` only if it arrived over DERP, the DERP sender `peer` is known, and the message's sender key is that peer's netmap or TSMP key. If the key was inactive, make it active for that peer (Go `checkAndUpdateDiscoKey`). Other peers holding the same key are unaffected. Otherwise yield `misroutedDisco` (notes §4.2 item 3).
5. Emit `.pathChanged` for every peer holding that key whose path changed (in table order).

### D. Path State Machine (`PeerPathState`, Notes §4.4~§4.8)

1. **Candidates** (notes §4.4 item 1). Use netmap `Endpoints`, UDP Ping sources, and addresses from DERP CallMeMaybe. Accept **IPv4 only** (one IPv4 socket, see "UDP socket" in the decision table). Unwrap IPv4-mapped addresses. Accept IPv4 link-local addresses (169.254/16). Go filters only IPv6 link-local addresses. Local STUN results and Pong Src are excluded from candidates.
2. **Removal** (notes §4.4 item 2) and **disco key change** (notes §4.4 item 3) follow the notes.
3. **Path selection** (notes §4.5 items 1–4). A `bestAddr` within its trust period uses UDP only. Otherwise use UDP to `bestAddr` (if present) + the peer's home DERP. With home DERP 0 and no `bestAddr`, drop with `noRouteToPeer`. (`shortcut:` Reverse DERP regions are unused, see notes §4.5 item 4 and DERP notes §4.9 item 3. Peers with home DERP 0 are rare in Go too. This becomes necessary if such a peer appears at the real tailnet gate.)
4. **On every send** (notes §4.5 items 3 and 5, §4.8 item 2). Without a trusted direct path, send a full Ping round (including CallMeMaybe). Record the outbound send time and schedule a heartbeat for 3 seconds later if none is scheduled.
5. **Ping, Pong, and deadlines** (notes §4.6), **`betterAddr`** (notes §4.7), and **full Ping round, heartbeat, and receiving CallMeMaybe** (notes §4.8 items 1, 3, and 5) follow the notes. Reply to a received Ping only with a Pong (notes §4.8 item 6).
6. **Timer values match Go** (notes §5). Ping deadline 5 seconds, per-candidate Ping interval 5 seconds, heartbeat 3 seconds, trust 6.5 seconds, idle 45 seconds, good latency 5 ms, upgrade Ping 1 minute, and Ping-learned candidate 45 seconds. These values are fixed. Tests verify them by passing time explicitly.
7. **Trust expiry is also a deadline.** Include `trustBestAddrUntil` in `nextDeadline` so `Magicsock` can emit `.pathChanged(.relayed)` on `advance` at expiry.
8. `path(at:)` returns `.direct(bestAddr)` if `bestAddr` exists and `now ≤ trustBestAddrUntil`, otherwise `.relayed(derpRegion: homeDERP)` (`curAddr` in notes §7.1).

### E. Local Endpoints, STUN, and Home Region (`Netcheck`)

1. **Interface addresses** (`LocalInterfaceAddresses`, Go `net/netmon/state.go:38-143`). From IPv4 addresses on interfaces that are up, whose names do not start with `zt`, and that are not `wt0`, exclude Tailscale addresses (`100.64.0.0/10`, except `100.115.92.0/23`). Put loopback interfaces' addresses and loopback addresses in `loopback`. Collect link-local addresses (169.254/16) separately and use them as `regular` only when there are no ordinary addresses. Sort each list in ascending address order. Confine the `getifaddrs` call to this file and document why in a comment.
   - The node reads addresses **once at startup** and passes them to `Magicsock.init`. `shortcut:` Address change detection comes in M5 (along with link changes, notes §4.11).
2. **STUN round** (DERP notes §4.10 item 1, Go `net/netcheck/netcheck.go:559-587`). For each region with `stunServers`, send one request to `stunServers[try % count]` at 0, 100, and 200 ms (3 per region). Keep each sent TxID in the current round table. The first reply in a region supplies its latency (from send time) and external address. End the round when all regions have replied or 3 seconds have passed from the start. Responses from outside the round yield `unexpectedSTUN`.
3. **STUN address** (Go `netcheck.go:1665-1700`). The node extracts it from DERPMap. Use `stunTestIP` if present, otherwise use `ipv4` if it is an IPv4 literal. A `stunPort` of 0 means 3478, and a negative value excludes the node. `shortcut:` Skip DNS lookup for nodes with empty `ipv4` (value types cannot resolve DNS, and the production DERPMap provides IPv4 literals). When a DERPMap without literals is encountered, the node will resolve the hostnames and pass in the resulting addresses.
4. **Endpoint list** (notes §4.9 item 1 subitems 2 and 7). At the end of a round, use [STUN global addresses (.stun)] + [each address in localAddresses:localPort (.local)]. If both are empty, use loopback addresses:localPort (.local). Keep only the first occurrence of duplicates. STUN global addresses are the round's first response address and addresses observed at least twice (notes §4.9 item 1.2). Update `endpointsRefreshedAt` and emit `.endpointsRefreshed` after every round. Emit `.endpointsChanged` only when the list changes **as a set** (Go `magicsock.go:1448-1473` treats the same set as equal even in a different order). Emit no list if there are no regions and no STUN results (notes §4.9 item 5).
5. **Periodicity** (notes §4.9 item 5, Go `magicsock.go:887-923`, `:3683-3712`). When a round ends and `isActive` is true, schedule the next round after a random 20–26 seconds. `isActive` means "at least one peer exists, and 45 seconds have not elapsed since at least one peer's last send (`lastSend`)." Otherwise stop periodic rounds and let the next `send` restart them. Changes in `setRegions` and attempts to send CallMeMaybe with stale endpoints (F2) start a round immediately.
   - Go determines idleness by TUN send and receive times (`net/tstun/wrap.go:842-853`, `wgengine/userspace.go:435`). This contract uses WireGuard send time instead. The difference is that after traffic stops, STUN keeps running through the WireGuard keepalives (at most two, about 20 seconds, behavior ported from wireguard-go's `needAnotherKeepalive`), and idle detection (nil in G3) is delayed. In measurements against a Go peer on 2026-11-15, the path became nil about 55~64 seconds after the last traffic.
6. **Home region selection** (DERP notes §4.10 item 5, Go `netcheck.go:1426-1531`). At round completion, consider regions that replied in this round. Take each region's minimum latency over rounds in the last 5 minutes 5 seconds, multiply it by `score` if positive, and choose the region with the lowest result. The previous measured home is reachable if it has a latency this round or a DERP packet from it arrived after the round started or less than 8 seconds before the round ended. If it is reachable, keep it when its weighted current-round latency (0 without a measurement this round) minus the candidate's weighted historical minimum is less than 10 ms or the candidate's value is greater than 2/3 of the previous home's value. With no measurements, retain the previous measured home as the baseline only if a DERP packet arrived from it less than 120 seconds before the round ended. Keep the current home even if the baseline resets to 0 (DERP notes §4.8 item 1).
   - **Fallback home.** If `setRegions` arrives while home is 0, immediately emit the region with the smallest ID as home (M3 rule). This connects to DERP without waiting for the first round (3 seconds). Choose again under rule 6 when the round ends. The fallback home does not qualify as the "existing home" in rule 6. The baseline for retention is **the home selected from measurements in the previous round** (Go uses `PreferredDERP` from the previous report, `netcheck.go:1431`. Magicsock's fallback home is not fed back into it). The first round with measurements picks the fastest region without a retention condition. After a round without measurements, the baseline survives only if a DERP packet arrived within 120 seconds (M4 review A, 2026-11-15).
   - Emit `.homeRegionChanged` when home changes. `shortcut:` Go does not change home while the map stream to the control server is disconnected (DERP notes §4.8 item 2). This contract changes it, and because the node does not close the old home connection (engine contract M4 behavior N3), packets still sent to the old home also arrive. Publish the new home after reconnecting to the control server.
   - `shortcut:` Skip HTTPS latency measurement when UDP is blocked and no STUN replies arrive (DERP notes §4.10 item 4). Keep the existing home according to the above rules.
   - Count only packets received through `receiveDERP` as DERP activity. `DERPClient` does not forward KeepAlive. In the rare case where the existing home sends only KeepAlive and does not answer STUN, home may move sooner.

### F. Sending CallMeMaybe (Notes §4.8 Item 4)

1. On `.callMeMaybe` from `PeerPathState`, if `endpointsRefreshedAt` is within the preceding 27 seconds, include **all** current endpoint addresses without `EndpointType`, seal using the peer's disco key, and emit `.derp(_, to: peer, region: peer's home DERP)`. Skip sending if home DERP is 0.
2. If stale, add the peer to the list of peers to send to after endpoint refresh and call `reSTUN`. On `.endpointsRefreshed`, perform step 1 for the listed peers (one slot per peer).
3. Order between UDP Ping and CallMeMaybe is unspecified (notes §4.8 item 4.3, as in Go).

### G. Path Events

1. At the end of every state-changing call, `Magicsock` emits `.pathChanged` if an affected peer's `path(at:)` differs from the last reported value. `advance` also checks peers whose trust expired (D7).
2. Do not reemit the same value. `.direct(a)` → `.direct(b)` is a change.
3. An idle peer has a nil path (added after first adopter review on 2026-11-15). If more than 45 seconds (idle detection, timer values in D) have passed since the last WireGuard datagram sent to that peer, `path(to:at:)` is nil, and `advance` at that point emits `.pathChanged(key, nil)`. Sending again emits `.pathChanged` with the path at that time.
4. The reason for the downgrade (added 2026-11-16 for diagnostics) is retained when a path goes from `direct` to `relayed` or from a reported path to nil. The node queries it with package-scoped `downgrade(of:)` (outside the public API). `PathDowngrade` has six reasons, trust expiry (`bestAddr` remained or a Ping deadline cleared it), candidate removal (removed the candidate that was `bestAddr`), rebinding, disco key change (nil because the send record was cleared), idleness, and peer removal. This does not affect behavior.

### H. Limits (Untrusted Input)

| Item | Limit | When exceeded |
| --- | --- | --- |
| Received UDP datagram | 65,535 bytes (socket read buffer) | WireGuard or disco drops socket-truncated datagrams as malformed |
| Candidates per peer | 128 (cap above Go's pruning threshold of 100) | First prune per notes §4.4 item 2. If still full, evict the Ping-only candidate whose last received Ping is oldest and insert the new one. Never evict candidates learned from netmap or CallMeMaybe, or `bestAddr`. If none can be evicted, skip the new candidate. Insert CallMeMaybe entries in list order |
| Sent Ping table per peer | 128 | Skip new Pings (the 5-second deadline drains it) |
| STUN round table | Region count × 3 | Clear at the end of the round |
| Peers with deferred CallMeMaybe | Peer count (one slot per peer) | N/A |
| Received CallMeMaybe addresses | Bounded by datagram length | Enforce the per-peer candidate limit |

- Fail closed. Discard disco messages that fail parsing, opening, or path checks without changing state or sending a response (Pong). Do not pass packets that failed to open to WireGuard (notes §3.2 item 6).
- No byte sequence passed to `receiveUDP` or `receiveDERP` may cause a crash. Avoid out-of-range indexing and integer overflow (latency score calculation uses nanoseconds in `Int64`, notes §4.7 item 4).
- Disco messages have no replay protection (Go also only checks for duplicate TxIDs, notes §4.2 item 4.2). Replaying a captured Ping from another address makes that address a candidate. A Ping goes to that address, and it becomes `bestAddr` only if a Pong arrives, so the path cannot be taken over this way.
- Such Pings cannot tie up the candidate table (2026-11-17, two differences from Go).
  - **A Ping with a recently seen TxID (a replay) neither refreshes the candidate's last Ping time nor creates a new candidate.** For each peer, retain the 32 most recent Ping TxIDs received over UDP in receipt order (forget the oldest when full). A TxID in that list is a replay regardless of its source (2026-11-17 security verification, round 2. Previously the check used only the last TxID for that candidate, so alternating two captured Pings made both look new). Clear the list when the peer's disco key changes. Go's `addCandidateEndpoint` checks only one previous TxID per candidate and updates `lastGotPing` even on a replay, so repeating a single captured Ping keeps a candidate past its 45-second lifetime. The Pong rule matches Go. Skip the Pong only when the same candidate sends the same TxID as before (even a replay that was not added as a candidate gets a Pong).
  - **When the table is full, evict the oldest candidate learned only from Ping** (see the table above). Go has no cap and therefore no eviction. Previously, a full table rejected new candidates, so replaying one Ping from 128 addresses prevented the peer's new addresses (netmap endpoints or genuine Ping sources) from becoming candidates.
  - Normal traffic is unaffected. Go uses a new TxID for every Ping (`startDiscoPingLocked`), so only a duplicate of the same datagram delivered by the network looks like a replay. Normal peers do not reach 128 candidates (Go's pruning threshold is 100).
  - Remaining limitation. With only 32 retained TxIDs, more captured Pings (cycling through 33 or more) can still extend a candidate's life or add new addresses. Genuine peer Pings also displace entries in the ring, so fewer captured Pings suffice while the peer sends Pings actively. A candidate added that way can evict a Ping-source candidate that has not yet become `bestAddr`. That candidate returns on the next Ping (3-second heartbeat). Candidates learned from netmap or CallMeMaybe and paths established to those addresses (`bestAddr`) are unaffected. An exception occurs when someone on the path captures a new Ping and gets it delivered from a different address first. The genuine source is then treated as a replay, so an address learned only through Ping (including one that is `bestAddr`) is not refreshed and is removed after 45 seconds, falling back to relay. Someone in that position could achieve the same result by dropping packets, so this adds no capability (reconfirmed 2026-11-17).

### I. Secrets

1. Hide the private disco key and shared keys with the `customMirror` of `Magicsock` and `DiscoSharedKey`. The `Magicsock` mirror shows only `discoPublicKey`, peer count, and home region.
2. Outputs (`Output`, `Drop`) contain no key material. Only sealed bytes go out.
3. Do not persist the disco key (generate a new one each startup, notes §4.10 item 4).

## Decisions (Notes §6.3, “Decisions for the lead session to make in the contract”)

| Decision | Choice | Rationale |
| --- | --- | --- |
| UDP socket | One IPv4 wildcard socket, OS-selected port | IPv4 suffices for the gate. Dual stack would require unmapping received addresses, and the table would differ from Go's |
| Timer values | Match Go. Take time as an argument so tests can supply it | These values determine when Go peers fall back and recover, which the gate checks |
| Home region | Measure with STUN and choose per DERP notes §4.10 item 5 (E6). Omit HTTPS measurements | STUN is needed for endpoints anyway. There is one test region, so gate results are the same, and unit tests cover the rules |
| Published endpoints | local + STUN | This suffices because Go's loopback endpoint comes from STUN at the gate (notes §7.1) |
| CapabilityVersion | Keep 148 | Lowering it can change other server behavior (notes §4.12, plan risk 13) |
| Relay and Geneve messages | Drop | Closing the connection would break the path when a Go peer sends these messages normally (notes §4.12) |
| TSMP advertisement | Send for every session key and use received keys under the same rules as Go ("TSMP Disco Key Advertisement," 2026-11-16) | Go does this from CapabilityVersion 144, and Swiftail declares 148 (notes §4.10 item 3) |
| Test mechanisms for blocking direct paths | Both a filter at the Swift socket boundary and a Go knob in the tool | "M4 Gate" items 3 and 4 below |
| Path query API | Same meaning as Go `curAddr` (`PeerPath`) | The gate can use the same criterion as Go `peerStatus` |

### Lead Session Confirmations (2026-11-15)

All three decisions followed the recommendations (Q1 (a), Q2 (a), Q3 (b)). The table records the options and rationale.

| # | Decision | Options | Recommendation |
| --- | --- | --- | --- |
| Q1 | Where to connect the engine and `Magicsock` | (a) The node holds the two value types as stored properties and passes their outputs to each other / (b) `TailnetEngine` contains `Magicsock` and emits UDP or DERP output (plan §5 dependency diagram) | (a). Engine output remains "a datagram for a peer," consistent with the design principle in the `SwiftailWireGuard` contract, and the engine does not need to know about UDP, STUN, or DERP regions. The trade-off is that the connecting code (four output branches) lives in the actor, so node tests and the gate cover it instead of unit tests |
| Q2 | Shape of path events (RemoteDebug, "path state for a single paired peer (a Mac)") | (a) Emit `NodeEvent.peerPathChanged(fqdn:path:)` for all peers + `path(toPeerNamed:)` query / (b) Per-peer `AsyncStream<PeerPath?>` / (c) Query only | (a). With one event stream, the app needs no separate subscription, and path changes are no more frequent than the trust period (6.5 seconds). They do not fill the event buffer (64 entries) enough to displace other events |
| Q3 | Sending WireGuard cookie replies and assessing load (deferred by the M1 contract to "M4, when a UDP port opens on an untrusted network") | (a) Add to this M4 unit / (b) Add separately as a `SwiftailWireGuard` contract change before the M4 closing gate (real network) / (c) M5 | (b). The gate (loopback and LAN) does not need it, and it is outside the `SwiftailMagicsock` scope. It must be present before the closing gate opens a UDP port to the internet (the public node key is no secret, so an initiation flood can force X25519) |

## Exclusions (Record in `shortcut:` Comments)

| Exclusion | Rationale | When needed |
| --- | --- | --- |
| Sending and processing peer relay (0x04–0x09, Geneve) | Notes §4.12. Drop on receipt | When measurements show a problem with the NAT traversal rate (plan risk 4) |
| Path MTU measurement (sending padded Pings) | Notes §4.12. Disabled by default in Go and unavailable on iOS. Reply to received padded Pings with ordinary Pongs | N/A |
| Port mapping (UPnP, NAT-PMP, PCP) | Excluded by plan §3. Notes §6.2 | After the measurement for plan risk 4 |
| IPv6 sockets, IPv6 endpoints, and IPv6 candidates | IPv4 suffices for the gate (notes §6.2) | When M5 real-device work encounters an IPv6-only network (some cellular networks). Bind both sockets to the same port when added |
| Rebind, link change detection, ReSTUN after an address change, and handling send errors (`EHOSTUNREACH`, `EPERM`, broken pipe) | Notes §4.11 and §4.5 item 6. Sockets and addresses are stable in the gate scenario. Ignore send errors (DERP is used in parallel) | M5 (`setDefaultInterface`, Wi-Fi ↔ cellular) |
| `EndpointSTUN4LocalPort`, cloud metadata, 5-minute 10-second advertisement cache, and static endpoints | Notes §6.2 | When the closing gate fails behind hard NAT |
| Address-to-peer table | Notes §4.1. WireGuard identifies the peer | N/A |
| Reverse DERP region (peer with home 0) | Behavior D3. Notes §6.2 | When such a peer appears in a real tailnet |
| 64-entry Pong history and UDP lifetime measurement | Comparison uses only the latest latency (notes §6.2) | N/A |
| HTTPS latency measurement, retaining home while the map stream is disconnected, and STUN nodes requiring DNS | E3, E6 | See E3 and E6 |
| Cleaning up non-home DERP connections (unused for 60 seconds) | The number of DERPMap regions bounds the number of open connections | If M5 memory measurements show a problem (engine contract M4 behavior N3) |
| CLI Ping (disco Ping over DERP) | The gate uses only Go's `peerPing` | N/A |

## Tests

### Unit Tests (`Tests/SwiftailMagicsockTests`, No Sockets or Clock, Deterministic with Supplied Time)

1. **`DiscoMessage`.** Plaintext bytes match Go reference values (Ping with and without NodeKey, IPv4 and IPv6 Pong, and CallMeMaybe with 0, 1, and 3 addresses). Boundaries from notes §7.2 item 1 include 17- and 19-byte CallMeMaybe and version 1 → empty list, 29-byte Pong → `malformed`, 12-, 44-, and 45-byte Ping (padding), 32-byte all-zero NodeKey → nil, 0- and 1-byte plaintext, type 0x04–0x0A → `unknownType`, and unwrapping IPv4-mapped addresses.
2. **`DiscoPacket`.** Bytes sealed with a fixed key and nonce match Go reference values. Open bytes sealed by Go. Tampering with one byte of nonce, tag, ciphertext, or sender key → `authenticationFailed`. Classification at 37, 38, and 61 bytes. Low-order public key → `invalidKey`. `dump` exposes no shared key.
3. **`PeerPathState`.** The `betterAddr` table in notes §4.7 (comparison of the same address (Swiftail omits the MTU check), comparison against an absent address, loopback +50 versus LAN +20, latency ratio score, and the 1-point rule) and the calculation in notes §4.7 (loopback beats LAN). Three path selection branches and `noRouteToPeer`. The 6.5-second trust boundary (`==`). The 5-second per-candidate Ping interval and how CallMeMaybe resets it. The 5-second Pong deadline keeps `bestAddr` while trusted and clears it only after expiry. A 3-second heartbeat stops after 45 seconds of idleness and restarts on the next send. Full Ping conditions (skip at 5 ms or less, probe for a better path after 1 minute). Candidate removal (absent from netmap, 45 seconds for Ping-learned candidates, and CallMeMaybe replacement) and clearing `bestAddr` with it. A Ping from the same candidate with the same TxID gets no Pong and does not extend lifetime. In a full table, evict the oldest Ping-only candidate (keep netmap and CallMeMaybe candidates and `bestAddr`). Disco key change. IPv6 and IPv6 link-local candidates are excluded. Limits of 128 candidates and 128 sent Pings.
4. **`STUNMessage`.** A request with fixed TxID matches Go `stun.Request`. Parse IPv4 and IPv6 replies made with Go `stun.Response`, `0x8020`, and a response with only MAPPED-ADDRESS. Reject 19 bytes, bad cookie, a type other than `01 01`, a declared length exceeding input, an attribute length exceeding remaining bytes, family 3, or no address attribute. Random input does not cause a crash.
5. **`Netcheck`.** Round request times (0, 100, and 200 ms) and targets (`try % count`), matching replies and replies outside the round, the 3-second deadline and early completion when every region replies, endpoint order, duplicate and loopback fallback rules, STUN global address rules, set comparison (order-only changes yield no `.endpointsChanged`), 20–26-second periodicity and stopping when idle or when there are no peers, and home selection (every condition in DERP notes §4.10 item 5, including 5 minutes 5 seconds of history, `score`, 10 ms, 2/3, DERP packets received in the preceding 8 seconds, the 120-second DERP activity window when there are no measurements, and immediate fallback home selection).
6. **`Magicsock`.** Connect two instances through an in-memory "network" (each has an address, `.udp` goes to the other's `receiveUDP`, and `.derp` goes to the other's `receiveDERP`. The network can drop or delay datagrams). Check the following.
   - A direct path forms both when the peers know each other's endpoints from netmap and when they do not (learn from Ping sources, notes §4.8 calculation). Emits `.pathChanged(.direct)`.
   - Blocking UDP produces `.relayed` at last Pong + 6.5 seconds. After trust expires and before the heartbeat Ping deadline (5 seconds), data goes over UDP + DERP. Once that deadline clears `bestAddr`, UDP sends stop. Unblocking produces `.direct` through a full Ping round within the next heartbeat (3 seconds). Verify the calculated times in gate item 3 using the supplied times.
   - Answer a DERP Ping with a Pong through the same DERP region (Src `127.3.3.40:<region>`). Drop CallMeMaybe over UDP, CallMeMaybe with mismatched keys, and Pings from unknown DERP senders without replying.
   - Drop packets with unknown disco keys without calculating a new shared key (verify that the shared key cache size does not exceed the peer count).
   - Peer relay types (0x04–0x09) and datagrams with a Geneve header leave state unchanged (notes §7.2 item 7).
   - STUN responses from outside the round never go to WireGuard. Ordinary datagrams pass through unchanged as `.wireGuard`.
   - CallMeMaybe. If endpoints are older than 27 seconds, defer it and start a round, then send it when the round completes (Swift side of notes §7.2 item 4). On receipt, immediately Ping every candidate.
   - A peer removed by `setPeers` yields `.pathChanged(_, nil)`. A disco key change clears trust.
   - Arbitrary byte sequences (length 0~200, including ones beginning with disco magic) do not cause a crash. `dump` exposes no private disco key or shared keys.
7. **`SwiftailIO`.** Two `DatagramSocket` instances exchange data over loopback (port, source address, 65,535 bytes, and stream ending after `close`). Test the selection rules in `LocalInterfaceAddresses` using simulated `getifaddrs` results (the internal function via `@testable`).

### Comparison with Go Reference Values

- **`Tools/interop/cmd/magicsockvectors`** (new Go tool, used by Unit 1). With two disco keys made from public test seeds (`SHA-256("swiftail-vectors/disco/<number>")` as X25519 private input), fixed nonces, and fixed TxIDs, write the following as JSON (`Tests/SwiftailMagicsockTests/Fixtures/magicsock-vectors.json`).
  - `AppendMarshal` plaintext for `disco.Ping/Pong/CallMeMaybe` (cases in unit test 1 above).
  - The full outer format for the same plaintext sealed with `golang.org/x/crypto/nacl/box.Precompute` + `secretbox.Seal` (fixed nonce). Before writing, the tool opens those bytes with `key.DiscoPrivate.Shared(...).Open` to check against Go's actual opening path. Go's `Seal` generates the nonce internally, so fixed-nonce sealing calls the same calculation directly (notes §3.2 item 3).
  - Results of passing boundary cases (notes §7.2 item 1) to `disco.Parse` (message or error).
  - `stun.Request(txID)`, `stun.Response(txID, addrPort)` (IPv4 and IPv6), and the result of parsing that response with `stun.ParseResponse`.
- A session independent of the implementation session writes the comparison tests (as in the M3 filter comparison). The data contains no current time or production keys.
- The Go functions for `betterAddr` and timer behavior are unexported, so turn the tables in notes §4.7 and §5 into tests (origin and BSD-3-Clause at the top of the file).

## M4 Gate

Test against `tailnet` in `Tools/interop` (testcontrol + 1 DERP region + STUN on `127.0.0.1` + a Go tsnet peer, which echoes on TCP and UDP port 7). The Swift node opens a real UDP socket. Put the tests in `Tests/SwiftailInteropTests/DirectPathTests.swift` and skip if `SWIFTAIL_TAILNET` is absent.

### Tool Additions (`Tools/interop/cmd/tailnet`, Including README Update)

1. `{"cmd":"setNeverDirectUDP","enabled":true|false}` → `envknob.Setenv("TS_DEBUG_NEVER_DIRECT_UDP", "true"/"false")`. Applies to all Go peers in the tool process (notes §7.2 item 3).
2. Extend the `peerStatus` response with the Go node's own endpoints `selfAddrs` (`Status.Self.Addrs`) and `active` and `lastWrite` per peer (end of notes §7.2, Go `endpoint.go:2232-2253`).
3. Extend `nodes` with `endpoints` for each node registered with testcontrol (the value stored by testcontrol from a map request, notes §4.9 item 4). Verify the Swift node's published endpoints from the Go side.

### Test UDP Filter on the Swift Side

Put it at the UDP edge in `TailnetNode` (engine contract M4 behavior N8). `package func setBlockedUDPPorts(_ ports: Set<UInt16>)` drops UDP to those remote ports and UDP from those ports at the socket boundary. `Magicsock` has no knowledge of it (it lives at the socket boundary, outside the subject under test, notes §6.3). It is outside the public API.

### Checks

Defect found at the gate (2026-11-15). On Darwin, UDP `sendto` can also fail with `EPIPE`, delivering SIGPIPE. In item 5, when sending to the Go peer's LAN endpoint, the test process died with signal 13 in 2 of 3 runs. The two cases observed by Unit 4b had the same cause. The Go runtime ignores this signal and handles only `EPIPE` (`net/neterror/neterror_unix.go`). Setting `SO_NOSIGPIPE` on `DatagramSocket` fixed it, and item 5 then passed 6 consecutive runs. Item 5 protects against this regression (unit tests cannot deliberately produce UDP `EPIPE`).

Observations between a Go peer and a Swift node (2026-11-15, Unit 4b, 5 runs). Endpoints were published within 0.1 seconds of `running`. Both sides went direct about 0.9~1.0 seconds after the first echo. After blocking on the Swift side, it went `.relayed` in 6.38~6.51 seconds (3.44 seconds once. Blocking just before a heartbeat Pong makes it earlier because trust is measured from the last Pong). Unblocking restored direct in 0.11~0.20 seconds (2.0 seconds once). Turning on the Go knob restored relay in 5.0~6.2 seconds, and turning it off restored direct in 0.07~0.9 seconds. Echo loss was 0 over the 130-second run. The gate's "within 6.5 seconds (+3 seconds)" is an upper bound, not a lower bound.

Baseline observations (2026-11-14, between two Go peers, tool `setNeverDirectUDP`). After enabling it, both `curAddr` values cleared at 6.45 and 6.60 seconds (consistent with the 6.5-second trust period). After disabling it and sending UDP, the direct path returned in about 0.04 seconds. UDP data keeps flowing while the knob is enabled (it blocks only discovery Pings). A `peerPing` (disco) immediately after enabling the knob fails with a timeout after 30 seconds. The timing expectations below add margin to these observations and the calculations in the notes.

Start with one Go peer (`addPeer`) and one Swift node. Expected times come from the calculations in notes §7.2 item 3. Tests wait for the condition until the expected time plus margin (in parentheses below).

1. **Endpoints.** Within 10 seconds after the Swift node is `running`, the Swift entry's `endpoints` in `nodes` contains `127.0.0.1:<Swift port>` (STUN result). Get the Go port from `selfAddrs` in Go `peerStatus`.
2. **Direct path establishment (Swift first).** Swift sends a UDP echo to port 7 at the Go peer's IPv4 address every 1 second. Within 15 seconds, (a) `curAddr` for Swift in Go `peerStatus` is one of Swift's published endpoints (the calculation predicts `127.0.0.1:<Swift port>`, but Go was observed choosing a LAN address in 2 out of about 10 transitions. Accept either), (b) Swift `path(toPeerNamed:)` is `.direct(127.0.0.1:<Go port>)`, and (c) a `peerPathChanged` event reported `.direct`. Echoes keep coming back.
3. **Blocking and recovery on the Swift side.** Call `setBlockedUDPPorts([Go port])` and keep sending echoes.
   - Within 6.5 seconds (+3 seconds), Swift reports `.relayed(derpRegion: 1)` and Go's `curAddr` is empty.
   - During the trust period immediately after blocking, echoes are lost because both sides use UDP only. After trust expires (block + 9.5 seconds), no echoes are lost (both UDP and DERP are used, then only DERP).
   - Unblock. Within 10 seconds, both return to direct and echoes continue.
4. **Go knob.** Set `setNeverDirectUDP true`. Within 6.5 seconds (+3 seconds), the Swift path is `.relayed` and Go's `curAddr` is empty. Echoes continue. Set it back to `false` and both go direct within 10 seconds. (Go also sends UDP because it has no Pings whose deadlines it needs to process. Notes §7.2 item 3.)
5. **Go first.** Once the Swift node is `running`, add a new Go peer. With Swift having sent it nothing, have the Go peer contact the Swift address with `peerPing` (disco) or `peerSend` every 1 second. Do not use ICMP `peerPing`. The Swift node's in-memory device has no ICMP responder, so it always times out. Within 15 seconds, 2(a) and 2(b) hold (Go Pings Swift's netmap endpoints, and Swift replies with Pong and learns the Go source as a candidate). Unit test 6 covers Go sending before Swift publishes endpoints (notes §4.8 calculation).
6. **Idleness and resumption.** Stop echoing and wait 50 seconds. The Swift entry's `active` in Go `peerStatus` is false (Go also uses a 45-second idle period). Within 75 seconds after stopping, Swift `path(toPeerNamed:)` is nil and `peerPathChanged` emitted nil (45 seconds + up to two keepalives). Sending again restores the direct path within 15 seconds.
7. **Sustaining the path for more than 2 minutes.** Send echoes every 1 second for 130 seconds over the direct path. The Swift path and Go `curAddr` checked every 10 seconds both indicate direct, and all echoes come back (through WireGuard's 120-second rekey, heartbeats, and periodic STUN).
8. **TSMP advertisement.** Once the session is established, the TSMP disco advertisement sent by Go does not appear in `inboundPackets` (as in M3).
9. **M3 gate regression.** Pass M3 gate items 2~7 (UDP and TCP echo, ACL, and peer removal) again with a direct path established.

For the closing gate (real tailnet), after completing this gate and Q3, the lead session notifies the owner first and obtains an auth key through secret input. Check whether Swift `path(toPeerNamed:)` reaches `.direct` to a device behind NAT (a real device selected by the owner), whether STUN measurements determine the home region, and whether direct and DERP paths survive a Go peer's `CallMeMaybeVia` in a tailnet with a relay server (plan risk 13).

## Implementation Units

Divide the work so owned files do not overlap. The lead session handles Unit 0 first (as with M3 Unit 0).

| Unit | Scope | Owned files | Dependencies |
| --- | --- | --- | --- |
| 0 | Set up placeholders. Move `IPEndpoint` (and its tests) to `SwiftailBase`, add the `SwiftailBase` dependency to `SwiftailIO`, add `SwiftailMagicsock` and `SwiftailMagicsockTests` targets and new dependencies for `Swiftail`, `SwiftailTests`, and `SwiftailInteropTests`, and add `TransactionID.swift` and `PeerPath.swift`. Preserve behavior (existing tests pass) | `Package.swift`, `Sources/SwiftailBase/IPEndpoint.swift`, `Sources/SwiftailControl/Tailcfg/IPEndpoint.swift` (keep only Codable), `Sources/SwiftailMagicsock/{TransactionID,PeerPath}.swift` | None |
| 1 | Disco codec and cryptography, and Go vector tool | `Sources/SwiftailMagicsock/{DiscoMessage,DiscoPacket}.swift`, `Tests/SwiftailMagicsockTests/{DiscoMessageTests,DiscoPacketTests}.swift`, `Tools/interop/cmd/magicsockvectors/`, `Tests/SwiftailMagicsockTests/Fixtures/magicsock-vectors.json` | 0 |
| 2 | Path state machine | `Sources/SwiftailMagicsock/PeerPathState*.swift`, `Tests/SwiftailMagicsockTests/PeerPathStateTests.swift` | 0 |
| 3 | STUN and Netcheck, UDP socket, and interface addresses | `Sources/SwiftailMagicsock/{STUNMessage,Netcheck}*.swift`, `Sources/SwiftailIO/{DatagramSocket,LocalInterfaceAddresses}.swift`, `Tests/SwiftailMagicsockTests/{STUNMessageTests,NetcheckTests}.swift`, `Tests/SwiftailIOTests/{DatagramSocketTests,LocalInterfaceAddressesTests}.swift` | 0. Compare against STUN reference values after Unit 1 provides the data |
| 4 | `Magicsock` integration + engine and node integration (engine contract "Changes in M4") | `Sources/SwiftailMagicsock/Magicsock*.swift`, `Tests/SwiftailMagicsockTests/MagicsockTests.swift`, `Sources/SwiftailEngine/*`, `Tests/SwiftailEngineTests/*`, `Sources/Swiftail/*`, `Tests/SwiftailTests/*` | 1, 2, 3 |
| 5 | Gate tool commands and Swift gate tests | `Tools/interop/cmd/tailnet/*`, tailnet section of `Tools/interop/README.md`, `Tests/SwiftailInteropTests/DirectPathTests.swift` | Tool work starts alongside 0. Swift tests follow 4 |

Order is 0 → (1, 2, 3, and 5's tool work) in parallel → 4 → 5's Swift tests → review by another session → lead session reruns the gate. Unit 4 is the largest (state machine integration and actor integration). If split in two, use 4a (`Magicsock`) and 4b (engine and node, starting from 4a's public signatures alone), and build 4b after merging 4a. A session other than the implementer's writes comparison tests (the tests that read the vector data).

## Direct Path Delay Investigation (2026-11-16)

### Observations

The first adopter's real devices (2026-11-15). A Mac host (`.inProcess`, running for a long time) and an iPhone tunnel (`.utun`, just enabled) are on the same Wi-Fi. The iPhone dials TCP to port 443 on the Mac's tailnet address.

- From first contact, `relayed(7)` → `direct` took 44 seconds and 25 seconds. Both first contacts were within 10~30 seconds of enabling the tunnel. Communication used DERP in the meantime. The Go tunnel + Go host reportedly took a few seconds (no timings were recorded).
- After about 26 seconds of idleness, `Peer path: none`. On the next request, `direct → relayed(7) → direct` within 1 second.

### Measurements

Contract gate environment (`tailnet` tool, loopback on one machine, testcontrol). Measure from first data (UDP every 1 second, `peerSend` on the Go side) until both sides are direct. The 50 ms polling interval introduces that much measurement error. Values are from two measurements.

| Case | Swift (or A) | Go (or B) |
| --- | --- | --- |
| (a) Swift ↔ Go after both idle for 70 seconds | 72 ms, 72 ms | 14 ms, 18 ms |
| (b) Newly started Swift ↔ running Go | 81 ms, 69 ms | 22 ms, 15 ms |
| (c) Newly started Swift ↔ Swift (two `.memory` nodes sending to each other) | 58 ms, 55 ms | 58 ms, 55 ms |
| (d) Control case, Go ↔ Go | 99 ms, 90 ms | 26 ms, 26 ms |

The delays of tens of seconds on real devices did not reproduce. A unit test (`MagicsockStartupTests`) that ran the state machines in the real-device sequence also brought both sides direct within 12 ms of the first data, with a host idle for 120 seconds and a tunnel enabled 30 seconds earlier. The tunnel's CallMeMaybe is deferred because its endpoints are older than 27 seconds, then sent at 15 ms when the round that started immediately finishes. The host sends its CallMeMaybe at 25 ms.

### Comparison with Go (v1.104.7)

| Event | Go | Swiftail | Difference |
| --- | --- | --- | --- |
| First data | Without a trusted direct path, Ping every candidate and send CallMeMaybe if at least one Ping was sent (`endpoint.go:1107-1130`, `:1423-1462`) | `planSend` → `pingAllCandidates(sendCallMeMaybe: true)` | None |
| Endpoints are stale | Schedule the send for the end of the round and call `ReSTUN`. If a refresh is running, run another after it finishes (`magicsock.go:2693-2723`, `:3720-3750`, `:887-900`, `:979`) | Add to the deferred list and start a round if none is active. If one is active, send when that round ends (`callMeMaybe(to:)`, `.endpointsRefreshed`) | Swiftail uses the active round's result, so it sends at the same time or earlier. No path waits for a periodic round (unit test) |
| Receive CallMeMaybe | Replace candidates, remove the Ping interval restriction, immediately Ping all candidates, and send no CallMeMaybe in return (`endpoint.go:2150-2215`) | `receiveCallMeMaybe` | None |
| Receive Pong | Promote the candidate to `bestAddr` if it is better or trust has expired. If the Pong is for `bestAddr`, refresh its trust for 6.5 seconds (`endpoint.go:1929-2017`) | `receivePong` | None |
| Netmap endpoints change | Remove candidates that never sent a Ping when they disappear from netmap (`endpoint.go:1762-1800`, `:510-521`) | `replaceNetmapCandidates` | None |
| Ping from an unknown source | If the disco key is known, add the source as a candidate and reply with Pong (`magicsock.go:2581-2690`) | `receivePing` | None |
| Unknown disco key | Drop (`magicsock.go:2245-2252`). "Known keys" include keys learned through TSMP | Drop. Only netmap keys are known | **Yes** (below) |
| Peer disco key changes | Clear trust, send history, and Ping history (`endpoint.go:1694-1697`, `:2286-2310`) | `resetForNewDiscoKey` | None |

Verdicts on the four hypotheses. CallMeMaybe waits for the next periodic round. False (table above, unit test 1). The first data does not start a full Ping round. False. The peer does not Ping immediately on receiving CallMeMaybe. False (`callMeMaybeExchange`). Ping handling for an unknown source differs. No difference.

### Cause (Unverified on Real Devices)

The remaining difference is **TSMP disco key advertisement** (notes §3.8 and §4.10). Each time a WireGuard session key is established, Go advertises its disco key via TSMP inside the tunnel (`magicsock.go:4631-4676`, CapabilityVersion 144, `tailcfg.go:195`). The receiver uses it immediately as its active key (`net/tstun/wrap.go:1133-1146`, `wgengine/userspace.go:608-623`, `magicsock.go:4579-4622`). This lets a peer learn the new disco key of a just-started Go node at the first handshake. Swiftail neither sends nor uses it (decision table, "TSMP advertisement"). With Swiftail on either side, the long-running side learns the newly started side's new disco key only through netmap. Until then, both sides drop disco. The long-running side sees an unknown key, and the newly started side cannot open messages sealed to its old key. Data flows over DERP, and both sides go direct within 1 second of receiving the new key in netmap (unit test 2). Relay duration therefore equals the time the control server takes to distribute the new key. Testcontrol distributes it immediately, so the above measurements are fast (Swiftail publishes the key in the status update before the stream request. Testcontrol ignores DiscoKey in stream requests with Version ≥ 68, `testcontrol.go:1452-1458`).

Consistent with the observations, both were first contacts with a just-enabled tunnel, and Go-to-Go took a few seconds. One point remains unverified. Because 10~30 seconds had already elapsed from enabling the tunnel to first contact, the hypothesis requires the production control server to take 35~74 seconds to distribute the new disco key. Swiftail declares CapabilityVersion 148 (≥ 144), so the server may trust the TSMP advertisement and delay distributing the updated disco key. The server code is not public, so this was unverified.

### `none` and Path Flapping After Idleness

`none` occurs in only three cases. More than 45 seconds have passed since the last WireGuard send (including keepalive, behavior G3), netmap changed the peer's disco key (`resetForNewDiscoKey`), or the peer was removed or its node key changed. The next send after the second or third case has no trust and yields `relayed → direct`. The observed `direct → relayed → direct` fits the first case. Heartbeats Ping `bestAddr` until 45 seconds, so the peer goes idle while trust remains. The next send uses that trust and reports `direct`. When trust expires (last Pong + 6.5 seconds), it reports `relayed`, and when that send starts a full Ping round and a Pong arrives, it reports `direct`. Go behaves identically internally (`endpoint.go:635-656`, `:1117-1124`). It emits no path events, so the changes are invisible. This is as designed, and the observed "26 seconds" appears to have been measured from a time other than the last WireGuard send. "Since previous event" in the logs below distinguishes this.

### Fixes

Behavior was unchanged. Within scope (`SwiftailMagicsock` and the node's data plane), no trigger or wait was found to differ from Go.

- Regression tests in `MagicsockStartupTests`. (1) With an idle host and a tunnel enabled later, both CallMeMaybe messages go out within 3 seconds of the first data (round deadline), and both sides go direct within 1 second. (2) While the host holds the tunnel's old disco key, both sides drop disco (`unknownDiscoKey`, `malformedDisco`). The instant netmap supplies the new key, the host path becomes nil, and both sides go direct within 1 second.
- Diagnostic log. The `Peer N path:` line includes the reason if the path was downgraded (behavior G4), the elapsed time since that peer's previous path event, and the counts by category of disco messages dropped since the previous path event for any peer (`Peer 1 path: relayed(7) (trust expired, 96.5s since previous event, dropped disco: unknown key 0, could not open 0, path rule 0)`). Assign each peer its number N on its first path event, starting at 1. When a peer leaves netmap, log its final event, then delete its record. If it returns, assign a new number on its next first event. Numbers are not reused in the same run. The first event shows `first event` in place of elapsed time. Logs contain no keys, addresses, names, or stable IDs (`PathEventTally`). Peer number, reason, and same-peer elapsed time were added on 2026-11-16 (when one device communicated with several peers, interleaved lines could not be distinguished).

### Distinguishing the Cases on Real Devices

Collect `Peer N path:` lines around first contact from both devices' `Swiftail`/`node` logs.

- **If the disco key hypothesis holds**, 25~44 seconds after `relayed(7)` the host logs `none (disco key changed, …s since previous event, dropped disco: unknown key N …)` (N > 0) for the same peer, immediately followed by `relayed(7)` and `direct`. The tunnel's `direct` line has `could not open` > 0.
- **If both counts are 0 and the delay persists**, disco was exchanged but UDP was unreachable (client isolation on the same Wi-Fi, iOS local network permission, or NAT hairpinning). Check port mapping (notes §6.2 `shortcut:`) and whether LAN endpoints were published.
- **Idle `none`.** `none (idle, …)` is as designed.

### Remaining Work (Outside This Scope)

- If the hypothesis holds, send and use TSMP disco key advertisements. The areas affected are `SwiftailWireGuard` (once inside the tunnel when a session key is established, for the initiator on receiving the response and for the responder on receiving the first transport under the new key, notes §4.10 item 1), `SwiftailEngine` (construct the 33-byte TSMP `'a'` and consume received messages while reporting the key upward), `SwiftailMagicsock` (Go's two-key model with one active key from the netmap key and TSMP key, `endpoint.go:382-436`, `:1552-1688`), the conclusion in notes §4.10 item 3, and the decision table's "TSMP advertisement" row. Another option is lowering the declared CapabilityVersion below 144 (`SwiftailControl`), which requires separate review because it also changes other server behavior.
- The time the production control server takes to distribute the new disco key can be verified only through real-device logs.

## TSMP Disco Key Advertisement (2026-11-16)

Each time a WireGuard session key is established, Go advertises its public disco key in a TSMP message inside the tunnel. The receiver uses it without waiting for netmap (notes `disco-magicsock.md` §3.8 and §4.10, capability version 144 "Client sends `TSMPDiscoKeyAdvertisement` around WireGuard handshakes"). Swiftail declared 148 but neither sent nor used these advertisements (the conclusion in notes §4.10 item 3 that "sending is unnecessary" was wrong). The apparent result is that a long-running peer learns a recently started node's new disco key only from netmap. Until then the peers cannot open each other's disco messages and no direct path forms (see "Direct Path Delay Investigation" above, 25~44 seconds on real devices. Real-device logs have yet to establish whether this is the cause). Add it regardless of the cause because it is part of the declared version's behavior.

Reference sources are `PriorityMessageForPeer`, `HandleDiscoKeyAdvertisement`, and `selfIPMatchingFamily` in `wgengine/magicsock/magicsock.go`, `updateTSMPDiscoKey`, `changedActiveDiscoLocked`, and the disco key storage (`keyFromTSMP` and its relation to the netmap key) in `endpoint.go`, `TSMPDiscoKeyAdvertisement` in `net/packet/tsmp.go`, the receive path in `net/tstun/wrap.go` and `wgengine/userspace.go`, and priority messages in the Tailscale fork of wireguard-go (`device/send.go`, `device/receive.go`, `MaxPriorityMessageContentSize`). Verify details in the source during implementation and record them in "Implementation Decisions."

### Behavior T

1. **Sending.** Send one advertisement to the peer inside the tunnel each time a new WireGuard session key is established with that peer. Match Go's timing. The handshake initiator sends when it receives the response and establishes the session. The responder sends when it receives the first transport under the new key. Match Go in whether the advertisement goes out before queued data.
2. **Contents.** Use the format in notes §3.8. The source is a local tailnet address of the same family as the peer's address (Go `selfIPMatchingFamily`), the destination is the peer's address, and the key is the local public disco key. Skip sending if there is no local address of that family or no disco key.
3. **Receiving.** The engine consumes the advertisement (as it already does, without forwarding it to the app or netstack) and reports the peer's node key and advertised disco key to `Magicsock`. Accept advertisements only from packets authenticated by WireGuard that pass source validation. Drop a key of 0.
4. **Active key.** For each peer, keep the key learned from netmap and the key learned from TSMP under the same rules as Go and make one active (verify from source what happens if netmap later provides a different key, the same key, or TSMP provides a key older than netmap). When the active key changes, clear that peer's direct path trust and in-flight Pings (notes §4.4 item 3) and rediscover the path promptly.
5. **Peers change only their own keys.** An advertisement changes only the disco key of the peer that sent it (the WireGuard session's node key). Match Go when one peer advertises a disco key used by another peer (two peers using the same disco key) and capture the behavior in tests.
6. **Secrets and logs.** Disco keys are public, and logs retain only event types and counts.

### Tests and Gate

- Unit tests. Advertisement bytes match Go `TSMPDiscoKeyAdvertisement.Marshal` output (generate vectors with the Go reference value tool). Cover initiator and responder send timing, the active key decision table on receipt, a key of 0, no address of the right family, ignoring advertisements from unauthenticated paths, and two peers using the same disco key.
- State machine. In the investigation's regression test for "while the host holds the tunnel's old disco key," both sides go direct within 1 second of the WireGuard handshake **without changing netmap**.
- Interop (`tailnet` tool, real Go peer). ① Restart the Swift node to change its disco key and verify a direct path forms with netmap updates to the Go peer blocked (tool map suppression). Go receives and uses Swiftail's advertisement. ② Conversely, change the Go peer's disco key and verify a direct path forms with netmap updates to the Swift node blocked. Swiftail receives and uses Go's advertisement. Document why if either case cannot be set up with the tool.
- Swift ↔ Swift. With two nodes in one process, restart one and measure time to a direct path without a netmap update.

### Implementation Decisions (2026-11-16)

Reference sources are tailscale.com v1.104.7 and the Tailscale fork of wireguard-go `v0.0.0-20261106233718-9e0ab45c16ca`. The code used for advertisements (`PriorityMessageForPeer`, `HandleDiscoKeyAdvertisement`, `endpoint.go`, `peermap.go`, `tsmp.go`, `wrap.go`) is identical character for character in v1.104.6, which the gate tool uses.

1. **Send timing and count** (`device/receive.go:416`, `:483`, `device/send.go:111-140`). Immediately after receiving the response and establishing the session, the initiator sends advertisement → keepalive (if the queue is empty) or queued data. The responder sends advertisement → queued data when the first transport using the new keypair passes AEAD and replay checks and confirms next, then delivers the received packet. Send once per keypair. Both sides send again on every rekey (initiator keypair 120 seconds). It bypasses the staged queue and precedes pending data. If there is no session for sending, stop without initiating a handshake. It counts as a data send (new handshake timer). The size limit is 512 bytes (`MaxPriorityMessageContentSize`), and an advertisement is 53 bytes for IPv4 and 73 bytes for IPv6. Swiftail ports this as `WireGuardDevice.setPriorityMessage(_:for:)`, and the engine determines per-peer advertisement bytes when applying netmap (including recomputation on key expiration).
2. **Contents.** The source is the first single-address prefix in the node's netmap `Addresses` whose family matches the peer's first `Addresses` address (Go `endpoint.nodeAddr`). The destination is that first peer address, and the key is `Magicsock.discoPublicKey` (the engine `init`'s `discoKey`). Skip sending if no address matches or the key is 0. WireGuard-only peers do not enter the engine, so no separate filter is needed. The bytes (ID 0, TTL 64, IPv4 header checksum) match Go's `Marshal` output (`Tools/interop/cmd/tsmpvectors`, `Tests/SwiftailEngineTests/Fixtures/tsmp-vectors.json`, `TSMPVectorTests`).
3. **Receive path.** The engine parses as TSMP only packets that WireGuard decrypted and whose source addresses passed the check against that peer's AllowedIPs. If the TSMP type is `'a'`, the body is at least 33 bytes (ignore trailing bytes as in Go), and the key is not 0, emit `.discoKeyAdvertised(key, from: that WireGuard peer)`. The node passes it to `Magicsock.receiveDiscoKeyAdvertisement(_:from:at:)`. Go finds the peer by source address (`wgengine/userspace.go:618`), but that WireGuard peer is the sole owner of a source address that passed validation, so the result is the same. Unauthenticated paths are unused. WireGuard drops bare packets received over UDP or DERP as malformed, drops sources outside AllowedIPs with `disallowedSource`, and the engine drops outgoing TSMP from the app or netstack (engine test `unauthenticatedAdvertisementsAreIgnored`).
4. **Active key decision table** (`endpoint.go:382-436`, `:1552-1688`, `magicsock.go:4579-4622`, value type `PeerDiscoKeys`, tests `PeerDiscoKeysTests`). "Rediscover" means `PeerPathState.resetForNewDiscoKey()` (Go `changedActiveDiscoLocked`, which clears trust, send history, and in-flight Pings).

   | Current state | Input | Active | Rediscover |
   | --- | --- | --- | --- |
   | Netmap key C only | Advertisement T (≠C) | T | Yes |
   | Netmap key C only | First advertisement C | C (TSMP side) | Yes. Go treats it as changed even though the value is equal |
   | TSMP key T active | Same advertisement T | T | No |
   | TSMP key T active | Netmap supplies a different key C2 | T | Yes |
   | TSMP key T active | Netmap supplies T (catches up) | T | Yes |
   | No key | Advertisement T, then netmap C | T, still T | Yes, yes |
   | Netmap key C2 | Advertisement C older than netmap | C. The advertisement always wins (Go ignores order) | Yes |
   | TSMP key T active | UDP Ping sealed with netmap key C (Ping's node key is that peer) or DERP CallMeMaybe (DERP sender is that peer) | C | Yes |
   | After reverting to C as above | Same advertisement T | C | No (same as previous TSMP key means "unchanged") |
   | Two keys | Netmap key disappears (0 or low-order) | T | Yes |

   Contract T4 said to clear state "when the active key changes." Go clears it whenever the update function returns true (including "even though the value is equal" in the table), so the implementation follows Go. Pong does not change the active key (as in Go). Match incoming disco sender keys against both the netmap key and the TSMP key (Go `knownPeerDiscoKey`), and seal outgoing disco with the active key. Forget the previous TSMP key when a new advertisement arrives (it remains if it equals the netmap key).
5. **When two peers use the same disco key** (fixed after independent review, see "Independent Review Results" below). The first implementation applied behavior B1 (one peer per key) to TSMP keys too. If peer C advertised peer B's new key before B, it rejected B's advertisement and delivered Pings that B sealed with the key only to C. The current model matches Go. Multiple peers hold one key (`Magicsock.DiscoKeyHolders`), and the owner of each incoming message is determined by Go's rules. The same model applies to netmap keys (B1). The change affected one table, and treating them differently would create two sets of rules.

   Reference sources are all of `peermap.go` (`nodesOfDisco`, `upsertEndpoint`, `cleanFromNodesOfDisco`, `deleteEndpoint`, `forEachEndpointWithDiscoKey`), `magicsock.go:2213-2538` (`handleDiscoMessage`), `:2547-2577` (`unambiguousNodeKeyOfPingLocked`), `:2581-2684` (`handlePingLocked`), `:3237-3345` (`upsertPeerLocked`), `:4579-4622` (`HandleDiscoKeyAdvertisement`), `endpoint.go:1645-1688` (`checkAndUpdateDiscoKey`), and `:1929-2022` (`handlePongConnLocked`). K in the decision table is the sender's disco key, and a "holder" is a peer with K as its netmap or TSMP key. Go and Swiftail agree.

   | Input | Who can send it | What changes | What stays the same | Tests |
   | --- | --- | --- | --- | --- |
   | Netmap | Control server | Each peer's netmap key. If multiple peers claim the same key, all hold it | Remaining peers' TSMP keys (even if another peer claims the same key through netmap) | `sharedDiscoKey`, `netmapKeepsTSMPKey`, `recoversOnNetmap` |
   | TSMP advertisement K from peer P | P (authenticated by WireGuard) | P's TSMP key = K, active = K, and P's path is rediscovered. P releases the previous TSMP key | Keys, paths, and trust of other peers already holding K | `advertisingAnotherPeersKey`, `ownerAdvertisementIsAcceptedAfterSquat` |
   | UDP Ping (sealed with K, node key N inside) | Holder of K's private key | The source becomes a candidate for all holders. If N is a holder, N's active key = K. One Pong | N's keys and candidates if N does not hold K. Peers that do not hold K | `udpPingReachesAllHolders`, `pingNodeKeyMustHoldSenderKey`, `ownersPingReachesOwner` |
   | DERP Ping (K, DERP sender D) | Holder of K's private key | None. Only a Pong to D (if D is known) | Every peer's candidates and keys | `derpPingTouchesNoCandidates` |
   | Pong (K, TxID) | Holder of K's private key | Path of the single peer whose state sent the Ping with that TxID | Other holders | `pongGoesToPingOwner`, `squatterPathPointsAtOwner` |
   | CallMeMaybe (K, DERP sender D) | D (authenticated by DERP with its node key) holding K's private key | D's candidates and D's active key = K if D holds K | Other holders. Drop if D does not hold K | `sharedDiscoKey`, `callMeMaybeFromInactiveKey` |

   A peer (C) advertising another peer's key can therefore change only its own state. Preserve what Go allows. If C holds B's key, B's Ping adds B's address to C's candidates, too. A Ping to C is sealed with that key and B replies, so C's path becomes direct to B's address (`squatterPathPointsAtOwner`). B drops WireGuard traffic sent to C, so C loses only its own traffic. WireGuard protects the traffic end to end, so no one else can read the contents. B's path, trust, and active key stay the same.

   **Differences from Go.** (a) If a peer's previous TSMP key equals its netmap key, Go removes that peer from the key when a new advertisement arrives (`upsertEndpoint` removes `oldDiscoKey`). It also removes the peer on a netmap key change if the key matches the TSMP key. Afterward, disco using that key is dropped unless another peer holds it. Swiftail keeps keys the peer still holds in its table. (b) If a UDP Ping is a replay for any holder, Go may stop there while iterating in random order, leaving later peers without the candidate. Swiftail inserts it for all peers. Both skip the Pong. (c) Swiftail does not retain low-order keys for which a shared key cannot be calculated (Go accepts them, see B2).
6. **Computation.** Compute the shared key (X25519) only for a changed advertised key and only from a peer authenticated by WireGuard (as in Go `discoInfoForKnownPeerLocked`). Garbage UDP or DERP packets claiming unknown keys still cannot trigger computation.
7. **Logging.** On receiving an advertisement, the node logs only `Received TSMP disco key advertisement` (debug). It logs no keys, addresses, or names.
8. **State machine regression test** (`MagicsockStartupTests.staleDiscoKeyWithAdvertisement`). With the host still holding the tunnel's old disco key, inject advertisements at handshake times (+30 and +40 ms). Both sides go direct 0.51 seconds after the first data (on the next data send) without a netmap update. Without the advertisement, the same scenario stays relayed until netmap arrives (`staleDiscoKeyUntilNetmap`).
9. **Interop gate** (`Tests/SwiftailInteropTests/DiscoAdvertisementTests.swift`, `tailnet` tool, loopback). Both sides go direct in ① 10.3~10.5 seconds after restarting the Swift node with automatic maps to the Go peer blocked, ② 10.5~10.8 seconds after restarting the Go peer (new tool command `restartPeer`, same state directory and node key, new disco key and port) with maps to the Swift node blocked, and 10.8 seconds for Swift ↔ Swift (one side restarted), each run 3 times. Most of the time is WireGuard session establishment before advertisement. The long-running side trusts the pre-restart address for 6.5 seconds after the last Pong and sends the handshake response only to that dead address. The restarted side retries every 5 seconds (same rules as Go). After receiving advertisements, node logs showed both sides going direct within 0.1 seconds. Running the same tests with code predating this unit leaves all three relayed without going direct within 20 seconds. When two Swift nodes send at the same instants, their initiations cross (an incoming initiation clears the local one, and the next retries are also triggered by the same sends), adding 5 seconds each time. This follows WireGuard rules, so the tests use different send intervals.
10. **Lines outside this section.** The decision table's "TSMP advertisement" row and behaviors B1 and C1~C5 were updated to the current behavior after independent review. The exclusions table's "sending TSMP advertisements and switching the active TSMP key" row was removed.
11. **Engine `init`'s `discoKey`.** Accept it without a default. Omitting it would silently disable advertisement, so callers always supply it (tests that do not need advertisements use `.zero`).

### Independent Review Results (2026-11-16)

An independent review by another session compared this section's implementation with the Go source. Reproduction tests are in `Tests/SwiftailMagicsockTests/DiscoKeyAdvertisementReviewTests.swift` and `Tests/SwiftailEngineTests/TSMPAdvertisementReviewTests.swift`. Findings were 1 medium and 4 low.

| # | Severity | Finding | Resolution |
| --- | --- | --- | --- |
| 1 | Medium | If another peer advertises a disco key before its owner, it blocks the owner's advertisement and Pings sealed with that key (T5). The owner cannot establish a direct path until netmap supplies the key | Fixed using the Go model and decision table in item 5 above. Removed `withKnownIssue` from two reproduction tests (renamed to `ownerAdvertisementIsAcceptedAfterSquat` and `ownersPingReachesOwner`). `recoversOnNetmap` changed meaning. Even when netmap gives the key to its owner, the other peer that advertised the key keeps using it (as in Go, that peer loses only its own traffic) |
| 2 | Low | The engine `init` defaults `discoKey` to `.zero`. Omitting it silently disables advertisements | Fixed by requiring the argument (item 11 above) |
| 3 | Low | The parsing vectors covered only IPv4 bodies. IPv6 and fragments were covered only by Swift tests | Fixed by adding an IPv6 advertisement, three IPv4 fragments (MF, offset 1, offset 10), and three IPv6 fragment headers (first fragment M 1 and 0, later fragment) to `tsmpvectors` and generating Go verdicts. Go accepts the two IPv6 first fragments and Swiftail drops them. `TSMPVectorTests` checks those two as known differences. Go peers do not fragment 73-byte advertisements, so no advertisements are missed |
| 4 | Low | Contract lines outside this section (decision table, exclusions table, B1, C2, and C4) differ from actual behavior | Fixed in item 10 above |
| 5 | Low | A delayed stale advertisement overwrites the new key, and advertisements that keep changing keys trigger X25519 | Retained (below) |

Items retained and their rationale follow.
- **Delayed stale advertisements.** Advertisements have no sequence number, so a delayed old advertisement can overwrite the new TSMP key. Go also ignores order (the "advertisement older than netmap" row in item 4 above). An advertisement arrives once per WireGuard keypair, so the next rekey's advertisement (within 120 seconds) corrects it. Meanwhile, a Ping or CallMeMaybe sealed with the inactive key makes that key active again on receipt, and netmap is also a recovery path.
- **Cost of advertisements that keep changing keys.** An authenticated peer can trigger one X25519 per advertisement. Go does the same (`discoInfoForKnownPeerLocked`). The table holds at most two keys per peer (netmap and TSMP keys, `rotatingAdvertisementsAreBounded`). An advertisement is one WireGuard transport, so the sender performs that much work too.

Unverified items include behavior in a real tailnet (a production control server and its netmap propagation time) and on an IPv6-only network. Real cases of several peers holding the same disco key (node sharing and account switching) were also unobserved in a real tailnet. Interop tests ran only against Go peers on loopback.

## Real-Device Remeasurement (2026-11-16, First Adopter Session)

Both sides were built with `b27b482`, which includes TSMP disco key advertisement, and measured again on the same Wi-Fi (Swiftail tunnel on iPhone 14 Pro with iOS 27.2, Swiftail host on Mac, production tailnet with lock enabled). The record is from the iPhone extension. Mac `Swiftail`/`node` logs were at info level and did not persist to disk, so they were unavailable for this run.

| Peer | Tunnel `running` | First contact (`relayed`) | `direct` | Dropped disco |
| --- | --- | --- | --- | --- |
| Go host | +0 seconds | +9 seconds | Same second (`relayed → direct → none → relayed → direct` at 0.0-second intervals) | 0 |
| Swiftail host | +0 seconds | +9 seconds | About 2 seconds later (`relayed(20)` → 0.7 seconds `none` → `relayed(20)` → 1.5 seconds `direct`) | 0 |

- The value comparable to the earlier result (25~44 seconds before TSMP advertisement) is **about 2 seconds**. This is faster than the roughly 10.5 seconds in the test environment without an account (netmap updates blocked), presumably because the production control server also provides netmap.
- **This record cannot establish that the advertisement caused the improvement.** The already running Mac would learn the new disco key from the advertisement, and its logs are missing. The iPhone record had no `Received TSMP disco key advertisement` (the node logs the engine's advertisement event before Magicsock compares the keys). Conditions differed as well. This time the Mac node reregistered about 40 seconds before the tunnel was enabled. In the next measurement, check the Mac's `Peer N path:` and `Received TSMP disco key advertisement` lines.
- The relay region was logged first as 20 and later as 7. The recently registered Mac node's home DERP appears to have changed from the pre-STUN fallback home (unverified).

### `relayed` About 100 Seconds After Going Direct

In both measurements the iPhone logged `relayed(7)` once, at 96.5 and 105.3 seconds since the last path event. Dropped disco was 0.

- In the Go host measurement it was near the end of a 100MiB transfer and returned to `direct` 5.8 seconds later. The return time fits the rule against Pinging the same candidate again within 5 seconds (`pingInterval`, as in Go).
- In the Swiftail host measurement it was after the transfer finished, followed 6.6 seconds later by idle `none`.
- Two causes considered at this point for a transition to `relayed` were trust expiry after 6.5 seconds without a Pong (`trustDuration`) and rebinding the UDP socket, which discards the path (`noteConnectivityChange`). The investigation below also considers candidate removal. The unfiltered extension logs for those times showed no `Network path:`, rebind, or DERP lines in either interval (the only rebind was when enabling the tunnel). Rebinding was ruled out.
- The transfer continued over DERP. See "Investigation Results" below for the verdict.

### Investigation Results (2026-11-16)

Later findings. The iPhone communicated with two nodes on the Mac (the Go node in the first adopter's app, apparently home region 7, and the test server's Swiftail node, apparently home region 20), and `Peer path:` lines did not distinguish peers. "Since previous event" also meant the previous event for any peer. Both `relayed(7)` events therefore appear to concern the Go node's path. In measurement 1, the transfer peer was that Go node (the app's "direct connection on the same network" was disabled). In measurement 2, `relayed(7)` may be unrelated to the transfer peer (the Swiftail server). The findings below prioritize measurement 1.

**Ways to reach `relayed`** (all paths from direct to relayed, matching Go v1.104.7 line for line).

| Path | Swiftail | When it occurs | Go |
| --- | --- | --- | --- |
| Trust expiry | 6.5 seconds after the last Pong (`PeerPathState.path(at:)`, expiry deadline in `advance`). The heartbeat Pings `bestAddr` every 3 seconds (`heartbeat`), so **at least two consecutive** Pongs must be missed | Heartbeat time + 0.5 seconds + round trip | `endpoint.go:926-930` (heartbeat Ping), `:2003-2019` (Pong extends trust), `:635-652` (also send through DERP after expiry), `magicsock.go:4099` and `:4103` |
| Candidate removal | `dropBestAddrIfRemoved` ← `removeStaleCandidates` (full Ping round, netmap update, more than 100 candidates), `receiveCallMeMaybe` | Time of the call (heartbeat time or arrival of netmap or CallMeMaybe) | `:510-521` (`shouldDeleteLocked`), `:1423-1433`, `:1762-1800`, `:1810-1846`, `:2150-2215` |
| Rebinding | `noteConnectivityChange` | Same time as the rebind log line | `:1876` (`noteConnectivityChange`) |
| Ping deadline | `expirePings` clears `bestAddr` | Clears only after trust has expired, so it does not produce a new `relayed` | `:1244-1257` |
| Disco key change | `resetForNewDiscoKey` (netmap, TSMP advertisement, disco under an inactive key) | Clears send history and goes directly to `none`, skipping `relayed`. The next send yields `relayed → direct` | `:1694-1697` (`changedActiveDiscoLocked`), `:2294-2310` (`lastSendExt = 0`) |

**Findings that distinguish the cases**
- State machine test `MagicsockLongSessionTests.repeatedDownloads`. Connect two `Magicsock` instances with a virtual clock (one-way latency of 2, 10, and 30 ms). For 300 seconds, repeat 26-second downloads (host sends every 20 ms, client every 100 ms) and 42-second idle periods. Supply netmap in four ways (once at the start, same list every 30 seconds, changed list every 30 seconds, client learns the host address only through Ping). None of the 12 cases show `relayed` or nil after direct. Without loss, candidate removal (including the 45-second rule), stopping heartbeats, and netmap updates are not the cause. Even Ping-learned candidates are refreshed by the host's heartbeat Ping every 3 seconds during downloads, and 42 seconds of idleness is within the host heartbeat window (45 seconds since the last send). A real Go node also includes its endpoints in CallMeMaybe, so the address may become a CallMeMaybe candidate that is kept.
- Interop test `LongDownloadPathTests` (loopback, real Go peer, same 26-second and 42-second repetition). 0 path events while receiving 780MiB over 162 seconds. Loopback has a round trip below 5 ms, so it does not exercise the full Ping path that runs every 1 minute.
- Measurement 1 timing. The preceding event (23:38:30.5, simultaneous with the first send and therefore the heartbeat baseline) plus 96.5 seconds equals the 32nd heartbeat (96.0 seconds) + 0.5 seconds. If the last Pong was for the 30th heartbeat (90.0 seconds), trust expires at 96.5 seconds plus the round trip. Candidate removal would have coincided exactly with the heartbeat or with a netmap arrival. No rebind line is present, and a disco key change would have logged `none`.
- State machine test `MagicsockLongSessionTests.pongLossDuringDownload`. Dropping only the host's Pongs for 9 seconds during a download yields `relayed` 6.5 seconds (79.52 seconds) after the last Pong (73.02 seconds) and `direct` at the first Pong after loss ends (84.02 seconds). This matches the observed pattern.

**Verdict**
- Likely, unconfirmed cause. The iPhone missed at least two consecutive heartbeat Pongs from the Go node (a Ping or Pong was lost or the reply missed the 5-second deadline). The expiry rule and timer values match Go. If Go were the receiver there, the same expiry would happen internally (also send through DERP). Go emits no path events, so it is invisible. Behavior was therefore unchanged.
- Where packets were lost could not be determined. Candidates are Wi-Fi (queue near the end of the transfer), UDP sending on the remote Go node (drops the datagram when the send buffer fills, unverified), and the iPhone receive queue (`DatagramSocket`, 256 entries and 1MiB, dropping the oldest first). The third is part of Swiftail, but the 780MiB loopback run did not show it. There is no `relayed` during transfer in measurement 2, which exchanged 100MiB with the Swiftail server on the same Wi-Fi, or in the server-side record for the cellular measurement.
- Measurement 1's 5.8 seconds. After trust expires, the deadline for the Ping at 93 seconds (98 seconds) clears `bestAddr`. The heartbeat then stops Pinging `bestAddr` and only runs full Ping rounds. Each candidate cannot be Pinged again within 5 seconds (`pingInterval`, Go `endpoint.go:1437-1439`), so the address Pinged at 96 seconds can be Pinged again starting at 101 seconds. The transfer ended at 23:40:11 (100.5 seconds), so there was no send at 101 seconds to trigger a full Ping round. The 102-second heartbeat Ping received a Pong and restored `direct` (96.5 seconds + 5.5 seconds + round trip). Losing just two Pongs (93 and 96 seconds) thus accounts for 5.8 seconds. During transfer, a send as soon as the 5 seconds elapse triggers a Ping (84.02 seconds in the test above).
- Measurement 2 (`relayed(7)` → 6.6 seconds → `none`, no `direct` in between, 0 dropped disco). For the same peer, there are only two ways for `none` to occur at 6.6 seconds instead of 45 seconds after the last send (`Magicsock.path(of:)`, `idleDeadline`). (a) The app sends one batch to the idle Go node, yielding `relayed` (no trust, full Ping round and CallMeMaybe). No Pong arrives within 6.6 seconds. Then that peer's active disco key changes (for example, its first TSMP advertisement this run. Even if it equals the netmap key, it triggers rediscovery, as in Go). Clearing the send history immediately yields `none`. (b) The peer was removed from netmap. If lines from different peers interleaved, (c) `relayed` could indicate trust expiry and `none` could be idleness for another peer. New logs distinguish these with `none (disco key changed, …)`, `none (peer removed, …)`, and distinct peer numbers, respectively. The record cannot establish why no Pong arrived.

**Changes.** Diagnostic logs only (the diagnostic log item under "Fixes" above, behavior G4). State machine behavior stayed the same.

**Options to reduce the impact** (all differ from Go, so choose after determining the source of loss). Ping `bestAddr` once more at trust expiry regardless of the 5-second rule (would restore `direct` about 3 seconds sooner in measurement 1), or change the trust duration or heartbeat interval (behavior D6 precludes this). After trust expires, sending continues over UDP and also goes through DERP, so the transfer continues (as observed).

**Lines to check in the next real-device measurement** are the `Peer N path:` lines on both iPhone and Mac.
- `relayed(…) (trust expired, …)` during transfer means Pongs stopped arriving. Check whether the Swiftail peer also downgraded that peer for `trust expired` at the same time (loss in both directions) or did not (loss in one direction only).
- `candidate removed` means netmap or CallMeMaybe changed the candidate. Check the netmap update line at that time.
- `rebind` refers to the full rebind on a path update for the same interface described in [M5 gate (b) in `SwiftailTunnel.md`](SwiftailTunnel.md#b-real-device).
