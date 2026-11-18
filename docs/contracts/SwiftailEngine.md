# SwiftailEngine and Swiftail contract (M3)

This layer turns the netmap into a data plane. The M3 goal is to exchange IP packets with a Go tsnet peer **using only DERP relay, without a direct UDP path** (`docs/plan.md` §7 M3).

- `SwiftailEngine` provides I/O-free value types for IP packet parsing, packet filtering, and computing WireGuard peers from a netmap. The `TailnetEngine` data plane state machine combines them with `WireGuardDevice`.
- `Swiftail` provides the public `TailnetNode` actor, the edge that connects `ControlClient`, `DERPClient`, `TailnetEngine`, and the clock.

Protocol details follow [protocol-notes/netmap-engine.md](../protocol-notes/netmap-engine.md) (verified) and [derp-stun.md](../protocol-notes/derp-stun.md) §§4.8 and 4.9.

## Targets

| Target | Dependencies | Contents |
| --- | --- | --- |
| `SwiftailEngine` | `SwiftailBase`, `SwiftailWireGuard`, `SwiftailControl`, CryptoKit | [Engine API](#engine-api-swiftailengine) below. No sockets or clock |
| `Swiftail` | `SwiftailBase`, `SwiftailEngine`, `SwiftailControl`, `SwiftailDERP`, `SwiftailIO` | `TailnetNode` |

## M3 support

M3 exchanges IPv4 and IPv6 packets with ordinary Tailscale peers (Go tsnet) using their own addresses (/32, /128). It supports one home DERP region.

Unsupported cases **fail closed** (exclude peers or drop packets):

- Subnet routes and exit nodes (fixed at `RouteAll=false` and no exit node), WireGuard-only peers (`isWireGuardOnly`), jailed peers (`isJailed`), peers with masquerade addresses, peers marked `unsignedPeerAPIOnly` (Go clears all packet rules if a rule overlaps with one of these peers), `cap:` source rules, and shields-up.
- IP fragments and IPv6 extension headers are dropped (Go passes some through. M3 has no stack to reassemble them).
- The engine consumes inbound TSMP (IP protocol 99) without passing it up. It emits advertisements carrying a nonzero disco key as `.discoKeyAdvertised` with the sending WireGuard peer. It sends neither pongs nor rejections. It sends disco key advertisements when a WireGuard session is established for each peer (2026-11-16, `SwiftailMagicsock` contract section [TSMP Disco Key Advertisement](SwiftailMagicsock.md#tsmp-disco-key-advertisement-2026-11-16)). It drops TSMP from above (Go also drops host-generated TSMP. Added in M5-8a, `SwiftailTunnel` contract behavior L 4).
- If legacy rules (`SrcBits`, `DstPorts[].Bits`) are present, clear all rules. Local addresses and recorded UDP flows remain, so replies to previously sent UDP are still accepted (as in Go).
- Direct UDP, disco, STUN, and non-home DERP regions are M4.

## Engine API (`SwiftailEngine`)

```swift
/// The header of a validated IP packet. Contains only the fields read by filtering and path selection.
public struct IPPacket: Sendable, Equatable {
    public enum TransportProtocol: Sendable, Equatable { case tcp, udp, sctp, icmpv4, icmpv6, tsmp, other(UInt8) }
    public enum ParseError: Error, Sendable, Equatable {
        case malformed      // Invalid length, version, or header length
        case fragment       // Fragment, including the first fragment
        case extensionHeader // IPv6 extension header
    }

    /// The entire packet, trimmed to its declared length.
    public let bytes: [UInt8]
    public let source: IPAddress
    public let destination: IPAddress
    public let transportProtocol: TransportProtocol
    /// The TCP, UDP, or SCTP port. Zero for other protocols.
    public let sourcePort: UInt16
    public let destinationPort: UInt16
    /// Whether this TCP packet has SYN set and ACK clear (the start of a new connection).
    public let isTCPSYN: Bool

    public init(parsing bytes: [UInt8]) throws(ParseError)
}

/// Determines whether to accept an incoming packet. Built from tailcfg filter rules and local addresses.
public struct PacketFilter: Sendable {
    public enum Verdict: Sendable, Equatable {
        case accept
        case drop(DropReason)
    }
    public enum DropReason: Sendable, Equatable { case notForUs, noRuleMatched, multicastOrLinkLocal }

    /// A filter with no rules or local addresses. Drops every packet (the state before receiving a netmap).
    public static var allowNone: PacketFilter { get }

    /// - Parameters:
    ///   - rules: `Netmap.packetFilter` as provided.
    ///   - localAddresses: The local node's addresses. Drops packets whose destination is absent from this list.
    public init(rules: [FilterRule], localAddresses: [IPAddress])

    /// Evaluates an incoming packet. Accepts replies to previously sent UDP even without a rule.
    public mutating func checkInbound(_ packet: IPPacket) -> Verdict
    /// Records an outgoing packet so that UDP replies can be accepted.
    public mutating func recordOutbound(_ packet: IPPacket)
    /// Replaces the rules and preserves recorded UDP flows.
    public mutating func replaceRules(_ rules: [FilterRule], localAddresses: [IPAddress])
}

/// A netmap peer installed in the data plane.
public struct EnginePeer: Sendable, Equatable {
    public var key: NodePublicKey
    /// The addresses this peer may use as sources. These become WireGuard AllowedIPs.
    public var allowedIPs: [IPPrefix]
    /// The DERP region to use when sending to this peer. Zero means unknown.
    public var homeDERP: Int64

    /// Selects the netmap peers to install in the data plane, in ascending node ID order.
    public static func peers(in netmap: Netmap, at now: Date) -> [EnginePeer]
}

/// A node's data plane state machine, combining its netmap, WireGuard, and packet filter.
public struct TailnetEngine: Sendable {
    public enum Output: Sendable, Equatable {
        /// A WireGuard message to send over DERP.
        case datagram([UInt8], to: NodePublicKey, derpRegion: Int64)
        /// An IP packet that passed the filter and should be passed up.
        case ipPacket([UInt8])
        /// A dropped packet, for diagnostics and tests.
        case dropped(Drop)
    }
    public enum Drop: Sendable, Equatable {
        case inbound(PacketFilter.DropReason)
        case malformedPacket
        case unsupportedPacket        // Fragment, IPv6 extension header
        case consumedControlPacket    // TSMP
        case noPeerForDestination
        case noRouteToPeer            // The peer's home DERP is unknown or differs from our home region
        case discoMessage             // M3 does not handle disco
        case wireGuard(WireGuardError)
    }

    public init(nodeKey: Curve25519.KeyAgreement.PrivateKey, now: ContinuousClock.Instant, wallClock: Date)

    /// Applies the netmap by adding and removing peers and replacing the filter. Returns any outputs to send.
    public mutating func apply(_ netmap: Netmap, homeDERP: Int64, at now: ContinuousClock.Instant, wallClock: Date) -> [Output]
    /// Sends one IP packet from the layer above.
    public mutating func send(_ ipPacket: [UInt8], at now: ContinuousClock.Instant) -> [Output]
    /// Processes one packet received from DERP.
    public mutating func receive(_ packet: [UInt8], from peer: NodePublicKey, at now: ContinuousClock.Instant) -> [Output]
    /// Processes timers due by now (WireGuard timers and peer key expiration).
    public mutating func advance(to now: ContinuousClock.Instant) -> [Output]
    /// The next time to call advance.
    public var nextDeadline: ContinuousClock.Instant? { get }
}
```

### Behavior

1. **IP packet parsing** (notes [§3.1](../protocol-notes/netmap-engine.md#31-ip-and-transport-headers-read-by-the-filter) and [§3.2](../protocol-notes/netmap-engine.md#32-fragments-and-ipv6-extension-headers)). Validate once at the boundary. IPv4 requires at least 20 bytes, IHL of at least 5, and declared length within the buffer. IPv6 requires at least 40 bytes and declared length within the buffer. Require the minimum transport header length for TCP (20 bytes), UDP (8 bytes), SCTP (12 bytes), and ICMP. Trim bytes after the declared length. IP protocol numbers 0 and 255 are `malformed` (Go drops both as Unknown). IPv4 with MF set or a nonzero offset and IPv6 with next-header 44 are `fragment`. IPv6 next-header 0, 43, 50, 51, 60, 135, 139, or 140 is `extensionHeader`. Swiftail enforces a minimum IHL and initializes packet fields afresh. Go can retain fields from a previous decode, such as `TCPFlags` when decoding a non-TCP packet.
2. **Peer computation** (notes §4.1, `RouteAll=false` and no exit node):
   - Exclude peers with `id` 0, `key` 0, expiration (`expired` or a nonzero `keyExpiry <= now`), both zero `discoKey` and zero `homeDERP`, or an unsupported peer type listed above.
   - AllowedIPs. Keep only the peer's single-address `allowedIPs` (IPv4 `/32`, IPv6 `/128`) that are in the Tailscale address ranges or the peer's `addresses`. The Tailscale ranges are `100.64.0.0/10` except `100.115.92.0/23`, and `fd7a:115c:a1e0::/48`. Never assign prefixes matching this node's own `addresses` to a peer. Reject IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d/128`) even if present in `addresses` (2026-11-17 security verification, second pass). `whoIs` converts mapped addresses to IPv4 when looking up identity by address. A peer that uses a mapped source without owning the IPv4 address could therefore appear as another node. Exclude the peer if nothing remains. Go's `peerViewOf` treats any prefix in `addresses` as a local address regardless of length. This implementation rejects broader prefixes (2026-11-17 security verification). `WireGuardDevice` checks sources separately for each peer and does not select the owner by longest prefix. A peer with a broad prefix could use another peer's or this node's address as a source. Revisit this rule and source checks together when supporting subnet routes.
   - Assign each key and each prefix to only one peer. If several nodes claim the same key or prefix, the lowest node ID wins (each source address must bind to one peer, and wireguard-go AllowedIPs also gives each prefix one owner).
   - `shortcut:` Use the local clock for expiration (Go compensates for clock skew over 1 minute using ControlTime). Original inputs with host bits set cannot be distinguished (`IPPrefix` clears them when decoding).
3. **Applying a netmap** (notes §4.2 design choice and §6.1). Install all computed peers up front with `WireGuardDevice.addPeer` (Go creates them lazily). Call `removePeer` for keys that disappear or become ineligible. Changing AllowedIPs for the same key preserves the session. Replace filter rules and carry over recorded UDP flows. Put the next key expiration in `nextDeadline` and recompute peers then (remove expired peers and reassign their prefixes to other nodes that claim them). Each peer computation also builds the "address → owner node" table (`addressOwners`) in the same pass. The node's `whoIs` and connection owner checks read this table (host contract behaviors W1 and W6). `recomputesPeers(at:)` indicates whether `advance(to:)` handles key expiration.
4. **Sending**. Parse the packet → select the destination peer from `addressOwners`, built from the AllowedIPs used for inbound source checks (if absent, `noPeerForDestination`) → if the peer's `homeDERP` differs from our home region, `noRouteToPeer` → `recordOutbound` → `WireGuardDevice.send`. Attach the region to each `.datagram` the device emits and return it. Outbound packets bypass ACLs (as in Go).
5. **Receiving**. Drop packets that start with disco magic `54 53 f0 9f 92 ac` and are at least 62 bytes long as `discoMessage`. (`shortcut:` Go identifies disco at 38 bytes (`disco-magicsock.md`). The WireGuard device drops packets between those lengths as malformed, so the result is the same. Match 38 in M4 when handling disco.) Otherwise pass the packet to `WireGuardDevice.receive`. Parse only the device's `.ipPacket` output (packets that passed decryption and the AllowedIPs source check) → consume TSMP → `checkInbound` → on `accept`, emit `.ipPacket`. Attach the region to the device's `.datagram` output (such as handshake responses) and emit it. The sender key from the DERP frame does not substitute for source checks.
6. **Filter** (notes §§4.4–4.6):
   - Rule conversion. If `SrcBits` or `DstPorts[].Bits` is present, the entire filter becomes `allowNone` (as in Go, so broad legacy rules do not survive). An empty `IPProto` means TCP, UDP, ICMPv4, and ICMPv6. Otherwise keep only 0…255. Address strings are `*`, CIDR (discard the entry if host bits are set), an `a-b` range, or a single address. Discard individual sources beginning with `cap:` and individual unparseable entries. A rule with only `CapGrant` does not allow packets.
   - Evaluation order. Drop multicast or link-local destinations → `notForUs` if the destination is not a local address → protocol-specific evaluation.
   - TCP. Check rules (protocol, source address, destination address, and destination port) only for packets with SYN set and ACK clear. Accept all other TCP packets (no connection tracking, as in Go).
   - UDP and SCTP. Accept matching recorded flows, otherwise check rules. The record is the reverse tuple of outbound UDP or SCTP (protocol and address/port pairs), with a 512-entry LRU and no timeout. Inbound packets create no records.
   - ICMP. Accept echo replies and errors (v4 types 3, 11, and 12, v6 types 1, 2, 3, and 4). Otherwise accept when a rule matches the source and destination addresses, ignoring ports. Go's v4 error set is 3, 11, and `0x12` (18), but the specification uses 12 for Parameter Problem, so use 12 (known difference, marked in the Go comparison fixtures).
   - Other protocols. Accept only if a rule specifies that protocol number and a port range of 0…65535.
   - The result is the union of allow rules. There are no deny rules or priorities.
7. `TailnetEngine` holds the node private key and WireGuard sessions, so it hides its children with `CustomReflectable`.

## Node API (`Swiftail`)

These are the M3 declarations. The canonical source for current events and public API is [Public API in `docs/contracts/SwiftailTunnel.md`](SwiftailTunnel.md#public-api-swiftail-complete-as-of-m5). Additions on 2026-11-18 were `NodeEvent.statusChanged` (only when `status` actually changes, with no value), `TailnetNode.hasSavedIdentity(in:)` (whether a saved identity exists), and aliases for other modules' types that appear in the public API (their names require only `import Swiftail`).

```swift
public struct NodeConfiguration: Sendable {
    /// The directory for identity files.
    public var stateDirectory: URL
    public var hostname: String
    public var controlURL: URL
    /// Used only for initial registration.
    public var authKey: String?
    public var ephemeral: Bool
    public init(stateDirectory: URL, hostname: String, controlURL: URL, authKey: String? = nil, ephemeral: Bool = false)
}

public enum NodeEvent: Sendable {
    /// The user must sign in at this URL.
    case loginRequired(URL)
    /// The node registered and received a netmap. Includes its own tailnet addresses. Emitted again when they change.
    /// Also emitted when all lost connections recover after `reconnecting`.
    case running(addresses: [IPAddress])
    /// A connection to the control server or DERP dropped and is being restored.
    case reconnecting
}

public enum NodeError: Error, Sendable {
    case control(ControlError)
    case invalidConfiguration(String)
}

/// A node in a tailnet. M3 exchanges IP packets in memory (TUN is M5, listeners are M6).
public actor TailnetNode {
    public init(configuration: NodeConfiguration)

    /// The event stream for one subscriber. The stream ends when `run()` ends.
    public nonisolated var events: AsyncStream<NodeEvent> { get }
    /// The stream of IP packets sent by peers and accepted by the filter. One subscriber. Slow consumption drops the oldest packets first.
    public nonisolated var inboundPackets: AsyncStream<[UInt8]> { get }

    /// Registers, receives the netmap, and maintains the data plane. Does not return until the calling task is canceled.
    /// Throws failures that retrying cannot resolve. Call only once per node.
    public func run() async throws(NodeError)

    /// Sends one IP packet to the tailnet. Silently drops it if it cannot be sent (as IP normally does).
    public func send(_ ipPacket: [UInt8])

    /// Requests a new interactive login URL.
    public func startInteractiveLogin()
}
```

The change from the draft in `docs/plan.md` §6 is `run()` with Task cancellation in place of `start()`/`stop()` (the same shape as `ControlClient` and `DERPClient`, with the lifetime scoped to the call and no detached Task). M5 defines `TunnelDevice` and `TunnelNetworkSettings`.

### Behavior

1. **Startup**. Create `NodeIdentityStore` and `ControlClient`. Generate a new disco key without saving it to disk and publish its public key as `LocalStatus.discoKey`. **Go peers install this node as a peer only if its DiscoKey is nonzero** (derp-stun notes §6 item 7). M3 does not answer disco messages.
2. **After registration**. On a `registered` event, read the node private key from the identity file and create `TailnetEngine` (recreate it if the key changes).
3. **Home DERP** (derp-stun notes §4.8). From the first netmap's DERPMap, choose the lowest-ID region that is eligible (`noMeasureNoHome` is false) and has a usable server (not `stunOnly` and with a nonempty `hostName`. Starting in M8 ③, `certName` does not cause a skip). Publish it as `LocalStatus.netInfo.preferredDERP` (**otherwise Go peers do not know where to send**). Start a `DERPClient` for the region with `isPreferred: true`. Restart it if that region changes in DERPMap. If no usable regions remain, stop the client and exclude DERP from the count of lost connections. `shortcut:` no latency measurement, one region only (M4).
   - `DERPServer` conversion. Keep `hostName` as is. Use `ipv4` if it is an IPv4 address, DNS if empty, or apply the same rule to `ipv6` otherwise (`"none"`). Skip the server if neither works. Use 443 when `derpPort` is 0. For certificate verification, use `.pinned(remainder)` when `certName` starts with `sha256-raw:`, `.named(certName)` when it is nonempty and differs from `hostName`, or `.noneForTests` when `insecureForTests` is set in the remaining case (DERP contract "M8 ③"). Skip servers with an empty `hostName`.
4. **Netmap**. Call `engine.apply` on every netmap. Emit `running` once local addresses are known.
5. **Packets**. `send` → `engine.send`. DERP `packet` event → `engine.receive`. Engine `.datagram` → `DERPClient.send`, `.ipPacket` → `inboundPackets`. Call `engine.advance` at `nextDeadline`.
6. **Structured concurrency**. Control, DERP, and timers run as children in one TaskGroup within `run()`. They all stop when the Task that called `run()` is canceled. The actor serializes engine calls.
7. **Secrets**. Keep the node and disco private keys out of events, errors, `description`, and `dump`.

## Tests

Unit tests (`Tests/SwiftailEngineTests`, no sockets or clock. Decode tailcfg values from JSON):

- `IPPacket`. Fixed IPv4 and IPv6 TCP, UDP, and ICMP packets, trimming to declared length, short headers, IHL 4, fragments (MF, offset, IPv6 44), extension headers, and arbitrary input without a crash.
- Filter conversion and evaluation. Items 3–6 of notes §7 cover `*`, CIDR, single addresses, ranges, `cap:`, both port endpoints, empty `IPProto`, explicit protocols, out-of-range numbers, invalid CIDR, `SrcBits`, `CapGrant`-only rules, TCP SYN and non-SYN packets, ICMP address-only rules and echo replies, nonlocal destinations, and recorded UDP flows (reply to an earlier send, one tuple with a single differing field, the 513th record, and retention after rule replacement).
- **Comparison against Go**. Feed identical rules and packets to Go's actual `wgengine/filter`, save the verdicts as fixtures (`Tests/SwiftailEngineTests/Fixtures`), and compare. A tool in `Tools/interop` produces the fixtures, and a separate session from the implementer writes the comparison tests. Mark and examine intentional M3 differences separately in the fixtures (fragments, extension headers, and `cap:` sources).
- Peer computation. Notes §7 item 7 covers expiration boundaries (`==`, `<`, `>`), no expiration, zero keys, empty AllowedIPs, removing subnets and `/0` from AllowedIPs, and unsupported peers.
- `TailnetEngine`. Connect two engines in memory (send one engine's `.datagram` to the other's `receive`) for a UDP round trip. Test peer addition, removal, and key rotation through netmap updates, sources outside AllowedIPs, disco messages, TSMP consumption, peers in another home region, removal at key expiration, and absence of keys in `dump`.

## M3 gate

Test against `tailnet` from `Tools/interop` (testcontrol + DERP + Go tsnet peer, which echoes on TCP and UDP port 7). The Swift node opens no UDP socket, so all traffic goes through DERP:

1. The Swift node registers and becomes `running`. The Go peer's `peerStatus` shows the Swift node and a DERP (relay) path.
2. **UDP echo**. The echo of a Swift UDP packet sent to port 7 at the Go peer's address returns through `inboundPackets`. Test IPv4 and IPv6 separately.
3. **TCP**. The Go peer returns a SYN-ACK to Swift's SYN (port 7) and an RST on a port without a listener.
4. **ACL**. Inject a filter into the Swift node's map allowing only a specific UDP port. UDP from the Go peer to an open port on the Swift address appears in `inboundPackets`. UDP to a blocked port is absent. The same holds for TCP SYN. (Add a tool command for the Go peer to send packets to an arbitrary address and port.)
5. Replies to UDP first sent by Swift return even when the filter blocks everything.
6. Removing a peer from the map (injecting `PeersRemoved`) stops packets to that peer.
7. Echo still works after keeping the connection for more than 2 minutes (through WireGuard rekey and DERP KeepAlive).

The final gate (a real tailnet) takes place at the end of M4.

## Changes in M4

This section records the M4 changes while retaining the M3 description above. This section takes precedence where they differ. Path discovery itself is in [SwiftailMagicsock.md](SwiftailMagicsock.md) (the "magicsock contract" below).

The engine still emits only "a WireGuard datagram to send to this peer," and `Magicsock` chooses between UDP and DERP. The node holds the two value types as stored properties and passes their outputs to one another (magicsock contract Q1). This follows the same principle as the WireGuard device having no knowledge of addresses ([Why this structure? in `docs/contracts/SwiftailWireGuard.md`](SwiftailWireGuard.md#why-this-structure)).

### Engine (`SwiftailEngine`)

```swift
public struct EnginePeer: Sendable, Equatable {
    public var key: NodePublicKey
    public var allowedIPs: [IPPrefix]
    public var homeDERP: Int64
    /// Added. The netmap's `DiscoKey`. Zero disables disco.
    public var discoKey: DiscoPublicKey
    /// Added. The netmap's `Endpoints` as provided (`Magicsock` filters them).
    public var endpoints: [IPEndpoint]
    public static func peers(in netmap: Netmap, at now: Date) -> [EnginePeer]   // Unchanged
}

public struct TailnetEngine: Sendable {
    public enum Output: Sendable, Equatable {
        /// A WireGuard message to send to a peer. The caller (`Magicsock`) chooses the path.
        case datagram([UInt8], to: NodePublicKey)
        case ipPacket([UInt8])
        case dropped(Drop)
        /// Added 2026-11-15. A WireGuard cookie reply to return to the source of the last `receive` datagram over the same path.
        /// The sending peer is unknown, so it bypasses peer path selection. Appears only in `receive` output.
        case cookieReply([UInt8])
        /// Added 2026-11-16. A disco key advertised by a peer through the tunnel (TSMP advertisement, nonzero key). Appears only in `receive` output.
        case discoKeyAdvertised(DiscoPublicKey, from: NodePublicKey)
    }
    public enum Drop: Sendable, Equatable {
        case inbound(PacketFilter.DropReason)
        case malformedPacket
        case unsupportedPacket
        case consumedControlPacket
        case noPeerForDestination
        case wireGuard(WireGuardError)
        // Removed noRouteToPeer (→ Magicsock.Drop.noRouteToPeer) and discoMessage (disco never reaches the engine)
    }
    /// Added 2026-11-15. The source of a received datagram. The node builds this opaque value from the path, and the engine only passes it to the device.
    public typealias Source = WireGuardDevice.Source

    /// Creates the engine with its disco public key to advertise when a peer session is established. `discoKey` was added 2026-11-16 and is required
    /// because a default would silently disable advertisement when omitted. Pass a zero key to disable advertisement.
    public init(nodeKey: Curve25519.KeyAgreement.PrivateKey, discoKey: DiscoPublicKey, now: ContinuousClock.Instant, wallClock: Date)
    /// Applies a netmap. Removes the `homeDERP` argument because the engine does not know the region.
    public mutating func apply(_ netmap: Netmap, at now: ContinuousClock.Instant, wallClock: Date) -> [Output]
    public mutating func send(_ ipPacket: [UInt8], at now: ContinuousClock.Instant) -> [Output]   // Unchanged
    /// Receives one datagram emitted as `.wireGuard` by `Magicsock`. Removes the sender key argument (UDP has none. WireGuard determines the peer).
    /// `source` was added 2026-11-15. It is used only to bind cookies and track usage for per-source rate limiting when WireGuard is under load.
    public mutating func receive(_ datagram: [UInt8], from source: Source, at now: ContinuousClock.Instant) -> [Output]
    public mutating func advance(to now: ContinuousClock.Instant) -> [Output]   // Unchanged
    public var nextDeadline: ContinuousClock.Instant? { get }                 // Unchanged
}
```

Behavior changes (numbers refer to "Behavior" above):

- **M-E1 (behavior 4, sending)**. Remove "if the peer's `homeDERP` differs from our home region, `noRouteToPeer`." Any peer installed in the data plane can be the destination of a `.datagram(_, to:)` output. `Magicsock` drops the datagram with `noRouteToPeer` if it has no path to that peer. The same applies to handshake responses, retries, and keepalive (`route` does not attach a region).
- **M-E2 (behavior 5, receiving)**. Remove disco detection. The engine receives only packets that `Magicsock` classified as WireGuard (magicsock contract behavior A). The sender key from the DERP frame was already unused in M3, so remove the argument. The rest stays the same (WireGuard → AllowedIPs source check → TSMP consumption → filter).
- **M-E3 (behavior 2, peer computation)**. Copy `discoKey` and `endpoints` into `EnginePeer` as provided. The inclusion criteria stay the same (include a peer with a zero disco key if it has a home DERP. That peer uses only DERP).
- **M-E4 (TSMP)**. Consume it without passing it up. Starting 2026-11-16, emit disco key advertisements (`disco-magicsock.md` §3.8) as `.discoKeyAdvertised(key, from: peer)` (the node passes them to `Magicsock.receiveDiscoKeyAdvertisement`). If the `init` `discoKey` is nonzero, set the advertisement as each peer's WireGuard priority message so it is sent when the session is established (magicsock contract section [TSMP Disco Key Advertisement](SwiftailMagicsock.md#tsmp-disco-key-advertisement-2026-11-16)).
- Tests. Only the output shape changes in the tests connecting two engines. The "peer in another home region" test now checks that a datagram is emitted. Move the disco message test from the engine to `MagicsockTests`.

### Node (`Swiftail`)

```swift
public enum NodeEvent: Sendable {
    case loginRequired(URL)
    case running(addresses: [IPAddress])
    case reconnecting
    /// Added. A peer's path changed. nil means the peer was removed from the data plane.
    /// - Parameter fqdn: The node name from the netmap with its trailing dot removed (`rd-mac-1a2b3c4d.tail0001.ts.net`).
    case peerPathChanged(fqdn: String, path: PeerPath?)
}

public enum NodeError: Error, Sendable {
    case control(ControlError)
    case invalidConfiguration(String)
    /// Added. The UDP socket could not be opened or bound. The message contains only the errno name.
    case udpUnavailable(String)
}

extension TailnetNode {
    /// Returns the current path of the peer named `fqdn`, or nil if absent from the data plane. This API is new.
    ///
    /// Comparison strips one trailing dot and ignores ASCII case. When two names match, the lower node ID wins.
    /// The path has the same meaning as the direct address (`CurAddr`) in Go's `tailscale status` (`PeerPath`).
    public func path(toPeerNamed fqdn: String) -> PeerPath?

    /// For tests only (outside the public API). Drops outbound and inbound traffic for these remote UDP ports at the socket boundary.
    package func setBlockedUDPPorts(_ ports: Set<UInt16>)
}
```

`PeerPath` is a public type in `SwiftailMagicsock` (as `IPAddress` is in `SwiftailBase`). Starting 2026-11-18, `Swiftail` exposes both under same-name aliases ([Types from other modules in the public API in `docs/contracts/SwiftailTunnel.md`](SwiftailTunnel.md#types-from-other-modules-in-the-public-api-2026-11-18)).

Behavior changes:

- **N1 (startup)**. When `run()` starts, open `DatagramSocket(port: 0)` (throw `udpUnavailable` on failure), and read `LocalInterfaceAddresses.current()` once (continue with an empty list on failure and publish only STUN endpoints). Generate a disco private key and **retain it on the node** (M3 retained only the public key). Its public key is `LocalStatus.discoKey`. Close the socket when `run()` ends.
- **N2 (after registration)**. When the node key is available, create `Magicsock(discoKey:nodeKey:localPort:localAddresses:loopbackAddresses:now:)` alongside the engine. If the node key changes, recreate both (keep the disco key and socket). Then reapply the peers and regions from the last netmap.
- **N3 (DERP regions)**. Replace M3 behavior 3's "fixed home DERP choice, one client."
  - Home candidate `Magicsock.Region`. Include DERPMap regions meeting the M3 home criteria (`noMeasureNoHome` is false and a node can be converted to `DERPServer`). Build `stunServers` by examining the region's nodes in order, including `stunOnly` nodes, using magicsock contract E3 rules (`stunTestIP` → IPv4 literal, `stunPort` 0 means 3478, skip negative values). The `score` is `homeParams.regionScore[id]` (0 if absent). Call `setRegions` whenever DERPMap changes. Keep this conversion in an I/O-free function and test it in `SwiftailTests`.
  - Connections. Maintain a region ID → `DERPClient` table. Open the home region (received via `.homeRegionChanged`) with `isPreferred: true`. Open a region with `isPreferred: false` when `Magicsock` first targets it in `.derp(_, to:, region:)` (any region in DERPMap, including `noMeasureNoHome`. Drop the datagram if the region cannot be converted to servers). Keep the previous home connection open when home changes (magicsock contract E6). Close connections for regions removed from DERPMap. Also close connections whose server lists (converted to `DERPServer`) change, and immediately reopen a home connection with the new servers (Go `derp.go`'s `derp-region-redefined`. A `DERPClient` server list is fixed on creation). Reopen all connections when the node key changes. In that case first clear the old `Magicsock` peers to withdraw previously reported paths using nil (M4 review B, 2026-11-15).
  - `shortcut:` Skip cleanup of non-home connections after 60 seconds of inactivity (DERP notes §4.9 item 5). The number of open connections is bounded by the number of DERPMap regions. M5 memory measurements will determine when this cleanup is needed. When home changes, do not resend NotePreferred on already-open connections (used for server statistics, DERP notes §4.8 item 3).
  - `reconnecting` reports only loss of the home region connection. Continue ignoring `peerGone` (reverse routes are unused).
  - Pass each connection's `.packet` to `magicsock.receiveDERP(_, from:, region: the connection's region)`.
  - `DERPHome.choose` is unused (`Magicsock` chooses home). Keep using `DERPServer.init(_: DERPNode)`.
- **N4 (publishing to the control server)**. `.endpointsChanged(eps)` → `localStatus.endpoints = eps.map(\.address)`, with `endpointTypes` in the same order, `.local`→`EndpointType.local`, `.stun`→`EndpointType.stun`. `.homeRegionChanged(id)` → `localStatus.netInfo = NetInfo(preferredDERP: id)`. When either changes, call `control.setLocalStatus(localStatus)`. `ControlClient` sends `DiscoKey` and all endpoints together on each status update, matching testcontrol's wholesale replacement of node values (`disco-magicsock.md` §4.9 item 4). This replaces M3's publication of the home region on each netmap.
- **N5 (packet flow)**:
  - Sending. `send(ipPacket)` → `engine.send` → `.datagram(b, to: k)` → `magicsock.send(b, to: k)`.
  - Receiving UDP. `(bytes, source)` from the socket stream → `magicsock.receiveUDP`.
  - `Magicsock` output. `.udp` → `socket.send` (discard failures. `shortcut:` rebinding on send errors is M5, see exclusions table in magicsock contract), `.derp` → that region's connection (N3), `.wireGuard(b, from: path)` → `engine.receive(b, from: path source)` → engine output reenters this flow, `.endpointsChanged` and `.homeRegionChanged` → N4, `.pathChanged` → N6, discard `.dropped`.
  - Cookie reply (2026-11-15). Send a `.cookieReply(b)` emitted by `engine.receive` back over the incoming path without calling `magicsock.send`. For UDP input feed `.udp(b, to: source)` into the flow above. For DERP input feed `.derp(b, to: sender, region: incoming region)` into it (the N8 filter still applies). The source passed to the engine is `address` (what the cookie binds to) and `host` (the rate limit unit). For UDP, as with Go's standard bind, `address` = address ‖ port (LE), `host` = address. For DERP, as in Tailscale magicsock, use one value per peer and omit the region. Both values are the 32-byte node public key (Go binds to the per-peer fake address `fakeWGAddr` and limits by the peer's tailnet address `nodeAddr`, `wgengine/magicsock/endpoint.go` `DstToBytes` and `DstIP`). The lengths differ, so they do not collide with UDP values.
  - Netmap. After `engine.apply`, call `magicsock.setPeers(EnginePeer.peers(in: netmap, at: Date()).map { Magicsock.Peer(key: $0.key, discoKey: $0.discoKey, homeDERP: $0.homeDERP, endpoints: $0.endpoints) })`. Order is ascending node ID (disco key ownership, magicsock contract B1). After `engine.apply`, retain the engine's address owner table and compare it with the owners tracked by the stack (host contract behavior W6, netstack contract behavior X10). `shortcut:` Peers that the engine removes in `advance` due to key expiration stay in `Magicsock` until the next netmap. The engine emits no datagrams to those peers, so heartbeat stops after 45 seconds, and the device drops incoming WireGuard. Reconcile the owner table and the stack's owners immediately at expiration (see timers below).
  - Timers. Wake at `min(engine.nextDeadline, magicsock.nextDeadline)` and call `advance` on both. If the engine's `advance` handled key expiration (`recomputesPeers(at:)`), immediately retain the new owner table and close connections to addresses whose owner changed (the same path as applying a netmap).
- **N6 (path events and lookup)**. For each netmap the node builds a data plane peer key → name table (the name is `Node.name` with one trailing dot removed). `.pathChanged(k, p)` emits `peerPathChanged` using the name from that table. For a removed peer use its name from before the table changed. Emit no event for peers with empty names. `path(toPeerNamed:)` maps name → key (N6 comparison rules) → `magicsock.path(to:at: .now)`. The name belongs to the exact node installed by the engine (`EnginePeer.name`. If multiple nodes claim a key, looking it up again in the netmap can attach a different node's name).
  - Report paths **only when actually known** (first adopter review, 2026-11-15). If nothing has been exchanged with a peer in the last 45 seconds (Go's idle criterion, which `Magicsock` determines using the last WireGuard send per peer), `path(toPeerNamed:)` returns nil. Emit `peerPathChanged` when the path goes idle (nil) and when traffic resumes (the path at that time). Reporting an idle peer as `.relayed` would label a connection "relayed" even though it will connect directly when traffic starts. Apply this nil rule in `Magicsock.path(to:at:)` and emit the same value in path events (`pathChanged`), including the deadline at which the peer becomes idle in `nextDeadline`.
- **N7 (structured concurrency)**. The TaskGroup children in `run()` change.

  ```
  run()
   └ TaskGroup
      ├ control.run()
      ├ follow(control)
      ├ forwardLoginRequests
      ├ uploadLocalStatus()  Publishes endpoints and home region to the control server. Receives them through a channel because output handling has no await
      ├ receiveUDP()     Socket datagram → magicsock.receiveUDP. Ends when the socket closes
      ├ maintainDERP()   Group of DERPClient instances by region (home + regions targeted by Magicsock). Each region uses the same structure as M3's serve
      └ runTimer()       Earlier deadline of the engine and Magicsock
  ```

  Keep the engine and `Magicsock` as actor stored properties and mutate them only in place. Pass outputs between them without `await` in a single actor execution so reentrancy cannot put their states out of sync.
- **N8 (UDP filter for tests)**. Check the `setBlockedUDPPorts` set only in `receiveUDP()` (immediately after receiving) and on `.udp` output (just before sending). `Magicsock` and the engine have no knowledge of the set. It defaults to empty.
- **N9 (secrets)**. Keep the disco private key out of events, errors, `description`, and `dump`. `customMirror` still exposes only the hostname.

Tests (`Tests/SwiftailTests`, no sockets) cover N3 region conversion (`noMeasureNoHome`, regions with only unusable servers, `stunTestIP`, zero or negative `stunPort`, `stunOnly`, and `regionScore`) and N6 name comparison (trailing dot, case, and two identical names). The magicsock contract's [M4 Gate](SwiftailMagicsock.md#m4-gate) covers the full node flow.

The only public API additions are `NodeEvent.peerPathChanged`, `NodeError.udpUnavailable`, `TailnetNode.path(toPeerNamed:)`, and `PeerPath` (`SwiftailMagicsock`). M5 defines `setDefaultInterface` from `docs/plan.md` §6.
