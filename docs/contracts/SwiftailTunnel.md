# Swiftail tunnel contract (M5, draft)

M5's goal is an **iOS packet tunnel node**. The node exchanges IP packets through the utun file descriptor located by the app's Network Extension (packet tunnel provider), derives address, route, and DNS settings for the OS, answers MagicDNS queries sent to the service IPs (`100.100.100.100`, `fd7a:115c:a1e0::53`), starts as the same node after a restart, and recovers after Wi-Fi ↔ cellular transitions (M5 in `docs/plan.md` §7). The first adopter is the iPhone packet tunnel extension. The goal is to replace its current Go core (`rd_start`, `rd_next_event`, `rd_status`, `rd_tunnel_*`, and `rd_stop`) with this contract's `TailnetNode`. The library has no dependency on the NetworkExtension framework. Applying `NEPacketTunnelNetworkSettings`, locating utun, and using `NWPathMonitor` are the app's responsibility.

This document is a **draft**. Send "First adopter confirmation needed" to the first adopter for review against its call sites before finalizing the contract.

Protocol details follow the notes below (all verified). This document only defines module boundaries, M5 scope, public APIs, tests, and gates.

- [dns-state-node.md](../protocol-notes/dns-state-node.md) ("DNS notes" below) covers DNS derivation in §4.1.4, the responder in §3.1 and §4.2, service IPs in §4.3, state persistence in §4.4, the state machine in §4.5, network transitions in §4.6, and the decision table in §6.4.
- [netmap-engine.md](../protocol-notes/netmap-engine.md) ("engine notes" below) covers address and OS route derivation in §4.8.
- [disco-magicsock.md](../protocol-notes/disco-magicsock.md) ("magicsock notes" below) covers rebinding in §4.11.

This document supplements the existing, unchanged contracts in [SwiftailEngine.md](SwiftailEngine.md) (M3, including "Changes in M4") and [SwiftailMagicsock.md](SwiftailMagicsock.md) (M4) with the M5 changes. This contract takes precedence in a conflict. The starting point is the completion of M4 unit 4 (`Magicsock` integration).

## Targets

| Target | Additions in M5 | Rationale |
| --- | --- | --- |
| `SwiftailEngine` | DNS message codec, MagicDNS responder, service IP reply packet generation, tunnel settings derivation (`TunnelNetworkSettings`), and local handling in `TailnetEngine.send` (service IPs and the node's own addresses). All are value types without I/O | The module table in plan §5 assigns "netmap → routes and DNS, MagicDNS responder, TUN" to the engine. It can be tested without sockets or clocks |
| `SwiftailIO` (package) | `UTUNDevice` (validation, duplication, reads, and writes for the utun file descriptor), binding sockets to interfaces (`IP_BOUND_IF` in `DatagramSocket` and `requiredInterface` in `NetworkSocket`) | Confines POSIX calls to one edge (code standards in plan §5) |
| `SwiftailControl` | `ControlClient.setNetworkInterface(_:)` (disconnect and reconnect on the new interface) and a lower map frame limit | Control connection rebinding (DNS notes §4.6.3 item 4) and memory |
| `SwiftailDERP` | `DERPClient` accepts an interface, and the receive packet buffer has a byte limit | DERP connection rebinding (DNS notes §4.6.3 item 2) and memory |
| `SwiftailMagicsock` | `Magicsock.rebind(localPort:localAddresses:loopbackAddresses:at:)` | magicsock notes §4.11 item 2 |
| `Swiftail` | Public API with `TunnelDevice`, `NodeState`, `NodeStatus`, and the M5 form of `TailnetNode`, plus the state machine, utun read loop, and rejection of duplicate state directories | The public API stays in `Swiftail` alone (existing architecture) |

No new target is created. Dependency direction does not change. `Swiftail` uses the Network framework's `NWInterface` in the public API (the framework allowed by plan §4(c)).

`TunnelNetworkSettings` is a public type in `SwiftailEngine`, just as `PeerPath` belongs to `SwiftailMagicsock`. The app uses `import Swiftail`, `import SwiftailEngine` (for the settings type), and `import SwiftailBase` (for `IPAddress` and `IPPrefix`).

## Scope supported in M5

M5 supports one utun, IPv4 and IPv6 tailnet addresses, per-peer routes (iOS rules), MagicDNS queries over UDP (tailnet names, reverse zones, and `ExtraRecords`), ICMP echo for service IPs, and default interface transitions reported through `setDefaultInterface`.

Unsupported features fail closed. See "Exclusions" below for the rationale and when each would become necessary. Subnet routes and exit nodes remain unsupported, as in M3.

## Public API (`Swiftail`, complete as of M5)

```swift
import Network
import SwiftailBase
import SwiftailEngine
import SwiftailMagicsock

/// Settings required to start a `TailnetNode`. (Changed in M3: `defaultControlURL`)
public struct NodeConfiguration: Sendable {
    /// Tailscale control server (`https://controlplane.tailscale.com`, Go `ipn.DefaultControlURL`).
    public static let defaultControlURL: URL
    /// Directory for the identity file (`identity.json`). Must be a file URL. Two nodes cannot use the same directory simultaneously.
    public var stateDirectory: URL
    public var hostname: String
    public var controlURL: URL
    /// Used during first registration and when registering a new node key (not sent when reconnecting with a stored key). Not stored.
    public var authKey: String?
    public var ephemeral: Bool
    public init(stateDirectory: URL, hostname: String, controlURL: URL = Self.defaultControlURL,
                authKey: String? = nil, ephemeral: Bool = false)
}

/// A device that sends and receives IP packets.
public enum TunnelDevice: Sendable {
    /// A utun control socket created by Network Extension. The node uses a duplicate of the descriptor and leaves the original open and unread.
    ///
    /// - Parameter mtu: The value the app applies through `NEPacketTunnelNetworkSettings.mtu`. 1280…1420. The node leaves the utun MTU
    ///   unchanged and returns this value as `TunnelNetworkSettings.mtu`.
    case utun(fileDescriptor: Int32, mtu: Int = 1280)
    /// An in-memory device. Inject packets through `TailnetNode.send(_:)` and receive them through `inboundPackets`. It is for tests and gates and follows the same processing as utun.
    case memory(mtu: Int = 1280)
    /// (M6) An in-process TCP stack. `TailnetNode.listen(port:)` and `connect(to:port:)` are available only with this device. The MTU is fixed at 1280.
    case inProcess
}

/// State of the node. Only what the app uses from Go `ipn.State` remains (DNS notes §4.5).
public enum NodeState: Sendable, Equatable {
    /// The node is waiting for registration, a netmap, and its first connection.
    case starting
    /// The user must sign in at this URL. The control server always supplies a URL when the node starts registration.
    case needsLogin(URL)
    /// The tailnet administrator must authorize this device (netmap's `MachineAuthorized` for the node is false).
    case needsMachineAuth
    /// The node has received a netmap and has established a home DERP connection or completed a WireGuard handshake with a peer at least once.
    case running
}

/// Changes the node reports through `TailnetNode.events`. (Changed in M4: T1 under "Lead session confirmation needed" below)
public enum NodeEvent: Sendable, Equatable {
    /// State has changed. The same state is not issued again.
    case stateChanged(NodeState)
    /// A peer's path changed. A nil path means the peer left the data plane or is idle (as in M4).
    case peerPathChanged(fqdn: String, path: PeerPath?)
    /// (M8) The tailnet lock status changed. See decision L4 in `docs/contracts/SwiftailTailnetLock.md`.
    case tailnetLockChanged(TailnetLockStatus)
    /// Added 2026-11-18. The `status` value changed. The event carries no value (T1). See "Status change event" below.
    case statusChanged
}

/// The node's current status, read by the app's status screen and diagnostics.
public struct NodeStatus: Sendable, Equatable {
    public var state: NodeState
    /// The node's own tailnet addresses (`Addresses` on the local netmap node). Empty before a netmap arrives.
    public var addresses: [IPAddress]
    /// Own MagicDNS name with the trailing dot removed (`rd-phone-1a2b3c4d.tail0001.ts.net`). nil before netmap.
    public var fqdn: String?
    /// Own node's `StableID`. The first adopter's pairing is bound to this value. nil before netmap.
    public var stableID: String?
    /// Names eligible for ts.net certificates (`DNSConfig.CertDomains` in the netmap). M5 only reads and displays them.
    public var certDomains: [String]
    /// Number of peers in netmap.
    public var peerCount: Int
    /// The last settings emitted to `networkSettings`. Nil until the first emission.
    public var networkSettings: TunnelNetworkSettings?
}

public enum NodeError: Error, Sendable {
    case control(ControlError)
    /// Invalid state directory, control server URL, hostname, utun descriptor, or MTU. Calling `run()` twice also produces this error.
    /// The message identifies the invalid setting and omits paths, descriptor numbers, and keys. An MTU diagnostic may include the supported range.
    case invalidConfiguration(String)
    /// Failed to open or bind UDP socket (M4).
    case udpUnavailable(String)
    /// Newly added. Another node of the same process is running in this state directory.
    case stateDirectoryInUse
    /// Added. The tunnel device can no longer be read because a utun read failed or reached EOF. The message carries only the errno name or `EOF` at end of file.
    case tunnelDeviceClosed(String)
}

public actor TailnetNode {
    /// Inspects configuration and device. Does not create files, sockets, or Tasks (utun inspection is a read-only system call).
    public init(configuration: NodeConfiguration, device: TunnelDevice = .memory()) throws(NodeError)

    /// Events for state, path, lock, and status changes. There is one subscriber. The stream ends when `run()` ends.
    /// Keeps the newest 64 unread events. Only one `statusChanged` remains at the end, outside this limit.
    public nonisolated var events: AsyncStream<NodeEvent> { get }

    /// Returns whether `stateDirectory` contains a registered identity (an `identity.json` file with a node key). Added 2026-11-18. See behavior P 5 below.
    public static func hasSavedIdentity(in stateDirectory: URL) throws(NodeError) -> Bool

    /// Tunnel configuration for the app to apply to the OS. Only appears if changed, and only the **most recent one** remains unread.
    /// There is one subscriber. The stream ends when `run()` finishes.
    public nonisolated var networkSettings: AsyncStream<TunnelNetworkSettings> { get }

    /// For the memory device, IP packets sent by peers that passed the filter and responses the node generates locally (such as MagicDNS).
    /// When it is a utun device, the stream emits nothing (packets go to utun). Otherwise, it is the same as M3.
    public nonisolated var inboundPackets: AsyncStream<[UInt8]> { get }

    /// Registers the node and maintains the data plane. Keeps running until the calling Task is canceled. Call only once per node.
    /// Throws only for failures that cannot be resolved by retrying (terminal control failure, device closure, or a state directory already in use).
    public func run() async throws(NodeError)

    /// Injects one IP packet into the memory device, with the same processing as a utun read. Discards it for a utun device.
    public func send(_ ipPacket: [UInt8])

    /// The current status.
    public var status: NodeStatus { get }

    /// Requests a new interactive login URL. The URL comes via `.stateChanged(.needsLogin(url))`.
    public func startInteractiveLogin()

    /// Sets the interface that carries the device's default route (from the app's `NWPathMonitor`). The node binds its control, DERP, and UDP sockets
    /// to this interface and rebinds on a change. Call on every satisfied path if desired (the same interface and addresses trigger only another STUN run).
    public func setDefaultInterface(_ interface: NWInterface)

    /// The current path to the peer named `fqdn`, as in M4.
    public func path(toPeerNamed fqdn: String) -> PeerPath?
}
```

Public type in `SwiftailEngine`

```swift
/// Values the app translates to `NEPacketTunnelNetworkSettings` and applies. The library has no NetworkExtension dependency.
/// List order is deterministic. The same netmap produces the same values.
public struct TunnelNetworkSettings: Sendable, Equatable {
    /// The node's own addresses, /32 for IPv4 and /128 for IPv6. Always nonempty.
    public var addresses: [IPPrefix]
    /// Routes to send through the tunnel. Sorted peer routes precede service IP routes. A family has routes only if the node has an address in that family.
    public var routes: [IPPrefix]
    /// DNS servers. An empty list disables DNS configuration. If present, the IPv4 service IP comes first.
    public var dnsServers: [IPAddress]
    /// Lowercase names without trailing dots. This list is nonempty whenever `dnsServers` is nonempty.
    public var dnsMatchDomains: [String]
    public var mtu: Int

    /// Derives settings from the netmap (behavior S below). Returns nil if the node has no addresses.
    /// - Parameter now: The time used to determine key expiration for peers and the local node (the same clock as behavior 2 of the M3 engine contract).
    public init?(netmap: Netmap, mtu: Int, at now: Date)
}
```

Differences from the draft in `docs/plan.md` §6 and their rationale

- `run()` + Task cancellation instead of `start()`/`stop()` (same as M3). Stopping is `runTask.cancel()` followed by `await runTask.value`.
  - A `do`-`catch` inside `Task { }` infers `any Error` as its error type. Use `do throws(NodeError)` to branch on `NodeError` cases (verified by the first adopter while making the build variant, 2026-11-15).

    ```swift
    let runTask = Task {
        do throws(NodeError) {
            try await node.run()        // Returning from cancellation is a normal termination
        } catch {
            switch error {              // error: NodeError
            case .control(let failure): …
            case .tunnelDeviceClosed, .stateDirectoryInUse, .udpUnavailable, .invalidConfiguration: …
            }
        }
    }
    ```
- `NodeState` has no `stopped` or `failed` case. A return from `run()` signals a stop, and a `NodeError` thrown by `run()` signals a failure. The result of `run()` reports both outcomes outside the event stream.
- A separate `networkSettings` stream takes the place of `NodeEvent.networkSettings` (lead session confirmation needed T2).
- Using `IPPrefix` and `IPAddress` instead of strings lets `TunnelNetworkSettings` pass validated values. The app obtains the CIDR string via `description`.
- `setDefaultInterface` takes an `NWInterface` in place of a name (lead session confirmation needed T3).
- `init` throws (lead session confirmation needed T4).
- `TunnelDevice.inProcess` (M6, behavior N 1 in `docs/contracts/SwiftailNetstack.md`) uses neither utun nor the memory stream. The stack receives packets the engine emits for the device (including packets looped back in behavior L). Packets the stack emits go through the engine's send path. `inboundPackets` emits nothing and `send(_:)` discards packets with this device. `networkSettings` emits as with other devices (the app may leave it unread). The MTU is fixed at 1280 and takes no argument.

### Status change event (2026-11-18)

The sample app (`Examples/PairingDemo`) no longer needs to poll `status` to learn that the peer count or the node's own name changed.

- `statusChanged` is emitted only when `status` (state, addresses, FQDN, `StableID`, certificate names, peer count, tunnel settings, and tailnet lock) differs from the last reported value. An identical netmap does not trigger it. The app reads `status` once at startup because the node omits the initial status (`.starting`, no netmap).
- **Overlap** occurs when state and lock change. `statusChanged` follows `stateChanged` and `tailnetLockChanged`. The first two events report the transition itself with its value (login URL or signing instructions). `statusChanged` carries no value and only means "read the status again for display." This satisfies T1's rule against reporting the same fact through two channels by carrying the value in just one event. Apps that only update a screen can use `statusChanged` alone. Settings emitted by `networkSettings` are also in `status.networkSettings`, so a settings change also emits `statusChanged`.
- **Order**: In one update (one netmap, one state transition) `tailnetLockChanged` → `peerPathChanged` → `stateChanged` → `statusChanged`. Regardless of which event is received, `status` already contains that update.
- **Buffer**: Only one unread `statusChanged` remains. If a new one occurs, the previous one is deleted and the new one is placed at the end. Thus, it does not count toward the 64-item limit and does not displace other events, and if the `status` changed after the app read any event, there is definitely one following it. Since the `AsyncStream` buffer cannot selectively delete types, the node holds the buffer (`NodeEventQueue`) and provides it via `AsyncStream(unfolding:)` (similar to `DERPClient.EventQueue`).
- **Subscription**: If the consuming Task is canceled, the `events` stream ends and cannot be subscribed to again. Subscribe once in one place in the app.
- Source Compatibility: Since the number of cases in `NodeEvent` has increased, code that lists all cases with `switch` must add `.statusChanged`.

### Types from other modules in the public API (2026-11-18)

`import Swiftail` alone makes the public API's type names available. The table lists types from other modules that occur in `Swiftail` public declarations (collected from type identifiers whose USRs in the symbol graph belong to other modules), and in those types' public properties and associated values.

| Type | Original Module | Position in `Swiftail` |
| --- | --- | --- |
| `IPAddress` | `SwiftailBase` | `NodeStatus.addresses`, `NodeStatus.init`, `TailnetNode.whoIs(_:)`, `TunnelNetworkSettings.dnsServers`, `IPEndpoint.address` |
| `IPEndpoint` | `SwiftailBase` | `TailnetConnection.localEndpoint`·`remoteEndpoint`, `PeerPath.direct(_:)` |
| `IPPrefix` | `SwiftailBase` | `TunnelNetworkSettings.addresses`·`routes` |
| `ControlError` | `SwiftailControl` | `NodeError.control(_:)` |
| `TailnetLockStatus` (includes nested `Mode`·`Issue`·`SigningRequest`) | `SwiftailControl` | `NodeStatus.tailnetLock`, `NodeStatus.init`, `NodeEvent.tailnetLockChanged(_:)` |
| `TunnelNetworkSettings` | `SwiftailEngine` | `TailnetNode.networkSettings`, `NodeStatus.networkSettings`, `NodeStatus.init` |
| `PeerPath` | `SwiftailMagicsock` | `NodeEvent.peerPathChanged(fqdn:path:)`, `TailnetNode.path(toPeerNamed:)`·`path(toPeerWithStableID:)` |

Items not exported: `Netmap` of `TunnelNetworkSettings.init?(netmap:mtu:at:)` (the app receives settings from the node).

`Swiftail` exposes only these names through `public typealias` (`Sources/Swiftail/ReexportedTypes.swift`). `@_exported import` is an unofficial underscored feature that adds the whole module (tailcfg models, key types, and the control client) to `Swiftail`'s surface. Swift 6 `public import` (SE-0409) does not reexport names. An alias denotes the same type, so values pass unchanged to and from code that also imports the original module.

Files that import **both** `Swiftail` and the original module (such as `SwiftailBase`) see two declarations for each name (the alias and original type). Type positions (`let a: IPAddress`, `[IPAddress: Node]`, `extension IPAddress`) and calls (`IPAddress("…")`) still work, but syntactic sugar for types in expressions and key paths with explicit roots are ambiguous and fail to compile (verified with `swiftc -typecheck` in the 2026-11-18 review). The affected forms are `[IPAddress]()` and `[IPAddress].self`, `[IPAddress: Int]()`, `IPAddress?.self` and `IPAddress?.none`, `(IPAddress, Int).self` and `(IPAddress).self` (the form generated by swift-testing `@Test(arguments:)`), `IPAddress.Type.self`, an array of a nested type through an alias (`[TailnetLockStatus.Mode]()`), and `\IPEndpoint.address`. The following still work: `Array<IPAddress>()`, `Set<…>`, `extension`, pattern matching, `as?`, `MemoryLayout<IPAddress>`, and `TailnetLockStatus.Mode.enforcing`. Remove the now-unnecessary `import` of the original module or qualify the name with its module (`SwiftailBase.IPAddress`). In this repository, one parameter in `Tests/SwiftailTests/NodeTailnetLockTests.swift` needed a module qualifier.

## Behaviors

Tests and reviews refer to behaviors by number.

### U. utun device (`SwiftailIO.UTUNDevice`, node read loop)

1. **Validation (`init`)**. The descriptor must be 0 or greater, `getpeername` must return address family `AF_SYSTEM` (32), and the name from `getsockopt(SYSPROTO_CONTROL=2, UTUN_OPT_IFNAME=2)` must begin with `utun`. Otherwise the result is `invalidConfiguration`. An MTU outside 1280…1420 also produces `invalidConfiguration`. Validation uses read-only calls and has no side effects. The basis is the first adopter's Go `CheckUTUN` (`core/internal/tunnel/utun_darwin.go`) and `Name()` in wireguard-go `tun/tun_darwin.go:199-214`. The MTU range comes from the first adopter's test contract (`docs/tunnel.md`, "Settings") and the wireguard-go default of 1420 (`device/tun.go:13`).
2. **Duplication (start of `run()`)**. Duplicate the descriptor with `fcntl(F_DUPFD_CLOEXEC)` and set `O_NONBLOCK` on the duplicate. `O_NONBLOCK` also applies to the original descriptor because it shares the same open file description. The app does not read or write with the original descriptor, so this is safe (as in "Settings" in the first adopter's `docs/tunnel.md`). The node closes **only the duplicate** when `run()` ends. It never closes the original descriptor.
3. **Protocol header**. utun places 4 bytes in front of every packet. On read, discard reads shorter than 4 bytes and pass the remaining bytes through as an IP packet without inspecting the header. On write, use `00 00 00 02` (`AF_INET`) for IP version 4 or `00 00 00 1e` (`AF_INET6`) for version 6. Other versions are not written. The basis is wireguard-go `tun/tun_darwin.go:224-262` (`Read` discards `n < 4` and ignores the header, and `Write` uses `AF_INET`/`AF_INET6` based on the version), and the Darwin constants in `golang.org/x/sys@v0.49.0/unix/zerrors_darwin_arm64.go:27-28`.
4. **Reads**. A `DispatchSource` read event wakes the reader, which reads until `EAGAIN` without polling (as in M4 `DatagramSocket`). One `read` yields one packet. Reuse one buffer (4 + 65,535 bytes) and copy only the length read. Discard reads of 4 bytes or fewer and packets larger than the MTU. This is defensive because the OS does not put packets larger than the configured MTU into utun. Together with the 256-item read stream limit, this caps queued bytes at 256 × MTU. Applying a different MTU causes large packets to disappear, so the app applies `TunnelNetworkSettings.mtu` as given. Retry on `EINTR`. A 0-byte read (EOF) or any error other than `EAGAIN` or `EINTR` means the device closed. `run()` throws `tunnelDeviceClosed` with the errno name or `EOF` and ends. Go also closes the device on a TUN read error (wireguard-go `device/send.go:436-450`). The first adopter's "`Error` if the engine stops on its own, latched until `rd_stop`" corresponds to `run()` having ended.
5. **Writes**. Call `write` once for each packet from the node and return without waiting. On failure (`EAGAIN`, `ENOBUFS`, `EMSGSIZE`, and so on), discard that packet and continue. This follows IP semantics. Go likewise only records the TUN write error and continues (wireguard-go `device/receive.go:552-555`). There is no write queue.
6. Confine POSIX calls and address reinterpretation to `UTUNDevice.swift` and document the rationale in comments. Protect the descriptor with a `Mutex`.
7. **Memory device**. `send` takes the place of the read result in item 3, and `inboundPackets` takes the place of the write in item 5. The intervening processing is identical. The test-only `package func failMemoryDevice()` produces the same result as a read error in item 4 (`tunnelDeviceClosed("test")`).

### L. Local handling (`TailnetEngine.send`, packets read from the device)

The following steps precede M3 behavior 4 (send). Engine output remains `.datagram`, `.ipPacket`, and `.dropped`. Local replies are emitted as `.ipPacket` for writing to the device.

1. Parse the packet (M3 behavior 1). Failures are handled as in M3.
2. **Service IPs** (DNS notes §4.3). A destination of `100.100.100.100` or `fd7a:115c:a1e0::53` bypasses WireGuard.
   - UDP 53. Return the responder's answer (behavior D) over UDP with the source and destination addresses and ports swapped. The original design would emit nothing if behavior D returned no response. The implemented responder always returns response bytes (see the M5-1 decisions below). Compute UDP checksums for both IPv4 and IPv6 (required for IPv6, RFC 8200 §8.1).
   - ICMP echo request (v4 type 8, v6 type 128). Return an echo reply (v4 0, v6 129) with the addresses swapped and the identifier, sequence, and payload unchanged (Go `net/tstun/wrap.go:752-769`, decision D5).
   - TCP. Reply with RST (decision D4). If the incoming segment has ACK, use `seq = SEG.ACK` with RST alone. Otherwise use `seq = 0`, `ack = SEG.SEQ + SEG.LEN` (SYN and FIN each count as 1), and RST+ACK. Do not reply to an incoming RST (RFC 9293 §3.10.7.1).
   - Other packets (other UDP ports, other protocols, and other ICMP types) are discarded without a response, including ICMP unreachable (as in Go, DNS notes §4.3 item 3).
   - Reply TTL and hop limit are 64 (Go `net/packet/ip4.go:49`, `ip6.go:42`. The gVisor default in `pkg/tcpip/network/ipv4/ipv4.go:59` is also 64).
   - The new `Drop` case is `.serviceIPPacket` for packets dropped by branch 4.
3. **The node's own address**. When the destination is one of the node's own tailnet addresses, return the packet unchanged as `.ipPacket` and bypass filtering. Network Extension sends packets addressed to the tunnel address to the tunnel instead of looping them back in the kernel (Go `wgengine/userspace.go:652-667`, comments and behavior).
4. **TSMP**. Drop device-originated TSMP (IP protocol 99) as `.consumedControlPacket`. This resolves the M3 engine contract's `shortcut:` that left TSMP received from above undropped.
5. The remaining steps follow M3 and M4 (peer selection → flow recording → WireGuard).

Implementation decisions (M5-8a, 2026-11-15)

- Classification order is service IP (2) → TSMP (4) → own address (3). Go also drops TSMP before checking its own addresses. TSMP addressed to the node itself is not looped back. TSMP addressed to a service IP produces `.serviceIPPacket`.
- For UDP port 53, pass only the payload bytes covered by the UDP length field to the responder. A length field below 8 or longer than the IP packet produces `.serviceIPPacket`. Declining to reply to an incoming RST also produces `.serviceIPPacket`.
- Public signatures (`send(_:at:)`, `apply(_:at:wallClock:)`, `advance(to:)`) stay the same. The node handles every `.ipPacket` as a packet to write to the device. Local replies, looped-back packets, and packets sent by peers all use `.ipPacket`.

### S. Settings derivation (`TunnelNetworkSettings.init?(netmap:mtu:at:)`)

1. **Addresses**. Take single-address prefixes (IPv4 /32, IPv6 /128) from the local node's `Addresses` in netmap order. Return nil and emit no settings if there are none.
2. **Peer routes** (engine notes §4.8 table). Derive routes from the AllowedIPs of peers admitted to the data plane (`EnginePeer.peers(in:at:)`).
   - For IPv4 /32 prefixes within CGNAT (`100.64.0.0/10`), use individual routes for up to 10,000 unique prefixes and a single `100.64.0.0/10` route above that. If the local node's `CapMap` contains `one-cgnat?v=true`, the threshold is 1 (use /10 starting at two). With `one-cgnat?v=false` or neither entry, use the default iOS threshold of 10,000. The key strings are in Go `tailcfg/nodecap/nodecap.go:148`, `:153`. Go reads control directives from the local node's `CapMap` in `control/controlclient/map.go:197` and `control/controlknobs/controlknobs.go:155-198`.
   - For IPv6 /128 prefixes within the Tailscale ULA (`fd7a:115c:a1e0::/48`), use one `fd7a:115c:a1e0::/48` route if at least one exists.
   - Since M3, AllowedIPs retains only single-address prefixes in the Tailscale ranges that are the peer's own addresses (M3 engine contract behavior 2). No other prefixes are emitted.
   - Sort peer routes with IPv4 first, then by address bytes within each family, and by prefix length for equal addresses. The node's own addresses produce no routes.
3. **Service routes**. Append `100.100.100.100/32` for a local IPv4 address and `fd7a:115c:a1e0::53/128` for a local IPv6 address, in that order after peer routes (engine notes §4.8 item 2).
4. **Address family filtering**. Omit routes for any family without a local address (as in `buildSettings` in the first adopter's `core/internal/tunnel/settings.go`).
5. **DNS**. Follow DNS notes §4.1.4 items 1~5 exactly. In summary: expired local key → no DNS → `localZones` = (if `Proxied`, MagicDNS suffix + `0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.` + `64`~`127.100.in-addr.arpa.`) ∪ (`Routes` keys with empty resolver lists) ∪ (valid `ExtraRecords` names outside every zone) → no DNS if empty → `dnsServers` follows the local address families, with the IPv4 service IP first (IPv4 only if the local node's `CapMap` contains `force-register-magicdns-ipv4-only`) → `dnsMatchDomains` is `localZones` sorted as strings with trailing dots, then stripped of those dots. Ignore `Resolvers` and `Routes` with resolvers (decisions D1 and D2).
6. **MTU**. Use the device's MTU as given.
7. The same `localZones` and netmap configure the responder in behavior D (DNS notes §4.1.4 item 6). The engine updates the responder when it applies the netmap.

### E. Settings emission rules (`networkSettings` stream)

Follow the first adopter's rules exactly (`docs/tunnel.md`, "`network-settings` event", and DNS notes §8.2).

1. Derive settings using behavior S every time a netmap is applied. Emit nothing for nil (no local addresses).
2. Suppress a value equal to the previous emission (`==`, including list order). This prevents a settings application → utun link change → settings reapplication loop. Emit even if only DNS changes (servers or match domains).
3. The stream buffer is `.bufferingNewest(1)`. New settings replace unread settings.
4. Emit no empty settings when `NodeState` changes to `.needsLogin` or `.needsMachineAuth` (as in item 1. The first adopter also emits nothing without addresses). In the meantime, packets do not go out because the data plane has no netmap or does not admit expired peers.
5. Emit no settings when `run()` ends. `status.networkSettings` retains the last emitted value.

### D. MagicDNS responder (`SwiftailEngine`, internal)

Implement the minimum described in DNS notes §6.1 item 2 as written. Inputs are query bytes and the current time (for the SOA SERIAL). The design allowed response bytes or no response. The implementation always returns response bytes (see the M5-1 decisions below). The responder has no sockets or clock.

1. **Codec** (DNS notes §3.1). Read only the header and first question. Follow up to 10 pointers when reading names, and write responses without compression. Copy the query header into the response, then set QR=1 and AA=1, and set RA=1 if RD=1. Preserve query case in question and answer names, and compare in ASCII lowercase. TTL is 5 seconds for A, AAAA, and PTR, and 10 seconds for SOA.
2. **Classification** (DNS notes §3.1 RCODE table and §4.2.2 items 1~3 and 5). FORMERR (missing header or question, QR=1 / include the question for an invalid FQDN) → PTR follows reverse rules → `.onion` yields NXDOMAIN → A and AAAA for `magicdns.localhost-tailscale-daemon.` → `ExtraRecords` host table → node index (§4.2.1: local node and peer `Name`, short names with the MagicDNS suffix removed, and nodes with no addresses treated as unknown) → result by type (one A, AAAA, or ANY result, NOERROR + SOA if there is no address of that type, NOTIMP for NS, SOA, AXFR, and HINFO, and NOERROR with an empty answer otherwise) → NXDOMAIN + SOA for an unknown name inside `localZones`.
3. **Peer AAAA**. Follow the Go rule (decision D7). If the target has IPv4 and `magicdns-aaaa` is absent from both the local node's `capabilities` and its `CapMap` keys, omit IPv6 from the answer. If the local node is IPv6-only, use only the target's IPv6 (DNS notes §4.2.1 `magicDNSAddrs`).
4. **Reverse lookup** (DNS notes §4.2.2 item 5). Bonjour reverse names get NXDOMAIN (include the question, RA = RD, no AA). Read `in-addr.arpa` and `ip6.arpa` (32 nibbles) as addresses. For the 4to6 range, look up `100.x.y.z` first. Service IPs map to `magicdns.localhost-tailscale-daemon.`. If the lookup fails and the name is in `localZones`, return NXDOMAIN + SOA.
5. **Outside a zone**. With no local answer and a name outside `localZones`, return SERVFAIL (include the question, AA=1, RA from the query). Do not forward upstream (DNS notes §4.2.3, decision D2).
6. **UDP size** (DNS notes §4.2.4). Set only TC when the response exceeds the advertised size if the last 11 bytes of the query form a valid OPT, or 512 bytes otherwise. Do not truncate. Omit OPT from the response.
7. **Expired local key or no netmap**. The responder's `localZones` and index are empty. Queries with no local answer yield SERVFAIL (fail closed), subject to the FORMERR and NXDOMAIN rules above. The responder continues to answer for the service IP's fixed name (`magicdns.localhost-tailscale-daemon.`), as in Go. The engine includes local key expiration in `nextDeadline`, and `advance` clears the responder at that time without waiting for a new netmap. SOA SERIAL time comes from the engine's wall clock, anchored to `wallClock` in `apply`.
8. Omitted (DNS notes §6.1, "May be omitted") are 4via6 names, `dns-subdomain-resolve` subdomain rules, and all upstream forwarding.

### B. State machine (`Swiftail`, internal value type)

Map the correspondence table in DNS notes §4.5 to Swiftail's inputs. Inputs are control events (`loginRequired`, `registered`, `netmap`), establishment of the home DERP connection, and completion of an engine handshake with any peer. Output is `NodeState`. Emit `.stateChanged` only on change.

| # | Condition (top to bottom) | Result | Go table |
| --- | --- | --- | --- |
| 1 | Control emitted `loginRequired(url)` and no `registered` has arrived since | `.needsLogin(url)` | 2, 5 |
| 2 | No netmap | `.starting` | 3 |
| 3 | The local node is not `MachineAuthorized` | `.needsMachineAuth` | 6 |
| 4 | Previous state was `.running` | `.running` | 9 |
| 5 | The node has established a home DERP connection or completed a handshake with a peer at least once | `.running` | 8 (decision D9) |
| 6 | Otherwise | `.starting` | 7, 10 |

- `ControlClient` handles local key expiration (Go table item 5) by registering again with a new key (SwiftailControl contract unit 4). If interactive login is required, `loginRequired` arrives and the state follows item 1. If the new key is also rejected as expired, `ControlClient` ends with `nodeKeyExpired` and `run()` throws it.
- Receiving `registered` clears the URL from item 1 (same effect as Go clearing the URL on entering `Running`, DNS notes §4.5).
- The first adopter's "request login again every 30 seconds in `NeedsLogin` without a URL or auth key" (end of DNS notes §4.5) is unnecessary. On registration, Swiftail's `ControlClient` always emits `loginRequired` with the server-provided `AuthURL` (`Sources/SwiftailControl/Client/ControlClient+Registration.swift`, doc comment 3). `needsLogin` always has a URL, so the URL in `NodeState.needsLogin` is nonoptional.
- Go's `Stopped`, `NoState`, and `InUseOtherUser` are absent. Stopping is the end of `run()`.
- After `.running`, losing control or DERP connections leaves the node `.running` (as in Go table item 9). M3 and M4's `reconnecting` is removed (lead session confirmation needed T1).
- Implementation decisions (M5-8b, 2026-11-15). The initial `.starting` state produces no event (read it through `status`). For row 5, "a peer completed a handshake" is measured when the engine first emits a decrypted transport packet (`shortcut:` this can be one packet later than Go's `LastHandshake`. Use a direct handshake signal if `.running` is delayed on a tailnet that only uses direct paths without DERP).

### N. Network transitions (`setDefaultInterface`)

See DNS notes §4.6 and magicsock notes §4.11. Swiftail has no `AF_ROUTE` watcher, so the app's `setDefaultInterface` calls are the only source of notifications (decision D6).

1. **Ignored input**. Ignore an interface with the same name as this node's utun (read in behavior U1), just as Go `net/netns/netns_darwin.go:57-145` treats Tailscale utun as invalid. For calls before or after `run()`, retain only the last interface that was not ignored.
2. **Classification**. The node retains the last interface (name and `index`) and last read local IPv4 addresses (`LocalInterfaceAddresses.current()`). Read the addresses again on every call.
   - First interface, changed interface, or changed local addresses → **rebind** under item 3. This is Swiftail's version of Go `RebindLikelyRequired` (DNS notes §4.6.2). It does not check changes to available protocols, cost, or PAC.
   - Same → restart only the STUN round with `Magicsock.restartSTUN(at:)` (Go uses `ReSTUN` on every link change, DNS notes §4.6.3 item 1). If a round is in progress or there is no region, do nothing (`shortcut:` Go schedules another round after the current one).
3. **Rebinding** (Go engine order, DNS notes §4.6.3 item 1).
   1. Set the new interface as the node's "current interface." Use it for subsequently opened sockets, subject to the binding rules and fallback below.
   2. DERP. Close every open regional connection and reopen starting with the home region (create a new `DERPClient` with the new interface). `shortcut:` Go keeps connections whose local address belongs to the default interface and checks them with a 3-second Ping (DNS notes §4.6.3 item 2). Reopening all of them is simpler and costs only reconnection of non-home connections. Selective retention becomes necessary if reconnection delay is a problem in real device transitions.
   3. UDP. Close the socket and bind again to the same port. On failure, bind to port 0. If that also fails, use a socket without interface binding (the reported interface disappeared in the meantime. This is a recoverable failure, so keep `run()` going) and bind again on the next `setDefaultInterface` regardless of what it reports. `run()` throws `udpUnavailable` only when opening even an unbound socket fails (M5 review B, 2026-11-15). The same applies to opening the initial socket. If socket reads stop due to an error, the node opens a new socket using the same procedure. Then call `Magicsock.rebind(localPort:localAddresses:loopbackAddresses:at:)` to clear all peers' `bestAddr`, trust, and Ping records (magicsock notes §4.11 item 2) and start a STUN round immediately. Report changed endpoints to the control server as in M4 N4. The node sequence is open a new socket → `rebind` → process outputs in order → `advance` at `nextDeadline`. Because `close(2)` in `DatagramSocket.close()` happens later on a dispatch queue, a child of `run()` retries rebinding the same port up to 25 times at 20ms intervals before falling back to port 0. Discard outgoing UDP packets in the meantime. Reconnect control (3.4) after opening the new socket.
      - Cleared (as in Go `noteConnectivityChange`, `endpoint.go:1876`) are `bestAddr`, trust, latest Ping time per candidate, TxID of the received Ping, and Pong history. Candidates and their origins, send history, and heartbeat are retained.
      - Differences from Go. ① Also clear the sent Ping table (a Pong for a Ping sent on the old socket is no evidence for the new socket). ② Drop the STUN round in progress and start a new one (Go keeps it and schedules `ReSTUN`). Replies for the old round produce `.dropped(.unexpectedSTUN)`. ③ Clear the time at which endpoints were set, defer CallMeMaybe until the new round finishes, and send it with the new endpoints (Go sends it immediately with the old endpoints). ④ `shortcut:` Keep candidates learned through CallMeMaybe until the next CallMeMaybe removes them (Go marks them so the next netmap update can remove them).
   4. Control. `ControlClient.setNetworkInterface(_:)` closes the current connection and reconnects on the new interface without backoff (Go `tsdial` closes system connections whose default interface changed, DNS notes §4.6.3 item 4). Registration state and the most recent netmap are retained.
   5. Settings. Skip recomputation. The netmap did not change, so behavior E 2 would emit nothing.
4. **Socket binding** (DNS notes §4.6.4). UDP sockets use `setsockopt(IPPROTO_IP, IP_BOUND_IF, index)`. Control and DERP `NWConnection` use `NWParameters.requiredInterface = interface`. Leave control and DERP connections to loopback destinations unbound (Go `netns_darwin.go:38-55`. This rule allows the macOS gate's loopback testcontrol and DERP to work). Open without binding if the interface is still unknown.
   - `DatagramSocket(port:interfaceIndex:)` applies `IP_BOUND_IF` before `bind`. Failure (such as a nonexistent index) produces `bindFailed(errno name)`. Binding happens once at open time, so open a new socket on an interface change (behavior N 3.3).
   - Observation on macOS (M5-7a, one device). A UDP socket bound to a physical interface can still send to and receive from loopback (so there is no loopback exception for UDP, which serves multiple destinations). A socket bound to lo0 gets `ENETUNREACH` when sending to a non-loopback destination. When sending to a non-loopback address on its own device, packets fail to arrive without an error.
5. `shortcut:` Network loss (no satisfied path) has no handling (Go closes DERP and pauses control, DNS notes §4.6.3 items 1 and 3). The app reports only satisfied paths. Connections rely on their own retries and backoff during disconnection. Handling becomes necessary if retries while offline cause battery or memory problems on real devices.
6. `shortcut:` There is no automatic rebind on UDP send errors (`EPERM` or broken pipe, magicsock notes §4.11 item 3). This becomes necessary if a socket dies without a `setDefaultInterface` call during real device transition tests.

### P. State persistence and restart

1. The existing `identity.json` (machine key + node key) is the entire identity, the same minimum set DNS notes §4.4.3 verified for "the same node after restarting." Nothing else is persisted. The disco key remains unpersisted, as in M4.
2. **File protection** (iOS). The node sets `completeUntilFirstUserAuthentication` data protection and `isExcludedFromBackup` on `identity.json` directly. The identity file contains private keys, so restoring it to a different device would give two devices the same machine key (lead session confirmation needed T6). The app chooses the directory location (App Group container) and protection for the directory itself.
3. **Duplicate rejection**. `run()` adds the directory to a process-wide table (`Mutex<Set<String>>`, standardized directory path) on start and removes it on exit. If it is already present, `run()` throws `stateDirectoryInUse` immediately, before opening files or sockets. This does not prevent duplicates across processes (the first adopter's Go implementation also checks only within one process, DNS notes §4.4.3). Create the directory with mode 0700 before adding it (both `run()` and `logOut()`, with `control(.storage)` on failure). Symlinks cannot be resolved for a nonexistent path, which would produce a different key from the same location after creation. Remove the entry using the key obtained when adding it (2026-11-17 security verification).
4. Use a separate state directory from the first adopter's Go core (decision D8). Migration from Go `tailscaled.state` is an M7 decision.
5. **Checking for a saved identity** (2026-11-18). `TailnetNode.hasSavedIdentity(in:)` lets the app decide before starting the node whether to connect automatically with a saved identity or ask for an auth key or login. It reads the identity file using the same rules as `run()` (no following symlinks, regular files only, up to 64KiB) and validates its format. When the file exists but cannot be read, `run()` would also end with `control(.storage)`. The method throws the same error early so the app does not collect an auth key and then fail at startup. A node key is required for true. A file with only a machine key indicates a stop before registration (`run()` saves the machine key before registration). A missing file returns false without creating the directory. A non-file URL produces `invalidConfiguration`. Even if the method returns true, `run()` reports `.needsLogin` or a failure if the server removed the node or the key expired. Keys are never exposed.

### M. Memory

The goal is at most 20MiB idle resident memory (plan §7), with a 50MiB extension limit (as reported in "Memory and size" in the first adopter's `docs/tunnel.md`, unverified against Apple documentation). Real device measurements settle this (gate (b)). The contract **caps both item count and total bytes in each buffer that can accumulate untrusted input**.

| Buffer | Current | M5 | On overflow |
| --- | --- | --- | --- |
| utun reads | None | One reusable buffer of 4 + 65,535 bytes (behavior U4) | Not applicable |
| utun writes | None | No queue (behavior U5) | Drop the packet |
| Map response frame (`MapResponseFramer`) | 64MiB | **8MiB** (implemented, M5-6) | `malformed`. A 64MiB frame had a measured decoding peak of about 110MB (SwiftailControl contract unit 3 `shortcut:`). An 8MiB frame is about 14MB at the same ratio |
| `DERPClient` receive events | 256 items (16MiB worst case at the Go server packet limit of 65,536 bytes. 256MiB if a server sends frames at the 1MiB limit) | 256 items **and 1MiB** (implemented, M5-6) | Drop oldest first |
| `DatagramSocket` received datagrams | 256 items (up to 65,535 bytes, 16MiB worst case) | 256 items **and 1MiB** (implemented, M5-7a) | Drop oldest first |
| Node → DERP send queue | 256 items | 256 items and 1MiB | Drop oldest first |
| Node → UDP send queue (`DatagramSocket.enqueue`) | None (the node actor calls `sendto` directly) | 256 items and 1MiB (implemented 2026-11-15. `sendto` moved outside the node actor to the socket's serial queue. The node collects outgoing packets during one processing pass and passes them on as a batch) | Drop oldest first. Drop packets left on a socket closed during rebinding and never write to a closed descriptor. At shutdown, send the remaining packets (RST from netstack behavior N8), then close |
| `inboundPackets` (memory device) | 256 items | Same (worst case 256 × 64KiB ≈ 16MiB. The extension uses utun and has no such buffer. Add a byte limit if the memory device is used in a production path) | Drop oldest first |
| `events` | 64 items | Same (if there are more than 64 peers and the app consumes slowly, a burst of path events can displace a state event. Estimated in M4 review B and not reproduced. The app can also read the current state through `status`) | Drop oldest first |
| `networkSettings` | None | 1 item (behavior E 3) | Replace with the newest |

- Write deadlines do not accumulate memory. `DERPClient` creates no deadline Task or timer per write. One watcher per connection enforces the 5-second deadline from the start time of the in-progress write (SwiftailDERP contract `DERPClient` behavior 3). When every write used `withTimeout`, canceled `Task.sleep` Tasks and timers lasted until the deadline and accumulated in proportion to write rate (100MiB bidirectional over a DERP-only path, release build, peak phys_footprint sample 83MB → 15MB). `withTimeout` now also removes the timer immediately on cancellation, but creates a Task per call, so it is omitted from per-packet paths.
- The 1MiB byte limit is proposed by this contract. Its only basis is the calculation that the 16MiB worst case is about one third of the 50MiB limit. Three such buffers would consume 48MiB, leaving 2MiB for the rest of the extension. Adjust if real device throughput measurements show drops.
- The existing `shortcut:` that M5 **tightens** is the map frame limit (SwiftailControl contract unit 3. Where the number of values was bounded, the frame size is now bounded first).
- Existing `shortcut:` entries **to decide after measuring** in M5 (leave the contracts as written and decide from gate (b) results) are peer preregistration (M3 engine contract behavior 3, engine notes §6.3), cleanup of non-home DERP connections (M4 engine contract N3), allocations per WireGuard packet (`shortcut:` in `Sources/SwiftailWireGuard/Transport.swift` and `WireGuardDevice.swift`), and HTTP/2 receiver backpressure (SwiftailHTTP2 contract. The frame limit bounds accumulation).

### C. Limits and failures

1. The node must survive any byte sequence read from the device and any DNS query. Avoid out-of-bounds indices, integer overflow (checksum sums and `UInt32` overflow in `SEG.SEQ + SEG.LEN` wrap), and unbounded name pointers.
2. The responder fails closed. Return FORMERR for unparseable input and NXDOMAIN or SERVFAIL for unknown input. Never forward queries upstream.
3. Packets addressed to a service IP never go through WireGuard (behavior L2).
4. Failed `init` validation and `stateDirectoryInUse` terminate before creating files, sockets, or Tasks.

### K. Secrets

1. Keep node, machine, and disco private keys and auth keys out of events, errors, `description`, and `dump` (same as before). `NodeStatus` carries no keys.
2. `NodeError.udpUnavailable` reports the errno name. `NodeError.tunnelDeviceClosed` reports the errno name or `EOF` for utun failures. The memory device test hook uses `"test"` (behavior U7). `invalidConfiguration` identifies the invalid setting and may state the supported MTU range. It omits paths, descriptor numbers, and keys.
3. Do not log DNS query contents (names). This contract creates no logging API (first adopter confirmation needed F6).

### Responder implementation decisions (M5-1, 2026-11-15)

Go reference comparisons (`GoMagicDNSComparisonTests`, `GoTunnelSettingsComparisonTests`). Of the 85 MagicDNS steps, 81 match Go down to the response bytes, 3 differ as documented (4via6 and subdomain rules), and 1 is the question leak below. Of the 32 tunnel setting steps, 15 match Go, 16 differ as documented (omit search domains, ignore global resolvers and split DNS, and so on), and 1 concerns the route to a peer past its expiration time (Go's route derivation checks only the `Expired` flag, which is set by a preceding stage. Swiftail itself removes peers with `keyExpiry <= now`).

- Service IP constants live in `ServiceIP` and are shared by the responder, DNS server and route derivation, and local processing in the engine.
- Entry points are `MagicDNSResolver(netmap: Netmap?, localZones: [String])` and `response(to:at:) -> [UInt8]` (internal). Always emit response bytes. Even queries shorter than 12 bytes get FORMERR with ID 0, as in Go.
- Even if `netmap` is nil because there is no netmap or the local key expired, respond for fixed names such as the service IP PTR (as in Go). Other names get SERVFAIL.
- **Intentional differences from Go**. When answering a query whose header is short or whose response bit is set, Go includes **the preceding query's question** left in a reused parser, which can leak another app's query name (verified in Go output). Swiftail answers without a question. It normalizes `ExtraRecords` names and the MagicDNS suffix to lowercase before comparison (Go preserves the original case).

## Decisions ([DNS notes §6.4](../protocol-notes/dns-state-node.md#64-m5-contract-decisions-for-the-lead-session))

| # | Decision | Defined | Rationale |
| --- | --- | --- | --- |
| D1 | How DNS is provided to the OS | (a) Match domains only | Primary resolver mode requires upstream forwarding and a way to read the OS default resolver in the extension. The latter is unverified. The first adopter also limits the scope this way |
| D2 | Global `Resolvers` and `Routes` with resolvers | (a) Ignore them and match only local zones | Names outside those zones go to the OS default DNS. This document marks them unsupported (exclusions table). The first adopter's test contract `TestTunnelIOSDNS` has the same result |
| D3 | Search domains | (a) None. The app sets `matchDomainsNoSearch = true` | Same as the first adopter. Short names are not resolved |
| D4 | TCP to service IPs | (b) RST | Go also sends RST except for 53, 80, and 8080. The original plan was to use option (c) for port 53 once the M6 TCP stack was available. M6 keeps the RST for tunnel mode (see the Netstack contract's exclusions) |
| D5 | ICMP echo for service IP | Response | Matches Go and used for diagnostics. |
| D6 | Source of link change notifications | (a) Only `setDefaultInterface` | The app owns path monitoring policy. Calling again with the same interface rereads the addresses and reruns STUN (as with Go `InjectEvent`). See T3 for the argument type |
| D7 | Peer AAAA | Go rules | As per behavior D3 |
| D8 | State directory | Separate | Migration is M7. For existing first adopter users, this becomes a new node (first adopter confirmation required F9). |
| D9 | `Running` determination | Go rules | A peerless tailnet can report `running` via DERP (as per behavior B5). |

## Lead session confirmation needed

Lead session decisions (2026-11-15, after the first adopter's review). T1~T6 follow the recommendations below. For T7, the lead session chose option (b), a **build variant of the first adopter's tunnel extension**. That is where signing, App Group, and real device installation are configured, and it allows side-by-side comparison with the Go tunnel on the same device. Swiftail is included as a SwiftPM path dependency. The extension links the `Swiftail` product and uses `import` for `SwiftailBase`, `SwiftailControl`, `SwiftailEngine`, and `SwiftailMagicsock` as needed for the types in the public API (since 2026-11-18, `import Swiftail` alone suffices. See "Types from other modules in the public API" above). The code uses only APIs available to an App Extension.

| # | What | Options | Recommendation |
| --- | --- | --- | --- |
| T1 | Shape of `NodeEvent` | (a) Remove `loginRequired`, `running(addresses:)`, and `reconnecting`. Use `stateChanged(NodeState)` and read addresses through `status` / (b) Keep the existing cases and add `stateChanged` | (a). Report each fact through one channel. Go has no state corresponding to `reconnecting`, and the first adopter does not use it. This requires updating event waits in the M3 and M4 gate tests (`Tests/SwiftailInteropTests`), included in implementation unit M5-8 |
| T2 | Path for configuration events | (a) Separate `AsyncStream<TunnelNetworkSettings>`, `.bufferingNewest(1)` / (b) As per plan §6: `NodeEvent.networkSettings` | (a). The first adopter rule "queue holds only the latest entry" is expressed as a single buffering policy. (b) Cannot selectively remove old settings from a mixed event buffer (64 entries) |
| T3 | `setDefaultInterface` argument | (a) `NWInterface` (with name and `index` and `Sendable`, iPhoneOS 27.2 SDK `Network.swiftinterface`) / (b) string name (plan §6, equivalent to Go) | (a) Control and DERP connections use `NWConnection`, and the only way to bind it to an interface is via `NWParameters.requiredInterface(NWInterface)`. A name alone is insufficient to create an `NWInterface`, necessitating path monitoring within the library (contradicts D6). The app already holds an `NWInterface` from `NWPath.availableInterfaces`. Name validation (15 characters, allowed characters) is no longer required |
| T4 | Configuration validation timing | (a) `init` throws (`throws(NodeError)`) / (b) In `run()` as in M3 | (a). The first adopter gets an immediate failure from the start call for an invalid fd or MTU (`rd_start` returns `invalid_config`). Since `run()` starts asynchronously, with (b) the app would learn of the failure after reporting "started." This adds `try` to existing `init(configuration:)` calls |
| T5 | Map frame limit | Keep 64MiB / 8MiB / Decide after real device measurements | Lower to 8MiB and confirm at gate (b). The estimate that uncompressed maps for tailnets with 1,000 peers reach several MB is unverified. Split by platform if a large tailnet on a Mac host (M6/M7) causes a problem |
| T6 | Protection class and backup exclusion for `identity.json` | (a) The node sets them directly on the file (iOS only) / (b) The app is responsible (the first adopter currently sets them on the directory) | (a). A library guarantee is safer for a private key file. Verify whether new files inherit the directory's protection class and whether a temporary file retains protection after rename (unverified against Apple documentation) |
| T7 | Test tunnel app for the real device gate | (a) Minimal app in the Swiftail repository (`Tools/TunnelHarness/`, container app + packet tunnel extension, outside the library targets) / (b) Swiftail build variant in the first adopter's extension | Pass the gate with (a), then switch to (b). Changes to the first adopter's repository need separate approval (plan §7 M7). Signing team and NE entitlements are open decisions in plan §9 |


## First adopter review results (2026-11-15)

The first adopter answered the 16 questions under "First adopter confirmation needed" by checking the code at its call sites. The questions are recorded as originally asked. This section records only decisions that change the contract and takes precedence in a conflict.

1. **Error types (question 6, follow-up 1)**. The app chooses text by error type and translates it into 5 languages, so the types users need to distinguish must be exposed as enum cases instead of associated strings. `run()` distinguishes registration with an auth key rejected (the server gives no error type, so do not further distinguish invalid, expired, or already used based on its string), registration without an auth key rejected (such as due to administrator policy), node key expired even after reregistration with a new key, tailnet lock, and device, state directory, or configuration errors. Control server response errors (HTTP status) and connection failures are transient and are logged without throwing. The state remains `.starting` or `.running`. Preserve diagnostic strings from the server as associated values and keep them out of user-facing text. **`run()` throws only for failures that a restart cannot resolve. For transient failures (disconnection, temporary server error, or timeout), it backs off and retries internally without throwing.** The app disables on-demand connection if `run()` throws.
2. **Key expiration and login (question 8)**. A node started without an auth key reregisters with a new node key on key expiration without an app call, and emits `.needsLogin(url)` with the server-provided URL. A node started with an auth key resends it when registering a new node key. With a reusable key, it reauthenticates automatically. With a one-time key, registration is rejected and `run()` ends with "registration with an auth key rejected" from item 1 above. When reconnecting with an already registered saved key (a restart), the node omits the auth key, so leaving a one-time key in the app configuration does not cause rejection on restart (SwiftailControl contract unit 4 behavior 2).
3. **Path lookup (questions 12 and 13)**. `path(toPeerNamed:)` and `peerPathChanged` return values **only when the path is actually known**. If there has been no exchange with the peer in the past 45 seconds (Go's idle threshold), the value is nil. This matches the first adopter's current rule. Showing an idle peer as `.relayed` would label a connection "relayed" even if it goes direct when traffic starts. The region ID suffices for `.relayed`.
4. **State directory (follow-ups 2 and 3)**. `stateDirectoryInUse` checks within the same process. It allows different processes to take turns using the same directory (as in the first adopter, where there are two tunnel extensions and only one VPN can be active at a time) and leaves no lock file. The data protection class for `identity.json` is `completeUntilFirstUserAuthentication`. The extension can start while the screen is locked, and startup would fail in that case with `complete`.
5. **Logs (question 14)**. The library logs summaries without secrets via `os.Logger(subsystem: "Swiftail")` without expanding the public API. It logs state transitions, control and DERP connection, disconnection, and backoff, path switches (direct ↔ relayed), interface rebinding, and when it derives settings. It omits keys, auth keys, full addresses, and DNS query names. Logging occurs only at the edge (the node in `Swiftail` and `SwiftailIO`).
6. **Sleep and wake (follow-up 5)**. There is no separate call into the library. On wake, control and DERP connections resume through the existing reconnect path (to be verified in M5 gate (b)).
7. **Confirmed as proposed**. Report startup completion immediately after `init` succeeds (question 2). The app supplies the default for an empty `controlURL` (3). `TunnelNetworkSettings` provides types whose `description` has the form `100.64.0.11/32` or `fd7a:…/128`, and the app converts to strings (4). Use per-peer /32 (5). Call `setDefaultInterface(NWInterface)` for every satisfied path (10). Keep `status.peerCount` and StableID (9. The app does not use them, but M7 WhoIs and diagnostics do).
8. **Transition for existing users (question 16)**. Await the owner's decision. Keep migration out of M5 until the owner decides (after replacement, existing devices log in as new nodes and pair again. The first adopter handles user guidance).
9. **Memory (question 15)**. There is no record of observing the extension limit in practice (50MiB is a reported value only). The first adopter measures the Go tunnel's `phys_footprint` at idle and during transfer before replacement to provide a baseline.

## First adopter confirmation needed

This section examines the first adopter's committed call sites (`Apps/iOSTunnel/PacketTunnelProvider.swift`, `docs/tunnel.md`, `docs/protocol-addenda.md` N.3, `core/internal/tunnel/`, and `rd_tunnel_*` in `core/capi/include/rdcore.h`) and lists the mapping and questions for verifying whether this contract can replace them.

### F1. Start and Stop

Mapping

```swift
// startTunnel: after finding utun with the existing UTUNLocator
let node = try TailnetNode(
    configuration: .init(stateDirectory: stateDir, hostname: config.hostname,
                         controlURL: config.controlURL ?? NodeConfiguration.defaultControlURL,
                         authKey: authKey.isEmpty ? nil : authKey),
    device: .utun(fileDescriptor: found.fd, mtu: 1280))
let runTask = Task { try await node.run() }   // Failure handled in F3
// stopTunnel
runTask.cancel(); _ = await runTask.result
```

- The `invalid_config` (fd·MTU) for `rd_start` is an `invalidConfiguration` (T4) thrown by `init`. If either `tunnel_in_use` or `state_dir_in_use` indicates the same directory, then `run()` reports `stateDirectoryInUse`.
- For `rd_stop`, the statement that "the engine shutdown may take several seconds, so it is called from a serial queue" has been replaced with task cancellation and `await`. A serial queue is no longer needed.
- There is no corresponding value for `goMemLimitMiB`, `logPath`, `hostDisplayName`, or `appVersion`.

Questions

1. Swiftail does not block launching a second tunnel node to a different state directory (`tunnel_in_use`). Since the extension only allows one node, is the app's `TunnelLifecycle` sufficient for this use case?
2. Can the completion of `startTunnel` be signaled immediately after `init` success (without waiting for `run()`)? Currently, it does not wait for `Running`. If `run()` throws immediately (`stateDirectoryInUse` or `udpUnavailable`), call `cancelTunnelWithError` after signaling completion.
3. Can the app preserve the empty-`controlURL` rule by substituting `NodeConfiguration.defaultControlURL` for an empty string?

### F2. Configuration Application

Mapping. `for await settings in node.networkSettings { applier.submit(SettingsTranslator.translate(settings)) }`. The rules match those of the first adopter (behavior E. Do not emit with no addresses or with identical settings, do emit on a DNS-only change, and keep only the latest unread value). If `dnsServers` is empty, use `dnsSettings = nil`. Keep `matchDomainsNoSearch = true`, `tunnelRemoteAddress = "127.0.0.1"`, and the `SerialApplier` that applies one configuration at a time.

Questions

4. `SettingsTranslator.translate` currently receives a string CIDR (`NetworkSettingsEvent`). Is it sufficient to put a thin conversion in the app that produces and passes along the same string using `IPPrefix.description` and `IPAddress.description`, or should it be modified to directly accept `TunnelNetworkSettings`?
5. Even on macOS, peer routes follow iOS rules (per-peer /32). Go could emit a single `100.64.0.0/10` on macOS (`docs/tunnel.md`, "routes"). Do any e2e tests expect a /10?

### F3. State and error display

Correspondence (first adopter `backendState`):

| First adopter | Swiftail |
| --- | --- |
| `Starting` | `.stateChanged(.starting)` |
| `NeedsLogin` + `authURL` | `.stateChanged(.needsLogin(url))` |
| `NeedsMachineAuth` | `.stateChanged(.needsMachineAuth)` |
| `Running` | `.stateChanged(.running)` |
| `Error` + `errorMessage` (auth key rejected, control server error) | `run()`-thrown `NodeError.control(…)` |
| `Error` + `"TUN 장치가 닫혔습니다."` (“The TUN device has closed.”) | `run()` throws `NodeError.tunnelDeviceClosed` → call `cancelTunnelWithError` as before |
| `Stopped` | `run()` returns |
| `rd_status`'s `fqdn`, `tailscaleIPs`, `certDomains`, `tunnel{…}`, `peerCount` | `await node.status`'s `fqdn`, `addresses`, `certDomains`, `networkSettings`, `peerCount` |

Questions

6. `NodeError` does not provide human-readable sentences (it only includes type and a brief diagnostic string). Is it sufficient for the app to select a Korean message based on the error type (as in `TunnelProviderError`)? Currently, the core sentence associated with the cause in `backendErrorMessage(cause:)` corresponds to the diagnostic string of `NodeError`.
7. Unlike Go, if auth key rejection or registration denial occurs, the node terminates (`run()` throws). To retry, the VPN must be restarted again. Since the UI's "Reconnect" and "Connect with an auth key" actions both perform the same action of restarting the VPN, this is considered correct. Is this correct?
8. Since the URL for `NeedsLogin` is always present, there is no need to restart login every 30 seconds (`needLoginKick`). Is there a screen displaying a `NeedsLogin` with no URL?
9. A `stableID` can be added to the status response (`NodeStatus.stableID`). Will it be used on the phone UI or in diagnostics? If not, it is removed from the contract. The same question applies to `peerCount` (it is present in the test contract).

### F4. Default Interface Notification

Mapping. `PacketTunnelProvider.defaultInterfaceName(_:)` should return an `NWInterface` instead of a name. The app then calls `node.setDefaultInterface(interface)` (T3). The name validation (`bad_request`) is no longer performed.

Questions

10. The app currently calls this only when the interface name changes (`TunnelRuntime.updateDefaultInterface`). Swiftail lacks Go's `netmon` route socket monitoring, so the node learns of an address-only change on the same Wi-Fi (different AP or DHCP renewal) only if the app tells it. Can the app call it on every satisfied path without filtering? If the interface and address remain the same, the node only re-runs STUN.
11. The selection rule (the first interface after excluding loopback, `other`, `utun*`, and `ipsec*`) remains unchanged. The node also ignores any interface with the same name as its own utun.

### F5. Path State

Mapping. `rd_tunnel_set_path_peer(fqdn)` + state's `peerPath` → when creating state, `await node.path(toPeerNamed: fqdn)`, or remember the last value of the peer in `peerPathChanged`. `PeerPath.direct(endpoint)` → `{"direct": true, "addr": "<endpoint>"}`, `.relayed(derpRegion:)` → `{"direct": false, "relay": …}`.

Questions

12. The first adopter's `relay` is a region code string (such as `"tok"`), while Swiftail returns a region ID (`Int64`). Does the screen need the code? If so, request an M4 contract change to add a DERPMap ID → code table to `NodeStatus` or carry the code in `PeerPath`.
13. The first adopter says, "Omit peers with no recent exchanges because their paths are unknown" (`docs/protocol-addenda.md` N.3). Swiftail's `path(toPeerNamed:)` returns `.relayed` (or `.direct` if still within the trust period) even for idle peers. Should idle peers be omitted from display?

### F6. Logs

Swiftail has no logging API or log events. The first adopter has logged the core logs privately in `os.Logger`.

Question

14. Is internal library logging required for real device diagnostics? If so, propose in the lead session to log only non-sensitive summaries via `os.Logger(subsystem: "Swiftail")`, without expanding the public API.

### F7. Memory

- There is no setting corresponding to `goMemLimitMiB`. Buffer limits are fixed by contract (behavior M).
- Question 15. Record `TunnelStatusReply.physFootprintMiB` (measured by the app using `TASK_VM_INFO`) directly in the gate (b) memory record. Can the first adopter provide a way to record it at idle and during transfer (for example, by requesting status periodically)?

### F8. State File and Login Initialization

- Storage is only `stateDir/identity.json`. Keep the existing directory cleanup in `resetsLogin`. The node must be stopped when it is deleted (as today, delete it in `startTunnel` before starting the node).
- Data protection class and backup exclusion are set by the node on the file (T6). The directory setup in `TunnelStorage.prepareStateDirectory` remains unchanged.

### F9. Transition for existing users (D8)

16. Swiftail does not read Go's `tailscaled.state` (migration is an M7 decision). When a device currently logged in with Go core transitions to Swiftail, it must log in as a new node (new IP, new StableID) and re-pair with the Mac. Can this transition be accepted at M5 replacement, or must M7 migration be moved forward to before M5 replacement?

## Exclusions (recorded as `shortcut:` comments)

| Excluded | Rationale | Point of need |
| --- | --- | --- |
| Subnet routes and exit nodes (using and providing them), VIP and 4via6 routes | Excluded in plan §3. `RouteAll=false` fixed since M3 (M3 engine contract) | When the plan scope expands |
| Global resolvers (`Resolvers`), `Routes` with resolvers, upstream forwarding (UDP, TCP, and DoH), `FallbackResolvers`, `GetBaseConfig` and primary resolver mode | D1 and D2. The OS does not send names outside the match domains to quad-100 (DNS notes §4.2.3) | When custom split DNS needs resolution through the tunnel |
| Search domain | D3 | When short-name resolution is required |
| TCP port 53 for service IP (DNS over TCP) | D4. No local response with TC occurs (DNS notes §4.2.4) | After M6 TCP stack |
| 4via6 names and `dns-subdomain-resolve` subdomains | DNS notes §6.1 | When encountering a tailnet that uses these features |
| tailnet lock support | Added in M8 (`SwiftailTailnetLock.md`). M5 refused connections to tailnets with it enabled (`ControlError.tailnetLockEnabled`, now removed) | — |
| IPv6 UDP sockets and IPv6 endpoints | Magicsock contract exclusions table. DERP (TLS, hostname) works on IPv6-only networks too | When a real device encounters an IPv6-only cellular network and needs a direct path |
| Handling network loss, automatic rebinding on UDP send errors, and selective retention of DERP connections | Behavior N 3.2, 5, and 6 | See behavior N |
| Preventing duplicate state directory access between processes | Behavior P 3. File locking within App Group container may interfere with app suspension and is therefore not implemented | When two processes share the same directory |
| TSMP pong · rejection · disco advertisement sending | As per Engine contract M3·M4 | Not applicable |
| Logs | F6 | Based on F6's response |

## Tests

### Unit tests (no sockets or file descriptors, deterministic with supplied times)

`Tests/SwiftailEngineTests/Tunnel/`:

1. **DNS codec**. Header flag copying rules (QR, AA, and RA, RD 0 and 1, preserve Opcode, TC, AD, and CD), 0 and 2 questions, QR=1, pointers (valid, forward, self-referencing loop, 11th pointer), 01 and 10 label formats, `.` inside a label, 254-byte boundary, uncompressed output bytes, and no crash on arbitrary input.
2. **Responder**. Cases in DNS notes §7 items 2~4: A, AAAA, ANY, PTR (IPv4, IPv6, 4to6, and service IP), NS, SOA, TXT, and unknown type, plus short names, FQDNs, mixed case, missing trailing dot, nodes without addresses, names outside the zone (SERVFAIL), `.onion`, Bonjour reverse names, `magicdns-aaaa` present and absent, IPv6-only local node, `ExtraRecords` before the node index, EDNS advertised size and TC at the 512-byte boundary, no OPT in the response, and SOA SERIAL equal to the supplied time.
3. **Settings derivation**. Engine notes §7 item 10 and DNS notes §7 item 1: per-peer /32, 10,000/10,001 boundary, `one-cgnat?v=true`, `v=false`, and absent, /48 when a ULA peer exists, service routes and DNS servers for each local address family, IPv4-only and IPv6-only local node, no local addresses → nil, MagicDNS on and off, empty routes, routes with resolvers (ignored), global `Resolvers` (ignored), `ExtraRecords` (covered, uncovered, invalid names), `force-register-magicdns-ipv4-only`, local key expiration → no DNS, match domain sorting and trailing dots, and same values for the same netmap (including order).
4. **Local handling** (`TailnetEngine.send`. M5-8 writes this test, the only one located in `Tests/SwiftailEngineTests/TailnetEngineTests.swift`). UDP 53 query → reply packet (addresses and ports swapped, IPv4 and IPv6 checksums verified), ICMP and ICMPv6 echo → reply, TCP SYN, ACK segment, or RST → behavior L2 RST rules (including `UInt32` wraparound), other UDP port or protocol → `.serviceIPPacket`, no service IP packet emits `.datagram`, packet to a local address → identical bytes in `.ipPacket`, and device-originated TSMP → drop.

`Tests/SwiftailTests`:

5. **State machine** (behavior B table). Boundaries of each row, `registered` clears the URL, `.running` persists after disconnection, and identical states are not emitted again.
6. **Settings emission** (behavior E). No addresses or an identical value → no emission. Only DNS servers or only match domains change → emit. New settings replace unread ones (the stream yields only one).
7. **Transition classification** (behavior N 1 and 2). First event, same interface and address (STUN only), address-only change (rebind), interface change (rebind), and interface matching the utun name (ignore). Keep classification as an I/O-free function.
8. **State directory table** (behavior P 3). Same path twice, including different forms before standardization → second gets `stateDirectoryInUse`. It can run after the first ends.

`Tests/SwiftailIOTests`:

9. **`UTUNDevice`**. Reject non-utun descriptors (pipe, `socketpair`, closed descriptor, and -1) and leave the caller's descriptor open. Use `socketpair(AF_UNIX, SOCK_DGRAM)` in place of utun with a test-only initializer that skips validation. Test adding and removing the 4-byte header (IPv4 → 2, IPv6 → 30, otherwise skip writing), dropping reads shorter than 4 bytes, a device-closed error when the peer closes, closing only the duplicate and leaving the original descriptor open, and `FD_CLOEXEC` on the duplicate. Creating utun requires administrator privileges, so leave that to the real device gate.
10. **Socket binding**. Loopback still sends and receives when `DatagramSocket` sets `IP_BOUND_IF` to the loopback interface `index`. A nonexistent `index` produces `bindFailed`.

### Go reference comparison

Use the same approach as M3 `filterfixtures` and M2 `mapfixtures`. Go tools in `Tools/interop` run actual Go code to generate fixtures. A different session from the implementer writes the comparison tests. Fixtures omit the current time, production keys, and real names (use fake names such as `tail0001.ts.net`).

- **`Tools/interop/cmd/dnsfixtures`** (new tool). Use `New` + `SetConfig` (host table, `LocalDomains`) + `SetMagicDNSHosts` (`tsdns.go:270-300`) + `Query(…, "udp", …)` from `tailscale.com/net/dns/resolver`. Pass query bytes from unit test 2 to get response bytes. Mark SOA SERIAL in the fixture and exclude it from comparison. Fixture: `Tests/SwiftailEngineTests/Fixtures/magicdns-fixtures.json`. Limitation: Go's node indexing code (the `ipnlocal` side that populates `MagicDNSHosts`, filters AAAA, and handles short names) is unexported, so the tool substitutes a fixed table. This fixture compares byte format, RCODE, SOA, and TC. Queries against the Go peer in gate (a) and unit tests cover the index rules (DNS notes §4.2.1).
- **`Tools/interop/cmd/tunnelfixtures`** (new tool). Derive routes by passing the same set of peers to the exported `tailscale.com/net/routemanager` (`New`, `Begin`, `UpsertPeer`, `SetTailnetConfig`, `Commit`, `OSRoutes`, `routemanager.go:219-511`). Since Go's `dnsConfigForNetmap` is unexported (`ipn/ipnlocal/node_backend.go:1435`), the tool starts a Go node and intercepts the `dns.Config` that `LocalBackend` passes to the engine. Compile it with `dns.NewManager(…, goos "ios", …)` (`net/dns/manager.go:97`) and an `OSConfigurator` that only receives values to obtain `OSConfig`. Convert the result to the behavior S form (after narrowing per D1 and D2). Fixture: `Tests/SwiftailEngineTests/Fixtures/tunnel-settings-fixtures.json`. The cases are the unit test 3 netmaps (JSON).
- Mark intentional differences (narrowing under D1 and D2, and omitting 4via6 and subdomains) in the fixture and review them separately.

## M5 gate

### (a) Items from the first adopter's tunnel test contract using a memory device

Start a Swift node with `.memory(mtu:)` against `tailnet` from `Tools/interop` (testcontrol + DERP + STUN + Go tsnet peer, port 7 echo). The tests live in `Tests/SwiftailInteropTests/TunnelTests.swift` and skip when `SWIFTAIL_TAILNET` is absent. The left column uses the names from the first adopter's "Test contract" in `docs/tunnel.md`.

| First adopter test | Swiftail Gate item |
| --- | --- |
| `TestTunnelDataPath/network-settings` | First `networkSettings` value after `.running` has the local /32 in `addresses`, the Go peer address /32 in `routes`, `dnsServers[0] == 100.100.100.100`, the tailnet suffix without a trailing dot in `dnsMatchDomains`, and `mtu == 1280`. `status.networkSettings` has the same value, and `peerCount ≥ 1` |
| `…/udp` | The echo of a UDP packet sent to Go peer port 7 arrives in `inboundPackets` (retry once per second) |
| `…/tcp` | SYN sent to Go peer port 7 receives a SYN-ACK |
| `…/magicdns` | An A query to `100.100.100.100:53` for the Go peer FQDN returns the peer's IPv4 address. Also check AAAA → NOERROR with empty answer + SOA, PTR for the peer address → peer FQDN, unknown name inside the zone → NXDOMAIN, `example.com` → SERVFAIL, the same answers via `fd7a:115c:a1e0::53`, ICMP echo → reply, TCP 53 SYN → RST, and no packets addressed to a service IP visible on the Go peer side during the test |
| `…/stop` | Canceling the `run()` Task makes `run()` return and the three streams end. The last send timestamp in the Go peer's `peerStatus` stops advancing |
| `TestTunnelEngineDeath` | After `failMemoryDevice()`, `run()` throws `tunnelDeviceClosed`, the streams end, and no further events occur |
| `TestTunnelRestartKeepsNode` | Restart with the same directory → same address without `.needsLogin`. New directory → different address. Moved directory → original address. `identity.json` is created |
| `TestTunnelInUse` | Second node in the same directory → `stateDirectoryInUse`. Available again after stopping the first node (other directories are allowed, F1 question 1) |
| `TestTunnelSlotReleasedOnFailedStart` | Even if the first `run()` fails, the next node can run in the same directory. No test hook for `udpUnavailable` was added because binding failure now falls back to an unbound socket, leaving no way to induce the failure. Unit test `failMemoryDeviceEndsRun` instead checks that the state directory is released after `run()` fails (one `defer` in `run()` releases the claim) |
| `TestTunnelInvalidConfig` | `.utun` -1 and a pipe descriptor → `invalidConfiguration` from `init`. MTUs 1, 1000, 1279, 1421, 1500, 9000, and -1280 → MTU message. Rejection creates nothing in the state directory |
| `TestTunnelMTUBounds` | The node starts with each of MTU 1280, MTU 1420, and the default. `networkSettings.mtu` is 1280, 1420, and 1280, respectively |
| `TestTunnelSetDefaultInterface`, `…Reevaluates` | Calling `setDefaultInterface` with a real interface from `NWPathMonitor` rebinds the UDP socket on the same port and republishes endpoints (`endpoints` in `nodes`). After DERP and control reconnect, echo works and the direct path to the Go peer recovers (M4 gate item 2 criterion). Control and DERP connections to loopback destinations remain unbound, which lets the test run on the loopback tailnet |
| `TestTunnelIOSDNS`, `TestTunnelScopeDNS`, `TestTunnelSettingsBuild`, `…Equal`, `…SinkFlush`, `…EventReplaced` | Unit tests 3 and 6 and Go reference comparison (`tunnelfixtures`) |
| `TestTunnelLoginRecovers`, `TestTunnelOpenUTUNKeepsCallerFD` | No corresponding test (Go panic recovery) / Unit test 9 |
| (Added) Interactive login | Require interactive authentication with `setAuth` → `.needsLogin(url)`. Complete authentication at that URL → `.starting` → `.running` |
| (additional) M3·M4 gate regression | M3 gate 2–7 and M4 gate 2–9 pass through the `.memory` device unchanged (only event waiting is adjusted to match T1) |

### (b) Real device

The first adopter session owns real device verification (agreement on 2026-11-15). Create a build variant of the RemoteDebug tunnel extension that selects the Swiftail implementation (SwiftPM path dependency, local-only settings). Run it with a **separate state directory** to leave the Go node's state untouched. The Swiftail side fixes defects found in the results. The extension measures times and memory and reports them in the device log (Swiftail adds no diagnostic APIs. Use `events`, `status`, `networkSettings`, and `os.Logger(subsystem: "Swiftail")`).

| # | items to verify | pass criteria | items to record only |
| --- | --- | --- | --- |
| 1 | Start with a utun descriptor | `TailnetNode(configuration:device: .utun(…))` does not throw. With authentication complete, `.stateChanged(.running)` and the first `networkSettings` value arrive within 30 seconds of `run()`. Neither `tunnelDeviceClosed` nor `udpUnavailable` occurs. Turning the tunnel off and back on returns to `.running` with the same address and StableID (evidence that only the duplicate was closed) | Time from startup to `.running` |
| 2 | Connect to Mac tailnet HTTPS by FQDN | First request after `.running` gets an HTTP response within 10 seconds (DERP is allowed). All subsequent 10 requests succeed | When `peerPathChanged` becomes `.direct`, and the paths on LAN and cellular separately |
| 3 | MagicDNS and match domains | From the app (a regular socket outside the tunnel), the Mac's FQDN resolves to its tailnet IPv4 and the PTR for that address resolves to the FQDN. Names outside the tailnet (such as public sites) resolve and connect as usual because the tunnel does not intercept the device's regular DNS | Number of match domains and time to resolve |
| 4 | Cellular and CGNAT | With Wi-Fi off and only cellular on, regular internet HTTPS works while the tunnel is on and item 2 also passes | Whether the carrier-provided address range is 100.64/10 |
| 5 | Wi-Fi ↔ cellular and exiting airplane mode | Requests to the Mac succeed again **within 15 seconds** of the transition (when the extension calls `setDefaultInterface`). Pass all 3 repetitions in each direction (Wi-Fi→cellular, cellular→Wi-Fi) and 3 exits from airplane mode. `run()` stays running through each transition | Time the direct path returns (about 10 seconds in the memory device gate) and time control and DERP reconnect (logs) |
| 6 | Extension `phys_footprint` | **At most 20MiB** after 10 minutes idle (plan §7 goal), **at most 40MiB** peak while downloading 100MB (10MiB headroom against the reported 50MiB limit), and no jetsam termination. Idle memory is at most the Go tunnel value for the same procedure | Values immediately on connection, at 1 minute, 5 minutes, and 10 minutes, the peak during transfer, and the same values for the Go tunnel |
| 7 | Identity file protection | After the device's first unlock, `identity.json` has `completeUntilFirstUserAuthentication` protection and backup exclusion (after registration and after changing the node key). Starting on demand after reboot **before the device's first unlock** must not crash. On a registered device, either the file is unreadable and `run()` ends with `control(.storage)`, or the file is readable and startup succeeds. In either case, restarting after the device's first unlock starts the same node | Which of the two behaviors occurs before the device's first unlock |
| 8 | Signals and termination | There are 0 records of termination by signal or trap (crash logs, unexpected VPN disconnection) while doing items 1~6. The same holds on a direct LAN path (on macOS, SIGPIPE on UDP send was reproduced and prevented with `SO_NOSIGPIPE`) | — |
| 9 | Path for unbound requests | No threshold. Pass if registration and login work with the tunnel on | Whether the `/key` lookup and non-Noise ping replies (URLSession) use the physical interface or enter the tunnel |
| 10 | Real tailnet (final gate, plan §4(b)) | Items 2 and 5 pass with the production control server and production DERP | The lead session informs the owner first and obtains an auth key through secret input |

Treat any item that misses its criterion as a defect and collect measured values and relevant raw log lines. Item 6 gives targets. Reevaluate them alongside the Go tunnel baseline once the 10-minute idle and 100MB transfer measurements are available.

**Go tunnel baseline values** (2026-11-15, measured by the first adopter session on a real device. iPhone 14 Pro, iOS 27.2, Wi-Fi, against a Go host):

| Item | Value |
| --- | --- |
| Immediately after connection `phys_footprint` | 3.9–5.2 → 9.4–10.3 → 11.3–11.8 MiB (first 5 seconds) |
| 10 minutes idle | 13.0MiB (peak 13.2. The extension sampled itself every 30 seconds) |
| During a 100MiB download | Less than 12.6 MiB |
| Receiving 100 MiB (HTTPS, Mac → iPhone, direct UDP path on same Wi-Fi) | 23.0 seconds (4.56 MB/s) |

Thus, item 6's "idle memory is at most the Go tunnel value" means **at most 13MiB idle** (20MiB remains the upper bound). Cellular and DERP-only values are still unavailable.

**First Swiftail tunnel run** (same device, RemoteDebug build variant + Swiftail `966c141`). It started with a real utun descriptor (`TailnetNode(configuration:device: .utun(…))` and `run()` ran, and the extension did not crash). About 4.3 seconds after the VPN showed "Connecting," `.needsLogin(url)` arrived and the app showed "Login required." During the roughly 90-second wait for login, `phys_footprint` went from 3.1 → 7.8MiB. Registration creates a new node, so **the owner must log in on the iPhone** before item 1 and later can be checked. The node is a new device without a Mac pairing. To upload device logs to the Mac while the Swiftail tunnel is on, keep the same-Wi-Fi direct connection to the Mac enabled or pair the node with the Mac (pairing requires owner approval).

**Result after login** (2026-11-15, same device and same build. The tunnel path matches `9d87e85`. The first adopter session read the results from device logs):

| Item | Result |
| --- | --- |
| After login `.running` | Achieved. Did not end with `tailnetLockEnabled` |
| 1. `.running` within 30 seconds of startup | **Pass.** Three runs while logged in: 4.5 seconds, 6.3 seconds, and 4.2 seconds. The app shows "Connected" after applying `networkSettings`, so the first settings also arrived within that time (the settings event was not timestamped separately) |
| Stop and restart | Stopped about 0.4 seconds after the stop request and restarted in the same state directory all three times |
| 6. Idle `phys_footprint` | **Pass.** 4.0~5.1 → 6.7~7.0MiB immediately after startup (2 seconds), 8.2MiB at 5 minutes, 8.7MiB at 10 minutes, and steady at 8.7~8.8MiB for 43 minutes (peak 8.8). The Go tunnel used 13.0MiB on the same device. The extension neither stopped nor restarted while the screen was off and the app was in the background |

**Transition test** (2026-11-15, same device, build variant + Swiftail `dfd7008`. The app sends HTTPS HEAD to the Mac's tailnet FQDN every 1 second, using a new connection per request and a 3-second limit. Control Center drives transitions. "Path" is the tunnel extension's `NWPathMonitor` record.)

| Transition | Engine | Path | Probe | Time to recover | 15-second criterion |
| --- | --- | --- | --- | --- | --- |
| Wi-Fi → cellular | Swiftail | "No path," immediately followed in the same second by `pdp_ip0` | Failed after 3 seconds (timeout). No success during 41 seconds on cellular | No recovery | **Fail** |
| Cellular → Wi-Fi | Swiftail | `en0` | Succeeded after 4 seconds | About 4 seconds | Pass |
| Airplane mode on for 12 seconds → off | Swiftail | No path → `en0` | Succeeded 2 seconds after turning it off | About 2 seconds | Pass |
| Wi-Fi → cellular (control) | Go | `pdp_ip0` immediately | Succeeded after 1 failure | About 5 seconds | Pass |
| Cellular → Wi-Fi (control) | Go | `en0` | No failures | 0 seconds | Pass |

Each ran once (item 5 calls for three repetitions each). Go recovered on the same Mac and cellular network, ruling out the network or Mac as the cause. Swiftail logs are unavailable for that interval. Other measurements (Swiftail tunnel, Wi-Fi): first HTTPS HEAD to the Mac FQDN succeeded in 0.27 seconds, no failures during 27 seconds, and restart took 4.4 seconds.

**Cause of Wi-Fi → cellular failure** (confirmed by retest on 2026-11-15 with added diagnostics in the build variant, Swiftail source at `597559c`, and 66 seconds on cellular)

- The cellular path is **IPv6-only + CLAT**. The `pdp_ip0`'s `NWPath` has `supportsIPv4` false, `supportsIPv6` true, `supportsDNS` true, and the interface contains an IPv4 address of `192.0.0.x` (CLAT) and an IPv6 address outside of link-local scope. Wi-Fi (`en0`) supports only IPv4.
- During those 66 seconds, the Swiftail log showed only rebinding entries (`Rebinding default interface: pdp_ip0`, `Rebind: UDP port …`, and `Control: disconnected, reconnecting`). It never showed `DERP region …: connected`. There was also no `Could not bind the UDP socket to the default interface…` entry because binding succeeded. On returning to Wi-Fi, DERP connected and the path became direct in the same second.
- All 18 probe failures were timeouts at 3.00–3.01 seconds. None failed immediately.
- Extension calls during the transition were `en0` (the path was still satisfied at the moment `en0` had no addresses) → "No path" (no call) → `pdp_ip0` three times → two more calls from path updates while it stayed on cellular.

Swiftail dials DERP using **only one IPv4 literal** from the DERP map (`DERPServer+DERPNode.swift`). The connection fails on paths without IPv4 support (`NetworkSocket` treats `.waiting` as failure), and `DERPClient` emits neither an event nor a log for failure before connection, which explains the missing line. Go dials IPv4 and IPv6 concurrently per node and uses the first connection to succeed (`derp/derphttp/derphttp_client.go` `dialNode`). Fixes: ① Dial DERP with both address families (DERP alone restores relay connectivity). ② Log failed connection attempts. Then verify whether `AF_INET` UDP bound to `pdp_ip0` actually leaves via CLAT (whether a direct path is established). If it does not, check IPv6 for outer UDP, STUN, and endpoints. Whether the control connection recovered on cellular is unverified because the log has no success line (control dials by name and is presumed to benefit from DNS64).

**Retest after the fix** (2026-11-15, Swiftail `98cbbf0`. DERP now dials IPv4 and IPv6 destinations concurrently. Same device, actions, and conditions.)

| Transition | Probe | Recovery time | 15s benchmark |
| --- | --- | --- | --- |
| Wi-Fi → Cellular | Failure 1 (3.01s timeout) then success (request 0.26s, path at time was relayed) | ~4s | **Pass** |
| Stays in cellular for 76s | 59 consecutive successes | — | — |
| Cellular → Wi-Fi | Failure 1 then success (request 0.09s) | ~4s | Pass |

- In the same second as the switch to cellular, the log showed `DERP region 7: connected`, followed 5 seconds later by `Peer path: direct`. **On the IPv6-only + CLAT network, `AF_INET` UDP went out through CLAT and established a direct path.** Outer UDP and STUN did not require IPv6 on this network (an IPv6-only network without CLAT was unobserved). There was no `Connection failed (…)` entry.
- Each ran once (item 5 calls for three repetitions each).
- Two observations, neither a failure. ① About 70 seconds into the cellular connection, a path update for the same interface (`pdp_ip0`) triggered a **full rebind** instead of rerunning only STUN. The path switched to relay for 1 second, with no probe failures. This also occurred at the same point in the earlier failed test. `DefaultLink` compares all of the device's IPv4 addresses instead of only the default interface's addresses, so an address change on another interface also triggers rebinding (inferred. There is no record of which address changed at that moment). ② There was no log entry reporting that the control connection had reconnected. An entry was added (`Control: reconnected`, once on the first netmap after disconnection).

Test conditions (confirmed with the owner by the first adopter session). The iPhone app and Mac were logged in to **different tailnets** (same user. The Mac appears to the iPhone node as a peer in a different tailnet). On Wi-Fi, this was sufficient for a direct path. Whether the iPhone's Go and Swiftail nodes are in the same tailnet is unverified. The post-fix retest uses the same conditions.

Still unverified are item 2 (Mac tailnet HTTPS request), item 6 memory during transfer, receiving 100MiB, MagicDNS, and path display, which wait for pairing the node to the Mac (pending owner approval). Item 5 (Wi-Fi ↔ cellular and airplane mode) and item 7 (starting before the device's first unlock) require the owner to operate the device manually. The first adopter's production extension can be replaced once separately approved (plan §7 M7, T7).

## Implementation units

Split ownership files to avoid overlap. M4 unit 4 is currently working on `Sources/Swiftail/**`, `Sources/SwiftailEngine/**` (existing files), `Sources/SwiftailMagicsock/Magicsock*.swift`, `Tests/SwiftailEngineTests/*`, and `Tests/SwiftailTests/*`. Therefore, **units that can start before M4 must consist solely of new files**. These new files will be placed in a subfolder (`Tunnel/`) to avoid name conflicts with M4's files.

| Unit | Content | Owned files | Precedence |
| --- | --- | --- | --- |
| M5-0 | Lead session: contract finalized (T1~T7, incorporating answers to F questions) | `docs/contracts/SwiftailTunnel.md` | first |
| M5-1 | DNS codec and responder (behavior D) | `Sources/SwiftailEngine/Tunnel/{DNSMessage,MagicDNSResolver}*.swift`, `Tests/SwiftailEngineTests/Tunnel/{DNSMessageTests,MagicDNSResolverTests}.swift` | **in parallel with M4** |
| M5-2 | Configuration derivation (behavior S, `TunnelNetworkSettings`) | `Sources/SwiftailEngine/Tunnel/TunnelNetworkSettings*.swift`, `Tests/SwiftailEngineTests/Tunnel/TunnelNetworkSettingsTests.swift` | **Parallel with M4** (this unit only calls `EnginePeer.peers` using its existing M3 signature) |
| M5-3 | Service IP reply packet generation (UDP, ICMP echo, RST, checksum), pure functions before engine integration | `Sources/SwiftailEngine/Tunnel/ServiceIPReply*.swift`, `Tests/SwiftailEngineTests/Tunnel/ServiceIPReplyTests.swift` | **Parallel with M4** |
| M5-4 | `UTUNDevice` (behavior U) | `Sources/SwiftailIO/UTUNDevice.swift`, `Tests/SwiftailIOTests/UTUNDeviceTests.swift` | **Parallel with M4** |
| M5-5 | Go baseline tooling and data | `Tools/interop/cmd/{dnsfixtures,tunnelfixtures}/`, `Tests/SwiftailEngineTests/Fixtures/{magicdns-fixtures,tunnel-settings-fixtures}.json`, a new section in `Tools/interop/README.md` | **Parallel with M4**. A different session writes the comparison tests after M5-1 and M5-2 |
| M5-6 | Binding and memory limits at the edge: `NetworkSocket` `requiredInterface`, `ControlClient.setNetworkInterface`, 8MiB map frames, `DERPClient` interface argument and event byte limit | `Sources/SwiftailIO/NetworkSocket*.swift`, `Sources/SwiftailControl/Client/ControlClient*.swift`, `Sources/SwiftailControl/Netmap/MapResponseFramer.swift`, `Sources/SwiftailDERP/DERPClient*.swift` and their tests | **Parallel with M4** (files M4 does not change). The `DERPClient` initializer change intersects M4 unit 4 call sites, so add an argument with a default |
| M5-7 | UDP binding and rebinding: `IP_BOUND_IF` and byte limit in `DatagramSocket`, `Magicsock.rebind` | `Sources/SwiftailIO/DatagramSocket.swift`, `Sources/SwiftailMagicsock/Magicsock*.swift` and tests | **After M4 units 3 and 4 merge**. 7a (`DatagramSocket`) goes first because it shares no files with M4 unit 4. 7b (`Magicsock.rebind`) follows the unit 4 merge |
| M5-8 | Engine and node integration (8a engine completed in b503d5f, 8b node in 9f1ec00): `TailnetEngine.send` local handling (behavior L), responder installation, state machine (behavior B), settings emission (behavior E), `TunnelDevice` and utun read loop, `setDefaultInterface` (behavior N), state directory table and file protection (behavior P), public API shape (T1~T4), and event waits in existing gate tests | `Sources/SwiftailEngine/TailnetEngine*.swift`, `Sources/Swiftail/*`, `Tests/SwiftailEngineTests/TailnetEngineTests.swift`, `Tests/SwiftailTests/*`, `Tests/SwiftailInteropTests/*` (event waits only), `Sources/SwiftailControl/Client/NodeIdentityStore.swift` (protection class) | **After M4 unit 4 merges**, after M5-1~4, 6, and 7. Largest unit. If split, make 8a engine (behavior L and responder installation) and 8b node. Build 8b after 8a merges |
| M5-9 | Gate (a): enhance `tailnet` tool command (if needed), `TunnelTests.swift` | `Tools/interop/cmd/tailnet/*`, `Tests/SwiftailInteropTests/TunnelTests.swift` | Tool work can start any time after M4 unit 5 merges. Swift test after M5-8 |
| M5-10 | Gate (b): test tunnel app (T7) | `Tools/TunnelHarness/` (outside library targets) | After M5-8 and the signing decision (plan §9) |

Order: M5-0 → (M5-1, 2, 3, 4, 5, 6) in parallel with M4 → merge M4 units 3 and 4 → M5-7 → M5-8 → M5-9 → review by another session → lead session reruns gate (a) → M5-10 and gate (b) → first adopter replacement (separate approval). A session other than the implementer writes the comparison tests (the tests that read fixtures).
