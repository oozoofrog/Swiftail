# netmap → engine layer (peer configuration · packet filter · routes)

| Item | Value |
| --- | --- |
| Reference versions | `tailscale.com` v1.104.6 (CapabilityVersion 148), `wireguard-go` v0.0.0-20261106233718-9e0ab45c16ca — [Reference sources](README.md#reference-sources) |
| Authoring model | Claude Sonnet 5.5 (`claude-sonnet-5-5`), 2026-11-13 |
| Verification status | GPT-6.1 Sol completed the source comparison on 2026-11-14. Corrected 10 factual errors (§8.3) and filled gaps in implementation coverage (§4.3, §4.7, §6). Runtime interop was not tested |
| Milestones using this note | M3 (DERP-only UDP echo, TCP SYN-ACK, and ACL blocking), M5 (iOS tunnel configuration) — `docs/plan.md:193-195` |

Source references use `path:line` relative to the module root. `wireguard-go/` is the root of the fork above, and `gvisor/` is the root of the Go dependency `gvisor.dev/gvisor` v0.0.0-20260915211658-a6f909f08a72 (version in `tailscale.com/go.mod:156`). `Sources/` and `docs/` are relative to the Swiftail repository. The **recommendations, design choices, and test plans** below are distinct from Go's required wire behavior.

## 1. Scope

M3 implementers follow the packet input in §3, peer and filter conversion in §4.1–4.6, in-process receive boundary in §4.7, and procedure in §6.1. Deriving OS address, route, and DNS settings is grouped under M5 (§4.8 and §6.2, milestone `docs/plan.md:193-195`).

[wireguard.md](wireguard.md) covers Noise and rekeying, [control-map.md](control-map.md) covers map JSON and delta merging, [disco-magicsock.md](disco-magicsock.md) covers direct UDP, disco, and DERP path selection, and [dns-state-node.md](dns-state-node.md) covers MagicDNS responses.

## 2. Source map and current module boundaries

| Role | Where to verify |
| --- | --- |
| netmap → per-peer AllowedIPs | `tailscale.com/net/routemanager/routemanager.go:260-297`, `:408-431`, `:665-687`, `:827-862` |
| Outbound peer selection and peer configuration supply | `tailscale.com/ipn/ipnlocal/resolve.go:20-52` |
| Peer configuration synchronization and local packets | `tailscale.com/wgengine/userspace.go:652-750` |
| Filter rule conversion, matching, and verdicts | `tailscale.com/wgengine/filter/tailcfg.go:30-180`, `tailscale.com/wgengine/filter/match.go:17-107`, `tailscale.com/wgengine/filter/filter.go:443-720` |
| Filter and netstack wiring after WireGuard | `tailscale.com/net/tstun/wrap.go:1128-1254`, `tailscale.com/wgengine/netstack/netstack.go:465-466` |
| OS routes | `tailscale.com/net/routemanager/routemanager.go:874-892`, `:909-1029`, `tailscale.com/ipn/ipnlocal/local.go:6710-6797` |

In this version, `wgcfg.Config` has only `PrivateKey` and `Addresses`, with no peer array. `PeerConfig` has only `AllowedIPs` and `PresharedKey`. The old `wgcfg/nmcfg` approach of generating a peer array therefore does not describe this version (`tailscale.com/wgengine/wgcfg/config.go:17-35`).

Swiftail's `Netmap` holds self, peers, the DERP map, filter rules, and `controlTime`. The WireGuard module provides `addPeer`, `removePeer`, and `send` targeting a public key. `ipPacket` output has already passed decryption and AllowedIPs checks. The engine handles the filter and outbound peer selection outside that module (`Sources/SwiftailControl/Netmap/Netmap.swift:7-26`, `Sources/SwiftailWireGuard/WireGuardDevice.swift:19-29`, `:57-78`, `docs/contracts/SwiftailWireGuard.md:70-101`).

## 3. Packet input and wire fields

### 3.1 IP and transport headers read by the filter

Offsets are relative to the start of the IP packet, and integers are big-endian unless otherwise noted. The Go parser extracts version, addresses, ports, and flags and performs the length checks below (`tailscale.com/net/packet/packet.go:104-160`, `:202-229`, `:271-365`).

| Format | Offset:length → meaning | Length and parsing conditions and source |
| --- | --- | --- |
| IPv4 | `0` high 4 bits version, low 4 bits×4 IHL. `2:2` total length. `6:2` MF=`0x2000` and offset=`&0x1fff`. `9:1` protocol. `12:4` source and `16:4` destination | Unknown if under 20 bytes, declared length exceeds the buffer, or IHL exceeds declared length. No minimum IHL check — `tailscale.com/net/packet/packet.go:132-178` |
| IPv6 | `0` high 4 bits version. `4:2` payload length (+40=total). `6:1` next-header. `8:16` source and `24:16` destination | Unknown if under 40 bytes or declared length exceeds the buffer — `tailscale.com/net/packet/packet.go:271-311` |
| TCP(6) | Transport header `0:2` source port, `2:2` destination port, `12` high 4 bits×4 header length, `13:1` flags | At least 20 bytes — `tailscale.com/net/packet/packet.go:202-212`, `:324-334` |
| UDP(17) and SCTP(132) | Transport header `0:2` source port and `2:2` destination port | At least 8 and 12 bytes, respectively — `tailscale.com/net/packet/packet.go:213-229`, `:335-350` |
| ICMPv4(1) and ICMPv6(58) | Transport header `0:1` type and `1:1` code, ports are 0 | The parser requires at least 4 bytes. Identifying echo or error requires 8 bytes — `tailscale.com/net/packet/packet.go:185-193`, `:316-323`, `:497-539` |
| TSMP(99) | Everything after the IP header is the TSMP payload | At least 7 bytes — `tailscale.com/net/packet/packet.go:230-242`, `:351-358`, `tailscale.com/net/packet/tsmp.go:23` |

Go's `Parsed` can use bytes beyond the declared IP length in `Buffer` and in transport header length checks. Only `Payload` is trimmed to the declared length. The WireGuard receive path trims the packet to IP length earlier, but `Parsed.Decode` by itself does not guarantee this for local input (`tailscale.com/net/packet/packet.go:161-162`, `:312-313`, `:461-478`, `wireguard-go/device/receive.go:497-528`). **Swiftail recommendation.** Validate declared length, IHL, and TCP header length at the input boundary, then trim and parse. Reset ports and flags for each packet. Do not carry over Go's reused fields or weak checks as safety requirements (Go field update scope `tailscale.com/net/packet/packet.go:104-123`, `:185-248`).

### 3.2 Fragments and IPv6 extension headers

| Condition | Actual Go result | Source |
| --- | --- | --- |
| First IPv4 fragment (offset 0) | For known protocols such as TCP and UDP, check minimum transport header length and read the ports | `tailscale.com/net/packet/packet.go:180-242` |
| IPv6 base next-header is 44 | Skip one 8-byte Fragment header. Inside, `0:1`=next-header and `2:2 >> 3`=offset. Check the transport header on the first fragment | `tailscale.com/net/packet/packet.go:307-311`, `:375-408` |
| Noninitial IPv4 or IPv6 fragment | Unknown if offset <10 blocks (80 bytes), otherwise use the internal `Fragment` marker. The filter performs no reassembly or first-fragment association check | `tailscale.com/net/packet/packet.go:249-267`, `:400-408`, `tailscale.com/wgengine/filter/filter.go:712-716` |
| MF on the first IPv4 TSMP fragment | Unknown. No equivalent check for MF in the IPv6 Fragment header | `tailscale.com/net/packet/packet.go:230-235`, `:351-358`, `:383-397` |
| Wire protocol 255 | Converted to Unknown by the switch for first-fragment and unfragmented parsing (distinct from internal Fragment) | `tailscale.com/net/packet/packet.go:243-248`, `:359-364` |

**Comment and code disagree.** The `decode6` comment says other extension headers are discarded as Unknown, but the actual switch has no such handling. Next-header 0 is dropped as Unknown (0). A value other than 0 that is absent from the switch, such as 43 or 60, remains and reaches the filter's other-protocol branch. A rule that names that number and covers the entire destination port range can allow it. The parser does not walk the extension header chain to read inner TCP ports (`tailscale.com/net/packet/packet.go:278`, `:302-365`, `tailscale.com/types/ipproto/ipproto.go:46-75`, `tailscale.com/wgengine/filter/filter.go:615-619`, `tailscale.com/wgengine/filter/match.go:89-107`).

**M3 recommendation.** Allowing noninitial fragments requires a receiving stack to perform reassembly. If the M3 in-memory test device does not support reassembly, explicitly drop all fragments and limit the gate to unfragmented packets. Record the difference from Go in tests (Go's reassembly assumption `tailscale.com/net/packet/packet.go:260-265`, `:293-300`, decision in §6.3).

### 3.3 Minimum TSMP formats

These messages use IP protocol 99. Offsets below are relative to the end of the IP header (`tailscale.com/net/packet/tsmp.go:66-81`).

| Type | Offset, length, and contents | Source |
| --- | --- | --- |
| `p` ping | `0:1`=`p`, `1:8` data to return unchanged. The parser accepts at least 9 bytes | `tailscale.com/net/packet/tsmp.go:214-233` |
| `o` pong | `0:1`=`o`, `1:8` ping data, `9:2` PeerAPI port. Send 11 bytes and also accept 9 on receive | `tailscale.com/net/packet/tsmp.go:235-273` |
| `!` rejection | `0:1`=`!`, `1:1` original protocol, `2:1` reason (`A` ACL or `S` shields-up), `3:2` original source port, `5:2` original destination port, optional `7:1` bit0=MaybeBroken | `tailscale.com/net/packet/tsmp.go:25-60`, `:91-107`, `:174-210` |
| `a` disco advertisement | `0:1`=`a`, `1:32` disco public key. The parser accepts at least 33 bytes | `tailscale.com/net/packet/tsmp.go:276-330` |

Go's pong swaps addresses, copies 8 bytes of ping data, and uses port 0 when there is no PeerAPI. TSMP rejections go from the original destination to the original source and keep the port fields in their original order (`tailscale.com/net/tstun/wrap.go:1216-1229`, `:1454-1475`).

## 4. Procedures and state machines

### 4.1 netmap peer → WireGuard configuration

Input is a normalized `Node`. If `AllowedIPs` is omitted or null in JSON, use a copy of `Addresses`. An empty array stays empty, and `UnsignedPeerAPIOnly` is forcibly narrowed to `Addresses`. Swiftail's `Node` performs the same normalization (`tailscale.com/control/controlclient/map.go:266-274`, `Sources/SwiftailControl/Tailcfg/Node.swift:123-124`, `:146-148`).

1. Identify the peer by NodeID and `Key`. `Key` is the WireGuard public key, distinct from `Machine` and `DiscoKey`. magicsock treats NodeID=0 or `Key`=0 as an error and creates no endpoint. **Swiftail recommendation.** Reject the peer at the engine input and remove any previously registered old key. RouteManager itself has no zero-key check, so AllowedIPs alone do not establish that the key is valid (`tailscale.com/tailcfg/tailcfg.go:388-395`, `tailscale.com/wgengine/magicsock/magicsock.go:3237-3251`, `tailscale.com/net/routemanager/routemanager.go:408-431`).
2. There are no candidate prefixes if `Expired`. There are also none if `DiscoKey`=0, `HomeDERP`=0, and `IsWireGuardOnly=false`. Otherwise, iterate **only `AllowedIPs`** (`tailscale.com/net/routemanager/routemanager.go:408-431`).
3. Classify each prefix `p` as self if `(p.IsSingleIP && IsTailscaleIP(p.Addr)) || Addresses.contains(p)`, or as route otherwise. Here self means **the peer's own address**, distinct from the local self node address. The `Addresses.contains(p)` branch does not require a single IP (`tailscale.com/net/routemanager/routemanager.go:422-429`).
4. Tailscale addresses are IPv4 `100.64.0.0/10` excluding `100.115.92.0/23` or IPv6 `fd7a:115c:a1e0::/48`. Unmap IPv4-mapped addresses. After unmapping a prefix's address, exclude each entry that still has host bits, leaving the other entries intact (`tailscale.com/net/tsaddr/tsaddr.go:23-36`, `:72-91`, `tailscale.com/net/routemanager/routemanager.go:665-687`).
5. Apply the eligibility conditions below, deduplicate, and sort. If the result is empty, omit the peer from WireGuard. Presence in `Addresses` alone does not add a prefix to AllowedIPs (`tailscale.com/net/routemanager/routemanager.go:260-297`, `:400-407`, `:827-840`).

| Classification | Condition for retaining in AllowedIPs | Source |
| --- | --- | --- |
| self | Always by default. IPv4 self is an exception when `DisableIPv4` is true (the current LocalBackend does not set this) | `tailscale.com/net/routemanager/routemanager.go:828-832`, `tailscale.com/ipn/ipnlocal/node_backend.go:954-960` |
| Routes exactly `0.0.0.0/0` or `::/0` | Resolved `ExitNodeID != 0` matching that peer ID. `RouteAll` alone does not permit them | `tailscale.com/net/routemanager/routemanager.go:833-837`, `tailscale.com/net/tsaddr/tsaddr.go:270-272` |
| Other routes | `RouteAll=true` | `tailscale.com/net/routemanager/routemanager.go:837` |
| Extra AllowedIPs from extension hooks | Add only for peers that already have a valid self/route contribution. Allow on receive without creating an OS route | `tailscale.com/net/routemanager/routemanager.go:681-684`, `:825-839`, `:853-855` |

| WireGuard configuration | Value and notes | Source |
| --- | --- | --- |
| Public key | Peer `Node.Key` | `tailscale.com/ipn/ipnlocal/resolve.go:29-51`, `tailscale.com/ipn/ipnlocal/node_backend.go:275-288` |
| AllowedIPs | Per-peer source address prefixes retained above. Do not narrow to prefixes of the outbound winner alone | `tailscale.com/net/routemanager/routemanager.go:282-296`, `:846-862` |
| PSK | Zero on this LocalBackend path. The PSK layer is not configured | `tailscale.com/ipn/ipnlocal/resolve.go:49-52`, `tailscale.com/wgengine/wgcfg/config.go:33-35` |
| PersistentKeepalive | 0 (disabled). The current `PeerConfig` and lazy creation path do not set it. This is separate from WireGuard data-driven keepalive | `tailscale.com/wgengine/wgcfg/config.go:28-35`, `wireguard-go/device/device.go:551-575`, `wireguard-go/device/peer.go:97`, `:134-135`, `wireguard-go/device/timers.go:110-116`, `:220-225` |
| endpoint | The **magicsock peer object** obtained by passing the public key's unprefixed hex string to `bind.ParseEndpoint`. Do not use `Node.Endpoints` or a DERP server IP as the WireGuard endpoint | `tailscale.com/wgengine/wgcfg/device.go:47-64`, `tailscale.com/wgengine/magicsock/magicsock.go:3943-3965` |

**Expiration.** If `KeyExpiry` is nonzero and `KeyExpiry <= controlNow` for the adjusted current time `controlNow = localNow + clockDelta`, Go sets `Expired=true`, `Endpoints=nil`, and `HomeDERP=0` and changes the public key to a deliberately broken value. Store the delta only when `abs(ControlTime-localNow) > 1 minute` and reset it to 0 otherwise. The check stops when the **adjusted current time** predates epoch `1673373066`. The age of the last `ControlTime` field itself is irrelevant (`tailscale.com/ipn/ipnlocal/expiry.go:23-28`, `:65-73`, `:92-135`). **Swiftail recommendation.** Compute expiration in the engine's derived state without modifying `Node`, remove the WireGuard peer and relay send eligibility, and recompute at the expiration deadline too. Go also computes the next expiration time (`tailscale.com/ipn/ipnlocal/expiry.go:139-181`).

### 4.2 Outbound peer selection and lazy configuration

Go's outbound selection is (1) exact match against a **single-IP `Addresses`** of self or any peer → (2) LPM on eligible routes → (3) silent drop on failure. The winner for the same prefix has the higher score, with ties going to the lower NodeID. The exact match path does not check AllowedIPs membership, but the subsequent peer configuration lookup filters out expired peers and peers without candidates (`tailscale.com/ipn/ipnlocal/node_backend.go:712-734`, `tailscale.com/ipn/ipnlocal/resolve.go:20-52`, `tailscale.com/net/routemanager/routemanager.go:846-862`, `wireguard-go/device/send.go:388-413`).

| Event | Go behavior | Source |
| --- | --- | --- |
| Outbound send or inbound initiation looks up a peer key | If missing, look up live `peerConfig` and create the peer. Receive alone can trigger creation | `wireguard-go/device/device.go:542-575`, `wireguard-go/device/noise-protocol.go:386-389` |
| `SyncDevicePeer` on netmap change | Remove if configuration is unavailable. If the peer exists, update only AllowedIPs and PSK. **Do not create a missing peer** | `tailscale.com/wgengine/userspace.go:698-717` |
| Lazy peer creation | `deleteOnIdle=true`. Start a 540-second cleanup timer at startup | `wireguard-go/device/device.go:568`, `wireguard-go/device/peer.go:310-316` |
| Session key derivation | Reset the cleanup timer to 540 seconds | `wireguard-go/device/timers.go:206-214` |
| Handshake give-up | Set a 540-second cleanup timer **only if none exists yet**. Do not extend a running timer | `wireguard-go/device/timers.go:80-98` |
| Cleanup timer expiration | Clear keys and remove the `deleteOnIdle` peer | `wireguard-go/device/timers.go:127-138` |

**M3 design choice.** Lazy creation and idle peer removal are not wire requirements for interop. This follows from creation timing being decided by a local lookup callback in a design that also has a regular `NewPeer`. The recommendation is to `addPeer` every valid peer when applying the netmap and synchronize deletions, expirations, and AllowedIPs changes. Swiftail requires peer registration before receiving, and its 540-second timer only clears keys (`wireguard-go/device/device.go:542-575`, `wireguard-go/device/peer.go:117-170`, `Sources/SwiftailWireGuard/WireGuardDevice.swift:57-78`, `Sources/SwiftailWireGuard/WireGuardDevice+Receiving.swift:35-43`, `Sources/SwiftailWireGuard/WireGuardDevice+Timers.swift:57-59`).

### 4.3 Engine → DERP/magicsock boundary

| Information extracted from netmap | Purpose and M3/M4 boundary | Source |
| --- | --- | --- |
| `Node.ID` and `Key` | Peer identity. Also remove the old key's relay route on key rotation or deletion | `tailscale.com/wgengine/magicsock/magicsock.go:3192-3198`, `:3237-3251` |
| Peer `HomeDERP`, global `DERPMap` | Region ID → DERP server connection information. HomeDERP=0 means unknown. Update the DERP map separately from the self/peer list | `tailscale.com/tailcfg/tailcfg.go:418-423`, `tailscale.com/ipn/ipnlocal/local.go:2094-2109`, `tailscale.com/wgengine/magicsock/endpoint.go:1733-1752` |
| `DiscoKey`, `Endpoints`, `Cap`, and `Expired` | Disco key, direct UDP candidates, peer relay support, and expiration state. M3 can leave direct UDP candidates unused while keeping these fields distinct from WireGuard keys | `tailscale.com/wgengine/magicsock/endpoint.go:1717-1759` |
| Self addresses, own node private key, and disco private key | TSMP advertisement address selection, DERP authentication, and disco. Prepare DERP before applying the private key to WireGuard | `tailscale.com/wgengine/magicsock/magicsock.go:4631-4665`, `tailscale.com/wgengine/userspace.go:886-899` |
| `IsJailed` and masquerade addresses | Inputs for engine filter selection and SNAT/DNAT. Separate from direct path discovery | `tailscale.com/net/tstun/wrap.go:667-687`, `:707-731` |

RouteManager eligibility differs from magicsock endpoint eligibility. For example, `HomeDERP != 0` alone can qualify for RouteManager, but magicsock does not support a non-WireGuard-only peer with `DiscoKey=0`. It also does not create an endpoint for a zero node key (`tailscale.com/net/routemanager/routemanager.go:416-421`, `tailscale.com/wgengine/magicsock/magicsock.go:3242-3244`, `:3258-3267`, `:3305-3308`). **M3 recommendation.** Support only ordinary Go tsnet peers and valid HomeDERP/DERPMap. Explicitly reject unsupported modes such as WireGuard-only and masquerade. Leave detailed path selection and DERP return-route to the contract in another note.

### 4.4 `FilterRule` → match rules

Swiftail's `Netmap.packetFilter` is already a list of **raw `FilterRule`** with named groups concatenated. The engine parses strings such as `SrcIPs`. Go control retains the conversion result after the same merge (`Sources/SwiftailControl/Netmap/Netmap.swift:16-17`, `Sources/SwiftailControl/Tailcfg/FilterRule.swift:5-9`, `tailscale.com/control/controlclient/map.go:449-480`).

1. If `SrcBits` is nonempty or `DstPorts[].Bits != nil`, **the entire conversion returns nil + an error**. The Go caller logs the error and installs the nil result. Swiftail should also avoid retaining the previous broad allow rules on failure (`tailscale.com/wgengine/filter/tailcfg.go:38-40`, `:75-78`, `tailscale.com/control/controlclient/map.go:475-480`).
2. If `IPProto` is nil or an empty array, use `{6,17,1,58}` (TCP, UDP, ICMPv4, ICMPv6). For an explicit array, retain only 0...255. If every entry is out of range, the result is an empty protocol set and does not fall back to the default set (`tailscale.com/wgengine/filter/tailcfg.go:21-26`, `:50-60`).
3. Parse each string in `SrcIPs` and `DstPorts[].IP` in the order below. The source list is an OR, with no source port condition (`tailscale.com/wgengine/filter/tailcfg.go:62-96`, `:138-180`, `tailscale.com/wgengine/filter/match.go:17-53`).
4. Pair each destination prefix with the original `Ports.First...Last` to create `Dsts`. Both ends of the range are inclusive, and First>Last matches no ports (`tailscale.com/wgengine/filter/tailcfg.go:88-96`, `tailscale.com/wgengine/filter/filtertype/filtertype.go:21-40`).
5. `CapGrant` converts `Dsts × (each entry in Caps and CapMap)` into a capability list. Deprecated `Caps` has no values, and `CapMap` has lists of JSON values. This is separate from allowing packets. The schema prohibits `DstPorts` and `CapGrant` from both being non-nil, but the conversion function does not enforce mutual exclusion (`tailscale.com/wgengine/filter/tailcfg.go:75-114`, `tailscale.com/tailcfg/tailcfg.go:1580-1595`, `:1750`, `:1764-1774`).
6. Split source and destination prefixes by IPv4 and IPv6. Keep only packet rules where `(Srcs is present or SrcCaps is present) && Dsts is present`. Keep capability rules only when there are **Srcs** for the family and capability entries (`tailscale.com/wgengine/filter/filter.go:267-312`).

| String | Interpretation and errors | Source |
| --- | --- | --- |
| `*` | Both IPv4 /0 and IPv6 /0 | `tailscale.com/wgengine/filter/tailcfg.go:138-145` |
| `cap:<name>` | Node capability name in SrcCaps. A nonempty destination capability produces an error and drops that entry. Empty `cap:` yields no result | `tailscale.com/wgengine/filter/tailcfg.go:69-71`, `:84-87`, `:146-148` |
| Contains `/` | CIDR. Remaining host bits produce an error without silent masking | `tailscale.com/wgengine/filter/tailcfg.go:149-157` |
| Exactly one `-` | Inclusive IP range in the same address family. Reversed or invalid ranges produce an error. Valid ranges decompose into prefixes | `tailscale.com/wgengine/filter/tailcfg.go:159-173` |
| Otherwise | Single IP → /32 or /128 | `tailscale.com/wgengine/filter/tailcfg.go:175-179` |

Address expression errors preserve the other convertible entries. Go normally keeps the first error, but **a destination capability error can overwrite an existing error**. Conversion does not atomically drop a whole rule, and only some errors give an overall nil result (`tailscale.com/wgengine/filter/tailcfg.go:30-33`, `:62-86`, `:116-118`).

| Match function | Condition | Source |
| --- | --- | --- |
| `match` (TCP SYN, UDP, SCTP) | In the same rule, protocol matches AND (source address∈Srcs OR source node capability∈SrcCaps) AND the address and destination port match a Dst. Allow rules are evaluated as a union, with no deny rules or priorities | `tailscale.com/wgengine/filter/match.go:17-53` |
| `matchIPsOnly` (ICMP) | Ignore protocol and port. Allow if Srcs and Dsts addresses match. A separate SrcCaps path allows a matching capability alone, without rechecking destination | `tailscale.com/wgengine/filter/match.go:62-84` |
| Other protocols | Protocol, Srcs, and destination address match, and Ports is exactly `0...65535`. **Does not check SrcCaps** | `tailscale.com/wgengine/filter/match.go:89-107` |

SrcCaps lookup uses `Addresses`'s single-IP → node index and treats `UnsignedPeerAPIOnly` as false. Addresses behind a subnet do not inherit the capability. Rules containing only CapGrant do not contribute to packet allows (`tailscale.com/ipn/ipnlocal/node_backend.go:719-734`, `tailscale.com/ipn/ipnlocal/local.go:9318-9334`, `tailscale.com/wgengine/filter/filter.go:267-312`).

Capability lookup `CapsWithValues(src,dst)` matches Srcs and the destination prefix and accumulates JSON value lists for the same capability. Capability lookup does not use SrcCaps, protocol, or port conditions. Node capability lookup checks whether the key exists in `CapMap` (`tailscale.com/wgengine/filter/filter.go:294-312`, `:410-434`, `tailscale.com/tailcfg/tailcfg.go:574-575`).

### 4.5 Filter installation and state

1. Before netmap, install `NewAllowNone` (no rules or localNets). A nil filter also Drops both inbound and outbound packets (`tailscale.com/ipn/ipnlocal/local.go:3533-3538`, `tailscale.com/wgengine/filter/filter.go:199-201`, `tailscale.com/net/tstun/wrap.go:820-822`, `:1190-1192`).
2. The recommended M3 design derives `localNets` only from self `Addresses`. Go also includes hosted VIPs, advertised routes, and app connector addresses, which are outside the M3 gate (`tailscale.com/ipn/ipnlocal/local.go:3452-3511`, `docs/plan.md:193`).
3. If prefs are invalid or ShieldsUp is set, install a shields-up filter with no rules. Otherwise, install the converted rules. Use a separate shields-up filter for jailed peers (`tailscale.com/ipn/ipnlocal/local.go:3446`, `:3541-3555`).
4. If any packet allow rule (with Dsts) has Srcs intersecting an `UnsignedPeerAPIOnly` peer's AllowedIPs, clear all packet rules. This safeguard does not check SrcCaps (`tailscale.com/ipn/ipnlocal/local.go:3459-3463`, `:3568-3598`).
5. Regular filter replacement shares prior UDP/SCTP state. A new shields-up filter shares it only if the previous filter was also shields-up. Keep the jailed cache separate from the regular cache (`tailscale.com/wgengine/filter/filter.go:204-234`, `tailscale.com/ipn/ipnlocal/local.go:3553-3555`).

Go selects the jailed filter using the `Jailed` value from an LPM lookup in the peer routing table by inbound **source IP** or outbound **destination IP**. WireGuard verifies the actual peer source before this selection (`tailscale.com/net/tstun/wrap.go:667-687`, `:812-819`, `:1184-1189`, `wireguard-go/device/receive.go:510-528`).

The cache key is `(IPProto, srcIP, srcPort, dstIP, dstPort)` and the LRU holds at most 512 entries. Insert the **reverse tuple** of outbound UDP/SCTP and look it up on receive. Lookups also update recency. There is no TTL. Inbound acceptance itself adds no entry. TCP and ICMP connection state are not stored in this cache (`tailscale.com/wgengine/filter/filter.go:102-109`, `:538-550`, `:600-611`, `:625-650`, `tailscale.com/net/flowtrack/flowtrack.go:22-44`, `:102-151`).

### 4.6 Packet verdicts and source validation

**Layer order.** WireGuard authentication and replay protection → trim IP length and **check source against that authenticated peer's AllowedIPs** → DNAT when needed → engine control packets such as TSMP → receive filter → netstack or TUN. A DERP frame's source key or an ACL rule alone cannot replace WireGuard source validation (`wireguard-go/device/receive.go:465-539`, `tailscale.com/net/tstun/wrap.go:1270-1277`, `:1128-1254`).

The common `pre` for `RunIn` and `RunOut` returns the first verdict in the following order (`tailscale.com/wgengine/filter/filter.go:688-720`).

| Order | Condition | Verdict and source |
| --- | --- | --- |
| 1 | Length 0 | Accept. Actual WireGuard keepalives are consumed by the device and do not reach the stack — `tailscale.com/wgengine/filter/filter.go:689-691`, `wireguard-go/device/receive.go:491-494` |
| 2 | Length <20 | Drop — `tailscale.com/wgengine/filter/filter.go:693-696` |
| 3 | Unknown(0) | Drop — `tailscale.com/wgengine/filter/filter.go:698-701` |
| 4 | Multicast destination | Drop — `tailscale.com/wgengine/filter/filter.go:703-706` |
| 5 | Link-local unicast destination | Drop except for `169.254.169.254` or an extension hook exception — `tailscale.com/wgengine/filter/filter.go:672-684`, `:707-710` |
| 6 | Internal Fragment marker | Accept. **Before localNets and ACL** — `tailscale.com/wgengine/filter/filter.go:712-716` |

Receive then selects the IP family and first checks whether the destination is in localNets. If outside, the result is noVerdict. If the checks below also yield noVerdict, Go tries IngressAllowHooks before a final Drop. M3 recommends Drop without hooks. An ordinary packet destined outside self is therefore dropped even with an allowing ACL. **Noninitial fragments and TSMP consumed earlier are separate cases** (`tailscale.com/wgengine/filter/filter.go:443-471`, `:502-509`, `:564-570`, `tailscale.com/net/tstun/wrap.go:1133-1157`).

| Protocol | Inbound verdict after localNets check | Source |
| --- | --- | --- |
| ICMPv4 and ICMPv6 | Accept echo replies and errors without checking state. Otherwise, Accept if `matchIPsOnly` | `tailscale.com/wgengine/filter/filter.go:510-522`, `:572-584` |
| TCP | Only packets with SYN=1 AND ACK=0 use `match`. Accept SYN-ACK, ACK, RST, and other non-SYN packets. **Acceptance does not depend on TCP session tracking** | `tailscale.com/wgengine/filter/filter.go:523-537`, `:585-599`, `tailscale.com/net/packet/packet.go:491-495` |
| UDP and SCTP | Accept on a cache hit OR `match` | `tailscale.com/wgengine/filter/filter.go:538-550`, `:600-612` |
| TSMP | Accept if it reaches the filter | `tailscale.com/wgengine/filter/filter.go:551-552`, `:613-614` |
| Other | Accept under the other-protocol conditions in §4.4 | `tailscale.com/wgengine/filter/filter.go:553-559`, `:615-621` |

ICMP echo uses type/code 8/0 for v4 and 128/0 for v6. Echo reply uses 0/0 for v4 and 129/0 for v6. Go's error type sets are `{3,11,0x12}` for v4 and `{1,2,3,4}` for v6. `0x12` is the source constant verbatim. Standards conformance is left to §8 (`tailscale.com/net/packet/icmp4.go:22-26`, `tailscale.com/net/packet/icmp6.go:22-27`, `tailscale.com/net/packet/packet.go:497-539`).

**Outbound.** The upstream TUN wrapper first drops host-originated TSMP and its own disco UDP. `RunOut` then Accepts everything that passes `pre` without applying the ACL's SrcIPs and DstPorts in reverse. Record reverse UDP/SCTP state before SNAT. **In-process stack injection skips `RunOut` but must record the same state.** Record outbound traffic to jailed peers in the jailed filter's cache so the same filter allows the response (`tailscale.com/net/tstun/wrap.go:771-788`, `tailscale.com/wgengine/filter/filter.go:476-487`, `:625-650`, `tailscale.com/net/tstun/wrap.go:812-832`, `:932-934`, `:1052-1072`, `:1099`).

**Rejection response.** Go filter rejection does not generate TCP RST. If `IPv4 && TCP && SYN bit set && !disableTSMPRejected`, send TSMP `!`. This condition includes SYN-ACK and differs from `IsTCPSyn`. A packet with the SYN bit set for a PeerAPI port can be Accepted by an L7 inspection exception after rejection. The M3 recommendation is to keep PeerAPI closed, omit outbound TSMP rejection, and always drop the original packet (`tailscale.com/net/tstun/wrap.go:1195-1236`).

### 4.7 In-process receive for UDP, TCP, and ping

Go netstack is installed at `PostFilterPacketInboundFromWireGuard`. With the default fake TUN, tsnet enables `ProcessLocalIPs=true` and `ProcessSubnets=true`. It registers self addresses from netmap on the stack NIC and uses the self `Addresses` set to decide whether an address is local (`tailscale.com/wgengine/netstack/netstack.go:465-466`, `:729-770`, `:810-825`, `tailscale.com/tsnet/tsnet.go:916-933`).

1. Pass only packets that have passed decryption, source validation, and the receive filter into this boundary. If `ProcessLocalIPs && isLocal`, netstack handles the packet regardless of protocol. PeerAPI, service, and 4via6 interception and `ProcessSubnets` have separate conditions and are unnecessary for the M3 self-address UDP/TCP gate (`tailscale.com/net/tstun/wrap.go:1193-1252`, `tailscale.com/wgengine/netstack/netstack.go:1279-1357`).
2. Drop silently if not ready or shutting down. Deliver eligible packets to the link endpoint and use `DropSilently` to prevent duplicate delivery to TUN (`tailscale.com/wgengine/netstack/netstack.go:1472-1513`).
3. Send receive-stack responses through the WireGuard-bound queue → `InjectOutboundPacketBuffer`. This path also records UDP state per §4.6 and selects the peer by destination (`tailscale.com/wgengine/netstack/netstack.go:1047-1083`, `tailscale.com/net/tstun/wrap.go:1052-1072`, `wireguard-go/device/send.go:388-413`).

| Packet received at a self address | Where Go tsnet responds and under what conditions | Implication for the M3 gate and source |
| --- | --- | --- |
| UDP | `ListenPacket` registers a gVisor UDP endpoint. The UDP forwarder looks up the tsnet handler for an unregistered flow and closes and consumes it with no listener. There is no automatic echo | The **test app or peer listener** implements UDP echo. The forwarder returns true to avoid sending ICMP port-unreachable for unhandled UDP — `tailscale.com/tsnet/tsnet.go:1305-1310`, `:1392-1420`, `tailscale.com/wgengine/netstack/netstack.go:2000-2010`, `:2054-2067` |
| TCP SYN with a matching listener or handler | Creating a TCP endpoint starts the handshake. After it completes, provide the connection to the handler | Expect SYN-ACK only with a listener on the allowed port — `tailscale.com/tsnet/tsnet.go:1289-1302`, `tailscale.com/wgengine/netstack/netstack.go:1662-1673`, `:1712-1719`, `:1748-1760` |
| TCP SYN with no listener or fallback | tsnet returns `(nil,true)`, prompting a call to `Complete(true)` → RST | Test **ACL blocking (Drop before the stack)** and **a closed port (stack RST)** separately — `tailscale.com/tsnet/tsnet.go:1289-1300`, `tailscale.com/wgengine/netstack/netstack.go:1748-1753`, `:1607-1611`, `tailscale.com/net/tstun/wrap.go:1206-1236` |
| ICMP echo request | Tailscale addresses are excluded from subnet ping proxying and reach gVisor. The IPv4 and IPv6 stacks create an echo reply unless another handler or similar consumer takes the packet | Distinguish ACL acceptance from reply generation for ping. **Filter Accept itself does not generate an echo reply** — `tailscale.com/wgengine/netstack/netstack.go:1484-1505`, `:1570-1584`, `gvisor/pkg/tcpip/network/ipv4/icmp.go:346-380`, `gvisor/pkg/tcpip/network/ipv6/icmp.go:655-678` |

**M3 design recommendation.** Do not add a complete TCP/UDP stack to Swiftail. Provide an in-memory packet boundary and verify the gate with UDP echo and TCP listeners on the Go tsnet side. If the gate also includes Swiftail receive responses, attach a test-only UDP echo and TCP SYN responder to the boundary. The actual public listen/dial stack is in M6 (`docs/plan.md:57`, `:193-196`).

### 4.8 TUN and router configuration (M5, skipped in M3)

On local outbound TUN, the wrapper injects local replies to ICMP echo for service IPs `100.100.100.100` and `fd7a:115c:a1e0::53`, and netstack absorbs all protocols and ports on those two IPs. On darwin/ios, the engine reflects packets destined for its own tunnel address back to the OS. Netstack's own outbound traffic to self uses a separate loopback queue (`tailscale.com/net/tstun/wrap.go:752-769`, `tailscale.com/wgengine/netstack/netstack.go:866-896`, `:1047-1060`, `tailscale.com/wgengine/userspace.go:652-667`).

1. `LocalAddrs` lists self `Addresses` after Unmap. `Routes` sorts the set derived from eligible peer-contributed prefixes by the rules below (`tailscale.com/ipn/ipnlocal/local.go:6710-6716`, `:6800-6810`, `tailscale.com/ipn/ipnlocal/node_backend.go:988-996`).
2. If self has IPv4, add `100.100.100.100/32`. If it has IPv6, add `fd7a:115c:a1e0::53/128`. Append hosted VIPs when an address of the same family exists (`tailscale.com/ipn/ipnlocal/local.go:6773-6790`).
3. If an exit node is selected, retain both /0 routes in the OS to blackhole traffic even if no peer is routable. LAN and local route adjustments also exist. The recommended design for M3 and baseline M5 keeps exit node functionality unexposed (`tailscale.com/net/routemanager/routemanager.go:1009-1014`, `tailscale.com/ipn/ipnlocal/local.go:6726-6771`).
4. Call the router callback only on change. Go's `Config.Equal` compares order as well. Pass CallbackRouter's `InitialMTU` as `NewMTU` only on the first Set, with 0 meaning no change. **Recommendation.** Keep Swiftail's output list order stable too (`tailscale.com/wgengine/router/router.go:123-126`, `:145-152`, `tailscale.com/wgengine/router/callback.go:27-31`, `:45-67`).

| Eligible prefix classification | OS Routes | Source |
| --- | --- | --- |
| Single IPv4 within CGNAT | Individual /32s by default. One /10 if the count of unique prefixes exceeds 10,000. OneCGNAT=true sets the threshold to 1 (/10 starting at 2) | `tailscale.com/net/routemanager/routemanager.go:148`, `:874-891`, `:959-972` |
| Single IPv6 within Tailscale ULA | One /48 instead of individual /128s if there is at least one eligible contribution | `tailscale.com/net/routemanager/routemanager.go:881-883`, `:934-957` |
| Other | Eligible prefixes unchanged, excluding extra AllowedIPs | `tailscale.com/net/routemanager/routemanager.go:846-884`, `:948-952` |

OS aggregation is computed from **peer contributions**. The self address alone does not create a /48 route. Do not use the OS /10 and /48 aggregates for WireGuard AllowedIPs. The CGNAT aggregation check includes the ChromeOS range, which `IsTailscaleIP` excludes when classifying self addresses (`tailscale.com/net/routemanager/routemanager.go:282-296`, `:408-431`, `:874-883`, `:986-1025`, `tailscale.com/net/tsaddr/tsaddr.go:83-90`).

For `OneCGNAT`, control instructions take precedence. It is true on plan9, true on macOS and android when no other CGNAT interface exists, and false elsewhere (including iOS). The **iOS default is therefore individual /32s**. controlknobs parses `one-cgnat?v=true/false` (`tailscale.com/ipn/ipnlocal/local.go:6364-6398`, `tailscale.com/control/controlknobs/controlknobs.go:190-193`, `tailscale.com/tailcfg/nodecap/nodecap.go:148-153`).

## 5. Constants and timers

| Item | Value | Source |
| --- | --- | --- |
| Filter cache | 512-entry LRU with no TTL | `tailscale.com/wgengine/filter/filter.go:102-109`, `tailscale.com/net/flowtrack/flowtrack.go:102-151` |
| Minimum noninitial fragment offset | 10×8=80 bytes | `tailscale.com/net/packet/packet.go:25`, `:251-266`, `:403-407` |
| Lazy peer cleanup | 540 seconds (RejectAfterTime×3). See §4.2 for startup, key derivation, and give-up conditions | `wireguard-go/device/constants.go:22`, `wireguard-go/device/peer.go:314-315`, `wireguard-go/device/timers.go:95-96`, `:214` |
| Clock delta storage | Absolute difference **greater than 1 minute** | `tailscale.com/ipn/ipnlocal/expiry.go:28`, `:65-73` |
| Default safe TUN MTU | 1280 when no other information is available | `tailscale.com/net/tstun/mtu.go:76-79` |
| OS CGNAT aggregation | More than 10,000 by default, more than 1 for OneCGNAT | `tailscale.com/net/routemanager/routemanager.go:148`, `:887-891`, `:959` |

Follow the verified table in [wireguard.md](wireguard.md) for WireGuard rekey, handshake retry, and keepalive timers. Do not change the retry cutoff to "exactly 90 seconds later" based on one retry constant. Actual termination depends on attempt count and jitter (`wireguard-go/device/constants.go:17-25`, `wireguard-go/device/timers.go:80-106`, `:185-192`).

## 6. Minimum Swiftail requirements and optional parts

### 6.1 Recommended M3 procedure

This is the **proposed engine contract**. Go's ownership structure and callback names do not need to be reproduced (I/O-free WireGuard contract `docs/contracts/SwiftailWireGuard.md:3-13`, gate `docs/plan.md:193`).

1. Take `Netmap` and a time, then compute §4.1 eligibility and AllowedIPs, the self destination set, the address → peer/key index, and the §4.4 filter as values. Fix the scope at `RouteAll=false` with no exit node. Explicitly declare WireGuard-only, masquerade, and tailnet lock unsupported (fields `Sources/SwiftailControl/Netmap/Netmap.swift:22-25`, `Sources/SwiftailControl/Tailcfg/Node.swift:69-76`, computation basis §4.1 and §4.3).
2. Have one engine owner serialize packet processing, calling `removePeer` for deleted, rotated-key, and expired peers, and `addPeer` for valid peers. Updating AllowedIPs for an existing key preserves the session. Prepare relay region and peer information before releasing handshake output (`Sources/SwiftailWireGuard/WireGuardDevice.swift:57-78`, Go ordering `tailscale.com/wgengine/magicsock/magicsock.go:3957-3962`, `tailscale.com/wgengine/userspace.go:886-899`).
3. Feed WireGuard bytes from DERP into the device. Send only the device's `ipPacket` to the §4.6 receive filter and pass only Accept to the in-memory packet boundary. Use separate regular and jailed filters, and resolve noVerdict to Drop (output contract `Sources/SwiftailWireGuard/WireGuardDevice.swift:18-31`, verdict basis §4.5–4.7).
4. For local packets, validate structure → handle special destinations locally → apply the §4.6 outbound verdict and record state → select the peer in §4.2 → call `send`. Forward `.datagram(to:)` over the DERP path corresponding to the public key. Apply netmap, expiration, and filter updates under the same owner (device boundary `docs/contracts/SwiftailWireGuard.md:70-101`, Go injection and ordering §4.3 and §4.6).
5. Use `nextDeadline` to schedule calls to `advance`. Assign TCP SYN-ACK and UDP echo response generation to the receiving device or test peer as in §4.7. Keep the response stack out of the filter (`Sources/SwiftailWireGuard/WireGuardDevice.swift:80-82`, `docs/contracts/SwiftailWireGuard.md:113`, Go basis §4.7).

### 6.2 Items deferred to M5 or assigned to a separate milestone

| Item | Scope and rationale for omission | Source |
| --- | --- | --- |
| Address, OS route, and DNS settings, utun, self-address reflection, and local service IP handling | M5. Derive settings using §4.8 and combine MagicDNS UDP responses with the dns-state-node note | `docs/plan.md:195`, `tailscale.com/net/tstun/wrap.go:752-769`, `tailscale.com/wgengine/netstack/netstack.go:875-896` |
| Direct UDP candidates and disco discovery | M4. M3 is DERP-only | `docs/plan.md:193-194` |
| Public TCP/UDP listen and dial and a complete reassembly stack | M6. Verify the M3 gate with an in-memory packet boundary and Go tsnet listeners | `docs/plan.md:57`, `:193-196` |
| Accepting and offering subnets and exit nodes, VIP and 4via6, app connectors | Recommended as unsupported in M3 and baseline M5. False prefs and no advertisements make these routes unnecessary | `tailscale.com/net/routemanager/routemanager.go:827-839`, `tailscale.com/ipn/ipnlocal/local.go:3470-3511` |
| Lazy creation and idle peer removal | Can be omitted in M3 (§4.2). Review again during M5 memory measurements | `wireguard-go/device/device.go:542-575`, `docs/plan.md:199` |
| TSMP ping/pong, rejection, and advertisement | For diagnostic ping and disco updates. The design allows omitting outbound messages for the UDP/TCP gate. Consume inbound messages separately from app IP input, and implement §3.3 pong if providing ping diagnostics | `tailscale.com/wgengine/userspace.go:1272-1298`, `tailscale.com/net/tstun/wrap.go:1133-1157`, `:1454-1475`, `tailscale.com/wgengine/magicsock/magicsock.go:4631-4677` |
| Public WhoIs and PeerCaps APIs | M7. Preventing CapGrant from being misinterpreted as packet permission is required starting in M3 | `docs/plan.md:197`, `tailscale.com/wgengine/filter/filter.go:267-312`, `:410-434` |
| Log rate limiting, flow logs, pendopen, and PeerAPI exceptions | Optional for the M3 gate. This does not justify omitting Drop verdicts or the cache | `tailscale.com/wgengine/filter/filter.go:326-327`, `tailscale.com/net/tstun/wrap.go:1178-1204` |

Go consumes TSMP ping and disco advertisements before the receive filter, but pong can continue after the callback. **Swiftail recommendation.** Consume all TSMP in the engine without passing it to the ordinary app stack. Do not interpret Go as "always consuming all TSMP" (`tailscale.com/net/tstun/wrap.go:1133-1157`, `tailscale.com/wgengine/filter/filter.go:551-552`).

### 6.3 Decisions for the lead session to make in the contract

| Decision | Options | Recommendation |
| --- | --- | --- |
| Peer lifetime | Preregister on each netmap / Go-style lazy creation | Preregister in M3. Apply deletions and expirations immediately. Review after measuring memory in M5 (§4.2) |
| Gate responder | Go tsnet listener + Swift in-memory input / also add a Swift test responder | Add the test responder for a bidirectional gate. The public TCP stack is M6 (§4.7) |
| Fragments and IPv6 extension headers | Reproduce Go filter behavior / explicitly Drop unsupported packets | Devices without reassembly in M3 explicitly Drop fragments and extension headers, starting with an unfragmented UDP/TCP gate. Record the difference in the contract (§3.2) |
| Control packets | Consume TSMP only / also send pong and rejection | Consume in M3, add pong when testing diagnostics, and send rejections and advertisements later (§3.3 and §6.2) |
| Where to check invalid raw CIDRs | control decoding / engine | Check FilterRule strings in the engine. The current Node prefix type has already cleared original host bits, so the lead session decides whether to change the control boundary (§8.1) |
| Delivering server time samples | Estimate from netmap arrival time / deliver ControlTime and actual receive time separately | Prefer the second option. Avoid recomputing delta from a stale stored ControlTime each time (§8.1) |
| Recovery after a disco key change | Remove and register the peer again / add a WireGuard API to schedule a fresh handshake | In M3, use removal and re-registration on change as an explicit simplification. Review a Go-style scheduling API in M4 (§8.1) |

## 7. What to verify in interop tests

These **planned tests have not been run yet**. Parentheses give source evidence for the expected results.

1. **DERP-only gate.** Block direct UDP and use only local DERP. Round-trip data to a Go tsnet UDP echo listener, and send SYN to a TCP listener and receive SYN-ACK. Test IPv4 and IPv6 separately and repeat in reverse if attaching a Swift receive device (`docs/plan.md:193`, §4.3 and §4.7).
2. **ACL and closed ports.** Distinguish SYN-ACK from an allowed TCP listener, silence/Drop on an ACL-blocked port, and RST from an ACL-allowed Go port without a listener. TSMP `!` is an optional diagnostic, so it is not a required expectation (`tailscale.com/net/tstun/wrap.go:1193-1236`, `tailscale.com/wgengine/netstack/netstack.go:1748-1753`, `tailscale.com/tsnet/tsnet.go:1289-1300`).
3. **Filter conversion.** Test SrcIPs `*`, CIDR, single IP, range, and cap, both port endpoints, empty IPProto, explicit protocols, out-of-range numbers, and invalid CIDR, SrcBits, and DstBits. A rule with only CapGrant must not open UDP/TCP (§4.4).
4. **UDP response state.** An exact reverse response to UDP that Swift sent first passes even with no allow rules. A different port, address, or protocol fails. Test ordinary send and stack injection. Check the 513th LRU insertion, lookup order, rule replacement, switching to shields-up, and a separate jailed cache (§4.5 and §4.6).
5. **TCP and ICMP verdicts.** Drop disallowed SYN. SYN-ACK, ACK, and RST for the same self destination pass the filter without TCP state. ICMP echo from a source allowed on only one TCP port also passes via the IP-only rule, and echo replies and errors pass without a cache. Distinguish passage from actual ping reply generation (§4.6 and §4.7).
6. **Source and destination spoofing.** If a peer with a valid session sends a source outside AllowedIPs, reject it before ACL evaluation. Reject a destination outside self addresses even with a broad ACL. Check fragment and TSMP exceptions or Swiftail's explicit Drop policy separately (§3.2 and §4.6).
7. **Peer updates.** Test expiration boundary `==`, `<`, and `>`, nonexpiring, clock differences of ±60 seconds and beyond, zero node key, no candidates, empty AllowedIPs, deletion, key rotation, and recovery. Verify that `RouteAll=false` does not accept subnets or /0 as sources (§4.1). The old key must not be mistakenly reused as the new key (`tailscale.com/net/routemanager/routemanager.go:626-647`).
8. **shields-up and jailed.** Drop new SYN and unregistered UDP and accept replies to UDP sent first and non-SYN packets. Do not deliver normal app packets during startup without a filter. Test Go's empty-buffer and noninitial-fragment `pre` exceptions separately (§4.5 and §4.6).
9. **Optional TSMP gate.** If ping/pong is implemented, test copying the 8-byte data, a PeerAPI port of 0, and short input. Verify that disco advertisements are not mistakenly delivered as UDP echo (§3.3 and §6.2).
10. **M5 settings.** Verify individual /32s on iOS, /48 when an eligible ULA peer exists, service routes by self address family, OneCGNAT thresholds, no changes for identical netmap, route removal after deletion, self-address reflection, and preventing service IP leaks (§4.8).

## 8. Unverified items and verification limits

### 8.1 Implementation boundaries for the lead session

- **Host bits in original Node prefixes.** Go excludes noncanonical AllowedIPs, but Swift `IPPrefix` already masks them at creation. An engine receiving only `Netmap` cannot recover whether the original was noncanonical. This was outside the assigned scope and was not changed. FilterRule IP strings are retained and can be checked by the engine (`tailscale.com/net/routemanager/routemanager.go:665-672`, `Sources/SwiftailBase/IPPrefix.swift:12-28`, `Sources/SwiftailControl/Tailcfg/Node.swift:123-124`, `Sources/SwiftailControl/Tailcfg/FilterRule.swift:13-22`).
- **Fresh handshake on disco key change.** When a nonzero disco key changes, Go schedules a handshake after the next user transport send. The actual call does not immediately remove the peer or flush keypairs. Swift WireGuard currently has no corresponding public API, so the lead session must decide between re-registration and adding an API (`tailscale.com/ipn/ipnlocal/node_backend.go:899-911`, `tailscale.com/wgengine/userspace.go:719-725`, `wireguard-go/device/device.go:765-782`, `Sources/SwiftailWireGuard/WireGuardDevice.swift:57-82`).
- **Observation time for ControlTime.** Go computes the delta from local time on receiving a ControlTime event. Swift's current `MapSession` stores only the last ControlTime and emits no netmap when that alone changes. `ControlClient.Event` also has no separate time event. If the engine treats the stored time in a netmap it receives later as "current server time," it can adjust incorrectly. The lead session must decide the boundary for delivering it with the actual receive time (`tailscale.com/ipn/ipnlocal/expiry.go:56-73`, `Sources/SwiftailControl/Netmap/MapSession.swift:43-49`, `:82-88`, `Sources/SwiftailControl/Client/ControlClient.swift:40-49`).

### 8.2 Unverified scope

- **Runtime evidence.** This verification compared pinned source versions and checked references. Swift builds, unit tests, Go tsnet interop, and iOS real device tests were not run. §7 is a plan with no reported passes.
- **Control server policy.** How the server turns subnet and exit node approvals into AllowedIPs was not verified from these client sources alone. Only the conditions under which the client narrows received AllowedIPs were checked (`tailscale.com/tailcfg/tailcfg.go:397-402`, `tailscale.com/net/routemanager/routemanager.go:827-840`).
- **OS app adapter.** Applying `NEPacketTunnelNetworkSettings`, DNS configuration policy, and recovery from interface changes were not verified in this note. Only the Go callback boundary was checked (`tailscale.com/wgengine/router/callback.go:12-31`, `:45-67`, M5 gate `docs/plan.md:195`).
- **ICMPv4 ParamProblem.** The Go constant `0x12` was verified. Its difference from the standard value and the policy need separate review (`tailscale.com/net/packet/icmp4.go:26`).
- **Full login and stop state machine and auxiliary features.** The complete path that shuts down the data plane when the local key expires and the full behavior of PeerAPI/SSH/Serve/app connectors and 4via6 are outside the verification scope. M3 needs a contract with narrower support (related entry points `tailscale.com/ipn/ipnlocal/local.go:6967-6980`, `tailscale.com/wgengine/netstack/netstack.go:1287-1350`).

### 8.3 Factual corrections

The count of 10 treats repeated statements of the same error as one. It excludes additions to source references, section rearrangements, and new implementation explanations.

| # | Corrected claim | Verification source |
| --- | --- | --- |
| 1 | netmap synchronization also creates missing WireGuard peers → updates existing peers only | `tailscale.com/wgengine/userspace.go:698-717` |
| 2 | `Parsed.Decode` ignores all bytes after declared IP length → bytes can remain in transport parsing and Buffer | `tailscale.com/net/packet/packet.go:161-162`, `:461-478` |
| 3 | All remaining IPv6 extension headers are Unknown → actual switch retains some numbers | `tailscale.com/net/packet/packet.go:278-365` |
| 4 | Expiration when `KeyExpiry` is earlier than current time → equality also expires | `tailscale.com/ipn/ipnlocal/expiry.go:104-109` |
| 5 | Skip expiration if the ControlTime field is old → compare adjusted current time with the epoch | `tailscale.com/ipn/ipnlocal/expiry.go:92-98` |
| 6 | Clock adjustment threshold is at least 1 minute → no adjustment at exactly 1 minute | `tailscale.com/ipn/ipnlocal/expiry.go:65-73` |
| 7 | Rule conversion always returns only the first error → a destination capability error can overwrite it | `tailscale.com/wgengine/filter/tailcfg.go:80-86` |
| 8 | Always reschedule 540-second cleanup when giving up on a handshake → only schedule if there is no timer | `wireguard-go/device/timers.go:92-97` |
| 9 | TSMP rejection sending is described as a simple TCP SYN check → SYN bit independent of ACK, plus the disable flag condition | `tailscale.com/net/tstun/wrap.go:1216-1234` |
| 10 | A handshake is described as an attempt lasting up to 90 seconds → actual give-up depends on the count and a 5-second timer plus jitter | `wireguard-go/device/constants.go:18-21`, `wireguard-go/device/timers.go:80-106`, `:188-192` |
