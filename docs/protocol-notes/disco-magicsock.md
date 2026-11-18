# disco and magicsock

## 1. Introduction

| Item | Value |
| --- | --- |
| Reference sources | `tailscale.com` v1.104.6 (CapabilityVersion 148, Reference sources table in `docs/protocol-notes/README.md`) |
| Authoring model | GPT-6.1 Sol |
| Verification status | Verified by Claude Opus 5.5, 2026-11-15, 7 corrections + M4 procedures, decisions, and tests expanded |

Origins use `tailscale.com/<path>:<line>` relative to the module root. Dependency modules use `golang.org/x/crypto@v0.58.0/...` (`tailscale.com/go.mod:139`) and `wireguard-go/...` (the Tailscale fork in the README Reference sources table). Files in this repository use paths relative to its root. Statements marked "implementation proposal" or "calculation" are Swiftail conclusions drawn from Go rules and do not describe Go behavior.

## 2. Scope

M4 covers the disco message format and cryptography, classification of received UDP datagrams, per-peer candidate addresses and path selection (`bestAddr`), when to send Ping, Pong, and CallMeMaybe, discovering and uploading local endpoints to the control server, TSMP disco key advertisements, network changes within the scope of the M4 gate, why Swiftail can ignore certain Go peer expectations (peer relay and peer MTU), and tests using `Tools/interop` `tailnet`.

Outside the scope are the STUN byte format and netcheck home region selection (`derp-stun.md` 3.8, 3.9, 4.10), DERP frames and region connections (`derp-stun.md`), WireGuard itself (`wireguard.md`), the remaining map request fields (`control-map.md`), peer relay server and client procedures (only the format is documented), and details of Wi-Fi↔cellular transitions and iOS socket binding (M5).

## 3. Wire format

### 3.1 disco outer format

The UDP datagram or DERP packet payload uses this format directly (see 3.6 for the Geneve-encapsulated peer relay path) (`tailscale.com/disco/disco.go:6-19`, `tailscale.com/wgengine/magicsock/magicsock.go:2041-2051`).

| Offset | Length | Field | Value |
| --- | --- | --- | --- |
| 0 | 6 | magic | `54 53 f0 9f 92 ac` (`"TS💬"`) (`disco/disco.go:35`) |
| 6 | 32 | Sender disco public key | 32 raw bytes (`magicsock.go:2042`) |
| 38 | 24 | nonce | Fresh random value for each message (`tailscale.com/types/key/disco.go:223-225`) |
| 62 | 16 | Poly1305 tag | First 16 bytes of the secretbox output (`golang.org/x/crypto@v0.58.0/nacl/secretbox/secretbox.go:76-118`) |
| 78 | L | Ciphertext | The plaintext from 3.3 (L bytes) encrypted with XSalsa20 |

Length calculation (`tailscale.com/wgengine/magicsock/endpoint.go:1294-1298`). The outer format is 78 bytes longer than the plaintext. A Ping that Go currently sends (with NodeKey and no padding) is 124 bytes. A Ping without NodeKey is 92 bytes, a Pong is 110 bytes, and a CallMeMaybe with N addresses is 80 + 18N bytes.

### 3.2 Cryptography

1. disco private key. Clamp 32 random bytes with `b[0] &= 248` and `b[31] = (b[31] & 127) | 64`. The public key is the result of X25519 base-point multiplication. Generate it independently of the node key without deriving it from the node key (`tailscale.com/types/key/disco.go:36-43`, `:65-74`, `tailscale.com/types/key/util.go:51-54`, `tailscale.com/wgengine/magicsock/magicsock.go:579-580`).
2. Shared key. Call `box.Precompute` with the local **disco** private key and the peer's **disco** public key. The 32-byte result comes from applying `HSalsa20(key: that result, input: 0^16, sigma)` to the result of `X25519(private key, peer public key)` (`tailscale.com/types/key/disco.go:76-84`, `golang.org/x/crypto@v0.58.0/nacl/box/box.go:81-84`). Swiftail's `NaClBox.sharedKey(privateKey:peerPublicKey:)` performs the same calculation (`Sources/SwiftailCrypto/NaCl.swift:39-44`).
3. Sealing. Use a fresh random nonce N (24 bytes) to produce `secretbox.Seal(plaintext, N, shared key)` (XSalsa20-Poly1305, output = tag 16 ‖ ciphertext) and append `N ‖ output` after the magic and public key. There is no additional authenticated data. The magic and sender's public key are not cryptographically bound (`tailscale.com/types/key/disco.go:219-226`, `golang.org/x/crypto@v0.58.0/nacl/box/box.go:97-99`). Swiftail's `NaClSecretBox.seal` uses the same layout (`Sources/SwiftailCrypto/NaCl.swift:4-11`).
4. Opening. Take the bytes starting at offset 38, use the first 24 bytes as the nonce, and open the remainder with secretbox. Opening fails if there are fewer than 24 bytes or the tag is incorrect (`tailscale.com/types/key/disco.go:231-240`, `golang.org/x/crypto@v0.58.0/nacl/secretbox/secretbox.go:125-128`).
5. Cache. Go computes the shared key once per peer disco public key and stores it in a table. It creates entries only for disco keys in the netmap or learned through TSMP (4.10). Changing the local disco key clears the entire table (`tailscale.com/wgengine/magicsock/magicsock.go:2742-2753`, `:1261`).
6. Failure. Drop unknown disco keys, boxes that fail to open, and parse failures without a response. A packet that fails to open is also withheld from WireGuard (`tailscale.com/wgengine/magicsock/magicsock.go:2245-2253`, `:2267-2286`, `:2295-2307`, `:1875-1876`).

One difference from Go concerns all-zero results. If Go's `curve25519.ScalarMult` produces an all-zero result (a low-order public key), it uses the zero value and continues (`golang.org/x/crypto@v0.58.0/curve25519/curve25519.go:23-31`). Swiftail's `sharedKey` throws `invalidKey` in this case (`Sources/SwiftailCrypto/NaCl.swift:43`). Drop messages with such keys (implementation proposal).

### 3.3 Plaintext header and message types

| Plaintext offset | Length | Field | Value |
| --- | --- | --- | --- |
| 0 | 1 | type | See the table below |
| 1 | 1 | version | Always 0 when sending |
| 2 | … | Body | Depends on the type (3.4, 3.5) |

(`tailscale.com/disco/disco.go:44-56`, `:119-132`)

| type | Name | v0 body length | Go parser |
| --- | --- | --- | --- |
| `0x01` | `Ping` | 12, 44, or more (padding) | Ignores version. Errors below 12. Allows trailing bytes |
| `0x02` | `Pong` | 30 | Ignores version. Errors below 30. Ignores trailing bytes |
| `0x03` | `CallMeMaybe` | 18N | If version ≠ 0, length is 0, or length is not a multiple of 18, returns **0 addresses without an error** |
| `0x04` | `BindUDPRelayEndpoint` | 72 | Ignores version. Errors below 72 |
| `0x05` | `BindUDPRelayEndpointChallenge` | 72 | Same as above |
| `0x06` | `BindUDPRelayEndpointAnswer` | 72 | Same as above |
| `0x07` | `CallMeMaybeVia` | 124 + 18N (N ≥ 1) | Returns an empty message if version ≠ 0. Errors if the length is invalid |
| `0x08` | `AllocateUDPRelayEndpointRequest` | 68 | Returns an empty message if version ≠ 0. Errors below 68 |
| `0x09` | `AllocateUDPRelayEndpointResponse` | 128 + 18N (N ≥ 1) | Returns an empty message if version ≠ 0. Errors if the length is invalid |

(`tailscale.com/disco/disco.go:81-109`, `:169-189`, `:232-247`, `:271-284`, `:385-397`, `:491-505`, `:526-537`, `:594-598`, `:651-658`)

Plaintext shorter than 2 bytes or with an unknown type produces a parse error. The receiver silently drops it (treating it as a message from a newer version) (`disco/disco.go:82-84`, `:106-107`, `tailscale.com/wgengine/magicsock/magicsock.go:2299-2307`). Swiftail applies the same rules as Go to version and trailing bytes (implementation proposal to follow the table above).

### 3.4 Ping, Pong, CallMeMaybe

The table uses body offsets (plaintext offset − 2). Integers are BE.

| Message | Offset | Length | Field | Value |
| --- | --- | --- | --- | --- |
| `Ping` | 0 | 12 | TxID | Fresh random value for each send (`tailscale.com/wgengine/magicsock/endpoint.go:1405`) |
| `Ping` | 12 | 32 | NodeKey | Sender's raw WireGuard (node) public key. Unused if zero |
| `Ping` | 12 or 44 | P | Padding | Zero-filled. Used for path MTU measurement |
| `Pong` | 0 | 12 | TxID | TxID of the received Ping |
| `Pong` | 12 | 16 | Src IP | Observed source IP of the Ping. IPv4 uses IPv4-mapped IPv6 (`::ffff:a.b.c.d`) |
| `Pong` | 28 | 2 | Src port | Observed source port of the Ping |
| `CallMeMaybe` | 18i | 16 | IP of address i | IPv4 is IPv4-mapped. Unmap on receipt |
| `CallMeMaybe` | 18i + 16 | 2 | Port of address i | Derive the count from the length. There is no count field |

(`tailscale.com/disco/disco.go:134-189`, `:219-247`, `:249-284`)

- Ping parsing. If at least 32 bytes follow the TxID and those 32 bytes are not all zero, treat them as the NodeKey and the rest as padding. If all 32 bytes are zero, treat all of them as padding with no NodeKey (`disco/disco.go:169-189`).
- Go always includes its own NodeKey in the Ping it sends. Padding is present only when path MTU measurement is enabled (`tailscale.com/wgengine/magicsock/endpoint.go:1309-1317`, 4.12).
- Go uses the Pong Src only for recordkeeping and logs. Path selection and local endpoint discovery do not use it (`tailscale.com/wgengine/magicsock/endpoint.go:1966-1975`, `:1993-1997`). Swiftail still includes the observed source address as Go does (implementation proposal).

### 3.5 peer relay messages (identification only)

Swiftail drops these types on receipt and never sends them (4.12). The formats are documented for test data and boundary checks.

Bodies of `0x04`, `0x05`, and `0x06` (72 bytes, `tailscale.com/disco/disco.go:342-397`).

| Offset | Length | Field |
| --- | --- | --- |
| 0 | 4 | VNI (u32 BE, must match the Geneve VNI) |
| 4 | 4 | Generation (u32 BE) |
| 8 | 32 | RemoteKey (disco public key of the peer on the other side of the relay) |
| 40 | 32 | Challenge |

Relay endpoint E (`tailscale.com/disco/disco.go:539-623`) has 0:32 ServerDisco, 32:32 ClientDisco[0], 64:32 ClientDisco[1], 96:8 LamportID (u64 BE), 104:4 VNI (u32 BE), 108:8 BindLifetime (u64 BE, nanoseconds), 116:8 SteadyStateLifetime (u64 BE, nanoseconds), and N 18-byte addresses starting at 124 (same layout as CallMeMaybe in 3.4, N ≥ 1). The `CallMeMaybeVia` body is E and the `AllocateUDPRelayEndpointResponse` body is `Generation(u32 BE) ‖ E` (`disco/disco.go:517-523`, `:644-649`). The `AllocateUDPRelayEndpointRequest` body is ClientDisco[0] 32 ‖ ClientDisco[1] 32 ‖ Generation u32 BE (`disco/disco.go:477-489`).

### 3.6 Geneve header (peer relay path)

UDP on the peer relay path adds an 8-byte Geneve header before disco or WireGuard. Go sends byte 0 = 0, byte 1 = Control bit (`0x80`) or 0, bytes 2–3 = protocol (u16 BE, disco `0x7A11`, WireGuard `0x7A12`), bytes 4–6 = VNI (24-bit BE), and byte 7 = 0 (`tailscale.com/net/packet/geneve.go:18-22`, `:100-118`). Swiftail does not use this path and needs only the classification rules in 4.1.

### 3.7 STUN

See `derp-stun.md` 3.8 and 3.9 for the request and response byte formats and Go STUN server filtering. magicsock sends and receives STUN on the **same UDP socket** as data and disco (`derp-stun.md` 4.10 2, `tailscale.com/wgengine/magicsock/magicsock.go:1632-1644`, `:1877-1881`).

### 3.8 TSMP disco key advertisements

The advertisement is an IP packet inside the WireGuard tunnel, distinct from disco on the outer UDP transport. The IP header protocol is 99 (TSMP), and the source and destination are the two sides' Tailscale addresses (`tailscale.com/types/ipproto/ipproto.go:67`, `tailscale.com/net/packet/tsmp.go:291-315`).

| IP payload offset | Length | Field | Value |
| --- | --- | --- | --- |
| 0 | 1 | TSMP type | `0x61` (`'a'`) |
| 1 | 32 | disco public key | raw |

The receiving parser checks only that the payload is at least 33 bytes long and checks its first byte (`tailscale.com/net/packet/tsmp.go:80`, `:318-331`).

## 4. Procedures and state machines

### 4.1 Classifying received UDP datagrams

Check in order (`tailscale.com/wgengine/magicsock/magicsock.go:2143-2191`, `:1849-1921`).

1. **STUN**. If length ≥ 20, the top 2 bits of the first byte are 0, bytes 4–7 are `21 12 a4 42`, and byte 1 is `0x01`, classify it as STUN binding and pass it to netcheck. It does not reach WireGuard (`tailscale.com/net/stun/stun.go:308-312`, `magicsock.go:2144-2147`, `:1877-1881`). See `derp-stun.md` 4.10 3 for response validation.
2. **Geneve**. If length ≥ 8, `b[0] & 0xC0 == 0`, `b[1] & 0x3F == 0`, and `b[7] == 0`, classify protocol `0x7A11` with disco after the first 8 bytes (step 3 below) as Geneve disco, and protocol `0x7A12` as Geneve WireGuard. If the protocol is `0x7A11` and the bytes after the header are not disco, treat the packet as bare WireGuard. For other protocol values, continue to step 3 (`magicsock.go:2158-2184`).
3. **disco**. If length ≥ 38 and the first 6 bytes match the magic, classify it as disco (`magicsock.go:2103`, `:2151-2156`, `:2186-2187`). `disco.LooksLikeDiscoWrapper` uses a different threshold of 62 bytes (`tailscale.com/disco/disco.go:62-67`). Disco packets of 38–61 bytes fail to open and are dropped (3.2 4).
4. Treat **everything else** as WireGuard (`magicsock.go:2188-2190`). Drop the packet if there is no local node private key (`magicsock.go:1887-1892`).

Associating source addresses with peers

- disco finds the peer by the **sender's disco public key**, independently of the address (4.2).
- Go looks up a WireGuard packet's source address in the address→peer table. On a miss, it passes a temporary endpoint to WireGuard, then adds the address to the table once decryption identifies the peer (`magicsock.go:1905-1921`, `:4524`). Swiftail's WireGuard device identifies the peer by receiver index and reports it with `.ipPacket(_, from:)` (`docs/contracts/SwiftailWireGuard.md` `Output`), so decryption needs no address→peer table (implementation proposal).
- Go uses the address→peer table only to record UDP receipt times and extend trust for peers with heartbeat disabled (`magicsock.go:1922-1924`, `tailscale.com/wgengine/magicsock/endpoint.go:579-606`). Receiving a WireGuard packet does not extend trust for ordinary peers (`endpoint.go:588-597`).

### 4.2 Receiving disco messages

1. Drop the packet unless the sender's disco key belongs to a peer known through the netmap or TSMP (`tailscale.com/wgengine/magicsock/magicsock.go:2234-2253`). The Geneve Control bit marks relay server handshake messages. Swiftail drops them (`magicsock.go:2236-2244`).
2. Open with the shared key (3.2 4) and parse (3.3). Drop failures.
3. Handling by type (`magicsock.go:2329-2444`).
   - **Ping** → step 4 below.
   - **Pong** → pass it to the peers with that disco key in order, stopping at the first peer that claims the TxID (4.6 4).
   - **CallMeMaybe** → the message must arrive over DERP and the DERP sender's node key must be nonzero. A peer must exist for that node key, and the message's disco key must match either the peer's netmap key or its TSMP key. If the key was inactive, make it the peer's active key (`tailscale.com/wgengine/magicsock/endpoint.go:1645-1688` `checkAndUpdateDiscoKey`, 4.10 2). Drop CallMeMaybe received over UDP. On success, continue to 4.8 5 (`magicsock.go:2352-2443`).
   - **CallMeMaybeVia, Allocate…, Bind…** → peer relay path. Swiftail drops them (4.12).
4. **Ping handling** (`tailscale.com/wgengine/magicsock/magicsock.go:2581-2684`).
   1. For a Ping received over UDP, add the source address to the address→node table if its owner can be established. Check in this order. (a) The peer for the Ping's NodeKey has this disco key (its netmap key or TSMP key. If it was inactive, make it the peer's active key, `checkAndUpdateDiscoKey`). → (b) Exactly one node has this disco key (`magicsock.go:2547-2577`, `:2617-2621`). The function also has a branch that checks the DERP sender first, but it is called only for Ping received over UDP, so that branch is unused. NodeKey alone is insufficient for trust (`disco/disco.go:138-142`).
   2. For a Ping received over UDP, add the **source address** as a candidate for each peer with this disco key (the Ping origin in 4.4 1). If its TxID matches the previous Ping received for that candidate, treat it as a duplicate and skip the Pong (`magicsock.go:2643-2657`, `tailscale.com/wgengine/magicsock/endpoint.go:1810-1845`).
   3. A Ping received over DERP adds no candidate. Drop it if the DERP sender's node key belongs to an unknown peer (`magicsock.go:2636-2639`, `:2665-2668`).
   4. Send `Pong{TxID: received TxID, Src: source address}` **over the incoming path**. Reply to a UDP Ping at its source address and to a DERP Ping through the same DERP region to the sender's node key. The DERP Src is `127.3.3.40:<region ID>` (`magicsock.go:2678-2683`).

### 4.3 Receiving over DERP

The DERP `FrameRecvPacket` body also goes through the disco check in 4.1 3 (≥ 38 bytes, magic). For disco, attach source address `127.3.3.40:<receiving region ID>` and the DERP sender's node key, then pass it to 4.2. Otherwise, pass it to WireGuard only if the peer for the sender's node key exists (`tailscale.com/wgengine/magicsock/derp.go:734-777`). The M3 contract identifies and drops disco over DERP using a 62-byte threshold (`docs/contracts/SwiftailEngine.md` Receiving 5). In M4, pass it to 4.2 using the check above (implementation proposal).

### 4.4 Per-peer state and candidate addresses

Go skips creating peers with a zero disco key unless they are WireGuard-only (`tailscale.com/wgengine/magicsock/magicsock.go:3305-3307`). The following state is kept per peer (`tailscale.com/wgengine/magicsock/endpoint.go:635-652`, `:1356-1419`, `:1929-2022`).

- DERP address. Use `127.3.3.40:<region ID>` if the netmap's `HomeDERP` is nonzero. A zero value means no address (`endpoint.go:1733-1753`). See `derp-stun.md` 4.9 for region connection selection.
- Candidate address table. Each address has the last Ping send time, last received Ping time and TxID, time received through CallMeMaybe, and Pong history (latency).
- Sent Ping table. TxID → (destination address, send time, purpose, size, 5-second timer).
- `bestAddr` (address, latency, wire MTU), `trustBestAddrUntil`, `lastFullPing`, `lastSendExt` (outbound send activity), and heartbeat timer.

1. **Candidate origins**.
   - `Node.Endpoints` from the netmap. Reconcile on every map update (step 2 below) (`endpoint.go:1755-1757`, `:1762-1801`).
   - The source address of a Ping received over UDP (4.2 4.2).
   - The address list in a CallMeMaybe received over DERP (4.8 5). Exclude IPv6 link-local addresses (`endpoint.go:2163-2168`).
   - Local STUN results go to the control server and into CallMeMaybe as local endpoints (4.9). They **do not become peer candidates**.
   - Pong Src is also excluded from candidates (3.4).
2. **Removal** (`endpoint.go:510-521`). Keep a candidate with a CallMeMaybe receipt time. Remove a candidate with no received Ping (netmap origin) when it disappears from the netmap. Remove a candidate learned through Ping 45 seconds after receiving its last Ping. Check on netmap updates, when sending a full Ping, and when the candidate count exceeds 100 (`endpoint.go:1796-1800`, `:1429-1433`, `:1835-1843`). Remove previous CallMeMaybe addresses missing from the next CallMeMaybe regardless of origin (`endpoint.go:2197-2204`). Clear `bestAddr` as well if the removed address is `bestAddr` (`endpoint.go:547-563`).
3. When the peer's disco key changes in the netmap, clear trust, pending Pings, `lastPing`, `lastFullPing`, and `lastSendExt`. Keep the `bestAddr` address itself (`endpoint.go:1719-1727`, `:1694-1697`, `:2294-2310`).

### 4.5 Sending and path selection

When sending a WireGuard datagram to a peer (`tailscale.com/wgengine/magicsock/endpoint.go:635-652`, `:1107-1206`).

1. If `bestAddr` exists and `now ≤ trustBestAddrUntil`, send **only to `bestAddr` over UDP**.
2. Otherwise, send the same bytes to **both** the UDP `bestAddr` (if still present) and the DERP address. Keep using `bestAddr` after trust expires. Only the Pong deadline in 4.6 3 and the events in 4.5 6, 4.4 2, and 4.11 2 clear it.
3. If step 1 does not apply (the path is indirect or trust has expired), do a full Ping (4.8 1) before sending (`endpoint.go:1123-1128`).
4. If neither address exists, send through the DERP region where a packet from the peer was received (reverse path). If that is also unavailable, the packet cannot be sent (`endpoint.go:1133-1143`, `derp-stun.md` 4.9 3).
5. Record outbound send activity and schedule a heartbeat for 3 seconds later if none is scheduled (`endpoint.go:1020-1025`, `:1129`).
6. If sending over UDP returns `EHOSTUNREACH`, clear `bestAddr` and trust and reset the measurement state for that candidate (`endpoint.go:1151-1153`, `:1860-1871`, `tailscale.com/wgengine/magicsock/endpoint_default.go:15-22`). If everything was sent over DERP, the send succeeds despite a UDP error (`endpoint.go:1184-1205`).

### 4.6 Sending Ping and receiving Pong

1. When sending Ping to a candidate address (`tailscale.com/wgengine/magicsock/endpoint.go:1356-1419`), set the candidate's `lastPing` to now, add an entry with a fresh TxID to the sent Ping table, set a 5-second timer, and send Ping. Send only to candidates in the table (except CLI Ping). The Ping body is `TxID ‖ local node public key` (`endpoint.go:1309-1317`).
2. If sending fails, remove that TxID from the table (`endpoint.go:1318-1321`, `:1262-1268`).
3. **5-second deadline** (`endpoint.go:1244-1259`). Remove the entry if it is still in the table. If the Ping address is `bestAddr` and **trust has already expired at that time**, clear `bestAddr` and trust. Otherwise, change nothing (loss of a single Ping does not discard the path).
4. **Receiving Pong** (`endpoint.go:1929-2022`).
   1. If the TxID is absent from the sent Ping table, ignore it (pass it to the next peer, 4.2 3).
   2. Remove the entry from the table and compute latency = now − send time.
   3. For a Pong received over DERP, stop here (it is unused as a direct path).
   4. For a Pong received over UDP, stop if the destination address of the Ping (`sp.to`) is absent from the candidate table. Otherwise, add the Pong's actual source address to the address→peer table for this peer and record latency for candidate `sp.to`.
   5. Use `betterAddr` (4.7) to compare candidate `sp.to` (distinct from the Pong source) with the current `bestAddr`. If it is better or current trust has expired, make it `bestAddr`.
   6. If `bestAddr` is `sp.to`, update latency and timestamp and set `trustBestAddrUntil = now + 6.5 seconds`.

### 4.7 `betterAddr` (whether a is better than b)

(`tailscale.com/wgengine/magicsock/endpoint.go:2059-2144`)

1. If the addresses match, a is better only if its wire MTU is larger.
2. If b is absent, a is better. If a is absent, it is not better.
3. A direct path is better than a peer relay (Geneve) path.
4. Scores start at 0 for both. If `a.latency > b.latency` and `a.latency > 0`, set `bPoints = 100 − (b.latency × 100) / a.latency` (integer division). Otherwise, if `b.latency > 0`, set `aPoints = 100 − (a.latency × 100) / b.latency`. Latencies are integers in nanoseconds.
5. For each address, add +50 for loopback, otherwise +30 for link-local unicast, otherwise +20 for private (RFC 1918 or ULA). Independently add +10 for IPv6.
6. If `aPoints ≤ 1` and `bPoints == 0`, a is not better. Otherwise, a is better if `aPoints > bPoints`.

Calculation. If Go's endpoints on the same machine include both `127.0.0.1:p` and the LAN address `192.168.x.y:p`, loopback wins as long as latencies are similar.

### 4.8 When to send each message

1. **Full Ping** (`tailscale.com/wgengine/magicsock/endpoint.go:1423-1459`). Set `lastFullPing` to now, remove candidates due for removal, skip those with `lastPing` within 5 seconds, and send Ping to the rest. If at least one Ping was sent, the caller requested CallMeMaybe, and the peer has a DERP address, schedule CallMeMaybe (step 4 below).
2. **First packet and every subsequent send**. Per 4.5 3, invoke a full Ping (including CallMeMaybe) on every packet sent while there is no trusted direct path. The 5-second limit per candidate means Ping and CallMeMaybe actually go out about once every 5 seconds per peer (calculation). Discovery Ping goes only to candidates (direct addresses). Only CLI Ping uses DERP (`endpoint.go:1429-1449`, `:1064-1066`).
3. **heartbeat** (`endpoint.go:872-941`, `:1001-1018`) runs every 3 seconds when there is outbound send activity.
   - Stop once 45 seconds have elapsed since the last outbound send (the next send schedules it again).
   - If `bestAddr` exists, send one Ping to it regardless of trust.
   - Do a full Ping if any of these conditions holds. `bestAddr` is indirect, there has never been a full Ping, trust has expired, or latency exceeds 5 ms and 1 minute has elapsed since the last full Ping. Skip the full Ping for a trusted direct path with latency of 5 ms or less.
   - A heartbeat full Ping also schedules CallMeMaybe (`endpoint.go:933`).
4. **Sending CallMeMaybe** (`tailscale.com/wgengine/magicsock/magicsock.go:2693-2732`).
   1. If the local endpoints were last determined (4.9 5) more than 27 seconds ago, defer sending. Schedule a retry when the endpoint refresh finishes, and start ReSTUN.
   2. If fresh, put the entire last determined list of local endpoint addresses in `MyNumber`, seal it with the peer's disco key, and send it to the peer's node key at its DERP address (its home region). Omit the endpoint type (`EndpointType`).
   3. UDP Ping should go first to open the peer's NAT before CallMeMaybe arrives. Go schedules them separately, so it does not guarantee the order (`tailscale.com/disco/disco.go:191-198`, `endpoint.go:1448`, `:1457`).
5. **Receiving CallMeMaybe** (`endpoint.go:2150-2230`). After the checks in 4.2 3 pass, add each address (except IPv6 link-local) as a candidate or update its CallMeMaybe time. Remove previous CallMeMaybe addresses absent from this list (4.4 2). Then **set `lastPing` to 0 for all candidates** to lift the 5-second limit and send a full Ping immediately. This full Ping does not send CallMeMaybe back.
6. **Reply to a received Ping with Pong only** (4.2 4). Receiving a Ping does not trigger a Ping back. The peer address is probed as a candidate on the next send or heartbeat.

Calculation for the Go peer sending first. If Swiftail has uploaded no endpoints and has yet to send a Ping, Go's candidate table is empty, so it sends neither Ping nor CallMeMaybe (step 1 requires at least one Ping sent) and uses DERP only. If Swiftail sends a Ping while replying to that packet, Go learns the source address as a candidate (4.2 4.2) and looks for a direct path starting with the next send.

### 4.9 Discovering and uploading local endpoints

1. **Collection order** (`tailscale.com/wgengine/magicsock/magicsock.go:1278-1442`). Keep only the first occurrence of each address.
   1. External address from port mapping (UPnP, NAT-PMP, PCP) → `EndpointPortmapped` (3). Skip if there is no port mapper.
   2. netcheck IPv4 global addresses, then IPv6 global addresses → `EndpointSTUN` (2). The IPv4 global address comes from the first STUN response, and the IPv6 global address comes from the last response. Add any other addresses observed at least twice (`tailscale.com/net/netcheck/netcheck.go:137-167`, `:705-733`). Keep loopback addresses.
   3. If IPv4 mapping varies by destination (`MappingVariesByDestIP`) and a fixed local port is configured, `(first IPv4 global IP, local port)` → `EndpointSTUN4LocalPort` (4).
   4. Fake addresses for debugging → `EndpointExplicitConf` (5). Public IP from cloud metadata + socket port → `EndpointLocal` (1).
   5. Re-add previously advertised addresses for 5 minutes 10 seconds (up to 6 per IP) (`tailscale.com/wgengine/magicsock/endpoint_tracker.go:18-22`, `:37`, `:117`).
   6. User-configured fixed endpoints → `EndpointExplicitConf` (5).
   7. If the IPv4 socket is bound to a wildcard, use `(IP, IPv4 socket port)` for each interface address → `EndpointLocal` (1). Use the IPv4 socket's port for IPv6 addresses too. Use loopback addresses only if there are no ordinary addresses and nothing has been collected in earlier steps. If bound to a specific IP, use that address alone (`magicsock.go:1406-1426`).
2. **Type values** are 0 unknown, 1 local, 2 STUN, 3 portmapped, 4 STUN4LocalPort, 5 explicit (`tailscale.com/tailcfg/tailcfg.go:1392-1397`). No use of a peer's type by the Go peer was found (§8).
3. **STUN**. Send from the same UDP socket to the STUN port of a DERP node in the region (3.7, `derp-stun.md` 4.10). The address in the response is the global address in step 2 above.
4. **Uploading to the control server**. Send the changed list in `MapRequest.Endpoints` (addresses) and `EndpointTypes` (types) in matching order, together with `DiscoKey` and `Hostinfo`, in a map request with `Stream=false, OmitPeers=true`. Send only when the list changes (`tailscale.com/control/controlclient/auto.go:888-896`, `tailscale.com/control/controlclient/direct.go:1052-1099`, `docs/contracts/SwiftailControl.md` state upload). The server may ignore values in a streaming request with Version ≥ 68 (`tailcfg.go:1494-1498`). On every non-stream request, testcontrol **overwrites the node's `Endpoints`, `DiscoKey`, and `Cap` (= request `Version`) in full with the request values**. Include the current `DiscoKey` and all endpoints in every state upload request. It filters out IPv6 link-local addresses and addresses with zones (`tailscale.com/tstest/integration/testcontrol/testcontrol.go:1452-1497`, `:1941-1962`).
5. **Timing** (`magicsock.go:887-989`, `:3683-3712`, `:3720-3753`). ReSTUN triggers endpoint refresh (= netcheck + the collection above). Update the "last determined time" on completion, even if the list is unchanged, and upload through step 4 only if the list has changed. Repeat at random 20–26-second intervals while active. Stop if the network is down, there is no home, there are no peers, there is no node key, or the node has been idle for more than 45 seconds. Also run ReSTUN when the DERPMap changes, a node key is set, port mappings change, fixed endpoints change, links change, or CallMeMaybe is about to be sent with stale endpoints (4.8 4) (`tailscale.com/wgengine/magicsock/derp.go:875`, `magicsock.go:1005`, `:2717`, `:3714`, `tailscale.com/wgengine/userspace.go:1218-1224`). Do not upload a list when there is no DERPMap and there are no STUN results (`magicsock.go:964-976`).
6. **Home DERP**. See `derp-stun.md` 4.10 5 and 4.8 for the rules for choosing a home from netcheck results. In magicsock, that result becomes `NetInfo.PreferredDERP` in the map request (`magicsock.go:1075`). The control server sends it to other nodes as this node's `HomeDERP`, and they use it as this node's DERP address (4.4).
7. **Other `NetInfo` fields** (`MappingVariesByDestIP`, `WorkingUDP`, `WorkingIPv6`, `DERPLatency`, `HavePortMap`, and others, `magicsock.go:1054-1078`). wgengine, magicsock, and ipnlocal do not read **the peer's** NetInfo (no `grep NetInfo()` results). Only `PreferredDERP` (→ `HomeDERP`) affects Go peer path behavior.

### 4.10 disco key changes and TSMP advertisements

1. **TSMP advertisements sent by Go**. The Tailscale fork of wireguard-go sends one "priority message" inside the tunnel when session keys are established. The initiator sends it when it receives the handshake response, and the responder sends it when it receives the first transport packet under the new key (`wireguard-go/device/receive.go:416`, `:483`, `wireguard-go/device/send.go:111-140`). Go uses this message to produce the advertisement in 3.8. It requires a local disco key, a peer that is not WireGuard-only, and a local Tailscale address in the same address family as the peer's first address. It ignores the peer's CapabilityVersion (`tailscale.com/wgengine/magicsock/magicsock.go:4631-4676`, `tailscale.com/ipn/ipnlocal/local.go:645`). Swiftail therefore receives this packet every time a WireGuard session is established.
2. **When Go receives an advertisement**. Go withholds TSMP advertisements from the app (`tailscale.com/net/tstun/wrap.go:1133-1146`). If the key is nonzero and differs from the key previously learned through TSMP, store it as the peer's "TSMP key" and make it active. If the active key changes, clear trust and pending Pings as in 4.4 3 (`magicsock.go:4579-4622`, `tailscale.com/wgengine/userspace.go:608-623`, `tailscale.com/wgengine/magicsock/endpoint.go:1595-1620`). Only one of the netmap key and the TSMP key is active. A disco message received under the inactive key makes that key active (`tailscale.com/wgengine/magicsock/endpoint.go:386-392`, `:1645-1688`).
3. **Whether Swiftail needs to send advertisements**. Yes (the conclusion changed on 2026-11-16. The original conclusion was "there is no need to send it"). Go treats both the netmap `DiscoKey` and the key learned through TSMP as "known keys" (4.2 1), and advertising is a CapabilityVersion 144 behavior (`tailscale.com/tailcfg/tailcfg.go:195`). Swiftail declares 148. Without sending an advertisement, the peer learns the restarted Swiftail's new disco key only through the netmap. Until then, both sides' disco messages are dropped and a direct path cannot be established. Without receiving advertisements, the same thing happens with a restarted Go peer. Swiftail therefore sends advertisements at the times in step 1 and uses received keys according to the rules in step 2 (`docs/contracts/SwiftailMagicsock.md` "TSMP disco key advertisements"). The engine consumes advertisements and withholds them from the app and netstack.
4. **Local disco key**. Swiftail generates a new disco key at each startup (`docs/contracts/SwiftailEngine.md` Startup 1). It uploads the new key with the request in 4.9 4, and Go drops Swiftail disco messages until the key appears in the Go peer's map (4.2 1). DERP data continues to flow in the meantime (4.5 2).

### 4.11 Network changes

Go behavior (`tailscale.com/wgengine/userspace.go:1207-1224`, `tailscale.com/wgengine/magicsock/magicsock.go:3777-3926`).

1. Link change. Update network state. If the network is up and the change is major (appears to require rebinding), run Rebind followed by ReSTUN. For a minor change, run only ReSTUN. If the network went down, close DERP and take no further action (`magicsock.go:2755-2773`).
2. Rebind. Close and rebind the UDP sockets. The port priority is configured port → current port → 0 (OS-selected). Ignore IPv6 failures and treat only IPv4 failures as errors. Then clear `bestAddr` and trust for all peers and reset each candidate's Ping history (`magicsock.go:3800-3807`, `:3880-3926`, `tailscale.com/wgengine/magicsock/endpoint.go:1876-1885`). Close the DERP connection if its local address is not an address of the default interface. If it matches, verify the connection with a DERP Ping within 3 seconds (`tailscale.com/wgengine/magicsock/derp.go:905-950`).
3. For broken pipe or `EPERM` send errors, run Rebind + ReSTUN at most once every 5 seconds (`magicsock.go:1612-1625`, `tailscale.com/wgengine/magicsock/magicsock_notplan9.go:17-33`). See 4.5 6 for `EHOSTUNREACH`.

The M4 gate requires no network-change handling. "Switch to DERP when the direct path is blocked and back to direct when unblocked" is a situation where neither sockets nor addresses change. Trust expiry, the Pong deadline, and heartbeat in 4.5, 4.6, and 4.8 suffice (7.2 3). Defer link change detection, Rebind, ReSTUN after address changes, Rebind on errors, rechecking DERP connections, and iOS interface binding to M5.

### 4.12 Go peer expectations for peer relay and peer MTU

**peer relay**. Go assumes the peer supports relay if its `Node.Cap` (CapabilityVersion) is at least 121 (`tailscale.com/wgengine/magicsock/magicsock.go:2921-2923`, `tailscale.com/wgengine/magicsock/endpoint.go:1759`). There is no separate capability or confirmation message. Swiftail can still declare 148 and omit relay without breaking either the direct or DERP path. The reasons follow.

1. Relay path discovery requires relay server candidates in the netmap. A candidate is a node with CapabilityVersion ≥ 121 that the packet filter grants the `tailscale.com/cap/relay-target` peer capability (`magicsock.go:2977-2998`, `tailscale.com/tailcfg/peercap/peercap.go:57-60`, `endpoint.go:960-971`). The default testcontrol map has no such permission (see §8 for the scope of verification).
2. Skip relay discovery when a trusted direct path exists (`endpoint.go:975-977`). Direct path discovery (4.8) and DERP sends (4.5 2) proceed independently of relay.
3. The relay messages Go can send to Swiftail are `CallMeMaybeVia` (0x07) over DERP and `AllocateUDPRelayEndpointRequest` (0x08) when Swiftail is a relay server candidate (`magicsock.go:2437`, `:2445-2536`). If Swiftail drops them, Go's relay handshake and allocation time out (allocation wait 10 seconds, handshake `min(BindLifetime, 30 seconds)`) (`tailscale.com/wgengine/magicsock/relaymanager.go:1036`, `:928-932`). Direct and DERP paths continue unaffected during this time (step 2).
4. Geneve-encapsulated packets arrive only through a relay server, which forwards them only after both sides finish Bind (`tailscale.com/net/udprelay/server.go:289-310`, `:344-348`). Swiftail does not Bind, so they do not arrive. If they arrive anyway, identify and drop them according to 4.1 2.

Conclusion. Ignore these messages. Drop incoming 0x04–0x09 and Geneve. Keep Swiftail out of the relay server role by withholding that permission.

**peer MTU**. Go sends padded Ping only when path MTU measurement is enabled (UDP body lengths are wire MTUs 1280, 1360, 1400, 1500, 8000, and 9000 minus 28 bytes for IPv4 or 48 bytes for IPv6) (`endpoint.go:1379-1394`, `:1910-1923`, `tailscale.com/net/tstun/mtu.go:85-92`). It is off by default and absent from iOS builds (`tailscale.com/wgengine/magicsock/peermtu.go:38-56`, `tailscale.com/wgengine/magicsock/peermtu_stubs.go:4`, `:14-20`). Swiftail only needs to parse padded Ping as in 3.4 and reply with an ordinary Pong (110 bytes). It does not measure path MTU.

## 5. Constants and timers

| Name | Value | Use | Origin (`tailscale.com/`) |
| --- | --- | --- | --- |
| nonce | 24 bytes | 3.1 | `disco/disco.go:40` |
| Minimum outer format length (classification) | 38 bytes | 4.1 3, 4.3 | `wgengine/magicsock/magicsock.go:2103` |
| `pingTimeoutDuration` | 5 seconds | Pong deadline (4.6 3) | `wgengine/magicsock/magicsock.go:4119`, `tsconst/ping.go:11` |
| `discoPingInterval` | 5 seconds | Minimum Ping interval per candidate. Receiving CallMeMaybe lifts it | `wgengine/magicsock/magicsock.go:4125`, `tsconst/ping.go:15` |
| `heartbeatInterval` | 3 seconds | Heartbeat interval | `wgengine/magicsock/magicsock.go:4099` |
| `trustUDPAddrDuration` | 6.5 seconds | UDP-only send period after Pong | `wgengine/magicsock/magicsock.go:4103` |
| `sessionActiveTimeout` | 45 seconds | Stops heartbeat and periodic STUN, expires candidates learned through Ping | `wgengine/magicsock/magicsock.go:4083` |
| `goodEnoughLatency` | 5 ms | Skip full Ping for path improvement at or below this latency | `wgengine/magicsock/magicsock.go:4107` |
| `upgradeUDPDirectInterval` | 1 minute | Full Ping to improve a slow direct path | `wgengine/magicsock/magicsock.go:4087` |
| `endpointsFreshEnoughDuration` | 27 seconds | Local endpoint freshness before CallMeMaybe | `wgengine/magicsock/magicsock.go:4112` |
| Periodic ReSTUN | Random 20–26 seconds | 4.9 5 | `wgengine/magicsock/magicsock.go:904` |
| Candidate cleanup threshold | More than 100 | 4.4 2 | `wgengine/magicsock/endpoint.go:1835` |
| `pongHistoryCount` | 64 | Per-candidate Pong history. Comparisons use only the latest value | `wgengine/magicsock/endpoint.go:490`, `:525-530` |
| `endpointTrackerLifetime` / per address | 5 minutes 10 seconds / 6 | 4.9 1.5 | `wgengine/magicsock/endpoint_tracker.go:22`, `:37` |
| Relay allocation wait / handshake limit | 10 seconds / 30 seconds | 4.12 3 | `wgengine/magicsock/relaymanager.go:1036`, `:928-932` |
| Minimum relay discovery interval / improvement | 30 seconds / 1 minute | 4.12 | `wgengine/magicsock/magicsock.go:4095`, `:4091` |
| Rebind interval on error | 5 seconds | 4.11 3 | `wgengine/magicsock/magicsock.go:1618` |
| DERP Ping wait after Rebind | 3 seconds | 4.11 2 | `wgengine/magicsock/derp.go:923` |

## 6. The minimum Swiftail needs and what it can omit (M4)

### 6.1 Requirements for the loopback and LAN gate

1. One UDP socket (IPv4, wildcard, OS-selected port) and the classification in 4.1. Reply on the socket that received the packet.
2. The disco outer format and cryptography (3.1, 3.2) and Ping, Pong, and CallMeMaybe codecs (3.3, 3.4). Cache shared keys by peer disco key.
3. Reply to Ping with Pong (4.2 4). Reply to UDP at its source address and to DERP over DERP. Add the source address of UDP Ping to the candidates. Skip Pong for the same TxID from the same candidate.
4. Per-peer candidates, sent Ping table, `bestAddr`, and trust (4.4, 4.6), plus `betterAddr` (4.7).
5. Path selection (4.5 1–4). Use UDP alone for a trusted `bestAddr`, otherwise UDP `bestAddr` + DERP.
6. Full Ping and heartbeat (4.8 1–3). 5-second candidate limit, 5-second Pong deadline, 3-second heartbeat, 45-second idle period, and 6.5-second trust period. **Match Go's values.** These values determine when the Go peer falls back and recovers, and the gate checks that timing.
7. Receive (4.8 5) and send (4.8 4) CallMeMaybe. Addresses learned through Ping (4.8 6) suffice for loopback and LAN paths alone, but CallMeMaybe is needed for the final M4 gate with devices behind NAT.
8. Local endpoints. Collect STUN (same socket, home region node) and interface addresses and upload them as `EndpointSTUN` and `EndpointLocal` (4.9 1 steps 2 and 7, and 4). Do this on changes and every 20–26 seconds while active. Include `DiscoKey` with every upload.
9. Pass disco received over DERP to 4.2 (4.3). Change the M3 contract's "identify and drop" rule.

### 6.2 What Swiftail can omit

| Item | Rationale |
| --- | --- |
| Sending and handling peer relay (0x04–0x09, Geneve) | 4.12. Drop on receipt |
| Path MTU measurement | 4.12. Off by default and absent on iOS |
| Port mapping (UPnP, NAT-PMP, PCP) | Optional (4.9 1.1). The test tool also disables it (`Tools/interop/cmd/tailnet/main.go:60`) |
| `EndpointSTUN4LocalPort`, cloud metadata, 5-minute 10-second advertisement cache | Enhancements for hard NAT and cloud environments (4.9 1.3–1.5). Unused on loopback and LAN |
| Sending TSMP advertisements and switching the active TSMP key | 4.10 3. Continue to consume received advertisements only |
| Address→peer table | 4.1. The WireGuard device reports the peer |
| IPv6 socket and IPv6 endpoints | IPv4 suffices for the gate. Go uses the IPv4 port even for IPv6 local addresses (4.9 1.7), so bind both sockets to the same port when adding this support (implementation proposal) |
| Rebind, link changes, and rebinding on error | 4.11. M5 |
| 64-entry Pong history, UDP lifetime measurement, fixed endpoints | Comparisons use only the latest latency (`tailscale.com/wgengine/magicsock/endpoint.go:525-530`). The other features are enabled only when configured (`endpoint.go:1709-1716`) |
| Reverse-path DERP region (peers with home 0) | Follow the M3 contract (`derp-stun.md` 4.9 3) |

### 6.3 Decisions for the lead session to make in the contract

| Decision | Options | Recommendation |
| --- | --- | --- |
| UDP socket | One IPv4 / two, IPv4+IPv6 (Go) / one dual-stack | One IPv4 socket. With dual stack, received addresses need unmapping and the table differs from Go's |
| Timer values | Match Go / shorten for tests | Match Go. Allow tests to inject a clock (the time argument approach in the M3 engine contract) |
| Home region | Fixed as in M3 / selected by netcheck | Add STUN because endpoints need it, and select the home according to `derp-stun.md` 4.10 5. The gate result is the same because there is only one test region |
| Endpoints to upload | local+STUN / all Go endpoint types | local+STUN. This suffices because the Go loopback endpoint comes from STUN in gate tests (§7) |
| CapabilityVersion | Keep 148 / lower below 121 | Keep 148 (4.12). Lowering it can change other server behavior (`docs/plan.md` risk 13) |
| Relay and Geneve messages | Drop / disconnect with an error | Drop. Disconnecting would break the path when a Go peer sends a valid message |
| TSMP advertisements | Omit / send | Omit (4.10 3) |
| Direct path blocking test mechanism | Swift test UDP filter / Go debug knob in the tool / both | Both (§7 3). Place the filter at the socket boundary, outside the system under test |
| Path lookup API (`path(toPeerNamed:)`) | `bestAddr` plus trust status / Go's `curAddr` semantics | Match Go's `curAddr` semantics (trusted direct address, otherwise DERP) (`tailscale.com/wgengine/magicsock/endpoint.go:2246-2252`) |

## 7. What to verify in interop tests

### 7.1 Behavior in the `tailnet` environment

- The STUN server is at `127.0.0.1`, and there is one DERP region (ID 1, code `test`) (`Tools/interop/cmd/tailnet/main.go:66-90`, `derp-stun.md` 7.1). The port mapper is disabled (`main.go:60`).
- Calculation. The Go tsnet peer queries the `127.0.0.1` STUN server from a wildcard socket, so the STUN result is `127.0.0.1:<Go port>`. netcheck keeps loopback addresses, so it is uploaded as `EndpointSTUN` (4.9 1.2). The machine's LAN addresses are also included as `EndpointLocal` with the same port (4.9 1.7). If Swiftail follows the same approach, it uploads `127.0.0.1:<Swiftail port>`. The loopback test therefore needs no fixed endpoints.
- testcontrol copies Swiftail's map request `Version` directly to `Node.Cap`, and copies `Endpoints` and `DiscoKey` directly to the node (4.9 4). It grants no packet filter capability, so there are no relay candidates (4.12 1).
- In `peerStatus`, `curAddr` is the address when Go uses **only a trusted direct path** to that peer. It is empty when Go also uses DERP or uses DERP alone. `relay` is the peer's home DERP region code (`test`), regardless of whether DERP is currently in use (`tailscale.com/wgengine/magicsock/endpoint.go:2232-2253`). `curAddr` is populated only after Go has sent to that peer (`endpoint.go:2238-2240`).
- `peerPing` with `type=disco` sends Ping to the trusted direct address and DERP if a trusted direct path exists, otherwise to DERP and all candidates, and replies with the **first Pong received**. A direct Pong populates `Endpoint`, while a DERP Pong populates `DERPRegionID` and `DERPRegionCode`. CLI Ping also counts as outbound send activity and starts heartbeat (`endpoint.go:1044-1099`, `:1400-1402`, `tailscale.com/wgengine/magicsock/magicsock.go:1208-1221`).

### 7.2 Checks

1. **Codecs and cryptography (Swift unit tests)**. Check byte equality with Go `disco.Ping/Pong/CallMeMaybe.AppendMarshal`, the length and version boundaries in the 3.3 table (CallMeMaybe 17 and 19 bytes, version 1 → 0 addresses, Pong 29 bytes → drop, Ping 12, 44, and 45 bytes, zero NodeKey), and IPv4-mapped addresses. Compare the sealed output with a fixed nonce against Go (nonce injection requires a Go test tool). Confirm that tampered nonces, tags, or public keys, unknown disco keys, and 38–61-byte disco packets leave state unchanged.
2. **Direct path establishment (gate)**. After exchanging UDP echo traffic between Swiftail and a Go peer (`addPeer`), check that `curAddr` for Swiftail in Go `peerStatus` is one of the endpoints Swiftail uploaded (expected `127.0.0.1:<Swiftail port>`, calculation in 4.7) and that Swiftail path lookup also returns a direct address. Test both Swift→Go sending first and Go→Swift sending first (start with Go `peerPing` `type=ICMP` or `TSMP`).
3. **Blocking and unblocking (gate)**. Use two mechanisms.
   - Swift filter (recommended). Drop all datagrams to and from the Go peer's port at Swiftail's UDP socket boundary. The calculated expectation is that trust expires on both sides 6.5 seconds after the last Pong and sends switch to both UDP and DERP. A subsequent expired heartbeat Ping (5-second deadline) clears `bestAddr` (4.6 3), leaving only DERP. Go `curAddr` is empty from the moment trust expires. UDP echo continues through DERP in the meantime. When the filter is lifted, a full Ping from the next send or heartbeat (within the 5-second limit) and a Pong restore `curAddr`.
   - Go knob. Add the `setNeverDirectUDP {enabled}` command to the tool and call `envknob.Setenv("TS_DEBUG_NEVER_DIRECT_UDP", "true"/"false")`. When enabled, Go stops answering UDP Ping and stops sending direct Ping and CallMeMaybe (`tailscale.com/wgengine/magicsock/debugknobs.go:65-68`, `magicsock.go:2606-2608`, `endpoint.go:1360-1362`, `:1424-1426`, `tailscale.com/envknob/envknob.go:94-108`). Go has no Ping to expire, so it keeps `bestAddr` and continues sending UDP data on both paths. Check that Swiftail receives no Pong and falls back to UDP + DERP, that Go `curAddr` becomes empty, and that both return to direct when disabled. The knob affects all Go peers in the tool process.
4. **CallMeMaybe**. Have Go send before Swiftail uploads its endpoints (calculation in 4.8). Check whether Swiftail's reply Ping establishes a path and whether Go immediately sends Ping after receiving Swiftail's CallMeMaybe (Go debug logs or Swift receipt time). A Swift unit test checks whether a CallMeMaybe after more than 27 seconds without an endpoint refresh goes out after ReSTUN (4.8 4.1).
5. **Idle**. After 45 seconds without sending, Swiftail's heartbeat stops. Resuming sending starts with a full Ping (4.8 3).
6. **TSMP advertisements**. Swiftail consumes the packet from 3.8 that Go sends when the session is established and withholds it from the app (same as the M3 contract).
7. **Ignoring relay**. Getting Go to send a relay message requires a relay server and a capability grant, so this tool cannot produce one. Check in Swift unit tests that 0x04–0x09 and Geneve packets do not change state.

Proposed additions to the tool are `setNeverDirectUDP` above and, in `peerStatus`, the Go node's own endpoint list (`Status.Self.Addrs`, `magicsock.go:4026-4028`) and per-peer `active` and `lastWrite` (`endpoint.go:2243-2244`). These would expose the Go port and heartbeat state directly.

## 8. Unverified details

- No runtime results were obtained. The expected timing in §7 (dual sends after 6.5 seconds, DERP only after a Ping expires, and recovery timing) and Go's STUN endpoint in `tailnet` becoming `127.0.0.1:<port>` were calculated from the code.
- No use of a peer's `EndpointTypes` by the Go peer was found in wgengine or magicsock. Public sources do not show how the production control server handles types or loopback endpoints (whether it filters them or passes them unchanged to other nodes).
- The absence of the `tailscale.com/cap/relay-target` capability in the default testcontrol map's packet filter was inferred from the fact that the `tailnet` tool configures neither a filter nor a capability (`Tools/interop/cmd/tailnet/main.go:90`). The actual contents of the default testcontrol filter are unverified.
- Changing the knob at runtime with `envknob.Setenv` changes a value that is read without a lock (`tailscale.com/envknob/envknob.go:165-176`). The effect of races in the test tool was not tested.
- The actual delay and logs while a Go peer sends `CallMeMaybeVia` to Swiftail and times out with a relay server present in a production tailnet were not observed (observe at the final M4 gate).
- Direct path success under real NAT (one side or both sides, hard NAT) and Swift equivalence for iOS and macOS socket binding (`IP_BOUND_IF` and others, `tailscale.com/net/netns/netns_darwin.go:295`). Verify during M4 wrap-up and M5.
