# DERP and STUN

## 1. Introduction

| Item | Value |
| --- | --- |
| Reference sources | `tailscale.com` v1.104.6 (CapabilityVersion 148, Reference sources table in `docs/protocol-notes/README.md`) |
| Authoring model | GPT-6.1 Terra |
| Verification status | Verified by Claude Opus 5.5, 2026-11-14, 13 corrections |

Source citations use `tailscale.com/<path>:<line>` relative to the module root. Dependencies use `golang.org/x/crypto@v0.58.0/...` (`tailscale.com/go.mod:139`), the standard library uses `Go 1.27.3/src/...`, and files in this repository use paths relative to its root.

## 2. Scope

M3 covers the HTTP upgrade, frame format, handshake, sending and receiving, reconnection, conditions for server disconnects, home region selection and notification, and per-peer region selection that a DERP client needs to interoperate with Go `derpserver`. It also covers the conditions of the test server started by this repository's `Tools/interop` `tailnet`.

M4 preparation covers the byte formats of STUN binding requests and responses and a summary of netcheck's home region selection rules.

Outside the scope are details of mesh (server-to-server) behavior, WebSocket and HTTP proxy paths, the DERP server implementation, WireGuard and disco message contents (`wireguard.md`, `disco-magicsock.md`), and the rules for receiving DERPMap in map responses (`control-map.md`).

## 3. Wire format

### 3.1 Frame header

Every DERP frame has a 5-byte header followed by its body. The length is the number of bytes in the body, excluding the header (`tailscale.com/derp/derp.go:36`, `:51-53`, `:209-216`).

| Offset | Length | Field | Encoding |
| --- | --- | --- | --- |
| 0 | 1 | frame type | u8, table in 3.2 |
| 1 | 4 | length | uint32 BE, body byte count |
| 5 | length | Body | Depends on type |

On receipt, a body larger than 1 MiB (`1<<20`) causes the client to drop the connection with an error (`tailscale.com/derp/derp_client.go:556-558`). On send, the packet body (excluding the destination key) must be at most `MaxPacketSize = 65536` bytes (`tailscale.com/derp/derp.go:28`, `tailscale.com/derp/derp_client.go:266-268`).

### 3.2 Frame types

C is the client and S is the server. "Go client handling" reflects `derp.Client.Recv` and the magicsock read loop.

| Type | Value | Direction | Body | Go client handling | Origin |
| --- | --- | --- | --- | --- | --- |
| `FrameServerKey` | `0x01` | S→C | 3.3 | Reads only during the handshake. Skips it like an unknown frame if it arrives later | `derp/derp.go:72`, `derp/derp_client.go:157-171`, `:581-582` |
| `FrameClientInfo` | `0x02` | C→S | 3.4 | | `derp/derp.go:73` |
| `FrameServerInfo` | `0x03` | S→C | 3.5 | Opens it and sets the rate limit. Failure to open is a connection error | `derp/derp.go:74`, `derp/derp_client.go:583-599` |
| `FrameSendPacket` | `0x04` | C→S | 0:32 destination node public key, 32 onward: packet | | `derp/derp.go:75`, `derp/derp_client.go:278-287` |
| `FrameRecvPacket` | `0x05` | S→C | 0:32 sender node public key, 32 onward: packet (protocol version 2) | Drops bodies shorter than 32 bytes | `derp/derp.go:47-49`, `:77`, `derp/derp_client.go:665-673` |
| `FrameKeepAlive` | `0x06` | S→C | None (length 0) | Sends no reply | `derp/derp.go:78`, `derp/derp_client.go:600-603` |
| `FrameNotePreferred` | `0x07` | C→S | 1 byte, `0x01` for home, otherwise `0x00` | | `derp/derp.go:79`, `derp/derp_client.go:350-371` |
| `FramePeerGone` | `0x08` | S→C | 0:32 peer public key, 32:1 reason (3.6) | Drops bodies shorter than 32 bytes. Uses `0x00` if the reason byte is absent | `derp/derp.go:88`, `derp/derp_client.go:604-618` |
| `FramePeerPresent` | `0x09` | S→C | 0:32 key, 32:16 IP, 48:2 port BE, 50:1 flags, 51:1 name length n, 52:n AppName. Everything after 32 bytes is optional | Arrives only on mesh watch connections | `derp/derp.go:93-102`, `:154-157`, `derp/derp_client.go:620-663` |
| `FrameForwardPacket` | `0x0a` | mesh | 0:32 sender, 32:32 destination, 64:packet | Ordinary clients do not use it | `derp/derp.go:76` |
| `FrameWatchConns` | `0x10` | mesh | None | The server disconnects an ordinary client that sends it | `derp/derp.go:110`, `derp/derpserver/derpserver.go:1323-1332` |
| `FrameClosePeer` | `0x11` | mesh | 0:32 key of the peer to close | The server disconnects an ordinary client that sends it | `derp/derp.go:116`, `derp/derpserver/derpserver.go:1357-1363` |
| `FramePing` | `0x12` | C→S, S→C | 8-byte opaque value | Sends `FramePong` with the same 8 bytes on receipt. Drops bodies shorter than 8 bytes | `derp/derp.go:118`, `derp/derp_client.go:675-682`, `wgengine/magicsock/derp.go:640-648` |
| `FramePong` | `0x13` | C→S, S→C | 8 bytes from the received ping | Consumes it if it matches a ping it sent | `derp/derp.go:119`, `derp/derphttp/derphttp_client.go:1129-1136` |
| `FrameHealth` | `0x14` | S→C | The entire body is an error string. An empty string means recovery | Used only for status display | `derp/derp.go:121-126`, `derp/derp_client.go:693-694`, `wgengine/magicsock/derp.go:649-651` |
| `FrameRestarting` | `0x15` | S→C | 0:4 `ReconnectIn` ms, 4:4 `TryFor` ms, each uint32 BE | Drops bodies shorter than 8 bytes. magicsock ignores it | `derp/derp.go:128-133`, `derp/derp_client.go:696-704`, `wgengine/magicsock/derp.go:667-669` |

(Source paths omit `tailscale.com/`.)

For unknown types, the client reads the entire body and skips it (`tailscale.com/derp/derp_client.go:581-582`). The server drops the frame if its body is at most `MaxPacketSize + 32 = 65568` bytes and closes the connection if it exceeds that limit (`tailscale.com/derp/derpserver/derpserver.go:1296`, `:1303-1309`). The server also drops `FramePong` sent by a client as an unknown frame (`derpserver.go:1263-1278`).

This version of `derpserver` sends only ServerKey, ServerInfo, RecvPacket, KeepAlive, PeerGone, PeerPresent, and Pong. The `derpserver` package does not write `FramePing`, `FrameHealth`, or `FrameRestarting` (`WriteFrameHeader` calls in `derp/derpserver/derpserver.go` at `:1910`, `:2746`, `:2753`, `:2781`, `:2793`, `:2889`, and `sendServerKey` at `:1828-1835`). Other server implementations may send them, so the client handles them as shown in the table.

### 3.3 FrameServerKey body (S→C)

| Offset | Length | Field | Value |
| --- | --- | --- | --- |
| 0 | 8 | magic | `44 45 52 50 f0 9f 94 91` (`"DERP🔑"`) |
| 8 | 32 | Server DERP public key | Curve25519, raw |
| 40 | Remainder | Future extension | Ignore |

The client checks for type `0x01`, length of at least 40, and matching magic, and rejects a body longer than 1024 bytes. It discards any bytes after the first 40 (`tailscale.com/derp/derp.go:32`, `tailscale.com/derp/derp_client.go:157-171`). The server sends exactly 40 bytes (`tailscale.com/derp/derpserver/derpserver.go:1828-1835`).

### 3.4 FrameClientInfo body (C→S)

| Offset | Length | Field | Encoding |
| --- | --- | --- | --- |
| 0 | 32 | Client node public key | Raw. Same key as the WireGuard public key (the client is created with magicsock's `privateKey`) |
| 32 | 24 | nonce | Random |
| 56 | 16 | Poly1305 tag | |
| 72 | n | JSON ciphertext | XSalsa20 |

Sources are `tailscale.com/derp/derp_client.go:232-249`, `tailscale.com/types/key/node.go:136-143`, and `tailscale.com/wgengine/magicsock/derp.go:399`.

Encryption (NaCl `box.Seal`, `golang.org/x/crypto@v0.58.0/nacl/box/box.go:81-93`, `nacl/secretbox/secretbox.go:47-119`).

1. `s = X25519(client private key, server public key)`.
2. `k = HSalsa20(key: s, input: 0^16)`.
3. `subKey = HSalsa20(key: k, input: nonce[0..<16])`, and the XSalsa20 stream nonce is `nonce[16..<24]`.
4. The first 32 bytes of block 0 are the Poly1305 key. XOR the plaintext with the keystream starting at zero-based offset 32 of block 0 (`nacl/secretbox/secretbox.go:85-112`).
5. The output is `tag(16) ‖ ciphertext`. The tag is Poly1305 over the entire ciphertext.

This repository's `SwiftailCrypto` uses the same construction. `NaClBox.sharedKey` implements steps 1–2, and `NaClSecretBox.seal` and `open` implement steps 3–5 (`Sources/SwiftailCrypto/NaCl.swift:4-56`).

For plaintext JSON (`ClientInfo`, `tailscale.com/derp/derp_client.go:196-219`), Go writes fields in struct declaration order. The server reads them in any order.

| JSON key | Type | Omission rule | Value sent by Go magicsock |
| --- | --- | --- | --- |
| `meshKey` | String | Omit if zero value | Omitted |
| `version` | Integer | Omit if 0 | `2` (`ProtocolVersion`, `derp/derp.go:49`) |
| `CanAckPings` | bool | Always include | `true` (`wgengine/magicsock/derp.go:422`) |
| `IsProber` | bool | Omit if false | Omitted |
| `AppName` | String | Omit if empty. Must be at most 32 bytes of printable ASCII (`0x20`–`0x7e`) | magicsock `Options.DERPAppName` (`wgengine/magicsock/derp.go:417`) |

For example, with `{"version":2,"CanAckPings":true}` (32 bytes), the body is 32 + 24 + 16 + 32 = 104 bytes, and the frame is 109 bytes.

During validation (`tailscale.com/derp/derpserver/derpserver.go:1922-1956`), the server closes the connection if the type differs from `0x02`, the body is shorter than 56 bytes or larger than 256 KiB (`256<<10`), the box fails to open, the JSON is invalid, or `AppName` violates its rules. See `tailscale.com/derp/derp_client.go:97-112` for the `AppName` rules.

### 3.5 FrameServerInfo body (S→C)

| Offset | Length | Field |
| --- | --- | --- |
| 0 | 24 | nonce |
| 24 | 16 | Poly1305 tag |
| 40 | n | JSON ciphertext |

The server seals with the server private key and the client public key. The client opens with its own private key and the server public key. X25519 is symmetric, so both use the same `k` as in 3.4 (`tailscale.com/derp/derpserver/derpserver.go:1903-1917`, `tailscale.com/types/key/node.go:148-157`, `tailscale.com/derp/derp_client.go:174-192`).

The plaintext JSON (`tailscale.com/derp/derp.go:304-309`) has `version` (integer, omitted if 0), `TokenBucketBytesPerSecond`, and `TokenBucketBytesBurst` (integers, omitted if 0). This version of the server sends only `{"version":2}` (`derpserver.go:1904`). The body in this case is 24 + 16 + 13 = 53 bytes.

The `FrameServerInfo` parser rejects a body shorter than 24 bytes or larger than `24 + 1 MiB`. Failure to open or decode JSON also causes a connection error (`tailscale.com/derp/derp_client.go:174-192`, `:590-593`). The general 1 MiB receive limit in §3.1 applies before parsing.

### 3.6 PeerGone reason codes

| Value | Name | Meaning |
| --- | --- | --- |
| `0x00` | `PeerGoneReasonDisconnected` | A peer that previously sent a packet to this client disconnected from the region |
| `0x01` | `PeerGoneReasonNotHere` | The server does not know the destination peer for the packet |
| `0xf0` | `PeerGoneReasonMeshConnBroke` | Internal to the client. Never appears on the wire |

See `tailscale.com/derp/derp.go:141-143`. The server sends `NotHere` only if the destination is absent and the packet is a disco message, up to 1 per second (burst of 3) per client connection (`tailscale.com/derp/derpserver/derpserver.go:1092-1100`, `:1174`, `:1497-1502`). It sends `Disconnected` for a peer that has disappeared from the region (`derpserver.go:1694-1696`).

### 3.7 HTTP upgrade request and response

Request (bytes written by the client, Go `http.Request.Write`).

```
GET /derp HTTP/1.1\r\n
Host: <HostName>[:<DERPPort>]\r\n
User-Agent: Go-http-client/1.1\r\n
Connection: Upgrade\r\n
Upgrade: DERP\r\n
[Ideal-Node: <Region.Nodes[0].Name>\r\n]
\r\n
```

- The path is `/derp`. Append the port to Host only if it differs from the default for the URL scheme (443 for TLS, 80 for plaintext) (`tailscale.com/derp/derphttp/derphttp_client.go:280-295`, `:511`).
- Include `Upgrade: DERP` and `Connection: Upgrade` (`derphttp_client.go:515-516`). The server checks only whether the `Upgrade` value matches `derp` or `websocket` case-insensitively. Otherwise, it returns 426 (`tailscale.com/derp/derpserver/handler.go:34-41`).
- Include `Ideal-Node` only when connected to a node other than the first node in the region. The server uses it for statistics (`derphttp_client.go:517-520`, `tailscale.com/derp/derp.go:160-164`).
- Always include the Host header. The Go HTTP/1.1 server returns 400 if Host is missing (`Go 1.27.3/src/net/http/server.go:1072`).
- Send `Derp-Fast-Start: 1` only when the server key is already known from the server's meta certificate in TLS 1.3 (4.2).

Response (without fast-start, bytes written directly to the socket by the server, `tailscale.com/derp/derpserver/handler.go:58-78`).

```
HTTP/1.1 101 Switching Protocols\r\n
Upgrade: DERP\r\n
Connection: Upgrade\r\n
Derp-Version: 2\r\n
Derp-Public-Key: <server public key as 64 lowercase hex digits>\r\n
\r\n
```

The server immediately follows this by writing `FrameServerKey` to the same connection (`handler.go:108`, `tailscale.com/derp/derpserver/derpserver.go:1137-1143`). The client preserves any bytes already received after the end of the response header (`\r\n\r\n`) and passes them to the frame reader. The Go client also reads the response and frames with the same buffer (`derphttp_client.go:508`, `:552`, `:562`). The Go client checks only for status code 101 and skips reading `Derp-Version` and `Derp-Public-Key` (`derphttp_client.go:552-561`). If the status is not 101, it includes the first 1 KiB of the body in the error (`derphttp_client.go:340`, `:556-559`).

### 3.8 STUN binding request (M4)

Integers are BE. Go constructs a 40-byte request (`tailscale.com/net/stun/stun.go:17-34`, `:48-71`).

| Offset | Length | Field | Value |
| --- | --- | --- | --- |
| 0 | 2 | message type | `00 01` (binding request) |
| 2 | 2 | message length | `00 14` (20 bytes after the header, including FINGERPRINT) |
| 4 | 4 | magic cookie | `21 12 a4 42` |
| 8 | 12 | transaction ID | Cryptographically random value (`stun.go:40-46`) |
| 20 | 2 | SOFTWARE attribute type | `80 22` |
| 22 | 2 | Attribute length | `00 08` |
| 24 | 8 | Value | ASCII `tailnode` (no padding) |
| 32 | 2 | FINGERPRINT attribute type | `80 28` |
| 34 | 2 | Attribute length | `00 04` |
| 36 | 4 | Value | `CRC32-IEEE(bytes 0..<32) XOR 0x5354554e` |

The Go STUN servers (`net/stunserver`, `stuntest`, and `tailnet` in `Tools/interop`) filter requests with `ParseBindingRequest`. They respond only if the SOFTWARE value is exactly `tailnode`, the last attribute is FINGERPRINT, and the CRC matches. Otherwise, they silently drop the request (`tailscale.com/net/stun/stun.go:87-122`, `tailscale.com/net/stunserver/stunserver.go:110`, `Tools/interop/cmd/tailnet/main.go:77-80`). Swiftail must therefore construct the 40 bytes exactly as shown above.

### 3.9 STUN binding response (M4)

| Offset | Length | Field | Value |
| --- | --- | --- | --- |
| 0 | 2 | message type | `01 01` (success) |
| 2 | 2 | message length | Total attribute length |
| 4 | 4 | magic cookie | `21 12 a4 42` |
| 8 | 12 | transaction ID | Value from the request |
| 20 | … | Attributes | Each attribute has 0:2 type, 2:2 value length L, 4:L value, followed by padding to a 4-byte boundary |

Address attribute values

| Offset | Length | Field | Encoding |
| --- | --- | --- | --- |
| 0 | 1 | Reserved | Go server uses 0 |
| 1 | 1 | family | `01` IPv4, `02` IPv6. Other values are format errors |
| 2 | 2 | port | BE. XOR attributes use `port XOR 0x2112` |
| 4 | 4 or 16 | address | In XOR attributes, XOR the first 4 bytes with the cookie and the remaining 12 bytes of IPv6 with the transaction ID. MAPPED-ADDRESS is unchanged |

Attribute types are XOR-MAPPED-ADDRESS `0x0020`, alternate `0x8020` (handled identically), and MAPPED-ADDRESS `0x0001` (`stun.go:17-27`). The Go server response contains only one XOR-MAPPED-ADDRESS and omits FINGERPRINT (`stun.go:155-191`). See `stun.go:134-152`, `:175-189`, and `:252-305`.

## 4. Procedures and state machines

### 4.1 Node selection, TCP, TLS

1. Check the region's `Nodes` in order. Skip `STUNOnly` nodes. Try a TCP connection to each node and use the first that succeeds. A TLS failure ends the entire connection attempt without proceeding to the next node (`tailscale.com/derp/derphttp/derphttp_client.go:640-661`, `:477-486`).
2. For TCP to a single node, if `IPv4` is empty, resolve `HostName` through DNS. If it is an IPv4 address, use that address. Any other value (conventionally `"none"`) disables IPv4. IPv6 follows the same rules. If neither is usable, the attempt fails. Try both concurrently and use the first to succeed. If IPv6 is deemed preferable, delay the IPv4 attempt by 200 ms (`derphttp_client.go:725-731`, `:769-821`, `tailscale.com/tailcfg/derpmap.go:216-228`).
3. Use `DERPPort` if nonzero, otherwise 443 for TLS (3340 for plaintext) (`derphttp_client.go:796-802`).
4. A region client (`NewRegionClient`, used by magicsock) uses TLS by default. Plaintext is available only with `NewClient` given an `http://` URL or with the `TS_DEBUG_USE_DERP_HTTP` environment variable (`derphttp_client.go:252`, `:261-270`). DERP therefore uses TLS in Go peer interop tests too.
5. The TLS server name is `HostName` (`derphttp_client.go:273-278`, `:667`). Apply these certificate validation rules.
   - If `InsecureForTests` is true, skip validation (`derphttp_client.go:669-672`).
   - If `CertName` is `sha256-raw:<hex>`, there must be exactly one certificate after excluding the meta certificate, and the SHA-256 hex digest of its entire DER must match. The current time must be within the certificate's validity period. If a name was sent in SNI, the certificate must be valid for that name. When `HostName` is an IP literal, the client sends no SNI (`hostnameInSNI` in `crypto/tls`), so it skips the name check (`derphttp_client.go:673-679`, `tailscale.com/net/tlsdial/tlsdial.go:316-358`. Verified against source and added during M8 ③ implementation on 2026-11-15).
   - For other `CertName` values, verify the certificate against that name. If it is empty, verify against `HostName` (`tailscale.com/tailcfg/derpmap.go:204-214`, `tlsdial.go:242-272`).
6. The entire connection (DNS, TCP, TLS, HTTP, and DERP handshake) is capped at 10 seconds, and a single node's TCP attempt at 1.5 seconds (`derphttp_client.go:359-363`, `:733`, `:764`).

### 4.2 HTTP upgrade

1. Write the request in 3.7 and flush.
2. Read the response header. If the status is not 101, fail.
3. Use the bytes remaining after the header directly as the start of DERP frame reading.

Optional fast-start applies when TLS is 1.3, the server certificate chain has a certificate with CN `derpkey<64 hex digits>`, and its serial number fits in 8 bits. The client uses the key as the server key and the serial number as the protocol version (`derphttp_client.go:499-503`, `:1198-1209`, `tailscale.com/derp/derpconst/derpconst.go:11`). It adds `Derp-Fast-Start: 1` to the request and writes `FrameClientInfo` immediately without waiting for the response (`derphttp_client.go:530-543`). The server skips the 101 response and still sends `FrameServerKey` (`tailscale.com/derp/derpserver/handler.go:43`, `:58`, `derpserver.go:1141`). The server includes a meta certificate only when its operator uses `ModifyTLSConfigToAddMetaCert` (`derpserver.go:851-874`).

### 4.3 DERP handshake

1. Read and validate `FrameServerKey` (3.3). Skip this step with fast-start (`tailscale.com/derp/derp_client.go:142-148`).
2. Write `FrameClientInfo` (3.4).
3. For a home region connection, immediately write `FrameNotePreferred` with `0x01` (`tailscale.com/derp/derphttp/derphttp_client.go:572-577`). Omit this frame for other regions.
4. The client can now send. The Go client handles `FrameServerInfo` in the read loop without waiting for it before sending (`derp_client.go:583-589`).
5. The server sets a 10-second deadline each for sending ServerKey and receiving ClientInfo. When validation finishes, the server clears the deadline and sends `FrameServerInfo` (`tailscale.com/derp/derpserver/derpserver.go:1139-1156`, `:1200`).

### 4.4 Sending

1. Write `FrameSendPacket` as one unit consisting of the header (`0x04`, length 32 + n), the 32-byte destination public key, and the n-byte packet (n ≤ 65536). Go holds a write lock, writes one complete frame, and then flushes. Frames must not interleave when several tasks write to the same connection (`tailscale.com/derp/derp_client.go:259-288`).
2. If `FrameServerInfo` gives a nonzero `TokenBucketBytesPerSecond`, the client maintains a token bucket with the given rate and burst. It silently drops the packet without an error if `5 + 32 + n` tokens are unavailable. A zero value removes the limit (`derp_client.go:272-277`, `:709-720`). This server version does not send these values (3.5).
3. magicsock maintains a write queue of depth 32 per region connection. Try to enqueue the new request up to 3 times total. On a full queue, try to remove the oldest request. If all attempts fail, drop the new packet (`tailscale.com/wgengine/magicsock/derp.go:329`, `tailscale.com/wgengine/magicsock/magicsock.go:1696-1718`).
4. The destination queue on the server also has depth 32. If full, drop the packet at the front (the oldest) (`tailscale.com/derp/derpserver/derpserver.go:89`, `:2204-2223`).

### 4.5 Read loop

The client reads continuously while the connection is alive. It sets a 120-second deadline for each read (`tailscale.com/derp/derp_client.go:525-541`). The server sends KeepAlive every 60 seconds + [0, 5) seconds, so something arrives within this deadline (`tailscale.com/derp/derp.go:41-44`, `tailscale.com/derp/derpserver/derpserver.go:2635-2637`).

Handle each frame type as the Go client does in the table in 3.2.

1. `FrameRecvPacket`. The first 32 bytes are the sender's node public key. Go records this region connection as a reverse path for a newly seen sender (§4.9). Go handles bare disco with the 38-byte classification rule in [disco-magicsock.md §4.3](disco-magicsock.md#43-receiving-over-derp) (`tailscale.com/wgengine/magicsock/derp.go:734-777`). The M3 Swiftail engine drops disco beginning with magic `54 53 f0 9f 92 ac` (`"TS💬"`) at the 6 + 32 + 24 = 62-byte threshold used by `disco.LooksLikeDiscoWrapper`. Before forwarding other packets to WireGuard, Go looks up the peer by the sender key and drops the packet if the peer is unknown (`tailscale.com/wgengine/magicsock/derp.go:613-628`, `tailscale.com/wgengine/magicsock/magicsock.go:747-753`, `tailscale.com/disco/disco.go:35`, `:62-67`).
2. `FramePing`. Send `FramePong` with the same 8 bytes (`tailscale.com/wgengine/magicsock/derp.go:640-648`).
3. `FramePeerGone`. Delete the peer's reverse path if it points to this connection (`wgengine/magicsock/derp.go:652-666`).
4. `FrameServerInfo`. Open it and set the rate limit (4.4 2).
5. KeepAlive, Health, Restarting, PeerPresent, Pong (other than a reply to the client's own ping), and unknown types. Ignore except for recording status (`wgengine/magicsock/derp.go:607-670`).

The server sets a 2-second write deadline when writing to the client. If the client fails to read and the deadline expires, the server's write fails and the connection ends (`tailscale.com/derp/derpserver/derpserver.go:90`, `:2716-2741`). Keep reading from the socket without long pauses even if the upper layer is slow to take received packets.

### 4.6 Disconnects and reconnection

1. After a read or write error, stop using that `derp.Client` (read errors are sticky, `tailscale.com/derp/derp_client.go:519-539`). `derphttp.Client` closes the TCP connection and establishes a new connection from 4.1 on the next `Send` or `Recv` (`tailscale.com/derp/derphttp/derphttp_client.go:937-946`, `:1124-1145`, `:1183-1194`).
2. On error, the magicsock read loop clears all reverse paths learned on this connection, starts STUN remeasurement, backs off, and calls read again (thus reconnecting) (`tailscale.com/wgengine/magicsock/derp.go:563-598`).
3. For n consecutive failures, back off for `min(n² × 10 ms, 5 s)` multiplied by a random number in [0.5, 1.5). Reset n to 0 on receipt of any message (`tailscale.com/util/backoff/backoff.go:49-77`, `wgengine/magicsock/derp.go:558`, `:599`).
4. The new connection repeats the handshake from the beginning and sends `NotePreferred(true)` again if it is home (4.3).
5. If there are two or more connections to the server with the same key, the default server policy (`lastWriterIsActive`) sends packets only to the connection that most recently sent a frame (`tailscale.com/derp/derpserver/derpserver.go:112`, `:1860-1862`). Close the previous connection before reconnecting.

### 4.7 Conditions under which the server disconnects (ordinary clients)

| Condition | Origin (`tailscale.com/derp/derpserver/`) |
| --- | --- |
| No valid `FrameClientInfo` within 10 seconds after upgrade, or validation in 3.4 fails | `derpserver.go:1139-1148`, `:1922-1956` |
| Client verification fails (when tailscaled or an admission URL is configured on a production server. The test server has neither) | `derpserver.go:1761-1826` |
| `FrameNotePreferred` body length differs from 1 byte | `derpserver.go:1311-1314` |
| `FrameSendPacket` body is shorter than 32 bytes or packet exceeds 65536 bytes | `derpserver.go:1962-1972` |
| `FramePing` body is shorter than 8 bytes or exceeds 1000 bytes | `derpserver.go:1334-1344` |
| `FrameWatchConns` or `FrameClosePeer` without a mesh key, or with an invalid length | `derpserver.go:1323-1332`, `:1357-1363` |
| Body of an unknown type exceeds 65568 bytes | `derpserver.go:1296-1309` |
| Server cannot write within 2 seconds | `derpserver.go:2716-2741` |

Packets addressed to a destination peer the server cannot find are dropped while the connection stays open (3.6, `derpserver.go:1483-1508`).

### 4.8 Home region selection and notification

Go magicsock behavior

1. Use `PreferredDERP` from the netcheck report. If it is 0 (UDP is blocked and there are no measurements), keep the existing home. If there is also no existing home, choose one of the region IDs in `DERPMap` (`tailscale.com/wgengine/magicsock/derp.go:114-148`, `:197-202`).
2. If the map stream to the control server is disconnected, keep the existing home unless forced to change it, because peers cannot be notified of a new home (`derp.go:160-195`).
3. When the home changes, send `NotePreferred(that region == home)` on all open region connections and open a connection to the home region (`derp.go:283-295`, `:423`). The server uses `NotePreferred` only for statistics (`tailscale.com/derp/derp_client.go:347-349`).
4. Put the selected home in `Hostinfo.NetInfo.PreferredDERP` and upload it to the control server (`tailscale.com/wgengine/magicsock/magicsock.go:1075`, `tailscale.com/tailcfg/tailcfg.go:1128-1135`). The control server sends this value to other nodes as the node's `HomeDERP`. testcontrol stores a map request's nonzero `NetInfo.PreferredDERP` as the node's `HomeDERP` (`tailscale.com/tstest/integration/testcontrol/testcontrol.go:1471-1496`).
5. Skip measuring `NoMeasureNoHome` regions and exclude them from home selection. If a peer advertises such a region as home, a connection can still be opened to communicate with that peer (`tailscale.com/tailcfg/derpmap.go:161-169`). The fallback selection in step 1 ignores this field and chooses from all region IDs (`derpmap.go:40-47`, `derp.go:121-147`).

A fixed choice suffices for M3 because Go also picks a region without measuring when there are no netcheck results (step 1). The test DERPMap contains only region 1 (§7), so the Go peer uses 1 as home regardless of measurements, and both sides use the same server if Swiftail chooses 1. If Swiftail does not upload `PreferredDERP`, the Go peer sees Swiftail's `HomeDERP` as 0 and has nowhere to send until Swiftail sends first and creates a reverse path (4.9 3).

### 4.9 Region for sending to a peer and origin of received packets

1. The peer's home region is `Node.HomeDERP` in the map. Map processing converts the `DERP` string (`"127.3.3.40:<region ID>"`) sent by older servers to `HomeDERP` (`tailscale.com/tailcfg/tailcfg.go:406-423`). magicsock represents this as the synthetic address `127.3.3.40:<region ID>` and uses it for DERP path selection inside magicsock. WireGuard's endpoint is the magicsock peer object (see [wireguard.md](wireguard.md#connbind-and-connendpoint)) (`tailscale.com/wgengine/magicsock/endpoint.go:1733-1753`, `tailscale.com/tailcfg/tailcfg.go:3072-3079`).
2. Select a connection for sending (`tailscale.com/wgengine/magicsock/derp.go:339-475`).
   1. If a connection to the peer's home region is already open, use it.
   2. Otherwise, use a region connection that previously received a packet from the peer (reverse path) if it is still the same connection.
   3. Otherwise, open a new connection to the peer's home region.
3. If there is no direct path and the peer's `HomeDERP` is also 0, use the peer's reverse-path region. If that is also unavailable, the packet cannot be sent (`tailscale.com/wgengine/magicsock/endpoint.go:635-652`, `:1133-1143`).
4. The origin of a received packet is the sender key in `FrameRecvPacket` and the receiving region. magicsock represents the origin internally as `127.3.3.40:<receiving region ID>` and passes the sender's peer endpoint object to WireGuard (`tailscale.com/wgengine/magicsock/magicsock.go:747`, `tailscale.com/wgengine/magicsock/derp.go:747-777`). Clear a reverse path on a connection error or when receiving that peer's `FramePeerGone` on the connection (4.5, 4.6).
5. Close a non-home region connection 60 seconds after the last write request. Check every 15 seconds (`tailscale.com/wgengine/magicsock/derp.go:990-1019`, `:1071-1077`).

### 4.10 STUN queries and netcheck home selection (M4)

1. For each region, send the request from 3.8 to the node's `STUNPort` (3478 if 0, disabled if -1). Add the outgoing transaction ID to the in-flight table and use the response for that region's latency and external address only if its ID is in the table (`tailscale.com/net/netcheck/netcheck.go:1608-1643`, `:331-353`, `tailscale.com/tailcfg/derpmap.go:230-233`).
2. Send STUN through the same UDP socket as WireGuard so the address in the response is a WireGuard endpoint (`tailscale.com/wgengine/magicsock/magicsock.go:713`, `:1632-1644`).
3. Response parsing (`tailscale.com/net/stun/stun.go:195-250`, `:307-312`) requires at least 20 bytes, the top 2 bits of the first byte set to 0, a matching cookie, type `01 01`, and a declared length no larger than the remaining bytes (discard extra bytes). Each attribute's length and padding must fit within the remaining bytes. Use the XOR address if present, otherwise MAPPED-ADDRESS. If neither exists, return an error. An invalid family or short address attribute makes the entire response invalid. Skip FINGERPRINT validation in the response.
4. The report timeout is 5 seconds and the STUN wait is 3 seconds (`netcheck.go:61`, `:66`). If no UDP responses arrive, measure the round trip of HTTPS `GET https://<HostName>/derp/latency-check` instead. Status 300 or higher is a failure (`netcheck.go:1198-1216`).
5. For home selection (`netcheck.go:1426-1531`), use reports from the last 5 minutes 5 seconds (`fullReportInterval + ReportTimeout`). Multiply each region's minimum latency by `HomeParams.RegionScore` (only if positive) and pick the lowest result among regions with a latency measurement in the current report. If the current home is still reachable (latency in the current report or a DERP frame received since the current report began or within the last 8 seconds), keep it if the difference from the new candidate is less than 10 ms or the candidate's weighted latency exceeds 2/3 of the existing home's weighted current latency. If there are no measurements at all, keep the current home if it delivered a frame within the last 120 seconds (`netcheck.go:1379-1401`, `:1416`).

## 5. Constants and timers

| Item | Value | Origin (`tailscale.com/`) |
| --- | --- | --- |
| `ProtocolVersion` | 2 | `derp/derp.go:49` |
| Frame header | 5 bytes | `derp/derp.go:36` |
| `MaxPacketSize` | 65536 bytes (excluding destination key and header) | `derp/derp.go:28` |
| Client receive body limit | 1 MiB | `derp/derp_client.go:556` |
| ServerKey body limit (client) | 1024 bytes | `derp/derp_client.go:159` |
| ClientInfo body (server) | At least 56 bytes and at most 256 KiB | `derp/derpserver/derpserver.go:1927-1935` |
| ServerInfo body (parser, also subject to the general receive limit in §3.1) | At least 24 bytes and at most 24 + 1 MiB | `derp/derp.go:38`, `derp/derp_client.go:175-182` |
| Server KeepAlive | 60 seconds + [0, 5) seconds | `derp/derp.go:44`, `derp/derpserver/derpserver.go:2635-2637` |
| Client read deadline | 120 seconds | `derp/derp_client.go:526` |
| Server handshake deadline | 10 seconds per step | `derp/derpserver/derpserver.go:1139`, `:1144` |
| Server write deadline | 2 seconds | `derp/derpserver/derpserver.go:90`, `:2716-2741` |
| Overall connection limit | 10 seconds | `derp/derphttp/derphttp_client.go:362` |
| Node TCP limit | 1.5 seconds, with IPv4 delayed by 200 ms if IPv6 is preferred | `derp/derphttp/derphttp_client.go:733`, `:784-795` |
| `derphttp.Client.Ping` maximum wait | 5 seconds | `derp/derphttp/derphttp_client.go:982-988` |
| Reconnect backoff | `min(n²×10ms, 5s) × [0.5, 1.5)` | `util/backoff/backoff.go:60-66`, `wgengine/magicsock/derp.go:558` |
| magicsock region write queue | 32, 3 enqueue attempts | `wgengine/magicsock/derp.go:329`, `wgengine/magicsock/magicsock.go:1699-1718` |
| Server destination queue | 32, drops the oldest when full | `derp/derpserver/derpserver.go:89`, `:2204-2223` |
| Non-home connection cleanup | 60 seconds unused, checked every 15 seconds | `wgengine/magicsock/derp.go:1071-1077` |
| `AppName` | At most 32 bytes of ASCII `0x20`–`0x7e` | `derp/derp_client.go:97-112` |
| Default STUN port | 3478 if 0, -1 disables STUN | `tailcfg/derpmap.go:230-233` |
| netcheck report and STUN wait | 5 seconds, 3 seconds | `net/netcheck/netcheck.go:61`, `:66` |

## 6. The minimum Swiftail needs and what it can omit (M3)

Requirements

1. TCP + TLS (4.1). Region clients use TLS by default and the test server uses TLS (4.1 4, §7). Disable certificate verification only for `InsecureForTests` nodes. Otherwise, verify against `CertName` or `HostName`.
2. HTTP upgrade (3.7, 4.2) and carryover of remaining bytes.
3. Handshake (4.3). Validate ServerKey, use NaCl box for ClientInfo (`version` 2, `CanAckPings` true), send NotePreferred(true) if home, and open ServerInfo.
4. SendPacket and RecvPacket, Pong in response to Ping, clearing reverse paths on PeerGone, skipping unknown frames, and withholding received disco messages from WireGuard (4.4, 4.5).
5. On error, drop the connection and reconnect after backing off (4.6).
6. Fixed home region selection and `NetInfo.PreferredDERP` reporting (4.8), and sending to the peer's home region (4.9).
7. Include a nonzero `DiscoKey` in the map request. Go magicsock does not create a peer with a zero `DiscoKey` unless it is a WireGuard-only node, so it also creates no DERP path (`tailscale.com/wgengine/magicsock/magicsock.go:3305-3309`). Even without a response to disco messages, the Go peer sends over DERP if there is no direct path (`tailscale.com/wgengine/magicsock/endpoint.go:635-652`).

Omissions

| Item | Rationale |
| --- | --- |
| All of STUN and netcheck | DERP sends and receives using only node keys for addressing (3.2). Peers send to Swiftail's `HomeDERP`, so they need no external Swiftail address (4.8 4, 4.9). Region measurement and home changes are in M4 scope (`SwiftailMagicsock` in the module table in `docs/plan.md` §5) |
| fast-start | The test server includes no meta certificate, so the Go client also leaves fast-start unused (4.2, §7) |
| `sha256-raw:` certificate pinning | Added in M8 ③ (M8 ③ in the [SwiftailDERP contract](../contracts/SwiftailDERP.md)) |
| Multiple regions, reverse paths, and non-home connection cleanup | There is one test region. Step 1 of 4.9 2 reaches all peers on its own |
| Client token bucket | This server version does not send the values (3.5). Adding it would take only a few lines |
| `Ideal-Node`, `AppName` | Used for server statistics (3.7, `tailscale.com/derp/derp_client.go:89-95`) |
| Health and Restarting behavior | Go magicsock also ignores them except for recording status (4.5 5) |
| Mesh frames (0x0a, 0x10, 0x11) and PeerPresent | Only for server-to-server connections with a mesh key (3.2) |
| WebSocket, HTTP proxy | Separate paths (`tailscale.com/derp/derphttp/derphttp_client.go:403-436`, `:742-757`) |

## 7. What to verify in interop tests

### 7.1 Server started by `Tools/interop` `tailnet`

| Item | Value | Origin |
| --- | --- | --- |
| DERP server | `derpserver.New(key.NewNode(), …)`, default settings (no verification URL or mesh key) | `Tools/interop/cmd/tailnet/main.go:83` |
| HTTP paths | `ServeMux` has `/derp` (exactly this path) and `/derp/probe` | `main.go:84-86` |
| TLS | `httptest.NewUnstartedServer(mux).StartTLS()`. Loopback port assigned by the OS. Go test self-signed RSA 2048 certificate (names `127.0.0.1`, `::1`, `example.com`, `*.example.com`). ALPN is `http/1.1`. No meta certificate (no fast-start) | `main.go:87-89`, `Go 1.27.3/src/net/http/httptest/server.go:349-368`, `Go 1.27.3/src/net/http/internal/testcert/testcert.go:11-13` |
| DERPMap | 1 region with `RegionID` 1 and `RegionCode` and `RegionName` `"test"`. 1 node with `Name` `"1a"`, `HostName` and `IPv4` `"127.0.0.1"`, `IPv6` `"none"`, random `DERPPort` and `STUNPort`, and `InsecureForTests` true | `main.go:90` |
| STUN server | `udp4` on a random `127.0.0.1` port. Replies with `stun.Response` (one XOR-MAPPED-ADDRESS) only to requests that pass `ParseBindingRequest` | `main.go:66-82` |
| `ready` output | `derp.regionID` 1, `host` `127.0.0.1`, `port`, `stunPort` | `main.go:111-113` |
| Control server | Plaintext HTTP testcontrol. Sets the node's `HomeDERP` from the map request's `NetInfo.PreferredDERP` | `main.go:90-99`, `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1471-1496` |

Swiftail sees connection address `127.0.0.1:<port>`, Host `127.0.0.1:<port>`, TLS name `127.0.0.1`, a self-signed certificate (verification must be disabled), HTTP/1.1, and a ServerKey frame immediately after the 101 response. The Go tsnet peer in the same process receives the same DERPMap, so its home is 1 (4.8).

### 7.2 Checks

1. Handshake. Swiftail receives 101 and ServerKey, sends ClientInfo, and opens ServerInfo to get `{"version":2}`. The server log shows no rejection.
2. Swiftail ↔ Go tsnet peer. The Go peer's `HomeDERP` in Swiftail's map is 1, and the Go peer's `peerStatus` shows Swiftail's home region as `test` (the `relay` code for region ID 1, [Tools/interop/README.md](../../Tools/interop/README.md#tailnet)). The M3 gate (UDP echo round trip, TCP SYN-ACK) passes using DERP alone (`docs/plan.md` §7 M3).
3. The sender key of a received `FrameRecvPacket` equals the Go peer's node key. Disco messages from the Go peer are withheld from WireGuard.
4. Ping/Pong. When Swiftail sends `FramePing`, it receives `FramePong` with the same 8 bytes (`tailscale.com/derp/derpserver/derpserver.go:1334-1355`).
5. KeepAlive. `FrameKeepAlive` arrives every 60–65 seconds and the 120-second read deadline does not expire.
6. Reconnection. Forcibly closing Swiftail's DERP TCP connection causes a reconnect after backoff and restores round trips.
7. Boundary inputs. Drop short RecvPacket, PeerGone, and Ping frames and keep the connection open. Drop the connection on a frame with a body larger than 1 MiB, incorrect magic, or ServerInfo that fails to open (3.2, 3.3, 3.5). The Go server does not generate these cases, so verify them with Swift unit tests.
8. Known-answer tests. Use existing `SwiftailCrypto` test vectors for NaCl box. Compare the ClientInfo byte layout to a frame generated with the same key and nonce by Go `derp.Client` (nonce injection requires a Go test tool).
9. STUN (M4). Send the request in 3.8 to the `tailnet` STUN server and check that it returns `127.0.0.1:<Swiftail UDP port>` and that requests with modified SOFTWARE or FINGERPRINT get no response.

## 8. Unverified details

- When production DERP servers (Tailscale-operated infrastructure) send `FramePing`, `FrameHealth`, and `FrameRestarting`, and whether they advertise `TokenBucketBytesPerSecond`. The public `derpserver` source has no send sites for them (3.2).
- Which TLS version and cipher combination the Network framework actually negotiates with the Go `crypto/tls` server, and whether it sends SNI for an IP address name (`127.0.0.1`). This was not tested.
- When testcontrol reflects Swiftail's `DiscoKey` and `PreferredDERP` in the Go peer's map after receiving them (map stream update latency). Only the code path was checked (`testcontrol.go:1471-1498`).
