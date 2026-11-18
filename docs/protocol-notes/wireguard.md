# WireGuard data plane

The reference sources are `github.com/tailscale/wireguard-go` v0.0.0-20261106233718-9e0ab45c16ca and `tailscale.com` v1.104.6. The authoring model was Claude Opus 5.5. Verified by GPT-6.1 Sol on 2026-11-14, with 31 corrections.

Source references use `wireguard-go/…` (the module root of the fork above) and `tailscale.com/…` (the module root). In this note, "wireguard-go" means the Tailscale fork unless marked otherwise.

## Scope

Covered topics follow.

- Byte layouts for all 4 message types
- Noise IKpsk2 handshake (initiator and responder)
- mac1, mac2, cookie, and under-load state
- Transport data nonce, padding, keepalive, replay protection, and AllowedIPs checks
- Timers and the keypair rotation state machine
- Tailscale fork extension points (`conn.Bind` and `conn.Endpoint`, and lazy peer creation) and configuration supplied by Tailscale
- Reusable tests and the minimum implementation for the M1 gate

The scope excludes the following.

- magicsock path selection, disco, and DERP transport (`disco-magicsock.md`, `derp-stun.md`)
- Packet processing on the TUN and netstack side
- The full UAPI text protocol
- Batching, pooling, and GSO for performance, and platform-specific sticky sockets

## Wire formats

The first 4 bytes of every message are its type. A 1-byte type is followed by three bytes set to 0, and the receiver reads the field as little-endian `uint32` (`wireguard-go/device/noise-protocol.go:81`, `wireguard-go/device/receive.go:142`). Reserved bytes other than 0 therefore cause the message to be dropped as an unknown type (`wireguard-go/device/receive.go:209`). All integer fields (type, sender, receiver, counter) are little-endian (`wireguard-go/device/noise-protocol.go:128`, `wireguard-go/device/noise-protocol.go:144`, `wireguard-go/device/send.go:588`).

| type value | Message | Size |
| --- | --- | --- |
| 1 | `MessageInitiationType` | 148 (`MessageInitiationSize`) |
| 2 | `MessageResponseType` | 92 (`MessageResponseSize`) |
| 3 | `MessageCookieReplyType` | 64 (`MessageCookieReplySize`) |
| 4 | `MessageTransportType` | At least 32 (16 header + 16 tag) |

Sources are `wireguard-go/device/noise-protocol.go:58`, `wireguard-go/device/noise-protocol.go:65`, and `wireguard-go/device/noise-protocol.go:70`.

### Handshake initiation (148 bytes)

| Offset | Length | Field | Contents |
| --- | --- | --- | --- |
| 0 | 4 | Type | `1`, LE uint32 |
| 4 | 4 | Sender | Local index chosen by the initiator, LE uint32 |
| 8 | 32 | Ephemeral | Initiator ephemeral public key, plaintext |
| 40 | 48 | Static | Initiator static public key 32 + Poly1305 tag 16 |
| 88 | 28 | Timestamp | TAI64N 12 + tag 16 |
| 116 | 16 | MAC1 | keyed BLAKE2s-128 |
| 132 | 16 | MAC2 | Keyed BLAKE2s-128 or 0 |

Sources are `wireguard-go/device/noise-protocol.go:87` and `wireguard-go/device/noise-protocol.go:139`.

### Handshake response (92 bytes)

| Offset | Length | Field | Contents |
| --- | --- | --- | --- |
| 0 | 4 | Type | `2` |
| 4 | 4 | Sender | Responder local index |
| 8 | 4 | Receiver | Sender value from the initiation |
| 12 | 32 | Ephemeral | Responder ephemeral public key |
| 44 | 16 | Empty | AEAD tag for empty plaintext |
| 60 | 16 | MAC1 | |
| 76 | 16 | MAC2 | |

Sources are `wireguard-go/device/noise-protocol.go:97` and `wireguard-go/device/noise-protocol.go:171`.

### Cookie reply (64 bytes)

| Offset | Length | Field | Contents |
| --- | --- | --- | --- |
| 0 | 4 | Type | `3` |
| 4 | 4 | Receiver | Sender value of the rejected message (offset 4) |
| 8 | 24 | Nonce | Random XChaCha20 nonce |
| 32 | 32 | Cookie | Encrypted cookie 16 + tag 16 |

Sources are `wireguard-go/device/noise-protocol.go:114`, `wireguard-go/device/noise-protocol.go:200`, and `wireguard-go/device/send.go:258`.

### Transport data

| Offset | Length | Field | Contents |
| --- | --- | --- | --- |
| 0 | 4 | Type | `4` |
| 4 | 4 | Receiver | Sender index sent by the peer in the handshake |
| 8 | 8 | Counter | LE uint64, also used as the nonce |
| 16 | n+16 | Content | ChaCha20-Poly1305 ciphertext of n bytes of padded plaintext + tag |

Sources are `wireguard-go/device/noise-protocol.go:76` and `wireguard-go/device/send.go:588`.

- A keepalive is a transport message with plaintext length 0 and a total size of 32 bytes (`MessageKeepaliveSize`, `wireguard-go/device/noise-protocol.go:71`).
- `MessageEncapsulatingTransportSize` = 8 is headroom before the buffer passed to `conn.Bind.Send`. It is excluded from the WireGuard wire bytes (`wireguard-go/device/noise-protocol.go:69`, `wireguard-go/device/peer.go:226`).

## Procedures and state machines

### Basic operations

- **HASH(x)**: BLAKE2s-256(`wireguard-go/device/noise-protocol.go:240`).
- **MAC(key, x)** uses keyed BLAKE2s-128 initialized for 16 bytes of output. It uses the BLAKE2s key parameter rather than HMAC. Truncating BLAKE2s-256 output to 16 bytes is not equivalent (`wireguard-go/device/cookie.go:79`, `:98`, `:109`).
- **HMAC(key, x)** uses the HMAC construction with BLAKE2s-256 as its hash (`wireguard-go/device/noise-helpers.go:24`).
- **KDF1/2/3(key, input)** (`wireguard-go/device/noise-helpers.go:43`):
  1. prk = HMAC(key, input)
  2. T0 = HMAC(prk, 0x01)
  3. T1 = HMAC(prk, T0 ‖ 0x02)
  4. T2 = HMAC(prk, T1 ‖ 0x03)

  KDF1 returns T0, KDF2 returns (T0, T1), and KDF3 returns (T0, T1, T2). KDF1 overwrites t0 instead of keeping a separate prk and yields the same result (`wireguard-go/device/noise-helpers.go:44`).
- **mixHash(h, d)** = HASH(h ‖ d), **mixKey(ck, d)** = KDF1(ck, d)(`wireguard-go/device/noise-protocol.go:236`).
- **AEAD** uses ChaCha20-Poly1305 IETF (key 32, nonce 12, tag 16). Every AEAD operation in the handshake uses a 12-byte nonce set to 0 (`ZeroNonce`) and AAD = current hash (`wireguard-go/device/noise-protocol.go:233`, `wireguard-go/device/noise-protocol.go:312`).
- **DH(sk, pk)** uses X25519. If all 32 result bytes are 0, it fails with `errInvalidPublicKey` (`wireguard-go/device/noise-helpers.go:100`).
- **Private key clamping** applies at creation and when reading with `FromHex`. The operations are `sk[0] &= 248` and `sk[31] = (sk[31] & 127) | 64`. `FromMaybeZeroHex` does not clamp the value with all bytes set to 0 that denotes key removal (`wireguard-go/device/noise-helpers.go:80`, `wireguard-go/device/noise-types.go:48`, `:54`).
- **index** is a cryptographically random uint32. Draw again if the value is already in use. There is no check excluding 0, so do not reject incoming index 0 unconditionally (`wireguard-go/device/indextable.go:25`, `:58`–`:90`).

### Initial constants

- `NoiseConstruction` = `"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"`
- `WGIdentifier` = `"WireGuard v1 zx2c4 Jason@zx2c4.com"`
- `WGLabelMAC1` = `"mac1----"`
- `WGLabelCookie` = `"cookie--"`

Source is `wireguard-go/device/noise-protocol.go:51`.

- `InitialChainKey` = HASH(`NoiseConstruction`)
- `InitialHash` = HASH(`InitialChainKey` ‖ `WGIdentifier`)

Source is `wireguard-go/device/noise-protocol.go:267`.

### Initiator creates an initiation

S_i/S_r are static keys, E_i/E_r are ephemeral keys, ck is the chaining key, and h is the hash (`wireguard-go/device/noise-protocol.go:272`).

1. Set ck = InitialChainKey and h = InitialHash, and generate a fresh E_i (`:282`).
2. h = mixHash(h, S_r.pub)(`:289`).
3. msg.Ephemeral = E_i.pub. ck = mixKey(ck, E_i.pub), h = mixHash(h, E_i.pub)(`:296`).
4. (ck, k) = KDF2(ck, DH(E_i, S_r.pub)). msg.Static = AEAD(k, 0, S_i.pub, AAD=h). h = mixHash(h, msg.Static)(`:300`–`:313`).
5. If the precomputed DH(S_i, S_r.pub) is 0, stop with `errInvalidPublicKey` (`:316`). This value is precomputed at peer creation and when the private key changes (`wireguard-go/device/peer.go:155`, `wireguard-go/device/device.go:440`).
6. (ck, k) = KDF2(ck, DH(S_i, S_r.pub)). msg.Timestamp = AEAD(k, 0, TAI64N.now, AAD=h)(`:319`–`:327`).
7. Choose a new index for msg.Sender. Delete the previous handshake index (`:330`).
8. Set h = mixHash(h, msg.Timestamp). The state becomes `handshakeInitiationCreated` (`:337`).
9. Serialize, then add mac1 and mac2 (`wireguard-go/device/send.go:198`).

### Responder consumes the initiation

Source is `wireguard-go/device/noise-protocol.go:342`.

1. Drop if type is anything other than 1 (`:348`).
2. h = HASH(HASH(InitialHash ‖ S_r.pub) ‖ E_i.pub), ck = KDF1(InitialChainKey, E_i.pub)(`:360`).
3. Compute (ck, k) = KDF2(ck, DH(S_r, E_i.pub)). Open msg.Static with AEAD (AAD=h). Drop on failure. Set h = mixHash(h, msg.Static) (`:367`–`:377`).
4. If Endpoint is `conn.InitiationAwareEndpoint`, call `InitiationMessagePublicKey` with the decrypted public key (`:381`).
5. Look up the peer with `LookupPeer`. Drop if it is missing or not running (`:386`). The Tailscale section below covers lazy creation.
6. Drop if the precomputed static-static value is 0. Open Timestamp using (ck, k) = KDF2(ck, DH(S_r, S_i.pub)). Drop on failure. Set h = mixHash(h, msg.Timestamp) (`:399`–`:415`).
7. **Replay protection.** Drop as a replay unless the decrypted timestamp is strictly greater than the per-peer `lastTimestamp` in a bytewise comparison (`:419`).
8. **Flood protection.** Drop within `HandshakeInitationRate` (20ms) of the last consumed initiation (`:420`).
9. Store h, ck, remoteIndex = msg.Sender, and remoteEphemeral. Update `lastTimestamp` and `lastInitiationConsumption`, and set the state to `handshakeInitiationConsumed` (`:435`–`:446`).

`lastTimestamp` survives `Handshake.Clear` (`wireguard-go/device/noise-protocol.go:248`). If the peer object persists, a restarted initiator must still send a timestamp strictly greater than the last one accepted by the peer. `TAI64N.Now` only reads the wall clock. It neither guarantees monotonic increase nor compensates for the clock going backward (`wireguard-go/device/noise-protocol.go:419`, `wireguard-go/tai64n/tai64n.go:22`, `:31`).

### Responder creates a response

Source is `wireguard-go/device/noise-protocol.go:456`.

1. Return an error unless the state is `handshakeInitiationConsumed` (`:461`).
2. Write a new index as Sender and remoteIndex as Receiver (`:468`).
3. Generate E_r. Set h = mixHash(h, E_r.pub) and ck = mixKey(ck, E_r.pub) (`:481`).
4. Set ck = mixKey(ck, DH(E_r, E_i.pub)). Then set ck = mixKey(ck, DH(E_r, S_i.pub)) (`:489`–`:498`).
5. Compute (ck, τ, k) = KDF3(ck, PSK) and h = mixHash(h, τ) (`:505`–`:513`). Use 32 bytes set to 0 if there is no PSK. Even when the "PSK layer is disabled," still perform KDF3 and mixHash of τ (`wireguard-go/device/peer.go:195`, `wireguard-go/device/noise-protocol.go:505`, `:583`).
6. Set msg.Empty = AEAD(k, 0, empty plaintext, AAD=h), which is a 16-byte tag. Set h = mixHash(h, msg.Empty). The state becomes `handshakeResponseCreated` (`:515`–`:519`).

### Initiator consumes the response

Source is `wireguard-go/device/noise-protocol.go:524`.

1. Check that type is 2, then look up the Receiver index in the index table. Drop if there is no handshake entry. If the index already points to a keypair, treat it as a "duplicate" and drop it without logging (`:525`, `:531`, `wireguard-go/device/receive.go:390`).
2. Drop unless the state is `handshakeInitiationCreated` (`:556`).
3. Set h = mixHash(h, E_r.pub) and ck = mixKey(ck, E_r.pub). Then set ck = mixKey(ck, DH(E_i, E_r.pub)) and ck = mixKey(ck, DH(S_i, E_r.pub)) (`:562`–`:576`).
4. Compute (ck, τ, k) = KDF3(ck, PSK) and h = mixHash(h, τ). Open msg.Empty with AEAD (AAD=h). Drop on failure. Set h = mixHash(h, msg.Empty) (`:583`–`:599`).
5. Reacquire the lock and apply the result only if the state is still `handshakeInitiationCreated` and localIndex equals Receiver. Applying it sets the state to `handshakeResponseConsumed` and remoteIndex = msg.Sender (`:614`).

### Transport key derivation (`BeginSymmetricSession`)

Source is `wireguard-go/device/noise-protocol.go:635`.

- Initiator (`handshakeResponseConsumed`) computes (sendKey, recvKey) = KDF2(ck, empty input) (`:647`).
- Responder (`handshakeResponseCreated`) computes (recvKey, sendKey) = KDF2(ck, empty input) (`:655`).
- Other states are errors (`:664`).
- Clear ck, h, and the ephemeral private key, and reset the state to `handshakeZeroed` (`:669`).
- A new keypair has sendNonce 0, an empty replay filter, `created` = now, and `isInitiator`. Keep the localIndex and remoteIndex values from the handshake (`:683`–`:687`).
- Replace the index table's handshake entry with a keypair entry at the same index (`:691`, `wireguard-go/device/indextable.go:44`). Thus transport Receiver equals the Sender index sent during the handshake.

### Keypair rotation (previous/current/next)

The following describes `BeginSymmetricSession` (`wireguard-go/device/noise-protocol.go:704`).

| Side | When next exists | When next is absent |
| --- | --- | --- |
| Initiator | previous ← next, delete old current, next ← nil | previous ← current |
| Both initiator cases | Delete old previous, current ← new keypair | |
| Responder | next ← new keypair, delete old next, previous ← nil (delete old previous), keep current | |

- **Responder confirmation.** The responder confirms on receiving the first transport message authenticated with the new keypair. `ReceivedWithKeypair` sets previous ← current, current ← next, next ← nil, and deletes the old previous (`wireguard-go/device/noise-protocol.go:724`, `wireguard-go/device/receive.go:480`).
- **Responder send wait.** Sending always uses only `current` (`wireguard-go/device/send.go:488`). The responder therefore waits for confirmation before sending with the new keypair.
- **Responder in its first session.** With no current keypair, the responder attempts an initiation when it has a packet to send. Sending the response updates `lastSentHandshake`, which prevents the initiation for `RekeyTimeout` (`wireguard-go/device/send.go:170`, `wireguard-go/device/send.go:220`). The packet remains staged and is sent on confirmation (`wireguard-go/device/receive.go:484`).
- **Initiator prompts confirmation.** The initiator calls `SendKeepalive` immediately after processing the response. It sends staged data if available or an empty transport message otherwise, confirming the responder's next keypair. A separate keepalive is not necessarily sent (`wireguard-go/device/receive.go:414`–`:417`, `wireguard-go/device/send.go:85`–`:105`).
- **Keypair deletion.** Only the index table entry is deleted (`wireguard-go/device/keypair.go:48`). Transport messages arriving for the deleted index cannot find a keypair and are dropped (`wireguard-go/device/receive.go:161`).

### mac1, mac2, and cookie

**Keys** (`wireguard-go/device/cookie.go:44`, `wireguard-go/device/cookie.go:173`)

- The receiver (`CookieChecker`) derives keys from its own public key M. The mac1 key is HASH(`"mac1----"` ‖ M), and the cookie encryption key is HASH(`"cookie--"` ‖ M). Reinitialize when the private key changes (`wireguard-go/device/device.go:433`).
- The sender (`CookieGenerator`) derives the same keys for each peer using that peer's public key (`wireguard-go/device/peer.go:137`).

**Adding MACs** (`AddMacs`, `wireguard-go/device/cookie.go:215`)

1. Compute mac1 = MAC(mac1 key, msg[0 : len−32]) (`:229`).
2. Remember that mac1 as `lastMAC1` (`:234`).
3. Leave mac2 untouched if no cookie has been received or more than `CookieRefreshTime` (120 seconds) have elapsed since it was received. Go allocates a fresh send buffer, so the bytes remain set to 0. If Swift reuses buffers, explicitly set the 16 mac2 bytes to 0 on this branch too (`:239`, `wireguard-go/device/send.go:196`, `:231`).
4. Otherwise compute mac2 = MAC(16-byte cookie, msg[0 : len−16]) (`:243`).

**Validation** (`wireguard-go/device/receive.go:310`)

- Always check mac1 on initiation and response with a constant-time comparison. Drop on mismatch (`:314`, `wireguard-go/device/cookie.go:69`).
- Perform additional checks only when `IsUnderLoad()` (`:321`).
  1. Check mac2. If invalid, send a cookie reply and drop the original message (`:325`).
  2. If mac2 is valid, it must pass the per-source-IP rate limiter (`:332`).

**Cookie value and secret** (`wireguard-go/device/cookie.go:86`, `wireguard-go/device/cookie.go:117`)

- The receiver's cookie = MAC(32-byte secret, src).
- src is `Endpoint.DstToBytes()`. In the standard bind, it is the binary representation of `netip.AddrPort` (`wireguard-go/conn/bind_std.go:113`).
- Once 120 seconds have elapsed from the last refresh, `CreateReply` replaces the secret with fresh random bytes (`:126`).
- `CheckMAC2` always fails if the secret is older than 120 seconds (`:90`).
- The cookie is opaque and the sender returns it unchanged, so src encoding does not affect interop.

**Creating a cookie reply** (`wireguard-go/device/cookie.go:155`, `wireguard-go/device/send.go:255`)

- Receiver = Sender at offset 4 of the rejected message, and Nonce = 24 random bytes.
- Cookie = XChaCha20-Poly1305(key = cookie encryption key, nonce, plaintext = 16-byte cookie, AAD = mac1 of the rejected message).
- Send directly to the receiving Endpoint.

**Consuming a cookie reply** (`wireguard-go/device/receive.go:280`, `wireguard-go/device/cookie.go:194`)

1. Look up the peer by Receiver index. Either a handshake or a keypair entry works. Do not consume the reply if the peer is missing or not running (`wireguard-go/device/receive.go:293`–`:305`).
2. Fail if the peer has never sent mac1 (`hasLastMAC1` is false).
3. Open using `lastMAC1` as AAD and store the cookie and receive time.
4. On failure, only log it. A stored cookie is used in mac2 starting with the next `AddMacs`. Do not immediately resend the same initiation.

**Detecting load** (`wireguard-go/device/device.go:385`)

- The device is under load when the handshake queue length is at least max(1, `queueHandshakeSize`/8). Record `underLoadUntil` = now + `UnderLoadAfterTime` (1 second).
- Otherwise, determine whether `underLoadUntil` has yet elapsed.
- With the default queue size of 1024, the threshold is 128 (`wireguard-go/device/queueconstants_default.go:16`).
- Drop handshake packets when the queue is full (`wireguard-go/device/receive.go:223`).

**rate limiter**(`wireguard-go/ratelimiter/ratelimiter.go:14`, `wireguard-go/ratelimiter/ratelimiter.go:99`):

- The key is `Endpoint.DstIP()`.
- The rate is 20 per second with a burst of 5 (`packetCost` = 1e9/20 ns, `maxTokens` = `packetCost`×5).
- Allow the first packet for a new IP, and start its tokens at `maxTokens−packetCost`. For an existing IP, replenish tokens by elapsed ns, cap them at `maxTokens`, and deduct tokens and allow the packet only when tokens are **strictly greater than** `packetCost`. Thus "burst 5" describes the constant and does not guarantee acceptance of all 5 consecutive packets with no elapsed time (`wireguard-go/ratelimiter/ratelimiter.go:107`–`:136`).

### TAI64N

Source is `wireguard-go/tai64n/tai64n.go:15`.

- 12 bytes = big-endian uint64(`0x400000000000000a` + Unix seconds) ‖ big-endian uint32(nanoseconds & ^`0xFFFFFF`).
- Clear the low 24 bits of nanoseconds to reduce resolution to about 16.8ms (`whitenerMask`).
- Compare the 12 bytes lexicographically (`wireguard-go/tai64n/tai64n.go:35`).
- At the test's specific start time (`time.Unix(0, 123456789)`), a 10ms difference is not "after" and a 20ms difference is "after". In general, a shorter interval can be "after" if it crosses a 16.8ms quantization boundary (`wireguard-go/tai64n/tai64n_test.go:16`–`:28`, `wireguard-go/tai64n/tai64n.go:22`–`:27`).

### Sending transport data

1. **Nonce assignment.** Atomically increment `sendNonce` by 1 for each packet and use the previous value as the counter. The first counter is 0 (`wireguard-go/device/send.go:501`).
2. **Nonce limit.** When the counter is at least `RejectAfterMessages`, pin the nonce to that value and put the packet back in staged (`wireguard-go/device/send.go:502`).
3. **When sending is blocked.** Leave packets staged and call `SendHandshakeInitiation(false)` in any of the following cases (`wireguard-go/device/send.go:488`).
   - There is no current keypair.
   - The nonce is exhausted.
   - At least `RejectAfterTime` (180 seconds) have elapsed since `created`.
4. **Staged queue.** The default size is 128 (`DefaultQueueStagedSize` = `conn.IdealBatchSize`). On overflow, drop the oldest group first (`wireguard-go/device/queueconstants_default.go:13`, `wireguard-go/conn/conn.go:19`, `wireguard-go/device/send.go:456`).
5. **Header.** Write type 4, Receiver = keypair.remoteIndex, and Counter = nonce in LE (`wireguard-go/device/send.go:588`).
6. **Padding.** Fill with 0. `calculatePaddingSize(len, mtu)` follows these rules (`wireguard-go/device/send.go:552`, `wireguard-go/device/send.go:593`).
   - If mtu == 0, round up to a multiple of 16.
   - Otherwise, if len > mtu, apply len %= mtu, then round up to a multiple of 16 without exceeding mtu.
   - A keepalive (0 bytes) has 0 bytes of padding.
   - If TUN cannot supply an MTU, use `DefaultMTU` = 1420 (`wireguard-go/device/tun.go:14`, `wireguard-go/device/device.go:468`).
7. **Encryption.** The 12-byte AEAD nonce is 0x00000000 ‖ LE uint64(counter), with no AAD (`wireguard-go/device/send.go:599`).
8. **Size limit.** Plaintext read from TUN must satisfy 1 ≤ size ≤ `MaxContentSize` (= `MaxSegmentSize` − 32 − 8) (`wireguard-go/device/send.go:380`, `wireguard-go/device/constants.go:32`).
9. **Path selection.** Check the IP version (first nibble 4/6) and minimum header length. Look up the destination address in the AllowedIPs trie. If `PeerByIPPacketFunc` exists, call `LookupPeer` with the resulting public key (`wireguard-go/device/send.go:390`, `wireguard-go/device/allowedips.go:363`).
10. **Keepalive.** If the staged queue is empty, insert one empty packet and drain staged. Otherwise, send only the packets waiting in the queue (`wireguard-go/device/send.go:85`).
11. **After sending.** After sending a group, `keepKeyFreshSending` calls for an initiation in any of the following cases (`wireguard-go/device/send.go:275`, `wireguard-go/device/send.go:699`).
    - `handshakeOnUserSend` is enabled.
    - nonce > `RekeyAfterMessages`.
    - The keypair is an initiator keypair and its age > `RekeyAfterTime` (120 seconds).

### Receiving transport data

Source is `wireguard-go/device/receive.go`.

1. **Size and type.** Drop datagrams smaller than `MinMessageSize` (32) without inspecting type (`:135`). Drop any of the 3 handshake message types with an incorrect size, and drop unknown types (`:194`–`:211`).
2. **Keypair lookup.** For transport, look up the keypair by Receiver index. Drop in either of the following cases (`:158`–`:171`).
   - The entry is missing or the index is still in the handshake phase.
   - The keypair age exceeds `RejectAfterTime` (180 seconds).
3. **Decryption.** nonce = 0x00000000 ‖ LE counter, with no AAD. Silently drop on decryption failure (`:243`–`:259`, `:469`).
4. **Replay protection.** After successful decryption, validate the counter with the per-keypair replay filter (`:474`). The limit is `RejectAfterMessages`.
   - The window is a ring of 128 blocks of 64 bits, with size `windowSize` = (128−1)×64 = 8128 (`wireguard-go/replay/replay.go:11`).
   - Reject if counter ≥ limit.
   - If greater than `last`, advance the window. Clear the skipped blocks, up to the entire ring.
   - Reject if `last − counter` > 8128.
   - Otherwise, reject if the bit is already set. If it is clear, set it and accept (`wireguard-go/replay/replay.go:37`).
5. **Confirming next.** Confirm next with `ReceivedWithKeypair`. On confirmation, the handshake completion timer, priority message, and staged send follow (`:480`).
6. **Peer notification.** If Endpoint is `conn.PeerAwareEndpoint`, call `FromPeer(peer public key)` (`:486`).
7. **Keepalive.** Plaintext of length 0 is a keepalive and is not written to TUN (`:491`).
8. **IP validation** (`:497`–`:536`).
   - If the first nibble is 4, check length ≥ 20. The total length (BE, offset 2) must be within [20, len]. Trim to that length to remove the padding.
   - If it is 6, check length ≥ 40, add 40 to payload length (BE, offset 4), and trim to that length. The Go source performs this addition in `uint16`, which wraps on large inputs (`wireguard-go/device/receive.go:515`–`:525`). In Swift, convert to a wider integer and check that the sum is at most len. Avoid reproducing the wrap or trapping on UInt16 addition.
   - Drop other versions.
9. **AllowedIPs.** The **source address** must be within that peer's AllowedIPs (`:510`, `:528`). The fork first uses the per-peer predicate from `SetAllowedIPs`. If there is none, check whether the peer owns the source address in the shared trie (`wireguard-go/device/allowedips.go:412`).
10. **Timers.** If any transport in the group passes AEAD and replay checks, call `keepKeyFreshReceiving`, `timersAnyAuthenticatedPacketTraversal`, and `timersAnyAuthenticatedPacketReceived`. If any of those packets has nonempty plaintext, also call `timersDataReceived`. Packets dropped by IP format or AllowedIPs checks still count for these timer conditions (`wireguard-go/device/receive.go:474`–`:495`, `:543`–`:549`).
    - `keepKeyFreshReceiving` sends one initiation if current is an initiator keypair and age > `RejectAfterTime − KeepaliveTimeout − RekeyTimeout` (165 seconds). `sentLastMinuteHandshake` prevents duplicates (`:63`).

### Endpoint roaming

This fork changes the peer's endpoint value in only three places (`wireguard-go/device/peer.go:161`, `wireguard-go/device/device.go:571`, `wireguard-go/device/uapi.go:345`).

- Initialization in `NewPeer` (nil)
- `NewPeerConfig.Endpoint` during lazy creation
- UAPI `endpoint=`

The receive path never updates the endpoint to the source of a received packet (`wireguard-go/device/receive.go:479`–`:489`). At that point it only notifies Bind through `PeerAwareEndpoint.FromPeer`.

Sending to a peer with no endpoint therefore returns `"no known endpoint for peer"` (`wireguard-go/device/peer.go:216`). This also applies when a responder sends a response. Roaming is the responsibility of Bind (magicsock).

`tests/netns.sh` checks endpoint changes (`wireguard-go/tests/netns.sh:196`), but compatibility with this fork's code is unverified.

### Handshake send rules

`SendHandshakeInitiation`(`wireguard-go/device/send.go:164`):

- Reset the attempt count to 0 unless isRetry.
- Do nothing if `RekeyTimeout` (5 seconds) have not passed since the last handshake message, whether initiation or response, was sent (`wireguard-go/device/send.go:170`).
- If initiation creation succeeds, call `timersHandshakeInitiated` even if the UDP send fails. If creation itself fails, return before that call (`wireguard-go/device/send.go:190`–`:213`).
- A retry creates a fresh initiation rather than resending saved bytes. Call `CreateMessageInitiation` again, start at InitialChainKey and InitialHash, and create a new ephemeral key, timestamp, Sender index, and MACs. The responder rejects retransmission with the same timestamp (`wireguard-go/device/send.go:190`, `wireguard-go/device/noise-protocol.go:282`–`:338`, `:419`).
- The responder does not retransmit a response periodically. It creates a fresh response when the initiator restarts with a fresh initiation. During rekeying it continues sending with a valid current keypair while waiting for confirmation of next, derived from the fresh response (`wireguard-go/device/receive.go:358`–`:372`, `wireguard-go/device/send.go:218`–`:252`, `wireguard-go/device/noise-protocol.go:714`–`:719`).
- `Peer.Start` sets `lastSentHandshake` to now − 6 seconds so the first attempt is not blocked (`wireguard-go/device/peer.go:294`).

The responder derives a keypair immediately after creating a response and puts it in next. It then calls `timersSessionDerived` and sends the response (`wireguard-go/device/send.go:218`).

### Timers

`Timer.Mod(d)` schedules expiration d from now whether or not a timer is pending. `Del` cancels it (`wireguard-go/device/timers.go:48`). The jitter is `fastrandn(334)`, or 0–333ms (`wireguard-go/device/timers.go:159`). Event-driven timer scheduling and cancellation are mostly gated on `timersActive` (the peer is running and the device is up). Expiration callbacks have no blanket up check. When a peer stops, cancel all six timers with `DelSync` (`wireguard-go/device/timers.go:75`, `:79`–`:154`, `:243`–`:249`).

| Timer | Scheduled when | Cleared when | Expiration behavior |
| --- | --- | --- | --- |
| retransmitHandshake | `RekeyTimeout`+jitter after sending an initiation (`timers.go:189`) | Handshake completion (`timers.go:197`) | Give up if the attempt count exceeds `MaxTimerHandshakes` (18). Cancel sendKeepalive, drop staged, and schedule zeroKeyMaterial for 540 seconds if it is absent. Otherwise, increment the count by 1, mark endpoint src for clearing, and send a retry initiation (`timers.go:79`). As long as creation and retries continue and no external action resets the attempt count, there is 1 initial attempt + 19 retries, at most 20 attempts (`timers.go:80`–`:106`, `wireguard-go/device/send.go:165`). |
| sendKeepalive | On receiving data, schedule for `KeepaliveTimeout` (10 seconds) if not pending. If pending, set `needAnotherKeepalive` (`timers.go:164`) | Sending an authenticated packet (`timers.go:175`), or giving up | Send a keepalive. If the flag is set, clear it and reschedule for 10 seconds (`timers.go:110`). |
| newHandshake | `KeepaliveTimeout+RekeyTimeout`+jitter (15 seconds+) after sending data if not pending (`timers.go:157`) | Receiving an authenticated packet (`timers.go:182`) | Mark endpoint src for clearing and send a fresh initiation (`timers.go:120`) |
| sessionExpired | `RejectAfterTime` (180 seconds) on session derivation (`timers.go:213`) | Peer stop or key deletion (`peer.go:321`) | Fork only. Report `PeerSessionExpired` to the session state callback (`timers.go:140`). |
| zeroKeyMaterial | `RejectAfterTime×3` (540 seconds) on session derivation (`timers.go:214`), when giving up, or when a lazily created peer starts (`peer.go:314`) | Rescheduled on fresh session derivation, canceled on peer stop (`timers.go:248`) | Delete all keypairs, handshake state, and staged packets. Remove a lazily created peer from the device (`timers.go:127`, `peer.go:319`–`:345`). |
| persistentKeepalive | On sending or receiving an authenticated packet, reschedule for the interval if it is greater than 0 (`timers.go:221`) | Peer stop (`timers.go:249`) | Send a keepalive if the interval is greater than 0. The send's traversal schedules the next expiration. A pending expiration does nothing after the interval is set to 0 (`timers.go:150`, `:221`, `wireguard-go/device/send.go:677`). |

"Authenticated packet" includes handshake messages. A responder receiving an initiation and an initiator receiving a response call the traversal and received timer functions (`wireguard-go/device/receive.go:366`, `wireguard-go/device/receive.go:401`). Sending an initiation or response calls the traversal and sent functions (`wireguard-go/device/send.go:201`, `wireguard-go/device/send.go:243`).

`timersHandshakeComplete` (`wireguard-go/device/timers.go:197`) does the following.

- Cancel retransmit
- Reset the attempt count and `sentLastMinuteHandshake`
- Record `lastHandshakeNano`

Two points call this function.

- Initiator, immediately after consuming the response (`wireguard-go/device/receive.go:415`)
- Responder, when confirming next (`wireguard-go/device/receive.go:482`)

### Key changes and peer stop

`SetPrivateKey`(`wireguard-go/device/device.go:399`):

- Do nothing if the keys are equal.
- Remove the peer whose public key matches the new public key.
- Reinitialize the cookie checker.
- Recompute the precomputed static-static value for all peers.
- Call `ExpireCurrentKeypairs`. It clears the handshake and its index, and sets sendNonce on current and next to `RejectAfterMessages`. It also resets `lastSentHandshake` to now − 6 seconds so the 5-second throttle does not block the next send's new initiation. It does not immediately delete the receive indexes of existing keypairs (`wireguard-go/device/peer.go:353`–`:368`).

Stopping a peer synchronously cancels all timers and clears its keypairs, handshake, and staged packets (`wireguard-go/device/peer.go:484`, `wireguard-go/device/peer.go:319`).

## Tailscale fork and how Tailscale uses it

This section describes only what is in the fork's sources. It does not establish differences from upstream wireguard-go.

### `conn.Bind` and `conn.Endpoint`

**`Bind`**(`wireguard-go/conn/conn.go:46`):

| Method | Behavior |
| --- | --- |
| `Open(port)` | Returns the list of `ReceiveFunc` and the actual port |
| `Close` | Causes open receive functions to return `net.ErrClosed` |
| `SetMark` | Sets the socket mark |
| `Send(bufs, ep, offset)` | Bind may use the space before `offset` |
| `ParseEndpoint(s)` | Creates an Endpoint from a string |
| `BatchSize` | Number of buffers handled at once |

- `ReceiveFunc` writes packets to the slab and fills `ReceivedPacket{Offset, Size, Endpoint}` (`wireguard-go/conn/conn.go:22`, `wireguard-go/conn/conn.go:40`).
- The device runs one loop per receive function (`wireguard-go/device/device.go:947`).

**`Endpoint`**(`wireguard-go/conn/conn.go:92`):

| Method | Use in the device |
| --- | --- |
| `ClearSrc` | Called before sending on retry (`wireguard-go/device/peer.go:220`) |
| `SrcToString` | |
| `DstToString` | |
| `DstToBytes` | src for the mac2 cookie |
| `DstIP` | Rate limiter key |
| `SrcIP` | |

**Optional interfaces** (present in the fork)

- `InitiationAwareEndpoint.InitiationMessagePublicKey([32]byte)` is called immediately after decrypting the initiation's static key, before peer lookup. Static-static DH, Timestamp authentication, and replay and flood checks are still pending, so this notification does not indicate completed authentication (`wireguard-go/conn/conn.go:109`–`:113`, `wireguard-go/device/noise-protocol.go:381`–`:428`).
- `PeerAwareEndpoint.FromPeer([32]byte)` is called after transport decryption and successful replay validation (`wireguard-go/conn/conn.go:127`, `wireguard-go/device/receive.go:486`).

**magicsock implementation**

- `connBind.Open` returns three receive functions (IPv4, IPv6, and DERP) in builds with UDP transport, or just DERP in builds without it. It ignores the port argument (`tailscale.com/wgengine/magicsock/magicsock.go:3543`–`:3558`).
- `SetMark` does nothing (`tailscale.com/wgengine/magicsock/magicsock.go:3565`).
- `BatchSize` is 128 on linux and 1 elsewhere (`tailscale.com/wgengine/magicsock/magicsock.go:3528`).
- `ParseEndpoint` takes the **node public key hex string** and returns that peer's `*endpoint` (`tailscale.com/wgengine/magicsock/magicsock.go:3946`). The wireguard-go endpoint is thus a fixed object per peer, and magicsock chooses the actual path.
- Methods of `*endpoint` (`tailscale.com/wgengine/magicsock/endpoint.go:619`, `tailscale.com/wgengine/magicsock/endpoint.go:568`, `tailscale.com/wgengine/magicsock/magicsock.go:3929`) follow.
  - `DstToString` = public key hex
  - `DstIP` = the node's first tailnet address
  - `DstToBytes` = fake address `fakeWGAddr` encoded as IP bytes ‖ 2-byte LE port
- When it cannot determine the peer from the source or needs confirmation, magicsock passes `*lazyEndpoint` (`tailscale.com/wgengine/magicsock/magicsock.go:1914`, `tailscale.com/wgengine/magicsock/magicsock.go:1936`). This Endpoint uses the two optional interfaces to associate the source address with the peer key (`tailscale.com/wgengine/magicsock/magicsock.go:4487`, `tailscale.com/wgengine/magicsock/magicsock.go:4530`).
- Under load, a cookie reply sent to `*lazyEndpoint` is written directly to the source UDP address (`tailscale.com/wgengine/magicsock/magicsock.go:1514`).

### Lazy peer configuration

**Peer creation callback**

- After setting `Device.SetPeerLookupFunc(f)`, `LookupPeer` calls f for an unknown public key. If f returns `NewPeerConfig{AllowedIPs, PresharedKey, Endpoint}`, it creates and starts the peer (`wireguard-go/device/device.go:542`, `wireguard-go/device/device.go:634`).
- A peer created this way is `deleteOnIdle` and is removed when zeroKeyMaterial expires (540 seconds) (`wireguard-go/device/device.go:568`, `wireguard-go/device/timers.go:130`).
- `LookupPeer` is called when receiving an initiation (`wireguard-go/device/noise-protocol.go:386`) and when sending through `PeerByIPPacketFunc` (`wireguard-go/device/allowedips.go:370`).
- `LookupActivePeer` does not create a peer (`wireguard-go/device/device.go:585`).

**Other fork APIs**

| API | Behavior | Source |
| --- | --- | --- |
| `SetPeerByIPPacketFunc` | Determines the peer public key from (src, dst, packet) on the send path | `wireguard-go/device/device.go:670`, `:710` |
| `SetSessionStateFunc` | Reports changes in peer session state (None/Handshake/Established/Expired) | `wireguard-go/device/device.go:672`, `:725` |
| `SetPriorityMessageOnEstablishmentFunc` | Sends a message of at most 512 bytes (`MaxPriorityMessageContentSize`) on keypair confirmation, bypassing staged | `wireguard-go/device/device.go:738`, `wireguard-go/device/send.go:111` |
| `ScheduleHandshakeOnUserSend` | Schedules an initiation after the next send. Has no effect on peers without keys | `wireguard-go/device/device.go:772` |
| `RemoveMatchingPeers` | Removes peers matching a condition | `wireguard-go/device/device.go:619` |
| `Option` such as `WithMetrics` | Queue sizes and metrics | `wireguard-go/device/device.go:127`, `:193` |

### Configuration supplied by Tailscale

**`wgcfg.Config`**(`tailscale.com/wgengine/wgcfg/config.go:23`):

- It has only `PrivateKey` and `Addresses`.
- The configuration has no peer list. A callback supplies `PeerConfig{AllowedIPs, PresharedKey}` for each peer.

**Device and peer creation**

- `wgcfg.NewDevice` creates the device, with `magicConn.Bind()` as Bind (`tailscale.com/wgengine/userspace.go:519`).
- Peer creation goes through a single `PeerLookupFunc` installed by `SetPeerConfigFunc` (`tailscale.com/wgengine/userspace.go:687`).
- That function creates an endpoint with `bind.ParseEndpoint(public key hex)` and puts it in `NewPeerConfig` (`tailscale.com/wgengine/wgcfg/device.go:47`).

**PSK**:

- The actual callback `LocalBackend.peerConfig` fills only `AllowedIPs` (`tailscale.com/ipn/ipnlocal/resolve.go:49`). PSK is therefore always 0, and KDF3 takes 32 bytes set to 0.
- No non-test code was found that sets a PSK to a value other than 0 (searching for `PresharedKey` only found it being passed at `tailscale.com/wgengine/userspace.go:714` and `tailscale.com/wgengine/wgcfg/device.go:60`).

**PersistentKeepalive.** A search of the `tailscale.com` non-test code found neither `PersistentKeepalive` nor `persistent_keepalive`. Tailscale therefore leaves the wireguard-go persistentKeepalive timer disabled (interval 0, `wireguard-go/device/timers.go:151`).

**Peer synchronization and cleanup**

- On netmap changes, `SyncDevicePeer` takes effect (`tailscale.com/wgengine/userspace.go:698`).
  - Remove the peer if it has no configuration.
  - Update PSK and AllowedIPs for an existing peer.
  - Do not create a missing peer.
- Idle peer cleanup is left to `deleteOnIdle` above and the 540-second timer.
- Status lookup uses `LookupActivePeer` and does not create peers (`tailscale.com/wgengine/userspace.go:1015`).

**Other wiring**

- The send path lookup uses only the destination address through `SetPeerByIPPacketFunc` (`tailscale.com/wgengine/userspace.go:739`, `tailscale.com/ipn/ipnlocal/resolve.go:28`).
- Wire up the session state callback, priority message, and `ScheduleHandshakeOnUserSend` (`tailscale.com/wgengine/userspace.go:720`, `:752`, `:769`).
- Set the private key in both magicsock and wireguard-go (`tailscale.com/wgengine/userspace.go:891`, `:895`).

### Memory-related constants

| Platform | staged | outbound | inbound | handshake | Preallocated buffers / pool | `MaxSegmentSize` | Source |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Default | 128 | 1024 | 1024 | 1024 | 0 (unlimited) | 65535 | `wireguard-go/device/queueconstants_default.go:12` |
| iOS | 128 | 1024 | 1024 | 1024 | 1024 | 1700 | `wireguard-go/device/queueconstants_ios.go:13` |
| Android | 128 | 1024 | 1024 | 1024 | 4096 | 2200 | `wireguard-go/device/queueconstants_android.go:12` |
| Windows | 128 | 1024 | 1024 | 1024 | 0 | 2016 | `wireguard-go/device/queueconstants_windows.go:8` |

- **Tailscale iOS.** Overrides all five values to 64 (staged, outbound, inbound, handshake, and preallocation). The load threshold is therefore 64/8 = 8 (`tailscale.com/wgengine/wgcfg/mem_ios.go:20`).
- **Tailscale on other platforms.** Changes only inbound and outbound to min(1024, CPU count×4) (`tailscale.com/wgengine/wgcfg/mem_notios.go:37`).
- **iOS size limit.** `MaxSegmentSize` is 1700. Outbound plaintext read from TUN is checked against `MaxContentSize` = 1700−40 = 1660 bytes (`wireguard-go/device/queueconstants_ios.go:21`, `wireguard-go/device/constants.go:32`, `wireguard-go/device/send.go:380`). The receive loop has no 1700-byte limit check. Receive capacity depends on the slab passed to Bind, which is `MaxContentSize+128` in single-packet mode (1788 on iOS) and 131070 bytes in batch mode. Therefore, do not use 1700 as a wire receive limit (`wireguard-go/device/receive.go:115`–`:152`, `wireguard-go/device/packetbuf.go:25`–`:31`, `wireguard-go/tun/tun.go:30`, `wireguard-go/device/pools.go:96`–`:99`).

## Constants and timers

| Name | Value | Source |
| --- | --- | --- |
| `RekeyAfterMessages` | 2^60 | `wireguard-go/device/constants.go:15` |
| `RejectAfterMessages` | 2^64 − 2^13 − 1 | `wireguard-go/device/constants.go:16` |
| `RekeyAfterTime` | 120 seconds | `wireguard-go/device/constants.go:17` |
| `RekeyAttemptTime` | 90 seconds (used as the basis for computing `MaxTimerHandshakes`, without direct use in code) | `wireguard-go/device/constants.go:18` |
| `RekeyTimeout` | 5 seconds | `wireguard-go/device/constants.go:19` |
| `MaxTimerHandshakes` | 90/5 = 18 | `wireguard-go/device/constants.go:20` |
| `RekeyTimeoutJitterMaxMs` | 334 | `wireguard-go/device/constants.go:21` |
| `RejectAfterTime` | 180 seconds | `wireguard-go/device/constants.go:22` |
| `KeepaliveTimeout` | 10 seconds | `wireguard-go/device/constants.go:23` |
| `CookieRefreshTime` | 120 seconds | `wireguard-go/device/constants.go:24` |
| `HandshakeInitationRate` | 1 second/50 = 20ms | `wireguard-go/device/constants.go:25` |
| `PaddingMultiple` | 16 | `wireguard-go/device/constants.go:26` |
| `MinMessageSize` | 32 (`MessageKeepaliveSize`) | `wireguard-go/device/constants.go:30` |
| `MaxMessageSize` | `MaxSegmentSize` | `wireguard-go/device/constants.go:31` |
| `MaxContentSize` | `MaxSegmentSize` − 32 − 8 | `wireguard-go/device/constants.go:32` |
| `UnderLoadAfterTime` | 1 second | `wireguard-go/device/constants.go:38` |
| `MaxPeers` | 65536 | `wireguard-go/device/constants.go:39` |
| `DefaultMTU` | 1420 | `wireguard-go/device/tun.go:14` |
| replay `windowSize` | 8128 | `wireguard-go/replay/replay.go:15` |
| ratelimiter | 20 pps, burst 5 | `wireguard-go/ratelimiter/ratelimiter.go:15` |
| `MaxPriorityMessageContentSize` | 512 | `wireguard-go/device/device.go:738` |
| `conn.IdealBatchSize` | 128 | `wireguard-go/conn/conn.go:19` |

`RekeyAttemptTime` is 90 seconds, but retry termination checks whether the attempt count exceeds 18 instead of directly measuring elapsed time. Jitter is also added to each 5-second interval, so do not implement an exact 90-second cutoff (`wireguard-go/device/constants.go:18`–`:21`, `wireguard-go/device/timers.go:80`, `:191`). This was not checked against the original white paper.

## Minimum Swiftail requirements and optional parts

For the M1 gate, a Swift peer and a wireguard-go peer handshake over UDP loopback, exchange packets in both directions, and stay connected after rekeying.

### Required

1. **Cryptographic primitives.** X25519 (clamp and reject a shared secret with all bytes set to 0), BLAKE2s-256, keyed BLAKE2s-128, HMAC-BLAKE2s and KDF1/2/3, and ChaCha20-Poly1305 IETF.
2. **TAI64N.** Generate timestamps and compare their bytes. Also implement the per-peer `lastTimestamp` replay check and 20ms flood check. The Go responder applies the same checks, so a Swift initiator must emit monotonically increasing timestamps.
3. **mac1 generation and validation.** The Go receiver always validates it (`wireguard-go/device/receive.go:314`). Leave mac2 at 0 without a cookie.
4. **Serialization of all 4 message types.** Reserved type bytes set to 0 and LE integers.
5. **Initiator and responder state machines.** Index table (replace handshake index → keypair index), previous/current/next rotation, responder confirmation of next, and initiator keepalive for confirmation.
6. **Transport encryption and decryption.** 12-byte nonce = 0⁴ ‖ LE counter, sendNonce limit, replay filter (8128 window), and rejection at a keypair age of 180 seconds.
7. **Incoming IP processing.** Validate length, remove padding, and check source address AllowedIPs. The Go peer sends with padding.
8. **Timers and rules needed to sustain rekeying.**
   - `RekeyAfterMessages` (sendNonce > 2^60 independent of role) and `RekeyAfterTime` (when the initiator sends) (`wireguard-go/device/send.go:275`–`:283`)
   - `keepKeyFreshReceiving` (165 seconds)
   - `RejectAfterTime`
   - retransmitHandshake (5 seconds + jitter, up to 20 attempts)
   - `RekeyTimeout` send throttle
   - sendKeepalive (10 seconds)
   - newHandshake (15 seconds+)
   - zeroKeyMaterial (540 seconds)

   Test both roles in rekeying. Test Swift as the rekey initiator, and test Swift receiving and confirming next as the responder when Go initiates a rekey after 120 seconds.
9. **Outbound padding.** The Go receiver trims padding based on the IP length, so it accepts packets without padding. Including padding is preferable because the implementation cost is small.

### Deferrable parts

| Item | Rationale for deferral |
| --- | --- |
| Cookie reply creation and consumption, XChaCha20-Poly1305, load detection, rate limiter | Defer **only for the M1 loopback test that blocks external input and guarantees the Go peer is not under load**. The threshold depends on the configured queue size, and recent load persists for 1 second (`wireguard-go/device/device.go:385`–`:396`). Under continued load, retries without mac2 keep getting rejected with cookie replies, so ignoring type 3 alone cannot guarantee recovery (`wireguard-go/device/receive.go:321`–`:334`). Validate type 3 size 64 and ignore it for now, and implement cookie handling before handling load or external communication. |
| PSK | `LocalBackend.peerConfig` does not configure a PSK in this version (`tailscale.com/ipn/ipnlocal/resolve.go:49`–`:51`). KDF3 input can be fixed at 32 bytes set to 0 provided the M1 Go peer also has no configured PSK. KDF3 itself remains required (`wireguard-go/device/noise-protocol.go:505`–`:513`, `:583`–`:590`). |
| persistentKeepalive | The Tailscale configuration path above does not set an interval. M1 peers can also leave the interval at 0. This is separate from sendKeepalive (10 seconds) after receiving data (`wireguard-go/device/peer.go:135`, `wireguard-go/device/timers.go:150`–`:170`). |
| Endpoint roaming | The fork also lacks it. M1 uses a fixed UDP address per peer. |
| Lazy creation via APIs like `PeerLookupFunc`, `deleteOnIdle` removal, `PeerByIPPacketFunc`, session state callbacks, priority message, `ScheduleHandshakeOnUserSend` | These features integrate magicsock and netmap (M3–M5) and do not affect the wire format. |
| Optional Endpoint interfaces (`InitiationAwareEndpoint`, `PeerAwareEndpoint`) | Both calls check whether the interface is implemented, so M1 can omit the hooks when using fixed UDP peers (`wireguard-go/device/noise-protocol.go:381`–`:384`, `wireguard-go/device/receive.go:486`–`:488`). |
| Batch receive, multiple queues, buffer pools, GSO, `SetMark`, sticky sockets | M1 can defer these with single packets and a single queue (`wireguard-go/device/packetbuf.go:23`–`:31`, `wireguard-go/tun/tun.go:63`–`:89`). A queue size of 64 alone cannot guarantee an overall iOS memory limit. Tailscale limits all five queue and pool options together, and `WaitPool` also caps the number of outstanding entries per pool (`tailscale.com/wgengine/wgcfg/mem_ios.go:20`–`:25`, `wireguard-go/device/pools.go:28`–`:37`). |

## What to verify in interop tests

### Reusable tests

- **KDF test vectors** (`wireguard-go/device/kdf_test.go:30`) provide three (key, input, T0, T1, T2) groups in hex, including empty key and empty input cases. KDF1 and KDF2 use the first part of the same vectors (`:68`, `:78`). These are the only fixed vectors that pin down HMAC-BLAKE2s, so port them directly to Swift unit tests.
- **Replay tests** (`wireguard-go/replay/replay_test.go:19`) have 34 fixed sequence cases and 6 bulk cases. They cover the window boundary and the `RejectAfterMessages` boundary. Port them directly because inputs and expected values are constants.
- **TAI64N quantization** (`wireguard-go/tai64n/tai64n_test.go:15`–`:28`) covers a specific start time where a 10ms difference is not after and a 20ms difference is after. Do not generalize this to a minimum interval of 10ms for arbitrary times.
- **Cookie round trip** (`wireguard-go/device/cookie_test.go:12`) tests round-trip properties with random keys. It checks mac1 generation and validation, mac2 failure without a cookie, mac2 success after creating and consuming a cookie reply, and failure when one byte changes or src differs. Port it as a property test because it has no fixed vectors.
- **Handshake round trip** (`wireguard-go/device/noise_test.go:80`) creates two devices with random keys. It checks whether Seal/Open works both ways after initiation, response, and `BeginSymmetricSession` on both sides, and whether `InitiationAwareEndpoint` is called. With no fixed vectors, use a Swift property test and verify actual interop against a Go peer.
- **Go test peer components**
  - `NewChannelTUN` (MTU 1420) in `tun/tuntest` and `Ping` for ICMPv4 packet creation (`wireguard-go/tun/tuntest/tuntest.go:92`, `wireguard-go/tun/tuntest/tuntest.go:17`, `wireguard-go/tun/tuntest/tuntest.go:170`)
  - Standard bind `conn.NewDefaultBind` and `ParseEndpoint` in `ip:port` format (`wireguard-go/conn/bind_std.go:90`)
  - `device_test.go`'s setup for connecting two devices with UAPI (`wireguard-go/device/device_test.go:68`)

### M1 cross-implementation tests

1. Configure the Swift UDP address as `endpoint=` on the Go peer. Without roaming, Go cannot send a response as responder if this is missing (`wireguard-go/device/peer.go:216`).
2. Swift initiator → Go responder. Check whether Go logs "Received handshake initiation". Swift sends a keepalive immediately after the response. Verify that Go confirms next and that Go→Swift data flows.
3. Go initiator → Swift responder. Verify that Swift waits until confirmation before sending with the new keypair, and sends with it afterward.
4. Bidirectional ICMP or arbitrary IP packets. Verify that Swift trims Go padding (based on MTU 1420) using the IP length and does not mistake a keepalive (32 bytes) for data.
5. Replay and flood boundaries follow.
   - Go drops a retransmission of the same initiation as a replay.
   - Go drops a second initiation within 20ms as flooding.
   - Because of Go's `RekeyTimeout` throttle (5 seconds), Go does not send an initiation within 5 seconds of sending a response.
6. rekey:
   - Send traffic for more than 120 seconds to verify time-based rekeying on the initiator side.
   - Verify that delayed packets from the previous keypair are accepted.
   - Verify that packets from a keypair older than 180 seconds are dropped.
   - Verify correct previous/current/next rotation when Swift is the responder.
7. Counter boundaries. Verify that packets outside the replay window (more than 8128 behind) and duplicate counters are rejected.
8. Error branches. Verify that Go drops invalid mac1, incorrectly sized handshakes, unknown types, and reserved bytes other than 0. Invalid mac1 and unknown types have verbose logs, so do not expect "no log" (`wireguard-go/device/receive.go:194`–`:211`, `:314`–`:316`). The same inputs must leave Swift handshake and keypair state unchanged.
9. Loss and delay. Verify recovery after dropping the first response or confirmation transport, fresh values for ephemeral, Sender, and timestamp in retry initiations, and that a delayed response to an old Receiver cannot overwrite a new handshake (`wireguard-go/device/noise-protocol.go:282`–`:338`, `:614`–`:622`, `wireguard-go/device/timers.go:79`–`:106`).
10. Authentication boundary. Invalid AEAD tags must leave the replay window and next unchanged. An invalid IP packet that passes AEAD and replay checks may count toward next confirmation and authenticated-packet timers but must not be delivered to TUN (`wireguard-go/device/receive.go:469`–`:549`).

## Unverified items

- **Differences from upstream wireguard-go.** Upstream (zx2c4) sources were absent from the reference sources, so no byte-for-byte comparison was possible. Whether the APIs in "Tailscale fork" above (`PeerLookupFunc`, the two optional Endpoint interfaces, session state, priority message, `ScheduleHandshakeOnUserSend`, and metrics) and the absence of receive-path roaming are unique to the fork is based on recollection and remains unconfirmed.
- **Internals of `golang.org/x/crypto`.** The module was absent from the cache, so its internals were unverified (BLAKE2s block size and HMAC composition, key handling in keyed BLAKE2s, the XChaCha20 HChaCha step, and internal clamping in `curve25519.ScalarMult`). The `kdf_test.go` vectors can pin down the KDF, but the source tree has no fixed vectors for XChaCha20-Poly1305 or keyed BLAKE2s-128.
- **`netip.AddrPort.MarshalBinary` format.** The standard bind's `DstToBytes` format is part of the Go standard library and was unverified. The cookie src is internal to the receiver and does not affect interop.
- **Fixed Noise handshake vectors.** None were found in the source tree. Handshake correctness can only be verified by cross-testing with a Go peer.
- **Roaming check in `tests/netns.sh`.** Whether the endpoint roaming checks (`wireguard-go/tests/netns.sh:196`, `:202`) pass in this fork is unverified.
- **magicsock keepalive and path maintenance.** Whether magicsock does its own keepalive in place of wireguard-go persistentKeepalive remains in scope for `disco-magicsock.md`. The `lazyEndpoint` selection branch in `receiveIP` was checked (`tailscale.com/wgengine/magicsock/magicsock.go:1905`–`:1939`), but overall path selection, including disco and DERP, was unverified.
- **Runtime verification.** This verification read and checked the sources and test bodies for the two specified versions. Go noise, cookie, and replay test execution, UDP cross-testing, and real-time timer behavior were unverified. In particular, the `uint16` wrap in the IPv6 length addition is a limitation identified from source and should not be reproduced in Swift (`wireguard-go/device/receive.go:519`–`:525`).
- **Swift support.** Whether Apple frameworks provide BLAKE2s and XChaCha20-Poly1305 falls outside the sources for this note and was unverified.
