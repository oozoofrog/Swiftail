# Control transport layer (ts2021: controlhttp · controlbase · HTTP/2)

## 1. Introduction

| Item | Value |
| --- | --- |
| Reference sources | `tailscale.com` v1.104.6 (CapabilityVersion 148, `tailscale.com/tailcfg/tailcfg.go:200`) |
| Authoring model | Claude Opus 5.5 |
| Verification status | Verified by GPT-6.1 Sol, 2026-11-14, with 28 corrections |

Source references use `tailscale.com/<path>:<line>` relative to the module root. References that give only a filename use the path stated earlier in the same section. The actual cached sources for the dependent modules `golang.org/x/net` v0.60.0 and `golang.org/x/crypto` v0.58.0 were also checked (`tailscale.com/go.mod:139-143`). References to these modules prefix the path with the module name and version. Standard library references of the form `Go 1.27.3/src/...` use the Go sources used for execution. §8 describes the material that was not checked, including the original RFCs.

## 2. Scope

Covered topics follow.

- The `/key` request for the server Noise public key
- The `/ts2021` HTTP upgrade, the race between ports 80 and 443, and ControlDialPlan (summary only for proxies, WebSockets, and ACE)
- The Noise IK handshake and record layer in controlbase
- The early payload (EarlyNoise) and how HTTP/2 is used over ts2021
- Minimum HTTP/2 client requirements, distinguishing what can and cannot be verified in the repository
- Key text and binary formats in `types/key`
- The capability version in the handshake
- Reusable Go tests and testcontrol as the interop test server

The scope excludes the contents of `/machine/register` and `/machine/map` requests and responses, inner map stream framing (`control-map.md`), DERP, disco, WireGuard, and the server-side implementation.

## 3. Wire formats

Fixed-width multibyte integers in §3 are big-endian (`controlbase/messages.go:43-45`, `controlbase/conn.go:170`, `:395`, `ts2021/conn.go:143`). §6.3 describes the integer formats for HTTP/2 and HPACK.

### 3.1 Noise handshake initiation (client → server, 101 bytes)

| Offset | Length | Field | Encoding | Source |
| --- | --- | --- | --- | --- |
| 0 | 2 | protocol version (= default capability version, §4.5) | uint16 BE | `tailscale.com/control/controlbase/messages.go:32`, `:43` |
| 2 | 1 | message type = `0x01` (`msgTypeInitiation`) | u8 | `messages.go:10`, `:44` |
| 3 | 2 | payload length = 96 | uint16 BE | `messages.go:34`, `:45` |
| 5 | 32 | Client ephemeral public key, plaintext | X25519 public key | `messages.go:36`, `:56-58` |
| 37 | 48 | Client machine public key ciphertext (32) + tag (16) | ChaCha20-Poly1305 | `messages.go:37`, `:59-61` |
| 85 | 16 | Tag for an empty payload | Poly1305 tag | `messages.go:38`, `:62` |

The header length is `initiationHeaderLen = 5` (`messages.go:26`). For version 148, the header is `00 94 01 00 60`.

### 3.2 Noise handshake response (server → client, 51 bytes)

| Offset | Length | Field | Encoding | Source |
| --- | --- | --- | --- | --- |
| 0 | 1 | message type = `0x02` (`msgTypeResponse`) | u8 | `messages.go:12`, `:75` |
| 1 | 2 | payload length = 48 | uint16 BE | `messages.go:68`, `:76` |
| 3 | 32 | Server ephemeral public key, plaintext | X25519 public key | `messages.go:69`, `:86` |
| 35 | 16 | Tag for an empty payload | Poly1305 tag | `messages.go:70`, `:87` |

The response has no version field. The header length is `headerLen = 3` (`messages.go:24`).

### 3.3 error (server → client, during the handshake only)

| Offset | Length | Field | Encoding | Source |
| --- | --- | --- | --- | --- |
| 0 | 1 | message type = `0x03` (`msgTypeError`) | u8 | `messages.go:19`, `handshake.go:218` |
| 1 | 2 | Message length n | uint16 BE | `handshake.go:219` |
| 3 | n | Human-readable error string | Byte sequence without encryption or authentication | `messages.go:13-18`, `handshake.go:223` |

Use this message only as a hint because it is unauthenticated (`messages.go:16-18`). On the HTTP upgrade path, the message may never reach the client (step 6 of §4.4).

### 3.4 record (transport phase, both directions)

| Offset | Length | Field | Encoding | Source |
| --- | --- | --- | --- | --- |
| 0 | 1 | message type = `0x04` (`msgTypeRecord`) | u8 | `messages.go:21`, `conn.go:169` |
| 1 | 2 | Ciphertext length n = plaintext length + 16 | uint16 BE | `conn.go:170` |
| 3 | n | ChaCha20-Poly1305 ciphertext + 16-byte tag, no AD | | `conn.go:171`, `:146` |

- The maximum total record size, including the header, is `maxMessageSize = 4096`. The ciphertext is at most 4093 bytes and the plaintext is at most 4077 bytes (`conn.go:28-34`).
- The receiver returns the non-transient `errReadTooBig` if `3 + n > 4096` (`conn.go:97-99`, `:375-382`). This branch leaves the receive key intact. The separate branch clears the key only on authentication failure (`conn.go:149-155`, `:230-233`). Swift discards the connection on an invalid type or length, nonce exhaustion, or authentication failure. This implementation policy prevents resumption after a boundary error. This does not mean that every Go read error automatically clears the key.
- Valid ciphertext lengths are 16–4093 bytes. A length below 16 fails authentication because the tag is incomplete (`golang.org/x/crypto@v0.58.0/chacha20poly1305/chacha20poly1305.go:74-85`). For a record with 0 bytes of plaintext, the receiver authenticates the 16-byte tag and consumes the nonce before skipping the record (`conn.go:146-147`, `:249-257`). Go's `Write([])` itself creates no record (`conn.go:300-320`).
- The sender splits one Write into chunks of 4077 plaintext bytes and sends them in multiple records (`conn.go:300-305`). Record boundaries are independent of higher-layer data boundaries.

### 3.5 Transport nonce (12 bytes)

| Offset | Length | Value | Source |
| --- | --- | --- | --- |
| 0 | 4 | Always 0 | `conn.go:388` |
| 4 | 8 | Per-direction counter, **uint64 big-endian** | `conn.go:388`, `:395` |

- The counter starts at 0 in each direction and increments by 1 for each record (one encryption or decryption attempt) (`conn.go:146-147`, `:171-172`).
- Once the counter reaches `^uint64(0)` (2^64−1), that value cannot be used (`errCipherExhausted`, `handshake.go:43`, `conn.go:163-167`, `:142-144`).
- The Noise specification uses a little-endian ChaChaPoly nonce (outside the repository). The Noise Explorer reference implementation in the repository also uses little-endian (`tailscale.com/control/controlbase/noiseexplorer_test.go:164`, `:173`). The interop tests exchange only one transport message in each direction (counter 0), so the difference does not appear (`interop_test.go:161-187`, `:237-253`). **Interoperating with Tailscale requires the big-endian encoding in `conn.go`.** The encodings diverge at counter 1.
- Each encryption within the handshake uses a fresh key and a nonce with all 12 bytes set to 0 (`handshake.go:464-494`).

### 3.6 HTTP upgrade request (HTTP/1.1, client → server)

| Item | Value | Source |
| --- | --- | --- |
| Method | `POST` | `tailscale.com/control/controlhttp/client.go:540` |
| Path | `/ts2021` (`serverUpgradePath`) | `controlhttp/constants.go:26`, `client.go:251-260` |
| `Upgrade` | `tailscale-control-protocol` | `controlhttp/controlhttpcommon/controlhttpcommon.go:10`, `client.go:543` |
| `Connection` | `upgrade` | `client.go:544` |
| `X-Tailscale-Handshake` | The 101-byte initiation from §3.1, encoded as standard base64 with padding (`base64.StdEncoding`) | `controlhttpcommon.go:15`, `client.go:545` |
| `Host` | Host and port of the upgrade URL | `Go 1.27.3/src/net/http/request.go:611-620`, `:683-689` |
| `Content-Length` | Go sends `0`. testcontrol also accepts omission (verified in the run reported in §7.3) | `Go 1.27.3/src/net/http/transfer.go:262-274` |
| Body | None. The headers end with `\r\n\r\n`, and the initiation is sent only in the header | `client.go:539-547`, `controlhttpserver.go:61-66`, `:100` |

Omitting HTTP/1.1 `Host` yields 400 before the request reaches the testcontrol handler (`Go 1.27.3/src/net/http/server.go:1069-1075`, verified in the run reported in §7.3).

The server response has the following fields.

| Item | Value | Source |
| --- | --- | --- |
| Status | `101 Switching Protocols` | `controlhttpserver/controlhttpserver.go:80` |
| `Upgrade` | `tailscale-control-protocol` | `controlhttpserver.go:78` |
| `Connection` | `upgrade` | `controlhttpserver.go:79` |

The §3.2 response begins at the byte immediately following the 101 response headers. The HTTP headers and Noise bytes can arrive in the same TCP read, so the HTTP/1.1 parser must pass any remaining bytes it has already read to the Noise layer (`client.go:517-525`, `:559-562`).

### 3.7 early payload (server → client, optional, at the start of the Noise plaintext stream)

| Offset | Length | Field | Encoding | Source |
| --- | --- | --- | --- | --- |
| 0 | 5 | `EarlyPayloadMagic` = `ff ff ff 54 53` (`"\xff\xff\xffTS"`) | Bytes | `tailscale.com/control/ts2021/conn.go:91` |
| 5 | 4 | JSON length L | uint32 BE | `conn.go:143`, `client_test.go:433-434` |
| 9 | L | `tailcfg.EarlyNoise` JSON | UTF-8 JSON | `conn.go:148-156` |

- The 9-byte header is the same size as an HTTP/2 frame header. The first 9 bytes of Noise plaintext from the server are either the HTTP/2 SETTINGS frame header or this header (`conn.go:81-87`).
- L > 10 MiB (`10<<20`), EOF partway through the first 9 bytes or the body, and JSON decoding failure all produce an error. Subsequent reads return the same error (`conn.go:127-156`). L=0 fails because the JSON is empty. The reader reads exactly L bytes of JSON and decodes them once, without newline delimiters (`conn.go:148-156`).
- If the magic does not match, put the 9 bytes back and use them unchanged as HTTP/2 input (`conn.go:137-141`).
- The known field in the JSON object is `{"nodeKeyChallenge":"chalpub:<64 hex>"}` (`tailcfg/tailcfg.go:3087-3091`, `types/key/chal.go:19`, `:76-77`). Go calls `json.Unmarshal` on a pointer, so `null` means no payload and `{}` means a zero-value challenge. Unknown fields are ignored. An invalid prefix, length, or hex in a known key field causes failure (`ts2021/conn.go:153-157`, `types/key/chal.go:85-87`. See also `Go 1.27.3/src/encoding/json/decode.go:30-49`, `:72-95`).
- The server supplies a random public key for each connection so the client can prove possession of the WireGuard (node) private key (`tailcfg.go:3088-3089`). This version's client code does not use `GetEarlyPayload` or `NodeKeyChallenge` outside tests (a repository-wide search found only the definition at `ts2021/conn.go:63`).
- The test server implementation writes the magic, length, and JSON separately, so they may arrive in multiple Noise records (`client_test.go:437-445`, `controlbase/conn.go:300-305`).

### 3.8 `/key` response (`tailcfg.OverTLSPublicKeyResponse`)

| JSON field | Format | Meaning | Source |
| --- | --- | --- | --- |
| `legacyPublicKey` | `"mkey:<64 hex>"` | Legacy NaCl crypto_box key. May be 0 for sufficiently new clients, based on the `v` argument | `tailcfg.go:2977-2983` |
| `publicKey` | `"mkey:<64 hex>"` | Server static public key for the Noise handshake | `tailcfg.go:2985-2988` |

A key of 0 also serializes as the prefix followed by 64 copies of the digit 0 (`types/key/machine.go:252-254` does not check for 0).

## 4. Procedures and state machines

### 4.1 Fetching the server public key (`/key`)

1. Send `GET <serverURL>/key?v=<CurrentCapabilityVersion>`. Append the request path and query to the control server URL as given, including its scheme (`tailscale.com/control/controlclient/direct.go:1535-1537`, `control/tsp/tsp.go:112`). This request uses ordinary HTTP(S) outside Noise. HTTPS key retrieval uses `tlsdial.Config`, which returns certificate validation errors. The upgrade policy of ignoring certificate errors (§4.4) must not apply here (`direct.go:355-359`, `net/tlsdial/tlsdial.go:111-115`, `:166-226`). testcontrol's plaintext `/key` assumes trust for local testing.
2. Read at most 64 KiB (`64<<10`) of the response body (`direct.go:1546`).
3. Fail if the status is anything other than 200 (`direct.go:1551-1553`).
4. Decode the body as the JSON in §3.8. On failure, retry with the legacy format (one unprefixed 64-character hex string = legacy key). If that also fails, combine the two errors and fail (`direct.go:1554-1568`, `types/key/machine.go:196-202`).
5. If `publicKey` is 0, stop with "control server is too old; no noise key" (`direct.go:700-702`).
6. Cache the result in `serverLegacyKey` and `serverNoiseKey`. Fetch it again at login only when `serverLegacyKey` is 0 (`direct.go:641-642`, `:675-692`). Close idle TLS connections after the fetch (`direct.go:694-697`). `loadServerPubKeys` itself does not retry (`direct.go:1535-1569`).
7. If `v` is empty (missing or `?v=`), testcontrol returns only the unprefixed hex of the legacy key as `text/plain`. Otherwise, it returns JSON. It does not parse the value as a number or check the version range (`tstest/integration/testcontrol/testcontrol.go:525-537`). Therefore, append `v=148`. The first `/key` request also creates the test server's Noise key pair, so call it before `/ts2021` (`testcontrol.go:487-490`, `:508-526`).

### 4.2 Overall dial flow (`ts2021.Client.dial`)

1. Determine the ports from the server URL (`tailscale.com/control/ts2021/client.go:134-156`).
   - Defaults are HTTP 80 and HTTPS 443.
   - Explicit port + `https`: HTTP port `""`, HTTPS port = explicit port. controlhttp maps HTTP port `""` back to 80 (`controlhttp/client.go:253`).
   - Explicit port + `http`: HTTP port = explicit port, HTTPS 443. HTTPS is disabled for a private or loopback IP or `localhost`.
   - No port + `http` + private host: HTTP 80, no HTTPS.
   - Pass the absence of HTTPS as `NoPort` (`"none"`) (`client.go:250`, `controlhttp/constants.go:32`).
2. The overall dial timeout defaults to 5 seconds. With a DialPlan, use the largest `DialStartDelaySec + DialTimeoutSec` among the candidates if it exceeds 5. Add 5 seconds for the handshake and clamp to [5, 60] seconds (`ts2021/client.go:213-245`). The same context deadline becomes the socket deadline during the handshake (`controlbase/handshake.go:127-134`).
3. If a DialPlan has at least 1 candidate, follow §4.3. Otherwise, start the port race in §4.4 immediately (`controlhttp/client.go:102-107`).

### 4.3 ControlDialPlan (summary)

- The format is `ControlDialPlan{Candidates []ControlIPCandidate}`, with candidate fields `IP`, `ACEHost`, `DialStartDelaySec`, `DialTimeoutSec`, and `Priority` (`tailcfg.go:2335-2365`). It arrives in the map response's `ControlDialPlan` field (`tailcfg.go:2197-2200`).
- Run candidate dials in parallel, starting each after its `DialStartDelaySec` and applying its `DialTimeoutSec` timeout. Connect directly to the candidate IP while keeping the original hostname in the URL (`controlhttp/client.go:122-151`, `:410-415`).
- Use the first successful connection and close the rest. If all fail, use DNS and follow §4.4 (`client.go:153-170`).
- This dial code does not read `Priority` (`client.go:122-151`).
- If `ACEHost` is present, use an HTTPS CONNECT tunnel and skip the 443 attempt (`tailcfg.go:2346-2351`, `controlhttp/client.go:261-263`, `:427-436`, `:464-469`).
- The `TS_USE_CONTROL_DIAL_PLAN` environment variable can disable the dial plan (`client.go:104`).

### 4.4 Port race and HTTP upgrade

1. The race follows these rules (`controlhttp/client.go:239-340`).
   1. Start the `http://host:HTTPPort/ts2021` attempt immediately unless HTTPS is forced and configured (`:291-293`).
   2. If HTTPS is configured, start the `https://host:HTTPSPort/ts2021` attempt after 500 ms. The delay is 0 if HTTPS is forced (`:87-94`, `:298-305`).
   3. If the HTTP attempt fails before the HTTPS timer fires, start HTTPS immediately (`:320-329`).
   4. Return the first successful connection. If both are attempted, fail once both errors are collected (`:315-337`). With HTTPS disabled, failure of HTTP alone does not meet this condition, so the code waits for the context deadline or cancellation (`:261-263`, `:307-336`). Returning immediately when a single candidate fails is a separate Swift implementation policy. Context cancellation closes the remaining attempts (`:240-244`, `:281-284`).
   5. Force 443 when the `TS_FORCE_NOISE_443` environment variable is set, on plan9, or when the preceding Noise dial was within 2 minutes (`client.go:181-214`, `health/health.go:1414-1425`).
2. An individual attempt follows these steps (`dialURL`, `client.go:346-363`).
   1. Create the 101-byte initiation using steps 1–8 in §4.5.
   2. Connect over TCP (or TLS) and send the request in §3.6. Leave ALPN empty for TLS because negotiating HTTP/2 would prevent the upgrade (`client.go:479-481`). Log certificate validation failures and continue the connection because Noise authenticates the server (`client.go:493-502`). Disable response compression (`client.go:505`).
   3. Fail with `unexpected HTTP response` if the status is anything other than 101 (`client.go:555-557`).
   4. Fail unless the response `Upgrade` value is exactly `tailscale-control-protocol` (`client.go:569-572`). The client does not inspect the `Connection` header.
   5. Continue on the same socket from step 9 of §4.5 onward. Close the socket on failure (`client.go:355-359`).
3. The server expects and handles the following.
   1. Lowercase `Upgrade` before comparing it. Accept `tailscale-control-protocol` on the HTTP upgrade path, take the WebSocket path for `websocket`, and return 400 for an empty or unrecognized value (`controlhttpserver.go:48-59`).
   2. Return 400 if `X-Tailscale-Handshake` is missing or its base64 is invalid (`controlhttpserver.go:61-70`).
   3. If hijacking is unavailable because this is not HTTP/1, return 400 "make request over HTTP/1" (`controlhttpserver.go:72-76`).
   4. Write 101, hijack the connection, and arrange for any buffered client bytes to be read first (`controlhttpserver.go:78-96`).
   5. Keep writes "corked" during the handshake, write the early payload, then flush everything together (`controlhttpserver.go:98-119`, `:174-230`). The 51-byte response and early payload records can therefore arrive together.
   6. If the handshake fails, close the connection without flushing the cork buffer (`controlhttpserver.go:87-91`, `:100-103`). On the HTTP upgrade path, an EOF may therefore follow 101 in place of the §3.3 error message. The client treats EOF immediately after 101 as handshake failure.
   7. AcceptHTTP itself does not check the method. testcontrol accepts only POST and GET at `/ts2021` (`testcontrol.go:476-485`).
4. Proxies (summary). Both plaintext and TLS follow HTTP proxy settings (`client.go:470-477`). Test cases include no proxy, port80 MITM, SOCKS5, and HTTP→HTTP/HTTPS proxies (`controlhttp/http_test.go:56-140`).
5. WebSockets (summary). This path is for JS builds only. The default is `wss://host/ts2021`, with `ws://host:port/ts2021` under the custom HTTP port condition (`controlhttp/client_js.go:31-40`). The `X-Tailscale-Handshake` query value is the initiation's standard base64 encoded as a URL query value (`client_js.go:41-49`). Keep the encoding because appending characters such as `+` verbatim can change them during form parsing. The subprotocol is `tailscale-control-protocol` and carries the same Noise byte stream over binary messages (`client_js.go:51-58`, `controlhttpserver.go:144-165`).

### 4.5 controlbase handshake (client = initiator)

Notation follows. `h` and `ck` are 32 bytes. `BLAKE2s` is unkeyed BLAKE2s-256 (`handshake.go:440-450`). `HKDF(ck, ikm)` is BLAKE2s-based HKDF with salt = `ck`, input keying material = `ikm`, and no info. It uses the first 32 bytes and the next 32 bytes of output (`handshake.go:376-383`, `:422-428`. For the definition of HKDF itself, see `golang.org/x/crypto@v0.58.0/hkdf/hkdf.go:27-37`, `:63-70`, `:90-99`). `MixHash(x)` computes `h = BLAKE2s(h ‖ x)` (`handshake.go:350-358`). `MixDH(priv, pub)` computes `dh = X25519(priv, pub)` and `(ck, k) = HKDF(ck, dh)`, with k a one-use ChaCha20-Poly1305 key (`handshake.go:360-385`). `EncryptAndHash(k, pt)` computes `c = Seal(k, nonce=0¹², ad=h, pt)` and `MixHash(c)` (`handshake.go:387-397`). For `DecryptAndHash(k, c)`, if `Open(k, nonce=0¹², ad=h, c)` succeeds, compute `MixHash(c)` (`handshake.go:399-413`).

The two HKDF outputs here are `(t1, t2)`, computed as `prk = HMAC-BLAKE2s(key=ck, data=ikm)`, `t1 = HMAC-BLAKE2s(key=prk, data=01)`, and `t2 = HMAC-BLAKE2s(key=prk, data=t1 ‖ 02)`. `01` and `02` are each 1 byte. Do not substitute a BLAKE2s keyed hash for HMAC (`golang.org/x/crypto@v0.58.0/hkdf/hkdf.go:27-37`, `:63-70`, `:90-99`. See also `Go 1.27.3/src/crypto/internal/fips140/hkdf/hkdf.go:13-24`).

1. `h = BLAKE2s("Noise_IK_25519_ChaChaPoly_BLAKE2s")`, `ck = h` (`handshake.go:31`, `:344-348`). The name is 33 bytes, so the Noise rule also takes the hashing path (pad names of 32 bytes or less with 0) (`noiseexplorer_test.go:182-189`).
2. `MixHash(prologue)`. prologue = ASCII `"Tailscale Control Protocol v"` + base-10 string of the version, with no terminator. For example, version 148 → `Tailscale Control Protocol v148` (`handshake.go:42`, `:46-50`, `:73`).
3. `MixHash(32-byte server static public key)` (`handshake.go:77`).
4. Create the ephemeral key pair e. `key.NewMachine()` clamps 32 random bytes according to the X25519 rules (`handshake.go:81-82`, `types/key/machine.go:42-46`, `types/key/util.go:51-54`). Write `e.pub` to initiation[5:37] and perform `MixHash(e.pub)` (`handshake.go:83-84`).
5. es: `k1 = MixDH(e.priv, server static public key)` (`handshake.go:85`).
6. `EncryptAndHash(k1, 32-byte client machine public key)` → write 48 bytes to initiation[37:85] (`handshake.go:89-90`).
7. ss: `k2 = MixDH(machine private key, server static public key)` (`handshake.go:91`).
8. `EncryptAndHash(k2, empty plaintext)` → write the 16-byte tag to initiation[85:101] (`handshake.go:95`). Send it in the header as in §3.6.
9. Read the 3-byte header. If the type is anything other than `0x02`, check for `0x03`. For that type, read the specified length and fail with "server error". For other types, fail with "unexpected response message type" (`handshake.go:137-150`).
10. Fail if the length is anything other than 48. Read 48 bytes (`handshake.go:151-156`).
11. Use `re` (the server ephemeral public key) for `MixHash(re)` (`handshake.go:159-160`).
12. ee: `MixDH(e.priv, re)`. Discard the returned key and update only `ck` (`handshake.go:161-163`).
13. se: `k3 = MixDH(machine private key, re)` (`handshake.go:164-167`).
14. `DecryptAndHash(k3, 16-byte tag)`. On failure, stop with "decrypting payload" (`handshake.go:168-170`).
15. Split: `(k_a, k_b) = HKDF(ck, empty input)` (`handshake.go:418-437`). The client sends with `k_a` and receives with `k_b`. The server sends with `k_b` and receives with `k_a` (`handshake.go:177-188`, `:313-324`). Both directions start with nonce 0.
16. The final `h` is the handshake hash (`handshake.go:181`, `conn.go:76-82`). In this repository, only tests read it.

Each X25519 input must be 32 bytes. Reject inputs that produce a shared secret with all bytes set to 0, such as low-order public keys (`golang.org/x/crypto@v0.58.0/curve25519/curve25519.go:20-26`, `:77-92`). Fail with the name of the relevant step and do not continue by feeding a shared secret of 0 into HKDF (`handshake.go:369-374`). The server only mixes the version into the prologue and does not block the handshake based on its value (`handshake.go:241-246`, `:262`). Server-side initiation validation errors are "wrong handshake initiation size" for size, "unexpected handshake message type" for type, and "wrong handshake initiation length" for length (`handshake.go:233-252`).

All handshake AEAD operations use nonce=0¹² and AAD=`h` immediately before that operation. The initiation and response type and length headers themselves are neither passed to `MixHash` nor included directly in AAD. Only the version is authenticated through the prologue (`handshake.go:71-95`, `:159-168`, `:387-413`). Records use no AAD, and their header is excluded as well (`conn.go:146`, `:169-171`).

The capability version appears in `/key?v=148`, as the initiation's uint16 BE, and as the prologue's decimal string (`direct.go:1536`, `messages.go:43`, `handshake.go:46-50`). The response does not return a version for negotiation. If `ts2021.ClientOpts.ProtocolVersion` is not 0, use that value for the handshake. If it is 0, use the current value 148 (`ts2021/client.go:253`). `Version` in higher-level request JSON is a separate field supplied by that request. It is neither an HTTP/2 frame version nor a header (for example, `tailcfg.go:2595-2601`, `:2648-2650`. For registration and maps, see `control-map.md`).

### 4.6 Transport phase state

1. Read the 3-byte header → read the specified length → fail if the type is anything other than `0x04` → check the nonce → decrypt → increment the nonce (`conn.go:131-157`, `:196-239`).
2. If decryption fails even once, discard the receive key and return `net.ErrClosed` on all subsequent reads (`conn.go:149-155`, `:246-248`).
3. If any write fails, including a partial write or a deadline expiration, all subsequent writes fail (`conn.go:37-40`, `:274-293`, `:311-317`).
4. There is no separate termination message (types are limited to 1–4, `messages.go:8-21`). Close the underlying socket and clear references to the cipher state (`conn.go:323-338`).

### 4.7 HTTP/2 over ts2021 (verified in the repository)

1. The client configures the Go `net/http` Transport for unencrypted HTTP/2 only and returns a Noise connection from the dial hook (`ts2021/client.go:166-178`). This HTTP/2 implementation comes from the Go standard library (`Go 1.27.3/src/net/http/internal/http2/transport.go:673-687`).
2. There is 1 connection per host (`MaxConnsPerHost: 1`, `client.go:168`). All requests are multiplexed over one HTTP/2 connection. The connection pool normally holds 0–1 connections and briefly holds 2 during reconnection after a network failure (`client.go:284-286`).
3. The request URL is `"https://" + host + path` (`client.go:304`). Thus `:scheme` is `https`, and `:authority` is the control server hostname (`Go 1.27.3/src/net/http/internal/httpcommon/httpcommon.go:285-297`).
4. Requests with a body use JSON and `Content-Type: application/json`, and include the `Ts-Lb: nodekey:<hex>` header when the node key is not 0 (`client.go:299-318`, `tailcfg.go:3093-3109`).
5. By default, the response body is cut off at 1 MiB (`httpbody.DefaultMaxSize = 1 << 20`) and treated as an error (`client.go:320-336`, `util/httpbody/httpbody.go:30-34`). The map stream disables this limit (`controlclient/direct.go:1150-1157`). The map response body is an unending stream of length-prefixed messages (`direct.go:1150-1154`, details in `control-map.md`).
6. After disconnection, the Transport dials again on the next request, with a fresh Noise handshake on each dial (`client.go:174-176`, `controlhttp/client.go:346-363`). Closing the client closes all live Noise connections (`ts2021/client.go:182-197`, `controlclient/direct.go:422-436`).
7. The server (testcontrol and ts2021 tests) runs `golang.org/x/net/http2`'s `Server.ServeConn` over Noise with default settings (`testcontrol.go:497-505`, `ts2021/client_test.go:456-458`). The version is `golang.org/x/net v0.60.0` (`go.mod:143`). With the default Go 1.27 build, x/net's `Server` delegates to the Go standard library HTTP/2 implementation. x/net's `server.go` is the `http2legacy` build path (`golang.org/x/net@v0.60.0/http2/server_wrap.go:5-7`, `:115-166`, `http2/server.go:5`). This verification actually ran through Go 1.27.3's `src/net/http/internal/http2`.
8. To receive an early payload, perform the 9-byte check in §3.7 before reading HTTP/2 input (`ts2021/conn.go:103-106`, `:122-157`). The Go client defers the check until its first Read, so it can send the HTTP/2 preface immediately without waiting for the early payload (`conn.go:103-106`).

## 5. Constants and timers

| Name | Value | Source |
| --- | --- | --- |
| `protocolName` | `Noise_IK_25519_ChaChaPoly_BLAKE2s` | `controlbase/handshake.go:31` |
| `protocolVersionPrefix` | `Tailscale Control Protocol v` | `handshake.go:42` |
| Protocol version | Default `CurrentCapabilityVersion` = 148, or the explicit `ProtocolVersion` if present | `ts2021/client.go:253`, `tailcfg.go:200` |
| `msgTypeInitiation` / `Response` / `Error` / `Record` | 1 / 2 / 3 / 4 | `controlbase/messages.go:10-21` |
| `headerLen` / `initiationHeaderLen` | 3 / 5 | `messages.go:24-26` |
| Initiation / response size | 101 / 51 | `messages.go:39`, `:71` |
| `maxMessageSize` | 4096 | `controlbase/conn.go:28` |
| `maxCiphertextSize` / `maxPlaintextSize` | 4093 / 4077 | `conn.go:31-34` |
| `invalidNonce` | 2^64−1 | `handshake.go:43` |
| `serverUpgradePath` | `/ts2021` | `controlhttp/constants.go:26` |
| `UpgradeHeaderValue` | `tailscale-control-protocol` | `controlhttpcommon.go:10` |
| `HandshakeHeaderName` | `X-Tailscale-Handshake` | `controlhttpcommon.go:15` |
| `NoPort` | `none` | `controlhttp/constants.go:32` |
| 443 delay | 500ms | `controlhttp/client.go:87-94` |
| Force 443 after a recent dial | 2 minutes | `health/health.go:1414-1425` |
| Dial timeout | Default 5+5 seconds, clamped to [5, 60] seconds | `ts2021/client.go:213-243` |
| `EarlyPayloadMagic` | `ff ff ff 54 53` | `ts2021/conn.go:91` |
| Early payload header / maximum | 9 bytes / 10 MiB | `ts2021/conn.go:87`, `:144` |
| `LBHeader` | `Ts-Lb` | `tailcfg.go:3109` |
| Default response body limit | 1 MiB | `util/httpbody/httpbody.go:34` |
| `/key` response limit | 64 KiB | `controlclient/direct.go:1546` |
| Maximum protocol version | `math.MaxUint16` (panics above this value) | `ts2021/client.go:202-206` |

### 5.1 Key string and binary formats (`types/key`)

All text formats use `prefix + hex of key bytes` (`types/key/util.go:56-61`). On read, the prefix must match exactly, the hex length must be 2 times the key length, and uppercase and lowercase hex are both accepted (`util.go:63-101`). Repository test vectors use lowercase (`types/key/machine_test.go:43-44`). JSON represents this text as a JSON string (MarshalText implementations, for example `machine_test.go:42-45`, `node_test.go:58-60`).

| Key | Private key text | Public key text | Byte length | Source |
| --- | --- | --- | --- | --- |
| machine (X25519) | `privkey:` | `mkey:` | 32 | `machine.go:24`, `:31`, `:71-83`, `:252-264` |
| node (X25519, WireGuard) | `privkey:` | `nodekey:` | 32 | `node.go:29`, `:36`, `:116-128`, `:333-347` |
| disco (X25519) | No text format | `discokey:` | 32 | `disco.go:23`, `:56-77`, `:188-200` |
| challenge (X25519) | Serialization rejected | `chalpub:` | 32 | `chal.go:19`, `:45-47`, `:76-88` |
| network-lock (Ed25519) | `nlpriv:` (64 bytes → 128 hex) | `nlpub:` (also accepts `tlpub:` on read, CLI displays `tlpub:`) | Private 64 / public 32 | `nl.go:18-29`, `:36`, `:60-72`, `:116`, `:133-157` |

- Node public key binary format: ASCII `np` + 32 bytes (34 total). Other lengths or prefixes are errors (`node.go:40`, `:350-369`).
- The unprefixed hex parser for machine public keys is used for the legacy `/key` format on this transport path (`control/controlclient/direct.go:1560-1568`, `types/key/machine.go:196-202`). Node public keys also have a separate parser used on other paths, including DERP. Do not generalize this as exclusive to `/key` (`types/key/node.go:203`, `derp/derphttp/derphttp_client.go:1203`).
- Short display (`ShortString`): `[` + first 5 characters of standard base64 + `]`, with an empty string for a key of 0 (`util.go:103-120`). This format is for logging and does not appear on the wire.
- Machine, node, and disco private keys are clamped at creation (`machine.go:45`, `node.go:61`, `disco.go:41`). Challenge keys are created the same way as node keys (`chal.go:32-34`). Text deserialization preserves the input bytes without reclamping machine and node private keys (`machine.go:81-82`, `node.go:126-127`). Noise uses the raw, unprefixed 32 key bytes. It does not use `mkey:` text or the node's 34-byte `np` format (`controlbase/handshake.go:77-90`, `:369`).
- Standard base64 encodes the initiation in the `X-Tailscale-Handshake` header for an HTTP upgrade and in the URL query value of the same name for WebSocket. Keep this distinct from key text hex (`controlhttp/client.go:545`, `controlhttp/client_js.go:47-49`).

## 6. Minimum Swiftail requirements and optional parts

M2 gate (transport portion) reads "The Swift client completes a Noise handshake with testcontrol and exchanges one HTTP/2 request and response."

### 6.1 Required implementation

1. Send a plaintext HTTP/1.1 GET to `/key?v=148` and decode `publicKey` (`mkey:` hex) from the JSON. testcontrol runs only over plaintext HTTP (`cmd/testcontrol/testcontrol.go:25`, `:40-43`, `:54-57`).
2. Write the HTTP/1.1 upgrade request over plaintext TCP, validate the 101 response (status and `Upgrade` value), and hand over any bytes remaining after the headers (§3.6, §4.4).
3. Implement the full client handshake in §4.5. Required primitives are X25519, BLAKE2s-256, HMAC-BLAKE2s-based HKDF, and ChaCha20-Poly1305.
4. Implement the record layer in §3.4 and §3.5, with big-endian nonces, 4077-byte write chunks, a 4096-byte read limit, skipping records with zero bytes of plaintext, and discarding the connection on decryption failure.
5. Check for the §3.7 early payload. testcontrol does not send it (earlyWrite is nil in `testcontrol.go:490`), but a server can send it when the client announces version 49 or higher (`tailcfg.go:100`). Include detection from the start because failing to recognize the magic breaks HTTP/2 parsing. M2 may leave the challenge unused while still enforcing the length limit, receiving the complete body, decoding JSON, and validating known key fields (`ts2021/conn.go:143-157`, `types/key/chal.go:85-87`).
6. Implement the minimum HTTP/2 client features in §4.7, with 1 connection, at least 1 request stream, `:scheme https`, and `:authority` = host. Follow §6.3 for required frame, HPACK, and flow control handling.
7. Select a route that testcontrol accepts. testcontrol handles HTTP/2 requests over Noise with the same mux (`testcontrol.go:500-505`). An unregistered route causes a goroutine panic that kills the process (`testcontrol.go:413`, `:430-434`). For M2, the recommended requests are `GET /generate_204` (204, no body, `testcontrol.go:414-416`) or `GET /key?v=148` (JSON body, `testcontrol.go:417`, `:525-537`). The latter also verifies DATA frame reception.

### 6.2 Deferrable parts and rationale

| Item | Rationale |
| --- | --- |
| 443 TLS fallback, 80/443 race, forcing 443 | testcontrol uses a private-address `http://` URL, so there is no HTTPS attempt (`ts2021/client.go:143-150`, `controlhttp/client.go:261-263`, `:291-293`) |
| ControlDialPlan, ACE | This information becomes available only after a map response arrives (`tailcfg.go:2197-2200`) |
| HTTP proxy, SOCKS5, WebSocket | For deployment environment compatibility (`controlhttp/client.go:470-477`, `client_js.go`) |
| Exposing the handshake hash | Used only by tests in the repository (step 16 of §4.5) |
| `Ts-Lb` header | Omit it for a node key of 0 (`ts2021/client.go:313-318`). The M2 request has no node key |
| Legacy key, old `/key` format | The Noise path uses only `publicKey` (`direct.go:700-702`) |
| Per-request adjustment of the response size limit | Keep the default 1 MiB and the `/key` limit of 64 KiB starting in M2. Defer only disabling the limit for unending streams such as map (`ts2021/client.go:320-336`, `controlclient/direct.go:1546`, `util/httpbody/httpbody.go:39-45`) |
| Connection reuse and reconnection policy | M2 uses 1 connection and 1 request. Later, follow steps 2 and 6 of §4.7 |
| Sending error messages (type 3) | Only the server sends them (`handshake.go:211-227`). The client needs only the receive branch |

### 6.3 Minimum HTTP/2 requirements

The repository confirms the following.

- The client starts HTTP/2 first. The server starts `ServeConn` after the Noise handshake and early payload (`controlhttpserver.go:100-121`, `testcontrol.go:490-505`).
- The first HTTP/2 bytes from the server are the SETTINGS frame header (comment in `ts2021/conn.go:81-84`).
- Multiple requests are multiplexed on one connection, and unending response bodies such as the map stream flow alongside other requests (steps 2 and 5 of §4.7).
- The server uses `golang.org/x/net/http2` v0.60.0 with default settings (step 7 of §4.7).

The dependencies and the Go 1.27.3 standard library used for execution establish the following minimum requirements. See the delegation path in §4.7.

- After removing the early payload, start HTTP/2 directly over the Noise plaintext byte stream. The outer `/ts2021` HTTP/1.1 upgrade is the only upgrade. Do not repeat HTTP/1.1 or an `h2c` upgrade inside it (`testcontrol.go:490-505`, `Go 1.27.3/src/net/http/internal/http2/server.go:793`, `:965-994`). The client first sends the 24 ASCII bytes `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` and a non-ACK SETTINGS frame. An empty SETTINGS frame is allowed. The server waits 10 seconds for the preface and has a 2-second limit for the first SETTINGS (`Go 1.27.3/src/net/http/internal/http2/http2.go:65-67`, `server.go:58-59`, `:817`, `:1441-1446`, `golang.org/x/net@v0.60.0/http2/frame.go:878-884`). Apply the server's non-ACK SETTINGS and send back empty ACK SETTINGS (`00 00 00 04 01 00 00 00 00`). Do not ACK a received ACK (`Go 1.27.3/src/net/http/internal/http2/server.go:1616-1641`, `golang.org/x/net@v0.60.0/http2/frame.go:887-893`). Send the preface without waiting for server SETTINGS.
- The HTTP/2 frame header is the 9 bytes shown below. Accumulate the specified payload length from the stream independently of Noise record boundaries (`http2/frame.go:249-259`, `controlbase/conn.go:258-259`, `:300-305`).

| Offset | Length | Field | Encoding | Source |
| --- | --- | --- | --- | --- |
| 0 | 3 | payload length | uint24 BE, excluding the header | `golang.org/x/net@v0.60.0/http2/frame.go:255` |
| 3 | 1 | type | DATA=0, HEADERS=1, SETTINGS=4, PING=6, GOAWAY=7, WINDOW_UPDATE=8, CONTINUATION=9 | `http2/frame.go:32-43` |
| 4 | 1 | flags | END_STREAM=1, END_HEADERS=4, SETTINGS/PING ACK=1 (meaning depends on type) | `http2/frame.go:76-95` |
| 5 | 4 | reserved bit + stream ID | Low 31 bits of a uint32 BE | `http2/frame.go:258` |

- SETTINGS payload is a sequence of 6-byte `ID:uint16 BE + value:uint32 BE` entries, with stream ID=0. The ACK payload is empty (`golang.org/x/net@v0.60.0/http2/frame.go:766-825`, `:878-893`).
- Request streams use increasing odd IDs starting with stream 1 (`Go 1.27.3/src/net/http/internal/http2/server.go:1865-1903`). A GET without a body sets END_STREAM on HEADERS, and END_HEADERS ends the header block. Read the response through END_STREAM on HEADERS or DATA, and combine CONTINUATION frames into the same stream's header block through END_HEADERS (`golang.org/x/net@v0.60.0/http2/frame.go:76-95`, `:590-617`, `:1588-1590`). For M2, the client can send `:method GET`, `:scheme https`, `:authority tail0001` (the test host), and `:path /key?v=148` (`ts2021/client.go:304`, verified in the run reported in §7.3). Pseudo-headers precede ordinary headers, and names must be lowercase (`golang.org/x/net@v0.60.0/http2/frame.go:1730-1738`).
- Response HPACK must handle the static table, the default 4096-byte dynamic table, indexed and literal representations, table size updates, and Huffman strings. The server encodes matching entries by index, adds nonsensitive fields to the dynamic table when they fit, and uses Huffman when it is shorter (`Go 1.27.3/src/net/http/internal/http2/server.go:305-306`, `golang.org/x/net@v0.60.0/http2/hpack/encode.go:49-99`, `:138-140`, `:215-227`). HPACK integers use a variable-length encoding with an n-bit prefix in the first byte followed by groups of 7 low bits, rather than fixed-width BE. Indexed uses `1`+7 bits, incremental literal uses `01`+6 bits, without indexing uses `0000`+4 bits, never indexed uses `0001`+4 bits, and table size update uses `001`+5 bits. Strings carry the bytes after a 1-bit Huffman flag and a length with a 7-bit prefix (`http2/hpack/hpack.go:303-330`, `:433-500`). The sending encoder can start with literals and no Huffman, but the receiving decoder must handle Huffman. The client can simplify by sending SETTINGS_HEADER_TABLE_SIZE=0 at the start to prevent creation of dynamic entries. It must still account for responses before the server processes SETTINGS and for table size updates (`Go 1.27.3/src/net/http/internal/http2/server.go:1653-1659`, `:1166-1174`).
- The initial connection and stream send windows are each 65535 bytes. The initial maximum frame payload is 16384 bytes (`golang.org/x/net@v0.60.0/http2/http2.go:74-85`, `http2/flow.go:87-89`). The default testcontrol server advertises MAX_FRAME_SIZE=1048576, MAX_CONCURRENT_STREAMS=250, MAX_HEADER_LIST_SIZE=1048896, HEADER_TABLE_SIZE=4096, and INITIAL_WINDOW_SIZE=1048576. It also sends WINDOW_UPDATE(0, 983041) to increase the connection window (`Go 1.27.3/src/net/http/internal/http2/config.go:50-75`, `server.go:58-61`, `:769-791`, verified in the run reported in §7.3). Extension SETTINGS can also arrive, so ignore unknown IDs (`Go 1.27.3/src/net/http/internal/http2/server.go:1670-1683`). Keep these server values distinct from the client's own receive limits.
- Apply both connection and stream flow control when sending and receiving DATA. SETTINGS_INITIAL_WINDOW_SIZE changes the stream window, and WINDOW_UPDATE(stream 0) changes the connection window (`golang.org/x/net@v0.60.0/http2/flow.go:68-105`, `Go 1.27.3/src/net/http/internal/http2/server.go:1517-1550`, `:1688-1701`). To keep a long map response from stalling, replenish both windows with WINDOW_UPDATE for the DATA consumed (`golang.org/x/net@v0.60.0/http2/transport.go:2235-2278`. The Go 1.27 path does this too at `Go 1.27.3/src/net/http/internal/http2/transport.go:2431-2448`). The server also replenishes the window as it consumes request bodies and accumulates small increments (`Go 1.27.3/src/net/http/internal/http2/server.go:2406-2436`, `golang.org/x/net@v0.60.0/http2/flow.go:29-55`). Even a single small GET that does not require replenishment must handle incoming WINDOW_UPDATE.
- Reply to a non-ACK PING with the same 8 bytes in an ACK. Do not reply to ACK (`Go 1.27.3/src/net/http/internal/http2/server.go:1493-1514`). The default testcontrol settings have IdleTimeout and SendPingTimeout=0, so they enable neither periodic PING nor idle close timers. When configured, the timers run, and the default PingTimeout is 15 seconds (`Go 1.27.3/src/net/http/internal/http2/server.go:804-813`, `config.go:65`). Connection errors can arrive as GOAWAY and stream errors as RST_STREAM, so even M2 must end with failure and avoid blindly sending a new request (`Go 1.27.3/src/net/http/internal/http2/server.go:1412-1435`). Do not start a new stream on a connection that has received a normal GOAWAY either (`Go 1.27.3/src/net/http/internal/http2/transport.go:856-863`).
- For ordinary requests, `:method` and `:path` must be nonempty, and `:scheme` must be `http` or `https`. If `:authority` is missing, use Host. Reject userinfo (`@`) in the authority (`Go 1.27.3/src/net/http/internal/http2/server.go:2132-2157`, `Go 1.27.3/src/net/http/internal/httpcommon/httpcommon.go:587-593`). The x/net legacy path also checks for mismatches between authority and Host and invalid Host characters. Do not assume those checks carry over unchanged to the Go 1.27 delegation path (`golang.org/x/net@v0.60.0/internal/httpcommon/request.go:437-470`). Swift sends a valid authority without a duplicate Host (`Go 1.27.3/src/net/http/internal/httpcommon/httpcommon.go:289-309`). The `https` scheme over Noise entails no additional TLS handshake (`testcontrol.go:490-505`, `ts2021/client.go:170-175`).
- After the preface, the actual Go standard client sends SETTINGS with ENABLE_PUSH=0, INITIAL_WINDOW_SIZE=4 MiB, MAX_FRAME_SIZE=1 MiB, and MAX_HEADER_LIST_SIZE=10 MiB, and sends a connection WINDOW_UPDATE increment of 1 GiB. Go 1.27.3 chooses these values. Swift does not require them (`Go 1.27.3/src/net/http/internal/http2/transport.go:43-50`, `:673-687`, `:82-91`, `config.go:50-65`, `http2.go:82`). Swift can start with small requests using the protocol's default receive window.

## 7. What to verify in interop tests

### 7.1 Repository Go tests and what can be reused

| Test | Coverage | Reuse in Swift tests | Source |
| --- | --- | --- | --- |
| `TestHandshake` | Handshake hash, version, and peer keys agree on both sides | Repeat the checks with a Swift client and Swift server pair for testing | `controlbase/handshake_test.go:18-56` |
| `TestNoReuse` | Wire bytes and hash differ every time even with the same long-term keys | Can be ported directly | `handshake_test.go:60` onward |
| `TestTampering` | Verifies failure after tampering with all 101 initiation bytes and 51 response bytes and the first 30 bytes of the first server record. That record is 14 plaintext + 16 tag + 3 header = 33 actual bytes | In Swift, tamper with all 33 bytes, including the last 3 bytes of the record tag | `handshake_test.go:163-240`, `conn.go:169-171` |
| `TestMessageSize` | Maximum ciphertext is at most 65535 | Check the constant | `controlbase/conn_test.go:28-39` |
| `TestBigData` | Both nonce directions stay in sync after a large transfer (client 4, server 8) | Check nonce progression | `conn_test.go:117-160` |
| `TestDataTrickle`, `TestConnStd` | Data arriving incrementally, net.Conn contract | Check partial reads | `conn_test.go:175`, `:192` |
| `FuzzWholeMessageLocked`, `FuzzDecryptLocked` | Record parser fuzzing. Seed frames generated with AEAD using a key of 0 | Refer to the seed construction method (`sealFrame`) | `controlbase/fuzz_test.go:19`, `:49-72` |
| `TestInteropClient`/`Server` | Handshake with the Noise Explorer reference implementation + 1 transport message each way | Valid only for verifying the handshake. Cannot verify nonce endianness (§3.5) | `controlbase/interop_test.go:19-112`, `noiseexplorer_test.go` |
| `TestControlHTTP` | Upgrade, proxy types, early write | Verify upgrade request format | `controlhttp/http_test.go:56-140` |
| `TestDialPlan` | DialPlan race | Defer | `http_test.go:574` |
| `TestNoiseClientHTTP2Upgrade(_earlyPayload)` | HTTP/2 request over Noise, with and without early payload | Use the behavior of the early-payload test server (`Upgrader`) as the reference | `ts2021/client_test.go:55-63`, `:387-459` |
| `TestNoiseClientMaxResponseBodySize` | Response body limit | Use when implementing the limit | `ts2021/client_test.go:65-71` |
| `TestMachineSerialization` and others | `privkey:`/`mkey:`/`nodekey:`/`discokey:` JSON serialization vectors | Reuse directly as key text format test vectors | `types/key/machine_test.go:41-79`, `node_test.go:58-60`, `disco_test.go:41-42` |

The original Go tests have no handshake vectors with fixed keys and fixed ephemeral keys (`handshake_test.go:21-22`). §7.3 contains the reusable vectors generated and checked separately.

### 7.2 What to verify against testcontrol

For the interop test, `cmd/testcontrol` listens for plaintext HTTP on `--addr` (default `127.0.0.1:9911`) and also starts DERP and STUN on the same IP (`cmd/testcontrol/testcontrol.go:24-58`). The integration test environment also uses plaintext HTTP with `httptest.NewUnstartedServer` + `Start()` (`tstest/integration/integration.go:579`, `:596`). The required routes are `/key`, `/ts2021`, and either `/generate_204` or `/key` over Noise (`testcontrol.go:411-423`).

1. Verify that `/key?v=148` returns JSON and that `publicKey` is `mkey:` + 64 hex. If `v` is missing or empty, verify that it returns text/plain hex (`testcontrol.go:525-537`).
2. Verify that the upgrade response has status 101 and `Upgrade: tailscale-control-protocol`, immediately followed by the 51-byte response.
3. Verify that handshaking with the wrong server key causes the server to fail machine key decryption and yields EOF after 101 (§4.4, item 3, step 6).
4. Verify that sending an initiation shortened to 100 bytes yields EOF after 101 (server-side "wrong handshake initiation size", `handshake.go:233-236`).
5. Verify that one HTTP/2 request succeeds. The HTTP/2 exchange uses multiple records in both directions, so this verifies the big-endian nonce implementation.
6. Verify that missing `X-Tailscale-Handshake`, invalid base64, or missing `Upgrade` yields 400 (`controlhttpserver.go:48-70`).
7. Verify that a request body exceeding 4077 bytes is received across multiple records.
8. Verify early payload handling separately because testcontrol does not send it. Use a server that writes magic, length, and JSON separately, as `Upgrader` in `ts2021/client_test.go` does.
9. Compare frame traces from the Swift implementation for the HTTP/2 handling in §6.3 (Huffman, dynamic table, window sizes, PING, GOAWAY). Verify that it applies received SETTINGS without assuming fixed Go defaults (`golang.org/x/net@v0.60.0/http2/server.go:780-801`, `:1654-1695`).

### 7.3 Fixed-input test vectors and execution results

On 2026-11-14, the unmodified `controlbase.ClientDeferred`, `Server`, and `Conn.Write` from v1.104.6 ran under Go 1.27.3. **All keys below are public, fixed test-only values. Never reuse them for real connections.** version=148, the handshake uses nonce 0¹², and the transport counter starts at 0 in each direction. Separate code computed §4.5, expanding HKDF directly as two HMAC blocks, using `crypto/ecdh` for X25519, and using only BLAKE2s and ChaCha20-Poly1305 as primitives. The initiation, response, both handshake hashes, and records 0, 1, and 2 in both directions matched byte for byte (procedure sources `controlbase/handshake.go:67-95`, `:159-188`, `:264-324`, `:344-437`, `controlbase/conn.go:162-172`, `:391-395`). The dependencies were `golang.org/x/crypto` v0.58.0 and `golang.org/x/net` v0.60.0. The separate Go tests for `controlbase`, `types/key`, `controlhttp`, and `ts2021` all passed as well.

Inputs are raw 32-byte hex. The private keys below come from applying the §4.5 clamp to the original byte sequences 00..1f, 20..3f, 40..5f, and 60..7f, and are listed alongside their public keys (`types/key/util.go:51-54`, `machine.go:61-67`).

| Key | Private key (hex) | Public key (hex) |
| --- | --- | --- |
| Client machine | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e5f` | `8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f` |
| Server static | `202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e7f` | `358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254` |
| Client ephemeral | `404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f` | `79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a` |
| Server ephemeral | `606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f` | `675dd574ed7789310b3d2e7681f3790b466c773b1521fecf36577958371ea52f` |

All intermediate values are 32-byte hex. AAD uses the immediately preceding hash. The es, ss, and se keys are the AEAD keys for the machine public key, empty initiation payload, and empty response payload, respectively. The ee key is discarded (`handshake.go:85-95`, `:161-168`, `:376-413`).

| Step | hash / ck / AEAD key (hex) |
| --- | --- |
| Initial h=ck | `bbea022b948cf3bc5857d70804229179e1116bc40cb8cc074835349c464bca36` |
| h after prologue | `fec1c32c3bfa98e7b8fe17ed6a11ca98010faf537dfe04facd365dcc7278c6e3` |
| h after server static public key | `4ff25d533e57e80cde501455476df3c74d6105a0404fd2367b2fe2bb4bba0ac1` |
| h after client ephemeral public key = first AEAD AAD | `8f4d3fee07c8dca8b9193141d281d1a219a6020d14f310b55b11664105de1e99` |
| ck after es | `638c46b2fa99a1d28c6eb68e133c5d220eaf490852adf740ac083beb644259fa` |
| es key | `61d19a096c56c8c57f13d65d3d35f392b87fecc40b9be69c2431d14021761348` |
| h after machine ciphertext = initiation tag AAD | `a46b7bce53ea6f082652cfbe415cbc3d09124ac9a1c5917c42c8a028b4df851c` |
| ck after ss | `859ff0aa416be42ccff019b9b0a8c90127042d9022f1b7653360236214fabc5c` |
| ss key | `27d4bfb4f102b7b35e13f29013edb4f8297fd35051466874ee42f211a7a26251` |
| h after initiation tag | `771e5e7a343ed7076b5956fa19a2ec6ac6179f4457291c0cf14cebf949988998` |
| h after server ephemeral public key = response tag AAD | `0a4c2fc98dedfaed302eb21c6766a44475caeb9875fc68b16f77687547edf9d2` |
| ck after ee | `4d7a28f286cc2ba50b46631421d591b895a65b320c6ecc06ae9257c3892ee374` |
| ck after se | `6cbc50260668a0a00ce3581cf60c6b0917f53b1237ec69031af3e2564ece36b4` |
| se key | `3924ede1bd3140a5e6600880c30b3a717c8b726a300233b30e9684aadcf40ca9` |
| Final handshake hash | `e1450d6bb0ab8e06a5cda35ff6c7ec232f7f2f6be0cc5f93433c43dc11abc66f` |
| Split k_a: client → server | `b5a6c358cd51a1fc717517315852e009148ee5480cf70a3caf4d4f9498c9ca8e` |
| Split k_b: server → client | `d8ebca0df9236e3c51fcc4e5d506d473b019dd191d7ac7112d1e046898a1e78d` |

Complete wire messages are hex including headers and tags. The initiation is 101 bytes and the response is 51 bytes (`messages.go:39-45`, `:71-76`).

initiation:

```text
009401006079a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51aad5b8febedeb97415be53612205e6bfab385e34cb127dd8854c4f9afb10f9b0e635d32b6eacf64ca7ce3a83fdf2f525f62cda6ef940fef0c11064f09a292d01e
```

response:

```text
020030675dd574ed7789310b3d2e7681f3790b466c773b1521fecf36577958371ea52fe938fd4935979fcc3489231f7ef4c9c7
```

Record plaintext is the UTF-8 string in the table, with no newline or NUL. All records use no AAD and nonce=`00000000 ‖ uint64BE(counter)`. The hex in the table includes `04` and the uint16 BE length (`conn.go:169-172`, `:395`).

| Direction | counter | Plaintext | Complete record hex |
| --- | --- | --- | --- |
| Client → server | 0 | `client-0` | `0400184d8db142648da2b8ceb16a43dbdb67e57ba92f2c667e173e` |
| Server → client | 0 | `server-0` | `040018775de2b464bfc78e7ed71c2598a5bf25f9c23ad37efcd53e` |
| Client → server | 1 | `client-1` | `040018848768a068cbdd2364ed56d8293a3f5264a340bdf735bb5a` |
| Server → client | 1 | `server-1` | `040018a0b7204f4127b4280c93761eceed2305f8f1ec9fa93d8760` |
| Client → server | 2 | `client-2` | `0400186f62b5bf6af70eaae2e7bd9d858d139300bdedcb660f97df` |
| Server → client | 2 | `server-2` | `0400180096fa0ae79135bea550c3d6d6a63c427e2b5eb1980579f4` |
| Client → server | 3 | Empty plaintext | `04001002e188736cdfc5af317a26b1fed85ca0` |
| Client → server | 4 | `after-empty` | `04001b8a5c4fe32e73ff64383e91d49bec27571d8e198737eae631cbd94a` |

The empty record at counter 3 and the record at counter 4 were computed with primitives and injected directly into the Go server. It authenticated and skipped the first record and returned `after-empty`. Tampering with 1 tag byte of the server → client counter 3 record produced an authentication error on the first Read and `net.ErrClosed` on the next Read (`conn.go:146-155`, `:246-257`). Execution output: `PASS: independent primitive computation = controlbase initiation/response/hash/bidirectional nonces 0·1·2; empty record skipped; net.ErrClosed after authentication failure`.

On the same day, the test ran testcontrol with `httptest.NewServer` and verified the two `/key` forms in §7.2, Noise after 101 + HTTP/2 `GET /key?v=148` (200, 176 bytes of JSON DATA), and presence and absence of `Content-Length: 0`. Missing `Host` and invalid base64 yielded 400. A 100-byte initiation and an incorrect server key yielded `reading response header: EOF` after 101. Initial SETTINGS and WINDOW_UPDATE matched the §6.3 values (counterpart code `testcontrol.go:476-537`, `controlhttpserver.go:48-119`, `Go 1.27.3/src/net/http/internal/http2/server.go:769-793`). The original `controlhttp` and `ts2021` tests also passed for cases with and without early payload, upgrade, and proxies. This run did not test the Swift implementation or a production server.

## 8. Unverified items

- Actual behavior of the private production control server and headscale, including early payload delivery, HTTP/2 settings, idle connection policy, and whether `/ts2021` allows GET. Verification covered the Go v1.104.6 sources, local testcontrol, and Go tests.
- Higher-layer retry and backoff after `/key` failure. The check established only that `loadServerPubKeys` does not retry internally (`controlclient/direct.go:1535-1569`).
- HTTP proxies, SOCKS5, ACE, and JS WebSocket were checked against the sources in §4.3 and §4.4 and existing Go tests. They were not run separately in a real network environment. TLS port racing and the certificate failure path were also not run separately.
- Full HTTP/2 RFC 9113 and HPACK RFC 7541 conformance, the full range of malicious inputs, and measurements of long map streams and actual PING, GOAWAY, and idle timer activation were not tested. The corresponding behavior in §6.3 comes from checking dependency sources.
- The original Noise specification and the complete RFCs for the cryptographic primitives were not checked. The nonce difference comes from comparing `controlbase/conn.go:395` and `noiseexplorer_test.go:164`, and actual fixed-input interop was verified in §7.3.
