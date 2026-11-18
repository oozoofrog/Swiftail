# wgpeer

This wireguard-go test peer communicates with the Swift WireGuard implementation over UDP loopback. It depends on `github.com/tailscale/wireguard-go` `v0.0.0-20261106233718-9e0ab45c16ca`, which is MIT-licensed. The default bind opens all addresses, so the peer uses a loopback-only UDP bind and the default endpoint parser.

Build from the repository root.

```sh
sh Scripts/build-interop-tools.sh
```

Run the tests as follows.

```sh
cd Tools/interop
GOCACHE="$(eyebuild dir interop-tools)/gocache" GOMODCACHE="$(eyebuild dir ref-src)/gomod" GOFLAGS=-modcacherw go test -count=1 ./...
```

The first line of standard input is the JSON configuration. Each key is 32 bytes in hexadecimal, and `peerEndpoint` is the peer's `127.0.0.1:port`. A `listenPort` of 0 selects an available port. Put the peer's IP prefixes in `allowedIPs`.

```json
{"privateKey":"<64 hex digits>","peerPublicKey":"<64 hex digits>","peerEndpoint":"127.0.0.1:12345","allowedIPs":["10.99.0.1/32"],"listenPort":0}
```

When ready, it writes one line to standard output: `{"event":"ready","listenPort":12345,"publicKey":"<hex>"}`. Subsequent input consists of one JSON command per line.

- `{"cmd":"send","packet":"<hex IP packet>"}` sends a packet to the peer.
- `{"cmd":"stats"}` prints `{"event":"stats","lastHandshakeSec":0,"lastHandshakeNsec":0,"txBytes":0,"rxBytes":0}`.
- `{"cmd":"quit"}` or EOF closes the device.

It prints `{"event":"recv","packet":"<hex>"}` for each decrypted packet. Invalid input produces `{"event":"error","message":"…"}`, and configuration errors produce a exit code other than 0. Logs go to standard error. Outgoing destinations and incoming sources must each fall within the corresponding peer's `allowedIPs`.

# tailnet

Build with `sh Scripts/build-interop-tools.sh tailnet`. Invoking the script without arguments still prints the `wgpeer` path on one line. `tailnet` starts a plaintext testcontrol server, a self-signed TLS DERP server, and a STUN server on loopback, then prints the `ready` JSON. DERPMap's `InsecureForTests` disables certificate verification, so Swift tests must also allow self-signed certificates for this test server only (switching to `setDERPCertificate` pins the certificate. See "DERP certificate pinning" below). STUN uses the same `stun` package because `stuntest` requires `testing.TB`, which is unavailable in an executable.

Each standard input line is JSON with an `id` and a `cmd`. The output is one JSON line containing the command's `id`. Errors use the `error` event. `quit` or EOF exits.

- The `name` for `addPeer` is a lowercase DNS label. The command starts a temporary tsnet node that echoes on TCP and UDP port 7. The `peer` event contains the public nodeKey, addresses, and fqdn.
- `removePeer` closes the node and cleans up its temporary state and returns `removed`. testcontrol has no node deletion API, so the node does not automatically disappear from `nodes` or from other peers' maps.
- `nodes` lists testcontrol registrations. Each node's `endpoints` is an array of IP:port strings that the control server receives and stores from map state updates, or `[]` if none. The command uses `Endpoints` directly from the clone that `AllNodes()` returns (`tailscale.com` v1.104.6 `tstest/integration/testcontrol/testcontrol.go:853-862`, `:1452-1486`). testcontrol does not track individual connections, so `online` does not indicate actual connectivity. `keyExpiry` is the node key expiration time held by the server (UTC RFC 3339), or `""` if absent. On logout it becomes `1970-01-01T00:02:03Z` ("Logout gate commands").
- `peerStatus` returns the nodeKey, addresses, online, curAddr, relay, `active`, and `lastWrite` of the `peers` as seen by the `name` node, along with its own endpoints, `selfAddrs`. `selfAddrs` is the array of IP:port strings from `Status.Self.Addrs`, or `[]` if absent. `active` is a bool, and `lastWrite` is the RFC3339Nano string for a Go `time.Time` (`0001-01-01T00:00:00Z` before any transmission). magicsock reports a peer as active within 45 seconds of outbound activity (data or CLI Ping) and records the time of that last activity in lastWrite. Sending a heartbeat alone does not extend it (`wgengine/magicsock/endpoint.go:2232-2253`, `magicsock.go:4026-4028`, `:4083`). `curAddr` is the address when sending solely over a trusted direct path and is empty if DERP is also used. `relay` is the peer's home DERP region code and does not indicate whether DERP is currently in use. `keyExpiry` is the peer's node key expiration time (UTC RFC 3339, or `""` if absent). `expired` indicates whether Go marked the peer as expired. Go receives `KeyExpiry` changes as deltas and computes `expired` only when it receives a full netmap (`flagExpiredPeers` in `ipn/ipnlocal/local.go:1895`), so immediately after expiration only `keyExpiry` may change while `expired` remains `false`.
- `peerPing` takes `name`, the destination IP `to`, and `type` (`disco`, `TSMP`, `ICMP`). The `result` is a LocalClient PingResult. Success requires an empty `Err`.
- Send `peerSend` as in `{"id":1,"cmd":"peerSend","name":"go-peer-a","to":"100.64.0.2","port":42001,"proto":"udp","payload":"010203"}`. `proto` is `udp` or `tcp`, `port` is 1…65535, and `payload` is up to 65507 bytes in hex (empty is allowed). The command uses the specified peer's tsnet to write one UDP datagram or attempts a TCP connection with a 2-second timeout and writes the payload if connected. The result is `{"id":1,"event":"peerSend","name":"go-peer-a","attempted":true,"sent":true,"error":""}`. Send failures also return a `peerSend` event with `sent:false` and an error string. Invalid command input uses the existing `error` event. `sent` means the payload write completed and does not guarantee receipt. A Swift destination without a TCP stack usually times out with `sent:false`. Check incoming packets to determine whether a SYN was sent. TCP and UDP sockets close when the command ends.
- `injectMapResponse` takes the target `nodeKey` and a `response` object. It queues the response only if the stream is connected, and sends it when the stream is processed. Automatic maps for that node remain suppressed starting with the first injection. Re-encoding the `MapResponse` type as JSON loses original JSON representations such as empty arrays.
- `restartPeer` closes the `name` peer's tsnet and restarts it using the same state directory. The node key and addresses stay the same, while the disco key and UDP port are new (magicsock generates the disco key at startup). The result is the same `peer` event as for `addPeer`. Port 7 echo reopens. Anything opened with `startCapture` or `peerServe` does not carry over. The TSMP disco key advertisement gate (`DiscoAdvertisementTests`) uses this to change the Go peer's disco key.
- `setAuth` sets `requireAuth` and `authKey` before the first control request. testcontrol compares a single key string and has no expiration, reuse, or tag policy. Complete interactive authentication successfully by passing the returned sign-in URL as `authURL`. Completing it with failure or manipulating device approval is unsupported. When a key is required, addPeer uses the same key. While interactive authentication is required, addPeer waits for it to finish, so use this mode to test Swift node registration.
- `setNeverDirectUDP` takes a bool as in `{"id":1,"cmd":"setNeverDirectUDP","enabled":true}` and returns `{"id":1,"event":"neverDirectUDP","enabled":true}`. It can be set back to `false`, and repeating the same value is allowed. Missing or null `enabled`, or a value of another type, produces an `error` event. `envknob.Setenv("TS_DEBUG_NEVER_DIRECT_UDP", "true"/"false")` updates even the registered knob cache, so the setting applies to all Go peers in the tool process, including running peers and peers added later. The `id` and error conventions match other commands.

`setNeverDirectUDP` does not block UDP. Enabling it prevents new direct disco Pings, Pong replies to UDP Pings, and full direct discovery with its associated CallMeMaybe transmission. DERP Pings and UDP data transmission and reception continue (`tailscale.com` v1.104.6 `wgengine/magicsock/debugknobs.go:65-68`, `endpoint.go:1360-1362`, `:1424-1426`, `magicsock.go:2606-2608`). Because it does not immediately clear an established `bestAddr` or its trust period, transmission uses UDP alone for up to 6.5 seconds after the last valid Pong, then uses both UDP and DERP after trust expires. UDP data can still flow while `curAddr` is empty (`endpoint.go:635-653`, `:1107-1205`). Disabling the knob resumes direct discovery on the next transmission, heartbeat, or CLI Ping, and a valid Pong restores the direct path. The command response itself does not indicate that the path has switched.

Pings already sent and CallMeMaybe transmissions or send goroutines already scheduled before the switch are not canceled. A Pong from discovery in progress can therefore still be processed after enabling the knob and extend trust, and an existing Ping timer can clear an untrusted bestAddr when it expires (`endpoint.go:1244-1256`, `:1405-1419`, `:1929-2018`). Since no new direct Pings are scheduled, note 7.2 correctly describes the usual case in which bestAddr remains and duplicate sends over UDP continue, but this is not guaranteed at every transition. Upstream `envknob.Setenv` also explicitly states that it is unsafe with concurrent reads of registered knobs (`envknob/envknob.go:89-108`, `:162-177`). This is a limitation of the test-only runtime switch under the contract, which does not guarantee a switch free of data races.

Measure transition time by polling `peerStatus`. Contrary to note 7.1, the default size-0 disco Ping is not also sent over DERP when a trusted direct path exists (`endpoint.go:720-722`, `:1061-1070`). If you call `peerPing type=disco` immediately after enabling the knob in this state, it may wait until the command times out because direct Ping transmission is also blocked. To observe the transition, keep sending UDP data and reading status.

In an actual reproduction that enabled the knob and called disco Ping immediately after establishing the direct path, the following response arrived after 30.002 seconds. The tool processes commands in order, so status commands also wait during that time.

```json
{"event":"error","id":8,"message":"error Post \"http://local-tailscaled.sock/localapi/v0/ping?ip=100.64.0.2&size=0&type=disco\": context deadline exceeded: "}
```

On 2026-11-14 (KST), JSON commands were used to observe two actual Go peers. After verifying the direct loopback path with mutual disco Pings, the test wrote UDP in both directions every 1 second and read status about every 0.1 seconds. The loopback addresses in `selfAddrs` and `nodes.endpoints` also matched.

- The knob was enabled at 23:31:49.820. peer-b's curAddr became empty at 23:31:56.272 (+6.451 seconds), and peer-a's at 23:31:56.422 (+6.602 seconds). active was true for both. With the knob still enabled, both remained empty through 14 seconds, and UDP writes continued to succeed in both directions (writes alone do not guarantee receipt).
- The knob was disabled at 23:32:03.978, and UDP was written again. At 23:32:04.017 (about +0.040 seconds), both curAddr values returned to direct addresses. This value was observed in this loopback run and does not indicate an upper bound for general networks.
- The separate Go test `TestNeverDirectUDPLeavesUDPData` confirms that 3 new UDP echoes return even after both curAddr values become empty and the DERP server and listener are closed. This agrees with the source reading that the knob does not block direct UDP data.

Registration is automatically approved by default. The default testcontrol map includes the self Node, all Peers, DERPMap, DNSConfig, PacketFilter, and other fields. ControlTime is fixed. Test log uploads are disabled with `logtail.Disable()` and `TS_NO_LOGS_NO_SUPPORT=true`, and portmapper is also disabled. Use only test values because the upstream testcontrol auth key comparison is not constant-time.

## Run `listen` and `connect` with two Swiftail nodes on the test control server

You can register two Swift nodes with local `testcontrol`, DERP, and STUN without an account or auth key. From the repository root, run the executable printed by `sh Scripts/build-interop-tools.sh tailnet` in a terminal. Pass the `controlURL` from the first JSON line, `ready`, to the function below. Keep the terminal open because the tool exits on standard input EOF. `addPeer` is unnecessary. Enter `{"id":1,"cmd":"quit"}` when the test is done.

The integration test target depends on `Swiftail` and `SwiftailBase`. The code below creates separate state directories for the two nodes and waits for `.running` and for each peer to appear in the other's netmap. You can open `listen` before `run()`, but call `connect` after `.running`. Cancel `run()` at the end of the test and always await it. `controlURL` is the value received at runtime, and `root` is an empty temporary directory created by the test.

```swift
import Foundation
import Swiftail
import SwiftailBase

func exchangeWithTwoNodes(controlURL: URL, root: URL) async throws {
    let server = try TailnetNode(configuration: .init(
        stateDirectory: root.appending(path: "server"),
        hostname: "rd-mac-1a2b3c4d", controlURL: controlURL), device: .inProcess)
    let client = try TailnetNode(configuration: .init(
        stateDirectory: root.appending(path: "client"),
        hostname: "rd-mac-5e6f7a8b", controlURL: controlURL), device: .inProcess)
    let listener = try await server.listen(port: 9_200)
    let serverRun = Task { try await server.run() }
    let clientRun = Task { try await client.run() }
    do {
        let deadline = ContinuousClock.now + .seconds(25)
        while true {
            let serverStatus = await server.status
            let clientStatus = await client.status
            if serverStatus.state == .running, clientStatus.state == .running,
               serverStatus.peerCount >= 1, clientStatus.peerCount >= 1 { break }
            guard ContinuousClock.now < deadline else { throw CancellationError() }
            try await Task.sleep(for: .milliseconds(50))
        }
        let status = await server.status
        guard let address = status.addresses.first(where: { $0.isIPv4 }) else {
            throw ConnectionError.unknownHost
        }
        let connection = try await client.connect(to: address.description, port: listener.port)
        var iterator = listener.makeAsyncIterator()
        guard let accepted = await iterator.next() else { throw ConnectionError.closed }
        try await connection.write([1, 2, 3])
        try await connection.finishWriting()
        var request: [UInt8] = []
        while let bytes = try await accepted.read() { request += bytes }
        guard request == [1, 2, 3] else { throw ConnectionError.reset }
        try await accepted.write([4, 5])
        try await accepted.finishWriting()
        var response: [UInt8] = []
        while let bytes = try await connection.read() { response += bytes }
        guard response == [4, 5] else { throw ConnectionError.reset }
        await connection.close()
        await accepted.close()
        await listener.close()
        serverRun.cancel()
        clientRun.cancel()
        _ = await (serverRun.result, clientRun.result)
    } catch {
        await listener.close()
        serverRun.cancel()
        clientRun.cancel()
        _ = await (serverRun.result, clientRun.result)
        throw error
    }
}
```

In an actual test, run the entire function within a cancellable deadline (for example, 60 seconds), then delete `root`. The public API has no deadline argument, so the Task subject to the time limit must be canceled. Consume large bodies in chunks instead of accumulating them as in this small example. `NetstackTests.twoSwiftNodes` verifies the same registration, half-close, and request/response flow against an actual server. Other projects can supply just `root` and `controlURL` and substitute their own protocol test for the byte exchange above.

## M6 TCP transfer commands

Every command accepts `id` under the existing JSON line protocol and responds immediately with the same `id`. The connection and transfer in `peerDial` and the accept and transfer in `peerServe` run in the background without writing asynchronous events to standard output. Query progress with `transfers`. Create the peers first with `addPeer`.

```json
{"id":1,"cmd":"peerServe","name":"go-peer-b","port":9100,"timeoutSec":60}
{"id":2,"cmd":"peerDial","name":"go-peer-a","to":"100.64.0.2","port":9100,"send":104857600,"seed":1,"timeoutSec":60}
{"id":3,"cmd":"transfers"}
{"id":4,"cmd":"peerClose","name":"go-peer-b","port":9100}
```

- `peerServe` takes `name`, `port` (1…65535), and optional `timeoutSec`. The response is `{"id":1,"event":"peerServe","name":"go-peer-b","port":9100}`. One peer can listen on several ports, and a duplicate port is an error. For each connection, it reads the 16-byte header below to determine the send length and seed.
- `peerDial` takes `name`, `to` (an IPv4 or IPv6 literal without a zone), `port`, `send` (an integer from 0…4294967296), `seed` (an integer from 0…18446744073709551615), and optional `timeoutSec`. `send` and `seed` are required and cannot be null. The response is `{"id":2,"event":"peerDial","name":"go-peer-a","transferID":1}`. Connection refusals and transfer failures appear in the transfer record's `error` after this response. The UInt64 seed is never read as floating point.
- `transfers` returns `{"id":3,"event":"transfers","transfers":[...]}`. The optional `name` filters by peer name. An empty list is `[]`, and entries appear in start order. Each entry always contains `transferID` (incremented from 1 within the process), `name`, `remote` (IP:port, with IPv6 in brackets), `sent`, `sentSHA256`, `received`, `receivedSHA256`, `elapsedMs`, `error`, and `state`. `state` is `dialing`, `running`, `complete`, or `error`. While a transfer is in progress, you can read the accumulated byte counts and their hashes. Hashes are lowercase hex, and an empty stream uses SHA-256(empty). `remote` is the destination when Dial starts. On the accept side it is the actual remote address after reading the entire header (an empty string until then). `elapsedMs` is the elapsed time since the start of Dial or since Accept. Success has an empty `error`, and failure has a message wrapping the original Go error. Completed records survive peer and listener closure until the process exits.
- `peerClose` takes `name` and `port`. It closes only that listener and replies with `{"id":4,"event":"peerClose","name":"go-peer-b","port":9100}`. Accepted connections continue, and the port can be reopened. A missing listener is an error. `removePeer`, `quit`, and EOF cancel the relevant listeners, connections, and ongoing Dials and wait for their goroutines to exit.

If omitted or null, `timeoutSec` defaults to 15. If supplied, it must be an integer from 1…3600. The timeout applies once to the header and the entire bidirectional transfer, starting when Dial begins or when accept receives the connection. The listener itself has no deadline. `peerClose` needs no deadline.

### Transfer byte protocol

Only the dialing side writes the initial 16 bytes. The first 8 bytes are **the number of bytes the listener should send, as a big-endian UInt64**. The next 8 bytes are **the seed the listener should use, as a big-endian UInt64**. There is no ACK or response header. Go `peerDial` puts its own `send` and `seed` in this header as well, so both directions use the same length and seed. When Swift dials, it can choose its own send length and seed independently. A truncated header or a requested length greater than 4GiB ends the transfer with an error.

After the header, each side runs separate write and read streams concurrently. The writer sends the specified length of data and calls `CloseWrite` (FIN), while the reader continues until EOF from the peer. **The 16-byte header is excluded from byte counts and hashes on both sides.** The transfer does not assume that received length or content automatically matches. The test caller cross-checks the peer's `sent`/`sentSHA256` against its own `received`/`receivedSHA256`. The same protocol can verify a half-close with different lengths.

The pseudorandom stream is **LCG64** for public tests, not for production cryptography. Its state is `x₀ = seed` (UInt64), with `xₙ₊₁ = (6364136223846793005 × xₙ + 1442695040888963407) mod 2⁶⁴`. After every update, emit `xₙ₊₁` as **8 little-endian bytes** (least significant byte first). Truncate the last word to the required length. Carry over the remaining bytes in a word across read and write chunk boundaries. Seed 0 is accepted as is. Swift can perform the same wrapping arithmetic with `&*` and `&+`. The first 32 bytes for seed 1 follow.

```text
7c00fd43ac6f576c1b1b4a86b38668820eaa972099e1faa5c5579311cd550362
```

The SHA-256 of these 32 bytes is `d96bbb8821f933a5b368b9c127d725ed65b2d2f89f5b6d4505545306e834537d`. Each transfer keeps only a 32KiB send buffer, a 32KiB receive buffer, and the SHA-256 state, so it avoids retaining the full data even for 100MiB or more.

The default testcontrol registration log, which repeatedly logs the public nodeKey, is also disabled.

Go has no command to inject loss or delay. M6 gates 8 and 9 use the contract's Swift `setInProcessLoss(rate:seed:)`. `addKernelPeer` is **not available yet**.

## M7 host gate commands

Existing commands and JSON formats remain. M7 DNS behavior activates when you run any of `acmeStart`, `setCertDomains`, or `setDNSConfig`. The default `DNSConfig` is `Proxied:true`, `CertDomains:["<hostname>.tail0001.test"]`. If you used the existing `setMagicDNS` first, its `Proxied` value is preserved. The existing pre-registration-only convention for `setMagicDNS` still applies. To change MagicDNS after registration, use the new `setDNSConfig`.

The tool pins pebble `github.com/letsencrypt/pebble/v2 v2.10.3` and challtestsrv `github.com/letsencrypt/challtestsrv v1.4.2`. **Both are MPL-2.0 and linked only into the test tool.** The Swift library does not link them. Each module's `LICENSE` contains the original MPL-2.0 text. ACME HTTPS and DNS TCP/UDP listen only on `127.0.0.1`. pebble uses only challtestsrv as a DNS resolver and sends nothing to real DNS or Let's Encrypt. It opens no HTTP-01 or TLS-ALPN-01 listeners. `peerHTTP` also connects only to registered tailnet addresses and does not follow redirects.

All responses to the new commands also return the original `id`. Input and request failures return `{"id":1,"event":"error","message":"…"}`. **Only `peerHTTP` runs the request in the background and writes one response line when it completes.** Other command responses may therefore arrive first. Match responses by `id`. You can send `removePeer` or `peerClose(stop:true)` during a transfer. `quit` and EOF cancel and await outstanding HTTP requests. The `quit` response comes last. Other commands still run in order.

| Command | Input (besides `id` and `cmd`) | Success response (besides `id`) |
| --- | --- | --- |
| `acmeStart` | Optional `nonceReject` (0…100, default 0), `authzReuse` (0…100, default 0), `validationDelaySec` (0…60, default 0) | `{"event":"acmeStart","directoryURL":"https://127.0.0.1:<port>/dir","rootPEM":"-----BEGIN CERTIFICATE-----\n…","dnsAddress":"127.0.0.1:<port>","nonceReject":0,"authzReuse":0,"validationDelaySec":0}` |
| `setCertDomains` | Required `domains` string array, optional `nodeKey` | `{"event":"certDomains","nodeKey":"","domains":[]}`. If supplied, the public `nodeKey` also appears in the response |
| `setDNSConfig` | Required `enabled` bool | `{"event":"dnsConfig","enabled":false}` |
| `setDNSLog` | None | `{"event":"setDNSLog","requests":[{"name":"_acme-challenge.rd-mac-1a2b3c4d.tail0001.test","type":"TXT","value":"<TXT value>","nodeKeySummary":"<public key summary>","time":"2026-01-02T03:04:05.123456789Z"}]}` |
| `setDNSFault` | Required `count` (0…10000), one fault from below | `{"event":"setDNSFault","count":1}` |
| `peerWhoIs` | `name` (the querying Go peer), `to` (IP or IP:port, with brackets for IPv6 with a port) | `{"event":"peerWhoIs","name":"go-peer-a","stableID":"<StableID>","nodeName":"rd-mac-1a2b3c4d.tail0001.test","computedName":"rd-mac-1a2b3c4d","loginName":"<test user login>"}` |
| `peerHTTP` | `name`, `url`, optional `method` (default GET), `headers` (values are string arrays), `send` and `seed` (a pair), `range`, `rootPEM`, `to`, `timeoutSec` | `{"event":"peerHTTP","name":"go-peer-a","status":206,"headers":{"Content-Range":["bytes 0-52428799/104857600"]},"bodyLength":52428800,"bodySHA256":"<lowercase SHA-256 hex>","elapsedMs":1234}` |
| `goState` | `name` | `{"event":"goState","name":"go-peer-a","directory":"<state directory>","stopped":false}` |
| Additional `peerClose` mode | `name`, `stop:true`, omit `port` | `{"event":"peerClose","name":"go-peer-a","stopped":true}` |

`acmeStart` starts only once per network in the process. The root, account, and issuance data are test data for this run and change on restart. `rootPEM` contains **only the certificate PEM** and does not export the private key. Swift tests use it as an explicit test anchor for directory HTTPS and issued chain verification. `nonceReject` is the percentage of valid nonces to reject at random. At 100, issuance never completes. `authzReuse:100` reuses valid authorization for the same account and domain. `validationDelaySec:0` disables pebble's random validation delay, and a positive value caps pebble's randomly chosen delay in seconds. Validation itself always runs. The waiting goroutines of pebble validation workers that expose no API remain for the process lifetime. HTTP and DNS listeners opened by the tool close at exit.

`setCertDomains` **replaces the entire list** rather than adding to the automatic FQDN. `[]` removes even the automatic FQDN and turns off HTTPS. Without `nodeKey`, it applies to current and future nodes and clears existing per-node overrides. With it, only that registered node changes. Domains are lowercase ASCII DNS names without a trailing dot. Each label is 1…63 characters, and the name with `_acme-challenge.` prepended is at most 253 characters. `setDNSConfig` changes only `DNSConfig.Proxied` for every node. Changed settings and existing peer and endpoint changes are compared every 50ms and included in the next map. To ensure a reconnect after raw map injection still receives a first map, the full map is sent again every 1 second even if unchanged. The response does not guarantee map receipt, so wait for Swift's fact stream or Go status to change. Nodes given a manual map with the existing `injectMapResponse` stay excluded from these updates (the existing automatic map suppression convention).

`set-dns` uses the existing testcontrol Noise handler. The tool records the original request and checks the configured certificate domain in `MaybeRejectRequest`. To accept custom domains too, it changes the internal request name to the automatic FQDN that testcontrol knows and stores the original request in an internal value. Once the request passes testcontrol's checks for TXT, empty fields, node key, and **machine ownership**, `OnSetDNS` restores the original request and publishes the TXT record to challtestsrv. It replaces any prior TXT record of the same name. `setDNSLog` keeps only the **original** name, type, and value of requests decoded as JSON, including faults and domain rejections, in receipt order. It emits only the `ShortString` summary of the public node key. Invalid JSON is not logged. The time is actual UTC RFC3339Nano. The list accumulates, and an empty list is `[]`. Record deletion and production DNS propagation are outside these tests.

`setDNSFault` applies **one** of the following to the next `count` decodable `set-dns` requests. A new command replaces the remaining fault settings. To clear them, use `count:0` and omit the fault field.

- `status` responds with a final HTTP status from 200…599 (for example, 403 rejection or an unusual success status such as 201).
- `delayMs` waits 1…3600000ms and then processes the request normally. Request cancellation or tool exit ends the wait.
- `body` takes `large` (an object with 8192 characters of padding), `null`, `array` (`[]`), `scalar` (`"test"`), or `empty` (a whitespace body). It responds with 200 and publishes no TXT record. The testcontrol hook responds with `http.Error`, so it uses `Content-Type:text/plain` and a trailing newline. Swift's object and 4KiB checks are verified against the body. Go accepts `null` and the large object.
- `wrongTXT:true` responds normally but publishes `swiftail-invalid-txt` in DNS. The log value is the original request value.

`peerWhoIs.nodeName` is Go's `Node.Name` with the trailing dot removed. The response's `name` is the Go peer that made the query. `computedName` is the value Go actually computed, and the login name is Go's `UserProfile.LoginName`. A lookup failure is an `error` event.

`peerHTTP.headers` has the form `{"Authorization":["Bearer <test token>"],"Content-Type":["application/octet-stream"]}`. `send` is 0…4294967296 and `seed` spans the full UInt64 range. The tool streams the M6 LCG64 byte sequence as is. If both are omitted, there is no body. `range` sets the `Range` header and takes precedence over same-named `headers`. Response header values are also always arrays, and the body is neither stored nor printed. SHA-256 and length are based on the response bytes actually read (after Go HTTP transfer decoding, with content encoding intact). `elapsedMs` covers the connection, TLS, and the entire response body. `timeoutSec` uses the same 15-second default and 1…3600 range as M6. Large requests and responses also use 32KiB buffers without accumulating the whole body in memory.

If HTTPS `rootPEM` is omitted, only the root created by `acmeStart` is used. If supplied, only that PEM anchor is used. System roots and disabled verification are unavailable. The TLS server name is the URL's host, and overriding the address with `to` leaves name verification in place. If the URL host is a registered node's FQDN or IP, the tool connects to that tailnet address. For an arbitrary certificate domain, specify a registered node address such as `to:"100.64.0.1"`. This connection does not query OS DNS. IPv6 is also supported. Each request uses an independent connection. TLS failures, deadlines, and truncated responses produce an `error` event that exposes neither the body nor the URL. A 4xx or 5xx HTTP response itself returns the status and hash in a success event.

Gate sequence (domains and addresses are examples. Get the actual values from the run's `nodes` and map):

```json
{"id":1,"cmd":"acmeStart","nonceReject":25,"authzReuse":100}
{"id":2,"cmd":"addPeer","name":"go-peer-a"}
{"id":3,"cmd":"addPeer","name":"go-peer-b"}
{"id":4,"cmd":"peerWhoIs","name":"go-peer-a","to":"100.64.0.2"}
{"id":5,"cmd":"setDNSLog"}
{"id":6,"cmd":"peerHTTP","name":"go-peer-a","url":"https://rd-mac-1a2b3c4d.tail0001.test/pair","method":"POST","send":32,"seed":1}
{"id":7,"cmd":"peerHTTP","name":"go-peer-a","url":"https://rd-mac-1a2b3c4d.tail0001.test/ipa","range":"bytes=0-52428799","timeoutSec":60}
{"id":8,"cmd":"peerHTTP","name":"go-peer-a","url":"https://rd-mac-1a2b3c4d.tail0001.test/ipa","range":"bytes=52428800-104857599","timeoutSec":60}
{"id":9,"cmd":"setCertDomains","domains":[]}
{"id":10,"cmd":"setCertDomains","domains":["rd-mac-1a2b3c4d.tail0001.test"]}
{"id":11,"cmd":"setDNSConfig","enabled":false}
{"id":12,"cmd":"setDNSConfig","enabled":true}
{"id":13,"cmd":"setDNSFault","count":1,"status":403}
{"id":14,"cmd":"setDNSFault","count":1,"wrongTXT":true}
{"id":15,"cmd":"goState","name":"go-peer-a"}
{"id":16,"cmd":"peerClose","name":"go-peer-a","stop":true}
{"id":17,"cmd":"goState","name":"go-peer-a"}
```

After 1, connect the Swift node to `ready.controlURL` and give the returned directory and root to the test issuer. After issuance, compare the TXT value from 5. Use the Swift test's node, clock, and storage to trigger restart, renewal, and reuse. During 6~8, wait for each prior request to finish and put the server-provided session and token in subsequent headers. To observe removal during a transfer, send `removePeer` before `peerHTTP` completes. The existing `removePeer` does not clear the testcontrol node list. To observe **peer removal from the netmap**, separately inject `PeersRemoved` into the Swift node with `injectMapResponse` (get the required NodeID from the test map). The tool does not check Swift's origin table, TLS listener, file permissions, or renewal clock on Swift's behalf.

To import state, **get the path in 15 → wait for the response to 16 → confirm `stopped:true` in 17**, then read or copy `tailscaled.state` and `certs/`. The existing `peerClose(name,port)` closes only the listener and must not be used for this purpose. The stopped node's directory is deleted by `removePeer`, `quit`, or EOF. Do not send any of these until you finish reading. The Go certificate cache is not created automatically. The test prepares it if needed.

Temporary files for builds, runs, and Go regression tests also go under the dedicated eyebuild directory. Apart from `go mod download`, the only network activity is loopback and local tailnet testing.

```sh
check_dir="$(eyebuild dir m7-tailnet-tool)"
mkdir -p "$check_dir/tmp"
export TMPDIR="$check_dir/tmp"
export GOCACHE="$(eyebuild dir interop-tools)/gocache"
export GOMODCACHE="$(eyebuild dir ref-src)/gomod"
export GOFLAGS=-modcacherw
(cd Tools/interop && go mod download)
export GOPROXY=off GOSUMDB=off
(cd Tools/interop && go test -count=1 ./...)
# If you need to run it, use the same environment:
# tailnet_tool="$(sh Scripts/build-interop-tools.sh tailnet)"
# "$tailnet_tool"
eyebuild rm m7-tailnet-tool
```

`TestHostTools` verifies command validation, actual Noise `SetDNS`, response faults, issuance failure with incorrect TXT, DNS-01 issuance and chain/name validation with an independent Go ACME client, authorization reuse, HTTPS Range and a 100MiB upload, HTTP, state preservation, and reconnection with the same Go identity. `TestPeerHTTPConcurrentRemove` verifies that an actual Go peer can be removed while an HTTP request is pending in a JSON session. Swift gates, real devices, and production servers are outside the scope of these Go tests.

## Tailnet Lock gate commands

This simulates a tailnet with lock enabled without an account (`docs/contracts/SwiftailTailnetLock.md` §7 "Gate (a)", decision L15). Go peers (tsnet) act as signing devices, and the testcontrol copy handles the server side. Existing commands and JSON formats remain the same.

### testcontrol copy

`tailnet` uses `internal/testcontrol/` in place of the upstream package. `doc.go`, `testcontrol.go`, `testcontrol_test.go`, and `capability_default_test.go` were copied from `tstest/integration/testcontrol/` in `tailscale.com` v1.104.6 (the version built by `go.mod`. This directory is identical in v1.104.7). Each file retains the original BSD-3-Clause header and an origin line. The module's `LICENSE` is in the same directory. Other tools, such as `h2server`, still use the original package.

Omitted files are `reco-experiment.go`, `capability_reco_test.go`, and `reco.md` (the alternate implementation under the `experiment.reco` build tag). Consequently, `//go:build !experiment.reco` was removed from `testcontrol.go` and `capability_default_test.go`. In `testcontrol_test.go`, only the import path was changed to the copy. Immediately after copying, before adding anything, `go test ./internal/testcontrol ./cmd/tailnet` passed as a baseline.

Differences from the original (the code has "Addition absent from the original" or "Differs from the original" comments. The main additions are in `internal/testcontrol/tka.go`. The logout addition (`Expiry`) is in `logout.go` and listed in the table under "Logout gate commands"):

| Location | Difference | Basis |
| --- | --- | --- |
| `/machine/tka/sync/send` | Adds a handler. It uses `tkatest.HandleTKASyncSend` to verify and ingest received AUMs (`Inform`) and returns the server head. When the head changes, it sends a new map to every node. Returns 400 if there is no lock. The original has no handler and the process panics | `HandleTKASyncSend` in `tstest/tkatest/tkatest.go`, `TestTKASync` in `ipn/ipnlocal/tailnet-lock_test.go` |
| `/machine/tka/disable` | Adds a handler. If `Version` is `CurrentCapabilityVersion` and the secret passes the server state's `ValidDisablement`, it clears the server's lock state and remembers the secret. Otherwise it returns 400. It does not check that heads match | Request shape from `tkaDoDisablement` in `ipn/ipnlocal/tailnet-lock.go` and `TestTKADisable`. What the server checks is **conjecture** |
| `/machine/tka/bootstrap` | After disablement it returns `DisablementSecret` (the remembered secret, or `0x42`×32 with `wrongSecret`). If `setLockBootstrapFault` is enabled, it truncates the last byte of `GenesisAUM`. Invalid requests (a different `Version`, for example) return only 400 without panicking | Fake server in `TestTKADisablementFlow` |
| `/machine/tka/sync/offer` | Returns 400 if there is no lock (the original panics while opening a nil store). It does not panic on failures such as no intersection, because a Go node that receives the wrong disablement secret continues syncing even after the server disables lock | `ipn/ipnlocal/tailnet-lock.go:399-418` |
| `/machine/tka/sign` | Does not panic on failed verification or an unregistered node key (for the latter, it has already written 200, so it only discards the signature) | — |
| `init/begin` and `init/finish` | begin clears the disabled state. After finish, it sends a new map to every node (the original waits for the next map request) | — |
| Map response | When `setLockCapability` is enabled, the self node's `CapMap` includes `https://tailscale.com/cap/tailnet-lock` (`[]`). After disablement it includes `TKAInfo{Disabled: true}`, unless `omitTKAInfo` is set | The original can include this only in registration `Capabilities` via `DefaultNodeCapabilities`, and map response `CapMap` is overwritten with the value from `SetNodeCapMap`. What the production server sends after disablement is **conjecture** |
| Registration | Verifies the requested `NodeKeySignature` via the server state's `NodeKeyAuthorized` and sets it as the node's `KeySignature` if valid. On failure it still registers the node and omits the signature. When a node key selected by `lockRequestResign` next registers without `OldNodeKey`, the response includes the current signature in `NodeKeySignature` to request re-signing. When a re-signed key change is accepted, it immediately deletes the old key's entry (the original deletes it only after completing the auth URL, leaving two entries with the same node ID on an unauthenticated change) | Client side at `control/controlclient/direct.go:534-545` and `:704-747`. The handling of signature failure, when to request re-signing, and how to handle the old key are **conjecture** |
| Recording | Accumulates `/machine/tka/` requests (path, `NodeKey`, `Head`) and registration requests (signature verdict, decrypted body) | — |

The `tkatest` offer and send handlers use Go `log` to write received requests and responses (public node keys, AUM bytes) to standard error. They are left enabled because this is the original package. They contain no secrets. Update the copy when upgrading the upstream version.

### Commands

Every response contains the original `id`, and failures are `error` events. `name` is the Go peer that performs the command. Text forms are `nodekey:<hex>` for node keys, `tlpub:<hex>` for lock keys (input also accepts `nlpub:`), and the AUM hash in base32 (52 characters) for heads.

| Command | Input (besides `id` and `cmd`) | Success response (besides `id`) |
| --- | --- | --- |
| `setLockCapability` | `enabled` bool | `{"event":"lockCapability","enabled":true}`. Can be changed at any time and sends a new map to every node |
| `lockInit` | `name`, optional `signers` (Go peer names to add as trusted keys, default `[name]`) | `{"event":"lockInit",…}` with the same fields as `lockStatus`. Creates one disablement secret and holds it only inside the tool. All nodes registered at that point receive `name`'s signature (no rotation key). Responds after `signers` reach the server head |
| `lockStatus` | `name` | `{"event":"lockStatus","name":"go-peer-a","enabled":true,"head":"<base32>","nodeKey":"nodekey:…","lockKey":"tlpub:…","nodeKeySigned":true,"trustedKeys":["tlpub:…"],"visiblePeers":["nodekey:…"],"filteredPeers":["nodekey:…"],"controlHead":"<server head, or \"\" if absent>","controlDisabled":false}`. Mirrors Go's `TailnetLockStatus`. `nodeKeySigned:false` means the node itself is locked. For peers with lock disabled, `visiblePeers` and `filteredPeers` are empty, so use `peerStatus` to see visible peers |
| `lockSign` | `name`, `nodeKey`, optional `lockKey` (rotation key) | `{"event":"lockSign","name":"go-peer-a","nodeKey":"nodekey:…"}`. Pass the Swift node's two `signingRequest` values as is. Supply `lockKey` so that node can later re-sign itself |
| `lockWrapAuthKey` | `name`, optional `authKey` (defaults to the `setAuth` key) | `{"event":"lockWrapAuthKey","name":"go-peer-a","authKey":"<auth key>--TL<credential>-<private key>"}`. Like `tailscale lock sign <auth key>`, it creates a new credential-only lock key, wraps the auth key, and adds the new key as trusted (the chain grows by one). The response key is **a test-only value containing a private key**, so keep it out of logs. You can also use it as `authKey` in `addPeer` to register a Go peer |
| `lockModify` | `name`, `addKeys` and `removeKeys` (arrays of `tlpub:` values, at least one) | `{"event":"lockModify",…}` with the same fields as `lockStatus`. Adds and removes keys with 1 vote. Responds after `name` reaches the server head (so the next command does not fork from a stale head) |
| `lockDisable` | `name`, optional `wrongSecret` and `omitTKAInfo` bools | `{"event":"lockDisable","name":"go-peer-a","wrongSecret":false,"omitTKAInfo":false,"alreadyDisabled":false}`. First configures the secret the server will return and the shape of the map. Then `name` disables lock using the `lockInit` secret. With `wrongSecret`, bootstrap returns the wrong secret and nodes keep lock enabled. If the server has already disabled it (`alreadyDisabled:true`), the command just changes those two settings and sends a new map without a peer RPC. Calling it again after `wrongSecret` thus gives nodes the right secret |
| `setLockBootstrapFault` | `enabled` bool | `{"event":"lockBootstrapFault","enabled":true}`. While enabled, bootstrap's `GenesisAUM` is corrupted. A change sends a new map (Go retries only on receipt of a netmap) |
| `lockRequestResign` | `nodeKey` (a signed registered node) | `{"event":"lockRequestResign","nodeKey":"nodekey:…"}`. Includes a re-signing request in that node's next registration response only |
| `lockRegistrations` | None | `{"event":"lockRegistrations","registrations":[{"nodeKey":"nodekey:…","oldNodeKey":"","nlKey":"tlpub:…","auth":false,"expiry":"0001-01-01T00:00:00Z","expiryUnix":0,"signature":"accepted","signatureError":"","resignRequested":false,"wrappedKeyTrace":false}]}`. In receipt order. All registrations unrelated to Tailnet Lock (including logout) also accumulate. `auth` indicates whether the request included `Auth`, `expiry` is the request JSON's `Expiry` string (as it appeared on the wire), and `expiryUnix` is the corresponding Unix seconds (0 for the zero time). A zero `nlKey` becomes `""`. `signature` is `none`, `noLock`, `accepted`, or `rejected` (Go's `NodeKeyAuthorized` verdict). `wrappedKeyTrace` indicates whether any request JSON string value contains `--TL` or a private key or seed wrapped by this tool (three base64 forms and hex). The credential is not checked because it is a public value always included in the signature's `Nested` |
| `lockRequests` | None | `{"event":"lockRequests","requests":[{"path":"/machine/tka/bootstrap","nodeKey":"nodekey:…","head":""}]}`. All received `/machine/tka/` requests. Use this to check for absence of bootstrap after restarting and absence of TKA requests on a tailnet without lock |

`addPeer` accepts an optional `authKey` (if absent, it uses the `setAuth` key as before).

`TKAInfo` after disablement defaults to `{"Disabled":true}`, so connected nodes enter the disablement flow immediately. With `omitTKAInfo`, `TKAInfo` is absent. Go and contract behavior O1 treat missing `TKAInfo` during a map session as "no change," so only nodes that reconnect the map stream enter the disablement flow. Sessions that already received `Disabled:true` retain that value.

Re-signing works as follows. After signing a node with `lockSign` and `lockKey`, set `lockRequestResign` for it. When the node registers again (Go registers on restart), it creates a new node key and registers again with `OldNodeKey` and a re-signed `NodeKeySignature`. On acceptance, the server deletes the old key's entry. The old key thus disappears from other peers' netmaps because the server deleted it, rather than because the Go client's stale-key filter (`rotationTracker`) removed it.

Go peer flow (the Go baseline for gate (a)):

```json
{"id":1,"cmd":"setLockCapability","enabled":true}
{"id":2,"cmd":"addPeer","name":"go-peer-a"}
{"id":3,"cmd":"lockInit","name":"go-peer-a"}
{"id":4,"cmd":"addPeer","name":"go-peer-c"}
{"id":5,"cmd":"lockStatus","name":"go-peer-a"}
{"id":6,"cmd":"lockSign","name":"go-peer-a","nodeKey":"nodekey:<c>","lockKey":"tlpub:<c>"}
{"id":7,"cmd":"lockWrapAuthKey","name":"go-peer-a"}
{"id":8,"cmd":"lockModify","name":"go-peer-a","addKeys":["tlpub:<b>"]}
{"id":9,"cmd":"lockDisable","name":"go-peer-a","wrongSecret":true}
{"id":10,"cmd":"lockDisable","name":"go-peer-a"}
```

`TestTailnetLock` (`cmd/tailnet/lock_test.go`) runs this flow with only Go peers. It covers enabling lock and signing peers that already exist, unsigned peers disappearing from other peers' netmaps and becoming locked, appearing after signing, a peer registered with a signed auth key being visible from the start with an `accepted` registration signature and no trace, a late peer catching up to the head through `sync/offer` and `sync/send` after bootstrap, adding a key and losing the peer signed by that other signing device after removing its key, switching to a new key after a re-signing request, failing to enable lock after a corrupted bootstrap and enabling it after restoring bootstrap, retaining lock with the wrong disablement secret, disabling lock everywhere with the correct secret and seeing unsigned peers again, and the map response shape after disablement. Swift nodes are outside this test's scope (`Tests/SwiftailInteropTests/TailnetLockTests.swift`).

## Logout gate commands

Used by the "Logout" interop test in `docs/contracts/SwiftailHost.md`. The addition to the testcontrol copy is `internal/testcontrol/logout.go` (table below).

| Location | Difference | Basis |
| --- | --- | --- |
| Registration | A nonzero request `Expiry` earlier than now is treated as logout. It sets the node's `KeyExpiry` for that node key to the requested value and sends a new map to all nodes. The response's `NodeKeyExpired` is true because the original check uses that `KeyExpiry` (if the request has `OldNodeKey`, it skips the original check and the value is false). The node is retained. On an unknown node key, the node just created by the original code expires immediately. Future `Expiry` (`SetExpirySooner`) is not handled. The original does not read `Expiry` | The `RegisterRequest.Expiry` comment in `tailcfg/tailcfg.go` and `doLogin` (`loginOpt.Logout`) in `control/controlclient/direct.go`. The response shape and retaining the node are **conjecture** |

| Command | Input (besides `id` and `cmd`) | Success response (besides `id`) |
| --- | --- | --- |
| `peerLogout` | `name` | `{"event":"peerLogout","name":"go-peer-b","backendState":"NeedsLogin"}`. The Go peer calls LocalAPI `Logout` (the same path as `tailscale logout`). The response is the `BackendState` after logout completes |

The Go peer's logout request carries `time.Unix(123, 0)` in `Expiry`. Go's `time.Unix` uses local time, so the wire representation follows the process's time zone (for example, `1970-01-01T09:02:03+09:00`). Compare `expiryUnix` to determine whether the times are equal.

`TestPeerLogout` (`cmd/tailnet/logout_test.go`) uses only Go peers to check that the logout request has Unix second 123 in `Expiry` and retains the node key, the server has the corresponding `keyExpiry` for that node, the node remains in another peer's netmap with a changed `keyExpiry`, and restarting with the same state directory (Go deleted the profile on logout) creates a new node with a new node key. The Swift counterpart is `Tests/SwiftailInteropTests/LogoutTests.swift`.

## DERP certificate pinning (M8 ③)

`setDERPCertificate` is accepted only before the first control request (`{"id":1,"cmd":"setDERPCertificate","mode":"pinned"}`). It replaces the DERP server certificate with the self-signed certificate that derper's manual certificate mode creates for an IP hostname (same shape as `createSelfSignedIPCert` in `cmd/derper/cert.go`: P-256, CN and IP SAN `127.0.0.1`, server authentication EKU, 1 year from now) and appends the meta certificate with `derpserver.ModifyTLSConfigToAddMetaCert` as derper does. The DERPMap node gets `InsecureForTests: false` and `CertName: "sha256-raw:<lowercase hexadecimal SHA-256 of the server certificate DER>"`. `mode` of `wrongPin` advertises the hash of the meta certificate that the server also presents (no client can connect). `leafNotFirst` is a chain that impersonates the server without the pinned certificate's key. It presents a newly keyed certificate with CN `derpkey00` first, followed by the pinned certificate (`presented` 2. The Go client accepts it. Swiftail rejects it). `named` leaves the certificate in place (httptest's default self-signed certificate) and only sets the node's `CertName` to `derp-cert.example.test` (`InsecureForTests` stays true. `CertName` verification takes precedence, so it cannot connect). `dottedHostName` leaves the certificate in place and sets the node's `HostName` to `localhost.` (checks whether SNI arrives as `localhost`). The response is `{"id":1,"event":"derpCertificate","mode":"pinned","certName":"sha256-raw:…","presented":2}`, where `presented` is the number of certificates the server presents. Go peers also use the same DERPMap and undergo `tlsdial.SetConfigExpectedCertHash` verification.

The server selects its certificate with `tls.Config.GetConfigForClient`. `GetCertificate` is not called when `Certificates` is populated and there is no SNI (Go `crypto/tls` `Config.getCertificate`). httptest populates `Certificates` with the default certificate, so this would miss IP-based clients. Outside pinned mode, the callback returns nil so httptest's default certificate is used as is.

`tailnet certificate-fixtures` writes the fixed certificates from `Tests/SwiftailIOTests/ServerCertificateFixtures.swift` to standard output as JSON (name → base64 DER, plus `ipLeafSHA256`, `dnsLeafSHA256`, and `metaSHA256`). It also writes the four independent review certificates (`reviewFixtures`: 10-year certificate, no EKU, Ed25519 key, and `derpkey00` with a VisibleString CN) and their hashes (`Tests/SwiftailIOTests/ServerCertificateReviewTests.swift`). The self-signed certificates have the same shape as above with dates fixed to 2026-01-01 ..< 2027-01-01 (IP `100.64.0.1`, DNS name `derp1a.example.test`, and one other key of the same shape). It adds the test root, the `derp-cert.example.test` certificate it issued, and the actual `derpserver.Server.MetaCert()`. Keys and signatures are random, so the bytes differ each run.

```sh
cd Tools/interop
GOCACHE="$(eyebuild dir interop-tools)/gocache" GOMODCACHE="$(eyebuild dir ref-src)/gomod" GOFLAGS=-modcacherw go run ./cmd/tailnet certificate-fixtures
```

# h2server

Build with `sh Scripts/build-interop-tools.sh h2server`. It accepts prior knowledge HTTP/2 without TLS or HTTP/1 upgrade on an arbitrary port at `127.0.0.1`. Readiness is one line, `{"event":"ready","port":12345}`. It uses `Server.ServeConn` from `golang.org/x/net/http2` v0.60.0 with defaults. In Go 1.27.3 this delegates to the standard library HTTP/2 server. `ConfigureServer` hooks up the graceful GOAWAY path of `http.Server.Shutdown` (the same frame implementation as testcontrol's ServeConn).

| Request | Response |
| --- | --- |
| `GET /small` | 200, `ok` |
| `POST /echo` | 200 with the unchanged request body. Maximum 8MiB, or 413 if exceeded |
| `GET /bytes?size=N` | 200, N bytes. The zero-based ith byte is `i % 251`. N is 0…8MiB |
| `GET /stream?count=N&intervalMs=M` | 200, waits M milliseconds and flushes `0\n`, `1\n`, … individually. If N=0, continues until canceled. N is 0…1,000,000 and M is 0…60,000 |
| `GET /headers?count=N&size=S` | 200, `x-test-0`…`x-test-(N-1)`. Each value is an S-byte string whose jth character is `a + j % 26`. N≤1024, S≤64KiB, `N*(S+64)`≤1MiB |
| `GET /status?code=N` | Final status N (200…599), empty body |

Negative, missing, and out-of-range numbers return 400, other methods return 405, and other paths return 404. It does not generate a Date header. `/stream` flushes the response headers first, so another request can go out even before the first line. Large `/headers` responses exercise CONTINUATION and Huffman decoding. A test that reuses the dynamic table calls `/headers?count=4&size=20` twice on the same connection. A large header set cannot fit in the 4096-byte dynamic table, so do not expect every field to be re-indexed in that case.

Standard input consists of JSON lines. `{"cmd":"goaway"}` closes the listener and sends GOAWAY with graceful Shutdown to reject new streams. Existing streams continue. `{"cmd":"quit"}` or EOF closes all connections. An invalid command produces one line, `{"event":"error","message":"…"}`. Standard output contains only JSON lines, and logs go to standard error. The server keeps its default settings, so there is no command to force a server-initiated PING.

# Generate HPACK fixtures

Run the following commands from the repository root. They use the reference modules and toolchain already downloaded without accessing the external network.

```sh
export GOCACHE="$(eyebuild dir interop-tools)/gocache"
export GOMODCACHE="$(eyebuild dir ref-src)/gomod"
export GOFLAGS=-modcacherw GOPROXY=off GOSUMDB=off
(cd Tools/interop && go run ./cmd/h2server -hpack-fixtures ../../Tests/SwiftailHTTP2Tests/Fixtures/hpack.json)
```

`hpack.json` is an array of connections. A connection's `name` is its description, and `blocks` is its ordered array of header blocks. A block's `hex` is the lowercase hexadecimal string of HPACK bytes, and `headers` is the expected header array. Each header has `name`, `value`, and `sensitive`. Create a new decoder per connection and retain the dynamic table between blocks on that connection. The decoder's maximum allowed dynamic table size is 4096.

Go's `golang.org/x/net/http2/hpack.Encoder` chooses Huffman coding and the representation. The 2 connections and 10 blocks cover static indexing, dynamic insertion, re-indexing, eviction, table size updates 4096→128→0→4096 and 0→512 in one block, an empty value, a 4096-byte value, and never indexed with `Sensitive=true`. All generated blocks are decoded again with the Go Decoder for verification.

# mapfixtures

This feeds map responses in order to Go's actual `mapSession` and produces normalized state and request JSON. It does not read or call the Swift implementation. Build with `sh Scripts/build-interop-tools.sh mapfixtures` and run with `Tools/interop` as the working directory. Run from the repository root after setting the environment variables above.

```sh
(cd Tools/interop && go run ./cmd/mapfixtures ../../Tests/SwiftailControlTests/Fixtures)
```

It locates `tailscale.com` v1.104.6 with `go list -m` and temporarily copies it under `eyebuild dir interop-tools`. The copy is necessary because Go rejects overlays inside GOMODCACHE and embed rejects symlinks. The local replace in a temporary `-modfile` points to that copy, and `-overlay` adds only `control/controlclient/swiftail_fixtures.go`. The added file calls `newMapSession` and `HandleNonKeepAliveMapResponse` and receives the actual netmap in `NetmapUpdater.UpdateFullNetmap`. It leaves the delta updater unimplemented to use Go's full netmap output path. It does not reimplement application logic. It skips only `KeepAlive` before entering mapSession, like upstream `direct.go`. The module cache is left untouched, and the temporary copy, overlay, and modfile are removed on exit.

The package and session clocks used for `PeerSeenChange=true` are fixed at `2026-01-02T03:04:05.123456789Z`. Public keys are derived using `SHA-256("swiftail-fixtures/node/<number>")` or `.../disco/<number>` as X25519 private input. NLKey uses `SHA-256("swiftail-fixtures/lock")` as the Ed25519 seed. These are public test seeds, not production keys. The fixtures contain no current time, randomness, or real tailnet.

`map-sessions.json` is an array of scenarios. Each has a `name` and `steps`, and each step has a descriptive `name`, a raw string `response`, and a normalized object or null `netmap`. The value of `response` is decoded as JSON once more and passed to Go. The raw input is not re-encoded as a tailcfg type, preserving omitted keys, `null`, `[]`, and `{}`. If the step's normalized state equals the previous state, `netmap` is null (this does not indicate whether a Go callback occurred). Each scenario starts with a new session.

The normalized netmap always has the keys below. Object key order is immaterial. Compare 64-bit IDs without converting through floating point.

| Key | Format |
| --- | --- |
| `SelfNode` | Node projection object below |
| `Peers` | Array of Node projections sorted by numeric ID in ascending order. Empty is `[]` |
| `DERPMap` | Null or the Go `tailcfg.DERPMap` JSON. `Regions` maps decimal ID strings to region objects, with the `Nodes` of each region in Go order. `omitDefaultRegions` begins with lowercase and is omitted if false. `HomeParams.RegionScore` is omitted if empty |
| `DNSConfig` | Go `tailcfg.DNSConfig` JSON object. The initial zero object is also emitted. A nil DNSConfig response preserves the previous object |
| `PacketFilter` | Array of applied `tailcfg.FilterRule` values concatenated in name order. Empty is `[]`. Each rule is the unchanged Go JSON |
| `UserProfiles` | Go `tailcfg.UserProfile` JSON objects by decimal UserID string, with only the profiles needed by the current self.User, peer.User, and peer.Sharer |
| `Domain` | String |
| `TKAEnabled` | bool |

A Node projection always emits `ID`, `StableID`, `Name`, `Key`, `DiscoKey`, `Addresses`, `AllowedIPs`, `Endpoints`, `HomeDERP`, `Online`, `LastSeen`, `KeyExpiry`, `Expired`, `Cap`, `CapMap`, `User`, `Sharer`, and `MachineAuthorized`. ID, User, Sharer, HomeDERP, and Cap are integers, StableID and Name are strings, and keys are `nodekey:`/`discokey:` plus 64 hex digits. Addresses and AllowedIPs are arrays of CIDR strings, and Endpoints is an array of IP:port strings. Nil in any of these three arrays is normalized to `[]`. Online is a bool or null, LastSeen is an RFC3339Nano string or null, KeyExpiry is an RFC3339Nano string (`0001-01-01T00:00:00Z` if zero), and Expired and MachineAuthorized are bools. Times preserve the offset retained by Go. CapMap is null or an object mapping capability strings to arrays of raw JSON values or null. It does not arbitrarily merge null and empty arrays. Other Node fields, the computed display name, and ControlTime are excluded from this projection.

`requests.json` is an array of cases. Each has `name`, `type` (`RegisterRequest` or `MapRequest`), `input` (a JSON object of explicitly populated values), and `json` (the raw Go `encoding/json.Marshal` string). Fields absent from input have the corresponding Go type's zero value. The same rule applies to nested objects. Compare decoded objects and field presence, not whitespace or key order in json. The zero RegisterRequest and MapRequest, auth key, Followup, OldNodeKey, Expiry, stream and state update, Hostinfo, and NetInfo cases expose `omitempty`/`omitzero` differences.

In `peer-full-empty-omitted` in particular, both an empty Peers array and omission preserve peers (full replacement requires `len(Peers)>0`). In `derp-replacement-and-preservation`, the Regions object is a full replacement, not a per-region patch, and nil regions are removed. Null Regions preserves both the previous Regions and omitDefaultRegions. In `packet-filters`, an empty PacketFilter clears only `base` and leaves other names. `"*":null` clears all names after applying PacketFilter from the same response. In `profiles-domain-tka`, the profile store accumulates but the output netmap contains only currently referenced users. In `peer-patches`, a past KeyExpiry alone does not make Expired true, and the patch applies after seen and online changes.

Full Go verification follows. Keep the `interop-tools` and `ref-src` directories.

```sh
(cd Tools/interop && go vet ./... && go test -count=1 ./...)
```

# filterfixtures

This runs the public `wgengine/filter` from `tailscale.com` v1.104.6 directly
to generate `Tests/SwiftailEngineTests/Fixtures/filter-verdicts.json`.
It does not read or run the Swift implementation. It uses the same cache environment as `mapfixtures`.
The filter functions are public, so no temporary copy or overlay is needed. It does not modify the Go module cache.
Build information confirms the reference version and the absence of a replace.

Run from the repository root. Keep `interop-tools` and `ref-src`.

```sh
export GOCACHE="$(eyebuild dir interop-tools)/gocache"
export GOMODCACHE="$(eyebuild dir ref-src)/gomod"
export GOFLAGS=-modcacherw GOPROXY=off GOSUMDB=off
sh Scripts/build-interop-tools.sh filterfixtures
(cd Tools/interop && go vet ./... && go run ./cmd/filterfixtures ../../Tests/SwiftailEngineTests/Fixtures)
```

Decode the scenario's **raw rule string** into Go `[tailcfg.FilterRule]` and
call `filter.MatchesFromFilterRules` → `filter.New`.
`localNets` includes only /32 and /128 prefixes for the node's own addresses. Use `logIPs=nil`, `logger.Discard`, and run flags of 0 to
disable logs. On an invalid address string, install the partial match list returned with the error.
Likewise, install the nil returned on `SrcBits` or `DstPorts.Bits` errors. Converting every conversion error to nil
does not match actual Go behavior (`wgengine/filter/tailcfg.go:30-118`).

For each packet, call `Decode` on a fresh `packet.Parsed`. For inbound packets, record the final Accept/Drop from `RunIn`.
For outbound packets, call `RunOut` to record the reverse flow and verify Accept.
Keep the filter within a scenario. On rule replacement, pass the previous filter to `filter.New` as `shareStateWith`.
Scenarios do not share state.
Run all scenarios once more with new filters and verify the entire JSON, including verdicts and conversion errors, is identical
before writing it. This uses no current time, randomness, or sockets.

The fixtures have top-level `reference` (reference module and version) and a `scenarios` array.

| Scenario key | Meaning |
| --- | --- |
| `name` | Korean scenario name. It is unique and distinguishes IPv4 and IPv6 |
| `rules` | Raw JSON **string** of the `tailcfg.FilterRule` array. Swift also decodes it directly as `[FilterRule]` |
| `localAddresses` | Array of strings for the node's own addresses, excluding prefixes and routes |
| `capabilitySources` | Optional. Installs a deterministic Go callback that grants the `fixture:test` capability only to these fake sources. If omitted, the callback is nil. Swift does not support this capability |
| `conversionError` | Optional. Error string Go returned during initial rule conversion. It does not replace verdicts |
| `steps` | Array of steps executed with the same filter state carried forward |

| Step key | Meaning |
| --- | --- |
| `name` | Description of the step |
| `direction` | `in` receives, `out` records send state, and `replace` replaces rules and the node's own addresses |
| `packet` | Lowercase hex preserving the entire IP packet for `in` and `out`, including invalid lengths, fragments, and other details mentioned in the name |
| `verdict` | `accept` or `drop` from the actual `RunIn` for `in`. Absent for `out` and `replace` |
| `rules`, `localAddresses` | Raw rules and the node's own addresses to apply in `replace`. Empty rules `"[]"` also count as replacement |
| `conversionError` | Optional. Actual Go conversion error in `replace` |
| `swiftailDiffers` | Optional. Why the M3 contract must be checked separately from the Go verdict. Marked even if values match when the intended processing boundary differs |
| `swiftailExpected` | Swift contract expectation accompanying a difference marker. See the table below |

| `swiftailExpected` | What the Swift test checks | Step count |
| --- | --- | --- |
| `fragment` | `IPPacket.ParseError.fragment` | 7 |
| `extensionHeader` | `IPPacket.ParseError.extensionHeader` | 8 |
| `malformed` | `IPPacket.ParseError.malformed` (IHL 4, UDP header outside the declared length) | 3 |
| `accept`, `drop` | `checkInbound` verdict after successful parsing. Removal of only the `cap:` entry, and differences for ICMPv4 types 12 and 18 | 12 |
| `trimmedAccept` | Checks both bytes trimmed to the declared length and an accept verdict | 2 |
| `tsmp` | Checks parsing as `.tsmp`. Engine consumption is outside this filter test's API scope | 2 |

There are **91 scenarios and 2,429 steps** in total (333 inbound, 2,058 outbound, 38 replacements),
with **34** difference markers. IPv4 and IPv6 each have the 43 common scenarios below.
Each row groups scenario names from the fixtures and creates the separately specified number of independent filters.

| Common scenario names and list | Count per family |
| --- | --- |
| All sources, CIDR, single address, and inclusive range | 4 |
| Protocol 6 port range, protocol 17 port range, all ports and reversed range | 3 |
| Default protocols with an empty array or null, TCP only, UDP only, ICMP only, other protocol 47 only, other protocol 254 only, out-of-range numbers only, and out-of-range numbers with UDP | 9 |
| Other protocols require all ports, explicit protocol number boundaries, special handling of SCTP protocol number 132, and IPProto omission | 4 |
| CIDR with host bits, unparseable address, and reversed address range, each as source and destination (invalid entry only or with a valid entry added) | 6 |
| SrcBits fails closed for all rules and DstPorts.Bits fails closed for all rules (including broad prior rules and replacement) | 2 |
| CapGrant alone does not open access, and TCP flags and stateless allow | 2 |
| Reverse UDP tuple, inbound allow does not create a flow, and rule replacement preserves flows | 3 |
| UDP LRU with 513 entries, lookup refresh=false or true | 2 |
| ICMP replies and errors are stateless, and ICMP ignores protocol and port | 2 |
| Destination checked against the node's own addresses, and multicast and link-local destinations (rejected even when registered as the node's own addresses) | 2 |
| A cap source only discards the entry, and TSMP is an engine control packet | 2 |
| Bytes beyond the declared length and transport header outside the declared length | 2 |

IPv4 adds scenarios for fragments (MF and offsets 1 and 10), minimum IHL, and the ICMPv4 type 18 address rule,
one each. IPv6 adds one scenario each for fragments (atomic, first fragment, offsets 1 and 10) and extension headers
(0, 43, 50, 51, 60, 135, 139, 140). This yields 46 IPv4 scenarios and 45 IPv6 scenarios.
The UDP tuple test includes inputs that differ only in destination among the node's own addresses so `notForUs` does not mask
the cache comparison. The LRU test separates inserting a 513th entry after 512 insertions from the case that looks up flow 0 just before
that insertion, distinguishing FIFO from refreshing order on lookup.

The results revealed the following **contract omissions**. These were not agreed as intentional M3 differences, so
they have no `swiftailDiffers` marker and the comparison test exposes the mismatch.

- Go rejects wire protocols 0 and 255 even with an explicit all-ports rule. 0 is Unknown, and
  the parser converts 255 to Unknown. The contract's 0…255 and "other protocols" wording has no such exception
  (`net/packet/packet.go:243-248`, `:359-364`). IPv6's 0 is already marked separately as an extension header difference.
- Go uses the same port checks and outbound reverse cache for SCTP (132) as for UDP. The contract does not define SCTP as a separate
  protocol and specifies that only UDP is recorded. Thus the contract alone cannot reproduce Go's accept verdicts for
  rules that open only some ports and replies without a rule
  (`wgengine/filter/filter.go:538-550`, `:600-612`, `:642-650`).

Both behaviors are already in notes 3.2, 4.5, and 4.6. No other new Go behavior differing from the notes was found.
Also, ICMP requests are accepted if an address rule remains even when all of `IPProto` is out of range.
This matches note 4.4, in which ICMP ignores protocol and ports.

The Swift comparison test depends only on `IPPacket(parsing:)`, `bytes`, `transportProtocol`, `ParseError`,
`PacketFilter(rules:localAddresses:)`, `checkInbound`, `recordOutbound`,
`replaceRules(_:localAddresses:)`, and `Verdict.accept` (no `@testable`).
It was written in a worktree without the implementation, so the test target was not compiled or run.
After merging, the lead session must verify that the contract signatures match the implementation.
Consumption of TSMP by `TailnetEngine.receive`, actual WireGuard, AllowedIPs, and DERP paths, and elapsed time
are outside this value-type filter comparison. The UDP cache has no TTL in either Go or the contract.

# controlfaults

A control server for `ControlClient` regression tests. Build with `sh Scripts/build-interop-tools.sh controlfaults` and run with `controlfaults <mode>`. It listens on an arbitrary port at `127.0.0.1` and writes the server URL (`http://127.0.0.1:12345`) as the first line of standard output. It exits when standard input closes (EOF). Logs go to standard error and omit request bodies and keys. The server generates a new key each run.

It handles `/key` and `/ts2021` (upgrade, Noise, HTTP/2) like a real control server using `tailscale.com/control/controlhttp/controlhttpserver` and `golang.org/x/net/http2`, varying only the `/machine/register` and `/machine/map` responses inside them by mode. It does not use testcontrol.

| Mode | Behavior |
| --- | --- |
| `basic` | Registration immediately returns `MachineAuthorized`. A state update (`Stream=false`) gets an empty 200. The map stream sends one self Node (`ID` 1, the request's NodeKey) and stays open |
| `initialUploadHang` | Same as `basic`, but does not answer state updates |
| `interactiveRace` | Holds the first registration request until `/release` arrives. Subsequent registrations are approved immediately |
| `followupReconnect` | A registration with empty Followup gets an `AuthURL` (`<server URL>/login/1`). The first Followup request breaks the stream (RST_STREAM). Approval starts with the second Followup |
| `followupHold` | A registration with empty Followup gets an `AuthURL` with that request's sequence number (`<server URL>/login/<sequence number>`). Holds a Followup request until `/release` arrives, then approves it |
| `sameAuthURL` | Immediately returns the same `AuthURL` (`<server URL>/login/1`) for all registrations, including Followup, until `/release`. Approves them thereafter |
| `expiryTimer` | The map stream sets the self Node's `KeyExpiry` to response time + 1 second |
| `alwaysExpired` | The map stream sets the self Node's `KeyExpiry` to response time − 1 hour |
| `authEcho` | Rejects registration with `Auth` using `{"Error":"invalid authkey: <received AuthKey>"}` |
| `manyMaps` | The first map stream sends the self Node response and 199 responses differing only in `Domain` (`d1`…`d199`), then ends. The next map stream sends only its header and stays open |

Plaintext HTTP paths:

- `GET /probe` returns counts so far. `{"connections":0,"registers":0,"followups":0,"maps":0,"nodeKeys":0}`. `connections` counts `/ts2021` connections, `maps` counts `/machine/map` requests for both streams and state updates, and `nodeKeys` counts distinct NodeKey values in registration requests (the keys themselves are omitted).
- `GET /release` releases the first registration held in `interactiveRace`. It can be called repeatedly.

Set `SWIFTAIL_CONTROLFAULTS` to the tool path to run the Swift tests. If unset, they are skipped.

```sh
SWIFTAIL_CONTROLFAULTS="$(sh Scripts/build-interop-tools.sh controlfaults)" eyebuild swift <purpose> -- test --filter ControlFaultsTests
```

# magicsockvectors

Generates fixed vectors for `SwiftailMagicsock` unit tests with the public packages from `tailscale.com` v1.104.6 (`disco`, `types/key`, `net/stun`) and `golang.org/x/crypto/nacl`, and writes them to `Tests/SwiftailMagicsockTests/Fixtures/magicsock-vectors.json`. It does not read or run the Swift implementation. The keys are public test values using `SHA-256("swiftail-vectors/disco/<number>")` (1, 2) as X25519 private key input. The nonce is determined by the message number. With no time, randomness, or production values, identical input produces byte-for-byte identical output. Build information confirms the reference version and absence of a replace.

Run from the repository root. Keep `interop-tools` and `ref-src`.

```sh
export GOCACHE="$(eyebuild dir interop-tools)/gocache"
export GOMODCACHE="$(eyebuild dir ref-src)/gomod"
export GOFLAGS=-modcacherw GOPROXY=off GOSUMDB=off
(cd Tools/interop && go vet ./... && go run ./cmd/magicsockvectors ../../Tests/SwiftailMagicsockTests/Fixtures/magicsock-vectors.json)
```

With no output file specified, it writes to standard output. The output contains the following.

- `keys` contains the `seed` (private key input) and `public` for test disco keys `a` and `b`.
- `disco.messages` contains `plaintext` (`AppendMarshal` bytes) for Ping (with and without NodeKey, and with padding), Pong (IPv4 and IPv6), and CallMeMaybe (0, 1, and 3 addresses), plus the full outer-format `packet` sealing the same plaintext with `box.Precompute` + `secretbox.Seal` (fixed `nonce`). Before writing, the tool reopens `packet` with `key.DiscoPrivate.Shared(...).Open` to check that it matches the plaintext and that `disco.Source` returns the sender's key. Go's `Seal` generates its nonce internally, so fixed-nonce sealing calls the same computation directly.
- `disco.parse` contains the results of passing boundary plaintexts (0 and 1 bytes, Ping at 11, 12, 13, 43, 44, and 45 bytes and with zero NodeKey, Pong at 29, 30, and 31 bytes, CallMeMaybe at 17, 18, 19, 35, and 36 bytes and with version 1, types 0x00, 0x04–0x09, 0x0a, and 0xff) to `disco.Parse`. A successful parse yields `result`, otherwise `error` is the Go error message. `kind: "relay"` denotes types (0x04–0x09) parsed by Go and unsupported by Swiftail.
- `stun.requests` contains the bytes from `stun.Request(txID)`.
- `stun.parse` contains the results of passing IPv4 and IPv6 responses from `stun.Response` and hand-modified responses (0x8020, MAPPED-ADDRESS only, SOFTWARE before the attribute, bytes beyond the declared length, and rejection cases) to `stun.ParseResponse`, and whether the same packet passes `looksLikeSTUN` (`stun.Is` and byte 1 equal to `0x01`).

# tsmpvectors

Generates the TSMP disco key advertisement vectors for `SwiftailEngine` unit tests with `packet.TSMPDiscoKeyAdvertisement.Marshal` and `Parsed.AsTSMPDiscoAdvertisement` from `tailscale.com` v1.104.6 and writes them to `Tests/SwiftailEngineTests/Fixtures/tsmp-vectors.json` (the code is identical in v1.104.7). The keys are public test values using `SHA-256("swiftail-vectors/tsmp/<number>")` (1, 2) as X25519 private key input, and the addresses are test tailnet addresses. With no time, randomness, or production values, identical input produces byte-for-byte identical output. The generated bytes are parsed again before writing to confirm the same addresses and keys. Build information confirms the reference version and absence of a replace.

```sh
export GOCACHE="$(eyebuild dir interop-tools)/gocache"
export GOMODCACHE="$(eyebuild dir ref-src)/gomod"
export GOFLAGS=-modcacherw GOPROXY=off GOSUMDB=off
(cd Tools/interop && go vet ./cmd/tsmpvectors && go run ./cmd/tsmpvectors ../../Tests/SwiftailEngineTests/Fixtures/tsmp-vectors.json)
```

The output contains `advertisements` (two IPv4 and one IPv6 advertisement, with `src`, `dst`, `key`, and `Marshal` bytes in `packet`) and `parse` (results from parsing IPv4 TSMP bodies of 33, 34, and 32 bytes, type `'p'`, zero key, IPv6 advertisement, IPv4 fragments (MF, offset 1, offset 10), and IPv6 first fragments (M 1 and 0) and later fragments with the fragment header using `Parsed.Decode` and `AsTSMPDiscoAdvertisement`. Non-advertisements have no `key`). `key` preserves Go's verdict. Go accepts both IPv6 first fragments, and Swiftail drops them. `TSMPVectorTests` checks these two separately as known differences.

# Generate MagicDNS reference fixtures (`dnsfixtures`)

Writes actual UDP response bytes from `tailscale.com v1.104.6` to `Tests/SwiftailEngineTests/Fixtures/magicdns-fixtures.json`. It does not change Swift files. The environment below is shared by both tools and the full Go verification. The reference modules must already have been fetched with `Scripts/fetch-reference-sources.sh`.

```sh
export GOCACHE="$(eyebuild dir interop-tools)/gocache"
export GOMODCACHE="$(eyebuild dir ref-src)/gomod"
export GOFLAGS=-modcacherw
export GOPROXY=off
export GOSUMDB=off
(cd Tools/interop && go run ./cmd/dnsfixtures ../../Tests/SwiftailEngineTests/Fixtures)
```

Use the same environment to run the executable built with `sh Scripts/build-interop-tools.sh dnsfixtures` as `dnsfixtures <Engine Fixtures directory>`. The argument is required and the filename is fixed.

The call path is `resolver.New` → `SetConfig(Hosts, LocalDomains)` → `SetMagicDNSHosts` → per-step `Query(context, query, "udp", 100.64.0.1:42001)` (`net/dns/resolver/tsdns.go`). It does not duplicate response generation, type selection, RCODE, SOA, EDNS, or TC logic. A fixed table stands in for the unexported `ipnlocal` node index as specified by the contract. `nodes[].addresses` are the original PTR addresses, `answerAddresses` are forward lookup addresses predetermined according to D7, and `aliases` are the FQDNs and short names to recognize. Nodes without addresses have no aliases. `subdomain` is also an explicit test table. These fixtures cannot establish the correctness of the index implementation itself.

To keep the current SOA time out of the fixtures, add a small bridge to a temporary module copy with `-overlay` as in `mapfixtures`, and set only the upstream test `timeNow` hook to `1767323045` (fixed Unix seconds). The response bytes are exactly what `Query` returns afterward. The module cache is read only, and the temporary module copy, bridge, worker, overlay, modfile, and sum are removed on success or failure. Temporary files are kept only under `interop-tools`.

The fixture header contains `reference`, `scenarioCount: 8`, `stepCount: 85`, `soaSerial: 1767323045`, and `scenarios`. Each scenario has `name`, `magicDNSSuffix` (including the trailing dot), `proxied`, `capabilities`, `nodes`, `localDomains`, `hosts`, and `steps`. `hosts` is the ExtraRecords table supplied as Go `Config.Hosts`.

Step keys:

| Key | Meaning |
| --- | --- |
| `name` | Purpose of the query |
| `query`, `response` | Lowercase hex of the entire UDP DNS message, without IP or UDP headers |
| `decoded.id`, `rcode`, `flags` | Response ID, numeric RCODE, and 16-bit header flags |
| `decoded.qr/aa/tc/rd/ra` | Frequently compared header bits. Compare Opcode, AD, CD, and others via `flags` |
| `decoded.questions` | Array of `name`, numeric `type`, and `class`. The response's first question or an empty array |
| `decoded.answers/authorities/additionals` | Arrays of `type`, `name`, `class`, `ttl`, and `value`. Names include the trailing dot |
| Record `value` | Address string for A and AAAA, FQDN for PTR, and an `ns/mbox/serial/refresh/retry/expire/minimum` object for SOA |
| `swiftailDiffers` | Contract reason for an intentional difference. If absent, compare the Go result as is |

The Swift comparison test can pass a fixed time and compare the entire hex, or exclude only the SOA SERIAL field per the contract. The wire format cannot distinguish a query name with or without a trailing dot. An input created without a trailing dot encodes as the same absolute DNS name. The question and record names in `decoded` preserve the actual case in Go's response. Empty lists are `[]`.

Scenarios:

1. Basic nodes and query formats (61 steps): A/AAAA/ANY for self, peer, IPv4-only, and IPv6-only, IPv4/IPv6/4to6/service PTR, variations in notation, unknown name and PTR, nodes without addresses, out-of-zone queries, onion and Bonjour, TXT/MX/NS/SOA/AXFR/HINFO/unknown types, service name, header bits, 0 and 2 questions, valid compression, loops, and more than 11 pointers, truncation, invalid labels and FQDN, and EDNS.
2. `magicdns-aaaa` capability present (3 steps).
3. Self is IPv6-only (4 steps).
4. MagicDNS disabled (3 steps).
5. ExtraRecords precedence and reverse lookup (3 steps).
6. Self key expired or no netmap (4 steps): empty table and zones, plus service name and PTR exceptions.
7. Large SOA response for a long local zone (4 steps): over 512, EDNS 1232 and 512, OPT with options. The tool checks that the response exceeds 512 bytes and checks the TC result.
8. 4via6 and subdomains excluded from M5 (3 steps).

`swiftailDiffers` marks **3 steps** in the final scenario: 2 omissions of 4via6 names and 1 omission of `dns-subdomain-resolve` (behavior D8 and exclusions). No upstream forwarding is configured, so out-of-zone queries get Go's "no route" SERVFAIL. It matches Swiftail and is unmarked.

Observed contract gap: behavior D7 says "all names return SERVFAIL" when the self key is expired or the netmap is absent, but Go still answers A for `magicdns.localhost-tailscale-daemon.` and the service IPv4 PTR with an empty index and empty `LocalDomains`. Neither step has an intentional difference marker. The service response is handled before the index (`resolveLocal`, `resolveLocalReverse`). This matches the notes' special handling rule for the service.

# Generate tunnel settings reference fixtures (`tunnelfixtures`)

Run in the same environment.

```sh
(cd Tools/interop && go run ./cmd/tunnelfixtures ../../Tests/SwiftailEngineTests/Fixtures)
# Or build with sh Scripts/build-interop-tools.sh tunnelfixtures, then run:
# tunnelfixtures <Engine Fixtures directory>
```

The output is `tunnel-settings-fixtures.json`. It preserves both the original Go results and the results narrowed to the form of contract S.

- Routes: Sort the result of public `routemanager.New` → `Begin` → `SetPrefs(RouteAll:false, no exit node)` → `SetTailnetConfig` → `UpsertPeer` → `Commit` → `OSRoutes().All()`. Interpret `one-cgnat?v=true/false` via `controlknobs.UpdateFromNodeAttributes`. Do not interpret unknown control directives directly.
- DNS, local addresses, and service routes: Create one Go node with an in-memory store and fake TUN engine as in upstream LocalBackend tests. Add an overlay bridge to `ipn/ipnlocal` in the temporary copy, supply a fixed netmap and prefs, and run the actual `LocalBackend.authReconfigLocked`. A capture type embedding `Engine` intercepts only `Reconfig` to receive `dns.Config` and `router.Config`. It does not copy the logic that computes the unexported `dnsConfigForNetmap` and `routerConfigLocked` results. It neither connects to a control server nor applies real OS settings.
- Compile the captured `dns.Config` via public `dns.NewManager(..., goos:"ios")` → `Set`. The `OSConfigurator` has `SupportsSplitDNS=true`. `GetBaseConfig` returns the fixed fake base resolver `192.0.2.54` and `SetDNS` only receives values. Get the actual `LocalDomains` from `Resolver.TestOnlySetHook`. The tool does not read host OS DNS even in primary mode, which requires a base resolver.
- Take `router.Config.LocalAddrs` and service routes as Go produces them. Check that the public RouteManager peer routes with service routes appended for each family present in the node's addresses match the full captured Go routes.
- Apply only the policies of S1, S4, S5, and D1 through D3 to `settings`: use `null` if the node has no addresses, exclude routes and DNS servers for a family with no local address, use only Go's `LocalDomains` as DNS matches, and omit search domains, global resolvers, and Routes with resolvers. The tool does not recompute local DNS zones. It also retains Go's values at expiration boundaries without an intentional difference marker.

The second tool also deletes its temporary copy, overlay, and modfile on exit and checks the reference module's version and whether it has a replace. It sets `TS_DEBUG_MAGIC_DNS_DUAL_STACK=false` at process startup so the external environment cannot override the IPv4-only directive. Log uploads and portmapper are disabled for the test node. The fixtures omit current time and generated identities and socket addresses.

The fixture header contains `reference`, `scenarioCount: 27`, `stepCount: 32`, `now: "2026-01-02T03:04:05Z"`, `baseResolvers`, and `scenarios`. Each scenario has `name` and `steps`. Each step is an independent full netmap input, not a delta to the previous step.

| Key | Meaning |
| --- | --- |
| `input.self`, `input.peers` | `id/name/addresses/allowedIPs/expired/keyExpiry/homeDERP`. Addresses are CIDR strings. There is no disco key, and the presence of a value in `homeDERP` determines candidacy. Test public keys are generated deterministically from IDs and omitted from output |
| `input.dnsConfig` | Control's `tailcfg.DNSConfig` JSON. Preserves Go's original capitalized keys (`Proxied`, `Routes`, `Resolvers`, `Domains`, `ExtraRecords`, and others) |
| `input.capMap` | Control capability map for the self node |
| `input.routeAll`, `exitNode` | Fixed `false` and empty string, respectively |
| `input.selfExpired` | Key expiration snapshot supplied to LocalBackend. The tool does not reassess expiration at run time |
| `input.mtu` | MTU to carry into the contract settings (1280) |
| `go.addresses` | Go `router.Config.LocalAddrs` |
| `go.peerRoutes`, `go.routes` | Sorted peer routes from the public RouteManager, and original routes with service routes appended by LocalBackend |
| `go.dns` | `servers/matchDomains/searchDomains` from iOS OSConfig and `localDomains` from the actual resolver. Domain strings omit the trailing dot |
| `go.dnsConfig` | Raw `dns.Config` received by the engine. Preserves Go struct keys and FQDNs with trailing dots. Keeps optional fields' original `null` |
| `settings` | Contract-shaped `addresses/routes/dnsServers/dnsMatchDomains/mtu`, or `null` if the node has no addresses |
| `swiftailDiffers` | Intentional difference under the contract that precludes direct comparison with the original Go settings |

The Swift comparison test creates a netmap from `input` and compares `settings`. For the **unmarked observed differences** below, first check whether the contract needs an amendment. Consult `go` to inspect the original Go results. Unlike Go `dnsConfig`'s `null`, empty normalized output lists are always `[]`, and IPv4 routes precede IPv6. Go's service routes follow the sorted peer routes in IPv4 then IPv6 order. Search domains omitted from `settings` are retained in `go.dns.searchDomains`.

Scenarios (OneCGNAT alone has 6 steps, and all others have 1 step each):

- IPv4-only, IPv6-only, and dual-stack × 0, 1, and 3 peers (9): self addresses, per-peer routes, family filters, service routes, MagicDNS, and search domains.
- IPv4 peer without search domains and /48 aggregation for one ULA peer (2).
- OneCGNAT threshold and control directive (1, 6 steps): absent, true, or false directive × 1 or 2 CGNAT peers. With true, 1 gives /32 and 2 gives /10. Check only the boundary at threshold 1, as the contract permits, instead of the default 10,000 boundary.
- Expired peer, past KeyExpiry with Expired false, peer without disco or DERP, and rejection of subnet and exit advertisements (4).
- MagicDNS disabled, no suffix, empty Routes, custom split DNS, global resolvers, and global resolvers only (6).
- Unshadowed ExtraRecords, user routes shadowing ExtraRecords, directive to register only IPv4 DNS, expired self key, and no self addresses (5).

`swiftailDiffers` marks **16 steps**. Counts by reason, including overlaps, are 10 for omitting search domains (D3), 5 for filtering by self address family (S4 and S5), 5 for narrowing primary DNS, global resolvers, and custom split DNS to local matches (D1 and D2), and 1 for omitting settings when there are no self addresses (S1). A step may have multiple reasons.

Observed differences and caveats:

- A peer with `Expired=false` and `KeyExpiry` earlier than the fixed `now` remains in both Go RouteManager and LocalBackend routes. RouteManager checks only `Expired` (`peerViewOf`). This differs from the time check in `EnginePeer.peers(in:at:)` referenced by contract S2. No contract defines it as intentional, so it is **unmarked**. The step's `settings` also retain the Go routes.
- If the self `Name` is empty, Go's `magicDNSRootDomains` omits even all reverse zones. Do not read the contract S5 summary as always adding 65 reverse zones based on `Proxied` alone. The function cited as the origin in the DNS notes checks the suffix.
- With MagicDNS off, no Routes, and no global resolver, there are no nameservers even with `MagicDNSHostsUnrouted=true` because `needsOSResolver` returns early. With one empty Routes entry, Go chooses primary mode because of the same flag. The flag description alone does not imply primary mode in all cases.

# Reproduction and regression verification for both fixture sets

Set the common environment variables above and run from the repository root. `go test` also compiles and runs the embedded workers and bridges for both new tools and compares the saved fixtures byte for byte. `dnsfixtures` also checks each query's RCODE and the length and TC of large responses.

```sh
(cd Tools/interop && go vet ./... && go test -count=1 ./...)
check_dir=$(mktemp -d "$(eyebuild dir interop-tools)/m5-fixture-check.XXXXXX")
(cd Tools/interop && go run ./cmd/dnsfixtures "$check_dir/first")
(cd Tools/interop && go run ./cmd/dnsfixtures "$check_dir/second")
(cd Tools/interop && go run ./cmd/tunnelfixtures "$check_dir/first")
(cd Tools/interop && go run ./cmd/tunnelfixtures "$check_dir/second")
cmp "$check_dir/first/magicdns-fixtures.json" "$check_dir/second/magicdns-fixtures.json"
cmp "$check_dir/first/tunnel-settings-fixtures.json" "$check_dir/second/tunnel-settings-fixtures.json"
rm -r "$check_dir"
eyebuild swift m5-fixtures -- build --build-tests 2>&1 | grep -E "warning|error"; echo build-done
eyebuild rm m5-fixtures
```

Real-device OS application, name queries against actual Go peers, and Swift comparison tests are outside this tool's verification scope. The node index rules are represented by a fixed table, so verify them in separate unit tests and M5 gate (a).

Observation commands for the M5 memory gate:

- `startCapture` (`name`) starts that Go peer's public `StreamDebugCapture`, reads the pcap header, and responds with `captureStarted`. It starts only once per peer and closes when the peer is removed or the tool exits.
- `captureStatus` (`name`, `port` 1…65535) returns the number of `FromPeer` packets destined for the two service IPs (`servicePackets`) and the number whose UDP source port is `port` (`observedPackets`). It does not store or print raw packets or addresses. Use observation of ordinary UDP echo as a positive control, and wait for a subsequent echo to verify the read boundary. A closed observation stream or invalid boundary is an error.
- `networkStatus` returns `controlConnections` (number of `/ts2021` requests), `derpConnections` (number of `/derp` requests), `derpTLSHandshakes` (TLS ClientHellos received by the DERP server), `derpServerNames` (sorted SNI values from those ClientHellos, with `""` for missing SNI), and `stunRequests` (valid STUN Binding requests). These process-wide cumulative counts allow observation of interface rebinding and same-interface reevaluation without addresses.

- `setMagicDNS` (bool `enabled`) sets `DNSConfig.Proxied` before the first control request and responds with `magicDNS`. `MagicDNSDomain` only sets the name suffix, so the DNS gate uses this command to enable MagicDNS before registering peers and Swift nodes. Missing bools and post-registration changes are rejected.

# Generate TCP segment reference fixtures (`tcpfixtures`)

Calls the public `pkg/tcpip/header` and `checksum` APIs from pinned gVisor `v0.0.0-20260915211658-a6f909f08a72`. It builds packets with `IPv4.Encode`, `IPv6.Encode`, `TCP.Encode`, and option encoders, and reads them with `TCPValid` and `ParseSynOptions`. It does not read or call Swift. It modifies bytes only to create invalid boundaries. It uses no network, randomness, or time.

```sh
fixture_tool="$(sh Scripts/build-interop-tools.sh tcpfixtures)"
"$fixture_tool" Tests/SwiftailNetstackTests/Fixtures
```

The directory argument is required, and the tool writes `tcp-segments.json`. The fixture header contains `reference`, `caseCount: 62`, and `cases`. Each case has a `name`, `packet` (lowercase hex including the IP header), `go`, `swiftail`, and optional `swiftailDiffers`. `go` contains actual Go return values. `swiftail` contains expectations with only the intentional differences defined by W2, T5, and X9 applied. The two objects are identical when there is no difference.

Keys in each result:

| Key | Meaning |
| --- | --- |
| `error` | Empty string on success, or `malformed`, `badChecksum`, or `notTCP` on failure. The tool normalizes gVisor bool results to these names. They are not Go error strings |
| `ipChecksumValid` | IPv4 header checksum. Null for IPv6 or truncation before the check |
| `checksumValid` | TCP checksum. Null if the structure, such as the data offset, cannot be read |
| `decoded` | Parsed object if the TCP structure could be read. Retained for diagnostics even on checksum errors. A packet with `error` is not acceptable. Null if the header cannot be read |

`decoded` contains `ipVersion`, `source`, `destination`, `ipHeaderLength`, `sourcePort`, `destinationPort`, `sequenceNumber`, `ackNumber`, `flags` (raw 8-bit value), `window` (raw 16-bit wire value), `tcpHeaderLength`, `optionsHex`, `mss`, `windowScale`, `sackPermitted` (SYN only), `sackBlocks` (non-SYN segments only, [left edge, right edge] per block), and `dataLength`. `mss` is the **effective MSS** for a SYN and includes defaults when the option is omitted (the Swift codec's `maximumSegmentSize` is nil without the option, and the connection state machine fills in the default under contract T5. The comparison test treats nil as the default). `windowScale` is -1 for a SYN without the option. MSS and WS are both null for non-SYN segments. The data offset length is in bytes. When `swiftail.error` is `malformed`, `decoded` is diagnostic data read by Go and does not indicate successful Swift parsing.

62 cases:

- For each of IPv4 and IPv6: SYN (MSS and WS), SYN-ACK, odd-length data, checksum with repeated carries, FIN-ACK, RST, MSS and WS on non-SYN, omitted options, MSS 0, shift 15, and invalid checksum (22).
- IPv4 options, misalignment from NOP, ignoring invalid bytes after EOL, unknown option, SACK and timestamp combined with MSS and WS, shift 14, maximum 60-byte TCP header, and small MSS 1 (8).
- Option length 0, 1, or beyond the header, missing length field on the last option, truncated MSS body (5, `malformed` under the contract), MSS length 3, and WS length 2 (2, the contract skips the values without reading them, as gVisor does).
- Truncation to 0, 1, and 19 TCP bytes, and 0, 1, 19, and 39 IP bytes (7).
- Data offsets 4, 6, and 15 (outside the segment), and inserting 16 so that the 4 bits wrap to 0 (4). The wire cannot carry 16.
- IPv4 with a protocol other than TCP (1).
- SACK (13, M6-10a): SACK-Permitted in SYN (IPv4 and IPv6), one and four blocks in ACK (including sequence wraparound) and with data, duplicate options, SACK blocks in a SYN, SACK-Permitted in a non-SYN segment, invalid lengths for SACK-Permitted (3) and SACK (2, 9), SACK extending beyond the header, and 5 blocks.

There are **11** `swiftailDiffers` markers: 1 for IPv6 default MSS (Go 536, contract 1220), 2 for MSS 0 where Go stops parsing options and ignores the following WS (also IPv6 MSS 536), 1 for small MSS (Go 48, contract codec 1), and 7 where Go returns the parsed prefix on option errors but the contract rejects it as `malformed` (including the two cases for SACK beyond the header and 5 blocks). The codec does not raise a small MSS, and the connection state machine rejects values below 64 under X9. Both read shift 15 as 14, so it is unmarked. The absence of MSS and WS from general `ParseTCPOptions` is not marked as a difference in SYN option behavior.

The following checks verify byte equality between saved and regenerated fixtures, reproducibility across consecutive runs, 10,000 deterministic random byte inputs at gVisor accessor boundaries, new-command boundary inputs, JSON `id`, empty lists, and control header errors, and two actual tsnet peers with bidirectional 100MiB and simultaneous IPv6 transfer, empty transfer, asymmetric half-close with 3 bytes versus 1MiB, connection refusal, and cancellation. The random-input test checks the Go tool's safety and does not replace the Swift codec's separate 10,000-input test.

```sh
check_dir="$(eyebuild dir m6-tools)"
mkdir -p "$check_dir/tmp"
export TMPDIR="$check_dir/tmp"
export GOCACHE="$(eyebuild dir interop-tools)/gocache"
export GOMODCACHE="$(eyebuild dir ref-src)/gomod"
export GOFLAGS=-modcacherw GOPROXY=off GOSUMDB=off
(cd Tools/interop && go test -count=1 ./cmd/tcpfixtures ./cmd/tailnet)
eyebuild rm m6-tools
```

`SwiftailNetstackTests` in `Package.swift` does not yet declare the Fixtures resource. The session adding the Swift comparison test must add `resources: [.copy("Fixtures")]`. This tool work does not change Swift code or the package declaration.

# Generate ACME reference fixtures (`acmefixtures`)

Calls `tempfork/acme` from `tailscale.com` v1.104.6 and the Go 1.27.3 standard library directly. It does not read or run Swift source. It reads `sha256("swiftail-fixtures/acme/<number>")` with `ecdsa.ParseRawPrivateKey` to determine test keys. It finds the first key and then keys whose first X or Y coordinate byte is 0, respectively, in that order (up to 4096 seeds). **Private keys in the fixtures are public test-only values. Do not use them in production.** Fixture generation uses no network, current time, or external randomness.

```sh
check_dir="$(eyebuild dir m7-acmefixtures)"
mkdir -p "$check_dir/tmp"
export TMPDIR="$check_dir/tmp" GOTMPDIR="$check_dir/tmp"
export GOPROXY=off GOSUMDB=off
fixture_tool="$(sh Scripts/build-interop-tools.sh acmefixtures)"
"$fixture_tool" Tests/SwiftailCertificatesTests/Fixtures
# Without an argument, writes the same JSON to standard output.
"$fixture_tool" > "$check_dir/recreated.json"
cmp "$check_dir/recreated.json" Tests/SwiftailCertificatesTests/Fixtures/acme-fixtures.json
export GOCACHE="$(eyebuild dir interop-tools)/gocache"
export GOMODCACHE="$(eyebuild dir ref-src)/gomod"
export GOFLAGS=-mod=readonly
(cd Tools/interop && eyebuild run m7-acmefixtures -- go test -count=1 ./cmd/acmefixtures)
eyebuild rm m7-acmefixtures
```

With a directory argument it writes `acme-fixtures.json`. `reference` contains the actual build's `go` and `tailscale` versions. A different tailscale version or a replace is rejected. `caseCount: 22` is the sum of the lengths of the following four arrays. All hex is lowercase, and base64url is canonical and unpadded.

| Array | Count | Keys and meanings |
| --- | --- | --- |
| `keys` | 3 | `id` (`account`, `leading-zero-x`, `leading-zero-y`), `testOnly: true`, public seed `seed`, 32-byte private scalar `scalarHex`, public JWK `publicKey` (`crv`, `kty`, base64url `x` and `y` for the 32-byte coordinates), RFC 7638 canonical `jwkJSON` string, `thumbprint`, SEC1 `sec1PEM`, and PKCS#8 `pkcs8PEM` |
| `challenges` | 9 | `keyID`, `token`, `keyAuthorization` (`token.thumbprint`), and `dns01TXT` (43 bytes without quotes). Three different tokens per key |
| `jws` | 6 | `keyID`, `mode` (`jwk` or `kid`), decoded `protectedJSON` and `payloadJSON`, ASCII `signingInput`, and `verifiedExample` (`protected`, `payload`, `signature`). One newAccount and one POST-as-GET example per key |
| `csrs` | 4 | `name`, `keyID`, `domain`, full CSR `derHex`, signature input DER `certificationRequestInfoHex`, and `cnStringTag` (19 = PrintableString) |

CSRs use the `account` key for a short name (`a.ts.net`), an ordinary name (`rd-mac-1a2b3c4d.tail0001.ts.net`), a 63-character label, and a 253-character name. The last is a DER length boundary fixture and is not an example of an actual DNS-01 issuance target, since prepending `_acme-challenge.` would exceed the DNS name limit. Each CSR subject has one CN, the SAN has the same single name, and `ExtraExtensions` is nil. x509 puts the SAN in the extensionRequest attribute.

How values are obtained and which parts cannot be called directly:

- JWK JSON and JWS: Capture the requests made by public `Client.Register` and `Client.GetAuthorization` with an in-memory `http.RoundTripper`. The tool does not duplicate private `jwkEncode` or `jwsEncodeJSON`. The newAccount body is `{}`, and the POST-as-GET body is 0 bytes. The fake URL is `https://acme.invalid`, the fixed nonce is `AAECAwQFBgcICQoLDA0ODw`, and the kid is `https://acme.invalid/account/1`.
- Calls `acme.JWKThumbprint` for the thumbprint, `Client.HTTP01ChallengeResponse` for key authorization (the same internal `keyAuth`), and `Client.DNS01ChallengeRecord` for TXT.
- For CSRs, `feature/acme.certRequest` is private with no public path for calling it independently. `ipn/ipnlocal/cert.go` delegates through a feature hook. Pass the same regular-name template (`certstore.go:306-320`) used by `certRequest(key, domain, nil)` in the actual issuance path `feature/acme/cert.go:578-589` to `x509.CreateCertificateRequest`. Wildcards are outside the scope of these fixtures.
- The SEC1 format for storing account and certificate keys uses `x509.MarshalECPrivateKey` + `pem.EncodeToMemory`, as in `encodeECDSAKey` (`certstore.go:323-330`). PKCS#8 uses `x509.MarshalPKCS8PrivateKey`. The tool uses the same standard parsers as Go storage's `parsePrivateKey` (`certstore.go:340-359`), but accepts only P-256.
- For signing, the `crypto.Signer` calls `ecdsa.PrivateKey.Sign(nil, digest, opts)` to use Go's standard RFC 6979. It does not read the random reader from acme. This test policy ensures reproducibility across the fixtures and differs from the actual Go client's randomized signing policy. JWS and CSR examples are verified during generation, and signature bytes themselves are not compared with Swift.

The three verification commands take **one JSON object on standard input**, write one JSON line, and exit. Success produces exit code 0 and `ok:true`. An error produces exit code 1 and `{"ok":false,"error":"Korean description"}`. Input is at most 256KiB, DER and PEM are each at most 64KiB, and JSON nesting is at most 32 levels. Duplicate members, unknown fields, incorrect field name casing, trailing JSON, and noncanonical base64url are rejected. The commands do not write files or open network connections.

`acmefixtures verify-jws` input:

```json
{"jws":{"protected":"<base64url>","payload":"<base64url or empty string>","signature":"<base64url of 64-byte R ‖ S>"},"jwk":{"crv":"P-256","kty":"EC","x":"<32-byte base64url>","y":"<32-byte base64url>"},"expectedNonce":"AAECAwQFBgcICQoLDA0ODw","expectedURL":"https://acme.invalid/new-account"}
```

`expectedNonce` and `expectedURL` are required. A kid header also requires `expectedKID`. For a jwk header, omit it or provide an empty string. When verifying the fixture kid example, `expectedURL` is `https://acme.invalid/authz/1` and `expectedKID` is `https://acme.invalid/account/1`. Provide the fixture's `keys[].publicKey` looked up by `keyID` as the public key and `jws[].verifiedExample` as the JWS.

Success output is `{"ok":true,"protected":{…},"payloadHex":"<decoded payload hex>","signingInput":"<protected.payload>"}`. `protected` is an object, not a string. It checks ES256, 64-byte signature, P-256 curve and coordinate length, jwk/kid mutual exclusion, equality of the included JWK and supplied public key, and equality of nonce, URL, and kid with expected values. It verifies the actual signing input with `ecdsa.Verify`. The header is at most 8KiB, and URL and kid must be HTTPS, at most 2048 bytes, with no userinfo or fragment. It does not check server account ownership or nonce use history. It verifies the received payload bytes without reserializing them as JSON.

`acmefixtures verify-csr` takes `{"derHex":"<full CSR DER hex>"}`. Both `x509.ParseCertificateRequest` and `CheckSignature` must succeed. Success output:

```json
{"ok":true,"commonName":"a.ts.net","dnsNames":["a.ts.net"],"publicKey":{"crv":"P-256","kty":"EC","x":"<32-byte base64url>","y":"<32-byte base64url>"},"signatureAlgorithm":"ECDSA-SHA256","certificationRequestInfoHex":"<DER hex>","cnStringTag":19}
```

It checks CSR syntax, self-signature, and the P-256 key. The caller compares name, SAN, and tag against desired values and checks whether the Info bytes match. It also accepts UTF8String in a valid CSR and returns `cnStringTag:12`.

`acmefixtures parse-key` takes `{"pem":"-----BEGIN EC PRIVATE KEY-----\n…\n-----END EC PRIVATE KEY-----\n"}`. It reads SEC1 `EC PRIVATE KEY` with `x509.ParseECPrivateKey` and PKCS#8 `PRIVATE KEY` with `x509.ParsePKCS8PrivateKey`. Success output is `{"ok":true,"format":"EC PRIVATE KEY","publicKey":{"crv":"P-256","kty":"EC","x":"<32-byte base64url>","y":"<32-byte base64url>"}}`. PKCS#8 has `format` of `PRIVATE KEY`. It allows only a single block, no PEM headers, no leading or trailing junk, and P-256. The result does not contain private key bytes.

Following chapter 7, items 1 and 2 of the notes, **compare bytes** for canonical JWK, thumbprint, key authorization, and TXT. **Compare bytes** for CSR Info when the same key, SAN attribute, CN tag, and DER rules are chosen. Go's actual protected header order is `alg,jwk,nonce,url` and `alg,kid,nonce,url`, but **compare JWS JSON semantically** for order and whitespace. Go and Swift verify each other's signatures without requiring byte equality. Go tests check equality with saved fixtures and consecutive regeneration, verification of every example, rejection of altered JWS and CSR, acceptance of a reordered and re-signed JWS, validity and Info differences for a UTF8String CSR, and rejection of boundary inputs.

# Generate Ed25519 verification reference fixtures (`ed25519fixtures`)

Build with `sh Scripts/build-interop-tools.sh ed25519fixtures`. For each input generated from fixed seeds, it writes the verdicts of `ed25519consensus.Verify` (`zip215`) and `crypto/ed25519.Verify` (`standard`, recorded as false for an invalid public key length because Go panics). With a directory argument, it writes `ed25519-verify.json`. Without one, it writes to standard output. Swift tests also compare fresh verdicts when `SWIFTAIL_ED25519FIXTURES=<tool path>`. `go test ./cmd/ed25519fixtures` checks equality across consecutive generations, equality with saved fixtures (`Tests/SwiftailCryptoTests/Vectors/ed25519-verify.json`), and that the first 196 match `zip215_test.go`. Case types: `zip215`, `valid`, `flipSignature`, `flipPublicKey`, `flipMessage`, `nonCanonicalS`, `highBits`, `smallOrderA`, `smallOrderZeroS`, `nonCanonicalA`, `nonCanonicalR`, `torsionR`, `torsionA`, `offCurve`, and `length`.

# Generate Argon2i reference values (`argon2fixtures`)

Build with `sh Scripts/build-interop-tools.sh argon2fixtures`. Run without arguments to write 75 `argon2.Key` outputs from `golang.org/x/crypto` as JSON to standard output (`argon2fixtures > Tests/SwiftailCryptoTests/Vectors/argon2i-go.json`). The last entry uses the TKA disablement secret arguments as is and fails if it differs from `tka.DisablementKDF`. Inputs are fixed test-only patterns. Swift tests regenerate and compare if `SWIFTAIL_ARGON2FIXTURES=<path>` is set.

# Generate pairing reference vectors (`pairingvectors`)

Build with `sh Scripts/build-interop-tools.sh pairingvectors`. Run without arguments to write 4 fixed vectors for the pairing procedure (`docs/contracts/SwiftailPairing.md` §5) as JSON to standard output (`pairingvectors > Tests/SwiftailPairingTests/Fixtures/pairing-vectors.json`). It was written using only the contract text and the Go standard library (`crypto/hmac`, `crypto/sha256`, `net/netip`), without reading or calling the Swift implementation. Each vector contains inputs (`secret`, `offerHost`, `offerPort`, `deviceName`, both nonces, and both connection endpoints) and their resulting `joinerCommitment` and `hostCommitment` (commitments to the two nonces), `hello` (version 3), `challenge` (status 0 ‖ commitH), `challengeNoOffer` (status 1 ‖ commitH), `proofTranscript` (P, 198 bytes), `transcript` (T = P ‖ nonceH, 230 bytes), `proof` (nonceJ ‖ HMAC of P), `accepted` (nonceH ‖ HMAC of T), `confirmationCode`, and `approved`, `denied`, and `timedOut` (`decision` body ‖ HMAC), in hexadecimal. Inputs are fixed test-only patterns. Cases: two IPv4 endpoints, two IPv6 endpoints with a Hangul device name and an empty display name, longest names (64-byte device name, 255-byte `StableID`, 64-byte display name), and an SAS starting with 0 (the first result obtained by incrementing the first byte of the joiner nonce from 0). `go test ./cmd/pairingvectors` checks equality across consecutive generations and against saved fixtures. The Swift test (`ProtocolVectorTests`) compares the saved fixtures with each codec operation and computation, and connects the two state machines to check whether the bytes on the wire match.

# Generate TKA reference fixtures (`tkafixtures`)

The tool for "Comparison with Go reference values" in §7 of the Tailnet Lock contract (`docs/contracts/SwiftailTailnetLock.md`). It writes verdicts from the `tka` package in `tailscale.com` v1.104.6 as JSON. It does not read or run Swift source. It uses no network, current time, or external randomness. All keys use `SHA-256("swiftail-fixtures/tka/<role>/<number>")` as an Ed25519 seed or node key input (X25519 private key), with roles `lock`, `nl`, `credential`, `fork`, `node`, and `disablement`. **Private keys in the fixtures are public test-only values.** Go Ed25519 signatures are deterministic, so regeneration produces the same bytes.

```sh
check_dir="$(eyebuild dir tl5-fixtures)"
mkdir -p "$check_dir/tmp"
export TMPDIR="$check_dir/tmp" GOTMPDIR="$check_dir/tmp"
export GOCACHE="$(eyebuild dir interop-tools)/gocache"
export GOMODCACHE="$(eyebuild dir ref-src)/gomod"
export GOFLAGS=-modcacherw GOPROXY=off GOSUMDB=off
fixture_tool="$(sh Scripts/build-interop-tools.sh tkafixtures)"
# The working directory must be Tools/interop (the peer set overlay build uses its go.mod).
(cd Tools/interop && "$fixture_tool" ../../Tests/SwiftailTKATests/Fixtures)
# Without an argument, writes the same JSON to standard output.
(cd Tools/interop && "$fixture_tool" > "$check_dir/recreated.json")
cmp "$check_dir/recreated.json" Tests/SwiftailTKATests/Fixtures/tka-fixtures.json
(cd Tools/interop && go vet ./cmd/tkafixtures && go test -count=1 ./cmd/tkafixtures)
eyebuild rm tl5-fixtures
```

It does not run with an empty `GOCACHE` (to avoid creating a Go cache in the home directory). `go test` checks equality across consecutive generations, byte equality with saved fixtures, that `caseCount` is nonzero and equals the sum of array lengths, that the file is at most 2MB, that the Go test values copied to `genesis.go` are present unchanged in the original test file, and that `verify-nks` produces the same verdicts as the fixtures and rejects invalid input.

All verdicts come from public `tka` APIs: `AUM.Unserialize`, `StaticValidate`, `Serialize`, `Hash`, `SigHash`, `NodeKeySignature.Unserialize`, `Serialize`, `SigHash`, `Bootstrap`, `Inform`, `Head`, `Keys`, `StateIDs`, `SyncOffer`, `MissingAUMs`, `FromSyncOffer`, `NodeKeyAuthorizedWithDetails`, `ValidDisablement`, `DisablementKDF`, `DecodeWrappedAuthkey`, `SignByCredential`, `ResignNKS`, `MakeRetroactiveRevocation`, `AUMHash.String`, `UnmarshalText`, and the text forms of `key.NLPublic`, `NLPrivate`, and `NodePublic`. There are two exceptions.

- The state's disablement values have no public accessor. Walk backward from the head with `ChonkMem.AUM` and read `State.DisablementValues` from the first checkpoint encountered (Go changes these values only when applying a checkpoint, `tka/state.go:162-254`).
- Peer filtering (including `rotationTracker`) is an unexported function in `ipn/ipnlocal`. As in `mapfixtures`, copy `tailscale.com` to a temporary copy under `eyebuild dir interop-tools`, add only `ipn/ipnlocal/swiftail_fixtures.go` (`bridge.go.txt`) via `-overlay`, and build and run a small program (`worker.go.txt`) that calls the actual `tkaFilterNetmapLocked`. It does not copy the filtering logic. The module cache is left untouched, and the temporary copy is deleted afterward.
- Canonical bytes for standalone Key and State values (`encodings`) are generated with the same encoder settings as `tka`, `cbor.CTAP2EncOptions()`, because `tka` does not provide standalone `Serialize` for them.

Deliberately invalid inputs are assembled directly as CBOR bytes (`rawAUMCases` and `rawNKSCases` in `cbor.go`, and signed AUM variants in `chains.go`). Signatures with a point of order 2 added to R and signatures for a noncanonical identity public key are computed with `filippo.io/edwards25519` (`keys.go`).

The output is one JSON object, with one array element per line. All bytes are lowercase hex, and nil is `null` (an empty byte string is `""`). 64-bit StateID values are decimal strings. Top-level keys:

| Key | Contents |
| --- | --- |
| `reference` | `go` and `tailscale` versions. Rejects tailscale versions other than v1.104.6 or a replace |
| `caseCount` | Sum of the scenario array lengths below (for `sync`, the count of nested `cases`). Excludes `keys` and `authorities` |
| `keys` | Test keys: `role`, `index`, `seed` (SHA-256 input string), `private` (32-byte seed), `public`, and `text` (`tlpub:` and `nodekey:`) |
| `authorities` | Trust state used for verdicts: `name`, `aums` (first for bootstrap, remainder in one `Inform` batch), `head`, and `state` |
| `text` | `kind`(`aumHash.encode`·`aumHash.decode`·`nlPublic.*`·`nlPrivate.*`·`nodePublic.*`), `input`, `ok`, `output`, `error` |
| `encodings` | Key and State values (`value`) and canonical CBOR (`encoded`) |
| `cbor` | `type` (`aum` or `nks`), `input`, `decoded`, `staticValid` (AUM only, null for NKS), `accepted` (successful decoding and static validation for AUM, decoding for NKS), and `error`. On successful decoding, `reencoded`, `canonical` (re-encoding equals input), `hash` (AUM), and `sigHash` |
| `chains` | `bootstrap`, `bootstrapOK`, `bootstrapError`, `initial` (state), and `steps` (`name`, `aums` for bytes passed to one `Inform`, `ok`, `error`, and `after` for the state after the step) |
| `sync` | Each group has a `pool` (AUM bytes) and `cases`. The case's `local` and `remote` contain `aums` (pool indices, bootstrapped with the first), `offer` (hex and `FromSyncOffer` text), `missing` (`MissingAUMs` for the peer's offer: `ok`, `error`, `count`, `digest` = SHA-256 of concatenated hashes, and `hashes` for 100 or fewer), `informOK` for ingesting the peer's list, and `headAfter` |
| `signatures` | `authority`, `nodeKey` (32 bytes), `nks`, `sigHash` (if decoded), `authorized`, `error`, and `rotation` (`prevNodeKeys` newest first, `initialKind`, and `initialWrappingPubkey`) |
| `peerSets` | `authority`, `peers` (`nodeKey`, `signature`, `unsignedPeerAPIOnly`), and `kept` (node keys retained by `tkaFilterNetmapLocked`, preserving order) |
| `disablement` | `authority`, `secret`, `kdf`(`DisablementKDF`), `valid`(`ValidDisablement`) |
| `authKeys` | `input`, `authKey`, `isWrapped`, `returnedInput` (whether it returned the entire original), `credential` (re-encoded), and `privateKeyLength` from `DecodeWrappedAuthkey`. If wrapped, `sign` (`ok`, `error`, or `panic`), `signError`, and `nks` from `SignByCredential` (node/8). If trust state exists, `verdict` |
| `resign` | `nlKey` (the key's seed string), `oldNKS`, `nodeKey`, `ok`, `error`, `result`, `sigHash`, `sameAsOld`, and `depth` from `ResignNKS`, and the result's `verdict` |
| `unorderedPeerSets` | Peer sets where Go's answer depends on map iteration order: `authority`, `peers`, `runs` (runs with identical input, 256), and `outcomes` (the distinct `kept` results, sorted). For `peerSets` cases, generation succeeds only if all `runs` (64) give the same answer |
| `limits` | Chains of more than 2,000 from the root. Each group has `pool` (the `sync` group name using the same AUMs), `extra` (AUMs appended to that pool), and `cases` (`baseCount` for bootstrap plus one batch using that many entries from index 0, `baseHead`, and `steps` with `aums` indices, `ok`, `error`, and `head`) |
| `padded` | Inputs exceeding Swiftail's byte limits (NKS 8KiB, AUM 512KiB). Provides the recipe in place of bytes: input = (`base` map header + 1) ‖ `base[1:]` ‖ uint(`padKey`) ‖ bstr(0 × `padLength`), length `length`. For each `kind` (`authorize`, `resign`, `inform`, `authKey`), Go's `ok`, `error`, `head`, `sigHash`, and `verdict`. The `authKey` input string is `controlValue` ‖ `--TL` ‖ RawStd(input) ‖ `-` ‖ RawStd(`privateKey`) |
| `openedStates` | `NodeKeyAuthorizedWithDetails` after opening a state that Bootstrap cannot create (a non-Key25519 key) via `CommitVerifiedAUMs`, `SetLastActiveAncestor`, and `tka.Open`: `checkpoint`, `openOK`, `nodeKey`, `nks`, and verdict |
| `reviewChains` | Chains added by the TL-11a review (`review.go`). Same shape as `chains` |
| `reviewSignatures` | NKS verdicts added by the TL-11a review (`review.go`). Same shape as `signatures` |

`caseCount` also includes entries in `unorderedPeerSets`, `padded`, `openedStates`, `reviewChains`, and `reviewSignatures`, and the `cases` under `limits`.

The `cbor` case name prefixes describe decoding verdicts expected by the notes and contract. `accept/` cases decode and `reject/` cases are rejected in decoding (the fixtures confirm that these match). `probe/` cases are inputs for which the notes and contract had not verified Go's verdict by running it. `value/` cases are static validation boundaries from serializing `tka.AUM` values with `Serialize`. Compare the verdict itself using `decoded` and `accepted`, not the names. Under contract behaviors E6 and D8, Swift compares only the verdict for AUMs that fail static validation.

Scenarios (items 1 through 8 in contract §7):

- `cbor`: all of the acceptance and rejection table in note 8.1, all major types and simple values for unknown fields (one-byte 0~19, 99, and 255, two-byte 0, 23, 24, 31, and 32), negative and integer key endpoints (−2^63, −2^63−1, −2^64, 2^63−1, 2^63, 2^64−1), text keys, non-minimal integers, lengths, and map headers, null and undefined in each known field, null elements in `Signatures`, duplicate keys with non-minimal encoding of the same key, duplicates in struct, `Meta`, Key, State, and Signature maps, indefinite lengths, tags, reserved additional information 28~30 and 31, and `break`, non-map top-level values (including null and undefined), integer arrays in place of byte strings, 16/17 levels of nesting (arrays and maps), arrays of 4096/4097, maps of 1024/1025 (nested in values and at top level), required and forbidden fields and static validation boundaries by kind (`Votes` 0, 1, 4096, and 4097, `Meta` 512 and 513 bytes, signature KeyID 31, 32, and 33 bytes and signature 63, 64, and 65 bytes, 0, 1, 32, and 33 disablement values, 31- and 33-byte disablement values and duplicates, 0, 1, 512, and 513 keys and duplicates, `PrevAUMHash` 0, 1, and 33 bytes), and NKS decoding variants.
- `chains`: linear chain (AddKey → UpdateKey(`Votes`, `Meta`) → RemoveKey → NoOp → Checkpoint → AddKey → three batches), bootstrap (later checkpoint, Go test genesis, non-checkpoint, no signature, untrusted key, `LastAUMHash` present, invalid signature), rejection (empty batch, no signature, unknown key mixed in, invalid signature, no parent, unknown parent, 31- and 33-byte `PrevAUMHash`, duplicate AddKey, checkpoint with a different StateID, Remove/Update of an absent key, update to `Votes` 0 and 4097, signed static violation, batch with an invalid AUM at the start or end, already held AUM, reordered batch, removal of last key, signature from removed key), unusual accepted cases (kinds 0, 9, and 255, NoOp with extra fields, AddKey with null, empty, 31-byte, or 33-byte `Public` and subsequent Remove/Update/checkpoint, unknown field and non-minimal integer, unsorted keys, `PrevAUMHash` and signatures with bytes encoded as integer arrays, null `Meta` values, and the next AUM for each), ZIP-215 (R with an order-2 component, noncanonical identity public key), forks (weight, two signatures versus one, same key twice, RemoveKey priority, hash, descendant of losing fork, retroactive revocation checkpoint, and a batch forming several levels and forks). Fork cases choose the relative hash ordering so the previous rule's result differs from hash comparison.
- `sync`: `basic` (same head, behind, ahead, diverged, checkpoint only the peer knows, peer has only genesis, no intersection), `checkpoint-51` (ancestor list for the 51st checkpoint, head intersection), and `long` (checkpoint depths 999 and 1000 for the 1000-iteration ancestor-list limit, and 1999 and 2000 fast-forward iterations for the 2000-iteration limit).
- `signatures`: direct (with and without rotation key, different node key, untrusted key, removed key, `Nested` present, 31-byte trusted key, invalid signature, ZIP-215-only signature, noncanonical identity key, no KeyID or Pubkey, kinds 0 and 4, trailing bytes, unknown field), credential alone, rotation with 1~16 layers, intermediate `WrappingPubkey`, missing and 31-byte rotation key, inner Pubkey other than `np`, outer ZIP-215-only signature, no `Nested`, different signing key, and credential → rotation (different node key, untrusted credential, different signing key, `np` Pubkey, garbage Pubkey, and rotation on top).
- `peerSets`: no signature, invalid signature, `UnsignedPeerAPIOnly`, key made stale by rotation, longest history in a group with the same rotation key, all dropped if lengths tie, stale keys excluded from the group, credential chains not grouped, different rotation keys, and removed signing key.
- `disablement`: 0xa5 × 32 (KDF `c3fea8a0…4e2f`), matching one of three disablement values, incorrect value, empty secret, 31 bytes, and before and after a checkpoint changes the values.
- `authKeys`: Go test string (`tka/sig_test.go:479`), valid, unwrapped, missing `-`, padded base64, URL alphabet, extra `-`, non-CBOR, A that is not a credential, B of 32, 63, and 65 bytes (Go panic), B with different last 32 bytes, A with different `WrappingPubkey`, untrusted credential, and both parts empty.
- `resign`: same node key (unchanged), direct with NL key as the rotation key, different NL key, direct without a rotation key, credential chain, chains with 14~17 Pubkeys (trimming starts at 16, decoding rejects 17), and undecodable old signature.

Additions from the TL-5 comparison test (inputs listed as unverified by execution in contract §5, "Decisions made during implementation," and boundaries of Swiftail limits):

- `cbor`: simple values in integer fields (`MessageKind` `e3`, `f3`, `f863`, and `f8ff`, `Votes` `f820`, Key `Kind` and `Votes` `e1`, `StateID` `e7`, NKS `SigKind` `e1` and `f8c8`), `MessageKind` false, simple value, null (`8401e5f618ff`), undefined, true, float, and array elements in an integer array in place of a byte string, simple value, undefined, and false `Meta` keys and simple values, duplicate null and empty `Meta` keys, and simple-value struct map keys.
- `text`: `\r` and `\n` in `AUMHash` text (50, 51, or 48 characters plus newline, in the middle or at the start, and 52 characters plus newline).
- `chains`: `batch-duplicates` (same AUM in one batch: twice, twice with a child between, already held twice, fork twice, unsigned twice, and parent after its child).
- `sync`: `long`'s `head-intersection-distance-999` and `-1000` (boundary beyond 1,000 head intersection iterations where it switches to tail intersection).
- `signatures`: empty `Pubkey` in direct inside rotation, and empty `Pubkey` in intermediate rotation.
- `peerSets`: an `UnsignedPeerAPIOnly` peer becomes stale through rotation, and rotation by such a peer does not make another peer stale. `unorderedPeerSets`: the same node key belongs to groups with different rotation keys.
- `authKeys`: nonzero unused bits in credential and wrapped key base64, and newlines (`\n`, `\r\n`, and trailing `\n`).
- `limits`: linear chain of more than 2,000 from the root (fast path), 1,999th and 2,000th forks from the root, a batch with an already held AUM mixed in and what follows (the failed batch remains in the Go store), and 2,000 and 2,001 entries from checkpoint to parent.
- `padded`: verdicts for 8,192- and 8,193-byte NKS, an 8,193-byte old signature for re-signing, ingestion of 524,288- and 524,289-byte AUMs, and a wrapped auth key with an 8,193-byte credential.
- `openedStates`: states with a non-Key25519 key before or after the signing key.

Additions from the TL-11a review (`SwiftailTKA` security review) in `review.go`, with the Swift comparison in `TKAReviewTests.swift`:

- `reviewChains`: variants changing only the signature list (repeating signatures gives the smaller-hash variant a win over the original, leaving the original's child RemoveKey on the losing fork, the larger variant loses, and original and variant in one batch in both orders), siblings with only two signatures swapped in order, altered signature lists (untrusted key appended, invalid copy at the start or end, signature from a different AUM, empty list, same signature 1,024 times), an original and a copy padded by 1KiB of unknown fields, re-adding a removed key with the same KeyID (signature in between, adding twice, removing the last key), Votes 0, 4,096, and 4,097 and Meta 512 and 513 bytes (AddKey and UpdateKey), UpdateKey with only empty Meta (`07a0`) and UpdateKey with neither Votes nor Meta, update to the maximum `Votes`, two heavy signatures versus one light one, checkpoint on the losing fork (descendants verified with the checkpoint's keys), the same AUM tree in one batch in three orders, in split batches, and in a child-first batch, a sibling made by a removed key from the old parent when the key to remove has greater weight, bootstrap from a checkpoint with 31-byte, 32-byte, 33-byte, or empty parent hash, and bootstrap with an untrusted signature mixed in or a repeated signature.
- `reviewSignatures`: direct and rotation signatures of 63, 65, and 0 bytes, 33-byte rotation key, rotation to the same node key, outer rotation KeyID (unused), trusted key itself as rotation key, credential of a removed key (before and after), rotation over a rotation wrapping a credential (intermediate `WrappingPubkey`, wrong signing key), truncated NKS, and non-minimal `SigKind`.

`tkafixtures verify-nks` takes one JSON object on standard input, `{"aums":["<hex>",…],"nodeKey":"<32-byte hex>","nks":"<hex>"}`. It bootstraps with the first of `aums` and applies the others via `Inform`, then uses `NodeKeyAuthorizedWithDetails` for the verdict, writes one line `{"ok":true,"authorized":…,"error":…,"rotation":…}`, and exits 0 (even for a rejection verdict). If input exceeds 4MiB, is not a single JSON object, contains unknown fields or uppercase hex, or bootstrap or `Inform` fails, it writes `{"ok":false,"error":"…"}` and exits 1. Use it to verify Swift-generated signatures (`SignByCredential` and re-signing. CryptoKit signatures are nondeterministic).

# Auth key issuance recording server (`authkeyrecorder`)

Tool for M9 gate (a) 7 (`docs/contracts/SwiftailPairing.md` §7). It compares the requests sent to the same server by Go's auth key issuance flow and Swift's `AuthKeyIssuer`. Build with `sh Scripts/build-interop-tools.sh authkeyrecorder`. Dependencies are `golang.org/x/oauth2` v0.37.0 (BSD-3-Clause) and public `client/tailscale` from `tailscale.com` v1.104.6 (BSD-3-Clause). It does not call the real admin API (`api.tailscale.com`).

`authkeyrecorder serve [-reject-basic]` listens on an arbitrary port at `127.0.0.1` and writes the server URL (`http://127.0.0.1:12345`) as the first line of standard output. It exits when standard input closes (EOF). With `-reject-basic` it rejects token requests with `Authorization` or without `client_id` or `client_secret` in the form, returning 401 `{"error":"invalid_client"}` (it records the requests). Use this to compare how the two clients retry with body credentials after using header credentials.

- `/api/v2/oauth/token` records the request and returns `{"access_token":"tskey-api-EXAMPLE-token","token_type":"Bearer","expires_in":3600}`.
- `/api/v2/tailnet/-/keys` records the request and returns `{"id":"kEXAMPLE","key":"tskey-auth-EXAMPLE","created":"2026-01-01T00:00:00Z","expires":"2026-01-01T00:10:00Z","capabilities":{…}}`.
- `GET /recorded` returns the recorded requests in receipt order as a JSON array and clears them. Each entry is `{"method","path","authorization","contentType","body","json","form"}`. If the body is JSON, `json` is the body rewritten with sorted keys. For a non-JSON form body, `form` is the body rewritten by `url.Values.Encode()` (sorted keys), and otherwise it is `""`. It reads at most 64KiB of the body.

The recording server returns the incoming `Authorization` header as is. This test tool handles fake values only, so do not supply real OAuth client secrets.

`authkeyrecorder issue -base <server URL> -tags tag:a,tag:b -expiry <seconds>` creates one key using the same structure as `cmd/get-authkey` (tailscale.com v1.104.7) and writes it to standard output. It calls `CreateKeyWithExpiry` on `tailscale.NewClient("-", nil)` using `clientcredentials.Config{TokenURL: <base>/api/v2/oauth/token}.Client` as its HTTP client. get-authkey uses `internal/client/tailscale`, which is inaccessible outside the module, so use the public package with the same code and enable `I_Acknowledge_This_API_Is_Unstable`. get-authkey's `CreateKey` uses expiration 0 (omitting `expirySeconds` from the body), so call `CreateKeyWithExpiry` to supply a lifetime. As in get-authkey, read the client ID and secret from `TS_API_CLIENT_ID` and `TS_API_CLIENT_SECRET`. `-base` only accepts loopback `http` addresses. The key's `reusable`, `ephemeral`, and `preauthorized` flags are fixed to false, false, and true under contract §4 K3. If header credentials fail, `x/oauth2` retries once with body credentials (`RetrieveToken` in `internal/token.go`). With ordinary `serve`, the first attempt returns 200, so there is no retry.

Go `client/tailscale` omits `Content-Type` for key requests (`CreateKeyWithExpiry` in `keys.go`, `Do` in `tailscale.go`). Swift sends `application/json`. The gate test checks this difference separately. Everything else must match (request count and order, method, path, entire `Authorization` value (empty for body credentials), token request `Content-Type`, and canonical form and JSON bodies). It compares both ordinary `serve` and `-reject-basic`.

Set `SWIFTAIL_AUTHKEYRECORDER` to the tool path to run the Swift tests. If unset, they are skipped.

```sh
SWIFTAIL_AUTHKEYRECORDER="$(sh Scripts/build-interop-tools.sh authkeyrecorder)" eyebuild swift <purpose> -- test --filter AuthKeyInteropTests
```
