# SwiftailControl Contract (M2)

Handles the entire conversation with the control server, including server key lookup, HTTP upgrade, the Noise connection, registration and the map stream over HTTP/2 on that connection, and maintaining a netmap from the maps received.

Protocol details follow the two cross-verified notes below.

- [protocol-notes/control-transport.md](../protocol-notes/control-transport.md) covers the upgrade, Noise, records, early payload, and key formats. §7.3 contains fixed test vectors.
- [protocol-notes/control-map.md](../protocol-notes/control-map.md) covers registration, map requests and responses, delta application, and JSON details.

## Structure

As in M1, protocol logic lives in I/O-free value types. A single actor at the edge (`ControlClient`) owns the sockets and clock.

```
 ControlClient (actor: TCP connection, clock, reconnection)             ← Unit 4
   │ bytes
   ├─ UpgradeRequest / UpgradeResponseParser   HTTP/1.1 upgrade         ┐
   ├─ ControlHandshake → ControlSession        Noise IK, records        ├ Unit 2 (Transport/)
   ├─ EarlyPayloadParser                       Server's early message       ┘
   ├─ HTTP2ClientConnection                    SwiftailHTTP2           ← Unit 1
   ├─ MapResponseFramer                        Length-prefixed frames   ┐
   ├─ tailcfg models (Codable)                 Request/response JSON    ├ Unit 3 (Tailcfg/, Netmap/)
   └─ MapSession → Netmap                      Delta application       ┘
```

`Sources/SwiftailControl/Keys.swift` already exists and contains the shared key types `MachinePublicKey`, `NodePublicKey`, `DiscoPublicKey`, and `ChallengePublicKey`.

## Unit 2 — Transport (`Sources/SwiftailControl/Transport/`)

```swift
public enum ControlTransportError: Error, Sendable, Equatable {
    case malformed                 // Length, type, or format differs from the specification
    case upgradeRejected(status: Int)   // Status other than 101
    case handshakeFailed           // Decryption failure, server error message, or an all-zero shared secret
    case authenticationFailed      // Transport-phase record decryption failed. Discard the connection
    case messageTooLarge           // Record, early payload, or upgrade response head exceeds the limit
    case closed                    // Called a failed or completed state machine (one that already returned a result), or exhausted the send counter
}

/// The bytes of a `POST /ts2021` upgrade request.
public enum UpgradeRequest {
    public static func bytes(host: String, initiation: [UInt8]) -> [UInt8]
}

/// Reads an upgrade response. Validates the complete head and returns any bytes already received after it.
public struct UpgradeResponseParser: Sendable {
    public init()
    /// Returns nil until the head is complete, then returns the remaining bytes (for the Noise layer).
    public mutating func receive(_ bytes: [UInt8]) throws(ControlTransportError) -> [UInt8]?
}

/// The initiator for control Noise (Noise_IK_25519_ChaChaPoly_BLAKE2s).
public struct ControlHandshake: Sendable {
    /// Throws `handshakeFailed` if a low-order server key yields an all-zero shared secret.
    public init(machineKey: Curve25519.KeyAgreement.PrivateKey, serverKey: MachinePublicKey, protocolVersion: UInt16 = 148) throws(ControlTransportError)
    /// The 101 initiation bytes to send to the server.
    public var initiation: [UInt8] { get }
    /// Feeds bytes from the server. Returns nil until the response is complete.
    /// Once complete, returns the transport-phase session and any bytes already received after the response.
    public mutating func receive(_ bytes: [UInt8]) throws(ControlTransportError) -> (session: ControlSession, remainder: [UInt8])?
}

/// The transport phase converts between a plaintext byte stream and records.
public struct ControlSession: Sendable {
    /// Seals plaintext into one or more records. Each record contains at most 4,077 bytes of plaintext.
    public mutating func seal(_ plaintext: [UInt8]) throws(ControlTransportError) -> [UInt8]
    /// Feeds received bytes and returns the concatenated plaintext of complete records. Buffers incomplete records.
    public mutating func receive(_ bytes: [UInt8]) throws(ControlTransportError) -> [UInt8]
}

/// Extracts the optional early message from the server at the start of the Noise plaintext stream.
public struct EarlyPayloadParser: Sendable {
    public struct EarlyPayload: Sendable, Equatable {
        public var nodeKeyChallenge: ChallengePublicKey?
    }
    public init()
    /// Returns nil until there are enough bytes to decide. Then returns the early message, if present, and the bytes after it (for HTTP/2).
    public mutating func receive(_ plaintext: [UInt8]) throws(ControlTransportError) -> (payload: EarlyPayload?, remainder: [UInt8])?
}
```

Transport rules follow.

- Generate the ephemeral key in `ControlHandshake.init` with system randomness. Provide an internal initializer that takes the ephemeral key for fixed-vector tests.
- The record nonce is a big-endian counter. The Noise specification uses little-endian. See the notes, §3.5.
- After the first decryption failure, the session becomes `closed` and discards its keys.
- Limits are 4,096 bytes per record, 10MiB for the early payload, and 16KiB for the upgrade response head. Discard buffered bytes on failure or when a limit is exceeded.
- A lone CR or LF, or any control character other than a tab, in the upgrade response status line or header values yields `malformed`.
- Public types that hold keys (`ControlHandshake`, `ControlSession`) hide their children with `CustomReflectable`. `print` and `dump` expose no key material.

Tests cover the fixed vectors from the notes, §7.3 (initiation, response, keys by direction, records with counters 0, 1, and 2, and an empty record), fragmented input (one byte at a time), splitting at the 4,077-byte boundary, `closed` after a tampered record, server error messages, state needed to handle EOF after a 101, present, absent, and malformed early payloads, validation of the upgrade response status and `Upgrade` value, and avoiding crashes on arbitrary input.

## Unit 3 — Map (`Sources/SwiftailControl/Tailcfg/`, `Sources/SwiftailControl/Netmap/`)

### tailcfg Models

`Codable` structs correspond to Go's `tailcfg` types. JSON keys are the Go field names verbatim (starting with an uppercase letter).

- Request-side types are `RegisterRequest`, `MapRequest`, `Hostinfo`, `NetInfo`, and `RegisterResponseAuth`.
- Response-side types are `RegisterResponse`, `MapResponse`, `Node`, `PeerChange`, `DERPMap`, `DERPRegion`, `DERPNode`, `DNSConfig`, `UserProfile`, `Login` and `User` (registration response), `FilterRule`, `PingRequest`, and `TKAInfo`.
- Keep the same names as Go because they are protocol terms. Include fields marked "required for a minimal client" in the tables in the notes, §3.2~§3.7, and those used to apply deltas. Other fields are optional to implement, but **decoding must succeed even when unknown keys are present.**
- Follow the JSON rules in the notes, §3.1.
  - When sending, emit fields without `omitempty` even when empty (a zero key is `nodekey:000…`, and the zero time is `0001-01-01T00:00:00Z`). Omit empty fields with `omitempty`.
  - When receiving, accept fractional seconds and non-UTC offsets in timestamps, maps with numeric IDs as base-10 string keys, `null` values in `CapMap`, and `true`, `false`, and `null` for `opt.Bool`.
  - When a delta field distinguishes between an absent key, `null`, and an empty array, preserve the distinction during decoding.

### Framing and Delta Application

```swift
/// Splits the map stream body into frames (4-byte little-endian length + JSON).
public struct MapResponseFramer: Sendable {
    public init()
    /// Feeds received bytes and returns complete responses. Frame boundaries are independent of HTTP/2 DATA boundaries.
    public mutating func receive(_ bytes: [UInt8]) throws(MapError) -> [MapResponse]
}

public enum MapError: Error, Sendable, Equatable {
    case frameTooLarge              // The length prefix exceeds the limit
    case malformed                  // JSON decoding failed, or the nesting depth or value count exceeded the limit
    case missingSelfNode            // The first ordinary response has no Node
    case stateTooLarge              // The session's state exceeds the limit. Discard the session and start over
}

/// The tailnet's current state after applying map responses in order.
public struct Netmap: Sendable, Equatable {
    public var selfNode: Node
    public var peers: [Node]                       // Ascending Node ID
    public var derpMap: DERPMap?
    public var dnsConfig: DNSConfig?
    public var packetFilter: [FilterRule]
    public var userProfiles: [Int64: UserProfile]  // User ID → profile
    public var domain: String
    public var tailnetLock: TailnetLockStatus      // Since M8. The netmap from `ControlClient` is already filtered (`SwiftailTailnetLock.md`). M2~M7 used `tailnetLockEnabled: Bool` (detection only)
    public var controlTime: Date?
}

/// State for one map stream. Applies responses to build a netmap.
public struct MapSession: Sendable {
    public struct Update: Sendable {
        /// The netmap after this response. Nil if nothing changed (KeepAlive, identical retransmission, or only the server time changed).
        public var netmap: Netmap?
        /// A ping the server wants answered. The caller handles it.
        public var pingRequest: PingRequest?
    }
    public init()
    /// Applies the response using now as its receipt time (the last online time for a "seen now" delta).
    public mutating func apply(_ response: MapResponse, receivedAt now: Date) throws(MapError) -> Update
}
```

- Apply deltas using the algorithm and order from the notes, §4.3. The order is `Peers` (full replacement), `PeersChanged`, `PeersRemoved`, `PeersChangedPatch`, `PeerSeenChange`, `OnlineChange`, `DERPMap` (partial retention rules), `DNSConfig`, `PacketFilter` and `PacketFilters` (named deltas, where an empty array means "block all"), `UserProfiles`, `Domain`, `TKAInfo`, and `ControlTime`.
- Frame limits are 8MiB (256MiB in Go, reduced here because of the iOS extension's memory limit. Decoding normal data that fills the limit was measured to peak at about 1.7 times the frame size, or about 14MB for 8MiB. Actual map sizes for large tailnets were unmeasured), JSON nesting depth of 64, and 1,000,000 values (array elements + object members). Scan the bytes to count depth and values before passing them to `JSONDecoder`. Exceeding the frame size limit yields `frameTooLarge`. Exceeding the depth or value count limit yields `malformed`. A payload containing a byte of 0 also yields `malformed` (this filters out UTF-16 and UTF-32 JSON so the decoder receives only UTF-8).
- Session limits are 20,000 peers, 40,000 user profiles, 256 named filters, and 50,000 filter rules in total. Exceeding them yields `stateTooLarge`. Like Go, retain profiles for the duration of the session.
- A failed framer or session discards buffered bytes and state and repeats the same error thereafter.
- Responses without state fields (KeepAlive, or server time or ping only) do not rebuild the netmap.
- Decode `JSONValue` numbers in the order `integer(Int64)` → `unsignedInteger(UInt64)` → `number(Double)`. Integers outside the 64-bit range and high-precision decimals are rounded to `Double`.
- `RegisterResponseAuth` hides the auth key with `CustomReflectable` (`print` and `dump` show only its length).
- `shortcut:` The value count limit only caps the frame at a size the decoder can finish processing. It cannot guarantee that decoding stays within the extension's memory limit (about 50MB). The worst-case frame filled with empty nodes uses about 1.3GB, and a frame filled with normal data uses about 110MB. Measurements are from Debug. In M5, tighten the limit by limiting the `Peers` element count during decoding, alongside real-device measurements.
- Known differences remain because Noise authenticates the control server and the Go server does not produce this JSON. Filter names that Unicode normalization makes equal are merged (Go distinguishes their bytes). For a duplicate key, Swift may keep a different value from the one Go keeps. Integer fields accept `1.0` and `1e0` (Go rejects them).
- Leave zstd unimplemented and request uncompressed data by leaving `Compress` empty. `shortcut:` Add a decompressor if the production server rejects uncompressed mode (verify at the M2 closing gate).

Tests verify decoding and encoding using the JSON examples in the notes, §3.1, and data generated by Go (`Tests/SwiftailControlTests/Fixtures/`, produced by another unit). Compare delta application with the results of feeding the same response sequence to Go's actual `mapSession`. Cover the distinction between `null`, empty arrays, and omission, removal of the last peer, fragmented frames, limit violations (depth, value count, and session state boundaries, with a small stack on a secondary thread), absence of Node in the first response, overlapping deltas for one peer within a response, and ensuring `dump` exposes no secrets.

## Unit 4 — ControlClient (`Sources/SwiftailControl/Client/`)

The edge connects the state machines in Units 1~3 to a real connection. It alone owns sockets and clocks.

```swift
/// The node's identity consists of a machine key identifying the device and a node key for WireGuard.
public struct NodeIdentity: Sendable {
    public var machineKey: Curve25519.KeyAgreement.PrivateKey
    /// The registered node key. Nil if it has never been registered.
    public var nodeKey: Curve25519.KeyAgreement.PrivateKey?
    public init()                                   // New machine key, no node key
    public var machinePublicKey: MachinePublicKey { get }
    public var nodePublicKey: NodePublicKey? { get }
}

/// Stores the identity in one file in the directory. This is the only state needed for the node to retain its identity across restarts.
public struct NodeIdentityStore: Sendable {
    public init(directory: URL)
    public func load() throws(ControlError) -> NodeIdentity?    // Nil if the file does not exist
    public func save(_ identity: NodeIdentity) throws(ControlError)
}

public enum ControlError: Error, Sendable {
    case invalidConfiguration(String)
    case storage(String)                    // Failed to read or write the identity file
    case connection(String)                 // Connection or transport-layer failure (retryable)
    case http(status: Int)                  // A response other than 200 (waits for 429 and 503 are handled internally)
    case authKeyRejected(String)            // RegisterResponse.Error from registration with an auth key
    case registrationRejected(String)       // RegisterResponse.Error from registration without an auth key
    case nodeKeyExpired                     // Still expired after reregistering with a new key
    // M2~M7 had `tailnetLockEnabled` (rejecting tailnets with lock enabled). M8 removed it (`SwiftailTailnetLock.md` decision L5).
}

public actor ControlClient {
    public struct Configuration: Sendable {
        public var serverURL: URL             // http:// or https://
        public var hostname: String
        public var authKey: String?           // Sent when registering a new node key. Never logged
        public var ephemeral: Bool
        public init(serverURL: URL, hostname: String, authKey: String? = nil, ephemeral: Bool = false)
    }

    public enum Event: Sendable {
        /// The user must log in at this URL to complete registration.
        case loginRequired(URL)
        /// Registration is complete and the identity has been saved.
        case registered(NodePublicKey)
        /// The netmap changed, including on the first map stream response.
        case netmap(Netmap)
        /// The map stream disconnected. The client backs off and reconnects. The last netmap remains valid meanwhile.
        case disconnected
    }

    /// The node's current status to report. Sent in a request separate from the map stream.
    public struct LocalStatus: Sendable, Equatable {
        public var discoKey: DiscoPublicKey
        public var endpoints: [IPEndpoint]
        public var endpointTypes: [EndpointType]
        public var netInfo: NetInfo?
        public init(discoKey: DiscoPublicKey = .zero, endpoints: [IPEndpoint] = [], endpointTypes: [EndpointType] = [], netInfo: NetInfo? = nil)
    }

    public init(configuration: Configuration, identityStore: NodeIdentityStore)

    /// The event stream has one subscriber and ends when `run()` ends.
    /// Keeps only the newest 64 unread events and discards the oldest first (netmap events always carry the full state).
    public nonisolated var events: AsyncStream<Event> { get }

    /// Registers, publishes status, and maintains the map stream. On disconnection, backs off and reconnects.
    /// Returns only when the calling Task is canceled. Throws for failures that a retry cannot resolve.
    /// Call once per client. A repeated call, whether concurrent or after completion, yields `invalidConfiguration`.
    public func run() async throws(ControlError)

    /// Changes the status. Publishes it shortly if connected, or on the next connection. Retains only the latest value.
    public func setLocalStatus(_ status: LocalStatus)

    /// Requests a new interactive login URL, even when already registered. Emits `disconnected` first because it opens a new connection.
    public func startInteractiveLogin()

    /// Changes the outbound interface (nil leaves it unbound). Closes the current connection and reconnects without backoff.
    public func setNetworkInterface(_ interface: NWInterface?)
}
```

Behavior follows the control-map notes (§4.1, §4.2, §4.4, and §4.5) and the control-transport notes (chapter 4).

1. **Connection** (after disconnection, a conclusion from an already received response, such as a non-retryable registration rejection, takes precedence over a connection error. Wait up to 1 second for an in-flight request to finish on its own). Fetch the server key with `GET <serverURL>/key?v=148` (URLSession). Use the Network framework to open a TCP connection for `http://` or a TLS connection for `https://`. Use the port in the URL if supplied, otherwise use 80 for `http://` and 443 for `https://`. Then proceed through upgrade → Noise → early payload → HTTP/2. Multiplex requests on one connection. If it disconnects, open a new one on the next request.
   - `shortcut:` There is no 80/443 race, ControlDialPlan, or proxy. These become necessary when a network blocking 443 is reported.
   - `shortcut:` When the receiver abandons a response stream because of a deadline, it cancels the stream with RST_STREAM only when more data arrives on it. If unanswered requests accumulate to the server's concurrent stream limit, the next request yields a connection error and triggers reconnection.
   - Verify TLS for `/key` and also for the upgrade connection. Go overlooks verification failures because Noise authenticates the server, and this implementation is stricter.
2. **Registration.** Send `POST /machine/register` with the saved node key if available, otherwise with a new candidate key.
   - Send the auth key when registering a new node key, either on initial registration or when replacing a key after expiration or a new login (a reusable auth key reauthenticates automatically). Omit it when reconnecting after restart with a saved, registered key (a single-use key has already been used. Go tsnet also provides the auth key only when login is required). If it contains `--TL`, send only the part before it.
   - When `AuthURL` arrives, emit `loginRequired` and repeat `Followup` requests (long polling) with the same candidate key. Confirm and save the candidate key only after authentication completes.
   - On `NodeKeyExpired`, try once more with a new key. On `Error`, throw `authKeyRejected` or `registrationRejected` according to whether the request carried an auth key (the app gives the user different guidance, and the server message is for diagnostics). Redact the auth key (the original and the part before `--TL`) from the message and if it exceeds 200 characters, keep the first 200 and append `…`.
   - Deadlines are 120 seconds for a registration request (Go has no such value) and 10 minutes for Followup long polling. Treat expiration as a connection error, then back off and reconnect.
   - Keep the unconfirmed candidate key and Followup URL across reconnections (the login URL the user sees is tied to that candidate key). Discard them only on confirmation, rejection, or a new login request.
   - A `startInteractiveLogin()` requested during registration survives that registration and triggers a new one. Abandon any Followup long poll waiting for login immediately, restart with a new candidate key, and report a new URL.
3. **Status publishing.** Publish Hostinfo, NetInfo, DiscoKey, and Endpoints with a map request using `Stream=false, OmitPeers=true`. Read the entire response body and discard it. Failure to receive the whole response within 120 seconds is a connection error (as in Go's watchdog). Use only this form for changes after the stream opens (other forms make the server close the existing stream).
4. **Map stream.** Use `Stream=true, KeepAlive=true, Compress=""`. Feed bytes through `MapResponseFramer` → `MapSession` and emit a `netmap` event when the netmap changes. Disconnect and reconnect if nothing arrives for 120 seconds. Start with a fresh `MapSession` on reconnection.
   - (M2~M7) If `TKAInfo` indicated that tailnet lock was enabled, stop with `tailnetLockEnabled`. Since M8, synchronize signing authority state and filter peers (`SwiftailTailnetLock.md` behavior N).
   - Restart from registration when the self node's key expires, even if the expiration time passes without a new map. If it is still expired after reregistering with a new key, end `run()` with `nodeKeyExpired`.
   - Answer a `PingRequest` with empty Types by sending HEAD to its URL. Ignore other types.
5. **Backoff.** Use `min(n² × 10ms, 30s) × [0.5, 1.5)`. Reset on receipt of a full netmap, except when the self key in the netmap is expired. For 429 or a 503 with `Retry-After`, wait for the specified duration, up to 5 minutes. If the header is missing, invalid, or gives a delay outside (0, 1 hour], wait 5 seconds plus a random delay in [0, 5 seconds).
6. **Hostinfo.** Use the minimal fields in the notes, §3.3. Report the actual OS name and version and the configured hostname. Identify Swiftail in the app and app version fields so it does not impersonate the official client.
7. **Identity file.** Use one file in the directory (JSON, keys as `privkey:` + base-16 encoding). Write atomically and make it readable only by the owner (0600). Keep keys out of logs, errors, and descriptions. Since M8, include `"NLKey":"nlpriv:<hex encoding of (32-byte seed ‖ 32-byte public key)>"` (the tailnet lock key, `SwiftailTailnetLock.md` behavior R1). Before connecting for the first time, `run()` rewrites older files without `NLKey` with a new NL key and the same machine and node keys (it comes up as the same node). A malformed `NLKey` (length, prefix, base-16 encoding, or the final 32 bytes differing from the seed's public key) yields `storage`. On read, refuse to follow symbolic links (`O_NOFOLLOW`), accept only regular files, and read at most 64KiB (2026-11-17 security verification. Tailnet lock state files use the same rules with a limit of 17MiB). A violation yields `storage`. The directory's owner and permissions are unchecked. The app provides a directory that other users cannot write to (`NodeConfiguration.stateDirectory`).
8. **Secret output.** `NodeIdentity` and `Configuration` adopt `CustomStringConvertible` and `CustomReflectable` to keep private and auth keys out of `print` and `dump` (only public keys and a "redacted" marker appear).
9. **Interface binding** (M5, `SwiftailTunnel` contract behavior N). Send the upgrade connection only through the interface supplied via `setNetworkInterface(_:)` (`requiredInterface` in the Network framework). Leave the connection unbound when its destination is a loopback address or `localhost`.
   - Each call closes the current connection and reconnects without backoff, whether connecting, receiving the map, or waiting in backoff. Even supplying the same interface again reconnects (if only the address on the same Wi-Fi changed, the old connection is dead. The caller decides whether to reconnect). Consecutive calls produce one reconnection with the latest value.
   - Preserve registration state and the last netmap, and report the closed connection as `disconnected`. Reset the backoff count to 0 so failures on the old network do not delay the first attempt on the new one.
   - A call before `run()` only stores the value for the first connection.
   - `shortcut:` The `/key` lookup uses URLSession and remains unbound. The tunnel captures only routes to tailnet addresses and service IPs, so assume the request goes out through a physical interface. If it is observed entering the tunnel on a real device, switch to HTTP/1.1 over `NetworkSocket`.
   - `shortcut:` Handle a network outage (no satisfied path) through connection errors and backoff, with no separate handling.

An internal type wraps one connection (socket, `ControlSession`, `HTTP2ClientConnection`, and read loop). Layer two operations over it, "send one request and receive a response" and "stream a response body." Use those for registration, map streaming, and status publishing. Use structured concurrency (avoid scattering detached Tasks. Cancellation propagates from the Task that calls `run()`).

Unit tests cover identity storage (round trip, file permissions, and corrupted files), backoff calculation, keeping the part of an auth key before `--TL`, parsing Retry-After, and encoding Hostinfo. The gate below covers cases that need a network.

## M2 Gate

Test against `tailnet` in `Tools/interop` (testcontrol + DERP + STUN + Go tsnet peer).

1. `/key` lookup → upgrade → Noise → HTTP/2 → registration (without authentication, and with an auth key).
2. Receive a netmap from the map stream, including the local address, Go peer, DERPMap, DNSConfig, and packet filter.
3. Adding a Go peer makes it appear in the netmap. Injected deltas (`PeersChanged`, `PeersRemoved`, `PeersChangedPatch`, `OnlineChange`) are reflected.
4. The same node key and tailnet address persist after restart.
5. Sending a status update while the stream is open leaves it connected. It stays open for more than 2 minutes and receives KeepAlive messages.
6. The Swift node is visible from Go (`nodes`, `peerStatus`).

To close out the milestone, notify the owner first, then register as an ephemeral node in a real tailnet and check for differences with the production server, particularly uncompressed map responses, production HTTP/2 behavior, and delta responses.
