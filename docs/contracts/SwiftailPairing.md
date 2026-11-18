# Swiftail Pairing Contract (M9)

The goal of M9 is for **two apps using Swiftail to authenticate each other with a single QR code or link**. One side (the host) displays a QR code and link, and the two apps pair when the other side (the joiner) reads it. If the link carries a single-use tailnet auth key, the joiner joins the tailnet without logging in and then pairs. The library also creates that key (Tailscale management API).

On 2026-11-17, another session reviewed the draft design (verdict: fix before implementing), and this revision incorporates its findings. See §9 for the changes. See §11 for the findings of the security verification on the same day (the procedure went through version 2 to version 3).

Owner decisions (2026-11-17):

| | Decision |
| --- | --- |
| U1 | The link handles both pairing and joining the tailnet. The library also creates the single-use auth key |
| U2 | Generate the QR image with CoreImage. The app provides the camera screen for scanning it |
| U3 | Build this as a new library feature. Leave the first adopter's (RemoteDebug's) current pairing as it is and decide separately whether to migrate after this is complete |

References: the first adopter's pairing (`docs/protocol.md` §§2–4.3, `docs/protocol-addenda.md` B.3 and J. Read-only), `tailscale.com` v1.104.7 (the test tools build with v1.104.6. The files below are identical in both versions) `client/tailscale/keys.go` (`CreateKeyWithExpiry`), `cmd/get-authkey/main.go`, `feature/oauthkey/oauthkey.go`, `tailcfg/tailcfg.go` (`CheckTag`), and `golang.org/x/oauth2` v0.37.0 `clientcredentials` and `internal/token.go`. The pairing procedure (§5) is specific to Swiftail and has no Go counterpart.

## 1. Scope

| Included | Reason |
| --- | --- |
| Offer (`PairingOffer`), its link, and its QR code | U1 and U2 |
| Pairing procedure: the host uses a tailnet listener, and the joiner uses an in-process node or an OS socket | An iOS app whose node is in the tunnel extension can only reach the tailnet through OS sockets |
| Host's paired peer list (store, look up, delete) | Used to screen connections after pairing |
| Single-use auth key issuance: OAuth client → API token → key | U1 |

| Excluded | Reason |
| --- | --- |
| Scanning QR codes with the camera, the approval screen, and registering the URL scheme or associated domain that receives links | These are app UI and configuration. The library validates the scanned string |
| Short codes typed by hand | Use only QR codes and links (as requested). The 256-bit secret requires no limit on attempts |
| OAuth client secret storage | The app keeps it in the Keychain. The library receives and uses the value without storing it |
| The rest of the management API, including listing and deleting keys and listing devices | No caller needs them |
| Creating or putting signed (wrapped) tailnet lock auth keys in links | The private key at the end of a wrapped key is not single-use. It can sign any node key until revoked in TKA (Go `tka/sig.go`). A single photo of a QR code must not leak that value |
| Authentication outside the tailnet (direct connection on the same network) | A paired peer's identity is its tailnet node identity |
| Changes to the first adopter's repository | U3 |

Limitations:

- **The host must be an in-process node (`.inProcess`).** `listen` is available only with that device mode. An app whose node is in the tunnel extension can only be the joiner. Two such iPhone apps cannot pair with each other.
- **On a tailnet with lock enabled**, a node that joins with the link's key is locked until signed. The locked node is absent from the host's netmap, so pairing ends with `.unreachable`. The app uses `status.tailnetLock` to explain that a signature is required and retries with the same offer after signing (open the offer with a lifetime long enough for this).
- If the joiner uses an OS socket, the library has no way to verify that the remote peer on a later connection is the peer it paired with. It trusts name resolution (MagicDNS) and WireGuard. An in-process node can compare the `StableID` from `whoIs` with `PairedHost.stableID`.
- The library cannot directly tell whether the joiner's OS socket connection went through the tunnel. It checks that the connection's local endpoint matches the device's tailnet address supplied by the app (`localAddress`) and that the remote endpoint is in the tailnet range, before sending anything (J2). This check is meaningless if the app supplies the wrong address. The address must be the value the tunnel extension read from the node.

## 2. Target

`SwiftailPairing` (new product). Depends on `Swiftail` and `SwiftailBase`. Uses the system frameworks CryptoKit (HMAC, SHA-256, randomness), Foundation's `URLSession` (HTTPS with the management API), Network (joining through an OS socket), and CoreImage (QR). No external packages or C code. The iOS tunnel extension does not link this target.

```
Swiftail ◄─ SwiftailPairing   (CryptoKit, Foundation, Network, CoreImage)
```

Folders: `AuthKey/` (§4), `Offer/` (§3: offer, link, QR), `Protocol/` (value-type state machine from §5), `Store/` (§6), and the edge at the top level (`PairingHost`, `PairingJoiner`).

Apps can use all public API type names with just `import Swiftail` and `import SwiftailPairing` (2026-11-18). The only types from other modules in public declarations are `Swiftail`'s `TailnetNode` and `PeerIdentity` and `SwiftailBase`'s `IPAddress`, and `Swiftail` exports `IPAddress` as an alias (`docs/contracts/SwiftailTunnel.md`, [Types from other modules in the public API](SwiftailTunnel.md#types-from-other-modules-in-the-public-api-2026-11-18)). `SwiftailPairing` does not export its own alias. Apps that use this product already import `Swiftail` to create a node, and exporting the same name from both modules would make some uses ambiguous in files that import both.

## 3. Offers and Links

```swift
/// An offer from the host. The secret and auth key are redacted in `description` and `dump`. Does not conform to `Equatable`.
public struct PairingOffer: Sendable {
    public let host: String        // Host node's MagicDNS FQDN (lowercase, no trailing dot)
    public let port: UInt16
    public let expires: Date       // In seconds. The host determines expiration
    public let authKey: String?    // Add to the node configuration if the joiner is not on the tailnet
    // The 32-byte secret is not public (package).

    /// Creates an offer from a received URL (`url.absoluteString`) or a string scanned from a QR code.
    public init(link: String) throws(PairingOfferError)
    public func url(base: URL) -> URL
    /// Returns an image with one pixel per module and a 4-module margin. The app scales it without interpolation.
    public func qrCode(base: URL) -> CGImage?
}

public enum PairingOfferError: Error, Sendable, Equatable {
    case notAnOffer          // Missing fragment, unknown version or key, duplicate key, or excessive length
    case invalidHost, invalidPort, invalidSecret, invalidExpiry, invalidAuthKey
    case wrappedAuthKey      // Wrapped key (`--TL`)
}
```

A link is `<base>#v=1&h=<host>&p=<port>&s=<secret, 43 base64url characters>&e=<expiration, Unix seconds>[&k=<auth key>]`. The app owns `base` (`myapp://pair`, `https://example.com/pair`).

- O1. All values are in the fragment (after `#`). The fragment is not included in the server request or Referer. If `base` has a fragment, `url(base:)` discards it.
- O2. Parsing is strict. Read only what follows the first `#`. The fragment must be at most 2048 bytes and contain no `%` (none of the characters in the values needs encoding). Accept only `1` for `v` and only the six keys above, each at most once.
  - `h`: A valid DNS name (labels of 1–63 characters, `a-z0-9-`, no leading or trailing hyphen, at most 253 characters in total, at least two labels). The last label must start with a letter (`a-z`) (a top-level domain does not start with a digit. An `xn--` label works). Reject a last label starting with a digit because it looks like an IP address rather than a name (`192.168.1.1`, `1.2`, and hexadecimal forms that the OS parses as IPv4, `192.168.1.0x1`, `1.0x7f`). Requiring a name lets the tunnel's MagicDNS resolve it and prevents an IP address in a link from directing the joiner outside the tailnet. The host checks its own FQDN by the same rule (P9).
  - `p`: A decimal number from 1 to 65535, with no leading zero.
  - `s`: 43 unpadded base64url characters that decode to exactly 32 bytes (spare bits are 0).
  - `e`: A decimal number of 1–11 digits with no sign or leading zero.
  - `k`: At most 256 bytes starting with `tskey-auth-` and using only `A-Za-z0-9-`. Return `.wrappedAuthKey` if it contains `--TL`.
- O3. Errors do not include values. The parser ignores `base`. The app decides which URLs belong to it.
- O4. An offer whose `e` has passed can still be parsed (clocks may differ). The joiner uses `expires` only for display, and the host decides whether to reject the offer.
- O5. The QR code contains the UTF-8 bytes of the link string (`CIQRCodeGenerator`, error correction M). Returns nil if generation fails.

**App requirements**:

- The offer's URL and QR code are secrets. Keep them out of logs, analytics, and conversation history.
- Scanning the QR code with the in-app camera is the safest option. That string does not go through OS link delivery.
- OS-delivered links: Another app that declares the same custom scheme may receive the link. Use an associated domain (universal link) for a link carrying an auth key. The domain's fallback web page must load no third-party scripts and remove the fragment from the address as soon as it opens. Browser history may retain the fragment.
- Links can come from anywhere. For pairing initiated by a link, display `host` and ask the user before pairing.
- Pass the auth key once when starting the node (as a startup option for a tunnel extension) and do not store it. Skip it if already on the tailnet.
- **The auth key is independent of pairing.** Anyone who obtains the link can use the key to join the tailnet while it is valid, regardless of host approval. Approval gates only pairing. The host app therefore gives the key the same short lifetime as the offer (K8) and limits where the key's tag can connect in tailnet policy (ACL) to the pairing and app ports (K7).
- **Opening a link with a key means joining the tailnet that the link points to.** That tailnet's administrator can see this device's node and set policy. Before starting a node from an offer with an `authKey`, the joiner app explains this to the user and asks for confirmation.

## 4. Auth Key Issuance

```swift
public struct TailscaleOAuthClient: Sendable {   // Redacts the secret in description and dump
    public var id: String
    public var secret: String      // tskey-client-…
    public var tags: [String]      // One or more tag:… entries
    public init(id: String, secret: String, tags: [String])   // AuthKeyIssuer.init validates the values
}

public struct AuthKeyIssuer: Sendable {           // Redacts the client secret in description and dump
    public static let defaultBaseURL: URL          // https://api.tailscale.com
    public init(client: TailscaleOAuthClient, baseURL: URL = AuthKeyIssuer.defaultBaseURL) throws(AuthKeyIssueError)
    /// Issues a single-use, preauthorized, non-ephemeral key.
    public func issue(lifetime: Duration) async throws(AuthKeyIssueError) -> IssuedAuthKey
}

public struct IssuedAuthKey: Sendable {          // Redacts key in description and dump
    public let key: String
    public let expires: Date
}

public enum AuthKeyIssueError: Error, Sendable, Equatable {   // Associated values contain no secrets, tokens, keys, or server bodies
    case invalidClient, invalidTags, invalidLifetime, invalidBaseURL
    case clientRejected, unauthorized, forbidden, http(status: Int)
    case invalidResponse, network, cancelled
}
```

- K1. Requests follow the same flow as Go `get-authkey` (`x/oauth2/clientcredentials` + `client/tailscale`).
  1. `POST <base>/api/v2/oauth/token`, `Content-Type: application/x-www-form-urlencoded`. First send `Authorization: Basic base64(<QueryEscape(id)>:<QueryEscape(secret)>)` and the body `grant_type=client_credentials` (`x/oauth2` `internal/token.go:186-205`). If this attempt fails **for any reason** (non-2xx, transport failure, unreadable body, a nonempty `error`, or a missing or empty `access_token`), retry once without `Authorization` and with the body `client_id=…&client_secret=…&grant_type=client_credentials` (key order, `url.Values.Encode`) and classify that result (automatic detection in `internal/token.go:226-243`). Task cancellation is the only exception to retrying. Do not remember the method. Start with Basic on every call (K2). Success requires 2xx, absent or empty `error` in the JSON, and nonempty `access_token` (`internal/token.go:269`, `:326-331`). Do not filter by `token_type`. Do not parse form-encoded token responses.
  2. `POST <base>/api/v2/tailnet/-/keys`, `Authorization: Bearer <token>`, with the same body as Go `CreateKeyWithExpiry`, `{"capabilities":{"devices":{"create":{"reusable":false,"ephemeral":false,"preauthorized":true,"tags":[…]}}},"expirySeconds":<seconds>}` (`client/tailscale/keys.go:93-96`). `get-authkey` calls `CreateKey` (expiration 0) and omits `expirySeconds`, so the Go side of gate 8 calls `CreateKeyWithExpiry`. Only Swift sets `Content-Type: application/json` (Go omits it, `keys.go:103`, `tailscale.go:156-165`). Exclude that header from the comparison. From the 200 response (same as Go, `keys.go:112`), read `key` (starting with `tskey-auth-`) and `expires` (RFC 3339, fractional seconds allowed) from JSON.
- K2. Get a fresh token for every call and do not retain it. Issuance is infrequent.
- K3. Body values are fixed: `reusable` is false, `ephemeral` is false (an ephemeral node loses its StableID and breaks pairing), and `preauthorized` is true (pending approval blocks pairing). Truncate `lifetime` to seconds (Go `int64(expiry.Seconds())`). If it is less than 1 second, send nothing and return `.invalidLifetime`. Set no upper limit (Go has none. Return `.http(status)` if the server rejects it).
- K4. Validation: `id` and `secret` are 1–512 bytes and use only `A-Za-z0-9-_.~` (characters QueryEscape leaves unchanged). `secret` starts with `tskey-client-`. There must be at least one tag and each follows Go `tailcfg.CheckTag` exactly (`tailcfg/tailcfg.go:766-786`): the suffix after `tag:` must be nonempty, start with an ASCII letter, and use only ASCII letters, digits, and `-` thereafter. There is no maximum length. `baseURL` must use `https` (for tests, accept `http` only on loopback hosts `127.0.0.1`, `::1`, and `localhost`). Reject user information, query, or fragment. If it has a path, append `/api/v2/…` to it (as Go does). Return `.invalidClient`, `.invalidTags`, or `.invalidBaseURL` on mismatch.
- K5. HTTP: `URLSessionConfiguration.ephemeral`, 15 seconds per request, no redirects, and read at most 64KiB of the response body. Use no cookies or cache.
- K6. Errors: token request 400 or 401, or 2xx with a nonempty `error` or missing or empty `access_token` → `.clientRejected`, key request 401 → `.unauthorized`, 403 → `.forbidden` (missing `auth_keys` write permission or tag), other statuses (including unfollowed 3xx) → `.http(status)`, unreadable response (including more than 64KiB or a token that cannot go in a header) → `.invalidResponse`, transport failure (including the 15-second timeout) → `.network`, Task cancellation → `.cancelled`. Classify a token request using the final result after retry. Keep secrets, tokens, keys, and server bodies out of errors and logs.
- K7. A node that joins using a key created with an OAuth client is a tagged node. Tailnet policy must allow connections from that tag to **both the pairing port and the app port used after pairing** on the host node (the app explains this).
- K8. An unused key remains valid until expiration. Do not add a deletion request (give the key the same short lifetime as the offer).

## 5. Pairing Procedure

The joiner (J) opens a TCP connection to the host's (H) `host:port`. WireGuard encrypts the connection and authenticates it with both node keys. H learns J's node identity from the connection's remote address (`whoIs`). J verifies H by its proof of knowledge of the offer secret. The proofs bind the two endpoints as seen by both sides. If another node sits in the middle forwarding bytes, the endpoints differ and the proofs do not match.

```
J→H  hello     "SWPR" ‖ 0x03 ‖ commitJ(32) ‖ length(1) ‖ device name (UTF-8, 1–64 bytes)
               commitJ = SHA256("swiftail-pairing-3 commit joiner" ‖ nonceJ)
H→J  challenge status(1) ‖ commitH(32)          status: 0 continue, 1 no open offer (H closes)
               commitH = SHA256("swiftail-pairing-3 commit host" ‖ nonceH)
J→H  proof     nonceJ(32) ‖ HMAC-SHA256(secret, "swiftail-pairing-3 joiner" ‖ P)
H→J  accepted  nonceH(32) ‖ HMAC-SHA256(secret, "swiftail-pairing-3 host" ‖ T)
H→J  decision  D ‖ HMAC-SHA256(secret, "swiftail-pairing-3 decision" ‖ T ‖ D)
               D = status(1) ‖ [if approved: length(1) ‖ H's StableID ‖ length(1) ‖ H's display name]
               status: 1 approved, 2 denied, 3 approval timed out

P = commitJ ‖ commitH ‖ nonceJ ‖ SHA256(offer's host string) ‖ offer's port(2, big-endian) ‖ SHA256(sent device name bytes)
    ‖ J's address(16) ‖ J's port(2) ‖ H's address(16) ‖ H's port(2)    length 198 bytes
T = P ‖ nonceH                                                    length 230 bytes
SAS = first 4 bytes (big-endian) of HMAC-SHA256(secret, "swiftail-pairing-3 sas" ‖ T) mod 1000000, 6 digits
```

**Nonce commitments (version 3).** The SAS has roughly 20 bits, so a party that can choose its own nonce after seeing the other party's nonce can try different values until it gets the number it wants. Both parties therefore fix their nonce before seeing the other's value. J sends its commitment commitJ in `hello` and reveals nonceJ in `proof`. H sends its commitment commitH in `challenge` and reveals nonceH in `accepted`. Neither side can reveal a nonce that differs from its commitment. The two commitments have different labels so a party cannot reflect the other side's commitment as its own.

**Why H delays revealing its nonce.** A party that knows the offer secret can calculate the SAS once it knows both nonces. If H reveals nonceH in `challenge` (version 2), that party can see the number before sending `proof`, then repeatedly disconnect and dial again if the number is not what it wants (disconnecting does not consume the offer, P3). H therefore reveals nonceH only after receiving a valid `proof`. By then the offer is already used (P4), so there is only one chance to see the number and back out. `proof` must be computable without nonceH, so it is computed over P. The subsequent values (`accepted`, `decision`, and the SAS) are computed over T, which also includes nonceH.

Reject version 1 (`0x01`, nonceJ in `hello`) and version 2 (`0x02`, nonceH in `challenge`, label `swiftail-pairing-2`). Neither version had any users.

The addresses are the connection's two endpoints (IPv4 as 16-byte IPv4-mapped IPv6). H and an in-process J use `localEndpoint` and `remoteEndpoint` from `TailnetConnection`. An OS socket J uses the local and remote endpoints of the ready `NWConnection`. Addresses do not change within the tailnet, so both sides see the same four values.

Host:

- P1. When accepting a connection, check `whoIs(remote address)` first. If the identity is unknown, close without reading.
- P2. If there is no open offer or it has expired, read `hello`, send `challenge` with status 1, and close.
- P3. Generate and hold a fresh nonceH per connection and send only its commitment commitH in `challenge`. On receiving `proof`, first check that the revealed nonceJ matches its commitment: `SHA256("swiftail-pairing-3 commit joiner" ‖ nonceJ) == commitJ`. On mismatch, close without sending anything because the format was violated. On a match, construct P and compare the HMAC in constant time. If incorrect, close without sending anything. If either check fails, or if the connection drops or the deadline passes without `proof`, leave the offer intact and do not reveal nonceH (a 256-bit secret cannot be guessed by trying, and consuming the offer on a wrong attempt would let any tailnet peer make it unusable).
- P4. If valid, mark the offer used immediately (single-use). Other connections with the same secret then follow P2. Reveal nonceH, send `accepted`, and wait for the app's decision. This is the first point at which the SAS is computed.
- P5. The app's decision is `decide(PairingRequest) async -> Bool`. The request includes J's `PeerIdentity`, device name, and SAS. **The device name is self-reported by the peer.** Nodes that join with keys from the same OAuth client have the same login name, so the approval screen displays the SAS and asks the user to approve when it matches the number on the joining device's screen. If there is no answer within 120 seconds, use status 3. `decide` must return promptly when canceled (if it ignores cancellation, the connection closes but `run()` cannot finish).
- P6. Keep a read pending while waiting for the decision. Treat EOF, an error, or any bytes as a disconnect and cancel the decision Task. Opening a new offer or calling `closeOffer()` in the meantime does not interrupt the decision.
- P7. On approval, add the peer to the list and save it before sending status 1, and do so only if `whoIs` at that moment returns the same `StableID` as at the start. If saving fails, use status 2. If the connection drops before status 1 is sent, H retains a paired peer and J does not. Pairing again replaces the entry (S1).
- P8. Limits: 8 connections undergoing the procedure, at most 2 from the same node (`StableID`) (close excess connections as soon as they are accepted. One peer cannot hold all slots), 10 seconds from accepting the connection to `proof`, and exactly the message lengths above (close if longer or shorter). Bytes arriving out of turn are a violation. The device name must be valid UTF-8. Reject control characters (Cc) and format characters (Cf, including direction controls). Accept the join controls U+200C and U+200D as the only exceptions (joined emoji, names in Persian and Indic scripts).
- P9. Only one offer at a time. Opening a new offer immediately invalidates the previous one. Default lifetime 300 seconds, range 1–3600 seconds. `openOffer` works before `run()` (connections are accepted once `run()` starts listening). Return `.notRunning` if the node has no FQDN of its own, and `.invalidAuthKey` if `authKey` violates O2.
- P10. Log summaries only (acceptance, reason for closing, decision). Keep secrets, proofs, auth keys, SAS values, names, and addresses out of logs.
- P11. Report changes to the paired peer list and offer via `events` (2026-11-18, removes periodic rereads of `pairedPeers` from the sample app). Events contain no secrets (offer secret or link), proofs, SAS values, or auth keys. Pairing emits the `PairedPeer`, removal emits the `StableID`, and an offer emits only its state. As with `TailnetNode.events`, keep up to the newest 64 unread events and discard the oldest first. The paired peer list can change outside `run()`, so the stream ends when `PairingHost` goes away, independently of `run()`. A child of `run()` (`expireOffers()`) wakes at the open offer's expiration, clears the offer, and reports it (the offer was already unusable, so the procedure is unchanged). When a new offer opens, sleep again until its expiration. Request a 25ms timer tolerance and check after waking whether the wall clock has reached the expiration time. Canceling the consuming Task ends the stream and prevents resubscribing. Calling `run()` again still uses the same stream, so subscribe once where the host is created instead of subscribing again for every `run()`.

Joiner:

- J1. Retry dialing at 1-second intervals for 60 seconds until the first `challenge` arrives. A node that just joined needs time for name resolution, for a path, and to appear in H's netmap (H closes under P1 in the meantime). After 60 seconds, return `.unreachable`.
- J2. OS socket: The app supplies this device's tailnet address (`localAddress`, read from the node by the tunnel extension). Use the same tailnet ranges as the engine (`100.64.0.0/10` excluding `100.115.92.0/23`, and `fd7a:115c:a1e0::/48`). If the local address is outside those ranges, return `.invalidConfiguration` without dialing. Dial `host:port` with `NWConnection` (the tunnel's MagicDNS resolves the name). Pin the IP version to that of `localAddress` (this also filters DNS answers to that version). Restrict no interface types (see the gate 13 result below). Once ready, if **the local endpoint address differs from `localAddress`** or the remote endpoint is outside the ranges above, return `.notOnTailnet` without sending `hello` (do not redial). Checking only the range would let a connection on a local network using the same range through with the tunnel off (carriers and routers also use `100.64.0.0/10`).
  - If `localAddress` is IPv4-mapped IPv6, convert it to IPv4 to determine the range and IP version and compare the local endpoint.
  - Order: the dial completes (`NWConnection` `ready`) → read both endpoints from `currentPath` → range and `localAddress` checks → only then build the session and send `hello`. Before the checks pass, only the TCP handshake (and the OS's DNS query for the offer's host name) can leave the device. `hello` carries a commitment to nonceJ and the device name. Nothing derived from the offer secret is sent before `proof`, which follows `challenge`. T and P also bind both endpoints (§5), so a relaying peer cannot reuse `proof`.
  - No interface restriction: Network.framework treats a path through a VPN as also using the physical interface beneath it (`nw_path_uses_interface_type`: "Paths can use interface types by directly routing over an interface, routing through a tunnel that goes over a physical interface, or being eligble to use multiple interfaces directly."). Prohibiting Wi-Fi and cellular therefore also prohibits the packet tunnel's path, and `NWConnection` stays in `waiting`. Requiring `other` is not a restriction either: `nw_parameters_get_required_interface_type` returns `nw_interface_type_other` "if no interface type is required". The endpoint checks above are what keep pairing on the tailnet.
  - Diagnostics: each dial logs its `NWConnection` state changes to subsystem `Swiftail`, category `pairing` (the host's category). `preparing`, `setup`, and `cancelled` are debug. `ready`, `waiting`, and `failed` are info, with the path status, unsatisfied reason, the interface types the path uses, and the available interfaces with their names and types. These values and the state's error code are public. Local and remote endpoints are private (`<private>` unless a logging profile is installed). The offer secret, auth key, proof, and SAS are never logged. To see them on an iPhone, connect it to a Mac, open Console.app, select the device, enable Action → Include Info Messages and Include Debug Messages, start streaming, and search `subsystem:Swiftail category:pairing`. On a Mac: `log stream --level debug --predicate 'subsystem == "Swiftail" AND category == "pairing"'` (in zsh, call `/usr/bin/log`, because `log` is a shell builtin). Info and debug messages are not persisted by default, so stream them while reproducing.
- J3. Return `.rejected` on `challenge` status 1. Return `.rejected` if the connection closes after sending `proof` without receiving `accepted`.
- J4. Check that nonceH in `accepted` matches the commitment from `challenge`: `SHA256("swiftail-pairing-3 commit host" ‖ nonceH) == commitH`. Return `.hostNotVerified` on mismatch. If it matches, construct T and compare the HMAC in constant time. Return `.hostNotVerified` if incorrect. If correct, call `awaitingApproval(SAS)` and wait for `decision` (the deadline is 130 seconds from sending `proof`. On expiry, return `.timedOut`). Return `.protocolViolation` if the connection closes after `accepted` without `decision`, or if other bytes arrive.
- J5. Compare the `decision` HMAC in constant time. Return `.hostNotVerified` if incorrect. Status must be 1–3, `StableID` must be 1–255 bytes of printable ASCII, and the display name must be 0–64 bytes of valid UTF-8 with the same character rules as the device name (P8). Return `.protocolViolation` on mismatch. Status 2 → `.denied`, 3 → `.timedOut`.
- J6. On approval return `PairedHost` (`host`, `stableID`, `name`, `pairedAt`). The app stores it (`Codable`). When joining through an in-process node, the `StableID` in `decision` must match the one from `whoIs(remote address)`. Return `.hostNotVerified` on mismatch.
- J7. If the calling Task is canceled, close the connection and return `.cancelled`.

```swift
public actor PairingHost {
    /// Throws `.invalidConfiguration` if the node's device is not `.inProcess` or the port is 0,
    /// `.storeUnreadable` if the list cannot be read or another user owns the directory or the group or others can write to it,
    /// and `.storeInUse` if this process already has a host using the same directory.
    public init(node: TailnetNode, port: UInt16, storeDirectory: URL,
                decide: @escaping @Sendable (PairingRequest) async -> Bool) async throws(PairingError)
    /// Listens and runs the pairing procedure. Returns only after cancellation.
    public func run() async throws(PairingError)
    public func openOffer(lifetime: Duration = .seconds(300), authKey: String? = nil) async throws(PairingError) -> PairingOffer
    public func closeOffer()
    public var pairedPeers: [PairedPeer] { get }
    public func pairedPeer(withStableID stableID: String) -> PairedPeer?
    public func removePairedPeer(withStableID stableID: String) throws(PairingError)
    /// Changes to the paired peer list and offer (P11). One subscriber, up to the newest 64 unread events. Ends when this host goes away.
    public nonisolated var events: AsyncStream<Event> { get }

    public enum Event: Sendable, Equatable {
        case pairedPeerAdded(PairedPeer)          // After saving, including when the same node pairs again (S1)
        case pairedPeerRemoved(stableID: String)  // After removePairedPeer removes and saves. Skipped if the peer was absent
        case offerChanged(OfferState)
    }
    public enum OfferState: Sendable, Equatable {
        case opened    // openOffer. No separate notification for the displaced offer (P9)
        case used      // Consumed by a valid proof (P4). Emitted before decide for that connection
        case expired   // At expiration during run(). If it expired outside run(), emitted when run() starts
        case closed    // closeOffer closed an open offer
    }
}

public struct PairingRequest: Sendable {
    public let peer: PeerIdentity
    public let deviceName: String
    public let confirmationCode: String   // 6 digits
}

public enum PairingJoiner {
    /// Joins through an in-process node.
    public static func pair(with offer: PairingOffer, deviceName: String, node: TailnetNode,
                            awaitingApproval: @escaping @Sendable (_ confirmationCode: String) -> Void = { _ in })
        async throws(PairingError) -> PairedHost
    /// Joins through an OS socket (for an app with a node in the tunnel extension). Call after the tunnel connects.
    /// `localAddress` is this device's tailnet address (read from the node by the tunnel extension and passed to the app).
    public static func pair(with offer: PairingOffer, deviceName: String, localAddress: IPAddress,
                            awaitingApproval: @escaping @Sendable (_ confirmationCode: String) -> Void = { _ in })
        async throws(PairingError) -> PairedHost
}

public enum PairingError: Error, Sendable, Equatable {
    case invalidConfiguration(String)   // Device, port, lifetime, device name, or localAddress outside tailnet ranges
    case invalidAuthKey
    case notRunning                     // No FQDN of its own yet, or node has stopped
    case storeUnreadable, storeInUse, storeWriteFailed
    case unreachable                    // No challenge received within 60 seconds
    case notOnTailnet
    case rejected                       // No open offer, expiration, or wrong secret
    case hostNotVerified
    case denied
    case timedOut
    case protocolViolation
    case cancelled
}
```

The app screens connections after pairing: get the connection's identity from `whoIs` or the bridge's `Origin.peer`, then query `pairedPeer(withStableID:)`.

## 6. Paired Peer List

- S1. Entries are `PairedPeer` (`peer: PeerIdentity` (snapshot at pairing), `deviceName`, `pairedAt`). The key is `peer.stableID`. Pairing the same node again replaces its entry. Decisions use only `StableID`. The name is for display. If a node is deleted and registers again, its `StableID` changes and it is no longer paired.
- S2. Store in `storeDirectory/paired-peers.json` (`{"version":1,"peers":[…]}`). For every change, write to a temporary file in the same directory and replace the original. Permissions are 0600. The directory must belong to the current user and be unwritable by the group and others (same rule as `SwiftailCertificates`'s `certs/`). Anyone who can write to that directory can replace the file and add paired peers.
- S3. A missing file means an empty list. If it cannot be read, `init` throws `.storeUnreadable` (without overwriting it with an empty list): non-JSON, different `version`, empty `StableID`, duplicate `StableID`, more than 256 entries, or more than 1MiB. Skip unknown fields. After creating the directory, `init` checks its owner and permissions. If they violate S2, it throws `.storeUnreadable` without reading the file. All file descriptors opened for the file use `O_CLOEXEC`.
- S4. Up to 256 entries. When full, reject a new paired peer (status 2). Replacing an existing `StableID` is allowed.
- S5. Only one `PairingHost` per directory in a process (with two, one can restore a peer the other deleted). There is no interprocess exclusion. `init` creates the directory first (0700, `.storeWriteFailed` on failure) and compares paths with symbolic links resolved.

## 7. Tests and Gates

Unit tests (`SwiftailPairingTests`):

1. Link: round trip, each O2 rejection (`%`, duplicate key, unknown key, wrapped key, boundaries for each value), redacted `description` and `dump`, QR code for the longest link.
2. Fixed vector for the full procedure: match the commitJ, commitH, `hello`, `challenge`, P, T, `proof`, `accepted`, SAS, and `decision` bytes generated by a different implementation (a `Tools/interop` tool written with Go `crypto/hmac` and `crypto/sha256`).
3. Host state machine: normal flow, wrong proof (offer remains and nonceH is not sent), nonceJ differing from its commitment (connection closes and offer remains. nonceJ cannot change after `hello` and `challenge` are exchanged), repeated disconnects after reaching only `challenge` (the joiner receives only commitH, and sending `proof` to see the number consumes the offer), version 1 and 2 `hello`, missing, expired, and changed offers, single use, truncated and oversized messages, out-of-turn bytes, 10 and 120 seconds, limits of 8 total and 2 per node, Cc and Cf in device names, disconnect while awaiting a decision (cancels the decision Task), `StableID` changes at approval, and save failure.
4. Joiner state machine: no nonceJ in `hello`, wrong `accepted`, nonceH differing from its commitment (`.hostNotVerified` even with a valid HMAC), SAS emitted only after `accepted`, wrong `decision` HMAC, unknown status, excessive length, invalid UTF-8, 130 seconds, cancellation, proofs generated with different addresses in T (a node in the middle) do not match, address outside the tailnet ranges, and a connection with a local endpoint different from `localAddress`.
5. Paired peer list: save and reload, pair again, each S3 case, limit, permissions, directory writable by group or others, and two hosts using the same directory.
6. QR: scan the generated image with the system detector and compare with the link, and check the margin.
7. Key issuance: request format (K1) with fake transport, second authentication method, response and error classification (K6), validation (K4), redaction.

Interop gate (a) (without an account, `SwiftailInteropTests`):

8. Go `CreateKeyWithExpiry` (+`clientcredentials`) and Swift send identical requests to the same recording server: method, path, Basic value, and body. Also compare the second request when the server refuses Basic.
9. Two Swiftail nodes on the test control server: offer → join → approve → paired peer list, then `pairedPeer(withStableID:)` answers using the connection's identity. Denial, wrong secret, expiration, pairing again, and matching SAS on both sides.
10. A new node registers with the offer's auth key and then pairs (including J1 redialing).
11. Join through an OS socket: round trip with a host state machine attached to a loopback listener (disable the range checks only in the test. Keep the comparison of the local endpoint and `localAddress` enabled). Send nothing if the local endpoint differs from `localAddress`. Through the public API (range checks on, `localAddress` `100.64.0.1`), the loopback connection comes up and ends with `.notOnTailnet` after the host receives 0 bytes, with the offer still open. A unit test checks that the dial parameters pin the IP version and restrict no interface.

What gate (a) does not cover: the test control server's auth keys have no expiration, single-use policy, or tag policy. Gate (b) checks `whoIs` for tagged nodes (whether their user profile comes in the netmap) and whether the real server accepts Basic. Test 11 bypasses name resolution and the tunnel.

Gate (b), real environment (requires the owner's OAuth client):

12. Create a key with the real management API. Use it to join a real tailnet as a new node and pair. Check whether `whoIs` answers for the tagged node.
13. Pair from an iPhone app (tunnel extension) through an OS socket. Check this when migrating the first adopter (U3). Until then the OS socket path is unverified on a real tunnel.

### Gate 13 Status (2026-11-18, First Adopter, Real iPhone)

Failed with the interface prohibition, fixed, and awaiting a rerun on a real device. With the node in a packet tunnel extension and the app calling `pair(with:deviceName:localAddress:awaitingApproval:)` (`localAddress` = the tunnel's first IPv4 tailnet address, offer host = the Mac's MagicDNS name), the connection never reached the host, on Wi-Fi and on cellular. The app gave up after 60 seconds, and no `.invalidConfiguration` or `.notOnTailnet` surfaced. At the same time, plain HTTP from the same app to the same Mac over the tailnet worked. A build from before the prohibition paired in under 1 second. Cause, from the SDK headers and documentation (J2): prohibiting `wifi` and `cellular` also excluded the tunnel's path, which uses one of them underneath, so `NWConnection` stayed in `waiting` and each attempt counted as unreachable until J1's 60 seconds ran out. The fix removes the prohibition and keeps the endpoint checks, which run before anything is sent. Not observed on the device: the `waiting` state and its unsatisfied reason (the dial diagnostics in J2 now log them). The pinned IP version is an unlikely cause: Swiftail's MagicDNS resolver answers A queries with the node's IPv4 address.

### Gate 12 Results (2026-11-18, Real Server and Real Devices)

Used the sample app (`Examples/PairingDemo`, version 3). The host is the Mac app (sandbox enabled, in-process node), and the joiner is the app on a real iPhone (in-process node). Tailnet lock is enabled.

| Check | Result |
| --- | --- |
| Mac node interactive login and signing | "Waiting for a signature" after registration. Unlocked without restart about 5 seconds after the signing device signed |
| Restart with stored identity (new build) | `running` in about 4 seconds without login. Signature retained |
| Single-use key issuance through the real management API (K1) | Succeeded (OAuth client: `auth_keys` write, one tag) |
| QR scan with the iPhone camera and link opened as a URL | Both parsed as offers |
| iPhone node registration with offer key | `running` without login. Tagged node, joined locked |
| Pairing while locked | `.unreachable` after 60 seconds (J1) |
| Retry with the same offer after signing | Changed to signed without restart and proceeded with pairing |
| SAS | Same on both screens |
| Tagged node `whoIs` | Answered (login name `tagged-devices`) |
| Approval → paired peer list and connection verification | Paired, received a greeting, and `StableID` matched |

Unverified: whether the token request succeeded with Basic or fell back to the body method (the app does not log the distinction), pairing on a network other than the same Wi-Fi (cellular), rejection after removing a paired peer and rejection of reuse (checked with the test control server), and configurations where the iPhone is the host.

## 8. Unverified

- Gate 12 confirmed that the real management API returned a JSON token response and an `expires` value the library could parse. The app did not record whether Basic or the body method succeeded, or the exact `expires` format. Form-encoded token responses are unsupported. The upper limit on lifetime remains unverified.
- Delivery when custom schemes conflict on iOS, and whether the fragment reaches the app when opening an associated domain link (gate 13).
- Whether `CIQRCodeGenerator` adds a margin (check in implementation and add it if absent).
- Whether the address of the OS-socket joiner's `NWConnection` local endpoint matches the tunnel's tailnet address (gate 13). J2 relies on an address match. If the address differs, the OS socket path returns `.notOnTailnet` every time.
- Whether the OS socket joiner pairs through a real packet tunnel without the interface prohibition, on Wi-Fi and on cellular (gate 13 rerun). The diagnosis rests on the SDK documentation and the field symptom. The `waiting` state was not observed on the device.
- When MagicDNS returns both IPv4 and IPv6 addresses for the host's name, whether a connection pinned to `localAddress`'s IP version comes up with an address of that version (gate 13).

### Accepted residual risk

With the tunnel down, if the active network assigns this device exactly its tailnet `localAddress` and routes to a peer in the tailnet ranges, both endpoint checks pass (J2). That peer can receive `hello` (the joiner's nonce commitment and device name) and, after a `challenge`, `proof`. The proof uses HMAC-SHA256 keyed by the offer secret over `"swiftail-pairing-3 joiner" ‖ P`. P binds both IP addresses and ports, so the proof cannot be replayed to the real host. The offer secret comes from `SystemRandomNumberGenerator` and is 32 bytes long, so the HMAC gives no practical offline guessing oracle.

Binding the socket to the provider's `virtualInterface` via `NWParameters.requiredInterface` would require dialing inside the packet tunnel provider. `PairingJoiner` runs in the containing app. The earlier interface-type prohibition also excluded the tunnel itself (gate 13). [Apple's `virtualInterface` documentation](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider/virtualinterface-7l3ol) · [Apple's `requiredInterface` documentation](https://developer.apple.com/documentation/network/nwparameters/requiredinterface)

## 9. Design Review Changes (2026-11-17)

| Finding | Change |
| --- | --- |
| The wrapped auth key's private key is not single-use | Keep it out of links (O2 `.wrappedAuthKey`). Document the locked tailnet flow in the limitations in §1 |
| Proofs are not bound to the connection endpoints, so a node in the middle can relay them, and `decision` is unauthenticated | Addresses and ports of both endpoints in T, HMAC on `decision`, OS socket range check (J2) |
| If someone who obtained the link joins first, the approval screen cannot distinguish them | SAS (P5, J4) |
| The fragment can leak through fallback page scripts and browser history. Another app can receive a custom scheme | Fix O1 and document this under "App requirements" |
| `k` can contain `&` or `%`, and `e` has no upper bound | O2 character set and digit count, ban on `%` |
| Key issuance differs from Go (`expirySeconds`, second authentication method, `CheckTag`, `error` in 2xx) | K1, K3, K4, K6, gate 8 |
| The host only works with `.inProcess`. Lookup must work with the bridge's `Origin.peer` | Limitations in §1, `pairedPeer(withStableID:)` |
| A single connection attempt can easily fail right after joining. Connection failure and rejection were grouped together | J1 (redial for 60 seconds), `challenge` status, `.unreachable` and `.rejected` |
| Starting the clock at `hello` leaves silent connections. A way to detect disconnect while awaiting a decision | P8 (10 seconds from acceptance), P6 |
| Direction controls in device names | Reject Cf too (P8) |
| Items to cut | Removed `ephemeral` and `preauthorized` parameters, `IssuedAuthKey.id`, `init(url:)`, `moduleSize`, `Equatable`, and `PairedHost.port` |

## 10. Code Review (2026-11-17)

A session other than the author checked the entire implementation against each contract item. Its verdict was "can be released as is," with three low-severity findings.

| Finding | Resolution |
| --- | --- |
| The key for a path through a symbolic link differs before and after directory creation, bypassing S5 (reproduced) | `init` creates the directory first. Added a test |
| If `decide` ignores cancellation, `run()` cannot finish | Documented in the doc comment and P5 |
| `url(base:)` hides a construction failure by returning `base` | `preconditionFailure` |

Remaining: no test directly checks the edge `PairingHost`'s 10-second deadline, limit of 8, or read limit (state machine tests and gate 9 check them indirectly). U+2028 and U+2029 are accepted in a device name. (A single peer blocking all 8 slots and the node's `StateDirectoryClaims` were fixed in §11.)

## 11. Security Verification (2026-11-17)

Another session read the implementation and reproduced the findings below. The table records their resolutions. The procedure's bytes changed to version 2 (version 1 is rejected. Nothing used it).

| Finding | Resolution |
| --- | --- |
| The SAS comes from two nonces, and the party that chooses its nonce later can see the peer's value and try its own values to get the desired number (20 bits) | Nonce commitment (§5): commitJ in `hello`, reveal nonceJ in `proof`. Add commitJ to T and change the label to `swiftail-pairing-2`. Regenerated the fixed vector |
| The OS socket range check lets through a connection on a local network using the same range while the tunnel is off | `localAddress` (public API), comparison with the local endpoint, and pinned IP version (J2). The interface prohibition added here kept the tunnel's path from coming up and was removed after gate 13 |
| One tailnet peer can keep reopening 8 connections to occupy the pairing slots | Limit connections in the procedure to 2 per `StableID` (P8) |
| The offer's `host` can be an IP address | `.invalidHost` if the last label contains only digits (O2) |
| If others can write to the paired peer list directory, they can replace the file and add paired peers | `init` checks the owner and permissions (S2 and S3) |
| The auth key is independent of pairing. Opening a link carrying a key means joining that tailnet | "App requirements" in §3 and doc comments on `PairingOffer.authKey` and `openOffer` |

Second round (same day, remaining findings after another session rechecked the fixes above). The procedure's bytes changed again to version 3 (version 2 is also rejected. Nothing used it).

| Finding | Resolution |
| --- | --- |
| In version 2 the host reveals nonceH immediately in `challenge`. A party that knows the offer secret can compute the SAS before sending `proof`, and repeatedly disconnect and dial again if the number is not what it wants (disconnecting neither consumes the offer nor counts toward any limit) | Host also commits its nonce (§5): commitH in `challenge`, nonceH in `accepted` after a valid `proof`. Compute `proof` over P and the rest over T = P ‖ nonceH. Changed the label to `swiftail-pairing-3` and distinguished the labels of the two commitments. Regenerated the fixed vector |
| Rejecting only an all-digit last label in the offer's `host` lets hexadecimal IPv4 forms through (`192.168.1.0x1`, `1.0x7f`) | The last label must start with a letter (O2) |
