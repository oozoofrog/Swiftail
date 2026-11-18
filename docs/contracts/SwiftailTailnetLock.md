# Swiftail Tailnet Lock contract (M8 ①, draft)

M8 ① aims for **an ordinary node that makes the same decisions as a Go node on a tailnet with lock enabled** (`docs/plan.md` §3 and §7 M8). It registers (with a signed auth key, `--TL`, or with a signing device signing later), receives, verifies, and saves the signing authority state (TKA), filters unsigned peers out of the netmap, and accepts disablement only after verifying the disablement secret. Lock is enabled on the first adopter's (RemoteDebug) Mac host tailnet, making this feature a prerequisite for replacing the Mac host.

This document is a **draft**. Before implementation, resolve "Lead session confirmation required" and "Owner confirmation required," and send "First adopter confirmation required" to the first adopter's session before finalizing.

Protocol details follow only [tailnet-lock.md](../protocol-notes/tailnet-lock.md) (the "notes" below, verified by another session on 2026-11-15 against `tailscale.com` v1.104.7 source and by execution). Where the notes had no coverage and the Go source was read directly, `path:line` references are given relative to the `tailscale.com@v1.104.7` module. This document defines only scope, targets, API, behavior, limits, decisions, tests, and gates.

Relationship to existing contracts. Add signature creation to [SwiftailControl.md](SwiftailControl.md) unit 4 behavior 2 ("if it contains `--TL`, send only the preceding part") and remove behavior 4's "if `TKAInfo` indicates tailnet lock is enabled, end with `tailnetLockEnabled`" and `ControlError.tailnetLockEnabled`. Replace the entry in [SwiftailHost.md](SwiftailHost.md) §4, "`NetworkLockStatus` diagnostic log → absent. A tailnet with lock enabled ends with `tailnetLockEnabled`," with this document's `TailnetLockStatus`. This document closes plan §8 risk 8 and §9's "handling tailnets with tailnet lock enabled." This document takes precedence in case of conflict.

Settled decisions (closed to further discussion):

- **Implement Ed25519 verification directly in pure Swift** (owner decision, 2026-11-15, notes §6.1 (b)). Support both ZIP-215 and Go standard rules. Use CryptoKit (`Curve25519.Signing`) to create signatures.
- Two cryptographic primitives are **prerequisite units** from another session. `Sources/SwiftailCrypto/Ed25519Verification.swift` (`Ed25519Verification.isValidZIP215(signature:message:publicKey:) -> Bool`, `isValidStandard(signature:message:publicKey:) -> Bool`, with `[UInt8]` arguments), and `Sources/SwiftailCrypto/BLAKE2b.swift` and `Argon2i.swift` (`BLAKE2b.hash(_:outputByteCount:key:)`, `Argon2i.derive(password:salt:iterations:memoryKiB:parallelism:outputByteCount:) -> [UInt8]`). This contract depends only on their declarations.
- Go state migration is out of scope. The storage format differs from Go's (tailchonk) (notes §6.3).
- The library is entirely Swift, with value-type state machines, edge I/O, typed errors, and input validation at boundaries (plan §5 code standards).

## 1. Goals and scope

| Included | Basis (notes) |
| --- | --- |
| Generating and storing the NL key and always including it in `RegisterRequest.NLKey` | 4.6 item 1, 6.3 |
| Parsing a signed auth key (`--TL`) and `SignByCredential` | 3.8, 4.6 item 2 |
| Server re-signing request (`RegisterResponse.NodeKeySignature`) → `ResignNKS` (including chain trimming) | End of 4.4, 4.6 item 4 |
| `MapRequest.TKAHead` | 3.9, 4.7 |
| Bootstrap (TOFU on the first checkpoint received), synchronization (offer and send), and admitting AUMs (`Inform`) | 4.3, 4.8 |
| AUM verification and state application, fork resolution, and head computation | 4.1–4.3 |
| NKS verification (direct, rotation, credential), peer filtering, and keys made obsolete by rotation | 4.4, 4.9 |
| Removing lock only after verifying the disablement secret | 4.5, 4.10 |
| Telling the app when the local node is locked out and awaiting a signature | 4.6 item 3, 6.3 |
| Persisting signing authority state locally and resuming after restart | 3.11, 6.3 |
| **Verifying** products of signing devices (AUM chains, forks created by recovery AUMs, signatures, and wrapped auth keys) | Chapter 2 |

| Excluded | Reason | When needed |
| --- | --- | --- |
| Acting as a signing device, including signing other nodes, commands to enable or disable lock, adding or removing signing keys, wrapping auth keys, creating recovery AUMs, signing deep links, and listing affected signatures | Outside M8 scope (plan §3, notes chapter 2) | An adopter needs a Swiftail node to act as a signing device |
| Local force-disable and `DisallowedTKAStateIDs` | The list is always empty without force-disable (notes §6.3) | When adding force-disable |
| A switch corresponding to `TS_UNSAFE_SKIP_NKS_VERIFICATION` | Filtering cannot be disabled (notes §4.9) | — |
| c2n `/debug/tka/log` | tsnet omits it too (notes chapter 2) | — |
| Compaction | Decision L7. Reduces only storage while preserving decisions | A tailnet reports storage reaching its limit (behavior M) |
| Installing `UnsignedPeerAPIOnly` peers in the data plane | Already excluded (`Sources/SwiftailEngine/EnginePeer.swift:94-103`). Keeps the existing difference (notes §6.3) | When adding a feature such as Funnel ingress |
| Reading Go state (tailchonk, `Persist.NetworkLockKey`) | Owner decision | — |

## Targets and dependency direction

| Target | Kind | Additions in M8 ① |
| --- | --- | --- |
| `SwiftailCrypto` | Existing | (Prerequisite unit, in progress) `Ed25519Verification`, `BLAKE2b`, `Argon2i` |
| `SwiftailTKA` | **New target** (`package` access, outside the exported products) | CBOR reading and writing, `AUMHash`, `TrustedKey`, `AUMSignature`, `AUM`, `AuthorityState`, `NodeKeySignature`, the `Authority` signing authority state machine, NKS verification and creation, and signed auth key parsing. No sockets, files, or clock |
| `SwiftailControl` | Existing | NL key (`NodeIdentity` and `NodeIdentityStore`), tailcfg additions (TKA RPC set, `MapRequest.TKAHead`), registration request signatures, TKA RPCs, persistence (`TailnetLockStore`), procedure on netmap receipt and peer filtering, `TailnetLockStatus`, and changes to `Netmap` and `ControlError` |
| `Swiftail` | Existing | `NodeStatus.tailnetLock`, `NodeEvent.tailnetLockChanged` |

```
SwiftailBase ◄─┐
SwiftailCrypto ◄─ SwiftailTKA ◄─ SwiftailControl ◄─ SwiftailEngine ◄─ Swiftail
                  (CryptoKit)
```

- **Why a new target** (decision L1). ① Matches Go's boundary. Data formats and verification are in the `tka` package, and the procedure is in `ipnlocal` and `controlclient` (notes chapters 3 and 4). ② Pure logic with no I/O needs no `SwiftailControl` dependencies (HTTP/2, sockets), and tests against Go reference values run without the control client. ③ File ownership follows target boundaries, allowing parallel implementation and separate review (§8). ④ `package` access keeps the public surface the same (as with `SwiftailNetstack`).
- Keep CBOR inside `SwiftailTKA`, since TKA is its only consumer (same reasoning as `SwiftailHost.md` H14). Keep only cryptographic primitives in `SwiftailCrypto`.
- The iOS tunnel extension also becomes a node on a tailnet with lock enabled, so this is a `SwiftailControl` dependency and remains outside optional products.
- The `SwiftailControl` public surface exposes no TKA types (`TailnetLockStatus` contains only strings and numbers).

### Where lock is currently handled

| Location | Current | After the change |
| --- | --- | --- |
| `Sources/SwiftailControl/Tailcfg/RegisterRequest.swift:20`, `:32`, `:38`, `:44` | `nlKey` defaults to `.zero`, and `nodeKeySignature` is empty. The fields and encoding (`:76`, `:82`) already exist | Populate the values (behavior R) |
| `Sources/SwiftailControl/Client/ControlClient+Registration.swift:44-53` | Registration request creation omits the NL key and signature | Behaviors R2 and R5 |
| `Sources/SwiftailControl/Client/ControlClient+Registration.swift:76-79` | `RegisterResponse.NodeKeySignature` produces `ControlError.tailnetLockEnabled` | Re-sign with the new node key and register again (behavior R6) |
| `Sources/SwiftailControl/Client/AuthKey.swift:10-13` | Discards everything after `--TL` and returns only the prefix | Send the prefix to the server as is and parse the suffix for signing (behavior R3) |
| `Sources/SwiftailControl/Client/NodeIdentity.swift:12-31`, `NodeIdentityStore.swift` (`identity.json`) | Machine and node keys only | Add the NL key (behavior R1) |
| `Sources/SwiftailControl/Tailcfg/NLPublicKey.swift:5-9` | "Always sends the field despite having no lock implementation" | Update only the comment |
| `Sources/SwiftailControl/Tailcfg/MapRequest.swift` | No `TKAHead` | Add it (behavior N4) |
| `Sources/SwiftailControl/Tailcfg/TKAInfo.swift:6`, `MapResponse.swift:48` | Decode only | Unchanged |
| `Sources/SwiftailControl/Netmap/MapSession.swift:44`, `:99-101`, `:218` | Holds `TKAInfo` in the session and sets `tailnetLockEnabled = !disabled`. Skips parsing `Head` (`shortcut:`) | Compute using Go's `TKAEnabled` and `TKAHead` rules (behavior N1) |
| `Sources/SwiftailControl/Netmap/MapSession.swift:158`, `:240`, `:255`, `Tailcfg/Node.swift:34`, `PeerChange.swift:29` | Reflects `KeySignature` in the netmap | Unchanged (input to filtering) |
| `Sources/SwiftailControl/Netmap/Netmap.swift:23` | `tailnetLockEnabled: Bool` | `tailnetLock: TailnetLockStatus` |
| `Sources/SwiftailControl/Client/ControlClient+MapPoll.swift:82`, `:101-104`, `ControlClient.swift:142-143` | Records `lastTKAInfo` and ends with `tailnetLockEnabled` for a netmap with lock enabled | Run the procedure and emit a filtered netmap (behaviors N and P) |
| `Sources/SwiftailControl/Client/ControlError.swift:25`, `:33` | `case tailnetLockEnabled` | Remove (decision L5) |
| `Sources/SwiftailControl/Tailcfg/Node.swift:66`, `:146`, `Sources/SwiftailEngine/EnginePeer.swift:94-103` | Narrows `UnsignedPeerAPIOnly` peers' `allowedIPs` to their own addresses and excludes them from the engine | Unchanged (behavior P1) |
| `Sources/Swiftail/NodeError.swift:9`, `Sources/Swiftail/TailnetNode.swift:477`, `Sources/SwiftailCertificates/CertificateManager.swift:392` | Comment and `switch` branches referring to `tailnetLockEnabled` | Remove the branches |
| First adopter `Apps/iOSTunnel/SwiftailTunnelEngine.swift:180` (read only) | Adds user-facing text to `.control(.tailnetLockEnabled)` | First adopter removes it (first adopter confirmation required F1) |

## 2. Draft API

### `SwiftailTKA` (`package`)

```swift
import CryptoKit
import SwiftailBase

// MARK: CBOR (notes §§3.1 and 6.2)

/// A decoded CBOR data item. Includes types used by TKA structures and those needed to skip unknown fields.
package enum CBORValue: Sendable, Equatable {
    case unsigned(UInt64)
    /// The negative integer `-1 - n`. Appears only as a key or value of an unknown field.
    case negative(UInt64)
    case bytes([UInt8])
    /// The text bytes. UTF-8 is unchecked here (even invalid UTF-8 is skipped for unknown field values. Behavior D6).
    case text([UInt8])
    case array([CBORValue])
    case map([CBORPair])
    /// null (0xf6) and undefined (0xf7). Re-encodes as 0xf6. Go's decoder treats undefined like null and reads it as the
    /// zero value for known fields (`nextCBORNil` in `fxamacker/cbor` `decode.go`. TL-1 verified this and updated the draft declaration).
    case null
    /// The remaining major type 7 items (false, true, simple values, and floats). Discards the value. Cannot appear in known fields.
    case simpleOrFloat
}
package struct CBORPair: Sendable, Equatable {
    package var key: CBORValue
    package var value: CBORValue
}

package enum CBORError: Error, Sendable, Equatable {
    case truncated          // Empty input or input that ends within an item
    case trailingBytes      // Bytes left over after the first item
    case indefiniteLength
    case tag
    case malformed          // Ill-formed items, such as reserved additional information
    case nestingTooDeep     // 17 levels
    case arrayTooLong       // 4,097 elements
    case mapTooLong         // 1,025 pairs
}

package enum CBOR {
    /// Decodes one item. The full input must be exactly one item. See behavior D for limits and rejection rules.
    package static func decode(_ bytes: [UInt8]) throws(CBORError) -> CBORValue
}

/// Writes canonical (CTAP2) encoding in one direction. Cannot write indefinite lengths, tags, or floats.
/// The caller writes map pairs in canonical order (ascending integer keys for structures, behavior E3 for `Meta`).
package struct CBORWriter: Sendable {
    package init()
    package private(set) var bytes: [UInt8]
    package mutating func unsigned(_ value: UInt64)        // Shortest length
    package mutating func byteString(_ value: [UInt8])
    package mutating func textString(utf8 value: [UInt8])
    package mutating func null()
    package mutating func arrayHeader(count: Int)
    package mutating func mapHeader(count: Int)
}

// MARK: Data formats (notes §§3.2–3.8)

/// A 32-byte AUM hash (Go `tka.AUMHash`). Compares bytes (text can differ in the last character and still represent the same hash. Notes §3.8).
package struct AUMHash: Sendable, Hashable {
    package init?(_ bytes: [UInt8])          // nil unless 32 bytes
    /// Parses 52 unpadded characters in the standard base32 alphabet (uppercase). Returns nil for lowercase, padding, or other lengths.
    package init?(text: String)
    package var bytes: [UInt8] { get }
    package var text: String { get }
}

/// A pair in `Meta`. Stored without converting to Swift `String`. Swift compares `String` values by Unicode canonical equivalence, which differs from Go's byte comparison
/// and changes the re-encoded hash (behavior E3).
package struct MetaEntry: Sendable, Equatable {
    package var key: [UInt8]      // Validated UTF-8
    package var value: [UInt8]    // Validated UTF-8
}

/// A key with signing authority (Go `tka.Key`). The KeyID is the raw `publicKey` bytes.
package struct TrustedKey: Sendable, Equatable {
    package var kind: UInt8               // 1 = Key25519
    package var votes: UInt64
    /// The public key, with nil representing CBOR null. Null and empty byte strings encode differently and are distinguished (behavior E4).
    package var publicKey: [UInt8]?
    package var meta: [MetaEntry]         // Canonical order. Omitted from encoding when empty
    package func validate() throws(TKAError)          // Go `Key.StaticValidate`
}

/// A signature attached to an AUM (Go `tkatype.Signature`).
package struct AUMSignature: Sendable, Equatable {
    package var keyID: [UInt8]
    package var signature: [UInt8]
}

/// A message that updates signing authority state (Go `tka.AUM`).
package struct AUM: Sendable, Equatable {
    package var messageKind: UInt8
    package var prevAUMHash: [UInt8]?     // nil = no parent (encoded as null)
    package var key: TrustedKey?
    package var keyID: [UInt8]            // Omitted from encoding when empty
    package var state: AuthorityState?
    package var votes: UInt64?            // Encoded if present, even if 0
    package var meta: [MetaEntry]?        // nil and an empty map differ only in validation (both are omitted from encoding)
    package var signatures: [AUMSignature]

    /// Decodes within the limits of behavior M and the rules of behavior D. Skips static validation.
    package init(decoding bytes: [UInt8]) throws(TKAError)
    /// Returns canonical CBOR. Hashing and signature verification use these bytes in place of the received bytes (behavior E5).
    package func serialized() -> [UInt8]
    package var hash: AUMHash { get }                  // BLAKE2s-256(serialized())
    package var signatureHash: [UInt8] { get }         // BLAKE2s-256 with signatures removed
    package func validate() throws(TKAError)           // Go `AUM.StaticValidate`
}

/// Trust state after applying updates through a particular AUM (Go `tka.State`).
package struct AuthorityState: Sendable, Equatable {
    package var lastAUMHash: AUMHash?
    package var disablementValues: [[UInt8]]
    package var keys: [TrustedKey]
    package var stateID1: UInt64
    package var stateID2: UInt64
    /// Returns the new state after applying a verified AUM (Go `applyVerifiedAUM`). Behavior A6.
    package func applying(_ update: AUM) throws(TKAError) -> AuthorityState
}

/// A signature for a node key (Go `tka.NodeKeySignature`). Stores `nested` indirectly for value-type recursion.
package struct NodeKeySignature: Sendable, Equatable {
    package var kind: UInt8               // 1 direct, 2 rotation, 3 credential
    package var publicKey: [UInt8]        // "np" ‖ 32-byte node public key
    package var keyID: [UInt8]
    package var signature: [UInt8]
    package var nested: NodeKeySignature? { get set }
    package var wrappingPublicKey: [UInt8]
    package init(decoding bytes: [UInt8]) throws(TKAError)
    package func serialized() -> [UInt8]
    package var signatureHash: [UInt8] { get }
}

// MARK: Signing authority state machine (notes §§4.1–4.5 and 4.8)

/// An offer exchanged during synchronization, with the head and ancestors for finding an intersection (Go `tka.SyncOffer`).
package struct SyncOffer: Sendable, Equatable {
    package var head: AUMHash
    package var ancestors: [AUMHash]
}

/// The history of a verified rotation signature (Go `tka.RotationDetails`). Used to identify obsolete keys (behavior P4).
package struct RotationDetails: Sendable, Equatable {
    package var previousNodeKeys: [NodePublicKey]     // Newest first
    package var initialSignature: NodeKeySignature    // Innermost non-rotation signature
}

/// Input for evaluating one peer.
package struct PeerCredential: Sendable {
    package var nodeKey: NodePublicKey
    package var keySignature: [UInt8]
}

/// A tailnet's signing authority state. A value type holding all admitted AUMs and the head and trust state computed from them.
/// Has no sockets, files, or clock. The edge (`TailnetLockStore`) persists `aums`.
package struct Authority: Sendable {
    /// Bootstraps from one server-provided checkpoint (Go `Bootstrap`). Verifies signatures against the checkpoint's own state (behavior F5).
    package init(bootstrappingWith checkpoint: AUM) throws(TKAError)
    /// Recomputes from persisted AUMs (Go `Open`). Behaviors F6 and T3.
    package init(opening stored: [AUM], bootstrap: AUMHash) throws(TKAError)

    package var head: AUMHash { get }
    package var state: AuthorityState { get }
    /// The hash of the bootstrap AUM. The sole root of the store.
    package var bootstrap: AUMHash { get }
    /// All admitted AUMs (active chain and forks) for persistence.
    package var aums: [AUM] { get }

    /// Admits a group of AUMs in arrival order (Go `Inform`). Any failure leaves everything unchanged (behavior F4).
    package mutating func inform(_ updates: [AUM]) throws(TKAError)
    /// Returns an offer to send to the server (Go `SyncOffer`). Behavior Y1.
    package func syncOffer() throws(TKAError) -> SyncOffer
    /// Returns local AUMs unknown to the peer based on its offer (Go `MissingAUMs`). Behavior Y4.
    package func missingAUMs(for remote: SyncOffer) throws(TKAError) -> [AUM]

    /// Verifies that this node key is authorized by the current state (Go `NodeKeyAuthorizedWithDetails`). Throws if unauthorized.
    /// Returns the history for an outer rotation signature and nil for a direct one. Behavior S.
    package func authorize(_ nodeKey: NodePublicKey, keySignature: [UInt8]) throws(TKAError) -> RotationDetails?
    /// Evaluates a peer set by verifying signatures and identifying keys made obsolete by rotation (Go `tkaFilterNetmapLocked` items 2–5). Returns "keep" flags in input order.
    package func admitted(_ peers: [PeerCredential]) -> [Bool]
    /// Checks whether a disablement secret is valid (Go `ValidDisablement`). Uses 16MiB once for Argon2i (behavior X).
    package func isValidDisablement(secret: [UInt8]) -> Bool
}

// MARK: Signature creation (notes §§3.8 and 4.6)

/// A parsed auth key with `--TL`. Holds a wrapped private key and hides its contents from `description` and `dump`.
package struct WrappedAuthKey: Sendable {
    /// The part to send to the server (before `--TL`).
    package let controlValue: String
    /// Parses an auth key, returning nil without `--TL`. If present, any failure of behavior R3's checks throws before anything is sent to the server.
    package init?(parsing authKey: String) throws(TKAError)
    /// Returns a signature for a new node key (Go `SignByCredential`), as canonical bytes of a rotation NKS nesting the credential.
    package func keySignature(for nodeKey: NodePublicKey) throws(TKAError) -> [UInt8]
}

extension NodeKeySignature {
    /// Extends the old signature to the new node key (Go `ResignNKS`, including chain trimming). Behavior R7.
    package static func resigned(
        _ previous: [UInt8], for nodeKey: NodePublicKey, with lockKey: Curve25519.Signing.PrivateKey
    ) throws(TKAError) -> [UInt8]
}

package enum TKAError: Error, Sendable, Equatable {
    case cbor(CBORError)
    /// Valid CBOR with an invalid structure. Non-map at the top level, unsupported key type, duplicate key, invalid type or range of a known field, or invalid UTF-8.
    case invalidStructure
    /// Failed static validation (`StaticValidate` and checkpoint state validation).
    case invalidAUM
    case emptyUpdate            // Empty group
    case missingParent          // Attempt to admit an AUM without a parent, or unknown parent
    case unsigned               // No signatures
    case untrustedSigner        // Signature whose KeyID is not trusted
    case invalidSignature
    /// Failed application due to parent hash mismatch, existing or missing key, removal of the last key, mismatched StateID, or invalid updated key.
    case rejectedUpdate
    case notACheckpoint         // Bootstrap AUM is not a checkpoint
    case corruptStore           // Stored AUMs do not form a chain (behavior T3)
    case iterationLimit
    case noIntersection
    /// The node key is unauthorized (failure at any step of behavior S).
    case unauthorized
    case invalidAuthKey         // The suffix after `--TL` violates behavior R3
    case signingFailed
    case limitExceeded          // A limit in this contract (behavior M)
}
```

`SignByCredential` and `ResignNKS` are impure because they sign with CryptoKit (CryptoKit produces a different signature each time even for the same key and message. Notes §8.1). Tests verify signatures without comparing their bytes (the same exception as ECDSA in `SwiftailHost.md` behavior C).

### `SwiftailControl`

```swift
/// The current tailnet lock status. `ControlClient` fills it for every netmap. Contains no private keys or secrets.
public struct TailnetLockStatus: Sendable, Equatable {
    public enum Mode: Sendable, Equatable {
        /// Lock is absent. There is no local signing authority state, and either the server did not report lock enabled or the node lacks the `tailnet-lock` capability.
        case disabled
        /// Holds verified signing authority state and uses it to filter peers.
        case enforcing
        /// No basis for filtering. Either the server reports lock enabled but bootstrap failed, or persisted state could not be opened.
        /// Installs no peers (owner confirmation required U1).
        case unverified
    }
    public var mode: Mode
    /// The local head (52-character base32). Present only in `.enforcing` mode.
    public var head: String?
    /// The number of peers removed from the netmap for missing or unverified signatures or obsolete keys.
    public var filteredPeerCount: Int
    /// The values to give a signing device when the current state cannot verify the local node's signature (locked out). Nil otherwise.
    public var signingRequest: SigningRequest?
    /// Whether the local node is locked out. It cannot communicate with peers enforcing lock until a signing device signs it.
    public var isLockedOut: Bool { get }

    /// The two values for `tailscale lock sign <nodeKey> <lockKey>` on a signing device. Both are public keys.
    public struct SigningRequest: Sendable, Equatable {
        public var nodeKey: String      // `nodekey:` + hex
        public var lockKey: String      // `tlpub:` + hex
    }
}

public struct Netmap: Sendable, Equatable {
    // …
    /// The tailnet lock status. `peers` is already filtered against it in the netmap emitted by `ControlClient`.
    public var tailnetLock: TailnetLockStatus          // Replaces `tailnetLockEnabled: Bool`
}

public struct NodeIdentity: Sendable {
    // …
    /// The tailnet lock key (NL key). Remains fixed once created. `init()` generates a new key.
    public var lockKey: Curve25519.Signing.PrivateKey
}

public enum ControlError: Error, Sendable {
    // Removes `tailnetLockEnabled` and adds no cases.
    // An auth key with a malformed suffix after `--TL` is `invalidConfiguration` (behavior R3).
}

// package·internal
public struct MapRequest {
    /// The local head in base32. An empty string omitted from JSON when there is no lock state (`TKAHead`, omitzero).
    public var tkaHead: String
}
/// The server-reported lock state (Go `netmap.TKAEnabled` and `TKAHead`). Computed by `MapSession` (behavior N1).
package struct ServerLockState: Sendable, Equatable {
    package var isEnabled: Bool
    package var head: AUMHash?
}
extension MapSession.Update {
    /// The current session value. Included even in responses that leave the netmap unchanged.
    package var serverLock: ServerLockState
}
/// The action to take on netmap receipt (Go `tkaSyncIfNeeded` branches). Evaluated without I/O (behavior N2).
enum TailnetLockPlan: Equatable {
    case nothing
    case bootstrap                 // No local state, server enabled
    case synchronize               // Local state present, heads differ
    case verifyDisablement         // Local state present, server disabled
    init(localHead: AUMHash?, hasCapability: Bool, server: ServerLockState)
}
/// Stores signing authority state in one file in the state directory (behavior T).
struct TailnetLockStore: Sendable {
    init(directory: URL)
    func load() throws(ControlError) -> Authority?        // nil if no file. Throws if it cannot be opened
    func save(_ authority: Authority) throws(ControlError)
    func remove() throws(ControlError)
}
// tailcfg: TKABootstrapRequest/Response, TKASyncOfferRequest/Response, TKASyncSendRequest/Response (internal, Codable)
extension ControlClient {
    func tkaBootstrap(head: AUMHash?, over connection: ControlConnection) async throws -> TKABootstrapResponse
    func tkaSyncOffer(_ offer: SyncOffer, over connection: ControlConnection) async throws -> TKASyncOfferResponse
    func tkaSyncSend(head: AUMHash, missing: [AUM], over connection: ControlConnection) async throws -> TKASyncSendResponse
}
```

`ControlClient` public declarations (`init`, `Configuration`, `Event`, `run()`) stay the same. The netmap in `Event.netmap` is now filtered and contains `tailnetLock`. The storage location comes from the `NodeIdentityStore` directory without a new argument.

### `Swiftail`

```swift
public struct NodeStatus: Sendable, Equatable {
    // …
    /// The tailnet lock status. `.disabled` before a netmap arrives.
    public var tailnetLock: TailnetLockStatus
}

public enum NodeEvent: Sendable, Equatable {
    // …
    /// The tailnet lock status changed. The same value is never emitted twice in a row. The initial value is `.disabled` and is not emitted.
    case tailnetLockChanged(TailnetLockStatus)
}
```

The `NodeState` and `NodeError` cases stay the same (decision L4). A locked-out node still reaches `.running` as in Go, and `tailnetLock.isLockedOut` indicates lockout. `NodeError.control` no longer carries `tailnetLockEnabled`.

App usage:

```swift
for await event in node.events {
    if case let .tailnetLockChanged(lock) = event, let request = lock.signingRequest {
        // On the signing device: tailscale lock sign <request.nodeKey> <request.lockKey>
    }
}
```

## 3. Behavior

The numbers are identifiers used by tests and reviews. Parenthetical section numbers refer to the notes. Items labeled "Swiftail's choice" are rules absent from Go. All other items must produce the same decisions as Go.

### E. CBOR encoding

1. Use only canonical (CTAP2) encoding, with shortest integers and lengths, definite lengths only, and no tags or floats (3.1, 6.2).
2. Structures are maps with integer keys. The keys are 1, 2, 3, and 12 for `Key`, 1 and 2 for `AUMSignature`, 1–7 and 23 for `AUM`, 1–5 for `State`, and 1–6 for NKS (3.2–3.6). All fit in one byte, so ascending numeric order is canonical.
3. `Meta` is a text → text map. Order pairs by **lexicographic order of encoded key bytes** (the header byte contains the length, so shorter keys come first, as in `a`, `c`, `bb`. 3.1). Write key and value UTF-8 bytes as received.
4. Field omission and retention (3.1, 3.4–3.6). Omit empty omitempty fields (`Key`, `KeyID`, `State`, `Meta`, and `Signatures` in `AUM`, `Key.Meta`, zero `State.StateID1/2`, and NKS `Pubkey`, `KeyID`, `Signature`, `Nested`, and `WrappingPubkey`). Write `AUM.Votes` when present even if 0 (`0600`). Always write fields without omitempty. These are `AUM.MessageKind`, `AUM.PrevAUMHash` (null `f6` if absent), `Key.Kind`, `Votes`, and `Public` (`f6` for null, `40` for length 0), `Signature.KeyID` and `Signature`, `State.LastAUMHash` (null if absent), `State.DisablementValues` and `Keys`, and NKS `SigKind`. Reference bytes are `UpdateKey{KeyID:[1], Votes:0, Meta:{}}` → `a4010402f60441010600`, `NoOp{PrevAUMHash: length 0}` → `a201030240`, and `StateID1=2^40` → `041b0000010000000000` (8.1).
5. **Hash and sign the re-encoded bytes of the decoded value** (3.1, 3.7). `AUMHash` = BLAKE2s-256(canonical AUM, including signatures). AUM `SigHash` = BLAKE2s-256 with `Signatures` omitted. NKS `SigHash` = BLAKE2s-256 with `Signature` omitted (`Nested` is intact). Unknown fields, non-shortest integers, and unsorted keys are accepted and disappear from the hash.
6. Three values used in decisions distinguish null from empty in storage. They are `AUM.prevAUMHash`, `AUM.votes`, and `TrustedKey.publicKey`. Null and length 0 in `TrustedKey.publicKey` differ **only on writing** (`f6` and `40`). KeyID comparison treats them as the same key. An AddKey with an empty value after AddKey with null reports "key already exists" (verified by execution). No distinction is kept for `State` arrays and `LastAUMHash`, because accepted checkpoints have nonempty arrays and null `LastAUMHash` (3.5). Re-encoded bytes may therefore differ from Go for inputs that fail static validation. Comparison tests check only the decision for those inputs (§7).

### D. CBOR decoding and rejection

Apply the same rules to AUM and NKS (the `Unmarshal` path in 3.1).

1. **Reject at the item level**. Reject empty input, truncated items, bytes after the first item, indefinite lengths, tags (even within unknown field values), 17 levels of nesting (outermost map is level 1), arrays of 4,097 elements, and maps of 1,025 pairs (3.1, 6.2, 8.1). Also reject other violations of RFC 8949 well-formedness rules, including reserved additional information 28–30 (all major types), 31 for integers, unmatched `ff`, and simple values below 32 encoded in 2 bytes (`f800`–`f81f`. Accept `f820`). Accept single-byte simple values 0–19 and 255 as values of unknown fields. This line was confirmed by running `tkafixtures` (`cbor` in `tka-fixtures.json`).
2. **Accept** non-shortest integers (values and keys), non-shortest map headers and byte string lengths, and unsorted keys (3.1, verified by execution).
3. **Structure map keys** (AUM, `Key`, `State`, `Signature`, NKS). Accept positive integers up to 2^63−1, negative integers (down to −2^63), and valid UTF-8 text. Reject other keys (bstr, floats, true, false, null, undefined, arrays, maps, integers at or above 2^63, and invalid UTF-8 text) (3.1).
4. **Duplicate keys**. Reject repeated keys in structure maps and `Meta`, whether the keys are known, unknown, or negative. A non-shortest encoding of one still counts as the same key (comparison is by value, verified by execution). Allow duplicates in maps **inside the value** of an unknown field (3.1).
5. Look up **known fields** only by integer keys. Text keys `"1"` and `"MessageKind"` are unknown fields (3.1). Reject type mismatches (negative integers, floats, or text where an integer is expected, text for byte strings, `Meta` keys or values like true or arrays, and `Signatures` elements that are neither maps nor null). **Accept the following because Go does** (confirmed by running `tkafixtures`. The draft specified rejection). ① **Integer arrays in place of byte strings** decode as the corresponding byte string if all elements are 0–255 (re-encoded as a byte string. Confirmed for `PrevAUMHash`, `Key.Public`, signature KeyID and Signature, `DisablementValues` elements, and NKS `Pubkey`. Reject elements at or above 256 or negative). ② **Null or undefined `Meta` keys or values** decode as empty strings (re-encoded as `60`). ③ Null `Signatures` elements decode and then fail static validation. ④ AddKey `Public` decodes when null, absent, empty, 31 bytes, or 33 bytes (RemoveKey and UpdateKey also pass with that KeyID. A signature with a 33-byte KeyID fails static validation). Range limits are 255 for `MessageKind`, `SigKind`, and `Key.Kind` (reject 256) and the full `UInt64` range for `Votes` and `StateID`. Null and undefined become the field's zero value (integer 0 or absent). `Meta` text must be valid UTF-8 (3.1, 6.2).
6. Silently discard **unknown fields**. Their values can be any well-formed item (negative integers, floats, simple values, invalid UTF-8 text, or nested maps). D1 limits and prohibitions still apply inside them (3.1, 6.2).
7. Reject top-level arrays, integers, byte strings, and text. **Accept top-level null (`f6`) or undefined (`f7`)** as a structure with all zero-valued fields (AUM decodes as kind 0 with no parent, re-encodes to `a2010002f6`, and passes static validation. NKS re-encodes to `a10100`). This matches Go (confirmed by running `tkafixtures`. The draft and notes §3.1 specified "reject if it is not a map").
8. **Swiftail's choice**. Reject a non-null `LastAUMHash` in checkpoint `State` during decoding. Go decodes lengths such as 2 or 33 and rejects them in static validation (3.5, 8.1). The decision to reject the AUM is the same. Go also rejects a text `LastAUMHash` during decoding.
9. Check byte length before decoding (behavior M). No input crashes the process.
10. **Swiftail's choice**. Accept only 52 characters from the base32 alphabet in `AUMHash` text. Reject text containing line breaks (`\r` or `\n`). Go measures the length before stripping line breaks, then strips them and decodes, accepting a **different hash from the original** with only 31 or 30 bytes filled (`tailscale.com/tka/aum.go:33-41`. Verified with 7 cases in `tkafixtures`, including 50 characters + `\r\n`). Following Go would use a truncated hash. Only the control server can send such text, and behavior N1 handles unreadable heads.

### A. AUM verification and state application

1. **Static validation** (3.4, 3.5). Reject a length-0 byte string for `PrevAUMHash` (null is accepted. Length is otherwise unchecked). If `Key` is present, require `Kind` of 1, `Votes` of 1–4,096, and total `Meta` key and value length at most 512 bytes (3.2). Every signature must have a 32-byte KeyID and a 64-byte signature. If `State` is present, validate the checkpoint. Require no `LastAUMHash`, 1–32 distinct 32-byte `DisablementValues`, and 1–512 valid `Keys` with distinct KeyIDs. By kind, AddKey requires `Key` and forbids `KeyID`, `State`, `Votes`, and `Meta`. RemoveKey requires `KeyID` (length>0) and forbids `Key`, `State`, `Votes`, and `Meta`. UpdateKey requires `KeyID` (length>0) and at least one of `Votes` or `Meta` (an empty `Meta` map counts as present), and forbids `Key` and `State`. Checkpoint requires `State` and forbids `KeyID`, `Key`, `Votes`, and `Meta`. NoOp (3), kind 0, and kinds 6 and higher have no kind-specific validation.
2. **Parent** (4.1 item 2). Unless the AUM has no parent, the parent state's `LastAUMHash` must exist and match the bytes of `PrevAUMHash`. A `PrevAUMHash` with length other than 32 fails here (3.4).
3. **Signatures** (4.1 items 3 and 4, 3.7). Require at least one. **Every** signature's KeyID must be trusted by the parent state, and `Ed25519Verification.isValidZIP215` must be true for `SigHash` using that key's `Public` (the value from state, which must be 32 bytes). Reject if any signature uses an unknown key. Verify an identical (KeyID, signature) pair only once within an AUM (2026-11-17 security verification). The decision matches Go, which verifies every repetition. A single AUM repeating one trusted key's signature 4,096 times cannot tie up the recipient for tens of seconds.
4. `Votes` has no threshold. One trusted key's signature is enough (4.1).
5. Reject a RemoveKey that would remove the only key in the state (4.1 item 5).
6. **Application** (4.2). The resulting state's `LastAUMHash` is the hash of this AUM. NoOp leaves the rest unchanged. Checkpoint requires `StateID1/2` to match the parent and replaces the whole state with the checkpoint's state. AddKey rejects existing KeyIDs and otherwise appends (the 512-key check does not apply here). UpdateKey rejects missing keys and requires the key with updated `Votes` and `Meta` to pass A1 key validation again. RemoveKey rejects missing keys and removes the key while preserving order. Other kinds leave the state unchanged.
7. **Kind 0 (`AUMInvalid`) and kinds 6 and higher** are accepted if their signatures are valid, and the head advances (4.2, 8.1. Decision L10). Only NoOp, AddKey, and Checkpoint are allowed where there is no parent (4.2).

### F. Chains, fork resolution, and head

1. **Fork resolution** (4.3 `pickNextAUM`). If a parent has several children, prefer ① the largest signature weight (sum of parent state `Votes`, counting signatures from the same key once and unknown keys as 0), ② on a tie, a RemoveKey, and ③ on a tie, the smaller AUM hash by byte comparison.
2. **Head**. Start with the root state (bootstrap AUM) and apply successive children according to F1 until no child remains (4.3 `fastForward`).
3. **State at an AUM** (4.3 `computeStateAt`). Walk backward from that AUM to a checkpoint or the root, then reapply updates along the path taken, following the path without fork selection.
4. **Admission** (4.3 `Inform`). An empty group is an error. Process in arrival order without sorting. Skip AUMs already held. An AUM without a parent is an error. Use the parent state previously processed in the same group or compute it with F3. An unknown parent is an error. Require A1–A6 to pass. **If any update fails, admit none of them, including earlier ones.** If all pass, recompute the head.
5. **Bootstrap** (4.3 `Bootstrap`). Only when state is empty. Require a Checkpoint AUM with `State` and perform checks A1 and A3 using the checkpoint's **own state** as the parent state. Initial trust is TOFU for the control server's checkpoint. This also applies when the server supplies a later checkpoint in place of genesis (8.2).
6. **Reopening**. Swiftail stores have one root (F4 rejects AUMs with unknown parents, and there is no compaction. Decision L7). This avoids Go `Open`'s "choosing an ancestor among multiple chains" (4.3, unverified item in 8.2). Check the invariant on open. The recorded bootstrap hash is the only root, and every other AUM has its parent in the store. Otherwise return `corruptStore`. Recompute from the root with F2 and check A1–A6 again (Swiftail's choice. Decision L14).
7. Iteration limits (chapter 5) are 2,000 for walking back to find a parent state, 1,000 for synchronization head intersection, and 2,000 for fast-forwarding on tail intersection. Recomputing root to head (F2 and F6) does not use Go's 2,000. In a store without compaction, the chain can grow longer. The storage limit (behavior M) bounds it (Swiftail's choice).

### S. NKS verification

`Authority.authorize` (4.4). Failure at any step means unauthorized.

1. Decode using behavior D.
2. Reject an outermost credential.
3. Resolve the authorizing KeyID. For direct or credential, use its own `KeyID` (reject if empty). For rotation, follow `Nested` (reject if `Nested` is absent).
4. That KeyID must be trusted in the **current state**.
5. Verify signatures recursively:
   - For non-credentials, `Pubkey` must match `"np"` ‖ the 32-byte node public key.
   - **rotation** requires `Nested`. The rotation key is `Nested.WrappingPubkey`. If empty and `Nested` is a rotation, use the key further inside. Reject a missing key or a length other than 32 bytes. Verify the outer `Signature` with that key and **`Ed25519Verification.isValidStandard`** (Go standard rules). For a nested non-credential, require a valid `np` format (34 bytes) in its `Pubkey` and verify it recursively using that public key.
   - **direct and credential** reject `Nested`. Require a trusted `Key25519` key with a 32-byte `Public` and verify with **`isValidZIP215`**.
6. A valid rotation returns its history. `previousNodeKeys` contains keys of nested signatures with nonempty `Pubkey` (newest first, including the innermost direct key), and `initialSignature` is the innermost non-rotation signature. If the credential has a `Pubkey` value that cannot be parsed in `np` format, the entire verification fails (4.4 item 6).
7. CBOR nesting limits depth to 16 levels. Up to 15 rotations on top of a direct signature can be verified (4.4).

### X. Disablement secret

1. `Authority.isValidDisablement(secret:)` returns true when the result of `Argon2i.derive(password: secret, salt: "tailscale network-lock disablement salt"(39 ASCII bytes), iterations: 4, memoryKiB: 16384, parallelism: 4, outputByteCount: 32)` matches any state `DisablementValues` by **constant-time comparison** (`constantTimeEqual`) (4.5). It uses Argon2**i**, version `0x13`, with empty secret key and associated data.
2. Pass even an empty secret to the KDF unchanged (same decision as Go. An omitted server secret is empty).
3. Reference value for secret `0xa5` × 32 → `c3fea8a0d70ede2555990ca60d70a8a03cbe627d2c9f3cb0e2ba7093d0884e2f` (4.5).
4. Use 16MiB once and release it afterward. Only one procedure runs at a time (behavior N3), so computations do not overlap. Do not recompute for the same secret (behavior O6).

### R. NL key and registration

1. **NL key** (4.6 item 1). `NodeIdentity` holds it and stores it in `identity.json` as `"NLKey":"nlpriv:<128 hexadecimal digits>"` (32 bytes of seed ‖ 32 public bytes, Go text format, 3.8). On read, verify that the last 32 bytes match the public key derived from the seed, or return `storage`. If an old identity file lacks `NLKey`, generate a new key and **save it before sending the first request** (registering without saving would send a different key after restart). Keep the key fixed once set. Losing it prevents self-re-signing after the next node key rotation.
2. Always include a nonzero public key in `RegisterRequest.NLKey` (4.6 item 1).
3. **Auth key parsing** (3.8). `run()` parses it once before the first connection. Without `--TL`, it is an ordinary auth key. Otherwise split at the first `--TL` and split the remainder at its first `-` into A and B. If any check fails, end with `ControlError.invalidConfiguration` and **send nothing to the server**. The whole string is at most 16KiB. The `-` is present. A and B use canonical unpadded standard base64 (`+/`). A is at most 8KiB and decodes using behavior D as a credential NKS with a 32-byte `WrappingPubkey`. **B is exactly 64 bytes.** The public key derived from B's first 32 bytes (seed) matches B's last 32 bytes and A's `WrappingPubkey`. Go sends the entire original text, including the private key, to the server if decoding fails, and panics when B is not 64 bytes (3.8). Swiftail rejects both cases (decisions L12 and L13).
4. **What goes to the server**. Include only the prefix before `--TL` in `Auth.AuthKey` (4.6 item 2). No request includes the original wrapped private key (B) or credential (A). Keep the existing rule hiding the original auth key and prefix in server rejection messages (`SwiftailControl.md` behavior 2).
5. **Request signature** (Go's order, 4.6 items 2 and 4). ① If the old node key and the old signature just supplied by the server exist, re-sign using R7. On failure, log and register without a signature. ② Otherwise, for a request sending a wrapped auth key, use `WrappedAuthKey.keySignature(for:)` (= sign the `SigHash` of rotation NKS{`Pubkey`: `"np"` ‖ new node key, `Nested`: credential} with the wrapped key). If this fails, end registration with an error. ③ In all other cases, register without a signature (null). Unsigned registration proceeds regardless of lock, and a signing device supplies the signature later (4.6 item 3).
6. **Server re-signing request** (4.6 item 4). If `RegisterResponse.NodeKeySignature` is nonempty, generate a new node key and register again. `OldNodeKey` is the stored current node key, and re-signing uses the **bytes from the response just received** in place of a locally stored signature. Continue examining responses in this order: `Error` → `NodeKeySignature` → `NodeKeyExpired` → `AuthURL`. Follow only one re-signing request per registration. Treat a second as a connection error, back off, and reconnect (Swiftail's choice. Go ignores a re-signing request in the second response, `control/controlclient/direct.go:534-545`. Go's state afterward is unverified, §9).
7. **Re-signing** (end of 4.4, 4.6 item 4 `ResignNKS`). If the old signature's `Pubkey` matches the new key, reuse the old signature unchanged. Otherwise sign a rotation NKS with the old signature as `Nested` using the NL key. If the current signature's `Pubkey` and the nested keys total more than 15, re-sign and wrap only the 14 most recent keys with the NL key above the innermost non-rotation signature, then add the new rotation. Send the resulting signature without verifying it locally (as in Go. Decision L9). If the old chain's rotation key differs from the local NL public key (nodes registered with `--TL`, direct signatures without `WrappingPubkey`), the signature fails verification and the node is locked out until it is signed again. Log the type of this case and report lockout in the next netmap via `signingRequest`.
8. Registration completion does not tell us whether the signature is valid. Evaluate the local signature against the local node's `KeySignature` in the netmap (behavior P6).

### N. Receiving a netmap

Decisions (`TailnetLockPlan`, `Authority`) use value types. `ControlClient` handles RPCs and files. **Unfiltered netmaps never leave `ControlClient`** (decision L2).

1. **Server-reported state** (4.7, 4.10 item 1). `MapSession` computes it. `isEnabled` = the current map session has received a `TKAInfo` and the last one is not `Disabled`. If `Head` is nonempty and `AUMHash(text:)` cannot parse it, `isEnabled` is false. A response without `TKAInfo` means "no change," and it starts absent in a new session (new `MapSession` per map stream). Capability is the presence of `https://tailscale.com/cap/tailnet-lock` in the **union** of the local node's `Capabilities` list and `CapMap` keys (Go combines them in `tailscale.com/control/controlclient/map.go:371-381`. The draft listed only `capMap` and TL-9 flagged it).
2. **Action** (4.7, 4.12. `TailnetLockPlan`):

   | Local state | Capability | Server | Action |
   | --- | --- | --- | --- |
   | Absent | Absent | Any | None. Skip filtering (owner confirmation required U2) |
   | Absent | Present | Disabled | None |
   | Absent | Present | Enabled | `bootstrap`: bootstrap RPC (empty `Head` string) → behavior F5 → persist → synchronize immediately (behavior Y) |
   | Present | Irrelevant | Enabled, same head | None |
   | Present | Irrelevant | Enabled, different head | `synchronize` (behavior Y) |
   | Present | Irrelevant | Disabled | `verifyDisablement` (behavior O) |

   Compare heads as 32 bytes (3.8).
3. **Order**. Hold netmaps that require action until the procedure completes, regardless of success or failure. This matches Go's order of synchronization followed by filtering (4.7). Run one procedure at a time per connection (Go's `tkaSyncLock`). Keep reading the map stream and retain only the latest netmap received during the procedure. Once it completes, filter and emit the latest netmap using the state at that time. Filter and emit netmaps needing no action immediately (decision L3).
4. **Publishing the head** (3.9, 4.7). Include the local head in `TKAHead` on map requests (both stream and status upload). After the procedure, if the head differs from the last published value, send one more status upload (Go `SetTKAHead` → `updateControl`, `control/controlclient/auto.go:706-714`). Compare against the head last **sent**. If the head changes while waiting for the upload response (including lock disablement resulting in an empty head), publish the current head after that response (Go increments the generation on every change and compares it with the generation sent by `updateRoutine`, `auto.go:61-107` and `:264-272`). If persisted state exists, include the head starting with the first request (Swiftail's choice. Whether Go includes it in the first request is unverified, §9).
5. **Failures** (4.7 item 5). Log only the type for RPC, response decoding, and verification failures. Keep `run()` going. If local state exists, keep filtering with the old state. Retry when the next netmap arrives or the server-reported head changes. TKA RPCs have no 429 or `Retry-After` handling (3.10).
6. **`.unverified`** (owner confirmation required U1). If the server reports enabled, the capability is present, and local state is still absent after the procedure (bootstrap failed), or if persisted state could not be opened, emit a netmap with no peers and set `mode` to `.unverified`. Go accepts all peers without filtering in this case (end of 4.7). Retry failed bootstrap with backoff without waiting for another netmap (start at 5 seconds and double up to 5 minutes. Swiftail's choice, because failing closed leaves no peers until the next netmap). Skip retrying a store that could not be opened because the outcome would be the same (behavior T4).
7. **Startup**. `run()` opens the store before the first connection (behavior T3). Retain the in-memory state across reconnections.

### Y. Synchronization

When `Authority` exists (4.8).

1. **Offer**. `head` is the local head. For `ancestors`, walk back from the head (at most 1,000), collecting hashes of checkpoint AUMs (newest first, excluding the root), then append the root hash.
2. Send to `/machine/tka/sync/offer`. Parse response `Head` and `Ancestors` with `AUMHash(text:)` (fail if unparseable).
3. If the server head matches the local head, **stop here** without sending a send request.
4. **First** compute local AUMs unknown to the server (`missingAUMs(for:)`, decision L8). If the server head exists locally, walk backward from the local head (at most 1,000) to find it as the head intersection. Otherwise examine server `ancestors` in order, taking the first whose AUM state can fast-forward to the local head (at most 2,000) as the tail intersection. Skip server ancestors absent locally. Other failures, such as iteration limits, are immediate errors. If there is no intersection, return `noIntersection`. The send list runs from immediately after the intersection AUM through the local head. **If this computation fails, stop synchronization entirely**, skipping steps 5 and 6.
5. If the response contains `MissingAUMs`, decode all of them (any failure is an error) and admit them with behavior F4. On success, persist them (behavior T2).
6. Send the local head and the list from step 4 to `/machine/tka/sync/send` (`Interactive` false, `[]` even for an empty list). Only log a mismatch between response `Head` and local head.
7. **RPC format** (3.10). All three are **`GET` with JSON bodies** over the Noise channel. Omit `Content-Type` and load balancing headers. `Version` is 148, `NodeKey` is `nodekey:` text, and JSON keys use Go's field names as is. `TKABootstrapRequest.Head` is always present, as `""` if empty. `MissingAUMs`, `GenesisAUM`, and `DisablementSecret` are base64. Each request has a 60-second deadline. A status other than 200 is a failure, and the body is omitted from logs (Swiftail's choice. Go includes it in the error). Response body limits are in behavior M.

### P. Peer filtering

When `mode` is `.enforcing`, filter **the entire netmap again** each time (4.9. Decision L11).

1. **Skip signature checks** for `UnsignedPeerAPIOnly` peers (outside lock scope). Obsolete key checks apply to all peers, so these peers are also removed if rotation made their node key obsolete (as in Go, `tailscale.com/ipn/ipnlocal/tailnet-lock.go:225-231`. The draft only said "skip filtering," and TL-4 flagged it). Survivors stay in the netmap, and the engine continues to exclude them (`Sources/SwiftailEngine/EnginePeer.swift:94-103`). This makes Go's safeguard of clearing the packet filter when it overlaps such a peer unnecessary (end of 4.9).
2. Remove peers with an empty `KeySignature`.
3. Remove peers that fail behavior S.
4. **Keys made obsolete by rotation** (4.9 item 4 `rotationTracker`). Every key in a verified rotation signature's `previousNodeKeys` is obsolete. Group rotations whose `initialSignature` is direct by its `WrappingPubkey`, excluding keys already marked obsolete. If a group has multiple keys, keep only the one with the most `previousNodeKeys` and mark the others obsolete. If two or more tie for the most, mark the entire group obsolete. Do not group chains starting with a credential.
5. Remove the peers rejected in steps 2 and 3 and peers with obsolete keys from the netmap while preserving order. The removal count is `filteredPeerCount`. Their addresses also resolve to absent nodes in `whoIs` and MagicDNS (both read the netmap).
6. Keep the **local node**. If its node key and `KeySignature` fail behavior S, populate `signingRequest` (Go's `LockedOut` health warning. 4.6 item 3, 4.9 item 6). Signed peers stay in the netmap, but communication is impossible because peers enforcing lock exclude this node.
7. In `.disabled`, skip filtering. In `.unverified`, remove every peer (including `UnsignedPeerAPIOnly`. Behavior N6).
8. There is no setting to disable filtering (4.9).

### O. When lock is disabled

1. **`TKAInfo` absent from the start of a session** means "server reports disabled," and **omission mid-session** means "no change" (4.10 item 1, behavior N1). Take no action for a delta without `TKAInfo` while enabled, and go to step 2 if the first response on a reconnected map stream lacks `TKAInfo`. If `TKAInfo.Disabled` is true, go to step 2 even mid-session.
2. If there is no local state, take no action. Otherwise call the bootstrap RPC **with the local head** to get `DisablementSecret` (4.10 item 2).
3. If behavior X returns true, delete the store (behavior T5), clear local state, and publish an empty `TKAHead`. Emit the netmap without filtering and set `mode` to `.disabled`.
4. If false (wrong or empty secret), log and **keep lock enabled**. The server-reported head (absent) differs from the local head, so continue with synchronization (behavior Y) (4.10 item 3, `ipn/ipnlocal/tailnet-lock.go:410`, `:423`). If the bootstrap RPC itself fails, end the procedure there (behavior N5). In either case, keep filtering with the old state.
5. `TKAInfo.Disabled` alone cannot remove lock. Disablement values are signed in a trusted checkpoint, so verifying the secret prevents the control server from disabling lock (4.10).
6. **Swiftail's choice**. When the same secret recurs on a connection, skip rerunning the KDF (hold the rejected secret's BLAKE2s-256 only in memory). This avoids a 16MiB computation on every netmap if the server repeatedly sends `Disabled`. The decision is the same.

### T. Persistence

1. **Location and format** (decision L6). One file in the state directory, `tailnet-lock.cbor`. It contains a canonical CBOR map `{1: format version (1), 2: bootstrap AUM hash (32 bytes), 3: [canonical bytes of admitted AUMs, in admission order]}` followed by the 32-byte BLAKE2s-256 of those bytes. Keeping canonical bytes preserves AUM hashes when reread (6.3). Recompute trust state on open without persisting it directly.
2. **Writing**. Rewrite the file after successful bootstrap and whenever admission accepts new AUMs. Write everything to a temporary file in the same directory, set 0600, flush to disk, and rename (same order as `NodeIdentityStore`). Apply the same iOS data protection class and backup exclusion as `identity.json` (`SwiftailTunnel.md` behavior P 2). **Write failures leave decisions unchanged**. Keep filtering with in-memory state, log the failure type, and write again on the next change. Restart resumes from persisted data, and synchronization fills the rest. If no write ever succeeded, restart with bootstrap (as Go does with an in-memory store and no state directory, 3.11).
3. **Reading**. A missing file means no local state. Otherwise check the size limit (behavior M), hash in the last 32 bytes, CBOR, format version, behavior D for each AUM, and then behavior F6, in order.
4. **Open failure**. If any check in step 3 fails, leave the file intact and set `mode` to `.unverified` (behavior N6. Owner confirmation required U1). This also applies when the server reports lock disabled, because the disablement values are unknown and the claim cannot be verified. To recover, the app stops the node and deletes the file. The next startup bootstraps again. Go skips filtering until the store is repaired (end of 4.7).
5. **Deletion**. Delete the file only when the disablement secret is valid (behavior O3). If deletion fails, clear in-memory state and log the failure. The next startup opens the file again and retains lock (fail closed).
6. `shortcut:` Signing in again to a different tailnet with the same state directory leaves old tailnet state, filtering out all peers in the new tailnet (Go keeps state per profile, 3.11). Revisit when an adopter switches tailnets in one state directory. Until then, the app uses a new state directory (same as the answer to `SwiftailHost.md` U1).

### M. Limits

| Item | Value | Origin | On exceeding the limit |
| --- | --- | --- | --- |
| CBOR nesting, arrays, maps | 16 levels, 4,096 elements, 1,024 pairs | Go (chapter 5) | Decode rejects |
| `Key.Votes` | 1–4,096 | Go | Static validation fails |
| Total `Meta` key and value length | 512 bytes | Go | Static validation fails |
| Checkpoint disablement values and keys | 1–32, 1–512 | Go | Static validation fails |
| Previous keys in re-signing chain | 15 | Go | Trim (behavior R7) |
| Synchronization head intersection, tail intersection, and parent state lookup | 1,000 / 2,000 / 2,000 | Go | Computation fails |
| TKA RPC deadline | 60 seconds | Go | Procedure fails |
| Bootstrap and sync/send response body | 1MiB | Go | Fail |
| sync/offer response body | **8MiB** | Swiftail (Go uses 512MiB. Lowered to match the map frame limit) | Fail |
| Bytes in one AUM | 512KiB | Swiftail (about 350KiB for a checkpoint with 512 keys and full `Meta`) | Reject before decoding |
| Bytes in one NKS | 8KiB | Swiftail (16 layers are about 3KiB) | Reject (remove the peer) |
| Auth key string and its credential | 16KiB, 8KiB | Swiftail | `invalidConfiguration` |
| Wrapped private key | Exactly 64 bytes | Swiftail (behavior R3) | `invalidConfiguration` |
| AUMs admitted at once | 4,096 | Swiftail | Reject the group |
| Total retained AUMs | 4,096, 16MiB total canonical bytes | Swiftail (decision L7) | Reject the group (`limitExceeded`). Keep filtering with old state |
| Store file | 17MiB | Swiftail | Open fails (behavior T4) |
| `.unverified` retry interval | 5 seconds–5 minutes | Swiftail | — |

Swiftail limits are proposed and will be adjusted based on gate results. Limits below Go's fail closed by refusing excess input while continuing to filter.

### K. Secrets and logs

1. Secrets are the NL private key, the entire auth key and its wrapped private key, and the server-supplied disablement secret. The NL key is stored only in `identity.json` (0600) and held in memory as a CryptoKit key type. The wrapped key exists only in `WrappedAuthKey`. The disablement secret is discarded after use in the KDF without persisting it.
2. `description` and `dump` for `NodeIdentity`, `WrappedAuthKey`, and `ControlClient.Configuration` omit private keys, wrapped keys, and auth keys (`CustomReflectable`). `TailnetLockStatus` contains only public keys and hashes.
3. No request includes the wrapped private key (behavior R4). A test checks this in the registration request bytes.
4. Only the disablement value is compared against a secret, using a constant-time comparison (behavior X1). Matching the wrapped key's public key (behavior R3) compares public values.
5. Logs (`os.Logger(subsystem: "Swiftail")`, category `tailnet-lock`) record `mode` changes, procedure and failure types, counts of admitted AUMs and filtered peers, and local node lockout. Logs omit keys (including public keys), auth keys, disablement secrets, signature and AUM bytes, server error bodies, and peer names and addresses. Error-associated strings omit keys and paths.
6. The store contains no secrets (AUMs contain public keys and signatures, and disablement values are KDF outputs). Keep 0600 because replacing the file changes trust state.

## 4. C API and Go behavior mapping

Three of the first adopter's 18 C functions (`SwiftailHost.md` §4) touch lock.

| Function | Go core behavior | After the change |
| --- | --- | --- |
| `rd_start` | Passes configuration `AuthKey` to tsnet. For a key with `--TL`, tsnet creates a signature and registers | Pass the same string to `NodeConfiguration.authKey` (behaviors R3–R5). For invalid format, `run()` throws `NodeError.invalidConfiguration` |
| `rd_status` | Omits lock state. Calls `LocalClient.NetworkLockStatus` once per startup to log whether enabled, whether a head exists, whether the node is signed, the trusted key count, and the filtered peer count (RemoteDebug `core/internal/node/node.go:492-504`) | `node.status.tailnetLock` (`mode`, `head`, `filteredPeerCount`, `signingRequest`). Omits the trusted key count |
| `rd_next_event` | No lock events | `NodeEvent.tailnetLockChanged` |

Go function mapping to Swiftail (origin lines from the notes, with the starting line of `tkaSyncLocked` and testcontrol read directly for this document):

| Go | Origin | Swiftail |
| --- | --- | --- |
| `cbor.CTAP2EncOptions`, `cborDecOpts` | `cbor/encode.go:641-660`, `tka/tka.go:22-32` | `CBORWriter`, `CBOR.decode` (behaviors E and D) |
| `AUM.Serialize`·`Unserialize` | `tka/aum.go:249-271` | `AUM.serialized()`, `AUM(decoding:)` |
| `AUM.Hash`·`SigHash` | `tka/aum.go:273-288` | `AUM.hash`, `AUM.signatureHash` |
| `AUM.StaticValidate`, `Key.StaticValidate`, `staticValidateCheckpoint` | `tka/aum.go:159-222`, `tka/key.go:107-132`, `tka/state.go:258-316` | `AUM.validate()`, `TrustedKey.validate()` (behavior A1) |
| `AUMHash.MarshalText`·`UnmarshalText` | `tka/aum.go:24-51` | `AUMHash.text`, `AUMHash(text:)` |
| `aumVerify`, `signatureVerify` | `tka/tka.go:421-468`, `tka/verify.go:17-36` | Inside `Authority` (behaviors A2–A5) |
| `State.applyVerifiedAUM` | `tka/state.go:157-254` | `AuthorityState.applying(_:)` (behavior A6) |
| `AUM.Weight`, `pickNextAUM`, `fastForward`, `computeStateAt` | `tka/aum.go:316-361`, `tka/tka.go:122-331` | Inside `Authority` (behaviors F1–F3) |
| `Bootstrap` | `tka/tka.go:527-565` | `Authority(bootstrappingWith:)` (behavior F5) |
| `Open`, `computeActiveChain` | `tka/tka.go:68-120`, `:333-419`, `:476-498` | `Authority(opening:bootstrap:)` (behavior F6, restricted to one root) |
| `Inform` | `tka/tka.go:584-676` | `Authority.inform(_:)` (behavior F4) |
| `SyncOffer`, `MissingAUMs`, `computeSyncIntersection` | `tka/sync.go:65-261` | `Authority.syncOffer()`, `missingAUMs(for:)` (behaviors Y1 and Y4) |
| `NodeKeyAuthorizedWithDetails`, `verifySignature`, `rotationDetails` | `tka/tka.go:685-711`, `tka/sig.go:247-348` | `Authority.authorize(_:keySignature:)` (behavior S) |
| `DisablementKDF`, `ValidDisablement` | `tka/state.go:114-141` | `Authority.isValidDisablement(secret:)` (behavior X) |
| `DecodeWrappedAuthkey`, `SignByCredential` | `tka/sig.go:439-498` | `WrappedAuthKey(parsing:)`, `keySignature(for:)` (behaviors R3 and R5) |
| `ResignNKS`, `maybeTrimRotationSignatureChain` | `tka/sig.go:350-437` | `NodeKeySignature.resigned(_:for:with:)` (behavior R7) |
| `doLogin` NL key, signature, and wrapped key, `doLoginOrRegen` | `control/controlclient/direct.go:534-545`, `:643`, `:704-747`, `:763-783` | `ControlClient` registration (behavior R) |
| `mapSession` `lastTKAInfo`, `TKAEnabled` and `TKAHead` | `control/controlclient/map.go:99`, `:516-518`, `:1039-1047` | `MapSession` `serverLock` (behavior N1) |
| `SetTKAHead`, `MapRequest.TKAHead` | `control/controlclient/auto.go:706-714`, `direct.go:476-489`, `:1103` | `MapRequest.tkaHead` and status upload (behavior N4) |
| `tkaSyncIfNeeded` | `ipn/ipnlocal/tailnet-lock.go:340-437` | `TailnetLockPlan` and `ControlClient` procedure (behavior N) |
| `tkaBootstrapFromGenesisLocked` | `ipn/ipnlocal/tailnet-lock.go:536-584` | `bootstrap` in behavior N2 |
| `tkaSyncLocked` | `ipn/ipnlocal/tailnet-lock.go:444-511` | Behavior Y |
| `tkaApplyDisablementLocked` | `ipn/ipnlocal/tailnet-lock.go:513-526` | Behavior O |
| `tkaFetchBootstrap`, `tkaDoSyncOffer`, `tkaDoSyncSend` | `ipn/ipnlocal/tailnet-lock.go:1377-1516` | `ControlClient.tkaBootstrap`, `tkaSyncOffer`, `tkaSyncSend` (behavior Y7) |
| `tkaFilterNetmapLocked`, `rotationTracker` | `ipn/ipnlocal/tailnet-lock.go:189-338` | `Authority.admitted(_:)` and `ControlClient` filtering (behavior P) |
| `tkaFilterDeltaMutsLocked` | `ipn/ipnlocal/tailnet-lock.go:137-183` | Absent. Filters every netmap in full (decision L11) |
| `initTKALocked`, tailchonk (`FS`) | `ipn/ipnlocal/tailnet-lock.go:83-125`, `tka/tailchonk.go` | `TailnetLockStore` (behavior T, different format) |
| `NetworkLockStatus` | `ipn/ipnlocal/tailnet-lock.go:641-668` | `TailnetLockStatus` |
| `Compact` | `tka/tailchonk.go:745-1048` | Absent (decision L7) |
| Signing device features (`TailnetLockSign`, `Init`, `Modify`, `Disable`, `UpdateBuilder`, `MakeRetroactiveRevocation`, `TailnetLockWrapPreauthKey`) | `ipn/ipnlocal/tailnet-lock.go:696-1300`, `tka/builder.go`, `tka/tka.go:750-860` | Absent (§1) |

## 5. Decisions

**Match Go's decisions by default**. Fail-closed behavior was considered only where Go fails open. Changes to fail-closed behavior that affect availability are listed under "Owner confirmation required."

### Lead session confirmation required

| # | Item | Options | Recommendation and rationale |
| --- | --- | --- | --- |
| L1 | Target layout | (a) New `SwiftailTKA` target (`package`, outside exported products) + additions to `SwiftailControl` and `Swiftail` / (b) A folder in `SwiftailControl` / (c) CBOR in `SwiftailBase`, the rest in `SwiftailControl` | **(a)** for the four reasons under "Targets and dependency direction." Cost is two `Package.swift` targets (including tests) and one `SwiftailControl` dependency |
| L2 | Who runs the procedure and filters | (a) `ControlClient` emits only filtered netmaps / (b) The node (`Swiftail`) does it, with control exposing only RPCs | **(a)**. `ControlClient` owns the RPC connection and `TKAHead`, and even users of `SwiftailControl` alone receive no unfiltered netmap. If the event buffer overflows and discards old events, the netmap carries lock state and remains consistent |
| L3 | Procedure and map stream order (behavior N3) | (a) Run the procedure separately and hold only netmaps requiring it until completion / (b) Run it in sequence in the map read loop (like Go) | **(a)**. (b) stops reading the map stream while running three RPCs (60 seconds each), triggering the 120-second watchdog, and has no place for `.unverified` retries (behavior N6). The cost is one piece of state, the "held netmap." TL-7 chooses where the procedure runs (existing signal channel or separate Task). Status upload backoff must never block it |
| L4 | How to report local node lockout to the app | (a) `NodeStatus.tailnetLock` + `NodeEvent.tailnetLockChanged`, with `NodeState` unchanged / (b) Add `.needsLockSignature` to `NodeState` (alongside `needsMachineAuth`) | **(a)**. Go's `ipn.State` also keeps locked-out nodes `Running` and reports a health warning (notes §4.6 item 3). With (b), code depending on `.running` would be blocked during lockout (`notRunning` in `connect(to:port:)`, `nodeNotRunning` in certificate issuance), diverging from Go. Reporting `.unverified` would still need a separate mechanism. Cost is that an app ignoring events cannot tell why a `.running` node cannot communicate (first adopter confirmation required F2) |
| L5 | `ControlError.tailnetLockEnabled` | (a) Remove it / (b) Keep it unused | **(a)**. Nothing will throw it. Cost is that code listing this case in a `switch` will fail compilation (three places in this repository and one in the first adopter, see "Where lock is currently handled") |
| L6 | Storage format and location (behavior T) | (a) One file in the state directory (`tailnet-lock.cbor`, 0600, atomic writes, trailing hash) / (b) A subdirectory (0700) with a file per AUM (0600) and a root file (tailchonk layout) | **(a)**. Data is small (hundreds of bytes to tens of KiB per checkpoint) and changes rarely. Replacing one entire file prevents a persisted mismatch between the AUM set and root record. There is no reason to match Go's format because migration is out of scope. Cost is a full rewrite on every change. (b) adds checks for directory permissions (whether others can write to an existing directory) and consistency across files |
| L7 | Compaction | (a) Omit it and enforce limits (4,096 entries and 16MiB) / (b) On every sync as in Go (`MinChain` 24, `MinAge` 14 days) | **(a)**. Storage grows by one AUM per key change (about 100–200 bytes) and one checkpoint per 50 AUMs (about 0.6KiB for 10 keys, tens of KiB for 512). A tailnet with 10 keys and 1,000 changes uses about 160KiB. Without compaction the bootstrap AUM remains the only root, so Go `Open`'s ancestor selection (unverified in notes §8.2) is unnecessary. **Decision difference**. A compacted Go node forgets old fork parents and rejects a group containing AUMs from such a fork, while Swiftail accepts it. This matches a Go node that received them less than 14 days ago (notes §4.11). At the limit no new AUMs are accepted and state stops advancing (fail closed) |
| L8 | `MissingAUMs` computation (behavior Y4) | (a) Implement (about 150 lines) / (b) Always send an empty list | **(a)**. Omitting it changes when Go stops synchronization (intersection computation failure → neither `Inform` nor send, notes §4.8 item 4), and the notes did not verify the outcome matches in every case (6.3). Implement it to match decisions |
| L9 | Re-signing and signatures that fail verification (behavior R7) | (a) Create and send as Go does, and log if known to fail verification / (b) Register without a signature if the rotation key differs from the local NL key / (c) In that case, if there is a wrapped auth key, create a new signature with `SignByCredential` | **(a)**. Implement re-signing (required by notes §6.3). Other nodes decide the same for (a) and (b), locking the node out either way. Production server handling of a signature that fails verification versus an empty signature is unknown (§9), so match Go on the wire. (c) gives a better result than Go but adds a registration path absent from Go. Revisit if key rotation actually locks out a node registered with `--TL` |
| L10 | AUM kind 0 (`AUMInvalid`) | (a) Accept as Go does unless it is in a position without a parent / (b) Reject | **(a)**. Rejecting such an AUM stalls Swiftail before it in the chain. Later key removals would be missed, leaving Swiftail trusting **more** keys than Go (the same failure mode as the CryptoKit path in notes §6.1). The apparently stricter choice fails open. Only a holder of a trusted key can create such an AUM |
| L11 | Filtering deltas | (a) Filter every full netmap (including obsolete keys) / (b) Verify only signatures on deltas, as Go does | **(a)**. `MapSession` emits a full netmap for each response, so there is no separate delta path. Go retains a peer with an obsolete key added by a delta until the next full netmap (notes §4.9). Swiftail removes it immediately. This matches Go's decision on a full netmap and is more closed only in the interim |
| L12 | Auth key with an unparseable suffix after `--TL` (behavior R3) | (a) `invalidConfiguration` before registration / (b) Send the full original text as the auth key like Go / (c) Send only the prefix as today and register without a signature | **(a)**. (b) sends the wrapped private key to the server. In (c), supplying a signed key silently produces a locked-out node |
| L13 | Wrapped private key validation (behavior R3) | (a) 64 bytes, seed-derived public key = last 32 bytes = credential `WrappingPubkey` / (b) Length only | **(a)**. Go panics on the wrong length and does not recompute the last 32 bytes (notes §3.8). Signatures made with mismatched keys fail verification, so report the problem before registration |
| L14 | Reverification on open (behavior F6) | (a) Repeat static validation and signature verification / (b) Only reapply, like Go | **(a)**. Using the admission rules gives the same decision and checks signatures even if the file was replaced. The startup cost is Ed25519 verification for each AUM |
| L15 | testcontrol additions for gate (a) (§7) | (a) Copy testcontrol to `Tools/interop/internal/testcontrol` (about 2,000 lines, BSD-3-Clause header) and add sync/send, disable, disablement secrets, and registration signatures / (b) Add a file to the testcontrol package at build time with `-overlay` (the `mapfixtures` approach) / (c) Add nothing and use only genesis-only lock at the gate | **(a)**. testcontrol's TKA store (`tkaStorage`) and inner Noise mux are inaccessible externally (`tstest/integration/testcontrol/testcontrol.go:199-201`, `:476-503`). With no handler, `/machine/tka/sync/send` panics the process (notes §7.3). (b) takes fewer lines, but ties the `tailnet` tool build to a module copy and overlay, and requires build tags to keep `go vet ./...` working. (c) cannot test synchronization after chain growth or disablement at the gate. Cost is resynchronizing the copy when upgrading the reference version |
| L16 | Limits lower than Go's (behavior M) | sync/offer response 8MiB (Go 512MiB), AUM 512KiB, retained AUMs 4,096 and 16MiB | Start with the table values because of the iOS extension memory limit. Excess input is rejected and filtering remains active. Cost is that a long-disconnected node cannot catch up if the AUMs it would receive at once exceed a limit |
| L17 | Additions absent from Go | `.unverified` retries (behavior N6), skipping recomputation of the same disablement secret (behavior O6), `TKAHead` from the first request (behavior N4), handling a second re-signing request (behavior R6), rejecting a checkpoint with `LastAUMHash` at decode time (behavior D8) | Include them. They preserve decisions or fail closed. Drop N6 if U1 is decided in favor of matching Go |

### Owner confirmation required

Failing closed in these cases can leave Go nodes able to communicate while Swiftail nodes cannot.

| # | Item | Options and impact | Recommendation |
| --- | --- | --- | --- |
| U1 | Lock enabled with no verified state (behaviors N6 and T4) | **(a) Pass through like Go (fail-open)**. If bootstrap fails or persisted state cannot be opened, accept all peers without filtering. If the store is corrupt, this continues until repair (end of notes §4.7). Availability matches Go. Lock offers no protection during this period. The control server can put unsigned nodes into the netmap simply by failing bootstrap. / **(b) Install no peers (fail-closed)**. During this period, `mode` is `.unverified` and there are no peers. Retry bootstrap failures at 5-second to 5-minute intervals. If the store cannot be opened, the app must delete `tailnet-lock.cbor` to recover (deletion restarts with TOFU). Impact is that Go nodes can communicate while Swiftail nodes cannot during transient control server TKA RPC failures or when the file is corrupt. How often this happens in production is unknown (notes §8.2) | **(b)**. Administrators enabling lock expect no communication with unsigned nodes. This Go behavior can break that expectation. Bootstrap happens once at initial registration, after which persisted state is used to filter (failed synchronization keeps filtering with the old state, so availability does not decrease) |
| U2 | Node without the `tailnet-lock` capability (first row of behavior N2) | **(a) Match Go**. With neither local state nor capability, skip bootstrap and filtering even if the server reports lock enabled (notes §4.12). / **(b)** Bootstrap and filter whenever the server reports enabled, regardless of capability. Impact depends on which nodes the production server gives the capability to, which is unknown (notes §8.2). If it grants it to only some nodes, (b) may cause other nodes' bootstrap RPCs to be rejected. If U1 is (b), those nodes have no peers | **(a)**. Failing closed without knowing the server's intent could stop nodes that do not use lock. Record whether nodes on a real tailnet receive the capability at gate (b) and revisit |
| U3 | What to provide for the real tailnet gate | §7 gate (b) "What to obtain from the owner." A tailnet with lock enabled, a signed auth key made on a signing device, and one `tailscale lock sign` on a signing device | — |

**Owner's answers (2026-11-15)**:

- U1. **(b) Install no peers.** Until verified state exists, `mode` is `.unverified` and there are no peers. Behavior N6 retries apply (L17).
- U2. **(a) Match Go.** At gate (b), record whether the node on a real tailnet with lock enabled receives the `tailnet-lock` capability. If it always does, ask again whether to fail closed.
- U3. Request it at gate (b). The first adopter's Mac host tailnet has lock enabled (plan §7 M8) (correction from RemoteDebug session diagnostics. The Mac's prior tailnet had always had lock disabled. Around 2026-11-15 13:26 UTC, the owner moved the Mac to a new tailnet under a new account, enabled lock, and signed it. The statement has been true since then. The iPhone app node remains in the old tailnet). Run gate (b) in this new tailnet (two signing devices).
- Earlier decision. Implement Ed25519 verification directly in pure Swift (notes §6.1 (b), `Ed25519Verification` in `SwiftailCrypto`).

**Lead session confirmation (2026-11-15)**. L1–L17 follow the recommendations. Additional decisions:

- TL-0 does not create stubs for the §2 declarations. Units land in order (TL-1 → TL-2 → TL-3 and TL-4), so the earlier unit's real declarations are the interfaces for the later one. Include only the `Package.swift` targets and placeholder files.
- Nodes that cannot catch up because they exceed L16 limits keep filtering with the old state (fail closed). Log the case (behavior K5 "procedure and failure types").
- F1–F3 were sent to the first adopter session. `SwiftailTKA` (TL-1–TL-5) proceeds before the answers arrive. The F answers affect only the `Swiftail` surface (TL-8).

### First adopter confirmation required

| # | Question | Draft assumption | What depends on the answer |
| --- | --- | --- | --- |
| F1 | `ControlError.tailnetLockEnabled` is being removed. The iPhone tunnel app associates text with that case in `Apps/iOSTunnel/SwiftailTunnelEngine.swift:180`. Can it be removed? | Yes, remove only that line | L5. If it must stay, keep it as an unused case |
| F2 | A locked-out node is `.running` and has `tailnetLock.signingRequest`. Can the Mac host and tunnel app listen for `tailnetLockChanged` and tell the user to run `tailscale lock sign <nodeKey> <lockKey>` on a signing device? `.unverified` (no peers) also needs a message | Show them | L4. Revisit (b) if a single state is preferred |
| F3 | Which path is used when registering the Mac host as a new node (`SwiftailHost.md` U1), a signed auth key (`--TL`) or a signing device signing after login? | Both work | Gate (b) order. If the signed auth key is single-use, make a new one each time the node registers again |

### Decisions made during implementation

- **TL-1 (CBOR, 2026-11-15)**. `CBORValue.null` also holds undefined (0xf7) (see declaration above). `CBOR.decode` accepts duplicate keys. Go also accepts duplicates inside values of unknown fields, so data format handling (TL-2) rejects duplicates in structure maps and `Meta` (behavior D4). Maps preserve input order and duplicates. When writing, callers choose pair order (TL-2 handles `Meta` order in behavior E3). The AUM 512KiB and NKS 8KiB limits (behaviors D9 and M) depend on the structure, so TL-2 checks them before calling `CBOR.decode`. Two cases report a different rejection reason than Go (lengths and element counts at or above 2^63, both rejected), without affecting decisions. The TL-5 tool will confirm decoder inputs still unverified by execution (reserved additional information 28–30, 31 for major types 0, 1, and 6, unmatched `ff`, simple values below 32 encoded in 2 bytes, and undefined keys).

- **TL-5 tool (`tkafixtures`, 2026-11-15)**. Added 426 Go `tka` decisions to `Tests/SwiftailTKATests/Fixtures/tka-fixtures.json` (go1.27.3, `tailscale.com` v1.104.6). Running it found inputs Go's decoder accepts despite the draft, so behaviors D1, D2, D4, D5, D7, and E6 were updated (top-level null, integer arrays in place of byte strings, null in `Meta`, and KeyIDs of null and empty public keys). Also confirmed that negative keys are accepted down to −2^63, nesting up to 16 levels and up to 1,024 top-level map pairs are accepted, and spare bits of the last `AUMHash` text character are unchecked (`A`, `B`, and `P` give the same hash). Remaining intentional differences include Go skipping validation of the last 32 bytes of `nlpriv:` while Swiftail checks them (behavior R1). Go panics for a 63-byte wrapped key (only the wording differs from the message in the notes). The tool could not generate RemoveKey in a position with no parent (unreachable through the public API).

- **TL-2 (data formats, 2026-11-15)**. All 255 `cbor` cases in `tka-fixtures.json` match Go's final decision. Re-encoded bytes, hashes, and SigHash match for inputs Go accepts. Changes from the §2 declarations are ① `AUM.keyID` is `[UInt8]?`. Go's AddKey and Checkpoint static validation checks `KeyID != nil`, so empty byte strings (`0440`) fail and null or omission passes (`tka/aum.go:189`, `:207`). All three encode the same way. ② Added `case simple(UInt8)` to `CBORValue` (simple values 0–19 and 32–255). Go puts simple values into integer fields as those numbers (`parseToValue` in `fxamacker/cbor` `decode.go`). ③ TL-3 places `AuthorityState.applying(_:)` in `Authority/`. Only the two behavior D8 cases differ from Go at decoding (final decisions match). Five AUMs that fail static validation re-encode differently (behavior E6 encodes Go nil as empty. Accepted checkpoints have nonempty disablement values, so hashes are unaffected. `tka/state.go:262`). **Decisions based on Go source but unverified by execution** (the TL-5 comparison test session will add them to the tool and confirm them) cover simple values in integer fields (`MessageKind` such as `e3` or `f863`), simple and null integer array elements, `Meta` keys encoded as simple values or undefined, and `\r` and `\n` in `AUMHash` text (Go's `base32.Decode` strips them and decodes, while Swiftail rejects them. Decide whether to match Go after comparison).

- **TL-9 (gate tool, 2026-11-15)**. Copied testcontrol (v1.104.6) to `Tools/interop/internal/testcontrol` and added to `tka.go` the `sync/send` and `disable` endpoints, bootstrap after disablement (disablement secret), verification and attachment of registration request signatures, re-signing requests, lock capability in the local node's `CapMap`, and broken bootstrap. `tailnet` commands are `setLockCapability`, `lockInit`, `lockStatus`, `lockSign`, `lockWrapAuthKey`, `lockModify`, `lockDisable`, and `lockRegistrations`, plus `setLockBootstrapFault`, `lockRequestResign`, and `lockRequests` beyond the contract (README `tailnet` section). The flow between Go peers (`TestTailnetLock`) and the 43 existing Swift gates pass. Code labels behavior inferred without knowing the production server's behavior as "speculation" (disable checks, map response shape after disablement, handling registration with failed signature verification, when re-signing is requested, and handling old keys). Implications for gate (a) are ① Item 9's "old key is removed as obsolete" appears on this server as "the server deletes the old key entry." Verify the obsolete-key decision itself with `tkafixtures` `peerSets` and `verify-nks`. ② For item 7 (disablement), the Swift test must reconnect the map stream. A node injected once with `injectMapResponse` receives no automatic maps afterward (inject at the end or use a different node). ③ When an AUM fork exists, the original implementation omits `TKAInfo`, so a new session sees lock as disabled (left alone. Unit tests and Go comparison cover forks).

- **TL-4 (signatures, 2026-11-15)**. Decisions match Go for 51 `signatures`, 8 `peerSets`, and 10 `resign` cases in `tka-fixtures.json`. Of 16 `authKeys` cases, 4 match and Swiftail intentionally rejects 12 at parse time (6 for L12, 4 for L13, and 2 for behavior R3). Go's `tkafixtures verify-nks` classified 10 signatures from Swift (CryptoKit) as expected. Changes from the §2 declarations are ① `authorize` and `admitted` extend `AuthorityState`. They are outside `Authority` (`Authority` forwards to them). ② `PeerCredential` includes `unsignedPeerAPIOnly` (behavior P1). ③ `WrappedAuthKey` is hidden in `description` and `dump`, including `controlValue` because it is also an auth key. ④ `authorize` throws only `.unauthorized`, including on decode failure, and `WrappedAuthKey(parsing:)` uses `.invalidAuthKey` for limit breaches too. Another intentional L12 difference is accepting only canonical base64 after `--TL` (Go `RawStdEncoding` accepts nonzero spare bits and line breaks). When the old signature supplied to re-signing exceeds 8KiB (only possible if inflated with unknown fields), Swiftail rejects it and registers unsigned (behaviors M and R5 ①). **Decisions based on Go source but unverified by execution** (the comparison test session will add them to the tool and confirm them) cover failure when Go `State.GetKey` encounters a key other than `Key25519`, an empty `Pubkey` in a direct signature nested in rotation, and obsolete keys of API-only peers. Go leaves one ordering unspecified when the same node key belongs to groups for multiple rotation keys. Go iterates a map, and Swiftail uses the peer order in which groups first appeared.

- **TL-3 (`Authority`, 2026-11-15)**. Go matches all 19 `chains` in `tka-fixtures.json` across 82 steps (bootstrap decision and each step's decision, head, and state), both sides of 14 `sync` cases (offer, `MissingAUMs`, and head after admission), and 9 `disablement` cases. Changes from §2 are that `syncOffer()` does not throw (no store read) and `SyncOffer.init(head:ancestors:)` is `package` (TL-7 builds it from the server response). Implementation decisions check limits (4,096 entries, 16MiB, and 4,096 per group) **before** signature verification (same decision) and skip repeated AUMs in a group (Go processes them again. Reading the source indicates the outcome matches). TL-7 needs to know that a throw from `missingAUMs` aborts the entire sync, empty lists must not be passed to `inform`, `inform` is atomic, persistence uses `aums` and `bootstrap`, any `opening` failure gives `.unverified`, and `isValidDisablement` runs Argon2i on every call (TL-7 skips recomputing the same secret). **Decisions based on Go source but unverified by execution** (the comparison test session will add them to the tool and confirm them) cover the parent state search limit during admission (2,000 including checkpoint succeeds, 2,001 fails), falling back to tail intersection after exceeding 1,000 head intersection iterations, duplicate AUMs in a group, and chains over 2,000 from root to head (intentional behavior F7 difference). Pure Swift Ed25519 verification takes 6–10ms each in debug, so the 4,096-entry limit test takes about 44 seconds (release reopen time was unmeasured).

- **TL-6 (registration, 2026-11-15)**. Identity files gained `NLKey` (`nlpriv:` + seed ‖ public key). Before its first connection, `run()` fills in the NL key and rewrites old files (only `run()` saves, because there are two callers of `load()` and this avoids a race where they generate and use different keys). Every registration request contains the local NL public key in `NLKey` (nonzero). With a signed auth key, send the prefix before `--TL` to the server and a rotation signature made with the wrapped key as `NodeKeySignature` (a test checks that the suffix, wrapped key, and seed are absent from the request body, headers, and path in any representation). An unparseable `--TL` sends no requests, even `GET /key`. Declarations absent from §2 are `NodeIdentity.lockPublicKey`, `NLPublicKey.commandLineDescription` (`tlpub:` form, used by `SigningRequest.lockKey`), and `ControlClient.wrappedAuthKey`. Decisions from reading Go (`control/controlclient/direct.go:534-545`, `:643`, `:704-768`, `:857`) are to sign with the wrapped key on each request carrying the auth key, use re-signing input only for the next request, skip re-signing with a zero old node key even if requested, and send the new key when an existing node reconnects after changing its former zero `NLKey` to a new key (like Go). Of 14 NL key representation cases in `tka-fixtures.json`, 12 match Go and 2 intentionally differ (checking the last 32 bytes of `nlpriv:` = behavior R1, and no `tlpub:` reader because Swiftail only writes `tlpub:`). An existing interop test (auth key redaction in `ControlFaultsTests`) used an unparseable `--TL` key and was changed to an ordinary key to match L12.

- **TL-5 comparison tests (2026-11-15)**. A session separate from the implementers compared all rows of `tka-fixtures.json` through the `package` surface (`GoComparisonTests`). Previously unsettled decisions were added to the tool and confirmed by running Go (426 → 486 fixtures). **No Swift implementation defects were found.** Confirmed that simple values in integer fields are accepted as those numbers, simple, null, and undefined elements in integer arrays are accepted as bytes, an undefined `Meta` key is an empty string and a simple value key is rejected, `GetKey` rejects when a key other than `Key25519` precedes the signing key, empty `Pubkey` within rotation is rejected, API-only peers are removed if their keys are obsolete and their rotations do not obsolete other peers, head intersection covers distances up to 999 and tail intersection begins at 1,000, and duplicate AUMs within a group are all accepted. Confirmed intentional differences are line breaks in `AUMHash` text (behavior D10), chains over 2,000 from the root (behavior F7. Go fails when forks or already-held AUMs are mixed in, and the AUMs remain in the store, causing the next group to fail too. Swiftail accepts), and Swiftail's limit boundaries (behavior M. Go accepts and Swiftail rejects NKS of 8,193 bytes, AUM of 524,289 bytes, and re-signing input of 8,193 bytes. Unknown fields do not affect hashes, so the sender can inflate an AUM, but could also withhold it, so this adds no new capability). One Go result varies between runs for a peer set where the same node key belongs to two rotation key groups (two answers over 256 runs. Swiftail always produces one of them). The 4,097-AUM admission boundary was omitted (fixtures exceed 2MB, and a unit test covers it).

- **TL-7 (maps, 2026-11-15)**. Netmaps from `ControlClient` are already filtered and carry `tailnetLock`. Nothing throws `ControlError.tailnetLockEnabled` anymore (TL-8 removes the case). **Procedure structure**. For each map response, `receivedLock` chooses an action. With none, it filters and emits immediately. Otherwise it holds the netmap and wakes the procedure (stream reading continues). The procedure (`runLockProcedures`) is one child of the `serve` TaskGroup and runs one at a time. The held netmap is the latest unfiltered one and is cleared on reconnection. When the procedure succeeds or fails, filter and emit once using current state. Emit again if lock status changes even without a new netmap. Triggers are a new netmap, a change in server-reported state, and the `.unverified` retry timer (5 seconds–300 seconds). If the head changed after the procedure, request another status upload (`MapRequest.tkaHead`). **Store file**. `<state directory>/tailnet-lock.cbor`, 0600, `{1: 1, 2: bootstrap hash, 3: [canonical AUM bytes…]}` ‖ BLAKE2s-256. Writes follow the identity file order (temporary file → fsync → rename, with iOS protection class and backup exclusion). Open failure gives `.unverified` rather than "no state." On save failure continue filtering with in-memory state (behavior T2. Restart from bootstrap). **Disablement secret**. The KDF runs without suspension on the actor, keeping map decoding from overlapping the 16MiB cost (the actor is blocked for about 2 seconds in debug). Remember a rejected secret by its BLAKE2s-256 and the head at the time to avoid recomputation, including across connections. Changes from §2 are RPCs using `throws(ControlError)`, `public init` on `TailnetLockStatus` and `SigningRequest` (default `.disabled`), reading `ServerLockState.head` even when `Disabled`, and `filteredPeerCount` counting all server-reported peers in `.unverified`. Decisions from Go source (`ipn/ipnlocal/tailnet-lock.go`, `control/controlclient/map.go:1039-1047`) are to call sync/offer after bootstrap even with equal heads and omit send when heads match, fail sync when any response `Head` or `Ancestors` entry cannot be read, treat empty `GenesisAUM` as decode failure, retry failed procedures on each subsequent netmap, and avoid interpreting KeepAlive before the first netmap as "no `TKAInfo` from the start." Code using `MapSession` directly gets an unfiltered netmap (default `tailnetLock`). Remaining points are the unmeasured cost of rechecking all signatures on each netmap in large tailnets (`shortcut:`), two matching atomic write implementations in the identity and lock stores, and two fake test control servers (`SetDNSFakeControlServer`, `LockFakeControlServer`).

- **TL-8 (node, 2026-11-15)**. Added `NodeStatus.tailnetLock` and `NodeEvent.tailnetLockChanged` and removed `ControlError.tailnetLockEnabled`. Order for one netmap (`apply(netmap)`, one uninterrupted run on the actor) is ① update the last netmap (updating `status`), ② `tailnetLockChanged` if lock status changed (omit initial `.disabled`), ③ data plane (`peerPathChanged`), ④ netstack, ⑤ tunnel settings, ⑥ state machine (`stateChanged`), ⑦ certificate facts. Thus `status` read after any event contains the entire netmap, and a locked-out node's `tailnetLockChanged` precedes `stateChanged(.running)` (F2 requirement 1). This guarantee depends on no `await` in `apply` (the test checks event order and `status` after events. Whether state is updated first within the sequence is not externally visible). `.unverified` reaches `.running` without peers (`peerCount` 0, `filteredPeerCount` is the server-reported peer count). `tailnetLock` retains its last value after `run()` ends, like other fields. A change in peer count alone emits an event if `filteredPeerCount` changes. `TailnetLockStatus` is the `SwiftailControl` type as is (`import SwiftailControl`). The first adopter needs to update two `.control(.tailnetLockEnabled)` branches and one exhaustive `NodeEvent` `switch` (new case) in `Apps/iOSTunnel/SwiftailTunnelEngine.swift`.

- **TL-10 (gate (a) tests, 2026-11-15)**. `Tests/SwiftailInteropTests/TailnetLockTests.swift` (7 tests cover items 1–11). The Go peer's `lockStatus` and Swift node decisions matched at 11 points (head text, sets of visible and filtered peer node keys, and local lockout). UDP echo and TCP SYN also verified "visible/removed" (no traffic with unsigned peers for 6 seconds). **One defect found by the gate**. If the server changes only the disablement secret and resends an identical map, Go runs the procedure again on that map and disables lock (`tkaSyncIfNeeded` runs on every map response). Swiftail treated the netmap as unchanged and skipped the procedure. Fix. When work remains (`lockPlan` is nonempty), a non-KeepAlive map response triggers the procedure even if the content is unchanged (`MapSession.Update.isMapResponse`. Behavior N5's "retry on each subsequent netmap" now applies to maps with identical content. The same applies to an `.enforcing` node whose sync failed). Criteria checked differently with this tool were item 9's "old key is removed as obsolete," checked as "the new key is visible and the old one is absent" (this server deletes the old entry), and item 7's "reconnected stream," checked by restarting the node (there is no command to restart the Go peer, so the resulting decision was not compared with Go). The test reads the Swift node's internal last netmap to obtain its peer set (the public API only exposes `peerCount`).

### Independent review fixes for the control procedure (TL-11b, 2026-11-15)

Another session reviewed registration and map procedures on the premise that the control server is untrusted. It found no path for the server to disable filtering on a node holding local state or for unsigned peers to leave `ControlClient` (tests exercised an unparseable head, empty `TKAInfo`, a different head, capability removal, `Disabled`, RPC failure, and reconnection during the procedure). Fix the two reproduced defects and four contract omissions as follows. These items take precedence over the corresponding behavior in §3.

1. **Re-signing was a signing oracle (critical, inherited from Go)**. If the server sent a fake rotation with **exactly 15 layers** in `RegisterResponse.NodeKeySignature` (the maximum within the decoder's 16-level nesting limit, yielding 16 previous keys and triggering trimming. The initial "more than 15 layers" was wrong, as reverified on 2026-11-16), trimming would use the NL key to re-sign and return **node keys chosen by the server** (behavior R7, "re-sign only the 14 most recent keys with the NL key"). If the victim node's direct signature has its own NL key as `WrappingPubkey` (as all nodes signed with `tailscale lock sign <nodeKey> <lockKey>` on a signing device do), the chain starts at a trusted key and passes authorization on all nodes enforcing lock. Rotation makes the genuine node's key obsolete. Go has the same code. `ResignNKS` and `maybeTrimRotationSignatureChain` do not verify received signatures (`tailscale.com/tka/sig.go:359-437`), and input comes from the server response (`control/controlclient/direct.go:734-737`, `:857-858`). Verified by reading the source, without running Go. **Fix (changes behavior R7 and withdraws decision L9 (a))**. Re-sign **only what the local NL key already signed**. Re-sign only when the local NL public key verifies every rotation layer's signature (standard rules) and matches the innermost non-rotation signature's `WrappingPubkey`. Otherwise register without re-signing or a signature (the node is locked out and exposes `signingRequest`. Log the failure type). Put the check in the `SwiftailTKA` re-signing function so callers cannot forget it. Unlike Go, Swiftail no longer creates "signatures that fail verification" (nodes registered with `--TL`, direct signatures without `WrappingPubkey`). Other nodes see the same decision (both lock out).
2. **Only one rejected disablement secret was remembered (low)**. If the server alternated two wrong secrets, Argon2i ran every time (contrary to behaviors O6 and X4). Fix by retaining a small set of rejected secret digests per head (8 entries, evict the oldest on overflow).
3. **Unreadable `Head` was interpreted as "no lock" (low, changes behavior N1)**. If `TKAInfo` is present and not `Disabled` but `Head` is unreadable, interpret it as **enabled with unknown head**. Bootstrap if local state is absent and synchronize if present. Previously, absent local state meant emitting all peers without filtering, and behavior D10 (text containing line breaks) meant Go filtered cases Swiftail did not.
4. **The app could not distinguish the cause of `.unverified` and had no recovery path (medium)**. Add reasons to `TailnetLockStatus` for acquiring verified state (automatic retries), inability to open persisted state (no automatic recovery), and persisted state disconnected from the chain reported by the server (state from another tailnet. `mode` is `.enforcing` in this case and signing does not resolve it). Add a **public function to delete only the lock state file** (deleting the entire state directory loses the NL key and requires signing again). Deletion leads to fresh TOFU on next startup, so document that it "must be an action chosen by the user."
5. **The sync/offer response decoded all `MissingAUMs` before checking the count limit (low)**. An 8MiB body holds a million entries of a few bytes each. Fix by checking the count (4,096) before decoding.

**Fix results (2026-11-15)**. All five items landed. ① The re-signing function checks the received chain before re-signing (verify each rotation layer with the local NL key using standard rules, or return `.invalidSignature`. Return `.untrustedSigner` when the innermost signature is missing or its `WrappingPubkey` differs from the local NL key). If it throws, registration logs only the type and proceeds unsigned. The shortcut returning the old bytes when the old signature's `Pubkey` matches the new key remains because it does not create a signature. Three of 10 Go `resign` reference rows (`direct-wrapping-is-other-key`, `direct-no-wrapping`, `credential-chain`) became intentional differences. Go creates a signature, but that signature also fails authorization. ② Keep up to 8 rejected disablement secret digests per head. ③ `ServerLockState` interprets an unreadable `Head` as enabled with no head. Retested all entries in the N2 table starting from `TKAInfo` JSON. ④ Added `TailnetLockStatus.issue: Issue?` (`.acquiringState` / `.unreadableStoredState` / `.storedStateDiverged`). Divergence is set only when synchronization's `missingAUMs` finds no intersection (distinct from RPC failure). It clears when heads match, intersection computation succeeds, or lock is disabled. **The function that deletes only the lock state file** is `ControlClient.removeTailnetLockState(inDirectory:)`. Pass the node's `configuration.stateDirectory` (no node wrapper because the app already uses `SwiftailControl` types). Call it while the node is stopped. ⑤ `TKASyncOfferResponse` checks the `MissingAUMs` count (4,096) before base64 decoding.

Remaining items (left as is). Without local state the server's report determines the decision (`.unverified` also clears if the server reports `Disabled`. Initial trust is TOFU, as in Go). A wholesale replacement store containing an attacker-created genesis passes reverification (with that access the attacker can also read the identity file in the same directory. Behavior K6 covers this with 0600). The cost of reverifying all peer signatures on each netmap was unmeasured (`shortcut:`).

### Independent review fixes for pure logic (TL-11a, 2026-11-15)

Another session compared `SwiftailTKA` line by line with the Go source and generated new inputs outside the comparison tests (new Go reference cases were 22 chains with 63 steps and 15 signatures, with 0 decision differences. Release fuzzer ran 200,000 each for AUM and NKS, with 0 traps). It found no way to authorize an unsigned node key or introduce an untrusted key into state. It reproduced two inputs with results differing from Go using temporary Go programs and fixes them as follows. These items take precedence over corresponding behaviors in §3 and decisions L7, L14, and L16.

1. **The server alone could fill the storage limit (high, changes decision L7 and L16 limits)**. AUM hashes include the signature list, and repeating a signature, retaining a subset, or reordering signatures still passes verification (`tailscale.com/tka/tka.go:433-445`, `tka/aum.go:168-172`). Thus arbitrarily many sibling AUMs can be accepted without a signing key (Go accepts them too). Swiftail rejected entire groups once retained AUMs reached 4,096 or 16MiB. If the server filled the limit with variants, later RemoveKey and checkpoint AUMs were rejected and **removed keys remained trusted**. This did not resolve when the server recovered, and Go nodes on the same server were unaffected (Go has no retention count limit). Fix. **Apply the limit only to the active chain from root to head.** Drop AUMs outside it (losing forks) at the limit (state is unaffected, and Go compaction also discards them). Fork resolution selects among siblings at each branch point (behavior F1), so dropping a losing sibling leaves later decisions unchanged. An incoming AUM whose parent was discarded is still an "AUM with an unknown parent."
2. **An accepted chain could fail to reopen (medium, narrows decision L14)**. An UpdateKey with only empty `Meta` (`07a0`) passes static validation and Go accepts it. Canonical writing omits the empty map, so after saving and rereading, the AUM has neither Votes nor Meta and fails static validation. The restarted node was stuck in `.unverified` (no peers). Go's `Open` skips reverification. Fix. **On reopen, check only parents and signatures again** (perform static validation only at admission). Keep canonical writing unchanged because changes would make hashes differ from Go.
3. **Server-supplied ancestor lists amplified `missingAUMs` computation (low)**. Repeating a losing-fork AUM in the ancestor list caused a walk back to the checkpoint for each ancestor (worst case 71 seconds in release for one 8MiB response, blocking `ControlClient` throughout). Fix by deduplicating ancestors and considering only up to 1,001 (the maximum in Go's offer).
4. **Admission memory grew quadratically with group size (low)**. It held the full state per AUM (about 290MiB for one group of 4,095 AddKey updates in release). Fix by discarding states no longer used as parents within the group.
5. Also add documentation comments to `package` declarations lacking them and license notices to `Model/` and `CBOR/` files ported from Go.

**Fix results (2026-11-15)**. All five items landed. ① Removed the total-count check before admission. After recomputing the head, check active chain count and bytes and reject excess as `limitExceeded` (state stays as before). If only the overall retained data exceeds limits, drop non-active AUMs **from the most recently admitted first** (children always arrive after parents, so every retained AUM keeps its parent). Go source confirms that dropping losing forks does not change later decisions. Siblings are compared only using parent state (total order of weight → RemoveKey → hash, without consulting descendants, `tailscale.com/tka/tka.go:134-167`). The active chain descends from the root with that rule at each fork (`:200-242`, `:385-420`), and sync intersections come only from the active chain (`tka/sync.go:160-209`). A new sibling can leave the current winner in place or become the winner, and descendants of a losing fork do not enter the comparison. Limit checks no longer run **before** signature verification (the active chain is only known after verification. The 4,096-entry group limit and response body limit bound verification cost). ② On reopen, check only parents and signatures. Go's `Open` checks neither signatures nor static validation again (`tka/tka.go:482-505`), so both open a file containing a trusted-key-signed AUM that fails only static validation (same decision). To prevent traps on values that did not undergo static validation, weight addition wraps like Go's `uint`, and `key(withID:)` matches Go `GetKey`. **Admitting and reopening an UpdateKey with empty `Meta` preserves the head, but that key's `Meta` alone reverts to its old value** (received empty `Meta` clears the key's `Meta`, but canonical storage omits it. Source inspection indicates Go behaves the same, `tka/state.go:206`, `tka/tailchonk.go:658-673`. `Meta` is not used in decisions). ③ `missingAUMs` deduplicates ancestors and examines only up to 1,001 (`tka/sync.go:88-109`, checkpoints encountered while walking back 1,000 times and the oldest AUM). ④ Release states no longer used as parents in the group. ⑤ Added 18 comments and license notices (Tailscale BSD-3-Clause, `fxamacker/cbor` MIT). Release measurements (same input, before → after) were RSS of 330MiB → 44MiB for one group of 4,095 AddKey updates, ancestor amplification (8MiB, depth 1,999) about 58 seconds → 0.01 seconds, new worst case (1,001 distinct losing-fork ancestors) 0.22 seconds, and reopening 4,096 AUMs 0.35 seconds. Go comparison matches on all 523 rows.

Remaining items (left as is). **The node cannot catch up on a tailnet whose active chain itself exceeds 4,096 AUMs** (no compaction, decision L7. This is a tailnet with more than 4,096 key changes. Keep filtering with old state). Two protocol weaknesses match Go. If a signature variant with a smaller hash beats the original, a RemoveKey attached to the original remains in the losing fork. A key with more votes can create a sibling from an old parent and win even after removal (both are in Go reference `reviewChains` to check for matching decisions). `AuthorityState.authorize`, `admitted`, and `applying` can also be called on unverified state values (`SwiftailControl` currently uses only `authority.state`).

### First adopter review results (2026-11-15)

The first adopter session (RemoteDebug) read L4, L5, and "Where lock is currently handled" and answered.

- **F1**. Remove it (L5 (a)). That case appears in two places in `Apps/iOSTunnel/SwiftailTunnelEngine.swift` (`kind(of:)`, `message(for:)`). The first adopter will remove both branches when upgrading to the TL-8 commit.
- **F2**. Use (a). No new `NodeState` case is needed. The adopter's adapter reads `node.status` for every `node.events` event and passes it to the app, so the adopter will build new screens ("Signing required on a signing device," "Connection left closed because lock status could not be verified") that the Go core did not have. The contract must meet four requirements from TL-7 and TL-8, covered by tests 21 and 22 and gate (a) items 2 and 3:
  1. **There is no gap between first `.running` and lock information.** `NodeStatus.tailnetLock` is already populated when a locked-out node becomes `.running`. For events from the same netmap, `tailnetLockChanged` precedes `stateChanged(.running)`, and `status` read at any event already shows that netmap's lock status. "Connected" never appears briefly before changing to the notice.
  2. **`status` alone distinguishes four cases**. Lock disabled (`mode == .disabled`) / enabled and local node signed (`.enforcing`, `signingRequest == nil`) / enabled and awaiting signature (`.enforcing`, `signingRequest != nil`) / `.unverified`.
  3. **The two values are strings that can be pasted as is into `tailscale lock sign`** (`nodekey:…`, `tlpub:…`, `String` as declared in §2). Both are public keys and may appear on screen and on the clipboard. Swiftail does not log them (behavior K5). The first adopter also keeps them out of device logs.
  4. **Signing clears lockout without restarting.** The netmap after a signing device signs causes `tailnetLockChanged` and `signingRequest` becomes nil. The existing events report peers being installed afterward.
- **F3**. **Answer (2026-11-15, relayed by the RemoteDebug session). The Mac host registers by signing in through the browser and then having a signing device sign it.** It does not use the signed auth key (`--TL`) path. Thus gate (b) item 2 (signing device signs later) is the first adopter path, and item 1 confirms Swiftail support. The lock screen (two signing request values, `.unverified` message, clearing persisted state) will be built when migrating the Mac to Swiftail. Tailnet logout for the Mac app clears the entire state directory. The adopter was told to delete only after `run()` ends, that Swiftail has no server-side logout (node key expiration request) so the old node remains, that a new key on a tailnet with lock enabled requires signing again, and that certificates are reissued. Note (corrected by the adopter on 2026-11-15. The initial statement "The Mac has no auth key input screen" was wrong). The Mac app's network screen has an auth key field (unsaved, used only once when sharing next starts. Visible when sharing is off or the app has not joined the tailnet). The signed auth key (`--TL`) path thus works without a new screen (verify at migration whether the field passes the long key with `--TL` intact). The paths differ in whether they move a secret and whether F2's signing instructions are required. The Mac app has no logout and login-again feature or way to delete the node state directory (decide where to use `removeTailnetLockState` and how to provide U1's "register again as a new node" during migration). Swiftail supports both paths (gate (b) items 1 and 2).

## 6. First adopter changes

These are recorded as context for F1–F3, outside the contract. Changes to the repository require separate approval (plan §7 M7).

- Remove the `.control(.tailnetLockEnabled)` branch from the `switch`.
- Receive `.tailnetLockChanged` from `node.events`. If there is a `signingRequest`, show both values and make them copyable. For `mode == .unverified`, show a message conveying "the connection was left closed because tailnet lock status could not be verified."
- "Reset login" that deletes the state directory also deletes `tailnet-lock.cbor`, since it is in the same directory.
- Swiftail logs (behavior K5) replace the Go core's lock diagnostic logs (`core/internal/node/node.go:492-504`).

## 7. Tests and gates

### Unit tests (no sockets or time)

`Tests/SwiftailTKATests` (new test target):

1. **CBOR writing**. Shortest encoding of integers 0, 23, 24, 255, 256, 65,535, 65,536, 2^32−1, 2^32, and 2^64−1, length boundaries, and null. The three reference byte strings in behavior E4. Ordering of `Meta{"bb","a","c"}`.
2. **CBOR read acceptance and rejection table** (the two tables in notes §8.1 are reference values). Acceptance covers unknown integer keys (with integer, float, negative integer, true, undefined, invalid UTF-8 text, and nested map values), unknown negative keys, unknown text keys (`"MessageKind"`, `"messagekind"`, `"1"`), duplicate keys inside unknown values, non-shortest integers (values and keys), unsorted keys, omitted `PrevAUMHash`, kind 9, null `MessageKind`, empty `Meta`, integer key 2^63−1, and simple value 99 and float64 values. Rejection covers duplicate keys in structures and `Meta` (known, unknown integer, text, and negative keys), indefinite-length maps and byte strings, tags (including `c24101` inside an unknown value), trailing bytes, empty input, a top-level array, kind 256, negative and float kinds, text `PrevAUMHash`, `Meta` bstr keys, integer keys, bstr values, integer values, and invalid UTF-8, truncated byte strings, bstr, float (`f93c00`), true, null, and array keys, invalid UTF-8 text keys (`61ff`), integer key 2^64−1, non-map `Signatures` elements, nesting at level 16 (accepted) and 17, arrays of 4,096 (accepted) and 4,097 elements, and maps of 1,024 (accepted) and 1,025 pairs. No crash on any prefix cut at a byte boundary or on arbitrary bytes.
3. **Hashes**. Re-encoding the genesis checkpoint (notes §7.1, 558 bytes) matches the original, `hash` is `4a6313e0…eea8`, and `signatureHash` is `f34f12d8…f325` (8.1). For noncanonical input, `hash ≠ BLAKE2s(original)`. `AUMHash(text:)` rejects lowercase, padding, 51 and 53 characters. Final characters `A`, `B`, and `P` yield the same hash and `Q` yields a different hash.
4. **Static validation** (behavior A1). Required and forbidden fields by kind, `Votes` 0, 1, 4,096, and 4,097, `Meta` of 512 and 513 bytes, signature KeyID of 31 and 33 bytes and signature of 63 and 65 bytes, checkpoint disablement value counts of 0, 1, 32, and 33, 31-byte values and duplicates, key counts of 0, 1, 512, and 513 and duplicates, length-0 `PrevAUMHash`, and UpdateKey with an empty `Meta` map.
5. **Verification and application** (behaviors A2–A7). No signature, an unknown key's signature mixed in, bad signature, 33-byte `PrevAUMHash`, AddKey of an existing key, RemoveKey and UpdateKey of missing keys, removal of the last key, checkpoint with different StateID, kinds 0 and 9 advancing the head, and RemoveKey in a position with no parent.
6. **Fork resolution** (behavior F1). Higher weight wins, two signatures by the same key count once, RemoveKey wins ties, and the smaller hash wins remaining ties. Adding a child to a losing fork leaves the head unchanged.
7. **Admission** (behavior F4). Empty group, parentless AUM, AUM with unknown parent, AUM already held, rejecting the whole group if one update fails, group in the wrong order, and head after a group creates a fork.
8. **Bootstrap and reopen** (behaviors F5 and F6). Non-checkpoint AUM, checkpoint without a signature from a key in its own state, same head and state after reopening persisted data, store with two roots, store missing a parent, and store with a changed signature.
9. **Sync computation** (behaviors Y1 and Y4). Offer ancestor lists (0, 1, and multiple checkpoints, beyond 1,000), equal heads, head intersection, tail intersection, no intersection, and iteration limits.
10. **NKS** (behavior S). Direct, 1 and 15 rotation layers (pass) and 16 layers, credential alone (rejected), credential → rotation, omitted intermediate `WrappingPubkey`, missing rotation key, different node key, untrusted KeyID, removed key, direct with `Nested`, 31-byte trusted key, nested `Pubkey` outside `np` format, and order of `previousNodeKeys` in history. A signature valid only under ZIP-215 (with a point of order 2 added to R) is valid for direct and rejected for the outer layer of rotation (notes §8.1).
11. **Peer sets** (behaviors P2–P5). Missing signatures, obsolete keys, only the longest history surviving a `WrappingPubkey` group, all removed on tied lengths, and no grouping of credential chains.
12. **Disablement secret** (behavior X). Reference value, wrong secret, empty secret, and a match among multiple disablement values.
13. **Signature creation** (behaviors R3, R5, and R7). Parse the wrapped auth key string in the Go tests (notes §7.1). Rejections cover missing `-`, padded base64, URL alphabet, non-credential A, 63- and 65-byte B, B with different last 32 bytes, A with a different `WrappingPubkey`, and exceeded limits. Created signatures pass `authorize`. Re-signing reuses the signature for the same key, passes for direct with the NL key as rotation key, produces signatures that fail verification for credential chains and direct signatures without `WrappingPubkey`, and trims on the 16th.
14. **Limits and secrets**. Swiftail limit boundaries from behavior M. Key bytes are absent from `WrappedAuthKey` `description` and `dump`.

`Tests/SwiftailControlTests`:

15. **Identity**. NL key round trip, old file lacking `NLKey` (generates and saves a new key), `nlpriv:` with wrong last 32 bytes, and no NL private key in `dump`.
16. **Registration requests** (behavior R). Nonzero `NLKey`, only the prefix in `Auth.AuthKey` for a request made with a wrapped key, **no base64 or hexadecimal wrapped private key anywhere in request bytes**, `NodeKeySignature` as base64 NKS, null for unsigned requests, and `invalidConfiguration` for invalid `--TL` before any request is sent.
17. **`MapSession` `serverLock`** (behaviors N1 and O1). No `TKAInfo` in first response (disabled), present, omitted mid-session (retained), `Disabled`, unreadable `Head` (disabled), empty `Head` (enabled with no head), and a changed `Head` with the same netmap.
18. **`TailnetLockPlan`** (behavior N2). Six table rows and byte comparisons of heads.
19. **TKA RPC JSON** (behavior Y7). Key names of all three requests and `"Head":""` and `"MissingAUMs":[]`, response base64 decoding, body over the limit, and non-200 response. Method is `GET` with no `Content-Type`.
20. **Persistence** (behavior T). Write and read, 0600, bad trailing hash, truncated file, unknown format version, more than 17MiB, continued filtering with in-memory state after write failure, and deletion.
21. **Filtering and status** (behaviors P and N6). `peers` and `filteredPeerCount` in `.disabled`, `.enforcing`, and `.unverified`, retention of an `UnsignedPeerAPIOnly` peer, and `signingRequest` (`nodekey:` and `tlpub:` text) when local signature is missing.

`Tests/SwiftailTests`:

22. **Node**. `status.tailnetLock` follows the netmap, `tailnetLockChanged` emits only on changes, and a locked-out node reaches `.running`.

### Comparison against Go reference values

`Tools/interop/cmd/tkafixtures` (new tool). Follow the existing reference tool conventions in `Tools/interop/README.md`. Build with `sh Scripts/build-interop-tools.sh tkafixtures`. With a directory argument, write `Tests/SwiftailTKATests/Fixtures/tka-fixtures.json`, otherwise write the same JSON to stdout. Record `go` and `tailscale` versions under `reference` and reject version mismatches. Do not read or run Swift source. Use no network, current time, or external randomness. For keys, use `SHA-256("swiftail-fixtures/tka/<role>/<number>")` as Ed25519 seeds and node key inputs (public, test-only values). Go Ed25519 signatures are deterministic, so regenerating yields the same bytes. All decisions come from public functions in Go's `tka` package (notes §7.2). A **different session** from the implementer writes the comparison tests (`GoComparisonTests.swift`).

| Array | Generated data | What Swift compares |
| --- | --- | --- |
| `cbor` | For each input hex string, the kind (AUM or NKS), whether `Unserialize` and `StaticValidate` succeeded, and on success the re-encoded bytes, `Hash`, and `SigHash` | Bytes and hashes match for inputs that pass static validation. Otherwise compare only the rejection decision (behaviors E6 and D8) |
| `chains` | Per scenario, bootstrap AUM and steps (AUM hex list for `Inform`, success, resulting head, resulting state with key KeyID, `Votes`, and `Meta`, disablement values, and StateID) | Success, head, and state at each step |
| `sync` | AUM lists from both stores, each side's `SyncOffer`, `MissingAUMs` against the other side's offer (hash list or error), and head after receipt | Offer, list, error status, and head |
| `signatures` | Per (chain step, node key, NKS hex), `NodeKeyAuthorizedWithDetails` decision and history (`PrevNodeKeys`, initial signature kind and `WrappingPubkey`) | Decision and history |
| `peerSets` | Peer list (node key, NKS) and surviving peers. `rotationTracker` is an unexported type, so call it by overlaying a file on a temporary copy at execution as `mapfixtures` does. If that fails, copy the table in `TestRotationTracker` (`ipn/ipnlocal/tailnet-lock_test.go:1088`) with its origin | Surviving peers |
| `disablement` | Secret, `DisablementKDF` value, and `ValidDisablement` against state | Value and decision |
| `authKeys` | Wrapped auth key string and `DecodeWrappedAuthkey` result (auth key portion, credential hex, key length), and Go behavior for each malformed variant ("return the full original," "panic") | Matching parts for valid inputs. Swiftail rejects every variant (behavior R3) |
| `resign` | Old signature, NL seed, new node key, `ResignNKS` result, and its decision | The created signature's `signatureHash` matches Go's, and Swift verifies Go's signature with the same result |

Scenarios to generate:

1. Linear chain. Genesis checkpoint → AddKey → UpdateKey (`Votes`, `Meta`) → RemoveKey → NoOp → Checkpoint → subsequent AddKey. One long chain with a checkpoint at the 51st position (ancestor list).
2. Forks. Different weights, equal-weight RemoveKey versus AddKey, a tie broken by hash, descendants of losing forks, and a winning fork diverging at an old point (shape of recovery AUM).
3. Rejection. No signature, mixed unknown-key signature, invalid signature, removal of the last key, duplicate AddKey, checkpoint with different StateID, parentless AUM, AUM with an unknown parent, 33-byte `PrevAUMHash`, and the entire group containing an invalid AUM.
4. Unusual accepted input. Kinds 0 and 9, NoOp carrying extra fields, AddKey with `Public` null, length 0, 31 bytes, or 33 bytes followed by a chain, and AUM with unknown fields and non-shortest integers (hash uses canonical bytes).
5. Signature valid only under ZIP-215. AUM with that signature (accepted), direct NKS (passes), and the outer layer of rotation (rejected). Trusted key with a noncanonical public key.
6. NKS. Direct, 1–15 rotation layers and 16 layers, credential → rotation, trimmed chain, decision after key removal, and a different node key with the same signature.
7. Decoder. All inputs in notes §8.1 and cases absent from the notes (reserved additional information, simple values below 32 encoded in 2 bytes, duplicate keys with non-shortest encoding, null in a noninteger field, null `Signatures` elements, and negative key boundary).
8. Synchronization. Node behind, node ahead (AUMs unknown to the server), two divergent sides, and no intersection.

Verification command (one JSON object on stdin, one JSON line on stdout, exit code 1 on failure). `tkafixtures verify-nks` takes a chain of AUMs, node key, and NKS and returns Go's decision and history. Use it to check Swift-created signatures (`SignByCredential` and re-signing), whose bytes differ each time.

### Gate (a) without an account

Test against `tailnet` in `Tools/interop` (testcontrol + DERP + STUN + Go tsnet peer). Put the tests in `Tests/SwiftailInteropTests/TailnetLockTests.swift` and skip when `SWIFTAIL_TAILNET` is absent.

testcontrol capabilities and gaps (notes §7.3). Available are enabling lock (`init/begin` and `finish`), `bootstrap` (genesis only), `sync/offer`, `sign`, map response `TKAInfo{Head}`, and the `tailnet-lock` capability (`DefaultNodeCapabilities`). **Absent are `sync/send`, `disable`, `bootstrap` with a disablement secret, `TKAInfo.Disabled`, and storage of registration request `NodeKeySignature`.**

Tool additions (decision L15 (a)):

- In the testcontrol copy, add `sync/send` (`tkatest.HandleTKASyncSend`), `disable` (clear the store and remember the received secret), post-disablement `bootstrap` returning `DisablementSecret` (correct or deliberately wrong), and `TKAInfo{Disabled: true}` in map responses. Verify the registration request's `NodeKeySignature` with Go `NodeKeyAuthorized` and store it as that node's `KeySignature` if it passes.
- `tailnet` commands are `setLockCapability` (before first registration, adds `tailnet-lock` to existing capabilities), `lockInit` (enables lock with Go peers as signing devices), `lockStatus` (the Go peer's `NetworkLockStatus` with enabled status, head, whether it is signed, and node keys of remaining and filtered peers), `lockSign` (signs the node key and rotation key), `lockWrapAuthKey` (wraps an auth key, a test-only value), `lockModify` (adds or removes signing keys), `lockDisable` (disables lock, with `wrongSecret` causing the server to supply a wrong secret), and `lockRegistrations` (presence of `NLKey` and `NodeKeySignature` in registration requests received by testcontrol, Go's decision, and whether the request body contains traces of the wrapped key).

| # | Check | Pass criteria |
| --- | --- | --- |
| 1 | Bootstrap | When the Swift node registers on a test tailnet with lock enabled, `mode` is `.enforcing` and `head` matches the Go signing device's `lockStatus` head. Registration request `NLKey` is nonzero |
| 2 | Lockout before signing | `signingRequest` is present and its `nodeKey` and `lockKey` match the registered values. `tailnetLockChanged` was emitted. Go peers' `lockStatus` lists the Swift node as filtered. The Swift node's netmap retains signed Go peers |
| 3 | After signing | Passing the two values from item 2 to `lockSign` makes `signingRequest` nil, brings the Swift node into the Go peer's netmap, and enables UDP echo and TCP on both sides |
| 4 | Signed auth key | A new Swift node registered with a key made by `lockWrapAuthKey` is unlocked from the start. `lockRegistrations` shows that Go accepted the request's signature and that the body contains no trace of the wrapped private key |
| 5 | Unsigned Go peer | Adding an unsigned Go peer leaves it out of the Swift node's `peers` and increases `filteredPeerCount`. At the same point, the Go signing device and the Swift node retain and filter the same peer node keys (exclude the Swift node itself and `UnsignedPeerAPIOnly` peers from comparison). The Swift node does not answer packets from that peer |
| 6 | After chain growth | Adding and removing keys with `lockModify` advances the Swift node's `head` to match Go's. Swift and Go nodes both remove peers signed only by a removed key |
| 7 | Lock disabled | After `lockDisable`, `mode` is `.disabled`, unsigned peers are visible again, and `tailnet-lock.cbor` is absent. With `wrongSecret`, mode stays `.enforcing` and the file remains. A response without `TKAInfo` injected midstream does not change the state. If the first response on the reconnected stream lacks `TKAInfo`, start the disablement procedure |
| 8 | Restart | Restarting with the same state directory filters with the same `head` without a bootstrap RPC (verify against requests received by testcontrol). If the chain grew in the meantime, synchronization catches up. The NL key is unchanged |
| 9 | Node key rotation | After a signed Swift node changes its node key through a new login and testcontrol requests re-signing, Go accepts the re-signed request's signature and the Go peer removes the old key as obsolete (requires testcontrol to request re-signing. If difficult to add, substitute comparison using `tkafixtures verify-nks` and record that) |
| 10 | Fail closed (U1 is (b)) | Corrupting the bootstrap response gives `mode` `.unverified` and empty `peers`. Restoring it gives `.enforcing` on the next retry. Corrupting the store file and restarting gives `.unverified` |
| 11 | Tailnet without lock | Existing gates (M2–M7) still pass. `mode` is `.disabled` and no TKA RPCs are sent |
| 12 | Entire suite | All of `eyebuild swift <purpose> -- test` passes with 0 warnings |

### Gate (b) on a real tailnet

Check only what cannot be observed locally. Notify the owner first each time (plan §4(b)).

| # | Check | Pass criteria |
| --- | --- | --- |
| 1 | Registration with a signed auth key | Register an ephemeral node in a real tailnet with lock enabled. `mode` is `.enforcing` and the node is unlocked. Another signed device sees this node (its `tailscale status` and `tailscale lock status`) and ping works |
| 2 | Signing device signs later | Register with an unsigned auth key (or sign in) to get a `signingRequest`. Use its two values with `tailscale lock sign` on the signing device to clear lockout and enable communication |
| 3 | Record production server behavior | Record whether this node gets the `tailnet-lock` capability (U2), whether bootstrap supplies genesis or a later checkpoint, the count of `MissingAUMs` and response size, the server response to unsigned registration, and the sync/send response |
| 4 | Restart and synchronization | Restart resumes from persisted state. If a signing device adds a key in the interim (only with the owner's permission), the head catches up |
| 5 | iPhone tunnel | The M5 tunnel build's node is unlocked in the same tailnet and reaches the Mac's tailnet HTTPS. Disablement secret verification does not run, so record normal memory use |

What to obtain from the owner:

- A tailnet with lock enabled and one signing device on that tailnet (the owner runs the commands directly).
- A **signed auth key** for an ephemeral node, created with `tailscale lock sign <auth key>` on a signing device. Receive it through secret input outside chat. Use a fake hostname in the form `rd-mac-1a2b3c4d`.
- One unsigned auth key for item 2 and one run of `tailscale lock sign <node key> <lock key>` on a signing device.
- Leave lock enabled on the real tailnet (check disablement only under gate (a) item 7).

#### Results on a tailnet with lock enabled (2026-11-15)

The Mac command-line test covered item 2 and the first half of item 4. See `SwiftailHost.md` "Results of gates 1 and 2." Registration with an unsigned auth key reaches `.running` with `enforcing`, lockout, and `signingRequest`. Running `tailscale lock sign` with those two values on the signing device **clears lockout without restarting**. Restarting resumes from persisted state with unlocked `enforcing` from the first netmap. Item 3 observations were that the node receives the `tailnet-lock` capability and the server accepts `set-dns` from a locked-out node. Remaining are item 1 (signed auth key. The first adopter does not use this path, F3), the rest of item 3 (count of `MissingAUMs` and sync/send response), and the latter half of item 4 (whether the head catches up when a key is added).

iPhone tunnel (item 5, first adopter session, 2026-11-15, iPhone 14 Pro iOS 27.2, Swiftail tunnel variant). A node from another tailnet registered in this tailnet via the app's "Sign in with a different account." One second after registration, "bootstrapped" appeared once, immediately followed by `enforcing`, lockout, and 0 filtered peers, then `.running` 1 second later. Neither `disabled` nor `unverified` appeared before signing. There was no sync line ("admitted … AUMs") because bootstrap with current state leaves nothing to synchronize. After signing, the Mac no longer listed this node as a filtered peer. **Whether lockout cleared without a restart could not be determined** (around signing time, the tunnel restarted once for another reason, and the first line of that run already showed it unlocked). Starting with the second run, it entered unlocked `enforcing` immediately without bootstrap. Extension memory was 7.9MiB immediately after bootstrap and 7.3–9.0MiB idle (disablement secret verification did not run). The node reached the Mac's tailnet HTTPS and received 100MiB (`SwiftailNetstack.md` "first value in (b) 6").

#### Earlier results on a tailnet with lock disabled (2026-11-15)

Before using a tailnet with lock enabled, the lead session directly tested two paths that all nodes take regardless of lock on the production server (lock disabled in the tailnet, ephemeral node). Tests are in `Tests/SwiftailControlInteropTests/RealTailnetGateTests.swift`.

| Check | Result |
| --- | --- |
| Fresh registration carrying an NL key (`RealTailnetGateTests`) | Passed. Registration succeeded and the map stream stayed uninterrupted for 90 seconds. The server did not report lock enabled, `mode` was `.disabled`, and 0 peers were filtered |
| Upgrade path (`RealTailnetUpgradeTests`). Reconnect with the current version using the existing state directory of a node registered on a pre-M8 commit (`6f30600`, registration request `NLKey` was 0). No auth key supplied | Passed. Registered with the same node key and received a netmap without requiring login (0 interruptions). `NLKey` was saved to the identity file |

**On a tailnet with lock disabled**, the production server accepts re-registration that changes a zero `NLKey` to a value. Upgrading an existing Swiftail node does not require signing in again.

Upgrade on a real device (RemoteDebug session, 2026-11-15). An existing Swiftail node on iPhone 14 Pro (iOS 27.2), an ordinary non-ephemeral node registered with pre-M8 `98cbbf0` on a tailnet with lock disabled, was upgraded about 6 hours later to `a58cc40`. It kept the state directory and had no auth key. **Passed**. Registration took 2 seconds without requiring login. Lock was `disabled`, with 0 filtered peers and no lockout. Connection start to `.running` took about 4 seconds, and a direct path to the sharing peer formed. This also covered a "non-ephemeral node" and a "long interval." This run did not verify whether `NLKey` was saved to the identity file (device files were not read) or a second run.

Unverified is the same upgrade on a tailnet with lock **enabled** (pre-M8 ended with `tailnetLockEnabled` on such a tailnet, so there would be no Swiftail node still registered in that state. A node on a tailnet that enabled lock after it registered does fall into this case).

## 8. Implementation units

Divide ownership so no files overlap. §2 declarations define interfaces between units, and TL-0 finalizes them.

| Unit | Work | Owned files | Order | Estimated size (library / tests) |
| --- | --- | --- | --- | --- |
| TL-0 | Lead session finalizes this contract (L, U, and F answers), adds `SwiftailTKA`, `SwiftailTKATests`, and the `SwiftailControl` dependency to `Package.swift`, stubs the §2 `package` declarations, and updates the relevant lines in the plan, `SwiftailControl.md`, and `SwiftailHost.md` | `docs/`, `Package.swift` | First | — |
| TL-P1 | (Prerequisite, in progress) Ed25519 verification | `Sources/SwiftailCrypto/Ed25519Verification.swift` and tests | Another session | — |
| TL-P2 | (Prerequisite, in progress) BLAKE2b, Argon2i | `Sources/SwiftailCrypto/BLAKE2b.swift`, `Argon2i.swift`, and tests | Another session | — |
| TL-1 | CBOR reading and writing (behaviors E1, D1, D2, and D9, item-level tests 1 and 2) | `Sources/SwiftailTKA/CBOR/*`, `Tests/SwiftailTKATests/CBOR/*` | **Parallel** | 350 / 500 |
| TL-2 | Data formats. `AUMHash` and base32, reading, canonical writing, hashing, and static validation of `TrustedKey`, `AUMSignature`, `AUM`, `AuthorityState`, and `NodeKeySignature` (behaviors E2–E6, D3–D8, and A1, tests 2–4) | `Sources/SwiftailTKA/Model/*`, `Tests/SwiftailTKATests/Model/*` | After TL-1 declarations. **Parallel** with TL-3 and TL-4 (agree on declarations first) | 550 / 700 |
| TL-3 | `Authority` verification, application, forks, admission, bootstrap, reopen, sync computation, and disablement secret (behaviors A2–A7, F, X, Y1, and Y4, tests 5–9 and 12) | `Sources/SwiftailTKA/Authority/*`, `Tests/SwiftailTKATests/Authority/*` | After TL-2. Signature tests need TL-P1. Only disablement secret needs TL-P2 | 650 / 900 |
| TL-4 | Signatures. `authorize`, history, peer sets, `WrappedAuthKey`, and re-signing (behaviors S, P2–P5, R3, R5, and R7, tests 10, 11, 13, and 14) | `Sources/SwiftailTKA/Signatures/*`, `Tests/SwiftailTKATests/Signatures/*` | After TL-2. **Parallel** with TL-3 | 450 / 700 |
| TL-5 | Go reference value tool, fixtures, and comparison tests | `Tools/interop/cmd/tkafixtures/*`, the tool name line in `Scripts/build-interop-tools.sh`, a new section in `Tools/interop/README.md`, `Tests/SwiftailTKATests/Fixtures/*`, `Tests/SwiftailTKATests/GoComparisonTests.swift` | Tool in **parallel** (start with TL-1). Comparison tests after TL-2–4, by a **different session** from the implementer | Go 900 / 500 |
| TL-6 | Control registration. NL key and identity file, wiring auth key parsing, request signatures, and re-signing requests (behavior R, tests 15 and 16) | `Sources/SwiftailControl/Client/NodeIdentity.swift`, `NodeIdentityStore.swift`, `AuthKey.swift`, `ControlClient+Registration.swift`, `Sources/SwiftailControl/Tailcfg/NLPublicKey.swift`, and corresponding tests | After TL-4 declarations. **Parallel** with TL-7 | 220 / 350 |
| TL-7 | Control maps. `serverLock`, `TailnetLockPlan`, TKA RPC and tailcfg, `TailnetLockStore`, procedures, filtering, `TailnetLockStatus`, `MapRequest.tkaHead`, and `Netmap.tailnetLock` (behaviors N, Y, P, O, T, and K, tests 17–21) | `Sources/SwiftailControl/Client/ControlClient+TailnetLock.swift`, `TailnetLockStore.swift`, `TailnetLockStatus.swift`, `ControlClient+MapPoll.swift`, `ControlClient.swift`, `Sources/SwiftailControl/Tailcfg/TKA*.swift`, `MapRequest.swift`, `Sources/SwiftailControl/Netmap/*`, and corresponding tests | After TL-3 and TL-4. Largest unit | 600 / 900 |
| TL-8 | Node and wrap-up. `NodeStatus.tailnetLock`, `NodeEvent.tailnetLockChanged`, and removing `ControlError.tailnetLockEnabled` and branches that refer to it (test 22) | `Sources/Swiftail/NodeStatus.swift`, `NodeEvent.swift`, `NodeError.swift`, `TailnetNode.swift`, `TailnetNode+Control.swift`, `Sources/SwiftailControl/Client/ControlError.swift`, the relevant line in `Sources/SwiftailCertificates/CertificateManager.swift`, and corresponding tests | After TL-6 and TL-7 | 120 / 200 |
| TL-9 | Gate (a) tool. testcontrol copy and additions, and `tailnet` lock commands | `Tools/interop/internal/testcontrol/*`, `Tools/interop/cmd/tailnet/lock.go`, `lock_test.go` and the branch in `main.go`, and the `tailnet` section in `Tools/interop/README.md` | **Parallel** (different README section from TL-5) | Go 500 (excluding 2,000 copied lines) |
| TL-10 | Gate (a) tests | `Tests/SwiftailInteropTests/TailnetLockTests.swift` | After TL-8 and TL-9 | — / 500 |
| TL-11 | Independent review. All of `SwiftailTKA` and control procedures (cryptography and protocol code, plan §10) | — | After TL-5 comparison passes, before the lead session reruns gate (a). A **different session** from the implementer | — |
| TL-12 | Gate (b) | With the owner | After U3 | — |

Order is TL-0 → (TL-1, TL-5 tool, TL-9) in parallel → TL-2 → (TL-3, TL-4) in parallel → (TL-5 comparison tests, TL-6, TL-7) → TL-8 → TL-10 → TL-11 → lead session reruns gate (a) → TL-12. TL-P1 and TL-P2 must be done before TL-3 and TL-4 tests run.

### Estimated size

About 2,900 library lines (`SwiftailTKA` 2,000, `SwiftailControl` 820, `Swiftail` 120, excluding cryptography prerequisites), about 5,250 Swift test lines, and about 1,400 Go lines (excluding about 2,000 copied testcontrol lines). Similar to M7 (about 3,200 library lines). The difficulty is decoder correctness, "accept the input and hash canonical bytes," more than size.

### Largest risks

1. **If the decoder re-encodes even one byte differently from Go, protection weakens.** The hash changes and the signature fails verification. The entire group containing that AUM is rejected and state stalls before it. If later key removals cannot be followed, only Swiftail trusts keys that Go nodes no longer trust (failure mode in notes §6.1). Null versus empty, `Meta` bytes, and unknown field handling all affect this. A separate session compares the reference tool's `cbor` and `chains`, and accepted unusual inputs (scenarios 4 and 5) go inside the chain to verify that "subsequent AUMs are followed too." Inputs not enumerated by the notes (§9) remain.
2. **Production control server TKA behavior is absent from the source.** Who receives the capability, what bootstrap supplies, how unsigned registrations and signatures that fail verification are handled, and how sync/send is validated are unknown (notes §8.2). testcontrol is for tests and we write its additions. Record behavior in gate (b) item 3 and revisit U1 and U2 using that record. With U1 (b), a transient server error immediately means "no peers," making retry values (behavior N6) important.
3. **The 16MiB for disablement secret verification.** The iOS extension's idle resident memory is about 8.7MiB and the limit is 50MiB. Overlapping large map frame decoding (peak about 14MB) brings it to about 39MiB. Pure Swift Argon2i speed on a real device is unmeasured. Run one at a time, skip recomputation of the same secret (behavior O6), and sequence procedures so they do not overlap map decoding. Measure once on a real device (gate (a) item 7 using the tunnel test app).
4. **In-house Ed25519 verification and Argon2i** (prerequisite units). A decision differing from Go has the same consequence as item 1. Use those units' vectors (196 ZIP-215, RFC 9106), review by another session, and scenario 5 of this contract.

Other risks are old state remaining when switching tailnets with one state directory (behavior T6), and a difference in decisions for old forks compared with compacted Go nodes because Swiftail does not compact (decision L7).

### Items to leave as `shortcut:`

| Deferred item | When needed |
| --- | --- |
| Compaction (L7) | A tailnet reports storage reaching its limit |
| Re-sign with a wrapped auth key (L9 (c)) | Rotation locks out a node registered with `--TL` |
| Switch tailnets in one state directory (behavior T6) | An adopter needs it |
| Install `UnsignedPeerAPIOnly` peers | When adding a feature such as Funnel ingress |
| Rewrite the entire store on every change | Writes become noticeable as the chain grows |
| The app recovers from an unreadable store only by deleting the file | When this is reported in practice (consider a reset API) |

## 9. Unverified items

Items from notes §8.2 that affect this contract:

- **Production control server behavior**. Which nodes get the `tailnet-lock` capability, whether bootstrap supplies genesis or a later checkpoint, when `RegisterResponse.NodeKeySignature` is sent, how signatures of nodes registered with signed auth keys are stored and distributed, what responses unsigned registration gets, whether admin console signing uses registration request `NLKey` as rotation key, when `UnsignedPeerAPIOnly` is granted, how sync/send `Interactive=false` requests are checked, whether TKA RPCs use 429 or 503, and response size distribution. Gate (b) item 3 records some of this.
- **Whether bootstrap actually fails in production** (magnitude of U1's availability impact).
- **The full set of CBOR decoder inputs accepted** has not been enumerated. The notes' tables cover tested inputs. Go decisions for these contract additions are unverified by execution. Rejection of reserved additional information and simple values below 32 encoded in 2 bytes (behavior D1), whether a duplicate of the same key encoded non-minimally is detected (D4), null in a noninteger known field (D5), null `Signatures` elements, and whether AddKey with null `Public` or a length other than 32 is accepted and what its KeyID is compared as (behavior E6, inferred from notes §3.2 saying `StaticValidate` does not check length). Confirm all with `tkafixtures` scenarios 4 and 7 and update the contract if they differ.
- **Whether compaction leaves decisions unchanged** is unverified in the notes as well. Decision L7 omits compaction and does not depend on this unverified claim, but "matches a Go node that received them less than 14 days ago" comes from the notes §4.11 summary without running Go's `Compact` for comparison.
- **`computeActiveAncestor` determinism** (notes §8.2). Restricted to one root to avoid this path (behavior F6). There is no comparison of Swiftail's head with the head of a Go node whose store has multiple roots.
- **Source read was v1.104.7 and execution used v1.104.6**, without running Go `tka` and `ipnlocal` tests (notes §8.2). Go lines read directly for this contract (`direct.go:534-545` and `:704-747`, `auto.go:706-714`, `tailnet-lock.go:340-437`, testcontrol) are also from v1.104.7.

Unverified items arising from the design:

- **Go state after a second re-signing request** (behavior R6). Only verified by reading that `doLoginOrRegen` discards the second response's re-signing request. Whether Go considers itself registered afterward was not traced.
- **Whether Go's first map request includes `TKAHead`** (behavior N4). Only the head setter (`SetTKAHead`) was read. Whether a stored head is set at startup before the first request is unverified.
- **Server behavior when an already registered Swiftail node reconnects with a new key replacing its zero `NLKey`** (behavior R1). M2–M7 nodes sent zero.
- **Whether the server retains the old signature on reconnection with a registered key (without an auth key) when the request omits the signature** (behavior R5 ③).
- **Whether the testcontrol additions work**. Only `tkatest.HandleTKASyncSend` and the copy's map response and registration handlers were read, with no build. testcontrol has no precedent for disablement or re-signing requests, so production server behavior is inferred (gate (a) items 7 and 9 only show that "Swiftail and Go clients react alike to the same server behavior").
- **Whether `rotationTracker` can be called by the reference value tool** (§7 `peerSets`). The `mapfixtures` approach was not tried with `ipn/ipnlocal`.
- **Pure Swift Argon2i time and peak memory**, and `phys_footprint` when overlapping map decoding.
- **Decision L11 relies on `MapSession` emitting a full netmap per response**. Verified by reading `Sources/SwiftailControl/Netmap/MapSession.swift` and `ControlClient+MapPoll.swift:81-96`. Revisit if a path delivering only deltas to the node is added.
- For **the first adopter's Swift code**, only the line using `tailnetLockEnabled` and the Go core's diagnostic log were located and read. How the status screen receives the new event depends on F2's answer.
- This contract's declarations were not compiled (this was a session without code changes). No builds or tests ran.
