# Tailnet Lock (TKA) Notes for Ordinary Nodes

## 1. Introduction

| Item | Details |
| --- | --- |
| Reference version | Examined `tailscale.com` **v1.104.7** (CapabilityVersion 148, `tailscale.com/tailcfg/tailcfg.go:200`). Only 8 files differ from the README reference version v1.104.6: `VERSION.txt`, `go.mod`, toolchain files, `k8s-operator/api-proxy/proxy{,_test}.go`, and `flakehashes.json` (verified with `diff -rq`). The files cited in these notes are identical in both versions, including their line numbers |
| Dependency modules | `github.com/fxamacker/cbor/v2` v2.9.3, `github.com/hdevalence/ed25519consensus` v0.2.0, `golang.org/x/crypto` v0.58.0 (`tailscale.com/go.mod:51`, `:80`, `:139`). The Go standard library is Go 1.27.3's `src/` |
| Applicable milestone | M8 ① Tailnet Lock (`docs/plan.md` §3, milestone table M8) |
| Authoring model | Claude Opus 5.5 (`claude-opus-5-5`), 2026-11-15 |
| Verification | Verified (2026-11-15, Claude Opus 5.5 `claude-opus-5-5`, in a separate session from authoring). Checked against `tailscale.com` v1.104.7 sources (ran v1.104.6 and reconfirmed the 8 differing files), `fxamacker/cbor/v2` v2.9.3, `ed25519consensus` v0.2.0, `golang.org/x/crypto` v0.58.0, and Go 1.27.3 `src/`. Factual statements assessed: 256 correct, 11 incorrect (9 in substance, 2 in origin line numbers), and 4 unverifiable. Made 11 corrections and added 12 missing paths. See the "Verification session" table in §8.1 for execution records |

Origins use `path:line` relative to the module root. Module prefixes are abbreviated as `tailscale.com/`, `cbor/` (= `fxamacker/cbor/v2@v2.9.3/`), `ed25519consensus/`, `x/crypto/` (= `golang.org/x/crypto@v0.58.0/`), and `go/src/` (Go 1.27.3). Swiftail repository paths use `Sources/...`. §8.1 records the commands used to verify behavior by execution. Example values are fictitious or come from Go test files.

## 2. Scope

In scope (ordinary nodes without signing authority)

- Data formats. CBOR byte formats for `AUM`, `Key`, `tkatype.Signature`, `State`, and `NodeKeySignature` (NKS), along with hash and signature inputs and text representations.
- CBOR. Go's encoding and decoding options, their byte-level implications, and the subset Swiftail needs.
- Verification. AUM acceptance, state application, fork resolution and head selection, NKS verification (direct, rotation, credential), and disablement secret verification.
- Client procedures. NL keys, registration (signed auth keys and server requests to re-sign), netmap processing (bootstrap, synchronization, disablement), peer filtering, local storage, and capability conditions.
- Material for interop tests that verify this work.

Out of scope (signing devices and administrative functions, with verification rules for their outputs covered above)

- Signing other nodes (`TailnetLockSign`, `/machine/tka/sign`), enabling lock (`/machine/tka/init/begin` and `/init/finish`), disable command (`/machine/tka/disable`), adding and removing signing keys (`TailnetLockModify`, `UpdateBuilder`), wrapping auth keys (`TailnetLockWrapPreauthKey`), recovery AUMs (`MakeRetroactiveRevocation`, `revoke-keys`), signing deep links (`tka/deeplink.go`), querying affected signatures (`/machine/tka/affected-sigs`), and forced local disablement (`TailnetLockForceLocalDisable`) (`tailscale.com/ipn/ipnlocal/tailnet-lock.go:696-1300`, `tailscale.com/tka/builder.go:36-187`, `tailscale.com/tka/tka.go:750-860`).
- c2n `/debug/tka/log` (`tailscale.com/feature/tailnetlock/tailnetlock.go:21-26`). tsnet does not import `feature/condregister` (`tailscale.com/tsnet/tsnet.go:181-185`).
- Go state file migration (owner decision to omit it).

## 3. Wire Format

### 3.1 CBOR Rules

**Encoding.** `AUM.Serialize`, `NodeKeySignature.Serialize`, and tailchonk files all use `cbor.CTAP2EncOptions()` (`tailscale.com/tka/aum.go:249-260`, `tailscale.com/tka/sig.go:219-232`, `tailscale.com/tka/tailchonk.go:733-742`). These options have the following effects (`cbor/encode.go:641-660`, `cbor/encode.go:183-202`).

| Rule | Details | Origin |
| --- | --- | --- |
| Integers and lengths | Shortest encoding (argument rules in RFC 8949 §3: 0~23 in the first byte, larger values in 1, 2, 4, or 8 bytes in big-endian order) | `cbor/encode.go:644-646` |
| Map key order | Lexicographic order of encoded key bytes (`SortBytewiseLexical`). Integer keys 1~23 take one byte and therefore follow numeric order. String keys sort shorter strings first because their initial byte encodes the length (Go run: `{"bb","a","c"}` → `a`, `c`, `bb`, §8.1) | `cbor/encode.go:183-187`, `cbor/encode.go:1393-1394` |
| Indefinite length | Prohibited | `cbor/encode.go:657` |
| Tags | Prohibited | `cbor/encode.go:658` |
| Floating point | Unchanged. TKA structures have no floating-point fields ("No floats!") | `cbor/encode.go:654`, `tailscale.com/tka/aum.go:131` |

Struct fields use the `cbor:"N,keyasint"` tag to form an **integer-keyed map**. For fields without `omitempty`, Go `nil` slices and pointers encode as CBOR null (`0xf6`), while zero-length non-nil slices encode as an empty byte string (`0x40`) or an empty array (`0x80`). The hashes differ (`tailscale.com/tka/aum_test.go:26-44`, `tailscale.com/tka/key.go:56-57`, Go run in §8.1: `PrevAUMHash=[]byte{}` → `a201030240`). A field with `omitempty` is omitted for a nil pointer, a zero-length slice or map, or an integer of 0. A pointer to 0 is retained (Go run: `Votes=&0` leaves `0600`, and empty `Meta={}` is omitted, §8.1).

**Decoding.** Use `cborDecOpts` (`tailscale.com/tka/tka.go:22-32`). AUMs, NKSs, and tailchonk files share these options (`tailscale.com/tka/aum.go:268-271`, `tailscale.com/tka/sig.go:239-242`, `tailscale.com/tka/tailchonk.go:466-474`). AUMs and NKSs use `Unmarshal`, which first checks that the entire input is well-formed and rejects trailing bytes (`cbor/decode.go:1291-1302`). Tailchonk files use the streaming `Decoder.Decode`, which reads only the first item (`tailscale.com/tka/tailchonk.go:472`). The table below covers the `Unmarshal` path.

| Rule | Go behavior | Origin |
| --- | --- | --- |
| Duplicate map keys | Rejected (`DupMapKeyEnforcedAPF`). Duplicate unknown keys in a struct map and duplicate string keys in `Meta` are both rejected. Duplicates in a map **inside the value** of an unknown field were accepted | `tailscale.com/tka/tka.go:24`, `cbor/decode.go:313-319`, Go run in §8.1 |
| Indefinite length | Rejected | `tailscale.com/tka/tka.go:25` |
| Tags | Rejected | `tailscale.com/tka/tka.go:26` |
| Nesting | At most 16 levels (the outermost map is level 1). Rejects 17 levels | `tailscale.com/tka/tka.go:29`, Go run in §8.1 |
| Array elements | At most 4096 | `tailscale.com/tka/tka.go:30`, Go run in §8.1 |
| Map pairs | At most 1024 | `tailscale.com/tka/tka.go:31`, Go run in §8.1 |
| Trailing bytes | Rejected (`extraneous data`) | Go run in §8.1 |
| Unknown fields | Silently discarded (`ExtraDecErrorNone` is the default). A well-formed value is skipped even if it is a float, negative number, true, undefined, or an invalid UTF-8 string | `cbor/decode.go:437-446`, Go run in §8.1 |
| Text keys | Discarded as unknown fields if the UTF-8 is valid. `keyasint` fields are looked up only by integer key, so `"1"`, `"MessageKind"`, and `"messagekind"` also fail to match | `cbor/decode.go:2767-2804`, `cbor/decode_map_utils.go:36-63`, `cbor/cache.go:136-158`, Go run in §8.1 |
| **Keys other than integer or text** | **Rejected.** A bstr, float, true/false/null/undefined, array, or map key in a struct map (AUM, Key, State, Signature, NKS) causes a decoding error. Invalid UTF-8 text keys and positive integer keys of 2^63 or greater are also rejected. Negative integer keys down to −2^63 and positive integer keys up to 2^63−1 are discarded as unknown fields | `cbor/decode.go:2760-2780`, `:2806-2834`, `:2862-2897`, Go run in §8.1 (verification session) |
| `Meta` map | Keys and values must both be text. bstr and integer keys and bstr values are rejected | Go run in §8.1 (verification session) |
| Non-shortest integers and unsorted keys | **Accepted** (canonical form is optional) | Go run in §8.1 |
| Type mismatch in known fields | Rejected (negative numbers, floats, or text in `uint8` or `[]byte`, or integers in `Meta` values) | Go run in §8.1 |
| Out of range | `MessageKind` 256 is rejected due to `uint8` overflow | Go run in §8.1 |
| null | null in a known integer field becomes 0 (e.g., `MessageKind` null → 0) | Go run in §8.1 |
| Known text | Invalid UTF-8 is rejected (`UTF8RejectInvalid` is the default) | `cbor/decode.go:456-459`, `cbor/decode.go:2317-2318`, Go run in §8.1 |
| Outermost item other than a map | Rejected | Go run in §8.1 |

**Compute hashes over the bytes obtained by re-encoding the decoded value.** `AUM.Hash`, `SigHash`, and `NodeKeySignature.SigHash` all call `Serialize` on the struct and then apply BLAKE2s (`tailscale.com/tka/aum.go:274-288`, `tailscale.com/tka/sig.go:208-212`). Inputs with unknown fields, non-shortest integers, or unsorted keys are therefore accepted, and the hash covers the canonical encoding that normalizes them (Go run in §8.1: canonical input gives `hash == blake2s(original)`, other input differs). Signature verification also uses the hash of the re-encoded bytes, leaving unknown fields outside signature protection.

### 3.2 `Key`

`Key` is an integer-keyed map (`tailscale.com/tka/key.go:36-52`).

| CBOR key | Field | Type | Rule |
| ---: | --- | --- | --- |
| 1 | `Kind` | uint (`KeyKind`, uint8) | 0 `KeyInvalid`, 1 `Key25519`. `StaticValidate` accepts only 1 and rejects all other values, including 0 (`tailscale.com/tka/key.go:15-22`, `:128-132`) |
| 2 | `Votes` | uint | 1 through 4096 inclusive (`tailscale.com/tka/key.go:107-113`) |
| 3 | `Public` | bstr | 32-byte Ed25519 public key. `StaticValidate` skips the length check. Signature verification fails if the length differs from 32 (`tailscale.com/tka/verify.go:25-27`, `tailscale.com/tka/sig.go:297-299`) |
| 12 | `Meta` | map(tstr→tstr), omitempty | Sum of all key and value lengths at most 512 bytes (`tailscale.com/tka/key.go:120-126`, `tailscale.com/tka/limits.go:18`) |

KeyID for `Key25519` is the `Public` byte string itself (`tailscale.com/tka/key.go:84-94`, `tailscale.com/types/key/nl.go:87-99`). `tkatype.KeyID` is `[]byte` (`tailscale.com/types/tkatype/tkatype.go:10-19`).

### 3.3 `tkatype.Signature` (AUM Signature)

| CBOR key | Field | Type | Rule |
| ---: | --- | --- | --- |
| 1 | `KeyID` | bstr | 32 bytes (`AUM.StaticValidate`) |
| 2 | `Signature` | bstr | 64-byte Ed25519 signature |

Origin: `tailscale.com/types/tkatype/tkatype.go:35-40`, `tailscale.com/tka/aum.go:168-172`.

### 3.4 `AUM`

`AUM` is an integer-keyed map (`tailscale.com/tka/aum.go:132-156`).

| CBOR key | Field | Type | Notes |
| ---: | --- | --- | --- |
| 1 | `MessageKind` | uint (`AUMKind`, uint8) | No omitempty |
| 2 | `PrevAUMHash` | bstr or null | No omitempty. No parent (genesis) requires **nil=null**. `StaticValidate` rejects a zero-length bstr (`tailscale.com/tka/aum.go:165-167`). `StaticValidate` does not check length. `Parent()` copies from the start into a 32-byte slot (`tailscale.com/tka/aum.go:292-298`). State application compares the 32 bytes of `LastAUMHash` with all bytes of `PrevAUMHash` and fails if the lengths differ (`tailscale.com/tka/state.go:150-155`) |
| 3 | `Key` | `Key` map, omitempty | AddKey |
| 4 | `KeyID` | bstr, omitempty | RemoveKey and UpdateKey. No length check |
| 5 | `State` | `State` map, omitempty | Checkpoint |
| 6 | `Votes` | uint, omitempty (pointer) | UpdateKey |
| 7 | `Meta` | map(tstr→tstr), omitempty | UpdateKey |
| 23 | `Signatures` | array of `Signature` maps, omitempty | Signatures. 23 is the last key that fits in one byte |

`MessageKind` values and permitted fields by kind (`tailscale.com/tka/aum.go:69-94`, `:180-222`).

| Value | Name | Required | Prohibited |
| ---: | --- | --- | --- |
| 0 | `AUMInvalid` | — | No check (default branch) |
| 1 | `AUMAddKey` | `Key` | `KeyID`, `State`, `Votes`, `Meta` |
| 2 | `AUMRemoveKey` | `KeyID` (length>0) | `Key`, `State`, `Votes`, `Meta` |
| 3 | `AUMNoOp` | — | No check |
| 4 | `AUMUpdateKey` | `KeyID` (length>0), at least one of `Votes` or `Meta` (non-nil) | `Key`, `State` |
| 5 | `AUMCheckpoint` | `State` | `KeyID`, `Key`, `Votes`, `Meta` |
| 6 or greater | Unknown kind | — | Accepted without checks. The contract says old clients can safely ignore them (`tailscale.com/tka/aum.go:213-222`) |

Regardless of kind, `StaticValidate` calls `Key.StaticValidate` when a `Key` is present, checks every signature for a 32-byte KeyID and a 64-byte signature, and validates checkpoint state when `State` is present (`tailscale.com/tka/aum.go:159-178`). An empty `Meta` map (`0xa0`) passes UpdateKey validation because it is non-nil, and re-encoding omits it (Go run in §8.1).

### 3.5 `State`

| CBOR key | Field | Type | Notes |
| ---: | --- | --- | --- |
| 1 | `LastAUMHash` | bstr(32) or null | No omitempty. State within a checkpoint requires null (`tailscale.com/tka/state.go:259-261`) |
| 2 | `DisablementValues` | array of bstr or null | No omitempty |
| 3 | `Keys` | array of `Key` or null | No omitempty |
| 4 | `StateID1` | uint64, omitempty | First 8 bytes of a 16-byte random value (little-endian) generated when lock is enabled. Fixed for its lifetime |
| 5 | `StateID2` | uint64, omitempty | Last 8 bytes |

Origin: `tailscale.com/tka/state.go:26-53`, `tailscale.com/ipn/ipnlocal/tailnet-lock.go:720-734`. Go run in §8.1: `StateID1=2^40` gives `041b0000010000000000`.

Static checkpoint state validation (`staticValidateCheckpoint`, `tailscale.com/tka/state.go:258-316`) requires a nil `LastAUMHash`, 1~32 distinct `DisablementValues` of 32 bytes each, and 1~512 `Keys`, each passing `Key.StaticValidate` with a distinct KeyID.

### 3.6 `NodeKeySignature`(NKS)

This is an integer-keyed map (`tailscale.com/tka/sig.go:74-104`). It is the byte representation of `Node.KeySignature`, `RegisterRequest/Response.NodeKeySignature`, and `PeerChange.KeySignature` (`tailscale.com/types/tkatype/tkatype.go:21-22`).

| CBOR key | Field | Type | Use |
| ---: | --- | --- | --- |
| 1 | `SigKind` | uint (uint8) | See the table below |
| 2 | `Pubkey` | bstr, omitempty | **Binary form** of the authorized node public key: `"np"` (2 bytes) + 32 bytes = 34 bytes (`tailscale.com/types/key/node.go:40`, `:350-369`). Credential signatures omit it |
| 3 | `KeyID` | bstr, omitempty | Direct and credential only. KeyID of the trusted key |
| 4 | `Signature` | bstr, omitempty | 64-byte Ed25519 signature |
| 5 | `Nested` | NKS map, omitempty | Rotation only |
| 6 | `WrappingPubkey` | bstr, omitempty | Ed25519 public key (32 bytes) for signing the signature that wraps this one. Intermediate levels in a multilevel rotation may omit it, in which case the inner one is used |

`SigKind`(`tailscale.com/tka/sig.go:26-55`):

| Value | Name | Meaning |
| ---: | --- | --- |
| 0 | `SigInvalid` | — |
| 1 | `SigDirect` | The trusted key (`KeyID`) signs the node key (`Pubkey`) directly |
| 2 | `SigRotation` | The rotation key authorized by `Nested` (`Nested`'s `WrappingPubkey`) signs the new node key (`Pubkey`) |
| 3 | `SigCredential` | The trusted key (`KeyID`) delegates signing authority to another public key (`WrappingPubkey`). It must be nested inside a rotation to authorize a node |

### 3.7 Hash and Signature Inputs

| Value | Computation | Origin |
| --- | --- | --- |
| `AUMHash` | `BLAKE2s-256(Serialize(aum))`. No key, 32-byte output. **Includes** signatures (23) | `tailscale.com/tka/aum.go:21-22`, `:273-276` |
| AUM `SigHash` | `BLAKE2s-256(Serialize)` of a copy with `Signatures` set to nil. Key 23 is omitted entirely | `tailscale.com/tka/aum.go:278-288` |
| AUM signature | `Ed25519.Sign(priv, SigHash 32 bytes)` (pure Ed25519, no context) | `tailscale.com/tka/aum.go:300-314`, `tailscale.com/types/key/nl.go:102-107` |
| NKS `SigHash` | `BLAKE2s-256(Serialize)` of a copy with `Signature` set to nil. `Nested` is included as is | `tailscale.com/tka/sig.go:202-212` |
| NKS signature | `Ed25519.Sign(priv, SigHash 32 bytes)` | `tailscale.com/types/key/nl.go:109-112`, `tailscale.com/tka/sig.go:450-459` |

Ed25519 **verification functions differ by case**. AUM signatures and direct and credential NKSs use `ed25519consensus.Verify` (ZIP-215 rules). The outer signature of a rotation NKS uses Go's standard `ed25519.Verify` (`tailscale.com/tka/verify.go:28`, `tailscale.com/tka/sig.go:273`, `:300`). §6.1 explains the difference between the rules.

### 3.8 Text Representations

| Representation | Format | Origin |
| --- | --- | --- |
| `AUMHash` text | RFC 4648 base32 **standard alphabet (uppercase), no padding**, 32 bytes → 52 characters. Lowercase and lengths other than 52 are rejected. The remaining 4 bits of the last character are unchecked (Go run in §8.1: final `A`, `B`, and `P` give the same hash). Compare the decoded 32 bytes of two heads to match Go | `tailscale.com/tka/aum.go:24-51`, Go run in §8.1 |
| `nlpub:` | Lowercase hex for the 32-byte NL public key. Decoding accepts both `nlpub:` and the CLI form `tlpub:` | `tailscale.com/types/key/nl.go:15-30`, `:133-157`, `tailscale.com/types/key/util.go:56-85` |
| `nlpriv:` | Hex for the **64-byte** NL private key (Go `ed25519.PrivateKey` = 32-byte seed ‖ 32-byte public key) | `tailscale.com/types/key/nl.go:34-37`, `:59-67` |
| `nodekey:` | Hex for the 32-byte node public key (JSON). An NKS uses the `np` binary form in §3.6 | `tailscale.com/types/key/node.go:40`, `:350-369` |
| Signed auth key | `<auth key>--TL<A>-<B>`. Split at the first `--TL` and split the rest at the first `-`. A = credential NKS CBOR, B = 64-byte Ed25519 private key, both **base64 RawStd (no padding, `+/`)** | `tailscale.com/tka/sig.go:462-498`, `tailscale.com/ipn/ipnlocal/tailnet-lock.go:1226`, `:1234-1258` |

If the `-` is missing or base64 or CBOR decoding fails, Go's `DecodeWrappedAuthkey` only logs the failure and returns the **entire original string** (including the suffix) as the auth key (`tailscale.com/tka/sig.go:472-494`). This sends the suffix containing the private key to the server. Swiftail currently always sends only the portion before `--TL` (`Sources/SwiftailControl/Client/AuthKey.swift:10-13`). Keeping this as an intentional difference is safer.

`DecodeWrappedAuthkey` checks neither B's length nor A's `SigKind` (`tailscale.com/tka/sig.go:484-497`). `SignByCredential` checks the kind (`:443-445`) and passes B directly to `ed25519.Sign`, so Go **panics** if B is not 64 bytes (`go/src/crypto/ed25519/ed25519.go:205-224`, `go/src/crypto/internal/fips140/ed25519/ed25519.go:110-114`, Go run in §8.1: 63 bytes → `bad private key length: 63`). Go hashes the last 32 bytes of B directly as the public key without recomputing it from the seed (`go/src/crypto/internal/fips140/ed25519/ed25519.go:125-128`). At the boundary, Swiftail should check that B is 64 bytes and that the public key derived from the seed matches both the last 32 bytes of B and the credential's `WrappingPubkey`. A mismatch should end the operation with an error before registration (all three match in Go's test string, Go run in §8.1).

### 3.9 TKA Fields in the Control Protocol (JSON)

| Message | Field | Format and meaning | Origin |
| --- | --- | --- | --- |
| `RegisterRequest` | `NLKey` | `nlpub:` text. Go always includes a nonzero key | `tailscale.com/tailcfg/tailcfg.go:1330`, `tailscale.com/control/controlclient/direct.go:721-725`, `:763` |
| `RegisterRequest` | `NodeKeySignature` | Base64 NKS CBOR (JSON `[]byte`). Null if absent | `tailscale.com/tailcfg/tailcfg.go:1345-1350` |
| `RegisterResponse` | `NodeKeySignature` | When present, requests re-signing the current signature for the new node key | `tailscale.com/tailcfg/tailcfg.go:1379-1381` |
| `MapRequest` | `TKAHead` | Base32 text of the local head, or an empty string if there is no lock (omitzero) | `tailscale.com/tailcfg/tailcfg.go:1500-1503`, `tailscale.com/control/controlclient/direct.go:1103` |
| `MapResponse` | `TKAInfo` | `{"Head": base32, "Disabled": bool}`, both omitempty. Nil in the first response means lock is off. Later nil values mean no change | `tailscale.com/tailcfg/tailcfg.go:2179-2187`, `tailscale.com/tailcfg/tka.go:85-102` |
| `Node` | `KeySignature` | The node's NKS (omitempty) | `tailscale.com/tailcfg/tailcfg.go:388-390` |
| `Node` | `UnsignedPeerAPIOnly` | A node allowed to use only PeerAPI without a signature. Exempt from TKA filtering | `tailscale.com/tailcfg/tailcfg.go:488-494` |
| `PeerChange` | `KeySignature` | Signature changed | `tailscale.com/tailcfg/tailcfg.go:3055-3057` |

Capability version history: 40 introduced `Node.KeySignature` and `PeersChangedPatch.KeySignature`, 47 introduced `Register{Request,Response}.NodeKeySignature`, 48 introduced `Node.UnsignedPeerAPIOnly`, 51 introduced `CapabilityTailnetLockAlpha`, and 64 renamed it to `CapabilityTailnetLock` (`tailscale.com/tailcfg/tailcfg.go:91`, `:98-99`, `:102`, `:115`). The node capability string is `https://tailscale.com/cap/tailnet-lock` (`tailscale.com/tailcfg/nodecap/nodecap.go:74-75`, `tailscale.com/tailcfg/tailcfg.go:2513`).

### 3.10 TKA RPCs (Three Used by Ordinary Nodes)

All three RPCs use **`GET` with a JSON body** over the Noise channel (ts2021 HTTP/2). Go sends `http.NewRequestWithContext(ctx, "GET", "https://unused/machine/tka/...", body)` through `DoNoiseRequest`. This path omits `Content-Type` and the load-balancing header (`Ts-Lb`), which only `DoWithBody` adds. Each request has a 1-minute deadline. A status other than 200 fails with the entire body in the error. The response body is decoded as one JSON value (`tailscale.com/ipn/ipnlocal/tailnet-lock.go:1377-1516`, `tailscale.com/control/controlclient/direct.go:1798-1807`, `tailscale.com/control/ts2021/client.go:299-336`, `tailscale.com/tailcfg/tailcfg.go:3109`). testcontrol rejects methods other than `GET` with 400 (`tailscale.com/tstest/integration/testcontrol/testcontrol.go:1138-1142`).

| Path | Request JSON | Response JSON | Response body limit |
| --- | --- | --- | --- |
| `/machine/tka/bootstrap` | `TKABootstrapRequest{Version: 148, NodeKey, Head}`. `Head` is the local head in base32, or `""` if absent (field always present) | `TKABootstrapResponse{GenesisAUM?, DisablementSecret?}`. Both are base64 bstr, omitempty | 1 MiB (default) |
| `/machine/tka/sync/offer` | `TKASyncOfferRequest{Version, NodeKey, Head, Ancestors[]}` | `TKASyncOfferResponse{Head, Ancestors[], MissingAUMs[]}`. `MissingAUMs` is an array of base64 AUM CBOR | **512 MiB** |
| `/machine/tka/sync/send` | `TKASyncSendRequest{Version, NodeKey, Head, MissingAUMs[], Interactive}`. Ordinary nodes use `Interactive=false` | `TKASyncSendResponse{Head}` | 1 MiB (default) |

Origins: `tailscale.com/tailcfg/tka.go:104-194`, `tailscale.com/ipn/ipnlocal/tailnet-lock.go:54-59`, `:1445`, `tailscale.com/util/httpbody/httpbody.go:34`. `Version` is `CurrentCapabilityVersion` (`tailscale.com/ipn/ipnlocal/tailnet-lock.go:1379`, `:1431`, `:1478`). `NodeKey` uses `nodekey:` text. The structs have no JSON tags, so the keys are the field names as written. Even when there are no AUMs to send, `TKASyncSendRequest.MissingAUMs` is a zero-length non-nil slice and encodes as `[]` rather than null (`tailscale.com/ipn/ipnlocal/tailnet-lock.go:1481`, Go run in §8.1). The TKA RPC paths have no 429 or Retry-After handling. Only the registration and map paths do (`tailscale.com/control/controlclient/direct.go:600-630`, `auto.go:653-660`).

### 3.11 Go Local Storage (tailchonk)

| Item | Details | Origin |
| --- | --- | --- |
| Location | `<varRoot>/tka-profiles/<profile ID>/`. tsnet uses `varRoot = Server.Dir`. Empty varRoot uses in-memory storage (`ChonkMem`) and emits a health warning | `tailscale.com/ipn/ipnlocal/tailnet-lock.go:528-534`, `:559-572`, `tailscale.com/tsnet/tsnet.go:984` |
| AUM files | `<base>/<first 2 characters of base32(hash)>/<base32(hash)>`. Contents are the CTAP2 CBOR of `fsHashInfo{2: AUM, 3: CreatedUnix int64 omitempty, 4: PurgedUnix int64 omitempty}`. Key 1 (`Children`) is legacy and is no longer written | `tailscale.com/tka/tailchonk.go:334-366`, `:710-742` |
| Read checks | An AUM hash differing from the filename causes an error. `PurgedUnix>0` is treated as absent | `tailscale.com/tka/tailchonk.go:379-394`, `:475-477` |
| Last active ancestor | Raw 32-byte hash in `<base>/last_active_ancestor` | `tailscale.com/tka/tailchonk.go:618-656` |
| Writes | `atomicfile.WriteFile`, files 0644, directories 0755 | `tailscale.com/tka/tailchonk.go:315`, `:625`, `:729`, `:742` |
| Deletion | Compaction only marks `PurgedUnix` and leaves the files in place. Disabling lock deletes the entire directory with `RemoveAll` | `tailscale.com/tka/tailchonk.go:327-329`, `:516-523`, `:677-705` |
| When opened | If the profile directory exists, call `tka.Open` at startup. If it is absent, treat lock as disabled | `tailscale.com/ipn/ipnlocal/tailnet-lock.go:83-125` |

Go's `Persist` (node state JSON) contains `NetworkLockKey` (the NL private key) and `DisallowedTKAStateIDs` (`tailscale.com/types/persist/persist.go:28-39`).

## 4. Procedures and State Machines

### 4.1 Conditions for Accepting an AUM (`aumVerify`)

All of the following must hold for the parent `state` (`tailscale.com/tka/tka.go:421-468`).

1. Pass `StaticValidate` (§3.4).
2. For a non-genesis AUM, a parent must exist and `state.LastAUMHash` must be non-nil and match the parent hash.
3. There must be **at least one** signature.
4. The KeyID of **every** signature must identify a trusted key in `state`. `ed25519consensus.Verify` over `SigHash` must pass with that key's `Public` from state, without deriving it from KeyID (`tailscale.com/tka/verify.go:17-36`). A single signature from an unknown key causes rejection.
5. Reject RemoveKey when it would delete the only key in state.

**There is no `Votes` threshold.** A signature from one trusted key suffices. `Votes` only weights fork resolution (`tailscale.com/tka/aum.go:316-361`, `tailscale.com/tka/tka.go:142-167`). The `MakeRetroactiveRevocation` comment calls for signatures outweighing the sum of compromised key votes. That rule is for signing devices to win fork resolution and is unenforced by `aumVerify` (`tailscale.com/tka/tka.go:804-805`).

### 4.2 Applying State (`applyVerifiedAUM`)

Apply the verified AUM to the parent state (`tailscale.com/tka/state.go:157-254`). In every case, if `state.LastAUMHash` is non-nil, its bytes must match `PrevAUMHash`. The resulting `LastAUMHash` is this AUM's hash (`cloneForUpdate`, `tailscale.com/tka/state.go:107-112`).

| Kind | Application |
| --- | --- |
| NoOp | Leave state as is |
| Checkpoint | `State.StateID1/2` must match the parent's. Replace the entire state with the checkpoint's |
| AddKey | Reject if KeyID already exists. Append the key. **This path does not enforce the 512-key limit** (only `UpdateBuilder.AddKey` and checkpoint validation do, `tailscale.com/tka/builder.go:73-75`) |
| UpdateKey | Reject if the key is missing. Change `Votes` and `Meta` and require `Key.StaticValidate` to pass again |
| RemoveKey | Reject if the key is missing. Delete it, preserving order |
| Other | Leave state as is (future kinds). 0 `AUMInvalid` also takes this path and is accepted (Go run in §8.1: a signed kind 0 AUM advances the head). It is rejected only at genesis (below) |

Genesis (an AUM without a parent) allows only NoOp, AddKey, and Checkpoint (`tailscale.com/tka/tka.go:276-292`).

### 4.3 Chains, Fork Resolution, and the Head

- **Fork resolution** (`pickNextAUM`). When a parent has multiple children, choose by ① greatest signature weight (using parent state, counting each key once, and giving unknown keys zero weight), ② RemoveKey if tied, and ③ the **smaller** AUM hash by byte comparison if still tied (`tailscale.com/tka/tka.go:122-168`, `tailscale.com/tka/aum.go:324-361`).
- **Fast-forwarding** (`fastForward`). From the starting state, apply one child at a time using the rules above until there are no children. The iteration limit is `maxIter` (`tailscale.com/tka/tka.go:193-246`).
- **State at a particular AUM** (`computeStateAt`). Walk backward from that AUM until reaching a checkpoint or genesis, then apply forward along the same path (following that path without fork resolution) (`tailscale.com/tka/tka.go:248-331`).
- **Opening** (`Open`). Walk backward from all heads (AUMs without children) to find the oldest ancestors. Use the sole ancestor if there is one. If there are several, use the ancestor whose chain included the previous run's `LastActiveAncestor`. If there is none, return "multiple distinct chains". The head is the end reached by fast-forwarding from that ancestor's state (`tailscale.com/tka/tka.go:68-120`, `:333-419`, `:476-498`). The iteration limit is 2000 (`maxScanIterations`).
- **Checkpoint**. An AUM containing the entire state at that point. It serves as a starting point for state computation, allowing earlier AUMs to be absent (`tailscale.com/tka/tka.go:271-275`). Signing devices append a checkpoint if there is none within 50 AUMs of the head (`checkpointEvery = 50`, `tailscale.com/tka/builder.go:122-160`).
- **Bootstrap** (`Bootstrap`). Storage must be empty. The AUM must be a Checkpoint with a `State`. Use **the checkpoint's own state** as the trusted state for `aumVerify(genesis=true)`. Initial trust is therefore TOFU (trust on first use) for the checkpoint received from the control server. On success, store it, set `LastActiveAncestor` to its hash, and call `Open` (`tailscale.com/tka/tka.go:527-565`).
- **Ingesting AUMs** (`Inform`). Process the list in **received order** without sorting. The caller (server) must supply oldest first (comment in `tailscale.com/tka/tka.go:582-583`). An empty list is an error. Skip already stored AUMs. AUMs without parents (genesis form) return "missing parent". Get each parent state from earlier processing or use `computeStateAt` on storage (an unknown parent is an error). Each AUM must pass `aumVerify(genesis=false)` and state application. **If any fail, store nothing, including earlier entries**. If all extend the head, use the final state. Otherwise run `computeActiveChain` again (`tailscale.com/tka/tka.go:584-676`, Go run in §8.1: empty list, missing parent, missing signature, and inclusion of an unknown key's signature all cause errors).

### 4.4 `NodeKeySignature` Verification (`NodeKeyAuthorizedWithDetails`)

Inputs are the node's public node key and the NKS bytes (`tailscale.com/tka/tka.go:685-711`).

1. Decode using §3.1. Reject on failure.
2. Reject an outermost credential ("credential signatures cannot authorize nodes on their own").
3. Find the authorizing KeyID. Direct and credential use their own `KeyID` (reject if empty). Rotation follows `Nested` inward (reject if `Nested` is absent) (`tailscale.com/tka/sig.go:183-200`).
4. The KeyID must identify a trusted key in the **current state**.
5. Call `verifySignature(nodeKey, trusted key)` (`tailscale.com/tka/sig.go:247-312`).
   - For a non-credential signature, `Pubkey` must match the bytes of `"np" ‖ nodeKey`.
   - Rotation requires `Nested`. The rotation key is `Nested.WrappingPubkey`. If empty and `Nested` is a rotation, look further inward (`tailscale.com/tka/sig.go:153-170`). Reject a missing key or a length other than 32 bytes. Verify the outer `Signature` with standard `ed25519.Verify`. If the inner signature is not a credential, its `Pubkey` must have valid `np` form (the value is not compared with anything), and the inner signature is verified recursively with that key.
   - Direct and credential reject a present `Nested`. The trusted key must be a 32-byte Key25519. Verify with `ed25519consensus.Verify`.
6. On success for a rotation, return `RotationDetails{PrevNodeKeys: keys from inner signatures with nonempty Pubkey (newest first, including the innermost direct key), InitialSig: innermost non-rotation signature}`. A credential's `Pubkey` is unchecked during verification. If it has a value, this step decodes it as `np`, and decoding failure makes the entire verification fail (`tailscale.com/tka/sig.go:314-348`, `tailscale.com/tka/tka.go:707-710`). When the outer signature is direct, `RotationDetails` is nil.

CBOR nesting limits the depth to 16 levels. A Go test shows that 15 rotation layers over a direct signature (16 levels total) verify (`tailscale.com/tka/sig_test.go:129-196`). When rewrapping its own signature, if the current signature's `Pubkey` plus the inner keys total more than 15, the node re-signs and wraps only the 14 most recent keys with the NL key over the innermost non-rotation signature, then adds the new rotation on top (intervening keys drop out of the chain) (`maybeTrimRotationSignatureChain`, `tailscale.com/tka/sig.go:394-437`).

### 4.5 Disablement Secret Verification

`DisablementKDF(secret) = Argon2i(password=secret, salt="tailscale network-lock disablement salt", t=4, m=16·1024 KiB, p=4, output 32 bytes)` (`tailscale.com/tka/state.go:114-130`). `argon2.Key` in `x/crypto` uses **Argon2i** (distinct from Argon2id), version `0x13`, with empty secret key K and associated data X (`x/crypto/argon2/argon2.go:48-53`, `:75-76`). The salt is 39 ASCII bytes. Return true if the output matches any of the state's `DisablementValues` using a **constant-time comparison** (`tailscale.com/tka/state.go:132-141`). Go run in §8.1: `DisablementKDF(0xa5 × 32)` = `c3fea8a0d70ede2555990ca60d70a8a03cbe627d2c9f3cb0e2ba7093d0884e2f` (the secret is a Go test value, `tailscale.com/tka/state.go:325`).

### 4.6 NL Keys and Registration

1. **NL key.** At login, if `Persist.NetworkLockKey` is zero, generate a new Ed25519 key and put it in node state. Keep it thereafter (`tailscale.com/control/controlclient/direct.go:721-725`). Always include its public key in `RegisterRequest.NLKey` (`:763`). The signing device uses it as the rotation key (`WrappingPubkey`) when signing this node (a locked-out node displays `tailscale lock sign <nodekey> <tlpub>`, `tailscale.com/cmd/tailscale/cli/tailnet-lock.go:245-257`). The node uses it in step 4 to re-sign when changing its node key. Losing it prevents self-re-signing after the next node key change.
2. **Signed auth key** (`--TL`). Extract the auth key, credential NKS, and 64-byte private key with `DecodeWrappedAuthkey` (§3.8). Send only the part before `--TL` to the server in `Auth.AuthKey` (`tailscale.com/control/controlclient/direct.go:643`, `:779-783`). `SignByCredential` builds `NKS{SigKind: rotation, Pubkey: "np"‖new node key, Nested: credential}`, signs its `SigHash` with the wrapped private key, and includes it in `RegisterRequest.NodeKeySignature` (`tailscale.com/tka/sig.go:439-460`, `tailscale.com/control/controlclient/direct.go:739-747`, `:768`). A kind other than credential ends registration with an error.
3. **Node registered without a signature.** Registration proceeds regardless of lock (the Go client source sends a registration request even without a signature). When a signing device submits the signature through `/machine/tka/sign`, the control server distributes it as `Node.KeySignature` in a later map (testcontrol behavior: `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1247-1262`). Until then the local node is locked out. Go only emits a health warning (`LockedOut`) if its own `SelfNode.KeySignature` fails verification with current state (`tailscale.com/ipn/ipnlocal/tailnet-lock.go:245-250`, `tailscale.com/health/healthmsg/healthmsg.go:13`). Other Go peers remove the node from their netmaps (§4.9), preventing communication (`tailscale.com/tstest/integration/integration_test.go:2557-2569`).
4. **Server request to re-sign.** If `RegisterResponse.NodeKeySignature` is present, Go generates a new node key (`Regen`) and registers again. If the old node key and old signature are present, it includes `ResignNKS(NL private key, new node key, old signature)`. Here the old signature is **the bytes of the just-received `RegisterResponse.NodeKeySignature`**, irrespective of any locally stored value (`doLoginOrRegen` passes it as `OldNodeKeySignature`, `tailscale.com/control/controlclient/direct.go:534-545`, `:704-738`, `:857-858`). If the condition is false during the second registration and a `--TL` auth key exists, call `SignByCredential` (`:739-747`). `ResignNKS` reuses the old signature when its `Pubkey` matches the new key. Otherwise it signs a rotation NKS with the NL key, using the old signature (trimmed if necessary) as `Nested` (`tailscale.com/tka/sig.go:350-392`). For verification to pass, the old signature chain's rotation key must be this node's NL public key (§4.4 step 5). If re-signing fails, log the error and register without a signature (`direct.go:736-738`).

   `ResignNKS` skips verification of the signature it creates. When the rotation key is different from the NL key, it therefore **produces a signature that fails verification without returning an error** (Go run in §8.1). (a) For a node registered with a `--TL` auth key, the signature (`rotation(credential)`) uses the credential's one-time `WrappingPubkey` as its rotation key (`tailscale.com/ipn/ipnlocal/tailnet-lock.go:1234-1258`), so wrapping with the NL key produces `invalid signature`. (b) A direct signature without `WrappingPubkey` produces `missing rotation key`. Even with Go, these nodes drop out of other nodes' netmaps after changing their node keys until they are signed again.

### 4.7 State Machine on Receipt of a Netmap (`tkaSyncIfNeeded`)

On every netmap (full netmap path), do the following (`tailscale.com/ipn/ipnlocal/local.go:2021-2063`).

- `capTailnetLock = netmap.AllCaps contains "https://tailscale.com/cap/tailnet-lock"` (`local.go:2030`, `tailscale.com/types/netmap/netmap.go:211-213`, `tailscale.com/control/controlclient/map.go:1051`).
- `TKAEnabled = lastTKAInfo != nil && !lastTKAInfo.Disabled`. If `TKAInfo.Head` is nonempty and base32 decoding fails, set `TKAEnabled = false` (`tailscale.com/control/controlclient/map.go:516-518`, `:1039-1047`). Responses containing `TKAInfo` take the full netmap path rather than the delta path (`tailscale.com/types/netmap/nodemut.go:200-209`).

Then call `tkaSyncIfNeeded(nm)` (`tailscale.com/ipn/ipnlocal/tailnet-lock.go:340-437`).

1. If there is no local lock (`tka == nil`) and `capTailnetLock` is false, **do nothing**.
2. If there is no node key, return an error.
3. If `isEnabled(local) != wantEnabled(TKAEnabled)`, call `/machine/tka/bootstrap` (use the local head as `Head`, or an empty string if absent).
   - Enabling (absent locally, enabled on the server). Decode `GenesisAUM`. Reject if `Persist.DisallowedTKAStateIDs` contains `"<StateID1>:<StateID2>"`. Create storage (directory or memory) and call `Bootstrap` (§4.3). Set `didJustEnable = true` (`tailnet-lock.go:536-584`).
   - Disabling (present locally, disabled on the server). See §4.10.
4. If a local lock exists and either the local head ≠ `nm.TKAHead` or `didJustEnable` is true, synchronize (§4.8), then compact (§4.11).
5. Errors are only logged at `[v1]` (`local.go:2034-2036`). There is no retry or backoff (`tailnet-lock.go:47` "RPC retry/backoff was broken and has been removed"). Try again on the next netmap.

Next, reflect the local head in `MapRequest.TKAHead`. If the value changes, resend a map update (`local.go:2038-2051`, `tailscale.com/control/controlclient/auto.go:706-714`, `direct.go:476-489`). Finally, filter peers (§4.9) (`local.go:2053-2055`). `tkaFilterDeltaMutsLocked` filters the delta path (`PeersChanged` and similar) (`local.go:2494-2502`).

**If `TKAEnabled` is true but bootstrap fails, there is no local lock and peer filtering is skipped** (`tailnet-lock.go:189-197`). Go accepts all peers in this case.

The same fail-open occurs **when storage cannot be opened**, and in this case it persists. On every netmap, `initTKALocked` calls `tka.Open` if the profile has a tailchonk directory. If it fails (file corruption, hash and filename mismatch, chain computation failure, etc.), Go only logs the error and leaves `b.tka` nil (`tailnet-lock.go:83-125`, `local.go:2021-2025`). The subsequent `tkaSyncIfNeeded` attempts bootstrap. Because AUMs remain in the same directory, `Bootstrap` fails with "tailchonk is not empty" (`tailnet-lock.go:559-576`, `tailscale.com/tka/tka.go:537-543`). The failure repeats on each netmap until storage is repaired, and peers remain unfiltered. If synchronization (§4.8) or compaction fails, the local lock remains and filtering continues with the previous state (`tailnet-lock.go:423-434`, `local.go:2053-2055`).

### 4.8 Synchronization (`tkaSyncLocked`)

1. Build a local `SyncOffer`: `Head` = local head. `Ancestors` = **checkpoint AUM hashes** encountered walking backward from the head (at most 1000, newest first, excluding the oldest ancestor), followed by the oldest ancestor's hash (`oldestAncestor`) (`tailscale.com/tka/sync.go:65-111`).
2. Send it to `/machine/tka/sync/offer`.
3. Decode the server's `Head` and `Ancestors`. If the server head equals the local head, **stop here** without sending a send request (`tailnet-lock.go:456-464`).
4. **First** compute `MissingAUMs` (local AUMs unknown to the server) for the server offer (`tailnet-lock.go:466-472`). Intersection computation (`computeSyncIntersection`, `tailscale.com/tka/sync.go:129-212`): equal heads are up to date. If the server head is present locally, walk backward from the local head (at most 1000) to find it as the head intersection. Otherwise, check the server's `Ancestors` in order and choose the first whose state can fast-forward to the local head as the tail intersection (iteration limit 2000). If none qualifies, return `ErrNoIntersection`. The list to send consists of AUMs encountered by fast-forwarding from just after the intersection AUM (`tailscale.com/tka/sync.go:214-261`). For a tail intersection, skip to the next ancestor if the server ancestor is absent locally (`os.ErrNotExist`). Other errors (failure to read a parent, exceeding the 2000 iteration limit, etc.) return immediately (`sync.go:188-202`). **Failure here ends the entire synchronization**, skipping `Inform` in step 5 and the send in step 6 (`tailnet-lock.go:469-472`).
5. If the response includes `MissingAUMs`, decode them all (any failure is an error) and call `Inform` (§4.3).
6. Send the local head and the list from step 4 to `/machine/tka/sync/send` (`Interactive=false`).
7. If the response `Head` differs from the local head, only log "TKA desync" (`tailnet-lock.go:502-508`).

### 4.9 Peer Filtering (`tkaFilterNetmapLocked`)

Without a local lock, skip filtering (`tailnet-lock.go:189-197`). With a local lock, do the following for each peer (`tailnet-lock.go:199-243`).

1. Skip filtering a peer with `UnsignedPeerAPIOnly` (outside lock's scope).
2. Exclude it if `KeySignature` is empty.
3. Exclude it if `NodeKeyAuthorizedWithDetails(peer node key, KeySignature)` (§4.4) fails.
4. Collect `RotationDetails` for passing rotation signatures. **Keys superseded by rotation** (`rotationTracker`, `tailnet-lock.go:253-338`). Every key in any rotation signature's `PrevNodeKeys` is superseded. Group rotations whose `InitialSig` is direct by `InitialSig.WrappingPubkey`, excluding keys already marked superseded. With several entries in a group, keep only the one with the most `PrevNodeKeys` and mark the rest superseded. If two or more tie for most, mark the entire group superseded. Do not group chains starting from credentials (several nodes can join with the same reusable auth key).
5. Remove the peers excluded in steps 2 and 3 and any peers with superseded keys from the netmap, preserving order.
6. Emit the `LockedOut` health warning if the local node's signature fails verification.

Deltas (`tkaFilterDeltaMutsLocked`, `tailnet-lock.go:137-183`). Apply steps 1~3 to `NodeMutationUpsert` (a new or fully replaced peer) and turn a failure into a `Remove` for the same ID. Deltas skip the superseded-key check (step 4). `PeerChange` patches to `Key` or `KeySignature` take the full netmap path instead of the delta path (`tailscale.com/types/netmap/nodemut.go:111-138`, `:165-170`).

Go skips filtering if `TS_UNSAFE_SKIP_NKS_VERIFICATION` is enabled (`tailscale.com/envknob/envknob.go:427`, `local.go:2053`). Swiftail omits this option.

Related safeguards. Regardless of lock, if an `UnsignedPeerAPIOnly` peer's AllowedIPs overlap the sources of even one packet filter rule with a destination, Go sets the entire packet filter to nil and emits a health warning (`local.go:3459-3464`, `:3562-3599`). An `UnsignedPeerAPIOnly` peer can have only the `PeerCapabilityIngress` peer capability (Funnel ingress). The rest are removed (`tailscale.com/ipn/ipnlocal/node_backend.go:415-440`). magicsock does not use these peers for relay allocation or as relay targets (`tailscale.com/wgengine/magicsock/magicsock.go:3009-3013`).

### 4.10 When Lock Is Disabled

1. If the server sends `TKAInfo.Disabled=true` or has never sent `TKAInfo` in this map session, `wantEnabled=false` (§4.7). A response that omits `TKAInfo` mid-session means no change. Go updates `lastTKAInfo` only for non-nil values (`tailscale.com/control/controlclient/map.go:516-518`, `tailscale.com/tailcfg/tailcfg.go:2179-2187`). `lastTKAInfo` is a map session field and starts nil because each new map request creates a new session (`map.go:99`, `map.go:112`, `direct.go:1228`).
2. If there is a local lock, call `/machine/tka/bootstrap` with the local head to receive `DisablementSecret`.
3. If `ValidDisablement(secret)` (§4.5) is true, call `RemoveAll` on storage and set the local lock to nil. If false, only log the failure and **keep** the lock (synchronization continues even if the server supplied the wrong secret) (`tailnet-lock.go:399-418`, `:513-526`, `tailscale.com/ipn/ipnlocal/tailnet-lock_test.go:213-299`).

Deleting on the strength of `TKAInfo.Disabled` alone would let a malicious or faulty control server disable lock protection. The disablement secret's KDF value is signed into the trusted checkpoint, so verifying the secret preserves that protection.

### 4.11 Compaction and Storage

Go calls `Compact(head, {MinChain: 24, MinAge: 14 days})` on every synchronization (`tailnet-lock.go:427-433`, `tailscale.com/tka/limits.go:30-35`). It keeps at least 24 AUMs from the head (possibly more to reach a checkpoint), AUMs stored within 14 days, their descendants, and AUMs needed for ancestor intersection. It marks the rest with `PurgedUnix` and updates `LastActiveAncestor` to the new ancestor (`tailscale.com/tka/tailchonk.go:745-1048`). As `oldestAncestor` changes, so does the final ancestor in the next `SyncOffer`.

### 4.12 Capabilities and Conditions

| Situation | Go behavior |
| --- | --- |
| No local lock, no `tailnet-lock` cap | Skip all TKA processing. Skip bootstrap and filtering even if `TKAEnabled` is true |
| No local lock, cap present, `TKAEnabled` | Bootstrap → synchronize → filter |
| Local lock present | Synchronize, filter, and handle disablement regardless of cap |
| Built with `ts_omit_tailnetlock` | All TKA functions do nothing (`tailscale.com/ipn/ipnlocal/tailnetlock_disabled.go:19-31`) |

Origin: `tailnet-lock.go:189-197`, `:363-365`.

## 5. Constants and Timers

| Name | Value | Origin |
| --- | --- | --- |
| `maxDisablementValues` | 32 | `tailscale.com/tka/limits.go:13` |
| `maxKeys` | 512 | `tailscale.com/tka/limits.go:14` |
| `maxMetaBytes` | 512 | `tailscale.com/tka/limits.go:18` |
| `maxSyncIter` | 2000 | `tailscale.com/tka/limits.go:21` |
| `maxSyncHeadIntersectionIter` | 1000 | `tailscale.com/tka/limits.go:24` |
| `maxScanIterations` | 2000 | `tailscale.com/tka/limits.go:27` |
| `CompactionDefaults` | `MinChain` 24, `MinAge` 14 days | `tailscale.com/tka/limits.go:30-35` |
| `Key.Votes` | 1~4096 | `tailscale.com/tka/key.go:108-113` |
| CBOR nesting, array, map | 16 levels, 4096 elements, 1024 pairs | `tailscale.com/tka/tka.go:29-31` |
| Previous keys when re-signing a rotation | At most 15 | `tailscale.com/tka/sig.go:414-420` |
| `disablementLength` | 32 | `tailscale.com/tka/state.go:114` |
| Argon2i | t=4, m=16384 KiB, p=4, 32 bytes, v=0x13 | `tailscale.com/tka/state.go:124-130`, `x/crypto/argon2/argon2.go:48` |
| `checkpointEvery` (signing device) | 50 | `tailscale.com/tka/builder.go:123` |
| TKA RPC deadline | 1 minute | `tailscale.com/ipn/ipnlocal/tailnet-lock.go:1395`, `:1442`, `:1493` |
| sync/offer response limit | 512 MiB | `tailscale.com/ipn/ipnlocal/tailnet-lock.go:59`, `:1445` |
| Other Noise response limit | 1 MiB | `tailscale.com/util/httpbody/httpbody.go:34`, `tailscale.com/control/ts2021/client.go:330-336` |

## 6. Minimum Swiftail Requirements and Optional Parts

### 6.1 Cryptographic Primitives

| Primitive | Use | CryptoKit | `SwiftailCrypto` | New work |
| --- | --- | --- | --- | --- |
| BLAKE2s-256 (unkeyed) | AUM hash and SigHash, NKS SigHash | Absent | Present (`Sources/SwiftailCrypto/BLAKE2s.swift:3-4`, `:32`) | None |
| Ed25519 signing | `ResignNKS` (NL key), `SignByCredential` (wrapped key) | `Curve25519.Signing.PrivateKey.signature(for:)` (`CryptoKit.swiftinterface:35-37`). The private key is a 32-byte seed (`rawRepresentation`) | Absent | NL key storage. The first 32 bytes of the 64-byte Go-format wrapped key are the seed (`ed25519.PrivateKey` format) |
| Ed25519 verification (standard rules) | Outer rotation NKS signature | `Curve25519.Signing.PublicKey.isValidSignature` (`CryptoKit.swiftinterface:31-33`). Its rules **differ** from Go's standard rules: it rejects noncanonical A (run in §8.1) | Absent | See below |
| Ed25519 verification (ZIP-215) | AUM signatures and direct and credential NKSs | Absent (CryptoKit's verification rules were unverified in public documentation) | Absent | See below |
| Argon2i + BLAKE2b | Disablement secret | Absent | Absent (including BLAKE2b) | BLAKE2b (RFC 7693) and Argon2i (RFC 9106). Argon2 uses BLAKE2b-512 (H0, `x/crypto/argon2/argon2.go:130-159`) and variable-length H' (`x/crypto/argon2/blake2b.go:16-53`) |
| Constant-time comparison | Disablement value comparison | — | Present (`Sources/SwiftailCrypto/CryptoError.swift:12`) | None |

**Differences in Ed25519 verification rules.** `ed25519consensus.Verify` (ZIP-215) requires a 64-byte signature and `sig[63]&224 == 0`, **accepts noncanonical encodings** of public key A and R, requires canonical S (`< L`), and checks the equation **with the cofactor** `[8](R' − R) = 0` (`ed25519consensus/ed25519.go:19-66`). Go's standard `ed25519.Verify` requires the same length and bit checks and canonical S, accepts noncanonical A (`go/src/crypto/internal/fips140/edwards25519/edwards25519.go:137-145`), and requires the encoding of R computed **without the cofactor** to match `sig[:32]` byte for byte (`go/src/crypto/internal/fips140/ed25519/ed25519.go:290-327`). It therefore rejects noncanonical R and R with a small-order component. Honestly generated signatures (Go `ed25519.Sign`) pass both rules. Differences arise only in deliberately constructed signatures from a private key holder, such as those with small-order components or noncanonical A or R.

Measured differences (§8.1). Of 196 ZIP-215 vectors (`ed25519consensus/zip215_test.go`), `ed25519consensus` accepted 196, standard Go accepted 12, and CryptoKit accepted 8. All 8 CryptoKit accepted were among Go's 12. The other 4 (112, 130, 168, and 182) have a noncanonical public key encoding (`y ≥ p`, or x=0 with the sign bit set). Only `ed25519consensus` accepted a signature made by adding an order-2 point to R. Standard Go and CryptoKit rejected it. In tka, the same signature passed `Inform` for an AUM and `NodeKeyAuthorized` for a direct NKS, and was rejected as an outer rotation signature. Options:

- (a) Use CryptoKit for all verification. 0 lines of implementation. CryptoKit differs from Go both on the ZIP-215 path and on the standard path (outer rotation). CryptoKit was always stricter in the measured cases. The effects differ by path. For NKS, this only excludes additional peers that Go accepts. **For AUMs, protection can weaken**. If a trusted key holder adds an AUM signed with a signature that only ZIP-215 accepts, Go nodes accept it and Swiftail rejects the entire group containing it (`Inform` stores nothing if any entry fails, §4.3). Every later AUM extending it is rejected because its parent is unknown, leaving Swiftail state stuck before it. If an administrator then appends a RemoveKey for that key to the same chain, Go nodes stop trusting it and Swiftail continues to trust it and accept peers signed by it. Whether CryptoKit accepts any signatures that ZIP-215 rejects is unverified (presumably none, since the equation without the cofactor implies the equation with it. None appeared in the 197 measured inputs).
- (b) Implement both ZIP-215 and the standard rules with pure Swift edwards25519 (field arithmetic, point decoding, double scalar multiplication). Estimated 800~1200 lines plus test vectors (ZIP-215 vectors in `ed25519consensus/zip215_test.go`).

Option (b) achieves identical verdicts but is large. Because of the AUM path above, option (a) can weaken protection. At least AUM signatures need ZIP-215 verification to maintain the same state as Go. Adding the standard rule (the equation without the cofactor and the R byte comparison) to the same edwards25519 code is a small addition. Ask the owner to decide before implementation.

**Argon2i test vectors.** RFC 9106 §5.2 (Argon2i, t=3, m=32 KiB, p=4, K and X present), its transcription in `x/crypto/argon2/argon2_test.go:70`, and the Go execution value in these notes (§4.5, no K or X, exact TKA parameters). The TKA parameters fill 16 MiB of memory once, so verification runs only on a disablement event. Size estimate: about 120 lines for BLAKE2b and about 200~250 for Argon2i (parallelism p=4 is an input to H0, divides memory into 4 lanes, and participates in indexing to select reference blocks (`x/crypto/argon2/argon2.go:161-166`, `:183-186`, `:262-282`). Processing the 4 lanes sequentially within each slice yields the same result as parallel computation, so threads are unnecessary).

### 6.2 CBOR Subset

- **Encoding**. Only major types 0 (uint, shortest of 1~8 bytes), 2 (bstr), 3 (tstr, `Meta` only), 4 (array), 5 (map, one-byte integer keys 1~23, `Meta` string keys ordered lexicographically by encoded bytes), and null (`0xf6`) from major type 7. Only definite lengths. Follow each field's nil, empty, and omitempty rules exactly (§3.1~3.6) to match hashes.
- **Decoding**. Accept only the types above for known fields. To match Go, struct map keys must be integers (−2^63~2^63−1) or valid UTF-8 text, and other keys must be rejected (§3.1). To match Go, skip any well-formed **value** of an unknown field, including major type 1 negative integers, major type 7 16-, 32-, and 64-bit floats and simple values, and text whose contents are unchecked. Restrictions on tags, indefinite lengths, and nesting also apply inside skipped values (Go run in §8.1: a bignum tag and indefinite-length bstr in unknown values were rejected). Reject tags, indefinite lengths, duplicate keys (at struct and `Meta` levels), and trailing bytes. Limit nesting to 16, arrays to 4096, and maps to 1024. Accept non-shortest integers and unsorted keys. Hash and verify signatures using **the canonical encoding of the decoded value** in place of received bytes (§3.1).
- Value ranges. `MessageKind`, `SigKind`, and `KeyKind` are 0~255 (reject larger). Read `Votes` as 0~2^64−1 (`uint`, 64-bit platform) and validate 1~4096. `StateID` uses the full uint64 range.
- Size estimate. A general CBOR value decoder (including skipping), mapping for the five structures, and a canonical encoder total 300~450 lines.

### 6.3 Classification

| Feature | Classification | Rationale |
| --- | --- | --- |
| NL key generation and persistence, `RegisterRequest.NLKey` | Required | Signing devices use it as the rotation key, and it is used in re-signing after node key replacement (§4.6). Swiftail currently sends a zero key (`Sources/SwiftailControl/Tailcfg/RegisterRequest.swift:38`, no NL key in `Sources/SwiftailControl/Client/NodeIdentity.swift:13-15`) |
| Signed auth key → `SignByCredential` | Required | Preauthorized registration path (M8 ①) |
| `RegisterResponse.NodeKeySignature` → `ResignNKS` (including chain trimming) | Required | Currently ends with `tailnetLockEnabled` (`Sources/SwiftailControl/Client/ControlClient+Registration.swift:76-79`). Go also sends a signature that fails verification without an error for credential chains and direct signatures without a rotation key (§4.6 step 4). |
| `MapRequest.TKAHead` | Required | Lets the server know the node's head (§4.7) |
| Bootstrap (TOFU checkpoint verification), synchronization offer + `Inform` | Required | Receive and verify signing authority state |
| Fork resolution, ancestor selection among multiple chains | Required | Recovery AUMs create forks (`tailscale.com/tka/tka.go:798-860`). Omitting this can select a different head from Go |
| sync/send (head notification) | Required | Go always sends it when heads differ (§4.8 step 6) |
| sync/send `MissingAUMs` computation (intersection algorithm) | Optional | Ordinary nodes create no AUMs, so AUMs unknown to the server arise only when the server loses data. An empty list cannot help that recovery. Implement for parity with Go (about 150 lines). Omitting it also changes when synchronization stops. Go ends synchronization without calling `Inform` on the server's AUMs if intersection computation fails (`ErrNoIntersection`, iteration limit exceeded, etc., §4.8 step 4). With the computation omitted, execution reaches `Inform`. `Inform` also rejects unknown parents, so most outcomes are the same. Whether all cases match is unverified |
| NKS verification + peer filtering + tracking superseded keys + delta filtering | Required (cannot omit) | Omitting these removes lock protection (`docs/plan.md` §8 risk 8) |
| Disablement secret verification (Argon2i) | Required (cannot omit) | Without it, either all new peers are excluded after disablement, or trusting `Disabled` alone hands protection over to the server |
| Local node lockout notification | Required (public API) | The user needs the node key and tlpub to run `tailscale lock sign <nodekey> <tlpub>` (`tailscale.com/cmd/tailscale/cli/tailnet-lock.go:245-257`) |
| Local storage | Required (any format) | See below |
| Compaction | Optional (a limit is required) | No effect on verdicts. Some way to bound storage is needed |
| `DisallowedTKAStateIDs` | Omit | List used by `TailnetLockForceLocalDisable` (`tailnet-lock.go:811-835`). It is always empty if Swiftail lacks forced local disablement |
| `UnsignedPeerAPIOnly` handling | Keep existing difference | Go keeps these peers in the netmap and restricts their privileges. The Swiftail engine omits them entirely (`Sources/SwiftailEngine/EnginePeer.swift:94-103`) |
| All signing-device features (§2) | Omit | Outside M8 scope (`docs/plan.md` §3) |
| Accepting all peers on bootstrap or storage open failure (end of §4.7) | **Review a departure from Go** | Go skips filtering if `TKAEnabled` is true and there is no local lock. If storage cannot be opened, this persists until storage is repaired (§4.7). It is safer for Swiftail to omit peers before bootstrap or when storage cannot be opened (fail closed). An owner decision is needed because matching verdicts is the default |
| Ignoring TKA on nodes without the cap (§4.12) | Match Go | Which nodes get the cap from the production server is unknown (§8.2). The `nodecap.TailnetLock` comment says the node can initialize tailnet lock (`tailscale.com/tailcfg/nodecap/nodecap.go:74-75`). If the server accordingly gives it only to some nodes, nodes without it would skip filtering even in a locked tailnet. Go integration tests give it to all nodes (`integration_test.go:2521-2523`). Matching Go yields the same verdicts |

**Storage format considerations.** Go state migration is omitted, so the tailchonk file format is unnecessary. Verdicts depend on (1) all accepted AUMs (look up by hash and find children from a parent), (2) `LastActiveAncestor` (selection with multiple chains, §4.3), and (3) storage timestamps if compacting. Store AUMs as canonical CBOR bytes so hashes match on reread. Keep separate storage per profile (node identity), delete it entirely when lock is disabled, and keep the NL private key with the node key in the node identity store (`NodeIdentityStore`). Recomputing state from storage at startup (`Open`), as Go does, avoids persisting state itself.

## 7. Interop Test Checks

### 7.1 Existing Go Reference Values

| Reference value | Location |
| --- | --- |
| Five AUM serialization byte sequences (AddKey, RemoveKey, UpdateKey, Checkpoint, Signature) and deserialization | `tailscale.com/tka/aum_test.go:17-159` |
| Genesis checkpoint from an actual test tailnet (558 bytes, 10 disablement values, 2 keys, 1 signature) | `tailscale.com/tka/aum_test.go:171-233`. The Go run for these notes obtained the hash, SigHash, and passing `Bootstrap` result (§8.1) |
| AUM chain hashes (AddKey `53898e43…`, RemoveKey `15d65756…`, UpdateKey `d55458a9…`, chain `f09bda3b…`→`218165fe…`, checkpoint `57343671…`) | `tailscale.com/tka/state_test.go:96-164` |
| Weights | `tailscale.com/tka/aum_test.go:235-304` |
| Signed auth key string (credential NKS + 64-byte key) | `tailscale.com/tka/sig_test.go:464-501` |
| NKS direct, nested, deep nesting, credential, rotation details, and re-signing | `tailscale.com/tka/sig_test.go:17-627` |
| Synchronization, intersection, and fork scenarios | `tailscale.com/tka/sync_test.go`, `tailscale.com/tka/scenario_test.go`, `tailscale.com/tka/tka_test.go` (chain description language in `chaintest_test.go`) |
| Client flows (enablement, disablement, synchronization, compaction, filtering, superseded keys) | `tailscale.com/ipn/ipnlocal/tailnet-lock_test.go:132`, `:213`, `:301`, `:452`, `:585`, `:1088` |
| Argon2i KAT | RFC 9106 5.2, `x/crypto/argon2/argon2_test.go:70` |
| ZIP-215 signature vectors | `ed25519consensus/zip215_test.go` |

### 7.2 Reference Value Tool for `Tools/interop`

`tailscale.com/tka` exposes public APIs for external use (`Create`, `Bootstrap`, `Open`, `NewUpdater`, `Inform`, `SyncOffer`, `MissingAUMs`, `NodeKeyAuthorizedWithDetails`, `DisablementKDF`, `ResignNKS`, `SignByCredential`, `DecodeWrappedAuthkey`, `ChonkMem`) (`tailscale.com/tka/tka.go:476-711`, `tailscale.com/tka/sync.go:30-261`, `tailscale.com/tka/sig.go:350-498`, `tailscale.com/tka/state.go:124`, `tailscale.com/tka/tailchonk.go:112`). As in the runs for these notes (§8.1), `Tools/interop` (currently using `tailscale.com v1.104.6`) can use them directly. Tool outputs:

1. Canonical bytes, hash, and SigHash for AUM chains (genesis checkpoint, AddKey/RemoveKey/UpdateKey/NoOp, checkpoint, fork, recovery AUM), plus expected state and head per step.
2. Synchronization scenarios. `SyncOffer` (head and ancestors) from both stores, `MissingAUMs`, and the head after `Inform`.
3. NKS. Direct, n rotation layers (1~15), credential→rotation, bytes after chain trimming, and the `NodeKeyAuthorizedWithDetails` verdict and `PrevNodeKeys` for each (node key, NKS, state). Verify Swift-generated signatures using Go verdicts in place of byte comparison (CryptoKit's `signature(for:)` gave different signatures each time for the same key and message, run in §8.1).
4. Peer set scenarios. `rotationTracker` verdicts using the input form of `TestRotationTracker` (`tailnet-lock_test.go:1088`).
5. Decoder rejection table. Inputs from §8.1, their verdicts, and re-encoded hashes.
6. `DisablementKDF` values.

### 7.3 What testcontrol Can Simulate

testcontrol handles `/machine/tka/init/begin`, `init/finish`, `bootstrap`, `sync/offer`, and `sign`. If TKA state exists and there is one head, it includes `TKAInfo{Head}` in the map response (`tailscale.com/tstest/integration/testcontrol/testcontrol.go:418`, `:1138-1262`, `:1770-1783`). The handlers are in `tailscale.com/tstest/tkatest/tkatest.go:39-220`. `DefaultNodeCapabilities` can grant the `tailnet-lock` cap (`testcontrol.go:1065-1075`, `tailscale.com/tstest/integration/integration_test.go:2521-2523`). The Go integration test uses this to show that two signed nodes can communicate, and an unsigned node cannot communicate with anyone until signed (`integration_test.go:2517-2584`).

Gaps and injection points:

| Missing | Result | Alternative |
| --- | --- | --- |
| `sync/send` handler | If a node with a different head sends a send request, `serveUnhandled` calls `go panic` (`testcontrol.go:413`, `:430-434`). Only a genesis-only lock can be tested (no additional AUMs such as `lock add`) | Port testcontrol to `Tools/interop` and connect `tkatest.HandleTKASyncSend`, or verify chain synchronization in Swift unit tests using §7.2 reference values |
| Bootstrap returning `DisablementSecret`, `/machine/tka/disable` | Disablement flow unavailable (bootstrap response includes only `GenesisAUM`, `testcontrol.go:1223-1225`) | Same as above. Alternatively, inject `TKAInfo{Disabled: true}` with `AddRawMapResponse`, though this cannot change the bootstrap response |
| Storage of registration request `NodeKeySignature` | Registration with a signed auth key leaves the node unsigned (testcontrol has no `NodeKeySignature` handling) | Verify Swift's NKS with a Go verdict (§7.2 step 3), then use `UpdateNode` to set `KeySignature` and test map propagation (`testcontrol.go:1315-1320`) |
| `TKAInfo.Disabled`, a different head | — | Inject with `AddRawMapResponse` (`testcontrol.go:337-339`) |

A tsnet peer can call `TailnetLockInit`, `TailnetLockSign`, `TailnetLockWrapPreauthKey`, and `TailnetLockStatus` through `LocalClient` (`tailscale.com/client/local/tailnetlock.go:22-151`, LocalAPI handler `tailscale.com/ipn/localapi/tailnetlock.go:21-33`). This allows adding the following gate to `Tools/interop/cmd/tailnet` (testcontrol + tsnet, `Tools/interop/cmd/tailnet/main.go:132`, `:193`).

1. Grant the `tailnet-lock` cap in testcontrol. tsnet signing nodes A and B call `TailnetLockInit` (A and B's NL keys, N disablement values).
2. Swift node S registers and bootstraps. Check that its head matches A's (`TailnetLockStatus().Head`).
3. While S is unsigned, A and B remain in S's netmap (A and B are signed), and S is absent from A and B's netmaps. S reports its own lockout.
4. A calls `TailnetLockSign(S's node key, S's NL public key)`. S appears in A and B's netmaps and can communicate.
5. Add unsigned tsnet node C. S and A both exclude C.
6. Compare peer sets. Compare A's `TailnetLockStatus().VisiblePeers` and `FilteredPeers` (`tailnet-lock.go:641-668`) with the peer set S retained at the same time, by node ID. Handle `UnsignedPeerAPIOnly` peers separately in the comparison since Swiftail already omits them.
7. (If testcontrol is extended) Check that S catches up through sync when A adds a key and thereby adds an AUM, that S clears its state after disablement with the disablement secret, and that S retains state for an incorrect secret.
8. Node key replacement. S changes its node key and re-signs with `ResignNKS`. Check that A accepts it and excludes the old key as superseded.

## 8. Execution Records and Unverified Items

### 8.1 Execution Records

All runs used a temporary Go module under `$(eyebuild dir tka-note)`. Environment: `GOMODCACHE=$(eyebuild dir ref-src)/gomod GOPROXY=off GOSUMDB=off GOFLAGS=-modcacherw GOTOOLCHAIN=local`, Go 1.27.3. v1.104.7 required `go >= 1.27.4` and failed to build, so the runs used `tailscale.com v1.104.6` (cited files are identical between versions, §1). Command: `go mod tidy && go run .`.

| Check | Result |
| --- | --- |
| Genesis checkpoint (`aum_test.go:181`) | 558 bytes, re-encoding matches the original. First 8 bytes `a4010502f605a501` (map with 4 pairs: 1, 2=null, 5=State map with 5 pairs, 23). `Hash` = `JJRRHYGNBVUWY77ZY436U35DVPHXPY4C5HPQZA2PHUPBNM5252UA` (hex `4a6313e0cd0d696c7ff9c737ea6fa3abcf77e382e9df0c834f3d1e16b3baeea8`) = BLAKE2s-256 of the original. `SigHash` = `f34f12d83807a70bd9d7c5bef557ebfa453846cdfff1ce5c60d18d7a9facf325`. `tka.Bootstrap(ChonkMem, genesis)` returns no error, head = hash above |
| `DisablementKDF(0xa5 × 32)` | `c3fea8a0d70ede2555990ca60d70a8a03cbe627d2c9f3cb0e2ba7093d0884e2f` |
| Signed auth key (`sig_test.go:479`) | Auth key portion matches the text before `--TL`, private key 64 bytes, credential NKS KeyID 32, WrappingPubkey 32, and signature 64 bytes, CBOR map with 4 pairs (keys 1,3,4,6) |
| `NodePublic.MarshalBinary` | 34 bytes, prefix `"np"` |
| Encoding | `UpdateKey{KeyID:[1], Votes:&0, Meta:{}}` → `a4010402f60441010600`. `Meta{"bb","a","c"}` → key order `a`, `c`, `bb`. `NoOp{PrevAUMHash: []byte{}}` → `a201030240`. Empty `Keys` and `DisablementValues` give `80`, `StateID1=2^40` gives `041b0000010000000000`, and `StateID2=0` is omitted |
| Decoding: accepted | Unknown integer keys (including values that are integers, floats, negative numbers, true, undefined, invalid UTF-8 text, or nested maps), unknown negative keys, unknown text keys, duplicate keys inside unknown values, non-shortest integers (values and keys), unsorted keys, omitted `PrevAUMHash`, kind 9, `MessageKind` null (→0), empty `Meta` map, and 2- or 33-byte `LastAUMHash` in checkpoint state (rejected by static validation). All noncanonical inputs give `Hash ≠ BLAKE2s(original)` |
| Decoding: rejected | Duplicate keys in structs and `Meta`, indefinite-length maps, tags, trailing bytes, empty input, outermost array, kind 256, negative or floating-point kind, text `PrevAUMHash`, integer or invalid UTF-8 `Meta` value, truncated byte string, 17 nesting levels, array with 4097 elements, map with 1025 pairs |
| `AUMHash.UnmarshalText` | Rejects lowercase, padding, and 51 characters. Accepts final `A`/`B`/`P` as the same hash |

Output was stored in `$(eyebuild dir tka-note)/run1.txt`~`run4.txt` and later deleted with `eyebuild rm tka-note`.

**Verification session runs** (2026-11-15). Three temporary Go modules and one Swift executable under `$(eyebuild dir tka-verify)`. Environment as above (Go 1.27.3, `tailscale.com v1.104.6`, with `GOCACHE` also in the same directory). Swift used `xcrun swiftc -O -module-cache-path <same directory>/mc`. Afterward, the directory was deleted with `eyebuild rm tka-verify`. All values in the table above were reproduced (genesis hash, SigHash and Bootstrap, KDF value, signed auth key, four encodings, `AUMHash` text, nesting 16/17, array 4096/4097, map 1024/1025, empty input, outermost array, and duplicate keys inside unknown values).

| Check | Result |
| --- | --- |
| Map key types (AUM) | Rejected: bstr keys, float keys (`f93c00`), `true` and `null` keys, array keys, invalid UTF-8 text keys (`61ff`), and integer key 2^64−1. Accepted: negative key (`20`), integer key 2^63−1, and text keys `"MessageKind"`, `"messagekind"`, and `"1"` (all unknown fields, kind remains 3). Duplicate unknown integer, text, and negative keys are rejected |
| `Meta` map | Rejects bstr and integer keys and bstr values. Rejects duplicate keys. Accepts the empty map and omits it on re-encoding |
| Other decoding | Rejects a text `State.LastAUMHash` (does not use `TextUnmarshaler`). Accepts a 2-byte bstr by zero-padding to 32 bytes (static validation rejects it). Rejects a bignum tag (`c24101`) and indefinite-length bstr inside unknown values. Accepts simple value 99, undefined, and float64 values. Rejects a non-map `Signatures` element |
| `AUMHash.UnmarshalText` | Final `A`, `B`, and `P` give the same hash, and `Q` gives a different hash. Rejects 51 and 53 characters, padded 56 characters, and lowercase |
| Fork resolution (two children of the same parent via `Inform`) | Smaller hash wins with equal weights, two signatures (two keys) beat one, two signatures from the same key have weight 1, and RemoveKey wins with equal weights |
| Unusual AUMs (`Inform`) | Kinds 0 (`AUMInvalid`) and 9 are accepted and the head advances. No parent → `missing parent`, 33-byte `PrevAUMHash` (first 32 bytes are the head) → `parent AUMHash mismatch` at application, no signatures → `unsigned AUM`, includes unknown key signature → `key not found`, empty list → error |
| Signed auth key | Last 32 bytes of the 64-byte key = public key derived from seed = credential `WrappingPubkey`. `SignByCredential` with 63 bytes → panic `bad private key length: 63` |
| `ResignNKS` | Rewrapping a credential chain (result of `SignByCredential`) with the NL key gives `invalid signature`. Direct without `WrappingPubkey` → `missing rotation key`. Direct with the NL public key as `WrappingPubkey` → passes |
| Ed25519 signature with an order-2 point added to R | Standard Go rejects, `ed25519consensus` accepts, and CryptoKit rejects. In tka, an AUM with this signature passes `Inform`, a direct NKS passes, and an outer rotation signature gives `invalid signature` |
| 196 ZIP-215 vectors (message `"Zcash"`) | `ed25519consensus` 196, standard Go 12 (0, 16, 19, 28, 43, 73, 75, 76, 112, 130, 168, 182), CryptoKit 8 (0, 16, 19, 28, 43, 73, 75, 76). CryptoKit accepted every public key through `PublicKey(rawRepresentation:)` |
| CryptoKit signing | Signing twice with the same key and message yields different bytes (nondeterministic) |
| JSON | Empty `Head` in `TKABootstrapRequest` encodes as `"Head":""`. Empty `MissingAUMs` in `TKASyncSendRequest` is `[]`. Empty `TKAInfo` is `{}` |

### 8.2 Unverified Items

- **Production control server behavior** (source unavailable). Which nodes receive the `tailnet-lock` node cap (whether it is all nodes in a locked tailnet), whether bootstrap always gives genesis or can give a later checkpoint (the `Bootstrap` comment allows both, `tailscale.com/tka/tka.go:532`), when it sends `RegisterResponse.NodeKeySignature`, how it stores and distributes signatures for nodes registered with signed auth keys, whether it accepts unsigned node registration and what response it gives, whether it accepts registration with a zero `NLKey` (also unverified in `control-map.md` §4.6), whether admin console signing uses the registration request's `NLKey` as the rotation key, when it grants `UnsignedPeerAPIOnly`, how it checks sync/send requests with `Interactive=false`, whether it uses 429, 503, or Retry-After for TKA RPCs, and the actual response size distribution.
- **CryptoKit Ed25519**. The complete verification rules were unverified in documentation. The `swiftinterface` has declarations only (`CryptoKit.swiftinterface:31-37`). Measurements cover only §8.1 (196 ZIP-215 vectors and one order-2 signature, all at least as strict as standard Go) and nondeterministic signing. Whether CryptoKit accepts any input that standard Go or ZIP-215 rejects is unverified.
- **Difference in cited versions**. Source read was v1.104.7 and execution used v1.104.6 (Go 1.27.3 could not build v1.104.7). `diff -rq` confirmed the cited files match, and there are no run results from v1.104.7 itself.
- **Go tests were unrun**. The `tka`, `ipnlocal`, and integration tests (`TestTailnetLock`) were read only. Hashes in §7.1 are the expected values written in the test files.
- The comment in `ipnlocal/tailnet-lock_test.go:164-165` says offer/send are called even when up to date, but the code (`tailnet-lock.go:461-464`) skips send when heads match. These notes follow the code.
- `Compact` details (`markAncestorIntersectionAUMs`, `markDescendantAUMs`) received only a cursory read (`tailscale.com/tka/tailchonk.go:871-1005`). Thus the claim in §6.3 that compaction has no effect on verdicts remained unverified in the verification session (compaction changes `LastActiveAncestor` and may affect ancestor selection when several chains exist, §4.3).
- `computeActiveAncestor` overwrites `chainsThroughActive` in a map for each ancestor and does not mark a chain whose head is itself `LastActiveAncestor` (length 1) (`tailscale.com/tka/tka.go:95-118`, `:342-369`). Whether chains with the same ancestor can be marked differently and whether Go's result would then be deterministic (map iteration and `sort.Slice`) are unverified. It has no effect in the normal flow (one ancestor).
- The full set of inputs accepted by the CBOR decoder was not enumerated. The tables in §3.1 and §8.1 cover tested inputs.
- Whether Go actually skips peer filtering after bootstrap failure in production (§4.7), meaning cases in which the server indicates `TKAEnabled` but bootstrap fails, is unknown.
