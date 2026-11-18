# WhoIs, ts.net Certificates, and Go State Files

## 1. Introduction

| Item | Description |
| --- | --- |
| Reference Version | `tailscale.com` v1.104.6 (CapabilityVersion 148). Its ACME client is `tempfork/acme` (a fork of `golang.org/x/crypto/acme`) |
| Specifications | RFC 8555 (ACME), RFC 7515 (JWS), RFC 7517 (JWK), RFC 7518 (JWA), RFC 7638 (JWK thumbprint), RFC 2985 (PKCS#9) and 2986 (PKCS#10), RFC 5280 (X.509 extensions), RFC 3279, 5480, 5758, and 5915 (ASN.1 for EC keys and signatures), RFC 7807 (problem documents), RFC 8737 (TLS-ALPN-01, exclusion boundary), and RFC 9773 (ARI). Sections were checked against the original RFC Editor texts (`https://www.rfc-editor.org/rfc/rfcNNNN.txt`) |
| Milestone Using This Note | M7(`docs/contracts/SwiftailHost.md`) |
| Authoring Model | Claude Fable 5.2 (`claude-fable-5-2`), 2026-11-15 |
| Verification | **Verified** by GPT-6.1 Sol, 2026-11-15, against Tailscale v1.104.6, 20 original RFC Editor texts, official Let's Encrypt documentation and the PSL, the Go 1.27.3 standard library, and the SDK. See §9 for verdicts by claim and §8 for remaining unverified items |

This note expands on §3.2 (Go state files), §4.8 (`WhoIs`), and §4.9 (ts.net certificates) of [dns-state-node.md](dns-state-node.md) to the depth required for M7 implementation. It refers to facts already covered there by section number, without repeating them, and calls it the "DNS note" below. Source references use `path:line` relative to the module root. Swiftail implementation references describe the verification snapshot at `70cf65e`. Code from the first adopter (RemoteDebug) uses paths at `2814b2c` in that repository. Example values are fake (`rd-mac-1a2b3c4d.tail0001.ts.net`, `100.64.0.1`).

In verification origins, `tailscale.com/` is the v1.104.6 module root. This version implements certificates in `feature/acme/cert.go` and `certstore.go`, with `feature/acme/acme.go:198-212` wiring the backend hooks. The implementation is outside `ipn/ipnlocal/cert.go`. Go standard library paths are **relative to `src/` in Go 1.27.3**. All original RFC texts came from the RFC Editor at `https://www.rfc-editor.org/rfc/rfcNNNN.txt`: 1034, 1123, 2985, 2986, 3279, 4648, 5280, 5480, 5758, 5915, 7231, 7468, 7515, 7517, 7518, 7638, 7807, 8555, 8737, and 9773.

Apple API declarations were checked against `Security.framework/Headers/` and `CryptoKit.framework/Modules/CryptoKit.swiftmodule/arm64e-apple-macos.swiftinterface` (hereafter `CryptoKit.swiftinterface`) in `MacOSX.sdk`. This session reran only the small format checks in §4.6. The authoring session's CSR and TLS network experiments were moved to §8 because their materials were unavailable. Implementation proposals and future tests are distinct from verified execution results.

## 2. Scope

In scope

- `WhoIs`: Rules for finding a node and user by address, how user profiles enter the netmap, tagged and shared nodes, and capabilities.
- ts.net certificates: Go's issuance, storage, and renewal flow, the control server's `set-dns`, the ACME (RFC 8555) subset needed for DNS-01 issuance, the JWS (ES256) and CSR byte formats, and how to generate them on Apple platforms.
- Go state directory: Files written by tsnet, keys holding node identity, and their counterparts in Swiftail identity storage.

Out of scope

- TLS-ALPN-01, wildcard certificates, BYO Funnel domains, Kubernetes storage, account key rollover, and certificate revocation (unused, see §6).
- TLS itself and the HTTP server. The first adopter uses the Network framework to terminate TLS and writes the HTTP server in Swift (item 1 of “First adopter review results (2026-11-15)” in [`docs/contracts/SwiftailNetstack.md`](../contracts/SwiftailNetstack.md#first-adopter-review-results-2026-11-15)).
- Tailnet lock, multiple profiles, and Windows.

## 3. Wire and Storage Formats

### 3.1 `WhoIs` Response (Go)

`WhoIsResponse` has three fields: `Node` (the entire `tailcfg.Node`), `UserProfile`, and `CapMap` (`tailscale.com/client/tailscale/apitype/apitype.go:35-42`). The `UserProfile` fields are `ID`, `LoginName`, `DisplayName`, `ProfilePicURL`, and `Groups` (`tailscale.com/tailcfg/tailcfg.go:307-319`). The first adopter reads only `Node.StableID` (reject if empty), the first label of `Node.Name` (fall back to `Node.ComputedName` if empty), and `UserProfile.LoginName` (RemoteDebug `core/internal/node/node.go:526-551`).

Identity fields in `tailcfg.Node` (`tailcfg/tailcfg.go:370-386`, `:436`, `:501`):

| Field | Meaning |
| --- | --- |
| `StableID` | Immutable string ID for the node. The first adopter's allowlist is tied to it |
| `Name` | FQDN with a trailing dot (`rd-phone-1a2b3c4d.tail0001.ts.net.`) |
| `User` | ID of the user who created the node. For a tagged node, it does not reflect "the ACL identity under which that node operates" (source comment `:380-383`) |
| `Sharer` | If nonzero, the user who shared this node |
| `Tags` | ACL tags. At least one makes it a tagged node (`IsTagged`, `:635-637`) |
| `ComputedName` | The client computes this field (§4.1, 5). The control server does not compute and send it. It has a JSON tag, so it can appear in LocalAPI's `Node` JSON (`tailcfg/tailcfg.go:496-503`) |

### 3.2 `set-dns` Request (Control Server)

This is `POST /machine/set-dns` over the Noise channel (ts2021 HTTP/2) (`tailcfg/tailcfg.go:2589-2594`, `tailscale.com/control/controlclient/direct.go:1765`).

The request body is the JSON object `SetDNSRequest` (`tailcfg/tailcfg.go:2595-2618`):

| Key | Value |
| --- | --- |
| `Version` | `CurrentCapabilityVersion` (148). `LocalBackend.SetDNS` sets 1, but the value is overwritten just before sending over Noise (`tailscale.com/ipn/ipnlocal/local.go:7813-7818`, `direct.go:1759-1760`) |
| `NodeKey` | Current node public key (`nodekey:` + hex) |
| `Name` | `_acme-challenge.<domain>` |
| `Type` | `"TXT"` |
| `Value` | Value to put in the TXT record (3.5) |

Request headers include `Content-Type: application/json`. When the node key is nonzero, the load balancing header (`tailcfg.LBHeader`) carries the node key text (`tailscale.com/control/ts2021/client.go:299-318`). Other Noise requests (registration and map) follow the same rule.

Treat any status other than 200 as failure. Apply `TrimSpace` to the response body and include up to 200 Unicode code points in the error (Go `fmt` counts runes for `%.200s`, see `fmt/doc.go:116-130`). For 200, decode one JSON value into `SetDNSResponse` (a Go struct with no fields). An empty body fails with EOF. The check also accepts inputs beyond `{}`, including `null` in Go `encoding/json` (`direct.go:1770-1778`, `tailcfg/tailcfg.go:2620-2621`, Go `encoding/json/decode.go:94-98`). The default Noise response body limit is 1MiB (`control/ts2021/client.go:320-336`, `util/httpbody/httpbody.go:30-34`). Swiftail contract D3 separately limits responses to 4KiB and JSON objects and keeps error bodies private.

`LocalBackend.SetDNS` fails immediately with `not connected` when there is no control client or `no nodekey` when the node key is zero (`ipn/ipnlocal/local.go:7820-7839`). It uses the **same Noise client** as the map stream, with no guarantee of sharing one physical HTTP/2 connection (`control/controlclient/direct.go:1761-1765`, `control/ts2021/client.go:254-290`).

### 3.3 ACME Request Envelope (JWS)

Every POST body is one Flattened JWS JSON Serialization object (RFC 8555 6.2, RFC 7515 7.2.2). The `Content-Type` is `application/jose+json` (RFC 8555 6.2).

```json
{"protected":"<base64url(protected header JSON)>","payload":"<base64url(body JSON)>","signature":"<base64url(signature)>"}
```

| Part | Rule | Origin |
| --- | --- | --- |
| Protected header | `alg`, `nonce`, `url`, and exactly one of `jwk` and `kid`. No unprotected header is used | RFC 8555 6.2 |
| `alg` | `"ES256"` for a P-256 account key. The server must implement ES256 | RFC 8555 6.2, `tailscale.com/tempfork/acme/jws.go:231-247` |
| `jwk` | Public key corresponding to the key that signs the JWS. Used only for newAccount requests (account key) and revocation requests signed with the certificate key | RFC 8555 6.2 |
| `kid` | All other requests. Account URL received in the `Location` header of the newAccount response | RFC 8555 6.2, 7.3 |
| `url` | Exact URL to which this request is sent | RFC 8555 6.4.1 |
| `nonce` | One value from the server's `Replay-Nonce` header. Discard it after one use | RFC 8555 6.5, 6.5.2 |
| `payload` | base64url of the JSON body. **POST-as-GET** (reading a resource) uses the empty string `""` and does not encode `"{}"` | RFC 8555 6.3 |
| Bytes to sign | ASCII(`protected` + `"."` + `payload`) | RFC 7515 5.1, `jws.go:106-107` |
| `signature` | For ES256, concatenate **R (32 bytes) ‖ S (32 bytes)** from the ECDSA signature over SHA-256 into 64 bytes. This uses raw bytes rather than DER | RFC 7518 3.4, `jws.go:200-227` |

base64url uses the URL-safe alphabet, with `-` and `_` in place of `+` and `/` and no `=` padding (RFC 7515 §2, RFC 4648 §5).

Go creates a P-256 account key (`tailscale.com/feature/acme/certstore.go:377`). Signing also supports RSA, P-384, and P-521 keys (`jws.go:231-247`), but Tailscale creates only P-256 keys.

### 3.4 JWK and Thumbprint

The minimal JWK for the P-256 public key generated here has four members: `crv` (`"P-256"`), `kty` (`"EC"`), `x`, and `y`. Encode the `x` and `y` coordinates as 32-byte big-endian values and then as base64url (RFC 7517 4.1, RFC 7518 6.2.1, `jws.go:160-196`).

The ACME thumbprint applies SHA-256 to the UTF-8 bytes of JSON written with **only required members, in Unicode code point order by name, without whitespace**. RFC 7638 itself takes hash H as a parameter. RFC 8555 8.1 fixes it to SHA-256 (RFC 7638 3, 3.2, 3.3, 3.4). For P-256, the input is exactly the following byte string (`jws.go:189-193` produces the same string):

```
{"crv":"P-256","kty":"EC","x":"<x>","y":"<y>"}
```

The thumbprint text is the base64url encoding of those 32 bytes (`jws.go:250-257`). Go puts the same sorted string directly in the `jwk` header (`jws.go:81-87`).

### 3.5 DNS-01 Value

```
keyAuthorization = token ‖ "." ‖ base64url(JWK thumbprint)
TXT value        = base64url(SHA-256(keyAuthorization))
Record name      = "_acme-challenge." ‖ domain
```

See RFC 8555 8.1 (key authorization) and 8.4 (DNS challenge). In Go, see `tempfork/acme/acme.go:591-598` (`DNS01ChallengeRecord`), `:783-789` (`keyAuth`), and `feature/acme/cert.go:626` (name). The `token` must use only the unpadded base64url alphabet, and the server must generate it with at least 128 bits of entropy. The client cannot prove entropy from the string alone (RFC 8555 8.4). Keep P-256 JWK coordinates at 32 bytes each without dropping leading 0s (RFC 7518 6.2.1.2 and 6.2.1.3). The TXT value is the base64url encoding of 32 SHA-256 bytes, so it is 43 ASCII bytes. Do not add DNS display quotes to the JSON `Value` (formula above, `feature/acme/cert.go:620-639`).

### 3.6 CSR(PKCS#10)

The finalize request is `{"csr":"<base64url(CSR DER)>"}`. Encode the DER as base64url without a PEM header (RFC 8555 7.4, `tempfork/acme/rfc8555.go:371-375`).

The Go CSR has a subject with a single `CN=<domain>`, a single SAN extension (`dNSName` = domain), a newly generated P-256 key, and an ECDSA-SHA256 signature (`feature/acme/certstore.go:306-317`, `feature/acme/cert.go:578-589`).

Structure (RFC 2986 §4):

```
CertificationRequest ::= SEQUENCE {
  certificationRequestInfo  SEQUENCE {
    version        INTEGER 0,
    subject        Name,                    -- RDNSequence { SET { SEQUENCE { OID 2.5.4.3, PrintableString domain } } }
    subjectPKInfo  SubjectPublicKeyInfo,    -- RFC 5480 §2. id-ecPublicKey + secp256r1 + uncompressed point
    attributes     [0] IMPLICIT SET OF Attribute
                   -- Attribute { OID 1.2.840.113549.1.9.14(extensionRequest),
                   --   SET { Extensions { Extension { OID 2.5.29.17(subjectAltName),
                   --     OCTET STRING { GeneralNames { [2] IA5String domain } } } } } }
  },
  signatureAlgorithm  SEQUENCE { OID 1.2.840.10045.4.3.2 },   -- ecdsa-with-SHA256, no parameters (RFC 5758 3.2)
  signature           BIT STRING            -- 0 unused bits + DER ECDSA-Sig-Value(SEQUENCE { r INTEGER, s INTEGER })
}
```

The subject's `PrintableString` (tag 0x13) above **matches Go's encoding** for the ASCII names in this note. `UTF8String` (0x0C) is also a DirectoryString choice for the name, but changes the DER bytes relative to Go (RFC 5280 4.1.2.4, Go `crypto/x509/pkix/pkix.go:258-259`, `encoding/asn1/marshal.go:638-652`). The verification program also confirmed CN tag 19, ECDSA-SHA256, one SAN, and `CheckSignature=<nil>`.

RFC 5280 4.2.1.6 defines the SAN format. `dNSName` is `[2] IMPLICIT IA5String` (tag 0x82), and the `extnValue` wrapping the SAN is an OCTET STRING. Omit `critical` in the request above because it defaults to false (RFC 5280 4.1 and 4.2, Go `crypto/x509/x509.go:1614-1630`). `id-ecPublicKey` is 1.2.840.10045.2.1 and `secp256r1` is 1.2.840.10045.3.1.7 (RFC 5480 2.1.1, 2.1.1.1). The `extensionRequest` OID and its single `Extensions` value were verified in PKCS#9 (RFC 2985 5.4.2 and Appendix A). ECDSA `(r,s)` consists of two positive INTEGERs in a DER SEQUENCE (RFC 3279 2.2.3). Include a leading 0x00 when needed, and distinguish this representation from JWS's fixed 64 bytes. The signature input is the DER bytes of `certificationRequestInfo` (RFC 2986 4.2).

### 3.7 Certificate Chain and Private Key Storage Formats

The default file store holds `acme-account.key.pem` (0600), `<domain>.key` (0600), and `<domain>.crt` (0644) under `<varRoot>/certs/` (mode 0700 on creation) (`feature/acme/certstore.go:64-81`, `:116-168`, `:284-288`). `MkdirAll` gives no guarantee of fixing existing directory permissions. Additional details follow.

- The certificate response is `application/pem-certificate-chain`, a sequence of `CERTIFICATE` PEM blocks starting with the leaf (RFC 8555 7.4.2, 9.1). If anything other than `CERTIFICATE` follows `-----BEGIN`, **reject the entire file** (RFC 8555 11.4). This protects against malicious servers inserting private key blocks. Go's bundle path fails if a **successfully PEM-decoded** block has a type other than `CERTIFICATE`, and rejects empty chains and chains with 6 or more certificates. The body limit is exactly `5 × 1MiB + floor(5 × 1MiB / 33)` = 5,401,755 bytes. The RFC path does not separately check that each DER is at most 1MiB (`tempfork/acme/rfc8555.go:412-446`, `acme.go:62-67`). The loop exits when `pem.Decode` returns nil, so malformed BEGIN lines or trailing garbage are not uniformly rejected. Swiftail must inspect the entire input under RFC 8555 9.1 and 11.4.
- Go rewrites the received chain as PEM block by block and saves it to `<domain>.crt` (`feature/acme/cert.go:600-609`).
- The private key is SEC1 `ECPrivateKey` (RFC 5915 §3) in `EC PRIVATE KEY` PEM (`feature/acme/certstore.go:323-330`). For account keys, Go tries PKCS#1, PKCS#8, and SEC1 in order (`certstore.go:340-359`), so it also reads PKCS#8 (`PRIVATE KEY`) PEM. Go uses standard library `tls.X509KeyPair` to read the certificate key (`certstore.go:415`).
- Write the key file before the certificate file. For each, use a temporary file in the same directory → set permissions → `Sync` → close → rename. **The two writes have no shared transaction.** If stopped between them, key-pair validation detects the mismatch on the next read (`certstore.go:156-169`, `atomicfile/atomicfile.go:21-51`, `certstore.go:415-417`).
- The certificate response can offer alternate chains with the same leaf via `Link: rel="alternate"` (RFC 8555 7.4.2). `tempfork/acme` has `ListCertAlternates` (`rfc8555.go:475-492`), but Tailscale's issuance path saves only the default chain selected by `CreateOrderCert(..., true)` (`feature/acme/cert.go:594-607`). The root certificate **may be omitted** from the response, with no requirement to omit it (RFC 8555 9.1).

## 4. Procedures and State Machines

### 4.1 `WhoIs`

See DNS note §4.8 for the `LocalBackend.WhoIs` steps. Details needed for M7 implementation follow.

1. **Address table**: Whenever the netmap changes, add only **single-address prefixes (/32, /128)** from the local node's and all peers' `Addresses` to the address → node ID table (`tailscale.com/ipn/ipnlocal/node_backend.go:712-732`). Exclude `AllowedIPs` (subnet routes and similar entries). Keep peers with expired keys and offline peers. If they are in the netmap, they are in the table.
2. **Lookup**: Convert IPv4-mapped IPv6 addresses (`::ffff:100.64.0.1`) to IPv4 before lookup (`local.go:1756-1758`). If the address is absent from the table, `LocalBackend.WhoIs` falls back to `ProxyMapper` when netstack is built in and the port is nonzero (`local.go:1773-1797`). It maps back addresses of local connections established by tailscaled on a peer's behalf, so it does not apply to listeners receiving tailnet addresses directly.
3. **User**: Look up the profile by the node's `User`, rather than `Sharer`. A missing profile is a **failure** (`local.go:1806-1811`).
4. **How profiles enter the netmap**: Map responses contain only changed `UserProfiles`. The client accumulates all received profiles without deleting them. When building the netmap, it selects profiles only for the local node's `User` and each peer's `Sharer` and `User` (`tailscale.com/control/controlclient/map.go:384-387`, `:1054-1058`, `:674-685`). It also retrieves profiles for peers reintroduced by a delta from its accumulated profiles (`map.go:302-346`). Swiftail's `MapSession` works the same way (`Sources/SwiftailControl/Netmap/MapSession.swift:36-38`, `:198-206`).
5. **`ComputedName`**: This is `dnsname.TrimSuffix(Name, suffix)`. Remove the local tailnet suffix only if it matches at a label boundary, and strip the trailing dot. **A name shared from another tailnet keeps its FQDN (without a trailing dot) because its suffix differs.** If the result is empty, strip `.local`, `.localdomain`, and `.lan` from `Hostinfo.Hostname` and run `SanitizeLabel`. If still empty, use `Node.Key.String()` (`nodekey:` + hex) (`tailcfg/tailcfg.go:660-689`, `util/dnsname/dnsname.go:203-239`, `:162-200`, `types/key/node.go:322-328`). To get the suffix, strip dots from both ends of the local name and take what follows the first dot, or use the name as-is if it has no dot (`types/netmap/netmap.go:256-270`). Compute this for the local node, Peers, and PeersChanged in map responses (`control/controlclient/direct.go:1419-1434`).
6. **Tagged nodes**: `User` remains the ID of the user who created the node (3.1). One tool in the reference sources uses `Node.Tags` as the identity when `UserProfile.LoginName` is `"tagged-devices"` (`tailscale.com/cmd/pgproxy/pgproxy.go:218-222`). The client sources do not show what the production control server sends as the profile for a tagged node (§8).
7. **Capability**: `CapMap` comes from the packet filter's `CapGrant`. Match the remote node's first address as the source and the local address of the same family as the destination. An `UnsignedPeerAPIOnly` peer can have only the ingress capability (`node_backend.go:443-467`, `tailscale.com/ipn/localapi/localapi.go:603-620`). The first adopter does not read it.
8. **Local API failure**: A failed lookup returns 404, received by the client as `ErrPeerNotFound` (`localapi.go:593-596`, `tailscale.com/client/local/local.go:353-362`). The first adopter responds to any failure with 403 `not_paired` (RemoteDebug `core/internal/host/host.go:232-244`).

What Swiftail already has and what it still needs follows.

| Requirement | Swiftail | Notes |
| --- | --- | --- |
| Node `StableID`, `Name`, `User`, `Sharer`, `Tags`, `Addresses`, and `Hostinfo` | Available (`Sources/SwiftailControl/Tailcfg/Node.swift`) | |
| User profile (`LoginName`, `DisplayName`, `ProfilePicURL`) | Available (`Netmap.userProfiles`, `Sources/SwiftailControl/Netmap/Netmap.swift:19`) | `Groups` is not decoded (`Tailcfg/UserProfile.swift`) |
| Address → node table | Absent. Build it from the netmap | No new data to receive |
| `ComputedName` | Absent at verification time. Use the rule in §4.1, step 5 | The name resolution code already obtains the MagicDNS suffix (`Sources/Swiftail/Netmap+HostResolution.swift`) |
| `CapMap` | Rules are decoded (`capGrant` in `Tailcfg/FilterRule.swift`). No code collects them by address pair | The first adopter does not use it |

Looking up `Node` and `UserProfile` by address requires no additional fields from the control server (`local.go:1771-1811`). Reproducing `CapMap` also requires the current packet filter built from the netmap (`node_backend.go:443-467`).

The LocalAPI path is `tsnet.Server.LocalClient()` → `client/local.Client.WhoIs` → `GET /localapi/v0/whois?addr=<URL escape>` → `serveWhoIs` → backend (`tsnet/tsnet.go:449-453`, `client/local/local.go:353-361`, `ipn/localapi/localapi.go:552-599`). `addr` is an IP, IP:port, or node public key. Missing or invalid input yields 400, lack of read permission 403, and failed lookup 404 (`localapi.go:552-596`). With no protocol specified, WhoIs tries the TCP proxy mapping first, then the UDP mapping (`local.go:1773-1797`). Passing `svc_name` or `dst_ip` changes the capability destination (`localapi.go:601-620`). Swiftail's minimum scope is address lookup and basic identity only (§6).

### 4.2 Go Certificate Flow (Summary and Additional Details)

The eight issuance steps are in DNS note §4.9, 4. Additional details follow.

1. **Per-domain lock**: The issuance function acquires a per-domain mutex and then rereads the stored certificate to check whether another call renewed it in the meantime (`feature/acme/cert.go:345-363`).
2. **Account preparation**: Look up the account with an `onlyReturnExisting` request signed by the account key. On `accountDoesNotExist`, register with `termsOfServiceAgreed` (Go sends this true field only if the directory has a terms URL, `rfc8555.go:49-61`). If registration reports that it already exists, look it up again. Any account status other than `valid` is a failure (`cert.go:451-473`, `:386-392`, `tempfork/acme/rfc8555.go:126-138`, `:45-92`). Go sends no contacts (`new(xacme.Account)`, `cert.go:460`).
3. **Existing TXT record**: Before `set-dns`, look up the TXT record with the system resolver under a 500ms deadline and skip `set-dns` if the value is already present. A comment says this is best effort and that at worst the client asks the server to recreate what is already there (`cert.go:628-643`).
4. **After `set-dns`**: Respond to the challenge immediately, without waiting for DNS propagation or repeating the lookup on the client (`cert.go:639-650`). Whether the production server delays its response is unverified (§8).
5. **After the challenge response**: Repeatedly read the **order** instead of the authorization until it is `ready` or `valid`. The interval is `Retry-After` or 1 second if absent. `invalid` is a failure (`cert.go:563-576`, `rfc8555.go:283-318`).
6. **Certificate key**: After `WaitOrder` returns `ready` or `valid`, Go generates a new P-256 key and sends the CSR in a finalize request in either case (`cert.go:564-594`). Normal new issuance follows the `ready` path. Each renewal changes the key (`cert.go:578-585`).
7. **Already `valid` authorization**: Go always responds to the dns-01 challenge without checking authorization status (`cert.go:531-561`, `:615-651`). The outcome when the server reuses an already `valid` authorization was not verified by execution (§8).
8. **Cleanup after failed issuance**: The DNS-01 path has no TXT deletion, order cancellation, or stored order URL for resumption (`cert.go:487-654`). TLS-ALPN-01 deletes the temporary challenge certificate with `defer cleanup` (`cert.go:547-548`). Release the lock and clear the renewal-in-progress marker on success and failure (`cert.go:145-149`, `:346-348`). Keep the stored account key and certificate, and start the next issuance call with a new order. ACME HTTP request retries (§4.3) are separate from retrying the whole issuance. The first adopter doubles the retry delay starting at 30 seconds, up to a cap of 10 minutes (RemoteDebug `core/internal/node/node.go:825-859`).
9. **Conditions**: For ordinary ts.net names in M7 scope, require a netmap, nonempty `DNS.CertDomains`, and an **exact** match in the list (`cert.go:689-728`). Go also has capability-enabled wildcard and BYO Funnel exceptions (`cert.go:700-724`). Before reading the cache, remove one trailing dot and perform the path name check and allowlist check (`cert.go:91-121`). The path check rejects empty names, `..`, `:`, `/`, `\`, NUL, names without a dot, and asterisks other than a wildcard prefix `*.`. The part after `*.` must also contain a dot. It does not fully validate ordinary DNS label lengths and characters (`cert.go:656-677`). The first adopter also checks `MagicDNSEnabled` (RemoteDebug `core/internal/node/tls.go:27-32`).
10. **User-Agent**: Append the ACME package name to `tailscaled/<version>` (`certstore.go:399-403`, `tempfork/acme/http.go:295-304`). RFC 8555 6.1 requires the client to send a User-Agent.
11. **Out-of-scope challenge branches**: Go uses DNS-01 for wildcards and for anything other than Funnel `:443`. BYO Funnel uses TLS-ALPN-01 from the first issuance. Ordinary Funnel tries TLS-ALPN-01 first when it has a valid previous certificate. On failure, end with an error for context cancellation or BYO, otherwise fall back to a new DNS-01 order (`cert.go:253-290`, `:428-446`). TLS-ALPN-01 is a separate challenge using `acme-tls/1` and the critical `acmeIdentifier` extension from RFC 8737 §§3 and 4. Keep it separate from DNS-01 TXT records.
12. **Cache and read-only branches**: Return a valid cached certificate even if determining whether to renew fails (`cert.go:128-134`). `TS_CERT_SHARE_MODE=ro` returns only a valid cached certificate and skips issuance when the cache is absent or invalid (`cert.go:123-125`, `:158-160`). During issuance without a usable cache, enable a health warning and clear it at the end (`cert.go:367-375`, `:730-748`). This user-facing indication and sharing mode are outside the M7 minimum scope.


### 4.3 ACME Procedure (DNS-01, One Identifier)

This is the sequence Swiftail will implement. Sections refer to RFC 8555. Parentheses point to the corresponding Go implementation.

1. **Directory**: `GET <directory URL>`. Read `newNonce`, `newAccount`, `newOrder`, and `meta.termsOfService` from the response JSON (7.1.1, `tempfork/acme/acme.go:166-213`). Go treats a missing `newOrder` as pre-RFC and fails (`acme.go:199-201`). Swiftail likewise fails if any of the three URLs required for issuance are missing (implementation proposal, RFC 8555 7.1.1).
2. **Nonce**: If no valid nonce is on hand, get it from the `Replay-Nonce` header of `HEAD <newNonce>` (7.2). Use the `Replay-Nonce` from the POST response (success or error) in the next request (6.5). `Replay-Nonce` must use unpadded base64url encoding from RFC 7515 §2. Ignore invalid values (6.5.1). This is the RFC rule. Go's `nonceFromHeader` accepts any nonempty string as-is (`acme.go:722-759`).
3. **Look up the account**: `POST <newAccount>`, `jwk` header, body `{"onlyReturnExisting":true}`. On 200, the `Location` header is the account URL (`kid`). On error type `urn:ietf:params:acme:error:accountDoesNotExist`, go to 4 (7.3.1).
4. **Create the account**: `POST <newAccount>`, `jwk` header, body `{"termsOfServiceAgreed":true}`. Expect 201 (new account) or 200 (account already exists for the same key). In both cases `Location` is the account URL (7.3). The response body `status` must be `valid` (7.1.2, 7.1.6).
5. **Order**: Use a certificate key **distinct** from the account key (RFC 8555 11.1). `POST <newOrder>`, `kid` header, body `{"identifiers":[{"type":"dns","value":"<domain>"}]}`. Expect 201 with the order URL in `Location`. Read `status`, `identifiers`, `authorizations` (URL array), and `finalize` (URL) from the body (7.4, 7.1.3). **Identifiers and authorizations have no guaranteed 1:1 correspondence. Do not rely on array order to associate them.** Check all `authorizations` and verify that the requested identifier set is preserved (7.1.3 and 7.4). Branch first on the returned `status`. If already `ready`, go straight to finalize preparation (7.1.3 and 7.1.6).
6. **Read authorization**: POST-as-GET to each URL. Read `status`, `identifier`, and `challenges` (7.5, 7.1.4). If `status` is `valid`, the authorization is complete (7.1.6). If `pending`, use the `url` and `token` of one challenge of type `dns-01` (7.1.4 and 8.4). There is no need to perform all challenge types. Go selects the first dns-01, fails if none exists, and does not separately check authorization or challenge `status` (`feature/acme/cert.go:531-561`, `:615-653`). Swiftail checks `identifier.type == "dns"`, the expected name, and absence of a wildcard. It fails on `invalid`, `deactivated`, `expired`, `revoked`, or unknown status (implementation proposal, 7.1.4). If the challenge is already `processing`, check whether the TXT record was prepared, then reread the challenge status. If the challenge is `valid`, do not respond again (7.1.6 and 8.2).
7. **Publish the record**: Send the `set-dns` request from 3.2 with the value from 3.5.
8. **Respond to the challenge**: `POST <challenge url>` with body `{}` (7.5.1). Go treats both 200 and 202 as success (`acme.go:570-573`).
9. **Wait**: Repeat POST-as-GET to the order URL. On `ready`, go to 10. On `invalid`, discard the order and report failure with the error object (`error`). On `pending` or `processing`, reread after `Retry-After` (7.1.3, 7.1.6, and 7.4). With no header, 1 second is **Go's chosen value**, outside the RFC constants (`rfc8555.go:303-308`). `valid` means issuance is complete, so go to 12, but **the private key used in that order's CSR must already exist**. If `valid` arrives for a new order before the CSR has been sent, fail without generating a new key to pair with it (implementation proposal, 7.4, with key pair verification in 3.7 and §4.4, 5). The typical RFC 7.5.1 flow polls the authorization URL. Go polls the order.
10. **Finalize**: `POST <finalize>` with body `{"csr":"…"}` (3.6). Expect 200 and an updated order object. If the order was not `ready`, the response is 403 `orderNotReady` (7.4).
11. **Wait for issuance**: Branch immediately on finalize response `status`. For `valid`, proceed to the `certificate` URL. For `processing`, reread the order URL after `Retry-After`. For `invalid`, fail. For `pending`, check which authorizations are still pending. For `ready`, finalize with the **same key and CSR**. Fail on unknown status (five branches from 7.4, with retention of key and CSR and rejection of unknown status as implementation proposals). Go calls `WaitOrder` for any status other than `valid` and then fails if the result is still not `valid` (`rfc8555.go:381-398`).
12. **Download**: POST-as-GET to the `certificate` URL. The default format is `application/pem-certificate-chain`. Explicit `Accept` is a Swiftail choice (7.4.2, Go `fetchCertRFC` sets no separate Accept, `rfc8555.go:405-410`, `http.go:214-241`). Decode under the rules in 3.7.

HTTP errors **SHOULD** include an RFC 7807 problem document, and the JSON media type is `application/problem+json` (RFC 8555 6.7, RFC 7807 §3). `type` is a URI reference. Standard ACME errors are under `urn:ietf:params:acme:error:`, but server-specific URIs can also occur. The default when `type` is absent is `about:blank` (RFC 8555 6.7, RFC 7807 3.1 and 4.2). Preserve both the HTTP status and the problem document and handle non-JSON errors as well. Distinguish `status`, `title`, `detail`, `instance`, and `subproblems` and their `identifier` (RFC 7807 3.1, RFC 8555 6.7.1). Order `error` and challenge `error` are also problem documents (RFC 8555 7.1.3 and §8). This procedure handles the following types separately:

| Type | Handling | Origin |
| --- | --- | --- |
| `badNonce` | Re-sign and resend the same request with the error response's `Replay-Nonce` | 6.5 (the client must use that nonce), `tempfork/acme/http.go:184-198` |
| `accountDoesNotExist` | 3 → 4 | 7.3.1 |
| `rateLimited` | If `Retry-After` is present, wait until then before attempting again | 6.6 |
| `orderNotReady` | Reread the order and proceed according to its status | 7.4 |
| `userActionRequired` | User action, such as accepting changed terms, is required. Report failure with `instance` and `Link: rel="terms-of-service"` available for inspection | 6.7, 7.3.3 |

Go's ordinary HTTP retry logic considers **responses other than the expected success status** retryable at 399 or below, 500 or above, or 429. It immediately returns network transport errors from this loop (`http.go:128-154`, `:172-198`, `:321-323`). With `Retry-After`, use its value plus jitter (1–1000ms if cryptographic random sampling succeeds). Without it, use `min(2^(n−1) seconds + jitter, 10 seconds)`. There is no attempt limit, and context cancellation stops the default backoff (`http.go:39-90`).

When retrying `badNonce`, **use the nonce from that error response** (RFC 8555 6.5). Go adds the response nonce, then clears all nonces with `clearNonces` and refetches with HEAD on the next attempt. Swiftail does not reproduce this behavior (`http.go:187-198`, `:240`, `acme.go:692-718`). `Retry-After` is integer seconds or HTTP-date, and a date depends on the current wall clock (RFC 7231 7.1.3, `http.go:92-104`). Do not shorten a valid server wait to an arbitrary cap of 30 seconds or 24 hours and send an earlier **request**. If the wait exceeds the overall deadline, end the attempt or preserve the deferred retry state until then (implementation proposal, RFC 8555 6.6 and 7.4).

### 4.4 Renewal

1. Go defaults to ARI (RFC 9773) for renewal decisions. It gets the suggested window from the directory's `renewalInfo` URL and renews once a random time within that window has passed. If the lookup fails under its 5-second deadline, check whether **the 2/3 point of the certificate lifetime** has passed (`feature/acme/cert.go:173-198`, `:233-251`, `:306-340`). Cache the chosen time in memory per domain, but **delete it after successful renewal** so the new certificate gets a fresh calculation (`cert.go:183-204`, `:610`). If `minValidity != 0`, compare remaining lifetime to the requested duration instead of using ARI or 2/3 (`cert.go:174-180`). RFC 9773 4.2 and 4.3 also specify looking up ARI again according to the response's `Retry-After`. Go's cache should be distinguished from that procedure.
2. Go includes `replaces` if a **valid previous certificate** can be loaded from cache and parsed and `TS_DEBUG_ACME_FORCE_RENEWAL` is off. Omit it if the store's `ARIReplacesAllower` explicitly returns false. An error from that check still permits inclusion (`cert.go:353-363`, `:394-420`). If expiration or failed validation leaves `previous` nil, omit it. The RFC certID encodes the AKI keyIdentifier and the serial's **DER INTEGER content bytes** separately as unpadded base64url and joins them with a dot. Include the serial's leading sign byte 0x00 (RFC 9773 4.1 and the example in 5). The Go fork uses `SerialNumber.Bytes()` and omits that 0x00 (`tempfork/acme/acme.go:299-302`, `rfc8555.go:227-228`). Keep this difference from the RFC explicit when describing Go's behavior. ARI is outside M7 minimum scope (§6).
3. If renewal is due and the caller requested no validity period (`min_validity = 0`), return the current certificate and renew in the background. Only one renewal runs per domain (`cert.go:138-153`, `:212-222`).
4. A node using only tsnet's `Listen` does not run the 1-hour background renewal loop (DNS note §4.9, 5). This is why renewal on the first adopter's Go host starts **when a TLS handshake arrives** (`GetCertificate`) (RemoteDebug `core/internal/node/tls.go:41`).
5. On each read, parse the stored certificate and validate its key match, name, validity at the current time, and chain. If default system roots fail, retry with the built-in Let's Encrypt roots. If test roots are specified, use only those roots (`certstore.go:135-154`, `:411-459`). For **non-production directories**, a Go debug exception allows a final `UnknownAuthorityError` (`certstore.go:461-477`). Swiftail instead uses explicit test anchors (contract X3). Validation failure (`errCertExpired`) and missing files (`ErrStateNotExist`) lead to new issuance, while other read errors are returned (`cert.go:353-365`). Go does no direct key-pair or chain verification on freshly downloaded certificates before saving (`cert.go:594-612`). Swiftail's pre-save validation is a stronger boundary (contract C8).
6. Go obtains `now` before reading and passes the same value to the check after locking (`cert.go:107`, `:162`, `:353`). This path has no clock offset correction or `NotBefore` tolerance (`certstore.go:444-449`). An incorrect wall clock can cause validation failure. Swiftail reads the current time again after long waits and injects the clock as a validation input (implementation proposal).

### 4.5 Let's Encrypt Rate Limits

Each named limit was checked in the corresponding section of [Let's Encrypt Rate Limits](https://letsencrypt.org/docs/rate-limits/) (updated 2026-08-05, rechecked 2026-11-15). The values reflect operational policy on those dates, outside the protocol constants. They constrain implementation retry intervals and the number of issuances at the gate.

| Limit | Value | Implication for This Implementation |
| --- | --- | --- |
| New Certificates per Exact Set of Identifiers | 5 certificates per 7 days (recovers 1 per 34 hours). Overrides cannot be requested | **Repeatedly clearing state and issuing again for the same name reaches this limit.** Test against staging or a local ACME server |
| New Certificates per Registered Domain | 50 certificates per 7 days | The Public Suffix List determines the "registered domain." Under the public PSL rule for `ts.net`, the registered domain in the ordinary example is `tail0001.ts.net` (see the source and inference below). See §8 for the production server's deployed list and separate overrides |
| New Orders per Account | 300 per 3 hours | A single node normally renews infrequently, but the limit includes other calls on the same account, so it may still be reached |
| Authorization Failures per Identifier per Account | 5 per 1 hour (recovers 1 per 12 minutes) | The token bucket refills at one token per 12 minutes. Use it to inform failure retry policy without treating it as a mandatory minimum interval between requests |
| New Registrations per IP Address | 10 per 3 hours | Save and reuse the account key |
| Renewal Exemptions | For an ARI renewal to qualify, at least one identifier must overlap with the previous certificate in `replaces`, and that certificate must not already have been replaced through ARI. A qualifying order is exempt from all limits. Without ARI, an order for the same identifier set is exempt only from the "new orders" and "registered domain" limits and remains subject to "5 certificates per exact set of identifiers" | The 2/3 point alone gives no guarantee of avoiding limits. Certificate lifetime, other issuances for the same set, failures, and retries also matter |
| When a Limit Is Reached | `Retry-After` header in the error response | `rateLimited` in 4.3 |

The [official Public Suffix List](https://publicsuffix.org/list/public_suffix_list.dat) (direct download VERSION `2026-11-14_18-11-30_UTC`, commit `6f1e25ba61adfd473749ba1cdda658e25de97ec7`, `:16249-16250`) has rules for `ts.net` and `*.c.ts.net`. Applying those rules, the **inferred** eTLD+1 of the ordinary name `rd-mac-1a2b3c4d.tail0001.ts.net` is `tail0001.ts.net`. The actual PSL version deployed by Let's Encrypt and any separate overrides were not checked.

The same page's "Consecutive Authorization Failures per Identifier per Account" also specifies 1,152 consecutive failures, recovery at 1 per day, and reset of the consecutive count on success. Retrying a permanent failure every 6 hours can eventually reach this limit. The page recommends staging for development and testing.

For lifetimes, [Certificate Lifetime Rationale and Plans](https://letsencrypt.org/docs/cert-lifetimes/) (2026-07-22) confirms the 90-day default and 6-day option. [64-Day Certificate Lifetimes Coming Feb 2027](https://letsencrypt.org/2026/10/07/64-day-certs) (2026-10-07) confirms the production transition to a 64-day default on **2027-02-10** and the staging transition on **2026-10-14**. These are not issuance results for this node, so the §8 gate remains. For example, a single renewal flow that renews a 6-day certificate at two-thirds of its lifetime issues a certificate every 4 days, but the same conclusion about avoiding limits does not apply to general ACME servers with no lifetime floor (calculation).

### 4.6 Implementation on Apple Platforms

The following are checks against SDK declarations and small format checks **rerun in this verification session** (2026-11-15, outside the sandbox). These checks do not establish successful ACME issuance, full CSR generation, or TLS networking.

| Requirement | Approach | Verification Evidence |
| --- | --- | --- |
| Generate a P-256 key | `P256.Signing.PrivateKey()` | `CryptoKit.swiftinterface:1267-1274`. Generation and PEM reread passed |
| JWS signature (R ‖ S) | `rawRepresentation` of `signature(for:)` | `CryptoKit.swiftinterface:1629-1646`. Measured 64 bytes and signature verification passed |
| CSR DER signature | `derRepresentation` of the same signature | `CryptoKit.swiftinterface:1630-1637`. The full CSR remains unverified (§8) |
| JWK `x` and `y` | `04 ‖ X ‖ Y` from the public key's `x963Representation` | `CryptoKit.swiftinterface:1251-1253`. Verified a 65-byte public representation. For the EC format, see `SecKey.h:824-826` |
| CSR SubjectPublicKeyInfo | Public key `derRepresentation` | `CryptoKit.swiftinterface:1258-1260`. Measured 91 bytes and verified id-ecPublicKey and secp256r1 OIDs and that the BIT STRING matches the X9.63 point. RFC 5480 §2 defines SPKI. CSR assembly needs separate verification |
| Read a Go-generated SEC1 key | `P256.Signing.PrivateKey(pemRepresentation:)` | Read a temporary `EC PRIVATE KEY` generated by Go `x509.MarshalECPrivateKey`. `CryptoKit.swiftinterface:1271-1274` |
| Store the key | `pemRepresentation` | The run yielded `BEGIN PRIVATE KEY`, and Go `x509.ParsePKCS8PrivateKey` read an ECDSA key. For Go's PKCS#8 reading, see `feature/acme/certstore.go:344-352` |
| Remaining CSR DER | Restricted ASN.1 writing from 3.6 | Implementation proposal. Matching Go's CN also requires PrintableString. Test short and long lengths and leading 0s for positive INTEGERs (RFC 2986 §4, RFC 3279 2.2.3) |
| Validity period | `SecCertificateCopyNotValidBeforeDate`·`SecCertificateCopyNotValidAfterDate` | `SecCertificate.h:204-223`. Available from macOS 15 and iOS 18. Can return NULL on failure |
| Chain verification | `SecPolicyCreateSSL` + `SecTrustCreateWithCertificates` + `SecTrustSetVerifyDate` + `SecTrustEvaluateWithError` | `SecPolicy.h:196`, `SecTrust.h:231-233`, `:347-348`, `:426-428`. Only the declarations were verified. Execution remains unverified (§8) |
| Public key comparison | `SecCertificateCopyKey` + `SecKeyCopyExternalRepresentation` | `SecCertificate.h:149-157`, `SecKey.h:843-855`. Proposal to compare the X9.63 representations of EC public keys. Execution remains unverified (§8) |
| HTTPS requests | Foundation `URLSession` | Framework availability follows project policy in `docs/plan.md` §4(c) |
| base64url·PEM | Convert Foundation base64 to the URL alphabet and remove padding. Wrap PEM | Implementation proposal. RFC 4648 §5, RFC 7515 §2, RFC 7468 §§2 and 5 |

`SecIdentityCreate(allocator, certificate, privateKey)` is public from macOS 10.12 and iOS 11.2. It returns NULL if the key does not match the certificate's public key (`SecIdentity.h:57-70`). `SecKeyCreateWithData` does not add the key to the keychain and takes `04 ‖ X ‖ Y ‖ K` for EC private keys (`SecKey.h:812-829`). This representation was 97 bytes in the CryptoKit check. `SecPKCS12Import` offers `kSecImportToMemoryOnly` from macOS 15 and iOS 18 to skip keychain storage (`SecImportExport.h:652-661`, `:711-712`). M7 proposes using the preceding APIs in place of generating PKCS#12.

If only the certificate validity period, public key, and trust decision are needed, a design can obtain them with the Security APIs above. This supports omitting a custom X.509 ASN.1 parser. Intermediate chain delivery and sandbox execution remain unverified (§8).

### 4.7 Go State Directory and Identity

See DNS note §3.2 for the `tailscaled.state` format and keys, §4.4.1 for startup read order, and §4.4.3 for what preserves the same node across restarts. Additional details for M7 migration decisions follow.

1. **Files tsnet puts in the state directory** (nonempty `Dir` is varRoot. Otherwise use `tsnet-<program>` in the user configuration directory. `tailscale.com/tsnet/tsnet.go:848-869`, `:984`):

   | Path | Contents | Origin |
   | --- | --- | --- |
   | `tailscaled.state` | Default FileStore when `Server.Store == nil`. Identity and prefs (JSON with base64 values) | `tsnet.go:965-972` |
   | `tailscaled.log.conf` | ID configuration for log uploads | `tsnet.go:1104` |
   | Log buffer files starting with `tailscaled` | Logs awaiting upload | `tsnet.go:1120` |
   | `certs/` | Certificates, certificate keys, and ACME account key (3.7) | `feature/acme/certstore.go:64-81` |

   The first adopter also stores the direct connection listener's `direct.json`, `direct-key.pem`, and `direct-cert.pem` in the same directory (RemoteDebug `core/internal/direct/direct.go:30-35`). These three files belong to the first adopter. The first adopter's iPhone pins the certificate SPKI SHA-256, so preserve these files separately in the migration design (RemoteDebug `2814b2c`, `core/internal/direct/direct.go:55-60`, `docs/protocol-addenda.md:657-663`, `:756-760`).

2. **Values containing identity**: `_machinekey` (machine private key), `Config.PrivateNodeKey` (node private key) in the `profile-<id>` pointed to by `_current-profile`, `Config.OldPrivateNodeKey`, `Config.NetworkLockKey`, `Config.NodeID`, and `Config.UserProfile` in the same place, and `ControlURL` and `LoggedOut` in prefs (DNS note §3.2). Machine and node private keys use `privkey:` + 64 hex characters. `NetworkLockKey` uses a separate Ed25519 type and the `nlpriv:` prefix (`types/key/machine.go:24`, `:68-82`, `types/key/node.go:29`, `:115-127`, `types/key/nl.go:16-18`, `:32-36`, `:60-66`). `Persist` is the **`Config`** field of prefs, rather than a standalone JSON object with the same name as the Swiftail identity file (`ipn/prefs.go:314-319`, `types/persist/persist.go:18-39`).

3. **Swiftail counterparts**:

   | Go | Swiftail `identity.json` | Notes |
   | --- | --- | --- |
   | `_machinekey` | `MachineKey` | Same text format (format description in `Sources/SwiftailControl/Client/NodeIdentityStore.swift`) |
   | `Config.PrivateNodeKey` | `NodeKey` | Same format. Contract G3 rejects migration if zero or absent in Go. A zero value alone cannot establish login history |
   | `Config.OldPrivateNodeKey` | Absent | Go sends the value as `OldNodeKey` in re-registration as well if present (`direct.go:718-720`, `:759-763`). Omission limits support to normal states where the server has finished registering the current key. This import does not guarantee identity preservation if key rotation was interrupted |
   | `Config.NetworkLockKey` | Absent | At verification time, Swiftail sent zero `NLKey` (§8) |
   | `Config.NodeID`, `Config.UserProfile`, `_profiles` | Absent | Go uses them for profile management and does not use them for re-registration (DNS note §4.4.3) |
   | Prefs `ControlURL` | Absent (provided by `NodeConfiguration.controlURL`) | At import, check that the two values identify the same server. An empty value in Go means the default control server (`ipn/prefs.go:60-64`). Go also migrates aliases for historic official login URLs to the default (`ipn/ipnlocal/profiles.go:701-708`) |
   | Prefs `LoggedOut` | Absent | true means the node is logged out |
   | `certs/<domain>.crt` and `.key`, `certs/acme-account.key.pem` | Can use the same names | 4.6: CryptoKit reads Go SEC1 PEM |

4. **If two implementations share a node key**: Each process can attempt registration, map, and DERP connections with the same public key while independently advertising endpoints and a disco key. The client sources for this path cannot guarantee that both sessions stay open or which one receives packets (§8). Go is confirmed to move the current key to `OldPrivateNodeKey` and include `OldNodeKey` when rotating. The sources do not establish that the server always rejects another implementation restarted with the old key or recognizes it only as `OldNodeKey` (`control/controlclient/direct.go:704-723`, `:759-768`).

5. **Actual FileStore read order and boundaries**:
   - The outer JSON encodes `map[StateKey][]byte`, so values are **standard base64**. After decoding those bytes, `_current-profile` contains the string `profile-<id>`. The value under that key is prefs JSON. Do not decode key strings within `Config` as base64url (`ipn/store/stores.go:145-150`, `:192-194`, `ipn/ipnlocal/profiles.go:898-925`, `ipn/prefs.go:314-319`, Go `encoding/json/encode.go:90-93`).
   - The actual `_profiles` value is a JSON map of {profile ID: LoginProfile}. A profile ID is 4 hex characters from 2 random bytes, and `_current-profile` contains the **entire key** with the `profile-` prefix (`profiles.go:494-503`, `:657-666`, `:819-825`). Go looks up this key in `_profiles` to choose the startup profile (`profiles.go:318-328`, `:951-977`). If absent, it creates an empty profile. It attempts legacy prefs migration only when the key itself is absent and there are no known profiles (`profiles.go:961-974`, `ipn/store.go:26-40`). If M7 omits legacy or multiple-profile support, explicitly reject those cases (implementation proposal).
   - If the file is missing or length 0, Go starts by writing `{}` with mode 0600. It returns JSON parsing errors. Equal values skip writes, nil deletes the key, and writes atomically replace all JSON (`stores.go:158-196`, `:211-226`). Unlike certificates, identity import must fail for missing files, invalid base64, invalid keys, or missing profiles rather than generating a new identity (implementation proposal, contracts G2 and G3).
   - tsnet with `mem.Store` must be `Ephemeral`, but the root directory and `certs/` still use disk. Only Kubernetes with a store other than FileStore or mem.Store reads and writes certificates under state store keys (`tsnet/tsnet.go:848-869`, `feature/acme/certstore.go:83-104`, `:223-260`). In-memory state therefore gives no basis for assuming the ACME account key is memory-only.

Preserving the same address and StableID during migration is the **expected gate result**. Whether machine and node keys alone preserve them for any production server, tailnet lock, or interrupted rotation state is unverified (3 and 4 above, §8).

### 4.8 Implementation Input Boundaries and Go Limitations

- **URL**: The JWS signature must cover the server-provided `url` string as-is without re-encoding (RFC 8555 6.4). Check HTTPS, response size, deadlines, and URL length at the edge. Go's ACME path defaults to `http.DefaultClient`. The Swiftail contract has distinct limits: "no redirects, 2,048-byte URLs, and 64KiB JSON" (`tempfork/acme/http.go:231-268`, contracts X1 and X2).
- **States and identifiers**: Distinguish authorization from challenge state names. Account states are `valid`, `deactivated`, and `revoked`. Order states are `pending`, `ready`, `processing`, `valid`, and `invalid`. Authorization states are `pending`, `valid`, `invalid`, `deactivated`, `expired`, and `revoked`. Challenge states are `pending`, `processing`, `valid`, and `invalid` (RFC 8555 7.1.2-7.1.6). Swiftail's boundary policy checks the requested name, type, wildcard status, and order identifier set, and avoids polling unknown states indefinitely (4.3).
- **DNS cleanup and retries**: The RFC recommends removing TXT records after the challenge as a SHOULD, but Tailscale's `SetDNSRequest` has no delete operation field and this issuance function sends no deletion (RFC 8555 8.4, `tailcfg/tailcfg.go:2595-2618`, `feature/acme/cert.go:615-654`). Do not infer that an empty `Value` signals deletion. Go's `WaitOrder` retries JSON decoding errors and polls unknown statuses (`tempfork/acme/rfc8555.go:292-308`). Swiftail separately needs invalid-state rejection and an overall deadline.
- **Accounts and concurrency**: In addition to the domain lock, `accountMu` covers reading, generating, and storing account keys and looking up and registering accounts. Do not treat key file errors as absence and create a new account (`feature/acme/certstore.go:361-388`, `feature/acme/cert.go:451-473`). The Go lock is local to the same backend extension. It provides no interprocess file locking (`feature/acme/acme.go:76-89`).
- **Validation and storage**: Parsing the chain alone or checking only system roots cannot replace key, name, and validity checks (3.7 and §4.4, 5). Fail on a corrupt existing account key, and reissue for a corrupt certificate cache (`certstore.go:150-151`, `:367-374`). Directory and file modes apply at creation time and do not replace all path security checks for existing entries (`certstore.go:76-78`, `atomicfile/atomicfile.go:22-26`).
- **Time**: Certificate validation, HTTP-date, and suggested ARI times depend on the wall clock, so test clock skew (RFC 9773 §6, `tempfork/acme/http.go:95-104`, `certstore.go:444-449`). Go's ARI window selection uses `randv2.N(end.Sub(start))` with no preceding `end > start` check (`feature/acme/cert.go:334-338`). If ARI is added later, reject invalid window and time inputs first (implementation proposal).

## 5. Constants and Timers

| Name | Value | Origin |
| --- | --- | --- |
| Let's Encrypt directory | `https://acme-v02.api.letsencrypt.org/directory` | `tempfork/acme/acme.go:47` |
| Override the directory (Go) | Environment variable `TS_DEBUG_ACME_DIRECTORY_URL` | `feature/acme/certstore.go:402` |
| Maximum certificates in a chain | 5 | `acme.go:63`, `rfc8555.go:439` |
| Size calculation constant `maxCertSize` | 1MiB (DER-based constant). The effective RFC issuance path limit is the total body limit in 3.7, with no individual DER length check | `acme.go:64-67`, `rfc8555.go:412-446` |
| Maximum cached nonces | 100 ("usually 1–2") | `acme.go:69-71` |
| Retry backoff | `min(1·2·4… seconds + jitter, 10 seconds)`. With `Retry-After`, its value plus jitter (no 10-second cap). Jitter is 0 if random generation fails | `http.go:68-90` |
| Order polling interval | `Retry-After` or 1 second if absent | `rfc8555.go:303-308` |
| ARI lookup deadline | 5 seconds | `feature/acme/cert.go:324` |
| Renewal point (without ARI) | 2/3 of lifetime | `cert.go:248` |
| TXT pre-lookup deadline | 500ms | `cert.go:632` |
| Certificate directory | `<varRoot>/certs`, 0700 | `certstore.go:64-81` |
| File permissions | Certificate and account keys 0600, certificates 0644 | `certstore.go:130-162` |
| First adopter: deadline per issuance | 2 minutes | RemoteDebug `core/internal/node/node.go:836` |
| First adopter: retry interval | Double from 30 seconds to 10 minutes | RemoteDebug `node.go:55-56`, `:849` |
| First adopter: WhoIs deadline | 5 seconds | RemoteDebug `core/internal/host/host.go:236` |

## 6. Swiftail Minimum Scope and Omissions

Minimum requirements

- `whoIs`: §4.1, steps 1–3 and 5. Return `StableID`, the name, `ComputedName`, tags, and user profile (`LoginName`, `DisplayName`).
- Control server `set-dns` (§3.2).
- ACME: The twelve steps of 4.3, formats in 3.3–3.6, `badNonce` and `rateLimited` handling, and one P-256 account key and certificate key.
- Storage: File names and PEM from 3.7. Matching Go's names lets Swiftail read certificates already obtained by Go (SEC1 reading in 4.6).
- Validation: §4.4, 5 (on every read), and the 3.7 rules for downloaded chains.
- Renewal: 2/3 of lifetime.

Omissions and rationale

| Omission | Evidence |
| --- | --- |
| ARI and `replaces` | A **policy choice** to keep the scope minimal. Go also falls back to 2/3 if ARI fails, but omitting ARI loses early renewal notices and ARI rate-limit exemptions. The 2/3 point alone gives no rate-limit guarantee (4.4 and 4.5) |
| TXT pre-lookup | As Go's comment says, the worst case is "posting a record that already exists" (§4.2, 3). This reduces code that depends on the system resolver outside the tunnel |
| TLS-ALPN-01, wildcard, and BYO domains | For Funnel and Serve (excluded by plan §3). The first adopter uses only its own single FQDN |
| RSA and P-384 keys, external account binding (EAB), contacts, account key rollover, account deactivation, and certificate revocation | Unused by Go's Tailscale integration (§4.2, 2) |
| Alternate chains (`Link: rel="alternate"`) | Unused by the Tailscale integration's issuance path. The ACME fork has a lookup API (3.7). This choice forgoes a chance to succeed with a different chain if the default is untrusted |
| Caching multiple nonces | Requests are sequential, so one nonce from the last response is enough |
| `CapMap`, node key lookup, and `ProxyMapper` | Unused by the first adopter (§4.1, 2 and 7) |
| X.509 parser | 4.6 |
| Kubernetes storage and `TS_CERT_SHARE_MODE` | Not applicable |

## 7. Interop Test Checks

1. **Go reference values**: With the same account key and input, the JWK string, thumbprint, key authorization, and DNS-01 TXT value from Go (`tempfork/acme` and the standard library) match Swift byte for byte. The specification **does not fix JSON member order** in the JWS protected header or body, so check the semantics, decoded header, actual signing input, and verification by the other implementation (RFC 7515 5.1, `jws.go:70-107`). Require byte equality for the header and signing input only if using the same JSON serialization order as Go. ECDSA signatures differ per run, so verify signatures in the other implementation (Swift verifies Go's JWS and Go verifies Swift's).
2. **CSR**: Go `x509.ParseCertificateRequest` + `CheckSignature` accepts Swift's CSR, and the subject and SAN match. The `certificationRequestInfo` structure matches the CSR from Go's `certRequest`. Require byte equality if using the same public key, attributes, CN string tag, and DER rules as Go (3.6). A CSR using UTF8String differs under that byte-equality criterion even if it is valid.
3. **`set-dns`**: The `testcontrol` `/machine/set-dns` handler validates the request. `Type` is `TXT`, `Name` and `Value` are nonempty, the node key belongs to the machine key, and `Name` is `_acme-challenge.` plus the node's cert domain (`tailscale.com/tstest/integration/testcontrol/testcontrol.go:605-649`). Tests can inspect the received values through the `OnSetDNS` hook (`:66`, `:641-646`).
4. **Cert domain**: If `DNSConfig` is present and `MagicDNSDomain` is nonempty, `testcontrol` adds `<Hostinfo.Hostname>.<MagicDNSDomain>` to the netmap's `CertDomains` (`testcontrol.go:1655-1668`, `:651-663`). The Swiftail test tool provided `MagicDNSDomain` without `DNSConfig` at verification time (`Tools/interop/cmd/tailnet/main.go:115`). **That configuration produces no CertDomains in the netmap.** Set DNSConfig as well when creating the ACME gate (`testcontrol.go:1651-1668`).
5. **Full issuance**: Complete the twelve steps of 4.3 against a local ACME server (pebble) and verify the received chain against its root. pebble accepts a resolver for DNS verification via `va.New(…, customResolverAddr, …)` (`github.com/letsencrypt/pebble/v2@v2.10.3/va/va.go:121-140`). challtestsrv provides a DNS server that adds TXT records via `AddDNSTXTRecord(host, content)` (`github.com/letsencrypt/challtestsrv@v1.4.2/dns.go:75-80`). The **test design** connects `testcontrol`'s `OnSetDNS` to it and runs `set-dns` → DNS-01 verification → issuance in one process. Create a local ACME account without needing a real tailnet account (RFC 8555 7.3). pebble controls nonce rejection frequency (`PEBBLE_WFE_NONCEREJECT`) and authorization reuse (`PEBBLE_AUTHZREUSE`) via environment variables, so the test can cover `badNonce` retry and the case in §4.2, 7. **The APIs, configuration, and licenses of both modules were rechecked. Integration build and execution were not performed** (§8).
6. **`WhoIs` comparison**: On the same netmap, match `StableID`, `Name`, `ComputedName`, and `LoginName` from the Go peer's `LocalClient().WhoIs(address)` to Swift `whoIs`. Test the local address, peer IPv4 and IPv6 addresses, and an address absent from the netmap.
7. **Go state file**: Stop the Go tsnet node and start the Swift node with machine and node keys read from `tailscaled.state`. Verify the same public keys, tailnet IP, and StableID. This is the expected result of a gate that has not run (4.7). Swift reads and verifies files Go wrote under `certs/`.
8. **Real Let's Encrypt** (account required): The real control server accepts `set-dns`, and the iOS installer (`itms-services`) downloads using the issued certificate. This cannot be verified locally.

## 8. Unverified Items

- **Production control server `set-dns`**: Acceptance conditions (HTTPS-enabled tailnet, ephemeral node, advertised CapabilityVersion), whether the response waits until the record appears in authoritative DNS, rate limits, and error body format. The client source has only the request and 200 check. The `testcontrol` handler is a test implementation separate from production.
- **Tagged and shared node profiles**: What the production server sends for a tagged node's `User` and profile (`LoginName`), and whether `User` and `Sharer` profiles always arrive together for shared nodes. The only evidence is the tool code and comment in §4.1, 6.
- **Authorization reuse and Go's result for this order**: The official 2026-10-07 announcement says the current 30-day reuse period will fall to 10 days in 2027 ([official announcement](https://letsencrypt.org/2026/10/07/64-day-certs)). Reuse was confirmed as a feature. The Go flow (§4.2, 7) was not run to see whether it completes on a reused `valid` authorization for this account and order.
- **Actual Let's Encrypt PSL deployment and overrides**: eTLD+1 for an ordinary ts.net name was checked and calculated from the public PSL (4.5). The production CA's deployed snapshot and any Tailscale override are unverified, so the actual production limit boundary remains unverified.
- **Relationship between MagicDNS and HTTPS**: Whether nonempty `CertDomains` always implies MagicDNS is enabled. The first adopter checks them separately (§4.2, 9).
- **Inside App Sandbox**: Whether `SecIdentityCreate`, `SecKeyCreateWithData`, a loopback `NWListener`, and `URLSession` run with only network server and client entitlements. The experiments ran outside the sandbox.
- **Chain verification with `SecTrust` and public key comparison** (4.6): Only the public declarations were verified. Neither was run. Passing intermediate certificates in the TLS handshake (`sec_identity_create_with_certificates`) was also untested.
- **Adding pebble and challtestsrv to `Tools/interop`**: Downloaded the modules (both MPL-2.0, pebble `go 1.25.0`, challtestsrv `go 1.24`, respective `LICENSE:1` and `go.mod:3`) and read packages and function signatures. Build and execution were not performed. It is unknown whether they run in the same process as `testcontrol` or whether dependencies conflict with the pinned `tailscale.com` version.
- **Re-registering a node imported from Go state**: The Swiftail version examined here sent zero `NLKey` in registration. The server's behavior when a node registered with Go's populated `NLKey` reconnects with zero (the same question as DNS note §8.1), and server and DERP behavior when two implementations open map streams simultaneously with the same node key, are unverified.
- **This node's certificate lifetime and actual issuance**: Official production policy was checked in 4.5. No production or staging issuance was performed in this work, so actual issued lifetime, propagation time, and elapsed time are unverified.
- **Authoring session Apple experiments**: "Generate a 295-byte CSR in fifteen lines and verify it with OpenSSL," "negotiate TLS 1.2 or higher and ALPN http/1.1 with NWListener," and "no keychain writes" could not be verified because reproduction materials and output were unavailable. This session reran only the §4.6 size, PEM read/write, and signature checks. Sandbox execution, intermediate chain delivery, and SecTrust execution are outside those results.
- **Server outcome for two sessions and re-registration after rotation**: Client code also could not verify the claim that the old key works only as OldNodeKey, so the body no longer makes that assertion (§4.7, 4).

## 9. Verification Record by Original Claim

These verdicts are from a GPT-6.1 Sol session separate from the authoring session, on 2026-11-15. They divide facts from the **original before corrections** into the units below. Repeated claims in the timer table, minimum scope, and unverified sections were counted once. Future test acceptance criteria and decisions about omitted features were not counted as observed results. A field list or conditional was grouped as one claim when the same evidence supported a joint verdict, and incorrect or unverifiable parts were split out. Even "Correct" entries include added branches or evidence lines where needed. Go paths in origins are relative to the same module as in the body, and shortened file names follow the full paths in the corresponding body sections.

**248** total: **208** correct, **18** incorrect, **22** could not verify. Newly discovered facts were added with evidence in the body and excluded from the original claim count.

| ID | Original Section and Claim | Verdict | Verification Evidence and Action |
| --- | --- | --- | --- |
| V001 | 1: Reference Tailscale v1.104.6 and CapabilityVersion 148 | Correct | `tailcfg/tailcfg.go:200`, reference module |
| V002 | 1: ACME is a tempfork of x/crypto | Correct | `tempfork/acme/README.md:1-5` |
| V003 | 1: Authoring history states Apple experiments were verified by execution | Could not verify | No execution materials from the authoring session. Moved to §8 except for items rerun in 4.6 |
| V004 | 2: M7 uses WhoIs, certificates, and state migration | Correct | `docs/contracts/SwiftailHost.md` §§1 and 3 |
| V005 | 2: The first adopter plans to terminate TLS with the Network framework | Correct | `docs/contracts/SwiftailNetstack.md`, "First adopter review results (2026-11-15)", item 1 (design) |
| V006 | 3.1: Node, UserProfile, and CapMap in WhoIsResponse | Correct | `client/tailscale/apitype/apitype.go:35-42` |
| V007 | 3.1: Five UserProfile fields | Correct | `tailcfg/tailcfg.go:307-319` |
| V008 | 3.1: First adopter rejects an empty StableID | Correct | RemoteDebug `2814b2c` `core/internal/node/node.go:535-536` |
| V009 | 3.1: First adopter's short name and ComputedName fallback | Correct | RemoteDebug `node.go:538-550` |
| V010 | 3.1: First adopter reads LoginName from the profile | Correct | RemoteDebug `node.go:542-544` |
| V011 | 3.1: StableID is a stable node ID for the allowlist | Correct | `tailcfg/tailcfg.go:249-259`, RemoteDebug `host.Peer.StableID` |
| V012 | 3.1: Node.Name is an FQDN with a trailing dot | Correct | `tailcfg/tailcfg.go:374-378` |
| V013 | 3.1: Node.User is the creating user and differs from tagged ACL identity | Correct | `tailcfg/tailcfg.go:380-383` |
| V014 | 3.1: Sharer is the sharing user and is set when different from User | Correct | `tailcfg/tailcfg.go:385-386` |
| V015 | 3.1: At least one entry in Tags means IsTagged | Correct | `tailcfg/tailcfg.go:635-637` |
| V016 | 3.1: The client computes ComputedName, which is absent from messages sent by the control server | Correct | `tailcfg/tailcfg.go:496-503`. Clarified that it can appear in LocalAPI Node JSON |
| V017 | 3.2: set-dns is POST /machine/set-dns over Noise | Correct | `control/controlclient/direct.go:1756-1765` |
| V018 | 3.2: Five SetDNSRequest JSON fields | Correct | `tailcfg/tailcfg.go:2595-2618` |
| V019 | 3.2: Version 1 is replaced with current capability just before send | Correct | `ipn/ipnlocal/local.go:7813-7818`, `direct.go:1759-1760` |
| V020 | 3.2: NodeKey is current node public key text | Correct | `local.go:7822-7823`, `types/key/node.go:331-340` |
| V021 | 3.2: Name, Type, and Value are DNS-01 name, TXT, and digest | Correct | `feature/acme/cert.go:620-639`, `local.go:7813-7818` |
| V022 | 3.2: Content-Type and LBHeader for a nonzero node key | Correct | `control/ts2021/client.go:299-318` |
| V023 | 3.2: A response other than 200 is an error carrying the first 200 characters of the body | Correct | Up to 200 runes after trimming whitespace (`direct.go:1770-1772`, Go `fmt/doc.go:116-130`). Added default Noise body limit |
| V024 | 3.2: Decode 200 into SetDNSResponse and return an error on failure | Correct | `direct.go:1774-1778`. Clarified that the check accepts more than objects |
| V025 | 3.3: POST uses Flattened JWS and application/jose+json | Correct | RFC 8555 6.2·6.3, RFC 7515 7.2.2 |
| V026 | 3.3: protected, payload, and signature are each base64url strings | Correct | RFC 7515 7.2.2, `tempfork/acme/jws.go:95-117` |
| V027 | 3.3: The protected header has alg, nonce, url, and either jwk or kid | Correct | RFC 8555 6.2 (top-level JWS envelopes of the ACME POST requests covered here) |
| V028 | 3.3: Unprotected headers are forbidden | Correct | RFC 8555 6.2 |
| V029 | 3.3: P-256 uses ES256 and the server must implement it | Correct | RFC 8555 6.2, `jws.go:231-245` |
| V030 | 3.3: newAccount and revoke with a certificate key use jwk | Correct | RFC 8555 6.2 |
| V031 | 3.3: Other requests use the account URL as kid | Correct | RFC 8555 6.2·7.3 |
| V032 | 3.3: url is the exact destination URL | Correct | RFC 8555 6.4·6.4.1 |
| V033 | 3.3: nonce is the Replay-Nonce value and is used only once | Correct | RFC 8555 6.5 |
| V034 | 3.3: POST-as-GET payload is an empty string | Correct | RFC 8555 6.3 |
| V035 | 3.3: Signing input is ASCII(protected + dot + payload) | Correct | RFC 7515 5.1, `jws.go:106-108` |
| V036 | 3.3: ES256 signature is 64 raw bytes, R32 and S32, without DER encoding | Correct | RFC 7518 3.4, `jws.go:200-223` |
| V037 | 3.3: base64url uses the URL alphabet and no padding | Correct | RFC 7515 §2, RFC 4648 §5 |
| V038 | 3.3: Tailscale generates new P-256 account keys | Correct | `feature/acme/certstore.go:377` |
| V039 | 3.3: The fork also supports signing with RSA, P-384, and P-521 | Correct | `jws.go:231-245` |
| V040 | 3.4: crv, kty, x, and y in the minimal P-256 JWK | Correct | RFC 7517 4.1, RFC 7518 6.2.1 |
| V041 | 3.4: x and y are 32-byte big-endian values encoded in base64url | Correct | RFC 7518 6.2.1.2·6.2.1.3, `jws.go:172-193` |
| V042 | 3.4: Thumbprint input has required members in lexical order without whitespace | Correct | RFC 7638 3·3.2·3.3 |
| V043 | 3.4: ACME thumbprint uses SHA-256 | Correct | `jws.go:250-257`, RFC 8555 8.1. Added evidence distinguishing it from generic hash H in RFC 7638 |
| V044 | 3.4: Thumbprint input JSON is ordered crv, kty, x, y | Correct | RFC 7638 3.2, `jws.go:189-193` |
| V045 | 3.4: Go thumbprint text is base64url of SHA-256 | Correct | `jws.go:250-257` |
| V046 | 3.4: Go also uses sorted JSON for the jwk header | Correct | `jws.go:81-87` |
| V047 | 3.5: keyAuthorization is token, dot, and thumbprint text | Correct | RFC 8555 8.1, `acme.go:783-789` |
| V048 | 3.5: TXT value is base64url of SHA-256 of keyAuthorization | Correct | RFC 8555 8.4, `acme.go:591-598` |
| V049 | 3.5: Record name is _acme-challenge + domain | Correct | RFC 8555 8.4, `feature/acme/cert.go:626` |
| V050 | 3.5: token uses only the base64url alphabet | Correct | RFC 8555 8.4. Added minimum 128 bits of entropy and prohibition on padding |
| V051 | 3.6: finalize csr value is base64url of CSR DER without PEM | Correct | RFC 8555 7.4, `rfc8555.go:371-375` |
| V052 | 3.6: Go CSR for an ordinary domain has one CN and one SAN | Correct | `certstore.go:306-320`, `cert.go:587` |
| V053 | 3.6: New P-256 certificate key and ECDSA-SHA256 | Correct | `cert.go:578-587`, Go `crypto/x509/x509.go:1653-1657`. Verified by execution |
| V054 | 3.6: CertificationRequest Info, algorithm, and signature structure | Correct | RFC 2986 4.1·4.2 |
| V055 | 3.6: CSR version is INTEGER 0 | Correct | RFC 2986 4.1 |
| V056 | 3.6: Go CN for an ASCII domain is UTF8String | Incorrect | Go chooses PrintableString. Go `encoding/asn1/marshal.go:638-652`, tag 19 in execution |
| V057 | 3.6: SPKI uses id-ecPublicKey, secp256r1, and an uncompressed point | Correct | RFC 5480 2.1.1·2.1.1.1·2.2 |
| V058 | 3.6: attributes is [0] IMPLICIT SET OF Attribute | Correct | RFC 2986 4.1 and IMPLICIT TAGS in Appendix A |
| V059 | 3.6: extensionRequest OID 1.2.840.113549.1.9.14 | Correct | Downloaded RFC 2985 5.4.2 and Appendix A and verified this time |
| V060 | 3.6: SAN OID 2.5.29.17·OCTET STRING·dNSName [2] IA5String | Correct | RFC 5280 4.1·4.2.1.6 |
| V061 | 3.6: ecdsa-with-SHA256 OID and no parameters | Correct | RFC 5758 3.2 |
| V062 | 3.6: Signature BIT STRING contains a DER SEQUENCE of r and s | Correct | RFC 2986 4.2, RFC 3279 2.2.3 |
| V063 | 3.6: CSR signs the DER of Info | Correct | RFC 2986 4.2 |
| V064 | 3.7: Default certificate, key, and account key file names and location | Correct | `certstore.go:64-81`, `:116`, `:284-288` (default file store) |
| V065 | 3.7: The certificate response is a PEM chain starting with the leaf | Correct | RFC 8555 7.4.2·9.1 |
| V066 | 3.7: Reject the whole input if a PEM block's BEGIN label is anything other than CERTIFICATE | Correct | RFC 8555 11.4. Added Go's limitations on remaining input after decode failure |
| V067 | 3.7: Go rejects other PEM types, chains of 6 or more certificates, and empty chains | Correct | `rfc8555.go:423-446` (bundle=true path) |
| V068 | 3.7: The Go certificate response body limit is about 5MiB | Correct | `rfc8555.go:412-420`. Added the exact 5,401,755 bytes |
| V069 | 3.7: Go saves the received chain by rewriting it as PEM | Correct | `feature/acme/cert.go:600-609` |
| V070 | 3.7: Go stores private keys as SEC1 EC PRIVATE KEY | Correct | RFC 5915 §3, `certstore.go:323-330` |
| V071 | 3.7: Account keys are read by trying PKCS#1, PKCS#8, and SEC1 in order | Correct | `certstore.go:340-359` |
| V072 | 3.7: Certificate keys are read with tls.X509KeyPair | Correct | `certstore.go:415` |
| V073 | 3.7: Key before certificate, with atomic replacement for each file | Correct | `certstore.go:164-168`, `atomicfile/atomicfile.go:21-51` |
| V074 | 4.1.1: Address table includes only individual IPs from local and peer Addresses | Correct | `ipn/ipnlocal/node_backend.go:712-733` |
| V075 | 4.1.1: Exclude AllowedIPs and apply no expired or offline filter | Correct | `node_backend.go:719-732` |
| V076 | 4.1.2: Look up IPv4-mapped IPv6 after Unmap | Correct | `ipn/ipnlocal/local.go:1756-1758` |
| V077 | 4.1.2: ProxyMapper path when no direct address is found | Correct | `local.go:1773-1797` (added port and buildfeatures conditions) |
| V078 | 4.1.2: Direct tailnet address listeners need no ProxyMapper | Correct | `local.go:1771-1773`, scope decision for the tsnet direct connection address path |
| V079 | 4.1.3: Look up profile by User and fail WhoIs if missing | Correct | `local.go:1807-1811` |
| V080 | 4.1.4: UserProfiles carries changes, accumulated in the Go cache | Correct | `control/controlclient/map.go:384-387`, same file `:302-313` |
| V081 | 4.1.4: Final netmap includes only local User and peer User and Sharer profiles | Correct | `map.go:674-685`, `:1054-1058` |
| V082 | 4.1.4: Profiles for delta upserts are supplied again from cache | Correct | `map.go:302-346` |
| V083 | 4.1.4: Swiftail MapSession also accumulates and selects profiles | Correct | `Sources/SwiftailControl/Netmap/MapSession.swift:36-38`, `:198-213` |
| V084 | 4.1.5: ComputedName suffix removal and hostname and key fallbacks | Correct | `tailcfg/tailcfg.go:660-689`. Added shared FQDN and dot handling |
| V085 | 4.1.5: Suffix is the remainder after the first label of the local name | Correct | `types/netmap/netmap.go:256-270`. Added branch for names without a dot |
| V086 | 4.1.5: Compute a display name for each node in the map response | Correct | `control/controlclient/direct.go:1419-1434` |
| V087 | 4.1.6: Tagged node User means the user who created it | Correct | `tailcfg/tailcfg.go:380-383` |
| V088 | 4.1.6: pgproxy uses Tags when tagged-devices | Correct | `cmd/pgproxy/pgproxy.go:218-222` |
| V089 | 4.1.6: Production server tag profile value | Could not verify | The tool's branch provides no production server guarantee (§8) |
| V090 | 4.1.7: CapMap uses current filter, first remote address, and local address of the same family | Correct | `ipn/localapi/localapi.go:601-620`, `node_backend.go:443-467` |
| V091 | 4.1.7: UnsignedPeerAPIOnly allows only the ingress capability | Correct | `node_backend.go:429-440`, `:460-462` |
| V092 | 4.1.7: First adopter does not read CapMap | Correct | RemoteDebug `node.go:526-545` |
| V093 | 4.1.8: Failed WhoIs lookup 404 → ErrPeerNotFound | Correct | `localapi.go:593-596`, `client/local/local.go:353-362` |
| V094 | 4.1.8: First adopter's WhoIs failure is 403 not_paired | Correct | RemoteDebug `core/internal/host/host.go:230-243` |
| V095 | 4.1 table: Swiftail Node has the required identity, address, and Hostinfo fields | Correct | `Sources/SwiftailControl/Tailcfg/Node.swift` |
| V096 | 4.1 table: Swiftail UserProfile does not decode Groups | Correct | `Sources/SwiftailControl/Tailcfg/UserProfile.swift` |
| V097 | 4.1 table: Swiftail lacks an address table and ComputedName computation | Correct | Search of `Sources/Swiftail/`, distinguished from name resolution in `Netmap+HostResolution.swift` |
| V098 | 4.1 table: Swiftail only decodes capGrant and does not collect by address pair | Correct | `Sources/SwiftailControl/Tailcfg/FilterRule.swift` and search of `Sources/` |
| V099 | End of 4.1: Minimal WhoIs identity lookup can use netmap data | Correct | `local.go:1771-1811`. Full CapMap also needs the derived current filter calculation (`node_backend.go:443-450`) |
| V100 | 4.2.1: Reread cache after acquiring the domain lock | Correct | `feature/acme/cert.go:345-363` |
| V101 | 4.2.2: onlyReturnExisting → Register on ErrNoAccount | Correct | `cert.go:451-473`, `rfc8555.go:126-137` |
| V102 | 4.2.2: Look up the account again if registration reports it already exists | Correct | `cert.go:460-462` |
| V103 | 4.2.2: Send terms acceptance in termsOfServiceAgreed | Correct | `rfc8555.go:49-61`. Added that the field is sent if the directory has a terms URL |
| V104 | 4.2.2: Check account valid and send no contacts | Correct | `cert.go:390-392`, `:460`, `rfc8555.go:54` |
| V105 | 4.2.3: System TXT lookup deadline is 500ms, skip if the value matches | Correct | `cert.go:628-643` |
| V106 | 4.2.4: Accept immediately after set-dns without propagation wait | Correct | `cert.go:639-650` |
| V107 | 4.2.4: Production set-dns waits for DNS propagation before responding | Could not verify | Client call order cannot establish that the server waits. Moved to §8 |
| V108 | 4.2.5: After challenge, WaitOrder returns for ready or valid and fails on invalid | Correct | `cert.go:563-576`, `rfc8555.go:283-318` |
| V109 | 4.2.5: WaitOrder uses Retry-After or 1 second | Correct | `rfc8555.go:303-308` |
| V110 | 4.2.6: Generate a new certificate key only after ready | Incorrect | WaitOrder also returns valid, but the caller always generates a new key and finalizes (`cert.go:564-594`) |
| V111 | 4.2.6: New P-256 key for each renewal | Correct | `cert.go:578-587` |
| V112 | 4.2.7: Go attempts a dns-01 response even for an already valid authorization | Correct | `cert.go:531-561`, `:615-651` |
| V113 | 4.2.7: Actual Go issuance outcome with authorization reuse | Could not verify | No execution. Distinguished code behavior from production success (§8) |
| V114 | 4.2.8: No TXT deletion or order cancellation after DNS-01 failure | Correct | `cert.go:487-654`. Added the distinctions for lock release, retry, and out-of-scope TLS-ALPN cleanup |
| V115 | 4.2.8: Issuance retries start a new order and the caller determines intervals | Correct | `cert.go:525`, RemoteDebug `node.go:825-859`. Distinguished from retries within HTTP |
| V116 | 4.2.8: First adopter doubles retry delay from 30 seconds to 10 minutes | Correct | RemoteDebug `node.go:55-56`, `:849` |
| V117 | 4.2.9: Ordinary ts.net names require an exact entry in nonempty CertDomains | Correct | `cert.go:699-718`. Added out-of-scope wildcard and BYO Funnel exceptions (`:700-724`) |
| V118 | 4.2.9: First adopter also checks MagicDNSEnabled | Correct | RemoteDebug `core/internal/node/tls.go:27-32` |
| V119 | 4.2.10: Go User-Agent contains tailscaled and ACME package name | Correct | `certstore.go:399-403`, `tempfork/acme/http.go:295-304` |
| V120 | 4.2.10: ACME User-Agent is required | Correct | RFC 8555 6.1 |
| V121 | 4.3.1: Directory GET, required URLs, and meta.termsOfService | Correct | RFC 8555 7.1.1, `acme.go:166-216` |
| V122 | 4.3.1: Go reports a pre-RFC error if newOrder is absent | Correct | `acme.go:199-201` |
| V123 | 4.3.2: HEAD newNonce and obtain Replay-Nonce | Correct | RFC 8555 7.2 |
| V124 | 4.3.2: Collect nonce from success and error responses | Correct | RFC 8555 6.5, `http.go:240` |
| V125 | 4.3.2: Ignore invalid nonces | Correct | RFC 8555 6.5.1. Added that Go skips validation |
| V126 | 4.3.3: onlyReturnExisting JWK, 200, Location, and account absence error | Correct | RFC 8555 7.3.1 |
| V127 | 4.3.4: Account creation terms acceptance, 201 or existing 200, and Location | Correct | RFC 8555 7.3·7.3.1 |
| V128 | 4.3.4: Check account valid status | Correct | RFC 8555 7.1.2·7.1.6, `cert.go:390-392` |
| V129 | 4.3.5: newOrder uses a dns identifier and kid, with 201 and Location | Correct | RFC 8555 7.4 |
| V130 | 4.3.5: Order includes status, authorizations, and finalize | Correct | RFC 8555 7.1.3 |
| V131 | 4.3.6: Authorization POST-as-GET and skip valid | Correct | RFC 8555 7.1.3·7.1.4·7.1.6 |
| V132 | 4.3.6: Select dns-01 on pending, fail on other terminal statuses | Correct | RFC 8555 7.1.4, 7.1.6, and 8.4 (rejecting unsupported states is implementation policy) |
| V133 | 4.3.7: Respond to challenge after setting TXT | Correct | RFC 8555 8.4, `feature/acme/cert.go:639-646` |
| V134 | 4.3.8: Challenge response is an empty JSON object | Correct | RFC 8555 7.5.1 |
| V135 | 4.3.8: Go Accept allows 200 and 202 | Correct | `tempfork/acme/acme.go:570-573` |
| V136 | 4.3.9: Order branches for ready, valid, and invalid | Correct | RFC 8555 7.1.6 and 7.4. Added requirement for an existing CSR key on valid |
| V137 | 4.3.9: Default 1 second for pending and processing polls | Correct | Go's chosen value (`rfc8555.go:303-308`), distinct from RFC constants |
| V138 | 4.3.10: finalize returns 200 and updated order, or 403 orderNotReady before ready | Correct | RFC 8555 7.4 |
| V139 | 4.3.11: Poll processing and use certificate URL on valid | Correct | RFC 8555 7.4. Added invalid, pending, and ready branches immediately after finalize |
| V140 | 4.3.12: Certificate POST-as-GET and default PEM chain format | Correct | RFC 8555 7.4.2 |
| V141 | 4.3.12: Procedure using the Accept header | Correct | Permitted implementation choice, distinct from RFC requirements and Go behavior |
| V142 | 4.3 errors: Errors are always problem+json and type is only an ACME URN | Incorrect | Problem documents are a SHOULD. Other URIs and about:blank are possible (RFC 8555 6.7, RFC 7807 3.1) |
| V143 | 4.3 errors: badNonce retry must use the error response nonce | Correct | RFC 8555 6.5. Added that Go actually clears the cache |
| V144 | 4.3 errors: Handling accountDoesNotExist, rateLimited, and orderNotReady | Correct | RFC 8555 7.3.1·6.6·7.4 |
| V145 | 4.3 errors: userActionRequired is used to signal terms changes | Correct | RFC 8555 7.3.3. Added other user actions and the `instance` link |
| V146 | End of 4.3: Go retry candidates are <=399, >=500, and 429 | Correct | `http.go:321-323`. Added exclusion for expected success and immediate return on transport error |
| V147 | End of 4.3: Add jitter after the 10-second cap | Incorrect | Without header, min(exponential delay+jitter,10 seconds). With header, header+jitter (`http.go:68-90`) |
| V148 | End of 4.3: Unlimited default retries, stopped by context | Correct | `http.go:39-59`, `:172-198` |
| V149 | 4.4.1: Default renewal decision uses a random time in the ARI suggested window | Correct | `feature/acme/cert.go:187-198`, `:334-339` |
| V150 | 4.4.1: ARI lookup deadline is 5 seconds, with fallback at 2/3 of lifetime | Correct | `cert.go:188-191`, `:233-251`, `:324-328` |
| V151 | 4.4.1: Cache the renewal time and do not ask again | Incorrect | Clear cache after success and recalculate (`cert.go:201-204`, `:610`) |
| V152 | 4.4.2: Include replaces on every renewal | Incorrect | Requires valid previous certificate, parsing, debug, and store allowance conditions (`cert.go:394-420`) |
| V153 | 4.4.3: min_validity=0 returns the current certificate and renews asynchronously | Correct | `cert.go:138-153` |
| V154 | 4.4.3: One asynchronous renewal per domain | Correct | `cert.go:212-230` |
| V155 | 4.4.4: Listen alone does not run a 1-hour refresh loop | Correct | `feature/acme/refresh.go:35-76`, `:134-153` |
| V156 | 4.4.4: First adopter's handshake triggers renewal | Correct | RemoteDebug `tls.go:41`, path after initial warmup |
| V157 | 4.4.5: Cache reads check key pair, name, time, and system or built-in roots | Correct | `certstore.go:135-154`, `:411-459` (default production directory) |
| V158 | 4.4.5: Treat failed validation as expiration and reissue | Correct | `certstore.go:150-151`, `cert.go:353-365`. Added ordinary I/O errors and debug root exception |
| V159 | 4.5: 5 certificates per exact identifier set per 7 days, 34-hour recovery, and no override | Correct | Corresponding Let's Encrypt Rate Limits section (2026-11-15) |
| V160 | 4.5: 50 certificates per registered domain per 7 days, using PSL | Correct | New Certificates per Registered Domain in the same official document |
| V161 | 4.5: 300 new orders per account per 3 hours | Correct | New Orders per Account in the same official document |
| V162 | 4.5: The new order limit will never be reached | Incorrect | Account sharing and error retries prevent a guarantee. Corrected to a conditional explanation in 4.5 |
| V163 | 4.5: 5 authorization failures per hour, 12-minute recovery | Correct | Authorization Failures per Identifier per Account in the same official document |
| V164 | 4.5: The 12-minute recovery rate is a mandatory minimum interval | Incorrect | It is a token bucket recovery rate and permits bursts. Corrected 4.5 |
| V165 | 4.5: 10 new accounts per IP per 3 hours | Correct | New Registrations per IP Address in the same official document |
| V166 | 4.5: Including replaces alone exempts all limits | Incorrect | ARI renewal qualification requires conditions such as overlapping identifiers and an unreplaced certificate. Official ARI Renewals section |
| V167 | 4.5: Same set without ARI is exempt from new orders and registered domain limits, but subject to exact set limit | Correct | Official Non-ARI Renewals section |
| V168 | 4.5: General conclusion that 2/3 renewal avoids rate limits | Incorrect | No guarantee without lifetime, simultaneous issuance, and failure conditions. Corrected 4.5 and §6 |
| V169 | 4.5: Retry-After on rate errors and staging recommendation | Correct | Official Retry-After Header section and development and testing guidance |
| V170 | 4.6: CryptoKit can create a P256.Signing.PrivateKey | Correct | SDK declaration and this session's format check (4.6) |
| V171 | 4.6: CryptoKit raw ECDSA signature is 64 bytes | Correct | Generated and verified signatures in this session |
| V172 | 4.6: derRepresentation yields the CSR signature representation | Correct | `CryptoKit.swiftinterface:1630-1637` |
| V173 | 4.6: Authoring session CSR passed openssl req -verify | Could not verify | No program or output. Moved to §8 |
| V174 | 4.6: Public x963 is 04, X, Y and 65 bytes | Correct | This session's format check, `SecKey.h:824-826` |
| V175 | 4.6: Public derRepresentation is 91 bytes | Correct | This session's format check. SPKI is in RFC 5480 §2 |
| V176 | 4.6: CryptoKit reads Go SEC1 EC PRIVATE KEY | Correct | Go generation → CryptoKit import passed in this session |
| V177 | 4.6: CryptoKit pemRepresentation is PKCS#8 PRIVATE KEY | Correct | PEM label and key reread passed in this session |
| V178 | 4.6: CSR writing needs only the listed tags and matches Go | Incorrect | Matching Go requires PrintableString. Kept the fixed 3-byte length limit as an implementation choice |
| V179 | 4.6: Experiment verified a 295-byte CSR in fifteen lines | Could not verify | No authoring session materials. Moved to §8 |
| V180 | 4.6: Validity period API starts with macOS 15 and iOS 18 | Correct | `SecCertificate.h:204-223` |
| V181 | 4.6: Authoring session successfully ran that validity period API | Could not verify | Reconfirmed SDK declarations only. Moved to §8 |
| V182 | 4.6: SecTrust and SSL policy APIs are public | Correct | `SecPolicy.h:196`, `SecTrust.h:231`, `:347`, `:426` |
| V183 | 4.6: Certificate public key extraction and external representation APIs are public | Correct | `SecCertificate.h:149-157`, `SecKey.h:843-855` |
| V184 | 4.6: URLSession is a framework allowed by the project | Correct | `docs/plan.md` §4(c) (policy) |
| V185 | 4.6: Security APIs can obtain the required certificate values | Correct | SDK declarations above, distinct from execution and sandbox verification |
| V186 | 4.6: SecIdentityCreate is public from macOS 10.12 and iOS 11.2 | Correct | `SecIdentity.h:57-70` |
| V187 | 4.6: The X9.63 private key representation passed to SecKeyCreateWithData is 97 bytes | Correct | `SecKey.h:812-829`, this session's CryptoKit size check |
| V188 | 4.6: TLS and ALPN negotiation ran successfully via SecIdentityCreate | Could not verify | No authoring session network experiment materials. Moved to §8 |
| V189 | 4.6: That network experiment made no keychain writes | Could not verify | API declarations differ from verification of execution side effects. Moved to §8 |
| V190 | 4.6: PKCS12 memory-only option starts with macOS 15 and iOS 18 | Correct | `SecImportExport.h:652-661`, `:711-712` |
| V191 | 4.6: Whether it also works in App Sandbox | Could not verify | SDK declarations alone cannot guarantee entitlements or runtime results (§8) |
| V192 | 4.7.1: tsnet Dir is varRoot | Correct | `tsnet/tsnet.go:848-869`, `:984`. Added default directory branch when empty |
| V193 | 4.7.1: Default tsnet state file, log configuration, and log buffer names | Correct | `tsnet.go:965-972`, `:1104`, `:1120`. Added specified Store and test logger exceptions |
| V194 | 4.7.1: Three kinds of file in the certs directory | Correct | `feature/acme/certstore.go:64-81`, `:116-168` |
| V195 | 4.7.1: First adopter owns the three direct connection files | Correct | RemoteDebug `2814b2c` `core/internal/direct/direct.go:30-35` |
| V196 | 4.7.1: Preserve the direct connection key because the iPhone pins it | Correct | RemoteDebug `direct.go:55-60`, direct connection TLS description in `docs/protocol-addenda.md` |
| V197 | 4.7.2: _machinekey, current profile Config, and prefs paths | Correct | `ipn/store.go:24`, `:55-57`, `profiles.go:657-666`, `ipn/prefs.go:314-319` |
| V198 | 4.7.2: Persist fields for node key, previous key, NLKey, ID, and profile | Correct | `types/persist/persist.go:21-39` |
| V199 | 4.7.2: All listed private keys are privkey + hex64 | Incorrect | NetworkLockKey uses the nlpriv prefix and Ed25519 type (`types/key/nl.go:16-18`, `:32-36`) |
| V200 | 4.7.3: Go machine and node text matches Swiftail stored text | Correct | `NodeIdentityStore.swift:5-11`, `types/key/machine.go:24`, `types/key/node.go:29` |
| V201 | 4.7.3: A zero node key means the node has never logged in | Incorrect | Key absence alone cannot establish login history. Kept as a separate G3 migration rejection condition |
| V202 | 4.7.3: OldPrivateNodeKey is used only in rotation requests and need not migrate | Incorrect | Sent on re-registration if present. Limit migration to keys whose normal registration completed (`direct.go:718-720`, `:761`) |
| V203 | 4.7.3: Swiftail sent NLKey as zero at verification time | Correct | `Sources/SwiftailControl/Client/ControlClient+Registration.swift:44-53`, `Tailcfg/RegisterRequest.swift` |
| V204 | 4.7.3: NodeID, UserProfile, and _profiles are absent from the Swiftail identity file | Correct | `NodeIdentityStore.swift`, `NodeIdentity.swift` |
| V205 | 4.7.3: This metadata is outside the Go RegisterRequest identity keys | Correct | `control/controlclient/direct.go:759-770`. Distinguished from Go profile selection |
| V206 | 4.7.3: Empty ControlURL means the default server | Correct | `ipn/prefs.go:60-64`. Added migration of historic official URL aliases |
| V207 | 4.7.3: LoggedOut means intentional logout | Correct | `ipn/prefs.go:152-159` |
| V208 | 4.7.3: Compatibility path for P-256 SEC1 and PKCS#8 certificate files | Correct | This session's import check, `certstore.go:340-359`, `:415`. Trust verification is separate |
| V209 | 4.7.4: Two map and DERP sessions for the same node key stay open | Could not verify | Each client's connection attempt is known, but server duplicate-session policy is unverified. Removed the assertion |
| V210 | 4.7.4: Rotation moves the current key to OldPrivateNodeKey | Correct | `control/controlclient/direct.go:704-720` |
| V211 | 4.7.4: Another implementation's old key is meaningful only as OldNodeKey | Could not verify | Client inclusion of the old key cannot establish how the server treats it |
| V212 | 5: Cache limit is 100 nonces, usually 1–2 | Correct | `tempfork/acme/acme.go:69-71` |
| V213 | 5: Check 1MiB size limit for each certificate | Incorrect | The RFC path checks only the aggregate body limit (`rfc8555.go:412-446`) |
| V214 | 5: Key and account key 0600, certificate 0644, directory 0700 | Correct | `certstore.go:76-78`, `:130-162` |
| V215 | 5: First adopter's issuance deadline is 2 minutes and WhoIs deadline is 5 seconds | Correct | RemoteDebug `node.go:836`, `host.go:236` |
| V216 | 6: Go Tailscale account registration uses neither EAB nor contacts | Correct | `feature/acme/cert.go:460`, `rfc8555.go:49-69` |
| V217 | 6: RSA and P-384 are among the types unused by the minimal new key generation path | Correct | `feature/acme/certstore.go:377`, `cert.go:578`. Existing key read support is separate |
| V218 | 6: Go Tailscale issuance path does not use alternate chains | Correct | `feature/acme/cert.go:594-607`. The fork separately provides ListCertAlternates (`rfc8555.go:475-498`) |
| V219 | 6: WireGuard identity can omit ProxyMapper, node key lookup, and CapMap | Correct | Choice based on the first adopter's call scope. `node.go:526-545` |
| V220 | 6: TLS-ALPN-01, wildcard, and BYO are outside this minimum scope | Correct | `docs/plan.md` §3 and contract exclusions table. Go has separate branches |
| V221 | 7.1: Can test byte equality for JWK, thumbprint, and DNS-01 with identical input | Correct | Comparison design for deterministic formulas (`jws.go:160-196`, `:250-257`, `acme.go:591-598`) |
| V222 | 7.1: JWS protected header and signing input must be byte-identical across implementations | Incorrect | JSON member order is unspecified. RFC 7515 5.1. Compare bytes only if choosing the same serialization |
| V223 | 7.1: Compare ECDSA signatures by verification in the other implementation rather than by bytes | Correct | Go `jws.go:205`, CryptoKit signing API. Test design |
| V224 | 7.2: CSR Info is always byte-identical for the same public key | Incorrect | CN tag, attributes, and DER choices must also match. Corrected 3.6 and 7.2 |
| V225 | 7.3: testcontrol checks TXT, nonempty name and value, and node/machine ownership | Correct | `tstest/integration/testcontrol/testcontrol.go:605-649` |
| V226 | 7.3: testcontrol checks cert domain and ACME prefix and provides OnSetDNS | Correct | `testcontrol.go:636-648`, `:66` |
| V227 | 7.4: DNSConfig and MagicDNSDomain cause netmap CertDomains to be added | Correct | `testcontrol.go:1651-1668` |
| V228 | 7.4: The tool provided MagicDNSDomain at verification time | Correct | `Tools/interop/cmd/tailnet/main.go:115`. Added absence of DNSConfig |
| V229 | 7.5: pebble va.New accepts a custom resolver | Correct | `github.com/letsencrypt/pebble/v2@v2.10.3/va/va.go:121-142` |
| V230 | 7.5: challtestsrv provides a DNS server API to add TXT | Correct | `github.com/letsencrypt/challtestsrv@v1.4.2/dns.go:75-80` |
| V231 | 7.5: Connecting OnSetDNS makes issuance work in one process | Could not verify | APIs exist, but integration build and execution were not performed. Corrected to gate design |
| V232 | 7.5: pebble environment variables for nonce rejection and authorization reuse | Correct | `github.com/letsencrypt/pebble/v2@v2.10.3/wfe/wfe.go:86`, `:111` |
| V233 | 7.7: Importing Go keys gives the same IP and StableID | Could not verify | Expected result of a gate that has not run. Removed guarantees beyond normally completed registration |
| V234 | 7.8: Real set-dns, issuance, and itms-services are unverified by local tests alone | Correct | Gate scope. No real issuance in this session |
| V235 | 8: Production set-dns acceptance, response delays, frequency, and error format | Could not verify | The client and testcontrol are separate from the production control server implementation |
| V236 | 8: Production guarantees for tagged and shared node profiles | Could not verify | Only client types and lookup rules could be checked |
| V237 | 8: Real production CA limit boundary for ts.net | Could not verify | The public PSL eTLD+1 for ordinary names was checked and calculated in 4.5. CA deployment snapshot and overrides are unverified |
| V238 | 8: CertDomains guarantees MagicDNS is enabled | Could not verify | The first adopter checks separately. No server guarantee connects them |
| V239 | 8: Running SecTrust, public key comparison, and intermediate chain delivery | Could not verify | Checked SDK declarations only. No execution |
| V240 | 8: Integrated build of pebble and challtestsrv and whether versions conflict | Could not verify | Checked dependency signatures only. No execution |
| V241 | 8: Both modules are MPL-2.0 | Correct | Each module's `LICENSE:1` |
| V242 | 8: Both modules use go1.25 | Incorrect | pebble go1.25.0 and challtestsrv go1.24 (respective `go.mod:3`) |
| V243 | 8: Production server outcome when reconnecting with NLKey zero | Could not verify | Verified only the client's send format |
| V244 | 8: Lifetime of the certificate actually issued to this node | Could not verify | Moved official default lifetime to 4.5. No actual issuance |
| V245 | 5: Default ACME directory URL is the Let's Encrypt production URL | Correct | `tempfork/acme/acme.go:45-47` |
| V246 | 5: TS_DEBUG_ACME_DIRECTORY_URL changes the directory | Correct | `feature/acme/certstore.go:399-403` |
| V247 | 6: Sequential requests can be implemented by keeping only one nonce | Correct | RFC 8555 6.5 and 7.2. Obtain with HEAD if absent and use the badNonce-specific nonce when retrying |
| V248 | 6: Tailscale integration does not call account key rollover, account deactivation, or revocation | Correct | Call search in `feature/acme/` and `cert.go:451-473`, `:525-607`. Distinguished from fork API support |

## 10. Comparison with the Draft Contract (Contract Files Unedited)

The following compares W, D, C, S, R, and G from `docs/contracts/SwiftailHost.md` with this note. Choosing different limits from Go is valid in itself. The entries below identify conflicts with the protocol, places that need this note's corrections, or places that need more detail on the limits of a choice.

| Behavior | Corrections and Clarifications | Evidence |
| --- | --- | --- |
| W4, public `computedName` comment | Document that names shared from other tailnets **retain the FQDN**, matching suffixes are removed only at label boundaries, the trailing dot is removed, and common hostname suffixes are stripped. W1–W3 and W5 match current Go address lookup, and rejecting an empty StableID is the first adopter's additional policy | 4.1 1~5, `tailcfg/tailcfg.go:660-689`, `util/dnsname/dnsname.go:203-239` |
| D1~D3 | Distinguish the same **Noise client** from a guarantee of the same physical HTTP/2 connection. D2's 60-second connection wait differs from Go's immediate error. D3's object-only, 4KiB, and hidden-body restrictions remain narrower choices. Avoid broadening these to "the same behavior as Go" | 3.2, `local.go:7826-7830`, `control/ts2021/client.go:320-336` |
| C2 | Distinguish path checks from DNS name validation. For DNS name validation, require that each label **start and end with an alphanumeric character** and the total length without a trailing dot satisfy the 255-byte DNS wire limit (at most 253 characters for ordinary ASCII names). Check the final record name with `_acme-challenge.` prepended against the same limit separately. The current 255-byte limit and character set alone do not imply these conditions | RFC 1034 3.1 and 3.5, RFC 1123 2.1, and `util/dnsname/dnsname.go:129-158`. Go `validLookingCertDomain` performs only partial DNS validation |
| C4, S2, G6 | Specify concurrency for account key reading, creation, and registration, and the error for a corrupt account key. A minimal P-256-only implementation gives no compatibility guarantee for existing RSA account keys Go can read. This session verified the S2 PKCS#8 and SEC1 read path | 3.7·4.6·4.8, `certstore.go:340-388` |
| C5 | One identifier gives no basis to require `authorizations.count == 1`. Handle all authorizations by status and check `identifier.type`, value, and wildcard status. Specify the branch where the order is already ready | RFC 8555 7.1.3·7.1.4·7.4, 4.3 5·6 |
| C7, R4, X2 and X5, limits table | Shortening a valid `Retry-After` to 30 seconds or 24 hours and sending a **new HTTP request** sooner violates the server's wait time. Fail after the deadline or preserve the wait time. Distinguish reevaluating only local state every 24 hours from retrying a request | RFC 8555 6.6·7.4, RFC 7231 7.1.3, 4.3·4.5 |
| C7, `CertificateFailure.validationFailed`, R4 | Handle valid, invalid, pending, ready, and processing in the finalize response. A valid status before sending the CSR has no corresponding private key, so do not proceed with just the download. Order invalid can also mean expiration or CSR/issuance failure, in addition to DNS failure. Avoid classifying every invalid as "DNS verification failure" | RFC 8555 7.1.6·7.4, 4.3 9~11 |
| C and R problem documents, public `CertificateFailure.acme` comment | `type` is a URI reference and can be an ACME URN, a server-specific URI reference, or `about:blank`. Allow representation of HTTP status, non-JSON errors, and subproblems | RFC 8555 6.7 and 6.7.1, RFC 7807 3.1, error handling in 4.3 |
| C8, S3 | Keep pre-save key, name, and chain verification. S3's choice to use only system roots differs from Go's built-in root fallback. Use explicit test anchors and skip reproducing Go's non-production exception for UnknownAuthorityError | 4.4 5, `certstore.go:440-477` |
| S1–S3, public `chain` comment | Distinguish 0700 for new directories from permission checks on existing directories. The two files do not share a transaction. The ACME wire format does not guarantee that "the root is absent," so if omitting roots is API policy, specify how to handle them after verification | 3.7, RFC 8555 9.1, `atomicfile/atomicfile.go:21-51` |
| R1 and R4, H6 and shortcut rationale | The 2/3 point can remain the minimum policy. Remove the rate-limit avoidance guarantee. Account for ARI exemption conditions, certificate lifetime, other issuances for the same set, and consecutive authorization failure limits. Define a state requiring user action to prevent endless reissuance on permanent failures | 4.4 and 4.5, official [Rate Limits](https://letsencrypt.org/docs/rate-limits/) |
| G2~G4 | Limit migration to a single profile with normally completed registration. Require the full key in `_current-profile` and the expected Config structure. Specify how to reject zero machine keys, mismatched _profiles, and legacy state. Omitting OldPrivateNodeKey differs from Go when rotation was interrupted. Decide whether to normalize historic official ControlURL aliases when comparing to the default server | 4.7 2~5, `profiles.go:318-328`, `:701-708`, `:951-977`, `direct.go:718-720` |
| G3 | Avoid treating "same scheme, host, and port" as unconditionally equivalent to "same server used for registration." First define or disallow paths, queries, and fragments in custom control URLs (the existing ControlEndpoint already rejects userinfo). Handle only default server aliases separately | Go preserves `ServerURL` when creating the control endpoint (`control/controlclient/direct.go:810-817`, `:1535-1537`, `Sources/SwiftailControl/Client/ControlEndpoint.swift:46-52`). Proposed conservative migration boundary |
| G public API, G4 and G7, gate (a) 11 | Qualify the unconditional guarantee of the same IP and StableID on import and the asserted outcome of restarting with the old key. Zero NLKey, interrupted key rotation, and server duplicate-session outcomes remain unverified until the real migration gate | 4.7 and §8. Keep G1 and G5's requirements for a read-only source and stopping Go |

Apply these changes to the contract's test section as well. Distinguish the CN tag in the CSR reference value from JWS JSON order (§7, 1 and 2). The gate tool must also provide DNSConfig (§7, 4). **Do not use the unverified Apple experiments in contract §7 and §9 as evidence of completed implementation** (4.6 and §8).

## 11. Execution Results from This Verification

On 2026-11-15, small Go and Swift format verification programs ran with `eyebuild run m7-note-check -- …`. Go was 1.27.3. Swift compiled with `-swift-version 6 -strict-concurrency=complete -warnings-as-errors` and emitted no compiler diagnostics. Keys were randomly generated at runtime and exchanged only in the working directory. Output contained no key bytes. Results:

```text
CryptoKit: signature raw=64, public x963=65, private x963=97, public DER=91
CryptoKit PEM label: -----BEGIN PRIVATE KEY-----; Go SEC1 import: passed
CryptoKit SPKI OID and BIT STRING structure: passed
Go PKCS#8 parsing of CryptoKit output: passed
Go CSR: CN tag=19, signature=ECDSA-SHA256, SAN count=1, CheckSignature=<nil>
```

The documentation checks confirmed continuity and totals for 248 verdict IDs, a change to just one README row, table column counts and paired code fences, 204 source-reference checks covering full paths and SDK and RemoteDebug `2814b2c` files and line ranges, and receipt of 20 original RFC texts. Automated line-range checks do not replace semantic verification, which was performed by reading the body alongside the evidence in §9. `git diff --check` passed. With no library code changes, the full repository Swift test suite was not run. Actual issuance, pebble integration, TLS, and sandbox tests were also not run and remain in §8.
