# DNS, State Storage, and Node API Notes

## 1. Introduction

| Item | Details |
| --- | --- |
| Reference version | `tailscale.com` v1.104.6 (CapabilityVersion 148). The DNS message parser is `golang.org/x/net` v0.60.0 (`tailscale.com/go.mod:143`). gVisor constants are from `gvisor.dev/gvisor@v0.0.0-20260915211658-a6f909f08a72`, pinned by go.mod |
| Applicable milestones | M5 (iOS packet tunnel), M6 (in-process listeners and dialing), M7 (WhoIs, ts.net certificates, Go state file migration) |
| Authoring model | Claude Sonnet 5.5 (`claude-sonnet-5-5`) |
| Verification | Claude Opus 5.5, 2026-11-15. Corrected 16 facts (§8.3) and 12 origin line references, and expanded the M5 procedures (§§4.1.4, 4.2, and 4.3) and decision table (§6.4) |

Section tags `[M5]`, `[M6]`, and `[M7]` indicate the milestone that needs the section. M5 implementers need only §§3.1, 4.1~4.6, 6.1, and 6.4 (§3.2 is for M7 migration). TUN address and route derivation follows [netmap-engine.md](netmap-engine.md) §4.8, and magicsock rebinding after link changes follows [disco-magicsock.md](disco-magicsock.md) §4.11. Those details are covered there. Origins use `path:line` relative to the module root. Requirements for the first adopter (RemoteDebug) use paths at that repository's HEAD. Example values are fictitious (`rd-mac-1a2b3c4d.tail0001.ts.net`, `100.64.0.1`).

## 2. Scope

In scope
- [M5] Deriving OS DNS settings (`OSConfig`) and built-in resolver settings from netmap `DNSConfig`, MagicDNS response rules and the DNS byte format, intercepting service IP packets (`100.100.100.100`, `fd7a:115c:a1e0::53`), persistent state format and restart, the backend state machine, and handling link changes (Wi-Fi ↔ cellular) and socket binding.
- [M6] tsnet `Listen` and `Dial`, and netstack configuration.
- [M7] `WhoIs`, ts.net certificates (ACME DNS-01 and the control server's `set-dns`), and the keys and format needed to migrate Go state files.

Out of scope
- WireGuard, DERP, disco, and the control protocol (covered in other notes). The only control protocol format here is `/machine/set-dns`.
- Linux and Windows OS DNS configurators, exit-node DNS proxy (DoH and PeerAPI DNS), Taildrive, SSH, Serve/Funnel, app connectors, and tailnet lock.
- iOS app code (`OSConfig` → `NEDNSSettings` conversion and `GetBaseConfig` implementation). The reference sources exclude the Tailscale iOS app code (§8).

## 3. Wire and Storage Formats

### 3.1 [M5] DNS Message Fields Handled by the Responder

Go reads the header and **only the first question** with `golang.org/x/net/dns/dnsmessage` (`tailscale.com/net/dns/resolver/tsdns.go:1020-1033`). If there are multiple questions, it skips the rest and includes only the first question in the response.

Header (12 bytes, big-endian. Layout in RFC 1035 4.1.1, AD and CD bits in RFC 4035)

| Offset | Length | Field | Response value (Go local response) |
| --- | --- | --- | --- |
| 0 | 2 | ID | Query value |
| 2 | 2 | QR·Opcode(4)·AA·TC·RD·RA·Z·AD·CD·RCODE(4) | Copy the query header as is, then overwrite QR=1, AA=1, and RA=1 if RD=1. Other bits (Opcode, TC, AD, CD, and RA when RD=0) retain their query values. Opcode is unchecked (`tsdns.go:1009-1011`, `:1203-1208`) |
| 4 | 2 | QDCOUNT | 1 (if including the question) or 0 |
| 6 | 2 | ANCOUNT | 0 or 1 |
| 8 | 2 | NSCOUNT | 1 if an SOA is attached to a negative response |
| 10 | 2 | ARCOUNT | 0. The response omits the query's EDNS OPT (`tsdns.go:1203-1287`) |

Include the question section when RCODE is NOERROR or the question's TYPE is nonzero (`tsdns.go:1222-1232`). That is, only FORMERR due to failure to read the question goes out without a question.

Names
- Reading. Length byte (0x00~0x3F) + label, terminated by 0x00. High two bits 11 indicate a 14-bit offset pointer. Follow at most 10 pointers per name. 01 and 10 are errors. A `.` byte within a label is an error. An assembled name (including the trailing dot) longer than 254 bytes (255 bytes onward) is an error (254 bytes are accepted, verified by running Go on 2026-11-15. `golang.org/x/net@v0.60.0/dns/dnsmessage/message.go:2039-2111`). Errors produce FORMERR.
- Comparison. Lowercase only ASCII `A`-`Z` (`tsdns.go:1320-1331`) and normalize to an FQDN with a trailing dot. A name fails FQDN validation if it contains a byte at or below 0x20 or equal to 0x7F, has an empty label or a label of 64 bytes or more, or exceeds 254 bytes after appending the trailing dot (`tailscale.com/util/dnsname/dnsname.go:29-84`). Comparisons use lowercase names, and question and answer names in responses preserve **the case received in the query** (`tsdns.go:1009-1011`, `:1037-1094`).
- Writing. Go's local responses omit name compression. Compression activates only with two or more `resp.IPs`, while the local path populates only one `resp.IP` (`tsdns.go:1213-1218`, `:1484`). Swiftail can match Go's bytes by writing without compression too.

Answer records (all CLASS IN)

| Type | Owner name | TTL | RDATA | Origin |
| --- | --- | --- | --- | --- |
| A | Question name | 5 seconds | 4 IPv4 bytes | `tsdns.go:58`, `:1037-1049` |
| AAAA | Question name | 5 seconds | 16 IPv6 bytes | `tsdns.go:1053-1065` |
| PTR | Question name | 5 seconds | Node FQDN (with trailing dot, no compression) | `tsdns.go:1079-1094` |
| SOA (authority section) | Authoritative zone name | 10 seconds | MNAME and RNAME = zone name, SERIAL = current Unix seconds, REFRESH, RETRY, EXPIRE, and MINIMUM = 10 | `tsdns.go:68`, `:1177-1199` |

- A, AAAA, and ANY answers contain at most one record. Even for a node with multiple addresses, only the first address matching the query type is returned (`tsdns.go:791-822`, `:1484`).
- SOA appears only on negative responses: NXDOMAIN, and NOERROR for A, AAAA, or ANY when the name exists but no address of the given type exists. Skip SOA if no authoritative zone is found (a `LocalDomains` entry from §4.1.3 that contains the name) (`tsdns.go:1405-1414`, `:1427-1429`, `:1486-1496`).
- Response size. Without compression, the theoretical maximum is 12 bytes of header + 259 for the question + SOA (zone name ≤255 three times + 30 fixed) ≈ 1,066 bytes. Actual tailnet zones (`tail0001.ts.net.` and reverse zones) yield about 350 bytes even with a maximum-length question name, so they stay within 512 bytes (calculation, §4.2.4).

RCODE rules (local decisions, in order)

| Situation | Result | Origin |
| --- | --- | --- |
| Unreadable header, query QR=1, or missing question | FORMERR, no question | `tsdns.go:1028-1032`, `:1447-1459` |
| Question name is an invalid FQDN | FORMERR, includes question | `tsdns.go:1461-1468` |
| PTR query | Reverse lookup rules (§4.2.2 step 5) | `tsdns.go:1473-1475` |
| Name ends in `.onion` | NXDOMAIN (SOA only if inside the zone) | `tsdns.go:727-731` |
| A / AAAA for `magicdns.localhost-tailscale-daemon.` | `100.100.100.100` / `fd7a:115c:a1e0::53` | `tsdns.go:45`, `:736-743` |
| Name not found, within `LocalDomains` | NXDOMAIN + SOA | `tsdns.go:772-778` |
| Name not found, outside `LocalDomains` | No local answer → forwarding stage (§4.2.3) | `tsdns.go:779-782`, `:1477-1480` |
| Found, A: IPv4 present / absent | 1 A / empty NOERROR answer + SOA | `tsdns.go:792-800` |
| Found, AAAA: IPv6 present / absent | 1 AAAA / empty NOERROR answer + SOA | `tsdns.go:801-809` |
| Found, ANY(255) | First address in the list (1 A or AAAA), or empty NOERROR answer + SOA if there are no addresses | `tsdns.go:810-820` |
| Found, NS, SOA, AXFR, or HINFO | NOTIMP (no SOA) | `tsdns.go:824-826` |
| Found, other type | Empty NOERROR answer (no SOA) | `tsdns.go:834-837` |

TCP framing (when Go accepts TCP 53) uses a 2-byte big-endian length followed by the message. Close the connection if request length exceeds 4096. One connection accepts multiple queries with no response order guarantee. Idle timeout is 45 seconds (`tailscale.com/net/dns/manager.go:678-688`, `:743-815`).

### 3.2 [M5·M7] Go State File (FileStore) Format

M5 uses Swiftail's own storage (`Sources/SwiftailControl/Client/NodeIdentityStore.swift`) and does not need this format. It is used in the M7 migration decision and interop tests.

- The file is a single JSON object. Its type is `map[ipn.StateKey][]byte`, so keys are strings and values are standard base64 strings (`tailscale.com/ipn/store/stores.go:145-150`, Go `encoding/json` rules for `[]byte`). Each write replaces the whole file via `MarshalIndent` with two-space indentation and renames a temporary file in the same directory to replace the 0600 file. Equal values skip the write. Writing `nil` removes the key (`stores.go:211-227`, `tailscale.com/atomicfile/atomicfile.go:21-51`). The directory is 0700 (`tailscale.com/paths/paths.go:147-152`).
- If the file is absent or empty, attempt to write `{}` and start with an empty store (`stores.go:158-190`).
- tsnet opens `Dir/tailscaled.state` with `store.New` (`tailscale.com/tsnet/tsnet.go:965-972`). The first adopter's iOS tunnel keeps a FileStore of the same name in the App Group container (RemoteDebug `core/internal/tunnel/tunnel.go:134-139`).

Keys (single user, non-Windows)

| Key | Value (base64-decoded bytes) | Origin |
| --- | --- | --- |
| `_machinekey` | `privkey:` + 64 lowercase hex characters (32-byte machine private key) | `tailscale.com/ipn/store.go:24`, `tailscale.com/types/key/machine.go:24`, `:76-78` |
| `_current-profile` | Key string of the current profile (e.g., `profile-3fa2`) | `ipn/store.go:55-57`, `tailscale.com/ipn/ipnlocal/profiles.go:657-667` |
| `_profiles` | JSON object `{profile ID: LoginProfile}`. The comment in `store.go` describes an array, but the actual type is a map | `ipn/store.go:51-53`, `profiles.go:819-826`, `:912-926` |
| `profile-<id>` | The profile's `Prefs` JSON (tab indentation). `<id>` is 4 lowercase hex characters from 2 random bytes | `profiles.go:494-504`, `:563-572`, `tailscale.com/ipn/prefs.go:650-656` |
| `_daemon` | Single prefs entry from before profiles. Read and migrate only if there are no profiles, then retain the entry. iOS and sandboxed macOS read `ipn-go-bridge`, and Android reads `ipn-android` | `ipn/store.go:26-40`, `tailscale.com/ipn/ipnlocal/profiles_notwindows.go:16-30`, `profiles.go:951-958` |

Other keys are `server-mode-start-key` (Windows) and `_taildrop-received` (`ipn/store.go:49`, `:62`). Certificates are stored outside this file (§4.9 item 1).

`LoginProfile` JSON contains `ID`, `Name`, `NetworkProfile`, `Key`, `UserProfile`, `NodeID`, `LocalUserID`, `ControlURL`, and `Created` (omitted if 0) (`ipn/prefs.go:1077-1124`).

In `Prefs` JSON, `Persist` uses the key `Config` (`ipn/prefs.go:319`). `Persist` fields (`tailscale.com/types/persist/persist.go:20-38`):

| Field | Format |
| --- | --- |
| `PrivateNodeKey` | `privkey:` + 64 hex characters (`tailscale.com/types/key/node.go:29`, `:115-123`) |
| `OldPrivateNodeKey` | Same format. Used for key replacement requests. If absent, text representation of 32 zero bytes |
| `UserProfile` | `tailcfg.UserProfile` |
| `NetworkLockKey` | `nlpriv:` + hex(`tailscale.com/types/key/nl.go:18`) |
| `NodeID` | `tailcfg.StableNodeID` string |
| `AttestationKey` | Hardware attestation key. Omitted if zero |
| `DisallowedTKAStateIDs` | String array. Omitted if empty |

## 4. Procedures and State Machine

### 4.1 [M5] Netmap `DNSConfig` → OS DNS Settings

#### 4.1.1 `DNSConfig` Fields and Their Use in M5

Fields are defined in `tailscale.com/tailcfg/tailcfg.go:1788-1872`. The Swiftail model is `Sources/SwiftailControl/Tailcfg/DNSConfig.swift` (no `Nameservers` or `ExitNodeFilteredSet`).

| Field | Go usage | M5 |
| --- | --- | --- |
| `Proxied` | If true, add MagicDNS root zones (§4.1.2 step 6) as routes for which the built-in resolver is authoritative. As the comment says, this means MagicDNS is enabled (`tailscale.com/ipn/ipnlocal/node_backend.go:1539-1551`). If false, skip short names without dots (`node_backend.go:1276-1278`) | Required |
| `Routes` | Empty list = zone answered by the built-in resolver (`LocalDomains`, match domain). List with resolvers = split DNS forwarded to those resolvers (`tailscale.com/net/dns/manager.go:341-353`) | Keys with empty lists are required. Resolver-bearing routes are decision D2 |
| `ExtraRecords` | Add only entries with `Type` of `""`, `A`, or `AAAA` and an IP value to the built-in resolver's host table. If no route covers the name, add the name itself as an empty route (`node_backend.go:1497-1521`, `:1592-1606`) | Required |
| `Resolvers` | Default resolvers if nonempty. Then quad-100 becomes the primary resolver for all names even on iOS (§4.1.3 table row 3) | Decision D2 |
| `Domains` | Search domains. A comment says the Apple extension installs them only in primary resolver mode (`manager.go:361-366`) | Decision D3 |
| `FallbackResolvers` | Used as default resolvers only when using an exit node without default resolvers (`node_backend.go:1657-1677`) | Ignore (exit nodes unsupported) |
| `ExitNodeFilteredSet` | Used only if this node is an exit-node DNS proxy (`tailcfg.go:1835-1848`) | Ignore |
| `Nameservers` | Obsolete (only for MapRequest.Version ≥9 and <14). Client code does not read it (`tailcfg.go:1817-1821`) | Ignore |
| `CertDomains` | Unused in DNS responses. Certificate issuance targets (§4.9) | M7 |

#### 4.1.2 `dnsConfigForNetmap` — netmap → `dns.Config`

`tailscale.com/ipn/ipnlocal/node_backend.go:1435-1680`. Exit-node and app connector branches are omitted.

1. No netmap gives no configuration. An expired local node key gives empty configuration (no DNS) (`:1436-1453`).
2. Use `OnlyIPv6` if the local addresses are IPv6-only. If the local node's `AllCaps` includes `magicdns-aaaa` (`nodecap.MagicDNSPeerAAAA`), allow peer AAAA (`:1461-1470`, `tailscale.com/tailcfg/nodecap/nodecap.go:306`).
3. Leave node name → address mappings out of the configuration (except on Windows). The resolver obtains them at query time (§4.2.1) (`:1472-1496`).
4. `ExtraRecords` → `Hosts` (append addresses with the same name) (`:1497-1521`).
5. If prefs `CorpDNS` is false, stop here. With no routes, there are no OS settings (`:1523-1525`, §4.1.3 row 1).
6. `Domains` → search domains (discard entries that cannot convert to FQDNs) (`:1527-1538`). If `Proxied`, add empty routes for the MagicDNS suffix (trim leading and trailing dots from the local node's `Name` and remove the first label), `0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.`, and the 64 zones from `64.100.in-addr.arpa.` through `127.100.in-addr.arpa.` (`:1539-1542`, `tailscale.com/ipn/ipnlocal/local.go:6665-6687`, `tailscale.com/types/netmap/netmap.go:256-270`). If false, set `MagicDNSHostsUnrouted = SelfNode.Valid()` (`:1543-1551`).
7. `Resolvers` → default resolvers (`:1640-1641`). Duplicate `Routes` with each suffix converted to an FQDN (create entries even for empty lists) (`:1557-1568`, `:1649`). Add `ExtraRecords` names not covered by any route as empty routes (`:1592-1606`, `:1651`).

#### 4.1.3 `compileConfig`: `dns.Config` → (Resolver Settings, `OSConfig`), `goos == "ios"`

`tailscale.com/net/dns/manager.go:334-526`. `OSConfig` has `Nameservers`, `SearchDomains`, `MatchDomains` (install as primary resolver if empty), `Hosts` (Windows), and `Resolvers` (input only) (`tailscale.com/net/dns/osconfig.go:55-80`).

Common steps (`:338-366`)
- Keys of routes with empty lists become the resolver's sorted `LocalDomains`. Only routes with resolvers become forwarding routes.
- `ocfg.SearchDomains = search domains` (do not add split DNS suffixes).
- `serviceIPs`: `[fd7a:115c:a1e0::53]` if `OnlyIPv6`. Otherwise `[100.100.100.100, fd7a:115c:a1e0::53]`. If the control server grants `force-register-magicdns-ipv4-only`, use `[100.100.100.100]` (`tailscale.com/net/dns/config.go:79-94`, `tailscale.com/control/controlknobs/controlknobs.go:248-250`, `nodecap.go:362`).
- `matchDomains`: all route keys sorted by string, including the trailing dot (`config.go:232-242`).

iOS procedure (first match in order)

| # | Condition | Result | Origin |
| --- | --- | --- | --- |
| 1 | No default resolvers or routes | Search domains only. No name servers | `manager.go:373-377`, `config.go:112-120` |
| 2 | All default resolvers are `IP:53` (no DoH-only IP), with no routes or hosts outside the routes | `Nameservers` = those IPs (primary resolver). No quad-100 | `manager.go:378-390`, `config.go:123-151` |
| 3 | Default resolvers exist | `Nameservers = serviceIPs`, no `MatchDomains` (primary), forwarding routes + `"." = default resolvers` | `manager.go:391-397` |
| 4 | (Split DNS) Scoping available (`scopeApple`) | `Nameservers = serviceIPs`, `MatchDomains = matchDomains`. Read OS default resolvers via `GetBaseConfig` and use them as the `"."` route. An empty list is allowed (only queries for names outside the tailnet sent directly to quad-100 go unanswered) | `manager.go:434`, `:446-451`, `:463`, `:491-515` |
| 5 | (Split DNS) Scoping unavailable | `Nameservers = serviceIPs`, no `MatchDomains` (primary). Use OS default resolvers for `"."` and append their search domains. An empty list fails with `errEmptyBaseConfig` and leaves OS settings intact (Apple skips retries and waits for the app to call `RecompileDNSConfig` again) | `manager.go:463-525`, `:207-214` |

- `scopeApple` = iOS without the control server's `disable-split-dns-when-no-custom-resolvers` capability **and** no routes with resolvers (ignore `ts.net` as an exception) **and** no hosts outside the routes (false if MagicDNS is off and `MagicDNSHostsUnrouted` is set) **and** all reverse names for addresses in `Hosts` covered by routes (`manager.go:446-449`, `:557-559`, `tailscale.com/net/dns/resolver/tsdns.go:209-226`, `config.go:137-189`, `nodecap.go:227`).
- iOS takes neither the branch delegating split DNS directly to the OS (`:421-429`) nor the branch that finishes without base configuration (`:453-455`). If `GetBaseConfig` returns `ErrGetBaseConfigNotSupported` and scoping is possible, finish at row 4 without `"."` (`:473-484`).
- Rows 4 and 5 assume `OSConfigurator.SupportsSplitDNS()` is true. The iOS `OSConfigurator` is app code outside the reference sources (`tailscale.com/wgengine/userspace.go:330-337`). The first adopter returns true and returns a dummy resolver from `GetBaseConfig` meaning no upstream resolver (RemoteDebug `core/internal/tunnel/settings.go:227-251`).
- With MagicDNS enabled and no global name servers or custom split DNS in the tailnet, Go on iOS produces `dnsServers = serviceIPs`, `matchDomains = [MagicDNS suffix, ip6.arpa zone, 64 in-addr.arpa zones, ExtraRecords names…]` (row 4). Otherwise quad-100 is the primary resolver for all names and needs upstream forwarding (rows 3 and 5).

#### 4.1.4 Swiftail M5 Derivation Procedure (Recommended)

Implement Go's row 4 only and narrow rows 3 and 5 per decision D2's recommendation. The first adopter does the same on top of Go. Restrict any primary resolver setting to the suffixes quad-100 answers itself, and leave DNS unconfigured if there are no suffixes (RemoteDebug `core/internal/tunnel/settings.go:179-215`, `docs/tunnel.md:111-114`).

1. No DNS if netmap is absent or the local key has expired (`dnsServers = []`, `dnsMatchDomains = []`). §4.1.2 step 1.
2. `localZones` = (66 zones from §4.1.2 step 6 if `Proxied`) ∪ (keys in `Routes` with empty resolver lists) ∪ (valid `ExtraRecords` names outside every zone). All are lowercase FQDNs.
3. No DNS if `localZones` is empty.
4. For `dnsServers`, include `100.100.100.100` for a local IPv4 address and `fd7a:115c:a1e0::53` for a local IPv6 address (IPv4 first). Go's `serviceIPs` includes the IPv6 service IP even on IPv4-only nodes, but those lack a `fd7a:115c:a1e0::53/128` route ([netmap-engine.md](netmap-engine.md) §4.8 item 2), so omit it as the first adopter does (RemoteDebug `settings.go:58-77`). Use IPv4 only with `force-register-magicdns-ipv4-only`.
5. For `dnsMatchDomains`, sort `localZones` by string with trailing dots, then remove the dots (`config.go:232-242`, RemoteDebug `settings.go:78-80`).
6. Give the responder in §4.2 the same configuration: `LocalDomains = localZones`, host table = `ExtraRecords`, node index = netmap.
7. Emit `TunnelNetworkSettings` as `NodeEvent.networkSettings` only when it differs from the previous value, even if only DNS changed (RemoteDebug `docs/tunnel.md:170-174`). Addresses, routes, and MTU are in [netmap-engine.md](netmap-engine.md) §4.8.

### 4.2 [M5] MagicDNS Responder

#### 4.2.1 Name Index

v1.104.6 obtains node records from the netmap index at query time without pushing them into configuration (`tsdns.go:253-300`, installation in `tailscale.com/ipn/ipnlocal/local.go:647-651`).

- Name index (`nodeByName`). Insert the local node followed by all peers (later entries overwrite earlier ones), keyed by lowercase `Name` with no trailing dot. If it ends with the MagicDNS suffix, also key by the short name without that suffix. Skip empty `Name` (`node_backend.go:778-787`, `:805-821`).
- Forward lookup (`LookupHost`). Lowercase the query name and remove its trailing dot. It is unknown if `Proxied` is false and it contains no dot, if it is missing from the index, or if the node has **no addresses at all** (`node_backend.go:1198-1220`, `:1266-1282`).
- Returned addresses (`magicDNSAddrs`, `node_backend.go:1299-1325`). If the local node is IPv6-only, use only target IPv6 addresses. Otherwise use all target addresses, omitting IPv6 if the target has IPv4 and the `magicdns-aaaa` capability is absent. Preserve target `Addresses` order. For example, an AAAA query for a dual-stack peer defaults to an empty NOERROR answer + SOA.
- Reverse lookup (`LookupPTR`). A node's own addresses (excluding subnet routes) → FQDN of the node's `Name` (`node_backend.go:119-121`, `:1214-1233`).
- `ExtraRecords`. Consult the resolver's host table before the node index and build the reverse table from the same host table (`tsdns.go:347-372`, `:756-759`, `:943-946`).
- Subdomains. If absent from the host table and index, walk up parent names one at a time. If a parent is a node with `dns-subdomain-resolve`, answer with its addresses (`tsdns.go:760-771`, `node_backend.go:1246-1264`). M5 can omit it (§6.1).

#### 4.2.2 Query Processing

`Resolver.Query`(`tsdns.go:408-439`) → `respond`(`tsdns.go:1437-1499`).

1. Read the header and first question. Return FORMERR on failure (§3.1 RCODE table).
2. Convert the question name to a lowercase FQDN. Return FORMERR with the question on failure.
3. For PTR, go to step 5. Otherwise use `resolveLocal` (`tsdns.go:725-839`): `.onion` → symbolic name → 4via6 name → host table → node index → subdomain → zone determination → result by type. Unknown names outside the zone go to forwarding (§4.2.3).
4. 4via6 name (`<IPv4 with hyphens in place of dots>-via-<site ID>`, with no suffix or under `ts.net` or `tailscale.net`). A returns NOERROR with an existing name and no address. AAAA and ANY return IPv6 in the Via range (`tsdns.go:850-900`). Optional in M5.
5. Reverse lookup (`tsdns.go:903-958`, `:1416-1433`):
   - Names starting with `b`, `db`, `r`, `dr`, or `lb` followed by `_dns-sd._udp.` (Bonjour) go to forwarding without a local reply. Forwarding returns NXDOMAIN (question included, RA = RD, no AA) without sending upstream (`tsdns.go:1304-1316`, `tailscale.com/net/dns/resolver/forwarder.go:1296-1306`, `:1510-1528`).
   - For `*.in-addr.arpa.`, parse the prefix as four dotted IPv4 components and reverse them. For `*.ip6.arpa.`, the prefix must be exactly 63 bytes (32 nibbles, 31 dots). If neither matches or parsing fails, go to forwarding (`tsdns.go:1343-1397`).
   - For addresses in `fd7a:115c:a1e0:ab12:4843:cd96:6200::/104`, look up `100.x.y.z` (last 3 bytes) first (`tailscale.com/net/tsaddr/tsaddr.go:104-110`, `:151-157`).
   - Both service IPs return `magicdns.localhost-tailscale-daemon.`. Otherwise use the reverse host table → node index. If missing, return NXDOMAIN + SOA for a query name in `LocalDomains`, or forward if outside.
6. After creating a UDP response, check its size (§4.2.4).

#### 4.2.3 Unknown Names and Names Outside the Tailnet

- Go hands queries without a local answer to the forwarder (10-second overall query timeout). Check routes in descending label count and send to resolvers of the first route containing the name. `"."` matches every name. If no route matches or the resolvers are empty, return SERVFAIL (question included, AA=1, RA retains query value) (`tsdns.go:403-431`, `forwarder.go:491-494`, `:1180-1200`, `:1316-1330`, `:1534-1551`). Transport (TCP racing UDP after 2 seconds, DoH, response aggregation, latency) is in `forwarder.go:96-112`, `:383-443`, `:683-810`, `:1358-1459`.
- In M5, the OS sends only names within match domains to quad-100 (§4.1.4. OS semantics of `matchDomains` come from Apple's `NEDNSSettings.matchDomains` documentation and are outside these sources, §8). All are in `LocalDomains`, so they resolve locally as NOERROR or NXDOMAIN without forwarding. Forwarding is needed only when a user queries quad-100 directly, as with `dig @100.100.100.100 example.com`.
- The M5 recommendation is to omit forwarding and return SERVFAIL as Go does when no route matches. The first adopter also returns SERVFAIL without an upstream resolver (RemoteDebug `settings.go:244-251`, `tunnel.go:118-122`). Bonjour reverse names return NXDOMAIN (step 5).

#### 4.2.4 UDP Size, Truncation, and EDNS

- UDP check for local responses (`forwarder.go:220-261`). Set only TC if the reply exceeds the size advertised by a valid OPT at the end of the query, or 512 bytes if absent. Leave the response intact. Skip TCP queries.
- OPT recognition (`forwarder.go:148-191`). ARCOUNT must be nonzero and the **last 11 bytes** must be a record with NAME 0, TYPE 41, version 0 (offset 6), and RDLEN 0. An OPT with options is not recognized as EDNS (the 512 rule applies).
- By §3.1's calculation, local responses in tailnet zones stay within 512 bytes, so TC is practically never set. The check is only a few lines, so keeping Go's behavior is recommended. A response IP packet fits the TUN MTU because 1,066 + 48 < 1280.
- Upstream responses (unused in M5). Cap the query's advertised OPT size at 4095, receive into a 4096-byte buffer, and truncate and set TC on overflow (`forwarder.go:193-210`, `:868-941`, `tsdns.go:50`).

#### 4.2.5 TCP 53

Go accepts TCP 53 on the service IP in netstack and uses §3.1 TCP framing (`tailscale.com/wgengine/netstack/netstack.go:1723-1734`). Swiftail M5 has no TCP stack (plan §8 risk 12). Local replies leave TC clear, so the OS will not retry over TCP. Decision D4.

### 4.3 [M5] Service IP Packet Interception

Packets sent by the OS to TUN (read from utun) pass through `filterPacketOutboundToWireGuard` before WireGuard (`tailscale.com/net/tstun/wrap.go:752-830`, `:920`).

1. For an ICMP echo request to `100.100.100.100` or `fd7a:115c:a1e0::53`, the tstun wrapper rewrites the header for a reply (swaps addresses, echo reply), injects the packet with its original payload toward the OS, and drops the original packet (`wrap.go:752-769`).
2. Drop TSMP and local disco packets (`wrap.go:773-789`).
3. netstack interception. Consume packets to either service IP in netstack regardless of protocol or port and skip WireGuard (`wrap.go:790-796`, `netstack.go:866-897`).
   - UDP 53 → `handleMagicDNSUDP`. Receive queries on the same flow in a loop with a 150ms read deadline, pass each to `Manager.Query(…, "udp", source)`, and reply on the same flow. No reply on `Query` error (e.g., above 256 concurrent queries) (`netstack.go:2036-2041`, `:2080-2113`, `manager.go:652-676`).
   - Other UDP ports. Close the endpoint without replying. No ICMP port unreachable is sent (`netstack.go:2000-2011`, `:2042-2051`).
   - TCP 53 → `HandleTCPConn`. 80 and 8080 (web client and Taildrive) and the debug loopback port have respective handlers. Other TCP ports get RST (`netstack.go:1723-1787`, `tailscale.com/ipn/ipnlocal/netstack.go:21-39`).
   - Other protocols. Consume and drop (no netstack handler).
4. Response direction. Outgoing netstack packets sourced from a service IP go toward the OS (TUN write) (`netstack.go:1047-1062`, `:1119-1147`).
5. On darwin and ios, the engine then returns packets for its own tunnel address to the OS (`wgengine/userspace.go:652-667`).

This matches the first paragraph of [netmap-engine.md](netmap-engine.md) §4.8 (wrapper handles ICMP echo, netstack handles the rest). An earlier revision of these notes incorrectly left echo handling unverified.

Swiftail M5 recommendations (per-packet processing, no TCP stack)
- UDP 53 (IPv4 and IPv6). Return the §4.2 response in UDP with source and destination addresses and ports swapped. IPv6 UDP requires a checksum (RFC 8200 8.1). One response fits within 1280, so fragmentation is unnecessary (§4.2.4).
- ICMP and ICMPv6 echo. Return an echo reply, matching Go.
- Other packets. Drop before WireGuard. TCP follows decision D4.

### 4.4 [M5] State Storage and Identity

#### 4.4.1 Go Startup Read Order

1. Read `_current-profile` (`profiles.go:898-910`). Read `_profiles` into a map, empty if absent (`:912-926`).
2. If the key exists, look up its profile. If both key and profile are absent, try migrating from `_daemon` (`ipn-go-bridge` on iOS). If still absent, use a new unsaved profile with `NewPrefs()`, `LoggedOut=true`, and `WantRunning=false` (`profiles.go:860-866`, `:952-977`).
3. Read the profile key's value over `NewPrefs()`. If absent or empty, use the default prefs from step 2. Clear a stored `ControlURL` that is a synonym for the default control server (`profiles.go:669-720`).
4. `Start` sets state to `NoState` (`local.go:3151`) and reads `_machinekey` if `WantRunning`. Generate and write a new key only if absent. Stop with an error if present but unparseable or zero (`local.go:3207-3211`, `:4619-4651`).

#### 4.4.2 When State Is Written

- A profile appears in storage only after both `Persist.NodeID` and `Persist.UserProfile.LoginName` are populated (login has finished and the netmap's self node has arrived). Before then, prefs exist only in memory. Before first login, only `_machinekey` persists in the file (`profiles.go:350-356`, `:425-428`, `:545-551`).
- After login, use any existing profile for the same node and user and remove duplicates. For a new profile, make an ID and key and write `_profiles` → `profile-<id>` → `_current-profile` in order (`profiles.go:357-404`, `:411-492`, `:657-667`).
- Node key. At registration, if `PrivateNodeKey` is zero or regeneration is requested, create a new key and move the previous key to `OldPrivateNodeKey`. Generate `NetworkLockKey` if zero (`tailscale.com/control/controlclient/direct.go:704-723`).
- On every `Start`, tsnet fills `NewPrefs()` with `Hostname`, `WantRunning=true`, `ControlURL`, `RunWebClient`, and `AdvertiseTags` and passes it to `UpdatePrefs`, overwriting all stored prefs except `Persist` (`tsnet/tsnet.go:991-1004`, `ipn/backend.go:685-690`, `local.go:3157-3173`).

#### 4.4.3 Requirements for Keeping the Same Node on Restart

| Item | Classification | Rationale |
| --- | --- | --- |
| Node private key | Required. Registration uses it to refer to the same node. Generate a new one if absent | `direct.go:704-713` |
| Machine private key | Required (retain). Generate a new one if absent. How the server handles a changed machine key is unverified (§8) | `local.go:4619-4651` |
| Previous node key, NetworkLock key | For key replacement and tailnet lock. Swiftail sends zero `NLKey` in registration requests | `direct.go:714-723`, `Sources/SwiftailControl/Tailcfg/RegisterRequest.swift:38` |
| `NodeID`, `UserProfile`, profile | For Go profile management. Unused in re-registration | `profiles.go:350-356` |
| disco key | Not persisted. Generate anew on each start | `tailscale.com/wgengine/magicsock/magicsock.go:580` |
| On-disk netmap cache | Optional feature | `tailscale.com/ipn/ipnlocal/diskcache.go:32-65` |

Swiftail's `identity.json` (machine key + node key) is this minimum set. M5 adds location and protection. The first adopter puts state under the App Group container with file protection `completeUntilFirstUserAuthentication` and excludes it from backup (on a locked device, unreadable after reboot until first unlock). A second start with the same state directory is rejected (RemoteDebug `Apps/iOSTunnel/Shared/TunnelStorage.swift:5-56`, `core/internal/api/api.go:75-90`). See Apple's `FileProtectionType.completeUntilFirstUserAuthentication` documentation for the protection class.

Relevant `ipn.Prefs` fields for a node (`ipn/prefs.go:59-320`) are `ControlURL` (`https://controlplane.tailscale.com` if empty, `:42`), `Hostname`, `WantRunning`, `LoggedOut`, `CorpDNS`, `RouteAll`, `AdvertiseTags`, `ShieldsUp`, and `Persist`. `NewPrefs()` defaults to `CorpDNS=true`, `WantRunning=false`, `NoStatefulFiltering=true`, `NetfilterMode=on`, and `AutoUpdate.Check=true`. `RouteAll` is true on windows, android, and **ios**, true on sandboxed macOS, and false elsewhere (`prefs.go:734-757`, `:787-799`). The first adopter overrides iOS with `RouteAll=false`, `CorpDNS=true`, and `WantRunning=true` (RemoteDebug `core/internal/tunnel/tunnel.go:155-160`). Swiftail M5 accepts no subnet routes ([netmap-engine.md](netmap-engine.md) §6.1 item 1).

### 4.5 [M5] Node State Machine

Values are `NoState`=0, `InUseOtherUser`=1, `NeedsLogin`=2, `NeedsMachineAuth`=3, `Stopped`=4, `Starting`=5, and `Running`=6 (`ipn/backend.go:25-35`). `nextStateLocked` uses the first matching rule (`local.go:7024-7097`).

| # | Condition | Result | Line |
| --- | --- | --- | --- |
| 0 | State store initialization failed | `NoState` | `:7026-7028` |
| 1 | `WantRunning` false, `LoggedOut` false, engine unblocked, node key present | `Stopped` | `:7048-7049` |
| 2 | No netmap + (control client cannot continue authentication without human intervention, or `LoggedOut`) | `NeedsLogin` | `:7050-7055` |
| 3 | No netmap, previous `Stopped` / `NoState` / `Starting`, `Running`, or `NeedsLogin` | `Starting` / `NoState` / retain previous | `:7056-7072` |
| 4 | Netmap present, `WantRunning` false | `Stopped` | `:7074-7075` |
| 5 | Local key expired: netmap self node's `KeyExpiry` is nonzero and earlier than now | `NeedsLogin` | `:7076-7079`, `local.go:1924-1929` |
| 6 | Self node is not `MachineAuthorized` (Unknown if missing) | `NeedsMachineAuth` | `:7080-7082`, `types/netmap/netmap.go:200-208` |
| 7 | Previous `NeedsMachineAuth` | `Starting` | `:7083-7085` |
| 8 | Previous `Starting`: a peer has completed at least one handshake or a DERP connection is active | `Running`, else `Starting` | `:7086-7091`, `local.go:4920-4934` |
| 9 | Previous `Running` | `Running` | `:7092-7093` |
| 10 | Other | `Starting` | `:7094-7095` |

- Login URL. Reuse the control server's URL for up to 6 days and 23 hours (`local.go:4818-4823`). Clear on first entry to `Running` (`local.go:6934-6937`). tsnet calls `StartLoginInteractive` if in `NeedsLogin` just after startup (`tsnet.go:1008-1016`).
- Side effects on state entry (`local.go:6917-7000`). Emit `Notify{State}` only on change. `NeedsLogin` blocks engine updates. `NeedsLogin`, `Stopped`, and `NoState` restore empty engine, router, and DNS settings (= remove addresses and DNS from OS settings). `Starting` and `NeedsMachineAuth` recompute settings.

Mapping plan §6 `NodeState` and first adopter events (recommended)

| Go | First adopter output | Swiftail `NodeState` |
| --- | --- | --- |
| `NoState` | `Starting` | `.starting` |
| `NeedsLogin` | `NeedsLogin` (+ authURL, https only) | `.needsLogin` + `authURL` |
| `NeedsMachineAuth` | As is | `.needsMachineAuth` |
| `Starting`, `Running`, `Stopped` | As is | Same names |
| `InUseOtherUser`, backend error message (outside Running), engine exit due to TUN read error | `Error` + message. Engine exit persists until stop | `.failed` + `errorMessage` |

Origin: RemoteDebug `core/internal/node/node.go:409-484`, `:577-627`, `:876-878`, `Apps/iOSTunnel/Shared/TunnelStateMapping.swift:45-88`. If `NeedsLogin` with neither URL nor auth key, the first adopter requests interactive login again every 30 seconds (`node.go:54`, `:752-778`).

### 4.6 [M5] Network Switching (Wi-Fi ↔ Cellular)

#### 4.6.1 Default Interface

- The iOS app passes the interface name of a satisfied path from `NWPathMonitor` to `UpdateLastKnownDefaultRouteInterface(name)`. Ignore an empty name. Use the interface as the default route only if it exists, is up, and has at least one address. Otherwise look in the routing table (`tailscale.com/net/netmon/defaultroute_darwin.go:16-112`). NetworkExtension selects the delegated interface only once at tunnel creation (comment at `:38-48`).
- Changing the name alone does nothing. Call `netmon.InjectEvent()` to recompute immediately. `InjectEvent` forces notification even if state is equal, and `Poll` notifies only on state change (`tailscale.com/net/netmon/netmon.go:544-570`, `:640-648`). The first adopter calls both in order when the name changes and announces the utun name via `SetTailscaleInterfaceProps` before start (it cannot detect it itself on GOOS=ios) (RemoteDebug `core/internal/tunnel/tunnel.go:85-91`, `:211-229`). Name validation allows at most 15 characters, alphanumeric and `_.-` (`docs/tunnel.md:130`).
- In darwin builds (including iOS), `netmon` reads the `AF_ROUTE` socket and discards messages for uninteresting interfaces (prefixes `llw`, `awdl`, `ipsec`, `gif`, `XHC`, `anpi`, `lo`, `utun`). The minimum check interval is 1 second (`netmon_darwin.go:19-46`, `:110-178`, `netmon.go:583-630`). The polling implementation is only for platforms other than darwin (`polling.go:4`).

#### 4.6.2 Detecting Changes (`ChangeDelta`)

`netmon.go:153-209`. Without a previous state, this is the initial state. Otherwise compute `DefaultInterfaceChanged` (default interface name), `InterfaceIPsChanged`, `AvailableProtocolsChanged` (HaveV4 and HaveV6), `IsLessExpensive`, and `HasPACOrProxyConfigChanged`. `DefaultInterfaceMaybeViable` = default interface is up and is not a Tailscale interface. `RebindLikelyRequired` = (initial state ∨ clock jump of at least 10 minutes ∨ any change above) ∧ `DefaultInterfaceMaybeViable`. iOS does not monitor clock jumps (`netmon.go:726`).

#### 4.6.3 Notification Recipients and Actions

1. Engine (`wgengine/userspace.go:1155-1225`). If no interfaces are up, clear the DNS cache and tell magicsock the network is down, closing all DERP connections (`magicsock.go:2755-2773`). If `RebindLikelyRequired` and an interface is up, clear the DNS cache, reapply the last DNS settings on iOS, and emit VPN settings again if needed. If up, start the home DERP connection, call `Rebind` if `RebindLikelyRequired`, then always `ReSTUN` (rediscover endpoints and update control).
2. `Rebind`. Rebind UDP sockets to the same port. Close DERP connections without the default interface address as their local address, reconnecting the home connection. Check the rest with a 3-second ping and clear path state for all peers. See [disco-magicsock.md](disco-magicsock.md) §4.11 for details (`magicsock.go:3880-3916`, `derp.go:908-938`).
3. Backend (`local.go:1128-1164`, `:1215-1250`). Pause the control client if no interface is up and resume otherwise. Recompute the packet filter.
4. System connections (`tailscale.com/net/tsdial/tsdial.go:301-355`). TCP connections opened by `SystemDial` (control and others) close for the upper layer to reconnect if the state is no longer initial and the default interface, PAC, or proxy changes, if the default interface name is empty, or if the connection's local IP disappears.

#### 4.6.4 Socket Binding

- To prevent loops, bind control, DERP, magicsock UDP, netcheck, and port mapper sockets to the default interface. Set `IP_BOUND_IF` for IPv4 and `IPV6_BOUND_IF` for IPv6 with `setsockopt`. Leave localhost unbound and proceed without binding if the index is unavailable (`tailscale.com/net/netns/netns_darwin.go:38-55`, `:295-315`). Enabled by default on iOS. The switches to disable it are the general `SetDisableBindConnToInterface` (off by default) and an Apple extension switch honored only in macOS GUI variants (`netns_darwin.go:40`, `tailscale.com/net/netns/netns.go:61-95`).
- Index selection. Prefer the interface from `UpdateLastKnownDefaultRouteInterface`, falling back to the `netmon` cache. Reject a selected Tailscale `utun` (`netns_darwin.go:57-145`).
- Bind once at socket creation. On interface change, Rebind, DERP reconnection, and system connection closure from §4.6.3 let new sockets obtain the new index.

M5 requirements (recommended). `setDefaultInterface(name)` → validate name → if changed, update the default interface and handle link change (engine step 1 order: close and reconnect DERP, rebind UDP, ReSTUN, reconnect control, and re-emit DNS settings). This is the link change detection, Rebind, ReSTUN, DERP recheck, and iOS binding that `disco-magicsock.md` deferred to M5. Swiftail has no `AF_ROUTE` monitor, so the app's `setDefaultInterface` call is the sole notification source (decision D6).

### 4.7 [M6] tsnet Listeners and Dialing

#### 4.7.1 Inbound Path

Fake TUN (`Tun == nil`) path (`tsnet.go:922-934`).

1. Decrypted packets reach netstack after the packet filter (`netstack.go:465`, `:1472-1480`). Netstack handles packets to local addresses if `ProcessLocalIPs` is set (`netstack.go:1352-1354`).
2. In-progress TCP connection limits: global 1024 on mobile, 8192 on Linux, 2048 elsewhere, and 2/3 of that per remote IP. Ignore retransmitted SYNs with the same 4-tuple (`netstack.go:76-120`, `:539-627`).
3. `acceptTCP`: service IP handling → `TCPHandlerForDst` (quad-100 port 80 and Drive, VIP services, 22, web client, PeerAPI, serve. These take precedence over tsnet listeners. PeerAPI wins a listener port collision with PeerAPI) → tsnet `getTCPHandlerForFlow` (`netstack.go:1736-1762`, `ipnlocal/netstack.go:21-72`).
4. Listener lookup: (`tcp4`/`tcp6`, destination IP, port) → (`tcp`, IP, port) → (`tcp4`/`tcp6`, no host, port) → (`tcp`, no host, port). Hostless listeners apply only when the destination is the local node address. If none is found, send RST (`tsnet.go:1238-1266`, `:1289-1303`).
5. `CreateEndpoint` **only starts** the handshake and immediately hands a keepalive-enabled `gonet.TCPConn` to the listener. The connection returned by `Accept` may still be handshaking (reads and writes block until it completes), and address lookups are empty before completion (`netstack.go:1666-1673`, `:1702`, `:1712-1720`). Delivery uses an unbuffered channel and closes the connection if `Accept` does not take it within 1 second (`tsnet.go:2406-2417`).

`Listen` (`tsnet.go:1321-1323`, `:2090-2094`, `:2115-2271`). Normalize `0.0.0.0` and `::` to no host. Port 0 cycles through 10002~19999 starting from `nextEphemeralPort`. Reopening the same key gives `listener already open`. With `Server.Tun`, rewrite `tcp` and the empty value to `tcp4`/`tcp6`. No host uses dual-stack tcp6 (`tsnet.go:2160-2180`).

#### 4.7.2 Dialing

1. Resolve non-IP addresses through the MagicDNS callback (node FQDNs, short names, and `ExtraRecords` with empty `Type`). Prefer IPv4 for `tcp`. Bypass quad-100, falling back to the system resolver if unresolved (`tsdial.go:401-489`, `ipnlocal/resolve.go:60-77`, `:115-146`, `node_backend.go:823-836`).
2. Race multiple addresses at 300ms intervals (`tsdial.go:640-656`).
3. If `PeerForIP` succeeds (a peer with the tailnet address or route), dial through netstack, otherwise through OS networking (`tsnet.go:935-939`, `tsdial.go:608-638`, `ipnlocal/resolve.go:166-198`). The source is the local tailnet IP of the same family (`tsnet.go:940-951`).
4. tsnet `Dial` waits until `Running` (`NeedsLogin` and `Starting` wait, other states give an error) (`tsnet.go:382-419`).

#### 4.7.3 Netstack Configuration (Swift TCP Reference)

| Item | Value | Origin |
| --- | --- | --- |
| Protocols | IPv4 and IPv6, TCP, UDP, ICMPv4 and ICMPv6, 1 NIC (promiscuous), two default routes | `netstack.go:388-391`, `:436-464` |
| MTU and queue | 1280 (`DefaultTUNMTU`), 512 | `netstack.go:434`, `tailscale.com/net/tstun/mtu.go:77-79` |
| Congestion control and loss recovery | `cubic`, RACK off (enabled only with `TS_NETSTACK_ENABLE_RACK=true`. The comment at `:141-145` in the same file says the reverse, so these notes follow the code) | `netstack.go:405-417` |
| Receive buffer | Minimum 4096, default 1MiB, maximum 8MiB (iOS uses the gVisor maximum of 4MiB) | `netstack_tcpbuf_default.go:13-19`, `netstack_tcpbuf_ios.go:13-23`, `gvisor/pkg/tcpip/transport/tcp/protocol.go:41-52` |
| Send buffer | Minimum 4096, default 1MiB, maximum 6MiB (iOS 4MiB). Default constant names are swapped for send and receive, but their values are equal | Same |
| Forwarder receive window argument | 1MiB | `netstack.go:669` |
| keepalive | Enabled on accepted connections. Idle 2 hours, interval 75 seconds, count 9 | `gvisor/pkg/tcpip/transport/tcp/protocol.go:72-80` |

iOS keeps the buffer maximum at the gVisor default (4MiB) to avoid adding pressure to the NetworkExtension memory limit (`netstack_tcpbuf_ios.go:13-16`).

### 4.8 [M7] `WhoIs`

`LocalBackend.WhoIs(proto, ipport)`(`local.go:1753-1805`):

1. Convert `::ffff:a.b.c.d` to IPv4.
2. Look up in `nodeByAddr` (node-owned addresses including the local node). Port 0 is allowed for tailnet addresses (`node_backend.go:119-121`).
3. If absent (and the build includes netstack), fail for port 0. Otherwise map (proto, ip:port) to the real remote IP with `ProxyMapper` and look up again. With empty `proto`, try tcp then udp (`local.go:1773-1797`). The remote address of a connection accepted by a tsnet listener is already the peer address.
4. Fail without a netmap. Look up the user profile by the node's `User` and fail if absent (`local.go:1799-1805`).

Local API `GET /localapi/v0/whois?addr=` response (`ip`, `ip:port`, `nodekey:…`, plus `proto`, `svc_name`, `dst_ip`) (`tailscale.com/ipn/localapi/localapi.go:516-629`, `tailscale.com/client/tailscale/apitype/apitype.go:35-42`):

| Key | Contents |
| --- | --- |
| `Node` | Full `tailcfg.Node` |
| `UserProfile` | `ID`, `LoginName`, `DisplayName`, `ProfilePicURL` (omit empty), `Groups` (omit empty) (`tailcfg.go:307-319`) |
| `CapMap` | Packet filter `CapsWithValues(src, dst)`, with src = first remote node address and dst = first local address of the same family. Only ingress capability for `UnsignedPeerAPIOnly` peers. Omit if the node has no address (`node_backend.go:443-466`) |

Status codes: no read permission 403, absent or invalid `addr` 400, missing peer 404. tsnet has no `WhoIs` method and uses `LocalClient().WhoIs`. A 404 becomes `ErrPeerNotFound` (`tailscale.com/client/local/local.go:353-362`). The first adopter reads only `Node.StableID` (required, reject if absent), the first label of `Node.Name` (or `ComputedName` if empty), and `UserProfile.LoginName` (RemoteDebug `core/internal/node/node.go:526-551`).

### 4.9 [M7] ts.net Certificates

1. Storage location (`tailscale.com/feature/acme/certstore.go:64-104`, `:247-261`). With FileStore or in-memory state storage, use files in `<varRoot>/certs/` (0700). With another store in Kubernetes, use keys of the same names in the state store. Empty varRoot fails. tsnet uses varRoot = `Dir` (`tsnet.go:848-862`, `:984`).

   | File | Contents | Permissions |
   | --- | --- | --- |
   | `<domain>.key` | Certificate private key, PEM `EC PRIVATE KEY` (SEC1, P-256) | 0600 |
   | `<domain>.crt` | Chain, series of PEM `CERTIFICATE` blocks | 0644 |
   | `acme-account.key.pem` | ACME account key, PEM `EC PRIVATE KEY` (P-256) | 0600 |

   A wildcard `*.` becomes `wildcard_.` in a filename (`certstore.go:116-169`, `:284-330`, `:361-389`).
2. Call path: `LocalClient.CertPair` → `GET /localapi/v0/cert/<domain>?type=pair&min_validity=` → certificate PEM after private key PEM (`client/local/cert.go:102-135`, `ipn/localapi/cert.go:21-70`). The local API handler's build tag is `!ios && !android && !js && !ts_omit_acme` (`ipn/localapi/cert.go:4`). `feature/acme` itself also links on iOS, but tsnet TLS goes through the local API, so Go tsnet `ListenTLS` cannot obtain a certificate on iOS (inference from `tsnet/maybe_acme.go:4`, `tsnet.go:1505-1511`).
3. `GetCertificate`. Missing SNI is an error. A name without dots expands to a `CertDomains` entry starting with the name followed by a dot. Timeout is 1 minute (`client/local/cert.go:162-205`). `ListenTLS` accepts only `tcp`, waits indefinitely for `Up`, and then requires `MagicDNSEnabled` and nonempty `CertDomains`. With `min_validity=0`, the handshake uses the cached certificate and renewal is asynchronous (`tsnet.go:1458-1481`). The first adopter uses `Listen` + `tls.NewListener(GetCertificate)` in place of `ListenTLS` and prewarms with `CertPair` (retries increasing from 30 seconds to 10 minutes) (RemoteDebug `core/internal/node/tls.go:22-51`, `node.go:825-859`).
4. Issuance (`feature/acme/cert.go:81-168`, `:345-447`, `:487-654`):
   1. Remove the trailing dot and validate the name (requires a dot, prohibits `..`, `:`, `/`, `\`, and NUL, permits `*` only in an initial `*.`) (`:96-100`, `:662-678`).
   2. Requires a netmap. Only exact names in `CertDomains` (except BYO Funnel domains). `*.<domain>` requires `dns-subdomain-resolve` (`:689-728`).
   3. Read the stored pair and validate the chain using `DNSName` and current time (system roots → bundled Let's Encrypt roots) (`certstore.go:135-154`, `:411-474`).
   4. Renewal decision. With nonzero `min_validity`, renew synchronously when remaining lifetime is shorter. For 0, once a random time in the suggested ARI window has passed (2/3 of lifetime if the 5-second ARI lookup fails), renew asynchronously once per domain and return the current certificate (`:138-251`, `:306-340`).
   5. Account key (generate and save P-256 if absent), default directory `https://acme-v02.api.letsencrypt.org/directory` (override with `TS_DEBUG_ACME_DIRECTORY_URL`), HTTP uses `http.DefaultClient` (`certstore.go:361-404`, `tempfork/acme/acme.go:47`, `tempfork/acme/http.go:264-269`). `GetReg` → `Register` if absent → check `valid` (`cert.go:386-392`, `:451-473`).
   6. Order (ARI `replaces` if a previous certificate exists) → DNS-01 for each authorization (TLS-ALPN-01 only for :443 Funnel + previous certificate, or BYO Funnel) (`:253-275`, `:394-446`, `:515-536`).
   7. DNS-01. TXT value = `base64url(SHA-256(token + "." + JWK thumbprint))` (no padding), name = `_acme-challenge.<domain>`. Check whether it already exists via the system resolver within 500ms. If absent, send `POST /machine/set-dns` on the Noise channel to the control server with JSON `SetDNSRequest{Version, NodeKey, Name, Type: "TXT", Value}` (Version is `CurrentCapabilityVersion`). A non-200 is an error, and 200 decodes `{}` (`:615-654`, `tempfork/acme/acme.go:591-598`, `local.go:7809-7839`, `direct.go:1758-1781`, `tailcfg.go:2595-2621`). Then call `Accept`.
   8. `WaitOrder` → new P-256 key and CSR (`CN` and SAN = domain) → `CreateOrderCert(bundle=true)` → save key file, then certificate file (`:563-613`, `certstore.go:164-169`, `:305-330`).
5. Background renewal loop (1 hour, first run immediately). Runs only in `Running` with a Web entry or `TerminateTLS` in serve settings. Using only `Listen`, `ListenTLS`, or `ListenFunnel` leaves it off. `ListenService` (HTTP mode or `TerminateTLS`) enables it. `TS_CERT_SHARE_MODE=ro` disables issuance and renewal (`feature/acme/refresh.go:21-76`, `:134-155`, `tsnet.go:2007-2039`, `cert.go:123-125`).

### 4.10 [M6·M7] tsnet API Summary

| Call | Summary | Origin |
| --- | --- | --- |
| `Up` | Subscribe to the bus including initial state, return `Status` on `Running`, fail on `ErrMessage`, continue waiting on `NeedsLogin` or `NeedsMachineAuth`. Clear serve settings on first `Up` | `tsnet.go:573-636` |
| `Status` | `ipnstate.Status`: `Version`, `TUN`, `BackendState`, `HaveNodeKey`, `AuthURL`, `TailscaleIPs`, `Self`, `ExitNodeStatus`, `Health`, `MagicDNSSuffix`, `CurrentTailnet`, `CertDomains`, `Peer`, `User`, `ClientVersion` | `ipn/ipnstate/ipnstate.go:32-91` |
| `WatchIPNBus` | `Notify` JSON stream (`State`, `ErrMessage`, `BrowseToURL`, `LoginFinished`, `Prefs`, `InitialStatus`, etc.) | `client/local/local.go:1516-1544`, `ipn/backend.go:84-227`, `:335-509` |
| `StartLoginInteractive` | Notify immediately if a valid URL exists, otherwise request interactive login | `local.go:4798-4839` |

## 5. Constants and Timers

| Name | Value | Origin |
| --- | --- | --- |
| [M5] Service IP | `100.100.100.100`, `fd7a:115c:a1e0::53` | `tailscale.com/net/tsaddr/tsaddr.go:52-68` |
| [M5] 4to6 range | `fd7a:115c:a1e0:ab12:4843:cd96:6200::/104` | `tsaddr.go:104-110` |
| [M5] Local reply TTL (A, AAAA, PTR) | 5 seconds | `tsdns.go:58` |
| [M5] SOA TTL·REFRESH·RETRY·EXPIRE·MINIMUM | 10 | `tsdns.go:68`, `:1186-1198` |
| [M5] Default UDP maximum (without EDNS) | 512 bytes | `forwarder.go:228` |
| [M5] Concurrent DNS queries | 256 | `manager.go:60` |
| [M5] Service IP UDP read deadline | 150ms | `netstack.go:2085` |
| [M5] DNS TCP idle time and maximum request | 45 seconds and 4096 bytes | `manager.go:682`, `:687` |
| [M5] Overall query timeout (forwarding) | 10 seconds | `tsdns.go:406` |
| [M5] Maximum forwarded response | 4095 bytes (4096-byte buffer) | `tsdns.go:50` |
| [M5] Maximum name pointers | 10 | `golang.org/x/net@v0.60.0/dns/dnsmessage/message.go:2097` |
| [M5] Default TUN MTU | 1280 | `tailscale.com/net/tstun/mtu.go:79` |
| [M5] Minimum `netmon` check interval | 1 second | `netmon.go:627` |
| [M5] Large clock jump (unmonitored on iOS) | 10 minutes | `netmon.go:42`, `:726` |
| [M5] DERP ping after Rebind | 3 seconds | `derp.go:923` |
| [M5] Login URL reuse | 6 days and 23 hours | `local.go:4822` |
| [M5] Retry on empty base configuration (non-Apple) | Double from 1 second, 6 attempts | `manager.go:54-55` |
| [M6] In-progress connection limit | Mobile 1024, Linux 8192, others 2048, 2/3 per remote IP | `netstack.go:85-120` |
| [M6] `Accept` delivery wait | 1 second | `tsnet.go:2412` |
| [M6] Ephemeral ports | 10002~19999 | `tsnet.go:2110-2113` |
| [M6] Dial race interval | 300ms | `tsdial.go:643` |
| [M7] Certificate renewal loop | 1 hour (first run immediately), 2 minutes per call | `refresh.go:21`, `:84-132` |
| [M7] Renewal point on ARI failure | 2/3 of lifetime | `cert.go:248` |
| [M7] ARI lookup and preliminary TXT lookup | 5 seconds and 500ms | `cert.go:306-340`, `:615-636` |
| [M7] `GetCertificate` timeout | 1 minute | `client/local/cert.go:162-205` |

## 6. Minimum Swiftail Requirements and Optional Parts

### 6.1 M5 — iOS Packet Tunnel

Minimum implementation
1. DNS settings derivation. Steps 1~7 of §4.1.4. Emit results as `TunnelNetworkSettings.dnsServers` and `dnsMatchDomains`.
2. Responder. Byte format (header, one question, reading names with pointers, writing without compression) and RCODE table in §3.1, index rules in §4.2.1, steps 1~3, 5, and 6 in §4.2.2, SERVFAIL in §4.2.3, TC check in §4.2.4.
3. Service IP interception. §4.3 recommendation (reply to UDP 53 and echo, drop the rest).
4. State. Use existing `identity.json` with the App Group path and file protection class. Reject duplicate starts in the same directory (§4.4.3).
5. State machine. §4.5 table (netmap, `MachineAuthorized`, `KeyExpiry`, liveness) and `NodeState` mapping. Return DNS and addresses to empty settings on key expiry or `NeedsLogin`.
6. Network switching. Recommendations at the end of §4.6 and in [disco-magicsock.md](disco-magicsock.md) §4.11, and socket binding (§4.6.4).

Optional parts and reasons
- All upstream forwarding (route selection, UDP, TCP, DoH, response aggregation). With only match domains, the OS does not send names outside the tailnet to quad-100 (§4.2.3). The first adopter also skips forwarding.
- `GetBaseConfig` and primary resolver mode (§4.1.3 rows 3 and 5). Decision D2.
- TCP 53. Local replies leave TC clear (§4.2.4). Decision D4.
- 4via6 names, subdomain rules (`dns-subdomain-resolve`), `.onion` (one line, so it could be included), `FallbackResolvers`, `ExitNodeFilteredSet`, and `Nameservers` (§4.1.1).
- Go state file format (§3.2). M7.

### 6.2 M6 — In-Process Listeners and Dialing

The minimum implementation includes the §4.7.1 inbound path (receive after filtering, 4-step listener lookup, RST without a listener, 1 second for `Accept`, in-progress connection limits, keepalive), `Listen` normalization, ephemeral ports and duplicate errors, and §4.7.2 dialing (MagicDNS index for names, bypass quad-100, local IP as source). The M6 contract determines the connection state at Accept (whether the handshake is complete). Go hands it off before completion.

Optional parts are `ListenPacket`, `ListenTLS`/Funnel/Service, subnets, PeerAPI, SSH, and web client (`TCPHandlerForDst`), and `ProxyMapper`.

### 6.3 M7 — Verification of Replacement at the First Adopter

Minimum implementation
- `whoIs`. §4.8 steps 1, 2, and 4, returning `Node` and `UserProfile`. The first adopter reads `StableID`, `Name` (or `ComputedName`), and `LoginName`.
- Certificates. §4.9 item 4 steps 1~8 (DNS-01 only), file format in item 1, and renewal decisions on request (2/3 rule is sufficient). Required parts are an ACME (RFC 8555) client, ES256 JWS, P-256 keys and SEC1 PEM, PKCS#10 CSR, X.509 chain verification, control server `set-dns`, and per-domain locking. Determine the binding policy for ACME HTTP requests separately (Go uses the OS default route).
- Go state file migration. Create Swiftail `identity.json` by reading only `_machinekey` and `_current-profile` → `profile-<id>` → `Config.PrivateNodeKey` (and `OldPrivateNodeKey` if needed) from §3.2. After base64 decoding, values are `privkey:` + hex.

Optional parts are ARI and `replaces`, wildcards, TLS-ALPN-01, the background loop, Kubernetes storage, and multiple profiles.

### 6.4 M5 Contract Decisions for the Lead Session

| # | Decision | Options | Recommendation |
| --- | --- | --- | --- |
| D1 | How to provide DNS to the OS | (a) Match domains only (Go row 4, first adopter) / (b) Follow Go including primary resolver mode | (a). (b) requires upstream forwarding and a way to read OS default resolvers inside NE. The latter is unverified (§8) |
| D2 | Incoming `DNSConfig.Resolvers` (global name servers) and `Routes` with resolvers (custom split DNS) | (a) Ignore and match local zones only (first adopter) / (b) Include those suffixes in the match list and return SERVFAIL / (c) Implement forwarding | (a). Record the lack of support in the contract and state. Those names go to OS default DNS |
| D3 | Search domains (`Domains`) and `matchDomainsNoSearch` | (a) Omit, app sets `matchDomainsNoSearch = true` (first adopter. Short names do not resolve) / (b) Add a search domains field to `TunnelNetworkSettings` | (a). Go comments say Apple scoped mode uses match domains as the search list, which would include all 65 reverse zones (§8) |
| D4 | Service IP TCP (including 53) | (a) Drop silently / (b) Generate and send RST / (c) Connect M6 TCP stack | (b). Go also sends RST for ports other than 53. Use (c) for 53 after M6 |
| D5 | Service IP ICMP echo | Reply / Drop | Reply (matches Go and supports diagnostics) |
| D6 | Link-change notification source | (a) `setDefaultInterface` only / (b) `NWPathMonitor` inside Swiftail | (a). The library leaves NetworkExtension and Network framework policy to the app (plan §6). Reevaluate when called again even with the same name (like Go `InjectEvent`) |
| D7 | Peer AAAA | Go rules (no AAAA if IPv4 exists unless `magicdns-aaaa` permits it) / Always AAAA | Go rules |
| D8 | State directory | Same directory as the first adopter's Go state file / Separate | Separate directory. Migration is an M7 decision (§6.3) |
| D9 | `Running` determination | Go rules (peer with completed handshake or DERP connection) / Receipt of netmap alone | Go rules. DERP permits `Running` even in a tailnet without peers |

## 7. Interop Test Checks

These plans were unexecuted.

M5 DNS (in-memory TUN, compared with a Go node)
1. Settings derivation. MagicDNS on and off, `ExtraRecords` covered and uncovered by routes, empty routes, routes with resolvers, global `Resolvers`, IPv4-only and IPv6-only nodes, and `force-register-magicdns-ipv4-only`. Record Go `dns.NewManager(goos "ios")`'s `OSConfig` alongside §4.1.4 results (same approach as the first adopter's test in `docs/tunnel.md:175-176`).
2. Send A, AAAA, ANY, PTR (IPv4, IPv6, 4to6, service IP), NS, SOA, TXT, and unknown types to `100.100.100.100:53` and `[fd7a:115c:a1e0::53]:53` and compare byte for byte with Go. Check RCODE, AA, RA (RD 0 and 1), TTL, SOA presence and contents (except SERIAL), and question case preservation.
3. Short names, FQDNs, mixed case, names without a trailing dot, nodes without addresses, names outside the zone (SERVFAIL), `.onion`, Bonjour reverse names, 0 or 2 questions, QR=1, pointer-compressed questions, and invalid labels (FORMERR).
4. EDNS (`+bufsize=4096`) with no OPT in response, TC at the 512-byte boundary.
5. Service IP. No response on other UDP ports, TCP RST (D4), ICMP and ICMPv6 echo replies, no packets going to WireGuard.

M5 state and switching
6. Restart in the same directory gives the same IP without `NeedsLogin`. A new directory gives a different IP (first adopter `docs/tunnel.md:163`). Key expiry → `NeedsLogin` and removal of DNS and addresses, unauthorized machine → `NeedsMachineAuth`, DERP alone gives `Running` in a tailnet without peers.
7. Wi-Fi ↔ cellular and disabling airplane mode on a real device. Measure time to DERP reconnection, UDP rebinding, and control reconnection, and check FQDN resolution after switching.

M6·M7
8. RST on ports without a listener, 1 second for `Accept`, limit per remote IP, and state at Accept (§6.2).
9. `whoIs` returns the same `Node.StableID` and `LoginName` as Go `LocalClient.WhoIs`.
10. Issue through the Let's Encrypt staging directory and check whether control receives `set-dns` (testcontrol `tstest/integration/testcontrol/testcontrol.go:605`) and the renewal decision.
11. Verify that a node migrated from Go `tailscaled.state` starts with the same IP.

## 8. Unverified Items

### 8.1 Unverified Facts

- iOS app code outside Go. The reference sources omit the Tailscale iOS app's `OSConfigurator` (`SupportsSplitDNS`, `GetBaseConfig`) and `OSConfig` → `NEDNSSettings` conversion. The claims in comments at `manager.go:361-366`, `:436-445` (the Apple extension installs search domains only in primary mode and uses match domains as the search list in scoped mode, and configd clears `NEDNSSettings.searchDomains`) were verified only as comments.
- OS behavior of `NEDNSSettings.matchDomains` (names outside the match list do not go to tunnel DNS, `matchDomainsNoSearch`) should be based on Apple's documentation, which this review did not check. How to read OS default resolvers inside the NE extension is also unverified (D1).
- With `selfExpired`, settings are empty but resolver lookups in the node index are independent of settings (`tsdns.go:756-759`). Removing OS routes and DNS (§4.5) appears to prevent packets from reaching quad-100. This was unverified by execution.
- How the control server handles a node with a changed machine key and the effect of sending zero `NLKey` (covered by the control notes).
- When the production control server grants `force-register-magicdns-ipv4-only` and `disable-split-dns-when-no-custom-resolvers`.
- Whether the `AF_ROUTE` socket (`netmon_darwin.go`) actually opens in the iOS extension sandbox. Go relies on the build rule that `GOOS=ios` also matches the `darwin` build tag.
- Exact conditions for populating `ProxyMapper` and the path to `InUseOtherUser` (appears Windows-only).
- ACME. JWS, nonce, and polling interval details in `tempfork/acme`, and Let's Encrypt rate limits.
- The inbound path's failure to find a listener registered with tsnet `Listen("")` (empty network) is a code observation (`tsnet.go:2117`, `:1238-1266`).

### 8.2 First Adopter Requirements Still Missing from the Plan and Contracts

- State file protection class, backup exclusion, App Group path, and rejection of duplicate starts with the same state directory (§4.4.3).
- Settings event rules. Skip emission with no addresses or unchanged settings, emit even for DNS-only changes, and keep only the latest entry in the queue (RemoteDebug `core/internal/tunnel/settings.go:125-142`, `core/internal/node/node.go:396-407`).
- Engine exit (TUN read error) → error state, retained until stop (`docs/tunnel.md:162`).
- utun fd handling. dup, close-on-exec, non-blocking, verify `utun*` with `UTUN_OPT_IFNAME`, leave caller fd open (`core/internal/tunnel/utun_darwin.go:16-60`). MTU 1280~1420 (default 1280) and reported mtu in state (`docs/tunnel.md` tests 10 and 11).
- `setDefaultInterface` name validation and immediate reevaluation (§4.6.1).
- Repeat interactive login requests every 30 seconds in `NeedsLogin` when URL and auth key are absent (§4.5).
- Values exposed in state: `CertDomains`, local FQDN, and local `StableID` (pairing is tied to `StableID`, `docs/tunnel.md:28`).

### 8.3 Factual Correction Tally

Repeated instances of the same error counted once. The tally excludes changes only to origin line references (12) and newly filled sections.

| # | Corrected claim | Verification origin |
| --- | --- | --- |
| 1 | Service IP ICMP echo handling unverified → tstun wrapper injects an echo reply | `tailscale.com/net/tstun/wrap.go:752-769` |
| 2 | Implementing mode B alone gives the same behavior as mode A → Mode B makes quad-100 primary resolver for all names, requiring upstream forwarding and OS default resolvers. Empty default resolvers leave OS settings intact | `manager.go:463-525`, `:207-214` |
| 3 | Local replies never exceed 512 bytes → Without compression, about 1,066 bytes are theoretically possible. Tailnet zones stay within 512 | `tsdns.go:1213-1218`, `:1177-1199` |
| 4 | An existing name is known even when its addresses are empty → A node without any addresses has an unknown name | `node_backend.go:1205-1207` |
| 5 | Every FORMERR omits the question → FORMERR for invalid FQDN includes the question | `tsdns.go:1222`, `:1461-1468` |
| 6 | RA is 1 only when RD is 1 → If RD is 0, RA retains the query value (whole header copied) | `tsdns.go:1009-1011`, `:1206-1208` |
| 7 | `RouteAll` absent from `NewPrefs()` defaults → iOS defaults to `RouteAll=true` | `ipn/prefs.go:756`, `:787-799` |
| 8 | Both `InjectEvent` and `Poll` recompute immediately → Only `InjectEvent` forces notification even if state is equal | `netmon.go:544-570`, `:640-648` |
| 9 | Accepted connection handed off after handshake completion → Handed off after merely starting the handshake | `netstack.go:1666-1720` |
| 10 | iOS maximum buffer is left without reducing it → gVisor's maximum (4MiB) is smaller than on other platforms and is left without increasing it | `gvisor/pkg/tcpip/transport/tcp/protocol.go:52`, `netstack_tcpbuf_ios.go:13-16` |
| 11 | Certificate renewal loop does not run in tsnet → Runs with `ListenService` (Web or `TerminateTLS`) | `feature/acme/refresh.go:36`, `:134-155`, `tsnet.go:2007-2039` |
| 12 | Certificates always in `<varRoot>/certs/` → Non-file stores in Kubernetes use state store keys | `feature/acme/certstore.go:83-104`, `:247-261` |
| 13 | WhoIs skips ProxyMapper for port 0 → Fails. Missing netmap also fails | `local.go:1773-1802` |
| 14 | `Server.Tun` path accepts only `tcp4`/`tcp6` → tsnet rewrites `tcp` and the empty value | `tsnet.go:2160-2180` |
| 15 | Certificate local API build tag `!ios && !android` → `!ios && !android && !js && !ts_omit_acme`. iOS Go tsnet `ListenTLS` cannot obtain a certificate | `ipn/localapi/cert.go:4`, `tsnet/maybe_acme.go:4` |
| 16 | One asynchronous renewal at a time → One per domain. BYO Funnel domains pass even with empty `CertDomains` | `feature/acme/cert.go:212-221`, `:700`, `:723-725` |
