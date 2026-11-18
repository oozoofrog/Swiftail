# Protocol notes

These notes document each protocol to the level needed to implement Swiftail. Verify each detail against the source before recording it. Do not rely on recollection.

## Reference sources

| Module | Version | License |
| --- | --- | --- |
| `tailscale.com` | v1.104.6 (CapabilityVersion 148) | BSD-3-Clause |
| `github.com/tailscale/wireguard-go` | v0.0.0-20261106233718-9e0ab45c16ca | MIT |
| `gvisor.dev/gvisor` (version pinned by `tailscale.com/go.mod`) | v0.0.0-20260915211658-a6f909f08a72 | Apache-2.0 |

`Scripts/fetch-reference-sources.sh` downloads the sources and prints their root paths. The script skips gVisor. Building the test tools with `sh Scripts/build-interop-tools.sh` adds gVisor to the same module cache (`gvisor.dev/gvisor@<version>`). The notes cite source locations as module-relative paths with line numbers (e.g., `tailscale.com/control/controlbase/handshake.go:120`, `wireguard-go/device/noise-protocol.go:60`).

## Notes and verification status

Verification means checking the notes against the Go sources in a session other than the one that wrote them. Complete verification before starting the corresponding milestone.

| Note | Milestones that use it | Author | Verification |
| --- | --- | --- | --- |
| [wireguard.md](wireguard.md) | M1 | Claude Opus 5.5 | GPT-6.1 Sol, 2026-11-14, 31 corrections |
| [control-transport.md](control-transport.md) | M2 | Claude Opus 5.5 | GPT-6.1 Sol, 2026-11-14, 28 corrections |
| [control-map.md](control-map.md) | M2 | GPT-6.1 Sol | Claude Opus 5.5, 2026-11-14, 16 corrections |
| [derp-stun.md](derp-stun.md) | M3 | GPT-6.1 Terra | Claude Opus 5.5, 2026-11-14, 13 corrections + missing procedures added |
| [disco-magicsock.md](disco-magicsock.md) | M4 | GPT-6.1 Sol | Claude Opus 5.5, 2026-11-15, 7 corrections + M4 procedures expanded |
| [netmap-engine.md](netmap-engine.md) | M3 and M5 | Claude Sonnet 5.5 | GPT-6.1 Sol, 2026-11-14, 10 corrections + M3 procedures expanded |
| [dns-state-node.md](dns-state-node.md) | M5–M7 | Claude Sonnet 5.5 | Claude Opus 5.5, 2026-11-15, 16 corrections + M5 procedures expanded |
| [tcp-netstack.md](tcp-netstack.md) | M6 | Claude Fable 5.2 | GPT-6.1 Sol, 2026-11-15, checked against 12 RFCs, Tailscale v1.104.6, and gVisor a6f909f08a72, corrected factual errors and added details on unverified paths |
| [whois-certs-state.md](whois-certs-state.md) | M7 | Claude Fable 5.2 | Verified (2026-11-15, GPT-6.1 Sol) against Tailscale v1.104.6, 20 original RFCs from the RFC Editor, official Let's Encrypt documentation, the PSL, Go 1.27.3, and the Apple SDK. Assessed 248 claims (208 correct, 18 incorrect, 22 unverifiable) |
| [tailnet-lock.md](tailnet-lock.md) | M8 | Claude Opus 5.5 | Verified (2026-11-15, a different Claude Opus 5.5 session) against Tailscale v1.104.7 (ran v1.104.6), fxamacker/cbor v2.9.3, ed25519consensus v0.2.0, x/crypto v0.58.0, and Go 1.27.3. Assessed 256 claims as correct, 11 as incorrect, and 4 as unverifiable, made 11 corrections, and added details on 12 missing paths |

## Note format

1. Introduction with the reference version, authoring model, and verification status.
2. Scope, including what the note covers and excludes.
3. Wire format with a byte-level table per message (offset, length, field, encoding and endianness).
4. Procedures and state machines in numbered steps. Specify the exact inputs and outputs of cryptographic operations.
5. Constants and timers, with a table of values and their sources.
6. The minimum Swiftail needs and what it can omit, including the rationale for omissions.
7. What to verify in interop tests.
8. Unverified details.

Cite a source for every factual sentence (`path:line`). Do not transcribe Go code. Quote only constant values and short expressions.
