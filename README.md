# Swiftail

[![CI](https://github.com/oozoofrog/Swiftail/actions/workflows/ci.yml/badge.svg)](https://github.com/oozoofrog/Swiftail/actions/workflows/ci.yml)
[![Swift versions](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2Foozoofrog%2FSwiftail%2Fbadge%3Ftype%3Dswift-versions)](https://swiftpackageindex.com/oozoofrog/Swiftail)
[![Platforms](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2Foozoofrog%2FSwiftail%2Fbadge%3Ftype%3Dplatforms)](https://swiftpackageindex.com/oozoofrog/Swiftail)
[![License: BSD-3-Clause](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)

A Tailscale tailnet node written entirely in Swift. Swiftail lets an app join a tailnet in-process, or power an iOS Network Extension packet tunnel, without embedding the Go client.

> **Status: pre-1.0.** It registers with the production Tailscale control plane and exchanges traffic with stock Tailscale nodes. The public API may still change.
>
> Swiftail is an independent project. It is not made, endorsed, or supported by Tailscale Inc.

## What it does

| Area | Implemented |
| --- | --- |
| Control plane | HTTP/2 over the Noise (ts2021) transport, registration (auth key, interactive login), streaming netmaps, logout |
| Data plane | WireGuard (Noise IK, cookies, rekey), packet filter from tailnet policy, MagicDNS responder |
| Connectivity | DERP relays, STUN, disco path discovery, direct UDP paths with fallback and upgrade |
| Sockets | A TCP stack written in Swift: `listen` and `connect` on tailnet addresses inside the process |
| Tunnel | A `utun` device mode for iOS/macOS packet tunnel extensions |
| Identity | `whoIs` (tailnet address → node and user), Tailnet Lock signature verification |
| TLS | `ts.net` certificate issuance and renewal (ACME DNS-01), loopback bridge to an OS TLS listener |
| Pairing | App-to-app pairing by QR code or link, with one-time auth key issuance |

Not implemented: subnet routers, exit nodes, Taildrop, Tailscale SSH, Funnel, Serve.

## Requirements

- Swift 6 (language mode 6, strict concurrency)
- iOS 18+ or macOS 15+
- No third-party packages and no C code. Core targets use CryptoKit, Network, and Foundation. Optional products add Security (certificates) and CoreImage (QR codes).

## Installation

Swiftail is pre-1.0. Minor releases may break API compatibility. Patch releases preserve it. Add the package to `Package.swift` with an up-to-next-minor requirement to receive patch updates.

```swift
dependencies: [
    .package(url: "https://github.com/oozoofrog/Swiftail.git", .upToNextMinor(from: "0.1.2"))
]
```

| Product | Use it for |
| --- | --- |
| `Swiftail` | The node: `TailnetNode`, connections, status, events |
| `SwiftailBase` | Shared value types such as `IPAddress` and `IPEndpoint` |
| `SwiftailPairing` | QR/link pairing between two apps, auth key issuance |
| `SwiftailCertificates` | `ts.net` TLS certificates |
| `SwiftailLoopback` | Bridging tailnet connections to a `127.0.0.1` listener |

The remaining products (`SwiftailControl`, `SwiftailWireGuard`, `SwiftailDERP`, and others) are building blocks. Most apps do not import them directly.

## Quick start

An in-process node that accepts TCP connections on its tailnet address:

```swift
import Swiftail

let configuration = NodeConfiguration(
    stateDirectory: stateDirectoryURL,   // must not be writable by other users
    hostname: "my-app",
    authKey: authKey                     // omit to use a stored identity or interactive login
)
let node = try TailnetNode(configuration: configuration, device: .inProcess)

// run() returns when its task is cancelled.
let running = Task { try await node.run() }

// Follow state changes. `.needsLogin(url)` carries the login URL.
Task {
    for await event in node.events {
        if case .stateChanged(let state) = event { print(state) }
    }
}

let listener = try await node.listen(port: 8080)
for await connection in listener {
    Task {
        let peer = await node.whoIs(connection.remoteEndpoint.address)
        while let bytes = try await connection.read() {
            try await connection.write(bytes)
        }
    }
}
```

To dial a peer: `try await node.connect(to: "peer-name", port: 8080)`.

A complete app for macOS and iOS, including QR pairing, is in [`Examples/PairingDemo`](Examples/PairingDemo/).

## Repository layout

| Path | Contents |
| --- | --- |
| `Sources/` | Library targets. Protocol logic is value-type state machines; actors at the edge own sockets and clocks |
| `Tests/` | Unit tests (swift-testing) and interoperability tests against Go peers |
| `Examples/PairingDemo/` | Sample app for macOS and iOS (XcodeGen project) |
| `Tools/` | Go test tools: a test control server, DERP, and vector generators. Not part of the library |
| `docs/plan.md` | Scope, decisions, milestones, and gates |
| `docs/contracts/` | Per-module contracts: API, behavior, limits, tests, and review records |
| `docs/protocol-notes/` | Protocol notes verified against the Tailscale source |
| `AGENTS.md` | Working rules for contributors and coding agents |

Design documents, contracts, and source comments are written in English. Identifiers and protocol terms are in English. Korean reference copies of the README, security policy, and release guide are in [`docs/ko/`](docs/ko/).

## Testing

```sh
swift test
```

Interoperability tests need Go 1.27.3 or later and skip themselves when their tool path is not set.

```sh
SWIFTAIL_TAILNET="$(sh Scripts/build-interop-tools.sh tailnet)" \
SWIFTAIL_WGPEER="$(sh Scripts/build-interop-tools.sh)" \
SWIFTAIL_AUTHKEYRECORDER="$(sh Scripts/build-interop-tools.sh authkeyrecorder)" \
swift test --filter "SwiftailInteropTests|SwiftailWireGuardInteropTests|SwiftailDERPInteropTests"
```

These run a local test control server, DERP relay, and Go tsnet peers. They take several minutes of wall-clock time and never contact production servers.

## Security

See the [security policy](SECURITY.md) for how to report a suspected vulnerability privately.

Swiftail has **not** been audited by independent human security experts.

- **AI-assisted review (2026-11-17).** The full source was reviewed with Claude Mythos 5.2 across three scopes: the app-facing layer (pairing, loopback bridge, certificates, state files), cryptography and authenticated channels (WireGuard, control protocol, Tailnet Lock), and the data plane (path discovery, DERP, TCP stack, packet filter, DNS). Suspected issues were reproduced with tests. The review found no critical or high-severity issues, 3 medium, and 11 low. All were fixed, and the fixes were re-reviewed twice with the same model. Accepted limitations are recorded in the contracts under `docs/contracts/`.
- **This review is not a guarantee.** It does not replace an independent audit.
- **Hand-written cryptography.** Some primitives are implemented in Swift (BLAKE2s, BLAKE2b, XSalsa20-Poly1305, Argon2i, Ed25519 verification) and validated with published test vectors and cross-vectors from Go. Key material is not zeroed on release.
- **Unofficial protocol.** The Tailscale control protocol is not a public contract. A server-side change can break this library.
- For environments that need assurance, use the official Tailscale client.

## For coding agents

- Read [`AGENTS.md`](AGENTS.md) before changing anything. It defines language, concurrency, dependency, privacy, and build rules.
- Each module's contract in `docs/contracts/` is the source of truth for behavior and limits. Change the contract together with the code.
- Do not rely on memory for protocol details. Check `docs/protocol-notes/` or the Tailscale source fetched by `Scripts/fetch-reference-sources.sh`.
- Never commit keys, auth keys, real tailnet or device names, personal names, email addresses, or local paths. Use placeholders such as `tail0001`, `rd-mac-1a2b3c4d`, and `100.64.0.1`.
- A change is done when it has unit tests, passes the interoperability tests it touches, and builds with zero warnings.

## License

BSD-3-Clause. See [`LICENSE`](LICENSE). Files adapted from other projects carry their origin and license in the file header; the full texts are in [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md).

Tailscale and WireGuard are trademarks of their respective owners.
