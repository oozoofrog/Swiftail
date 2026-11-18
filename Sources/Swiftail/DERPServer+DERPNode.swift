// Dial target selection and certificate verification follow `shouldDialProto`, `dialNode`, and `tlsClient` in
// tailscale.com v1.104.7 `derp/derphttp/derphttp_client.go`
// (Copyright (c) Tailscale Inc & AUTHORS, BSD-3-Clause).

import SwiftailBase
import SwiftailControl
import SwiftailDERP

/// Converts tailcfg DERP nodes to servers for `DERPClient` to connect to. The node uses this when opening a region connection.
///
/// Contract `docs/contracts/SwiftailEngine.md` node API behavior 3, `docs/protocol-notes/derp-stun.md` §4.1.
extension DERPServer {
    /// Connectable servers among the region's nodes, in DERPMap order. Returns an empty list if the region is absent or has no usable nodes.
    static func servers(of region: DERPRegion?) -> [DERPServer] {
        region?.nodes.compactMap(DERPServer.init) ?? []
    }

    /// Converts one tailcfg DERP node to a server to connect to. Returns nil if the node cannot be used.
    ///
    /// - Skips `stunOnly` nodes, empty `hostName` values, and out-of-range `derpPort` values.
    /// - Dial target (Go `shouldDialProto`). For each of `ipv4` and `ipv6`, use `hostName` if empty or the address if
    ///   it is an IP literal in that field's family. Other values (conventionally `"none"`, an address of the other
    ///   family, or garbage) disable dialing in that family. If both fields give `hostName`, use `hostName` as the only
    ///   target. The Network framework resolves the name and tries both families itself. Returns nil if there is no
    ///   dial target.
    /// - Port. A `derpPort` of 0 means 443.
    /// - Certificate (same order as Go `tlsClient`). If `certName` starts with `sha256-raw:`, passes the rest unchanged
    ///   to `.pinned`. A nonempty `certName` different from `hostName` uses `.named(certName)`. Otherwise, uses
    ///   `.noneForTests` if `insecureForTests` is set, or `.system`. The first two take precedence over
    ///   `insecureForTests`. Go also reinstalls a verification hook when `CertName` is set.
    // shortcut: Go resolves a blank field only in its family (`tcp4` or `tcp6`). Here, dialing `hostName` is
    // family-independent, so a blank field and `"none"` in the other can still result in dialing the disabled family.
    // Revisit when using a DERPMap that intentionally disables one family.
    init?(_ node: DERPNode) {
        guard !node.stunOnly, !node.hostName.isEmpty else { return nil }
        guard let port = node.derpPort == 0 ? 443 : UInt16(exactly: node.derpPort) else { return nil }
        var targets: [Target] = []
        for target in [Self.target(node.ipv4, isIPv4: true), Self.target(node.ipv6, isIPv4: false)] {
            if let target, !targets.contains(target) { targets.append(target) }
        }
        guard !targets.isEmpty else { return nil }
        self.init(
            hostName: node.hostName,
            targets: targets,
            port: port,
            verification: Self.verification(of: node)
        )
    }

    /// Certificate verification implied by the node's `certName` and `insecureForTests` (`tlsClient` in Go `derphttp_client.go`).
    private static func verification(of node: DERPNode) -> Verification {
        if node.certName.hasPrefix(pinnedPrefix) {
            return .pinned(sha256Hex: String(node.certName.dropFirst(pinnedPrefix.count)))
        }
        if !node.certName.isEmpty, node.certName != node.hostName { return .named(node.certName) }
        return node.insecureForTests ? .noneForTests : .system
    }

    /// The certificate pin prefix in `certName` (`"sha256-raw:"` in Go `tlsClient`).
    private static let pinnedPrefix = "sha256-raw:"

    /// The target indicated by one `IPv4` or `IPv6` field of `DERPNode`. Returns nil if this family should not be dialed.
    private static func target(_ text: String, isIPv4: Bool) -> Target? {
        if text.isEmpty { return .hostName }
        guard let address = IPAddress(text), address.isIPv4 == isIPv4 else { return nil }
        return .address(address)
    }
}
