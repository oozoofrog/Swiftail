// The name resolution rules were ported from the Go implementation. Origin: tailscale.com v1.104.6
// `net/tsdial/tsdial.go` (`resolveAddr`), `net/tsdial/dnsmap.go` (`canonMapKey`),
// `ipn/ipnlocal/node_backend.go`(`addNodeNameLocked`, `updateNodeByNameLocked`), `ipn/ipnlocal/resolve.go`
// (`resolveMagicDNS`, `nodeAddrForNetwork`), `types/netmap/netmap.go`(`MagicDNSSuffixOfNodeName`),
// `util/dnsname/dnsname.go`(`HasSuffix`, `TrimSuffix`).
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import SwiftailBase
import SwiftailControl

extension Netmap {
    /// Resolves the `host` in `connect(to:port:)` to an address (contract `docs/contracts/SwiftailNetstack.md` behavior
    /// A2 ②, TCP notes §6.3 item 2).
    ///
    /// Returns an IP address as is. Otherwise lowercases the name, removes one trailing dot, and looks it up among the
    /// local node and peers, matching their FQDN or short name with the MagicDNS suffix removed (the part of the local
    /// name after its first label). On a duplicate name, the later entry wins, as in Go's table. Processes the local
    /// node first, followed by peers in node ID order. Prefers an IPv4 address of the matched node and falls back to
    /// IPv6. Skips `ExtraRecords` and names outside the tailnet (system DNS), per the contract exclusions table.
    ///
    /// - Returns: Nil if no node matched or if that node has no address.
    func address(ofHost host: String) -> IPAddress? {
        if let address = IPAddress(host) { return address }
        let wanted = Self.canonicalName(host)
        guard !wanted.isEmpty else { return nil }
        let suffix = Self.magicDNSSuffix(ofNodeName: selfNode.name)

        var match: Node?
        for node in [selfNode] + peers.sorted(by: { $0.id < $1.id }) where !node.name.isEmpty {
            let name = Self.canonicalName(node.name)
            if name == wanted || Self.trimmingSuffix(suffix, from: name) == wanted {
                match = node
            }
        }
        guard let addresses = match?.addresses.map(\.address) else { return nil }
        return addresses.first(where: \.isIPv4) ?? addresses.first
    }

    /// Go `canonMapKey`: Removes one trailing dot and lowercases the name.
    private static func canonicalName(_ name: String) -> String {
        (name.hasSuffix(".") ? String(name.dropLast()) : name).lowercased()
    }

    /// Go `MagicDNSSuffixOfNodeName`: Removes leading and trailing dots and takes everything after the first label.
    /// Returns the name unchanged if there is no dot.
    static func magicDNSSuffix(ofNodeName name: String) -> String {
        let trimmed = name.trimmingDots
        guard let dot = trimmed.firstIndex(of: ".") else { return trimmed }
        return String(trimmed[trimmed.index(after: dot)...])
    }

    /// Go `dnsname.TrimSuffix`: Returns the short name after trimming `.suffix` from the end of `name`. Otherwise
    /// returns nil because there is no short name.
    private static func trimmingSuffix(_ suffix: String, from name: String) -> String? {
        let suffix = suffix.trimmingDots
        guard !suffix.isEmpty, name.hasSuffix("." + suffix) else { return nil }
        let short = name.dropLast(suffix.count + 1)
        return short.isEmpty ? nil : String(short)
    }
}

extension String {
    /// Removes all leading and trailing dots (Go `strings.Trim(s, ".")`).
    var trimmingDots: String {
        String(drop(while: { $0 == "." }).reversed().drop(while: { $0 == "." }).reversed())
    }
}
