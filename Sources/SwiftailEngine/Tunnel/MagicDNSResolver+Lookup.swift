// Name indexing follows Tailscale's `ipn/ipnlocal/node_backend.go` (`addNodeNameLocked`, `nodeByFQDNLocked`, `magicDNSAddrs`,
// `magicDNSPTR`, and `ExtraRecords` in `dnsConfigForNetmap`) and `MagicDNSSuffixOfNodeName` in `types/netmap/netmap.go`
// (BSD-3-Clause, Copyright (c) Tailscale Inc & contributors). Only the rules were ported. The code was written from scratch in Swift.

import SwiftailBase
import SwiftailControl

/// Looks up names ↔ addresses, using the `ExtraRecords` host table first, then netmap nodes (self and peers). Notes 4.2.1.
extension MagicDNSResolver {
    /// One name from `ExtraRecords` and its addresses.
    struct HostRecord: Sendable {
        /// The lowercase name used for comparisons.
        let key: DNSMessage.Name
        /// The name used in PTR answers, with the received casing.
        let name: DNSMessage.Name
        /// Addresses in receive order. Concatenates addresses from records with the same name.
        var addresses: [IPAddress]
    }

    /// A local node attribute that enables AAAA answers for peers that also have IPv4 addresses (Go `nodecap.MagicDNSPeerAAAA`).
    static let peerAAAACapability = "magicdns-aaaa"

    /// Adds only records with `Type` `""`, `A`, or `AAAA` and an IP address value to the host table. Drops entries whose names are invalid.
    static func hostRecords(from records: [DNSRecord]) -> [HostRecord] {
        var hosts: [HostRecord] = []
        for record in records where ["", "A", "AAAA"].contains(record.type) {
            guard let address = IPAddress(record.value), let name = DNSMessage.Name(record.name) else { continue }
            let key = name.lowercased()
            if let index = hosts.firstIndex(where: { $0.key == key }) {
                hosts[index].addresses.append(address)
            } else {
                hosts.append(HostRecord(key: key, name: name, addresses: [address]))
            }
        }
        return hosts
    }

    /// The addresses for a lowercase name. Nil means unknown, and an empty array means the name exists but has no address to answer with.
    func addresses(for name: DNSMessage.Name) -> [IPAddress]? {
        if let host = hosts.first(where: { $0.key == name }) {
            return host.addresses
        }
        guard let netmap, let node = node(named: name, in: netmap), !node.addresses.isEmpty else { return nil }
        return Self.answerAddresses(of: node, in: netmap)
    }

    /// The name for an address (the PTR target). Checks the service IP, then the host table, then nodes' own addresses (single-address prefixes).
    func name(for address: IPAddress) -> DNSMessage.Name? {
        if ServiceIP.contains(address) {
            return Self.symbolicName
        }
        if let host = hosts.first(where: { $0.addresses.contains(address) }) {
            return host.name
        }
        guard let netmap else { return nil }
        let owns = { (node: Node) in
            node.addresses.contains { $0.address == address && $0.length == $0.address.bytes.count * 8 }
        }
        // The Go index is filled with self first and then peers, with later entries overwriting earlier ones, so search from the end.
        guard let node = netmap.peers.last(where: owns) ?? (owns(netmap.selfNode) ? netmap.selfNode : nil) else { return nil }
        return DNSMessage.Name(node.name)
    }

    /// The node the name identifies (Go `nodeByFQDNLocked`).
    ///
    /// Each node is indexed by its lowercase `Name` without the trailing dot, and also by its short name if the full name ends in the MagicDNS suffix.
    /// If `Proxied` (MagicDNS) is disabled, skips names without a dot. When multiple nodes share a key, the later peer in the list wins
    /// as in Go's index. A node with an empty `Name` is excluded (Go `addNodeNameLocked`). Including it would cause a query for the root name `.`
    /// to be answered with that node's address.
    private func node(named name: DNSMessage.Name, in netmap: Netmap) -> Node? {
        guard netmap.dnsConfig?.proxied == true || name.labels.count > 1 else { return nil }
        let dot = UInt8(ascii: ".")
        let key = Array(name.labels.joined(separator: [dot]))
        let suffix = Self.magicDNSSuffix(of: netmap.selfNode.name)
        // A node whose short-name key is `key` has the canonical key `key.suffix`.
        let qualifiedKey = suffix.isEmpty ? nil : key + [dot] + suffix
        let matches = { (node: Node) -> Bool in
            guard !node.name.isEmpty else { return false }
            let canonical = Self.canonicalKey(of: node.name)
            if canonical.elementsEqual(key) { return true }
            guard let qualifiedKey else { return false }
            return canonical.elementsEqual(qualifiedKey)
        }
        return netmap.peers.last(where: matches) ?? (matches(netmap.selfNode) ? netmap.selfNode : nil)
    }

    /// The addresses to answer with (Go `magicDNSAddrs`, decision D7). If the local node is IPv6-only, uses only the target's IPv6 addresses. Otherwise uses all target addresses,
    /// except that it omits IPv6 when the target has IPv4 and the local node lacks `magicdns-aaaa` (because the peer is not guaranteed to handle IPv6 properly).
    private static func answerAddresses(of node: Node, in netmap: Netmap) -> [IPAddress] {
        let selfAddresses = netmap.selfNode.addresses
        let selfIPv6Only = !selfAddresses.contains { $0.address.isIPv4 } && selfAddresses.contains { !$0.address.isIPv4 }
        let wantsAAAA = netmap.selfNode.capMap[peerAAAACapability] != nil
        let targetHasIPv4 = node.addresses.contains { $0.address.isIPv4 }
        return node.addresses.map(\.address).filter { address in
            selfIPv6Only ? !address.isIPv4 : address.isIPv4 || !targetHasIPv4 || wantsAAAA
        }
    }

    /// The node name comparison key, with one trailing dot removed and ASCII lowercased (Go `strings.ToLower(strings.TrimSuffix(name, "."))`).
    private static func canonicalKey(of name: String) -> some Collection<UInt8> {
        name.utf8.dropLast(name.utf8.last == UInt8(ascii: ".") ? 1 : 0).lazy.map(DNSMessage.Name.lowercased)
    }

    /// The MagicDNS suffix (lowercase, without leading or trailing dots) is the local node name with its leading and trailing dots and first label removed.
    /// If there is no dot, uses the entire name (Go `MagicDNSSuffixOfNodeName`).
    private static func magicDNSSuffix(of selfName: String) -> [UInt8] {
        let dot = UInt8(ascii: ".")
        var bytes = Array(selfName.utf8.map(DNSMessage.Name.lowercased))
        while bytes.first == dot { bytes.removeFirst() }
        while bytes.last == dot { bytes.removeLast() }
        guard let firstDot = bytes.firstIndex(of: dot) else { return bytes }
        return Array(bytes[(firstDot + 1)...])
    }
}
