// The `computedName` rules were ported from the Go implementation. Origin: tailscale.com v1.104.6 `tailcfg/tailcfg.go`
// (`Node.InitDisplayNames`), `util/dnsname/dnsname.go` (`HasSuffix`),
// `TrimSuffix`, `TrimCommonSuffixes`, `SanitizeHostname`, `SanitizeLabel`), `types/netmap/netmap.go`
// (`MagicDNSSuffixOfNodeName`), `ipn/ipnlocal/local.go`(`WhoIs`), `ipn/ipnlocal/node_backend.go`(`updateNodeByAddrLocked`).
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import Foundation
import SwiftailBase
import SwiftailControl
import SwiftailEngine

/// The identity of one tailnet node, supplied by the control server in the netmap.
public struct PeerIdentity: Sendable, Equatable {
    /// The node's stable ID (`tailcfg.Node.StableID`). Nonempty. Use as an allowlist key.
    public var stableID: String
    /// The MagicDNS name with its trailing dot removed (`rd-phone-1a2b3c4d.tail0001.ts.net`). An empty string if there is no name.
    public var name: String
    /// The display name. Follows Go `Node.ComputedName` (behavior W4). Removes the local tailnet suffix only when it
    /// matches at a label boundary, and strips the trailing dot (`rd-phone-1a2b3c4d`). A node shared from another
    /// tailnet has a different suffix, so keeps the FQDN without its trailing dot. Falls back to the sanitized hostname
    /// if empty, and to the node public key text (`nodekey:` + hex) if that is also empty.
    public var computedName: String
    /// The login name of the user who created the node (`alice@example.com`). For display. On tagged nodes it does not identify a person.
    public var loginName: String

    /// Creates an identity from supplied values. The node creates identities from the netmap and does not use this
    /// initializer. Use it to test consumers of this type without a node.
    public init(stableID: String, name: String, computedName: String, loginName: String) {
        self.stableID = stableID
        self.name = name
        self.computedName = computedName
        self.loginName = loginName
    }
}

// MARK: Lookup by Address (Behaviors W1~W3)

extension PeerIdentity {
    /// The identity of the node that owns `address` in the data plane. Returns nil when absent.
    ///
    /// A peer address belongs to the peer whose AllowedIPs the engine assigned it to (`owners`,
    /// `EnginePeer.addressOwners`). Only that peer can send packets from the address, so the result for a connection's
    /// remote address identifies that connection's peer. Returns nil for addresses of nodes absent from the data plane
    /// (expired keys, unsupported peers) and uses the engine's choice (lower node ID) when multiple nodes have the same
    /// address. Skips addresses in subnet routes. Go's `WhoIs` selects the last entry in the netmap `Addresses` table,
    /// but for overlapping addresses that table can point to a different node than the data plane.
    ///
    /// A single-address entry in the local node's `Addresses` identifies the local node. If a data plane peer also has
    /// that address, returns nil (fails closed) because the origin of a connection from the address is ambiguous.
    /// Converts an IPv4-mapped IPv6 address to IPv4 before lookup. The data plane does not accept mapped peer
    /// addresses. Returns nil if the matched node's `StableID` is empty or its user profile is absent from the netmap.
    ///
    /// - Parameters: - owners: Maps data plane addresses to their owner nodes. The node replaces this table alongside
    ///   the engine peers (`TailnetNode.addressOwners`). - netmap: The netmap from which to read the local node, user
    ///   profiles, and the local tailnet suffix.
    init?(address: IPAddress, owners: [IPAddress: Node], in netmap: Netmap) {
        let address = address.unmappedIPv4
        let peer = owners[address]
        let isLocal = netmap.selfNode.hasSingleAddress(address)
        guard let node = isLocal ? (peer == nil ? netmap.selfNode : nil) : peer,
            !node.stableID.isEmpty, let profile = netmap.userProfiles[node.user]
        else { return nil }
        stableID = node.stableID
        name = node.name.hasSuffix(".") ? String(node.name.dropLast()) : node.name
        computedName = Self.computedName(
            nodeName: node.name,
            hostname: node.hostinfo.hostname,
            key: node.key,
            magicDNSSuffix: Netmap.magicDNSSuffix(ofNodeName: netmap.selfNode.name)
        )
        loginName = profile.loginName
    }
}

private extension Node {
    /// Returns whether `Addresses` contains a single-address prefix (/32 or /128) for `address`. Go `IsSingleIP`.
    func hasSingleAddress(_ address: IPAddress) -> Bool {
        addresses.contains { $0.address == address && $0.length == address.bytes.count * 8 }
    }
}

private extension IPAddress {
    /// Converts IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to IPv4 and returns other addresses unchanged. Go `Addr.Unmap`.
    var unmappedIPv4: IPAddress {
        let mappedPrefix: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF]
        guard bytes.count == 16, bytes.starts(with: mappedPrefix) else { return self }
        return IPAddress(bytes: bytes.dropFirst(12)) ?? self
    }
}

// MARK: Display Name (Behavior W4)

extension PeerIdentity {
    /// `ComputedName` from Go `Node.InitDisplayNames`.
    ///
    /// Removes `magicDNSSuffix` from the node name. Removes the suffix only if it matches at a label boundary, so names
    /// from other tailnets stay fully qualified (with the trailing dot removed). If the result is empty, uses the
    /// sanitized `hostname`, or the node public key text if that too is empty.
    ///
    /// - Parameters: - nodeName: netmap `Node.name`. - hostname: `Hostinfo.hostname` reported by the node. - key: The
    ///   node's public key. - magicDNSSuffix: The local tailnet suffix (`Netmap.magicDNSSuffix(ofNodeName:)`).
    static func computedName(nodeName: String, hostname: String, key: NodePublicKey, magicDNSSuffix: String) -> String {
        let name = trimmingSuffix(magicDNSSuffix, from: nodeName)
        guard name.isEmpty else { return name }
        let host = sanitizedHostname(hostname)
        return host.isEmpty ? key.description : host
    }

    /// Go `dnsname.TrimSuffix`: Removes the suffix only when `name` ends in `.suffix` (a label boundary), then removes one trailing dot.
    private static func trimmingSuffix(_ suffix: String, from name: String) -> String {
        var name = name
        if hasSuffix(suffix, in: name) {
            name = name.removingSuffix(".")
            name = name.removingSuffix(suffix.trimmingDots)
        }
        return name.removingSuffix(".")
    }

    /// Go `dnsname.HasSuffix`: Ignores one trailing dot and one leading and trailing dot on the suffix, then checks
    /// whether `name` ends in `<label>.<suffix>`. Returns false if the suffix is empty or the name consists only of the
    /// suffix.
    private static func hasSuffix(_ suffix: String, in name: String) -> Bool {
        let name = name.removingSuffix(".")
        let suffix = String(suffix.removingSuffix(".").removingPrefix("."))
        let base = name.removingSuffix(suffix)
        return base.count < name.count && base.hasSuffix(".")
    }

    /// Go `dnsname.SanitizeHostname`: Removes `.local`, `.localdomain`, and `.lan` once each in that order and
    /// sanitizes the result as a DNS label.
    private static func sanitizedHostname(_ hostname: String) -> String {
        let trimmed = hostname.removingSuffix(".local").removingSuffix(".localdomain").removingSuffix(".lan")
        return sanitizedLabel(trimmed)
    }

    /// Go `dnsname.SanitizeLabel` (RFC 1035). Works byte by byte. Truncates to 63 bytes, drops leading and trailing
    /// non-alphanumeric bytes, replaces internal separators (spaces, `.`, `@`, and `_`) with `-`, drops bytes other
    /// than alphanumerics and `-`, and lowercases uppercase letters.
    private static func sanitizedLabel(_ label: String) -> String {
        let bytes = Array(label.utf8)
        var start = 0
        var end = min(bytes.count, 63)
        while start < end, !bytes[start].isASCIIAlphanumeric { start += 1 }
        while start < end, !bytes[end - 1].isASCIIAlphanumeric { end -= 1 }

        let separators = Set(" .@_".utf8)
        var result: [UInt8] = []
        for index in start..<end {
            let byte = bytes[index]
            let isBoundary = index == start || index == end - 1
            if !isBoundary, separators.contains(byte) {
                result.append(UInt8(ascii: "-"))
            } else if byte.isASCIIAlphanumeric || byte == UInt8(ascii: "-") {
                result.append(byte.isASCIIUppercase ? byte + 32 : byte)
            }
        }
        return String(decoding: result, as: UTF8.self)
    }
}

private extension String {
    /// The string with `suffix` removed if it ends with it. Go `strings.TrimSuffix`.
    func removingSuffix(_ suffix: String) -> String {
        hasSuffix(suffix) ? String(dropLast(suffix.count)) : self
    }

    /// The string with `prefix` removed if it starts with it. Go `strings.TrimPrefix`.
    func removingPrefix(_ prefix: String) -> Substring {
        hasPrefix(prefix) ? dropFirst(prefix.count) : self[...]
    }
}

private extension UInt8 {
    var isASCIIUppercase: Bool { (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains(self) }

    var isASCIIAlphanumeric: Bool {
        isASCIIUppercase || (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(self)
            || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(self)
    }
}
