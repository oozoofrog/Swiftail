import SwiftailBase
import Testing
@testable import Swiftail

/// `PeerIdentity.computedName` follows the Go `Node.InitDisplayNames` rules (behavior W4, notes 4.1 5).
/// Expected values are the `ComputedName` obtained by passing the same input to Go `tailcfg.Node.InitDisplayNames` (tailscale.com v1.104.6).
/// Characters that cannot appear in DNS, such as apostrophes, are dropped instead of replaced with `-`.
@Suite("computedName: Go display name rules")
struct WhoIsComputedNameTests {
    private static let suffix = "tail0001.ts.net"
    private static let key = NodePublicKey(rawValue: [UInt8](repeating: 0x22, count: 32)) ?? .zero

    private static func computedName(_ name: String, hostname: String = "", suffix: String = suffix) -> String {
        PeerIdentity.computedName(nodeName: name, hostname: hostname, key: key, magicDNSSuffix: suffix)
    }

    @Test("Suffix removal applies only at a label boundary and removes a trailing dot", arguments: [
        // Same tailnet
        ("rd-phone-1a2b3c4d.tail0001.ts.net.", "rd-phone-1a2b3c4d"),
        ("rd-phone-1a2b3c4d.tail0001.ts.net", "rd-phone-1a2b3c4d"),
        // Keeps a suffix outside a label boundary (only removes the trailing dot)
        ("rd-a.xtail0001.ts.net.", "rd-a.xtail0001.ts.net"),
        ("xtail0001.ts.net.", "xtail0001.ts.net"),
        // A name consisting only of the suffix has no boundary
        ("tail0001.ts.net.", "tail0001.ts.net"),
        // A node shared from another tailnet retains its FQDN
        ("rd-shared.tail0002.ts.net.", "rd-shared.tail0002.ts.net"),
        // Removes only the suffix even when two labels precede it
        ("a.b.tail0001.ts.net.", "a.b"),
        // Removes only one trailing dot
        ("rd-a.tail0001.ts.net..", "rd-a.tail0001.ts.net."),
        // A name consisting of a single dot
        (".", ""),
        ("", ""),
    ])
    func trimmingSuffix(name: String, expected: String) {
        #expect(Self.computedName(name, hostname: "", suffix: Self.suffix) == (expected.isEmpty ? Self.key.description : expected))
    }

    @Test("Suffix spelling ignores one dot at each end", arguments: [".tail0001.ts.net", "tail0001.ts.net.", ".tail0001.ts.net."])
    func suffixSpelling(suffix: String) {
        #expect(Self.computedName("rd-a.tail0001.ts.net.", suffix: suffix) == "rd-a")
    }

    @Test("Removes nothing when the suffix is empty")
    func emptySuffix() {
        #expect(Self.computedName("rd-a.tail0001.ts.net.", suffix: "") == "rd-a.tail0001.ts.net")
    }

    @Test("Uses the sanitized hostname when the name is empty", arguments: [
        ("rd-mac-1a2b3c4d", "rd-mac-1a2b3c4d"),
        ("Alice's MacBook Pro.local", "alices-macbook-pro"),
        ("host.localdomain", "host"),
        ("host.lan", "host"),
        // Removes common suffixes in this order, only once each
        ("host.lan.local", "host"),
        ("host.local.lan", "host-local"),
        // Drops non-alphanumeric characters at the ends and replaces interior delimiters with `-`
        ("--my_host@lab--", "my-host-lab"),
        ("_a b_", "a-b"),
        // Drops characters that cannot appear in DNS (including non-ASCII bytes)
        ("호스트a!b", "ab"),
        ("UPPER-case", "upper-case"),
        // Truncates to 63 bytes
        (String(repeating: "a", count: 70), String(repeating: "a", count: 63)),
        // Also drops a delimiter at the truncated end
        (String(repeating: "a", count: 62) + "_b", String(repeating: "a", count: 62)),
        // Empty after sanitization
        ("...", ""),
        ("", ""),
    ])
    func sanitizedHostname(hostname: String, expected: String) {
        let computed = Self.computedName("", hostname: hostname)
        #expect(computed == (expected.isEmpty ? Self.key.description : expected))
    }

    @Test("Ignores the hostname when a name is present")
    func nameWinsOverHostname() {
        #expect(Self.computedName("rd-a.tail0001.ts.net.", hostname: "other-host") == "rd-a")
    }

    @Test("Uses the node public key text when the name and hostname are both empty")
    func nodeKeyFallback() {
        let computed = Self.computedName("", hostname: "")
        #expect(computed == "nodekey:" + String(repeating: "22", count: 32))
    }

    @Test("Keeps a name equal to the suffix itself (a local name without dots)")
    func nameEqualToSuffix() {
        #expect(Self.computedName("mac", suffix: "mac") == "mac")
    }
}
