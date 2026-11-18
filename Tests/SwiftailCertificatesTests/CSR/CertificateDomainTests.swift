// Name cases for contract behavior C2 (name validation) and §7 test 11: leading and trailing hyphens, 64-character labels, 253 characters,
// a 238-character name that exceeds the limit after adding `_acme-challenge.`, uppercase letters, and path characters.

import Testing

@testable import SwiftailCertificates

@Suite("Name validation")
struct CertificateDomainTests {
    @Test("Accepted names", arguments: [
        ("rd-mac-1a2b3c4d.tail0001.ts.net", "rd-mac-1a2b3c4d.tail0001.ts.net"),
        ("rd-mac-1a2b3c4d.tail0001.ts.net.", "rd-mac-1a2b3c4d.tail0001.ts.net"),  // Removes one trailing dot
        ("a.b", "a.b"),
        ("0.9a", "0.9a"),
        ("a--b.c-d", "a--b.c-d"),
    ])
    func accepted(input: String, name: String) throws {
        let domain = try #require(CertificateDomain(input))
        #expect(domain.name == name)
        #expect(domain.challengeRecordName == "_acme-challenge." + name)
    }

    @Test("Rejected names", arguments: [
        "", ".", "localhost", "localhost.",          // One label
        "-a.b", "a-.b", "a.-b", "a.b-",               // Leading or trailing hyphen
        "a..b", ".a.b", "a.b..",                       // Empty label (removes only one trailing dot)
        "Rd-mac.tail0001.ts.net", "a.B",               // Uppercase
        "_acme.a.b", "a_b.c", "*.a.b",                 // Underscores and wildcards
        "a/b.c", "a\\b.c", "a:b.c", "a\u{0}b.c", "../a.b", "a b.c",
        "é.a.b", "ａ.b",                                // Non-ASCII
        "100.64.0.1", "a.b.123", "0.9",                // Digits-only final label (IP address form)
    ])
    func rejected(_ input: String) {
        #expect(CertificateDomain(input) == nil)
    }

    @Test("Accepts a 63-character label and rejects a 64-character label")
    func labelLength() {
        #expect(CertificateDomain(String(repeating: "a", count: 63) + ".b") != nil)
        #expect(CertificateDomain(String(repeating: "a", count: 64) + ".b") == nil)
    }

    /// Add a label to three 63-character labels (191 characters) to reach the desired length.
    private static func name(length: Int) -> String {
        let base = Array(repeating: String(repeating: "a", count: 63), count: 3).joined(separator: ".")
        let last = String(repeating: "b", count: length - base.count - 1)
        return base + "." + last
    }

    @Test("Total length: accepts 237 characters and rejects 238 characters, which exceed 253 characters after adding _acme-challenge.")
    func totalLength() {
        #expect(CertificateDomain.maximumLength == 237)
        let longest = Self.name(length: 237)
        #expect(CertificateDomain(longest)?.challengeRecordName.utf8.count == 253)
        #expect(CertificateDomain(longest + ".") != nil)
        #expect(CertificateDomain(Self.name(length: 238)) == nil)
        #expect(CertificateDomain(Self.name(length: 253)) == nil)
    }
}
