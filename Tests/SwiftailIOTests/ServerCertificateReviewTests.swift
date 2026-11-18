import Foundation
import Testing

@testable import SwiftailIO

/// Reproduction tests from the independent review of M8 ③ (named DERP certificate verification and `sha256-raw:` pinning).
///
/// The reference is the Go client's verification behavior (tailscale.com v1.104.6 `SetConfigExpectedCertHash` and
/// `SetConfigExpectedCert` in `net/tlsdial/tlsdial.go`, Go 1.27.3 `hostnameInSNI` in `crypto/tls`, and `VerifyHostname` in `crypto/x509`). Each test's Go
/// values came from running that code. Current differences from Go are wrapped in `withKnownIssue`. Once fixed, the wrapper becomes a failure
/// to flag the change.
@Suite("Server certificate verification review")
struct ServerCertificateReviewTests {
    private typealias Fixture = ServerCertificateFixtures
    private typealias Review = ServerCertificateReviewFixtures

    /// Within the validity period of the certificate fixtures (2026-01-01T00:00:00Z ... 2027-01-01T00:00:00Z).
    private static let now = Date(timeIntervalSince1970: 1_780_272_000) // 2026-06-01T00:00:00Z
    private static let notBefore = Date(timeIntervalSince1970: 1_767_225_600) // 2026-01-01T00:00:00Z
    private static let notAfter = Date(timeIntervalSince1970: 1_798_761_600) // 2027-01-01T00:00:00Z

    private static func pinned(
        _ certificates: [[UInt8]], hash: String = Fixture.ipLeafSHA256, serverName: String = "100.64.0.1", at now: Date = now
    ) -> ServerCertificate.Failure? {
        do throws(ServerCertificate.Failure) {
            try ServerCertificate.checkPinned(certificates, sha256Hex: hash, serverName: serverName, at: now)
            return nil
        } catch {
            return error
        }
    }

    private static func named(
        _ certificates: [[UInt8]], name: String = "derp-cert.example.test", at now: Date = now
    ) -> ServerCertificate.Failure? {
        do throws(ServerCertificate.Failure) {
            try ServerCertificate.checkNamed(certificates, name: name, at: now, anchors: [Fixture.root])
            return nil
        } catch {
            return error
        }
    }

    private static func isUntrusted(_ failure: ServerCertificate.Failure?) -> Bool {
        if case .untrusted = failure { true } else { false }
    }

    // MARK: Cases to reject

    /// The TLS handshake proves possession of the key for the first certificate only. An attacker on the network can present a CN `derpkey…` certificate made with their own key
    /// first and append the publicly obtainable pinned certificate, satisfying "exactly one non-meta certificate, matching hash."
    /// Go accepts this (`SetConfigExpectedCertHash` ignores position. Running the Go client confirmed that it connects to a TLS server presenting
    /// that list. Swiftail also connected before the fix). Swiftail rejects this where Go accepts it. A real derper presents the server certificate first, followed by the meta
    /// certificate (`derpserver.ModifyTLSConfigToAddMetaCert`). The meta certificate's private key is discarded at creation, so
    /// no normal server presents the meta certificate first.
    @Test("Pinning requires the pinned certificate to be first (the position whose key the server proved it holds)")
    func pinnedCertificateMustBeTheHandshakeLeaf() {
        #expect(Self.pinned([Fixture.meta, Fixture.ipLeaf]) == .candidateNotLeaf)
        #expect(Self.pinned([Fixture.meta, Fixture.ipLeaf, Fixture.meta]) == .candidateNotLeaf)
        #expect(Self.pinned([Fixture.ipLeaf, Fixture.meta]) == nil)
    }

    /// Go's x509 leaves CommonName empty when the subject CN is a VisibleString. Go therefore treats it as a non-meta certificate and
    /// rejects the list (hash mismatch if first, "multiple certs" if later). `SecCertificateCopyCommonName` reads that CN.
    ///
    /// Swiftail also rejects it if first (the first certificate looks like a meta certificate). Only the appended case differs: Swiftail treats it as meta and accepts it. Even then,
    /// TLS proves possession of the key for the pinned certificate in the first position, so Swiftail identifies the server correctly. Leave this behavior as is.
    @Test("Pinning with a certificate whose CN (VisibleString) Go does not recognize as meta")
    func visibleStringCommonNameIsNotMeta() {
        #expect(Self.pinned([Review.visibleStringMeta, Fixture.ipLeaf]) == .candidateNotLeaf)
        withKnownIssue("The Security framework reads more string types as CN than Go, so it skips a trailing certificate that Go counts (harmless)") {
            #expect(Self.pinned([Fixture.ipLeaf, Review.visibleStringMeta]) == .multipleCandidates)
        }
    }

    /// In Go, `hostnameInSNI("100.064.0.1")` returns the string unchanged (`net.ParseIP` rejects leading zeros). Go compares it as a name, so
    /// a certificate with only an IP SAN does not match. `SecPolicyCreateSSL` reads the same string as `100.64.0.1` and matches the IP SAN.
    @Test("Pinning must not match a server name against an IP SAN when Go does not parse that name as an IP")
    func leadingZeroServerNameIsNotAnIPAddress() {
        withKnownIssue("The SSL policy parses dotted decimal with leading zeros as an IP address") {
            #expect(Self.isUntrusted(Self.pinned([Fixture.ipLeaf], serverName: "100.064.0.1")))
        }
    }

    @Test("Compares the pin verbatim. Whitespace, a prefix, or a truncated value prevents a match")
    func pinnedHashShape() {
        let hash = Fixture.ipLeafSHA256
        for wrong in [" \(hash)", "\(hash) ", "\(hash)\n", "sha256-raw:\(hash)", String(hash.dropLast()), "\(hash)0", "0x\(hash)"] {
            #expect(Self.pinned([Fixture.ipLeaf], hash: wrong) == .hashMismatch)
        }
    }

    // MARK: Cases to accept

    /// Go pinning checks only the hash, name (`VerifyHostname`), and validity period. The `SecTrust` SSL server policy checks more. derper's
    /// manual certificate mode (`NewManualCertManager` in `cmd/derper/cert.go`) uses the operator-provided certificate as is, so for a
    /// DERP server pinned with `sha256-raw:` to any of the self-signed certificate forms below, the Go client connects and Swiftail cannot.
    @Test("Self-signed certificate forms accepted by Go pinning", arguments: [
        ("10-year validity period", Review.longValidityLeaf, Review.longValidityLeafSHA256),
        ("No EKU", Review.noEKULeaf, Review.noEKULeafSHA256),
        ("Ed25519 key", Review.ed25519Leaf, Review.ed25519LeafSHA256),
    ])
    func pinnedShapesGoAccepts(shape: String, certificate: [UInt8], hash: String) {
        withKnownIssue("SecTrust's SSL server policy is stricter than Go's: \(shape)") {
            #expect(Self.pinned([certificate], hash: hash, serverName: "derp1a.example.test") == nil)
        }
        // When connecting to DERP by IP (a common use of pinning), the name is skipped, so the SSL server policy is unused. Only the validity period is checked, as in Go.
        #expect(Self.pinned([certificate], hash: hash, serverName: "100.64.0.1") == nil, "IP server name: \(shape)")
        #expect(Self.isUntrusted(Self.pinned([certificate], hash: hash, serverName: "100.64.0.1", at: Self.notBefore - 1)))
    }

    /// Go rejects only `now.After(cert.NotAfter)` and `now.Before(cert.NotBefore)`, so both endpoints are valid.
    @Test("Pinning includes both endpoints of the validity period and excludes times 1 second outside it")
    func pinnedValidityBoundaries() {
        #expect(Self.pinned([Fixture.ipLeaf], at: Self.notBefore) == nil)
        #expect(Self.pinned([Fixture.ipLeaf], at: Self.notAfter) == nil)
        #expect(Self.isUntrusted(Self.pinned([Fixture.ipLeaf], at: Self.notBefore - 1)))
        #expect(Self.isUntrusted(Self.pinned([Fixture.ipLeaf], at: Self.notAfter + 1)))
    }

    /// Go skips name verification entirely when there is no name to send in SNI (`hostnameInSNI` returns an empty string). A certificate without an IP SAN also passes.
    @Test("Pinning accepts a certificate without an IP SAN when the server name is an IP literal", arguments: [
        "100.64.0.1", "fd7a:115c:a1e0::1", "[fd7a:115c:a1e0::1]", "fe80::1%en0", "::ffff:100.64.0.1",
    ])
    func pinnedIPLiteralIgnoresSubjectAlternativeNames(serverName: String) {
        #expect(Self.pinned([Fixture.dnsLeaf], hash: Fixture.dnsLeafSHA256, serverName: serverName) == nil)
    }

    // MARK: Named verification

    @Test("Named verification fails for expired or not-yet-valid certificates")
    func namedValidity() {
        #expect(Self.named([Fixture.namedLeaf], at: Self.notAfter - 1) == nil)
        #expect(Self.isUntrusted(Self.named([Fixture.namedLeaf], at: Self.notAfter + 1)))
        #expect(Self.isUntrusted(Self.named([Fixture.namedLeaf], at: Self.notBefore - 1)))
    }

    /// Go `SetConfigExpectedCert` treats only `certs[0]` as the leaf.
    @Test("Named verification treats only the first certificate as the leaf, so a matching certificate later in the list is rejected")
    func namedLeafIsFirst() {
        #expect(Self.isUntrusted(Self.named([Fixture.meta, Fixture.namedLeaf])))
        #expect(Self.isUntrusted(Self.named([Fixture.dnsLeaf, Fixture.namedLeaf])))
        #expect(Self.isUntrusted(Self.named([Fixture.root, Fixture.namedLeaf])))
    }

    /// Go `VerifyHostname` ignores case and a trailing dot in the name being compared.
    @Test("Named verification ignores case and a trailing dot, and permits an additional root or a duplicate certificate in the list")
    func namedAccepts() {
        #expect(Self.named([Fixture.namedLeaf], name: "DERP-Cert.Example.Test") == nil)
        #expect(Self.named([Fixture.namedLeaf], name: "derp-cert.example.test.") == nil)
        #expect(Self.named([Fixture.namedLeaf, Fixture.root]) == nil)
        #expect(Self.named([Fixture.namedLeaf, Fixture.namedLeaf]) == nil)
    }

    // MARK: SNI name

    /// These (input, output) pairs came from running Go 1.27.3 `hostnameInSNI` in `crypto/tls/handshake_client.go` verbatim. An empty output means there is
    /// no SNI, and pinning skips name verification in that case.
    private static let goServerNames: [(String, String)] = [
        ("", ""),
        (".", ""),
        ("..", ""),
        ("a", "a"),
        ("a.", "a"),
        ("a..", "a"),
        ("derp1a.example.test", "derp1a.example.test"),
        ("derp1a.example.test.", "derp1a.example.test"),
        ("100.64.0.1", ""),
        ("100.64.0.1.", "100.64.0.1"),
        ("[100.64.0.1]", ""),
        ("100.64.0.1%en0", ""),
        ("[100.64.0.1%en0]", ""),
        ("100.064.0.1", "100.064.0.1"),
        ("0100.64.0.1", "0100.64.0.1"),
        ("100.64.1", "100.64.1"),
        ("100.64.0.256", "100.64.0.256"),
        ("0x64.64.0.1", "0x64.64.0.1"),
        ("1681915905", "1681915905"),
        ("100.64.0.1:443", "100.64.0.1:443"),
        (" 100.64.0.1", " 100.64.0.1"),
        ("100.64.0.1 ", "100.64.0.1 "),
        ("0.0.0.0", ""),
        ("255.255.255.255", ""),
        ("::", ""),
        ("::1", ""),
        ("[::1]", ""),
        ("[::1].", "[::1]"),
        ("::1.", "::1"),
        ("fd7a:115c:a1e0::1", ""),
        ("FD7A:115C:A1E0::1", ""),
        ("[fd7a:115c:a1e0::1]", ""),
        ("[[::1]]", "[[::1]]"),
        ("[::1", "[::1"),
        ("::1]", "::1]"),
        ("fe80::1%en0", ""),
        ("[fe80::1%en0]", ""),
        ("fe80::1%", ""),
        ("fe80::1%25en0", ""),
        ("fe80::1%en0%en1", "fe80::1%en0%en1"),
        ("%en0", "%en0"),
        ("%", "%"),
        ("a%b", "a%b"),
        ("[%]", "[%]"),
        ("[", "["),
        ("]", "]"),
        ("[]", "[]"),
        ("[.]", "[.]"),
        ("::ffff:100.64.0.1", ""),
        ("::ffff:100.064.0.1", "::ffff:100.064.0.1"),
        ("::ffff:6440:1", ""),
        ("::100.64.0.1", ""),
        ("64:ff9b::100.64.0.1", ""),
        ("1:2:3:4:5:6:100.64.0.1", ""),
        ("1:2:3:4:5:6:7:100.64.0.1", "1:2:3:4:5:6:7:100.64.0.1"),
        ("1:2:3:4:5:6:7:8", ""),
        ("1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7:8:9"),
        ("1::2::3", "1::2::3"),
        (":::", ":::"),
        ("::1::", "::1::"),
        ("0:0:0:0:0:0:0:1", ""),
        ("00000::1", "00000::1"),
        ("::00001", "::00001"),
        ("::g", "::g"),
        ("1:2:3:4:5:6:7::", ""),
        ("::2:3:4:5:6:7:8", ""),
        ("1::8", ""),
        ("fe80::1%en0.", ""),
        ("[fe80::1%en0].", "[fe80::1%en0]"),
        ("100.64.0.1%", ""),
        ("[::1]%en0", "[::1]%en0"),
        ("::1%en0]", ""),
        ("\u{FF11}\u{FF10}\u{FF10}.64.0.1", "\u{FF11}\u{FF10}\u{FF10}.64.0.1"),
        ("100.64.0.1\u{0}", "100.64.0.1\u{0}"),
        ("100.64.0.1\u{0}.example.test", "100.64.0.1\u{0}.example.test"),
        ("derp%1a.example.test", "derp%1a.example.test"),
        ("::1%\u{301}", ""),
        ("[\u{301}::1]", "[\u{301}::1]"),
    ]

    /// Inputs where the results differ from Go. The first two differ because `IPAddress` accepts IPv6 groups with five digits, unlike `net.ParseIP`. Swiftail
    /// treats them as IP literals and skips name verification, while Go compares them as names. In the last case, a combining character follows `%`. Go splits by
    /// byte and sees an IP, while Swiftail works by character and compares it as a name (Swiftail is stricter).
    private static let knownServerNameDifferences: Set<String> = ["::1%\u{301}"]

    private static func sniHostNameMatchesGo(_ input: String, _ expected: String) {
        #expect(ServerCertificate.sniHostName(input) == (expected.isEmpty ? nil : expected), "Input \(input.debugDescription)")
    }

    @Test("The SNI name matches Go hostnameInSNI")
    func sniHostNameMatchesGo() {
        for (input, expected) in Self.goServerNames where !Self.knownServerNameDifferences.contains(input) {
            Self.sniHostNameMatchesGo(input, expected)
        }
    }

    /// Swift does not split off the zone because a `%` followed by a combining character in the zone position is not a character on its own. Go splits it off and treats the result as an IP. Swiftail
    /// treats it as a name and verifies it, which is stricter. Leave this behavior as is.
    @Test("SNI name inputs that differ from Go (stricter)")
    func sniHostNameDifferences() {
        withKnownIssue("A combining character after the zone's `%` yields a name in Swiftail, unlike in Go (stricter)") {
            for (input, expected) in Self.goServerNames where Self.knownServerNameDifferences.contains(input) {
                Self.sniHostNameMatchesGo(input, expected)
            }
        }
    }
}

/// Fixed certificates for `ServerCertificateReviewTests`. Copied verbatim from the output of `tailnet certificate-fixtures` (`reviewFixtures` in
/// `Tools/interop/cmd/tailnet/derpcert.go`). All are self-signed certificates for `derp1a.example.test` (P-256, server authentication EKU,
/// 2026-01-01T00:00:00Z ..< 2027-01-01T00:00:00Z), with only the noted differences. Go pinning reads all four.
enum ServerCertificateReviewFixtures {
    /// The only difference is a 10-year validity period (2026-01-01 ..< 2036-01-01).
    static let longValidityLeaf = der("MIIBjzCCATagAwIBAgIRAOFFbb/j6J2vgIDZNZvRO40wCgYIKoZIzj0EAwIwHjEcMBoGA1UEAxMTZGVycDFhLmV4YW1wbGUudGVzdDAeFw0yNjAxMDEwMDAwMDBaFw0zNjAxMDEwMDAwMDBaMB4xHDAaBgNVBAMTE2RlcnAxYS5leGFtcGxlLnRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATH2STO/rQ/aTsBAg8m0I+PiQoI6MdqUxPRYH0mf4YvmSzMw0QMioyhpaTVVhOK1KUfjG4l2vawc6QHXb10iUJBo1UwUzAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAeBgNVHREEFzAVghNkZXJwMWEuZXhhbXBsZS50ZXN0MAoGCCqGSM49BAMCA0cAMEQCIFQSforo1haJvhAV+ACItlWZk+r9hp0JcUS6//e1FbvOAiB0/D54STV+HKEKhZb22GxycCbGXrHt9jIRrKFDcLKJ1Q==")
    static let longValidityLeafSHA256 = "04be93f33a34909781e021be60a728fe7fc31cd4d7566eaf0230b904ea8bc91e"
    /// The only difference is the absence of an extended key usage (EKU).
    static let noEKULeaf = der("MIIBfDCCASGgAwIBAgIRAKN2TC/OpFGn+1DsgWTWxQUwCgYIKoZIzj0EAwIwHjEcMBoGA1UEAxMTZGVycDFhLmV4YW1wbGUudGVzdDAeFw0yNjAxMDEwMDAwMDBaFw0yNzAxMDEwMDAwMDBaMB4xHDAaBgNVBAMTE2RlcnAxYS5leGFtcGxlLnRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQS2RaxVXO4UbeFxsjs5MMU6NCvspOoUA04rpik/+BNh7lSkLddcl00m2J0wRbFB5idtZ52Xkat2nDcCT6KcGiRo0AwPjAOBgNVHQ8BAf8EBAMCBaAwDAYDVR0TAQH/BAIwADAeBgNVHREEFzAVghNkZXJwMWEuZXhhbXBsZS50ZXN0MAoGCCqGSM49BAMCA0kAMEYCIQCVVEsAe3LF73KM0NUT6db5WrOgFVMTFs4Bw6QkYRMiYwIhANPpHykCY1tj3+bGvUm41oDCqM1ZG55M4AfpMaz1hiBi")
    static let noEKULeafSHA256 = "21a30850b6d41f14f30f33ed65623c0cddb74ee8afa15f933ea3e58507b4fbac"
    /// The only difference is an Ed25519 key (digital signature key usage).
    static let ed25519Leaf = der("MIIBUDCCAQKgAwIBAgIRAMM5JyrMoelVY1biBi4GBwgwBQYDK2VwMB4xHDAaBgNVBAMTE2RlcnAxYS5leGFtcGxlLnRlc3QwHhcNMjYwMTAxMDAwMDAwWhcNMjcwMTAxMDAwMDAwWjAeMRwwGgYDVQQDExNkZXJwMWEuZXhhbXBsZS50ZXN0MCowBQYDK2VwAyEAGrwtrGxcTuFBC94Z0+4HMInOYIMrureUKmx33u+Ng1yjVTBTMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB4GA1UdEQQXMBWCE2RlcnAxYS5leGFtcGxlLnRlc3QwBQYDK2VwA0EAMx9VXMFbLvBI5ROHsPQeyYUmm8WBllplsQYsCcQDSdnlml+MRay6ymrh0oOaeUj2s+4DEDYQ3GmyBFAKAQ3TBg==")
    static let ed25519LeafSHA256 = "f0f10a676b31c2799429a8c1e37d2161432dd1d53fb15227c4cc56bd30a6b9c2"
    /// The subject CN is `derpkey00` encoded as VisibleString (tag 26). Go's x509 does not read this type as a CN (CommonName is empty).
    static let visibleStringMeta = der("MIIBfDCCASKgAwIBAgIRAIZYWnlcVZ9yVlv6sjK2WmkwCgYIKoZIzj0EAwIwFDESMBAGA1UEAxoJZGVycGtleTAwMB4XDTI2MDEwMTAwMDAwMFoXDTI3MDEwMTAwMDAwMFowFDESMBAGA1UEAxoJZGVycGtleTAwMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6YdGd29edaWB0Ana83eZ+kw7ji90b150nC7mT4Jqryvn7j4tYDfYyBsczrKlsNGXo7VfmM+YhXsz2UIySck3naNVMFMwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwHgYDVR0RBBcwFYITZGVycDFhLmV4YW1wbGUudGVzdDAKBggqhkjOPQQDAgNIADBFAiBjyG4qTalvoGB87iV7REwl2s0Pk/B9ka0sLW870VFwogIhAOOTPaCV6xtlzJ3n3whWjvGWef6Q9mJl/pJkVS5JGVrL")

    private static func der(_ base64: String) -> [UInt8] {
        [UInt8](Data(base64Encoded: base64) ?? Data())
    }
}
