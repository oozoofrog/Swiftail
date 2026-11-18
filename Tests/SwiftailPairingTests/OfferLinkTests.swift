import Foundation
import Testing
@testable import SwiftailPairing

/// Tests offer links (contract `docs/contracts/SwiftailPairing.md` §3, behaviors O1–O4, §7 test 1).
@Suite("Offer links")
struct OfferLinkTests {
    /// The text encoding of `Sample.secret` (0x5A × 32).
    private static let secretText = "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo"
    private static let fragment = "v=1&h=rd-mac-1a2b3c4d.tail0001.ts.net&p=4747&s=\(secretText)&e=1900000300"

    /// Returns a link with the value of `key` in a valid fragment replaced by `value`. A nil `value` removes the key.
    private static func link(replacing key: String, with value: String?, authKey: String? = nil) -> String {
        var pairs = fragment.split(separator: "&").map(String.init)
        if let authKey { pairs.append("k=\(authKey)") }
        pairs = pairs.compactMap { pair in
            guard pair.hasPrefix("\(key)=") else { return pair }
            return value.map { "\(key)=\($0)" }
        }
        return "myapp://pair#" + pairs.joined(separator: "&")
    }

    private static func parseError(_ link: String) -> PairingOfferError? {
        do throws(PairingOfferError) {
            _ = try PairingOffer(link: link)
            return nil
        } catch {
            return error
        }
    }

    // MARK: Writing and round trips (O1)

    @Test("The link carries all values in the fragment and has a fixed format")
    func writesFragment() throws {
        let base = try #require(URL(string: "https://example.com/pair"))
        #expect(Sample.offer().url(base: base).absoluteString == "https://example.com/pair#" + Self.fragment)
        #expect(
            Sample.offer(authKey: Sample.authKey).url(base: base).absoluteString
                == "https://example.com/pair#" + Self.fragment + "&k=tskey-auth-EXAMPLE-0000")
        let url = Sample.offer(authKey: Sample.authKey).url(base: base)
        #expect(url.query == nil && url.path == "/pair", "The path and query carry no values")
    }

    @Test("Discards the base fragment", arguments: ["myapp://pair", "myapp://pair#old", "https://example.com/pair?x=1#old&v=9"])
    func dropsBaseFragment(base: String) throws {
        let url = Sample.offer().url(base: try #require(URL(string: base)))
        let stem = base.split(separator: "#")[0]
        #expect(url.absoluteString == stem + "#" + Self.fragment)
    }

    @Test("Reading a written link returns the same offer", arguments: [nil, Sample.authKey])
    func roundTrips(authKey: String?) throws {
        let offer = Sample.offer(authKey: authKey)
        let read = try PairingOffer(link: offer.url(base: try #require(URL(string: "myapp://pair"))).absoluteString)
        #expect(read.host == offer.host)
        #expect(read.port == offer.port)
        #expect(read.expires == offer.expires)
        #expect(read.authKey == authKey)
        #expect(read.secret == offer.secret)
    }

    @Test("Fractional expiration seconds are discarded and the result is written in seconds")
    func truncatesExpiry() throws {
        let offer = Sample.offer(expires: Date(timeIntervalSince1970: 1_900_000_300.9))
        #expect(offer.fragment.hasSuffix("&e=1900000300"))
    }

    // MARK: Reading (O2–O4)

    @Test("Ignores the base and reads only what follows the first #", arguments: ["", "myapp://pair", "https://example.com/pair?h=other.example.com"])
    func ignoresBase(base: String) throws {
        let offer = try PairingOffer(link: base + "#" + Self.fragment)
        #expect(offer.host == Sample.host && offer.port == Sample.port && offer.secret == Sample.secret)
        #expect(offer.authKey == nil)
    }

    @Test("Expired offers still parse, and the host rejects them")
    func readsExpiredOffer() throws {
        let offer = try PairingOffer(link: Self.link(replacing: "e", with: "1"))
        #expect(offer.expires == Date(timeIntervalSince1970: 1))
    }

    @Test("Key order does not matter")
    func acceptsAnyKeyOrder() throws {
        let pairs = Self.fragment.split(separator: "&").reversed().joined(separator: "&")
        #expect(try PairingOffer(link: "#" + pairs).secret == Sample.secret)
    }

    private static let nonOffers: [String] = [
        "myapp://pair",                                   // Missing fragment
        "myapp://pair#",                                  // Empty fragment
        "#" + fragment.replacingOccurrences(of: "v=1", with: "v=2"),
        "#" + fragment.replacingOccurrences(of: "v=1", with: "v=01"),
        "#" + fragment.replacingOccurrences(of: "v=1&", with: ""),
        "#" + fragment + "&x=1",                          // Unknown key
        "#" + fragment + "&V=1",                          // Keys must be lowercase
        "#" + fragment + "&p=4747",                       // Duplicate key
        "#" + fragment + "&v=1",
        "#" + fragment + "&",                             // Empty group
        "#&" + fragment,
        "#" + fragment + "&k",                            // Missing `=`
        "#" + fragment.replacingOccurrences(of: "ts.net", with: "ts%2Enet"),   // `%`
        "#" + fragment + "&k=tskey-auth-EXAMPLE%2D0000",
        "#" + fragment.replacingOccurrences(of: "rd-mac-1a2b3c4d", with: String(repeating: "a", count: 2048)),
    ]

    @Test("Input that is not an offer link", arguments: nonOffers)
    func rejectsNonOffers(link: String) {
        #expect(Self.parseError(link) == .notAnOffer)
    }

    @Test("The fragment can be up to 2048 bytes. An oversized fragment fails before malformed values are checked")
    func limitsFragmentLength() {
        let padding = 2048 - Self.fragment.utf8.count - "&k=".utf8.count
        let atLimit = "#" + Self.fragment + "&k=" + String(repeating: "a", count: padding)
        #expect(Self.parseError(atLimit) == .invalidAuthKey)
        #expect(Self.parseError(atLimit + "a") == .notAnOffer)
    }

    private static let badHosts: [String?] = [
        nil, "", "localhost", "RD-MAC.tail0001.ts.net", "rd_mac.tail0001.ts.net", "-rd.tail0001.ts.net",
        "rd-.tail0001.ts.net", "rd..ts.net", ".ts.net", "rd.ts.net.", "rd mac.ts.net", "100.64.0.1:80",
        String(repeating: "a", count: 64) + ".ts.net",
        // 254 characters: four 63-character labels give 255 characters, so shorten the last label to 62 characters.
        [63, 63, 63, 62].map { String(repeating: "a", count: $0) }.joined(separator: "."),
        "rd-mac.tail0001.ts.net#x",
    ]

    @Test("host: at least two labels of lowercase letters, digits, and hyphens", arguments: badHosts)
    func rejectsHosts(value: String?) {
        #expect(Self.parseError(Self.link(replacing: "h", with: value)) == .invalidHost)
    }

    @Test(
        "host: if the final label starts with a nonletter, it has the form of an IP address (decimal or hexadecimal)",
        arguments: [
            "192.168.1.1", "127.0.0.1", "1.2", "100.64.0.1", "rd-mac-1a2b3c4d.tail0001.0",
            // The OS also reads a final label of `0x…` as an IPv4 address.
            "192.168.1.0x1", "1.0x7f", "0x7f.0.0.0x1", "1.0x", "1a.2b", "rd-mac-1a2b3c4d.tail0001.-a",
        ])
    func rejectsAddressShapedHosts(value: String) {
        #expect(Self.parseError(Self.link(replacing: "h", with: value)) == .invalidHost)
        #expect(OfferField.host(value.utf8) == nil, "The host (openOffer) validates its own name using the same rules")
    }

    private static let goodHosts: [String] = [
        String(repeating: "a", count: 63) + ".ts.net",
        [63, 63, 63, 61].map { String(repeating: "a", count: $0) }.joined(separator: "."),
        "1a.b2", "a-b.c-d", "rd-mac-1a2b3c4d.tail0001.ts.net", "rd-mac-1a2b3c4d.xn--p1ai",
    ]

    @Test("host boundaries: 63-character label, 253 characters total, and labels starting with digits (the last label starts with a letter)", arguments: goodHosts)
    func acceptsHosts(value: String) throws {
        #expect(try PairingOffer(link: Self.link(replacing: "h", with: value)).host == value)
    }

    @Test("port: 1–65535 without leading zeros", arguments: [nil, "", "0", "65536", "04747", "+4747", "-1", "4747 ", "0x1f", "123456", "４７"])
    func rejectsPorts(value: String?) {
        #expect(Self.parseError(Self.link(replacing: "p", with: value)) == .invalidPort)
    }

    @Test("port boundaries", arguments: [("1", UInt16(1)), ("65535", UInt16(65535))])
    func acceptsPorts(value: String, expected: UInt16) throws {
        #expect(try PairingOffer(link: Self.link(replacing: "p", with: value)).port == expected)
    }

    private static let badSecrets: [String?] = [
        nil, "",
        String(secretText.dropLast()),            // 42 characters
        secretText + "A",                         // 44 characters
        secretText + "=",                         // Padding
        String(secretText.dropLast()) + "=",
        "+" + secretText.dropFirst(),             // Standard base64 characters
        "/" + secretText.dropFirst(),
        " " + secretText.dropFirst(),
        String(secretText.dropLast()) + "p",      // Nonzero trailing bits (the character after o)
        String(secretText.dropLast()) + "_",
    ]

    @Test("secret: 43 unpadded base64url characters encoding 32 bytes", arguments: badSecrets)
    func rejectsSecrets(value: String?) {
        #expect(Self.parseError(Self.link(replacing: "s", with: value)) == .invalidSecret)
    }

    @Test("secret characters: - and _")
    func acceptsURLSafeAlphabet() throws {
        let secret = [UInt8](repeating: 0xFB, count: 31) + [0xFF]
        let offer = try PairingOffer(link: "#" + Sample.offer(secret: secret).fragment)
        #expect(Sample.offer(secret: secret).fragment.contains("s=-_"), "0xFB 0xFF… is written using `-` and `_`")
        #expect(offer.secret == secret)
    }

    @Test("expiry: 1–11 digits with no sign or leading zeros", arguments: [nil, "", "0", "01", "-1", "+1", "1.5", "1e9", "123456789012", "19000003oo"])
    func rejectsExpiries(value: String?) {
        #expect(Self.parseError(Self.link(replacing: "e", with: value)) == .invalidExpiry)
    }

    @Test("expiry boundaries", arguments: [("1", 1.0), ("99999999999", 99_999_999_999.0)])
    func acceptsExpiries(value: String, expected: Double) throws {
        let offer = try PairingOffer(link: Self.link(replacing: "e", with: value))
        #expect(offer.expires == Date(timeIntervalSince1970: expected))
    }

    @Test("Treats a second # in the fragment as part of the value and rejects it")
    func rejectsSecondHash() {
        #expect(Self.parseError("#" + Self.fragment + "#x") == .invalidExpiry)
    }

    private static let badAuthKeys: [String] = [
        "", "tskey-client-EXAMPLE", "TSKEY-AUTH-EXAMPLE", "tskey-auth", "tskey-auth-EXAMPLE_0000",
        "tskey-auth-EXAMPLE.0000", "tskey-auth-EXAMPLE 0000", "tskey-auth-EXAMPLE=", "tskey-auth-EXAMPLE#",
        "tskey-auth-" + String(repeating: "a", count: 246),   // 257 bytes
    ]

    @Test("authKey: starts with tskey-auth-, uses only A-Za-z0-9-, and is at most 256 bytes", arguments: badAuthKeys)
    func rejectsAuthKeys(value: String) {
        #expect(Self.parseError(Self.link(replacing: "k", with: value, authKey: "")) == .invalidAuthKey)
    }

    @Test("authKey boundary: 256 bytes")
    func acceptsLongestAuthKey() throws {
        let key = "tskey-auth-" + String(repeating: "a", count: 245)
        #expect(try PairingOffer(link: Self.link(replacing: "k", with: key, authKey: "")).authKey == key)
    }

    private static let wrappedAuthKeys: [String] = [
        "tskey-auth-EXAMPLE-0000--TLEXAMPLE-EXAMPLE",
        "tskey-auth-EXAMPLE-0000--TLab+cd/ef-gh+ij/kl",   // The tail uses standard base64, so the character check also rejects it, but this is the reason.
        "--TL",
    ]

    @Test("Wrapped auth keys (--TL) cannot be included", arguments: wrappedAuthKeys)
    func rejectsWrappedAuthKeys(value: String) {
        #expect(Self.parseError(Self.link(replacing: "k", with: value, authKey: "")) == .wrappedAuthKey)
    }

    // MARK: Redaction

    @Test("description and dump omit the secret and auth key")
    func redactsSecrets() {
        let offer = Sample.offer(authKey: Sample.authKey)
        var dumped = ""
        dump(offer, to: &dumped)
        for text in [String(describing: offer), String(reflecting: offer), "\(offer)", dumped] {
            #expect(text.contains(Sample.host), "Values that need no redaction are visible")
            #expect(!text.contains(Self.secretText))
            #expect(!text.contains("90, 90"), "The secret's byte array is also absent")
            #expect(!text.contains("5a5a") && !text.contains("5A5A"))
            #expect(!text.contains("tskey"))
        }
        var withoutKey = ""
        dump(Sample.offer(), to: &withoutKey)
        #expect(withoutKey.contains("none"))
    }
}
