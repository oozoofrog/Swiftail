// Message parsing boundaries: two Retry-After forms (RFC 7231 7.1.3, three date formats in 7.1.1.1), problem document types (RFC 8555 6.7),
// nonce, token, and URL rules, and no crash on arbitrary bytes.

import Foundation
import Testing

@testable import SwiftailCertificates

@Suite("ACME messages")
struct ACMEMessageTests {
    private let received = Date(timeIntervalSince1970: 784_111_777)  // Sun, 06 Nov 1994 08:49:37 GMT

    @Test("Retry-After: seconds")
    func retryAfterSeconds() {
        #expect(RetryAfter.date(from: "120", receivedAt: received) == received.addingTimeInterval(120))
        #expect(RetryAfter.date(from: " 0 ", receivedAt: received) == received)
        #expect(RetryAfter.date(from: "99999999999999999999999999", receivedAt: received) == received.addingTimeInterval(7 * 86_400))
        for invalid in ["", "-1", "1.5", "+3", "12a", "１２"] {
            #expect(RetryAfter.date(from: invalid, receivedAt: received) == nil, "\(invalid)")
        }
    }

    @Test("Retry-After: three HTTP date formats (examples from RFC 7231 7.1.1.1)")
    func retryAfterDates() {
        let later = received.addingTimeInterval(-60)  // Move the reference time earlier so the date follows the receipt time
        for value in ["Sun, 06 Nov 1994 08:49:37 GMT", "Sunday, 06-Nov-94 08:49:37 GMT", "Sun Nov  6 08:49:37 1994"] {
            #expect(RetryAfter.date(from: value, receivedAt: later) == received, "\(value)")
        }
        #expect(RetryAfter.date(from: "Fri, 31 Dec 1999 23:59:59 GMT", receivedAt: Date(timeIntervalSince1970: 946_684_000))
                == Date(timeIntervalSince1970: 946_684_799))
        #expect(RetryAfter.date(from: "Tue, 29 Feb 2028 00:00:00 GMT", receivedAt: Date(timeIntervalSince1970: 1_835_000_000))
                == Date(timeIntervalSince1970: 1_835_395_200))
        for invalid in [
            "Sun, 6 Nov 1994 08:49:37 GMT", "sun, 06 Nov 1994 08:49:37 GMT", "Sun, 06 Nov 1994 08:49:37 UTC",
            "Sun, 31 Feb 1994 08:49:37 GMT", "Sun, 06 Nov 1994 24:00:00 GMT", "Sun Nov 6 08:49:37 1994",
            "2026-11-15T00:00:00Z",
        ] {
            #expect(RetryAfter.date(from: invalid, receivedAt: received) == nil, "\(invalid)")
        }
    }

    @Test("Retry-After: parses RFC 850 two-digit years using the 50-year rule")
    func rfc850Years() {
        let now = Date(timeIntervalSince1970: 1_800_000_000)  // Year 2027
        // 2070 is 43 years ahead, so the year is 2070. The delay is capped at 7 days.
        #expect(RetryAfter.date(from: "Monday, 06-Jan-70 00:00:00 GMT", receivedAt: now) == now.addingTimeInterval(7 * 86_400))
        // 2080 is 53 years ahead, so the year is 1980 (in the past).
        #expect(RetryAfter.date(from: "Sunday, 06-Jan-80 00:00:00 GMT", receivedAt: now) == Date(timeIntervalSince1970: 315_964_800))
    }

    @Test("Recognizes a problem document type only when it exactly matches the ACME URN")
    func problemKinds() {
        #expect(ProblemDocument(type: Fake.problem("badNonce")).kind == .badNonce)
        #expect(ProblemDocument(type: Fake.problem("rateLimited")).kind == .rateLimited)
        #expect(ProblemDocument(type: Fake.problem("badNonceX")).kind == nil)
        #expect(ProblemDocument(type: "urn:ietf:params:acme:error:BADNONCE").kind == nil)
        #expect(ProblemDocument(type: "https://acme.invalid/urn:ietf:params:acme:error:badNonce").kind == nil)
        #expect(ProblemDocument(responseBody: Array(#"{"type":null}"#.utf8)).type == "")
        #expect(ProblemDocument(responseBody: Array(#""urn:ietf:params:acme:error:badNonce""#.utf8)).type == "")
    }

    @Test("Nonces and tokens are 1–512 bytes of base64url")
    func nonceAndTokenRules() {
        #expect(ACMEInputRules.isAcceptableNonce("oFvnlFP1wIhRlYS2jTaXbA"))
        #expect(ACMEInputRules.isAcceptableNonce(String(repeating: "_", count: 512)))
        for invalid in ["", "abc=", "a b", "a+b/", String(repeating: "a", count: 513), "가"] {
            #expect(!ACMEInputRules.isAcceptableNonce(invalid), "\(invalid)")
            #expect(!ACMEInputRules.isAcceptableToken(invalid), "\(invalid)")
        }
    }

    @Test("URLs require https and a host and are at most 2,048 bytes")
    func urlRules() {
        #expect(ACMEInputRules.isAcceptableURL("https://acme.invalid/x"))
        #expect(ACMEInputRules.isAcceptableURL("HTTPS://acme.invalid/x"))
        for invalid in ["http://acme.invalid/x", "ftp://acme.invalid", "https://", "//acme.invalid/x", "not a url",
                        "https://acme.invalid/" + String(repeating: "a", count: 2028),
                        // Strings whose re-encoding makes the signed url differ from the actual request, and userinfo.
                        "https://acme.invalid/a b", "https://acme.invalid/%zz", "https://user@acme.invalid/x",
                        "https://user:secret@acme.invalid/x"] {
            #expect(!ACMEInputRules.isAcceptableURL(invalid), "\(invalid)")
        }
    }

    @Test("Same origin requires matching schemes, hosts, and ports (case-insensitive)")
    func sameOrigin() {
        let directory = "https://acme.invalid:14000/dir"
        #expect(ACMEInputRules.hasSameOrigin("https://acme.invalid:14000/order/1", as: directory))
        #expect(ACMEInputRules.hasSameOrigin("HTTPS://ACME.invalid:14000/x", as: directory))
        for other in ["https://acme.invalid/order/1", "https://acme.invalid:14001/x", "https://other.invalid:14000/x",
                      "https://127.0.0.1:14000/x", "https://acme.invalid.evil.invalid:14000/x", "not a url"] {
            #expect(!ACMEInputRules.hasSameOrigin(other, as: directory), "\(other)")
        }
    }

    @Test("Validates only the challenge it uses, so a malformed challenge of another type does not discard the authorization")
    func lenientChallenges() throws {
        let body = Body.authorization("pending", challenges: [
            ["type": "http-01"], ["type": "tls-alpn-01", "url": "http://acme.invalid"], Body.challenge(),
        ])
        let authorization = try #require(ACMEAuthorization(body: body))
        #expect(authorization.dns01Challenge?.validated?.token == Fake.token(1))
    }

    @Test("Arbitrary bytes and malformed JSON do not cause a crash")
    func fuzz() {
        var random = SplitMix64(seed: 0xACE4)
        let seeds = [Body.directory(), Body.order("pending"), Body.authorization("pending"), Body.account(), Body.problem("x")]
        for _ in 0..<2000 {
            var bytes: [UInt8]
            if Bool.random(using: &random), let seed = seeds.randomElement(using: &random) {
                // Change a few bytes in a valid body.
                bytes = seed
                for _ in 0..<Int.random(in: 1...8, using: &random) {
                    bytes[Int.random(in: 0..<bytes.count, using: &random)] = UInt8.random(in: .min ... .max, using: &random)
                }
            } else {
                bytes = random.bytes(Int.random(in: 0...256, using: &random))
            }
            _ = ACMEDirectory(body: bytes)
            _ = ACMEOrder(body: bytes)
            _ = ACMEAuthorization(body: bytes)
            _ = ACMEAccountStatus(body: bytes)
            _ = ProblemDocument(responseBody: bytes)
            _ = RetryAfter.date(from: String(decoding: bytes.prefix(40), as: UTF8.self), receivedAt: received)
        }
        // Deeply nested JSON.
        let nested = Array((String(repeating: "[", count: 10_000) + String(repeating: "]", count: 10_000)).utf8)
        #expect(ACMEOrder(body: nested) == nil)
        #expect(ProblemDocument(responseBody: nested).type == "")
    }
}
