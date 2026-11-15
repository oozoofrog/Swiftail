// 메시지 해석의 경계: Retry-After의 두 형식(RFC 7231 7.1.3, 날짜 세 형식 7.1.1.1), 문제 문서의 종류(RFC 8555 6.7),
// nonce·token·URL의 규칙, 임의 바이트를 넣어도 죽지 않음.

import Foundation
import Testing

@testable import SwiftailCertificates

@Suite("ACME 메시지")
struct ACMEMessageTests {
    private let received = Date(timeIntervalSince1970: 784_111_777)  // Sun, 06 Nov 1994 08:49:37 GMT

    @Test("Retry-After: 초")
    func retryAfterSeconds() {
        #expect(RetryAfter.date(from: "120", receivedAt: received) == received.addingTimeInterval(120))
        #expect(RetryAfter.date(from: " 0 ", receivedAt: received) == received)
        #expect(RetryAfter.date(from: "99999999999999999999999999", receivedAt: received) == received.addingTimeInterval(7 * 86_400))
        for invalid in ["", "-1", "1.5", "+3", "12a", "１２"] {
            #expect(RetryAfter.date(from: invalid, receivedAt: received) == nil, "\(invalid)")
        }
    }

    @Test("Retry-After: HTTP 날짜 세 형식(RFC 7231 7.1.1.1의 예)")
    func retryAfterDates() {
        let later = received.addingTimeInterval(-60)  // 날짜가 받은 시각보다 뒤가 되도록 기준을 앞당긴다
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

    @Test("Retry-After: RFC 850의 두 자리 해는 50년 규칙으로 읽는다")
    func rfc850Years() {
        let now = Date(timeIntervalSince1970: 1_800_000_000)  // 2027년
        // 2070년은 43년 뒤이므로 2070년이다. 7일로 묶인다.
        #expect(RetryAfter.date(from: "Monday, 06-Jan-70 00:00:00 GMT", receivedAt: now) == now.addingTimeInterval(7 * 86_400))
        // 2080년은 53년 뒤이므로 1980년이다(지난 시각).
        #expect(RetryAfter.date(from: "Sunday, 06-Jan-80 00:00:00 GMT", receivedAt: now) == Date(timeIntervalSince1970: 315_964_800))
    }

    @Test("문제 문서의 종류는 ACME URN과 정확히 같을 때만")
    func problemKinds() {
        #expect(ProblemDocument(type: Fake.problem("badNonce")).kind == .badNonce)
        #expect(ProblemDocument(type: Fake.problem("rateLimited")).kind == .rateLimited)
        #expect(ProblemDocument(type: Fake.problem("badNonceX")).kind == nil)
        #expect(ProblemDocument(type: "urn:ietf:params:acme:error:BADNONCE").kind == nil)
        #expect(ProblemDocument(type: "https://acme.invalid/urn:ietf:params:acme:error:badNonce").kind == nil)
        #expect(ProblemDocument(responseBody: Array(#"{"type":null}"#.utf8)).type == "")
        #expect(ProblemDocument(responseBody: Array(#""urn:ietf:params:acme:error:badNonce""#.utf8)).type == "")
    }

    @Test("nonce와 token은 base64url 1~512바이트")
    func nonceAndTokenRules() {
        #expect(ACMEInputRules.isAcceptableNonce("oFvnlFP1wIhRlYS2jTaXbA"))
        #expect(ACMEInputRules.isAcceptableNonce(String(repeating: "_", count: 512)))
        for invalid in ["", "abc=", "a b", "a+b/", String(repeating: "a", count: 513), "가"] {
            #expect(!ACMEInputRules.isAcceptableNonce(invalid), "\(invalid)")
            #expect(!ACMEInputRules.isAcceptableToken(invalid), "\(invalid)")
        }
    }

    @Test("URL은 https, 호스트 있음, 2,048바이트 이하")
    func urlRules() {
        #expect(ACMEInputRules.isAcceptableURL("https://acme.invalid/x"))
        #expect(ACMEInputRules.isAcceptableURL("HTTPS://acme.invalid/x"))
        for invalid in ["http://acme.invalid/x", "ftp://acme.invalid", "https://", "//acme.invalid/x", "not a url",
                        "https://acme.invalid/" + String(repeating: "a", count: 2028)] {
            #expect(!ACMEInputRules.isAcceptableURL(invalid), "\(invalid)")
        }
    }

    @Test("challenge는 쓰는 것만 검사하므로 다른 종류의 모양이 authorization을 버리지 않는다")
    func lenientChallenges() throws {
        let body = Body.authorization("pending", challenges: [
            ["type": "http-01"], ["type": "tls-alpn-01", "url": "http://acme.invalid"], Body.challenge(),
        ])
        let authorization = try #require(ACMEAuthorization(body: body))
        #expect(authorization.dns01Challenge?.validated?.token == Fake.token(1))
    }

    @Test("임의 바이트와 깨진 JSON을 넣어도 죽지 않는다")
    func fuzz() {
        var random = SplitMix64(seed: 0xACE4)
        let seeds = [Body.directory(), Body.order("pending"), Body.authorization("pending"), Body.account(), Body.problem("x")]
        for _ in 0..<2000 {
            var bytes: [UInt8]
            if Bool.random(using: &random), let seed = seeds.randomElement(using: &random) {
                // 올바른 본문의 바이트 몇 개를 바꾼다.
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
        // 깊이 중첩된 JSON.
        let nested = Array((String(repeating: "[", count: 10_000) + String(repeating: "]", count: 10_000)).utf8)
        #expect(ACMEOrder(body: nested) == nil)
        #expect(ProblemDocument(responseBody: nested).type == "")
    }
}
