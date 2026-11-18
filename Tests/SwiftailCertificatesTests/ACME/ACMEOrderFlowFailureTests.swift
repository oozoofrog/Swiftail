// Failure paths in contract §7 test 8: invalid and unknown finalize statuses and excess retries, invalid orders and authorizations,
// deactivated, expired, and revoked statuses, badNonce once, three times, and four times, Retry-After (seconds, date, past date, unparseable, 5-minute deadline, and 7 days),
// rateLimited, problem documents, identifier, wildcard, count, URL, size, and nonce boundaries, transport and TXT failures, and deadlines.

import Foundation
import Testing

@testable import SwiftailCertificates

@Suite("ACME order flow: failure paths")
struct ACMEOrderFlowFailureTests {
    private let issued = ACMEIssuanceResult.issued(certificateChainPEM: Fake.chainPEM, accountURL: Fake.accountURL)

    // MARK: Order and authorization status

    @Test("An invalid finalize response and an invalid authorization return validationFailed")
    func finalizeInvalidWithInvalidAuthorization() {
        let run = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order("ready")),
            .post(Fake.finalizeURL, 200, Body.order("invalid", errorType: Fake.problem("unauthorized"))),
            .post(Fake.authorizationURL(1), 200, Body.authorization("invalid", challenges: [
                Body.challenge(errorType: Fake.problem("dns")),
            ])),
        ])
        #expect(run.failure == .validationFailed(type: Fake.problem("dns")))
    }

    @Test("An invalid order with all authorizations valid returns orderFailed (the order's error)")
    func pollInvalidWithoutAuthorizationFailure() {
        let run = ACMEScript().run(Steps.accountFound + [Steps.newOrder(Body.order("pending"))] + Steps.pendingAuthorization() + [
            Steps.readOrder(Body.order("invalid", errorType: Fake.problem("badCSR"))),
            .post(Fake.authorizationURL(1), 200, Body.authorization("valid", challenges: [Body.challenge(status: "valid")])),
        ])
        #expect(run.failure == .orderFailed(type: Fake.problem("badCSR")))
    }

    @Test("A new order that is already invalid returns orderFailed")
    func createdInvalid() {
        let run = ACMEScript().run(Steps.accountFound + [Steps.newOrder(Body.order("invalid"))])
        #expect(run.failure == .orderFailed(type: ""))
    }

    @Test("An invalid authorization returns validationFailed (the challenge's error)")
    func authorizationInvalid() {
        let run = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order("pending")),
            .post(Fake.authorizationURL(1), 200, Body.authorization("invalid", challenges: [
                Body.challenge(type: "http-01"), Body.challenge(status: "invalid", errorType: Fake.problem("incorrectResponse")),
            ])),
        ])
        #expect(run.failure == .validationFailed(type: Fake.problem("incorrectResponse")))
    }

    @Test("An invalid challenge returns validationFailed")
    func challengeInvalid() {
        let run = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order("pending")),
            .post(Fake.authorizationURL(1), 200, Body.authorization("pending", challenges: [
                Body.challenge(status: "invalid", errorType: Fake.problem("dns")),
            ])),
        ])
        #expect(run.failure == .validationFailed(type: Fake.problem("dns")))
    }

    @Test("An authorization that cannot proceed returns orderFailed", arguments: ["deactivated", "expired", "revoked"])
    func unusableAuthorization(status: String) {
        let run = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order("pending")),
            .post(Fake.authorizationURL(1), 200, Body.authorization(status)),
        ])
        #expect(run.failure == .orderFailed(type: ""))
    }

    @Test("An unknown status returns unexpectedResponse")
    func unknownStatuses() {
        let script = ACMEScript()
        let finalize = script.run(Steps.accountFound + [
            Steps.newOrder(Body.order("ready")),
            .post(Fake.finalizeURL, 200, Body.order("issuing")),
        ])
        #expect(finalize.failure == .unexpectedResponse)

        let created = ACMEScript().run(Steps.accountFound + [Steps.newOrder(Body.order("queued"))])
        #expect(created.failure == .unexpectedResponse)

        let authorization = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order("pending")),
            .post(Fake.authorizationURL(1), 200, Body.authorization("unknown")),
        ])
        #expect(authorization.failure == .unexpectedResponse)

        let challenge = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order("pending")),
            .post(Fake.authorizationURL(1), 200, Body.authorization("pending", challenges: [Body.challenge(status: "waiting")])),
        ])
        #expect(challenge.failure == .unexpectedResponse)
    }

    @Test("A second repetition of ready or pending after finalize returns unexpectedResponse")
    func secondRepeatFails() {
        let ready = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order("ready")),
            .post(Fake.finalizeURL, 200, Body.order("ready")),
            .post(Fake.finalizeURL, 200, Body.order("ready")),
        ])
        #expect(ready.failure == .unexpectedResponse)

        let pending = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order("ready")),
            .post(Fake.finalizeURL, 200, Body.order("pending")),
        ] + Steps.pendingAuthorization() + [
            Steps.readOrder(Body.order("ready")),
            .post(Fake.finalizeURL, 200, Body.order("pending")),
        ])
        #expect(pending.failure == .unexpectedResponse)
    }

    @Test("A pending order without an authorization returns unexpectedResponse")
    func pendingWithoutAuthorizations() {
        let run = ACMEScript().run(Steps.accountFound + [Steps.newOrder(Body.order("pending", authorizations: []))])
        #expect(run.failure == .unexpectedResponse)
    }

    @Test("A valid order without a certificate URL returns unexpectedResponse")
    func validWithoutCertificateURL() {
        let run = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order("ready")),
            .post(Fake.finalizeURL, 200, Body.order("valid")),
        ])
        #expect(run.failure == .unexpectedResponse)
    }

    @Test("An account with a status other than valid fails")
    func accountNotValid() {
        let run = ACMEScript().run([
            .get(Fake.directoryURL, 200, Body.directory()),
            .head(),
            .post(Fake.newAccountURL, 200, Body.account("deactivated"), location: Fake.accountURL),
        ])
        #expect(run.failure == .unexpectedResponse)
    }

    // MARK: Identifiers and counts

    @Test("An authorization for a name other than the requested name returns unexpectedResponse")
    func mismatchedAuthorizations() {
        let identifiers: [([String: String], Bool?)] = [
            (["type": "dns", "value": "rd-phone-1a2b3c4d.tail0001.ts.net"], nil),
            (["type": "ip", "value": Fake.domainName], nil),
            (["type": "dns", "value": Fake.domainName], true),
        ]
        for (identifier, wildcard) in identifiers {
            let run = ACMEScript().run(Steps.accountFound + [
                Steps.newOrder(Body.order("pending")),
                .post(Fake.authorizationURL(1), 200, Body.authorization("valid", identifier: identifier, wildcard: wildcard)),
            ])
            #expect(run.failure == .unexpectedResponse)
        }
    }

    @Test("Response identifiers that differ from the request return unexpectedResponse")
    func mismatchedOrderIdentifiers() {
        let run = ACMEScript().run(Steps.accountFound + [Steps.newOrder(Body.order("ready", identifiers: [
            ["type": "dns", "value": Fake.domainName], ["type": "dns", "value": "rd-phone-1a2b3c4d.tail0001.ts.net"],
        ]))])
        #expect(run.failure == .unexpectedResponse)
    }

    @Test("An authorization without dns-01 returns unexpectedResponse")
    func noDNS01Challenge() {
        let run = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order("pending")),
            .post(Fake.authorizationURL(1), 200, Body.authorization("pending", challenges: [
                Body.challenge(type: "http-01"), Body.challenge(type: "tls-alpn-01"),
            ])),
        ])
        #expect(run.failure == .unexpectedResponse)
    }

    @Test("A token that is not base64url returns unexpectedResponse", arguments: ["", "abc=", "a+b", String(repeating: "a", count: 513)])
    func invalidToken(token: String) {
        let run = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order("pending")),
            .post(Fake.authorizationURL(1), 200, Body.authorization("pending", challenges: [Body.challenge(token: token)])),
        ])
        #expect(run.failure == .unexpectedResponse)
        #expect(run.published.isEmpty)
    }

    @Test("Accepts 8 authorizations and returns unexpectedResponse for 9")
    func authorizationLimit() {
        let eight = (1...8).map(Fake.authorizationURL)
        let validAuthorization = Body.authorization("valid", challenges: [Body.challenge(status: "valid")])
        let accepted = ACMEScript().run(Steps.accountFound + [Steps.newOrder(Body.order("pending", authorizations: eight))]
            + eight.map { .post($0, 200, validAuthorization) }
            + [Steps.readOrder(Body.order("ready", authorizations: eight)), Steps.finalizeValid, Steps.download])
        #expect(accepted.result == issued)

        let nine = (1...9).map(Fake.authorizationURL)
        let rejected = ACMEScript().run(Steps.accountFound + [Steps.newOrder(Body.order("pending", authorizations: nine))])
        #expect(rejected.failure == .unexpectedResponse)
    }

    // MARK: URLs and sizes

    @Test("A URL without https or over 2,048 bytes returns unexpectedResponse")
    func unacceptableURLs() {
        let long = "https://acme.invalid/" + String(repeating: "a", count: 2048 - 21 + 1)
        let exact = "https://acme.invalid/" + String(repeating: "a", count: 2048 - 21)
        #expect(exact.utf8.count == 2048)
        for finalize in ["http://acme.invalid/order/1/finalize", long, "acme.invalid/finalize", "https:///nohost"] {
            let run = ACMEScript().run(Steps.accountFound + [Steps.newOrder(Body.order("ready", finalize: finalize))])
            #expect(run.failure == .unexpectedResponse)
        }
        let accepted = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order("ready", finalize: exact)),
            .post(exact, 200, Body.order("valid", certificate: Fake.certificateURL)),
            Steps.download,
        ])
        #expect(accepted.result == issued)

        let location = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order("ready"), location: "http://acme.invalid/order/1"),
        ])
        #expect(location.failure == .unexpectedResponse)

        let directory = ACMEScript().run([.get(Fake.directoryURL, 200, Body.directory(newNonce: "http://acme.invalid/nonce"))])
        #expect(directory.failure == .unexpectedResponse)
    }

    /// Do not follow a server-provided URL to send a request signed with the account key to another host, including loopback.
    @Test("A URL from an origin different from the directory returns unexpectedResponse without a request", arguments: [
        "https://other.invalid/order/1/finalize", "https://127.0.0.1:8443/finalize", "https://acme.invalid:8443/finalize",
    ])
    func crossOriginURLs(_ url: String) {
        let finalize = ACMEScript().run(Steps.accountFound + [Steps.newOrder(Body.order("ready", finalize: url))])
        #expect(finalize.failure == .unexpectedResponse)
        let authorization = ACMEScript().run(Steps.accountFound + [Steps.newOrder(Body.order("pending", authorizations: [url]))])
        #expect(authorization.failure == .unexpectedResponse)
        let nonce = ACMEScript().run([.get(Fake.directoryURL, 200, Body.directory(newNonce: url))])
        #expect(nonce.failure == .unexpectedResponse)
    }

    @Test("A directory URL without https ends the flow without a request")
    func plainDirectoryURL() {
        var script = ACMEScript()
        script.directoryURL = "http://acme.invalid/directory"
        let run = script.run([])
        #expect(run.failure == .unexpectedResponse)
        #expect(run.requests.isEmpty)
    }

    @Test("A JSON response over 64KiB returns unexpectedResponse")
    func oversizedJSON() {
        var object = String(decoding: Body.order("ready"), as: UTF8.self)
        object.removeLast()
        let padded = object + #","padding":""# + String(repeating: "a", count: 64 * 1024) + #""}"#
        let run = ACMEScript().run(Steps.accountFound + [Steps.newOrder(Array(padded.utf8))])
        #expect(run.failure == .unexpectedResponse)
    }

    @Test("A certificate response over 256KiB returns unexpectedResponse")
    func oversizedChain() {
        let run = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order("ready")),
            Steps.finalizeValid,
            .post(Fake.certificateURL, 200, [UInt8](repeating: 0x41, count: 256 * 1024 + 1)),
        ])
        #expect(run.failure == .unexpectedResponse)
    }

    @Test("A non-JSON response or a response with missing fields returns unexpectedResponse")
    func malformedBodies() {
        for body in [Array("not json".utf8), Body.json(["status": "ready"]), Body.json([1, 2])] {
            let run = ACMEScript().run(Steps.accountFound + [Steps.newOrder(body)])
            #expect(run.failure == .unexpectedResponse)
        }
    }

    @Test("An unexpected success status code returns unexpectedResponse")
    func unexpectedSuccessStatus() {
        let run = ACMEScript().run(Steps.accountFound + [.post(Fake.newOrderURL, 200, Body.order("ready"), location: Fake.orderURL)])
        #expect(run.failure == .unexpectedResponse)
    }

    // MARK: nonce

    @Test("After a response without a nonce, obtain one with HEAD newNonce")
    func missingNonceFetchesNew() {
        let run = ACMEScript().run([
            .get(Fake.directoryURL, 200, Body.directory()),
            .head(),
            .post(Fake.newAccountURL, 200, Body.account(), location: Fake.accountURL).nonce(.omitted),
            .head(),
            Steps.newOrder(Body.order("ready")).nonce(.value("bad nonce!")),
            .head(),
            Steps.finalizeValid,
            Steps.download,
        ])
        #expect(run.result == issued)
        #expect(run.requests(to: Fake.newNonceURL).count == 3)
    }

    @Test("A newNonce response without a nonce returns unexpectedResponse")
    func newNonceWithoutNonce() {
        let run = ACMEScript().run([.get(Fake.directoryURL, 200, Body.directory()), .head(nonce: .omitted)])
        #expect(run.failure == .unexpectedResponse)
    }

    @Test("On badNonce, sign again with the response nonce and resend up to 3 times", arguments: [1, 3])
    func badNonceRetried(times: Int) {
        let badNonce = Exchange.post(Fake.newOrderURL, 400, Body.problem(Fake.problem("badNonce")))
        let run = ACMEScript().run(Steps.accountFound + Array(repeating: badNonce, count: times) + Steps.readyToIssued)
        #expect(run.result == issued)
        #expect(run.requests(to: Fake.newOrderURL).count == times + 1)
    }

    @Test("The fourth badNonce fails")
    func badNonceFourTimes() {
        let badNonce = Exchange.post(Fake.newOrderURL, 400, Body.problem(Fake.problem("badNonce")))
        let run = ACMEScript().run(Steps.accountFound + Array(repeating: badNonce, count: 4))
        #expect(run.failure == .acme(status: 400, type: Fake.problem("badNonce")))
        #expect(run.unusedExchanges == 0)
    }

    @Test("On badNonce without a response nonce, get one from newNonce and resend")
    func badNonceWithoutNonce() {
        let run = ACMEScript().run(Steps.accountFound + [
            Exchange.post(Fake.newOrderURL, 400, Body.problem(Fake.problem("badNonce"))).nonce(.omitted),
            .head(),
        ] + Steps.readyToIssued)
        #expect(run.result == issued)
    }

    @Test("Counts badNonce occurrences separately per request")
    func badNonceCountedPerRequest() {
        let badOrder = Exchange.post(Fake.newOrderURL, 400, Body.problem(Fake.problem("badNonce")))
        let badFinalize = Exchange.post(Fake.finalizeURL, 400, Body.problem(Fake.problem("badNonce")))
        let run = ACMEScript().run(Steps.accountFound + [badOrder, badOrder, badOrder, Steps.newOrder(Body.order("ready")),
                                                         badFinalize, badFinalize, badFinalize, Steps.finalizeValid, Steps.download])
        #expect(run.result == issued)
    }

    // MARK: Retry-After

    @Test("Order polling honors Retry-After in seconds")
    func retryAfterSeconds() {
        let run = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order("ready")),
            Exchange.post(Fake.finalizeURL, 200, Body.order("processing")).header("Retry-After", "7"),
            Steps.readOrder(Body.order("valid", certificate: Fake.certificateURL)),
            Steps.download,
        ])
        #expect(run.result == issued)
        #expect(run.waits == [Fake.start.addingTimeInterval(7)])
    }

    @Test("Honors an HTTP date in Retry-After and uses 1-second intervals for past dates and unparseable values")
    func retryAfterDates() {
        let cases: [(String, TimeInterval)] = [
            (Self.imfDate(Fake.start.addingTimeInterval(42)), 42),
            (Self.imfDate(Fake.start.addingTimeInterval(-3600)), 1),
            ("soon", 1),
            ("-5", 1),
            ("0", 1),
        ]
        for (value, delay) in cases {
            let run = ACMEScript().run(Steps.accountFound + [
                Steps.newOrder(Body.order("ready")),
                Exchange.post(Fake.finalizeURL, 200, Body.order("processing")).header("Retry-After", value),
                Steps.readOrder(Body.order("valid", certificate: Fake.certificateURL)),
                Steps.download,
            ])
            #expect(run.result == issued, "\(value)")
            #expect(run.waits == [Fake.start.addingTimeInterval(delay)], "\(value)")
        }
    }

    @Test("If Retry-After exceeds the 5-minute deadline, returns timedOut immediately and includes that time in the result")
    func retryAfterBeyondDeadline() {
        let run = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order("ready")),
            Exchange.post(Fake.finalizeURL, 200, Body.order("processing")).header("Retry-After", "600"),
        ])
        #expect(run.failure == .timedOut)
        #expect(run.retryNotBefore == Fake.start.addingTimeInterval(600))
        #expect(run.waits.isEmpty)
    }

    @Test("rateLimited includes the server-provided time, capped at 7 days")
    func rateLimited() {
        let soon = ACMEScript().run(Steps.accountFound + [
            Exchange.post(Fake.newOrderURL, 429, Body.problem(Fake.problem("rateLimited"), status: 429)).header("Retry-After", "3600"),
        ])
        let hour = Fake.start.addingTimeInterval(3600)
        #expect(soon.failure == .rateLimited(retryAfter: hour))
        #expect(soon.retryNotBefore == hour)

        let far = ACMEScript().run(Steps.accountFound + [
            Exchange.post(Fake.newOrderURL, 429, Body.problem(Fake.problem("rateLimited"), status: 429))
                .header("Retry-After", Self.imfDate(Fake.start.addingTimeInterval(30 * 86_400))),
        ])
        let week = Fake.start.addingTimeInterval(7 * 86_400)
        #expect(far.failure == .rateLimited(retryAfter: week))
        #expect(far.retryNotBefore == week)

        let none = ACMEScript().run(Steps.accountFound + [
            Exchange.post(Fake.newOrderURL, 429, Body.problem(Fake.problem("rateLimited"), status: 429)),
        ])
        #expect(none.failure == .rateLimited(retryAfter: nil))
        #expect(none.retryNotBefore == nil)
    }

    @Test("A 5xx Retry-After is also included in the result")
    func serverErrorRetryAfter() {
        let run = ACMEScript().run(Steps.accountFound + [
            Exchange.post(Fake.newOrderURL, 503, Body.problem(Fake.problem("serverInternal"), status: 503)).header("Retry-After", "120"),
        ])
        #expect(run.failure == .acme(status: 503, type: Fake.problem("serverInternal")))
        #expect(run.retryNotBefore == Fake.start.addingTimeInterval(120))
    }

    @Test("Retry-After on any response keeps the next request from being sent before that time")
    func retryAfterOnAnyResponse() {
        let run = ACMEScript().run([
            .get(Fake.directoryURL, 200, Body.directory()),
            Exchange.head().header("Retry-After", "30"),
            .post(Fake.newAccountURL, 200, Body.account(), location: Fake.accountURL),
        ] + Steps.readyToIssued)
        #expect(run.result == issued)
        #expect(run.waits == [Fake.start.addingTimeInterval(30)])
        #expect(run.requests.dropFirst(2).allSatisfy { $0.time >= Fake.start.addingTimeInterval(30) })
    }

    // MARK: Problem documents

    @Test("Represents an error response's problem document by its full type string")
    func problemDocuments() {
        let long = "https://acme.invalid/problems/" + String(repeating: "가", count: 100)
        let cases: [([UInt8], String)] = [
            (Body.problem(Fake.problem("badCSR")), Fake.problem("badCSR")),
            (Array("<html>500</html>".utf8), ""),
            ([], ""),
            (Body.problem(nil), ""),
            (Body.json(["type": 42]), ""),
            (Body.problem("about:blank"), "about:blank"),
            (Body.problem("https://acme.invalid/problems/quota"), "https://acme.invalid/problems/quota"),
            (Body.problem(long), String(long.prefix(30 + 75))),
            (Body.json(["type": Fake.problem("rejectedIdentifier"), "subproblems": [
                ["type": Fake.problem("caa"), "identifier": ["type": "dns", "value": Fake.domainName]],
            ]]), Fake.problem("rejectedIdentifier")),
            (Body.problem("https://acme.invalid/urn:ietf:params:acme:error:badNonce"), "https://acme.invalid/urn:ietf:params:acme:error:badNonce"),
            (Body.problem(Fake.problem("userActionRequired")), Fake.problem("userActionRequired")),
        ]
        for (body, type) in cases {
            let run = ACMEScript().run(Steps.accountFound + [
                Exchange.post(Fake.newOrderURL, 403, body).header("Content-Type", "application/problem+json"),
            ])
            #expect(run.failure == .acme(status: 403, type: type))
            // A suffix that mimics badNonce does not cause a resend.
            #expect(run.requests(to: Fake.newOrderURL).count == 1)
        }
        #expect(String(long.prefix(105)).utf8.count == 30 + 225)
    }

    @Test("Treats redirects as errors without following them")
    func redirectIsError() {
        let run = ACMEScript().run(Steps.accountFound + [
            Exchange.post(Fake.newOrderURL, 302, []).header("Location", "https://other.invalid/new-order"),
        ])
        #expect(run.failure == .acme(status: 302, type: ""))
    }

    // MARK: Transport, TXT, and deadlines

    @Test("A transport failure ends with that failure type")
    func transportFailures() {
        let cases: [(ACMETransportError, CertificateFailure)] = [
            (.network, .network("ACME server unreachable")), (.timedOut, .timedOut),
            (.responseTooLarge, .unexpectedResponse), (.invalidURL, .unexpectedResponse),
        ]
        for (error, failure) in cases {
            var flow = ACMEScript().flow
            guard case .send = flow.start(at: Fake.start) else {
                Issue.record("The first step must request the directory")
                continue
            }
            #expect(flow.transportFailed(error, at: Fake.start) == .finished(.failed(failure, retryNotBefore: nil, accountURL: nil)))
        }
    }

    @Test("Failure to publish TXT ends with that failure and sends no challenge response")
    func publishFailure() {
        var script = ACMEScript()
        script.publishFailure = .controlRejected(status: 403)
        let run = script.run(Steps.accountFound + [Steps.newOrder(Body.order("pending"))] + Steps.pendingAuthorization())
        #expect(run.failure == .controlRejected(status: 403))
        #expect(run.requests(to: Fake.challengeURL(1)).isEmpty)
        #expect(run.unusedExchanges == 1)
    }

    @Test("A response received after the 5-minute deadline returns timedOut")
    func deadline() {
        var script = ACMEScript()
        script.latency = 100
        let run = script.run(Steps.accountFound + Steps.readyToIssued)
        #expect(run.failure == .timedOut)
        #expect(run.finishedAt == Fake.start.addingTimeInterval(300))
    }

    @Test("Input after completion returns the same result, and unexpected input does not cause a crash")
    func misuse() {
        var flow = ACMEScript().flow
        let response = ACMEHTTPResponse(status: 200, headers: [], body: [])
        let failed = ACMEOrderFlow.Step.finished(.failed(.unexpectedResponse, retryNotBefore: nil, accountURL: nil))
        #expect(flow.receive(response, at: Fake.start) == failed)
        #expect(flow.resume(at: Fake.start) == failed)
        #expect(flow.txtPublished(at: Fake.start) == failed)
        #expect(flow.start(at: Fake.start) == failed)
    }

    @Test("dump omits the key, account URL, and name")
    func mirrorHidesSecrets() {
        var script = ACMEScript()
        script.accountURL = Fake.accountURL
        let flow = script.flow
        var text = ""
        dump(flow, to: &text)
        #expect(!text.contains(Fake.accountURL))
        #expect(!text.contains("tail0001"))
        #expect(!text.contains("rawRepresentation"))
        #expect(!String(describing: flow).contains("tail0001"))
    }

    static func imfDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = .gmt
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss 'GMT'"
        return formatter.string(from: date)
    }
}
