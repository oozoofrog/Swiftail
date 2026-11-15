// 계약 7절 시험 8의 실패 갈래: finalize의 invalid·모르는 상태·되풀이 초과, 주문·authorization의 invalid와
// deactivated·expired·revoked, badNonce 한 번·세 번·네 번, Retry-After(초·날짜·지난 날짜·읽지 못함·5분 기한·7일),
// rateLimited, 문제 문서, 식별자·wildcard·개수·URL·크기·nonce의 경계, 전송·TXT의 실패, 기한.

import Foundation
import Testing

@testable import SwiftailCertificates

@Suite("ACME 주문 절차: 실패 갈래")
struct ACMEOrderFlowFailureTests {
    private let issued = ACMEIssuanceResult.issued(certificateChainPEM: Fake.chainPEM, accountURL: Fake.accountURL)

    // MARK: 주문과 authorization의 상태

    @Test("finalize 응답이 invalid이고 authorization이 invalid면 validationFailed")
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

    @Test("주문이 invalid인데 authorization이 모두 valid면 orderFailed(주문의 error)")
    func pollInvalidWithoutAuthorizationFailure() {
        let run = ACMEScript().run(Steps.accountFound + [Steps.newOrder(Body.order("pending"))] + Steps.pendingAuthorization() + [
            Steps.readOrder(Body.order("invalid", errorType: Fake.problem("badCSR"))),
            .post(Fake.authorizationURL(1), 200, Body.authorization("valid", challenges: [Body.challenge(status: "valid")])),
        ])
        #expect(run.failure == .orderFailed(type: Fake.problem("badCSR")))
    }

    @Test("새 주문이 처음부터 invalid면 orderFailed")
    func createdInvalid() {
        let run = ACMEScript().run(Steps.accountFound + [Steps.newOrder(Body.order("invalid"))])
        #expect(run.failure == .orderFailed(type: ""))
    }

    @Test("authorization이 invalid면 validationFailed(challenge의 error)")
    func authorizationInvalid() {
        let run = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order("pending")),
            .post(Fake.authorizationURL(1), 200, Body.authorization("invalid", challenges: [
                Body.challenge(type: "http-01"), Body.challenge(status: "invalid", errorType: Fake.problem("incorrectResponse")),
            ])),
        ])
        #expect(run.failure == .validationFailed(type: Fake.problem("incorrectResponse")))
    }

    @Test("challenge가 invalid면 validationFailed")
    func challengeInvalid() {
        let run = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order("pending")),
            .post(Fake.authorizationURL(1), 200, Body.authorization("pending", challenges: [
                Body.challenge(status: "invalid", errorType: Fake.problem("dns")),
            ])),
        ])
        #expect(run.failure == .validationFailed(type: Fake.problem("dns")))
    }

    @Test("이어 갈 수 없는 authorization은 orderFailed", arguments: ["deactivated", "expired", "revoked"])
    func unusableAuthorization(status: String) {
        let run = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order("pending")),
            .post(Fake.authorizationURL(1), 200, Body.authorization(status)),
        ])
        #expect(run.failure == .orderFailed(type: ""))
    }

    @Test("모르는 상태는 unexpectedResponse")
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

    @Test("finalize 뒤 ready·pending의 두 번째 되풀이는 unexpectedResponse")
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

    @Test("pending 주문에 authorization이 없으면 unexpectedResponse")
    func pendingWithoutAuthorizations() {
        let run = ACMEScript().run(Steps.accountFound + [Steps.newOrder(Body.order("pending", authorizations: []))])
        #expect(run.failure == .unexpectedResponse)
    }

    @Test("valid 주문에 certificate URL이 없으면 unexpectedResponse")
    func validWithoutCertificateURL() {
        let run = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order("ready")),
            .post(Fake.finalizeURL, 200, Body.order("valid")),
        ])
        #expect(run.failure == .unexpectedResponse)
    }

    @Test("계정의 status가 valid가 아니면 실패")
    func accountNotValid() {
        let run = ACMEScript().run([
            .get(Fake.directoryURL, 200, Body.directory()),
            .head(),
            .post(Fake.newAccountURL, 200, Body.account("deactivated"), location: Fake.accountURL),
        ])
        #expect(run.failure == .unexpectedResponse)
    }

    // MARK: 식별자와 개수

    @Test("요청한 이름이 아닌 authorization은 unexpectedResponse")
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

    @Test("응답의 identifiers가 요청과 다르면 unexpectedResponse")
    func mismatchedOrderIdentifiers() {
        let run = ACMEScript().run(Steps.accountFound + [Steps.newOrder(Body.order("ready", identifiers: [
            ["type": "dns", "value": Fake.domainName], ["type": "dns", "value": "rd-phone-1a2b3c4d.tail0001.ts.net"],
        ]))])
        #expect(run.failure == .unexpectedResponse)
    }

    @Test("dns-01이 없는 authorization은 unexpectedResponse")
    func noDNS01Challenge() {
        let run = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order("pending")),
            .post(Fake.authorizationURL(1), 200, Body.authorization("pending", challenges: [
                Body.challenge(type: "http-01"), Body.challenge(type: "tls-alpn-01"),
            ])),
        ])
        #expect(run.failure == .unexpectedResponse)
    }

    @Test("token이 base64url이 아니면 unexpectedResponse", arguments: ["", "abc=", "a+b", String(repeating: "a", count: 513)])
    func invalidToken(token: String) {
        let run = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order("pending")),
            .post(Fake.authorizationURL(1), 200, Body.authorization("pending", challenges: [Body.challenge(token: token)])),
        ])
        #expect(run.failure == .unexpectedResponse)
        #expect(run.published.isEmpty)
    }

    @Test("authorization 8개는 받고 9개는 unexpectedResponse")
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

    // MARK: URL과 크기

    @Test("https가 아니거나 2,048바이트를 넘는 URL은 unexpectedResponse")
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

    @Test("디렉터리 URL이 https가 아니면 요청 없이 끝난다")
    func plainDirectoryURL() {
        var script = ACMEScript()
        script.directoryURL = "http://acme.invalid/directory"
        let run = script.run([])
        #expect(run.failure == .unexpectedResponse)
        #expect(run.requests.isEmpty)
    }

    @Test("64KiB를 넘는 JSON 응답은 unexpectedResponse")
    func oversizedJSON() {
        var object = String(decoding: Body.order("ready"), as: UTF8.self)
        object.removeLast()
        let padded = object + #","padding":""# + String(repeating: "a", count: 64 * 1024) + #""}"#
        let run = ACMEScript().run(Steps.accountFound + [Steps.newOrder(Array(padded.utf8))])
        #expect(run.failure == .unexpectedResponse)
    }

    @Test("256KiB를 넘는 인증서 응답은 unexpectedResponse")
    func oversizedChain() {
        let run = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order("ready")),
            Steps.finalizeValid,
            .post(Fake.certificateURL, 200, [UInt8](repeating: 0x41, count: 256 * 1024 + 1)),
        ])
        #expect(run.failure == .unexpectedResponse)
    }

    @Test("JSON이 아니거나 필드가 빠진 응답은 unexpectedResponse")
    func malformedBodies() {
        for body in [Array("not json".utf8), Body.json(["status": "ready"]), Body.json([1, 2])] {
            let run = ACMEScript().run(Steps.accountFound + [Steps.newOrder(body)])
            #expect(run.failure == .unexpectedResponse)
        }
    }

    @Test("기대한 것과 다른 성공 상태 코드는 unexpectedResponse")
    func unexpectedSuccessStatus() {
        let run = ACMEScript().run(Steps.accountFound + [.post(Fake.newOrderURL, 200, Body.order("ready"), location: Fake.orderURL)])
        #expect(run.failure == .unexpectedResponse)
    }

    // MARK: nonce

    @Test("nonce가 없는 응답 뒤에는 HEAD newNonce로 얻는다")
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

    @Test("newNonce 응답에 nonce가 없으면 unexpectedResponse")
    func newNonceWithoutNonce() {
        let run = ACMEScript().run([.get(Fake.directoryURL, 200, Body.directory()), .head(nonce: .omitted)])
        #expect(run.failure == .unexpectedResponse)
    }

    @Test("badNonce는 그 응답의 nonce로 다시 서명해 3번까지 다시 보낸다", arguments: [1, 3])
    func badNonceRetried(times: Int) {
        let badNonce = Exchange.post(Fake.newOrderURL, 400, Body.problem(Fake.problem("badNonce")))
        let run = ACMEScript().run(Steps.accountFound + Array(repeating: badNonce, count: times) + Steps.readyToIssued)
        #expect(run.result == issued)
        #expect(run.requests(to: Fake.newOrderURL).count == times + 1)
    }

    @Test("badNonce 네 번째는 실패")
    func badNonceFourTimes() {
        let badNonce = Exchange.post(Fake.newOrderURL, 400, Body.problem(Fake.problem("badNonce")))
        let run = ACMEScript().run(Steps.accountFound + Array(repeating: badNonce, count: 4))
        #expect(run.failure == .acme(status: 400, type: Fake.problem("badNonce")))
        #expect(run.unusedExchanges == 0)
    }

    @Test("badNonce 응답에 nonce가 없으면 newNonce로 얻어 다시 보낸다")
    func badNonceWithoutNonce() {
        let run = ACMEScript().run(Steps.accountFound + [
            Exchange.post(Fake.newOrderURL, 400, Body.problem(Fake.problem("badNonce"))).nonce(.omitted),
            .head(),
        ] + Steps.readyToIssued)
        #expect(run.result == issued)
    }

    @Test("요청마다 badNonce 횟수를 따로 센다")
    func badNonceCountedPerRequest() {
        let badOrder = Exchange.post(Fake.newOrderURL, 400, Body.problem(Fake.problem("badNonce")))
        let badFinalize = Exchange.post(Fake.finalizeURL, 400, Body.problem(Fake.problem("badNonce")))
        let run = ACMEScript().run(Steps.accountFound + [badOrder, badOrder, badOrder, Steps.newOrder(Body.order("ready")),
                                                         badFinalize, badFinalize, badFinalize, Steps.finalizeValid, Steps.download])
        #expect(run.result == issued)
    }

    // MARK: Retry-After

    @Test("주문 다시 읽기는 Retry-After(초)를 지킨다")
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

    @Test("Retry-After의 HTTP 날짜를 지키고, 지난 날짜·읽지 못하는 값은 1초 간격이다")
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

    @Test("Retry-After가 5분 기한을 넘으면 기다리지 않고 timedOut, 그 시각을 결과에 싣는다")
    func retryAfterBeyondDeadline() {
        let run = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order("ready")),
            Exchange.post(Fake.finalizeURL, 200, Body.order("processing")).header("Retry-After", "600"),
        ])
        #expect(run.failure == .timedOut)
        #expect(run.retryNotBefore == Fake.start.addingTimeInterval(600))
        #expect(run.waits.isEmpty)
    }

    @Test("rateLimited는 서버가 준 시각을 싣고, 7일로 묶는다")
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

    @Test("5xx의 Retry-After도 결과에 싣는다")
    func serverErrorRetryAfter() {
        let run = ACMEScript().run(Steps.accountFound + [
            Exchange.post(Fake.newOrderURL, 503, Body.problem(Fake.problem("serverInternal"), status: 503)).header("Retry-After", "120"),
        ])
        #expect(run.failure == .acme(status: 503, type: Fake.problem("serverInternal")))
        #expect(run.retryNotBefore == Fake.start.addingTimeInterval(120))
    }

    @Test("어느 응답의 Retry-After든 그 시각 전에는 다음 요청을 보내지 않는다")
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

    // MARK: 문제 문서

    @Test("오류 응답의 문제 문서는 type 전체 문자열로 든다")
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
            // 접미사로 흉내 낸 badNonce는 다시 보내지 않는다.
            #expect(run.requests(to: Fake.newOrderURL).count == 1)
        }
        #expect(String(long.prefix(105)).utf8.count == 30 + 225)
    }

    @Test("리다이렉트는 따르지 않고 오류로 본다")
    func redirectIsError() {
        let run = ACMEScript().run(Steps.accountFound + [
            Exchange.post(Fake.newOrderURL, 302, []).header("Location", "https://other.invalid/new-order"),
        ])
        #expect(run.failure == .acme(status: 302, type: ""))
    }

    // MARK: 전송, TXT, 기한

    @Test("전송의 실패는 그 종류로 끝난다")
    func transportFailures() {
        let cases: [(ACMETransportError, CertificateFailure)] = [
            (.network, .network("ACME server unreachable")), (.timedOut, .timedOut),
            (.responseTooLarge, .unexpectedResponse), (.invalidURL, .unexpectedResponse),
        ]
        for (error, failure) in cases {
            var flow = ACMEScript().flow
            guard case .send = flow.start(at: Fake.start) else {
                Issue.record("첫 단계는 디렉터리 요청이어야 한다")
                continue
            }
            #expect(flow.transportFailed(error, at: Fake.start) == .finished(.failed(failure, retryNotBefore: nil, accountURL: nil)))
        }
    }

    @Test("TXT를 올리지 못하면 그 실패로 끝나고 challenge에 응답하지 않는다")
    func publishFailure() {
        var script = ACMEScript()
        script.publishFailure = .controlRejected(status: 403)
        let run = script.run(Steps.accountFound + [Steps.newOrder(Body.order("pending"))] + Steps.pendingAuthorization())
        #expect(run.failure == .controlRejected(status: 403))
        #expect(run.requests(to: Fake.challengeURL(1)).isEmpty)
        #expect(run.unusedExchanges == 1)
    }

    @Test("5분 기한이 지나 받은 응답은 timedOut")
    func deadline() {
        var script = ACMEScript()
        script.latency = 100
        let run = script.run(Steps.accountFound + Steps.readyToIssued)
        #expect(run.failure == .timedOut)
        #expect(run.finishedAt == Fake.start.addingTimeInterval(300))
    }

    @Test("끝난 뒤의 입력은 같은 결과를 돌려주고, 기다리지 않은 입력은 죽지 않는다")
    func misuse() {
        var flow = ACMEScript().flow
        let response = ACMEHTTPResponse(status: 200, headers: [], body: [])
        let failed = ACMEOrderFlow.Step.finished(.failed(.unexpectedResponse, retryNotBefore: nil, accountURL: nil))
        #expect(flow.receive(response, at: Fake.start) == failed)
        #expect(flow.resume(at: Fake.start) == failed)
        #expect(flow.txtPublished(at: Fake.start) == failed)
        #expect(flow.start(at: Fake.start) == failed)
    }

    @Test("dump에 키·계정 URL·이름이 나오지 않는다")
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
