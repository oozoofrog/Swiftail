// 계약 7절 시험 8의 정상 갈래: 노트 4.3의 열두 단계, 계정이 있음·없음·이미 앎, authorization이 이미 valid·둘,
// challenge가 이미 processing, 주문이 처음부터 ready·valid·processing, processing을 여러 번 거침, finalize 응답의
// 다섯 상태와 orderNotReady.

import CryptoKit
import Foundation
import Testing

@testable import SwiftailCertificates

@Suite("ACME 주문 절차: 정상 갈래")
struct ACMEOrderFlowPathTests {
    private let issued = ACMEIssuanceResult.issued(certificateChainPEM: Fake.chainPEM, accountURL: Fake.accountURL)

    @Test("열두 단계의 기본 길")
    func basicPath() throws {
        let script = ACMEScript()
        let run = script.run(Steps.accountFound + [Steps.newOrder(Body.order("pending"))] + Steps.pendingAuthorization() + [
            Steps.readOrder(Body.order("pending")),
            Steps.readOrder(Body.order("ready")),
            .post(Fake.finalizeURL, 200, Body.order("processing")),
            Steps.readOrder(Body.order("valid", certificate: Fake.certificateURL)),
            Steps.download,
        ])
        #expect(run.result == issued)
        #expect(run.unusedExchanges == 0)

        // 계정 찾기는 onlyReturnExisting(RFC 8555 7.3.1), 주문은 dns 식별자 하나(7.4).
        #expect(run.requests(to: Fake.newAccountURL).first?.payloadObject?["onlyReturnExisting"] as? Bool == true)
        let identifiers = run.requests(to: Fake.newOrderURL).first?.payloadObject?["identifiers"] as? [[String: String]]
        #expect(identifiers == [["type": "dns", "value": Fake.domainName]])

        // TXT 이름과 값(노트 3.5), 그 뒤의 challenge 응답은 `{}`(RFC 8555 7.5.1).
        let value = KeyAuthorization(token: Fake.token(1), accountKey: JWK(script.accountKey.publicKey)).dns01TXTValue
        #expect(run.published.map(\.name) == ["_acme-challenge." + Fake.domainName])
        #expect(run.published.map(\.value) == [value])
        #expect(run.requests(to: Fake.challengeURL(1)).map(\.payload) == [Array("{}".utf8)])

        // POST-as-GET은 빈 payload(RFC 8555 6.3).
        for url in [Fake.authorizationURL(1), Fake.orderURL, Fake.certificateURL] {
            #expect(run.requests(to: url).allSatisfy { $0.payload.isEmpty })
        }

        // finalize의 CSR은 인증서 키의 것이다.
        let csr = try #require(finalizedCSRs(run).first)
        #expect(csrInfoMatches(csr, key: script.certificateKey))
        #expect(!csrInfoMatches(csr, key: script.accountKey))

        // 내려받기만 Accept를 싣는다(계약 C7).
        #expect(run.requests(to: Fake.certificateURL).map(\.request.accept) == ["application/pem-certificate-chain"])
        #expect(run.requests.filter { $0.request.url != Fake.certificateURL }.allSatisfy { $0.request.accept == nil })

        // challenge 응답 직후의 첫 읽기는 곧바로, 그 뒤의 다시 읽기는 1초 간격이다.
        #expect(run.waits == [Fake.start.addingTimeInterval(1), Fake.start.addingTimeInterval(2)])
    }

    @Test("계정이 없으면 약관에 동의해 만든다")
    func createsAccountWhenMissing() {
        let run = ACMEScript().run([
            .get(Fake.directoryURL, 200, Body.directory()),
            .head(),
            .post(Fake.newAccountURL, 400, Body.problem(Fake.problem("accountDoesNotExist"))),
            .post(Fake.newAccountURL, 201, Body.account(), location: Fake.accountURL),
        ] + Steps.readyToIssued)
        #expect(run.result == issued)
        let payloads = run.requests(to: Fake.newAccountURL).map(\.payloadObject)
        #expect(payloads.count == 2)
        #expect(payloads.last??["termsOfServiceAgreed"] as? Bool == true)
        #expect(payloads.last??["onlyReturnExisting"] == nil)
    }

    @Test("만들기가 200(같은 키의 계정이 이미 있음)이어도 그 계정을 쓴다")
    func createAccountReturnsExisting() {
        let run = ACMEScript().run([
            .get(Fake.directoryURL, 200, Body.directory()),
            .head(),
            .post(Fake.newAccountURL, 400, Body.problem(Fake.problem("accountDoesNotExist"))),
            .post(Fake.newAccountURL, 200, Body.account(), location: Fake.accountURL),
        ] + Steps.readyToIssued)
        #expect(run.result == issued)
    }

    @Test("계정 URL을 이미 알면 계정 찾기를 건너뛰고 kid로 주문한다")
    func knownAccountSkipsLookup() {
        var script = ACMEScript()
        script.accountURL = Fake.accountURL
        let run = script.run([.get(Fake.directoryURL, 200, Body.directory()), .head()] + Steps.readyToIssued)
        #expect(run.result == issued)
        #expect(run.requests(to: Fake.newAccountURL).isEmpty)
    }

    @Test("이미 valid인 authorization은 TXT를 올리지 않는다")
    func validAuthorizationIsSkipped() {
        let run = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order("pending")),
            .post(Fake.authorizationURL(1), 200, Body.authorization("valid", challenges: [Body.challenge(status: "valid")])),
            Steps.readOrder(Body.order("ready")),
            Steps.finalizeValid,
            Steps.download,
        ])
        #expect(run.result == issued)
        #expect(run.published.isEmpty)
        #expect(run.requests(to: Fake.challengeURL(1)).isEmpty)
    }

    @Test("authorization 둘(하나는 valid)을 모두 처리한다")
    func twoAuthorizations() {
        let authorizations = [Fake.authorizationURL(1), Fake.authorizationURL(2)]
        let run = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order("pending", authorizations: authorizations)),
            .post(Fake.authorizationURL(1), 200, Body.authorization("valid", challenges: [Body.challenge(status: "valid")])),
        ] + Steps.pendingAuthorization(2) + [
            Steps.readOrder(Body.order("ready", authorizations: authorizations)),
            Steps.finalizeValid,
            Steps.download,
        ])
        #expect(run.result == issued)
        #expect(run.published.count == 1)
    }

    @Test("challenge가 이미 processing이면 레코드만 올리고 응답은 다시 보내지 않는다")
    func processingChallenge() {
        let run = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order("pending")),
            .post(Fake.authorizationURL(1), 200, Body.authorization("pending", challenges: [Body.challenge(status: "processing")])),
            Steps.readOrder(Body.order("ready")),
            Steps.finalizeValid,
            Steps.download,
        ])
        #expect(run.result == issued)
        #expect(run.published.count == 1)
        #expect(run.requests(to: Fake.challengeURL(1)).isEmpty)
    }

    @Test("pending authorization의 challenge가 이미 valid면 건너뛴다")
    func validChallengeIsSkipped() {
        let run = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order("pending")),
            .post(Fake.authorizationURL(1), 200, Body.authorization("pending", challenges: [Body.challenge(status: "valid")])),
            Steps.readOrder(Body.order("ready")),
            Steps.finalizeValid,
            Steps.download,
        ])
        #expect(run.result == issued)
        #expect(run.published.isEmpty)
    }

    @Test("주문이 처음부터 ready면 authorization을 건너뛰고 finalize한다")
    func readyOrder() {
        let run = ACMEScript().run(Steps.accountFound + Steps.readyToIssued)
        #expect(run.result == issued)
        #expect(run.requests(to: Fake.authorizationURL(1)).isEmpty)
    }

    @Test("CSR 전에 valid·processing인 주문은 새 주문으로 한 번 다시 시작한다", arguments: ["valid", "processing"])
    func orderBeforeCSRRestarts(status: String) {
        let run = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order(status, certificate: Fake.certificateURL)),
            Steps.newOrder(Body.order("ready"), location: Fake.secondOrderURL),
            Steps.finalizeValid,
            Steps.download,
        ])
        #expect(run.result == issued)
        // 첫 주문의 인증서를 받지 않았다: 대응하는 개인 키가 없다(계약 C5).
        #expect(run.requests(to: Fake.newOrderURL).count == 2)
        #expect(run.requests(to: Fake.certificateURL).count == 1)
    }

    @Test("새 주문도 CSR 전에 valid면 orderFailed")
    func secondRestartFails() {
        let run = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order("valid", certificate: Fake.certificateURL)),
            Steps.newOrder(Body.order("processing", errorType: Fake.problem("serverInternal")), location: Fake.secondOrderURL),
        ])
        #expect(run.failure == .orderFailed(type: Fake.problem("serverInternal")))
        #expect(run.requests(to: Fake.certificateURL).isEmpty)
    }

    @Test("authorization 뒤 다시 읽기에서 CSR 전 valid면 새 주문")
    func pollValidBeforeCSRRestarts() {
        let run = ACMEScript().run(Steps.accountFound + [Steps.newOrder(Body.order("pending"))] + Steps.pendingAuthorization() + [
            Steps.readOrder(Body.order("valid", certificate: Fake.certificateURL)),
            Steps.newOrder(Body.order("ready"), location: Fake.secondOrderURL),
            Steps.finalizeValid,
            Steps.download,
        ])
        #expect(run.result == issued)
    }

    @Test("finalize 뒤 processing을 여러 번 거친다")
    func manyProcessing() {
        let processing = Steps.readOrder(Body.order("processing"))
        let run = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order("ready")),
            .post(Fake.finalizeURL, 200, Body.order("processing")),
            processing, processing, processing,
            Steps.readOrder(Body.order("valid", certificate: Fake.certificateURL)),
            Steps.download,
        ])
        #expect(run.result == issued)
        #expect(run.waits == (1...4).map { Fake.start.addingTimeInterval(TimeInterval($0)) })
    }

    @Test("finalize 응답이 ready면 같은 키·CSR로 한 번 더 finalize한다")
    func finalizeReadyRepeatsWithSameCSR() throws {
        let script = ACMEScript()
        let run = script.run(Steps.accountFound + [
            Steps.newOrder(Body.order("ready")),
            .post(Fake.finalizeURL, 200, Body.order("ready")),
            Steps.finalizeValid,
            Steps.download,
        ])
        #expect(run.result == issued)
        let csrs = finalizedCSRs(run)
        #expect(csrs.count == 2)
        #expect(Set(csrs).count == 1)
    }

    @Test("finalize 응답이 pending이면 authorization을 다시 처리한 뒤 같은 CSR로 finalize한다")
    func finalizePendingReprocessesAuthorizations() {
        let run = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order("ready")),
            .post(Fake.finalizeURL, 200, Body.order("pending")),
        ] + Steps.pendingAuthorization() + [
            Steps.readOrder(Body.order("ready")),
            Steps.finalizeValid,
            Steps.download,
        ])
        #expect(run.result == issued)
        #expect(Set(finalizedCSRs(run)).count == 1)
        #expect(run.published.count == 1)
    }

    @Test("finalize가 403 orderNotReady면 주문을 다시 읽어 그 상태로 간다")
    func orderNotReadyRereadsOrder() {
        let run = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order("ready")),
            .post(Fake.finalizeURL, 403, Body.problem(Fake.problem("orderNotReady"), status: 403)),
            Steps.readOrder(Body.order("ready")),
            Steps.finalizeValid,
            Steps.download,
        ])
        #expect(run.result == issued)
        #expect(run.requests(to: Fake.finalizeURL).count == 2)
    }

    @Test("Location이 다른 주문 URL이면 그 URL을 다시 읽는다")
    func usesOrderLocation() {
        let run = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order("pending"), location: Fake.secondOrderURL),
        ] + Steps.pendingAuthorization() + [
            Steps.readOrder(Body.order("ready"), url: Fake.secondOrderURL),
            Steps.finalizeValid,
            Steps.download,
        ])
        #expect(run.result == issued)
    }
}

/// finalize 요청의 CSR DER들.
func finalizedCSRs(_ run: ScriptRun) -> [[UInt8]] {
    run.requests(to: Fake.finalizeURL).compactMap { ($0.payloadObject?["csr"] as? String).flatMap(Base64URL.decode) }
}

/// CSR의 `certificationRequestInfo`가 그 키·이름의 것인가.
func csrInfoMatches(_ der: [UInt8], key: P256.Signing.PrivateKey) -> Bool {
    let info = CertificateSigningRequest.certificationRequestInfo(domain: Fake.domain, publicKey: key.publicKey).encoded
    guard der.count > 2 else { return false }
    let headerLength = der[1] & 0x80 == 0 ? 2 : 2 + Int(der[1] & 0x7F)
    return der.dropFirst(headerLength).starts(with: info)
}
