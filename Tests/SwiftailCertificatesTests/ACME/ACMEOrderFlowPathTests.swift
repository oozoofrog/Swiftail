// Successful paths in contract §7 test 8: the twelve steps in note §4.3, an existing, missing, or already known account, an already valid authorization or two authorizations,
// a challenge already processing, an order initially ready, valid, or processing, repeated processing, and the five finalize response statuses
// and orderNotReady.

import CryptoKit
import Foundation
import Testing

@testable import SwiftailCertificates

@Suite("ACME order flow: successful paths")
struct ACMEOrderFlowPathTests {
    private let issued = ACMEIssuanceResult.issued(certificateChainPEM: Fake.chainPEM, accountURL: Fake.accountURL)

    @Test("The basic twelve-step path")
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

        // Account lookup uses onlyReturnExisting (RFC 8555 7.3.1), and the order has one dns identifier (7.4).
        #expect(run.requests(to: Fake.newAccountURL).first?.payloadObject?["onlyReturnExisting"] as? Bool == true)
        let identifiers = run.requests(to: Fake.newOrderURL).first?.payloadObject?["identifiers"] as? [[String: String]]
        #expect(identifiers == [["type": "dns", "value": Fake.domainName]])

        // TXT name and value (note §3.5), then a `{}` challenge response (RFC 8555 7.5.1).
        let value = KeyAuthorization(token: Fake.token(1), accountKey: JWK(script.accountKey.publicKey)).dns01TXTValue
        #expect(run.published.map(\.name) == ["_acme-challenge." + Fake.domainName])
        #expect(run.published.map(\.value) == [value])
        #expect(run.requests(to: Fake.challengeURL(1)).map(\.payload) == [Array("{}".utf8)])

        // POST-as-GET uses an empty payload (RFC 8555 6.3).
        for url in [Fake.authorizationURL(1), Fake.orderURL, Fake.certificateURL] {
            #expect(run.requests(to: url).allSatisfy { $0.payload.isEmpty })
        }

        // The finalize CSR uses the certificate key.
        let csr = try #require(finalizedCSRs(run).first)
        #expect(csrInfoMatches(csr, key: script.certificateKey))
        #expect(!csrInfoMatches(csr, key: script.accountKey))

        // Only the download carries Accept (contract C7).
        #expect(run.requests(to: Fake.certificateURL).map(\.request.accept) == ["application/pem-certificate-chain"])
        #expect(run.requests.filter { $0.request.url != Fake.certificateURL }.allSatisfy { $0.request.accept == nil })

        // The first read follows the challenge response immediately. Later reads occur at 1-second intervals.
        #expect(run.waits == [Fake.start.addingTimeInterval(1), Fake.start.addingTimeInterval(2)])
    }

    @Test("If the account is missing, accepts the terms and creates one")
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

    @Test("Uses the account even if creation returns 200 because an account with the same key already exists")
    func createAccountReturnsExisting() {
        let run = ACMEScript().run([
            .get(Fake.directoryURL, 200, Body.directory()),
            .head(),
            .post(Fake.newAccountURL, 400, Body.problem(Fake.problem("accountDoesNotExist"))),
            .post(Fake.newAccountURL, 200, Body.account(), location: Fake.accountURL),
        ] + Steps.readyToIssued)
        #expect(run.result == issued)
    }

    @Test("If the account URL is known, skips lookup and orders with kid")
    func knownAccountSkipsLookup() {
        var script = ACMEScript()
        script.accountURL = Fake.accountURL
        let run = script.run([.get(Fake.directoryURL, 200, Body.directory()), .head()] + Steps.readyToIssued)
        #expect(run.result == issued)
        #expect(run.requests(to: Fake.newAccountURL).isEmpty)
    }

    @Test("An already valid authorization publishes no TXT record")
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

    @Test("Processes both authorizations, one of which is valid")
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

    @Test("If the challenge is already processing, publishes the record without sending another response")
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

    @Test("Skips a pending authorization's challenge if it is already valid")
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

    @Test("If the order is initially ready, skips authorization and finalizes")
    func readyOrder() {
        let run = ACMEScript().run(Steps.accountFound + Steps.readyToIssued)
        #expect(run.result == issued)
        #expect(run.requests(to: Fake.authorizationURL(1)).isEmpty)
    }

    @Test("An order that is valid or processing before CSR restarts once with a new order", arguments: ["valid", "processing"])
    func orderBeforeCSRRestarts(status: String) {
        let run = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order(status, certificate: Fake.certificateURL)),
            Steps.newOrder(Body.order("ready"), location: Fake.secondOrderURL),
            Steps.finalizeValid,
            Steps.download,
        ])
        #expect(run.result == issued)
        // The certificate from the first order was not accepted because there is no corresponding private key (contract C5).
        #expect(run.requests(to: Fake.newOrderURL).count == 2)
        #expect(run.requests(to: Fake.certificateURL).count == 1)
    }

    @Test("If the new order is also valid before CSR, returns orderFailed")
    func secondRestartFails() {
        let run = ACMEScript().run(Steps.accountFound + [
            Steps.newOrder(Body.order("valid", certificate: Fake.certificateURL)),
            Steps.newOrder(Body.order("processing", errorType: Fake.problem("serverInternal")), location: Fake.secondOrderURL),
        ])
        #expect(run.failure == .orderFailed(type: Fake.problem("serverInternal")))
        #expect(run.requests(to: Fake.certificateURL).isEmpty)
    }

    @Test("If a read after authorization returns valid before CSR, starts a new order")
    func pollValidBeforeCSRRestarts() {
        let run = ACMEScript().run(Steps.accountFound + [Steps.newOrder(Body.order("pending"))] + Steps.pendingAuthorization() + [
            Steps.readOrder(Body.order("valid", certificate: Fake.certificateURL)),
            Steps.newOrder(Body.order("ready"), location: Fake.secondOrderURL),
            Steps.finalizeValid,
            Steps.download,
        ])
        #expect(run.result == issued)
    }

    @Test("Goes through processing multiple times after finalize")
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

    @Test("A ready finalize response triggers one more finalize with the same key and CSR")
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

    @Test("A pending finalize response triggers authorization again, then finalize with the same CSR")
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

    @Test("A 403 orderNotReady from finalize triggers another order read and proceeds with the returned status")
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

    @Test("If Location points to another order URL, reads that URL again")
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

/// The CSR DER values from finalize requests.
func finalizedCSRs(_ run: ScriptRun) -> [[UInt8]] {
    run.requests(to: Fake.finalizeURL).compactMap { ($0.payloadObject?["csr"] as? String).flatMap(Base64URL.decode) }
}

/// Checks whether the CSR's `certificationRequestInfo` is for that key and name.
func csrInfoMatches(_ der: [UInt8], key: P256.Signing.PrivateKey) -> Bool {
    let info = CertificateSigningRequest.certificationRequestInfo(domain: Fake.domain, publicKey: key.publicKey).encoded
    guard der.count > 2 else { return false }
    let headerLength = der[1] & 0x80 == 0 ? 2 : 2 + Int(der[1] & 0x7F)
    return der.dropFirst(headerLength).starts(with: info)
}
