// An order flow test harness that feeds fake responses in order and advances time. It uses no real waits or sockets.
//
// The harness checks the following for every request (contract §7 test 8, JWS for every request):
// - The method and URL match the expected values.
// - The POST body is Flattened JWS. Its protected header carries ES256 as `alg`, the original request URL as `url`, and the preceding response's `nonce`.
//     It carries only `jwk` (the account public key) for newAccount, or only `kid` (the account URL) otherwise. The account public key verifies the signature.
// - A nonce is used at most once. If there is no nonce on hand, `HEAD newNonce` precedes POST.
// - Requests do not arrive before the time the server supplied in `Retry-After`.

import CryptoKit
import Foundation
import Testing

@testable import SwiftailCertificates

/// Fixed test values. The name and URLs are fake.
enum Fake {
    static let domainName = "rd-mac-1a2b3c4d.tail0001.ts.net"
    static var domain: CertificateDomain {
        guard let domain = CertificateDomain(domainName) else { preconditionFailure("The test name must pass name validation") }
        return domain
    }

    static let directoryURL = "https://acme.invalid/directory"
    static let newNonceURL = "https://acme.invalid/new-nonce"
    static let newAccountURL = "https://acme.invalid/new-account"
    static let newOrderURL = "https://acme.invalid/new-order"
    static let accountURL = "https://acme.invalid/acct/1"
    static let orderURL = "https://acme.invalid/order/1"
    static let secondOrderURL = "https://acme.invalid/order/2"
    static let finalizeURL = "https://acme.invalid/order/1/finalize"
    static let certificateURL = "https://acme.invalid/cert/1"
    static func authorizationURL(_ index: Int) -> String { "https://acme.invalid/authz/\(index)" }
    static func challengeURL(_ index: Int) -> String { "https://acme.invalid/chall/\(index)" }
    static func token(_ index: Int) -> String { "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-o\(index)" }

    static let start = Date(timeIntervalSince1970: 1_800_000_000)
    static let chainPEM = Array("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".utf8)

    static func problem(_ name: String) -> String { "urn:ietf:params:acme:error:" + name }
}

/// Builds the response body JSON.
enum Body {
    static func json(_ object: Any) -> [UInt8] {
        guard let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) else {
            preconditionFailure("The test JSON value must serialize")
        }
        return Array(data)
    }

    static func directory(newNonce: String = Fake.newNonceURL, newOrder: String = Fake.newOrderURL) -> [UInt8] {
        json([
            "newNonce": newNonce, "newAccount": Fake.newAccountURL, "newOrder": newOrder,
            "revokeCert": "https://acme.invalid/revoke", "keyChange": "https://acme.invalid/key-change",
            "meta": ["termsOfService": "https://acme.invalid/terms"],
        ])
    }

    static func account(_ status: String = "valid") -> [UInt8] {
        json(["status": status, "orders": "https://acme.invalid/acct/1/orders"])
    }

    static func order(
        _ status: String,
        authorizations: [String] = [Fake.authorizationURL(1)],
        identifiers: [[String: String]] = [["type": "dns", "value": Fake.domainName]],
        finalize: String = Fake.finalizeURL,
        certificate: String? = nil,
        errorType: String? = nil
    ) -> [UInt8] {
        var object: [String: Any] = [
            "status": status, "expires": "2027-01-20T14:09:07.99Z", "identifiers": identifiers,
            "authorizations": authorizations, "finalize": finalize,
        ]
        if let certificate { object["certificate"] = certificate }
        if let errorType { object["error"] = ["type": errorType, "detail": "rd-mac-1a2b3c4d.tail0001.ts.net secret"] }
        return json(object)
    }

    static func challenge(
        _ index: Int = 1,
        type: String = "dns-01",
        status: String = "pending",
        token: String? = nil,
        url: String? = nil,
        errorType: String? = nil
    ) -> [String: Any] {
        var object: [String: Any] = [
            "type": type, "url": url ?? Fake.challengeURL(index), "status": status, "token": token ?? Fake.token(index),
        ]
        if let errorType { object["error"] = ["type": errorType, "detail": "Missing TXT record"] }
        return object
    }

    static func authorization(
        _ status: String,
        identifier: [String: String] = ["type": "dns", "value": Fake.domainName],
        wildcard: Bool? = nil,
        challenges: [[String: Any]] = [challenge()]
    ) -> [UInt8] {
        var object: [String: Any] = [
            "status": status, "identifier": identifier, "challenges": challenges, "expires": "2027-01-20T14:09:07Z",
        ]
        if let wildcard { object["wildcard"] = wildcard }
        return json(object)
    }

    static func problem(_ type: String?, status: Int = 400) -> [UInt8] {
        var object: [String: Any] = ["detail": "rd-mac-1a2b3c4d.tail0001.ts.net", "status": status]
        if let type { object["type"] = type }
        return json(object)
    }
}

/// One exchange in the sequence, with the expected request and response to return.
struct Exchange {
    var method: ACMEHTTPRequest.Method
    var url: String
    var status: Int
    var body: [UInt8]
    /// For nil, the harness adds a new nonce. For `.omitted`, it adds none. For `.value`, it adds that value verbatim, including malformed values.
    var nonce: NonceHeader = .fresh
    var headers: [ACMEHTTPResponse.Header] = []

    enum NonceHeader { case fresh, omitted, value(String) }

    static func get(_ url: String, _ status: Int = 200, _ body: [UInt8]) -> Exchange {
        Exchange(method: .get, url: url, status: status, body: body, nonce: .omitted)
    }

    static func head(_ url: String = Fake.newNonceURL, status: Int = 200, nonce: NonceHeader = .fresh) -> Exchange {
        Exchange(method: .head, url: url, status: status, body: [], nonce: nonce)
    }

    static func post(_ url: String, _ status: Int = 200, _ body: [UInt8], location: String? = nil) -> Exchange {
        var exchange = Exchange(method: .post, url: url, status: status, body: body)
        if let location { exchange.headers.append(.init(name: "Location", value: location)) }
        return exchange
    }

    func header(_ name: String, _ value: String) -> Exchange {
        var copy = self
        copy.headers.append(.init(name: name, value: value))
        return copy
    }

    func nonce(_ nonce: NonceHeader) -> Exchange {
        var copy = self
        copy.nonce = nonce
        return copy
    }
}

/// A decoded POST request.
struct ReceivedRequest {
    var request: ACMEHTTPRequest
    var time: Date
    /// The protected header (POST only).
    var header: [String: Any] = [:]
    /// Decoded payload bytes (POST only). POST-as-GET has an empty array.
    var payload: [UInt8] = []

    var payloadObject: [String: Any]? {
        (try? JSONSerialization.jsonObject(with: Data(payload))) as? [String: Any]
    }
}

/// The result of running the scenario.
struct ScriptRun {
    var result: ACMEIssuanceResult?
    var requests: [ReceivedRequest] = []
    var waits: [Date] = []
    var published: [(name: String, value: String)] = []
    /// The number of unused exchanges.
    var unusedExchanges = 0
    /// The time the flow ended.
    var finishedAt = Fake.start

    var failure: CertificateFailure? {
        if case .failed(let failure, _, _) = result { return failure }
        return nil
    }

    var retryNotBefore: Date? {
        if case .failed(_, let date, _) = result { return date }
        return nil
    }

    var chain: [UInt8]? {
        if case .issued(let chain, _) = result { return chain }
        return nil
    }

    func requests(to url: String) -> [ReceivedRequest] {
        requests.filter { $0.request.url == url }
    }
}

/// Runs the flow to completion by feeding fake responses in order.
struct ACMEScript {
    let accountKey = P256.Signing.PrivateKey()
    let certificateKey = P256.Signing.PrivateKey()
    var accountURL: String?
    var directoryURL = Fake.directoryURL
    /// Response time (receipt time = send time + this value).
    var latency: TimeInterval = 0
    /// The TXT publication result. A nil value indicates success.
    var publishFailure: CertificateFailure?

    var flow: ACMEOrderFlow {
        ACMEOrderFlow(
            directoryURL: directoryURL,
            domain: Fake.domain,
            accountKey: accountKey,
            accountURL: accountURL,
            certificateKey: certificateKey
        )
    }

    /// - Parameter sourceLocation: The test location to report when a harness check fails.
    func run(_ exchanges: [Exchange], sourceLocation: SourceLocation = #_sourceLocation) -> ScriptRun {
        var flow = self.flow
        var run = ScriptRun()
        var now = Fake.start
        var queue = exchanges[...]
        var heldNonce: String?
        var usedNonces: Set<String> = []
        var serverNotBefore: Date?
        var nonceCounter = 0
        var step = flow.start(at: now)

        for _ in 0..<1000 {
            switch step {
            case .finished(let result):
                run.result = result
                run.unusedExchanges = queue.count
                run.finishedAt = now
                return run

            case .wait(let until):
                #expect(until > now, "The wait must end after the current time", sourceLocation: sourceLocation)
                run.waits.append(until)
                now = max(now, until)
                step = flow.resume(at: now)

            case .publishTXT(let name, let value):
                run.published.append((name, value))
                step = publishFailure.map { flow.txtPublishingFailed($0, at: now) } ?? flow.txtPublished(at: now)

            case .send(let request):
                if let serverNotBefore {
                    #expect(now >= serverNotBefore, "A request was sent before Retry-After", sourceLocation: sourceLocation)
                }
                var received = ReceivedRequest(request: request, time: now)
                if request.method == .post {
                    let nonce = verifyJWS(request, into: &received, sourceLocation: sourceLocation)
                    #expect(nonce != nil && nonce == heldNonce, "Must use the nonce from the previous response", sourceLocation: sourceLocation)
                    if let nonce {
                        #expect(!usedNonces.contains(nonce), "Nonce reused", sourceLocation: sourceLocation)
                        usedNonces.insert(nonce)
                    }
                    heldNonce = nil
                } else {
                    #expect(request.body.isEmpty, sourceLocation: sourceLocation)
                }
                run.requests.append(received)

                guard let exchange = queue.popFirst() else {
                    Issue.record("Received a request with no exchanges left: \(request.method) \(request.url)", sourceLocation: sourceLocation)
                    run.finishedAt = now
                    return run
                }
                #expect(request.method == exchange.method, sourceLocation: sourceLocation)
                #expect(request.url == exchange.url, sourceLocation: sourceLocation)

                now = now.addingTimeInterval(latency)
                var headers = exchange.headers
                switch exchange.nonce {
                case .fresh:
                    nonceCounter += 1
                    let nonce = "nonce-\(nonceCounter)"
                    headers.append(.init(name: "Replay-Nonce", value: nonce))
                    heldNonce = nonce
                case .omitted:
                    break
                case .value(let value):
                    headers.append(.init(name: "Replay-Nonce", value: value))
                    heldNonce = ACMEInputRules.isAcceptableNonce(value) ? value : heldNonce
                }
                if let value = headers.first(where: { $0.name == "Retry-After" })?.value,
                   let date = RetryAfter.date(from: value, receivedAt: now) {
                    serverNotBefore = max(serverNotBefore ?? date, date)
                }
                step = flow.receive(ACMEHTTPResponse(status: exchange.status, headers: headers, body: exchange.body), at: now)
            }
        }
        Issue.record("The flow did not finish", sourceLocation: sourceLocation)
        return run
    }

    /// Decodes the JWS, checks the protected header, and verifies the signature. Returns the header nonce.
    private func verifyJWS(
        _ request: ACMEHTTPRequest,
        into received: inout ReceivedRequest,
        sourceLocation: SourceLocation
    ) -> String? {
        guard let object = (try? JSONSerialization.jsonObject(with: Data(request.body))) as? [String: String],
              Set(object.keys) == ["protected", "payload", "signature"],
              let protected = object["protected"], let payload = object["payload"], let signature = object["signature"],
              let headerBytes = Base64URL.decode(protected), let payloadBytes = Base64URL.decode(payload),
              let signatureBytes = Base64URL.decode(signature),
              let header = (try? JSONSerialization.jsonObject(with: Data(headerBytes))) as? [String: Any]
        else {
            Issue.record("The POST body is not Flattened JWS", sourceLocation: sourceLocation)
            return nil
        }
        received.header = header
        received.payload = payloadBytes
        #expect(header["alg"] as? String == "ES256", sourceLocation: sourceLocation)
        #expect(header["url"] as? String == request.url, "The JWS url must match the original request URL", sourceLocation: sourceLocation)
        let isNewAccount = request.url == Fake.newAccountURL
        if isNewAccount {
            #expect(header["kid"] == nil, sourceLocation: sourceLocation)
            let jwk = header["jwk"] as? [String: String]
            let expected = JWK(accountKey.publicKey)
            #expect(jwk == ["crv": "P-256", "kty": "EC", "x": Base64URL.encode(expected.x), "y": Base64URL.encode(expected.y)],
                    sourceLocation: sourceLocation)
        } else {
            #expect(header["jwk"] == nil, sourceLocation: sourceLocation)
            #expect(header["kid"] as? String == Fake.accountURL, sourceLocation: sourceLocation)
        }
        let signed = (try? P256.Signing.ECDSASignature(rawRepresentation: signatureBytes)).map {
            accountKey.publicKey.isValidSignature($0, for: Array((protected + "." + payload).utf8))
        }
        #expect(signed == true, "The signature must verify with the account public key", sourceLocation: sourceLocation)
        return header["nonce"] as? String
    }
}

/// Common groups of exchanges.
enum Steps {
    /// directory, newNonce, and lookup of an existing account.
    static let accountFound: [Exchange] = [
        .get(Fake.directoryURL, 200, Body.directory()),
        .head(),
        .post(Fake.newAccountURL, 200, Body.account(), location: Fake.accountURL),
    ]

    static func newOrder(_ body: [UInt8], location: String = Fake.orderURL) -> Exchange {
        .post(Fake.newOrderURL, 201, body, location: location)
    }

    /// Reads one authorization (pending, dns-01 pending) and responds to the challenge.
    static func pendingAuthorization(_ index: Int = 1) -> [Exchange] {
        [
            .post(Fake.authorizationURL(index), 200, Body.authorization("pending", challenges: [
                Body.challenge(index, type: "http-01"), Body.challenge(index, type: "dns-01"),
            ])),
            .post(Fake.challengeURL(index), 200, Body.json(Body.challenge(index, status: "processing"))),
        ]
    }

    static func readOrder(_ body: [UInt8], url: String = Fake.orderURL) -> Exchange {
        .post(url, 200, body)
    }

    static let finalizeValid = Exchange.post(Fake.finalizeURL, 200, Body.order("valid", certificate: Fake.certificateURL))
    static let download = Exchange.post(Fake.certificateURL, 200, Fake.chainPEM)

    /// From newOrder (ready) through download.
    static let readyToIssued: [Exchange] = [newOrder(Body.order("ready")), finalizeValid, download]
}
