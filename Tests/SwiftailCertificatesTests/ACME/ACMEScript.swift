// 주문 절차 시험의 틀: 가짜 응답을 차례로 넣고 시각을 넘긴다. 실제 대기도 소켓도 없다.
//
// 틀이 모든 요청에서 스스로 확인하는 것(계약 7절 시험 8 "모든 요청의 JWS"):
// - 기대한 메서드와 URL이다.
// - POST의 본문은 Flattened JWS이고, 보호 머리의 `alg`가 ES256, `url`이 요청 URL 그대로, `nonce`가 직전 응답이 준 것,
//   newAccount면 `jwk`(계정 공개 키)만, 그 밖이면 `kid`(계정 URL)만 싣고, 서명이 계정 공개 키로 검증된다.
// - 같은 nonce를 두 번 쓰지 않는다. 쥔 nonce가 없으면 POST 전에 `HEAD newNonce`가 온다.
// - 서버가 `Retry-After`로 알려 준 시각 전에는 요청이 오지 않는다.

import CryptoKit
import Foundation
import Testing

@testable import SwiftailCertificates

/// 시험의 고정 값. 이름과 URL은 가짜다.
enum Fake {
    static let domainName = "rd-mac-1a2b3c4d.tail0001.ts.net"
    static var domain: CertificateDomain {
        guard let domain = CertificateDomain(domainName) else { preconditionFailure("시험용 이름이 이름 검사를 통과해야 한다") }
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

/// 응답 본문 JSON을 만든다.
enum Body {
    static func json(_ object: Any) -> [UInt8] {
        guard let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) else {
            preconditionFailure("시험의 JSON 값이 직렬화되어야 한다")
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
        if let errorType { object["error"] = ["type": errorType, "detail": "rd-mac-1a2b3c4d.tail0001.ts.net 비밀"] }
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
        if let errorType { object["error"] = ["type": errorType, "detail": "TXT 없음"] }
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

/// 차례로 넣는 교환 하나: 기대하는 요청과 돌려줄 응답.
struct Exchange {
    var method: ACMEHTTPRequest.Method
    var url: String
    var status: Int
    var body: [UInt8]
    /// nil이면 틀이 새 nonce를 붙인다. `.omitted`면 붙이지 않는다. `.value`면 그 값을 그대로 붙인다(형식이 틀린 값 포함).
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

/// 받은 POST 하나를 푼 것.
struct ReceivedRequest {
    var request: ACMEHTTPRequest
    var time: Date
    /// 보호 머리(POST만).
    var header: [String: Any] = [:]
    /// 풀어 낸 payload 바이트(POST만). POST-as-GET이면 빈 배열.
    var payload: [UInt8] = []

    var payloadObject: [String: Any]? {
        (try? JSONSerialization.jsonObject(with: Data(payload))) as? [String: Any]
    }
}

/// 시나리오를 돌린 결과.
struct ScriptRun {
    var result: ACMEIssuanceResult?
    var requests: [ReceivedRequest] = []
    var waits: [Date] = []
    var published: [(name: String, value: String)] = []
    /// 쓰이지 않고 남은 교환 수.
    var unusedExchanges = 0
    /// 끝난 시각.
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

/// 가짜 응답을 차례로 넣어 절차를 끝까지 돌린다.
struct ACMEScript {
    let accountKey = P256.Signing.PrivateKey()
    let certificateKey = P256.Signing.PrivateKey()
    var accountURL: String?
    var directoryURL = Fake.directoryURL
    /// 응답이 걸리는 시간(받은 시각 = 보낸 시각 + 이 값).
    var latency: TimeInterval = 0
    /// TXT 올리기의 결과. nil이면 성공.
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

    /// - Parameter sourceLocation: 틀의 확인이 실패했을 때 시험의 자리를 가리킨다.
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
                #expect(until > now, "기다림은 지금보다 뒤여야 한다", sourceLocation: sourceLocation)
                run.waits.append(until)
                now = max(now, until)
                step = flow.resume(at: now)

            case .publishTXT(let name, let value):
                run.published.append((name, value))
                step = publishFailure.map { flow.txtPublishingFailed($0, at: now) } ?? flow.txtPublished(at: now)

            case .send(let request):
                if let serverNotBefore {
                    #expect(now >= serverNotBefore, "Retry-After 전에 요청했다", sourceLocation: sourceLocation)
                }
                var received = ReceivedRequest(request: request, time: now)
                if request.method == .post {
                    let nonce = verifyJWS(request, into: &received, sourceLocation: sourceLocation)
                    #expect(nonce != nil && nonce == heldNonce, "직전 응답의 nonce를 써야 한다", sourceLocation: sourceLocation)
                    if let nonce {
                        #expect(!usedNonces.contains(nonce), "nonce를 다시 썼다", sourceLocation: sourceLocation)
                        usedNonces.insert(nonce)
                    }
                    heldNonce = nil
                } else {
                    #expect(request.body.isEmpty, sourceLocation: sourceLocation)
                }
                run.requests.append(received)

                guard let exchange = queue.popFirst() else {
                    Issue.record("남은 교환이 없는데 요청이 왔다: \(request.method) \(request.url)", sourceLocation: sourceLocation)
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
        Issue.record("절차가 끝나지 않는다", sourceLocation: sourceLocation)
        return run
    }

    /// JWS를 풀어 보호 머리를 확인하고 서명을 검증한다. 머리의 nonce를 돌려준다.
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
            Issue.record("POST 본문이 Flattened JWS가 아니다", sourceLocation: sourceLocation)
            return nil
        }
        received.header = header
        received.payload = payloadBytes
        #expect(header["alg"] as? String == "ES256", sourceLocation: sourceLocation)
        #expect(header["url"] as? String == request.url, "JWS url은 요청 URL 그대로", sourceLocation: sourceLocation)
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
        #expect(signed == true, "서명이 계정 공개 키로 검증되어야 한다", sourceLocation: sourceLocation)
        return header["nonce"] as? String
    }
}

/// 자주 쓰는 교환 묶음.
enum Steps {
    /// directory, newNonce, 계정 찾기(이미 있음).
    static let accountFound: [Exchange] = [
        .get(Fake.directoryURL, 200, Body.directory()),
        .head(),
        .post(Fake.newAccountURL, 200, Body.account(), location: Fake.accountURL),
    ]

    static func newOrder(_ body: [UInt8], location: String = Fake.orderURL) -> Exchange {
        .post(Fake.newOrderURL, 201, body, location: location)
    }

    /// authorization 하나(pending, dns-01 pending)를 읽고 challenge에 응답한다.
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

    /// newOrder(ready)부터 내려받기까지.
    static let readyToIssued: [Exchange] = [newOrder(Body.order("ready")), finalizeValid, download]
}
