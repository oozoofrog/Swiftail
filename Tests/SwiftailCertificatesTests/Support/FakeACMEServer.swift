// An in-memory server based on RFC 8555. Keeps successful state transitions separate from response fault injection.
import CryptoKit
import Foundation

@testable import SwiftailCertificates

actor FakeACMEServer: ACMETransport {
    static let base = "https://acme.invalid"
    static let directoryURL = base + "/directory"
    static let domain = "rd-mac-1a2b3c4d.tail0001.ts.net"
    static let errorPrefix = "urn:ietf:params:acme:error:"

    enum Endpoint: String, Sendable, Hashable {
        case directory, nonce, account, newOrder, authorization, challenge, order, finalize, certificate
    }

    enum ChainFault: String, Sendable, CaseIterable {
        case none, wrongKey, wrongName, expired, unknownRoot, includeRoot, privateKey, garbageAfter, garbageBetween
        case malformed, sixCertificates, tooLarge
    }

    enum NonceMode: Sendable { case normal, missing, invalid, missingExceptNonce, invalidExceptNonce }

    struct ResponseFault: Sendable {
        var endpoint: Endpoint = .newOrder
        var status: Int = 400
        var type: String? = errorPrefix + "rejectedIdentifier"
        var rawBody: [UInt8]?
        var retryAfter: String?
        var remaining = 1
    }

    /// Successful scenarios use only defaults. Boundary tests explicitly inject server responses that violate the RFC.
    struct Configuration: Sendable {
        var badNonce: [Endpoint: Int] = [:]
        var responseFault: ResponseFault?
        var nonceMode: NonceMode = .normal
        var directoryOrderURL: String = base + "/new-order"
        var initialOrderStatuses: [String] = ["pending"]
        var authorizationStates: [String] = ["pending"]
        var authorizationType = "dns"
        var authorizationName = domain
        var wildcard = false
        var challengeType = "dns-01"
        var challengeStatus = "pending"
        var token: String?
        var responseIdentifier = domain
        var accountStatus = "valid"
        var pollStatuses: [String] = []
        var finalizeStatuses: [String] = []
        var orderNotReadyCount = 0
        var processingPolls = 2
        var pendingPolls = 0
        var retryAfter: String?
        var retryAfterByEndpoint: [Endpoint: String] = [:]
        var orderErrorType: String? = errorPrefix + "badCSR"
        var challengeErrorType: String? = errorPrefix + "dns"
        var chainFault: ChainFault = .none
    }

    struct Record: Sendable {
        var time: Date
        var method: ACMEHTTPRequest.Method
        var url: String
        var endpoint: Endpoint?
        var protected: FakeACMECrypto.Protected?
        var payload: Data?
        var status: Int
        var responseNonce: String?
    }

    private struct Account {
        var url: String
        var jwk: FakeACMECrypto.JWK
    }

    private struct Authorization {
        var status: String
        var challengeStatus: String
        var token: String
    }

    private struct Order {
        var id: Int
        var owner: String
        var domain: String
        var status: String
        var authorizations: [Authorization]
        var publicKey: P256.Signing.PublicKey?
        var processingPolls: Int
        var pendingPolls: Int
        var csr: Data?
    }

    private var config: Configuration
    private let now: @Sendable () -> Date
    private let lookupTXT: @Sendable (String) -> [String]
    private let root: TestCertificateAuthority
    private let intermediate: TestCertificateAuthority
    private var nonces: Set<String> = []
    private var accounts: [String: Account] = [:]
    private var orders: [Int: Order] = [:]
    private(set) var records: [Record] = []

    init(
        configuration: Configuration = Configuration(), now: @escaping @Sendable () -> Date,
        lookupTXT: @escaping @Sendable (String) -> [String]
    ) {
        config = configuration
        self.now = now
        self.lookupTXT = lookupTXT
        let time = now()
        root = .root("Scenario Root", from: time.addingTimeInterval(-86400), to: time.addingTimeInterval(86400 * 365))
        intermediate = root.intermediate(
            "Scenario Intermediate", from: time.addingTimeInterval(-86400), to: time.addingTimeInterval(86400 * 180)
        )
    }

    var rootCertificate: [UInt8] { root.certificate }
    var accountCount: Int { accounts.count }
    var orderCount: Int { orders.count }
    var submittedCSRs: [Data] { orders.values.sorted { $0.id < $1.id }.compactMap(\.csr) }

    func send(_ request: ACMEHTTPRequest) async throws(ACMETransportError) -> ACMEHTTPResponse {
        let endpoint = endpoint(for: request.url)
        var header: FakeACMECrypto.Protected?
        var payload: Data?
        var response: ACMEHTTPResponse
        do {
            if request.method == .post {
                let signed = try authenticate(request)
                header = signed.0
                payload = signed.1
            }
            if let endpoint, (config.badNonce[endpoint] ?? 0) > 0, request.method == .post {
                config.badNonce[endpoint, default: 0] -= 1
                response = problem(400, "badNonce")
            } else if var fault = config.responseFault, fault.endpoint == endpoint, fault.remaining > 0 {
                fault.remaining -= 1
                config.responseFault = fault
                var object: [String: Any] = ["detail": "진단에 노출하지 않는 시험 식별자", "subproblems": [
                    ["type": Self.errorPrefix + "dns", "identifier": ["type": "dns", "value": Self.domain]],
                ]]
                if let type = fault.type { object["type"] = type }
                response = reply(
                    fault.status, bytes: fault.rawBody ?? json(object), contentType: "application/problem+json",
                    retryAfter: fault.retryAfter, endpoint: endpoint
                )
            } else {
                response = try route(request, endpoint: endpoint, header: header, payload: payload)
            }
        } catch let error as Rejection {
            response = problem(error.status, error.type)
        } catch {
            response = problem(400, "malformed")
        }
        if let endpoint, let value = config.retryAfterByEndpoint[endpoint] {
            response.headers.removeAll { $0.name.lowercased() == "retry-after" }
            response.headers.append(.init(name: "Retry-After", value: value))
        }
        records.append(Record(
            time: now(), method: request.method, url: request.url, endpoint: endpoint,
            protected: header ?? decodedHeader(request), payload: payload, status: response.status,
            responseNonce: response.firstHeader(named: "Replay-Nonce")
        ))
        return response
    }

    private struct Rejection: Error {
        var status = 400
        var type: String
    }

    private func decodedHeader(_ request: ACMEHTTPRequest) -> FakeACMECrypto.Protected? {
        guard let envelope = try? JSONDecoder().decode(FakeACMECrypto.Envelope.self, from: Data(request.body)),
              let bytes = FakeACMECrypto.decode(envelope.protected) else { return nil }
        return try? JSONDecoder().decode(FakeACMECrypto.Protected.self, from: bytes)
    }

    /// RFC 8555 6.2–6.5: Authenticate POSTs before changing state. The transport declaration guarantees Content-Type.
    private func authenticate(_ request: ACMEHTTPRequest) throws -> (FakeACMECrypto.Protected, Data) {
        guard let object = try JSONSerialization.jsonObject(with: Data(request.body)) as? [String: Any],
              Set(object.keys) == ["protected", "payload", "signature"],
              let envelope = try? JSONDecoder().decode(FakeACMECrypto.Envelope.self, from: Data(request.body)),
              let protectedBytes = FakeACMECrypto.decode(envelope.protected),
              let payload = FakeACMECrypto.decode(envelope.payload),
              let signatureBytes = FakeACMECrypto.decode(envelope.signature),
              let header = try? JSONDecoder().decode(FakeACMECrypto.Protected.self, from: protectedBytes),
              header.b64 == nil, header.crit == nil else { throw Rejection(type: "malformed") }
        // A nonce that has appeared once cannot be reused, even if another header or the signature was invalid (RFC 8555 6.5).
        guard let nonce = header.nonce, FakeACMECrypto.decode(nonce) != nil,
              nonces.remove(nonce) != nil else { throw Rejection(type: "badNonce") }
        guard header.alg == "ES256" else { throw Rejection(type: "badSignatureAlgorithm") }
        guard header.url == request.url else { throw Rejection(status: 403, type: "unauthorized") }
        guard (header.jwk != nil) != (header.kid != nil) else { throw Rejection(type: "malformed") }
        let key: P256.Signing.PublicKey
        if request.url == Self.base + "/new-account" {
            guard let jwk = header.jwk else { throw Rejection(type: "malformed") }
            guard let parsed = try? jwk.publicKey() else { throw Rejection(type: "badPublicKey") }
            key = parsed
        } else {
            guard let kid = header.kid, header.jwk == nil,
                  let account = accounts.values.first(where: { $0.url == kid })
            else { throw Rejection(status: 403, type: "unauthorized") }
            key = try account.jwk.publicKey()
        }
        guard let signature = try? P256.Signing.ECDSASignature(rawRepresentation: signatureBytes),
              key.isValidSignature(signature, for: Data("\(envelope.protected).\(envelope.payload)".utf8))
        else { throw Rejection(status: 403, type: "unauthorized") }
        return (header, payload)
    }

    private func route(
        _ request: ACMEHTTPRequest, endpoint: Endpoint?, header: FakeACMECrypto.Protected?, payload: Data?
    ) throws -> ACMEHTTPResponse {
        if endpoint == .directory {
            guard request.method == .get || (request.method == .post && payload?.isEmpty == true)
            else { throw Rejection(status: 405, type: "malformed") }
            return reply(200, object: [
                "newNonce": Self.base + "/new-nonce", "newAccount": Self.base + "/new-account",
                "newOrder": config.directoryOrderURL, "meta": ["termsOfService": Self.base + "/terms"],
            ], endpoint: .directory)
        }
        if endpoint == .nonce {
            guard request.method == .head || request.method == .get ||
                    (request.method == .post && payload?.isEmpty == true)
            else { throw Rejection(status: 405, type: "malformed") }
            var response = reply(request.method == .get ? 204 : 200, bytes: [], endpoint: .nonce)
            response.headers.append(.init(name: "Cache-Control", value: "no-store"))
            return response
        }
        guard request.method == .post, let header, let payload else {
            throw Rejection(status: 405, type: "malformed")
        }
        switch endpoint {
        case .account:
            guard let jwk = header.jwk, let body = try JSONSerialization.jsonObject(with: payload) as? [String: Any]
            else { throw Rejection(type: "malformed") }
            if let account = accounts[jwk.thumbprint] {
                return reply(200, object: ["status": config.accountStatus], location: account.url)
            }
            if body["onlyReturnExisting"] as? Bool == true { return problem(400, "accountDoesNotExist") }
            guard body["termsOfServiceAgreed"] as? Bool == true else { return problem(403, "userActionRequired") }
            let account = Account(url: Self.base + "/account/\(accounts.count + 1)", jwk: jwk)
            accounts[jwk.thumbprint] = account
            return reply(201, object: ["status": config.accountStatus], location: account.url)
        case .newOrder:
            guard let body = try JSONSerialization.jsonObject(with: payload) as? [String: Any],
                  let identifiers = body["identifiers"] as? [[String: String]], identifiers.count == 1,
                  identifiers[0]["type"] == "dns", let domain = identifiers[0]["value"], domain == Self.domain,
                  let owner = header.kid else { return problem(400, "rejectedIdentifier") }
            let status = config.initialOrderStatuses.count > 1
                ? config.initialOrderStatuses.removeFirst() : (config.initialOrderStatuses.first ?? "pending")
            let auths = config.authorizationStates.map {
                Authorization(
                    status: status == "ready" ? "valid" : $0,
                    challengeStatus: status == "ready" || $0 == "valid" ? "valid" : config.challengeStatus,
                    token: config.token ?? randomValue()
                )
            }
            let order = Order(
                id: orders.count + 1, owner: owner, domain: domain, status: status, authorizations: auths,
                processingPolls: config.processingPolls, pendingPolls: config.pendingPolls
            )
            orders[order.id] = order
            return reply(201, object: orderObject(order), location: orderURL(order.id))
        case .authorization, .challenge, .order, .finalize, .certificate:
            guard let id = resourceNumbers(request.url).first, var order = orders[id], order.owner == header.kid
            else { return problem(403, "unauthorized") }
            defer { orders[id] = order }
            switch endpoint {
            case .authorization:
                try requirePOSTAsGET(payload)
                guard let index = resourceNumbers(request.url).last, order.authorizations.indices.contains(index)
                else { return problem(404, "malformed") }
                return reply(200, object: authorizationObject(order, index))
            case .challenge:
                guard let index = resourceNumbers(request.url).last, order.authorizations.indices.contains(index),
                      (try JSONSerialization.jsonObject(with: payload)) is [String: Any]
                else { return problem(400, "malformed") }
                // RFC 8555 7.5.1 requires ignoring unknown response fields. The scenario checks the client's {}.
                if order.authorizations[index].challengeStatus == "pending" {
                    order.authorizations[index].challengeStatus = "processing"
                    validateDNS(&order, index)
                }
                return reply(200, object: challengeObject(order, index))
            case .order:
                try requirePOSTAsGET(payload)
                if !config.pollStatuses.isEmpty {
                    order.status = config.pollStatuses.removeFirst()
                } else if order.status == "pending" {
                    for index in order.authorizations.indices where order.authorizations[index].challengeStatus == "valid" {
                        order.authorizations[index].status = "valid"
                    }
                    for index in order.authorizations.indices where order.authorizations[index].challengeStatus == "processing" {
                        validateDNS(&order, index)
                    }
                    if order.authorizations.contains(where: { $0.status == "invalid" }) { order.status = "invalid" }
                    else if order.pendingPolls > 0 { order.pendingPolls -= 1 }
                    else if order.authorizations.allSatisfy({ $0.status == "valid" }) { order.status = "ready" }
                } else if order.status == "processing", order.publicKey != nil {
                    if order.processingPolls > 0 { order.processingPolls -= 1 }
                    else { order.status = "valid" }
                }
                return reply(200, object: orderObject(order), retryAfter: config.retryAfter)
            case .finalize:
                if config.orderNotReadyCount > 0 {
                    config.orderNotReadyCount -= 1
                    return problem(403, "orderNotReady")
                }
                guard order.status == "ready" else { return problem(403, "orderNotReady") }
                guard let body = try JSONSerialization.jsonObject(with: payload) as? [String: Any],
                      let csrText = body["csr"] as? String, let csrBytes = FakeACMECrypto.decode(csrText),
                      let csr = try? FakeACMECrypto.CSR(csrBytes), csr.names == [order.domain],
                      !accounts.values.contains(where: { $0.jwk == FakeACMECrypto.JWK(csr.publicKey) })
                else { return problem(400, "badCSR") }
                if let previous = order.csr, previous != csrBytes { return problem(400, "badCSR") }
                order.csr = csrBytes
                order.publicKey = csr.publicKey
                order.status = config.finalizeStatuses.isEmpty ? "processing" : config.finalizeStatuses.removeFirst()
                if order.status == "pending" {
                    for index in order.authorizations.indices {
                        order.authorizations[index].status = "pending"
                        order.authorizations[index].challengeStatus = "pending"
                    }
                }
                return reply(200, object: orderObject(order), retryAfter: config.retryAfter)
            case .certificate:
                try requirePOSTAsGET(payload)
                guard order.status == "valid", let key = order.publicKey else { return problem(403, "unauthorized") }
                guard request.accept == "application/pem-certificate-chain" else { return problem(406, "malformed") }
                return reply(200, bytes: certificateChain(order.domain, key), contentType: "application/pem-certificate-chain")
            default: return problem(404, "malformed")
            }
        default: return problem(404, "malformed")
        }
    }

    private func requirePOSTAsGET(_ payload: Data) throws {
        guard payload.isEmpty else { throw Rejection(type: "malformed") }
    }

    private func validateDNS(_ order: inout Order, _ index: Int) {
        guard let account = accounts.values.first(where: { $0.url == order.owner }) else { return }
        let expected = FakeACMECrypto.dnsValue(token: order.authorizations[index].token, account: account.jwk)
        let valid = lookupTXT("_acme-challenge." + order.domain).contains(expected)
        order.authorizations[index].status = valid ? "valid" : "invalid"
        order.authorizations[index].challengeStatus = valid ? "valid" : "invalid"
    }

    private func orderObject(_ order: Order) -> [String: Any] {
        var object: [String: Any] = [
            "status": order.status, "identifiers": [["type": "dns", "value": config.responseIdentifier]],
            "authorizations": order.authorizations.indices.map { authorizationURL(order.id, $0) },
            "finalize": orderURL(order.id) + "/finalize",
        ]
        if order.status == "valid" { object["certificate"] = orderURL(order.id) + "/certificate" }
        if order.status == "invalid", let type = config.orderErrorType { object["error"] = ["type": type] }
        return object
    }

    private func authorizationObject(_ order: Order, _ index: Int) -> [String: Any] {
        var object: [String: Any] = [
            "status": order.authorizations[index].status,
            "identifier": ["type": config.authorizationType, "value": config.authorizationName],
            "challenges": [challengeObject(order, index)],
        ]
        if config.wildcard { object["wildcard"] = true }
        if order.authorizations[index].status == "valid" { object["expires"] = "2030-01-01T00:00:00Z" }
        return object
    }

    private func challengeObject(_ order: Order, _ index: Int) -> [String: Any] {
        let auth = order.authorizations[index]
        var object: [String: Any] = [
            "type": config.challengeType, "url": challengeURL(order.id, index),
            "status": auth.challengeStatus, "token": auth.token,
        ]
        if auth.challengeStatus == "invalid", let type = config.challengeErrorType { object["error"] = ["type": type] }
        return object
    }

    private func certificateChain(_ domain: String, _ key: P256.Signing.PublicKey) -> [UInt8] {
        let time = now()
        let leafKey = config.chainFault == .wrongKey ? P256.Signing.PrivateKey().publicKey : key
        let name = config.chainFault == .wrongName ? "other.tail0001.ts.net" : domain
        let expired = config.chainFault == .expired
        let issuer = config.chainFault == .unknownRoot
            ? TestCertificateAuthority.root("Unknown Root", from: time.addingTimeInterval(-86400), to: time.addingTimeInterval(86400 * 30))
            : intermediate
        let leaf = issuer.leaf(
            name, publicKey: leafKey, from: time.addingTimeInterval(expired ? -86400 * 3 : -60),
            to: time.addingTimeInterval(expired ? -86400 : 86400 * 30)
        )
        let chain = pemChain([leaf, issuer.certificate])
        switch config.chainFault {
        case .includeRoot: return pemChain([leaf, issuer.certificate, root.certificate])
        case .privateKey: return chain + Array(P256.Signing.PrivateKey().pemRepresentation.utf8)
        case .garbageAfter: return chain + Array("garbage".utf8)
        case .garbageBetween: return pemChain([leaf]) + Array("garbage".utf8) + pemChain([issuer.certificate])
        case .malformed: return Array("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".utf8)
        case .sixCertificates: return pemChain([leaf] + Array(repeating: issuer.certificate, count: 5))
        case .tooLarge: return Array(repeating: 32, count: 256 * 1024 + 1)
        default: return chain
        }
    }

    private func endpoint(for url: String) -> Endpoint? {
        if url == Self.directoryURL { return .directory }
        if url == Self.base + "/new-nonce" { return .nonce }
        if url == Self.base + "/new-account" { return .account }
        if url == config.directoryOrderURL { return .newOrder }
        for order in orders.values {
            if url == orderURL(order.id) { return .order }
            if url == orderURL(order.id) + "/finalize" { return .finalize }
            if url == orderURL(order.id) + "/certificate" { return .certificate }
            for index in order.authorizations.indices {
                if url == authorizationURL(order.id, index) { return .authorization }
                if url == challengeURL(order.id, index) { return .challenge }
            }
        }
        return nil
    }

    private func resourceNumbers(_ url: String) -> [Int] { url.split(separator: "/").compactMap { Int($0) } }
    private func orderURL(_ id: Int) -> String { Self.base + "/order/\(id)" }
    private func authorizationURL(_ id: Int, _ index: Int) -> String { Self.base + "/authorization/\(id)/\(index)" }
    private func challengeURL(_ id: Int, _ index: Int) -> String { Self.base + "/challenge/\(id)/\(index)" }
    private func randomValue() -> String {
        FakeACMECrypto.base64URL(SHA256.hash(data: P256.Signing.PrivateKey().publicKey.x963Representation))
    }

    private func json(_ object: [String: Any]) -> [UInt8] {
        // Callers provide only JSON-representable values. On failure, sends an empty body so the server self-test can detect it.
        Array((try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data())
    }

    private func problem(_ status: Int, _ type: String) -> ACMEHTTPResponse {
        var object: [String: Any] = ["type": Self.errorPrefix + type]
        if type == "badSignatureAlgorithm" { object["algorithms"] = ["ES256"] }
        return reply(status, bytes: json(object), contentType: "application/problem+json")
    }

    private func reply(
        _ status: Int, object: [String: Any], location: String? = nil,
        retryAfter: String? = nil, endpoint: Endpoint? = nil
    ) -> ACMEHTTPResponse {
        reply(status, bytes: json(object), location: location, retryAfter: retryAfter, endpoint: endpoint)
    }

    private func reply(
        _ status: Int, bytes: [UInt8], contentType: String = "application/json", location: String? = nil,
        retryAfter: String? = nil, endpoint: Endpoint? = nil
    ) -> ACMEHTTPResponse {
        let nonce = randomValue()
        nonces.insert(nonce)
        var headers: [ACMEHTTPResponse.Header] = [.init(name: "Content-Type", value: contentType)]
        let isNonce = endpoint == .nonce
        switch config.nonceMode {
        case .missing: break
        case .invalid: headers.append(.init(name: "Replay-Nonce", value: "invalid="))
        case .missingExceptNonce where !isNonce: break
        case .invalidExceptNonce where !isNonce: headers.append(.init(name: "Replay-Nonce", value: "invalid="))
        default: headers.append(.init(name: "Replay-Nonce", value: nonce))
        }
        if let location { headers.append(.init(name: "Location", value: location)) }
        if let retryAfter { headers.append(.init(name: "Retry-After", value: retryAfter)) }
        return ACMEHTTPResponse(status: status, headers: headers, body: bytes)
    }
}
