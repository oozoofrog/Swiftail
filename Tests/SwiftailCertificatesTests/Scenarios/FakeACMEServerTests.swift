import CryptoKit
import Foundation
import Testing

@testable import SwiftailCertificates

@Suite("독립 ACME 서버 자체 검사")
struct FakeACMEServerTests {
    enum BadRequest: String, Sendable, CaseIterable {
        case reusedNonce, unknownNonce, missingNonce, wrongURL, bothKeys, neitherKey, wrongSignature
        case wrongAlgorithm, badPublicKey, paddedPayload, unprotected, multipleSignatures, missingPayload, unencodedPayload
    }

    @Test(arguments: BadRequest.allCases)
    func rejectsBadJWS(_ kind: BadRequest) async throws {
        let scenario = CertificateScenario()
        let server = scenario.server
        let nonceResponse = try await server.send(.init(method: .head, url: FakeACMEServer.base + "/new-nonce", body: []))
        let nonce = try #require(nonceResponse.firstHeader(named: "Replay-Nonce"))
        let key = scenario.accountKey
        let url = FakeACMEServer.base + "/new-account"
        var header = FakeACMECrypto.Protected(nonce: nonce, url: url, jwk: .init(key.publicKey))
        let payload = Data("{\"termsOfServiceAgreed\":true}".utf8)
        if kind == .reusedNonce {
            let good = try FakeACMECrypto.request(url: url, key: key, header: header, payload: payload)
            let response = try await server.send(.init(method: .post, url: url, body: good))
            #expect(response.status == 201)
        }
        switch kind {
        case .unknownNonce: header.nonce = FakeACMECrypto.base64URL(Data(repeating: 7, count: 32))
        case .missingNonce: header.nonce = nil
        case .wrongURL: header.url = url + "/different"
        case .bothKeys: header.kid = FakeACMEServer.base + "/account/1"
        case .neitherKey: header.jwk = nil
        case .wrongAlgorithm: header.alg = "none"
        case .badPublicKey: header.jwk?.x = "AA"
        case .unencodedPayload: header.b64 = false
        default: break
        }
        var bytes = try FakeACMECrypto.request(
            url: url, key: key, header: header, payload: payload,
            signingKey: kind == .wrongSignature ? P256.Signing.PrivateKey() : nil
        )
        if [.paddedPayload, .unprotected, .multipleSignatures, .missingPayload].contains(kind) {
            var object = try #require(JSONSerialization.jsonObject(with: Data(bytes)) as? [String: Any])
            switch kind {
            case .paddedPayload: object["payload"] = (object["payload"] as? String ?? "") + "="
            case .unprotected: object["header"] = ["alg": "ES256"]
            case .multipleSignatures: object["signatures"] = [["signature": "AA"]]
            case .missingPayload: object.removeValue(forKey: "payload")
            default: break
            }
            bytes = Array(try JSONSerialization.data(withJSONObject: object))
        }
        let response = try await server.send(.init(method: .post, url: url, body: bytes))
        let expected: (Int, String)
        switch kind {
        case .reusedNonce, .unknownNonce, .missingNonce: expected = (400, "badNonce")
        case .wrongURL, .wrongSignature: expected = (403, "unauthorized")
        case .wrongAlgorithm: expected = (400, "badSignatureAlgorithm")
        case .badPublicKey: expected = (400, "badPublicKey")
        default: expected = (400, "malformed")
        }
        #expect(response.status == expected.0)
        #expect(try problemType(response) == FakeACMEServer.errorPrefix + expected.1)
        #expect(response.firstHeader(named: "Replay-Nonce") != nonce)
        #expect(await server.accountCount == (kind == .reusedNonce ? 1 : 0))
    }

    @Test
    func nonceGETAndHEADAndResourceMethods() async throws {
        let scenario = CertificateScenario()
        let server = scenario.server
        let head = try await server.send(.init(method: .head, url: FakeACMEServer.base + "/new-nonce", body: []))
        let get = try await server.send(.init(method: .get, url: FakeACMEServer.base + "/new-nonce", body: []))
        #expect(head.status == 200)
        #expect(get.status == 204)
        #expect(head.body.isEmpty && get.body.isEmpty)
        #expect(head.firstHeader(named: "Cache-Control") == "no-store")
        #expect(head.firstHeader(named: "Replay-Nonce") != get.firstHeader(named: "Replay-Nonce"))
        let forbidden = try await server.send(.init(method: .get, url: FakeACMEServer.base + "/order/1", body: []))
        #expect(forbidden.status == 405)
        #expect(try problemType(forbidden) == FakeACMEServer.errorPrefix + "malformed")
    }

    @Test
    func accountLookupDoesNotCreateAndRegistrationIsIdempotent() async throws {
        let scenario = CertificateScenario()
        let client = HandACMEClient(server: scenario.server, key: scenario.accountKey)
        let missing = try await client.post("/new-account", payload: "{\"onlyReturnExisting\":true}", jwk: true)
        #expect(missing.status == 400)
        #expect(try problemType(missing) == FakeACMEServer.errorPrefix + "accountDoesNotExist")
        #expect(await scenario.server.accountCount == 0)
        let noTerms = try await client.post("/new-account", payload: "{}", jwk: true)
        #expect(noTerms.status == 403)
        let created = try await client.post("/new-account", payload: "{\"termsOfServiceAgreed\":true}", jwk: true)
        let existing = try await client.post("/new-account", payload: "{\"termsOfServiceAgreed\":false}", jwk: true)
        #expect(created.status == 201)
        #expect(existing.status == 200)
        #expect(created.firstHeader(named: "Location") == existing.firstHeader(named: "Location"))
        #expect(await scenario.server.accountCount == 1)
    }

    @Test
    func postAsGETAndChallengePayloadAreChecked() async throws {
        let scenario = CertificateScenario()
        let client = HandACMEClient(server: scenario.server, key: scenario.accountKey)
        try await client.register()
        let order = try await client.newOrder()
        #expect(order.status == 201)
        let wrongRead = try await client.post("/authorization/1/0", payload: "{}")
        #expect(wrongRead.status == 400)
        let wrongAnswer = try await client.post("/challenge/1/0", payload: "")
        #expect(wrongAnswer.status == 400)
        let early = try await client.post("/order/1/finalize", payload: "{}")
        #expect(early.status == 403)
        #expect(try problemType(early) == FakeACMEServer.errorPrefix + "orderNotReady")
        let correctRead = try await client.post("/authorization/1/0", payload: "")
        #expect(correctRead.status == 200)
    }

    enum BadCSR: String, Sendable, CaseIterable { case accountKey, wrongName, badSignature, trailingBytes }

    @Test(arguments: BadCSR.allCases)
    func rejectsBadCSR(_ fault: BadCSR) async throws {
        var config = FakeACMEServer.Configuration()
        config.initialOrderStatuses = ["ready"]
        let scenario = CertificateScenario(config)
        let client = HandACMEClient(server: scenario.server, key: scenario.accountKey)
        try await client.register()
        _ = try await client.newOrder()
        let key = fault == .accountKey ? scenario.accountKey : scenario.certificateKey
        var csr = try handCSR(key, name: fault == .wrongName ? "other.tail0001.ts.net" : FakeACMEServer.domain)
        if fault == .badSignature { csr[csr.count - 1] ^= 1 }
        if fault == .trailingBytes { csr.append(0) }
        let response = try await client.post(
            "/order/1/finalize", payload: "{\"csr\":\"\(FakeACMECrypto.base64URL(csr))\"}"
        )
        #expect(response.status == 400)
        #expect(try problemType(response) == FakeACMEServer.errorPrefix + "badCSR")
    }

    @Test
    func acceptsIndependentCSRAndChecksCertificateAccept() async throws {
        var config = FakeACMEServer.Configuration()
        config.initialOrderStatuses = ["ready"]
        config.finalizeStatuses = ["valid"]
        let scenario = CertificateScenario(config)
        let client = HandACMEClient(server: scenario.server, key: scenario.accountKey)
        try await client.register()
        _ = try await client.newOrder()
        let csr = try handCSR(scenario.certificateKey, name: FakeACMEServer.domain)
        let accepted = try await client.post(
            "/order/1/finalize", payload: "{\"csr\":\"\(FakeACMECrypto.base64URL(csr))\"}"
        )
        #expect(accepted.status == 200)
        let noAccept = try await client.post("/order/1/certificate", payload: "")
        #expect(noAccept.status == 406)
        let certificate = try await client.post("/order/1/certificate", payload: "", accept: "application/pem-certificate-chain")
        #expect(certificate.status == 200)
        #expect(certificate.firstHeader(named: "Content-Type") == "application/pem-certificate-chain")
    }

    @Test
    func authenticationAndOrderOwnershipAreChecked() async throws {
        let scenario = CertificateScenario()
        let first = HandACMEClient(server: scenario.server, key: scenario.accountKey)
        let second = HandACMEClient(server: scenario.server, key: P256.Signing.PrivateKey())
        try await first.register()
        _ = try await first.newOrder()
        try await second.register()
        let wrongSigner = try await second.post("/order/1", payload: "")
        #expect(wrongSigner.status == 403)
        let wrongOwner = try await second.post("/order/1", payload: "", kid: FakeACMEServer.base + "/account/2")
        #expect(wrongOwner.status == 403)
        let wrongKeyReference = try await first.post("/order/1", payload: "", jwk: true)
        #expect(wrongKeyReference.status == 403)
        let wrongNewAccountReference = try await first.post("/new-account", payload: "{}")
        #expect(wrongNewAccountReference.status == 400)
        #expect(await scenario.server.orderCount == 1)
    }

    @Test
    func badNonceResponseCanBeUsedForImmediateRetry() async throws {
        let scenario = CertificateScenario()
        let url = FakeACMEServer.base + "/new-account"
        let key = scenario.accountKey
        var header = FakeACMECrypto.Protected(nonce: "unknown", url: url, jwk: .init(key.publicKey))
        let payload = Data("{\"termsOfServiceAgreed\":true}".utf8)
        let bad = try FakeACMECrypto.request(url: url, key: key, header: header, payload: payload)
        let rejected = try await scenario.server.send(.init(method: .post, url: url, body: bad))
        #expect(try problemType(rejected) == FakeACMEServer.errorPrefix + "badNonce")
        let retryNonce = try #require(rejected.firstHeader(named: "Replay-Nonce"))
        header.nonce = retryNonce
        let retry = try FakeACMECrypto.request(url: url, key: key, header: header, payload: payload)
        let accepted = try await scenario.server.send(.init(method: .post, url: url, body: retry))
        #expect(accepted.status == 201)
    }

    @Test
    func challengeRetryKeepsTerminalStateAndIgnoresUnknownFields() async throws {
        let scenario = CertificateScenario()
        let client = HandACMEClient(server: scenario.server, key: scenario.accountKey)
        try await client.register()
        _ = try await client.newOrder()
        let invalid = try await client.post("/challenge/1/0", payload: "{\"unknown\":true}")
        #expect(invalid.status == 200)
        let object = try #require(JSONSerialization.jsonObject(with: Data(invalid.body)) as? [String: Any])
        #expect(object["status"] as? String == "invalid")
        // 실패 뒤 올바른 TXT를 올려도 이미 invalid인 challenge를 되살려서는 안 된다.
        let token = try #require(object["token"] as? String)
        scenario.dns.publish(
            "_acme-challenge." + FakeACMEServer.domain,
            FakeACMECrypto.dnsValue(token: token, account: .init(scenario.accountKey.publicKey))
        )
        let retried = try await client.post("/challenge/1/0", payload: "{}")
        let retriedObject = try #require(JSONSerialization.jsonObject(with: Data(retried.body)) as? [String: Any])
        #expect(retriedObject["status"] as? String == "invalid")
    }

    private func problemType(_ response: ACMEHTTPResponse) throws -> String {
        let object = try #require(JSONSerialization.jsonObject(with: Data(response.body)) as? [String: Any])
        return try #require(object["type"] as? String)
    }
}

/// 서버 자체 시험용 클라이언트. 라이브러리 JWS·CSR 생성기를 쓰지 않는다.
private struct HandACMEClient {
    let server: FakeACMEServer
    let key: P256.Signing.PrivateKey

    func post(
        _ path: String, payload: String, jwk: Bool = false, accept: String? = nil, kid: String? = nil
    ) async throws -> ACMEHTTPResponse {
        let nonceResponse = try await server.send(.init(method: .head, url: FakeACMEServer.base + "/new-nonce", body: []))
        let nonce = try #require(nonceResponse.firstHeader(named: "Replay-Nonce"))
        let url = FakeACMEServer.base + path
        let header = FakeACMECrypto.Protected(
            nonce: nonce, url: url, jwk: jwk ? .init(key.publicKey) : nil,
            kid: jwk ? nil : (kid ?? FakeACMEServer.base + "/account/1")
        )
        let body = try FakeACMECrypto.request(url: url, key: key, header: header, payload: Data(payload.utf8))
        return try await server.send(.init(method: .post, url: url, body: body, accept: accept))
    }

    func register() async throws {
        let response = try await post("/new-account", payload: "{\"termsOfServiceAgreed\":true}", jwk: true)
        #expect(response.status == 201)
    }

    func newOrder() async throws -> ACMEHTTPResponse {
        try await post("/new-order", payload: "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"\(FakeACMEServer.domain)\"}]}")
    }
}

/// CN만 쓰는 유효한 PKCS#10. RFC 8555 7.4는 CN 또는 SAN을 허용하므로 서버가 SAN을 강제하지 않는다.
private func handCSR(_ key: P256.Signing.PrivateKey, name: String) throws -> Data {
    func tlv(_ tag: UInt8, _ content: Data) -> Data {
        var length = content.count
        var encodedLength: [UInt8] = []
        repeat { encodedLength.insert(UInt8(length & 255), at: 0); length >>= 8 } while length > 0
        if content.count >= 128 { encodedLength.insert(0x80 | UInt8(encodedLength.count), at: 0) }
        return Data([tag] + encodedLength) + content
    }
    let cn = tlv(0x30, Data([6, 3, 0x55, 4, 3]) + tlv(0x13, Data(name.utf8)))
    let subject = tlv(0x30, tlv(0x31, cn))
    let info = tlv(0x30, Data([2, 1, 0]) + subject + key.publicKey.derRepresentation + Data([0xA0, 0]))
    let signature = try key.signature(for: info)
    let algorithm = Data([0x30, 0x0A, 6, 8, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 4, 3, 2])
    return tlv(0x30, info + algorithm + tlv(3, Data([0]) + signature.derRepresentation))
}
