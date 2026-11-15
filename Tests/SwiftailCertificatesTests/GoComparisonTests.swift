// Go 기준값과 Swift의 인증서 인코딩·서명 구현의 대조 시험(M7-8의 시험 부분).
//
// 자료(`Fixtures/acme-fixtures.json`, 22개 사례)는 `tailscale.com/tempfork/acme`와 Go 표준 라이브러리로 만들었고 Swift
// 소스를 읽지 않았다. 이 시험은 구현(M7-3)을 쓴 세션과 다른 세션이 썼다. 무엇을 어떻게 견주는지는 노트 7장 1·2와 계약
// 7절의 "Go 기준값 대조"를 따른다.
//
// - 바이트로 견준다: JWK 정규 문자열, 지문, 키 인가, DNS-01 TXT 값, CSR의 `certificationRequestInfo`.
// - 의미로 견준다: JWS 보호 머리(복호화해 멤버와 값). Swift가 Go와 같은 직렬화를 택했으므로 바이트도 따로 견준다.
// - 서명은 바이트로 견주지 않는다. Go가 서명한 것을 CryptoKit이 검증하고, Swift가 만든 것을 Go 도구가 검증한다.
//
// 1~4는 자료만으로 돈다. 5(`GoVerifiesSwiftTests`)는 환경 변수 `SWIFTAIL_ACMEFIXTURES`에 `acmefixtures`의 경로가 있을
// 때만 돈다(`sh Scripts/build-interop-tools.sh acmefixtures`가 경로를 낸다).
//
// 건너뛰는 사례: `csrs`의 `name-253`은 `CertificateDomain`이 받지 않는 이름(상한 237)이라 Swift가 그 이름으로 CSR을
// 만들 길이 없다. `nameOf253IsRejected`가 받지 않음을 단언하고, `nameOf253InfoViaDERValue`가 `DERValue`로 같은 구조를
// 시험 안에서 직접 짜서 긴 길이(`0x82`) 인코딩만 Go 바이트와 견준다. 그 밖의 사례는 모두 쓴다.

import CryptoKit
import Foundation
import Testing

@testable import SwiftailCertificates

// MARK: - 공통

/// 자료의 고정 nonce와 가짜 URL 값(`Tools/interop/README.md`의 acmefixtures 절).
private enum Constants {
    static let nonce = "AAECAwQFBgcICQoLDA0ODw"
    static let newAccountURL = "https://acme.invalid/new-account"
    static let authorizationURL = "https://acme.invalid/authz/1"
    static let accountURL = "https://acme.invalid/account/1"
}

private func jsonObject(_ text: String) throws -> NSDictionary {
    try #require(JSONSerialization.jsonObject(with: Data(text.utf8)) as? NSDictionary, "JSON 객체가 아님")
}

private func publicJWK(_ key: OracleKey) -> [String: String] {
    ["crv": key.publicKey.crv, "kty": key.publicKey.kty, "x": key.publicKey.x, "y": key.publicKey.y]
}

private func isValid(rawSignature: [UInt8], for input: [UInt8], publicKey: P256.Signing.PublicKey) throws -> Bool {
    try publicKey.isValidSignature(P256.Signing.ECDSASignature(rawRepresentation: rawSignature), for: input)
}

// MARK: - 자료의 구성

@Suite("Go 기준값: 자료의 구성")
struct GoFixtureShapeTests {
    @Test("22개 사례(키 3, 키 인가 9, JWS 6, CSR 4)이고 모두 자료의 키를 가리킨다")
    func caseCounts() throws {
        let fixtures = try GoOracle.fixtures()
        #expect(fixtures.caseCount == 22)
        #expect(fixtures.keys.count == 3)
        #expect(fixtures.challenges.count == 9)
        #expect(fixtures.jws.count == 6)
        #expect(fixtures.csrs.count == 4)
        #expect(fixtures.keys.count + fixtures.challenges.count + fixtures.jws.count + fixtures.csrs.count == fixtures.caseCount)
        let ids = Set(fixtures.keys.map(\.id))
        #expect(ids == ["account", "leading-zero-x", "leading-zero-y"])
        for challenge in fixtures.challenges { #expect(ids.contains(challenge.keyID)) }
        for jws in fixtures.jws { #expect(ids.contains(jws.keyID)) }
        for csr in fixtures.csrs { #expect(ids.contains(csr.keyID)) }
    }

    @Test("좌표 앞자리가 0인 키가 정말 그 좌표를 가진다(자료의 전제)")
    func leadingZeroCoordinates() throws {
        let fixtures = try GoOracle.fixtures()
        let x = try #require(Base64URL.decode(try fixtures.key("leading-zero-x").publicKey.x))
        let y = try #require(Base64URL.decode(try fixtures.key("leading-zero-y").publicKey.y))
        #expect(x.count == 32 && x.first == 0)
        #expect(y.count == 32 && y.first == 0)
    }
}

// MARK: - 1. 키

@Suite("Go 기준값: 키(JWK·지문·PEM)")
struct GoKeyComparisonTests {
    @Test("JWK 정규 문자열은 Go와 바이트까지 같고 지문이 같다")
    func canonicalJSONAndThumbprint() throws {
        for fixture in try GoOracle.fixtures().keys {
            let jwk = JWK(try fixture.privateKey().publicKey)
            #expect(Array(jwk.canonicalJSON.utf8) == Array(fixture.jwkJSON.utf8), "키 \(fixture.id): canonicalJSON 바이트")
            #expect(jwk.thumbprint == fixture.thumbprint, "키 \(fixture.id): 지문")
            #expect(Base64URL.encode(jwk.x) == fixture.publicKey.x && Base64URL.encode(jwk.y) == fixture.publicKey.y, "키 \(fixture.id): 좌표")
            #expect(jwk.x.count == 32 && jwk.y.count == 32, "키 \(fixture.id): 좌표는 선행 0을 포함해 32바이트")
        }
    }

    @Test("Go가 쓴 SEC1·PKCS#8 PEM을 Swift가 읽으면 같은 키가 나온다")
    func readsGoPEM() throws {
        for fixture in try GoOracle.fixtures().keys {
            let key = try fixture.privateKey()
            #expect(fixture.sec1PEM.hasPrefix("-----BEGIN EC PRIVATE KEY-----\n"), "키 \(fixture.id): SEC1 라벨")
            #expect(fixture.pkcs8PEM.hasPrefix("-----BEGIN PRIVATE KEY-----\n"), "키 \(fixture.id): PKCS#8 라벨")
            for (format, pem) in [("SEC1", fixture.sec1PEM), ("PKCS#8", fixture.pkcs8PEM)] {
                let read = try P256.Signing.PrivateKey(pemFile: Array(pem.utf8), maximumByteCount: 64 * 1024)
                #expect(read.publicKey.x963Representation == key.publicKey.x963Representation, "키 \(fixture.id) \(format): 공개 키")
                #expect(read.rawRepresentation == key.rawRepresentation, "키 \(fixture.id) \(format): 개인 스칼라")
                #expect(JWK(read.publicKey).canonicalJSON == fixture.jwkJSON, "키 \(fixture.id) \(format): JWK")
            }
        }
    }

    @Test("Go의 PEM을 읽어 다시 쓰면 같은 바이트다(64열, LF)")
    func pemRoundTripMatchesGoText() throws {
        for fixture in try GoOracle.fixtures().keys {
            for pem in [fixture.sec1PEM, fixture.pkcs8PEM] {
                let blocks = try PEM.decode(Array(pem.utf8), maximumByteCount: 64 * 1024)
                #expect(blocks.count == 1)
                #expect(blocks.map(PEM.encode).joined() == pem, "키 \(fixture.id): PEM 글")
            }
        }
    }
}

// MARK: - 2. 키 인가

@Suite("Go 기준값: 키 인가와 DNS-01 TXT")
struct GoKeyAuthorizationComparisonTests {
    @Test("9개 사례의 키 인가와 TXT 값이 Go와 바이트까지 같다")
    func keyAuthorizationAndTXT() throws {
        let fixtures = try GoOracle.fixtures()
        for challenge in fixtures.challenges {
            let jwk = JWK(try fixtures.key(challenge.keyID).privateKey().publicKey)
            let authorization = KeyAuthorization(token: challenge.token, accountKey: jwk)
            let label = "키 \(challenge.keyID), token \(challenge.token)"
            #expect(Array(authorization.value.utf8) == Array(challenge.keyAuthorization.utf8), "\(label): keyAuthorization")
            #expect(Array(authorization.dns01TXTValue.utf8) == Array(challenge.dns01TXT.utf8), "\(label): dns01TXT")
            #expect(authorization.dns01TXTValue.utf8.count == 43, "\(label): TXT는 43바이트")
        }
    }
}

// MARK: - 3. JWS

@Suite("Go 기준값: JWS")
struct GoJWSComparisonTests {
    /// 자료의 보호 머리에서 읽은 요청 입력(nonce, url, jwk/kid)으로 Swift가 JWS를 만든다.
    private struct Rebuilt {
        var fixture: OracleJWS
        var jws: JWS
        var header: NSDictionary
    }

    private static func rebuild(_ fixture: OracleJWS, fixtures: OracleFixtures) throws -> Rebuilt {
        let goHeader = try jsonObject(fixture.protectedJSON)
        let nonce = try #require(goHeader["nonce"] as? String)
        let url = try #require(goHeader["url"] as? String)
        let reference: JWS.KeyReference
        switch fixture.mode {
        case "jwk":
            #expect(goHeader["kid"] == nil && goHeader["jwk"] != nil, "자료의 jwk 머리")
            reference = .publicKey
        case "kid":
            #expect(goHeader["jwk"] == nil, "자료의 kid 머리")
            reference = .accountURL(try #require(goHeader["kid"] as? String))
        default:
            throw OracleFailure("알 수 없는 mode \(fixture.mode)")
        }
        let jws = try JWS(
            payload: Array(fixture.payloadJSON.utf8), url: url, nonce: nonce, keyReference: reference,
            signedWith: try fixtures.key(fixture.keyID).privateKey())
        let headerBytes = try #require(Base64URL.decode(jws.protected))
        return Rebuilt(fixture: fixture, jws: jws, header: try jsonObject(String(decoding: headerBytes, as: UTF8.self)))
    }

    private static func label(_ fixture: OracleJWS) -> String { "키 \(fixture.keyID), \(fixture.mode)" }

    @Test("보호 머리를 풀면 멤버와 값이 Go의 protectedJSON과 같다(의미)")
    func protectedHeaderSemantics() throws {
        let fixtures = try GoOracle.fixtures()
        for fixture in fixtures.jws {
            let rebuilt = try Self.rebuild(fixture, fixtures: fixtures)
            let goHeader = try jsonObject(fixture.protectedJSON)
            #expect(Set(rebuilt.header.allKeys.compactMap { $0 as? String }) == Set(goHeader.allKeys.compactMap { $0 as? String }), "\(Self.label(fixture)): 멤버 이름")
            #expect(rebuilt.header.isEqual(goHeader), "\(Self.label(fixture)): 멤버 값")
        }
    }

    @Test("보호 머리 JSON의 바이트가 Go와 같다(같은 직렬화를 택한 결과)")
    func protectedHeaderBytes() throws {
        let fixtures = try GoOracle.fixtures()
        for fixture in fixtures.jws {
            let rebuilt = try Self.rebuild(fixture, fixtures: fixtures)
            let swiftBytes = try #require(Base64URL.decode(rebuilt.jws.protected))
            #expect(swiftBytes == Array(fixture.protectedJSON.utf8), "\(Self.label(fixture)): 보호 머리 JSON 바이트")
            #expect(rebuilt.jws.protected == fixture.verifiedExample.protected, "\(Self.label(fixture)): base64url(보호 머리)")
        }
    }

    @Test("본문과 서명 입력의 바이트가 Go와 같다(POST-as-GET은 빈 문자열)")
    func payloadAndSigningInput() throws {
        let fixtures = try GoOracle.fixtures()
        var postAsGet = 0
        for fixture in fixtures.jws {
            let rebuilt = try Self.rebuild(fixture, fixtures: fixtures)
            let example = fixture.verifiedExample
            #expect(rebuilt.jws.payload == example.payload, "\(Self.label(fixture)): payload")
            #expect(Array((rebuilt.jws.protected + "." + rebuilt.jws.payload).utf8) == Array(fixture.signingInput.utf8), "\(Self.label(fixture)): signingInput")
            // 자료 자체의 일관성: 서명 입력은 `protected.payload`이고 POST-as-GET의 본문은 빈 문자열이다.
            #expect(fixture.signingInput == example.protected + "." + example.payload, "\(Self.label(fixture)): 자료의 signingInput")
            if fixture.payloadJSON.isEmpty {
                postAsGet += 1
                #expect(rebuilt.jws.payload.isEmpty && example.payload.isEmpty, "\(Self.label(fixture)): POST-as-GET")
            }
            #expect(rebuilt.jws.flattenedJSON == Array(#"{"protected":"\#(example.protected)","payload":"\#(example.payload)","signature":"\#(rebuilt.jws.signature)"}"#.utf8), "\(Self.label(fixture)): Flattened JSON의 멤버 순서")
        }
        #expect(postAsGet == 3, "POST-as-GET 사례는 키마다 하나")
    }

    @Test("Swift의 서명은 64바이트이고 자기 공개 키로 검증된다")
    func swiftSignatureVerifies() throws {
        let fixtures = try GoOracle.fixtures()
        for fixture in fixtures.jws {
            let rebuilt = try Self.rebuild(fixture, fixtures: fixtures)
            let publicKey = try fixtures.key(fixture.keyID).privateKey().publicKey
            let raw = try #require(Base64URL.decode(rebuilt.jws.signature))
            #expect(raw.count == 64, "\(Self.label(fixture)): R ‖ S")
            #expect(try isValid(rawSignature: raw, for: Array(fixture.signingInput.utf8), publicKey: publicKey), "\(Self.label(fixture)): 서명 검증")
        }
    }

    @Test("Go가 서명한 JWS를 CryptoKit이 검증한다")
    func verifiesGoSignature() throws {
        let fixtures = try GoOracle.fixtures()
        for fixture in fixtures.jws {
            let publicKey = try fixtures.key(fixture.keyID).privateKey().publicKey
            let example = fixture.verifiedExample
            let raw = try #require(Base64URL.decode(example.signature))
            #expect(raw.count == 64, "\(Self.label(fixture)): Go 서명은 R ‖ S 64바이트")
            let input = Array((example.protected + "." + example.payload).utf8)
            #expect(try isValid(rawSignature: raw, for: input, publicKey: publicKey), "\(Self.label(fixture)): Go 서명")
            // 검증이 실제로 입력을 본다는 확인.
            #expect(try !isValid(rawSignature: raw, for: input + [UInt8(ascii: "x")], publicKey: publicKey), "\(Self.label(fixture)): 변조한 입력")
            // 다른 키로는 통과하지 않는다.
            let otherFixture = try #require(fixtures.keys.first { $0.id != fixture.keyID })
            let other = try otherFixture.privateKey().publicKey
            #expect(try !isValid(rawSignature: raw, for: input, publicKey: other), "\(Self.label(fixture)): 다른 키")
        }
    }
}

// MARK: - 4. CSR

@Suite("Go 기준값: CSR")
struct GoCSRComparisonTests {
    /// Go의 ecdsa-with-SHA256 AlgorithmIdentifier(매개변수 없음).
    private static let ecdsaWithSHA256: [UInt8] = [0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]

    @Test("Swift가 만든 certificationRequestInfo가 Go와 바이트까지 같다(253자 이름 제외)")
    func certificationRequestInfoBytes() throws {
        let fixtures = try GoOracle.fixtures()
        var compared = 0
        for csr in fixtures.csrs {
            guard let domain = CertificateDomain(csr.domain) else { continue }  // 253자 이름: `nameOf253` 시험이 다룬다.
            let key = try fixtures.key(csr.keyID).privateKey()
            let request = try CertificateSigningRequest(domain: domain, signedWith: key)
            let goInfo = try #require(GoOracle.bytes(fromHex: csr.certificationRequestInfoHex), "\(csr.name): hex")
            #expect(request.certificationRequestInfo == goInfo, "\(csr.name): certificationRequestInfo 바이트")
            // 전체 DER에서도 가른 첫 SEQUENCE가 같다. 서명은 실행마다 다르므로 견주지 않는다.
            let parts = try #require(GoOracle.csrParts(request.der), "\(csr.name): Swift DER의 바깥 구조")
            #expect(parts.info.encoded == goInfo, "\(csr.name): Swift DER 안의 info")
            #expect(parts.algorithm.encoded == Self.ecdsaWithSHA256, "\(csr.name): signatureAlgorithm")
            #expect(GoOracle.commonNameStringTag(info: request.certificationRequestInfo) == UInt8(csr.cnStringTag), "\(csr.name): CN 태그")
            compared += 1
        }
        #expect(compared == 3, "받는 이름의 사례 셋을 모두 견줌")
    }

    @Test("Go의 CSR 전체 DER에서 서명을 떼어 CryptoKit으로 검증한다")
    func verifiesGoCSRSignature() throws {
        let fixtures = try GoOracle.fixtures()
        for csr in fixtures.csrs {
            let publicKey = try fixtures.key(csr.keyID).privateKey().publicKey
            let der = try #require(GoOracle.bytes(fromHex: csr.derHex), "\(csr.name): derHex")
            let goInfo = try #require(GoOracle.bytes(fromHex: csr.certificationRequestInfoHex), "\(csr.name): info hex")
            let parts = try #require(GoOracle.csrParts(der), "\(csr.name): 바깥 SEQUENCE 셋")
            #expect(parts.info.encoded == goInfo, "\(csr.name): 자료의 info가 derHex 안의 info와 같다")
            #expect(parts.algorithm.encoded == Self.ecdsaWithSHA256, "\(csr.name): signatureAlgorithm")
            #expect(GoOracle.commonNameStringTag(info: goInfo) == UInt8(csr.cnStringTag) && csr.cnStringTag == 19, "\(csr.name): CN은 PrintableString")
            let signature = try P256.Signing.ECDSASignature(derRepresentation: parts.signatureDER)
            #expect(publicKey.isValidSignature(signature, for: goInfo), "\(csr.name): Go 서명")
            var tampered = goInfo
            tampered[tampered.count - 1] ^= 0x01
            #expect(!publicKey.isValidSignature(signature, for: tampered), "\(csr.name): 변조한 info는 거절")
        }
    }

    @Test("253자 이름은 CertificateDomain이 받지 않는다(상한 237)")
    func nameOf253IsRejected() throws {
        let fixtures = try GoOracle.fixtures()
        let csr = try #require(fixtures.csrs.first { $0.name == "name-253" })
        #expect(csr.domain.utf8.count == 253)
        #expect(CertificateDomain.maximumLength == 237)
        #expect(CertificateDomain(csr.domain) == nil)
        // 다른 세 이름은 받는다.
        #expect(fixtures.csrs.filter { CertificateDomain($0.domain) != nil }.count == 3)
    }

    /// 253자 이름의 CSR은 `CertificateSigningRequest`로 만들 길이 없으므로, 같은 구조를 `DERValue`로 시험 안에서 짠다.
    /// CertificateSigningRequest의 문서 구조(RFC 2986, Go의 `certRequest`)를 그대로 옮긴 것이라 이름 검사 밖에서
    /// DER의 긴 길이(`0x82`)와 SAN·CN의 큰 문자열 인코딩만 Go 바이트와 견준다.
    @Test("253자 이름: 같은 구조를 DERValue로 짜서 Go의 info와 바이트로 견준다")
    func nameOf253InfoViaDERValue() throws {
        let fixtures = try GoOracle.fixtures()
        let csr = try #require(fixtures.csrs.first { $0.name == "name-253" })
        let publicKey = try fixtures.key(csr.keyID).privateKey().publicKey
        let commonName = try #require(PrintableString(csr.domain))
        let dnsName = try #require(IA5String(csr.domain))
        let subjectAltName = DERValue.sequence([
            .objectIdentifier(.subjectAltName),
            .octetString(DERValue.sequence([.implicitlyTagged(number: 2, .ia5String(dnsName))]).encoded),
        ])
        let info = DERValue.sequence([
            .integer(magnitude: []),
            .sequence([.setOf([.sequence([.objectIdentifier(.commonName), .printableString(commonName)])])]),
            .sequence([
                .sequence([.objectIdentifier(.ecPublicKey), .objectIdentifier(.secp256r1)]),
                .bitString(Array(publicKey.x963Representation)),
            ]),
            .implicitlyTagged(number: 0, .setOf([
                .sequence([.objectIdentifier(.extensionRequest), .setOf([.sequence([subjectAltName])])]),
            ])),
        ])
        let goInfo = try #require(GoOracle.bytes(fromHex: csr.certificationRequestInfoHex))
        #expect(info.encoded == goInfo, "name-253: info 바이트")
        #expect(goInfo.count > 255 && goInfo[1] == 0x82, "자료가 긴 길이 경계를 실제로 밟는다")
    }
}

// MARK: - 5. Swift가 만든 것을 Go가 검증한다

@Suite(
    "Go 기준값: Swift가 만든 것을 Go 도구가 검증한다",
    .enabled(if: GoOracle.toolPath != nil, "SWIFTAIL_ACMEFIXTURES가 없어 Go 도구 검증을 건너뜁니다"),
    .timeLimit(.minutes(3)))
struct GoVerifiesSwiftTests {
    /// 이름 목록: 짧은 이름, 보통 이름, 63자 레이블, 상한 237자, 레이블이 많은 이름.
    private static let names: [String] = {
        let label63 = String(repeating: "a", count: 63)
        let longest = [label63, String(repeating: "b", count: 63), String(repeating: "c", count: 63), String(repeating: "d", count: 45)].joined(separator: ".")
        return ["a.ts.net", "rd-mac-1a2b3c4d.tail0001.ts.net", "\(label63).tail0001.ts.net", longest, "a.b.c.d.e.f.g.ts.net", "x-1.tail0001.ts.net"]
    }()

    private static func expectOK(_ response: [String: Any], _ label: String) {
        #expect(response["ok"] as? Bool == true, "\(label): Go가 거절함: \(response["error"] ?? "(오류 없음)")")
    }

    private static func expectRejected(_ response: [String: Any], _ label: String) {
        #expect(response["ok"] as? Bool == false, "\(label): Go가 받아들임")
        #expect((response["error"] as? String)?.isEmpty == false, "\(label): 거절에 설명이 있다")
    }

    /// 자료의 키 셋과 그 자리에서 만든 키들.
    private static func keys(fresh count: Int) throws -> [P256.Signing.PrivateKey] {
        try GoOracle.fixtures().keys.map { try $0.privateKey() } + (0..<count).map { _ in P256.Signing.PrivateKey() }
    }

    // MARK: 양성 대조(도구 입력 형식이 맞는지)

    @Test("양성 대조: 도구가 자료의 Go 예제를 받아들인다")
    func toolAcceptsGoFixtures() async throws {
        let fixtures = try GoOracle.fixtures()
        for fixture in fixtures.jws {
            let key = try fixtures.key(fixture.keyID)
            var request: [String: Any] = [
                "jws": ["protected": fixture.verifiedExample.protected, "payload": fixture.verifiedExample.payload, "signature": fixture.verifiedExample.signature],
                "jwk": publicJWK(key),
                "expectedNonce": Constants.nonce,
                "expectedURL": fixture.mode == "jwk" ? Constants.newAccountURL : Constants.authorizationURL,
            ]
            if fixture.mode == "kid" { request["expectedKID"] = Constants.accountURL }
            let response = try await GoOracle.ask("verify-jws", request)
            Self.expectOK(response, "verify-jws 자료 \(fixture.keyID) \(fixture.mode)")
            #expect((response["protected"] as? NSDictionary)?.isEqual(try jsonObject(fixture.protectedJSON)) == true)
        }
        for csr in fixtures.csrs {
            let response = try await GoOracle.ask("verify-csr", ["derHex": csr.derHex])
            Self.expectOK(response, "verify-csr 자료 \(csr.name)")
            #expect(response["cnStringTag"] as? Int == 19)
        }
        for key in fixtures.keys {
            for pem in [key.sec1PEM, key.pkcs8PEM] {
                let response = try await GoOracle.ask("parse-key", ["pem": pem])
                Self.expectOK(response, "parse-key 자료 \(key.id)")
                #expect(response["publicKey"] as? [String: String] == publicJWK(key))
            }
        }
    }

    // MARK: JWS

    private struct JWSVariant {
        var name: String
        var reference: JWS.KeyReference
        var payload: [UInt8]
        var nonce: String
        var url: String
        var expectedKID: String?
    }

    private static let jwsVariants: [JWSVariant] = [
        JWSVariant(
            name: "jwk newAccount", reference: .publicKey,
            payload: Array(#"{"termsOfServiceAgreed":true,"contact":["mailto:ops@example.invalid"]}"#.utf8),
            nonce: Constants.nonce, url: Constants.newAccountURL, expectedKID: nil),
        JWSVariant(name: "jwk 본문 {}", reference: .publicKey, payload: Array("{}".utf8), nonce: "n-_0aA", url: Constants.newAccountURL, expectedKID: nil),
        JWSVariant(
            name: "kid 본문", reference: .accountURL(Constants.accountURL), payload: Array(#"{"status":"deactivated"}"#.utf8),
            nonce: Constants.nonce, url: Constants.authorizationURL, expectedKID: Constants.accountURL),
        JWSVariant(
            name: "kid POST-as-GET", reference: .accountURL(Constants.accountURL), payload: [],
            nonce: Constants.nonce, url: Constants.authorizationURL, expectedKID: Constants.accountURL),
        JWSVariant(
            name: "kid POST-as-GET, 이스케이프할 문자가 든 URL", reference: .accountURL(Constants.accountURL), payload: [],
            nonce: "AA-_", url: "https://acme.invalid/order/7?a=b&c=%3C&d=<>", expectedKID: Constants.accountURL),
    ]

    @Test("Swift가 만든 JWS(jwk·kid·POST-as-GET)를 Go가 검증하고 보호 머리·본문이 넣은 것과 같다")
    func goVerifiesSwiftJWS() async throws {
        for (index, key) in try Self.keys(fresh: 5).enumerated() {
            for variant in Self.jwsVariants {
                let label = "키 \(index), \(variant.name)"
                let jws = try JWS(payload: variant.payload, url: variant.url, nonce: variant.nonce, keyReference: variant.reference, signedWith: key)
                var request: [String: Any] = [
                    "jws": ["protected": jws.protected, "payload": jws.payload, "signature": jws.signature],
                    "jwk": GoOracle.jwkObject(key.publicKey),
                    "expectedNonce": variant.nonce,
                    "expectedURL": variant.url,
                ]
                if let kid = variant.expectedKID { request["expectedKID"] = kid }
                let response = try await GoOracle.ask("verify-jws", request)
                Self.expectOK(response, label)
                let sent = try jsonObject(String(decoding: try #require(Base64URL.decode(jws.protected)), as: UTF8.self))
                #expect((response["protected"] as? NSDictionary)?.isEqual(sent) == true, "\(label): 돌려준 보호 머리")
                #expect(response["payloadHex"] as? String == GoOracle.hexString(variant.payload), "\(label): 본문")
                #expect(response["signingInput"] as? String == jws.protected + "." + jws.payload, "\(label): signingInput")
            }
        }
    }

    @Test("변조한 JWS는 Go가 거절한다")
    func goRejectsTamperedJWS() async throws {
        let key = P256.Signing.PrivateKey()
        let other = P256.Signing.PrivateKey()
        let payload = Array(#"{"status":"deactivated"}"#.utf8)
        let jws = try JWS(payload: payload, url: Constants.authorizationURL, nonce: Constants.nonce, keyReference: .accountURL(Constants.accountURL), signedWith: key)

        func request(
            protected: String? = nil, payload: String? = nil, signature: String? = nil,
            publicKey: P256.Signing.PublicKey? = nil, nonce: String = Constants.nonce, url: String = Constants.authorizationURL
        ) -> [String: Any] {
            [
                "jws": ["protected": protected ?? jws.protected, "payload": payload ?? jws.payload, "signature": signature ?? jws.signature],
                "jwk": GoOracle.jwkObject(publicKey ?? key.publicKey),
                "expectedNonce": nonce, "expectedURL": url, "expectedKID": Constants.accountURL,
            ]
        }

        Self.expectOK(try await GoOracle.ask("verify-jws", request()), "변조 전(대조)")
        var flipped = try #require(Base64URL.decode(jws.signature))
        flipped[0] ^= 0x01
        Self.expectRejected(try await GoOracle.ask("verify-jws", request(signature: Base64URL.encode(flipped))), "서명 한 비트")
        Self.expectRejected(try await GoOracle.ask("verify-jws", request(payload: Base64URL.encode(Array(#"{"status":"valid"}"#.utf8)))), "본문 바꿈")
        Self.expectRejected(try await GoOracle.ask("verify-jws", request(publicKey: other.publicKey)), "다른 공개 키")
        Self.expectRejected(try await GoOracle.ask("verify-jws", request(nonce: "AAAA")), "다른 nonce")
        Self.expectRejected(try await GoOracle.ask("verify-jws", request(url: "https://acme.invalid/authz/2")), "다른 URL")
    }

    // MARK: CSR

    @Test("Swift가 만든 CSR(여러 이름, 여러 키)을 Go가 검증하고 CN·SAN·공개 키·알고리즘·태그가 맞다")
    func goVerifiesSwiftCSR() async throws {
        let keys = try Self.keys(fresh: 20)
        for (index, key) in keys.enumerated() {
            let name = Self.names[index % Self.names.count]
            let label = "키 \(index), 이름 \(name.utf8.count)자"
            let domain = try #require(CertificateDomain(name), "\(label): 이름 검사")
            let request = try CertificateSigningRequest(domain: domain, signedWith: key)
            let response = try await GoOracle.ask("verify-csr", ["derHex": GoOracle.hexString(request.der)])
            Self.expectOK(response, label)
            #expect(response["commonName"] as? String == name, "\(label): CN")
            #expect(response["dnsNames"] as? [String] == [name], "\(label): dnsNames")
            #expect(response["publicKey"] as? [String: String] == GoOracle.jwkObject(key.publicKey), "\(label): 공개 키")
            #expect(response["signatureAlgorithm"] as? String == "ECDSA-SHA256", "\(label): 서명 알고리즘")
            #expect(response["cnStringTag"] as? Int == 19, "\(label): CN 태그")
            #expect(response["certificationRequestInfoHex"] as? String == GoOracle.hexString(request.certificationRequestInfo), "\(label): Go가 읽은 info")
        }
    }

    @Test("변조한 CSR은 Go가 거절한다")
    func goRejectsTamperedCSR() async throws {
        let name = "rd-mac-1a2b3c4d.tail0001.ts.net"
        let domain = try #require(CertificateDomain(name))
        let request = try CertificateSigningRequest(domain: domain, signedWith: P256.Signing.PrivateKey())
        Self.expectOK(try await GoOracle.ask("verify-csr", ["derHex": GoOracle.hexString(request.der)]), "변조 전(대조)")

        var signatureByte = request.der
        signatureByte[signatureByte.count - 1] ^= 0x01
        Self.expectRejected(try await GoOracle.ask("verify-csr", ["derHex": GoOracle.hexString(signatureByte)]), "서명 끝 바이트")

        // 이름의 첫 글자를 한 칸 올린다(`r`→`s`). 문자열은 여전히 올바른 PrintableString이므로 서명 검사가 거절해야 한다.
        var nameByte = request.der
        let start = try #require(nameByte.firstRange(of: Array(name.utf8))?.lowerBound)
        nameByte[start] += 1
        Self.expectRejected(try await GoOracle.ask("verify-csr", ["derHex": GoOracle.hexString(nameByte)]), "CN의 글자")

        Self.expectRejected(try await GoOracle.ask("verify-csr", ["derHex": GoOracle.hexString(Array(request.der.dropLast(4)))]), "잘림")
    }

    // MARK: 키 PEM

    @Test("Swift가 쓴 PKCS#8 PEM을 Go가 읽고 공개 키가 같다")
    func goParsesSwiftPEM() async throws {
        for (index, key) in try Self.keys(fresh: 20).enumerated() {
            let pem = PEM.encode(PEMBlock(label: .privateKey, der: Array(key.derRepresentation)))
            let response = try await GoOracle.ask("parse-key", ["pem": pem])
            Self.expectOK(response, "키 \(index)")
            #expect(response["format"] as? String == "PRIVATE KEY", "키 \(index): 형식")
            #expect(response["publicKey"] as? [String: String] == GoOracle.jwkObject(key.publicKey), "키 \(index): 공개 키")
        }
    }

    @Test("깨진 키 PEM은 Go가 거절한다")
    func goRejectsBrokenPEM() async throws {
        let key = P256.Signing.PrivateKey()
        let pem = PEM.encode(PEMBlock(label: .privateKey, der: Array(key.derRepresentation)))
        Self.expectOK(try await GoOracle.ask("parse-key", ["pem": pem]), "깨기 전(대조)")
        // PKCS#8 본문에 SEC1 라벨을 붙인다.
        let wrongLabel = pem.replacingOccurrences(of: "PRIVATE KEY", with: "EC PRIVATE KEY")
        Self.expectRejected(try await GoOracle.ask("parse-key", ["pem": wrongLabel]), "라벨과 본문이 다름")
        // 끝 경계선이 없다.
        let truncated = String(pem.dropLast("-----END PRIVATE KEY-----\n".count))
        Self.expectRejected(try await GoOracle.ask("parse-key", ["pem": truncated]), "끝 경계선 없음")
        // 뒤에 쓰레기가 붙는다.
        Self.expectRejected(try await GoOracle.ask("parse-key", ["pem": pem + "garbage\n"]), "뒤따르는 글")
    }
}
