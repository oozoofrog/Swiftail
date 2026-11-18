// Compares Swift certificate encoding and signing with Go reference values (the test portion of M7-8).
//
// The 22 cases in `Fixtures/acme-fixtures.json` were generated with `tailscale.com/tempfork/acme` and the Go standard library without reading the Swift
// sources. A different session from the one that wrote the implementation (M7-3) wrote this test. The compared values and methods follow note chapter 7 items 1 and 2 and
// the Go reference comparison in contract §7.
//
// - Compare byte for byte: canonical JWK strings, thumbprints, key authorization, DNS-01 TXT values, and CSR `certificationRequestInfo`.
// - Compare semantically: decoded JWS protected header members and values. Swift chose the same serialization as Go, so also compare the bytes separately.
// - Compare signatures by verification. CryptoKit verifies Go signatures, and the Go tool verifies Swift signatures.
//
// Sections 1–4 run with the fixtures alone. Section 5 (`GoVerifiesSwiftTests`) runs only with the `acmefixtures` path in `SWIFTAIL_ACMEFIXTURES`
// (`sh Scripts/build-interop-tools.sh acmefixtures` prints the path).
//
// Skipped case: `name-253` in `csrs` is a name that `CertificateDomain` rejects (limit 237), so Swift cannot build a CSR for it through that path.
// `nameOf253IsRejected` asserts rejection, and `nameOf253InfoViaDERValue` builds the same structure with `DERValue`
// in the test to compare only the long-form length (`0x82`) encoding with Go's bytes. All other cases are used.

import CryptoKit
import Foundation
import Testing

@testable import SwiftailCertificates

// MARK: - Shared support

/// Fixed nonce and fake URL values from the fixtures (acmefixtures section in `Tools/interop/README.md`).
private enum Constants {
    static let nonce = "AAECAwQFBgcICQoLDA0ODw"
    static let newAccountURL = "https://acme.invalid/new-account"
    static let authorizationURL = "https://acme.invalid/authz/1"
    static let accountURL = "https://acme.invalid/account/1"
}

private func jsonObject(_ text: String) throws -> NSDictionary {
    try #require(JSONSerialization.jsonObject(with: Data(text.utf8)) as? NSDictionary, "Expected a JSON object")
}

private func publicJWK(_ key: OracleKey) -> [String: String] {
    ["crv": key.publicKey.crv, "kty": key.publicKey.kty, "x": key.publicKey.x, "y": key.publicKey.y]
}

private func isValid(rawSignature: [UInt8], for input: [UInt8], publicKey: P256.Signing.PublicKey) throws -> Bool {
    try publicKey.isValidSignature(P256.Signing.ECDSASignature(rawRepresentation: rawSignature), for: input)
}

// MARK: - Fixture structure

@Suite("Go reference values: fixture structure")
struct GoFixtureShapeTests {
    @Test("All 22 cases (3 keys, 9 key authorizations, 6 JWS, and 4 CSRs) refer to fixture keys")
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

    @Test("The leading-zero keys have the stated coordinates (fixture prerequisite)")
    func leadingZeroCoordinates() throws {
        let fixtures = try GoOracle.fixtures()
        let x = try #require(Base64URL.decode(try fixtures.key("leading-zero-x").publicKey.x))
        let y = try #require(Base64URL.decode(try fixtures.key("leading-zero-y").publicKey.y))
        #expect(x.count == 32 && x.first == 0)
        #expect(y.count == 32 && y.first == 0)
    }
}

// MARK: - 1. Keys

@Suite("Go reference values: keys (JWK, thumbprints, and PEM)")
struct GoKeyComparisonTests {
    @Test("Canonical JWK strings match Go byte for byte, and thumbprints match")
    func canonicalJSONAndThumbprint() throws {
        for fixture in try GoOracle.fixtures().keys {
            let jwk = JWK(try fixture.privateKey().publicKey)
            #expect(Array(jwk.canonicalJSON.utf8) == Array(fixture.jwkJSON.utf8), "Key \(fixture.id): canonicalJSON bytes")
            #expect(jwk.thumbprint == fixture.thumbprint, "Key \(fixture.id): thumbprint")
            #expect(Base64URL.encode(jwk.x) == fixture.publicKey.x && Base64URL.encode(jwk.y) == fixture.publicKey.y, "Key \(fixture.id): coordinates")
            #expect(jwk.x.count == 32 && jwk.y.count == 32, "Key \(fixture.id): coordinates are 32 bytes including leading zeros")
        }
    }

    @Test("Swift reads the same keys from Go-written SEC1 and PKCS#8 PEM")
    func readsGoPEM() throws {
        for fixture in try GoOracle.fixtures().keys {
            let key = try fixture.privateKey()
            #expect(fixture.sec1PEM.hasPrefix("-----BEGIN EC PRIVATE KEY-----\n"), "Key \(fixture.id): SEC1 label")
            #expect(fixture.pkcs8PEM.hasPrefix("-----BEGIN PRIVATE KEY-----\n"), "Key \(fixture.id): PKCS#8 label")
            for (format, pem) in [("SEC1", fixture.sec1PEM), ("PKCS#8", fixture.pkcs8PEM)] {
                let read = try P256.Signing.PrivateKey(pemFile: Array(pem.utf8), maximumByteCount: 64 * 1024)
                #expect(read.publicKey.x963Representation == key.publicKey.x963Representation, "Key \(fixture.id) \(format): public key")
                #expect(read.rawRepresentation == key.rawRepresentation, "Key \(fixture.id) \(format): private scalar")
                #expect(JWK(read.publicKey).canonicalJSON == fixture.jwkJSON, "Key \(fixture.id) \(format): JWK")
            }
        }
    }

    @Test("Parsing and rewriting Go PEM preserves the bytes (64 columns, LF)")
    func pemRoundTripMatchesGoText() throws {
        for fixture in try GoOracle.fixtures().keys {
            for pem in [fixture.sec1PEM, fixture.pkcs8PEM] {
                let blocks = try PEM.decode(Array(pem.utf8), maximumByteCount: 64 * 1024)
                #expect(blocks.count == 1)
                #expect(blocks.map(PEM.encode).joined() == pem, "Key \(fixture.id): PEM text")
            }
        }
    }
}

// MARK: - 2. Key authorization

@Suite("Go reference values: key authorization and DNS-01 TXT")
struct GoKeyAuthorizationComparisonTests {
    @Test("Key authorization and TXT values match Go byte for byte in all 9 cases")
    func keyAuthorizationAndTXT() throws {
        let fixtures = try GoOracle.fixtures()
        for challenge in fixtures.challenges {
            let jwk = JWK(try fixtures.key(challenge.keyID).privateKey().publicKey)
            let authorization = KeyAuthorization(token: challenge.token, accountKey: jwk)
            let label = "Key \(challenge.keyID), token \(challenge.token)"
            #expect(Array(authorization.value.utf8) == Array(challenge.keyAuthorization.utf8), "\(label): keyAuthorization")
            #expect(Array(authorization.dns01TXTValue.utf8) == Array(challenge.dns01TXT.utf8), "\(label): dns01TXT")
            #expect(authorization.dns01TXTValue.utf8.count == 43, "\(label): TXT is 43 bytes")
        }
    }
}

// MARK: - 3. JWS

@Suite("Go reference values: JWS")
struct GoJWSComparisonTests {
    /// Swift builds a JWS from the request inputs (nonce, url, jwk/kid) read from the fixture's protected header.
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
            #expect(goHeader["kid"] == nil && goHeader["jwk"] != nil, "Fixture jwk header")
            reference = .publicKey
        case "kid":
            #expect(goHeader["jwk"] == nil, "Fixture kid header")
            reference = .accountURL(try #require(goHeader["kid"] as? String))
        default:
            throw OracleFailure("Unknown mode \(fixture.mode)")
        }
        let jws = try JWS(
            payload: Array(fixture.payloadJSON.utf8), url: url, nonce: nonce, keyReference: reference,
            signedWith: try fixtures.key(fixture.keyID).privateKey())
        let headerBytes = try #require(Base64URL.decode(jws.protected))
        return Rebuilt(fixture: fixture, jws: jws, header: try jsonObject(String(decoding: headerBytes, as: UTF8.self)))
    }

    private static func label(_ fixture: OracleJWS) -> String { "Key \(fixture.keyID), \(fixture.mode)" }

    @Test("Decoded protected header members and values match Go protectedJSON semantically")
    func protectedHeaderSemantics() throws {
        let fixtures = try GoOracle.fixtures()
        for fixture in fixtures.jws {
            let rebuilt = try Self.rebuild(fixture, fixtures: fixtures)
            let goHeader = try jsonObject(fixture.protectedJSON)
            #expect(Set(rebuilt.header.allKeys.compactMap { $0 as? String }) == Set(goHeader.allKeys.compactMap { $0 as? String }), "\(Self.label(fixture)): member names")
            #expect(rebuilt.header.isEqual(goHeader), "\(Self.label(fixture)): member values")
        }
    }

    @Test("Protected header JSON bytes match Go because both use the same serialization")
    func protectedHeaderBytes() throws {
        let fixtures = try GoOracle.fixtures()
        for fixture in fixtures.jws {
            let rebuilt = try Self.rebuild(fixture, fixtures: fixtures)
            let swiftBytes = try #require(Base64URL.decode(rebuilt.jws.protected))
            #expect(swiftBytes == Array(fixture.protectedJSON.utf8), "\(Self.label(fixture)): protected header JSON bytes")
            #expect(rebuilt.jws.protected == fixture.verifiedExample.protected, "\(Self.label(fixture)): base64url of the protected header")
        }
    }

    @Test("Body and signing input bytes match Go (POST-as-GET uses an empty string)")
    func payloadAndSigningInput() throws {
        let fixtures = try GoOracle.fixtures()
        var postAsGet = 0
        for fixture in fixtures.jws {
            let rebuilt = try Self.rebuild(fixture, fixtures: fixtures)
            let example = fixture.verifiedExample
            #expect(rebuilt.jws.payload == example.payload, "\(Self.label(fixture)): payload")
            #expect(Array((rebuilt.jws.protected + "." + rebuilt.jws.payload).utf8) == Array(fixture.signingInput.utf8), "\(Self.label(fixture)): signingInput")
            // Fixture consistency: the signing input is `protected.payload`, and POST-as-GET has an empty body string.
            #expect(fixture.signingInput == example.protected + "." + example.payload, "\(Self.label(fixture)): fixture signingInput")
            if fixture.payloadJSON.isEmpty {
                postAsGet += 1
                #expect(rebuilt.jws.payload.isEmpty && example.payload.isEmpty, "\(Self.label(fixture)): POST-as-GET")
            }
            #expect(rebuilt.jws.flattenedJSON == Array(#"{"protected":"\#(example.protected)","payload":"\#(example.payload)","signature":"\#(rebuilt.jws.signature)"}"#.utf8), "\(Self.label(fixture)): Flattened JSON member order")
        }
        #expect(postAsGet == 3, "One POST-as-GET case per key")
    }

    @Test("Swift signatures are 64 bytes and verify with their public keys")
    func swiftSignatureVerifies() throws {
        let fixtures = try GoOracle.fixtures()
        for fixture in fixtures.jws {
            let rebuilt = try Self.rebuild(fixture, fixtures: fixtures)
            let publicKey = try fixtures.key(fixture.keyID).privateKey().publicKey
            let raw = try #require(Base64URL.decode(rebuilt.jws.signature))
            #expect(raw.count == 64, "\(Self.label(fixture)): R ‖ S")
            #expect(try isValid(rawSignature: raw, for: Array(fixture.signingInput.utf8), publicKey: publicKey), "\(Self.label(fixture)): signature verification")
        }
    }

    @Test("CryptoKit verifies a Go-signed JWS")
    func verifiesGoSignature() throws {
        let fixtures = try GoOracle.fixtures()
        for fixture in fixtures.jws {
            let publicKey = try fixtures.key(fixture.keyID).privateKey().publicKey
            let example = fixture.verifiedExample
            let raw = try #require(Base64URL.decode(example.signature))
            #expect(raw.count == 64, "\(Self.label(fixture)): Go signature is 64 bytes of R ‖ S")
            let input = Array((example.protected + "." + example.payload).utf8)
            #expect(try isValid(rawSignature: raw, for: input, publicKey: publicKey), "\(Self.label(fixture)): Go signature")
            // Confirm that verification checks the input.
            #expect(try !isValid(rawSignature: raw, for: input + [UInt8(ascii: "x")], publicKey: publicKey), "\(Self.label(fixture)): tampered input")
            // Verification fails with another key.
            let otherFixture = try #require(fixtures.keys.first { $0.id != fixture.keyID })
            let other = try otherFixture.privateKey().publicKey
            #expect(try !isValid(rawSignature: raw, for: input, publicKey: other), "\(Self.label(fixture)): different key")
        }
    }
}

// MARK: - 4. CSR

@Suite("Go reference values: CSR")
struct GoCSRComparisonTests {
    /// Go ecdsa-with-SHA256 AlgorithmIdentifier (no parameters).
    private static let ecdsaWithSHA256: [UInt8] = [0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]

    @Test("Swift certificationRequestInfo matches Go byte for byte except for the 253-character name")
    func certificationRequestInfoBytes() throws {
        let fixtures = try GoOracle.fixtures()
        var compared = 0
        for csr in fixtures.csrs {
            guard let domain = CertificateDomain(csr.domain) else { continue }  // The `nameOf253` tests cover the 253-character name.
            let key = try fixtures.key(csr.keyID).privateKey()
            let request = try CertificateSigningRequest(domain: domain, signedWith: key)
            let goInfo = try #require(GoOracle.bytes(fromHex: csr.certificationRequestInfoHex), "\(csr.name): hex")
            #expect(request.certificationRequestInfo == goInfo, "\(csr.name): certificationRequestInfo bytes")
            // The first SEQUENCE extracted from the full DER also matches. Signatures vary by run and are excluded from the comparison.
            let parts = try #require(GoOracle.csrParts(request.der), "\(csr.name): outer structure of Swift DER")
            #expect(parts.info.encoded == goInfo, "\(csr.name): info in Swift DER")
            #expect(parts.algorithm.encoded == Self.ecdsaWithSHA256, "\(csr.name): signatureAlgorithm")
            #expect(GoOracle.commonNameStringTag(info: request.certificationRequestInfo) == UInt8(csr.cnStringTag), "\(csr.name): CN tag")
            compared += 1
        }
        #expect(compared == 3, "Compared all three accepted name cases")
    }

    @Test("Extracts the signature from Go's full CSR DER and verifies it with CryptoKit")
    func verifiesGoCSRSignature() throws {
        let fixtures = try GoOracle.fixtures()
        for csr in fixtures.csrs {
            let publicKey = try fixtures.key(csr.keyID).privateKey().publicKey
            let der = try #require(GoOracle.bytes(fromHex: csr.derHex), "\(csr.name): derHex")
            let goInfo = try #require(GoOracle.bytes(fromHex: csr.certificationRequestInfoHex), "\(csr.name): info hex")
            let parts = try #require(GoOracle.csrParts(der), "\(csr.name): three elements of the outer SEQUENCE")
            #expect(parts.info.encoded == goInfo, "\(csr.name): fixture info matches the info inside derHex")
            #expect(parts.algorithm.encoded == Self.ecdsaWithSHA256, "\(csr.name): signatureAlgorithm")
            #expect(GoOracle.commonNameStringTag(info: goInfo) == UInt8(csr.cnStringTag) && csr.cnStringTag == 19, "\(csr.name): CN is PrintableString")
            let signature = try P256.Signing.ECDSASignature(derRepresentation: parts.signatureDER)
            #expect(publicKey.isValidSignature(signature, for: goInfo), "\(csr.name): Go signature")
            var tampered = goInfo
            tampered[tampered.count - 1] ^= 0x01
            #expect(!publicKey.isValidSignature(signature, for: tampered), "\(csr.name): rejects tampered info")
        }
    }

    @Test("CertificateDomain rejects a 253-character name (limit 237)")
    func nameOf253IsRejected() throws {
        let fixtures = try GoOracle.fixtures()
        let csr = try #require(fixtures.csrs.first { $0.name == "name-253" })
        #expect(csr.domain.utf8.count == 253)
        #expect(CertificateDomain.maximumLength == 237)
        #expect(CertificateDomain(csr.domain) == nil)
        // The other three names are accepted.
        #expect(fixtures.csrs.filter { CertificateDomain($0.domain) != nil }.count == 3)
    }

    /// Since `CertificateSigningRequest` cannot build a CSR for a 253-character name, build the same structure with `DERValue` in the test.
    /// This copies the documented CertificateSigningRequest structure (RFC 2986, Go `certRequest`). Bypassing name validation lets the test
    /// compare only DER long-form lengths (`0x82`) and the encoding of long SAN and CN strings with Go's bytes.
    @Test("253-character name: builds the same structure with DERValue and compares it byte for byte with Go info")
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
        #expect(info.encoded == goInfo, "name-253: info bytes")
        #expect(goInfo.count > 255 && goInfo[1] == 0x82, "The fixture actually exercises the long-form length boundary")
    }
}

// MARK: - 5. Go verifies Swift output

@Suite(
    "Go reference values: the Go tool verifies Swift output",
    .enabled(if: GoOracle.toolPath != nil, "SWIFTAIL_ACMEFIXTURES is missing, so Go tool verification is skipped"),
    .timeLimit(.minutes(3)))
struct GoVerifiesSwiftTests {
    /// Name list: short name, typical name, 63-character label, 237-character limit, and a name with many labels.
    private static let names: [String] = {
        let label63 = String(repeating: "a", count: 63)
        let longest = [label63, String(repeating: "b", count: 63), String(repeating: "c", count: 63), String(repeating: "d", count: 45)].joined(separator: ".")
        return ["a.ts.net", "rd-mac-1a2b3c4d.tail0001.ts.net", "\(label63).tail0001.ts.net", longest, "a.b.c.d.e.f.g.ts.net", "x-1.tail0001.ts.net"]
    }()

    private static func expectOK(_ response: [String: Any], _ label: String) {
        #expect(response["ok"] as? Bool == true, "\(label): Go rejected it: \(response["error"] ?? "(no error)")")
    }

    private static func expectRejected(_ response: [String: Any], _ label: String) {
        #expect(response["ok"] as? Bool == false, "\(label): Go accepted it")
        #expect((response["error"] as? String)?.isEmpty == false, "\(label): rejection has an explanation")
    }

    /// The fixture key set and keys generated on the spot.
    private static func keys(fresh count: Int) throws -> [P256.Signing.PrivateKey] {
        try GoOracle.fixtures().keys.map { try $0.privateKey() } + (0..<count).map { _ in P256.Signing.PrivateKey() }
    }

    // MARK: Positive control (checks the tool input format)

    @Test("Positive control: the tool accepts the fixture's Go examples")
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
            Self.expectOK(response, "verify-jws fixture \(fixture.keyID) \(fixture.mode)")
            #expect((response["protected"] as? NSDictionary)?.isEqual(try jsonObject(fixture.protectedJSON)) == true)
        }
        for csr in fixtures.csrs {
            let response = try await GoOracle.ask("verify-csr", ["derHex": csr.derHex])
            Self.expectOK(response, "verify-csr fixture \(csr.name)")
            #expect(response["cnStringTag"] as? Int == 19)
        }
        for key in fixtures.keys {
            for pem in [key.sec1PEM, key.pkcs8PEM] {
                let response = try await GoOracle.ask("parse-key", ["pem": pem])
                Self.expectOK(response, "parse-key fixture \(key.id)")
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
        JWSVariant(name: "jwk body {}", reference: .publicKey, payload: Array("{}".utf8), nonce: "n-_0aA", url: Constants.newAccountURL, expectedKID: nil),
        JWSVariant(
            name: "kid body", reference: .accountURL(Constants.accountURL), payload: Array(#"{"status":"deactivated"}"#.utf8),
            nonce: Constants.nonce, url: Constants.authorizationURL, expectedKID: Constants.accountURL),
        JWSVariant(
            name: "kid POST-as-GET", reference: .accountURL(Constants.accountURL), payload: [],
            nonce: Constants.nonce, url: Constants.authorizationURL, expectedKID: Constants.accountURL),
        JWSVariant(
            name: "kid POST-as-GET with a URL containing characters that need escaping", reference: .accountURL(Constants.accountURL), payload: [],
            nonce: "AA-_", url: "https://acme.invalid/order/7?a=b&c=%3C&d=<>", expectedKID: Constants.accountURL),
    ]

    @Test("Go verifies Swift-generated JWS (jwk, kid, and POST-as-GET), with the original protected header and body")
    func goVerifiesSwiftJWS() async throws {
        for (index, key) in try Self.keys(fresh: 5).enumerated() {
            for variant in Self.jwsVariants {
                let label = "Key \(index), \(variant.name)"
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
                #expect((response["protected"] as? NSDictionary)?.isEqual(sent) == true, "\(label): returned protected header")
                #expect(response["payloadHex"] as? String == GoOracle.hexString(variant.payload), "\(label): body")
                #expect(response["signingInput"] as? String == jws.protected + "." + jws.payload, "\(label): signingInput")
            }
        }
    }

    @Test("Go rejects tampered JWS")
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

        Self.expectOK(try await GoOracle.ask("verify-jws", request()), "Before tampering (control)")
        var flipped = try #require(Base64URL.decode(jws.signature))
        flipped[0] ^= 0x01
        Self.expectRejected(try await GoOracle.ask("verify-jws", request(signature: Base64URL.encode(flipped))), "One signature bit")
        Self.expectRejected(try await GoOracle.ask("verify-jws", request(payload: Base64URL.encode(Array(#"{"status":"valid"}"#.utf8)))), "Changed body")
        Self.expectRejected(try await GoOracle.ask("verify-jws", request(publicKey: other.publicKey)), "Different public key")
        Self.expectRejected(try await GoOracle.ask("verify-jws", request(nonce: "AAAA")), "Different nonce")
        Self.expectRejected(try await GoOracle.ask("verify-jws", request(url: "https://acme.invalid/authz/2")), "Different URL")
    }

    // MARK: CSR

    @Test("Go verifies Swift-generated CSRs for multiple names and keys, and CN, SAN, public key, algorithm, and tag match")
    func goVerifiesSwiftCSR() async throws {
        let keys = try Self.keys(fresh: 20)
        for (index, key) in keys.enumerated() {
            let name = Self.names[index % Self.names.count]
            let label = "Key \(index), name of \(name.utf8.count) characters"
            let domain = try #require(CertificateDomain(name), "\(label): name validation")
            let request = try CertificateSigningRequest(domain: domain, signedWith: key)
            let response = try await GoOracle.ask("verify-csr", ["derHex": GoOracle.hexString(request.der)])
            Self.expectOK(response, label)
            #expect(response["commonName"] as? String == name, "\(label): CN")
            #expect(response["dnsNames"] as? [String] == [name], "\(label): dnsNames")
            #expect(response["publicKey"] as? [String: String] == GoOracle.jwkObject(key.publicKey), "\(label): public key")
            #expect(response["signatureAlgorithm"] as? String == "ECDSA-SHA256", "\(label): signature algorithm")
            #expect(response["cnStringTag"] as? Int == 19, "\(label): CN tag")
            #expect(response["certificationRequestInfoHex"] as? String == GoOracle.hexString(request.certificationRequestInfo), "\(label): info read by Go")
        }
    }

    @Test("Go rejects tampered CSRs")
    func goRejectsTamperedCSR() async throws {
        let name = "rd-mac-1a2b3c4d.tail0001.ts.net"
        let domain = try #require(CertificateDomain(name))
        let request = try CertificateSigningRequest(domain: domain, signedWith: P256.Signing.PrivateKey())
        Self.expectOK(try await GoOracle.ask("verify-csr", ["derHex": GoOracle.hexString(request.der)]), "Before tampering (control)")

        var signatureByte = request.der
        signatureByte[signatureByte.count - 1] ^= 0x01
        Self.expectRejected(try await GoOracle.ask("verify-csr", ["derHex": GoOracle.hexString(signatureByte)]), "Final signature byte")

        // Increment the first character of the name by one (`r`→`s`). The string remains valid PrintableString, so signature verification must reject it.
        var nameByte = request.der
        let start = try #require(nameByte.firstRange(of: Array(name.utf8))?.lowerBound)
        nameByte[start] += 1
        Self.expectRejected(try await GoOracle.ask("verify-csr", ["derHex": GoOracle.hexString(nameByte)]), "CN character")

        Self.expectRejected(try await GoOracle.ask("verify-csr", ["derHex": GoOracle.hexString(Array(request.der.dropLast(4)))]), "Truncated")
    }

    // MARK: Key PEM

    @Test("Go reads Swift-written PKCS#8 PEM and obtains the same public key")
    func goParsesSwiftPEM() async throws {
        for (index, key) in try Self.keys(fresh: 20).enumerated() {
            let pem = PEM.encode(PEMBlock(label: .privateKey, der: Array(key.derRepresentation)))
            let response = try await GoOracle.ask("parse-key", ["pem": pem])
            Self.expectOK(response, "Key \(index)")
            #expect(response["format"] as? String == "PRIVATE KEY", "Key \(index): format")
            #expect(response["publicKey"] as? [String: String] == GoOracle.jwkObject(key.publicKey), "Key \(index): public key")
        }
    }

    @Test("Go rejects malformed key PEM")
    func goRejectsBrokenPEM() async throws {
        let key = P256.Signing.PrivateKey()
        let pem = PEM.encode(PEMBlock(label: .privateKey, der: Array(key.derRepresentation)))
        Self.expectOK(try await GoOracle.ask("parse-key", ["pem": pem]), "Before corruption (control)")
        // Apply the SEC1 label to the PKCS#8 body.
        let wrongLabel = pem.replacingOccurrences(of: "PRIVATE KEY", with: "EC PRIVATE KEY")
        Self.expectRejected(try await GoOracle.ask("parse-key", ["pem": wrongLabel]), "Label and body mismatch")
        // The closing boundary is missing.
        let truncated = String(pem.dropLast("-----END PRIVATE KEY-----\n".count))
        Self.expectRejected(try await GoOracle.ask("parse-key", ["pem": truncated]), "Missing closing boundary")
        // Garbage follows the block.
        Self.expectRejected(try await GoOracle.ask("parse-key", ["pem": pem + "garbage\n"]), "Trailing text")
    }
}
