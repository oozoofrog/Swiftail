// Contract §7 test 6: JWS. Protected header fields and order-independent interpretation, mutual exclusion of jwk and kid, `""` for POST-as-GET,
// and a 64-byte signature (R ‖ S) verifiable with the public key. Also verifies the RFC 7515 Appendix A.3 signature and the structure of RFC 8555 example messages.

import CryptoKit
import Foundation
import Testing

@testable import SwiftailCertificates

@Suite("JWS")
struct JWSTests {
    /// Decodes the protected header as a JSON object, ignoring member order.
    private static func header(_ jws: JWS) throws -> (text: String, object: [String: Any]) {
        let bytes = try #require(Base64URL.decode(jws.protected))
        let object = try #require(try JSONSerialization.jsonObject(with: Data(bytes)) as? [String: Any])
        return (String(decoding: bytes, as: UTF8.self), object)
    }

    private static func verifies(_ jws: JWS, with publicKey: P256.Signing.PublicKey) throws -> Bool {
        let raw = try #require(Base64URL.decode(jws.signature))
        #expect(raw.count == 64)
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: raw)
        return publicKey.isValidSignature(signature, for: Array((jws.protected + "." + jws.payload).utf8))
    }

    @Test("Verifies the RFC 7515 Appendix A.3 ES256 signature with the public key")
    func rfc7515Signature() throws {
        let raw = try #require(Base64URL.decode(RFC7515Example.signature))
        #expect(raw.count == 64)
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: raw)
        let publicKey = try RFC7515Example.publicKey()
        #expect(publicKey.isValidSignature(signature, for: Array(RFC7515Example.signingInput.utf8)))
        #expect(!publicKey.isValidSignature(signature, for: Array((RFC7515Example.signingInput + "x").utf8)))
    }

    /// RFC 8555 8.4 challenge response example: kid and a `{}` body.
    @Test("Request signed with kid: header members and bytes matching Go, and a {} body")
    func accountURLRequest() throws {
        let key = try RFC7515Example.privateKey()
        let jws = try JWS(
            payload: Array("{}".utf8),
            url: "https://example.com/acme/chall/Rg5dV14Gh1Q",
            nonce: "SS2sSl1PtspvFZ08kNtzKd",
            keyReference: .accountURL("https://example.com/acme/acct/evOfKhNU60wg"),
            signedWith: key
        )
        let (text, object) = try Self.header(jws)
        #expect(Set(object.keys) == ["alg", "kid", "nonce", "url"])
        #expect(object["alg"] as? String == "ES256")
        #expect(object["kid"] as? String == "https://example.com/acme/acct/evOfKhNU60wg")
        #expect(object["nonce"] as? String == "SS2sSl1PtspvFZ08kNtzKd")
        #expect(object["url"] as? String == "https://example.com/acme/chall/Rg5dV14Gh1Q")
        // Go `jwsEncodeJSON` member order (alg, kid, nonce, url) and whitespace-free serialization.
        #expect(text == #"{"alg":"ES256","kid":"https://example.com/acme/acct/evOfKhNU60wg","nonce":"SS2sSl1PtspvFZ08kNtzKd","url":"https://example.com/acme/chall/Rg5dV14Gh1Q"}"#)
        #expect(jws.payload == "e30")
        #expect(try Self.verifies(jws, with: key.publicKey))
    }

    /// RFC 8555 7.3 newAccount example: jwk and no kid.
    @Test("A request signed with jwk carries the signing key's JWK and omits kid")
    func publicKeyRequest() throws {
        let key = P256.Signing.PrivateKey()
        let payload = Array(#"{"termsOfServiceAgreed":true}"#.utf8)
        let jws = try JWS(
            payload: payload, url: "https://example.com/acme/new-account", nonce: "6S8IqOGY7eL2lsGoTZYifg",
            keyReference: .publicKey, signedWith: key
        )
        let (text, object) = try Self.header(jws)
        #expect(Set(object.keys) == ["alg", "jwk", "nonce", "url"])
        let jwk = try #require(object["jwk"] as? [String: String])
        let expected = JWK(key.publicKey)
        #expect(jwk == ["crv": "P-256", "kty": "EC", "x": Base64URL.encode(expected.x), "y": Base64URL.encode(expected.y)])
        #expect(text == #"{"alg":"ES256","jwk":"# + expected.canonicalJSON + #","nonce":"6S8IqOGY7eL2lsGoTZYifg","url":"https://example.com/acme/new-account"}"#)
        #expect(Base64URL.decode(jws.payload) == payload)
        #expect(try Self.verifies(jws, with: key.publicKey))
        #expect(try !Self.verifies(jws, with: P256.Signing.PrivateKey().publicKey))
    }

    @Test("POST-as-GET: an empty body has a payload of \"\" (RFC 8555 6.3)")
    func postAsGet() throws {
        let key = P256.Signing.PrivateKey()
        let jws = try JWS(payload: [], url: "https://example.com/acme/order/1", nonce: "n", keyReference: .accountURL("https://example.com/acme/acct/1"), signedWith: key)
        #expect(jws.payload == "")
        #expect(try Self.verifies(jws, with: key.publicKey))
        let body = try #require(try JSONSerialization.jsonObject(with: Data(jws.flattenedJSON)) as? [String: String])
        #expect(body == ["protected": jws.protected, "payload": "", "signature": jws.signature])
    }

    @Test("Flattened JSON: three members in Go jsonWebSignature order")
    func flattenedJSON() throws {
        let jws = try JWS(payload: Array("{}".utf8), url: "https://example.com/u", nonce: "n", keyReference: .publicKey, signedWith: P256.Signing.PrivateKey())
        #expect(String(decoding: jws.flattenedJSON, as: UTF8.self)
            == #"{"protected":"\#(jws.protected)","payload":"e30","signature":"\#(jws.signature)"}"#)
        #expect(jws.signature.utf8.count == 86)
    }

    @Test("Escapes URL and nonce strings like Go and does not re-encode the URL")
    func headerEscaping() throws {
        let url = "https://example.com/acme/order?a=1&b=<2>%20"
        let jws = try JWS(payload: [], url: url, nonce: "n", keyReference: .accountURL("https://example.com/acct"), signedWith: P256.Signing.PrivateKey())
        let (text, object) = try Self.header(jws)
        #expect(object["url"] as? String == url)
        #expect(text.hasSuffix(#""url":"https://example.com/acme/order?a=1\u0026b=\u003c2\u003e%20"}"#))
    }

    @Test("Signatures for identical inputs vary by run and all verify")
    func signaturesAreRandomizedButValid() throws {
        let key = P256.Signing.PrivateKey()
        let make = { () throws -> JWS in
            try JWS(payload: Array("{}".utf8), url: "https://example.com/u", nonce: "n", keyReference: .publicKey, signedWith: key)
        }
        let first = try make(), second = try make()
        #expect(first.protected == second.protected && first.payload == second.payload)
        #expect(first.signature != second.signature)
        #expect(try Self.verifies(first, with: key.publicKey) && Self.verifies(second, with: key.publicKey))
    }
}
