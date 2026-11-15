// 계약 7절 시험 6: JWS. 보호 머리의 필드와 순서 무관한 해석, jwk·kid가 함께 나오지 않음, POST-as-GET의 `""`,
// 서명이 64바이트(R ‖ S)이고 공개 키로 검증됨. RFC 7515 부록 A.3의 서명 검증과 RFC 8555의 예시 메시지 구조.

import CryptoKit
import Foundation
import Testing

@testable import SwiftailCertificates

@Suite("JWS")
struct JWSTests {
    /// 보호 머리를 풀어 JSON 객체로 읽는다(멤버 순서와 무관하게 본다).
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

    @Test("RFC 7515 부록 A.3의 ES256 서명을 공개 키로 검증한다")
    func rfc7515Signature() throws {
        let raw = try #require(Base64URL.decode(RFC7515Example.signature))
        #expect(raw.count == 64)
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: raw)
        let publicKey = try RFC7515Example.publicKey()
        #expect(publicKey.isValidSignature(signature, for: Array(RFC7515Example.signingInput.utf8)))
        #expect(!publicKey.isValidSignature(signature, for: Array((RFC7515Example.signingInput + "x").utf8)))
    }

    /// RFC 8555 8.4의 challenge 응답 예: kid, 본문 `{}`.
    @Test("kid로 서명한 요청: 머리의 멤버와 Go와 같은 바이트, 본문 {}")
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
        // Go `jwsEncodeJSON`의 멤버 순서(alg, kid, nonce, url)와 공백 없는 직렬화.
        #expect(text == #"{"alg":"ES256","kid":"https://example.com/acme/acct/evOfKhNU60wg","nonce":"SS2sSl1PtspvFZ08kNtzKd","url":"https://example.com/acme/chall/Rg5dV14Gh1Q"}"#)
        #expect(jws.payload == "e30")
        #expect(try Self.verifies(jws, with: key.publicKey))
    }

    /// RFC 8555 7.3의 newAccount 예: jwk, kid 없음.
    @Test("jwk로 서명한 요청: 서명 키의 JWK가 실리고 kid는 없다")
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

    @Test("POST-as-GET: 빈 본문은 payload가 \"\"이다 (RFC 8555 6.3)")
    func postAsGet() throws {
        let key = P256.Signing.PrivateKey()
        let jws = try JWS(payload: [], url: "https://example.com/acme/order/1", nonce: "n", keyReference: .accountURL("https://example.com/acme/acct/1"), signedWith: key)
        #expect(jws.payload == "")
        #expect(try Self.verifies(jws, with: key.publicKey))
        let body = try #require(try JSONSerialization.jsonObject(with: Data(jws.flattenedJSON)) as? [String: String])
        #expect(body == ["protected": jws.protected, "payload": "", "signature": jws.signature])
    }

    @Test("Flattened JSON: 세 멤버를 Go jsonWebSignature의 순서로")
    func flattenedJSON() throws {
        let jws = try JWS(payload: Array("{}".utf8), url: "https://example.com/u", nonce: "n", keyReference: .publicKey, signedWith: P256.Signing.PrivateKey())
        #expect(String(decoding: jws.flattenedJSON, as: UTF8.self)
            == #"{"protected":"\#(jws.protected)","payload":"e30","signature":"\#(jws.signature)"}"#)
        #expect(jws.signature.utf8.count == 86)
    }

    @Test("URL과 nonce의 문자열은 Go처럼 이스케이프하고, URL은 다시 인코딩하지 않는다")
    func headerEscaping() throws {
        let url = "https://example.com/acme/order?a=1&b=<2>%20"
        let jws = try JWS(payload: [], url: url, nonce: "n", keyReference: .accountURL("https://example.com/acct"), signedWith: P256.Signing.PrivateKey())
        let (text, object) = try Self.header(jws)
        #expect(object["url"] as? String == url)
        #expect(text.hasSuffix(#""url":"https://example.com/acme/order?a=1\u0026b=\u003c2\u003e%20"}"#))
    }

    @Test("같은 입력의 서명은 실행마다 다르지만 모두 검증된다")
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
