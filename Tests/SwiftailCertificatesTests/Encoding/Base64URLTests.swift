// Contract §7 test 4 (encoding): base64url. Vectors from RFC 4648 §10 and values from RFC 7515 Appendix A.

import Testing

@testable import SwiftailCertificates

@Suite("base64url")
struct Base64URLTests {
    /// The test vectors from RFC 4648 §10 with padding removed. These vectors contain neither `+` nor `/`, so the two alphabets are equivalent for them.
    @Test("RFC 4648 §10 vectors", arguments: [
        ("", ""), ("f", "Zg"), ("fo", "Zm8"), ("foo", "Zm9v"),
        ("foob", "Zm9vYg"), ("fooba", "Zm9vYmE"), ("foobar", "Zm9vYmFy"),
    ])
    func rfc4648Vectors(plain: String, encoded: String) {
        #expect(Base64URL.encode(plain.utf8) == encoded)
        #expect(Base64URL.decode(encoded) == Array(plain.utf8))
    }

    @Test("URL alphabet: 62 is -, 63 is _ (RFC 4648 §5)")
    func urlAlphabet() {
        #expect(Base64URL.encode([0xFB, 0xFF]) == "-_8")
        #expect(Base64URL.encode([0xFF, 0xFF, 0xFE]) == "___-")
        #expect(Base64URL.decode("___-") == [0xFF, 0xFF, 0xFE])
    }

    @Test("Header and body from RFC 7515 Appendix A")
    func rfc7515Values() {
        #expect(Base64URL.encode(#"{"alg":"ES256"}"#.utf8) == "eyJhbGciOiJFUzI1NiJ9")
        let payload = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}"
        #expect(Base64URL.encode(payload.utf8)
            == "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ")
    }

    @Test("Strict parsing rejects padding, whitespace, the standard alphabet, truncated text, and nonzero trailing bits", arguments: [
        "Zg==", "Zm8=", "Zm9v=", "Zm 9v", "Zm9v\n", " Zm9v", "+/8", "-/8", "Z", "Zm9vY",
        "Zh", "Zm9", "Zm9vYmF", "é", "Zm9v\u{0}",
    ])
    func strictDecoding(_ text: String) {
        #expect(Base64URL.decode(text) == nil)
    }

    @Test("Round trips for lengths 0–66")
    func roundTrip() {
        var random = SplitMix64(seed: 0x6234_7375_726c)
        for count in 0...66 {
            let bytes = random.bytes(count)
            let text = Base64URL.encode(bytes)
            #expect(text.utf8.count == (count * 8 + 5) / 6)
            #expect(Base64URL.decode(text) == bytes)
        }
    }

    @Test("Arbitrary text does not cause a crash, and accepted text is canonically encoded")
    func randomText() {
        var random = SplitMix64(seed: 0xb64)
        let characters = Array("AZaz09-_+/= \n.é".unicodeScalars)
        for _ in 0..<5_000 {
            let length = Int.random(in: 0...24, using: &random)
            var text = ""
            for _ in 0..<length {
                text.unicodeScalars.append(characters[Int.random(in: 0..<characters.count, using: &random)])
            }
            if let bytes = Base64URL.decode(text) {
                #expect(Base64URL.encode(bytes) == text)
            }
        }
    }
}
