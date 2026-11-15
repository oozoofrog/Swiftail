// 계약 7절 시험 4(인코딩): base64url. RFC 4648 10절의 벡터와 RFC 7515 부록 A의 값.

import Testing

@testable import SwiftailCertificates

@Suite("base64url")
struct Base64URLTests {
    /// RFC 4648 10절의 시험 벡터에서 채움 문자를 뗀 것(이 벡터에는 `+`·`/`가 없어 두 알파벳이 같다).
    @Test("RFC 4648 10절의 벡터", arguments: [
        ("", ""), ("f", "Zg"), ("fo", "Zm8"), ("foo", "Zm9v"),
        ("foob", "Zm9vYg"), ("fooba", "Zm9vYmE"), ("foobar", "Zm9vYmFy"),
    ])
    func rfc4648Vectors(plain: String, encoded: String) {
        #expect(Base64URL.encode(plain.utf8) == encoded)
        #expect(Base64URL.decode(encoded) == Array(plain.utf8))
    }

    @Test("URL 알파벳: 62는 -, 63은 _ (RFC 4648 5절)")
    func urlAlphabet() {
        #expect(Base64URL.encode([0xFB, 0xFF]) == "-_8")
        #expect(Base64URL.encode([0xFF, 0xFF, 0xFE]) == "___-")
        #expect(Base64URL.decode("___-") == [0xFF, 0xFF, 0xFE])
    }

    @Test("RFC 7515 부록 A의 머리와 본문")
    func rfc7515Values() {
        #expect(Base64URL.encode(#"{"alg":"ES256"}"#.utf8) == "eyJhbGciOiJFUzI1NiJ9")
        let payload = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}"
        #expect(Base64URL.encode(payload.utf8)
            == "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ")
    }

    @Test("엄격한 읽기: 채움, 공백, 표준 알파벳, 잘린 글, 0이 아닌 남는 비트를 거절", arguments: [
        "Zg==", "Zm8=", "Zm9v=", "Zm 9v", "Zm9v\n", " Zm9v", "+/8", "-/8", "Z", "Zm9vY",
        "Zh", "Zm9", "Zm9vYmF", "é", "Zm9v\u{0}",
    ])
    func strictDecoding(_ text: String) {
        #expect(Base64URL.decode(text) == nil)
    }

    @Test("길이 0~66의 왕복")
    func roundTrip() {
        var random = SplitMix64(seed: 0x6234_7375_726c)
        for count in 0...66 {
            let bytes = random.bytes(count)
            let text = Base64URL.encode(bytes)
            #expect(text.utf8.count == (count * 8 + 5) / 6)
            #expect(Base64URL.decode(text) == bytes)
        }
    }

    @Test("임의 글로 죽지 않고, 읽힌 글은 정규 인코딩이다")
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
