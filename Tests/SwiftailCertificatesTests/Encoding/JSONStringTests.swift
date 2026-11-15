// JWS 보호 머리의 문자열을 Go `json.Marshal`과 같은 바이트로 적는지(Go `encoding/json` `appendString`의 규칙).

import Foundation
import Testing

@testable import SwiftailCertificates

@Suite("JSON 문자열")
struct JSONStringTests {
    @Test("Go json.Marshal과 같은 이스케이프", arguments: [
        ("https://example.com/acme/acct/1", #""https://example.com/acme/acct/1""#),  // `/`는 그대로
        ("a\"b\\c", #""a\"b\\c""#),
        ("\u{08}\u{0C}\n\r\t", #""\b\f\n\r\t""#),
        ("\u{00}\u{01}\u{1F}", #""\u0000\u0001\u001f""#),
        ("<a>&", #""\u003ca\u003e\u0026""#),
        ("\u{2028}\u{2029}", #""\u2028\u2029""#),
        ("é😀\u{7F}", "\"é😀\u{7F}\""),  // 그 밖의 문자는 그대로
        ("", #""""#),
    ])
    func goEscaping(value: String, expected: String) {
        #expect(JSONString.quoted(value) == expected)
    }

    @Test("JSON으로 읽으면 원래 문자열이다")
    func roundTripThroughJSONSerialization() throws {
        var random = SplitMix64(seed: 0x6a73_6f6e)
        for _ in 0..<500 {
            var value = ""
            for _ in 0..<Int.random(in: 0...20, using: &random) {
                let scalar = [UInt32.random(in: 0...0x7F, using: &random), 0x2028, 0xE9, 0x1F600][Int.random(in: 0...3, using: &random)]
                value.unicodeScalars.append(try #require(Unicode.Scalar(scalar)))
            }
            let json = Data("[\(JSONString.quoted(value))]".utf8)
            let decoded = try #require(try JSONSerialization.jsonObject(with: json) as? [String])
            #expect(decoded == [value])
        }
    }
}
