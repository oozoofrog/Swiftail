// Checks that JWS protected header strings match Go `json.Marshal` byte for byte using the Go `encoding/json` `appendString` rules.

import Foundation
import Testing

@testable import SwiftailCertificates

@Suite("JSON strings")
struct JSONStringTests {
    @Test("Escapes like Go json.Marshal", arguments: [
        ("https://example.com/acme/acct/1", #""https://example.com/acme/acct/1""#),  // Leaves `/` unchanged
        ("a\"b\\c", #""a\"b\\c""#),
        ("\u{08}\u{0C}\n\r\t", #""\b\f\n\r\t""#),
        ("\u{00}\u{01}\u{1F}", #""\u0000\u0001\u001f""#),
        ("<a>&", #""\u003ca\u003e\u0026""#),
        ("\u{2028}\u{2029}", #""\u2028\u2029""#),
        ("é😀\u{7F}", "\"é😀\u{7F}\""),  // Leaves other characters unchanged
        ("", #""""#),
    ])
    func goEscaping(value: String, expected: String) {
        #expect(JSONString.quoted(value) == expected)
    }

    @Test("Parsing the JSON returns the original string")
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
