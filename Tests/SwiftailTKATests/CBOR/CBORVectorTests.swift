import Foundation
import Testing

@testable import SwiftailTKA

/// `Fixtures/cbor-vectors.json`(노트 8.1의 디코더 표). 필드의 뜻과 출처는 `Fixtures/README.md`.
struct CBORVectorFile: Decodable {
    struct Vector: Decodable {
        let name: String
        let section: String
        let hex: String
        /// `CBOR.decode`의 판정: `accept`이거나 `CBORError`의 경우 이름.
        let cbor: String
        /// 노트가 적은 Go `AUM` 디코딩의 판정: `accept`·`reject`. 구조 수준(TL-2)의 기대값이다.
        let aum: String
        /// 받아들인 값을 정준으로 다시 쓴 바이트. 쓰는 길이 없는 값(음수, 단순값·실수)이 있으면 없다.
        let canonical: String?

        func input() throws -> [UInt8] {
            try #require(CBORTesting.bytes(hex: hex), "\(name)")
        }
    }

    let vectors: [Vector]

    static func load() throws -> CBORVectorFile {
        let url = try #require(Bundle.module.url(forResource: "cbor-vectors", withExtension: "json", subdirectory: "Fixtures"))
        return try JSONDecoder().decode(CBORVectorFile.self, from: Data(contentsOf: url))
    }
}

@Suite("CBOR 벡터")
struct CBORVectorTests {
    @Test("노트 8.1의 표: 항목 수준의 판정과 정준 다시 쓰기")
    func noteVectors() throws {
        let file = try CBORVectorFile.load()
        #expect(file.vectors.count == 63)
        for vector in file.vectors {
            let input = try vector.input()
            let result = Result { () throws(CBORError) in try CBOR.decode(input) }
            switch result {
            case .success(let value):
                #expect(vector.cbor == "accept", "\(vector.name): 받아들였다")
                if let canonical = vector.canonical {
                    #expect(CBORTesting.canonical(value).map(CBORTesting.hex) == canonical, "\(vector.name)")
                } else {
                    #expect(CBORTesting.canonical(value) == nil, "\(vector.name): 쓰는 길이 없는 값이 있어야 한다")
                }
            case .failure(let error):
                #expect(vector.cbor == "\(error)", "\(vector.name): \(error)")
            }
            // 항목 수준에서 거절하는 입력은 Go도 거절한다.
            if vector.cbor != "accept" {
                #expect(vector.aum == "reject", "\(vector.name)")
            }
        }
    }

    @Test("genesis 체크포인트는 정준이라 다시 쓰면 원본과 같다")
    func genesis() throws {
        let vector = try #require(CBORVectorFile.load().vectors.first { $0.name == "genesis 체크포인트" })
        let input = try vector.input()
        #expect(input.count == 558)
        #expect(CBORTesting.canonical(try CBOR.decode(input)) == input)
    }

    /// RFC 8949 부록 A의 예. 기대값은 부록의 진단 표기를 옮긴 것이다.
    @Test(
        "RFC 8949 부록 A: 받아들이는 예",
        arguments: [
            ("00", CBORValue.unsigned(0)), ("01", .unsigned(1)), ("0a", .unsigned(10)), ("17", .unsigned(23)),
            ("1818", .unsigned(24)), ("1819", .unsigned(25)), ("1864", .unsigned(100)), ("1903e8", .unsigned(1_000)),
            ("1a000f4240", .unsigned(1_000_000)), ("1b000000e8d4a51000", .unsigned(1_000_000_000_000)),
            ("1bffffffffffffffff", .unsigned(UInt64.max)),
            ("3bffffffffffffffff", .negative(UInt64.max)), ("20", .negative(0)), ("29", .negative(9)),
            ("3863", .negative(99)), ("3903e7", .negative(999)),
            ("f4", .simpleOrFloat), ("f5", .simpleOrFloat), ("f6", .null), ("f7", .null), ("f0", .simple(16)),
            ("f8ff", .simple(255)),
            ("40", .bytes([])), ("4401020304", .bytes([1, 2, 3, 4])),
            ("60", .text([])), ("6161", .text(Array("a".utf8))), ("6449455446", .text(Array("IETF".utf8))),
            ("62225c", .text(Array("\"\\".utf8))), ("62c3bc", .text(Array("\u{00fc}".utf8))),
            ("63e6b0b4", .text(Array("\u{6c34}".utf8))), ("64f0908591", .text(Array("\u{10151}".utf8))),
            ("80", .array([])), ("83010203", .array([.unsigned(1), .unsigned(2), .unsigned(3)])),
            (
                "8301820203820405",
                .array([.unsigned(1), .array([.unsigned(2), .unsigned(3)]), .array([.unsigned(4), .unsigned(5)])])
            ),
            ("98190102030405060708090a0b0c0d0e0f101112131415161718181819", .array((1...25).map { .unsigned($0) })),
            ("a0", .map([])),
            (
                "a201020304",
                .map([CBORPair(key: .unsigned(1), value: .unsigned(2)), CBORPair(key: .unsigned(3), value: .unsigned(4))])
            ),
            (
                "a26161016162820203",
                .map([
                    CBORPair(key: .text([0x61]), value: .unsigned(1)),
                    CBORPair(key: .text([0x62]), value: .array([.unsigned(2), .unsigned(3)])),
                ])
            ),
            ("826161a161626163", .array([.text([0x61]), .map([CBORPair(key: .text([0x62]), value: .text([0x63]))])])),
            (
                "a56161614161626142616361436164614461656145",
                .map(["a", "b", "c", "d", "e"].map { CBORPair(key: .text(Array($0.utf8)), value: .text(Array($0.uppercased().utf8))) })
            ),
        ] as [(String, CBORValue)]
    )
    func rfcAccepted(hex: String, expected: CBORValue) throws {
        let input = try #require(CBORTesting.bytes(hex: hex))
        let value = try CBOR.decode(input)
        #expect(value == expected)
        // 부록의 예는 정준이므로 쓸 수 있는 값은 같은 바이트로 다시 쓴다. undefined만 null(f6)로 쓴다.
        if let canonical = CBORTesting.canonical(value) {
            #expect(canonical == (input == [0xf7] ? [0xf6] : input))
        }
    }

    /// 실수는 값을 쥐지 않지만 받아들인다(모르는 필드의 값, 노트 6.2).
    @Test(
        "RFC 8949 부록 A: 실수",
        arguments: [
            "f90000", "f98000", "f93c00", "fb3ff199999999999a", "f93e00", "f97bff", "fa47c35000", "fa7f7fffff",
            "fb7e37e43c8800759c", "f90001", "f90400", "f9c400", "fbc010666666666666", "f97c00", "f97e00", "f9fc00",
            "fa7f800000", "fa7fc00000", "faff800000", "fb7ff0000000000000", "fb7ff8000000000000", "fbfff0000000000000",
        ]
    )
    func rfcFloats(hex: String) throws {
        #expect(try CBOR.decode(#require(CBORTesting.bytes(hex: hex))) == .simpleOrFloat)
    }

    @Test(
        "RFC 8949 부록 A: 태그와 길이 미정은 거절한다",
        arguments: [
            ("c249010000000000000000", CBORError.tag), ("c349010000000000000000", .tag),
            ("c074323031332d30332d32315432303a30343a30305a", .tag), ("c11a514b67b0", .tag), ("c1fb41d452d9ec200000", .tag),
            ("d74401020304", .tag), ("d818456449455446", .tag), ("d82076687474703a2f2f7777772e6578616d706c652e636f6d", .tag),
            ("5f42010243030405ff", .indefiniteLength), ("7f657374726561646d696e67ff", .indefiniteLength),
            ("9fff", .indefiniteLength), ("9f018202039f0405ffff", .indefiniteLength),
            ("9f01820203820405ff", .indefiniteLength), ("83018202039f0405ff", .indefiniteLength),
            ("83019f0203ff820405", .indefiniteLength),
            ("9f0102030405060708090a0b0c0d0e0f101112131415161718181819ff", .indefiniteLength),
            ("bf61610161629f0203ffff", .indefiniteLength), ("826161bf61626163ff", .indefiniteLength),
            ("bf6346756ef563416d7421ff", .indefiniteLength),
        ] as [(String, CBORError)]
    )
    func rfcRejected(hex: String, expected: CBORError) throws {
        let input = try #require(CBORTesting.bytes(hex: hex))
        #expect(throws: expected) { try CBOR.decode(input) }
    }
}
