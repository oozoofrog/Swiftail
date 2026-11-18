import Testing

@testable import SwiftailTKA

/// Accepted and rejected AUM decodings (contract behaviors D3–D9, §7 test 2, note §§3.1 and 8.1).
@Suite("AUM decoding")
struct AUMDecodingTests {
    @Test("Matches cbor-vectors.json aum outcomes (Go outcomes in note §8.1), with only two differences under behavior D8")
    func noteVerdicts() throws {
        let file = try CBORVectorFile.load()
        var deviations: [String] = []
        for vector in file.vectors {
            let input = try vector.input()
            let result = Result { () throws(TKAError) in try AUM(decoding: input) }
            let verdict = (try? result.get()) == nil ? "reject" : "accept"
            if verdict != vector.aum { deviations.append(vector.name) }
            // Wrap item-level rejections in `.cbor`.
            if vector.cbor != "accept" {
                guard case .failure(.cbor(let error)) = result else {
                    Issue.record("\(vector.name): \(result)")
                    continue
                }
                #expect("\(error)" == vector.cbor, "\(vector.name)")
            }
        }
        // Go decodes a 2- or 33-byte `LastAUMHash` in checkpoint state and rejects it during static validation. Swiftail rejects it during decoding.
        #expect(deviations == ["2-byte LastAUMHash in checkpoint state", "33-byte LastAUMHash in checkpoint state"])
    }

    @Test("Accepted values: null becomes the zero value, text keys are unknown fields, and unknown fields are discarded")
    func acceptedValues() throws {
        let noOp = ModelTesting.bytes("a2010302f6")
        for hex in [
            "a3010302f60801", "a3010302f62001", "a3010302f6613104", "a3010302f66b4d6573736167654b696e6404",
            "a201180302f6", "a218010302f6", "a202f60103", "a3010302f608a201010102", "a3010302f61b7fffffffffffffff01",
        ] {
            let aum = try ModelTesting.decodeAUM(hex).get()
            #expect(aum == AUM(messageKind: 3, prevAUMHash: nil), "\(hex)")
            #expect(aum.serialized() == noOp, "\(hex)")
        }
        #expect(try ModelTesting.decodeAUM("a201f602f6").get().messageKind == 0)
        #expect(try ModelTesting.decodeAUM("a10103").get() == AUM(messageKind: 3, prevAUMHash: nil))
        #expect(try ModelTesting.decodeAUM("a2010902f6").get().messageKind == 9)
        #expect(try ModelTesting.decodeAUM("a20118ff02f6").get().messageKind == 255)

        let emptyMeta = try ModelTesting.decodeAUM("a4010402f604410107a0").get()
        #expect(emptyMeta.meta == [])
        #expect(ModelTesting.hex(emptyMeta.serialized()) == "a3010402f6044101")
    }

    @Test("Structure map keys reject unsupported types and out-of-range values")
    func structureKeys() {
        for hex in [
            "a3010302f6410101",  // bstr key
            "a3010302f6f93c0001",  // Float key
            "a3010302f6f501", "a3010302f6f601", "a3010302f6f701",  // true, null, or undefined key
            "a3010302f6e001", "a3010302f6f86301",  // Simple value key
            "a3010302f68001", "a3010302f6a001",  // Array or map key
            "a3010302f661ff01",  // Invalid UTF-8 text key
            "a3010302f61b800000000000000001",  // 2^63
            "a3010302f61bffffffffffffffff01",  // 2^64−1
            "a3010302f63b800000000000000001",  // −2^63−1
        ] {
            #expect(throws: TKAError.invalidStructure, "\(hex)") { try ModelTesting.decodeAUM(hex).get() }
        }
        // Negative integer keys down to −2^63 are unknown fields.
        #expect(throws: Never.self) { try ModelTesting.decodeAUM("a3010302f63b7fffffffffffffff01").get() }
    }

    @Test("Rejects duplicate keys in structure maps and Meta, including different encodings of the same key")
    func duplicateKeys() {
        for hex in [
            "a30103010302f6", "a3010318010302f6",  // Known key (identical encoding or non-shortest encoding)
            "a4010302f608010802", "a4010302f60800180800",  // Unknown integer key
            "a4010302f6616101616102", "a4010302f661610178016101",  // Unknown text key
            "a4010302f620012002",  // Unknown negative integer key
            "a4010402f604410107a26161617861616179",  // Meta
            "a4010402f604410107a2f661786061 79",  // A null key in Meta becomes the empty string and duplicates ""
        ] {
            let input = hex.replacingOccurrences(of: " ", with: "")
            #expect(throws: TKAError.invalidStructure, "\(hex)") { try ModelTesting.decodeAUM(input).get() }
        }
        // Maps inside unknown field values are exempt from duplicate checks.
        #expect(throws: Never.self) { try ModelTesting.decodeAUM("a3010302f608a201010102").get() }
    }

    @Test("Rejects known fields with incorrect types or out-of-range values")
    func knownFieldTypes() {
        for hex in [
            "a20119010002f6", "a2012002f6", "a201f93c0002f6", "a201f502f6", "a201616102f6", "a201410102f6",  // MessageKind
            "a20103026161", "a201030201", "a2010302a0",  // PrevAUMHash
            "a20103028201190100", "a2010302816161", "a2010302818101",  // Array element is not a byte
            "a3010102f60301", "a3010102f6034101", "a3010102f60380",  // Key is not a map
            "a3010402f60661 61", "a3010402f60620",  // Votes
            "a3010402f60780", "a3010402f6074101",  // Meta is not a map
            "a4010402f604410107a141616178", "a4010402f604410107a1016178",  // Meta key
            "a4010402f604410107a161614178", "a4010402f604410107a1616101", "a4010402f604410107a1616161ff",  // Meta value
            "a3010302f6178101", "a3010302f61701", "a3010302f617818101",  // Signatures
            "a3010502f6058101",  // State is not a map
            "a3010502f605a1016161", "a3010502f605a10101",  // State.LastAUMHash type
            "a3010502f605a1024101", "a3010502f605a10281816161",  // DisablementValues
            "a3010502f605a1038101",  // Keys element
        ] {
            let input = hex.replacingOccurrences(of: " ", with: "")
            #expect(throws: TKAError.invalidStructure, "\(hex)") { try ModelTesting.decodeAUM(input).get() }
        }
    }

    @Test("Checkpoint state LastAUMHash accepts only null (behavior D8)")
    func checkpointLastAUMHash() throws {
        let hash32 = "5820" + String(repeating: "11", count: 32)
        #expect(throws: TKAError.invalidStructure) { try ModelTesting.decodeAUM("a3010502f605a101" + hash32).get() }
        #expect(throws: TKAError.invalidStructure) { try ModelTesting.decodeAUM("a3010502f605a101820102").get() }
        let state = try #require(try ModelTesting.decodeAUM("a3010502f605a101f6").get().state)
        #expect(state.lastAUMHash == nil)
    }

    /// Outcomes based on reading the Go origin (`fxamacker/cbor` v2.9.3 `decode.go`). Unverified by execution (Unverified Go outcomes in the report).
    @Test("Go decodes simple values, integer arrays, and null elements as zero values, integers, or bytes")
    func goFillRules() throws {
        // A simple value goes into an integer field as that number (`parseToValue` → `fillPositiveInt`).
        #expect(try ModelTesting.decodeAUM("a201e302f6").get().serialized() == ModelTesting.bytes("a2010302f6"))
        #expect(try ModelTesting.decodeAUM("a201f86302f6").get().messageKind == 99)
        #expect(try ModelTesting.decodeAUM("a3010402f606f820").get().votes == 32)
        // An array of integers or simple values in 0–255, or nulls, decodes as a byte sequence (`parseArrayToSlice`).
        let array = try ModelTesting.decodeAUM("a20103028401e5f618ff").get()
        #expect(array.prevAUMHash == [1, 5, 0, 255])
        #expect(ModelTesting.hex(array.serialized()) == "a2010302440105 00ff".replacingOccurrences(of: " ", with: ""))
        #expect(try ModelTesting.decodeAUM("a201030280").get().prevAUMHash == [])
        // A null pointer field is absent.
        let nulls = try ModelTesting.decodeAUM("a8010302f603f604f605f606f607f617f6").get()
        #expect(nulls == AUM(messageKind: 3, prevAUMHash: nil))
        // A null array element is a zero-valued struct and fails static validation.
        let nullSignature = try ModelTesting.decodeAUM("a3010302f61781f6").get()
        #expect(nullSignature.signatures == [AUMSignature(keyID: [], signature: [])])
        #expect(throws: TKAError.invalidAUM) { try nullSignature.validate() }
        let nullKey = try #require(try ModelTesting.decodeAUM("a3010502f605a10381f6").get().state)
        #expect(nullKey.keys == [TrustedKey(kind: 0, votes: 0, publicKey: nil)])
        // A null Meta value is an empty string.
        let meta = try ModelTesting.decodeAUM("a4010402f604410107a16161f6").get()
        #expect(meta.meta == [MetaEntry(key: Array("a".utf8), value: [])])
    }

    @Test("AddKey KeyID: null is absent and an empty byte sequence is present (Go `a.KeyID != nil`)")
    func keyIDPresence() throws {
        let key = "03a301010201035820" + String(repeating: "22", count: 32)
        let absent = try ModelTesting.decodeAUM("a3010102f6" + key).get()
        let null = try ModelTesting.decodeAUM("a4010102f6" + key + "04f6").get()
        let empty = try ModelTesting.decodeAUM("a4010102f6" + key + "0440").get()
        #expect(absent.keyID == nil && null.keyID == nil && empty.keyID == [])
        try absent.validate()
        try null.validate()
        #expect(throws: TKAError.invalidAUM) { try empty.validate() }
        // All three encode identically (omitempty).
        #expect(absent.serialized() == empty.serialized())
    }

    @Test("Decodes up to 512KiB and rejects larger input before decoding")
    func byteLimit() throws {
        // {1: 3, 2: null, 8: h'…'}: 11-byte header (`a3 01 03 02 f6 08 5a xxxxxxxx`) plus contents.
        func noOp(totalCount: Int) -> [UInt8] {
            let count = totalCount - 11
            let length = (0..<4).reversed().map { UInt8(truncatingIfNeeded: count >> ($0 * 8)) }
            return [0xa3, 0x01, 0x03, 0x02, 0xf6, 0x08, 0x5a] + length + [UInt8](repeating: 0x5a, count: count)
        }
        let limit = 512 * 1_024
        #expect(try AUM(decoding: noOp(totalCount: limit)) == AUM(messageKind: 3, prevAUMHash: nil))
        #expect(throws: TKAError.limitExceeded) { try AUM(decoding: noOp(totalCount: limit + 1)) }
    }

    @Test("All prefixes and arbitrary bytes avoid a crash. Decoded values survive rewriting and decoding")
    func robustness() throws {
        let genesis = try #require(CBORVectorFile.load().vectors.first { $0.name == "Genesis checkpoint" }).input()
        for count in 0..<genesis.count {
            #expect(throws: TKAError.self) { try AUM(decoding: Array(genesis.prefix(count))) }
        }
        var random = CBORTesting.Random(state: 0xa0b1)
        for round in 0..<3_000 {
            var input: [UInt8]
            if round.isMultiple(of: 2) {
                input = genesis
                for _ in 0..<Int.random(in: 1...4, using: &random) {
                    input[Int.random(in: 0..<input.count, using: &random)] = UInt8.random(in: 0...255, using: &random)
                }
            } else {
                input = (0..<Int.random(in: 0...64, using: &random)).map { _ in UInt8.random(in: 0...255, using: &random) }
            }
            guard let aum = try? AUM(decoding: input) else { continue }
            let canonical = aum.serialized()
            #expect(try AUM(decoding: canonical) == aum, "\(ModelTesting.hex(input))")
            #expect(try AUM(decoding: canonical).serialized() == canonical)
            _ = try? aum.validate()
        }
    }
}
