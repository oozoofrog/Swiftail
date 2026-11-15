import Testing

@testable import SwiftailTKA

/// AUM 읽기의 받아들임·거절(계약 동작 D3~D9, 7절 시험 2, 노트 3.1·8.1).
@Suite("AUM 읽기")
struct AUMDecodingTests {
    @Test("cbor-vectors.json의 aum 판정(노트 8.1의 Go 판정)과 같다. 다른 것은 동작 D8의 둘뿐이다")
    func noteVerdicts() throws {
        let file = try CBORVectorFile.load()
        var deviations: [String] = []
        for vector in file.vectors {
            let input = try vector.input()
            let result = Result { () throws(TKAError) in try AUM(decoding: input) }
            let verdict = (try? result.get()) == nil ? "reject" : "accept"
            if verdict != vector.aum { deviations.append(vector.name) }
            // 항목 수준의 거절은 `.cbor`로 감싼다.
            if vector.cbor != "accept" {
                guard case .failure(.cbor(let error)) = result else {
                    Issue.record("\(vector.name): \(result)")
                    continue
                }
                #expect("\(error)" == vector.cbor, "\(vector.name)")
            }
        }
        // Go는 체크포인트 상태의 2·33바이트 `LastAUMHash`를 읽은 뒤 정적 검사에서 거절한다. Swiftail은 디코딩에서 거절한다.
        #expect(deviations == ["체크포인트 상태의 2바이트 LastAUMHash", "체크포인트 상태의 33바이트 LastAUMHash"])
    }

    @Test("받아들인 값: null은 0 값, 텍스트 키는 모르는 필드, 모르는 필드는 버린다")
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

    @Test("구조 맵의 키: 받지 않는 종류와 범위 밖은 거절한다")
    func structureKeys() {
        for hex in [
            "a3010302f6410101",  // bstr 키
            "a3010302f6f93c0001",  // 실수 키
            "a3010302f6f501", "a3010302f6f601", "a3010302f6f701",  // true·null·undefined 키
            "a3010302f6e001", "a3010302f6f86301",  // 단순값 키
            "a3010302f68001", "a3010302f6a001",  // 배열·맵 키
            "a3010302f661ff01",  // 잘못된 UTF-8 텍스트 키
            "a3010302f61b800000000000000001",  // 2^63
            "a3010302f61bffffffffffffffff01",  // 2^64−1
            "a3010302f63b800000000000000001",  // −2^63−1
        ] {
            #expect(throws: TKAError.invalidStructure, "\(hex)") { try ModelTesting.decodeAUM(hex).get() }
        }
        // 음의 정수 키는 −2^63까지 모르는 필드다.
        #expect(throws: Never.self) { try ModelTesting.decodeAUM("a3010302f63b7fffffffffffffff01").get() }
    }

    @Test("구조 맵과 Meta의 중복 키는 거절한다. 비최단으로 쓴 같은 키도 중복이다")
    func duplicateKeys() {
        for hex in [
            "a30103010302f6", "a3010318010302f6",  // 알려진 키(같은 인코딩, 비최단)
            "a4010302f608010802", "a4010302f60800180800",  // 모르는 정수 키
            "a4010302f6616101616102", "a4010302f661610178016101",  // 모르는 텍스트 키
            "a4010302f620012002",  // 모르는 음수 키
            "a4010402f604410107a26161617861616179",  // Meta
            "a4010402f604410107a2f661786061 79",  // Meta의 null 키는 빈 문자열이라 ""와 겹친다
        ] {
            let input = hex.replacingOccurrences(of: " ", with: "")
            #expect(throws: TKAError.invalidStructure, "\(hex)") { try ModelTesting.decodeAUM(input).get() }
        }
        // 모르는 필드의 값 안쪽 맵은 중복을 보지 않는다.
        #expect(throws: Never.self) { try ModelTesting.decodeAUM("a3010302f608a201010102").get() }
    }

    @Test("알려진 필드의 타입과 범위가 맞지 않으면 거절한다")
    func knownFieldTypes() {
        for hex in [
            "a20119010002f6", "a2012002f6", "a201f93c0002f6", "a201f502f6", "a201616102f6", "a201410102f6",  // MessageKind
            "a20103026161", "a201030201", "a2010302a0",  // PrevAUMHash
            "a20103028201190100", "a2010302816161", "a2010302818101",  // 배열 원소가 바이트가 아님
            "a3010102f60301", "a3010102f6034101", "a3010102f60380",  // Key가 맵이 아님
            "a3010402f60661 61", "a3010402f60620",  // Votes
            "a3010402f60780", "a3010402f6074101",  // Meta가 맵이 아님
            "a4010402f604410107a141616178", "a4010402f604410107a1016178",  // Meta 키
            "a4010402f604410107a161614178", "a4010402f604410107a1616101", "a4010402f604410107a1616161ff",  // Meta 값
            "a3010302f6178101", "a3010302f61701", "a3010302f617818101",  // Signatures
            "a3010502f6058101",  // State가 맵이 아님
            "a3010502f605a1016161", "a3010502f605a10101",  // State.LastAUMHash의 타입
            "a3010502f605a1024101", "a3010502f605a10281816161",  // DisablementValues
            "a3010502f605a1038101",  // Keys의 원소
        ] {
            let input = hex.replacingOccurrences(of: " ", with: "")
            #expect(throws: TKAError.invalidStructure, "\(hex)") { try ModelTesting.decodeAUM(input).get() }
        }
    }

    @Test("체크포인트 상태의 LastAUMHash는 null만 받는다(동작 D8)")
    func checkpointLastAUMHash() throws {
        let hash32 = "5820" + String(repeating: "11", count: 32)
        #expect(throws: TKAError.invalidStructure) { try ModelTesting.decodeAUM("a3010502f605a101" + hash32).get() }
        #expect(throws: TKAError.invalidStructure) { try ModelTesting.decodeAUM("a3010502f605a101820102").get() }
        let state = try #require(try ModelTesting.decodeAUM("a3010502f605a101f6").get().state)
        #expect(state.lastAUMHash == nil)
    }

    /// Go 원본(`fxamacker/cbor` v2.9.3 `decode.go`)을 읽어 정한 판정. 실행으로는 확인하지 않았다(보고의 "Go 판정 미확인").
    @Test("Go가 0 값이나 정수·바이트로 읽는 것: 단순값, 정수 배열, 원소의 null")
    func goFillRules() throws {
        // 단순값은 정수 필드에 그 수로 들어간다(`parseToValue` → `fillPositiveInt`).
        #expect(try ModelTesting.decodeAUM("a201e302f6").get().serialized() == ModelTesting.bytes("a2010302f6"))
        #expect(try ModelTesting.decodeAUM("a201f86302f6").get().messageKind == 99)
        #expect(try ModelTesting.decodeAUM("a3010402f606f820").get().votes == 32)
        // 0~255의 정수·단순값·null 배열은 바이트열로 읽힌다(`parseArrayToSlice`).
        let array = try ModelTesting.decodeAUM("a20103028401e5f618ff").get()
        #expect(array.prevAUMHash == [1, 5, 0, 255])
        #expect(ModelTesting.hex(array.serialized()) == "a2010302440105 00ff".replacingOccurrences(of: " ", with: ""))
        #expect(try ModelTesting.decodeAUM("a201030280").get().prevAUMHash == [])
        // 포인터 필드의 null은 없음이다.
        let nulls = try ModelTesting.decodeAUM("a8010302f603f604f605f606f607f617f6").get()
        #expect(nulls == AUM(messageKind: 3, prevAUMHash: nil))
        // 배열 원소의 null은 0 값의 구조다. 정적 검사에서 떨어진다.
        let nullSignature = try ModelTesting.decodeAUM("a3010302f61781f6").get()
        #expect(nullSignature.signatures == [AUMSignature(keyID: [], signature: [])])
        #expect(throws: TKAError.invalidAUM) { try nullSignature.validate() }
        let nullKey = try #require(try ModelTesting.decodeAUM("a3010502f605a10381f6").get().state)
        #expect(nullKey.keys == [TrustedKey(kind: 0, votes: 0, publicKey: nil)])
        // Meta의 null 값은 빈 문자열이다.
        let meta = try ModelTesting.decodeAUM("a4010402f604410107a16161f6").get()
        #expect(meta.meta == [MetaEntry(key: Array("a".utf8), value: [])])
    }

    @Test("AddKey의 KeyID: null은 없음이고 빈 바이트열은 있음이다(Go `a.KeyID != nil`)")
    func keyIDPresence() throws {
        let key = "03a301010201035820" + String(repeating: "22", count: 32)
        let absent = try ModelTesting.decodeAUM("a3010102f6" + key).get()
        let null = try ModelTesting.decodeAUM("a4010102f6" + key + "04f6").get()
        let empty = try ModelTesting.decodeAUM("a4010102f6" + key + "0440").get()
        #expect(absent.keyID == nil && null.keyID == nil && empty.keyID == [])
        try absent.validate()
        try null.validate()
        #expect(throws: TKAError.invalidAUM) { try empty.validate() }
        // 인코딩은 셋 다 같다(omitempty).
        #expect(absent.serialized() == empty.serialized())
    }

    @Test("512KiB까지 읽고 그보다 길면 디코딩 전에 거절한다")
    func byteLimit() throws {
        // {1: 3, 2: null, 8: h'…'}: 머리 11바이트(`a3 01 03 02 f6 08 5a xxxxxxxx`)와 내용.
        func noOp(totalCount: Int) -> [UInt8] {
            let count = totalCount - 11
            let length = (0..<4).reversed().map { UInt8(truncatingIfNeeded: count >> ($0 * 8)) }
            return [0xa3, 0x01, 0x03, 0x02, 0xf6, 0x08, 0x5a] + length + [UInt8](repeating: 0x5a, count: count)
        }
        let limit = 512 * 1_024
        #expect(try AUM(decoding: noOp(totalCount: limit)) == AUM(messageKind: 3, prevAUMHash: nil))
        #expect(throws: TKAError.limitExceeded) { try AUM(decoding: noOp(totalCount: limit + 1)) }
    }

    @Test("모든 접두와 임의 바이트로 죽지 않는다. 읽은 값은 다시 쓰고 읽어도 같다")
    func robustness() throws {
        let genesis = try #require(CBORVectorFile.load().vectors.first { $0.name == "genesis 체크포인트" }).input()
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
