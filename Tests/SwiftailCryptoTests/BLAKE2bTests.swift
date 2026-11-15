// BLAKE2b(RFC 7693) 시험.
//
// 출처:
// - RFC 7693 부록 A: BLAKE2b-512("abc")
// - RFC 7693 부록 E: 자체 시험 모듈의 "hash of hashes"(출력 20·32·48·64, 입력 0·3·128·129·255·1024, 키 있음·없음)
// - BLAKE2 공식 KAT(`Vectors/blake2b-kat.json`, 출처는 `Vectors/README.md`): 키 없음 256개, 키 64바이트 256개
// - "교차 계산" 표시가 붙은 값은 Python hashlib.blake2b의 결과다. 입력은 `pattern(_:_:_:)`으로 정해진 바이트열이다.

import Foundation
import Testing

import SwiftailCrypto

private func hexString(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

/// 교차 계산 입력: i번째 바이트 = (i·mul + add) mod 256.
private func pattern(_ count: Int, _ mul: Int, _ add: Int) -> [UInt8] {
    (0..<count).map { UInt8(truncatingIfNeeded: $0 * mul + add) }
}

/// RFC 7693 부록 E의 `selftest_seq`(피보나치 수열의 위 8비트).
private func selfTestSequence(_ count: Int, seed: UInt32) -> [UInt8] {
    var a = 0xDEAD_4BAD &* seed
    var b: UInt32 = 1
    return (0..<count).map { _ in
        let t = a &+ b
        a = b
        b = t
        return UInt8(truncatingIfNeeded: t >> 24)
    }
}

@Suite("BLAKE2b")
struct BLAKE2bTests {
    @Test("RFC 7693 부록 A: BLAKE2b-512(\"abc\")")
    func abc() {
        let expected = "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
            + "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        #expect(hexString(BLAKE2b.hash(Array("abc".utf8))) == expected)
    }

    @Test("RFC 7693 부록 E: 자체 시험의 hash of hashes")
    func selfTest() {
        var grand = BLAKE2b(outputByteCount: 32)
        for outputLength in [20, 32, 48, 64] {
            for inputLength in [0, 3, 128, 129, 255, 1024] {
                let input = selfTestSequence(inputLength, seed: UInt32(inputLength))
                grand.update(BLAKE2b.hash(input, outputByteCount: outputLength))
                let key = selfTestSequence(outputLength, seed: UInt32(outputLength))
                grand.update(BLAKE2b.hash(input, outputByteCount: outputLength, key: key))
            }
        }
        #expect(hexString(grand.finalize()) == "c23a7800d98123bd10f506c61e29da5603d763b8bbad2e737f5e765a7bccd475")
    }

    @Test("BLAKE2 공식 KAT: 키 없음·키 64바이트, 입력 = 00 01 02 … (0~255바이트), 조각낸 update도 같다")
    func officialKAT() throws {
        let vectors = try loadVectors("blake2b-kat")
        #expect(vectors.count == 512)
        #expect(vectors.filter { $0.key.isEmpty }.count == 256)
        for v in vectors {
            let key = bytes(v.key), input = bytes(v.input), expected = bytes(v.output)
            #expect(BLAKE2b.hash(input, key: key) == expected, "입력 길이 \(input.count), 키 길이 \(key.count)")
            var hasher = BLAKE2b(key: key)
            let cut = input.count / 3
            hasher.update(input.prefix(cut))
            hasher.update(input.dropFirst(cut))
            #expect(hasher.finalize() == expected, "조각낸 입력, 길이 \(input.count)")
        }
    }

    @Test("출력 길이 1·32·64: 잘라 낸 값이 아니라 매개변수 블록에 길이가 들어간 값(교차 계산)")
    func outputLengths() {
        let abc = Array("abc".utf8)
        #expect(hexString(BLAKE2b.hash(abc, outputByteCount: 1)) == "6b")
        #expect(hexString(BLAKE2b.hash(abc, outputByteCount: 32)) == "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319")
        #expect(BLAKE2b.hash(abc, outputByteCount: 64) == BLAKE2b.hash(abc))
        #expect(BLAKE2b.hash(abc, outputByteCount: 64).count == 64)
    }

    @Test("블록 경계 0·1·127·128·129·255·256바이트: 키 없음 64바이트, 키 16바이트 32바이트 출력(교차 계산)")
    func blockBoundaries() {
        let rows: [(Int, String, String)] = [
            (0, "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
             "91a06356331db764f15a5dee8980d7987670db5716c83c7e7541ded4605893de"),
            (1, "4fe4da61bcc756071b226843361d74944c72245d23e8245ea678c13fdcd7fe2ae529cf999ad99cc24f7a73416a18ba53e76c0afef83b16a568b12fbfc1a2674d",
             "b073d54b01faa1448ca303a5f54f316db8ea7f01d692eea46dc76fecd392cc0f"),
            (127, "71546bbf9110ad184cc60f2eb120fcfd9b4dbbca7a7f1270045b8a23a6a4f4330f65c1f030dd2f5fabc6c57617242c37cf427bd90407fac5b9deffd3ae888c39",
             "f1de4f61562e22dc3e92ecc7a5d10fc80424ce550582058c923e1736b3e475f1"),
            (128, "2d9e329f42afa3601d646692b81c13e87fcaff5bf15972e9813d7373cb6d181f9599f4d513d4af4fd6ebd37497aceb29aba5ee23ed764d8510b552bd088814fb",
             "6e73f45dd68b2f026b1bfb1e8b28a0cfb9262eeff6ac3045c4da490effb05f31"),
            (129, "47889df9eb4d717afc5019df5c6a83df00a0b8677395e078cd5778ace0f338a618e68b7d9afb065d9e6a01ccd31d109447e7fae771c3ee3e105709194122ba2b",
             "736ae27f04801520d8607b8617ec44fdba3a63ebff3229f47e59149345cb6448"),
            (255, "1a5199ac66a00e8a87ad1c7fbad30b33137dd8312bf6d98602dacf8f40ea2cb623a7fbc63e5a6bfa434d337ae7da5ca1a52502a215a3fe0297a151be85d88789",
             "5997b13faa0cac0b77269144eac252ec3fa9b76001e75163ea76b809d1693c7e"),
            (256, "91019c558584980249ca43eceed27e19f1c3c24161b93eed1eee2a6a774f60bf8a81b43750870bee1698feac9c5336ae4d5c842e7ead159bf3916387e8ded9ae",
             "08d5396d4e824e2e05188e745c72cc64f087eb6f39c20d3883e8d8e766a0623a"),
        ]
        let key = pattern(16, 9, 4)
        for (length, plain, keyed) in rows {
            let data = pattern(length, 7, 3)
            #expect(hexString(BLAKE2b.hash(data)) == plain, "키 없음, 길이 \(length)")
            #expect(hexString(BLAKE2b.hash(data, outputByteCount: 32, key: key)) == keyed, "키 있음, 길이 \(length)")
        }
    }

    @Test("한 바이트씩·블록 크기에 맞춰·어긋나게 나눈 update가 한 번에 넣은 것과 같고, finalize는 상태를 바꾸지 않는다")
    func incremental() {
        let data = pattern(1000, 5, 1)
        let whole = BLAKE2b.hash(data)
        for chunk in [1, 3, 127, 128, 129, 500] {
            var hasher = BLAKE2b()
            var start = 0
            while start < data.count {
                let end = min(start + chunk, data.count)
                hasher.update(data[start..<end])
                start = end
            }
            #expect(hasher.finalize() == whole, "조각 \(chunk)바이트")
            #expect(hasher.finalize() == whole)
        }
        var hasher = BLAKE2b()
        hasher.update(data[0..<128])
        #expect(hasher.finalize() == BLAKE2b.hash(data[0..<128]))
        hasher.update(data[128...])
        #expect(hasher.finalize() == whole)
    }
}
