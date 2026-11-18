// Tests SwiftailCrypto fundamentals with public vectors from specifications.
//
// Origins (vectors were downloaded from the originals and transcribed mechanically).
// - RFC 7693 Appendix B gives BLAKE2s-256("abc").
// - Official BLAKE2 KAT, testvectors/blake2s-kat.txt at https://github.com/BLAKE2/BLAKE2 (keyed BLAKE2s-256).
// - RFC 8439 §2.5.2 and Appendix A.3 give Poly1305 vectors #1–#11 (including vectors that catch carry and subtraction errors).
// - draft-irtf-cfrg-xchacha-03 §2.2.1 (HChaCha20) and Appendix A.3.1 (AEAD_XCHACHA20_POLY1305).
// - "Cryptography in NaCl" (cr.yp.to/highspeed/naclcrypto-20090310.pdf), chapters 3, 4, 8, and 10
//   Alice and Bob keys, X25519 shared secret, HSalsa20 stage 1 and 2 keys, SHA-256 of a 4 MiB XSalsa20 stream, and the box for a 131-byte packet.
// - Values labeled "cross-check" come from running the same operations in Python hashlib/hmac and Go golang.org/x/crypto
//   at various lengths, including block boundaries, in place of specification vectors. `pattern(_:_:_:)` defines the input bytes.

import CryptoKit
import Foundation
import Testing

@testable import SwiftailCrypto

private func hex(_ s: String) -> [UInt8] {
    let digits = Array(s.filter { !$0.isWhitespace })
    precondition(digits.count % 2 == 0, "Odd-length hex")
    return stride(from: 0, to: digits.count, by: 2).map { UInt8(String(digits[$0..<$0 + 2]), radix: 16)! }
}

private func hexString(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

private func sha256Hex(_ bytes: [UInt8]) -> String {
    hexString(Array(SHA256.hash(data: bytes)))
}

/// Generates input for cross-checks, with byte i equal to (i·mul + add) mod 256.
private func pattern(_ count: Int, _ mul: Int, _ add: Int) -> [UInt8] {
    (0..<count).map { UInt8(truncatingIfNeeded: $0 * mul + add) }
}

private struct PolyVector: Sendable {
    let number: Int
    let key: String
    let message: String
    let tag: String
}

private func flipped(_ bytes: [UInt8], at index: Int) -> [UInt8] {
    var copy = bytes
    copy[index] ^= 0x01
    return copy
}

@Suite("Specification vectors")
struct SpecVectorTests {
    // MARK: BLAKE2s

    @Test("RFC 7693 Appendix B BLAKE2s-256(\"abc\")")
    func blake2sAbc() {
        let expected = hex("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982")
        #expect(BLAKE2s.hash(Array("abc".utf8)) == expected)
    }

    @Test("Official BLAKE2 KAT for keyed BLAKE2s-256, input = 00 01 02 ...")
    func blake2sKeyedKAT() {
        let key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        let rows: [(Int, String)] = [
        (0, "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49"),
        (1, "40d15fee7c328830166ac3f918650f807e7e01e177258cdc0a39b11f598066f1"),
        (2, "6bb71300644cd3991b26ccd4d274acd1adeab8b1d7914546c1198bbe9fc9d803"),
        (3, "1d220dbe2ee134661fdf6d9e74b41704710556f2f6e5a091b227697445dbea6b"),
        (31, "b6156f72d380ee9ea6acd190464f2307a5c179ef01fd71f99f2d0f7a57360aea"),
        (32, "c03bc642b20959cbe133a0303e0c1abff3e31ec8e1a328ec8565c36decff5265"),
        (33, "2c3e08176f760c6264c3a2cd66fec6c3d78de43fc192457b2a4a660a1e0eb22b"),
        (63, "c65382513f07460da39833cb666c5ed82e61b9e998f4b0c4287cee56c3cc9bcd"),
        (64, "8975b0577fd35566d750b362b0897a26c399136df07bababbde6203ff2954ed4"),
        (65, "21fe0ceb0052be7fb0f004187cacd7de67fa6eb0938d927677f2398c132317a8"),
        (127, "ddbfea75cc467882eb3483ce5e2e756a4f4701b76b445519e89f22d60fa86e06"),
        (128, "0c311f38c35a4fb90d651c289d486856cd1413df9b0677f53ece2cd9e477c60a"),
        (129, "46a73a8dd3e70f59d3942c01df599def783c9da82fd83222cd662b53dce7dbdf"),
        (255, "3fb735061abc519dfe979e54c1ee5bfad0a9d858b3315bad34bde999efd724dd")
        ]
        for (length, expected) in rows {
            let input = (0..<length).map { UInt8($0) }
            #expect(hexString(BLAKE2s.hash(input, key: key)) == expected, "Input length \(length)")
        }
    }

    @Test("BLAKE2s cross-check (Python hashlib) at several lengths, with 32-byte unkeyed and 16-byte keyed output (16-byte key)")
    func blake2sCross() {
        let key = Array(pattern(32, 7, 3)[0..<16])
        let rows: [(Int, String, String)] = [
        (0, "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9", "895c79cfc8db1e7b1f10f3951e1f3b2a"),
        (1, "fc87f4f1d721942d282aa61989c069b290d1447d20d4b811430f47ea0edf9991", "9fe263271f4cb2e9499807630b024958"),
        (31, "69a7488cf184c90756514ccb1e73ad98af07dadd31bc8748cdc964c000a9b7b3", "0e0b82aa42622e0dd2e02d45517e60cc"),
        (32, "d4d8337e5fa884febbcb4ff8b09ea533e0b81307c2ba104abb417d12921c8a20", "3b0e608144b3aa9e14e1931bdf060ff0"),
        (33, "8dc75b5b34bddf2db14bcb1eb4d21181419769eed19f37893d0ef3a9b3149676", "4e40840c30d34d0389f785cfcf5d885f"),
        (63, "4f931897d12f7239927df2ed1e3a8c0bb3c9797966008b6703203f38a733c74f", "118488582afc927aea1394a75127501e"),
        (64, "25ebd84a9d46b000ab1fb77ee9259adb3174ccb4db318b1a501fe77ced3993bf", "807b78a7e577b34173dc853df5bc731a"),
        (65, "1251002794c7450b1d630f4250a1b466a100dd54c3bf975a0478e8a6913059b1", "48c9bf3f54bc784854ce5dc0a864fb7a"),
        (127, "e5b93e5b1776359a953eab4a5d9038b431c8957e777899a7532e6c0359e0a117", "13df229f5e40bce380080105ac1eafc3"),
        (128, "1f461cb262a271aca87f0d94ec294858e4cf6b3e22916d5fcbc42fe7c8d1a9e0", "20200348df24666eb8367c8c1c26cf3b"),
        (129, "2907a0ad06c6ad722ae15e61744954397e2edad682e020a600e68d5e885e42b1", "c501054c4c0342c089b128a66458e20b"),
        (300, "6361c191ba4c746bdced383b3ce3ac672e833c2902d532adb6bc04f91537590c", "a018ba1a942683716762ca8a97ea04f8")
        ]
        for (length, plain, keyed) in rows {
            let data = pattern(length, 13, 1)
            #expect(hexString(BLAKE2s.hash(data)) == plain, "Unkeyed, length \(length)")
            #expect(hexString(BLAKE2s.hash(data, outputByteCount: 16, key: key)) == keyed, "Keyed, length \(length)")
        }
    }

    @Test("BLAKE2s chunked updates match a single update, and finalize preserves state")
    func blake2sIncremental() {
        let data = pattern(200, 13, 1)
        var hasher = BLAKE2s()
        hasher.update(data[0..<64])
        let first = hasher.finalize()
        #expect(first == BLAKE2s.hash(data[0..<64]))
        hasher.update(data[64..<65])
        hasher.update(data[65..<200])
        #expect(hasher.finalize() == BLAKE2s.hash(data))
        #expect(hasher.finalize() == BLAKE2s.hash(data))
    }

    // MARK: HMAC, HKDF (cross-checked with Python hmac because the specifications provide no vectors)

    @Test("HMAC-BLAKE2s cross-check (Python hmac) with key lengths 0, 1, 32, 64, 65, and 100")
    func hmacCross() {
        let rows: [(Int, String)] = [
        (0, "4a18206b50f2d6e8c8ca60665a33730fb1300c890f35428a630f823b9b9588e0"),
        (1, "a0fecb550af245fff58b5917d5601ac20f2acf948d0e38bd9fccc461b256d5e6"),
        (32, "9211c9d39a7dec0550f8716612100f7499b22f8b2ccadb966ca4b3caacff2c42"),
        (64, "650823ab633a81095bf25ea0e7261140ed667d8751d622a09c00dd7cfaa77490"),
        (65, "c23bae6019e971041914473eb5e507c06fd9405db1f9a0be5cf010c9bcb413ed"),
        (100, "7630d94234768bbecc22cadc2488fc85215415e59f8f493a666e798302301b48")
        ]
        for (keyLength, expected) in rows {
            let mac = HMACBLAKE2s.authenticationCode(for: Array("swiftail hmac".utf8), key: pattern(keyLength, 9, 4))
            #expect(hexString(mac) == expected, "Key length \(keyLength)")
        }
    }

    @Test("HKDF-BLAKE2s cross-check (Python hmac) for T1, T2, and T3")
    func hkdfCross() {
        let key = pattern(32, 17, 2)
        let input = Array("swiftail hkdf input".utf8)
        let expected = ["6f251c30c41f475d23ca51dace7463529576df1ca31fddffbeb05c62cf92e185", "9100a93283cf25226548c441b3f0da71e3500f2df62b5fc60040a9af377205cb", "e4b0d6eadafb6dd3ca58d14ab865d037b4de2f9d56987132f2c1f607a0c5dad7"]
        #expect(hexString(key) == "02132435465768798a9bacbdcedff00112233445566778899aabbccddeef0011")
        for count in 1...3 {
            let out = HKDFBLAKE2s.derive(chainingKey: key, input: input, outputCount: count)
            #expect(out.map(hexString) == Array(expected[0..<count]), "outputCount \(count)")
        }
    }

    // MARK: Poly1305

    @Test("RFC 8439 §2.5.2 Poly1305 example")
    func poly1305Section252() {
        let tag = Poly1305.authenticate(Array("Cryptographic Forum Research Group".utf8), key: hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"))
        #expect(hexString(tag) == "a8061dc1305136c6c22b8baf0c0127a9")
    }

    @Test("RFC 8439 Appendix A.3 Poly1305 vectors #1–#11")
    func poly1305AppendixA3() {
        let vectors: [PolyVector] = [
        PolyVector(number: 1, key: "0000000000000000000000000000000000000000000000000000000000000000",
            message: """
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            """,
            tag: "00000000000000000000000000000000"),
        PolyVector(number: 2, key: "0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e",
            message: """
            416e79207375626d697373696f6e20746f20746865204945544620696e74656e
            6465642062792074686520436f6e7472696275746f7220666f72207075626c69
            636174696f6e20617320616c6c206f722070617274206f6620616e2049455446
            20496e7465726e65742d4472616674206f722052464320616e6420616e792073
            746174656d656e74206d6164652077697468696e2074686520636f6e74657874
            206f6620616e204945544620616374697669747920697320636f6e7369646572
            656420616e20224945544620436f6e747269627574696f6e222e205375636820
            73746174656d656e747320696e636c756465206f72616c2073746174656d656e
            747320696e20494554462073657373696f6e732c2061732077656c6c20617320
            7772697474656e20616e6420656c656374726f6e696320636f6d6d756e696361
            74696f6e73206d61646520617420616e792074696d65206f7220706c6163652c
            207768696368206172652061646472657373656420746f
            """,
            tag: "36e5f6b5c5e06070f0efca96227a863e"),
        PolyVector(number: 3, key: "36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000",
            message: """
            416e79207375626d697373696f6e20746f20746865204945544620696e74656e
            6465642062792074686520436f6e7472696275746f7220666f72207075626c69
            636174696f6e20617320616c6c206f722070617274206f6620616e2049455446
            20496e7465726e65742d4472616674206f722052464320616e6420616e792073
            746174656d656e74206d6164652077697468696e2074686520636f6e74657874
            206f6620616e204945544620616374697669747920697320636f6e7369646572
            656420616e20224945544620436f6e747269627574696f6e222e205375636820
            73746174656d656e747320696e636c756465206f72616c2073746174656d656e
            747320696e20494554462073657373696f6e732c2061732077656c6c20617320
            7772697474656e20616e6420656c656374726f6e696320636f6d6d756e696361
            74696f6e73206d61646520617420616e792074696d65206f7220706c6163652c
            207768696368206172652061646472657373656420746f
            """,
            tag: "f3477e7cd95417af89a6b8794c310cf0"),
        PolyVector(number: 4, key: "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
            message: """
            2754776173206272696c6c69672c20616e642074686520736c6974687920746f
            7665730a446964206779726520616e642067696d626c6520696e207468652077
            6162653a0a416c6c206d696d737920776572652074686520626f726f676f7665
            732c0a416e6420746865206d6f6d65207261746873206f757467726162652e
            """,
            tag: "4541669a7eaaee61e708dc7cbcc5eb62"),
        PolyVector(number: 5, key: "0200000000000000000000000000000000000000000000000000000000000000",
            message: "ffffffffffffffffffffffffffffffff",
            tag: "03000000000000000000000000000000"),
        PolyVector(number: 6, key: "02000000000000000000000000000000ffffffffffffffffffffffffffffffff",
            message: "02000000000000000000000000000000",
            tag: "03000000000000000000000000000000"),
        PolyVector(number: 7, key: "0100000000000000000000000000000000000000000000000000000000000000",
            message: """
            fffffffffffffffffffffffffffffffff0ffffffffffffffffffffffffffffff
            11000000000000000000000000000000
            """,
            tag: "05000000000000000000000000000000"),
        PolyVector(number: 8, key: "0100000000000000000000000000000000000000000000000000000000000000",
            message: """
            fffffffffffffffffffffffffffffffffbfefefefefefefefefefefefefefefe
            01010101010101010101010101010101
            """,
            tag: "00000000000000000000000000000000"),
        PolyVector(number: 9, key: "0200000000000000000000000000000000000000000000000000000000000000",
            message: "fdffffffffffffffffffffffffffffff",
            tag: "faffffffffffffffffffffffffffffff"),
        PolyVector(number: 10, key: "0100000000000000040000000000000000000000000000000000000000000000",
            message: """
            e33594d7505e43b900000000000000003394d7505e4379cd0100000000000000
            0000000000000000000000000000000001000000000000000000000000000000
            """,
            tag: "14000000000000005500000000000000"),
        PolyVector(number: 11, key: "0100000000000000040000000000000000000000000000000000000000000000",
            message: """
            e33594d7505e43b900000000000000003394d7505e4379cd0100000000000000
            00000000000000000000000000000000
            """,
            tag: "13000000000000000000000000000000")
        ]
        #expect(vectors.count == 11)
        for v in vectors {
            let tag = Poly1305.authenticate(hex(v.message), key: hex(v.key))
            #expect(hexString(tag) == v.tag, "A.3 vector #\(v.number)")
        }
    }

    // The cross-review (GPT-6.1 Sol) generated this vector with Go x/crypto. The partial block has all limbs at their maximum values.
    @Test("Poly1305 with key ff×32 and message ff×15")
    func poly1305AllOnes() {
        let tag = Poly1305.authenticate([UInt8](repeating: 0xff, count: 15), key: [UInt8](repeating: 0xff, count: 32))
        #expect(tag == hex("fbff27e6030028e6030028e6030028ee"))
    }

    @Test("Ciphertext shorter than the tag (0–15 bytes) yields invalidLength")
    func shortCiphertexts() {
        let key = [UInt8](repeating: 1, count: 32), nonce = [UInt8](repeating: 2, count: 24)
        for count in 0..<16 {
            let short = [UInt8](repeating: 3, count: count)
            #expect(throws: CryptoError.invalidLength) { try NaClSecretBox.open(short, nonce: nonce, key: key) }
            #expect(throws: CryptoError.invalidLength) {
                try XChaCha20Poly1305.open(short, key: key, nonce: nonce, authenticating: [UInt8]())
            }
        }
    }

    // MARK: HChaCha20, XChaCha20-Poly1305

    @Test("draft-irtf-cfrg-xchacha-03 §2.2.1: HChaCha20")
    func hchacha20Vector() {
        let out = hchacha20(key: hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), input: hex("000000090000004a0000000031415927"))
        #expect(hexString(out) == "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")
    }

    private static let xKey = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
    private static let xIV = hex("404142434445464748494a4b4c4d4e4f5051525354555657")
    private static let xAAD = hex("50515253c0c1c2c3c4c5c6c7")
    private static let xPlaintext = hex("""
        4c616469657320616e642047656e746c656d656e206f662074686520636c6173
        73206f66202739393a204966204920636f756c64206f6666657220796f75206f
        6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73
        637265656e20776f756c642062652069742e
        """)
    private static let xSealed = hex("""
        bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb
        731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452
        2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9
        21f9664c97637da9768812f615c68b13b52e
        """) + hex("c0875924c1c7987947deafd8780acf49")

    @Test("draft-irtf-cfrg-xchacha-03 A.3.1: AEAD_XCHACHA20_POLY1305 seal·open")
    func xchachaAEAD() throws {
        let sealed = try XChaCha20Poly1305.seal(Self.xPlaintext, key: Self.xKey, nonce: Self.xIV, authenticating: Self.xAAD)
        #expect(sealed == Self.xSealed)
        let opened = try XChaCha20Poly1305.open(Self.xSealed, key: Self.xKey, nonce: Self.xIV, authenticating: Self.xAAD)
        #expect(opened == Self.xPlaintext)
    }

    @Test("XChaCha20-Poly1305 yields authenticationFailed if even one bit of the ciphertext, tag, nonce, AAD, or key changes")
    func xchachaTamper() {
        let sealed = Self.xSealed
        for index in [0, 57, sealed.count - 17, sealed.count - 16, sealed.count - 1] {
            #expect(throws: CryptoError.authenticationFailed, "Sealed byte \(index)") {
                try XChaCha20Poly1305.open(flipped(sealed, at: index), key: Self.xKey, nonce: Self.xIV, authenticating: Self.xAAD)
            }
        }
        for index in [0, 15, 16, 23] {
            #expect(throws: CryptoError.authenticationFailed, "Nonce byte \(index)") {
                try XChaCha20Poly1305.open(sealed, key: Self.xKey, nonce: flipped(Self.xIV, at: index), authenticating: Self.xAAD)
            }
        }
        for index in [0, 11] {
            #expect(throws: CryptoError.authenticationFailed, "AAD byte \(index)") {
                try XChaCha20Poly1305.open(sealed, key: Self.xKey, nonce: Self.xIV, authenticating: flipped(Self.xAAD, at: index))
            }
        }
        #expect(throws: CryptoError.authenticationFailed) {
            try XChaCha20Poly1305.open(sealed, key: flipped(Self.xKey, at: 31), nonce: Self.xIV, authenticating: Self.xAAD)
        }
        #expect(throws: CryptoError.authenticationFailed) {
            try XChaCha20Poly1305.open(sealed, key: Self.xKey, nonce: Self.xIV, authenticating: Array(Self.xAAD.dropLast()))
        }
    }

    @Test("XChaCha20-Poly1305 length errors yield invalidLength")
    func xchachaLengths() {
        #expect(throws: CryptoError.invalidLength) {
            try XChaCha20Poly1305.seal([UInt8](), key: Array(Self.xKey.dropLast()), nonce: Self.xIV, authenticating: [UInt8]())
        }
        #expect(throws: CryptoError.invalidLength) {
            try XChaCha20Poly1305.seal([UInt8](), key: Self.xKey, nonce: Array(Self.xIV.dropLast()), authenticating: [UInt8]())
        }
        #expect(throws: CryptoError.invalidLength) {
            try XChaCha20Poly1305.open([UInt8](repeating: 0, count: 15), key: Self.xKey, nonce: Self.xIV, authenticating: [UInt8]())
        }
    }

    @Test("XChaCha20-Poly1305 cross-check (Go x/crypto) for SHA-256 of ciphertext‖tag")
    func xchachaCross() throws {
        let rows: [(Int, String)] = [
        (0, "56c714edaa03b44e1826e9997fe4aae1fd31169ee3f199d7af4d5d49853dda3a"),
        (1, "a51184d641aae4e1db4118df4821ae3aa8379509702881caff88ffea918ecff7"),
        (15, "ee4e2e9192702b1cb496b99986db1699e288e72afdc2d51b1251981028d762fa"),
        (16, "7117dd865a737e95d9deda93d66507e42654db4b6b5ffcb768c5a7029aa52e05"),
        (17, "2578699aaacac1ade8a78fe87fd172a72084e8894825fd2bac7ef465a44a5704"),
        (31, "7cbeba2ce797e5fa81ff6ac844572f8fef8e1962c8a7076d76299551d2153409"),
        (32, "aeb6bba2f1f22086366404d3325ac245952244fd34d525b0bd76679cd78f2162"),
        (33, "89d414a704d3375b35b3e8a0b8a8c1e94292e5020d35d71fa3dc93d441641cc8"),
        (63, "31e7ad68171e62f5be1b7b6218e338ba3da6137b3e3ec26b61401ec73cbb421d"),
        (64, "655e7969d81c462505f46d40cfd6ec17bc62c050b6ce60c259c3a904a986bf55"),
        (65, "c22e57a59708f15b405073a0c27503a1b2e273d2c166e3ac3a58f2abe1c82c85"),
        (127, "03e4b0cc8f090f93ec3266970d988c327135c35ef48a5b8e9ac871509eb5d07e"),
        (128, "d9f29f885d36fec38548f7e9d4fed43d139cf9e7056087dae70d7d6c68584b93"),
        (129, "cf12319e6deb8735102ee69a050a3aead884bf1fa3925c483dc422265f3a1289"),
        (300, "75f9256dcf38c8ef42a914fe6ab67a92a52cb8bc865b19f497d557a379765ef0")
        ]
        for (length, digest) in rows {
            let sealed = try XChaCha20Poly1305.seal(
                pattern(length, 13, 1), key: pattern(32, 7, 3), nonce: pattern(24, 11, 5), authenticating: pattern(21, 5, 9))
            #expect(sha256Hex(sealed) == digest, "Length \(length)")
        }
    }

    // MARK: Salsa20 family and NaCl

    private static let aliceSK = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    private static let alicePK = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    private static let bobSK = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    private static let bobPK = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    private static let firstKey = hex("1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389")
    private static let nonce = hex("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37")
    private static let packet = hex("""
        be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffc
        e5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb31
        0e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde
        048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f93776384864
        5e0705
        """)
    private static let boxed = hex("""
        f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce
        48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c972
        71d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae
        90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b3
        7973f622a43d14a6599b1f654cb45a74e355a5
        """)

    @Test("NaCl chapters 4 and 8 cover the X25519 shared secret and HSalsa20 stage 1 and 2 keys")
    func naclKeyDerivation() throws {
        // First check that CryptoKit X25519 yields the documented shared secret (that the input key pairs are correct).
        let priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Self.aliceSK)
        let pub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: Self.bobPK)
        let secret = try priv.sharedSecretFromKeyAgreement(with: pub).withUnsafeBytes { Array($0) }
        #expect(secret == hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"))

        let zero = [UInt8](repeating: 0, count: 16)
        #expect(Salsa20.hsalsa20(key: secret, input: zero) == Self.firstKey)
        let second = Salsa20.hsalsa20(key: Self.firstKey, input: hex("69696ee955b62b73cd62bda875fc73d6"))
        #expect(second == hex("dc908dda0b9344a953629b733820778880f3ceb421bb61b91cbd4c3e66256ce4"))
    }

    @Test("NaCl chapter 8 covers SHA-256 of a 4 MiB Salsa20 or XSalsa20 stream")
    func naclStreamDigest() {
        let count = 4_194_304
        let viaSalsa = Salsa20.keystream(key: hex("dc908dda0b9344a953629b733820778880f3ceb421bb61b91cbd4c3e66256ce4"), nonce: hex("8219e0036b7a0b37"), count: count)
        #expect(sha256Hex(viaSalsa) == "662b9d0e3463029156069b12f918691a98f7dfb2ca0393c96bbfc6b1fbd630a2")
        let viaXSalsa = Salsa20.xsalsa20Keystream(key: Self.firstKey, nonce: Self.nonce, count: count)
        #expect(sha256Hex(viaXSalsa) == "662b9d0e3463029156069b12f918691a98f7dfb2ca0393c96bbfc6b1fbd630a2")
    }

    @Test("NaCl chapter 10 covers sharedKey, secretbox, and box for a 131-byte packet")
    func naclBoxVector() throws {
        #expect(try NaClBox.sharedKey(privateKey: Self.aliceSK, peerPublicKey: Self.bobPK) == Self.firstKey)
        #expect(try NaClBox.sharedKey(privateKey: Self.bobSK, peerPublicKey: Self.alicePK) == Self.firstKey)

        let sealed = try NaClSecretBox.seal(Self.packet, nonce: Self.nonce, key: Self.firstKey)
        #expect(sealed.count == 147)
        #expect(sealed == Self.boxed)
        #expect(try NaClSecretBox.open(Self.boxed, nonce: Self.nonce, key: Self.firstKey) == Self.packet)
    }

    @Test("NaCl secretbox yields authenticationFailed if even one bit of the tag, ciphertext, nonce, or key changes")
    func naclTamper() {
        let box = Self.boxed
        for index in [0, 7, 15, 16, 17, 100, box.count - 1] {
            #expect(throws: CryptoError.authenticationFailed, "Box byte \(index)") {
                try NaClSecretBox.open(flipped(box, at: index), nonce: Self.nonce, key: Self.firstKey)
            }
        }
        for index in [0, 23] {
            #expect(throws: CryptoError.authenticationFailed, "Nonce byte \(index)") {
                try NaClSecretBox.open(box, nonce: flipped(Self.nonce, at: index), key: Self.firstKey)
            }
        }
        #expect(throws: CryptoError.authenticationFailed) {
            try NaClSecretBox.open(box, nonce: Self.nonce, key: flipped(Self.firstKey, at: 0))
        }
    }

    @Test("NaCl length errors yield invalidLength and low-order points yield invalidKey")
    func naclErrors() {
        let key = Self.firstKey
        #expect(throws: CryptoError.invalidLength) { try NaClSecretBox.seal([UInt8](), nonce: Self.nonce, key: Array(key.dropLast())) }
        #expect(throws: CryptoError.invalidLength) { try NaClSecretBox.seal([UInt8](), nonce: Array(Self.nonce.dropLast()), key: key) }
        #expect(throws: CryptoError.invalidLength) { try NaClSecretBox.open([UInt8](repeating: 0, count: 15), nonce: Self.nonce, key: key) }
        #expect(throws: CryptoError.invalidLength) { try NaClBox.sharedKey(privateKey: Array(Self.aliceSK.dropLast()), peerPublicKey: Self.bobPK) }
        #expect(throws: CryptoError.invalidLength) { try NaClBox.sharedKey(privateKey: Self.aliceSK, peerPublicKey: Array(Self.bobPK.dropLast())) }
        #expect(throws: CryptoError.invalidKey) {
            try NaClBox.sharedKey(privateKey: Self.aliceSK, peerPublicKey: [UInt8](repeating: 0, count: 32))
        }
    }

    @Test("NaCl cross-check (Go x/crypto) for SHA-256 of secretbox output and the box.Precompute result")
    func naclCross() throws {
        let rows: [(Int, String)] = [
        (0, "7ad948af042e44c02b4af78f77236b42e79fae850d68206304f0e839f4792f30"),
        (1, "8c217f15cadfd7b7689beb402aeedda6af3ddb7e154ceb81eba0f7da72420ec4"),
        (15, "065970f5d3c4889fabd1c8602b978f4f1ba963053d5e6c25614d0d04b3fed796"),
        (16, "ebbf4f272a8239080e1861aed67f849f3cd4bc117309b5f8a81b07da4a8ce6ea"),
        (17, "18f93c86d70147ff240f1fea1f7ae2deba8049ed6870524337719ac22928c073"),
        (31, "91ed91984c045380f13b0a36b1899342fe7d572b81d00cbd3172ed24bd572300"),
        (32, "78de81dd4b0b1f5d7f0c3dc96c519927e4f7ab481c20f94b5f31612fa1bd8263"),
        (33, "2d2c9ea2c5d6dfdea1e425f38c2c8eada914bf9e48ba46b2012d142057440e7b"),
        (63, "16383d4127a6ce40bbca0e19ef7d9c1adfd529337f7302767fea2d6f3cb06d78"),
        (64, "ef494cea510ff85905249a61e388e95e7560ad2803d1b3259fef8bf76cf074af"),
        (65, "521ac365f28202fa5c50e4625b491e1bfb6add7e0115a4f4f2b85d1a47d51415"),
        (127, "6418ed692347a6e9c0cc909a0ee512b8f24b3d294362a0eb1dd57dc29cdf33b7"),
        (128, "ae8ad4957bf2d65712ee2e9226a0d8a72cfdb2b84ceea9f0490074b4db64a5dd"),
        (129, "ec504f5bbeaded7aa25b50a44e814dd0e356c03f00a0b51847805f0a44a4bf15"),
        (300, "cae68478d132d10072662b53d3b7a00cfe7ca7f92a39baabadd683bc00a6f9f5")
        ]
        for (length, digest) in rows {
            let sealed = try NaClSecretBox.seal(pattern(length, 13, 1), nonce: pattern(24, 11, 5), key: pattern(32, 7, 3))
            #expect(sha256Hex(sealed) == digest, "Length \(length)")
            #expect(try NaClSecretBox.open(sealed, nonce: pattern(24, 11, 5), key: pattern(32, 7, 3)) == pattern(length, 13, 1))
        }
        let shared = try NaClBox.sharedKey(privateKey: pattern(32, 3, 1), peerPublicKey: pattern(32, 5, 2))
        #expect(hexString(shared) == "9e2f84e914a8da4f7473e84ffe9991d6fe3e78eeffb3591c3b6a8d1b0a792c8d")
    }

    // MARK: constantTimeEqual

    @Test("constantTimeEqual with equal contents, different contents, and different lengths")
    func constantTimeEqualBasics() {
        #expect(constantTimeEqual([1, 2, 3], [1, 2, 3]))
        #expect(constantTimeEqual([], []))
        #expect(!constantTimeEqual([1, 2, 3], [1, 2, 4]))
        #expect(!constantTimeEqual([0, 2, 3], [1, 2, 3]))
        #expect(!constantTimeEqual([1, 2], [1, 2, 3]))
    }
}
