// credential 기준값은 Go 시험에서 옮겼다: tailscale.com v1.104.7 `tka/sig_test.go:479`(`TestDecodeWrappedAuthkey`)의
// 감싼 인증 키 가운데 `--TL` 뒤 첫 부분(credential NKS, base64 RawStd)을 16진으로 바꿨다. 개인 키 부분은 옮기지 않았다.
//   Copyright (c) Tailscale Inc & contributors, SPDX-License-Identifier: BSD-3-Clause.

import SwiftailCrypto
import Testing

@testable import SwiftailTKA

/// NKS의 읽기·정준 쓰기·SigHash(계약 동작 E4·E5·D·M, 노트 3.6·3.7).
@Suite("NodeKeySignature")
struct NodeKeySignatureTests {
    static let goCredential =
        "a401030358209d7bb0e3f7d69cd594c1ca0e8cb7a684ebe69758ee325e6584b998e6c054b23f0458401f2f681d783f60f150f0e6d81cc428871a"
        + "511bebb0605360e5173640a62e0b85e2c9ada03ea588d3182855869673d62ca204f0fe536ab10d001b337f96158d04065820c6656a1b9dc7bb"
        + "4460f8a9872453255217e0ce8f8040febe2a4f46cef2493ace"

    @Test("Go 시험의 credential: 다시 쓰면 같고, SigHash에 대한 서명이 KeyID로 검증된다")
    func goCredential() throws {
        let input = ModelTesting.bytes(Self.goCredential)
        let signature = try NodeKeySignature(decoding: input)
        #expect(signature.kind == NodeKeySignature.Kind.credential)
        #expect(signature.keyID.count == 32 && signature.signature.count == 64 && signature.wrappingPublicKey.count == 32)
        #expect(signature.publicKey.isEmpty && signature.nested == nil)
        #expect(signature.serialized() == input)
        #expect(
            Ed25519Verification.isValidZIP215(
                signature: signature.signature, message: signature.signatureHash, publicKey: signature.keyID
            )
        )
    }

    @Test("SigHash는 바깥 서명만 빼고 안쪽 서명은 넣는다")
    func signatureHash() {
        let inner = NodeKeySignature(kind: 1, publicKey: [0x6e, 0x70, 1], keyID: [2], signature: [3])
        var outer = NodeKeySignature(kind: 2, publicKey: [0x6e, 0x70, 4], signature: [5], nested: inner)
        let hash = outer.signatureHash
        var unsigned = outer
        unsigned.signature = []
        #expect(hash == BLAKE2s.hash(unsigned.serialized()))
        outer.signature = [6, 7]
        #expect(outer.signatureHash == hash)
        outer.nested?.signature = [8]
        #expect(outer.signatureHash != hash)
    }

    @Test("SigKind는 늘, 나머지는 비지 않을 때만 쓴다. 맨 바깥 null은 a10100이다")
    func encoding() throws {
        #expect(ModelTesting.hex(NodeKeySignature(kind: 0).serialized()) == "a10100")
        #expect(ModelTesting.hex(try ModelTesting.decodeNKS("f6").get().serialized()) == "a10100")
        #expect(ModelTesting.hex(try ModelTesting.decodeNKS("f7").get().serialized()) == "a10100")
        let full = NodeKeySignature(kind: 2, publicKey: [1], keyID: [2], signature: [3], nested: NodeKeySignature(kind: 1), wrappingPublicKey: [4])
        #expect(ModelTesting.hex(full.serialized()) == "a6010202410103410204410305a1010106410" + "4")
        // 빈 바이트열과 null은 둘 다 빠진다.
        #expect(try ModelTesting.decodeNKS("a601010240034004f605f606f6").get() == NodeKeySignature(kind: 1))
    }

    @Test("읽기의 거절: 맨 바깥 맵 아님, 중복 키, 타입, 범위")
    func rejected() throws {
        for hex in [
            "80", "01", "4101",  // 맨 바깥
            "a201010101", "a20101180101",  // 중복(비최단 포함)
            "a20101036161", "a101190100", "a10120", "a10541 01", "a1058101",  // 타입·범위
            "a20102028201190100",  // 바이트열 자리 배열의 256
            "a1f601",  // null 키
        ] {
            let input = hex.replacingOccurrences(of: " ", with: "")
            #expect(throws: TKAError.invalidStructure, "\(hex)") { try ModelTesting.decodeNKS(input).get() }
        }
        #expect(throws: TKAError.cbor(.trailingBytes)) { try ModelTesting.decodeNKS("a1010100").get() }
        // 바이트열 자리의 정수 배열은 바이트열로 읽는다.
        #expect(try ModelTesting.decodeNKS("a201010282186e1870").get().publicKey == [0x6e, 0x70])
    }

    @Test("중첩: 맨 바깥을 포함해 16단(rotation 15겹 위 direct)까지 읽고 17단은 거절한다")
    func nesting() throws {
        func chain(depth: Int) -> NodeKeySignature {
            var signature = NodeKeySignature(kind: 1, publicKey: [0x6e, 0x70], keyID: [1], signature: [2])
            for _ in 1..<depth {
                signature = NodeKeySignature(kind: 2, publicKey: [0x6e, 0x70], signature: [3], nested: signature)
            }
            return signature
        }
        let sixteen = chain(depth: 16)
        #expect(try NodeKeySignature(decoding: sixteen.serialized()) == sixteen)
        #expect(throws: TKAError.cbor(.nestingTooDeep)) { try NodeKeySignature(decoding: chain(depth: 17).serialized()) }
    }

    @Test("8KiB까지 읽고 그보다 길면 디코딩 전에 거절한다")
    func byteLimit() throws {
        // {1: 1, 8: h'…'}: 머리 7바이트(`a2 01 01 08 59 xxxx`)와 내용.
        func exact(_ totalCount: Int) -> [UInt8] {
            let count = totalCount - 7
            return [0xa2, 0x01, 0x01, 0x08, 0x59, UInt8(count >> 8), UInt8(count & 0xff)] + [UInt8](repeating: 1, count: count)
        }
        #expect(exact(8 * 1_024).count == 8 * 1_024)
        #expect(try NodeKeySignature(decoding: exact(8 * 1_024)) == NodeKeySignature(kind: 1))
        #expect(throws: TKAError.limitExceeded) { try NodeKeySignature(decoding: exact(8 * 1_024 + 1)) }
    }

    @Test("임의의 값: 쓰고 읽으면 같고, 비정준 인코딩도 같은 정준 바이트가 된다. 모든 접두는 거절한다")
    func roundTripProperty() throws {
        var generator = ModelTesting.Generator(random: CBORTesting.Random(state: 0x4e4b))
        for index in 0..<300 {
            let signature = generator.nodeKeySignature()
            let canonical = signature.serialized()
            #expect(try NodeKeySignature(decoding: canonical) == signature, "값 \(index)")
            let loose = generator.looseEncoding(of: try CBOR.decode(canonical))
            let decoded = try NodeKeySignature(decoding: loose)
            #expect(decoded.serialized() == canonical, "값 \(index)")
            #expect(decoded.signatureHash == signature.signatureHash, "값 \(index)")
            if index < 20 {
                for count in 0..<canonical.count {
                    #expect(throws: TKAError.self) { try NodeKeySignature(decoding: Array(canonical.prefix(count))) }
                }
            }
        }
    }
}
