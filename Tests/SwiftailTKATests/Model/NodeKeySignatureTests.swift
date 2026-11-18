// The credential reference comes from a Go test: from the wrapped auth key in tailscale.com v1.104.7 `tka/sig_test.go:479` (`TestDecodeWrappedAuthkey`),
// convert the first part after `--TL` (credential NKS, base64 RawStd) to hex. The private key part was omitted.
//   Copyright (c) Tailscale Inc & contributors, SPDX-License-Identifier: BSD-3-Clause.

import SwiftailCrypto
import Testing

@testable import SwiftailTKA

/// NKS decoding, canonical encoding, and SigHash (contract behaviors E4, E5, D, and M, note §§3.6 and 3.7).
@Suite("NodeKeySignature")
struct NodeKeySignatureTests {
    static let goCredential =
        "a401030358209d7bb0e3f7d69cd594c1ca0e8cb7a684ebe69758ee325e6584b998e6c054b23f0458401f2f681d783f60f150f0e6d81cc428871a"
        + "511bebb0605360e5173640a62e0b85e2c9ada03ea588d3182855869673d62ca204f0fe536ab10d001b337f96158d04065820c6656a1b9dc7bb"
        + "4460f8a9872453255217e0ce8f8040febe2a4f46cef2493ace"

    @Test("Go test credential: rewriting preserves the bytes, and the signature over SigHash verifies with KeyID")
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

    @Test("SigHash omits only the outer signature and includes inner signatures")
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

    @Test("Always writes SigKind and writes other fields only when nonempty. Top-level null becomes a10100")
    func encoding() throws {
        #expect(ModelTesting.hex(NodeKeySignature(kind: 0).serialized()) == "a10100")
        #expect(ModelTesting.hex(try ModelTesting.decodeNKS("f6").get().serialized()) == "a10100")
        #expect(ModelTesting.hex(try ModelTesting.decodeNKS("f7").get().serialized()) == "a10100")
        let full = NodeKeySignature(kind: 2, publicKey: [1], keyID: [2], signature: [3], nested: NodeKeySignature(kind: 1), wrappingPublicKey: [4])
        #expect(ModelTesting.hex(full.serialized()) == "a6010202410103410204410305a1010106410" + "4")
        // Omits both empty byte sequences and null.
        #expect(try ModelTesting.decodeNKS("a601010240034004f605f606f6").get() == NodeKeySignature(kind: 1))
    }

    @Test("Decode rejection cases: top level is not a map, duplicate keys, types, and ranges")
    func rejected() throws {
        for hex in [
            "80", "01", "4101",  // Top level
            "a201010101", "a20101180101",  // Duplicate (including non-shortest encodings)
            "a20101036161", "a101190100", "a10120", "a10541 01", "a1058101",  // Type and range
            "a20102028201190100",  // 256 in an array in a byte sequence field
            "a1f601",  // null key
        ] {
            let input = hex.replacingOccurrences(of: " ", with: "")
            #expect(throws: TKAError.invalidStructure, "\(hex)") { try ModelTesting.decodeNKS(input).get() }
        }
        #expect(throws: TKAError.cbor(.trailingBytes)) { try ModelTesting.decodeNKS("a1010100").get() }
        // An integer array in a byte sequence field decodes as bytes.
        #expect(try ModelTesting.decodeNKS("a201010282186e1870").get().publicKey == [0x6e, 0x70])
    }

    @Test("Nesting: accepts up to 16 levels including the top level (15 rotations over direct) and rejects level 17")
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

    @Test("Decodes up to 8KiB and rejects larger input before decoding")
    func byteLimit() throws {
        // {1: 1, 8: h'…'}: 7-byte header (`a2 01 01 08 59 xxxx`) plus contents.
        func exact(_ totalCount: Int) -> [UInt8] {
            let count = totalCount - 7
            return [0xa2, 0x01, 0x01, 0x08, 0x59, UInt8(count >> 8), UInt8(count & 0xff)] + [UInt8](repeating: 1, count: count)
        }
        #expect(exact(8 * 1_024).count == 8 * 1_024)
        #expect(try NodeKeySignature(decoding: exact(8 * 1_024)) == NodeKeySignature(kind: 1))
        #expect(throws: TKAError.limitExceeded) { try NodeKeySignature(decoding: exact(8 * 1_024 + 1)) }
    }

    @Test("Arbitrary values round-trip, noncanonical encodings yield the same canonical bytes, and all prefixes are rejected")
    func roundTripProperty() throws {
        var generator = ModelTesting.Generator(random: CBORTesting.Random(state: 0x4e4b))
        for index in 0..<300 {
            let signature = generator.nodeKeySignature()
            let canonical = signature.serialized()
            #expect(try NodeKeySignature(decoding: canonical) == signature, "Value \(index)")
            let loose = generator.looseEncoding(of: try CBOR.decode(canonical))
            let decoded = try NodeKeySignature(decoding: loose)
            #expect(decoded.serialized() == canonical, "Value \(index)")
            #expect(decoded.signatureHash == signature.signatureHash, "Value \(index)")
            if index < 20 {
                for count in 0..<canonical.count {
                    #expect(throws: TKAError.self) { try NodeKeySignature(decoding: Array(canonical.prefix(count))) }
                }
            }
        }
    }
}
