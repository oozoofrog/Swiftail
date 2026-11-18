import Foundation
import Testing
import SwiftailCrypto

@Test func CrossVectors() throws {
    for name in ["cross", "blake2s-kat", "wireguard-kdf"] {
        for v in try loadVectors(name) {
            let key = bytes(v.key), input = bytes(v.input), expected = bytes(v.output)
            switch v.kind {
            case "blake2s":
                #expect(BLAKE2s.hash(input, outputByteCount: expected.count, key: key) == expected, "\(name), input length \(input.count), key length \(key.count), output length \(expected.count)")
                var h = BLAKE2s(outputByteCount: expected.count, key: key)
                let cut = input.count / 2
                h.update(input.prefix(cut))
                let snapshot = h.finalize()
                #expect(snapshot == BLAKE2s.hash(input.prefix(cut), outputByteCount: expected.count, key: key))
                h.update(input.dropFirst(cut).prefix(1))
                h.update(input.dropFirst(min(cut + 1, input.count)))
                #expect(h.finalize() == expected)
                #expect(h.finalize() == expected)
            case "kdf", "wireguard":
                if v.kind == "kdf" { #expect(HMACBLAKE2s.authenticationCode(for: input, key: key) == expected) }
                let outputs = v.outputs!.map(bytes)
                for count in 1...3 {
                    #expect(HKDFBLAKE2s.derive(chainingKey: key, input: input, outputCount: count) == Array(outputs.prefix(count)))
                }
            case "secretbox":
                let nonce = bytes(v.nonce!)
                #expect(try NaClSecretBox.seal(input, nonce: nonce, key: key) == expected)
                #expect(try NaClSecretBox.open(expected, nonce: nonce, key: key) == input)
            case "box":
                #expect(try NaClBox.sharedKey(privateKey: key, peerPublicKey: bytes(v.public!)) == expected)
            case "xchacha":
                let nonce = bytes(v.nonce!), aad = bytes(v.aad ?? "")
                #expect(try XChaCha20Poly1305.seal(input, key: key, nonce: nonce, authenticating: aad) == expected)
                #expect(try XChaCha20Poly1305.open(expected, key: key, nonce: nonce, authenticating: aad) == input)
            default:
                Issue.record("Unknown vector kind \(v.kind)")
            }
        }
    }
}

@Test func CrossVectorTampering() throws {
    let all = try loadVectors("cross")
    let s = all.first { $0.kind == "secretbox" && !$0.input.isEmpty }!
    let x = all.first { $0.kind == "xchacha" && !$0.input.isEmpty && !($0.aad ?? "").isEmpty }!
    func flip(_ value: [UInt8], _ index: Int = 0) -> [UInt8] { var b = value; b[index] ^= 1; return b }
    let sk = bytes(s.key), sn = bytes(s.nonce!), sb = bytes(s.output)
    for b in [flip(sb), flip(sb, 16)] {
        #expect(throws: CryptoError.authenticationFailed) { try NaClSecretBox.open(b, nonce: sn, key: sk) }
    }
    #expect(throws: CryptoError.authenticationFailed) { try NaClSecretBox.open(sb, nonce: flip(sn), key: sk) }
    #expect(throws: CryptoError.authenticationFailed) { try NaClSecretBox.open(sb, nonce: sn, key: flip(sk)) }
    let k = bytes(x.key), n = bytes(x.nonce!), aad = bytes(x.aad!), sealed = bytes(x.output)
    for b in [flip(sealed), flip(sealed, sealed.count - 1)] {
        #expect(throws: CryptoError.authenticationFailed) { try XChaCha20Poly1305.open(b, key: k, nonce: n, authenticating: aad) }
    }
    #expect(throws: CryptoError.authenticationFailed) { try XChaCha20Poly1305.open(sealed, key: flip(k), nonce: n, authenticating: aad) }
    #expect(throws: CryptoError.authenticationFailed) { try XChaCha20Poly1305.open(sealed, key: k, nonce: flip(n), authenticating: aad) }
    #expect(throws: CryptoError.authenticationFailed) { try XChaCha20Poly1305.open(sealed, key: k, nonce: n, authenticating: flip(aad)) }
}

@Test func CrossVectorInvalidInputs() throws {
    let key = [UInt8](repeating: 1, count: 32), nonce = [UInt8](repeating: 2, count: 24)
    for bad in [[], [UInt8](repeating: 1, count: 31), [UInt8](repeating: 1, count: 33)] {
        #expect(throws: CryptoError.invalidLength) { try NaClSecretBox.seal([], nonce: nonce, key: bad) }
        #expect(throws: CryptoError.invalidLength) { try NaClSecretBox.open([UInt8](repeating: 0, count: 16), nonce: nonce, key: bad) }
        #expect(throws: CryptoError.invalidLength) { try XChaCha20Poly1305.seal([], key: bad, nonce: nonce, authenticating: []) }
        #expect(throws: CryptoError.invalidLength) { try XChaCha20Poly1305.open([UInt8](repeating: 0, count: 16), key: bad, nonce: nonce, authenticating: []) }
        #expect(throws: CryptoError.invalidLength) { try NaClBox.sharedKey(privateKey: bad, peerPublicKey: key) }
        #expect(throws: CryptoError.invalidLength) { try NaClBox.sharedKey(privateKey: key, peerPublicKey: bad) }
    }
    for bad in [[], [UInt8](repeating: 0, count: 23), [UInt8](repeating: 0, count: 25)] {
        #expect(throws: CryptoError.invalidLength) { try NaClSecretBox.seal([], nonce: bad, key: key) }
        #expect(throws: CryptoError.invalidLength) { try NaClSecretBox.open([UInt8](repeating: 0, count: 16), nonce: bad, key: key) }
        #expect(throws: CryptoError.invalidLength) { try XChaCha20Poly1305.seal([], key: key, nonce: bad, authenticating: []) }
        #expect(throws: CryptoError.invalidLength) { try XChaCha20Poly1305.open([UInt8](repeating: 0, count: 16), key: key, nonce: bad, authenticating: []) }
    }
    for length in [0, 1, 15] {
        let short = [UInt8](repeating: 0, count: length)
        #expect(throws: CryptoError.invalidLength) { try NaClSecretBox.open(short, nonce: nonce, key: key) }
        #expect(throws: CryptoError.invalidLength) { try XChaCha20Poly1305.open(short, key: key, nonce: nonce, authenticating: []) }
    }
    #expect(throws: CryptoError.invalidKey) { try NaClBox.sharedKey(privateKey: key, peerPublicKey: [UInt8](repeating: 0, count: 32)) }
    #expect(constantTimeEqual([], []))
    #expect(constantTimeEqual([1, 2], [1, 2]))
    #expect(!constantTimeEqual([1, 2], [1, 3]))
    #expect(!constantTimeEqual([1], [1, 0]))
}
