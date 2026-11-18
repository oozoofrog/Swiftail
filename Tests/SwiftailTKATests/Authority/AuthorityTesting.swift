import CryptoKit
import Foundation
import Testing

@testable import SwiftailTKA

/// Shared support for signing authority state machine tests. Each test generates its own keys on demand.
enum AuthorityTesting {
    /// Bootstraps with the first AUM and admits the rest in a group, as `tkafixtures` builds an Authority.
    static func authority(_ aums: [AUM]) throws(TKAError) -> Authority {
        guard let first = aums.first else { throw .emptyUpdate }
        var authority = try Authority(bootstrappingWith: first)
        if aums.count > 1 { try authority.inform(Array(aums.dropFirst())) }
        return authority
    }

    /// Checks that the head and state (key type, `Votes`, public key, `Meta`, disablement values, and StateID) match Go's output.
    /// Treats Go's nil and empty `Meta` as equivalent because encoding omits both.
    static func expect(
        _ authority: Authority, matches expected: AuthorityFixtureFile.StateValue, _ label: String,
        sourceLocation: SourceLocation = #_sourceLocation
    ) {
        let state = authority.state
        #expect(ModelTesting.hex(authority.head.bytes) == expected.head, "\(label) head", sourceLocation: sourceLocation)
        #expect(state.lastAUMHash == authority.head, "\(label)", sourceLocation: sourceLocation)
        #expect(
            state.disablementValues.map(ModelTesting.hex) == (expected.disablementValues ?? []), "\(label) disablement values",
            sourceLocation: sourceLocation
        )
        #expect(String(state.stateID1) == expected.stateID1, "\(label) StateID1", sourceLocation: sourceLocation)
        #expect(String(state.stateID2) == expected.stateID2, "\(label) StateID2", sourceLocation: sourceLocation)
        let keys = expected.keys ?? []
        #expect(state.keys.count == keys.count, "\(label) key count", sourceLocation: sourceLocation)
        for (key, expectedKey) in zip(state.keys, keys) {
            #expect(key.kind == expectedKey.kind && key.votes == expectedKey.votes, "\(label)", sourceLocation: sourceLocation)
            #expect(key.publicKey.map(ModelTesting.hex) == expectedKey.public, "\(label) public key", sourceLocation: sourceLocation)
            let meta = Dictionary(
                key.meta.map { (String(decoding: $0.key, as: UTF8.self), String(decoding: $0.value, as: UTF8.self)) },
                uniquingKeysWith: { first, _ in first }
            )
            #expect(meta == (expectedKey.meta ?? [:]), "\(label) Meta", sourceLocation: sourceLocation)
        }
    }

    // MARK: Creating signed AUMs

    /// One trusted key. CryptoKit signatures are nondeterministic, so signing the same AUM again changes its hash.
    struct Signer {
        let privateKey = Curve25519.Signing.PrivateKey()
        var publicKey: [UInt8] { Array(privateKey.publicKey.rawRepresentation) }

        func trusted(votes: UInt64 = 1) -> TrustedKey {
            TrustedKey(kind: 1, votes: votes, publicKey: publicKey)
        }

        func signature(over aum: AUM) -> AUMSignature {
            // Signing 32 bytes with a test key is expected to succeed. Failure yields an empty signature and fails the test.
            let signature = (try? privateKey.signature(for: aum.signatureHash)).map { Array($0) } ?? []
            return AUMSignature(keyID: publicKey, signature: signature)
        }
    }

    /// The `aum` signed in order by `signers`.
    static func signed(_ aum: AUM, by signers: [Signer]) -> AUM {
        var signed = aum
        signed.signatures += signers.map { $0.signature(over: aum) }
        return signed
    }

    /// A state with one disablement value (32 bytes) and `keys`. The StateID values are 1 and 2.
    static func checkpointState(_ keys: [TrustedKey], stateID1: UInt64 = 1) -> AuthorityState {
        AuthorityState(disablementValues: [Array(repeating: 0xd1, count: 32)], keys: keys, stateID1: stateID1, stateID2: 2)
    }

    static func checkpoint(_ state: AuthorityState, parent: AUMHash? = nil, by signers: [Signer]) -> AUM {
        signed(AUM(messageKind: AUM.Kind.checkpoint, prevAUMHash: parent?.bytes, state: state), by: signers)
    }

    static func noOp(after parent: AUMHash, by signers: [Signer]) -> AUM {
        signed(AUM(messageKind: AUM.Kind.noOp, prevAUMHash: parent.bytes), by: signers)
    }

    static func addKey(_ key: TrustedKey, after parent: AUMHash, by signers: [Signer]) -> AUM {
        signed(AUM(messageKind: AUM.Kind.addKey, prevAUMHash: parent.bytes, key: key), by: signers)
    }

    static func removeKey(_ keyID: [UInt8], after parent: AUMHash, by signers: [Signer]) -> AUM {
        signed(AUM(messageKind: AUM.Kind.removeKey, prevAUMHash: parent.bytes, keyID: keyID), by: signers)
    }

    /// Links `count` NoOps after `parent`.
    static func noOpChain(after parent: AUMHash, count: Int, by signer: Signer) -> [AUM] {
        var chain: [AUM] = []
        var parent = parent
        for _ in 0..<count {
            let next = noOp(after: parent, by: [signer])
            chain.append(next)
            parent = next.hash
        }
        return chain
    }

    /// The active chain in reverse from head through root, head first.
    static func activeChain(of authority: Authority) -> [AUM] {
        var chain: [AUM] = []
        var cursor: AUMHash? = authority.head
        while let hash = cursor, let position = authority.positions[hash] {
            chain.append(authority.aums[position])
            cursor = hash == authority.bootstrap ? nil : authority.aums[position].parentHash
        }
        return chain
    }

    /// The total number of canonical bytes.
    static func byteCount(_ aums: [AUM]) -> Int {
        aums.reduce(0) { $0 + $1.serialized().count }
    }

    /// The `inform` outcome, nil on success or the error on failure.
    static func informError(_ authority: inout Authority, _ updates: [AUM]) -> TKAError? {
        do throws(TKAError) {
            try authority.inform(updates)
            return nil
        } catch {
            return error
        }
    }
}
