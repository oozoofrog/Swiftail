import CryptoKit
import Foundation
import Testing

@testable import SwiftailTKA

/// 서명 권한 상태 기계 시험이 함께 쓰는 도구. 키는 시험마다 그 자리에서 만든다.
enum AuthorityTesting {
    /// 첫 것으로 부트스트랩하고 나머지를 한 묶음으로 들인다(`tkafixtures`가 Authority를 만드는 방식).
    static func authority(_ aums: [AUM]) throws(TKAError) -> Authority {
        guard let first = aums.first else { throw .emptyUpdate }
        var authority = try Authority(bootstrappingWith: first)
        if aums.count > 1 { try authority.inform(Array(aums.dropFirst())) }
        return authority
    }

    /// 머리와 상태(키의 종류·`Votes`·공개 키·`Meta`, 끄기 값, StateID)가 Go가 적은 것과 같다.
    /// Go의 nil `Meta`와 빈 `Meta`는 인코딩에서 둘 다 빠지므로 같게 본다.
    static func expect(
        _ authority: Authority, matches expected: AuthorityFixtureFile.StateValue, _ label: String,
        sourceLocation: SourceLocation = #_sourceLocation
    ) {
        let state = authority.state
        #expect(ModelTesting.hex(authority.head.bytes) == expected.head, "\(label) 머리", sourceLocation: sourceLocation)
        #expect(state.lastAUMHash == authority.head, "\(label)", sourceLocation: sourceLocation)
        #expect(
            state.disablementValues.map(ModelTesting.hex) == (expected.disablementValues ?? []), "\(label) 끄기 값",
            sourceLocation: sourceLocation
        )
        #expect(String(state.stateID1) == expected.stateID1, "\(label) StateID1", sourceLocation: sourceLocation)
        #expect(String(state.stateID2) == expected.stateID2, "\(label) StateID2", sourceLocation: sourceLocation)
        let keys = expected.keys ?? []
        #expect(state.keys.count == keys.count, "\(label) 키 수", sourceLocation: sourceLocation)
        for (key, expectedKey) in zip(state.keys, keys) {
            #expect(key.kind == expectedKey.kind && key.votes == expectedKey.votes, "\(label)", sourceLocation: sourceLocation)
            #expect(key.publicKey.map(ModelTesting.hex) == expectedKey.public, "\(label) 공개 키", sourceLocation: sourceLocation)
            let meta = Dictionary(
                key.meta.map { (String(decoding: $0.key, as: UTF8.self), String(decoding: $0.value, as: UTF8.self)) },
                uniquingKeysWith: { first, _ in first }
            )
            #expect(meta == (expectedKey.meta ?? [:]), "\(label) Meta", sourceLocation: sourceLocation)
        }
    }

    // MARK: 서명한 AUM 만들기

    /// 신뢰 키 하나. CryptoKit의 서명은 결정적이지 않으므로 같은 AUM도 서명할 때마다 해시가 다르다.
    struct Signer {
        let privateKey = Curve25519.Signing.PrivateKey()
        var publicKey: [UInt8] { Array(privateKey.publicKey.rawRepresentation) }

        func trusted(votes: UInt64 = 1) -> TrustedKey {
            TrustedKey(kind: 1, votes: votes, publicKey: publicKey)
        }

        func signature(over aum: AUM) -> AUMSignature {
            // 시험 키로 32바이트에 서명하는 일은 실패하지 않는다. 실패하면 빈 서명이 되어 시험이 떨어진다.
            let signature = (try? privateKey.signature(for: aum.signatureHash)).map { Array($0) } ?? []
            return AUMSignature(keyID: publicKey, signature: signature)
        }
    }

    /// `signers`가 차례로 서명한 `aum`.
    static func signed(_ aum: AUM, by signers: [Signer]) -> AUM {
        var signed = aum
        signed.signatures += signers.map { $0.signature(over: aum) }
        return signed
    }

    /// 끄기 값 하나(32바이트)와 `keys`의 상태. StateID는 1·2다.
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

    /// `parent` 뒤에 `count`개의 NoOp을 잇는다.
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

    /// `inform`의 판정. 성공이면 nil, 아니면 오류.
    static func informError(_ authority: inout Authority, _ updates: [AUM]) -> TKAError? {
        do throws(TKAError) {
            try authority.inform(updates)
            return nil
        } catch {
            return error
        }
    }
}
