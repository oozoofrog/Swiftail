import Testing

@testable import SwiftailTKA

/// Static validation (contract behavior A1, §7 test 4, Go `AUM.StaticValidate`, `Key.StaticValidate`, and `staticValidateCheckpoint`).
@Suite("AUM static validation")
struct AUMValidationTests {
    static let key = TrustedKey(kind: 1, votes: 1, publicKey: [UInt8](repeating: 0x21, count: 32))
    static let keyID = [UInt8](repeating: 0x21, count: 32)
    static let signature = AUMSignature(keyID: keyID, signature: [UInt8](repeating: 0x5e, count: 64))

    static func checkpointState(disablementCount: Int = 1, keyCount: Int = 1) -> AuthorityState {
        AuthorityState(
            disablementValues: (0..<disablementCount).map { [UInt8](repeating: UInt8(truncatingIfNeeded: $0), count: 32) },
            keys: (0..<keyCount).map { index in
                TrustedKey(kind: 1, votes: 1, publicKey: [UInt8(index & 0xff), UInt8(index >> 8)] + [UInt8](repeating: 0, count: 30))
            }
        )
    }

    static func isValid(_ aum: AUM) -> Bool { (try? aum.validate()) != nil }

    @Test("Required and forbidden fields by kind")
    func kinds() {
        let state = Self.checkpointState()
        // AddKey requires Key and forbids KeyID, State, Votes, and Meta.
        #expect(Self.isValid(AUM(messageKind: 1, prevAUMHash: nil, key: Self.key)))
        #expect(!Self.isValid(AUM(messageKind: 1, prevAUMHash: nil)))
        #expect(!Self.isValid(AUM(messageKind: 1, prevAUMHash: nil, key: Self.key, keyID: Self.keyID)))
        #expect(!Self.isValid(AUM(messageKind: 1, prevAUMHash: nil, key: Self.key, keyID: [])))
        #expect(!Self.isValid(AUM(messageKind: 1, prevAUMHash: nil, key: Self.key, state: state)))
        #expect(!Self.isValid(AUM(messageKind: 1, prevAUMHash: nil, key: Self.key, votes: 0)))
        #expect(!Self.isValid(AUM(messageKind: 1, prevAUMHash: nil, key: Self.key, meta: [])))
        // RemoveKey requires nonempty KeyID and forbids Key, State, Votes, and Meta.
        #expect(Self.isValid(AUM(messageKind: 2, prevAUMHash: nil, keyID: [1])))
        #expect(!Self.isValid(AUM(messageKind: 2, prevAUMHash: nil)))
        #expect(!Self.isValid(AUM(messageKind: 2, prevAUMHash: nil, keyID: [])))
        #expect(!Self.isValid(AUM(messageKind: 2, prevAUMHash: nil, key: Self.key, keyID: [1])))
        #expect(!Self.isValid(AUM(messageKind: 2, prevAUMHash: nil, keyID: [1], state: state)))
        #expect(!Self.isValid(AUM(messageKind: 2, prevAUMHash: nil, keyID: [1], votes: 1)))
        #expect(!Self.isValid(AUM(messageKind: 2, prevAUMHash: nil, keyID: [1], meta: [])))
        // UpdateKey requires nonempty KeyID and at least one of Votes and Meta (an empty map counts), and forbids Key and State.
        #expect(Self.isValid(AUM(messageKind: 4, prevAUMHash: nil, keyID: [1], votes: 0)))
        #expect(Self.isValid(AUM(messageKind: 4, prevAUMHash: nil, keyID: [1], meta: [])))
        #expect(!Self.isValid(AUM(messageKind: 4, prevAUMHash: nil, keyID: [1])))
        #expect(!Self.isValid(AUM(messageKind: 4, prevAUMHash: nil, keyID: [], votes: 1)))
        #expect(!Self.isValid(AUM(messageKind: 4, prevAUMHash: nil, key: Self.key, keyID: [1], votes: 1)))
        #expect(!Self.isValid(AUM(messageKind: 4, prevAUMHash: nil, keyID: [1], state: state, votes: 1)))
        // Checkpoint requires State and forbids KeyID, Key, Votes, and Meta.
        #expect(Self.isValid(AUM(messageKind: 5, prevAUMHash: nil, state: state)))
        #expect(!Self.isValid(AUM(messageKind: 5, prevAUMHash: nil)))
        #expect(!Self.isValid(AUM(messageKind: 5, prevAUMHash: nil, keyID: [], state: state)))
        #expect(!Self.isValid(AUM(messageKind: 5, prevAUMHash: nil, key: Self.key, state: state)))
        #expect(!Self.isValid(AUM(messageKind: 5, prevAUMHash: nil, state: state, votes: 1)))
        #expect(!Self.isValid(AUM(messageKind: 5, prevAUMHash: nil, state: state, meta: [])))
        // NoOp and kinds 0 and 6 or higher have no kind-specific checks.
        for kind: UInt8 in [0, 3, 6, 9, 255] {
            #expect(Self.isValid(AUM(messageKind: kind, prevAUMHash: nil, keyID: [], votes: 7, meta: [])), "\(kind)")
        }
    }

    @Test("Key: Votes 1–4,096, Meta 512 bytes, and kind 1. Checks regardless of kind")
    func keyLimits() {
        func addKey(_ key: TrustedKey) -> Bool { Self.isValid(AUM(messageKind: 1, prevAUMHash: nil, key: key)) }
        for (votes, valid) in [(0, false), (1, true), (4_096, true), (4_097, false)] as [(UInt64, Bool)] {
            var key = Self.key
            key.votes = votes
            #expect(addKey(key) == valid, "\(votes)")
        }
        for (count, valid) in [(512, true), (513, false)] {
            var key = Self.key
            key.meta = [MetaEntry(key: [0x6b], value: [UInt8](repeating: 0x76, count: count - 1))]
            #expect(addKey(key) == valid, "\(count)")
        }
        for kind: UInt8 in [0, 2, 255] {
            var key = Self.key
            key.kind = kind
            #expect(!addKey(key), "\(kind)")
        }
        // Public key length is not checked.
        for publicKey: [UInt8]? in [nil, [], [1], [UInt8](repeating: 1, count: 33)] {
            var key = Self.key
            key.publicKey = publicKey
            #expect(addKey(key))
        }
        var badKey = Self.key
        badKey.votes = 0
        #expect(!Self.isValid(AUM(messageKind: 3, prevAUMHash: nil, key: badKey)))
    }

    @Test("Signatures: 32-byte KeyID and 64-byte signature")
    func signatures() {
        func noOp(keyIDCount: Int, signatureCount: Int) -> Bool {
            let signature = AUMSignature(
                keyID: [UInt8](repeating: 1, count: keyIDCount), signature: [UInt8](repeating: 2, count: signatureCount)
            )
            return Self.isValid(AUM(messageKind: 3, prevAUMHash: nil, signatures: [Self.signature, signature]))
        }
        #expect(noOp(keyIDCount: 32, signatureCount: 64))
        #expect(!noOp(keyIDCount: 31, signatureCount: 64))
        #expect(!noOp(keyIDCount: 33, signatureCount: 64))
        #expect(!noOp(keyIDCount: 32, signatureCount: 63))
        #expect(!noOp(keyIDCount: 32, signatureCount: 65))
    }

    @Test("PrevAUMHash rejects length 0 and accepts null and other lengths")
    func prevAUMHash() {
        #expect(Self.isValid(AUM(messageKind: 3, prevAUMHash: nil)))
        #expect(!Self.isValid(AUM(messageKind: 3, prevAUMHash: [])))
        #expect(Self.isValid(AUM(messageKind: 3, prevAUMHash: [1])))
        #expect(Self.isValid(AUM(messageKind: 3, prevAUMHash: [UInt8](repeating: 1, count: 33))))
    }

    @Test("Checkpoint state: 1–32 distinct 32-byte disablement values, 1–512 distinct valid keys, and no LastAUMHash")
    func checkpointState() throws {
        func checkpoint(_ state: AuthorityState) -> Bool { Self.isValid(AUM(messageKind: 5, prevAUMHash: nil, state: state)) }
        for (count, valid) in [(0, false), (1, true), (32, true), (33, false)] {
            #expect(checkpoint(Self.checkpointState(disablementCount: count)) == valid, "Disablement values \(count)")
        }
        for (count, valid) in [(0, false), (1, true), (512, true), (513, false)] {
            #expect(checkpoint(Self.checkpointState(keyCount: count)) == valid, "Keys \(count)")
        }
        var state = Self.checkpointState(disablementCount: 2)
        state.disablementValues[1] = state.disablementValues[0]
        #expect(!checkpoint(state))
        for count in [31, 33] {
            state = Self.checkpointState()
            state.disablementValues[0] = [UInt8](repeating: 0, count: count)
            #expect(!checkpoint(state))
        }
        state = Self.checkpointState(keyCount: 2)
        state.keys[1].publicKey = state.keys[0].publicKey
        state.keys[1].votes = 9
        #expect(!checkpoint(state))
        // A null public key and an empty public key are the same key by KeyID (behavior E6).
        state = Self.checkpointState(keyCount: 2)
        state.keys[0].publicKey = nil
        state.keys[1].publicKey = []
        #expect(!checkpoint(state))
        state = Self.checkpointState()
        state.keys[0].votes = 0
        #expect(!checkpoint(state))
        state = Self.checkpointState()
        state.lastAUMHash = AUMHash([UInt8](repeating: 0, count: 32))
        #expect(!checkpoint(state))
        // Checks State whenever present, regardless of kind.
        #expect(!Self.isValid(AUM(messageKind: 3, prevAUMHash: nil, state: Self.checkpointState(keyCount: 0))))
    }

    @Test("Top-level null is an AUM with all zero-valued fields and passes static validation (behavior D7)")
    func topLevelNull() throws {
        for hex in ["f6", "f7"] {
            let aum = try ModelTesting.decodeAUM(hex).get()
            #expect(aum == AUM(messageKind: 0, prevAUMHash: nil))
            #expect(ModelTesting.hex(aum.serialized()) == "a2010002f6")
            try aum.validate()
        }
        for hex in ["80", "00", "40", "60", "f5"] {
            #expect(throws: TKAError.invalidStructure, "\(hex)") { try ModelTesting.decodeAUM(hex).get() }
        }
    }
}
