// Trust state (Go `tka.State`, `tailscale.com/tka/state.go:26-53`, `:258-316`). Notes §3.5, contract behaviors E4, E6, D8, and A1.
// Copyright (c) Tailscale Inc & contributors. BSD-3-Clause.

/// Trust state after applying updates through a given AUM. A checkpoint AUM carries this entire state.
///
/// Does not distinguish nil and empty arrays or nil elements and empty byte strings. In an accepted checkpoint, arrays are nonempty and their elements
/// contain 32 bytes (behavior E6).
package struct AuthorityState: Sendable, Equatable {
    /// The hash of the last applied AUM. Always nil in checkpoint state (behavior D8).
    package var lastAUMHash: AUMHash?
    /// The disablement secrets' KDF values (32 bytes each).
    package var disablementValues: [[UInt8]] = []
    /// The trusted keys, in lookup order. A KeyID lookup starts from the beginning (Go `GetKey`).
    package var keys: [TrustedKey] = []
    /// A random value chosen when enabling lock. Omitted from encoding if 0 (omitempty).
    package var stateID1: UInt64 = 0
    /// Identifies the tailnet's lock together with `stateID1`. A checkpoint applies only if both values match the parent state. Omitted from encoding if 0.
    package var stateID2: UInt64 = 0

    /// The maximum disablement value count and their length (Go `maxDisablementValues` and `disablementLength`).
    static let maximumDisablementValueCount = 32
    static let disablementValueByteCount = 32
    /// The maximum key count (Go `maxKeys`).
    static let maximumKeyCount = 512

    /// Statically checks state for a checkpoint (Go `staticValidateCheckpoint`, behavior A1). Requires no `LastAUMHash`, 1–32 distinct disablement values of 32 bytes each,
    /// and 1–512 keys that each pass validation and have distinct KeyIDs.
    func validateAsCheckpoint() throws(TKAError) {
        guard lastAUMHash == nil,
            (1...Self.maximumDisablementValueCount).contains(disablementValues.count),
            disablementValues.allSatisfy({ $0.count == Self.disablementValueByteCount }),
            Set(disablementValues).count == disablementValues.count,
            (1...Self.maximumKeyCount).contains(keys.count)
        else { throw .invalidAUM }
        var keyIDs: Set<[UInt8]> = []
        for key in keys {
            try key.validate()
            // A validated key is `Key25519` and therefore has a KeyID.
            guard let keyID = key.keyID, keyIDs.insert(keyID).inserted else { throw .invalidAUM }
        }
    }
}

// MARK: CBOR

extension AuthorityState {
    private enum Field {
        static let lastAUMHash: UInt64 = 1
        static let disablementValues: UInt64 = 2
        static let keys: UInt64 = 3
        static let stateID1: UInt64 = 4
        static let stateID2: UInt64 = 5
    }

    /// Reads `State` from a checkpoint AUM. Rejects a non-null `LastAUMHash` (behavior D8, a Swiftail choice).
    ///
    /// Go reads byte strings of any length into the 32-byte slot and rejects them during static checks. The decision to reject the AUM is the same.
    init(checkpointField value: CBORValue) throws(TKAError) {
        let fields = try StructureFields(
            value,
            knownKeys: [Field.lastAUMHash, Field.disablementValues, Field.keys, Field.stateID1, Field.stateID2]
        )
        guard (fields[Field.lastAUMHash] ?? .null) == .null else { throw .invalidStructure }
        var disablementValues: [[UInt8]] = []
        for element in try fields[Field.disablementValues]?.arrayField() ?? [] {
            disablementValues.append(try element.byteField() ?? [])
        }
        var keys: [TrustedKey] = []
        for element in try fields[Field.keys]?.arrayField() ?? [] {
            // A null element becomes a zero-value key as in Go (`fillNil`). It fails static checks.
            keys.append(try TrustedKey(field: element))
        }
        self.init(
            lastAUMHash: nil,
            disablementValues: disablementValues,
            keys: keys,
            stateID1: try fields[Field.stateID1]?.unsignedField() ?? 0,
            stateID2: try fields[Field.stateID2]?.unsignedField() ?? 0
        )
    }

    /// Always writes `LastAUMHash` (null if absent), `DisablementValues`, and `Keys`. Writes `StateID1/2` only if nonzero (behavior E4).
    func write(to writer: inout CBORWriter) {
        writer.mapHeader(count: 3 + (stateID1 == 0 ? 0 : 1) + (stateID2 == 0 ? 0 : 1))
        writer.unsigned(Field.lastAUMHash)
        writer.optionalByteString(lastAUMHash?.bytes)
        writer.unsigned(Field.disablementValues)
        writer.arrayHeader(count: disablementValues.count)
        for value in disablementValues {
            writer.byteString(value)
        }
        writer.unsigned(Field.keys)
        writer.arrayHeader(count: keys.count)
        for key in keys {
            key.write(to: &writer)
        }
        if stateID1 != 0 {
            writer.unsigned(Field.stateID1)
            writer.unsigned(stateID1)
        }
        if stateID2 != 0 {
            writer.unsigned(Field.stateID2)
            writer.unsigned(stateID2)
        }
    }
}
