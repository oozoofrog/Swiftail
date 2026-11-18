// A message that changes signing authority state (Go `tka.AUM`, `tailscale.com/tka/aum.go:132-288`). Notes §§3.4 and 3.7, contract behaviors E2–E6, D3–D9, and A1.
// Copyright (c) Tailscale Inc & contributors. BSD-3-Clause.

/// A message that changes signing authority state (Authority Update Message).
///
/// Does not retain received bytes. Hashing and signature verification use this value's reencoded canonical bytes (behavior E5). Unknown fields,
/// non-shortest integers, and unsorted keys are accepted. Reencoding drops unknown fields and canonicalizes integer encodings and key order before hashing.
package struct AUM: Sendable, Equatable {
    /// The kind (`Kind`). Also accepts 0 and values at least 6 (notes §3.4).
    package var messageKind: UInt8
    /// nil means no parent and encodes as null. A zero-length byte string encodes differently and fails static checks (behaviors E4 and A1).
    package var prevAUMHash: [UInt8]?
    /// The key added by AddKey. Static checks require nil for RemoveKey, UpdateKey, and Checkpoint.
    package var key: TrustedKey? = nil
    /// Both nil and empty byte strings are omitted from encoding (omitempty), but static checks distinguish them. AddKey and Checkpoint accept only nil
    /// (Go `aum.go:189` and `:207`, `a.KeyID != nil`).
    package var keyID: [UInt8]? = nil
    /// The complete state carried by Checkpoint. Static checks require nil for AddKey, RemoveKey, and UpdateKey.
    package var state: AuthorityState? = nil
    /// Encodes a present value even if 0 (Go `*uint`, omitempty).
    package var votes: UInt64? = nil
    /// nil and an empty map differ only in validation. Encoding omits both.
    package var meta: [MetaEntry]? = nil
    /// Trusted key signatures. They are included in `hash` and omitted from the signing input `signatureHash`, so repeating a signature or reordering the
    /// list produces a "valid" AUM with a different hash (contract §5 TL-11a item 1).
    package var signatures: [AUMSignature] = []

    /// The byte limit per AUM (behavior M, a Swiftail choice).
    static let maximumByteCount = 512 * 1_024

    /// `MessageKind` values (Go `AUMKind`, notes §3.4).
    enum Kind {
        static let invalid: UInt8 = 0
        static let addKey: UInt8 = 1
        static let removeKey: UInt8 = 2
        static let noOp: UInt8 = 3
        static let updateKey: UInt8 = 4
        static let checkpoint: UInt8 = 5
    }

    /// Canonical CBOR (behaviors E1–E4). `hash` uses these bytes. `signatureHash` uses canonical CBOR without `Signatures` (behavior E5).
    package func serialized() -> [UInt8] {
        var writer = CBORWriter()
        write(to: &writer, includingSignatures: true)
        return writer.bytes
    }

    /// BLAKE2s-256(`serialized()`). Includes signatures (notes §3.7).
    package var hash: AUMHash { AUMHash(hashing: serialized()) }

    /// The BLAKE2s-256 of the canonical bytes without `Signatures`. Signatures cover these 32 bytes (notes §3.7).
    package var signatureHash: [UInt8] {
        var writer = CBORWriter()
        write(to: &writer, includingSignatures: false)
        return AUMHash(hashing: writer.bytes).bytes
    }

    /// Implements Go's `AUM.StaticValidate` checks (behavior A1). `Authority` checks signatures and parents separately (behaviors A2 and A3).
    package func validate() throws(TKAError) {
        try key?.validate()
        if let prevAUMHash, prevAUMHash.isEmpty { throw .invalidAUM }
        guard signatures.allSatisfy({ $0.keyID.count == 32 && $0.signature.count == 64 }) else { throw .invalidAUM }
        try state?.validateAsCheckpoint()

        let isValid =
            switch messageKind {
            case Kind.addKey:
                key != nil && keyID == nil && state == nil && votes == nil && meta == nil
            case Kind.removeKey:
                !(keyID ?? []).isEmpty && key == nil && state == nil && votes == nil && meta == nil
            case Kind.updateKey:
                !(keyID ?? []).isEmpty && (votes != nil || meta != nil) && key == nil && state == nil
            case Kind.checkpoint:
                state != nil && keyID == nil && key == nil && votes == nil && meta == nil
            default:
                // NoOp and unknown kinds have no kind-specific checks (Go's contract lets older clients ignore them).
                true
            }
        guard isValid else { throw .invalidAUM }
    }
}

// MARK: CBOR

extension AUM {
    /// Decodes under the limits in behavior M and rules in behavior D. Does not run static checks. Lives in an extension to preserve the memberwise initializer.
    package init(decoding bytes: [UInt8]) throws(TKAError) {
        try self.init(item: decodeItem(bytes, maximumByteCount: Self.maximumByteCount))
    }

    private enum Field {
        static let messageKind: UInt64 = 1
        static let prevAUMHash: UInt64 = 2
        static let key: UInt64 = 3
        static let keyID: UInt64 = 4
        static let state: UInt64 = 5
        static let votes: UInt64 = 6
        static let meta: UInt64 = 7
        static let signatures: UInt64 = 23
    }

    private init(item: CBORValue) throws(TKAError) {
        let fields = try StructureFields(
            item,
            knownKeys: [
                Field.messageKind, Field.prevAUMHash, Field.key, Field.keyID, Field.state, Field.votes, Field.meta,
                Field.signatures,
            ]
        )
        messageKind = UInt8(
            truncatingIfNeeded: try fields[Field.messageKind]?.unsignedField(maximum: UInt64(UInt8.max)) ?? 0
        )
        prevAUMHash = try fields[Field.prevAUMHash]?.byteField()
        // Null pointer fields (`Key`, `State`, and `Votes`) are absent.
        if let value = fields[Field.key], value != .null {
            key = try TrustedKey(field: value)
        }
        keyID = try fields[Field.keyID]?.byteField()
        if let value = fields[Field.state], value != .null {
            state = try AuthorityState(checkpointField: value)
        }
        if let value = fields[Field.votes], value != .null {
            votes = try value.unsignedField()
        }
        meta = try fields[Field.meta]?.metaField()
        for element in try fields[Field.signatures]?.arrayField() ?? [] {
            signatures.append(try AUMSignature(element: element))
        }
    }

    /// Writes in key order (behavior E2). Always writes `MessageKind` and `PrevAUMHash` and writes other fields only when present (`Key`, `State`, `Votes`) or nonempty (`KeyID`, `Meta`, `Signatures`), subject to `includingSignatures` (behavior E4).
    private func write(to writer: inout CBORWriter, includingSignatures: Bool) {
        let keyID = keyID ?? []
        let meta = meta ?? []
        let signatures = includingSignatures ? signatures : []
        let present = [key != nil, !keyID.isEmpty, state != nil, votes != nil, !meta.isEmpty, !signatures.isEmpty]
        writer.mapHeader(count: 2 + present.count(where: \.self))

        writer.unsigned(Field.messageKind)
        writer.unsigned(UInt64(messageKind))
        writer.unsigned(Field.prevAUMHash)
        writer.optionalByteString(prevAUMHash)
        if let key {
            writer.unsigned(Field.key)
            key.write(to: &writer)
        }
        if !keyID.isEmpty {
            writer.unsigned(Field.keyID)
            writer.byteString(keyID)
        }
        if let state {
            writer.unsigned(Field.state)
            state.write(to: &writer)
        }
        if let votes {
            writer.unsigned(Field.votes)
            writer.unsigned(votes)
        }
        if !meta.isEmpty {
            writer.unsigned(Field.meta)
            writer.meta(meta)
        }
        if !signatures.isEmpty {
            writer.unsigned(Field.signatures)
            writer.arrayHeader(count: signatures.count)
            for signature in signatures {
                signature.write(to: &writer)
            }
        }
    }
}
