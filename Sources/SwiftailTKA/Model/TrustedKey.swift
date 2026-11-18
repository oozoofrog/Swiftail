// A key with signing authority (Go `tka.Key`, `tailscale.com/tka/key.go:36-132`). Notes §3.2, contract behaviors E4, D5, and A1.
// Copyright (c) Tailscale Inc & contributors. BSD-3-Clause.

/// A key with signing authority. The KeyID is the raw `publicKey` bytes (notes §3.2).
package struct TrustedKey: Sendable, Equatable {
    /// 1 = `Key25519`. Static checks accept only 1.
    package var kind: UInt8
    /// The fork resolution weight. Static checks accept only 1–4,096.
    package var votes: UInt64
    /// nil is CBOR null. It is distinguished from an empty byte string because the encodings differ (behavior E4). Static checks do not inspect length.
    package var publicKey: [UInt8]?
    /// Canonical order. Omitted from encoding if empty (omitempty).
    package var meta: [MetaEntry] = []

    /// `Key25519` (notes §3.2).
    static let ed25519Kind: UInt8 = 1
    /// The `Votes` limit (Go `Key.StaticValidate`).
    static let maximumVotes: UInt64 = 4_096
    /// The limit on the combined length of `Meta` keys and values (Go `maxMetaBytes`).
    static let maximumMetaByteCount = 512

    /// The KeyID (Go `Key.ID`), or nil for a kind other than `Key25519`.
    var keyID: [UInt8]? { kind == Self.ed25519Kind ? publicKey ?? [] : nil }

    /// Go `Key.StaticValidate`: `Votes` from 1 to 4,096, `Meta` at most 512 bytes, and kind `Key25519` (behavior A1).
    package func validate() throws(TKAError) {
        guard (1...Self.maximumVotes).contains(votes), meta.byteCount <= Self.maximumMetaByteCount, kind == Self.ed25519Kind
        else { throw .invalidAUM }
    }
}

// MARK: CBOR

extension TrustedKey {
    private enum Field {
        static let kind: UInt64 = 1
        static let votes: UInt64 = 2
        static let publicKey: UInt64 = 3
        static let meta: UInt64 = 12
    }

    /// Reads an integer-keyed map. Absent and null fields become zero values as in Go (behavior D5). Null in place of the map yields a zero-value key.
    init(field value: CBORValue) throws(TKAError) {
        let fields = try StructureFields(value, knownKeys: [Field.kind, Field.votes, Field.publicKey, Field.meta])
        kind = UInt8(truncatingIfNeeded: try fields[Field.kind]?.unsignedField(maximum: UInt64(UInt8.max)) ?? 0)
        votes = try fields[Field.votes]?.unsignedField() ?? 0
        publicKey = try fields[Field.publicKey]?.byteField()
        meta = try fields[Field.meta]?.metaField() ?? []
    }

    /// Always writes `Kind`, `Votes`, and `Public`. Writes `Meta` only when nonempty (behavior E4).
    func write(to writer: inout CBORWriter) {
        writer.mapHeader(count: meta.isEmpty ? 3 : 4)
        writer.unsigned(Field.kind)
        writer.unsigned(UInt64(kind))
        writer.unsigned(Field.votes)
        writer.unsigned(votes)
        writer.unsigned(Field.publicKey)
        writer.optionalByteString(publicKey)
        if !meta.isEmpty {
            writer.unsigned(Field.meta)
            writer.meta(meta)
        }
    }
}

extension CBORWriter {
    /// Writes null for nil or a byte string otherwise (a `[]byte` field without omitempty, behavior E4).
    mutating func optionalByteString(_ value: [UInt8]?) {
        if let value { byteString(value) } else { null() }
    }
}
