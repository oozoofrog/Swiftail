// A signature over a node key (Go `tka.NodeKeySignature`, `tailscale.com/tka/sig.go:74-242`). Notes §§3.6 and 3.7, contract behaviors E2, E4, E5, D, and M.
// Copyright (c) Tailscale Inc & contributors. BSD-3-Clause.

/// A node key signature (NKS). `Authority` verifies it (behavior S). This type handles reading, canonical writing, and `SigHash`.
///
/// All byte fields use omitempty, so nil and empty values are treated alike (notes §3.6).
package struct NodeKeySignature: Sendable, Equatable {
    /// 1 direct, 2 rotation, 3 credential(`Kind`).
    package var kind: UInt8
    /// `"np"` ‖ 32 bytes of node public key. credential leaves it empty.
    package var publicKey: [UInt8]
    /// The KeyID of the trusted signing key. Only direct and credential use it.
    package var keyID: [UInt8]
    /// The Ed25519 signature. The input is `signatureHash`.
    package var signature: [UInt8]
    /// The Ed25519 public key used to verify a signature that wraps this one.
    package var wrappingPublicKey: [UInt8]
    /// The slot for `Nested`. A value type cannot contain itself directly, so an `indirect` enum stores it.
    private var nestedLink: Link?

    /// The signature wrapped by rotation.
    package var nested: NodeKeySignature? {
        get {
            guard case .signature(let signature) = nestedLink else { return nil }
            return signature
        }
        set { nestedLink = newValue.map(Link.signature) }
    }

    private indirect enum Link: Sendable, Equatable {
        case signature(NodeKeySignature)
    }

    /// The byte limit per NKS (behavior M, a Swiftail choice. 16 layers take about 3KiB).
    static let maximumByteCount = 8 * 1_024

    /// `SigKind` values (notes §3.6).
    enum Kind {
        static let invalid: UInt8 = 0
        static let direct: UInt8 = 1
        static let rotation: UInt8 = 2
        static let credential: UInt8 = 3
    }

    init(
        kind: UInt8, publicKey: [UInt8] = [], keyID: [UInt8] = [], signature: [UInt8] = [],
        nested: NodeKeySignature? = nil, wrappingPublicKey: [UInt8] = []
    ) {
        self.kind = kind
        self.publicKey = publicKey
        self.keyID = keyID
        self.signature = signature
        self.wrappingPublicKey = wrappingPublicKey
        self.nested = nested
    }

    /// Reads under the limit (8KiB) and the rules in behavior D. Does not verify the signature.
    package init(decoding bytes: [UInt8]) throws(TKAError) {
        try self.init(item: decodeItem(bytes, maximumByteCount: Self.maximumByteCount))
    }

    /// Canonical CBOR (behaviors E1–E4). These bytes go in `RegisterRequest` and `Node.KeySignature`.
    package func serialized() -> [UInt8] {
        var writer = CBORWriter()
        write(to: &writer)
        return writer.bytes
    }

    /// The BLAKE2s-256 of the canonical bytes without `Signature`. `Nested` is included unchanged, including its signature (notes §3.7).
    package var signatureHash: [UInt8] {
        var unsigned = self
        unsigned.signature = []
        return AUMHash(hashing: unsigned.serialized()).bytes
    }
}

// MARK: CBOR

extension NodeKeySignature {
    private enum Field {
        static let kind: UInt64 = 1
        static let publicKey: UInt64 = 2
        static let keyID: UInt64 = 3
        static let signature: UInt64 = 4
        static let nested: UInt64 = 5
        static let wrappingPublicKey: UInt64 = 6
    }

    /// The CBOR nesting limit (16 levels) bounds recursion depth.
    private init(item: CBORValue) throws(TKAError) {
        let fields = try StructureFields(
            item,
            knownKeys: [Field.kind, Field.publicKey, Field.keyID, Field.signature, Field.nested, Field.wrappingPublicKey]
        )
        var nested: NodeKeySignature?
        // Null pointer fields are absent.
        if let value = fields[Field.nested], value != .null {
            nested = try NodeKeySignature(item: value)
        }
        self.init(
            kind: UInt8(truncatingIfNeeded: try fields[Field.kind]?.unsignedField(maximum: UInt64(UInt8.max)) ?? 0),
            publicKey: try fields[Field.publicKey]?.byteField() ?? [],
            keyID: try fields[Field.keyID]?.byteField() ?? [],
            signature: try fields[Field.signature]?.byteField() ?? [],
            nested: nested,
            wrappingPublicKey: try fields[Field.wrappingPublicKey]?.byteField() ?? []
        )
    }

    /// Writes in key order. Always writes `SigKind` and writes the rest only when nonempty (behavior E4).
    private func write(to writer: inout CBORWriter) {
        let nested = nested
        let present = [!publicKey.isEmpty, !keyID.isEmpty, !signature.isEmpty, nested != nil, !wrappingPublicKey.isEmpty]
        writer.mapHeader(count: 1 + present.count(where: \.self))
        writer.unsigned(Field.kind)
        writer.unsigned(UInt64(kind))
        if !publicKey.isEmpty {
            writer.unsigned(Field.publicKey)
            writer.byteString(publicKey)
        }
        if !keyID.isEmpty {
            writer.unsigned(Field.keyID)
            writer.byteString(keyID)
        }
        if !signature.isEmpty {
            writer.unsigned(Field.signature)
            writer.byteString(signature)
        }
        if let nested {
            writer.unsigned(Field.nested)
            nested.write(to: &writer)
        }
        if !wrappingPublicKey.isEmpty {
            writer.unsigned(Field.wrappingPublicKey)
            writer.byteString(wrappingPublicKey)
        }
    }
}
