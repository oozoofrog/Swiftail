// A signature attached to an AUM (Go `tkatype.Signature`, `tailscale.com/types/tkatype/tkatype.go:35-40`). Notes §3.3.
// Copyright (c) Tailscale Inc & contributors. BSD-3-Clause.

/// One signature attached to an AUM. The signing input is that AUM's `signatureHash` (notes §3.7).
///
/// Go encodes nil and an empty slice differently as null and an empty byte string. Static checks accept only 32 and 64 bytes, so this type does not distinguish them
/// (behavior E6: AUMs where the difference matters are rejected).
package struct AUMSignature: Sendable, Hashable {
    /// The KeyID of the trusted signing key. Static checks accept exactly 32 bytes.
    package var keyID: [UInt8]
    /// The Ed25519 signature. Static checks accept exactly 64 bytes.
    package var signature: [UInt8]
}

// MARK: CBOR

extension AUMSignature {
    private enum Field {
        static let keyID: UInt64 = 1
        static let signature: UInt64 = 2
    }

    /// Reads an integer-keyed map. A null array element becomes the zero value (an empty signature), as in Go (`fillNil`).
    init(element value: CBORValue) throws(TKAError) {
        let fields = try StructureFields(value, knownKeys: [Field.keyID, Field.signature])
        self.init(
            keyID: try fields[Field.keyID]?.byteField() ?? [],
            signature: try fields[Field.signature]?.byteField() ?? []
        )
    }

    /// Always writes both fields, without omitempty (behavior E4).
    func write(to writer: inout CBORWriter) {
        writer.mapHeader(count: 2)
        writer.unsigned(Field.keyID)
        writer.byteString(keyID)
        writer.unsigned(Field.signature)
        writer.byteString(signature)
    }
}
