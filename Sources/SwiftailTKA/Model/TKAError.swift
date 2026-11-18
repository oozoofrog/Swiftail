// Tailnet Lock rejection reasons. Declared in contract `docs/contracts/SwiftailTailnetLock.md` §2.

/// Reasons for rejecting TKA data during reading or verification. Distinguishes the stage of rejection and omits contents such as keys or bytes (behavior K5).
package enum TKAError: Error, Sendable, Equatable {
    /// Rejection at the CBOR item level (behavior D1).
    case cbor(CBORError)
    /// Valid CBOR with an invalid structure: a non-map top level, an unsupported key type, duplicate keys, known field type or range violations,
    /// invalid UTF-8, or non-null `LastAUMHash` in checkpoint `State` (behaviors D3–D8).
    case invalidStructure
    /// Failed a static check (`StaticValidate` or checkpoint state checks, behavior A1).
    case invalidAUM
    case emptyUpdate
    case missingParent
    case unsigned
    case untrustedSigner
    case invalidSignature
    /// Application failure: parent hash mismatch, an existing or missing key, removal of the last key, StateID mismatch, or failed validation of an updated key.
    case rejectedUpdate
    case notACheckpoint
    /// Stored AUMs do not form a chain (behavior T3).
    case corruptStore
    case iterationLimit
    case noIntersection
    /// The node key is not authorized (at any stage of behavior S).
    case unauthorized
    /// The suffix after `--TL` violates behavior R3.
    case invalidAuthKey
    case signingFailed
    /// A contract limit (behavior M). For data formats, the byte length is checked before decoding.
    case limitExceeded
}
