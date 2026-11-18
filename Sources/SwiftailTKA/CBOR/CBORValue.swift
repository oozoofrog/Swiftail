// The CBOR (RFC 8949) data item forms TKA handles. See `docs/protocol-notes/tailnet-lock.md` §§3.1 and 6.2.

/// A decoded CBOR data item, covering types used by TKA structures and the remaining types needed to skip unknown fields.
///
/// Integers discard the received encoding length (`18 01` and `01` both give `.unsigned(1)`). Maps preserve received order and
/// duplicates. The structure decoder decides whether to reject duplicate keys based on whether the map is part of the structure or
/// the value of an unknown field (contract behavior D4).
package enum CBORValue: Sendable, Equatable {
    case unsigned(UInt64)
    /// A negative integer, `-1 - n`. Appears only as a key or value in an unknown field.
    case negative(UInt64)
    case bytes([UInt8])
    /// The text bytes. UTF-8 is unchecked here because unknown field values are skipped even with invalid UTF-8 (behavior D6).
    case text([UInt8])
    case array([CBORValue])
    case map([CBORPair])
    /// null (`f6`) and undefined (`f7`). The Go decoder treats them alike, producing the zero value in a known field and
    /// discarding them in unknown fields (`nextCBORNil` in `fxamacker/cbor` v2.9.3 `decode.go`). The writer emits null.
    case null
    /// Unassigned simple values (0–19, 32–255). The Go decoder writes these as integers into integer fields
    /// (the remaining major 7 branch in `parseToValue` calls `fillPositiveInt` in `fxamacker/cbor` v2.9.3 `decode.go`).
    case simple(UInt8)
    /// Other major 7 items (false, true, and floating-point values). Their values are discarded. They cannot appear in known fields.
    case simpleOrFloat
}

/// One map pair.
package struct CBORPair: Sendable, Equatable {
    /// The key exactly as received. In a structure map it must be an integer or text, as checked by the structure decoder.
    package var key: CBORValue
    /// The value associated with the key.
    package var value: CBORValue
}
