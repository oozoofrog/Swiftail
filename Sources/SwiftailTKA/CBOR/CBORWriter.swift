// Canonical CBOR writing. Go TKA encodes with `cbor.CTAP2EncOptions()` (notes §3.1, contract behavior E1).

/// Writes canonical (CTAP2) encoding in one direction. There is no way to write indefinite lengths, tags, or floating-point values.
///
/// Integers and lengths always use the shortest header (RFC 8949 4.2.1). The caller writes map pairs in canonical order
/// (ascending integer keys for structures, lexicographic order of encoded key bytes for `Meta`, behaviors E2 and E3).
package struct CBORWriter: Sendable {
    /// The canonical bytes written so far.
    package private(set) var bytes: [UInt8] = []

    /// Starts with empty output.
    package init() {}

    /// Writes a unsigned integer (major 0) using the shortest header.
    package mutating func unsigned(_ value: UInt64) {
        appendHead(major: 0, argument: value)
    }

    /// A definite-length byte string (major 2). The writer omits indefinite-length byte strings because the Go decoder rejects them.
    package mutating func byteString(_ value: [UInt8]) {
        appendHead(major: 2, argument: UInt64(value.count))
        bytes += value
    }

    /// `value` is UTF-8 validated by the caller. Writes the supplied bytes unchanged (behavior E3).
    package mutating func textString(utf8 value: [UInt8]) {
        appendHead(major: 3, argument: UInt64(value.count))
        bytes += value
    }

    /// null (`f6`). Go writes this for nil pointers and nil slices (behavior E4).
    package mutating func null() {
        bytes.append(0xf6)
    }

    /// Write `count` items next.
    package mutating func arrayHeader(count: Int) {
        // All callers pass a collection's `count`, so a negative number would indicate a writer bug.
        precondition(count >= 0, "The CBOR array element count must be nonnegative")
        appendHead(major: 4, argument: UInt64(count))
    }

    /// Write `count` key-value pairs next.
    package mutating func mapHeader(count: Int) {
        // Callers pass a collection's `count` or that count plus a constant, so a negative number would indicate a writer bug.
        precondition(count >= 0, "The CBOR map pair count must be nonnegative")
        appendHead(major: 5, argument: UInt64(count))
    }

    /// Writes 0–23 in the first byte and larger values as 1-, 2-, 4-, or 8-byte big-endian arguments.
    private mutating func appendHead(major: UInt8, argument: UInt64) {
        let byteCount: Int
        switch argument {
        case 0..<24:
            bytes.append(major << 5 | UInt8(argument))
            return
        case ...0xff: byteCount = 1
        case ...0xffff: byteCount = 2
        case ...0xffff_ffff: byteCount = 4
        default: byteCount = 8
        }
        bytes.append(major << 5 | (24 + UInt8(byteCount.trailingZeroBitCount)))
        for shift in stride(from: (byteCount - 1) * 8, through: 0, by: -8) {
            bytes.append(UInt8(truncatingIfNeeded: argument >> UInt64(shift)))
        }
    }
}
