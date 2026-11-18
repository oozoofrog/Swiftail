/// A TCP sequence number (RFC 9293 §3.4).
///
/// A number modulo 2³². The sequence wraps through zero and returns to its starting value after advancing by
/// 2³² bytes (4GiB). Unsigned `UInt32` magnitude comparisons cannot order sequence numbers across a wrap. The sign of the 32-bit difference orders two sequence numbers. The comparison is meaningful
/// only when they are less than 2³¹ apart, which the TCP window guarantees even with scaling (less than 2³⁰). This is
/// not a total order, so the type does not conform to `Comparable`.
package struct SequenceNumber: Sendable, Hashable {
    /// The value carried in the segment header.
    package var rawValue: UInt32

    /// Creates a sequence number from the exact 32-bit value in the segment header.
    package init(_ rawValue: UInt32) {
        self.rawValue = rawValue
    }

    /// Returns the number `count` ahead, wrapping at 2³².
    package func advanced(by count: UInt32) -> SequenceNumber {
        SequenceNumber(rawValue &+ count)
    }

    /// Returns the distance from `other` to this number. Positive if this number follows `other`, negative if it precedes it.
    package func distance(from other: SequenceNumber) -> Int32 {
        Int32(bitPattern: rawValue &- other.rawValue)
    }

    /// Returns whether this sequence number precedes `other` (the RFC's `<`).
    package func precedes(_ other: SequenceNumber) -> Bool {
        distance(from: other) < 0
    }

    /// Returns whether this sequence number equals or precedes `other` (the RFC's `=<`).
    package func precedesOrEquals(_ other: SequenceNumber) -> Bool {
        distance(from: other) <= 0
    }
}
