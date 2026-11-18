/// An Internet checksum (RFC 1071), the complement of the ones' complement sum of 16-bit big-endian words.
///
/// IPv4 headers, TCP and UDP (including the IP pseudo-header), and ICMP use the same sum. The engine's service IP responses and the netstack's segment codec
/// share this calculation (`docs/contracts/SwiftailNetstack.md` decision D10).
///
/// Calling `add` with separate chunks of bytes yields the same result as concatenating them and adding them at once. This allows the pseudo-header
/// and segment to be added in sequence without copying them into a single array. The sender sets the checksum field to 0 for the calculation. The verifier
/// includes the field in the sum and accepts a checksum of `0` (a sum of `0xFFFF`).
///
/// The sum accumulates in a `UInt64`, so it cannot overflow before exceeding 2⁴⁸ bytes.
package struct InternetChecksum: Sendable {
    private var sum: UInt64 = 0
    /// Whether the next byte is the high byte of the word. The first byte after a chunk ending on an odd length is the low byte.
    private var nextIsHighByte = true

    /// Creates an empty sum.
    package init() {}

    /// Adds bytes to the sum. If the total length already added is odd, the first byte fills the low byte of the preceding word.
    package mutating func add(_ bytes: ArraySlice<UInt8>) {
        var index = bytes.startIndex
        if !nextIsHighByte, index < bytes.endIndex {
            sum += UInt64(bytes[index])
            nextIsHighByte = true
            index += 1
        }
        while bytes.endIndex - index >= 2 {
            sum += UInt64(bytes[index]) << 8 | UInt64(bytes[index + 1])
            index += 2
        }
        // Pad a trailing odd byte with 0 (RFC 1071 §1). The next byte added, if any, fills that 0 position.
        if index < bytes.endIndex {
            sum += UInt64(bytes[index]) << 8
            nextIsHighByte = false
        }
    }

    /// Adds bytes to the sum.
    package mutating func add(_ bytes: [UInt8]) {
        add(bytes[...])
    }

    /// Adds the IP pseudo-header for TCP, UDP, or ICMPv6 to the sum. Call this first, before adding the transport-layer segment.
    ///
    /// For IPv4 (4-byte addresses), the fields are the source address, destination address, 0, protocol, and transport-layer length (16 bits).
    /// All other lengths are treated as IPv6, with source address, destination address, transport-layer length (32 bits), three zeros, and next header (RFC 9293 §3.1, RFC 8200 §8.1).
    ///
    /// - Parameters:
    ///   - source: The source address (4 or 16 bytes).
    ///   - destination: The destination address, with the same length as `source`.
    ///   - protocolNumber: The IPv4 protocol or IPv6 next header.
    ///   - length: The total transport-layer segment length, excluding IP and extension headers and including options and data for TCP.
    package mutating func addPseudoHeader(source: [UInt8], destination: [UInt8], protocolNumber: UInt8, length: Int) {
        let length = UInt32(truncatingIfNeeded: length)
        add(source)
        add(destination)
        if source.count == 4 {
            add([0, protocolNumber, UInt8(truncatingIfNeeded: length >> 8), UInt8(truncatingIfNeeded: length)])
        } else {
            add([
                UInt8(truncatingIfNeeded: length >> 24), UInt8(truncatingIfNeeded: length >> 16),
                UInt8(truncatingIfNeeded: length >> 8), UInt8(truncatingIfNeeded: length),
                0, 0, 0, protocolNumber,
            ])
        }
    }

    /// The checksum of the bytes added so far. Folds carries back in until the sum fits in 16 bits, then takes the complement. Returns `0xFFFF` for an empty sum.
    package var value: UInt16 {
        var folded = sum
        while folded > 0xFFFF {
            folded = (folded & 0xFFFF) + (folded >> 16)
        }
        return ~UInt16(truncatingIfNeeded: folded)
    }

    /// Returns the checksum of a single `bytes` value.
    package static func checksum(of bytes: [UInt8]) -> UInt16 {
        var checksum = InternetChecksum()
        checksum.add(bytes)
        return checksum.value
    }
}
