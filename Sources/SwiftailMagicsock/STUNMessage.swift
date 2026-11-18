// The STUN binding request format follows Tailscale's `net/stun/stun.go` (BSD-3-Clause, Copyright (c) Tailscale Inc & contributors).
// Only the byte layout and constants were ported. The code was written from scratch in Swift.

import SwiftailBase

/// Encoding and detection of STUN binding messages, used to discover the local external address (endpoint).
///
/// This type has no I/O. It builds request bytes, checks whether received bytes are STUN, and extracts the TxID and external address from responses.
/// `Netcheck` remembers the TxID sent with each request.
///
/// See `docs/protocol-notes/derp-stun.md` 3.8 (requests), 3.9 (responses), and 4.10 3 (parsing), and `disco-magicsock.md` 4.1 1 (detection) for the format.
/// - The request is 40 bytes. The Go STUN server replies only if SOFTWARE is exactly `tailnode` and the final attribute is a valid FINGERPRINT,
///   so these bytes must match exactly.
/// - Responses are untrusted input. `parseBindingResponse` parses them once and returns `nil` on failure.
enum STUNMessage {
    /// Header length comprises message type (2), body length (2), cookie (4), and TxID (12).
    static let headerLength = 20
    /// The magic cookie from RFC 5389. Used for address XOR and STUN detection.
    static let magicCookie: [UInt8] = [0x21, 0x12, 0xa4, 0x42]

    /// The SOFTWARE attribute value. The Go STUN server uses it as a marker of where the request came from. The 8-byte value needs no padding.
    private static let software = Array("tailnode".utf8)
    private static let softwareAttribute: UInt16 = 0x8022
    private static let fingerprintAttribute: UInt16 = 0x8028
    /// FINGERPRINT XORs this value with CRC-32 (RFC 5389 15.5, ASCII `STUN`).
    private static let fingerprintXOR: UInt32 = 0x5354_554e

    /// The 40-byte request in DERP notes 3.8.
    static func bindingRequest(_ txID: TransactionID) -> [UInt8] {
        var bytes: [UInt8] = [0x00, 0x01]  // binding request
        // Length after the header, SOFTWARE (4 + 8) and FINGERPRINT (4 + 4).
        bytes += bigEndian(UInt16(4 + software.count + 8))
        bytes += magicCookie
        bytes += txID.bytes
        bytes += bigEndian(softwareAttribute)
        bytes += bigEndian(UInt16(software.count))
        bytes += software
        // The length field includes FINGERPRINT, and the CRC covers the 32 bytes before FINGERPRINT.
        let fingerprint = CRC32.checksum(bytes) ^ fingerprintXOR
        bytes += bigEndian(fingerprintAttribute)
        bytes += bigEndian(UInt16(4))
        bytes += bigEndian(fingerprint)
        return bytes
    }

    /// STUN detection in notes §4.1, item 1 requires at least 20 bytes, the two high bits of the first byte set to 0, a matching cookie, and byte 1 equal to 0x01 (binding method).
    ///
    /// Checks only the format. `Netcheck` matches these datagrams to requests and WireGuard never receives them.
    static func looksLikeSTUN(_ bytes: [UInt8]) -> Bool {
        hasSTUNHeader(bytes) && bytes[1] == 0x01
    }

    /// Length ≥ 20, first byte's high 2 bits 0, and matching cookie. Equivalent to Go `stun.Is`.
    static func hasSTUNHeader(_ bytes: [UInt8]) -> Bool {
        bytes.count >= headerLength && bytes[0] & 0b1100_0000 == 0 && bytes[4..<8].elementsEqual(magicCookie)
    }

    static func bigEndian(_ value: UInt16) -> [UInt8] {
        [UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value)]
    }

    private static func bigEndian(_ value: UInt32) -> [UInt8] {
        (0..<4).map { UInt8(truncatingIfNeeded: value >> UInt32(24 - 8 * $0)) }
    }
}

/// CRC-32/IEEE (polynomial 0xEDB88320, reflected). Equivalent to Go `crc32.ChecksumIEEE`. Used only to calculate FINGERPRINT.
private enum CRC32 {
    private static let table: [UInt32] = (0..<256).map { index in
        (0..<8).reduce(UInt32(index)) { value, _ in
            value & 1 == 1 ? (value >> 1) ^ 0xEDB8_8320 : value >> 1
        }
    }

    static func checksum(_ bytes: [UInt8]) -> UInt32 {
        ~bytes.reduce(UInt32.max) { crc, byte in
            table[Int(UInt8(truncatingIfNeeded: crc) ^ byte)] ^ (crc >> 8)
        }
    }
}
