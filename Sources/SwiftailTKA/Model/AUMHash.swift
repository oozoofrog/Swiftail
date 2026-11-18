// An AUM hash and its text representation. Notes `docs/protocol-notes/tailnet-lock.md` §§3.7 and 3.8, Go `tailscale.com/tka/aum.go:21-51`.
// Copyright (c) Tailscale Inc & contributors. BSD-3-Clause.

import SwiftailCrypto

/// A 32-byte AUM hash (Go `tka.AUMHash`), the BLAKE2s-256 of the canonical AUM bytes (behavior E5).
///
/// Compares bytes. Text decoding ignores the final character's 4 unused bits, so different text can represent the same hash (notes §3.8).
package struct AUMHash: Sendable, Hashable {
    /// The 32-byte hash. The initializer checks length, so it is always 32 bytes.
    package let bytes: [UInt8]

    /// Returns nil unless the input contains 32 bytes.
    package init?(_ bytes: [UInt8]) {
        guard bytes.count == 32 else { return nil }
        self.bytes = bytes
    }

    /// The BLAKE2s-256 of `content`. The output is always 32 bytes.
    init(hashing content: [UInt8]) {
        bytes = BLAKE2s.hash(content)
    }

    /// The standard RFC 4648 base32 alphabet (uppercase), unpadded, 52 characters (Go `UnmarshalText`). Returns nil for lowercase, padding, or other lengths.
    ///
    /// Discards the final character's low 4 bits, as Go does. Go's `base32.Encoding.Decode` strips `\r` and `\n` before decoding.
    /// This decoder rejects them as outside the alphabet (accepts only 52 alphabet characters per the declaration in contract §2).
    package init?(text: String) {
        let characters = Array(text.utf8)
        guard characters.count == Self.textLength else { return nil }
        var result: [UInt8] = []
        result.reserveCapacity(32)
        var buffer: UInt32 = 0
        var bitCount = 0
        for character in characters {
            guard let value = Self.alphabetValue(character) else { return nil }
            buffer = buffer << 5 | UInt32(value)
            bitCount += 5
            if bitCount >= 8 {
                bitCount -= 8
                result.append(UInt8(truncatingIfNeeded: buffer >> UInt32(bitCount)))
            }
        }
        // Fill 32 bytes from 52 × 5 = 260 bits and discard the remaining 4 bits.
        bytes = result
    }

    /// The standard base32 alphabet (uppercase), unpadded, 52 characters (Go `String` and `MarshalText`).
    package var text: String {
        var characters: [UInt8] = []
        characters.reserveCapacity(Self.textLength)
        var buffer: UInt32 = 0
        var bitCount = 0
        for byte in bytes {
            buffer = buffer << 8 | UInt32(byte)
            bitCount += 8
            while bitCount >= 5 {
                bitCount -= 5
                characters.append(Self.alphabet[Int(buffer >> UInt32(bitCount) & 0x1f)])
            }
        }
        // Place the remaining 1 bit at the top and fill the low bits with zeros.
        characters.append(Self.alphabet[Int(buffer << UInt32(5 - bitCount) & 0x1f)])
        return String(decoding: characters, as: UTF8.self)
    }

    private static let textLength = 52
    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".utf8)

    private static func alphabetValue(_ character: UInt8) -> UInt8? {
        switch character {
        case UInt8(ascii: "A")...UInt8(ascii: "Z"): character - UInt8(ascii: "A")
        case UInt8(ascii: "2")...UInt8(ascii: "7"): character - UInt8(ascii: "2") + 26
        default: nil
        }
    }
}
