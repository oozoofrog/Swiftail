// An element of GF(2^255−19), used only for coordinates of edwards25519 points.
//
// Origin: ported to Swift from `fe.go` and `fe_generic.go` in the Go 1.27.3 standard library's `crypto/internal/fips140/edwards25519/field`.
// The port includes the five 51-bit limb representation, column computations and carries for multiplication and squaring, addition chains for
// inversion and Pow22523, and SqrtRatio. 128-bit intermediates use `UInt128` in place of Go's `uint128` struct.
//
// Copyright (c) 2017 The Go Authors. All rights reserved.
// BSD-3-Clause. Original text from the Go distribution's LICENSE follows.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google LLC nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

/// An element of GF(p), where p = 2^255−19.
///
/// The value is `l0 + l1·2^51 + l2·2^102 + l3·2^153 + l4·2^204`. Between operations, the limbs are less than 2^52
/// (the same invariant as Go `field.Element`). Representations are nonunique, so equality compares canonical bytes.
///
/// This type handles only public values (signature verification inputs). Comparison and selection use variable time.
struct FieldElement: Equatable {
    private var l0, l1, l2, l3, l4: UInt64

    private static let maskLow51Bits: UInt64 = (1 << 51) - 1

    static let zero = FieldElement(l0: 0, l1: 0, l2: 0, l3: 0, l4: 0)
    static let one = FieldElement(l0: 1, l1: 0, l2: 0, l3: 0, l4: 0)

    /// The d = −121665/121666 in the curve equation (RFC 8032 §5.1).
    static let d = FieldElement(bytes: [
        0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
        0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
    ])

    /// The value 2^((p−1)/4), which squares to −1.
    static let sqrtMinusOne = FieldElement(
        l0: 1_718_705_420_411_056, l1: 234_908_883_556_509, l2: 2_233_514_472_574_048,
        l3: 2_117_202_627_021_982, l4: 765_476_049_583_133)

    private init(l0: UInt64, l1: UInt64, l2: UInt64, l3: UInt64, l4: UInt64) {
        self.l0 = l0; self.l1 = l1; self.l2 = l2; self.l3 = l3; self.l4 = l4
    }

    /// Reads a 32-byte little-endian value. Discards the high bit (bit 255) and accepts values from p up to but excluding 2^255
    /// (noncanonical representations), treating them as remainders modulo p. This is more permissive than RFC 8032 and matches Go's
    /// `field.Element.SetBytes`. Point decoding in both verification rules relies on this behavior.
    ///
    /// - Precondition: `bytes.count == 32`. The caller checks the length.
    init(bytes: [UInt8]) {
        precondition(bytes.count == 32, "Field elements are 32 bytes")
        func load64(_ offset: Int) -> UInt64 {
            (0..<8).reduce(0) { $0 | UInt64(bytes[offset + $1]) << (8 * $1) }
        }
        let mask = Self.maskLow51Bits
        self.init(
            l0: load64(0) & mask,
            l1: (load64(6) >> 3) & mask,
            l2: (load64(12) >> 6) & mask,
            l3: (load64(19) >> 1) & mask,
            l4: (load64(24) >> 12) & mask)
    }

    /// The canonical (0 ≤ value < p) 32-byte little-endian representation. The high bit is 0.
    var bytes: [UInt8] {
        var t = self
        t.reduce()
        let words = [
            t.l1 << 51 | t.l0,
            t.l2 << (102 - 64) | t.l1 >> (64 - 51),
            t.l3 << (153 - 128) | t.l2 >> (128 - 102),
            t.l4 << (204 - 192) | t.l3 >> (192 - 153),
        ]
        return words.flatMap { word in (0..<8).map { UInt8(truncatingIfNeeded: word >> (8 * $0)) } }
    }

    /// Whether the canonical representation is odd and therefore "negative" (the sign bit of x in RFC 8032 §5.1.2).
    var isNegative: Bool { bytes[0] & 1 == 1 }

    static func == (a: FieldElement, b: FieldElement) -> Bool { a.bytes == b.bytes }

    // MARK: Addition and subtraction

    static func + (a: FieldElement, b: FieldElement) -> FieldElement {
        var v = FieldElement(l0: a.l0 + b.l0, l1: a.l1 + b.l1, l2: a.l2 + b.l2, l3: a.l3 + b.l3, l4: a.l4 + b.l4)
        v.carryPropagate()
        return v
    }

    /// Adds 2p before subtracting to keep the limbs nonnegative (b can be as large as 2^255 + 2^13·19).
    static func - (a: FieldElement, b: FieldElement) -> FieldElement {
        var v = FieldElement(
            l0: (a.l0 + 0xF_FFFF_FFFF_FFDA) - b.l0,
            l1: (a.l1 + 0xF_FFFF_FFFF_FFFE) - b.l1,
            l2: (a.l2 + 0xF_FFFF_FFFF_FFFE) - b.l2,
            l3: (a.l3 + 0xF_FFFF_FFFF_FFFE) - b.l3,
            l4: (a.l4 + 0xF_FFFF_FFFF_FFFE) - b.l4)
        v.carryPropagate()
        return v
    }

    static prefix func - (a: FieldElement) -> FieldElement { zero - a }

    // MARK: Multiplication and squaring

    /// Multiplies limbs in columns like long multiplication, folding overflowing columns down using 2^255 ≡ 19.
    /// The largest column r0 is below 2^111, so carries fit in UInt64 (see the comment on Go `feMulGeneric`).
    static func * (a: FieldElement, b: FieldElement) -> FieldElement {
        let r0 = wide(a.l0, b.l0) + wide19(a.l1, b.l4) + wide19(a.l2, b.l3) + wide19(a.l3, b.l2) + wide19(a.l4, b.l1)
        let r1 = wide(a.l0, b.l1) + wide(a.l1, b.l0) + wide19(a.l2, b.l4) + wide19(a.l3, b.l3) + wide19(a.l4, b.l2)
        let r2 = wide(a.l0, b.l2) + wide(a.l1, b.l1) + wide(a.l2, b.l0) + wide19(a.l3, b.l4) + wide19(a.l4, b.l3)
        let r3 = wide(a.l0, b.l3) + wide(a.l1, b.l2) + wide(a.l2, b.l1) + wide(a.l3, b.l0) + wide19(a.l4, b.l4)
        let r4 = wide(a.l0, b.l4) + wide(a.l1, b.l3) + wide(a.l2, b.l2) + wide(a.l3, b.l1) + wide(a.l4, b.l0)
        return carried(r0, r1, r2, r3, r4)
    }

    /// Squares using multiplication with symmetric terms grouped together.
    func squared() -> FieldElement {
        let r0 = Self.wide(l0, l0) + Self.wide19(l1, 2 * l4) + Self.wide19(l2, 2 * l3)
        let r1 = Self.wide(2 * l0, l1) + Self.wide19(l2, 2 * l4) + Self.wide19(l3, l3)
        let r2 = Self.wide(2 * l0, l2) + Self.wide(l1, l1) + Self.wide19(l3, 2 * l4)
        let r3 = Self.wide(2 * l0, l3) + Self.wide(2 * l1, l2) + Self.wide19(l4, l4)
        let r4 = Self.wide(2 * l0, l4) + Self.wide(2 * l1, l3) + Self.wide(l2, l2)
        return Self.carried(r0, r1, r2, r3, r4)
    }

    /// x^(2^n). n ≥ 1.
    func squared(times n: Int) -> FieldElement {
        var v = self
        for _ in 0..<n { v = v.squared() }
        return v
    }

    private static func wide(_ a: UInt64, _ b: UInt64) -> UInt128 { UInt128(a) * UInt128(b) }

    /// Computes 19·a·b. Both a and b are at most 52 bits, so 19·a fits in UInt64.
    private static func wide19(_ a: UInt64, _ b: UInt64) -> UInt128 { UInt128(19 * a) * UInt128(b) }

    /// Converts five wide columns back into 51-bit limbs. Multiplies the top carry by 19 and adds it to the bottom limb.
    private static func carried(_ r0: UInt128, _ r1: UInt128, _ r2: UInt128, _ r3: UInt128, _ r4: UInt128) -> FieldElement {
        let mask = maskLow51Bits
        func low(_ r: UInt128) -> UInt64 { UInt64(truncatingIfNeeded: r) & mask }
        func carry(_ r: UInt128) -> UInt64 { UInt64(truncatingIfNeeded: r >> 51) }

        let rr0 = low(r0) + 19 * carry(r4)
        let rr1 = low(r1) + carry(r0)
        let rr2 = low(r2) + carry(r1)
        let rr3 = low(r3) + carry(r2)
        let rr4 = low(r4) + carry(r3)
        // Carries may remain above the low 51 bits of the intermediate limbs. Propagate them once more. The resulting limbs have enough spare bits.
        return FieldElement(
            l0: rr0 & mask + 19 * (rr4 >> 51),
            l1: rr1 & mask + rr0 >> 51,
            l2: rr2 & mask + rr1 >> 51,
            l3: rr3 & mask + rr2 >> 51,
            l4: rr4 & mask + rr3 >> 51)
    }

    // MARK: Exponentiation

    /// Computes 1/self = self^(p−2). The inverse of 0 is 0. Uses an addition chain of 254 squarings and 11 multiplications.
    func inverted() -> FieldElement {
        let z2 = squared()                         // 2
        let z9 = z2.squared(times: 2) * self       // 9
        let z11 = z9 * z2                          // 11
        let z2_5_0 = z11.squared() * z9            // 31 = 2^5 − 2^0
        let z2_10_0 = z2_5_0.squared(times: 5) * z2_5_0
        let z2_20_0 = z2_10_0.squared(times: 10) * z2_10_0
        let z2_40_0 = z2_20_0.squared(times: 20) * z2_20_0
        let z2_50_0 = z2_40_0.squared(times: 10) * z2_10_0
        let z2_100_0 = z2_50_0.squared(times: 50) * z2_50_0
        let z2_200_0 = z2_100_0.squared(times: 100) * z2_100_0
        let z2_250_0 = z2_200_0.squared(times: 50) * z2_50_0
        return z2_250_0.squared(times: 5) * z11    // 2^255 − 21 = p − 2
    }

    /// Computes self^((p−5)/8) = self^(2^252 − 3) for square roots.
    private func pow22523() -> FieldElement {
        let x3 = squared() * self                  // 3
        let x15 = x3.squared(times: 2) * x3        // 15
        let z2_5_0 = x15.squared() * self          // 31 = 2^5 − 1
        let z2_10_0 = z2_5_0.squared(times: 5) * z2_5_0
        let z2_20_0 = z2_10_0.squared(times: 10) * z2_10_0
        let z2_40_0 = z2_20_0.squared(times: 20) * z2_20_0
        let z2_50_0 = z2_40_0.squared(times: 10) * z2_10_0
        let z2_100_0 = z2_50_0.squared(times: 50) * z2_50_0
        let z2_200_0 = z2_100_0.squared(times: 100) * z2_100_0
        let z2_250_0 = z2_200_0.squared(times: 50) * z2_50_0
        return z2_250_0.squared(times: 2) * self   // 2^252 − 3
    }

    /// The nonnegative √(u/v) (step 3 of RFC 8032 §5.1.3, Go `SqrtRatio`).
    /// Returns `nil` if u/v is not a square. For v = 0, returns 0 only if u = 0.
    static func squareRootOfRatio(_ u: FieldElement, _ v: FieldElement) -> FieldElement? {
        // r = (u·v^3)·(u·v^7)^((p−5)/8)
        let v3 = v.squared() * v
        let uv3 = u * v3
        let uv7 = uv3 * v3 * v
        var r = uv3 * uv7.pow22523()

        let check = v * r.squared()
        let correctSign = check == u
        let flippedSign = check == -u
        let flippedSignTimesI = check == -u * sqrtMinusOne
        if flippedSign || flippedSignTimesI { r = r * sqrtMinusOne }
        guard correctSign || flippedSign else { return nil }
        return r.isNegative ? -r : r
    }

    // MARK: Reduction

    /// Folds the top limb's carry into the bottom limb using 2^255 ≡ 19 to keep each limb below 2^52.
    private mutating func carryPropagate() {
        let mask = Self.maskLow51Bits
        let c0 = l0 >> 51, c1 = l1 >> 51, c2 = l2 >> 51, c3 = l3 >> 51, c4 = l4 >> 51
        l0 = l0 & mask + 19 * c4
        l1 = l1 & mask + c0
        l2 = l2 & mask + c1
        l3 = l3 & mask + c2
        l4 = l4 & mask + c3
    }

    /// Fully reduces the value to 0 ≤ v < p.
    private mutating func reduce() {
        carryPropagate()
        // Now v < 2^255 + 2^13·19. If v ≥ p, v + 19 reaches or exceeds 2^255 and the top carry c becomes 1.
        var c = (l0 + 19) >> 51
        c = (l1 + c) >> 51
        c = (l2 + c) >> 51
        c = (l3 + c) >> 51
        c = (l4 + c) >> 51
        // If c = 1, compute v − p = v + 19 − 2^255 (the final mask discards the 2^255 bit).
        let mask = Self.maskLow51Bits
        l0 += 19 * c
        l1 += l0 >> 51; l0 &= mask
        l2 += l1 >> 51; l1 &= mask
        l3 += l2 >> 51; l2 &= mask
        l4 += l3 >> 51; l3 &= mask
        l4 &= mask
    }
}
