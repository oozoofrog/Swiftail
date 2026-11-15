// GF(2^255−19)의 원소. edwards25519 점의 좌표에만 쓴다.
//
// 출처: Go 1.27.3 표준 라이브러리 `crypto/internal/fips140/edwards25519/field`의
// `fe.go`·`fe_generic.go`(51비트 림 다섯 개의 표현, 곱·제곱의 열 계산과 올림, 역원과 Pow22523의
// 덧셈 사슬, SqrtRatio)를 Swift로 옮겼다. 128비트 중간값은 Go의 `uint128` 구조체 대신 `UInt128`을 쓴다.
//
// Copyright (c) 2017 The Go Authors. All rights reserved.
// BSD-3-Clause. 원문(Go 배포본의 LICENSE):
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

/// GF(p), p = 2^255−19의 원소.
///
/// 값은 `l0 + l1·2^51 + l2·2^102 + l3·2^153 + l4·2^204`이고, 연산과 연산 사이에 림은 2^52보다 작다
/// (Go `field.Element`와 같은 불변식). 표현은 하나가 아니므로 같음은 정준 바이트로 비교한다.
///
/// 이 타입은 공개 값(서명 검증의 입력)만 다룬다. 비교와 선택이 상수 시간이 아니다.
struct FieldElement: Equatable {
    private var l0, l1, l2, l3, l4: UInt64

    private static let maskLow51Bits: UInt64 = (1 << 51) - 1

    static let zero = FieldElement(l0: 0, l1: 0, l2: 0, l3: 0, l4: 0)
    static let one = FieldElement(l0: 1, l1: 0, l2: 0, l3: 0, l4: 0)

    /// 곡선 식의 d = −121665/121666 (RFC 8032 5.1).
    static let d = FieldElement(bytes: [
        0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
        0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
    ])

    /// 2^((p−1)/4). 제곱하면 −1이다.
    static let sqrtMinusOne = FieldElement(
        l0: 1_718_705_420_411_056, l1: 234_908_883_556_509, l2: 2_233_514_472_574_048,
        l3: 2_117_202_627_021_982, l4: 765_476_049_583_133)

    private init(l0: UInt64, l1: UInt64, l2: UInt64, l3: UInt64, l4: UInt64) {
        self.l0 = l0; self.l1 = l1; self.l2 = l2; self.l3 = l3; self.l4 = l4
    }

    /// 32바이트 리틀 엔디언 값을 읽는다. 맨 위 비트(255번)는 버리고, p 이상 2^255 미만의 값
    /// (비정준 표현)도 그대로 받아 p로 나눈 나머지로 다룬다. RFC 8032보다 느슨하지만 Go
    /// `field.Element.SetBytes`와 같고, 두 검증 규칙의 점 해독이 이 동작에 기댄다.
    ///
    /// - Precondition: `bytes.count == 32`. 호출하는 쪽이 길이를 검사한다.
    init(bytes: [UInt8]) {
        precondition(bytes.count == 32, "필드 원소는 32바이트")
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

    /// 정준(0 ≤ 값 < p) 32바이트 리틀 엔디언 표현. 맨 위 비트는 0이다.
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

    /// 정준 표현이 홀수이면 "음수"다(RFC 8032 5.1.2의 x의 부호 비트).
    var isNegative: Bool { bytes[0] & 1 == 1 }

    static func == (a: FieldElement, b: FieldElement) -> Bool { a.bytes == b.bytes }

    // MARK: 더하기와 빼기

    static func + (a: FieldElement, b: FieldElement) -> FieldElement {
        var v = FieldElement(l0: a.l0 + b.l0, l1: a.l1 + b.l1, l2: a.l2 + b.l2, l3: a.l3 + b.l3, l4: a.l4 + b.l4)
        v.carryPropagate()
        return v
    }

    /// 2p를 먼저 더해 림이 음수가 되지 않게 한 뒤 뺀다(b는 2^255 + 2^13·19까지 될 수 있다).
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

    // MARK: 곱과 제곱

    /// 림을 종이 위 곱셈처럼 열로 곱하고, 2^255 ≡ 19로 넘치는 열을 아래로 접는다.
    /// 가장 큰 열 r0는 2^111보다 작아 올림이 UInt64에 들어간다(Go `feMulGeneric`의 주석).
    static func * (a: FieldElement, b: FieldElement) -> FieldElement {
        let r0 = wide(a.l0, b.l0) + wide19(a.l1, b.l4) + wide19(a.l2, b.l3) + wide19(a.l3, b.l2) + wide19(a.l4, b.l1)
        let r1 = wide(a.l0, b.l1) + wide(a.l1, b.l0) + wide19(a.l2, b.l4) + wide19(a.l3, b.l3) + wide19(a.l4, b.l2)
        let r2 = wide(a.l0, b.l2) + wide(a.l1, b.l1) + wide(a.l2, b.l0) + wide19(a.l3, b.l4) + wide19(a.l4, b.l3)
        let r3 = wide(a.l0, b.l3) + wide(a.l1, b.l2) + wide(a.l2, b.l1) + wide(a.l3, b.l0) + wide19(a.l4, b.l4)
        let r4 = wide(a.l0, b.l4) + wide(a.l1, b.l3) + wide(a.l2, b.l2) + wide(a.l3, b.l1) + wide(a.l4, b.l0)
        return carried(r0, r1, r2, r3, r4)
    }

    /// 곱과 같지만 대칭인 항을 묶는다.
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

    /// 19·a·b. a와 b는 52비트 이하라 19·a가 UInt64에 들어간다.
    private static func wide19(_ a: UInt64, _ b: UInt64) -> UInt128 { UInt128(19 * a) * UInt128(b) }

    /// 다섯 개의 넓은 열을 51비트 림으로 되돌린다. 맨 위 올림은 19를 곱해 맨 아래에 더한다.
    private static func carried(_ r0: UInt128, _ r1: UInt128, _ r2: UInt128, _ r3: UInt128, _ r4: UInt128) -> FieldElement {
        let mask = maskLow51Bits
        func low(_ r: UInt128) -> UInt64 { UInt64(truncatingIfNeeded: r) & mask }
        func carry(_ r: UInt128) -> UInt64 { UInt64(truncatingIfNeeded: r >> 51) }

        let rr0 = low(r0) + 19 * carry(r4)
        let rr1 = low(r1) + carry(r0)
        let rr2 = low(r2) + carry(r1)
        let rr3 = low(r3) + carry(r2)
        let rr4 = low(r4) + carry(r3)
        // 올림이 아직 2^51을 넘으므로 한 번 더 전파한다. 이번 올림은 림의 여유분에 들어간다.
        return FieldElement(
            l0: rr0 & mask + 19 * (rr4 >> 51),
            l1: rr1 & mask + rr0 >> 51,
            l2: rr2 & mask + rr1 >> 51,
            l3: rr3 & mask + rr2 >> 51,
            l4: rr4 & mask + rr3 >> 51)
    }

    // MARK: 거듭제곱

    /// 1/self = self^(p−2). 0의 역원은 0이다. 제곱 254번과 곱 11번의 덧셈 사슬.
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

    /// self^((p−5)/8) = self^(2^252 − 3). 제곱근 계산에 쓴다.
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

    /// √(u/v)의 음수가 아닌 쪽(RFC 8032 5.1.3의 3단계, Go `SqrtRatio`).
    /// u/v가 제곱수가 아니면 `nil`이다. v = 0이면 u = 0일 때만 0을 돌려준다.
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

    // MARK: 줄이기

    /// 2^255 ≡ 19로 맨 위 림의 올림을 맨 아래로 접어 모든 림을 52비트 아래로 둔다.
    private mutating func carryPropagate() {
        let mask = Self.maskLow51Bits
        let c0 = l0 >> 51, c1 = l1 >> 51, c2 = l2 >> 51, c3 = l3 >> 51, c4 = l4 >> 51
        l0 = l0 & mask + 19 * c4
        l1 = l1 & mask + c0
        l2 = l2 & mask + c1
        l3 = l3 & mask + c2
        l4 = l4 & mask + c3
    }

    /// 값을 0 ≤ v < p로 완전히 줄인다.
    private mutating func reduce() {
        carryPropagate()
        // 이제 v < 2^255 + 2^13·19. v ≥ p이면 v + 19가 2^255를 넘어 맨 위 올림 c가 1이 된다.
        var c = (l0 + 19) >> 51
        c = (l1 + c) >> 51
        c = (l2 + c) >> 51
        c = (l3 + c) >> 51
        c = (l4 + c) >> 51
        // c = 1이면 v − p = v + 19 − 2^255를 계산한다(2^255 비트는 마지막 마스크로 버린다).
        let mask = Self.maskLow51Bits
        l0 += 19 * c
        l1 += l0 >> 51; l0 &= mask
        l2 += l1 >> 51; l1 &= mask
        l3 += l2 >> 51; l2 &= mask
        l4 += l3 >> 51; l3 &= mask
        l4 &= mask
    }
}
