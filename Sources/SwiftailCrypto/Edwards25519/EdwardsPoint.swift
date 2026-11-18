// A point on the edwards25519 curve −x² + y² = 1 + d·x²·y² (RFC 8032 §5.1).
//
// Origin: ported to Swift from the Go 1.27.3 standard library's `crypto/internal/fips140/edwards25519/edwards25519.go`.
// The port includes `Point.SetBytes` (relaxed decoding rules), `Point.Bytes`, and addition in extended coordinates (`projP1xP1.Add` and `projCached`)
// and doubling (`projP1xP1.Double`). The same code is also in `filippo.io/edwards25519` v1.2.0, which
// `ed25519consensus` uses (a diff confirmed that `SetBytes` is identical).
// Copyright (c) 2017 The Go Authors. BSD-3-Clause (full text at the top of `FieldElement.swift`).

/// A point in extended coordinates (X : Y : Z : T). x = X/Z, y = Y/Z, x·y = T/Z (Hisil–Wong–Carter–Dawson 2008).
///
/// The addition formulas are complete for all points on the curve, including the identity and points of small order. Operations are variable time
/// because they handle only public values.
struct EdwardsPoint {
    private var x, y, z, t: FieldElement

    private static let d2 = FieldElement.d + FieldElement.d

    static let identity = EdwardsPoint(x: .zero, y: .one, z: .one, t: .zero)

    /// The base point B, where y = 4/5 and x is nonnegative (RFC 8032 §5.1). Its encoding is `58 66 66 … 66`.
    static let basepoint: EdwardsPoint = {
        let y = FieldElement(bytes: [0x58] + [UInt8](repeating: 0x66, count: 31))
        // For y = 4/5, x² = (y² − 1)/(d·y² + 1) is a square (a point on the curve). If this ever fails, use 0,
        // which will fail the base point test (encoding round trip).
        let x = FieldElement.squareRootOfRatio(y.squared() - .one, FieldElement.d * y.squared() + .one) ?? .zero
        return EdwardsPoint(x: x, y: y, z: .one, t: x * y)
    }()

    private init(x: FieldElement, y: FieldElement, z: FieldElement, t: FieldElement) {
        self.x = x; self.y = y; self.z = z; self.t = t
    }

    /// Decodes a 32-byte encoding using Go `Point.SetBytes`'s relaxed version of the rules in RFC 8032 §5.1.3.
    ///
    /// Accepts two kinds of noncanonical encodings beyond those allowed by the RFC.
    /// 1. A representation with y ≥ p (`FieldElement(bytes:)` reduces it modulo p).
    /// 2. A representation with x = 0 and the sign bit set (−0 = 0, so it denotes the same point).
    ///
    /// Returns `nil` if x² = (y² − 1)/(d·y² + 1) is not a square (the point is off the curve) or if the length differs from 32.
    /// ZIP-215 and Go's standard `crypto/ed25519` decode A and R by these rules.
    init?(encoding: [UInt8]) {
        guard encoding.count == 32 else { return nil }
        let y = FieldElement(bytes: encoding)
        let y2 = y.squared()
        guard let root = FieldElement.squareRootOfRatio(y2 - .one, FieldElement.d * y2 + .one) else { return nil }
        let x = encoding[31] >> 7 == 1 ? -root : root
        self.init(x: x, y: y, z: .one, t: x * y)
    }

    /// The canonical encoding (RFC 8032 §5.1.2), the 32 little-endian bytes of canonical y with x's sign in the high bit.
    var encoding: [UInt8] {
        let zInverse = z.inverted()
        var bytes = (y * zInverse).bytes
        if (x * zInverse).isNegative { bytes[31] |= 0x80 }
        return bytes
    }

    /// Whether this is the identity (0, 1), equivalent to X = 0 and Y = Z in projective coordinates.
    var isIdentity: Bool { x == .zero && y == z }

    // MARK: Group operations

    static func + (p: EdwardsPoint, q: EdwardsPoint) -> EdwardsPoint {
        let pp = (p.y + p.x) * (q.y + q.x)
        let mm = (p.y - p.x) * (q.y - q.x)
        let tt2d = p.t * (q.t * d2)
        let zz = p.z * q.z
        let zz2 = zz + zz
        return completed(x: pp - mm, y: pp + mm, z: zz2 + tt2d, t: zz2 - tt2d)
    }

    static prefix func - (p: EdwardsPoint) -> EdwardsPoint {
        EdwardsPoint(x: -p.x, y: p.y, z: p.z, t: -p.t)
    }

    static func - (p: EdwardsPoint, q: EdwardsPoint) -> EdwardsPoint { p + -q }

    func doubled() -> EdwardsPoint {
        let xx = x.squared()
        let yy = y.squared()
        let zz = z.squared()
        let zz2 = zz + zz
        let yPlusXX = yy + xx
        let yMinusXX = yy - xx
        return Self.completed(x: (x + y).squared() - yPlusXX, y: yPlusXX, z: yMinusXX, t: zz2 - yMinusXX)
    }

    /// Returns [8]P, removing small-order (1, 2, 4, 8) components.
    func multipliedByCofactor() -> EdwardsPoint { doubled().doubled().doubled() }

    /// Converts Go's `projP1xP1` (completed coordinates ((X : Z), (Y : T))) to extended coordinates.
    private static func completed(x: FieldElement, y: FieldElement, z: FieldElement, t: FieldElement) -> EdwardsPoint {
        EdwardsPoint(x: x * t, y: y * z, z: z * t, t: x * y)
    }

    // MARK: Scalar multiplication

    /// Computes [a]A + [b]B (B is the base point). Scans the bits of both scalars together from the top using Straus–Shamir.
    ///
    /// This is variable time because it skips additions based on the bits. In signature verification a = k, A = −public key, and b = S are all
    /// public, so timing leaks no secrets (Go's `VarTimeDoubleScalarBaseMult` is variable time for the same reason).
    static func varTimeDoubleScalarBaseMultiply(_ a: Scalar, _ point: EdwardsPoint, _ b: Scalar) -> EdwardsPoint {
        let sum = point + basepoint
        var result = identity
        for i in (0..<256).reversed() {
            result = result.doubled()
            switch (a.bit(i), b.bit(i)) {
            case (true, true): result = result + sum
            case (true, false): result = result + point
            case (false, true): result = result + basepoint
            case (false, false): break
            }
        }
        return result
    }
}
