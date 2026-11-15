// edwards25519 곡선 −x² + y² = 1 + d·x²·y² 위의 점(RFC 8032 5.1).
//
// 출처: Go 1.27.3 표준 라이브러리 `crypto/internal/fips140/edwards25519/edwards25519.go`의
// `Point.SetBytes`(느슨한 해독 규칙), `Point.Bytes`, 확장 좌표의 더하기(`projP1xP1.Add`·`projCached`)와
// 두 배(`projP1xP1.Double`)를 Swift로 옮겼다. 같은 코드가 `filippo.io/edwards25519` v1.2.0에도 있고
// `ed25519consensus`는 그쪽을 쓴다(`SetBytes`가 같음을 diff로 확인했다).
// Copyright (c) 2017 The Go Authors. BSD-3-Clause(전문은 `FieldElement.swift` 머리).

/// 확장 좌표 (X : Y : Z : T)의 점. x = X/Z, y = Y/Z, x·y = T/Z (Hisil–Wong–Carter–Dawson 2008).
///
/// 더하기 공식은 곡선 위의 모든 점(항등원과 작은 위수의 점 포함)에 대해 완전하다. 공개 값만 다루므로
/// 연산이 가변 시간이다.
struct EdwardsPoint {
    private var x, y, z, t: FieldElement

    private static let d2 = FieldElement.d + FieldElement.d

    static let identity = EdwardsPoint(x: .zero, y: .one, z: .one, t: .zero)

    /// 기준점 B: y = 4/5이고 x가 음수가 아닌 점(RFC 8032 5.1). 인코딩은 `58 66 66 … 66`.
    static let basepoint: EdwardsPoint = {
        let y = FieldElement(bytes: [0x58] + [UInt8](repeating: 0x66, count: 31))
        // y = 4/5에서 x² = (y² − 1)/(d·y² + 1)은 제곱수다(곡선 위의 점). 만에 하나 아니면 0을 쓰고,
        // 그러면 기준점 시험(인코딩 왕복)이 실패한다.
        let x = FieldElement.squareRootOfRatio(y.squared() - .one, FieldElement.d * y.squared() + .one) ?? .zero
        return EdwardsPoint(x: x, y: y, z: .one, t: x * y)
    }()

    private init(x: FieldElement, y: FieldElement, z: FieldElement, t: FieldElement) {
        self.x = x; self.y = y; self.z = z; self.t = t
    }

    /// 32바이트 인코딩을 해독한다(RFC 8032 5.1.3에서 Go `Point.SetBytes`가 느슨하게 한 규칙).
    ///
    /// RFC와 다르게 두 종류의 비정준 인코딩을 받아들인다.
    /// 1. y ≥ p인 표현(`FieldElement(bytes:)`가 p로 줄인다).
    /// 2. x = 0인데 부호 비트가 선 표현(−0 = 0이라 같은 점이 된다).
    ///
    /// x² = (y² − 1)/(d·y² + 1)이 제곱수가 아니면(곡선 위가 아니면) `nil`이다. 길이가 32가 아니어도 `nil`이다.
    /// ZIP-215와 Go 표준 `crypto/ed25519`가 A와 R을 이 규칙으로 해독한다.
    init?(encoding: [UInt8]) {
        guard encoding.count == 32 else { return nil }
        let y = FieldElement(bytes: encoding)
        let y2 = y.squared()
        guard let root = FieldElement.squareRootOfRatio(y2 - .one, FieldElement.d * y2 + .one) else { return nil }
        let x = encoding[31] >> 7 == 1 ? -root : root
        self.init(x: x, y: y, z: .one, t: x * y)
    }

    /// 정준 인코딩(RFC 8032 5.1.2): 정준 y의 리틀 엔디언 32바이트, 맨 위 비트는 x의 부호.
    var encoding: [UInt8] {
        let zInverse = z.inverted()
        var bytes = (y * zInverse).bytes
        if (x * zInverse).isNegative { bytes[31] |= 0x80 }
        return bytes
    }

    /// 항등원 (0, 1)인가. 사영 좌표에서 X = 0이고 Y = Z인 것과 같다.
    var isIdentity: Bool { x == .zero && y == z }

    // MARK: 군 연산

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

    /// [8]P. 작은 위수(1·2·4·8) 성분을 없앤다.
    func multipliedByCofactor() -> EdwardsPoint { doubled().doubled().doubled() }

    /// Go의 `projP1xP1`(완료 좌표 ((X : Z), (Y : T)))를 확장 좌표로 바꾼다.
    private static func completed(x: FieldElement, y: FieldElement, z: FieldElement, t: FieldElement) -> EdwardsPoint {
        EdwardsPoint(x: x * t, y: y * z, z: z * t, t: x * y)
    }

    // MARK: 스칼라 곱

    /// [a]A + [b]B (B는 기준점). Straus–Shamir 방식으로 두 스칼라의 비트를 위에서부터 함께 훑는다.
    ///
    /// 비트에 따라 더하기를 건너뛰므로 가변 시간이다. 서명 검증에서는 a = k, A = −공개 키, b = S가 모두
    /// 공개 값이라 시간으로 새는 비밀이 없다(Go `VarTimeDoubleScalarBaseMult`도 같은 이유로 가변 시간이다).
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
