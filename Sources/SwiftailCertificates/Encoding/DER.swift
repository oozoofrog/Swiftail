/// DER(ITU-T X.690의 Distinguished Encoding Rules)로 적을 ASN.1 값.
///
/// CSR(RFC 2986)을 만드는 데 필요한 형만 있다. 읽기는 없다: 받은 X.509의 해석은 Security가 한다.
/// 값마다 바이트가 하나로 정해지는 것이 DER의 성질이고(X.690 10·11절), 그래야 Go와 같은 입력에서 같은 바이트가
/// 나온다(노트 7장 2). 틀린 값을 만들 수 없게 타입으로 막는다: 길이는 내용에서 계산하고, 정수는 음이 아닌 크기만,
/// OID는 이 타깃이 정한 상수만, 문자열은 문자 집합을 검사한 타입만 받는다.
indirect enum DERValue: Sendable, Equatable {
    /// `SEQUENCE`(태그 0x30). 원소를 차례대로 잇는다.
    case sequence([DERValue])
    /// `SET OF`(태그 0x31). DER는 원소의 인코딩을 바이트열로 견준 오름차순으로 적는다(X.690 11.6).
    case setOf([DERValue])
    /// 음이 아닌 `INTEGER`(태그 0x02). 값은 빅엔디언 크기 바이트다. 앞의 0은 떼고, 첫 비트가 1이면 부호를
    /// 위해 0x00을 앞에 붙인다(X.690 8.3). 빈 배열은 0이다.
    case integer(magnitude: [UInt8])
    /// `OBJECT IDENTIFIER`(태그 0x06, X.690 8.19).
    case objectIdentifier(ASN1ObjectIdentifier)
    /// `PrintableString`(태그 0x13).
    case printableString(PrintableString)
    /// `IA5String`(태그 0x16).
    case ia5String(IA5String)
    /// 남는 비트가 없는 `BIT STRING`(태그 0x03). 내용 앞에 "안 쓰는 비트 수" 0을 붙인다(X.690 8.6.2).
    case bitString([UInt8])
    /// `OCTET STRING`(태그 0x04).
    case octetString([UInt8])
    /// 문맥 태그로 바꾼 값: `[number] IMPLICIT`(X.690 8.14.3). 안 값의 태그를 문맥 부류의 `number`로 바꾸고
    /// 구성형 여부와 내용은 그대로 둔다. CSR의 `attributes [0]`과 SAN의 `dNSName [2]`가 이것이다.
    case implicitlyTagged(number: UInt8, DERValue)

    /// DER 바이트(식별자 ‖ 길이 ‖ 내용).
    var encoded: [UInt8] {
        let content = contentOctets
        return identifierOctets + Self.lengthOctets(content.count) + content
    }

    // MARK: - 식별자(X.690 8.1.2)

    private var identifierOctets: [UInt8] {
        switch self {
        case .sequence: return [0x30]
        case .setOf: return [0x31]
        case .integer: return [0x02]
        case .objectIdentifier: return [0x06]
        case .printableString: return [0x13]
        case .ia5String: return [0x16]
        case .bitString: return [0x03]
        case .octetString: return [0x04]
        case .implicitlyTagged(let number, let value):
            // 부류 비트 10(문맥), 구성형 비트는 안 값의 것. 번호 31 이상은 높은 번호 형식(X.690 8.1.2.4).
            let leading: UInt8 = 0x80 | (value.isConstructed ? 0x20 : 0)
            return number < 31 ? [leading | number] : [leading | 0x1F] + base128(UInt64(number))
        }
    }

    private var isConstructed: Bool {
        switch self {
        case .sequence, .setOf: true
        case .implicitlyTagged(_, let value): value.isConstructed
        default: false
        }
    }

    // MARK: - 길이(X.690 8.1.3, 10.1)

    /// 정규 길이: 127 이하는 짧은 형식 한 바이트, 그 위는 `0x80 | n` 뒤에 앞의 0을 뗀 빅엔디언 n바이트.
    private static func lengthOctets(_ length: Int) -> [UInt8] {
        guard length >= 0x80 else { return [UInt8(length)] }
        var bytes: [UInt8] = []
        var rest = length
        while rest > 0 {
            bytes.insert(UInt8(truncatingIfNeeded: rest), at: 0)
            rest >>= 8
        }
        return [0x80 | UInt8(bytes.count)] + bytes
    }

    // MARK: - 내용

    private var contentOctets: [UInt8] {
        switch self {
        case .sequence(let elements):
            elements.flatMap(\.encoded)
        case .setOf(let elements):
            elements.map(\.encoded).sorted(by: Self.precedesInSetOf).flatMap { $0 }
        case .integer(let magnitude):
            Self.integerContent(magnitude)
        case .objectIdentifier(let identifier):
            identifier.contentOctets
        case .printableString(let string):
            Array(string.value.utf8)
        case .ia5String(let string):
            Array(string.value.utf8)
        case .bitString(let bytes):
            [0x00] + bytes
        case .octetString(let bytes):
            bytes
        case .implicitlyTagged(_, let value):
            value.contentOctets
        }
    }

    /// X.690 8.3: 2의 보수 최소 바이트. 음이 아닌 값이므로 첫 비트가 1이면 0x00을 앞에 둔다.
    private static func integerContent(_ magnitude: [UInt8]) -> [UInt8] {
        let trimmed = magnitude.drop(while: { $0 == 0 })
        guard let first = trimmed.first else { return [0x00] }
        return first & 0x80 == 0 ? Array(trimmed) : [0x00] + trimmed
    }

    /// X.690 11.6의 순서: 짧은 쪽의 끝을 0으로 채워 바이트열로 견준다.
    private static func precedesInSetOf(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
        for index in 0..<max(lhs.count, rhs.count) {
            let left = index < lhs.count ? lhs[index] : 0
            let right = index < rhs.count ? rhs[index] : 0
            if left != right { return left < right }
        }
        return false
    }
}

/// X.690 8.19.2: 7비트씩 빅엔디언으로, 마지막이 아닌 바이트는 첫 비트를 1로. OID의 호와 높은 태그 번호가 쓴다.
private func base128(_ value: UInt64) -> [UInt8] {
    var bytes = [UInt8(value & 0x7F)]
    var rest = value >> 7
    while rest > 0 {
        bytes.insert(UInt8(rest & 0x7F) | 0x80, at: 0)
        rest >>= 7
    }
    return bytes
}

/// CSR에 쓰는 OBJECT IDENTIFIER. 이 타깃이 정한 상수만 있다(밖에서 만들 수 없으므로 첫 두 호의 규칙
/// X.690 8.19.4를 어기는 값이 생기지 않는다).
struct ASN1ObjectIdentifier: Sendable, Equatable {
    /// 점으로 적는 호들(`2.5.4.3`이면 `[2, 5, 4, 3]`).
    let arcs: [UInt64]
    /// DER의 내용 바이트. 첫 두 호는 `40 × 첫째 + 둘째` 하나로 적는다(X.690 8.19.4).
    let contentOctets: [UInt8]

    private init(_ first: UInt64, _ second: UInt64, _ rest: UInt64...) {
        arcs = [first, second] + rest
        contentOctets = base128(first * 40 + second) + rest.flatMap(base128)
    }

    /// `id-at-commonName` 2.5.4.3(RFC 5280 부록 A.1).
    static let commonName = Self(2, 5, 4, 3)
    /// `id-ce-subjectAltName` 2.5.29.17(RFC 5280 4.2.1.6).
    static let subjectAltName = Self(2, 5, 29, 17)
    /// `id-ecPublicKey` 1.2.840.10045.2.1(RFC 5480 2.1.1).
    static let ecPublicKey = Self(1, 2, 840, 10045, 2, 1)
    /// `secp256r1` 1.2.840.10045.3.1.7(RFC 5480 2.1.1.1).
    static let secp256r1 = Self(1, 2, 840, 10045, 3, 1, 7)
    /// `ecdsa-with-SHA256` 1.2.840.10045.4.3.2(RFC 5758 3.2).
    static let ecdsaWithSHA256 = Self(1, 2, 840, 10045, 4, 3, 2)
    /// `pkcs-9-at-extensionRequest` 1.2.840.113549.1.9.14(RFC 2985 5.4.2).
    static let extensionRequest = Self(1, 2, 840, 113549, 1, 9, 14)
}

/// `PrintableString`의 문자 집합(영문자, 숫자, 공백, `'()+,-./:=?`)만으로 된 문자열(RFC 4517 3.2
/// `PrintableCharacter`, X.680의 PrintableString).
struct PrintableString: Sendable, Equatable {
    let value: String

    /// 문자 집합 밖의 문자가 있으면 `nil`. 빈 문자열은 받는다(길이 제한은 쓰는 자리의 몫이다).
    init?(_ value: String) {
        guard value.utf8.allSatisfy(Self.isPrintable) else { return nil }
        self.value = value
    }

    private static func isPrintable(_ byte: UInt8) -> Bool {
        switch byte {
        case UInt8(ascii: "A")...UInt8(ascii: "Z"), UInt8(ascii: "a")...UInt8(ascii: "z"),
             UInt8(ascii: "0")...UInt8(ascii: "9"):
            true
        default:
            punctuation.contains(byte)
        }
    }

    private static let punctuation = Array(" '()+,-./:=?".utf8)
}

/// ASCII(0x00~0x7F)만으로 된 문자열(RFC 4517 3.2 `IA5String`). SAN의 `dNSName`이 이 형이다(RFC 5280 4.2.1.6).
struct IA5String: Sendable, Equatable {
    let value: String

    /// ASCII 밖의 문자가 있으면 `nil`.
    init?(_ value: String) {
        guard value.utf8.allSatisfy({ $0 < 0x80 }) else { return nil }
        self.value = value
    }
}
