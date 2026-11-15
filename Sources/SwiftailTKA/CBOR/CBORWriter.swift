// 정준 CBOR 쓰기. Go TKA는 `cbor.CTAP2EncOptions()`로 인코딩한다(노트 3.1, 계약 동작 E1).

/// 정준(CTAP2) 인코딩을 한 방향으로 써 나간다. 길이 미정·태그·실수를 쓰는 길이 없다.
///
/// 정수와 길이는 늘 가장 짧은 머리로 쓴다(RFC 8949 4.2.1). 맵의 쌍은 부르는 쪽이 정준 순서로 쓴다
/// (구조의 정수 키는 오름차순, `Meta`는 인코딩한 키 바이트의 사전순. 동작 E2·E3).
package struct CBORWriter: Sendable {
    package private(set) var bytes: [UInt8] = []

    package init() {}

    package mutating func unsigned(_ value: UInt64) {
        appendHead(major: 0, argument: value)
    }

    package mutating func byteString(_ value: [UInt8]) {
        appendHead(major: 2, argument: UInt64(value.count))
        bytes += value
    }

    /// `value`는 부르는 쪽이 검증한 UTF-8이다. 받은 바이트를 그대로 쓴다(동작 E3).
    package mutating func textString(utf8 value: [UInt8]) {
        appendHead(major: 3, argument: UInt64(value.count))
        bytes += value
    }

    package mutating func null() {
        bytes.append(0xf6)
    }

    /// 뒤따라 `count`개의 항목을 써야 한다.
    package mutating func arrayHeader(count: Int) {
        precondition(count >= 0, "CBOR 배열의 원소 수는 0 이상이다")
        appendHead(major: 4, argument: UInt64(count))
    }

    /// 뒤따라 키·값 항목을 `count`쌍 써야 한다.
    package mutating func mapHeader(count: Int) {
        precondition(count >= 0, "CBOR 맵의 쌍 수는 0 이상이다")
        appendHead(major: 5, argument: UInt64(count))
    }

    /// 0~23은 첫 바이트에, 그 위는 1·2·4·8바이트 빅엔디언 인자로 쓴다.
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
