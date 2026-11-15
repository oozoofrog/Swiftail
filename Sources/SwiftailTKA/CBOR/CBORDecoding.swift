// CBOR 항목 하나를 Go TKA의 디코더(`tailscale.com/tka/tka.go`의 `cborDecOpts`, `fxamacker/cbor` v2.9.3
// `valid.go`의 잘 짜임 검사)와 같은 규칙으로 읽는다. 계약 동작 D1·D2·D9, 노트 3.1·6.2·8.1.

/// CBOR 항목 수준의 거절 까닭. 구조(AUM·NKS)에 맞지 않는 것은 여기가 아니라 구조를 읽는 쪽이 거절한다.
package enum CBORError: Error, Sendable, Equatable {
    /// 빈 입력, 항목 중간에서 끝남, 남은 바이트보다 긴 길이 필드.
    case truncated
    /// 첫 항목 뒤에 바이트가 남음.
    case trailingBytes
    case indefiniteLength
    case tag
    /// 잘 짜이지 않은 항목: 예약된 추가 정보 28~30, 정수·태그의 추가 정보 31, 짝 없는 break(`ff`),
    /// 두 바이트로 쓴 32 미만 단순값(RFC 8949 3.3).
    case malformed
    /// 배열·맵이 17단 이상 겹침(맨 바깥이 1단).
    case nestingTooDeep
    /// 원소 4,097개 이상의 배열.
    case arrayTooLong
    /// 1,025쌍 이상의 맵.
    case mapTooLong
}

/// CBOR 읽기의 입구.
package enum CBOR {
    /// 배열·맵이 겹칠 수 있는 단 수(Go `MaxNestedLevels`).
    static let maximumNestingDepth = 16
    /// 배열 하나의 원소 수(Go `MaxArrayElements`).
    static let maximumArrayCount = 4_096
    /// 맵 하나의 쌍 수(Go `MaxMapPairs`).
    static let maximumMapPairCount = 1_024

    /// 항목 하나를 읽는다. 입력 전체가 정확히 항목 하나여야 한다.
    ///
    /// 비최단 정수와 정렬되지 않은 맵 키는 받아들인다(동작 D2). 텍스트의 UTF-8, 맵 키의 종류와 중복은 보지 않는다.
    /// 그것은 구조를 읽는 쪽의 일이다(동작 D3·D4). 오류는 Go가 앞에서부터 훑다 처음 만나는 것과 같은 자리에서 난다.
    /// 길이 필드만 믿고 미리 할당하지 않으며 재귀는 `maximumNestingDepth`로 묶이므로 어떤 입력으로도 죽지 않는다.
    package static func decode(_ bytes: [UInt8]) throws(CBORError) -> CBORValue {
        guard !bytes.isEmpty else { throw .truncated }
        var reader = Reader(bytes: bytes)
        let value = try reader.item(depth: 0)
        guard reader.offset == bytes.count else { throw .trailingBytes }
        return value
    }
}

/// 입력 위를 앞으로만 움직이는 읽기 위치.
private struct Reader {
    let bytes: [UInt8]
    var offset = 0

    /// 항목의 머리(RFC 8949 3장): 주 타입, 추가 정보, 인자.
    private struct Head {
        var major: UInt8
        var info: UInt8
        var argument: UInt64
        var isIndefinite: Bool { info == 31 }
    }

    /// `depth`는 이 항목을 감싼 배열·맵의 수다.
    mutating func item(depth: Int) throws(CBORError) -> CBORValue {
        let head = try readHead()
        switch head.major {
        case 0:
            return .unsigned(head.argument)
        case 1:
            return .negative(head.argument)
        case 2, 3:
            guard !head.isIndefinite else { throw .indefiniteLength }
            let content = try readBytes(count: head.argument)
            return head.major == 2 ? .bytes(content) : .text(content)
        case 4, 5:
            // Go와 같은 순서로 본다: 깊이, 길이 미정, 원소 수. 원소 수는 원소를 읽기 전에 거절한다.
            guard depth < CBOR.maximumNestingDepth else { throw .nestingTooDeep }
            guard !head.isIndefinite else { throw .indefiniteLength }
            if head.major == 4 {
                guard head.argument <= UInt64(CBOR.maximumArrayCount) else { throw .arrayTooLong }
                var elements: [CBORValue] = []
                for _ in 0..<head.argument {
                    elements.append(try item(depth: depth + 1))
                }
                return .array(elements)
            } else {
                guard head.argument <= UInt64(CBOR.maximumMapPairCount) else { throw .mapTooLong }
                var pairs: [CBORPair] = []
                for _ in 0..<head.argument {
                    let key = try item(depth: depth + 1)
                    pairs.append(CBORPair(key: key, value: try item(depth: depth + 1)))
                }
                return .map(pairs)
            }
        case 6:
            throw .tag
        default:
            // major 7: 0~19와 24는 단순값(24는 32 이상만 남는다. `readHead`), 22 null, 23 undefined.
            // 나머지(20 false, 21 true, 25~27 실수)는 값을 쥐지 않는다.
            switch head.info {
            case 22, 23: return .null
            case 0...19, 24: return .simple(UInt8(truncatingIfNeeded: head.argument))
            default: return .simpleOrFloat
            }
        }
    }

    private mutating func readHead() throws(CBORError) -> Head {
        guard offset < bytes.count else { throw .truncated }
        let initial = bytes[offset]
        offset += 1
        let major = initial >> 5
        let info = initial & 0x1f
        switch info {
        case 0...23:
            return Head(major: major, info: info, argument: UInt64(info))
        case 24...27:
            let argument = try readUnsigned(byteCount: 1 << Int(info - 24))
            // 단순값 0~31은 한 바이트 머리로만 쓴다(RFC 8949 3.3).
            if major == 7, info == 24, argument < 32 { throw .malformed }
            return Head(major: major, info: info, argument: argument)
        case 31:
            // 길이 미정은 bstr·tstr·배열·맵에만 있다. major 7의 31은 짝 없는 break다.
            guard (2...5).contains(major) else { throw .malformed }
            return Head(major: major, info: info, argument: 0)
        default:
            throw .malformed
        }
    }

    private mutating func readUnsigned(byteCount: Int) throws(CBORError) -> UInt64 {
        guard bytes.count - offset >= byteCount else { throw .truncated }
        var value: UInt64 = 0
        for byte in bytes[offset..<offset + byteCount] {
            value = value << 8 | UInt64(byte)
        }
        offset += byteCount
        return value
    }

    private mutating func readBytes(count: UInt64) throws(CBORError) -> [UInt8] {
        // 남은 길이와 먼저 견준다. 그래야 `Int`로 바꿀 때 넘치지 않고, 거대한 길이로 할당하지 않는다.
        guard count <= UInt64(bytes.count - offset) else { throw .truncated }
        let end = offset + Int(count)
        let content = Array(bytes[offset..<end])
        offset = end
        return content
    }
}
