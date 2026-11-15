// TKA 구조(AUM·Key·State·Signature·NKS)를 `CBORValue`에서 읽는 공통 규칙. Go는 이 구조들을 `fxamacker/cbor` v2.9.3의
// 구조체 디코딩(`decode.go`의 `parseMapToStruct`·`parseToValue`·`fill*`)으로 읽는다. 계약 동작 D3~D7, 노트 3.1·6.2·8.1.

/// 구조 맵에서 알려진 필드의 값을 꺼낸 것.
///
/// 키의 규칙(동작 D3·D4): 양의 정수는 2^63−1까지, 음의 정수는 −2^63까지, 텍스트는 올바른 UTF-8만 받는다. 같은 키가 두 번이면
/// 거절한다. Go는 알려진 필드를 필드 번호로, 모르는 키를 `int64`나 문자열 값으로 견주므로 비최단으로 쓴 같은 정수도 중복이다.
/// 알려진 필드는 정수 키로만 찾는다(텍스트 `"1"`은 모르는 필드다. 동작 D5). 모르는 필드의 값은 보지 않고 버린다(동작 D6).
struct StructureFields {
    private var values: [UInt64: CBORValue] = [:]

    /// null(undefined 포함)은 빈 맵처럼 모든 필드가 0 값인 구조다(Go `fillNil`은 구조체를 건드리지 않는다). 맨 바깥과
    /// 배열 원소에 해당한다. 포인터 필드(`Key`·`State`·`Nested`)의 null은 부르는 쪽이 먼저 "없음"으로 읽는다.
    /// 그 밖의 맵이 아닌 값은 거절한다(동작 D7, 그리고 구조 자리의 타입 불일치).
    init(_ value: CBORValue, knownKeys: Set<UInt64>) throws(TKAError) {
        if value == .null { return }
        guard case .map(let pairs) = value else { throw .invalidStructure }
        var seen: Set<Key> = []
        for pair in pairs {
            let key = try Key(pair.key)
            guard seen.insert(key).inserted else { throw .invalidStructure }
            if case .integer(let number) = key, number >= 0, knownKeys.contains(UInt64(number)) {
                values[UInt64(number)] = pair.value
            }
        }
    }

    /// 알려진 필드의 값. 없으면 nil이다(null은 `.null`로 남는다).
    subscript(key: UInt64) -> CBORValue? { values[key] }

    /// 같은 키인지 가리는 값.
    private enum Key: Hashable {
        case integer(Int64)
        case text([UInt8])

        init(_ value: CBORValue) throws(TKAError) {
            switch value {
            case .unsigned(let number) where number <= UInt64(Int64.max):
                self = .integer(Int64(number))
            case .negative(let number) where number <= UInt64(Int64.max):
                self = .integer(~Int64(number))  // −1 − n
            case .text(let content) where content.isValidUTF8:
                self = .text(content)
            default:
                throw .invalidStructure
            }
        }
    }
}

// MARK: 알려진 필드의 값

extension CBORValue {
    /// Go의 부호 없는 정수 필드(`uint8`·`uint`·`uint64`)에 들어가는 값: 정수와 단순값은 그 수, null은 0(`fillNil`은 정수를
    /// 건드리지 않는다). `maximum`을 넘거나 다른 종류면 거절한다(동작 D5).
    func unsignedField(maximum: UInt64 = .max) throws(TKAError) -> UInt64 {
        let number: UInt64
        switch self {
        case .unsigned(let value): number = value
        case .simple(let value): number = UInt64(value)
        case .null: number = 0
        default: throw .invalidStructure
        }
        guard number <= maximum else { throw .invalidStructure }
        return number
    }

    /// Go의 `[]byte` 필드에 들어가는 값. null은 nil이다.
    ///
    /// 바이트열 말고 원소가 0~255의 정수·단순값·null(0)인 배열도 Go는 바이트로 읽는다(`parseArrayToSlice`가 원소를
    /// `uint8`로 채운다). 다시 쓰면 바이트열이 되므로 해시는 같은 내용의 바이트열과 같다.
    func byteField() throws(TKAError) -> [UInt8]? {
        switch self {
        case .null:
            return nil
        case .bytes(let content):
            return content
        case .array(let elements):
            var content: [UInt8] = []
            content.reserveCapacity(elements.count)
            for element in elements {
                content.append(UInt8(truncatingIfNeeded: try element.unsignedField(maximum: UInt64(UInt8.max))))
            }
            return content
        default:
            throw .invalidStructure
        }
    }

    /// Go의 `string`에 들어가는 값(`Meta`의 키와 값): 올바른 UTF-8 텍스트, null은 빈 문자열.
    func textField() throws(TKAError) -> [UInt8] {
        switch self {
        case .null:
            return []
        case .text(let content) where content.isValidUTF8:
            return content
        default:
            throw .invalidStructure
        }
    }

    /// Go의 슬라이스 필드에 들어가는 배열. null은 빈 배열이다(nil과 빈 슬라이스를 가리지 않는 필드에만 쓴다. 동작 E6).
    func arrayField() throws(TKAError) -> [CBORValue] {
        switch self {
        case .null: return []
        case .array(let elements): return elements
        default: throw .invalidStructure
        }
    }
}

extension [UInt8] {
    var isValidUTF8: Bool { String(validating: self, as: UTF8.self) != nil }
}

// MARK: 바이트 한도

/// 디코딩 전에 바이트 길이를 보고(동작 D9·M) 항목 하나로 읽는다.
func decodeItem(_ bytes: [UInt8], maximumByteCount: Int) throws(TKAError) -> CBORValue {
    guard bytes.count <= maximumByteCount else { throw .limitExceeded }
    do {
        return try CBOR.decode(bytes)
    } catch {
        throw .cbor(error)
    }
}
