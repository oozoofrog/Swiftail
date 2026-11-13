import Foundation

// Go `encoding/json`의 표현 가운데 Swift `Codable`의 기본과 다른 것들을 필드 단위로 읽고 쓰는 도구.
// 모델의 `init(from:)`·`encode(to:)`가 쓴다. 디코더·인코더의 설정(날짜 전략 등)에 기대지 않으므로
// 모델은 어떤 `JSONDecoder`·`JSONEncoder`로도 같은 결과를 낸다.
//
// - 시각: RFC 3339 문자열(`GoTime`).
// - 바이트열(`[]byte`, `MarshaledSignature`): 패딩 있는 표준 base64 문자열.
// - 정수 ID를 키로 쓰는 map(`map[NodeID]bool` 등): 키가 10진 정수 문자열인 JSON 객체.
//
// 받을 때 Go는 `null`과 키 없음을 똑같이 0 값으로 둔다. 그래서 `decodeIfPresent`의 `nil`이 둘을 함께
// 뜻해도 Go와 같다. 증분의 의미를 가르는 것은 `nil`과 빈 배열·객체의 차이이고, `Optional<[T]>`가 그것을
// 그대로 담는다. `docs/protocol-notes/control-map.md` 3.1.

extension KeyedDecodingContainer {
    /// 시각. 키가 없거나 `null`이면 `nil`. 0 시각은 그대로 돌려준다(필드마다 뜻이 달라서다).
    func decodeTimeIfPresent(forKey key: Key) throws -> Date? {
        guard let text = try decodeIfPresent(String.self, forKey: key) else { return nil }
        guard let date = GoTime.parse(text) else {
            throw DecodingError.dataCorruptedError(forKey: key, in: self, debugDescription: "RFC 3339 시각이 아니다")
        }
        return date
    }

    /// base64 바이트열. 키가 없거나 `null`이면 `nil`.
    func decodeBytesIfPresent(forKey key: Key) throws -> [UInt8]? {
        guard let text = try decodeIfPresent(String.self, forKey: key) else { return nil }
        guard let data = Data(base64Encoded: text) else {
            throw DecodingError.dataCorruptedError(forKey: key, in: self, debugDescription: "base64가 아니다")
        }
        return [UInt8](data)
    }

    /// 키가 10진 정수 문자열인 JSON 객체. 키가 정수가 아니거나 범위 밖이면 오류다.
    func decodeIntegerKeyedIfPresent<Value: Decodable>(_ type: Value.Type, forKey key: Key) throws -> [Int64: Value]? {
        guard let object = try decodeIfPresent([String: Value].self, forKey: key) else { return nil }
        var result: [Int64: Value] = [:]
        for (text, value) in object {
            guard let id = Int64(text) else {
                throw DecodingError.dataCorruptedError(forKey: key, in: self, debugDescription: "정수 키가 아니다: \(text)")
            }
            result[id] = value
        }
        return result
    }

    /// `NodeCapMap`·`PeerCapMap`: 속성 이름 → 인자 배열. 값이 `null`이면 빈 배열(인자 없음)이다.
    func decodeCapMapIfPresent(forKey key: Key) throws -> [String: [JSONValue]]? {
        try decodeIfPresent([String: [JSONValue]?].self, forKey: key)?.mapValues { $0 ?? [] }
    }
}

extension KeyedEncodingContainer {
    /// 시각. `nil`이면 Go의 0 시각을 쓴다(`omitempty`가 없는 `time.Time` 필드).
    mutating func encodeTime(_ date: Date?, forKey key: Key) throws {
        guard let text = GoTime.format(date ?? GoTime.zero) else {
            throw EncodingError.invalidValue(date as Any, .init(codingPath: codingPath + [key], debugDescription: "0~9999년 밖의 시각"))
        }
        try encode(text, forKey: key)
    }

    /// 바이트열. 비어 있으면 `null`(Go의 nil 슬라이스, `omitempty` 없음).
    mutating func encodeBytesOrNull(_ bytes: [UInt8], forKey key: Key) throws {
        if bytes.isEmpty {
            try encodeNil(forKey: key)
        } else {
            try encode(Data(bytes).base64EncodedString(), forKey: key)
        }
    }

    /// 0 값(빈 문자열·`false`·0·빈 배열·빈 객체)이면 쓰지 않는다. Go의 `omitempty`·`omitzero`.
    mutating func encodeUnlessEmpty(_ value: String, forKey key: Key) throws {
        if !value.isEmpty { try encode(value, forKey: key) }
    }

    mutating func encodeUnlessEmpty(_ value: Bool, forKey key: Key) throws {
        if value { try encode(value, forKey: key) }
    }

    mutating func encodeUnlessEmpty(_ value: Int64, forKey key: Key) throws {
        if value != 0 { try encode(value, forKey: key) }
    }

    mutating func encodeUnlessEmpty<Element: Encodable>(_ value: [Element], forKey key: Key) throws {
        if !value.isEmpty { try encode(value, forKey: key) }
    }

    mutating func encodeUnlessEmpty<Value: Encodable>(_ value: [String: Value], forKey key: Key) throws {
        if !value.isEmpty { try encode(value, forKey: key) }
    }
}
