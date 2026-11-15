// `Key.Meta`와 `AUM.Meta`(Go `map[string]string`). 노트 3.1·3.2·3.4, 계약 동작 E3·D4·D5.

/// `Meta`의 한 쌍. Swift `String`으로 바꾸지 않는다: `String`의 비교는 유니코드 정규 동등이라 Go의 바이트 비교와 다르고,
/// 그 차이는 다시 인코딩한 해시를 바꾼다(동작 E3).
package struct MetaEntry: Sendable, Equatable {
    /// 검증된 UTF-8.
    package var key: [UInt8]
    /// 검증된 UTF-8.
    package var value: [UInt8]

    package init(key: [UInt8], value: [UInt8]) {
        self.key = key
        self.value = value
    }
}

extension CBORValue {
    /// `Meta` 맵을 읽는다. null은 nil이다. 키와 값은 텍스트(null은 빈 문자열, Go `fillNil`)여야 하고, 같은 키가 두 번이면
    /// 거절한다(Go는 키를 문자열 값으로 견준다). 결과는 정준 순서다.
    func metaField() throws(TKAError) -> [MetaEntry]? {
        guard case .map(let pairs) = self else {
            guard self == .null else { throw .invalidStructure }
            return nil
        }
        var entries: [MetaEntry] = []
        var keys: Set<[UInt8]> = []
        for pair in pairs {
            let entry = MetaEntry(key: try pair.key.textField(), value: try pair.value.textField())
            guard keys.insert(entry.key).inserted else { throw .invalidStructure }
            entries.append(entry)
        }
        return entries.canonicallyOrdered()
    }
}

extension [MetaEntry] {
    /// 인코딩한 키 바이트의 사전순(CTAP2, 노트 3.1). 머리 바이트가 길이를 담으므로 짧은 키가 먼저다(`a`, `c`, `bb`).
    func canonicallyOrdered() -> [MetaEntry] {
        map { entry in
            var writer = CBORWriter()
            writer.textString(utf8: entry.key)
            return (encodedKey: writer.bytes, entry: entry)
        }
        .sorted { $0.encodedKey.lexicographicallyPrecedes($1.encodedKey) }
        .map(\.entry)
    }

    /// 키·값 길이의 합(Go `Key.StaticValidate`의 `metaBytes`).
    var byteCount: Int { reduce(0) { $0 + $1.key.count + $1.value.count } }
}

extension CBORWriter {
    /// `Meta` 맵을 정준 순서로 쓴다(동작 E3). 키와 값은 받은 바이트 그대로다.
    mutating func meta(_ entries: [MetaEntry]) {
        mapHeader(count: entries.count)
        for entry in entries.canonicallyOrdered() {
            textString(utf8: entry.key)
            textString(utf8: entry.value)
        }
    }
}
