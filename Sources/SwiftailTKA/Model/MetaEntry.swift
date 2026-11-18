// `Key.Meta` and `AUM.Meta` (Go `map[string]string`). Notes §§3.1, 3.2, and 3.4, contract behaviors E3, D4, and D5.
// Copyright (c) Tailscale Inc & contributors. BSD-3-Clause.

/// One `Meta` pair. Avoids converting to Swift `String` because its Unicode canonical equivalence differs from Go's byte comparison,
/// and that difference changes the reencoded hash (behavior E3).
package struct MetaEntry: Sendable, Equatable {
    /// Validated UTF-8.
    package var key: [UInt8]
    /// Validated UTF-8.
    package var value: [UInt8]

    /// One pair. Does not check UTF-8. `metaField()` checks received `Meta` as it reads it, and callers creating values must preserve UTF-8.
    package init(key: [UInt8], value: [UInt8]) {
        self.key = key
        self.value = value
    }
}

extension CBORValue {
    /// Reads the `Meta` map. Null gives nil. Keys and values must be text (null becomes an empty string, Go `fillNil`), and duplicate keys are rejected
    /// (Go compares keys as string values). Returns pairs in canonical order.
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
    /// Lexicographic order of encoded key bytes (CTAP2, notes §3.1). The header byte contains the length, so shorter keys come first (`a`, `c`, `bb`).
    func canonicallyOrdered() -> [MetaEntry] {
        map { entry in
            var writer = CBORWriter()
            writer.textString(utf8: entry.key)
            return (encodedKey: writer.bytes, entry: entry)
        }
        .sorted { $0.encodedKey.lexicographicallyPrecedes($1.encodedKey) }
        .map(\.entry)
    }

    /// The sum of key and value lengths (`metaBytes` in Go `Key.StaticValidate`).
    var byteCount: Int { reduce(0) { $0 + $1.key.count + $1.value.count } }
}

extension CBORWriter {
    /// Writes the `Meta` map in canonical order (behavior E3). Writes the received key and value bytes unchanged.
    mutating func meta(_ entries: [MetaEntry]) {
        mapHeader(count: entries.count)
        for entry in entries.canonicallyOrdered() {
            textString(utf8: entry.key)
            textString(utf8: entry.value)
        }
    }
}
