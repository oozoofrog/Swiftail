// 서명 권한을 가진 키(Go `tka.Key`, `tailscale.com/tka/key.go:36-132`). 노트 3.2, 계약 동작 E4·D5·A1.
// Copyright (c) Tailscale Inc & contributors. BSD-3-Clause.

/// 서명 권한을 가진 키. KeyID는 `publicKey` 바이트 그 자체다(노트 3.2).
package struct TrustedKey: Sendable, Equatable {
    /// 1 = `Key25519`. 정적 검사는 1만 통과시킨다.
    package var kind: UInt8
    /// 갈래 해소의 가중치. 정적 검사는 1~4,096만 통과시킨다.
    package var votes: UInt64
    /// nil은 CBOR null이다. null과 빈 바이트열은 인코딩이 다르므로 구분한다(동작 E4). 길이는 정적 검사가 보지 않는다.
    package var publicKey: [UInt8]?
    /// 정준 순서. 비면 인코딩에서 빠진다(omitempty).
    package var meta: [MetaEntry] = []

    /// `Key25519`(노트 3.2).
    static let ed25519Kind: UInt8 = 1
    /// `Votes`의 상한(Go `Key.StaticValidate`).
    static let maximumVotes: UInt64 = 4_096
    /// `Meta`의 키·값 길이 합의 상한(Go `maxMetaBytes`).
    static let maximumMetaByteCount = 512

    /// KeyID(Go `Key.ID`). `Key25519`가 아니면 nil이다.
    var keyID: [UInt8]? { kind == Self.ed25519Kind ? publicKey ?? [] : nil }

    /// Go `Key.StaticValidate`: `Votes` 1~4,096, `Meta` 512바이트 이하, 종류 `Key25519`(동작 A1).
    package func validate() throws(TKAError) {
        guard (1...Self.maximumVotes).contains(votes), meta.byteCount <= Self.maximumMetaByteCount, kind == Self.ed25519Kind
        else { throw .invalidAUM }
    }
}

// MARK: CBOR

extension TrustedKey {
    private enum Field {
        static let kind: UInt64 = 1
        static let votes: UInt64 = 2
        static let publicKey: UInt64 = 3
        static let meta: UInt64 = 12
    }

    /// 정수 키 맵을 읽는다. 없는 필드와 null은 Go와 같이 0 값이다(동작 D5). 맵 자리의 null은 0 값의 키다.
    init(field value: CBORValue) throws(TKAError) {
        let fields = try StructureFields(value, knownKeys: [Field.kind, Field.votes, Field.publicKey, Field.meta])
        kind = UInt8(truncatingIfNeeded: try fields[Field.kind]?.unsignedField(maximum: UInt64(UInt8.max)) ?? 0)
        votes = try fields[Field.votes]?.unsignedField() ?? 0
        publicKey = try fields[Field.publicKey]?.byteField()
        meta = try fields[Field.meta]?.metaField() ?? []
    }

    /// `Kind`·`Votes`·`Public`은 늘, `Meta`는 비지 않을 때만 쓴다(동작 E4).
    func write(to writer: inout CBORWriter) {
        writer.mapHeader(count: meta.isEmpty ? 3 : 4)
        writer.unsigned(Field.kind)
        writer.unsigned(UInt64(kind))
        writer.unsigned(Field.votes)
        writer.unsigned(votes)
        writer.unsigned(Field.publicKey)
        writer.optionalByteString(publicKey)
        if !meta.isEmpty {
            writer.unsigned(Field.meta)
            writer.meta(meta)
        }
    }
}

extension CBORWriter {
    /// nil이면 null, 아니면 바이트열(omitempty가 아닌 `[]byte` 필드. 동작 E4).
    mutating func optionalByteString(_ value: [UInt8]?) {
        if let value { byteString(value) } else { null() }
    }
}
