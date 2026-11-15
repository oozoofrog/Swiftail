// 서명 권한 상태를 바꾸는 메시지(Go `tka.AUM`, `tailscale.com/tka/aum.go:132-288`). 노트 3.4·3.7, 계약 동작 E2~E6·D3~D9·A1.
// Copyright (c) Tailscale Inc & contributors. BSD-3-Clause.

/// 서명 권한 상태를 바꾸는 메시지 하나(Authority Update Message).
///
/// 받은 바이트를 쥐지 않는다. 해시와 서명 검증은 이 값을 다시 인코딩한 정준 바이트로 한다(동작 E5). 그래서 모르는 필드,
/// 비최단 정수, 정렬 안 된 키는 받아들이되 해시에서 사라진다.
package struct AUM: Sendable, Equatable {
    /// 종류(`Kind`). 0과 6 이상도 받아들인다(노트 3.4).
    package var messageKind: UInt8
    /// nil = 부모 없음(null로 인코딩). 길이 0인 바이트열은 null과 다르게 인코딩되고 정적 검사에서 떨어진다(동작 E4·A1).
    package var prevAUMHash: [UInt8]?
    /// AddKey가 더하는 키. 그 밖의 종류에서는 정적 검사가 nil만 통과시킨다.
    package var key: TrustedKey? = nil
    /// nil과 빈 바이트열은 둘 다 인코딩에서 빠지지만(omitempty) 정적 검사에서 다르다: AddKey·Checkpoint는 nil만 통과한다
    /// (Go `aum.go:189`, `:207`의 `a.KeyID != nil`).
    package var keyID: [UInt8]? = nil
    /// Checkpoint가 싣는 상태 전체. 그 밖의 종류에서는 정적 검사가 nil만 통과시킨다.
    package var state: AuthorityState? = nil
    /// 0이어도 있으면 인코딩한다(Go `*uint`, omitempty).
    package var votes: UInt64? = nil
    /// nil과 빈 맵은 검증에서만 다르다(인코딩에서는 둘 다 빠진다).
    package var meta: [MetaEntry]? = nil
    /// 신뢰 키의 서명들. 해시(`hash`)에는 들고 서명의 입력(`signatureHash`)에는 들지 않으므로, 같은 서명을 되풀이하거나
    /// 순서를 바꾼 목록은 해시가 다른 "유효한" AUM이다(계약 5절 TL-11a 항목 1).
    package var signatures: [AUMSignature] = []

    /// AUM 하나의 바이트 한도(동작 M, Swiftail의 선택).
    static let maximumByteCount = 512 * 1_024

    /// `MessageKind`의 값(Go `AUMKind`, 노트 3.4).
    enum Kind {
        static let invalid: UInt8 = 0
        static let addKey: UInt8 = 1
        static let removeKey: UInt8 = 2
        static let noOp: UInt8 = 3
        static let updateKey: UInt8 = 4
        static let checkpoint: UInt8 = 5
    }

    /// 정준 CBOR(동작 E1~E4). 해시와 서명 검증은 받은 바이트가 아니라 이것으로 한다(동작 E5).
    package func serialized() -> [UInt8] {
        var writer = CBORWriter()
        write(to: &writer, includingSignatures: true)
        return writer.bytes
    }

    /// BLAKE2s-256(`serialized()`). 서명을 포함한다(노트 3.7).
    package var hash: AUMHash { AUMHash(hashing: serialized()) }

    /// `Signatures`를 뺀 정준 바이트의 BLAKE2s-256. 서명은 이 32바이트에 대한 것이다(노트 3.7).
    package var signatureHash: [UInt8] {
        var writer = CBORWriter()
        write(to: &writer, includingSignatures: false)
        return AUMHash(hashing: writer.bytes).bytes
    }

    /// Go `AUM.StaticValidate`(동작 A1). 서명과 부모는 보지 않는다(동작 A2·A3은 `Authority`가 한다).
    package func validate() throws(TKAError) {
        try key?.validate()
        if let prevAUMHash, prevAUMHash.isEmpty { throw .invalidAUM }
        guard signatures.allSatisfy({ $0.keyID.count == 32 && $0.signature.count == 64 }) else { throw .invalidAUM }
        try state?.validateAsCheckpoint()

        let isValid =
            switch messageKind {
            case Kind.addKey:
                key != nil && keyID == nil && state == nil && votes == nil && meta == nil
            case Kind.removeKey:
                !(keyID ?? []).isEmpty && key == nil && state == nil && votes == nil && meta == nil
            case Kind.updateKey:
                !(keyID ?? []).isEmpty && (votes != nil || meta != nil) && key == nil && state == nil
            case Kind.checkpoint:
                state != nil && keyID == nil && key == nil && votes == nil && meta == nil
            default:
                // NoOp와 모르는 종류는 종류별 검사가 없다(옛 클라이언트는 무시해도 된다는 Go의 계약).
                true
            }
        guard isValid else { throw .invalidAUM }
    }
}

// MARK: CBOR

extension AUM {
    /// 한도(동작 M)와 동작 D의 규칙으로 읽는다. 정적 검사는 하지 않는다. 멤버별 생성자가 남도록 확장에 둔다.
    package init(decoding bytes: [UInt8]) throws(TKAError) {
        try self.init(item: decodeItem(bytes, maximumByteCount: Self.maximumByteCount))
    }

    private enum Field {
        static let messageKind: UInt64 = 1
        static let prevAUMHash: UInt64 = 2
        static let key: UInt64 = 3
        static let keyID: UInt64 = 4
        static let state: UInt64 = 5
        static let votes: UInt64 = 6
        static let meta: UInt64 = 7
        static let signatures: UInt64 = 23
    }

    private init(item: CBORValue) throws(TKAError) {
        let fields = try StructureFields(
            item,
            knownKeys: [
                Field.messageKind, Field.prevAUMHash, Field.key, Field.keyID, Field.state, Field.votes, Field.meta,
                Field.signatures,
            ]
        )
        messageKind = UInt8(
            truncatingIfNeeded: try fields[Field.messageKind]?.unsignedField(maximum: UInt64(UInt8.max)) ?? 0
        )
        prevAUMHash = try fields[Field.prevAUMHash]?.byteField()
        // 포인터 필드(`Key`·`State`·`Votes`)의 null은 없음이다.
        if let value = fields[Field.key], value != .null {
            key = try TrustedKey(field: value)
        }
        keyID = try fields[Field.keyID]?.byteField()
        if let value = fields[Field.state], value != .null {
            state = try AuthorityState(checkpointField: value)
        }
        if let value = fields[Field.votes], value != .null {
            votes = try value.unsignedField()
        }
        meta = try fields[Field.meta]?.metaField()
        for element in try fields[Field.signatures]?.arrayField() ?? [] {
            signatures.append(try AUMSignature(element: element))
        }
    }

    /// 키 순서대로 쓴다(동작 E2). `MessageKind`·`PrevAUMHash`는 늘, 나머지는 비지 않을 때만 쓴다(동작 E4).
    private func write(to writer: inout CBORWriter, includingSignatures: Bool) {
        let keyID = keyID ?? []
        let meta = meta ?? []
        let signatures = includingSignatures ? signatures : []
        let present = [key != nil, !keyID.isEmpty, state != nil, votes != nil, !meta.isEmpty, !signatures.isEmpty]
        writer.mapHeader(count: 2 + present.count(where: \.self))

        writer.unsigned(Field.messageKind)
        writer.unsigned(UInt64(messageKind))
        writer.unsigned(Field.prevAUMHash)
        writer.optionalByteString(prevAUMHash)
        if let key {
            writer.unsigned(Field.key)
            key.write(to: &writer)
        }
        if !keyID.isEmpty {
            writer.unsigned(Field.keyID)
            writer.byteString(keyID)
        }
        if let state {
            writer.unsigned(Field.state)
            state.write(to: &writer)
        }
        if let votes {
            writer.unsigned(Field.votes)
            writer.unsigned(votes)
        }
        if !meta.isEmpty {
            writer.unsigned(Field.meta)
            writer.meta(meta)
        }
        if !signatures.isEmpty {
            writer.unsigned(Field.signatures)
            writer.arrayHeader(count: signatures.count)
            for signature in signatures {
                signature.write(to: &writer)
            }
        }
    }
}
