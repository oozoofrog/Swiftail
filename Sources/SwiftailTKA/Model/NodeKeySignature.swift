// node 키에 대한 서명(Go `tka.NodeKeySignature`, `tailscale.com/tka/sig.go:74-242`). 노트 3.6·3.7, 계약 동작 E2·E4·E5·D·M.

/// node 키에 대한 서명(NKS). 검증은 `Authority`가 한다(동작 S). 여기는 읽기·정준 쓰기·`SigHash`까지다.
///
/// 바이트 필드는 모두 omitempty라 nil과 빈 값을 가리지 않는다(노트 3.6).
package struct NodeKeySignature: Sendable, Equatable {
    /// 1 direct, 2 rotation, 3 credential(`Kind`).
    package var kind: UInt8
    /// `"np"` ‖ node 공개 키 32바이트. credential은 비운다.
    package var publicKey: [UInt8]
    /// 서명한 신뢰 키의 KeyID. direct·credential만 쓴다.
    package var keyID: [UInt8]
    /// Ed25519 서명. 입력은 `signatureHash`다.
    package var signature: [UInt8]
    /// 이 서명을 감싸는 서명에 서명할 Ed25519 공개 키.
    package var wrappingPublicKey: [UInt8]
    /// `Nested`의 자리. 값 타입은 자기 자신을 바로 담지 못하므로 `indirect` 열거형으로 간접 저장한다.
    private var nestedLink: Link?

    /// rotation이 감싸는 서명.
    package var nested: NodeKeySignature? {
        get {
            guard case .signature(let signature) = nestedLink else { return nil }
            return signature
        }
        set { nestedLink = newValue.map(Link.signature) }
    }

    private indirect enum Link: Sendable, Equatable {
        case signature(NodeKeySignature)
    }

    /// NKS 하나의 바이트 한도(동작 M, Swiftail의 선택. 16겹이 약 3KiB).
    static let maximumByteCount = 8 * 1_024

    /// `SigKind`의 값(노트 3.6).
    enum Kind {
        static let invalid: UInt8 = 0
        static let direct: UInt8 = 1
        static let rotation: UInt8 = 2
        static let credential: UInt8 = 3
    }

    init(
        kind: UInt8, publicKey: [UInt8] = [], keyID: [UInt8] = [], signature: [UInt8] = [],
        nested: NodeKeySignature? = nil, wrappingPublicKey: [UInt8] = []
    ) {
        self.kind = kind
        self.publicKey = publicKey
        self.keyID = keyID
        self.signature = signature
        self.wrappingPublicKey = wrappingPublicKey
        self.nested = nested
    }

    /// 한도(8KiB)와 동작 D의 규칙으로 읽는다. 서명은 검증하지 않는다.
    package init(decoding bytes: [UInt8]) throws(TKAError) {
        try self.init(item: decodeItem(bytes, maximumByteCount: Self.maximumByteCount))
    }

    /// 정준 CBOR(동작 E1~E4). `RegisterRequest`·`Node.KeySignature`에 싣는 바이트다.
    package func serialized() -> [UInt8] {
        var writer = CBORWriter()
        write(to: &writer)
        return writer.bytes
    }

    /// `Signature`를 뺀 정준 바이트의 BLAKE2s-256. `Nested`는 서명까지 그대로 들어간다(노트 3.7).
    package var signatureHash: [UInt8] {
        var unsigned = self
        unsigned.signature = []
        return AUMHash(hashing: unsigned.serialized()).bytes
    }
}

// MARK: CBOR

extension NodeKeySignature {
    private enum Field {
        static let kind: UInt64 = 1
        static let publicKey: UInt64 = 2
        static let keyID: UInt64 = 3
        static let signature: UInt64 = 4
        static let nested: UInt64 = 5
        static let wrappingPublicKey: UInt64 = 6
    }

    /// 재귀의 깊이는 CBOR의 중첩 한도(16단)가 묶는다.
    private init(item: CBORValue) throws(TKAError) {
        let fields = try StructureFields(
            item,
            knownKeys: [Field.kind, Field.publicKey, Field.keyID, Field.signature, Field.nested, Field.wrappingPublicKey]
        )
        var nested: NodeKeySignature?
        // 포인터 필드의 null은 없음이다.
        if let value = fields[Field.nested], value != .null {
            nested = try NodeKeySignature(item: value)
        }
        self.init(
            kind: UInt8(truncatingIfNeeded: try fields[Field.kind]?.unsignedField(maximum: UInt64(UInt8.max)) ?? 0),
            publicKey: try fields[Field.publicKey]?.byteField() ?? [],
            keyID: try fields[Field.keyID]?.byteField() ?? [],
            signature: try fields[Field.signature]?.byteField() ?? [],
            nested: nested,
            wrappingPublicKey: try fields[Field.wrappingPublicKey]?.byteField() ?? []
        )
    }

    /// 키 순서대로 쓴다. `SigKind`는 늘, 나머지는 비지 않을 때만 쓴다(동작 E4).
    private func write(to writer: inout CBORWriter) {
        let nested = nested
        let present = [!publicKey.isEmpty, !keyID.isEmpty, !signature.isEmpty, nested != nil, !wrappingPublicKey.isEmpty]
        writer.mapHeader(count: 1 + present.count(where: \.self))
        writer.unsigned(Field.kind)
        writer.unsigned(UInt64(kind))
        if !publicKey.isEmpty {
            writer.unsigned(Field.publicKey)
            writer.byteString(publicKey)
        }
        if !keyID.isEmpty {
            writer.unsigned(Field.keyID)
            writer.byteString(keyID)
        }
        if !signature.isEmpty {
            writer.unsigned(Field.signature)
            writer.byteString(signature)
        }
        if let nested {
            writer.unsigned(Field.nested)
            nested.write(to: &writer)
        }
        if !wrappingPublicKey.isEmpty {
            writer.unsigned(Field.wrappingPublicKey)
            writer.byteString(wrappingPublicKey)
        }
    }
}
