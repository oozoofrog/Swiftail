// AUM에 붙는 서명(Go `tkatype.Signature`, `tailscale.com/types/tkatype/tkatype.go:35-40`). 노트 3.3.
// Copyright (c) Tailscale Inc & contributors. BSD-3-Clause.

/// AUM에 붙는 서명 하나. 서명의 입력은 그 AUM의 `signatureHash`다(노트 3.7).
///
/// Go는 nil과 빈 슬라이스를 null과 빈 바이트열로 다르게 쓰지만, 정적 검사가 32·64바이트만 통과시키므로 여기서는 가리지 않는다
/// (동작 E6: 그 차이가 나는 AUM은 거절된다).
package struct AUMSignature: Sendable, Equatable {
    /// 서명한 신뢰 키의 KeyID. 정적 검사는 32바이트만 통과시킨다.
    package var keyID: [UInt8]
    /// Ed25519 서명. 정적 검사는 64바이트만 통과시킨다.
    package var signature: [UInt8]
}

// MARK: CBOR

extension AUMSignature {
    private enum Field {
        static let keyID: UInt64 = 1
        static let signature: UInt64 = 2
    }

    /// 정수 키 맵을 읽는다. 배열 원소의 null은 Go와 같이 0 값(빈 서명)이다(`fillNil`).
    init(element value: CBORValue) throws(TKAError) {
        let fields = try StructureFields(value, knownKeys: [Field.keyID, Field.signature])
        self.init(
            keyID: try fields[Field.keyID]?.byteField() ?? [],
            signature: try fields[Field.signature]?.byteField() ?? []
        )
    }

    /// 두 필드 모두 늘 쓴다(omitempty가 아니다. 동작 E4).
    func write(to writer: inout CBORWriter) {
        writer.mapHeader(count: 2)
        writer.unsigned(Field.keyID)
        writer.byteString(keyID)
        writer.unsigned(Field.signature)
        writer.byteString(signature)
    }
}
