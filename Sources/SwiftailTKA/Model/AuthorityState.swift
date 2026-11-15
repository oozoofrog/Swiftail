// 신뢰 상태(Go `tka.State`, `tailscale.com/tka/state.go:26-53`, `:258-316`). 노트 3.5, 계약 동작 E4·E6·D8·A1.
// Copyright (c) Tailscale Inc & contributors. BSD-3-Clause.

/// 어느 AUM까지 적용한 뒤의 신뢰 상태. 체크포인트 AUM은 이것을 통째로 싣는다.
///
/// 배열의 nil과 빈 값, 원소의 nil과 빈 바이트열은 가리지 않는다: 받아들여지는 체크포인트에서는 배열이 비지 않고 원소가
/// 32바이트다(동작 E6).
package struct AuthorityState: Sendable, Equatable {
    /// 마지막으로 적용한 AUM의 해시. 체크포인트 안의 상태에서는 늘 nil이다(동작 D8).
    package var lastAUMHash: AUMHash?
    /// 끄기 비밀의 KDF 값(각 32바이트).
    package var disablementValues: [[UInt8]] = []
    /// 신뢰 키. 순서가 있다: KeyID로 찾을 때 앞에서부터 본다(Go `GetKey`).
    package var keys: [TrustedKey] = []
    /// lock을 켤 때 정한 난수. 0이면 인코딩에서 빠진다(omitempty).
    package var stateID1: UInt64 = 0
    /// `stateID1`과 함께 tailnet의 lock을 가린다. 체크포인트는 두 값이 부모 상태와 같아야 적용된다. 0이면 인코딩에서 빠진다.
    package var stateID2: UInt64 = 0

    /// 끄기 값의 개수 상한과 길이(Go `maxDisablementValues`, `disablementLength`).
    static let maximumDisablementValueCount = 32
    static let disablementValueByteCount = 32
    /// 키 개수의 상한(Go `maxKeys`).
    static let maximumKeyCount = 512

    /// 체크포인트에 실을 상태의 정적 검사(Go `staticValidateCheckpoint`, 동작 A1): `LastAUMHash` 없음, 끄기 값 1~32개·각 32바이트·
    /// 서로 다름, 키 1~512개·각각 검사 통과·KeyID 서로 다름.
    func validateAsCheckpoint() throws(TKAError) {
        guard lastAUMHash == nil,
            (1...Self.maximumDisablementValueCount).contains(disablementValues.count),
            disablementValues.allSatisfy({ $0.count == Self.disablementValueByteCount }),
            Set(disablementValues).count == disablementValues.count,
            (1...Self.maximumKeyCount).contains(keys.count)
        else { throw .invalidAUM }
        var keyIDs: Set<[UInt8]> = []
        for key in keys {
            try key.validate()
            // 검사를 통과한 키는 `Key25519`라 KeyID가 있다.
            guard let keyID = key.keyID, keyIDs.insert(keyID).inserted else { throw .invalidAUM }
        }
    }
}

// MARK: CBOR

extension AuthorityState {
    private enum Field {
        static let lastAUMHash: UInt64 = 1
        static let disablementValues: UInt64 = 2
        static let keys: UInt64 = 3
        static let stateID1: UInt64 = 4
        static let stateID2: UInt64 = 5
    }

    /// 체크포인트 AUM의 `State`를 읽는다. `LastAUMHash`가 null이 아니면 거절한다(동작 D8, Swiftail의 선택).
    ///
    /// Go는 바이트열이면 길이와 관계없이 32바이트 칸에 채워 읽고 정적 검사에서 거절한다. 그 AUM이 거절된다는 판정은 같다.
    init(checkpointField value: CBORValue) throws(TKAError) {
        let fields = try StructureFields(
            value,
            knownKeys: [Field.lastAUMHash, Field.disablementValues, Field.keys, Field.stateID1, Field.stateID2]
        )
        guard (fields[Field.lastAUMHash] ?? .null) == .null else { throw .invalidStructure }
        var disablementValues: [[UInt8]] = []
        for element in try fields[Field.disablementValues]?.arrayField() ?? [] {
            disablementValues.append(try element.byteField() ?? [])
        }
        var keys: [TrustedKey] = []
        for element in try fields[Field.keys]?.arrayField() ?? [] {
            // 원소의 null은 Go와 같이 0 값의 키다(`fillNil`). 정적 검사에서 떨어진다.
            keys.append(try TrustedKey(field: element))
        }
        self.init(
            lastAUMHash: nil,
            disablementValues: disablementValues,
            keys: keys,
            stateID1: try fields[Field.stateID1]?.unsignedField() ?? 0,
            stateID2: try fields[Field.stateID2]?.unsignedField() ?? 0
        )
    }

    /// `LastAUMHash`(없으면 null)·`DisablementValues`·`Keys`는 늘, `StateID1/2`는 0이 아닐 때만 쓴다(동작 E4).
    func write(to writer: inout CBORWriter) {
        writer.mapHeader(count: 3 + (stateID1 == 0 ? 0 : 1) + (stateID2 == 0 ? 0 : 1))
        writer.unsigned(Field.lastAUMHash)
        writer.optionalByteString(lastAUMHash?.bytes)
        writer.unsigned(Field.disablementValues)
        writer.arrayHeader(count: disablementValues.count)
        for value in disablementValues {
            writer.byteString(value)
        }
        writer.unsigned(Field.keys)
        writer.arrayHeader(count: keys.count)
        for key in keys {
            key.write(to: &writer)
        }
        if stateID1 != 0 {
            writer.unsigned(Field.stateID1)
            writer.unsigned(stateID1)
        }
        if stateID2 != 0 {
            writer.unsigned(Field.stateID2)
            writer.unsigned(stateID2)
        }
    }
}
