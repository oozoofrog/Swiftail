/// controlbase 메시지의 바이트 배치: initiation, response, error, record.
///
/// 모든 메시지는 type 1바이트와 길이(uint16 BE)로 시작한다. initiation만 그 앞에 프로토콜 버전
/// (uint16 BE)이 붙는다. 서버가 보낸 바이트는 여기서 한 번 해석해 검증된 타입이 된다.
///
/// `docs/protocol-notes/control-transport.md` 3.1~3.4절
/// (출처: tailscale.com `control/controlbase/messages.go`, `conn.go`).
enum NoiseMessageType {
    static let initiation: UInt8 = 1
    static let response: UInt8 = 2
    /// 서버만 보낸다. 인증되지 않은 사람용 문자열이 따른다.
    static let error: UInt8 = 3
    static let record: UInt8 = 4
}

/// type과 길이로 된 3바이트 머리(initiation 제외).
enum NoiseHeader {
    static let size = 3
}

/// 클라이언트 → 서버 initiation(101바이트). 업그레이드 요청 헤더에 실린다.
struct HandshakeInitiation: Equatable {
    static let payloadSize = 96

    var protocolVersion: UInt16
    /// 클라이언트 임시 공개 키(평문 32).
    var ephemeralPublicKey: [UInt8]
    /// 클라이언트 machine 공개 키 암호문 32 + 태그 16.
    var encryptedMachineKey: [UInt8]
    /// 빈 페이로드의 태그 16.
    var tag: [UInt8]

    var bytes: [UInt8] {
        protocolVersion.bigEndianBytes
            + [NoiseMessageType.initiation]
            + UInt16(Self.payloadSize).bigEndianBytes
            + ephemeralPublicKey + encryptedMachineKey + tag
    }
}

/// 서버 → 클라이언트 response(51바이트). 버전 필드는 없다.
struct HandshakeResponse: Equatable {
    static let payloadSize = 48
    static let size = NoiseHeader.size + payloadSize

    /// 서버 임시 공개 키(평문 32).
    var ephemeralPublicKey: [UInt8]
    /// 빈 페이로드의 태그 16.
    var tag: [UInt8]

    /// 받은 바이트의 앞부분에서 response를 읽는다. 판단하기에 바이트가 모자라면 `nil`.
    ///
    /// - Throws: 서버의 error 메시지면 `handshakeFailed`(문자열은 인증되지 않으므로 읽지 않는다),
    ///   모르는 type이거나 길이가 48이 아니면 `malformed`.
    init?(parsingPrefixOf bytes: [UInt8]) throws(ControlTransportError) {
        guard bytes.count >= NoiseHeader.size else { return nil }
        switch bytes[0] {
        case NoiseMessageType.response:
            guard UInt16(bigEndianBytes: bytes[1..<3]) == Self.payloadSize else { throw .malformed }
            guard bytes.count >= Self.size else { return nil }
            ephemeralPublicKey = Array(bytes[3..<35])
            tag = Array(bytes[35..<Self.size])
        case NoiseMessageType.error:
            throw .handshakeFailed
        default:
            throw .malformed
        }
    }
}

/// 전송 단계 레코드: type(4) ‖ 길이(uint16 BE) ‖ 암호문 + 태그.
enum NoiseRecord {
    /// 머리를 포함한 레코드 전체의 한도.
    static let maximumSize = 4096
    /// 한 레코드에 담을 수 있는 평문의 최대 = 4096 − 머리 3 − 태그 16.
    static let maximumPlaintextSize = maximumSize - NoiseHeader.size - NoiseAEAD.tagSize
}
