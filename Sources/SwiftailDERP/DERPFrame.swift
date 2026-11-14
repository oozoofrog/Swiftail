/// DERP 프레임: 5바이트 머리(타입 1, 본문 길이 4 BE) 뒤에 본문.
///
/// 바이트 경계는 TCP 조각과도 HTTP 응답 머리와도 무관하다. `DERPFrameReader`가 조각난 입력에서 프레임을 모은다.
///
/// `docs/protocol-notes/derp-stun.md` 3.1·3.2절 (출처: tailscale.com `derp/derp.go`, BSD-3-Clause).
struct DERPFrame: Sendable, Equatable {
    /// 알려진 프레임 타입. 모르는 타입은 `rawValue`로만 있고 본문을 건너뛴다.
    enum Kind: UInt8, Sendable {
        case serverKey = 0x01
        case clientInfo = 0x02
        case serverInfo = 0x03
        case sendPacket = 0x04
        case recvPacket = 0x05
        case keepAlive = 0x06
        case notePreferred = 0x07
        case peerGone = 0x08
        case peerPresent = 0x09
        case ping = 0x12
        case pong = 0x13
        case health = 0x14
        case restarting = 0x15
    }

    static let headerSize = 5
    /// 프레임 본문 앞의 키 길이(RecvPacket·SendPacket·PeerGone).
    static let keySize = 32
    /// 받은 프레임 본문의 한도(Go 클라이언트와 같다).
    static let maximumBody = 1 << 20

    let type: UInt8
    let body: [UInt8]

    var kind: Kind? { Kind(rawValue: type) }

    /// 보낼 프레임 한 덩어리. 본문은 호출하는 쪽이 이미 한도 안으로 줄였다(가장 큰 것이 SendPacket의 65,568바이트).
    static func encoded(_ kind: Kind, body: [UInt8]) -> [UInt8] {
        let length = UInt32(clamping: body.count)
        return [kind.rawValue,
                UInt8(truncatingIfNeeded: length >> 24), UInt8(truncatingIfNeeded: length >> 16),
                UInt8(truncatingIfNeeded: length >> 8), UInt8(truncatingIfNeeded: length)] + body
    }
}

/// 조각난 입력에서 프레임을 하나씩 꺼낸다.
///
/// 본문 길이는 머리 5바이트가 오면 곧바로 한도와 견준다. 본문이 다 오기를 기다리다가 한도를 넘는 메모리를 쌓지
/// 않는다. 읽은 만큼은 `start`만 옮기고, 앞부분 정리는 `compact()`가 한 번에 한다(작은 프레임이 많아도 입력 길이에
/// 비례한다).
struct DERPFrameReader: Sendable {
    private var buffer: [UInt8] = []
    private var start = 0

    mutating func append(_ bytes: [UInt8]) {
        buffer += bytes
    }

    /// 다음 프레임. 아직 다 오지 않았으면 nil.
    ///
    /// - Parameter maximumBody: 이 프레임의 본문 한도. 넘으면 `frameTooLarge`.
    mutating func nextFrame(maximumBody: Int) throws(DERPError) -> DERPFrame? {
        guard buffer.count - start >= DERPFrame.headerSize else { return nil }
        let length = buffer[(start + 1)..<(start + 5)].reduce(0) { $0 << 8 | Int($1) }
        guard length <= maximumBody else { throw .frameTooLarge }
        let end = start + DERPFrame.headerSize + length
        guard buffer.count >= end else { return nil }
        let frame = DERPFrame(type: buffer[start], body: Array(buffer[(start + DERPFrame.headerSize)..<end]))
        start = end
        return frame
    }

    /// 이미 꺼낸 앞부분을 버린다.
    mutating func compact() {
        buffer.removeSubrange(..<start)
        start = 0
    }

    /// 받아 둔 바이트를 모두 버린다.
    mutating func discard() {
        buffer = []
        start = 0
    }
}
