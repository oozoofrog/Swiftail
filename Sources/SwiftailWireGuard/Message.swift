/// WireGuard 메시지 4종의 바이트 배치.
///
/// 네트워크에서 받은 데이터그램은 여기서 한 번 해석해 검증된 타입(`Message`)이 된다. 이후 단계는
/// 바이트 오프셋을 다시 다루지 않는다. 모든 정수는 little-endian이고, 첫 4바이트는 type 1바이트와
/// 0 세 바이트를 LE `uint32` 하나로 읽는다. 그래서 예약 바이트가 0이 아니면 모르는 type이 된다.
///
/// 백서 §5.4, `docs/protocol-notes/wireguard.md` "와이어 형식"
/// (출처: wireguard-go `device/noise-protocol.go`, `device/receive.go`).
enum Message {
    case initiation(Initiation, MessageMACs)
    case response(Response, MessageMACs)
    case cookieReply(CookieReply)
    case transportData(TransportData)

    /// 데이터그램 하나를 해석한다. 32바이트보다 짧거나, 모르는 type이거나,
    /// 핸드셰이크 메시지의 크기가 정확하지 않으면 `malformed`.
    init(parsing datagram: [UInt8]) throws(WireGuardError) {
        // wireguard-go는 MinMessageSize(32)보다 짧으면 type도 보지 않고 버린다.
        guard datagram.count >= TransportData.minimumSize else { throw .malformed }
        var reader = ByteReader(datagram)
        switch reader.uint32() {
        case Initiation.type:
            guard datagram.count == Initiation.size else { throw .malformed }
            let message = Initiation(
                sender: reader.uint32(),
                ephemeral: reader.take(32),
                encryptedStatic: reader.take(32 + 16),
                encryptedTimestamp: reader.take(TAI64N.size + 16)
            )
            self = .initiation(message, MessageMACs(mac1: reader.take(16), mac2: reader.take(16)))
        case Response.type:
            guard datagram.count == Response.size else { throw .malformed }
            let message = Response(
                sender: reader.uint32(),
                receiver: reader.uint32(),
                ephemeral: reader.take(32),
                encryptedNothing: reader.take(16)
            )
            self = .response(message, MessageMACs(mac1: reader.take(16), mac2: reader.take(16)))
        case CookieReply.type:
            guard datagram.count == CookieReply.size else { throw .malformed }
            self = .cookieReply(CookieReply(receiver: reader.uint32(), nonce: reader.take(24), encryptedCookie: reader.take(16 + 16)))
        case TransportData.type:
            self = .transportData(TransportData(receiver: reader.uint32(), counter: reader.uint64(), encryptedPacket: reader.rest()))
        default:
            throw .malformed
        }
    }
}

/// 핸드셰이크 메시지 끝의 두 MAC. mac1은 늘, mac2는 받은 cookie가 있을 때만 0이 아니다.
struct MessageMACs: Equatable {
    var mac1: [UInt8]
    var mac2: [UInt8]

    var bytes: [UInt8] { mac1 + mac2 }
}

/// Handshake initiation(type 1, 148바이트). 초기자 → 응답자.
struct Initiation: Equatable {
    static let type: UInt32 = 1
    static let size = 148

    var sender: UInt32
    /// 초기자의 임시 공개 키(평문).
    var ephemeral: [UInt8]
    /// 초기자의 정적 공개 키 32 + 태그 16.
    var encryptedStatic: [UInt8]
    /// TAI64N 12 + 태그 16.
    var encryptedTimestamp: [UInt8]

    /// mac1·mac2 앞까지의 바이트. MAC은 이 바이트 위에서 계산한다.
    var bytesBeforeMACs: [UInt8] {
        Self.type.littleEndianBytes + sender.littleEndianBytes + ephemeral + encryptedStatic + encryptedTimestamp
    }
}

/// Handshake response(type 2, 92바이트). 응답자 → 초기자.
struct Response: Equatable {
    static let type: UInt32 = 2
    static let size = 92

    var sender: UInt32
    /// 응답을 부른 initiation의 sender.
    var receiver: UInt32
    var ephemeral: [UInt8]
    /// 빈 평문의 AEAD 태그 16바이트. 응답자가 핸드셰이크 전체를 인증했다는 증거다.
    var encryptedNothing: [UInt8]

    var bytesBeforeMACs: [UInt8] {
        Self.type.littleEndianBytes + sender.littleEndianBytes + receiver.littleEndianBytes + ephemeral + encryptedNothing
    }
}

/// Cookie reply(type 3, 64바이트). 부하 상태의 응답자가 mac2를 요구할 때 보낸다.
struct CookieReply: Equatable {
    static let type: UInt32 = 3
    static let size = 64

    /// 거절된 핸드셰이크 메시지의 sender.
    var receiver: UInt32
    /// XChaCha20 nonce 24바이트.
    var nonce: [UInt8]
    /// cookie 16 + 태그 16.
    var encryptedCookie: [UInt8]

    var bytes: [UInt8] {
        Self.type.littleEndianBytes + receiver.littleEndianBytes + nonce + encryptedCookie
    }
}

/// Transport data(type 4). 머리 16바이트 뒤에 패딩한 IP 패킷의 암호문과 태그가 온다.
struct TransportData: Equatable {
    static let type: UInt32 = 4
    static let headerSize = 16
    /// 머리 16 + 태그 16. 평문이 비어 있는 keepalive의 크기이기도 하다.
    static let minimumSize = headerSize + 16

    /// 받는 쪽이 핸드셰이크 때 보낸 sender index.
    var receiver: UInt32
    /// 패킷 번호. AEAD nonce이자 재전송 방지 창의 입력이다.
    var counter: UInt64
    /// 암호문 ‖ 태그. 받은 데이터그램의 저장소를 그대로 가리키며 복사하지 않는다.
    var encryptedPacket: ArraySlice<UInt8>

    /// 머리 16바이트(type, receiver, counter)를 쓴 배열. 뒤에 암호문과 태그를 붙여 메시지를 완성한다.
    /// - Parameter capacity: 완성한 메시지의 크기. 한 번만 할당하도록 미리 잡아 둔다.
    static func header(receiver: UInt32, counter: UInt64, capacity: Int) -> [UInt8] {
        var header: [UInt8] = []
        header.reserveCapacity(capacity)
        header.appendLittleEndian(type)
        header.appendLittleEndian(receiver)
        header.appendLittleEndian(counter)
        return header
    }
}

/// 길이를 이미 확인한 메시지를 앞에서부터 읽는다.
///
/// 호출하는 쪽이 메시지 전체 길이를 먼저 확인하므로 범위 밖을 읽지 않는다.
private struct ByteReader {
    private let bytes: [UInt8]
    private var offset = 0

    init(_ bytes: [UInt8]) { self.bytes = bytes }

    mutating func take(_ count: Int) -> [UInt8] {
        defer { offset += count }
        return Array(bytes[offset..<offset + count])
    }

    /// 남은 바이트 전부. 복사하지 않고 같은 저장소를 가리킨다.
    mutating func rest() -> ArraySlice<UInt8> {
        defer { offset = bytes.count }
        return bytes[offset...]
    }

    mutating func uint32() -> UInt32 {
        UInt32(truncatingIfNeeded: littleEndian(count: 4))
    }

    mutating func uint64() -> UInt64 {
        littleEndian(count: 8)
    }

    private mutating func littleEndian(count: Int) -> UInt64 {
        defer { offset += count }
        return bytes[offset..<offset + count].reversed().reduce(0) { $0 << 8 | UInt64($1) }
    }
}

extension [UInt8] {
    /// little-endian으로 덧붙인다.
    mutating func appendLittleEndian<Integer: FixedWidthInteger>(_ value: Integer) {
        for offset in 0..<(Integer.bitWidth / 8) {
            append(UInt8(truncatingIfNeeded: value >> (offset * 8)))
        }
    }
}

extension FixedWidthInteger {
    /// little-endian 바이트열.
    var littleEndianBytes: [UInt8] {
        (0..<(Self.bitWidth / 8)).map { UInt8(truncatingIfNeeded: self >> ($0 * 8)) }
    }
}
