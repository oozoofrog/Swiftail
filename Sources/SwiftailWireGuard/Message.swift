/// The byte layout of the 4 WireGuard message types.
///
/// Each datagram received from the network is parsed here once into a validated type (`Message`). Later stages
/// do not revisit byte offsets. All integers are little-endian. The first 4 bytes are read as one LE `uint32` consisting of 1 type byte and
/// three bytes of 0. As a result, any reserved byte other than 0 produces an unknown type.
///
/// Whitepaper §5.4, `docs/protocol-notes/wireguard.md` "Wire format"
/// (origin: wireguard-go `device/noise-protocol.go`, `device/receive.go`).
enum Message {
    case initiation(Initiation, MessageMACs)
    case response(Response, MessageMACs)
    case cookieReply(CookieReply)
    case transportData(TransportData)

    /// Parses a datagram. Returns `malformed` if it is shorter than 32 bytes, has an unknown type,
    /// or is a handshake message with an incorrect size.
    init(parsing datagram: [UInt8]) throws(WireGuardError) {
        // wireguard-go discards messages shorter than MinMessageSize (32) before checking the type.
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

/// The two MACs at the end of a handshake message. mac1 always differs from 0, and mac2 differs from 0 only when a cookie has been received.
struct MessageMACs: Equatable {
    var mac1: [UInt8]
    var mac2: [UInt8]

    var bytes: [UInt8] { mac1 + mac2 }
}

/// Handshake initiation (type 1, 148 bytes). Initiator → responder.
struct Initiation: Equatable {
    static let type: UInt32 = 1
    static let size = 148

    var sender: UInt32
    /// The initiator's ephemeral public key (plaintext).
    var ephemeral: [UInt8]
    /// The initiator's 32-byte static public key + 16-byte tag.
    var encryptedStatic: [UInt8]
    /// 12-byte TAI64N + 16-byte tag.
    var encryptedTimestamp: [UInt8]

    /// The bytes preceding mac1 and mac2. The MAC is computed over these bytes.
    var bytesBeforeMACs: [UInt8] {
        Self.type.littleEndianBytes + sender.littleEndianBytes + ephemeral + encryptedStatic + encryptedTimestamp
    }
}

/// Handshake response (type 2, 92 bytes). Responder → initiator.
struct Response: Equatable {
    static let type: UInt32 = 2
    static let size = 92

    var sender: UInt32
    /// The sender field of the initiation that prompted the response.
    var receiver: UInt32
    var ephemeral: [UInt8]
    /// The 16-byte AEAD tag for empty plaintext. It proves that the responder authenticated the entire handshake.
    var encryptedNothing: [UInt8]

    var bytesBeforeMACs: [UInt8] {
        Self.type.littleEndianBytes + sender.littleEndianBytes + receiver.littleEndianBytes + ephemeral + encryptedNothing
    }
}

/// Cookie reply (type 3, 64 bytes). The responder sends it under load when it requires mac2.
struct CookieReply: Equatable {
    static let type: UInt32 = 3
    static let size = 64

    /// The sender field of the rejected handshake message.
    var receiver: UInt32
    /// The 24-byte XChaCha20 nonce.
    var nonce: [UInt8]
    /// 16-byte cookie + 16-byte tag.
    var encryptedCookie: [UInt8]

    var bytes: [UInt8] {
        Self.type.littleEndianBytes + receiver.littleEndianBytes + nonce + encryptedCookie
    }
}

/// Transport data (type 4). The 16-byte header is followed by the ciphertext of the padded IP packet and the tag.
struct TransportData: Equatable {
    static let type: UInt32 = 4
    static let headerSize = 16
    /// 16-byte header + 16-byte tag. This is also the size of a keepalive, which has empty plaintext.
    static let minimumSize = headerSize + 16

    /// The sender index the receiving side sent during the handshake.
    var receiver: UInt32
    /// The packet number. It is both the AEAD nonce and the input to the replay protection window.
    var counter: UInt64
    /// Ciphertext ‖ tag. References the received datagram's storage without copying it.
    var encryptedPacket: ArraySlice<UInt8>

    /// An array containing the 16-byte header (type, receiver, counter). Append the ciphertext and tag to complete the message.
    /// - Parameter capacity: The size of the complete message. Reserve it up front so there is only one allocation.
    static func header(receiver: UInt32, counter: UInt64, capacity: Int) -> [UInt8] {
        var header: [UInt8] = []
        header.reserveCapacity(capacity)
        header.appendLittleEndian(type)
        header.appendLittleEndian(receiver)
        header.appendLittleEndian(counter)
        return header
    }
}

/// Reads a message of already validated length from the beginning.
///
/// The caller checks the full message length first, which prevents out-of-bounds reads.
private struct ByteReader {
    private let bytes: [UInt8]
    private var offset = 0

    init(_ bytes: [UInt8]) { self.bytes = bytes }

    mutating func take(_ count: Int) -> [UInt8] {
        defer { offset += count }
        return Array(bytes[offset..<offset + count])
    }

    /// All remaining bytes. References the same storage without copying it.
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
    /// Appends in little-endian order.
    mutating func appendLittleEndian<Integer: FixedWidthInteger>(_ value: Integer) {
        for offset in 0..<(Integer.bitWidth / 8) {
            append(UInt8(truncatingIfNeeded: value >> (offset * 8)))
        }
    }
}

extension FixedWidthInteger {
    /// A little-endian byte sequence.
    var littleEndianBytes: [UInt8] {
        (0..<(Self.bitWidth / 8)).map { UInt8(truncatingIfNeeded: self >> ($0 * 8)) }
    }
}
