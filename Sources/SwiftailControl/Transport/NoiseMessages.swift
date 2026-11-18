/// The byte layout of controlbase messages: initiation, response, error, and record.
///
/// All messages start with a 1-byte type and length (uint16 BE). Initiation alone prefixes them with the protocol version
/// (uint16 BE). Server bytes are parsed here once into validated types.
///
/// `docs/protocol-notes/control-transport.md` §3.1~§3.4
/// (origin: tailscale.com `control/controlbase/messages.go`, `conn.go`).
enum NoiseMessageType {
    static let initiation: UInt8 = 1
    static let response: UInt8 = 2
    /// Sent only by the server. Followed by an unauthenticated human-readable string.
    static let error: UInt8 = 3
    static let record: UInt8 = 4
}

/// The 3-byte header containing the type and length (except in initiation).
enum NoiseHeader {
    static let size = 3
}

/// Client → server initiation (101 bytes). Carried in the upgrade request header.
struct HandshakeInitiation: Equatable {
    static let payloadSize = 96

    var protocolVersion: UInt16
    /// The client's ephemeral public key (32 plaintext bytes).
    var ephemeralPublicKey: [UInt8]
    /// The client's machine public key as 32 bytes of ciphertext + a 16-byte tag.
    var encryptedMachineKey: [UInt8]
    /// The 16-byte tag for the empty payload.
    var tag: [UInt8]

    var bytes: [UInt8] {
        protocolVersion.bigEndianBytes
            + [NoiseMessageType.initiation]
            + UInt16(Self.payloadSize).bigEndianBytes
            + ephemeralPublicKey + encryptedMachineKey + tag
    }
}

/// Server → client response (51 bytes). Has no version field.
struct HandshakeResponse: Equatable {
    static let payloadSize = 48
    static let size = NoiseHeader.size + payloadSize

    /// The server's ephemeral public key (32 plaintext bytes).
    var ephemeralPublicKey: [UInt8]
    /// The 16-byte tag for the empty payload.
    var tag: [UInt8]

    /// Reads the Noise response from the start of the received bytes. Returns `nil` until enough bytes are available to decide.
    ///
    /// - Throws: `handshakeFailed` for a server error message (skips reading the unauthenticated string),
    ///   or `malformed` for an unknown type or a length other than 48.
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

/// A transport-phase record with type(4) ‖ length(uint16 BE) ‖ ciphertext + tag.
enum NoiseRecord {
    /// The limit on the complete record, including the header.
    static let maximumSize = 4096
    /// The maximum plaintext in one record = 4096 − 3-byte header − 16-byte tag.
    static let maximumPlaintextSize = maximumSize - NoiseHeader.size - NoiseAEAD.tagSize
}
