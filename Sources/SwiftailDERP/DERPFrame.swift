/// A DERP frame with a 5-byte header (1 byte for the type and a 4-byte BE body length) followed by the body.
///
/// Byte boundaries are independent of TCP chunks and the HTTP response head. `DERPFrameReader` assembles frames from fragmented input.
///
/// `docs/protocol-notes/derp-stun.md` §3.1 and §3.2 (origin: tailscale.com `derp/derp.go`, BSD-3-Clause).
struct DERPFrame: Sendable, Equatable {
    /// A known frame type. Unknown types are represented only by `rawValue`, and their bodies are skipped.
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
    /// The key length at the start of a frame body (RecvPacket, SendPacket, PeerGone).
    static let keySize = 32
    /// The received frame body limit, matching the Go client.
    static let maximumBody = 1 << 20

    let type: UInt8
    let body: [UInt8]

    var kind: Kind? { Kind(rawValue: type) }

    /// One complete outgoing frame. The caller has already limited the body (the largest is SendPacket at 65,568 bytes).
    static func encoded(_ kind: Kind, body: [UInt8]) -> [UInt8] {
        let length = UInt32(clamping: body.count)
        return [kind.rawValue,
                UInt8(truncatingIfNeeded: length >> 24), UInt8(truncatingIfNeeded: length >> 16),
                UInt8(truncatingIfNeeded: length >> 8), UInt8(truncatingIfNeeded: length)] + body
    }
}

/// Takes frames one at a time from fragmented input.
///
/// Checks the body length against the limit as soon as the 5-byte header arrives. This avoids accumulating memory beyond the limit while
/// waiting for the complete body. Reading only advances `start`, and `compact()` discards the consumed prefix in one pass
/// (time is proportional to input length even with many small frames).
struct DERPFrameReader: Sendable {
    private var buffer: [UInt8] = []
    private var start = 0

    mutating func append(_ bytes: [UInt8]) {
        buffer += bytes
    }

    /// The next frame, or nil if it has yet to arrive in full.
    ///
    /// - Parameter maximumBody: The body limit for this frame. Throws `frameTooLarge` if exceeded.
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

    /// Discards the prefix already taken.
    mutating func compact() {
        buffer.removeSubrange(..<start)
        start = 0
    }

    /// Discards all buffered bytes.
    mutating func discard() {
        buffer = []
        start = 0
    }
}
