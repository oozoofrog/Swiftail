import SwiftailBase

/// A disco message before sealing, either Ping, Pong, or CallMeMaybe.
///
/// Handles only plaintext encoding and parsing (`DiscoPacket` handles the envelope and cryptography). Bytes from the peer are checked for
/// length and type and converted to this type at the single `init(parsing:)` entry point. Parsing never traps on any byte sequence.
///
/// Plaintext is `type(1) ‖ version(1) ‖ body` and version is 0 when sending. See notes 3.3 and 3.4 for the body layout.
/// Parsing is lenient as in Go. Ping and Pong ignore version and permit bytes after the body.
///
/// `docs/protocol-notes/disco-magicsock.md` §§3.3 and 3.4 (origin: tailscale.com `disco/disco.go`, BSD-3-Clause).
enum DiscoMessage: Sendable, Equatable {
    /// - nodeKey: The sender's node public key, or nil if absent or 0. The parser discards path MTU measurement padding.
    case ping(TransactionID, nodeKey: NodePublicKey?)
    /// - source: The observed source address of the Ping. On the wire, an IPv4 address arrives as a 16-byte IPv4-mapped IPv6 address. The parser converts it back to IPv4.
    case pong(TransactionID, source: IPEndpoint)
    /// The address list advertised by the peer. A version ≠ 0, a 0-byte body, or a body whose length is not a multiple of 18 yields an empty list without error (as in Go).
    case callMeMaybe([IPEndpoint])

    private enum Kind: UInt8 {
        case ping = 0x01
        case pong = 0x02
        case callMeMaybe = 0x03
    }

    private static let headerLength = 2
    private static let transactionIDLength = TransactionID.byteCount
    private static let pongBodyLength = transactionIDLength + endpointLength
    /// An address on the wire consists of a 16-byte IP address and a 2-byte big-endian port.
    private static let endpointLength = 18

    /// Parses decrypted plaintext.
    ///
    /// - Throws: `malformed` for fewer than 2 bytes or a body shorter than the minimum for its type. If the type is outside `0x01`–`0x03`, throws
    ///   `unknownType` (including peer relay types `0x04`–`0x09`, which Go parses and M4 discards).
    init(parsing plaintext: [UInt8]) throws(DiscoError) {
        guard plaintext.count >= Self.headerLength else { throw .malformed }
        guard let kind = Kind(rawValue: plaintext[0]) else { throw .unknownType(plaintext[0]) }
        let version = plaintext[1]
        let body = plaintext[Self.headerLength...]

        switch kind {
        case .ping:
            guard let txID = TransactionID(body.prefix(Self.transactionIDLength)) else { throw .malformed }
            // If at least 32 bytes follow the TxID and those first 32 bytes are not all 0, they contain a NodeKey. Otherwise the rest is padding.
            let extra = body.dropFirst(Self.transactionIDLength)
            let nodeKey = NodePublicKey(rawValue: extra.prefix(NodePublicKey.byteCount)).flatMap { $0.isZero ? nil : $0 }
            self = .ping(txID, nodeKey: nodeKey)

        case .pong:
            guard body.count >= Self.pongBodyLength,
                  let txID = TransactionID(body.prefix(Self.transactionIDLength)),
                  let source = Self.endpoint(from: body.dropFirst(Self.transactionIDLength).prefix(Self.endpointLength))
            else { throw .malformed }
            self = .pong(txID, source: source)

        case .callMeMaybe:
            guard version == 0, !body.isEmpty, body.count.isMultiple(of: Self.endpointLength) else {
                self = .callMeMaybe([])
                return
            }
            var endpoints: [IPEndpoint] = []
            endpoints.reserveCapacity(body.count / Self.endpointLength)
            var offset = body.startIndex
            while offset < body.endIndex {
                let end = offset + Self.endpointLength
                guard let endpoint = Self.endpoint(from: body[offset..<end]) else { throw .malformed }
                endpoints.append(endpoint)
                offset = end
            }
            self = .callMeMaybe(endpoints)
        }
    }

    /// The plaintext (type ‖ version 0 ‖ body). Sends Ping without padding, with a 12-byte body if `nodeKey` is nil or 0.
    var plaintext: [UInt8] {
        switch self {
        case .ping(let txID, let nodeKey):
            let key = nodeKey.flatMap { $0.isZero ? nil : $0.rawValue } ?? []
            return Self.header(.ping) + txID.bytes + key
        case .pong(let txID, let source):
            return Self.header(.pong) + txID.bytes + Self.wireBytes(of: source)
        case .callMeMaybe(let endpoints):
            return Self.header(.callMeMaybe) + endpoints.flatMap(Self.wireBytes(of:))
        }
    }

    private static func header(_ kind: Kind) -> [UInt8] {
        [kind.rawValue, 0]
    }

    /// Decodes an 18-byte wire address. Converts IPv4-mapped addresses (`::ffff:a.b.c.d`) back to IPv4.
    private static func endpoint(from bytes: ArraySlice<UInt8>) -> IPEndpoint? {
        guard bytes.count == endpointLength else { return nil }
        let ip = bytes.prefix(16)
        let isMapped = ip.prefix(10).allSatisfy { $0 == 0 } && ip.dropFirst(10).prefix(2).allSatisfy { $0 == 0xFF }
        guard let address = IPAddress(bytes: isMapped ? ip.suffix(4) : ip) else { return nil }
        let port = UInt16(bytes[bytes.startIndex + 16]) << 8 | UInt16(bytes[bytes.startIndex + 17])
        return IPEndpoint(address: address, port: port)
    }

    /// Encodes an address as 18 bytes on the wire. Stores IPv4 as IPv4-mapped IPv6.
    private static func wireBytes(of endpoint: IPEndpoint) -> [UInt8] {
        let ip = endpoint.address.isIPv4
            ? [UInt8](repeating: 0, count: 10) + [0xFF, 0xFF] + endpoint.address.bytes
            : endpoint.address.bytes
        return ip + [UInt8(endpoint.port >> 8), UInt8(endpoint.port & 0xFF)]
    }
}
