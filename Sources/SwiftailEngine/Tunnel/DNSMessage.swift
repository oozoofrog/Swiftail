// DNS message byte layout and parsing rules follow golang.org/x/net `dns/dnsmessage/message.go` (BSD-3-Clause,
// Copyright 2009 The Go Authors), and response size rules follow Tailscale's `net/dns/resolver/forwarder.go`
// (BSD-3-Clause, Copyright (c) Tailscale Inc & contributors). Only the rules and constants were ported. The code was written from scratch in Swift.

/// A DNS message codec covering what the MagicDNS responder handles (RFC 1035 4.1).
///
/// Any app inside the tunnel can send a query, so treat it as untrusted input. At the boundary, read only the header and first question once,
/// converting them to a validated value (`Query`), and write responses (`Response`) without name compression. Go's local responses also omit compression,
/// so the bytes match. There is no I/O.
///
/// `docs/protocol-notes/dns-state-node.md` 3.1 and 4.2.4, and `docs/contracts/SwiftailTunnel.md` behaviors D1 and D6.
enum DNSMessage {
    /// The header length includes the ID, flags, and counts for the four sections (2 bytes each, big-endian).
    static let headerLength = 12
    /// The maximum UDP response size when a query has no EDNS (RFC 1035 4.2.1).
    static let defaultUDPPayloadLimit = 512
    /// CLASS IN. All records in a response use this class.
    static let internetClass: UInt16 = 1

    /// The maximum UDP response size for a query. Notes 4.2.4 and Go `findOPTRecord` and `checkResponseSizeAndSetTC`.
    ///
    /// Uses the advertised size if ARCOUNT is not 0 and the last 11 message bytes are an EDNS 0 OPT record with no options (NAME 0, TYPE 41, version 0,
    /// RDLEN 0). Ignores OPT records with options or outside the last position and uses 512.
    /// Also applies to queries whose question could not be read (Go searches the original bytes).
    static func udpPayloadLimit(ofQuery message: [UInt8]) -> Int {
        let optLength = 11
        guard message.count >= headerLength + optLength, readUInt16(message, at: 10) != 0 else {
            return defaultUDPPayloadLimit
        }
        let opt = message.count - optLength
        guard message[opt] == 0,
              readUInt16(message, at: opt + 1) == RecordType.opt.rawValue,
              message[opt + 6] == 0,
              readUInt16(message, at: opt + 9) == 0
        else { return defaultUDPPayloadLimit }
        return Int(readUInt16(message, at: opt + 3))
    }

    /// Reads 2 big-endian bytes starting at `offset`. The caller validates the bounds.
    static func readUInt16(_ bytes: [UInt8], at offset: Int) -> UInt16 {
        UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
    }

    static func bigEndian(_ value: UInt16) -> [UInt8] {
        [UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value)]
    }

    static func bigEndian(_ value: UInt32) -> [UInt8] {
        [UInt8(truncatingIfNeeded: value >> 24), UInt8(truncatingIfNeeded: value >> 16),
         UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value)]
    }
}

// MARK: - Header

extension DNSMessage {
    /// The header ID and flags. Section counts are handled only when reading and writing the message.
    struct Header: Equatable, Sendable {
        /// The ID that pairs a query with its response. Responses reuse the query value verbatim.
        var id: UInt16
        var flags: Flags

        /// 16 bits of flags consisting of QR, Opcode (4), AA, TC, RD, RA, Z, AD, CD, and RCODE (4). RFC 1035 4.1.1, and RFC 4035 3.2 for AD and CD.
        struct Flags: OptionSet, Sendable {
            let rawValue: UInt16

            static let response = Flags(rawValue: 1 << 15)
            static let authoritative = Flags(rawValue: 1 << 10)
            static let truncated = Flags(rawValue: 1 << 9)
            static let recursionDesired = Flags(rawValue: 1 << 8)
            static let recursionAvailable = Flags(rawValue: 1 << 7)
            /// The reserved Z bit. Go `dnsmessage.Header` lacks this field, so Go responses always use 0.
            static let reserved = Flags(rawValue: 1 << 6)
            /// The position of the 4 RCODE bits.
            static let responseCodeBits = Flags(rawValue: 0x000F)
        }

        /// Reads the first 4 bytes of the message (ID and flags). Returns nil if fewer than the 12 header bytes are present.
        init?(parsing message: [UInt8]) {
            guard message.count >= DNSMessage.headerLength else { return nil }
            id = DNSMessage.readUInt16(message, at: 0)
            flags = Flags(rawValue: DNSMessage.readUInt16(message, at: 2))
        }

        init(id: UInt16, flags: Flags) {
            self.id = id
            self.flags = flags
        }

        /// Replaces the RCODE bits.
        mutating func setResponseCode(_ code: ResponseCode) {
            flags.subtract(.responseCodeBits)
            flags.insert(Flags(rawValue: code.rawValue))
        }
    }

    /// RCODE values used by the responder. RFC 1035 4.1.1.
    enum ResponseCode: UInt16, Sendable {
        case noError = 0
        case formatError = 1
        case serverFailure = 2
        case nameError = 3
        case notImplemented = 4
    }

    /// Record TYPE, including QTYPE. Also holds undefined values.
    struct RecordType: Hashable, Sendable {
        let rawValue: UInt16

        static let a = RecordType(rawValue: 1)
        static let ns = RecordType(rawValue: 2)
        static let soa = RecordType(rawValue: 6)
        static let ptr = RecordType(rawValue: 12)
        static let hinfo = RecordType(rawValue: 13)
        static let aaaa = RecordType(rawValue: 28)
        static let opt = RecordType(rawValue: 41)
        static let axfr = RecordType(rawValue: 252)
        /// QTYPE `*`(ANY). Go `dnsmessage.TypeALL`.
        static let any = RecordType(rawValue: 255)
    }
}
