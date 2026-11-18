import SwiftailBase

/// A validated TCP segment that can be converted to or from IP packet bytes.
///
/// The connection state machine uses this value. Parsing bytes happens once at the edge (`init(parsingIPPacket:)`), so
/// later code does not recheck header lengths, options, or checksums. Serialization also produces the packet bytes from
/// this value in a single step
/// (`ipPacket(hopLimit:)`).
///
/// Stores only fields the state machine uses. Drops the urgent pointer, CWR, and ECE on receipt and sets them to 0 on
/// send. Uses only `SequenceNumber` for sequence and acknowledgment numbers.
///
/// Specifications: RFC 9293 §3.1 (header, checksum), §3.2 (options), RFC 7323 §2.2 (Window Scale), RFC 2018 §§2 and 3
/// (SACK-Permitted, SACK), `docs/protocol-notes/tcp-netstack.md` §3, `docs/contracts/SwiftailNetstack.md` behavior W.
package struct TCPSegment: Sendable, Equatable {
    /// Control bits. Contains the five the state machine uses.
    package struct Flags: OptionSet, Sendable {
        /// The bits used in the TCP header's flags byte (offset 13). Parsing drops the other bits (URG, ECE, CWR).
        package let rawValue: UInt8

        /// Creates flags from their bit values. Only the five bits above are meaningful.
        package init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        /// The sender has no more data to send.
        package static let fin = Flags(rawValue: 0x01)
        /// Synchronizes sequence numbers to open a connection.
        package static let syn = Flags(rawValue: 0x02)
        /// Resets the connection.
        package static let rst = Flags(rawValue: 0x04)
        /// The receiver passes data to the application immediately. The state machine does not use this flag.
        package static let psh = Flags(rawValue: 0x08)
        /// `acknowledgmentNumber` is meaningful.
        package static let ack = Flags(rawValue: 0x10)
    }

    /// The reason IP packet bytes could not be parsed as a segment. Each case drops only that packet and leaves the connection open.
    package enum ParseError: Error, Sendable, Equatable {
        /// The packet is not TCP (protocol 6). This includes IPv6 packets with preceding extension headers, since the
        /// parser does not follow the chain.
        case notTCP
        /// The length, version, or header length is invalid, the packet is fragmented, or an option length is invalid.
        case malformed
        /// The IPv4 header or TCP segment checksum is incorrect.
        case badChecksum
    }

    /// The source address and port.
    package var source: IPEndpoint
    /// The destination address and port.
    package var destination: IPEndpoint
    /// SEG.SEQ. With SYN set, this is ISS, the sequence number SYN itself consumes.
    package var sequenceNumber: SequenceNumber
    /// SEG.ACK. Meaningless when `.ack` is clear. Preserves the received value.
    package var acknowledgmentNumber: SequenceNumber
    /// The control bits.
    package var flags: Flags
    /// SEG.WND. The exact 16-bit value from the header, before window scaling. The state machine interprets non-SYN
    /// segments using the negotiated shift.
    package var window: UInt16
    /// The MSS option. Present only in segments with SYN set. Parsing replaces 0 with the default (536 for IPv4, 1220
    /// for IPv6). Returns `nil` if not advertised.
    package var maximumSegmentSize: UInt16?
    /// The Window Scale option shift. Present only in segments with SYN set. Parsing clamps values above 14 to 14 (RFC
    /// 7323 §2.3). Returns `nil` if not advertised.
    package var windowScale: UInt8?
    /// The SACK-Permitted option (RFC 2018 §2). Meaningful only in segments with SYN set. Parsing drops it from non-SYN segments.
    package var sackPermitted: Bool
    /// The SACK option blocks (RFC 2018 §3), in wire order. Present only in segments with SYN clear. Parsing validates
    /// only the format and does not interpret the numbers, such as whether the left edge precedes the right edge or
    /// falls within the window. More than 4 blocks cannot fit in the header when serializing.
    package var sackBlocks: [SACKBlock]
    /// The data.
    package var payload: [UInt8]

    /// One SACK block, the contiguous bytes `[leftEdge, rightEdge)` the receiver has buffered beyond a gap (RFC 2018 §3).
    package struct SACKBlock: Sendable, Equatable {
        /// The block's first sequence number.
        package var leftEdge: SequenceNumber
        /// The sequence number after the block's last byte.
        package var rightEdge: SequenceNumber

        /// Creates a block from its two edges without validating them.
        package init(leftEdge: SequenceNumber, rightEdge: SequenceNumber) {
            self.leftEdge = leftEdge
            self.rightEdge = rightEdge
        }
    }

    /// The maximum number of blocks one SACK option can carry. This is the largest n for which `2 + 8n` fits into the
    /// 40-byte option area (RFC 2018 §3).
    package static let maximumSACKBlockCount = 4

    /// Creates a segment from its fields without validating them. The state machine and tests construct these values.
    /// Received bytes enter only through `init(parsingIPPacket:)`. `ipPacket(hopLimit:)` includes `maximumSegmentSize`,
    /// `windowScale`, and `sackPermitted` only on segments with SYN set, and `sackBlocks` only on segments with SYN
    /// clear.
    package init(
        source: IPEndpoint,
        destination: IPEndpoint,
        sequenceNumber: SequenceNumber,
        acknowledgmentNumber: SequenceNumber = SequenceNumber(0),
        flags: Flags,
        window: UInt16 = 0,
        maximumSegmentSize: UInt16? = nil,
        windowScale: UInt8? = nil,
        sackPermitted: Bool = false,
        sackBlocks: [SACKBlock] = [],
        payload: [UInt8] = []
    ) {
        self.source = source
        self.destination = destination
        self.sequenceNumber = sequenceNumber
        self.acknowledgmentNumber = acknowledgmentNumber
        self.flags = flags
        self.window = window
        self.maximumSegmentSize = maximumSegmentSize
        self.windowScale = windowScale
        self.sackPermitted = sackPermitted
        self.sackBlocks = sackBlocks
        self.payload = payload
    }

    /// SEG.LEN, the number of data bytes plus 1 each for SYN and FIN (RFC 9293 §3.4). This is the segment's length in sequence space.
    package var sequenceLength: UInt32 {
        UInt32(clamping: payload.count) + (flags.contains(.syn) ? 1 : 0) + (flags.contains(.fin) ? 1 : 0)
    }
}
