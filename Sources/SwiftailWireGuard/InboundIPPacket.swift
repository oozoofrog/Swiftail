import SwiftailBase

/// The result of interpreting decrypted transport plaintext as an IP packet.
///
/// Treat the plaintext as untrusted even after authentication because the remote peer created it. Check the length once here,
/// strip padding using the IP header's length field, and extract the source address for the AllowedIPs check.
///
/// Whitepaper §5.4.6 (cryptokey routing), `docs/protocol-notes/wireguard.md` "Transport data: receiving" 8
/// (origin: wireguard-go `device/receive.go`).
struct InboundIPPacket {
    /// The IP packet with padding removed.
    let bytes: [UInt8]
    let source: IPAddress

    /// Returns `nil` if the version is neither 4 nor 6, the packet is shorter than its header, or the length field points past the plaintext.
    init?(plaintext: [UInt8]) {
        guard let first = plaintext.first else { return nil }
        let length: Int
        let sourceRange: Range<Int>
        switch first >> 4 {
        case 4:
            let headerLength = 20
            guard plaintext.count >= headerLength else { return nil }
            length = Self.bigEndianLength(plaintext, at: 2)
            guard (headerLength...plaintext.count).contains(length) else { return nil }
            sourceRange = 12..<16
        case 6:
            let headerLength = 40
            guard plaintext.count >= headerLength else { return nil }
            // Payload length + 40. Go performs this addition in UInt16, where it wraps. Here it is added in Int and compared directly.
            length = Self.bigEndianLength(plaintext, at: 4) + headerLength
            guard length <= plaintext.count else { return nil }
            sourceRange = 8..<24
        default:
            return nil
        }
        guard let source = IPAddress(bytes: plaintext[sourceRange]) else { return nil }
        // Without padding, the plaintext is the packet, so there is no copy.
        self.bytes = length == plaintext.count ? plaintext : Array(plaintext[..<length])
        self.source = source
    }

    /// Call only after checking the header length.
    private static func bigEndianLength(_ bytes: [UInt8], at offset: Int) -> Int {
        Int(bytes[offset]) << 8 | Int(bytes[offset + 1])
    }
}
