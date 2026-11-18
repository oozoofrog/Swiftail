import SwiftailBase

/// The Internet checksum for reply packets (RFC 1071). The same sum applies to the IPv4 header, UDP, TCP, and ICMPv6 (with pseudo-headers), and ICMPv4.
///
/// `InternetChecksum` in `SwiftailBase` computes the sum and pseudo-header (the same calculation as netstack).
///
/// Protocols differ only in the checksum field offset, whether the sum includes a pseudo-header, and how a computed 0 is represented. The field
/// must be 0 before computation.
///
/// RFC 1071 (sum), RFC 768 (UDP, IPv4 pseudo-header), RFC 9293 3.1 (TCP), RFC 8200 8.1 (IPv6 pseudo-header), RFC 4443 2.3 (ICMPv6),
/// RFC 792(ICMPv4).
struct TransportChecksum: Sendable {
    /// The offset of the checksum field within the transport segment.
    let offset: Int
    /// Includes the IP pseudo-header in the sum for every protocol except ICMPv4.
    let usesPseudoHeader: Bool
    /// Writes 0xFFFF for a computed 0 because 0 means "no checksum" in UDP.
    let zeroBecomesAllOnes: Bool

    static let udp = TransportChecksum(offset: 6, usesPseudoHeader: true, zeroBecomesAllOnes: true)
    static let tcp = TransportChecksum(offset: 16, usesPseudoHeader: true, zeroBecomesAllOnes: false)
    static let icmpv4 = TransportChecksum(offset: 2, usesPseudoHeader: false, zeroBecomesAllOnes: false)
    static let icmpv6 = TransportChecksum(offset: 2, usesPseudoHeader: true, zeroBecomesAllOnes: false)

    /// The checksum for transport-layer segment `transport`, whose checksum field is 0.
    ///
    /// - Parameters:
    ///   - source: The reply packet's source address (4 or 16 bytes).
    ///   - destination: The reply packet's destination address. The same length as `source`.
    ///   - protocolNumber: IPv4 protocol or IPv6 next header.
    func compute(over transport: [UInt8], source: [UInt8], destination: [UInt8], protocolNumber: UInt8) -> UInt16 {
        var checksum = InternetChecksum()
        if usesPseudoHeader {
            checksum.addPseudoHeader(
                source: source, destination: destination, protocolNumber: protocolNumber, length: transport.count)
        }
        checksum.add(transport)
        let sum = checksum.value
        return sum == 0 && zeroBecomesAllOnes ? 0xFFFF : sum
    }

    /// The Internet checksum of a single byte. `InternetChecksum` in `SwiftailBase` computes the sum.
    static func internetChecksum(of bytes: [UInt8]) -> UInt16 {
        InternetChecksum.checksum(of: bytes)
    }
}
