/// An IP address and UDP port. Corresponds to Go `netip.AddrPort`.
///
/// Used for addresses that can receive direct connections (endpoints reported to the control server or advertised by peers) and UDP destinations.
/// The text form is `"192.0.2.1:41641"` for IPv4 and `"[2001:db8::1]:41641"` for IPv6. IPv6 requires square brackets.
public struct IPEndpoint: Hashable, Sendable, LosslessStringConvertible {
    public var address: IPAddress
    public var port: UInt16

    public init(address: IPAddress, port: UInt16) {
        self.address = address
        self.port = port
    }

    /// Parses `"address:port"`. The port is a decimal number in 0~65535. Returns `nil` for bracketed IPv4 or unbracketed IPv6.
    public init?(_ description: String) {
        guard let colon = description.lastIndex(of: ":"),
              let port = Self.parsePort(description[description.index(after: colon)...])
        else { return nil }
        let host = description[..<colon]
        let address: IPAddress?
        if host.hasPrefix("["), host.hasSuffix("]"), host.count >= 2 {
            address = IPAddress(String(host.dropFirst().dropLast())).flatMap { $0.isIPv4 ? nil : $0 }
        } else {
            address = IPAddress(String(host)).flatMap { $0.isIPv4 ? $0 : nil }
        }
        guard let address else { return nil }
        self.init(address: address, port: port)
    }

    public var description: String {
        address.isIPv4 ? "\(address):\(port)" : "[\(address)]:\(port)"
    }

    private static func parsePort(_ text: Substring) -> UInt16? {
        guard (1...5).contains(text.count), text.allSatisfy({ ("0"..."9").contains($0) }) else { return nil }
        return UInt16(text)
    }
}
