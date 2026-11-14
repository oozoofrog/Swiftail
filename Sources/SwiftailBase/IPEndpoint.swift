/// IP 주소와 UDP 포트. Go `netip.AddrPort`에 대응한다.
///
/// 직접 연결을 받을 후보 주소(제어 서버에 올리는 엔드포인트, 피어가 알려 준 엔드포인트)와 UDP 목적지에 쓴다.
/// 텍스트는 IPv4가 `"192.0.2.1:41641"`, IPv6가 `"[2001:db8::1]:41641"`이다. IPv6는 반드시 대괄호로 감싼다.
public struct IPEndpoint: Hashable, Sendable, LosslessStringConvertible {
    public var address: IPAddress
    public var port: UInt16

    public init(address: IPAddress, port: UInt16) {
        self.address = address
        self.port = port
    }

    /// `"주소:포트"`를 읽는다. 포트는 십진수 0~65535다. 대괄호 안이 IPv4이거나, 대괄호 없는 IPv6이면 `nil`.
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
