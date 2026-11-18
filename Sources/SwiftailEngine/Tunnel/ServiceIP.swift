import SwiftailBase

/// The service IPs are the two addresses at which the node receives MagicDNS directly (`100.100.100.100`, `fd7a:115c:a1e0::53`).
///
/// Centralizes constants shared by the responder, settings derivation, reply packets, and local handling in `TailnetEngine.send`.
/// The values are Go's `tsaddr.TailscaleServiceIP` and `TailscaleServiceIPv6` (`docs/protocol-notes/dns-state-node.md` §5).
enum ServiceIP {
    static let ipv4Text = "100.100.100.100"
    static let ipv6Text = "fd7a:115c:a1e0::53"

    // The literal addresses always parse. Tests verify the values.
    static let ipv4 = IPAddress(ipv4Text)
    static let ipv6 = IPAddress(ipv6Text)

    /// Whether `address` is one of the two service IPs.
    static func contains(_ address: IPAddress) -> Bool {
        address == ipv4 || address == ipv6
    }
}
