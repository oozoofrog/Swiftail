// Selection follows Tailscale's `net/netmon/state.go` (`LocalAddresses`, :38-143) and `net/tsaddr/tsaddr.go`
// (`IsTailscaleIP`) (BSD-3-Clause, Copyright (c) Tailscale Inc & contributors). The code was written from scratch in
// Swift.

import Darwin
import SwiftailBase

/// Selects IPv4 addresses from this device's interfaces to advertise as direct connection candidates.
///
/// Uses the same rules as Go's `netmon.LocalAddresses` (`docs/contracts/SwiftailMagicsock.md` E1). Considers IPv4
/// addresses on interfaces that are up, whose names do not start with `zt`, and whose names are not `wt0`.
/// - Excludes Tailscale addresses (`100.64.0.0/10`, except `100.115.92.0/23`). An address that reaches the node through
///   its own tunnel cannot be advertised.
/// - Puts addresses on the loopback interface and addresses in `127/8` in `loopback`.
/// - Collects link-local addresses (`169.254/16`) separately and uses them as `regular` only if no regular addresses
///   are available. In some environments behind NAT (such as AWS Lambda), these addresses can be used to connect.
/// - Puts the remaining addresses in `regular`. Each list is in ascending address order.
///
/// Reads the addresses at node startup and on each `setDefaultInterface` call, then passes them to `Magicsock`. It does
/// not watch for changes itself.
///
/// - `shortcut:` Does not read IPv6 addresses because there is a single IPv4 socket. Add them when `DatagramSocket` gains IPv6 support.
package enum LocalInterfaceAddresses {
    /// Input to address selection. Contains the IPv4 addresses `getifaddrs` returned for one interface.
    struct Interface: Sendable, Equatable {
        var name: String
        var isUp: Bool
        var isLoopback: Bool
        var addresses: [IPAddress]
    }

    /// Selects the current interfaces' IPv4 addresses.
    ///
    /// - Throws: `SocketError.readFailed` (errno name) if `getifaddrs` fails.
    package static func current() throws(SocketError) -> (regular: [IPAddress], loopback: [IPAddress]) {
        select(from: try interfaces())
    }

    /// Selects addresses from an interface list. Tests pass the list directly because this pure function makes no system calls.
    static func select(from interfaces: [Interface]) -> (regular: [IPAddress], loopback: [IPAddress]) {
        var regular: [IPAddress] = []
        var linkLocal: [IPAddress] = []
        var loopback: [IPAddress] = []
        for interface in interfaces where interface.isUp && !isProblematic(interface.name) {
            for address in interface.addresses where address.isIPv4 && !isTailscale(address) {
                if interface.isLoopback || address.bytes[0] == 127 {
                    loopback.append(address)
                } else if address.bytes[0] == 169 && address.bytes[1] == 254 {
                    linkLocal.append(address)
                } else {
                    regular.append(address)
                }
            }
        }
        if regular.isEmpty { regular = linkLocal }
        return (regular.sorted(by: ascending), loopback.sorted(by: ascending))
    }

    /// Excludes ZeroTier (`zt*`) and NetBird (`wt0`) because routing through one another amplifies traffic (Go `isProblematicInterface`).
    private static func isProblematic(_ name: String) -> Bool {
        name.hasPrefix("zt") || name == "wt0"
    }

    /// Addresses assigned by Tailscale are `100.64.0.0/10` excluding the ChromeOS VM range `100.115.92.0/23`.
    private static func isTailscale(_ address: IPAddress) -> Bool {
        let bytes = address.bytes
        guard bytes[0] == 100, bytes[1] & 0b1100_0000 == 0b0100_0000 else { return false }
        return !(bytes[1] == 115 && bytes[2] & 0b1111_1110 == 92)
    }

    private static func ascending(_ first: IPAddress, _ second: IPAddress) -> Bool {
        first.bytes.lexicographicallyPrecedes(second.bytes)
    }

    // MARK: POSIX Edge

    /// Converts the linked list returned by `getifaddrs` to IPv4 address lists grouped by interface.
    ///
    /// C allocates the list as a chain of `ifaddrs` pointers, so traversal requires pointers. `ifa_addr` hides the
    /// address family behind `sockaddr`, so check for IPv4 before reinterpreting it as `sockaddr_in`. Pointers are used
    /// only within this function and before `freeifaddrs`.
    private static func interfaces() throws(SocketError) -> [Interface] {
        var first: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&first) == 0 else { throw .readFailed("getifaddrs: \(errnoName(errno))") }
        defer { freeifaddrs(first) }

        var interfaces: [Interface] = []
        var cursor = first
        while let entry = cursor?.pointee {
            cursor = entry.ifa_next
            guard let socketAddress = entry.ifa_addr, socketAddress.pointee.sa_family == sa_family_t(AF_INET) else { continue }
            let host = socketAddress.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
            guard let address = IPAddress(bytes: (0..<4).map { UInt8(truncatingIfNeeded: host >> UInt32(24 - 8 * $0)) }) else { continue }
            let flags = Int32(truncatingIfNeeded: entry.ifa_flags)
            interfaces.append(Interface(
                name: String(cString: entry.ifa_name),
                isUp: flags & IFF_UP != 0,
                isLoopback: flags & IFF_LOOPBACK != 0,
                addresses: [address]
            ))
        }
        return interfaces
    }
}
