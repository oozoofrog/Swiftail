// 고르는 규칙은 Tailscale의 `net/netmon/state.go`(`LocalAddresses`, :38-143)와 `net/tsaddr/tsaddr.go`
// (`IsTailscaleIP`)(BSD-3-Clause, Copyright (c) Tailscale Inc & contributors)를 따른다. 코드는 Swift로 새로 썼다.

import Darwin
import SwiftailBase

/// 이 기기의 인터페이스에서 직접 연결 후보로 올릴 IPv4 주소를 고른다.
///
/// Go `netmon.LocalAddresses`와 같은 규칙이다(`docs/contracts/SwiftailMagicsock.md` E1). 올라와 있고 이름이 `zt`로
/// 시작하지 않으며 `wt0`이 아닌 인터페이스의 IPv4 주소 가운데
/// - Tailscale 주소(`100.64.0.0/10`, 단 `100.115.92.0/23`은 제외)는 뺀다. 자기 터널로 자기에게 닿는 주소를 알릴 수 없다.
/// - loopback 인터페이스의 주소나 `127/8` 주소는 `loopback`에 담는다.
/// - link-local(`169.254/16`)은 따로 모아 일반 주소가 하나도 없을 때만 `regular`로 쓴다. NAT 뒤에서 이 주소로 연결되는
///   환경이 있다(AWS Lambda 등).
/// - 나머지는 `regular`다. 각 목록은 주소 오름차순이다.
///
/// 노드가 시작할 때 한 번 읽어 `Magicsock`에 넘긴다.
///
/// - `shortcut:` 주소 변경 감지는 하지 않는다. 필요해지는 시점: M5(링크 변경과 함께. `disco-magicsock.md` 4.11).
/// - `shortcut:` IPv6 주소는 읽지 않는다(소켓이 IPv4 하나다). 필요해지는 시점: `DatagramSocket`에 IPv6를 넣을 때.
package enum LocalInterfaceAddresses {
    /// 고르는 규칙의 입력. `getifaddrs`가 돌려준 인터페이스 하나의 IPv4 주소들이다.
    struct Interface: Sendable, Equatable {
        var name: String
        var isUp: Bool
        var isLoopback: Bool
        var addresses: [IPAddress]
    }

    /// 지금 인터페이스의 IPv4 주소를 고른다.
    ///
    /// - Throws: `getifaddrs`가 실패하면 `SocketError.readFailed`(errno 이름).
    package static func current() throws(SocketError) -> (regular: [IPAddress], loopback: [IPAddress]) {
        select(from: try interfaces())
    }

    /// 인터페이스 목록에서 주소를 고른다. 시스템을 부르지 않는 순수 함수라 시험이 목록을 직접 넘긴다.
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

    /// ZeroTier(`zt*`)와 NetBird(`wt0`)는 서로를 경로로 삼아 트래픽을 증폭하므로 쓰지 않는다(Go `isProblematicInterface`).
    private static func isProblematic(_ name: String) -> Bool {
        name.hasPrefix("zt") || name == "wt0"
    }

    /// Tailscale이 나눠 주는 주소: `100.64.0.0/10`에서 ChromeOS VM 대역 `100.115.92.0/23`을 뺀 것.
    private static func isTailscale(_ address: IPAddress) -> Bool {
        let bytes = address.bytes
        guard bytes[0] == 100, bytes[1] & 0b1100_0000 == 0b0100_0000 else { return false }
        return !(bytes[1] == 115 && bytes[2] & 0b1111_1110 == 92)
    }

    private static func ascending(_ first: IPAddress, _ second: IPAddress) -> Bool {
        first.bytes.lexicographicallyPrecedes(second.bytes)
    }

    // MARK: POSIX 경계

    /// `getifaddrs`가 돌려준 연결 리스트를 인터페이스별 IPv4 주소 목록으로 바꾼다.
    ///
    /// 리스트는 C가 할당한 `ifaddrs`의 포인터 사슬이라 따라가려면 포인터가 필요하고, `ifa_addr`는 주소 종류가 `sockaddr`
    /// 하나로 감춰져 있어 IPv4인지 본 뒤 `sockaddr_in`으로 다시 본다. 포인터는 `freeifaddrs` 전까지, 이 함수 안에서만 쓴다.
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
