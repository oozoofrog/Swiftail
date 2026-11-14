import Testing

import SwiftailBase

@testable import SwiftailIO

/// 인터페이스 주소를 고르는 규칙(계약 E1, Go `net/netmon/state.go` `LocalAddresses`)과 실제 호출.
@Suite("인터페이스 주소")
struct LocalInterfaceAddressesTests {
    private typealias Interface = LocalInterfaceAddresses.Interface

    private static func address(_ text: String) -> IPAddress { IPAddress(text)! }

    private static func interface(
        _ name: String,
        up: Bool = true,
        loopback: Bool = false,
        _ addresses: String...
    ) -> Interface {
        Interface(name: name, isUp: up, isLoopback: loopback, addresses: addresses.map(address))
    }

    private static func texts(_ addresses: [IPAddress]) -> [String] { addresses.map(\.description) }

    @Test("일반 주소와 loopback을 나누고 각각 오름차순으로 돌려준다")
    func splitsAndSorts() {
        let result = LocalInterfaceAddresses.select(from: [
            Self.interface("lo0", loopback: true, "127.0.0.1"),
            Self.interface("en0", "192.168.1.20", "10.0.0.7"),
            Self.interface("en1", "172.16.0.2"),
        ])
        #expect(Self.texts(result.regular) == ["10.0.0.7", "172.16.0.2", "192.168.1.20"])
        #expect(Self.texts(result.loopback) == ["127.0.0.1"])
    }

    @Test("주소는 숫자 순서로 정렬한다(문자열 순서가 아니다)")
    func sortsNumerically() {
        let result = LocalInterfaceAddresses.select(from: [Self.interface("en0", "10.0.0.9", "10.0.0.10", "9.9.9.9", "100.1.1.1")])
        #expect(Self.texts(result.regular) == ["9.9.9.9", "10.0.0.9", "10.0.0.10", "100.1.1.1"])
    }

    @Test("내려간 인터페이스는 건너뛴다")
    func skipsDownInterfaces() {
        let result = LocalInterfaceAddresses.select(from: [
            Self.interface("en0", up: false, "192.168.1.20"),
            Self.interface("lo0", up: false, loopback: true, "127.0.0.1"),
            Self.interface("en1", "10.1.1.1"),
        ])
        #expect(Self.texts(result.regular) == ["10.1.1.1"])
        #expect(result.loopback.isEmpty)
    }

    @Test("ZeroTier(zt*)와 NetBird(wt0)는 건너뛴다")
    func skipsProblematicInterfaces() {
        let result = LocalInterfaceAddresses.select(from: [
            Self.interface("ztabcdef", "10.147.17.5"),
            Self.interface("zt", "10.147.17.6"),
            Self.interface("wt0", "10.9.9.9"),
            Self.interface("wt1", "10.8.8.8"),  // 이름이 정확히 wt0일 때만 거른다
            Self.interface("en0", "10.0.0.1"),
        ])
        #expect(Self.texts(result.regular) == ["10.0.0.1", "10.8.8.8"])
    }

    @Test("loopback 인터페이스의 주소와 127/8 주소는 loopback이다")
    func loopbackClassification() {
        let result = LocalInterfaceAddresses.select(from: [
            Self.interface("lo0", loopback: true, "127.0.0.1", "10.99.0.1"),  // loopback 인터페이스에 붙은 일반 주소도 loopback
            Self.interface("en0", "127.0.0.2", "192.168.5.5"),  // 일반 인터페이스에 붙은 127/8도 loopback
        ])
        #expect(Self.texts(result.regular) == ["192.168.5.5"])
        #expect(Self.texts(result.loopback) == ["10.99.0.1", "127.0.0.1", "127.0.0.2"])
    }

    @Test("Tailscale 주소(100.64.0.0/10)는 뺀다. 경계와 ChromeOS 대역(100.115.92.0/23) 예외를 지킨다")
    func tailscaleRange() {
        let result = LocalInterfaceAddresses.select(from: [Self.interface(
            "en0",
            "100.63.255.255",  // 범위 바로 아래: 일반 주소
            "100.64.0.0",  // 범위의 첫 주소: 뺀다
            "100.100.100.100",  // 뺀다
            "100.115.91.255",  // ChromeOS 대역 바로 아래: 뺀다(Tailscale 범위 안)
            "100.115.92.0",  // ChromeOS 대역: 일반 주소
            "100.115.93.255",  // ChromeOS 대역 끝: 일반 주소
            "100.115.94.0",  // ChromeOS 대역 바로 위: 뺀다
            "100.127.255.255",  // 범위의 끝: 뺀다
            "100.128.0.0"  // 범위 바로 위: 일반 주소
        )])
        #expect(Self.texts(result.regular) == ["100.63.255.255", "100.115.92.0", "100.115.93.255", "100.128.0.0"])
        #expect(result.loopback.isEmpty)
    }

    @Test("link-local(169.254/16)은 일반 주소가 없을 때만 일반 주소로 쓴다")
    func linkLocalFallback() {
        let only = LocalInterfaceAddresses.select(from: [Self.interface("en0", "169.254.7.7", "169.254.1.1")])
        #expect(Self.texts(only.regular) == ["169.254.1.1", "169.254.7.7"])

        let mixed = LocalInterfaceAddresses.select(from: [Self.interface("en0", "169.254.7.7"), Self.interface("en1", "192.168.0.4")])
        #expect(Self.texts(mixed.regular) == ["192.168.0.4"])

        // 169.254가 아닌 169.x는 link-local이 아니다.
        let edge = LocalInterfaceAddresses.select(from: [Self.interface("en0", "169.253.0.1", "169.255.0.1")])
        #expect(Self.texts(edge.regular) == ["169.253.0.1", "169.255.0.1"])
    }

    @Test("일반 주소가 Tailscale 주소뿐이면 link-local을 대신 쓴다")
    func tailscaleOnlyCountsAsNoRegular() {
        let result = LocalInterfaceAddresses.select(from: [Self.interface("utun4", "100.64.0.5"), Self.interface("en0", "169.254.2.2")])
        #expect(Self.texts(result.regular) == ["169.254.2.2"])
    }

    @Test("loopback 인터페이스의 link-local은 loopback이다")
    func loopbackInterfaceWinsOverLinkLocal() {
        let result = LocalInterfaceAddresses.select(from: [Self.interface("lo0", loopback: true, "169.254.9.9")])
        #expect(result.regular.isEmpty)
        #expect(Self.texts(result.loopback) == ["169.254.9.9"])
    }

    @Test("입력이 비면 둘 다 비어 있다")
    func emptyInput() {
        let result = LocalInterfaceAddresses.select(from: [])
        #expect(result.regular.isEmpty)
        #expect(result.loopback.isEmpty)
    }

    @Test("IPv6 주소는 고르지 않는다")
    func ignoresIPv6() {
        let result = LocalInterfaceAddresses.select(from: [Interface(
            name: "en0",
            isUp: true,
            isLoopback: false,
            addresses: [Self.address("2001:db8::1"), Self.address("10.0.0.3")]
        )])
        #expect(Self.texts(result.regular) == ["10.0.0.3"])
    }

    @Test("실제 호출은 죽지 않고 loopback 주소를 따로 돌려준다")
    func currentReportsLoopback() throws {
        let result = try LocalInterfaceAddresses.current()
        #expect(result.loopback.contains(Self.address("127.0.0.1")))
        #expect(!result.regular.contains(Self.address("127.0.0.1")))
        #expect(result.regular.allSatisfy { $0.isIPv4 })
        // 목록은 오름차순이다.
        #expect(result.regular.map(\.bytes) == result.regular.map(\.bytes).sorted { $0.lexicographicallyPrecedes($1) })
    }
}
