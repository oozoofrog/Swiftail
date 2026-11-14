import SwiftailBase
import Testing
@testable import Swiftail

/// 기본 인터페이스 통지의 판정. 계약 `docs/contracts/SwiftailTunnel.md` 동작 N 1·2, 시험 목록 7.
@Suite("기본 인터페이스 전환 판정")
struct DefaultLinkTests {
    private static func link(_ name: String = "en0", index: Int = 4, addresses: [String] = ["192.168.0.10"]) -> DefaultLink {
        DefaultLink(
            name: name, index: index,
            addresses: addresses.compactMap(IPAddress.init),
            loopbackAddresses: ["127.0.0.1"].compactMap(IPAddress.init)
        )
    }

    @Test("처음 받은 인터페이스는 재결속이다")
    func first() {
        #expect(Self.link().change(from: nil, tunnelName: "utun5") == .rebind)
    }

    @Test("같은 인터페이스·같은 주소는 STUN만 다시 한다")
    func same() {
        #expect(Self.link().change(from: Self.link(), tunnelName: "utun5") == .restartSTUN)
    }

    @Test("주소만 바뀌어도 재결속이다")
    func addressChanged() {
        #expect(Self.link(addresses: ["192.168.0.11"]).change(from: Self.link(), tunnelName: "utun5") == .rebind)
        #expect(Self.link(addresses: []).change(from: Self.link(), tunnelName: "utun5") == .rebind)
    }

    @Test("인터페이스(이름이나 번호)가 바뀌면 재결속이다")
    func interfaceChanged() {
        #expect(Self.link("pdp_ip0", index: 9).change(from: Self.link(), tunnelName: "utun5") == .rebind)
        #expect(Self.link(index: 5).change(from: Self.link(), tunnelName: "utun5") == .rebind)
    }

    @Test("이 노드의 utun 이름과 같은 인터페이스는 무시한다. 메모리 장치는 거르지 않는다")
    func ownTunnel() {
        #expect(Self.link("utun5", index: 20).change(from: Self.link(), tunnelName: "utun5") == .ignore)
        #expect(Self.link("utun5", index: 20).change(from: nil, tunnelName: "utun5") == .ignore)
        #expect(Self.link("utun5", index: 20).change(from: Self.link(), tunnelName: nil) == .rebind)
    }
}
