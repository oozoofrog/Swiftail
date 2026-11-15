import SwiftailBase
import Testing
@testable import Swiftail

/// `PeerIdentity.computedName`: Go `Node.InitDisplayNames`의 규칙(동작 W4, 노트 4.1 5).
/// 기대값은 같은 입력을 Go `tailcfg.Node.InitDisplayNames`(tailscale.com v1.104.6)에 넣어 얻은 `ComputedName`이다.
/// 아포스트로피처럼 DNS에 쓸 수 없는 문자는 `-`가 아니라 버려진다.
@Suite("computedName: Go의 표시 이름 규칙")
struct WhoIsComputedNameTests {
    private static let suffix = "tail0001.ts.net"
    private static let key = NodePublicKey(rawValue: [UInt8](repeating: 0x22, count: 32)) ?? .zero

    private static func computedName(_ name: String, hostname: String = "", suffix: String = suffix) -> String {
        PeerIdentity.computedName(nodeName: name, hostname: hostname, key: key, magicDNSSuffix: suffix)
    }

    @Test("접미사 떼기: 레이블 경계에서만 떼고 끝 점을 뗀다", arguments: [
        // 같은 tailnet
        ("rd-phone-1a2b3c4d.tail0001.ts.net.", "rd-phone-1a2b3c4d"),
        ("rd-phone-1a2b3c4d.tail0001.ts.net", "rd-phone-1a2b3c4d"),
        // 레이블 경계가 아니면 떼지 않는다(끝 점만 뗀다)
        ("rd-a.xtail0001.ts.net.", "rd-a.xtail0001.ts.net"),
        ("xtail0001.ts.net.", "xtail0001.ts.net"),
        // 접미사만 있는 이름은 경계가 없다
        ("tail0001.ts.net.", "tail0001.ts.net"),
        // 다른 tailnet에서 공유받은 노드: FQDN이 남는다
        ("rd-shared.tail0002.ts.net.", "rd-shared.tail0002.ts.net"),
        // 이름이 접미사 앞에 레이블 둘을 가진 경우도 접미사만 뗀다
        ("a.b.tail0001.ts.net.", "a.b"),
        // 끝 점은 하나만 뗀다
        ("rd-a.tail0001.ts.net..", "rd-a.tail0001.ts.net."),
        // 점 하나뿐인 이름
        (".", ""),
        ("", ""),
    ])
    func trimmingSuffix(name: String, expected: String) {
        #expect(Self.computedName(name, hostname: "", suffix: Self.suffix) == (expected.isEmpty ? Self.key.description : expected))
    }

    @Test("접미사 표기: 앞뒤의 점을 하나씩 무시한다", arguments: [".tail0001.ts.net", "tail0001.ts.net.", ".tail0001.ts.net."])
    func suffixSpelling(suffix: String) {
        #expect(Self.computedName("rd-a.tail0001.ts.net.", suffix: suffix) == "rd-a")
    }

    @Test("접미사가 비어 있으면 아무것도 떼지 않는다")
    func emptySuffix() {
        #expect(Self.computedName("rd-a.tail0001.ts.net.", suffix: "") == "rd-a.tail0001.ts.net")
    }

    @Test("이름이 비면 호스트 이름을 정리한 것을 쓴다", arguments: [
        ("rd-mac-1a2b3c4d", "rd-mac-1a2b3c4d"),
        ("Alice's MacBook Pro.local", "alices-macbook-pro"),
        ("host.localdomain", "host"),
        ("host.lan", "host"),
        // 흔한 접미사는 이 차례로 한 번씩만 뗀다
        ("host.lan.local", "host"),
        ("host.local.lan", "host-local"),
        // 처음·끝의 영숫자가 아닌 문자를 버리고 가운데 구분자는 `-`로
        ("--my_host@lab--", "my-host-lab"),
        ("_a b_", "a-b"),
        // DNS에 쓸 수 없는 문자는 버린다(ASCII가 아닌 바이트 포함)
        ("호스트a!b", "ab"),
        ("UPPER-case", "upper-case"),
        // 63바이트로 자른다
        (String(repeating: "a", count: 70), String(repeating: "a", count: 63)),
        // 자른 끝이 구분자이면 그것도 버린다
        (String(repeating: "a", count: 62) + "_b", String(repeating: "a", count: 62)),
        // 정리하면 비는 것
        ("...", ""),
        ("", ""),
    ])
    func sanitizedHostname(hostname: String, expected: String) {
        let computed = Self.computedName("", hostname: hostname)
        #expect(computed == (expected.isEmpty ? Self.key.description : expected))
    }

    @Test("이름이 있으면 호스트 이름을 보지 않는다")
    func nameWinsOverHostname() {
        #expect(Self.computedName("rd-a.tail0001.ts.net.", hostname: "other-host") == "rd-a")
    }

    @Test("이름도 호스트 이름도 비면 node 공개 키의 텍스트다")
    func nodeKeyFallback() {
        let computed = Self.computedName("", hostname: "")
        #expect(computed == "nodekey:" + String(repeating: "22", count: 32))
    }

    @Test("접미사 자체가 이름이어도(점 없는 자기 이름) 떼지 않는다")
    func nameEqualToSuffix() {
        #expect(Self.computedName("mac", suffix: "mac") == "mac")
    }
}
