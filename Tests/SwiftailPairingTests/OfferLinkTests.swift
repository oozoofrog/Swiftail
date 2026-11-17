import Foundation
import Testing
@testable import SwiftailPairing

/// 제안의 링크(계약 `docs/contracts/SwiftailPairing.md` 3절, 동작 O1~O4. 7절 시험 1).
@Suite("제안의 링크")
struct OfferLinkTests {
    /// `Sample.secret`(0x5A × 32)을 적은 글.
    private static let secretText = "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo"
    private static let fragment = "v=1&h=rd-mac-1a2b3c4d.tail0001.ts.net&p=4747&s=\(secretText)&e=1900000300"

    /// 올바른 조각에서 `key`의 값을 `value`로 바꾼 링크. `value`가 nil이면 그 키를 뺀다.
    private static func link(replacing key: String, with value: String?, authKey: String? = nil) -> String {
        var pairs = fragment.split(separator: "&").map(String.init)
        if let authKey { pairs.append("k=\(authKey)") }
        pairs = pairs.compactMap { pair in
            guard pair.hasPrefix("\(key)=") else { return pair }
            return value.map { "\(key)=\($0)" }
        }
        return "myapp://pair#" + pairs.joined(separator: "&")
    }

    private static func parseError(_ link: String) -> PairingOfferError? {
        do throws(PairingOfferError) {
            _ = try PairingOffer(link: link)
            return nil
        } catch {
            return error
        }
    }

    // MARK: 쓰기와 왕복 (O1)

    @Test("링크는 값을 전부 조각에 싣고, 정해진 모양이다")
    func writesFragment() throws {
        let base = try #require(URL(string: "https://example.com/pair"))
        #expect(Sample.offer().url(base: base).absoluteString == "https://example.com/pair#" + Self.fragment)
        #expect(
            Sample.offer(authKey: Sample.authKey).url(base: base).absoluteString
                == "https://example.com/pair#" + Self.fragment + "&k=tskey-auth-EXAMPLE-0000")
        let url = Sample.offer(authKey: Sample.authKey).url(base: base)
        #expect(url.query == nil && url.path == "/pair", "값은 경로나 질의에 실리지 않는다")
    }

    @Test("base의 조각은 버린다", arguments: ["myapp://pair", "myapp://pair#old", "https://example.com/pair?x=1#old&v=9"])
    func dropsBaseFragment(base: String) throws {
        let url = Sample.offer().url(base: try #require(URL(string: base)))
        let stem = base.split(separator: "#")[0]
        #expect(url.absoluteString == stem + "#" + Self.fragment)
    }

    @Test("쓴 링크를 다시 읽으면 같은 제안이다", arguments: [nil, Sample.authKey])
    func roundTrips(authKey: String?) throws {
        let offer = Sample.offer(authKey: authKey)
        let read = try PairingOffer(link: offer.url(base: try #require(URL(string: "myapp://pair"))).absoluteString)
        #expect(read.host == offer.host)
        #expect(read.port == offer.port)
        #expect(read.expires == offer.expires)
        #expect(read.authKey == authKey)
        #expect(read.secret == offer.secret)
    }

    @Test("만료의 소수 초는 버리고 초 단위로 적는다")
    func truncatesExpiry() throws {
        let offer = Sample.offer(expires: Date(timeIntervalSince1970: 1_900_000_300.9))
        #expect(offer.fragment.hasSuffix("&e=1900000300"))
    }

    // MARK: 읽기 (O2~O4)

    @Test("base는 보지 않고 첫 # 뒤만 읽는다", arguments: ["", "myapp://pair", "https://example.com/pair?h=other.example.com"])
    func ignoresBase(base: String) throws {
        let offer = try PairingOffer(link: base + "#" + Self.fragment)
        #expect(offer.host == Sample.host && offer.port == Sample.port && offer.secret == Sample.secret)
        #expect(offer.authKey == nil)
    }

    @Test("만료가 지난 제안도 읽힌다(거절은 여는 쪽이 한다)")
    func readsExpiredOffer() throws {
        let offer = try PairingOffer(link: Self.link(replacing: "e", with: "1"))
        #expect(offer.expires == Date(timeIntervalSince1970: 1))
    }

    @Test("키의 차례는 가리지 않는다")
    func acceptsAnyKeyOrder() throws {
        let pairs = Self.fragment.split(separator: "&").reversed().joined(separator: "&")
        #expect(try PairingOffer(link: "#" + pairs).secret == Sample.secret)
    }

    private static let nonOffers: [String] = [
        "myapp://pair",                                   // 조각이 없다
        "myapp://pair#",                                  // 빈 조각
        "#" + fragment.replacingOccurrences(of: "v=1", with: "v=2"),
        "#" + fragment.replacingOccurrences(of: "v=1", with: "v=01"),
        "#" + fragment.replacingOccurrences(of: "v=1&", with: ""),
        "#" + fragment + "&x=1",                          // 모르는 키
        "#" + fragment + "&V=1",                          // 키는 소문자만
        "#" + fragment + "&p=4747",                       // 겹친 키
        "#" + fragment + "&v=1",
        "#" + fragment + "&",                             // 빈 묶음
        "#&" + fragment,
        "#" + fragment + "&k",                            // `=`가 없다
        "#" + fragment.replacingOccurrences(of: "ts.net", with: "ts%2Enet"),   // `%`
        "#" + fragment + "&k=tskey-auth-EXAMPLE%2D0000",
        "#" + fragment.replacingOccurrences(of: "rd-mac-1a2b3c4d", with: String(repeating: "a", count: 2048)),
    ]

    @Test("제안의 링크가 아닌 것", arguments: nonOffers)
    func rejectsNonOffers(link: String) {
        #expect(Self.parseError(link) == .notAnOffer)
    }

    @Test("조각은 2048바이트까지다. 넘으면 값의 잘못보다 먼저 걸린다")
    func limitsFragmentLength() {
        let padding = 2048 - Self.fragment.utf8.count - "&k=".utf8.count
        let atLimit = "#" + Self.fragment + "&k=" + String(repeating: "a", count: padding)
        #expect(Self.parseError(atLimit) == .invalidAuthKey)
        #expect(Self.parseError(atLimit + "a") == .notAnOffer)
    }

    private static let badHosts: [String?] = [
        nil, "", "localhost", "RD-MAC.tail0001.ts.net", "rd_mac.tail0001.ts.net", "-rd.tail0001.ts.net",
        "rd-.tail0001.ts.net", "rd..ts.net", ".ts.net", "rd.ts.net.", "rd mac.ts.net", "100.64.0.1:80",
        String(repeating: "a", count: 64) + ".ts.net",
        // 254자: 63자 라벨 넷이면 255자이므로 마지막 라벨을 62자로 줄인다.
        [63, 63, 63, 62].map { String(repeating: "a", count: $0) }.joined(separator: "."),
        "rd-mac.tail0001.ts.net#x",
    ]

    @Test("host: 소문자·숫자·하이픈의 라벨 둘 이상", arguments: badHosts)
    func rejectsHosts(value: String?) {
        #expect(Self.parseError(Self.link(replacing: "h", with: value)) == .invalidHost)
    }

    private static let goodHosts: [String] = [
        String(repeating: "a", count: 63) + ".ts.net",
        [63, 63, 63, 61].map { String(repeating: "a", count: $0) }.joined(separator: "."),
        "1a.2b", "a-b.c-d",
    ]

    @Test("host의 경계: 63자 라벨, 전체 253자, 숫자로 시작하는 라벨", arguments: goodHosts)
    func acceptsHosts(value: String) throws {
        #expect(try PairingOffer(link: Self.link(replacing: "h", with: value)).host == value)
    }

    @Test("port: 앞자리 0 없는 1~65535", arguments: [nil, "", "0", "65536", "04747", "+4747", "-1", "4747 ", "0x1f", "123456", "４７"])
    func rejectsPorts(value: String?) {
        #expect(Self.parseError(Self.link(replacing: "p", with: value)) == .invalidPort)
    }

    @Test("port의 경계", arguments: [("1", UInt16(1)), ("65535", UInt16(65535))])
    func acceptsPorts(value: String, expected: UInt16) throws {
        #expect(try PairingOffer(link: Self.link(replacing: "p", with: value)).port == expected)
    }

    private static let badSecrets: [String?] = [
        nil, "",
        String(secretText.dropLast()),            // 42자
        secretText + "A",                         // 44자
        secretText + "=",                         // 채움
        String(secretText.dropLast()) + "=",
        "+" + secretText.dropFirst(),             // 표준 base64 글자
        "/" + secretText.dropFirst(),
        " " + secretText.dropFirst(),
        String(secretText.dropLast()) + "p",      // 남는 비트가 0이 아니다(o 다음 글자)
        String(secretText.dropLast()) + "_",
    ]

    @Test("secret: 32바이트를 적은 채움 없는 base64url 43자", arguments: badSecrets)
    func rejectsSecrets(value: String?) {
        #expect(Self.parseError(Self.link(replacing: "s", with: value)) == .invalidSecret)
    }

    @Test("secret의 글자: - 와 _")
    func acceptsURLSafeAlphabet() throws {
        let secret = [UInt8](repeating: 0xFB, count: 31) + [0xFF]
        let offer = try PairingOffer(link: "#" + Sample.offer(secret: secret).fragment)
        #expect(Sample.offer(secret: secret).fragment.contains("s=-_"), "0xFB 0xFF…은 `-`·`_`로 적힌다")
        #expect(offer.secret == secret)
    }

    @Test("expiry: 부호와 앞자리 0이 없는 1~11자리", arguments: [nil, "", "0", "01", "-1", "+1", "1.5", "1e9", "123456789012", "19000003oo"])
    func rejectsExpiries(value: String?) {
        #expect(Self.parseError(Self.link(replacing: "e", with: value)) == .invalidExpiry)
    }

    @Test("expiry의 경계", arguments: [("1", 1.0), ("99999999999", 99_999_999_999.0)])
    func acceptsExpiries(value: String, expected: Double) throws {
        let offer = try PairingOffer(link: Self.link(replacing: "e", with: value))
        #expect(offer.expires == Date(timeIntervalSince1970: expected))
    }

    @Test("조각 안의 둘째 #은 값의 글자로 보고 거절한다")
    func rejectsSecondHash() {
        #expect(Self.parseError("#" + Self.fragment + "#x") == .invalidExpiry)
    }

    private static let badAuthKeys: [String] = [
        "", "tskey-client-EXAMPLE", "TSKEY-AUTH-EXAMPLE", "tskey-auth", "tskey-auth-EXAMPLE_0000",
        "tskey-auth-EXAMPLE.0000", "tskey-auth-EXAMPLE 0000", "tskey-auth-EXAMPLE=", "tskey-auth-EXAMPLE#",
        "tskey-auth-" + String(repeating: "a", count: 246),   // 257바이트
    ]

    @Test("authKey: tskey-auth-로 시작하고 A-Za-z0-9-만 쓰는 256바이트 이하", arguments: badAuthKeys)
    func rejectsAuthKeys(value: String) {
        #expect(Self.parseError(Self.link(replacing: "k", with: value, authKey: "")) == .invalidAuthKey)
    }

    @Test("authKey의 경계: 256바이트")
    func acceptsLongestAuthKey() throws {
        let key = "tskey-auth-" + String(repeating: "a", count: 245)
        #expect(try PairingOffer(link: Self.link(replacing: "k", with: key, authKey: "")).authKey == key)
    }

    private static let wrappedAuthKeys: [String] = [
        "tskey-auth-EXAMPLE-0000--TLEXAMPLE-EXAMPLE",
        "tskey-auth-EXAMPLE-0000--TLab+cd/ef-gh+ij/kl",   // 뒤쪽은 표준 base64라 글자 검사에도 걸리지만 까닭은 이것이다
        "--TL",
    ]

    @Test("감싼 인증 키(--TL)는 싣지 못한다", arguments: wrappedAuthKeys)
    func rejectsWrappedAuthKeys(value: String) {
        #expect(Self.parseError(Self.link(replacing: "k", with: value, authKey: "")) == .wrappedAuthKey)
    }

    // MARK: 가림

    @Test("description과 dump에 비밀과 인증 키가 나오지 않는다")
    func redactsSecrets() {
        let offer = Sample.offer(authKey: Sample.authKey)
        var dumped = ""
        dump(offer, to: &dumped)
        for text in [String(describing: offer), String(reflecting: offer), "\(offer)", dumped] {
            #expect(text.contains(Sample.host), "가리지 않아도 되는 값은 보인다")
            #expect(!text.contains(Self.secretText))
            #expect(!text.contains("90, 90"), "비밀의 바이트 배열도 나오지 않는다")
            #expect(!text.contains("5a5a") && !text.contains("5A5A"))
            #expect(!text.contains("tskey"))
        }
        var withoutKey = ""
        dump(Sample.offer(), to: &withoutKey)
        #expect(withoutKey.contains("없음"))
    }
}
