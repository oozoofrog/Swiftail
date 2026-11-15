// 계약 동작 C2(이름 검사)와 7절 시험 11의 이름 사례: 처음·끝의 하이픈, 64자 레이블, 253자,
// `_acme-challenge.`를 붙이면 넘는 238자 이름, 대문자, 경로 문자.

import Testing

@testable import SwiftailCertificates

@Suite("이름 검사")
struct CertificateDomainTests {
    @Test("받는 이름", arguments: [
        ("rd-mac-1a2b3c4d.tail0001.ts.net", "rd-mac-1a2b3c4d.tail0001.ts.net"),
        ("rd-mac-1a2b3c4d.tail0001.ts.net.", "rd-mac-1a2b3c4d.tail0001.ts.net"),  // 끝의 점 하나는 뗀다
        ("a.b", "a.b"),
        ("0.9", "0.9"),
        ("a--b.c-d", "a--b.c-d"),
    ])
    func accepted(input: String, name: String) throws {
        let domain = try #require(CertificateDomain(input))
        #expect(domain.name == name)
        #expect(domain.challengeRecordName == "_acme-challenge." + name)
    }

    @Test("거절하는 이름", arguments: [
        "", ".", "localhost", "localhost.",          // 레이블 하나
        "-a.b", "a-.b", "a.-b", "a.b-",               // 처음·끝의 하이픈
        "a..b", ".a.b", "a.b..",                       // 빈 레이블(끝의 점은 하나만 뗀다)
        "Rd-mac.tail0001.ts.net", "a.B",               // 대문자
        "_acme.a.b", "a_b.c", "*.a.b",                 // 밑줄, 와일드카드
        "a/b.c", "a\\b.c", "a:b.c", "a\u{0}b.c", "../a.b", "a b.c",
        "é.a.b", "ａ.b",                                // ASCII 밖
    ])
    func rejected(_ input: String) {
        #expect(CertificateDomain(input) == nil)
    }

    @Test("레이블 63자는 받고 64자는 거절")
    func labelLength() {
        #expect(CertificateDomain(String(repeating: "a", count: 63) + ".b") != nil)
        #expect(CertificateDomain(String(repeating: "a", count: 64) + ".b") == nil)
    }

    /// 63자 레이블 셋(191자)에 레이블을 더해 길이를 맞춘다.
    private static func name(length: Int) -> String {
        let base = Array(repeating: String(repeating: "a", count: 63), count: 3).joined(separator: ".")
        let last = String(repeating: "b", count: length - base.count - 1)
        return base + "." + last
    }

    @Test("전체 길이: 237자는 받고, _acme-challenge.를 붙이면 253자를 넘는 238자는 거절")
    func totalLength() {
        #expect(CertificateDomain.maximumLength == 237)
        let longest = Self.name(length: 237)
        #expect(CertificateDomain(longest)?.challengeRecordName.utf8.count == 253)
        #expect(CertificateDomain(longest + ".") != nil)
        #expect(CertificateDomain(Self.name(length: 238)) == nil)
        #expect(CertificateDomain(Self.name(length: 253)) == nil)
    }
}
