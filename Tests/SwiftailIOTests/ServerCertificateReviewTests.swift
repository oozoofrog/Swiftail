import Foundation
import Testing

@testable import SwiftailIO

/// M8 ③(DERP 인증서의 이름 지정 검증과 `sha256-raw:` 고정)의 독립 검토가 남긴 재현 시험.
///
/// 기준은 Go 클라이언트의 판정이다(tailscale.com v1.104.6 `net/tlsdial/tlsdial.go`의 `SetConfigExpectedCertHash`·
/// `SetConfigExpectedCert`, Go 1.27.3 `crypto/tls`의 `hostnameInSNI`, `crypto/x509`의 `VerifyHostname`). 각 시험의 Go 쪽
/// 값은 그 코드를 실제로 돌려 얻었다. 지금 Go와 갈리는 것은 `withKnownIssue`로 감쌌다. 고치면 그 감싼 것이 실패로
/// 바뀌어 알려 준다.
@Suite("서버 인증서 판정: 검토")
struct ServerCertificateReviewTests {
    private typealias Fixture = ServerCertificateFixtures
    private typealias Review = ServerCertificateReviewFixtures

    /// 고정 인증서들의 유효 기간(2026-01-01T00:00:00Z ... 2027-01-01T00:00:00Z) 안.
    private static let now = Date(timeIntervalSince1970: 1_780_272_000) // 2026-06-01T00:00:00Z
    private static let notBefore = Date(timeIntervalSince1970: 1_767_225_600) // 2026-01-01T00:00:00Z
    private static let notAfter = Date(timeIntervalSince1970: 1_798_761_600) // 2027-01-01T00:00:00Z

    private static func pinned(
        _ certificates: [[UInt8]], hash: String = Fixture.ipLeafSHA256, serverName: String = "100.64.0.1", at now: Date = now
    ) -> ServerCertificate.Failure? {
        do throws(ServerCertificate.Failure) {
            try ServerCertificate.checkPinned(certificates, sha256Hex: hash, serverName: serverName, at: now)
            return nil
        } catch {
            return error
        }
    }

    private static func named(
        _ certificates: [[UInt8]], name: String = "derp-cert.example.test", at now: Date = now
    ) -> ServerCertificate.Failure? {
        do throws(ServerCertificate.Failure) {
            try ServerCertificate.checkNamed(certificates, name: name, at: now, anchors: [Fixture.root])
            return nil
        } catch {
            return error
        }
    }

    private static func isUntrusted(_ failure: ServerCertificate.Failure?) -> Bool {
        if case .untrusted = failure { true } else { false }
    }

    // MARK: 받으면 안 되는 것

    /// TLS 핸드셰이크가 증명하는 것은 첫 인증서의 키뿐이다. 망 위의 공격자가 자기 키로 만든 CN `derpkey…` 인증서를 첫
    /// 자리에 내고, 누구나 받아 볼 수 있는 고정 인증서를 뒤에 붙이면 "meta가 아닌 것이 정확히 하나, 해시가 맞음"을
    /// 채운다. Go도 받는다(`SetConfigExpectedCertHash`가 자리를 보지 않는다. 그 목록을 내는 TLS 서버에 Go 클라이언트와
    /// Swiftail의 `.pinned` 연결이 모두 붙는 것을 실행으로 확인했다). 실제 derper는 서버 인증서를 첫 자리에, meta
    /// 인증서를 그 뒤에 낸다(`derpserver.ModifyTLSConfigToAddMetaCert`). meta 인증서의 개인 키는 만들 때 버려지므로
    /// meta 인증서가 첫 자리에 오는 정상 서버는 없다.
    @Test("고정: 고정한 인증서가 첫 자리(서버가 키를 증명한 자리)가 아니면 받지 않아야 한다")
    func pinnedCertificateMustBeTheHandshakeLeaf() {
        withKnownIssue("Go와 같은 판정이지만 고정이 키 소유를 증명하지 못한다: meta 모양의 leaf 뒤에 고정 인증서를 붙인 목록이 통과한다") {
            #expect(Self.pinned([Fixture.meta, Fixture.ipLeaf]) != nil)
        }
    }

    /// Go의 x509는 주체 CN이 VisibleString이면 CommonName을 비운다. 그래서 Go에서는 meta가 아닌 인증서이고, 목록은
    /// 거절된다(첫 자리면 해시 불일치, 뒤면 "multiple certs"). `SecCertificateCopyCommonName`은 그 CN을 읽는다.
    @Test("고정: Go가 meta로 보지 않는 CN(VisibleString)의 인증서를 meta로 빼면 안 된다")
    func visibleStringCommonNameIsNotMeta() {
        withKnownIssue("Security 프레임워크가 Go보다 많은 문자열 형을 CN으로 읽어, Go가 세는 인증서를 세지 않는다") {
            #expect(Self.pinned([Review.visibleStringMeta, Fixture.ipLeaf]) != nil)
            #expect(Self.pinned([Fixture.ipLeaf, Review.visibleStringMeta]) == .multipleCandidates)
        }
    }

    /// Go: `hostnameInSNI("100.064.0.1")`은 그 문자열 그대로다(`net.ParseIP`가 앞자리 0을 받지 않는다). 이름으로 견주므로
    /// IP SAN만 있는 인증서는 맞지 않는다. `SecPolicyCreateSSL`은 같은 문자열을 `100.64.0.1`로 읽어 IP SAN과 맞춘다.
    @Test("고정: Go가 IP로 읽지 않는 서버 이름을 IP SAN과 맞추면 안 된다")
    func leadingZeroServerNameIsNotAnIPAddress() {
        withKnownIssue("SSL 정책이 앞자리 0이 붙은 점 십진을 IP로 읽는다") {
            #expect(Self.isUntrusted(Self.pinned([Fixture.ipLeaf], serverName: "100.064.0.1")))
        }
    }

    @Test("고정: 고정 값은 글자 그대로 견준다. 공백·머리·잘린 값은 맞지 않는다")
    func pinnedHashShape() {
        let hash = Fixture.ipLeafSHA256
        for wrong in [" \(hash)", "\(hash) ", "\(hash)\n", "sha256-raw:\(hash)", String(hash.dropLast()), "\(hash)0", "0x\(hash)"] {
            #expect(Self.pinned([Fixture.ipLeaf], hash: wrong) == .hashMismatch)
        }
    }

    // MARK: 받아야 하는 것

    /// Go의 고정 판정은 해시, 이름(`VerifyHostname`), 유효 기간만 본다. `SecTrust`의 SSL 서버 정책은 더 본다. derper의
    /// 수동 인증서 모드(`cmd/derper/cert.go`의 `NewManualCertManager`)는 운영자가 둔 인증서를 그대로 쓰므로, 아래 모양의
    /// 자체 서명 인증서를 `sha256-raw:`로 고정한 DERP에 Go 클라이언트는 붙고 Swiftail은 붙지 못한다.
    @Test("고정: Go가 받는 자체 서명 인증서의 모양", arguments: [
        ("유효 기간 10년", Review.longValidityLeaf, Review.longValidityLeafSHA256),
        ("EKU 없음", Review.noEKULeaf, Review.noEKULeafSHA256),
        ("Ed25519 키", Review.ed25519Leaf, Review.ed25519LeafSHA256),
    ])
    func pinnedShapesGoAccepts(shape: String, certificate: [UInt8], hash: String) {
        withKnownIssue("SecTrust의 SSL 서버 정책이 Go보다 엄격하다: \(shape)") {
            #expect(Self.pinned([certificate], hash: hash, serverName: "derp1a.example.test") == nil)
        }
    }

    /// Go: `now.After(cert.NotAfter)`와 `now.Before(cert.NotBefore)`만 거절하므로 두 끝의 시각은 유효하다.
    @Test("고정: 유효 기간의 두 끝은 안이고, 1초 밖은 밖이다")
    func pinnedValidityBoundaries() {
        #expect(Self.pinned([Fixture.ipLeaf], at: Self.notBefore) == nil)
        #expect(Self.pinned([Fixture.ipLeaf], at: Self.notAfter) == nil)
        #expect(Self.isUntrusted(Self.pinned([Fixture.ipLeaf], at: Self.notBefore - 1)))
        #expect(Self.isUntrusted(Self.pinned([Fixture.ipLeaf], at: Self.notAfter + 1)))
    }

    /// Go는 SNI로 나가는 이름이 없으면(`hostnameInSNI`가 빈 문자열) 이름을 아예 보지 않는다. IP SAN이 없는 인증서도 통과한다.
    @Test("고정: 서버 이름이 IP 리터럴이면 IP SAN이 없는 인증서도 받는다", arguments: [
        "100.64.0.1", "fd7a:115c:a1e0::1", "[fd7a:115c:a1e0::1]", "fe80::1%en0", "::ffff:100.64.0.1",
    ])
    func pinnedIPLiteralIgnoresSubjectAlternativeNames(serverName: String) {
        #expect(Self.pinned([Fixture.dnsLeaf], hash: Fixture.dnsLeafSHA256, serverName: serverName) == nil)
    }

    // MARK: 이름 지정

    @Test("이름: 기한이 지났거나 아직 아니면 실패한다")
    func namedValidity() {
        #expect(Self.named([Fixture.namedLeaf], at: Self.notAfter - 1) == nil)
        #expect(Self.isUntrusted(Self.named([Fixture.namedLeaf], at: Self.notAfter + 1)))
        #expect(Self.isUntrusted(Self.named([Fixture.namedLeaf], at: Self.notBefore - 1)))
    }

    /// Go `SetConfigExpectedCert`는 `certs[0]`만 leaf로 본다.
    @Test("이름: 첫 인증서만 leaf다. 맞는 인증서가 뒤에 있어도 받지 않는다")
    func namedLeafIsFirst() {
        #expect(Self.isUntrusted(Self.named([Fixture.meta, Fixture.namedLeaf])))
        #expect(Self.isUntrusted(Self.named([Fixture.dnsLeaf, Fixture.namedLeaf])))
        #expect(Self.isUntrusted(Self.named([Fixture.root, Fixture.namedLeaf])))
    }

    /// Go `VerifyHostname`은 견줄 이름의 대소문자와 끝의 점을 가리지 않는다.
    @Test("이름: 대소문자와 끝의 점은 가리지 않고, 루트나 같은 인증서가 목록에 더 있어도 된다")
    func namedAccepts() {
        #expect(Self.named([Fixture.namedLeaf], name: "DERP-Cert.Example.Test") == nil)
        #expect(Self.named([Fixture.namedLeaf], name: "derp-cert.example.test.") == nil)
        #expect(Self.named([Fixture.namedLeaf, Fixture.root]) == nil)
        #expect(Self.named([Fixture.namedLeaf, Fixture.namedLeaf]) == nil)
    }

    // MARK: SNI 이름

    /// Go 1.27.3 `crypto/tls/handshake_client.go`의 `hostnameInSNI`를 그대로 돌려 얻은 (입력, 출력)이다. 빈 출력은 SNI가
    /// 없다는 뜻이고, 고정 판정은 그때 이름을 보지 않는다.
    private static let goServerNames: [(String, String)] = [
        ("", ""),
        (".", ""),
        ("..", ""),
        ("a", "a"),
        ("a.", "a"),
        ("a..", "a"),
        ("derp1a.example.test", "derp1a.example.test"),
        ("derp1a.example.test.", "derp1a.example.test"),
        ("100.64.0.1", ""),
        ("100.64.0.1.", "100.64.0.1"),
        ("[100.64.0.1]", ""),
        ("100.64.0.1%en0", ""),
        ("[100.64.0.1%en0]", ""),
        ("100.064.0.1", "100.064.0.1"),
        ("0100.64.0.1", "0100.64.0.1"),
        ("100.64.1", "100.64.1"),
        ("100.64.0.256", "100.64.0.256"),
        ("0x64.64.0.1", "0x64.64.0.1"),
        ("1681915905", "1681915905"),
        ("100.64.0.1:443", "100.64.0.1:443"),
        (" 100.64.0.1", " 100.64.0.1"),
        ("100.64.0.1 ", "100.64.0.1 "),
        ("0.0.0.0", ""),
        ("255.255.255.255", ""),
        ("::", ""),
        ("::1", ""),
        ("[::1]", ""),
        ("[::1].", "[::1]"),
        ("::1.", "::1"),
        ("fd7a:115c:a1e0::1", ""),
        ("FD7A:115C:A1E0::1", ""),
        ("[fd7a:115c:a1e0::1]", ""),
        ("[[::1]]", "[[::1]]"),
        ("[::1", "[::1"),
        ("::1]", "::1]"),
        ("fe80::1%en0", ""),
        ("[fe80::1%en0]", ""),
        ("fe80::1%", ""),
        ("fe80::1%25en0", ""),
        ("fe80::1%en0%en1", "fe80::1%en0%en1"),
        ("%en0", "%en0"),
        ("%", "%"),
        ("a%b", "a%b"),
        ("[%]", "[%]"),
        ("[", "["),
        ("]", "]"),
        ("[]", "[]"),
        ("[.]", "[.]"),
        ("::ffff:100.64.0.1", ""),
        ("::ffff:100.064.0.1", "::ffff:100.064.0.1"),
        ("::ffff:6440:1", ""),
        ("::100.64.0.1", ""),
        ("64:ff9b::100.64.0.1", ""),
        ("1:2:3:4:5:6:100.64.0.1", ""),
        ("1:2:3:4:5:6:7:100.64.0.1", "1:2:3:4:5:6:7:100.64.0.1"),
        ("1:2:3:4:5:6:7:8", ""),
        ("1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7:8:9"),
        ("1::2::3", "1::2::3"),
        (":::", ":::"),
        ("::1::", "::1::"),
        ("0:0:0:0:0:0:0:1", ""),
        ("00000::1", "00000::1"),
        ("::00001", "::00001"),
        ("::g", "::g"),
        ("1:2:3:4:5:6:7::", ""),
        ("::2:3:4:5:6:7:8", ""),
        ("1::8", ""),
        ("fe80::1%en0.", ""),
        ("[fe80::1%en0].", "[fe80::1%en0]"),
        ("100.64.0.1%", ""),
        ("[::1]%en0", "[::1]%en0"),
        ("::1%en0]", ""),
        ("\u{FF11}\u{FF10}\u{FF10}.64.0.1", "\u{FF11}\u{FF10}\u{FF10}.64.0.1"),
        ("100.64.0.1\u{0}", "100.64.0.1\u{0}"),
        ("100.64.0.1\u{0}.example.test", "100.64.0.1\u{0}.example.test"),
        ("derp%1a.example.test", "derp%1a.example.test"),
        ("::1%\u{301}", ""),
        ("[\u{301}::1]", "[\u{301}::1]"),
    ]

    /// Go와 갈리는 입력. 앞의 둘은 `IPAddress`가 `net.ParseIP`와 달리 다섯 자리 묶음의 IPv6를 받아서다: Swiftail은 IP
    /// 리터럴로 보아 이름 검사를 건너뛰고, Go는 이름으로 견준다. 마지막은 `%`에 결합 문자가 붙은 경우로, Go는 바이트로
    /// 잘라 IP로 보고 Swiftail은 글자 단위로 보아 이름으로 견준다(Swiftail이 더 엄격하다).
    private static let knownServerNameDifferences: Set<String> = ["00000::1", "::00001", "::1%\u{301}"]

    private static func sniHostNameMatchesGo(_ input: String, _ expected: String) {
        #expect(ServerCertificate.sniHostName(input) == (expected.isEmpty ? nil : expected), "입력 \(input.debugDescription)")
    }

    @Test("SNI 이름은 Go hostnameInSNI와 같은 값을 낸다")
    func sniHostNameMatchesGo() {
        for (input, expected) in Self.goServerNames where !Self.knownServerNameDifferences.contains(input) {
            Self.sniHostNameMatchesGo(input, expected)
        }
    }

    @Test("SNI 이름: Go가 IP로 읽지 않는 문자열에서 이름 검사를 건너뛰면 안 된다")
    func sniHostNameDifferences() {
        withKnownIssue("IP 리터럴 판정이 Go net.ParseIP와 다르다") {
            for (input, expected) in Self.goServerNames where Self.knownServerNameDifferences.contains(input) {
                Self.sniHostNameMatchesGo(input, expected)
            }
        }
    }
}

/// `ServerCertificateReviewTests`의 고정 인증서. `tailnet certificate-fixtures`(`Tools/interop/cmd/tailnet/derpcert.go`의
/// `reviewFixtures`)가 만든 것을 그대로 옮겼다. 모두 `derp1a.example.test`의 자체 서명 인증서(P-256, 서버 인증 EKU,
/// 2026-01-01T00:00:00Z ..< 2027-01-01T00:00:00Z)이고 적은 것만 다르다. Go의 고정 판정은 넷 다 읽는다.
enum ServerCertificateReviewFixtures {
    /// 유효 기간이 10년(2026-01-01 ..< 2036-01-01)인 것만 다르다.
    static let longValidityLeaf = der("MIIBjzCCATagAwIBAgIRAOFFbb/j6J2vgIDZNZvRO40wCgYIKoZIzj0EAwIwHjEcMBoGA1UEAxMTZGVycDFhLmV4YW1wbGUudGVzdDAeFw0yNjAxMDEwMDAwMDBaFw0zNjAxMDEwMDAwMDBaMB4xHDAaBgNVBAMTE2RlcnAxYS5leGFtcGxlLnRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATH2STO/rQ/aTsBAg8m0I+PiQoI6MdqUxPRYH0mf4YvmSzMw0QMioyhpaTVVhOK1KUfjG4l2vawc6QHXb10iUJBo1UwUzAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAeBgNVHREEFzAVghNkZXJwMWEuZXhhbXBsZS50ZXN0MAoGCCqGSM49BAMCA0cAMEQCIFQSforo1haJvhAV+ACItlWZk+r9hp0JcUS6//e1FbvOAiB0/D54STV+HKEKhZb22GxycCbGXrHt9jIRrKFDcLKJ1Q==")
    static let longValidityLeafSHA256 = "04be93f33a34909781e021be60a728fe7fc31cd4d7566eaf0230b904ea8bc91e"
    /// 확장 키 용도(EKU)가 없는 것만 다르다.
    static let noEKULeaf = der("MIIBfDCCASGgAwIBAgIRAKN2TC/OpFGn+1DsgWTWxQUwCgYIKoZIzj0EAwIwHjEcMBoGA1UEAxMTZGVycDFhLmV4YW1wbGUudGVzdDAeFw0yNjAxMDEwMDAwMDBaFw0yNzAxMDEwMDAwMDBaMB4xHDAaBgNVBAMTE2RlcnAxYS5leGFtcGxlLnRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQS2RaxVXO4UbeFxsjs5MMU6NCvspOoUA04rpik/+BNh7lSkLddcl00m2J0wRbFB5idtZ52Xkat2nDcCT6KcGiRo0AwPjAOBgNVHQ8BAf8EBAMCBaAwDAYDVR0TAQH/BAIwADAeBgNVHREEFzAVghNkZXJwMWEuZXhhbXBsZS50ZXN0MAoGCCqGSM49BAMCA0kAMEYCIQCVVEsAe3LF73KM0NUT6db5WrOgFVMTFs4Bw6QkYRMiYwIhANPpHykCY1tj3+bGvUm41oDCqM1ZG55M4AfpMaz1hiBi")
    static let noEKULeafSHA256 = "21a30850b6d41f14f30f33ed65623c0cddb74ee8afa15f933ea3e58507b4fbac"
    /// 키가 Ed25519인 것만 다르다(키 용도는 디지털 서명).
    static let ed25519Leaf = der("MIIBUDCCAQKgAwIBAgIRAMM5JyrMoelVY1biBi4GBwgwBQYDK2VwMB4xHDAaBgNVBAMTE2RlcnAxYS5leGFtcGxlLnRlc3QwHhcNMjYwMTAxMDAwMDAwWhcNMjcwMTAxMDAwMDAwWjAeMRwwGgYDVQQDExNkZXJwMWEuZXhhbXBsZS50ZXN0MCowBQYDK2VwAyEAGrwtrGxcTuFBC94Z0+4HMInOYIMrureUKmx33u+Ng1yjVTBTMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB4GA1UdEQQXMBWCE2RlcnAxYS5leGFtcGxlLnRlc3QwBQYDK2VwA0EAMx9VXMFbLvBI5ROHsPQeyYUmm8WBllplsQYsCcQDSdnlml+MRay6ymrh0oOaeUj2s+4DEDYQ3GmyBFAKAQ3TBg==")
    static let ed25519LeafSHA256 = "f0f10a676b31c2799429a8c1e37d2161432dd1d53fb15227c4cc56bd30a6b9c2"
    /// 주체 CN이 VisibleString(태그 26)으로 쓴 `derpkey00`이다. Go의 x509는 이 형을 CN으로 읽지 않는다(CommonName이 빈다).
    static let visibleStringMeta = der("MIIBfDCCASKgAwIBAgIRAIZYWnlcVZ9yVlv6sjK2WmkwCgYIKoZIzj0EAwIwFDESMBAGA1UEAxoJZGVycGtleTAwMB4XDTI2MDEwMTAwMDAwMFoXDTI3MDEwMTAwMDAwMFowFDESMBAGA1UEAxoJZGVycGtleTAwMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6YdGd29edaWB0Ana83eZ+kw7ji90b150nC7mT4Jqryvn7j4tYDfYyBsczrKlsNGXo7VfmM+YhXsz2UIySck3naNVMFMwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwHgYDVR0RBBcwFYITZGVycDFhLmV4YW1wbGUudGVzdDAKBggqhkjOPQQDAgNIADBFAiBjyG4qTalvoGB87iV7REwl2s0Pk/B9ka0sLW870VFwogIhAOOTPaCV6xtlzJ3n3whWjvGWef6Q9mJl/pJkVS5JGVrL")

    private static func der(_ base64: String) -> [UInt8] {
        [UInt8](Data(base64Encoded: base64) ?? Data())
    }
}
