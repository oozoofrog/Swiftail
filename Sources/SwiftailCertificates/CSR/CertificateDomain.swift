/// 인증서를 받을 이름. 이름 검사(계약 동작 C2)를 통과한 값만 만들 수 있다.
///
/// 이 이름은 파일 이름(`certs/<이름>.crt`), DNS 레코드 이름(`_acme-challenge.<이름>`), ACME 식별자, CSR의
/// 주체 CN과 SAN이 된다. 경로로 안전한지와 DNS 이름으로 맞는지를 DNS 이름 규칙 하나로 함께 닫는다(RFC 1034
/// 3.1·3.5, RFC 1123 2.1): 끝의 점 하나를 뗀 이름이
///
/// 1. 점으로 나뉜 레이블 둘 이상이고,
/// 2. 레이블마다 1~63자, 처음과 끝은 영숫자, 가운데는 영숫자와 `-`이고,
/// 3. 전체가 253자 이하이고, `_acme-challenge.`를 붙인 레코드 이름도 253자 이하다(그래서 237자 이하).
///
/// 영문자는 소문자만 받는다. 대소문자를 가리지 않는 파일 시스템에서 파일 이름이 겹치지 않게 하는 계약의
/// 좁힘이다. 이 규칙이면 `..`·`/`·`\`·`:`·NUL·`*`·`_`는 저절로 빠지고, 남는 문자는 모두 `PrintableString`과
/// `IA5String`에 든다(계약 동작 C7, 노트 3.6).
///
/// 이름에는 tailnet 이름이 들어 있으므로 `description`을 두지 않는다(로그에 남기지 않는다. 계약 동작 K2).
struct CertificateDomain: Sendable, Hashable {
    /// 끝 점 없는 이름(`rd-mac-1a2b3c4d.tail0001.ts.net`).
    let name: String

    /// 끝 점 없는 이름의 최대 길이. DNS 이름 253자에서 `_acme-challenge.` 16자를 뺀 값이다.
    static let maximumLength = 253 - challengeLabelPrefix.utf8.count

    /// 끝의 점 하나를 떼고 이름 검사를 한다. 어긋나면 `nil`(부르는 쪽은 `domainNotAllowed`로 적는다. 계약 H23).
    init?(_ fqdn: String) {
        let name = fqdn.hasSuffix(".") ? String(fqdn.dropLast()) : fqdn
        let labels = name.utf8.split(separator: UInt8(ascii: "."), omittingEmptySubsequences: false)
        guard name.utf8.count <= Self.maximumLength, labels.count >= 2, labels.allSatisfy(Self.isValidLabel),
              // 끝 레이블이 숫자뿐이면 이름이 아니라 IP 주소 꼴이다(`100.64.0.1`). 인증 기관이 받지 않는다.
              let last = labels.last, !last.allSatisfy({ (UInt8(ascii: "0")...UInt8(ascii: "9")).contains($0) })
        else {
            return nil
        }
        self.name = name
    }

    /// DNS-01 TXT 레코드의 이름(RFC 8555 8.4).
    var challengeRecordName: String {
        Self.challengeLabelPrefix + name
    }

    private static let challengeLabelPrefix = "_acme-challenge."

    private static func isValidLabel(_ label: Substring.UTF8View) -> Bool {
        guard (1...63).contains(label.count), let first = label.first, let last = label.last,
              isLowercaseAlphanumeric(first), isLowercaseAlphanumeric(last)
        else { return false }
        return label.allSatisfy { isLowercaseAlphanumeric($0) || $0 == UInt8(ascii: "-") }
    }

    private static func isLowercaseAlphanumeric(_ byte: UInt8) -> Bool {
        (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(byte) || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte)
    }
}
