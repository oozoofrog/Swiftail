import CryptoKit
import Foundation
import Security

/// 사슬 검증에서 믿을 루트(계약 동작 S3 ⑤·X3 ④·C8).
///
/// 운영은 `system`만 쓴다. Go와 다른 선택이다: Go는 시스템 루트로 실패하면 내장 Let's Encrypt 루트로 다시 검사하고,
/// 비운영 디렉터리에서는 "모르는 인증 기관" 오류를 통과시킨다(`feature/acme/certstore.go:440-477`). Swiftail은 둘 다
/// 옮기지 않고, 시험과 스테이징은 앵커를 명시적으로 준다(Go `testRoots`의 자리).
package enum CertificateTrustAnchors: Sendable, Equatable {
    /// OS의 기본 신뢰 저장소(`SecTrust`의 기본 앵커).
    case system
    /// 이 DER 인증서들만 믿는다. 시스템 루트는 쓰지 않는다(`SecTrustSetAnchorCertificatesOnly`).
    case only([[UInt8]])
}

/// 받은 사슬이 검증을 통과하지 못한 까닭. `CertificateManager`는 모두 `CertificateFailure.invalidCertificate`로 낸다.
///
/// 이름과 경로를 담지 않는다(계약 동작 K3). `untrusted`의 상태 코드는 Security의 오류 코드(`SecBase.h`의 `errSec…`)다.
enum CertificateVerificationError: Error, Sendable, Equatable {
    /// PEM이 틀렸거나, `CERTIFICATE`가 아닌 블록이 있거나, 1~5장이 아니다(동작 X3 ①·②).
    case malformedChain(PEMError)
    /// DER가 X.509 인증서로 읽히지 않았다(`SecCertificateCreateWithData`가 nil).
    case unparsableCertificate
    /// leaf의 공개 키가 쥔 개인 키의 공개 키와 다르다(동작 X3 ③·S3 ④).
    case keyMismatch
    /// leaf에서 유효 기간을 꺼내지 못했다.
    case validityUnavailable
    /// `notAfter − notBefore`가 1시간보다 짧다(동작 X3 ⑤).
    case lifetimeTooShort
    /// `SecTrust`가 받지 않았다: 이름, 지금 시각의 기간, 사슬(앵커까지) 가운데 하나(동작 X3 ④·S3 ⑤).
    case untrusted(status: Int)
}

/// 검증을 통과한 인증서 사슬과 그 개인 키. 이 타입의 값은 `init`의 검증을 거쳐서만 생긴다.
///
/// ACME가 내려 준 사슬(동작 C8·X3)과 `certs/`에서 읽은 사슬(동작 S3)이 같은 검증을 지난다. 저장소는 이 타입만 쓴다.
/// 그래서 검증하지 않은 사슬이 디스크에 남지 않는다.
///
/// 개인 키를 담으므로 `description`과 `dump`에는 유효 기간만 드러낸다(이름에는 tailnet 이름이 들어 있다. 동작 K).
struct VerifiedCertificate: Sendable {
    /// 인증서의 이름과 유효 기간(leaf의 것).
    let lifetime: CertificateLifetime
    /// 받은 그대로의 사슬(DER, leaf 먼저). `<이름>.crt`에 이것을 쓴다(동작 S6. Go와 같다).
    let receivedChain: [[UInt8]]
    /// TLS 신원에 실을 사슬: 받은 사슬에서 leaf가 아닌 자기 서명 인증서(루트)를 뗀 것(동작 S6).
    /// `TailnetCertificate.chain`이 이것이다.
    let chain: [[UInt8]]
    /// leaf의 개인 키.
    let privateKey: P256.Signing.PrivateKey

    /// 인증서 수명의 하한(동작 X3 ⑤). 짧으면 갱신 판정이 헛돈다.
    static let minimumLifetime: TimeInterval = 3600

    /// PEM 사슬을 읽고 검증한다.
    ///
    /// 차례: ① PEM 전체 검사와 1~5장(`PEM.certificateChain`), ② leaf의 공개 키가 `privateKey`의 것과 같음,
    /// ③ 수명 1시간 이상, ④ `SecTrust`(SSL 서버 정책과 `domain`, 검증 시각 `now`, `anchors`)가 받음.
    /// 통과하면 동작 S6으로 `chain`을 만든다.
    ///
    /// `SecTrustEvaluateWithError`는 부른 스레드를 막는다. 빠진 중간 인증서를 네트워크에서 받지 않게 했으므로
    /// (`SecTrustSetNetworkFetchAllowed`) 서버가 보낸 사슬만으로 검증한다.
    ///
    /// - Parameter maximumByteCount: PEM 입력의 한도(ACME 응답 256KiB, 디스크의 파일 64KiB. 동작 M).
    init(
        pemChain: [UInt8],
        maximumByteCount: Int,
        privateKey: P256.Signing.PrivateKey,
        domain: CertificateDomain,
        at now: Date,
        anchors: CertificateTrustAnchors
    ) throws(CertificateVerificationError) {
        let der: [[UInt8]]
        do {
            der = try PEM.certificateChain(from: pemChain, maximumByteCount: maximumByteCount)
        } catch {
            throw .malformedChain(error)
        }
        let facts = try Self.evaluate(der, publicKey: privateKey.publicKey, domain: domain, at: now, anchors: anchors)
        lifetime = CertificateLifetime(domain: domain, notBefore: facts.notBefore, notAfter: facts.notAfter)
        receivedChain = der
        chain = der.enumerated().filter { index, _ in index == 0 || !facts.isSelfSigned[index] }.map(\.element)
        self.privateKey = privateKey
    }

    /// Security로 본 사슬의 사실. Security의 타입(`SecCertificate`, `SecTrust`)은 이 함수 밖으로 나가지 않는다.
    private struct Facts {
        var notBefore: Date
        var notAfter: Date
        /// 사슬의 각 인증서가 자기 서명(정규화한 주체와 발급자가 같음)인가.
        var isSelfSigned: [Bool]
    }

    private static func evaluate(
        _ der: [[UInt8]],
        publicKey: P256.Signing.PublicKey,
        domain: CertificateDomain,
        at now: Date,
        anchors: CertificateTrustAnchors
    ) throws(CertificateVerificationError) -> Facts {
        let certificates = der.compactMap { SecCertificateCreateWithData(nil, Data($0) as CFData) }
        guard certificates.count == der.count, let leaf = certificates.first else { throw .unparsableCertificate }

        // ② 공개 키: X9.63 비압축 점(04 ‖ X ‖ Y)끼리 견준다(`SecKey.h`의 EC 외부 표현). 공개 값이라 상수 시간이 아니어도 된다.
        guard let leafKey = SecCertificateCopyKey(leaf),
              let leafPoint = SecKeyCopyExternalRepresentation(leafKey, nil) as Data?,
              leafPoint == publicKey.x963Representation
        else { throw .keyMismatch }

        // ③ 기간: macOS 15·iOS 18의 `SecCertificateCopyNotValidBeforeDate`·`…AfterDate`.
        guard let notBefore = SecCertificateCopyNotValidBeforeDate(leaf) as Date?,
              let notAfter = SecCertificateCopyNotValidAfterDate(leaf) as Date?
        else { throw .validityUnavailable }
        guard notAfter.timeIntervalSince(notBefore) >= minimumLifetime else { throw .lifetimeTooShort }

        // ④ 사슬, 이름, 지금 시각.
        let policy = SecPolicyCreateSSL(true, domain.name as CFString)
        var created: SecTrust?
        try check(SecTrustCreateWithCertificates(certificates as CFArray, policy, &created))
        guard let trust = created else { throw .untrusted(status: Int(errSecParam)) }
        try check(SecTrustSetNetworkFetchAllowed(trust, false))
        try check(SecTrustSetVerifyDate(trust, now as CFDate))
        if case .only(let anchorDER) = anchors {
            let anchorCertificates = anchorDER.compactMap { SecCertificateCreateWithData(nil, Data($0) as CFData) }
            // 읽지 못하는 앵커를 빼고 나머지로 검증하면 넓어질 일은 없지만, 시험의 실수를 가리므로 닫는다.
            guard anchorCertificates.count == anchorDER.count else { throw .untrusted(status: Int(errSecParam)) }
            try check(SecTrustSetAnchorCertificates(trust, anchorCertificates as CFArray))
            try check(SecTrustSetAnchorCertificatesOnly(trust, true))
        }
        var error: CFError?
        guard SecTrustEvaluateWithError(trust, &error) else {
            throw .untrusted(status: error.map { CFErrorGetCode($0) } ?? Int(errSecNotTrusted))
        }

        // 동작 S6: 자기 서명의 판별은 정규화한 주체와 발급자의 DER 비교다(`SecCertificate.h`의
        // `SecCertificateCopyNormalizedSubjectSequence`·`…IssuerSequence`).
        let isSelfSigned = certificates.map { certificate in
            guard let subject = SecCertificateCopyNormalizedSubjectSequence(certificate) as Data?,
                  let issuer = SecCertificateCopyNormalizedIssuerSequence(certificate) as Data?
            else { return false }
            return subject == issuer
        }
        return Facts(notBefore: notBefore, notAfter: notAfter, isSelfSigned: isSelfSigned)
    }

    private static func check(_ status: OSStatus) throws(CertificateVerificationError) {
        guard status == errSecSuccess else { throw .untrusted(status: Int(status)) }
    }
}

extension VerifiedCertificate: CustomStringConvertible, CustomReflectable {
    var description: String {
        "VerifiedCertificate(notBefore: \(lifetime.notBefore), notAfter: \(lifetime.notAfter))"
    }

    var customMirror: Mirror {
        Mirror(self, children: ["notBefore": lifetime.notBefore, "notAfter": lifetime.notAfter], displayStyle: .struct)
    }
}
