import Foundation

/// 쥔 인증서의 이름과 유효 기간. 갱신 판정(`RenewalSchedule`)의 입력이다.
///
/// 값은 검증을 통과한 leaf에서 Security가 꺼낸 것이다(`VerifiedCertificate.lifetime`).
struct CertificateLifetime: Sendable, Equatable {
    /// 인증서의 이름. 노드의 이름이 바뀌면 이 값과 달라져 새로 발급한다(계약 동작 S4).
    let domain: CertificateDomain
    let notBefore: Date
    let notAfter: Date

    /// 갱신을 시작하는 시각: 수명의 2/3 지점(계약 동작 R1, H6).
    ///
    /// Go가 ARI 조회에 실패했을 때 쓰는 규칙이다(`feature/acme/cert.go:233-251`, 노트 4.4 1). 이 규칙이 Let's Encrypt의
    /// 속도 제한을 피한다는 보장은 없다(노트 4.5).
    // shortcut: ARI(RFC 9773)와 `replaces`를 쓰지 않는다. 인증 기관이 갱신 시점을 앞당겨 알리거나(대량 폐기) ARI 갱신의
    // 제한 면제가 필요해지면 다시 본다(계약 8절 `shortcut:` 표).
    var renewalDate: Date {
        notBefore.addingTimeInterval(notAfter.timeIntervalSince(notBefore) * 2 / 3)
    }
}
