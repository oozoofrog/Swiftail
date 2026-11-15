import Foundation

/// `CertificateManager`의 지금 모습. 앱이 화면에 보이고(만료 시각, 실패의 문구, 다음 시도 시각) "지금 다시 시도"를
/// 붙일지 정하는 데 쓴다.
public struct CertificateStatus: Sendable, Equatable {
    /// 인증서를 받으려는 이름. 노드의 이름을 아직 모르면 nil.
    public var domain: String?
    /// 지금 쥔 인증서의 만료 시각. 없으면 nil.
    public var notAfter: Date?
    /// 마지막 시도가 실패한 까닭. 성공하면 nil로 돌아간다.
    public var lastFailure: CertificateFailure?
    /// 다음에 발급이나 갱신을 시도할 시각. ACME 서버가 `Retry-After`로 알려 준 시각이 더 늦으면 그 시각이다(7일로 묶는다.
    /// 동작 X5). 조건(로그인, MagicDNS, HTTPS, cert 도메인)을 기다리는 중이면 nil이다: 시간으로 다시 시도하지 않는다.
    public var nextAttempt: Date?

    /// 값을 직접 채운다. 관리자는 자기 상태에서 만들므로 쓰지 않는다. 이 타입을 받는 쪽의 코드를 관리자 없이 시험할 때 쓴다.
    public init(domain: String? = nil, notAfter: Date? = nil, lastFailure: CertificateFailure? = nil, nextAttempt: Date? = nil) {
        self.domain = domain
        self.notAfter = notAfter
        self.lastFailure = lastFailure
        self.nextAttempt = nextAttempt
    }
}
