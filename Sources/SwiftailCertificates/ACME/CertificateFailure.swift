// 계약 `docs/contracts/SwiftailHost.md` 2절의 선언 그대로다. ACME 주문 절차(M7-4)와 `CertificateManager`(M7-6)가
// 값을 만들고, `CertificateStatus.lastFailure`로 앱에 낸다.

import Foundation

/// 발급이 되지 않는 까닭. 앱은 종류로 사용자 문구를 고르고, 연관 문자열은 진단에만 쓴다.
public enum CertificateFailure: Sendable, Equatable {
    /// 노드가 `.running`이 아니다.
    case nodeNotRunning
    /// tailnet에서 MagicDNS가 꺼져 있다. 사용자가 관리 콘솔에서 켜야 한다.
    case magicDNSDisabled
    /// tailnet에서 HTTPS 인증서가 꺼져 있다(netmap `DNSConfig.CertDomains`가 비었다). 사용자가 관리 콘솔에서 켜야 한다.
    case httpsNotEnabled
    /// 노드의 이름이 netmap의 cert 도메인에 없거나, 동작 C2의 이름 검사에 어긋난다.
    case domainNotAllowed
    /// 제어 서버가 DNS 레코드 요청을 받지 않았다. HTTP 상태 코드.
    case controlRejected(status: Int)
    /// ACME 서버가 성공이 아닌 HTTP 응답으로 거절했다. `status`는 HTTP 상태 코드, `type`은 문제 문서의 `type` 전체
    /// 문자열(`urn:ietf:params:acme:error:badCSR`, 서버 고유 URI, `about:blank`)이다. 문제 문서가 없거나 JSON이
    /// 아니거나 `type`이 없으면 빈 문자열이다. 256바이트로 자른다. 문제 문서의 `detail`은 싣지 않는다(식별자가 들어
    /// 있을 수 있다. 동작 K2).
    case acme(status: Int, type: String)
    /// ACME 서버의 속도 제한(`type`이 `urn:ietf:params:acme:error:rateLimited`). 서버가 알려 준 다시 시도할 시각.
    case rateLimited(retryAfter: Date?)
    /// 인증 기관이 이름의 소유를 확인하지 못했다: authorization이 `invalid`다(DNS 레코드를 찾지 못했거나 값이 달랐다).
    /// `type`은 그 challenge의 `error` 문제 문서의 `type`이다(`acme`와 같은 규칙).
    case validationFailed(type: String)
    /// 주문이 `invalid`가 되었는데 authorization의 실패가 아니다(만료, CSR·발급의 거절 등), 또는 주문을 이어 갈 수 없는
    /// authorization(`deactivated`·`expired`·`revoked`)이 있다. `type`은 주문의 `error` 문제 문서의 `type`이다.
    case orderFailed(type: String)
    /// ACME 서버의 응답이 규격이나 이 계약의 한도에 맞지 않았다(모르는 상태, 다른 이름의 authorization, 한도를 넘는
    /// 본문, `https`가 아닌 URL 등. 동작 C5·X).
    case unexpectedResponse
    /// 받은 인증서가 검증을 통과하지 못했다(이름, 기간, 사슬, 키).
    case invalidCertificate
    /// ACME 서버나 제어 서버에 닿지 못했다.
    case network(String)
    /// 발급이 기한 안에 끝나지 않았다.
    case timedOut
}
