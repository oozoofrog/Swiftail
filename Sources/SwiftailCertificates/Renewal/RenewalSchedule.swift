import Foundation

/// 갱신 판정이 받는 실패의 분류. 계약 동작 R4 표의 줄 하나가 case 하나다.
///
/// 공개 타입 `CertificateFailure`(계약 2절)를 이 분류로 옮기는 것은 `CertificateManager`의 몫이다. 서버가 알려 준
/// 다시 시도할 시각(`Retry-After`, `rateLimited(retryAfter:)`의 값)은 분류와 따로 `RenewalSchedule.recordFailure`에 준다.
/// 어느 줄의 실패에도 붙을 수 있기 때문이다(5xx와 `Retry-After`, 기한을 넘긴 주문 다시 읽기 등. 동작 X5).
enum RenewalFailure: Sendable, Equatable {
    /// 사용자가 tailnet 설정을 고쳐야 한다(`magicDNSDisabled`, `httpsNotEnabled`, `domainNotAllowed`).
    /// 시간으로 다시 시도하지 않는다.
    case needsUserAction
    /// 노드가 `.running`이 아니다(`nodeNotRunning`). 노드의 상태가 바뀔 때까지 기다린다.
    case nodeNotRunning
    /// 닿지 못함·기한 초과·서버 오류(`network`, `timedOut`, 상태가 5xx인 `acme`, `controlRejected`).
    /// 30초에서 두 배씩, 10분 상한.
    case unreachable
    /// ACME 서버나 인증 기관의 거절(`validationFailed`, `orderFailed`, `unexpectedResponse`, 5xx가 아닌 `acme`).
    /// 15분에서 두 배씩, 6시간 상한.
    case rejected
    /// 속도 제한(`rateLimited`). 서버가 준 시각까지, 없거나 15분보다 이르면 15분 뒤.
    case rateLimited
    /// 받은 인증서가 검증을 통과하지 못했다(`invalidCertificate`). 6시간 뒤.
    case invalidCertificate
}

/// 갱신 판정의 결과.
enum RenewalDecision: Sendable, Equatable {
    /// 지금 발급(또는 갱신)한다.
    case issueNow
    /// 이 시각까지 기다린다. `CertificateStatus.nextAttempt`가 이 시각이다.
    case wait(until: Date)
    /// 조건(노드의 상태, netmap)이 바뀌거나 `retryNow()`가 불릴 때까지 기다린다. 시간으로 깨어나지 않는다.
    /// `CertificateStatus.nextAttempt`는 nil이다.
    case waitForChange
}

/// 언제 발급하고, 실패하면 언제 다시 시도할지를 정하는 값 타입(계약 동작 R, X5).
///
/// 시계와 소켓을 갖지 않는다. 지금 시각은 메서드마다 인자로 받고, 쥔 인증서의 기간과 실패의 종류도 입력이다.
/// `CertificateManager`는 깨어날 때마다(동작 R3) `decision(for:holding:at:)`을 묻고, 시도의 결과를 `recordFailure`나
/// `recordSuccess`로 적는다.
///
/// 지터는 두지 않는다. 계약이 식을 정하지 않았고, 한 노드가 한 서버에 혼자 보내는 요청이라 몰림을 흩을 까닭이 없다.
struct RenewalSchedule: Sendable, Equatable {
    /// 마지막 실패의 분류. 성공하면 nil.
    private(set) var lastFailure: RenewalFailure?
    /// 같은 분류의 실패가 이어진 횟수. 분류가 바뀌면 1부터 다시 센다. 두 배씩 늘리는 간격의 지수다.
    private(set) var consecutiveFailures = 0
    /// R4 표가 정한 다음 시도 시각. 조건을 기다리는 중이면 nil.
    private(set) var backoffUntil: Date?
    /// 조건이 바뀌거나 `retryNow()`가 불릴 때까지 시간으로 다시 시도하지 않는다.
    private(set) var isAwaitingChange = false
    /// ACME 서버가 `Retry-After`로 알려 준 시각(7일로 묶은 것). 이 시각 전에는 그 서버에 요청하지 않는다(동작 X5).
    ///
    /// 실패의 분류와 따로 둔다: 뒤의 실패(예: 조건 실패)가 와도, 성공해도 지우지 않고 시각이 지나야 효력이 없어진다.
    /// 성공은 이 시각 뒤에만 있을 수 있지만, 저장된 인증서를 쓰는 길 등으로 `recordSuccess`가 먼저 불려도 약속이
    /// 깨지지 않게 하려는 것이다.
    private(set) var serverRetryAfter: Date?

    /// 서버가 알려 준 시각의 상한: 지금부터 7일(동작 X5, 한도 표). 위쪽 끝만 묶는다.
    static let maximumServerDelay: TimeInterval = 7 * 24 * 3600

    init() {}

    /// 발급을 시도할지, 언제까지 기다릴지 정한다.
    ///
    /// - Parameters:
    ///   - domain: 지금 받으려는 이름(동작 C1·C2의 조건을 통과한 것).
    ///   - certificate: 쥔 인증서. 없으면 nil. 이름이 `domain`과 다르면 없는 것과 같다(동작 S4).
    func decision(for domain: CertificateDomain, holding certificate: CertificateLifetime?, at now: Date) -> RenewalDecision {
        if isAwaitingChange {
            return .waitForChange
        }
        var earliest = [backoffUntil, serverRetryAfter].compactMap { $0 }.max()
        if let certificate, certificate.domain == domain, now < certificate.renewalDate {
            earliest = max(earliest ?? certificate.renewalDate, certificate.renewalDate)
        }
        if let earliest, earliest > now {
            return .wait(until: earliest)
        }
        return .issueNow
    }

    /// 시도의 실패를 적는다.
    ///
    /// - Parameter retryAfter: 그 실패에 서버가 알려 준 다시 시도할 시각(`Retry-After`). 지난 시각이면 기다림이 없다.
    ///   7일보다 멀면 7일로 묶는다. 표의 시각보다 늦으면 이 시각까지 기다린다(동작 R4 표 아래).
    mutating func recordFailure(_ failure: RenewalFailure, retryAfter: Date?, at now: Date) {
        consecutiveFailures = failure == lastFailure ? consecutiveFailures + 1 : 1
        lastFailure = failure
        if let retryAfter, retryAfter > now {
            let bounded = min(retryAfter, now.addingTimeInterval(Self.maximumServerDelay))
            serverRetryAfter = max(bounded, serverRetryAfter ?? bounded)
        }
        if let delay = Self.delay(after: failure, consecutiveFailures: consecutiveFailures) {
            isAwaitingChange = false
            backoffUntil = now.addingTimeInterval(delay)
        } else {
            isAwaitingChange = true
            backoffUntil = nil
        }
    }

    /// 발급이 성공했다. 실패의 기록과 물러남을 지운다(동작 R5). `serverRetryAfter`는 남긴다(그 주석).
    mutating func recordSuccess() {
        lastFailure = nil
        consecutiveFailures = 0
        backoffUntil = nil
        isAwaitingChange = false
    }

    /// 노드의 상태·이름·cert 도메인·MagicDNS가 바뀌었다(동작 R3). 조건을 기다리던 것을 끝낸다. 물러남은 그대로다.
    mutating func conditionsChanged() {
        isAwaitingChange = false
    }

    /// 사용자의 "지금 다시 시도". 물러남과 조건 기다림을 끝낸다.
    ///
    /// 서버가 알려 준 시각 전이면 아무것도 바꾸지 않고 `false`를 낸다(동작 X5: 그 전에는 `retryNow()`도 요청하지 않는다).
    @discardableResult
    mutating func retryNow(at now: Date) -> Bool {
        if let serverRetryAfter, serverRetryAfter > now {
            return false
        }
        isAwaitingChange = false
        backoffUntil = nil
        return true
    }

    // MARK: - 계약 동작 R4의 표

    /// 실패 뒤 다음 시도까지의 간격. 시간으로 다시 시도하지 않는 실패면 nil.
    static func delay(after failure: RenewalFailure, consecutiveFailures: Int) -> TimeInterval? {
        switch failure {
        case .needsUserAction, .nodeNotRunning:
            nil
        case .unreachable:
            doubling(from: 30, upTo: 10 * 60, times: consecutiveFailures - 1)
        case .rejected:
            doubling(from: 15 * 60, upTo: 6 * 3600, times: consecutiveFailures - 1)
        case .rateLimited:
            15 * 60
        case .invalidCertificate:
            6 * 3600
        }
    }

    /// `base × 2^times`를 `limit`로 묶는다. `times`가 커도 넘치지 않게 한도에 닿으면 멈춘다.
    private static func doubling(from base: TimeInterval, upTo limit: TimeInterval, times: Int) -> TimeInterval {
        var value = base
        var remaining = times
        while remaining > 0, value < limit {
            value *= 2
            remaining -= 1
        }
        return min(value, limit)
    }
}
