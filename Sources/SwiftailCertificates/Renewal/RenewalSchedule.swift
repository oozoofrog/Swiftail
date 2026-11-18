import Foundation

/// Failure classifications used by the renewal decision. Each row of the contract's behavior R4 table is a case.
///
/// `CertificateManager` maps the public `CertificateFailure` type (contract §2) to these classifications. Pass the retry time supplied by the server
/// (`Retry-After`, the value of `rateLimited(retryAfter:)`) separately to `RenewalSchedule.recordFailure`,
/// because it can accompany any row's failure (5xx with `Retry-After`, a poll beyond the deadline, etc., behavior X5).
enum RenewalFailure: Sendable, Equatable {
    /// The user must fix the tailnet configuration (`magicDNSDisabled`, `httpsNotEnabled`, `domainNotAllowed`).
    /// Does not retry on a timer.
    case needsUserAction
    /// The node is not `.running` (`nodeNotRunning`). Waits for the node state to change.
    case nodeNotRunning
    /// Unreachable server, deadline exceeded, or server error (`network`, `timedOut`, `acme` with 5xx status, `controlRejected`).
    /// Starts at 30 seconds and doubles up to 10 minutes.
    case unreachable
    /// Rejection by the ACME server or certificate authority (`validationFailed`, `orderFailed`, `unexpectedResponse`, `acme` with a non-5xx status).
    /// Starts at 15 minutes and doubles up to 6 hours.
    case rejected
    /// A rate limit (`rateLimited`). Wait until the server's time, or 15 minutes if it is absent or sooner than 15 minutes.
    case rateLimited
    /// The received certificate failed verification (`invalidCertificate`). Wait 6 hours.
    case invalidCertificate
}

/// The result of the renewal decision.
enum RenewalDecision: Sendable, Equatable {
    /// Issue or renew now.
    case issueNow
    /// Wait until this time. `CertificateStatus.nextAttempt` is this time.
    case wait(until: Date)
    /// Wait until conditions (node state, netmap) change or `retryNow()` is called. No timer wakes it.
    /// `CertificateStatus.nextAttempt` is nil.
    case waitForChange
}

/// A value type that determines when to issue and when to retry after failure (contract behaviors R and X5).
///
/// Owns no clock or sockets. Each method takes the current time as an argument. The held certificate's validity period and failure kind are also inputs.
/// `CertificateManager` queries `decision(for:holding:at:)` on each wake (behavior R3) and records the result with `recordFailure` or
/// `recordSuccess`.
///
/// No jitter is applied. The contract does not define a formula, and a single node sending requests to a single server has no crowding to disperse.
struct RenewalSchedule: Sendable, Equatable {
    /// The last failure's classification, or nil after a success.
    private(set) var lastFailure: RenewalFailure?
    /// The number of consecutive failures of the same classification. Resets to 1 when the classification changes. Used as the exponent for doubling the interval.
    private(set) var consecutiveFailures = 0
    /// The next attempt time defined by table R4, or nil when waiting for conditions.
    private(set) var backoffUntil: Date?
    /// Avoids timer-based retries until conditions change or `retryNow()` is called.
    private(set) var isAwaitingChange = false
    /// The time the ACME server supplied via `Retry-After` (capped at 7 days). No requests go to that server before this time (behavior X5).
    ///
    /// Stored independently of the failure classification. Later failures (such as unmet conditions) and successes leave it in force until the time passes.
    /// Success can occur only after this time, but this preserves the guarantee if `recordSuccess` is called earlier, such as when using
    /// a stored certificate.
    private(set) var serverRetryAfter: Date?

    /// The upper limit on the server-supplied time is 7 days from now (behavior X5, limits table). Only the upper end is capped.
    static let maximumServerDelay: TimeInterval = 7 * 24 * 3600

    init() {}

    /// Determines whether to attempt issuance or how long to wait.
    ///
    /// - Parameters:
    ///   - domain: The name currently requested (satisfies behaviors C1 and C2).
    ///   - certificate: The held certificate, or nil if absent. A name mismatch with `domain` is treated as absence (behavior S4).
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

    /// Records a failed attempt.
    ///
    /// - Parameter retryAfter: The retry time the server supplied for the failure (`Retry-After`). A past time requires no wait.
    ///   Caps times more than 7 days out at 7 days. If later than the table's time, wait until this time (below the behavior R4 table).
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

    /// Records successful issuance. Clears the failure record and backoff (behavior R5). Retains `serverRetryAfter` (see its comment).
    mutating func recordSuccess() {
        lastFailure = nil
        consecutiveFailures = 0
        backoffUntil = nil
        isAwaitingChange = false
    }

    /// Handles changes to node state, name, cert domains, or MagicDNS (behavior R3). Ends the wait for conditions and preserves backoff.
    mutating func conditionsChanged() {
        isAwaitingChange = false
    }

    /// Handles the user's "Retry Now" action. Ends backoff and the wait for conditions.
    ///
    /// Returns `false` without changes if the server's time has not arrived (behavior X5, which also keeps `retryNow()` from sending an early request).
    @discardableResult
    mutating func retryNow(at now: Date) -> Bool {
        if let serverRetryAfter, serverRetryAfter > now {
            return false
        }
        isAwaitingChange = false
        backoffUntil = nil
        return true
    }

    // MARK: - Contract Behavior R4 Table

    /// The interval from failure to the next attempt. Returns nil for failures without timer-based retries.
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

    /// Caps `base × 2^times` at `limit`. Stops at the limit to avoid overflow even for large `times`.
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
