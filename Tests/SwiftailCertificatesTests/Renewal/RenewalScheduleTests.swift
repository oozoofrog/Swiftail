// Contract §7 unit test 10 (renewal decision): behaviors R1, R3–R5, X5, and H6. All times are passed as arguments.

import Foundation
import Testing

@testable import SwiftailCertificates

@Suite("Renewal decision")
struct RenewalScheduleTests {
    private static let minute: TimeInterval = 60
    private static let hour: TimeInterval = 3600
    private static let day: TimeInterval = 24 * 3600
    /// 2026-11-01T00:00:00Z.
    private static let start = Date(timeIntervalSince1970: 1_793_491_200)

    let domain: CertificateDomain
    let otherDomain: CertificateDomain
    /// A 90-day lifetime. The 2/3 point is day 60.
    let lifetime: CertificateLifetime

    init() throws {
        domain = try #require(CertificateDomain("rd-mac-1a2b3c4d.tail0001.ts.net"))
        otherDomain = try #require(CertificateDomain("rd-mac-5e6f7a8b.tail0001.ts.net"))
        lifetime = CertificateLifetime(domain: domain, notBefore: Self.start, notAfter: Self.start + 90 * Self.day)
    }

    private func decision(_ schedule: RenewalSchedule, at now: Date, holding: CertificateLifetime? = nil) -> RenewalDecision {
        schedule.decision(for: domain, holding: holding, at: now)
    }

    // MARK: - Renewal time (behavior R1)

    @Test("The 2/3 point of the lifetime")
    func renewalDate() {
        #expect(lifetime.renewalDate == Self.start + 60 * Self.day)
        let six = CertificateLifetime(domain: domain, notBefore: Self.start, notAfter: Self.start + 6 * Self.day)
        #expect(six.renewalDate == Self.start + 4 * Self.day)
    }

    @Test("Waits until the 2/3 point if it is in the future and issues immediately once it has passed, including after expiration")
    func beforeAndAfterTwoThirds() {
        let schedule = RenewalSchedule()
        let renewal = Self.start + 60 * Self.day
        #expect(decision(schedule, at: Self.start + Self.day, holding: lifetime) == .wait(until: renewal))
        #expect(decision(schedule, at: renewal - 1, holding: lifetime) == .wait(until: renewal))
        #expect(decision(schedule, at: renewal, holding: lifetime) == .issueNow)
        #expect(decision(schedule, at: lifetime.notAfter + Self.day, holding: lifetime) == .issueNow)
        #expect(decision(schedule, at: Self.start, holding: nil) == .issueNow)
    }

    @Test("A name change triggers issuance even if the current certificate is valid")
    func domainChanged() {
        let held = CertificateLifetime(domain: otherDomain, notBefore: Self.start, notAfter: Self.start + 90 * Self.day)
        #expect(decision(RenewalSchedule(), at: Self.start + Self.day, holding: held) == .issueNow)
    }

    // MARK: - Failures the user must fix (first two rows of behavior R4)

    @Test("Failures the user must fix and a node not running cause no timed retries. Only a change or retryNow wakes the scheduler",
          arguments: [RenewalFailure.needsUserAction, .nodeNotRunning])
    func waitsForChange(failure: RenewalFailure) {
        var schedule = RenewalSchedule()
        schedule.recordFailure(failure, retryAfter: nil, at: Self.start)
        #expect(schedule.backoffUntil == nil)
        for later in [Self.start, Self.start + Self.hour, Self.start + 30 * Self.day, Self.start + 365 * Self.day] {
            #expect(decision(schedule, at: later) == .waitForChange)
        }
        var changed = schedule
        changed.conditionsChanged()
        #expect(decision(changed, at: Self.start + Self.minute) == .issueNow)
        var retried = schedule
        let accepted = retried.retryNow(at: Self.start + Self.minute)
        #expect(accepted)
        #expect(decision(retried, at: Self.start + Self.minute) == .issueNow)
    }

    // MARK: - Intervals and caps (behavior R4 table)

    private func intervals(_ failure: RenewalFailure, count: Int) -> [TimeInterval] {
        var schedule = RenewalSchedule()
        var now = Self.start
        var result: [TimeInterval] = []
        for _ in 0..<count {
            schedule.recordFailure(failure, retryAfter: nil, at: now)
            guard case .wait(let until) = decision(schedule, at: now) else { return result }
            result.append(until.timeIntervalSince(now))
            now = until
        }
        return result
    }

    @Test("Unreachable, deadline exceeded, and 5xx: doubles from 30 seconds, capped at 10 minutes")
    func unreachableBackoff() {
        #expect(intervals(.unreachable, count: 7) == [30, 60, 120, 240, 480, 600, 600])
    }

    @Test("Rejection: doubles from 15 minutes, capped at 6 hours")
    func rejectedBackoff() {
        let m = Self.minute
        #expect(intervals(.rejected, count: 7) == [15 * m, 30 * m, 60 * m, 120 * m, 240 * m, 360 * m, 360 * m])
    }

    @Test("Certificate verification failure: always 6 hours")
    func invalidCertificateInterval() {
        #expect(intervals(.invalidCertificate, count: 3) == [6 * Self.hour, 6 * Self.hour, 6 * Self.hour])
    }

    @Test("Large consecutive failure counts stay at the cap without overflow")
    func hugeCount() {
        #expect(RenewalSchedule.delay(after: .unreachable, consecutiveFailures: .max) == 600)
        #expect(RenewalSchedule.delay(after: .rejected, consecutiveFailures: 1) == 900)
    }

    @Test("A different failure type starts at that type's initial interval")
    func kindChangeResetsExponent() {
        var schedule = RenewalSchedule()
        for _ in 0..<3 { schedule.recordFailure(.unreachable, retryAfter: nil, at: Self.start) }
        #expect(decision(schedule, at: Self.start) == .wait(until: Self.start + 120))
        schedule.recordFailure(.rejected, retryAfter: nil, at: Self.start)
        #expect(decision(schedule, at: Self.start) == .wait(until: Self.start + 15 * Self.minute))
        #expect(schedule.consecutiveFailures == 1)
    }

    // MARK: - Retry-After (behavior X5)

    @Test("Rate limiting uses the server time. Uses 15 minutes if that time is missing or less than 15 minutes away, and caps the wait at 7 days")
    func rateLimited() {
        let cases: [(retryAfter: Date?, expected: Date)] = [
            (nil, Self.start + 15 * Self.minute),
            (Self.start + 5 * Self.minute, Self.start + 15 * Self.minute),
            (Self.start + 3 * Self.hour, Self.start + 3 * Self.hour),
            (Self.start - Self.hour, Self.start + 15 * Self.minute),           // A time in the past causes no wait
            (Self.start + 30 * Self.day, Self.start + 7 * Self.day),          // Only the upper end is capped
        ]
        for (retryAfter, expected) in cases {
            var schedule = RenewalSchedule()
            schedule.recordFailure(.rateLimited, retryAfter: retryAfter, at: Self.start)
            #expect(decision(schedule, at: Self.start) == .wait(until: expected), "\(String(describing: retryAfter))")
        }
    }

    @Test("Uses Retry-After if it is later than the table interval, otherwise uses the table time")
    func retryAfterVersusTable() {
        var later = RenewalSchedule()
        later.recordFailure(.unreachable, retryAfter: Self.start + Self.hour, at: Self.start)
        #expect(decision(later, at: Self.start) == .wait(until: Self.start + Self.hour))
        var earlier = RenewalSchedule()
        earlier.recordFailure(.unreachable, retryAfter: Self.start + 10, at: Self.start)
        #expect(decision(earlier, at: Self.start) == .wait(until: Self.start + 30))
    }

    @Test("Even retryNow() sends no request before the Retry-After time")
    func retryNowBeforeServerTime() {
        var schedule = RenewalSchedule()
        let hold = Self.start + 2 * Self.hour
        schedule.recordFailure(.rateLimited, retryAfter: hold, at: Self.start)
        let before = schedule
        let refused = schedule.retryNow(at: hold - 1)
        #expect(!refused)
        #expect(schedule == before)
        #expect(decision(schedule, at: hold - 1) == .wait(until: hold))
        let accepted = schedule.retryNow(at: hold)
        #expect(accepted)
        #expect(decision(schedule, at: hold) == .issueNow)
    }

    @Test("Later condition failures or successes do not clear the server time")
    func serverTimeSurvives() {
        var schedule = RenewalSchedule()
        let hold = Self.start + 3 * Self.day
        schedule.recordFailure(.rateLimited, retryAfter: hold, at: Self.start)
        schedule.recordFailure(.needsUserAction, retryAfter: nil, at: Self.start + Self.hour)
        #expect(decision(schedule, at: Self.start + Self.hour) == .waitForChange)
        let refused = schedule.retryNow(at: Self.start + 2 * Self.hour)
        #expect(!refused)
        schedule.conditionsChanged()
        #expect(decision(schedule, at: Self.start + 2 * Self.hour) == .wait(until: hold))
        schedule.recordSuccess()
        #expect(decision(schedule, at: Self.start + 2 * Self.hour) == .wait(until: hold))
        #expect(decision(schedule, at: hold) == .issueNow)
    }

    @Test("retryNow() triggers immediate re-evaluation during backoff")
    func retryNowDuringBackoff() {
        var schedule = RenewalSchedule()
        schedule.recordFailure(.rejected, retryAfter: nil, at: Self.start)
        let accepted = schedule.retryNow(at: Self.start + Self.minute)
        #expect(accepted)
        #expect(decision(schedule, at: Self.start + Self.minute) == .issueNow)
    }

    @Test("Changing conditions do not end backoff")
    func conditionsChangeKeepsBackoff() {
        var schedule = RenewalSchedule()
        schedule.recordFailure(.unreachable, retryAfter: nil, at: Self.start)
        schedule.conditionsChanged()
        #expect(decision(schedule, at: Self.start) == .wait(until: Self.start + 30))
    }

    // MARK: - Success (behavior R5)

    @Test("Success clears the failure record and makes the next failure start at the initial interval")
    func successResets() {
        var schedule = RenewalSchedule()
        for _ in 0..<4 { schedule.recordFailure(.unreachable, retryAfter: nil, at: Self.start) }
        schedule.recordSuccess()
        #expect(schedule.lastFailure == nil)
        #expect(schedule.consecutiveFailures == 0)
        #expect(decision(schedule, at: Self.start, holding: lifetime) == .wait(until: lifetime.renewalDate))
        schedule.recordFailure(.unreachable, retryAfter: nil, at: Self.start)
        #expect(decision(schedule, at: Self.start) == .wait(until: Self.start + 30))
    }

    @Test("If the current certificate is not due for renewal, waits until renewal time even after backoff ends")
    func freshCertificateWithBackoff() {
        var schedule = RenewalSchedule()
        schedule.recordFailure(.unreachable, retryAfter: nil, at: Self.start)
        #expect(decision(schedule, at: Self.start + Self.hour, holding: lifetime) == .wait(until: lifetime.renewalDate))
    }
}
