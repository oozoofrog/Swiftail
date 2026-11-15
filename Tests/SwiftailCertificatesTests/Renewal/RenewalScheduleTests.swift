// 계약 7절 단위 시험 10(갱신 판정): 동작 R1·R3~R5, X5, H6. 시각은 모두 인자로 넘긴다.

import Foundation
import Testing

@testable import SwiftailCertificates

@Suite("갱신 판정")
struct RenewalScheduleTests {
    private static let minute: TimeInterval = 60
    private static let hour: TimeInterval = 3600
    private static let day: TimeInterval = 24 * 3600
    /// 2026-11-01T00:00:00Z.
    private static let start = Date(timeIntervalSince1970: 1_793_491_200)

    let domain: CertificateDomain
    let otherDomain: CertificateDomain
    /// 90일짜리. 2/3 지점은 60일째.
    let lifetime: CertificateLifetime

    init() throws {
        domain = try #require(CertificateDomain("rd-mac-1a2b3c4d.tail0001.ts.net"))
        otherDomain = try #require(CertificateDomain("rd-mac-5e6f7a8b.tail0001.ts.net"))
        lifetime = CertificateLifetime(domain: domain, notBefore: Self.start, notAfter: Self.start + 90 * Self.day)
    }

    private func decision(_ schedule: RenewalSchedule, at now: Date, holding: CertificateLifetime? = nil) -> RenewalDecision {
        schedule.decision(for: domain, holding: holding, at: now)
    }

    // MARK: - 갱신 시점(동작 R1)

    @Test("수명의 2/3 지점")
    func renewalDate() {
        #expect(lifetime.renewalDate == Self.start + 60 * Self.day)
        let six = CertificateLifetime(domain: domain, notBefore: Self.start, notAfter: Self.start + 6 * Self.day)
        #expect(six.renewalDate == Self.start + 4 * Self.day)
    }

    @Test("2/3 전에는 그 시각까지 기다리고, 지나면·만료 뒤에는 곧바로 발급")
    func beforeAndAfterTwoThirds() {
        let schedule = RenewalSchedule()
        let renewal = Self.start + 60 * Self.day
        #expect(decision(schedule, at: Self.start + Self.day, holding: lifetime) == .wait(until: renewal))
        #expect(decision(schedule, at: renewal - 1, holding: lifetime) == .wait(until: renewal))
        #expect(decision(schedule, at: renewal, holding: lifetime) == .issueNow)
        #expect(decision(schedule, at: lifetime.notAfter + Self.day, holding: lifetime) == .issueNow)
        #expect(decision(schedule, at: Self.start, holding: nil) == .issueNow)
    }

    @Test("이름이 바뀌면 쥔 인증서가 유효해도 새로 발급")
    func domainChanged() {
        let held = CertificateLifetime(domain: otherDomain, notBefore: Self.start, notAfter: Self.start + 90 * Self.day)
        #expect(decision(RenewalSchedule(), at: Self.start + Self.day, holding: held) == .issueNow)
    }

    // MARK: - 사용자가 고칠 실패(동작 R4 첫 두 줄)

    @Test("사용자가 고쳐야 하는 실패와 노드가 서지 않음: 시간이 지나도 시도하지 않고 변화나 retryNow에만 깨어난다",
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

    // MARK: - 간격과 상한(동작 R4의 표)

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

    @Test("닿지 못함·기한 초과·5xx: 30초에서 두 배씩, 10분 상한")
    func unreachableBackoff() {
        #expect(intervals(.unreachable, count: 7) == [30, 60, 120, 240, 480, 600, 600])
    }

    @Test("거절: 15분에서 두 배씩, 6시간 상한")
    func rejectedBackoff() {
        let m = Self.minute
        #expect(intervals(.rejected, count: 7) == [15 * m, 30 * m, 60 * m, 120 * m, 240 * m, 360 * m, 360 * m])
    }

    @Test("검증 실패한 인증서: 늘 6시간")
    func invalidCertificateInterval() {
        #expect(intervals(.invalidCertificate, count: 3) == [6 * Self.hour, 6 * Self.hour, 6 * Self.hour])
    }

    @Test("연속 횟수가 커도 넘치지 않고 상한에 머문다")
    func hugeCount() {
        #expect(RenewalSchedule.delay(after: .unreachable, consecutiveFailures: .max) == 600)
        #expect(RenewalSchedule.delay(after: .rejected, consecutiveFailures: 1) == 900)
    }

    @Test("실패의 종류가 바뀌면 그 종류의 처음 간격부터")
    func kindChangeResetsExponent() {
        var schedule = RenewalSchedule()
        for _ in 0..<3 { schedule.recordFailure(.unreachable, retryAfter: nil, at: Self.start) }
        #expect(decision(schedule, at: Self.start) == .wait(until: Self.start + 120))
        schedule.recordFailure(.rejected, retryAfter: nil, at: Self.start)
        #expect(decision(schedule, at: Self.start) == .wait(until: Self.start + 15 * Self.minute))
        #expect(schedule.consecutiveFailures == 1)
    }

    // MARK: - Retry-After(동작 X5)

    @Test("속도 제한: 서버가 준 시각, 없거나 15분보다 이르면 15분, 7일로 묶는다")
    func rateLimited() {
        let cases: [(retryAfter: Date?, expected: Date)] = [
            (nil, Self.start + 15 * Self.minute),
            (Self.start + 5 * Self.minute, Self.start + 15 * Self.minute),
            (Self.start + 3 * Self.hour, Self.start + 3 * Self.hour),
            (Self.start - Self.hour, Self.start + 15 * Self.minute),           // 지난 시각은 기다림이 없다
            (Self.start + 30 * Self.day, Self.start + 7 * Self.day),          // 위쪽 끝만 묶는다
        ]
        for (retryAfter, expected) in cases {
            var schedule = RenewalSchedule()
            schedule.recordFailure(.rateLimited, retryAfter: retryAfter, at: Self.start)
            #expect(decision(schedule, at: Self.start) == .wait(until: expected), "\(String(describing: retryAfter))")
        }
    }

    @Test("Retry-After가 표의 간격보다 늦으면 그 시각, 이르면 표의 시각")
    func retryAfterVersusTable() {
        var later = RenewalSchedule()
        later.recordFailure(.unreachable, retryAfter: Self.start + Self.hour, at: Self.start)
        #expect(decision(later, at: Self.start) == .wait(until: Self.start + Self.hour))
        var earlier = RenewalSchedule()
        earlier.recordFailure(.unreachable, retryAfter: Self.start + 10, at: Self.start)
        #expect(decision(earlier, at: Self.start) == .wait(until: Self.start + 30))
    }

    @Test("Retry-After 시각 전에는 retryNow()도 요청하지 않는다")
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

    @Test("서버의 시각은 뒤의 조건 실패나 성공으로 지워지지 않는다")
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

    @Test("물러나는 중의 retryNow()는 곧바로 다시 보게 한다")
    func retryNowDuringBackoff() {
        var schedule = RenewalSchedule()
        schedule.recordFailure(.rejected, retryAfter: nil, at: Self.start)
        let accepted = schedule.retryNow(at: Self.start + Self.minute)
        #expect(accepted)
        #expect(decision(schedule, at: Self.start + Self.minute) == .issueNow)
    }

    @Test("조건의 변화는 물러남을 끝내지 않는다")
    func conditionsChangeKeepsBackoff() {
        var schedule = RenewalSchedule()
        schedule.recordFailure(.unreachable, retryAfter: nil, at: Self.start)
        schedule.conditionsChanged()
        #expect(decision(schedule, at: Self.start) == .wait(until: Self.start + 30))
    }

    // MARK: - 성공(동작 R5)

    @Test("성공 뒤 초기화: 실패 기록이 지워지고 다음 실패는 처음 간격부터")
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

    @Test("쥔 인증서가 갱신 시점 전이면 물러남이 끝나도 갱신 시점까지 기다린다")
    func freshCertificateWithBackoff() {
        var schedule = RenewalSchedule()
        schedule.recordFailure(.unreachable, retryAfter: nil, at: Self.start)
        #expect(decision(schedule, at: Self.start + Self.hour, holding: lifetime) == .wait(until: lifetime.renewalDate))
    }
}
