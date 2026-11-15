import CryptoKit
import Foundation
import os
import Swiftail
import SwiftailControl
import Synchronization

/// 노드 자신의 ts.net 이름에 대한 인증서를 받아 두고, 만료 전에 갱신한다. tsnet `CertPair`·`GetCertificate`.
///
/// 저장은 노드의 상태 디렉터리 아래 `certs/`에 한다. 다시 시작하면 저장된 것을 검증해 다시 쓴다.
///
/// 가장자리 actor다. 판단은 값 타입이 한다: 주문 절차는 `ACMEOrderFlow`, 언제 시도할지는 `RenewalSchedule`, 사슬의
/// 검증은 `VerifiedCertificate`. 관리자는 노드의 사실, 시계, 깨우기, 디스크, ACME 전송을 그것들에 잇는다.
///
/// 한 노드에 관리자를 둘 만들지 않는다. 같은 `certs/`를 두 관리자나 두 프로세스가 함께 쓰는 것은 막지 못한다(Go의
/// 잠금도 프로세스 사이의 파일 잠금이 아니다. 동작 C9).
public actor CertificateManager {
    /// 제어 서버에 TXT 레코드를 올린다(`TailnetNode.setDNS(name:value:)`).
    typealias SetDNS = @Sendable (_ name: String, _ value: String) async throws(ControlError) -> Void
    /// 그 시각까지 기다린다. 취소되면 `CancellationError`.
    typealias Sleep = @Sendable (_ until: Date) async throws(CancellationError) -> Void

    private static let log = Logger(subsystem: "Swiftail", category: "certificates")

    private let facts: AsyncStream<CertificateFacts>
    private let setDNS: SetDNS
    private let store: CertificateStore
    private let transport: any ACMETransport
    private let directoryURL: String
    private let anchors: CertificateTrustAnchors
    private let now: @Sendable () -> Date
    private let sleep: Sleep
    private let makeCertificateKey: @Sendable () -> P256.Signing.PrivateKey

    private let certificateStream: AsyncStream<TailnetCertificate>
    private let certificateContinuation: AsyncStream<TailnetCertificate>.Continuation
    private let wake = WakeSignal()

    private var hasStarted = false
    /// 마지막으로 받은 노드의 사실. 첫 사실 전이면 nil.
    private var latestFacts: CertificateFacts?
    /// 사실이 바뀐 횟수. 발급이 도는 동안 바뀌었는지를 본다.
    private var factsGeneration = 0
    private var schedule = RenewalSchedule()
    /// 지금 쥐고 낸 인증서.
    private var held: VerifiedCertificate?
    /// `certs/`에서 저장된 인증서를 찾아본 이름. 이름마다 한 번만 읽는다.
    private var loadedDomain: CertificateDomain?
    /// 계정 키와 계정 URL(`kid`)은 메모리에만 둔다(동작 C4). Go도 계정 URL을 저장하지 않는다(노트 3.7).
    // shortcut: 계정 URL을 저장하지 않으므로 `run()`마다 계정 찾기 요청 하나가 더 나간다. 요청 하나를 아껴야 할 때 다시 본다.
    private var accountKey: P256.Signing.PrivateKey?
    private var accountURL: String?
    private var isIssuing = false
    /// 동작 C1의 조건이 맞지 않는 까닭. 조건이 맞으면 nil.
    private var conditionFailure: CertificateFailure?
    /// 마지막 발급 시도의 실패. 성공하면 nil.
    private var attemptFailure: CertificateFailure?
    private var nextAttempt: Date?

    /// - Throws: 디렉터리 URL이 `https`가 아니면 `invalidConfiguration`.
    public init(node: TailnetNode, configuration: CertificateConfiguration = CertificateConfiguration()) throws(CertificateError) {
        try self.init(
            facts: node.certificateFacts,
            setDNS: { name, value throws(ControlError) in try await node.setDNS(name: name, value: value) },
            stateDirectory: node.stateDirectory,
            transport: URLSessionACMETransport(),
            configuration: configuration
        )
    }

    /// 노드 없이 접점을 직접 받는다. 공개 init이 노드에서 꺼낸 넷(사실의 흐름, `setDNS`, 상태 디렉터리, 운영 전송)을
    /// 넘기고, 시험은 가짜 전송과 넘기는 시계로 돈다. 공개 옵션이 아니다.
    ///
    /// - Parameters:
    ///   - anchors: 받은 사슬과 저장된 사슬을 검증할 루트. 운영은 `.system`, 시험·스테이징은 그 서버의 루트(동작 X3).
    ///   - now: 벽시계(동작 R6).
    ///   - sleep: 기다림. 재시도·갱신 시각과 주문 절차의 기다림에 쓴다.
    ///   - makeCertificateKey: 시도마다 새 인증서 키를 만든다(동작 C7, RFC 8555 11.1).
    init(
        facts: AsyncStream<CertificateFacts>,
        setDNS: @escaping SetDNS,
        stateDirectory: URL,
        transport: any ACMETransport,
        configuration: CertificateConfiguration,
        anchors: CertificateTrustAnchors = .system,
        now: @escaping @Sendable () -> Date = { Date() },
        sleep: @escaping Sleep = sleepUntil,
        makeCertificateKey: @escaping @Sendable () -> P256.Signing.PrivateKey = { P256.Signing.PrivateKey() }
    ) throws(CertificateError) {
        let directoryURL = configuration.directoryURL.absoluteString
        guard ACMEInputRules.isAcceptableURL(directoryURL) else {
            throw .invalidConfiguration("ACME 디렉터리 URL은 2,048바이트 이하의 https URL이어야 한다")
        }
        self.facts = facts
        self.setDNS = setDNS
        store = CertificateStore(stateDirectory: stateDirectory)
        self.transport = transport
        self.directoryURL = directoryURL
        self.anchors = anchors
        self.now = now
        self.sleep = sleep
        self.makeCertificateKey = makeCertificateKey
        (certificateStream, certificateContinuation) = AsyncStream.makeStream(bufferingPolicy: .bufferingNewest(1))
    }

    // MARK: - 공개 API

    /// 인증서를 받고 갱신하는 일을 한다. `node.run()`과 같은 Task 묶음에서 돌린다. 취소될 때까지 돈다.
    ///
    /// 발급의 실패는 던지지 않고 `status`에 적는다. 사용자가 tailnet 설정을 고쳐야 하는 실패(MagicDNS·HTTPS가 꺼짐,
    /// 이름이 cert 도메인에 없음)는 netmap이 바뀌거나 `retryNow()`가 불릴 때까지 기다리고, 그 밖의 실패(ACME 서버의
    /// 거절, 연결 끊김)는 물러났다가 다시 시도한다(동작 R4). 다시 돌려도 소용없는 실패(`CertificateError`)만 던진다.
    ///
    /// 돌아오면(취소, 던짐) `certificates`도 끝난다.
    public func run() async throws(CertificateError) {
        guard !hasStarted else { throw .invalidConfiguration("run()은 한 번만 부를 수 있다") }
        hasStarted = true
        defer { certificateContinuation.finish() }
        let facts = self.facts
        let outcome = await withTaskGroup(of: Void.self, returning: Result<Void, CertificateError>.self) { group in
            // 노드의 사실을 받는 일은 같은 묶음의 자식이다. `run()`을 부른 Task가 취소되면 함께 멈춘다.
            group.addTask {
                for await value in facts {
                    await self.receive(value)
                }
                await self.factsEnded()
            }
            let outcome = await self.manage()
            group.cancelAll()
            return outcome
        }
        try outcome.get()
    }

    /// 지금 쓸 인증서와, 갱신될 때마다 새 인증서. 저장된 것이 유효하면 그것부터 낸다. 한 Task만 돌 수 있다.
    /// 받아 가지 않은 것이 있으면 가장 새것 하나만 남는다.
    public nonisolated var certificates: AsyncStream<TailnetCertificate> { certificateStream }

    /// 지금의 모습: 쥔 인증서의 만료 시각, 마지막 실패, 다음 시도 시각.
    public var status: CertificateStatus {
        CertificateStatus(
            domain: latestFacts?.fqdn,
            notAfter: held?.lifetime.notAfter,
            lastFailure: conditionFailure ?? attemptFailure,
            nextAttempt: nextAttempt
        )
    }

    /// 물러나 기다리는 중이거나 조건을 기다리는 중이면 기다림을 끝내고 곧바로 다시 본다. 사용자가 tailnet 설정을 고친 뒤
    /// 누르는 "지금 다시 시도"다. 발급이 돌고 있거나, ACME 서버가 `Retry-After`로 알려 준 시각(속도 제한 `rateLimited`
    /// 포함) 전이면 아무 일도 하지 않는다. 그 시각 전에는 그 서버에 요청을 보내지 않는다(동작 X5).
    public func retryNow() {
        guard !isIssuing, schedule.retryNow(at: now()) else { return }
        wake.signal()
    }

    // MARK: - 한 흐름(동작 C9)

    /// 판정하고, 기다리거나 발급하기를 취소될 때까지 되풀이한다. 발급은 이 흐름 안에서만 차례로 돈다.
    private func manage() async -> Result<Void, CertificateError> {
        while !Task.isCancelled {
            do {
                switch try plan(at: now()) {
                case .wait(let until):
                    await waitForWake(until: until)
                case .issue(let domain):
                    try await issue(for: domain)
                }
            } catch {
                Self.log.error("인증서 관리를 멈춘다: \(Self.kind(of: error), privacy: .public)")
                return .failure(error)
            }
        }
        return .success(())
    }

    private enum Plan {
        /// 이 시각까지(nil이면 사실이 바뀌거나 `retryNow()`까지) 기다린다.
        case wait(until: Date?)
        case issue(CertificateDomain)
    }

    /// 깨어날 때마다(동작 R3) 지금의 사실·쥔 인증서·실패 기록으로 할 일을 정한다. 요청은 보내지 않는다.
    private func plan(at now: Date) throws(CertificateError) -> Plan {
        guard let facts = latestFacts else { return .wait(until: nil) }
        let domain: CertificateDomain
        switch Self.eligibility(of: facts) {
        case .blocked(let failure):
            if failure != conditionFailure {
                Self.log.notice("인증서 조건이 맞지 않는다: \(Self.kind(of: failure), privacy: .public). 조건이 바뀔 때까지 기다린다")
            }
            conditionFailure = failure
            nextAttempt = nil
            return .wait(until: nil)
        case .eligible(let eligible):
            domain = eligible
        }
        conditionFailure = nil

        // 동작 C3: 이름마다 한 번 저장된 것을 읽는다.
        // shortcut: 이름이 바뀌어도 옛 이름의 파일은 지우지 않는다(동작 S4). 이름이 자주 바뀌는 사용처가 생기면 다시 본다.
        if loadedDomain != domain {
            loadedDomain = domain
            if held?.lifetime.domain != domain, let stored = try loadStoredCertificate(for: domain, at: now) {
                Self.log.info("저장된 인증서를 쓴다. 만료 \(Self.format(stored.lifetime.notAfter), privacy: .public)")
                adopt(stored)
            }
        }

        switch schedule.decision(for: domain, holding: held?.lifetime, at: now) {
        case .issueNow:
            return .issue(domain)
        case .wait(let until):
            nextAttempt = until
            return .wait(until: until)
        case .waitForChange:
            nextAttempt = nil
            return .wait(until: nil)
        }
    }

    /// 사실이 바뀌거나, `retryNow()`가 불리거나, 그 시각이 될 때 가운데 먼저 오는 것까지 기다린다.
    private func waitForWake(until deadline: Date?) async {
        let wake = self.wake
        let sleep = self.sleep
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await wake.wait() }
            if let deadline {
                group.addTask { try? await sleep(deadline) }
            }
            await group.next()
            group.cancelAll()
        }
    }

    /// 발급을 한 번 시도한다(동작 C4~C8). 실패는 `schedule`과 `status`에 적고 던지지 않는다.
    ///
    /// 도는 동안 사실이 바뀌어도(이름이 바뀜, 노드가 멈춤) 그 시도를 끊지 않는다. 계약이 끊으라고 정하지 않았고(동작 C9는
    /// 사실의 변화가 기다림만 깨운다고 한다) 시도는 5분 기한(동작 C10) 안에 끝난다. 바뀐 사실은 다음 판정이 본다.
    ///
    /// - Throws: 계정 키를 읽지 못함(`accountKeyUnreadable`), `certs/`의 실패(`storage`). 취소되면 아무것도 적지 않고
    ///   돌아온다.
    private func issue(for domain: CertificateDomain) async throws(CertificateError) {
        isIssuing = true
        nextAttempt = nil
        defer { isIssuing = false }
        let generation = factsGeneration
        let accountKey = try loadAccountKey()
        let certificateKey = makeCertificateKey()
        let flow = ACMEOrderFlow(
            directoryURL: directoryURL, domain: domain, accountKey: accountKey, accountURL: accountURL,
            certificateKey: certificateKey
        )
        let setDNS = self.setDNS
        Self.log.info("인증서 발급을 시작한다")
        let result: ACMEIssuanceResult
        do {
            result = try await issueCertificate(with: flow, transport: transport, now: now, sleep: sleep) { name, value in
                do throws(ControlError) {
                    try await setDNS(name, value)
                    return nil
                } catch {
                    return Self.failure(for: error)
                }
            }
        } catch {
            return
        }

        let finishedAt = now()
        switch result {
        case .issued(let pem, let url):
            accountURL = url
            let verified: VerifiedCertificate
            do {
                verified = try VerifiedCertificate(
                    pemChain: pem, maximumByteCount: ACMEInputRules.maximumCertificateChainByteCount,
                    privateKey: certificateKey, domain: domain, at: finishedAt, anchors: anchors
                )
            } catch {
                recordFailure(.invalidCertificate, retryAfter: nil, at: finishedAt)
                break
            }
            // 동작 C8: 검증을 통과한 것만 저장하고, 저장한 뒤에 낸다.
            do {
                try store.save(verified)
            } catch {
                throw CertificateError(error)
            }
            schedule.recordSuccess()
            attemptFailure = nil
            // 도는 동안 이름이 바뀌었으면 받은 것은 저장만 하고 내지 않는다. 지금 이름의 것이 아닌 인증서가 앱의 TLS 신원이
            // 되지 않게 한다. 다음 판정이 지금 이름으로 디스크를 읽거나 새로 발급한다.
            if let facts = latestFacts, Self.eligibility(of: facts) == .eligible(domain) {
                adopt(verified)
            }
            Self.log.info("인증서를 받았다. 만료 \(Self.format(verified.lifetime.notAfter), privacy: .public)")
        case .failed(let failure, let retryNotBefore, let url):
            if let url { accountURL = url }
            recordFailure(failure, retryAfter: retryNotBefore, at: finishedAt)
        }
        // 도는 동안 사실이 바뀌었으면, 그 시도의 실패가 세운 조건 기다림은 이미 지난 조건에 대한 것이다.
        if factsGeneration != generation {
            schedule.conditionsChanged()
        }
    }

    private func recordFailure(_ failure: CertificateFailure, retryAfter: Date?, at date: Date) {
        attemptFailure = failure
        let (kind, serverDate) = Self.renewalFailure(for: failure)
        schedule.recordFailure(kind, retryAfter: [retryAfter, serverDate].compactMap { $0 }.max(), at: date)
        if let next = [schedule.backoffUntil, schedule.serverRetryAfter].compactMap({ $0 }).max(), !schedule.isAwaitingChange {
            let seconds = Int(next.timeIntervalSince(date).rounded(.up))
            Self.log.notice("인증서 발급 실패: \(Self.kind(of: failure), privacy: .public). \(seconds)초 뒤에 다시 시도한다")
        } else {
            Self.log.notice("인증서 발급 실패: \(Self.kind(of: failure), privacy: .public). 조건이 바뀔 때까지 기다린다")
        }
    }

    private func adopt(_ certificate: VerifiedCertificate) {
        held = certificate
        certificateContinuation.yield(TailnetCertificate(certificate))
    }

    // MARK: - 디스크

    /// 계정 키(동작 C4): 파일이 없을 때만 새로 만들어 저장한 뒤에 쓴다. 이 흐름 안에서만 불리므로 둘이 겹치지 않는다.
    private func loadAccountKey() throws(CertificateError) -> P256.Signing.PrivateKey {
        if let accountKey { return accountKey }
        let key: P256.Signing.PrivateKey
        do {
            if let stored = try store.accountKey() {
                key = stored
            } else {
                key = P256.Signing.PrivateKey()
                try store.saveAccountKey(key)
            }
        } catch {
            throw CertificateError(error)
        }
        accountKey = key
        return key
    }

    private func loadStoredCertificate(for domain: CertificateDomain, at now: Date) throws(CertificateError) -> VerifiedCertificate? {
        do {
            return try store.certificate(for: domain, at: now, anchors: anchors)
        } catch {
            throw CertificateError(error)
        }
    }

    // MARK: - 사실과 깨우기

    private func receive(_ facts: CertificateFacts) {
        guard facts != latestFacts else { return }
        latestFacts = facts
        factsGeneration += 1
        schedule.conditionsChanged()
        wake.signal()
    }

    /// 노드의 `run()`이 끝나 사실의 흐름이 끝났다. 노드가 멈춘 것으로 보고 취소를 기다린다.
    private func factsEnded() {
        let last = latestFacts
        receive(CertificateFacts(isRunning: false, fqdn: last?.fqdn, certDomains: last?.certDomains ?? [], isMagicDNSEnabled: last?.isMagicDNSEnabled ?? false))
    }

    // MARK: - 값 함수

    /// 동작 C1의 네 조건과 C2의 이름 검사를 차례로 본 결과.
    enum Eligibility: Equatable {
        case eligible(CertificateDomain)
        case blocked(CertificateFailure)
    }

    static func eligibility(of facts: CertificateFacts) -> Eligibility {
        guard facts.isRunning else { return .blocked(.nodeNotRunning) }
        guard facts.isMagicDNSEnabled else { return .blocked(.magicDNSDisabled) }
        guard !facts.certDomains.isEmpty else { return .blocked(.httpsNotEnabled) }
        guard let fqdn = facts.fqdn, facts.certDomains.contains(fqdn), let domain = CertificateDomain(fqdn) else {
            return .blocked(.domainNotAllowed)
        }
        return .eligible(domain)
    }

    /// 제어 서버의 실패(`set-dns`)를 발급 실패로 옮긴다. 연관 문자열은 고정 문구다(동작 K3).
    static func failure(for error: ControlError) -> CertificateFailure {
        switch error {
        case .http(let status): .controlRejected(status: status)
        case .invalidConfiguration: .domainNotAllowed
        case .connection, .storage, .authKeyRejected, .registrationRejected, .nodeKeyExpired, .tailnetLockEnabled:
            .network("제어 서버에 닿지 못했다")
        }
    }

    /// 발급 실패를 동작 R4 표의 줄로 옮긴다. 속도 제한이 알려 준 시각도 함께 낸다.
    static func renewalFailure(for failure: CertificateFailure) -> (RenewalFailure, retryAfter: Date?) {
        switch failure {
        case .magicDNSDisabled, .httpsNotEnabled, .domainNotAllowed: (.needsUserAction, nil)
        case .nodeNotRunning: (.nodeNotRunning, nil)
        case .network, .timedOut, .controlRejected: (.unreachable, nil)
        case .acme(let status, _) where (500..<600).contains(status): (.unreachable, nil)
        case .acme, .validationFailed, .orderFailed, .unexpectedResponse: (.rejected, nil)
        case .rateLimited(let retryAfter): (.rateLimited, retryAfter)
        case .invalidCertificate: (.invalidCertificate, nil)
        }
    }

    /// 로그에 남기는 실패의 종류. 연관 문자열(`type`의 URI, 진단 문구)은 싣지 않는다(동작 K2).
    static func kind(of failure: CertificateFailure) -> String {
        switch failure {
        case .nodeNotRunning: "nodeNotRunning"
        case .magicDNSDisabled: "magicDNSDisabled"
        case .httpsNotEnabled: "httpsNotEnabled"
        case .domainNotAllowed: "domainNotAllowed"
        case .controlRejected(let status): "controlRejected(\(status))"
        case .acme(let status, _): "acme(\(status))"
        case .rateLimited: "rateLimited"
        case .validationFailed: "validationFailed"
        case .orderFailed: "orderFailed"
        case .unexpectedResponse: "unexpectedResponse"
        case .invalidCertificate: "invalidCertificate"
        case .network: "network"
        case .timedOut: "timedOut"
        }
    }

    private static func kind(of error: CertificateError) -> String {
        switch error {
        case .invalidConfiguration: "invalidConfiguration"
        case .storage: "storage"
        case .accountKeyUnreadable: "accountKeyUnreadable"
        }
    }

    private static func format(_ date: Date) -> String {
        date.formatted(.iso8601)
    }
}

/// 계정 키와 계정 URL을 쥐므로 아무것도 드러내지 않는다(동작 K1).
extension CertificateManager: CustomStringConvertible, CustomReflectable {
    public nonisolated var description: String { "CertificateManager" }

    public nonisolated var customMirror: Mirror {
        Mirror(self, children: [:] as KeyValuePairs<String, Any>, displayStyle: .class)
    }
}

/// 관리자의 기다림을 깨우는 신호. 기다리는 쪽이 없을 때 온 신호는 하나만 남겨 다음 기다림이 곧바로 끝나게 한다(놓치는
/// 깨움이 없게). 기다리는 Task가 취소되면 기다림이 끝난다.
///
/// actor가 아니라 잠금으로 지킨다: 취소 처리기는 동기 함수라 actor로 건너가려면 새 Task가 필요하기 때문이다.
private final class WakeSignal: Sendable {
    private struct State {
        var isPending = false
        var waiter: CheckedContinuation<Void, Never>?
    }

    private let state = Mutex(State())

    func signal() {
        let waiter = state.withLock { state -> CheckedContinuation<Void, Never>? in
            guard let waiter = state.waiter else {
                state.isPending = true
                return nil
            }
            state.waiter = nil
            return waiter
        }
        waiter?.resume()
    }

    func wait() async {
        await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                let resumeNow = state.withLock { state -> Bool in
                    if state.isPending {
                        state.isPending = false
                        return true
                    }
                    if Task.isCancelled { return true }
                    state.waiter = continuation
                    return false
                }
                if resumeNow { continuation.resume() }
            }
        } onCancel: {
            let waiter = state.withLock { state -> CheckedContinuation<Void, Never>? in
                defer { state.waiter = nil }
                return state.waiter
            }
            waiter?.resume()
        }
    }
}
