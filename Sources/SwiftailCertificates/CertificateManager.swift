import CryptoKit
import Foundation
import os
import Swiftail
import SwiftailControl
import Synchronization

/// Obtains a certificate for the node's own ts.net name and renews it before expiration. Corresponds to tsnet `CertPair` and `GetCertificate`.
///
/// Stores certificates in `certs/` under the node's state directory. Verifies and reuses the stored certificate on restart.
///
/// An actor at the edge. Value types make decisions: `ACMEOrderFlow` handles the order flow, `RenewalSchedule` determines when to attempt issuance,
/// and `VerifiedCertificate` verifies the chain. The manager connects node facts, the clock, wakeups, disk, and ACME transport to them.
///
/// Create one manager per node. Sharing the same `certs/` across two managers or processes cannot be prevented (Go's lock is also
/// not a cross-process file lock, behavior C9).
public actor CertificateManager {
    /// Publishes a TXT record on the control server (`TailnetNode.setDNS(name:value:)`).
    typealias SetDNS = @Sendable (_ name: String, _ value: String) async throws(ControlError) -> Void
    /// Waits until the given time. Throws `CancellationError` if canceled.
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
    /// The most recently received node facts, or nil before the first facts arrive.
    private var latestFacts: CertificateFacts?
    /// The number of changes to the facts. Used to detect changes during issuance.
    private var factsGeneration = 0
    private var schedule = RenewalSchedule()
    /// The certificate currently held and emitted.
    private var held: VerifiedCertificate?
    /// The most recent name checked for stored certificates in `certs/`. A name change allows another lookup.
    private var loadedDomain: CertificateDomain?
    /// Caches the account key and account URL (`kid`) in memory. Only the key is persisted (behavior C4, notes §3.7). Go also leaves the URL out of storage.
    // shortcut: Keeping the account URL out of storage adds one account lookup request per `run()`. Revisit if that request needs to be saved.
    private var accountKey: P256.Signing.PrivateKey?
    private var accountURL: String?
    private var isIssuing = false
    /// The reason behavior C1's conditions are unmet, or nil when they are met.
    private var conditionFailure: CertificateFailure?
    /// The last issuance attempt's failure, or nil after success.
    private var attemptFailure: CertificateFailure?
    private var nextAttempt: Date?

    /// - Throws: `invalidConfiguration` if the directory URL fails the `https` URL rules in behavior X1 or `trustAnchors` is empty.
    public init(node: TailnetNode, configuration: CertificateConfiguration = CertificateConfiguration()) throws(CertificateError) {
        try self.init(
            facts: node.certificateFacts,
            setDNS: { name, value throws(ControlError) in try await node.setDNS(name: name, value: value) },
            stateDirectory: node.stateDirectory,
            transport: URLSessionACMETransport(),
            configuration: configuration
        )
    }

    /// Takes dependencies directly without a node. The public initializer passes four values from the node (the facts stream, `setDNS`, the state
    /// directory, and production transport), and tests use a fake transport and an advancing clock. This is internal.
    ///
    /// - Parameters:
    ///   - anchors: Roots for verifying received and stored chains (behavior X3). If nil, uses `configuration.trustAnchors`
    ///     (or `.system` if that is also nil).
    ///   - now: The wall clock (behavior R6).
    ///   - sleep: Waits for retry and renewal times and during the order flow.
    ///   - makeCertificateKey: Creates a fresh certificate key for each attempt (behavior C7, RFC 8555 11.1).
    init(
        facts: AsyncStream<CertificateFacts>,
        setDNS: @escaping SetDNS,
        stateDirectory: URL,
        transport: any ACMETransport,
        configuration: CertificateConfiguration,
        anchors: CertificateTrustAnchors? = nil,
        now: @escaping @Sendable () -> Date = { Date() },
        sleep: @escaping Sleep = sleepUntil,
        makeCertificateKey: @escaping @Sendable () -> P256.Signing.PrivateKey = { P256.Signing.PrivateKey() }
    ) throws(CertificateError) {
        let directoryURL = configuration.directoryURL.absoluteString
        guard ACMEInputRules.isAcceptableURL(directoryURL) else {
            throw .invalidConfiguration("The ACME directory URL must be an https URL of at most 2,048 bytes")
        }
        if let configured = configuration.trustAnchors, configured.isEmpty {
            throw .invalidConfiguration("The trust anchor list is empty")
        }
        self.facts = facts
        self.setDNS = setDNS
        store = CertificateStore(stateDirectory: stateDirectory)
        self.transport = transport
        self.directoryURL = directoryURL
        self.anchors = anchors ?? configuration.trustAnchors.map { .only($0) } ?? .system
        self.now = now
        self.sleep = sleep
        self.makeCertificateKey = makeCertificateKey
        (certificateStream, certificateContinuation) = AsyncStream.makeStream(bufferingPolicy: .bufferingNewest(1))
    }

    // MARK: - Public API

    /// Obtains and renews certificates. Run it in the same Task group as `node.run()`. Runs until canceled.
    ///
    /// Records issuance failures in `status` without throwing. If the user must fix tailnet settings (disabled MagicDNS or HTTPS, or a name
    /// absent from the cert domains), it waits for a netmap change or a call to `retryNow()`. For other failures (ACME server rejection or a
    /// lost connection), it backs off and retries (behavior R4). Only failures that restarting would not resolve (`CertificateError`) are thrown.
    ///
    /// The `certificates` stream ends when this call returns after cancellation or an error.
    public func run() async throws(CertificateError) {
        guard !hasStarted else { throw .invalidConfiguration("run() can only be called once") }
        hasStarted = true
        defer { certificateContinuation.finish() }
        let facts = self.facts
        let outcome = await withTaskGroup(of: Void.self, returning: Result<Void, CertificateError>.self) { group in
            // Receive node facts in a child of the same group, so cancellation of the Task that calls `run()` also stops reception.
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

    /// The current certificate and each new certificate upon renewal. Emits the stored certificate first if valid. Only one Task can consume the stream.
    /// Keeps only the newest unread certificate.
    public nonisolated var certificates: AsyncStream<TailnetCertificate> { certificateStream }

    /// The current status, including the held certificate's expiration time, the last failure, and the next attempt time.
    public var status: CertificateStatus {
        CertificateStatus(
            domain: latestFacts?.fqdn,
            notAfter: held?.lifetime.notAfter,
            lastFailure: conditionFailure ?? attemptFailure,
            nextAttempt: nextAttempt
        )
    }

    /// Ends any backoff or wait for conditions and checks again immediately. This handles the user's "Retry Now" action after fixing tailnet settings.
    /// Does nothing while issuance is in progress or before the ACME server's `Retry-After` time (including `rateLimited`).
    /// No requests go to that server before that time (behavior X5).
    public func retryNow() {
        guard !isIssuing, schedule.retryNow(at: now()) else { return }
        wake.signal()
    }

    // MARK: - Single Flow (behavior C9)

    /// Repeatedly decides, then waits or issues until canceled. Issuance runs sequentially within this flow alone.
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
                Self.log.error("Stopping certificate management: \(Self.kind(of: error), privacy: .public)")
                return .failure(error)
            }
        }
        return .success(())
    }

    private enum Plan {
        /// Waits until this time, or until facts change or `retryNow()` is called if nil.
        case wait(until: Date?)
        case issue(CertificateDomain)
    }

    /// Chooses an action on each wake (behavior R3) from the current facts, held certificate, and failure record. Sends no requests.
    private func plan(at now: Date) throws(CertificateError) -> Plan {
        guard let facts = latestFacts else { return .wait(until: nil) }
        let domain: CertificateDomain
        switch Self.eligibility(of: facts) {
        case .blocked(let failure):
            if failure != conditionFailure {
                Self.log.notice("Certificate prerequisites are unmet: \(Self.kind(of: failure), privacy: .public). Waiting for conditions to change")
            }
            conditionFailure = failure
            nextAttempt = nil
            return .wait(until: nil)
        case .eligible(let eligible):
            domain = eligible
        }
        conditionFailure = nil

        // Behavior C3: Check for a stored certificate when the name changes, unless a certificate for that name is already held.
        // shortcut: Keep files for the old name after a name change (behavior S4). Revisit if a use case involves frequent name changes.
        if loadedDomain != domain {
            loadedDomain = domain
            if held?.lifetime.domain != domain, let stored = try loadStoredCertificate(for: domain, at: now) {
                Self.log.info("Using the stored certificate. Expires \(Self.format(stored.lifetime.notAfter), privacy: .public)")
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

    /// Waits until facts change, `retryNow()` is called, or the specified time arrives, whichever comes first.
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

    /// Attempts issuance once (behaviors C4–C8). Records failures in `schedule` and `status` without throwing.
    ///
    /// Continues the attempt even if facts change mid-flight (the name changes or the node stops). The contract calls for fact changes to wake
    /// only a wait (behavior C9), and an attempt finishes within the 5-minute deadline (behavior C10). The next decision sees the changed facts.
    ///
    /// - Throws: `accountKeyUnreadable` if the account key cannot be read or `storage` on a `certs/` failure. On cancellation, returns without
    ///   recording anything.
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
        Self.log.info("Starting certificate issuance")
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
            // Behavior C8: Store only verified certificates and emit them after storing.
            do {
                try store.save(verified)
            } catch {
                throw CertificateError(error)
            }
            schedule.recordSuccess()
            attemptFailure = nil
            // If the name changed during issuance, store the certificate without emitting it. This keeps a certificate for a different name from becoming
            // the app's TLS identity. The next decision reads from disk or issues a new certificate for the current name.
            if let facts = latestFacts, Self.eligibility(of: facts) == .eligible(domain) {
                adopt(verified)
            }
            Self.log.info("Received the certificate. Expires \(Self.format(verified.lifetime.notAfter), privacy: .public)")
        case .failed(let failure, let retryNotBefore, let url):
            if let url { accountURL = url }
            recordFailure(failure, retryAfter: retryNotBefore, at: finishedAt)
        }
        // If facts changed during issuance, any wait for conditions set by that attempt's failure is for conditions that have already passed.
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
            Self.log.notice("Certificate issuance failed: \(Self.kind(of: failure), privacy: .public). Retrying in \(seconds) seconds")
        } else {
            Self.log.notice("Certificate issuance failed: \(Self.kind(of: failure), privacy: .public). Waiting for conditions to change")
        }
    }

    private func adopt(_ certificate: VerifiedCertificate) {
        held = certificate
        certificateContinuation.yield(TailnetCertificate(certificate))
    }

    // MARK: - Disk

    /// Creates and stores a new account key only when the file is missing, then uses it (behavior C4). Calls occur only in this flow, so two cannot overlap.
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

    // MARK: - Facts and Wakeups

    private func receive(_ facts: CertificateFacts) {
        guard facts != latestFacts else { return }
        latestFacts = facts
        factsGeneration += 1
        schedule.conditionsChanged()
        wake.signal()
    }

    /// The facts stream ended because the node's `run()` ended. Treat the node as stopped and wait for cancellation.
    private func factsEnded() {
        let last = latestFacts
        receive(CertificateFacts(isRunning: false, fqdn: last?.fqdn, certDomains: last?.certDomains ?? [], isMagicDNSEnabled: last?.isMagicDNSEnabled ?? false))
    }

    // MARK: - Value Functions

    /// The result of checking behavior C1's four conditions and C2's name check in order.
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

    /// Maps control server `set-dns` failures to issuance failures. Associated strings are fixed text (behavior K3).
    static func failure(for error: ControlError) -> CertificateFailure {
        switch error {
        case .http(let status): .controlRejected(status: status)
        case .invalidConfiguration: .domainNotAllowed
        case .connection, .storage, .authKeyRejected, .registrationRejected, .nodeKeyExpired:
            .network("Could not reach the control server")
        }
    }

    /// Maps an issuance failure to a row of the behavior R4 table. Also returns any time supplied by the rate limit.
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

    /// The failure kind to log. Omits associated strings (the `type` URI and diagnostic wording, behavior K2).
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

/// Exposes nothing because it holds the account key and account URL (behavior K1).
extension CertificateManager: CustomStringConvertible, CustomReflectable {
    public nonisolated var description: String { "CertificateManager" }

    public nonisolated var customMirror: Mirror {
        Mirror(self, children: [:] as KeyValuePairs<String, Any>, displayStyle: .class)
    }
}

/// A signal that wakes the manager. When nobody is waiting, retains a single signal so the next wait ends immediately and wakeups are
/// never lost. Cancellation of the waiting Task also ends the wait.
///
/// A lock protects the signal because the cancellation handler is synchronous, so crossing into an actor would require a new Task.
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
