// Flow for M7 gate (b) 1 and 2 (the `docs/contracts/SwiftailHost.md` contract §7, "Gate (b)" and "How to Run the Gate Tests" below it).
//
// A real tailnet (production control server + Let's Encrypt staging) and an account-free environment (testcontrol + pebble) run the same flow. The flow
// starts a node, waits for a signature if tailnet lock has locked it out, checks cert domains, obtains a certificate, and connects to the same node to check
// tailnet TLS using the certificate. Results contain only counts, times, Booleans, and state names (no FQDN, tailnet name, addresses, or keys).

import Foundation
import Network
import Security
import Swiftail
import SwiftailBase
import SwiftailControl
import SwiftailLoopback
import Synchronization
import Testing

@testable import SwiftailCertificates

/// The flow's inputs.
struct HostGateFlowInput: Sendable {
    var configuration: NodeConfiguration
    /// ACME directory URL.
    var directoryURL: URL
    /// Trust anchor (DER) for ACME directory HTTPS. Uses system roots if nil (the staging server presents a public HTTPS certificate).
    var transportAnchors: [[UInt8]]?
    /// Test anchor (DER) for verifying the received chain. If nil, skips issuance and checks only gate 1.
    var certificateAnchors: [[UInt8]]?
    /// Time limit for reaching `.running`.
    var runningTimeout: Duration
    /// Time limit for the locked node to unlock.
    var signWait: Duration
    /// Time limit for the first certificate after starting the manager.
    var issueTimeout: Duration
    /// Called once if the node is locked. The flow waits for unlocking after it returns.
    var onLocked: @Sendable (HostGateLockedContext) async throws -> Void
}

/// What `onLocked` receives from a locked node.
struct HostGateLockedContext: Sendable {
    /// The two values passed to the signing device (both public keys). They are omitted from output and logs.
    let request: TailnetLockStatus.SigningRequest
    let arrival: CertificateArrival

    /// Whether the manager issued its first certificate (always false if there is no issuance stage).
    var certificateArrived: Bool { arrival.value != nil }
}

/// The manager's first certificate and its timestamp.
final class CertificateArrival: Sendable {
    private let state = Mutex<(certificate: TailnetCertificate, at: ContinuousClock.Instant)?>(nil)

    var value: (certificate: TailnetCertificate, at: ContinuousClock.Instant)? { state.withLock { $0 } }

    func record(_ certificate: TailnetCertificate) {
        state.withLock { if $0 == nil { $0 = (certificate, .now) } }
    }
}

/// The part of lock state used in the report (excludes keys and head).
struct LockSnapshot: Sendable, CustomStringConvertible {
    var mode: TailnetLockStatus.Mode
    var isLockedOut: Bool
    var filteredPeerCount: Int
    var issue: TailnetLockStatus.Issue?

    init(_ lock: TailnetLockStatus) {
        (mode, isLockedOut, filteredPeerCount, issue) = (lock.mode, lock.isLockedOut, lock.filteredPeerCount, lock.issue)
    }

    var description: String {
        "mode \(mode), locked \(isLockedOut), filtered peers \(filteredPeerCount), issue \(issue.map { "\($0)" } ?? "none")"
    }
}

/// The flow's result. A nil `failure` means the flow completed (the test checks individual outcomes).
struct HostGateFlowReport: Sendable {
    var finalState = "starting"
    var runningSeconds: Double?
    var peerCount = 0
    var lockAtRunning: LockSnapshot?
    // Signing
    var locked = false
    var unlockSeconds: Double?
    /// A `tailnetLockChanged` event with nil `signingRequest` arrived in the same `run()`.
    var unlockedInSameRun = false
    var lockAfterWait: LockSnapshot?
    /// Whether the first certificate arrived while locked. False means the node stayed locked and no certificate arrived by the deadline. The outcome is undetermined
    /// and nil if signing came before issuance, the node was not locked, there was no issuance stage, or the flow started with a stored certificate.
    var issuedWhileLocked: Bool?
    /// The manager's last failure at unlock (or when the wait ended). It helps determine whether issuance was blocked while locked.
    var failureWhileLocked: String?
    // Gate 1
    var certDomainCount = 0
    var fqdnInCertDomains = false
    // Gate 2
    var issuanceSkipped: String?
    var storedCertificateBefore = false
    var issued = false
    var issueSeconds: Double?
    var acmeRequests = 0
    var setDNSSeconds: [Double] = []
    var setDNSFailures = 0
    var lastFailure: String?
    var lifetimeDays: Double?
    var chainCount: Int?
    var chainVerifiesWithAnchors: Bool?
    /// Started with a stored certificate and presented it without ACME requests or `set-dns`.
    var reusedStored: Bool?
    // TLS
    var tls: TailnetTLSProbe?
    /// Whether the peer the server obtained from the bridge is its own node (same `stableID`).
    var tlsOriginIsSelf: Bool?
    var tlsSkipped: String?
    // Completion
    var failure: String?
    var runFailure: String?

    var summary: String {
        func seconds(_ value: Double?) -> String { value.map { String(format: "%.1f seconds", $0) } ?? "-" }
        func flag(_ value: Bool?) -> String { value.map { "\($0)" } ?? "-" }
        let dns = setDNSSeconds.isEmpty ? "none" : setDNSSeconds.map { String(format: "%.1f seconds", $0) }.joined(separator: ", ")
        let tlsLine = tls.map { "handshake \($0.handshake), verified with test anchor \($0.trustVerified), HTTP \($0.status.map(String.init) ?? "-"), bridge peer is own node \(flag(tlsOriginIsSelf)), end \($0.end)" }
            ?? "skipped (\(tlsSkipped ?? "ended at an earlier stage"))"
        return """
            Host gate (b) 1 and 2 summary (counts, times, Booleans, and state names only):
              Node: state \(finalState), time to running \(seconds(runningSeconds)), \(peerCount) peers
              Tailnet lock at running: \(lockAtRunning.map(\.description) ?? "-")
              Signing: locked \(locked), unlocked \(locked ? (unlockSeconds.map { String(format: "%.1f seconds", $0) } ?? "did not unlock within the time limit") : "-"), unlocked without restarting \(locked ? "\(unlockedInSameRun)" : "-"), lock after waiting: \(lockAfterWait.map(\.description) ?? "-")
              Gate 1: \(certDomainCount) cert domains, own FQDN present \(fqdnInCertDomains)
              Gate 2: \(issuanceSkipped.map { "skipped (\($0))" } ?? "started with stored certificate \(storedCertificateBefore), reused stored certificate without new issuance \(flag(reusedStored)), received certificate \(issued), time from manager start to first certificate \(seconds(issueSeconds)), \(acmeRequests) ACME requests, \(setDNSSeconds.count) set-dns calls (round trips \(dns), \(setDNSFailures) failures), lifetime \(lifetimeDays.map { String(format: "%.2f days", $0) } ?? "-"), chain \(chainCount.map(String.init) ?? "-") certificates, verified with test anchor \(flag(chainVerifiesWithAnchors)), first certificate while locked \(flag(issuedWhileLocked)) (failure at that point \(failureWhileLocked ?? "none"), last failure \(lastFailure ?? "none")")
              tailnet TLS: \(tlsLine)
              Failure: \(failure ?? "none")\(runFailure.map { ", run(): \($0)" } ?? "")
            """
    }
}

/// Resources opened by the flow. Closes them on success and failure.
private struct HostGateFlowResources {
    var fqdn: String?
    var manager: Task<Void, any Error>?
    var issuing: Task<Void, Never>?
    var acceptor: BridgeAcceptor?
    var server: MinimalHTTPServer?

    func close() async {
        await acceptor?.close()
        server?.close()
        issuing?.cancel()
        manager?.cancel()
        _ = await manager?.result
        await issuing?.value
    }
}

/// Runs one flow. Starts the node and stops it at the end. Records failures in `failure` without throwing to preserve the records from earlier stages.
func runHostGateFlow(_ input: HostGateFlowInput) async -> HostGateFlowReport {
    var report = HostGateFlowReport()
    let node: TailnetNode
    do {
        node = try TailnetNode(configuration: input.configuration, device: .inProcess)
    } catch {
        report.failure = "Could not create TailnetNode: \(redacted(String(describing: error)))"
        return report
    }
    let recorder = NodeRecorder()
    let collector = Task {
        for await event in node.events { recorder.append(event, await node.status) }
    }
    let run = Task { try await node.run() }
    var resources = HostGateFlowResources()
    do {
        try await hostGateSteps(input, node: node, recorder: recorder, report: &report, resources: &resources)
    } catch {
        report.failure = scrubbed(String(describing: error), fqdn: resources.fqdn)
    }
    await resources.close()
    run.cancel()
    let result = await run.result
    await collector.value
    if case .failure(let error) = result, !(error is CancellationError) {
        report.runFailure = scrubbed(String(describing: error), fqdn: resources.fqdn)
    }
    return report
}

private func hostGateSteps(_ input: HostGateFlowInput, node: TailnetNode, recorder: NodeRecorder,
                           report: inout HostGateFlowReport, resources: inout HostGateFlowResources) async throws {
    // 1. Wait for `.running`. A login request means the auth key was not accepted (the URL is omitted).
    let started = ContinuousClock.now
    var status = await node.status
    while status.state != .running {
        report.finalState = stateName(status.state)
        if case .needsLogin = status.state { throw GateFailure("Login required (needsLogin): the auth key was not accepted") }
        if status.state == .needsMachineAuth { throw GateFailure("Device approval required (needsMachineAuth): approve in the admin console") }
        guard started.duration(to: .now) < input.runningTimeout else {
            throw GateFailure("Did not reach running within \(input.runningTimeout)")
        }
        try await Task.sleep(for: .milliseconds(200))
        status = await node.status
    }
    report.finalState = stateName(status.state)
    report.runningSeconds = started.duration(to: .now).netstackSeconds
    report.peerCount = status.peerCount
    report.lockAtRunning = LockSnapshot(status.tailnetLock)

    // Evaluate gate 1 first because it is independent of lock (issuance is attempted while locked too, and the result is recorded).
    let fqdn = status.fqdn
    resources.fqdn = fqdn
    report.certDomainCount = status.certDomains.count
    report.fqdnInCertDomains = fqdn.map { status.certDomains.contains($0) } ?? false

    // Gate 2 manager. It also runs while waiting for the signature.
    let arrival = CertificateArrival()
    var issuance: (manager: CertificateManager, transport: CountingTransport, setDNS: SetDNSRecorder, started: ContinuousClock.Instant)?
    if report.fqdnInCertDomains, let fqdn, let anchors = input.certificateAnchors {
        let certificates = node.stateDirectory.appending(path: "certs")
        report.storedCertificateBefore = ["crt", "key"].allSatisfy {
            FileManager.default.fileExists(atPath: certificates.appending(path: "\(fqdn).\($0)").path)
        }
        let transport = CountingTransport(URLSessionACMETransport(trustAnchors: input.transportAnchors))
        let recorder = SetDNSRecorder()
        let setDNS: CertificateManager.SetDNS = { name, value throws(ControlError) in
            try await recorder.record(name: name, value: value) { () async throws(ControlError) in
                try await node.setDNS(name: name, value: value)
            }
        }
        let manager = try CertificateManager(facts: node.certificateFacts, setDNS: setDNS, stateDirectory: node.stateDirectory,
                                             transport: transport, configuration: CertificateConfiguration(directoryURL: input.directoryURL),
                                             anchors: .only(anchors))
        issuance = (manager, transport, recorder, .now)
        resources.manager = Task { try await manager.run() }
        resources.issuing = Task {
            for await certificate in manager.certificates {
                arrival.record(certificate)
                return
            }
        }
    } else if !report.fqdnInCertDomains {
        report.issuanceSkipped = "Gate 1 did not pass"
    } else {
        report.issuanceSkipped = "No test anchor"
    }

    // 2 and 3. Wait for a signature if locked.
    if let request = status.tailnetLock.signingRequest {
        report.locked = true
        try await input.onLocked(HostGateLockedContext(request: request, arrival: arrival))
        let waiting = ContinuousClock.now
        var unlockedAt: ContinuousClock.Instant?
        while waiting.duration(to: .now) < input.signWait {
            if await node.status.tailnetLock.signingRequest == nil {
                unlockedAt = .now
                break
            }
            try await Task.sleep(for: .milliseconds(500))
        }
        report.unlockSeconds = unlockedAt.map { waiting.duration(to: $0).netstackSeconds }
        report.lockAfterWait = LockSnapshot(await node.status.tailnetLock)
        // The flow calls `run()` only once, so an unlock event on the same node means it unlocked without a restart.
        let changes = recorder.lockChanges
        if let lockedIndex = changes.firstIndex(where: { $0.signingRequest != nil }) {
            report.unlockedInSameRun = changes[(lockedIndex + 1)...].contains { $0.signingRequest == nil }
        }
        if let issuance, !report.storedCertificateBefore {
            report.failureWhileLocked = await issuance.manager.status.lastFailure.map { scrubbed("\($0)", fqdn: fqdn) }
            switch (arrival.value?.at, unlockedAt) {
            case let (at?, unlocked?): report.issuedWhileLocked = at < unlocked ? true : nil
            case (.some, nil): report.issuedWhileLocked = true
            case (nil, nil): report.issuedWhileLocked = false
            case (nil, .some): report.issuedWhileLocked = nil
            }
        }
    }

    guard report.fqdnInCertDomains, let fqdn else {
        throw GateFailure("Gate 1: certDomains lacks the node's own FQDN (HTTPS certificates may be disabled on this tailnet)")
    }
    guard let issuance, let anchors = input.certificateAnchors else { return }

    // 5. First certificate.
    while arrival.value == nil, issuance.started.duration(to: .now) < input.issueTimeout {
        try await Task.sleep(for: .milliseconds(200))
    }
    let calls = issuance.setDNS.all
    report.setDNSSeconds = calls.map(\.seconds)
    report.setDNSFailures = calls.count { $0.failure != nil }
    report.acmeRequests = issuance.transport.count
    guard let (certificate, at) = arrival.value else {
        report.lastFailure = await issuance.manager.status.lastFailure.map { scrubbed("\($0)", fqdn: fqdn) }
        throw GateFailure("Gate 2: no certificate within \(input.issueTimeout)")
    }
    report.issued = true
    report.issueSeconds = issuance.started.duration(to: at).netstackSeconds
    report.lastFailure = await issuance.manager.status.lastFailure.map { scrubbed("\($0)", fqdn: fqdn) }
    report.lifetimeDays = certificate.notAfter.timeIntervalSince(certificate.notBefore) / 86_400
    report.chainCount = certificate.chain.count
    report.chainVerifiesWithAnchors = try chainVerifies(certificate.chain, domain: fqdn, anchors: anchors)
    if report.storedCertificateBefore {
        report.reusedStored = issuance.transport.count == 0 && calls.isEmpty
    }

    // 6. Tailnet port 443 → bridge → TLS listener. Connect to the same node and verify using the test anchor.
    guard let address = status.addresses.first(where: \.isIPv4) else {
        report.tlsSkipped = "No IPv4 address for the node"
        return
    }
    let bridge = LoopbackBridge(node: node)
    let server = try await MinimalHTTPServer.start(.tls, certificate: certificate, label: "gate", bridge: bridge,
                                                   sessions: HostSessions(), domain: fqdn, ipaSeed: 1, ipaLength: 0)
    resources.server = server
    resources.acceptor = BridgeAcceptor(listener: try await node.listen(port: 443), bridge: bridge, port: server.port)
    let probe = await TailnetTLSProbe.run(node: node, host: address.description, domain: fqdn, anchors: anchors)
    report.tls = probe
    if probe.status != nil {
        let selfID = await node.status.stableID
        report.tlsOriginIsSelf = selfID != nil && server.records.first { $0.request == "POST /pair" }?.stableID == selfID
    }
}

/// State names without the login URL.
func stateName(_ state: NodeState) -> String {
    switch state {
    case .starting: "starting"
    case .needsLogin: "needsLogin"
    case .needsMachineAuth: "needsMachineAuth"
    case .running: "running"
    }
}

/// Redacts keys, paths, and emails (`redacted`) along with the node's own FQDN and tailnet name from error strings.
func scrubbed(_ text: String, fqdn: String?) -> String {
    var result = redacted(text)
    if let fqdn, !fqdn.isEmpty {
        result = result.replacingOccurrences(of: fqdn, with: "<fqdn>")
        if let dot = fqdn.firstIndex(of: ".") {
            let suffix = String(fqdn[fqdn.index(after: dot)...])
            if !suffix.isEmpty { result = result.replacingOccurrences(of: suffix, with: "<tailnet>") }
        }
    }
    return result
}

/// Attempts a TLS connection to port 443 at the node's own tailnet address from the same process.
///
/// A `TailnetConnection` is a byte stream, so OS TLS cannot be layered directly over it. This probe uses a plaintext TCP listener on `127.0.0.1` as a
/// relay. Each accepted connection forwards bytes over the tailnet via `node.connect`. The TLS client (`NWConnection`) connects to that relay
/// with the FQDN as the server name. Only test anchors are used to verify the server certificate (no system roots or network fetching).
struct TailnetTLSProbe: Sendable {
    var handshake = false
    var trustVerified = false
    var status: Int?
    var end = ""

    static func run(node: TailnetNode, host: String, domain: String, anchors: [[UInt8]]) async -> TailnetTLSProbe {
        let result = Mutex(TailnetTLSProbe())
        let relay: LoopbackRelay
        do {
            relay = try await LoopbackRelay.start(node: node, host: host)
        } catch {
            result.withLock { $0.end = "Could not start the relay: \(redacted(String(describing: error)))" }
            return result.withLock { $0 }
        }
        let queue = DispatchQueue(label: "test.tailnet.tls")
        let tls = NWProtocolTLS.Options()
        let options = tls.securityProtocolOptions
        sec_protocol_options_set_tls_server_name(options, domain)
        sec_protocol_options_add_tls_application_protocol(options, "http/1.1")
        sec_protocol_options_set_verify_block(options, { _, trust, complete in
            let verified = trustEvaluates(sec_trust_copy_ref(trust).takeRetainedValue(), domain: domain, anchors: anchors)
            result.withLock { $0.trustVerified = verified }
            complete(verified)
        }, queue)
        let connection = NWConnection(host: .ipv4(.loopback), port: NWEndpoint.Port(rawValue: relay.port) ?? .any,
                                      using: NWParameters(tls: tls, tcp: NWProtocolTCP.Options()))
        let ready = await waitUntilReady(connection, queue: queue, seconds: 30)
        if let ready {
            let relayFailures = relay.failures
            result.withLock { $0.end = "Ended before readiness: \(ready)" + (relayFailures.isEmpty ? "" : "; relay: \(relayFailures.joined(separator: "; "))") }
        } else {
            result.withLock { $0.handshake = true }
            let request = "POST /pair HTTP/1.1\r\nHost: \(domain)\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            if let failure = await MinimalHTTPServer.send(connection, Array(request.utf8)) {
                result.withLock { $0.end = "Send failed: \(failure)" }
            } else {
                var head: [UInt8] = []
                let deadline = ContinuousClock.now + .seconds(30)
                loop: while ContinuousClock.now < deadline, !String(decoding: head, as: UTF8.self).contains("\r\n\r\n") {
                    switch await MinimalHTTPServer.receive(connection) {
                    case .bytes(let bytes): head += bytes
                    case .end: result.withLock { $0.end = "eof" }; break loop
                    case .failed(let error): result.withLock { $0.end = "error(\(error))" }; break loop
                    }
                }
                let line = String(decoding: head.prefix { $0 != 0x0D }, as: UTF8.self).split(separator: " ")
                let status = line.count >= 2 && line[0].hasPrefix("HTTP/") ? Int(line[1]) : nil
                result.withLock {
                    $0.status = status
                    if $0.end.isEmpty { $0.end = status == nil ? "Could not read the response header" : "Received the response header" }
                }
            }
        }
        connection.cancel()
        await relay.close()
        return result.withLock { $0 }
    }
}

/// Plaintext TCP listener on `127.0.0.1`. Connects each accepted connection to `host:443` on the tailnet and forwards bytes in both directions.
private final class LoopbackRelay: Sendable {
    let port: UInt16
    private let listener: NWListener
    private let state = Mutex<(tasks: [Task<Void, Never>], remotes: [TailnetConnection], failures: [String])>(([], [], []))

    private init(port: UInt16, listener: NWListener) {
        (self.port, self.listener) = (port, listener)
    }

    var failures: [String] { state.withLock { $0.failures } }

    static func start(node: TailnetNode, host: String) async throws -> LoopbackRelay {
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
        let listener = try NWListener(using: parameters)
        let (accepted, sink) = AsyncStream.makeStream(of: NWConnection.self)
        listener.newConnectionHandler = { sink.yield($0) }
        let port = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<UInt16, any Error>) in
            let once = Mutex<CheckedContinuation<UInt16, any Error>?>(continuation)
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    if let port = listener.port?.rawValue { once.withLock { $0.take() }?.resume(returning: port) }
                case .failed(let error):
                    sink.finish()
                    once.withLock { $0.take() }?.resume(throwing: error)
                case .cancelled:
                    sink.finish()
                    once.withLock { $0.take() }?.resume(throwing: CancellationError())
                default: break
                }
            }
            listener.start(queue: DispatchQueue(label: "test.relay.listener"))
        }
        let relay = LoopbackRelay(port: port, listener: listener)
        let accepting = Task {
            for await connection in accepted {
                let task = Task { await relay.pipe(connection, node: node, host: host) }
                relay.state.withLock { $0.tasks.append(task) }
            }
        }
        relay.state.withLock { $0.tasks.append(accepting) }
        return relay
    }

    private func pipe(_ local: NWConnection, node: TailnetNode, host: String) async {
        if let failure = await waitUntilReady(local, queue: DispatchQueue(label: "test.relay.connection"), seconds: 10) {
            state.withLock { $0.failures.append("Loopback setup failed: \(failure)") }
            local.cancel()
            return
        }
        let remote: TailnetConnection
        do {
            remote = try await node.connect(to: host, port: 443)
        } catch {
            state.withLock { $0.failures.append("Tailnet connection to the node's own address failed: \(error)") }
            local.cancel()
            return
        }
        state.withLock { $0.remotes.append(remote) }
        await withDiscardingTaskGroup { group in
            group.addTask {
                while true {
                    switch await MinimalHTTPServer.receive(local) {
                    case .bytes(let bytes):
                        guard !bytes.isEmpty else { continue }
                        do { try await remote.write(bytes) } catch { return }
                    case .end:
                        try? await remote.finishWriting()
                        return
                    case .failed:
                        await remote.abort()
                        return
                    }
                }
            }
            group.addTask {
                while true {
                    do {
                        guard let bytes = try await remote.read() else {
                            _ = await MinimalHTTPServer.send(local, [], final: true)
                            return
                        }
                        if await MinimalHTTPServer.send(local, bytes) != nil { return }
                    } catch {
                        local.cancel()
                        return
                    }
                }
            }
        }
        await remote.close()
        local.cancel()
    }

    func close() async {
        listener.cancel()
        let (tasks, remotes) = state.withLock { ($0.tasks, $0.remotes) }
        for remote in remotes { await remote.abort() }
        for task in tasks { task.cancel() }
        for task in tasks { await task.value }
    }
}

/// Waits for `.ready`. Returns the reason if it fails or times out.
private func waitUntilReady(_ connection: NWConnection, queue: DispatchQueue, seconds: Int) async -> String? {
    await withCheckedContinuation { (continuation: CheckedContinuation<String?, Never>) in
        let once = Mutex<CheckedContinuation<String?, Never>?>(continuation)
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready: once.withLock { $0.take() }?.resume(returning: nil)
            case .failed(let error): once.withLock { $0.take() }?.resume(returning: MinimalHTTPServer.describe(error))
            case .waiting(let error): once.withLock { $0.take() }?.resume(returning: "waiting \(MinimalHTTPServer.describe(error))")
            case .cancelled: once.withLock { $0.take() }?.resume(returning: "cancelled")
            default: break
            }
        }
        connection.start(queue: queue)
        queue.asyncAfter(deadline: .now() + .seconds(seconds)) { once.withLock { $0.take() }?.resume(returning: "Did not finish within \(seconds) seconds") }
    }
}

/// DER from the PEM file's `CERTIFICATE` blocks, in order. Any other block causes a failure.
func certificateDERs(fromPEM pem: String) throws -> [[UInt8]] {
    let blocks = pem.components(separatedBy: "-----END CERTIFICATE-----").dropLast()
    let ders = try blocks.map { block -> [UInt8] in
        guard let begin = block.range(of: "-----BEGIN CERTIFICATE-----") else { throw GateFailure("PEM contains a block other than CERTIFICATE") }
        return try certificateDER(fromPEM: String(block[begin.lowerBound...]))
    }
    guard !ders.isEmpty else { throw GateFailure("PEM contains no CERTIFICATE blocks") }
    return ders
}
