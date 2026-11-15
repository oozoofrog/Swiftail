// M7 관문 (나) 1·2의 흐름(계약 `docs/contracts/SwiftailHost.md` 7절 "관문 (나)"와 그 아래 "관문 시험의 쓰는 법").
//
// 실제 tailnet(운영 제어 서버 + Let's Encrypt 스테이징)과 계정 없는 환경(testcontrol + pebble)이 같은 흐름을 돈다. 흐름은
// 노드를 띄우고, tailnet lock에 잠겼으면 서명을 기다리고, cert 도메인을 보고, 인증서를 받아, 받은 인증서로 tailnet 쪽 TLS가
// 되는지 자기 노드에 붙어 본다. 결과는 개수·시간·참거짓·상태 이름만 담는다(FQDN·tailnet 이름·주소·키를 담지 않는다).

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

/// 흐름의 입력.
struct HostGateFlowInput: Sendable {
    var configuration: NodeConfiguration
    /// ACME 디렉터리 URL.
    var directoryURL: URL
    /// ACME 디렉터리 HTTPS의 신뢰 앵커(DER). nil이면 시스템 루트다(스테이징 서버의 HTTPS는 공개 인증서다).
    var transportAnchors: [[UInt8]]?
    /// 받은 사슬을 검증할 시험 앵커(DER). nil이면 발급 단계를 건너뛰고 관문 1만 본다.
    var certificateAnchors: [[UInt8]]?
    /// `.running`까지 기다리는 한도.
    var runningTimeout: Duration
    /// 잠긴 노드가 풀리기를 기다리는 한도.
    var signWait: Duration
    /// 관리자를 띄운 뒤 첫 인증서까지의 한도.
    var issueTimeout: Duration
    /// 노드가 잠겨 있으면 한 번 부른다. 돌아오면 흐름이 풀리기를 기다린다.
    var onLocked: @Sendable (HostGateLockedContext) async throws -> Void
}

/// 잠긴 노드에서 `onLocked`가 받는 것.
struct HostGateLockedContext: Sendable {
    /// 서명 기기에 넘길 두 값(둘 다 공개 키). 출력·로그에 찍지 않는다.
    let request: TailnetLockStatus.SigningRequest
    let arrival: CertificateArrival

    /// 관리자가 첫 인증서를 냈는가(발급 단계가 없으면 늘 거짓).
    var certificateArrived: Bool { arrival.value != nil }
}

/// 관리자의 첫 인증서와 그 시각.
final class CertificateArrival: Sendable {
    private let state = Mutex<(certificate: TailnetCertificate, at: ContinuousClock.Instant)?>(nil)

    var value: (certificate: TailnetCertificate, at: ContinuousClock.Instant)? { state.withLock { $0 } }

    func record(_ certificate: TailnetCertificate) {
        state.withLock { if $0 == nil { $0 = (certificate, .now) } }
    }
}

/// lock 모습 가운데 보고에 쓰는 것(키·머리는 담지 않는다).
struct LockSnapshot: Sendable, CustomStringConvertible {
    var mode: TailnetLockStatus.Mode
    var isLockedOut: Bool
    var filteredPeerCount: Int
    var issue: TailnetLockStatus.Issue?

    init(_ lock: TailnetLockStatus) {
        (mode, isLockedOut, filteredPeerCount, issue) = (lock.mode, lock.isLockedOut, lock.filteredPeerCount, lock.issue)
    }

    var description: String {
        "mode \(mode), 잠김 \(isLockedOut), 거른 피어 \(filteredPeerCount)명, issue \(issue.map { "\($0)" } ?? "없음")"
    }
}

/// 흐름의 결과. `failure`가 nil이면 흐름이 끝까지 갔다(각 판정은 시험이 본다).
struct HostGateFlowReport: Sendable {
    var finalState = "starting"
    var runningSeconds: Double?
    var peerCount = 0
    var lockAtRunning: LockSnapshot?
    // 서명
    var locked = false
    var unlockSeconds: Double?
    /// 같은 `run()` 안에서 `signingRequest`가 nil인 `tailnetLockChanged`가 나왔다.
    var unlockedInSameRun = false
    var lockAfterWait: LockSnapshot?
    /// 잠긴 동안 첫 인증서가 나왔는가. 거짓은 기다리는 한도 내내 잠긴 채 인증서가 오지 않은 것이다. 인증서보다 서명이 먼저
    /// 왔거나, 잠기지 않았거나, 발급 단계가 없거나, 저장된 인증서로 시작했으면 판정하지 못해 nil.
    var issuedWhileLocked: Bool?
    /// 풀린 때(또는 기다림이 끝난 때) 관리자의 마지막 실패. 잠긴 동안 발급이 막혔는지의 단서다.
    var failureWhileLocked: String?
    // 관문 1
    var certDomainCount = 0
    var fqdnInCertDomains = false
    // 관문 2
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
    /// 저장된 인증서로 시작해 ACME 요청과 `set-dns` 없이 그것을 냈다.
    var reusedStored: Bool?
    // TLS
    var tls: TailnetTLSProbe?
    /// 서버가 다리에서 얻은 상대가 자기 노드(`stableID`가 같다)인가.
    var tlsOriginIsSelf: Bool?
    var tlsSkipped: String?
    // 끝
    var failure: String?
    var runFailure: String?

    var summary: String {
        func seconds(_ value: Double?) -> String { value.map { String(format: "%.1f초", $0) } ?? "-" }
        func flag(_ value: Bool?) -> String { value.map { "\($0)" } ?? "-" }
        let dns = setDNSSeconds.isEmpty ? "없음" : setDNSSeconds.map { String(format: "%.1f초", $0) }.joined(separator: ", ")
        let tlsLine = tls.map { "핸드셰이크 \($0.handshake), 시험 앵커로 검증 \($0.trustVerified), HTTP \($0.status.map(String.init) ?? "-"), 다리의 상대가 자기 노드 \(flag(tlsOriginIsSelf)), 끝 \($0.end)" }
            ?? "건너뜀(\(tlsSkipped ?? "앞 단계에서 끝남"))"
        return """
            호스트 관문 (나) 1·2 요약(개수·시간·참거짓·상태 이름만):
              노드: 상태 \(finalState), running까지 \(seconds(runningSeconds)), 피어 \(peerCount)명
              running 때의 tailnet lock: \(lockAtRunning.map(\.description) ?? "-")
              서명: 잠김 \(locked), 풀림 \(locked ? (unlockSeconds.map { String(format: "%.1f초", $0) } ?? "기한 안에 풀리지 않음") : "-"), 다시 시작 없이 풀림 \(locked ? "\(unlockedInSameRun)" : "-"), 기다린 뒤 lock: \(lockAfterWait.map(\.description) ?? "-")
              관문 1: cert 도메인 \(certDomainCount)개, 자기 FQDN 있음 \(fqdnInCertDomains)
              관문 2: \(issuanceSkipped.map { "건너뜀(\($0))" } ?? "저장된 인증서로 시작 \(storedCertificateBefore), 저장된 것을 새 발급 없이 씀 \(flag(reusedStored)), 인증서 받음 \(issued), 관리자 시작부터 첫 인증서까지 \(seconds(issueSeconds)), ACME 요청 \(acmeRequests)개, set-dns \(setDNSSeconds.count)번(왕복 \(dns), 실패 \(setDNSFailures)번), 수명 \(lifetimeDays.map { String(format: "%.2f일", $0) } ?? "-"), 사슬 \(chainCount.map(String.init) ?? "-")장, 시험 앵커로 검증 \(flag(chainVerifiesWithAnchors)), 잠긴 동안 첫 인증서 \(flag(issuedWhileLocked))(그때의 실패 \(failureWhileLocked ?? "없음")), 마지막 실패 \(lastFailure ?? "없음")")
              tailnet TLS: \(tlsLine)
              실패: \(failure ?? "없음")\(runFailure.map { ", run(): \($0)" } ?? "")
            """
    }
}

/// 흐름이 연 것. 성공·실패 모두에서 닫는다.
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

/// 흐름 하나를 돌린다. 노드를 띄우고 끝에 멈춘다. 실패는 던지지 않고 `failure`에 적는다(앞 단계의 기록을 잃지 않게).
func runHostGateFlow(_ input: HostGateFlowInput) async -> HostGateFlowReport {
    var report = HostGateFlowReport()
    let node: TailnetNode
    do {
        node = try TailnetNode(configuration: input.configuration, device: .inProcess)
    } catch {
        report.failure = "TailnetNode를 만들지 못함: \(redacted(String(describing: error)))"
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
    // 1. `.running`까지. 로그인 요구는 인증 키가 받아들여지지 않은 것이다(URL은 찍지 않는다).
    let started = ContinuousClock.now
    var status = await node.status
    while status.state != .running {
        report.finalState = stateName(status.state)
        if case .needsLogin = status.state { throw GateFailure("로그인 요구(needsLogin): 인증 키가 받아들여지지 않았다") }
        if status.state == .needsMachineAuth { throw GateFailure("기기 승인 요구(needsMachineAuth): 관리 콘솔에서 승인해야 한다") }
        guard started.duration(to: .now) < input.runningTimeout else {
            throw GateFailure("\(input.runningTimeout) 안에 running이 되지 않음")
        }
        try await Task.sleep(for: .milliseconds(200))
        status = await node.status
    }
    report.finalState = stateName(status.state)
    report.runningSeconds = started.duration(to: .now).netstackSeconds
    report.peerCount = status.peerCount
    report.lockAtRunning = LockSnapshot(status.tailnetLock)

    // 관문 1의 판정. 잠김과 무관하므로 먼저 본다(발급은 잠긴 동안에도 시도해 그 결과를 기록한다).
    let fqdn = status.fqdn
    resources.fqdn = fqdn
    report.certDomainCount = status.certDomains.count
    report.fqdnInCertDomains = fqdn.map { status.certDomains.contains($0) } ?? false

    // 관문 2의 관리자. 서명을 기다리는 동안에도 돈다.
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
        report.issuanceSkipped = "관문 1이 통과하지 않음"
    } else {
        report.issuanceSkipped = "시험 앵커가 없음"
    }

    // 2·3. 잠겼으면 서명을 기다린다.
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
        // 흐름은 `run()`을 한 번만 부르므로, 같은 노드에서 풀린 사건이 보였으면 다시 시작 없이 풀린 것이다.
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
        throw GateFailure("관문 1: certDomains에 자기 FQDN이 없다(HTTPS 인증서가 꺼진 tailnet일 수 있다)")
    }
    guard let issuance, let anchors = input.certificateAnchors else { return }

    // 5. 첫 인증서.
    while arrival.value == nil, issuance.started.duration(to: .now) < input.issueTimeout {
        try await Task.sleep(for: .milliseconds(200))
    }
    let calls = issuance.setDNS.all
    report.setDNSSeconds = calls.map(\.seconds)
    report.setDNSFailures = calls.count { $0.failure != nil }
    report.acmeRequests = issuance.transport.count
    guard let (certificate, at) = arrival.value else {
        report.lastFailure = await issuance.manager.status.lastFailure.map { scrubbed("\($0)", fqdn: fqdn) }
        throw GateFailure("관문 2: \(input.issueTimeout) 안에 인증서를 받지 못함")
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

    // 6. tailnet 443 → 다리 → TLS 리스너. 자기 노드에 붙어 시험 앵커로 검증한다.
    guard let address = status.addresses.first(where: \.isIPv4) else {
        report.tlsSkipped = "자기 IPv4 주소가 없음"
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

/// 상태 이름(로그인 URL은 담지 않는다).
func stateName(_ state: NodeState) -> String {
    switch state {
    case .starting: "starting"
    case .needsLogin: "needsLogin"
    case .needsMachineAuth: "needsMachineAuth"
    case .running: "running"
    }
}

/// 오류 문자열에서 키·경로·메일(`redacted`)과 자기 FQDN·tailnet 이름을 가린다.
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

/// 같은 프로세스에서 tailnet의 자기 주소 443으로 TLS 연결을 걸어 본다.
///
/// `TailnetConnection`은 바이트 흐름이라 OS의 TLS를 바로 얹을 수 없다. 그래서 `127.0.0.1`의 평문 TCP 리스너(이 탐침 안의
/// 중계)를 두고, 받은 연결마다 `node.connect`로 tailnet에 이어 바이트를 나른다. TLS 클라이언트(`NWConnection`)는 그 중계에
/// 걸고 서버 이름은 FQDN이다. 서버 인증서는 시험 앵커만으로 검증한다(시스템 루트·네트워크 가져오기 없음).
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
            result.withLock { $0.end = "중계를 띄우지 못함: \(redacted(String(describing: error)))" }
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
            result.withLock { $0.end = "준비 전 끝: \(ready)" + (relayFailures.isEmpty ? "" : "; 중계: \(relayFailures.joined(separator: "; "))") }
        } else {
            result.withLock { $0.handshake = true }
            let request = "POST /pair HTTP/1.1\r\nHost: \(domain)\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            if let failure = await MinimalHTTPServer.send(connection, Array(request.utf8)) {
                result.withLock { $0.end = "보내기 실패: \(failure)" }
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
                    if $0.end.isEmpty { $0.end = status == nil ? "응답 머리를 읽지 못함" : "응답 머리 받음" }
                }
            }
        }
        connection.cancel()
        await relay.close()
        return result.withLock { $0 }
    }
}

/// `127.0.0.1`의 평문 TCP 리스너. 받은 연결마다 tailnet의 `host:443`에 이어 두 방향으로 바이트를 나른다.
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
            state.withLock { $0.failures.append("루프백 쪽 준비 실패: \(failure)") }
            local.cancel()
            return
        }
        let remote: TailnetConnection
        do {
            remote = try await node.connect(to: host, port: 443)
        } catch {
            state.withLock { $0.failures.append("자기 주소로의 tailnet 연결 실패: \(error)") }
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

/// `.ready`까지 기다린다. 실패하거나 기한이 지나면 그 까닭.
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
        queue.asyncAfter(deadline: .now() + .seconds(seconds)) { once.withLock { $0.take() }?.resume(returning: "\(seconds)초 안에 끝나지 않음") }
    }
}

/// PEM 파일의 `CERTIFICATE` 블록들의 DER(나온 차례). 다른 블록이 있으면 실패한다.
func certificateDERs(fromPEM pem: String) throws -> [[UInt8]] {
    let blocks = pem.components(separatedBy: "-----END CERTIFICATE-----").dropLast()
    let ders = try blocks.map { block -> [UInt8] in
        guard let begin = block.range(of: "-----BEGIN CERTIFICATE-----") else { throw GateFailure("PEM에 CERTIFICATE 블록이 아닌 것이 있음") }
        return try certificateDER(fromPEM: String(block[begin.lowerBound...]))
    }
    guard !ders.isEmpty else { throw GateFailure("PEM에 CERTIFICATE 블록이 없음") }
    return ders
}
