// M7 관문 (나) 1·2: 운영 제어 서버 + Let's Encrypt 스테이징으로 실제 인증서를 받는다(계약 `docs/contracts/SwiftailHost.md`
// 7절 "관문 (나)"와 "관문 시험의 쓰는 법"). 같은 흐름(`runHostGateFlow`)을 계정 없이 testcontrol + pebble에서도 돌린다.
//
// 스테이징 디렉터리 URL의 출처: tailscale.com v1.104.7 `cmd/k8s-operator/sts.go:119`의 `letsEncryptStagingEndpoint`.
// Copyright (c) Tailscale Inc & contributors; SPDX-License-Identifier: BSD-3-Clause.
//
// 실제 관문은 인증 키를 파일로 받고(값이 프로세스 목록과 로그에 남지 않게), 출력에는 개수·시간·참거짓·상태 이름만 쓴다.
// 상태 디렉터리는 지우지 않는다: 두 번째 실행에서 저장된 신원·lock 상태·인증서를 다시 쓰는 것을 본다.

import Foundation
import Swiftail
import SwiftailBase
import Testing

@testable import SwiftailCertificates

private enum RealHostGateEnvironment {
    static let values = ProcessInfo.processInfo.environment

    static func value(_ name: String) -> String? { values[name].flatMap { $0.isEmpty ? nil : $0 } }

    static let authKeyFile = value("SWIFTAIL_REAL_AUTHKEY_FILE")
    static let stateDirectory = value("SWIFTAIL_REAL_HOST_STATE_DIR")
    static let acmeRoots = value("SWIFTAIL_REAL_ACME_ROOTS")
    static let acmeDirectory = value("SWIFTAIL_REAL_ACME_DIRECTORY")
    static let signWaitSeconds = value("SWIFTAIL_REAL_SIGN_WAIT_SECONDS").flatMap(Int.init) ?? 600
    static let isEnabled = authKeyFile != nil && stateDirectory != nil
    /// 서명 대기 + 10분.
    static let timeLimitMinutes = (max(signWaitSeconds, 0) + 59) / 60 + 10

    /// Let's Encrypt 스테이징 디렉터리(위 머리말의 출처).
    static let stagingDirectoryURL = URL(string: "https://acme-staging-v02.api.letsencrypt.org/directory")
}

@Suite("M7 관문 (나) 1·2: 실제 tailnet과 Let's Encrypt 스테이징",
       .enabled(if: RealHostGateEnvironment.isEnabled,
                "SWIFTAIL_REAL_AUTHKEY_FILE과 SWIFTAIL_REAL_HOST_STATE_DIR이 없어 건너뜁니다"),
       .timeLimit(.minutes(RealHostGateEnvironment.timeLimitMinutes)))
struct RealTailnetHostGateTests {
    @Test("등록하면 certDomains에 자기 FQDN이 있고, 실제 set-dns와 스테이징으로 발급한 인증서로 tailnet TLS가 된다")
    func stagingIssuance() async throws {
        let environment = RealHostGateEnvironment.self
        let keyPath = try #require(environment.authKeyFile)
        let authKey = try String(contentsOfFile: keyPath, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
        try #require(!authKey.isEmpty, "인증 키 파일이 비었다")
        let state = URL(filePath: try #require(environment.stateDirectory), directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: state, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])

        let directoryURL = try #require(environment.acmeDirectory.map(URL.init(string:)) ?? environment.stagingDirectoryURL,
                                        "SWIFTAIL_REAL_ACME_DIRECTORY가 URL이 아니다")
        try #require(directoryURL.scheme == "https", "ACME 디렉터리는 https여야 한다")
        try #require(directoryURL.host() != CertificateConfiguration.letsEncryptDirectoryURL.host(),
                     "운영 Let's Encrypt 디렉터리다. 이 관문은 스테이징 전용이다(운영 발급은 횟수 한도가 있어 따로 한다)")
        let anchors = try environment.acmeRoots.map { try certificateDERs(fromPEM: String(contentsOfFile: $0, encoding: .utf8)) }

        let signCommand = state.appending(path: "sign-command.txt")
        let input = HostGateFlowInput(
            configuration: NodeConfiguration(stateDirectory: state, hostname: "rd-mac-1a2b3c4d", authKey: authKey),
            directoryURL: directoryURL, transportAnchors: nil, certificateAnchors: anchors,
            runningTimeout: .seconds(90), signWait: .seconds(environment.signWaitSeconds), issueTimeout: .seconds(300)
        ) { context in
            // 두 값은 공개 키지만 노드를 가리키므로 표준 출력에 찍지 않고 상태 디렉터리의 파일로만 넘긴다.
            let line = "tailscale lock sign \(context.request.nodeKey) \(context.request.lockKey)\n"
            try Data(line.utf8).write(to: signCommand, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: signCommand.path)
            print("서명이 필요하다. 명령은 상태 디렉터리의 sign-command.txt에 있다(기다리는 한도 \(environment.signWaitSeconds)초)")
        }
        let report = await runHostGateFlow(input)
        print(report.summary)

        #expect(report.failure == nil, "흐름이 끝까지 가지 못했다")
        #expect(report.runFailure == nil, "TailnetNode.run()이 취소 전에 끝났다")
        #expect(report.fqdnInCertDomains, "관문 1: certDomains에 자기 FQDN이 없다")
        if report.locked {
            #expect(report.unlockSeconds != nil, "기한 안에 서명으로 풀리지 않았다")
        }
        guard anchors != nil else { return }
        #expect(report.issued, "관문 2: 스테이징 인증서를 받지 못했다")
        #expect(report.chainVerifiesWithAnchors == true, "관문 2: 사슬이 스테이징 루트로 검증되지 않았다")
        if report.storedCertificateBefore {
            #expect(report.reusedStored == true, "두 번째 실행: 저장된 인증서를 새 발급 없이 쓰지 않았다")
        }
        if report.tlsSkipped == nil {
            #expect(report.tls?.trustVerified == true, "tailnet TLS: 스테이징 루트로 검증되지 않았다")
            #expect(report.tls?.status == 200)
            #expect(report.tlsOriginIsSelf == true)
        }
    }
}

/// 같은 흐름을 계정 없이 돌린다. 상대는 `tailnet` 도구(testcontrol 사본 + DERP + pebble)다.
@Suite("M7 관문 (나) 1·2의 흐름: 계정 없이", .enabled(if: tailnetBinary != nil, "SWIFTAIL_TAILNET가 없어 건너뜁니다"),
       .serialized, .timeLimit(.minutes(10)))
struct HostGateFlowTests {
    @Test("lock 없는 tailnet: 관문 1·2와 tailnet TLS, 두 번째 실행은 저장된 인증서를 새 발급 없이 쓴다")
    func unlockedFlowTwice() async throws {
        try await withLockGate(capability: false) { gate in
            let acme = try await gate.command(.init(cmd: "acmeStart"), expecting: "acmeStart")
            let root = try certificateDER(fromPEM: try requireValue(acme.rootPEM, "acmeStart rootPEM 없음"))
            let directoryURL = try requireValue(acme.directoryURL.flatMap(URL.init(string:)), "acmeStart directoryURL 없음")
            let input = Self.input(gate, directoryURL: directoryURL, root: root) { _ in
                Issue.record("lock 없는 tailnet에서 잠김")
            }

            let first = await runHostGateFlow(input)
            print(first.summary)
            #expect(first.failure == nil && first.runFailure == nil)
            #expect(!first.locked)
            #expect(first.fqdnInCertDomains && first.certDomainCount == 1)
            #expect(!first.storedCertificateBefore && first.issued && first.reusedStored == nil)
            #expect(first.setDNSSeconds.count == 1 && first.setDNSFailures == 0)
            #expect(first.chainVerifiesWithAnchors == true)
            #expect(first.tls?.handshake == true && first.tls?.trustVerified == true && first.tls?.status == 200)
            #expect(first.tlsOriginIsSelf == true)

            let second = await runHostGateFlow(input)
            print(second.summary)
            #expect(second.failure == nil && second.runFailure == nil)
            #expect(second.storedCertificateBefore && second.issued)
            #expect(second.reusedStored == true, "두 번째 실행은 ACME 요청과 set-dns 없이 저장된 인증서를 낸다")
            #expect(second.tls?.trustVerified == true && second.tls?.status == 200)
            await gate.tool.checkpoint("관문 (나) 흐름(계정 없이, lock 없음): 첫 실행 발급 \(first.issueSeconds ?? -1)초, set-dns \(first.setDNSSeconds), 두 번째 실행 ACME 요청 \(second.acmeRequests)개")
        }
    }

    @Test("lock 켜진 tailnet: 잠김 → (잠긴 동안 발급을 기다림) → 서명 → 다시 시작 없이 풀림 → 관문 1·2와 tailnet TLS")
    func lockedFlow() async throws {
        try await withLockGate { gate in
            _ = try await gate.addPeer("go-peer-a")
            let started = try await gate.command(.init(cmd: "lockInit", name: "go-peer-a"), expecting: "lockInit")
            try #require(started.enabled == true && started.nodeKeySigned == true)
            let acme = try await gate.command(.init(cmd: "acmeStart"), expecting: "acmeStart")
            let root = try certificateDER(fromPEM: try requireValue(acme.rootPEM, "acmeStart rootPEM 없음"))
            let directoryURL = try requireValue(acme.directoryURL.flatMap(URL.init(string:)), "acmeStart directoryURL 없음")
            let input = Self.input(gate, directoryURL: directoryURL, root: root) { context in
                // 잠긴 동안 발급이 되는지 보려고 서명 전에 첫 인증서를 기다린다(오지 않으면 그대로 서명으로 간다).
                try? await netstackWait("잠긴 동안의 첫 인증서", seconds: 90) { context.certificateArrived }
                _ = try await gate.command(.init(cmd: "lockSign", name: "go-peer-a", nodeKey: context.request.nodeKey,
                                                 lockKey: context.request.lockKey), expecting: "lockSign")
            }

            let report = await runHostGateFlow(input)
            print(report.summary)
            #expect(report.failure == nil && report.runFailure == nil)
            #expect(report.locked)
            #expect(report.lockAtRunning?.mode == .enforcing && report.lockAtRunning?.isLockedOut == true)
            #expect(report.unlockSeconds != nil && report.unlockedInSameRun, "서명 뒤 다시 시작 없이 풀린다")
            #expect(report.lockAfterWait?.isLockedOut == false)
            #expect(report.fqdnInCertDomains && report.issued && report.chainVerifiesWithAnchors == true)
            #expect(report.issuedWhileLocked != nil)
            #expect(report.tls?.trustVerified == true && report.tls?.status == 200 && report.tlsOriginIsSelf == true)
            await gate.tool.checkpoint("관문 (나) 흐름(계정 없이, lock 켜짐): 잠긴 동안 첫 인증서 \(report.issuedWhileLocked.map { "\($0)" } ?? "-")(testcontrol 사본의 set-dns는 lock을 보지 않는다. 운영 서버의 동작은 아니다), 서명 뒤 \(report.unlockSeconds ?? -1)초에 풀림")
        }
    }

    private static func input(_ gate: LockGate, directoryURL: URL, root: [UInt8],
                              onLocked: @escaping @Sendable (HostGateLockedContext) async throws -> Void) -> HostGateFlowInput {
        HostGateFlowInput(
            configuration: NodeConfiguration(stateDirectory: gate.root.appending(path: "host"), hostname: "rd-mac-1a2b3c4d",
                                             controlURL: gate.controlURL),
            directoryURL: directoryURL, transportAnchors: [root], certificateAnchors: [root],
            runningTimeout: .seconds(30), signWait: .seconds(60), issueTimeout: .seconds(180), onLocked: onLocked
        )
    }
}
