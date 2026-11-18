// M7 gate (b) 1 and 2 obtain a real certificate using the production control server and Let's Encrypt staging (the `docs/contracts/SwiftailHost.md` contract,
// §7, "Gate (b)" and "How to Run the Gate Tests"). The same flow (`runHostGateFlow`) also runs with testcontrol and pebble without an account.
//
// Origin of the staging directory URL: `letsEncryptStagingEndpoint` in tailscale.com v1.104.7 `cmd/k8s-operator/sts.go:119`.
// Copyright (c) Tailscale Inc & contributors; SPDX-License-Identifier: BSD-3-Clause.
//
// The real gate reads the auth key from a file to keep its value out of process listings and logs. It prints only counts, times, Booleans, and state names.
// Keeps the state directory to verify that the second run reuses the saved identity, lock state, and certificate.

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
    /// Signature wait + 10 minutes.
    static let timeLimitMinutes = (max(signWaitSeconds, 0) + 59) / 60 + 10

    /// Let's Encrypt staging directory (see the origin in the file header).
    static let stagingDirectoryURL = URL(string: "https://acme-staging-v02.api.letsencrypt.org/directory")
}

@Suite("M7 gate (b) 1 and 2: real tailnet and Let's Encrypt staging",
       .enabled(if: RealHostGateEnvironment.isEnabled,
                "Skipping because SWIFTAIL_REAL_AUTHKEY_FILE and SWIFTAIL_REAL_HOST_STATE_DIR are missing"),
       .timeLimit(.minutes(RealHostGateEnvironment.timeLimitMinutes)))
struct RealTailnetHostGateTests {
    @Test("Registration adds the node's own FQDN to certDomains, and tailnet TLS works with a certificate issued via real set-dns and staging")
    func stagingIssuance() async throws {
        let environment = RealHostGateEnvironment.self
        let keyPath = try #require(environment.authKeyFile)
        let authKey = try String(contentsOfFile: keyPath, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
        try #require(!authKey.isEmpty, "The auth key file is empty")
        let state = URL(filePath: try #require(environment.stateDirectory), directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: state, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])

        let directoryURL = try #require(environment.acmeDirectory.map(URL.init(string:)) ?? environment.stagingDirectoryURL,
                                        "SWIFTAIL_REAL_ACME_DIRECTORY is not a URL")
        try #require(directoryURL.scheme == "https", "The ACME directory must use https")
        try #require(directoryURL.host() != CertificateConfiguration.letsEncryptDirectoryURL.host(),
                     "This is the production Let's Encrypt directory. This gate uses staging only (production issuance has rate limits and runs separately)")
        let anchors = try environment.acmeRoots.map { try certificateDERs(fromPEM: String(contentsOfFile: $0, encoding: .utf8)) }

        let signCommand = state.appending(path: "sign-command.txt")
        let input = HostGateFlowInput(
            configuration: NodeConfiguration(stateDirectory: state, hostname: "rd-mac-1a2b3c4d", authKey: authKey),
            directoryURL: directoryURL, transportAnchors: nil, certificateAnchors: anchors,
            runningTimeout: .seconds(90), signWait: .seconds(environment.signWaitSeconds), issueTimeout: .seconds(300)
        ) { context in
            // Both values are public keys but identify the node, so pass them only through a file in the state directory and keep them off standard output.
            let line = "tailscale lock sign \(context.request.nodeKey) \(context.request.lockKey)\n"
            try Data(line.utf8).write(to: signCommand, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: signCommand.path)
            print("A signature is required. See sign-command.txt in the state directory (wait limit: \(environment.signWaitSeconds) seconds)")
        }
        let report = await runHostGateFlow(input)
        print(report.summary)

        #expect(report.failure == nil, "The flow did not run to completion")
        #expect(report.runFailure == nil, "TailnetNode.run() ended before cancellation")
        #expect(report.fqdnInCertDomains, "Gate 1: certDomains lacks the node's own FQDN")
        if report.locked {
            #expect(report.unlockSeconds != nil, "The signature did not unlock the node within the limit")
        }
        guard anchors != nil else { return }
        #expect(report.issued, "Gate 2: no staging certificate was received")
        #expect(report.chainVerifiesWithAnchors == true, "Gate 2: the chain did not verify with the staging root")
        if report.storedCertificateBefore {
            #expect(report.reusedStored == true, "Second run: failed to reuse the stored certificate without new issuance")
        }
        if report.tlsSkipped == nil {
            #expect(report.tls?.trustVerified == true, "tailnet TLS: verification with the staging root failed")
            #expect(report.tls?.status == 200)
            #expect(report.tlsOriginIsSelf == true)
        }
    }
}

/// Runs the same flow without an account, using the `tailnet` tool (testcontrol copy + DERP + pebble) as the counterpart.
@Suite("M7 gate (b) 1 and 2 flow without an account", .enabled(if: tailnetBinary != nil, "Skipping because SWIFTAIL_TAILNET is missing"),
       .serialized, .timeLimit(.minutes(10)))
struct HostGateFlowTests {
    @Test("Tailnet without lock: gates 1 and 2 and tailnet TLS, with no new issuance when the second run uses the stored certificate")
    func unlockedFlowTwice() async throws {
        try await withLockGate(capability: false) { gate in
            let acme = try await gate.command(.init(cmd: "acmeStart"), expecting: "acmeStart")
            let root = try certificateDER(fromPEM: try requireValue(acme.rootPEM, "acmeStart returned no rootPEM"))
            let directoryURL = try requireValue(acme.directoryURL.flatMap(URL.init(string:)), "acmeStart returned no directoryURL")
            let input = Self.input(gate, directoryURL: directoryURL, root: root) { _ in
                Issue.record("Locked on a tailnet without lock")
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
            #expect(second.reusedStored == true, "The second run presents the stored certificate without ACME requests or set-dns")
            #expect(second.tls?.trustVerified == true && second.tls?.status == 200)
            await gate.tool.checkpoint("Gate (b) flow (no account, no lock): first-run issuance \(first.issueSeconds ?? -1) seconds, set-dns \(first.setDNSSeconds), second-run ACME requests \(second.acmeRequests)")
        }
    }

    @Test("Tailnet with lock enabled: locked → wait for issuance while locked → sign → unlock without restarting → gates 1 and 2 and tailnet TLS")
    func lockedFlow() async throws {
        try await withLockGate { gate in
            _ = try await gate.addPeer("go-peer-a")
            let started = try await gate.command(.init(cmd: "lockInit", name: "go-peer-a"), expecting: "lockInit")
            try #require(started.enabled == true && started.nodeKeySigned == true)
            let acme = try await gate.command(.init(cmd: "acmeStart"), expecting: "acmeStart")
            let root = try certificateDER(fromPEM: try requireValue(acme.rootPEM, "acmeStart returned no rootPEM"))
            let directoryURL = try requireValue(acme.directoryURL.flatMap(URL.init(string:)), "acmeStart returned no directoryURL")
            let input = Self.input(gate, directoryURL: directoryURL, root: root) { context in
                // Wait for the first certificate before signing to see if issuance works while locked. If none arrives, proceed to signing.
                try? await netstackWait("first certificate while locked", seconds: 90) { context.certificateArrived }
                _ = try await gate.command(.init(cmd: "lockSign", name: "go-peer-a", nodeKey: context.request.nodeKey,
                                                 lockKey: context.request.lockKey), expecting: "lockSign")
            }

            let report = await runHostGateFlow(input)
            print(report.summary)
            #expect(report.failure == nil && report.runFailure == nil)
            #expect(report.locked)
            #expect(report.lockAtRunning?.mode == .enforcing && report.lockAtRunning?.isLockedOut == true)
            #expect(report.unlockSeconds != nil && report.unlockedInSameRun, "Unlocks after signing without restarting")
            #expect(report.lockAfterWait?.isLockedOut == false)
            #expect(report.fqdnInCertDomains && report.issued && report.chainVerifiesWithAnchors == true)
            #expect(report.issuedWhileLocked != nil)
            #expect(report.tls?.trustVerified == true && report.tls?.status == 200 && report.tlsOriginIsSelf == true)
            await gate.tool.checkpoint("Gate (b) flow (no account, lock enabled): first certificate while locked \(report.issuedWhileLocked.map { "\($0)" } ?? "-") (set-dns in the testcontrol copy does not check lock, unlike the production server), unlocked \(report.unlockSeconds ?? -1) seconds after signing")
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
