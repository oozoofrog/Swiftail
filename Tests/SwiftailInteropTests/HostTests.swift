// M7 gate (a) without an account (items 1–10 in the table in the `docs/contracts/SwiftailHost.md` contract §7).
//
// The counterpart is the `tailnet` tool: testcontrol + DERP + STUN + two Go tsnet peers + pebble (local ACME) and challtestsrv. It does not reach
// the real internet. Item 11 (importing Go state, M7-11) is unimplemented and unused. The lead session runs item 12 (the full test).

import CryptoKit
import Foundation
import Swiftail
import SwiftailBase
import SwiftailLoopback
import Synchronization
import Testing

@testable import SwiftailCertificates

@Suite("M7 gate (a) without an account", .enabled(if: tailnetBinary != nil, "Skipping the M7 gate because SWIFTAIL_TAILNET is missing"),
       .serialized, .timeLimit(.minutes(30)))
struct HostTests {
    private static let fqdn = HostGate.fqdn
    private static let ipaSeed: UInt64 = 0x4950_4131
    private static let mebibyte: UInt64 = 1_048_576

    @Test("Item 1: whoIs matches peerWhoIs for both Go peers and the node's own addresses, and returns nil for a peer removed from the netmap")
    func item1WhoIs() async throws {
        try await withHostGate { gate in
            for (label, peer) in [("go-peer-a", gate.peerA), ("go-peer-b", gate.peerB), ("Swift self", gate.local)] {
                for address in peer.addresses {
                    let swift = try #require(await gate.node.whoIs(address), "Item 1: whoIs is nil for \(label) IPv\(address.isIPv4 ? 4 : 6)")
                    for viewer in ["go-peer-a", "go-peer-b"] {
                        let go = try await gate.goWhoIs(from: viewer, address)
                        #expect(swift.stableID == go.stableID, "Item 1: \(label) stableID as seen by \(viewer)")
                        #expect(swift.name == go.nodeName, "Item 1: \(label) name as seen by \(viewer)")
                        #expect(swift.computedName == go.computedName, "Item 1: \(label) computedName as seen by \(viewer)")
                        #expect(swift.loginName == go.loginName, "Item 1: \(label) loginName as seen by \(viewer)")
                    }
                    #expect(!swift.stableID.isEmpty)
                }
            }
            await gate.tool.checkpoint("M7 item 1: identities for all 6 addresses match peerWhoIs for both Go peers")

            _ = try await gate.tool.command(.init(cmd: "removePeer", name: "go-peer-b"), expecting: "removed")
            try await gate.removeFromNetmap(gate.peerB, marker: 1)
            for address in gate.peerB.addresses {
                #expect(await gate.node.whoIs(address) == nil, "Item 1: whoIs returns nil for a peer removed from the netmap")
            }
            for address in gate.peerA.addresses {
                #expect(await gate.node.whoIs(address) != nil, "Item 1: whoIs still resolves the remaining peer")
            }
            await gate.tool.checkpoint("M7 item 1: after PeersRemoved, whoIs is nil for go-peer-b and unchanged for go-peer-a")
        }
    }

    @Test("Items 2, 3, and 4: set-dns TXT, pebble issuance and certs/ files, and the stored certificate after restart without requests")
    func items2to4IssueAndRestart() async throws {
        try await withHostGate { gate in
            let transport = gate.makeTransport()
            let manager = try gate.makeManager(transport: transport)
            let (task, certificate, seconds) = try await runManager(manager)
            let firstRequests = transport.count
            await stopManager(task)

            // Item 2: the value the manager published and the value testcontrol received.
            let calls = gate.setDNS.all
            let call = try #require(calls.first)
            #expect(calls.count == 1)
            #expect(call.failure == nil)
            #expect(call.name == "_acme-challenge." + Self.fqdn)
            #expect(call.value.utf8.count == 43, "Item 2: TXT is unpadded base64url SHA-256 (43 bytes)")
            let log = try #require(await gate.tool.command(.init(cmd: "setDNSLog"), expecting: "setDNSLog").requests)
            #expect(log.count == 1)
            #expect(log.last?.name == call.name)
            #expect(log.last?.type == "TXT")
            #expect(log.last?.value == call.value, "Item 2: the value in setDNSLog matches the TXT Swift computed")
            await gate.tool.checkpoint("M7 item 2: set-dns round trip \(call.seconds) seconds, matching name, type, and value in setDNSLog")

            // Item 3: chain, name, and files.
            #expect(certificate.domain == Self.fqdn)
            #expect(try chainVerifies(certificate.chain, domain: Self.fqdn, anchor: gate.rootDER), "Item 3: the chain verifies with the pebble root")
            #expect(!certificate.chain.contains(gate.rootDER), "Item 3: chain excludes the root (behavior S6)")
            #expect(certificate.notAfter > certificate.notBefore)
            let status = await manager.status
            #expect(status.notAfter == certificate.notAfter && status.lastFailure == nil && status.domain == Self.fqdn)
            let files = FileManager.default
            let directory = gate.certificatesDirectory
            #expect(try files.attributesOfItem(atPath: directory.path)[.posixPermissions] as? Int == 0o700)
            for name in ["\(Self.fqdn).crt", "\(Self.fqdn).key", "acme-account.key.pem"] {
                let attributes = try files.attributesOfItem(atPath: directory.appending(path: name).path)
                #expect(attributes[.posixPermissions] as? Int == 0o600, "Item 3: \(name) permissions are 0600")
            }
            let stored = try String(contentsOf: directory.appending(path: "\(Self.fqdn).crt"), encoding: .utf8)
            let blocks = stored.components(separatedBy: "-----BEGIN CERTIFICATE-----").count - 1
            #expect(try files.contentsOfDirectory(atPath: directory.path).sorted()
                    == ["\(Self.fqdn).crt", "\(Self.fqdn).key", "acme-account.key.pem"].sorted())
            await gate.tool.checkpoint("M7 item 3: issuance \(seconds) seconds (manager start to first certificate), \(firstRequests) ACME requests, chain \(certificate.chain.count) certificates (\(blocks) in file), valid \(certificate.notAfter.timeIntervalSince(certificate.notBefore) / 86_400) days, certs/ 0700 and file 0600")

            // Item 4: restart with the same state directory.
            let again = gate.makeTransport()
            let restarted = try gate.makeManager(transport: again)
            let (task2, reused, reuseSeconds) = try await runManager(restarted, waitingSeconds: 15)
            try await Task.sleep(for: .seconds(1))
            #expect(reused.chain == certificate.chain)
            #expect(reused.publicKeyBytes == certificate.publicKeyBytes)
            #expect(again.count == 0, "Item 4: the restarted manager sends no ACME requests")
            #expect(gate.setDNS.all.count == 1)
            #expect(await restarted.status.lastFailure == nil)
            await stopManager(task2)
            await gate.tool.checkpoint("M7 item 4: the restarted manager presents the stored certificate in \(reuseSeconds) seconds, \(again.count) ACME requests")
        }
    }

    @Test("Item 5: issuance with pebble nonce rejection (10%) and authorization reuse enabled")
    func item5BadNonceAndAuthorizationReuse() async throws {
        try await withHostGate(nonceReject: 10, authzReuse: 100) { gate in
            var badNonces = 0
            var requests = 0
            var issuances = 0
            // After first issuance, reissue with the same account until badNonce appears at least once (up to ten times).
            while issuances < 2 || (badNonces == 0 && issuances < 10) {
                if issuances > 0 { try gate.removeStoredCertificate() }
                let transport = gate.makeTransport()
                let manager = try gate.makeManager(transport: transport)
                let (task, certificate, seconds) = try await runManager(manager)
                await stopManager(task)
                issuances += 1
                badNonces += transport.badNonceCount
                requests += transport.count
                #expect(try chainVerifies(certificate.chain, domain: Self.fqdn, anchor: gate.rootDER))
                await gate.tool.checkpoint("M7 item 5: issuance \(issuances) took \(seconds) seconds, \(transport.badNonceCount) badNonce responses out of \(transport.count) requests")
            }
            #expect(badNonces > 0, "Item 5: a nonce rejection actually occurred and re-signing succeeded")
            #expect(gate.setDNS.all.count == 1, "Item 5: the second and later issuances reuse a valid authorization with no set-dns")
            await gate.tool.checkpoint("M7 item 5: all \(issuances) issuances passed, \(badNonces) badNonce responses out of \(requests) requests, \(gate.setDNS.all.count) set-dns calls")
        }
    }

    @Test("Item 6: moving the test clock to the 2/3 point yields a new certificate with a new key and preserves connections on the old listener")
    func item6Renewal() async throws {
        // Pebble v2.10.3 rarely reuses authorizations even at 0. Pin it to always reuse authorizations in the renewal gate.
        try await withHostGate(authzReuse: 100) { gate in
            let clock = TestClock()
            let transport = gate.makeTransport()
            let manager = try gate.makeManager(transport: transport, clock: clock)
            let (task, first, _) = try await runManager(manager)
            let bridge = LoopbackBridge(node: gate.node)
            let sessions = HostSessions()
            let hold = TransferHold(afterBytes: 4 * Self.mebibyte)
            let length = 32 * Self.mebibyte
            let old = try await MinimalHTTPServer.start(.tls, certificate: first, label: "1", bridge: bridge, sessions: sessions,
                                                        domain: Self.fqdn, ipaSeed: Self.ipaSeed, ipaLength: length, hold: hold)
            let acceptor = BridgeAcceptor(listener: try await gate.node.listen(port: 443), bridge: bridge, port: old.port)
            var renewed: MinimalHTTPServer?
            do {
                let created = try await gate.http("go-peer-a", path: "/sessions", method: "POST")
                #expect(created.status == 200)
                let token = try #require(sessions.issued.last).token
                let download = try await gate.startHTTP("go-peer-a", path: "/ipa?token=\(token)", timeout: 300)
                try await netstackWait("Item 6: the old listener's IPA transfer paused at 4MiB") { hold.isReached }

                let renewalPoint = first.notBefore.addingTimeInterval(first.notAfter.timeIntervalSince(first.notBefore) * 2 / 3)
                let started = ContinuousClock.now
                clock.advance(by: renewalPoint.timeIntervalSince(clock.now()) + 60)
                let second = try await nextEvent(manager.certificates, waitingFor: "Item 6: renewed certificate", timeout: .seconds(120))
                let renewalSeconds = started.duration(to: .now).netstackSeconds
                #expect(second.publicKeyBytes != first.publicKeyBytes, "Item 6: renewal uses a new key")
                #expect(second.chain[0] != first.chain[0])
                #expect(try chainVerifies(second.chain, domain: Self.fqdn, anchor: gate.rootDER))
                #expect(await manager.status.notAfter == second.notAfter)
                #expect(gate.setDNS.all.count == 1, "Renewal reuses the first issuance's DNS-01 authorization")

                let server = try await MinimalHTTPServer.start(.tls, certificate: second, label: "2", bridge: bridge, sessions: sessions,
                                                               domain: Self.fqdn, ipaSeed: Self.ipaSeed, ipaLength: length)
                renewed = server
                acceptor.switchTo(port: server.port)
                old.stopAccepting()
                let pair = try await gate.http("go-peer-b", path: "/pair", method: "POST", body: 32)
                #expect(pair.status == 200)
                #expect(pair.headers?["Swiftail-Listener"] == ["2"], "Item 6: new connections go to the listener with the new certificate")

                hold.release()
                let done = try await gate.tool.response(to: download, expecting: "peerHTTP", timeout: .seconds(300))
                #expect(done.status == 200)
                #expect(done.headers?["Swiftail-Listener"] == ["1"], "Item 6: a connection established before renewal completes on the old listener")
                #expect(done.bodyLength == length)
                #expect(done.bodySHA256 == Self.ipaDigest(offset: 0, length: length))
                let record = try #require(old.records.first { $0.request == "GET /ipa" })
                #expect(record.sendError == nil && record.bodyBytesSent == length)
                await gate.tool.checkpoint("M7 item 6: after moving the clock ahead \(Int(renewalPoint.timeIntervalSince(first.notBefore) / 86_400)) days, a certificate with a new key arrived in \(renewalSeconds) seconds. The old listener's 32MiB transfer survived renewal and its hash matched")
            } catch {
                hold.release()
                await acceptor.close()
                old.close()
                renewed?.close()
                await stopManager(task)
                throw error
            }
            await acceptor.close()
            old.close()
            renewed?.close()
            await stopManager(task)
        }
    }

    @Test("Item 7: no cert domains or disabled MagicDNS waits without requests. Rejected set-dns and incorrect TXT use the R4 intervals")
    func item7Failures() async throws {
        // Use a fresh ACME server for each scenario so the previous issuance's DNS-01 authorization does not bypass fault injection.
        try await withHostGate { gate in
            // HTTPS disabled (empty cert domains).
            _ = try await gate.tool.command(.init(cmd: "setCertDomains", domains: []), expecting: "certDomains")
            try await netstackWait("Item 7: netmap with no cert domains") { gate.facts.latest?.certDomains.isEmpty == true }
            try await expectConditionWait(gate, failure: .httpsNotEnabled) {
                _ = try await gate.tool.command(.init(cmd: "setCertDomains", domains: [Self.fqdn]), expecting: "certDomains")
            }
        }

        // MagicDNS disabled.
        try await withHostGate { gate in
            _ = try await gate.tool.command(.init(cmd: "setDNSConfig", enabled: false), expecting: "dnsConfig")
            try await netstackWait("Item 7: netmap with MagicDNS disabled") { gate.facts.latest?.isMagicDNSEnabled == false }
            try await expectConditionWait(gate, failure: .magicDNSDisabled) {
                _ = try await gate.tool.command(.init(cmd: "setDNSConfig", enabled: true), expecting: "dnsConfig")
            }
        }

        // Rejected set-dns.
        try await withHostGate { gate in
            _ = try await gate.tool.command(.init(cmd: "setDNSFault", count: 1, status: 403), expecting: "setDNSFault")
            let rejected = try await failedAttempt(gate) { $0 == .controlRejected(status: 403) }
            let rejectedDelay = rejected.next.timeIntervalSince(rejected.at)
            #expect(rejectedDelay > 25 && rejectedDelay <= 31, "Item 7: the next attempt after controlRejected is in 30 seconds (R4)")
            await gate.tool.checkpoint("M7 item 7: set-dns 403 → controlRejected(403), next attempt in \(rejectedDelay) seconds")
        }

        // Incorrect TXT.
        try await withHostGate { gate in
            _ = try await gate.tool.command(.init(cmd: "setDNSFault", count: 1, wrongTXT: true), expecting: "setDNSFault")
            let invalid = try await failedAttempt(gate) {
                if case .validationFailed = $0 { return true }
                return false
            }
            let invalidDelay = invalid.next.timeIntervalSince(invalid.at)
            #expect(invalidDelay > 15 * 60 - 10 && invalidDelay <= 15 * 60 + 1, "Item 7: the next attempt after validationFailed is in 15 minutes (R4)")
            await gate.tool.checkpoint("M7 item 7: incorrect TXT → \(String(describing: invalid.failure)), next attempt in \(invalidDelay) seconds")
        }
    }

    /// When a precondition fails (something the user must fix), no requests are sent and `nextAttempt` is nil. Issuance follows when `restore` restores the netmap.
    private func expectConditionWait(_ gate: HostGate, failure: CertificateFailure,
                                     restore: () async throws -> Void) async throws {
        let transport = gate.makeTransport()
        let manager = try gate.makeManager(transport: transport)
        let dnsCalls = gate.setDNS.all.count
        let task = Task { try await manager.run() }
        do {
            let status = try await waitForStatus(manager, "Item 7: \(failure)") { $0.lastFailure == failure }
            #expect(status.nextAttempt == nil, "Item 7: \(failure) leaves nextAttempt nil")
            try await Task.sleep(for: .seconds(2))
            #expect(transport.count == 0, "Item 7: \(failure) sends no ACME requests")
            #expect(gate.setDNS.all.count == dnsCalls)
            #expect(await manager.status.nextAttempt == nil)
            let started = ContinuousClock.now
            try await restore()
            let certificate = try await nextEvent(manager.certificates, waitingFor: "Item 7: issuance after reverting \(failure)", timeout: .seconds(120))
            #expect(certificate.domain == Self.fqdn)
            #expect(await manager.status.lastFailure == nil)
            await gate.tool.checkpoint("M7 item 7: \(failure) → 0 requests and nil nextAttempt, issued \(started.duration(to: .now).netstackSeconds) seconds after reverting")
        } catch {
            await stopManager(task)
            throw error
        }
        await stopManager(task)
    }

    /// Triggers one failure with a new manager and observes the failure and the time of the next attempt.
    private func failedAttempt(_ gate: HostGate, matching predicate: @escaping @Sendable (CertificateFailure) -> Bool) async throws
        -> (failure: CertificateFailure, at: Date, next: Date) {
        let manager = try gate.makeManager(transport: gate.makeTransport())
        let task = Task { try await manager.run() }
        do {
            let status = try await waitForStatus(manager, "Item 7: issuance failure", seconds: 120) {
                guard let failure = $0.lastFailure else { return false }
                return predicate(failure) && $0.nextAttempt != nil
            }
            let at = Date()
            await stopManager(task)
            return (try requireValue(status.lastFailure), at, try requireValue(status.nextAttempt))
        } catch {
            await stopManager(task)
            throw error
        }
    }

    @Test("Items 8 and 9: pairing, session, manifest, and 100MiB IPA over tailnet → bridge → TLS listener. Another peer's token yields 403, and connections outside the bridge are dropped")
    func items8and9Scenario() async throws {
        try await withHostGate { gate in
            let manager = try gate.makeManager(transport: gate.makeTransport())
            let (task, certificate, _) = try await runManager(manager)
            let bridge = LoopbackBridge(node: gate.node)
            let sessions = HostSessions()
            let length = 100 * Self.mebibyte
            let server = try await MinimalHTTPServer.start(.tls, certificate: certificate, label: "1", bridge: bridge, sessions: sessions,
                                                           domain: Self.fqdn, ipaSeed: Self.ipaSeed, ipaLength: length)
            let acceptor = BridgeAcceptor(listener: try await gate.node.listen(port: 443), bridge: bridge, port: server.port)
            do {
                let identity = try await gate.goWhoIs(from: "go-peer-b", try gate.peerA.address())
                let stableID = try requireValue(identity.stableID)
                let computedName = try requireValue(identity.computedName)

                // ① Pairing: the server identifies the peer from the bridge's Origin.peer.
                let pair = try await gate.http("go-peer-a", path: "/pair", method: "POST", body: 32)
                #expect(pair.status == 200)
                #expect(pair.bodySHA256 == Self.digest(MinimalHTTPServer.pairBody(stableID: stableID, computedName: computedName)),
                        "Item 8: stableID and computedName in ① belong to that Go peer")
                #expect(server.records.first { $0.request == "POST /pair" }?.stableID == stableID)

                // ② Install session.
                let created = try await gate.http("go-peer-a", path: "/sessions", method: "POST")
                let session = try #require(sessions.issued.last)
                #expect(created.status == 200)
                #expect(session.stableID == stableID)
                #expect(created.bodySHA256 == Self.digest(MinimalHTTPServer.sessionBody(token: session.token)))

                // ③ Manifest.
                let manifest = try await gate.http("go-peer-a", path: "/manifest?token=\(session.token)")
                #expect(manifest.status == 200)
                #expect(manifest.bodySHA256 == Self.digest(MinimalHTTPServer.manifestBody(domain: Self.fqdn, token: session.token)))

                // ④ Transfer 100MiB of IPA in two ranges. Compute expected hashes before starting the measurement.
                let half = length / 2
                let parts = [(UInt64(0), half), (half, length - half)]
                let expected = parts.map { Self.ipaDigest(offset: $0.0, length: $0.1) }
                let sampler = FootprintSampler.start()
                let before = NetstackResources.sample()
                let started = ContinuousClock.now
                var goMilliseconds: Int64 = 0
                for ((offset, count), digest) in zip(parts, expected) {
                    let range = "bytes=\(offset)-\(offset + count - 1)"
                    let part = try await gate.http("go-peer-a", path: "/ipa?token=\(session.token)", range: range, timeout: 600)
                    #expect(part.status == 206)
                    #expect(part.headers?["Content-Range"] == ["bytes \(offset)-\(offset + count - 1)/\(length)"])
                    #expect(part.bodyLength == count)
                    #expect(part.bodySHA256 == digest, "Item 8: SHA-256 of \(range)")
                    goMilliseconds += part.elapsedMs ?? 0
                }
                let seconds = started.duration(to: .now).netstackSeconds
                let cpu = NetstackResources.sample().cpuSeconds - before.cpuSeconds
                let peak = await sampler.stop()
                await gate.tool.checkpoint("M7 item 8: 100MiB IPA (two ranges) hashes match, wall time \(seconds) seconds (\(Double(length) / seconds / 1_048_576) MiB/s), sum of Go elapsedMs \(goMilliseconds), process CPU \(cpu) seconds, phys_footprint initially \(before.footprint ?? 0) and peak sample \(peak) bytes")

                // Reject another Go peer that uses the token from ②.
                let stolen = try await gate.http("go-peer-b", path: "/ipa?token=\(session.token)", range: "bytes=0-1023")
                #expect(stolen.status == 403, "Item 8: another peer requesting ④ with someone else's token gets 403")
                let stolenManifest = try await gate.http("go-peer-b", path: "/manifest?token=\(session.token)")
                #expect(stolenManifest.status == 403)
                await gate.tool.checkpoint("M7 item 8: go-peer-b requested with go-peer-a's token → IPA \(stolen.status ?? 0), manifest \(stolenManifest.status ?? 0)")

                // Item 9: direct TLS to the loopback port outside the bridge.
                let handled = server.records.filter { $0.request != nil }.count
                let probe = await DirectTLSProbe.run(port: server.port, domain: Self.fqdn)
                // A tokenless connection never reaches the TLS handshake. The server-side connection ends without becoming `.ready`.
                try await netstackWait("Item 9: tokenless connection ends on the server before readiness", seconds: 10) {
                    server.records.contains { $0.stateError != nil && $0.stableID == nil && $0.request == nil }
                }
                #expect(!probe.handshake, "Item 9: a connection outside the bridge does not finish the TLS handshake")
                #expect(probe.peerCertificates == 0, "Item 9: no server certificate is received either")
                #expect(probe.receivedBytes == 0, "Item 9: the server sends no response")
                #expect(!probe.end.contains("Did not finish"), "Item 9: the server closes the rejected connection so the peer sees it end (\(probe.end))")
                #expect(!server.records.contains { $0.rejected }, "Item 9: every connection that reached `.ready` has an identity")
                #expect(server.records.filter { $0.request != nil }.count == handled, "Item 9: no request was read")
                await gate.tool.checkpoint("M7 item 9: direct TLS handshake \(probe.handshake), ALPN \(probe.negotiatedALPN ?? "none"), \(probe.peerCertificates) certificates received (chain \(certificate.chain.count)), \(probe.receivedBytes) bytes received, end \(probe.end)")
            } catch {
                await acceptor.close()
                server.close()
                await stopManager(task)
                throw error
            }
            await acceptor.close()
            server.close()
            await stopManager(task)
        }
    }

    @Test("Item 10: removing a Go peer from the netmap during a large transfer closes the loopback connection with an error and removes the origin (TLS and plaintext)")
    func item10OwnerChange() async throws {
        try await withHostGate { gate in
            let manager = try gate.makeManager(transport: gate.makeTransport())
            let (task, certificate, _) = try await runManager(manager)
            let bridge = LoopbackBridge(node: gate.node)
            let sessions = HostSessions()
            let length = 100 * Self.mebibyte
            let tlsHold = TransferHold(afterBytes: 8 * Self.mebibyte)
            let plainHold = TransferHold(afterBytes: 8 * Self.mebibyte)
            let tls = try await MinimalHTTPServer.start(.tls, certificate: certificate, label: "tls", bridge: bridge, sessions: sessions,
                                                        domain: Self.fqdn, ipaSeed: Self.ipaSeed, ipaLength: length, hold: tlsHold)
            let plain = try await MinimalHTTPServer.start(.plain, certificate: nil, label: "plain", bridge: bridge, sessions: sessions,
                                                          domain: Self.fqdn, ipaSeed: Self.ipaSeed, ipaLength: length, hold: plainHold)
            let tlsAcceptor = BridgeAcceptor(listener: try await gate.node.listen(port: 443), bridge: bridge, port: tls.port)
            let plainAcceptor = BridgeAcceptor(listener: try await gate.node.listen(port: 8_080), bridge: bridge, port: plain.port)
            do {
                for (mode, server, hold, peer, name, marker) in [("TLS", tls, tlsHold, gate.peerA, "go-peer-a", UInt8(1)),
                                                                 ("plaintext", plain, plainHold, gate.peerB, "go-peer-b", UInt8(2))] {
                    let scheme = mode == "TLS" ? "https" : "http"
                    let port: UInt16? = mode == "TLS" ? nil : 8_080
                    let created = try await gate.http(name, path: "/sessions", method: "POST", scheme: scheme, port: port)
                    #expect(created.status == 200)
                    let token = try #require(sessions.issued.last).token
                    let download = try await gate.startHTTP(name, path: "/ipa?token=\(token)", scheme: scheme, port: port, timeout: 30)
                    try await netstackWait("Item 10 \(mode): IPA transfer paused at 8MiB") { hold.isReached }
                    // The identity the server obtained and retained at `.ready` belongs to that Go peer.
                    let serving = try #require(server.records.first { $0.request == "GET /ipa" })
                    #expect(serving.stableID == (await gate.node.whoIs(try peer.address()))?.stableID, "Item 10 \(mode): identity of the connection transferring data")
                    #expect(serving.stableID != nil)

                    let started = ContinuousClock.now
                    try await gate.removeFromNetmap(peer, marker: marker)
                    #expect(await gate.node.whoIs(try peer.address()) == nil)
                    try await netstackWait("Item 10 \(mode): server receive ended", seconds: 10) {
                        server.records.first { $0.request == "GET /ipa" }?.receiveEnd != nil
                    }
                    let goneSeconds = started.duration(to: .now).netstackSeconds
                    hold.release()
                    try await netstackWait("Item 10 \(mode): server send ended", seconds: 10) {
                        let record = server.records.first { $0.request == "GET /ipa" }
                        return record?.sendError != nil || record?.bodyBytesSent == length
                    }
                    let record = try #require(server.records.first { $0.request == "GET /ipa" })
                    #expect(record.receiveEnd?.hasPrefix("error(") == true, "Item 10 \(mode): the tailnet-side disconnect does not appear to the server as a clean EOF")
                    #expect(record.sendError != nil, "Item 10 \(mode): the rest of the body cannot be sent")
                    #expect(record.bodyBytesSent < length)
                    var goResult = "No response"
                    do {
                        let response = try await gate.tool.response(to: download, expecting: "peerHTTP", timeout: .seconds(60))
                        goResult = "Received all \(response.bodyLength ?? 0) bytes"
                        Issue.record("Item 10 \(mode): the Go peer received the entire body even after removal from the netmap")
                    } catch {
                        goResult = "Error (\(redacted(String(describing: error)).prefix(120)))"
                    }
                    await gate.tool.checkpoint("M7 item 10 \(mode): loopback connection dropped \(goneSeconds) seconds after PeersRemoved, server receive end \(record.receiveEnd ?? "-"), send error \(record.sendError ?? "-"), \(record.bodyBytesSent) body bytes sent, Go \(goResult)")
                }
            } catch {
                tlsHold.release()
                plainHold.release()
                await tlsAcceptor.close()
                await plainAcceptor.close()
                tls.close()
                plain.close()
                await stopManager(task)
                throw error
            }
            await tlsAcceptor.close()
            await plainAcceptor.close()
            tls.close()
            plain.close()
            await stopManager(task)
        }
    }

    private static func digest(_ bytes: [UInt8]) -> String { Array(SHA256.hash(data: Data(bytes))).hex }

    private static let ipa = IPAContent(seed: ipaSeed)

    static func ipaDigest(offset: UInt64, length: UInt64) -> String { ipa.digest(offset: offset, length: length) }
}

/// Measures peak `phys_footprint` by sampling every 250ms during a transfer.
final class FootprintSampler: Sendable {
    private let peak = Mutex<UInt64>(0)
    private let task = Mutex<Task<Void, Never>?>(nil)

    static func start() -> FootprintSampler {
        let sampler = FootprintSampler()
        let running = Task {
            while !Task.isCancelled {
                let value = NetstackResources.sample().footprint ?? 0
                sampler.peak.withLock { $0 = max($0, value) }
                try? await Task.sleep(for: .milliseconds(250))
            }
        }
        sampler.task.withLock { $0 = running }
        return sampler
    }

    func stop() async -> UInt64 {
        let running = task.withLock { $0 }
        running?.cancel()
        await running?.value
        return peak.withLock { $0 }
    }
}

@Suite("M7 gate (a) test server helpers")
struct HostServerSupportTests {
    @Test("IPA bytes repeat the first period of the LCG64 byte sequence and match when read across a period boundary")
    func ipaContentRepeatsPeriod() {
        var stream = NetstackStream(seed: 7)
        let cycle = stream.bytes(IPAContent.period)
        let content = IPAContent(seed: 7)
        #expect(content.bytes(at: 0, count: 100) == Array(cycle.prefix(100)))
        let boundary = UInt64(IPAContent.period) - 10
        #expect(content.bytes(at: boundary, count: 30) == Array(cycle.suffix(10) + cycle.prefix(20)))
        #expect(content.bytes(at: 3 * UInt64(IPAContent.period) + 5, count: 8) == Array(cycle[5..<13]))
        #expect(content.digest(offset: 0, length: 52_428_800) != content.digest(offset: 52_428_800, length: 52_428_800))
    }

    @Test("Range accepts only bytes=a-b and bytes=a-")
    func ranges() {
        #expect(MinimalHTTPServer.parseRange("bytes=0-99", length: 100).map { [$0.0, $0.1] } == [0, 99])
        #expect(MinimalHTTPServer.parseRange("bytes=50-", length: 100).map { [$0.0, $0.1] } == [50, 99])
        for invalid in ["bytes=0-100", "bytes=10-5", "bytes=-5", "items=0-1", "bytes=0-1,3-4", "bytes=a-b"] {
            #expect(MinimalHTTPServer.parseRange(invalid, length: 100) == nil, "\(invalid)")
        }
    }
}
