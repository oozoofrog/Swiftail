// M7 관문 (가): 계정 없이(계약 `docs/contracts/SwiftailHost.md` 7절 표의 항목 1~10).
//
// 상대는 `tailnet` 도구다: testcontrol + DERP + STUN + Go tsnet 피어 둘 + pebble(로컬 ACME)·challtestsrv. 실제 인터넷에는
// 닿지 않는다. 항목 11(Go 상태 가져오기, M7-11)은 구현이 없어 쓰지 않고, 항목 12(전체 시험)는 총괄이 돌린다.

import CryptoKit
import Foundation
import Swiftail
import SwiftailBase
import SwiftailLoopback
import Synchronization
import Testing

@testable import SwiftailCertificates

@Suite("M7 관문 (가): 계정 없이", .enabled(if: tailnetBinary != nil, "SWIFTAIL_TAILNET가 없어 M7 관문을 건너뜁니다"),
       .serialized, .timeLimit(.minutes(30)))
struct HostTests {
    private static let fqdn = HostGate.fqdn
    private static let ipaSeed: UInt64 = 0x4950_4131
    private static let mebibyte: UInt64 = 1_048_576

    @Test("항목 1: whoIs가 Go 피어 둘·자기 주소에서 peerWhoIs와 같고, netmap에서 뺀 피어는 nil")
    func item1WhoIs() async throws {
        try await withHostGate { gate in
            for (label, peer) in [("go-peer-a", gate.peerA), ("go-peer-b", gate.peerB), ("Swift 자기", gate.local)] {
                for address in peer.addresses {
                    let swift = try #require(await gate.node.whoIs(address), "항목 1: \(label) IPv\(address.isIPv4 ? 4 : 6)의 whoIs가 nil")
                    for viewer in ["go-peer-a", "go-peer-b"] {
                        let go = try await gate.goWhoIs(from: viewer, address)
                        #expect(swift.stableID == go.stableID, "항목 1: \(label) stableID (\(viewer) 기준)")
                        #expect(swift.name == go.nodeName, "항목 1: \(label) name (\(viewer) 기준)")
                        #expect(swift.computedName == go.computedName, "항목 1: \(label) computedName (\(viewer) 기준)")
                        #expect(swift.loginName == go.loginName, "항목 1: \(label) loginName (\(viewer) 기준)")
                    }
                    #expect(!swift.stableID.isEmpty)
                }
            }
            await gate.tool.checkpoint("M7 항목 1: 주소 6개의 신원이 Go 피어 둘의 peerWhoIs와 같음")

            _ = try await gate.tool.command(.init(cmd: "removePeer", name: "go-peer-b"), expecting: "removed")
            try await gate.removeFromNetmap(gate.peerB, marker: 1)
            for address in gate.peerB.addresses {
                #expect(await gate.node.whoIs(address) == nil, "항목 1: netmap에서 뺀 피어의 whoIs는 nil")
            }
            for address in gate.peerA.addresses {
                #expect(await gate.node.whoIs(address) != nil, "항목 1: 남은 피어의 whoIs는 그대로")
            }
            await gate.tool.checkpoint("M7 항목 1: PeersRemoved 뒤 go-peer-b의 whoIs nil, go-peer-a는 그대로")
        }
    }

    @Test("항목 2·3·4: set-dns의 TXT, pebble 발급과 certs/ 파일, 다시 띄우면 요청 없이 저장된 인증서")
    func items2to4IssueAndRestart() async throws {
        try await withHostGate { gate in
            let transport = gate.makeTransport()
            let manager = try gate.makeManager(transport: transport)
            let (task, certificate, seconds) = try await runManager(manager)
            let firstRequests = transport.count
            await stopManager(task)

            // 항목 2: 관리자가 올린 값과 testcontrol이 받은 값.
            let calls = gate.setDNS.all
            let call = try #require(calls.first)
            #expect(calls.count == 1)
            #expect(call.failure == nil)
            #expect(call.name == "_acme-challenge." + Self.fqdn)
            #expect(call.value.utf8.count == 43, "항목 2: TXT 값은 채움 없는 base64url SHA-256(43바이트)")
            let log = try #require(await gate.tool.command(.init(cmd: "setDNSLog"), expecting: "setDNSLog").requests)
            #expect(log.count == 1)
            #expect(log.last?.name == call.name)
            #expect(log.last?.type == "TXT")
            #expect(log.last?.value == call.value, "항목 2: setDNSLog의 값이 Swift가 계산한 TXT와 같다")
            await gate.tool.checkpoint("M7 항목 2: set-dns 왕복 \(call.seconds)초, setDNSLog의 이름·종류·값 일치")

            // 항목 3: 사슬·이름·파일.
            #expect(certificate.domain == Self.fqdn)
            #expect(try chainVerifies(certificate.chain, domain: Self.fqdn, anchor: gate.rootDER), "항목 3: 사슬이 pebble 루트로 검증된다")
            #expect(!certificate.chain.contains(gate.rootDER), "항목 3: chain에 루트가 없다(동작 S6)")
            #expect(certificate.notAfter > certificate.notBefore)
            let status = await manager.status
            #expect(status.notAfter == certificate.notAfter && status.lastFailure == nil && status.domain == Self.fqdn)
            let files = FileManager.default
            let directory = gate.certificatesDirectory
            #expect(try files.attributesOfItem(atPath: directory.path)[.posixPermissions] as? Int == 0o700)
            for name in ["\(Self.fqdn).crt", "\(Self.fqdn).key", "acme-account.key.pem"] {
                let attributes = try files.attributesOfItem(atPath: directory.appending(path: name).path)
                #expect(attributes[.posixPermissions] as? Int == 0o600, "항목 3: \(name)의 권한은 0600")
            }
            let stored = try String(contentsOf: directory.appending(path: "\(Self.fqdn).crt"), encoding: .utf8)
            let blocks = stored.components(separatedBy: "-----BEGIN CERTIFICATE-----").count - 1
            #expect(try files.contentsOfDirectory(atPath: directory.path).sorted()
                    == ["\(Self.fqdn).crt", "\(Self.fqdn).key", "acme-account.key.pem"].sorted())
            await gate.tool.checkpoint("M7 항목 3: 발급 \(seconds)초(관리자 시작부터 첫 인증서까지), ACME 요청 \(firstRequests)개, chain \(certificate.chain.count)장(파일 \(blocks)장), 유효 \(certificate.notAfter.timeIntervalSince(certificate.notBefore) / 86_400)일, certs/ 0700·파일 0600")

            // 항목 4: 같은 상태 디렉터리로 다시 띄운다.
            let again = gate.makeTransport()
            let restarted = try gate.makeManager(transport: again)
            let (task2, reused, reuseSeconds) = try await runManager(restarted, waitingSeconds: 15)
            try await Task.sleep(for: .seconds(1))
            #expect(reused.chain == certificate.chain)
            #expect(reused.publicKeyBytes == certificate.publicKeyBytes)
            #expect(again.count == 0, "항목 4: 다시 띄운 관리자는 ACME 요청을 보내지 않는다")
            #expect(gate.setDNS.all.count == 1)
            #expect(await restarted.status.lastFailure == nil)
            await stopManager(task2)
            await gate.tool.checkpoint("M7 항목 4: 다시 띄운 관리자가 \(reuseSeconds)초에 저장된 인증서를 냄, ACME 요청 \(again.count)개")
        }
    }

    @Test("항목 5: pebble의 nonce 거부(10%)와 authorization 재사용을 켠 채 발급")
    func item5BadNonceAndAuthorizationReuse() async throws {
        try await withHostGate(nonceReject: 10, authzReuse: 100) { gate in
            var badNonces = 0
            var requests = 0
            var issuances = 0
            // 첫 발급 뒤 같은 계정으로 다시 발급한다. badNonce가 한 번이라도 보일 때까지(많아야 열 번).
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
                await gate.tool.checkpoint("M7 항목 5: 발급 \(issuances)번째 \(seconds)초, 요청 \(transport.count)개 중 badNonce \(transport.badNonceCount)번")
            }
            #expect(badNonces > 0, "항목 5: nonce 거부를 실제로 겪고 다시 서명해 통과했다")
            #expect(gate.setDNS.all.count == 1, "항목 5: 두 번째 발급부터는 valid authorization을 재사용해 set-dns가 없다")
            await gate.tool.checkpoint("M7 항목 5: 발급 \(issuances)번 모두 통과, 요청 \(requests)개 중 badNonce \(badNonces)번, set-dns \(gate.setDNS.all.count)번")
        }
    }

    @Test("항목 6: 시험용 시계를 2/3 뒤로 옮기면 새 키의 새 인증서, 옛 리스너의 연결은 그대로")
    func item6Renewal() async throws {
        try await withHostGate { gate in
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
                try await netstackWait("항목 6: 옛 리스너의 IPA 전송이 4MiB에서 멈춤") { hold.isReached }

                let renewalPoint = first.notBefore.addingTimeInterval(first.notAfter.timeIntervalSince(first.notBefore) * 2 / 3)
                let started = ContinuousClock.now
                clock.advance(by: renewalPoint.timeIntervalSince(clock.now()) + 60)
                let second = try await nextEvent(manager.certificates, waitingFor: "항목 6: 갱신 인증서", timeout: .seconds(120))
                let renewalSeconds = started.duration(to: .now).netstackSeconds
                #expect(second.publicKeyBytes != first.publicKeyBytes, "항목 6: 갱신은 새 키다")
                #expect(second.chain[0] != first.chain[0])
                #expect(try chainVerifies(second.chain, domain: Self.fqdn, anchor: gate.rootDER))
                #expect(await manager.status.notAfter == second.notAfter)
                #expect(gate.setDNS.all.count == 2)

                let server = try await MinimalHTTPServer.start(.tls, certificate: second, label: "2", bridge: bridge, sessions: sessions,
                                                               domain: Self.fqdn, ipaSeed: Self.ipaSeed, ipaLength: length)
                renewed = server
                acceptor.switchTo(port: server.port)
                old.stopAccepting()
                let pair = try await gate.http("go-peer-b", path: "/pair", method: "POST", body: 32)
                #expect(pair.status == 200)
                #expect(pair.headers?["Swiftail-Listener"] == ["2"], "항목 6: 새 연결은 새 인증서의 리스너로 간다")

                hold.release()
                let done = try await gate.tool.response(to: download, expecting: "peerHTTP", timeout: .seconds(300))
                #expect(done.status == 200)
                #expect(done.headers?["Swiftail-Listener"] == ["1"], "항목 6: 갱신 전에 맺은 연결은 옛 리스너에서 끝까지 간다")
                #expect(done.bodyLength == length)
                #expect(done.bodySHA256 == Self.ipaDigest(offset: 0, length: length))
                let record = try #require(old.records.first { $0.request == "GET /ipa" })
                #expect(record.sendError == nil && record.bodyBytesSent == length)
                await gate.tool.checkpoint("M7 항목 6: 시계를 \(Int(renewalPoint.timeIntervalSince(first.notBefore) / 86_400))일 뒤로 옮긴 뒤 \(renewalSeconds)초에 새 키의 인증서, 옛 리스너의 32MiB 전송이 갱신을 지나 해시 일치")
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

    @Test("항목 7: cert 도메인 없음·MagicDNS 꺼짐은 요청 없이 기다리고, set-dns 거절·틀린 TXT는 R4의 간격")
    func item7Failures() async throws {
        try await withHostGate { gate in
            // HTTPS 꺼짐(cert 도메인이 빔).
            _ = try await gate.tool.command(.init(cmd: "setCertDomains", domains: []), expecting: "certDomains")
            try await netstackWait("항목 7: cert 도메인이 빈 netmap") { gate.facts.latest?.certDomains.isEmpty == true }
            try await expectConditionWait(gate, failure: .httpsNotEnabled) {
                _ = try await gate.tool.command(.init(cmd: "setCertDomains", domains: [Self.fqdn]), expecting: "certDomains")
            }

            // MagicDNS 꺼짐.
            try gate.removeStoredCertificate()
            _ = try await gate.tool.command(.init(cmd: "setDNSConfig", enabled: false), expecting: "dnsConfig")
            try await netstackWait("항목 7: MagicDNS가 꺼진 netmap") { gate.facts.latest?.isMagicDNSEnabled == false }
            try await expectConditionWait(gate, failure: .magicDNSDisabled) {
                _ = try await gate.tool.command(.init(cmd: "setDNSConfig", enabled: true), expecting: "dnsConfig")
            }

            // set-dns 거절.
            try gate.removeStoredCertificate()
            _ = try await gate.tool.command(.init(cmd: "setDNSFault", count: 1, status: 403), expecting: "setDNSFault")
            let rejected = try await failedAttempt(gate) { $0 == .controlRejected(status: 403) }
            let rejectedDelay = rejected.next.timeIntervalSince(rejected.at)
            #expect(rejectedDelay > 25 && rejectedDelay <= 31, "항목 7: controlRejected의 다음 시도는 30초 뒤(R4)")
            await gate.tool.checkpoint("M7 항목 7: set-dns 403 → controlRejected(403), 다음 시도 \(rejectedDelay)초 뒤")

            // 틀린 TXT.
            try gate.removeStoredCertificate()
            _ = try await gate.tool.command(.init(cmd: "setDNSFault", count: 1, wrongTXT: true), expecting: "setDNSFault")
            let invalid = try await failedAttempt(gate) {
                if case .validationFailed = $0 { return true }
                return false
            }
            let invalidDelay = invalid.next.timeIntervalSince(invalid.at)
            #expect(invalidDelay > 15 * 60 - 10 && invalidDelay <= 15 * 60 + 1, "항목 7: validationFailed의 다음 시도는 15분 뒤(R4)")
            await gate.tool.checkpoint("M7 항목 7: 틀린 TXT → \(String(describing: invalid.failure)), 다음 시도 \(invalidDelay)초 뒤")
            _ = try await gate.tool.command(.init(cmd: "setDNSFault", count: 0), expecting: "setDNSFault")
        }
    }

    /// 조건 실패(사용자가 고칠 것)면 요청이 나가지 않고 `nextAttempt`가 nil이며, `restore`로 netmap을 되돌리면 발급한다.
    private func expectConditionWait(_ gate: HostGate, failure: CertificateFailure,
                                     restore: () async throws -> Void) async throws {
        let transport = gate.makeTransport()
        let manager = try gate.makeManager(transport: transport)
        let dnsCalls = gate.setDNS.all.count
        let task = Task { try await manager.run() }
        do {
            let status = try await waitForStatus(manager, "항목 7: \(failure)") { $0.lastFailure == failure }
            #expect(status.nextAttempt == nil, "항목 7: \(failure)면 nextAttempt는 nil")
            try await Task.sleep(for: .seconds(2))
            #expect(transport.count == 0, "항목 7: \(failure)면 ACME 요청이 나가지 않는다")
            #expect(gate.setDNS.all.count == dnsCalls)
            #expect(await manager.status.nextAttempt == nil)
            let started = ContinuousClock.now
            try await restore()
            let certificate = try await nextEvent(manager.certificates, waitingFor: "항목 7: \(failure)를 되돌린 뒤 발급", timeout: .seconds(120))
            #expect(certificate.domain == Self.fqdn)
            #expect(await manager.status.lastFailure == nil)
            await gate.tool.checkpoint("M7 항목 7: \(failure) → 요청 0개·nextAttempt nil, 되돌린 뒤 \(started.duration(to: .now).netstackSeconds)초에 발급")
        } catch {
            await stopManager(task)
            throw error
        }
        await stopManager(task)
    }

    /// 새 관리자로 한 번 실패시키고 그 실패와 다음 시도 시각을 본다.
    private func failedAttempt(_ gate: HostGate, matching predicate: @escaping @Sendable (CertificateFailure) -> Bool) async throws
        -> (failure: CertificateFailure, at: Date, next: Date) {
        let manager = try gate.makeManager(transport: gate.makeTransport())
        let task = Task { try await manager.run() }
        do {
            let status = try await waitForStatus(manager, "항목 7: 발급 실패", seconds: 120) {
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

    @Test("항목 8·9: tailnet → 다리 → TLS 리스너의 페어링·세션·매니페스트·IPA 100MiB, 다른 피어의 토큰은 403, 다리 밖의 접속은 끊김")
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

                // ① 페어링: 서버가 다리의 Origin.peer로 상대를 안다.
                let pair = try await gate.http("go-peer-a", path: "/pair", method: "POST", body: 32)
                #expect(pair.status == 200)
                #expect(pair.bodySHA256 == Self.digest(MinimalHTTPServer.pairBody(stableID: stableID, computedName: computedName)),
                        "항목 8: ①의 stableID·computedName이 그 Go 피어의 것")
                #expect(server.records.first { $0.request == "POST /pair" }?.stableID == stableID)

                // ② 설치 세션.
                let created = try await gate.http("go-peer-a", path: "/sessions", method: "POST")
                let session = try #require(sessions.issued.last)
                #expect(created.status == 200)
                #expect(session.stableID == stableID)
                #expect(created.bodySHA256 == Self.digest(MinimalHTTPServer.sessionBody(token: session.token)))

                // ③ 매니페스트.
                let manifest = try await gate.http("go-peer-a", path: "/manifest?token=\(session.token)")
                #expect(manifest.status == 200)
                #expect(manifest.bodySHA256 == Self.digest(MinimalHTTPServer.manifestBody(domain: Self.fqdn, token: session.token)))

                // ④ IPA 100MiB를 Range 둘로. 기대 해시는 재기 전에 만든다.
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
                    #expect(part.bodySHA256 == digest, "항목 8: \(range)의 SHA-256")
                    goMilliseconds += part.elapsedMs ?? 0
                }
                let seconds = started.duration(to: .now).netstackSeconds
                let cpu = NetstackResources.sample().cpuSeconds - before.cpuSeconds
                let peak = await sampler.stop()
                await gate.tool.checkpoint("M7 항목 8: IPA 100MiB(Range 둘) 해시 일치, 벽시계 \(seconds)초(\(Double(length) / seconds / 1_048_576) MiB/s), Go elapsedMs 합 \(goMilliseconds), 프로세스 CPU \(cpu)초, phys_footprint 시작 \(before.footprint ?? 0)·표본 최고 \(peak)바이트")

                // 다른 Go 피어가 ②의 토큰을 쓰면 거절한다.
                let stolen = try await gate.http("go-peer-b", path: "/ipa?token=\(session.token)", range: "bytes=0-1023")
                #expect(stolen.status == 403, "항목 8: 다른 피어가 남의 토큰으로 ④를 요청하면 403")
                let stolenManifest = try await gate.http("go-peer-b", path: "/manifest?token=\(session.token)")
                #expect(stolenManifest.status == 403)
                await gate.tool.checkpoint("M7 항목 8: go-peer-b가 go-peer-a의 토큰으로 요청 → IPA \(stolen.status ?? 0), 매니페스트 \(stolenManifest.status ?? 0)")

                // 항목 9: 다리 밖에서 루프백 포트로 직접 TLS.
                let handled = server.records.filter { $0.request != nil }.count
                let probe = await DirectTLSProbe.run(port: server.port, domain: Self.fqdn)
                // 토큰이 없는 연결은 TLS 핸드셰이크에 닿지도 못한다: 서버 쪽 연결은 `.ready`가 되지 못하고 끝난다.
                try await netstackWait("항목 9: 서버가 토큰 없는 연결을 준비 전에 잃음", seconds: 10) {
                    server.records.contains { $0.stateError != nil && $0.stableID == nil && $0.request == nil }
                }
                #expect(!probe.handshake, "항목 9: 다리 밖의 연결은 TLS 핸드셰이크를 끝내지 못한다")
                #expect(probe.peerCertificates == 0, "항목 9: 서버의 인증서도 받지 못한다")
                #expect(probe.receivedBytes == 0, "항목 9: 서버가 응답하지 않는다")
                #expect(!probe.end.contains("끝나지 않음"), "항목 9: 서버가 거절한 연결을 닫아 상대가 끝을 본다(\(probe.end))")
                #expect(!server.records.contains { $0.rejected }, "항목 9: `.ready`가 된 연결 가운데 신원 없는 것은 없다")
                #expect(server.records.filter { $0.request != nil }.count == handled, "항목 9: 요청을 읽지 않았다")
                await gate.tool.checkpoint("M7 항목 9: 직접 TLS 핸드셰이크 \(probe.handshake), ALPN \(probe.negotiatedALPN ?? "없음"), 받은 인증서 \(probe.peerCertificates)장(chain \(certificate.chain.count)장), 받은 바이트 \(probe.receivedBytes), 끝 \(probe.end)")
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

    @Test("항목 10: 큰 전송 중 Go 피어를 netmap에서 빼면 루프백 연결이 오류로 닫히고 origin이 사라진다(TLS·평문)")
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
                                                                 ("평문", plain, plainHold, gate.peerB, "go-peer-b", UInt8(2))] {
                    let scheme = mode == "TLS" ? "https" : "http"
                    let port: UInt16? = mode == "TLS" ? nil : 8_080
                    let created = try await gate.http(name, path: "/sessions", method: "POST", scheme: scheme, port: port)
                    #expect(created.status == 200)
                    let token = try #require(sessions.issued.last).token
                    let download = try await gate.startHTTP(name, path: "/ipa?token=\(token)", scheme: scheme, port: port, timeout: 30)
                    try await netstackWait("항목 10 \(mode): IPA 전송이 8MiB에서 멈춤") { hold.isReached }
                    // 서버가 `.ready`에서 얻어 쥔 신원이 그 Go 피어의 것이다.
                    let serving = try #require(server.records.first { $0.request == "GET /ipa" })
                    #expect(serving.stableID == (await gate.node.whoIs(try peer.address()))?.stableID, "항목 10 \(mode): 전송 중인 연결의 신원")
                    #expect(serving.stableID != nil)

                    let started = ContinuousClock.now
                    try await gate.removeFromNetmap(peer, marker: marker)
                    #expect(await gate.node.whoIs(try peer.address()) == nil)
                    try await netstackWait("항목 10 \(mode): 서버의 받기가 끝남", seconds: 10) {
                        server.records.first { $0.request == "GET /ipa" }?.receiveEnd != nil
                    }
                    let goneSeconds = started.duration(to: .now).netstackSeconds
                    hold.release()
                    try await netstackWait("항목 10 \(mode): 서버의 보내기가 끝남", seconds: 10) {
                        let record = server.records.first { $0.request == "GET /ipa" }
                        return record?.sendError != nil || record?.bodyBytesSent == length
                    }
                    let record = try #require(server.records.first { $0.request == "GET /ipa" })
                    #expect(record.receiveEnd?.hasPrefix("error(") == true, "항목 10 \(mode): tailnet 쪽 끊김이 서버에 깨끗한 EOF로 보이지 않는다")
                    #expect(record.sendError != nil, "항목 10 \(mode): 남은 본문을 보내지 못한다")
                    #expect(record.bodyBytesSent < length)
                    var goResult = "응답 없음"
                    do {
                        let response = try await gate.tool.response(to: download, expecting: "peerHTTP", timeout: .seconds(60))
                        goResult = "끝까지 받음 \(response.bodyLength ?? 0)바이트"
                        Issue.record("항목 10 \(mode): Go 피어가 netmap에서 빠진 뒤에도 본문을 끝까지 받았다")
                    } catch {
                        goResult = "오류(\(redacted(String(describing: error)).prefix(120)))"
                    }
                    await gate.tool.checkpoint("M7 항목 10 \(mode): PeersRemoved 뒤 \(goneSeconds)초에 루프백 연결이 끊김, 서버 받기 끝 \(record.receiveEnd ?? "-"), 보내기 오류 \(record.sendError ?? "-"), 보낸 본문 \(record.bodyBytesSent)바이트, Go \(goResult)")
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

/// 전송 동안 `phys_footprint`의 최고값을 250ms마다 표본으로 잰다.
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

@Suite("M7 관문 (가)의 시험 서버 도우미")
struct HostServerSupportTests {
    @Test("IPA 바이트열: LCG64 바이트열의 앞 주기를 되풀이하고, 주기 경계를 넘어 꺼내도 같다")
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

    @Test("Range: bytes=a-b와 bytes=a-만 받는다")
    func ranges() {
        #expect(MinimalHTTPServer.parseRange("bytes=0-99", length: 100).map { [$0.0, $0.1] } == [0, 99])
        #expect(MinimalHTTPServer.parseRange("bytes=50-", length: 100).map { [$0.0, $0.1] } == [50, 99])
        for invalid in ["bytes=0-100", "bytes=10-5", "bytes=-5", "items=0-1", "bytes=0-1,3-4", "bytes=a-b"] {
            #expect(MinimalHTTPServer.parseRange(invalid, length: 100) == nil, "\(invalid)")
        }
    }
}
