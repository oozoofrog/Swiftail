// 노드의 인증서 접점: `certificateFacts`, `setDNS`, `stateDirectory`.
// 계약 `docs/contracts/SwiftailHost.md` 8절 머리의 `package` 선언, 동작 C1·D4.

import Foundation
import SwiftailBase
import SwiftailControl
import Testing
@testable import Swiftail

@Suite("노드: 인증서 접점", .timeLimit(.minutes(1)))
struct CertificateFactsTests {
    static let fqdn = "rd-mac-1a2b3c4d.tail0001.ts.net"

    /// 자기 노드 이름, cert 도메인, MagicDNS 켬을 정한 netmap.
    static func netmap(name: String = fqdn + ".", certDomains: [String] = [fqdn], proxied: Bool = true) throws -> Netmap {
        let domains = certDomains.map { "\"\($0)\"" }.joined(separator: ",")
        let json = #"{"Node":{"ID":1,"StableID":"nStable1","Name":"\#(name)","User":101,"Key":"\#(NodeTestSupport.nodeKey(0x11))","#
            + #""Addresses":["100.64.0.1/32"],"MachineAuthorized":true},"Peers":[],"Domain":"tail0001.ts.net","#
            + #""DNSConfig":{"Proxied":\#(proxied),"CertDomains":[\#(domains)]}}"#
        let response = try JSONDecoder().decode(MapResponse.self, from: Data(json.utf8))
        var session = MapSession()
        return try #require(try session.apply(response, receivedAt: Date()).netmap)
    }

    static func facts(running: Bool, fqdn: String?, certDomains: [String], magicDNS: Bool) -> CertificateFacts {
        var facts = CertificateFacts(state: .starting, netmap: nil)
        facts.isRunning = running
        facts.fqdn = fqdn
        facts.certDomains = certDomains
        facts.isMagicDNSEnabled = magicDNS
        return facts
    }

    private func setDNSError(_ node: TailnetNode, name: String) async -> ControlError? {
        do throws(ControlError) {
            try await node.setDNS(name: name, value: "Zm9vYmFyLWFjbWUtY2hhbGxlbmdlLXZhbHVlLTEyMzQ")
            return nil
        } catch {
            return error
        }
    }

    // MARK: certificateFacts

    @Test("구독하면 지금 값부터 나온다: netmap 전에는 서지 않음, 이름·cert 도메인 없음, MagicDNS 꺼짐")
    func initialValue() async throws {
        let node = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
        var facts = node.certificateFacts.makeAsyncIterator()
        #expect(await facts.next() == Self.facts(running: false, fqdn: nil, certDomains: [], magicDNS: false))
    }

    @Test("netmap을 받은 뒤 구독해도 지금 값(가장 새 것)이 먼저 나온다")
    func subscribeAfterChanges() async throws {
        let node = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
        await node.apply(try Self.netmap())
        var facts = node.certificateFacts.makeAsyncIterator()
        #expect(await facts.next() == Self.facts(running: false, fqdn: Self.fqdn, certDomains: [Self.fqdn], magicDNS: true))
    }

    @Test("상태·이름·cert 도메인·MagicDNS가 바뀔 때마다 새 값이 나오고, 그대로면 나오지 않는다")
    func changes() async throws {
        let node = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
        var facts = node.certificateFacts.makeAsyncIterator()
        _ = await facts.next()

        await node.apply(try Self.netmap())
        #expect(await facts.next() == Self.facts(running: false, fqdn: Self.fqdn, certDomains: [Self.fqdn], magicDNS: true))

        await node.markConnectedForTesting()
        #expect(await facts.next() == Self.facts(running: true, fqdn: Self.fqdn, certDomains: [Self.fqdn], magicDNS: true))

        await node.apply(try Self.netmap(proxied: false))
        #expect(await facts.next() == Self.facts(running: true, fqdn: Self.fqdn, certDomains: [Self.fqdn], magicDNS: false))

        await node.apply(try Self.netmap(certDomains: [], proxied: false))
        #expect(await facts.next() == Self.facts(running: true, fqdn: Self.fqdn, certDomains: [], magicDNS: false))

        let renamed = "rd-mac-5e6f7a8b.tail0001.ts.net"
        await node.apply(try Self.netmap(name: renamed + ".", certDomains: [], proxied: false))
        #expect(await facts.next() == Self.facts(running: true, fqdn: renamed, certDomains: [], magicDNS: false))

        // 같은 사실이 되는 netmap(다시 받음)과 같은 상태(다시 연결)는 내지 않는다.
        await node.apply(try Self.netmap(name: renamed + ".", certDomains: [], proxied: false))
        await node.markConnectedForTesting()
        await node.certificateFactsContinuation.finish()
        #expect(await facts.next() == nil)
    }

    @Test("netmap의 다른 부분만 바뀌면 내지 않는다")
    func unrelatedNetmapChange() async throws {
        let node = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
        await node.apply(try Self.netmap())
        var facts = node.certificateFacts.makeAsyncIterator()
        _ = await facts.next()
        // 피어가 생기고 주소가 바뀐 netmap: 네 사실은 같다.
        await node.apply(try NodeTestSupport.netmap(
            addresses: ["100.64.0.9/32"], dnsConfig: #"{"Proxied":true,"CertDomains":["\#(Self.fqdn)"]}"#, peerAddress: "100.64.0.2/32"
        ))
        await node.certificateFactsContinuation.finish()
        #expect(await facts.next() == nil)
    }

    @Test("소비가 느리면 가장 새 것 하나만 남는다")
    func slowConsumer() async throws {
        let node = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
        await node.apply(try Self.netmap())
        await node.markConnectedForTesting()
        await node.apply(try Self.netmap(proxied: false))
        await node.certificateFactsContinuation.finish()

        let seen = await NodeTestSupport.drain(node.certificateFacts)
        #expect(seen == [Self.facts(running: true, fqdn: Self.fqdn, certDomains: [Self.fqdn], magicDNS: false)])
    }

    @Test("run()이 끝나면 흐름도 끝난다")
    func endsWithRun() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            let node = try TailnetNode(configuration: try NodeTestSupport.configuration(stateDirectory: directory))
            let running = Task { try await node.run() }
            running.cancel()
            _ = await running.result
            let seen = await NodeTestSupport.drain(node.certificateFacts)
            #expect(seen.count <= 1)
        }
    }

    // MARK: setDNS

    @Test("노드가 running이 아니면 setDNS는 connection으로 거절한다")
    func setDNSBeforeRunning() async throws {
        let node = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
        await node.apply(try Self.netmap())
        guard case .connection? = await setDNSError(node, name: "_acme-challenge." + Self.fqdn) else {
            Issue.record("running 전의 setDNS가 connection으로 끝나지 않았다")
            return
        }
    }

    @Test(
        "자기 cert 도메인의 _acme-challenge. 레코드가 아닌 이름은 invalidConfiguration이다",
        arguments: [
            "rd-mac-1a2b3c4d.tail0001.ts.net",
            "_acme-challenge.rd-phone-1a2b3c4d.tail0001.ts.net",
            "_acme-challenge.rd-mac-1a2b3c4d.tail0001.ts.net.",
            "_ACME-CHALLENGE.rd-mac-1a2b3c4d.tail0001.ts.net",
            "_acme-challenge.tail0001.ts.net",
        ]
    )
    func setDNSRejectsOtherNames(_ name: String) async throws {
        let node = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
        await node.apply(try Self.netmap())
        await node.markConnectedForTesting()
        guard case .invalidConfiguration(let message)? = await setDNSError(node, name: name) else {
            Issue.record("다른 이름을 받아들였다")
            return
        }
        #expect(!message.contains("tail0001"), "오류 문자열에 이름이 남았다")
    }

    @Test("자기 이름이 cert 도메인에 없으면 그 이름의 레코드도 invalidConfiguration이다")
    func setDNSRequiresCertDomain() async throws {
        let node = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
        await node.apply(try Self.netmap(certDomains: ["rd-phone-1a2b3c4d.tail0001.ts.net"]))
        await node.markConnectedForTesting()
        guard case .invalidConfiguration? = await setDNSError(node, name: "_acme-challenge." + Self.fqdn) else {
            Issue.record("cert 도메인에 없는 이름을 받아들였다")
            return
        }
    }

    @Test("이름이 맞아도 run() 밖이면(제어 클라이언트 없음) connection이다")
    func setDNSOutsideRun() async throws {
        let node = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
        await node.apply(try Self.netmap())
        await node.markConnectedForTesting()
        guard case .connection? = await setDNSError(node, name: "_acme-challenge." + Self.fqdn) else {
            Issue.record("제어 클라이언트 없이 connection으로 끝나지 않았다")
            return
        }
    }

    // MARK: stateDirectory

    @Test("stateDirectory는 설정의 상태 디렉터리다")
    func stateDirectory() throws {
        let configuration = try NodeTestSupport.unusedConfiguration()
        let node = try TailnetNode(configuration: configuration)
        #expect(node.stateDirectory == configuration.stateDirectory)
    }
}

private extension TailnetNode {
    /// 홈 DERP 연결이 선 것처럼 상태 기계에 넣는다(netmap 뒤면 `.running`).
    func markConnectedForTesting() {
        announce(stateMachine.connected())
    }
}
