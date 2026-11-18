// The node's certificate interfaces: `certificateFacts`, `setDNS`, and `stateDirectory`.
// The `package` declarations at the start of contract `docs/contracts/SwiftailHost.md` §8, behaviors C1·D4.

import Foundation
import SwiftailBase
import SwiftailControl
import Testing
@testable import Swiftail

@Suite("Node certificate interfaces", .timeLimit(.minutes(1)))
struct CertificateFactsTests {
    static let fqdn = "rd-mac-1a2b3c4d.tail0001.ts.net"

    /// A netmap that specifies the local node name, cert domains, and whether MagicDNS is enabled.
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

    @Test("A subscription yields the current value first: before a netmap, the node is not up, has no name or cert domains, and MagicDNS is off")
    func initialValue() async throws {
        let node = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
        var facts = node.certificateFacts.makeAsyncIterator()
        #expect(await facts.next() == Self.facts(running: false, fqdn: nil, certDomains: [], magicDNS: false))
    }

    @Test("A subscription after the netmap arrives still yields the current (latest) value first")
    func subscribeAfterChanges() async throws {
        let node = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
        await node.apply(try Self.netmap())
        var facts = node.certificateFacts.makeAsyncIterator()
        #expect(await facts.next() == Self.facts(running: false, fqdn: Self.fqdn, certDomains: [Self.fqdn], magicDNS: true))
    }

    @Test("Yields a new value whenever the state, name, cert domains, or MagicDNS changes, and yields nothing if they stay the same")
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

        // Do not emit for a netmap with the same facts (received again) or the same state (reconnected).
        await node.apply(try Self.netmap(name: renamed + ".", certDomains: [], proxied: false))
        await node.markConnectedForTesting()
        node.certificateFactsPublisher.finish()
        #expect(await facts.next() == nil)
    }

    /// Before the fix, the node had only one stream. Stopping the manager (canceling the reading Task ends the stream) and installing a new manager
    /// on the same node handed it a stream that ended immediately, leaving it at "the node is not running" indefinitely.
    @Test("Resubscribing starts again with the current value and ends the previous subscription")
    func resubscribing() async throws {
        let node = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
        var first = node.certificateFacts.makeAsyncIterator()
        _ = await first.next()
        await node.apply(try Self.netmap())
        await node.markConnectedForTesting()

        var second = node.certificateFacts.makeAsyncIterator()
        let current = Self.facts(running: true, fqdn: Self.fqdn, certDomains: [Self.fqdn], magicDNS: true)
        #expect(await second.next() == current)
        await node.apply(try Self.netmap(proxied: false))
        #expect(await second.next() == Self.facts(running: true, fqdn: Self.fqdn, certDomains: [Self.fqdn], magicDNS: false))
        // The previous subscription yields one unread value before ending.
        var rest: [CertificateFacts] = []
        while let facts = await first.next() { rest.append(facts) }
        #expect(rest.count <= 1)
    }

    @Test("Changes elsewhere in the netmap yield nothing")
    func unrelatedNetmapChange() async throws {
        let node = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
        await node.apply(try Self.netmap())
        var facts = node.certificateFacts.makeAsyncIterator()
        _ = await facts.next()
        // A netmap with a new peer and changed addresses: the four facts stay the same.
        await node.apply(try NodeTestSupport.netmap(
            addresses: ["100.64.0.9/32"], dnsConfig: #"{"Proxied":true,"CertDomains":["\#(Self.fqdn)"]}"#, peerAddress: "100.64.0.2/32"
        ))
        node.certificateFactsPublisher.finish()
        #expect(await facts.next() == nil)
    }

    @Test("A slow consumer retains only the latest value")
    func slowConsumer() async throws {
        let node = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
        await node.apply(try Self.netmap())
        await node.markConnectedForTesting()
        await node.apply(try Self.netmap(proxied: false))
        node.certificateFactsPublisher.finish()

        let seen = await NodeTestSupport.drain(node.certificateFacts)
        #expect(seen == [Self.facts(running: true, fqdn: Self.fqdn, certDomains: [Self.fqdn], magicDNS: false)])
    }

    @Test("The stream ends when run() ends")
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

    @Test("setDNS rejects with connection when the node is not running")
    func setDNSBeforeRunning() async throws {
        let node = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
        await node.apply(try Self.netmap())
        guard case .connection? = await setDNSError(node, name: "_acme-challenge." + Self.fqdn) else {
            Issue.record("setDNS before running did not end with connection")
            return
        }
    }

    @Test(
        "A name other than an _acme-challenge. record for a local cert domain yields invalidConfiguration",
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
            Issue.record("Accepted a different name")
            return
        }
        #expect(!message.contains("tail0001"), "The error string still contains the name")
    }

    @Test("If the node's own name is absent from the cert domains, its record also yields invalidConfiguration")
    func setDNSRequiresCertDomain() async throws {
        let node = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
        await node.apply(try Self.netmap(certDomains: ["rd-phone-1a2b3c4d.tail0001.ts.net"]))
        await node.markConnectedForTesting()
        guard case .invalidConfiguration? = await setDNSError(node, name: "_acme-challenge." + Self.fqdn) else {
            Issue.record("Accepted a name absent from the cert domains")
            return
        }
    }

    @Test("A matching name still yields connection outside run() (no control client)")
    func setDNSOutsideRun() async throws {
        let node = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
        await node.apply(try Self.netmap())
        await node.markConnectedForTesting()
        guard case .connection? = await setDNSError(node, name: "_acme-challenge." + Self.fqdn) else {
            Issue.record("Did not end with connection when the control client was absent")
            return
        }
    }

    // MARK: stateDirectory

    @Test("stateDirectory is the configured state directory")
    func stateDirectory() throws {
        let configuration = try NodeTestSupport.unusedConfiguration()
        let node = try TailnetNode(configuration: configuration)
        #expect(node.stateDirectory == configuration.stateDirectory)
    }
}

private extension TailnetNode {
    /// Updates the state machine as if the home DERP connection came up (`.running` after the netmap).
    func markConnectedForTesting() {
        announce(stateMachine.connected())
    }
}
