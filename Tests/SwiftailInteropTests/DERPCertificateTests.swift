import Foundation
import Swiftail
import SwiftailBase
import Testing

/// M8 ③ advertises the DERP node with `CertName: sha256-raw:<hash>` instead of `InsecureForTests` (the `docs/contracts/SwiftailDERP.md` contract,
/// "M8 ③" tests and gates). The tool's DERP server presents a meta certificate alongside a self-signed certificate like derper's manual IP certificate mode.
@Suite("M8 ③ DERP certificate pinning gate", .enabled(if: tailnetBinary != nil, "Skipping the M8 ③ gate because SWIFTAIL_TAILNET is missing"),
       .serialized, .timeLimit(.minutes(4)))
struct DERPCertificateTests {
    @Test("Correct pin: the Swift node exchanges packets with the Go peer through the pinned DERP server")
    func pinnedRelay() async throws {
        try await withGate(direct: false, derpCertificate: "pinned") { gate in
            let nodes = try #require(await gate.tool.command(.init(cmd: "nodes"), expecting: "nodes").nodes)
            let fqdn = try #require(nodes.first { $0.nodeKey == gate.peer.key }?.name)
            // Block all UDP candidate ports advertised by Go so traffic goes only through DERP (same method as `netstackPrepare`).
            var ports: Set<UInt16> = []
            try await netstackWait("Go UDP candidates") {
                let status = try await gate.tool.command(.init(cmd: "peerStatus", name: "go-peer-a"), expecting: "peerStatus")
                ports = Set((status.selfAddrs ?? []).compactMap(IPEndpoint.init).map(\.port))
                return !ports.isEmpty
            }
            await gate.node.setBlockedUDPPorts(ports)
            try await netstackWait("UDP echo over the DERP path") {
                try await gate.echo(payload: [0x4d, 0x38, 0x03])
                return await gate.node.path(toPeerNamed: fqdn) == .relayed(derpRegion: 1)
            }
            try await gate.echo(payload: [0x4d, 0x38, 0x04])
            #expect(await gate.node.path(toPeerNamed: fqdn) == .relayed(derpRegion: 1))
        }
    }

    /// No Go peer is started, so only the Swift node connects to the DERP server over TLS. Without peers, only the home DERP connection can bring it to `running`.
    @Test("Swift node only: with the correct pin, DERP connects and the node reaches running")
    func pinnedConnects() async throws {
        try await withSwiftOnlyNode(mode: "pinned") { tool, node, certificate in
            #expect(certificate.presented == 2, "The server must present its certificate with a meta certificate, as derper does")
            #expect(certificate.certName?.hasPrefix("sha256-raw:") == true)
            _ = try await running(node)
            let network = try await tool.command(.init(cmd: "networkStatus"), expecting: "networkStatus")
            #expect((network.derpConnections ?? 0) >= 1)
            // Like Go (`hostnameInSNI`), the Network framework does not send SNI for an IP literal server name (`127.0.0.1`).
            #expect(network.derpServerNames == [""])
        }
    }

    /// Three servers the client should reject. A `/derp` request appears if validation incorrectly accepts any of them.
    /// - `wrongPin`: The pin is not the server certificate's hash.
    /// - `leafNotFirst`: A server without the pinned certificate's key presents its own key's `derpkey…` certificate first and the pinned certificate afterward.
    ///   The Go client accepts it (verified by running it in independent review). Swiftail requires the pinned certificate to be first.
    /// - `named`: `CertName` differs from `HostName`, and the server certificate is self-signed and untrusted by the system. Even with `InsecureForTests`
    ///   enabled, `CertName` validation takes precedence.
    @Test("Swift node only: an unacceptable certificate disconnects during TLS and no /derp request is sent", arguments: ["wrongPin", "leafNotFirst", "named"])
    func rejected(mode: String) async throws {
        try await withSwiftOnlyNode(mode: mode) { tool, node, certificate in
            #expect(certificate.presented == (mode == "named" ? 1 : 2))
            var last: GoTailnet.Event?
            // The second attempt occurs only after the first fails and backs off. If validation incorrectly succeeds, a /derp request appears first.
            try await netstackWait("Two DERP TLS attempts by the Swift node", seconds: 30) {
                last = try await tool.command(.init(cmd: "networkStatus"), expecting: "networkStatus")
                return (last?.derpTLSHandshakes ?? 0) >= 2 || (last?.derpConnections ?? 0) > 0
            }
            let network = try #require(last)
            #expect(network.derpConnections == 0, "TLS validation should disconnect before any HTTP upgrade request")
            #expect(await node.status.state != .running)
            #expect(network.derpServerNames == [""])
        }
    }

    /// The Network framework does not send SNI for a server name with a trailing dot. Go strips the dot before sending, and derper's manual certificate
    /// mode rejects SNI that differs from its own name. Strip the dot before passing the name through.
    @Test("Swift node only: a hostName with a trailing dot is sent as SNI without the dot")
    func dottedHostNameSendsServerName() async throws {
        try await withSwiftOnlyNode(mode: "dottedHostName") { tool, node, _ in
            _ = try await running(node)
            let network = try await tool.command(.init(cmd: "networkStatus"), expecting: "networkStatus")
            #expect((network.derpConnections ?? 0) >= 1)
            #expect(network.derpServerNames == ["localhost"])
        }
    }
}

/// Starts the tool and one Swift node without Go peers. Changes the DERP certificate to `mode` before the first control request.
private func withSwiftOnlyNode(
    mode: String, _ body: (GoTailnet, TailnetNode, GoTailnet.Event) async throws -> Void
) async throws {
    let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-m8-\(UUID().uuidString)")
    let tool = GoTailnet(temporaryDirectory: directory)
    defer {
        if FileManager.default.fileExists(atPath: directory.path) {
            do { try FileManager.default.removeItem(at: directory) }
            catch { Issue.record("Could not clean up the M8 state directory: \(redacted(String(describing: error)))") }
        }
    }
    var run: Task<Void, any Error>?
    do {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let ready = try await tool.start()
        let certificate = try await tool.command(.init(cmd: "setDERPCertificate", mode: mode), expecting: "derpCertificate")
        let node = try TailnetNode(configuration: .init(stateDirectory: directory, hostname: "rd-mac-1a2b3c4d",
                                                      controlURL: try #require(ready.controlURL)), device: .memory())
        run = Task { try await node.run() }
        try await body(tool, node, certificate)
        run?.cancel()
        await tool.stop()
        _ = await run?.result
    } catch {
        run?.cancel()
        await tool.stop()
        _ = await run?.result
        throw GateFailure("\(redacted(String(describing: error)))\n\(await tool.diagnostics())")
    }
}
