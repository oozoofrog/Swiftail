import Foundation
import Swiftail
import SwiftailBase
import Testing

/// M8 ③: DERP 노드를 `InsecureForTests` 대신 `CertName: sha256-raw:<해시>`로 알린다(계약 `docs/contracts/SwiftailDERP.md`
/// "M8 ③" 시험과 관문). 도구의 DERP 서버는 derper의 IP 수동 인증서 모드와 같은 자체 서명 인증서에 meta 인증서를 붙여 낸다.
@Suite("M8 ③ DERP 인증서 고정 관문", .enabled(if: tailnetBinary != nil, "SWIFTAIL_TAILNET가 없어 M8 ③ 관문을 건너뜁니다"),
       .serialized, .timeLimit(.minutes(4)))
struct DERPCertificateTests {
    @Test("맞는 고정: Swift 노드가 고정한 DERP를 거쳐 Go 피어와 주고받는다")
    func pinnedRelay() async throws {
        try await withGate(direct: false, derpCertificate: "pinned") { gate in
            let nodes = try #require(await gate.tool.command(.init(cmd: "nodes"), expecting: "nodes").nodes)
            let fqdn = try #require(nodes.first { $0.nodeKey == gate.peer.key }?.name)
            // Go가 올린 UDP 후보 포트를 모두 막아 DERP로만 오가게 한다(`netstackPrepare`와 같은 방법).
            var ports: Set<UInt16> = []
            try await netstackWait("Go UDP 후보") {
                let status = try await gate.tool.command(.init(cmd: "peerStatus", name: "go-peer-a"), expecting: "peerStatus")
                ports = Set((status.selfAddrs ?? []).compactMap(IPEndpoint.init).map(\.port))
                return !ports.isEmpty
            }
            await gate.node.setBlockedUDPPorts(ports)
            try await netstackWait("DERP 경로의 UDP 에코") {
                try await gate.echo(payload: [0x4d, 0x38, 0x03])
                return await gate.node.path(toPeerNamed: fqdn) == .relayed(derpRegion: 1)
            }
            try await gate.echo(payload: [0x4d, 0x38, 0x04])
            #expect(await gate.node.path(toPeerNamed: fqdn) == .relayed(derpRegion: 1))
        }
    }

    /// Go 피어를 띄우지 않으므로 DERP 서버에 TLS로 오는 것은 Swift 노드뿐이다. 피어가 없으면 `running`은 홈 DERP 연결로만 온다.
    @Test("Swift 노드만: 맞는 고정이면 DERP가 붙어 running이 되고, 틀린 고정이면 TLS에서 끊겨 /derp 요청이 없다",
          arguments: ["pinned", "wrongPin"])
    func swiftOnly(mode: String) async throws {
        try await withSwiftOnlyNode(mode: mode) { tool, node in
            let network: GoTailnet.Event
            if mode == "pinned" {
                _ = try await running(node)
                network = try await tool.command(.init(cmd: "networkStatus"), expecting: "networkStatus")
                #expect((network.derpConnections ?? 0) >= 1)
            } else {
                var last: GoTailnet.Event?
                // 두 번째 시도는 첫 시도가 실패해 물러난 뒤에만 온다. 검증이 잘못 통과하면 /derp 요청이 먼저 보인다.
                try await netstackWait("Swift 노드의 DERP TLS 시도 두 번", seconds: 30) {
                    last = try await tool.command(.init(cmd: "networkStatus"), expecting: "networkStatus")
                    return (last?.derpTLSHandshakes ?? 0) >= 2 || (last?.derpConnections ?? 0) > 0
                }
                network = try #require(last)
                #expect(network.derpConnections == 0, "TLS 검증에서 끊겨 HTTP 업그레이드 요청이 없어야 한다")
                #expect(await node.status.state != .running)
            }
            // Network 프레임워크도 Go(`hostnameInSNI`)처럼 IP 리터럴 서버 이름(`127.0.0.1`)에는 SNI를 보내지 않는다.
            #expect(network.derpServerNames == [""])
        }
    }
}

/// Go 피어 없이 도구와 Swift 노드 하나를 띄운다. 첫 제어 요청 전에 DERP 인증서를 `mode`로 바꾼다.
private func withSwiftOnlyNode(
    mode: String, _ body: (GoTailnet, TailnetNode) async throws -> Void
) async throws {
    let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-m8-\(UUID().uuidString)")
    let tool = GoTailnet(temporaryDirectory: directory)
    defer {
        if FileManager.default.fileExists(atPath: directory.path) {
            do { try FileManager.default.removeItem(at: directory) }
            catch { Issue.record("M8 상태 디렉터리 정리 실패: \(redacted(String(describing: error)))") }
        }
    }
    var run: Task<Void, any Error>?
    do {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let ready = try await tool.start()
        let certificate = try await tool.command(.init(cmd: "setDERPCertificate", mode: mode), expecting: "derpCertificate")
        #expect(certificate.presented == 2, "derper처럼 서버 인증서와 meta 인증서를 함께 내야 한다")
        #expect(certificate.certName?.hasPrefix("sha256-raw:") == true)
        let node = try TailnetNode(configuration: .init(stateDirectory: directory, hostname: "rd-mac-1a2b3c4d",
                                                      controlURL: try #require(ready.controlURL)), device: .memory())
        run = Task { try await node.run() }
        try await body(tool, node)
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
