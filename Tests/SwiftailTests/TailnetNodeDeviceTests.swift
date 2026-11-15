import CryptoKit
import Darwin
import Foundation
import SwiftailBase
import SwiftailEngine
import Testing
@testable import Swiftail

/// 노드의 장치·시작 검사·끝내기. 계약 `docs/contracts/SwiftailTunnel.md` 동작 U·C 4·E 5, 공개 API.
@Suite("노드의 터널 장치")
struct TailnetNodeDeviceTests {
    // MARK: init의 검사 (동작 U1, C 4)

    @Test("utun이 아닌 기술자(-1, 파이프)는 init이 invalidConfiguration으로 거절하고 호출자의 기술자는 열려 있다")
    func rejectsNonUTUN() throws {
        var pipeDescriptors: [Int32] = [-1, -1]
        #expect(pipe(&pipeDescriptors) == 0)
        defer { pipeDescriptors.forEach { close($0) } }

        let configuration = try NodeTestSupport.unusedConfiguration()
        for descriptor in [Int32(-1), pipeDescriptors[0], pipeDescriptors[1]] {
            Self.expectInvalidConfiguration(containing: "utun", configuration, device: .utun(fileDescriptor: descriptor))
        }
        #expect(fcntl(pipeDescriptors[0], F_GETFD) >= 0)
        #expect(fcntl(pipeDescriptors[1], F_GETFD) >= 0)
    }

    @Test("범위 밖 MTU는 init이 invalidConfiguration으로 거절하고, 경계 값과 기본값은 받는다", arguments: [1, 1000, 1279, 1421, 1500, 9000, -1280])
    func rejectsMTU(mtu: Int) throws {
        let configuration = try NodeTestSupport.unusedConfiguration()
        Self.expectInvalidConfiguration(containing: "MTU", configuration, device: .memory(mtu: mtu))
        // 기술자 검사보다 MTU 검사가 먼저다(utun이 아니어도 MTU 메시지).
        Self.expectInvalidConfiguration(containing: "MTU", configuration, device: .utun(fileDescriptor: -1, mtu: mtu))
    }

    @Test("MTU 1280·1420·기본값은 받는다")
    func acceptsMTU() throws {
        for device in [TunnelDevice.memory(mtu: 1280), .memory(mtu: 1420), .memory()] {
            _ = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration(), device: device)
        }
    }

    @Test("설정 오류(파일 URL이 아닌 상태 디렉터리, http(s)가 아닌 제어 서버, 빈 호스트 이름)는 init이 거절한다")
    func rejectsConfiguration() throws {
        var notFile = try NodeTestSupport.unusedConfiguration()
        notFile.stateDirectory = try #require(URL(string: "https://example.com/state"))
        var wrongScheme = try NodeTestSupport.unusedConfiguration()
        wrongScheme.controlURL = try #require(URL(string: "ftp://127.0.0.1"))
        var noHost = try NodeTestSupport.unusedConfiguration()
        noHost.controlURL = try #require(URL(string: "https:///key"))
        var emptyHostname = try NodeTestSupport.unusedConfiguration()
        emptyHostname.hostname = ""
        for configuration in [notFile, wrongScheme, noHost, emptyHostname] {
            Self.expectInvalidConfiguration(containing: "", configuration, device: .memory())
        }
        #expect(NodeConfiguration(stateDirectory: URL(filePath: "/var/empty"), hostname: "h").controlURL
            == URL(string: "https://controlplane.tailscale.com"))
    }

    // MARK: 메모리 장치 (동작 U7, L)

    @Test("메모리 장치에서 서비스 IP로 보낸 MagicDNS 질의의 응답이 inboundPackets로 나온다")
    func magicDNSOverMemoryDevice() async throws {
        let node = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
        await node.installEngineForTesting()
        await node.apply(try NodeTestSupport.netmap())
        let selfAddress: [UInt8] = [100, 64, 0, 1], service: [UInt8] = [100, 100, 100, 100]
        let query = NodeTestSupport.dnsQuery(NodeTestSupport.selfName, type: 1, id: 0x5A5A)
        await node.send(NodeTestSupport.udp(from: selfAddress, 40001, to: service, 53, payload: query))
        await node.inboundContinuation.finish()

        let packets = await NodeTestSupport.drain(node.inboundPackets)
        let reply = try #require(packets.first)
        #expect(packets.count == 1)
        #expect(Array(reply[12..<16]) == service && Array(reply[16..<20]) == selfAddress, "주소가 맞바뀌어야 한다")
        #expect(Array(reply[20..<24]) == [0, 53, 0x9C, 0x41], "포트가 맞바뀌어야 한다(53 → 40001)")
        let dns = Array(reply[28...])
        #expect(Array(dns[0..<2]) == [0x5A, 0x5A])
        #expect(dns[2] & 0x80 != 0, "응답(QR)")
        #expect(dns[3] & 0x0F == 0, "NOERROR")
        #expect(Array(dns[6..<8]) == [0, 1], "답 하나")
        #expect(Array(dns.suffix(4)) == selfAddress, "A 레코드가 자기 주소")
    }

    @Test("failMemoryDevice()가 run()을 tunnelDeviceClosed(\"test\")로 끝내고 세 흐름이 끝난다")
    func failMemoryDeviceEndsRun() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            let node = try TailnetNode(configuration: try NodeTestSupport.configuration(stateDirectory: directory))
            let run = Task { try await node.run() }
            await node.failMemoryDevice()
            let result = await run.result
            guard case let .failure(error) = result, case .tunnelDeviceClosed("test")? = error as? NodeError else {
                Issue.record("기대 tunnelDeviceClosed(\"test\"), 실제 \(result)")
                return
            }
            _ = await NodeTestSupport.drain(node.events)
            _ = await NodeTestSupport.drain(node.networkSettings)
            _ = await NodeTestSupport.drain(node.inboundPackets)
            #expect(StateDirectoryClaims.shared.claim(directory), "끝난 노드는 상태 디렉터리를 놓는다")
            StateDirectoryClaims.shared.release(directory)
        }
    }

    @Test("run()을 취소하면 돌아오고 세 흐름이 끝나며, 다시 부르면 invalidConfiguration이다")
    func cancelEndsStreams() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            let node = try TailnetNode(configuration: try NodeTestSupport.configuration(stateDirectory: directory))
            let run = Task { try await node.run() }
            try await Task.sleep(for: .milliseconds(100))
            run.cancel()
            let result = await run.result
            guard case .success = result else {
                Issue.record("취소는 실패가 아니다: \(result)")
                return
            }
            _ = await NodeTestSupport.drain(node.events)
            _ = await NodeTestSupport.drain(node.networkSettings)
            _ = await NodeTestSupport.drain(node.inboundPackets)
            #expect(await node.path(toPeerNamed: "rd-phone-1a2b3c4d.tail0001.ts.net") == nil)
            #expect(await node.path(toPeerWithStableID: "n1234567890CNTRL") == nil)
            #expect(await node.path(toPeerWithStableID: "") == nil)
            do throws(NodeError) {
                try await node.run()
                Issue.record("두 번째 run()이 던지지 않았다")
            } catch {
                guard case .invalidConfiguration = error else {
                    Issue.record("기대 invalidConfiguration, 실제 \(error)")
                    return
                }
            }
        }
    }

    // MARK: 상태 (NodeStatus)

    @Test("status는 마지막 netmap의 자기 주소·이름·StableID·피어 수와 상태를 담는다")
    func status() async throws {
        let node = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
        let before = await node.status
        #expect(before.state == .starting && before.addresses.isEmpty && before.fqdn == nil && before.stableID == nil)
        #expect(before.peerCount == 0 && before.networkSettings == nil)

        await node.apply(try NodeTestSupport.netmap(
            addresses: ["100.64.0.1/32", "fd7a:115c:a1e0::1/128"], machineAuthorized: false, peerAddress: "100.64.0.2/32"))
        let after = await node.status
        #expect(after.state == .needsMachineAuth)
        #expect(after.addresses.map(\.description) == ["100.64.0.1", "fd7a:115c:a1e0::1"])
        #expect(after.fqdn == "rd-mac-1a2b3c4d.tail0001.ts.net")
        #expect(after.stableID == "nStable1")
        #expect(after.peerCount == 1)
        #expect(after.networkSettings?.mtu == 1280)
    }

    // MARK: DERP 송신 큐 (동작 M)

    @Test("DERP 송신 큐는 256개와 1MiB를 넘으면 오래된 것부터 버리고, 닫으면 끝난다")
    func derpOutboxBounds() async throws {
        let outbox = TailnetNode.DERPOutbox()
        let peer = try #require(NodePublicKey(rawValue: [UInt8](repeating: 0x22, count: 32)))
        for index in 0..<300 {
            outbox.push(TailnetNode.DERPDatagram(bytes: [UInt8(index & 0xFF)], peer: peer))
        }
        #expect(outbox.backlog.count == 256)
        #expect(await outbox.next()?.bytes == [UInt8(44)], "가장 오래된 44개가 버려졌다")

        let large = TailnetNode.DERPOutbox()
        for byte in UInt8(1)...3 {
            large.push(TailnetNode.DERPDatagram(bytes: [UInt8](repeating: byte, count: 400_000), peer: peer))
        }
        #expect(large.backlog.count == 2 && large.backlog.bytes == 800_000)
        #expect(await large.next()?.bytes.first == 2)
        large.close()
        #expect(await large.next() == nil)
        large.push(TailnetNode.DERPDatagram(bytes: [1], peer: peer))
        #expect(large.backlog.count == 0, "닫은 뒤에는 버린다")
    }

    private static func expectInvalidConfiguration(containing text: String, _ configuration: NodeConfiguration, device: TunnelDevice) {
        do throws(NodeError) {
            _ = try TailnetNode(configuration: configuration, device: device)
            Issue.record("invalidConfiguration을 던지지 않았다")
        } catch {
            guard case let .invalidConfiguration(message) = error, text.isEmpty || message.contains(text) else {
                Issue.record("기대 invalidConfiguration(\(text)), 실제 \(error)")
                return
            }
        }
    }
}

private extension TailnetNode {
    /// 등록을 거치지 않고 엔진만 만든다. 서비스 IP 응답은 엔진만 있으면 나온다.
    func installEngineForTesting() {
        engine = TailnetEngine(nodeKey: Curve25519.KeyAgreement.PrivateKey(), now: .now, wallClock: Date())
    }
}
