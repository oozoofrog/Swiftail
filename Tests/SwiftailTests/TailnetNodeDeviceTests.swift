import CryptoKit
import Darwin
import Foundation
import SwiftailBase
import SwiftailEngine
import Testing
@testable import Swiftail

/// Node device, startup validation, and shutdown. Contract `docs/contracts/SwiftailTunnel.md` behaviors U·C 4·E 5, public API.
@Suite("Node tunnel device")
struct TailnetNodeDeviceTests {
    // MARK: Initializer validation (behaviors U1, C 4)

    @Test("The initializer rejects non-utun descriptors (-1, pipe) with invalidConfiguration and leaves the caller's descriptor open")
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

    @Test("The initializer rejects an out-of-range MTU with invalidConfiguration and accepts the boundary values and the default", arguments: [1, 1000, 1279, 1421, 1500, 9000, -1280])
    func rejectsMTU(mtu: Int) throws {
        let configuration = try NodeTestSupport.unusedConfiguration()
        Self.expectInvalidConfiguration(containing: "MTU", configuration, device: .memory(mtu: mtu))
        // MTU validation precedes descriptor validation (the message is about MTU even for a non-utun descriptor).
        Self.expectInvalidConfiguration(containing: "MTU", configuration, device: .utun(fileDescriptor: -1, mtu: mtu))
    }

    @Test("Accepts MTU 1280, 1420, and the default")
    func acceptsMTU() throws {
        for device in [TunnelDevice.memory(mtu: 1280), .memory(mtu: 1420), .memory()] {
            _ = try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration(), device: device)
        }
    }

    @Test("The initializer rejects configuration errors (a non-file state directory URL, a control server outside http(s), and an empty hostname)")
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

    // MARK: Memory device (behaviors U7, L)

    @Test("The response to a MagicDNS query sent to the service IP on the memory device appears on inboundPackets")
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
        #expect(Array(reply[12..<16]) == service && Array(reply[16..<20]) == selfAddress, "Addresses must be swapped")
        #expect(Array(reply[20..<24]) == [0, 53, 0x9C, 0x41], "Ports must be swapped (53 → 40001)")
        let dns = Array(reply[28...])
        #expect(Array(dns[0..<2]) == [0x5A, 0x5A])
        #expect(dns[2] & 0x80 != 0, "Response (QR)")
        #expect(dns[3] & 0x0F == 0, "NOERROR")
        #expect(Array(dns[6..<8]) == [0, 1], "One answer")
        #expect(Array(dns.suffix(4)) == selfAddress, "The A record is the local address")
    }

    @Test("failMemoryDevice() ends run() with tunnelDeviceClosed(\"test\") and ends all three streams")
    func failMemoryDeviceEndsRun() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            let node = try TailnetNode(configuration: try NodeTestSupport.configuration(stateDirectory: directory))
            let run = Task { try await node.run() }
            await node.failMemoryDevice()
            let result = await run.result
            guard case let .failure(error) = result, case .tunnelDeviceClosed("test")? = error as? NodeError else {
                Issue.record("Expected tunnelDeviceClosed(\"test\"), got \(result)")
                return
            }
            _ = await NodeTestSupport.drain(node.events)
            _ = await NodeTestSupport.drain(node.networkSettings)
            _ = await NodeTestSupport.drain(node.inboundPackets)
            let claim = try #require(StateDirectoryClaims.shared.claim(directory), "A stopped node releases the state directory")
            StateDirectoryClaims.shared.release(claim)
        }
    }

    @Test("Canceling run() makes it return and ends all three streams. Calling it again yields invalidConfiguration")
    func cancelEndsStreams() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            let node = try TailnetNode(configuration: try NodeTestSupport.configuration(stateDirectory: directory))
            let run = Task { try await node.run() }
            try await Task.sleep(for: .milliseconds(100))
            run.cancel()
            let result = await run.result
            guard case .success = result else {
                Issue.record("Cancellation is not a failure: \(result)")
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
                Issue.record("The second run() did not throw")
            } catch {
                guard case .invalidConfiguration = error else {
                    Issue.record("Expected invalidConfiguration, got \(error)")
                    return
                }
            }
        }
    }

    // MARK: Status (NodeStatus)

    @Test("status contains the state and the latest netmap's local addresses, name, StableID, and peer count")
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

    // MARK: DERP send queue (behavior M)

    @Test("The DERP send queue drops the oldest entries first above the limits of 256 entries and 1MiB, and ends on close")
    func derpOutboxBounds() async throws {
        let outbox = TailnetNode.DERPOutbox()
        let peer = try #require(NodePublicKey(rawValue: [UInt8](repeating: 0x22, count: 32)))
        for index in 0..<300 {
            outbox.push(TailnetNode.DERPDatagram(bytes: [UInt8(index & 0xFF)], peer: peer))
        }
        #expect(outbox.backlog.count == 256)
        #expect(await outbox.next()?.bytes == [UInt8(44)], "The oldest 44 entries were dropped")

        let large = TailnetNode.DERPOutbox()
        for byte in UInt8(1)...3 {
            large.push(TailnetNode.DERPDatagram(bytes: [UInt8](repeating: byte, count: 400_000), peer: peer))
        }
        #expect(large.backlog.count == 2 && large.backlog.bytes == 800_000)
        #expect(await large.next()?.bytes.first == 2)
        large.close()
        #expect(await large.next() == nil)
        large.push(TailnetNode.DERPDatagram(bytes: [1], peer: peer))
        #expect(large.backlog.count == 0, "Discards entries after closing")
    }

    private static func expectInvalidConfiguration(containing text: String, _ configuration: NodeConfiguration, device: TunnelDevice) {
        do throws(NodeError) {
            _ = try TailnetNode(configuration: configuration, device: device)
            Issue.record("Did not throw invalidConfiguration")
        } catch {
            guard case let .invalidConfiguration(message) = error, text.isEmpty || message.contains(text) else {
                Issue.record("Expected invalidConfiguration(\(text)), got \(error)")
                return
            }
        }
    }
}

private extension TailnetNode {
    /// Create only the engine, without registering. The engine alone is enough to produce the service IP response.
    func installEngineForTesting() {
        engine = TailnetEngine(nodeKey: Curve25519.KeyAgreement.PrivateKey(), discoKey: .zero, now: .now, wallClock: Date())
    }
}
