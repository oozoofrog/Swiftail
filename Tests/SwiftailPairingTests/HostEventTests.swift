// `PairingHost.events`: 짝 목록과 제안의 변화. 비밀 없이 짝·StableID·제안의 상태만 싣는다.
//
// 제안을 열려면 노드에 자기 FQDN이 있어야 하므로 netmap을 직접 적용한다. 짝이 되는 흐름은 노드 하나가 자기 주소로
// 들어오는 쪽과 여는 쪽을 함께 맡는다(`Tests/SwiftailLoopbackTests/BridgeTestSupport.swift`와 같은 방식).

import CryptoKit
import Foundation
import SwiftailControl
import SwiftailEngine
import Synchronization
import Testing
@testable import Swiftail
@testable import SwiftailPairing

@Suite("여는 쪽의 사건", .timeLimit(.minutes(1)))
struct HostEventTests {
    /// 자기 노드(`rd-mac-1a2b3c4d`, `100.64.0.1`)만 있는 netmap. 사용자 프로필이 있어 `whoIs`가 자기 신원을 준다.
    private static func netmap() throws -> Netmap {
        let key = "nodekey:" + [UInt8](repeating: 0x11, count: 32).hex
        let selfNode = #"{"ID":1,"StableID":"nStableSelf","Name":"\#(Sample.host).","User":101,"#
            + #""Key":"\#(key)","Addresses":["100.64.0.1/32"],"MachineAuthorized":true}"#
        let json = #"{"Node":\#(selfNode),"Peers":[],"UserProfiles":[{"ID":101,"LoginName":"alice@example.com"}],"#
            + #""Domain":"tail0001.ts.net"}"#
        let response = try JSONDecoder().decode(MapResponse.self, from: Data(json.utf8))
        var session = MapSession()
        return try #require(try session.apply(response, receivedAt: Date()).netmap)
    }

    private static func configuration(_ directory: URL) throws -> NodeConfiguration {
        NodeConfiguration(
            stateDirectory: directory.appending(path: "node"), hostname: "rd-mac-1a2b3c4d",
            controlURL: try #require(URL(string: "http://127.0.0.1:9")))
    }

    /// 빈 임시 디렉터리를 만들어 넘기고, 끝나면 지운다.
    private static func withDirectory<T>(_ body: (URL) async throws -> T) async throws -> T {
        let directory = Sample.temporaryDirectory()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        return try await body(directory)
    }

    /// `run()` 없이 netmap만 적용한 `.inProcess` 노드 위의 여는 쪽. 제안을 열 수 있고 `run()`이 듣기를 시작할 수 있다.
    private static func host(in directory: URL, decide: @escaping @Sendable (PairingRequest) async -> Bool = { _ in false })
        async throws -> PairingHost
    {
        let node = try TailnetNode(configuration: try configuration(directory), device: .inProcess)
        await node.apply(try netmap())
        return try await PairingHost(node: node, port: Sample.port, storeDirectory: directory.appending(path: "store"), decide: decide)
    }

    /// 흐름이 끝날 때까지 읽는다.
    private static func drain(_ events: AsyncStream<PairingHost.Event>) async -> [PairingHost.Event] {
        var seen: [PairingHost.Event] = []
        for await event in events { seen.append(event) }
        return seen
    }

    // MARK: 제안

    @Test("제안을 열고 닫으면 opened·closed가 나온다. 열린 제안이 없을 때 닫으면 아무것도 나오지 않는다")
    func openAndClose() async throws {
        try await Self.withDirectory { directory in
            let host = try await Self.host(in: directory)
            var events = host.events.makeAsyncIterator()
            await host.closeOffer()
            _ = try await host.openOffer()
            await host.closeOffer()
            await host.closeOffer()
            _ = try await host.openOffer()
            #expect(await events.next() == .offerChanged(.opened))
            #expect(await events.next() == .offerChanged(.closed))
            #expect(await events.next() == .offerChanged(.opened))
        }
    }

    @Test("run() 동안 쓰이지 않은 제안은 만료 시각에 expired가 나온다. 새 제안을 열면 그 만료 시각을 따른다")
    func expires() async throws {
        try await Self.withDirectory { directory in
            let host = try await Self.host(in: directory)
            var events = host.events.makeAsyncIterator()
            let running = Task { try await host.run() }
            defer { running.cancel() }
            // 긴 제안에 맞춰 잠든 타이머가 짧은 새 제안으로 다시 깨어나야 한다.
            _ = try await host.openOffer(lifetime: .seconds(600))
            _ = try await host.openOffer(lifetime: .seconds(1))
            let started = ContinuousClock.now
            #expect(await events.next() == .offerChanged(.opened))
            #expect(await events.next() == .offerChanged(.opened))
            #expect(await events.next() == .offerChanged(.expired))
            #expect(ContinuousClock.now - started < .seconds(5))
            // 만료된 제안은 지워졌으니 닫아도 closed가 나오지 않는다.
            await host.closeOffer()
            _ = try await host.openOffer()
            #expect(await events.next() == .offerChanged(.opened))
        }
    }

    @Test("들어오는 쪽이 제안을 쓰면 used, 승인해 저장하면 pairedPeerAdded가 차례로 나온다")
    func pairs() async throws {
        try await Self.withDirectory { directory in
            let node = try TailnetNode(configuration: try Self.configuration(directory), device: .inProcess)
            let stopping = Mutex(false)
            let run = Task {
                do throws(NodeError) {
                    try await node.run()
                } catch {
                    if !stopping.withLock({ $0 }) { Issue.record("시험 중에 run()이 끝났다: \(error)") }
                }
            }
            defer {
                stopping.withLock { $0 = true }
                run.cancel()
            }
            while await !node.isRunning { try await Task.sleep(for: .milliseconds(10)) }
            await node.prepareForPairingTesting(try Self.netmap())

            let host = try await PairingHost(
                node: node, port: Sample.port, storeDirectory: directory.appending(path: "store")) { _ in true }
            var events = host.events.makeAsyncIterator()
            let serving = Task { try await host.run() }
            defer { serving.cancel() }
            let offer = try await host.openOffer()
            let paired = try await PairingJoiner.pair(with: offer, deviceName: "rd-phone-5e6f7a8b", node: node)
            #expect(paired.stableID == "nStableSelf")

            #expect(await events.next() == .offerChanged(.opened))
            #expect(await events.next() == .offerChanged(.used))
            guard case .pairedPeerAdded(let peer) = await events.next() else {
                Issue.record("pairedPeerAdded가 아니다")
                return
            }
            #expect(peer.peer.stableID == "nStableSelf")
            #expect(peer.deviceName == "rd-phone-5e6f7a8b")
            #expect(await host.pairedPeers == [peer])
        }
    }

    // MARK: 짝 목록

    @Test("짝을 지우면 pairedPeerRemoved가 나온다. 없는 짝을 지우면 나오지 않는다")
    func removes() async throws {
        try await Self.withDirectory { directory in
            let store = directory.appending(path: "store")
            try FileManager.default.createDirectory(
                at: store, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let record = #"{"stableID":"nEXAMPLEJOINER","name":"rd-phone-5e6f7a8b.tail0001.ts.net","#
                + #""computedName":"rd-phone-5e6f7a8b","loginName":"alice@example.com","deviceName":"rd-phone-5e6f7a8b","#
                + #""pairedAt":1900000000}"#
            try Data(#"{"version":1,"peers":[\#(record)]}"#.utf8).write(to: store.appending(path: "paired-peers.json"))
            let node = try TailnetNode(configuration: try Self.configuration(directory), device: .inProcess)
            var host: PairingHost? = try await PairingHost(node: node, port: Sample.port, storeDirectory: store) { _ in false }
            let events = try #require(host).events

            try await host?.removePairedPeer(withStableID: "nUNKNOWN")
            try await host?.removePairedPeer(withStableID: "nEXAMPLEJOINER")
            try await host?.removePairedPeer(withStableID: "nEXAMPLEJOINER")
            host = nil
            #expect(await Self.drain(events) == [.pairedPeerRemoved(stableID: "nEXAMPLEJOINER")])
        }
    }

    // MARK: 버퍼

    @Test("읽지 않은 사건은 가장 새 것 64개만 남고, 여는 쪽이 사라지면 흐름이 끝난다")
    func bufferLimit() async throws {
        try await Self.withDirectory { directory in
            var host: PairingHost? = try await Self.host(in: directory)
            let events = try #require(host).events
            for _ in 0..<(PairingHost.eventBufferLimit + 10) { _ = try await host?.openOffer() }
            await host?.closeOffer()
            host = nil
            let seen = await Self.drain(events)
            #expect(seen.count == PairingHost.eventBufferLimit)
            #expect(seen.last == .offerChanged(.closed))
            #expect(seen.dropLast().allSatisfy { $0 == .offerChanged(.opened) })
        }
    }
}

private extension TailnetNode {
    /// 등록을 거치지 않고 엔진을 만들고 netmap을 적용한 뒤 상태를 `.running`으로 만든다. 자기 주소로 건 연결은 엔진이
    /// 되돌려 같은 노드가 받는다.
    func prepareForPairingTesting(_ netmap: Netmap) {
        engine = TailnetEngine(nodeKey: Curve25519.KeyAgreement.PrivateKey(), discoKey: .zero, now: .now, wallClock: Date())
        apply(netmap)
        announce(stateMachine.connected())
    }
}
