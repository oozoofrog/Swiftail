// `PairingHost.events` reports paired peer list and offer changes. Events carry only the paired peer, StableID, or offer state and contain no secrets.
//
// Apply the netmap directly because a node needs its own FQDN to open an offer. To pair, a single node uses its own address
// and acts as both joiner and host, as in `Tests/SwiftailLoopbackTests/BridgeTestSupport.swift`.

import CryptoKit
import Foundation
import SwiftailControl
import SwiftailEngine
import Synchronization
import Testing
@testable import Swiftail
@testable import SwiftailPairing

@Suite("Host events", .timeLimit(.minutes(1)))
struct HostEventTests {
    /// A netmap with only the local node (`rd-mac-1a2b3c4d`, `100.64.0.1`). The user profile lets `whoIs` return the node's own identity.
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

    /// Creates and passes an empty temporary directory, then removes it when done.
    private static func withDirectory<T>(_ body: (URL) async throws -> T) async throws -> T {
        let directory = Sample.temporaryDirectory()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        return try await body(directory)
    }

    /// A host on an `.inProcess` node with the netmap applied and no `run()` call. The host can open offers, and `run()` can start listening.
    private static func host(in directory: URL, decide: @escaping @Sendable (PairingRequest) async -> Bool = { _ in false })
        async throws -> PairingHost
    {
        let node = try TailnetNode(configuration: try configuration(directory), device: .inProcess)
        await node.apply(try netmap())
        return try await PairingHost(node: node, port: Sample.port, storeDirectory: directory.appending(path: "store"), decide: decide)
    }

    /// Reads the stream until it ends.
    private static func drain(_ events: AsyncStream<PairingHost.Event>) async -> [PairingHost.Event] {
        var seen: [PairingHost.Event] = []
        for await event in events { seen.append(event) }
        return seen
    }

    // MARK: Offers

    @Test("Opening and closing an offer emits opened and closed. Closing without an open offer emits nothing")
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

    @Test("During run(), an unused offer emits expired at expiration. A new offer uses its own expiration time")
    func expires() async throws {
        try await Self.withDirectory { directory in
            let host = try await Self.host(in: directory)
            var events = host.events.makeAsyncIterator()
            let running = Task { try await host.run() }
            defer { running.cancel() }
            // The timer sleeping for the long-lived offer must wake again for the new short-lived offer.
            _ = try await host.openOffer(lifetime: .seconds(600))
            let offer = try await host.openOffer(lifetime: .seconds(2))
            #expect(await events.next() == .offerChanged(.opened))
            #expect(await events.next() == .offerChanged(.opened))
            #expect(await events.next() == .offerChanged(.expired))
            let lateness = Date().timeIntervalSince(offer.expires)
            #expect((0...0.5).contains(lateness))
            // Expiration removes the offer, so closing emits no closed event.
            await host.closeOffer()
            _ = try await host.openOffer()
            #expect(await events.next() == .offerChanged(.opened))
        }
    }

    /// Applies the netmap to a running `.inProcess` node and passes it to `body`. The same node receives connections to its own address, so one node
    /// can complete the entire pairing flow.
    private static func withRunningNode<T>(_ directory: URL, _ body: (TailnetNode) async throws -> T) async throws -> T {
        let node = try TailnetNode(configuration: try configuration(directory), device: .inProcess)
        let stopping = Mutex(false)
        let run = Task {
            do throws(NodeError) {
                try await node.run()
            } catch {
                if !stopping.withLock({ $0 }) { Issue.record("run() ended during the test: \(error)") }
            }
        }
        defer {
            stopping.withLock { $0 = true }
            run.cancel()
        }
        while await !node.isRunning { try await Task.sleep(for: .milliseconds(10)) }
        await node.prepareForPairingTesting(try netmap())
        return try await body(node)
    }

    @Test("The used event is already in the stream when decide is called for that connection")
    func usedPrecedesDecide() async throws {
        try await Self.withDirectory { directory in
            try await Self.withRunningNode(directory) { node in
                // The decide closure needs to read the host's stream, and the host takes decide at initialization. Pass the stream after initialization.
                let stream = Mutex<AsyncStream<PairingHost.Event>?>(nil)
                let seenInDecide = Mutex<[PairingHost.Event]?>(nil)
                let host = try await PairingHost(
                    node: node, port: Sample.port, storeDirectory: directory.appending(path: "store")
                ) { _ in
                    guard let events = stream.withLock({ $0 }) else { return false }
                    // Check that `.used` is read before decide returns. Cancel the read after 5 seconds to bound the wait.
                    let reader = Task {
                        var seen: [PairingHost.Event] = []
                        for await event in events {
                            seen.append(event)
                            if event == .offerChanged(.used) { break }
                        }
                        return seen
                    }
                    let watchdog = Task {
                        try await Task.sleep(for: .seconds(5))
                        reader.cancel()
                    }
                    let seen = await reader.value
                    watchdog.cancel()
                    seenInDecide.withLock { $0 = seen }
                    return true
                }
                stream.withLock { $0 = host.events }
                let serving = Task { try await host.run() }
                defer { serving.cancel() }
                let offer = try await host.openOffer()
                _ = try await PairingJoiner.pair(with: offer, deviceName: "rd-phone-5e6f7a8b", node: node)

                #expect(seenInDecide.withLock { $0 } == [.offerChanged(.opened), .offerChanged(.used)])
            }
        }
    }

    @Test("The joiner using the offer emits used, then approval and storage emit pairedPeerAdded")
    func pairs() async throws {
        try await Self.withDirectory { directory in
            try await Self.withRunningNode(directory) { node in
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
                    Issue.record("Expected pairedPeerAdded")
                    return
                }
                #expect(peer.peer.stableID == "nStableSelf")
                #expect(peer.deviceName == "rd-phone-5e6f7a8b")
                #expect(await host.pairedPeers == [peer])
            }
        }
    }

    // MARK: Paired peer list

    @Test("Removing a paired peer emits pairedPeerRemoved. Removing a missing paired peer emits nothing")
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

    // MARK: Subscription

    @Test("Canceling the consuming Task ends the stream. Subscribing again yields no events")
    func cancellingTheConsumerEndsTheStream() async throws {
        try await Self.withDirectory { directory in
            let host = try await Self.host(in: directory)
            let consumer = Task {
                var seen: [PairingHost.Event] = []
                for await event in host.events { seen.append(event) }
                return seen
            }
            consumer.cancel()
            #expect(await consumer.value.isEmpty)

            // Events cannot reach the ended stream. A new subscription uses the same stream and ends immediately.
            _ = try await host.openOffer()
            var again = host.events.makeAsyncIterator()
            #expect(await again.next() == nil)
        }
    }

    // MARK: Buffer

    @Test("Only the 64 newest unread events remain, and the stream ends when the host goes away")
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
    /// Creates the engine without registering, applies the netmap, and sets the state to `.running`. The engine loops connections to its own address back
    /// to the same node.
    func prepareForPairingTesting(_ netmap: Netmap) {
        engine = TailnetEngine(nodeKey: Curve25519.KeyAgreement.PrivateKey(), discoKey: .zero, now: .now, wallClock: Date())
        apply(netmap)
        announce(stateMachine.connected())
    }
}
