// M2 final gate. Registers as an ephemeral node with the production control server to check differences from testcontrol.
//
// Runs only with an ephemeral auth key supplied by the owner. Reads the key from a file instead of an environment variable to keep it out of process listings and
// logs. Output contains only counts and Booleans. It omits real tailnet names, device names, addresses, and keys.
//
//   SWIFTAIL_REAL_AUTHKEY_FILE=<file-containing-the-key> eyebuild swift m1-gate -- test --filter RealTailnetGateTests

import Foundation
import SwiftailBase
import Testing

@testable import SwiftailControl

private let realAuthKeyFile = ProcessInfo.processInfo.environment["SWIFTAIL_REAL_AUTHKEY_FILE"].flatMap { $0.isEmpty ? nil : $0 }
private let realStateDirectory = ProcessInfo.processInfo.environment["SWIFTAIL_REAL_STATE_DIR"].flatMap { $0.isEmpty ? nil : $0 }

@Suite("M2 final gate: Production control server", .enabled(if: realAuthKeyFile != nil,
    "Skipping because SWIFTAIL_REAL_AUTHKEY_FILE is missing"), .timeLimit(.minutes(5)))
struct RealTailnetGateTests {
    @Test("Registers as an ephemeral node, receives an uncompressed netmap, and holds the connection for 90 seconds")
    func registerAndHoldMapStream() async throws {
        let path = try #require(realAuthKeyFile)
        let authKey = try String(contentsOfFile: path, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
        try #require(!authKey.isEmpty, "Auth key file is empty")
        let controlURL = try #require(URL(string: "https://controlplane.tailscale.com"))
        let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-real-gate-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }

        let client = ControlClient(
            configuration: .init(serverURL: controlURL, hostname: "swiftail-gate", authKey: authKey, ephemeral: true),
            identityStore: NodeIdentityStore(directory: directory)
        )
        let running = Task<ControlError?, Never> {
            do { try await client.run(); return nil }
            catch let error as ControlError { return error }
            catch { return .connection("Unexpected run error") }
        }
        defer { running.cancel() }

        let started = ContinuousClock.now
        let hold = Duration.seconds(90)

        let observing = Task { () -> (Bool, Int, Int, Netmap?) in
            var registered = false
            var netmaps = 0
            var disconnects = 0
            var first: Netmap?
            for await event in client.events {
                switch event {
                case .loginRequired:
                    return (registered, netmaps, -1, first)   // Interactive login required after auth key registration failed
                case .registered:
                    registered = true
                case .netmap(let netmap):
                    netmaps += 1
                    if first == nil { first = netmap }
                case .disconnected:
                    disconnects += 1
                }
                if first != nil, started.duration(to: .now) >= hold { break }
            }
            return (registered, netmaps, disconnects, first)
        }
        // If the map is quiet, no events arrive and the loop above does not end. End run after the hold interval to close the stream.
        try await Task.sleep(for: hold + .seconds(5))
        running.cancel()
        let (didRegister, netmapCount, disconnectCount, netmap) = await observing.value
        let failure = await running.value

        if let failure {
            Issue.record("run() ended with an error: \(redacted(String(describing: failure)))")
        }
        // Tailnet lock diagnostics. Check only the state reported by the server in the last map session and omit hash values.
        let serverLock = await client.lockSession.server
        print("Final gate diagnostics: server reports lock enabled \(serverLock.isEnabled), head present \(serverLock.head != nil)")
        #expect(disconnectCount != -1, "Interactive login was required because the auth key was not accepted")
        #expect(didRegister, "Registration did not complete")
        let map = try #require(netmap, "Did not receive a netmap (the server may not have sent an uncompressed map response)")
        #expect(disconnectCount == 0, "The map stream did not stay open")

        let tailnetV4 = try #require(IPPrefix("100.64.0.0/10"))
        #expect(map.selfNode.addresses.contains { $0.address.isIPv4 && tailnetV4.contains($0.address) })
        #expect(map.selfNode.machineAuthorized)
        let regionCount = map.derpMap?.regions?.count ?? 0
        #expect(regionCount > 0, "The production DERPMap is empty")

        print("""
            Final gate summary (counts and Booleans only):
              registered \(didRegister), \(netmapCount) netmap events, \(disconnectCount) disconnects, hold \(hold)
              \(map.selfNode.addresses.count) own addresses, \(map.peers.count) peers, \(regionCount) DERP regions
              DNSConfig \(map.dnsConfig != nil), \(map.packetFilter.count) filter rules, \(map.userProfiles.count) user profiles
              tailnet lock \(map.tailnetLock.mode), \(map.tailnetLock.filteredPeerCount) filtered peers, server time present \(map.controlTime != nil), self key expiry present \(map.selfNode.keyExpiry != nil)
            """)
    }
}

/// Preceding step for M8 gate (b). Checks whether the production server accepts a node registered with pre-tailnet-lock Swiftail (registration request `NLKey` was 0)
/// when it reconnects with current Swiftail after filling in a new NL key in the same identity file. This is the upgrade path for existing users.
///
/// Create the state directory by registering once with the pre-M8 commit (`6f30600`), using an auth key and an ephemeral node. Supply no auth key here.
/// If the server already removed the node, a new registration would bypass the upgrade path, so let a login requirement expose that case.
///
///   SWIFTAIL_REAL_STATE_DIR=<state-directory-registered-with-the-old-commit> eyebuild swift m1-gate -- test --filter RealTailnetUpgradeTests
@Suite("Step before M8 gate (b): Upgrading an old identity", .enabled(if: realStateDirectory != nil,
    "Skipping because SWIFTAIL_REAL_STATE_DIR is missing"), .timeLimit(.minutes(3)))
struct RealTailnetUpgradeTests {
    @Test("A node registered without an NL key reconnects with one and receives a netmap")
    func identityWithoutLockKeyReconnects() async throws {
        let directory = URL(filePath: try #require(realStateDirectory), directoryHint: .isDirectory)
        let store = NodeIdentityStore(directory: directory)
        let before = try String(contentsOf: store.fileURL, encoding: .utf8)
        try #require(!before.contains("NLKey"), "The identity file already has an NL key. This is not the upgrade path")
        let previous = try #require(try store.load()?.nodePublicKey, "The old identity has no node key")
        let controlURL = try #require(URL(string: "https://controlplane.tailscale.com"))

        let client = ControlClient(
            configuration: .init(serverURL: controlURL, hostname: "swiftail-gate", authKey: nil, ephemeral: true),
            identityStore: store
        )
        let running = Task<ControlError?, Never> {
            do { try await client.run(); return nil }
            catch let error as ControlError { return error }
            catch { return .connection("Unexpected run error") }
        }
        defer { running.cancel() }

        let observing = Task { () -> (loginRequired: Bool, registered: NodePublicKey?, netmap: Netmap?, disconnects: Int) in
            var registered: NodePublicKey?
            var netmap: Netmap?
            var disconnects = 0
            for await event in client.events {
                switch event {
                case .loginRequired: return (true, registered, netmap, disconnects)
                case .registered(let key): registered = key
                case .netmap(let map): netmap = netmap ?? map
                case .disconnected: disconnects += 1
                }
            }
            return (false, registered, netmap, disconnects)
        }
        try await Task.sleep(for: .seconds(30))
        running.cancel()
        let outcome = await observing.value
        if let failure = await running.value {
            Issue.record("run() ended with an error: \(redacted(String(describing: failure)))")
        }

        #expect(!outcome.loginRequired, "Server required login: The old node was already removed or the server does not accept registration with a changed NL key")
        #expect(outcome.registered == previous, "Did not register with the same node key")
        let map = try #require(outcome.netmap, "Did not receive a netmap")
        #expect(outcome.disconnects == 0, "The map stream did not stay open")
        #expect(map.selfNode.machineAuthorized)
        let after = try String(contentsOf: store.fileURL, encoding: .utf8)
        #expect(after.contains("NLKey"), "The identity file did not store the NL key")

        print("""
            Upgrade gate summary (counts and Booleans only):
              login required \(outcome.loginRequired), registered with the same node key \(outcome.registered == previous), \(outcome.disconnects) disconnects
              \(map.peers.count) peers, tailnet lock \(map.tailnetLock.mode), NL key stored \(after.contains("NLKey"))
            """)
    }
}
