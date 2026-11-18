// M8 Tailnet Lock gate (a) (items 1–11 under "Gate (a): Without an Account" in docs/contracts/SwiftailTailnetLock.md §7).
// Uses the testcontrol copy and Go tsnet peers without an account to check end-to-end whether a Swift node (`TailnetNode`) reaches the same
// decisions as Go nodes on a tailnet with lock enabled. `Tools/interop/cmd/tailnet/lock_test.go` covers the same flow between Go peers.
//
// Cases this server cannot verify and the tests omit (also listed in the report):
// - Item 7: Recreate a "reconnected stream" by restarting the node with the same state directory. The tool has no command to close just the map stream, and a node whose
//   automatic maps stopped after injection does not receive them after reconnecting (README `injectMapResponse`). The tool cannot restart Go peers,
//   so decisions after reconnecting are not compared with Go.
// - Item 9: This server deletes the old key entry when it accepts the re-signed key rotation. "The Go peer drops the old key as obsolete" is checked
//   only as "the new key is visible and the old key is not." `peerSets` in `tkafixtures` covers the obsolete-key decision itself.
// - Item 10: The server sends a new map when restoring a broken bootstrap, so an outside observer cannot tell whether recovery came from the retry timer (initially 5 seconds)
//   or the new netmap. Only elapsed time is recorded.
// - Go nodes leave lock off and do not filter after a broken bootstrap (Swiftail fails closed with `.unverified`, an intentional difference in decisions U1 and L4).
//
// Item 7 checks whether both Swift and Go rerun bootstrap and disable lock when the server switches to the correct disablement secret
// and resends a map with identical content. If work remains, Swift retries the procedure on non-KeepAlive map responses even with identical content (5cde854).

import Foundation
import SwiftailBase
import SwiftailControl
import Testing

@testable import Swiftail

@Suite("M8 gate (a): Tailnet Lock", .enabled(if: tailnetBinary != nil,
    "Skipping the M8 Tailnet Lock gate because SWIFTAIL_TAILNET is missing"), .serialized, .timeLimit(.minutes(10)))
struct TailnetLockTests {
    @Test("Items 1, 2, 3, 5, and 6: bootstrap, lockout before signing, communication after signing, unsigned Go peers, and chain growth")
    func signingFlow() async throws {
        try await withLockGate { gate in
            let peers = try await enableLock(gate, alsoSigned: ["go-peer-b"])
            let a = try #require(peers["go-peer-a"]), b = try #require(peers["go-peer-b"])
            let swift = try gate.startNode("swift-s")

            // Item 1: bootstrap. The head matches the signing device's head (the server's head), and the registration request's NLKey is nonzero.
            let locked = try await gate.wait(swift, "Items 1 and 2: locked in enforcing mode") {
                $0.state == .running && $0.tailnetLock.mode == .enforcing && $0.tailnetLock.signingRequest != nil
            }
            let signer = try await gate.lockStatus("go-peer-a")
            #expect(locked.tailnetLock.head != nil && locked.tailnetLock.head == signer.head, "Item 1: the head matches the Go signing device")
            #expect(signer.head == signer.controlHead, "Item 1: the signing device is at the server head")
            #expect(locked.tailnetLock.issue == nil)
            let selfKey = try #require(await swift.selfKey)
            gate.name(selfKey, "swift-s")
            let registration = try #require(try await gate.registrations().last { $0.nodeKey == selfKey })
            #expect(!registration.nlKey.isEmpty, "Item 1: the registration request has a nonzero NLKey")
            #expect(try await gate.tkaRequestCount("bootstrap", from: selfKey) >= 1, "Item 1: a bootstrap RPC was sent")

            // Item 2: lockout before signing.
            let request = try #require(locked.tailnetLock.signingRequest)
            #expect(request.nodeKey == selfKey, "Item 2: signingRequest.nodeKey is the registered node key")
            #expect(request.lockKey == registration.nlKey, "Item 2: signingRequest.lockKey is the registered NL key")
            try expectLockBeforeRunning(swift, "Item 2")
            for name in ["go-peer-a", "go-peer-b"] {
                let go = try await gate.lockStatus(name)
                #expect(go.filteredPeers?.contains(selfKey) == true, "Item 2: \(name) filters the Swift node")
                #expect(go.visiblePeers?.contains(selfKey) == false)
            }
            #expect(await swift.peerKeys == [a.key, b.key], "Item 2: the two signed Go peers remain in the Swift netmap")
            try await gate.expectAgreement(swift, with: "go-peer-a", "Item 2")
            try await gate.expectSilent("Item 2: locked Swift → go-peer-a UDP echo") {
                try await gate.udpEcho(from: swift, to: a, within: LockGate.silence)
            }
            try await gate.expectSilent("Item 2: go-peer-a → locked Swift UDP") {
                try await gate.goSend("go-peer-a", to: swift, proto: "udp", within: LockGate.silence)
            }

            // Item 3: passing both values verbatim as strings to lockSign unlocks the node without a restart (F2 requirements 3 and 4).
            let signedAt = swift.recorder.events.count
            _ = try await gate.command(.init(cmd: "lockSign", name: "go-peer-a", nodeKey: request.nodeKey, lockKey: request.lockKey),
                                       expecting: "lockSign")
            try await gate.wait(swift, "Item 3: signingRequest is nil") {
                $0.tailnetLock.mode == .enforcing && $0.tailnetLock.signingRequest == nil
            }
            let unlocked = swift.recorder.events.dropFirst(signedAt).contains {
                if case let .tailnetLockChanged(lock) = $0.event { lock.signingRequest == nil } else { false }
            }
            #expect(unlocked, "Item 3: tailnetLockChanged with nil signingRequest appeared in the same run")
            try await netstackWait("Item 3: Swift node in the netmaps of both Go peers", seconds: 30) {
                for name in ["go-peer-a", "go-peer-b"] {
                    guard try await gate.lockStatus(name).visiblePeers?.contains(selfKey) == true else { return false }
                }
                return true
            }
            try await gate.expectAgreement(swift, with: "go-peer-a", "Item 3")
            try await gate.expectReachable("Item 3: Swift → go-peer-a UDP echo") { try await gate.udpEcho(from: swift, to: a, within: LockGate.reachable) }
            try await gate.expectReachable("Item 3: Swift → go-peer-b UDP echo") { try await gate.udpEcho(from: swift, to: b, within: LockGate.reachable) }
            try await gate.expectReachable("Item 3: Swift SYN → go-peer-a SYN-ACK") { try await gate.tcpHandshake(from: swift, to: a, within: LockGate.reachable) }
            try await gate.expectReachable("Item 3: go-peer-a → Swift UDP") { try await gate.goSend("go-peer-a", to: swift, proto: "udp", within: LockGate.reachable) }
            try await gate.expectReachable("Item 3: go-peer-a → Swift TCP SYN") { try await gate.goSend("go-peer-a", to: swift, proto: "tcp", within: LockGate.reachable) }

            // Item 5: unsigned Go peer.
            let filteredBefore = await swift.status.tailnetLock.filteredPeerCount
            let c = try await gate.addPeer("go-peer-c")
            try await gate.wait(swift, "Item 5: filters go-peer-c") { $0.tailnetLock.filteredPeerCount == filteredBefore + 1 }
            #expect(await !swift.peerKeys.contains(c.key), "Item 5: the unsigned peer is absent from Swift peers")
            try await gate.expectAgreement(swift, with: "go-peer-a", "Item 5")
            try await gate.expectReachable("Item 5 (control): go-peer-a → Swift UDP") { try await gate.goSend("go-peer-a", to: swift, proto: "udp", within: LockGate.reachable) }
            try await gate.expectSilent("Item 5: go-peer-c → Swift UDP") { try await gate.goSend("go-peer-c", to: swift, proto: "udp", within: LockGate.silence) }
            try await gate.expectSilent("Item 5: go-peer-c → Swift TCP SYN") { try await gate.goSend("go-peer-c", to: swift, proto: "tcp", within: LockGate.silence) }
            try await gate.expectSilent("Item 5: Swift → go-peer-c UDP echo") { try await gate.udpEcho(from: swift, to: c, within: LockGate.silence) }

            // Item 6: the chain grows. Add b's key, have b sign e, then remove b's key and see e removed with it.
            let bLock = try #require(try await gate.lockStatus("go-peer-b").lockKey)
            let added = try await gate.command(.init(cmd: "lockModify", name: "go-peer-a", addKeys: [bLock]), expecting: "lockModify")
            try await gate.wait(swift, "Item 6: catches up to the head that added the key") { $0.tailnetLock.head == added.head }
            try await gate.expectAgreement(swift, with: "go-peer-a", "Item 6: after adding the key")
            try await netstackWait("Item 6: go-peer-b reaches a head that trusts its own key", seconds: 30) {
                let status = try await gate.lockStatus("go-peer-b")
                return status.head == status.controlHead && status.trustedKeys?.contains(bLock) == true
            }
            let e = try await gate.addPeer("go-peer-e")
            try await gate.wait(swift, "Item 6: filters go-peer-e before signing") { $0.tailnetLock.filteredPeerCount == filteredBefore + 2 }
            _ = try await gate.command(.init(cmd: "lockSign", name: "go-peer-b", nodeKey: e.key), expecting: "lockSign")
            try await netstackWait("Item 6: go-peer-e is visible after b signs it", seconds: 30) { await swift.peerKeys.contains(e.key) }
            try await gate.expectAgreement(swift, with: "go-peer-a", "Item 6: after b signs")
            try await gate.expectReachable("Item 6: Swift → go-peer-e UDP echo") { try await gate.udpEcho(from: swift, to: e, within: LockGate.reachable) }
            let removed = try await gate.command(.init(cmd: "lockModify", name: "go-peer-a", removeKeys: [bLock]), expecting: "lockModify")
            try await gate.wait(swift, "Item 6: catches up to the head that removed the key") { $0.tailnetLock.head == removed.head }
            try await gate.expectAgreement(swift, with: "go-peer-a", "Item 6: after removing the key")
            #expect(await !swift.peerKeys.contains(e.key), "Item 6: Swift drops the peer signed only by the removed key")
            #expect(try await gate.lockStatus("go-peer-a").filteredPeers?.contains(e.key) == true, "Item 6: Go also drops the peer")
            try await gate.expectSilent("Item 6: Swift → go-peer-e UDP echo after removing the key") {
                try await gate.udpEcho(from: swift, to: e, within: LockGate.silence)
            }
        }
    }

    @Test("Item 4: registering with a signed auth key avoids lockout from the start")
    func wrappedAuthKey() async throws {
        try await withLockGate { gate in
            let peers = try await enableLock(gate)
            let a = try #require(peers["go-peer-a"])
            // Test-only auth key (testcontrol does not require one). The wrapped result contains a private key, so never print it.
            let wrapped = try #require(try await gate.command(
                .init(cmd: "lockWrapAuthKey", name: "go-peer-a", authKey: "tskey-auth-tl10gate0001"), expecting: "lockWrapAuthKey").authKey)
            let swift = try gate.startNode("swift-w", authKey: wrapped)
            let joined = try await gate.wait(swift, "Item 4: enforcing and at the server head") {
                $0.state == .running && $0.tailnetLock.mode == .enforcing && $0.tailnetLock.head != nil
            }
            let signer = try await gate.lockStatus("go-peer-a")
            #expect(joined.tailnetLock.head == signer.controlHead, "Item 4: caught up to the server head after the chain grew")
            #expect(joined.tailnetLock.signingRequest == nil)
            #expect(swift.recorder.lockChanges.allSatisfy { $0.signingRequest == nil }, "Item 4: the node was never locked out")
            try expectLockBeforeRunning(swift, "Item 4")
            let selfKey = try #require(await swift.selfKey)
            gate.name(selfKey, "swift-w")
            let mine = try await gate.registrations().filter { $0.nodeKey == selfKey }
            #expect(!mine.isEmpty)
            #expect(mine.first?.signature == "accepted", "Item 4: Go accepted the request signature")
            #expect(mine.allSatisfy { !$0.wrappedKeyTrace }, "Item 4: the request body has no trace of the wrapped private key")
            #expect(mine.allSatisfy { !$0.nlKey.isEmpty })
            try await gate.expectAgreement(swift, with: "go-peer-a", "Item 4")
            #expect(signer.filteredPeers?.contains(selfKey) != true)
            try await gate.expectReachable("Item 4: Swift → go-peer-a UDP echo") { try await gate.udpEcho(from: swift, to: a, within: LockGate.reachable) }
            try await gate.expectReachable("Item 4: go-peer-a → Swift UDP") { try await gate.goSend("go-peer-a", to: swift, proto: "udp", within: LockGate.reachable) }
        }
    }

    @Test("Item 7: lockDisable stays enforcing with the wrong secret, and disables lock and removes the file with the correct secret")
    func disableWithSecret() async throws {
        try await withLockGate { gate in
            _ = try await enableLock(gate, alsoSigned: ["go-peer-b"])
            let swift = try await joinAndSign(gate, "swift-s")
            let selfKey = try #require(await swift.selfKey)
            let c = try await gate.addPeer("go-peer-c")
            try await netstackWait("Item 7: filters go-peer-c", seconds: 30) {
                try await gate.lockStatus("go-peer-b").filteredPeers?.contains(c.key) == true
            }
            try await gate.expectAgreement(swift, with: "go-peer-b", "Item 7: before disabling")
            #expect(FileManager.default.fileExists(atPath: swift.lockFile.path), "Item 7: tailnet-lock.cbor exists before disabling")

            // Wrong secret: the server disables lock, but the node still enforces it.
            let bootstraps = try await gate.tkaRequestCount("bootstrap", from: selfKey)
            let wrong = try await gate.command(.init(cmd: "lockDisable", name: "go-peer-a", wrongSecret: true), expecting: "lockDisable")
            #expect(wrong.alreadyDisabled == false)
            try await netstackWait("Item 7: Swift node requests bootstrap after lock is disabled to fetch the secret", seconds: 30) {
                try await gate.tkaRequestCount("bootstrap", from: selfKey) > bootstraps
            }
            try await netstackWait("Item 7: go-peer-b also receives the wrong secret", seconds: 30) {
                let status = try await gate.lockStatus("go-peer-b")
                return status.controlDisabled == true && status.enabled == true
            }
            // Allow secret verification to finish (Argon2i, about 2 seconds in debug), and check that state stays the same during and afterward.
            try await gate.holds(swift, "Item 7: remains enforcing after the wrong secret", seconds: 6) {
                $0.tailnetLock.mode == .enforcing && $0.tailnetLock.filteredPeerCount == 1
            }
            #expect(FileManager.default.fileExists(atPath: swift.lockFile.path), "Item 7: the file remains after the wrong secret")
            #expect(await !swift.peerKeys.contains(c.key))
            #expect(try await gate.lockStatus("go-peer-b").filteredPeers?.contains(c.key) == true, "Item 7: Go still filters c")
            try await gate.expectAgreement(swift, with: "go-peer-b", "Item 7: after the wrong secret")
            try await gate.expectSilent("Item 7: go-peer-c → Swift UDP after the wrong secret") {
                try await gate.goSend("go-peer-c", to: swift, proto: "udp", within: LockGate.silence)
            }

            // Correct secret: lock is disabled, the unsigned peer is visible again, and the file is gone. The server already has lock disabled, so the tool changes only
            // the secret bootstrap will return and sends a new map (README `alreadyDisabled` for `lockDisable`). That map has the same content as the previous one.
            let goKey = try #require(try await gate.lockStatus("go-peer-b").nodeKey)
            let goFrom = try await gate.tkaRequestCount("bootstrap", from: goKey)
            let swiftFrom = try await gate.tkaRequestCount("bootstrap", from: selfKey)
            let right = try await gate.command(.init(cmd: "lockDisable", name: "go-peer-a"), expecting: "lockDisable")
            #expect(right.alreadyDisabled == true)
            // Check Go's decision first. It receives the identical map, calls bootstrap again, and disables lock using the correct secret
            // (ipnlocal `tkaSyncIfNeeded` runs on each map response: controlclient/map.go:240, ipnlocal/local.go:2034).
            try await netstackWait("Item 7: go-peer-b calls bootstrap again after the identical map", seconds: 30) {
                try await gate.tkaRequestCount("bootstrap", from: goKey) > goFrom
            }
            try await netstackWait("Item 7: go-peer-b disables lock and sees c", seconds: 30) {
                guard try await gate.lockStatus("go-peer-b").enabled == false else { return false }
                let seen = try await gate.command(.init(cmd: "peerStatus", name: "go-peer-b"), expecting: "peerStatus").peers ?? []
                return seen.contains { $0.nodeKey == c.key }
            }
            // The Swift node received the same map at the same time. If it retried, its request would arrive around the same time as Go's. Allow 2 more seconds.
            try await Task.sleep(for: .seconds(2))
            let swiftRetries = try await gate.tkaRequestCount("bootstrap", from: selfKey) - swiftFrom
            let stuck = gate.describe(await swift.status)
            #expect(swiftRetries > 0, """
                Item 7: On the identical map announcing the correct secret, Go reruns the disablement procedure (bootstrap) and disables lock, while the Swift node \
                does not retry (\(swiftRetries) bootstrap calls, \(stuck))
                """)
            if swiftRetries == 0 {
                // Isolate the cause by checking whether a map with different content (a new peer) triggers a retry and disables lock. This also lets the post-disablement checks continue.
                _ = try await gate.addPeer("go-peer-y")
                try await gate.wait(swift, "Item 7 (isolating the cause): .disabled after a map with different content") { $0.tailnetLock.mode == .disabled }
                await gate.tool.checkpoint("Item 7 (isolating the cause): an identical map does not trigger a retry, and a map with different content disables lock")
            } else {
                try await gate.wait(swift, "Item 7: .disabled after the correct secret") { $0.tailnetLock.mode == .disabled }
            }
            try await netstackWait("Item 7: Swift node sees c", seconds: 30) { await swift.peerKeys.contains(c.key) }
            #expect(!FileManager.default.fileExists(atPath: swift.lockFile.path), "Item 7: tailnet-lock.cbor is absent after disabling lock")
            #expect(swift.recorder.lockChanges.last?.mode == .disabled, "Item 7: tailnetLockChanged reported the change to .disabled")
            try await gate.expectReachable("Item 7: go-peer-c → Swift UDP after disabling lock") {
                try await gate.goSend("go-peer-c", to: swift, proto: "udp", within: LockGate.reachable)
            }
            try await gate.expectReachable("Item 7: Swift → go-peer-c UDP echo after disabling lock") {
                try await gate.udpEcho(from: swift, to: c, within: LockGate.reachable)
            }
        }
    }

    @Test("Item 7: a response without TKAInfo leaves state unchanged mid-stream and starts disablement if it is the first response on a reconnected stream")
    func disableWithoutTKAInfo() async throws {
        try await withLockGate { gate in
            _ = try await enableLock(gate, alsoSigned: ["go-peer-b"])
            let swift = try await joinAndSign(gate, "swift-s")
            let other = try await joinAndSign(gate, "swift-t", hostname: "rd-mac-5e6f7a8b")
            let selfKey = try #require(await swift.selfKey)
            let c = try await gate.addPeer("go-peer-c")
            for node in [swift, other] {
                try await gate.wait(node, "Item 7: filters go-peer-c") { $0.tailnetLock.filteredPeerCount == 1 }
            }

            // Mid-stream injection (server lock is enabled): a response without TKAInfo leaves state unchanged. Because the injected node stops receiving automatic maps
            // afterward (README `injectMapResponse`), inject into another Swift node. Injecting the node's own Node omits KeySignature and
            // locks it out (the injection helper's Node lacks the field), so inject a response that changes only the packet filter.
            let before = await other.status.tailnetLock
            let otherKey = try #require(await other.selfKey)
            let filterBefore = await other.node.lastNetmap?.packetFilter
            try await gate.tool.inject(.init(PacketFilter: [.init(SrcIPs: ["100.64.254.10/32"], IPProto: [17],
                                                                  DstPorts: [.init(IP: "*", Ports: .init(First: 9, Last: 9))])]),
                                       into: otherKey)
            try await netstackWait("Item 7: injected response is applied", seconds: 25) {
                let filter = await other.node.lastNetmap?.packetFilter
                return filter != nil && filter != filterBefore
            }
            #expect(await other.status.tailnetLock == before, "Item 7: a mid-stream injected response without TKAInfo leaves lock state unchanged")

            // The server disables lock and omits TKAInfo. The Swift node and Go peers on the existing streams keep filtering.
            _ = try await gate.command(.init(cmd: "lockDisable", name: "go-peer-a", omitTKAInfo: true), expecting: "lockDisable")
            #expect(try await gate.lockStatus("go-peer-b").controlDisabled == true)
            let x = try await gate.addPeer("go-peer-x")
            try await gate.wait(swift, "Item 7: still filters the new peer on a map sent after the server disabled lock") { $0.tailnetLock.filteredPeerCount == 2 }
            #expect(await swift.status.tailnetLock.mode == .enforcing, "Item 7: a mid-stream response without TKAInfo does not disable lock")
            #expect(FileManager.default.fileExists(atPath: swift.lockFile.path))
            try await netstackWait("Item 7: go-peer-b also keeps lock enabled and filters x", seconds: 30) {
                let status = try await gate.lockStatus("go-peer-b")
                return status.enabled == true && status.filteredPeers?.contains(x.key) == true
            }
            try await gate.expectAgreement(swift, with: "go-peer-b", "Item 7: after the server disabled lock without TKAInfo")

            // If the first response on a reconnected stream (restart with the same state directory) lacks TKAInfo, it starts the disablement procedure.
            let bootstraps = try await gate.tkaRequestCount("bootstrap", from: selfKey)
            await swift.stop()
            let restarted = try gate.startNode("swift-s")
            try await gate.wait(restarted, "Item 7: .disabled after reconnecting") { $0.state == .running && $0.tailnetLock.mode == .disabled }
            try await netstackWait("Item 7: unsigned c and x are visible", seconds: 30) {
                let keys = await restarted.peerKeys
                return keys.contains(c.key) && keys.contains(x.key)
            }
            #expect(!FileManager.default.fileExists(atPath: restarted.lockFile.path), "Item 7: tailnet-lock.cbor is absent after disabling lock")
            #expect(try await gate.tkaRequestCount("bootstrap", from: selfKey) > bootstraps, "Item 7: received the disablement secret via bootstrap")
            try await gate.expectReachable("Item 7: go-peer-c → Swift UDP after disabling lock") {
                try await gate.goSend("go-peer-c", to: restarted, proto: "udp", within: LockGate.reachable)
            }
        }
    }

    @Test("Items 8 and 9: restart from saved state without bootstrap (sync any chain growth in the meantime), node key rotation, and re-signing")
    func restartAndRotation() async throws {
        try await withLockGate { gate in
            let peers = try await enableLock(gate, alsoSigned: ["go-peer-b"])
            let a = try #require(peers["go-peer-a"]), b = try #require(peers["go-peer-b"])
            let first = try await joinAndSign(gate, "swift-s")
            let selfKey = try #require(await first.selfKey)
            let c = try await gate.addPeer("go-peer-c")
            try await gate.wait(first, "Item 8: filters go-peer-c") { $0.tailnetLock.filteredPeerCount == 1 }
            let head = try #require(await first.status.tailnetLock.head)
            let nlKey = try #require(try await gate.registrations().last { $0.nodeKey == selfKey }?.nlKey)
            let bootstraps = try await gate.tkaRequestCount("bootstrap", from: selfKey)
            let registered = try await gate.registrations().count { $0.nodeKey == selfKey }

            // Item 8 ①: if the chain is unchanged, filter immediately with the same head.
            await first.stop()
            let second = try gate.startNode("swift-s")
            try await gate.wait(second, "Item 8: filters with the same head after restart") {
                $0.state == .running && $0.tailnetLock.mode == .enforcing && $0.tailnetLock.head == head && $0.tailnetLock.signingRequest == nil
            }
            try expectStoredStateFromStart(second, signedPeers: [a.key, b.key], stage: "Item 8 ①")
            #expect(second.recorder.lockChanges.first?.head == head, "Item 8: initial lock state has the saved head")
            #expect(await !second.peerKeys.contains(c.key))
            #expect(try await gate.tkaRequestCount("bootstrap", from: selfKey) == bootstraps, "Item 8: no bootstrap RPC after restart")
            let afterSecond = try await gate.registrations().filter { $0.nodeKey == selfKey }
            #expect(afterSecond.count > registered, "Item 8: the restarted node sent a registration")
            #expect(afterSecond.allSatisfy { $0.nlKey == nlKey }, "Item 8: same NL key")
            try await gate.expectAgreement(second, with: "go-peer-a", "Item 8 ①")

            // Item 8 ②: if the chain grows while stopped, sync catches up from the saved state.
            await second.stop()
            let bLock = try #require(try await gate.lockStatus("go-peer-b").lockKey)
            let grown = try await gate.command(.init(cmd: "lockModify", name: "go-peer-a", addKeys: [bLock]), expecting: "lockModify")
            #expect(grown.head != head)
            let offers = try await gate.tkaRequestCount("sync/offer", from: selfKey)
            let third = try gate.startNode("swift-s")
            try await gate.wait(third, "Item 8 ②: catches up to the newer head") {
                $0.state == .running && $0.tailnetLock.mode == .enforcing && $0.tailnetLock.head == grown.head
            }
            try expectStoredStateFromStart(third, signedPeers: [a.key, b.key], stage: "Item 8 ②")
            #expect(try await gate.tkaRequestCount("bootstrap", from: selfKey) == bootstraps, "Item 8 ②: no bootstrap RPC")
            #expect(try await gate.tkaRequestCount("sync/offer", from: selfKey) > offers, "Item 8 ②: caught up via sync/offer")
            #expect(try await gate.registrations().filter { $0.nodeKey == selfKey }.allSatisfy { $0.nlKey == nlKey })
            try await gate.expectAgreement(third, with: "go-peer-a", "Item 8 ②")

            // Item 9: when the server requests re-signing, rotate to a new node key and have Go validate the re-signed request's signature.
            _ = try await gate.command(.init(cmd: "lockRequestResign", nodeKey: selfKey), expecting: "lockRequestResign")
            await third.stop()
            let fourth = try gate.startNode("swift-s")
            var rotated: GoTailnet.LockRegistration?
            try await netstackWait("Item 9: registration carrying the old key as OldNodeKey", seconds: 30) {
                rotated = try await gate.registrations().last { $0.oldNodeKey == selfKey }
                return rotated != nil
            }
            let rotation = try #require(rotated)
            #expect(rotation.signature == "accepted", "Item 9: Go accepted the re-signed request's signature (\(rotation.signatureError))")
            #expect(rotation.nlKey == nlKey, "Item 9: same NL key")
            #expect(try await gate.registrations().contains { $0.nodeKey == selfKey && $0.resignRequested }, "Item 9: the server requested re-signing")
            let newKey = rotation.nodeKey
            gate.name(newKey, "swift-s(new key)")
            #expect(newKey != selfKey)
            try await gate.wait(fourth, "Item 9: filters with the new key without being locked out") {
                $0.state == .running && $0.tailnetLock.mode == .enforcing && $0.tailnetLock.signingRequest == nil
            }
            #expect(await fourth.selfKey == newKey)
            try await netstackWait("Item 9: go-peer-a sees the new key and no longer sees the old key", seconds: 30) {
                let status = try await gate.lockStatus("go-peer-a")
                let all = Set(status.visiblePeers ?? []).union(status.filteredPeers ?? [])
                return status.visiblePeers?.contains(newKey) == true && !all.contains(selfKey)
            }
            try await gate.expectAgreement(fourth, with: "go-peer-a", "Item 9")
            try await gate.expectReachable("Item 9: Swift with the new key → go-peer-a UDP echo") {
                try await gate.udpEcho(from: fourth, to: a, within: LockGate.reachable)
            }
            try await gate.expectReachable("Item 9: go-peer-a → Swift with the new key UDP") {
                try await gate.goSend("go-peer-a", to: fourth, proto: "udp", within: LockGate.reachable)
            }
        }
    }

    @Test("Item 10: fails closed with .unverified and acquiringState for broken bootstrap, unreadableStoredState for a corrupt state file, and bootstraps again after the file is deleted")
    func closedSide() async throws {
        try await withLockGate { gate in
            let peers = try await enableLock(gate, alsoSigned: ["go-peer-b"])
            let a = try #require(peers["go-peer-a"])

            // Broken bootstrap. On the same server, the Go node cannot enable lock and does not filter (intentional difference, recorded only for comparison).
            // Add it before the Swift node. Adding it afterward would send a map that triggers one more Swift retry and lengthens the backoff interval.
            try await gate.setBootstrapFault(true)
            let f = try await gate.addPeer("go-peer-f")
            try await netstackWait("Item 10: go-peer-f attempts bootstrap", seconds: 30) {
                try await gate.tkaRequestCount("bootstrap", from: f.key) > 0
            }
            let goUnderFault = try await gate.lockStatus("go-peer-f")
            #expect(goUnderFault.enabled == false, "Item 10 (control): Go does not enable lock with broken bootstrap")

            // The Swift node adds no peers.
            let swift = try gate.startNode("swift-s")
            let closed = try await gate.wait(swift, "Item 10: .unverified with broken bootstrap") {
                $0.state == .running && $0.tailnetLock.mode == .unverified
            }
            let selfKey = try #require(await swift.selfKey)
            gate.name(selfKey, "swift-s")
            #expect(closed.tailnetLock.issue == .acquiringState, "Item 10: issue is .acquiringState")
            let closedPeers = await swift.peerKeys
            #expect(closed.peerCount == 0 && closedPeers.isEmpty, "Item 10: peers is empty")
            let others = try await gate.registeredKeys().subtracting([selfKey])
            #expect(closed.tailnetLock.filteredPeerCount == others.count, "Item 10: filteredPeerCount matches the number of peers advertised by the server")
            #expect(closed.tailnetLock.head == nil && closed.tailnetLock.signingRequest == nil)
            try await gate.expectSilent("Item 10: .unverified Swift → go-peer-a UDP echo") {
                try await gate.udpEcho(from: swift, to: a, within: LockGate.silence)
            }
            await gate.tool.checkpoint("Item 10: broken bootstrap — Swift .unverified and 0 peers, Go enabled=\(goUnderFault.enabled ?? false)")

            // Restoring bootstrap leads to .enforcing on the next retry. The retry interval starts at 5 seconds and doubles on each failure (TL-7, capped at 300 seconds).
            // The server sends an identical map on restoration (Go retries immediately on that map), so the Swift node waits for its timer.
            let failures = try await gate.tkaRequestCount("bootstrap", from: selfKey)
            #expect(failures >= 1)
            let backoff = min(5 * (1 << min(max(failures - 1, 0), 6)), 300)
            let restored = ContinuousClock.now
            try await gate.setBootstrapFault(false)
            let recovered = try await gate.wait(swift, "Item 10: .enforcing on the next retry after restoration (\(failures) failures, interval at most \(backoff) seconds)",
                                                seconds: backoff + 10) {
                $0.tailnetLock.mode == .enforcing && $0.tailnetLock.issue == nil
            }
            await gate.tool.checkpoint("""
                Item 10: \(restored.duration(to: .now).formatted(.units(allowed: [.milliseconds]))) to .enforcing after restoration \
                (\(failures) prior bootstrap failures, next interval at most \(backoff) seconds)
                """)
            let request = try #require(recovered.tailnetLock.signingRequest, "Item 10: still locked before signing")
            let controlHead = try await gate.lockStatus("go-peer-a").controlHead
            #expect(recovered.tailnetLock.head == controlHead, "Item 10: server head after restoration")
            try await gate.expectAgreement(swift, with: "go-peer-a", "Item 10: after restoration")
            _ = try await gate.command(.init(cmd: "lockSign", name: "go-peer-a", nodeKey: request.nodeKey, lockKey: request.lockKey),
                                       expecting: "lockSign")
            try await gate.wait(swift, "Item 10: unlocks after signing") { $0.tailnetLock.signingRequest == nil && $0.tailnetLock.mode == .enforcing }
            try await gate.expectReachable("Item 10: Swift → go-peer-a UDP echo after signing") {
                try await gate.udpEcho(from: swift, to: a, within: LockGate.reachable)
            }
            let nlKey = try #require(try await gate.registrations().last { $0.nodeKey == selfKey }?.nlKey)

            // Corrupt the saved file and restart to get .unverified and unreadableStoredState.
            await swift.stop()
            var stored = try Data(contentsOf: swift.lockFile)
            stored[stored.count / 2] ^= 0xff
            try stored.write(to: swift.lockFile)
            let broken = try gate.startNode("swift-s")
            let unreadable = try await gate.wait(broken, "Item 10: .unverified with a corrupt state file") {
                $0.state == .running && $0.tailnetLock.mode == .unverified
            }
            #expect(unreadable.tailnetLock.issue == .unreadableStoredState, "Item 10: issue is .unreadableStoredState")
            let brokenPeers = await broken.peerKeys
            #expect(unreadable.peerCount == 0 && brokenPeers.isEmpty, "Item 10: peers is empty")
            try await gate.holds(broken, "Item 10: a corrupt state file does not recover on its own", seconds: 7) {
                $0.tailnetLock.mode == .unverified && $0.tailnetLock.issue == .unreadableStoredState
            }
            try await gate.expectSilent("Item 10: Swift with a corrupt state file → go-peer-a UDP echo") {
                try await gate.udpEcho(from: broken, to: a, within: LockGate.silence)
            }

            // Deleting only the lock state file lets a new node bootstrap from scratch and unlock (same NL key, signature still valid).
            await broken.stop()
            try ControlClient.removeTailnetLockState(inDirectory: broken.directory)
            #expect(!FileManager.default.fileExists(atPath: broken.lockFile.path))
            let bootstraps = try await gate.tkaRequestCount("bootstrap", from: selfKey)
            let fresh = try gate.startNode("swift-s")
            try await gate.wait(fresh, "Item 10: bootstraps after deletion, reaches .enforcing, and is signed") {
                $0.state == .running && $0.tailnetLock.mode == .enforcing && $0.tailnetLock.signingRequest == nil && $0.tailnetLock.issue == nil
            }
            #expect(try await gate.tkaRequestCount("bootstrap", from: selfKey) > bootstraps, "Item 10: started with bootstrap")
            #expect(await fresh.selfKey == selfKey)
            #expect(try await gate.registrations().last { $0.nodeKey == selfKey }?.nlKey == nlKey, "Item 10: same NL key")
            try await gate.expectAgreement(fresh, with: "go-peer-a", "Item 10: after deletion")
            try await gate.expectReachable("Item 10: Swift → go-peer-a UDP echo after deletion") {
                try await gate.udpEcho(from: fresh, to: a, within: LockGate.reachable)
            }
        }
    }

    @Test("Item 11: a tailnet without lock stays .disabled and sends no TKA RPCs")
    func noLock() async throws {
        try await withLockGate(capability: false) { gate in
            let a = try await gate.addPeer("go-peer-a")
            let swift = try gate.startNode("swift-s")
            try await gate.wait(swift, "Item 11: running with one peer") { $0.state == .running && $0.peerCount == 1 }
            try await gate.expectReachable("Item 11: Swift → go-peer-a UDP echo") {
                try await gate.udpEcho(from: swift, to: a, within: LockGate.reachable)
            }
            #expect(await swift.status.tailnetLock == TailnetLockStatus(), "Item 11: mode is .disabled and other fields are at their defaults")
            #expect(swift.recorder.lockChanges.isEmpty, "Item 11: no tailnetLockChanged event")
            #expect(try await gate.tkaRequests().isEmpty, "Item 11: no TKA RPCs")

            // The same holds for a tailnet with only the capability and lock disabled (no TKAInfo).
            _ = try await gate.command(.init(cmd: "setLockCapability", enabled: true), expecting: "lockCapability")
            _ = try await gate.addPeer("go-peer-b")
            try await gate.wait(swift, "Item 11: map after adding the capability (two peers)") { $0.peerCount == 2 }
            try await gate.holds(swift, "Item 11: .disabled with only the capability", seconds: 3) { $0.tailnetLock.mode == .disabled }
            #expect(swift.recorder.lockChanges.isEmpty)
            #expect(try await gate.tkaRequests().isEmpty, "Item 11: no TKA RPCs with only the capability")
            #expect(try await gate.lockStatus("go-peer-a").enabled == false)
        }
    }
}

/// Enables lock by adding the signing device `go-peer-a` and any `alsoSigned` peers signed during enablement, then calling `lockInit`. Returns
/// after peers reach the server head and see that they are signed.
private func enableLock(_ gate: LockGate, alsoSigned: [String] = []) async throws -> [String: GatePeer] {
    var peers: [String: GatePeer] = [:]
    for name in ["go-peer-a"] + alsoSigned { peers[name] = try await gate.addPeer(name) }
    let started = try await gate.command(.init(cmd: "lockInit", name: "go-peer-a"), expecting: "lockInit")
    #expect(started.enabled == true && started.head == started.controlHead && started.nodeKeySigned == true)
    for name in alsoSigned {
        try await netstackWait("Enable lock: \(name) bootstraps and sees itself as signed", seconds: 45) {
            let status = try await gate.lockStatus(name)
            return status.enabled == true && status.head == status.controlHead && status.nodeKeySigned == true
        }
    }
    return peers
}

/// Starts a new Swift node, verifies it is locked, then unlocks it by passing both signing request values verbatim to `lockSign`.
private func joinAndSign(_ gate: LockGate, _ label: String, hostname: String = "rd-mac-1a2b3c4d") async throws -> LockNode {
    let node = try gate.startNode(label, hostname: hostname)
    let locked = try await gate.wait(node, "\(label): locked") {
        $0.state == .running && $0.tailnetLock.mode == .enforcing && $0.tailnetLock.signingRequest != nil
    }
    let request = try #require(locked.tailnetLock.signingRequest)
    gate.name(request.nodeKey, label)
    _ = try await gate.command(.init(cmd: "lockSign", name: "go-peer-a", nodeKey: request.nodeKey, lockKey: request.lockKey),
                               expecting: "lockSign")
    try await gate.wait(node, "\(label): unlocked after signing") { $0.tailnetLock.signingRequest == nil && $0.tailnetLock.mode == .enforcing }
    return node
}

/// F2 requirement 1: No gap between the first `.running` and lock information. For the same netmap, `tailnetLockChanged` precedes
/// `stateChanged(.running)`, and `status` read after receiving `.running` already has lock state.
private func expectLockBeforeRunning(_ node: LockNode, _ stage: String) throws {
    let entries = node.recorder.events
    let lockIndex = entries.firstIndex { if case .tailnetLockChanged = $0.event { true } else { false } }
    let runningIndex = try #require(entries.firstIndex { $0.event == .stateChanged(.running) }, "\(stage): .running event")
    #expect(lockIndex.map { $0 < runningIndex } == true, "\(stage): tailnetLockChanged comes before the first .running")
    #expect(entries[runningIndex].status.tailnetLock.mode != .disabled, "\(stage): status after .running contains lock state")
}

/// The restarted node filtered with the saved state from the start. It never emitted lock state with `.unverified` or `.disabled`, and
/// `status` after each event included no more peers than the signed peers.
private func expectStoredStateFromStart(_ node: LockNode, signedPeers: Set<String>, stage: String) throws {
    let changes = node.recorder.lockChanges
    #expect(!changes.isEmpty && changes.allSatisfy { $0.mode == .enforcing }, "\(stage): .enforcing from the start")
    #expect(node.recorder.events.allSatisfy { $0.status.peerCount <= signedPeers.count }, "\(stage): no unsigned peer was ever added")
    try expectLockBeforeRunning(node, stage)
}
