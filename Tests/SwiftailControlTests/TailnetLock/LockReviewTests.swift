// Regression tests for the independent review (TL-11b). Uses an untrusted control server threat model to examine the `ControlClient` tailnet lock procedure.
//
// The defects and contract issues found by the review were addressed by items 1–5 in contract `docs/contracts/SwiftailTailnetLock.md` §5, "Independent review fixes: Control procedure
// (TL-11b)." "Fix n" in the test names refers to that item. "Remaining behavior" refers to behavior that section left unchanged.
// The rest are fail-closed properties confirmed by the review.
//
// The test generates all keys on the spot.

import CryptoKit
import Foundation
import Testing

import SwiftailBase
@testable import SwiftailControl
@testable import SwiftailTKA

@Suite("Review: Control client tailnet lock", .timeLimit(.minutes(3)))
struct LockReviewTests {
    private typealias Server = LockFakeControlServer

    // MARK: Re-signing requests

    /// Fix 1: A server re-signing request does not become a signing oracle for the NL key.
    ///
    /// The server can put anything in `RegisterResponse.NodeKeySignature`. Without validation, when a chain holds more than 15 node keys,
    /// "trimming" creates new rotation signatures with the NL key for **`Pubkey` values chosen by the server** (Go `tka/sig.go:393-437`). If the server sends
    /// 15 layers of fake rotation over this node's genuine direct signature (created by the signing device with `tailscale lock sign <nodeKey> <lockKey>`),
    /// the returned registration request contained a chain authorizing the attacker's node key. The re-signing function now checks the NL key signature
    /// at every layer and throws, and the node registers without a signature.
    @Test("Fix 1: Does not sign a node key chosen by the server with the NL key (chain trimming for a re-signing request)")
    func resignRequestIsNotASigningOracle() async throws {
        let lock = RegistrationSigningTests.Lock()
        let identity = NodeIdentity(machineKey: .init(), nodeKey: .init())
        let ownKey = try #require(identity.nodePublicKey)
        // The genuine signature from the signing device for this node. The rotation key is this node's NL public key.
        let direct = try lock.directSignature(for: ownKey, wrappingKey: identity.lockPublicKey)
        // A node key whose private key is known only to the server (attacker).
        let attackerKey = LockTesting.newNodeKey()

        // 15 rotation layers with signatures filled with 0 over the genuine direct signature. The outermost `Pubkey` is the attacker's key.
        var forged = try NodeKeySignature(decoding: direct)
        for layer in 0..<15 {
            let key = layer == 14 ? attackerKey : LockTesting.newNodeKey()
            forged = NodeKeySignature(
                kind: NodeKeySignature.Kind.rotation, publicKey: key.binaryForm,
                signature: [UInt8](repeating: 0, count: 64), nested: forged
            )
        }
        // The chain sent by the server authorizes nothing on its own.
        #expect(throws: TKAError.unauthorized) { try lock.state.authorize(attackerKey, keySignature: forged.serialized()) }

        let server = try SetDNSFakeControlServer()
        defer { server.close() }
        let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-review-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = NodeIdentityStore(directory: directory)
        try store.save(identity)
        server.enqueueRegisterReply(#"{"NodeKeySignature":"\#(Data(forged.serialized()).base64EncodedString())"}"#)
        let url = try await server.start()
        let client = ControlClient(configuration: .init(serverURL: url, hostname: "rd-mac-1a2b3c4d"), identityStore: store)
        let running = Task { try await client.run() }
        defer { running.cancel() }
        try await server.wait("The map stream did not open") { !$0.openMapStreams.isEmpty }

        // The second registration request, sent in response to the re-signing request, uses a new node key and no signature (the node is locked out and a signing request appears).
        let requests = server.requests.filter { $0.path == "/machine/register" }
        #expect(requests.count == 2)
        let body = Data(try #require(requests.last).body)
        let second = try #require(try JSONSerialization.jsonObject(with: body) as? [String: Any])
        #expect(second["NodeKeySignature"] is NSNull, "Signed the server-supplied chain with the NL key and returned it")
        #expect(second["NodeKey"] as? String != ownKey.description)
        #expect(second["OldNodeKey"] as? String == ownKey.description)
        // No request contains an NL key signature for the attacker's node key. Inspect the signatures in every registration request sent to the server.
        for request in requests {
            let object = try #require(try JSONSerialization.jsonObject(with: Data(request.body)) as? [String: Any])
            guard let text = object["NodeKeySignature"] as? String, let bytes = Data(base64Encoded: text) else { continue }
            var current: NodeKeySignature? = try NodeKeySignature(decoding: [UInt8](bytes))
            while let signature = current {
                #expect(signature.publicKey != attackerKey.binaryForm)
                current = signature.nested
            }
        }
    }

}

extension LockDisablementTests {
    /// Fix 2: Remembers rejected disablement secrets in a set of 8 per head. With only one entry, alternating two secrets makes the client
    /// rerun Argon2i (16MiB) every time (behavior O6). The KDF blocks the actor.
    @Test("Fix 2: Even if the server alternates two wrong disablement secrets, the KDF runs only once per secret (behavior O6)")
    func alternatingDisablementSecrets() async throws {
        let world = try LockWorld()
        try await withEnforcingClient(world) { run, _ in
            let secrets = [[UInt8](repeating: 0x11, count: 32), [UInt8](repeating: 0x22, count: 32)]
            for round in 0..<4 {
                let domain = "round\(round).example"
                run.server.updateLock {
                    $0.authority = nil
                    $0.disablementSecret = secrets[round % 2]
                }
                run.server.push(LockTesting.mapJSON(lock: LockTesting.tkaDisabled, #""Domain":"\#(domain)""#))
                let netmap = try await run.latest("Netmap number \(round)") { $0.domain == domain }
                #expect(netmap.tailnetLock.mode == .enforcing)
            }
            let derivations = await run.client.disablementDerivationCount
            #expect(derivations == 2, "Reran the KDF with an already rejected secret")
        }
    }

    /// Limit for fix 2: Remembers up to 8. Rejecting a 9th forgets the oldest. A head change starts a fresh set.
    @Test("Fix 2: Remembers 8 rejections per head and forgets the oldest first when full")
    func rejectedDisablementCapacity() async throws {
        let world = try LockWorld()
        try await withEnforcingClient(world) { run, _ in
            var round = 0
            func disable(_ secret: [UInt8]) async throws {
                round += 1
                let domain = "round\(round).example"
                run.server.updateLock {
                    $0.authority = nil
                    $0.disablementSecret = secret
                }
                run.server.push(LockTesting.mapJSON(lock: LockTesting.tkaDisabled, #""Domain":"\#(domain)""#))
                let netmap = try await run.latest("Netmap number \(round)") { $0.domain == domain }
                #expect(netmap.tailnetLock.mode == .enforcing)
            }
            let secrets = (1...9).map { [UInt8](repeating: UInt8($0), count: 32) }
            for secret in secrets.prefix(8) { try await disable(secret) }
            #expect(await run.client.disablementDerivationCount == 8)
            // Remembers all eight.
            for secret in secrets.prefix(8).reversed() { try await disable(secret) }
            #expect(await run.client.disablementDerivationCount == 8)
            #expect(ControlClient.maximumRejectedDisablementCount == 8)
            // Rejecting the ninth forgets the first.
            try await disable(secrets[8])
            #expect(await run.client.disablementDerivationCount == 9)
            try await disable(secrets[1])
            #expect(await run.client.disablementDerivationCount == 9)
            try await disable(secrets[0])
            #expect(await run.client.disablementDerivationCount == 10, "Did not forget the oldest secret")
        }
    }

    // MARK: With local state

    /// Verified (pass): Once verified state is retained, no change to the server's lock report, failure in the procedure, or disconnect
    /// can emit an unsigned peer (ID 3) through `Event.netmap`.
    @Test("With local state, no server report, failure, or reconnection emits an unfiltered netmap")
    func serverCannotOpenAnEnforcingNode() async throws {
        let world = try LockWorld()
        try await withEnforcingClient(world) { run, _ in
            var step = 0
            /// Pushes one response and waits for a netmap reflecting it.
            func push(lock: String?, selfNode: String? = nil) async throws {
                step += 1
                let domain = "step\(step).example"
                run.server.push(LockTesting.mapJSON(selfNode: selfNode, lock: lock, #""Domain":"\#(domain)""#))
                _ = try await run.latest("Netmap for response number \(step)") { $0.domain == domain }
            }
            let bareSelf = LockTesting.selfJSON(key: world.selfKey, hasCapability: false)

            // Unreadable head, TKAInfo without a head, a different head, and a self node without capability.
            try await push(lock: #""TKAInfo":{"Head":"not-a-hash"}"#)
            try await push(lock: #""TKAInfo":{}"#)
            try await push(lock: LockTesting.tkaInfo(head: try LockWorld().head))
            try await push(lock: nil, selfNode: bareSelf)
            // Disabled report: No secret (empty value), failed bootstrap RPC, and failed synchronization.
            run.server.updateLock { $0.authority = nil }
            try await push(lock: LockTesting.tkaDisabled, selfNode: bareSelf)
            run.server.updateLock { $0.faults[Server.bootstrapPath] = .respond(status: 500, body: []) }
            try await push(lock: #""TKAInfo":{"Disabled":true,"Head":"not-a-hash"}"#)
            run.server.updateLock { $0.faults[Server.bootstrapPath] = .json("{}") }
            try await push(lock: LockTesting.tkaDisabled)

            // New map session: No TKAInfo, capability, or self signature from the start. The procedure's response is held until the connection drops.
            run.server.updateLock { $0.faults[Server.bootstrapPath] = .hold }
            run.server.setMapResponse(try world.map(
                selfSigned: false, hasCapability: false, lock: LockWorld.noTKAInfo, #""Domain":"reconnected.example""#
            ))
            let attempts = run.server.requests(to: Server.bootstrapPath).count
            run.server.dropConnections()
            try await eventually("Disablement procedure for the new session") { run.server.requests(to: Server.bootstrapPath).count > attempts }
            run.server.updateLock { $0.faults[Server.bootstrapPath] = .respond(status: 500, body: []) }
            run.server.setMapResponse(try world.map(
                selfSigned: false, hasCapability: false, lock: LockWorld.noTKAInfo, #""Domain":"again.example""#
            ))
            run.server.dropConnections()
            _ = try await run.latest("Netmap after reconnecting") { $0.domain == "again.example" }

            #expect(run.netmaps.allSatisfy { $0.tailnetLock.mode == .enforcing && $0.tailnetLock.head == world.head.text })
            #expect(run.netmaps.allSatisfy { !$0.peers.contains { $0.id == 3 } }, "Emitted an unsigned peer")
            #expect(await run.client.lockAuthority?.head == world.head)
            #expect(try TailnetLockStore(directory: run.directory).load()?.head == world.head)
        }
    }

}

extension LockReviewTests {
    // MARK: Without local state

    /// Head text Go accepts (by stripping the newline) and Swiftail rejects: 50 characters + CRLF (behavior D10).
    private static func goReadableHead(_ world: LockWorld) -> String {
        String(world.head.text.prefix(50)) + "\\r\\n"
    }

    /// Fix 3: If a server sends `TKAInfo` with no disabled marker and an unreadable `Head` to a node without local state, it means "enabled,
    /// head unknown." If capability is present, bootstrap and filter with that state. Previously it read "no lock" and emitted all peers,
    /// and with the newline in behavior D10, Go nodes filtered while Swiftail nodes did not.
    @Test("Fix 3: Receiving an unreadable Head without local state bootstraps and filters", arguments: ["not-a-hash", "goReadable"])
    func unreadableHeadWithoutLocalStateBootstraps(_ head: String) async throws {
        let world = try LockWorld()
        let text = head == "goReadable" ? Self.goReadableHead(world) : head
        try await withLockClient(world, prepare: { server, _ in
            server.updateLock { $0.authority = world.authority }
            server.setMapResponse(try world.map(lock: #""TKAInfo":{"Head":"\#(text)"}"#))
        }) { run in
            let netmap = try await run.latest("First netmap") { _ in true }
            #expect(netmap.tailnetLock == TailnetLockStatus(mode: .enforcing, head: world.head.text, filteredPeerCount: 1))
            #expect(netmap.peers.map(\.id) == [2, 4], "Emitted an unsigned peer (ID 3)")
            #expect(run.server.tkaPaths.first == Server.bootstrapPath)
            #expect(run.netmaps.allSatisfy { !$0.peers.contains { $0.id == 3 } })
        }
    }

    /// Fixes 3 and 4: If bootstrap fails with an unreadable head, the result is `.unverified` with reason "acquiring." Without capability, it skips
    /// filtering as Go does (first row of the N2 table).
    @Test("Fixes 3 and 4: Failed bootstrap with an unreadable Head yields .unverified (acquiring), and without capability it skips filtering")
    func unreadableHeadBootstrapFailure() async throws {
        let world = try LockWorld()
        let lock = #""TKAInfo":{"Head":"\#(Self.goReadableHead(world))"}"#
        try await withLockClient(world, prepare: { server, _ in
            server.updateLock {
                $0.authority = world.authority
                $0.faults[Server.bootstrapPath] = .respond(status: 500, body: [])
            }
            server.setMapResponse(try world.map(lock: lock))
        }) { run in
            let closed = try await run.latest("First netmap") { _ in true }
            #expect(closed.tailnetLock == TailnetLockStatus(mode: .unverified, filteredPeerCount: 3, issue: .acquiringState))
            #expect(closed.peers.isEmpty)
        }
        try await withLockClient(world, prepare: { server, _ in
            server.updateLock { $0.authority = world.authority }
            server.setMapResponse(try world.map(hasCapability: false, lock: lock))
        }) { run in
            let open = try await run.latest("First netmap") { _ in true }
            #expect(open.tailnetLock == TailnetLockStatus())
            #expect(run.server.tkaPaths.isEmpty)
        }
    }

    /// Fix 3: With local state, an unreadable head triggers synchronization (treat it as a different head). Even if synchronization fails, filter with the old state.
    @Test("Fix 3: With local state, an unreadable Head triggers synchronization")
    func unreadableHeadWithLocalStateSynchronizes() async throws {
        let world = try LockWorld()
        try await withEnforcingClient(world) { run, _ in
            let offers = run.server.requests(to: Server.syncOfferPath).count
            run.server.push(LockTesting.mapJSON(lock: #""TKAInfo":{"Head":"not-a-hash"}"#, #""Domain":"unreadable.example""#))
            let netmap = try await run.latest("netmap") { $0.domain == "unreadable.example" }
            #expect(netmap.tailnetLock == TailnetLockStatus(mode: .enforcing, head: world.head.text, filteredPeerCount: 1))
            #expect(run.server.requests(to: Server.syncOfferPath).count == offers + 1)
            #expect(run.server.requests(to: Server.bootstrapPath).count == 1, "Started the disablement procedure")
        }
    }

    /// Remaining behavior (§5, TL-11b): `.unverified` (owner decision U1) provides protection when the server is honest. While there is no local state, the server
    /// can release it just by changing its report to "disabled." Neither a disablement secret nor an RPC is required. This follows from TOFU for initial trust, as in Go.
    @Test("Remaining behavior: After failed bootstrap, .unverified clears without a secret when the server reports Disabled")
    func unverifiedIsReleasedByTheServersWord() async throws {
        let world = try LockWorld()
        try await withLockClient(world, prepare: { server, _ in
            server.updateLock {
                $0.authority = world.authority
                $0.faults[Server.bootstrapPath] = .respond(status: 500, body: [])
            }
            server.setMapResponse(try world.map())
        }) { run in
            let closed = try await run.latest("First netmap") { _ in true }
            #expect(closed.tailnetLock.mode == .unverified && closed.peers.isEmpty)

            run.server.push(LockTesting.mapJSON(lock: LockTesting.tkaDisabled))
            let open = try await run.latest("Netmap after Disabled") { $0.tailnetLock.mode == .disabled }
            #expect(open.peers.map(\.id) == [2, 3, 4])
            #expect(await run.client.disablementDerivationCount == 0)
        }
    }

    // MARK: Reason and recovery path (fix 4)

    /// "Not connected" means synchronization found no common ancestor (`noIntersection`). A transient RPC failure does not report it.
    /// It clears if the server later reports this node's head.
    @Test("Fix 4: Reports not connected only when there is no intersection, skips it on RPC failure, and clears it when the server reports the same head")
    func divergedIssue() async throws {
        let world = try LockWorld()
        let other = try LockWorld()
        // When stored state matches this server's chain, a failed sync/offer provides no reason.
        try await withLockClient(world, prepare: { server, directory in
            try TailnetLockStore(directory: directory).save(world.authority)
            server.updateLock {
                $0.authority = world.authority
                $0.faults[Server.syncOfferPath] = .respond(status: 500, body: [])
            }
            server.setMapResponse(try world.map(lock: LockTesting.tkaInfo(head: other.head)))
        }) { run in
            let netmap = try await run.latest("First netmap") { _ in true }
            #expect(netmap.tailnetLock.mode == .enforcing && netmap.tailnetLock.issue == nil)
            #expect(run.server.tkaPaths == [Server.syncOfferPath])
        }
        // State from another tailnet: Not connected. Clears when the server reports this node's head, without synchronization.
        try await withLockClient(world, prepare: { server, directory in
            try TailnetLockStore(directory: directory).save(other.authority)
            server.updateLock { $0.authority = world.authority }
            server.setMapResponse(try world.map())
        }) { run in
            let diverged = try await run.latest("First netmap") { _ in true }
            #expect(diverged.tailnetLock.mode == .enforcing && diverged.tailnetLock.issue == .storedStateDiverged)
            run.server.push(LockTesting.mapJSON(lock: LockTesting.tkaInfo(head: other.head), #""Domain":"same.example""#))
            let joined = try await run.latest("Netmap with the same head") { $0.domain == "same.example" }
            #expect(joined.tailnetLock.mode == .enforcing && joined.tailnetLock.issue == nil)
        }
    }

    /// Recovery path: Stop the node and delete only the lock state file, and the next client starts with bootstrap (TOFU). The identity (NL key) remains unchanged.
    @Test("Fix 4: Deleting only the lock state file makes the new client start with bootstrap and preserves the NL key", arguments: ["foreign", "garbage"])
    func removingLockStateStartsOver(_ kind: String) async throws {
        let world = try LockWorld()
        let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-lock-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let expected: TailnetLockStatus.Issue = kind == "foreign" ? .storedStateDiverged : .unreadableStoredState
        try await withLockClient(world, directory: directory, prepare: { server, directory in
            let store = TailnetLockStore(directory: directory)
            if kind == "foreign" {
                try store.save(try LockWorld().authority)
            } else {
                try Data("깨진 파일".utf8).write(to: store.fileURL)
            }
            server.updateLock { $0.authority = world.authority }
            server.setMapResponse(try world.map())
        }) { run in
            let stuck = try await run.latest("First netmap") { _ in true }
            #expect(stuck.tailnetLock.issue == expected)
        }

        try ControlClient.removeTailnetLockState(inDirectory: directory)
        #expect(!FileManager.default.fileExists(atPath: directory.appending(path: TailnetLockStore.fileName).path))
        #expect(try NodeIdentityStore(directory: directory).load()?.lockPublicKey == world.identity.lockPublicKey)
        // Removing a missing file is allowed.
        try ControlClient.removeTailnetLockState(inDirectory: directory)

        try await withLockClient(world, directory: directory, prepare: { server, _ in
            server.updateLock { $0.authority = world.authority }
            server.setMapResponse(try world.map())
        }) { run in
            let netmap = try await run.latest("Filtered netmap") { $0.tailnetLock.mode == .enforcing }
            #expect(netmap.tailnetLock == TailnetLockStatus(mode: .enforcing, head: world.head.text, filteredPeerCount: 1))
            #expect(run.server.tkaPaths.first == Server.bootstrapPath)
            #expect(try TailnetLockStore(directory: directory).load()?.head == world.head)
        }
    }
}
