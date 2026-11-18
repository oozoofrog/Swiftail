// `ControlClient` tailnet lock: handling netmap receipt, fail-closed behavior, synchronization, disablement, storage, and restart.
// Runs against a fake control server (`LockFakeControlServer`) over a real connection (upgrade → Noise → HTTP/2).
// Contract `docs/contracts/SwiftailTailnetLock.md`, behaviors N, Y, P, O, and T, owner answers U1 and U2, unit tests 19–21.

import CryptoKit
import Foundation
import Testing

import SwiftailBase
import SwiftailCrypto
@testable import SwiftailControl
@testable import SwiftailTKA

@Suite("Control client: Tailnet lock", .timeLimit(.minutes(3)))
struct ControlClientLockTests {
    private typealias Server = LockFakeControlServer

    /// Adds one signing device to the server's authority state. Returns the new head.
    private func addSigner(_ added: LockTesting.Signer, to server: Server, signedBy signer: LockTesting.Signer) throws -> (head: AUMHash, aum: AUM) {
        var authority = try #require(server.lock.authority)
        let aum = try LockTesting.addKey(added, after: authority.head, signedBy: signer)
        try authority.inform([aum])
        server.updateLock { $0.authority = authority }
        return (authority.head, aum)
    }

    // MARK: Without lock

    @Test("A tailnet without lock skips filtering, is .disabled, and sends no TKA RPCs", arguments: [true, false])
    func noLock(hasCapability: Bool) async throws {
        let world = try LockWorld()
        try await withLockClient(world, prepare: { server, _ in
            server.setMapResponse(try world.map(selfSigned: false, hasCapability: hasCapability, lock: LockWorld.noTKAInfo))
        }) { run in
            let netmap = try await run.latest("First netmap") { _ in true }
            #expect(netmap.peers.map(\.id) == [2, 3, 4])
            #expect(netmap.tailnetLock == TailnetLockStatus())

            // With no local state, there is nothing to do even if the server reports disabled.
            run.server.push(LockTesting.mapJSON(lock: LockTesting.tkaDisabled, #""Domain":"tail0001.ts.net""#))
            let next = try await run.latest("Delta") { $0.domain == "tail0001.ts.net" }
            #expect(next.tailnetLock == TailnetLockStatus())
            #expect(run.server.tkaPaths.isEmpty)
            #expect(run.uploadedHeads == [""])
            #expect(!FileManager.default.fileExists(atPath: run.storeURL.path))
        }
    }

    @Test("Without capability, a server report of enabled triggers neither bootstrap nor filtering (as in Go). Bootstrap when capability becomes available")
    func capabilityRequired() async throws {
        let world = try LockWorld()
        try await withLockClient(world, prepare: { server, _ in
            server.updateLock { $0.authority = world.authority }
            server.setMapResponse(try world.map(hasCapability: false))
        }) { run in
            let open = try await run.latest("First netmap") { _ in true }
            #expect(open.peers.map(\.id) == [2, 3, 4])
            #expect(open.tailnetLock == TailnetLockStatus())
            #expect(run.server.tkaPaths.isEmpty)

            // The legacy `Capabilities` list also conveys capability.
            let selfNode = LockTesting.selfJSON(
                key: world.selfKey, hasCapability: false, #","Capabilities":["https://tailscale.com/cap/tailnet-lock"]"#
            )
            run.server.push(LockTesting.mapJSON(selfNode: selfNode))
            let enforced = try await run.latest("Filtered netmap") { $0.tailnetLock.mode == .enforcing }
            #expect(enforced.peers.map(\.id) == [2, 4])
            #expect(run.server.tkaPaths == [Server.bootstrapPath, Server.syncOfferPath])
        }
    }

    // MARK: Bootstrap and filtering

    @Test("Bootstrap emits only the filtered netmap, includes a signing request for the locked-out self node, and unlocks it in the netmap after signing without restarting")
    func bootstrapAndFilter() async throws {
        let world = try LockWorld()
        try await withLockClient(world, prepare: { server, _ in
            server.updateLock { $0.authority = world.authority }
            server.setMapResponse(try world.map(selfSigned: false))
        }) { run in
            let locked = try await run.latest("Filtered netmap") { $0.tailnetLock.mode == .enforcing }
            #expect(locked.peers.map(\.key) == [world.signedPeer, world.apiOnlyPeer])
            #expect(locked.tailnetLock == TailnetLockStatus(
                mode: .enforcing, head: world.head.text, filteredPeerCount: 1,
                signingRequest: .init(
                    nodeKey: "nodekey:" + world.selfKey.rawValue.hex,
                    lockKey: "tlpub:" + [UInt8](world.identity.lockKey.publicKey.rawRepresentation).hex
                )
            ))
            #expect(locked.tailnetLock.isLockedOut)
            #expect(run.netmaps.count == 1, "The unfiltered netmap was emitted first")

            // RPC format (behavior Y7): GET over Noise, no Content-Type or load-balancing header, JSON body.
            #expect(run.server.tkaPaths == [Server.bootstrapPath, Server.syncOfferPath], "Skips the send RPC when the heads match")
            let bootstrap = try #require(run.server.requests(to: Server.bootstrapPath).first)
            #expect(bootstrap.method == "GET")
            #expect(bootstrap.header("content-type") == nil)
            #expect(bootstrap.header("ts-lb") == nil)
            #expect(try jsonObject(Data(bootstrap.body)) == ["Version": 148, "NodeKey": world.selfKey.description, "Head": ""])
            let offer = try #require(run.server.requests(to: Server.syncOfferPath).first)
            #expect(offer.method == "GET")
            #expect(offer.header("content-type") == nil)
            #expect(try jsonObject(Data(offer.body)) == [
                "Version": 148, "NodeKey": world.selfKey.description, "Head": world.head.text, "Ancestors": [world.head.text],
            ])

            // Stored the state (0600) and reported the new head in a state upload.
            #expect(try TailnetLockStore(directory: run.directory).load()?.head == world.head)
            #expect(try FileManager.default.attributesOfItem(atPath: run.storeURL.path)[.posixPermissions] as? Int == 0o600)
            try await eventually("Upload TKAHead") { run.uploadedHeads == ["", world.head.text] }

            // Netmap after the signing device signs.
            run.server.push(try world.map())
            let signed = try await run.latest("Netmap after signing") { !$0.tailnetLock.isLockedOut }
            #expect(signed.tailnetLock == TailnetLockStatus(mode: .enforcing, head: world.head.text, filteredPeerCount: 1))
            #expect(signed.peers.map(\.id) == [2, 4])
            #expect(run.server.tkaPaths.count == 2, "Sent an RPC for a netmap with the same head")
        }
    }

    @Test("Holds netmaps without emitting them while the procedure runs. Keeps reading the map stream, then filters and emits only the newest netmap")
    func heldUntilProcedureEnds() async throws {
        let world = try LockWorld()
        try await withLockClient(world, prepare: { server, _ in
            server.updateLock {
                $0.authority = world.authority
                $0.faults[Server.bootstrapPath] = .hold
            }
            server.setMapResponse(try world.map())
        }) { run in
            try await eventually("Bootstrap request") { !run.server.requests(to: Server.bootstrapPath).isEmpty }
            #expect(run.netmaps.isEmpty)

            // Continues reading the map stream while the procedure is pending. Two new responses reach the session.
            run.server.push(#"{"Domain":"first.example"}"#)
            run.server.push(#"{"Domain":"second.example"}"#)
            try await eventually("Read the map stream") { await run.client.lockSession.netmap?.domain == "second.example" }
            #expect(run.netmaps.isEmpty, "Emitted a netmap before the procedure finished")
            #expect(await run.client.lockSession.isProcedureRunning)

            run.server.release(Server.bootstrapPath)
            let netmap = try await run.latest("Filtered netmap") { _ in true }
            #expect(netmap.domain == "second.example")
            #expect(netmap.tailnetLock.mode == .enforcing)
            #expect(netmap.peers.map(\.id) == [2, 4])
            try await eventually("Upload TKAHead") { run.uploadedHeads.last == world.head.text }
            #expect(run.netmaps.count == 1, "Emitted all held netmaps one by one")
        }
    }

    // MARK: Fail-closed behavior

    /// Ways bootstrap can fail.
    enum BootstrapFault: String, CaseIterable, CustomTestStringConvertible {
        case serverError, notJSON, noCheckpoint, truncatedCheckpoint, notACheckpoint, unverifiableCheckpoint, oversizedBody, noAnswer

        var testDescription: String { rawValue }

        func reply(in world: LockWorld) throws -> LockFakeControlServer.Reply {
            let genesis = { (bytes: [UInt8]) in LockFakeControlServer.Reply.json(#"{"GenesisAUM":"\#(Data(bytes).base64EncodedString())"}"#) }
            let checkpoint = try #require(world.authority.aums.first).serialized()
            switch self {
            case .serverError: return .respond(status: 500, body: Array("internal error".utf8))
            case .notJSON: return .json("<html>")
            case .noCheckpoint: return .json("{}")
            case .truncatedCheckpoint: return genesis(checkpoint.dropLast())
            case .notACheckpoint:
                return genesis(try LockTesting.addKey(LockTesting.Signer(), after: world.head, signedBy: world.signer).serialized())
            case .unverifiableCheckpoint:
                // A checkpoint with no signature from the keys in its own state.
                return genesis(try LockTesting.checkpoint(trusting: [world.signer], signedBy: LockTesting.Signer()).serialized())
            case .oversizedBody:
                // A valid response padded with spaces to exceed the limit (1MiB) by one byte.
                let valid = #"{"GenesisAUM":"\#(Data(checkpoint).base64EncodedString())"}"#
                return .json(valid + String(repeating: " ", count: ControlClient.maximumTKAResponseSize + 1 - valid.utf8.count))
            case .noAnswer: return .hold
            }
        }
    }

    @Test("A bootstrap failure publishes no peers (.unverified) and recovers by retrying without waiting for the next netmap", arguments: BootstrapFault.allCases)
    func unverifiedUntilBootstrapSucceeds(fault: BootstrapFault) async throws {
        let world = try LockWorld()
        var timeouts = ControlClient.Timeouts.lockTesting
        if fault == .noAnswer { timeouts.tkaRequest = .milliseconds(100) }
        try await withLockClient(world, timeouts: timeouts, prepare: { server, _ in
            let reply = try fault.reply(in: world)
            server.updateLock {
                $0.authority = world.authority
                $0.faults[Server.bootstrapPath] = reply
            }
            server.setMapResponse(try world.map())
        }) { run in
            let closed = try await run.latest("First netmap") { _ in true }
            #expect(closed.peers.isEmpty)
            #expect(closed.tailnetLock == TailnetLockStatus(mode: .unverified, filteredPeerCount: 3, issue: .acquiringState))
            #expect(closed.selfNode.key == world.selfKey)
            #expect(run.netmaps.count == 1)
            #expect(await run.client.lockAuthority == nil)

            // Netmaps arriving in the meantime also come out without peers.
            run.server.push(#"{"Domain":"tail0001.ts.net"}"#)
            let still = try await run.latest("Delta") { $0.domain == "tail0001.ts.net" }
            #expect(still.peers.isEmpty && still.tailnetLock.mode == .unverified)
            // Backs off and retries even if no netmap arrives.
            let attempts = run.server.requests(to: Server.bootstrapPath).count
            try await eventually("Retry") { run.server.requests(to: Server.bootstrapPath).count >= attempts + 2 }
            #expect(run.netmaps.allSatisfy { $0.peers.isEmpty && $0.tailnetLock.mode == .unverified })
            #expect(!FileManager.default.fileExists(atPath: run.storeURL.path))
            #expect(Set(run.uploadedHeads) == [""])
            #expect(!run.server.tkaPaths.contains(Server.syncOfferPath))

            // Once the server is fixed, the next retry recovers.
            run.server.release(Server.bootstrapPath)
            let opened = try await run.latest("Filtered netmap") { $0.tailnetLock.mode == .enforcing }
            #expect(opened.peers.map(\.id) == [2, 4])
            #expect(opened.tailnetLock == TailnetLockStatus(mode: .enforcing, head: world.head.text, filteredPeerCount: 1))
        }
    }

    @Test("Accepts bootstrap responses up to the limit (1MiB)")
    func bootstrapBodyAtLimit() async throws {
        let world = try LockWorld()
        try await withLockClient(world, prepare: { server, _ in
            let checkpoint = try #require(world.authority.aums.first).serialized()
            let valid = #"{"GenesisAUM":"\#(Data(checkpoint).base64EncodedString())"}"#
            let padded = valid + String(repeating: " ", count: ControlClient.maximumTKAResponseSize - valid.utf8.count)
            server.updateLock {
                $0.authority = world.authority
                $0.faults[Server.bootstrapPath] = .json(padded)
            }
            server.setMapResponse(try world.map())
        }) { run in
            let netmap = try await run.latest("First netmap") { _ in true }
            #expect(netmap.tailnetLock.mode == .enforcing)
            #expect(run.server.requests(to: Server.bootstrapPath).count == 1)
        }
    }

    /// Types of stored files that cannot be opened.
    enum BrokenStore: String, CaseIterable, CustomTestStringConvertible {
        case garbage, forgedSignature

        var testDescription: String { rawValue }
    }

    @Test("If stored state cannot be opened, stays .unverified without falling back to bootstrap, even if the server reports disabled, and leaves the file untouched", arguments: BrokenStore.allCases)
    func unreadableStore(kind: BrokenStore) async throws {
        let world = try LockWorld()
        var contents = Data("깨진 파일".utf8)
        try await withLockClient(world, prepare: { server, directory in
            let store = TailnetLockStore(directory: directory)
            if kind == .forgedSignature {
                // Changes the last byte of the signature and recomputes the trailing hash. Passes the integrity check and fails signature revalidation.
                try store.save(world.authority)
                var body = [UInt8](try Data(contentsOf: store.fileURL).dropLast(32))
                body[body.count - 1] ^= 0x01
                contents = Data(body + BLAKE2s.hash(body))
            }
            try contents.write(to: store.fileURL)
            server.updateLock { $0.authority = world.authority }
            server.setMapResponse(try world.map())
        }) { run in
            let closed = try await run.latest("First netmap") { _ in true }
            #expect(closed.peers.isEmpty)
            #expect(closed.tailnetLock == TailnetLockStatus(mode: .unverified, filteredPeerCount: 3, issue: .unreadableStoredState))

            // Even if the server reports lock disabled, the client cannot verify it without knowing the disablement value.
            run.server.push(LockTesting.mapJSON(lock: LockTesting.tkaDisabled, #""Domain":"tail0001.ts.net""#))
            let still = try await run.latest("Delta") { $0.domain == "tail0001.ts.net" }
            #expect(still.peers.isEmpty && still.tailnetLock.mode == .unverified && still.tailnetLock.issue == .unreadableStoredState)
            #expect(run.server.tkaPaths.isEmpty, "Sent an RPC with a store that could not be opened")
            #expect(Set(run.uploadedHeads) == [""])
            #expect(try Data(contentsOf: run.storeURL) == contents)
        }
    }

    @Test("A storage failure does not change the decision. Filters with in-memory state and tries writing again on the next change")
    func saveFailureKeepsEnforcing() async throws {
        let world = try LockWorld()
        try await withLockClient(world, prepare: { server, _ in
            server.updateLock {
                $0.authority = world.authority
                $0.faults[Server.bootstrapPath] = .hold
            }
            server.setMapResponse(try world.map())
        }) { run in
            try await eventually("Bootstrap request") { !run.server.requests(to: Server.bootstrapPath).isEmpty }
            try FileManager.default.setAttributes([.posixPermissions: 0o500], ofItemAtPath: run.directory.path)
            run.server.release(Server.bootstrapPath)
            let netmap = try await run.latest("Filtered netmap") { _ in true }
            #expect(netmap.tailnetLock.mode == .enforcing)
            #expect(netmap.peers.map(\.id) == [2, 4])
            #expect(!FileManager.default.fileExists(atPath: run.storeURL.path))

            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: run.directory.path)
            let advanced = try addSigner(LockTesting.Signer(), to: run.server, signedBy: world.signer)
            run.server.push(LockTesting.mapJSON(lock: LockTesting.tkaInfo(head: advanced.head)))
            _ = try await run.latest("Synchronized netmap") { $0.tailnetLock.head == advanced.head.text }
            #expect(try TailnetLockStore(directory: run.directory).load()?.head == advanced.head)
        }
    }

    // MARK: Synchronization

    @Test("Synchronizes even when only the server head changes, then filters the same netmap again with the new state")
    func synchronizeOnHeadChange() async throws {
        let world = try LockWorld()
        let second = LockTesting.Signer()
        let peerKey = LockTesting.newNodeKey()
        // A peer signed by a signing device that is still untrusted.
        let peer = LockTesting.peerJSON(5, key: peerKey, signature: try second.signature(for: peerKey))
        try await withEnforcingClient(world, extraPeers: [peer]) { run, first in
            #expect(first.peers.map(\.id) == [2, 4])
            #expect(first.tailnetLock.filteredPeerCount == 2)

            let advanced = try addSigner(second, to: run.server, signedBy: world.signer)
            run.server.push(LockTesting.mapJSON(lock: LockTesting.tkaInfo(head: advanced.head)))
            let synced = try await run.latest("Synchronized netmap") { $0.tailnetLock.head == advanced.head.text }
            #expect(synced.peers.map(\.id) == [2, 4, 5])
            #expect(synced.tailnetLock == TailnetLockStatus(mode: .enforcing, head: advanced.head.text, filteredPeerCount: 1))
            #expect(run.netmaps.count == 2)

            #expect(run.server.tkaPaths == [Server.bootstrapPath, Server.syncOfferPath, Server.syncOfferPath, Server.syncSendPath])
            let send = try #require(run.server.requests(to: Server.syncSendPath).first)
            #expect(send.method == "GET")
            #expect(send.header("content-type") == nil)
            #expect(try jsonObject(Data(send.body)) == [
                "Version": 148, "NodeKey": world.selfKey.description, "Head": advanced.head.text,
                "MissingAUMs": [String](), "Interactive": false,
            ])
            #expect(String(decoding: send.body, as: UTF8.self).contains(#""MissingAUMs":[]"#))
            #expect(try TailnetLockStore(directory: run.directory).load()?.head == advanced.head)
            try await eventually("Upload the new TKAHead") { run.uploadedHeads.last == advanced.head.text }
        }
    }

    /// Ways synchronization can fail.
    enum SyncFault: String, CaseIterable, CustomTestStringConvertible {
        case offerServerError, unreadableHead, unreadableAncestor, forgedUpdate, undecodableUpdate, oversizedOffer, sendServerError

        var testDescription: String { rawValue }
        var path: String { self == .sendServerError ? LockFakeControlServer.syncSendPath : LockFakeControlServer.syncOfferPath }
    }

    @Test("If synchronization fails, keeps filtering with the old state (does not open up). Retries on the next netmap and catches up", arguments: SyncFault.allCases)
    func synchronizationFailureKeepsOldState(fault: SyncFault) async throws {
        let world = try LockWorld()
        let second = LockTesting.Signer()
        let peerKey = LockTesting.newNodeKey()
        let peer = LockTesting.peerJSON(5, key: peerKey, signature: try second.signature(for: peerKey))
        try await withEnforcingClient(world, extraPeers: [peer]) { run, _ in
            let advanced = try addSigner(second, to: run.server, signedBy: world.signer)
            let update = { (aum: AUM) in Data(aum.serialized()).base64EncodedString() }
            let offer = { (head: String, ancestor: String, updates: [String]) in
                #"{"Head":"\#(head)","Ancestors":["\#(ancestor)"],"MissingAUMs":[\#(updates.map { #""\#($0)""# }.joined(separator: ","))]}"#
            }
            let (head, root) = (advanced.head.text, world.head.text)
            let reply: Server.Reply
            switch fault {
            case .offerServerError, .sendServerError: reply = .respond(status: 503, body: Array("unavailable".utf8))
            case .unreadableHead: reply = .json(offer(head.lowercased(), root, [update(advanced.aum)]))
            case .unreadableAncestor: reply = .json(offer(head, "AAAA", [update(advanced.aum)]))
            case .forgedUpdate:
                // AddKey signed with an untrusted key, mimicking a server trying to establish trust in an unsigned node's key.
                let forged = try LockTesting.addKey(second, after: world.head, signedBy: second)
                reply = .json(offer(forged.hash.text, root, [update(forged)]))
            case .undecodableUpdate: reply = .json(offer(head, root, [update(advanced.aum), "AA=="]))
            case .oversizedOffer:
                let valid = offer(head, root, [update(advanced.aum)])
                reply = .json(valid + String(repeating: " ", count: ControlClient.maximumTKASyncOfferResponseSize + 1 - valid.utf8.count))
            }
            run.server.updateLock { $0.faults[fault.path] = reply }
            run.server.push(LockTesting.mapJSON(lock: LockTesting.tkaInfo(head: advanced.head), #""Domain":"first.example""#))

            let stale = try await run.latest("Netmap after failure") { $0.domain == "first.example" }
            if fault == .sendServerError {
                // The AUM was already accepted. Only notifying the server failed.
                #expect(stale.tailnetLock.head == advanced.head.text)
            } else {
                #expect(stale.peers.map(\.id) == [2, 4], "Published peers using unverified state")
                #expect(stale.tailnetLock == TailnetLockStatus(mode: .enforcing, head: world.head.text, filteredPeerCount: 2))
                #expect(try TailnetLockStore(directory: run.directory).load()?.head == world.head)
                #expect(run.server.requests(to: Server.syncSendPath).isEmpty, "Issued the send RPC without accepting the AUM")
            }

            // Once the server is fixed and the next netmap arrives, it catches up.
            run.server.updateLock { $0.faults = [:] }
            run.server.push(#"{"Domain":"second.example"}"#)
            let synced = try await run.latest("Netmap after catching up") { $0.domain == "second.example" }
            #expect(synced.peers.map(\.id) == [2, 4, 5])
            #expect(synced.tailnetLock.head == advanced.head.text)
        }
    }

    @Test("Accepts sync/offer responses up to 8MiB, beyond the 1MiB limit for other RPCs")
    func syncOfferBodyAtLimit() async throws {
        let world = try LockWorld()
        try await withEnforcingClient(world) { run, _ in
            let advanced = try addSigner(LockTesting.Signer(), to: run.server, signedBy: world.signer)
            let valid = #"{"Head":"\#(advanced.head.text)","Ancestors":["\#(world.head.text)"],"MissingAUMs":["\#(Data(advanced.aum.serialized()).base64EncodedString())"]}"#
            let padded = valid + String(repeating: " ", count: ControlClient.maximumTKASyncOfferResponseSize - valid.utf8.count)
            run.server.updateLock { $0.faults[Server.syncOfferPath] = .json(padded) }
            run.server.push(LockTesting.mapJSON(lock: LockTesting.tkaInfo(head: advanced.head)))
            _ = try await run.latest("Synchronized netmap") { $0.tailnetLock.head == advanced.head.text }
        }
    }

    @Test("Sends local AUMs unknown to the server via sync/send. With saved state, skips bootstrap and includes TKAHead from the first request")
    func sendsAUMsUnknownToServer() async throws {
        let world = try LockWorld()
        var ahead = world.authority
        let added = try LockTesting.addKey(LockTesting.Signer(), after: world.head, signedBy: world.signer)
        try ahead.inform([added])
        try await withLockClient(world, prepare: { server, directory in
            try TailnetLockStore(directory: directory).save(ahead)
            server.updateLock { $0.authority = world.authority }
            server.setMapResponse(try world.map())
        }) { run in
            let netmap = try await run.latest("Filtered netmap") { $0.tailnetLock.mode == .enforcing }
            #expect(netmap.tailnetLock.head == ahead.head.text)
            #expect(run.netmaps.count == 1)
            #expect(run.server.tkaPaths == [Server.syncOfferPath, Server.syncSendPath])

            let offer = try #require(run.server.requests(to: Server.syncOfferPath).first)
            #expect(try jsonObject(Data(offer.body)) == [
                "Version": 148, "NodeKey": world.selfKey.description, "Head": ahead.head.text, "Ancestors": [world.head.text],
            ])
            let send = try #require(run.server.requests(to: Server.syncSendPath).first)
            #expect(try jsonObject(Data(send.body)) == [
                "Version": 148, "NodeKey": world.selfKey.description, "Head": ahead.head.text,
                "MissingAUMs": [Data(added.serialized()).base64EncodedString()], "Interactive": false,
            ])
            #expect(run.server.lock.authority?.head == ahead.head)

            // Both the stream request and state upload included the head from the first request.
            let heads = run.server.requests(to: "/machine/map").map { $0.object["TKAHead"] as? String }
            #expect(heads.count >= 2 && heads.allSatisfy { $0 == ahead.head.text })
        }
    }

    @Test("If state from another tailnet remains, filters with it. With no intersection with the server, cannot catch up and does not trust the new tailnet's signatures")
    func foreignStoreStaysClosed() async throws {
        let world = try LockWorld()
        let other = try LockWorld()
        try await withLockClient(world, prepare: { server, directory in
            try TailnetLockStore(directory: directory).save(other.authority)
            server.updateLock { $0.authority = world.authority }
            server.setMapResponse(try world.map())
        }) { run in
            let netmap = try await run.latest("First netmap") { _ in true }
            // Only peers exempt from signature checks remain, and the self signature is also unverified.
            #expect(netmap.peers.map(\.id) == [4])
            #expect(netmap.tailnetLock.mode == .enforcing)
            #expect(netmap.tailnetLock.head == other.head.text)
            #expect(netmap.tailnetLock.filteredPeerCount == 2)
            #expect(netmap.tailnetLock.isLockedOut)
            // The app knows that signing will not unlock the node (§5, TL-11b item 4).
            #expect(netmap.tailnetLock.issue == .storedStateDiverged)
            #expect(run.server.tkaPaths == [Server.syncOfferPath])
            #expect(try TailnetLockStore(directory: run.directory).load()?.head == other.head)
        }
    }

}

extension LockDisablementTests {
    @Test("Disablement with the correct secret removes state and its file and stops filtering. The bootstrap RPC carries the local head")
    func disablementWithValidSecret() async throws {
        let world = try LockWorld()
        try await withEnforcingClient(world) { run, _ in
            run.server.updateLock {
                $0.authority = nil
                $0.disablementSecret = LockTesting.disablementSecret
            }
            run.server.push(LockTesting.mapJSON(lock: LockTesting.tkaDisabled))
            let open = try await run.latest("Netmap after disablement") { $0.tailnetLock.mode == .disabled }
            #expect(open.peers.map(\.id) == [2, 3, 4])
            #expect(open.tailnetLock == TailnetLockStatus())
            #expect(!FileManager.default.fileExists(atPath: run.storeURL.path))
            #expect(await run.client.lockAuthority == nil)

            let requests = run.server.requests(to: Server.bootstrapPath)
            #expect(requests.count == 2)
            #expect(requests.last?.object["Head"] as? String == world.head.text)
            #expect(run.server.tkaPaths.suffix(1) == [Server.bootstrapPath], "Sent a sync after disablement")
            try await eventually("Upload an empty TKAHead") { run.uploadedHeads.last == "" && run.uploadedHeads.count == 3 }
            #expect(await run.client.disablementDerivationCount == 1)
        }
    }

    @Test("Disablement before the response to the enabled head upload arrives uploads an empty TKAHead again after the response (behavior N4)")
    func disablementWhileHeadUploadInFlight() async throws {
        let world = try LockWorld()
        try await withLockClient(world, prepare: { server, _ in
            server.updateLock {
                $0.authority = world.authority
                $0.faults[Server.bootstrapPath] = .hold
            }
            server.setMapResponse(try world.map())
        }) { run in
            // The first state upload (empty head) finished when connecting. Hold only later uploads.
            try await eventually("Bootstrap request") { !run.server.requests(to: Server.bootstrapPath).isEmpty }
            run.server.updateLock { $0.faults[Server.mapPath] = .hold }
            run.server.release(Server.bootstrapPath)
            _ = try await run.latest("Filtered netmap") { $0.tailnetLock.mode == .enforcing }
            try await eventually("Upload the enabled head") { run.uploadedHeads == ["", world.head.text] }

            run.server.updateLock {
                $0.authority = nil
                $0.disablementSecret = LockTesting.disablementSecret
            }
            run.server.push(LockTesting.mapJSON(lock: LockTesting.tkaDisabled))
            _ = try await run.latest("Netmap after disablement") { $0.tailnetLock.mode == .disabled }
            #expect(run.uploadedHeads == ["", world.head.text], "Sent the next upload before the held response arrived")

            run.server.release(Server.mapPath)
            try await eventually("Upload an empty TKAHead again") { run.uploadedHeads == ["", world.head.text, ""] }
        }
    }

    @Test("Disablement with a wrong secret or Disabled with no secret keeps lock active and continues syncing. A repeated secret does not rerun the KDF")
    func disablementWithInvalidSecret() async throws {
        let world = try LockWorld()
        try await withEnforcingClient(world) { run, _ in
            // The server reports `Disabled` and supplies `secret`. Returns the resulting netmap.
            var round = 0
            func disable(secret: [UInt8]) async throws -> Netmap {
                round += 1
                let domain = "round\(round).example"
                run.server.updateLock {
                    $0.authority = nil
                    $0.disablementSecret = secret
                }
                run.server.push(LockTesting.mapJSON(lock: LockTesting.tkaDisabled, #""Domain":"\#(domain)""#))
                return try await run.latest("Netmap number \(round)") { $0.domain == domain }
            }
            let enforced = TailnetLockStatus(mode: .enforcing, head: world.head.text, filteredPeerCount: 1)
            let wrong = [UInt8](repeating: 0x5a, count: 32)

            var netmap = try await disable(secret: wrong)
            #expect(netmap.tailnetLock == enforced)
            #expect(netmap.peers.map(\.id) == [2, 4])
            #expect(await run.client.disablementDerivationCount == 1)
            // The local head differs from the head reported by the server (none), so synchronization continues to be attempted. On failure, still filters with the old state.
            #expect(run.server.tkaPaths.suffix(2) == [Server.bootstrapPath, Server.syncOfferPath])

            netmap = try await disable(secret: wrong)
            #expect(netmap.tailnetLock == enforced)
            #expect(await run.client.disablementDerivationCount == 1, "Reran the KDF with the same secret")
            #expect(run.server.requests(to: Server.bootstrapPath).count == 3)

            netmap = try await disable(secret: [])
            #expect(netmap.tailnetLock == enforced, "Cleared lock on Disabled without a secret")
            #expect(await run.client.disablementDerivationCount == 2)

            netmap = try await disable(secret: Array(LockTesting.disablementSecret.dropLast()))
            #expect(netmap.tailnetLock == enforced)
            #expect(await run.client.disablementDerivationCount == 3)
            #expect(try TailnetLockStore(directory: run.directory).load()?.head == world.head)

            // Remembering a rejection does not block the correct secret.
            netmap = try await disable(secret: LockTesting.disablementSecret)
            #expect(netmap.tailnetLock == TailnetLockStatus())
            #expect(netmap.peers.map(\.id) == [2, 3, 4])
            #expect(await run.client.disablementDerivationCount == 4)
        }
    }

    /// Gate (a) 7 revealed that if the server changes only the disablement secret and resends an identical map, the unchanged netmap
    /// prevented the procedure from running again. Go runs the procedure on every map response.
    @Test("Disablement reruns the procedure on identical map responses when work remains, and skips it on KeepAlive")
    func unchangedMapRetriesPendingProcedure() async throws {
        let world = try LockWorld()
        try await withEnforcingClient(world) { run, _ in
            let disabledMap = LockTesting.mapJSON(lock: LockTesting.tkaDisabled, #""Domain":"same.example""#)
            run.server.updateLock {
                $0.authority = nil
                $0.disablementSecret = [UInt8](repeating: 0x5a, count: 32)
            }
            run.server.push(disabledMap)
            let kept = try await run.latest("Netmap after the wrong secret") { $0.domain == "same.example" }
            #expect(kept.tailnetLock.mode == .enforcing)
            let attempts = run.server.requests(to: Server.bootstrapPath).count

            // KeepAlive is not a trigger.
            run.server.push(#"{"KeepAlive":true}"#)
            try await Task.sleep(for: .milliseconds(300))
            #expect(run.server.requests(to: Server.bootstrapPath).count == attempts)

            // Only the secret changes to a correct one. The map stays the same.
            run.server.updateLock { $0.disablementSecret = LockTesting.disablementSecret }
            run.server.push(disabledMap)
            let open = try await run.latest("Netmap after retrying on the same map and disabling lock") { $0.tailnetLock.mode == .disabled }
            #expect(open.peers.map(\.id) == [2, 3, 4])
            #expect(run.server.requests(to: Server.bootstrapPath).count == attempts + 1)
        }
    }

    @Test("Omitting TKAInfo midstream leaves it unchanged. Omitting it from the first response on a reconnected stream starts disablement")
    func missingTKAInfo() async throws {
        let world = try LockWorld()
        try await withEnforcingClient(world) { run, _ in
            run.server.push(LockTesting.mapJSON(lock: #""TKAInfo":null"#, #""Domain":"first.example""#))
            let unchanged = try await run.latest("Delta") { $0.domain == "first.example" }
            #expect(unchanged.tailnetLock == TailnetLockStatus(mode: .enforcing, head: world.head.text, filteredPeerCount: 1))
            #expect(run.server.tkaPaths == [Server.bootstrapPath, Server.syncOfferPath])

            // The new map session has no TKAInfo from the start. The server supplies the wrong secret, so lock stays enabled.
            run.server.updateLock {
                $0.authority = nil
                $0.disablementSecret = [1, 2, 3]
            }
            run.server.setMapResponse(try world.map(lock: LockWorld.noTKAInfo, #""Domain":"second.example""#))
            run.server.dropConnections()
            let kept = try await run.latest("Netmap after reconnecting") { $0.domain == "second.example" }
            #expect(kept.tailnetLock == TailnetLockStatus(mode: .enforcing, head: world.head.text, filteredPeerCount: 1))
            #expect(run.server.requests(to: Server.bootstrapPath).last?.object["Head"] as? String == world.head.text)
            #expect(await run.client.disablementDerivationCount == 1)

            // The correct secret disables lock.
            run.server.updateLock { $0.disablementSecret = LockTesting.disablementSecret }
            run.server.setMapResponse(try world.map(lock: LockWorld.noTKAInfo, #""Domain":"third.example""#))
            run.server.dropConnections()
            let open = try await run.latest("Netmap after disablement") { $0.domain == "third.example" }
            #expect(open.tailnetLock == TailnetLockStatus())
            #expect(open.peers.map(\.id) == [2, 3, 4])
            #expect(!FileManager.default.fileExists(atPath: run.storeURL.path))
        }
    }

}

extension ControlClientLockTests {
    // MARK: Restart and reconnect

    @Test("A restart filters with the same head from stored state without bootstrap and catches up by synchronizing any chain growth")
    func restart() async throws {
        let world = try LockWorld()
        let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-lock-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let prepare = { (authority: Authority) in
            { (server: Server, _: URL) in
                server.updateLock { $0.authority = authority }
                server.setMapResponse(LockTesting.mapJSON(
                    selfNode: LockTesting.selfJSON(key: world.selfKey), peers: try world.peers(), lock: LockTesting.tkaInfo(head: authority.head)
                ))
            }
        }
        let first = try await withLockClient(world, directory: directory, prepare: prepare(world.authority)) { run in
            try await run.latest("Filtered netmap") { $0.tailnetLock.mode == .enforcing }
        }
        #expect(first.tailnetLock.head == world.head.text)

        try await withLockClient(world, directory: directory, prepare: prepare(world.authority)) { run in
            let netmap = try await run.latest("Netmap after restart") { _ in true }
            #expect(netmap.tailnetLock == first.tailnetLock, "The head and signing request (same NL key) must match")
            #expect(netmap.peers.map(\.id) == [2, 4])
            #expect(run.server.tkaPaths.isEmpty, "Sent an RPC despite matching heads")
            #expect(run.server.requests(to: "/machine/map").allSatisfy { $0.object["TKAHead"] as? String == world.head.text })
        }

        var advanced = world.authority
        try advanced.inform([try LockTesting.addKey(LockTesting.Signer(), after: world.head, signedBy: world.signer)])
        try await withLockClient(world, directory: directory, prepare: prepare(advanced)) { run in
            let netmap = try await run.latest("Netmap after restart") { _ in true }
            #expect(netmap.tailnetLock.head == advanced.head.text)
            #expect(run.server.tkaPaths == [Server.syncOfferPath, Server.syncSendPath])
            #expect(run.netmaps.count == 1)
        }
    }

    @Test("A disconnect mid-procedure preserves consistent state. The reconnected session reruns the procedure, and no unfiltered netmap is emitted in the meantime")
    func reconnectDuringProcedure() async throws {
        let world = try LockWorld()
        try await withLockClient(world, prepare: { server, _ in
            server.updateLock {
                $0.authority = world.authority
                $0.faults[Server.bootstrapPath] = .hold
            }
            server.setMapResponse(try world.map())
        }) { run in
            // Disconnect while waiting for the bootstrap response.
            try await eventually("Bootstrap request") { run.server.requests(to: Server.bootstrapPath).count == 1 }
            run.server.updateLock { $0.faults = [:] }
            run.server.dropConnections()
            let netmap = try await run.latest("Netmap after reconnecting") { _ in true }
            #expect(netmap.tailnetLock == TailnetLockStatus(mode: .enforcing, head: world.head.text, filteredPeerCount: 1))
            #expect(run.server.requests(to: Server.bootstrapPath).count == 2)
            #expect(run.netmaps.count == 1)

            // Disconnect while waiting for the sync response. Retain the in-memory state, and the new session synchronizes again.
            let advanced = try addSigner(LockTesting.Signer(), to: run.server, signedBy: world.signer)
            run.server.updateLock { $0.faults[Server.syncOfferPath] = .hold }
            let offers = run.server.requests(to: Server.syncOfferPath).count
            run.server.push(LockTesting.mapJSON(lock: LockTesting.tkaInfo(head: advanced.head)))
            try await eventually("Sync request") { run.server.requests(to: Server.syncOfferPath).count == offers + 1 }
            #expect(await run.client.lockAuthority?.head == world.head)
            run.server.updateLock { $0.faults = [:] }
            run.server.setMapResponse(try world.map(lock: LockTesting.tkaInfo(head: advanced.head)))
            run.server.dropConnections()
            let synced = try await run.latest("Netmap after catching up") { $0.tailnetLock.head == advanced.head.text }
            #expect(synced.peers.map(\.id) == [2, 4])
            #expect(run.netmaps.allSatisfy { $0.tailnetLock.mode == .enforcing && $0.peers.map(\.id) == [2, 4] })
            #expect(run.server.requests(to: Server.bootstrapPath).count == 2, "Bootstrapped again despite retaining state")
            #expect(try TailnetLockStore(directory: run.directory).load()?.head == advanced.head)
        }
    }

    // MARK: Decisions matching Go

    @Test("Peer set decisions match Go (peerSets in tka-fixtures.json)", arguments: try GoPeerSetFile.load().peerSets)
    func goPeerSets(peerSet: GoPeerSetFile.PeerSet) async throws {
        let world = try LockWorld()
        let authority = try GoPeerSetFile.load().authority(named: peerSet.authority)
        try await withLockClient(world, prepare: { server, _ in
            let peers = try peerSet.peers.enumerated().map { index, peer in
                let key = try #require([UInt8](hex: peer.nodeKey).flatMap { NodePublicKey(rawValue: $0) })
                let signature = try #require([UInt8](hex: peer.signature ?? ""))
                return LockTesting.peerJSON(Int64(index + 2), key: key, signature: signature, apiOnly: peer.unsignedPeerAPIOnly)
            }
            server.updateLock { $0.authority = authority }
            server.setMapResponse(LockTesting.mapJSON(
                selfNode: LockTesting.selfJSON(key: world.selfKey), peers: peers, lock: LockTesting.tkaInfo(head: authority.head)
            ))
        }) { run in
            let netmap = try await run.latest("Filtered netmap") { _ in true }
            #expect(netmap.tailnetLock.mode == .enforcing)
            #expect(netmap.peers.map { $0.key.rawValue.hex } == peerSet.kept)
            #expect(netmap.tailnetLock.filteredPeerCount == peerSet.peers.count - peerSet.kept.count)
        }
    }
}
