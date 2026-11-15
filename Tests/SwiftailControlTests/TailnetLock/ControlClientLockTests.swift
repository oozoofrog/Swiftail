// `ControlClient`의 tailnet lock: netmap을 받을 때의 절차, 닫힌 쪽, 동기화, 끄기, 저장과 다시 시작.
// 가짜 제어 서버(`LockFakeControlServer`)와 실제 연결(업그레이드 → Noise → HTTP/2)로 돈다.
// 계약 `docs/contracts/SwiftailTailnetLock.md` 동작 N·Y·P·O·T, 사용자의 답 U1·U2, 단위 시험 19~21.

import CryptoKit
import Foundation
import Testing

import SwiftailBase
import SwiftailCrypto
@testable import SwiftailControl
@testable import SwiftailTKA

@Suite("제어 클라이언트: tailnet lock", .timeLimit(.minutes(3)))
struct ControlClientLockTests {
    private typealias Server = LockFakeControlServer

    /// lock이 켜진 tailnet에 붙어 `.enforcing`이 된 클라이언트로 `body`를 돌린다.
    private func withEnforcingClient(
        _ world: LockWorld, extraPeers: [String] = [], _ body: (LockRun, Netmap) async throws -> Void
    ) async throws {
        try await withLockClient(world, prepare: { server, _ in
            server.updateLock { $0.authority = world.authority }
            server.setMapResponse(try world.map(extraPeers: extraPeers))
        }) { run in
            try await body(run, try await run.latest("거른 netmap") { $0.tailnetLock.mode == .enforcing })
        }
    }

    /// 서버의 서명 권한 상태에 서명 기기를 하나 더한다. 새 머리를 돌려준다.
    private func addSigner(_ added: LockTesting.Signer, to server: Server, signedBy signer: LockTesting.Signer) throws -> (head: AUMHash, aum: AUM) {
        var authority = try #require(server.lock.authority)
        let aum = try LockTesting.addKey(added, after: authority.head, signedBy: signer)
        try authority.inform([aum])
        server.updateLock { $0.authority = authority }
        return (authority.head, aum)
    }

    // MARK: lock이 없을 때

    @Test("lock이 없는 tailnet: 거르지 않고 .disabled이며 TKA RPC가 하나도 나가지 않는다", arguments: [true, false])
    func noLock(hasCapability: Bool) async throws {
        let world = try LockWorld()
        try await withLockClient(world, prepare: { server, _ in
            server.setMapResponse(try world.map(selfSigned: false, hasCapability: hasCapability, lock: LockWorld.noTKAInfo))
        }) { run in
            let netmap = try await run.latest("첫 netmap") { _ in true }
            #expect(netmap.peers.map(\.id) == [2, 3, 4])
            #expect(netmap.tailnetLock == TailnetLockStatus())

            // 로컬 상태가 없으면 서버가 꺼졌다고 알려도 할 일이 없다.
            run.server.push(LockTesting.mapJSON(lock: LockTesting.tkaDisabled, #""Domain":"tail0001.ts.net""#))
            let next = try await run.latest("증분") { $0.domain == "tail0001.ts.net" }
            #expect(next.tailnetLock == TailnetLockStatus())
            #expect(run.server.tkaPaths.isEmpty)
            #expect(run.uploadedHeads == [""])
            #expect(!FileManager.default.fileExists(atPath: run.storeURL.path))
        }
    }

    @Test("capability가 없으면 서버가 켜졌다고 알려도 부트스트랩하지 않고 거르지 않는다(Go와 같다). capability가 생기면 부트스트랩한다")
    func capabilityRequired() async throws {
        let world = try LockWorld()
        try await withLockClient(world, prepare: { server, _ in
            server.updateLock { $0.authority = world.authority }
            server.setMapResponse(try world.map(hasCapability: false))
        }) { run in
            let open = try await run.latest("첫 netmap") { _ in true }
            #expect(open.peers.map(\.id) == [2, 3, 4])
            #expect(open.tailnetLock == TailnetLockStatus())
            #expect(run.server.tkaPaths.isEmpty)

            // 옛 `Capabilities` 목록으로 와도 capability다.
            let selfNode = LockTesting.selfJSON(
                key: world.selfKey, hasCapability: false, #","Capabilities":["https://tailscale.com/cap/tailnet-lock"]"#
            )
            run.server.push(LockTesting.mapJSON(selfNode: selfNode))
            let enforced = try await run.latest("거른 netmap") { $0.tailnetLock.mode == .enforcing }
            #expect(enforced.peers.map(\.id) == [2, 4])
            #expect(run.server.tkaPaths == [Server.bootstrapPath, Server.syncOfferPath])
        }
    }

    // MARK: 부트스트랩과 거르기

    @Test("부트스트랩: 거른 netmap만 나오고, 잠긴 자기 노드의 서명 요청이 실리고, 서명 뒤의 netmap에서 다시 시작 없이 풀린다")
    func bootstrapAndFilter() async throws {
        let world = try LockWorld()
        try await withLockClient(world, prepare: { server, _ in
            server.updateLock { $0.authority = world.authority }
            server.setMapResponse(try world.map(selfSigned: false))
        }) { run in
            let locked = try await run.latest("거른 netmap") { $0.tailnetLock.mode == .enforcing }
            #expect(locked.peers.map(\.key) == [world.signedPeer, world.apiOnlyPeer])
            #expect(locked.tailnetLock == TailnetLockStatus(
                mode: .enforcing, head: world.head.text, filteredPeerCount: 1,
                signingRequest: .init(
                    nodeKey: "nodekey:" + world.selfKey.rawValue.hex,
                    lockKey: "tlpub:" + [UInt8](world.identity.lockKey.publicKey.rawRepresentation).hex
                )
            ))
            #expect(locked.tailnetLock.isLockedOut)
            #expect(run.netmaps.count == 1, "거르기 전의 netmap이 먼저 나갔다")

            // RPC의 모양(동작 Y7): Noise 위의 GET, Content-Type과 부하 분산 머리 없음, 본문은 JSON.
            #expect(run.server.tkaPaths == [Server.bootstrapPath, Server.syncOfferPath], "머리가 같으면 send를 보내지 않는다")
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

            // 저장했고(0600), 새 머리를 상태 올리기로 알렸다.
            #expect(try TailnetLockStore(directory: run.directory).load()?.head == world.head)
            #expect(try FileManager.default.attributesOfItem(atPath: run.storeURL.path)[.posixPermissions] as? Int == 0o600)
            try await eventually("TKAHead를 올림") { run.uploadedHeads == ["", world.head.text] }

            // 서명 기기가 서명한 뒤의 netmap.
            run.server.push(try world.map())
            let signed = try await run.latest("서명 뒤의 netmap") { !$0.tailnetLock.isLockedOut }
            #expect(signed.tailnetLock == TailnetLockStatus(mode: .enforcing, head: world.head.text, filteredPeerCount: 1))
            #expect(signed.peers.map(\.id) == [2, 4])
            #expect(run.server.tkaPaths.count == 2, "머리가 같은 netmap에 RPC를 보냈다")
        }
    }

    @Test("절차가 도는 동안 netmap을 내지 않고 쥔다. 맵 스트림은 계속 읽고, 끝나면 가장 새 netmap 하나만 걸러 낸다")
    func heldUntilProcedureEnds() async throws {
        let world = try LockWorld()
        try await withLockClient(world, prepare: { server, _ in
            server.updateLock {
                $0.authority = world.authority
                $0.faults[Server.bootstrapPath] = .hold
            }
            server.setMapResponse(try world.map())
        }) { run in
            try await eventually("부트스트랩 요청") { !run.server.requests(to: Server.bootstrapPath).isEmpty }
            #expect(run.netmaps.isEmpty)

            // 절차가 걸려 있는 동안에도 맵 스트림은 읽힌다: 새 응답 둘이 세션에 들어간다.
            run.server.push(#"{"Domain":"first.example"}"#)
            run.server.push(#"{"Domain":"second.example"}"#)
            try await eventually("맵 스트림 읽기") { await run.client.lockSession.netmap?.domain == "second.example" }
            #expect(run.netmaps.isEmpty, "절차가 끝나기 전에 netmap이 나갔다")
            #expect(await run.client.lockSession.isProcedureRunning)

            run.server.release(Server.bootstrapPath)
            let netmap = try await run.latest("거른 netmap") { _ in true }
            #expect(netmap.domain == "second.example")
            #expect(netmap.tailnetLock.mode == .enforcing)
            #expect(netmap.peers.map(\.id) == [2, 4])
            try await eventually("TKAHead를 올림") { run.uploadedHeads.last == world.head.text }
            #expect(run.netmaps.count == 1, "쥔 netmap을 하나씩 다 냈다")
        }
    }

    // MARK: 닫힌 쪽

    /// 부트스트랩이 실패하는 길들.
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
                // 자기 상태의 키로 서명되지 않은 체크포인트.
                return genesis(try LockTesting.checkpoint(trusting: [world.signer], signedBy: LockTesting.Signer()).serialized())
            case .oversizedBody:
                // 올바른 응답 뒤에 공백을 채워 한도(1MiB)를 한 바이트 넘긴 것.
                let valid = #"{"GenesisAUM":"\#(Data(checkpoint).base64EncodedString())"}"#
                return .json(valid + String(repeating: " ", count: ControlClient.maximumTKAResponseSize + 1 - valid.utf8.count))
            case .noAnswer: return .hold
            }
        }
    }

    @Test("부트스트랩이 실패하면 피어를 하나도 올리지 않고(.unverified), 다음 netmap을 기다리지 않고 다시 시도해 풀린다", arguments: BootstrapFault.allCases)
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
            let closed = try await run.latest("첫 netmap") { _ in true }
            #expect(closed.peers.isEmpty)
            #expect(closed.tailnetLock == TailnetLockStatus(mode: .unverified, filteredPeerCount: 3))
            #expect(closed.selfNode.key == world.selfKey)
            #expect(run.netmaps.count == 1)
            #expect(await run.client.lockAuthority == nil)

            // 그동안 온 netmap도 피어 없이 나온다.
            run.server.push(#"{"Domain":"tail0001.ts.net"}"#)
            let still = try await run.latest("증분") { $0.domain == "tail0001.ts.net" }
            #expect(still.peers.isEmpty && still.tailnetLock.mode == .unverified)
            // netmap이 오지 않아도 물러나며 다시 시도한다.
            let attempts = run.server.requests(to: Server.bootstrapPath).count
            try await eventually("재시도") { run.server.requests(to: Server.bootstrapPath).count >= attempts + 2 }
            #expect(run.netmaps.allSatisfy { $0.peers.isEmpty && $0.tailnetLock.mode == .unverified })
            #expect(!FileManager.default.fileExists(atPath: run.storeURL.path))
            #expect(Set(run.uploadedHeads) == [""])
            #expect(!run.server.tkaPaths.contains(Server.syncOfferPath))

            // 서버가 고쳐지면 다음 재시도에 풀린다.
            run.server.release(Server.bootstrapPath)
            let opened = try await run.latest("거른 netmap") { $0.tailnetLock.mode == .enforcing }
            #expect(opened.peers.map(\.id) == [2, 4])
            #expect(opened.tailnetLock == TailnetLockStatus(mode: .enforcing, head: world.head.text, filteredPeerCount: 1))
        }
    }

    @Test("부트스트랩 응답은 한도(1MiB)까지 받는다")
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
            let netmap = try await run.latest("첫 netmap") { _ in true }
            #expect(netmap.tailnetLock.mode == .enforcing)
            #expect(run.server.requests(to: Server.bootstrapPath).count == 1)
        }
    }

    /// 열리지 않는 저장 파일의 종류.
    enum BrokenStore: String, CaseIterable, CustomTestStringConvertible {
        case garbage, forgedSignature

        var testDescription: String { rawValue }
    }

    @Test("저장된 상태를 열지 못하면 .unverified에 머문다: 부트스트랩으로 넘어가지 않고, 서버가 꺼졌다고 해도 같고, 파일을 건드리지 않는다", arguments: BrokenStore.allCases)
    func unreadableStore(kind: BrokenStore) async throws {
        let world = try LockWorld()
        var contents = Data("깨진 파일".utf8)
        try await withLockClient(world, prepare: { server, directory in
            let store = TailnetLockStore(directory: directory)
            if kind == .forgedSignature {
                // 서명의 마지막 바이트를 바꾸고 끝의 해시를 다시 계산한 것: 무결성 검사는 통과하고 서명 재검증에서 떨어진다.
                try store.save(world.authority)
                var body = [UInt8](try Data(contentsOf: store.fileURL).dropLast(32))
                body[body.count - 1] ^= 0x01
                contents = Data(body + BLAKE2s.hash(body))
            }
            try contents.write(to: store.fileURL)
            server.updateLock { $0.authority = world.authority }
            server.setMapResponse(try world.map())
        }) { run in
            let closed = try await run.latest("첫 netmap") { _ in true }
            #expect(closed.peers.isEmpty)
            #expect(closed.tailnetLock == TailnetLockStatus(mode: .unverified, filteredPeerCount: 3))

            // 서버가 lock이 꺼졌다고 알려도 끄기 값을 모르므로 확인할 수 없다.
            run.server.push(LockTesting.mapJSON(lock: LockTesting.tkaDisabled, #""Domain":"tail0001.ts.net""#))
            let still = try await run.latest("증분") { $0.domain == "tail0001.ts.net" }
            #expect(still.peers.isEmpty && still.tailnetLock.mode == .unverified)
            #expect(run.server.tkaPaths.isEmpty, "열지 못한 저장소를 두고 RPC를 보냈다")
            #expect(Set(run.uploadedHeads) == [""])
            #expect(try Data(contentsOf: run.storeURL) == contents)
        }
    }

    @Test("저장하지 못해도 판정은 바뀌지 않는다: 메모리의 상태로 거르고, 다음 변화 때 다시 쓴다")
    func saveFailureKeepsEnforcing() async throws {
        let world = try LockWorld()
        try await withLockClient(world, prepare: { server, _ in
            server.updateLock {
                $0.authority = world.authority
                $0.faults[Server.bootstrapPath] = .hold
            }
            server.setMapResponse(try world.map())
        }) { run in
            try await eventually("부트스트랩 요청") { !run.server.requests(to: Server.bootstrapPath).isEmpty }
            try FileManager.default.setAttributes([.posixPermissions: 0o500], ofItemAtPath: run.directory.path)
            run.server.release(Server.bootstrapPath)
            let netmap = try await run.latest("거른 netmap") { _ in true }
            #expect(netmap.tailnetLock.mode == .enforcing)
            #expect(netmap.peers.map(\.id) == [2, 4])
            #expect(!FileManager.default.fileExists(atPath: run.storeURL.path))

            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: run.directory.path)
            let advanced = try addSigner(LockTesting.Signer(), to: run.server, signedBy: world.signer)
            run.server.push(LockTesting.mapJSON(lock: LockTesting.tkaInfo(head: advanced.head)))
            _ = try await run.latest("동기화한 netmap") { $0.tailnetLock.head == advanced.head.text }
            #expect(try TailnetLockStore(directory: run.directory).load()?.head == advanced.head)
        }
    }

    // MARK: 동기화

    @Test("서버의 머리만 바뀌어도 동기화하고, 새 상태로 같은 netmap을 다시 걸러 낸다")
    func synchronizeOnHeadChange() async throws {
        let world = try LockWorld()
        let second = LockTesting.Signer()
        let peerKey = LockTesting.newNodeKey()
        // 아직 신뢰받지 않는 서명 기기가 서명한 피어.
        let peer = LockTesting.peerJSON(5, key: peerKey, signature: try second.signature(for: peerKey))
        try await withEnforcingClient(world, extraPeers: [peer]) { run, first in
            #expect(first.peers.map(\.id) == [2, 4])
            #expect(first.tailnetLock.filteredPeerCount == 2)

            let advanced = try addSigner(second, to: run.server, signedBy: world.signer)
            run.server.push(LockTesting.mapJSON(lock: LockTesting.tkaInfo(head: advanced.head)))
            let synced = try await run.latest("동기화한 netmap") { $0.tailnetLock.head == advanced.head.text }
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
            try await eventually("새 TKAHead를 올림") { run.uploadedHeads.last == advanced.head.text }
        }
    }

    /// 동기화가 실패하는 길들.
    enum SyncFault: String, CaseIterable, CustomTestStringConvertible {
        case offerServerError, unreadableHead, unreadableAncestor, forgedUpdate, undecodableUpdate, oversizedOffer, sendServerError

        var testDescription: String { rawValue }
        var path: String { self == .sendServerError ? LockFakeControlServer.syncSendPath : LockFakeControlServer.syncOfferPath }
    }

    @Test("동기화가 실패하면 예전 상태로 계속 거른다(열지 않는다). 다음 netmap에서 다시 시도해 따라잡는다", arguments: SyncFault.allCases)
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
                // 신뢰 키가 아닌 키로 서명한 AddKey: 서버가 서명 없는 노드의 키를 믿게 하려는 것과 같은 모양이다.
                let forged = try LockTesting.addKey(second, after: world.head, signedBy: second)
                reply = .json(offer(forged.hash.text, root, [update(forged)]))
            case .undecodableUpdate: reply = .json(offer(head, root, [update(advanced.aum), "AA=="]))
            case .oversizedOffer:
                let valid = offer(head, root, [update(advanced.aum)])
                reply = .json(valid + String(repeating: " ", count: ControlClient.maximumTKASyncOfferResponseSize + 1 - valid.utf8.count))
            }
            run.server.updateLock { $0.faults[fault.path] = reply }
            run.server.push(LockTesting.mapJSON(lock: LockTesting.tkaInfo(head: advanced.head), #""Domain":"first.example""#))

            let stale = try await run.latest("실패 뒤의 netmap") { $0.domain == "first.example" }
            if fault == .sendServerError {
                // AUM은 이미 들였다. 서버에 알리는 것만 실패했다.
                #expect(stale.tailnetLock.head == advanced.head.text)
            } else {
                #expect(stale.peers.map(\.id) == [2, 4], "검증하지 못한 상태로 피어를 올렸다")
                #expect(stale.tailnetLock == TailnetLockStatus(mode: .enforcing, head: world.head.text, filteredPeerCount: 2))
                #expect(try TailnetLockStore(directory: run.directory).load()?.head == world.head)
                #expect(run.server.requests(to: Server.syncSendPath).isEmpty, "들이지 못했는데 send를 보냈다")
            }

            // 서버가 고쳐지고 다음 netmap이 오면 따라잡는다.
            run.server.updateLock { $0.faults = [:] }
            run.server.push(#"{"Domain":"second.example"}"#)
            let synced = try await run.latest("따라잡은 netmap") { $0.domain == "second.example" }
            #expect(synced.peers.map(\.id) == [2, 4, 5])
            #expect(synced.tailnetLock.head == advanced.head.text)
        }
    }

    @Test("sync/offer 응답은 8MiB까지 받는다(다른 RPC의 1MiB 한도가 아니다)")
    func syncOfferBodyAtLimit() async throws {
        let world = try LockWorld()
        try await withEnforcingClient(world) { run, _ in
            let advanced = try addSigner(LockTesting.Signer(), to: run.server, signedBy: world.signer)
            let valid = #"{"Head":"\#(advanced.head.text)","Ancestors":["\#(world.head.text)"],"MissingAUMs":["\#(Data(advanced.aum.serialized()).base64EncodedString())"]}"#
            let padded = valid + String(repeating: " ", count: ControlClient.maximumTKASyncOfferResponseSize - valid.utf8.count)
            run.server.updateLock { $0.faults[Server.syncOfferPath] = .json(padded) }
            run.server.push(LockTesting.mapJSON(lock: LockTesting.tkaInfo(head: advanced.head)))
            _ = try await run.latest("동기화한 netmap") { $0.tailnetLock.head == advanced.head.text }
        }
    }

    @Test("서버가 모르는 로컬 AUM은 sync/send로 보낸다. 저장된 상태가 있으면 부트스트랩하지 않고 첫 요청부터 TKAHead를 싣는다")
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
            let netmap = try await run.latest("거른 netmap") { $0.tailnetLock.mode == .enforcing }
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

            // 스트림 요청과 상태 올리기 둘 다 첫 요청부터 머리를 실었다.
            let heads = run.server.requests(to: "/machine/map").map { $0.object["TKAHead"] as? String }
            #expect(heads.count >= 2 && heads.allSatisfy { $0 == ahead.head.text })
        }
    }

    @Test("다른 tailnet의 상태가 남아 있으면 그 상태로 거른다: 서버와 교차가 없어 따라가지 못하고, 새 tailnet의 서명을 믿지 않는다")
    func foreignStoreStaysClosed() async throws {
        let world = try LockWorld()
        let other = try LockWorld()
        try await withLockClient(world, prepare: { server, directory in
            try TailnetLockStore(directory: directory).save(other.authority)
            server.updateLock { $0.authority = world.authority }
            server.setMapResponse(try world.map())
        }) { run in
            let netmap = try await run.latest("첫 netmap") { _ in true }
            // 서명 검사를 받지 않는 피어만 남고, 자기 서명도 검증되지 않는다.
            #expect(netmap.peers.map(\.id) == [4])
            #expect(netmap.tailnetLock.mode == .enforcing)
            #expect(netmap.tailnetLock.head == other.head.text)
            #expect(netmap.tailnetLock.filteredPeerCount == 2)
            #expect(netmap.tailnetLock.isLockedOut)
            #expect(run.server.tkaPaths == [Server.syncOfferPath])
            #expect(try TailnetLockStore(directory: run.directory).load()?.head == other.head)
        }
    }

    // MARK: lock이 꺼질 때

    @Test("끄기: 맞는 비밀이면 상태와 파일을 지우고 거르기를 멈춘다. 부트스트랩 RPC에 로컬 머리를 싣는다")
    func disablementWithValidSecret() async throws {
        let world = try LockWorld()
        try await withEnforcingClient(world) { run, _ in
            run.server.updateLock {
                $0.authority = nil
                $0.disablementSecret = LockTesting.disablementSecret
            }
            run.server.push(LockTesting.mapJSON(lock: LockTesting.tkaDisabled))
            let open = try await run.latest("끈 뒤의 netmap") { $0.tailnetLock.mode == .disabled }
            #expect(open.peers.map(\.id) == [2, 3, 4])
            #expect(open.tailnetLock == TailnetLockStatus())
            #expect(!FileManager.default.fileExists(atPath: run.storeURL.path))
            #expect(await run.client.lockAuthority == nil)

            let requests = run.server.requests(to: Server.bootstrapPath)
            #expect(requests.count == 2)
            #expect(requests.last?.object["Head"] as? String == world.head.text)
            #expect(run.server.tkaPaths.suffix(1) == [Server.bootstrapPath], "끈 뒤에 동기화를 보냈다")
            try await eventually("빈 TKAHead를 올림") { run.uploadedHeads.last == "" && run.uploadedHeads.count == 3 }
            #expect(await run.client.disablementDerivationCount == 1)
        }
    }

    @Test("끄기: 틀린 비밀·비밀 없는 Disabled로는 lock을 유지하고 동기화를 이어 간다. 같은 비밀로는 KDF를 다시 돌리지 않는다")
    func disablementWithInvalidSecret() async throws {
        let world = try LockWorld()
        try await withEnforcingClient(world) { run, _ in
            // 서버가 `Disabled`를 알리고 `secret`을 준다. 그 뒤의 netmap을 돌려준다.
            var round = 0
            func disable(secret: [UInt8]) async throws -> Netmap {
                round += 1
                let domain = "round\(round).example"
                run.server.updateLock {
                    $0.authority = nil
                    $0.disablementSecret = secret
                }
                run.server.push(LockTesting.mapJSON(lock: LockTesting.tkaDisabled, #""Domain":"\#(domain)""#))
                return try await run.latest("\(round)번째 netmap") { $0.domain == domain }
            }
            let enforced = TailnetLockStatus(mode: .enforcing, head: world.head.text, filteredPeerCount: 1)
            let wrong = [UInt8](repeating: 0x5a, count: 32)

            var netmap = try await disable(secret: wrong)
            #expect(netmap.tailnetLock == enforced)
            #expect(netmap.peers.map(\.id) == [2, 4])
            #expect(await run.client.disablementDerivationCount == 1)
            // 서버가 알린 머리(없음)와 다르므로 동기화를 이어서 시도한다. 그것이 실패해도 예전 상태로 거른다.
            #expect(run.server.tkaPaths.suffix(2) == [Server.bootstrapPath, Server.syncOfferPath])

            netmap = try await disable(secret: wrong)
            #expect(netmap.tailnetLock == enforced)
            #expect(await run.client.disablementDerivationCount == 1, "같은 비밀로 KDF를 다시 돌렸다")
            #expect(run.server.requests(to: Server.bootstrapPath).count == 3)

            netmap = try await disable(secret: [])
            #expect(netmap.tailnetLock == enforced, "비밀 없는 Disabled로 lock을 지웠다")
            #expect(await run.client.disablementDerivationCount == 2)

            netmap = try await disable(secret: Array(LockTesting.disablementSecret.dropLast()))
            #expect(netmap.tailnetLock == enforced)
            #expect(await run.client.disablementDerivationCount == 3)
            #expect(try TailnetLockStore(directory: run.directory).load()?.head == world.head)

            // 거절을 기억하는 것이 맞는 비밀을 막지 않는다.
            netmap = try await disable(secret: LockTesting.disablementSecret)
            #expect(netmap.tailnetLock == TailnetLockStatus())
            #expect(netmap.peers.map(\.id) == [2, 3, 4])
            #expect(await run.client.disablementDerivationCount == 4)
        }
    }

    @Test("TKAInfo가 도중에 빠진 응답은 변화 없음이고, 다시 이은 스트림의 첫 응답에 없으면 끄기 절차로 간다")
    func missingTKAInfo() async throws {
        let world = try LockWorld()
        try await withEnforcingClient(world) { run, _ in
            run.server.push(LockTesting.mapJSON(lock: #""TKAInfo":null"#, #""Domain":"first.example""#))
            let unchanged = try await run.latest("증분") { $0.domain == "first.example" }
            #expect(unchanged.tailnetLock == TailnetLockStatus(mode: .enforcing, head: world.head.text, filteredPeerCount: 1))
            #expect(run.server.tkaPaths == [Server.bootstrapPath, Server.syncOfferPath])

            // 새 맵 세션은 처음부터 TKAInfo가 없다. 서버는 틀린 비밀을 준다: 유지한다.
            run.server.updateLock {
                $0.authority = nil
                $0.disablementSecret = [1, 2, 3]
            }
            run.server.setMapResponse(try world.map(lock: LockWorld.noTKAInfo, #""Domain":"second.example""#))
            run.server.dropConnections()
            let kept = try await run.latest("다시 이은 뒤의 netmap") { $0.domain == "second.example" }
            #expect(kept.tailnetLock == TailnetLockStatus(mode: .enforcing, head: world.head.text, filteredPeerCount: 1))
            #expect(run.server.requests(to: Server.bootstrapPath).last?.object["Head"] as? String == world.head.text)
            #expect(await run.client.disablementDerivationCount == 1)

            // 맞는 비밀을 주면 꺼진다.
            run.server.updateLock { $0.disablementSecret = LockTesting.disablementSecret }
            run.server.setMapResponse(try world.map(lock: LockWorld.noTKAInfo, #""Domain":"third.example""#))
            run.server.dropConnections()
            let open = try await run.latest("끈 뒤의 netmap") { $0.domain == "third.example" }
            #expect(open.tailnetLock == TailnetLockStatus())
            #expect(open.peers.map(\.id) == [2, 3, 4])
            #expect(!FileManager.default.fileExists(atPath: run.storeURL.path))
        }
    }

    // MARK: 다시 시작과 다시 잇기

    @Test("다시 시작: 저장된 상태로 부트스트랩 없이 같은 머리로 거르고, 그사이 자란 사슬은 동기화로 따라온다")
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
            try await run.latest("거른 netmap") { $0.tailnetLock.mode == .enforcing }
        }
        #expect(first.tailnetLock.head == world.head.text)

        try await withLockClient(world, directory: directory, prepare: prepare(world.authority)) { run in
            let netmap = try await run.latest("다시 시작한 뒤의 netmap") { _ in true }
            #expect(netmap.tailnetLock == first.tailnetLock, "머리와 서명 요청(같은 NL 키)이 같아야 한다")
            #expect(netmap.peers.map(\.id) == [2, 4])
            #expect(run.server.tkaPaths.isEmpty, "머리가 같은데 RPC를 보냈다")
            #expect(run.server.requests(to: "/machine/map").allSatisfy { $0.object["TKAHead"] as? String == world.head.text })
        }

        var advanced = world.authority
        try advanced.inform([try LockTesting.addKey(LockTesting.Signer(), after: world.head, signedBy: world.signer)])
        try await withLockClient(world, directory: directory, prepare: prepare(advanced)) { run in
            let netmap = try await run.latest("다시 시작한 뒤의 netmap") { _ in true }
            #expect(netmap.tailnetLock.head == advanced.head.text)
            #expect(run.server.tkaPaths == [Server.syncOfferPath, Server.syncSendPath])
            #expect(run.netmaps.count == 1)
        }
    }

    @Test("절차 중에 연결이 끊겨도 상태가 어긋나지 않는다: 다시 이은 세션에서 절차를 다시 돌고, 그사이 거르지 않은 netmap이 나가지 않는다")
    func reconnectDuringProcedure() async throws {
        let world = try LockWorld()
        try await withLockClient(world, prepare: { server, _ in
            server.updateLock {
                $0.authority = world.authority
                $0.faults[Server.bootstrapPath] = .hold
            }
            server.setMapResponse(try world.map())
        }) { run in
            // 부트스트랩의 답을 기다리는 중에 끊긴다.
            try await eventually("부트스트랩 요청") { run.server.requests(to: Server.bootstrapPath).count == 1 }
            run.server.updateLock { $0.faults = [:] }
            run.server.dropConnections()
            let netmap = try await run.latest("다시 이은 뒤의 netmap") { _ in true }
            #expect(netmap.tailnetLock == TailnetLockStatus(mode: .enforcing, head: world.head.text, filteredPeerCount: 1))
            #expect(run.server.requests(to: Server.bootstrapPath).count == 2)
            #expect(run.netmaps.count == 1)

            // 동기화의 답을 기다리는 중에 끊긴다. 메모리의 상태는 그대로 쥐고, 새 세션이 다시 동기화한다.
            let advanced = try addSigner(LockTesting.Signer(), to: run.server, signedBy: world.signer)
            run.server.updateLock { $0.faults[Server.syncOfferPath] = .hold }
            let offers = run.server.requests(to: Server.syncOfferPath).count
            run.server.push(LockTesting.mapJSON(lock: LockTesting.tkaInfo(head: advanced.head)))
            try await eventually("동기화 요청") { run.server.requests(to: Server.syncOfferPath).count == offers + 1 }
            #expect(await run.client.lockAuthority?.head == world.head)
            run.server.updateLock { $0.faults = [:] }
            run.server.setMapResponse(try world.map(lock: LockTesting.tkaInfo(head: advanced.head)))
            run.server.dropConnections()
            let synced = try await run.latest("따라잡은 netmap") { $0.tailnetLock.head == advanced.head.text }
            #expect(synced.peers.map(\.id) == [2, 4])
            #expect(run.netmaps.allSatisfy { $0.tailnetLock.mode == .enforcing && $0.peers.map(\.id) == [2, 4] })
            #expect(run.server.requests(to: Server.bootstrapPath).count == 2, "상태를 쥐고 있는데 다시 부트스트랩했다")
            #expect(try TailnetLockStore(directory: run.directory).load()?.head == advanced.head)
        }
    }

    // MARK: Go와 같은 판정

    @Test("피어 집합의 판정이 Go와 같다(tka-fixtures.json의 peerSets)", arguments: try GoPeerSetFile.load().peerSets)
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
            let netmap = try await run.latest("거른 netmap") { _ in true }
            #expect(netmap.tailnetLock.mode == .enforcing)
            #expect(netmap.peers.map { $0.key.rawValue.hex } == peerSet.kept)
            #expect(netmap.tailnetLock.filteredPeerCount == peerSet.peers.count - peerSet.kept.count)
        }
    }
}
