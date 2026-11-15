// 독립 검토(TL-11b)의 재현 시험. 제어 서버를 믿지 않는 위협 모델로 `ControlClient`의 tailnet lock 절차를 본다.
//
// 검토가 찾은 결함과 계약의 문제는 계약 `docs/contracts/SwiftailTailnetLock.md` 5절 "독립 검토에서 고치는 것: 제어의 절차
// (TL-11b)"의 항목 1~5로 고쳤다. 시험 이름의 "고침 n"이 그 항목이다. "남는 것"은 그 절이 고치지 않기로 한 동작이다.
// 나머지는 검토가 확인한 닫힌 쪽의 성질이다.
//
// 키는 모두 시험이 그 자리에서 만든다.

import CryptoKit
import Foundation
import Testing

import SwiftailBase
@testable import SwiftailControl
@testable import SwiftailTKA

@Suite("검토: 제어 클라이언트의 tailnet lock", .timeLimit(.minutes(3)))
struct LockReviewTests {
    private typealias Server = LockFakeControlServer

    private func withEnforcingClient(_ world: LockWorld, _ body: (LockRun) async throws -> Void) async throws {
        try await withLockClient(world, prepare: { server, _ in
            server.updateLock { $0.authority = world.authority }
            server.setMapResponse(try world.map())
        }) { run in
            _ = try await run.latest("거른 netmap") { $0.tailnetLock.mode == .enforcing }
            try await body(run)
        }
    }

    // MARK: 재서명 요청

    /// 고침 1: 서버의 재서명 요청이 NL 키의 서명 오라클이 되지 않는다.
    ///
    /// 서버는 `RegisterResponse.NodeKeySignature`에 무엇이든 넣을 수 있다. 검사가 없으면 사슬이 node 키를 15개 넘게 담을 때
    /// "줄이기"가 **서버가 고른 `Pubkey`들**에 NL 키로 rotation 서명을 새로 만든다(Go `tka/sig.go:393-437`). 서버가 이 노드의
    /// 진짜 direct 서명(서명 기기가 `tailscale lock sign <nodeKey> <lockKey>`로 만든 것) 위에 가짜 rotation 15겹을 얹어 보내면,
    /// 돌아온 등록 요청 안에 공격자의 node 키를 인가하는 사슬이 들어 있었다. 지금은 재서명 함수가 겹마다 NL 키의 서명을
    /// 검사해 던지고, 노드는 서명 없이 등록한다.
    @Test("고침 1: 서버가 고른 node 키에 NL 키로 서명해 주지 않는다(재서명 요청의 사슬 줄이기)")
    func resignRequestIsNotASigningOracle() async throws {
        let lock = RegistrationSigningTests.Lock()
        let identity = NodeIdentity(machineKey: .init(), nodeKey: .init())
        let ownKey = try #require(identity.nodePublicKey)
        // 서명 기기가 이 노드에 준 진짜 서명. 회전 키는 이 노드의 NL 공개 키다.
        let direct = try lock.directSignature(for: ownKey, wrappingKey: identity.lockPublicKey)
        // 서버(공격자)만 개인 키를 아는 node 키.
        let attackerKey = LockTesting.newNodeKey()

        // 진짜 direct 위에 서명이 0으로 찬 rotation 15겹. 맨 바깥의 `Pubkey`가 공격자의 키다.
        var forged = try NodeKeySignature(decoding: direct)
        for layer in 0..<15 {
            let key = layer == 14 ? attackerKey : LockTesting.newNodeKey()
            forged = NodeKeySignature(
                kind: NodeKeySignature.Kind.rotation, publicKey: key.binaryForm,
                signature: [UInt8](repeating: 0, count: 64), nested: forged
            )
        }
        // 서버가 보낸 사슬 자체는 아무것도 인가하지 않는다.
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
        try await server.wait("맵 스트림이 열리지 않았다") { !$0.openMapStreams.isEmpty }

        // 노드가 재서명 요청에 답해 보낸 두 번째 등록 요청: 새 node 키로, 서명 없이 간다(노드는 잠기고 서명 요청이 뜬다).
        let requests = server.requests.filter { $0.path == "/machine/register" }
        #expect(requests.count == 2)
        let body = Data(try #require(requests.last).body)
        let second = try #require(try JSONSerialization.jsonObject(with: body) as? [String: Any])
        #expect(second["NodeKeySignature"] is NSNull, "서버가 보낸 사슬 위에 NL 키로 서명해 돌려보냈다")
        #expect(second["NodeKey"] as? String != ownKey.description)
        #expect(second["OldNodeKey"] as? String == ownKey.description)
        // 어느 요청에도 공격자의 node 키에 대한 NL 키의 서명이 없다: 서버로 간 모든 등록 요청의 서명을 펼쳐 본다.
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

    // MARK: 끄기 비밀

    /// 고침 2: 거절한 끄기 비밀을 머리마다 집합(8개)으로 기억한다. 하나뿐이면 서버가 비밀 둘을 번갈아 줄 때 매번
    /// Argon2i(16MiB)를 다시 돈다(동작 O6). KDF는 actor를 막는다.
    @Test("고침 2: 서버가 틀린 끄기 비밀 둘을 번갈아 보내도 KDF는 비밀마다 한 번만 돈다(동작 O6)")
    func alternatingDisablementSecrets() async throws {
        let world = try LockWorld()
        try await withEnforcingClient(world) { run in
            let secrets = [[UInt8](repeating: 0x11, count: 32), [UInt8](repeating: 0x22, count: 32)]
            for round in 0..<4 {
                let domain = "round\(round).example"
                run.server.updateLock {
                    $0.authority = nil
                    $0.disablementSecret = secrets[round % 2]
                }
                run.server.push(LockTesting.mapJSON(lock: LockTesting.tkaDisabled, #""Domain":"\#(domain)""#))
                let netmap = try await run.latest("\(round)번째 netmap") { $0.domain == domain }
                #expect(netmap.tailnetLock.mode == .enforcing)
            }
            let derivations = await run.client.disablementDerivationCount
            #expect(derivations == 2, "이미 거절한 비밀로 KDF를 다시 돌렸다")
        }
    }

    /// 고침 2의 한도: 8개까지 기억하고, 9번째를 거절하면 가장 오래된 것을 잊는다. 머리가 바뀌면 새로 쥔다.
    @Test("고침 2: 거절 기억은 머리마다 8개이고 넘치면 가장 오래된 것부터 잊는다")
    func rejectedDisablementCapacity() async throws {
        let world = try LockWorld()
        try await withEnforcingClient(world) { run in
            var round = 0
            func disable(_ secret: [UInt8]) async throws {
                round += 1
                let domain = "round\(round).example"
                run.server.updateLock {
                    $0.authority = nil
                    $0.disablementSecret = secret
                }
                run.server.push(LockTesting.mapJSON(lock: LockTesting.tkaDisabled, #""Domain":"\#(domain)""#))
                let netmap = try await run.latest("\(round)번째 netmap") { $0.domain == domain }
                #expect(netmap.tailnetLock.mode == .enforcing)
            }
            let secrets = (1...9).map { [UInt8](repeating: UInt8($0), count: 32) }
            for secret in secrets.prefix(8) { try await disable(secret) }
            #expect(await run.client.disablementDerivationCount == 8)
            // 여덟 개 모두 기억한다.
            for secret in secrets.prefix(8).reversed() { try await disable(secret) }
            #expect(await run.client.disablementDerivationCount == 8)
            #expect(ControlClient.maximumRejectedDisablementCount == 8)
            // 아홉 번째를 거절하면 첫 번째를 잊는다.
            try await disable(secrets[8])
            #expect(await run.client.disablementDerivationCount == 9)
            try await disable(secrets[1])
            #expect(await run.client.disablementDerivationCount == 9)
            try await disable(secrets[0])
            #expect(await run.client.disablementDerivationCount == 10, "가장 오래된 비밀을 잊지 않았다")
        }
    }

    // MARK: 로컬 상태가 있을 때

    /// 확인(통과): 검증한 상태를 쥔 뒤에는 서버가 lock 알림을 어떻게 바꾸든, 절차를 어떻게 실패시키든, 연결을 어떻게 끊든
    /// 서명 없는 피어(ID 3)가 `Event.netmap`으로 나가지 않는다.
    @Test("로컬 상태가 있으면 서버의 어떤 알림·실패·재연결에도 거르지 않은 netmap이 나가지 않는다")
    func serverCannotOpenAnEnforcingNode() async throws {
        let world = try LockWorld()
        try await withEnforcingClient(world) { run in
            var step = 0
            /// 응답 하나를 밀어 넣고 그것이 반영된 netmap이 나올 때까지 기다린다.
            func push(lock: String?, selfNode: String? = nil) async throws {
                step += 1
                let domain = "step\(step).example"
                run.server.push(LockTesting.mapJSON(selfNode: selfNode, lock: lock, #""Domain":"\#(domain)""#))
                _ = try await run.latest("\(step)번째 응답의 netmap") { $0.domain == domain }
            }
            let bareSelf = LockTesting.selfJSON(key: world.selfKey, hasCapability: false)

            // 읽히지 않는 머리, 머리 없는 TKAInfo, 다른 머리, capability를 뺀 자기 노드.
            try await push(lock: #""TKAInfo":{"Head":"not-a-hash"}"#)
            try await push(lock: #""TKAInfo":{}"#)
            try await push(lock: LockTesting.tkaInfo(head: try LockWorld().head))
            try await push(lock: nil, selfNode: bareSelf)
            // 꺼졌다는 알림: 비밀이 없고(빈 값), 부트스트랩 RPC가 실패하고, 동기화가 실패한다.
            run.server.updateLock { $0.authority = nil }
            try await push(lock: LockTesting.tkaDisabled, selfNode: bareSelf)
            run.server.updateLock { $0.faults[Server.bootstrapPath] = .respond(status: 500, body: []) }
            try await push(lock: #""TKAInfo":{"Disabled":true,"Head":"not-a-hash"}"#)
            run.server.updateLock { $0.faults[Server.bootstrapPath] = .json("{}") }
            try await push(lock: LockTesting.tkaDisabled)

            // 새 맵 세션: 처음부터 TKAInfo도 capability도 자기 서명도 없다. 절차의 답은 붙들려 있다가 연결이 끊긴다.
            run.server.updateLock { $0.faults[Server.bootstrapPath] = .hold }
            run.server.setMapResponse(try world.map(
                selfSigned: false, hasCapability: false, lock: LockWorld.noTKAInfo, #""Domain":"reconnected.example""#
            ))
            let attempts = run.server.requests(to: Server.bootstrapPath).count
            run.server.dropConnections()
            try await eventually("새 세션의 끄기 절차") { run.server.requests(to: Server.bootstrapPath).count > attempts }
            run.server.updateLock { $0.faults[Server.bootstrapPath] = .respond(status: 500, body: []) }
            run.server.setMapResponse(try world.map(
                selfSigned: false, hasCapability: false, lock: LockWorld.noTKAInfo, #""Domain":"again.example""#
            ))
            run.server.dropConnections()
            _ = try await run.latest("다시 이은 뒤의 netmap") { $0.domain == "again.example" }

            #expect(run.netmaps.allSatisfy { $0.tailnetLock.mode == .enforcing && $0.tailnetLock.head == world.head.text })
            #expect(run.netmaps.allSatisfy { !$0.peers.contains { $0.id == 3 } }, "서명 없는 피어가 나갔다")
            #expect(await run.client.lockAuthority?.head == world.head)
            #expect(try TailnetLockStore(directory: run.directory).load()?.head == world.head)
        }
    }

    // MARK: 로컬 상태가 없을 때

    /// Go는 받고(줄바꿈을 지우고 읽는다) Swiftail은 거절하는 머리 텍스트: 50자 + CRLF(동작 D10).
    private static func goReadableHead(_ world: LockWorld) -> String {
        String(world.head.text.prefix(50)) + "\\r\\n"
    }

    /// 고침 3: 로컬 상태가 없는 노드에 서버가 `TKAInfo`(꺼졌다는 표시 없음)를 읽히지 않는 `Head`와 함께 실으면 "켜짐, 머리
    /// 모름"이다. capability가 있으면 부트스트랩하고 그 상태로 거른다. 예전에는 "lock 없음"으로 읽어 모든 피어를 냈고,
    /// 동작 D10의 줄바꿈에서는 Go 노드가 거르는 동안 Swiftail 노드는 거르지 않았다.
    @Test("고침 3: 로컬 상태 없이 읽히지 않는 Head를 받으면 부트스트랩해 거른다", arguments: ["not-a-hash", "goReadable"])
    func unreadableHeadWithoutLocalStateBootstraps(_ head: String) async throws {
        let world = try LockWorld()
        let text = head == "goReadable" ? Self.goReadableHead(world) : head
        try await withLockClient(world, prepare: { server, _ in
            server.updateLock { $0.authority = world.authority }
            server.setMapResponse(try world.map(lock: #""TKAInfo":{"Head":"\#(text)"}"#))
        }) { run in
            let netmap = try await run.latest("첫 netmap") { _ in true }
            #expect(netmap.tailnetLock == TailnetLockStatus(mode: .enforcing, head: world.head.text, filteredPeerCount: 1))
            #expect(netmap.peers.map(\.id) == [2, 4], "서명 없는 피어(ID 3)가 나갔다")
            #expect(run.server.tkaPaths.first == Server.bootstrapPath)
            #expect(run.netmaps.allSatisfy { !$0.peers.contains { $0.id == 3 } })
        }
    }

    /// 고침 3·4: 읽히지 않는 머리로 부트스트랩이 실패하면 `.unverified`이고 까닭은 "얻는 중"이다. capability가 없으면 Go와
    /// 같이 거르지 않는다(N2 표의 첫 줄).
    @Test("고침 3·4: 읽히지 않는 Head에서 부트스트랩이 실패하면 .unverified(얻는 중), capability가 없으면 거르지 않는다")
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
            let closed = try await run.latest("첫 netmap") { _ in true }
            #expect(closed.tailnetLock == TailnetLockStatus(mode: .unverified, filteredPeerCount: 3, issue: .acquiringState))
            #expect(closed.peers.isEmpty)
        }
        try await withLockClient(world, prepare: { server, _ in
            server.updateLock { $0.authority = world.authority }
            server.setMapResponse(try world.map(hasCapability: false, lock: lock))
        }) { run in
            let open = try await run.latest("첫 netmap") { _ in true }
            #expect(open.tailnetLock == TailnetLockStatus())
            #expect(run.server.tkaPaths.isEmpty)
        }
    }

    /// 고침 3: 로컬 상태가 있으면 읽히지 않는 머리는 동기화의 계기다(머리가 다르다고 본다). 동기화가 실패해도 예전 상태로 거른다.
    @Test("고침 3: 로컬 상태가 있으면 읽히지 않는 Head에 동기화로 간다")
    func unreadableHeadWithLocalStateSynchronizes() async throws {
        let world = try LockWorld()
        try await withEnforcingClient(world) { run in
            let offers = run.server.requests(to: Server.syncOfferPath).count
            run.server.push(LockTesting.mapJSON(lock: #""TKAInfo":{"Head":"not-a-hash"}"#, #""Domain":"unreadable.example""#))
            let netmap = try await run.latest("netmap") { $0.domain == "unreadable.example" }
            #expect(netmap.tailnetLock == TailnetLockStatus(mode: .enforcing, head: world.head.text, filteredPeerCount: 1))
            #expect(run.server.requests(to: Server.syncOfferPath).count == offers + 1)
            #expect(run.server.requests(to: Server.bootstrapPath).count == 1, "끄기 절차로 갔다")
        }
    }

    /// 남는 것(5절 TL-11b): `.unverified`(사용자 결정 U1)는 서버가 정직할 때의 보호다. 로컬 상태가 없는 동안에는 서버가
    /// "꺼졌다"고 고쳐 말하는 것만으로 풀린다. 끄기 비밀도 RPC도 필요 없다. 첫 신뢰가 TOFU인 것의 귀결이고 Go도 같다.
    @Test("남는 것: 부트스트랩이 실패한 .unverified는 서버가 Disabled를 알리면 비밀 없이 풀린다")
    func unverifiedIsReleasedByTheServersWord() async throws {
        let world = try LockWorld()
        try await withLockClient(world, prepare: { server, _ in
            server.updateLock {
                $0.authority = world.authority
                $0.faults[Server.bootstrapPath] = .respond(status: 500, body: [])
            }
            server.setMapResponse(try world.map())
        }) { run in
            let closed = try await run.latest("첫 netmap") { _ in true }
            #expect(closed.tailnetLock.mode == .unverified && closed.peers.isEmpty)

            run.server.push(LockTesting.mapJSON(lock: LockTesting.tkaDisabled))
            let open = try await run.latest("Disabled 뒤의 netmap") { $0.tailnetLock.mode == .disabled }
            #expect(open.peers.map(\.id) == [2, 3, 4])
            #expect(await run.client.disablementDerivationCount == 0)
        }
    }

    // MARK: 까닭과 푸는 길(고침 4)

    /// "이어지지 않음"은 동기화에서 공통 조상을 찾지 못한 것(`noIntersection`)이다. 일시적인 RPC 실패로는 내지 않는다.
    /// 서버가 그 뒤 이 노드의 머리를 알리면 풀린다.
    @Test("고침 4: 이어지지 않음은 교차가 없을 때만이고, RPC 실패로는 내지 않으며, 서버가 같은 머리를 알리면 풀린다")
    func divergedIssue() async throws {
        let world = try LockWorld()
        let other = try LockWorld()
        // 저장된 상태가 이 서버의 사슬과 같을 때: sync/offer가 실패해도 까닭은 없다.
        try await withLockClient(world, prepare: { server, directory in
            try TailnetLockStore(directory: directory).save(world.authority)
            server.updateLock {
                $0.authority = world.authority
                $0.faults[Server.syncOfferPath] = .respond(status: 500, body: [])
            }
            server.setMapResponse(try world.map(lock: LockTesting.tkaInfo(head: other.head)))
        }) { run in
            let netmap = try await run.latest("첫 netmap") { _ in true }
            #expect(netmap.tailnetLock.mode == .enforcing && netmap.tailnetLock.issue == nil)
            #expect(run.server.tkaPaths == [Server.syncOfferPath])
        }
        // 다른 tailnet의 상태: 이어지지 않음. 서버가 이 노드의 머리를 알리면(동기화 없이) 풀린다.
        try await withLockClient(world, prepare: { server, directory in
            try TailnetLockStore(directory: directory).save(other.authority)
            server.updateLock { $0.authority = world.authority }
            server.setMapResponse(try world.map())
        }) { run in
            let diverged = try await run.latest("첫 netmap") { _ in true }
            #expect(diverged.tailnetLock.mode == .enforcing && diverged.tailnetLock.issue == .storedStateDiverged)
            run.server.push(LockTesting.mapJSON(lock: LockTesting.tkaInfo(head: other.head), #""Domain":"same.example""#))
            let joined = try await run.latest("같은 머리의 netmap") { $0.domain == "same.example" }
            #expect(joined.tailnetLock.mode == .enforcing && joined.tailnetLock.issue == nil)
        }
    }

    /// 푸는 길: 노드를 멈추고 lock 상태 파일만 지우면 다음 클라이언트가 부트스트랩부터 한다(TOFU). 신원(NL 키)은 그대로다.
    @Test("고침 4: lock 상태 파일만 지우면 새 클라이언트가 부트스트랩부터 하고 NL 키는 그대로다", arguments: ["foreign", "garbage"])
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
            let stuck = try await run.latest("첫 netmap") { _ in true }
            #expect(stuck.tailnetLock.issue == expected)
        }

        try ControlClient.removeTailnetLockState(inDirectory: directory)
        #expect(!FileManager.default.fileExists(atPath: directory.appending(path: TailnetLockStore.fileName).path))
        #expect(try NodeIdentityStore(directory: directory).load()?.lockPublicKey == world.identity.lockPublicKey)
        // 없는 파일을 지워도 된다.
        try ControlClient.removeTailnetLockState(inDirectory: directory)

        try await withLockClient(world, directory: directory, prepare: { server, _ in
            server.updateLock { $0.authority = world.authority }
            server.setMapResponse(try world.map())
        }) { run in
            let netmap = try await run.latest("거른 netmap") { $0.tailnetLock.mode == .enforcing }
            #expect(netmap.tailnetLock == TailnetLockStatus(mode: .enforcing, head: world.head.text, filteredPeerCount: 1))
            #expect(run.server.tkaPaths.first == Server.bootstrapPath)
            #expect(try TailnetLockStore(directory: directory).load()?.head == world.head)
        }
    }
}
