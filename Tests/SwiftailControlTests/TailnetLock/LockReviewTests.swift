// 독립 검토(TL-11b)의 재현 시험. 제어 서버를 믿지 않는 위협 모델로 `ControlClient`의 tailnet lock 절차를 본다.
//
// - "결함"이라고 적은 시험은 지금 실패한다. 그것이 발견이다.
// - "지금 동작"이라고 적은 시험은 통과한다. 계약이 그렇게 정했지만 검토가 계약의 문제로 본 것을 기록한다.
// - 나머지는 검토가 확인한 닫힌 쪽의 성질이다(통과).
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

    /// 결함(높음): 서버의 재서명 요청이 NL 키의 서명 오라클이 된다.
    ///
    /// 서버는 `RegisterResponse.NodeKeySignature`에 무엇이든 넣을 수 있다. 노드는 그것을 검증하지 않고 `ResignNKS`에 넣고,
    /// 사슬이 node 키를 15개 넘게 담으면 "줄이기"가 **서버가 고른 `Pubkey`들**에 NL 키로 rotation 서명을 새로 만든다
    /// (`Sources/SwiftailTKA/Signatures/Resigning.swift`의 `trimmingRotationChain`, Go `tka/sig.go:393-437`).
    /// 서버가 이 노드의 진짜 direct 서명(서명 기기가 `tailscale lock sign <nodeKey> <lockKey>`로 만든 것) 위에 가짜 rotation
    /// 15겹을 얹어 보내면, 돌아온 등록 요청 안에 **공격자의 node 키를 인가하는 사슬**이 들어 있다. 그 사슬은 서명 기기의
    /// 신뢰 키에서 시작하고 이 노드의 NL 키로 이어져, lock을 지키는 모든 노드(Go 포함)의 검증을 통과한다.
    @Test("결함: 서버가 고른 node 키에 NL 키로 서명해 주지 않는다(재서명 요청의 사슬 줄이기)")
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

        // 노드가 재서명 요청에 답해 보낸 두 번째 등록 요청.
        let requests = server.requests.filter { $0.path == "/machine/register" }
        #expect(requests.count == 2)
        let body = Data(try #require(requests.last).body)
        let second = try #require(try JSONSerialization.jsonObject(with: body) as? [String: Any])
        guard let text = second["NodeKeySignature"] as? String, let bytes = Data(base64Encoded: text) else {
            // 서명 없이 등록했다면 오라클이 아니다(권하는 고침의 한 모양).
            return
        }
        // 그 서명에서 한 겹을 벗기면 공격자의 키에 대한 사슬이 나온다. 서버는 이것을 공격자 노드의 `KeySignature`로 쓴다.
        let sent = try NodeKeySignature(decoding: [UInt8](bytes))
        let leaked = try #require(sent.nested)
        #expect(leaked.publicKey != attackerKey.binaryForm, "서버가 고른 node 키가 NL 키로 서명되어 서버로 돌아갔다")
        #expect(throws: TKAError.unauthorized, "공격자의 node 키가 이 tailnet의 서명 권한 상태로 인가된다") {
            try lock.state.authorize(attackerKey, keySignature: leaked.serialized())
        }
        // lock을 지키는 다른 노드가 받는 netmap: 서버가 이 노드(옛 키, 진짜 서명)와 공격자 노드(새어 나간 사슬)를 함께 싣는다.
        // 공격자 노드는 남고, 진짜 노드는 그 사슬의 "이전 키"라서 회전으로 낡은 키로 빠진다(자리를 빼앗긴다).
        let admitted = lock.state.admitted([
            PeerCredential(nodeKey: ownKey, keySignature: direct, unsignedPeerAPIOnly: false),
            PeerCredential(nodeKey: attackerKey, keySignature: leaked.serialized(), unsignedPeerAPIOnly: false),
        ])
        #expect(admitted == [true, false], "진짜 노드가 빠지고 공격자 노드가 남는다")
    }

    // MARK: 끄기 비밀

    /// 결함(낮음): 거절한 끄기 비밀의 기억이 하나뿐이라, 서버가 비밀 둘을 번갈아 주면 매번 Argon2i(16MiB)를 다시 돈다.
    /// 계약 동작 O6은 "같은 비밀을 다시 받으면 KDF를 다시 돌리지 않는다"이다. KDF는 actor를 막는다.
    @Test("결함: 서버가 틀린 끄기 비밀 둘을 번갈아 보내도 KDF는 비밀마다 한 번만 돈다(동작 O6)")
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

    // MARK: 로컬 상태가 없을 때 (계약 문제)

    /// 지금 동작(계약 문제, 낮음): 로컬 상태가 없는 노드에 서버가 `TKAInfo`(꺼졌다는 표시 없음)를 읽히지 않는 `Head`와 함께
    /// 실으면, 계약 동작 N1은 그것을 "꺼짐"으로 읽는다. capability가 있어도 부트스트랩하지 않고 모든 피어를 `.disabled`로 낸다.
    /// lock을 알리는 응답을 해석하지 못한 것이 "lock 없음"이 되는 열린 쪽이다. Go가 읽는 머리 텍스트 가운데 Swiftail이
    /// 거절하는 것(동작 D10의 줄바꿈)에서는 Go 노드가 부트스트랩해 거르는 동안 Swiftail 노드는 거르지 않는다.
    @Test("지금 동작: 로컬 상태 없이 읽히지 않는 Head를 받으면 lock 없음(.disabled)으로 모든 피어를 낸다(동작 N1)")
    func unreadableHeadWithoutLocalStateIsOpen() async throws {
        let world = try LockWorld()
        // Go는 받고(줄바꿈을 지우고 읽는다) Swiftail은 거절하는 머리 텍스트: 50자 + CRLF.
        let goReadable = String(world.head.text.prefix(50)) + "\\r\\n"
        try await withLockClient(world, prepare: { server, _ in
            server.updateLock { $0.authority = world.authority }
            server.setMapResponse(try world.map(lock: #""TKAInfo":{"Head":"\#(goReadable)"}"#))
        }) { run in
            let netmap = try await run.latest("첫 netmap") { _ in true }
            #expect(netmap.tailnetLock == TailnetLockStatus())
            #expect(netmap.peers.map(\.id) == [2, 3, 4], "서명 없는 피어(ID 3)가 그대로 나간다")
            #expect(run.server.tkaPaths.isEmpty, "부트스트랩을 시도하지 않는다")
        }
    }

    /// 지금 동작(참고): `.unverified`(사용자 결정 U1)는 서버가 정직할 때의 보호다. 로컬 상태가 없는 동안에는 서버가
    /// "꺼졌다"고 고쳐 말하는 것만으로 풀린다. 끄기 비밀도 RPC도 필요 없다. 첫 신뢰가 TOFU인 것의 귀결이고 Go도 같다.
    @Test("지금 동작: 부트스트랩이 실패한 .unverified는 서버가 Disabled를 알리면 비밀 없이 풀린다")
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
}
