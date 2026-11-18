// `ControlClient`의 tailnet lock 시험이 함께 쓰는 틀: 시험용 tailnet 하나(`LockWorld`)와, 가짜 제어 서버에 붙은
// 클라이언트 한 벌(`LockRun`).

import CryptoKit
import Foundation
import Synchronization
import Testing

import SwiftailBase
@testable import SwiftailControl
@testable import SwiftailTKA

/// 시험용 tailnet: 서명 기기 하나, 그 체크포인트로 시작한 서명 권한 상태, 이 노드의 신원, 피어 셋.
struct LockWorld: Sendable {
    let signer = LockTesting.Signer()
    /// 이 노드의 저장된 신원. node 키가 이미 있어 등록이 그 키로 끝난다.
    let identity = NodeIdentity(machineKey: .init(), nodeKey: .init())
    let selfKey: NodePublicKey
    /// 서버의 처음 서명 권한 상태(체크포인트 하나).
    let authority: Authority
    /// 서명된 피어(ID 2), 서명 없는 피어(ID 3), 서명 없는 `UnsignedPeerAPIOnly` 피어(ID 4).
    let signedPeer = LockTesting.newNodeKey()
    let unsignedPeer = LockTesting.newNodeKey()
    let apiOnlyPeer = LockTesting.newNodeKey()

    init() throws {
        selfKey = try #require(identity.nodePublicKey)
        authority = try Authority(bootstrappingWith: LockTesting.checkpoint(trusting: [signer], signedBy: signer))
    }

    var head: AUMHash { authority.head }

    func peers() throws -> [String] {
        [
            LockTesting.peerJSON(2, key: signedPeer, signature: try signer.signature(for: signedPeer)),
            LockTesting.peerJSON(3, key: unsignedPeer),
            LockTesting.peerJSON(4, key: apiOnlyPeer, apiOnly: true),
        ]
    }

    /// 전체 맵 응답. `lock`이 nil이면 서버의 처음 머리를 알리는 `TKAInfo`를 싣고, 빈 문자열이면 `TKAInfo`를 싣지 않는다.
    func map(
        selfSigned: Bool = true, hasCapability: Bool = true, lock: String? = nil, extraPeers: [String] = [], _ extra: String = ""
    ) throws -> String {
        let signature = selfSigned ? try signer.signature(for: selfKey, rotationKey: identity.lockKey.publicKey) : []
        let lockField = lock ?? LockTesting.tkaInfo(head: head)
        return LockTesting.mapJSON(
            selfNode: LockTesting.selfJSON(key: selfKey, signature: signature, hasCapability: hasCapability),
            peers: try peers() + extraPeers, lock: lockField.isEmpty ? nil : lockField, extra
        )
    }

    /// `TKAInfo`를 싣지 않는 맵 응답의 `lock` 인자.
    static let noTKAInfo = ""
}

extension ControlClient.Timeouts {
    /// 시험용 기한: 닫힌 쪽의 재시도를 곧바로 본다.
    static var lockTesting: ControlClient.Timeouts {
        var timeouts = ControlClient.Timeouts()
        timeouts.tkaRequest = .seconds(10)
        timeouts.lockRetry = .milliseconds(50)...Duration.milliseconds(200)
        return timeouts
    }
}

/// 가짜 서버에 붙어 도는 클라이언트 한 벌과, 그것이 낸 netmap의 기록.
final class LockRun: Sendable {
    let client: ControlClient
    let server: LockFakeControlServer
    /// 상태 디렉터리.
    let directory: URL
    private let received = Mutex<[Netmap]>([])

    init(client: ControlClient, server: LockFakeControlServer, directory: URL) {
        self.client = client
        self.server = server
        self.directory = directory
    }

    /// 클라이언트가 사건으로 낸 netmap 전부. 낸 순서다.
    var netmaps: [Netmap] { received.withLock { $0 } }
    fileprivate func record(_ netmap: Netmap) { received.withLock { $0.append(netmap) } }

    var storeURL: URL { directory.appending(path: TailnetLockStore.fileName) }

    /// 가장 새 netmap이 `condition`에 맞을 때까지 기다려 그것을 돌려준다.
    func latest(_ what: String, where condition: (Netmap) -> Bool) async throws -> Netmap {
        var matched: Netmap?
        try await eventually(what) {
            matched = netmaps.last.flatMap { condition($0) ? $0 : nil }
            return matched != nil
        }
        return try #require(matched)
    }

    /// 상태 올리기(스트림이 아닌 맵 요청)가 실은 `TKAHead`들. 받은 순서이고, 싣지 않았으면 빈 문자열이다.
    var uploadedHeads: [String] {
        server.requests(to: "/machine/map").map(\.object).filter { $0["Stream"] as? Bool != true }.map { $0["TKAHead"] as? String ?? "" }
    }
}

/// `condition`이 참이 될 때까지 기다린다. 기한을 넘기면 시험 실패로 적고 던진다.
func eventually(_ what: String, within duration: Duration = .seconds(30), _ condition: () async -> Bool) async throws {
    let deadline = ContinuousClock.now + duration
    while await !condition() {
        guard ContinuousClock.now < deadline else {
            Issue.record("\(duration) 안에 일어나지 않았다: \(what)")
            throw CancellationError()
        }
        try await Task.sleep(for: .milliseconds(5))
    }
}

// 실제 Argon2i 검증을 여러 시험에서 겹쳐 돌리면 서로의 netmap 처리가 밀린다. 끄기 비밀 시험끼리만 차례로 돈다.
@Suite("제어 클라이언트: tailnet lock 끄기 비밀", .serialized, .timeLimit(.minutes(3)))
struct LockDisablementTests {
    typealias Server = LockFakeControlServer
}

/// lock이 켜진 tailnet에 붙어 `.enforcing`이 된 클라이언트로 `body`를 돌린다.
func withEnforcingClient(
    _ world: LockWorld, extraPeers: [String] = [], _ body: (LockRun, Netmap) async throws -> Void
) async throws {
    try await withLockClient(world, prepare: { server, _ in
        server.updateLock { $0.authority = world.authority }
        server.setMapResponse(try world.map(extraPeers: extraPeers))
    }) { run in
        try await body(run, try await run.latest("거른 netmap") { $0.tailnetLock.mode == .enforcing })
    }
}

/// 가짜 서버와 클라이언트를 띄우고 `body`를 돌린다. 끝나면 `run()`을 취소하고 끝날 때까지 기다린다.
///
/// - Parameters:
///   - directory: 상태 디렉터리. 주면 지우지 않는다(다시 시작하는 시험이 두 번 쓴다).
///   - prepare: 서버가 연결을 받기 전에 서버와 상태 디렉터리를 준비한다. 신원은 이미 저장되어 있다.
func withLockClient<T: Sendable>(
    _ world: LockWorld,
    directory: URL? = nil,
    timeouts: ControlClient.Timeouts = .lockTesting,
    prepare: (LockFakeControlServer, URL) throws -> Void,
    _ body: (LockRun) async throws -> T
) async throws -> T {
    let server = try LockFakeControlServer()
    defer { server.close() }
    let stateDirectory = directory ?? FileManager.default.temporaryDirectory.appending(path: "swiftail-lock-\(UUID().uuidString)")
    defer {
        if directory == nil {
            try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: stateDirectory.path)
            try? FileManager.default.removeItem(at: stateDirectory)
        }
    }
    let store = NodeIdentityStore(directory: stateDirectory)
    try store.save(world.identity)
    try prepare(server, stateDirectory)
    let url = try await server.start()
    let client = ControlClient(
        configuration: .init(serverURL: url, hostname: "rd-mac-1a2b3c4d"), identityStore: store, timeouts: timeouts
    )
    let run = LockRun(client: client, server: server, directory: stateDirectory)
    let observing = Task {
        for await event in client.events {
            if case .netmap(let netmap) = event { run.record(netmap) }
        }
    }
    let running = Task { try await client.run() }
    let outcome: Result<T, any Error>
    do {
        outcome = .success(try await body(run))
    } catch {
        outcome = .failure(error)
    }
    running.cancel()
    _ = await running.result
    await observing.value
    return try outcome.get()
}
