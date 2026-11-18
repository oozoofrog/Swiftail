// Shared harness for `ControlClient` tailnet lock tests: a test tailnet (`LockWorld`) and
// one client connected to a fake control server (`LockRun`).

import CryptoKit
import Foundation
import Synchronization
import Testing

import SwiftailBase
@testable import SwiftailControl
@testable import SwiftailTKA

/// A test tailnet with one signing device, authority state initialized from its checkpoint, this node's identity, and three peers.
struct LockWorld: Sendable {
    let signer = LockTesting.Signer()
    /// The stored identity of this node. It already has a node key, so registration completes with that key.
    let identity = NodeIdentity(machineKey: .init(), nodeKey: .init())
    let selfKey: NodePublicKey
    /// Initial server authority state (one checkpoint).
    let authority: Authority
    /// A signed peer (ID 2), an unsigned peer (ID 3), and an unsigned `UnsignedPeerAPIOnly` peer (ID 4).
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

    /// A full map response. If `lock` is nil, includes `TKAInfo` reporting the server's initial head. An empty string omits `TKAInfo`.
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

    /// The `lock` argument for a map response that omits `TKAInfo`.
    static let noTKAInfo = ""
}

extension ControlClient.Timeouts {
    /// Test deadlines that let the closed side's retries be observed immediately.
    static var lockTesting: ControlClient.Timeouts {
        var timeouts = ControlClient.Timeouts()
        timeouts.tkaRequest = .seconds(10)
        timeouts.lockRetry = .milliseconds(50)...Duration.milliseconds(200)
        return timeouts
    }
}

/// One client running against a fake server, with a record of its emitted netmaps.
final class LockRun: Sendable {
    let client: ControlClient
    let server: LockFakeControlServer
    /// State directory.
    let directory: URL
    private let received = Mutex<[Netmap]>([])

    init(client: ControlClient, server: LockFakeControlServer, directory: URL) {
        self.client = client
        self.server = server
        self.directory = directory
    }

    /// All netmaps emitted by the client as events, in emission order.
    var netmaps: [Netmap] { received.withLock { $0 } }
    fileprivate func record(_ netmap: Netmap) { received.withLock { $0.append(netmap) } }

    var storeURL: URL { directory.appending(path: TailnetLockStore.fileName) }

    /// Waits for the newest netmap to satisfy `condition` and returns it.
    func latest(_ what: String, where condition: (Netmap) -> Bool) async throws -> Netmap {
        var matched: Netmap?
        try await eventually(what) {
            matched = netmaps.last.flatMap { condition($0) ? $0 : nil }
            return matched != nil
        }
        return try #require(matched)
    }

    /// The `TKAHead` values sent by state uploads (non-streaming map requests), in receipt order. An omitted value is an empty string.
    var uploadedHeads: [String] {
        server.requests(to: "/machine/map").map(\.object).filter { $0["Stream"] as? Bool != true }.map { $0["TKAHead"] as? String ?? "" }
    }
}

/// Waits for `condition` to become true. Records a test failure and throws when the deadline expires.
func eventually(_ what: String, within duration: Duration = .seconds(30), _ condition: () async -> Bool) async throws {
    let deadline = ContinuousClock.now + duration
    while await !condition() {
        guard ContinuousClock.now < deadline else {
            Issue.record("Did not occur within \(duration): \(what)")
            throw CancellationError()
        }
        try await Task.sleep(for: .milliseconds(5))
    }
}

// Concurrent real Argon2i verification across tests delays their netmap processing. Run only the disablement secret tests in sequence.
@Suite("Control client: Tailnet lock disablement secret", .serialized, .timeLimit(.minutes(3)))
struct LockDisablementTests {
    typealias Server = LockFakeControlServer
}

/// Runs `body` with a client that joined a tailnet with lock enabled and reached `.enforcing`.
func withEnforcingClient(
    _ world: LockWorld, extraPeers: [String] = [], _ body: (LockRun, Netmap) async throws -> Void
) async throws {
    try await withLockClient(world, prepare: { server, _ in
        server.updateLock { $0.authority = world.authority }
        server.setMapResponse(try world.map(extraPeers: extraPeers))
    }) { run in
        try await body(run, try await run.latest("Filtered netmap") { $0.tailnetLock.mode == .enforcing })
    }
}

/// Starts a fake server and client and runs `body`. Cancels `run()` afterward and waits for it to finish.
///
/// - Parameters:
///   - directory: State directory. If supplied, it is kept (the restart test uses it twice).
///   - prepare: Prepares the server and state directory before the server accepts connections. The identity is already stored.
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
