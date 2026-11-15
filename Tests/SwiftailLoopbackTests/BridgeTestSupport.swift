// 다리 시험의 공용 도우미: 제어 서버 없이 돌린 `.inProcess` 노드, 자기 주소로 맺은 tailnet 연결 한 쌍, 다리를 건 연결.
//
// `Tests/SwiftailTests/NetstackTestSupport.swift`·`WhoIsTestSupport.swift`와 같은 방식이다. 그 파일들은 `SwiftailTests`
// 타깃 안에 있어 쓸 수 없으므로 필요한 만큼만 따로 둔다. 노드는 제어 서버가 없는 루프백 포트로 `run()`을 돌리고(등록은
// 끝없이 다시 시도한다), 시험이 엔진을 직접 만들고 netmap을 적용한다. 자기 주소로 간 패킷은 엔진이 되돌리므로 노드 하나가
// 듣는 쪽과 거는 쪽이 된다. 듣는 쪽이 받은 연결의 상대 주소는 자기 주소이고, `whoIs`는 자기 노드의 신원을 준다.

import CryptoKit
import Foundation
import SwiftailBase
import SwiftailControl
import SwiftailEngine
import Synchronization
import Testing
@testable import Swiftail
@testable import SwiftailLoopback

enum BridgeTestSupport {
    static let selfIdentity = PeerIdentity(
        stableID: "nStableSelf", name: "rd-mac-1a2b3c4d.tail0001.ts.net", computedName: "rd-mac-1a2b3c4d",
        loginName: "alice@example.com")

    /// 자기 노드(`rd-mac-1a2b3c4d`)만 있는 netmap. `withProfile`이 거짓이면 사용자 프로필이 없어 `whoIs`가 nil이다.
    static func netmap(
        selfAddresses: [String] = ["100.64.0.1/32", "fd7a:115c:a1e0::1/128"], withProfile: Bool = true
    ) throws -> Netmap {
        let addresses = selfAddresses.map { "\"\($0)\"" }.joined(separator: ",")
        let key = "nodekey:" + [UInt8](repeating: 0x11, count: 32).hex
        let selfNode = #"{"ID":1,"StableID":"nStableSelf","Name":"rd-mac-1a2b3c4d.tail0001.ts.net.","User":101,"#
            + #""Key":"\#(key)","Addresses":[\#(addresses)],"MachineAuthorized":true}"#
        let profiles = withProfile ? #"{"ID":101,"LoginName":"alice@example.com"}"# : ""
        let json = #"{"Node":\#(selfNode),"Peers":[],"UserProfiles":[\#(profiles)],"Domain":"tail0001.ts.net"}"#
        let response = try JSONDecoder().decode(MapResponse.self, from: Data(json.utf8))
        var session = MapSession()
        return try #require(try session.apply(response, receivedAt: Date()).netmap)
    }

    /// `.inProcess` 노드를 돌리고 `netmap`을 적용해 `.running`으로 만든 뒤 `body`에 넘긴다. `body`가 받는 함수는 노드의
    /// `run()`을 멈추고 끝날 때까지 기다린다. 끝나면(이미 멈추지 않았다면) 멈춘다.
    static func withRunningNode(
        _ netmap: Netmap, _ body: (TailnetNode, _ stop: @escaping @Sendable () async -> Void) async throws -> Void
    ) async throws {
        let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-bridge-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let configuration = NodeConfiguration(
            stateDirectory: directory, hostname: "rd-mac-1a2b3c4d",
            controlURL: try #require(URL(string: "http://127.0.0.1:9")))
        let node = try TailnetNode(configuration: configuration, device: .inProcess)
        // 시험이 멈추기 전에 `run()`이 스스로 끝나면 그 까닭을 남긴다(노드가 멈춘 것을 다리의 잘못으로 읽지 않게).
        let stopping = Mutex(false)
        let run = Task {
            do throws(NodeError) {
                try await node.run()
            } catch {
                if !stopping.withLock({ $0 }) { Issue.record("시험 중에 run()이 끝났다: \(error)") }
            }
        }
        let stop: @Sendable () async -> Void = {
            stopping.withLock { $0 = true }
            run.cancel()
            _ = await run.result
        }
        do {
            try await waitUntil("run()이 시작됨") { await node.isRunning }
            await node.prepareForTesting(netmap)
            try await body(node, stop)
        } catch {
            await stop()
            throw error
        }
        await stop()
    }

    /// 자기 주소로 건 연결 한 쌍. `server`가 듣는 쪽이 받은 연결이고 다리에 넘긴다. 리스너를 함께 돌려준다(버리면 닫힌다).
    static func connectedPair(
        _ node: TailnetNode, port: UInt16 = 9_000
    ) async throws -> (client: TailnetConnection, server: TailnetConnection, listener: TailnetListener) {
        let listener = try await node.listen(port: port)
        let client = try await node.connect(to: "100.64.0.1", port: port)
        var connections = listener.makeAsyncIterator()
        let server = try #require(await connections.next())
        return (client, server, listener)
    }

    /// 다리가 이은 연결 하나: tailnet의 거는 쪽(`client`), 루프백 서버가 받은 연결(`peer`), 돌고 있는 `forward`.
    struct Bridged {
        var client: TailnetConnection
        var server: TailnetConnection
        var listener: TailnetListener
        var peer: PeerConnection
        var forwarding: Task<LoopbackBridgeError?, Never>

        /// `forward`가 돌아올 때까지 기다린다. 던진 오류, 정상으로 돌아왔으면 nil. 기다리던 Task가 취소되면(시험의 기한)
        /// `forward`를 취소한다.
        func finished() async -> LoopbackBridgeError? {
            let forwarding = forwarding
            return await withTaskCancellationHandler { await forwarding.value } onCancel: { forwarding.cancel() }
        }
    }

    /// `port`에서 받은 tailnet 연결을 다리로 `server`에 잇는다.
    static func bridge(
        _ node: TailnetNode, _ bridge: LoopbackBridge, to server: PlainLoopbackServer, port: UInt16 = 9_000
    ) async throws -> Bridged {
        let pair = try await connectedPair(node, port: port)
        let forwarding = forward(pair.server, with: bridge, toLoopbackPort: server.port)
        let peer = try await server.next()
        return Bridged(client: pair.client, server: pair.server, listener: pair.listener, peer: peer, forwarding: forwarding)
    }

    /// `forward`를 돌리는 Task. 던진 오류, 정상으로 돌아왔으면 nil.
    static func forward(
        _ connection: TailnetConnection, with bridge: LoopbackBridge, toLoopbackPort port: UInt16
    ) -> Task<LoopbackBridgeError?, Never> {
        Task {
            do throws(LoopbackBridgeError) {
                try await bridge.forward(connection, toLoopbackPort: port)
                return nil
            } catch {
                return error
            }
        }
    }

    /// `condition`이 참이 될 때까지 10ms마다 본다. 5초 안에 참이 되지 않으면 실패한다.
    static func waitUntil(_ what: String, _ condition: () async -> Bool) async throws {
        for _ in 0..<500 {
            if await condition() { return }
            try await Task.sleep(for: .milliseconds(10))
        }
        Issue.record("5초 안에 일어나지 않음: \(what)")
        throw CancellationError()
    }

    /// `length`바이트의 정해진 무늬. 주기가 길어 어긋난 조각을 해시가 알아챈다.
    static func pattern(_ length: Int, seed: UInt8 = 0) -> [UInt8] {
        (0..<length).map { UInt8(truncatingIfNeeded: ($0 &* 31) ^ ($0 >> 9) &+ Int(seed)) }
    }

    static func digest(_ bytes: [UInt8]) -> SHA256.Digest {
        SHA256.hash(data: bytes)
    }

    /// 상대가 쓰기를 닫을 때까지 읽는다.
    static func readToEnd(_ connection: TailnetConnection) async throws -> [UInt8] {
        var received: [UInt8] = []
        while let chunk = try await connection.read() { received += chunk }
        return received
    }

    /// `body`가 던진 `ConnectionError`. 던지지 않으면 nil. 다른 오류는 시험 실패다.
    static func error<T>(_ body: () async throws -> T) async -> ConnectionError? {
        do {
            _ = try await body()
            return nil
        } catch let error as ConnectionError {
            return error
        } catch {
            Issue.record("ConnectionError가 아닌 오류: \(error)")
            return nil
        }
    }
}

extension TailnetNode {
    /// 등록을 거치지 않고 엔진을 만들고 netmap을 적용한 뒤 상태를 `.running`으로 만든다.
    func prepareForTesting(_ netmap: Netmap) {
        engine = TailnetEngine(nodeKey: Curve25519.KeyAgreement.PrivateKey(), discoKey: .zero, now: .now, wallClock: Date())
        apply(netmap)
        announce(stateMachine.connected())
    }
}
