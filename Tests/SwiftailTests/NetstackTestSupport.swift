// `.inProcess` 노드 시험의 공용 도우미: 피어를 고를 수 있는 netmap, 제어 서버 없이 돌린 노드, 자기 주소로 맺은 연결 한 쌍.
//
// 노드는 제어 서버가 없는 루프백 포트로 `run()`을 돌리고(등록은 끝없이 다시 시도한다), 시험이 엔진을 직접 만들고 netmap을
// 적용한다. 자기 주소로 간 패킷은 엔진이 되돌리므로(터널 계약 동작 L) 노드 하나가 듣는 쪽과 거는 쪽이 된다. 피어 주소로 건
// 연결의 SYN은 `Magicsock`이 없어 나가지 않는다(맺어지지 않는 연결을 만들 때 쓴다).

import CryptoKit
import Foundation
import SwiftailBase
import SwiftailControl
import SwiftailEngine
import Testing
@testable import Swiftail

enum NetstackTestSupport {
    struct Peer {
        var id: Int64
        var key: UInt8
        var name: String
        var addresses: [String]
    }

    static let phone = Peer(
        id: 2, key: 0x22, name: "rd-phone-1a2b3c4d.tail0001.ts.net.", addresses: ["100.64.0.2/32", "fd7a:115c:a1e0::2/128"])

    /// 자기 노드(ID 1, `rd-mac-1a2b3c4d.tail0001.ts.net.`)와 `peers`의 netmap. 피어는 홈 DERP 1에 있어 데이터면에 오른다.
    static func netmap(
        selfAddresses: [String] = ["100.64.0.1/32", "fd7a:115c:a1e0::1/128"], peers: [Peer] = []
    ) throws -> Netmap {
        func list(_ values: [String]) -> String { values.map { "\"\($0)\"" }.joined(separator: ",") }
        let selfNode = #"{"ID":1,"StableID":"nStable1","Name":"\#(NodeTestSupport.selfName)","User":101,"#
            + #""Key":"\#(NodeTestSupport.nodeKey(0x11))","Addresses":[\#(list(selfAddresses))],"MachineAuthorized":true}"#
        let peerList = peers.map { peer in
            #"{"ID":\#(peer.id),"Name":"\#(peer.name)","User":101,"Key":"\#(NodeTestSupport.nodeKey(peer.key))","#
                + #""Addresses":[\#(list(peer.addresses))],"AllowedIPs":[\#(list(peer.addresses))],"HomeDERP":1}"#
        }
        let json = #"{"Node":\#(selfNode),"Peers":[\#(peerList.joined(separator: ","))],"Domain":"tail0001.ts.net"}"#
        let response = try JSONDecoder().decode(MapResponse.self, from: Data(json.utf8))
        var session = MapSession()
        return try #require(try session.apply(response, receivedAt: Date()).netmap)
    }

    /// `.inProcess` 노드를 돌리고 `netmap`을 적용해 `.running`으로 만든 뒤 `body`에 넘긴다. 끝나면 `run()`을 멈춘다.
    static func withRunningNode(
        _ netmap: Netmap, _ body: (TailnetNode) async throws -> Void
    ) async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            let node = try TailnetNode(
                configuration: try NodeTestSupport.configuration(stateDirectory: directory), device: .inProcess)
            let run = Task { try await node.run() }
            do {
                try await waitUntil("run()이 시작됨") { await node.isRunning }
                await node.prepareForTesting(netmap)
                try await body(node)
            } catch {
                run.cancel()
                _ = await run.result
                throw error
            }
            run.cancel()
            _ = await run.result
        }
    }

    /// 자기 주소로 건 연결 한 쌍. 리스너를 함께 돌려준다(버리면 닫힌다).
    static func connectedPair(
        _ node: TailnetNode, port: UInt16 = 9_000, host: String = "100.64.0.1"
    ) async throws -> (client: TailnetConnection, server: TailnetConnection, listener: TailnetListener) {
        let listener = try await node.listen(port: port)
        let client = try await node.connect(to: host, port: port)
        var connections = listener.makeAsyncIterator()
        let server = try #require(await connections.next())
        return (client, server, listener)
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

    /// `length`바이트의 정해진 무늬.
    static func pattern(_ length: Int, seed: UInt8 = 0) -> [UInt8] {
        (0..<length).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ Int(seed)) }
    }

    /// `length`바이트를 다 읽는다. 그 전에 끝나면 읽은 만큼이다.
    static func read(_ length: Int, from connection: TailnetConnection) async throws -> [UInt8] {
        var received: [UInt8] = []
        while received.count < length, let chunk = try await connection.read() {
            received += chunk
        }
        return received
    }

    /// `body`가 던진 `ConnectionError`. 던지지 않으면 nil. 다른 오류는 시험 실패다(`Task.value`는 타입 없는 오류를 던진다).
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

    func isReading(_ connection: TailnetConnection) -> Bool {
        netstack?.connections[connection.id]?.readWaiter != nil
    }

    func isWriting(_ connection: TailnetConnection) -> Bool {
        netstack?.connections[connection.id]?.writeWaiter != nil
    }

    func isAccepting(_ listener: TailnetListener) -> Bool {
        listenerRecords[listener.token]?.waiter != nil
    }

    /// 응용이 쥐었거나 거는 중인 연결의 수.
    var trackedConnectionCount: Int {
        netstack?.connections.count ?? 0
    }

    /// 거는 중인 연결이 맺어지기를 기다리고 있다.
    var isConnecting: Bool {
        netstack?.connections.values.contains { $0.writeWaiter != nil && !$0.isEstablished } ?? false
    }
}
