import CryptoKit
import Foundation
import Network
import Synchronization
import Testing

import SwiftailControl
@testable import Swiftail

/// `TailnetNode.logOut()`의 독립 검토가 보탠 시험. 계약 `docs/contracts/SwiftailHost.md` "로그아웃" 동작 O1·O6.
/// 잘못된 때에 불렸을 때(겹친 `logOut()`, 도는 `run()`, 취소)와 상태 디렉터리의 차지가 모든 길에서 풀리는지를 본다.
@Suite("노드: 로그아웃(검토)", .timeLimit(.minutes(1)))
struct NodeLogoutReviewTests {
    /// 등록한 적이 있는 신원을 `directory`에 저장하고 파일의 바이트를 돌려준다.
    private static func saveRegisteredIdentity(in directory: URL) throws -> Data {
        var identity = NodeIdentity()
        identity.nodeKey = Curve25519.KeyAgreement.PrivateKey()
        try NodeIdentityStore(directory: directory).save(identity)
        return try identityFile(in: directory)
    }

    /// 상태 디렉터리의 하나뿐인 파일(신원 파일)의 바이트.
    private static func identityFile(in directory: URL) throws -> Data {
        let names = try FileManager.default.contentsOfDirectory(atPath: directory.path)
        try #require(names.count == 1, "신원 파일 말고 다른 파일이 생겼다: \(names.count)개")
        return try Data(contentsOf: directory.appending(path: names[0]))
    }

    private static func logOutError(_ node: TailnetNode) async -> NodeError? {
        do throws(NodeError) {
            try await node.logOut()
            return nil
        } catch {
            return error
        }
    }

    /// 연결은 받되 아무것도 답하지 않는 루프백 리스너를 띄우고 그 주소와 받은 연결 수를 넘긴다.
    private static func withSilentServer<T>(_ body: (URL, @Sendable () -> Int) async throws -> T) async throws -> T {
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: .any)
        let listener = try NWListener(using: parameters)
        let connections = Mutex<[NWConnection]>([])
        listener.newConnectionHandler = { connection in
            connections.withLock { $0.append(connection) }
            connection.start(queue: .global())
        }
        defer {
            listener.cancel()
            for connection in connections.withLock({ $0 }) { connection.cancel() }
        }
        let port = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<UInt16, any Error>) in
            let once = Mutex<CheckedContinuation<UInt16, any Error>?>(continuation)
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    if let port = listener.port?.rawValue { once.withLock { $0.take() }?.resume(returning: port) }
                case .failed(let error):
                    once.withLock { $0.take() }?.resume(throwing: error)
                default:
                    break
                }
            }
            listener.start(queue: .global())
        }
        return try await body(try #require(URL(string: "http://127.0.0.1:\(port)")), { connections.withLock { $0.count } })
    }

    @Test("서버에 닿지 못해 던져도 차지를 남기지 않고 신원 파일은 그대로다")
    func throwingReleasesClaim() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            let before = try Self.saveRegisteredIdentity(in: directory)
            // 127.0.0.1:9에는 제어 서버가 없다.
            let node = try TailnetNode(configuration: try NodeTestSupport.configuration(stateDirectory: directory))
            guard case .control(.connection)? = await Self.logOutError(node) else {
                Issue.record("control(.connection)이 아니다")
                return
            }
            let claim = try #require(StateDirectoryClaims.shared.claim(directory), "던진 logOut()은 차지를 남기지 않는다")
            StateDirectoryClaims.shared.release(claim)
            #expect(try Self.identityFile(in: directory) == before)
        }
    }

    @Test("겹친 logOut()은 stateDirectoryInUse이고(같은 노드든 다른 노드든), 취소한 logOut()은 차지를 풀며, 그동안 시작한 run()도 거절된다")
    func overlapAndCancellation() async throws {
        try await Self.withSilentServer { url, connectionCount in
            try await NodeTestSupport.withTemporaryDirectory { directory in
                let before = try Self.saveRegisteredIdentity(in: directory)
                let configuration = NodeConfiguration(stateDirectory: directory, hostname: "rd-mac-1a2b3c4d", controlURL: url)
                let node = try TailnetNode(configuration: configuration)
                let other = try TailnetNode(configuration: configuration)

                let first = Task { await Self.logOutError(node) }
                // 첫 logOut()이 서버에 닿았으면 디렉터리를 쥐고 `/key`의 답을 기다리는 중이다.
                let deadline = ContinuousClock.now + .seconds(5)
                while connectionCount() == 0, ContinuousClock.now < deadline { try await Task.sleep(for: .milliseconds(10)) }
                try #require(connectionCount() == 1)

                for overlapping in [node, other] {
                    guard case .stateDirectoryInUse? = await Self.logOutError(overlapping) else {
                        Issue.record("겹친 logOut()이 stateDirectoryInUse가 아니다")
                        return
                    }
                }
                // logOut()이 도는 동안 시작한 run()도 같은 오류로 끝난다(파일·소켓을 열기 전).
                do throws(NodeError) {
                    try await other.run()
                    Issue.record("run()이 던지지 않았다")
                } catch {
                    guard case .stateDirectoryInUse = error else {
                        Issue.record("run()이 stateDirectoryInUse가 아니다: \(error)")
                        return
                    }
                }
                #expect(connectionCount() == 1, "거절된 호출은 서버에 닿지 않는다")

                let start = ContinuousClock.now
                first.cancel()
                guard case .control(.connection)? = await first.value else {
                    Issue.record("취소한 logOut()이 control(.connection)이 아니다")
                    return
                }
                #expect(ContinuousClock.now - start < .seconds(3), "취소는 기한(10초)을 기다리지 않는다")
                let claim = try #require(StateDirectoryClaims.shared.claim(directory), "취소한 logOut()은 차지를 남기지 않는다")
                StateDirectoryClaims.shared.release(claim)
                #expect(try Self.identityFile(in: directory) == before)
            }
        }
    }

    @Test("같은 노드의 run()이 도는 중이거나 방금 취소돼 아직 끝나지 않았으면 stateDirectoryInUse이고, 끝난 뒤에는 된다")
    func whileRunning() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            // 127.0.0.1:9: run()은 연결에 실패하며 물러났다가 다시 시도한다(등록하지 못하므로 node 키는 생기지 않는다).
            let node = try TailnetNode(configuration: try NodeTestSupport.configuration(stateDirectory: directory))
            let run = Task { () -> NodeError? in
                do throws(NodeError) {
                    try await node.run()
                    return nil
                } catch {
                    return error
                }
            }
            // 차지 표를 직접 찔러 보지 않는다(그 순간의 run()이 거절당한다). 노드가 돈다고 할 때까지 기다린다.
            let deadline = ContinuousClock.now + .seconds(5)
            while !(await node.isRunning) {
                try #require(ContinuousClock.now < deadline, "run()이 돌지 않는다")
                try await Task.sleep(for: .milliseconds(10))
            }
            guard case .stateDirectoryInUse? = await Self.logOutError(node) else {
                Issue.record("도는 중의 logOut()이 stateDirectoryInUse가 아니다")
                return
            }

            run.cancel()
            // 취소 직후의 logOut()은 run()이 아직 끝나지 않았으면 거절되고, 끝났으면 된다. 어느 쪽이든 그 밖의 오류는 없다.
            switch await Self.logOutError(node) {
            case nil, .stateDirectoryInUse?: break
            case let error?: Issue.record("취소 직후의 logOut(): \(error)")
            }
            #expect(await run.value == nil)
            // run()이 끝난 뒤: 등록한 적이 없어 아무것도 보내지 않고 돌아온다.
            #expect(await Self.logOutError(node) == nil)
            let claim = try #require(StateDirectoryClaims.shared.claim(directory))
            StateDirectoryClaims.shared.release(claim)
        }
    }
}
