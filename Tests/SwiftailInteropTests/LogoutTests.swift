// 로그아웃 관문(testcontrol): 계약 `docs/contracts/SwiftailHost.md` "로그아웃"의 "시험과 관문" 상호 운용 항목.
//
// 상대는 `tailnet` 도구다. testcontrol 사본은 과거의 `Expiry`를 실은 등록을 그 node 키의 만료로 받는다(README "testcontrol 사본").
// Go 피어(go-peer-b)의 로그아웃을 같은 서버에 보내 두 요청을 견준다.

import Foundation
import Swiftail
import Testing

@Suite("로그아웃 관문: testcontrol", .enabled(if: tailnetBinary != nil, "SWIFTAIL_TAILNET가 없어 로그아웃 관문을 건너뜁니다"),
       .serialized, .timeLimit(.minutes(5)))
struct LogoutGateTests {
    /// Go `time.Unix(123, 0)`.
    private static let logoutExpiry = "1970-01-01T00:02:03Z"

    @Test("logOut() 뒤 서버의 그 노드 키가 만료되고(요청은 Go 로그아웃과 같은 모양), 다른 피어도 그 만료를 받으며, 같은 상태 디렉터리로 다시 run()하면 새 키를 등록한 뒤 nodeKeyExpired로 끝난다")
    func logOut() async throws {
        let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-logout-\(UUID().uuidString)")
        let tool = GoTailnet(temporaryDirectory: directory)
        defer {
            if FileManager.default.fileExists(atPath: directory.path) {
                do { try FileManager.default.removeItem(at: directory) }
                catch { Issue.record("로그아웃 관문 상태 디렉터리 정리 실패: \(redacted(String(describing: error)))") }
            }
        }
        var run: Task<Void, any Error>?
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let ready = try await tool.start()
            let controlURL = try #require(ready.controlURL)
            _ = try await tool.command(.init(cmd: "addPeer", name: "go-peer-a"), expecting: "peer")
            let configuration = NodeConfiguration(stateDirectory: directory, hostname: "rd-mac-1a2b3c4d", controlURL: controlURL)

            // 1. 등록하고 running까지 간 뒤 멈춘다(앱의 순서: run() 취소 → 끝나기를 기다림 → logOut()).
            let node = try TailnetNode(configuration: configuration)
            run = Task { try await node.run() }
            let addresses = try await running(node)
            let nodes = try #require(await tool.command(.init(cmd: "nodes"), expecting: "nodes").nodes)
            let key = try #require(nodes.first { Set($0.addresses) == Set(addresses.map(\.description)) }?.nodeKey)
            #expect(nodes.first { $0.nodeKey == key }?.keyExpiry == "", "등록 직후에는 만료가 없다")
            run?.cancel()
            _ = await run?.result
            run = nil
            await tool.checkpoint("로그아웃: 등록·running 뒤 run() 멈춤")

            // 2. 로그아웃.
            try await node.logOut()
            let afterLogout = try #require(await tool.command(.init(cmd: "nodes"), expecting: "nodes").nodes)
            #expect(afterLogout.first { $0.nodeKey == key }?.keyExpiry == Self.logoutExpiry, "서버 쪽 그 노드의 키가 만료로 보인다")
            let registrations = try #require(await tool.command(.init(cmd: "lockRegistrations"), expecting: "lockRegistrations").registrations)
            let swift = try #require(registrations.last)
            #expect(swift.nodeKey == key, "새 node 키를 만들지 않는다")
            #expect(swift.expiry == Self.logoutExpiry)
            #expect(swift.expiryUnix == 123)
            #expect(!swift.auth)
            #expect(swift.oldNodeKey == "")
            #expect(!swift.nlKey.isEmpty)
            #expect(swift.signature == "none")
            await tool.checkpoint("로그아웃: 서버의 keyExpiry \(Self.logoutExpiry), 요청 하나")

            // 3. 다른 피어(Go)가 본 그 노드: netmap에 남되 키 만료가 그 시각이다.
            let deadline = ContinuousClock.now + .seconds(20)
            var seen: GoTailnet.Event.Node?
            while seen == nil {
                let status = try await tool.command(.init(cmd: "peerStatus", name: "go-peer-a"), expecting: "peerStatus")
                seen = status.peers?.first { $0.nodeKey == key && $0.keyExpiry == Self.logoutExpiry }
                if seen == nil {
                    guard ContinuousClock.now < deadline else { throw GateFailure("go-peer-a가 로그아웃한 노드의 만료를 20초 안에 받지 못함") }
                    try await Task.sleep(for: .milliseconds(100))
                }
            }
            await tool.checkpoint("로그아웃: go-peer-a가 본 그 노드 keyExpiry \(seen?.keyExpiry ?? ""), expired \(seen?.expired.map(String.init) ?? "없음")")

            // 4. 같은 서버에 Go 피어의 로그아웃을 보내 요청을 견준다.
            _ = try await tool.command(.init(cmd: "addPeer", name: "go-peer-b"), expecting: "peer")
            let loggedOut = try await tool.command(.init(cmd: "peerLogout", name: "go-peer-b"), expecting: "peerLogout")
            let all = try #require(await tool.command(.init(cmd: "lockRegistrations"), expecting: "lockRegistrations").registrations)
            let go = try #require(all.last)
            #expect(go.expiryUnix == swift.expiryUnix, "Go와 같은 시각(Go는 로컬 시간대로 적는다: \(go.expiry))")
            #expect(go.auth == swift.auth)
            #expect(go.oldNodeKey == swift.oldNodeKey)
            #expect(go.nlKey.isEmpty == swift.nlKey.isEmpty)
            #expect(go.signature == swift.signature)
            await tool.checkpoint("로그아웃: Go 요청 expiry \(go.expiry), auth \(go.auth), BackendState \(loggedOut.backendState ?? "")")

            // 5. 같은 상태 디렉터리로 다시 run(). 신원 파일은 그대로다(로컬 파일 정리는 앱의 몫이고 앱은 이 경로를 타지 않는다).
            //    기록용이다: testcontrol은 키 교체 때 옛 노드를 복제하며 만료 시각까지 옮기므로, 새 키도 만료로 보여
            //    nodeKeyExpired로 끝난다. 운영 서버의 결과는 이것과 다를 수 있다(계약 "구현하며 정해진 것").
            let again = try TailnetNode(configuration: configuration)
            let rerun = Task { () async -> Result<Void, NodeError> in
                do throws(NodeError) {
                    try await again.run()
                    return .success(())
                } catch {
                    return .failure(error)
                }
            }
            // 끝나지 않으면 60초에 멈추고 아래의 결과 검사가 실패를 적는다.
            let watchdog = Task {
                try? await Task.sleep(for: .seconds(60))
                rerun.cancel()
            }
            var states: [String] = []
            for await event in again.events {
                if case let .stateChanged(state) = event { states.append(String(describing: state)) }
            }
            let result = await rerun.value
            watchdog.cancel()
            let tail = try #require(await tool.command(.init(cmd: "lockRegistrations"), expecting: "lockRegistrations").registrations)
                .dropFirst(all.count)
            await tool.checkpoint("로그아웃 뒤 같은 디렉터리로 run(): 상태 \(states), 결과 \(redacted(String(describing: result))), 등록 \(tail.map { "old=\($0.oldNodeKey.isEmpty ? "없음" : ($0.oldNodeKey == key ? "로그아웃한 키" : "다른 키")) 같은 키=\($0.nodeKey == key)" })")
            guard case .failure(.control(.nodeKeyExpired)) = result else {
                throw GateFailure("다시 run()의 결과가 control(.nodeKeyExpired)가 아님: \(redacted(String(describing: result)))")
            }
            #expect(tail.first?.nodeKey == key && tail.first?.oldNodeKey == "", "처음에는 저장된(로그아웃한) 키로 등록한다")
            #expect(tail.dropFirst().first.map { $0.nodeKey != key && $0.oldNodeKey == key } == true, "만료 응답에 새 키로 바꿔 등록한다")
            await tool.stop()
        } catch {
            run?.cancel()
            _ = await run?.result
            await tool.stop()
            throw GateFailure("\(redacted(String(describing: error)))\n\(await tool.diagnostics())")
        }
    }
}
