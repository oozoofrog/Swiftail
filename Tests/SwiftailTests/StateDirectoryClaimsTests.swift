import Foundation
import Testing
@testable import Swiftail

/// 상태 디렉터리 중복 거절. 계약 `docs/contracts/SwiftailTunnel.md` 동작 P 3·C 4, 시험 목록 8.
@Suite("상태 디렉터리 표")
struct StateDirectoryClaimsTests {
    @Test("같은 경로는 표기가 달라도 둘째가 거절되고, 첫째가 풀린 뒤 다시 된다. 다른 경로는 막지 않는다")
    func sameDirectoryTwice() throws {
        let claims = StateDirectoryClaims()
        let plain = URL(filePath: "/var/empty/swiftail-claims/node", directoryHint: .isDirectory)
        let dotted = try #require(URL(string: "file:///var/empty/swiftail-claims/./other/../node/"))
        let other = URL(filePath: "/var/empty/swiftail-claims/other", directoryHint: .isDirectory)

        let first = try #require(claims.claim(plain))
        #expect(claims.claim(dotted) == nil)
        #expect(claims.claim(plain) == nil)
        #expect(claims.claim(other) != nil)
        claims.release(first)
        #expect(claims.claim(dotted) != nil)
    }

    @Test("심볼릭 링크를 거친 경로와 직접 경로는 디렉터리가 생기기 전에도 뒤에도 같은 것으로 잡힌다")
    func sameDirectoryThroughSymlink() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            let real = directory.appending(path: "real")
            let link = directory.appending(path: "link")
            try FileManager.default.createDirectory(at: real, withIntermediateDirectories: true)
            try FileManager.default.createSymbolicLink(at: link, withDestinationURL: real)
            let claims = StateDirectoryClaims()

            // 생기기 전: 링크를 거친 경로로 쥐면 디렉터리가 만들어지고, 직접 경로도 같은 것으로 본다.
            let throughLink = link.appending(path: "state")
            let direct = real.appending(path: "state")
            let first = try claims.claimCreating(throughLink)
            #expect(try FileManager.default.attributesOfItem(atPath: direct.path)[.posixPermissions] as? Int == 0o700)
            for same in [direct, throughLink] {
                #expect(throws: NodeError.self) { try claims.claimCreating(same) }
                #expect(claims.claim(same) == nil)
            }

            // 푼 뒤(디렉터리는 이제 있다): 직접 경로로 쥐어도 링크를 거친 경로가 같은 것이다.
            claims.release(first)
            let second = try claims.claimCreating(direct)
            #expect(claims.claim(throughLink) == nil)

            // 차지한 뒤 링크가 다른 곳을 가리키게 되어도, 받은 열쇠로 풀면 쥔 것이 풀린다.
            try FileManager.default.removeItem(at: link)
            try FileManager.default.createSymbolicLink(at: link, withDestinationURL: directory.appending(path: "elsewhere"))
            claims.release(second)
            #expect(claims.claim(direct) != nil)
        }
    }

    @Test("노드 둘이 같은 디렉터리를 하나는 링크로, 하나는 직접 경로로 받아도 둘째의 run()은 stateDirectoryInUse다")
    func nodeRejectsDirectoryClaimedThroughSymlink() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            let real = directory.appending(path: "real")
            let link = directory.appending(path: "link")
            try FileManager.default.createDirectory(at: real, withIntermediateDirectories: true)
            try FileManager.default.createSymbolicLink(at: link, withDestinationURL: real)
            // 첫 노드가 아직 없는 디렉터리를 링크를 거쳐 쥐고 있다.
            let claim = try StateDirectoryClaims.shared.claimCreating(link.appending(path: "state"))
            defer { StateDirectoryClaims.shared.release(claim) }

            let node = try TailnetNode(
                configuration: try NodeTestSupport.configuration(stateDirectory: real.appending(path: "state")))
            do throws(NodeError) {
                try await node.run()
                Issue.record("run()이 던지지 않았다")
            } catch {
                guard case .stateDirectoryInUse = error else {
                    Issue.record("기대 stateDirectoryInUse, 실제 \(error)")
                    return
                }
            }
        }
    }

    @Test("다른 노드가 돌고 있는 디렉터리면 run()이 파일을 만들기 전에 stateDirectoryInUse로 끝나고 차지를 남기지 않는다")
    func nodeRejectsClaimedDirectory() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            let claim = try #require(StateDirectoryClaims.shared.claim(directory))
            let node = try TailnetNode(configuration: try NodeTestSupport.configuration(stateDirectory: directory))
            do throws(NodeError) {
                try await node.run()
                Issue.record("run()이 던지지 않았다")
            } catch {
                guard case .stateDirectoryInUse = error else {
                    Issue.record("기대 stateDirectoryInUse, 실제 \(error)")
                    return
                }
            }
            #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path).isEmpty)
            #expect(await NodeTestSupport.drain(node.events).isEmpty, "run()이 끝나면 흐름이 끝난다")
            StateDirectoryClaims.shared.release(claim)
            let again = try #require(StateDirectoryClaims.shared.claim(directory), "거절된 노드는 차지를 남기지 않는다")
            StateDirectoryClaims.shared.release(again)
        }
    }
}
