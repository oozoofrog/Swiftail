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

        #expect(claims.claim(plain))
        #expect(!claims.claim(dotted))
        #expect(!claims.claim(plain))
        #expect(claims.claim(other))
        claims.release(dotted)
        #expect(claims.claim(plain))
    }

    @Test("다른 노드가 돌고 있는 디렉터리면 run()이 파일을 만들기 전에 stateDirectoryInUse로 끝나고 차지를 남기지 않는다")
    func nodeRejectsClaimedDirectory() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            #expect(StateDirectoryClaims.shared.claim(directory))
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
            StateDirectoryClaims.shared.release(directory)
            #expect(StateDirectoryClaims.shared.claim(directory), "거절된 노드는 차지를 남기지 않는다")
            StateDirectoryClaims.shared.release(directory)
        }
    }
}
