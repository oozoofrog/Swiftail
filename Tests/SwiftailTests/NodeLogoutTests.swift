import Foundation
import Testing
@testable import Swiftail

/// `TailnetNode.logOut()`의 시작 검사. 계약 `docs/contracts/SwiftailHost.md` "로그아웃" 동작 O1·O2.
/// 요청의 모양과 응답은 `SwiftailControlTests`의 `LogoutTests`, 서버 쪽 결과는 상호 운용 시험이 본다.
@Suite("노드: 로그아웃")
struct NodeLogoutTests {
    @Test("같은 상태 디렉터리의 run()이 도는 중이면 stateDirectoryInUse이고, 아무것도 만들지 않는다")
    func rejectsClaimedDirectory() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            #expect(StateDirectoryClaims.shared.claim(directory))
            defer { StateDirectoryClaims.shared.release(directory) }
            let node = try TailnetNode(configuration: try NodeTestSupport.configuration(stateDirectory: directory))
            do throws(NodeError) {
                try await node.logOut()
                Issue.record("logOut()이 던지지 않았다")
            } catch {
                guard case .stateDirectoryInUse = error else {
                    Issue.record("기대 stateDirectoryInUse, 실제 \(error)")
                    return
                }
            }
            #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path).isEmpty)
        }
    }

    @Test("등록한 적이 없으면 연결하지 않고 돌아오며, 신원 파일을 만들지 않고 차지를 남기지 않는다")
    func noIdentity() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            // 제어 서버 주소(127.0.0.1:9)는 닿지 않는다. 연결을 시도했다면 실패로 던졌을 것이다.
            let node = try TailnetNode(configuration: try NodeTestSupport.configuration(stateDirectory: directory))
            try await node.logOut()
            #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path).isEmpty)
            #expect(StateDirectoryClaims.shared.claim(directory), "logOut()은 차지를 남기지 않는다")
            StateDirectoryClaims.shared.release(directory)
        }
    }
}
