import Foundation
import Testing
@testable import Swiftail

/// 설정과 노드 값이 인증 키를 드러내지 않는지. 계약 노드 API 동작 7.
@Suite("노드 설정의 비밀 가리기")
struct NodeConfigurationTests {
    /// 가짜 인증 키. 실제 키 형식을 흉내 낼 뿐이다.
    private static let authKey = "tskey-auth-fake0000-swiftail0000"

    private static func configuration(stateDirectory: String = "file:///var/empty/swiftail-test/") throws -> NodeConfiguration {
        NodeConfiguration(
            stateDirectory: try #require(URL(string: stateDirectory)),
            hostname: "rd-mac-1a2b3c4d",
            controlURL: try #require(URL(string: "http://127.0.0.1:9")),
            authKey: authKey
        )
    }

    @Test("description에 인증 키가 나오지 않는다")
    func description() throws {
        let text = String(describing: try Self.configuration())
        #expect(!text.contains(Self.authKey))
        #expect(text.contains("<가림>"))
    }

    @Test("dump에 인증 키가 나오지 않는다")
    func dumpOutput() throws {
        var text = ""
        dump(try Self.configuration(), to: &text)
        #expect(!text.contains(Self.authKey))
        #expect(text.contains("rd-mac-1a2b3c4d"))
    }

    @Test("노드의 dump에 설정의 비밀이 나오지 않는다")
    func nodeDump() throws {
        var text = ""
        dump(TailnetNode(configuration: try Self.configuration()), to: &text)
        #expect(!text.contains(Self.authKey))
    }

    @Test("run()을 두 번 부르면 invalidConfiguration")
    func runTwice() async throws {
        let node = TailnetNode(configuration: try Self.configuration(stateDirectory: "https://example.com/state"))
        // 첫 호출은 파일 URL이 아닌 상태 디렉터리로 곧바로 끝난다. 그래도 한 번 부른 것이다.
        await #expect(throws: NodeError.self) { try await node.run() }
        do {
            try await node.run()
            Issue.record("두 번째 run()이 던지지 않았다")
        } catch {
            guard case .invalidConfiguration = error else {
                Issue.record("기대 invalidConfiguration, 실제 \(error)")
                return
            }
        }
    }
}
