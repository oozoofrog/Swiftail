// `import Swiftail`만으로 공개 API에 나오는 타입의 이름을 쓴다. 이 파일은 다른 모듈을 가져오지 않는다. 별명 하나라도
// 빠지면 이 파일이 컴파일되지 않는다(`Sources/Swiftail/ReexportedTypes.swift`).

import Swiftail
import Testing

@Suite("import Swiftail만으로 쓰는 타입")
struct ReexportedTypesTests {
    @Test("공개 API에 나오는 다른 모듈의 타입을 이름으로 쓴다")
    func namesFromOtherModules() throws {
        let address: IPAddress = try #require(IPAddress("100.64.0.1"))
        let endpoint = IPEndpoint(address: address, port: 4747)
        let prefix: IPPrefix = try #require(IPPrefix("100.64.0.0/10"))
        #expect(prefix.contains(address))

        let path: PeerPath = .direct(endpoint)
        guard case .direct(let direct) = path else { Issue.record("직접 경로가 아니다"); return }
        #expect(direct.port == 4747)

        let lock = TailnetLockStatus(mode: .enforcing, signingRequest: TailnetLockStatus.SigningRequest(nodeKey: "n", lockKey: "l"))
        let mode: TailnetLockStatus.Mode = lock.mode
        let issue: TailnetLockStatus.Issue? = lock.issue
        #expect(mode == .enforcing && issue == nil && lock.isLockedOut)

        let failure: ControlError = .storage("시험")
        guard case .control(.storage) = NodeError.control(failure) else { Issue.record("control(.storage)가 아니다"); return }

        let settings: TunnelNetworkSettings? = NodeStatus(state: .starting).networkSettings
        #expect(settings == nil)
        let addresses: [IPAddress] = NodeStatus(state: .starting, addresses: [address]).addresses
        #expect(addresses == [address])
    }
}
