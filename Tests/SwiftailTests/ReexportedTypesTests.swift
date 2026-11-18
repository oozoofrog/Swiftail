// Names the types in the public API using only `import Swiftail`. This file imports no other module. If any alias is missing,
// this file does not compile (`Sources/Swiftail/ReexportedTypes.swift`).

import Swiftail
import Testing

@Suite("Types accessible with only import Swiftail")
struct ReexportedTypesTests {
    @Test("Names types from other modules that appear in the public API")
    func namesFromOtherModules() throws {
        let address: IPAddress = try #require(IPAddress("100.64.0.1"))
        let endpoint = IPEndpoint(address: address, port: 4747)
        let prefix: IPPrefix = try #require(IPPrefix("100.64.0.0/10"))
        #expect(prefix.contains(address))

        let path: PeerPath = .direct(endpoint)
        guard case .direct(let direct) = path else { Issue.record("Expected a direct path"); return }
        #expect(direct.port == 4747)

        let lock = TailnetLockStatus(mode: .enforcing, signingRequest: TailnetLockStatus.SigningRequest(nodeKey: "n", lockKey: "l"))
        let mode: TailnetLockStatus.Mode = lock.mode
        let issue: TailnetLockStatus.Issue? = lock.issue
        #expect(mode == .enforcing && issue == nil && lock.isLockedOut)

        let failure: ControlError = .storage("test")
        guard case .control(.storage) = NodeError.control(failure) else { Issue.record("Expected control(.storage)"); return }

        let settings: TunnelNetworkSettings? = NodeStatus(state: .starting).networkSettings
        #expect(settings == nil)
        let addresses: [IPAddress] = NodeStatus(state: .starting, addresses: [address]).addresses
        #expect(addresses == [address])
    }
}
