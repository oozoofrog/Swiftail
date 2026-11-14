// M2 마무리 관문: 운영 제어 서버에 임시(ephemeral) 노드로 등록해 testcontrol과의 차이를 본다.
//
// 사용자가 준 임시 인증 키가 있을 때만 돈다. 키는 환경 변수가 아니라 파일로 받는다(값이 프로세스 목록과
// 로그에 남지 않게). 출력에는 개수와 참·거짓만 쓴다. 실제 tailnet 이름·기기 이름·주소·키는 쓰지 않는다.
//
//   SWIFTAIL_REAL_AUTHKEY_FILE=<키가 든 파일> eyebuild swift m1-gate -- test --filter RealTailnetGateTests

import Foundation
import SwiftailBase
import SwiftailControl
import Testing

private let realAuthKeyFile = ProcessInfo.processInfo.environment["SWIFTAIL_REAL_AUTHKEY_FILE"].flatMap { $0.isEmpty ? nil : $0 }

@Suite("M2 마무리 관문: 운영 제어 서버", .enabled(if: realAuthKeyFile != nil,
    "SWIFTAIL_REAL_AUTHKEY_FILE이 없어 건너뜁니다"), .timeLimit(.minutes(5)))
struct RealTailnetGateTests {
    @Test("임시 노드로 등록하고 비압축 netmap을 받아 90초 유지한다")
    func registerAndHoldMapStream() async throws {
        let path = try #require(realAuthKeyFile)
        let authKey = try String(contentsOfFile: path, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
        try #require(!authKey.isEmpty, "인증 키 파일이 비었다")
        let controlURL = try #require(URL(string: "https://controlplane.tailscale.com"))
        let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-real-gate-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }

        let client = ControlClient(
            configuration: .init(serverURL: controlURL, hostname: "swiftail-gate", authKey: authKey, ephemeral: true),
            identityStore: NodeIdentityStore(directory: directory)
        )
        let running = Task<ControlError?, Never> {
            do { try await client.run(); return nil }
            catch let error as ControlError { return error }
            catch { return .connection("예상하지 않은 run 오류") }
        }
        defer { running.cancel() }

        let started = ContinuousClock.now
        let hold = Duration.seconds(90)

        let observing = Task { () -> (Bool, Int, Int, Netmap?) in
            var registered = false
            var netmaps = 0
            var disconnects = 0
            var first: Netmap?
            for await event in client.events {
                switch event {
                case .loginRequired:
                    return (registered, netmaps, -1, first)   // 인증 키로 등록되지 않고 대화형 로그인을 요구받았다
                case .registered:
                    registered = true
                case .netmap(let netmap):
                    netmaps += 1
                    if first == nil { first = netmap }
                case .disconnected:
                    disconnects += 1
                }
                if first != nil, started.duration(to: .now) >= hold { break }
            }
            return (registered, netmaps, disconnects, first)
        }
        // 맵이 조용하면 사건이 오지 않아 위 반복이 끝나지 않는다. 유지 시간이 지나면 run을 끝내 흐름을 닫는다.
        try await Task.sleep(for: hold + .seconds(5))
        running.cancel()
        let (didRegister, netmapCount, disconnectCount, netmap) = await observing.value
        let failure = await running.value

        if let failure {
            Issue.record("run()이 오류로 끝났다: \(redacted(String(describing: failure)))")
        }
        #expect(disconnectCount != -1, "인증 키가 받아들여지지 않아 대화형 로그인을 요구받았다")
        #expect(didRegister, "등록되지 않았다")
        let map = try #require(netmap, "netmap을 받지 못했다(비압축 맵 응답을 서버가 주지 않았을 수 있다)")
        #expect(disconnectCount == 0, "맵 스트림이 유지되지 않았다")

        let tailnetV4 = try #require(IPPrefix("100.64.0.0/10"))
        #expect(map.selfNode.addresses.contains { $0.address.isIPv4 && tailnetV4.contains($0.address) })
        #expect(map.selfNode.machineAuthorized)
        let regionCount = map.derpMap?.regions?.count ?? 0
        #expect(regionCount > 0, "운영 DERPMap이 비었다")

        print("""
            마무리 관문 요약(개수와 참·거짓만):
              등록 \(didRegister), netmap 사건 \(netmapCount)개, 끊김 \(disconnectCount)회, 유지 \(hold)
              자기 주소 \(map.selfNode.addresses.count)개, 피어 \(map.peers.count)명, DERP 지역 \(regionCount)개
              DNSConfig \(map.dnsConfig != nil), 필터 규칙 \(map.packetFilter.count)개, 사용자 프로필 \(map.userProfiles.count)개
              tailnet lock \(map.tailnetLockEnabled), 서버 시각 있음 \(map.controlTime != nil), self 키 만료 있음 \(map.selfNode.keyExpiry != nil)
            """)
    }
}
