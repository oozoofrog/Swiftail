// M2 마무리 관문: 운영 제어 서버에 임시(ephemeral) 노드로 등록해 testcontrol과의 차이를 본다.
//
// 사용자가 준 임시 인증 키가 있을 때만 돈다. 키는 환경 변수가 아니라 파일로 받는다(값이 프로세스 목록과
// 로그에 남지 않게). 출력에는 개수와 참·거짓만 쓴다. 실제 tailnet 이름·기기 이름·주소·키는 쓰지 않는다.
//
//   SWIFTAIL_REAL_AUTHKEY_FILE=<키가 든 파일> eyebuild swift m1-gate -- test --filter RealTailnetGateTests

import Foundation
import SwiftailBase
import Testing

@testable import SwiftailControl

private let realAuthKeyFile = ProcessInfo.processInfo.environment["SWIFTAIL_REAL_AUTHKEY_FILE"].flatMap { $0.isEmpty ? nil : $0 }
private let realStateDirectory = ProcessInfo.processInfo.environment["SWIFTAIL_REAL_STATE_DIR"].flatMap { $0.isEmpty ? nil : $0 }

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
        // tailnet lock 진단: 서버가 마지막 맵 세션에서 알린 상태만 본다(해시 값은 찍지 않는다).
        let serverLock = await client.lockSession.server
        print("마무리 관문 진단: 서버가 알린 lock 켜짐 \(serverLock.isEnabled), 머리 있음 \(serverLock.head != nil)")
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
              tailnet lock \(map.tailnetLock.mode), 거른 피어 \(map.tailnetLock.filteredPeerCount)명, 서버 시각 있음 \(map.controlTime != nil), self 키 만료 있음 \(map.selfNode.keyExpiry != nil)
            """)
    }
}

/// M8 관문 (나)의 앞 단계: tailnet lock 전의 Swiftail(등록 요청의 `NLKey`가 0)로 등록했던 노드가, 같은 신원 파일에 새 NL 키를
/// 채운 지금의 Swiftail로 다시 붙을 때 운영 서버가 받아들이는지 본다. 기존 사용자의 올림 경로다.
///
/// 상태 폴더는 M8 전 커밋(`6f30600`)으로 한 번 등록해 만든다(인증 키와 임시 노드). 여기서는 인증 키를 주지 않는다:
/// 서버가 그 노드를 이미 지웠으면 새 등록이 되어 버려 올림 경로를 보지 못하므로, 그때는 로그인 요구로 드러나게 한다.
///
///   SWIFTAIL_REAL_STATE_DIR=<옛 커밋으로 등록한 상태 폴더> eyebuild swift m1-gate -- test --filter RealTailnetUpgradeTests
@Suite("M8 관문 (나) 앞 단계: 옛 신원의 올림", .enabled(if: realStateDirectory != nil,
    "SWIFTAIL_REAL_STATE_DIR이 없어 건너뜁니다"), .timeLimit(.minutes(3)))
struct RealTailnetUpgradeTests {
    @Test("NL 키 없이 등록했던 노드가 NL 키를 싣고 다시 붙어 netmap을 받는다")
    func identityWithoutLockKeyReconnects() async throws {
        let directory = URL(filePath: try #require(realStateDirectory), directoryHint: .isDirectory)
        let store = NodeIdentityStore(directory: directory)
        let before = try String(contentsOf: store.fileURL, encoding: .utf8)
        try #require(!before.contains("NLKey"), "신원 파일에 이미 NL 키가 있다. 올림 경로가 아니다")
        let previous = try #require(try store.load()?.nodePublicKey, "옛 신원에 node 키가 없다")
        let controlURL = try #require(URL(string: "https://controlplane.tailscale.com"))

        let client = ControlClient(
            configuration: .init(serverURL: controlURL, hostname: "swiftail-gate", authKey: nil, ephemeral: true),
            identityStore: store
        )
        let running = Task<ControlError?, Never> {
            do { try await client.run(); return nil }
            catch let error as ControlError { return error }
            catch { return .connection("예상하지 않은 run 오류") }
        }
        defer { running.cancel() }

        let observing = Task { () -> (loginRequired: Bool, registered: NodePublicKey?, netmap: Netmap?, disconnects: Int) in
            var registered: NodePublicKey?
            var netmap: Netmap?
            var disconnects = 0
            for await event in client.events {
                switch event {
                case .loginRequired: return (true, registered, netmap, disconnects)
                case .registered(let key): registered = key
                case .netmap(let map): netmap = netmap ?? map
                case .disconnected: disconnects += 1
                }
            }
            return (false, registered, netmap, disconnects)
        }
        try await Task.sleep(for: .seconds(30))
        running.cancel()
        let outcome = await observing.value
        if let failure = await running.value {
            Issue.record("run()이 오류로 끝났다: \(redacted(String(describing: failure)))")
        }

        #expect(!outcome.loginRequired, "서버가 로그인을 요구했다: 옛 노드가 이미 지워졌거나 NL 키가 바뀐 등록을 받지 않는다")
        #expect(outcome.registered == previous, "같은 node 키로 등록되지 않았다")
        let map = try #require(outcome.netmap, "netmap을 받지 못했다")
        #expect(outcome.disconnects == 0, "맵 스트림이 유지되지 않았다")
        #expect(map.selfNode.machineAuthorized)
        let after = try String(contentsOf: store.fileURL, encoding: .utf8)
        #expect(after.contains("NLKey"), "신원 파일에 NL 키가 저장되지 않았다")

        print("""
            올림 관문 요약(개수와 참·거짓만):
              로그인 요구 \(outcome.loginRequired), 같은 node 키로 등록 \(outcome.registered == previous), 끊김 \(outcome.disconnects)회
              피어 \(map.peers.count)명, tailnet lock \(map.tailnetLock.mode), NL 키 저장됨 \(after.contains("NLKey"))
            """)
    }
}
