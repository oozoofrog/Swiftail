import Foundation
import Swiftail
import SwiftailBase
import SwiftailMagicsock
import Testing

/// 실기기 관측("내려받는 쪽에서 direct가 선 뒤 약 100초에 `relayed`")을 실제 Go 피어와 실제 소켓으로 다시 본다.
/// `docs/contracts/SwiftailMagicsock.md` "direct가 선 뒤 약 100초에 `relayed`"의 "조사 결과".
///
/// 루프백이라 왕복 지연이 5 ms 아래여서 1분마다의 전체 Ping 길은 거의 타지 않는다. 그 길과 Wi-Fi 손실은 상태 기계
/// 시험(`MagicsockLongSessionTests`)이 덮는다.
@Suite("조사: 긴 내려받기 중 경로", .enabled(if: tailnetBinary != nil,
    "SWIFTAIL_TAILNET가 없어 긴 내려받기 조사를 건너뜁니다"), .serialized, .timeLimit(.minutes(10)))
struct LongDownloadPathTests {
    private static let chunk: UInt64 = 20 * 1_048_576

    @Test("Go 피어에게서 26초 내려받기와 42초 유휴를 되풀이하는 162초 동안 Swift 노드의 경로가 direct에서 내려가지 않는다")
    func repeatedDownloads() async throws {
        try await withGate(direct: false, device: .inProcess) { gate in
            // 준비가 양쪽 direct를 확인한다. 그 뒤로는 경로가 바뀔 때만 사건이 온다.
            let fqdn = try await netstackPrepare(gate)
            let initial = await gate.node.path(toPeerNamed: fqdn)
            let recorder = PathRecorder()
            let started = ContinuousClock.now
            var received: UInt64 = 0
            try await withThrowingTaskGroup(of: UInt64.self) { group in
                defer { group.cancelAll() }
                group.addTask {
                    for await event in gate.node.events {
                        if case let .peerPathChanged(name, path) = event, name == fqdn { await recorder.record(path) }
                    }
                    return 0
                }
                group.addTask {
                    var total: UInt64 = 0
                    for round in 0..<3 {
                        let downloadEnd = started + .seconds(68 * round + 26)
                        while ContinuousClock.now < downloadEnd {
                            let connection = try await netstackDeadline("긴 내려받기 connect") {
                                try await gate.node.connect(to: gate.peer.address().description, port: 9_100)
                            }
                            try await connection.write(NetstackStream.header(count: Self.chunk, seed: 1))
                            _ = try await netstackExchange(gate, connection: connection, stage: "긴 내려받기 \(round + 1)",
                                sendCount: 0, receiveCount: Self.chunk)
                            total += Self.chunk
                        }
                        if round < 2 {
                            try await Task.sleep(until: started + .seconds(68 * round + 68), clock: .continuous)
                        }
                    }
                    return total
                }
                received = try #require(try await group.next())
            }
            let events = await recorder.events.map { (started.duration(to: $0.time), $0.path) }
            await gate.tool.checkpoint("긴 내려받기: \(started.duration(to: .now)) 동안 \(received / 1_048_576)MiB, 경로 사건 \(events)")
            #expect(started.duration(to: .now) >= .seconds(150))
            let isDirect: (PeerPath?) -> Bool = { if case .direct = $0 { true } else { false } }
            #expect(isDirect(initial))
            #expect(events.allSatisfy { isDirect($0.1) }, "direct 뒤 경로 사건: \(events)")
        }
    }
}

/// 받은 경로 사건과 그 시각.
private actor PathRecorder {
    private(set) var events: [(time: ContinuousClock.Instant, path: PeerPath?)] = []

    func record(_ path: PeerPath?) {
        events.append((.now, path))
    }
}
