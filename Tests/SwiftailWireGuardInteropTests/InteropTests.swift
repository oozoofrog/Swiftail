import Foundation
import Testing
import SwiftailWireGuard

@Suite("M1 wireguard-go UDP 상호 운용", .enabled(if: wgpeerBinary != nil, "SWIFTAIL_WGPEER가 없어 실제 Go 상호 운용 시험을 건너뜁니다"), .timeLimit(.minutes(4)))
struct WireGuardInteropTests {
    @Test("초기자 양쪽 역할에서 양방향 바이트 보존", arguments: [true, false])
    func handshake(swiftInitiates: Bool) async throws {
        try await withInteropPair { pair in
            try await pair.establish(swiftInitiates: swiftInitiates)
        }
    }

    @Test("IPv4 크기와 패딩 경계 양방향", arguments: [20, 21, 35, 36, 37, 1280, 1420])
    func sizes(size: Int) async throws {
        try await withInteropPair { pair in
            try await pair.swiftToGo(size: size)
            try await pair.goToSwift(size: size)
        }
    }

    @Test("IPv6 길이와 패딩 양방향")
    func ipv6() async throws {
        try await withInteropPair { pair in
            try await pair.swiftToGo(size: 1291, ipv6: true)
            try await pair.goToSwift(size: 1291, ipv6: true)
        }
    }

    @Test("첫 response 유실 뒤 새 initiation으로 복구")
    func lostResponse() async throws {
        try await withInteropPair { pair in
            await pair.swift.dropIncoming(1)
            let start = ContinuousClock.now
            try await pair.swiftToGo(timeout: .seconds(20))
            try await pair.goToSwift()
            let history = await pair.swift.datagrams()
            let attempts = history.filter { !$0.incoming && $0.bytes.first == 1 }
            guard let first = attempts.first, let second = attempts.dropFirst().first else {
                throw InteropFailure("유실 복구에서 initiation 재시도 없음")
            }
            guard history.contains(where: { $0.incoming && $0.dropped && $0.bytes.first == 2 }),
                  second.time - first.time >= .seconds(5), second.time - first.time < .seconds(10),
                  first.bytes != second.bytes, ContinuousClock.now - start >= .seconds(5) else {
                throw InteropFailure("response 유실·5초 재시도 관측 불일치")
            }
            // 매 재시도는 새 sender, ephemeral, 암호화 timestamp를 사용해야 한다.
            for range in [4..<8, 8..<40, 88..<116] {
                guard first.bytes[range] != second.bytes[range] else {
                    throw InteropFailure("재시도 initiation 필드가 재사용됨: \(range)")
                }
            }
        }
    }

    @Test("부하 상태의 Swift 응답자: cookie reply를 받은 Go가 mac2를 붙여 다시 보내고 핸드셰이크를 마친다")
    func cookieReplyUnderLoad() async throws {
        try await withInteropPair { pair in
            await pair.swift.holdUnderLoad()
            try await pair.goToSwift(marker: 51)
            try await pair.swiftToGo(marker: 52)

            let history = await pair.swift.datagrams()
            let initiations = history.filter { $0.incoming && $0.bytes.first == 1 }
            let replies = history.filter { !$0.incoming && $0.bytes.first == 3 }
            let responses = history.filter { !$0.incoming && $0.bytes.first == 2 }
            guard let first = initiations.first, let reply = replies.first, let accepted = initiations.last,
                  initiations.count == 2, replies.count == 1, responses.count == 1 else {
                throw InteropFailure("initiation·cookie reply·response 수 불일치")
            }
            guard first.bytes[132..<148].allSatisfy({ $0 == 0 }), !accepted.bytes[132..<148].allSatisfy({ $0 == 0 }),
                  reply.bytes.count == 64, reply.bytes[4..<8] == first.bytes[4..<8],
                  reply.time < accepted.time, accepted.time < responses[0].time else {
                throw InteropFailure("cookie reply 형식·순서 불일치")
            }
        }
    }

    @Test("변조 거부·중복 전달 방지 뒤 세션 유지")
    func tamperAndReplay() async throws {
        try await withInteropPair { pair in
            try await pair.establish(swiftInitiates: true)
            await pair.swift.interceptNextTransport(.flipBit)
            try await pair.swift.send(ipPacket(fromSwift: true, marker: 31))
            try await pair.go.expectSilence(for: .seconds(1))

            await pair.swift.interceptNextTransport(.duplicate)
            try await pair.swiftToGo(marker: 32)
            try await pair.go.expectSilence(for: .seconds(1))
            try await pair.swiftToGo(marker: 33)
            try await pair.goToSwift(marker: 34)

            let history = await pair.swift.datagrams()
            guard let captured = history.last(where: { $0.incoming && $0.bytes.first == 4 && $0.bytes.count > 32 }) else {
                throw InteropFailure("Go transport 캡처 없음")
            }
            do {
                try await pair.swift.reinject(captured.bytes)
                throw InteropFailure("Swift가 중복 transport를 받아들임")
            } catch let error as WireGuardError {
                guard error == .replayed else { throw InteropFailure("중복 transport 오류: \(error)") }
            }
            var changed = captured.bytes
            changed[changed.count - 1] ^= 1
            do {
                try await pair.swift.reinject(changed)
                throw InteropFailure("Swift가 변조 transport를 받아들임")
            } catch let error as WireGuardError {
                guard error == .authenticationFailed else { throw InteropFailure("변조 transport 오류: \(error)") }
            }
            try await pair.swiftToGo(marker: 35)
            try await pair.goToSwift(marker: 36)
        }
    }

    @Test("실제 135초 동안 양방향 전송과 rekey", arguments: [true, false])
    func rekey(swiftInitiates: Bool) async throws {
        try await withInteropPair { pair in
            try await pair.establish(swiftInitiates: swiftInitiates)
            let initial = try await pair.go.stats()
            guard let firstSec = initial.lastHandshakeSec, let firstNsec = initial.lastHandshakeNsec,
                  firstSec > 0 else { throw InteropFailure("초기 handshake 시각 없음") }
            let start = ContinuousClock.now
            for round in 1...27 {
                try await ContinuousClock().sleep(until: start + .seconds(round * 5))
                try await pair.swiftToGo(marker: UInt8(round + 40))
                try await pair.goToSwift(marker: UInt8(round + 80))
            }
            let final = try await pair.go.stats()
            guard let finalSec = final.lastHandshakeSec, let finalNsec = final.lastHandshakeNsec,
                  finalSec != firstSec || finalNsec != firstNsec else {
                throw InteropFailure("135초 뒤에도 Go lastHandshake가 바뀌지 않음")
            }
            guard ContinuousClock.now - start > .seconds(130) else {
                throw InteropFailure("실제 시간 130초를 넘기지 않음")
            }
        }
    }

    @Test("15초 유휴와 keepalive 뒤 양방향 재개")
    func idleResume() async throws {
        try await withInteropPair { pair in
            try await pair.establish(swiftInitiates: true)
            let before = await pair.swift.datagrams().count
            try await Task.sleep(for: .seconds(15))
            let idle = await pair.swift.datagrams().dropFirst(before)
            guard idle.contains(where: { $0.bytes.first == 4 && $0.bytes.count == 32 }) else {
                throw InteropFailure("15초 유휴 중 keepalive 경로가 실행되지 않음")
            }
            try await pair.swiftToGo(marker: 101)
            try await pair.goToSwift(marker: 102)
        }
    }
}
