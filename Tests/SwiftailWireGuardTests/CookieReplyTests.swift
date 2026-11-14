// cookie reply를 보내는 쪽: 부하 판정, mac2 검사, cookie reply, 비밀 교체, 출처별 속도 제한.
// 시각을 직접 넘겨 결정적으로 돌린다. 부하 상태는 문턱을 넘는 입력으로 만들거나 `underLoadUntil`을 정해 만든다.

import Foundation
import Testing

import SwiftailCrypto
@testable import SwiftailWireGuard

/// 부하 상태의 bob과, bob에게 보낼 alice의 첫 initiation.
private func loadedPair() throws -> (pair: Pair, initiation: [UInt8]) {
    var pair = Pair()
    pair.bob.handshakeLoad.underLoadUntil = t0 + .seconds(600)
    let initiation = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0).datagrams[0]
    return (pair, initiation)
}

/// mac1을 `receiver`에 맞게 다시 계산한 initiation. 본문은 아무 바이트여도 된다.
private func withValidMAC1(_ body: [UInt8], for receiver: PublicKey) -> [UInt8] {
    let head = Array(body[..<116])
    return head + MAC.authenticate(head, key: MAC.mac1Key(for: receiver)) + [UInt8](repeating: 0, count: 16)
}

private let elsewhere = WireGuardDevice.Source(address: [198, 51, 100, 9, 0x51, 0xA2], host: [198, 51, 100, 9])

@Suite("부하 판정")
struct HandshakeLoadTests {
    @Test("1초보다 짧은 간격 안에 128번째 메시지가 오면 부하다. 127개, 또는 정확히 1초 간격의 128개는 아니다")
    func thresholdAndWindow() {
        var load = HandshakeLoad()
        func record(_ now: ContinuousClock.Instant) -> Bool { load.record(at: now) }
        for i in 0..<127 {
            #expect(!record(t0 + .milliseconds(i)))
        }
        #expect(record(t0 + .seconds(1) - .nanoseconds(1)))

        load = HandshakeLoad()
        for i in 0..<127 {
            #expect(!record(t0 + .milliseconds(i)))
        }
        // 첫 메시지와 정확히 1초 떨어졌다. 그 뒤로는 창 안에 127개뿐이다.
        #expect(!record(t0 + .seconds(1)))
        #expect(!record(t0 + .seconds(1) + .milliseconds(1)))
    }

    @Test("감지한 뒤 1초 동안 부하로 머물고, 그 시각 정각에 끝난다")
    func holdsForOneSecond() {
        var load = HandshakeLoad()
        func record(_ now: ContinuousClock.Instant) -> Bool { load.record(at: now) }
        for i in 0..<128 {
            _ = record(t0 + .milliseconds(7 * i))
        }
        let detected = t0 + .milliseconds(7 * 127)
        #expect(load.underLoadUntil == detected + .seconds(1))
        // 창 안에 다시 128개가 모이지 않아도 남은 기간 동안은 부하다.
        #expect(record(detected + .seconds(1) - .nanoseconds(1)))
        #expect(!record(detected + .seconds(1)))
    }

    @Test("mac1이 틀린 메시지는 부하 수에 들지 않는다")
    func invalidMAC1DoesNotCount() throws {
        var pair = Pair()
        let initiation = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0).datagrams[0]
        var forged = initiation
        forged[120] ^= 0x01
        for _ in 0..<1_000 {
            #expect(throws: WireGuardError.authenticationFailed) { try pair.bob.receive(forged, at: t0) }
        }
        #expect(try pair.bob.receive(initiation, at: t0).messageTypes == [2])
    }

    @Test("mac1이 맞는 initiation이 문턱을 넘으면 그다음부터 cookie reply로 답한다")
    func realInputCrossesThreshold() throws {
        var pair = Pair()
        let initiation = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0).datagrams[0]
        #expect(try pair.bob.receive(initiation, at: t0).messageTypes == [2])
        // 같은 initiation의 재전송은 timestamp 검사에서 버리지만 mac1은 맞으므로 센다.
        for _ in 2..<128 {
            #expect(throws: WireGuardError.replayed) { try pair.bob.receive(initiation, at: t0) }
        }
        guard case let .cookieReply(reply)? = try pair.bob.receive(initiation, at: t0).first else {
            Issue.record("문턱에서 cookie reply가 나오지 않았다")
            return
        }
        #expect(reply.count == 64)
    }
}

@Suite("cookie reply 보내기")
struct CookieReplySendingTests {
    @Test("부하 상태에서 mac2 없는 initiation에는 64바이트 cookie reply로 답하고 핸드셰이크 상태는 그대로다")
    func replyFormat() throws {
        var (pair, initiation) = try loadedPair()
        let outputs = try pair.bob.receive(initiation, at: t0)
        guard case let .cookieReply(reply)? = outputs.first, outputs.count == 1 else {
            Issue.record("cookie reply 하나가 아니다: \(outputs)")
            return
        }
        #expect(reply.count == 64)
        #expect(Array(reply[0..<4]) == [3, 0, 0, 0])
        // receiver는 거절한 initiation의 sender다.
        #expect(Array(reply[4..<8]) == Array(initiation[4..<8]))
        let peer = try #require(pair.bob.peers[pair.key(.alice)])
        #expect(peer.lastInitiationConsumed == nil && peer.lastAcceptedTimestamp == nil && peer.keypairs.current == nil && peer.keypairs.next == nil)

        // 보낸 쪽(Swift 소비 코드)이 연다.
        #expect(try pair.alice.receive(reply, at: t0).isEmpty)
    }

    @Test("X25519 전에 답한다: 열리지 않는 본문, 모르는 피어의 initiation에도 오류 대신 cookie reply다")
    func noHandshakeComputation() throws {
        var (pair, initiation) = try loadedPair()
        var random = SplitMix64(seed: 0xC00C1E)
        // 본문이 무작위이면 부하가 아닐 때는 DH 단계에서 authenticationFailed다.
        let garbage = withValidMAC1([1, 0, 0, 0] + random.bytes(144), for: pair.key(.bob))
        var idle = Pair()
        #expect(throws: WireGuardError.authenticationFailed) { try idle.bob.receive(withValidMAC1(garbage, for: idle.key(.bob)), at: t0) }
        guard case .cookieReply? = try pair.bob.receive(garbage, at: t0).first else {
            Issue.record("열리지 않는 initiation을 처리하려 했다")
            return
        }
        pair.bob.removePeer(pair.key(.alice))
        guard case .cookieReply? = try pair.bob.receive(initiation, at: t0).first else {
            Issue.record("모르는 피어의 initiation을 처리하려 했다")
            return
        }
    }

    @Test("cookie를 받은 초기자의 재시도는 mac2가 맞아 핸드셰이크가 끝난다")
    func roundTrip() throws {
        var (pair, initiation) = try loadedPair()
        let packet = pair.packet(from: .alice)
        // deliver는 cookie reply를 보낸 쪽에 되돌린다. 첫 시도는 cookie만 남기고 끝난다.
        #expect(try pair.deliver([.datagram(initiation, to: pair.key(.bob))], from: .alice, at: t0)[.bob] == [])
        let retryAt = try #require(pair.alice.nextDeadline)
        let retry = pair.alice.advance(to: retryAt)
        #expect(try pair.deliver(retry, from: .alice, at: retryAt)[.bob] == [packet])
    }

    @Test("다른 출처에서 가져온 mac2는 받지 않는다")
    func mac2BoundToSource() throws {
        var (pair, initiation) = try loadedPair()
        let reply = try pair.bob.receive(initiation, at: t0)
        guard case let .cookieReply(bytes)? = reply.first else { throw WireGuardError.malformed }
        _ = try pair.alice.receive(bytes, at: t0)
        let retryAt = try #require(pair.alice.nextDeadline)
        let retried = pair.alice.advance(to: retryAt).datagrams[0]
        guard case .cookieReply? = try pair.bob.receive(retried, from: elsewhere, at: retryAt).first else {
            Issue.record("다른 출처의 mac2를 받아들였다")
            return
        }
        #expect(try pair.bob.receive(retried, at: retryAt).messageTypes == [2])
    }

    @Test("120초가 넘은 비밀로 만든 cookie는 받지 않고, 그때 비밀을 바꾼다")
    func staleSecret() throws {
        var (pair, initiation) = try loadedPair()
        guard case let .cookieReply(first)? = try pair.bob.receive(initiation, at: t0).first else { throw WireGuardError.malformed }
        // alice는 10ms 뒤에 받았으므로 120초 5ms 뒤에도 cookie를 쓴다. bob의 비밀은 그때 120초를 넘었다.
        _ = try pair.alice.receive(first, at: t0 + .milliseconds(10))
        while let deadline = pair.alice.nextDeadline, !pair.alice.advance(to: deadline).isEmpty {}
        let late = t0 + .seconds(120) + .milliseconds(5)
        let stale = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: late).datagrams[0]
        #expect(!stale[132..<148].allSatisfy { $0 == 0 })
        guard case let .cookieReply(second)? = try pair.bob.receive(stale, at: late).first else {
            Issue.record("낡은 비밀의 cookie를 받아들였다")
            return
        }
        // 새 비밀로 만든 cookie로는 끝난다.
        _ = try pair.alice.receive(second, at: late)
        let retryAt = try #require(pair.alice.nextDeadline)
        #expect(try pair.deliver(pair.alice.advance(to: retryAt), from: .alice, at: retryAt)[.bob]?.count == 1)
    }

    @Test("비밀은 만든 지 120초 정각까지 쓰고 그 뒤 reply를 만들 때 바꾼다")
    func secretRotation() throws {
        let receiver = try #require(PublicKey(rawValue: [UInt8](repeating: 0x42, count: 32)))
        var checker = CookieChecker(publicKey: receiver)
        var generator = CookieGenerator(peer: receiver)
        var random = SplitMix64(seed: 7)
        let body = [UInt8](repeating: 7, count: 116)

        /// generator가 body에 붙이는 MAC과 그 mac1로 만든 reply.
        func reply(at now: ContinuousClock.Instant) throws -> MessageMACs {
            let mac1 = generator.macs(for: body, at: now).mac1
            let reply = try #require(checker.makeReply(to: 0, mac1: mac1, from: .test, at: now, using: &random))
            #expect(reply.bytes.count == 64)
            let result = generator.consume(reply, at: now)
            #expect(result)
            return generator.macs(for: body, at: now)
        }

        #expect(!checker.isValidMAC2(generator.macs(for: body, at: t0), over: body, from: .test, at: t0))
        let first = try reply(at: t0)
        #expect(checker.isValidMAC2(first, over: body, from: .test, at: t0 + .seconds(120)))
        #expect(!checker.isValidMAC2(first, over: body, from: .test, at: t0 + .seconds(120) + .nanoseconds(1)))
        // 120초 정각에 만든 reply는 같은 비밀이므로 같은 cookie다.
        #expect(try reply(at: t0 + .seconds(120)).mac2 == first.mac2)
        // 그 뒤에 만든 reply는 새 비밀이다. 옛 cookie는 이제 틀리다.
        let rotated = t0 + .seconds(120) + .nanoseconds(1)
        let second = try reply(at: rotated)
        #expect(second.mac2 != first.mac2)
        #expect(checker.isValidMAC2(second, over: body, from: .test, at: rotated))
        #expect(!checker.isValidMAC2(first, over: body, from: .test, at: rotated))
    }

    @Test("부하 상태에서 mac2가 맞아도 출처 호스트마다 버스트 5개를 넘으면 rateLimited다")
    func rateLimitAtDevice() throws {
        var (pair, initiation) = try loadedPair()
        guard case let .cookieReply(bytes)? = try pair.bob.receive(initiation, at: t0).first else { throw WireGuardError.malformed }
        _ = try pair.alice.receive(bytes, at: t0)
        let retryAt = try #require(pair.alice.nextDeadline)
        let retried = pair.alice.advance(to: retryAt).datagrams[0]
        #expect(try pair.bob.receive(retried, at: retryAt).messageTypes == [2])
        // 2~5번째는 몫 안이라 핸드셰이크 검사까지 간다(같은 timestamp라 replayed). 6번째는 그 전에 막힌다.
        for i in 1..<5 {
            #expect(throws: WireGuardError.replayed) { try pair.bob.receive(retried, at: retryAt + .nanoseconds(i)) }
        }
        #expect(throws: WireGuardError.rateLimited) { try pair.bob.receive(retried, at: retryAt + .nanoseconds(5)) }
    }

    @Test("부하 상태에서 response에도 mac2를 요구한다")
    func responseNeedsMAC2() throws {
        var pair = Pair()
        let initiation = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0).datagrams[0]
        let response = try pair.bob.receive(initiation, at: t0).datagrams[0]
        pair.alice.handshakeLoad.underLoadUntil = t0 + .seconds(600)
        guard case let .cookieReply(reply)? = try pair.alice.receive(response, at: t0).first else {
            Issue.record("mac2 없는 response를 처리했다")
            return
        }
        #expect(Array(reply[4..<8]) == Array(response[4..<8]))
        #expect(try pair.bob.receive(reply, at: t0).isEmpty)
    }

    @Test("부하 상태에서 임의 입력과 mac1만 맞춘 입력으로 죽지 않는다")
    func fuzzUnderLoad() throws {
        var (pair, _) = try loadedPair()
        var random = SplitMix64(seed: 0x10AD)
        for step in 0..<3_000 {
            let now = t0 + .milliseconds(step)
            let size = [148, 92, 64, Int.random(in: 0...200, using: &random)][step % 4]
            var bytes = random.bytes(size)
            if size == 148 || size == 92 {
                bytes[0] = size == 148 ? 1 : 2
                bytes[1...3] = [0, 0, 0]
                let head = Array(bytes[..<(size - 32)])
                bytes = head + MAC.authenticate(head, key: MAC.mac1Key(for: pair.key(.bob))) + random.bytes(16)
            }
            let source = WireGuardDevice.Source(address: random.bytes(Int.random(in: 0...18, using: &random)), host: random.bytes(4))
            _ = try? pair.bob.receive(bytes, from: source, at: now)
        }
    }

    @Test("dump에 cookie 비밀과 속도 제한 표가 펼쳐지지 않는다")
    func reflectionHidesCookieState() throws {
        var (pair, initiation) = try loadedPair()
        _ = try pair.bob.receive(initiation, at: t0)
        var dumped = ""
        dump(pair.bob, to: &dumped)
        let printed = (String(describing: pair.bob) + String(reflecting: pair.bob) + dumped).lowercased()
        for field in ["secret", "cookiechecker", "ratelimiter", "buckets", "handshakeload"] {
            #expect(!printed.contains(field), "\(field)")
        }
    }
}
