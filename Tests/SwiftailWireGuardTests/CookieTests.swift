// 계약 시험 5: cookie reply를 받으면 이후 핸드셰이크 메시지에 mac2가 붙고, 120초가 지나면 쓰지 않는다.
//
// 이 모듈은 cookie reply를 보내지 않으므로, 부하 상태의 응답자가 보낼 reply는 시험이 직접 만든다
// (wireguard-go `device/cookie.go`의 `CreateReply`와 같은 식).

import Testing

import SwiftailCrypto
@testable import SwiftailWireGuard

@Suite("cookie")
struct CookieTests {
    /// 응답자(receiver)가 거절한 메시지에 대해 보낼 cookie reply.
    private func cookieReply(rejecting message: [UInt8], cookie: [UInt8], receiver: PublicKey, nonce: [UInt8]) throws -> [UInt8] {
        let mac1 = Array(message[(message.count - 32)..<(message.count - 16)])
        let encrypted = try XChaCha20Poly1305.seal(cookie, key: MAC.cookieKey(for: receiver), nonce: nonce, authenticating: mac1)
        return [3, 0, 0, 0] + Array(message[4..<8]) + nonce + encrypted
    }

    private let cookie: [UInt8] = Array(0x10..<0x20)
    private let nonce: [UInt8] = Array(0..<24)

    @Test("cookie가 없으면 mac2는 0이다")
    func noCookieNoMAC2() throws {
        var pair = Pair()
        let initiation = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0).datagrams[0]
        #expect(initiation[132..<148].allSatisfy { $0 == 0 })
        // mac1 = MAC(HASH("mac1----" ‖ bob 공개 키), 앞 116바이트).
        #expect(Array(initiation[116..<132]) == MAC.authenticate(Array(initiation[..<116]), key: MAC.mac1Key(for: pair.key(.bob))))
    }

    @Test("reply를 소비한 뒤의 initiation에는 mac2가 붙고, 120초가 지나면 다시 0이다")
    func mac2AfterCookieReply() throws {
        var pair = Pair()
        let first = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0).datagrams[0]
        let reply = try cookieReply(rejecting: first, cookie: cookie, receiver: pair.key(.bob), nonce: nonce)

        let receivedAt = t0 + .milliseconds(10)
        #expect(try pair.alice.receive(reply, at: receivedAt).isEmpty)

        // 거절된 initiation을 곧바로 다시 보내지는 않는다. 다음 재시도부터 mac2가 붙는다.
        let retryAt = try #require(pair.alice.nextDeadline)
        let retry = pair.alice.advance(to: retryAt).datagrams[0]
        #expect(Array(retry[132..<148]) == MAC.authenticate(Array(retry[..<132]), key: cookie))
        #expect(!retry[132..<148].allSatisfy { $0 == 0 })

        // 재시도가 모두 실패한 뒤, cookie를 받은 지 120초가 넘어 만든 initiation에는 mac2가 없다.
        while let deadline = pair.alice.nextDeadline, !pair.alice.advance(to: deadline).isEmpty {}
        let late = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: receivedAt + .seconds(121))
        #expect(late.messageTypes == [1])
        #expect(late.datagrams[0][132..<148].allSatisfy { $0 == 0 })
    }

    @Test("cookie는 받은 지 120초 정각까지 쓰고 그 뒤에는 쓰지 않는다")
    func cookieRefreshBoundary() throws {
        let receiver = try #require(PublicKey(rawValue: [UInt8](repeating: 0x42, count: 32)))
        var generator = CookieGenerator(peer: receiver)
        let body = [UInt8](repeating: 7, count: 116)
        let mac1 = generator.macs(for: body, at: t0).mac1
        let reply = CookieReply(
            receiver: 0,
            nonce: nonce,
            encryptedCookie: try XChaCha20Poly1305.seal(cookie, key: MAC.cookieKey(for: receiver), nonce: nonce, authenticating: mac1)
        )
        let result1 = generator.consume(reply, at: t0)
        #expect(result1)
        let atLimit = generator.macs(for: body, at: t0 + .seconds(120))
        #expect(atLimit.mac2 == MAC.authenticate(body + mac1, key: cookie))
        let afterLimit = generator.macs(for: body, at: t0 + .seconds(120) + .nanoseconds(1))
        #expect(afterLimit.mac2 == [UInt8](repeating: 0, count: 16))
    }

    @Test("변조한 reply와 모르는 receiver는 거절하고 mac2를 붙이지 않는다")
    func invalidReplies() throws {
        var pair = Pair()
        let first = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0).datagrams[0]
        let reply = try cookieReply(rejecting: first, cookie: cookie, receiver: pair.key(.bob), nonce: nonce)

        for offset in 8..<reply.count {
            var tampered = reply
            tampered[offset] ^= 0x01
            #expect(throws: WireGuardError.authenticationFailed) { try pair.alice.receive(tampered, at: t0) }
        }
        var unknown = reply
        unknown[4] ^= 0xFF
        #expect(throws: WireGuardError.unknownPeer) { try pair.alice.receive(unknown, at: t0) }
        // 다른 키(bob 대신 alice 자신)로 암호화한 cookie도 열리지 않는다.
        let wrongKey = try cookieReply(rejecting: first, cookie: cookie, receiver: pair.key(.alice), nonce: nonce)
        #expect(throws: WireGuardError.authenticationFailed) { try pair.alice.receive(wrongKey, at: t0) }

        let retryAt = try #require(pair.alice.nextDeadline)
        let retry = pair.alice.advance(to: retryAt).datagrams[0]
        #expect(retry[132..<148].allSatisfy { $0 == 0 })
    }

    @Test("mac2가 붙은 initiation도 부하 상태가 아닌 응답자는 받아들인다")
    func responderAcceptsMAC2() throws {
        var pair = Pair()
        let packet = pair.packet(from: .alice)
        let first = try pair.alice.send(packet, to: pair.key(.bob), at: t0).datagrams[0]
        _ = try pair.alice.receive(try cookieReply(rejecting: first, cookie: cookie, receiver: pair.key(.bob), nonce: nonce), at: t0)
        let retryAt = try #require(pair.alice.nextDeadline)
        let retry = pair.alice.advance(to: retryAt)
        #expect(try pair.deliver(retry, from: .alice, at: retryAt)[.bob] == [packet])
    }
}
