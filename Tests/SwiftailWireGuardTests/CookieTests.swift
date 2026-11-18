// Contract test 5. After a cookie reply arrives, subsequent handshake messages carry mac2. It is no longer used after 120 seconds.
//
// To pin down the receiver's format independently, the test constructs the reply an under-load responder would send according to the specification
// (using the same formula as `CreateReply` in wireguard-go `device/cookie.go`). `CookieReplyTests.swift` covers the device as sender.

import Testing

import SwiftailCrypto
@testable import SwiftailWireGuard

@Suite("cookie")
struct CookieTests {
    /// Builds the cookie reply the responder (receiver) sends for a rejected message.
    private func cookieReply(rejecting message: [UInt8], cookie: [UInt8], receiver: PublicKey, nonce: [UInt8]) throws -> [UInt8] {
        let mac1 = Array(message[(message.count - 32)..<(message.count - 16)])
        let encrypted = try XChaCha20Poly1305.seal(cookie, key: MAC.cookieKey(for: receiver), nonce: nonce, authenticating: mac1)
        return [3, 0, 0, 0] + Array(message[4..<8]) + nonce + encrypted
    }

    private let cookie: [UInt8] = Array(0x10..<0x20)
    private let nonce: [UInt8] = Array(0..<24)

    @Test("mac2 is 0 without a cookie")
    func noCookieNoMAC2() throws {
        var pair = Pair()
        let initiation = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0).datagrams[0]
        #expect(initiation[132..<148].allSatisfy { $0 == 0 })
        // mac1 = MAC(HASH("mac1----" ‖ bob's public key), first 116 bytes).
        #expect(Array(initiation[116..<132]) == MAC.authenticate(Array(initiation[..<116]), key: MAC.mac1Key(for: pair.key(.bob))))
    }

    @Test("Initiations carry mac2 after consuming a reply, and it returns to 0 after 120 seconds")
    func mac2AfterCookieReply() throws {
        var pair = Pair()
        let first = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0).datagrams[0]
        let reply = try cookieReply(rejecting: first, cookie: cookie, receiver: pair.key(.bob), nonce: nonce)

        let receivedAt = t0 + .milliseconds(10)
        #expect(try pair.alice.receive(reply, at: receivedAt).isEmpty)

        // The rejected initiation is not resent immediately. mac2 is attached starting with the next retry.
        let retryAt = try #require(pair.alice.nextDeadline)
        let retry = pair.alice.advance(to: retryAt).datagrams[0]
        #expect(Array(retry[132..<148]) == MAC.authenticate(Array(retry[..<132]), key: cookie))
        #expect(!retry[132..<148].allSatisfy { $0 == 0 })

        // After all retries fail, an initiation made more than 120 seconds after receiving the cookie has no mac2.
        while let deadline = pair.alice.nextDeadline, !pair.alice.advance(to: deadline).isEmpty {}
        let late = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: receivedAt + .seconds(121))
        #expect(late.messageTypes == [1])
        #expect(late.datagrams[0][132..<148].allSatisfy { $0 == 0 })
    }

    @Test("A cookie is used through exactly 120 seconds after receipt and expires after that")
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

    @Test("Rejects a tampered reply or unknown receiver and omits mac2")
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
        // A cookie encrypted with a different key (alice's own key instead of bob's) also fails to open.
        let wrongKey = try cookieReply(rejecting: first, cookie: cookie, receiver: pair.key(.alice), nonce: nonce)
        #expect(throws: WireGuardError.authenticationFailed) { try pair.alice.receive(wrongKey, at: t0) }

        let retryAt = try #require(pair.alice.nextDeadline)
        let retry = pair.alice.advance(to: retryAt).datagrams[0]
        #expect(retry[132..<148].allSatisfy { $0 == 0 })
    }

    @Test("A responder that is not under load also accepts initiations with mac2")
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
