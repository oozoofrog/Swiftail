// Tests the cookie reply sender, including load detection, mac2 checks, cookie replies, secret rotation, and per-source rate limiting.
// Supply times directly for deterministic runs. Trigger load by crossing the input threshold or setting `underLoadUntil`.

import Foundation
import Testing

import SwiftailCrypto
@testable import SwiftailWireGuard

/// Returns bob under load and alice's first initiation to send to bob.
private func loadedPair() throws -> (pair: Pair, initiation: [UInt8]) {
    var pair = Pair()
    pair.bob.handshakeLoad.underLoadUntil = t0 + .seconds(600)
    let initiation = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0).datagrams[0]
    return (pair, initiation)
}

/// Builds an initiation with mac1 recomputed for `receiver`. The body can contain arbitrary bytes.
private func withValidMAC1(_ body: [UInt8], for receiver: PublicKey) -> [UInt8] {
    let head = Array(body[..<116])
    return head + MAC.authenticate(head, key: MAC.mac1Key(for: receiver)) + [UInt8](repeating: 0, count: 16)
}

private let elsewhere = WireGuardDevice.Source(address: [198, 51, 100, 9, 0x51, 0xA2], host: [198, 51, 100, 9])

@Suite("Load detection")
struct HandshakeLoadTests {
    @Test("The 128th message triggers load within less than 1 second. A count of 127 or 128 spanning exactly 1 second does not trigger load")
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
        // This is exactly 1 second after the first message. From here on, the window contains only 127 messages.
        #expect(!record(t0 + .seconds(1)))
        #expect(!record(t0 + .seconds(1) + .milliseconds(1)))
    }

    @Test("The load state persists for 1 second after detection and ends at that exact instant")
    func holdsForOneSecond() {
        var load = HandshakeLoad()
        func record(_ now: ContinuousClock.Instant) -> Bool { load.record(at: now) }
        for i in 0..<128 {
            _ = record(t0 + .milliseconds(7 * i))
        }
        let detected = t0 + .milliseconds(7 * 127)
        #expect(load.underLoadUntil == detected + .seconds(1))
        // The load state persists for the remaining duration even if the window does not reach 128 again.
        #expect(record(detected + .seconds(1) - .nanoseconds(1)))
        #expect(!record(detected + .seconds(1)))
    }

    @Test("Messages with an incorrect mac1 do not count toward load")
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

    @Test("Once initiations with valid mac1 cross the threshold, subsequent replies are cookie replies")
    func realInputCrossesThreshold() throws {
        var pair = Pair()
        let initiation = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0).datagrams[0]
        #expect(try pair.bob.receive(initiation, at: t0).messageTypes == [2])
        // A retransmitted initiation fails the timestamp check but counts because its mac1 is valid.
        for _ in 2..<128 {
            #expect(throws: WireGuardError.replayed) { try pair.bob.receive(initiation, at: t0) }
        }
        guard case let .cookieReply(reply)? = try pair.bob.receive(initiation, at: t0).first else {
            Issue.record("Expected a cookie reply at the threshold")
            return
        }
        #expect(reply.count == 64)
    }
}

@Suite("Sending cookie replies")
struct CookieReplySendingTests {
    @Test("Under load, an initiation without mac2 receives a 64-byte cookie reply and leaves handshake state intact")
    func replyFormat() throws {
        var (pair, initiation) = try loadedPair()
        let outputs = try pair.bob.receive(initiation, at: t0)
        guard case let .cookieReply(reply)? = outputs.first, outputs.count == 1 else {
            Issue.record("Expected exactly one cookie reply, got \(outputs)")
            return
        }
        #expect(reply.count == 64)
        #expect(Array(reply[0..<4]) == [3, 0, 0, 0])
        // The receiver is the sender of the rejected initiation.
        #expect(Array(reply[4..<8]) == Array(initiation[4..<8]))
        let peer = try #require(pair.bob.peers[pair.key(.alice)])
        #expect(peer.lastInitiationConsumed == nil && peer.lastAcceptedTimestamp == nil && peer.keypairs.current == nil && peer.keypairs.next == nil)

        // The sender (the Swift consumer code) opens it.
        #expect(try pair.alice.receive(reply, at: t0).isEmpty)
    }

    @Test("Before X25519, an initiation with a body that cannot be opened or from an unknown peer receives a cookie reply instead of an error")
    func noHandshakeComputation() throws {
        var (pair, initiation) = try loadedPair()
        var random = SplitMix64(seed: 0xC00C1E)
        // With a random body and no load, the DH step yields authenticationFailed.
        let garbage = withValidMAC1([1, 0, 0, 0] + random.bytes(144), for: pair.key(.bob))
        var idle = Pair()
        #expect(throws: WireGuardError.authenticationFailed) { try idle.bob.receive(withValidMAC1(garbage, for: idle.key(.bob)), at: t0) }
        guard case .cookieReply? = try pair.bob.receive(garbage, at: t0).first else {
            Issue.record("Attempted to process an initiation that could not be opened")
            return
        }
        pair.bob.removePeer(pair.key(.alice))
        guard case .cookieReply? = try pair.bob.receive(initiation, at: t0).first else {
            Issue.record("Attempted to process an initiation from an unknown peer")
            return
        }
    }

    @Test("An initiator retry after receiving a cookie has a valid mac2 and completes the handshake")
    func roundTrip() throws {
        var (pair, initiation) = try loadedPair()
        let packet = pair.packet(from: .alice)
        // deliver returns the cookie reply to the sender. The first attempt ends with only a cookie.
        #expect(try pair.deliver([.datagram(initiation, to: pair.key(.bob))], from: .alice, at: t0)[.bob] == [])
        let retryAt = try #require(pair.alice.nextDeadline)
        let retry = pair.alice.advance(to: retryAt)
        #expect(try pair.deliver(retry, from: .alice, at: retryAt)[.bob] == [packet])
    }

    @Test("Rejects a mac2 obtained from a different source")
    func mac2BoundToSource() throws {
        var (pair, initiation) = try loadedPair()
        let reply = try pair.bob.receive(initiation, at: t0)
        guard case let .cookieReply(bytes)? = reply.first else { throw WireGuardError.malformed }
        _ = try pair.alice.receive(bytes, at: t0)
        let retryAt = try #require(pair.alice.nextDeadline)
        let retried = pair.alice.advance(to: retryAt).datagrams[0]
        guard case .cookieReply? = try pair.bob.receive(retried, from: elsewhere, at: retryAt).first else {
            Issue.record("Accepted mac2 from a different source")
            return
        }
        #expect(try pair.bob.receive(retried, at: retryAt).messageTypes == [2])
    }

    @Test("Rejects a cookie made with a secret more than 120 seconds old and rotates the secret then")
    func staleSecret() throws {
        var (pair, initiation) = try loadedPair()
        guard case let .cookieReply(first)? = try pair.bob.receive(initiation, at: t0).first else { throw WireGuardError.malformed }
        // alice received the cookie 10 ms later, so it still uses the cookie after 120 seconds and 5 ms. bob's secret is more than 120 seconds old at that point.
        _ = try pair.alice.receive(first, at: t0 + .milliseconds(10))
        while let deadline = pair.alice.nextDeadline, !pair.alice.advance(to: deadline).isEmpty {}
        let late = t0 + .seconds(120) + .milliseconds(5)
        let stale = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: late).datagrams[0]
        #expect(!stale[132..<148].allSatisfy { $0 == 0 })
        guard case let .cookieReply(second)? = try pair.bob.receive(stale, at: late).first else {
            Issue.record("Accepted a cookie from an old secret")
            return
        }
        // A cookie made with the new secret completes the handshake.
        _ = try pair.alice.receive(second, at: late)
        let retryAt = try #require(pair.alice.nextDeadline)
        #expect(try pair.deliver(pair.alice.advance(to: retryAt), from: .alice, at: retryAt)[.bob]?.count == 1)
    }

    @Test("Uses a secret through exactly 120 seconds after creation and rotates it when making a subsequent reply")
    func secretRotation() throws {
        let receiver = try #require(PublicKey(rawValue: [UInt8](repeating: 0x42, count: 32)))
        var checker = CookieChecker(publicKey: receiver)
        var generator = CookieGenerator(peer: receiver)
        var random = SplitMix64(seed: 7)
        let body = [UInt8](repeating: 7, count: 116)

        /// Returns the MAC that the generator appends to the body and the reply made with that mac1.
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
        // The reply made at exactly 120 seconds uses the same secret and therefore has the same cookie.
        #expect(try reply(at: t0 + .seconds(120)).mac2 == first.mac2)
        // The later reply uses a new secret, so the old cookie is now invalid.
        let rotated = t0 + .seconds(120) + .nanoseconds(1)
        let second = try reply(at: rotated)
        #expect(second.mac2 != first.mac2)
        #expect(checker.isValidMAC2(second, over: body, from: .test, at: rotated))
        #expect(!checker.isValidMAC2(first, over: body, from: .test, at: rotated))
    }

    @Test("Under load, exceeding a burst of 5 per source host yields rateLimited even with valid mac2")
    func rateLimitAtDevice() throws {
        var (pair, initiation) = try loadedPair()
        guard case let .cookieReply(bytes)? = try pair.bob.receive(initiation, at: t0).first else { throw WireGuardError.malformed }
        _ = try pair.alice.receive(bytes, at: t0)
        let retryAt = try #require(pair.alice.nextDeadline)
        let retried = pair.alice.advance(to: retryAt).datagrams[0]
        #expect(try pair.bob.receive(retried, at: retryAt).messageTypes == [2])
        // Messages 2–5 are within quota and reach the handshake check (replayed because they have the same timestamp). The 6th is blocked before the check.
        for i in 1..<5 {
            #expect(throws: WireGuardError.replayed) { try pair.bob.receive(retried, at: retryAt + .nanoseconds(i)) }
        }
        #expect(throws: WireGuardError.rateLimited) { try pair.bob.receive(retried, at: retryAt + .nanoseconds(5)) }
    }

    @Test("Under load, a response also requires mac2")
    func responseNeedsMAC2() throws {
        var pair = Pair()
        let initiation = try pair.alice.send(pair.packet(from: .alice), to: pair.key(.bob), at: t0).datagrams[0]
        let response = try pair.bob.receive(initiation, at: t0).datagrams[0]
        pair.alice.handshakeLoad.underLoadUntil = t0 + .seconds(600)
        guard case let .cookieReply(reply)? = try pair.alice.receive(response, at: t0).first else {
            Issue.record("Processed a response without mac2")
            return
        }
        #expect(Array(reply[4..<8]) == Array(response[4..<8]))
        #expect(try pair.bob.receive(reply, at: t0).isEmpty)
    }

    @Test("Under load, arbitrary input and input with only a valid mac1 do not crash")
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

    @Test("dump does not expose the cookie secret or the rate-limiting table")
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
