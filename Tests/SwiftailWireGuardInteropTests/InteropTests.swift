import Foundation
import Testing
import SwiftailWireGuard

@Suite("M1 wireguard-go UDP interop", .enabled(if: wgpeerBinary != nil, "Skipping real Go interop tests because SWIFTAIL_WGPEER is missing"), .timeLimit(.minutes(4)))
struct WireGuardInteropTests {
    @Test("Preserves bytes in both directions with either side as initiator", arguments: [true, false])
    func handshake(swiftInitiates: Bool) async throws {
        try await withInteropPair { pair in
            try await pair.establish(swiftInitiates: swiftInitiates)
        }
    }

    @Test("IPv4 sizes and padding boundaries in both directions", arguments: [20, 21, 35, 36, 37, 1280, 1420])
    func sizes(size: Int) async throws {
        try await withInteropPair { pair in
            try await pair.swiftToGo(size: size)
            try await pair.goToSwift(size: size)
        }
    }

    @Test("IPv6 length and padding in both directions")
    func ipv6() async throws {
        try await withInteropPair { pair in
            try await pair.swiftToGo(size: 1291, ipv6: true)
            try await pair.goToSwift(size: 1291, ipv6: true)
        }
    }

    @Test("Recovers from loss of the first response with a new initiation")
    func lostResponse() async throws {
        try await withInteropPair { pair in
            await pair.swift.dropIncoming(1)
            let start = ContinuousClock.now
            try await pair.swiftToGo(timeout: .seconds(20))
            try await pair.goToSwift()
            let history = await pair.swift.datagrams()
            let attempts = history.filter { !$0.incoming && $0.bytes.first == 1 }
            guard let first = attempts.first, let second = attempts.dropFirst().first else {
                throw InteropFailure("No initiation retry during loss recovery")
            }
            guard history.contains(where: { $0.incoming && $0.dropped && $0.bytes.first == 2 }),
                  second.time - first.time >= .seconds(5), second.time - first.time < .seconds(10),
                  first.bytes != second.bytes, ContinuousClock.now - start >= .seconds(5) else {
                throw InteropFailure("Observed response loss and 5-second retry did not match expectations")
            }
            // Every retry must use a new sender, ephemeral, and encrypted timestamp.
            for range in [4..<8, 8..<40, 88..<116] {
                guard first.bytes[range] != second.bytes[range] else {
                    throw InteropFailure("Retry reused an initiation field: \(range)")
                }
            }
        }
    }

    @Test("With Swift responding under load, Go receives a cookie reply, resends with mac2, and completes the handshake")
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
                throw InteropFailure("Unexpected number of initiations, cookie replies, or responses")
            }
            guard first.bytes[132..<148].allSatisfy({ $0 == 0 }), !accepted.bytes[132..<148].allSatisfy({ $0 == 0 }),
                  reply.bytes.count == 64, reply.bytes[4..<8] == first.bytes[4..<8],
                  reply.time < accepted.time, accepted.time < responses[0].time else {
                throw InteropFailure("Unexpected cookie reply format or order")
            }
        }
    }

    @Test("Keeps the session after rejecting tampering and preventing duplicate delivery")
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
                throw InteropFailure("No captured Go transport")
            }
            do {
                try await pair.swift.reinject(captured.bytes)
                throw InteropFailure("Swift accepted duplicate transport")
            } catch let error as WireGuardError {
                guard error == .replayed else { throw InteropFailure("Duplicate transport error: \(error)") }
            }
            var changed = captured.bytes
            changed[changed.count - 1] ^= 1
            do {
                try await pair.swift.reinject(changed)
                throw InteropFailure("Swift accepted tampered transport")
            } catch let error as WireGuardError {
                guard error == .authenticationFailed else { throw InteropFailure("Tampered transport error: \(error)") }
            }
            try await pair.swiftToGo(marker: 35)
            try await pair.goToSwift(marker: 36)
        }
    }

    @Test("Bidirectional transfer and rekey over 135 seconds of real time", arguments: [true, false])
    func rekey(swiftInitiates: Bool) async throws {
        try await withInteropPair { pair in
            try await pair.establish(swiftInitiates: swiftInitiates)
            let initial = try await pair.go.stats()
            guard let firstSec = initial.lastHandshakeSec, let firstNsec = initial.lastHandshakeNsec,
                  firstSec > 0 else { throw InteropFailure("No initial handshake time") }
            let start = ContinuousClock.now
            for round in 1...27 {
                try await ContinuousClock().sleep(until: start + .seconds(round * 5))
                try await pair.swiftToGo(marker: UInt8(round + 40))
                try await pair.goToSwift(marker: UInt8(round + 80))
            }
            let final = try await pair.go.stats()
            guard let finalSec = final.lastHandshakeSec, let finalNsec = final.lastHandshakeNsec,
                  finalSec != firstSec || finalNsec != firstNsec else {
                throw InteropFailure("Go lastHandshake did not change after 135 seconds")
            }
            guard ContinuousClock.now - start > .seconds(130) else {
                throw InteropFailure("Did not exceed 130 seconds of real time")
            }
        }
    }

    @Test("Resumes in both directions after 15 seconds of idle time and keepalive")
    func idleResume() async throws {
        try await withInteropPair { pair in
            try await pair.establish(swiftInitiates: true)
            let before = await pair.swift.datagrams().count
            try await Task.sleep(for: .seconds(15))
            let idle = await pair.swift.datagrams().dropFirst(before)
            guard idle.contains(where: { $0.bytes.first == 4 && $0.bytes.count == 32 }) else {
                throw InteropFailure("Keepalive path did not run during 15 seconds of idle time")
            }
            try await pair.swiftToGo(marker: 101)
            try await pair.goToSwift(marker: 102)
        }
    }
}
