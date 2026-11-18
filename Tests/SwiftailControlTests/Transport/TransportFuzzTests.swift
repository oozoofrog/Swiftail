// Contract unit test 2: No byte sequence sent by the server causes a trap.
//
// Generates input with a fixed random seed so each run uses the same inputs. Most fully random bytes are
// rejected at the first check, so include inputs with valid message prefixes or one changed byte to reach deeper branches.
// Checks only that the call returns without trapping, whether it returns a value or throws an error.

import Testing

@testable import SwiftailControl

@Suite("Arbitrary input")
struct TransportFuzzTests {
    private typealias V = TransportVectors
    private static let iterations = 2_000

    @Test("Upgrade response parser")
    func upgradeResponse() {
        var random = SplitMix64(seed: 1)
        let valid = Array("HTTP/1.1 101 Switching Protocols\r\nUpgrade: tailscale-control-protocol\r\n\r\n".utf8)
        for _ in 0..<Self.iterations {
            var parser = UpgradeResponseParser()
            for chunk in random.chunks(of: random.input(near: valid)) {
                // Keep feeding bytes on incomplete input (nil) or errors, and stop once the header is complete.
                guard (try? parser.receive(chunk)) == nil else { break }
            }
        }
    }

    @Test("Handshake response")
    func handshakeResponse() throws {
        var random = SplitMix64(seed: 2)
        let valid = try V.bytes(V.response) + V.bytes(V.serverRecords[0].record)
        let prototype = try V.handshake()
        for _ in 0..<Self.iterations {
            var handshake = prototype
            for chunk in random.chunks(of: random.input(near: valid)) {
                guard (try? handshake.receive(chunk)) == nil else { break }
            }
        }
    }

    @Test("Records")
    func records() throws {
        var random = SplitMix64(seed: 3)
        let valid = try V.serverRecords.flatMap { try V.bytes($0.record) }
        let prototype = try V.clientSession()
        for _ in 0..<Self.iterations {
            var session = prototype
            for chunk in random.chunks(of: random.input(near: valid)) {
                guard (try? session.receive(chunk)) != nil else { break }
            }
        }
    }

    @Test("early payload")
    func earlyPayload() {
        var random = SplitMix64(seed: 4)
        let json = Array("{\"nodeKeyChallenge\":\"chalpub:\(String(repeating: "5a", count: 32))\"}".utf8)
        let valid = [0xFF, 0xFF, 0xFF, 0x54, 0x53] + UInt32(json.count).bigEndianBytes + json
        for _ in 0..<Self.iterations {
            var parser = EarlyPayloadParser()
            for chunk in random.chunks(of: random.input(near: valid)) {
                guard (try? parser.receive(chunk)) == nil else { break }
            }
        }
    }
}

/// Deterministic pseudorandom generator for tests (SplitMix64).
private struct SplitMix64: RandomNumberGenerator {
    private var state: UInt64

    init(seed: UInt64) {
        state = seed
    }

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }

    mutating func bytes(_ count: Int) -> [UInt8] {
        (0..<count).map { _ in UInt8.random(in: .min ... .max, using: &self) }
    }

    /// Random bytes, a valid input prefix plus a random tail, or valid input with one changed byte.
    mutating func input(near valid: [UInt8]) -> [UInt8] {
        switch Int.random(in: 0..<3, using: &self) {
        case 0:
            return bytes(Int.random(in: 0...600, using: &self))
        case 1:
            return Array(valid.prefix(Int.random(in: 0...valid.count, using: &self))) + bytes(Int.random(in: 0...64, using: &self))
        default:
            var mutated = valid
            mutated[Int.random(in: 0..<mutated.count, using: &self)] = UInt8.random(in: .min ... .max, using: &self)
            return mutated
        }
    }

    /// Splits input into randomly sized chunks, including empty chunks.
    mutating func chunks(of input: [UInt8]) -> [[UInt8]] {
        var result: [[UInt8]] = []
        var start = 0
        repeat {
            let end = min(input.count, start + Int.random(in: 0...40, using: &self))
            result.append(Array(input[start..<end]))
            start = end
        } while start < input.count
        return result
    }
}
