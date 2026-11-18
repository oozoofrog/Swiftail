// Contract test 6. Passing any byte sequence to receive must not crash (random and boundary inputs of length 0–200).
// Inputs are pseudorandom with a fixed seed so failures can be reproduced exactly.

import Testing

@testable import SwiftailWireGuard

@Suite("Arbitrary input")
struct FuzzTests {
    @Test("Boundary inputs yield malformed")
    func boundaries() throws {
        var pair = Pair()
        let malformed: [[UInt8]] = [
            [],
            [4],
            [4, 0, 0, 0] + zeros(27),                // 31 bytes, below the 32-byte minimum
            [1, 0, 0, 0] + zeros(143),               // initiation 147
            [1, 0, 0, 0] + zeros(145),               // initiation 149
            [2, 0, 0, 0] + zeros(87),                // response 91
            [2, 0, 0, 0] + zeros(89),                // response 93
            [3, 0, 0, 0] + zeros(59),                // cookie reply 63
            [3, 0, 0, 0] + zeros(61),                // cookie reply 65
            [1, 0, 0, 1] + zeros(144),               // Reserved bytes are not all 0
            [4, 1, 0, 0] + zeros(28),
            [0, 0, 0, 0] + zeros(28),                // type 0
            [5, 0, 0, 0] + zeros(28),                // Unknown type
            [UInt8](repeating: 0xFF, count: 200),
        ]
        for input in malformed {
            #expect(throws: WireGuardError.malformed, "Length \(input.count)") { try pair.bob.receive(input, at: t0) }
        }
        // Messages of the correct size pass format checks and are rejected at the next step.
        #expect(throws: WireGuardError.authenticationFailed) { try pair.bob.receive([1, 0, 0, 0] + zeros(144), at: t0) }
        #expect(throws: WireGuardError.authenticationFailed) { try pair.bob.receive([2, 0, 0, 0] + zeros(88), at: t0) }
        #expect(throws: WireGuardError.unknownPeer) { try pair.bob.receive([3, 0, 0, 0] + zeros(60), at: t0) }
        #expect(throws: WireGuardError.unknownPeer) { try pair.bob.receive([4, 0, 0, 0] + zeros(28), at: t0) }
    }

    @Test("Random datagrams do not crash or change session state")
    func randomDatagrams() throws {
        var pair = Pair()
        try pair.establish()
        let bobIndex = try #require(pair.keypairs(of: .bob)?.current?.localIndex)
        let mac1Key = MAC.mac1Key(for: pair.key(.bob))
        var random = SplitMix64(seed: 0x5157_1F7A_0000_0001)

        var inputs: [[UInt8]] = []
        for length in 0...200 {
            for _ in 0..<8 {
                inputs.append(random.bytes(length))
            }
            // Input with a valid type header.
            for type in UInt8(1)...4 where length >= 4 {
                inputs.append([type, 0, 0, 0] + random.bytes(length - 4))
            }
            // Transport with an active receiver index reaches decryption.
            if length >= 8 {
                inputs.append([4, 0, 0, 0] + bobIndex.littleEndianBytes + random.bytes(length - 8))
            }
        }
        // Initiation and response with a valid mac1 reach the DH and AEAD stages.
        for _ in 0..<64 {
            let initiation = [1, 0, 0, 0] + random.bytes(112)
            inputs.append(initiation + MAC.authenticate(initiation, key: mac1Key) + random.bytes(16))
            let response = [2, 0, 0, 0] + random.bytes(4) + bobIndex.littleEndianBytes + random.bytes(48)
            inputs.append(response + MAC.authenticate(response, key: mac1Key) + zeros(16))
        }

        let deadline = pair.bob.nextDeadline
        let keypairs = pair.keypairs(of: .bob)?.localIndices
        for input in inputs {
            // Once handshake messages with valid mac1 at one instant cross the threshold (128 within 1 second), the device is under load and returns
            // a cookie reply instead of an error. All other input is rejected.
            do {
                let outputs = try pair.bob.receive(input, at: t0)
                #expect(outputs.count == 1 && outputs.allSatisfy { if case .cookieReply = $0 { true } else { false } })
            } catch {}
        }
        #expect(pair.bob.nextDeadline == deadline)
        #expect(pair.keypairs(of: .bob)?.localIndices == keypairs)

        // The session remains usable.
        let packet = pair.packet(from: .alice)
        let outputs = try pair.alice.send(packet, to: pair.key(.bob), at: t0 + .seconds(1))
        #expect(try pair.deliver(outputs, from: .alice, at: t0 + .seconds(1))[.bob] == [packet])
    }

    private func zeros(_ count: Int) -> [UInt8] {
        [UInt8](repeating: 0, count: count)
    }
}
