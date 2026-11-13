// 계약 시험 6: 어떤 바이트열을 receive에 넣어도 죽지 않는다(길이 0~200의 무작위·경계 입력).
// 입력은 고정 시드의 의사 난수라 실패하면 그대로 재현된다.

import Testing

@testable import SwiftailWireGuard

@Suite("임의 입력")
struct FuzzTests {
    @Test("경계 입력은 malformed")
    func boundaries() throws {
        var pair = Pair()
        let malformed: [[UInt8]] = [
            [],
            [4],
            [4, 0, 0, 0] + zeros(27),                // 31바이트: 최소 32바이트 미만
            [1, 0, 0, 0] + zeros(143),               // initiation 147
            [1, 0, 0, 0] + zeros(145),               // initiation 149
            [2, 0, 0, 0] + zeros(87),                // response 91
            [2, 0, 0, 0] + zeros(89),                // response 93
            [3, 0, 0, 0] + zeros(59),                // cookie reply 63
            [3, 0, 0, 0] + zeros(61),                // cookie reply 65
            [1, 0, 0, 1] + zeros(144),               // 예약 바이트가 0이 아니다
            [4, 1, 0, 0] + zeros(28),
            [0, 0, 0, 0] + zeros(28),                // type 0
            [5, 0, 0, 0] + zeros(28),                // 모르는 type
            [UInt8](repeating: 0xFF, count: 200),
        ]
        for input in malformed {
            #expect(throws: WireGuardError.malformed, "길이 \(input.count)") { try pair.bob.receive(input, at: t0) }
        }
        // 크기가 맞는 메시지는 형식 검사를 통과하고 다음 단계에서 거절된다.
        #expect(throws: WireGuardError.authenticationFailed) { try pair.bob.receive([1, 0, 0, 0] + zeros(144), at: t0) }
        #expect(throws: WireGuardError.authenticationFailed) { try pair.bob.receive([2, 0, 0, 0] + zeros(88), at: t0) }
        #expect(throws: WireGuardError.unknownPeer) { try pair.bob.receive([3, 0, 0, 0] + zeros(60), at: t0) }
        #expect(throws: WireGuardError.unknownPeer) { try pair.bob.receive([4, 0, 0, 0] + zeros(28), at: t0) }
    }

    @Test("무작위 데이터그램으로 죽지 않고 세션 상태도 바뀌지 않는다")
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
            // type 머리가 맞는 입력.
            for type in UInt8(1)...4 where length >= 4 {
                inputs.append([type, 0, 0, 0] + random.bytes(length - 4))
            }
            // 살아 있는 receiver index를 가진 transport: 복호화 단계까지 들어간다.
            if length >= 8 {
                inputs.append([4, 0, 0, 0] + bobIndex.littleEndianBytes + random.bytes(length - 8))
            }
        }
        // mac1이 맞는 initiation·response: DH와 AEAD 단계까지 들어간다.
        for _ in 0..<64 {
            let initiation = [1, 0, 0, 0] + random.bytes(112)
            inputs.append(initiation + MAC.authenticate(initiation, key: mac1Key) + random.bytes(16))
            let response = [2, 0, 0, 0] + random.bytes(4) + bobIndex.littleEndianBytes + random.bytes(48)
            inputs.append(response + MAC.authenticate(response, key: mac1Key) + zeros(16))
        }

        let deadline = pair.bob.nextDeadline
        let keypairs = pair.keypairs(of: .bob)?.localIndices
        for input in inputs {
            #expect(throws: WireGuardError.self) { try pair.bob.receive(input, at: t0) }
        }
        #expect(pair.bob.nextDeadline == deadline)
        #expect(pair.keypairs(of: .bob)?.localIndices == keypairs)

        // 세션은 그대로 쓸 수 있다.
        let packet = pair.packet(from: .alice)
        let outputs = try pair.alice.send(packet, to: pair.key(.bob), at: t0 + .seconds(1))
        #expect(try pair.deliver(outputs, from: .alice, at: t0 + .seconds(1))[.bob] == [packet])
    }

    private func zeros(_ count: Int) -> [UInt8] {
        [UInt8](repeating: 0, count: count)
    }
}
