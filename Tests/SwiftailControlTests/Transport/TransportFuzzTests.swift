// 계약 단위 2 시험: 서버가 보낸 어떤 바이트열로도 트랩이 없다.
//
// 고정 시드 난수로 입력을 만들어 매번 같은 입력을 돌린다. 완전 무작위 바이트는 첫 검사에서 대부분
// 걸러지므로, 유효한 메시지의 앞부분을 붙이거나 한 바이트를 바꾼 입력도 섞어 깊은 분기까지 들어가게 한다.
// 결과(값이든 오류든)는 보지 않는다. 트랩 없이 돌아오는 것만 확인한다.

import Testing

@testable import SwiftailControl

@Suite("임의 입력")
struct TransportFuzzTests {
    private typealias V = TransportVectors
    private static let iterations = 2_000

    @Test("업그레이드 응답 파서")
    func upgradeResponse() {
        var random = SplitMix64(seed: 1)
        let valid = Array("HTTP/1.1 101 Switching Protocols\r\nUpgrade: tailscale-control-protocol\r\n\r\n".utf8)
        for _ in 0..<Self.iterations {
            var parser = UpgradeResponseParser()
            for chunk in random.chunks(of: random.input(near: valid)) {
                guard (try? parser.receive(chunk)) != nil else { break }
            }
        }
    }

    @Test("핸드셰이크 response")
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

    @Test("레코드")
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

/// 시험용 결정적 난수(SplitMix64).
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

    /// 무작위 바이트, 유효한 입력의 앞부분 + 무작위 꼬리, 한 바이트를 바꾼 유효한 입력 중 하나.
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

    /// 입력을 임의 크기의 조각으로 나눈다. 빈 조각도 섞는다.
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
