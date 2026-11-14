import Testing

import SwiftailBase

/// 인터넷 체크섬(RFC 1071). 기대값은 규격의 예와, 시험 안에서 따로 짠 느린 계산이다.
@Suite("인터넷 체크섬")
struct InternetChecksumTests {
    /// 구현과 공유하지 않는 기준 계산: 낱말마다 더하고 올림을 되돌려 더한 뒤 보수.
    private func referenceChecksum(_ bytes: [UInt8]) -> UInt16 {
        var sum = 0
        for index in stride(from: 0, to: bytes.count, by: 2) {
            let low = index + 1 < bytes.count ? Int(bytes[index + 1]) : 0
            sum += Int(bytes[index]) << 8 | low
            while sum > 0xFFFF { sum = (sum & 0xFFFF) + (sum >> 16) }
        }
        return UInt16(~sum & 0xFFFF)
    }

    @Test("RFC 1071 3절의 예: 합 0xddf2, 보수 0x220d")
    func rfcExample() {
        #expect(InternetChecksum.checksum(of: [0x00, 0x01, 0xF2, 0x03, 0xF4, 0xF5, 0xF6, 0xF7]) == 0x220D)
    }

    @Test("알려진 IPv4 머리: 체크섬 필드를 0으로 두면 0xb861, 채워 넣고 더하면 0")
    func knownIPv4Header() {
        var header: [UInt8] = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00,
            0xC0, 0xA8, 0x00, 0x01, 0xC0, 0xA8, 0x00, 0xC7,
        ]
        #expect(InternetChecksum.checksum(of: header) == 0xB861)
        header[10] = 0xB8
        header[11] = 0x61
        #expect(InternetChecksum.checksum(of: header) == 0)
    }

    @Test("빈 입력은 0xFFFF, 홀수 길이는 0을 덧붙여 센다")
    func emptyAndOdd() {
        #expect(InternetChecksum().value == 0xFFFF)
        #expect(InternetChecksum.checksum(of: []) == 0xFFFF)
        #expect(InternetChecksum.checksum(of: [0x12, 0x34, 0x56]) == ~UInt16(0x1234 + 0x5600))
        #expect(InternetChecksum.checksum(of: [0xAB]) == ~UInt16(0xAB00))
    }

    @Test("올림이 여러 번 일어나도 접힌다")
    func manyCarries() {
        #expect(InternetChecksum.checksum(of: [UInt8](repeating: 0xFF, count: 70_000)) == 0)
        // 0xFFFF 낱말 3개와 0x0001: 합 0x2FFFE → 접으면 0x10000 → 접으면 0x0001.
        #expect(InternetChecksum.checksum(of: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01]) == ~UInt16(0x0001))
    }

    @Test("기준 계산과 같다", arguments: [0, 1, 2, 3, 19, 20, 21, 63, 64, 1239, 1240, 1500, 65_535])
    func matchesReference(length: Int) {
        var random = SplitMix64(seed: UInt64(length) &+ 1)
        let bytes = random.bytes(length)
        #expect(InternetChecksum.checksum(of: bytes) == referenceChecksum(bytes), "길이 \(length)")
    }

    @Test("나눠 더한 것은 이어 붙여 더한 것과 같다(홀수 길이로 나눠도)")
    func chunkedEqualsWhole() {
        var random = SplitMix64(seed: 0xC4EC)
        for length in [1, 2, 3, 7, 40, 101] {
            let bytes = random.bytes(length)
            for split in 0...length {
                var checksum = InternetChecksum()
                checksum.add(bytes[..<split])
                checksum.add(bytes[split...])
                #expect(checksum.value == referenceChecksum(bytes), "길이 \(length), 나눈 곳 \(split)")
            }
            // 세 조각, 빈 조각 사이에 끼워도.
            var checksum = InternetChecksum()
            checksum.add(bytes[..<(length / 3)])
            checksum.add([])
            checksum.add(bytes[(length / 3)..<(length / 3 * 2)])
            checksum.add(bytes[(length / 3 * 2)...])
            #expect(checksum.value == referenceChecksum(bytes), "세 조각, 길이 \(length)")
        }
    }

    @Test("IPv4 의사 머리는 이어 붙인 바이트와 같은 합을 낸다")
    func ipv4PseudoHeader() {
        let source: [UInt8] = [100, 64, 0, 1], destination: [UInt8] = [100, 64, 0, 2]
        var random = SplitMix64(seed: 4)
        let segment = random.bytes(33)
        var checksum = InternetChecksum()
        checksum.addPseudoHeader(source: source, destination: destination, protocolNumber: 6, length: segment.count)
        checksum.add(segment)
        // 출발, 목적, 0, 프로토콜, 길이(16비트)를 직접 이어 붙인 것.
        let expected = source + destination + [0, 6, 0, 33] + segment
        #expect(checksum.value == referenceChecksum(expected))
    }

    @Test("IPv6 의사 머리는 이어 붙인 바이트와 같은 합을 낸다(길이 32비트)")
    func ipv6PseudoHeader() {
        let source = [UInt8](hex: "fd7a115ca1e0ab120000000000000001")!
        let destination = [UInt8](hex: "fd7a115ca1e0ab120000000000000002")!
        var random = SplitMix64(seed: 6)
        let segment = random.bytes(70_000)
        var checksum = InternetChecksum()
        checksum.addPseudoHeader(source: source, destination: destination, protocolNumber: 6, length: segment.count)
        checksum.add(segment)
        // 70,000 = 0x0001_1170. 32비트 길이 다음에 0 셋과 next header.
        let expected = source + destination + [0x00, 0x01, 0x11, 0x70, 0, 0, 0, 6] + segment
        #expect(checksum.value == referenceChecksum(expected))
    }
}

/// 재현할 수 있는 의사 난수(SplitMix64).
struct SplitMix64: RandomNumberGenerator {
    private var state: UInt64

    init(seed: UInt64) { state = seed }

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
}
