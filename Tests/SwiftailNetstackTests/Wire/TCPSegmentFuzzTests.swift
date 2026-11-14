import Testing

import SwiftailBase

@testable import SwiftailNetstack

/// 어떤 바이트열에도 죽지 않는다(동작 X1). 씨앗은 고정이라 실패하면 같은 입력이 다시 나온다.
@Suite("TCP 세그먼트 해석: 임의 입력")
struct TCPSegmentFuzzTests {
    /// 해석에 성공했으면 다시 만들어 해석한 값이 같아야 한다(해석이 만든 값은 늘 만들 수 있는 값이다).
    private func checkInvariants(_ bytes: [UInt8], _ context: @autoclosure () -> String) {
        guard let parsed = try? TCPSegment(parsingIPPacket: bytes) else { return }
        guard let rebuilt = parsed.ipPacket() else {
            Issue.record("해석한 세그먼트를 만들 수 없다: \(context())")
            return
        }
        #expect((try? TCPSegment(parsingIPPacket: rebuilt)) == parsed, "\(context())")
    }

    @Test("순수 임의 바이트 1만 개(길이 0~120)")
    func pureRandom() {
        var random = WireFuzzRandom(seed: 0x7C9)
        for iteration in 0..<10_000 {
            let length = Int.random(in: 0...120, using: &random)
            var bytes = random.bytes(length)
            // 절반은 IP 버전을 4나 6으로 맞춰 머리 검사 뒤까지 가게 한다.
            if iteration % 2 == 0, !bytes.isEmpty { bytes[0] = bytes[0] & 0x0F | (iteration % 4 == 0 ? 0x40 : 0x60) }
            checkInvariants(bytes, "반복 \(iteration) \(bytes.hex)")
        }
    }

    @Test("머리와 체크섬이 맞는 IP 패킷 안의 임의 TCP 세그먼트 1만 개")
    func randomTCPBehindValidIPAndChecksum() {
        var random = WireFuzzRandom(seed: 0x0975)
        for iteration in 0..<10_000 {
            var segment = random.bytes(Int.random(in: 0...90, using: &random))
            // data offset을 5~15로 맞춰 머리 길이 검사와 옵션 영역까지 가게 한다.
            if segment.count >= 20 {
                segment[12] = UInt8(Int.random(in: 5...15, using: &random) << 4) | segment[12] & 0x0F
            }
            let packet = iteration % 2 == 0 ? RawPacket.ipv4(segment: segment) : RawPacket.ipv6(segment: segment)
            checkInvariants(packet, "반복 \(iteration) \(packet.hex)")
        }
    }

    /// 옵션 한 개. 규칙에 맞는 것만 만든다.
    private enum Item {
        case noOperation
        case maximumSegmentSize(UInt16)
        case windowScale(UInt8)
        case unknown(kind: UInt8, length: Int)

        func bytes(_ random: inout WireFuzzRandom) -> [UInt8] {
            switch self {
            case .noOperation: [1]
            case .maximumSegmentSize(let value): [2, 4, UInt8(value >> 8), UInt8(value & 0xFF)]
            case .windowScale(let shift): [3, 3, shift]
            case .unknown(let kind, let length): [kind, UInt8(length)] + random.bytes(length - 2)
            }
        }
    }

    @Test("규칙에 맞는 옵션 영역은 늘 해석되고, MSS·shift는 모델이 계산한 값이다(EOL 뒤는 쓰레기여도)")
    func grammarGeneratedOptions() throws {
        var random = WireFuzzRandom(seed: 0x6A4)
        for iteration in 0..<5_000 {
            let isIPv6 = iteration % 2 == 1
            var options: [UInt8] = []
            var expectedMSS: UInt16?
            var expectedShift: UInt8?
            for _ in 0..<12 {
                let item: Item
                switch Int.random(in: 0..<12, using: &random) {
                case 0...2: item = .noOperation
                case 3...5: item = .maximumSegmentSize([0, 1, 536, 1240, UInt16.random(in: 0...65_535, using: &random)].randomElement(using: &random) ?? 0)
                case 6...8: item = .windowScale(UInt8.random(in: 0...255, using: &random))
                default: item = .unknown(kind: UInt8.random(in: 4...255, using: &random), length: Int.random(in: 2...8, using: &random))
                }
                let bytes = item.bytes(&random)
                guard options.count + bytes.count <= 40 else { break }
                options += bytes
                switch item {
                case .maximumSegmentSize(let value): expectedMSS = value == 0 ? (isIPv6 ? 1220 : 536) : value
                case .windowScale(let shift): expectedShift = min(shift, 14)
                default: break
                }
                // 가끔 EOL을 놓고, 그 뒤는 길이가 틀린 옵션 같은 쓰레기로 채운다. 해석은 EOL에서 멈춘다.
                if options.count < 40, Int.random(in: 0..<10, using: &random) == 0 {
                    options.append(0)
                    options += random.bytes(Int.random(in: 0...(40 - options.count), using: &random))
                    break
                }
            }
            let segment = RawPacket.segment(flags: 0x02, options: options)
            let packet = isIPv6 ? RawPacket.ipv6(segment: segment) : RawPacket.ipv4(segment: segment)
            let parsed = try TCPSegment(parsingIPPacket: packet)
            #expect(parsed.maximumSegmentSize == expectedMSS, "반복 \(iteration) \(options.hex)")
            #expect(parsed.windowScale == expectedShift, "반복 \(iteration) \(options.hex)")
            checkInvariants(packet, "반복 \(iteration)")
        }
    }

    @Test("옵션 영역이 40바이트 임의 바이트인 SYN 1만 개")
    func randomOptionRegions() {
        var random = WireFuzzRandom(seed: 0x0B7)
        for iteration in 0..<10_000 {
            let options = random.bytes(40)
            let segment = RawPacket.segment(flags: 0x02, options: options)
            let packet = iteration % 2 == 0 ? RawPacket.ipv4(segment: segment) : RawPacket.ipv6(segment: segment)
            checkInvariants(packet, "반복 \(iteration) \(options.hex)")
        }
    }

    @Test("올바른 패킷의 바이트 하나를 바꾼 것 전부(모든 자리 × 여러 값, 체크섬 보정 포함)")
    func singleByteMutations() {
        let packets = [
            RawPacket.ipv4(segment: RawPacket.segment(flags: 0x02, options: [2, 4, 0x04, 0xD8, 1, 3, 3, 3], payload: [1, 2, 3])),
            RawPacket.ipv6(segment: RawPacket.segment(flags: 0x12, options: [2, 4, 0x04, 0xC4, 1, 3, 3, 3], payload: [1, 2, 3])),
        ]
        for packet in packets {
            for index in packet.indices {
                for value: UInt8 in [0x00, 0x01, 0x0F, 0x10, 0x40, 0x7F, 0x80, 0xFF] {
                    var mutated = packet
                    mutated[index] = value
                    checkInvariants(mutated, "자리 \(index) 값 \(value)")
                    // 체크섬을 다시 맞추면 옵션·머리 길이를 바꾼 것도 해석의 끝까지 간다.
                    checkInvariants(RawPacket.refixingTCPChecksum(mutated), "자리 \(index) 값 \(value) 체크섬 보정")
                }
            }
        }
    }
}
