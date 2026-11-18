import Testing

import SwiftailBase

@testable import SwiftailNetstack

/// Handles any byte sequence without crashing (behavior X1). Fixed seeds reproduce the same input on failure.
@Suite("TCP segment parsing with arbitrary input")
struct TCPSegmentFuzzTests {
    /// If parsing succeeds, rebuilding and parsing again must yield the same value (a parsed value is always serializable).
    private func checkInvariants(_ bytes: [UInt8], _ context: @autoclosure () -> String) {
        guard let parsed = try? TCPSegment(parsingIPPacket: bytes) else { return }
        guard let rebuilt = parsed.ipPacket() else {
            Issue.record("Could not build the parsed segment: \(context())")
            return
        }
        #expect((try? TCPSegment(parsingIPPacket: rebuilt)) == parsed, "\(context())")
    }

    @Test("10,000 purely random byte sequences (length 0~120)")
    func pureRandom() {
        var random = WireFuzzRandom(seed: 0x7C9)
        for iteration in 0..<10_000 {
            let length = Int.random(in: 0...120, using: &random)
            var bytes = random.bytes(length)
            // Set the IP version to 4 or 6 in half the cases so parsing goes beyond the header check.
            if iteration % 2 == 0, !bytes.isEmpty { bytes[0] = bytes[0] & 0x0F | (iteration % 4 == 0 ? 0x40 : 0x60) }
            checkInvariants(bytes, "Iteration \(iteration) \(bytes.hex)")
        }
    }

    @Test("10,000 random TCP segments inside IP packets with valid headers and checksums")
    func randomTCPBehindValidIPAndChecksum() {
        var random = WireFuzzRandom(seed: 0x0975)
        for iteration in 0..<10_000 {
            var segment = random.bytes(Int.random(in: 0...90, using: &random))
            // Set data offset to 5~15 so parsing reaches the header length check and option area.
            if segment.count >= 20 {
                segment[12] = UInt8(Int.random(in: 5...15, using: &random) << 4) | segment[12] & 0x0F
            }
            let packet = iteration % 2 == 0 ? RawPacket.ipv4(segment: segment) : RawPacket.ipv6(segment: segment)
            checkInvariants(packet, "Iteration \(iteration) \(packet.hex)")
        }
    }

    /// One option. Generates only valid ones.
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

    @Test("A valid option area always parses and yields the MSS and shift calculated by the model (even with garbage after EOL)")
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
                // Sometimes insert EOL, then fill the rest with garbage such as options with invalid lengths. Parsing stops at EOL.
                if options.count < 40, Int.random(in: 0..<10, using: &random) == 0 {
                    options.append(0)
                    options += random.bytes(Int.random(in: 0...(40 - options.count), using: &random))
                    break
                }
            }
            let segment = RawPacket.segment(flags: 0x02, options: options)
            let packet = isIPv6 ? RawPacket.ipv6(segment: segment) : RawPacket.ipv4(segment: segment)
            let parsed = try TCPSegment(parsingIPPacket: packet)
            #expect(parsed.maximumSegmentSize == expectedMSS, "Iteration \(iteration) \(options.hex)")
            #expect(parsed.windowScale == expectedShift, "Iteration \(iteration) \(options.hex)")
            checkInvariants(packet, "Iteration \(iteration)")
        }
    }

    @Test("10,000 SYNs with 40 random bytes in the option area")
    func randomOptionRegions() {
        var random = WireFuzzRandom(seed: 0x0B7)
        for iteration in 0..<10_000 {
            let options = random.bytes(40)
            let segment = RawPacket.segment(flags: 0x02, options: options)
            let packet = iteration % 2 == 0 ? RawPacket.ipv4(segment: segment) : RawPacket.ipv6(segment: segment)
            checkInvariants(packet, "Iteration \(iteration) \(options.hex)")
        }
    }

    @Test("All single-byte mutations of a valid packet (every position × multiple values, including checksum correction)")
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
                    checkInvariants(mutated, "Position \(index), value \(value)")
                    // Recomputing the checksum allows mutations of options and header length to reach the end of parsing.
                    checkInvariants(RawPacket.refixingTCPChecksum(mutated), "Position \(index), value \(value), checksum corrected")
                }
            }
        }
    }
}
