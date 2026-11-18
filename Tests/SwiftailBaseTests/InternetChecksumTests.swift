import Testing

import SwiftailBase

/// Tests the Internet checksum (RFC 1071) against a specification example and a slow, independent calculation in the test.
@Suite("Internet checksum")
struct InternetChecksumTests {
    /// Computes a reference checksum independently of the implementation by summing words, adding carries back, and taking the complement.
    private func referenceChecksum(_ bytes: [UInt8]) -> UInt16 {
        var sum = 0
        for index in stride(from: 0, to: bytes.count, by: 2) {
            let low = index + 1 < bytes.count ? Int(bytes[index + 1]) : 0
            sum += Int(bytes[index]) << 8 | low
            while sum > 0xFFFF { sum = (sum & 0xFFFF) + (sum >> 16) }
        }
        return UInt16(~sum & 0xFFFF)
    }

    @Test("RFC 1071 §3 example with sum 0xddf2 and complement 0x220d")
    func rfcExample() {
        #expect(InternetChecksum.checksum(of: [0x00, 0x01, 0xF2, 0x03, 0xF4, 0xF5, 0xF6, 0xF7]) == 0x220D)
    }

    @Test("Known IPv4 header yields 0xb861 with the checksum field set to 0 and 0 when the populated field is included")
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

    @Test("Empty input yields 0xFFFF, and odd-length input is counted with an appended 0")
    func emptyAndOdd() {
        #expect(InternetChecksum().value == 0xFFFF)
        #expect(InternetChecksum.checksum(of: []) == 0xFFFF)
        #expect(InternetChecksum.checksum(of: [0x12, 0x34, 0x56]) == ~UInt16(0x1234 + 0x5600))
        #expect(InternetChecksum.checksum(of: [0xAB]) == ~UInt16(0xAB00))
    }

    @Test("Folds repeated carries")
    func manyCarries() {
        #expect(InternetChecksum.checksum(of: [UInt8](repeating: 0xFF, count: 70_000)) == 0)
        // Adding 3 words of 0xFFFF and 0x0001 gives 0x2FFFE, which folds to 0x10000 and then to 0x0001.
        #expect(InternetChecksum.checksum(of: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01]) == ~UInt16(0x0001))
    }

    @Test("Matches the reference calculation", arguments: [0, 1, 2, 3, 19, 20, 21, 63, 64, 1239, 1240, 1500, 65_535])
    func matchesReference(length: Int) {
        var random = SplitMix64(seed: UInt64(length) &+ 1)
        let bytes = random.bytes(length)
        #expect(InternetChecksum.checksum(of: bytes) == referenceChecksum(bytes), "Length \(length)")
    }

    @Test("Summing chunks matches summing the concatenation, even with an odd-length split")
    func chunkedEqualsWhole() {
        var random = SplitMix64(seed: 0xC4EC)
        for length in [1, 2, 3, 7, 40, 101] {
            let bytes = random.bytes(length)
            for split in 0...length {
                var checksum = InternetChecksum()
                checksum.add(bytes[..<split])
                checksum.add(bytes[split...])
                #expect(checksum.value == referenceChecksum(bytes), "Length \(length), split at \(split)")
            }
            // Three chunks, including an empty chunk in the middle.
            var checksum = InternetChecksum()
            checksum.add(bytes[..<(length / 3)])
            checksum.add([])
            checksum.add(bytes[(length / 3)..<(length / 3 * 2)])
            checksum.add(bytes[(length / 3 * 2)...])
            #expect(checksum.value == referenceChecksum(bytes), "Three chunks, length \(length)")
        }
    }

    @Test("The IPv4 pseudo-header yields the same sum as the concatenated bytes")
    func ipv4PseudoHeader() {
        let source: [UInt8] = [100, 64, 0, 1], destination: [UInt8] = [100, 64, 0, 2]
        var random = SplitMix64(seed: 4)
        let segment = random.bytes(33)
        var checksum = InternetChecksum()
        checksum.addPseudoHeader(source: source, destination: destination, protocolNumber: 6, length: segment.count)
        checksum.add(segment)
        // Manually concatenate source, destination, 0, protocol, and length (16 bits).
        let expected = source + destination + [0, 6, 0, 33] + segment
        #expect(checksum.value == referenceChecksum(expected))
    }

    @Test("The IPv6 pseudo-header yields the same sum as the concatenated bytes (32-bit length)")
    func ipv6PseudoHeader() {
        let source = [UInt8](hex: "fd7a115ca1e0ab120000000000000001")!
        let destination = [UInt8](hex: "fd7a115ca1e0ab120000000000000002")!
        var random = SplitMix64(seed: 6)
        let segment = random.bytes(70_000)
        var checksum = InternetChecksum()
        checksum.addPseudoHeader(source: source, destination: destination, protocolNumber: 6, length: segment.count)
        checksum.add(segment)
        // 70,000 = 0x0001_1170. The 32-bit length is followed by three 0 bytes and the next header.
        let expected = source + destination + [0x00, 0x01, 0x11, 0x70, 0, 0, 0, 6] + segment
        #expect(checksum.value == referenceChecksum(expected))
    }
}

/// Generates reproducible pseudorandom values (SplitMix64).
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
