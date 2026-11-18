// DNS test helpers for building query bytes and parsing response bytes.
// Parse responses independently of the codec under test. The responder uses no name compression, so this parser does not handle pointers.

import Testing

import SwiftailBase

/// DNS query bytes for tests.
enum DNSWire {
    /// Query flags with only RD set.
    static let recursionDesired: UInt16 = 0x0100

    /// Encodes a dotted name in uncompressed wire format. The empty string and `.` represent the root.
    static func name(_ text: String) -> [UInt8] {
        var bytes: [UInt8] = []
        for label in text.split(separator: ".") {
            bytes.append(UInt8(label.utf8.count))
            bytes += label.utf8
        }
        return bytes + [0]
    }

    /// Builds a single-question query with CLASS IN.
    static func query(_ name: String, type: UInt16, id: UInt16 = 0xBEEF, flags: UInt16 = recursionDesired) -> [UInt8] {
        header(id: id, flags: flags, questions: 1) + question(name, type: type)
    }

    /// Builds a query with an optionless EDNS 0 OPT in the additional section (advertised size `udpPayloadSize`).
    static func query(_ name: String, type: UInt16, udpPayloadSize: UInt16) -> [UInt8] {
        header(id: 0xBEEF, flags: recursionDesired, questions: 1, additionals: 1)
            + question(name, type: type)
            + [0] + bigEndian(41) + bigEndian(udpPayloadSize) + [0, 0, 0, 0] + bigEndian(0)
    }

    static func header(id: UInt16, flags: UInt16, questions: UInt16, additionals: UInt16 = 0) -> [UInt8] {
        bigEndian(id) + bigEndian(flags) + bigEndian(questions) + [0, 0, 0, 0] + bigEndian(additionals)
    }

    static func question(_ name: String, type: UInt16) -> [UInt8] {
        self.name(name) + bigEndian(type) + bigEndian(1)
    }

    static func bigEndian(_ value: UInt16) -> [UInt8] {
        [UInt8(value >> 8), UInt8(value & 0xFF)]
    }

    /// Builds a name whose presentation length, including the trailing dot, is `length`. Fills 63-byte labels from the start.
    static func nameText(presentationLength length: Int, letter: Character = "a") -> String {
        var labels: [String] = []
        var remaining = length
        while remaining > 0 {
            let count = min(63, remaining - 1)
            labels.append(String(repeating: letter, count: count))
            remaining -= count + 1
        }
        return labels.joined(separator: ".") + "."
    }
}

/// Response fields inspected by tests.
struct DecodedResponse {
    struct Record {
        let name: String
        let type: UInt16
        let ttl: UInt32
        let data: [UInt8]
    }

    struct Malformed: Error {}

    let id: UInt16
    let flags: UInt16
    let questionName: String?
    let questionType: UInt16?
    let answer: Record?
    let authority: Record?
    let additionalCount: UInt16

    var responseCode: UInt16 { flags & 0x000F }
    func has(_ bit: UInt16) -> Bool { flags & bit != 0 }

    init(_ bytes: [UInt8]) throws {
        var reader = Reader(bytes: bytes)
        id = try reader.uint16()
        flags = try reader.uint16()
        let counts = try (0..<4).map { _ in try reader.uint16() }
        guard counts[0] <= 1, counts[1] <= 1, counts[2] <= 1 else { throw Malformed() }
        additionalCount = counts[3]
        if counts[0] == 1 {
            questionName = try reader.name()
            questionType = try reader.uint16()
            _ = try reader.uint16()
        } else {
            questionName = nil
            questionType = nil
        }
        answer = counts[1] == 1 ? try reader.record() : nil
        authority = counts[2] == 1 ? try reader.record() : nil
        guard reader.offset == bytes.count else { throw Malformed() }
    }

    private struct Reader {
        let bytes: [UInt8]
        var offset = 0

        mutating func take(_ count: Int) throws -> [UInt8] {
            guard offset + count <= bytes.count else { throw Malformed() }
            defer { offset += count }
            return Array(bytes[offset..<offset + count])
        }

        mutating func uint16() throws -> UInt16 {
            let pair = try take(2)
            return UInt16(pair[0]) << 8 | UInt16(pair[1])
        }

        mutating func name() throws -> String {
            var labels: [String] = []
            while true {
                let length = Int(try take(1)[0])
                if length == 0 { return labels.joined(separator: ".") + "." }
                guard length < 64 else { throw Malformed() }
                labels.append(String(decoding: try take(length), as: UTF8.self))
            }
        }

        mutating func record() throws -> Record {
            let name = try name()
            let type = try uint16()
            guard try uint16() == 1 else { throw Malformed() }
            let ttl = UInt32(try uint16()) << 16 | UInt32(try uint16())
            let length = Int(try uint16())
            return Record(name: name, type: type, ttl: ttl, data: try take(length))
        }
    }
}

/// Decodes a hex string into bytes for test vectors.
func hexBytes(_ text: String) throws -> [UInt8] {
    try #require([UInt8](hex: text))
}
