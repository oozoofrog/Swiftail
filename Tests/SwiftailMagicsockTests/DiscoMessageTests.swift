import Foundation
import Testing

import SwiftailBase

@testable import SwiftailMagicsock

/// The disco section of `magicsock-vectors.json`. `Tools/interop/cmd/magicsockvectors` generates it with Go's `disco` and `key` packages.
/// See the magicsockvectors section of `Tools/interop/README.md` to regenerate it. It contains no current timestamps or production keys.
enum DiscoVectors {
    struct File: Decodable {
        let keys: [Key]
        let disco: Disco

        func key(_ name: String) throws -> Key {
            try #require(keys.first { $0.name == name }, "Vectors have no key named \(name)")
        }
    }

    struct Key: Decodable {
        let name: String
        let seed: String
        let publicHex: String

        private enum CodingKeys: String, CodingKey {
            case name, seed
            case publicHex = "public"
        }
    }

    struct Disco: Decodable {
        let messages: [Sealed]
        let parse: [ParseCase]
    }

    /// A message sealed by Go, including the plaintext and the entire outer format.
    struct Sealed: Decodable {
        let name: String
        let sender: String
        let receiver: String
        let message: Described
        let plaintext: String
        let nonce: String
        let packet: String
    }

    /// The result of passing plaintext to `disco.Parse`. Success has `result` and failure has `error` (the Go error message).
    struct ParseCase: Decodable {
        let name: String
        let plaintext: String
        let result: Described?
        let error: String?
    }

    /// The human-readable form of a parsed message. A `kind` of `relay` is a type only Go parses.
    struct Described: Decodable {
        let kind: String
        let txID: String?
        let nodeKey: String?
        let padding: Int?
        let src: String?
        let endpoints: [String]?

        /// The message Swiftail parses. `relay` yields nil.
        func message() throws -> DiscoMessage? {
            switch kind {
            case "ping":
                let id = try transactionID()
                let key = try nodeKey.map { hex -> NodePublicKey in
                    let bytes = try DiscoVectors.bytes(hex)
                    return try #require(NodePublicKey(rawValue: bytes))
                }
                return .ping(id, nodeKey: key)
            case "pong":
                let text = try #require(src)
                return .pong(try transactionID(), source: try #require(IPEndpoint(text)))
            case "callMeMaybe":
                let texts = endpoints ?? []
                return .callMeMaybe(try texts.map { try #require(IPEndpoint($0)) })
            default:
                return nil
            }
        }

        private func transactionID() throws -> TransactionID {
            let hex = try #require(txID)
            let bytes = try DiscoVectors.bytes(hex)
            return try #require(TransactionID(bytes))
        }
    }

    static func load() throws -> File {
        let url = try #require(Bundle.module.url(forResource: "magicsock-vectors", withExtension: "json", subdirectory: "Fixtures"))
        return try JSONDecoder().decode(File.self, from: Data(contentsOf: url))
    }

    static func bytes(_ hex: String) throws -> [UInt8] {
        try #require([UInt8](hex: hex), "Expected a base-16 string")
    }
}

@Suite("DiscoMessage")
struct DiscoMessageTests {
    private let txID: TransactionID
    private let nodeKey: NodePublicKey

    init() throws {
        txID = try #require(TransactionID(Array(UInt8(1)...UInt8(12))))
        nodeKey = try #require(NodePublicKey(rawValue: Array(UInt8(0x30)...UInt8(0x4F))))
    }

    private func endpoint(_ text: String) throws -> IPEndpoint {
        try #require(IPEndpoint(text))
    }

    /// Builds plaintext from the header (type and version) and body.
    private func plaintext(type: UInt8, version: UInt8 = 0, body: [UInt8]) -> [UInt8] {
        [type, version] + body
    }

    private func zeros(_ count: Int) -> [UInt8] {
        [UInt8](repeating: 0, count: count)
    }

    /// An 18-byte wire address for IPv4-mapped `192.0.2.<last>:<port>`.
    private func mappedWire(last: UInt8, port: UInt16) -> [UInt8] {
        zeros(10) + [0xFF, 0xFF, 192, 0, 2, last, UInt8(port >> 8), UInt8(port & 0xFF)]
    }

    // MARK: Encoding and round trips

    @Test("Ping plaintext contains type 1, version 0, TxID, and NodeKey in that order")
    func pingLayout() {
        let withKey = DiscoMessage.ping(txID, nodeKey: nodeKey)
        #expect(withKey.plaintext == [0x01, 0x00] + txID.bytes + nodeKey.rawValue)
        #expect(DiscoMessage.ping(txID, nodeKey: nil).plaintext == [0x01, 0x00] + txID.bytes)
    }

    @Test("Pong plaintext encodes IPv4 as 16 IPv4-mapped bytes followed by a BE port")
    func pongLayout() throws {
        let message = DiscoMessage.pong(txID, source: try endpoint("192.0.2.1:5000"))
        #expect(message.plaintext == [0x02, 0x00] + txID.bytes + mappedWire(last: 1, port: 5000))
        let v6 = DiscoMessage.pong(txID, source: try endpoint("[2001:db8::7]:5060"))
        let address = try #require(IPAddress("2001:db8::7")).bytes
        #expect(v6.plaintext == [0x02, 0x00] + txID.bytes + address + [0x13, 0xC4])
    }

    @Test("CallMeMaybe plaintext uses 18 bytes per address and has no count field")
    func callMeMaybeLayout() throws {
        #expect(DiscoMessage.callMeMaybe([]).plaintext == [0x03, 0x00])
        let message = DiscoMessage.callMeMaybe([try endpoint("192.0.2.1:1001"), try endpoint("192.0.2.2:1002")])
        #expect(message.plaintext == [0x03, 0x00] + mappedWire(last: 1, port: 1001) + mappedWire(last: 2, port: 1002))
    }

    @Test("Every type round-trips through plaintext")
    func roundTrip() throws {
        let messages: [DiscoMessage] = [
            .ping(txID, nodeKey: nodeKey),
            .ping(txID, nodeKey: nil),
            .pong(txID, source: try endpoint("127.0.0.1:41641")),
            .pong(txID, source: try endpoint("[2001:db8::7]:5060")),
            .pong(txID, source: try endpoint("0.0.0.0:0")),
            .callMeMaybe([]),
            .callMeMaybe([try endpoint("192.0.2.1:41641")]),
            .callMeMaybe([try endpoint("192.0.2.1:1"), try endpoint("[2001:db8::7]:65535"), try endpoint("169.254.1.2:9")]),
        ]
        for message in messages {
            #expect(try DiscoMessage(parsing: message.plaintext) == message, "\(message)")
        }
    }

    @Test("Omits a NodeKey filled with 0 on send and treats it as absent on receive")
    func zeroNodeKeyIsAbsent() throws {
        let message = DiscoMessage.ping(txID, nodeKey: .zero)
        #expect(message.plaintext == [0x01, 0x00] + txID.bytes)
        #expect(try DiscoMessage(parsing: message.plaintext) == .ping(txID, nodeKey: nil))
    }

    // MARK: Boundaries

    @Test("Plaintext shorter than 2 bytes yields a format error", arguments: [0, 1])
    func tooShortPlaintext(_ count: Int) {
        #expect(throws: DiscoError.malformed) { try DiscoMessage(parsing: [UInt8](repeating: 0x01, count: count)) }
    }

    @Test("Reads a 12-byte Ping body without NodeKey, a 44-byte body with NodeKey, and trailing bytes at 45 bytes or more as padding")
    func pingBodyLengths() throws {
        let key = nodeKey.rawValue
        #expect(try DiscoMessage(parsing: plaintext(type: 1, body: txID.bytes)) == .ping(txID, nodeKey: nil))
        #expect(try DiscoMessage(parsing: plaintext(type: 1, body: txID.bytes + key)) == .ping(txID, nodeKey: nodeKey))
        #expect(try DiscoMessage(parsing: plaintext(type: 1, body: txID.bytes + key + [0])) == .ping(txID, nodeKey: nodeKey))
        // If fewer than 32 bytes are available for NodeKey, all of them are padding.
        #expect(try DiscoMessage(parsing: plaintext(type: 1, body: txID.bytes + key.prefix(31))) == .ping(txID, nodeKey: nil))
        #expect(try DiscoMessage(parsing: plaintext(type: 1, body: txID.bytes + zeros(5))) == .ping(txID, nodeKey: nil))
    }

    @Test("A Ping body of 11 bytes or less yields a format error", arguments: [0, 1, 11])
    func pingTooShort(_ count: Int) {
        #expect(throws: DiscoError.malformed) { try DiscoMessage(parsing: plaintext(type: 1, body: zeros(count))) }
    }

    @Test("A NodeKey field with all 32 bytes set to 0 is padding and leaves NodeKey absent")
    func zeroNodeKeyOnTheWire() throws {
        #expect(try DiscoMessage(parsing: plaintext(type: 1, body: txID.bytes + zeros(32))) == .ping(txID, nodeKey: nil))
        #expect(try DiscoMessage(parsing: plaintext(type: 1, body: txID.bytes + zeros(64))) == .ping(txID, nodeKey: nil))
    }

    @Test("Reads NodeKey even in a Ping with long padding")
    func pingWithLongPadding() throws {
        let body = txID.bytes + nodeKey.rawValue + zeros(1400)
        #expect(try DiscoMessage(parsing: plaintext(type: 1, body: body)) == .ping(txID, nodeKey: nodeKey))
    }

    @Test("Ping and Pong ignore version")
    func versionIgnoredByPingAndPong() throws {
        #expect(try DiscoMessage(parsing: plaintext(type: 1, version: 7, body: txID.bytes + nodeKey.rawValue)) == .ping(txID, nodeKey: nodeKey))
        let pong = txID.bytes + mappedWire(last: 1, port: 5000)
        #expect(try DiscoMessage(parsing: plaintext(type: 2, version: 1, body: pong)) == .pong(txID, source: try endpoint("192.0.2.1:5000")))
    }

    @Test("A 29-byte Pong body yields a format error. Accepts 30 bytes and any trailing bytes")
    func pongBodyLengths() throws {
        let body = txID.bytes + mappedWire(last: 1, port: 5000)
        #expect(throws: DiscoError.malformed) { try DiscoMessage(parsing: plaintext(type: 2, body: Array(body.prefix(29)))) }
        let expected = DiscoMessage.pong(txID, source: try endpoint("192.0.2.1:5000"))
        #expect(try DiscoMessage(parsing: plaintext(type: 2, body: body)) == expected)
        #expect(try DiscoMessage(parsing: plaintext(type: 2, body: body + [0xEE, 0xEE])) == expected)
    }

    @Test("Decodes IPv4-mapped addresses as IPv4 and leaves other 16-byte addresses as IPv6")
    func unmapping() throws {
        func pong(ip: [UInt8]) throws -> DiscoMessage {
            try DiscoMessage(parsing: plaintext(type: 2, body: txID.bytes + ip + [0, 80]))
        }
        let mapped = zeros(10) + [0xFF, 0xFF, 10, 1, 2, 3]
        #expect(try pong(ip: mapped) == .pong(txID, source: try endpoint("10.1.2.3:80")))
        // IPv4-compatible (::a.b.c.d) and addresses with a prefix containing bytes other than 0 before ::ffff are not mapped.
        let compatible = zeros(12) + [10, 1, 2, 3]
        #expect(try pong(ip: compatible) == .pong(txID, source: IPEndpoint(address: try #require(IPAddress(bytes: compatible)), port: 80)))
        var notMapped = mapped
        notMapped[0] = 1
        #expect(try pong(ip: notMapped) == .pong(txID, source: IPEndpoint(address: try #require(IPAddress(bytes: notMapped)), port: 80)))
    }

    @Test("CallMeMaybe parses as an empty list if version ≠ 0, the body has 0 bytes, or the body length is not a multiple of 18")
    func callMeMaybeLenientEmpty() throws {
        let one = mappedWire(last: 1, port: 1001)
        #expect(try DiscoMessage(parsing: plaintext(type: 3, body: [])) == .callMeMaybe([]))
        #expect(try DiscoMessage(parsing: plaintext(type: 3, body: Array(one.prefix(17)))) == .callMeMaybe([]))
        #expect(try DiscoMessage(parsing: plaintext(type: 3, body: one + [0])) == .callMeMaybe([]))
        #expect(try DiscoMessage(parsing: plaintext(type: 3, body: Array((one + one).prefix(35)))) == .callMeMaybe([]))
        #expect(try DiscoMessage(parsing: plaintext(type: 3, version: 1, body: one)) == .callMeMaybe([]))
        #expect(try DiscoMessage(parsing: plaintext(type: 3, body: one)) == .callMeMaybe([try endpoint("192.0.2.1:1001")]))
    }

    @Test("Reads every address from the largest CallMeMaybe that fits in a datagram")
    func largestCallMeMaybe() throws {
        let count = 65_000 / 18
        let body = (0..<count).flatMap { mappedWire(last: UInt8($0 % 250), port: UInt16($0 % 60_000)) }
        guard case .callMeMaybe(let endpoints) = try DiscoMessage(parsing: plaintext(type: 3, body: body)) else {
            Issue.record("Expected CallMeMaybe")
            return
        }
        #expect(endpoints.count == count)
    }

    @Test("Types outside 0x01–0x03 yield unknownType, including peer relay types 0x04–0x09", arguments: [0x00, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x7F, 0xFF] as [UInt8])
    func unknownTypes(_ type: UInt8) {
        // Fill the body to the length Go parses so the type is the sole reason for rejection.
        #expect(throws: DiscoError.unknownType(type)) { try DiscoMessage(parsing: plaintext(type: type, body: zeros(200))) }
    }

    // MARK: Go reference values

    @Test("Produces the same plaintext bytes as Go and parses them as the same message")
    func goPlaintextVectors() throws {
        for sealed in try DiscoVectors.load().disco.messages {
            let described = try sealed.message.message()
            let message = try #require(described, "\(sealed.name)")
            let goPlaintext = try DiscoVectors.bytes(sealed.plaintext)
            // Ping padding is discarded on read, so padded plaintext does not round-trip byte for byte.
            if sealed.message.padding ?? 0 == 0 {
                #expect(message.plaintext == goPlaintext, "\(sealed.name): encoding")
            }
            #expect(try DiscoMessage(parsing: goPlaintext) == message, "\(sealed.name): parsing")
        }
    }

    @Test("Agrees with Go `disco.Parse` on boundary plaintext that it accepts and rejects")
    func goParseBoundaries() throws {
        let cases = try DiscoVectors.load().disco.parse
        #expect(cases.count > 20)
        for entry in cases {
            let bytes = try DiscoVectors.bytes(entry.plaintext)
            if let result = entry.result {
                if let expected = try result.message() {
                    #expect(try DiscoMessage(parsing: bytes) == expected, "\(entry.name)")
                } else {
                    // Swiftail returns unknownType based solely on the type for peer relay types only Go parses.
                    #expect(throws: DiscoError.unknownType(bytes[0]), "\(entry.name)") { try DiscoMessage(parsing: bytes) }
                }
            } else if entry.error?.hasPrefix("unknown message type") == true {
                #expect(throws: DiscoError.unknownType(bytes[0]), "\(entry.name)") { try DiscoMessage(parsing: bytes) }
            } else {
                #expect(throws: DiscoError.malformed, "\(entry.name)") { try DiscoMessage(parsing: bytes) }
            }
        }
    }

    // MARK: Arbitrary input

    /// Generates the same bytes from the same seed. For tests only.
    private struct CountingGenerator: RandomNumberGenerator {
        var state: UInt64
        mutating func next() -> UInt64 {
            state &+= 0x9E37_79B9_7F4A_7C15
            var z = state
            z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
            z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
            return z ^ (z >> 31)
        }
    }

    @Test("Arbitrary plaintext does not stall, and parsed messages remain equal after re-encoding and parsing")
    func randomPlaintext() {
        var generator = CountingGenerator(state: 7)
        var parsed = 0
        for round in 0..<3_000 {
            let length = Int.random(in: 0...200, using: &generator)
            var bytes = (0..<length).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
            // Set a known type on half the inputs to reach body parsing.
            if round.isMultiple(of: 2), length >= 2 {
                bytes[0] = UInt8.random(in: 1...3, using: &generator)
                bytes[1] = round.isMultiple(of: 4) ? 0 : bytes[1]
            }
            guard let message = try? DiscoMessage(parsing: bytes) else { continue }
            parsed += 1
            #expect((try? DiscoMessage(parsing: message.plaintext)) == message)
        }
        #expect(parsed > 500, "Too few inputs parsed successfully to exercise body parsing")
    }
}
