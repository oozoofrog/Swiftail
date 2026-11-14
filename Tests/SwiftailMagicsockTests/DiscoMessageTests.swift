import Foundation
import Testing

import SwiftailBase

@testable import SwiftailMagicsock

/// `magicsock-vectors.json`의 disco 절. `Tools/interop/cmd/magicsockvectors`가 Go의 `disco`·`key` 패키지로 만든다.
/// 다시 뽑는 방법은 `Tools/interop/README.md`의 magicsockvectors 절이다. 현재 시각·운영 키는 담지 않는다.
enum DiscoVectors {
    struct File: Decodable {
        let keys: [Key]
        let disco: Disco

        func key(_ name: String) throws -> Key {
            try #require(keys.first { $0.name == name }, "벡터에 키 \(name)이 없다")
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

    /// Go가 봉한 메시지 하나: 평문과 겉 형식 전체.
    struct Sealed: Decodable {
        let name: String
        let sender: String
        let receiver: String
        let message: Described
        let plaintext: String
        let nonce: String
        let packet: String
    }

    /// 평문을 `disco.Parse`에 넣은 결과. 해석되면 `result`, 아니면 `error`(Go의 오류 문장).
    struct ParseCase: Decodable {
        let name: String
        let plaintext: String
        let result: Described?
        let error: String?
    }

    /// 해석된 메시지의 사람이 읽는 형태. `kind`가 `relay`이면 Go만 해석하는 종류다.
    struct Described: Decodable {
        let kind: String
        let txID: String?
        let nodeKey: String?
        let padding: Int?
        let src: String?
        let endpoints: [String]?

        /// Swiftail이 해석하는 메시지. `relay`는 nil이다.
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
        try #require([UInt8](hex: hex), "16진 문자열이 아니다")
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

    /// 헤더(type, version)와 본문으로 평문을 만든다.
    private func plaintext(type: UInt8, version: UInt8 = 0, body: [UInt8]) -> [UInt8] {
        [type, version] + body
    }

    private func zeros(_ count: Int) -> [UInt8] {
        [UInt8](repeating: 0, count: count)
    }

    /// 선 위의 주소 18바이트: IPv4-mapped `192.0.2.<last>:<port>`.
    private func mappedWire(last: UInt8, port: UInt16) -> [UInt8] {
        zeros(10) + [0xFF, 0xFF, 192, 0, 2, last, UInt8(port >> 8), UInt8(port & 0xFF)]
    }

    // MARK: 부호화와 왕복

    @Test("Ping 평문은 type 1, version 0, TxID, NodeKey 순서다")
    func pingLayout() {
        let withKey = DiscoMessage.ping(txID, nodeKey: nodeKey)
        #expect(withKey.plaintext == [0x01, 0x00] + txID.bytes + nodeKey.rawValue)
        #expect(DiscoMessage.ping(txID, nodeKey: nil).plaintext == [0x01, 0x00] + txID.bytes)
    }

    @Test("Pong 평문은 IPv4를 IPv4-mapped 16바이트와 BE 포트로 부호화한다")
    func pongLayout() throws {
        let message = DiscoMessage.pong(txID, source: try endpoint("192.0.2.1:5000"))
        #expect(message.plaintext == [0x02, 0x00] + txID.bytes + mappedWire(last: 1, port: 5000))
        let v6 = DiscoMessage.pong(txID, source: try endpoint("[2001:db8::7]:5060"))
        let address = try #require(IPAddress("2001:db8::7")).bytes
        #expect(v6.plaintext == [0x02, 0x00] + txID.bytes + address + [0x13, 0xC4])
    }

    @Test("CallMeMaybe 평문은 주소마다 18바이트이고 개수 필드가 없다")
    func callMeMaybeLayout() throws {
        #expect(DiscoMessage.callMeMaybe([]).plaintext == [0x03, 0x00])
        let message = DiscoMessage.callMeMaybe([try endpoint("192.0.2.1:1001"), try endpoint("192.0.2.2:1002")])
        #expect(message.plaintext == [0x03, 0x00] + mappedWire(last: 1, port: 1001) + mappedWire(last: 2, port: 1002))
    }

    @Test("모든 종류가 평문으로 왕복한다")
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

    @Test("0으로 채운 NodeKey는 보내지 않고, 받으면 없는 것과 같다")
    func zeroNodeKeyIsAbsent() throws {
        let message = DiscoMessage.ping(txID, nodeKey: .zero)
        #expect(message.plaintext == [0x01, 0x00] + txID.bytes)
        #expect(try DiscoMessage(parsing: message.plaintext) == .ping(txID, nodeKey: nil))
    }

    // MARK: 경계

    @Test("평문이 2바이트 미만이면 형식 오류다", arguments: [0, 1])
    func tooShortPlaintext(_ count: Int) {
        #expect(throws: DiscoError.malformed) { try DiscoMessage(parsing: [UInt8](repeating: 0x01, count: count)) }
    }

    @Test("Ping 본문 12바이트는 NodeKey 없이, 44바이트는 NodeKey와, 45바이트 이상의 끝은 패딩으로 읽는다")
    func pingBodyLengths() throws {
        let key = nodeKey.rawValue
        #expect(try DiscoMessage(parsing: plaintext(type: 1, body: txID.bytes)) == .ping(txID, nodeKey: nil))
        #expect(try DiscoMessage(parsing: plaintext(type: 1, body: txID.bytes + key)) == .ping(txID, nodeKey: nodeKey))
        #expect(try DiscoMessage(parsing: plaintext(type: 1, body: txID.bytes + key + [0])) == .ping(txID, nodeKey: nodeKey))
        // NodeKey 자리가 32바이트에 못 미치면 전부 패딩이다.
        #expect(try DiscoMessage(parsing: plaintext(type: 1, body: txID.bytes + key.prefix(31))) == .ping(txID, nodeKey: nil))
        #expect(try DiscoMessage(parsing: plaintext(type: 1, body: txID.bytes + zeros(5))) == .ping(txID, nodeKey: nil))
    }

    @Test("Ping 본문 11바이트 이하는 형식 오류다", arguments: [0, 1, 11])
    func pingTooShort(_ count: Int) {
        #expect(throws: DiscoError.malformed) { try DiscoMessage(parsing: plaintext(type: 1, body: zeros(count))) }
    }

    @Test("32바이트가 모두 0인 NodeKey 자리는 NodeKey가 아니라 패딩이다")
    func zeroNodeKeyOnTheWire() throws {
        #expect(try DiscoMessage(parsing: plaintext(type: 1, body: txID.bytes + zeros(32))) == .ping(txID, nodeKey: nil))
        #expect(try DiscoMessage(parsing: plaintext(type: 1, body: txID.bytes + zeros(64))) == .ping(txID, nodeKey: nil))
    }

    @Test("긴 패딩이 붙은 Ping도 NodeKey를 읽는다")
    func pingWithLongPadding() throws {
        let body = txID.bytes + nodeKey.rawValue + zeros(1400)
        #expect(try DiscoMessage(parsing: plaintext(type: 1, body: body)) == .ping(txID, nodeKey: nodeKey))
    }

    @Test("Ping과 Pong은 version을 보지 않는다")
    func versionIgnoredByPingAndPong() throws {
        #expect(try DiscoMessage(parsing: plaintext(type: 1, version: 7, body: txID.bytes + nodeKey.rawValue)) == .ping(txID, nodeKey: nodeKey))
        let pong = txID.bytes + mappedWire(last: 1, port: 5000)
        #expect(try DiscoMessage(parsing: plaintext(type: 2, version: 1, body: pong)) == .pong(txID, source: try endpoint("192.0.2.1:5000")))
    }

    @Test("Pong 본문 29바이트는 형식 오류이고 30바이트와 그 뒤 바이트는 받는다")
    func pongBodyLengths() throws {
        let body = txID.bytes + mappedWire(last: 1, port: 5000)
        #expect(throws: DiscoError.malformed) { try DiscoMessage(parsing: plaintext(type: 2, body: Array(body.prefix(29)))) }
        let expected = DiscoMessage.pong(txID, source: try endpoint("192.0.2.1:5000"))
        #expect(try DiscoMessage(parsing: plaintext(type: 2, body: body)) == expected)
        #expect(try DiscoMessage(parsing: plaintext(type: 2, body: body + [0xEE, 0xEE])) == expected)
    }

    @Test("IPv4-mapped 주소는 IPv4로 풀고, 그 밖의 16바이트는 IPv6로 둔다")
    func unmapping() throws {
        func pong(ip: [UInt8]) throws -> DiscoMessage {
            try DiscoMessage(parsing: plaintext(type: 2, body: txID.bytes + ip + [0, 80]))
        }
        let mapped = zeros(10) + [0xFF, 0xFF, 10, 1, 2, 3]
        #expect(try pong(ip: mapped) == .pong(txID, source: try endpoint("10.1.2.3:80")))
        // IPv4-compatible(::a.b.c.d)와 ::ffff 뒤가 0이 아닌 앞부분은 mapped가 아니다.
        let compatible = zeros(12) + [10, 1, 2, 3]
        #expect(try pong(ip: compatible) == .pong(txID, source: IPEndpoint(address: try #require(IPAddress(bytes: compatible)), port: 80)))
        var notMapped = mapped
        notMapped[0] = 1
        #expect(try pong(ip: notMapped) == .pong(txID, source: IPEndpoint(address: try #require(IPAddress(bytes: notMapped)), port: 80)))
    }

    @Test("CallMeMaybe는 version ≠ 0, 본문 0바이트, 18의 배수가 아닌 본문을 빈 목록으로 읽는다")
    func callMeMaybeLenientEmpty() throws {
        let one = mappedWire(last: 1, port: 1001)
        #expect(try DiscoMessage(parsing: plaintext(type: 3, body: [])) == .callMeMaybe([]))
        #expect(try DiscoMessage(parsing: plaintext(type: 3, body: Array(one.prefix(17)))) == .callMeMaybe([]))
        #expect(try DiscoMessage(parsing: plaintext(type: 3, body: one + [0])) == .callMeMaybe([]))
        #expect(try DiscoMessage(parsing: plaintext(type: 3, body: Array((one + one).prefix(35)))) == .callMeMaybe([]))
        #expect(try DiscoMessage(parsing: plaintext(type: 3, version: 1, body: one)) == .callMeMaybe([]))
        #expect(try DiscoMessage(parsing: plaintext(type: 3, body: one)) == .callMeMaybe([try endpoint("192.0.2.1:1001")]))
    }

    @Test("데이터그램에 들어가는 가장 큰 CallMeMaybe도 주소를 모두 읽는다")
    func largestCallMeMaybe() throws {
        let count = 65_000 / 18
        let body = (0..<count).flatMap { mappedWire(last: UInt8($0 % 250), port: UInt16($0 % 60_000)) }
        guard case .callMeMaybe(let endpoints) = try DiscoMessage(parsing: plaintext(type: 3, body: body)) else {
            Issue.record("CallMeMaybe가 아니다")
            return
        }
        #expect(endpoints.count == count)
    }

    @Test("type 0x01–0x03이 아니면 unknownType이다. peer relay 종류 0x04–0x09도 그렇다", arguments: [0x00, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x7F, 0xFF] as [UInt8])
    func unknownTypes(_ type: UInt8) {
        // 본문은 Go가 해석하는 길이로 채워 type만 이유가 되게 한다.
        #expect(throws: DiscoError.unknownType(type)) { try DiscoMessage(parsing: plaintext(type: type, body: zeros(200))) }
    }

    // MARK: Go 기준값

    @Test("Go가 부호화한 평문과 같은 바이트를 만들고 같은 메시지로 읽는다")
    func goPlaintextVectors() throws {
        for sealed in try DiscoVectors.load().disco.messages {
            let described = try sealed.message.message()
            let message = try #require(described, "\(sealed.name)")
            let goPlaintext = try DiscoVectors.bytes(sealed.plaintext)
            // Ping의 패딩은 읽을 때 버리므로 패딩이 있는 평문은 같은 바이트로 되돌리지 않는다.
            if sealed.message.padding ?? 0 == 0 {
                #expect(message.plaintext == goPlaintext, "\(sealed.name): 부호화")
            }
            #expect(try DiscoMessage(parsing: goPlaintext) == message, "\(sealed.name): 해석")
        }
    }

    @Test("Go `disco.Parse`가 받아들이는 경계 평문과 거절하는 경계 평문에서 같은 결론을 낸다")
    func goParseBoundaries() throws {
        let cases = try DiscoVectors.load().disco.parse
        #expect(cases.count > 20)
        for entry in cases {
            let bytes = try DiscoVectors.bytes(entry.plaintext)
            if let result = entry.result {
                if let expected = try result.message() {
                    #expect(try DiscoMessage(parsing: bytes) == expected, "\(entry.name)")
                } else {
                    // Go만 해석하는 peer relay 종류: Swiftail은 종류만 보고 unknownType으로 돌린다.
                    #expect(throws: DiscoError.unknownType(bytes[0]), "\(entry.name)") { try DiscoMessage(parsing: bytes) }
                }
            } else if entry.error?.hasPrefix("unknown message type") == true {
                #expect(throws: DiscoError.unknownType(bytes[0]), "\(entry.name)") { try DiscoMessage(parsing: bytes) }
            } else {
                #expect(throws: DiscoError.malformed, "\(entry.name)") { try DiscoMessage(parsing: bytes) }
            }
        }
    }

    // MARK: 임의 입력

    /// 같은 시드면 같은 바이트를 내는 생성기. 시험 전용이다.
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

    @Test("임의 평문으로 멈추지 않고, 읽힌 메시지는 다시 부호화해 읽어도 같다")
    func randomPlaintext() {
        var generator = CountingGenerator(state: 7)
        var parsed = 0
        for round in 0..<3_000 {
            let length = Int.random(in: 0...200, using: &generator)
            var bytes = (0..<length).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
            // 절반은 type을 알려진 값으로 만들어 본문 해석까지 가게 한다.
            if round.isMultiple(of: 2), length >= 2 {
                bytes[0] = UInt8.random(in: 1...3, using: &generator)
                bytes[1] = round.isMultiple(of: 4) ? 0 : bytes[1]
            }
            guard let message = try? DiscoMessage(parsing: bytes) else { continue }
            parsed += 1
            #expect((try? DiscoMessage(parsing: message.plaintext)) == message)
        }
        #expect(parsed > 500, "해석되는 입력이 너무 적어 시험이 본문까지 가지 못했다")
    }
}
