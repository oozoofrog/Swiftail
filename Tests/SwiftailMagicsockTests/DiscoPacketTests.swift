import CryptoKit
import Foundation
import Testing

import SwiftailBase
import SwiftailCrypto

@testable import SwiftailMagicsock

@Suite("DiscoPacket")
struct DiscoPacketTests {
    /// 시험용 disco 키 하나: 개인 키와 접두사 붙은 공개 키.
    private struct Party {
        let privateKey: Curve25519.KeyAgreement.PrivateKey
        let publicKey: DiscoPublicKey

        init(seed: [UInt8]) throws {
            privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: seed)
            publicKey = DiscoPublicKey(privateKey.publicKey)
        }

        init(vector: DiscoVectors.Key) throws {
            try self.init(seed: DiscoVectors.bytes(vector.seed))
        }

        /// 이 키 쪽에서 본 상대와의 공유 키.
        func sharedKey(with peer: Party) throws -> DiscoSharedKey {
            try DiscoSharedKey(privateKey: privateKey, peerPublicKey: peer.publicKey)
        }
    }

    private let txID: TransactionID
    private let nonce = Array(UInt8(0)..<UInt8(24))

    init() throws {
        txID = try #require(TransactionID(Array(UInt8(1)...UInt8(12))))
    }

    private func parties() throws -> (a: Party, b: Party) {
        (try Party(seed: [UInt8](repeating: 0x11, count: 32)), try Party(seed: [UInt8](repeating: 0x22, count: 32)))
    }

    private func sealedPing() throws -> (packet: [UInt8], sender: Party, receiver: Party) {
        let (a, b) = try parties()
        let packet = DiscoPacket.seal(.ping(txID, nodeKey: nil), sender: a.publicKey, sharedKey: try a.sharedKey(with: b), nonce: nonce)
        return (packet, a, b)
    }

    // MARK: 알아보기

    @Test("disco 판정은 길이 38과 magic이다: 37바이트는 아니고 38·61·62바이트는 맞다")
    func classificationBoundary() {
        let header = DiscoPacket.magic + [UInt8](repeating: 0xAB, count: 100)
        #expect(DiscoPacket.classificationLength == 38)
        #expect(!DiscoPacket.isDisco(Array(header.prefix(37))))
        #expect(DiscoPacket.isDisco(Array(header.prefix(38))))
        #expect(DiscoPacket.isDisco(Array(header.prefix(61))))
        #expect(DiscoPacket.isDisco(Array(header.prefix(62))))
        #expect(!DiscoPacket.isDisco([]))
    }

    @Test("magic이 한 바이트라도 다르면 disco가 아니다", arguments: 0..<6)
    func magicMismatch(_ index: Int) {
        var packet = DiscoPacket.magic + [UInt8](repeating: 0, count: 60)
        #expect(DiscoPacket.isDisco(packet))
        packet[index] ^= 0x01
        #expect(!DiscoPacket.isDisco(packet))
        #expect(DiscoPacket.senderKey(of: packet) == nil)
    }

    @Test("magic은 \"TS💬\"의 UTF-8이다")
    func magicIsUTF8() {
        #expect(DiscoPacket.magic == Array("TS💬".utf8))
    }

    @Test("보낸 쪽 키는 오프셋 6..<38에서 읽고, 37바이트 이하면 nil이다")
    func senderKeyOffsets() throws {
        let key = Array(UInt8(100)..<UInt8(132))
        let packet = DiscoPacket.magic + key + [UInt8](repeating: 0, count: 24)
        #expect(DiscoPacket.senderKey(of: packet)?.rawValue == key)
        #expect(DiscoPacket.senderKey(of: Array(packet.prefix(38)))?.rawValue == key)
        #expect(DiscoPacket.senderKey(of: Array(packet.prefix(37))) == nil)
        #expect(DiscoPacket.senderKey(of: []) == nil)
    }

    // MARK: 봉하기와 열기

    @Test("겉 형식은 magic ‖ 보낸 쪽 키 ‖ nonce ‖ tag ‖ 암호문이고 평문보다 78바이트 길다")
    func layout() throws {
        let (packet, sender, _) = try sealedPing()
        let plaintext = DiscoMessage.ping(txID, nodeKey: nil).plaintext
        #expect(packet.count == plaintext.count + 78)
        #expect(Array(packet[0..<6]) == DiscoPacket.magic)
        #expect(Array(packet[6..<38]) == sender.publicKey.rawValue)
        #expect(Array(packet[38..<62]) == nonce)
        #expect(DiscoPacket.senderKey(of: packet) == sender.publicKey)
    }

    @Test("Go가 보내는 길이와 같다: NodeKey 있는 Ping 124, 없는 Ping 92, Pong 110, CallMeMaybe 80 + 18N")
    func goLengths() throws {
        let (a, b) = try parties()
        let key = try a.sharedKey(with: b)
        let nodeKey = try #require(NodePublicKey(rawValue: [UInt8](repeating: 9, count: 32)))
        let endpoint = try #require(IPEndpoint("192.0.2.1:1"))
        func length(_ message: DiscoMessage) -> Int {
            DiscoPacket.seal(message, sender: a.publicKey, sharedKey: key, nonce: nonce).count
        }
        #expect(length(.ping(txID, nodeKey: nodeKey)) == 124)
        #expect(length(.ping(txID, nodeKey: nil)) == 92)
        #expect(length(.pong(txID, source: endpoint)) == 110)
        #expect(length(.callMeMaybe([])) == 80)
        #expect(length(.callMeMaybe([endpoint, endpoint, endpoint])) == 80 + 18 * 3)
    }

    @Test("받는 쪽이 자기 개인 키로 만든 공유 키로 열면 같은 메시지가 나온다")
    func roundTrip() throws {
        let (a, b) = try parties()
        let nodeKey = try #require(NodePublicKey(rawValue: [UInt8](repeating: 9, count: 32)))
        let sent: [DiscoMessage] = try [
            .ping(txID, nodeKey: nodeKey),
            .pong(txID, source: #require(IPEndpoint("[2001:db8::7]:5060"))),
            .callMeMaybe([#require(IPEndpoint("192.0.2.1:41641")), #require(IPEndpoint("198.51.100.9:1"))]),
        ]
        for message in sent {
            let packet = DiscoPacket.seal(message, sender: a.publicKey, sharedKey: try a.sharedKey(with: b), nonce: nonce)
            let key = try #require(DiscoPacket.senderKey(of: packet))
            #expect(key == a.publicKey)
            #expect(try DiscoPacket.open(packet, sharedKey: b.sharedKey(with: a)) == message)
        }
    }

    @Test("nonce가 다르면 같은 메시지도 다른 바이트가 된다")
    func nonceChangesOutput() throws {
        let (a, b) = try parties()
        let key = try a.sharedKey(with: b)
        let first = DiscoPacket.seal(.callMeMaybe([]), sender: a.publicKey, sharedKey: key, nonce: nonce)
        let second = DiscoPacket.seal(.callMeMaybe([]), sender: a.publicKey, sharedKey: key, nonce: nonce.reversed())
        #expect(first != second)
        #expect(try DiscoPacket.open(second, sharedKey: b.sharedKey(with: a)) == .callMeMaybe([]))
    }

    @Test("인증에 쓰이지 않는 보낸 쪽 키 바이트는 열기에 영향이 없다. 어느 공유 키로 열지는 부르는 쪽이 보낸 쪽 키로 고른다")
    func senderBytesAreOnlyAHint() throws {
        let (packet, a, b) = try sealedPing()
        var forged = packet
        forged[6] ^= 0xFF
        #expect(try DiscoPacket.open(forged, sharedKey: b.sharedKey(with: a)) == .ping(txID, nodeKey: nil))
        // 보낸 쪽 키를 바꾼 패킷은 바뀐 키로 공유 키를 만들어 열게 되므로 열리지 않는다.
        let stranger = try Party(seed: [UInt8](repeating: 0x33, count: 32))
        var relabeled = packet
        relabeled.replaceSubrange(6..<38, with: stranger.publicKey.rawValue)
        let chosen = try #require(DiscoPacket.senderKey(of: relabeled))
        let wrongKey = try DiscoSharedKey(privateKey: b.privateKey, peerPublicKey: chosen)
        #expect(throws: DiscoError.authenticationFailed) { try DiscoPacket.open(relabeled, sharedKey: wrongKey) }
    }

    // MARK: Go 기준값

    @Test("같은 키·같은 nonce로 봉한 바이트가 Go와 한 바이트도 다르지 않다")
    func sealMatchesGo() throws {
        let vectors = try DiscoVectors.load()
        // 패딩이 있는 Ping은 Swift가 만들 수 없는 평문이다. 열기 시험이 다룬다.
        var compared = 0
        for sealed in vectors.disco.messages where (sealed.message.padding ?? 0) == 0 {
            let sender = try Party(vector: vectors.key(sealed.sender))
            let receiver = try Party(vector: vectors.key(sealed.receiver))
            #expect(sender.publicKey.rawValue == (try DiscoVectors.bytes(vectors.key(sealed.sender).publicHex)), "\(sealed.name): 공개 키")
            let described = try sealed.message.message()
            let message = try #require(described, "\(sealed.name)")
            let packet = DiscoPacket.seal(
                message, sender: sender.publicKey, sharedKey: try sender.sharedKey(with: receiver),
                nonce: try DiscoVectors.bytes(sealed.nonce)
            )
            #expect(packet == (try DiscoVectors.bytes(sealed.packet)), "\(sealed.name): 봉한 바이트")
            compared += 1
        }
        #expect(compared >= 6)
    }

    @Test("Go가 봉한 바이트를 받는 쪽 키로 열면 Go가 부호화한 메시지가 나온다")
    func openGoPackets() throws {
        let vectors = try DiscoVectors.load()
        #expect(vectors.disco.messages.count >= 8)
        for sealed in vectors.disco.messages {
            let sender = try Party(vector: vectors.key(sealed.sender))
            let receiver = try Party(vector: vectors.key(sealed.receiver))
            let packet = try DiscoVectors.bytes(sealed.packet)
            #expect(DiscoPacket.senderKey(of: packet) == sender.publicKey, "\(sealed.name): 보낸 쪽 키")
            let described = try sealed.message.message()
            let expected = try #require(described, "\(sealed.name)")
            #expect(try DiscoPacket.open(packet, sharedKey: receiver.sharedKey(with: sender)) == expected, "\(sealed.name)")
        }
    }

    // MARK: 거절

    @Test("틀린 키로는 열리지 않는다")
    func wrongKey() throws {
        let (packet, a, _) = try sealedPing()
        let stranger = try Party(seed: [UInt8](repeating: 0x33, count: 32))
        #expect(throws: DiscoError.authenticationFailed) { try DiscoPacket.open(packet, sharedKey: stranger.sharedKey(with: a)) }
    }

    @Test("nonce·tag·암호문의 어느 바이트를 바꿔도 열리지 않는다", arguments: [38, 61, 62, 77, 78, 79])
    func tamperedByte(_ index: Int) throws {
        let (packet, a, b) = try sealedPing()
        #expect(packet.count > index)
        var tampered = packet
        tampered[index] ^= 0x01
        #expect(throws: DiscoError.authenticationFailed) { try DiscoPacket.open(tampered, sharedKey: b.sharedKey(with: a)) }
    }

    @Test("모든 바이트를 하나씩 바꿔 보면 보낸 쪽 키(6..<38) 말고는 열리지 않는다")
    func everyByteIsCovered() throws {
        let (packet, a, b) = try sealedPing()
        let key = try b.sharedKey(with: a)
        for index in packet.indices {
            var tampered = packet
            tampered[index] ^= 0x80
            let opened = try? DiscoPacket.open(tampered, sharedKey: key)
            if (6..<38).contains(index) {
                #expect(opened != nil, "보낸 쪽 키는 암호로 묶이지 않는다. 오프셋 \(index)")
            } else {
                #expect(opened == nil, "오프셋 \(index)")
            }
        }
    }

    @Test("magic을 바꾸면 disco가 아니라 형식 오류다")
    func tamperedMagic() throws {
        var (packet, a, b) = try sealedPing()
        packet[0] ^= 0x01
        #expect(throws: DiscoError.malformed) { try DiscoPacket.open(packet, sharedKey: b.sharedKey(with: a)) }
    }

    @Test("잘린 입력: 78바이트 미만은 형식 오류, 78바이트 이상에서 잘린 것은 열리지 않는다")
    func truncated() throws {
        let (packet, a, b) = try sealedPing()
        let key = try b.sharedKey(with: a)
        for length in [0, 1, 37, 38, 61, 62, 77] {
            #expect(throws: DiscoError.malformed, "\(length)바이트") { try DiscoPacket.open(Array(packet.prefix(length)), sharedKey: key) }
        }
        for length in [78, 79, packet.count - 1] {
            #expect(throws: DiscoError.authenticationFailed, "\(length)바이트") { try DiscoPacket.open(Array(packet.prefix(length)), sharedKey: key) }
        }
    }

    @Test("뒤에 바이트가 붙어도 열리지 않는다")
    func appended() throws {
        let (packet, a, b) = try sealedPing()
        #expect(throws: DiscoError.authenticationFailed) { try DiscoPacket.open(packet + [0], sharedKey: b.sharedKey(with: a)) }
    }

    @Test("데이터그램 한도(65,535바이트)의 임의 입력은 형식 오류나 인증 실패로 끝난다")
    func longGarbage() throws {
        let (a, b) = try parties()
        let key = try b.sharedKey(with: a)
        let garbage = DiscoPacket.magic + a.publicKey.rawValue + (0..<(65_535 - 38)).map { UInt8(truncatingIfNeeded: $0 &* 31) }
        #expect(garbage.count == 65_535)
        #expect(throws: DiscoError.authenticationFailed) { try DiscoPacket.open(garbage, sharedKey: key) }
    }

    @Test("긴 CallMeMaybe는 봉하고 열 수 있다")
    func longValidPacket() throws {
        let (a, b) = try parties()
        let endpoints = try (0..<3_000).map { try #require(IPEndpoint("192.0.2.\($0 % 250):\(1 + $0)")) }
        let packet = DiscoPacket.seal(.callMeMaybe(endpoints), sender: a.publicKey, sharedKey: try a.sharedKey(with: b), nonce: nonce)
        #expect(packet.count == 80 + 18 * 3_000)
        #expect(try DiscoPacket.open(packet, sharedKey: b.sharedKey(with: a)) == .callMeMaybe(endpoints))
    }

    @Test("열린 평문이 틀리면 열린 뒤의 오류를 낸다: 모르는 종류, 짧은 Pong")
    func openedPlaintextIsParsed() throws {
        let (a, b) = try parties()
        let sender = try a.sharedKey(with: b)
        let receiver = try b.sharedKey(with: a)
        func packet(plaintext: [UInt8]) -> [UInt8] {
            DiscoPacket.magic + a.publicKey.rawValue + nonce + sender.seal(plaintext, nonce: nonce)
        }
        // peer relay 종류(0x04)는 Go가 해석하는 본문이어도 unknownType이다.
        #expect(throws: DiscoError.unknownType(0x04)) { try DiscoPacket.open(packet(plaintext: [0x04, 0x00] + [UInt8](repeating: 0, count: 72)), sharedKey: receiver) }
        #expect(throws: DiscoError.unknownType(0x0A)) { try DiscoPacket.open(packet(plaintext: [0x0A, 0x00]), sharedKey: receiver) }
        #expect(throws: DiscoError.malformed) { try DiscoPacket.open(packet(plaintext: [0x02, 0x00] + [UInt8](repeating: 0, count: 29)), sharedKey: receiver) }
        #expect(throws: DiscoError.malformed) { try DiscoPacket.open(packet(plaintext: []), sharedKey: receiver) }
        #expect(throws: DiscoError.malformed) { try DiscoPacket.open(packet(plaintext: [0x01]), sharedKey: receiver) }
        // 제대로 봉한 CallMeMaybe는 version이 1이어도 빈 목록으로 열린다.
        #expect(try DiscoPacket.open(packet(plaintext: [0x03, 0x01] + [UInt8](repeating: 0, count: 18)), sharedKey: receiver) == .callMeMaybe([]))
    }

    // MARK: 키

    @Test("저차수 공개 키로는 공유 키를 만들 수 없다")
    func lowOrderPeerKey() throws {
        let (a, _) = try parties()
        let one = try #require(DiscoPublicKey(rawValue: [1] + [UInt8](repeating: 0, count: 31)))
        for peer in [DiscoPublicKey.zero, one] {
            #expect(throws: DiscoError.invalidKey) { try DiscoSharedKey(privateKey: a.privateKey, peerPublicKey: peer) }
        }
    }

    @Test("양쪽이 만든 공유 키는 같은 키로 서로의 패킷을 연다")
    func sharedKeyIsSymmetric() throws {
        let (a, b) = try parties()
        let fromB = DiscoPacket.seal(.pong(txID, source: try #require(IPEndpoint("127.0.0.1:1"))), sender: b.publicKey, sharedKey: try b.sharedKey(with: a), nonce: nonce)
        #expect(try DiscoPacket.open(fromB, sharedKey: a.sharedKey(with: b)) == .pong(txID, source: try #require(IPEndpoint("127.0.0.1:1"))))
    }

    @Test("공유 키는 dump·description·debugDescription 어디에도 나오지 않는다")
    func sharedKeyIsHidden() throws {
        let (a, b) = try parties()
        let key = try a.sharedKey(with: b)
        let secret = try NaClBox.sharedKey(privateKey: Array(a.privateKey.rawRepresentation), peerPublicKey: b.publicKey.rawValue)

        var dumped = ""
        dump(key, to: &dumped)
        let outputs = [dumped, String(describing: key), String(reflecting: key), "\(key)"]
        for output in outputs {
            #expect(!output.contains(secret.hex), "\(output)")
            #expect(!output.contains(secret.map(String.init).joined(separator: ", ")), "\(output)")
        }
        // 자식이 없어 dump가 타입 이름 한 줄뿐이다.
        #expect(dumped.split(separator: "\n").count == 1, "\(dumped)")
        #expect(Mirror(reflecting: key).children.isEmpty)
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

    @Test("임의 바이트열로 판정·읽기·열기가 멈추지 않는다. magic으로 시작하는 입력도 그렇다")
    func randomInput() throws {
        let (a, b) = try parties()
        let key = try b.sharedKey(with: a)
        var generator = CountingGenerator(state: 42)
        for round in 0..<2_000 {
            let length = Int.random(in: 0...200, using: &generator)
            var bytes = (0..<length).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
            if round.isMultiple(of: 2), length >= 6 { bytes.replaceSubrange(0..<6, with: DiscoPacket.magic) }
            let isDisco = DiscoPacket.isDisco(bytes)
            #expect((DiscoPacket.senderKey(of: bytes) != nil) == isDisco)
            #expect(throws: DiscoError.self) { try DiscoPacket.open(bytes, sharedKey: key) }
        }
    }
}
