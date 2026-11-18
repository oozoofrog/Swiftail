import CryptoKit
import Foundation
import Testing

import SwiftailBase
import SwiftailCrypto

@testable import SwiftailMagicsock

@Suite("DiscoPacket")
struct DiscoPacketTests {
    /// A test disco key with a private key and a prefixed public key.
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

        /// Returns the shared key with the peer from this key's perspective.
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

    // MARK: Detection

    @Test("Disco detection checks the magic and a minimum length of 38. Rejects 37 bytes and accepts 38, 61, and 62 bytes")
    func classificationBoundary() {
        let header = DiscoPacket.magic + [UInt8](repeating: 0xAB, count: 100)
        #expect(DiscoPacket.classificationLength == 38)
        #expect(!DiscoPacket.isDisco(Array(header.prefix(37))))
        #expect(DiscoPacket.isDisco(Array(header.prefix(38))))
        #expect(DiscoPacket.isDisco(Array(header.prefix(61))))
        #expect(DiscoPacket.isDisco(Array(header.prefix(62))))
        #expect(!DiscoPacket.isDisco([]))
    }

    @Test("Changing even one magic byte prevents disco detection", arguments: 0..<6)
    func magicMismatch(_ index: Int) {
        var packet = DiscoPacket.magic + [UInt8](repeating: 0, count: 60)
        #expect(DiscoPacket.isDisco(packet))
        packet[index] ^= 0x01
        #expect(!DiscoPacket.isDisco(packet))
        #expect(DiscoPacket.senderKey(of: packet) == nil)
    }

    @Test("The magic is the UTF-8 encoding of \"TS💬\"")
    func magicIsUTF8() {
        #expect(DiscoPacket.magic == Array("TS💬".utf8))
    }

    @Test("Reads the sender key at offsets 6..<38 and yields nil for 37 bytes or less")
    func senderKeyOffsets() throws {
        let key = Array(UInt8(100)..<UInt8(132))
        let packet = DiscoPacket.magic + key + [UInt8](repeating: 0, count: 24)
        #expect(DiscoPacket.senderKey(of: packet)?.rawValue == key)
        #expect(DiscoPacket.senderKey(of: Array(packet.prefix(38)))?.rawValue == key)
        #expect(DiscoPacket.senderKey(of: Array(packet.prefix(37))) == nil)
        #expect(DiscoPacket.senderKey(of: []) == nil)
    }

    // MARK: Sealing and opening

    @Test("The outer format is magic ‖ sender key ‖ nonce ‖ tag ‖ ciphertext and is 78 bytes longer than the plaintext")
    func layout() throws {
        let (packet, sender, _) = try sealedPing()
        let plaintext = DiscoMessage.ping(txID, nodeKey: nil).plaintext
        #expect(packet.count == plaintext.count + 78)
        #expect(Array(packet[0..<6]) == DiscoPacket.magic)
        #expect(Array(packet[6..<38]) == sender.publicKey.rawValue)
        #expect(Array(packet[38..<62]) == nonce)
        #expect(DiscoPacket.senderKey(of: packet) == sender.publicKey)
    }

    @Test("Lengths match Go: Ping with NodeKey 124, Ping without NodeKey 92, Pong 110, CallMeMaybe 80 + 18N")
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

    @Test("The recipient opens the same message with the shared key derived from its private key")
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

    @Test("Different nonces produce different bytes for the same message")
    func nonceChangesOutput() throws {
        let (a, b) = try parties()
        let key = try a.sharedKey(with: b)
        let first = DiscoPacket.seal(.callMeMaybe([]), sender: a.publicKey, sharedKey: key, nonce: nonce)
        let second = DiscoPacket.seal(.callMeMaybe([]), sender: a.publicKey, sharedKey: key, nonce: nonce.reversed())
        #expect(first != second)
        #expect(try DiscoPacket.open(second, sharedKey: b.sharedKey(with: a)) == .callMeMaybe([]))
    }

    @Test("The sender key bytes are unauthenticated and do not affect opening. The caller uses the sender key to select the shared key")
    func senderBytesAreOnlyAHint() throws {
        let (packet, a, b) = try sealedPing()
        var forged = packet
        forged[6] ^= 0xFF
        #expect(try DiscoPacket.open(forged, sharedKey: b.sharedKey(with: a)) == .ping(txID, nodeKey: nil))
        // A packet with a changed sender key fails to open because the recipient derives the shared key using the changed key.
        let stranger = try Party(seed: [UInt8](repeating: 0x33, count: 32))
        var relabeled = packet
        relabeled.replaceSubrange(6..<38, with: stranger.publicKey.rawValue)
        let chosen = try #require(DiscoPacket.senderKey(of: relabeled))
        let wrongKey = try DiscoSharedKey(privateKey: b.privateKey, peerPublicKey: chosen)
        #expect(throws: DiscoError.authenticationFailed) { try DiscoPacket.open(relabeled, sharedKey: wrongKey) }
    }

    // MARK: Go reference values

    @Test("Sealing with the same key and nonce matches Go byte for byte")
    func sealMatchesGo() throws {
        let vectors = try DiscoVectors.load()
        // Swift cannot generate padded Ping plaintext. The opening test covers it.
        var compared = 0
        for sealed in vectors.disco.messages where (sealed.message.padding ?? 0) == 0 {
            let sender = try Party(vector: vectors.key(sealed.sender))
            let receiver = try Party(vector: vectors.key(sealed.receiver))
            #expect(sender.publicKey.rawValue == (try DiscoVectors.bytes(vectors.key(sealed.sender).publicHex)), "\(sealed.name): public key")
            let described = try sealed.message.message()
            let message = try #require(described, "\(sealed.name)")
            let packet = DiscoPacket.seal(
                message, sender: sender.publicKey, sharedKey: try sender.sharedKey(with: receiver),
                nonce: try DiscoVectors.bytes(sealed.nonce)
            )
            #expect(packet == (try DiscoVectors.bytes(sealed.packet)), "\(sealed.name): sealed bytes")
            compared += 1
        }
        #expect(compared >= 6)
    }

    @Test("Opening Go-sealed bytes with the recipient's key yields the message Go encoded")
    func openGoPackets() throws {
        let vectors = try DiscoVectors.load()
        #expect(vectors.disco.messages.count >= 8)
        for sealed in vectors.disco.messages {
            let sender = try Party(vector: vectors.key(sealed.sender))
            let receiver = try Party(vector: vectors.key(sealed.receiver))
            let packet = try DiscoVectors.bytes(sealed.packet)
            #expect(DiscoPacket.senderKey(of: packet) == sender.publicKey, "\(sealed.name): sender key")
            let described = try sealed.message.message()
            let expected = try #require(described, "\(sealed.name)")
            #expect(try DiscoPacket.open(packet, sharedKey: receiver.sharedKey(with: sender)) == expected, "\(sealed.name)")
        }
    }

    // MARK: Rejection

    @Test("Opening with the wrong key fails")
    func wrongKey() throws {
        let (packet, a, _) = try sealedPing()
        let stranger = try Party(seed: [UInt8](repeating: 0x33, count: 32))
        #expect(throws: DiscoError.authenticationFailed) { try DiscoPacket.open(packet, sharedKey: stranger.sharedKey(with: a)) }
    }

    @Test("Changing any byte of the nonce, tag, or ciphertext prevents opening", arguments: [38, 61, 62, 77, 78, 79])
    func tamperedByte(_ index: Int) throws {
        let (packet, a, b) = try sealedPing()
        #expect(packet.count > index)
        var tampered = packet
        tampered[index] ^= 0x01
        #expect(throws: DiscoError.authenticationFailed) { try DiscoPacket.open(tampered, sharedKey: b.sharedKey(with: a)) }
    }

    @Test("Changing each byte in turn prevents opening except within the sender key (6..<38)")
    func everyByteIsCovered() throws {
        let (packet, a, b) = try sealedPing()
        let key = try b.sharedKey(with: a)
        for index in packet.indices {
            var tampered = packet
            tampered[index] ^= 0x80
            let opened = try? DiscoPacket.open(tampered, sharedKey: key)
            if (6..<38).contains(index) {
                #expect(opened != nil, "The sender key is not cryptographically bound. Offset \(index)")
            } else {
                #expect(opened == nil, "Offset \(index)")
            }
        }
    }

    @Test("Changing the magic yields a format error because the packet is no longer disco")
    func tamperedMagic() throws {
        var (packet, a, b) = try sealedPing()
        packet[0] ^= 0x01
        #expect(throws: DiscoError.malformed) { try DiscoPacket.open(packet, sharedKey: b.sharedKey(with: a)) }
    }

    @Test("Truncated input under 78 bytes yields a format error, and truncated input of 78 bytes or more fails to open")
    func truncated() throws {
        let (packet, a, b) = try sealedPing()
        let key = try b.sharedKey(with: a)
        for length in [0, 1, 37, 38, 61, 62, 77] {
            #expect(throws: DiscoError.malformed, "\(length) bytes") { try DiscoPacket.open(Array(packet.prefix(length)), sharedKey: key) }
        }
        for length in [78, 79, packet.count - 1] {
            #expect(throws: DiscoError.authenticationFailed, "\(length) bytes") { try DiscoPacket.open(Array(packet.prefix(length)), sharedKey: key) }
        }
    }

    @Test("Appending bytes also prevents opening")
    func appended() throws {
        let (packet, a, b) = try sealedPing()
        #expect(throws: DiscoError.authenticationFailed) { try DiscoPacket.open(packet + [0], sharedKey: b.sharedKey(with: a)) }
    }

    @Test("Arbitrary input at the datagram size limit (65,535 bytes) yields a format error or authentication failure")
    func longGarbage() throws {
        let (a, b) = try parties()
        let key = try b.sharedKey(with: a)
        let garbage = DiscoPacket.magic + a.publicKey.rawValue + (0..<(65_535 - 38)).map { UInt8(truncatingIfNeeded: $0 &* 31) }
        #expect(garbage.count == 65_535)
        #expect(throws: DiscoError.authenticationFailed) { try DiscoPacket.open(garbage, sharedKey: key) }
    }

    @Test("Long CallMeMaybe messages can be sealed and opened")
    func longValidPacket() throws {
        let (a, b) = try parties()
        let endpoints = try (0..<3_000).map { try #require(IPEndpoint("192.0.2.\($0 % 250):\(1 + $0)")) }
        let packet = DiscoPacket.seal(.callMeMaybe(endpoints), sender: a.publicKey, sharedKey: try a.sharedKey(with: b), nonce: nonce)
        #expect(packet.count == 80 + 18 * 3_000)
        #expect(try DiscoPacket.open(packet, sharedKey: b.sharedKey(with: a)) == .callMeMaybe(endpoints))
    }

    @Test("Invalid plaintext yields a post-opening error for an unknown type or a short Pong")
    func openedPlaintextIsParsed() throws {
        let (a, b) = try parties()
        let sender = try a.sharedKey(with: b)
        let receiver = try b.sharedKey(with: a)
        func packet(plaintext: [UInt8]) -> [UInt8] {
            DiscoPacket.magic + a.publicKey.rawValue + nonce + sender.seal(plaintext, nonce: nonce)
        }
        // Peer relay type 0x04 yields unknownType even with a body that Go parses.
        #expect(throws: DiscoError.unknownType(0x04)) { try DiscoPacket.open(packet(plaintext: [0x04, 0x00] + [UInt8](repeating: 0, count: 72)), sharedKey: receiver) }
        #expect(throws: DiscoError.unknownType(0x0A)) { try DiscoPacket.open(packet(plaintext: [0x0A, 0x00]), sharedKey: receiver) }
        #expect(throws: DiscoError.malformed) { try DiscoPacket.open(packet(plaintext: [0x02, 0x00] + [UInt8](repeating: 0, count: 29)), sharedKey: receiver) }
        #expect(throws: DiscoError.malformed) { try DiscoPacket.open(packet(plaintext: []), sharedKey: receiver) }
        #expect(throws: DiscoError.malformed) { try DiscoPacket.open(packet(plaintext: [0x01]), sharedKey: receiver) }
        // A correctly sealed CallMeMaybe opens as an empty list even with version 1.
        #expect(try DiscoPacket.open(packet(plaintext: [0x03, 0x01] + [UInt8](repeating: 0, count: 18)), sharedKey: receiver) == .callMeMaybe([]))
    }

    // MARK: Keys

    @Test("A low-order public key cannot produce a shared key")
    func lowOrderPeerKey() throws {
        let (a, _) = try parties()
        let one = try #require(DiscoPublicKey(rawValue: [1] + [UInt8](repeating: 0, count: 31)))
        for peer in [DiscoPublicKey.zero, one] {
            #expect(throws: DiscoError.invalidKey) { try DiscoSharedKey(privateKey: a.privateKey, peerPublicKey: peer) }
        }
    }

    @Test("Both sides derive the same shared key and can open each other's packets with it")
    func sharedKeyIsSymmetric() throws {
        let (a, b) = try parties()
        let fromB = DiscoPacket.seal(.pong(txID, source: try #require(IPEndpoint("127.0.0.1:1"))), sender: b.publicKey, sharedKey: try b.sharedKey(with: a), nonce: nonce)
        #expect(try DiscoPacket.open(fromB, sharedKey: a.sharedKey(with: b)) == .pong(txID, source: try #require(IPEndpoint("127.0.0.1:1"))))
    }

    @Test("dump, description, and debugDescription all hide the shared key")
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
        // There are no children, so dump just prints the type name on one line.
        #expect(dumped.split(separator: "\n").count == 1, "\(dumped)")
        #expect(Mirror(reflecting: key).children.isEmpty)
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

    @Test("Detection, reading, and opening do not stall on arbitrary bytes, including input that starts with magic")
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
