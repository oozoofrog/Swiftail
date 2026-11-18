import CryptoKit
import Foundation
import Testing

import SwiftailBase

@Suite("Key text format")
struct KeysTests {
    private let hex = String(repeating: "ab", count: 32)

    @Test("Reads and writes a prefix followed by 64 base-16 digits")
    func roundTrip() throws {
        let key = try #require(NodePublicKey("nodekey:" + hex))
        #expect(key.rawValue == [UInt8](repeating: 0xAB, count: 32))
        #expect(key.description == "nodekey:" + hex)
        // Accepts uppercase base-16 digits and writes lowercase ones.
        #expect(NodePublicKey("nodekey:" + hex.uppercased()) == key)
    }

    @Test("Rejects an incorrect prefix or length", arguments: ["", "nodekey:", "mkey:" + String(repeating: "ab", count: 32), "nodekey:abcd", String(repeating: "ab", count: 32)])
    func rejects(_ text: String) {
        #expect(NodePublicKey(text) == nil)
    }

    @Test("JSON uses strings and includes keys set to 0")
    func json() throws {
        let encoded = try JSONEncoder().encode([MachinePublicKey.zero])
        #expect(String(decoding: encoded, as: UTF8.self) == "[\"mkey:" + String(repeating: "0", count: 64) + "\"]")
        #expect(try JSONDecoder().decode([MachinePublicKey].self, from: encoded) == [.zero])
        #expect(MachinePublicKey.zero.isZero)
        #expect(throws: DecodingError.self) { try JSONDecoder().decode([DiscoPublicKey].self, from: encoded) }
    }

    @Test("Initializing from a CryptoKit public key preserves the raw bytes")
    func fromCryptoKit() {
        let publicKey = Curve25519.KeyAgreement.PrivateKey().publicKey
        #expect(NodePublicKey(publicKey).rawValue == [UInt8](publicKey.rawRepresentation))
    }
}
