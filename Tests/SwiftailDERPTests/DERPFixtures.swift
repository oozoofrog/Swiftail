import CryptoKit
import Foundation
import SwiftailBase
import SwiftailCrypto
import SwiftailDERP
import Testing

/// Fixed test values and helpers for generating server-side bytes.
///
/// The keys are public test values. The private key input is `SHA-256("swiftail-fixtures/derp/<number>")` (client 1, server 2).
/// These are test-only keys. The nonce is `00 01 … 17`.
///
/// The fixed ClientInfo and ServerInfo body vectors were generated with Go's `box.Seal` (`golang.org/x/crypto/nacl/box`, the same call
/// as `NodePrivate.SealTo` in tailscale.com v1.104.6) using the same keys and nonce. To regenerate them,
/// run `go run ./cmd/derpvectors` from `Tools/interop` (see `Tools/interop/README.md` for environment variables).
enum DERPFixtures {
    static let clientSeed = "b7f801a79c5f48484f7c5bdf69b48d042fa0cc965db569b5df72e3893fe2e5b7"
    static let serverSeed = "ac720aec903565f3baa1fdc3f652959183cf04cb4d79b8b5e59d0c7234ab2bc3"
    static let clientPublic = "01b5e48ad0a98cecf0af5e20b9f7c1018d05eb3907f602a42ff64b872c54537f"
    static let serverPublic = "eec4e62b771c47da8fb0eb2c95f6fe3dd4290559303249239be2e077a54e0d67"
    static let nonce = "000102030405060708090a0b0c0d0e0f1011121314151617"
    /// ClientInfo plaintext sealed by Go: `{"version":2,"CanAckPings":true}`.
    static let clientInfoBody = "01b5e48ad0a98cecf0af5e20b9f7c1018d05eb3907f602a42ff64b872c54537f000102030405060708090a0b0c0d0e0f10111213141516174cd54de08147b1a40033c0a0e8a25de77ceff26dd8baa3416c70d17e0f231e85c823f65cbc2f1c2bdf0f8f129c77d92b"
    /// ServerInfo plaintext sealed by Go: `{"version":2}`.
    static let serverInfoBody = "000102030405060708090a0b0c0d0e0f1011121314151617adc070ff55d0e4d3be5ea1766a88021e7ceff26dd8baa3416c70d17e5e"

    static func bytes(_ hex: String) throws -> [UInt8] {
        try #require([UInt8](hex: hex), "Expected a hexadecimal string")
    }

    static func privateKey(seed: String) throws -> Curve25519.KeyAgreement.PrivateKey {
        try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: bytes(seed))
    }

    static func nodeKey(_ fill: UInt8) throws -> NodePublicKey {
        try #require(NodePublicKey(rawValue: [UInt8](repeating: fill, count: 32)))
    }

    /// A client-side state machine using fixed keys and a fixed nonce.
    static func connection(isPreferred: Bool = true, host: String = "127.0.0.1:3340") throws -> DERPConnection {
        try DERPConnection(
            privateKey: privateKey(seed: clientSeed), host: host, isPreferred: isPreferred, clientInfoNonce: bytes(nonce)
        )
    }

    /// A state machine made ready by draining the upgrade request and feeding it a 101 response and ServerKey. Outbound handshake bytes are discarded.
    static func readyConnection(isPreferred: Bool = true) throws -> DERPConnection {
        var connection = try connection(isPreferred: isPreferred)
        _ = connection.takeOutboundBytes()
        let events = try connection.receive(Server.upgradeResponse + Server.serverKeyFrame())
        #expect(events == [.ready])
        _ = connection.takeOutboundBytes()
        return connection
    }

    /// Bytes sent by the DERP server.
    enum Server {
        static let upgradeResponse = Array(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\nDerp-Version: 2\r\nDerp-Public-Key: \(serverPublic)\r\n\r\n".utf8
        )
        static let magic: [UInt8] = [0x44, 0x45, 0x52, 0x50, 0xF0, 0x9F, 0x94, 0x91]

        /// The 5-byte header and body.
        static func frame(_ type: UInt8, _ body: [UInt8]) -> [UInt8] {
            let length = UInt32(body.count)
            return [type, UInt8(length >> 24), UInt8(truncatingIfNeeded: length >> 16),
                    UInt8(truncatingIfNeeded: length >> 8), UInt8(truncatingIfNeeded: length)] + body
        }

        /// The server sends only 40 bytes of magic and public key. `trailing` is for future extensions.
        static func serverKeyFrame(trailing: [UInt8] = []) throws -> [UInt8] {
            try frame(0x01, magic + bytes(serverPublic) + trailing)
        }

        static func recvPacket(from peer: NodePublicKey, _ packet: [UInt8]) -> [UInt8] {
            frame(0x05, peer.rawValue + packet)
        }

        /// The ServerInfo frame sealed with the server's private key and the client's public key. `plaintext` can be sealed even if it is not JSON.
        static func serverInfoFrame(_ plaintext: [UInt8] = Array(#"{"version":2}"#.utf8)) throws -> [UInt8] {
            let shared = try NaClBox.sharedKey(
                privateKey: Array(privateKey(seed: serverSeed).rawRepresentation), peerPublicKey: bytes(clientPublic)
            )
            let nonce = try bytes(nonce)
            return try frame(0x03, nonce + NaClSecretBox.seal(plaintext, nonce: nonce, key: shared))
        }
    }
}

/// Reproducible pseudorandom numbers. A failing random-input test can be rerun with the same input.
struct SplitMix64: RandomNumberGenerator {
    var state: UInt64
    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}
